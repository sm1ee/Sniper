use std::collections::VecDeque;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, Mutex, RwLock};
use uuid::Uuid;

use crate::model::{EditableRequest, EditableResponse};

const MAX_INTERCEPT_QUEUE_ENTRIES: usize = 512;

// ── Intercept Rules ──

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptScope {
    #[default]
    Request,
    Response,
    Both,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterceptRule {
    pub id: Uuid,
    pub enabled: bool,
    #[serde(default)]
    pub scope: InterceptScope,
    #[serde(default)]
    pub host_pattern: String,
    #[serde(default)]
    pub path_pattern: String,
    #[serde(default)]
    pub method_filter: Vec<String>,
}

impl InterceptRule {
    pub fn matches(&self, request: &EditableRequest) -> bool {
        if !self.enabled {
            return false;
        }

        if !self.host_pattern.is_empty() {
            let host = normalize_host_for_matching(&request.host);
            let pattern = normalize_host_for_matching(&self.host_pattern);
            if let Some(suffix) = pattern.strip_prefix("*.") {
                if host != suffix && !host.ends_with(&format!(".{suffix}")) {
                    return false;
                }
            } else if host != pattern {
                return false;
            }
        }

        if !self.path_pattern.is_empty() && !request.path.contains(&self.path_pattern) {
            return false;
        }

        if !self.method_filter.is_empty() {
            let method_upper = request.method.to_ascii_uppercase();
            if !self
                .method_filter
                .iter()
                .any(|m| m.to_ascii_uppercase() == method_upper)
            {
                return false;
            }
        }

        true
    }
}

pub struct InterceptRuleStore {
    rules: RwLock<Vec<InterceptRule>>,
}

impl InterceptRuleStore {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(Vec::new()),
        }
    }

    pub fn from_rules(rules: Vec<InterceptRule>) -> Self {
        Self {
            rules: RwLock::new(rules),
        }
    }

    pub async fn list(&self) -> Vec<InterceptRule> {
        self.rules.read().await.clone()
    }

    pub async fn upsert(&self, rule: InterceptRule) {
        let mut rules = self.rules.write().await;
        if let Some(existing) = rules.iter_mut().find(|r| r.id == rule.id) {
            *existing = rule;
        } else {
            rules.push(rule);
        }
    }

    pub async fn delete(&self, id: Uuid) -> bool {
        let mut rules = self.rules.write().await;
        let len_before = rules.len();
        rules.retain(|r| r.id != id);
        rules.len() < len_before
    }

    pub async fn matches_any(&self, request: &EditableRequest) -> bool {
        let rules = self.rules.read().await;
        if rules.is_empty() {
            return true; // No rules = intercept everything (backward compat)
        }
        rules.iter().any(|rule| {
            rule.matches(request)
                && matches!(rule.scope, InterceptScope::Request | InterceptScope::Both)
        })
    }

    pub async fn matches_any_response(&self, request: &EditableRequest) -> bool {
        let rules = self.rules.read().await;
        if rules.is_empty() {
            return false; // No rules keeps the legacy request-only intercept behavior.
        }
        rules.iter().any(|rule| {
            rule.matches(request)
                && matches!(rule.scope, InterceptScope::Response | InterceptScope::Both)
        })
    }

    pub async fn snapshot(&self) -> Vec<InterceptRule> {
        self.rules.read().await.clone()
    }

    pub async fn replace_all(&self, rules: Vec<InterceptRule>) {
        *self.rules.write().await = rules;
    }
}

impl Default for InterceptRuleStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Intercept Queue ──

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterceptRecord {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub peer_addr: String,
    pub request: EditableRequest,
    pub is_websocket: bool,
}

impl InterceptRecord {
    pub fn summary(&self) -> InterceptSummary {
        InterceptSummary {
            id: self.id,
            started_at: self.started_at,
            peer_addr: self.peer_addr.clone(),
            scheme: self.request.scheme.clone(),
            host: self.request.host.clone(),
            method: self.request.method.clone(),
            path: self.request.path.clone(),
            is_websocket: self.is_websocket,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InterceptSummary {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub peer_addr: String,
    pub scheme: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub is_websocket: bool,
}

#[derive(Clone, Debug)]
pub enum InterceptResolution {
    /// `edited` is what the operator actually did, reported by the client. The
    /// server cannot tell from the request alone: the editor renders the held
    /// request to text and parses it back, and that round trip can rewrite
    /// Content-Length or trim header whitespace on its own.
    Forward {
        request: EditableRequest,
        edited: bool,
    },
    Drop(EditableRequest),
}

struct PendingIntercept {
    record: InterceptRecord,
    responder: oneshot::Sender<InterceptResolution>,
}

pub struct InterceptQueue {
    queue: Mutex<VecDeque<PendingIntercept>>,
}

impl InterceptQueue {
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
        }
    }

    pub async fn enqueue(&self, record: InterceptRecord) -> InterceptResolution {
        let (sender, receiver) = oneshot::channel();
        {
            let mut queue = self.queue.lock().await;
            queue.push_back(PendingIntercept {
                record: record.clone(),
                responder: sender,
            });
            trim_pending_request_intercepts(&mut queue, MAX_INTERCEPT_QUEUE_ENTRIES);
        }

        receiver
            .await
            .unwrap_or(InterceptResolution::Drop(record.request))
    }

    pub async fn list(&self) -> Vec<InterceptSummary> {
        self.queue
            .lock()
            .await
            .iter()
            .map(|entry| entry.record.summary())
            .collect()
    }

    pub async fn get(&self, id: Uuid) -> Option<InterceptRecord> {
        self.queue
            .lock()
            .await
            .iter()
            .find(|entry| entry.record.id == id)
            .map(|entry| entry.record.clone())
    }

    pub async fn forward(&self, id: Uuid, request: EditableRequest, edited: bool) -> Result<()> {
        let mut queue = self.queue.lock().await;
        let index = queue
            .iter()
            .position(|entry| entry.record.id == id)
            .ok_or_else(|| anyhow!("intercept item {id} was not found"))?;
        let pending = queue
            .remove(index)
            .ok_or_else(|| anyhow!("failed to remove intercept item {id}"))?;
        pending
            .responder
            .send(InterceptResolution::Forward { request, edited })
            .map_err(|_| anyhow!("intercept consumer dropped before forward"))?;
        Ok(())
    }

    pub async fn forward_all(&self) -> usize {
        let mut queue = self.queue.lock().await;
        let count = queue.len();
        while let Some(pending) = queue.pop_front() {
            let _ = pending.responder.send(InterceptResolution::Forward {
                request: pending.record.request,
                edited: false,
            });
        }
        count
    }

    pub async fn drop_all(&self) -> usize {
        let mut queue = self.queue.lock().await;
        let count = queue.len();
        while let Some(pending) = queue.pop_front() {
            let _ = pending
                .responder
                .send(InterceptResolution::Drop(pending.record.request));
        }
        count
    }

    pub async fn drop_request(&self, id: Uuid) -> Result<()> {
        let mut queue = self.queue.lock().await;
        let index = queue
            .iter()
            .position(|entry| entry.record.id == id)
            .ok_or_else(|| anyhow!("intercept item {id} was not found"))?;
        let pending = queue
            .remove(index)
            .ok_or_else(|| anyhow!("failed to remove intercept item {id}"))?;
        pending
            .responder
            .send(InterceptResolution::Drop(pending.record.request))
            .map_err(|_| anyhow!("intercept consumer dropped before drop"))?;
        Ok(())
    }
}

impl Default for InterceptQueue {
    fn default() -> Self {
        Self::new()
    }
}

fn trim_pending_request_intercepts(
    queue: &mut VecDeque<PendingIntercept>,
    max_entries: usize,
) -> usize {
    let mut evicted = 0;
    while queue.len() > max_entries {
        let Some(pending) = queue.pop_front() else {
            break;
        };
        let _ = pending.responder.send(InterceptResolution::Forward {
            request: pending.record.request,
            edited: false,
        });
        evicted += 1;
    }
    evicted
}

// ── Response Intercept Queue ──

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseInterceptRecord {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub scheme: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub response: EditableResponse,
}

impl ResponseInterceptRecord {
    pub fn summary(&self) -> ResponseInterceptSummary {
        ResponseInterceptSummary {
            id: self.id,
            started_at: self.started_at,
            scheme: self.scheme.clone(),
            host: self.host.clone(),
            method: self.method.clone(),
            path: self.path.clone(),
            status: self.status,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseInterceptSummary {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub scheme: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub status: u16,
}

#[derive(Clone, Debug)]
pub enum ResponseInterceptResolution {
    PassThrough,
    Forward {
        response: EditableResponse,
        edited: bool,
    },
    Drop,
}

struct PendingResponseIntercept {
    record: ResponseInterceptRecord,
    responder: oneshot::Sender<ResponseInterceptResolution>,
}

pub struct ResponseInterceptQueue {
    queue: Mutex<VecDeque<PendingResponseIntercept>>,
}

impl ResponseInterceptQueue {
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
        }
    }

    pub async fn enqueue(&self, record: ResponseInterceptRecord) -> ResponseInterceptResolution {
        let (sender, receiver) = oneshot::channel();
        {
            let mut queue = self.queue.lock().await;
            queue.push_back(PendingResponseIntercept {
                record,
                responder: sender,
            });
            trim_pending_response_intercepts(&mut queue, MAX_INTERCEPT_QUEUE_ENTRIES);
        }

        receiver.await.unwrap_or(ResponseInterceptResolution::Drop)
    }

    pub async fn list(&self) -> Vec<ResponseInterceptSummary> {
        self.queue
            .lock()
            .await
            .iter()
            .map(|entry| entry.record.summary())
            .collect()
    }

    pub async fn get(&self, id: Uuid) -> Option<ResponseInterceptRecord> {
        self.queue
            .lock()
            .await
            .iter()
            .find(|entry| entry.record.id == id)
            .map(|entry| entry.record.clone())
    }

    pub async fn forward(&self, id: Uuid, response: EditableResponse, edited: bool) -> Result<()> {
        let mut queue = self.queue.lock().await;
        let index = queue
            .iter()
            .position(|entry| entry.record.id == id)
            .ok_or_else(|| anyhow!("response intercept item {id} was not found"))?;
        let pending = queue
            .remove(index)
            .ok_or_else(|| anyhow!("failed to remove response intercept item {id}"))?;
        pending
            .responder
            .send(ResponseInterceptResolution::Forward { response, edited })
            .map_err(|_| anyhow!("response intercept consumer dropped before forward"))?;
        Ok(())
    }

    pub async fn forward_all(&self) -> usize {
        let mut queue = self.queue.lock().await;
        let count = queue.len();
        while let Some(pending) = queue.pop_front() {
            let _ = pending
                .responder
                .send(ResponseInterceptResolution::Forward {
                    response: pending.record.response,
                    edited: false,
                });
        }
        count
    }

    pub async fn drop_all(&self) -> usize {
        let mut queue = self.queue.lock().await;
        let count = queue.len();
        while let Some(pending) = queue.pop_front() {
            let _ = pending.responder.send(ResponseInterceptResolution::Drop);
        }
        count
    }

    pub async fn drop_response(&self, id: Uuid) -> Result<()> {
        let mut queue = self.queue.lock().await;
        let index = queue
            .iter()
            .position(|entry| entry.record.id == id)
            .ok_or_else(|| anyhow!("response intercept item {id} was not found"))?;
        let pending = queue
            .remove(index)
            .ok_or_else(|| anyhow!("failed to remove response intercept item {id}"))?;
        pending
            .responder
            .send(ResponseInterceptResolution::Drop)
            .map_err(|_| anyhow!("response intercept consumer dropped before drop"))?;
        Ok(())
    }
}

impl Default for ResponseInterceptQueue {
    fn default() -> Self {
        Self::new()
    }
}

fn trim_pending_response_intercepts(
    queue: &mut VecDeque<PendingResponseIntercept>,
    max_entries: usize,
) -> usize {
    let mut evicted = 0;
    while queue.len() > max_entries {
        let Some(pending) = queue.pop_front() else {
            break;
        };
        let _ = pending
            .responder
            .send(ResponseInterceptResolution::Forward {
                response: pending.record.response,
                edited: false,
            });
        evicted += 1;
    }
    evicted
}

fn host_without_port(host: &str) -> &str {
    let trimmed = host.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    if trimmed.matches(':').count() == 1 {
        return trimmed
            .split_once(':')
            .map(|(value, _)| value)
            .unwrap_or(trimmed);
    }
    trimmed
}

fn normalize_host_for_matching(host: &str) -> String {
    let host = host_without_port(host);
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::model::BodyEncoding;

    use super::*;

    fn request() -> EditableRequest {
        EditableRequest {
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
            preview_truncated: false,
        }
    }

    fn response() -> EditableResponse {
        EditableResponse {
            status: 200,
            headers: Vec::new(),
            body: String::new(),
            body_encoding: BodyEncoding::Utf8,
        }
    }

    #[test]
    fn intercept_rule_matches_trailing_dot_exact_hosts() {
        let mut request = request();
        request.host = "Example.COM.:443".to_string();
        let rule = InterceptRule {
            id: Uuid::new_v4(),
            enabled: true,
            scope: InterceptScope::Request,
            host_pattern: "example.com".to_string(),
            path_pattern: String::new(),
            method_filter: Vec::new(),
        };

        assert!(rule.matches(&request));
    }

    #[test]
    fn intercept_rule_matches_trailing_dot_wildcard_hosts() {
        let mut request = request();
        request.host = "api.Example.COM.".to_string();
        let rule = InterceptRule {
            id: Uuid::new_v4(),
            enabled: true,
            scope: InterceptScope::Request,
            host_pattern: "*.example.com".to_string(),
            path_pattern: String::new(),
            method_filter: Vec::new(),
        };

        assert!(rule.matches(&request));

        request.host = "example.com.".to_string();
        assert!(rule.matches(&request));
    }

    #[tokio::test]
    async fn pending_request_intercepts_forward_oldest_when_queue_is_full() {
        let mut queue = VecDeque::new();
        let old = request();
        let old_id = Uuid::new_v4();
        let new_id = Uuid::new_v4();
        let (old_sender, old_receiver) = oneshot::channel();
        let (new_sender, _new_receiver) = oneshot::channel();
        queue.push_back(PendingIntercept {
            record: InterceptRecord {
                id: old_id,
                started_at: Utc::now(),
                peer_addr: "127.0.0.1:11111".to_string(),
                request: old.clone(),
                is_websocket: false,
            },
            responder: old_sender,
        });
        queue.push_back(PendingIntercept {
            record: InterceptRecord {
                id: new_id,
                started_at: Utc::now(),
                peer_addr: "127.0.0.1:22222".to_string(),
                request: request(),
                is_websocket: false,
            },
            responder: new_sender,
        });

        let evicted = trim_pending_request_intercepts(&mut queue, 1);

        assert_eq!(evicted, 1);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.front().map(|pending| pending.record.id), Some(new_id));
        match old_receiver.await.unwrap() {
            InterceptResolution::Forward { request, .. } => assert_eq!(request.host, old.host),
            InterceptResolution::Drop(_) => panic!("old request should be forwarded"),
        }
    }

    #[tokio::test]
    async fn pending_response_intercepts_forward_oldest_when_queue_is_full() {
        let mut queue = VecDeque::new();
        let old = response();
        let old_id = Uuid::new_v4();
        let new_id = Uuid::new_v4();
        let (old_sender, old_receiver) = oneshot::channel();
        let (new_sender, _new_receiver) = oneshot::channel();
        queue.push_back(PendingResponseIntercept {
            record: ResponseInterceptRecord {
                id: old_id,
                started_at: Utc::now(),
                scheme: "https".to_string(),
                host: "example.com".to_string(),
                method: "GET".to_string(),
                path: "/old".to_string(),
                status: old.status,
                response: old.clone(),
            },
            responder: old_sender,
        });
        queue.push_back(PendingResponseIntercept {
            record: ResponseInterceptRecord {
                id: new_id,
                started_at: Utc::now(),
                scheme: "https".to_string(),
                host: "example.com".to_string(),
                method: "GET".to_string(),
                path: "/new".to_string(),
                status: 201,
                response: response(),
            },
            responder: new_sender,
        });

        let evicted = trim_pending_response_intercepts(&mut queue, 1);

        assert_eq!(evicted, 1);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.front().map(|pending| pending.record.id), Some(new_id));
        match old_receiver.await.unwrap() {
            ResponseInterceptResolution::Forward { response, .. } => {
                assert_eq!(response.status, old.status)
            }
            ResponseInterceptResolution::PassThrough | ResponseInterceptResolution::Drop => {
                panic!("old response should be forwarded")
            }
        }
    }

    #[tokio::test]
    async fn drop_all_releases_pending_request_intercepts() {
        let queue = Arc::new(InterceptQueue::new());
        let original = request();
        let record = InterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            peer_addr: "127.0.0.1:12345".to_string(),
            request: original.clone(),
            is_websocket: false,
        };
        let pending = tokio::spawn({
            let queue = Arc::clone(&queue);
            async move { queue.enqueue(record).await }
        });

        for _ in 0..10 {
            if !queue.list().await.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(queue.list().await.len(), 1);
        assert_eq!(queue.drop_all().await, 1);

        match pending.await.unwrap() {
            InterceptResolution::Drop(request) => assert_eq!(request.host, original.host),
            InterceptResolution::Forward { .. } => {
                panic!("expected pending intercept to be dropped")
            }
        }
    }

    #[tokio::test]
    async fn drop_all_releases_pending_response_intercepts() {
        let queue = Arc::new(ResponseInterceptQueue::new());
        let record = ResponseInterceptRecord {
            id: Uuid::new_v4(),
            started_at: Utc::now(),
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            status: 200,
            response: response(),
        };
        let pending = tokio::spawn({
            let queue = Arc::clone(&queue);
            async move { queue.enqueue(record).await }
        });

        for _ in 0..10 {
            if !queue.list().await.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(queue.list().await.len(), 1);
        assert_eq!(queue.drop_all().await, 1);

        match pending.await.unwrap() {
            ResponseInterceptResolution::Drop => {}
            ResponseInterceptResolution::PassThrough
            | ResponseInterceptResolution::Forward { .. } => {
                panic!("expected pending response intercept to be dropped")
            }
        }
    }
}
