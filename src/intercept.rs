use std::collections::VecDeque;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, Mutex, RwLock};
use uuid::Uuid;

use crate::model::{EditableRequest, EditableResponse};

// ── Intercept Rules ──

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptScope {
    Request,
    Response,
    Both,
}

impl Default for InterceptScope {
    fn default() -> Self {
        Self::Request
    }
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
            let host = request
                .host
                .split_once(':')
                .map(|(h, _)| h)
                .unwrap_or(&request.host)
                .to_ascii_lowercase();
            let pattern = self.host_pattern.to_ascii_lowercase();
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
            if !self.method_filter.iter().any(|m| m.to_ascii_uppercase() == method_upper) {
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
            return true; // No rules = intercept everything (backward compat)
        }
        rules.iter().any(|rule| {
            rule.matches(request)
                && matches!(rule.scope, InterceptScope::Response | InterceptScope::Both)
        })
    }

    pub async fn snapshot(&self) -> Vec<InterceptRule> {
        self.rules.read().await.clone()
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
    Forward(EditableRequest),
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
        self.queue.lock().await.push_back(PendingIntercept {
            record: record.clone(),
            responder: sender,
        });

        receiver
            .await
            .unwrap_or_else(|_| InterceptResolution::Drop(record.request))
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

    pub async fn forward(&self, id: Uuid, request: EditableRequest) -> Result<()> {
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
            .send(InterceptResolution::Forward(request))
            .map_err(|_| anyhow!("intercept consumer dropped before forward"))?;
        Ok(())
    }

    pub async fn forward_all(&self) -> usize {
        let mut queue = self.queue.lock().await;
        let count = queue.len();
        while let Some(pending) = queue.pop_front() {
            let _ = pending
                .responder
                .send(InterceptResolution::Forward(pending.record.request));
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
    Forward(EditableResponse),
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
        self.queue.lock().await.push_back(PendingResponseIntercept {
            record,
            responder: sender,
        });

        receiver
            .await
            .unwrap_or(ResponseInterceptResolution::Drop)
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

    pub async fn forward(&self, id: Uuid, response: EditableResponse) -> Result<()> {
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
            .send(ResponseInterceptResolution::Forward(response))
            .map_err(|_| anyhow!("response intercept consumer dropped before forward"))?;
        Ok(())
    }

    pub async fn forward_all(&self) -> usize {
        let mut queue = self.queue.lock().await;
        let count = queue.len();
        while let Some(pending) = queue.pop_front() {
            let _ = pending
                .responder
                .send(ResponseInterceptResolution::Forward(pending.record.response));
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
