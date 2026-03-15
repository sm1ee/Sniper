use std::collections::VecDeque;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, Mutex};
use uuid::Uuid;

use crate::model::EditableRequest;

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
