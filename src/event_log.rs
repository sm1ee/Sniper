use std::collections::VecDeque;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventLevel {
    Info,
    Warn,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventLogEntry {
    pub id: Uuid,
    pub captured_at: DateTime<Utc>,
    pub level: EventLevel,
    pub source: String,
    pub title: String,
    pub message: String,
}

pub struct EventLogStore {
    max_entries: usize,
    entries: RwLock<VecDeque<EventLogEntry>>,
    events: broadcast::Sender<EventLogEntry>,
}

impl EventLogStore {
    pub fn new(max_entries: usize) -> Self {
        Self::from_entries(max_entries, Vec::new())
    }

    pub fn from_entries(max_entries: usize, records: Vec<EventLogEntry>) -> Self {
        let (events, _) = broadcast::channel(max_entries.max(64));
        let mut entries = VecDeque::with_capacity(max_entries);
        entries.extend(records.into_iter().take(max_entries));
        Self {
            max_entries,
            entries: RwLock::new(entries),
            events,
        }
    }

    pub async fn push(
        &self,
        level: EventLevel,
        source: impl Into<String>,
        title: impl Into<String>,
        message: impl Into<String>,
    ) -> EventLogEntry {
        let entry = EventLogEntry {
            id: Uuid::new_v4(),
            captured_at: Utc::now(),
            level,
            source: source.into(),
            title: title.into(),
            message: message.into(),
        };

        let mut entries = self.entries.write().await;
        entries.push_front(entry.clone());
        while entries.len() > self.max_entries {
            entries.pop_back();
        }
        let _ = self.events.send(entry.clone());
        entry
    }

    pub async fn list(&self, limit: Option<usize>) -> Vec<EventLogEntry> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .take(limit.unwrap_or(self.max_entries).min(self.max_entries))
            .cloned()
            .collect()
    }

    pub async fn snapshot(&self, limit: Option<usize>) -> Vec<EventLogEntry> {
        self.list(limit).await
    }

    pub async fn replace_all(&self, records: Vec<EventLogEntry>) {
        let mut entries = self.entries.write().await;
        entries.clear();
        entries.extend(records.into_iter().take(self.max_entries));
    }

    pub async fn clear(&self) {
        self.entries.write().await.clear();
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EventLogEntry> {
        self.events.subscribe()
    }
}
