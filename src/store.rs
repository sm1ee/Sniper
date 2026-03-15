use std::collections::VecDeque;

use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

use crate::model::{TransactionRecord, TransactionSummary};

#[derive(Clone, Debug, Default)]
pub struct ListFilters {
    pub query: Option<String>,
    pub method: Option<String>,
    pub limit: Option<usize>,
}

pub struct TransactionStore {
    max_entries: usize,
    entries: RwLock<VecDeque<TransactionRecord>>,
    events: broadcast::Sender<TransactionSummary>,
}

impl TransactionStore {
    pub fn new(max_entries: usize) -> Self {
        Self::from_records(max_entries, Vec::new())
    }

    pub fn from_records(max_entries: usize, records: Vec<TransactionRecord>) -> Self {
        let (events, _) = broadcast::channel(max_entries.max(32));
        let mut entries = VecDeque::with_capacity(max_entries);
        entries.extend(records.into_iter().take(max_entries));
        Self {
            max_entries,
            entries: RwLock::new(entries),
            events,
        }
    }

    pub async fn insert(&self, record: TransactionRecord) {
        let summary = record.summary();
        let mut entries = self.entries.write().await;
        entries.push_front(record);

        while entries.len() > self.max_entries {
            entries.pop_back();
        }

        let _ = self.events.send(summary);
    }

    pub async fn list(&self, filters: &ListFilters) -> Vec<TransactionSummary> {
        let query = filters
            .query
            .as_ref()
            .map(|value| value.to_ascii_lowercase());
        let method = filters
            .method
            .as_ref()
            .map(|value| value.to_ascii_uppercase());
        let limit = filters.limit.unwrap_or(100).min(self.max_entries);
        let entries = self.entries.read().await;

        entries
            .iter()
            .filter(|record| matches_filters(record, query.as_deref(), method.as_deref()))
            .take(limit)
            .map(TransactionRecord::summary)
            .collect()
    }

    pub async fn get(&self, id: Uuid) -> Option<TransactionRecord> {
        let entries = self.entries.read().await;
        entries.iter().find(|record| record.id == id).cloned()
    }

    pub async fn snapshot(&self, limit: Option<usize>) -> Vec<TransactionRecord> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .take(limit.unwrap_or(self.max_entries).min(self.max_entries))
            .cloned()
            .collect()
    }

    pub async fn update_annotations(
        &self,
        id: Uuid,
        color_tag: Option<Option<String>>,
        user_note: Option<Option<String>>,
    ) -> Option<TransactionSummary> {
        let mut entries = self.entries.write().await;
        let record = entries.iter_mut().find(|r| r.id == id)?;
        if let Some(tag) = color_tag {
            record.color_tag = tag;
        }
        if let Some(note) = user_note {
            record.user_note = note;
        }
        Some(record.summary())
    }

    pub async fn replace_all(&self, records: Vec<TransactionRecord>) {
        let mut entries = self.entries.write().await;
        entries.clear();
        entries.extend(records.into_iter().take(self.max_entries));
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TransactionSummary> {
        self.events.subscribe()
    }
}

fn matches_filters(record: &TransactionRecord, query: Option<&str>, method: Option<&str>) -> bool {
    let method_match = method.map_or(true, |value| record.method.eq_ignore_ascii_case(value));
    if !method_match {
        return false;
    }

    query.map_or(true, |value| {
        let haystack = format!(
            "{} {} {} {}",
            record.id, record.method, record.host, record.path
        )
        .to_ascii_lowercase();
        haystack.contains(value)
    })
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::model::{MessageRecord, TransactionRecord};

    #[tokio::test]
    async fn store_respects_capacity_and_filters() {
        let store = TransactionStore::new(2);
        let empty_message = MessageRecord {
            headers: Vec::new(),
            body_preview: String::new(),
            body_encoding: crate::model::BodyEncoding::Utf8,
            body_size: 0,
            preview_truncated: false,
            content_type: None,
        };

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "GET".into(),
                "http".into(),
                "one.local".into(),
                "/".into(),
                Some(200),
                1,
                empty_message.clone(),
                Some(empty_message.clone()),
                Vec::new(),
                None,
                None,
            ))
            .await;

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "POST".into(),
                "http".into(),
                "two.local".into(),
                "/submit".into(),
                Some(201),
                2,
                empty_message.clone(),
                Some(empty_message.clone()),
                Vec::new(),
                None,
                None,
            ))
            .await;

        store
            .insert(TransactionRecord::http(
                Utc::now(),
                "DELETE".into(),
                "http".into(),
                "three.local".into(),
                "/resource".into(),
                Some(204),
                3,
                empty_message.clone(),
                Some(empty_message),
                Vec::new(),
                None,
                None,
            ))
            .await;

        let all = store.list(&ListFilters::default()).await;
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].method, "DELETE");

        let filtered = store
            .list(&ListFilters {
                query: Some("two.local".into()),
                method: Some("POST".into()),
                limit: Some(10),
            })
            .await;
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].host, "two.local");
    }
}
