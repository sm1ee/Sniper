//! Strict, session-pinned selection for managing saved HTTP records.
use std::collections::HashSet;

use rsa::sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    model::TransactionSummary,
    store::{ListFilters, TransactionStore},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySelection {
    pub session_id: Uuid,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ids: Vec<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_range: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selection_token: Option<String>,
}

impl HistorySelection {
    pub fn filters(&self) -> ListFilters {
        ListFilters {
            query: self.query.clone(),
            method: self.method.clone(),
            host: self.host.clone(),
            status: self.status,
            status_range: self.status_range.clone(),
            since: self.since.clone(),
            mime: self.mime.clone(),
            limit: Some(0),
            ..Default::default()
        }
    }

    pub fn has_filters(&self) -> bool {
        self.query.is_some()
            || self.method.is_some()
            || self.host.is_some()
            || self.status.is_some()
            || self.status_range.is_some()
            || self.since.is_some()
            || self.mime.is_some()
    }

    pub fn validate(&self, deleting: bool) -> Result<(), String> {
        if !self.ids.is_empty() && self.has_filters() {
            return Err("ids and filters are mutually exclusive".into());
        }
        if self.ids.is_empty() {
            crate::store::validate_delete_filters(&self.filters())?;
            if deleting && self.selection_token.is_none() {
                return Err(
                    "filtered deletion requires selection_token from capture.http.select".into(),
                );
            }
        }
        if let Some(token) = &self.selection_token {
            if token.len() != 64
                || !token
                    .bytes()
                    .all(|ch| ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))
            {
                return Err(
                    "selection_token must be the 64-character token from capture.http.select"
                        .into(),
                );
            }
        }
        Ok(())
    }

    pub async fn resolve(
        &self,
        store: &TransactionStore,
    ) -> Result<Vec<TransactionSummary>, String> {
        let filters = if self.ids.is_empty() {
            self.filters()
        } else {
            ListFilters {
                limit: Some(0),
                ..Default::default()
            }
        };
        let mut rows = store.list(&filters).await;
        if !self.ids.is_empty() {
            let ids: HashSet<_> = self.ids.iter().copied().collect();
            rows.retain(|row| ids.contains(&row.id));
            if rows.len() != ids.len() {
                return Err("selection contains missing transaction IDs in the specified session; nothing deleted".into());
            }
        }
        rows.sort_unstable_by_key(|row| row.id);
        Ok(rows)
    }
}

pub fn selection_token(session_id: Uuid, rows: &[TransactionSummary]) -> String {
    // Include the session and all summary fields so a token cannot be reused for
    // another session or after its selected IDs/metadata change. Bodies are not
    // fingerprinted: this token identifies saved rows, not their full contents.
    let mut hash = Sha256::new();
    hash.update(b"sniper-history-selection-v1\0");
    hash.update(session_id.as_bytes());
    hash.update(serde_json::to_vec(rows).expect("transaction summaries serialize"));
    format!("{:x}", hash.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn selection(extra: serde_json::Value) -> HistorySelection {
        let mut value = json!({"session_id":Uuid::nil()});
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn selection_requires_ids_or_valid_nonempty_filters() {
        for value in [
            json!({}),
            json!({"ids":[]}),
            json!({"host":" "}),
            json!({"status_range":"oops"}),
            json!({"since":"forever"}),
            json!({"ids":[Uuid::nil()],"host":"example.com"}),
        ] {
            assert!(selection(value).validate(false).is_err());
        }
        assert!(selection(json!({"ids":[Uuid::nil()]}))
            .validate(true)
            .is_ok());
        assert!(selection(json!({"host":"example.com"}))
            .validate(false)
            .is_ok());
        assert!(selection(json!({"host":"example.com"}))
            .validate(true)
            .is_err());
        assert!(
            selection(json!({"host":"example.com","selection_token":"a".repeat(64)}))
                .validate(true)
                .is_ok()
        );
    }

    #[test]
    fn selection_rejects_unknown_fields_and_bad_session_ids() {
        assert!(serde_json::from_value::<HistorySelection>(
            json!({"session_id":Uuid::nil(),"hots":"example.com"})
        )
        .is_err());
        assert!(serde_json::from_value::<HistorySelection>(
            json!({"session_id":"../other","ids":[Uuid::nil()]})
        )
        .is_err());
        assert!(serde_json::from_value::<HistorySelection>(json!({"ids":[Uuid::nil()]})).is_err());
    }

    #[test]
    fn selection_token_is_session_bound_even_for_zero_matches() {
        assert_ne!(
            selection_token(Uuid::nil(), &[]),
            selection_token(Uuid::new_v4(), &[])
        );
    }
}
