use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetPathNode {
    pub path: String,
    pub methods: Vec<String>,
    pub last_seen: DateTime<Utc>,
    pub status: Option<u16>,
    pub note_count: usize,
    pub is_websocket: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetHostNode {
    pub host: String,
    pub schemes: Vec<String>,
    pub request_count: usize,
    pub in_scope: bool,
    pub paths: Vec<TargetPathNode>,
}
