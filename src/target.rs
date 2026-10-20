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
    #[serde(default = "default_captured")]
    pub captured: bool,
    #[serde(default)]
    pub discovered: bool,
    #[serde(default)]
    pub recon_sources: Vec<String>,
    #[serde(default)]
    pub recon_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recon_last_seen: Option<DateTime<Utc>>,
}

fn default_captured() -> bool {
    true
}

/// A body-free inventory projection: the site map needs provenance names, not
/// every raw URL, archive timestamp, or evidence location retained by Recon.
pub struct ReconSiteMapEndpoint {
    pub url: String,
    pub method: String,
    pub last_seen: DateTime<Utc>,
    pub sources: Vec<String>,
    pub kinds: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetHostNode {
    pub host: String,
    pub schemes: Vec<String>,
    pub request_count: usize,
    pub in_scope: bool,
    pub paths: Vec<TargetPathNode>,
}

#[cfg(test)]
mod tests {
    use super::TargetPathNode;

    #[test]
    fn legacy_site_map_paths_default_to_captured() {
        let path: TargetPathNode = serde_json::from_value(serde_json::json!({
            "path": "/legacy",
            "methods": ["GET"],
            "last_seen": "2026-01-01T00:00:00Z",
            "status": 200,
            "note_count": 0,
            "is_websocket": false,
        }))
        .unwrap();
        assert!(path.captured);
        assert!(!path.discovered);
        assert!(path.recon_sources.is_empty());
        assert!(path.recon_kinds.is_empty());
        assert!(path.recon_last_seen.is_none());
    }
}
