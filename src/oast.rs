use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};
use uuid::Uuid;

/// OAST configuration stored in runtime settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OastConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server_url: String,
    #[serde(default)]
    pub token: String,
    #[serde(default = "default_polling_interval")]
    pub polling_interval_secs: u64,
}

fn default_polling_interval() -> u64 {
    5
}

impl Default for OastConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_url: String::new(),
            token: String::new(),
            polling_interval_secs: 5,
        }
    }
}

/// A single OAST callback received from the polling server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OastCallback {
    pub id: Uuid,
    pub received_at: DateTime<Utc>,
    pub protocol: String,
    pub remote_addr: String,
    pub raw_data: String,
    pub correlation_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OastCallbackSummary {
    pub id: Uuid,
    pub received_at: DateTime<Utc>,
    pub protocol: String,
    pub remote_addr: String,
    pub correlation_id: String,
}

impl OastCallback {
    pub fn summary(&self) -> OastCallbackSummary {
        OastCallbackSummary {
            id: self.id,
            received_at: self.received_at,
            protocol: self.protocol.clone(),
            remote_addr: self.remote_addr.clone(),
            correlation_id: self.correlation_id.clone(),
        }
    }
}

/// Store for OAST callbacks. Mirrors ScannerStore pattern.
pub struct OastStore {
    max_entries: usize,
    entries: RwLock<VecDeque<OastCallback>>,
    events: broadcast::Sender<OastCallbackSummary>,
    config: RwLock<OastConfig>,
}

impl OastStore {
    pub fn new(max_entries: usize) -> Self {
        let (events, _) = broadcast::channel(max_entries.max(64));
        Self {
            max_entries,
            entries: RwLock::new(VecDeque::new()),
            events,
            config: RwLock::new(OastConfig::default()),
        }
    }

    pub async fn push(&self, callback: OastCallback) {
        let summary = callback.summary();
        let mut entries = self.entries.write().await;
        entries.push_front(callback);
        while entries.len() > self.max_entries {
            entries.pop_back();
        }
        let _ = self.events.send(summary);
    }

    pub async fn list(&self, limit: Option<usize>) -> Vec<OastCallbackSummary> {
        let entries = self.entries.read().await;
        entries
            .iter()
            .take(limit.unwrap_or(self.max_entries).min(self.max_entries))
            .map(OastCallback::summary)
            .collect()
    }

    pub async fn get(&self, id: Uuid) -> Option<OastCallback> {
        let entries = self.entries.read().await;
        entries.iter().find(|c| c.id == id).cloned()
    }

    pub async fn clear(&self) {
        self.entries.write().await.clear();
    }

    pub async fn count(&self) -> usize {
        self.entries.read().await.len()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<OastCallbackSummary> {
        self.events.subscribe()
    }

    pub async fn get_config(&self) -> OastConfig {
        self.config.read().await.clone()
    }

    pub async fn update_config(&self, new_config: OastConfig) {
        *self.config.write().await = new_config;
    }

    pub async fn snapshot(&self) -> Vec<OastCallback> {
        self.entries.read().await.iter().cloned().collect()
    }

    pub async fn restore(&self, callbacks: Vec<OastCallback>) {
        let mut entries = self.entries.write().await;
        *entries = VecDeque::from(callbacks);
    }
}

/// Generate a unique correlation ID for OAST payloads.
pub fn generate_correlation_id() -> String {
    // Short UUID-based ID that's easy to embed in payloads
    let id = Uuid::new_v4();
    let hex = id.as_simple().to_string();
    hex[..12].to_string()
}

/// Build an OAST payload URL from server URL and correlation ID.
pub fn build_oast_payload(server_url: &str, correlation_id: &str) -> String {
    let base = server_url.trim_end_matches('/');
    // For Interactsh-style: correlation_id.server_domain
    // For generic: server_url/correlation_id
    if let Some(domain) = base.strip_prefix("https://").or_else(|| base.strip_prefix("http://")) {
        format!("{correlation_id}.{domain}")
    } else {
        format!("{base}/{correlation_id}")
    }
}

/// Poll an OAST server for new callbacks.
/// Supports generic JSON callback format.
pub async fn poll_oast_callbacks(
    config: &OastConfig,
    client: &reqwest::Client,
) -> Vec<OastCallback> {
    if !config.enabled || config.server_url.is_empty() {
        return vec![];
    }

    let base = config.server_url.trim_end_matches('/');
    let poll_url = if config.token.is_empty() {
        format!("{base}/poll")
    } else {
        format!("{base}/poll?token={}", config.token)
    };

    let response = match client.get(&poll_url).timeout(Duration::from_secs(10)).send().await {
        Ok(r) => r,
        Err(e) => {
            debug!(error = %e, "OAST poll failed");
            return vec![];
        }
    };

    if !response.status().is_success() {
        debug!(status = %response.status(), "OAST poll non-200");
        return vec![];
    }

    // Try to parse as JSON array of callbacks
    #[derive(Deserialize)]
    struct RawCallback {
        #[serde(default)]
        protocol: String,
        #[serde(default, alias = "remote-address", alias = "remote_address")]
        remote_addr: String,
        #[serde(default, alias = "raw-request", alias = "raw_request")]
        raw_data: String,
        #[serde(default, alias = "unique-id", alias = "unique_id", alias = "correlation_id")]
        correlation_id: String,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum PollResponse {
        Array(Vec<RawCallback>),
        Object {
            #[serde(default)]
            data: Vec<RawCallback>,
        },
    }

    let text = match response.text().await {
        Ok(t) => t,
        Err(_) => return vec![],
    };

    let raw_callbacks: Vec<RawCallback> = match serde_json::from_str::<PollResponse>(&text) {
        Ok(PollResponse::Array(arr)) => arr,
        Ok(PollResponse::Object { data }) => data,
        Err(e) => {
            debug!(error = %e, "OAST poll response parse failed");
            return vec![];
        }
    };

    raw_callbacks
        .into_iter()
        .map(|raw| OastCallback {
            id: Uuid::new_v4(),
            received_at: Utc::now(),
            protocol: raw.protocol,
            remote_addr: raw.remote_addr,
            raw_data: raw.raw_data,
            correlation_id: raw.correlation_id,
        })
        .collect()
}

/// Start the OAST polling background task.
pub fn start_oast_poller(store: Arc<OastStore>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();

        loop {
            let config = store.get_config().await;
            if !config.enabled || config.server_url.is_empty() {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }

            let interval = Duration::from_secs(config.polling_interval_secs.max(1));
            let callbacks = poll_oast_callbacks(&config, &client).await;

            if !callbacks.is_empty() {
                info!(count = callbacks.len(), "OAST callbacks received");
                for cb in callbacks {
                    store.push(cb).await;
                }
            }

            tokio::time::sleep(interval).await;
        }
    })
}
