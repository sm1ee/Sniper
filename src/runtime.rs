use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeSettingsSnapshot {
    pub intercept_enabled: bool,
    pub websocket_capture_enabled: bool,
    pub scope_patterns: Vec<String>,
    #[serde(default)]
    pub passthrough_hosts: Vec<String>,
    #[serde(default = "default_upstream_insecure")]
    pub upstream_insecure: bool,
    #[serde(default = "default_true")]
    pub intercept_scope_only: bool,
    #[serde(default)]
    pub oast_enabled: bool,
    #[serde(default)]
    pub oast_server_url: String,
    #[serde(default)]
    pub oast_token: String,
    #[serde(default = "default_oast_interval")]
    pub oast_polling_interval_secs: u64,
    #[serde(default)]
    pub oast_provider: crate::oast::OastProvider,
}

fn default_oast_interval() -> u64 {
    5
}

fn default_true() -> bool {
    true
}

fn default_upstream_insecure() -> bool {
    true
}

impl Default for RuntimeSettingsSnapshot {
    fn default() -> Self {
        Self {
            intercept_enabled: false,
            websocket_capture_enabled: true,
            scope_patterns: Vec::new(),
            passthrough_hosts: Vec::new(),
            upstream_insecure: true,
            intercept_scope_only: true,
            oast_enabled: false,
            oast_server_url: String::new(),
            oast_token: String::new(),
            oast_polling_interval_secs: 5,
            oast_provider: crate::oast::OastProvider::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RuntimeSettingsUpdate {
    pub intercept_enabled: Option<bool>,
    pub websocket_capture_enabled: Option<bool>,
    pub scope_patterns: Option<Vec<String>>,
    pub passthrough_hosts: Option<Vec<String>>,
    pub upstream_insecure: Option<bool>,
    pub intercept_scope_only: Option<bool>,
    pub oast_enabled: Option<bool>,
    pub oast_server_url: Option<String>,
    pub oast_token: Option<String>,
    pub oast_polling_interval_secs: Option<u64>,
    pub oast_provider: Option<crate::oast::OastProvider>,
}

pub struct RuntimeSettings {
    inner: RwLock<RuntimeSettingsSnapshot>,
}

impl RuntimeSettings {
    pub fn new() -> Self {
        Self::from_snapshot(RuntimeSettingsSnapshot::default())
    }

    pub fn from_snapshot(snapshot: RuntimeSettingsSnapshot) -> Self {
        Self {
            inner: RwLock::new(snapshot),
        }
    }

    pub async fn snapshot(&self) -> RuntimeSettingsSnapshot {
        self.inner.read().await.clone()
    }

    pub async fn update(&self, update: RuntimeSettingsUpdate) -> RuntimeSettingsSnapshot {
        let mut current = self.inner.write().await;

        if let Some(intercept_enabled) = update.intercept_enabled {
            current.intercept_enabled = intercept_enabled;
        }

        if let Some(websocket_capture_enabled) = update.websocket_capture_enabled {
            current.websocket_capture_enabled = websocket_capture_enabled;
        }

        if let Some(scope_patterns) = update.scope_patterns {
            current.scope_patterns = normalize_scope_patterns(scope_patterns);
        }

        if let Some(passthrough_hosts) = update.passthrough_hosts {
            current.passthrough_hosts = normalize_scope_patterns(passthrough_hosts);
        }

        if let Some(upstream_insecure) = update.upstream_insecure {
            current.upstream_insecure = upstream_insecure;
        }

        if let Some(intercept_scope_only) = update.intercept_scope_only {
            current.intercept_scope_only = intercept_scope_only;
        }

        if let Some(oast_enabled) = update.oast_enabled {
            current.oast_enabled = oast_enabled;
        }
        if let Some(oast_server_url) = update.oast_server_url {
            current.oast_server_url = oast_server_url;
        }
        if let Some(oast_token) = update.oast_token {
            current.oast_token = oast_token;
        }
        if let Some(oast_polling_interval_secs) = update.oast_polling_interval_secs {
            current.oast_polling_interval_secs = oast_polling_interval_secs;
        }
        if let Some(oast_provider) = update.oast_provider {
            current.oast_provider = oast_provider;
        }

        current.clone()
    }

    pub async fn replace_snapshot(
        &self,
        snapshot: RuntimeSettingsSnapshot,
    ) -> RuntimeSettingsSnapshot {
        let mut current = self.inner.write().await;
        *current = snapshot;
        current.clone()
    }

    pub async fn intercept_enabled(&self) -> bool {
        self.inner.read().await.intercept_enabled
    }

    pub async fn websocket_capture_enabled(&self) -> bool {
        self.inner.read().await.websocket_capture_enabled
    }

    pub async fn upstream_insecure(&self) -> bool {
        self.inner.read().await.upstream_insecure
    }

    pub async fn intercept_scope_only(&self) -> bool {
        self.inner.read().await.intercept_scope_only
    }

    pub async fn is_in_scope(&self, host: &str) -> bool {
        let current = self.inner.read().await;
        matches_scope(host, &current.scope_patterns)
    }

    pub async fn is_passthrough(&self, host: &str) -> bool {
        let current = self.inner.read().await;
        matches_passthrough(host, &current.passthrough_hosts)
    }
}

fn normalize_scope_patterns(patterns: Vec<String>) -> Vec<String> {
    patterns
        .into_iter()
        .map(|pattern| pattern.trim().to_ascii_lowercase())
        .filter(|pattern| !pattern.is_empty())
        .collect()
}

fn matches_scope(host: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }

    host_matches_any(host, patterns)
}

fn matches_passthrough(host: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return false;
    }

    host_matches_any(host, patterns)
}

fn host_matches_any(host: &str, patterns: &[String]) -> bool {
    let hostname = host
        .split_once(':')
        .map(|(value, _)| value)
        .unwrap_or(host)
        .trim()
        .to_ascii_lowercase();

    patterns.iter().any(|pattern| {
        if let Some(suffix) = pattern.strip_prefix("*.") {
            hostname == suffix || hostname.ends_with(&format!(".{suffix}"))
        } else {
            hostname == *pattern
        }
    })
}
