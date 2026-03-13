use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeSettingsSnapshot {
    pub intercept_enabled: bool,
    pub websocket_capture_enabled: bool,
    pub scope_patterns: Vec<String>,
}

impl Default for RuntimeSettingsSnapshot {
    fn default() -> Self {
        Self {
            intercept_enabled: false,
            websocket_capture_enabled: true,
            scope_patterns: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RuntimeSettingsUpdate {
    pub intercept_enabled: Option<bool>,
    pub websocket_capture_enabled: Option<bool>,
    pub scope_patterns: Option<Vec<String>>,
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

    pub async fn is_in_scope(&self, host: &str) -> bool {
        let current = self.inner.read().await;
        matches_scope(host, &current.scope_patterns)
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
