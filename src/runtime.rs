use anyhow::{bail, Result};
use serde::{Deserialize, Deserializer, Serialize};
use tokio::sync::RwLock;

pub const OAST_TOKEN_REDACTION: &str = "********";
pub const MIN_OAST_POLLING_INTERVAL_SECS: u64 = 1;
pub const MAX_OAST_POLLING_INTERVAL_SECS: u64 = 300;
const MAX_RUNTIME_PATTERN_ENTRIES: usize = 500;
const MAX_RUNTIME_PATTERN_BYTES: usize = 512;
const MAX_RUNTIME_TEXT_FIELD_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeSettingsSnapshot {
    #[serde(default)]
    pub intercept_enabled: bool,
    #[serde(default = "default_true")]
    pub websocket_capture_enabled: bool,
    #[serde(default)]
    pub scope_patterns: Vec<String>,
    /// Hosts taken back out of scope. Applied after the include list, and on their
    /// own when that list is empty, so excluding works without first including.
    #[serde(default)]
    pub excluded_scope_patterns: Vec<String>,
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
    #[serde(default, deserialize_with = "deserialize_oast_provider_for_load")]
    pub oast_provider: crate::oast::OastProvider,
}

fn deserialize_oast_provider_for_load<'de, D>(
    deserializer: D,
) -> std::result::Result<crate::oast::OastProvider, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<String>::deserialize(deserializer)? else {
        return Ok(crate::oast::OastProvider::default());
    };
    Ok(match value.as_str() {
        "interactsh" => crate::oast::OastProvider::Interactsh,
        "boast" => crate::oast::OastProvider::Boast,
        "custom" => crate::oast::OastProvider::Custom,
        _ => crate::oast::OastProvider::default(),
    })
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
            excluded_scope_patterns: Vec::new(),
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

impl RuntimeSettingsSnapshot {
    pub fn redacted_for_read(mut self) -> Self {
        if !self.oast_token.is_empty() {
            self.oast_token = OAST_TOKEN_REDACTION.to_string();
        }
        self
    }

    pub fn sanitized_for_load(mut self) -> Self {
        self.excluded_scope_patterns = normalize_bounded_scope_patterns(
            "excluded scope pattern",
            std::mem::take(&mut self.excluded_scope_patterns),
        )
        .unwrap_or_default();
        self.scope_patterns =
            normalize_bounded_scope_patterns("scope pattern", self.scope_patterns)
                .unwrap_or_default();
        self.passthrough_hosts =
            normalize_bounded_scope_patterns("passthrough host", self.passthrough_hosts)
                .unwrap_or_default();
        if validate_runtime_text_field("OAST server URL", &self.oast_server_url).is_err()
            || crate::oast::validate_oast_server_url(&self.oast_server_url).is_err()
        {
            self.oast_server_url.clear();
        }
        if validate_runtime_text_field("OAST token", &self.oast_token).is_err() {
            self.oast_token.clear();
        }
        if self.oast_provider == crate::oast::OastProvider::Boast {
            self.oast_token.clear();
        }
        if !(MIN_OAST_POLLING_INTERVAL_SECS..=MAX_OAST_POLLING_INTERVAL_SECS)
            .contains(&self.oast_polling_interval_secs)
        {
            self.oast_polling_interval_secs = default_oast_interval();
        }
        self
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RuntimeSettingsUpdate {
    pub session_id: Option<uuid::Uuid>,
    #[serde(default)]
    pub expected_active_session_id: Option<uuid::Uuid>,
    pub intercept_enabled: Option<bool>,
    pub websocket_capture_enabled: Option<bool>,
    pub scope_patterns: Option<Vec<String>>,
    #[serde(default)]
    pub excluded_scope_patterns: Option<Vec<String>>,
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
            inner: RwLock::new(snapshot.sanitized_for_load()),
        }
    }

    pub async fn snapshot(&self) -> RuntimeSettingsSnapshot {
        self.inner.read().await.clone()
    }

    pub async fn update(&self, update: RuntimeSettingsUpdate) -> Result<RuntimeSettingsSnapshot> {
        if let Some(oast_polling_interval_secs) = update.oast_polling_interval_secs {
            if !(MIN_OAST_POLLING_INTERVAL_SECS..=MAX_OAST_POLLING_INTERVAL_SECS)
                .contains(&oast_polling_interval_secs)
            {
                bail!(
                    "OAST polling interval must be between {} and {} seconds",
                    MIN_OAST_POLLING_INTERVAL_SECS,
                    MAX_OAST_POLLING_INTERVAL_SECS
                );
            }
        }
        let mut current = self.inner.write().await;
        let mut candidate = current.clone();
        let requested_oast_provider = update.oast_provider.clone();
        let requested_oast_token = update.oast_token.clone();
        let target_oast_provider = requested_oast_provider
            .clone()
            .unwrap_or_else(|| candidate.oast_provider.clone());
        let requested_real_oast_token = requested_oast_token
            .as_deref()
            .is_some_and(|token| token != OAST_TOKEN_REDACTION && !token.is_empty());
        if target_oast_provider == crate::oast::OastProvider::Boast && requested_real_oast_token {
            bail!("BOAST provider does not use an OAST token");
        }

        if let Some(intercept_enabled) = update.intercept_enabled {
            candidate.intercept_enabled = intercept_enabled;
        }

        if let Some(websocket_capture_enabled) = update.websocket_capture_enabled {
            candidate.websocket_capture_enabled = websocket_capture_enabled;
        }

        if let Some(excluded) = update.excluded_scope_patterns {
            candidate.excluded_scope_patterns =
                normalize_bounded_scope_patterns("excluded scope pattern", excluded)?;
        }
        if let Some(scope_patterns) = update.scope_patterns {
            candidate.scope_patterns =
                normalize_bounded_scope_patterns("scope pattern", scope_patterns)?;
        }

        if let Some(passthrough_hosts) = update.passthrough_hosts {
            candidate.passthrough_hosts =
                normalize_bounded_scope_patterns("passthrough host", passthrough_hosts)?;
        }

        if let Some(upstream_insecure) = update.upstream_insecure {
            candidate.upstream_insecure = upstream_insecure;
        }

        if let Some(intercept_scope_only) = update.intercept_scope_only {
            candidate.intercept_scope_only = intercept_scope_only;
        }

        if let Some(oast_enabled) = update.oast_enabled {
            candidate.oast_enabled = oast_enabled;
        }
        if let Some(oast_server_url) = update.oast_server_url {
            validate_runtime_text_field("OAST server URL", &oast_server_url)?;
            crate::oast::validate_oast_server_url(&oast_server_url)
                .map_err(|error| anyhow::anyhow!(error))?;
            candidate.oast_server_url = oast_server_url;
        }
        if let Some(oast_token) = requested_oast_token.as_deref() {
            if oast_token != OAST_TOKEN_REDACTION {
                validate_runtime_text_field("OAST token", oast_token)?;
                candidate.oast_token = oast_token.to_string();
            }
        }
        if let Some(oast_polling_interval_secs) = update.oast_polling_interval_secs {
            candidate.oast_polling_interval_secs = oast_polling_interval_secs;
        }
        if let Some(oast_provider) = requested_oast_provider {
            let provider_changed = oast_provider != candidate.oast_provider;
            if provider_changed && !requested_real_oast_token {
                candidate.oast_token.clear();
            }
            candidate.oast_provider = oast_provider;
        }
        if candidate.oast_provider == crate::oast::OastProvider::Boast {
            candidate.oast_token.clear();
        }

        *current = candidate.clone();
        Ok(candidate)
    }

    pub async fn replace_snapshot(
        &self,
        snapshot: RuntimeSettingsSnapshot,
    ) -> RuntimeSettingsSnapshot {
        let mut current = self.inner.write().await;
        *current = snapshot.sanitized_for_load();
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
        crate::scope::is_host_in_scope(
            host,
            &current.scope_patterns,
            &current.excluded_scope_patterns,
        )
    }

    pub async fn scope_lists(&self) -> (Vec<String>, Vec<String>) {
        let current = self.inner.read().await;
        (
            current.scope_patterns.clone(),
            current.excluded_scope_patterns.clone(),
        )
    }

    pub async fn is_passthrough(&self, host: &str) -> bool {
        let current = self.inner.read().await;
        matches_passthrough(host, &current.passthrough_hosts)
    }
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self::new()
    }
}

fn normalize_scope_patterns(patterns: Vec<String>) -> Vec<String> {
    patterns
        .into_iter()
        .filter_map(|pattern| normalize_scope_pattern(&pattern))
        .collect()
}

fn normalize_scope_pattern(pattern: &str) -> Option<String> {
    let mut value = pattern.trim().to_ascii_lowercase();
    if value.is_empty() {
        return None;
    }
    if let Some((_, rest)) = value.split_once("://") {
        value = rest.to_string();
    } else if let Some(rest) = value.strip_prefix("//") {
        value = rest.to_string();
    }
    let host = value.split(['/', '?', '#']).next().unwrap_or("").trim();
    if host.contains('@') {
        return None;
    }
    let host = host_without_port(host).to_string();
    (!host.is_empty()).then_some(host)
}

fn normalize_bounded_scope_patterns(label: &str, patterns: Vec<String>) -> Result<Vec<String>> {
    let normalized = normalize_scope_patterns(patterns);
    if normalized.len() > MAX_RUNTIME_PATTERN_ENTRIES {
        bail!("{label} list cannot exceed {MAX_RUNTIME_PATTERN_ENTRIES} entries");
    }
    for pattern in &normalized {
        if pattern.len() > MAX_RUNTIME_PATTERN_BYTES {
            bail!("{label} cannot exceed {MAX_RUNTIME_PATTERN_BYTES} bytes");
        }
    }
    Ok(normalized)
}

fn validate_runtime_text_field(label: &str, value: &str) -> Result<()> {
    if value.len() > MAX_RUNTIME_TEXT_FIELD_BYTES {
        bail!("{label} cannot exceed {MAX_RUNTIME_TEXT_FIELD_BYTES} bytes");
    }
    Ok(())
}

fn matches_passthrough(host: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return false;
    }

    crate::scope::host_matches_any(host, patterns)
}

fn host_without_port(host: &str) -> &str {
    let trimmed = host.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    if trimmed.matches(':').count() == 1 {
        return trimmed
            .split_once(':')
            .map(|(value, _)| value)
            .unwrap_or(trimmed);
    }
    trimmed
}

#[cfg(test)]
mod tests {
    use super::{
        RuntimeSettings, RuntimeSettingsSnapshot, RuntimeSettingsUpdate, OAST_TOKEN_REDACTION,
    };

    #[test]
    fn runtime_settings_accepts_legacy_partial_snapshot() {
        let snapshot: RuntimeSettingsSnapshot =
            serde_json::from_value(serde_json::json!({ "intercept_enabled": true }))
                .expect("legacy runtime settings should deserialize");

        assert!(snapshot.intercept_enabled);
        assert!(snapshot.websocket_capture_enabled);
        assert!(snapshot.scope_patterns.is_empty());
        assert!(snapshot.passthrough_hosts.is_empty());
        assert!(snapshot.upstream_insecure);
        assert!(snapshot.intercept_scope_only);
    }

    #[test]
    fn runtime_settings_defaults_unknown_oast_provider_on_load() {
        let snapshot: RuntimeSettingsSnapshot = serde_json::from_value(serde_json::json!({
            "oast_provider": "retired-provider",
            "oast_token": "stale-token"
        }))
        .expect("unknown durable OAST providers should not corrupt runtime settings");

        assert_eq!(snapshot.oast_provider, crate::oast::OastProvider::Custom);
        assert_eq!(snapshot.oast_token, "stale-token");
    }

    #[test]
    fn runtime_settings_read_view_redacts_oast_token() {
        let snapshot = RuntimeSettingsSnapshot {
            oast_token: "secret-token".to_string(),
            ..RuntimeSettingsSnapshot::default()
        };

        let redacted = snapshot.clone().redacted_for_read();

        assert_eq!(snapshot.oast_token, "secret-token");
        assert_eq!(redacted.oast_token, OAST_TOKEN_REDACTION);
    }

    #[tokio::test]
    async fn runtime_settings_from_snapshot_sanitizes_durable_fields() {
        let settings = RuntimeSettings::from_snapshot(RuntimeSettingsSnapshot {
            intercept_enabled: true,
            scope_patterns: vec![" Example.COM ".to_string()],
            passthrough_hosts: vec![
                "example.test".to_string();
                super::MAX_RUNTIME_PATTERN_ENTRIES + 1
            ],
            oast_server_url: "u".repeat(super::MAX_RUNTIME_TEXT_FIELD_BYTES + 1),
            oast_token: "t".repeat(super::MAX_RUNTIME_TEXT_FIELD_BYTES + 1),
            oast_polling_interval_secs: 0,
            ..RuntimeSettingsSnapshot::default()
        });
        let snapshot = settings.snapshot().await;

        assert!(snapshot.intercept_enabled);
        assert_eq!(snapshot.scope_patterns, vec!["example.com"]);
        assert!(snapshot.passthrough_hosts.is_empty());
        assert!(snapshot.oast_server_url.is_empty());
        assert!(snapshot.oast_token.is_empty());
        assert_eq!(
            snapshot.oast_polling_interval_secs,
            super::default_oast_interval()
        );
    }

    #[tokio::test]
    async fn runtime_settings_rejects_oast_server_url_with_request_components() {
        let settings = RuntimeSettings::new();
        for server_url in [
            "http://127.0.0.1/admin?x=1",
            "http://user@example.test",
            "file:///tmp/oast",
            "https://oast.example.test/#frag",
            " oast.example.test ",
        ] {
            let error = settings
                .update(RuntimeSettingsUpdate {
                    oast_server_url: Some(server_url.to_string()),
                    ..RuntimeSettingsUpdate::default()
                })
                .await
                .unwrap_err();

            assert!(
                error.to_string().contains("OAST server URL"),
                "{server_url} should be rejected"
            );
        }

        settings
            .update(RuntimeSettingsUpdate {
                oast_server_url: Some("https://oast.example.test:8443".to_string()),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap();
        assert_eq!(
            settings.snapshot().await.oast_server_url,
            "https://oast.example.test:8443"
        );
    }

    #[tokio::test]
    async fn runtime_settings_normalizes_scope_url_patterns_to_hosts() {
        let settings = RuntimeSettings::new();
        let snapshot = settings
            .update(RuntimeSettingsUpdate {
                scope_patterns: Some(vec![
                    " HTTPS://Example.COM:443/api?x=1#frag ".to_string(),
                    "example.org/path".to_string(),
                    "wss://*.Example.NET/socket".to_string(),
                    "/path-only".to_string(),
                ]),
                passthrough_hosts: Some(vec!["https://PassThrough.TEST/tunnel".to_string()]),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap();

        assert_eq!(
            snapshot.scope_patterns,
            vec!["example.com", "example.org", "*.example.net"]
        );
        assert_eq!(snapshot.passthrough_hosts, vec!["passthrough.test"]);
        assert!(settings.is_in_scope("api.example.net").await);
        assert!(settings.is_in_scope("api.example.net.").await);
        assert!(settings.is_in_scope("example.org:9443").await);
        assert!(settings.is_in_scope("example.org.:9443").await);
        assert!(settings.is_passthrough("passthrough.test:443").await);
        assert!(settings.is_passthrough("passthrough.test.:443").await);
    }

    #[tokio::test]
    async fn runtime_settings_rejects_scope_url_patterns_with_userinfo() {
        let settings = RuntimeSettings::new();
        let snapshot = settings
            .update(RuntimeSettingsUpdate {
                scope_patterns: Some(vec![
                    "https://user:pass@example.com/path".to_string(),
                    "//user@example.org".to_string(),
                    "https://safe.example.test/path".to_string(),
                ]),
                passthrough_hosts: Some(vec![
                    "https://user:pass@passthrough.test/path".to_string(),
                    "passthrough-safe.test".to_string(),
                ]),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap();

        assert_eq!(snapshot.scope_patterns, vec!["safe.example.test"]);
        assert_eq!(snapshot.passthrough_hosts, vec!["passthrough-safe.test"]);
    }

    #[tokio::test]
    async fn runtime_settings_clears_boast_token_on_load() {
        let settings = RuntimeSettings::from_snapshot(RuntimeSettingsSnapshot {
            oast_provider: crate::oast::OastProvider::Boast,
            oast_token: "unused-token".to_string(),
            ..RuntimeSettingsSnapshot::default()
        });

        assert!(settings.snapshot().await.oast_token.is_empty());
    }

    #[tokio::test]
    async fn runtime_settings_rejects_boast_token_updates() {
        let settings = RuntimeSettings::new();
        let error = settings
            .update(RuntimeSettingsUpdate {
                oast_provider: Some(crate::oast::OastProvider::Boast),
                oast_token: Some("manual-token".to_string()),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap_err();

        assert!(error.to_string().contains("BOAST provider"));
        let snapshot = settings.snapshot().await;
        assert_eq!(snapshot.oast_provider, crate::oast::OastProvider::Custom);
        assert!(snapshot.oast_token.is_empty());
    }

    #[tokio::test]
    async fn runtime_settings_accepts_empty_boast_token_update() {
        let settings = RuntimeSettings::new();
        let snapshot = settings
            .update(RuntimeSettingsUpdate {
                oast_provider: Some(crate::oast::OastProvider::Boast),
                oast_token: Some(String::new()),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap();

        assert_eq!(snapshot.oast_provider, crate::oast::OastProvider::Boast);
        assert!(snapshot.oast_token.is_empty());
    }

    #[tokio::test]
    async fn runtime_settings_clears_stale_oast_token_on_provider_change() {
        let settings = RuntimeSettings::from_snapshot(RuntimeSettingsSnapshot {
            oast_provider: crate::oast::OastProvider::Custom,
            oast_token: "stale-token".to_string(),
            ..RuntimeSettingsSnapshot::default()
        });
        let snapshot = settings
            .update(RuntimeSettingsUpdate {
                oast_provider: Some(crate::oast::OastProvider::Interactsh),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap();

        assert_eq!(
            snapshot.oast_provider,
            crate::oast::OastProvider::Interactsh
        );
        assert!(snapshot.oast_token.is_empty());
    }

    #[tokio::test]
    async fn runtime_settings_keeps_real_oast_token_on_provider_change() {
        let settings = RuntimeSettings::from_snapshot(RuntimeSettingsSnapshot {
            oast_provider: crate::oast::OastProvider::Custom,
            oast_token: "old-token".to_string(),
            ..RuntimeSettingsSnapshot::default()
        });
        let snapshot = settings
            .update(RuntimeSettingsUpdate {
                oast_provider: Some(crate::oast::OastProvider::Interactsh),
                oast_token: Some("new-token".to_string()),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap();

        assert_eq!(
            snapshot.oast_provider,
            crate::oast::OastProvider::Interactsh
        );
        assert_eq!(snapshot.oast_token, "new-token");
    }

    #[tokio::test]
    async fn runtime_settings_rejects_out_of_range_oast_polling_interval() {
        let settings = RuntimeSettings::new();
        let error = settings
            .update(RuntimeSettingsUpdate {
                oast_polling_interval_secs: Some(0),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap_err();

        assert!(error.to_string().contains("OAST polling interval"));
        assert_eq!(settings.snapshot().await.oast_polling_interval_secs, 5);

        let error = settings
            .update(RuntimeSettingsUpdate {
                oast_polling_interval_secs: Some(u64::MAX),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("OAST polling interval"));
        assert_eq!(settings.snapshot().await.oast_polling_interval_secs, 5);
    }

    #[tokio::test]
    async fn runtime_settings_rejects_oversized_durable_fields() {
        let settings = RuntimeSettings::new();
        let error = settings
            .update(RuntimeSettingsUpdate {
                scope_patterns: Some(vec!["x".repeat(super::MAX_RUNTIME_PATTERN_BYTES + 1)]),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("scope pattern"));

        let error = settings
            .update(RuntimeSettingsUpdate {
                passthrough_hosts: Some(vec![
                    "example.test".to_string();
                    super::MAX_RUNTIME_PATTERN_ENTRIES + 1
                ]),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("passthrough host list"));

        let error = settings
            .update(RuntimeSettingsUpdate {
                intercept_enabled: Some(true),
                oast_server_url: Some("x".repeat(super::MAX_RUNTIME_TEXT_FIELD_BYTES + 1)),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("OAST server URL"));
        assert!(!settings.snapshot().await.intercept_enabled);
    }

    #[tokio::test]
    async fn runtime_settings_keeps_oast_token_on_redaction_sentinel() {
        let settings = RuntimeSettings::new();
        settings
            .update(RuntimeSettingsUpdate {
                oast_token: Some("real-secret".to_string()),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap();
        let snapshot = settings
            .update(RuntimeSettingsUpdate {
                oast_token: Some(OAST_TOKEN_REDACTION.to_string()),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap();

        assert_eq!(snapshot.oast_token, "real-secret");
    }
}
