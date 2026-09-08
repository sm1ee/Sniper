use std::collections::{HashSet, VecDeque};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use aes::Aes256;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use cfb_mode::Decryptor as CfbDecryptor;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use rand::Rng;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::sha2::Sha256;
use rsa::Oaep;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};
use url::{form_urlencoded, Url};
use uuid::Uuid;

use crate::{session::SessionContext, state::AppState};

const MAX_OAST_BROADCAST_CAPACITY: usize = 4096;
const MAX_OAST_POLL_BODY_BYTES: usize = 1_048_576;
const MAX_OAST_POLL_CALLBACKS: usize = 4096;
const MAX_OAST_CALLBACK_FIELD_BYTES: usize = 64 * 1024;

// ── Provider enum ──

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OastProvider {
    Interactsh,
    Boast,
    #[default]
    Custom,
}

impl std::fmt::Display for OastProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Interactsh => write!(f, "interactsh"),
            Self::Boast => write!(f, "boast"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

// ── Configuration ──

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
    #[serde(default)]
    pub provider: OastProvider,
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
            provider: OastProvider::default(),
        }
    }
}

// ── Callback types (backward compatible) ──

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

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct OastCallbackDedupKey {
    protocol: String,
    remote_addr: String,
    correlation_id: String,
    raw_data: String,
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

// ── Registration state for Interactsh ──

#[allow(clippy::large_enum_variant)]
enum RegistrationState {
    None,
    Interactsh {
        server_url: String,
        token: String,
        correlation_id: String,
        secret_key: String,
        private_key: rsa::RsaPrivateKey,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredOastRegistration {
    #[serde(default)]
    pub server_url: String,
    #[serde(default)]
    pub token: String,
    pub correlation_id: String,
    pub secret_key: String,
    pub private_key_pkcs1_pem: String,
}

// ── Interactsh registration result ──

struct InteractshRegistration {
    correlation_id: String,
    secret_key: String,
    private_key: rsa::RsaPrivateKey,
}

struct PendingInteractshDeregistration {
    base_url: String,
    correlation_id: String,
    secret_key: String,
    token: String,
}

// ── OastStore ──

/// Store for OAST callbacks. Mirrors ScannerStore pattern.
pub struct OastStore {
    max_entries: usize,
    entries: RwLock<VecDeque<OastCallback>>,
    events: broadcast::Sender<OastCallbackSummary>,
    config: RwLock<OastConfig>,
    registration: RwLock<RegistrationState>,
    cleared_keys: RwLock<VecDeque<OastCallbackDedupKey>>,
    clear_generation: AtomicU64,
}

impl OastStore {
    pub fn new(max_entries: usize) -> Self {
        Self::new_with_config(max_entries, OastConfig::default())
    }

    pub fn new_with_config(max_entries: usize, config: OastConfig) -> Self {
        let (events, _) = broadcast::channel(max_entries.clamp(64, MAX_OAST_BROADCAST_CAPACITY));
        Self {
            max_entries,
            entries: RwLock::new(VecDeque::new()),
            events,
            config: RwLock::new(config),
            registration: RwLock::new(RegistrationState::None),
            cleared_keys: RwLock::new(VecDeque::new()),
            clear_generation: AtomicU64::new(0),
        }
    }

    pub async fn push(&self, callback: OastCallback) -> bool {
        self.push_inner(callback, None).await
    }

    pub async fn push_if_generation(&self, callback: OastCallback, generation: u64) -> bool {
        self.push_inner(callback, Some(generation)).await
    }

    async fn push_inner(&self, callback: OastCallback, generation: Option<u64>) -> bool {
        if generation.is_some_and(|expected| self.clear_generation() != expected) {
            return false;
        }
        let dedup_key = callback_dedup_key(&callback);
        let summary = callback.summary();
        let cleared_keys = self.cleared_keys.read().await;
        if cleared_keys.iter().any(|cleared| cleared == &dedup_key) {
            return false;
        }
        let mut entries = self.entries.write().await;
        if generation.is_some_and(|expected| self.clear_generation() != expected) {
            return false;
        }
        if entries
            .iter()
            .any(|existing| callback_dedup_key(existing) == dedup_key)
        {
            return false;
        }
        entries.push_front(callback);
        while entries.len() > self.max_entries {
            entries.pop_back();
        }
        let _ = self.events.send(summary);
        true
    }

    pub fn clear_generation(&self) -> u64 {
        self.clear_generation.load(Ordering::Acquire)
    }

    pub fn restore_clear_generation(&self, generation: u64) {
        self.clear_generation.store(generation, Ordering::Release);
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
        self.clear_generation.fetch_add(1, Ordering::AcqRel);
        let mut cleared_keys = self.cleared_keys.write().await;
        let mut entries = self.entries.write().await;
        for callback in entries.iter() {
            push_cleared_key(
                &mut cleared_keys,
                callback_dedup_key(callback),
                self.max_entries,
            );
        }
        entries.clear();
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

    pub async fn snapshot_cleared_keys(&self) -> Vec<OastCallbackDedupKey> {
        self.cleared_keys.read().await.iter().cloned().collect()
    }

    pub async fn snapshot_registration(&self) -> Option<StoredOastRegistration> {
        let registration = self.registration.read().await;
        match &*registration {
            RegistrationState::Interactsh {
                server_url,
                token,
                correlation_id,
                secret_key,
                private_key,
            } => private_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .ok()
                .map(|pem| StoredOastRegistration {
                    server_url: server_url.clone(),
                    token: token.clone(),
                    correlation_id: correlation_id.clone(),
                    secret_key: secret_key.clone(),
                    private_key_pkcs1_pem: pem.to_string(),
                }),
            RegistrationState::None => None,
        }
    }

    pub fn restore_registration_blocking(&self, registration: Option<StoredOastRegistration>) {
        let restored = registration
            .and_then(|stored| {
                let private_key =
                    rsa::RsaPrivateKey::from_pkcs1_pem(&stored.private_key_pkcs1_pem).ok()?;
                Some(RegistrationState::Interactsh {
                    server_url: stored.server_url,
                    token: stored.token,
                    correlation_id: stored.correlation_id,
                    secret_key: stored.secret_key,
                    private_key,
                })
            })
            .unwrap_or(RegistrationState::None);
        *self.registration_mut_blocking() = restored;
    }

    pub async fn restore(&self, callbacks: Vec<OastCallback>) {
        let mut entries = self.entries.write().await;
        *entries = callbacks_to_entries(callbacks, self.max_entries);
    }

    pub fn restore_blocking(&self, callbacks: Vec<OastCallback>) {
        *self.entries_mut_blocking() = callbacks_to_entries(callbacks, self.max_entries);
    }

    pub async fn restore_cleared_keys(&self, keys: Vec<OastCallbackDedupKey>) {
        *self.cleared_keys.write().await = cleared_keys_to_entries(keys, self.max_entries);
    }

    pub fn restore_cleared_keys_blocking(&self, keys: Vec<OastCallbackDedupKey>) {
        *self.cleared_keys_mut_blocking() = cleared_keys_to_entries(keys, self.max_entries);
    }

    /// Blocking mutable access to entries — for use outside async context (e.g. session restore).
    pub fn entries_mut_blocking(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, VecDeque<OastCallback>> {
        // tokio::sync::RwLock doesn't have blocking_write, so use try_write in a spin.
        // At init time there's no contention so this succeeds immediately.
        loop {
            if let Ok(guard) = self.entries.try_write() {
                return guard;
            }
            std::thread::yield_now();
        }
    }

    fn registration_mut_blocking(&self) -> tokio::sync::RwLockWriteGuard<'_, RegistrationState> {
        loop {
            if let Ok(guard) = self.registration.try_write() {
                return guard;
            }
            std::thread::yield_now();
        }
    }

    fn cleared_keys_mut_blocking(
        &self,
    ) -> tokio::sync::RwLockWriteGuard<'_, VecDeque<OastCallbackDedupKey>> {
        loop {
            if let Ok(guard) = self.cleared_keys.try_write() {
                return guard;
            }
            std::thread::yield_now();
        }
    }

    /// Returns (correlation_id, payload_suffix) if an Interactsh session is registered.
    pub async fn get_registration_info(&self) -> Option<(String, String)> {
        let config = self.config.read().await;
        if !config.enabled || config.provider != OastProvider::Interactsh {
            return None;
        }
        let reg = self.registration.read().await;
        match &*reg {
            RegistrationState::Interactsh {
                server_url,
                token,
                correlation_id,
                ..
            } => {
                if server_url != &config.server_url || token != &config.token {
                    return None;
                }
                let domain = extract_domain(&config.server_url);
                Some((correlation_id.clone(), domain))
            }
            RegistrationState::None => None,
        }
    }

    pub async fn registration_matches_config(&self, config: &OastConfig) -> bool {
        let reg = self.registration.read().await;
        match &*reg {
            RegistrationState::Interactsh {
                server_url, token, ..
            } => server_url == &config.server_url && token == &config.token,
            RegistrationState::None => false,
        }
    }

    async fn set_registration(&self, state: RegistrationState) {
        *self.registration.write().await = state;
    }

    async fn clear_registration(&self) {
        *self.registration.write().await = RegistrationState::None;
    }
}

fn callbacks_to_entries(
    callbacks: Vec<OastCallback>,
    max_entries: usize,
) -> VecDeque<OastCallback> {
    let mut seen = HashSet::new();
    callbacks
        .into_iter()
        .filter(callback_fields_within_oast_limits)
        .filter(|callback| seen.insert(callback_dedup_key(callback)))
        .take(max_entries)
        .collect()
}

fn cleared_keys_to_entries(
    keys: Vec<OastCallbackDedupKey>,
    max_entries: usize,
) -> VecDeque<OastCallbackDedupKey> {
    let mut seen = HashSet::new();
    keys.into_iter()
        .filter(|key| seen.insert(key.clone()))
        .take(max_entries)
        .collect()
}

fn push_cleared_key(
    cleared_keys: &mut VecDeque<OastCallbackDedupKey>,
    key: OastCallbackDedupKey,
    max_entries: usize,
) {
    if cleared_keys.iter().any(|cleared| cleared == &key) {
        return;
    }
    cleared_keys.push_front(key);
    while cleared_keys.len() > max_entries {
        cleared_keys.pop_back();
    }
}

fn callback_dedup_key(callback: &OastCallback) -> OastCallbackDedupKey {
    OastCallbackDedupKey {
        protocol: callback.protocol.trim().to_ascii_lowercase(),
        remote_addr: callback.remote_addr.trim().to_string(),
        correlation_id: callback.correlation_id.trim().to_string(),
        raw_data: callback.raw_data.clone(),
    }
}

// ── Helper: extract domain from URL ──

fn extract_domain(url: &str) -> String {
    if let Ok(domain) = oast_payload_domain(url) {
        return domain;
    }
    let base = url.trim_end_matches('/');
    base.strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))
        .unwrap_or(base)
        .to_string()
}

// ── Helper: generate random hex string ──

fn random_hex(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| format!("{:x}", rng.gen::<u8>() & 0x0f))
        .collect()
}

// ── Public utility functions (backward compatible) ──

/// Generate a unique correlation ID for OAST payloads.
pub fn generate_correlation_id() -> String {
    let id = Uuid::new_v4();
    let hex = id.as_simple().to_string();
    hex[..12].to_string()
}

/// Build an OAST payload URL from server URL and correlation ID.
pub fn build_oast_payload(server_url: &str, correlation_id: &str) -> String {
    if let Ok(payload) = build_oast_payload_checked(server_url, correlation_id) {
        return payload;
    }
    let base = server_url.trim_end_matches('/');
    if let Some(domain) = base
        .strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))
    {
        format!("{correlation_id}.{domain}")
    } else {
        format!("{base}/{correlation_id}")
    }
}

/// Build an OAST payload, rejecting server URLs that cannot produce a valid DNS payload.
pub fn build_oast_payload_checked(
    server_url: &str,
    correlation_id: &str,
) -> Result<String, String> {
    let trimmed = server_url.trim();
    if trimmed.is_empty() {
        return Err("OAST server URL is required before generating a payload.".to_string());
    }

    match Url::parse(trimmed) {
        Ok(url) => {
            let scheme = url.scheme();
            if scheme != "http" && scheme != "https" {
                return Err("OAST server URL must use http or https.".to_string());
            }
            if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
                return Err(
                    "OAST server URL cannot include a path, query, or fragment.".to_string()
                );
            }
            let domain = oast_payload_domain(trimmed)?;
            Ok(format!("{correlation_id}.{domain}"))
        }
        Err(_) => {
            let base = trimmed.trim_end_matches('/');
            if base.is_empty() {
                return Err("OAST server URL is required before generating a payload.".to_string());
            }
            if base.contains('/')
                || base.contains('?')
                || base.contains('#')
                || base.chars().any(char::is_whitespace)
            {
                return Err(
                    "OAST server URL must be a host or http/https URL without path, query, or fragment."
                        .to_string(),
                );
            }
            Ok(format!("{base}/{correlation_id}"))
        }
    }
}

fn oast_payload_domain(server_url: &str) -> Result<String, String> {
    let url =
        Url::parse(server_url.trim()).map_err(|_| "OAST server URL is invalid.".to_string())?;
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err("OAST server URL must use http or https.".to_string());
    }
    let domain = url
        .host_str()
        .map(str::trim)
        .map(|host| host.trim_end_matches('.'))
        .filter(|host| !host.is_empty())
        .ok_or_else(|| "OAST server URL must include a host.".to_string())?;
    Ok(domain.to_string())
}

pub fn validate_oast_server_url(server_url: &str) -> Result<(), String> {
    let trimmed = server_url.trim();
    if trimmed != server_url {
        return Err("OAST server URL must not include surrounding whitespace.".to_string());
    }
    if trimmed.is_empty() {
        return Ok(());
    }

    let url = Url::parse(trimmed).map_err(|_| "OAST server URL is invalid.".to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("OAST server URL must use http or https.".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("OAST server URL must not include credentials.".to_string());
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("OAST server URL must include a host.".to_string());
    }
    if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
        return Err("OAST server URL must not include a path, query, or fragment.".to_string());
    }
    Ok(())
}

fn oast_endpoint_url(base_url: &str, path: &str, query: &[(&str, &str)]) -> String {
    let base = base_url.trim_end_matches('/');
    let path = path.trim_start_matches('/');
    let endpoint = format!("{base}/{path}");
    if query.is_empty() {
        return endpoint;
    }

    if let Ok(mut url) = Url::parse(&endpoint) {
        {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }
        return url.to_string();
    }

    let mut encoded = form_urlencoded::Serializer::new(String::new());
    for (key, value) in query {
        encoded.append_pair(key, value);
    }
    format!("{endpoint}?{}", encoded.finish())
}

async fn read_limited_oast_poll_body(
    response: reqwest::Response,
    provider: &'static str,
) -> Option<String> {
    if let Some(length) = response.content_length() {
        if length > MAX_OAST_POLL_BODY_BYTES as u64 {
            debug!(
                provider,
                length,
                max = MAX_OAST_POLL_BODY_BYTES,
                "OAST poll body rejected by content length"
            );
            return None;
        }
    }

    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) => {
                debug!(provider, %error, "OAST poll body read failed");
                return None;
            }
        };
        if body.len().saturating_add(chunk.len()) > MAX_OAST_POLL_BODY_BYTES {
            debug!(
                provider,
                max = MAX_OAST_POLL_BODY_BYTES,
                "OAST poll body rejected after streaming limit"
            );
            return None;
        }
        body.extend_from_slice(&chunk);
    }

    match String::from_utf8(body) {
        Ok(text) => Some(text),
        Err(error) => {
            debug!(provider, %error, "OAST poll body was not valid UTF-8");
            None
        }
    }
}

fn callback_fields_within_oast_limits(callback: &OastCallback) -> bool {
    callback.protocol.len() <= MAX_OAST_CALLBACK_FIELD_BYTES
        && callback.remote_addr.len() <= MAX_OAST_CALLBACK_FIELD_BYTES
        && callback.raw_data.len() <= MAX_OAST_CALLBACK_FIELD_BYTES
        && callback.correlation_id.len() <= MAX_OAST_CALLBACK_FIELD_BYTES
}

// ── Generate payload (multi-backend aware) ──

/// Generate an OAST payload. Returns (correlation_id, full_payload).
///
/// - Interactsh: uses registered correlation_id + random nonce + server domain
/// - BOAST / Custom: uses a fresh UUID-based correlation_id + server URL
pub async fn generate_payload(store: &OastStore) -> Option<(String, String)> {
    let config = store.get_config().await;
    if !config.enabled || config.server_url.is_empty() {
        return None;
    }

    match config.provider {
        OastProvider::Interactsh => {
            let reg = store.registration.read().await;
            match &*reg {
                RegistrationState::Interactsh {
                    server_url,
                    token,
                    correlation_id,
                    ..
                } => {
                    if server_url != &config.server_url || token != &config.token {
                        debug!("Interactsh registration does not match current config");
                        return None;
                    }
                    let payload = build_interactsh_payload(correlation_id, &config.server_url);
                    Some((correlation_id.clone(), payload))
                }
                RegistrationState::None => {
                    debug!("Interactsh not registered, refusing unrecoverable payload generation");
                    None
                }
            }
        }
        OastProvider::Boast | OastProvider::Custom => {
            let cid = generate_correlation_id();
            match build_oast_payload_checked(&config.server_url, &cid) {
                Ok(payload) => Some((cid, payload)),
                Err(error) => {
                    warn!("Refusing to generate OAST payload: {error}");
                    None
                }
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════════
// Interactsh backend
// ══════════════════════════════════════════════════════════════════════

/// Register with an Interactsh server.
async fn register_interactsh(
    base_url: &str,
    token: &str,
    client: &reqwest::Client,
) -> Result<InteractshRegistration, String> {
    // 1. Generate RSA-2048 keypair (scope rng to avoid Send issues across await)
    let (private_key, pem_b64, correlation_id, secret_key) = {
        let mut rng = rand::thread_rng();
        let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| format!("RSA keygen failed: {e}"))?;
        let pub_key = rsa::RsaPublicKey::from(&priv_key);

        // 2. Export public key as PKCS1 PEM
        let pem_doc = pub_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .map_err(|e| format!("PKCS1 PEM export failed: {e}"))?;
        let pem_b64 = BASE64.encode(pem_doc.as_bytes());

        // 3. Generate correlation_id (20 hex chars) and random secret_key
        let cid = random_hex(20);
        let sk = random_hex(20);
        (priv_key, pem_b64, cid, sk)
    };

    // 4. Build registration URL
    let url = oast_endpoint_url(base_url, "register", &[]);

    // 5. POST registration
    let body = serde_json::json!({
        "public-key": pem_b64,
        "secret-key": secret_key,
        "correlation-id": correlation_id,
    });

    let mut req = client
        .post(&url)
        .json(&body)
        .timeout(Duration::from_secs(15));
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("register request failed: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();
        return Err(format!("register returned {status}: {body_text}"));
    }

    info!(correlation_id = %correlation_id, "Interactsh registration successful");

    Ok(InteractshRegistration {
        correlation_id,
        secret_key,
        private_key,
    })
}

/// Deregister from an Interactsh server.
async fn deregister_interactsh(
    base_url: &str,
    correlation_id: &str,
    secret_key: &str,
    token: &str,
    client: &reqwest::Client,
) {
    let url = oast_endpoint_url(base_url, "deregister", &[]);

    let body = serde_json::json!({
        "correlation-id": correlation_id,
        "secret-key": secret_key,
    });

    let mut req = client
        .post(&url)
        .json(&body)
        .timeout(Duration::from_secs(10));
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    match req.send().await {
        Ok(r) if r.status().is_success() => {
            info!(correlation_id = %correlation_id, "Interactsh deregistration successful");
        }
        Ok(r) => {
            debug!(status = %r.status(), "Interactsh deregister non-200");
        }
        Err(e) => {
            debug!(error = %e, "Interactsh deregister failed");
        }
    }
}

async fn pending_interactsh_deregistration(
    store: &OastStore,
    prev_url: &Option<String>,
) -> Option<PendingInteractshDeregistration> {
    let registration = {
        let reg = store.registration.read().await;
        match &*reg {
            RegistrationState::Interactsh {
                server_url,
                correlation_id,
                secret_key,
                token,
                ..
            } => Some((
                server_url.clone(),
                correlation_id.clone(),
                secret_key.clone(),
                token.clone(),
            )),
            RegistrationState::None => None,
        }
    };

    let (stored_base_url, correlation_id, secret_key, stored_token) = registration?;
    let base_url = if stored_base_url.is_empty() {
        prev_url.as_ref()?.clone()
    } else {
        stored_base_url
    };
    let token = if stored_token.is_empty() {
        store.get_config().await.token
    } else {
        stored_token
    };
    Some(PendingInteractshDeregistration {
        base_url,
        correlation_id,
        secret_key,
        token,
    })
}

fn spawn_interactsh_deregistration(
    pending: Option<PendingInteractshDeregistration>,
    client: reqwest::Client,
) {
    let Some(pending) = pending else {
        return;
    };
    tokio::spawn(async move {
        deregister_interactsh(
            &pending.base_url,
            &pending.correlation_id,
            &pending.secret_key,
            &pending.token,
            &client,
        )
        .await;
    });
}

fn spawn_interactsh_registration_cleanup(
    config: &OastConfig,
    registration: InteractshRegistration,
    client: reqwest::Client,
) {
    spawn_interactsh_deregistration(
        Some(PendingInteractshDeregistration {
            base_url: config.server_url.clone(),
            correlation_id: registration.correlation_id,
            secret_key: registration.secret_key,
            token: config.token.clone(),
        }),
        client,
    );
}

/// Poll an Interactsh server for new interactions.
async fn poll_interactsh(
    base_url: &str,
    correlation_id: &str,
    secret_key: &str,
    private_key: &rsa::RsaPrivateKey,
    token: &str,
    client: &reqwest::Client,
) -> Vec<OastCallback> {
    let url = oast_endpoint_url(
        base_url,
        "poll",
        &[("id", correlation_id), ("secret", secret_key)],
    );

    let mut req = client.get(&url).timeout(Duration::from_secs(15));
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            debug!(error = %e, "Interactsh poll request failed");
            return vec![];
        }
    };

    if !resp.status().is_success() {
        debug!(status = %resp.status(), "Interactsh poll non-200");
        return vec![];
    }

    let text = match read_limited_oast_poll_body(resp, "interactsh").await {
        Some(text) => text,
        None => return vec![],
    };

    #[derive(Deserialize)]
    struct InteractshPollResponse {
        data: Option<Vec<String>>,
        #[allow(dead_code)]
        extra: Option<Vec<String>>,
        aes_key: Option<String>,
    }

    let poll_resp: InteractshPollResponse = match serde_json::from_str(&text) {
        Ok(p) => p,
        Err(e) => {
            debug!(error = %e, "Interactsh poll response parse failed");
            return vec![];
        }
    };

    let data = match poll_resp.data {
        Some(d) if !d.is_empty() => d,
        _ => return vec![],
    };
    if data.len() > MAX_OAST_POLL_CALLBACKS {
        debug!(
            received = data.len(),
            max = MAX_OAST_POLL_CALLBACKS,
            "Interactsh poll response truncated to callback limit"
        );
    }

    let aes_key_b64 = match poll_resp.aes_key {
        Some(k) if !k.is_empty() => k,
        _ => {
            debug!("Interactsh poll: no aes_key in response");
            return vec![];
        }
    };

    // Decrypt AES key: base64 decode -> RSA-OAEP-SHA256 decrypt
    let encrypted_aes_key = match BASE64.decode(&aes_key_b64) {
        Ok(b) => b,
        Err(e) => {
            debug!(error = %e, "Interactsh: failed to base64-decode aes_key");
            return vec![];
        }
    };

    let padding = Oaep::new::<Sha256>();
    let aes_key_bytes = match private_key.decrypt(padding, &encrypted_aes_key) {
        Ok(k) => k,
        Err(e) => {
            debug!(error = %e, "Interactsh: RSA-OAEP decrypt of aes_key failed");
            return vec![];
        }
    };

    // Decrypt each data entry: base64 decode -> AES-CFB decrypt -> parse JSON
    let mut callbacks = Vec::with_capacity(data.len().min(MAX_OAST_POLL_CALLBACKS));
    for entry in data.iter().take(MAX_OAST_POLL_CALLBACKS) {
        match decrypt_interactsh_entry(entry, &aes_key_bytes) {
            Some(cb) if callback_fields_within_oast_limits(&cb) => callbacks.push(cb),
            Some(_) => debug!("Interactsh callback rejected by field-size limit"),
            None => continue,
        }
    }

    callbacks
}

/// Decrypt a single base64-encoded Interactsh data entry using AES-256-CFB.
fn decrypt_interactsh_entry(entry: &str, aes_key: &[u8]) -> Option<OastCallback> {
    let encrypted = match BASE64.decode(entry) {
        Ok(b) => b,
        Err(e) => {
            debug!(error = %e, "Interactsh: failed to base64-decode data entry");
            return None;
        }
    };

    if encrypted.len() < 16 {
        debug!("Interactsh: encrypted data entry too short for IV");
        return None;
    }

    // IV is first 16 bytes, rest is ciphertext
    let (iv_bytes, ciphertext) = encrypted.split_at(16);

    // Ensure AES key is correct length (256-bit = 32 bytes)
    if aes_key.len() != 32 {
        // Interactsh sometimes returns shorter keys; pad or truncate
        debug!(
            key_len = aes_key.len(),
            "Interactsh: unexpected AES key length"
        );
        // Try to use as-is if 16 or 24 bytes by padding to 32
        let mut padded = [0u8; 32];
        let copy_len = aes_key.len().min(32);
        padded[..copy_len].copy_from_slice(&aes_key[..copy_len]);
        return decrypt_interactsh_entry_with_key(iv_bytes, ciphertext, &padded);
    }

    decrypt_interactsh_entry_with_key(iv_bytes, ciphertext, aes_key)
}

fn decrypt_interactsh_entry_with_key(
    iv: &[u8],
    ciphertext: &[u8],
    key: &[u8],
) -> Option<OastCallback> {
    let mut plaintext = ciphertext.to_vec();

    let decryptor: CfbDecryptor<Aes256> = match CfbDecryptor::<Aes256>::new_from_slices(key, iv) {
        Ok(d) => d,
        Err(e) => {
            debug!(error = %e, "Interactsh: AES-CFB init failed");
            return None;
        }
    };

    decryptor.decrypt(&mut plaintext);

    let json_str = match String::from_utf8(plaintext) {
        Ok(s) => s,
        Err(e) => {
            debug!(error = %e, "Interactsh: decrypted data not valid UTF-8");
            return None;
        }
    };

    // Parse the interaction JSON
    #[derive(Deserialize)]
    struct Interaction {
        #[serde(default)]
        protocol: String,
        #[serde(default, alias = "unique-id")]
        unique_id: String,
        #[serde(default, alias = "full-id")]
        #[allow(dead_code)]
        full_id: String,
        #[serde(default, alias = "raw-request")]
        raw_request: String,
        #[serde(default, alias = "raw-response")]
        #[allow(dead_code)]
        raw_response: String,
        #[serde(default, alias = "remote-address")]
        remote_address: String,
        #[serde(default)]
        #[allow(dead_code)]
        timestamp: String,
    }

    let interaction: Interaction = match serde_json::from_str(&json_str) {
        Ok(i) => i,
        Err(e) => {
            debug!(error = %e, "Interactsh: interaction JSON parse failed");
            return None;
        }
    };

    Some(OastCallback {
        id: Uuid::new_v4(),
        received_at: Utc::now(),
        protocol: interaction.protocol,
        remote_addr: interaction.remote_address,
        raw_data: interaction.raw_request,
        correlation_id: interaction.unique_id,
    })
}

/// Build an Interactsh-style subdomain payload.
/// Format: `{correlation_id}{nonce}.{domain}` where nonce is 13 random hex chars.
fn build_interactsh_payload(correlation_id: &str, server_url: &str) -> String {
    let domain = extract_domain(server_url);
    let nonce = random_hex(13);
    format!("{correlation_id}{nonce}.{domain}")
}

// ══════════════════════════════════════════════════════════════════════
// BOAST backend
// ══════════════════════════════════════════════════════════════════════

/// Poll a BOAST server for events.
async fn poll_boast(base_url: &str, client: &reqwest::Client) -> Vec<OastCallback> {
    let base = base_url.trim_end_matches('/');
    let url = format!("{base}/events");

    let resp = match client
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            debug!(error = %e, "BOAST poll failed");
            return vec![];
        }
    };

    if !resp.status().is_success() {
        debug!(status = %resp.status(), "BOAST poll non-200");
        return vec![];
    }

    let text = match read_limited_oast_poll_body(resp, "boast").await {
        Some(text) => text,
        None => return vec![],
    };

    #[derive(Deserialize)]
    struct BoastEvent {
        #[serde(default)]
        protocol: String,
        #[serde(default, alias = "remoteAddress")]
        remote_address: String,
        #[serde(default)]
        data: String,
        #[serde(default)]
        id: String,
    }

    let events: Vec<BoastEvent> = match serde_json::from_str(&text) {
        Ok(e) => e,
        Err(e) => {
            debug!(error = %e, "BOAST events parse failed");
            return vec![];
        }
    };

    if events.len() > MAX_OAST_POLL_CALLBACKS {
        debug!(
            received = events.len(),
            max = MAX_OAST_POLL_CALLBACKS,
            "BOAST poll response truncated to callback limit"
        );
    }

    events
        .into_iter()
        .take(MAX_OAST_POLL_CALLBACKS)
        .map(|ev| OastCallback {
            id: Uuid::new_v4(),
            received_at: Utc::now(),
            protocol: ev.protocol,
            remote_addr: ev.remote_address,
            raw_data: ev.data,
            correlation_id: ev.id,
        })
        .filter(callback_fields_within_oast_limits)
        .collect()
}

// ══════════════════════════════════════════════════════════════════════
// Custom backend (original polling logic preserved)
// ══════════════════════════════════════════════════════════════════════

/// Poll a custom/generic OAST server for callbacks.
/// Supports both JSON array and `{ data: [...] }` envelope formats.
async fn poll_custom(config: &OastConfig, client: &reqwest::Client) -> Vec<OastCallback> {
    if config.server_url.is_empty() {
        return vec![];
    }

    let poll_url = if config.token.is_empty() {
        oast_endpoint_url(&config.server_url, "poll", &[])
    } else {
        oast_endpoint_url(&config.server_url, "poll", &[("token", &config.token)])
    };

    let response = match client
        .get(&poll_url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
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

    #[derive(Deserialize)]
    struct RawCallback {
        #[serde(default)]
        protocol: String,
        #[serde(default, alias = "remote-address", alias = "remote_address")]
        remote_addr: String,
        #[serde(default, alias = "raw-request", alias = "raw_request")]
        raw_data: String,
        #[serde(
            default,
            alias = "unique-id",
            alias = "unique_id",
            alias = "correlation_id"
        )]
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

    let text = match read_limited_oast_poll_body(response, "custom").await {
        Some(text) => text,
        None => return vec![],
    };

    let raw_callbacks: Vec<RawCallback> = match serde_json::from_str::<PollResponse>(&text) {
        Ok(PollResponse::Array(arr)) => arr,
        Ok(PollResponse::Object { data }) => data,
        Err(e) => {
            debug!(error = %e, "OAST poll response parse failed");
            return vec![];
        }
    };

    if raw_callbacks.len() > MAX_OAST_POLL_CALLBACKS {
        debug!(
            received = raw_callbacks.len(),
            max = MAX_OAST_POLL_CALLBACKS,
            "custom OAST poll response truncated to callback limit"
        );
    }

    raw_callbacks
        .into_iter()
        .take(MAX_OAST_POLL_CALLBACKS)
        .map(|raw| OastCallback {
            id: Uuid::new_v4(),
            received_at: Utc::now(),
            protocol: raw.protocol,
            remote_addr: raw.remote_addr,
            raw_data: raw.raw_data,
            correlation_id: raw.correlation_id,
        })
        .filter(callback_fields_within_oast_limits)
        .collect()
}

/// Legacy function kept for backward compatibility.
/// Routes to the correct backend based on provider config.
pub async fn poll_oast_callbacks(
    config: &OastConfig,
    client: &reqwest::Client,
) -> Vec<OastCallback> {
    if !config.enabled || config.server_url.is_empty() {
        return vec![];
    }

    match config.provider {
        OastProvider::Custom => poll_custom(config, client).await,
        OastProvider::Boast => poll_boast(&config.server_url, client).await,
        // Interactsh polling requires registration state; this legacy path
        // falls back to custom for callers that don't go through start_oast_poller.
        OastProvider::Interactsh => poll_custom(config, client).await,
    }
}

// ══════════════════════════════════════════════════════════════════════
// Polling loop
// ══════════════════════════════════════════════════════════════════════

/// Start the OAST polling background task.
///
/// The poller tracks configuration changes and handles:
/// - Auto-registering with Interactsh when the provider is first set
/// - Deregistering from Interactsh when switching providers or disabling
/// - Dispatching polls to the correct backend
pub fn start_oast_poller(store: Arc<OastStore>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();

        let mut prev_provider: Option<OastProvider> = None;
        let mut prev_url: Option<String> = None;
        let mut prev_token: Option<String> = None;

        loop {
            let config = store.get_config().await;

            if !config.enabled || config.server_url.is_empty() {
                // If we were previously registered with Interactsh, deregister
                if prev_provider.as_ref() == Some(&OastProvider::Interactsh) {
                    deregister_current_interactsh(&store, &prev_url, &client).await;
                    prev_provider = None;
                    prev_url = None;
                    prev_token = None;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }

            let interval = Duration::from_secs(config.polling_interval_secs.max(1));

            // Detect config change (provider or URL changed)
            let registration_missing = config.provider == OastProvider::Interactsh
                && !store.registration_matches_config(&config).await;
            let config_identity_changed = prev_provider.as_ref() != Some(&config.provider)
                || prev_url.as_deref() != Some(&config.server_url)
                || prev_token.as_deref() != Some(&config.token);
            let config_changed = config_identity_changed || registration_missing;

            if config_changed {
                // Deregister old Interactsh session if switching away
                if prev_provider.as_ref() == Some(&OastProvider::Interactsh)
                    && config_identity_changed
                {
                    deregister_current_interactsh(&store, &prev_url, &client).await;
                }

                // Register new Interactsh session if switching to it
                if config.provider == OastProvider::Interactsh {
                    match register_interactsh(&config.server_url, &config.token, &client).await {
                        Ok(reg) => {
                            info!(
                                correlation_id = %reg.correlation_id,
                                "Interactsh auto-registration complete"
                            );
                            store
                                .set_registration(RegistrationState::Interactsh {
                                    server_url: config.server_url.clone(),
                                    token: config.token.clone(),
                                    correlation_id: reg.correlation_id,
                                    secret_key: reg.secret_key,
                                    private_key: reg.private_key,
                                })
                                .await;
                        }
                        Err(e) => {
                            warn!(error = %e, "Interactsh auto-registration failed");
                            store.clear_registration().await;
                        }
                    }
                } else {
                    store.clear_registration().await;
                }

                prev_provider = Some(config.provider.clone());
                prev_url = Some(config.server_url.clone());
                prev_token = Some(config.token.clone());
            }

            // Dispatch poll to correct backend
            let clear_generation = store.clear_generation();
            let callbacks = match config.provider {
                OastProvider::Interactsh => {
                    poll_interactsh_from_store(&store, &config, &client).await
                }
                OastProvider::Boast => poll_boast(&config.server_url, &client).await,
                OastProvider::Custom => poll_custom(&config, &client).await,
            };

            if !callbacks.is_empty() {
                info!(count = callbacks.len(), provider = %config.provider, "OAST callbacks received");
                let mut inserted = 0usize;
                for cb in callbacks {
                    if store.push_if_generation(cb, clear_generation).await {
                        inserted += 1;
                    }
                }
                if inserted == 0 {
                    debug!(provider = %config.provider, "OAST poll returned only duplicate callbacks");
                }
            }

            tokio::time::sleep(interval).await;
        }
    })
}

/// Start an OAST poller that follows the active session.
///
/// Desktop and headless modes can switch sessions while the app keeps running.
/// This poller reads the active session on each tick, syncs OAST runtime config
/// into that session's store, and persists callbacks into the same session that
/// received them.
pub fn start_oast_poller_for_state(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_oast_poller_for_state(state))
}

pub async fn run_oast_poller_for_state(state: Arc<AppState>) {
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    let mut prev_session_id: Option<Uuid> = None;
    let mut prev_provider: Option<OastProvider> = None;
    let mut prev_url: Option<String> = None;
    let mut prev_token: Option<String> = None;
    let mut prev_store: Option<Arc<OastStore>> = None;

    loop {
        let session = state.session().await;
        let operation_lock = state.session_operation_lock(session.id()).await;
        let mut operation_guard = Some(operation_lock.lock().await);
        if !state.sessions.contains_session(session.id()) {
            prev_session_id = None;
            prev_provider = None;
            prev_url = None;
            prev_token = None;
            prev_store = None;
            drop(operation_guard.take());
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        let config = oast_config_from_session_runtime(&session).await;
        session.oast.update_config(config.clone()).await;

        let session_changed = prev_session_id != Some(session.id());
        let same_session_as_previous = !session_changed;

        if !config.enabled || config.server_url.is_empty() {
            if same_session_as_previous && prev_provider.as_ref() == Some(&OastProvider::Interactsh)
            {
                if let Some(store) = prev_store.as_deref() {
                    let pending_deregistration =
                        pending_interactsh_deregistration(store, &prev_url).await;
                    let _mutation_guard = session.mutation_guard().await;
                    store.clear_registration().await;
                    if let Err(error) = state
                        .persist_session_context_mutation_locked(&session)
                        .await
                    {
                        warn!(?error, session_id = %session.id(), "failed to persist OAST registration clear");
                    }
                    spawn_interactsh_deregistration(pending_deregistration, client.clone());
                }
            }
            prev_session_id = None;
            prev_provider = None;
            prev_url = None;
            prev_token = None;
            prev_store = None;
            drop(operation_guard.take());
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }

        let registration_missing = config.provider == OastProvider::Interactsh
            && !session.oast.registration_matches_config(&config).await;
        let config_changed = session_changed
            || prev_provider.as_ref() != Some(&config.provider)
            || prev_url.as_deref() != Some(&config.server_url)
            || prev_token.as_deref() != Some(&config.token)
            || registration_missing;

        if config_changed {
            let registration_config_changed = prev_provider.as_ref() != Some(&config.provider)
                || prev_url.as_deref() != Some(&config.server_url)
                || prev_token.as_deref() != Some(&config.token);
            if same_session_as_previous
                && registration_config_changed
                && prev_provider.as_ref() == Some(&OastProvider::Interactsh)
            {
                if let Some(store) = prev_store.as_deref() {
                    let pending_deregistration =
                        pending_interactsh_deregistration(store, &prev_url).await;
                    let _mutation_guard = session.mutation_guard().await;
                    store.clear_registration().await;
                    spawn_interactsh_deregistration(pending_deregistration, client.clone());
                }
            }

            let mut registration_changed = false;
            if config.provider == OastProvider::Interactsh {
                let has_existing_registration =
                    session.oast.registration_matches_config(&config).await;
                if has_existing_registration && session_changed {
                    debug!(
                        session_id = %session.id(),
                        "Reusing persisted Interactsh registration"
                    );
                } else {
                    drop(operation_guard.take());
                    let registration_result =
                        register_interactsh(&config.server_url, &config.token, &client).await;
                    operation_guard = Some(operation_lock.lock().await);
                    if !state.sessions.contains_session(session.id()) {
                        if let Ok(registration) = registration_result {
                            spawn_interactsh_registration_cleanup(
                                &config,
                                registration,
                                client.clone(),
                            );
                        }
                        prev_session_id = None;
                        prev_provider = None;
                        prev_url = None;
                        prev_token = None;
                        prev_store = None;
                        drop(operation_guard.take());
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                    let latest_config = oast_config_from_session_runtime(&session).await;
                    session.oast.update_config(latest_config.clone()).await;
                    if !oast_poll_target_still_current(&latest_config, &config) {
                        debug!(
                            session_id = %session.id(),
                            previous_provider = %config.provider,
                            latest_provider = %latest_config.provider,
                            "discarding stale Interactsh registration after config changed"
                        );
                        if let Ok(registration) = registration_result {
                            spawn_interactsh_registration_cleanup(
                                &config,
                                registration,
                                client.clone(),
                            );
                        }
                        drop(operation_guard.take());
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                    match registration_result {
                        Ok(reg) => {
                            info!(
                                session_id = %session.id(),
                                correlation_id = %reg.correlation_id,
                                "Interactsh auto-registration complete"
                            );
                            let _mutation_guard = session.mutation_guard().await;
                            session
                                .oast
                                .set_registration(RegistrationState::Interactsh {
                                    server_url: config.server_url.clone(),
                                    token: config.token.clone(),
                                    correlation_id: reg.correlation_id,
                                    secret_key: reg.secret_key,
                                    private_key: reg.private_key,
                                })
                                .await;
                            registration_changed = true;
                        }
                        Err(error) => {
                            warn!(%error, "Interactsh auto-registration failed");
                            let _mutation_guard = session.mutation_guard().await;
                            session.oast.clear_registration().await;
                            registration_changed = true;
                        }
                    }
                }
            } else {
                let _mutation_guard = session.mutation_guard().await;
                session.oast.clear_registration().await;
                registration_changed = true;
            }

            prev_session_id = Some(session.id());
            prev_provider = Some(config.provider.clone());
            prev_url = Some(config.server_url.clone());
            prev_token = Some(config.token.clone());
            prev_store = Some(session.oast.clone());

            if registration_changed {
                let _mutation_guard = session.mutation_guard().await;
                if let Err(error) = state
                    .persist_session_context_mutation_locked(&session)
                    .await
                {
                    warn!(?error, session_id = %session.id(), "failed to persist OAST registration");
                }
            }
        }

        drop(operation_guard.take());
        let clear_generation = session.oast.clear_generation();
        let callbacks = match config.provider {
            OastProvider::Interactsh => {
                poll_interactsh_from_store(&session.oast, &config, &client).await
            }
            OastProvider::Boast => poll_boast(&config.server_url, &client).await,
            OastProvider::Custom => poll_custom(&config, &client).await,
        };
        let operation_guard = operation_lock.lock().await;
        if !state.sessions.contains_session(session.id()) {
            prev_session_id = None;
            prev_provider = None;
            prev_url = None;
            prev_token = None;
            prev_store = None;
            drop(operation_guard);
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        let latest_config = oast_config_from_session_runtime(&session).await;
        session.oast.update_config(latest_config.clone()).await;
        if !oast_poll_target_still_current(&latest_config, &config) {
            debug!(
                session_id = %session.id(),
                previous_provider = %config.provider,
                latest_provider = %latest_config.provider,
                "discarding stale OAST poll result after config changed"
            );
            drop(operation_guard);
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        let interval = Duration::from_secs(latest_config.polling_interval_secs.max(1));

        if !callbacks.is_empty() {
            info!(
                count = callbacks.len(),
                provider = %config.provider,
                session_id = %session.id(),
                "OAST callbacks received"
            );
            let mutation_guard = session.mutation_guard().await;
            let mut inserted = 0usize;
            for callback in callbacks {
                if session
                    .oast
                    .push_if_generation(callback, clear_generation)
                    .await
                {
                    inserted += 1;
                }
            }
            if inserted == 0 {
                debug!(
                    provider = %config.provider,
                    session_id = %session.id(),
                    "OAST poll returned only duplicate callbacks"
                );
                drop(mutation_guard);
                drop(operation_guard);
                tokio::time::sleep(interval).await;
                continue;
            }
            if let Err(error) = state
                .persist_session_context_mutation_locked(&session)
                .await
            {
                warn!(?error, session_id = %session.id(), "failed to persist OAST callbacks");
            }
        }

        drop(operation_guard);
        tokio::time::sleep(interval).await;
    }
}

async fn oast_config_from_session_runtime(session: &SessionContext) -> OastConfig {
    let runtime = session.runtime.snapshot().await;
    OastConfig {
        enabled: runtime.oast_enabled,
        server_url: runtime.oast_server_url.clone(),
        token: runtime.oast_token.clone(),
        polling_interval_secs: runtime.oast_polling_interval_secs,
        provider: runtime.oast_provider.clone(),
    }
}

fn oast_poll_target_still_current(latest: &OastConfig, polled: &OastConfig) -> bool {
    latest.enabled
        && !latest.server_url.is_empty()
        && latest.provider == polled.provider
        && latest.server_url == polled.server_url
        && latest.token == polled.token
}

/// Poll Interactsh using the registration state stored in OastStore.
async fn poll_interactsh_from_store(
    store: &OastStore,
    config: &OastConfig,
    client: &reqwest::Client,
) -> Vec<OastCallback> {
    let reg = store.registration.read().await;
    match &*reg {
        RegistrationState::Interactsh {
            correlation_id,
            secret_key,
            private_key,
            ..
        } => {
            poll_interactsh(
                &config.server_url,
                correlation_id,
                secret_key,
                private_key,
                &config.token,
                client,
            )
            .await
        }
        RegistrationState::None => {
            debug!("Interactsh provider selected but not registered, skipping poll");
            vec![]
        }
    }
}

/// Deregister the current Interactsh session (if any) from the store.
async fn deregister_current_interactsh(
    store: &OastStore,
    prev_url: &Option<String>,
    client: &reqwest::Client,
) {
    let registration = {
        let reg = store.registration.read().await;
        match &*reg {
            RegistrationState::Interactsh {
                correlation_id,
                secret_key,
                token,
                ..
            } => Some((correlation_id.clone(), secret_key.clone(), token.clone())),
            RegistrationState::None => None,
        }
    };

    if let (Some(url), Some((correlation_id, secret_key, stored_token))) =
        (prev_url.as_ref(), registration)
    {
        let token = if stored_token.is_empty() {
            store.get_config().await.token
        } else {
            stored_token
        };
        deregister_interactsh(url, &correlation_id, &secret_key, &token, client).await;
    }
    store.clear_registration().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::AppConfig, runtime::RuntimeSettingsUpdate};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn interactsh_config(token: &str) -> OastConfig {
        OastConfig {
            enabled: true,
            server_url: "https://interact.example.test".to_string(),
            token: token.to_string(),
            polling_interval_secs: 1,
            provider: OastProvider::Interactsh,
        }
    }

    fn callback(protocol: &str) -> OastCallback {
        OastCallback {
            id: Uuid::new_v4(),
            received_at: Utc::now(),
            protocol: protocol.to_string(),
            remote_addr: "127.0.0.1:1".to_string(),
            raw_data: String::new(),
            correlation_id: protocol.to_string(),
        }
    }

    async fn serve_single_oast_response(response: String) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut buffer = [0_u8; 1024];
            let _ = socket.read(&mut buffer).await;
            let _ = socket.write_all(response.as_bytes()).await;
        });
        format!("http://{addr}")
    }

    #[test]
    fn oast_endpoint_url_encodes_query_values() {
        let url = oast_endpoint_url(
            "https://oast.example.test/",
            "/poll",
            &[("token", "a b&c=d")],
        );

        assert_eq!(url, "https://oast.example.test/poll?token=a+b%26c%3Dd");
    }

    #[test]
    fn interactsh_endpoint_urls_do_not_include_token_query() {
        assert_eq!(
            oast_endpoint_url("https://interact.example.test", "register", &[]),
            "https://interact.example.test/register"
        );
        assert!(
            !oast_endpoint_url("https://interact.example.test", "deregister", &[])
                .contains("token=")
        );
    }

    #[test]
    fn oast_payload_builder_uses_url_host_for_dns_payloads() {
        let payload =
            build_oast_payload_checked("https://oast.example.test:8443/", "abc123").unwrap();

        assert_eq!(payload, "abc123.oast.example.test");
    }

    #[test]
    fn oast_payload_builder_rejects_url_paths_queries_and_fragments() {
        assert!(build_oast_payload_checked("https://oast.example.test/api", "abc123").is_err());
        assert!(build_oast_payload_checked("https://oast.example.test?x=1", "abc123").is_err());
        assert!(build_oast_payload_checked("https://oast.example.test/#frag", "abc123").is_err());
    }

    #[test]
    fn oast_payload_builder_preserves_legacy_bare_host_payloads() {
        let payload = build_oast_payload_checked("oast.example.test", "abc123").unwrap();

        assert_eq!(payload, "oast.example.test/abc123");
    }

    #[tokio::test]
    async fn boast_poll_rejects_oversized_content_length() {
        let base = serve_single_oast_response(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n[]",
            MAX_OAST_POLL_BODY_BYTES + 1
        ))
        .await;

        let callbacks = poll_boast(&base, &reqwest::Client::new()).await;

        assert!(callbacks.is_empty());
    }

    #[tokio::test]
    async fn custom_poll_rejects_oversized_callback_fields() {
        let raw_data = "x".repeat(MAX_OAST_CALLBACK_FIELD_BYTES + 1);
        let body = serde_json::json!([{
            "protocol": "http",
            "remote_address": "127.0.0.1:53",
            "raw_request": raw_data,
            "correlation_id": "oversized"
        }])
        .to_string();
        let base = serve_single_oast_response(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        ))
        .await;
        let config = OastConfig {
            enabled: true,
            server_url: base,
            token: String::new(),
            polling_interval_secs: 1,
            provider: OastProvider::Custom,
        };

        let callbacks = poll_custom(&config, &reqwest::Client::new()).await;

        assert!(callbacks.is_empty());
    }

    #[tokio::test]
    async fn restore_trims_callbacks_to_max_entries() {
        let store = OastStore::new(2);
        store
            .restore(vec![
                callback("first"),
                callback("second"),
                callback("third"),
            ])
            .await;

        let callbacks = store.list(None).await;

        assert_eq!(callbacks.len(), 2);
        assert_eq!(callbacks[0].protocol, "first");
        assert_eq!(callbacks[1].protocol, "second");
    }

    #[tokio::test]
    async fn restore_drops_oversized_callback_fields() {
        let store = OastStore::new(4);
        let mut oversized = callback("oversized");
        oversized.raw_data = "x".repeat(MAX_OAST_CALLBACK_FIELD_BYTES + 1);
        store.restore(vec![oversized, callback("kept")]).await;

        let callbacks = store.list(None).await;

        assert_eq!(callbacks.len(), 1);
        assert_eq!(callbacks[0].protocol, "kept");
    }

    #[tokio::test]
    async fn push_skips_duplicate_callbacks_without_broadcasting() {
        let store = OastStore::new(16);
        let mut receiver = store.subscribe();
        let first = callback("dns");
        let duplicate = OastCallback {
            id: Uuid::new_v4(),
            received_at: Utc::now(),
            ..first.clone()
        };

        assert!(store.push(first).await);
        assert!(!store.push(duplicate).await);

        let first_event = receiver.recv().await.unwrap();
        assert_eq!(first_event.protocol, "dns");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), receiver.recv())
                .await
                .is_err()
        );
        assert_eq!(store.count().await, 1);
    }

    #[tokio::test]
    async fn clear_suppresses_previously_seen_callbacks() {
        let store = OastStore::new(16);
        let first = callback("dns");
        let duplicate = OastCallback {
            id: Uuid::new_v4(),
            received_at: Utc::now(),
            ..first.clone()
        };

        assert!(store.push(first).await);
        store.clear().await;

        assert!(!store.push(duplicate).await);
        assert_eq!(store.count().await, 0);
    }

    #[tokio::test]
    async fn clear_generation_rejects_callbacks_from_stale_poll() {
        let store = OastStore::new(16);
        let generation = store.clear_generation();

        store.clear().await;

        assert!(!store.push_if_generation(callback("dns"), generation).await);
        assert_eq!(store.count().await, 0);
    }

    #[tokio::test]
    async fn clear_generation_can_be_restored_after_failed_clear() {
        let store = OastStore::new(16);
        let generation = store.clear_generation();

        store.clear().await;
        store.restore_clear_generation(generation);

        assert!(store.push_if_generation(callback("dns"), generation).await);
        assert_eq!(store.count().await, 1);
    }

    #[tokio::test]
    async fn restored_cleared_keys_suppress_old_callbacks() {
        let store = OastStore::new(16);
        let first = callback("dns");
        let duplicate = OastCallback {
            id: Uuid::new_v4(),
            received_at: Utc::now(),
            ..first.clone()
        };

        assert!(store.push(first).await);
        store.clear().await;
        let cleared_keys = store.snapshot_cleared_keys().await;

        let restored = OastStore::new(16);
        restored.restore_cleared_keys(cleared_keys).await;

        assert!(!restored.push(duplicate).await);
        assert_eq!(restored.count().await, 0);
    }

    #[tokio::test]
    async fn restore_deduplicates_callbacks_with_fresh_local_ids() {
        let first = callback("http");
        let duplicate = OastCallback {
            id: Uuid::new_v4(),
            received_at: Utc::now(),
            ..first.clone()
        };
        let store = OastStore::new(16);

        store.restore(vec![first, duplicate]).await;

        let callbacks = store.list(None).await;
        assert_eq!(callbacks.len(), 1);
        assert_eq!(callbacks[0].protocol, "http");
    }

    #[tokio::test]
    async fn registration_config_match_checks_token_and_url() {
        let store = OastStore::new(16);
        let config = interactsh_config("token-a");
        let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();

        store
            .set_registration(RegistrationState::Interactsh {
                server_url: config.server_url.clone(),
                token: config.token.clone(),
                correlation_id: "cid".to_string(),
                secret_key: "secret".to_string(),
                private_key,
            })
            .await;

        assert!(store.registration_matches_config(&config).await);

        let mut changed_token = config.clone();
        changed_token.token = "token-b".to_string();
        assert!(!store.registration_matches_config(&changed_token).await);

        let mut changed_url = config;
        changed_url.server_url = "https://other.example.test".to_string();
        assert!(!store.registration_matches_config(&changed_url).await);
    }

    #[tokio::test]
    async fn registration_info_requires_interactsh_provider() {
        let store = OastStore::new(16);
        let mut config = interactsh_config("token-a");
        let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();

        store.update_config(config.clone()).await;
        store
            .set_registration(RegistrationState::Interactsh {
                server_url: config.server_url.clone(),
                token: config.token.clone(),
                correlation_id: "cid".to_string(),
                secret_key: "secret".to_string(),
                private_key,
            })
            .await;
        assert!(store.get_registration_info().await.is_some());

        config.provider = OastProvider::Custom;
        store.update_config(config).await;
        assert!(store.get_registration_info().await.is_none());
    }

    #[tokio::test]
    async fn interactsh_registration_retries_after_initial_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let register_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server_attempts = register_attempts.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let mut buffer = [0_u8; 8192];
                let read = socket.read(&mut buffer).await;
                let Ok(read) = read else {
                    continue;
                };
                let request = String::from_utf8_lossy(&buffer[..read]);
                let response = if request.starts_with("POST /register ") {
                    let attempt = server_attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if attempt == 0 {
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 4\r\nConnection: close\r\n\r\nfail"
                            .to_string()
                    } else {
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                            .to_string()
                    }
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"data\":[]}"
                        .to_string()
                };
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        let store = Arc::new(OastStore::new_with_config(
            16,
            OastConfig {
                enabled: true,
                server_url: format!("http://{addr}"),
                token: String::new(),
                polling_interval_secs: 1,
                provider: OastProvider::Interactsh,
            },
        ));
        let poller = start_oast_poller(store.clone());

        tokio::time::timeout(std::time::Duration::from_secs(45), async {
            loop {
                if store.get_registration_info().await.is_some() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("registration should retry after a transient failure");

        assert!(register_attempts.load(std::sync::atomic::Ordering::SeqCst) >= 2);
        poller.abort();
        server.abort();
    }

    #[tokio::test]
    async fn state_poller_releases_session_operation_lock_while_registering_interactsh() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (register_started_tx, register_started_rx) = tokio::sync::oneshot::channel();
        let (release_response_tx, release_response_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 8192];
            let read = socket.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..read]);
            assert!(request.starts_with("POST /register "));
            let _ = register_started_tx.send(());
            let _ = release_response_rx.await;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await;
        });

        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-oast-state-poller-register-lock-{}",
            Uuid::new_v4()
        ));
        let state = Arc::new(
            AppState::new(AppConfig {
                proxy_addr: "127.0.0.1:0".parse().unwrap(),
                ui_addr: "127.0.0.1:0".parse().unwrap(),
                max_entries: 100,
                max_transaction_entries: 100,
                body_preview_bytes: 4096,
                data_dir: data_dir.clone(),
            })
            .unwrap(),
        );
        let session = state.session().await;
        session
            .runtime
            .update(RuntimeSettingsUpdate {
                oast_enabled: Some(true),
                oast_server_url: Some(format!("http://{addr}")),
                oast_provider: Some(OastProvider::Interactsh),
                oast_polling_interval_secs: Some(1),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap();
        let poller = start_oast_poller_for_state(state.clone());

        tokio::time::timeout(Duration::from_secs(20), register_started_rx)
            .await
            .expect("registration request should start")
            .expect("registration signal should be delivered");
        let operation_lock = state.session_operation_lock(session.id()).await;
        let guard = tokio::time::timeout(Duration::from_millis(100), operation_lock.lock())
            .await
            .expect("OAST registration must not hold the session operation lock");
        drop(guard);

        let _ = release_response_tx.send(());
        poller.abort();
        server.abort();
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn state_poller_deregisters_registration_that_becomes_stale_before_persist() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (register_started_tx, register_started_rx) = tokio::sync::oneshot::channel();
        let (release_register_tx, release_register_rx) = tokio::sync::oneshot::channel();
        let (deregister_seen_tx, deregister_seen_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut register_started_tx = Some(register_started_tx);
            let mut release_register_rx = Some(release_register_rx);
            let mut deregister_seen_tx = Some(deregister_seen_tx);
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let mut buffer = [0_u8; 8192];
                let read = socket.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..read]);
                if request.starts_with("POST /register ") {
                    if let Some(tx) = register_started_tx.take() {
                        let _ = tx.send(());
                    }
                    if let Some(rx) = release_register_rx.take() {
                        let _ = rx.await;
                    }
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .await;
                } else if request.starts_with("POST /deregister ") {
                    if let Some(tx) = deregister_seen_tx.take() {
                        let _ = tx.send(());
                    }
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .await;
                    return;
                } else {
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"data\":[]}",
                        )
                        .await;
                }
            }
        });

        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-oast-state-poller-stale-register-{}",
            Uuid::new_v4()
        ));
        let state = Arc::new(
            AppState::new(AppConfig {
                proxy_addr: "127.0.0.1:0".parse().unwrap(),
                ui_addr: "127.0.0.1:0".parse().unwrap(),
                max_entries: 100,
                max_transaction_entries: 100,
                body_preview_bytes: 4096,
                data_dir: data_dir.clone(),
            })
            .unwrap(),
        );
        let session = state.session().await;
        session
            .runtime
            .update(RuntimeSettingsUpdate {
                oast_enabled: Some(true),
                oast_server_url: Some(format!("http://{addr}")),
                oast_provider: Some(OastProvider::Interactsh),
                oast_polling_interval_secs: Some(1),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap();
        let poller = start_oast_poller_for_state(state.clone());

        tokio::time::timeout(Duration::from_secs(20), register_started_rx)
            .await
            .expect("registration request should start")
            .expect("registration signal should be delivered");
        session
            .runtime
            .update(RuntimeSettingsUpdate {
                oast_enabled: Some(false),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap();
        let _ = release_register_tx.send(());

        tokio::time::timeout(Duration::from_secs(5), deregister_seen_rx)
            .await
            .expect("stale registration should be deregistered")
            .expect("deregistration signal should be delivered");
        assert!(session.oast.snapshot_registration().await.is_none());

        poller.abort();
        server.abort();
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn state_poller_releases_session_operation_lock_while_deregistering_interactsh() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (poll_seen_tx, poll_seen_rx) = tokio::sync::oneshot::channel();
        let (deregister_started_tx, deregister_started_rx) = tokio::sync::oneshot::channel();
        let (release_deregister_tx, release_deregister_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut poll_seen_tx = Some(poll_seen_tx);
            let mut deregister_started_tx = Some(deregister_started_tx);
            let mut release_deregister_rx = Some(release_deregister_rx);
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let mut buffer = [0_u8; 8192];
                let read = socket.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..read]);
                if request.starts_with("GET /poll?") {
                    if let Some(tx) = poll_seen_tx.take() {
                        let _ = tx.send(());
                    }
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"data\":[]}",
                        )
                        .await;
                } else if request.starts_with("POST /deregister ") {
                    if let Some(tx) = deregister_started_tx.take() {
                        let _ = tx.send(());
                    }
                    if let Some(rx) = release_deregister_rx.take() {
                        let _ = rx.await;
                    }
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .await;
                    return;
                } else {
                    panic!("unexpected OAST request: {request}");
                }
            }
        });

        let data_dir = std::env::temp_dir().join(format!(
            "sniper-test-oast-state-poller-deregister-lock-{}",
            Uuid::new_v4()
        ));
        let state = Arc::new(
            AppState::new(AppConfig {
                proxy_addr: "127.0.0.1:0".parse().unwrap(),
                ui_addr: "127.0.0.1:0".parse().unwrap(),
                max_entries: 100,
                max_transaction_entries: 100,
                body_preview_bytes: 4096,
                data_dir: data_dir.clone(),
            })
            .unwrap(),
        );
        let session = state.session().await;
        let server_url = format!("http://{addr}");
        session
            .runtime
            .update(RuntimeSettingsUpdate {
                oast_enabled: Some(true),
                oast_server_url: Some(server_url.clone()),
                oast_provider: Some(OastProvider::Interactsh),
                oast_polling_interval_secs: Some(1),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap();
        session
            .oast
            .set_registration(RegistrationState::Interactsh {
                server_url,
                token: String::new(),
                correlation_id: "cid".to_string(),
                secret_key: "secret".to_string(),
                private_key: rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap(),
            })
            .await;
        let poller = start_oast_poller_for_state(state.clone());

        tokio::time::timeout(Duration::from_secs(5), poll_seen_rx)
            .await
            .expect("persisted registration should be polled")
            .expect("poll signal should be delivered");
        session
            .runtime
            .update(RuntimeSettingsUpdate {
                oast_enabled: Some(false),
                ..RuntimeSettingsUpdate::default()
            })
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), deregister_started_rx)
            .await
            .expect("deregistration request should start")
            .expect("deregistration signal should be delivered");

        let operation_lock = state.session_operation_lock(session.id()).await;
        let guard = tokio::time::timeout(Duration::from_millis(100), operation_lock.lock())
            .await
            .expect("OAST deregistration must not hold the session operation lock");
        drop(guard);
        assert!(session.oast.snapshot_registration().await.is_none());

        let _ = release_deregister_tx.send(());
        poller.abort();
        server.abort();
        let _ = std::fs::remove_dir_all(data_dir);
    }

    #[tokio::test]
    async fn registration_snapshot_round_trips_config_fingerprint() {
        let store = OastStore::new(16);
        let config = interactsh_config("round-trip-token");
        let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();

        store
            .set_registration(RegistrationState::Interactsh {
                server_url: config.server_url.clone(),
                token: config.token.clone(),
                correlation_id: "cid".to_string(),
                secret_key: "secret".to_string(),
                private_key,
            })
            .await;

        let snapshot = store.snapshot_registration().await;
        let restored = OastStore::new(16);
        restored.restore_registration_blocking(snapshot);

        assert!(restored.registration_matches_config(&config).await);
    }

    #[tokio::test]
    async fn pending_deregistration_uses_stored_registration_url_without_prev_url() {
        let store = OastStore::new(16);
        let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        store
            .set_registration(RegistrationState::Interactsh {
                server_url: "https://stored.example.test".to_string(),
                token: "stored-token".to_string(),
                correlation_id: "cid".to_string(),
                secret_key: "secret".to_string(),
                private_key,
            })
            .await;

        let pending = pending_interactsh_deregistration(&store, &None)
            .await
            .expect("stored registration URL should be enough to deregister");

        assert_eq!(pending.base_url, "https://stored.example.test");
        assert_eq!(pending.token, "stored-token");
        assert_eq!(pending.correlation_id, "cid");
        assert_eq!(pending.secret_key, "secret");
    }

    #[test]
    fn oast_poll_target_matches_only_same_enabled_endpoint() {
        let config = interactsh_config("token-a");
        assert!(oast_poll_target_still_current(&config, &config));

        let mut interval_changed = config.clone();
        interval_changed.polling_interval_secs += 1;
        assert!(oast_poll_target_still_current(&interval_changed, &config));

        let mut disabled = config.clone();
        disabled.enabled = false;
        assert!(!oast_poll_target_still_current(&disabled, &config));

        let mut changed_provider = config.clone();
        changed_provider.provider = OastProvider::Boast;
        assert!(!oast_poll_target_still_current(&changed_provider, &config));

        let mut changed_url = config.clone();
        changed_url.server_url = "https://other.example.test".to_string();
        assert!(!oast_poll_target_still_current(&changed_url, &config));

        let mut changed_token = config.clone();
        changed_token.token = "token-b".to_string();
        assert!(!oast_poll_target_still_current(&changed_token, &config));
    }

    #[tokio::test]
    async fn stale_interactsh_registration_is_not_reported_or_used_for_payloads() {
        let store = OastStore::new(16);
        let config = interactsh_config("token-a");
        store.update_config(config.clone()).await;
        let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();

        store
            .set_registration(RegistrationState::Interactsh {
                server_url: config.server_url.clone(),
                token: config.token.clone(),
                correlation_id: "cid".to_string(),
                secret_key: "secret".to_string(),
                private_key,
            })
            .await;

        assert!(store.get_registration_info().await.is_some());
        assert!(generate_payload(&store).await.is_some());

        let mut disabled = config.clone();
        disabled.enabled = false;
        store.update_config(disabled).await;
        assert!(store.get_registration_info().await.is_none());
        assert!(generate_payload(&store).await.is_none());

        let mut changed = config;
        changed.token = "token-b".to_string();
        store.update_config(changed).await;

        assert!(store.get_registration_info().await.is_none());
        assert!(generate_payload(&store).await.is_none());
    }
}
