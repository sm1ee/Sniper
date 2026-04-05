use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use aes::Aes256;
use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use cfb_mode::Decryptor as CfbDecryptor;
use chrono::{DateTime, Utc};
use rand::Rng;
use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::sha2::Sha256;
use rsa::Oaep;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};
use uuid::Uuid;

// ── Provider enum ──

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OastProvider {
    Interactsh,
    Boast,
    Custom,
}

impl Default for OastProvider {
    fn default() -> Self {
        Self::Custom
    }
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

enum RegistrationState {
    None,
    Interactsh {
        correlation_id: String,
        secret_key: String,
        private_key: rsa::RsaPrivateKey,
    },
}

// ── Interactsh registration result ──

struct InteractshRegistration {
    correlation_id: String,
    secret_key: String,
    private_key: rsa::RsaPrivateKey,
}

// ── OastStore ──

/// Store for OAST callbacks. Mirrors ScannerStore pattern.
pub struct OastStore {
    max_entries: usize,
    entries: RwLock<VecDeque<OastCallback>>,
    events: broadcast::Sender<OastCallbackSummary>,
    config: RwLock<OastConfig>,
    registration: RwLock<RegistrationState>,
}

impl OastStore {
    pub fn new(max_entries: usize) -> Self {
        let (events, _) = broadcast::channel(max_entries.max(64));
        Self {
            max_entries,
            entries: RwLock::new(VecDeque::new()),
            events,
            config: RwLock::new(OastConfig::default()),
            registration: RwLock::new(RegistrationState::None),
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

    /// Blocking mutable access to entries — for use outside async context (e.g. session restore).
    pub fn entries_mut_blocking(&self) -> tokio::sync::RwLockWriteGuard<'_, VecDeque<OastCallback>> {
        // tokio::sync::RwLock doesn't have blocking_write, so use try_write in a spin.
        // At init time there's no contention so this succeeds immediately.
        loop {
            if let Ok(guard) = self.entries.try_write() {
                return guard;
            }
            std::thread::yield_now();
        }
    }

    /// Returns (correlation_id, payload_suffix) if an Interactsh session is registered.
    pub async fn get_registration_info(&self) -> Option<(String, String)> {
        let reg = self.registration.read().await;
        match &*reg {
            RegistrationState::Interactsh {
                correlation_id,
                secret_key: _,
                private_key: _,
            } => {
                let config = self.config.read().await;
                let domain = extract_domain(&config.server_url);
                Some((correlation_id.clone(), domain))
            }
            RegistrationState::None => None,
        }
    }

    async fn set_registration(&self, state: RegistrationState) {
        *self.registration.write().await = state;
    }

    async fn clear_registration(&self) {
        *self.registration.write().await = RegistrationState::None;
    }
}

// ── Helper: extract domain from URL ──

fn extract_domain(url: &str) -> String {
    let base = url.trim_end_matches('/');
    base.strip_prefix("https://")
        .or_else(|| base.strip_prefix("http://"))
        .unwrap_or(base)
        .to_string()
}

// ── Helper: generate random hex string ──

fn random_hex(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| format!("{:x}", rng.gen::<u8>() & 0x0f)).collect()
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
    let base = server_url.trim_end_matches('/');
    if let Some(domain) = base.strip_prefix("https://").or_else(|| base.strip_prefix("http://")) {
        format!("{correlation_id}.{domain}")
    } else {
        format!("{base}/{correlation_id}")
    }
}

// ── Generate payload (multi-backend aware) ──

/// Generate an OAST payload. Returns (correlation_id, full_payload).
///
/// - Interactsh: uses registered correlation_id + random nonce + server domain
/// - BOAST / Custom: uses a fresh UUID-based correlation_id + server URL
pub async fn generate_payload(store: &OastStore) -> Option<(String, String)> {
    let config = store.get_config().await;
    if config.server_url.is_empty() {
        return None;
    }

    match config.provider {
        OastProvider::Interactsh => {
            let reg = store.registration.read().await;
            match &*reg {
                RegistrationState::Interactsh {
                    correlation_id,
                    secret_key: _,
                    private_key: _,
                } => {
                    let payload = build_interactsh_payload(correlation_id, &config.server_url);
                    Some((correlation_id.clone(), payload))
                }
                RegistrationState::None => {
                    debug!("Interactsh not registered, falling back to generic payload");
                    let cid = generate_correlation_id();
                    let payload = build_oast_payload(&config.server_url, &cid);
                    Some((cid, payload))
                }
            }
        }
        OastProvider::Boast | OastProvider::Custom => {
            let cid = generate_correlation_id();
            let payload = build_oast_payload(&config.server_url, &cid);
            Some((cid, payload))
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
    let base = base_url.trim_end_matches('/');
    let url = if token.is_empty() {
        format!("{base}/register")
    } else {
        format!("{base}/register?token={token}")
    };

    // 5. POST registration
    let body = serde_json::json!({
        "public-key": pem_b64,
        "secret-key": secret_key,
        "correlation-id": correlation_id,
    });

    let mut req = client.post(&url).json(&body).timeout(Duration::from_secs(15));
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }

    let resp = req.send().await.map_err(|e| format!("register request failed: {e}"))?;
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
    let base = base_url.trim_end_matches('/');
    let url = if token.is_empty() {
        format!("{base}/deregister")
    } else {
        format!("{base}/deregister?token={token}")
    };

    let body = serde_json::json!({
        "correlation-id": correlation_id,
        "secret-key": secret_key,
    });

    let mut req = client.post(&url).json(&body).timeout(Duration::from_secs(10));
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

/// Poll an Interactsh server for new interactions.
async fn poll_interactsh(
    base_url: &str,
    correlation_id: &str,
    secret_key: &str,
    private_key: &rsa::RsaPrivateKey,
    token: &str,
    client: &reqwest::Client,
) -> Vec<OastCallback> {
    let base = base_url.trim_end_matches('/');
    let mut url = format!("{base}/poll?id={correlation_id}&secret={secret_key}");
    if !token.is_empty() {
        url.push_str(&format!("&token={token}"));
    }

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

    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => {
            debug!(error = %e, "Interactsh poll body read failed");
            return vec![];
        }
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
    let mut callbacks = Vec::with_capacity(data.len());
    for entry in &data {
        match decrypt_interactsh_entry(entry, &aes_key_bytes) {
            Some(cb) => callbacks.push(cb),
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
        debug!(key_len = aes_key.len(), "Interactsh: unexpected AES key length");
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

    let decryptor: CfbDecryptor<Aes256> =
        match CfbDecryptor::<Aes256>::new_from_slices(key, iv) {
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

    let resp = match client.get(&url).timeout(Duration::from_secs(10)).send().await {
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

    let text = match resp.text().await {
        Ok(t) => t,
        Err(e) => {
            debug!(error = %e, "BOAST poll body read failed");
            return vec![];
        }
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

    events
        .into_iter()
        .map(|ev| OastCallback {
            id: Uuid::new_v4(),
            received_at: Utc::now(),
            protocol: ev.protocol,
            remote_addr: ev.remote_address,
            raw_data: ev.data,
            correlation_id: ev.id,
        })
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

        loop {
            let config = store.get_config().await;

            if !config.enabled || config.server_url.is_empty() {
                // If we were previously registered with Interactsh, deregister
                if prev_provider.as_ref() == Some(&OastProvider::Interactsh) {
                    deregister_current_interactsh(&store, &prev_url, &client).await;
                    prev_provider = None;
                    prev_url = None;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }

            let interval = Duration::from_secs(config.polling_interval_secs.max(1));

            // Detect config change (provider or URL changed)
            let config_changed = prev_provider.as_ref() != Some(&config.provider)
                || prev_url.as_deref() != Some(&config.server_url);

            if config_changed {
                // Deregister old Interactsh session if switching away
                if prev_provider.as_ref() == Some(&OastProvider::Interactsh) {
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
            }

            // Dispatch poll to correct backend
            let callbacks = match config.provider {
                OastProvider::Interactsh => {
                    poll_interactsh_from_store(&store, &config, &client).await
                }
                OastProvider::Boast => poll_boast(&config.server_url, &client).await,
                OastProvider::Custom => poll_custom(&config, &client).await,
            };

            if !callbacks.is_empty() {
                info!(count = callbacks.len(), provider = %config.provider, "OAST callbacks received");
                for cb in callbacks {
                    store.push(cb).await;
                }
            }

            tokio::time::sleep(interval).await;
        }
    })
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
    let reg = store.registration.read().await;
    if let RegistrationState::Interactsh {
        correlation_id,
        secret_key,
        private_key: _,
    } = &*reg
    {
        if let Some(url) = prev_url {
            let config = store.get_config().await;
            deregister_interactsh(url, correlation_id, secret_key, &config.token, client).await;
        }
    }
    drop(reg);
    store.clear_registration().await;
}
