//! Known vulnerabilities for the product versions Sniper detects, matched on
//! this machine against public data files.

pub mod index;
pub mod products;
pub mod sources;
pub mod version;

use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::state::AppState;
use index::VulnIndex;
use sources::SourceId;

/// A source that loaded is fetched again a day later; one that failed, at the
/// next hourly look.
const REFETCH_AFTER: chrono::Duration = chrono::Duration::hours(24);
const FIRST_LOOK: Duration = Duration::from_secs(60);
const LOOK_EVERY: Duration = Duration::from_secs(60 * 60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
/// Matching runs off the proxy; under load a record is skipped for Rescan.
const MATCH_PERMITS: usize = 4;
const MAX_ERROR_CHARS: usize = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Download,
    Import,
}

/// What Sniper knows of one source's file: when it last loaded, from where,
/// and why the last attempt failed if it did.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SourceRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Manifest {
    /// None, as before the switch was ever touched, reads as on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auto_update: Option<bool>,
    #[serde(default)]
    sources: HashMap<SourceId, SourceRecord>,
}

impl Manifest {
    fn auto_update(&self) -> bool {
        self.auto_update.unwrap_or(true)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct VulnDataStatus {
    pub auto_update: bool,
    pub updating: bool,
    pub revision: Option<String>,
    pub sources: Vec<SourceStatus>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceStatus {
    pub id: SourceId,
    pub name: &'static str,
    pub url: &'static str,
    pub license: &'static str,
    /// No source signs its file; TLS is the only check.
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Whether the daily update fetches a source now: when it never loaded, when
/// its last attempt failed, or a day after it last loaded; never with the
/// switch off. An imported file counts as loaded, so the next fetch replaces it.
fn due(record: &SourceRecord, auto_update: bool, now: DateTime<Utc>) -> bool {
    auto_update
        && (record.error.is_some()
            || record
                .fetched_at
                .is_none_or(|fetched| now - fetched >= REFETCH_AFTER))
}

/// The downloaded files, shared by every session; findings stay per session.
pub struct VulnData {
    dir: PathBuf,
    manifest: Mutex<Manifest>,
    index: RwLock<Option<Arc<VulnIndex>>>,
    /// One rebuild at a time, each from the files on disk then.
    rebuilding: Mutex<()>,
    updating: AtomicBool,
    permits: Arc<Semaphore>,
}

/// Clears `updating` however the update ends.
struct Updating(Arc<VulnData>);

impl Drop for Updating {
    fn drop(&mut self) {
        self.0.updating.store(false, Ordering::Release);
    }
}

fn file_name(id: SourceId) -> &'static str {
    match id {
        SourceId::Retire => "retire.json",
        SourceId::Kev => "kev.json",
        SourceId::Epss => "epss.csv.gz",
    }
}

impl VulnData {
    /// Reads the manifest now and builds the index in the background: parsing
    /// EPSS takes a moment, and startup must not wait for it.
    pub fn load(data_dir: &Path) -> Arc<Self> {
        let dir = data_dir.join("vulndata");
        let manifest = match fs::read(dir.join("manifest.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|_| {
                // A corrupt manifest must not stop updates for good; it is kept
                // aside for a look and replaced.
                let aside = dir.join(format!(".manifest.corrupt-{}.json", uuid::Uuid::new_v4()));
                let _ = crate::platform::rename(dir.join("manifest.json"), aside);
                Manifest::default()
            }),
            Err(_) => Manifest::default(),
        };
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().contains(".tmp-") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
        let data = Arc::new(Self {
            dir,
            manifest: Mutex::new(manifest),
            index: RwLock::new(None),
            rebuilding: Mutex::new(()),
            updating: AtomicBool::new(false),
            permits: Arc::new(Semaphore::new(MATCH_PERMITS)),
        });
        let background = Arc::clone(&data);
        let _ = std::thread::Builder::new()
            .name("vulnerability-data".into())
            .spawn(move || background.rebuild_index());
        data
    }

    /// None until all three sources have loaded once.
    pub fn index(&self) -> Option<Arc<VulnIndex>> {
        self.index.read().unwrap().clone()
    }

    pub fn try_permit(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.permits).try_acquire_owned().ok()
    }

    pub fn status(&self) -> VulnDataStatus {
        let manifest = self.manifest.lock().unwrap();
        VulnDataStatus {
            auto_update: manifest.auto_update(),
            updating: self.updating.load(Ordering::Acquire),
            revision: self.index().map(|index| index.revision.clone()),
            sources: SourceId::ALL
                .iter()
                .map(|&id| {
                    let record = manifest.sources.get(&id).cloned().unwrap_or_default();
                    SourceStatus {
                        id,
                        name: id.name(),
                        url: id.url(),
                        license: id.license(),
                        verified: false,
                        fetched_at: record.fetched_at,
                        origin: record.origin,
                        size: record.size,
                        sha256: record.sha256,
                        error: record.error,
                    }
                })
                .collect(),
        }
    }

    pub fn set_auto_update(&self, enabled: bool) -> Result<()> {
        let mut manifest = self.manifest.lock().unwrap();
        let mut next = manifest.clone();
        next.auto_update = Some(enabled);
        crate::session::write_json(&self.dir.join("manifest.json"), &next)?;
        *manifest = next;
        Ok(())
    }

    /// For networks that cannot reach the hosts: the file is checked as a
    /// download would be. The next successful fetch replaces it.
    pub fn import_blocking(&self, bytes: &[u8]) -> Result<SourceId> {
        let id = sources::identify(bytes)
            .ok_or_else(|| anyhow!("not a retire.js, CISA KEV or FIRST EPSS file"))?;
        self.install(id, bytes, Origin::Import)?;
        self.rebuild_index();
        Ok(id)
    }

    /// Fetches every due source. Does nothing while another update runs.
    pub async fn update_sources<F, Fut>(self: &Arc<Self>, fetch: F)
    where
        F: Fn(SourceId) -> Fut,
        Fut: Future<Output = Result<Vec<u8>>>,
    {
        if !self.updating.swap(true, Ordering::AcqRel) {
            let _updating = Updating(Arc::clone(self));
            self.fetch(fetch, false).await;
        }
    }

    /// Update now: every source, due or not and with the switch off too.
    /// False while an update runs.
    pub fn update_now(self: &Arc<Self>) -> bool {
        if self.updating.swap(true, Ordering::AcqRel) {
            return false;
        }
        let updating = Updating(Arc::clone(self));
        tokio::spawn(async move {
            let data = Arc::clone(&updating.0);
            match client() {
                Ok(client) => {
                    data.fetch(
                        |id| {
                            let client = client.clone();
                            async move { download(&client, id).await }
                        },
                        true,
                    )
                    .await
                }
                Err(error) => {
                    for id in SourceId::ALL {
                        data.record_failure(id, &error);
                    }
                }
            }
            drop(updating);
        });
        true
    }

    #[cfg(test)]
    async fn fetch_all<F, Fut>(self: &Arc<Self>, fetch: F)
    where
        F: Fn(SourceId) -> Fut,
        Fut: Future<Output = Result<Vec<u8>>>,
    {
        self.fetch(fetch, true).await;
    }

    async fn fetch<F, Fut>(self: &Arc<Self>, fetch: F, every: bool)
    where
        F: Fn(SourceId) -> Fut,
        Fut: Future<Output = Result<Vec<u8>>>,
    {
        let now = Utc::now();
        let (auto_update, records) = {
            let manifest = self.manifest.lock().unwrap();
            (manifest.auto_update(), manifest.sources.clone())
        };
        let mut changed = false;
        for id in SourceId::ALL {
            let record = records.get(&id).cloned().unwrap_or_default();
            if !every && !due(&record, auto_update, now) {
                continue;
            }
            let data = Arc::clone(self);
            let result = match fetch(id).await {
                Ok(bytes) => {
                    tokio::task::spawn_blocking(move || data.install(id, &bytes, Origin::Download))
                        .await
                        .unwrap_or_else(|error| Err(anyhow!("installing {}: {error}", id.name())))
                }
                Err(error) => Err(error),
            };
            match result {
                Ok(()) => changed = true,
                Err(error) => {
                    let data = Arc::clone(self);
                    let _ =
                        tokio::task::spawn_blocking(move || data.record_failure(id, &error)).await;
                }
            }
        }
        if changed {
            let data = Arc::clone(self);
            let _ = tokio::task::spawn_blocking(move || data.rebuild_index()).await;
        }
    }

    /// Checks the file as its source's parser reads it, then writes it and its
    /// record. A refused file leaves the previous one in place.
    fn install(&self, id: SourceId, bytes: &[u8], origin: Origin) -> Result<()> {
        match id {
            SourceId::Retire => sources::parse_retire(bytes).map(drop)?,
            SourceId::Kev => sources::parse_kev(bytes).map(drop)?,
            SourceId::Epss => sources::parse_epss(bytes).map(drop)?,
        }
        let mut manifest = self.manifest.lock().unwrap();
        fs::create_dir_all(&self.dir).context("creating the vulnerability data folder")?;
        crate::templates::library::write_atomically(&self.dir.join(file_name(id)), bytes)?;
        let now = Utc::now();
        let mut next = manifest.clone();
        next.sources.insert(
            id,
            SourceRecord {
                fetched_at: Some(now),
                origin: Some(origin),
                size: Some(bytes.len() as u64),
                sha256: Some(crate::skill_status::sha256(bytes)),
                attempted_at: Some(now),
                error: None,
            },
        );
        crate::session::write_json(&self.dir.join("manifest.json"), &next)?;
        *manifest = next;
        Ok(())
    }

    fn record_failure(&self, id: SourceId, error: &anyhow::Error) {
        let mut manifest = self.manifest.lock().unwrap();
        let record = manifest.sources.entry(id).or_default();
        record.attempted_at = Some(Utc::now());
        record.error = Some(format!("{error:#}").chars().take(MAX_ERROR_CHARS).collect());
        if let Err(error) = crate::session::write_json(&self.dir.join("manifest.json"), &*manifest)
        {
            tracing::warn!(%error, "vulnerability data manifest could not be saved");
        }
    }

    /// From the files on disk. Until all three have loaded once, or if one no
    /// longer reads, the index stays as it was.
    fn rebuild_index(&self) {
        let _rebuilding = self.rebuilding.lock().unwrap();
        let built = (|| -> Result<VulnIndex> {
            let read = |id: SourceId| {
                fs::read(self.dir.join(file_name(id)))
                    .with_context(|| format!("reading {}", file_name(id)))
            };
            let (retire, kev, epss) = (
                read(SourceId::Retire)?,
                read(SourceId::Kev)?,
                read(SourceId::Epss)?,
            );
            let revision = [&retire, &kev, &epss]
                .map(|bytes| crate::skill_status::sha256(bytes)[..12].to_string())
                .join("-");
            Ok(VulnIndex::build(
                sources::parse_retire(&retire)?,
                sources::parse_kev(&kev)?,
                sources::parse_epss(&epss)?,
                revision,
            ))
        })();
        match built {
            Ok(index) => *self.index.write().unwrap() = Some(Arc::new(index)),
            Err(error) if self.index().is_some() => {
                tracing::warn!(%error, "vulnerability data could not be read again; keeping the loaded index");
            }
            Err(_) => {}
        }
    }
}

/// Checks a minute after launch, then every hour; each source is fetched when
/// it is due.
pub async fn run_daily_update(data: Arc<VulnData>) {
    let first = tokio::time::Instant::now() + FIRST_LOOK;
    let mut looks = tokio::time::interval_at(first, LOOK_EVERY);
    loop {
        looks.tick().await;
        match client() {
            Ok(client) => {
                data.update_sources(|id| {
                    let client = client.clone();
                    async move { download(&client, id).await }
                })
                .await
            }
            Err(error) => tracing::warn!(%error, "vulnerability data client could not be built"),
        }
    }
}

/// The environment's proxy unless it points back at this machine, as the
/// self-updater uses; redirects only over HTTPS and within the source's own
/// host (EPSS redirects to the day's file).
fn client() -> Result<reqwest::Client> {
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        let host = attempt.url().host_str().map(str::to_owned);
        let first = attempt
            .previous()
            .first()
            .and_then(|url| url.host_str())
            .map(str::to_owned);
        if attempt.previous().len() >= 5 || attempt.url().scheme() != "https" || host != first {
            attempt.stop()
        } else {
            attempt.follow()
        }
    });
    let builder = reqwest::Client::builder()
        .use_rustls_tls()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(DOWNLOAD_TIMEOUT)
        .redirect(policy)
        .user_agent(format!("Sniper/{}", env!("CARGO_PKG_VERSION")));
    let builder = if crate::state::release_proxy_env_targets_loopback() {
        builder.no_proxy()
    } else {
        builder
    };
    builder
        .build()
        .context("building the vulnerability data client")
}

async fn download(client: &reqwest::Client, id: SourceId) -> Result<Vec<u8>> {
    use futures_util::StreamExt;
    let limit = id.max_bytes();
    let response = client
        .get(id.url())
        .send()
        .await
        .with_context(|| format!("fetching {}", id.name()))?;
    if !response.status().is_success() {
        bail!("{} answered {}", id.name(), response.status());
    }
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        bail!("{} is larger than {} MiB", id.name(), limit >> 20);
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("fetching {}", id.name()))?;
        if body.len() + chunk.len() > limit {
            bail!("{} is larger than {} MiB", id.name(), limit >> 20);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

// ---- API ----

pub async fn get_status(State(state): State<Arc<AppState>>) -> Json<VulnDataStatus> {
    Json(state.vulndata.status())
}

/// Fetches every source now: 202 with the status, 409 while an update runs.
pub async fn start_update(State(state): State<Arc<AppState>>) -> Response {
    if !state.vulndata.update_now() {
        return (
            StatusCode::CONFLICT,
            "Vulnerability data is already updating. Try again when it finishes.",
        )
            .into_response();
    }
    (StatusCode::ACCEPTED, Json(state.vulndata.status())).into_response()
}

/// The body is one retire.js, CISA KEV or FIRST EPSS file.
pub async fn import(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    if body.is_empty() || body.len() > SourceId::Epss.max_bytes() {
        return (
            StatusCode::BAD_REQUEST,
            "Send one retire.js, CISA KEV or FIRST EPSS file of at most 16 MiB.",
        )
            .into_response();
    }
    let data = Arc::clone(&state.vulndata);
    match tokio::task::spawn_blocking(move || data.import_blocking(&body)).await {
        Ok(Ok(source)) => Json(serde_json::json!({
            "source": source,
            "status": state.vulndata.status(),
        }))
        .into_response(),
        Ok(Err(error)) => (StatusCode::BAD_REQUEST, format!("{error:#}")).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoUpdateRequest {
    enabled: bool,
}

pub async fn set_auto_update(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AutoUpdateRequest>,
) -> Response {
    let data = Arc::clone(&state.vulndata);
    match tokio::task::spawn_blocking(move || data.set_auto_update(request.enabled)).await {
        Ok(Ok(())) => Json(state.vulndata.status()).into_response(),
        Ok(Err(error)) => {
            tracing::warn!(%error, "saving the vulnerability data switch failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookupQuery {
    product: String,
    version: String,
}

/// The advisories for one product version, for agents; 409 until the data
/// has loaded.
pub async fn lookup(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LookupQuery>,
) -> Response {
    if query.product.len() > 100 || query.version.len() > 100 {
        return (
            StatusCode::BAD_REQUEST,
            "product and version are at most 100 characters",
        )
            .into_response();
    }
    let Some(index) = state.vulndata.index() else {
        return (
            StatusCode::CONFLICT,
            "Vulnerability data has not loaded yet: it needs retire.js, CISA KEV and FIRST EPSS once each.",
        )
            .into_response();
    };
    Json(serde_json::json!({
        "product": query.product,
        "version": query.version,
        "advisories": index.advisories(&query.product, &query.version),
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    const RETIRE: &str = r#"{"jquery": {"vulnerabilities": [{"atOrAbove": "1.0.3", "below": "3.5.0",
        "severity": "medium", "identifiers": {"CVE": ["CVE-2020-11023"], "summary": "jQuery XSS"},
        "info": ["https://example.com/advisory"]}]}}"#;
    const KEV: &str =
        r#"{"catalogVersion": "2026.10.27", "vulnerabilities": [{"cveID": "CVE-2020-11023"}]}"#;
    const EPSS: &str = "cve,epss,percentile\nCVE-2020-11023,0.94,0.99\n";

    fn fixture(id: SourceId) -> Vec<u8> {
        match id {
            SourceId::Retire => RETIRE,
            SourceId::Kev => KEV,
            SourceId::Epss => EPSS,
        }
        .as_bytes()
        .to_vec()
    }

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("sniper-vulndata-{name}-{}", uuid::Uuid::new_v4()))
    }

    fn source(status: &VulnDataStatus, id: SourceId) -> SourceStatus {
        status
            .sources
            .iter()
            .find(|source| source.id == id)
            .unwrap()
            .clone()
    }

    #[test]
    fn a_source_is_due_when_it_never_loaded_failed_or_is_a_day_old() {
        let now = Utc::now();
        let loaded = |hours| SourceRecord {
            fetched_at: Some(now - chrono::Duration::hours(hours)),
            ..SourceRecord::default()
        };
        assert!(due(&SourceRecord::default(), true, now));
        assert!(!due(&loaded(23), true, now));
        assert!(due(&loaded(24), true, now));
        let failed = SourceRecord {
            error: Some("refused".into()),
            ..loaded(1)
        };
        assert!(due(&failed, true, now));
        assert!(!due(&SourceRecord::default(), false, now));
    }

    // Review focus 1: on first launch a network blocks one host.
    #[tokio::test]
    async fn one_unreachable_source_keeps_the_others_and_says_why() {
        let dir = scratch("unreachable");
        let data = VulnData::load(&dir);
        let kev_reachable = Arc::new(AtomicBool::new(false));
        let fetch = |reachable: Arc<AtomicBool>| {
            move |id: SourceId| {
                let reachable = reachable.load(std::sync::atomic::Ordering::SeqCst);
                async move {
                    if id == SourceId::Kev && !reachable {
                        anyhow::bail!("www.cisa.gov could not be reached");
                    }
                    Ok(fixture(id))
                }
            }
        };
        data.update_sources(fetch(kev_reachable.clone())).await;
        let status = data.status();
        let kev = source(&status, SourceId::Kev);
        assert!(kev.fetched_at.is_none());
        assert!(kev
            .error
            .as_deref()
            .unwrap()
            .contains("could not be reached"));
        for id in [SourceId::Retire, SourceId::Epss] {
            let loaded = source(&status, id);
            assert!(
                loaded.fetched_at.is_some() && loaded.error.is_none(),
                "{id:?}"
            );
        }
        assert!(data.index().is_none());

        kev_reachable.store(true, std::sync::atomic::Ordering::SeqCst);
        data.update_sources(fetch(kev_reachable)).await;
        let index = data.index().expect("all three sources loaded");
        assert_eq!(index.advisories("jquery", "3.4.1").len(), 1);
        assert!(data.status().revision.is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    // Review focus 2: an oversized download is refused and changes nothing.
    #[tokio::test]
    async fn an_oversized_download_keeps_the_previous_file_and_index() {
        let dir = scratch("oversized");
        let data = VulnData::load(&dir);
        data.update_sources(|id| async move { Ok(fixture(id)) })
            .await;
        let revision = data.index().unwrap().revision.clone();

        data.fetch_all(|id| async move {
            if id == SourceId::Retire {
                Ok(vec![b' '; SourceId::Retire.max_bytes() + 1])
            } else {
                Ok(fixture(id))
            }
        })
        .await;
        let retire = source(&data.status(), SourceId::Retire);
        assert!(retire.error.is_some());
        assert!(retire.fetched_at.is_some());
        assert_eq!(
            std::fs::read(dir.join("vulndata").join("retire.json")).unwrap(),
            RETIRE.as_bytes()
        );
        assert_eq!(data.index().unwrap().revision, revision);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_import_names_its_source_and_is_marked_imported() {
        let dir = scratch("import");
        let data = VulnData::load(&dir);
        assert_eq!(data.import_blocking(KEV.as_bytes()).unwrap(), SourceId::Kev);
        let kev = source(&data.status(), SourceId::Kev);
        assert_eq!(kev.origin, Some(Origin::Import));
        assert!(kev.fetched_at.is_some());
        assert!(data.import_blocking(b"not a data file").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_daily_switch_survives_a_reload() {
        let dir = scratch("switch");
        VulnData::load(&dir).set_auto_update(false).unwrap();
        assert!(!VulnData::load(&dir).status().auto_update);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_corrupt_manifest_is_set_aside_and_the_store_starts_empty() {
        let dir = scratch("corrupt");
        std::fs::create_dir_all(dir.join("vulndata")).unwrap();
        std::fs::write(dir.join("vulndata").join("manifest.json"), b"{not json").unwrap();
        let status = VulnData::load(&dir).status();
        assert!(status.auto_update);
        assert!(status
            .sources
            .iter()
            .all(|source| source.fetched_at.is_none()));
        let aside = std::fs::read_dir(dir.join("vulndata"))
            .unwrap()
            .flatten()
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".manifest.corrupt-")
            });
        assert!(aside);
        let _ = std::fs::remove_dir_all(dir);
    }
}
