//! The template library: one release of the community templates, downloaded
//! or imported by the operator and kept under `<data_dir>/templates/` for
//! every session, like Burp's BCheck library.
//!
//! - `templates.json` — which release is installed, and which passive
//!   templates the operator turned on (none until they do).
//! - `bundle-<sha>.ndjson` — every template's text, written once per import
//!   and read back by offset. Archive paths are only labels: nothing from an
//!   archive ever becomes a file name.
//! - `index-<sha>-e<engine>.json` — what each template is and whether Sniper
//!   can run it. Derived, and rebuilt when the engine changes.

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use axum::{
    body::Bytes,
    extract::{Path as AxumPath, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::{
    active::{self, ActiveTemplate},
    engine::{self, CompiledTemplate, PassiveSet},
    model::{self, PassiveKind},
    ENGINE_VERSION,
};
use crate::state::AppState;

const REPOSITORY: &str = "https://github.com/projectdiscovery/nuclei-templates";
const LATEST_RELEASE_API: &str =
    "https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest";
pub const LICENSE: &str = "MIT";
/// The same cap as an API request body, so a download and an upload of the
/// same archive are held to the same size.
pub const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
const MAX_UNPACKED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_TEMPLATES: usize = 30_000;
/// The largest payload file in a release is about 2 MiB.
const MAX_HELPER_BYTES: usize = 8 * 1024 * 1024;
const MAX_HELPERS: usize = 10_000;
const MAX_CHECKSUMS_BYTES: usize = 64 * 1024;
/// Passive evaluations that may run at once. A capture burst beyond it skips
/// template evaluation rather than wait inside a proxy task, which would hold
/// the session busy.
const PASSIVE_PERMITS: usize = 4;
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(180);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LibraryInfo {
    /// The release tag, or `imported` for an archive the operator supplied.
    pub tag: String,
    /// `github` or `import`.
    pub source: String,
    pub sha256: String,
    /// The archive matched the SHA-256 the release publishes.
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    pub imported_at: DateTime<Utc>,
    pub templates: usize,
    pub bundle: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Manifest {
    #[serde(default)]
    library: Option<LibraryInfo>,
    #[serde(default)]
    passive_enabled: Vec<String>,
}

/// One template in the index: enough to list and filter it. Its text stays
/// in the bundle until someone opens it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TemplateMeta {
    pub id: String,
    pub path: String,
    pub offset: u64,
    pub len: u64,
    pub name: String,
    pub severity: String,
    pub authors: Vec<String>,
    pub tags: Vec<String>,
    pub cve: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f64>,
    pub protocol: String,
    /// `global` or `base_url_get` when the template can judge captured
    /// traffic without sending anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passive: Option<String>,
    pub passive_supported: bool,
    pub active_supported: bool,
    /// Requests one Template Scan run sends to a target, redirects aside;
    /// 0 when it cannot run actively.
    #[serde(default)]
    pub requests: usize,
    /// Why it cannot run: the passive reasons for a passive-shaped template,
    /// the active ones otherwise.
    pub reasons: Vec<String>,
    pub risks: Vec<String>,
}

/// Where a payload file sits in the bundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct HelperRow {
    path: String,
    offset: u64,
    len: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct IndexFile {
    engine: u32,
    sha256: String,
    templates: Vec<TemplateMeta>,
    #[serde(default)]
    helpers: Vec<HelperRow>,
    #[serde(default)]
    duplicates: usize,
    #[serde(default)]
    skipped: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Loading,
    Idle,
    Downloading,
    Importing,
    Failed,
}

#[derive(Clone, Debug)]
struct Task {
    state: TaskState,
    error: Option<String>,
    received_bytes: Option<u64>,
    /// While importing: templates checked so far, out of how many.
    checked: Option<(u64, u64)>,
    latest: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LibraryStatus {
    pub state: TaskState,
    pub library: Option<LibraryInfo>,
    pub templates: usize,
    pub http: usize,
    pub passive_supported: usize,
    pub active_supported: usize,
    pub passive_enabled: usize,
    /// Responses whose template evaluation was skipped under load; Rescan
    /// covers them.
    pub passive_skipped_under_load: u64,
    pub duplicates: usize,
    pub skipped: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
    pub repository: &'static str,
    pub license: &'static str,
}

#[derive(Default)]
struct Loaded {
    manifest: Manifest,
    index: Arc<Vec<TemplateMeta>>,
    /// The release's payload files by path, which scans compile with.
    helpers: Arc<HashMap<String, String>>,
    by_id: HashMap<String, usize>,
    duplicates: usize,
    skipped: usize,
}

pub struct TemplateLibrary {
    dir: PathBuf,
    loaded: RwLock<Loaded>,
    passive: RwLock<Option<Arc<PassiveSet>>>,
    /// Compiled passive templates by id, so turning one on does not compile
    /// the others again.
    compiled: Mutex<HashMap<String, Arc<CompiledTemplate>>>,
    task: Mutex<Task>,
    /// Serializes manifest writes: a passive toggle against an import.
    writer: Mutex<()>,
    permits: Arc<Semaphore>,
    skipped_under_load: AtomicU64,
}

pub enum Source {
    GitHub {
        tag: String,
        expected_sha256: String,
    },
    Import,
}

fn index_file_name(sha256: &str) -> String {
    format!("index-{}-e{ENGINE_VERSION}.json", &sha256[..16])
}

fn bundle_file_name(sha256: &str) -> String {
    format!("bundle-{}.ndjson", &sha256[..16])
}

impl TemplateLibrary {
    /// Loads the library in the background: the index can take seconds to
    /// rebuild, and startup must not wait for it.
    pub fn load(data_dir: &Path) -> Arc<Self> {
        let library = Arc::new(Self::empty(data_dir));
        let background = Arc::clone(&library);
        let spawned = std::thread::Builder::new()
            .name("template-library".into())
            .spawn(move || background.load_blocking());
        if spawned.is_err() {
            library.set_task(TaskState::Failed, Some("could not start the loader".into()));
        }
        library
    }

    fn empty(data_dir: &Path) -> Self {
        Self {
            dir: data_dir.join("templates"),
            loaded: RwLock::new(Loaded::default()),
            passive: RwLock::new(None),
            compiled: Mutex::new(HashMap::new()),
            task: Mutex::new(Task {
                state: TaskState::Loading,
                error: None,
                received_bytes: None,
                checked: None,
                latest: None,
            }),
            writer: Mutex::new(()),
            permits: Arc::new(Semaphore::new(PASSIVE_PERMITS)),
            skipped_under_load: AtomicU64::new(0),
        }
    }

    fn set_task(&self, state: TaskState, error: Option<String>) {
        let mut task = self.task.lock().unwrap();
        task.state = state;
        task.error = error;
        if state != TaskState::Downloading {
            task.received_bytes = None;
        }
        if state != TaskState::Importing {
            task.checked = None;
        }
    }

    fn manifest_path(&self) -> PathBuf {
        self.dir.join("templates.json")
    }

    fn load_blocking(&self) {
        match self.load_from_disk() {
            Ok(()) => self.set_task(TaskState::Idle, None),
            Err(error) => {
                tracing::warn!(%error, "template library could not be loaded");
                self.set_task(TaskState::Failed, Some(format!("{error:#}")));
            }
        }
    }

    fn load_from_disk(&self) -> Result<()> {
        let manifest = match fs::read(self.manifest_path()) {
            Ok(bytes) => match serde_json::from_slice::<Manifest>(&bytes) {
                Ok(manifest) => manifest,
                Err(_) => {
                    // A corrupt manifest must not take the library down for
                    // good; it is kept aside for a look and replaced.
                    let aside = self
                        .dir
                        .join(format!(".templates.corrupt-{}.json", uuid::Uuid::new_v4()));
                    let _ = crate::platform::rename(self.manifest_path(), aside);
                    Manifest::default()
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Manifest::default(),
            Err(error) => return Err(error).context("reading templates.json"),
        };
        let (built, helpers) = match &manifest.library {
            Some(info) => self.read_or_rebuild_index(info)?,
            None => (BuiltIndex::default(), HashMap::new()),
        };
        self.install(manifest, built, helpers);
        self.rebuild_passive();
        self.remove_orphans();
        Ok(())
    }

    fn read_or_rebuild_index(
        &self,
        info: &LibraryInfo,
    ) -> Result<(BuiltIndex, HashMap<String, String>)> {
        let path = self.dir.join(index_file_name(&info.sha256));
        let bundle = self.dir.join(&info.bundle);
        if let Ok(bytes) = fs::read(&path) {
            if let Ok(index) = serde_json::from_slice::<IndexFile>(&bytes) {
                if index.engine == ENGINE_VERSION && index.sha256 == info.sha256 {
                    let helpers = read_helpers(&bundle, &index.helpers)?;
                    let built = BuiltIndex {
                        templates: index.templates,
                        helpers: index.helpers,
                        duplicates: index.duplicates,
                        skipped: index.skipped,
                    };
                    return Ok((built, helpers));
                }
            }
        }
        // The engine changed, or the index is gone: classify the bundle again.
        let mut entries = Vec::new();
        let mut rows = Vec::new();
        let mut helpers = HashMap::new();
        let bundle = fs::read(bundle).context("reading the template bundle")?;
        let mut offset = 0u64;
        for line in bundle.split_inclusive(|byte| *byte == b'\n') {
            let length = line.len() as u64;
            let row: BundleRow =
                serde_json::from_slice(line).context("reading the template bundle")?;
            if row.path.ends_with(".yaml") {
                entries.push((row.path, row.yaml, offset, length));
            } else {
                rows.push(HelperRow {
                    path: row.path.clone(),
                    offset,
                    len: length,
                });
                helpers.insert(row.path, row.yaml);
            }
            offset += length;
        }
        let mut built = index_entries(entries, &helpers, &|_, _| {});
        built.helpers = rows;
        write_index(&self.dir, &info.sha256, &built)?;
        Ok((built, helpers))
    }

    fn install(&self, manifest: Manifest, built: BuiltIndex, helpers: HashMap<String, String>) {
        let by_id = built
            .templates
            .iter()
            .enumerate()
            .map(|(position, meta)| (meta.id.clone(), position))
            .collect();
        *self.loaded.write().unwrap() = Loaded {
            manifest,
            index: Arc::new(built.templates),
            helpers: Arc::new(helpers),
            by_id,
            duplicates: built.duplicates,
            skipped: built.skipped,
        };
    }

    /// Deletes bundles and indexes no manifest refers to: what a crash between
    /// writing a new release and committing it leaves behind.
    fn remove_orphans(&self) {
        let keep: HashSet<String> = {
            let loaded = self.loaded.read().unwrap();
            loaded
                .manifest
                .library
                .iter()
                .flat_map(|info| [info.bundle.clone(), index_file_name(&info.sha256)])
                .collect()
        };
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let ours = (name.starts_with("bundle-") && name.ends_with(".ndjson"))
                || (name.starts_with("index-") && name.ends_with(".json"))
                || name.contains(".tmp-");
            if ours && !keep.contains(&name) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    pub fn status(&self) -> LibraryStatus {
        let task = self.task.lock().unwrap().clone();
        let loaded = self.loaded.read().unwrap();
        let index = &loaded.index;
        LibraryStatus {
            state: task.state,
            library: loaded.manifest.library.clone(),
            templates: index.len(),
            http: index.iter().filter(|meta| meta.protocol == "http").count(),
            passive_supported: index.iter().filter(|meta| meta.passive_supported).count(),
            active_supported: index.iter().filter(|meta| meta.active_supported).count(),
            passive_enabled: loaded.manifest.passive_enabled.len(),
            passive_skipped_under_load: self.skipped_under_load.load(Ordering::Relaxed),
            duplicates: loaded.duplicates,
            skipped: loaded.skipped,
            error: task.error,
            received_bytes: task.received_bytes,
            checked: task.checked.map(|(done, _)| done),
            check_total: task.checked.map(|(_, total)| total),
            latest: task.latest,
            repository: REPOSITORY,
            license: LICENSE,
        }
    }

    /// The enabled passive templates, compiled; None when none are enabled.
    pub fn passive_set(&self) -> Option<Arc<PassiveSet>> {
        self.passive.read().unwrap().clone()
    }

    /// A permit for one passive evaluation, or None under load.
    pub fn try_passive_permit(&self) -> Option<OwnedSemaphorePermit> {
        let permit = Arc::clone(&self.permits).try_acquire_owned().ok();
        if permit.is_none() {
            self.skipped_under_load.fetch_add(1, Ordering::Relaxed);
        }
        permit
    }

    fn read_text(&self, meta: &TemplateMeta) -> Result<String> {
        let bundle = {
            let loaded = self.loaded.read().unwrap();
            let info = loaded
                .manifest
                .library
                .as_ref()
                .ok_or_else(|| anyhow!("no library"))?;
            self.dir.join(&info.bundle)
        };
        let mut file = fs::File::open(bundle).context("opening the template bundle")?;
        file.seek(SeekFrom::Start(meta.offset))?;
        let mut line = vec![0; meta.len as usize];
        file.read_exact(&mut line)?;
        let row: BundleRow =
            serde_json::from_slice(&line).context("reading the template bundle")?;
        if row.path != meta.path {
            bail!("the template bundle does not match its index");
        }
        Ok(row.yaml)
    }

    fn rebuild_passive(&self) {
        let (enabled, index, by_id) = {
            let loaded = self.loaded.read().unwrap();
            (
                loaded.manifest.passive_enabled.clone(),
                Arc::clone(&loaded.index),
                loaded.by_id.clone(),
            )
        };
        let mut templates = Vec::new();
        for id in &enabled {
            let Some(meta) = by_id.get(id).map(|position| &index[*position]) else {
                continue;
            };
            if !meta.passive_supported {
                continue;
            }
            if let Some(compiled) = self.compiled.lock().unwrap().get(id) {
                templates.push(Arc::clone(compiled));
                continue;
            }
            let compiled = self.read_text(meta).ok().and_then(|text| {
                let parsed = model::parse(&text).ok()?;
                let classification = model::classify(&parsed);
                engine::compile_passive(&parsed, &classification).ok()
            });
            if let Some(compiled) = compiled {
                let compiled = Arc::new(compiled);
                self.compiled
                    .lock()
                    .unwrap()
                    .insert(id.clone(), Arc::clone(&compiled));
                templates.push(compiled);
            }
        }
        *self.passive.write().unwrap() =
            (!templates.is_empty()).then(|| Arc::new(PassiveSet::new(templates)));
    }

    /// Turns passive templates on or off. Ids that are not passive-capable
    /// are ignored and counted. Returns how many are enabled afterwards.
    pub fn set_passive(&self, ids: &[String], enabled: bool) -> Result<(usize, usize)> {
        let _writer = self.writer.lock().unwrap();
        let (mut manifest, ignored) = {
            let loaded = self.loaded.read().unwrap();
            let mut manifest = loaded.manifest.clone();
            let mut current: Vec<String> = manifest.passive_enabled.clone();
            let mut ignored = 0;
            for id in ids {
                let capable = loaded
                    .by_id
                    .get(id)
                    .is_some_and(|position| loaded.index[*position].passive_supported);
                if !capable {
                    ignored += 1;
                    continue;
                }
                if enabled {
                    if !current.contains(id) {
                        current.push(id.clone());
                    }
                } else {
                    current.retain(|existing| existing != id);
                }
            }
            current.sort();
            manifest.passive_enabled = current;
            (manifest, ignored)
        };
        crate::session::write_json(&self.manifest_path(), &manifest)?;
        let count = manifest.passive_enabled.len();
        self.loaded.write().unwrap().manifest = std::mem::take(&mut manifest);
        self.rebuild_passive();
        Ok((count, ignored))
    }

    /// Unpacks, classifies and installs an archive. Runs on a blocking thread.
    pub fn import_blocking(&self, bytes: &[u8], source: Source) -> Result<()> {
        let sha256 = crate::skill_status::sha256(bytes);
        let (tag, verified) = match &source {
            Source::GitHub {
                tag,
                expected_sha256,
            } => {
                if !sha256.eq_ignore_ascii_case(expected_sha256) {
                    bail!(
                        "the downloaded archive does not match the SHA-256 the release publishes"
                    );
                }
                (tag.clone(), true)
            }
            Source::Import => ("imported".to_string(), false),
        };
        let unpacked = unpack(bytes)?;
        let commit = unpacked.commit.clone();
        let mut offset = 0u64;
        let mut lines = Vec::with_capacity(unpacked.files.len() + unpacked.helpers.len());
        let mut entries = Vec::with_capacity(unpacked.files.len());
        for (path, yaml) in unpacked.files {
            let mut line = serde_json::to_vec(&BundleRow {
                path: path.clone(),
                yaml: yaml.clone(),
            })?;
            line.push(b'\n');
            entries.push((path, yaml, offset, line.len() as u64));
            offset += line.len() as u64;
            lines.push(line);
        }
        // Payload files follow the templates in the same bundle.
        let mut rows = Vec::with_capacity(unpacked.helpers.len());
        let mut helpers = HashMap::with_capacity(unpacked.helpers.len());
        for (path, text) in unpacked.helpers {
            let mut line = serde_json::to_vec(&BundleRow {
                path: path.clone(),
                yaml: text.clone(),
            })?;
            line.push(b'\n');
            rows.push(HelperRow {
                path: path.clone(),
                offset,
                len: line.len() as u64,
            });
            offset += line.len() as u64;
            lines.push(line);
            helpers.insert(path, text);
        }
        let mut built = index_entries(entries, &helpers, &|done, total| {
            self.task.lock().unwrap().checked = Some((done as u64, total as u64));
        });
        built.helpers = rows;
        built.skipped += unpacked.skipped;
        fs::create_dir_all(&self.dir).context("creating the templates directory")?;
        let bundle = bundle_file_name(&sha256);
        write_atomically(&self.dir.join(&bundle), &lines.concat())?;
        write_index(&self.dir, &sha256, &built)?;
        let info = LibraryInfo {
            tag,
            source: match source {
                Source::GitHub { .. } => "github".into(),
                Source::Import => "import".into(),
            },
            sha256,
            verified,
            commit,
            imported_at: Utc::now(),
            templates: built.templates.len(),
            bundle,
        };
        {
            let _writer = self.writer.lock().unwrap();
            let mut manifest = self.loaded.read().unwrap().manifest.clone();
            manifest.library = Some(info);
            // Ids a new release dropped are no longer listed; the rest stay on.
            let ids: HashSet<&str> = built
                .templates
                .iter()
                .map(|meta| meta.id.as_str())
                .collect();
            manifest
                .passive_enabled
                .retain(|id| ids.contains(id.as_str()));
            crate::session::write_json(&self.manifest_path(), &manifest)?;
            self.compiled.lock().unwrap().clear();
            self.install(manifest, built, helpers);
        }
        self.rebuild_passive();
        self.remove_orphans();
        Ok(())
    }

    pub fn list(&self, query: &ListQuery) -> ListPage {
        let loaded = self.loaded.read().unwrap();
        let enabled: HashSet<&str> = loaded
            .manifest
            .passive_enabled
            .iter()
            .map(String::as_str)
            .collect();
        let search = query
            .search
            .as_deref()
            .map(str::to_ascii_lowercase)
            .filter(|s| !s.is_empty());
        let severities: Vec<String> = split_list(query.severity.as_deref());
        let protocols: Vec<String> = split_list(query.protocol.as_deref());
        let tag = query
            .tag
            .as_deref()
            .map(str::to_ascii_lowercase)
            .filter(|s| !s.is_empty());
        let mut matching: Vec<&TemplateMeta> = loaded
            .index
            .iter()
            .filter(|meta| severities.is_empty() || severities.contains(&meta.severity))
            .filter(|meta| protocols.is_empty() || protocols.contains(&meta.protocol))
            .filter(|meta| {
                tag.as_ref()
                    .is_none_or(|tag| meta.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)))
            })
            .filter(|meta| match query.support.as_deref() {
                Some("passive") => meta.passive_supported,
                Some("active") => meta.active_supported,
                Some("unsupported") => !meta.passive_supported && !meta.active_supported,
                _ => true,
            })
            .filter(|meta| {
                query
                    .enabled
                    .is_none_or(|on| on == enabled.contains(meta.id.as_str()))
            })
            .filter(|meta| {
                search.as_ref().is_none_or(|needle| {
                    meta.id.to_ascii_lowercase().contains(needle)
                        || meta.name.to_ascii_lowercase().contains(needle)
                        || meta.path.to_ascii_lowercase().contains(needle)
                        || meta
                            .tags
                            .iter()
                            .any(|t| t.to_ascii_lowercase().contains(needle))
                        || meta
                            .cve
                            .iter()
                            .any(|c| c.to_ascii_lowercase().contains(needle))
                })
            })
            .collect();
        // Templates Sniper can run come first, so a list of everything does not
        // open on a page of code and flow templates it cannot.
        matching.sort_by_key(|meta| !(meta.passive_supported || meta.active_supported));
        let total = matching.len();
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(200).min(MAX_LIST_LIMIT);
        let items = matching
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|meta| ListItem {
                enabled: enabled.contains(meta.id.as_str()),
                meta: meta.clone(),
            })
            .collect();
        ListPage { total, items }
    }

    /// The templates a scan would send: those that can run actively among
    /// `ids`, or among what `filter` selects. The second value counts ids
    /// that are unknown or cannot run actively.
    pub fn active_selection(
        &self,
        ids: &[String],
        filter: Option<&ListQuery>,
    ) -> (Vec<TemplateMeta>, usize) {
        if let Some(filter) = filter {
            let query = ListQuery {
                support: Some("active".into()),
                enabled: None,
                limit: Some(MAX_LIST_LIMIT),
                offset: Some(0),
                ..filter.clone()
            };
            let metas = self.list(&query).items.into_iter().map(|item| item.meta);
            return (metas.collect(), 0);
        }
        let loaded = self.loaded.read().unwrap();
        let mut seen = HashSet::new();
        let mut metas = Vec::new();
        let mut ignored = 0;
        for id in ids {
            if !seen.insert(id.as_str()) {
                continue;
            }
            match loaded
                .by_id
                .get(id)
                .map(|position| &loaded.index[*position])
            {
                Some(meta) if meta.active_supported => metas.push(meta.clone()),
                _ => ignored += 1,
            }
        }
        (metas, ignored)
    }

    /// One template compiled for sending, read from the installed release. It
    /// fails when the release changed since `meta` was listed.
    pub fn compile_active(&self, meta: &TemplateMeta) -> Result<ActiveTemplate> {
        let text = self.read_text(meta)?;
        let parsed = model::parse(&text).map_err(|error| anyhow!("{}", error.code))?;
        let classification = model::classify(&parsed);
        let helpers = Arc::clone(&self.loaded.read().unwrap().helpers);
        active::compile_active(&parsed, &classification, &helpers)
            .map_err(|error| anyhow!("{}", error.0))
    }

    /// The installed release as a scan records it: tag and archive hash.
    pub fn release_label(&self) -> Option<String> {
        let loaded = self.loaded.read().unwrap();
        loaded
            .manifest
            .library
            .as_ref()
            .map(|info| format!("{} ({})", info.tag, &info.sha256[..12]))
    }

    /// Every id the query selects, for turning a filtered list on at once.
    pub fn select_ids(&self, query: &ListQuery) -> Vec<String> {
        let unlimited = ListQuery {
            limit: Some(MAX_LIST_LIMIT),
            offset: Some(0),
            ..query.clone()
        };
        self.list(&unlimited)
            .items
            .into_iter()
            .map(|item| item.meta.id)
            .collect()
    }

    pub fn get(&self, id: &str) -> Option<TemplateDetail> {
        let (meta, enabled) = {
            let loaded = self.loaded.read().unwrap();
            let meta = loaded.index.get(*loaded.by_id.get(id)?)?.clone();
            let enabled = loaded.manifest.passive_enabled.contains(&meta.id);
            (meta, enabled)
        };
        let yaml = self.read_text(&meta).ok()?;
        let parsed = model::parse(&yaml).ok();
        Some(TemplateDetail {
            description: parsed
                .as_ref()
                .map(|parsed| parsed.info.description.clone())
                .unwrap_or_default(),
            references: parsed
                .as_ref()
                .map(|parsed| parsed.info.references.clone())
                .unwrap_or_default(),
            cwe: parsed.map(|parsed| parsed.info.cwe).unwrap_or_default(),
            enabled,
            meta,
            yaml,
        })
    }

    fn begin_task(&self, state: TaskState) -> bool {
        let mut task = self.task.lock().unwrap();
        if matches!(
            task.state,
            TaskState::Loading | TaskState::Downloading | TaskState::Importing
        ) {
            return false;
        }
        task.state = state;
        task.error = None;
        task.received_bytes = None;
        task.checked = None;
        true
    }

    /// The newest release tag, asked of GitHub once.
    pub async fn check_latest(&self) -> Result<String> {
        let client = github_client()?;
        let tag = latest_tag(&client).await?;
        self.task.lock().unwrap().latest = Some(tag.clone());
        Ok(tag)
    }

    async fn download(self: Arc<Self>) -> Result<()> {
        let client = github_client()?;
        let tag = latest_tag(&client).await?;
        self.task.lock().unwrap().latest = Some(tag.clone());
        let version = tag.trim_start_matches('v');
        let checksums = fetch_bytes(
            &client,
            &format!(
                "{REPOSITORY}/releases/download/{tag}/nuclei-templates-{version}_checksums.txt"
            ),
            MAX_CHECKSUMS_BYTES,
            None,
        )
        .await
        .context("downloading the release checksums")?;
        let expected = String::from_utf8_lossy(&checksums)
            .lines()
            .find_map(|line| {
                let (hash, name) = line.split_once(char::is_whitespace)?;
                (name.trim() == format!("nuclei-templates-{version}.tar.gz")
                    && hash.len() == 64
                    && hash.bytes().all(|b| b.is_ascii_hexdigit()))
                .then(|| hash.to_ascii_lowercase())
            })
            .ok_or_else(|| anyhow!("the release publishes no checksum for its archive"))?;
        let archive = fetch_bytes(
            &client,
            &format!("{REPOSITORY}/archive/refs/tags/{tag}.tar.gz"),
            MAX_ARCHIVE_BYTES,
            Some(&*self),
        )
        .await
        .context("downloading the templates archive")?;
        self.set_task(TaskState::Importing, None);
        let library = Arc::clone(&self);
        tokio::task::spawn_blocking(move || {
            library.import_blocking(
                &archive,
                Source::GitHub {
                    tag,
                    expected_sha256: expected,
                },
            )
        })
        .await
        .context("the import stopped")?
    }

    /// Starts downloading the latest release. False when a load, download or
    /// import is already running.
    pub fn start_download(self: &Arc<Self>) -> bool {
        if !self.begin_task(TaskState::Downloading) {
            return false;
        }
        let library = Arc::clone(self);
        tokio::spawn(async move {
            match Arc::clone(&library).download().await {
                Ok(()) => library.set_task(TaskState::Idle, None),
                Err(error) => {
                    tracing::warn!(%error, "template download failed");
                    library.set_task(TaskState::Failed, Some(format!("{error:#}")));
                }
            }
        });
        true
    }

    /// Starts importing an archive the operator supplied.
    pub fn start_import(self: &Arc<Self>, bytes: Bytes) -> bool {
        if !self.begin_task(TaskState::Importing) {
            return false;
        }
        let library = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            match library.import_blocking(&bytes, Source::Import) {
                Ok(()) => library.set_task(TaskState::Idle, None),
                Err(error) => {
                    tracing::warn!(%error, "template import failed");
                    library.set_task(TaskState::Failed, Some(format!("{error:#}")));
                }
            }
        });
        true
    }
}

const MAX_LIST_LIMIT: usize = 30_000;

fn split_list(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or("")
        .split(',')
        .map(|item| item.trim().to_ascii_lowercase())
        .filter(|item| !item.is_empty())
        .collect()
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    pub search: Option<String>,
    pub severity: Option<String>,
    pub protocol: Option<String>,
    pub support: Option<String>,
    pub tag: Option<String>,
    pub enabled: Option<bool>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ListItem {
    #[serde(flatten)]
    pub meta: TemplateMeta,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ListPage {
    pub total: usize,
    pub items: Vec<ListItem>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TemplateDetail {
    #[serde(flatten)]
    pub meta: TemplateMeta,
    pub enabled: bool,
    pub description: String,
    pub references: Vec<String>,
    pub cwe: Vec<String>,
    pub yaml: String,
}

/// One bundle line: a template, or a payload file whose path does not end in
/// `.yaml`.
#[derive(Serialize, Deserialize)]
struct BundleRow {
    path: String,
    yaml: String,
}

#[derive(Default)]
struct BuiltIndex {
    templates: Vec<TemplateMeta>,
    helpers: Vec<HelperRow>,
    duplicates: usize,
    skipped: usize,
}

/// Reads the payload files an index lists back from the bundle.
fn read_helpers(bundle: &Path, rows: &[HelperRow]) -> Result<HashMap<String, String>> {
    let mut helpers = HashMap::with_capacity(rows.len());
    if rows.is_empty() {
        return Ok(helpers);
    }
    let mut file = fs::File::open(bundle).context("opening the template bundle")?;
    for row in rows {
        file.seek(SeekFrom::Start(row.offset))?;
        let mut line = vec![0; row.len as usize];
        file.read_exact(&mut line)?;
        let read: BundleRow =
            serde_json::from_slice(&line).context("reading the template bundle")?;
        if read.path != row.path {
            bail!("the template bundle does not match its index");
        }
        helpers.insert(read.path, read.yaml);
    }
    Ok(helpers)
}

/// Classifies every template. The first of a duplicated id wins, as in
/// Nuclei; files that do not parse are counted, not listed. `progress` hears
/// how many are checked, out of how many, every so often and at the end.
fn index_entries(
    entries: Vec<(String, String, u64, u64)>,
    helpers: &HashMap<String, String>,
    progress: &dyn Fn(usize, usize),
) -> BuiltIndex {
    let mut seen = HashSet::new();
    let mut templates = Vec::new();
    let mut duplicates = 0;
    let mut skipped = 0;
    let total = entries.len();
    for (checked, (path, yaml, offset, len)) in entries.into_iter().enumerate() {
        if checked % 250 == 0 {
            progress(checked, total);
        }
        let Ok(parsed) = std::panic::catch_unwind(|| model::parse(&yaml)).unwrap_or_else(|_| {
            Err(model::ParseError {
                code: "panic",
                detail: String::new(),
            })
        }) else {
            skipped += 1;
            continue;
        };
        if !seen.insert(parsed.info.id.clone()) {
            duplicates += 1;
            continue;
        }
        let classification = model::classify(&parsed);
        let mut passive_supported = classification.passive_supported();
        let mut reasons: Vec<String> = if classification.passive.is_some() {
            classification.passive_reasons.iter().cloned().collect()
        } else {
            classification.active_reasons.iter().cloned().collect()
        };
        if passive_supported {
            // The classifier reads structure; compiling also checks every
            // pattern and expression.
            if let Err(error) = engine::compile_passive(&parsed, &classification) {
                passive_supported = false;
                reasons.push(error.0);
            }
        }
        let mut active_supported = classification.active_supported();
        let mut requests = 0;
        if active_supported {
            match active::compile_active(&parsed, &classification, helpers) {
                Ok(template) => requests = template.request_count(),
                Err(error) => {
                    active_supported = false;
                    if classification.passive.is_none() {
                        reasons.push(error.0);
                    }
                }
            }
        }
        let info = parsed.info;
        templates.push(TemplateMeta {
            id: info.id,
            path,
            offset,
            len,
            name: info.name,
            severity: info.severity,
            authors: info.authors,
            tags: info.tags,
            cve: info.cve,
            cvss_score: info.cvss_score,
            protocol: classification.protocol.to_string(),
            passive: classification.passive.map(|kind| {
                match kind {
                    PassiveKind::Global => "global",
                    PassiveKind::BaseUrlGet => "base_url_get",
                }
                .to_string()
            }),
            passive_supported,
            active_supported,
            requests,
            reasons,
            risks: classification.risks.into_iter().collect(),
        });
    }
    progress(total, total);
    BuiltIndex {
        templates,
        helpers: Vec::new(),
        duplicates,
        skipped,
    }
}

fn write_index(dir: &Path, sha256: &str, built: &BuiltIndex) -> Result<()> {
    crate::session::write_json(
        &dir.join(index_file_name(sha256)),
        &IndexFile {
            engine: ENGINE_VERSION,
            sha256: sha256.to_string(),
            templates: built.templates.clone(),
            helpers: built.helpers.clone(),
            duplicates: built.duplicates,
            skipped: built.skipped,
        },
    )
}

/// Temp file, fsync, rename, directory fsync: the bundle is either whole or
/// absent.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let temp = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = crate::session::create_private_file(&temp)
            .with_context(|| format!("writing {}", temp.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        crate::platform::rename(&temp, path)?;
        if let Some(parent) = path.parent() {
            crate::platform::sync_directory(parent)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

struct Unpacked {
    files: Vec<(String, String)>,
    /// Payload files: the text files under `helpers/`.
    helpers: Vec<(String, String)>,
    commit: Option<String>,
    skipped: usize,
}

/// Reads the YAML templates and the payload files out of a `.tar.gz`, in
/// memory. Each kept path is relative, made only of plain components,
/// outside dot-directories; the release's top directory is dropped. Nothing
/// is written as a file.
fn unpack(bytes: &[u8]) -> Result<Unpacked> {
    let decoder = flate2::read::GzDecoder::new(bytes).take(MAX_UNPACKED_BYTES);
    let mut archive = tar::Archive::new(decoder);
    let mut files = Vec::new();
    let mut helpers = Vec::new();
    let mut skipped = 0;
    let mut commit = None;
    for (count, entry) in archive
        .entries()
        .context("reading the archive")?
        .enumerate()
    {
        if count >= MAX_ARCHIVE_ENTRIES {
            bail!("the archive has more than {MAX_ARCHIVE_ENTRIES} entries");
        }
        let mut entry = entry.context("reading the archive")?;
        // git archive records the commit in a pax global header.
        if entry.header().entry_type() == tar::EntryType::XGlobalHeader {
            if let Ok(Some(extensions)) = entry.pax_extensions() {
                for extension in extensions.flatten() {
                    if extension.key() == Ok("comment") {
                        commit = extension
                            .value()
                            .ok()
                            .map(str::trim)
                            .filter(|value| {
                                value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
                            })
                            .map(str::to_string);
                    }
                }
            }
            continue;
        }
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .context("reading an archive path")?
            .into_owned();
        let mut parts = Vec::new();
        let mut plain = true;
        for component in path.components() {
            match component {
                Component::Normal(part) => match part.to_str() {
                    Some(part) if !part.is_empty() && !part.contains('\0') => {
                        parts.push(part.to_string())
                    }
                    _ => plain = false,
                },
                _ => plain = false,
            }
        }
        // Drop the single top-level directory a release archive wraps
        // everything in.
        if parts.len() > 1 {
            parts.remove(0);
        }
        let relative = parts.join("/");
        let helper = relative.starts_with("helpers/") && relative.ends_with(".txt");
        if !plain
            || !(relative.ends_with(".yaml") || helper)
            || parts.iter().any(|part| part.starts_with('.'))
        {
            continue;
        }
        let limit = if helper {
            MAX_HELPER_BYTES
        } else {
            model::MAX_TEMPLATE_BYTES
        } as u64;
        if entry.size() > limit {
            skipped += usize::from(!helper);
            continue;
        }
        let mut text = String::new();
        if entry
            .by_ref()
            .take(limit + 1)
            .read_to_string(&mut text)
            .is_err()
        {
            skipped += usize::from(!helper);
            continue;
        }
        if helper {
            if helpers.len() >= MAX_HELPERS {
                bail!("the archive has more than {MAX_HELPERS} payload files");
            }
            helpers.push((relative, text));
            continue;
        }
        if files.len() >= MAX_TEMPLATES {
            bail!("the archive has more than {MAX_TEMPLATES} templates");
        }
        files.push((relative, text));
    }
    if files.is_empty() {
        bail!("the archive holds no templates");
    }
    Ok(Unpacked {
        files,
        helpers,
        commit,
        skipped,
    })
}

/// A client for GitHub only: the same proxy policy as the self-updater (the
/// environment's proxy, unless it points back at this machine), redirects
/// only to GitHub's own hosts over HTTPS.
fn github_client() -> Result<reqwest::Client> {
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        let url = attempt.url();
        let host = url.host_str().unwrap_or("");
        let allowed = url.scheme() == "https"
            && (matches!(
                host,
                "github.com" | "api.github.com" | "codeload.github.com"
            ) || host.ends_with(".githubusercontent.com"));
        if attempt.previous().len() >= 5 || !allowed {
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
        .user_agent(format!(
            "Sniper/{} (+https://github.com/sm1ee/Sniper)",
            env!("CARGO_PKG_VERSION")
        ));
    let builder = if crate::state::release_proxy_env_targets_loopback() {
        builder.no_proxy()
    } else {
        builder
    };
    builder.build().context("building the GitHub client")
}

async fn latest_tag(client: &reqwest::Client) -> Result<String> {
    let body = fetch_bytes(client, LATEST_RELEASE_API, 1024 * 1024, None)
        .await
        .context("asking GitHub for the latest release")?;
    let value: serde_json::Value = serde_json::from_slice(&body).context("reading the release")?;
    let tag = value
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if !valid_tag(tag) {
        bail!("GitHub returned an unexpected release tag");
    }
    Ok(tag.to_string())
}

/// `v10.5.0` and the like; anything else could steer the archive URL.
fn valid_tag(tag: &str) -> bool {
    let digits = tag.strip_prefix('v').unwrap_or(tag);
    let parts: Vec<&str> = digits.split('.').collect();
    (2..=4).contains(&parts.len())
        && parts.iter().all(|part| {
            !part.is_empty() && part.len() <= 6 && part.bytes().all(|b| b.is_ascii_digit())
        })
}

async fn fetch_bytes(
    client: &reqwest::Client,
    url: &str,
    limit: usize,
    progress: Option<&TemplateLibrary>,
) -> Result<Vec<u8>> {
    use futures_util::StreamExt;
    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        bail!("GitHub answered {}", response.status());
    }
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        bail!("the download is larger than {} MiB", limit / (1024 * 1024));
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > limit {
            bail!("the download is larger than {} MiB", limit / (1024 * 1024));
        }
        body.extend_from_slice(&chunk);
        if let Some(library) = progress {
            library.task.lock().unwrap().received_bytes = Some(body.len() as u64);
        }
    }
    Ok(body)
}

// ---- API ----

fn busy() -> Response {
    (
        StatusCode::CONFLICT,
        "The template library is busy loading, downloading or importing. Try again when it finishes.",
    )
        .into_response()
}

pub async fn get_status(State(state): State<Arc<AppState>>) -> Response {
    Json(state.templates.status()).into_response()
}

pub async fn check_latest(State(state): State<Arc<AppState>>) -> Response {
    match state.templates.check_latest().await {
        Ok(latest) => {
            let current = state.templates.status().library.map(|info| info.tag);
            Json(json!({
                "latest": latest,
                "current": current,
                "update_available": current.as_deref() != Some(latest.as_str()),
            }))
            .into_response()
        }
        Err(error) => (StatusCode::BAD_GATEWAY, format!("{error:#}")).into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadRequest {
    #[serde(default)]
    acknowledged: bool,
}

pub async fn start_download(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DownloadRequest>,
) -> Response {
    if !request.acknowledged {
        return (
            StatusCode::BAD_REQUEST,
            "Downloading templates contacts GitHub; acknowledge it to continue.",
        )
            .into_response();
    }
    if !state.templates.start_download() {
        return busy();
    }
    (StatusCode::ACCEPTED, Json(state.templates.status())).into_response()
}

pub async fn start_import(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    if body.is_empty() || body.len() > MAX_ARCHIVE_BYTES {
        return (
            StatusCode::BAD_REQUEST,
            "Send a templates .tar.gz of at most 64 MiB.",
        )
            .into_response();
    }
    if !state.templates.start_import(body) {
        return busy();
    }
    (StatusCode::ACCEPTED, Json(state.templates.status())).into_response()
}

pub async fn list(State(state): State<Arc<AppState>>, Query(query): Query<ListQuery>) -> Response {
    Json(state.templates.list(&query)).into_response()
}

pub async fn get(State(state): State<Arc<AppState>>, AxumPath(id): AxumPath<String>) -> Response {
    let library = Arc::clone(&state.templates);
    match tokio::task::spawn_blocking(move || library.get(&id)).await {
        Ok(Some(detail)) => Json(detail).into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassiveRequest {
    #[serde(default)]
    ids: Vec<String>,
    /// Every template the list filter selects, instead of `ids`.
    #[serde(default)]
    filter: Option<ListQuery>,
    enabled: bool,
}

pub async fn set_passive(
    State(state): State<Arc<AppState>>,
    Json(request): Json<PassiveRequest>,
) -> Response {
    let library = Arc::clone(&state.templates);
    let outcome = tokio::task::spawn_blocking(move || {
        let ids = match &request.filter {
            Some(filter) => library.select_ids(filter),
            None => request.ids.clone(),
        };
        library.set_passive(&ids, request.enabled)
    })
    .await;
    match outcome {
        Ok(Ok((enabled, ignored))) => {
            Json(json!({ "passive_enabled": enabled, "ignored": ignored })).into_response()
        }
        Ok(Err(error)) => {
            tracing::warn!(%error, "saving passive templates failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSIVE: &str = "id: example-detect\ninfo:\n  name: Example Detect\n  severity: info\n  tags: tech,example\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n    matchers:\n      - type: word\n        words: ['Example Server']\n";
    const ACTIVE: &str = "id: example-exposure\ninfo:\n  name: Example Exposure\n  severity: medium\n  tags: exposure\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/.env']\n    matchers:\n      - type: word\n        words: ['APP_KEY=']\n";
    const DNS: &str = "id: example-dns\ninfo:\n  name: Example DNS\n  severity: info\ndns:\n  - name: '{{FQDN}}'\n";

    fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            // Written raw so a hostile path reaches the reader unchanged.
            let name = header.as_old_mut().name.as_mut();
            name[..path.len()].copy_from_slice(path.as_bytes());
            header.set_cksum();
            builder.append(&header, *body).unwrap();
        }
        let tar = builder.into_inner().unwrap();
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(&tar).unwrap();
        gzip.finish().unwrap()
    }

    fn release() -> Vec<u8> {
        archive(&[
            ("nuclei-templates-1.0/http/detect.yaml", PASSIVE.as_bytes()),
            ("nuclei-templates-1.0/http/exposure.yaml", ACTIVE.as_bytes()),
            ("nuclei-templates-1.0/dns/dns.yaml", DNS.as_bytes()),
            ("nuclei-templates-1.0/http/again.yaml", PASSIVE.as_bytes()),
            ("nuclei-templates-1.0/.github/ci.yaml", PASSIVE.as_bytes()),
            ("nuclei-templates-1.0/../escape.yaml", ACTIVE.as_bytes()),
            ("nuclei-templates-1.0/README.md", b"readme"),
            ("nuclei-templates-1.0/http/broken.yaml", b"id: [\n"),
        ])
    }

    fn library(dir: &Path) -> Arc<TemplateLibrary> {
        let library = Arc::new(TemplateLibrary::empty(dir));
        library.load_blocking();
        library
    }

    #[test]
    fn imports_lists_and_survives_a_reload() {
        let dir = std::env::temp_dir().join(format!("sniper-templates-{}", uuid::Uuid::new_v4()));
        let first = library(&dir);
        assert_eq!(first.status().state, TaskState::Idle);
        first.import_blocking(&release(), Source::Import).unwrap();
        let status = first.status();
        assert_eq!(status.templates, 3, "{status:?}");
        assert_eq!(status.duplicates, 1);
        assert_eq!(status.skipped, 1);
        assert_eq!(status.passive_supported, 1);
        assert!(!status.library.as_ref().unwrap().verified);

        let passive = first.list(&ListQuery {
            support: Some("passive".into()),
            ..ListQuery::default()
        });
        assert_eq!(passive.total, 1);
        assert_eq!(passive.items[0].meta.id, "example-detect");
        let dns = first.get("example-dns").unwrap();
        assert_eq!(dns.meta.protocol, "dns");
        assert!(dns.meta.reasons.contains(&"protocol:dns".to_string()));
        assert!(dns.yaml.contains("{{FQDN}}"));
        let searched = first.list(&ListQuery {
            search: Some("EXPOSURE".into()),
            ..ListQuery::default()
        });
        assert_eq!(searched.total, 1);

        assert!(first.passive_set().is_none());
        assert_eq!(
            first
                .set_passive(&["example-detect".into(), "example-exposure".into()], true)
                .unwrap(),
            (1, 1)
        );
        assert_eq!(first.passive_set().unwrap().len(), 1);

        let second = library(&dir);
        assert_eq!(second.status().templates, 3);
        assert_eq!(second.status().passive_enabled, 1);
        assert_eq!(second.passive_set().unwrap().len(), 1);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn templates_sniper_can_run_are_listed_first() {
        let dir = std::env::temp_dir().join(format!("sniper-templates-{}", uuid::Uuid::new_v4()));
        let library = library(&dir);
        let release = archive(&[
            ("nuclei-templates-1.0/dns/dns.yaml", DNS.as_bytes()),
            ("nuclei-templates-1.0/http/exposure.yaml", ACTIVE.as_bytes()),
        ]);
        library.import_blocking(&release, Source::Import).unwrap();
        let ids: Vec<String> = library
            .list(&ListQuery::default())
            .items
            .into_iter()
            .map(|item| item.meta.id)
            .collect();
        assert_eq!(ids, ["example-exposure", "example-dns"]);
        let _ = fs::remove_dir_all(dir);
    }

    const WORDS: &str = "id: example-words\ninfo:\n  name: Example Words\n  severity: info\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/{{word}}']\n    payloads:\n      word: helpers/wordlists/words.txt\n    matchers:\n      - type: status\n        status: [200]\n";
    const MISSING: &str = "id: example-missing\ninfo: {}\nhttp:\n  - path: ['{{BaseURL}}/{{word}}']\n    payloads:\n      word: helpers/wordlists/missing.txt\n    matchers:\n      - type: status\n        status: [200]\n";

    #[test]
    fn payload_files_come_from_the_release() {
        let dir = std::env::temp_dir().join(format!("sniper-templates-{}", uuid::Uuid::new_v4()));
        let first = library(&dir);
        first
            .import_blocking(
                &archive(&[
                    ("nuclei-templates-1.0/http/words.yaml", WORDS.as_bytes()),
                    ("nuclei-templates-1.0/http/missing.yaml", MISSING.as_bytes()),
                    (
                        "nuclei-templates-1.0/helpers/wordlists/words.txt",
                        b"admin\n\nlogin\r\n",
                    ),
                    ("nuclei-templates-1.0/helpers/payloads/key.bin", b"\x00\x01"),
                ]),
                Source::Import,
            )
            .unwrap();
        let status = first.status();
        assert_eq!((status.templates, status.skipped), (2, 0), "{status:?}");
        let words = first.get("example-words").unwrap().meta;
        assert!(words.active_supported, "{:?}", words.reasons);
        assert_eq!(words.requests, 2);
        let missing = first.get("example-missing").unwrap().meta;
        assert_eq!(missing.reasons, ["req:payload_file"]);
        // A reload reads the files back for the scans it compiles.
        let second = library(&dir);
        let meta = second.get("example-words").unwrap().meta;
        assert_eq!(second.compile_active(&meta).unwrap().request_count(), 2);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_stale_index_is_rebuilt_and_orphans_removed() {
        let dir = std::env::temp_dir().join(format!("sniper-templates-{}", uuid::Uuid::new_v4()));
        let first = library(&dir);
        first.import_blocking(&release(), Source::Import).unwrap();
        let info = first.status().library.unwrap();
        let index = first.dir.join(index_file_name(&info.sha256));
        let mut stale: serde_json::Value =
            serde_json::from_slice(&fs::read(&index).unwrap()).unwrap();
        stale["engine"] = json!(0);
        stale["templates"] = json!([]);
        fs::write(&index, serde_json::to_vec(&stale).unwrap()).unwrap();
        fs::write(first.dir.join("bundle-0000000000000000.ndjson"), b"orphan").unwrap();
        let second = library(&dir);
        assert_eq!(second.status().templates, 3);
        assert!(!second.dir.join("bundle-0000000000000000.ndjson").exists());
        // A corrupt manifest is set aside, not fatal.
        fs::write(second.dir.join("templates.json"), b"{not json").unwrap();
        let third = library(&dir);
        assert_eq!(third.status().state, TaskState::Idle);
        assert_eq!(third.status().templates, 0);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_download_must_match_the_published_checksum() {
        let dir = std::env::temp_dir().join(format!("sniper-templates-{}", uuid::Uuid::new_v4()));
        let library = library(&dir);
        let error = library
            .import_blocking(
                &release(),
                Source::GitHub {
                    tag: "v1.0.0".into(),
                    expected_sha256: "0".repeat(64),
                },
            )
            .unwrap_err();
        assert!(error.to_string().contains("SHA-256"), "{error}");
        assert_eq!(library.status().templates, 0);
        let bytes = release();
        library
            .import_blocking(
                &bytes,
                Source::GitHub {
                    tag: "v1.0.0".into(),
                    expected_sha256: crate::skill_status::sha256(&bytes),
                },
            )
            .unwrap();
        let info = library.status().library.unwrap();
        assert!(info.verified);
        assert_eq!(info.tag, "v1.0.0");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn checking_a_release_reports_how_far_it_got() {
        let entries = vec![
            ("http/a.yaml".to_string(), ACTIVE.to_string(), 0, 1),
            ("http/b.yaml".to_string(), PASSIVE.to_string(), 1, 1),
        ];
        let seen = std::cell::RefCell::new(Vec::new());
        index_entries(entries, &HashMap::new(), &|done, total| {
            seen.borrow_mut().push((done, total))
        });
        assert_eq!(seen.borrow().last(), Some(&(2, 2)));
    }

    #[test]
    fn hostile_archives_are_refused() {
        assert!(unpack(b"not gzip").is_err());
        assert!(unpack(&archive(&[("top/README.md", b"x")])).is_err());
        let large = vec![b'#'; model::MAX_TEMPLATE_BYTES + 1];
        let unpacked = unpack(&archive(&[
            ("top/http/large.yaml", &large),
            ("top/http/ok.yaml", PASSIVE.as_bytes()),
        ]))
        .unwrap();
        assert_eq!(unpacked.skipped, 1);
        assert_eq!(unpacked.files.len(), 1);
        assert_eq!(unpacked.files[0].0, "http/ok.yaml");
    }

    #[test]
    fn release_tags_are_plain_versions() {
        assert!(valid_tag("v10.5.0"));
        assert!(valid_tag("10.5"));
        assert!(!valid_tag("v10.5.0/../../x"));
        assert!(!valid_tag("v1"));
        assert!(!valid_tag(""));
    }
}
