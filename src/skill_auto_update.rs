//! Host-local, explicit consent for later updates from the executing binary only.
//!
//! Policy is separate from enrollment and session persistence. An uncertain attempt
//! consumes its authorization until a person deliberately records a new generation.
use crate::skill_managed::{error, ManagedSkillError};
use serde::Serialize;
use std::path::Path;
type Result<T> = std::result::Result<T, ManagedSkillError>;

#[derive(Debug, Serialize)]
pub struct AutoUpdateStatus {
    pub agent: String,
    pub state: &'static str,
    pub enabled: bool,
    pub policy_id: Option<String>,
    pub revision: Option<u64>,
    pub generation: Option<String>,
    pub path: Option<String>,
    pub operation_id: Option<String>,
    pub agent_reloaded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pause_reason: Option<String>,
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn disabled(agent: &str) -> Result<AutoUpdateStatus> {
    if !matches!(agent, "codex" | "claude") {
        return Err(error("invalid_agent"));
    }
    Ok(AutoUpdateStatus {
        agent: agent.into(),
        state: "disabled",
        enabled: false,
        policy_id: None,
        revision: None,
        generation: None,
        path: None,
        operation_id: None,
        agent_reloaded: false,
        error_code: None,
        pause_reason: None,
    })
}

/// A read-only observation. In particular, this never repairs or syncs a journal.
pub fn status(data_dir: &Path, agent: &str) -> Result<AutoUpdateStatus> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        supported::status(data_dir, agent)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (data_dir, agent);
        Err(error("platform_unsupported"))
    }
}
/// Records consent only. Existing policies require the exact displayed revision.
pub fn enable(
    data_dir: &Path,
    agent: &str,
    root: &Path,
    bundled: &str,
    version: &str,
    expected_revision: Option<u64>,
) -> Result<AutoUpdateStatus> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        supported::enable(data_dir, agent, root, bundled, version, expected_revision)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (data_dir, agent, root, bundled, version, expected_revision);
        Err(error("platform_unsupported"))
    }
}
pub fn disable(data_dir: &Path, agent: &str) -> Result<AutoUpdateStatus> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        supported::disable(data_dir, agent)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (data_dir, agent);
        Err(error("platform_unsupported"))
    }
}
/// Uses only the stored target; callers cannot redirect a prior authorization.
pub fn run_once(
    data_dir: &Path,
    agent: &str,
    bundled: &str,
    version: &str,
) -> Result<AutoUpdateStatus> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        supported::run_once(data_dir, agent, bundled, version, |_| Ok(()))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (data_dir, agent, bundled, version);
        Err(error("platform_unsupported"))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod supported {
    use super::*;
    use crate::{
        skill_activation::{self, supported::Directory, BaselineBinding, DirectoryBinding},
        skill_managed::{io_error, path_text, stage_skill_update, target},
        skill_status::sha256,
    };
    use serde::Deserialize;
    use std::{fs, path::PathBuf};
    const STORE: &str = "host-skill-updates";
    const MAX_RECORDS: usize = 128;
    const MAX_RECORD_BYTES: u64 = 32 * 1024;

    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    enum Event {
        Enabled,
        Disabled,
        Reserved,
        Completed,
        Paused,
    }
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    enum Outcome {
        Reserved,
        Committed,
    }
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct Attempt {
        operation_id: String,
        version: String,
        sha256: String,
        staging_dir: String,
        outcome: Outcome,
    }
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct Policy {
        schema_version: u32,
        kind: String,
        source: String,
        contract_revision: u32,
        agent: String,
        store_path: String,
        store_directory: DirectoryBinding,
        policy_directory: DirectoryBinding,
        policy_id: String,
        revision: u64,
        previous_sha256: Option<String>,
        generation: String,
        enabled: bool,
        event: Event,
        baseline: BaselineBinding,
        attempt: Option<Attempt>,
        pause_code: Option<String>,
    }
    struct Store {
        parent: Directory,
        dir: Directory,
        agent: String,
    }
    struct History {
        records: Vec<Policy>,
        hashes: Vec<String>,
    }
    impl History {
        fn last(&self) -> Option<&Policy> {
            self.records.last()
        }
    }
    fn uuid(s: &str) -> bool {
        skill_activation::valid_operation_id(s)
    }
    fn hash(s: &str) -> bool {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    fn file_name(revision: u64) -> String {
        format!("{revision:016}.json")
    }
    fn optional_dir(path: &Path) -> Result<Option<Directory>> {
        match Directory::open(path) {
            Ok(d) => Ok(Some(d)),
            Err(e) if e.code == "missing" => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn child(parent: &Directory, name: &str, create: bool) -> Result<Option<Directory>> {
        if let Some(d) = optional_dir(&parent.path().join(name))? {
            return Ok(Some(d));
        }
        if !create {
            return Ok(None);
        }
        match parent.child_new(name) {
            Ok(d) => Ok(Some(d)),
            Err(e) if e.code == "already_exists" => optional_dir(&parent.path().join(name)),
            Err(e) => Err(e),
        }
    }
    #[cfg(test)]
    thread_local! {
        static APPEND_FAILURE: std::cell::Cell<Option<(u64, &'static str)>> = const {std::cell::Cell::new(None)};
    }
    impl Store {
        fn open(data_dir: &Path, agent: &str, create: bool) -> Result<Option<Self>> {
            disabled(agent)?;
            let path = std::path::absolute(data_dir).map_err(io_error)?;
            // A missing policy never triggers installation-path discovery.
            if create {
                fs::create_dir_all(&path).map_err(io_error)?;
            }
            let Some(data) = optional_dir(&path)? else {
                return Ok(None);
            };
            let Some(parent) = child(&data, STORE, create)? else {
                return Ok(None);
            };
            let Some(dir) = child(&parent, agent, create)? else {
                return Ok(None);
            };
            parent.check()?;
            Ok(Some(Self {
                parent,
                dir,
                agent: agent.into(),
            }))
        }
        fn check(&self) -> Result<()> {
            self.parent.check()?;
            self.dir.check()
        }
        fn lock(&self) -> Result<()> {
            self.dir.lock().map_err(|e| {
                if e.code == "transaction_busy" {
                    error("policy_busy")
                } else {
                    e
                }
            })?;
            self.check()
        }
        fn load(&self) -> Result<History> {
            self.check()?;
            let mut names = Vec::new();
            let mut stages = Vec::new();
            for entry in fs::read_dir(self.dir.path()).map_err(io_error)? {
                let entry = entry.map_err(io_error)?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| error("invalid_policy_history"))?;
                if let Some(id) = name.strip_prefix("stage-") {
                    if !uuid(id) || stages.len() >= MAX_RECORDS {
                        return Err(error("invalid_policy_history"));
                    }
                    stages.push(name);
                } else {
                    if names.len() >= MAX_RECORDS {
                        return Err(error("policy_capacity"));
                    }
                    names.push(name);
                }
            }
            names.sort();
            let mut history = History {
                records: Vec::new(),
                hashes: Vec::new(),
            };
            for (i, name) in names.iter().enumerate() {
                if name != &file_name((i + 1) as u64) {
                    return Err(error("invalid_policy_history"));
                }
                let read = self.dir.read(name, MAX_RECORD_BYTES)?;
                let policy: Policy = serde_json::from_slice(&read.bytes)
                    .map_err(|_| error("invalid_policy_history"))?;
                self.validate(&policy, &history)?;
                history.hashes.push(sha256(&read.bytes));
                history.records.push(policy);
            }
            for stage in stages {
                if !history.records.iter().any(|p| {
                    p.attempt
                        .as_ref()
                        .is_some_and(|a| stage == format!("stage-{}", a.operation_id))
                }) {
                    return Err(error("invalid_policy_history"));
                }
                Directory::open(&self.dir.path().join(stage))?;
            }
            self.check()?;
            Ok(history)
        }
        fn validate(&self, p: &Policy, h: &History) -> Result<()> {
            let invalid = || error("invalid_policy_history");
            if p.schema_version != 1
                || p.kind != "sniper_host_skill_updates"
                || p.source != "bundled_binary"
                || p.contract_revision != 1
                || p.agent != self.agent
                || p.store_path != path_text(self.dir.path())?
                || p.store_directory != self.parent.binding()?
                || p.policy_directory != self.dir.binding()?
                || !uuid(&p.policy_id)
                || !uuid(&p.generation)
                || p.revision != h.records.len() as u64 + 1
                || p.previous_sha256 != h.hashes.last().cloned()
                || p.baseline.agent != p.agent
                || !hash(&p.baseline.installed_sha256)
                || p.baseline.installed_sha256 != p.baseline.skill.sha256
                || !hash(&p.baseline.receipt.sha256)
                || !hash(&p.baseline.history_sha256)
                || semver::Version::parse(&p.baseline.enrolled_version).is_err()
                || p.baseline.enrolled_version.len() > 128
                || !Path::new(&p.baseline.path).is_absolute()
                || Path::new(&p.baseline.path)
                    .file_name()
                    .and_then(|v| v.to_str())
                    != Some("SKILL.md")
            {
                return Err(invalid());
            }
            if let Some(a) = &p.attempt {
                if !uuid(&a.operation_id)
                    || !hash(&a.sha256)
                    || a.version.len() > 128
                    || semver::Version::parse(&a.version).is_err()
                    || a.staging_dir
                        != path_text(&self.dir.path().join(format!("stage-{}", a.operation_id)))?
                {
                    return Err(invalid());
                }
            }
            if p.pause_code.as_ref().is_some_and(|v| {
                v.is_empty()
                    || v.len() > 64
                    || !v.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            }) {
                return Err(invalid());
            }
            let Some(prev) = h.last() else {
                if p.event != Event::Enabled
                    || !p.enabled
                    || p.attempt.is_some()
                    || p.pause_code.is_some()
                {
                    return Err(invalid());
                }
                return Ok(());
            };
            if p.policy_id != prev.policy_id {
                return Err(invalid());
            }
            if p.event == Event::Enabled {
                if !p.enabled
                    || h.records.iter().any(|old| old.generation == p.generation)
                    || p.attempt.is_some()
                    || p.pause_code.is_some()
                {
                    return Err(invalid());
                }
                return Ok(());
            }
            if p.generation != prev.generation {
                return Err(invalid());
            }
            match p.event {
                Event::Disabled => {
                    if p.enabled
                        || !prev.enabled
                        || p.baseline != prev.baseline
                        || p.attempt != prev.attempt
                        || p.pause_code != prev.pause_code
                    {
                        return Err(invalid());
                    }
                }
                Event::Paused => {
                    if !p.enabled
                        || !prev.enabled
                        || p.baseline != prev.baseline
                        || p.attempt != prev.attempt
                        || p.pause_code.is_none()
                        || paused(prev)
                    {
                        return Err(invalid());
                    }
                }
                Event::Reserved => {
                    let a = p.attempt.as_ref().ok_or_else(invalid)?;
                    if !p.enabled
                        || !prev.enabled
                        || paused(prev)
                        || p.baseline != prev.baseline
                        || p.pause_code.is_some()
                        || a.outcome != Outcome::Reserved
                        || a.sha256 == prev.baseline.installed_sha256
                        || semver::Version::parse(&a.version)
                            .map_err(|_| invalid())?
                            .cmp_precedence(
                                &semver::Version::parse(&prev.baseline.enrolled_version)
                                    .map_err(|_| invalid())?,
                            )
                            != std::cmp::Ordering::Greater
                        || h.records.iter().any(|old| {
                            old.attempt
                                .as_ref()
                                .is_some_and(|v| v.operation_id == a.operation_id)
                        })
                    {
                        return Err(invalid());
                    }
                }
                Event::Completed => {
                    let a = p.attempt.as_ref().ok_or_else(invalid)?;
                    let mut old = a.clone();
                    old.outcome = Outcome::Reserved;
                    if prev.event != Event::Reserved
                        || prev.attempt.as_ref() != Some(&old)
                        || a.outcome != Outcome::Committed
                        || !p.enabled
                        || !prev.enabled
                        || p.pause_code.is_some()
                        || p.baseline.agent != prev.baseline.agent
                        || p.baseline.path != prev.baseline.path
                        || p.baseline.directory != prev.baseline.directory
                        || p.baseline.installed_sha256 != a.sha256
                        || p.baseline.enrolled_version != a.version
                        || p.baseline.receipt == prev.baseline.receipt
                        || p.baseline.history_sha256 == prev.baseline.history_sha256
                    {
                        return Err(invalid());
                    }
                }
                Event::Enabled => unreachable!(),
            }
            Ok(())
        }
        fn append(&self, history: &mut History, policy: Policy) -> Result<()> {
            if history.records.len() >= MAX_RECORDS {
                return Err(error("policy_capacity"));
            }
            self.validate(&policy, history)?;
            self.sync_history(history)?;
            #[cfg(test)]
            APPEND_FAILURE.with(|slot| {
                if let Some((revision, kind)) = slot.get() {
                    if revision == policy.revision {
                        crate::skill_activation::supported::set_policy_io_test_failure(Some((
                            kind, 1,
                        )));
                    }
                }
            });
            let bytes = serde_json::to_vec(&policy).map_err(|_| error("invalid_policy_history"))?;
            if bytes.len() as u64 > MAX_RECORD_BYTES {
                return Err(error("policy_too_large"));
            }
            self.dir
                .write_new(&file_name(policy.revision), &bytes, 0o600)?;
            self.dir.sync()?;
            self.check()?;
            history.hashes.push(sha256(&bytes));
            history.records.push(policy);
            Ok(())
        }
        fn sync_history(&self, history: &History) -> Result<()> {
            // A visible previous record may have survived an unsuccessful sync. A
            // writer re-establishes durability; an observer never does this.
            for (i, expected) in history.hashes.iter().enumerate() {
                let observed = self.dir.read(&file_name(i as u64 + 1), MAX_RECORD_BYTES)?;
                if &sha256(&observed.bytes) != expected {
                    return Err(error("policy_changed"));
                }
                observed.file.sync_all().map_err(io_error)?;
            }
            self.check()?;
            self.dir.sync()?;
            Ok(())
        }
    }
    fn paused(p: &Policy) -> bool {
        p.event == Event::Paused
            || p.attempt
                .as_ref()
                .is_some_and(|a| a.outcome == Outcome::Reserved)
    }
    fn root(p: &Policy) -> Result<PathBuf> {
        let dir = Path::new(&p.baseline.path)
            .parent()
            .ok_or_else(|| error("invalid_policy_history"))?;
        if dir.file_name().and_then(|v| v.to_str()) != Some("sniper-operator") {
            return Err(error("invalid_policy_history"));
        }
        Ok(dir
            .parent()
            .ok_or_else(|| error("invalid_policy_history"))?
            .to_owned())
    }
    fn row(p: &Policy) -> AutoUpdateStatus {
        AutoUpdateStatus {
            agent: p.agent.clone(),
            state: if !p.enabled {
                "disabled"
            } else if paused(p) {
                "paused"
            } else {
                "enabled"
            },
            enabled: p.enabled,
            policy_id: Some(p.policy_id.clone()),
            revision: Some(p.revision),
            generation: Some(p.generation.clone()),
            path: Some(p.baseline.path.clone()),
            operation_id: p.attempt.as_ref().map(|a| a.operation_id.clone()),
            agent_reloaded: false,
            pause_reason: p.pause_code.clone(),
            error_code: if p.enabled && paused(p) {
                Some("policy_paused")
            } else {
                None
            },
        }
    }
    fn next(p: &Policy, h: &History) -> Policy {
        let mut p = p.clone();
        p.revision += 1;
        p.previous_sha256 = h.hashes.last().cloned();
        p
    }
    fn unchanged(p: &Policy) -> Result<()> {
        let current = skill_activation::inspect_automatic_baseline(&p.agent, &root(p)?)?;
        if current != p.baseline {
            return Err(error("policy_baseline_changed"));
        }
        if let Some(attempt) = p
            .attempt
            .as_ref()
            .filter(|a| a.outcome == Outcome::Committed)
        {
            skill_activation::inspect_automatic_completion(
                &p.agent,
                &root(p)?,
                &p.baseline,
                &attempt.operation_id,
                &attempt.version,
                &attempt.sha256,
            )?;
        }
        Ok(())
    }
    pub(super) fn status(data_dir: &Path, agent: &str) -> Result<AutoUpdateStatus> {
        let Some(store) = Store::open(data_dir, agent, false)? else {
            return disabled(agent);
        };
        let history = store.load()?;
        let Some(p) = history.last() else {
            return disabled(agent);
        };
        let mut output = row(p);
        if p.enabled && !paused(p) {
            if let Err(e) = unchanged(p) {
                output.state = "paused";
                output.error_code = Some(e.code);
            }
        }
        Ok(output)
    }
    fn outside_active(data_dir: &Path, active: &Path) -> Result<()> {
        let active = fs::canonicalize(active).map_err(io_error)?;
        let mut existing = std::path::absolute(data_dir).map_err(io_error)?;
        let mut missing = Vec::new();
        let resolved = loop {
            match fs::canonicalize(&existing) {
                Ok(path) => break path,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(
                        existing
                            .file_name()
                            .ok_or_else(|| error("invalid_policy_path"))?
                            .to_owned(),
                    );
                    if !existing.pop() {
                        return Err(error("invalid_policy_path"));
                    }
                }
                Err(e) => return Err(io_error(e)),
            }
        };
        let mut resolved = resolved;
        for component in missing.into_iter().rev() {
            resolved.push(component);
        }
        if resolved.starts_with(&active) {
            return Err(error("staging_inside_active_skill"));
        }
        Ok(())
    }
    pub(super) fn enable(
        data_dir: &Path,
        agent: &str,
        root: &Path,
        bundle: &str,
        version: &str,
        expected: Option<u64>,
    ) -> Result<AutoUpdateStatus> {
        // Argument errors do not create policy directories.
        let selected = target(agent, root, bundle, version)?;
        outside_active(data_dir, selected.path.parent().unwrap())?;
        let store = Store::open(data_dir, agent, true)?.ok_or_else(|| error("missing"))?;
        store.lock()?;
        let mut history = store.load()?;
        let revision = history.last().map_or(0, |p| p.revision);
        if (revision > 0 && expected != Some(revision))
            || (revision == 0 && expected.is_some_and(|v| v != 0))
        {
            return Err(error("policy_revision_conflict"));
        }
        if history.records.len() + 1 >= MAX_RECORDS {
            return Err(error("policy_capacity"));
        }
        let baseline = skill_activation::inspect_automatic_baseline(agent, root)?;
        let p = Policy {
            schema_version: 1,
            kind: "sniper_host_skill_updates".into(),
            source: "bundled_binary".into(),
            contract_revision: 1,
            agent: agent.into(),
            store_path: path_text(store.dir.path())?,
            store_directory: store.parent.binding()?,
            policy_directory: store.dir.binding()?,
            policy_id: history
                .last()
                .map_or_else(|| uuid::Uuid::new_v4().to_string(), |p| p.policy_id.clone()),
            revision: revision + 1,
            previous_sha256: history.hashes.last().cloned(),
            generation: uuid::Uuid::new_v4().to_string(),
            enabled: true,
            event: Event::Enabled,
            baseline,
            attempt: None,
            pause_code: None,
        };
        store.append(&mut history, p)?;
        Ok(row(history.last().unwrap()))
    }
    pub(super) fn disable(data_dir: &Path, agent: &str) -> Result<AutoUpdateStatus> {
        let Some(store) = Store::open(data_dir, agent, false)? else {
            return disabled(agent);
        };
        store.lock()?;
        let mut history = store.load()?;
        let Some(p) = history.last() else {
            return disabled(agent);
        };
        if !p.enabled {
            store.sync_history(&history)?;
            return Ok(row(p));
        }
        let mut p = next(p, &history);
        p.enabled = false;
        p.event = Event::Disabled;
        store.append(&mut history, p)?;
        Ok(row(history.last().unwrap()))
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Step {
        Reserved,
        Staged,
        Applied,
        Completed,
    }
    pub(super) fn run_once(
        data_dir: &Path,
        agent: &str,
        bundle: &str,
        version: &str,
        mut checkpoint: impl FnMut(Step) -> Result<()>,
    ) -> Result<AutoUpdateStatus> {
        let Some(store) = Store::open(data_dir, agent, false)? else {
            return disabled(agent);
        };
        store.lock()?;
        let mut history = store.load()?;
        let Some(p) = history.last() else {
            return disabled(agent);
        };
        if !p.enabled || paused(p) {
            return Ok(row(p));
        }
        let p = p.clone();
        let eligibility = (|| {
            target(agent, &root(&p)?, bundle, version)?;
            unchanged(&p)?;
            outside_active(
                store.dir.path(),
                Path::new(&p.baseline.path).parent().unwrap(),
            )?;
            let next = semver::Version::parse(version).map_err(|_| error("invalid_version"))?;
            let current = semver::Version::parse(&p.baseline.enrolled_version)
                .map_err(|_| error("invalid_policy_history"))?;
            let precedence = next.cmp_precedence(&current);
            if precedence == std::cmp::Ordering::Less {
                return Err(error("bundle_downgrade"));
            }
            if precedence == std::cmp::Ordering::Equal
                && sha256(bundle.as_bytes()) != p.baseline.installed_sha256
            {
                return Err(error("version_conflict"));
            }
            Ok(precedence == std::cmp::Ordering::Greater
                && sha256(bundle.as_bytes()) != p.baseline.installed_sha256)
        })();
        let newer = match eligibility {
            Ok(newer) => newer,
            Err(e) => {
                // Keep a slot for disabling even when no further updates fit.
                if history.records.len() + 1 >= MAX_RECORDS {
                    return Err(error("policy_capacity"));
                }
                let mut pause = next(&p, &history);
                pause.event = Event::Paused;
                pause.pause_code = Some(e.code.into());
                store.append(&mut history, pause)?;
                let mut output = row(history.last().unwrap());
                output.error_code = Some(e.code);
                return Ok(output);
            }
        };
        if !newer {
            let mut output = row(&p);
            output.state = "current";
            return Ok(output);
        }
        if history.records.len() + 3 > MAX_RECORDS {
            return Err(error("policy_capacity"));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let staging = store.dir.path().join(format!("stage-{id}"));
        let mut reserved = next(&p, &history);
        reserved.event = Event::Reserved;
        reserved.attempt = Some(Attempt {
            operation_id: id.clone(),
            version: version.into(),
            sha256: sha256(bundle.as_bytes()),
            staging_dir: path_text(&staging)?,
            outcome: Outcome::Reserved,
        });
        store.append(&mut history, reserved)?;
        checkpoint(Step::Reserved)?;
        stage_skill_update(agent, &root(&p)?, bundle, version, &staging)?;
        checkpoint(Step::Staged)?;
        store.check()?;
        let applied = skill_activation::apply_automatic_skill_update(
            agent,
            &root(&p)?,
            bundle,
            version,
            &staging,
            &id,
            &p.baseline,
        )?;
        if applied.result.state != "applied"
            || applied.result.current_state != "updated"
            || applied.result.error_code.is_some()
        {
            return Err(error("recovery_required"));
        }
        checkpoint(Step::Applied)?;
        let mut completed = next(history.last().unwrap(), &history);
        completed.event = Event::Completed;
        completed.baseline = applied.committed_baseline;
        completed.attempt.as_mut().unwrap().outcome = Outcome::Committed;
        store.append(&mut history, completed)?;
        checkpoint(Step::Completed)?;
        let mut output = row(history.last().unwrap());
        output.state = "updated";
        Ok(output)
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::skill_managed::enroll_skill;
        use std::os::unix::fs::{symlink, PermissionsExt};
        const OLD: &str = "synthetic old policy skill";
        const NEW: &str = "synthetic new policy skill";
        struct Fixture {
            home: PathBuf,
            data: PathBuf,
            skills: PathBuf,
        }
        impl Fixture {
            fn new() -> Self {
                let home =
                    std::env::temp_dir().join(format!("sniper-policy-{}", uuid::Uuid::new_v4()));
                let data = home.join("data");
                let skills = home.join("skills");
                fs::create_dir_all(skills.join("sniper-operator")).unwrap();
                fs::write(skills.join("sniper-operator/SKILL.md"), OLD).unwrap();
                enroll_skill("codex", &skills, OLD, "1.0.0").unwrap();
                Self { home, data, skills }
            }
            fn enable(&self) -> AutoUpdateStatus {
                enable(&self.data, "codex", &self.skills, OLD, "1.0.0", None).unwrap()
            }
            fn run(&self) -> AutoUpdateStatus {
                super::run_once(&self.data, "codex", NEW, "2.0.0", |_| Ok(())).unwrap()
            }
            fn path(&self) -> PathBuf {
                self.skills.join("sniper-operator/SKILL.md")
            }
            fn policy(&self) -> PathBuf {
                self.data.join("host-skill-updates/codex")
            }
            fn store(&self) -> Store {
                Store::open(&self.data, "codex", false).unwrap().unwrap()
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.home);
            }
        }
        fn snapshot(path: &Path) -> Vec<(PathBuf, Vec<u8>)> {
            fn walk(path: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
                if path.is_dir() {
                    for entry in fs::read_dir(path).unwrap() {
                        walk(&entry.unwrap().path(), out);
                    }
                } else {
                    out.push((path.to_owned(), fs::read(path).unwrap()));
                }
            }
            let mut out = Vec::new();
            walk(path, &mut out);
            out.sort();
            out
        }
        #[test]
        fn absent_and_disabled_do_not_discover_or_touch_active_installations() {
            let f = Fixture::new();
            assert_eq!(status(&f.data, "codex").unwrap().state, "disabled");
            assert_eq!(
                super::run_once(
                    &f.data,
                    "codex",
                    "invalid ignored",
                    "not semver",
                    |_| panic!()
                )
                .unwrap()
                .state,
                "disabled"
            );
            assert!(!f.data.exists());
            f.enable();
            disable(&f.data, "codex").unwrap();
            fs::remove_dir_all(&f.skills).unwrap();
            let before = snapshot(&f.data);
            assert_eq!(f.run().state, "disabled");
            assert_eq!(status(&f.data, "codex").unwrap().state, "disabled");
            assert_eq!(before, snapshot(&f.data));
        }
        #[test]
        fn consent_only_newer_once_and_current_are_read_only() {
            let f = Fixture::new();
            let active = snapshot(&f.skills);
            let p = f.enable();
            assert_eq!(p.revision, Some(1));
            assert_eq!(active, snapshot(&f.skills));
            let before = snapshot(&f.home);
            assert_eq!(status(&f.data, "codex").unwrap().state, "enabled");
            assert_eq!(before, snapshot(&f.home));
            let done = f.run();
            assert_eq!(done.state, "updated");
            assert_eq!(done.revision, Some(3));
            assert_eq!(fs::read(f.path()).unwrap(), NEW.as_bytes());
            let before = snapshot(&f.home);
            assert_eq!(f.run().state, "current");
            assert_eq!(before, snapshot(&f.home));
            assert_eq!(status(&f.data, "codex").unwrap().state, "enabled");
            let receipt: serde_json::Value = serde_json::from_slice(
                &fs::read(f.skills.join("sniper-operator/.sniper-enrollment.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(receipt["allows_automatic_updates"], false);
            // Unchanged bytes in a newer binary also require no transaction.
            assert_eq!(
                super::run_once(&f.data, "codex", NEW, "3.0.0", |_| panic!())
                    .unwrap()
                    .state,
                "current"
            );
        }
        #[test]
        fn changes_and_version_conflicts_pause_until_deliberate_revision_acknowledgment() {
            for (bundle, version) in [(NEW, "1.0.0"), (NEW, "1.0.0+build"), (NEW, "0.9.0")] {
                let f = Fixture::new();
                f.enable();
                let paused =
                    super::run_once(&f.data, "codex", bundle, version, |_| panic!()).unwrap();
                assert_eq!(paused.state, "paused");
                let before = snapshot(&f.home);
                assert_eq!(f.run().state, "paused");
                assert_eq!(before, snapshot(&f.home));
                assert_eq!(
                    enable(&f.data, "codex", &f.skills, OLD, "1.0.0", None)
                        .unwrap_err()
                        .code,
                    "policy_revision_conflict"
                );
                let enabled =
                    enable(&f.data, "codex", &f.skills, OLD, "1.0.0", paused.revision).unwrap();
                assert_ne!(enabled.generation, paused.generation);
                assert_eq!(f.run().state, "updated");
            }
            let f = Fixture::new();
            f.enable();
            fs::write(f.path(), "edited").unwrap();
            assert_eq!(f.run().state, "paused");
            fs::write(f.path(), OLD).unwrap();
            assert_eq!(f.run().state, "paused");
        }
        #[test]
        fn unmanaged_incompatible_and_missing_targets_never_stage() {
            let f = Fixture::new();
            fs::remove_file(f.skills.join("sniper-operator/.sniper-enrollment.json")).unwrap();
            assert!(enable(&f.data, "codex", &f.skills, OLD, "1.0.0", None).is_err());
            assert_eq!(fs::read(f.path()).unwrap(), OLD.as_bytes());
            let f = Fixture::new();
            f.enable();
            fs::remove_dir_all(&f.skills).unwrap();
            assert_eq!(f.run().state, "paused");
            assert_eq!(fs::read_dir(f.policy()).unwrap().count(), 2);
            let f = Fixture::new();
            let receipt = f.skills.join("sniper-operator/.sniper-enrollment.json");
            let mut value: serde_json::Value =
                serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
            value["schema_version"] = 99.into();
            fs::write(receipt, serde_json::to_vec(&value).unwrap()).unwrap();
            assert!(f.enable_result().is_err());
        }
        impl Fixture {
            fn enable_result(&self) -> Result<AutoUpdateStatus> {
                enable(&self.data, "codex", &self.skills, OLD, "1.0.0", None)
            }
        }
        #[test]
        fn external_apply_then_rollback_breaks_authorization_even_with_original_inodes() {
            let f = Fixture::new();
            f.enable();
            let stage = f.home.join("explicit-stage");
            stage_skill_update("codex", &f.skills, NEW, "2.0.0", &stage).unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            skill_activation::apply_skill_update("codex", &f.skills, NEW, "2.0.0", &stage, &id)
                .unwrap();
            skill_activation::rollback_skill_update("codex", &f.skills, &id).unwrap();
            assert_eq!(fs::read(f.path()).unwrap(), OLD.as_bytes());
            assert_eq!(f.run().error_code, Some("policy_baseline_changed"));
        }
        #[test]
        fn reserved_staged_and_applied_interruptions_never_retry_or_adopt() {
            for step in [Step::Reserved, Step::Staged, Step::Applied] {
                let f = Fixture::new();
                f.enable();
                assert_eq!(
                    super::run_once(&f.data, "codex", NEW, "2.0.0", |at| if at == step {
                        Err(error("injected_failure"))
                    } else {
                        Ok(())
                    })
                    .unwrap_err()
                    .code,
                    "injected_failure"
                );
                let before = snapshot(&f.home);
                let row = f.run();
                assert_eq!(row.state, "paused");
                assert_eq!(row.revision, Some(2));
                assert!(row.operation_id.is_some());
                assert_eq!(before, snapshot(&f.home));
                assert_eq!(status(&f.data, "codex").unwrap().state, "paused");
            }
            let f = Fixture::new();
            f.enable();
            assert!(super::run_once(&f.data, "codex", NEW, "2.0.0", |step| {
                if step == Step::Completed {
                    Err(error("injected_failure"))
                } else {
                    Ok(())
                }
            })
            .is_err());
            assert_eq!(f.run().state, "current");
        }
        fn inject_append(revision: u64, kind: &'static str) {
            APPEND_FAILURE.with(|slot| slot.set(Some((revision, kind))));
        }
        fn clear_append_failure() {
            APPEND_FAILURE.with(|slot| slot.set(None));
            crate::skill_activation::supported::set_policy_io_test_failure(None);
        }
        #[test]
        fn policy_write_and_sync_failures_do_not_create_a_fresh_attempt() {
            for revision in [2, 3] {
                for kind in ["write", "file_sync", "directory_sync"] {
                    let f = Fixture::new();
                    f.enable();
                    inject_append(revision, kind);
                    let result = super::run_once(&f.data, "codex", NEW, "2.0.0", |_| Ok(()));
                    clear_append_failure();
                    assert!(result.is_err(), "{revision} {kind}");
                    let before = snapshot(&f.home);
                    let next = super::run_once(&f.data, "codex", NEW, "2.0.0", |_| {
                        panic!("must not stage or activate again")
                    });
                    if kind == "write" {
                        assert_eq!(next.unwrap_err().code, "invalid_policy_history");
                    } else {
                        assert_eq!(
                            next.unwrap().state,
                            if revision == 2 { "paused" } else { "current" }
                        );
                    }
                    assert_eq!(before, snapshot(&f.home));
                    let operation_count = fs::read_dir(f.skills.join("sniper-operator"))
                        .unwrap()
                        .filter(|entry| {
                            entry
                                .as_ref()
                                .unwrap()
                                .file_name()
                                .to_string_lossy()
                                .starts_with(".sniper-update-")
                        })
                        .count();
                    assert_eq!(operation_count, usize::from(revision == 3));
                }
            }
        }
        #[test]
        fn visible_completed_record_must_be_durable_before_a_later_reservation() {
            for kind in ["file_sync", "directory_sync"] {
                let f = Fixture::new();
                f.enable();
                inject_append(3, kind);
                assert!(super::run_once(&f.data, "codex", NEW, "2.0.0", |_| Ok(())).is_err());
                clear_append_failure();
                let before = snapshot(&f.home);
                crate::skill_activation::supported::set_policy_io_test_failure(Some((
                    "directory_sync",
                    1,
                )));
                assert!(super::run_once(
                    &f.data,
                    "codex",
                    "synthetic third bundle",
                    "3.0.0",
                    |_| panic!("reservation must not be published before history sync")
                )
                .is_err());
                clear_append_failure();
                assert_eq!(before, snapshot(&f.home));
                assert!(!f.policy().join(file_name(4)).exists());
                assert_eq!(
                    super::run_once(&f.data, "codex", "synthetic third bundle", "3.0.0", |_| Ok(
                        ()
                    ))
                    .unwrap()
                    .state,
                    "updated"
                );
                assert_eq!(status(&f.data, "codex").unwrap().revision, Some(5));
            }
        }
        #[test]
        fn explicit_disable_replay_reestablishes_visible_failed_record_durability() {
            for kind in ["file_sync", "directory_sync"] {
                let f = Fixture::new();
                f.enable();
                inject_append(2, kind);
                assert!(disable(&f.data, "codex").is_err());
                clear_append_failure();
                assert_eq!(status(&f.data, "codex").unwrap().state, "disabled");
                // A repeated explicit disable must actually sync; an injected
                // directory failure proves it cannot merely acknowledge bytes.
                crate::skill_activation::supported::set_policy_io_test_failure(Some((
                    "directory_sync",
                    1,
                )));
                assert!(disable(&f.data, "codex").is_err());
                clear_append_failure();
                assert_eq!(disable(&f.data, "codex").unwrap().state, "disabled");
                assert_eq!(f.run().state, "disabled");
            }
        }
        #[test]
        fn process_exit_at_policy_boundaries_never_retries_on_restart() {
            for point in [
                "reserved",
                "staged",
                "applied",
                "completed",
                "before_skill_swap",
                "after_skill_swap",
                "before_receipt_swap",
                "after_receipt_swap",
            ] {
                let f = Fixture::new();
                f.enable();
                let child = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "skill_auto_update::supported::tests::policy_crash_child_entry",
                        "--nocapture",
                    ])
                    .env("SNIPER_POLICY_TEST_ROOT", &f.home)
                    .env("SNIPER_POLICY_TEST_EXIT", point)
                    .env("HOME", f.home.join("home"))
                    .env("USERPROFILE", f.home.join("profile"))
                    .env("CODEX_HOME", f.home.join("codex"))
                    .env("CLAUDE_HOME", f.home.join("claude"))
                    .env("SNIPER_DATA_DIR", &f.data)
                    .env("TMPDIR", &f.home)
                    .env("TMP", &f.home)
                    .env("TEMP", &f.home)
                    .output()
                    .unwrap();
                assert_eq!(
                    child.status.code(),
                    Some(if point.ends_with("_swap") { 93 } else { 92 }),
                    "{point}: {child:?}"
                );
                let before = snapshot(&f.home);
                let status = f.run();
                assert_eq!(
                    status.state,
                    if point == "completed" {
                        "current"
                    } else {
                        "paused"
                    }
                );
                assert_eq!(before, snapshot(&f.home));
            }
        }
        #[test]
        fn policy_crash_child_entry() {
            let Some(home) = std::env::var_os("SNIPER_POLICY_TEST_ROOT") else {
                return;
            };
            let home = PathBuf::from(home);
            let fixture_name = home.file_name().unwrap().to_str().unwrap();
            let fixture_id = fixture_name.strip_prefix("sniper-policy-").unwrap();
            assert!(uuid(fixture_id));
            assert!(!fs::symlink_metadata(&home)
                .unwrap()
                .file_type()
                .is_symlink());
            let canonical = fs::canonicalize(&home).unwrap();
            for child in ["data", "skills"] {
                assert!(fs::canonicalize(home.join(child))
                    .unwrap()
                    .starts_with(&canonical));
            }
            let fixture_store = Store::open(&home.join("data"), "codex", false)
                .unwrap()
                .unwrap();
            let fixture_history = fixture_store.load().unwrap();
            let fixture_policy = fixture_history.last().unwrap();
            assert_eq!(fixture_policy.revision, 1);
            assert_eq!(fixture_policy.event, Event::Enabled);
            assert_eq!(
                fixture_policy.baseline.path,
                path_text(&home.join("skills/sniper-operator/SKILL.md")).unwrap()
            );
            assert_eq!(
                fixture_policy.baseline.installed_sha256,
                sha256(OLD.as_bytes())
            );
            assert_eq!(fixture_policy.baseline.enrolled_version, "1.0.0");
            let point = std::env::var("SNIPER_POLICY_TEST_EXIT").unwrap();
            use crate::skill_activation::{
                supported::set_automatic_test_exit, AutomaticTestCheckpoint,
            };
            let swap = match point.as_str() {
                "before_skill_swap" => Some(AutomaticTestCheckpoint::BeforeSkillSwap),
                "after_skill_swap" => Some(AutomaticTestCheckpoint::AfterSkillSwap),
                "before_receipt_swap" => Some(AutomaticTestCheckpoint::BeforeReceiptSwap),
                "after_receipt_swap" => Some(AutomaticTestCheckpoint::AfterReceiptSwap),
                _ => None,
            };
            set_automatic_test_exit(swap);
            super::run_once(&home.join("data"), "codex", NEW, "2.0.0", |step| {
                let name = match step {
                    Step::Reserved => "reserved",
                    Step::Staged => "staged",
                    Step::Applied => "applied",
                    Step::Completed => "completed",
                };
                if point == name {
                    std::process::exit(92);
                }
                Ok(())
            })
            .unwrap();
            panic!("did not reach policy crash checkpoint");
        }
        #[test]
        fn swap_interruptions_keep_reserved_attempt_and_never_auto_retry() {
            use crate::skill_activation::{set_automatic_test_failure, AutomaticTestCheckpoint};
            for checkpoint in [
                AutomaticTestCheckpoint::BeforeSkillSwap,
                AutomaticTestCheckpoint::AfterSkillSwap,
                AutomaticTestCheckpoint::BeforeReceiptSwap,
                AutomaticTestCheckpoint::AfterReceiptSwap,
            ] {
                let f = Fixture::new();
                f.enable();
                set_automatic_test_failure(Some(checkpoint));
                let result = super::run_once(&f.data, "codex", NEW, "2.0.0", |_| Ok(()));
                set_automatic_test_failure(None);
                assert!(result.is_err());
                let before = snapshot(&f.home);
                let row = f.run();
                assert_eq!(row.state, "paused");
                assert_eq!(row.revision, Some(2));
                assert!(row.operation_id.is_some());
                assert_eq!(before, snapshot(&f.home));
            }
        }
        #[test]
        fn concurrent_runner_and_disable_report_busy_then_disable_serializes() {
            let f = Fixture::new();
            f.enable();
            let data = f.data.clone();
            let (ready_rx, ready_tx) = (
                std::sync::mpsc::channel::<()>(),
                std::sync::mpsc::channel::<()>(),
            );
            let (notify, ready) = ready_rx;
            let (release, wait) = ready_tx;
            let runner = std::thread::spawn(move || {
                super::run_once(&data, "codex", NEW, "2.0.0", |step| {
                    if step == Step::Reserved {
                        notify.send(()).unwrap();
                        wait.recv().unwrap();
                    }
                    Ok(())
                })
            });
            ready.recv().unwrap();
            assert_eq!(disable(&f.data, "codex").unwrap_err().code, "policy_busy");
            assert_eq!(
                super::run_once(&f.data, "codex", NEW, "2.0.0", |_| Ok(()))
                    .unwrap_err()
                    .code,
                "policy_busy"
            );
            release.send(()).unwrap();
            assert_eq!(runner.join().unwrap().unwrap().state, "updated");
            assert_eq!(disable(&f.data, "codex").unwrap().state, "disabled");
            assert_eq!(f.run().state, "disabled");
        }
        #[test]
        fn changed_receipt_between_reservation_and_apply_cannot_activate() {
            let f = Fixture::new();
            f.enable();
            let receipt = f.skills.join("sniper-operator/.sniper-enrollment.json");
            let result = super::run_once(&f.data, "codex", NEW, "2.0.0", |step| {
                if step == Step::Reserved {
                    let bytes = fs::read(&receipt).unwrap();
                    fs::remove_file(&receipt).unwrap();
                    fs::write(&receipt, bytes).unwrap();
                }
                Ok(())
            });
            assert!(result.is_err());
            assert_eq!(fs::read(f.path()).unwrap(), OLD.as_bytes());
            assert_eq!(f.run().state, "paused");
            assert!(fs::read_dir(f.skills.join("sniper-operator"))
                .unwrap()
                .all(|e| !e
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".sniper-update-")));
        }
        #[test]
        fn copied_and_moved_policy_stores_do_not_copy_consent() {
            let f = Fixture::new();
            f.enable();
            let destination = f.home.join("copied/host-skill-updates/codex");
            fs::create_dir_all(&destination).unwrap();
            fs::copy(
                f.policy().join(file_name(1)),
                destination.join(file_name(1)),
            )
            .unwrap();
            assert!(status(&f.home.join("copied"), "codex").is_err());
            let moved = f.home.join("moved");
            fs::rename(&f.data, &moved).unwrap();
            assert!(status(&moved, "codex").is_err());
        }
        #[test]
        fn malformed_partial_unknown_gapped_linked_and_unsafe_policy_entries_fail_closed() {
            for mode in 0..7 {
                let f = Fixture::new();
                f.enable();
                let record = f.policy().join(file_name(1));
                match mode {
                    0 => fs::write(&record, b"{").unwrap(),
                    1 => {
                        let mut p: serde_json::Value =
                            serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
                        p["unknown"] = true.into();
                        fs::write(&record, serde_json::to_vec(&p).unwrap()).unwrap();
                    }
                    2 => fs::rename(&record, f.policy().join(file_name(2))).unwrap(),
                    3 => {
                        let other = f.home.join("outside");
                        fs::rename(&record, &other).unwrap();
                        symlink(other, record).unwrap();
                    }
                    4 => fs::hard_link(&record, f.home.join("hardlink")).unwrap(),
                    5 => fs::set_permissions(&record, fs::Permissions::from_mode(0o666)).unwrap(),
                    _ => fs::write(f.policy().join("unexpected"), b"bad").unwrap(),
                }
                assert!(status(&f.data, "codex").is_err());
                assert!(super::run_once(&f.data, "codex", NEW, "2.0.0", |_| panic!()).is_err());
                assert_eq!(fs::read(f.path()).unwrap(), OLD.as_bytes());
            }
        }
        #[test]
        fn ordinary_capacity_always_leaves_a_disable_record() {
            let f = Fixture::new();
            let mut p = f.enable();
            for _ in 1..MAX_RECORDS - 1 {
                p = enable(&f.data, "codex", &f.skills, OLD, "1.0.0", p.revision).unwrap();
            }
            assert_eq!(p.revision, Some((MAX_RECORDS - 1) as u64));
            assert_eq!(
                super::run_once(&f.data, "codex", NEW, "2.0.0", |_| panic!())
                    .unwrap_err()
                    .code,
                "policy_capacity"
            );
            assert_eq!(
                disable(&f.data, "codex").unwrap().revision,
                Some(MAX_RECORDS as u64)
            );
            assert_eq!(f.run().state, "disabled");
        }
        #[test]
        fn policy_and_stage_storage_cannot_be_inside_the_active_skill() {
            let f = Fixture::new();
            let nested = f.skills.join("sniper-operator/data");
            assert_eq!(
                enable(&nested, "codex", &f.skills, OLD, "1.0.0", None)
                    .unwrap_err()
                    .code,
                "staging_inside_active_skill"
            );
            assert!(!nested.exists());
            let alias = f.home.join("active-alias");
            symlink(f.skills.join("sniper-operator"), &alias).unwrap();
            assert_eq!(
                enable(&alias.join("data"), "codex", &f.skills, OLD, "1.0.0", None)
                    .unwrap_err()
                    .code,
                "staging_inside_active_skill"
            );
        }
        #[test]
        fn policy_file_and_directory_extended_attributes_are_refused() {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            for directory in [false, true] {
                let f = Fixture::new();
                f.enable();
                let path = if directory {
                    f.policy()
                } else {
                    f.policy().join(file_name(1))
                };
                let path = CString::new(path.as_os_str().as_bytes()).unwrap();
                let name = CString::new("user.sniper_synthetic").unwrap();
                #[cfg(target_os = "linux")]
                let rc = unsafe {
                    libc::setxattr(path.as_ptr(), name.as_ptr(), b"x".as_ptr().cast(), 1, 0)
                };
                #[cfg(target_os = "macos")]
                let rc = unsafe {
                    libc::setxattr(path.as_ptr(), name.as_ptr(), b"x".as_ptr().cast(), 1, 0, 0)
                };
                assert_eq!(rc, 0, "synthetic fixture must support xattrs");
                assert_eq!(
                    status(&f.data, "codex").unwrap_err().code,
                    "metadata_unsupported"
                );
                assert_eq!(
                    super::run_once(&f.data, "codex", NEW, "2.0.0", |_| panic!())
                        .unwrap_err()
                        .code,
                    "metadata_unsupported"
                );
                assert_eq!(fs::read(f.path()).unwrap(), OLD.as_bytes());
            }
        }
        #[test]
        fn policy_directory_lock_is_stable_and_cannot_be_redirected() {
            let f = Fixture::new();
            f.enable();
            let store = f.store();
            store.lock().unwrap();
            let old = f.home.join("old-policy");
            fs::rename(f.policy(), &old).unwrap();
            fs::create_dir(f.policy()).unwrap();
            assert!(store.check().is_err());
        }
    }
}

/// Owned only by the desktop shell, after successful WebView construction.
/// Blocking transactions are joined during teardown: abort is not cancellation.
#[derive(Default)]
pub struct DesktopTask {
    started: bool,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl DesktopTask {
    pub fn first_idle(&mut self, runtime: &tokio::runtime::Runtime, data_dir: &Path) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let data_dir = data_dir.to_owned();
            self.start_once(runtime, move |stop| {
                desktop_targets(&stop, |agent,bundle| {
                    match run_once(&data_dir,agent,bundle,env!("CARGO_PKG_VERSION")) {
                        Ok(result) if result.state=="updated" => {
                            tracing::info!(agent,"updated an opted-in bundled skill; restart the agent to reload");
                        }
                        Ok(result) if result.state=="paused" && result.error_code!=Some("policy_paused") => {
                            tracing::warn!(agent,code=?result.error_code,"skill automatic updates paused; inspect local CLI policy status");
                        }
                        Ok(_) => {},
                        Err(e) => {
                            tracing::warn!(agent,code=e.code,"could not check local skill update policy");
                        }
                    }
                });
            });
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            // Unsupported desktops do not probe installation paths or emit a
            // warning every launch for a feature that is off by default.
            let _ = (runtime, data_dir);
            self.started = true;
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos", test))]
    fn start_once(
        &mut self,
        runtime: &tokio::runtime::Runtime,
        run: impl FnOnce(std::sync::Arc<std::sync::atomic::AtomicBool>) + Send + 'static,
    ) {
        if self.started || self.stop.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        self.started = true;
        let stop = self.stop.clone();
        self.task = Some(runtime.spawn_blocking(move || run(stop)));
    }
    pub fn request_stop(&self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
    }
    pub fn shutdown(&mut self, runtime: &tokio::runtime::Runtime) {
        self.request_stop();
        if let Some(task) = self.task.take() {
            if let Err(e) = runtime.block_on(task) {
                tracing::warn!(?e, "skill update task stopped during desktop shutdown");
            }
        }
    }
}
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn desktop_targets(stop: &std::sync::atomic::AtomicBool, mut run: impl FnMut(&str, &str)) {
    for (agent, bundle) in [
        ("codex", crate::skills::CODEX_SKILL_TEMPLATE),
        ("claude", crate::skills::CLAUDE_SKILL_TEMPLATE),
    ] {
        // Crossing this check admits one target. Shutdown lets that transaction
        // finish, and prevents admission of the next target.
        if stop.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        run(agent, bundle);
    }
}
#[cfg(test)]
mod desktop_tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    #[test]
    fn first_idle_runs_once_and_shutdown_joins_running_work() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut task = DesktopTask::default();
        assert!(!task.started);
        assert!(task.task.is_none());
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        task.start_once(&runtime, move |stop| {
            desktop_targets(&stop, |_, _| {
                observed.fetch_add(1, Ordering::SeqCst);
            })
        });
        task.start_once(&runtime, |_| panic!("second idle cannot start work"));
        // Wait for completion without cancellation, then prove no second launch.
        runtime.block_on(task.task.take().unwrap()).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
        task.shutdown(&runtime);
        task.first_idle(&runtime, Path::new("unreachable"));
        assert!(task.task.is_none());
    }
    #[test]
    fn shutdown_before_first_idle_starts_nothing() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut task = DesktopTask::default();
        task.request_stop();
        task.start_once(&runtime, |_| panic!("stopped launch cannot run"));
        assert!(!task.started);
        assert!(task.task.is_none());
    }
    #[test]
    fn shutdown_waits_for_current_target_and_prevents_next() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut task = DesktopTask::default();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        task.start_once(&runtime, move |stop| {
            desktop_targets(&stop, |agent, _| {
                assert_eq!(agent, "codex");
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                observed.fetch_add(1, Ordering::SeqCst);
            })
        });
        started_rx.recv().unwrap();
        task.request_stop();
        assert_eq!(count.load(Ordering::SeqCst), 0);
        let release = std::thread::spawn(move || release_tx.send(()).unwrap());
        task.shutdown(&runtime);
        release.join().unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert!(task.task.is_none());
    }
    #[test]
    fn only_successful_desktop_webview_has_an_idle_hook() {
        let desktop = include_str!("bin/sniper-desktop.rs");
        assert!(
            desktop
                .find("let webview = match webview_builder.build()")
                .unwrap()
                < desktop.find("let mut skill_updates =").unwrap()
        );
        assert!(desktop.contains("Event::MainEventsCleared"));
        for source in [
            include_str!("lib.rs"),
            include_str!("main.rs"),
            include_str!("bin/sniper-cli.rs"),
        ] {
            assert!(!source.contains(".first_idle("));
            assert!(!source.contains("DesktopTask::default"));
        }
    }
}
