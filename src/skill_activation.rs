//! Explicit, transaction-bound activation of the executing binary's bundled skill.
//!
//! Retaining swaps preserve the actual displaced objects. The advisory lock only
//! coordinates Sniper writers: editors must be quiescent, and a detected race is
//! retained for inspection rather than hidden by an unsafe automatic reversal.
use std::path::Path;

use crate::skill_managed::{error, ManagedSkillError};
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, ManagedSkillError>;

pub fn valid_operation_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.hyphenated().to_string() == value)
}

#[derive(Debug, Serialize)]
pub struct SkillUpdateResult {
    pub agent: String,
    pub path: String,
    pub receipt_path: String,
    pub transaction_dir: String,
    pub operation_id: String,
    pub state: &'static str,
    pub current_state: &'static str,
    pub installed_sha256: Option<String>,
    pub allows_automatic_updates: bool,
    pub agent_reloaded: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<&'static str>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) struct Record {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) size: u64,
    pub(crate) mtime: i64,
    pub(crate) mtime_nsec: i64,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) struct DirectoryBinding {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

/// Exact local observations, not publisher authentication or update permission.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) struct BaselineBinding {
    pub(crate) agent: String,
    pub(crate) path: String,
    pub(crate) directory: DirectoryBinding,
    pub(crate) skill: Record,
    pub(crate) receipt: Record,
    pub(crate) installed_sha256: String,
    pub(crate) enrolled_version: String,
    pub(crate) history_sha256: String,
}

#[derive(Debug)]
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) struct AutomaticUpdateResult {
    pub(crate) result: SkillUpdateResult,
    pub(crate) committed_baseline: BaselineBinding,
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[derive(Clone, Copy)]
pub(crate) enum AutomaticTestCheckpoint {
    BeforeSkillSwap,
    AfterSkillSwap,
    BeforeReceiptSwap,
    AfterReceiptSwap,
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(crate) fn set_automatic_test_failure(checkpoint: Option<AutomaticTestCheckpoint>) {
    supported::set_automatic_test_failure(checkpoint);
}

#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) fn inspect_automatic_baseline(agent: &str, root: &Path) -> Result<BaselineBinding> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return supported::inspect_baseline(agent, root);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (agent, root);
        Err(error("platform_unsupported"))
    }
}

#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) fn inspect_automatic_completion(
    agent: &str,
    root: &Path,
    expected: &BaselineBinding,
    operation_id: &str,
    version: &str,
    hash: &str,
) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return supported::inspect_completion(agent, root, expected, operation_id, version, hash);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (agent, root, expected, operation_id, version, hash);
        Err(error("platform_unsupported"))
    }
}

/// The caller separately authorizes policy. This fresh-only entry cannot resume
/// a prior operation and returns a checked committed baseline under the same lock.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) fn apply_automatic_skill_update(
    agent: &str,
    root: &Path,
    bundled: &str,
    version: &str,
    staging_dir: &Path,
    operation_id: &str,
    expected: &BaselineBinding,
) -> Result<AutomaticUpdateResult> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return supported::apply_automatic(
        agent,
        root,
        bundled,
        version,
        staging_dir,
        operation_id,
        expected,
        |_step| {
            #[cfg(test)]
            supported::automatic_test_checkpoint(_step)?;
            Ok(())
        },
    );
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (
            agent,
            root,
            bundled,
            version,
            staging_dir,
            operation_id,
            expected,
        );
        Err(error("platform_unsupported"))
    }
}

pub fn apply_skill_update(
    agent: &str,
    root: &Path,
    bundled: &str,
    version: &str,
    staging_dir: &Path,
    operation_id: &str,
) -> Result<SkillUpdateResult> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return supported::apply(
        agent,
        root,
        bundled,
        version,
        staging_dir,
        operation_id,
        |_| Ok(()),
    );
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (agent, root, bundled, version, staging_dir, operation_id);
        Err(error("platform_unsupported"))
    }
}

pub fn update_result(agent: &str, root: &Path, operation_id: &str) -> Result<SkillUpdateResult> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return supported::result(agent, root, operation_id);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (agent, root, operation_id);
        Err(error("platform_unsupported"))
    }
}

pub fn rollback_skill_update(
    agent: &str,
    root: &Path,
    operation_id: &str,
) -> Result<SkillUpdateResult> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return supported::rollback(agent, root, operation_id, |_| Ok(()));
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (agent, root, operation_id);
        Err(error("platform_unsupported"))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod supported {
    use super::*;
    use crate::{
        skill_managed::{
            encode_receipt, io_error, parse_receipt, path_text, read_receipt, target,
            EnrollmentReceipt, Target, ENROLLMENT_FILE, STAGED_RECEIPT_FILE,
        },
        skill_status::{sha256, MAX_SKILL_BYTES},
    };
    use serde::Deserialize;
    use std::{
        ffi::CString,
        fs::{self, File, Metadata, OpenOptions},
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        path::PathBuf,
    };

    const PREFIX: &str = ".sniper-update-";
    const MANIFEST: &str = "intent.json";
    const SKILL_SLOT: &str = "skill.slot";
    const RECEIPT_SLOT: &str = "receipt.slot";
    const APPLIED: &str = "applied.json";
    const ROLLBACK: &str = "rollback-intent.json";
    const ROLLED_BACK: &str = "rolled-back.json";
    const LIMIT: u64 = 16 * 1024;
    const MAX_TRANSACTIONS: usize = 128;

    impl Record {
        fn new(meta: &Metadata, bytes: &[u8]) -> Self {
            Self {
                dev: meta.dev(),
                ino: meta.ino(),
                mode: meta.mode(),
                uid: meta.uid(),
                gid: meta.gid(),
                size: meta.len(),
                mtime: meta.mtime(),
                mtime_nsec: meta.mtime_nsec(),
                sha256: sha256(bytes),
            }
        }
    }

    pub(crate) struct Observed {
        pub(crate) file: File,
        pub(crate) bytes: Vec<u8>,
        pub(crate) record: Record,
    }
    pub(crate) struct Directory {
        path: PathBuf,
        file: File,
        locked: std::cell::Cell<bool>,
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            if self.locked.get() {
                // Explicit release also ends an inherited pre-exec descriptor lock.
                unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
            }
        }
    }
    impl Directory {
        pub(crate) fn path(&self) -> &Path {
            &self.path
        }
        pub(crate) fn binding(&self) -> Result<DirectoryBinding> {
            self.check()?;
            let meta = self.file.metadata().map_err(io_error)?;
            Ok(DirectoryBinding {
                dev: meta.dev(),
                ino: meta.ino(),
                mode: meta.mode(),
                uid: meta.uid(),
                gid: meta.gid(),
            })
        }
        pub(crate) fn open(path: &Path) -> Result<Self> {
            let before = fs::symlink_metadata(path).map_err(io_error)?;
            validate_dir(&before)?;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(
                    libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
                .open(path)
                .map_err(io_error)?;
            let result = Self {
                path: path.to_owned(),
                file,
                locked: std::cell::Cell::new(false),
            };
            result.check()?;
            if !identity(&before, &result.file.metadata().map_err(io_error)?) {
                return Err(error("directory_changed"));
            }
            Ok(result)
        }
        pub(crate) fn check(&self) -> Result<()> {
            let now = fs::symlink_metadata(&self.path).map_err(io_error)?;
            validate_dir(&now)?;
            let held = self.file.metadata().map_err(io_error)?;
            validate_access_metadata(&self.file)?;
            if !identity(&now, &held) {
                return Err(error("directory_changed"));
            }
            Ok(())
        }
        pub(crate) fn lock(&self) -> Result<()> {
            // SAFETY: the held directory fd remains live; flock never removes a lock inode.
            if unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(error("transaction_busy"));
            }
            self.locked.set(true);
            self.check()
        }
        pub(crate) fn sync(&self) -> Result<()> {
            sync_file(&self.file, "directory_sync")
        }
        pub(crate) fn read(&self, name: &str, limit: u64) -> Result<Observed> {
            self.check()?;
            let name_c = name_c(name)?;
            // SAFETY: both fd and single-component C string are live. NONBLOCK prevents FIFO hangs.
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name_c.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io_error(std::io::Error::last_os_error()));
            }
            // SAFETY: openat returned a uniquely owned fd.
            let file = unsafe { File::from_raw_fd(fd) };
            let before = file.metadata().map_err(io_error)?;
            validate_file(&file, &before, limit)?;
            let mut bytes = Vec::new();
            (&file)
                .take(limit + 1)
                .read_to_end(&mut bytes)
                .map_err(io_error)?;
            let after = file.metadata().map_err(io_error)?;
            validate_file(&file, &after, limit)?;
            let at_path = self.stat(name)?;
            if bytes.len() as u64 > limit {
                return Err(error("file_too_large"));
            }
            let record = Record::new(&after, &bytes);
            if Record::new(&before, &bytes) != record
                || Record::new(&at_path, &bytes) != record
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
                || bytes.len() as u64 != after.len()
            {
                return Err(error("changed_during_read"));
            }
            self.check()?;
            Ok(Observed {
                file,
                bytes,
                record,
            })
        }
        pub(crate) fn stat(&self, name: &str) -> Result<Metadata> {
            // This pathname observation is checked against the open directory on either side.
            self.check()?;
            let meta = fs::symlink_metadata(self.path.join(name)).map_err(io_error)?;
            self.check()?;
            Ok(meta)
        }
        pub(crate) fn exists(&self, name: &str) -> Result<bool> {
            match self.stat(name) {
                Ok(_) => Ok(true),
                Err(e) if e.code == "missing" => Ok(false),
                Err(e) => Err(e),
            }
        }
        pub(crate) fn write_new(&self, name: &str, bytes: &[u8], mode: u32) -> Result<Observed> {
            self.check()?;
            let name_c = name_c(name)?;
            // SAFETY: O_EXCL prevents replacing any existing entry or following its link.
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name_c.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(io_error(std::io::Error::last_os_error()));
            }
            // SAFETY: successful openat returned a uniquely owned descriptor.
            let mut file = unsafe { File::from_raw_fd(fd) };
            write_bytes(&mut file, bytes)?;
            // Preserve supported access bits; unexpected ACLs/xattrs are refused below.
            if unsafe { libc::fchmod(file.as_raw_fd(), (mode & 0o777) as libc::mode_t) } != 0 {
                return Err(io_error(std::io::Error::last_os_error()));
            }
            sync_file(&file, "file_sync")?;
            self.read(name, MAX_SKILL_BYTES)
        }
        pub(crate) fn child_new(&self, name: &str) -> Result<Self> {
            self.check()?;
            let c = name_c(name)?;
            // SAFETY: mkdirat creates only this single child in the held directory.
            if unsafe { libc::mkdirat(self.file.as_raw_fd(), c.as_ptr(), 0o700) } != 0 {
                return Err(io_error(std::io::Error::last_os_error()));
            }
            self.sync()?;
            self.check()?;
            Self::open(&self.path.join(name))
        }
    }
    #[cfg(test)]
    thread_local! { static IO_FAILURE: std::cell::RefCell<Option<(&'static str, usize, usize)>> = const { std::cell::RefCell::new(None) }; }
    #[cfg(test)]
    pub(crate) fn set_policy_io_test_failure(failure: Option<(&'static str, usize)>) {
        IO_FAILURE.with(|slot| *slot.borrow_mut() = failure.map(|(kind, nth)| (kind, nth, 0)));
    }
    fn io_boundary(kind: &'static str) -> Result<()> {
        #[cfg(test)]
        if IO_FAILURE.with(|cell| {
            let mut slot = cell.borrow_mut();
            if let Some((wanted, nth, observed)) = slot.as_mut() {
                if *wanted == kind {
                    *observed += 1;
                    return *nth == *observed;
                }
            }
            false
        }) {
            return Err(error("injected_io_failure"));
        }
        let _ = kind;
        Ok(())
    }
    fn sync_file(file: &File, kind: &'static str) -> Result<()> {
        io_boundary(kind)?;
        file.sync_all().map_err(io_error)
    }
    fn write_bytes(file: &mut File, bytes: &[u8]) -> Result<()> {
        if let Err(e) = io_boundary("write") {
            // A failed write may have exposed a prefix; no retry overwrites it.
            #[cfg(test)]
            file.write_all(&bytes[..bytes.len() / 2])
                .map_err(io_error)?;
            return Err(e);
        }
        file.write_all(bytes).map_err(io_error)
    }
    fn establish_durability(active: &Directory, tx: &Directory) -> Result<()> {
        for (dir, name, limit) in [
            (active, "SKILL.md", MAX_SKILL_BYTES),
            (active, ENROLLMENT_FILE, LIMIT),
            (tx, SKILL_SLOT, MAX_SKILL_BYTES),
            (tx, RECEIPT_SLOT, LIMIT),
            (tx, MANIFEST, LIMIT),
        ] {
            sync_file(&dir.read(name, limit)?.file, "file_sync")?;
        }
        sync_pair(active, tx)
    }

    fn name_c(name: &str) -> Result<CString> {
        if name.is_empty() || name.contains('/') || matches!(name, "." | "..") {
            return Err(error("invalid_filename"));
        }
        CString::new(name).map_err(|_| error("invalid_filename"))
    }
    fn identity(a: &Metadata, b: &Metadata) -> bool {
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    fn validate_dir(meta: &Metadata) -> Result<()> {
        if meta.file_type().is_symlink() {
            return Err(error("symlink"));
        }
        if !meta.is_dir() {
            return Err(error("non_directory"));
        }
        // SAFETY: geteuid has no preconditions.
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(error("unowned"));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(error("unsafe_permissions"));
        }
        Ok(())
    }
    fn validate_file(file: &File, meta: &Metadata, limit: u64) -> Result<()> {
        if !meta.is_file() {
            return Err(error("non_regular_file"));
        }
        if meta.nlink() != 1 {
            return Err(error("hardlink"));
        }
        // SAFETY: geteuid has no preconditions.
        if meta.uid() != unsafe { libc::geteuid() } {
            return Err(error("unowned"));
        }
        if meta.mode() & 0o7022 != 0 {
            return Err(error("unsafe_permissions"));
        }
        if meta.len() > limit {
            return Err(error("file_too_large"));
        }
        validate_access_metadata(file)
    }
    /// Attributes the system attaches by itself, which grant no access. macOS tags
    /// every file a process creates with the app it came from, so each file a
    /// downloaded Sniper or a terminal it started writes carries
    /// `com.apple.provenance`, and refusing it refused every activation there.
    /// Opening a file in an app (`open SKILL.md`) adds the time it was last used,
    /// `com.apple.lastuseddate#PS`, after which preview allowed an update that
    /// apply then refused.
    // ponytail: only this label. An SELinux host gives every file `security.selinux`
    // and is refused the same way; add it if such hosts are supported. Linux keeps
    // ACLs in attributes (`system.posix_acl_*`), so anything else stays refused.
    #[cfg(target_os = "macos")]
    const SYSTEM_ATTRIBUTES: &[&[u8]] = &[b"com.apple.provenance", b"com.apple.lastuseddate#PS"];
    #[cfg(target_os = "linux")]
    const SYSTEM_ATTRIBUTES: &[&[u8]] = &[];

    /// Whether a NUL-separated attribute name list holds only system labels.
    fn only_system_attributes(names: &[u8]) -> bool {
        names
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
            .all(|name| SYSTEM_ATTRIBUTES.contains(&name))
    }

    fn list_attribute_names(file: &File, names: &mut [u8]) -> isize {
        let list = if names.is_empty() {
            std::ptr::null_mut()
        } else {
            names.as_mut_ptr().cast()
        };
        #[cfg(target_os = "linux")]
        // SAFETY: a null list with zero size queries the length; otherwise the
        // buffer is live and its exact length is passed.
        let listed = unsafe { libc::flistxattr(file.as_raw_fd(), list, names.len()) };
        #[cfg(target_os = "macos")]
        // SAFETY: as above, with no options.
        let listed = unsafe { libc::flistxattr(file.as_raw_fd(), list, names.len(), 0) };
        listed
    }

    fn validate_access_metadata(file: &File) -> Result<()> {
        let length = list_attribute_names(file, &mut []);
        if length < 0 {
            return Err(error("metadata_unsupported"));
        }
        if length > 0 {
            let mut names = vec![0_u8; length as usize];
            // A list that grew since the length query fails with ERANGE, so it is
            // refused rather than read short.
            let listed = list_attribute_names(file, &mut names);
            if listed < 0 || !only_system_attributes(&names[..listed as usize]) {
                return Err(error("metadata_unsupported"));
            }
        }
        #[cfg(target_os = "macos")]
        check_macos_acl(file)?;
        Ok(())
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Intent {
        schema_version: u32,
        kind: String,
        agent: String,
        path: String,
        operation_id: String,
        staging_dir: String,
        bundle_version: String,
        old_version: String,
        old_skill: Record,
        new_skill: Record,
        old_receipt: Record,
        new_receipt: Record,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StageReceipt {
        schema_version: u32,
        kind: String,
        agent: String,
        path: String,
        enrollment_receipt_sha256: String,
        installed_sha256: String,
        bundled_sha256: String,
        bundled_version: String,
        candidate_file: String,
        activated: bool,
        allows_automatic_updates: bool,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Step {
        BaselineValidated,
        DirectoryCreated,
        SkillPrepared,
        ReceiptPrepared,
        IntentWritten,
        Prepared,
        BeforeSkillSwap,
        SkillSwapped,
        SkillSynced,
        BeforeReceiptSwap,
        ReceiptSwapped,
        ReceiptSynced,
        AppliedRecorded,
        RollbackRecorded,
        BeforeReceiptRestore,
        ReceiptRestored,
        BeforeSkillRestore,
        SkillRestored,
        RolledBackRecorded,
    }
    #[cfg(test)]
    thread_local! {
        static AUTOMATIC_TEST_FAILURE: std::cell::Cell<Option<Step>> = const { std::cell::Cell::new(None) };
    }
    #[cfg(test)]
    thread_local! { static AUTOMATIC_TEST_EXIT: std::cell::Cell<bool> = const {std::cell::Cell::new(false)}; }
    #[cfg(test)]
    pub(crate) fn set_automatic_test_exit(checkpoint: Option<AutomaticTestCheckpoint>) {
        set_automatic_test_failure(checkpoint);
        AUTOMATIC_TEST_EXIT.with(|value| value.set(checkpoint.is_some()));
    }
    #[cfg(test)]
    pub(super) fn set_automatic_test_failure(checkpoint: Option<AutomaticTestCheckpoint>) {
        AUTOMATIC_TEST_FAILURE.with(|value| {
            value.set(checkpoint.map(|point| match point {
                AutomaticTestCheckpoint::BeforeSkillSwap => Step::BeforeSkillSwap,
                AutomaticTestCheckpoint::AfterSkillSwap => Step::SkillSwapped,
                AutomaticTestCheckpoint::BeforeReceiptSwap => Step::BeforeReceiptSwap,
                AutomaticTestCheckpoint::AfterReceiptSwap => Step::ReceiptSwapped,
            }))
        });
    }
    #[cfg(test)]
    pub(super) fn automatic_test_checkpoint(step: Step) -> Result<()> {
        if AUTOMATIC_TEST_FAILURE.with(|value| value.get() == Some(step)) {
            if AUTOMATIC_TEST_EXIT.with(|value| value.get()) {
                std::process::exit(93);
            }
            Err(error("injected"))
        } else {
            Ok(())
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Placement {
        Before,
        After,
    }
    struct PlacementPair {
        skill: Placement,
        receipt: Placement,
    }

    fn validate_id(id: &str) -> Result<()> {
        if valid_operation_id(id) {
            Ok(())
        } else {
            Err(error("invalid_operation_id"))
        }
    }
    fn locate(agent: &str, root: &Path, id: &str) -> Result<(Target, Directory, String)> {
        validate_id(id)?;
        let target = target(agent, root, "", "0.0.0")?;
        let dir = Directory::open(target.path.parent().unwrap())?;
        Ok((target, dir, format!("{PREFIX}{id}")))
    }
    fn stage_path(path: &Path, active: &Directory) -> Result<PathBuf> {
        let absolute = std::path::absolute(path).map_err(io_error)?;
        if absolute.starts_with(&active.path) {
            return Err(error("staging_inside_active_skill"));
        }
        let dir = Directory::open(&absolute)?;
        let actual = fs::canonicalize(&absolute).map_err(io_error)?;
        let active_actual = fs::canonicalize(&active.path).map_err(io_error)?;
        if actual.starts_with(active_actual) {
            return Err(error("staging_inside_active_skill"));
        }
        dir.check()?;
        Ok(absolute)
    }
    fn load_intent(tx: &Directory, target: &Target, agent: &str, id: &str) -> Result<Intent> {
        let read = tx.read(MANIFEST, LIMIT)?;
        let intent: Intent =
            serde_json::from_slice(&read.bytes).map_err(|_| error("invalid_journal"))?;
        if intent.schema_version != 1
            || intent.kind != "sniper_skill_activation"
            || intent.agent != agent
            || intent.path != target.path_text
            || intent.operation_id != id
            || !valid_operation_id(&intent.operation_id)
            || semver::Version::parse(&intent.bundle_version).is_err()
            || semver::Version::parse(&intent.old_version).is_err()
            || version_upgrade(&intent.old_version, &intent.bundle_version).is_err()
            || intent.old_skill.sha256 == intent.new_skill.sha256
            || intent.old_skill.mode != intent.new_skill.mode
            || intent.old_skill.uid != intent.new_skill.uid
            || intent.old_skill.gid != intent.new_skill.gid
            || intent.old_receipt.mode != intent.new_receipt.mode
            || intent.old_receipt.uid != intent.new_receipt.uid
            || intent.old_receipt.gid != intent.new_receipt.gid
        {
            return Err(error("invalid_journal"));
        }
        for r in [
            &intent.old_skill,
            &intent.new_skill,
            &intent.old_receipt,
            &intent.new_receipt,
        ] {
            if r.sha256.len() != 64
                || !r
                    .sha256
                    .bytes()
                    .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
                || r.size > MAX_SKILL_BYTES
            {
                return Err(error("invalid_journal"));
            }
        }
        Ok(intent)
    }
    fn placements(active: &Directory, tx: &Directory, intent: &Intent) -> Result<PlacementPair> {
        fn placement(
            active: &Observed,
            slot: &Observed,
            old: &Record,
            new: &Record,
        ) -> Result<Placement> {
            if &active.record == old && &slot.record == new {
                Ok(Placement::Before)
            } else if &active.record == new && &slot.record == old {
                Ok(Placement::After)
            } else {
                Err(error("transaction_changed"))
            }
        }
        let current_receipt = active.read(ENROLLMENT_FILE, LIMIT)?;
        let slot_receipt = tx.read(RECEIPT_SLOT, LIMIT)?;
        let receipt = placement(
            &current_receipt,
            &slot_receipt,
            &intent.old_receipt,
            &intent.new_receipt,
        )?;
        let (old, new) = if receipt == Placement::Before {
            (&current_receipt.bytes, &slot_receipt.bytes)
        } else {
            (&slot_receipt.bytes, &current_receipt.bytes)
        };
        let old = parse_receipt(old, &intent.agent, &intent.path)
            .map_err(|_| error("invalid_journal"))?;
        let new = parse_receipt(new, &intent.agent, &intent.path)
            .map_err(|_| error("invalid_journal"))?;
        if old.enrolled_version != intent.old_version
            || old.enrolled_sha256 != intent.old_skill.sha256
            || new.schema_version != 2
            || new.enrolled_version != intent.bundle_version
            || new.enrolled_sha256 != intent.new_skill.sha256
            || new.last_operation_id.as_deref() != Some(intent.operation_id.as_str())
        {
            return Err(error("invalid_journal"));
        }
        Ok(PlacementPair {
            skill: placement(
                &active.read("SKILL.md", MAX_SKILL_BYTES)?,
                &tx.read(SKILL_SLOT, MAX_SKILL_BYTES)?,
                &intent.old_skill,
                &intent.new_skill,
            )?,
            receipt,
        })
    }

    fn marker_bytes(tx: &Directory, id: &str, name: &str) -> Result<Vec<u8>> {
        let intent_hash = sha256(&tx.read(MANIFEST, LIMIT)?.bytes);
        Ok(format!("{{\"operation_id\":\"{id}\",\"phase\":\"{name}\",\"intent_sha256\":\"{intent_hash}\"}}\n").into_bytes())
    }
    fn marker(tx: &Directory, id: &str, name: &str) -> Result<bool> {
        if !tx.exists(name)? {
            return Ok(false);
        }
        if tx.read(name, LIMIT)?.bytes != marker_bytes(tx, id, name)? {
            return Err(error("invalid_journal"));
        }
        Ok(true)
    }
    fn publish_marker(tx: &Directory, id: &str, name: &str) -> Result<()> {
        if !marker(tx, id, name)? {
            tx.write_new(name, &marker_bytes(tx, id, name)?, 0o600)?;
        }
        // A previous process may have written all bytes but failed file fsync.
        // Explicit retries must establish durability before relying on this intent.
        sync_file(&tx.read(name, LIMIT)?.file, "file_sync")?;
        tx.sync()
    }
    fn exchange(
        active: &Directory,
        active_name: &str,
        tx: &Directory,
        slot_name: &str,
    ) -> Result<()> {
        active.check()?;
        tx.check()?;
        io_boundary("swap")?;
        let a = name_c(active_name)?;
        let b = name_c(slot_name)?;
        #[cfg(target_os = "linux")]
        // SAFETY: live directory descriptors and single-component names; EXCHANGE retains both objects atomically.
        let result = unsafe {
            libc::renameat2(
                active.file.as_raw_fd(),
                a.as_ptr(),
                tx.file.as_raw_fd(),
                b.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        };
        #[cfg(target_os = "macos")]
        // SAFETY: RENAME_SWAP atomically retains both existing objects; never fall back to replacing rename.
        let result = unsafe {
            libc::renameatx_np(
                active.file.as_raw_fd(),
                a.as_ptr(),
                tx.file.as_raw_fd(),
                b.as_ptr(),
                libc::RENAME_SWAP,
            )
        };
        if result != 0 {
            let e = std::io::Error::last_os_error();
            return Err(
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENOSYS) | Some(libc::EINVAL) | Some(libc::ENOTSUP)
                ) {
                    error("swap_unsupported")
                } else {
                    io_error(e)
                },
            );
        }
        active.check()?;
        tx.check()?;
        Ok(())
    }
    fn sync_pair(active: &Directory, tx: &Directory) -> Result<()> {
        tx.sync()?;
        active.sync()?;
        tx.check()?;
        active.check()
    }

    fn pending(
        active: &Directory,
        target: &Target,
        agent: &str,
        excluding: Option<&str>,
    ) -> Result<()> {
        inspect_history(active, target, agent, excluding, true).map(|_| ())
    }
    fn inspect_history(
        active: &Directory,
        target: &Target,
        agent: &str,
        excluding: Option<&str>,
        establish_terminal_durability: bool,
    ) -> Result<String> {
        active.check()?;
        let mut count = 0;
        let mut found = false;
        let mut history = Vec::new();
        for entry in fs::read_dir(&active.path).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name();
            if !name.as_bytes().starts_with(PREFIX.as_bytes()) {
                continue;
            }
            let name = name.to_str().ok_or_else(|| error("pending_transaction"))?;
            let id = &name[PREFIX.len()..];
            count += 1;
            if count > MAX_TRANSACTIONS {
                return Err(error("transaction_limit"));
            }
            if Some(id) == excluding {
                found = true;
                continue;
            }
            let completed = (|| {
                validate_id(id)?;
                let tx = Directory::open(&entry.path())?;
                let recorded = tx.read(MANIFEST, LIMIT)?;
                load_intent(&tx, target, agent, id)?;
                let back = marker(&tx, id, ROLLED_BACK)?;
                let rolling = marker(&tx, id, ROLLBACK)?;
                let applied = marker(&tx, id, APPLIED)?;
                let terminal = if back && rolling {
                    Some(ROLLED_BACK)
                } else if applied && !rolling && !back {
                    Some(APPLIED)
                } else {
                    None
                };
                if let Some(name) = terminal.filter(|_| establish_terminal_durability) {
                    // Complete visible marker bytes can survive a failed file
                    // fsync. Establish their durability before a later operation
                    // moves the inode needed to reconcile this older transaction.
                    publish_marker(&tx, id, name)?;
                }
                if tx.read(MANIFEST, LIMIT)?.record != recorded.record {
                    return Err(error("transaction_changed"));
                }
                history.push((
                    id.to_owned(),
                    recorded.record.sha256,
                    applied,
                    rolling,
                    back,
                ));
                Ok::<_, ManagedSkillError>(terminal.is_some())
            })();
            if completed != Ok(true) {
                return Err(error("pending_transaction"));
            }
        }
        if count == MAX_TRANSACTIONS && excluding.is_some() && !found {
            return Err(error("transaction_limit"));
        }
        active.check()?;
        history.sort();
        // The entry count and every intent are bounded above. Exact journal
        // history catches an explicit apply/rollback that restored old inodes.
        let bytes = serde_json::to_vec(&history).map_err(|_| error("invalid_journal"))?;
        Ok(sha256(&bytes))
    }
    pub(super) fn check_pending(agent: &str, root: &Path) -> Result<()> {
        let target = target(agent, root, "", "0.0.0")?;
        let active = Directory::open(target.path.parent().unwrap())?;
        pending(&active, &target, agent, None)
    }

    fn baseline_from_observed(
        active: &Directory,
        target: &Target,
        agent: &str,
        skill: &Observed,
        receipt: &Observed,
    ) -> Result<BaselineBinding> {
        let enrolled = parse_receipt(&receipt.bytes, agent, &target.path_text)?;
        if enrolled.enrolled_sha256 != skill.record.sha256 {
            return Err(error("installed_modified"));
        }
        let history_sha256 = inspect_history(active, target, agent, None, false)?;
        let directory = active.binding()?;
        if active.read("SKILL.md", MAX_SKILL_BYTES)?.record != skill.record
            || active.read(ENROLLMENT_FILE, LIMIT)?.record != receipt.record
        {
            return Err(error("baseline_changed"));
        }
        Ok(BaselineBinding {
            agent: agent.into(),
            path: target.path_text.clone(),
            directory,
            skill: skill.record.clone(),
            receipt: receipt.record.clone(),
            installed_sha256: skill.record.sha256.clone(),
            enrolled_version: enrolled.enrolled_version,
            history_sha256,
        })
    }
    fn baseline_locked(
        active: &Directory,
        target: &Target,
        agent: &str,
    ) -> Result<BaselineBinding> {
        let skill = active.read("SKILL.md", MAX_SKILL_BYTES)?;
        let receipt = active.read(ENROLLMENT_FILE, LIMIT)?;
        baseline_from_observed(active, target, agent, &skill, &receipt)
    }
    pub(super) fn inspect_baseline(agent: &str, root: &Path) -> Result<BaselineBinding> {
        let target = target(agent, root, "", "0.0.0")?;
        let active = Directory::open(target.path.parent().unwrap())?;
        active.lock()?;
        baseline_locked(&active, &target, agent)
    }
    pub(super) fn inspect_completion(
        agent: &str,
        root: &Path,
        expected: &BaselineBinding,
        id: &str,
        version: &str,
        hash: &str,
    ) -> Result<()> {
        let (target, active, name) = locate(agent, root, id)?;
        active.lock()?;
        if &baseline_locked(&active, &target, agent)? != expected {
            return Err(error("baseline_changed"));
        }
        let tx = Directory::open(&active.path.join(name))?;
        let intent = load_intent(&tx, &target, agent, id)?;
        if !marker(&tx, id, APPLIED)?
            || marker(&tx, id, ROLLBACK)?
            || marker(&tx, id, ROLLED_BACK)?
            || intent.bundle_version != version
            || intent.new_skill.sha256 != hash
            || expected.enrolled_version != version
            || expected.installed_sha256 != hash
        {
            return Err(error("completion_mismatch"));
        }
        let placement = placements(&active, &tx, &intent)?;
        if placement.skill != Placement::After || placement.receipt != Placement::After {
            return Err(error("completion_mismatch"));
        }
        Ok(())
    }

    fn observation(
        target: &Target,
        active: &Directory,
        tx: &Directory,
        agent: &str,
        id: &str,
    ) -> SkillUpdateResult {
        let current = active.read("SKILL.md", MAX_SKILL_BYTES).ok();
        let mut result = SkillUpdateResult {
            agent: agent.into(),
            path: target.path_text.clone(),
            receipt_path: target.receipt_text.clone(),
            transaction_dir: path_text(&tx.path).unwrap_or_default(),
            operation_id: id.into(),
            state: "recovery_required",
            current_state: if current.is_some() {
                "changed"
            } else {
                "unavailable"
            },
            installed_sha256: current.as_ref().map(|v| v.record.sha256.clone()),
            allows_automatic_updates: false,
            agent_reloaded: false,
            error_code: Some("recovery_required"),
        };
        let classify = || -> Result<(&'static str, &'static str, Option<&'static str>)> {
            let intent = load_intent(tx, target, agent, id)?;
            let current_state = match current.as_ref().map(|v| &v.record) {
                Some(v) if v == &intent.old_skill => "baseline",
                Some(v) if v == &intent.new_skill => "updated",
                Some(_) => "changed",
                None => "unavailable",
            };
            let applied = marker(tx, id, APPLIED)?;
            let rolling = marker(tx, id, ROLLBACK)?;
            let back = marker(tx, id, ROLLED_BACK)?;
            // Terminal outcomes are history, not a claim that files are still unchanged.
            if back && rolling {
                return Ok(("rolled_back", current_state, None));
            }
            if applied && !rolling && !back {
                return Ok(("applied", current_state, None));
            }
            let places = placements(active, tx, &intent)?;
            if !rolling
                && !back
                && places.skill == Placement::Before
                && places.receipt == Placement::Before
            {
                Ok(("prepared", current_state, None))
            } else {
                Ok((
                    "recovery_required",
                    current_state,
                    Some(if rolling {
                        "rollback_incomplete"
                    } else {
                        "apply_incomplete"
                    }),
                ))
            }
        };
        match classify() {
            Ok((state, current_state, code)) => {
                result.state = state;
                result.current_state = current_state;
                result.error_code = code;
            }
            Err(e) => result.error_code = Some(e.code),
        }
        result
    }
    pub(super) fn result(agent: &str, root: &Path, id: &str) -> Result<SkillUpdateResult> {
        let (target, active, name) = locate(agent, root, id)?;
        let tx = Directory::open(&active.path.join(name))?;
        Ok(observation(&target, &active, &tx, agent, id))
    }

    fn version_upgrade(old: &str, new: &str) -> Result<()> {
        let old = semver::Version::parse(old).map_err(|_| error("invalid_version"))?;
        let new = semver::Version::parse(new).map_err(|_| error("invalid_version"))?;
        match new.cmp_precedence(&old) {
            std::cmp::Ordering::Greater => Ok(()),
            std::cmp::Ordering::Equal => Err(error("version_conflict")),
            std::cmp::Ordering::Less => Err(error("downgrade")),
        }
    }
    fn prepare(
        agent: &str,
        target: &Target,
        active: &Directory,
        bundle: &str,
        version: &str,
        staging: &Path,
        id: &str,
        name: &str,
        expected: Option<&BaselineBinding>,
        checkpoint: &mut impl FnMut(Step) -> Result<()>,
    ) -> Result<Directory> {
        if bundle.len() as u64 > MAX_SKILL_BYTES {
            return Err(error("bundle_too_large"));
        }
        let skill = active.read("SKILL.md", MAX_SKILL_BYTES)?;
        let receipt = active.read(ENROLLMENT_FILE, LIMIT)?;
        let (baseline, bytes) = read_receipt(target, agent)?;
        if receipt.bytes != bytes {
            return Err(error("receipt_changed"));
        }
        if baseline.enrolled_sha256 != skill.record.sha256 {
            return Err(error("installed_modified"));
        }
        if skill.bytes == bundle.as_bytes() {
            return Err(error("already_current"));
        }
        version_upgrade(&baseline.enrolled_version, version)?;
        let staged = Directory::open(staging)?;
        let candidate = staged.read("SKILL.md", MAX_SKILL_BYTES)?;
        let staged_receipt = staged.read(STAGED_RECEIPT_FILE, LIMIT)?;
        let stage: StageReceipt = serde_json::from_slice(&staged_receipt.bytes)
            .map_err(|_| error("invalid_staged_receipt"))?;
        if stage.schema_version != 1
            || stage.kind != "sniper_staged_skill_update"
            || stage.agent != agent
            || stage.path != target.path_text
            || stage.enrollment_receipt_sha256 != receipt.record.sha256
            || stage.installed_sha256 != skill.record.sha256
            || stage.bundled_sha256 != sha256(bundle.as_bytes())
            || stage.bundled_version != version
            || stage.candidate_file != "SKILL.md"
            || stage.activated
            || stage.allows_automatic_updates
        {
            return Err(error("invalid_staged_receipt"));
        }
        if candidate.bytes != bundle.as_bytes() {
            return Err(error("candidate_changed"));
        }
        if let Some(expected) = expected {
            if &baseline_from_observed(active, target, agent, &skill, &receipt)? != expected {
                return Err(error("baseline_changed"));
            }
        }
        let updated = EnrollmentReceipt {
            schema_version: 2,
            kind: "sniper_skill_enrollment".into(),
            agent: agent.into(),
            path: target.path_text.clone(),
            enrolled_sha256: sha256(bundle.as_bytes()),
            enrolled_version: version.into(),
            allows_automatic_updates: false,
            source: Some("bundled_binary".into()),
            contract_revision: Some(1),
            last_operation_id: Some(id.into()),
        };
        let updated_bytes = encode_receipt(&updated)?;
        // Sync the exact originals before preserving them by exchange. A copy made
        // here would not capture an editor's later save; the swap below does.
        sync_file(&skill.file, "file_sync")?;
        sync_file(&receipt.file, "file_sync")?;
        let tx = active.child_new(name)?;
        checkpoint(Step::DirectoryCreated)?;
        let new_skill = tx.write_new(SKILL_SLOT, bundle.as_bytes(), skill.record.mode)?;
        checkpoint(Step::SkillPrepared)?;
        let new_receipt = tx.write_new(RECEIPT_SLOT, &updated_bytes, receipt.record.mode)?;
        checkpoint(Step::ReceiptPrepared)?;
        if new_skill.record.gid != skill.record.gid || new_receipt.record.gid != receipt.record.gid
        {
            return Err(error("metadata_unsupported"));
        }
        let intent = Intent {
            schema_version: 1,
            kind: "sniper_skill_activation".into(),
            agent: agent.into(),
            path: target.path_text.clone(),
            operation_id: id.into(),
            staging_dir: path_text(staging)?,
            bundle_version: version.into(),
            old_version: baseline.enrolled_version,
            old_skill: skill.record,
            new_skill: new_skill.record,
            old_receipt: receipt.record,
            new_receipt: new_receipt.record,
        };
        tx.write_new(MANIFEST, &encode_receipt(&intent)?, 0o600)?;
        checkpoint(Step::IntentWritten)?;
        sync_pair(active, &tx)?;
        Ok(tx)
    }
    pub(super) fn apply(
        agent: &str,
        root: &Path,
        bundle: &str,
        version: &str,
        staging: &Path,
        id: &str,
        checkpoint: impl FnMut(Step) -> Result<()>,
    ) -> Result<SkillUpdateResult> {
        apply_checked(agent, root, bundle, version, staging, id, None, checkpoint)
            .map(|(result, _)| result)
    }
    pub(super) fn apply_automatic(
        agent: &str,
        root: &Path,
        bundle: &str,
        version: &str,
        staging: &Path,
        id: &str,
        expected: &BaselineBinding,
        checkpoint: impl FnMut(Step) -> Result<()>,
    ) -> Result<AutomaticUpdateResult> {
        let (result, committed_baseline) = apply_checked(
            agent,
            root,
            bundle,
            version,
            staging,
            id,
            Some(expected),
            checkpoint,
        )?;
        Ok(AutomaticUpdateResult {
            result,
            committed_baseline: committed_baseline.ok_or_else(|| error("recovery_required"))?,
        })
    }
    fn apply_checked(
        agent: &str,
        root: &Path,
        bundle: &str,
        version: &str,
        staging: &Path,
        id: &str,
        expected: Option<&BaselineBinding>,
        mut checkpoint: impl FnMut(Step) -> Result<()>,
    ) -> Result<(SkillUpdateResult, Option<BaselineBinding>)> {
        // Validate the public library API as strictly as the CLI's embedded inputs.
        target(agent, root, bundle, version)?;
        let (target, active, name) = locate(agent, root, id)?;
        active.lock()?;
        if let Some(expected) = expected {
            // Refuse stale authority or any prior operation before pending()
            // is allowed to fsync historical markers. Never resume automatically.
            if active.exists(&name)? {
                return Err(error("operation_exists"));
            }
            if &baseline_locked(&active, &target, agent)? != expected {
                return Err(error("baseline_changed"));
            }
            checkpoint(Step::BaselineValidated)?;
        }
        pending(&active, &target, agent, Some(id))?;
        let exists = active.exists(&name)?;
        if expected.is_some() && exists {
            return Err(error("operation_exists"));
        }
        let staging = if exists {
            std::path::absolute(staging).map_err(io_error)?
        } else {
            stage_path(staging, &active)?
        };
        let tx = if exists {
            Directory::open(&active.path.join(&name))?
        } else {
            prepare(
                agent,
                &target,
                &active,
                bundle,
                version,
                &staging,
                id,
                &name,
                expected,
                &mut checkpoint,
            )?
        };
        let mut resume = || -> Result<SkillUpdateResult> {
            let intent = load_intent(&tx, &target, agent, id)?;
            if intent.staging_dir != path_text(&staging)?
                || intent.bundle_version != version
                || intent.new_skill.sha256 != sha256(bundle.as_bytes())
                || intent.new_skill.size != bundle.len() as u64
            {
                return Err(error("request_conflict"));
            }
            if marker(&tx, id, ROLLED_BACK)? {
                return Err(error("already_rolled_back"));
            }
            if marker(&tx, id, ROLLBACK)? {
                return Err(error("rollback_in_progress"));
            }
            if marker(&tx, id, APPLIED)? {
                // Historical outcome replay never changes active placement, but
                // resyncs visible journal bytes before acknowledging the retry.
                publish_marker(&tx, id, APPLIED)?;
                sync_pair(&active, &tx)?;
                return Ok(observation(&target, &active, &tx, agent, id));
            }
            checkpoint(Step::Prepared)?;
            establish_durability(&active, &tx)?;
            let mut placement = placements(&active, &tx, &intent)?;
            if placement.skill == Placement::Before && placement.receipt == Placement::After {
                return Err(error("transaction_changed"));
            }
            if placement.skill == Placement::Before {
                checkpoint(Step::BeforeSkillSwap)?;
                exchange(&active, "SKILL.md", &tx, SKILL_SLOT)?;
                checkpoint(Step::SkillSwapped)?;
                sync_pair(&active, &tx)?;
                checkpoint(Step::SkillSynced)?;
                placement = placements(&active, &tx, &intent)?;
                if placement.skill != Placement::After || placement.receipt != Placement::Before {
                    return Err(error("transaction_changed"));
                }
            }
            if placement.receipt == Placement::Before {
                checkpoint(Step::BeforeReceiptSwap)?;
                exchange(&active, ENROLLMENT_FILE, &tx, RECEIPT_SLOT)?;
                checkpoint(Step::ReceiptSwapped)?;
                sync_pair(&active, &tx)?;
                checkpoint(Step::ReceiptSynced)?;
            }
            let placement = placements(&active, &tx, &intent)?;
            if placement.skill != Placement::After || placement.receipt != Placement::After {
                return Err(error("transaction_changed"));
            }
            // Re-sync on resume too: visible placement alone is not proof a prior
            // process completed its durability checks.
            sync_pair(&active, &tx)?;
            publish_marker(&tx, id, APPLIED)?;
            checkpoint(Step::AppliedRecorded)?;
            Ok(observation(&target, &active, &tx, agent, id))
        };
        let result = match resume() {
            Ok(v) => Ok(v),
            Err(e)
                if matches!(
                    e.code,
                    "request_conflict"
                        | "already_rolled_back"
                        | "rollback_in_progress"
                        | "swap_unsupported"
                ) =>
            {
                Err(e)
            }
            Err(_) => Err(error("recovery_required")),
        }?;
        let committed_baseline = if expected.is_some() {
            let checked = || -> Result<BaselineBinding> {
                let intent = load_intent(&tx, &target, agent, id)?;
                let committed = baseline_locked(&active, &target, agent)?;
                let placement = placements(&active, &tx, &intent)?;
                if result.state != "applied"
                    || result.current_state != "updated"
                    || result.error_code.is_some()
                    || placement.skill != Placement::After
                    || placement.receipt != Placement::After
                    || committed.skill != intent.new_skill
                    || committed.receipt != intent.new_receipt
                    || committed.enrolled_version != intent.bundle_version
                    || committed.directory != expected.unwrap().directory
                {
                    return Err(error("transaction_changed"));
                }
                Ok(committed)
            };
            Some(checked().map_err(|_| error("recovery_required"))?)
        } else {
            None
        };
        Ok((result, committed_baseline))
    }
    pub(super) fn rollback(
        agent: &str,
        root: &Path,
        id: &str,
        mut checkpoint: impl FnMut(Step) -> Result<()>,
    ) -> Result<SkillUpdateResult> {
        let (target, active, name) = locate(agent, root, id)?;
        active.lock()?;
        pending(&active, &target, agent, Some(id))?;
        let tx = Directory::open(&active.path.join(name))?;
        let mut reverse = || -> Result<SkillUpdateResult> {
            let intent = load_intent(&tx, &target, agent, id)?;
            marker(&tx, id, APPLIED)?;
            let rolling = marker(&tx, id, ROLLBACK)?;
            if marker(&tx, id, ROLLED_BACK)? {
                if !rolling {
                    return Err(error("invalid_journal"));
                }
                publish_marker(&tx, id, ROLLED_BACK)?;
                sync_pair(&active, &tx)?;
                return Ok(observation(&target, &active, &tx, agent, id));
            }
            // Validate before journaling a rollback, then again after the durable
            // intent. The actual displaced object is verified after each swap.
            let p = placements(&active, &tx, &intent)?;
            if p.skill == Placement::Before && p.receipt == Placement::After {
                return Err(error("transaction_changed"));
            }
            establish_durability(&active, &tx)?;
            publish_marker(&tx, id, ROLLBACK)?;
            checkpoint(Step::RollbackRecorded)?;
            let mut p = placements(&active, &tx, &intent)?;
            if p.receipt == Placement::After {
                checkpoint(Step::BeforeReceiptRestore)?;
                exchange(&active, ENROLLMENT_FILE, &tx, RECEIPT_SLOT)?;
                checkpoint(Step::ReceiptRestored)?;
                sync_pair(&active, &tx)?;
                p = placements(&active, &tx, &intent)?;
                if p.receipt != Placement::Before || p.skill != Placement::After {
                    return Err(error("transaction_changed"));
                }
            }
            if p.skill == Placement::After {
                checkpoint(Step::BeforeSkillRestore)?;
                exchange(&active, "SKILL.md", &tx, SKILL_SLOT)?;
                checkpoint(Step::SkillRestored)?;
                sync_pair(&active, &tx)?;
            }
            let p = placements(&active, &tx, &intent)?;
            if p.skill != Placement::Before || p.receipt != Placement::Before {
                return Err(error("transaction_changed"));
            }
            sync_pair(&active, &tx)?;
            publish_marker(&tx, id, ROLLED_BACK)?;
            checkpoint(Step::RolledBackRecorded)?;
            Ok(observation(&target, &active, &tx, agent, id))
        };
        reverse().map_err(|e| {
            if e.code == "swap_unsupported" {
                e
            } else {
                error("recovery_required")
            }
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::skill_managed::{
            enroll_skill, preview_skill_update, stage_skill_update, ManagedSkillState,
        };
        use serde_json::{json, Value};
        use std::{
            os::unix::fs::{symlink, PermissionsExt},
            process::Command,
        };

        const OLD: &str = "synthetic skill baseline\n";
        const NEW: &str = "synthetic skill bundle next\n";
        const OLD_VERSION: &str = "1.0.0";
        const NEW_VERSION: &str = "2.0.0";
        struct Fixture {
            home: PathBuf,
            id: String,
        }
        impl Fixture {
            fn empty() -> Self {
                let base = fs::canonicalize(std::env::temp_dir()).unwrap();
                Self {
                    home: base.join(format!("sniper-skill-activation-{}", uuid::Uuid::new_v4())),
                    id: uuid::Uuid::new_v4().to_string(),
                }
            }
            fn new() -> Self {
                let f = Self::empty();
                fs::create_dir_all(f.dir()).unwrap();
                fs::write(f.skill(), OLD).unwrap();
                enroll_skill("codex", &f.root(), OLD, OLD_VERSION).unwrap();
                f.stage(NEW_VERSION);
                f
            }
            fn root(&self) -> PathBuf {
                self.home.join("skills")
            }
            fn dir(&self) -> PathBuf {
                self.root().join("sniper-operator")
            }
            fn skill(&self) -> PathBuf {
                self.dir().join("SKILL.md")
            }
            fn receipt(&self) -> PathBuf {
                self.dir().join(ENROLLMENT_FILE)
            }
            fn staged(&self) -> PathBuf {
                self.home.join("candidate")
            }
            fn tx(&self) -> PathBuf {
                self.dir().join(format!("{PREFIX}{}", self.id))
            }
            fn stage(&self, version: &str) {
                stage_skill_update("codex", &self.root(), NEW, version, &self.staged()).unwrap();
            }
            fn apply(&self) -> Result<SkillUpdateResult> {
                apply(
                    "codex",
                    &self.root(),
                    NEW,
                    NEW_VERSION,
                    &self.staged(),
                    &self.id,
                    |_| Ok(()),
                )
            }
            fn at(&self, stop: Step) -> Result<SkillUpdateResult> {
                apply(
                    "codex",
                    &self.root(),
                    NEW,
                    NEW_VERSION,
                    &self.staged(),
                    &self.id,
                    |step| {
                        if step == stop {
                            Err(error("injected"))
                        } else {
                            Ok(())
                        }
                    },
                )
            }
            fn back(&self) -> Result<SkillUpdateResult> {
                rollback("codex", &self.root(), &self.id, |_| Ok(()))
            }
            fn result(&self) -> SkillUpdateResult {
                result("codex", &self.root(), &self.id).unwrap()
            }
            fn baseline(&self) {
                assert_eq!(fs::read(self.skill()).unwrap(), OLD.as_bytes());
            }
            fn edit_json(&self, path: &Path, edit: impl FnOnce(&mut Value)) {
                let mut value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
                edit(&mut value);
                fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.home);
            }
        }

        fn automatic(f: &Fixture, expected: &BaselineBinding) -> Result<AutomaticUpdateResult> {
            apply_automatic_skill_update(
                "codex",
                &f.root(),
                NEW,
                NEW_VERSION,
                &f.staged(),
                &f.id,
                expected,
            )
        }
        #[test]
        fn automatic_baseline_inspection_is_strict_and_never_syncs() {
            let f = Fixture::new();
            for kind in ["file_sync", "directory_sync", "write", "swap"] {
                fault(kind, 1);
                let baseline = inspect_automatic_baseline("codex", &f.root()).unwrap();
                assert_eq!(baseline.installed_sha256, sha256(OLD.as_bytes()));
                assert_eq!(baseline.enrolled_version, OLD_VERSION);
                assert_eq!(clear_fault(), 0);
            }
            f.apply().unwrap();
            // Even a terminal marker is only observed, not fsynced by inspection.
            fault("file_sync", 1);
            inspect_automatic_baseline("codex", &f.root()).unwrap();
            assert_eq!(clear_fault(), 0);
            fs::write(f.skill(), "synthetic edit").unwrap();
            assert_eq!(
                inspect_automatic_baseline("codex", &f.root())
                    .unwrap_err()
                    .code,
                "installed_modified"
            );
        }
        #[test]
        fn automatic_apply_returns_checked_baseline_and_never_replays_an_id() {
            let f = Fixture::new();
            let baseline = inspect_automatic_baseline("codex", &f.root()).unwrap();
            let outcome = automatic(&f, &baseline).unwrap();
            assert_eq!(outcome.result.state, "applied");
            assert_eq!(outcome.result.current_state, "updated");
            assert_eq!(
                outcome.committed_baseline,
                inspect_automatic_baseline("codex", &f.root()).unwrap()
            );
            assert_ne!(
                outcome.committed_baseline.history_sha256,
                baseline.history_sha256
            );
            assert_eq!(outcome.committed_baseline.directory, baseline.directory);
            fault("file_sync", 1);
            assert_eq!(
                automatic(&f, &outcome.committed_baseline).unwrap_err().code,
                "operation_exists"
            );
            assert_eq!(clear_fault(), 0);
            // The explicit interface still supports historical idempotent replay.
            assert_eq!(f.apply().unwrap().state, "applied");
        }
        #[test]
        fn automatic_completion_requires_exact_current_terminal_transaction_without_sync() {
            let f = Fixture::new();
            let baseline = inspect_automatic_baseline("codex", &f.root()).unwrap();
            let committed = automatic(&f, &baseline).unwrap().committed_baseline;
            let hash = sha256(NEW.as_bytes());
            for kind in ["file_sync", "directory_sync", "write", "swap"] {
                fault(kind, 1);
                inspect_automatic_completion(
                    "codex",
                    &f.root(),
                    &committed,
                    &f.id,
                    NEW_VERSION,
                    &hash,
                )
                .unwrap();
                assert!(inspect_automatic_completion(
                    "codex",
                    &f.root(),
                    &committed,
                    &f.id,
                    OLD_VERSION,
                    &hash
                )
                .is_err());
                assert!(inspect_automatic_completion(
                    "codex",
                    &f.root(),
                    &committed,
                    &f.id,
                    NEW_VERSION,
                    &sha256(OLD.as_bytes())
                )
                .is_err());
                assert!(inspect_automatic_completion(
                    "codex",
                    &f.root(),
                    &committed,
                    &uuid::Uuid::new_v4().to_string(),
                    NEW_VERSION,
                    &hash
                )
                .is_err());
                assert_eq!(clear_fault(), 0);
            }
            f.back().unwrap();
            let rolled_back = inspect_automatic_baseline("codex", &f.root()).unwrap();
            assert!(inspect_automatic_completion(
                "codex",
                &f.root(),
                &rolled_back,
                &f.id,
                NEW_VERSION,
                &hash
            )
            .is_err());
        }
        #[test]
        fn automatic_completion_validates_retained_placement_not_only_terminal_marker() {
            let f = Fixture::new();
            let baseline = inspect_automatic_baseline("codex", &f.root()).unwrap();
            let committed = automatic(&f, &baseline).unwrap().committed_baseline;
            fs::write(f.tx().join(SKILL_SLOT), "synthetic changed retained object").unwrap();
            assert_eq!(
                inspect_automatic_baseline("codex", &f.root()).unwrap(),
                committed
            );
            fault("file_sync", 1);
            assert!(inspect_automatic_completion(
                "codex",
                &f.root(),
                &committed,
                &f.id,
                NEW_VERSION,
                &sha256(NEW.as_bytes())
            )
            .is_err());
            assert_eq!(clear_fault(), 0);
            assert_eq!(fs::read(f.skill()).unwrap(), NEW.as_bytes());
        }
        #[test]
        fn automatic_baseline_rejects_same_bytes_on_replaced_objects_before_io() {
            for target in 0..3 {
                let f = Fixture::new();
                let expected = inspect_automatic_baseline("codex", &f.root()).unwrap();
                if target == 2 {
                    fs::rename(f.dir(), f.home.join("retained-directory")).unwrap();
                    fs::create_dir(f.dir()).unwrap();
                    fs::copy(f.home.join("retained-directory/SKILL.md"), f.skill()).unwrap();
                    fs::copy(
                        f.home.join("retained-directory").join(ENROLLMENT_FILE),
                        f.receipt(),
                    )
                    .unwrap();
                } else {
                    let path = if target == 0 { f.skill() } else { f.receipt() };
                    let replacement = f.home.join("replacement");
                    fs::copy(&path, &replacement).unwrap();
                    fs::rename(&replacement, &path).unwrap();
                }
                fault("file_sync", 1);
                assert_eq!(
                    automatic(&f, &expected).unwrap_err().code,
                    "baseline_changed"
                );
                assert_eq!(clear_fault(), 0);
                assert!(!f.tx().exists());
                f.baseline();
            }
        }
        #[test]
        fn automatic_history_detects_explicit_apply_then_rollback() {
            let f = Fixture::new();
            let expected = inspect_automatic_baseline("codex", &f.root()).unwrap();
            f.apply().unwrap();
            f.back().unwrap();
            let after = inspect_automatic_baseline("codex", &f.root()).unwrap();
            assert_eq!(after.skill, expected.skill);
            assert_eq!(after.receipt, expected.receipt);
            assert_ne!(after.history_sha256, expected.history_sha256);
            let new_id = uuid::Uuid::new_v4().to_string();
            fault("file_sync", 1);
            assert_eq!(
                apply_automatic_skill_update(
                    "codex",
                    &f.root(),
                    NEW,
                    NEW_VERSION,
                    &f.staged(),
                    &new_id,
                    &expected
                )
                .unwrap_err()
                .code,
                "baseline_changed"
            );
            assert_eq!(clear_fault(), 0);
            assert!(!f.dir().join(format!("{PREFIX}{new_id}")).exists());
        }
        #[test]
        fn automatic_capture_rejects_partial_and_malformed_journals_without_sync() {
            for malformed in [false, true] {
                let f = Fixture::new();
                if malformed {
                    f.apply().unwrap();
                    fs::write(f.tx().join(APPLIED), b"{").unwrap();
                } else {
                    f.at(Step::Prepared).unwrap_err();
                }
                fault("file_sync", 1);
                assert_eq!(
                    inspect_automatic_baseline("codex", &f.root())
                        .unwrap_err()
                        .code,
                    "pending_transaction"
                );
                assert_eq!(clear_fault(), 0);
            }
        }
        #[test]
        fn non_utf8_transaction_suffix_is_retained_or_refused_by_filesystem() {
            use std::os::unix::ffi::OsStringExt;
            let f = Fixture::new();
            let before = inspect_automatic_baseline("codex", &f.root()).unwrap();
            let malformed = f.dir().join(std::ffi::OsString::from_vec(
                b".sniper-update-\xff".to_vec(),
            ));
            let unrelated = f
                .dir()
                .join(std::ffi::OsString::from_vec(b"unrelated-\xff".to_vec()));
            if let Err(error) = fs::write(&unrelated, b"synthetic") {
                #[cfg(target_os = "macos")]
                if error.raw_os_error() == Some(libc::EILSEQ) {
                    // APFS can reject these names before the scanner sees them.
                    // Prove the dangerous prefix is equally unrepresentable;
                    // every other error and every supporting filesystem still
                    // exercises the retained-artifact refusal below.
                    assert_eq!(
                        fs::create_dir(&malformed).unwrap_err().raw_os_error(),
                        Some(libc::EILSEQ)
                    );
                    assert!(!unrelated.exists());
                    assert!(!malformed.exists());
                    assert_eq!(
                        inspect_automatic_baseline("codex", &f.root()).unwrap(),
                        before
                    );
                    f.baseline();
                    assert!(!f.tx().exists());
                    return;
                }
                panic!("could not create raw-filename fixture: {error}");
            }
            let baseline = inspect_automatic_baseline("codex", &f.root()).unwrap();
            assert_eq!(baseline, before);
            fs::create_dir(&malformed).unwrap();
            fault("file_sync", 1);
            assert_eq!(
                inspect_automatic_baseline("codex", &f.root())
                    .unwrap_err()
                    .code,
                "pending_transaction"
            );
            assert_eq!(
                automatic(&f, &baseline).unwrap_err().code,
                "pending_transaction"
            );
            assert_eq!(clear_fault(), 0);
            assert!(malformed.is_dir());
            assert!(!f.tx().exists());
            f.baseline();
        }
        #[test]
        fn automatic_prepare_rechecks_the_authorized_snapshot_before_first_write() {
            let f = Fixture::new();
            let expected = inspect_automatic_baseline("codex", &f.root()).unwrap();
            fault("file_sync", 1);
            let result = apply_automatic(
                "codex",
                &f.root(),
                NEW,
                NEW_VERSION,
                &f.staged(),
                &f.id,
                &expected,
                |step| {
                    if step == Step::BaselineValidated {
                        let replacement = f.home.join("same-byte-replacement");
                        fs::copy(f.skill(), &replacement).unwrap();
                        fs::rename(replacement, f.skill()).unwrap();
                    }
                    Ok(())
                },
            );
            assert_eq!(result.unwrap_err().code, "baseline_changed");
            assert_eq!(clear_fault(), 0);
            assert!(!f.tx().exists());
            f.baseline();
        }
        #[test]
        fn automatic_apply_refuses_a_transaction_created_after_its_first_check() {
            let f = Fixture::new();
            let expected = inspect_automatic_baseline("codex", &f.root()).unwrap();
            fault("file_sync", 1);
            let result = apply_automatic(
                "codex",
                &f.root(),
                NEW,
                NEW_VERSION,
                &f.staged(),
                &f.id,
                &expected,
                |step| {
                    if step == Step::BaselineValidated {
                        fs::create_dir(f.tx()).unwrap();
                    }
                    Ok(())
                },
            );
            assert_eq!(result.unwrap_err().code, "operation_exists");
            assert_eq!(clear_fault(), 0);
            assert_eq!(fs::read_dir(f.tx()).unwrap().count(), 0);
            f.baseline();
        }
        #[test]
        fn automatic_committed_result_refuses_an_editor_change_after_publication() {
            let f = Fixture::new();
            let expected = inspect_automatic_baseline("codex", &f.root()).unwrap();
            let result = apply_automatic(
                "codex",
                &f.root(),
                NEW,
                NEW_VERSION,
                &f.staged(),
                &f.id,
                &expected,
                |step| {
                    if step == Step::AppliedRecorded {
                        fs::write(f.skill(), "synthetic later editor save").unwrap();
                    }
                    Ok(())
                },
            );
            assert_eq!(result.unwrap_err().code, "recovery_required");
            assert_eq!(fs::read(f.skill()).unwrap(), b"synthetic later editor save");
            assert_eq!(fs::read(f.tx().join(SKILL_SLOT)).unwrap(), OLD.as_bytes());
            assert_eq!(f.result().state, "applied");
            assert_eq!(f.result().current_state, "changed");
        }
        #[test]
        fn automatic_test_hook_interrupts_each_swap_boundary_without_enabling_resume() {
            for point in [
                AutomaticTestCheckpoint::BeforeSkillSwap,
                AutomaticTestCheckpoint::AfterSkillSwap,
                AutomaticTestCheckpoint::BeforeReceiptSwap,
                AutomaticTestCheckpoint::AfterReceiptSwap,
            ] {
                let f = Fixture::new();
                let baseline = inspect_automatic_baseline("codex", &f.root()).unwrap();
                set_automatic_test_failure(Some(point));
                let interrupted = automatic(&f, &baseline);
                set_automatic_test_failure(None);
                assert_eq!(interrupted.unwrap_err().code, "recovery_required");
                assert_eq!(
                    automatic(&f, &baseline).unwrap_err().code,
                    "operation_exists"
                );
                assert_eq!(f.back().unwrap().state, "rolled_back");
                f.baseline();
            }
        }

        #[test]
        fn canonical_operation_ids_only() {
            let id = uuid::Uuid::new_v4().to_string();
            assert!(valid_operation_id(&id));
            for value in [
                id.to_uppercase(),
                id.replace('-', ""),
                format!("{{{id}}}"),
                format!(" {id}"),
                "../bad".into(),
            ] {
                assert!(!valid_operation_id(&value));
            }
        }
        #[test]
        fn apply_result_idempotency_and_exact_object_rollback() {
            let f = Fixture::new();
            let original = fs::metadata(f.skill()).unwrap();
            let receipt = fs::read(f.receipt()).unwrap();
            let receipt_meta = fs::metadata(f.receipt()).unwrap();
            let result = f.apply().unwrap();
            assert_eq!((result.state, result.current_state), ("applied", "updated"));
            assert!(!result.agent_reloaded && !result.allows_automatic_updates);
            assert_eq!(fs::read(f.skill()).unwrap(), NEW.as_bytes());
            assert_eq!(
                fs::metadata(f.tx().join(SKILL_SLOT)).unwrap().ino(),
                original.ino()
            );
            assert_eq!(
                fs::metadata(f.tx().join(RECEIPT_SLOT)).unwrap().ino(),
                receipt_meta.ino()
            );
            assert_eq!(fs::read(f.tx().join(RECEIPT_SLOT)).unwrap(), receipt);
            let enrolled: Value = serde_json::from_slice(&fs::read(f.receipt()).unwrap()).unwrap();
            assert_eq!(enrolled["schema_version"], 2);
            assert_eq!(enrolled["last_operation_id"], f.id);
            assert_eq!(enrolled["allows_automatic_updates"], false);
            assert_eq!(
                preview_skill_update("codex", &f.root(), NEW, NEW_VERSION)
                    .unwrap()
                    .state,
                ManagedSkillState::Current
            );
            assert_eq!(f.result().state, "applied");
            let new_ino = fs::metadata(f.skill()).unwrap().ino();
            assert_eq!(f.apply().unwrap().state, "applied");
            assert_eq!(fs::metadata(f.skill()).unwrap().ino(), new_ino);
            assert_eq!(f.back().unwrap().state, "rolled_back");
            f.baseline();
            assert_eq!(fs::metadata(f.skill()).unwrap().ino(), original.ino());
            assert_eq!(fs::read(f.receipt()).unwrap(), receipt);
            assert_eq!(fs::metadata(f.receipt()).unwrap().ino(), receipt_meta.ino());
            assert_eq!(f.back().unwrap().state, "rolled_back");
            assert_eq!(f.apply().unwrap_err().code, "already_rolled_back");
            assert_eq!(
                fs::read(f.staged().join("SKILL.md")).unwrap(),
                NEW.as_bytes()
            );
        }
        #[test]
        fn same_precedence_and_downgrades_refuse_before_transaction() {
            for version in ["1.0.0", "1.0.0+other", "0.9.0", "1.0.0-rc.1"] {
                let f = Fixture::new();
                let error = apply("codex", &f.root(), NEW, version, &f.staged(), &f.id, |_| {
                    Ok(())
                })
                .unwrap_err();
                assert_eq!(
                    error.code,
                    if version.starts_with("1.0.0") && !version.contains('-') {
                        "version_conflict"
                    } else {
                        "downgrade"
                    }
                );
                f.baseline();
                assert!(!f.tx().exists());
            }
        }
        #[test]
        fn successful_id_is_bound_to_exact_request_and_binary() {
            let f = Fixture::new();
            f.apply().unwrap();
            assert_eq!(
                apply(
                    "codex",
                    &f.root(),
                    "different",
                    NEW_VERSION,
                    &f.staged(),
                    &f.id,
                    |_| Ok(())
                )
                .unwrap_err()
                .code,
                "request_conflict"
            );
            assert_eq!(
                apply(
                    "codex",
                    &f.root(),
                    NEW,
                    "2.0.1",
                    &f.staged(),
                    &f.id,
                    |_| Ok(())
                )
                .unwrap_err()
                .code,
                "request_conflict"
            );
            let other = f.home.join("other");
            fs::create_dir(&other).unwrap();
            assert_eq!(
                apply("codex", &f.root(), NEW, NEW_VERSION, &other, &f.id, |_| Ok(
                    ()
                ))
                .unwrap_err()
                .code,
                "request_conflict"
            );
            assert_eq!(
                result("claude", &f.root(), &f.id).unwrap().state,
                "recovery_required"
            );
        }
        #[test]
        fn all_durable_apply_interruption_points_resume_or_rollback() {
            for stop in [
                Step::IntentWritten,
                Step::Prepared,
                Step::BeforeSkillSwap,
                Step::SkillSwapped,
                Step::SkillSynced,
                Step::BeforeReceiptSwap,
                Step::ReceiptSwapped,
                Step::ReceiptSynced,
                Step::AppliedRecorded,
            ] {
                for reverse in [false, true] {
                    let f = Fixture::new();
                    assert!(f.at(stop).is_err(), "{stop:?}");
                    let r = if reverse { f.back() } else { f.apply() }
                        .unwrap_or_else(|e| panic!("{stop:?}, rollback={reverse}: {e}"));
                    assert_eq!(r.state, if reverse { "rolled_back" } else { "applied" });
                    assert_eq!(
                        fs::read(f.skill()).unwrap(),
                        if reverse {
                            OLD.as_bytes()
                        } else {
                            NEW.as_bytes()
                        }
                    );
                }
            }
        }
        #[test]
        fn all_rollback_interruption_points_resume_without_forward_swap() {
            for stop in [
                Step::RollbackRecorded,
                Step::BeforeReceiptRestore,
                Step::ReceiptRestored,
                Step::BeforeSkillRestore,
                Step::SkillRestored,
                Step::RolledBackRecorded,
            ] {
                let f = Fixture::new();
                f.apply().unwrap();
                assert_eq!(
                    rollback("codex", &f.root(), &f.id, |step| if step == stop {
                        Err(error("injected"))
                    } else {
                        Ok(())
                    })
                    .unwrap_err()
                    .code,
                    "recovery_required"
                );
                if stop != Step::RolledBackRecorded {
                    assert_eq!(f.apply().unwrap_err().code, "rollback_in_progress");
                }
                assert_eq!(f.back().unwrap().state, "rolled_back");
                f.baseline();
            }
        }
        #[test]
        fn incomplete_preparation_preserves_active_and_blocks_all_managed_writes() {
            for stop in [
                Step::DirectoryCreated,
                Step::SkillPrepared,
                Step::ReceiptPrepared,
            ] {
                let f = Fixture::new();
                assert_eq!(f.at(stop).unwrap_err().code, "injected");
                f.baseline();
                assert_eq!(f.result().state, "recovery_required");
                assert_eq!(f.apply().unwrap_err().code, "recovery_required");
                assert_eq!(f.back().unwrap_err().code, "recovery_required");
                assert_eq!(
                    enroll_skill("codex", &f.root(), OLD, OLD_VERSION)
                        .unwrap_err()
                        .code,
                    "pending_transaction"
                );
                assert_eq!(
                    stage_skill_update(
                        "codex",
                        &f.root(),
                        NEW,
                        NEW_VERSION,
                        &f.home.join("next-stage")
                    )
                    .unwrap_err()
                    .code,
                    "pending_transaction"
                );
                assert_eq!(
                    apply(
                        "codex",
                        &f.root(),
                        NEW,
                        NEW_VERSION,
                        &f.staged(),
                        &uuid::Uuid::new_v4().to_string(),
                        |_| Ok(())
                    )
                    .unwrap_err()
                    .code,
                    "pending_transaction"
                );
            }
        }
        #[test]
        fn last_check_to_swap_editor_save_is_retained_and_never_auto_reversed() {
            for replacement in [false, true] {
                let f = Fixture::new();
                let result = apply(
                    "codex",
                    &f.root(),
                    NEW,
                    NEW_VERSION,
                    &f.staged(),
                    &f.id,
                    |step| {
                        if step == Step::BeforeSkillSwap {
                            if replacement {
                                let p = f.home.join("saved");
                                fs::write(&p, "editor latest").unwrap();
                                fs::rename(p, f.skill()).unwrap();
                            } else {
                                fs::write(f.skill(), "editor latest").unwrap();
                            }
                        }
                        Ok(())
                    },
                );
                assert_eq!(result.unwrap_err().code, "recovery_required");
                assert_eq!(fs::read(f.skill()).unwrap(), NEW.as_bytes());
                assert_eq!(fs::read(f.tx().join(SKILL_SLOT)).unwrap(), b"editor latest");
                assert_eq!(f.result().state, "recovery_required");
                assert_eq!(f.back().unwrap_err().code, "recovery_required");
                assert_eq!(fs::read(f.tx().join(SKILL_SLOT)).unwrap(), b"editor latest");
            }
        }
        #[test]
        fn last_check_receipt_and_rollback_races_preserve_actual_displaced_objects() {
            let f = Fixture::new();
            assert_eq!(
                apply(
                    "codex",
                    &f.root(),
                    NEW,
                    NEW_VERSION,
                    &f.staged(),
                    &f.id,
                    |step| {
                        if step == Step::BeforeReceiptSwap {
                            fs::write(f.receipt(), "receipt latest").unwrap();
                        }
                        Ok(())
                    }
                )
                .unwrap_err()
                .code,
                "recovery_required"
            );
            assert_eq!(
                fs::read(f.tx().join(RECEIPT_SLOT)).unwrap(),
                b"receipt latest"
            );
            let f = Fixture::new();
            f.apply().unwrap();
            assert_eq!(
                rollback("codex", &f.root(), &f.id, |step| {
                    if step == Step::BeforeSkillRestore {
                        fs::write(f.skill(), "editor during rollback").unwrap();
                    }
                    Ok(())
                })
                .unwrap_err()
                .code,
                "recovery_required"
            );
            assert_eq!(
                fs::read(f.tx().join(SKILL_SLOT)).unwrap(),
                b"editor during rollback"
            );
            f.baseline();
            assert_eq!(f.result().state, "recovery_required");
        }
        #[test]
        fn completed_result_is_history_and_edited_targets_or_backups_are_not_restored() {
            for backup in [false, true] {
                let f = Fixture::new();
                f.apply().unwrap();
                fs::write(
                    if backup {
                        f.tx().join(SKILL_SLOT)
                    } else {
                        f.skill()
                    },
                    "edited",
                )
                .unwrap();
                let r = f.result();
                assert_eq!(r.state, "applied");
                assert_eq!(r.current_state, if backup { "updated" } else { "changed" });
                assert_eq!(f.back().unwrap_err().code, "recovery_required");
                assert_eq!(
                    fs::read(if backup {
                        f.tx().join(SKILL_SLOT)
                    } else {
                        f.skill()
                    })
                    .unwrap(),
                    b"edited"
                );
            }
        }
        #[test]
        fn staged_receipts_are_strict_and_candidate_must_be_exact_bundle() {
            for field in [
                "agent",
                "path",
                "enrollment_receipt_sha256",
                "installed_sha256",
                "bundled_sha256",
                "bundled_version",
                "candidate_file",
                "kind",
            ] {
                let f = Fixture::new();
                f.edit_json(&f.staged().join(STAGED_RECEIPT_FILE), |v| {
                    v[field] = json!("wrong")
                });
                assert_eq!(
                    f.apply().unwrap_err().code,
                    "invalid_staged_receipt",
                    "{field}"
                );
                f.baseline();
                assert!(!f.tx().exists());
            }
            for edit in [0, 1, 2, 3, 4] {
                let f = Fixture::new();
                let p = f.staged().join(STAGED_RECEIPT_FILE);
                match edit {
                    0 => f.edit_json(&p, |v| v["extra"] = json!(true)),
                    1 => f.edit_json(&p, |v| v["activated"] = json!(true)),
                    2 => f.edit_json(&p, |v| v["allows_automatic_updates"] = json!(true)),
                    3 => {
                        let s = fs::read_to_string(&p).unwrap().replacen(
                            '{',
                            "{\"schema_version\":1,",
                            1,
                        );
                        fs::write(&p, s).unwrap();
                    }
                    _ => fs::write(&p, vec![b'x'; LIMIT as usize + 1]).unwrap(),
                }
                assert!(f.apply().is_err());
                f.baseline();
                assert!(!f.tx().exists());
            }
            let f = Fixture::new();
            fs::write(f.staged().join("SKILL.md"), "opaque untrusted input").unwrap();
            assert_eq!(f.apply().unwrap_err().code, "candidate_changed");
            f.baseline();
        }
        #[test]
        fn links_nonregular_oversize_and_mode_changes_are_refused() {
            for target in [0, 1, 2, 3] {
                for kind in [0, 1, 2, 3] {
                    let f = Fixture::new();
                    let path = [
                        f.skill(),
                        f.receipt(),
                        f.staged().join("SKILL.md"),
                        f.staged().join(STAGED_RECEIPT_FILE),
                    ][target]
                        .clone();
                    let saved = f.home.join("saved");
                    fs::rename(&path, &saved).unwrap();
                    match kind {
                        0 => symlink(&saved, &path).unwrap(),
                        1 => {
                            fs::hard_link(&saved, &path).unwrap();
                        }
                        2 => fs::create_dir(&path).unwrap(),
                        _ => fs::write(&path, vec![b'x'; MAX_SKILL_BYTES as usize + 1]).unwrap(),
                    }
                    assert!(f.apply().is_err(), "target={target} kind={kind}");
                    assert!(!f.tx().exists());
                    assert!(saved.exists());
                }
            }
            let f = Fixture::new();
            fs::set_permissions(f.skill(), fs::Permissions::from_mode(0o666)).unwrap();
            assert_eq!(f.apply().unwrap_err().code, "unsafe_permissions");
        }
        #[test]
        fn lock_conflict_and_directory_replacement_fail_without_destructive_fallback() {
            let f = Fixture::new();
            let dir = Directory::open(&f.dir()).unwrap();
            dir.lock().unwrap();
            assert_eq!(f.apply().unwrap_err().code, "transaction_busy");
            assert_eq!(
                stage_skill_update("codex", &f.root(), NEW, NEW_VERSION, &f.home.join("new"))
                    .unwrap_err()
                    .code,
                "transaction_busy"
            );
            assert_eq!(
                enroll_skill("codex", &f.root(), OLD, OLD_VERSION)
                    .unwrap_err()
                    .code,
                "transaction_busy"
            );
            drop(dir);
            let old = f.home.join("moved-directory");
            assert_eq!(
                apply(
                    "codex",
                    &f.root(),
                    NEW,
                    NEW_VERSION,
                    &f.staged(),
                    &f.id,
                    |step| {
                        if step == Step::BeforeSkillSwap {
                            fs::rename(f.dir(), &old).unwrap();
                            fs::create_dir(f.dir()).unwrap();
                            fs::write(f.skill(), "replacement-dir").unwrap();
                        }
                        Ok(())
                    }
                )
                .unwrap_err()
                .code,
                "recovery_required"
            );
            assert_eq!(fs::read(old.join("SKILL.md")).unwrap(), OLD.as_bytes());
            assert_eq!(fs::read(f.skill()).unwrap(), b"replacement-dir");
        }
        #[test]
        fn malformed_journal_and_partial_marker_are_retained() {
            for name in [MANIFEST, APPLIED, ROLLBACK] {
                let f = Fixture::new();
                f.at(Step::Prepared).unwrap_err();
                fs::write(f.tx().join(name), b"{partial").unwrap();
                assert_eq!(f.result().state, "recovery_required");
                assert_eq!(f.apply().unwrap_err().code, "recovery_required");
                assert_eq!(f.back().unwrap_err().code, "recovery_required");
                f.baseline();
                assert_eq!(fs::read(f.tx().join(name)).unwrap(), b"{partial");
            }
        }
        #[test]
        fn intent_and_receipt_semantics_are_revalidated_before_recovery() {
            for complete in [false, true] {
                let f = Fixture::new();
                if complete {
                    f.apply().unwrap();
                } else {
                    f.at(Step::Prepared).unwrap_err();
                }
                f.edit_json(&f.tx().join(MANIFEST), |v| {
                    v["old_version"] = json!("0.9.0")
                });
                assert_eq!(f.result().state, "recovery_required");
                assert_eq!(f.apply().unwrap_err().code, "recovery_required");
                assert_eq!(f.back().unwrap_err().code, "recovery_required");
                assert_eq!(
                    fs::read(f.skill()).unwrap(),
                    if complete {
                        NEW.as_bytes()
                    } else {
                        OLD.as_bytes()
                    }
                );
            }
            let f = Fixture::new();
            f.at(Step::Prepared).unwrap_err();
            f.edit_json(&f.tx().join(RECEIPT_SLOT), |v| {
                v["last_operation_id"] = json!(uuid::Uuid::new_v4().to_string())
            });
            let tx = Directory::open(&f.tx()).unwrap();
            let altered = tx.read(RECEIPT_SLOT, LIMIT).unwrap().record;
            f.edit_json(&f.tx().join(MANIFEST), |v| {
                v["new_receipt"] = serde_json::to_value(altered).unwrap()
            });
            assert_eq!(f.apply().unwrap_err().code, "recovery_required");
            assert_eq!(f.back().unwrap_err().code, "recovery_required");
            f.baseline();
        }

        #[test]
        fn contradictory_receipt_relationships_never_authorize_a_resume_or_rollback() {
            for replacement in [false, true] {
                let edits = if replacement {
                    vec![
                        ("schema_version", json!(1)),
                        ("source", json!("download")),
                        ("contract_revision", json!(2)),
                        ("last_operation_id", json!(uuid::Uuid::new_v4().to_string())),
                        ("enrolled_sha256", json!("0".repeat(64))),
                        ("enrolled_version", json!("3.0.0")),
                        ("agent", json!("claude")),
                        ("path", json!("/wrong/skill")),
                        ("allows_automatic_updates", json!(true)),
                    ]
                } else {
                    vec![
                        ("enrolled_sha256", json!("0".repeat(64))),
                        ("enrolled_version", json!("0.9.0")),
                        ("agent", json!("claude")),
                        ("path", json!("/wrong/skill")),
                        ("allows_automatic_updates", json!(true)),
                    ]
                };
                for (field, value) in edits {
                    let f = Fixture::new();
                    f.at(Step::Prepared).unwrap_err();
                    let path = if replacement {
                        f.tx().join(RECEIPT_SLOT)
                    } else {
                        f.receipt()
                    };
                    f.edit_json(&path, |v| v[field] = value);
                    let dir = Directory::open(path.parent().unwrap()).unwrap();
                    let record = dir
                        .read(path.file_name().unwrap().to_str().unwrap(), LIMIT)
                        .unwrap()
                        .record;
                    f.edit_json(&f.tx().join(MANIFEST), |v| {
                        v[if replacement {
                            "new_receipt"
                        } else {
                            "old_receipt"
                        }] = serde_json::to_value(record).unwrap()
                    });
                    let before = fs::read(&path).unwrap();
                    assert_eq!(
                        f.apply().unwrap_err().code,
                        "recovery_required",
                        "{field} replacement={replacement}"
                    );
                    assert_eq!(
                        f.back().unwrap_err().code,
                        "recovery_required",
                        "{field} replacement={replacement}"
                    );
                    f.baseline();
                    assert_eq!(fs::read(&path).unwrap(), before);
                    assert!(!f.tx().join(APPLIED).exists());
                    assert!(!f.tx().join(ROLLBACK).exists());
                }
            }
            let f = Fixture::new();
            f.at(Step::Prepared).unwrap_err();
            f.edit_json(&f.tx().join(MANIFEST), |v| {
                v["bundle_version"] = json!("3.0.0")
            });
            assert_eq!(f.apply().unwrap_err().code, "request_conflict");
            assert_eq!(f.back().unwrap_err().code, "recovery_required");
            f.baseline();
        }

        #[test]
        fn result_inspection_is_read_only_even_for_partial_transactions() {
            let f = Fixture::new();
            f.at(Step::SkillSwapped).unwrap_err();
            fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>, std::time::SystemTime)> {
                let mut v = Vec::new();
                for e in fs::read_dir(dir).unwrap() {
                    let p = e.unwrap().path();
                    if p.is_dir() {
                        v.extend(snapshot(&p));
                    } else {
                        v.push((
                            p.clone(),
                            fs::read(&p).unwrap(),
                            fs::metadata(p).unwrap().modified().unwrap(),
                        ));
                    }
                }
                v.sort_by(|a, b| a.0.cmp(&b.0));
                v
            }
            let before = snapshot(&f.home);
            assert_eq!(f.result().state, "recovery_required");
            assert_eq!(snapshot(&f.home), before);
        }
        fn fault(kind: &'static str, nth: usize) {
            IO_FAILURE.with(|v| *v.borrow_mut() = Some((kind, nth, 0)));
        }
        fn clear_fault() -> usize {
            IO_FAILURE.with(|v| {
                v.borrow_mut()
                    .take()
                    .map(|(_, _, count)| count)
                    .unwrap_or(0)
            })
        }
        #[test]
        fn every_io_boundary_failure_preserves_original_objects() {
            for reverse in [false, true] {
                for kind in ["file_sync", "directory_sync", "write", "swap"] {
                    let f = Fixture::new();
                    if reverse {
                        f.apply().unwrap();
                    }
                    fault(kind, usize::MAX);
                    if reverse {
                        f.back().unwrap();
                    } else {
                        f.apply().unwrap();
                    }
                    let count = clear_fault();
                    assert!(count > 0, "{kind} reverse={reverse}");
                    for nth in 1..=count {
                        let f = Fixture::new();
                        let original = fs::read(f.receipt()).unwrap();
                        if reverse {
                            f.apply().unwrap();
                        }
                        fault(kind, nth);
                        let attempt = if reverse { f.back() } else { f.apply() };
                        clear_fault();
                        assert!(attempt.is_err(), "{kind} #{nth} reverse={reverse}");
                        let original_skill_retained = [f.skill(), f.tx().join(SKILL_SLOT)]
                            .iter()
                            .any(|p| fs::read(p).ok().as_deref() == Some(OLD.as_bytes()));
                        let original_receipt_retained = [f.receipt(), f.tx().join(RECEIPT_SLOT)]
                            .iter()
                            .any(|p| fs::read(p).ok().as_deref() == Some(original.as_slice()));
                        assert!(
                            original_skill_retained && original_receipt_retained,
                            "{kind} #{nth} reverse={reverse}"
                        );
                        if f.tx().exists() {
                            let observation = f.result();
                            let valid = observation.error_code.is_none()
                                || matches!(
                                    observation.error_code,
                                    Some("apply_incomplete" | "rollback_incomplete")
                                );
                            if valid {
                                let finish = if reverse { f.back() } else { f.apply() };
                                assert_eq!(
                                    finish
                                        .unwrap_or_else(|e| panic!(
                                            "{kind} #{nth} reverse={reverse}: {e}"
                                        ))
                                        .state,
                                    if reverse { "rolled_back" } else { "applied" }
                                );
                            } else {
                                let before_skill = fs::read(f.skill()).unwrap();
                                assert!(if reverse { f.back() } else { f.apply() }.is_err());
                                assert_eq!(fs::read(f.skill()).unwrap(), before_skill);
                            }
                        }
                    }
                }
            }
        }
        #[test]
        fn visible_intent_and_rollback_marker_must_be_resynced_before_swapping() {
            let f = Fixture::new();
            // Original files, candidate, new receipt, then the intent file.
            fault("file_sync", 5);
            assert!(f.apply().is_err());
            clear_fault();
            f.baseline();
            assert!(f.tx().join(MANIFEST).exists());
            fault("file_sync", 1);
            assert_eq!(f.apply().unwrap_err().code, "recovery_required");
            clear_fault();
            f.baseline();
            f.apply().unwrap();
            rollback("codex", &f.root(), &f.id, |s| {
                if s == Step::RollbackRecorded {
                    Err(error("injected"))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            // Five referenced objects, then the already visible rollback intent.
            fault("file_sync", 6);
            assert_eq!(f.back().unwrap_err().code, "recovery_required");
            clear_fault();
            assert_eq!(fs::read(f.skill()).unwrap(), NEW.as_bytes());
            assert_eq!(
                serde_json::from_slice::<Value>(&fs::read(f.receipt()).unwrap()).unwrap()
                    ["schema_version"],
                2
            );
            f.back().unwrap();
            f.baseline();
        }
        #[test]
        fn rollback_chain_requires_the_latest_current_transaction_first() {
            let f = Fixture::new();
            f.apply().unwrap();
            let third_stage = f.home.join("third");
            stage_skill_update("codex", &f.root(), "synthetic third", "3.0.0", &third_stage)
                .unwrap();
            let third_id = uuid::Uuid::new_v4().to_string();
            apply(
                "codex",
                &f.root(),
                "synthetic third",
                "3.0.0",
                &third_stage,
                &third_id,
                |_| Ok(()),
            )
            .unwrap();
            assert_eq!(f.back().unwrap_err().code, "recovery_required");
            assert!(!f.tx().join(ROLLBACK).exists());
            assert_eq!(fs::read(f.skill()).unwrap(), b"synthetic third");
            rollback("codex", &f.root(), &third_id, |_| Ok(())).unwrap();
            assert_eq!(fs::read(f.skill()).unwrap(), NEW.as_bytes());
            f.back().unwrap();
            f.baseline();
        }

        #[test]
        fn later_managed_writes_resync_prior_terminal_markers_before_progressing() {
            let f = Fixture::new();
            f.apply().unwrap();
            fault("file_sync", 1);
            let err = stage_skill_update(
                "codex",
                &f.root(),
                "synthetic third bundle",
                "3.0.0",
                &f.home.join("third-stage"),
            )
            .unwrap_err();
            clear_fault();
            assert_eq!(err.code, "pending_transaction");
            assert!(!f.home.join("third-stage").exists());
            assert_eq!(fs::read(f.skill()).unwrap(), NEW.as_bytes());
            stage_skill_update(
                "codex",
                &f.root(),
                "synthetic third bundle",
                "3.0.0",
                &f.home.join("third-stage"),
            )
            .unwrap();
            let next = uuid::Uuid::new_v4().to_string();
            fault("file_sync", 1);
            assert_eq!(
                apply(
                    "codex",
                    &f.root(),
                    "synthetic third bundle",
                    "3.0.0",
                    &f.home.join("third-stage"),
                    &next,
                    |_| Ok(())
                )
                .unwrap_err()
                .code,
                "pending_transaction"
            );
            clear_fault();
            assert!(!f.dir().join(format!("{PREFIX}{next}")).exists());
            assert_eq!(
                apply(
                    "codex",
                    &f.root(),
                    "synthetic third bundle",
                    "3.0.0",
                    &f.home.join("third-stage"),
                    &next,
                    |_| Ok(())
                )
                .unwrap()
                .state,
                "applied"
            );
            assert_eq!(f.result().state, "applied");
            assert_eq!(f.result().current_state, "changed");
        }

        #[test]
        fn a_consumed_staging_directory_is_not_needed_for_id_replay() {
            let f = Fixture::new();
            f.apply().unwrap();
            fs::remove_dir_all(f.staged()).unwrap();
            assert_eq!(f.apply().unwrap().state, "applied");
            assert_eq!(f.back().unwrap().state, "rolled_back");
        }
        // On macOS the fixture files already carry the system's provenance label,
        // so this also shows that label does not let any other attribute through.
        #[test]
        fn extended_file_and_directory_metadata_fails_closed() {
            for directory in [false, true] {
                let f = Fixture::new();
                let path = if directory { f.dir() } else { f.skill() };
                let p = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
                let name = std::ffi::CString::new("user.sniper_test").unwrap();
                let value = b"synthetic";
                #[cfg(target_os = "linux")]
                // SAFETY: all buffers and explicit lengths are live in this temporary fixture.
                let rc = unsafe {
                    libc::setxattr(
                        p.as_ptr(),
                        name.as_ptr(),
                        value.as_ptr().cast(),
                        value.len(),
                        0,
                    )
                };
                #[cfg(target_os = "macos")]
                // SAFETY: as above, at position 0 with no options.
                let rc = unsafe {
                    libc::setxattr(
                        p.as_ptr(),
                        name.as_ptr(),
                        value.as_ptr().cast(),
                        value.len(),
                        0,
                        0,
                    )
                };
                assert_eq!(
                    rc, 0,
                    "fixture filesystem must support the tested attribute"
                );
                assert_eq!(f.apply().unwrap_err().code, "metadata_unsupported");
                f.baseline();
                assert!(!f.tx().exists());
            }
        }

        #[test]
        fn only_the_system_provenance_label_is_tolerated() {
            assert!(only_system_attributes(b""));
            for refused in [
                &b"user.sniper_test\0"[..],
                b"system.posix_acl_access\0",
                b"com.apple.provenance\0user.sniper_test\0",
                b"com.apple.provenance.extra\0",
            ] {
                assert!(!only_system_attributes(refused), "{refused:?}");
            }
            assert_eq!(
                only_system_attributes(b"com.apple.provenance\0"),
                cfg!(target_os = "macos"),
                "the label macOS attaches by itself, and only on macOS"
            );
            assert_eq!(
                only_system_attributes(b"com.apple.provenance\0com.apple.lastuseddate#PS\0"),
                cfg!(target_os = "macos"),
                "and the time an app last opened it"
            );
        }

        // These fixtures compile only on macOS. Linux test success does not
        // validate Darwin FFI, actual ACL inheritance, or native swap durability.
        #[cfg(target_os = "macos")]
        mod macos_acl_fixtures {
            use super::*;
            use std::ffi::c_void;

            const EXTENDED: i32 = 0x100;
            const ALLOW: i32 = 1;
            const DENY: i32 = 2;
            const READ_ATTRIBUTES: u64 = 1 << 7;
            const WRITE_ATTRIBUTES: u64 = 1 << 8;
            const INHERITED: u32 = 1 << 4;
            const FILE_INHERIT: u32 = 1 << 5;
            const DIRECTORY_INHERIT: u32 = 1 << 6;
            const ONLY_INHERIT: u32 = 1 << 8;

            // Types/constants follow Apple's sys/acl.h and membership.h. The
            // setter order is fd, acl, type; the getter order is fd, type.
            unsafe extern "C" {
                fn acl_init(count: i32) -> *mut c_void;
                fn acl_free(object: *mut c_void) -> i32;
                fn acl_create_entry(acl: *mut *mut c_void, entry: *mut *mut c_void) -> i32;
                fn acl_valid(acl: *mut c_void) -> i32;
                fn acl_set_tag_type(entry: *mut c_void, tag: i32) -> i32;
                fn acl_get_tag_type(entry: *mut c_void, tag: *mut i32) -> i32;
                fn acl_set_qualifier(entry: *mut c_void, qualifier: *const c_void) -> i32;
                fn acl_get_qualifier(entry: *mut c_void) -> *mut c_void;
                fn acl_set_permset_mask_np(entry: *mut c_void, mask: u64) -> i32;
                fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> i32;
                fn acl_get_flagset_np(entry: *mut c_void, flags: *mut *mut c_void) -> i32;
                fn acl_add_flag_np(flags: *mut c_void, flag: u32) -> i32;
                fn acl_get_flag_np(flags: *mut c_void, flag: u32) -> i32;
                fn acl_get_entry(acl: *mut c_void, which: i32, entry: *mut *mut c_void) -> i32;
                fn acl_get_fd_np(fd: i32, kind: i32) -> *mut c_void;
                fn acl_set_fd_np(fd: i32, acl: *mut c_void, kind: i32) -> i32;
                fn mbr_uid_to_uuid(uid: libc::uid_t, uuid: *mut u8) -> i32;
            }

            struct Allocation(*mut c_void);
            impl Drop for Allocation {
                fn drop(&mut self) {
                    // SAFETY: this owns one allocation returned by a Darwin ACL API.
                    unsafe { acl_free(self.0) };
                }
            }
            fn empty_acl() -> Allocation {
                // SAFETY: zero entries is the supported empty ACL constructor.
                let pointer = unsafe { acl_init(0) };
                assert!(!pointer.is_null(), "allocate synthetic empty ACL");
                Allocation(pointer)
            }
            fn read_acl(file: &File) -> Option<Allocation> {
                // SAFETY: the descriptor belongs to an owned synthetic fixture.
                let pointer = unsafe { acl_get_fd_np(file.as_raw_fd(), EXTENDED) };
                if pointer.is_null() {
                    assert_eq!(
                        std::io::Error::last_os_error().raw_os_error(),
                        Some(libc::ENOENT),
                        "native ACL inspection must work; do not skip unsupported/error results"
                    );
                    None
                } else {
                    let acl = Allocation(pointer);
                    assert_eq!(unsafe { acl_valid(acl.0) }, 0, "valid fixture ACL");
                    Some(acl)
                }
            }
            fn owner_uuid() -> [u8; 16] {
                let mut uuid = [0; 16];
                // SAFETY: uid is this process's owner and the output is 16 bytes.
                assert_eq!(
                    unsafe { mbr_uid_to_uuid(libc::geteuid(), uuid.as_mut_ptr()) },
                    0,
                    "resolve only the fixture owner"
                );
                uuid
            }
            fn owner_acl(tag: i32, mask: u64, inheritable: bool) -> Allocation {
                assert!(matches!(
                    (tag, mask),
                    (ALLOW, READ_ATTRIBUTES) | (DENY, WRITE_ATTRIBUTES)
                ));
                let mut acl = empty_acl();
                let mut entry = std::ptr::null_mut();
                let owner = owner_uuid();
                // SAFETY: all pointers refer to live owned ACL/output storage;
                // create_entry may replace the owned ACL allocation in place.
                unsafe {
                    assert_eq!(acl_create_entry(&mut acl.0, &mut entry), 0);
                    assert_eq!(acl_set_tag_type(entry, tag), 0);
                    assert_eq!(acl_set_qualifier(entry, owner.as_ptr().cast()), 0);
                    assert_eq!(acl_set_permset_mask_np(entry, mask), 0);
                    if inheritable {
                        assert_eq!(tag, ALLOW);
                        let mut flags = std::ptr::null_mut();
                        assert_eq!(acl_get_flagset_np(entry, &mut flags), 0);
                        for flag in [FILE_INHERIT, DIRECTORY_INHERIT, ONLY_INHERIT] {
                            assert_eq!(acl_add_flag_np(flags, flag), 0);
                        }
                    }
                    assert_eq!(acl_valid(acl.0), 0);
                }
                acl
            }
            fn open_fixture(f: &Fixture, path: &Path, directory: bool) -> File {
                assert!(
                    path.starts_with(&f.home),
                    "ACL fixture must stay inside its UUID temporary root"
                );
                let before = fs::symlink_metadata(path).unwrap();
                assert!(!before.file_type().is_symlink());
                assert_eq!(before.uid(), unsafe { libc::geteuid() });
                assert_eq!(before.is_dir(), directory);
                assert_eq!(before.is_file(), !directory);
                let file = OpenOptions::new()
                    .read(true)
                    .custom_flags(
                        libc::O_NOFOLLOW
                            | libc::O_NONBLOCK
                            | libc::O_CLOEXEC
                            | if directory { libc::O_DIRECTORY } else { 0 },
                    )
                    .open(path)
                    .unwrap();
                assert!(identity(&before, &file.metadata().unwrap()));
                file
            }
            struct RestoreAcl<'a> {
                file: &'a File,
                original: Allocation,
            }
            impl Drop for RestoreAcl<'_> {
                fn drop(&mut self) {
                    // The fixture ACEs never deny WRITE_SECURITY, traversal or
                    // deletion. Restore through the same fd before temp cleanup.
                    let rc =
                        unsafe { acl_set_fd_np(self.file.as_raw_fd(), self.original.0, EXTENDED) };
                    if rc != 0 {
                        if std::thread::panicking() {
                            eprintln!("synthetic ACL restoration failed; temporary fixture cleanup remains enabled");
                        } else {
                            panic!("restore synthetic fixture ACL");
                        }
                    }
                }
            }
            fn install<'a>(file: &'a File, acl: &Allocation) -> RestoreAcl<'a> {
                let restore = RestoreAcl {
                    file,
                    original: read_acl(file).unwrap_or_else(empty_acl),
                };
                // SAFETY: owned fixture descriptor and a validated live ACL.
                assert_eq!(
                    unsafe { acl_set_fd_np(file.as_raw_fd(), acl.0, EXTENDED) },
                    0,
                    "install only the synthetic current-owner ACE"
                );
                restore
            }
            fn assert_entry(file: &File, expected_tag: i32, expected_mask: u64, inherited: bool) {
                let acl = read_acl(file).expect("real ACE must be present");
                let mut entry = std::ptr::null_mut();
                let mut tag = 0;
                let mut mask = 0;
                let mut flags = std::ptr::null_mut();
                // Entry and flagset pointers are borrowed from acl, never freed.
                unsafe {
                    assert_eq!(acl_get_entry(acl.0, 0, &mut entry), 0);
                    assert_eq!(acl_get_tag_type(entry, &mut tag), 0);
                    assert_eq!(acl_get_permset_mask_np(entry, &mut mask), 0);
                    assert_eq!(acl_get_flagset_np(entry, &mut flags), 0);
                    assert_eq!(acl_get_flag_np(flags, INHERITED), i32::from(inherited));
                    let pointer = acl_get_qualifier(entry);
                    assert!(!pointer.is_null());
                    let qualifier = Allocation(pointer);
                    let expected_owner = owner_uuid();
                    assert_eq!(
                        std::slice::from_raw_parts(qualifier.0.cast::<u8>(), 16),
                        expected_owner.as_slice()
                    );
                }
                assert_eq!(tag, expected_tag);
                assert_eq!(mask, expected_mask);
                let mut next = std::ptr::null_mut();
                assert_eq!(
                    unsafe { acl_get_entry(acl.0, -1, &mut next) },
                    -1,
                    "exactly one fixture ACE"
                );
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EINVAL)
                );
            }

            #[test]
            fn absent_and_explicitly_empty_acls_allow_private_fixture_files_and_directories() {
                let f = Fixture::new();
                for (path, directory) in [(f.skill(), false), (f.dir(), true)] {
                    let file = open_fixture(&f, &path, directory);
                    check_macos_acl(&file).unwrap();
                    let empty = empty_acl();
                    let _restore = install(&file, &empty);
                    // The filesystem may canonicalize an empty ACL to absent.
                    check_macos_acl(&file).unwrap();
                    validate_access_metadata(&file).unwrap();
                }
                f.apply().unwrap();
                f.back().unwrap();
                f.baseline();
                fs::remove_dir_all(&f.home).unwrap();
            }
            #[test]
            fn current_owner_allow_and_deny_aces_refuse_before_activation() {
                for (tag, mask) in [(ALLOW, READ_ATTRIBUTES), (DENY, WRITE_ATTRIBUTES)] {
                    for target in 0..3 {
                        let f = Fixture::new();
                        let before_skill = fs::read(f.skill()).unwrap();
                        let before_receipt = fs::read(f.receipt()).unwrap();
                        let path = [f.skill(), f.receipt(), f.dir()][target].clone();
                        let file = open_fixture(&f, &path, target == 2);
                        {
                            let acl = owner_acl(tag, mask, false);
                            let _restore = install(&file, &acl);
                            assert_entry(&file, tag, mask, false);
                            assert_eq!(
                                check_macos_acl(&file).unwrap_err().code,
                                "metadata_unsupported"
                            );
                            assert_eq!(f.apply().unwrap_err().code, "metadata_unsupported");
                            assert_eq!(fs::read(f.skill()).unwrap(), before_skill);
                            assert_eq!(fs::read(f.receipt()).unwrap(), before_receipt);
                            assert!(!f.tx().exists());
                        }
                        check_macos_acl(&file).unwrap();
                        fs::remove_dir_all(&f.home).unwrap();
                    }
                }
            }
            #[test]
            fn real_parent_inheritance_is_rejected_on_new_child_files_and_directories() {
                let f = Fixture::new();
                let parent = f.home.join("acl-inheritance");
                fs::create_dir(&parent).unwrap();
                let parent_file = open_fixture(&f, &parent, true);
                {
                    let acl = owner_acl(ALLOW, READ_ATTRIBUTES, true);
                    let _restore = install(&parent_file, &acl);
                    assert_entry(&parent_file, ALLOW, READ_ATTRIBUTES, false);
                    let child_file = parent.join("child-file");
                    let child_dir = parent.join("child-dir");
                    // These objects are created after setting the parent ACL,
                    // so inherited bits must come from the filesystem itself.
                    fs::write(&child_file, b"synthetic inherited ACL").unwrap();
                    fs::create_dir(&child_dir).unwrap();
                    for (path, directory) in [(&child_file, false), (&child_dir, true)] {
                        let file = open_fixture(&f, path, directory);
                        assert_entry(&file, ALLOW, READ_ATTRIBUTES, true);
                        assert_eq!(
                            check_macos_acl(&file).unwrap_err().code,
                            "metadata_unsupported"
                        );
                        if directory {
                            assert_eq!(
                                Directory::open(path).err().unwrap().code,
                                "metadata_unsupported"
                            );
                        } else {
                            assert_eq!(
                                validate_file(&file, &file.metadata().unwrap(), MAX_SKILL_BYTES)
                                    .unwrap_err()
                                    .code,
                                "metadata_unsupported"
                            );
                        }
                    }
                }
                fs::remove_dir_all(&f.home).unwrap();
            }
        }

        #[test]
        fn process_exit_after_swap_is_reconciled_by_a_new_process() {
            let f = Fixture::new();
            let child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "skill_activation::supported::tests::crash_child_entry",
                    "--nocapture",
                ])
                .env("SNIPER_ACTIVATION_TEST_ROOT", &f.home)
                .env("SNIPER_ACTIVATION_TEST_ID", &f.id)
                .env("HOME", f.home.join("home"))
                .env("USERPROFILE", f.home.join("home"))
                .env("CODEX_HOME", f.home.join("codex"))
                .env("CLAUDE_HOME", f.home.join("claude"))
                .env("SNIPER_DATA_DIR", f.home.join("data"))
                .output()
                .unwrap();
            assert_eq!(child.status.code(), Some(91), "{child:?}");
            assert_eq!(f.result().state, "recovery_required");
            assert_eq!(f.apply().unwrap().state, "applied");
            assert!(!f.home.join("data").exists());
        }
        #[test]
        fn crash_child_entry() {
            let Some(home) = std::env::var_os("SNIPER_ACTIVATION_TEST_ROOT") else {
                return;
            };
            let home = PathBuf::from(home);
            assert!(home
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("sniper-skill-activation-"));
            let id = std::env::var("SNIPER_ACTIVATION_TEST_ID").unwrap();
            apply(
                "codex",
                &home.join("skills"),
                NEW,
                NEW_VERSION,
                &home.join("candidate"),
                &id,
                |step| {
                    if step == Step::SkillSwapped {
                        std::process::exit(91);
                    }
                    Ok(())
                },
            )
            .unwrap();
            panic!("did not reach crash checkpoint");
        }
    }

    #[cfg(target_os = "macos")]
    fn check_macos_acl(file: &File) -> Result<()> {
        use std::ffi::c_void;
        // Darwin ACL handles are opaque. The constants and return conventions
        // follow Apple's sys/acl.h and Libc posix1e implementation, not Linux's.
        unsafe extern "C" {
            fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut c_void;
            fn acl_valid(acl: *mut c_void) -> libc::c_int;
            fn acl_get_entry(
                acl: *mut c_void,
                which: libc::c_int,
                entry: *mut *mut c_void,
            ) -> libc::c_int;
            fn acl_free(acl: *mut c_void) -> libc::c_int;
        }
        // SAFETY: live descriptor and the Darwin ACL_TYPE_EXTENDED constant.
        let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
        if acl.is_null() {
            return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                Ok(())
            } else {
                Err(error("metadata_unsupported"))
            };
        }
        // SAFETY: nonnull acl_get_fd_np returned an owned ACL handle.
        let valid = unsafe { acl_valid(acl) } == 0;
        let mut entry = std::ptr::null_mut();
        // Darwin returns 0 for an entry and -1/EINVAL for an empty valid ACL.
        let rc = if valid {
            unsafe { acl_get_entry(acl, 0, &mut entry) }
        } else {
            0
        };
        let errno = std::io::Error::last_os_error().raw_os_error();
        // SAFETY: release the owned ACL exactly once, regardless of inspection outcome.
        unsafe { acl_free(acl) };
        if valid && rc == -1 && errno == Some(libc::EINVAL) {
            Ok(())
        } else {
            Err(error("metadata_unsupported"))
        }
    }
}

/// Called while the existing enrollment/staging writer holds its directory lock.
pub(crate) fn check_pending(agent: &str, root: &Path) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    return supported::check_pending(agent, root);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (agent, root);
        Ok(())
    }
}
