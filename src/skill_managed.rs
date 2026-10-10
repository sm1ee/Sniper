//! Explicit local enrollment and non-activating skill update candidates.
//!
//! Enrollment records one observed byte hash, not provenance or permission to
//! update a file. No operation in this module opens an active skill for writing.
//! Observations cannot lock out an editor; the active file may change afterward.
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::skill_status::{inspect, inspect_with_limit, sha256, SkillStatus, MAX_SKILL_BYTES};

pub const ENROLLMENT_FILE: &str = ".sniper-enrollment.json";
pub const STAGED_RECEIPT_FILE: &str = "receipt.json";
const MAX_RECEIPT_BYTES: usize = 16 * 1024;

/// Deliberately excludes OS messages, file contents, and JSON parser excerpts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedSkillError {
    pub code: &'static str,
}

impl fmt::Display for ManagedSkillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code)
    }
}

impl std::error::Error for ManagedSkillError {}

type Result<T> = std::result::Result<T, ManagedSkillError>;

fn error(code: &'static str) -> ManagedSkillError {
    ManagedSkillError { code }
}

fn io_error(err: io::Error) -> ManagedSkillError {
    error(match err.kind() {
        io::ErrorKind::AlreadyExists => "already_exists",
        io::ErrorKind::NotFound => "missing",
        io::ErrorKind::PermissionDenied => "permission_denied",
        _ => "io_error",
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedSkillState {
    Unmanaged,
    Current,
    UpdateAvailable,
    Modified,
    Missing,
    Error,
}

#[derive(Debug, Serialize)]
pub struct ManagedSkillPreview {
    pub agent: String,
    pub path: String,
    pub receipt_path: String,
    pub installed_sha256: Option<String>,
    pub bundled_sha256: String,
    pub bundled_version: String,
    pub enrolled_sha256: Option<String>,
    pub enrolled_version: Option<String>,
    pub state: ManagedSkillState,
    pub stage_eligible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct SkillEnrollmentResult {
    pub agent: String,
    pub path: String,
    pub receipt_path: String,
    pub enrolled_sha256: String,
    pub enrolled_version: String,
    pub allows_automatic_updates: bool,
}

#[derive(Debug, Serialize)]
pub struct StagedSkillUpdate {
    pub agent: String,
    /// The unchanged active installation, not the candidate.
    pub path: String,
    pub staging_dir: String,
    pub candidate_path: String,
    pub receipt_path: String,
    pub installed_sha256: String,
    pub bundled_sha256: String,
    pub bundled_version: String,
    pub activated: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentReceipt {
    schema_version: u32,
    kind: String,
    agent: String,
    path: String,
    enrolled_sha256: String,
    enrolled_version: String,
    allows_automatic_updates: bool,
}

#[derive(Debug, Serialize)]
struct StagingReceipt<'a> {
    schema_version: u32,
    kind: &'static str,
    agent: &'a str,
    path: &'a str,
    enrollment_receipt_sha256: String,
    installed_sha256: &'a str,
    bundled_sha256: &'a str,
    bundled_version: &'a str,
    candidate_file: &'static str,
    activated: bool,
    allows_automatic_updates: bool,
}

struct Target {
    path: PathBuf,
    receipt_path: PathBuf,
    path_text: String,
    receipt_text: String,
}

fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| error("non_utf8_path"))
}

fn validate_version(version: &str) -> bool {
    version.len() <= 128 && semver::Version::parse(version).is_ok()
}

fn target(agent: &str, root: &Path, bundled: &str, version: &str) -> Result<Target> {
    if !matches!(agent, "codex" | "claude") {
        return Err(error("invalid_agent"));
    }
    if !validate_version(version) {
        return Err(error("invalid_version"));
    }
    if bundled.len() as u64 > MAX_SKILL_BYTES {
        return Err(error("bundle_too_large"));
    }
    let dir = std::path::absolute(root.join("sniper-operator")).map_err(io_error)?;
    let path = dir.join("SKILL.md");
    let receipt_path = dir.join(ENROLLMENT_FILE);
    Ok(Target {
        path_text: path_text(&path)?,
        receipt_text: path_text(&receipt_path)?,
        path,
        receipt_path,
    })
}

fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    inspect(path).map_err(|(status, code)| {
        error(code.unwrap_or(if status == SkillStatus::Missing {
            "missing"
        } else {
            "inspection_failed"
        }))
    })
}

fn read_receipt(target: &Target, agent: &str) -> Result<(EnrollmentReceipt, Vec<u8>)> {
    let bytes = read_receipt_bytes(&target.receipt_path)?;
    let receipt: EnrollmentReceipt =
        serde_json::from_slice(&bytes).map_err(|_| error("invalid_receipt"))?;
    if receipt.schema_version != 1
        || receipt.kind != "sniper_skill_enrollment"
        || receipt.agent != agent
        || receipt.path != target.path_text
        || receipt.allows_automatic_updates
        || !validate_version(&receipt.enrolled_version)
        || receipt.enrolled_sha256.len() != 64
        || !receipt
            .enrolled_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(error("invalid_receipt"));
    }
    Ok((receipt, bytes))
}

fn read_receipt_bytes(path: &Path) -> Result<Vec<u8>> {
    inspect_with_limit(path, MAX_RECEIPT_BYTES as u64).map_err(|(status, code)| {
        error(code.unwrap_or(if status == SkillStatus::Missing {
            "missing"
        } else {
            "inspection_failed"
        }))
    })
}

/// Read-only comparison. An unmanaged file still reports both byte hashes.
/// An enrolled hash is a local baseline and makes no publisher-authenticity claim.
pub fn preview_skill_update(
    agent: &str,
    root: &Path,
    bundled: &str,
    bundled_version: &str,
) -> Result<ManagedSkillPreview> {
    let target = target(agent, root, bundled, bundled_version)?;
    let mut row = ManagedSkillPreview {
        agent: agent.to_owned(),
        path: target.path_text.clone(),
        receipt_path: target.receipt_text.clone(),
        installed_sha256: None,
        bundled_sha256: sha256(bundled.as_bytes()),
        bundled_version: bundled_version.to_owned(),
        enrolled_sha256: None,
        enrolled_version: None,
        state: ManagedSkillState::Error,
        stage_eligible: false,
        error_code: None,
    };
    let installed = match read_bytes(&target.path) {
        Ok(bytes) => bytes,
        Err(err) => {
            if err.code == "missing" {
                row.state = ManagedSkillState::Missing;
            } else {
                row.error_code = Some(err.code);
            }
            return Ok(row);
        }
    };
    let installed_hash = sha256(&installed);
    row.installed_sha256 = Some(installed_hash.clone());
    let receipt = match read_receipt(&target, agent) {
        Ok((receipt, _)) => receipt,
        Err(err) => {
            if err.code == "missing" {
                row.state = ManagedSkillState::Unmanaged;
            } else {
                row.error_code = Some(err.code);
            }
            return Ok(row);
        }
    };
    row.state = if installed_hash != receipt.enrolled_sha256 {
        ManagedSkillState::Modified
    } else if installed == bundled.as_bytes() {
        ManagedSkillState::Current
    } else {
        ManagedSkillState::UpdateAvailable
    };
    row.enrolled_sha256 = Some(receipt.enrolled_sha256);
    row.enrolled_version = Some(receipt.enrolled_version);
    row.stage_eligible = row.state == ManagedSkillState::UpdateAvailable;
    Ok(row)
}

/// Enroll only an exact copy of the current bundle. Never replace a receipt.
/// A write or sync error can leave a partial or complete visible receipt. Invalid
/// receipts are rejected, but preview may recognize a valid receipt even after
/// enrollment reports an error. Receipt presence does not prove that all
/// completion checks succeeded; later calls never overwrite it.
pub fn enroll_skill(
    agent: &str,
    root: &Path,
    bundled: &str,
    bundled_version: &str,
) -> Result<SkillEnrollmentResult> {
    enroll_impl(agent, root, bundled, bundled_version, || {})
}

fn enroll_impl(
    agent: &str,
    root: &Path,
    bundled: &str,
    bundled_version: &str,
    before_write: impl FnOnce(),
) -> Result<SkillEnrollmentResult> {
    let target = target(agent, root, bundled, bundled_version)?;
    if read_bytes(&target.path)? != bundled.as_bytes() {
        return Err(error("installed_not_current"));
    }
    let receipt = EnrollmentReceipt {
        schema_version: 1,
        kind: "sniper_skill_enrollment".into(),
        agent: agent.to_owned(),
        path: target.path_text.clone(),
        enrolled_sha256: sha256(bundled.as_bytes()),
        enrolled_version: bundled_version.to_owned(),
        allows_automatic_updates: false,
    };
    let bytes = encode_receipt(&receipt)?;
    let directory = CheckedDirectory::open(target.path.parent().unwrap())?;
    before_write();
    directory.check_path()?;
    // Catch an editor change before publishing the snapshot. Future changes are
    // detected by preview; no local receipt can exclude all concurrent editors.
    if read_bytes(&target.path)? != bundled.as_bytes() {
        return Err(error("changed_during_enrollment"));
    }
    directory.write_new(ENROLLMENT_FILE, &bytes)?;
    directory.sync()?;
    directory.check_path()?;
    Ok(SkillEnrollmentResult {
        agent: receipt.agent,
        path: receipt.path,
        receipt_path: target.receipt_text,
        enrolled_sha256: receipt.enrolled_sha256,
        enrolled_version: receipt.enrolled_version,
        allows_automatic_updates: false,
    })
}

fn encode_receipt(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| error("serialization_failed"))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_RECEIPT_BYTES {
        return Err(error("receipt_too_large"));
    }
    Ok(bytes)
}

/// Stage a changed bundle only when active bytes still match the enrollment.
/// The parent must exist, the output directory must be new and outside the active
/// skill folder, and the receipt is written last. Errors can leave partial or
/// complete visible output, so receipt presence does not prove completion or
/// durability. Existing output is preserved, including competing files.
pub fn stage_skill_update(
    agent: &str,
    root: &Path,
    bundled: &str,
    bundled_version: &str,
    staging_dir: &Path,
) -> Result<StagedSkillUpdate> {
    stage_impl(
        agent,
        root,
        bundled,
        bundled_version,
        staging_dir,
        |_, _| Ok(()),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StageStep {
    DirectoryCreated,
    CandidateWritten,
}

fn stage_impl(
    agent: &str,
    root: &Path,
    bundled: &str,
    bundled_version: &str,
    staging_dir: &Path,
    mut checkpoint: impl FnMut(StageStep, &Path) -> Result<()>,
) -> Result<StagedSkillUpdate> {
    let target = target(agent, root, bundled, bundled_version)?;
    let (receipt, receipt_bytes) = read_receipt(&target, agent)?;
    let installed = read_bytes(&target.path)?;
    let installed_hash = sha256(&installed);
    if installed_hash != receipt.enrolled_sha256 {
        return Err(error("installed_modified"));
    }
    if installed == bundled.as_bytes() {
        return Err(error("already_current"));
    }
    let staging_dir = staging_path(staging_dir, target.path.parent().unwrap())?;
    let bundled_hash = sha256(bundled.as_bytes());
    let stage_receipt = StagingReceipt {
        schema_version: 1,
        kind: "sniper_staged_skill_update",
        agent,
        path: &target.path_text,
        enrollment_receipt_sha256: sha256(&receipt_bytes),
        installed_sha256: &installed_hash,
        bundled_sha256: &bundled_hash,
        bundled_version,
        candidate_file: "SKILL.md",
        activated: false,
        allows_automatic_updates: false,
    };
    let stage_bytes = encode_receipt(&stage_receipt)?;
    let directory = CheckedDirectory::create(&staging_dir)?;
    checkpoint(StageStep::DirectoryCreated, &staging_dir)?;
    directory.check_path()?;
    check_baseline(&target, &installed, &receipt_bytes)?;
    directory.write_new("SKILL.md", bundled.as_bytes())?;
    checkpoint(StageStep::CandidateWritten, &staging_dir)?;
    directory.check_path()?;
    check_baseline(&target, &installed, &receipt_bytes)?;
    if read_bytes(&staging_dir.join("SKILL.md"))? != bundled.as_bytes() {
        return Err(error("candidate_changed"));
    }
    directory.write_new(STAGED_RECEIPT_FILE, &stage_bytes)?;
    directory.sync()?;
    directory.check_path()?;
    Ok(StagedSkillUpdate {
        agent: agent.to_owned(),
        path: target.path_text,
        candidate_path: path_text(&staging_dir.join("SKILL.md"))?,
        receipt_path: path_text(&staging_dir.join(STAGED_RECEIPT_FILE))?,
        staging_dir: path_text(&staging_dir)?,
        installed_sha256: installed_hash,
        bundled_sha256: bundled_hash,
        bundled_version: bundled_version.to_owned(),
        activated: false,
    })
}

fn check_baseline(target: &Target, installed: &[u8], receipt: &[u8]) -> Result<()> {
    if read_bytes(&target.path)? != installed
        || read_receipt_bytes(&target.receipt_path)? != receipt
    {
        return Err(error("changed_during_staging"));
    }
    Ok(())
}

fn staging_path(staging_dir: &Path, skill_dir: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(staging_dir).map_err(io_error)?;
    let filename = absolute
        .file_name()
        .ok_or_else(|| error("invalid_staging_dir"))?;
    // Resolve aliases before enforcing the boundary; never create missing parents.
    let parent = fs::canonicalize(
        absolute
            .parent()
            .ok_or_else(|| error("invalid_staging_dir"))?,
    )
    .map_err(io_error)?;
    let skill_dir = fs::canonicalize(skill_dir).map_err(io_error)?;
    if parent.starts_with(skill_dir) {
        return Err(error("staging_inside_active_skill"));
    }
    let path = parent.join(filename);
    path_text(&path)?;
    Ok(path)
}

/// A small directory anchor: on Unix child creation uses openat, while Windows
/// holds a directory handle that denies rename/deletion for the write's duration.
struct CheckedDirectory {
    path: PathBuf,
    file: File,
}

impl CheckedDirectory {
    fn create(path: &Path) -> Result<Self> {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path).map_err(io_error)?;
        Self::open(path)
    }

    fn open(path: &Path) -> Result<Self> {
        let before = fs::symlink_metadata(path).map_err(io_error)?;
        validate_directory(&before)?;
        let file = open_directory(path)?;
        let opened = file.metadata().map_err(io_error)?;
        validate_directory(&opened)?;
        if !same_directory(&before, &opened) {
            return Err(error("directory_changed"));
        }
        let directory = Self {
            path: path.to_owned(),
            file,
        };
        directory.check_path()?;
        Ok(directory)
    }

    fn check_path(&self) -> Result<()> {
        let at_path = fs::symlink_metadata(&self.path).map_err(io_error)?;
        validate_directory(&at_path)?;
        let held = self.file.metadata().map_err(io_error)?;
        if !same_directory(&held, &at_path) {
            return Err(error("directory_changed"));
        }
        #[cfg(windows)]
        {
            let at_path = open_directory(&self.path)?;
            validate_directory(&at_path.metadata().map_err(io_error)?)?;
            if windows_directory_identity(&self.file)? != windows_directory_identity(&at_path)? {
                return Err(error("directory_changed"));
            }
        }
        Ok(())
    }

    fn write_new(&self, name: &str, bytes: &[u8]) -> Result<()> {
        #[cfg(unix)]
        let mut file = {
            use std::{
                ffi::CString,
                os::fd::{AsRawFd, FromRawFd},
            };
            let name = CString::new(name).map_err(|_| error("invalid_filename"))?;
            // SAFETY: the directory fd and NUL-terminated single-component name
            // are live. O_EXCL never opens an existing file or follows a link.
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(io_error(io::Error::last_os_error()));
            }
            // SAFETY: successful openat returned an exclusively owned fd.
            unsafe { File::from_raw_fd(fd) }
        };
        #[cfg(not(unix))]
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.path.join(name))
            .map_err(io_error)?;
        file.write_all(bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)
    }

    fn sync(&self) -> Result<()> {
        #[cfg(unix)]
        self.file.sync_all().map_err(io_error)?;
        Ok(())
    }
}

fn open_directory(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE, SECURITY_ANONYMOUS,
        };
        options
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .security_qos_flags(SECURITY_ANONYMOUS)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(not(any(unix, windows)))]
    return Err(error("platform_unsupported"));
    options.open(path).map_err(io_error)
}

#[cfg(windows)]
fn windows_directory_identity(file: &File) -> Result<(u32, u32, u32)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: file is live and info has the API's required size and alignment.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, info.as_mut_ptr()) } == 0 {
        return Err(io_error(io::Error::last_os_error()));
    }
    // SAFETY: successful GetFileInformationByHandle initialized info.
    let info = unsafe { info.assume_init() };
    Ok((
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}

fn same_directory(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // The held handle denies deleting/renaming this directory. Reparse
        // points at the path are separately rejected before this comparison.
        a.creation_time() == b.creation_time()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (a, b);
        false
    }
}

fn validate_directory(metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() {
        return Err(error("symlink"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(error("reparse_point"));
        }
    }
    if !metadata.is_dir() {
        return Err(error("non_directory"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    const OLD: &str = "synthetic bundled skill v1\n";
    const NEW: &str = "synthetic bundled skill v2\n";
    const VERSION: &str = "0.3.0";

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            Self(
                std::env::temp_dir().join(format!("sniper-skill-managed-{}", uuid::Uuid::new_v4())),
            )
        }

        fn root(&self) -> PathBuf {
            self.0.join("skills")
        }

        fn active_dir(&self) -> PathBuf {
            self.root().join("sniper-operator")
        }

        fn active(&self) -> PathBuf {
            self.active_dir().join("SKILL.md")
        }

        fn receipt(&self) -> PathBuf {
            self.active_dir().join(ENROLLMENT_FILE)
        }

        fn stage_dir(&self) -> PathBuf {
            self.0.join("candidate")
        }

        fn install(&self, bytes: impl AsRef<[u8]>) {
            fs::create_dir_all(self.active_dir()).unwrap();
            fs::write(self.active(), bytes).unwrap();
        }

        fn enroll(&self, bundled: &str) -> Result<SkillEnrollmentResult> {
            enroll_skill("codex", &self.root(), bundled, VERSION)
        }

        fn ready(&self) {
            self.install(OLD);
            self.enroll(OLD).unwrap();
        }

        fn preview(&self, bundled: &str) -> ManagedSkillPreview {
            preview_skill_update("codex", &self.root(), bundled, VERSION).unwrap()
        }

        fn stage(&self) -> Result<StagedSkillUpdate> {
            stage_skill_update("codex", &self.root(), NEW, VERSION, &self.stage_dir())
        }

        fn edit_receipt(&self, edit: impl FnOnce(&mut Value)) {
            let mut receipt: Value =
                serde_json::from_slice(&fs::read(self.receipt()).unwrap()).unwrap();
            edit(&mut receipt);
            fs::write(self.receipt(), serde_json::to_vec(&receipt).unwrap()).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn preview_missing_is_read_only() {
        let f = Fixture::new();
        let row = f.preview(NEW);
        assert_eq!(row.state, ManagedSkillState::Missing);
        assert_eq!(row.installed_sha256, None);
        assert_eq!(row.error_code, None);
        assert!(!row.stage_eligible);
        assert!(!f.0.exists());
    }

    #[test]
    fn unmanaged_preview_compares_hashes_without_ownership_claim() {
        let f = Fixture::new();
        for content in [OLD, NEW] {
            f.install(content);
            let row = f.preview(NEW);
            assert_eq!(row.state, ManagedSkillState::Unmanaged);
            assert_eq!(row.installed_sha256, Some(sha256(content.as_bytes())));
            assert_eq!(row.bundled_sha256, sha256(NEW.as_bytes()));
            assert_eq!(row.enrolled_sha256, None);
            assert!(!row.stage_eligible);
            assert!(!f.receipt().exists());
            assert_eq!(fs::read_dir(f.active_dir()).unwrap().count(), 1);
        }
    }

    #[test]
    fn enrollment_records_exact_snapshot_without_activation_permission() {
        let f = Fixture::new();
        f.install(OLD);
        let original_metadata = fs::metadata(f.active()).unwrap();
        let result = f.enroll(OLD).unwrap();
        assert_eq!(result.enrolled_sha256, sha256(OLD.as_bytes()));
        assert_eq!(result.enrolled_version, VERSION);
        assert!(!result.allows_automatic_updates);
        let receipt: Value = serde_json::from_slice(&fs::read(f.receipt()).unwrap()).unwrap();
        assert_eq!(receipt["agent"], "codex");
        assert_eq!(receipt["path"], path_text(&f.active()).unwrap());
        assert_eq!(receipt["allows_automatic_updates"], false);
        assert_eq!(fs::read(f.active()).unwrap(), OLD.as_bytes());
        assert_eq!(
            original_metadata.modified().unwrap(),
            fs::metadata(f.active()).unwrap().modified().unwrap()
        );
        let row = f.preview(OLD);
        assert_eq!(row.state, ManagedSkillState::Current);
        assert!(!row.stage_eligible);
    }

    #[test]
    fn enrollment_requires_exact_bytes_and_never_creates_missing_skill() {
        let f = Fixture::new();
        assert_eq!(f.enroll(OLD).unwrap_err().code, "missing");
        assert!(!f.0.exists());
        for content in [
            NEW.as_bytes(),
            b"synthetic bundled skill v1\r\n",
            &[0xff, 0],
        ] {
            f.install(content);
            assert_eq!(f.enroll(OLD).unwrap_err().code, "installed_not_current");
            assert!(!f.receipt().exists());
            assert_eq!(fs::read(f.active()).unwrap(), content);
        }
    }

    #[test]
    fn enrollment_is_exclusive_even_when_receipt_is_invalid() {
        let f = Fixture::new();
        f.ready();
        let initial = fs::read(f.receipt()).unwrap();
        assert_eq!(f.enroll(OLD).unwrap_err().code, "already_exists");
        assert_eq!(fs::read(f.receipt()).unwrap(), initial);
        fs::write(f.receipt(), b"private malformed receipt marker").unwrap();
        assert_eq!(f.enroll(OLD).unwrap_err().code, "already_exists");
        assert_eq!(
            fs::read(f.receipt()).unwrap(),
            b"private malformed receipt marker"
        );
    }

    #[test]
    fn preview_recognizes_updates_by_bytes_not_version_order() {
        let f = Fixture::new();
        f.ready();
        for version in [VERSION, "0.2.0", "0.9.0"] {
            let row = preview_skill_update("codex", &f.root(), NEW, version).unwrap();
            assert_eq!(row.state, ManagedSkillState::UpdateAvailable);
            assert!(row.stage_eligible);
            assert_eq!(row.enrolled_version.as_deref(), Some(VERSION));
        }
        let row = preview_skill_update("codex", &f.root(), OLD, "9.0.0").unwrap();
        assert_eq!(row.state, ManagedSkillState::Current);
        assert!(!row.stage_eligible);
    }

    #[test]
    fn modified_missing_and_unmanaged_files_cannot_stage() {
        let f = Fixture::new();
        f.install(OLD);
        assert_eq!(f.stage().unwrap_err().code, "missing");
        assert!(!f.stage_dir().exists());
        f.enroll(OLD).unwrap();
        f.install("user edits stay here\n");
        let row = f.preview(NEW);
        assert_eq!(row.state, ManagedSkillState::Modified);
        assert!(!row.stage_eligible);
        assert_eq!(f.stage().unwrap_err().code, "installed_modified");
        assert_eq!(fs::read(f.active()).unwrap(), b"user edits stay here\n");
        assert!(!f.stage_dir().exists());
        fs::remove_file(f.active()).unwrap();
        assert_eq!(f.preview(NEW).state, ManagedSkillState::Missing);
        assert_eq!(f.stage().unwrap_err().code, "missing");
        assert!(!f.stage_dir().exists());
    }

    #[test]
    fn invalid_receipts_are_preserved_and_never_authorize_staging() {
        let invalid_fields = [
            ("schema_version", json!(2)),
            ("kind", json!("other")),
            ("agent", json!("claude")),
            ("path", json!("/unrelated/example/SKILL.md")),
            ("allows_automatic_updates", json!(true)),
            ("enrolled_sha256", json!("F".repeat(64))),
            ("enrolled_sha256", json!("x".repeat(64))),
            ("enrolled_sha256", json!("abc")),
            ("enrolled_version", json!("not a version")),
            ("unrecognized", json!(true)),
        ];
        for (field, value) in invalid_fields {
            let f = Fixture::new();
            f.ready();
            f.edit_receipt(|r| r[field] = value);
            let bytes = fs::read(f.receipt()).unwrap();
            let row = f.preview(NEW);
            assert_eq!(row.state, ManagedSkillState::Error, "{field}");
            assert_eq!(row.error_code, Some("invalid_receipt"), "{field}");
            assert!(!row.stage_eligible);
            assert_eq!(f.stage().unwrap_err().code, "invalid_receipt");
            assert!(!f.stage_dir().exists());
            assert_eq!(fs::read(f.receipt()).unwrap(), bytes);
        }
    }

    #[test]
    fn malformed_oversized_and_partial_receipts_fail_closed_without_content_leaks() {
        let f = Fixture::new();
        f.ready();
        for bytes in [
            b"PRIVATE_CONTENT_MARKER {\"schema_version\":1".to_vec(),
            Vec::new(),
            vec![b'x'; MAX_RECEIPT_BYTES + 1],
            vec![b'x'; MAX_SKILL_BYTES as usize + 1],
        ] {
            fs::write(f.receipt(), &bytes).unwrap();
            let row = f.preview(NEW);
            assert_eq!(row.state, ManagedSkillState::Error);
            assert!(!row.stage_eligible);
            let output = serde_json::to_string(&row).unwrap();
            assert!(!output.contains("PRIVATE_CONTENT_MARKER"));
            assert!(!f
                .stage()
                .unwrap_err()
                .to_string()
                .contains("PRIVATE_CONTENT_MARKER"));
            assert_eq!(fs::read(f.receipt()).unwrap(), bytes);
            assert!(!f.stage_dir().exists());
        }
    }

    #[test]
    fn duplicate_receipt_fields_fail_closed() {
        let f = Fixture::new();
        f.ready();
        let receipt = fs::read_to_string(f.receipt()).unwrap();
        let duplicate = receipt.replacen('{', "{\"schema_version\":1,", 1);
        fs::write(f.receipt(), duplicate).unwrap();
        assert_eq!(f.preview(NEW).error_code, Some("invalid_receipt"));
    }

    #[test]
    fn stage_writes_only_candidate_and_completion_receipt() {
        let f = Fixture::new();
        f.ready();
        let enrollment = fs::read(f.receipt()).unwrap();
        let result = f.stage().unwrap();
        assert!(!result.activated);
        assert_eq!(result.path, path_text(&f.active()).unwrap());
        assert_eq!(fs::read(&result.candidate_path).unwrap(), NEW.as_bytes());
        let receipt: Value =
            serde_json::from_slice(&fs::read(&result.receipt_path).unwrap()).unwrap();
        assert_eq!(receipt["kind"], "sniper_staged_skill_update");
        assert_eq!(receipt["path"], result.path);
        assert_eq!(receipt["enrollment_receipt_sha256"], sha256(&enrollment));
        assert_eq!(receipt["installed_sha256"], sha256(OLD.as_bytes()));
        assert_eq!(receipt["bundled_sha256"], sha256(NEW.as_bytes()));
        assert_eq!(receipt["candidate_file"], "SKILL.md");
        assert_eq!(receipt["activated"], false);
        assert_eq!(receipt["allows_automatic_updates"], false);
        assert_eq!(fs::read_dir(f.stage_dir()).unwrap().count(), 2);
        assert_eq!(fs::read(f.active()).unwrap(), OLD.as_bytes());
        assert_eq!(fs::read(f.receipt()).unwrap(), enrollment);
        assert_eq!(f.preview(NEW).state, ManagedSkillState::UpdateAvailable);
    }

    #[test]
    fn stage_current_bundle_is_noop() {
        let f = Fixture::new();
        f.install(NEW);
        f.enroll(NEW).unwrap();
        assert_eq!(f.stage().unwrap_err().code, "already_current");
        assert!(!f.stage_dir().exists());
    }

    #[test]
    fn existing_staging_directory_or_file_is_never_reused() {
        let f = Fixture::new();
        f.ready();
        fs::create_dir(f.stage_dir()).unwrap();
        fs::write(f.stage_dir().join("sentinel"), b"preserve").unwrap();
        assert_eq!(f.stage().unwrap_err().code, "already_exists");
        assert_eq!(fs::read_dir(f.stage_dir()).unwrap().count(), 1);
        assert_eq!(
            fs::read(f.stage_dir().join("sentinel")).unwrap(),
            b"preserve"
        );
        fs::remove_dir_all(f.stage_dir()).unwrap();
        fs::write(f.stage_dir(), b"preserve file").unwrap();
        assert_eq!(f.stage().unwrap_err().code, "already_exists");
        assert_eq!(fs::read(f.stage_dir()).unwrap(), b"preserve file");
    }

    #[test]
    fn staging_parent_must_exist_and_output_must_be_outside_active_folder() {
        let f = Fixture::new();
        f.ready();
        let missing = f.0.join("missing/child");
        assert_eq!(
            stage_skill_update("codex", &f.root(), NEW, VERSION, &missing)
                .unwrap_err()
                .code,
            "missing"
        );
        assert!(!f.0.join("missing").exists());
        for path in [
            f.active_dir().join("candidate"),
            f.active_dir().join("./candidate"),
        ] {
            assert_eq!(
                stage_skill_update("codex", &f.root(), NEW, VERSION, &path)
                    .unwrap_err()
                    .code,
                "staging_inside_active_skill"
            );
            assert!(!path.exists());
        }
    }

    #[test]
    fn enrollment_detects_editor_change_before_receipt_creation() {
        let f = Fixture::new();
        f.install(OLD);
        let err = enroll_impl("codex", &f.root(), OLD, VERSION, || {
            fs::write(f.active(), b"concurrent editor contents").unwrap();
        })
        .unwrap_err();
        assert_eq!(err.code, "changed_during_enrollment");
        assert!(!f.receipt().exists());
        assert_eq!(fs::read(f.active()).unwrap(), b"concurrent editor contents");
    }

    #[test]
    fn enrollment_competing_receipt_is_never_replaced() {
        let f = Fixture::new();
        f.install(OLD);
        let err = enroll_impl("codex", &f.root(), OLD, VERSION, || {
            fs::write(f.receipt(), b"competing writer").unwrap();
        })
        .unwrap_err();
        assert_eq!(err.code, "already_exists");
        assert_eq!(fs::read(f.receipt()).unwrap(), b"competing writer");
        assert_eq!(fs::read(f.active()).unwrap(), OLD.as_bytes());
    }

    #[test]
    fn stage_detects_editor_changes_at_both_checkpoints() {
        for step in [StageStep::DirectoryCreated, StageStep::CandidateWritten] {
            let f = Fixture::new();
            f.ready();
            let err = stage_impl("codex", &f.root(), NEW, VERSION, &f.stage_dir(), |at, _| {
                if at == step {
                    fs::write(f.active(), b"concurrent edit").unwrap();
                }
                Ok(())
            })
            .unwrap_err();
            assert_eq!(err.code, "changed_during_staging");
            assert_eq!(fs::read(f.active()).unwrap(), b"concurrent edit");
            assert!(!f.stage_dir().join(STAGED_RECEIPT_FILE).exists());
            assert_eq!(
                f.stage_dir().join("SKILL.md").exists(),
                step == StageStep::CandidateWritten
            );
        }
    }

    #[test]
    fn staging_detects_receipt_change_and_preserves_it() {
        let f = Fixture::new();
        f.ready();
        let err = stage_impl("codex", &f.root(), NEW, VERSION, &f.stage_dir(), |at, _| {
            if at == StageStep::CandidateWritten {
                fs::write(f.receipt(), b"receipt changed").unwrap();
            }
            Ok(())
        })
        .unwrap_err();
        assert_eq!(err.code, "changed_during_staging");
        assert_eq!(fs::read(f.receipt()).unwrap(), b"receipt changed");
        assert_eq!(fs::read(f.active()).unwrap(), OLD.as_bytes());
        assert!(!f.stage_dir().join(STAGED_RECEIPT_FILE).exists());
    }

    #[test]
    fn injected_failures_leave_partial_output_without_completion_marker() {
        for step in [StageStep::DirectoryCreated, StageStep::CandidateWritten] {
            let f = Fixture::new();
            f.ready();
            let err = stage_impl("codex", &f.root(), NEW, VERSION, &f.stage_dir(), |at, _| {
                if at == step {
                    Err(error("injected_write_failure"))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert_eq!(err.code, "injected_write_failure");
            assert!(f.stage_dir().is_dir());
            assert!(!f.stage_dir().join(STAGED_RECEIPT_FILE).exists());
            assert_eq!(f.stage().unwrap_err().code, "already_exists");
            assert_eq!(fs::read(f.active()).unwrap(), OLD.as_bytes());
        }
    }

    #[test]
    fn competing_candidate_or_receipt_is_preserved() {
        for (step, name) in [
            (StageStep::DirectoryCreated, "SKILL.md"),
            (StageStep::CandidateWritten, STAGED_RECEIPT_FILE),
        ] {
            let f = Fixture::new();
            f.ready();
            let err = stage_impl(
                "codex",
                &f.root(),
                NEW,
                VERSION,
                &f.stage_dir(),
                |at, dir| {
                    if at == step {
                        fs::write(dir.join(name), b"competing output").unwrap();
                    }
                    Ok(())
                },
            )
            .unwrap_err();
            assert_eq!(err.code, "already_exists");
            assert_eq!(
                fs::read(f.stage_dir().join(name)).unwrap(),
                b"competing output"
            );
            assert_eq!(fs::read(f.active()).unwrap(), OLD.as_bytes());
        }
    }

    #[test]
    fn candidate_mutation_prevents_completion_receipt() {
        let f = Fixture::new();
        f.ready();
        let err = stage_impl(
            "codex",
            &f.root(),
            NEW,
            VERSION,
            &f.stage_dir(),
            |at, dir| {
                if at == StageStep::CandidateWritten {
                    fs::write(dir.join("SKILL.md"), b"edited candidate").unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(err.code, "candidate_changed");
        assert!(!f.stage_dir().join(STAGED_RECEIPT_FILE).exists());
        assert_eq!(
            fs::read(f.stage_dir().join("SKILL.md")).unwrap(),
            b"edited candidate"
        );
    }

    #[test]
    fn activation_is_never_inferred_from_candidate_or_manual_copy() {
        let f = Fixture::new();
        f.ready();
        f.stage().unwrap();
        assert_eq!(f.preview(NEW).state, ManagedSkillState::UpdateAvailable);
        f.install(NEW);
        assert_eq!(f.preview(NEW).state, ManagedSkillState::Modified);
        assert_eq!(f.enroll(NEW).unwrap_err().code, "already_exists");
    }

    #[test]
    fn invalid_input_is_rejected_before_writes() {
        let f = Fixture::new();
        assert_eq!(
            enroll_skill("other", &f.root(), OLD, VERSION)
                .unwrap_err()
                .code,
            "invalid_agent"
        );
        assert_eq!(
            enroll_skill("codex", &f.root(), OLD, "invalid")
                .unwrap_err()
                .code,
            "invalid_version"
        );
        assert_eq!(
            enroll_skill(
                "codex",
                &f.root(),
                &"x".repeat(MAX_SKILL_BYTES as usize + 1),
                VERSION
            )
            .unwrap_err()
            .code,
            "bundle_too_large"
        );
        assert!(!f.0.exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_receipts_and_active_files_are_never_followed() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new();
        f.install(OLD);
        let other = f.0.join("other");
        fs::write(&other, OLD).unwrap();
        symlink(&other, f.receipt()).unwrap();
        assert_eq!(f.enroll(OLD).unwrap_err().code, "already_exists");
        assert_eq!(f.preview(NEW).error_code, Some("symlink"));
        assert_eq!(f.stage().unwrap_err().code, "symlink");
        fs::remove_file(f.receipt()).unwrap();
        fs::remove_file(f.active()).unwrap();
        symlink(&other, f.active()).unwrap();
        assert_eq!(f.enroll(OLD).unwrap_err().code, "symlink");
        assert_eq!(f.preview(NEW).error_code, Some("symlink"));
        assert_eq!(fs::read(other).unwrap(), OLD.as_bytes());
        assert!(!f.stage_dir().exists());
    }

    #[cfg(unix)]
    #[test]
    fn final_staging_symlink_and_active_folder_alias_are_rejected() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new();
        f.ready();
        symlink(f.active_dir(), f.stage_dir()).unwrap();
        assert_eq!(f.stage().unwrap_err().code, "already_exists");
        let nested = f.stage_dir().join("candidate");
        assert_eq!(
            stage_skill_update("codex", &f.root(), NEW, VERSION, &nested)
                .unwrap_err()
                .code,
            "staging_inside_active_skill"
        );
        assert!(!f.active_dir().join("candidate").exists());
        assert_eq!(fs::read(f.active()).unwrap(), OLD.as_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn staging_directory_replacement_cannot_redirect_writes() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new();
        f.ready();
        let moved = f.0.join("moved");
        let err = stage_impl(
            "codex",
            &f.root(),
            NEW,
            VERSION,
            &f.stage_dir(),
            |at, dir| {
                if at == StageStep::DirectoryCreated {
                    fs::rename(dir, &moved).unwrap();
                    symlink(f.active_dir(), dir).unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(err.code, "symlink");
        assert_eq!(fs::read_dir(moved).unwrap().count(), 0);
        assert_eq!(fs::read_dir(f.active_dir()).unwrap().count(), 2);
        assert_eq!(fs::read(f.active()).unwrap(), OLD.as_bytes());
        assert!(fs::symlink_metadata(f.stage_dir())
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn exclusive_child_creation_preserves_symlink_and_hardlink_targets() {
        use std::os::unix::fs::symlink;
        for hardlink in [false, true] {
            let f = Fixture::new();
            f.ready();
            let err = stage_impl(
                "codex",
                &f.root(),
                NEW,
                VERSION,
                &f.stage_dir(),
                |at, dir| {
                    if at == StageStep::DirectoryCreated {
                        if hardlink {
                            fs::hard_link(f.active(), dir.join("SKILL.md")).unwrap();
                        } else {
                            symlink(f.active(), dir.join("SKILL.md")).unwrap();
                        }
                    }
                    Ok(())
                },
            )
            .unwrap_err();
            assert_eq!(err.code, "already_exists");
            assert_eq!(fs::read(f.active()).unwrap(), OLD.as_bytes());
            assert!(!f.stage_dir().join(STAGED_RECEIPT_FILE).exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn output_directory_and_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        f.ready();
        f.stage().unwrap();
        assert_eq!(
            fs::metadata(f.stage_dir()).unwrap().permissions().mode() & 0o077,
            0
        );
        for path in [
            f.receipt(),
            f.stage_dir().join("SKILL.md"),
            f.stage_dir().join(STAGED_RECEIPT_FILE),
        ] {
            assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o077, 0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_are_rejected_without_lossy_identity_collisions() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};
        let f = Fixture::new();
        let root = f.0.join(OsString::from_vec(vec![0xff]));
        assert_eq!(
            enroll_skill("codex", &root, OLD, VERSION).unwrap_err().code,
            "non_utf8_path"
        );
        assert!(!f.0.exists());
    }
}
