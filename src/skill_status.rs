//! Read-only inspection of an installed skill. Hashes describe bytes, not provenance.
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read},
    path::Path,
};

use rsa::sha2::{Digest, Sha256};
use serde::Serialize;

/// Limits both allocation and bytes read, including files growing during inspection.
pub const MAX_SKILL_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillStatus {
    Missing,
    Current,
    ModifiedOrOutdated,
    Unreadable,
    Unsupported,
}

#[derive(Debug, Serialize)]
pub struct SkillStatusRow {
    pub agent: String,
    pub path: String,
    pub bundled_sha256: String,
    pub installed_sha256: Option<String>,
    pub status: SkillStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<&'static str>,
}

/// Inspect `<root>/sniper-operator/SKILL.md` without creating or changing anything.
/// Only path absolutization errors escape; file inspection errors are safe codes.
/// Ancestor symlinks retain their usual filesystem meaning; the final component
/// is never followed. This is a bounded observation, not a filesystem snapshot.
pub fn read_skill_status(agent: &str, root: &Path, bundled: &str) -> io::Result<SkillStatusRow> {
    let path = std::path::absolute(root.join("sniper-operator").join("SKILL.md"))?;
    let mut row = SkillStatusRow {
        agent: agent.to_owned(),
        path: path.to_string_lossy().into_owned(),
        bundled_sha256: sha256(bundled.as_bytes()),
        installed_sha256: None,
        status: SkillStatus::Unreadable,
        error_code: None,
    };
    match inspect(&path) {
        Ok(bytes) => {
            let hash = sha256(&bytes);
            row.status = if bytes == bundled.as_bytes() && hash == row.bundled_sha256 {
                SkillStatus::Current
            } else {
                SkillStatus::ModifiedOrOutdated
            };
            row.installed_sha256 = Some(hash);
        }
        Err((status, code)) => {
            row.status = status;
            row.error_code = code;
        }
    }
    Ok(row)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

type InspectionError = (SkillStatus, Option<&'static str>);
fn unreadable(code: &'static str) -> InspectionError {
    (SkillStatus::Unreadable, Some(code))
}
fn unsupported(code: &'static str) -> InspectionError {
    (SkillStatus::Unsupported, Some(code))
}
fn io_error(error: io::Error) -> InspectionError {
    unreadable(if error.kind() == io::ErrorKind::PermissionDenied {
        "permission_denied"
    } else {
        "io_error"
    })
}

fn validate_metadata(meta: &Metadata) -> Result<(), InspectionError> {
    if meta.file_type().is_symlink() {
        return Err(unsupported("symlink"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(unsupported("reparse_point"));
        }
    }
    if !meta.is_file() {
        return Err(unsupported("non_regular_file"));
    }
    if meta.len() > MAX_SKILL_BYTES {
        return Err(unsupported("file_too_large"));
    }
    Ok(())
}

fn inspect(path: &Path) -> Result<Vec<u8>, InspectionError> {
    let before = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err((SkillStatus::Missing, None));
        }
        Err(error) => return Err(io_error(error)),
    };
    validate_metadata(&before)?;
    let file = open_no_follow(path)?;
    let opened = file.metadata().map_err(io_error)?;
    validate_metadata(&opened)?;
    if !same_metadata(&before, &opened) {
        return Err(unreadable("changed_during_read"));
    }
    let mut bytes = Vec::new();
    // Read one extra byte to detect growth without an unbounded allocation.
    (&file)
        .take(MAX_SKILL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > MAX_SKILL_BYTES {
        return Err(unsupported("file_too_large"));
    }
    let after = file.metadata().map_err(io_error)?;
    let at_path = fs::symlink_metadata(path).map_err(|_| unreadable("changed_during_read"))?;
    validate_metadata(&after)?;
    validate_metadata(&at_path)?;
    if !same_metadata(&opened, &after)
        || !same_metadata(&after, &at_path)
        || bytes.len() as u64 != after.len()
    {
        return Err(unreadable("changed_during_read"));
    }
    #[cfg(windows)]
    verify_windows_identity(&file, path)?;
    Ok(bytes)
}

#[cfg(windows)]
fn verify_windows_identity(file: &File, path: &Path) -> Result<(), InspectionError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    fn identity(file: &File) -> Result<(u32, u32, u32), InspectionError> {
        let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        // SAFETY: file is live and info has the API's required size and alignment.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, info.as_mut_ptr()) } == 0
        {
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
    let at_path = open_no_follow(path)?;
    validate_metadata(&at_path.metadata().map_err(io_error)?)?;
    if identity(file)? != identity(&at_path)? {
        return Err(unreadable("changed_during_read"));
    }
    Ok(())
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File, InspectionError> {
    use std::os::unix::fs::OpenOptionsExt;
    // NONBLOCK ensures a replacement FIFO cannot hang between lstat and open.
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(io_error)
}

#[cfg(windows)]
fn open_no_follow(path: &Path) -> Result<File, InspectionError> {
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileType, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_TYPE_DISK,
        SECURITY_ANONYMOUS,
    };
    // Deny concurrent writers/deletion while the handle is open; reparse points
    // are opened as objects and then rejected, rather than following targets.
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        // Do not grant impersonation if an ancestor races to a named-pipe path.
        .security_qos_flags(SECURITY_ANONYMOUS)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(io_error)?;
    // SAFETY: file owns a live handle for the duration of this call.
    if unsafe { GetFileType(file.as_raw_handle() as _) } != FILE_TYPE_DISK {
        return Err(unsupported("non_regular_file"));
    }
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_no_follow(_path: &Path) -> Result<File, InspectionError> {
    Err(unsupported("platform_unsupported"))
}

fn same_metadata(a: &Metadata, b: &Metadata) -> bool {
    if a.len() != b.len() || a.modified().ok() != b.modified().ok() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        a.creation_time() == b.creation_time()
            && a.last_write_time() == b.last_write_time()
            && a.file_attributes() == b.file_attributes()
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!("sniper-skill-status-{}", uuid::Uuid::new_v4())))
        }
        fn path(&self) -> PathBuf {
            self.0.join("sniper-operator/SKILL.md")
        }
        fn prepare(&self) {
            fs::create_dir_all(self.path().parent().unwrap()).unwrap();
        }
        fn read(&self) -> SkillStatusRow {
            read_skill_status("codex", &self.0, "bundled\n").unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn missing_does_not_create_root() {
        let f = Fixture::new();
        let row = f.read();
        assert_eq!(row.status, SkillStatus::Missing);
        assert!(!f.0.exists());
        assert!(Path::new(&row.path).is_absolute());
        assert_eq!(row.installed_sha256, None);
        assert_eq!(row.error_code, None);
    }

    #[test]
    fn exact_bytes_are_current_and_different_bytes_are_ambiguous() {
        let f = Fixture::new();
        f.prepare();
        fs::write(f.path(), b"bundled\n").unwrap();
        let row = f.read();
        assert_eq!(row.status, SkillStatus::Current);
        assert_eq!(row.installed_sha256.as_ref(), Some(&row.bundled_sha256));
        fs::write(f.path(), b"bundled\r\n").unwrap();
        let row = f.read();
        assert_eq!(row.status, SkillStatus::ModifiedOrOutdated);
        assert_ne!(row.installed_sha256.as_ref(), Some(&row.bundled_sha256));
        assert_eq!(fs::read(f.path()).unwrap(), b"bundled\r\n");
        assert_eq!(fs::read_dir(f.path().parent().unwrap()).unwrap().count(), 1);
        assert_eq!(
            serde_json::to_value(row).unwrap()["status"],
            "modified_or_outdated"
        );
    }

    #[test]
    fn empty_and_non_utf8_are_hashed_without_exposing_contents() {
        let f = Fixture::new();
        f.prepare();
        for content in [vec![], vec![0xff, 0xfe, 0]] {
            fs::write(f.path(), &content).unwrap();
            let row = f.read();
            assert_eq!(row.status, SkillStatus::ModifiedOrOutdated);
            assert_eq!(row.installed_sha256, Some(sha256(&content)));
        }
    }

    #[test]
    fn enforces_size_boundary() {
        let f = Fixture::new();
        f.prepare();
        fs::write(f.path(), vec![b'x'; MAX_SKILL_BYTES as usize]).unwrap();
        assert_eq!(f.read().status, SkillStatus::ModifiedOrOutdated);
        fs::write(f.path(), vec![b'x'; MAX_SKILL_BYTES as usize + 1]).unwrap();
        let row = f.read();
        assert_eq!(row.status, SkillStatus::Unsupported);
        assert_eq!(row.error_code, Some("file_too_large"));
        assert_eq!(row.installed_sha256, None);
    }

    #[test]
    fn directory_is_unsupported() {
        let f = Fixture::new();
        fs::create_dir_all(f.path()).unwrap();
        assert_eq!(f.read().error_code, Some("non_regular_file"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_including_dangling_ones_are_not_followed() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new();
        f.prepare();
        let target = f.0.join("target");
        symlink(&target, f.path()).unwrap();
        assert_eq!(f.read().error_code, Some("symlink"));
        fs::write(&target, b"bundled\n").unwrap();
        assert_eq!(f.read().error_code, Some("symlink"));
        assert_eq!(fs::read(target).unwrap(), b"bundled\n");
    }

    #[cfg(unix)]
    #[test]
    fn fifo_is_rejected_before_reading() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let f = Fixture::new();
        f.prepare();
        let path = CString::new(f.path().as_os_str().as_bytes()).unwrap();
        // SAFETY: path is a live NUL-terminated string in a disposable fixture.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert_eq!(f.read().error_code, Some("non_regular_file"));
    }

    #[cfg(unix)]
    #[test]
    fn no_follow_open_rejects_symlink_and_does_not_block_on_fifo() {
        use std::{
            ffi::CString,
            os::unix::{ffi::OsStrExt, fs::symlink},
        };
        let f = Fixture::new();
        f.prepare();
        let target = f.0.join("target");
        fs::write(&target, b"bundled\n").unwrap();
        symlink(&target, f.path()).unwrap();
        assert!(open_no_follow(&f.path()).is_err());
        fs::remove_file(f.path()).unwrap();
        let path = CString::new(f.path().as_os_str().as_bytes()).unwrap();
        // SAFETY: path is a live NUL-terminated fixture path.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let file = open_no_follow(&f.path()).unwrap();
        assert_eq!(
            validate_metadata(&file.metadata().unwrap()).unwrap_err().1,
            Some("non_regular_file")
        );
    }

    #[cfg(unix)]
    #[test]
    fn replacement_with_identical_bytes_has_a_different_identity() {
        let f = Fixture::new();
        f.prepare();
        fs::write(f.path(), b"bundled\n").unwrap();
        let file = open_no_follow(&f.path()).unwrap();
        let before = file.metadata().unwrap();
        let replacement = f.0.join("replacement");
        fs::write(&replacement, b"bundled\n").unwrap();
        fs::rename(replacement, f.path()).unwrap();
        assert!(!same_metadata(
            &before,
            &fs::symlink_metadata(f.path()).unwrap()
        ));
    }

    #[cfg(unix)]
    #[test]
    fn permission_denial_is_reported_when_enforced() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        f.prepare();
        fs::write(f.path(), b"bundled\n").unwrap();
        fs::set_permissions(f.path(), fs::Permissions::from_mode(0o000)).unwrap();
        let denied = File::open(f.path()).is_err();
        let row = f.read();
        fs::set_permissions(f.path(), fs::Permissions::from_mode(0o600)).unwrap();
        if denied {
            assert_eq!(row.status, SkillStatus::Unreadable);
            assert_eq!(row.error_code, Some("permission_denied"));
            assert_eq!(row.installed_sha256, None);
        }
    }
}
