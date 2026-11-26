//! Keep TCP history operations anchored to a directory opened without following
//! its final component. The containing session directory is trusted storage.
use std::{
    ffi::OsStr,
    fs::{File, Metadata, OpenOptions},
    io,
    path::{Path, PathBuf},
};

pub(super) struct HistoryDirectory {
    path: PathBuf,
    handle: File,
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "TCP history storage changed or is unsafe",
    )
}

fn is_reparse(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    }
    #[cfg(not(windows))]
    {
        metadata.is_symlink()
    }
}

impl HistoryDirectory {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let before = std::fs::symlink_metadata(path)?;
        if !before.is_dir() || is_reparse(&before) {
            return Err(invalid());
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
                FILE_SHARE_WRITE,
            };
            // Pin the directory name until all relative-path operations finish.
            options
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        }
        // Only the first lookup can establish an absent history. Once seen,
        // disappearance is a storage race, not a new empty session directory.
        let changed = |error: io::Error| {
            if error.kind() == io::ErrorKind::NotFound {
                invalid()
            } else {
                error
            }
        };
        let directory = Self {
            path: path.to_owned(),
            handle: options.open(path).map_err(changed)?,
        };
        let metadata = directory.handle.metadata()?;
        if !metadata.is_dir() || is_reparse(&metadata) {
            return Err(invalid());
        }
        directory.check_current().map_err(changed)?;
        Ok(directory)
    }

    pub(super) fn create(path: &Path) -> io::Result<Self> {
        match Self::open(path) {
            Ok(directory) => Ok(directory),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(path)?;
                #[cfg(unix)]
                {
                    use std::os::unix::ffi::OsStrExt;
                    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
                        .map_err(|_| invalid())?;
                    // mkdir's mode is filtered by umask. Restore the private
                    // mode on only the newly created directory, without ever
                    // following a final symlink introduced by a racing writer.
                    if unsafe {
                        libc::fchmodat(
                            libc::AT_FDCWD,
                            path.as_ptr(),
                            0o700,
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    } != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                Self::open(path)
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn check_current(&self) -> io::Result<()> {
        let current = std::fs::symlink_metadata(&self.path)?;
        if !current.is_dir() || is_reparse(&current) {
            return Err(invalid());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let opened = self.handle.metadata()?;
            if (current.dev(), current.ino()) != (opened.dev(), opened.ino()) {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub(super) fn entries(&self) -> io::Result<std::fs::ReadDir> {
        self.check_current()?;
        // Unix entry names can race with rename, but open_file always resolves
        // each name against our pinned descriptor, never the replacement root.
        std::fs::read_dir(&self.path)
    }

    fn child_path(&self, name: &OsStr) -> io::Result<PathBuf> {
        if Path::new(name).file_name() != Some(name) {
            return Err(invalid());
        }
        Ok(self.path.join(name))
    }

    pub(super) fn is_regular_entry(&self, name: &OsStr) -> io::Result<bool> {
        let path = self.child_path(name)?;
        self.check_current()?;
        #[cfg(unix)]
        {
            use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};
            let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid())?;
            let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: fstatat initializes the stat buffer on success. Metadata
            // lookup is relative to our pinned root and never follows a link.
            if unsafe {
                libc::fstatat(
                    self.handle.as_raw_fd(),
                    name.as_ptr(),
                    metadata.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            let metadata = unsafe { metadata.assume_init() };
            let _ = path;
            Ok(metadata.st_mode & libc::S_IFMT == libc::S_IFREG)
        }
        #[cfg(not(unix))]
        {
            let metadata = std::fs::symlink_metadata(path)?;
            Ok(metadata.is_file() && !is_reparse(&metadata))
        }
    }

    pub(super) fn open_file(&self, name: &OsStr) -> io::Result<File> {
        let path = self.child_path(name)?;
        self.check_current()?;
        #[cfg(unix)]
        let file = self.open_at(name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
        #[cfg(not(unix))]
        let file = {
            let metadata = std::fs::symlink_metadata(&path)?;
            if !metadata.is_file() || is_reparse(&metadata) {
                return Err(invalid());
            }
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                options.custom_flags(
                    windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
                );
            }
            options.open(&path)?
        };
        let _ = path;
        let metadata = file.metadata()?;
        if !metadata.is_file() || is_reparse(&metadata) {
            return Err(invalid());
        }
        self.check_current()?;
        Ok(file)
    }

    /// Deletes one record by name, relative to the pinned root.
    pub(super) fn remove_file(&self, name: &OsStr) -> io::Result<()> {
        let path = self.child_path(name)?;
        self.check_current()?;
        #[cfg(unix)]
        {
            use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};
            let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid())?;
            let _ = path;
            // SAFETY: the directory descriptor and NUL-terminated name stay alive.
            if unsafe { libc::unlinkat(self.handle.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            if !self.is_regular_entry(name)? {
                return Err(invalid());
            }
            std::fs::remove_file(path)
        }
    }

    #[cfg(unix)]
    fn open_at(&self, name: &OsStr, flags: i32, mode: libc::mode_t) -> io::Result<File> {
        use std::os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        };
        let name = std::ffi::CString::new(name.as_bytes()).map_err(|_| invalid())?;
        // SAFETY: the directory descriptor and NUL-terminated name stay alive;
        // on success the returned descriptor is uniquely owned by File.
        let fd = unsafe {
            libc::openat(
                self.handle.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                // C variadic arguments require integer promotion: mode_t is
                // only u16 on Darwin, so passing it directly fails to compile.
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    pub(super) fn write_json(
        &self,
        name: &OsStr,
        value: &impl serde::Serialize,
    ) -> anyhow::Result<()> {
        let destination = self.child_path(name)?;
        self.check_current()?;
        // Do not replace a link, directory or special file, even though rename
        // itself would not follow a final symlink on Unix.
        match self.open_file(name) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        #[cfg(not(unix))]
        {
            // Keep the existing platform-specific permissions and durability
            // handling; on Windows our directory handle denies replacement.
            crate::session::write_json(&destination, value)?;
            self.check_current()?;
            Ok(())
        }
        #[cfg(unix)]
        {
            use std::io::Write;
            let temporary = destination.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
            let temporary_name = temporary.file_name().ok_or_else(invalid)?;
            let mut file = self.open_at(
                temporary_name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )?;
            {
                use std::os::unix::fs::PermissionsExt;
                // Like the shared session writer, do not let a restrictive
                // umask make a successfully persisted capture unreadable.
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            {
                let mut writer = io::BufWriter::new(&mut file);
                serde_json::to_writer_pretty(&mut writer, value)?;
                writer.flush()?;
            }
            file.sync_all()?;
            self.publish_file(temporary_name, name, &file)?;
            // Failure never claims durability, so the caller retains the full
            // in-memory capture. Unpublished files remain available for recovery.
            Ok(())
        }
    }

    #[cfg(unix)]
    fn publish_file(
        &self,
        temporary: &OsStr,
        destination: &OsStr,
        file: &File,
    ) -> anyhow::Result<()> {
        use std::os::{
            fd::AsRawFd,
            unix::{ffi::OsStrExt, fs::MetadataExt},
        };
        let expected = file.metadata()?;
        let same_file = |metadata: Metadata| {
            metadata.is_file()
                && (metadata.dev(), metadata.ino()) == (expected.dev(), expected.ino())
        };
        self.check_current()?;
        anyhow::ensure!(
            same_file(self.open_file(temporary)?.metadata()?),
            "TCP temporary file changed"
        );
        let from = std::ffi::CString::new(temporary.as_bytes())?;
        let to = std::ffi::CString::new(destination.as_bytes())?;
        // SAFETY: both names and the pinned directory descriptor remain valid;
        // replacement of the root cannot redirect this rename.
        if unsafe {
            libc::renameat(
                self.handle.as_raw_fd(),
                from.as_ptr(),
                self.handle.as_raw_fd(),
                to.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        self.handle.sync_all()?;
        // Keep the original descriptor alive through publication. If a writer
        // swaps the temp name after the precheck, do not claim its replacement
        // is durable and release our sole in-memory copy of the actual capture.
        anyhow::ensure!(
            same_file(self.open_file(destination)?.metadata()?),
            "TCP published file changed"
        );
        self.check_current()?;
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn swapped_temporary_file_cannot_claim_durable_success() {
        let root = std::env::temp_dir().join(format!("sniper-tcp-swap-{}", uuid::Uuid::new_v4()));
        let directory = HistoryDirectory::create(&root).unwrap();
        let name = OsStr::new("record.json");
        let temporary = OsStr::new("record.tmp-test");
        std::fs::write(root.join(name), b"previous").unwrap();
        let original = directory
            .open_at(
                temporary,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            )
            .unwrap();
        std::fs::rename(root.join(temporary), root.join("held")).unwrap();
        std::fs::write(root.join(temporary), b"replacement").unwrap();
        assert!(directory.publish_file(temporary, name, &original).is_err());
        assert_eq!(std::fs::read(root.join(name)).unwrap(), b"previous");
        assert_eq!(std::fs::read(root.join(temporary)).unwrap(), b"replacement");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restrictive_umask_still_produces_private_readable_history() {
        // umask is process-wide; run the mutation in a single-test subprocess,
        // never perturb unrelated parallel tests or the developer's process.
        if std::env::var_os("SNIPER_TCP_TEST_UMASK").is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tcp_capture::history_io::tests::restrictive_umask_still_produces_private_readable_history", "--nocapture"])
                .env("SNIPER_TCP_TEST_UMASK", "1")
                .status().unwrap();
            assert!(result.success());
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let previous = unsafe { libc::umask(0o777) };
        let root = std::env::temp_dir().join(format!("sniper-tcp-mode-{}", uuid::Uuid::new_v4()));
        let directory = HistoryDirectory::create(&root).unwrap();
        directory
            .write_json(OsStr::new("record.json"), &"capture")
            .unwrap();
        unsafe {
            libc::umask(previous);
        }
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(root.join("record.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::read(root.join("record.json")).unwrap(),
            b"\"capture\""
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_descriptor_never_resolves_a_replacement_root() {
        let base = std::env::temp_dir().join(format!("sniper-tcp-pin-{}", uuid::Uuid::new_v4()));
        let root = base.join("history");
        let external = base.join("external");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir(&external).unwrap();
        std::fs::write(root.join("record.json"), b"original").unwrap();
        std::fs::write(external.join("record.json"), b"external").unwrap();
        let pinned = HistoryDirectory::open(&root).unwrap();
        let held = base.join("held");
        std::fs::rename(&root, &held).unwrap();
        std::os::unix::fs::symlink(&external, &root).unwrap();
        // Model replacement after check_current but before openat. Even at that
        // exact race boundary the descriptor resolves only the original root.
        let mut file = pinned
            .open_at(OsStr::new("record.json"), libc::O_RDONLY, 0)
            .unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
        assert!(pinned.open_file(OsStr::new("record.json")).is_err());
        assert!(pinned
            .write_json(OsStr::new("record.json"), &"replacement")
            .is_err());
        assert_eq!(
            std::fs::read(external.join("record.json")).unwrap(),
            b"external"
        );
        assert_eq!(
            std::fs::read(held.join("record.json")).unwrap(),
            b"original"
        );
        std::fs::remove_dir_all(base).unwrap();
    }
}
