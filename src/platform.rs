use std::{
    env, fs, io,
    path::{Path, PathBuf},
};

pub fn user_home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .or_else(|| env::var_os("USERPROFILE").filter(|value| !value.is_empty()))
        .map(PathBuf::from)
}

pub fn default_data_dir() -> PathBuf {
    user_home_dir()
        .map(|home| home.join(".sniper"))
        .unwrap_or_else(|| PathBuf::from(".sniper"))
}

pub fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(not(windows))]
    {
        fs::File::open(path)?.sync_all()
    }
    #[cfg(windows)]
    {
        // Windows cannot fsync a directory through File::open. File contents
        // are synced before rename; rename uses MOVEFILE_WRITE_THROUGH here.
        if fs::metadata(path)?.is_dir() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a directory",
            ))
        }
    }
}

pub fn rename(from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<()> {
    #[cfg(not(windows))]
    {
        fs::rename(from, to)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        };

        fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
            let path = std::path::absolute(path)?;
            // canonicalize supplies the verbatim Windows prefix for long paths.
            // Only resolve the parent: the destination file need not exist yet.
            let path = match (path.parent(), path.file_name()) {
                (Some(parent), Some(name)) => fs::canonicalize(parent)?.join(name),
                _ => path,
            };
            let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
            if wide.contains(&0) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path contains a NUL",
                ));
            }
            wide.push(0);
            Ok(wide)
        }
        let from_path = from.as_ref();
        let to_path = to.as_ref();
        let from = wide_path(from_path)?;
        let to = wide_path(to_path)?;
        // No COPY_ALLOWED: persistence replacements must stay on one volume.
        // SAFETY: both paths are NUL-terminated and live for the entire call.
        if unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32)
            {
                // Rust falls back to FileRenameInfoEx with POSIX semantics.
                // This can replace a file whose previous contents are still open.
                fs::rename(from_path, to_path)
            } else {
                Err(error)
            }
        } else {
            Ok(())
        }
    }
}

pub(crate) fn truncate_journal(file: &fs::File, path: &Path) -> io::Result<()> {
    // Windows append-only handles lack FILE_WRITE_DATA, which SetEndOfFile
    // needs. Keep append semantics on the writer and use a separate handle
    // while its command queue is paused for rotation.
    #[cfg(windows)]
    let truncate = fs::OpenOptions::new().write(true).open(path)?;
    #[cfg(not(windows))]
    let truncate = {
        let _ = path;
        file
    };
    #[cfg(windows)]
    let _ = file;
    truncate.set_len(0)?;
    truncate.sync_all()
}

#[cfg(windows)]
pub(crate) fn lock_file(file: &fs::File, blocking: bool) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::ERROR_LOCK_VIOLATION,
        Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY},
        System::IO::OVERLAPPED,
    };
    let flags = LOCKFILE_EXCLUSIVE_LOCK
        | if blocking {
            0
        } else {
            LOCKFILE_FAIL_IMMEDIATELY
        };
    // SAFETY: the handle is synchronous and remains open; zero initializes
    // the byte offset and event. Windows releases the lock when it is closed.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    if unsafe { LockFileEx(file.as_raw_handle(), flags, 0, 1, 0, &mut overlapped) } != 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if !blocking && error.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
        Ok(false)
    } else {
        Err(error)
    }
}

#[cfg(windows)]
pub fn running_process_path(pid: u32) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, WAIT_TIMEOUT},
        System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, WaitForSingleObject,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        },
    };
    // SAFETY: the handle is checked before use and closed on every path.
    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        );
        if handle.is_null() {
            return None;
        }
        let mut buffer = vec![0u16; 32768];
        let mut length = buffer.len() as u32;
        let running = WaitForSingleObject(handle, 0) == WAIT_TIMEOUT;
        let queried =
            running && QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut length) != 0;
        CloseHandle(handle);
        queried.then(|| PathBuf::from(std::ffi::OsString::from_wide(&buffer[..length as usize])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_existing_file_and_syncs_directory() {
        let root = env::temp_dir()
            .join(format!("sniper-platform-{}", uuid::Uuid::new_v4()))
            .join("space 한글");
        fs::create_dir_all(&root).unwrap();
        let target = root.join("state.json");
        let temp = root.join("state.tmp");
        fs::write(&target, "old").unwrap();
        fs::write(&temp, "new").unwrap();
        fs::File::options()
            .write(true)
            .open(&temp)
            .unwrap()
            .sync_all()
            .unwrap();
        rename(&temp, &target).unwrap();
        sync_directory(&root).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
        assert!(!temp.exists());
        // Rejecting a non-directory is specific to the Windows arm, which has to
        // check because it cannot fsync a directory handle at all. On Unix the
        // idiomatic implementation is File::open(dir).sync_all(), and opening a
        // regular file and syncing it succeeds — there is nothing to fail on.
        #[cfg(windows)]
        assert!(sync_directory(&target).is_err());
        fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn resolves_current_live_process() {
        assert_eq!(
            running_process_path(std::process::id()),
            Some(env::current_exe().unwrap())
        );
        assert!(running_process_path(0).is_none());
    }
}
