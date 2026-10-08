//! Opt-in, per-user registration of the CLI shipped beside the desktop app.
//!
//! Keep the snapshot format in sync with packaging/windows/sniper.iss. We append
//! rather than prepend, never claim an existing entry, and retain exact registry
//! snapshots so the installer can undo only a change it still owns.

const REG_STRING: u32 = 1;
const REG_EXPAND_STRING: u32 = 2;
const MAX_PATH_UNITS: usize = 32_767;

#[derive(Clone, Debug, Eq, PartialEq)]
struct RawValue {
    kind: u32,
    bytes: Vec<u8>,
}

impl RawValue {
    fn string(kind: u32, value: &str) -> Self {
        Self {
            kind,
            bytes: value
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect(),
        }
    }

    fn path_text(&self) -> Result<String, String> {
        if !matches!(self.kind, REG_STRING | REG_EXPAND_STRING) {
            return Err("PATH has an unsupported registry type; it was left unchanged.".into());
        }
        if self.bytes.len() < 2 || self.bytes.len() % 2 != 0 {
            return Err(
                "PATH is not a valid UTF-16 registry string; it was left unchanged.".into(),
            );
        }
        let units: Vec<u16> = self
            .bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        if units.len() > MAX_PATH_UNITS || units.last() != Some(&0) {
            return Err("PATH is too long or lacks its terminator; it was left unchanged.".into());
        }
        if units[..units.len() - 1].contains(&0) {
            return Err("PATH contains an embedded NUL; it was left unchanged.".into());
        }
        String::from_utf16(&units[..units.len() - 1])
            .map_err(|_| "PATH contains invalid UTF-16; it was left unchanged.".into())
    }
}

fn validate_directory_text(directory: &str) -> Result<(), String> {
    if directory.is_empty()
        || directory
            .chars()
            .any(|ch| matches!(ch, ';' | '%' | '"') || ch.is_control())
    {
        return Err("This app directory cannot be represented safely in Windows PATH.".into());
    }
    Ok(())
}

fn append_path(before: Option<&RawValue>, directory: &str) -> Result<RawValue, String> {
    validate_directory_text(directory)?;
    let (kind, old) = match before {
        Some(value) => (value.kind, value.path_text()?),
        None => (REG_EXPAND_STRING, String::new()),
    };
    // An existing trailing separator represents an empty search entry. Keep it
    // rather than silently removing or replacing it during registration.
    let separator = if old.is_empty() { "" } else { ";" };
    if old.encode_utf16().count() + separator.len() + directory.encode_utf16().count() + 1
        > MAX_PATH_UNITS
    {
        return Err(
            "Adding this app would exceed the Windows PATH limit; PATH was left unchanged.".into(),
        );
    }
    Ok(RawValue::string(
        kind,
        &format!("{old}{separator}{directory}"),
    ))
}

fn effective_path(
    value: Option<&RawValue>,
    expand: impl FnOnce(&str) -> Result<String, String>,
) -> Result<String, String> {
    match value {
        Some(value) => {
            let raw = value.path_text()?;
            if value.kind == REG_EXPAND_STRING {
                expand(&raw)
            } else {
                Ok(raw)
            }
        }
        None => Ok(String::new()),
    }
}

fn path_entries(path: &str) -> Result<Vec<&str>, String> {
    let mut entries = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    for (index, ch) in path.char_indices() {
        match ch {
            '"' => quoted = !quoted,
            ';' if !quoted => {
                entries.push(&path[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    entries.push(&path[start..]);
    if quoted
        || entries
            .iter()
            .any(|entry| unquote_entry(entry).contains('"'))
    {
        return Err(
            "PATH has unsupported or unbalanced quotation marks; it was left unchanged.".into(),
        );
    }
    Ok(entries)
}

fn has_equivalent_entry(
    path: &str,
    directory: &str,
    mut equivalent: impl FnMut(&str, &str) -> Result<bool, String>,
) -> Result<bool, String> {
    for entry in path_entries(path)?
        .into_iter()
        .filter(|entry| !entry.trim().is_empty())
    {
        if equivalent(entry, directory)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn prior_registration_conflict(registered: bool, marker_exists: bool) -> Option<String> {
    (!registered && marker_exists).then(|| {
        "An earlier Sniper PATH registration exists. Run this folder's sniper-cli.exe directly, or edit the existing user PATH entry in Windows Environment Variables to this app folder. PATH was left unchanged to preserve uninstall information.".into()
    })
}

fn command_extensions(pathext: Option<&str>) -> Result<Vec<String>, String> {
    let mut extensions = vec![
        ".com".to_string(),
        ".exe".into(),
        ".bat".into(),
        ".cmd".into(),
    ];
    if let Some(pathext) = pathext {
        for extension in pathext
            .split(';')
            .map(str::trim)
            .filter(|extension| !extension.is_empty())
        {
            if !extension.starts_with('.')
                || extension.len() < 2
                || !extension[1..].chars().all(|ch| ch.is_ascii_alphanumeric())
            {
                return Err("PATHEXT contains an unsupported command extension, so existing commands could not be checked safely. PATH was left unchanged.".into());
            }
            if !extensions
                .iter()
                .any(|known| known.eq_ignore_ascii_case(extension))
            {
                extensions.push(extension.to_string());
            }
        }
    }
    Ok(extensions)
}

fn first_command_conflict(
    paths: &[String],
    extensions: &[String],
    mut locate: impl FnMut(&str, &str) -> Result<Option<String>, String>,
    mut same_bundled_cli: impl FnMut(&str) -> Result<bool, String>,
) -> Result<Option<String>, String> {
    for path in paths {
        for entry in path_entries(path)? {
            for extension in extensions {
                if let Some(candidate) = locate(unquote_entry(entry), extension)? {
                    if !extension.eq_ignore_ascii_case(".exe") || !same_bundled_cli(&candidate)? {
                        return Ok(Some(candidate));
                    }
                }
            }
        }
    }
    Ok(None)
}

// The native adapter supplies registry IO; this ordering is also exercised with
// an in-memory store so failures never need a real user's registry to be tested.
trait RegistrationStore {
    fn save_new_marker(
        &mut self,
        before: Option<&RawValue>,
        after: &RawValue,
    ) -> Result<(), String>;
    fn read_path(&mut self) -> Result<Option<RawValue>, String>;
    fn write_path(&mut self, value: &RawValue) -> Result<(), String>;
    fn discard_new_marker(&mut self) -> Result<(), String>;
}

fn commit_registration(
    store: &mut impl RegistrationStore,
    before: Option<&RawValue>,
    after: &RawValue,
) -> Result<bool, String> {
    store.save_new_marker(before, after)?;
    let write = (|| {
        if store.read_path()?.as_ref() != before {
            return Err("PATH changed during setup. It was left unchanged; try again.".into());
        }
        store.write_path(after)
    })();
    if let Err(mut error) = write {
        if let Err(cleanup) = store.discard_new_marker() {
            error.push_str(&format!(
                " The unused ownership record could not be removed: {cleanup}"
            ));
        }
        return Err(error);
    }
    // Once the PATH write succeeds, the marker must survive even if verification
    // fails or another process immediately edits PATH. Uninstall then fails safe.
    Ok(matches!(store.read_path(), Ok(Some(value)) if &value == after))
}

fn unquote_entry(entry: &str) -> &str {
    let entry = entry.trim();
    entry
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(entry)
}

fn normalize_entry(entry: &str) -> String {
    let entry = unquote_entry(entry).replace('/', "\\");
    let entry = if entry.starts_with("\\\\?\\UNC\\") {
        format!("\\\\{}", &entry[8..])
    } else {
        entry.strip_prefix("\\\\?\\").unwrap_or(&entry).to_owned()
    };
    // C:\ and C: have different semantics; retain the root separator.
    let minimum = if entry.as_bytes().get(1) == Some(&b':') {
        3
    } else {
        1
    };
    let mut entry = entry;
    while entry.len() > minimum && entry.ends_with('\\') {
        entry.pop();
    }
    entry
}

#[cfg(windows)]
pub(super) struct WindowsPathStatus {
    pub(super) registered: bool,
    pub(super) conflict: Option<String>,
}

#[cfg(windows)]
pub(super) fn inspect(directory: &std::path::Path) -> Result<WindowsPathStatus, String> {
    native::inspect(directory)
}

#[cfg(windows)]
pub(super) fn install(directory: &std::path::Path) -> Result<super::CliPathInstall, String> {
    native::install(directory)
}

#[cfg(windows)]
mod native {
    use super::{
        append_path, command_extensions, commit_registration, effective_path,
        first_command_conflict, has_equivalent_entry, normalize_entry, prior_registration_conflict,
        unquote_entry, validate_directory_text, RawValue, RegistrationStore,
    };
    use super::{WindowsPathStatus, MAX_PATH_UNITS, REG_STRING};
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS, HANDLE,
        WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};
    use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteKeyExW, RegOpenKeyExW, RegQueryValueExW,
        RegSetValueExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE,
        KEY_SET_VALUE, KEY_WOW64_64KEY, REG_CREATED_NEW_KEY, REG_DWORD, REG_OPTION_NON_VOLATILE,
    };
    use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
    };

    const USER_ENVIRONMENT: &str = "Environment";
    const MACHINE_ENVIRONMENT: &str =
        "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
    const OWNERSHIP_KEY: &str = "Software\\Sniper\\CliPath";
    const MUTEX_NAME: &str = "Local\\SniperCliPathRegistration";
    const PATH_LABEL: &str = "User PATH (HKCU\\Environment)";

    fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
        value
            .as_ref()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn failure(operation: &str, status: u32) -> String {
        format!(
            "{operation}: {} (Windows error {status}).",
            std::io::Error::from_raw_os_error(status as i32)
        )
    }

    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }

    impl Key {
        fn open(root: HKEY, name: &str, writable: bool) -> Result<Option<Self>, String> {
            let mut handle = null_mut();
            let flags =
                KEY_QUERY_VALUE | KEY_WOW64_64KEY | if writable { KEY_SET_VALUE } else { 0 };
            let status = unsafe { RegOpenKeyExW(root, wide(name).as_ptr(), 0, flags, &mut handle) };
            match status {
                ERROR_SUCCESS => Ok(Some(Self(handle))),
                ERROR_FILE_NOT_FOUND => Ok(None),
                _ => Err(failure("Could not read the Windows PATH settings", status)),
            }
        }

        fn create(root: HKEY, name: &str) -> Result<(Self, bool), String> {
            let mut handle = null_mut();
            let mut disposition = 0;
            let status = unsafe {
                RegCreateKeyExW(
                    root,
                    wide(name).as_ptr(),
                    0,
                    null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY,
                    null(),
                    &mut handle,
                    &mut disposition,
                )
            };
            if status == ERROR_SUCCESS {
                Ok((Self(handle), disposition == REG_CREATED_NEW_KEY))
            } else {
                Err(failure(
                    "Could not open the user PATH settings for writing",
                    status,
                ))
            }
        }

        fn read(&self, name: &str) -> Result<Option<RawValue>, String> {
            let name = wide(name);
            // Registry values can change between sizing and reading. Retry with a
            // fresh buffer, bounded in both size and attempts; never truncate.
            for _ in 0..4 {
                let mut kind = 0;
                let mut length = 0;
                let status = unsafe {
                    RegQueryValueExW(
                        self.0,
                        name.as_ptr(),
                        null(),
                        &mut kind,
                        null_mut(),
                        &mut length,
                    )
                };
                if status == ERROR_FILE_NOT_FOUND {
                    return Ok(None);
                }
                if status != ERROR_SUCCESS {
                    return Err(failure("Could not read the Windows PATH value", status));
                }
                if length as usize > MAX_PATH_UNITS * 2 {
                    return Err("The registry PATH value exceeds the safe Windows limit; it was left unchanged.".into());
                }
                let mut bytes = vec![0u8; length as usize];
                let status = unsafe {
                    RegQueryValueExW(
                        self.0,
                        name.as_ptr(),
                        null(),
                        &mut kind,
                        bytes.as_mut_ptr(),
                        &mut length,
                    )
                };
                match status {
                    ERROR_SUCCESS => {
                        bytes.truncate(length as usize);
                        return Ok(Some(RawValue { kind, bytes }));
                    }
                    ERROR_FILE_NOT_FOUND => return Ok(None),
                    ERROR_MORE_DATA => continue,
                    _ => return Err(failure("Could not read the Windows PATH value", status)),
                }
            }
            Err(
                "PATH kept changing while it was read. Try again after other installers finish."
                    .into(),
            )
        }

        fn write(&self, name: &str, value: &RawValue) -> Result<(), String> {
            let length = u32::try_from(value.bytes.len())
                .map_err(|_| "Registry value is too large.".to_string())?;
            let status = unsafe {
                RegSetValueExW(
                    self.0,
                    wide(name).as_ptr(),
                    0,
                    value.kind,
                    value.bytes.as_ptr(),
                    length,
                )
            };
            if status == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(failure("Could not save the user PATH settings", status))
            }
        }

        fn write_dword(&self, name: &str, value: u32) -> Result<(), String> {
            self.write(
                name,
                &RawValue {
                    kind: REG_DWORD,
                    bytes: value.to_le_bytes().to_vec(),
                },
            )
        }
    }

    struct RegistrationLock(HANDLE);

    impl RegistrationLock {
        fn acquire() -> Result<Self, String> {
            let handle = unsafe { CreateMutexW(null(), 0, wide(MUTEX_NAME).as_ptr()) };
            if handle.is_null() {
                return Err(failure("Could not lock PATH registration", unsafe {
                    GetLastError()
                }));
            }
            match unsafe { WaitForSingleObject(handle, 5_000) } {
                WAIT_OBJECT_0 => Ok(Self(handle)),
                WAIT_ABANDONED => {
                    // Ownership was acquired, but a previous writer was interrupted.
                    // Release it without changing its potentially incomplete snapshot.
                    drop(Self(handle));
                    Err("A previous PATH setup was interrupted. Check the PATH settings before retrying.".into())
                }
                outcome => {
                    let error = if outcome == WAIT_TIMEOUT {
                        "Another Sniper installer is updating PATH. Wait for it to finish, then try again.".into()
                    } else {
                        failure("Could not lock PATH registration", unsafe {
                            GetLastError()
                        })
                    };
                    unsafe {
                        CloseHandle(handle);
                    }
                    Err(error)
                }
            }
        }
    }

    impl Drop for RegistrationLock {
        fn drop(&mut self) {
            unsafe {
                ReleaseMutex(self.0);
                CloseHandle(self.0);
            }
        }
    }

    fn validate_directory(directory: &Path) -> Result<String, String> {
        let text = directory
            .to_str()
            .ok_or("The app directory is not valid Unicode.")?;
        validate_directory_text(text)?;
        if !directory.is_absolute()
            || !directory.is_dir()
            || !directory.join("sniper-cli.exe").is_file()
            || !directory.join("sniper-desktop.exe").is_file()
        {
            return Err(
                "PATH setup requires sniper-cli.exe beside the installed sniper-desktop.exe."
                    .into(),
            );
        }
        let current = std::env::current_exe()
            .map_err(|error| format!("Could not locate the running desktop app: {error}"))?;
        if !equivalent(
            &current.to_string_lossy(),
            &directory.join("sniper-desktop.exe").to_string_lossy(),
        )? {
            return Err(
                "PATH setup is only available from the bundled Windows desktop app.".into(),
            );
        }
        Ok(normalize_entry(text))
    }

    fn expand(value: &str) -> Result<String, String> {
        let input = wide(value);
        let mut required = unsafe { ExpandEnvironmentStringsW(input.as_ptr(), null_mut(), 0) };
        for _ in 0..3 {
            if required == 0 {
                return Err(failure("Could not expand a PATH entry", unsafe {
                    GetLastError()
                }));
            }
            if required as usize > MAX_PATH_UNITS {
                return Err("An expanded PATH entry exceeds the Windows limit.".into());
            }
            let mut result = vec![0u16; required as usize];
            let written =
                unsafe { ExpandEnvironmentStringsW(input.as_ptr(), result.as_mut_ptr(), required) };
            if written > required {
                required = written;
                continue;
            }
            if written == 0 {
                return Err(failure("Could not expand a PATH entry", unsafe {
                    GetLastError()
                }));
            }
            result.truncate(written as usize - 1);
            return String::from_utf16(&result)
                .map_err(|_| "An expanded PATH entry is not valid Unicode.".into());
        }
        Err("Environment variables kept changing while PATH was checked. Try again.".into())
    }

    fn normalized_existing(value: &str) -> Result<String, String> {
        let unquoted = unquote_entry(value);
        let path = Path::new(unquoted);
        let value = match std::fs::canonicalize(path) {
            Ok(canonical) => canonical.to_string_lossy().into_owned(),
            Err(_) => unquoted.to_string(),
        };
        Ok(normalize_entry(&value))
    }

    fn equivalent(left: &str, right: &str) -> Result<bool, String> {
        let left: Vec<u16> = normalized_existing(left)?.encode_utf16().collect();
        let right: Vec<u16> = normalized_existing(right)?.encode_utf16().collect();
        let result = unsafe {
            CompareStringOrdinal(
                left.as_ptr(),
                left.len() as i32,
                right.as_ptr(),
                right.len() as i32,
                1,
            )
        };
        if result == 0 {
            Err(failure("Could not compare PATH entries", unsafe {
                GetLastError()
            }))
        } else {
            Ok(result == CSTR_EQUAL)
        }
    }

    fn contains_directory(path: &str, directory: &str) -> Result<bool, String> {
        has_equivalent_entry(path, directory, equivalent)
    }

    fn read_path(root: HKEY, key: &str) -> Result<Option<RawValue>, String> {
        match Key::open(root, key, false)? {
            Some(key) => key.read("Path"),
            None => Ok(None),
        }
    }

    fn text(value: Option<&RawValue>) -> Result<String, String> {
        value
            .map(RawValue::path_text)
            .transpose()
            .map(|value| value.unwrap_or_default())
    }

    fn find_conflict(paths: &[String], directory: &str) -> Result<Option<String>, String> {
        let pathext = std::env::var_os("PATHEXT")
            .map(|value| {
                value.into_string().map_err(|_| {
                    "PATHEXT is not valid Unicode; PATH was left unchanged.".to_string()
                })
            })
            .transpose()?;
        let extensions = command_extensions(pathext.as_deref())?;
        let bundled_cli = Path::new(directory).join("sniper-cli.exe");
        first_command_conflict(paths, &extensions, |entry, extension| {
            let base = if entry.is_empty() {
                std::env::current_dir().map_err(|error| format!("Could not check the current search directory: {error}"))?
            } else { PathBuf::from(entry) };
            let candidate = base.join(format!("sniper-cli{extension}"));
            match std::fs::metadata(&candidate) {
                Ok(metadata) if metadata.is_file() => candidate.into_os_string().into_string().map(Some)
                    .map_err(|_| "A sniper-cli search location is not valid Unicode; PATH was left unchanged.".into()),
                Ok(_) => Ok(None),
                Err(error) if matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory) => Ok(None),
                Err(error) => Err(format!("Could not check {} for an existing sniper-cli command: {error}. PATH was left unchanged.", candidate.display())),
            }
        }, |candidate| equivalent(candidate, &bundled_cli.to_string_lossy()))
        .map(|conflict| conflict.map(|candidate| format!("Another sniper-cli command is already on PATH at {candidate}. PATH was left unchanged.")))
    }

    fn status(directory: &str, user_path: Option<&RawValue>) -> Result<WindowsPathStatus, String> {
        let user_text = effective_path(user_path, expand)?;
        let machine_path = read_path(HKEY_LOCAL_MACHINE, MACHINE_ENVIRONMENT)?;
        let machine_text = effective_path(machine_path.as_ref(), expand)?;
        let registered = contains_directory(&user_text, directory)?
            || contains_directory(&machine_text, directory)?;
        let process_text = std::env::var_os("PATH")
            .map(|value| {
                value.into_string().map_err(|_| {
                    "The process PATH is not valid Unicode; PATH was left unchanged.".to_string()
                })
            })
            .transpose()?
            .unwrap_or_default();
        // Registering a new directory also exposes its other command extensions.
        // Check it even when it is absent from every current PATH source.
        let mut conflict = find_conflict(
            &[machine_text, user_text, process_text, directory.to_string()],
            directory,
        )?;
        if conflict.is_none() && !registered {
            conflict = prior_registration_conflict(
                false,
                Key::open(HKEY_CURRENT_USER, OWNERSHIP_KEY, false)?.is_some(),
            );
        }
        Ok(WindowsPathStatus {
            registered,
            conflict,
        })
    }

    pub(super) fn inspect(directory: &Path) -> Result<WindowsPathStatus, String> {
        let directory = validate_directory(directory)?;
        let user_path = read_path(HKEY_CURRENT_USER, USER_ENVIRONMENT)?;
        status(&directory, user_path.as_ref())
    }

    fn write_ownership(
        key: &Key,
        directory: &str,
        before: Option<&RawValue>,
        after: &RawValue,
    ) -> Result<(), String> {
        key.write("Directory", &RawValue::string(REG_STRING, directory))?;
        key.write(
            "OwnerExecutable",
            &RawValue::string(
                REG_STRING,
                &Path::new(directory)
                    .join("sniper-desktop.exe")
                    .to_string_lossy(),
            ),
        )?;
        key.write("BeforePath", &RawValue::string(REG_STRING, &text(before)?))?;
        key.write(
            "AfterPath",
            &RawValue::string(REG_STRING, &after.path_text()?),
        )?;
        key.write_dword("PathType", after.kind)?;
        key.write_dword("BeforePresent", u32::from(before.is_some()))?;
        // Publishing the version last prevents a partial marker being mistaken
        // for a complete ownership record after a crash or write failure.
        key.write_dword("SchemaVersion", 1)
    }

    struct RegistryStore<'a> {
        environment: Key,
        marker: Option<Key>,
        directory: &'a str,
    }

    impl RegistrationStore for RegistryStore<'_> {
        fn save_new_marker(
            &mut self,
            before: Option<&RawValue>,
            after: &RawValue,
        ) -> Result<(), String> {
            let (marker, created) = Key::create(HKEY_CURRENT_USER, OWNERSHIP_KEY)?;
            if !created {
                return Err(
                    "Another Sniper PATH ownership record appeared. PATH was left unchanged."
                        .into(),
                );
            }
            self.marker = Some(marker);
            if let Err(mut error) =
                write_ownership(self.marker.as_ref().unwrap(), self.directory, before, after)
            {
                if let Err(cleanup) = self.discard_new_marker() {
                    error.push_str(&format!(
                        " The unused ownership record could not be removed: {cleanup}"
                    ));
                }
                return Err(error);
            }
            Ok(())
        }

        fn read_path(&mut self) -> Result<Option<RawValue>, String> {
            self.environment.read("Path")
        }

        fn write_path(&mut self, value: &RawValue) -> Result<(), String> {
            self.environment.write("Path", value)
        }

        fn discard_new_marker(&mut self) -> Result<(), String> {
            drop(self.marker.take());
            // Delete only the new marker, in the same view in which it was created.
            // This is not recursive: an unexpected subkey prevents deletion.
            let status = unsafe {
                RegDeleteKeyExW(
                    HKEY_CURRENT_USER,
                    wide(OWNERSHIP_KEY).as_ptr(),
                    KEY_WOW64_64KEY,
                    0,
                )
            };
            if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
                Ok(())
            } else {
                Err(failure(
                    "Could not remove the incomplete PATH ownership record",
                    status,
                ))
            }
        }
    }

    pub(super) fn install(directory: &Path) -> Result<super::super::CliPathInstall, String> {
        let directory = validate_directory(directory)?;
        let _lock = RegistrationLock::acquire()?;
        let before = read_path(HKEY_CURRENT_USER, USER_ENVIRONMENT)?;
        let existing = status(&directory, before.as_ref())?;
        if let Some(conflict) = existing.conflict {
            return Err(conflict);
        }
        if existing.registered {
            return Ok(super::super::CliPathInstall {
                unchanged: vec![PATH_LABEL.into()],
                message: "The bundled sniper-cli directory is already on PATH. Open a new terminal to use it.".into(),
                ..Default::default()
            });
        }
        if Key::open(HKEY_CURRENT_USER, OWNERSHIP_KEY, false)?.is_some() {
            return Err(prior_registration_conflict(false, true).unwrap());
        }
        let after = append_path(before.as_ref(), &directory)?;
        let (environment, _) = Key::create(HKEY_CURRENT_USER, USER_ENVIRONMENT)?;
        let mut store = RegistryStore {
            environment,
            marker: None,
            directory: &directory,
        };
        // The mutex serializes Sniper's runtime and installer. Other software does
        // not honor it, so the adapter also re-reads before its single PATH write.
        let verified = commit_registration(&mut store, before.as_ref(), &after)?;
        let mut result = super::super::CliPathInstall {
            updated: vec![PATH_LABEL.into()],
            message:
                "Added the bundled sniper-cli to your user PATH. Open a new terminal to use it."
                    .into(),
            ..Default::default()
        };
        if !verified {
            result.warnings.push("PATH changed again after registration. Check your Windows environment settings before retrying.".into());
        }
        // The durable change is complete; do not hold up another installer while
        // unrelated application windows process the environment notification.
        drop(_lock);
        let environment_name = wide("Environment");
        let delivered = unsafe {
            SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                environment_name.as_ptr() as isize,
                SMTO_ABORTIFHUNG,
                2_000,
                null_mut(),
            )
        };
        if delivered == 0 {
            result.warnings.push("Windows did not acknowledge the environment notification. You may need to sign out and back in before new terminals see the change.".into());
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_without_reordering_or_rewriting_existing_entries() {
        let before = RawValue::string(
            REG_EXPAND_STRING,
            "\"C:\\Old Tools\";%SystemRoot%\\System32;",
        );
        let after = append_path(Some(&before), "C:\\Sniper").unwrap();
        assert_eq!(after.kind, REG_EXPAND_STRING);
        assert_eq!(
            after.path_text().unwrap(),
            "\"C:\\Old Tools\";%SystemRoot%\\System32;;C:\\Sniper"
        );
        assert!(after
            .bytes
            .starts_with(&before.bytes[..before.bytes.len() - 2]));
    }

    #[test]
    fn preserves_plain_string_type_and_unicode() {
        let before = RawValue::string(REG_STRING, "C:\\工具;C:\\Other");
        let after = append_path(Some(&before), "C:\\Users\\Tester\\Sniper β").unwrap();
        assert_eq!(after.kind, REG_STRING);
        assert_eq!(
            after.path_text().unwrap(),
            "C:\\工具;C:\\Other;C:\\Users\\Tester\\Sniper β"
        );
    }

    #[test]
    fn missing_and_empty_path_have_no_leading_empty_search_entry() {
        assert_eq!(
            append_path(None, "C:\\Sniper").unwrap(),
            RawValue::string(REG_EXPAND_STRING, "C:\\Sniper")
        );
        assert_eq!(
            append_path(Some(&RawValue::string(REG_STRING, "")), "C:\\Sniper").unwrap(),
            RawValue::string(REG_STRING, "C:\\Sniper")
        );
    }

    #[test]
    fn refuses_malformed_registry_values_without_truncating_them() {
        for bytes in [
            vec![],
            vec![65],
            vec![65, 0],
            vec![65, 0, 0, 0, 0, 0],
            vec![0, 216, 0, 0],
        ] {
            assert!(append_path(
                Some(&RawValue {
                    kind: REG_STRING,
                    bytes
                }),
                "C:\\Sniper"
            )
            .is_err());
        }
        assert!(append_path(
            Some(&RawValue {
                kind: 7,
                bytes: vec![0, 0]
            }),
            "C:\\Sniper"
        )
        .is_err());
    }

    #[test]
    fn refuses_unsafe_directory_characters() {
        for directory in [
            "",
            "C:\\A;B",
            "C:\\%APP%",
            "C:\\A\nB",
            "C:\\A\rB",
            "C:\\A\0B",
            "C:\\A\"B",
        ] {
            assert!(append_path(None, directory).is_err(), "{directory:?}");
        }
    }

    #[test]
    fn refuses_oversized_values_instead_of_truncating() {
        let before = RawValue::string(REG_STRING, &"x".repeat(MAX_PATH_UNITS - 2));
        assert!(append_path(Some(&before), "C:\\Sniper").is_err());
        assert!(append_path(None, &"x".repeat(MAX_PATH_UNITS)).is_err());
    }

    #[test]
    fn normalizes_quotes_separators_and_extended_prefix_without_losing_drive_root() {
        assert_eq!(
            normalize_entry(" \"C:/Program Files/Sniper/\" "),
            "C:\\Program Files\\Sniper"
        );
        assert_eq!(normalize_entry("C:\\\\"), "C:\\");
        assert_eq!(normalize_entry("C:"), "C:");
        assert_eq!(normalize_entry("\\\\?\\C:\\Sniper\\"), "C:\\Sniper");
        assert_eq!(
            normalize_entry("\\\\?\\UNC\\server\\share\\"),
            "\\\\server\\share"
        );
    }

    #[test]
    fn equivalent_existing_entries_are_found_without_claiming_ownership() {
        fn mock_equal(left: &str, right: &str) -> Result<bool, String> {
            let resolve = |value: &str| {
                normalize_entry(
                    &value.replace("%LOCALAPPDATA%", "C:\\Users\\Tester\\AppData\\Local"),
                )
                .to_uppercase()
            };
            Ok(resolve(left) == resolve(right))
        }
        let directory = "C:\\Users\\Tester\\AppData\\Local\\Sniper";
        for path in [
            "C:\\Other;C:\\USERS\\TESTER\\APPDATA\\LOCAL\\SNIPER\\",
            "C:\\Other;\"C:/Users/Tester/AppData/Local/Sniper/\"",
            "C:\\Other;%LOCALAPPDATA%\\Sniper",
        ] {
            assert!(has_equivalent_entry(path, directory, mock_equal).unwrap());
        }
        assert!(
            !has_equivalent_entry("C:\\Other;C:\\SniperBeta", "C:\\Sniper", mock_equal).unwrap()
        );
    }

    #[derive(Default)]
    struct MockStore {
        path: Option<RawValue>,
        marker: Option<(Option<RawValue>, RawValue)>,
        reads: usize,
        writes: usize,
        fail_marker: bool,
        fail_read: bool,
        fail_write: bool,
        external_edit_after_write: Option<RawValue>,
    }

    impl RegistrationStore for MockStore {
        fn save_new_marker(
            &mut self,
            before: Option<&RawValue>,
            after: &RawValue,
        ) -> Result<(), String> {
            if self.fail_marker || self.marker.is_some() {
                return Err("Ownership record unavailable; PATH was left unchanged.".into());
            }
            self.marker = Some((before.cloned(), after.clone()));
            Ok(())
        }

        fn read_path(&mut self) -> Result<Option<RawValue>, String> {
            self.reads += 1;
            if self.fail_read {
                Err("Read failed or operation cancelled.".into())
            } else {
                Ok(self.path.clone())
            }
        }

        fn write_path(&mut self, value: &RawValue) -> Result<(), String> {
            if self.fail_write {
                return Err("Write failed.".into());
            }
            self.writes += 1;
            self.path = Some(
                self.external_edit_after_write
                    .clone()
                    .unwrap_or_else(|| value.clone()),
            );
            Ok(())
        }

        fn discard_new_marker(&mut self) -> Result<(), String> {
            self.marker = None;
            Ok(())
        }
    }

    #[test]
    fn saves_exact_ownership_snapshot_before_the_single_path_write() {
        let before = RawValue::string(REG_STRING, "C:\\工具;C:\\Other;");
        let after = append_path(Some(&before), "C:\\Sniper").unwrap();
        let mut store = MockStore {
            path: Some(before.clone()),
            ..Default::default()
        };
        assert!(commit_registration(&mut store, Some(&before), &after).unwrap());
        assert_eq!(store.path.as_ref(), Some(&after));
        assert_eq!(store.marker, Some((Some(before), after)));
        assert_eq!(store.writes, 1);
    }

    #[test]
    fn marker_failure_prevents_any_path_mutation() {
        let mut store = MockStore {
            fail_marker: true,
            ..Default::default()
        };
        let after = append_path(None, "C:\\Sniper").unwrap();
        assert!(commit_registration(&mut store, None, &after).is_err());
        assert!(store.path.is_none());
        assert_eq!(store.writes, 0);
    }

    #[test]
    fn read_failure_or_cancellation_cleans_only_new_marker() {
        let before = RawValue::string(REG_STRING, "C:\\Other");
        let after = append_path(Some(&before), "C:\\Sniper").unwrap();
        let mut store = MockStore {
            path: Some(before.clone()),
            fail_read: true,
            ..Default::default()
        };
        assert!(commit_registration(&mut store, Some(&before), &after).is_err());
        assert_eq!(store.path, Some(before));
        assert!(store.marker.is_none());
        assert_eq!(store.writes, 0);
    }

    #[test]
    fn failed_path_write_does_not_claim_ownership() {
        let mut store = MockStore {
            fail_write: true,
            ..Default::default()
        };
        assert!(
            commit_registration(&mut store, None, &append_path(None, "C:\\Sniper").unwrap())
                .is_err()
        );
        assert!(store.marker.is_none());
        assert!(store.path.is_none());
    }

    #[test]
    fn concurrent_user_edit_is_not_overwritten() {
        let before = RawValue::string(REG_STRING, "C:\\Other");
        let user_edit = RawValue::string(REG_EXPAND_STRING, "%SystemRoot%;C:\\Other;C:\\New");
        let mut store = MockStore {
            path: Some(user_edit.clone()),
            ..Default::default()
        };
        assert!(commit_registration(
            &mut store,
            Some(&before),
            &append_path(Some(&before), "C:\\Sniper").unwrap()
        )
        .is_err());
        assert_eq!(store.path, Some(user_edit));
        assert_eq!(store.writes, 0);
        assert!(store.marker.is_none());
    }

    #[test]
    fn later_path_edit_retains_snapshot_but_is_not_reported_verified() {
        let after = append_path(None, "C:\\Sniper").unwrap();
        let user_edit = RawValue::string(REG_EXPAND_STRING, "C:\\Sniper;C:\\UserAdded");
        let mut store = MockStore {
            external_edit_after_write: Some(user_edit.clone()),
            ..Default::default()
        };
        assert!(!commit_registration(&mut store, None, &after).unwrap());
        assert_eq!(store.path, Some(user_edit));
        assert_eq!(store.marker, Some((None, after)));
    }

    #[test]
    fn repeated_upgrade_does_not_overwrite_original_snapshot() {
        let before = RawValue::string(REG_STRING, "C:\\Other");
        let after = append_path(Some(&before), "C:\\Sniper").unwrap();
        let original_marker = Some((Some(before.clone()), after.clone()));
        let mut store = MockStore {
            path: Some(after.clone()),
            marker: original_marker.clone(),
            ..Default::default()
        };
        assert!(commit_registration(
            &mut store,
            Some(&after),
            &append_path(Some(&after), "C:\\Sniper2").unwrap()
        )
        .is_err());
        assert_eq!(store.path, Some(after));
        assert_eq!(store.marker, original_marker);
        assert_eq!(store.writes, 0);
    }

    #[test]
    fn expands_only_expandable_registry_strings() {
        let expand =
            |text: &str| Ok(text.replace("%LOCALAPPDATA%", "C:\\Users\\Tester\\AppData\\Local"));
        let plain = RawValue::string(REG_STRING, "%LOCALAPPDATA%\\Sniper");
        let expandable = RawValue::string(REG_EXPAND_STRING, "%LOCALAPPDATA%\\Sniper");
        assert_eq!(
            effective_path(Some(&plain), expand).unwrap(),
            "%LOCALAPPDATA%\\Sniper"
        );
        assert_eq!(
            effective_path(Some(&expandable), expand).unwrap(),
            "C:\\Users\\Tester\\AppData\\Local\\Sniper"
        );
        assert_eq!(
            effective_path(None, |_| panic!("No PATH to expand")).unwrap(),
            ""
        );
    }

    #[test]
    fn detects_every_standard_executable_extension_without_running_it() {
        let extensions = vec![".com".into(), ".exe".into(), ".bat".into(), ".cmd".into()];
        for other_extension in &extensions {
            let conflict = first_command_conflict(
                &["C:\\Sniper;C:\\Other".into()],
                &extensions,
                |entry, extension| {
                    if entry == "C:\\Sniper" && extension == ".exe" {
                        Ok(Some("C:\\Sniper\\sniper-cli.exe".into()))
                    } else if entry == "C:\\Other" && extension == other_extension {
                        Ok(Some(format!("C:\\Other\\sniper-cli{extension}")))
                    } else {
                        Ok(None)
                    }
                },
                |candidate| Ok(candidate == "C:\\Sniper\\sniper-cli.exe"),
            )
            .unwrap();
            assert_eq!(
                conflict,
                Some(format!("C:\\Other\\sniper-cli{other_extension}"))
            );
        }
    }

    #[test]
    fn bundled_exe_is_not_a_conflict_but_sibling_script_is() {
        let paths = ["C:\\Sniper".into()];
        let extensions = vec![".exe".into(), ".cmd".into()];
        let locate =
            |_: &str, extension: &str| Ok(Some(format!("C:\\Sniper\\sniper-cli{extension}")));
        assert_eq!(
            first_command_conflict(&paths, &extensions[..1], locate, |_| Ok(true)).unwrap(),
            None
        );
        assert_eq!(
            first_command_conflict(&paths, &extensions, locate, |_| Ok(true)).unwrap(),
            Some("C:\\Sniper\\sniper-cli.cmd".into())
        );
    }

    #[test]
    fn failed_conflict_inspection_does_not_assume_the_path_is_clear() {
        assert!(first_command_conflict(
            &["C:\\Private".into()],
            &[".exe".into()],
            |_, _| Err("Access denied".into()),
            |_| Ok(false)
        )
        .is_err());
    }

    #[test]
    fn expands_multi_directory_variables_before_splitting_entries() {
        let raw = RawValue::string(REG_EXPAND_STRING, "%TOOLS%;C:\\Other");
        let effective = effective_path(Some(&raw), |value| {
            Ok(value.replace("%TOOLS%", "C:\\First;C:\\Sniper"))
        })
        .unwrap();
        assert!(
            has_equivalent_entry(&effective, "C:\\Sniper", |left, right| Ok(
                left.eq_ignore_ascii_case(right)
            ))
            .unwrap()
        );
        let conflict = first_command_conflict(
            &[effective],
            &[".cmd".into()],
            |entry, _| Ok((entry == "C:\\First").then(|| "C:\\First\\sniper-cli.cmd".into())),
            |_| Ok(false),
        )
        .unwrap();
        assert_eq!(conflict, Some("C:\\First\\sniper-cli.cmd".into()));
    }

    #[test]
    fn quoted_semicolons_remain_inside_their_existing_path_entry() {
        let paths = ["C:\\Other;\"C:\\A;B\";C:\\Last".into()];
        let conflict = first_command_conflict(
            &paths,
            &[".exe".into()],
            |entry, _| Ok((entry == "C:\\A;B").then(|| "C:\\A;B\\sniper-cli.exe".into())),
            |_| Ok(false),
        )
        .unwrap();
        assert_eq!(conflict, Some("C:\\A;B\\sniper-cli.exe".into()));
        let before = RawValue::string(REG_STRING, &paths[0]);
        let after = append_path(Some(&before), "C:\\Sniper").unwrap();
        assert_eq!(
            after.path_text().unwrap(),
            "C:\\Other;\"C:\\A;B\";C:\\Last;C:\\Sniper"
        );
    }

    #[test]
    fn ambiguous_quotes_fail_closed_before_any_registry_write() {
        for path in ["C:\\Other;\"C:\\Unclosed", "C:\\Part\"ial\";C:\\Other"] {
            assert!(path_entries(path).is_err());
            assert!(has_equivalent_entry(path, "C:\\Other", |_, _| Ok(false)).is_err());
        }
    }

    #[test]
    fn prior_ownership_blocks_unregistered_status_but_not_existing_registration() {
        assert!(prior_registration_conflict(false, true).is_some());
        assert!(prior_registration_conflict(true, true).is_none());
        assert!(prior_registration_conflict(false, false).is_none());
    }

    #[test]
    fn new_target_directory_is_checked_for_command_siblings_before_registration() {
        let inherited_paths = ["C:\\System".to_string(), "C:\\UserTools".to_string()];
        let target = "C:\\Sniper";
        assert!(inherited_paths.iter().all(|path| !path.contains(target)));
        let mut search_paths = inherited_paths.to_vec();
        search_paths.push(target.into());
        for extension in [".com", ".cmd", ".bat", ".py"] {
            let extensions = vec![".exe".into(), extension.into()];
            let conflict = first_command_conflict(
                &search_paths,
                &extensions,
                |entry, candidate_extension| {
                    Ok((entry == target)
                        .then(|| format!("{entry}\\sniper-cli{candidate_extension}")))
                },
                |candidate| Ok(candidate == "C:\\Sniper\\sniper-cli.exe"),
            )
            .unwrap();
            assert_eq!(conflict, Some(format!("C:\\Sniper\\sniper-cli{extension}")));
        }
    }

    #[test]
    fn unsupported_pathext_never_silently_hides_a_possible_conflict() {
        for pathext in [".EXE;.C++", ".EXE;file", ".EXE;.", ".EXE;.A/B"] {
            assert!(command_extensions(Some(pathext)).is_err());
        }
        let extensions =
            command_extensions(Some(" .EXE;.py;;.ExtremelyLongButAlphanumeric; ")).unwrap();
        assert_eq!(
            extensions
                .iter()
                .filter(|extension| extension.eq_ignore_ascii_case(".exe"))
                .count(),
            1
        );
        assert!(extensions.contains(&".py".to_string()));
        assert!(extensions.contains(&".ExtremelyLongButAlphanumeric".to_string()));
        assert_eq!(command_extensions(None).unwrap().len(), 4);
    }
}
