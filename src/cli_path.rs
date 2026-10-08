//! Explicit, optional registration of the bundled CLI on the user's PATH.
//! Merely checking availability never changes a profile or the registry.

use std::env;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[cfg(any(windows, test))]
#[path = "cli_path_windows.rs"]
mod windows;

static INSTALL_LOCK: Mutex<()> = Mutex::new(());
const CHOICE_FILE: &str = "cli-path-choice.json";
const WINDOWS_INSTALLER_MARKER: &str = ".sniper-installed";

#[derive(Debug, Default, serde::Serialize)]
pub struct CliPathInstall {
    pub updated: Vec<String>,
    pub unchanged: Vec<String>,
    pub warnings: Vec<String>,
    pub message: String,
}

#[derive(Debug, serde::Serialize)]
pub struct CliPathStatus {
    pub platform: &'static str,
    pub supported: bool,
    pub registered: bool,
    pub can_install: bool,
    pub should_prompt: bool,
    pub directory: Option<String>,
    pub message: String,
}

/// The choice belongs to the app, not a webview origin (whose port can change).
/// An interrupted or failed registration is retried explicitly from Settings.
pub fn defer_cli_path(data_dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(data_dir).map_err(|e| format!("Could not save CLI choice: {e}"))?;
    let path = data_dir.join(CHOICE_FILE);
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(e) => return Err(format!("Could not save CLI choice: {e}")),
    };
    file.write_all(b"{\"version\":1,\"prompt_dismissed\":true}\n")
        .and_then(|()| file.sync_all())
        .and_then(|()| crate::platform::sync_directory(data_dir))
        .map_err(|e| format!("Could not save CLI choice: {e}"))
}

pub fn cli_path_status(data_dir: &Path) -> CliPathStatus {
    let platform = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(windows) {
        "windows"
    } else {
        "unsupported"
    };
    let mut status = CliPathStatus {
        platform,
        supported: platform != "unsupported",
        registered: false,
        can_install: false,
        should_prompt: false,
        directory: None,
        message: String::new(),
    };
    let result = (|| {
        let directory = bundled_cli_directory()?;
        status.directory = Some(directory.display().to_string());
        #[cfg(windows)]
        let (registered, conflict) = {
            let found = windows::inspect(&directory)?;
            (found.registered, found.conflict)
        };
        #[cfg(not(windows))]
        let (registered, conflict) =
            inspect_macos(&directory, &shell_targets()?, macos_search_dirs())?;
        status.registered = registered;
        status.can_install = conflict.is_none();
        status.message = conflict.unwrap_or_else(|| if registered {
            "sniper-cli is already registered. Open a new terminal to use it.".to_string()
        } else {
            "Add the bundled sniper-cli for this user. Existing PATH entries are preserved. Open a new terminal afterwards.".to_string()
        });
        status.should_prompt = should_offer_cli_path(
            status.can_install,
            registered,
            data_dir.join(CHOICE_FILE).exists(),
            cfg!(windows) && directory.join(WINDOWS_INSTALLER_MARKER).is_file(),
        );
        Ok::<(), String>(())
    })();
    if let Err(error) = result {
        status.message = error;
    }
    status
}

fn should_offer_cli_path(
    can_install: bool,
    registered: bool,
    decided: bool,
    installed_by_setup: bool,
) -> bool {
    // Setup already offered an unchecked choice. Its installed copy must not
    // immediately ask again; Settings still allows a later explicit opt-in.
    can_install && !registered && !decided && !installed_by_setup
}

pub fn install_cli_path() -> Result<CliPathInstall, String> {
    let _guard = INSTALL_LOCK
        .lock()
        .map_err(|_| "CLI PATH setup is unavailable. Restart Sniper and retry.".to_string())?;
    let directory = bundled_cli_directory()?;
    #[cfg(windows)]
    {
        windows::install(&directory)
    }
    #[cfg(not(windows))]
    {
        let home = home_dir()?;
        let _profile_lock = lock_profiles(&home)?;
        install_macos(&directory, &shell_targets()?, macos_search_dirs())
    }
}

fn bundled_cli_directory() -> Result<PathBuf, String> {
    if !cfg!(any(target_os = "macos", windows)) {
        return Err(
            "Automatic CLI PATH setup is available in the macOS and Windows desktop apps."
                .to_string(),
        );
    }
    let exe = env::current_exe().map_err(|e| format!("Could not locate the running app: {e}"))?;
    let directory = exe
        .parent()
        .ok_or("Could not locate the app directory.")?
        .to_path_buf();
    #[cfg(windows)]
    {
        if !exe.file_name().is_some_and(|name| {
            name.to_string_lossy()
                .eq_ignore_ascii_case("sniper-desktop.exe")
        }) || !directory.join("sniper-cli.exe").is_file()
        {
            return Err("Run sniper-desktop.exe from the installed app or an extracted portable ZIP containing sniper-cli.exe.".to_string());
        }
    }
    #[cfg(not(windows))]
    {
        if !should_install_cli_path(&directory) {
            return Err("Move Sniper.app to Applications before adding the CLI to PATH. Mounted disk images and translocated apps are not supported.".to_string());
        }
        if !is_executable_file(&directory.join("sniper-cli")) {
            return Err("sniper-cli is missing or not executable in this app bundle.".to_string());
        }
    }
    Ok(directory)
}

#[cfg(not(windows))]
fn home_dir() -> Result<PathBuf, String> {
    env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is not set.".to_string())
}

#[cfg(not(windows))]
fn shell_targets() -> Result<Vec<PathBuf>, String> {
    let home = home_dir()?;
    let zsh_dir = env::var_os("ZDOTDIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.clone());
    if !zsh_dir.is_absolute() {
        return Err("ZDOTDIR must be an absolute directory for automatic PATH setup.".to_string());
    }
    let mut targets = vec![zsh_dir.join(".zshrc")];
    for name in [".bash_profile", ".bashrc"] {
        let target = home.join(name);
        if target.exists() {
            targets.push(target);
        }
    }
    Ok(targets)
}

#[cfg(not(windows))]
fn macos_search_dirs() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = env::var_os("PATH")
        .map(|path| env::split_paths(&path).collect())
        .unwrap_or_default();
    // Finder-launched apps do not necessarily inherit Homebrew's shell PATH.
    paths.extend([
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
    ]);
    paths
}

#[cfg(any(not(windows), test))]
fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(any(not(windows), test))]
fn managed_path_line(directory: &Path) -> Result<String, String> {
    let value = directory
        .to_str()
        .ok_or("The app path is not valid Unicode.")?;
    if value.contains([':', '\n', '\r']) {
        return Err(
            "The app path contains characters that cannot safely be added to PATH.".to_string(),
        );
    }
    Ok(format!(
        "case \":$PATH:\" in *{}*) ;; *) export PATH=\"$PATH\":{} ;; esac # Added by Sniper.app",
        shell_single_quote(&format!(":{value}:")),
        shell_single_quote(value)
    ))
}

#[cfg(any(not(windows), test))]
fn inspect_macos(
    directory: &Path,
    targets: &[PathBuf],
    search_dirs: Vec<PathBuf>,
) -> Result<(bool, Option<String>), String> {
    let cli = std::fs::canonicalize(directory.join("sniper-cli"))
        .map_err(|e| format!("Could not read bundled CLI: {e}"))?;
    for path in search_dirs {
        let candidate = path.join("sniper-cli");
        if !is_executable_file(&candidate) {
            continue;
        }
        if std::fs::canonicalize(&candidate).ok().as_ref() == Some(&cli) {
            return Ok((true, None));
        }
        return Ok((false, Some(format!("Another sniper-cli already exists at {}. Its PATH entry was left unchanged. Resolve that conflict before adding this copy.", candidate.display()))));
    }
    let expected = managed_path_line(directory)?;
    let legacy = format!(
        "export PATH={}:$PATH # Added by Sniper.app",
        shell_single_quote(&directory.to_string_lossy())
    );
    let mut registered = !targets.is_empty();
    for target in targets {
        let contents =
            load_shell_rc_contents(target).map_err(|e| format!("{}: {e}", target.display()))?;
        registered &= contents
            .lines()
            .any(|line| line.trim() == expected || line.trim() == legacy);
    }
    Ok((registered, None))
}

#[cfg(any(not(windows), test))]
fn install_macos(
    directory: &Path,
    targets: &[PathBuf],
    search_dirs: Vec<PathBuf>,
) -> Result<CliPathInstall, String> {
    let (registered, conflict) = inspect_macos(directory, targets, search_dirs)?;
    if let Some(conflict) = conflict {
        return Err(conflict);
    }
    if registered {
        return Ok(CliPathInstall {
            unchanged: vec!["Existing CLI PATH registration".to_string()],
            message: "sniper-cli is already registered. Open a new terminal to use it.".to_string(),
            ..Default::default()
        });
    }
    let export_line = managed_path_line(directory)?;
    let mut result = CliPathInstall::default();
    for rc_path in targets {
        let update = (|| {
            let contents = load_shell_rc_contents(rc_path)?;
            let Some(updated) = upsert_managed_path_line(&contents, &export_line) else {
                return Ok(false);
            };
            // Do not knowingly overwrite an edit made while the setup was preparing.
            if load_shell_rc_contents(rc_path)? != contents {
                return Err(std::io::Error::other(
                    "The profile changed during setup; retry from Settings.",
                ));
            }
            PreparedShellRc::new(rc_path, &updated, Some(&contents))?.commit()?;
            Ok::<bool, std::io::Error>(true)
        })();
        match update {
            Ok(true) => result.updated.push(rc_path.display().to_string()),
            Ok(false) => result.unchanged.push(rc_path.display().to_string()),
            Err(e) => result.warnings.push(format!("{}: {e}", rc_path.display())),
        }
    }
    if result.updated.is_empty() && result.unchanged.is_empty() {
        return Err(result.warnings.join("; "));
    }
    result.message = if result.warnings.is_empty() {
        format!(
            "Registered sniper-cli in {}. Open a new terminal to use it.",
            result
                .updated
                .iter()
                .chain(&result.unchanged)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        "CLI PATH setup only partially completed. Review the warnings and retry from Settings."
            .to_string()
    };
    Ok(result)
}

#[cfg(not(windows))]
fn lock_profiles(home: &Path) -> Result<std::fs::File, String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(home.join(".sniper-cli-path.lock"))
        .map_err(|e| format!("Could not lock CLI PATH setup: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // The file descriptor stays open until registration finishes; close releases the lock.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("Another CLI PATH setup is running. Retry from Settings.".to_string());
        }
    }
    Ok(file)
}

#[cfg(not(windows))]
pub(crate) fn should_install_cli_path(macos_dir: &std::path::Path) -> bool {
    let path = macos_dir.to_string_lossy();
    if macos_dir.starts_with("/Volumes") || path.contains("/AppTranslocation/") {
        return false;
    }

    let Some(app_contents_dir) = macos_dir.parent() else {
        return false;
    };
    if macos_dir.file_name().and_then(|name| name.to_str()) != Some("MacOS")
        || app_contents_dir.file_name().and_then(|name| name.to_str()) != Some("Contents")
    {
        return false;
    }

    let Some(app_bundle) = app_contents_dir.parent() else {
        return false;
    };
    let Some(app_bundle_name) = app_bundle.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if !app_bundle_name.ends_with(".app") {
        return false;
    }

    let Some(install_dir) = app_bundle.parent() else {
        return false;
    };
    if install_dir == std::path::Path::new("/Applications") {
        return true;
    }
    match env::var("HOME") {
        Ok(home) => {
            let home = std::path::PathBuf::from(home);
            install_dir == home.join("Applications")
                || app_bundle == home.join("Desktop").join("Sniper.app")
        }
        Err(_) => false,
    }
}

#[cfg(any(not(windows), test))]
pub(crate) fn load_shell_rc_contents(rc_path: &Path) -> std::io::Result<String> {
    match std::fs::metadata(rc_path) {
        Ok(metadata) if !metadata.is_file() => {
            return Err(std::io::Error::other(
                "Shell profile is not a regular file.",
            ))
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(error),
    }
    std::fs::read_to_string(rc_path)
}

#[cfg(test)]
pub(crate) fn write_shell_rc_atomically(rc_path: &Path, contents: &str) -> std::io::Result<()> {
    PreparedShellRc::new(rc_path, contents, None)?.commit()
}

#[cfg(any(not(windows), test))]
struct PreparedShellRc {
    rc_path: PathBuf,
    write_path: PathBuf,
    tmp_path: PathBuf,
    expected: Option<String>,
}

#[cfg(any(not(windows), test))]
impl PreparedShellRc {
    fn new(rc_path: &Path, contents: &str, expected: Option<&str>) -> std::io::Result<Self> {
        let write_path = resolve_shell_rc_write_path(rc_path)?;
        let parent = write_path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)?;
        let existing_permissions = match std::fs::metadata(&write_path) {
            Ok(metadata) if metadata.is_file() => Some(metadata.permissions()),
            Ok(_) => {
                return Err(std::io::Error::other(
                    "Shell profile is not a regular file.",
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let name = write_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("shellrc");
        let tmp_path = parent.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
        let prepared = Self {
            rc_path: rc_path.to_path_buf(),
            write_path,
            tmp_path,
            expected: expected.map(str::to_owned),
        };
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&prepared.tmp_path)?;
        file.write_all(contents.as_bytes())?;
        if let Some(permissions) = existing_permissions {
            file.set_permissions(permissions)?;
        }
        file.sync_all()?;
        Ok(prepared)
    }

    fn commit(self) -> std::io::Result<()> {
        // Recheck after the slow write/fsync, immediately before rename. Other
        // editors do not share our flock; no portable filesystem CAS exists,
        // but a known concurrent edit or symlink move must never be overwritten.
        if resolve_shell_rc_write_path(&self.rc_path)? != self.write_path {
            return Err(std::io::Error::other(
                "The profile target changed during setup; retry from Settings.",
            ));
        }
        let current = load_shell_rc_contents(&self.rc_path)?;
        if self
            .expected
            .as_ref()
            .is_some_and(|expected| *expected != current)
        {
            return Err(std::io::Error::other(
                "The profile changed during setup; retry from Settings.",
            ));
        }
        crate::platform::rename(&self.tmp_path, &self.write_path)?;
        crate::platform::sync_directory(self.write_path.parent().unwrap_or_else(|| Path::new(".")))
    }
}

#[cfg(any(not(windows), test))]
impl Drop for PreparedShellRc {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.tmp_path);
    }
}

#[cfg(any(not(windows), test))]
pub(crate) fn resolve_shell_rc_write_path(rc_path: &std::path::Path) -> std::io::Result<PathBuf> {
    match std::fs::symlink_metadata(rc_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => std::fs::canonicalize(rc_path),
        Ok(_) => Ok(rc_path.to_path_buf()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(rc_path.to_path_buf()),
        Err(error) => Err(error),
    }
}

#[cfg(any(not(windows), test))]
fn decode_shell_single_quote(value: &str) -> Option<String> {
    let inner = value.strip_prefix('\'')?.strip_suffix('\'')?;
    if inner.contains('\0') {
        return None;
    }
    let decoded = inner.replace("'\\''", "\0");
    if decoded.contains('\'') {
        return None;
    }
    Some(decoded.replace('\0', "'"))
}

#[cfg(any(not(windows), test))]
fn is_managed_path_line(line: &str) -> bool {
    let line = line.trim();
    if let Some(quoted) = line
        .strip_prefix("export PATH=")
        .and_then(|s| s.strip_suffix(":$PATH # Added by Sniper.app"))
    {
        return decode_shell_single_quote(quoted).is_some();
    }
    let Some(quoted) = line
        .split("*) ;; *) export PATH=\"$PATH\":")
        .nth(1)
        .and_then(|s| s.strip_suffix(" ;; esac # Added by Sniper.app"))
    else {
        return false;
    };
    let Some(directory) = decode_shell_single_quote(quoted) else {
        return false;
    };
    managed_path_line(Path::new(&directory)).is_ok_and(|expected| expected == line)
}

#[cfg(any(not(windows), test))]
pub(crate) fn upsert_managed_path_line(contents: &str, export_line: &str) -> Option<String> {
    let mut changed = false;
    let mut found_managed = false;
    let mut updated = String::new();
    for line in contents.split_inclusive('\n') {
        if is_managed_path_line(line) {
            if found_managed {
                changed = true;
                continue;
            }
            found_managed = true;
            changed |= line.trim() != export_line;
            updated.push_str(export_line);
            updated.push('\n');
        } else {
            // Keep unrelated profile bytes, including CRLF and comments, intact.
            updated.push_str(line);
        }
    }
    if !found_managed {
        if !updated.is_empty() {
            if !updated.ends_with('\n') {
                updated.push('\n');
            }
            updated.push('\n');
        }
        updated.push_str(export_line);
        updated.push('\n');
        changed = true;
    }
    changed.then_some(updated)
}

#[cfg(any(not(windows), test))]
pub(crate) fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let path = env::temp_dir().join(format!("sniper-cli-path-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn cli(&self, name: &str) -> PathBuf {
            let directory = self.0.join(name);
            std::fs::create_dir_all(&directory).unwrap();
            let path = directory.join("sniper-cli");
            std::fs::write(&path, "test fixture only").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            directory
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn profile_edit_during_preparation_is_not_overwritten() {
        let root = TempRoot::new();
        let profile = root.0.join(".zshrc");
        std::fs::write(&profile, "original").unwrap();
        let prepared = PreparedShellRc::new(&profile, "our change", Some("original")).unwrap();
        std::fs::write(&profile, "user's newer edit").unwrap();
        assert!(prepared.commit().is_err());
        assert_eq!(
            std::fs::read_to_string(&profile).unwrap(),
            "user's newer edit"
        );
        assert_eq!(std::fs::read_dir(&root.0).unwrap().count(), 1);
    }

    #[test]
    #[cfg(unix)]
    fn profile_symlink_move_during_preparation_is_not_overwritten() {
        let root = TempRoot::new();
        let profile = root.0.join(".zshrc");
        let first = root.0.join("first");
        let second = root.0.join("second");
        std::fs::write(&first, "original").unwrap();
        std::fs::write(&second, "original").unwrap();
        std::os::unix::fs::symlink(&first, &profile).unwrap();
        let prepared = PreparedShellRc::new(&profile, "our change", Some("original")).unwrap();
        std::fs::remove_file(&profile).unwrap();
        std::os::unix::fs::symlink(&second, &profile).unwrap();
        assert!(prepared.commit().is_err());
        assert_eq!(std::fs::read_to_string(first).unwrap(), "original");
        assert_eq!(std::fs::read_to_string(second).unwrap(), "original");
    }

    #[test]
    #[cfg(unix)]
    fn nonregular_profiles_are_rejected_without_reading_or_replacing() {
        use std::os::unix::ffi::OsStrExt;
        let root = TempRoot::new();
        let profile = root.0.join(".zshrc");
        let path = std::ffi::CString::new(profile.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(load_shell_rc_contents(&profile).is_err());
        assert!(write_shell_rc_atomically(&profile, "new").is_err());
        assert!(!std::fs::metadata(profile).unwrap().is_file());
    }

    #[test]
    fn first_run_prompt_respects_setup_choice_and_registration() {
        assert!(should_offer_cli_path(true, false, false, false));
        assert!(!should_offer_cli_path(true, false, false, true));
        assert!(!should_offer_cli_path(true, false, true, false));
        assert!(!should_offer_cli_path(true, true, false, false));
        assert!(!should_offer_cli_path(false, false, false, false));
    }

    #[test]
    fn deferral_is_persistent_and_idempotent_without_shell_mutation() {
        let root = TempRoot::new();
        defer_cli_path(&root.0).unwrap();
        let first = std::fs::read(root.0.join(CHOICE_FILE)).unwrap();
        defer_cli_path(&root.0).unwrap();
        assert_eq!(std::fs::read(root.0.join(CHOICE_FILE)).unwrap(), first);
        assert_eq!(std::fs::read_dir(&root.0).unwrap().count(), 1);
    }

    #[test]
    fn deferral_failure_is_reported() {
        let root = TempRoot::new();
        let file = root.0.join("not-a-directory");
        std::fs::write(&file, "unchanged").unwrap();
        assert!(defer_cli_path(&file).is_err());
        assert_eq!(std::fs::read_to_string(file).unwrap(), "unchanged");
    }

    #[test]
    #[cfg(unix)]
    fn profile_registration_repeats_without_duplicates_and_updates_owned_paths() {
        let root = TempRoot::new();
        let directory = root.cli("Sniper's first.app");
        let target = root.0.join(".zshrc");
        std::fs::write(&target, "# keep this\r\nexport PATH=/my/bin:$PATH\r\n").unwrap();
        let first = install_macos(&directory, &[target.clone()], vec![]).unwrap();
        assert_eq!(first.updated.len(), 1);
        assert!(first.warnings.is_empty());
        let contents = std::fs::read_to_string(&target).unwrap();
        assert!(contents.starts_with("# keep this\r\nexport PATH=/my/bin:$PATH\r\n"));
        let second = install_macos(&directory, &[target.clone()], vec![]).unwrap();
        assert!(second.updated.is_empty());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), contents);
        let new_directory = root.cli("Sniper next.app");
        install_macos(&new_directory, &[target.clone()], vec![]).unwrap();
        let updated = std::fs::read_to_string(&target).unwrap();
        assert_eq!(updated.matches("# Added by Sniper.app").count(), 1);
        assert!(!updated.contains("first.app"));
        assert!(updated.contains("next.app"));
    }

    #[test]
    fn foreign_cli_blocks_registration_without_changing_profiles() {
        let root = TempRoot::new();
        let directory = root.cli("bundle");
        let foreign = root.cli("unrelated");
        let target = root.0.join(".zshrc");
        std::fs::write(&target, "original").unwrap();
        assert!(install_macos(&directory, &[target.clone()], vec![foreign]).is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "original");
    }

    #[test]
    fn existing_path_registration_does_not_create_a_profile() {
        let root = TempRoot::new();
        let directory = root.cli("bundle");
        let target = root.0.join(".zshrc");
        let result = install_macos(&directory, &[target.clone()], vec![directory.clone()]).unwrap();
        assert!(result.updated.is_empty());
        assert!(!target.exists());
    }

    #[test]
    fn unrelated_marker_comments_and_modified_commands_are_preserved() {
        let line = managed_path_line(Path::new("/Applications/Sniper.app/Contents/MacOS")).unwrap();
        let original = "# Added by Sniper.app is just a note\nexport PATH='x'; echo example # Added by Sniper.app\n";
        let updated = upsert_managed_path_line(original, &line).unwrap();
        assert!(updated.starts_with(original));
        assert!(upsert_managed_path_line(&updated, &line).is_none());
    }

    #[test]
    fn malformed_paths_cannot_be_written_as_shell_path_entries() {
        for path in ["/tmp/a:b", "/tmp/a\nb", "/tmp/a\rb"] {
            assert!(managed_path_line(Path::new(path)).is_err());
        }
    }

    #[test]
    #[cfg(unix)]
    fn generated_shell_line_preserves_precedence_and_is_safe_to_source_twice() {
        let directory = Path::new("/tmp/Sniper 'quoted' $(literal).app/Contents/MacOS");
        let line = managed_path_line(directory).unwrap();
        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!(
                "PATH=/existing/bin; {line}\n{line}\nprintf '%s' \"$PATH\""
            ))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("/existing/bin:{}", directory.display())
        );
    }

    #[test]
    #[cfg(unix)]
    fn profile_lock_rejects_concurrent_registration_then_releases() {
        let root = TempRoot::new();
        let first = lock_profiles(&root.0).unwrap();
        assert!(lock_profiles(&root.0).is_err());
        drop(first);
        assert!(lock_profiles(&root.0).is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn symlink_chains_and_permissions_are_preserved() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let root = TempRoot::new();
        let target = root.0.join("real-profile");
        let intermediate = root.0.join("intermediate");
        let profile = root.0.join(".zshrc");
        std::fs::write(&target, "old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&target, &intermediate).unwrap();
        symlink(&intermediate, &profile).unwrap();
        write_shell_rc_atomically(&profile, "new").unwrap();
        assert!(std::fs::symlink_metadata(&profile).unwrap().is_symlink());
        assert!(std::fs::symlink_metadata(&intermediate)
            .unwrap()
            .is_symlink());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
        assert_eq!(
            std::fs::metadata(target).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    #[cfg(unix)]
    fn dangling_profile_links_fail_without_replacing_the_link() {
        let root = TempRoot::new();
        let profile = root.0.join(".zshrc");
        std::os::unix::fs::symlink("missing", &profile).unwrap();
        assert!(write_shell_rc_atomically(&profile, "new").is_err());
        assert!(std::fs::symlink_metadata(&profile).unwrap().is_symlink());
        assert!(!root.0.join("missing").exists());
    }

    #[test]
    fn shell_single_quote_escapes_embedded_quotes() {
        assert_eq!(
            shell_single_quote("/Applications/Sniper 'Beta'.app/Contents/MacOS"),
            "'/Applications/Sniper '\\''Beta'\\''.app/Contents/MacOS'"
        );
    }

    #[test]
    fn upsert_managed_path_line_replaces_old_managed_line() {
        let updated = upsert_managed_path_line(
            "export PATH='/old/Sniper.app/Contents/MacOS':$PATH # Added by Sniper.app\n",
            "export PATH='/new/Sniper.app/Contents/MacOS':$PATH # Added by Sniper.app",
        )
        .unwrap();
        assert!(updated.contains("/new/Sniper.app"));
        assert!(!updated.contains("/old/Sniper.app"));
    }

    #[test]
    fn upsert_managed_path_line_collapses_duplicate_managed_lines() {
        let updated = upsert_managed_path_line(
            "before\nexport PATH='/old/Sniper.app/Contents/MacOS':$PATH # Added by Sniper.app\nmiddle\nexport PATH='/older/Sniper.app/Contents/MacOS':$PATH # Added by Sniper.app\nafter\n",
            "export PATH='/new/Sniper.app/Contents/MacOS':$PATH # Added by Sniper.app",
        )
        .unwrap();

        assert_eq!(updated.matches("# Added by Sniper.app").count(), 1);
        assert!(updated.contains("before\n"));
        assert!(updated.contains("middle\n"));
        assert!(updated.contains("after\n"));
        assert!(updated.contains("/new/Sniper.app"));
        assert!(!updated.contains("/old/Sniper.app"));
        assert!(!updated.contains("/older/Sniper.app"));
    }

    #[test]
    fn shell_rc_loader_only_defaults_missing_files() {
        let root = std::env::temp_dir().join(format!("sniper-rc-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        assert_eq!(load_shell_rc_contents(&root.join(".zshrc")).unwrap(), "");

        let invalid_utf8 = root.join(".bashrc");
        std::fs::write(&invalid_utf8, [0xff, 0xfe]).unwrap();
        assert!(load_shell_rc_contents(&invalid_utf8).is_err());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn shell_rc_writer_replaces_file_atomically() {
        let root =
            std::env::temp_dir().join(format!("sniper-rc-write-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let rc_path = root.join(".zshrc");
        std::fs::write(&rc_path, "old\n").unwrap();

        write_shell_rc_atomically(&rc_path, "new\n").unwrap();

        assert_eq!(std::fs::read_to_string(&rc_path).unwrap(), "new\n");
        assert!(!std::fs::read_dir(&root).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp")));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    #[cfg(unix)]
    fn shell_rc_writer_preserves_symlinked_rc_files() {
        let root =
            std::env::temp_dir().join(format!("sniper-rc-symlink-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let target_path = root.join("dotfiles").join("zshrc");
        std::fs::create_dir_all(target_path.parent().unwrap()).unwrap();
        std::fs::write(&target_path, "old\n").unwrap();
        let rc_path = root.join(".zshrc");
        std::os::unix::fs::symlink("dotfiles/zshrc", &rc_path).unwrap();

        write_shell_rc_atomically(&rc_path, "new\n").unwrap();

        assert!(std::fs::symlink_metadata(&rc_path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_to_string(&target_path).unwrap(), "new\n");

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn cli_path_install_skips_transient_dmg_mounts() {
        assert!(!should_install_cli_path(std::path::Path::new(
            "/Volumes/Sniper/Sniper.app/Contents/MacOS",
        )));
        assert!(!should_install_cli_path(std::path::Path::new(
            "/private/var/folders/xx/AppTranslocation/123/Sniper.app/Contents/MacOS",
        )));
        assert!(!should_install_cli_path(std::path::Path::new(
            "/Users/kakao/Desktop/git/Sniper/target/release",
        )));
        assert!(!should_install_cli_path(std::path::Path::new(
            "/tmp/sniper-build/release/Sniper.app/Contents/MacOS",
        )));
        assert!(!should_install_cli_path(std::path::Path::new(
            "/Users/kakao/Desktop/git/Sniper/dist/Sniper.app/Contents/MacOS",
        )));
        assert!(should_install_cli_path(
            &std::path::PathBuf::from(std::env::var("HOME").unwrap())
                .join("Desktop")
                .join("Sniper.app")
                .join("Contents")
                .join("MacOS")
        ));
        assert!(should_install_cli_path(std::path::Path::new(
            "/Applications/Sniper.app/Contents/MacOS",
        )));
        let user_app = std::path::PathBuf::from(std::env::var("HOME").unwrap())
            .join("Applications")
            .join("Sniper.app")
            .join("Contents")
            .join("MacOS");
        assert!(should_install_cli_path(&user_app));
    }
}
