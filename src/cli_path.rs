//! Putting `sniper-cli` on the shell `PATH`.
//!
//! Sniper does not touch shell profiles on its own — an app that silently edits
//! `~/.zshrc` is hard to undo and easy to get wrong when several copies are
//! installed. This runs only when the operator asks for it, from the Settings
//! button or `SNIPER_INSTALL_CLI_PATH=1` at launch.
//!
//! It lives in the library rather than the desktop binary so the UI can reach it
//! through the API; the bundle check below is what keeps it from doing anything
//! when the server is running from somewhere else.

use std::env;
use std::io::Write as _;
use std::path::PathBuf;

use tracing::{error, info};

/// What one run changed, so the UI can say something specific.
#[derive(Debug, Default, serde::Serialize)]
pub struct CliPathInstall {
    /// Shell rc files that were written.
    pub updated: Vec<String>,
    /// Shell rc files that already had the line.
    pub unchanged: Vec<String>,
}

/// Add the bundle's `MacOS` directory to `PATH` in the user's shell rc files.
///
/// Returns an error string the UI can show rather than only logging: a button
/// that silently does nothing is worse than no button.
pub fn install_cli_path() -> Result<CliPathInstall, String> {
    let exe =
        env::current_exe().map_err(|error| format!("could not locate the running app: {error}"))?;
    let macos_dir = exe.parent().unwrap_or(&exe).to_path_buf();
    if !should_install_cli_path(&macos_dir) {
        return Err(
            "PATH setup is only available when Sniper runs from an installed Sniper.app."
                .to_string(),
        );
    }
    let cli_bin = macos_dir.join("sniper-cli");
    if !cli_bin.exists() {
        return Err("sniper-cli is missing from this app bundle.".to_string());
    }

    let dir = macos_dir.to_string_lossy().to_string();
    let export_line = format!(
        "export PATH={}:$PATH # Added by Sniper.app",
        shell_single_quote(&dir)
    );

    let home = env::var("HOME").map_err(|_| "HOME is not set.".to_string())?;
    let home = PathBuf::from(home);

    // Always patch .zshrc (macOS default shell). Also patch .bashrc if it exists.
    let mut targets = vec![home.join(".zshrc")];
    let bashrc = home.join(".bashrc");
    if bashrc.exists() {
        targets.push(bashrc);
    }

    let mut result = CliPathInstall::default();
    let mut last_error = None;
    for rc_path in &targets {
        let contents = match load_shell_rc_contents(rc_path) {
            Ok(contents) => contents,
            Err(e) => {
                error!(?e, file = %rc_path.display(), "skipping unreadable shell rc");
                last_error = Some(format!("{}: {e}", rc_path.display()));
                continue;
            }
        };
        let Some(updated) = upsert_managed_path_line(&contents, &export_line) else {
            info!(file = %rc_path.display(), "sniper-cli PATH already configured");
            result.unchanged.push(rc_path.display().to_string());
            continue;
        };
        if let Err(e) = write_shell_rc_atomically(rc_path, &updated) {
            error!(?e, file = %rc_path.display(), "failed to write PATH to shell rc");
            last_error = Some(format!("{}: {e}", rc_path.display()));
        } else {
            info!(file = %rc_path.display(), "updated sniper-cli PATH");
            result.updated.push(rc_path.display().to_string());
        }
    }

    if result.updated.is_empty() && result.unchanged.is_empty() {
        return Err(last_error.unwrap_or_else(|| "no shell profile could be updated.".to_string()));
    }
    Ok(result)
}

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

pub(crate) fn load_shell_rc_contents(rc_path: &std::path::Path) -> std::io::Result<String> {
    match std::fs::read_to_string(rc_path) {
        Ok(contents) => Ok(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error),
    }
}

pub(crate) fn write_shell_rc_atomically(
    rc_path: &std::path::Path,
    contents: &str,
) -> std::io::Result<()> {
    let write_path = resolve_shell_rc_write_path(rc_path)?;
    let parent = write_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent)?;
    let file_name = write_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("shellrc");
    let tmp_path = parent.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
    let existing_permissions = std::fs::metadata(&write_path)
        .ok()
        .map(|metadata| metadata.permissions());

    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        drop(file);
        if let Some(permissions) = existing_permissions {
            std::fs::set_permissions(&tmp_path, permissions)?;
        }
        crate::platform::rename(&tmp_path, &write_path)?;
        crate::platform::sync_directory(parent)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

pub(crate) fn resolve_shell_rc_write_path(rc_path: &std::path::Path) -> std::io::Result<PathBuf> {
    match std::fs::symlink_metadata(rc_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let target = std::fs::read_link(rc_path)?;
            if target.is_absolute() {
                Ok(target)
            } else {
                Ok(rc_path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join(target))
            }
        }
        Ok(_) => Ok(rc_path.to_path_buf()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(rc_path.to_path_buf()),
        Err(error) => Err(error),
    }
}

pub(crate) fn upsert_managed_path_line(contents: &str, export_line: &str) -> Option<String> {
    const MARKER: &str = "# Added by Sniper.app";
    let mut changed = false;
    let mut found_managed = false;
    let mut lines = Vec::new();
    for line in contents.lines() {
        if line.contains(MARKER) {
            if found_managed {
                changed = true;
                continue;
            }
            found_managed = true;
            changed |= line.trim() != export_line;
            lines.push(export_line.to_string());
        } else {
            lines.push(line.to_string());
        }
    }

    if !found_managed {
        if !contents.is_empty() {
            lines.push(String::new());
        }
        lines.push(export_line.to_string());
        changed = true;
    }

    if !changed {
        return None;
    }
    let mut updated = lines.join("\n");
    updated.push('\n');
    Some(updated)
}

pub(crate) fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
