use std::{
    env,
    ffi::OsString,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde::Serialize;

pub const SKILL_NAME: &str = "sniper-operator";

pub const CODEX_SKILL_TEMPLATE: &str =
    include_str!("../packaging/skills/codex/sniper-operator/SKILL.md");
pub const CLAUDE_SKILL_TEMPLATE: &str =
    include_str!("../packaging/skills/claude/sniper-operator/SKILL.md");

#[derive(Debug, Serialize)]
pub struct InstalledSkill {
    pub agent: &'static str,
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct SkillsInstallResult {
    pub installed: Vec<InstalledSkill>,
}

#[derive(Debug, PartialEq, Eq)]
enum InstallOutcome {
    Created,
    Preserved,
}

/// Install or update the managed skill files into the given root directory.
pub fn install_skill_folder(root: &Path, name: &str, skill_md: &str) -> Result<PathBuf> {
    let (skill_dir, skill_path) = prepare_skill_folder(root, name)?;
    write_skill_markdown(&skill_dir, &skill_path, skill_md)?;
    Ok(skill_dir)
}

/// Install the managed skill only when the main SKILL.md is not already present.
/// Requires hard-link support; unsupported filesystems fail without replacing it.
pub fn install_skill_folder_if_missing(root: &Path, name: &str, skill_md: &str) -> Result<PathBuf> {
    install_skill_folder_if_missing_with(root, name, skill_md, |temp, destination| {
        fs::hard_link(temp, destination)
    })
    .map(|(path, _)| path)
}

fn install_skill_folder_if_missing_with(
    root: &Path,
    name: &str,
    skill_md: &str,
    publish: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> Result<(PathBuf, InstallOutcome)> {
    let (skill_dir, skill_path) = prepare_skill_folder(root, name)?;
    if path_is_occupied(&skill_path)? {
        return Ok((skill_dir, InstallOutcome::Preserved));
    }
    let tmp_path = skill_dir.join(format!("SKILL.{}.tmp", uuid::Uuid::new_v4()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .with_context(|| format!("failed to create {}", tmp_path.display()))?;
    let result = (|| {
        file.write_all(skill_md.as_bytes())
            .with_context(|| format!("failed to write {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync {}", tmp_path.display()))?;
        drop(file);

        // Link only the complete file, without replacing a competing creator.
        // Do not fall back to rename or in-place writes on unsupported filesystems.
        match publish(&tmp_path, &skill_path) {
            Ok(()) => Ok(InstallOutcome::Created),
            Err(error)
                if error.kind() == io::ErrorKind::AlreadyExists
                    || path_is_occupied(&skill_path)? =>
            {
                Ok(InstallOutcome::Preserved)
            }
            Err(error) => Err(error).with_context(|| {
                format!(
                    "failed to publish {} without replacing it (hard-link support required)",
                    skill_path.display()
                )
            }),
        }
    })();
    // The destination may belong to another installer, including after an error.
    let _ = fs::remove_file(&tmp_path);
    result.map(|outcome| (skill_dir, outcome))
}

fn prepare_skill_folder(root: &Path, name: &str) -> Result<(PathBuf, PathBuf)> {
    validate_skill_folder_name(name)?;
    fs::create_dir_all(root)
        .with_context(|| format!("failed to create skills dir {}", root.display()))?;
    let skill_dir = root.join(name);
    fs::create_dir_all(&skill_dir)
        .with_context(|| format!("failed to create {}", skill_dir.display()))?;
    let skill_path = skill_dir.join("SKILL.md");
    Ok((skill_dir, skill_path))
}

fn write_skill_markdown(skill_dir: &Path, skill_path: &Path, skill_md: &str) -> Result<()> {
    let tmp_path = skill_dir.join(format!("SKILL.{}.tmp", uuid::Uuid::new_v4()));
    fs::write(&tmp_path, skill_md)
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;
    if let Err(error) = crate::platform::rename(&tmp_path, skill_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(error).with_context(|| {
            format!(
                "failed to replace {} with {}",
                tmp_path.display(),
                skill_path.display()
            )
        });
    }
    Ok(())
}

fn path_is_occupied(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect existing path {}", path.display())),
    }
}

fn validate_skill_folder_name(name: &str) -> Result<()> {
    if name.trim().is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name == "."
        || name == ".."
    {
        bail!("skill folder name must be a single directory name");
    }
    Ok(())
}

pub fn default_codex_skills_dir() -> Option<PathBuf> {
    if let Some(codex_home) = agent_home_dir(env::var_os("CODEX_HOME")) {
        return Some(PathBuf::from(codex_home).join("skills"));
    }
    user_home_dir().map(|home| home.join(".codex/skills"))
}

pub fn default_claude_skills_dir() -> Option<PathBuf> {
    if let Some(claude_home) = agent_home_dir(env::var_os("CLAUDE_HOME")) {
        return Some(PathBuf::from(claude_home).join("skills"));
    }
    user_home_dir().map(|home| home.join(".claude/skills"))
}

fn agent_home_dir(value: Option<OsString>) -> Option<OsString> {
    let value = value?;
    if value.to_string_lossy().trim().is_empty() {
        return None;
    }
    Some(value)
}

pub fn user_home_dir() -> Option<PathBuf> {
    crate::platform::user_home_dir()
}

pub fn ensure_distinct_skill_install_targets(codex_root: &Path, claude_root: &Path) -> Result<()> {
    let codex_target = codex_root.join(SKILL_NAME).join("SKILL.md");
    let claude_target = claude_root.join(SKILL_NAME).join("SKILL.md");
    let canonical_conflict = match (
        canonicalize_existing_prefix(&codex_target),
        canonicalize_existing_prefix(&claude_target),
    ) {
        (Some(codex_target), Some(claude_target)) => codex_target == claude_target,
        _ => false,
    };
    if codex_target == claude_target || canonical_conflict {
        bail!(
            "codex and claude skill destinations resolve to the same SKILL.md path: {}",
            codex_target.display()
        );
    }
    Ok(())
}

fn canonicalize_existing_prefix(path: &Path) -> Option<PathBuf> {
    if let Ok(path) = fs::canonicalize(path) {
        return Some(path);
    }

    let mut current = path;
    let mut missing = Vec::new();
    while !current.exists() {
        missing.push(current.file_name()?.to_os_string());
        current = current.parent()?;
    }

    let mut canonical = fs::canonicalize(current).ok()?;
    for component in missing.iter().rev() {
        canonical.push(component);
    }
    Some(canonical)
}

/// Install missing Claude and Codex skills silently.
/// Returns the list of installed skills, or an empty vec if nothing was installed.
/// Unsupported hard-link publication is skipped, without a replacing fallback.
pub fn auto_install_all() -> Vec<InstalledSkill> {
    let Some(claude_root) = default_claude_skills_dir() else {
        return Vec::new();
    };
    let Some(codex_root) = default_codex_skills_dir() else {
        return Vec::new();
    };
    auto_install_all_to(claude_root, codex_root)
}

fn auto_install_all_to(claude_root: PathBuf, codex_root: PathBuf) -> Vec<InstalledSkill> {
    let mut installed = Vec::new();

    if ensure_distinct_skill_install_targets(&codex_root, &claude_root).is_err() {
        return installed;
    }

    if let Ok((path, InstallOutcome::Created)) = install_skill_folder_if_missing_with(
        &claude_root,
        SKILL_NAME,
        CLAUDE_SKILL_TEMPLATE,
        |temp, destination| fs::hard_link(temp, destination),
    ) {
        installed.push(InstalledSkill {
            agent: "claude",
            path: path.display().to_string(),
        });
    }

    if let Ok((path, InstallOutcome::Created)) = install_skill_folder_if_missing_with(
        &codex_root,
        SKILL_NAME,
        CODEX_SKILL_TEMPLATE,
        |temp, destination| fs::hard_link(temp, destination),
    ) {
        installed.push(InstalledSkill {
            agent: "codex",
            path: path.display().to_string(),
        });
    }

    installed
}

#[cfg(test)]
mod tests {
    use super::{agent_home_dir, auto_install_all_to, install_skill_folder};

    fn assert_no_skill_temps(skill_dir: &std::path::Path) {
        assert!(!std::fs::read_dir(skill_dir).unwrap().any(|entry| {
            let name = entry.unwrap().file_name();
            let name = name.to_string_lossy();
            name.starts_with("SKILL.") && name.ends_with(".tmp")
        }));
    }

    fn saved_data_guidance(template: &str) -> String {
        let mut lines = template.lines();
        assert!(
            lines.any(|line| line == "## Saved data and session management"),
            "packaged skill must explain saved-data contracts"
        );
        // Windows checkouts may use CRLF; compare Markdown content, not EOLs.
        lines
            .take_while(|line| !line.starts_with("## "))
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_owned()
    }

    #[test]
    fn packaged_saved_data_section_accepts_lf_and_crlf() {
        for newline in ["\n", "\r\n"] {
            let fixture = [
                "# Skill",
                "",
                "## Saved data and session management",
                "",
                "Saved guidance.",
                "### Details",
                "Keep this subsection.",
                "",
                "## Next section",
                "Exclude this section.",
            ]
            .join(newline);
            assert_eq!(
                saved_data_guidance(&fixture),
                "Saved guidance.\n### Details\nKeep this subsection."
            );
        }
    }

    #[test]
    fn packaged_saved_data_guidance_stays_in_sync_and_covers_the_contract() {
        let section = saved_data_guidance(super::CODEX_SKILL_TEMPLATE);
        assert_eq!(section, saved_data_guidance(super::CLAUDE_SKILL_TEMPLATE));
        for operation in crate::saved_contract::OPERATIONS {
            assert!(
                section.contains(operation),
                "missing saved operation: {operation}"
            );
        }
        let receipt_code =
            serde_json::to_string(&crate::saved_operations::SavedOperationCode::SelectionMismatch)
                .unwrap();
        assert!(section.contains(&format!("data.receipt.code:{receipt_code}")));
        for term in [
            "receipt.outcome",
            "operation_id",
            "continuation",
            "STALE_CONTINUATION",
            "found:false",
            "unknown",
            "--dry-run",
            "--yes",
        ] {
            assert!(section.contains(term), "missing contract guidance: {term}");
        }
    }

    #[test]
    fn packaged_saved_data_examples_validate_without_running_operations() {
        let mut examples = 0;
        let mut mutation_examples = 0;
        for line in saved_data_guidance(super::CODEX_SKILL_TEMPLATE).lines() {
            if !line.starts_with("sniper-cli ") {
                continue;
            }
            let Some((_, call)) = line.split_once("call saved.v1.") else {
                continue;
            };
            let operation = format!("saved.v1.{}", call.split_whitespace().next().unwrap());
            let Some((_, quoted)) = line.split_once("--input '") else {
                panic!("saved-data examples need literal JSON input: {line}");
            };
            let raw = quoted.split_once('\'').expect("closed shell JSON quote").0;
            let input: serde_json::Value = serde_json::from_str(raw).expect("valid example JSON");
            crate::saved_contract::validate_input(&operation, &input)
                .unwrap_or_else(|error| panic!("invalid {operation} example: {error}"));
            if crate::saved_contract::is_write(&operation) {
                assert!(
                    line.contains("--dry-run") || line.contains("--yes"),
                    "mutation examples require a confirmation gate"
                );
                if line.contains("--yes") {
                    assert!(
                        saved_data_guidance(super::CODEX_SKILL_TEMPLATE)
                            .contains(&line.replace("--yes", "--dry-run")),
                        "an apply example must have an identical preview example"
                    );
                }
                mutation_examples += 1;
            }
            examples += 1;
        }
        assert!(
            examples >= 3,
            "keep read, mutation preview, and receipt examples"
        );
        assert!(mutation_examples > 0);
    }

    #[test]
    fn packaged_skill_maintenance_guidance_stays_in_sync() {
        fn maintenance(template: &str) -> String {
            template
                .lines()
                .skip_while(|line| *line != "## Skill maintenance")
                .skip(1)
                .take_while(|line| !line.starts_with("## "))
                .collect::<Vec<_>>()
                .join("\n")
        }
        let section = maintenance(super::CODEX_SKILL_TEMPLATE);
        assert_eq!(section, maintenance(super::CLAUDE_SKILL_TEMPLATE));
        for term in [
            "skills status",
            "skills update-preview",
            "skills.enroll",
            "skills.stage_update",
            "activated:false",
            "does not enable automatic updates",
            "overwrite",
            "loaded context",
        ] {
            assert!(
                section.contains(term),
                "missing maintenance guidance: {term}"
            );
        }
    }

    #[test]
    fn install_skill_folder_rejects_path_like_names() {
        let root = std::env::temp_dir().join(format!("sniper-skill-test-{}", uuid::Uuid::new_v4()));

        assert!(install_skill_folder(&root, "../outside", "# test\n").is_err());
        assert!(install_skill_folder(&root, "nested/skill", "# test\n").is_err());
        assert!(install_skill_folder(&root, "", "# test\n").is_err());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn install_skill_folder_cleans_temp_file_after_replace_failure() {
        let root = std::env::temp_dir().join(format!("sniper-skill-test-{}", uuid::Uuid::new_v4()));
        let skill_dir = root.join("sniper-operator");
        std::fs::create_dir_all(skill_dir.join("SKILL.md")).unwrap();

        assert!(install_skill_folder(&root, "sniper-operator", "# test\n").is_err());

        let leaked_temp = std::fs::read_dir(&skill_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .any(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with("SKILL.") && name.ends_with(".tmp")
            });
        assert!(!leaked_temp);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn install_skill_folder_if_missing_preserves_competing_create() {
        let root = std::env::temp_dir().join(format!("sniper-skill-race-{}", uuid::Uuid::new_v4()));
        let (path, outcome) = super::install_skill_folder_if_missing_with(
            &root,
            super::SKILL_NAME,
            "# bundled skill\n",
            |temp, skill_path| {
                std::fs::write(skill_path, "# competing skill\n")?;
                std::fs::hard_link(temp, skill_path)
            },
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(path.join("SKILL.md")).unwrap(),
            "# competing skill\n"
        );
        assert_eq!(outcome, super::InstallOutcome::Preserved);
        assert_no_skill_temps(&path);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn install_skill_folder_if_missing_publishes_complete_file() {
        let root =
            std::env::temp_dir().join(format!("sniper-skill-complete-{}", uuid::Uuid::new_v4()));
        let content = "# complete skill\n".repeat(4096);
        let (path, outcome) = super::install_skill_folder_if_missing_with(
            &root,
            super::SKILL_NAME,
            &content,
            |temp, skill_path| {
                assert!(!super::path_is_occupied(skill_path).unwrap());
                assert_eq!(std::fs::read_to_string(temp).unwrap(), content);
                std::fs::hard_link(temp, skill_path)?;
                assert_eq!(std::fs::read_to_string(skill_path).unwrap(), content);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(outcome, super::InstallOutcome::Created);
        assert_eq!(
            std::fs::read_to_string(path.join("SKILL.md")).unwrap(),
            content
        );
        assert_no_skill_temps(&path);
        assert_eq!(
            super::install_skill_folder_if_missing(&root, super::SKILL_NAME, "replacement")
                .unwrap(),
            path
        );
        assert_eq!(
            std::fs::read_to_string(path.join("SKILL.md")).unwrap(),
            content
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn install_skill_folder_if_missing_preserves_existing_and_competing_directories() {
        for racing in [false, true] {
            let root = std::env::temp_dir()
                .join(format!("sniper-skill-directory-{}", uuid::Uuid::new_v4()));
            let skill_path = root.join(super::SKILL_NAME).join("SKILL.md");
            let create_directory = || {
                std::fs::create_dir_all(&skill_path).unwrap();
                std::fs::write(skill_path.join("keep"), "retained").unwrap();
            };
            if !racing {
                create_directory();
            }
            let (path, outcome) = super::install_skill_folder_if_missing_with(
                &root,
                super::SKILL_NAME,
                "# bundled skill\n",
                |temp, destination| {
                    assert!(racing, "an occupied destination must skip publication");
                    create_directory();
                    std::fs::hard_link(temp, destination)
                },
            )
            .unwrap();

            assert_eq!(outcome, super::InstallOutcome::Preserved);
            assert!(skill_path.is_dir());
            assert_eq!(
                std::fs::read_to_string(skill_path.join("keep")).unwrap(),
                "retained"
            );
            assert_no_skill_temps(&path);
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[cfg(unix)]
    #[test]
    fn install_skill_folder_if_missing_preserves_existing_and_competing_symlinks() {
        for racing in [false, true] {
            for dangling in [false, true] {
                let root = std::env::temp_dir()
                    .join(format!("sniper-skill-link-{}", uuid::Uuid::new_v4()));
                let skill_dir = root.join(super::SKILL_NAME);
                let skill_path = skill_dir.join("SKILL.md");
                let target = root.join("target.md");
                std::fs::create_dir_all(&skill_dir).unwrap();
                if !dangling {
                    std::fs::write(&target, "# custom skill\n").unwrap();
                }
                if !racing {
                    std::os::unix::fs::symlink(&target, &skill_path).unwrap();
                }
                let (path, outcome) = super::install_skill_folder_if_missing_with(
                    &root,
                    super::SKILL_NAME,
                    "# bundled skill\n",
                    |temp, destination| {
                        assert!(racing, "an occupied destination must skip publication");
                        std::os::unix::fs::symlink(&target, destination)?;
                        std::fs::hard_link(temp, destination)
                    },
                )
                .unwrap();

                assert_eq!(outcome, super::InstallOutcome::Preserved);
                assert!(std::fs::symlink_metadata(&skill_path)
                    .unwrap()
                    .file_type()
                    .is_symlink());
                assert_eq!(std::fs::read_link(&skill_path).unwrap(), target);
                if dangling {
                    assert!(!target.exists());
                } else {
                    assert_eq!(
                        std::fs::read_to_string(&target).unwrap(),
                        "# custom skill\n"
                    );
                }
                assert_no_skill_temps(&path);
                let _ = std::fs::remove_dir_all(root);
            }
        }
    }

    #[test]
    fn install_skill_folder_if_missing_cleans_temp_after_publication_failure() {
        for kind in [
            std::io::ErrorKind::Unsupported,
            std::io::ErrorKind::PermissionDenied,
        ] {
            let root = std::env::temp_dir()
                .join(format!("sniper-skill-failed-link-{}", uuid::Uuid::new_v4()));
            let skill_dir = root.join(super::SKILL_NAME);
            let error = super::install_skill_folder_if_missing_with(
                &root,
                super::SKILL_NAME,
                "# bundled skill\n",
                |temp, destination| {
                    assert_eq!(std::fs::read_to_string(temp).unwrap(), "# bundled skill\n");
                    assert!(!super::path_is_occupied(destination).unwrap());
                    Err(std::io::Error::new(kind, "injected publication failure"))
                },
            )
            .unwrap_err();

            assert!(error.to_string().contains("hard-link support required"));
            assert!(!super::path_is_occupied(&skill_dir.join("SKILL.md")).unwrap());
            assert_no_skill_temps(&skill_dir);
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[test]
    fn install_skill_folder_if_missing_preserves_competitor_after_other_publication_error() {
        let root =
            std::env::temp_dir().join(format!("sniper-skill-failed-race-{}", uuid::Uuid::new_v4()));
        let (path, outcome) = super::install_skill_folder_if_missing_with(
            &root,
            super::SKILL_NAME,
            "# bundled skill\n",
            |_, destination| {
                std::fs::write(destination, "# competing skill\n")?;
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "injected collision",
                ))
            },
        )
        .unwrap();

        assert_eq!(outcome, super::InstallOutcome::Preserved);
        assert_eq!(
            std::fs::read_to_string(path.join("SKILL.md")).unwrap(),
            "# competing skill\n"
        );
        assert_no_skill_temps(&path);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn install_skill_folder_if_missing_has_one_concurrent_winner() {
        let root =
            std::env::temp_dir().join(format!("sniper-skill-winners-{}", uuid::Uuid::new_v4()));
        let barrier = std::sync::Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = ["# first skill\n", "# second skill\n"]
                .into_iter()
                .map(|content| {
                    let root = &root;
                    let barrier = &barrier;
                    scope.spawn(move || {
                        let (_, outcome) = super::install_skill_folder_if_missing_with(
                            root,
                            super::SKILL_NAME,
                            content,
                            |temp, destination| {
                                barrier.wait();
                                std::fs::hard_link(temp, destination)
                            },
                        )
                        .unwrap();
                        (content, outcome)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });

        assert_eq!(
            results
                .iter()
                .filter(|(_, outcome)| *outcome == super::InstallOutcome::Created)
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|(_, outcome)| *outcome == super::InstallOutcome::Preserved)
                .count(),
            1
        );
        let winning_content = results
            .iter()
            .find(|(_, outcome)| *outcome == super::InstallOutcome::Created)
            .unwrap()
            .0;
        let skill_dir = root.join(super::SKILL_NAME);
        assert_eq!(
            std::fs::read_to_string(skill_dir.join("SKILL.md")).unwrap(),
            winning_content
        );
        assert_no_skill_temps(&skill_dir);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn install_skill_folder_still_replaces_existing_markdown_when_explicit() {
        let root =
            std::env::temp_dir().join(format!("sniper-skill-replace-{}", uuid::Uuid::new_v4()));
        let path = install_skill_folder(&root, super::SKILL_NAME, "# original skill\n").unwrap();
        assert_eq!(
            install_skill_folder(&root, super::SKILL_NAME, "# replacement skill\n").unwrap(),
            path
        );
        assert_eq!(
            std::fs::read_to_string(path.join("SKILL.md")).unwrap(),
            "# replacement skill\n"
        );
        assert_no_skill_temps(&path);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn agent_home_dir_ignores_empty_values() {
        assert!(agent_home_dir(Some("".into())).is_none());
        assert!(agent_home_dir(Some(" \t ".into())).is_none());
        assert_eq!(
            agent_home_dir(Some("/tmp/sniper-agent-home".into())),
            Some("/tmp/sniper-agent-home".into())
        );
    }

    #[test]
    fn auto_install_all_skips_same_claude_and_codex_destination() {
        let root = std::env::temp_dir().join(format!("sniper-skill-same-{}", uuid::Uuid::new_v4()));

        let installed = auto_install_all_to(root.join("skills"), root.join("skills"));

        assert!(installed.is_empty());
        assert!(!root
            .join("skills")
            .join(super::SKILL_NAME)
            .join("SKILL.md")
            .exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn auto_install_all_preserves_existing_skill_markdown() {
        let root =
            std::env::temp_dir().join(format!("sniper-skill-preserve-{}", uuid::Uuid::new_v4()));
        let claude_root = root.join("claude");
        let codex_root = root.join("codex");
        let claude_skill = claude_root.join(super::SKILL_NAME).join("SKILL.md");
        let codex_skill = codex_root.join(super::SKILL_NAME).join("SKILL.md");
        std::fs::create_dir_all(claude_skill.parent().unwrap()).unwrap();
        std::fs::create_dir_all(codex_skill.parent().unwrap()).unwrap();
        std::fs::write(&claude_skill, "# custom claude skill\n").unwrap();
        std::fs::write(&codex_skill, "# custom codex skill\n").unwrap();

        let installed = auto_install_all_to(claude_root, codex_root);

        assert!(installed.is_empty());
        assert_eq!(
            std::fs::read_to_string(&claude_skill).unwrap(),
            "# custom claude skill\n"
        );
        assert_eq!(
            std::fs::read_to_string(&codex_skill).unwrap(),
            "# custom codex skill\n"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn auto_install_all_reports_only_newly_created_files() {
        let root =
            std::env::temp_dir().join(format!("sniper-skill-count-{}", uuid::Uuid::new_v4()));
        let claude_root = root.join("claude");
        let codex_root = root.join("codex");
        let installed = auto_install_all_to(claude_root.clone(), codex_root.clone());
        assert_eq!(installed.len(), 2);
        assert_eq!(installed[0].agent, "claude");
        assert_eq!(installed[1].agent, "codex");
        for (skill_root, template) in [
            (&claude_root, super::CLAUDE_SKILL_TEMPLATE),
            (&codex_root, super::CODEX_SKILL_TEMPLATE),
        ] {
            let path = skill_root.join(super::SKILL_NAME);
            assert_eq!(
                std::fs::read_to_string(path.join("SKILL.md")).unwrap(),
                template
            );
            assert_no_skill_temps(&path);
        }
        assert!(auto_install_all_to(claude_root.clone(), codex_root.clone()).is_empty());

        std::fs::remove_file(claude_root.join(super::SKILL_NAME).join("SKILL.md")).unwrap();
        let codex_skill = codex_root.join(super::SKILL_NAME).join("SKILL.md");
        std::fs::write(&codex_skill, "# custom codex skill\n").unwrap();
        let installed = auto_install_all_to(claude_root.clone(), codex_root);
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].agent, "claude");
        assert_eq!(
            installed[0].path,
            claude_root.join(super::SKILL_NAME).display().to_string()
        );
        assert_eq!(
            std::fs::read_to_string(codex_skill).unwrap(),
            "# custom codex skill\n"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn auto_install_all_skips_symlinked_missing_skill_roots() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "sniper-skill-symlink-same-{}",
            uuid::Uuid::new_v4()
        ));
        let shared_home = root.join("shared-home");
        let codex_home = root.join("codex-home");
        let claude_home = root.join("claude-home");
        std::fs::create_dir_all(&shared_home).unwrap();
        symlink(&shared_home, &codex_home).unwrap();
        symlink(&shared_home, &claude_home).unwrap();

        let installed = auto_install_all_to(claude_home.join("skills"), codex_home.join("skills"));

        assert!(installed.is_empty());
        assert!(!shared_home
            .join("skills")
            .join(super::SKILL_NAME)
            .join("SKILL.md")
            .exists());
        let _ = std::fs::remove_dir_all(root);
    }
}
