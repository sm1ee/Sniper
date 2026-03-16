use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
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

/// Install skill files into the given root directory, replacing any existing copy.
pub fn install_skill_folder(root: &Path, name: &str, skill_md: &str) -> Result<PathBuf> {
    fs::create_dir_all(root)
        .with_context(|| format!("failed to create skills dir {}", root.display()))?;
    let skill_dir = root.join(name);
    if skill_dir.exists() {
        fs::remove_dir_all(&skill_dir)
            .with_context(|| format!("failed to replace {}", skill_dir.display()))?;
    }
    fs::create_dir_all(&skill_dir)
        .with_context(|| format!("failed to create {}", skill_dir.display()))?;
    fs::write(skill_dir.join("SKILL.md"), skill_md)
        .with_context(|| format!("failed to write {}", skill_dir.display()))?;
    Ok(skill_dir)
}

pub fn default_codex_skills_dir() -> PathBuf {
    if let Some(codex_home) = env::var_os("CODEX_HOME") {
        return PathBuf::from(codex_home).join("skills");
    }
    user_home_dir().join(".codex/skills")
}

pub fn default_claude_skills_dir() -> PathBuf {
    if let Some(claude_home) = env::var_os("CLAUDE_HOME") {
        return PathBuf::from(claude_home).join("skills");
    }
    user_home_dir().join(".claude/skills")
}

pub fn user_home_dir() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Install both Claude and Codex skills silently.
/// Returns the list of installed skills, or an empty vec if nothing was installed.
pub fn auto_install_all() -> Vec<InstalledSkill> {
    let mut installed = Vec::new();

    if let Ok(path) = install_skill_folder(
        &default_claude_skills_dir(),
        SKILL_NAME,
        CLAUDE_SKILL_TEMPLATE,
    ) {
        installed.push(InstalledSkill {
            agent: "claude",
            path: path.display().to_string(),
        });
    }

    if let Ok(path) = install_skill_folder(
        &default_codex_skills_dir(),
        SKILL_NAME,
        CODEX_SKILL_TEMPLATE,
    ) {
        installed.push(InstalledSkill {
            agent: "codex",
            path: path.display().to_string(),
        });
    }

    installed
}
