use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

const UI_SETTINGS_FILE: &str = "ui-settings.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisplaySettingsSnapshot {
    pub size_px: u16,
    pub theme: String,
    pub ui_font: String,
    pub mono_font: String,
}

impl Default for DisplaySettingsSnapshot {
    fn default() -> Self {
        Self {
            size_px: 12,
            theme: "charcoal".to_string(),
            ui_font: "plex".to_string(),
            mono_font: "jetbrains".to_string(),
        }
    }
}

impl DisplaySettingsSnapshot {
    fn sanitized(self) -> Self {
        Self {
            size_px: self.size_px.clamp(8, 20),
            theme: sanitize_string(self.theme, "charcoal"),
            ui_font: sanitize_string(self.ui_font, "plex"),
            mono_font: sanitize_string(self.mono_font, "jetbrains"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppUiSettingsSnapshot {
    pub display_settings: DisplaySettingsSnapshot,
    pub history_column_widths: BTreeMap<String, u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history_column_order: Vec<String>,
    pub workbench_height: Option<u16>,
}

impl Default for AppUiSettingsSnapshot {
    fn default() -> Self {
        Self {
            display_settings: DisplaySettingsSnapshot::default(),
            history_column_widths: default_history_column_widths(),
            history_column_order: Vec::new(),
            workbench_height: None,
        }
    }
}

impl AppUiSettingsSnapshot {
    fn sanitized(self) -> Self {
        let mut sanitized = Self::default();

        sanitized.display_settings = self.display_settings.sanitized();
        sanitized.workbench_height = self
            .workbench_height
            .filter(|height| *height > 0)
            .map(|height| height.min(4_096));

        for (key, value) in self.history_column_widths {
            if !key.trim().is_empty() {
                sanitized.history_column_widths.insert(key, value.max(1));
            }
        }

        sanitized.history_column_order = self
            .history_column_order
            .into_iter()
            .filter(|key| !key.trim().is_empty())
            .collect();

        sanitized
    }
}

pub struct AppUiSettingsStore {
    path: PathBuf,
    inner: RwLock<AppUiSettingsSnapshot>,
}

impl AppUiSettingsStore {
    pub fn load_or_create(data_dir: &Path) -> Result<Self> {
        let snapshot = load_ui_settings_snapshot(data_dir)?;
        Ok(Self {
            path: ui_settings_path(data_dir),
            inner: RwLock::new(snapshot),
        })
    }

    pub async fn snapshot(&self) -> AppUiSettingsSnapshot {
        self.inner.read().await.clone()
    }

    pub async fn replace_snapshot(
        &self,
        snapshot: AppUiSettingsSnapshot,
    ) -> Result<AppUiSettingsSnapshot> {
        let next = snapshot.sanitized();
        persist_ui_settings(&self.path, &next)?;
        *self.inner.write().await = next.clone();
        Ok(next)
    }
}

fn ui_settings_path(data_dir: &Path) -> PathBuf {
    data_dir.join(UI_SETTINGS_FILE)
}

fn load_ui_settings_snapshot(data_dir: &Path) -> Result<AppUiSettingsSnapshot> {
    fs::create_dir_all(data_dir).with_context(|| {
        format!(
            "failed to create ui settings directory {}",
            data_dir.display()
        )
    })?;
    let path = ui_settings_path(data_dir);

    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<AppUiSettingsSnapshot>(&bytes)
            .map(AppUiSettingsSnapshot::sanitized)
            .with_context(|| format!("failed to parse ui settings {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let snapshot = AppUiSettingsSnapshot::default();
            persist_ui_settings(&path, &snapshot)?;
            Ok(snapshot)
        }
        Err(error) => {
            Err(error).with_context(|| format!("failed to read ui settings {}", path.display()))
        }
    }
}

fn persist_ui_settings(path: &Path, snapshot: &AppUiSettingsSnapshot) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create ui settings directory {}",
                parent.display()
            )
        })?;
    }

    fs::write(
        path,
        serde_json::to_vec_pretty(snapshot).context("failed to serialize ui settings")?,
    )
    .with_context(|| format!("failed to write ui settings {}", path.display()))
}

fn sanitize_string(value: String, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn default_history_column_widths() -> BTreeMap<String, u16> {
    BTreeMap::from([
        ("host".to_string(), 320),
        ("index".to_string(), 48),
        ("length".to_string(), 104),
        ("method".to_string(), 110),
        ("mime".to_string(), 128),
        ("notes".to_string(), 90),
        ("path".to_string(), 420),
        ("started_at".to_string(), 176),
        ("status".to_string(), 110),
        ("tls".to_string(), 92),
    ])
}

#[cfg(test)]
mod tests {
    use super::{AppUiSettingsSnapshot, AppUiSettingsStore};

    #[tokio::test]
    async fn ui_settings_store_persists_snapshot() {
        let data_dir =
            std::env::temp_dir().join(format!("sniper-ui-settings-{}", uuid::Uuid::new_v4()));
        let store = AppUiSettingsStore::load_or_create(&data_dir).expect("store should load");

        let mut snapshot = AppUiSettingsSnapshot::default();
        snapshot.display_settings.theme = "white".to_string();
        snapshot.display_settings.size_px = 15;
        snapshot
            .history_column_widths
            .insert("host".to_string(), 444);
        snapshot.workbench_height = Some(333);

        store
            .replace_snapshot(snapshot.clone())
            .await
            .expect("snapshot should persist");

        let reloaded = AppUiSettingsStore::load_or_create(&data_dir).expect("store should reload");
        let persisted = reloaded.snapshot().await;

        assert_eq!(persisted.display_settings.theme, "white");
        assert_eq!(persisted.display_settings.size_px, 15);
        assert_eq!(persisted.history_column_widths.get("host"), Some(&444));
        assert_eq!(persisted.workbench_height, Some(333));

        let _ = std::fs::remove_dir_all(&data_dir);
    }
}
