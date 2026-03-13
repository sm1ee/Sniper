pub mod api;
pub mod certificate;
pub mod config;
pub mod event_log;
pub mod intercept;
pub mod intruder;
pub mod match_replace;
pub mod model;
pub mod proxy;
pub mod runtime;
pub mod runtime_state;
pub mod session;
pub mod special_host;
pub mod state;
pub mod store;
pub mod target;
pub mod ui_settings;
pub mod websocket;
pub mod workspace;

use std::sync::Arc;

use anyhow::Result;
use config::AppConfig;
use state::AppState;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub async fn run() -> Result<()> {
    let config = AppConfig::from_env()?;
    run_with_config(config).await
}

pub async fn run_with_config(config: AppConfig) -> Result<()> {
    let state = Arc::new(AppState::new(config.clone())?);
    state
        .log_info(
            "runtime",
            "Sniper started",
            format!(
                "Proxy listener {} and UI listener {} are starting",
                config.proxy_addr, config.ui_addr
            ),
        )
        .await;

    info!(
        proxy_addr = %config.proxy_addr,
        ui_addr = %config.ui_addr,
        max_entries = config.max_entries,
        body_preview_bytes = config.body_preview_bytes,
        data_dir = %config.data_dir.display(),
        "starting sniper"
    );

    tokio::try_join!(proxy::run_proxy(state.clone()), api::run_api(state))?;
    Ok(())
}

pub fn init_tracing() {
    static INIT: std::sync::Once = std::sync::Once::new();

    INIT.call_once(|| {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "sniper=info,tower_http=warn".into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();
    });
}
