pub mod api;
pub mod certificate;
pub mod config;
pub mod event_log;
pub mod intercept;
pub mod fuzzer;
pub mod match_replace;
pub mod model;
pub mod proxy;
pub mod runtime;
pub mod runtime_state;
pub mod scanner;
pub mod sequence;
pub mod session;
pub mod skills;
pub mod special_host;
pub mod state;
pub mod store;
pub mod target;
pub mod ui_settings;
pub mod websocket;
pub mod workspace;
pub mod ws_replay;

use std::sync::Arc;

use anyhow::Result;
use config::AppConfig;
use state::AppState;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub async fn run() -> Result<()> {
    let config = AppConfig::from_env()?;
    run_with_config(config).await
}

pub async fn run_with_config(config: AppConfig) -> Result<()> {
    let state = Arc::new(AppState::new(config.clone())?);

    info!(
        proxy_addr = %config.proxy_addr,
        ui_addr = %config.ui_addr,
        max_entries = config.max_entries,
        body_preview_bytes = config.body_preview_bytes,
        data_dir = %config.data_dir.display(),
        "starting sniper"
    );

    match proxy::run_proxy_listener(state.clone()).await {
        Ok(listener) => {
            state.set_proxy_online(true);
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

            let proxy_state = state.clone();
            let proxy_task = tokio::spawn(async move {
                if let Err(e) = proxy::serve_proxy(listener, proxy_state).await {
                    error!(?e, "proxy task stopped");
                }
            });

            let api_result = api::run_api(state).await;
            proxy_task.abort();
            api_result
        }
        Err(bind_error) => {
            warn!(%bind_error, "proxy listener failed to bind — starting UI only");
            state
                .log_error(
                    "runtime",
                    "Proxy listener failed",
                    format!(
                        "Could not bind proxy to {}: {}. The UI is available but proxy capture is offline.",
                        config.proxy_addr, bind_error
                    ),
                )
                .await;

            api::run_api(state).await
        }
    }
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
