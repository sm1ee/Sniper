#![allow(clippy::too_many_arguments)]

pub mod api;
pub mod certificate;
pub mod config;
pub mod event_log;
pub mod fuzzer;
pub mod intercept;
pub mod match_replace;
pub mod model;
pub mod oast;
pub mod proxy;
pub mod runtime;
pub mod runtime_state;
pub mod scanner;
pub mod scope;
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
pub mod ws_tls;

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use config::AppConfig;
use state::AppState;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub async fn run() -> Result<()> {
    let config = AppConfig::from_env()?;
    run_with_config(config).await
}

pub async fn run_with_config(config: AppConfig) -> Result<()> {
    let Some(_runtime_owner_lock) =
        runtime_state::try_acquire_runtime_owner_lock(&config.data_dir)?
    else {
        anyhow::bail!(
            "another Sniper runtime is already using data dir {}; use a different SNIPER_DATA_DIR or stop the existing process",
            config.data_dir.display()
        );
    };
    let state = Arc::new(AppState::new(config.clone())?);
    let oast_task = oast::start_oast_poller_for_state(state.clone());

    info!(
        proxy_addr = %config.proxy_addr,
        ui_addr = %config.ui_addr,
        max_entries = config.max_entries,
        max_transaction_entries = config.max_transaction_entries,
        body_preview_bytes = config.body_preview_bytes,
        data_dir = %config.data_dir.display(),
        "starting sniper"
    );

    match proxy::run_proxy_listener(state.clone()).await {
        Ok(listener) => {
            let proxy_addr = listener
                .local_addr()
                .context("failed to read bound proxy address")?;
            state.set_active_proxy_addr(proxy_addr).await;
            let proxy_generation = state.mark_proxy_listener_online();
            state
                .log_info(
                    "runtime",
                    "Sniper started",
                    format!(
                        "Proxy listener {} and UI listener {} are starting",
                        proxy_addr, config.ui_addr
                    ),
                )
                .await;

            let proxy_state = state.clone();
            let offline_state = state.clone();
            let proxy_task = tokio::spawn(async move {
                if let Err(e) = proxy::serve_proxy(listener, proxy_state).await {
                    error!(?e, "proxy task stopped");
                    proxy::mark_proxy_offline_after_task_exit(
                        &offline_state,
                        proxy_addr,
                        proxy_generation,
                        "after initial proxy task stopped",
                    )
                    .await;
                }
            });
            state.set_proxy_task(proxy_task).await;

            let api_result = run_api_until_shutdown(state.clone()).await;
            let shutdown_result = shutdown_headless_runtime(&state, oast_task).await;
            combine_api_and_shutdown_results(api_result, shutdown_result)
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

            let api_result = run_api_until_shutdown(state.clone()).await;
            let shutdown_result = shutdown_headless_runtime(&state, oast_task).await;
            combine_api_and_shutdown_results(api_result, shutdown_result)
        }
    }
}

fn combine_api_and_shutdown_results(
    api_result: Result<()>,
    shutdown_result: Result<()>,
) -> Result<()> {
    match (api_result, shutdown_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(api_error), Err(shutdown_error)) => {
            Err(api_error.context(format!("headless shutdown also failed: {shutdown_error:#}")))
        }
    }
}

async fn run_api_until_shutdown(state: Arc<AppState>) -> Result<()> {
    tokio::select! {
        result = api::run_api(state) => result,
        () = wait_for_shutdown_signal() => {
            Ok(())
        }
    }
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => Some(signal),
                Err(error) => {
                    warn!(?error, "failed to listen for SIGTERM");
                    None
                }
            };
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                if let Err(error) = signal {
                    warn!(?error, "failed to listen for shutdown signal");
                } else {
                    info!("shutdown signal received");
                }
            }
            _ = async {
                if let Some(signal) = &mut terminate {
                    signal.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                info!("termination signal received");
            }
        }
    }
    #[cfg(not(unix))]
    {
        match tokio::signal::ctrl_c().await {
            Ok(()) => info!("shutdown signal received"),
            Err(error) => warn!(?error, "failed to listen for shutdown signal"),
        }
    }
}

async fn shutdown_headless_runtime(
    state: &AppState,
    oast_task: tokio::task::JoinHandle<()>,
) -> Result<()> {
    oast_task.abort();
    if let Err(error) = oast_task.await {
        if !error.is_cancelled() {
            warn!(
                ?error,
                "OAST poller stopped with an error during headless shutdown"
            );
        }
    }
    state.ws_replay.disconnect_all().await;
    let relay_result = proxy::close_live_websocket_relays(
        state,
        "Sniper headless shutdown closed the live WebSocket relay.",
    )
    .await
    .context("failed to persist closed live WebSocket relays before headless shutdown");
    state.abort_proxy_task().await;
    proxy::drain_proxy_connections(Duration::from_secs(1)).await;
    let flush_result = proxy::flush_pending_session_persists(state)
        .await
        .context("failed to flush pending session snapshots before headless shutdown");
    let active_result = state
        .persist_active_session()
        .await
        .map(|_| ())
        .context("failed to persist active session before headless shutdown");
    if let Err(error) = combine_api_and_shutdown_results(flush_result, active_result) {
        warn!(
            ?error,
            "leaving runtime state after failed headless session persistence"
        );
        return Err(error);
    }
    if let Err(error) = relay_result {
        warn!(
            ?error,
            "leaving runtime state after failed live WebSocket relay persistence"
        );
        return Err(error);
    }
    match runtime_state::remove_runtime_state_if_owner(
        &state.config.data_dir,
        state.runtime_instance_id,
    ) {
        Ok(true) => {}
        Ok(false) => {
            warn!("runtime state was replaced before headless shutdown; leaving it intact")
        }
        Err(error) => warn!(
            ?error,
            "failed to remove runtime state during headless shutdown"
        ),
    }
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
