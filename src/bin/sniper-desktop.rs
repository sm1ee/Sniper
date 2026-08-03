use std::{
    env,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use anyhow::{Context, Result};
use sniper::{api, config::AppConfig, proxy, runtime_state, skills, state::AppState};
use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy},
    window::WindowBuilder,
};
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use url::Url;
use uuid::Uuid;
use wry::{WebView, WebViewBuilder};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DesktopUserEvent {
    ShutdownSignal,
    WebviewCloseFlushFinished { generation: u64, ok: bool },
    WebviewCloseFlushTimedOut { generation: u64 },
}

const APP_BUNDLE_IDENTIFIER: &str = "com.sm1ee.sniper";
const OPEN_PATH: &str = "/usr/bin/open";
const INSTALL_SKILLS_ENV: &str = "SNIPER_INSTALL_AGENT_SKILLS";
const INSTALL_CLI_PATH_ENV: &str = "SNIPER_INSTALL_CLI_PATH";
const SNIPER_DATA_DIR_ENV: &str = "SNIPER_DATA_DIR";
const DESKTOP_CLOSE_FLUSH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const DESKTOP_CLOSE_FLUSH_OK_PREFIX: &str = "sniper:native-close-flush-ok:";
const DESKTOP_CLOSE_FLUSH_ERROR_PREFIX: &str = "sniper:native-close-flush-error:";

fn desktop_data_dir_from_env() -> PathBuf {
    env::var_os(SNIPER_DATA_DIR_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_desktop_data_dir)
}

fn default_desktop_data_dir() -> PathBuf {
    env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".sniper"))
        .unwrap_or_else(|| PathBuf::from(".sniper"))
}

fn normalize_empty_data_dir_env() {
    if env::var_os(SNIPER_DATA_DIR_ENV).is_some_and(|value| value.is_empty()) {
        env::remove_var(SNIPER_DATA_DIR_ENV);
    }
}

fn request_existing_desktop_focus() -> bool {
    #[cfg(target_os = "macos")]
    {
        request_existing_desktop_focus_with(Path::new(OPEN_PATH), APP_BUNDLE_IDENTIFIER)
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

fn request_existing_desktop_focus_with(open_path: &Path, bundle_identifier: &str) -> bool {
    match Command::new(open_path)
        .args(["-b", bundle_identifier])
        .status()
    {
        Ok(status) if status.success() => true,
        Ok(status) => {
            warn!(
                ?status,
                "failed to request focus for existing Sniper desktop"
            );
            false
        }
        Err(error) => {
            warn!(
                ?error,
                "failed to request focus for existing Sniper desktop"
            );
            false
        }
    }
}

fn should_request_existing_desktop_focus(data_dir: &Path) -> bool {
    match runtime_state::load_runtime_state(data_dir) {
        Ok(Some(snapshot)) => {
            process_path_points_to_desktop_bundle(snapshot.process_path.as_deref())
        }
        Ok(None) => false,
        Err(error) => {
            warn!(
                ?error,
                data_dir = %data_dir.display(),
                "could not inspect existing Sniper runtime owner"
            );
            false
        }
    }
}

fn process_path_points_to_desktop_bundle(process_path: Option<&str>) -> bool {
    let Some(process_path) = process_path else {
        return false;
    };
    let path = Path::new(process_path);
    if path.file_name().and_then(|name| name.to_str()) != Some("Sniper") {
        return false;
    }

    let mut components = path.components().rev();
    if components
        .next()
        .and_then(|component| component.as_os_str().to_str())
        != Some("Sniper")
    {
        return false;
    }
    if components
        .next()
        .and_then(|component| component.as_os_str().to_str())
        != Some("MacOS")
    {
        return false;
    }
    if components
        .next()
        .and_then(|component| component.as_os_str().to_str())
        != Some("Contents")
    {
        return false;
    }
    components
        .next()
        .and_then(|component| component.as_os_str().to_str())
        .is_some_and(|bundle| bundle == "Sniper.app")
}

fn main() -> Result<()> {
    sniper::init_tracing();
    normalize_empty_data_dir_env();

    let data_dir = desktop_data_dir_from_env();
    let Some(_runtime_owner_lock) = runtime_state::try_acquire_runtime_owner_lock(&data_dir)?
    else {
        warn!(
            data_dir = %data_dir.display(),
            "another Sniper runtime is already using this data directory"
        );
        if should_request_existing_desktop_focus(&data_dir) && request_existing_desktop_focus() {
            return Ok(());
        }
        anyhow::bail!(
            "another Sniper runtime is already using data dir {}; stop the existing Sniper CLI/server process or use a different SNIPER_DATA_DIR before launching Sniper.app",
            data_dir.display()
        );
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create desktop runtime")?;

    let mut config = AppConfig::from_env_for_desktop()?;

    let proxy_listener = match runtime.block_on(proxy::bind_proxy_listener(config.proxy_addr)) {
        Ok(listener) => {
            config.proxy_addr = listener
                .local_addr()
                .context("failed to read bound proxy address")?;
            Some(listener)
        }
        Err(bind_error) => {
            error!(
                addr = %config.proxy_addr,
                %bind_error,
                "proxy listener failed to bind — starting UI only"
            );
            None
        }
    };

    let ui_listener = runtime
        .block_on(TcpListener::bind(config.ui_addr))
        .with_context(|| format!("failed to bind UI listener to {}", config.ui_addr))?;
    let bound_ui_addr = ui_listener
        .local_addr()
        .context("failed to read bound UI address")?;
    config.ui_addr = runtime_state::advertise_local_api_addr(bound_ui_addr);

    // Keep agent skill installation opt-in; normal desktop launch should not edit user dotfiles.
    let install_skills_env = env::var(INSTALL_SKILLS_ENV).ok();
    if should_install_skills_on_launch(install_skills_env.as_deref()) {
        let skill_results = skills::auto_install_all();
        for skill in &skill_results {
            info!(agent = skill.agent, path = %skill.path, "installed sniper-operator skill");
        }
    } else {
        info!(
            env = INSTALL_SKILLS_ENV,
            "skipping agent skill install unless explicitly requested"
        );
    }

    // Keep shell rc mutation opt-in; normal desktop launch should not edit user dotfiles.
    let install_cli_path_env = env::var(INSTALL_CLI_PATH_ENV).ok();
    if should_install_cli_path_on_launch(install_cli_path_env.as_deref()) {
        install_cli_path();
    } else {
        info!(
            env = INSTALL_CLI_PATH_ENV,
            "skipping sniper-cli PATH install unless explicitly requested"
        );
    }

    let state = Arc::new(AppState::new(config.clone())?);

    let initial_proxy_generation = if proxy_listener.is_some() {
        let proxy_generation = state.mark_proxy_listener_online();
        runtime.block_on(state.log_info(
            "runtime",
            "Sniper desktop started",
            format!(
                "Proxy listener {} and UI listener {} are ready",
                config.proxy_addr, config.ui_addr
            ),
        ));
        Some(proxy_generation)
    } else {
        runtime.block_on(state.log_error(
            "runtime",
            "Proxy listener failed",
            format!(
                "Could not bind proxy to {}. The UI is available but proxy capture is offline.",
                config.proxy_addr
            ),
        ));
        None
    };

    let ui_state = state.clone();

    info!(
        proxy_addr = %config.proxy_addr,
        ui_addr = %config.ui_addr,
        proxy_online = proxy_listener.is_some(),
        "starting sniper desktop"
    );

    let proxy_task = if let Some(listener) = proxy_listener {
        let proxy_state = state.clone();
        let offline_state = state.clone();
        let proxy_addr = config.proxy_addr;
        let proxy_generation =
            initial_proxy_generation.expect("proxy generation should exist when listener is bound");
        let handle = runtime.spawn(async move {
            if let Err(error) = proxy::serve_proxy(listener, proxy_state).await {
                error!(?error, "proxy task stopped");
                proxy::mark_proxy_offline_after_task_exit(
                    &offline_state,
                    proxy_addr,
                    proxy_generation,
                    "after initial proxy task stopped",
                )
                .await;
            }
        });
        // Store the handle so rebind_proxy can abort it later
        runtime.block_on(state.set_proxy_task(handle));
        // Read the handle back — we still need a reference for shutdown
        None::<tokio::task::JoinHandle<()>>
    } else {
        None
    };
    let oast_task = runtime.spawn(sniper::oast::run_oast_poller_for_state(state.clone()));

    let event_loop = EventLoopBuilder::<DesktopUserEvent>::with_user_event().build();
    let event_proxy = event_loop.create_proxy();
    let signal_task = runtime.spawn(wait_for_desktop_shutdown_signal(event_proxy));
    install_platform_app_menu();
    let window = WindowBuilder::new()
        .with_title("Sniper")
        .with_inner_size(LogicalSize::new(1440.0, 920.0))
        .with_min_inner_size(LogicalSize::new(1120.0, 720.0))
        .build(&event_loop)
        .context("failed to create desktop window")?;
    enable_window_fullscreen_support(&window);
    let ui_url = format!("http://{}/", config.ui_addr);
    let ui_origin = format!("http://{}", config.ui_addr);
    let ipc_event_proxy = event_loop.create_proxy();
    let ui_task = runtime.spawn(async move {
        if let Err(error) = api::serve_api(ui_listener, ui_state).await {
            error!(?error, "ui task stopped");
        }
    });
    let webview_builder = WebViewBuilder::new(&window)
        .with_incognito(true)
        .with_devtools(desktop_devtools_enabled())
        .with_navigation_handler({
            let ui_origin = ui_origin.clone();
            move |url| handle_navigation_request(&url, &ui_origin)
        })
        .with_new_window_req_handler({
            let ui_origin = ui_origin.clone();
            move |url| handle_new_window_request(&url, &ui_origin)
        })
        .with_ipc_handler(move |request| {
            let Some(event) = desktop_user_event_from_ipc(request.body()) else {
                return;
            };
            if let Err(error) = ipc_event_proxy.send_event(event) {
                warn!(?error, "failed to forward desktop webview IPC event");
            }
        })
        .with_url(&ui_url);
    let webview = match webview_builder.build() {
        Ok(webview) => webview,
        Err(error) => {
            ui_task.abort();
            if let Err(join_error) = runtime.block_on(ui_task) {
                if !join_error.is_cancelled() {
                    warn!(
                        ?join_error,
                        "UI API task stopped with an error after webview build failure"
                    );
                }
            }
            oast_task.abort();
            if let Err(join_error) = runtime.block_on(oast_task) {
                if !join_error.is_cancelled() {
                    warn!(
                        ?join_error,
                        "OAST poller stopped with an error after webview build failure"
                    );
                }
            }
            signal_task.abort();
            if let Err(join_error) = runtime.block_on(signal_task) {
                if !join_error.is_cancelled() {
                    warn!(
                        ?join_error,
                        "shutdown signal task stopped with an error after webview build failure"
                    );
                }
            }
            runtime.block_on(state.abort_proxy_task());
            remove_runtime_state_file(&state.config.data_dir, state.runtime_instance_id);
            return Err(anyhow::anyhow!("failed to build desktop webview: {error}"));
        }
    };

    let close_state = state.clone();
    let close_data_dir = close_state.config.data_dir.clone();
    let close_runtime_instance_id = close_state.runtime_instance_id;
    let teardown_started = Arc::new(AtomicBool::new(false));
    let shutdown_done = Arc::new(AtomicBool::new(false));
    let mut ui_task = Some(ui_task);
    let mut oast_task = Some(oast_task);
    let mut signal_task = Some(signal_task);
    let close_flush_event_proxy = event_loop.create_proxy();
    let mut close_flush_in_progress = false;
    let mut close_flush_generation = 0u64;
    event_loop.run(move |event, _, control_flow| {
        let _keep_runtime = &runtime;
        let _keep_window = &window;
        let _keep_webview = &webview;
        let _keep_proxy_task = &proxy_task;
        *control_flow = ControlFlow::Wait;

        let mut teardown_once = |session_persisted: bool| {
            if !begin_desktop_teardown(teardown_started.as_ref()) {
                return;
            }
            if let Some(ui_task) = ui_task.take() {
                ui_task.abort();
                if let Err(error) = runtime.block_on(ui_task) {
                    if !error.is_cancelled() {
                        warn!(
                            ?error,
                            "UI API task stopped with an error during desktop shutdown"
                        );
                    }
                }
            }
            if let Some(oast_task) = oast_task.take() {
                oast_task.abort();
                if let Err(error) = runtime.block_on(oast_task) {
                    if !error.is_cancelled() {
                        warn!(
                            ?error,
                            "OAST poller stopped with an error during desktop shutdown"
                        );
                    }
                }
            }
            if let Some(signal_task) = signal_task.take() {
                signal_task.abort();
                if let Err(error) = runtime.block_on(signal_task) {
                    if !error.is_cancelled() {
                        warn!(
                            ?error,
                            "shutdown signal task stopped with an error during desktop shutdown"
                        );
                    }
                }
            }
            runtime.block_on(close_state.ws_replay.disconnect_all());
            runtime.block_on(close_state.abort_proxy_task());
            if let Err(error) = runtime.block_on(proxy::close_live_websocket_relays(
                close_state.as_ref(),
                "Sniper desktop shutdown closed the live WebSocket relay.",
            )) {
                error!(
                    ?error,
                    "forced desktop teardown could not durably close live WebSocket relays"
                );
            }
            runtime.block_on(proxy::drain_proxy_connections(
                std::time::Duration::from_secs(1),
            ));
            finish_desktop_teardown(
                shutdown_done.as_ref(),
                &close_data_dir,
                close_runtime_instance_id,
                session_persisted,
            );
        };

        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if shutdown_done.load(Ordering::Acquire) {
                    *control_flow = ControlFlow::Exit;
                    return;
                }
                if close_flush_in_progress {
                    return;
                }
                if let Err(error) = begin_webview_flush_before_desktop_close(
                    &webview,
                    close_flush_event_proxy.clone(),
                    &mut close_flush_in_progress,
                    &mut close_flush_generation,
                ) {
                    *control_flow = block_desktop_shutdown(error);
                }
            }
            Event::UserEvent(DesktopUserEvent::ShutdownSignal) => {
                if shutdown_done.load(Ordering::Acquire) {
                    *control_flow = ControlFlow::Exit;
                    return;
                }
                if close_flush_in_progress {
                    return;
                }
                if let Err(error) = begin_webview_flush_before_desktop_close(
                    &webview,
                    close_flush_event_proxy.clone(),
                    &mut close_flush_in_progress,
                    &mut close_flush_generation,
                ) {
                    *control_flow = block_desktop_shutdown(error);
                }
            }
            Event::UserEvent(DesktopUserEvent::WebviewCloseFlushFinished {
                generation,
                ok,
            }) => {
                if !close_flush_in_progress || generation != close_flush_generation {
                    return;
                }
                close_flush_in_progress = false;
                if !ok {
                    *control_flow = block_desktop_shutdown(anyhow::anyhow!(
                        "failed to flush webview state before desktop shutdown"
                    ));
                    return;
                }
                match persist_desktop_session_state(&runtime, close_state.as_ref()) {
                    Ok(()) => {
                        teardown_once(true);
                        *control_flow = ControlFlow::Exit;
                    }
                    Err(error) => {
                        *control_flow = block_desktop_shutdown(error);
                    }
                }
            }
            Event::UserEvent(DesktopUserEvent::WebviewCloseFlushTimedOut { generation }) => {
                if !close_flush_in_progress || generation != close_flush_generation {
                    return;
                }
                close_flush_in_progress = false;
                *control_flow = block_desktop_shutdown(anyhow::anyhow!(
                    "timed out flushing webview state before desktop shutdown"
                ));
            }
            Event::LoopDestroyed => {
                let session_persisted = if shutdown_done.load(Ordering::Acquire) {
                    true
                } else {
                    match persist_desktop_session_state(&runtime, close_state.as_ref()) {
                        Ok(()) => true,
                        Err(error) => {
                            error!(
                                ?error,
                                "desktop shutdown finished without durable session persistence during forced teardown"
                            );
                            false
                        }
                    }
                };
                if !session_persisted && !teardown_started.load(Ordering::Acquire) {
                    error!(
                        "forced desktop teardown will preserve runtime state after failed persistence"
                    );
                }
                teardown_once(session_persisted);
            }
            _ => {}
        }
    })
}

fn desktop_user_event_from_ipc(message: &str) -> Option<DesktopUserEvent> {
    if let Some(generation) = message.strip_prefix(DESKTOP_CLOSE_FLUSH_OK_PREFIX) {
        return generation.parse::<u64>().ok().map(|generation| {
            DesktopUserEvent::WebviewCloseFlushFinished {
                generation,
                ok: true,
            }
        });
    }
    if let Some(rest) = message.strip_prefix(DESKTOP_CLOSE_FLUSH_ERROR_PREFIX) {
        let generation = rest
            .split_once(':')
            .map(|(generation, _)| generation)
            .unwrap_or(rest);
        return generation.parse::<u64>().ok().map(|generation| {
            DesktopUserEvent::WebviewCloseFlushFinished {
                generation,
                ok: false,
            }
        });
    }
    None
}

fn begin_webview_flush_before_desktop_close(
    webview: &WebView,
    event_proxy: EventLoopProxy<DesktopUserEvent>,
    close_flush_in_progress: &mut bool,
    close_flush_generation: &mut u64,
) -> Result<()> {
    if *close_flush_in_progress {
        return Ok(());
    }
    *close_flush_generation = close_flush_generation.wrapping_add(1);
    let generation = *close_flush_generation;
    let script = desktop_close_flush_script(generation);
    webview
        .evaluate_script(&script)
        .context("failed to request webview state flush before desktop shutdown")?;
    *close_flush_in_progress = true;
    schedule_webview_flush_timeout(event_proxy, generation);
    Ok(())
}

fn schedule_webview_flush_timeout(event_proxy: EventLoopProxy<DesktopUserEvent>, generation: u64) {
    std::thread::spawn(move || {
        std::thread::sleep(DESKTOP_CLOSE_FLUSH_TIMEOUT);
        if let Err(error) =
            event_proxy.send_event(DesktopUserEvent::WebviewCloseFlushTimedOut { generation })
        {
            warn!(?error, "failed to forward desktop webview flush timeout");
        }
    });
}

fn desktop_close_flush_script(generation: u64) -> String {
    format!(
        r#"(async () => {{
  const post = (message) => {{
    if (window.ipc && typeof window.ipc.postMessage === "function") {{
      window.ipc.postMessage(message);
    }}
  }};
  try {{
    if (typeof window.__sniperFlushBeforeNativeClose === "function") {{
      await window.__sniperFlushBeforeNativeClose();
    }}
    post("{DESKTOP_CLOSE_FLUSH_OK_PREFIX}{generation}");
  }} catch (error) {{
    const detail = error && error.message ? error.message : String(error);
    post("{DESKTOP_CLOSE_FLUSH_ERROR_PREFIX}{generation}:" + detail.slice(0, 200));
  }}
}})();"#
    )
}

fn desktop_devtools_enabled() -> bool {
    cfg!(debug_assertions)
        || env::var("SNIPER_ENABLE_DEVTOOLS")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
}

fn remove_runtime_state_file(data_dir: &Path, runtime_instance_id: Uuid) {
    match runtime_state::remove_runtime_state_if_owner(data_dir, runtime_instance_id) {
        Ok(true) => {}
        Ok(false) => {
            warn!("runtime state was replaced before desktop shutdown; leaving it intact");
        }
        Err(error) => {
            warn!(
                ?error,
                "failed to remove runtime state before desktop shutdown"
            );
        }
    }
}

async fn wait_for_desktop_shutdown_signal(proxy: EventLoopProxy<DesktopUserEvent>) {
    #[cfg(unix)]
    {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => Some(signal),
                Err(error) => {
                    warn!(?error, "failed to listen for desktop SIGTERM");
                    None
                }
            };
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                if let Err(error) = signal {
                    warn!(?error, "failed to listen for desktop shutdown signal");
                } else {
                    info!("desktop shutdown signal received");
                }
            }
            _ = async {
                if let Some(signal) = &mut terminate {
                    signal.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                info!("desktop termination signal received");
            }
        }
    }
    #[cfg(not(unix))]
    {
        match tokio::signal::ctrl_c().await {
            Ok(()) => info!("desktop shutdown signal received"),
            Err(error) => warn!(?error, "failed to listen for desktop shutdown signal"),
        }
    }
    if let Err(error) = proxy.send_event(DesktopUserEvent::ShutdownSignal) {
        warn!(
            ?error,
            "failed to forward desktop shutdown signal to event loop"
        );
    }
}

fn persist_desktop_session_state(
    runtime: &tokio::runtime::Runtime,
    state: &AppState,
) -> Result<()> {
    let relay_result = runtime
        .block_on(proxy::close_live_websocket_relays(
            state,
            "Sniper desktop shutdown closed the live WebSocket relay.",
        ))
        .context("failed to persist closed live WebSocket relays before desktop shutdown");
    runtime.block_on(state.abort_proxy_task());
    runtime.block_on(proxy::drain_proxy_connections(
        std::time::Duration::from_secs(1),
    ));
    let flush_result = runtime
        .block_on(proxy::flush_pending_session_persists(state))
        .context("failed to flush pending session snapshots before desktop shutdown");
    let active_result = runtime
        .block_on(state.persist_active_session())
        .map(|_| ())
        .context("failed to persist active session before desktop shutdown");
    combine_desktop_persist_results(flush_result, active_result)?;
    relay_result?;
    Ok(())
}

fn combine_desktop_persist_results(
    flush_result: Result<()>,
    active_result: Result<()>,
) -> Result<()> {
    match (flush_result, active_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(flush_error), Err(active_error)) => {
            Err(anyhow::anyhow!("{flush_error:#}; {active_error:#}"))
        }
    }
}

fn block_desktop_shutdown(error: anyhow::Error) -> ControlFlow {
    error!(
        ?error,
        "blocked desktop close because session state was not durably persisted"
    );
    ControlFlow::Wait
}

fn begin_desktop_teardown(teardown_started: &AtomicBool) -> bool {
    !teardown_started.swap(true, Ordering::AcqRel)
}

fn finish_desktop_teardown(
    shutdown_done: &AtomicBool,
    data_dir: &Path,
    runtime_instance_id: Uuid,
    session_persisted: bool,
) {
    if session_persisted {
        complete_desktop_shutdown(shutdown_done, data_dir, runtime_instance_id);
    } else {
        warn!(
            "leaving runtime state after failed desktop session persistence during forced teardown"
        );
    }
}

fn complete_desktop_shutdown(
    shutdown_done: &AtomicBool,
    data_dir: &Path,
    runtime_instance_id: Uuid,
) {
    // Clean up runtime-state only after session data is durably written, so
    // a failed close can be retried or diagnosed by the CLI.
    remove_runtime_state_file(data_dir, runtime_instance_id);
    shutdown_done.store(true, Ordering::Release);
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn install_platform_app_menu() {
    use cocoa::{
        appkit::{
            NSApp, NSApplication, NSApplicationActivationPolicyRegular, NSEventModifierFlags,
            NSMenu, NSMenuItem,
        },
        base::nil,
        foundation::{NSAutoreleasePool, NSProcessInfo, NSString},
    };

    unsafe {
        let _pool = NSAutoreleasePool::new(nil);
        let app = NSApp();
        let existing_menu = app.mainMenu();
        if existing_menu != nil {
            return;
        }

        app.setActivationPolicy_(NSApplicationActivationPolicyRegular);

        let menubar = NSMenu::new(nil).autorelease();
        let app_menu_item = NSMenuItem::new(nil).autorelease();
        let edit_menu_item = NSMenuItem::alloc(nil)
            .initWithTitle_action_keyEquivalent_(
                NSString::alloc(nil).init_str("Edit"),
                cocoa::base::selector("terminate:"),
                NSString::alloc(nil).init_str(""),
            )
            .autorelease();
        menubar.addItem_(app_menu_item);
        menubar.addItem_(edit_menu_item);
        app.setMainMenu_(menubar);

        let app_menu = NSMenu::new(nil).autorelease();
        let quit_prefix = NSString::alloc(nil).init_str("Quit ");
        let quit_title =
            quit_prefix.stringByAppendingString_(NSProcessInfo::processInfo(nil).processName());
        let quit_key = NSString::alloc(nil).init_str("q");
        let quit_item = NSMenuItem::alloc(nil)
            .initWithTitle_action_keyEquivalent_(
                quit_title,
                cocoa::base::selector("terminate:"),
                quit_key,
            )
            .autorelease();
        app_menu.addItem_(quit_item);
        app_menu_item.setSubmenu_(app_menu);

        let edit_menu = NSMenu::new(nil).autorelease();

        let undo_item = NSMenuItem::alloc(nil)
            .initWithTitle_action_keyEquivalent_(
                NSString::alloc(nil).init_str("Undo"),
                cocoa::base::selector("undo:"),
                NSString::alloc(nil).init_str("z"),
            )
            .autorelease();
        let redo_item = NSMenuItem::alloc(nil)
            .initWithTitle_action_keyEquivalent_(
                NSString::alloc(nil).init_str("Redo"),
                cocoa::base::selector("redo:"),
                NSString::alloc(nil).init_str("Z"),
            )
            .autorelease();
        let cut_item = NSMenuItem::alloc(nil)
            .initWithTitle_action_keyEquivalent_(
                NSString::alloc(nil).init_str("Cut"),
                cocoa::base::selector("cut:"),
                NSString::alloc(nil).init_str("x"),
            )
            .autorelease();
        let copy_item = NSMenuItem::alloc(nil)
            .initWithTitle_action_keyEquivalent_(
                NSString::alloc(nil).init_str("Copy"),
                cocoa::base::selector("copy:"),
                NSString::alloc(nil).init_str("c"),
            )
            .autorelease();
        let paste_item = NSMenuItem::alloc(nil)
            .initWithTitle_action_keyEquivalent_(
                NSString::alloc(nil).init_str("Paste"),
                cocoa::base::selector("paste:"),
                NSString::alloc(nil).init_str("v"),
            )
            .autorelease();
        let select_all_item = NSMenuItem::alloc(nil)
            .initWithTitle_action_keyEquivalent_(
                NSString::alloc(nil).init_str("Select All"),
                cocoa::base::selector("selectAll:"),
                NSString::alloc(nil).init_str("a"),
            )
            .autorelease();

        edit_menu.addItem_(undo_item);
        edit_menu.addItem_(redo_item);
        edit_menu.addItem_(cut_item);
        edit_menu.addItem_(copy_item);
        edit_menu.addItem_(paste_item);
        edit_menu.addItem_(select_all_item);
        edit_menu_item.setSubmenu_(edit_menu);

        // macOS routes Ctrl+Cmd+F through the "Enter Full Screen" menu item's key
        // equivalent. Without a View menu carrying it the shortcut reaches nothing,
        // so the window can only be zoomed from the green title-bar button.
        let view_menu_item = NSMenuItem::new(nil).autorelease();
        menubar.addItem_(view_menu_item);
        let view_menu = NSMenu::alloc(nil)
            .initWithTitle_(NSString::alloc(nil).init_str("View"))
            .autorelease();
        let fullscreen_item = NSMenuItem::alloc(nil)
            .initWithTitle_action_keyEquivalent_(
                NSString::alloc(nil).init_str("Enter Full Screen"),
                cocoa::base::selector("toggleFullScreen:"),
                NSString::alloc(nil).init_str("f"),
            )
            .autorelease();
        fullscreen_item.setKeyEquivalentModifierMask_(
            NSEventModifierFlags::NSControlKeyMask | NSEventModifierFlags::NSCommandKeyMask,
        );
        view_menu.addItem_(fullscreen_item);
        view_menu_item.setSubmenu_(view_menu);
    }
}

#[cfg(not(target_os = "macos"))]
fn install_platform_app_menu() {}

/// tao does not mark its windows full-screen capable, so AppKit would leave the
/// View > Enter Full Screen item (and its Ctrl+Cmd+F key equivalent) disabled.
#[cfg(target_os = "macos")]
fn enable_window_fullscreen_support(window: &tao::window::Window) {
    use cocoa::{
        appkit::{NSWindow, NSWindowCollectionBehavior},
        base::id,
    };
    use tao::platform::macos::WindowExtMacOS;

    let ns_window = window.ns_window() as id;
    if ns_window.is_null() {
        return;
    }
    // SAFETY: ns_window is the live NSWindow tao created for this window, and
    // this runs on the main thread during window setup.
    unsafe {
        let behavior = ns_window.collectionBehavior()
            | NSWindowCollectionBehavior::NSWindowCollectionBehaviorFullScreenPrimary;
        ns_window.setCollectionBehavior_(behavior);
    }
}

#[cfg(not(target_os = "macos"))]
fn enable_window_fullscreen_support(_window: &tao::window::Window) {}

/// Append a `PATH` export line to `~/.zshrc` (and `~/.bashrc` if present) so
/// that `sniper-cli` is available from the terminal without requiring root.
/// If the line already exists the function is a no-op.
fn install_cli_path() {
    let Ok(exe) = env::current_exe() else { return };
    let macos_dir = exe.parent().unwrap_or(&exe);
    if !should_install_cli_path(macos_dir) {
        info!(dir = %macos_dir.display(), "skipping sniper-cli PATH install from transient app location");
        return;
    }
    let cli_bin = macos_dir.join("sniper-cli");
    if !cli_bin.exists() {
        return;
    }

    let dir = macos_dir.to_string_lossy().to_string();
    let export_line = format!(
        "export PATH={}:$PATH # Added by Sniper.app",
        shell_single_quote(&dir)
    );

    let home = match env::var("HOME") {
        Ok(h) => PathBuf::from(h),
        Err(_) => return,
    };

    // Always patch .zshrc (macOS default shell). Also patch .bashrc if it exists.
    let mut targets = vec![home.join(".zshrc")];
    let bashrc = home.join(".bashrc");
    if bashrc.exists() {
        targets.push(bashrc);
    }

    for rc_path in &targets {
        let contents = match load_shell_rc_contents(rc_path) {
            Ok(contents) => contents,
            Err(e) => {
                error!(?e, file = %rc_path.display(), "skipping unreadable shell rc");
                continue;
            }
        };
        let Some(updated) = upsert_managed_path_line(&contents, &export_line) else {
            info!(file = %rc_path.display(), "sniper-cli PATH already configured");
            continue;
        };
        if let Err(e) = write_shell_rc_atomically(rc_path, &updated) {
            error!(?e, file = %rc_path.display(), "failed to write PATH to shell rc");
        } else {
            info!(file = %rc_path.display(), "updated sniper-cli PATH");
        }
    }
}

fn should_install_cli_path_on_launch(env_value: Option<&str>) -> bool {
    truthy_env_value(env_value)
}

fn should_install_skills_on_launch(env_value: Option<&str>) -> bool {
    truthy_env_value(env_value)
}

fn truthy_env_value(env_value: Option<&str>) -> bool {
    env_value
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn should_install_cli_path(macos_dir: &std::path::Path) -> bool {
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

fn load_shell_rc_contents(rc_path: &std::path::Path) -> std::io::Result<String> {
    match std::fs::read_to_string(rc_path) {
        Ok(contents) => Ok(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error),
    }
}

fn write_shell_rc_atomically(rc_path: &std::path::Path, contents: &str) -> std::io::Result<()> {
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
        std::fs::rename(&tmp_path, &write_path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

fn resolve_shell_rc_write_path(rc_path: &std::path::Path) -> std::io::Result<PathBuf> {
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

fn upsert_managed_path_line(contents: &str, export_line: &str) -> Option<String> {
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

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn handle_navigation_request(url: &str, ui_origin: &str) -> bool {
    if url == "about:blank" || is_same_origin(url, ui_origin) {
        return true;
    }

    if is_blocked_desktop_navigation_scheme(url) {
        warn!(url = %url, "blocked unsafe desktop navigation");
        return false;
    }

    if let Err(error) = webbrowser::open(url) {
        error!(?error, url = %url, "failed to open external url");
    }
    false
}

fn handle_new_window_request(url: &str, ui_origin: &str) -> bool {
    if url == "about:blank" || is_same_origin(url, ui_origin) {
        return false;
    }

    if is_blocked_desktop_navigation_scheme(url) {
        warn!(url = %url, "blocked unsafe desktop new-window request");
        return false;
    }

    if let Err(error) = webbrowser::open(url) {
        error!(?error, url = %url, "failed to open external url");
    }
    false
}

fn is_blocked_desktop_navigation_scheme(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url) else {
        return false;
    };
    matches!(parsed.scheme(), "data" | "javascript" | "file")
}

fn is_same_origin(url: &str, expected_origin: &str) -> bool {
    let (Ok(url), Ok(expected)) = (Url::parse(url), Url::parse(expected_origin)) else {
        return false;
    };
    url.scheme() == expected.scheme()
        && url
            .host_str()
            .zip(expected.host_str())
            .map(|(left, right)| left.eq_ignore_ascii_case(right))
            .unwrap_or(false)
        && url.port_or_known_default() == expected.port_or_known_default()
}

#[cfg(test)]
mod tests {
    use super::{
        begin_desktop_teardown, block_desktop_shutdown, combine_desktop_persist_results,
        complete_desktop_shutdown, desktop_close_flush_script, desktop_user_event_from_ipc,
        finish_desktop_teardown, handle_navigation_request, handle_new_window_request,
        is_blocked_desktop_navigation_scheme, is_same_origin, load_shell_rc_contents,
        normalize_empty_data_dir_env, persist_desktop_session_state,
        process_path_points_to_desktop_bundle, request_existing_desktop_focus_with,
        shell_single_quote, should_install_cli_path, should_install_cli_path_on_launch,
        should_install_skills_on_launch, should_request_existing_desktop_focus,
        upsert_managed_path_line, write_shell_rc_atomically, AppConfig, AppState, DesktopUserEvent,
        SNIPER_DATA_DIR_ENV,
    };
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set<K: Into<std::ffi::OsString>>(key: &'static str, value: K) -> Self {
            let guard = Self {
                key,
                previous: std::env::var_os(key),
            };
            std::env::set_var(key, value.into());
            guard
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    struct AbortFlag(Arc<AtomicBool>);

    impl Drop for AbortFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[test]
    fn shell_single_quote_escapes_embedded_quotes() {
        assert_eq!(
            shell_single_quote("/Applications/Sniper 'Beta'.app/Contents/MacOS"),
            "'/Applications/Sniper '\\''Beta'\\''.app/Contents/MacOS'"
        );
    }

    #[test]
    fn empty_sniper_data_dir_env_is_removed_before_desktop_config_loads() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _data_dir_guard = EnvVarGuard::set(SNIPER_DATA_DIR_ENV, "");

        normalize_empty_data_dir_env();

        assert!(std::env::var_os(SNIPER_DATA_DIR_ENV).is_none());
    }

    #[test]
    fn existing_runtime_focus_requires_desktop_bundle_process_path() {
        assert!(process_path_points_to_desktop_bundle(Some(
            "/Applications/Sniper.app/Contents/MacOS/Sniper"
        )));
        assert!(process_path_points_to_desktop_bundle(Some(
            "/Users/test/Desktop/Sniper.app/Contents/MacOS/Sniper"
        )));
        assert!(!process_path_points_to_desktop_bundle(Some(
            "/Applications/Sniper.app/Contents/MacOS/sniper"
        )));
        assert!(!process_path_points_to_desktop_bundle(Some(
            "/Users/test/Desktop/git/Sniper/target/debug/sniper"
        )));
        assert!(!process_path_points_to_desktop_bundle(Some(
            "/Users/test/Desktop/git/Sniper/target/debug/sniper-desktop"
        )));
        assert!(!process_path_points_to_desktop_bundle(None));
    }

    #[test]
    fn existing_runtime_focus_ignores_headless_runtime_state() {
        let root = std::env::temp_dir().join(format!(
            "sniper-desktop-existing-runtime-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut snapshot = super::runtime_state::RuntimeStateSnapshot::new(
            "127.0.0.1:18080".parse().unwrap(),
            "127.0.0.1:23001".parse().unwrap(),
        );

        snapshot.process_path = Some("/Applications/Sniper.app/Contents/MacOS/Sniper".to_string());
        super::runtime_state::persist_runtime_state(&root, &snapshot).unwrap();
        assert!(should_request_existing_desktop_focus(&root));

        snapshot.process_path = Some("/usr/local/bin/sniper".to_string());
        super::runtime_state::persist_runtime_state(&root, &snapshot).unwrap();
        assert!(!should_request_existing_desktop_focus(&root));

        snapshot.process_path = None;
        super::runtime_state::persist_runtime_state(&root, &snapshot).unwrap();
        assert!(!should_request_existing_desktop_focus(&root));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn existing_runtime_focus_reports_open_command_failures() {
        assert!(request_existing_desktop_focus_with(
            std::path::Path::new("/usr/bin/true"),
            "com.sm1ee.sniper"
        ));
        assert!(!request_existing_desktop_focus_with(
            std::path::Path::new("/usr/bin/false"),
            "com.sm1ee.sniper"
        ));
        assert!(!request_existing_desktop_focus_with(
            std::path::Path::new("/sniper/missing/open"),
            "com.sm1ee.sniper"
        ));
    }

    #[test]
    fn desktop_close_flush_ipc_messages_parse_to_user_events() {
        assert_eq!(
            desktop_user_event_from_ipc("sniper:native-close-flush-ok:7"),
            Some(DesktopUserEvent::WebviewCloseFlushFinished {
                generation: 7,
                ok: true,
            })
        );
        assert_eq!(
            desktop_user_event_from_ipc("sniper:native-close-flush-error:8:conflict"),
            Some(DesktopUserEvent::WebviewCloseFlushFinished {
                generation: 8,
                ok: false,
            })
        );
        assert_eq!(desktop_user_event_from_ipc("sniper:unrelated"), None);
    }

    #[test]
    fn desktop_close_flush_script_posts_generation_scoped_ipc_messages() {
        let script = desktop_close_flush_script(42);

        assert!(script.contains("window.__sniperFlushBeforeNativeClose"));
        assert!(script.contains("sniper:native-close-flush-ok:42"));
        assert!(script.contains("sniper:native-close-flush-error:42:"));
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
    fn desktop_shutdown_completion_removes_runtime_state_and_marks_done() {
        let root = std::env::temp_dir().join(format!(
            "sniper-desktop-shutdown-ok-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let runtime_state_path = super::runtime_state::runtime_state_path(&root);
        let ui_addr = "127.0.0.1:23001".parse().unwrap();
        let snapshot = super::runtime_state::RuntimeStateSnapshot::new(
            "127.0.0.1:18080".parse().unwrap(),
            ui_addr,
        );
        super::runtime_state::persist_runtime_state(&root, &snapshot).unwrap();
        let shutdown_done = std::sync::atomic::AtomicBool::new(false);

        complete_desktop_shutdown(&shutdown_done, &root, snapshot.instance_id);

        assert!(shutdown_done.load(std::sync::atomic::Ordering::Acquire));
        assert!(!runtime_state_path.exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn desktop_shutdown_completion_preserves_runtime_state_from_other_owner() {
        let root = std::env::temp_dir().join(format!(
            "sniper-desktop-shutdown-other-owner-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let runtime_state_path = super::runtime_state::runtime_state_path(&root);
        let ui_addr = "127.0.0.1:23001".parse().unwrap();
        let snapshot = super::runtime_state::RuntimeStateSnapshot::new(
            "127.0.0.1:18080".parse().unwrap(),
            ui_addr,
        );
        super::runtime_state::persist_runtime_state(&root, &snapshot).unwrap();
        let shutdown_done = std::sync::atomic::AtomicBool::new(false);

        complete_desktop_shutdown(&shutdown_done, &root, uuid::Uuid::new_v4());

        assert!(shutdown_done.load(std::sync::atomic::Ordering::Acquire));
        assert!(runtime_state_path.exists());
        let loaded = super::runtime_state::load_runtime_state(&root)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.ui_addr, snapshot.ui_addr);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn forced_desktop_teardown_preserves_runtime_state_when_persist_failed() {
        let root = std::env::temp_dir().join(format!(
            "sniper-desktop-shutdown-failed-persist-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let runtime_state_path = super::runtime_state::runtime_state_path(&root);
        let ui_addr = "127.0.0.1:23001".parse().unwrap();
        let snapshot = super::runtime_state::RuntimeStateSnapshot::new(
            "127.0.0.1:18080".parse().unwrap(),
            ui_addr,
        );
        super::runtime_state::persist_runtime_state(&root, &snapshot).unwrap();
        let teardown_started = std::sync::atomic::AtomicBool::new(false);
        let shutdown_done = std::sync::atomic::AtomicBool::new(false);

        assert!(begin_desktop_teardown(&teardown_started));
        finish_desktop_teardown(&shutdown_done, &root, snapshot.instance_id, false);

        assert!(teardown_started.load(std::sync::atomic::Ordering::Acquire));
        assert!(!shutdown_done.load(std::sync::atomic::Ordering::Acquire));
        assert!(runtime_state_path.exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn forced_desktop_teardown_removes_runtime_state_after_persist_success() {
        let root = std::env::temp_dir().join(format!(
            "sniper-desktop-shutdown-forced-ok-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let runtime_state_path = super::runtime_state::runtime_state_path(&root);
        let ui_addr = "127.0.0.1:23001".parse().unwrap();
        let snapshot = super::runtime_state::RuntimeStateSnapshot::new(
            "127.0.0.1:18080".parse().unwrap(),
            ui_addr,
        );
        super::runtime_state::persist_runtime_state(&root, &snapshot).unwrap();
        let teardown_started = std::sync::atomic::AtomicBool::new(false);
        let shutdown_done = std::sync::atomic::AtomicBool::new(false);

        assert!(begin_desktop_teardown(&teardown_started));
        finish_desktop_teardown(&shutdown_done, &root, snapshot.instance_id, true);

        assert!(shutdown_done.load(std::sync::atomic::Ordering::Acquire));
        assert!(!runtime_state_path.exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn desktop_shutdown_block_keeps_event_loop_waiting() {
        let control_flow = block_desktop_shutdown(anyhow::anyhow!("persist failed"));

        assert!(matches!(control_flow, tao::event_loop::ControlFlow::Wait));
    }

    #[test]
    fn desktop_shutdown_persist_result_reports_both_failures() {
        let error = combine_desktop_persist_results(
            Err(anyhow::anyhow!("flush failed")),
            Err(anyhow::anyhow!("active failed")),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("flush failed"));
        assert!(error.contains("active failed"));
    }

    #[test]
    fn desktop_persist_aborts_proxy_task_before_returning_success() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let root = std::env::temp_dir().join(format!(
            "sniper-desktop-persist-stops-proxy-{}",
            uuid::Uuid::new_v4()
        ));
        let state = AppState::new(AppConfig {
            proxy_addr: "127.0.0.1:0".parse().unwrap(),
            ui_addr: "127.0.0.1:0".parse().unwrap(),
            max_entries: 32,
            max_transaction_entries: 32,
            body_preview_bytes: 4096,
            data_dir: root.clone(),
        })
        .unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = AbortFlag(Arc::clone(&dropped));
        let handle = runtime.spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        runtime.block_on(state.set_proxy_task(handle));

        persist_desktop_session_state(&runtime, &state).unwrap();

        assert!(dropped.load(Ordering::Acquire));
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

    #[test]
    fn cli_path_install_requires_explicit_launch_opt_in() {
        assert!(!should_install_cli_path_on_launch(None));
        assert!(!should_install_cli_path_on_launch(Some("")));
        assert!(!should_install_cli_path_on_launch(Some("0")));
        assert!(should_install_cli_path_on_launch(Some("1")));
        assert!(should_install_cli_path_on_launch(Some("true")));
        assert!(should_install_cli_path_on_launch(Some("YES")));
    }

    #[test]
    fn agent_skill_install_requires_explicit_launch_opt_in() {
        assert!(!should_install_skills_on_launch(None));
        assert!(!should_install_skills_on_launch(Some("")));
        assert!(!should_install_skills_on_launch(Some("0")));
        assert!(should_install_skills_on_launch(Some("1")));
        assert!(should_install_skills_on_launch(Some("true")));
        assert!(should_install_skills_on_launch(Some("YES")));
    }

    #[test]
    fn navigation_origin_check_does_not_allow_prefix_collisions() {
        assert!(is_same_origin(
            "http://127.0.0.1:3000/dashboard",
            "http://127.0.0.1:3000",
        ));
        assert!(!is_same_origin(
            "http://127.0.0.1:30000/dashboard",
            "http://127.0.0.1:3000",
        ));
        assert!(!is_same_origin(
            "http://127.0.0.1.evil.test:3000/dashboard",
            "http://127.0.0.1:3000",
        ));
        assert!(is_same_origin(
            "http://[::1]:3000/dashboard",
            "http://[::1]:3000",
        ));
    }

    #[test]
    fn navigation_handler_blocks_unsafe_internal_schemes() {
        assert!(is_blocked_desktop_navigation_scheme("data:text/html,pwn"));
        assert!(is_blocked_desktop_navigation_scheme("javascript:alert(1)"));
        assert!(is_blocked_desktop_navigation_scheme("file:///etc/passwd"));

        assert!(!handle_navigation_request(
            "data:text/html,pwn",
            "http://127.0.0.1:3000",
        ));
    }

    #[test]
    fn new_window_handler_blocks_unsafe_internal_schemes() {
        assert!(!handle_new_window_request(
            "file:///etc/passwd",
            "http://127.0.0.1:3000",
        ));
        assert!(!handle_new_window_request(
            "javascript:alert(1)",
            "http://127.0.0.1:3000",
        ));
        assert!(!handle_new_window_request(
            "http://127.0.0.1:3000/popup",
            "http://127.0.0.1:3000",
        ));
    }
}
