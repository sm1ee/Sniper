use std::{env, fs, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use sniper::{api, config::AppConfig, proxy, runtime_state::{self, RuntimeStateSnapshot}, skills, state::AppState};
use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoop},
    window::WindowBuilder,
};
use tokio::net::TcpListener;
use tracing::{error, info};
use wry::WebViewBuilder;

fn main() -> Result<()> {
    sniper::init_tracing();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create desktop runtime")?;

    let mut config = AppConfig::from_env_for_desktop()?;

    let proxy_listener = match runtime.block_on(TcpListener::bind(config.proxy_addr)) {
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
    config.ui_addr = ui_listener
        .local_addr()
        .context("failed to read bound UI address")?;

    if let Err(error) = sniper::runtime_state::persist_runtime_state(
        &config.data_dir,
        &RuntimeStateSnapshot::new(config.proxy_addr, config.ui_addr),
    ) {
        error!(?error, "failed to persist runtime-state.json");
    }

    // Auto-install Claude & Codex skills on every launch so they stay in sync
    // with the current Sniper version. Errors are silently logged.
    let skill_results = skills::auto_install_all();
    for skill in &skill_results {
        info!(agent = skill.agent, path = %skill.path, "installed sniper-operator skill");
    }

    // Ensure sniper-cli is reachable from the user's shell.
    install_cli_path();

    let state = Arc::new(AppState::new(config.clone())?);

    if proxy_listener.is_some() {
        state.set_proxy_online(true);
        runtime.block_on(state.log_info(
            "runtime",
            "Sniper desktop started",
            format!(
                "Proxy listener {} and UI listener {} are ready",
                config.proxy_addr, config.ui_addr
            ),
        ));
    } else {
        runtime.block_on(state.log_error(
            "runtime",
            "Proxy listener failed",
            format!(
                "Could not bind proxy to {}. The UI is available but proxy capture is offline.",
                config.proxy_addr
            ),
        ));
    }

    let ui_state = state.clone();

    info!(
        proxy_addr = %config.proxy_addr,
        ui_addr = %config.ui_addr,
        proxy_online = proxy_listener.is_some(),
        "starting sniper desktop"
    );

    let proxy_task = if let Some(listener) = proxy_listener {
        let proxy_state = state.clone();
        let handle = runtime.spawn(async move {
            if let Err(error) = proxy::serve_proxy(listener, proxy_state).await {
                error!(?error, "proxy task stopped");
            }
        });
        // Store the handle so rebind_proxy can abort it later
        runtime.block_on(state.set_proxy_task(handle));
        // Read the handle back — we still need a reference for shutdown
        None::<tokio::task::JoinHandle<()>>
    } else {
        None
    };
    let ui_task = runtime.spawn(async move {
        if let Err(error) = api::serve_api(ui_listener, ui_state).await {
            error!(?error, "ui task stopped");
        }
    });

    let event_loop = EventLoop::new();
    install_platform_app_menu();
    let window = WindowBuilder::new()
        .with_title("Sniper")
        .with_inner_size(LogicalSize::new(1440.0, 920.0))
        .with_min_inner_size(LogicalSize::new(1120.0, 720.0))
        .build(&event_loop)
        .context("failed to create desktop window")?;
    let ui_url = format!("http://{}/", config.ui_addr);
    let ui_origin = format!("http://{}", config.ui_addr);
    let webview = WebViewBuilder::new(&window)
        .with_incognito(true)
        .with_devtools(true)
        .with_navigation_handler({
            let ui_origin = ui_origin.clone();
            move |url| handle_navigation_request(&url, &ui_origin)
        })
        .with_new_window_req_handler(move |url| {
            if let Err(error) = webbrowser::open(&url) {
                error!(?error, url = %url, "failed to open external url");
            }
            false
        })
        .with_url(&ui_url)
        .build()
        .context("failed to build desktop webview")?;

    let close_state = state.clone();
    event_loop.run(move |event, _, control_flow| {
        let _keep_runtime = &runtime;
        let _keep_window = &window;
        let _keep_webview = &webview;
        let _keep_proxy_task = &proxy_task;
        *control_flow = ControlFlow::Wait;

        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            runtime.block_on(close_state.abort_proxy_task());
            ui_task.abort();
            // Clean up runtime-state so CLI doesn't connect to a stale port
            let state_path = runtime_state::runtime_state_path(&close_state.config.data_dir);
            let _ = fs::remove_file(&state_path);
            *control_flow = ControlFlow::Exit;
        }
    })
}

#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn install_platform_app_menu() {
    use cocoa::{
        appkit::{NSApp, NSApplication, NSApplicationActivationPolicyRegular, NSMenu, NSMenuItem},
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
    }
}

#[cfg(not(target_os = "macos"))]
fn install_platform_app_menu() {}

/// Append a `PATH` export line to `~/.zshrc` (and `~/.bashrc` if present) so
/// that `sniper-cli` is available from the terminal without requiring root.
/// If the line already exists the function is a no-op.
fn install_cli_path() {
    let Ok(exe) = env::current_exe() else { return };
    let macos_dir = exe.parent().unwrap_or(&exe);
    let cli_bin = macos_dir.join("sniper-cli");
    if !cli_bin.exists() {
        return;
    }

    let dir = macos_dir.to_string_lossy();
    let export_line = format!("export PATH=\"{}:$PATH\" # Added by Sniper.app", dir);

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
        if let Ok(contents) = std::fs::read_to_string(rc_path) {
            if contents.contains(&*dir) {
                info!(file = %rc_path.display(), "sniper-cli PATH already configured");
                continue;
            }
        }
        // Append the export line
        let mut line = String::from("\n");
        line.push_str(&export_line);
        line.push('\n');
        match std::fs::OpenOptions::new().create(true).append(true).open(rc_path) {
            Ok(mut f) => {
                use std::io::Write;
                if let Err(e) = f.write_all(line.as_bytes()) {
                    error!(?e, file = %rc_path.display(), "failed to write PATH to shell rc");
                } else {
                    info!(file = %rc_path.display(), "added sniper-cli to PATH");
                }
            }
            Err(e) => error!(?e, file = %rc_path.display(), "failed to open shell rc"),
        }
    }
}

fn handle_navigation_request(url: &str, ui_origin: &str) -> bool {
    if url == "about:blank" || url.starts_with(ui_origin) || url.starts_with("data:") {
        return true;
    }

    if let Err(error) = webbrowser::open(url) {
        error!(?error, url = %url, "failed to open external url");
    }
    false
}
