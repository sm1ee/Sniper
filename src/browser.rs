//! Opens a browser that already sends its traffic through this Sniper and trusts
//! its CA, so a person or an agent can start analysing without touching proxy or
//! certificate settings.
//!
//! Chromium-family browsers all take the same switches, so this is one launch
//! path plus a per-browser list of where the executable lives. Nothing is put in
//! an OS or browser trust store: the CA is trusted by SPKI hash for this one
//! browser process. A trust-store install would outlive Sniper and widen what a
//! leaked CA key could impersonate to every application on the machine.

use std::{
    collections::HashMap,
    fs, io,
    io::{Read, Seek, SeekFrom},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{mpsc, Mutex, OnceLock},
    time::Duration,
};

use anyhow::{anyhow, Result};
use base64::Engine as _;
use rsa::sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;
use x509_parser::parse_x509_certificate;

pub const DEVTOOLS_WAIT: Duration = Duration::from_secs(10);
const DEVTOOLS_POLL: Duration = Duration::from_millis(100);
/// How long after starting a browser to check that it is still there. A browser
/// that dies this fast has not failed slowly; it could not start.
pub const EARLY_EXIT_PROBE: Duration = Duration::from_millis(500);
/// Throwaway browsers at once. Enough for anyone driving browsers side by side, low
/// enough that a loop of requests cannot turn the launcher into a process and
/// disk-space fork bomb. Persistent profiles are bounded by the number of browsers
/// and are never counted, so a flood of throwaway ones cannot lock the button out.
const MAX_LIVE_BROWSERS: usize = 8;
/// Left in a profile so a later Sniper can tell a browser it did not start.
const OWNER_FILE: &str = "sniper-browser.json";
/// The browser's stderr. Without it a browser that cannot start leaves no trace.
const LAUNCH_LOG: &str = "sniper-launch.log";
/// A throwaway profile younger than this may belong to a launch that has made the
/// directory but not yet started its browser.
const FRESH_PROFILE_GRACE: Duration = Duration::from_secs(60);
/// A browser this young is still opening its first window. Starting the binary
/// again now could win Chromium's startup race and leave a browser nothing tracks.
pub const STARTUP_SETTLE: Duration = Duration::from_secs(2);
/// Windows being opened in one running browser at a time. Each is a full browser
/// process until it hands over and exits.
const MAX_HANDOFFS_PER_PROFILE: usize = 4;
const LAUNCH_LOG_TAIL: u64 = 600;
const PROFILE_REMOVE_ATTEMPTS: u32 = 5;
const PROFILE_REMOVE_RETRY: Duration = Duration::from_millis(300);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BrowserKind {
    Chrome,
    Edge,
    Brave,
    Chromium,
    Ego,
}

impl BrowserKind {
    /// The order is what "auto" picks. ego is last: an agent drives it through its
    /// own CLI rather than a DevTools port, so choosing it silently would surprise
    /// someone expecting to attach over CDP.
    pub const ALL: [BrowserKind; 5] = [
        BrowserKind::Chrome,
        BrowserKind::Edge,
        BrowserKind::Brave,
        BrowserKind::Chromium,
        BrowserKind::Ego,
    ];

    pub fn name(self) -> &'static str {
        match self {
            BrowserKind::Chrome => "chrome",
            BrowserKind::Edge => "edge",
            BrowserKind::Brave => "brave",
            BrowserKind::Chromium => "chromium",
            BrowserKind::Ego => "ego",
        }
    }

    /// Every name `parse` accepts, so a message or an argument parser never carries a
    /// copy of the list that a new browser would have to remember to update.
    pub fn names() -> Vec<&'static str> {
        Self::ALL.into_iter().map(BrowserKind::name).collect()
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.name().eq_ignore_ascii_case(value.trim()))
    }

    /// How an agent drives this browser once it is open.
    pub fn driver(self) -> Driver {
        match self {
            BrowserKind::Ego => Driver::EgoCli,
            _ => Driver::Cdp,
        }
    }

    /// Where the browser exists at all. A browser that is not built for a platform
    /// is left out of the catalog there rather than listed as "not installed".
    pub fn platforms(self) -> &'static [&'static str] {
        match self {
            BrowserKind::Ego => &["macos"],
            _ => &["macos", "windows", "linux"],
        }
    }

    /// What to tell someone who picked a browser that is missing. Only where the
    /// answer is not obvious: ego is installed by the user and never by Sniper.
    fn install_hint(self) -> Option<&'static str> {
        match self {
            BrowserKind::Ego => Some(
                "Download ego lite from https://lite.ego.app in a browser and open it as usual. \
                 Sniper does not install it.",
            ),
            _ => None,
        }
    }

    fn candidates(self) -> Vec<PathBuf> {
        if cfg!(target_os = "macos") {
            let app = match self {
                BrowserKind::Chrome => "Google Chrome",
                BrowserKind::Edge => "Microsoft Edge",
                BrowserKind::Brave => "Brave Browser",
                BrowserKind::Chromium => "Chromium",
                BrowserKind::Ego => "ego lite",
            };
            let relative = format!("{app}.app/Contents/MacOS/{app}");
            let mut found = vec![PathBuf::from("/Applications").join(&relative)];
            if let Some(home) = crate::platform::user_home_dir() {
                found.push(home.join("Applications").join(&relative));
            }
            found
        } else if cfg!(windows) {
            let relative = match self {
                BrowserKind::Chrome => r"Google\Chrome\Application\chrome.exe",
                BrowserKind::Edge => r"Microsoft\Edge\Application\msedge.exe",
                BrowserKind::Brave => r"BraveSoftware\Brave-Browser\Application\brave.exe",
                BrowserKind::Chromium => r"Chromium\Application\chrome.exe",
                // ego ships for macOS only.
                BrowserKind::Ego => return Vec::new(),
            };
            ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"]
                .into_iter()
                .filter_map(std::env::var_os)
                .map(|base| PathBuf::from(base).join(relative))
                .collect()
        } else {
            let names: &[&str] = match self {
                BrowserKind::Chrome => &["google-chrome", "google-chrome-stable"],
                BrowserKind::Edge => &["microsoft-edge", "microsoft-edge-stable"],
                BrowserKind::Brave => &["brave-browser", "brave"],
                BrowserKind::Chromium => &["chromium", "chromium-browser"],
                BrowserKind::Ego => &[],
            };
            let path = std::env::var_os("PATH").unwrap_or_default();
            std::env::split_paths(&path)
                .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
                .collect()
        }
    }
}

pub fn find_executable(kind: BrowserKind) -> Option<PathBuf> {
    first_existing(kind.candidates(), |path| path.is_file())
}

fn first_existing(candidates: Vec<PathBuf>, exists: impl Fn(&Path) -> bool) -> Option<PathBuf> {
    candidates.into_iter().find(|path| exists(path))
}

/// How an agent drives a browser once it is open. This, not the browser's name, is
/// what differs between launches, so every decision about it lives here and
/// `launch_at` never asks which browser it has. A new browser is a row in
/// `BrowserKind`; a new way of driving one is a variant here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Driver {
    /// Chromium's DevTools protocol on a loopback port. The agent brings the client.
    Cdp,
    /// ego's own CLI, addressed by the name of a named browser service.
    EgoCli,
}

/// What an agent is given to drive a browser, whatever the driver.
#[derive(Debug, Serialize)]
#[serde(tag = "driver", rename_all = "kebab-case")]
pub enum Control {
    Cdp {
        endpoint: String,
    },
    EgoCli {
        server_name: String,
        command: String,
    },
}

/// What a driver offers an agent beyond the wired browser itself. These describe
/// the driver as its own documentation states it; they are not a promise Sniper
/// tests for every driver.
#[derive(Debug, Serialize)]
pub struct Capabilities {
    /// `via-client`: the agent needs a CDP client such as Playwright. `built-in`:
    /// the driver ships the actions itself.
    pub ui_actions: &'static str,
    pub snapshot_refs: bool,
    pub handoff: bool,
    pub visible_cursor: bool,
}

impl Driver {
    /// Whether this launch has to open a DevTools port. Off unless an agent asks:
    /// the port lets any local process drive a browser that holds the profile's
    /// logged-in sessions.
    fn opens_port(self, agent: bool) -> bool {
        self == Driver::Cdp && agent
    }

    /// A name that lets the agent's CLI find this instance rather than the user's
    /// own everyday one. The profile is part of it: the proxy port alone is the same
    /// for every data directory on the default settings, and a stale ego left by an
    /// earlier run would then answer to the name a new one was given. The same
    /// profile always gets the same name, so reuse and a restart keep agreeing.
    fn server_name(self, proxy_port: u16, profile: &Path) -> Option<String> {
        (self == Driver::EgoCli).then(|| {
            let digest = Sha256::digest(profile.to_string_lossy().as_bytes());
            format!("sniper-{proxy_port}-{}", &format!("{digest:x}")[..8])
        })
    }

    /// The switches this driver adds so that something can drive the browser.
    fn launch_args(self, agent: bool, server_name: Option<&str>) -> Vec<String> {
        match self {
            // Port 0 lets the OS pick, and the browser writes the choice to
            // DevToolsActivePort. A fixed port would collide with any other browser
            // already holding it. Chrome 136+ honours this only with a non-default
            // profile, which this always is.
            Driver::Cdp if agent => vec!["--remote-debugging-port=0".to_string()],
            Driver::Cdp => Vec::new(),
            // Gives this instance its own name so `ego-browser` can be pointed at it
            // instead of at the user's everyday ego. It costs nothing, so it is
            // always set, which keeps an agent from reaching the wrong instance.
            Driver::EgoCli => server_name
                .map(|name| format!("--ego-server-name={name}"))
                .into_iter()
                .collect(),
        }
    }

    fn control(self, devtools_port: Option<u16>, server_name: Option<&str>) -> Option<Control> {
        match self {
            Driver::Cdp => devtools_port.map(|port| Control::Cdp {
                endpoint: format!("http://127.0.0.1:{port}"),
            }),
            Driver::EgoCli => server_name.map(|name| Control::EgoCli {
                server_name: name.to_string(),
                command: format!("ego-browser --ego-server-name={name} nodejs -e '<script>'"),
            }),
        }
    }

    fn capabilities(self) -> Capabilities {
        match self {
            Driver::Cdp => Capabilities {
                ui_actions: "via-client",
                snapshot_refs: false,
                handoff: false,
                visible_cursor: false,
            },
            Driver::EgoCli => Capabilities {
                ui_actions: "built-in",
                snapshot_refs: true,
                handoff: true,
                visible_cursor: true,
            },
        }
    }
}

/// Something a driver needs on this machine that Sniper can see but never installs.
#[derive(Debug, Serialize)]
pub struct Requirement {
    pub name: &'static str,
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct CatalogEntry {
    pub browser: &'static str,
    pub installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub driver: Driver,
    pub platforms: &'static [&'static str],
    pub capabilities: Capabilities,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub requirements: Vec<Requirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_hint: Option<&'static str>,
}

fn current_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(windows) {
        "windows"
    } else {
        "linux"
    }
}

/// Every browser Sniper knows on this platform, installed or not, so a caller can
/// see what exists and how to get it instead of an empty list.
pub fn catalog() -> Vec<CatalogEntry> {
    catalog_for(current_platform(), find_executable, driver_requirements)
}

fn catalog_for(
    platform: &str,
    find: impl Fn(BrowserKind) -> Option<PathBuf>,
    requirements: impl Fn(Driver) -> Vec<Requirement>,
) -> Vec<CatalogEntry> {
    BrowserKind::ALL
        .into_iter()
        .filter(|kind| kind.platforms().contains(&platform))
        .map(|kind| {
            let path = find(kind);
            CatalogEntry {
                browser: kind.name(),
                installed: path.is_some(),
                install_hint: path.is_none().then(|| kind.install_hint()).flatten(),
                path: path.map(|path| path.display().to_string()),
                driver: kind.driver(),
                platforms: kind.platforms(),
                capabilities: kind.driver().capabilities(),
                requirements: requirements(kind.driver()),
            }
        })
        .collect()
}

fn driver_requirements(driver: Driver) -> Vec<Requirement> {
    match driver {
        Driver::Cdp => Vec::new(),
        Driver::EgoCli => {
            // Hints appear only for what is missing, and they point at where to look.
            // None of them is a command to run: this output is read by agents, and a
            // line that installs software must not read as one they may execute.
            let (command, skill) = (ego_cli_found(), ego_skill_found());
            vec![
                Requirement {
                    name: "ego-browser command",
                    found: command,
                    hint: (!command)
                        .then_some("ego lite registers it when its first-run setup finishes"),
                },
                Requirement {
                    name: "ego-browser agent skill",
                    found: skill,
                    hint: (!skill).then_some(
                        "ask the user to set up ego's agent skill; see https://github.com/citrolabs/ego-lite",
                    ),
                },
            ]
        }
    }
}

fn ego_cli_found() -> bool {
    let name = if cfg!(windows) {
        "ego-browser.exe"
    } else {
        "ego-browser"
    };
    let on_path = std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(name).is_file()));
    // ego's setup puts the command here, which a desktop app's PATH often lacks.
    on_path
        || crate::platform::user_home_dir()
            .is_some_and(|home| home.join(".local").join("bin").join(name).is_file())
}

fn ego_skill_found() -> bool {
    [
        crate::skills::default_claude_skills_dir(),
        crate::skills::default_codex_skills_dir(),
        // The shared location agents that follow the open skills convention read.
        crate::platform::user_home_dir().map(|home| home.join(".agents").join("skills")),
    ]
    .into_iter()
    .flatten()
    .any(|dir| dir.join("ego-browser").join("SKILL.md").is_file())
}

/// The hash Chromium's `--ignore-certificate-errors-spki-list` takes: base64 of
/// the SHA-256 of the certificate's SubjectPublicKeyInfo (RFC 7469 §2.4).
pub fn spki_sha256_base64(cert_der: &[u8]) -> Result<String> {
    let (_, cert) = parse_x509_certificate(cert_der)
        .map_err(|error| anyhow!("could not parse the root CA certificate: {error}"))?;
    let digest = Sha256::digest(cert.tbs_certificate.subject_pki.raw);
    Ok(base64::engine::general_purpose::STANDARD.encode(digest))
}

#[derive(Debug)]
pub enum LaunchError {
    NotInstalled(String),
    BadRequest(String),
    /// A browser is already open on this profile and cannot be reused as asked.
    AlreadyRunning {
        pid: u32,
        detail: String,
    },
    TooMany(String),
    /// Refused by policy, not by a bad request: the same call would succeed once the
    /// condition changes.
    Forbidden(String),
    Failed(String),
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LaunchError::NotInstalled(message)
            | LaunchError::BadRequest(message)
            | LaunchError::TooMany(message)
            | LaunchError::Forbidden(message)
            | LaunchError::Failed(message) => f.write_str(message),
            LaunchError::AlreadyRunning { pid, detail } => write!(
                f,
                "a browser is already open on this profile (pid {pid}) and {detail}; quit it \
                 (closing the window is not enough on macOS), then open again"
            ),
        }
    }
}

impl std::error::Error for LaunchError {}

#[derive(Debug, Default)]
pub struct LaunchRequest {
    pub browser: Option<BrowserKind>,
    pub url: Option<String>,
    /// Use a throwaway profile instead of the persistent Sniper one.
    pub fresh: bool,
    /// Ask for the way an agent drives this browser. For a driver that opens a port
    /// that is what this switches on, and it is off by default because the port lets
    /// any local process drive a browser holding the profile's logged-in sessions. A
    /// driver with no port (ego) is always reachable by its name, so this changes
    /// nothing there.
    pub agent: bool,
}

pub struct LaunchContext<'a> {
    pub data_dir: &'a Path,
    pub proxy_addr: SocketAddr,
    pub cert_der: &'a [u8],
    pub devtools_wait: Duration,
    pub early_exit_probe: Duration,
    pub startup_settle: Duration,
}

impl<'a> LaunchContext<'a> {
    pub fn new(data_dir: &'a Path, proxy_addr: SocketAddr, cert_der: &'a [u8]) -> Self {
        Self {
            data_dir,
            proxy_addr,
            cert_der,
            devtools_wait: DEVTOOLS_WAIT,
            early_exit_probe: EARLY_EXIT_PROBE,
            startup_settle: STARTUP_SETTLE,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct LaunchedBrowser {
    pub browser: &'static str,
    pub pid: u32,
    pub profile_dir: String,
    pub fresh: bool,
    pub proxy: String,
    pub url: String,
    pub driver: Driver,
    /// The browser was already running with these settings, so this opened another
    /// window in it instead of starting a second one.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub reused: bool,
    /// What an agent needs to drive it. Absent when the driver has nothing to offer
    /// unless asked (a DevTools port) and was not, or when the browser ended or never
    /// reported its port (see `warnings` and `hint`). For ego it is always a name
    /// Sniper chose, present from the start, not proof the service is ready.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control: Option<Control>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// What a running browser on a profile was started with. A later launch is
/// compared against it, because Chromium hands a second launch to the running
/// process and ignores the switches the second one carries.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Owner {
    pid: u32,
    exe: PathBuf,
    proxy: String,
    /// Whether the browser has a DevTools port, which a later launch may need.
    #[serde(alias = "debug_port")]
    devtools_port: bool,
    /// When this process started the browser. Not saved: a record read back from
    /// disk is from an earlier run, long past its first window.
    #[serde(skip)]
    started: Option<std::time::Instant>,
}

/// How a browser process ended, with the tail of what it printed. The tail is read
/// by the watcher before a throwaway profile is deleted, because the log it would
/// otherwise point to goes with the profile.
struct Exit {
    status: String,
    output: String,
}

impl Exit {
    fn describe(&self) -> String {
        if self.output.is_empty() {
            self.status.clone()
        } else {
            format!("{}; it printed: {}", self.status, self.output)
        }
    }
}

/// Open the requested browser, or the first installed one when none is named.
pub async fn launch(
    ctx: &LaunchContext<'_>,
    request: LaunchRequest,
) -> Result<LaunchedBrowser, LaunchError> {
    let (kind, exe) = match request.browser {
        Some(kind) => {
            let exe = find_executable(kind)
                .ok_or_else(|| LaunchError::NotInstalled(not_installed_message(kind)))?;
            (kind, exe)
        }
        None => BrowserKind::ALL
            .into_iter()
            .find_map(|kind| find_executable(kind).map(|exe| (kind, exe)))
            .ok_or_else(|| {
                let looked_for: Vec<_> = BrowserKind::ALL
                    .into_iter()
                    .filter(|kind| kind.platforms().contains(&current_platform()))
                    .map(BrowserKind::name)
                    .collect();
                LaunchError::NotInstalled(format!(
                    "no supported browser found (looked for {})",
                    looked_for.join(", ")
                ))
            })?,
    };
    launch_at(ctx, kind, &exe, request).await
}

/// The same answer the catalog gives, in the one place a caller who skipped the
/// catalog will read: where the browser does not exist, and how to get it where it
/// does.
fn not_installed_message(kind: BrowserKind) -> String {
    if !kind.platforms().contains(&current_platform()) {
        return format!("{} is not available on {}", kind.name(), current_platform());
    }
    match kind.install_hint() {
        Some(hint) => format!("{} is not installed. {hint}", kind.name()),
        None => format!("{} is not installed", kind.name()),
    }
}

enum Started {
    /// A new process. `exited` reports its exit status text when it ends.
    New {
        pid: u32,
        exited: mpsc::Receiver<Exit>,
    },
    /// An already-running browser took the request.
    Reused(Owner),
}

async fn launch_at(
    ctx: &LaunchContext<'_>,
    kind: BrowserKind,
    exe: &Path,
    request: LaunchRequest,
) -> Result<LaunchedBrowser, LaunchError> {
    let driver = kind.driver();
    let wants_port = driver.opens_port(request.agent);
    if wants_port && !ctx.proxy_addr.ip().is_loopback() {
        // The header guards on the API only keep web pages out, and a proxy that
        // listens beyond loopback relays requests to local ports, including this
        // one, which hands over the browser's logged-in sessions.
        return Err(LaunchError::Forbidden(
            "a DevTools port is only opened while the proxy listens on loopback only".to_string(),
        ));
    }
    let url = validate_url(request.url.as_deref().unwrap_or("about:blank"))?;
    let spki =
        spki_sha256_base64(ctx.cert_der).map_err(|error| LaunchError::Failed(error.to_string()))?;
    let proxy = proxy_arg(ctx.proxy_addr);

    let profiles_root = ctx.data_dir.join("browser-profiles");
    let profile = if request.fresh {
        profiles_root.join(format!("fresh-{}", Uuid::new_v4()))
    } else {
        profiles_root.join(kind.name())
    };
    let server_name = driver.server_name(ctx.proxy_addr.port(), &profile);
    let args = build_args(
        &profile,
        &proxy,
        &spki,
        &driver.launch_args(request.agent, server_name.as_deref()),
        &url,
    );

    let prepared = {
        let (root, profile) = (profiles_root.clone(), profile.clone());
        tokio::task::spawn_blocking(move || {
            sweep_stale_fresh_profiles(&root);
            prepare_profile(&profile)
        })
        .await
    };
    match prepared {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            return Err(LaunchError::Failed(format!(
                "could not prepare the browser profile: {error}"
            )))
        }
        Err(error) => return Err(LaunchError::Failed(error.to_string())),
    }

    let mut warnings = Vec::new();
    // Decide and start under one lock, so two launches cannot both conclude the
    // profile is free.
    let started = {
        let mut live = live_profiles()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let existing = if request.fresh {
            None
        } else {
            current_owner(&profile, &live)
        };
        match existing {
            Some(owner) if owner.proxy == proxy && (owner.devtools_port || !wants_port) => {
                // Same settings: the running browser is already wired correctly, so
                // starting the binary again just opens another window in it. This
                // is what makes the button work on macOS, where closing the last
                // window leaves the process running.
                let still_starting = owner
                    .started
                    .is_some_and(|at| at.elapsed() < ctx.startup_settle);
                if !still_starting {
                    let Some(slot) = HandoffSlot::take(&profile) else {
                        return Err(LaunchError::TooMany(format!(
                            "{MAX_HANDOFFS_PER_PROFILE} windows are already being opened in \
                             this browser; wait a moment and try again"
                        )));
                    };
                    // No log: the running browser has that file open, and opening it
                    // again to truncate would wipe what it has printed so far.
                    let child = spawn_browser(exe, &args, &profile, false)?;
                    reap_in_background(child, slot);
                }
                Started::Reused(owner)
            }
            Some(owner) => {
                let detail = if owner.proxy != proxy {
                    format!("was started for the proxy at {}, not {proxy}", owner.proxy)
                } else {
                    "was started without a DevTools port".to_string()
                };
                return Err(LaunchError::AlreadyRunning {
                    pid: owner.pid,
                    detail,
                });
            }
            None => {
                if request.fresh {
                    let throwaway_open = live
                        .keys()
                        .filter(|path| path.starts_with(&profiles_root) && is_throwaway(path))
                        .count();
                    if throwaway_open >= MAX_LIVE_BROWSERS {
                        let _ = fs::remove_dir_all(&profile);
                        return Err(LaunchError::TooMany(format!(
                            "{MAX_LIVE_BROWSERS} throwaway Sniper browsers are already open; quit \
                             one (closing the last window is not enough on macOS) before opening \
                             another"
                        )));
                    }
                }
                if wants_port {
                    // A leftover from an earlier run would be read as this run's
                    // port. Cleared here, after the decision above, so a launch
                    // that is refused never touches a running browser's file.
                    match fs::remove_file(profile.join("DevToolsActivePort")) {
                        Err(error) if error.kind() != io::ErrorKind::NotFound => {
                            warnings.push(format!(
                                "could not clear a stale DevTools port file: {error}"
                            ));
                        }
                        _ => {}
                    }
                }
                let child = match spawn_browser(exe, &args, &profile, true) {
                    Ok(child) => child,
                    Err(error) => {
                        if request.fresh {
                            let _ = fs::remove_dir_all(&profile);
                        }
                        return Err(error);
                    }
                };
                let pid = child.id();
                let owner = Owner {
                    pid,
                    exe: exe.to_path_buf(),
                    proxy: proxy.clone(),
                    devtools_port: wants_port,
                    started: Some(std::time::Instant::now()),
                };
                if let Err(error) = write_owner(&profile, &owner) {
                    // Without the record a later Sniper cannot tell this browser is
                    // open, so the caller is told rather than left to find out.
                    warn!(%error, "could not record which browser owns the profile");
                    warnings.push(format!(
                        "could not record which browser owns the profile: {error}"
                    ));
                }
                live.insert(profile.clone(), owner);
                let (exited_tx, exited) = mpsc::channel();
                if let Err(error) = watch_browser(child, &profile, pid, request.fresh, exited_tx) {
                    // Without the watcher nothing would ever clear this entry. The
                    // record stays: it is checked against the running process, so it
                    // keeps protecting a live browser and is discarded once it is not.
                    live.remove(&profile);
                    warnings.push(format!("could not watch the browser process: {error}"));
                }
                Started::New { pid, exited }
            }
        }
    };

    let mut reused_has_port = false;
    let (pid, reused, mut exited) = match started {
        Started::New { pid, exited } => {
            info!(
                browser = kind.name(),
                pid,
                fresh = request.fresh,
                "opened Sniper browser"
            );
            (pid, false, Some(exited))
        }
        Started::Reused(owner) => {
            info!(
                browser = kind.name(),
                pid = owner.pid,
                "opened another window in the running Sniper browser"
            );
            reused_has_port = owner.devtools_port;
            (owner.pid, true, None)
        }
    };

    let log_path = profile.join(LAUNCH_LOG);
    let mut ended = false;
    let mut devtools_port = None;
    if wants_port {
        match read_devtools_port(&profile, ctx.devtools_wait, exited.as_mut()).await {
            DevtoolsWait::Port(port) => devtools_port = Some(port),
            DevtoolsWait::BrowserExited(exit) => {
                ended = true;
                warnings.push(format!(
                    "the browser exited ({}) before reporting a DevTools port{}",
                    exit.describe(),
                    log_hint(request.fresh, &log_path)
                ));
            }
            DevtoolsWait::TimedOut => warnings.push(format!(
                "the browser did not report a DevTools port within {} seconds",
                ctx.devtools_wait.as_secs()
            )),
        }
    } else if let Some(exited) = exited.as_mut() {
        if let Some(exit) = wait_for_exit(exited, ctx.early_exit_probe).await {
            ended = true;
            warnings.push(format!(
                "the browser process ended within {} ms ({}): it either could not start or \
                 handed the request to a browser already running elsewhere{}",
                ctx.early_exit_probe.as_millis(),
                exit.describe(),
                log_hint(request.fresh, &log_path)
            ));
        }
    }
    // A browser that ended has nothing to drive, whichever driver it has. Handing
    // out its name anyway sends the agent to a command that fails.
    let control = if ended {
        None
    } else {
        driver.control(devtools_port, server_name.as_deref())
    };
    let hint = if ended {
        Some("the browser ended at once, so there is nothing to drive; see warnings".to_string())
    } else if control.is_none() && !request.agent {
        // Asking again is refused while this browser runs, because it was started
        // without the port; saying so here saves the round trip that finds out.
        Some(if reused_has_port {
            "this browser already has a DevTools port from an earlier agent open; open \
             again with agent to get its endpoint"
                .to_string()
        } else {
            "opened without agent control; to get it, quit this browser (closing the window \
             is not enough on macOS) and open again with agent, or add fresh for a separate \
             throwaway browser"
                .to_string()
        })
    } else {
        None
    };

    Ok(LaunchedBrowser {
        browser: kind.name(),
        pid,
        profile_dir: profile.display().to_string(),
        fresh: request.fresh,
        proxy,
        url,
        driver,
        reused,
        control,
        hint,
        warnings,
    })
}

/// A throwaway profile, and the log inside it, is gone by the time anyone reads the
/// warning, so only a persistent profile's log is worth naming.
fn log_hint(fresh: bool, log_path: &Path) -> String {
    if fresh {
        String::new()
    } else {
        format!("; full output in {}", log_path.display())
    }
}

/// Polls rather than sleeping once: a browser that dies at once is reported at once,
/// and only a healthy one costs the full probe.
async fn wait_for_exit(exited: &mut mpsc::Receiver<Exit>, within: Duration) -> Option<Exit> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if let Ok(exit) = exited.try_recv() {
            return Some(exit);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn is_throwaway(profile: &Path) -> bool {
    profile
        .file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with("fresh-"))
}

/// Only http(s) URLs. The value becomes a command-line argument, and a string that
/// parses as an absolute URL cannot also be read as a switch.
fn validate_url(raw: &str) -> Result<String, LaunchError> {
    if raw == "about:blank" {
        return Ok(raw.to_string());
    }
    let parsed = url::Url::parse(raw)
        .map_err(|_| LaunchError::BadRequest(format!("not an absolute URL: {raw}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(LaunchError::BadRequest(
            "only http and https URLs can be opened".to_string(),
        ));
    }
    Ok(parsed.to_string())
}

/// A wildcard bind is reachable at loopback, but `0.0.0.0` is not an address a
/// browser can connect to.
fn proxy_arg(addr: SocketAddr) -> String {
    let ip = match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::from([127, 0, 0, 1]),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, addr.port()).to_string()
}

fn build_args(
    profile: &Path,
    proxy: &str,
    spki: &str,
    driver_args: &[String],
    url: &str,
) -> Vec<String> {
    let mut args = vec![
        format!("--user-data-dir={}", profile.display()),
        format!("--proxy-server={proxy}"),
        // Chromium sends loopback traffic direct regardless of --proxy-server, which
        // would leave anything the tester runs locally out of the history.
        "--proxy-bypass-list=<-loopback>".to_string(),
        format!("--ignore-certificate-errors-spki-list={spki}"),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
    ];
    args.extend(driver_args.iter().cloned());
    args.push(url.to_string());
    args
}

fn prepare_profile(profile: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        // The profile holds cookies and saved logins.
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(profile)
    }
    #[cfg(not(unix))]
    fs::create_dir_all(profile)
}

/// The browser's stderr goes to a file in its profile, so a browser that cannot
/// start (a sandboxed package that cannot write the profile, a bad flag) leaves a
/// reason behind instead of silence.
fn spawn_browser(
    exe: &Path,
    args: &[String],
    profile: &Path,
    keep_log: bool,
) -> Result<Child, LaunchError> {
    let log = if keep_log {
        fs::File::create(profile.join(LAUNCH_LOG))
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::null())
    } else {
        Stdio::null()
    };
    Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .map_err(|error| LaunchError::Failed(format!("could not start {}: {error}", exe.display())))
}

/// Waits on the process so it is reaped, then forgets it: clears the registry and
/// owner record under the same lock a launch takes, and deletes a throwaway profile.
fn watch_browser(
    mut child: Child,
    profile: &Path,
    pid: u32,
    fresh: bool,
    exited: mpsc::Sender<Exit>,
) -> io::Result<()> {
    let profile = profile.to_path_buf();
    std::thread::Builder::new()
        .name("sniper-browser-wait".to_string())
        .spawn(move || {
            let status = match child.wait() {
                Ok(status) => status.to_string(),
                Err(error) => format!("wait failed: {error}"),
            };
            // Read before the profile, and the log in it, can be deleted below.
            let _ = exited.send(Exit {
                status,
                output: read_log_tail(&profile),
            });
            {
                let mut live = live_profiles()
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if live.get(&profile).is_some_and(|owner| owner.pid == pid) {
                    live.remove(&profile);
                    let _ = fs::remove_file(profile.join(OWNER_FILE));
                }
            }
            if fresh {
                // A throwaway profile holds whatever the session logged into;
                // leaving it behind would make "fresh" mean "unlisted".
                remove_profile_with_retry(&profile);
            }
        })
        .map(|_| ())
}

fn read_log_tail(profile: &Path) -> String {
    let Ok(mut file) = fs::File::open(profile.join(LAUNCH_LOG)) else {
        return String::new();
    };
    let length = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    if file
        .seek(SeekFrom::Start(length.saturating_sub(LAUNCH_LOG_TAIL)))
        .is_err()
    {
        return String::new();
    }
    let mut bytes = Vec::new();
    let _ = file.take(LAUNCH_LOG_TAIL).read_to_end(&mut bytes);
    String::from_utf8_lossy(&bytes)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// A browser's helper processes can still hold files for a moment after the main
/// process is gone, and Windows will not delete an open file, so one attempt is
/// not enough.
fn remove_profile_with_retry(profile: &Path) {
    for attempt in 1..=PROFILE_REMOVE_ATTEMPTS {
        match fs::remove_dir_all(profile) {
            Ok(()) => return,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Err(error) if attempt == PROFILE_REMOVE_ATTEMPTS => {
                warn!(%error, profile = %profile.display(), "could not remove the throwaway browser profile");
            }
            Err(_) => std::thread::sleep(PROFILE_REMOVE_RETRY),
        }
    }
}

/// Detached handoffs: the process exits as soon as the running browser takes the
/// request, and something has to collect it.
fn reap_in_background(mut child: Child, slot: HandoffSlot) {
    let _ = std::thread::Builder::new()
        .name("sniper-browser-reap".to_string())
        .spawn(move || {
            let _slot = slot;
            let _ = child.wait();
        });
}

/// One of the few windows that may be opening in a profile's running browser.
struct HandoffSlot(PathBuf);

fn handoffs() -> &'static Mutex<HashMap<PathBuf, usize>> {
    static HANDOFFS: OnceLock<Mutex<HashMap<PathBuf, usize>>> = OnceLock::new();
    HANDOFFS.get_or_init(Default::default)
}

impl HandoffSlot {
    fn take(profile: &Path) -> Option<Self> {
        let mut open = handoffs()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = open.entry(profile.to_path_buf()).or_insert(0);
        if *count >= MAX_HANDOFFS_PER_PROFILE {
            return None;
        }
        *count += 1;
        Some(Self(profile.to_path_buf()))
    }
}

impl Drop for HandoffSlot {
    fn drop(&mut self) {
        let mut open = handoffs()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = open.get_mut(&self.0) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                open.remove(&self.0);
            }
        }
    }
}

/// Written to a temporary name and renamed, so a reader sees the old record or the
/// new one and never a half-written file that would parse as "no browser".
fn write_owner(profile: &Path, owner: &Owner) -> io::Result<()> {
    let json = serde_json::to_vec(owner).map_err(io::Error::other)?;
    let temporary = profile.join(format!("{OWNER_FILE}.tmp"));
    fs::write(&temporary, json)?;
    crate::platform::rename(&temporary, profile.join(OWNER_FILE))
}

fn read_owner(profile: &Path) -> Option<Owner> {
    serde_json::from_slice(&fs::read(profile.join(OWNER_FILE)).ok()?).ok()
}

/// The browser running on a profile, whether this process started it or an earlier
/// Sniper did. The record alone is not trusted: the pid must still be running that
/// same executable, because a recycled pid would otherwise refuse the profile for
/// good on the strength of a process that is not a browser.
fn current_owner(profile: &Path, live: &HashMap<PathBuf, Owner>) -> Option<Owner> {
    if let Some(owner) = live.get(profile) {
        return Some(owner.clone());
    }
    let owner = read_owner(profile)?;
    if process_runs_as(owner.pid, &owner.exe) {
        Some(owner)
    } else {
        let _ = fs::remove_file(profile.join(OWNER_FILE));
        None
    }
}

/// Throwaway profiles are deleted by a thread inside this process, which dies with
/// it. Anything left by a crash or a quit is removed here on the next launch, unless
/// its browser is still running or it is too new to be sure it is abandoned.
fn sweep_stale_fresh_profiles(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let live: Vec<PathBuf> = live_profiles()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .keys()
        .cloned()
        .collect();
    for entry in entries.flatten() {
        let path = entry.path();
        let is_fresh_dir = entry.file_name().to_string_lossy().starts_with("fresh-")
            && entry.file_type().is_ok_and(|kind| kind.is_dir());
        if !is_fresh_dir || live.contains(&path) {
            continue;
        }
        let recent = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age < FRESH_PROFILE_GRACE);
        let still_running =
            read_owner(&path).is_some_and(|owner| process_runs_as(owner.pid, &owner.exe));
        if !recent && !still_running {
            remove_profile_with_retry(&path);
        }
    }
}

enum DevtoolsWait {
    Port(u16),
    BrowserExited(Exit),
    TimedOut,
}

// `&mut` rather than `&`: a std Receiver is not Sync, and a shared reference held
// across an await would make the whole request handler not Send.
async fn read_devtools_port(
    profile: &Path,
    wait: Duration,
    mut exited: Option<&mut mpsc::Receiver<Exit>>,
) -> DevtoolsWait {
    let file = profile.join("DevToolsActivePort");
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        if let Ok(text) = tokio::fs::read_to_string(&file).await {
            if let Some(port) = text
                .lines()
                .next()
                .and_then(|line| line.trim().parse().ok())
            {
                return DevtoolsWait::Port(port);
            }
        }
        // Waiting out the full limit on a browser that is already gone only delays
        // the answer to "why".
        if let Some(exit) = exited.as_mut().and_then(|channel| channel.try_recv().ok()) {
            return DevtoolsWait::BrowserExited(exit);
        }
        if tokio::time::Instant::now() >= deadline {
            return DevtoolsWait::TimedOut;
        }
        tokio::time::sleep(DEVTOOLS_POLL).await;
    }
}

#[cfg(target_os = "macos")]
fn process_exe(pid: u32) -> Option<PathBuf> {
    const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
    let mut buffer = vec![0_u8; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: the buffer outlives the call and its length is passed alongside it.
    let length = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len() as u32,
        )
    };
    (length > 0)
        .then(|| PathBuf::from(String::from_utf8_lossy(&buffer[..length as usize]).into_owned()))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn process_exe(pid: u32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(windows)]
fn process_exe(pid: u32) -> Option<PathBuf> {
    crate::platform::running_process_path(pid)
}

#[cfg(not(any(unix, windows)))]
fn process_exe(_pid: u32) -> Option<PathBuf> {
    None
}

fn process_runs_as(pid: u32, expected: &Path) -> bool {
    if pid == 0 {
        return false;
    }
    let Some(actual) = process_exe(pid) else {
        return false;
    };
    let resolved = |path: &Path| fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    resolved(&actual) == resolved(expected)
}

/// Profiles with a live browser started by this process.
fn live_profiles() -> &'static Mutex<HashMap<PathBuf, Owner>> {
    static LIVE: OnceLock<Mutex<HashMap<PathBuf, Owner>>> = OnceLock::new();
    LIVE.get_or_init(Default::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_hash_is_the_sha256_of_the_public_key_info() {
        // Derived from the key pair, not from the certificate, so this does not
        // share a parsing path with the code under test.
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["ca.example".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let expected =
            base64::engine::general_purpose::STANDARD.encode(Sha256::digest(key.public_key_der()));
        assert_eq!(spki_sha256_base64(cert.der().as_ref()).unwrap(), expected);
        assert!(spki_sha256_base64(b"not a certificate").is_err());
    }

    #[test]
    fn launch_args_carry_the_four_switches_and_keep_the_url_last() {
        let args = build_args(
            Path::new("/data/browser-profiles/chrome"),
            "127.0.0.1:8080",
            "HASH=",
            &[],
            "https://example.com/",
        );
        assert_eq!(args[0], "--user-data-dir=/data/browser-profiles/chrome");
        assert!(args.contains(&"--proxy-server=127.0.0.1:8080".to_string()));
        assert!(args.contains(&"--proxy-bypass-list=<-loopback>".to_string()));
        assert!(args.contains(&"--ignore-certificate-errors-spki-list=HASH=".to_string()));
        assert_eq!(args.last().unwrap(), "https://example.com/");
        assert!(
            !args
                .iter()
                .any(|arg| arg.contains("remote-debugging") || arg.contains("ego-server-name")),
            "the shared switches know nothing about any driver"
        );

        // A driver's switches go in before the URL, which stays last.
        let with_driver = build_args(
            Path::new("/p"),
            "h:1",
            "H=",
            &["--remote-debugging-port=0".to_string()],
            "about:blank",
        );
        let at = with_driver
            .iter()
            .position(|a| a == "--remote-debugging-port=0")
            .unwrap();
        assert_eq!(at, with_driver.len() - 2);
        assert_eq!(with_driver.last().unwrap(), "about:blank");
    }

    // Everything that differs between ways of driving a browser is in Driver, so
    // that is where it is pinned down.
    #[test]
    fn each_driver_adds_only_its_own_switches() {
        assert!(Driver::Cdp.launch_args(false, None).is_empty());
        assert_eq!(
            Driver::Cdp.launch_args(true, None),
            vec!["--remote-debugging-port=0".to_string()]
        );
        for agent in [false, true] {
            assert_eq!(
                Driver::EgoCli.launch_args(agent, Some("sniper-8080")),
                vec!["--ego-server-name=sniper-8080".to_string()],
                "ego is named whether or not an agent was asked for, so an agent can \
                 never be pointed at the user's own instance by omission"
            );
        }
        assert!(Driver::EgoCli.launch_args(true, None).is_empty());

        assert!(Driver::Cdp.opens_port(true) && !Driver::Cdp.opens_port(false));
        assert!(
            !Driver::EgoCli.opens_port(true),
            "ego has no DevTools port to open"
        );

        let profile = Path::new("/data/a/browser-profiles/ego");
        assert_eq!(Driver::Cdp.server_name(8080, profile), None);
        let name = Driver::EgoCli.server_name(8080, profile).unwrap();
        assert!(
            name.starts_with("sniper-8080-") && name.len() <= 64,
            "{name}"
        );
        assert!(
            name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "only characters ego accepts in a name: {name}"
        );
    }

    // The proxy port alone is the same for every data directory on default settings.
    // A stale ego left by an earlier run would then answer to a new one's name.
    #[test]
    fn the_ego_name_follows_the_profile_not_just_the_proxy_port() {
        let name = |port, path: &str| Driver::EgoCli.server_name(port, Path::new(path)).unwrap();
        let one = name(8080, "/data/one/browser-profiles/ego");
        assert_eq!(
            one,
            name(8080, "/data/one/browser-profiles/ego"),
            "the same profile keeps its name, so reuse and a restart agree"
        );
        assert_ne!(one, name(8080, "/data/two/browser-profiles/ego"));
        assert_ne!(one, name(8081, "/data/one/browser-profiles/ego"));
        assert_ne!(
            name(8080, "/data/one/browser-profiles/fresh-aaaa"),
            name(8080, "/data/one/browser-profiles/fresh-bbbb"),
            "two throwaway profiles never share a name"
        );
    }

    #[test]
    fn the_browser_names_come_from_one_list() {
        assert_eq!(
            BrowserKind::names(),
            ["chrome", "edge", "brave", "chromium", "ego"]
        );
        assert!(BrowserKind::names()
            .into_iter()
            .all(|name| BrowserKind::parse(name).is_some()));
    }

    #[test]
    fn a_missing_browser_says_where_it_does_not_exist_and_how_to_get_it() {
        let ego = not_installed_message(BrowserKind::Ego);
        if cfg!(target_os = "macos") {
            assert!(ego.contains("not installed"), "{ego}");
            assert!(ego.contains("Sniper does not install it"), "{ego}");
        } else {
            assert!(ego.contains("is not available on"), "{ego}");
        }
        assert_eq!(
            not_installed_message(BrowserKind::Edge),
            "edge is not installed"
        );
    }

    // This output is read by agents. A hint that is a command to install software
    // reads as one they may run, so the hints point at where to look, and only for
    // what is actually missing.
    #[test]
    fn requirement_hints_appear_only_when_missing_and_are_never_commands() {
        for requirement in driver_requirements(Driver::EgoCli) {
            if requirement.found {
                assert!(requirement.hint.is_none(), "{}", requirement.name);
            } else {
                let hint = requirement
                    .hint
                    .expect("a missing requirement says what to do");
                assert!(
                    !hint.contains("npx") && !hint.contains(" install "),
                    "{hint}"
                );
            }
        }
    }

    #[test]
    fn a_driver_hands_out_control_in_its_own_shape_under_one_contract() {
        let cdp = Driver::Cdp.control(Some(4242), None).unwrap();
        assert_eq!(
            serde_json::to_value(&cdp).unwrap(),
            serde_json::json!({"driver": "cdp", "endpoint": "http://127.0.0.1:4242"})
        );
        assert!(Driver::Cdp.control(None, None).is_none());

        let ego = Driver::EgoCli.control(None, Some("sniper-8080")).unwrap();
        let ego = serde_json::to_value(&ego).unwrap();
        assert_eq!(ego["driver"], "ego-cli");
        assert_eq!(ego["server_name"], "sniper-8080");
        assert!(ego["command"]
            .as_str()
            .unwrap()
            .contains("--ego-server-name=sniper-8080"));
        assert!(Driver::EgoCli.control(None, None).is_none());
    }

    #[test]
    fn the_catalog_lists_what_exists_on_this_platform_and_says_what_is_missing() {
        let requirements = |driver: Driver| match driver {
            Driver::Cdp => Vec::new(),
            Driver::EgoCli => vec![Requirement {
                name: "ego-browser command",
                found: false,
                hint: Some("registered by ego"),
            }],
        };
        let only_chrome = |kind: BrowserKind| {
            (kind == BrowserKind::Chrome).then(|| PathBuf::from("/Apps/Chrome"))
        };

        let mac = catalog_for("macos", only_chrome, requirements);
        let names: Vec<_> = mac.iter().map(|entry| entry.browser).collect();
        assert_eq!(names, ["chrome", "edge", "brave", "chromium", "ego"]);
        let chrome = &mac[0];
        assert!(chrome.installed && chrome.path.as_deref() == Some("/Apps/Chrome"));
        assert_eq!(chrome.driver, Driver::Cdp);
        assert_eq!(chrome.capabilities.ui_actions, "via-client");
        assert!(chrome.requirements.is_empty() && chrome.install_hint.is_none());

        let ego = mac.iter().find(|entry| entry.browser == "ego").unwrap();
        assert!(!ego.installed && ego.path.is_none());
        assert!(ego
            .install_hint
            .unwrap()
            .contains("Sniper does not install it"));
        assert_eq!(ego.capabilities.ui_actions, "built-in");
        assert_eq!(ego.requirements.len(), 1);

        // Not built for Windows, so it is not listed as "not installed" there.
        let windows = catalog_for("windows", only_chrome, requirements);
        assert!(windows.iter().all(|entry| entry.browser != "ego"));
        assert_eq!(windows.len(), 4);

        // An installed browser carries no install hint even if it has one to give.
        let ego_installed = catalog_for("macos", |_| Some(PathBuf::from("/x")), requirements);
        assert!(ego_installed
            .iter()
            .all(|entry| entry.install_hint.is_none()));

        let json = serde_json::to_value(&mac).unwrap();
        assert_eq!(json[0]["driver"], "cdp");
        assert_eq!(json[4]["driver"], "ego-cli");
        assert!(json[0].get("install_hint").is_none(), "absent, not null");
    }

    #[test]
    fn only_http_urls_are_accepted_and_none_can_be_read_as_a_switch() {
        assert_eq!(validate_url("about:blank").unwrap(), "about:blank");
        assert_eq!(
            validate_url("https://example.com").unwrap(),
            "https://example.com/"
        );
        for bad in [
            "--remote-debugging-port=1",
            "-x",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,hi",
            "chrome://settings",
            "example.com",
            "",
        ] {
            assert!(
                matches!(validate_url(bad), Err(LaunchError::BadRequest(_))),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn a_wildcard_bind_is_dialled_at_loopback() {
        let proxy = |text: &str| proxy_arg(text.parse().unwrap());
        assert_eq!(proxy("0.0.0.0:8080"), "127.0.0.1:8080");
        assert_eq!(proxy("[::]:8080"), "[::1]:8080");
        assert_eq!(proxy("127.0.0.1:18890"), "127.0.0.1:18890");
        assert_eq!(proxy("192.0.2.7:8080"), "192.0.2.7:8080");
    }

    #[test]
    fn names_parse_case_insensitively_and_auto_order_puts_ego_last() {
        assert_eq!(BrowserKind::parse(" Chrome "), Some(BrowserKind::Chrome));
        assert_eq!(BrowserKind::parse("EGO"), Some(BrowserKind::Ego));
        assert_eq!(BrowserKind::parse("firefox"), None);
        assert_eq!(BrowserKind::ALL.last(), Some(&BrowserKind::Ego));
        assert_eq!(BrowserKind::Ego.driver(), Driver::EgoCli);
        assert_eq!(BrowserKind::Chrome.driver(), Driver::Cdp);
    }

    #[test]
    fn detection_takes_the_first_candidate_that_exists() {
        let candidates = vec![
            PathBuf::from("/a"),
            PathBuf::from("/b"),
            PathBuf::from("/c"),
        ];
        let found = first_existing(candidates.clone(), |path| path != Path::new("/a"));
        assert_eq!(found, Some(PathBuf::from("/b")));
        assert_eq!(first_existing(candidates, |_| false), None);
    }

    // The process that runs these tests is a live process with a known executable,
    // which is all the ownership check looks at.
    #[cfg(any(unix, windows))]
    #[test]
    fn a_pid_is_only_trusted_while_it_still_runs_the_recorded_executable() {
        let me = std::process::id();
        let exe = std::env::current_exe().unwrap();
        assert!(process_runs_as(me, &exe));
        assert!(
            !process_runs_as(me, Path::new("/definitely/not/this/binary")),
            "a recycled pid must not vouch for a different program"
        );
        assert!(!process_runs_as(0, &exe));
    }

    #[cfg(unix)]
    mod spawn {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        use std::time::SystemTime;

        const PROXY: &str = "127.0.0.1:18890";

        struct Fixture {
            dir: PathBuf,
            cert: Vec<u8>,
        }

        impl Fixture {
            fn new() -> Self {
                let dir = std::env::temp_dir().join(format!("sniper-browser-{}", Uuid::new_v4()));
                fs::create_dir_all(&dir).unwrap();
                let key = rcgen::KeyPair::generate().unwrap();
                let cert = rcgen::CertificateParams::new(vec!["ca.example".to_string()])
                    .unwrap()
                    .self_signed(&key)
                    .unwrap();
                Self {
                    dir,
                    cert: cert.der().as_ref().to_vec(),
                }
            }

            fn script(&self, body: &str) -> PathBuf {
                let path = self.dir.join(format!("fake-browser-{}", Uuid::new_v4()));
                fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
                path
            }

            // A browser that stays open for exactly as long as the test does. A fixed
            // `sleep` made these tests depend on the loop finishing before it ended,
            // which a loaded machine does not guarantee.
            fn open_browser(&self, before: &str) -> PathBuf {
                self.script(&format!(
                    "{before}\nwhile [ -d '{}' ]; do sleep 0.05; done",
                    self.dir.display()
                ))
            }

            fn profile(&self, name: &str) -> PathBuf {
                self.dir.join("browser-profiles").join(name)
            }

            fn ctx(&self) -> LaunchContext<'_> {
                self.build(PROXY, Duration::from_secs(5), Duration::from_millis(50))
            }

            // The waits only cost time when the thing they wait for never happens,
            // so a test that expects it gets a generous limit and only the tests for
            // "never happens" use a short one. Short limits everywhere failed under
            // parallel load. The startup settle is zero so a second launch is a
            // handoff unless a test is about the settle itself.
            fn build(
                &self,
                proxy: &str,
                devtools_wait: Duration,
                early_exit_probe: Duration,
            ) -> LaunchContext<'_> {
                LaunchContext {
                    data_dir: &self.dir,
                    proxy_addr: proxy.parse().unwrap(),
                    cert_der: &self.cert,
                    devtools_wait,
                    early_exit_probe,
                    startup_settle: Duration::ZERO,
                }
            }
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.dir);
            }
        }

        // Generous because it only costs time when the file never comes: a two-second
        // limit failed once right after a compile, when the machine was busy.
        async fn wait_for(path: &Path) -> String {
            for _ in 0..500 {
                if let Ok(text) = fs::read_to_string(path) {
                    if !text.is_empty() {
                        return text;
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!("{} never appeared", path.display());
        }

        // Written to a temporary name and renamed, so `wait_for` never reads a file
        // the script is still part-way through writing. Reading at the first
        // non-empty moment saw only some of the arguments under full-suite load.
        fn recording_script(out: &Path) -> String {
            format!(
                "printf '%s\\n' \"$@\" > '{out}.tmp' && mv '{out}.tmp' '{out}'",
                out = out.display()
            )
        }

        fn age_directory(dir: &Path, seconds: u64) {
            fs::File::open(dir)
                .unwrap()
                .set_modified(SystemTime::now() - Duration::from_secs(seconds))
                .unwrap();
        }

        fn write_record(profile: &Path, owner: &Owner) {
            fs::create_dir_all(profile).unwrap();
            write_owner(profile, owner).unwrap();
        }

        fn this_process(proxy: &str, devtools_port: bool) -> Owner {
            Owner {
                pid: std::process::id(),
                exe: std::env::current_exe().unwrap(),
                proxy: proxy.to_string(),
                devtools_port,
                started: None,
            }
        }

        // A real browser cannot run in a test, so a script records what it was
        // handed. What matters is that the argv is what the browser would need.
        #[tokio::test]
        async fn the_browser_is_started_with_the_proxy_the_ca_hash_and_a_private_profile() {
            let fixture = Fixture::new();
            let out = fixture.dir.join("argv.txt");
            // Open for the whole test: the record exists only while the browser does.
            let exe = fixture.open_browser(&recording_script(&out));

            let launched = launch_at(
                &fixture.ctx(),
                BrowserKind::Chrome,
                &exe,
                LaunchRequest {
                    url: Some("https://example.com".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

            let argv = wait_for(&out).await;
            let profile = fixture.profile("chrome");
            assert!(argv.contains(&format!("--user-data-dir={}", profile.display())));
            assert!(argv.contains("--proxy-server=127.0.0.1:18890"));
            assert!(argv.contains("--ignore-certificate-errors-spki-list="));
            assert!(argv.trim_end().ends_with("https://example.com/"));
            assert_eq!(launched.browser, "chrome");
            assert!(launched.control.is_none(), "no agent asked, so no port");
            assert!(!launched.reused);
            assert!(launched.hint.as_deref().unwrap().contains("agent"));
            let mode = fs::metadata(&profile).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "the profile holds logged-in sessions");
            assert!(
                profile.join(LAUNCH_LOG).exists(),
                "stderr needs somewhere to go"
            );
            assert_eq!(
                read_owner(&profile).map(|owner| owner.pid),
                Some(launched.pid)
            );
            assert!(
                !profile.join(format!("{OWNER_FILE}.tmp")).exists(),
                "the record is renamed into place, not left beside it"
            );
        }

        // The case that made a plain "already open" refusal wrong: on macOS closing
        // the last window leaves the browser process running, so pressing the button
        // again is a request for a new window in it, not an error.
        #[tokio::test]
        async fn a_second_launch_with_the_same_settings_reuses_the_running_browser() {
            let fixture = Fixture::new();
            let exe = fixture.open_browser("");

            let first = launch_at(
                &fixture.ctx(),
                BrowserKind::Brave,
                &exe,
                LaunchRequest::default(),
            )
            .await
            .unwrap();
            let second = launch_at(
                &fixture.ctx(),
                BrowserKind::Brave,
                &exe,
                LaunchRequest::default(),
            )
            .await
            .unwrap();
            assert!(second.reused);
            assert_eq!(second.pid, first.pid);
            assert!(second.warnings.is_empty(), "{:?}", second.warnings);

            // A different browser has its own profile and is independent.
            let edge = launch_at(
                &fixture.ctx(),
                BrowserKind::Edge,
                &exe,
                LaunchRequest::default(),
            )
            .await
            .unwrap();
            assert!(!edge.reused);
        }

        // Two requests in quick succession are one intent. Starting the binary again
        // while the first is still opening its window can win Chromium's startup
        // race, and the browser that results is one nothing tracks.
        #[tokio::test]
        async fn a_launch_while_the_browser_is_still_starting_does_not_start_another() {
            let fixture = Fixture::new();
            let calls = fixture.dir.join("calls.txt");
            let exe = fixture.open_browser(&format!("echo started >> '{}'", calls.display()));
            let mut ctx = fixture.ctx();
            ctx.startup_settle = Duration::from_secs(30);

            let first = launch_at(&ctx, BrowserKind::Chromium, &exe, LaunchRequest::default())
                .await
                .unwrap();
            let second = launch_at(&ctx, BrowserKind::Chromium, &exe, LaunchRequest::default())
                .await
                .unwrap();
            assert!(second.reused);
            assert_eq!(second.pid, first.pid);

            wait_for(&calls).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert_eq!(
                fs::read_to_string(&calls).unwrap().lines().count(),
                1,
                "the second request started nothing"
            );
        }

        // A reused launch is a full browser process until it hands over and exits,
        // so a loop of requests must not be able to start an unbounded number.
        #[tokio::test]
        async fn windows_opening_in_one_browser_are_capped() {
            let fixture = Fixture::new();
            let exe = fixture.open_browser("");
            launch_at(
                &fixture.ctx(),
                BrowserKind::Brave,
                &exe,
                LaunchRequest::default(),
            )
            .await
            .unwrap();
            for _ in 0..MAX_HANDOFFS_PER_PROFILE {
                let again = launch_at(
                    &fixture.ctx(),
                    BrowserKind::Brave,
                    &exe,
                    LaunchRequest::default(),
                )
                .await
                .unwrap();
                assert!(again.reused);
            }
            let over = launch_at(
                &fixture.ctx(),
                BrowserKind::Brave,
                &exe,
                LaunchRequest::default(),
            )
            .await;
            assert!(matches!(over, Err(LaunchError::TooMany(_))), "{over:?}");
        }

        // The running browser has its stderr on this file. Reopening it to truncate
        // would wipe what the browser printed and leave its later writes at a stale
        // offset.
        #[tokio::test]
        async fn a_reused_launch_leaves_the_running_browsers_log_alone() {
            let fixture = Fixture::new();
            let exe = fixture.open_browser("echo 'printed at startup' >&2");
            launch_at(
                &fixture.ctx(),
                BrowserKind::Edge,
                &exe,
                LaunchRequest::default(),
            )
            .await
            .unwrap();
            let log = fixture.profile("edge").join(LAUNCH_LOG);
            assert!(wait_for(&log).await.contains("printed at startup"));

            let again = launch_at(
                &fixture.ctx(),
                BrowserKind::Edge,
                &exe,
                LaunchRequest::default(),
            )
            .await
            .unwrap();
            assert!(again.reused);
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(fs::read_to_string(&log)
                .unwrap()
                .contains("printed at startup"));
        }

        // Chromium ignores a second launch's switches, so reusing a browser that was
        // wired differently would look like success and capture nothing.
        #[tokio::test]
        async fn a_second_launch_wired_differently_is_refused_with_the_reason() {
            let fixture = Fixture::new();
            let exe = fixture.open_browser("");
            let first = launch_at(
                &fixture.ctx(),
                BrowserKind::Chromium,
                &exe,
                LaunchRequest::default(),
            )
            .await
            .unwrap();

            let other_proxy = fixture.build(
                "127.0.0.1:18891",
                Duration::from_secs(5),
                Duration::from_millis(50),
            );
            let refused = launch_at(
                &other_proxy,
                BrowserKind::Chromium,
                &exe,
                LaunchRequest::default(),
            )
            .await;
            assert!(
                matches!(&refused, Err(LaunchError::AlreadyRunning { pid, detail })
                    if *pid == first.pid && detail.contains("18890")),
                "{refused:?}"
            );
        }

        // The port file is how a running browser's DevTools port is found. A launch
        // that is going to be refused must not have deleted it on the way.
        #[tokio::test]
        async fn a_refused_launch_leaves_the_running_browsers_port_file_alone() {
            let fixture = Fixture::new();
            let exe = fixture.open_browser("");
            launch_at(
                &fixture.ctx(),
                BrowserKind::Brave,
                &exe,
                LaunchRequest::default(),
            )
            .await
            .unwrap();
            let port_file = fixture.profile("brave").join("DevToolsActivePort");
            fs::write(&port_file, "5555\n/devtools/browser/keep\n").unwrap();

            let refused = launch_at(
                &fixture.ctx(),
                BrowserKind::Brave,
                &exe,
                LaunchRequest {
                    agent: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(
                matches!(&refused, Err(LaunchError::AlreadyRunning { detail, .. })
                    if detail.contains("DevTools")),
                "{refused:?}"
            );
            assert_eq!(
                fs::read_to_string(&port_file).unwrap(),
                "5555\n/devtools/browser/keep\n"
            );
        }

        // After Sniper restarts its in-memory list is empty, but the browser it
        // started is still open. The record in the profile is how it is recognised.
        #[tokio::test]
        async fn a_browser_left_by_an_earlier_sniper_is_recognised_from_its_record() {
            let fixture = Fixture::new();
            let exe = fixture.script("exit 0");
            write_record(&fixture.profile("chrome"), &this_process(PROXY, false));

            let reused = launch_at(
                &fixture.ctx(),
                BrowserKind::Chrome,
                &exe,
                LaunchRequest::default(),
            )
            .await
            .unwrap();
            assert!(reused.reused);
            assert_eq!(reused.pid, std::process::id());

            let moved = fixture.build(
                "127.0.0.1:18891",
                Duration::from_secs(5),
                Duration::from_millis(50),
            );
            let refused =
                launch_at(&moved, BrowserKind::Chrome, &exe, LaunchRequest::default()).await;
            assert!(
                matches!(&refused, Err(LaunchError::AlreadyRunning { detail, .. })
                    if detail.contains("18890")),
                "{refused:?}"
            );
        }

        // A record is not proof of a browser: the pid may have been recycled. One
        // that no longer runs the recorded executable must not refuse the profile.
        #[tokio::test]
        async fn a_record_for_a_process_that_is_gone_is_ignored() {
            let fixture = Fixture::new();
            let exe = fixture.open_browser("");
            let mut gone = std::process::Command::new("sh")
                .args(["-c", "exit 0"])
                .spawn()
                .unwrap();
            gone.wait().unwrap();
            let stale = Owner {
                pid: gone.id(),
                exe: PathBuf::from("/bin/sh"),
                proxy: "127.0.0.1:9".to_string(),
                devtools_port: false,
                started: None,
            };
            write_record(&fixture.profile("edge"), &stale);

            let launched = launch_at(
                &fixture.ctx(),
                BrowserKind::Edge,
                &exe,
                LaunchRequest::default(),
            )
            .await
            .unwrap();
            assert!(!launched.reused);
            assert_ne!(launched.pid, stale.pid);
            assert_eq!(
                read_owner(&fixture.profile("edge")).map(|owner| owner.pid),
                Some(launched.pid),
                "the stale record is replaced by this launch's"
            );
        }

        #[tokio::test]
        async fn old_throwaway_profiles_are_swept_but_live_and_recent_ones_are_kept() {
            let fixture = Fixture::new();
            let exe = fixture.script("exit 0");
            let root = fixture.dir.join("browser-profiles");
            let orphan = root.join("fresh-orphan");
            let recent = root.join("fresh-recent");
            let running = root.join("fresh-running");
            let persistent = root.join("chrome");
            for dir in [&orphan, &recent, &running, &persistent] {
                fs::create_dir_all(dir.join("Default")).unwrap();
            }
            write_record(&running, &this_process(PROXY, false));
            for dir in [&orphan, &running, &persistent] {
                age_directory(dir, 3600);
            }

            launch_at(
                &fixture.ctx(),
                BrowserKind::Edge,
                &exe,
                LaunchRequest::default(),
            )
            .await
            .unwrap();

            assert!(
                !orphan.exists(),
                "an abandoned throwaway profile is removed"
            );
            assert!(
                recent.exists(),
                "one this young may belong to a launch in flight"
            );
            assert!(running.exists(), "its browser is still running");
            assert!(
                persistent.exists(),
                "only throwaway profiles are ever swept"
            );
        }

        // Persistent profiles are bounded by the number of browsers, so only
        // throwaway ones count. Otherwise eight of them would answer "too many" to
        // the button, which opens a persistent profile.
        #[tokio::test]
        async fn throwaway_browsers_are_capped_without_locking_out_the_persistent_one() {
            let fixture = Fixture::new();
            let exe = fixture.open_browser("");
            let fresh = || LaunchRequest {
                fresh: true,
                ..Default::default()
            };
            for _ in 0..MAX_LIVE_BROWSERS {
                launch_at(&fixture.ctx(), BrowserKind::Chromium, &exe, fresh())
                    .await
                    .unwrap();
            }
            let refused = launch_at(&fixture.ctx(), BrowserKind::Chromium, &exe, fresh()).await;
            assert!(
                matches!(&refused, Err(LaunchError::TooMany(message)) if message.contains("quit")),
                "{refused:?}"
            );
            let directories = fs::read_dir(fixture.dir.join("browser-profiles"))
                .unwrap()
                .count();
            assert_eq!(
                directories, MAX_LIVE_BROWSERS,
                "the refused launch left no profile behind"
            );

            let persistent = launch_at(
                &fixture.ctx(),
                BrowserKind::Chromium,
                &exe,
                LaunchRequest::default(),
            )
            .await;
            assert!(persistent.is_ok(), "{persistent:?}");
        }

        #[tokio::test]
        async fn a_browser_that_exits_at_once_is_reported_with_what_it_printed() {
            let fixture = Fixture::new();
            let dies = fixture.script("echo 'cannot write the profile' >&2; exit 3");
            // A generous probe costs nothing: the exit is seen and reported at once.
            let ctx = fixture.build(PROXY, Duration::from_secs(5), Duration::from_secs(5));

            let launched = launch_at(&ctx, BrowserKind::Chrome, &dies, LaunchRequest::default())
                .await
                .unwrap();
            assert_eq!(launched.warnings.len(), 1, "{:?}", launched.warnings);
            assert!(launched.warnings[0].contains("ended within"));
            assert!(
                launched.warnings[0].contains("cannot write the profile"),
                "the warning carries the output itself: {:?}",
                launched.warnings
            );
            assert!(
                launched.warnings[0].contains(LAUNCH_LOG),
                "a persistent profile keeps its log"
            );
            let log = fs::read_to_string(fixture.profile("chrome").join(LAUNCH_LOG)).unwrap();
            assert!(log.contains("cannot write the profile"), "{log}");

            // Asking for a DevTools port must not sit out the whole wait for a
            // browser that is already gone.
            let started = std::time::Instant::now();
            let quick = launch_at(
                &fixture.build(PROXY, Duration::from_secs(20), Duration::from_millis(50)),
                BrowserKind::Edge,
                &dies,
                LaunchRequest {
                    agent: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "waited out the DevTools limit"
            );
            assert!(quick.warnings[0].contains("exited"), "{:?}", quick.warnings);
            assert!(quick.control.is_none());
        }

        // A throwaway profile is deleted the moment its browser dies, log included,
        // so the warning cannot point at it. The output has to travel in the warning.
        #[tokio::test]
        async fn a_throwaway_browser_that_fails_still_reports_why() {
            let fixture = Fixture::new();
            let dies = fixture.script("echo 'unknown flag' >&2; exit 2");
            let ctx = fixture.build(PROXY, Duration::from_secs(5), Duration::from_secs(5));

            let launched = launch_at(
                &ctx,
                BrowserKind::Chromium,
                &dies,
                LaunchRequest {
                    fresh: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            assert_eq!(launched.warnings.len(), 1, "{:?}", launched.warnings);
            assert!(
                launched.warnings[0].contains("unknown flag"),
                "{:?}",
                launched.warnings
            );
            assert!(
                !launched.warnings[0].contains(LAUNCH_LOG),
                "it must not name a file that is about to be deleted"
            );
            for _ in 0..100 {
                if !Path::new(&launched.profile_dir).exists() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!("the throwaway profile was left behind");
        }

        #[tokio::test]
        async fn a_failed_start_of_a_throwaway_browser_leaves_no_profile_behind() {
            let fixture = Fixture::new();
            let not_executable = fixture.dir.join("not-a-program");
            fs::write(&not_executable, "text").unwrap();

            let result = launch_at(
                &fixture.ctx(),
                BrowserKind::Chromium,
                &not_executable,
                LaunchRequest {
                    fresh: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(matches!(result, Err(LaunchError::Failed(_))), "{result:?}");
            let leftovers = fs::read_dir(fixture.dir.join("browser-profiles"))
                .map(|entries| entries.count())
                .unwrap_or(0);
            assert_eq!(leftovers, 0);
        }

        #[tokio::test]
        async fn a_fresh_profile_is_unique_and_removed_when_the_browser_exits() {
            let fixture = Fixture::new();
            let exe = fixture.script("exit 0");

            let request = || LaunchRequest {
                fresh: true,
                ..Default::default()
            };
            let a = launch_at(&fixture.ctx(), BrowserKind::Chromium, &exe, request())
                .await
                .unwrap();
            let b = launch_at(&fixture.ctx(), BrowserKind::Chromium, &exe, request())
                .await
                .unwrap();
            assert_ne!(a.profile_dir, b.profile_dir);

            for _ in 0..100 {
                if !Path::new(&a.profile_dir).exists() && !Path::new(&b.profile_dir).exists() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!("fresh profiles were left behind");
        }

        #[tokio::test]
        async fn the_devtools_port_is_read_from_this_run_not_a_stale_file() {
            let fixture = Fixture::new();
            let profile = fixture.profile("chrome");
            fs::create_dir_all(&profile).unwrap();
            fs::write(
                profile.join("DevToolsActivePort"),
                "1111\n/devtools/browser/old\n",
            )
            .unwrap();

            let reports = fixture.open_browser(
                "for a in \"$@\"; do case \"$a\" in --user-data-dir=*) d=\"${a#--user-data-dir=}\";; esac; done\n\
                 printf '4242\\n/devtools/browser/new\\n' > \"$d/DevToolsActivePort\"",
            );
            let with_port = LaunchRequest {
                agent: true,
                ..Default::default()
            };
            let launched = launch_at(&fixture.ctx(), BrowserKind::Chrome, &reports, with_port)
                .await
                .unwrap();
            assert!(
                matches!(&launched.control, Some(Control::Cdp { endpoint })
                    if endpoint == "http://127.0.0.1:4242"),
                "{:?}",
                launched.control
            );

            // A browser that never reports a port yields a warning, not a stale value.
            let silent = fixture.open_browser("");
            let launched = launch_at(
                &fixture.build(PROXY, Duration::from_millis(300), Duration::from_millis(50)),
                BrowserKind::Edge,
                &silent,
                LaunchRequest {
                    agent: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            assert!(launched.control.is_none());
            assert_eq!(launched.warnings.len(), 1);
        }

        // For ego the name exists before the process does, so `control` has to be
        // withheld when the process turns out to have ended, or an agent is sent to a
        // command against an instance that is not there.
        #[tokio::test]
        async fn a_browser_that_ended_at_once_hands_out_no_control_whatever_its_driver() {
            let fixture = Fixture::new();
            let dies = fixture.script("echo 'cannot start' >&2; exit 2");
            let ctx = fixture.build(PROXY, Duration::from_secs(5), Duration::from_secs(5));

            let ego = launch_at(&ctx, BrowserKind::Ego, &dies, LaunchRequest::default())
                .await
                .unwrap();
            assert!(ego.control.is_none(), "{:?}", ego.control);
            assert!(
                ego.hint.as_deref().unwrap().contains("ended"),
                "{:?}",
                ego.hint
            );
            assert!(
                ego.warnings[0].contains("cannot start"),
                "{:?}",
                ego.warnings
            );

            let chrome = launch_at(
                &ctx,
                BrowserKind::Chrome,
                &dies,
                LaunchRequest {
                    agent: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            assert!(chrome.control.is_none());
            assert!(chrome.hint.as_deref().unwrap().contains("ended"));
        }

        // Asking again is refused while the browser runs, so the hint has to say what
        // actually works, not just "open again".
        #[tokio::test]
        async fn the_hint_states_what_getting_control_takes() {
            let fixture = Fixture::new();
            let exe = fixture.open_browser("");

            let plain = launch_at(
                &fixture.ctx(),
                BrowserKind::Edge,
                &exe,
                LaunchRequest::default(),
            )
            .await
            .unwrap();
            let hint = plain.hint.unwrap();
            assert!(hint.contains("quit") && hint.contains("fresh"), "{hint}");

            // The advice must be true: opening again with agent really is refused.
            let again = launch_at(
                &fixture.ctx(),
                BrowserKind::Edge,
                &exe,
                LaunchRequest {
                    agent: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(
                matches!(again, Err(LaunchError::AlreadyRunning { .. })),
                "{again:?}"
            );

            // ...and the fresh alternative it names really works.
            let fresh = launch_at(
                &fixture.ctx(),
                BrowserKind::Edge,
                &exe,
                LaunchRequest {
                    agent: true,
                    fresh: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(fresh.is_ok(), "{fresh:?}");
        }

        // A plain open of a browser an earlier agent open gave a port is not the same
        // case as one with no port, and the hint must not claim otherwise.
        #[tokio::test]
        async fn a_plain_open_of_a_browser_that_already_has_a_port_says_so() {
            let fixture = Fixture::new();
            let exe = fixture.open_browser(
                "for a in \"$@\"; do case \"$a\" in --user-data-dir=*) d=\"${a#--user-data-dir=}\";; esac; done\n\
                 printf '4242\\n/devtools/browser/x\\n' > \"$d/DevToolsActivePort\"",
            );
            let with_agent = launch_at(
                &fixture.ctx(),
                BrowserKind::Brave,
                &exe,
                LaunchRequest {
                    agent: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            assert!(with_agent.control.is_some());

            let plain = launch_at(
                &fixture.ctx(),
                BrowserKind::Brave,
                &exe,
                LaunchRequest::default(),
            )
            .await
            .unwrap();
            assert!(plain.reused && plain.control.is_none());
            let hint = plain.hint.unwrap();
            assert!(hint.contains("already has a DevTools port"), "{hint}");
        }

        #[test]
        fn a_record_written_under_the_earlier_field_name_still_reads() {
            let fixture = Fixture::new();
            let profile = fixture.profile("chrome");
            fs::create_dir_all(&profile).unwrap();
            fs::write(
                profile.join(OWNER_FILE),
                r#"{"pid":4242,"exe":"/x","proxy":"127.0.0.1:1","debug_port":true}"#,
            )
            .unwrap();
            let owner = read_owner(&profile).expect("the old field name is still understood");
            assert!(owner.devtools_port);
        }

        // ego is always given a name of its own and `agent` changes nothing for it:
        // there is no port to open. An agent is handed the same `control` either way.
        #[tokio::test]
        async fn ego_always_gets_a_name_of_its_own_and_agent_changes_nothing() {
            let fixture = Fixture::new();
            let out = fixture.dir.join("ego-argv.txt");
            let exe = fixture.open_browser(&recording_script(&out));

            let launched = launch_at(
                &fixture.ctx(),
                BrowserKind::Ego,
                &exe,
                LaunchRequest::default(),
            )
            .await
            .unwrap();
            assert_eq!(launched.driver, Driver::EgoCli);
            let expected = Driver::EgoCli
                .server_name(18890, &fixture.profile("ego"))
                .unwrap();
            assert!(wait_for(&out)
                .await
                .contains(&format!("--ego-server-name={expected}")));
            assert!(
                matches!(&launched.control, Some(Control::EgoCli { server_name, command })
                    if *server_name == expected
                        && command.contains(&format!("--ego-server-name={expected}"))),
                "{:?}",
                launched.control
            );
            assert!(launched.hint.is_none(), "control is already there");

            let with_agent = launch_at(
                &fixture.ctx(),
                BrowserKind::Ego,
                &exe,
                LaunchRequest {
                    agent: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            assert!(
                with_agent.reused,
                "same settings, so another window in the same ego"
            );
            assert!(matches!(with_agent.control, Some(Control::EgoCli { .. })));
        }

        // The DevTools port hands over the browser's sessions, and a proxy that
        // listens beyond loopback relays requests to local ports. The check sits
        // with the driver, which is what knows whether a port is opened.
        #[tokio::test]
        async fn a_devtools_port_is_withheld_while_the_proxy_listens_beyond_loopback() {
            let fixture = Fixture::new();
            let exe = fixture.open_browser("");
            let network = fixture.build(
                "0.0.0.0:18890",
                Duration::from_secs(5),
                Duration::from_millis(50),
            );

            let refused = launch_at(
                &network,
                BrowserKind::Chrome,
                &exe,
                LaunchRequest {
                    agent: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(
                matches!(refused, Err(LaunchError::Forbidden(_))),
                "{refused:?}"
            );

            // No port is involved without an agent, or for a driver with no port.
            let plain =
                launch_at(&network, BrowserKind::Edge, &exe, LaunchRequest::default()).await;
            assert!(plain.is_ok(), "{plain:?}");
            let ego = launch_at(
                &network,
                BrowserKind::Ego,
                &exe,
                LaunchRequest {
                    agent: true,
                    ..Default::default()
                },
            )
            .await;
            assert!(ego.is_ok(), "{ego:?}");
            assert!(
                !fixture.profile("chrome").exists(),
                "nothing was started for the refused one"
            );
        }

        #[tokio::test]
        async fn a_missing_executable_is_reported_not_panicked() {
            let fixture = Fixture::new();
            let missing = fixture.dir.join("does-not-exist");
            let result = launch_at(
                &fixture.ctx(),
                BrowserKind::Chrome,
                &missing,
                LaunchRequest::default(),
            )
            .await;
            assert!(matches!(result, Err(LaunchError::Failed(_))), "{result:?}");
        }
    }
}
