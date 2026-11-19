//! Proxy ports that each record into one session, whichever session the main
//! listener records into. The reasoning is in
//! `docs/superpowers/specs/2026-11-19-session-proxy-ports-design.md`.

use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::session::SessionContext;

/// The first number given. Not the numbers beside 8080: dev servers and other
/// proxy tools already listen there, and a session port among them would be
/// taken for one of them.
pub const FIRST_PORT: u16 = 18081;

/// Which number each session holds. A number is given once: a session keeps
/// it until the session is deleted, and `last` keeps a deleted session's from
/// being given to another, so a client left pointing at a port reaches its own
/// session or nothing.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct Numbers {
    last: u16,
    sessions: BTreeMap<Uuid, u16>,
}

impl Numbers {
    /// A missing file holds no numbers. One that cannot be read is an error:
    /// without it nobody knows which numbers are taken.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default())
            }
            Err(error) => {
                return Err(error).with_context(|| format!("failed to read {}", path.display()))
            }
        };
        let mut numbers: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let highest = numbers.sessions.values().copied().max().unwrap_or(0);
        numbers.last = numbers.last.max(highest);
        Ok(numbers)
    }

    pub(crate) fn of(&self, session: Uuid) -> Option<u16> {
        self.sessions.get(&session).copied()
    }

    pub(crate) fn holder_of(&self, port: u16) -> Option<Uuid> {
        self.sessions
            .iter()
            .find_map(|(session, held)| (*held == port).then_some(*session))
    }

    fn held(&self) -> Vec<u16> {
        self.sessions.values().copied().collect()
    }

    /// The numbers never given yet, lowest first, none below `first`.
    pub(crate) fn candidates(&self, first: u16) -> impl Iterator<Item = u16> {
        let next = self.last.max(first.saturating_sub(1)).saturating_add(1);
        next..=u16::MAX
    }

    pub(crate) fn give(&mut self, session: Uuid, port: u16) {
        self.last = self.last.max(port);
        self.sessions.insert(session, port);
    }

    /// The session's number, which no session gets again.
    pub(crate) fn forget(&mut self, session: Uuid) -> Option<u16> {
        self.sessions.remove(&session)
    }
}

/// The addresses Sniper itself listens on, kept in one place for every guard
/// against a connection that leads back into Sniper: the UI, the main proxy
/// listener and each open session port, and the numbers sessions keep for
/// ports that are closed now. A port that opens later is known to all of them
/// at once, also to the checks a session makes without the state at hand.
#[derive(Clone, Default)]
pub struct OwnListeners(Arc<std::sync::RwLock<OwnAddrs>>);

#[derive(Default)]
struct OwnAddrs {
    ui: Option<SocketAddr>,
    main: Option<SocketAddr>,
    session_ports: Vec<SocketAddr>,
    held: Vec<u16>,
}

impl OwnListeners {
    fn read(&self) -> std::sync::RwLockReadGuard<'_, OwnAddrs> {
        self.0.read().unwrap_or_else(|error| error.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, OwnAddrs> {
        self.0.write().unwrap_or_else(|error| error.into_inner())
    }

    pub(crate) fn set_ui(&self, addr: SocketAddr) {
        self.write().ui = Some(addr);
    }

    pub(crate) fn set_main(&self, addr: SocketAddr) {
        self.write().main = Some(addr);
    }

    /// Sniper's proxy listeners: the main one and every open session port.
    pub fn proxies(&self) -> Vec<SocketAddr> {
        let own = self.read();
        own.main
            .into_iter()
            .chain(own.session_ports.iter().copied())
            .collect()
    }

    /// Every listener of Sniper's: the UI and the proxies.
    pub fn all(&self) -> Vec<SocketAddr> {
        let ui = self.read().ui;
        ui.into_iter().chain(self.proxies()).collect()
    }

    /// Whether a session keeps this number for its port, open or not.
    pub fn keeps(&self, port: u16) -> bool {
        self.read().held.contains(&port)
    }
}

/// Why a session port, or an operation it stands in the way of, was refused.
/// The caller can clear the cause and try again, so the API answers 409.
#[derive(Debug)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

pub(crate) fn refused(reason: impl Into<String>) -> anyhow::Error {
    Refused(reason.into()).into()
}

/// A session's port as the API reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionPortStatus {
    pub session_id: Uuid,
    /// The number the session holds until it is deleted, open or not.
    pub proxy_port: Option<u16>,
    /// Where a client connects while the port is open.
    pub proxy_addr: Option<String>,
    pub open: bool,
}

/// At most this many ports are open at once. Each keeps its session loaded.
pub const MAX_OPEN: usize = crate::tcp_capture::MAX_LISTENERS;

const NUMBERS_FILE: &str = "session-ports.json";

pub(crate) fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// An open port: where it listens, the task that accepts on it, and the one
/// writable context of its session. Requests on the port use that context
/// directly, so no lookup can hand them another.
struct OpenPort {
    addr: SocketAddr,
    session: Arc<SessionContext>,
    accept: JoinHandle<()>,
}

struct Inner {
    /// Why the saved numbers could not be read, when they could not. Ports
    /// then stay closed, because nobody knows which numbers are taken.
    numbers: std::result::Result<Numbers, String>,
    open: HashMap<Uuid, OpenPort>,
    /// The ports a shutdown stopped, with the context each held, so a
    /// shutdown that does not go through can open them again.
    suspended: Vec<(Arc<SessionContext>, SocketAddr)>,
}

/// The session ports of one Sniper: the saved numbers and what is open now.
/// Opening and closing are serialized by `AppState`, under its activation lock.
pub(crate) struct SessionPorts {
    path: PathBuf,
    /// One writer of the numbers file at a time. The write runs off the
    /// runtime, so the registry's own lock cannot be held across it.
    numbers_write: tokio::sync::Mutex<()>,
    inner: Mutex<Inner>,
    /// What the guards read. Every change to the open ports and the kept
    /// numbers is copied into it here, so none can be forgotten.
    own: OwnListeners,
    #[cfg(test)]
    test_first_port: std::sync::OnceLock<u16>,
}

impl SessionPorts {
    pub(crate) fn load(data_dir: &Path, own: OwnListeners) -> Self {
        let path = data_dir.join(NUMBERS_FILE);
        let numbers = Numbers::load(&path).map_err(|error| format!("{error:#}"));
        match &numbers {
            Ok(numbers) => own.write().held = numbers.held(),
            Err(error) => {
                tracing::warn!(%error, "session ports stay closed until the numbers file is readable")
            }
        }
        Self {
            path,
            numbers_write: tokio::sync::Mutex::new(()),
            inner: Mutex::new(Inner {
                numbers,
                open: HashMap::new(),
                suspended: Vec::new(),
            }),
            own,
            #[cfg(test)]
            test_first_port: std::sync::OnceLock::new(),
        }
    }

    /// The first number this Sniper gives.
    #[cfg(not(test))]
    pub(crate) fn first_port(&self) -> u16 {
        FIRST_PORT
    }

    /// Tests run side by side, each with a state of its own. One must not take
    /// the number another is about to open again, nor a number of a Sniper
    /// that runs on the same machine, so each state that opens a port gets a
    /// range of its own.
    #[cfg(test)]
    pub(crate) fn first_port(&self) -> u16 {
        static NEXT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
        *self.test_first_port.get_or_init(|| {
            20_000 + (NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 300) * 40
        })
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|error| error.into_inner())
    }

    pub(crate) fn numbers(&self) -> Result<Numbers> {
        self.inner()
            .numbers
            .clone()
            .map_err(|error| anyhow::anyhow!(error))
    }

    /// The context requests on the session's port are recorded into.
    pub(crate) fn context(&self, session: Uuid) -> Option<Arc<SessionContext>> {
        self.inner()
            .open
            .get(&session)
            .map(|port| port.session.clone())
    }

    pub(crate) fn addr(&self, session: Uuid) -> Option<SocketAddr> {
        self.inner().open.get(&session).map(|port| port.addr)
    }

    pub(crate) fn is_open(&self, session: Uuid) -> bool {
        self.inner().open.contains_key(&session)
    }

    pub(crate) fn open_count(&self) -> usize {
        self.inner().open.len()
    }

    /// The session's port as the API reports it, open or not.
    pub(crate) fn status(&self, session: Uuid) -> SessionPortStatus {
        let inner = self.inner();
        let addr = inner.open.get(&session).map(|port| port.addr);
        SessionPortStatus {
            session_id: session,
            proxy_port: addr.map(|addr| addr.port()).or_else(|| {
                inner
                    .numbers
                    .as_ref()
                    .ok()
                    .and_then(|numbers| numbers.of(session))
            }),
            proxy_addr: addr.map(|addr| addr.to_string()),
            open: addr.is_some(),
        }
    }

    pub(crate) fn register(
        &self,
        session: Arc<SessionContext>,
        addr: SocketAddr,
        accept: JoinHandle<()>,
    ) {
        let mut inner = self.inner();
        let replaced = inner.open.insert(
            session.id(),
            OpenPort {
                addr,
                session,
                accept,
            },
        );
        debug_assert!(replaced.is_none(), "a session has one port");
        if let Some(replaced) = replaced {
            replaced.accept.abort();
        }
        self.own.write().session_ports = open_addrs(&inner);
    }

    /// Stops the port from accepting and forgets it. The listener is closed
    /// when this returns, so the number can be bound again.
    pub(crate) async fn unregister(&self, session: Uuid) -> Option<SocketAddr> {
        let port = {
            let mut inner = self.inner();
            let port = inner.open.remove(&session)?;
            self.own.write().session_ports = open_addrs(&inner);
            port
        };
        port.accept.abort();
        let _ = port.accept.await;
        Some(port.addr)
    }

    /// Stops every open port from accepting and remembers each, for a
    /// shutdown that may yet be cancelled. Their connections are left for the
    /// shutdown to drain.
    pub(crate) async fn suspend_all(&self) {
        let ports: Vec<OpenPort> = {
            let mut inner = self.inner();
            let ports = inner.open.drain().map(|(_, port)| port).collect();
            self.own.write().session_ports.clear();
            ports
        };
        for port in ports {
            port.accept.abort();
            let _ = port.accept.await;
            self.inner().suspended.push((port.session, port.addr));
        }
    }

    /// The sessions whose ports a shutdown stopped.
    pub(crate) fn suspended_sessions(&self) -> Vec<Arc<SessionContext>> {
        self.inner()
            .suspended
            .iter()
            .map(|(session, _)| session.clone())
            .collect()
    }

    /// The ports a shutdown stopped, for opening them again.
    pub(crate) fn take_suspended(&self) -> Vec<(Arc<SessionContext>, SocketAddr)> {
        std::mem::take(&mut self.inner().suspended)
    }

    /// Saves a change to the numbers and only then makes it visible, so a
    /// number that was not saved is never in use.
    async fn change_numbers(&self, change: impl FnOnce(&mut Numbers) -> bool) -> Result<()> {
        let _writer = self.numbers_write.lock().await;
        let mut numbers = self.numbers()?;
        if !change(&mut numbers) {
            return Ok(());
        }
        let path = self.path.clone();
        let saved = numbers.clone();
        tokio::task::spawn_blocking(move || crate::session::write_json(&path, &saved))
            .await
            .context("session port number writer panicked")?
            .with_context(|| format!("failed to save {}", self.path.display()))?;
        self.own.write().held = numbers.held();
        self.inner().numbers = Ok(numbers);
        Ok(())
    }

    /// Takes `port` from the session that keeps it, when the main listener
    /// was started there, and says which session that was.
    pub(crate) async fn release(&self, port: u16) -> Result<Option<Uuid>> {
        let Some(session) = self.numbers()?.holder_of(port) else {
            return Ok(None);
        };
        self.forget(session).await?;
        Ok(Some(session))
    }

    pub(crate) async fn give(&self, session: Uuid, port: u16) -> Result<()> {
        self.change_numbers(|numbers| {
            numbers.give(session, port);
            true
        })
        .await
    }

    /// Forgets a deleted session's number. No session gets it again.
    pub(crate) async fn forget(&self, session: Uuid) -> Result<()> {
        self.change_numbers(|numbers| numbers.forget(session).is_some())
            .await
    }
}

/// The open ports' addresses, lowest number first so the list reads the same
/// each time.
fn open_addrs(inner: &Inner) -> Vec<SocketAddr> {
    let mut addrs: Vec<_> = inner.open.values().map(|port| port.addr).collect();
    addrs.sort();
    addrs
}

/// Whether something accepts a connection on `addr` now.
async fn answers(addr: SocketAddr) -> bool {
    // A listener on this machine accepts at once. Windows takes seconds to
    // refuse a port nobody listens on, so no answer in time is "nobody".
    matches!(
        tokio::time::timeout(Duration::from_millis(250), TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

fn bind(addr: SocketAddr, reuse: bool) -> std::io::Result<TcpListener> {
    let socket = if addr.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    socket.set_reuseaddr(reuse)?;
    socket.bind(addr)?;
    socket.listen(1024)
}

/// Binds a listener that nothing else answers on.
///
/// `SO_REUSEADDR` lets a loopback bind succeed on macOS beside another
/// program's listener on every interface, and it then takes that program's
/// loopback traffic. So the bind is made without the option, and an address
/// something already answers on is refused. Without the option a port also
/// stays taken while its last connections wait out their close. Only then,
/// with nothing answering, is the option used, so a port that was closed opens
/// again at once.
// ponytail: a listener that starts between the second probe and the bind is
// not seen. Closing that takes the platform's own exclusive-bind option.
pub(crate) async fn bind_exclusive(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let taken = || std::io::Error::from(std::io::ErrorKind::AddrInUse);
    if answers(addr).await {
        return Err(taken());
    }
    match bind(addr, false) {
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            if answers(addr).await {
                return Err(taken());
            }
            bind(addr, true)
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::state::AppState;
    use crate::store::ListFilters;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("sniper-session-ports-{name}-{}", Uuid::new_v4()))
    }

    fn state_in(data_dir: &Path) -> Arc<AppState> {
        Arc::new(
            AppState::new(AppConfig {
                proxy_addr: "127.0.0.1:0".parse().unwrap(),
                ui_addr: "127.0.0.1:0".parse().unwrap(),
                max_entries: 100,
                max_transaction_entries: 100,
                body_preview_bytes: 4096,
                data_dir: data_dir.to_path_buf(),
            })
            .unwrap(),
        )
    }

    /// A loopback server that answers every request with `ok`.
    async fn upstream() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = [0u8; 2048];
                    let _ = stream.read(&mut request).await;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                });
            }
        });
        addr
    }

    /// The status line of one request sent to `upstream` through `proxy`.
    async fn get_through(proxy: SocketAddr, upstream: SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        let request = format!(
            "GET http://{upstream}{path} HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    }

    /// The paths a session recorded, once it holds `count` of them.
    async fn recorded(session: &SessionContext, count: usize) -> Vec<String> {
        for _ in 0..250 {
            let list = session.store.list(&ListFilters::default()).await;
            if list.len() >= count {
                let mut paths: Vec<_> = list.into_iter().map(|record| record.path).collect();
                paths.sort();
                return paths;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the session never recorded {count} request(s)");
    }

    /// A loopback server that sends back whatever it receives.
    async fn echo_upstream() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        addr
    }

    /// A CONNECT tunnel to `target` through `proxy`, ready for bytes.
    async fn open_tunnel(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        stream
            .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        assert!(String::from_utf8_lossy(&head).contains(" 200"), "{head:?}");
        stream
    }

    /// Whether bytes that are neither TLS nor HTTP come back through the tunnel.
    async fn echoes(tunnel: &mut TcpStream, bytes: &[u8]) -> bool {
        if tunnel.write_all(bytes).await.is_err() {
            return false;
        }
        let mut back = vec![0; bytes.len()];
        let read = tokio::time::timeout(Duration::from_secs(5), tunnel.read_exact(&mut back));
        matches!(read.await, Ok(Ok(_))) && back == bytes
    }

    async fn inactive_session(state: &AppState, name: &str) -> Uuid {
        state
            .create_inactive_session(Some(name.to_string()))
            .await
            .unwrap()
            .id
    }

    fn port_addr(status: &SessionPortStatus) -> SocketAddr {
        status.proxy_addr.as_deref().unwrap().parse().unwrap()
    }

    #[tokio::test]
    async fn a_session_port_records_into_its_session_whichever_is_active() {
        let _work = crate::proxy::GLOBAL_PROXY_WORK_TEST_LOCK.lock().await;
        let dir = scratch("records");
        let state = state_in(&dir);
        let default = state.session().await;
        let agent = inactive_session(&state, "agent").await;
        let main = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let main_addr = main.local_addr().unwrap();
        let main_task = tokio::spawn(crate::proxy::serve_proxy(main, state.clone()));
        let upstream = upstream().await;

        let status = state.open_session_port(agent).await.unwrap();
        assert!(status.open);
        assert!(status.proxy_port.unwrap() >= FIRST_PORT);
        let port = port_addr(&status);
        assert!(port.ip().is_loopback());

        assert!(get_through(port, upstream, "/agent").await.contains("200"));
        assert!(get_through(main_addr, upstream, "/main")
            .await
            .contains("200"));

        let agent_session = state.session_context_for_id(agent).await.unwrap();
        assert_eq!(recorded(&agent_session, 1).await, ["/agent"]);
        assert_eq!(recorded(&default, 1).await, ["/main"]);
        assert_eq!(state.session().await.id(), default.id());

        state.close_session_port(agent).await.unwrap();
        main_task.abort();
        let _ = std::fs::remove_dir_all(dir);
    }

    // A second writable context on one session directory shows another
    // request's body with no error, so the port must hold the very context
    // every other caller gets.
    #[tokio::test]
    async fn a_port_holds_the_sessions_one_writable_context() {
        let dir = scratch("one-context");
        let state = state_in(&dir);
        let first = state.session().await.id();

        // Never switched to since start-up.
        let never = inactive_session(&state, "never active").await;
        state.open_session_port(never).await.unwrap();
        let held = state.session_port_context(never).unwrap();
        assert!(Arc::ptr_eq(
            &held,
            &state.session_context_for_id(never).await.unwrap()
        ));

        // The session Sniper started on, after the main listener left it.
        let second = state
            .create_session(Some("second".into()))
            .await
            .unwrap()
            .id;
        state.open_session_port(first).await.unwrap();
        assert!(Arc::ptr_eq(
            &state.session_port_context(first).unwrap(),
            &state.session_context_for_id(first).await.unwrap()
        ));

        // One that was the default and is not any more.
        state.create_session(Some("third".into())).await.unwrap();
        state.open_session_port(second).await.unwrap();
        assert!(Arc::ptr_eq(
            &state.session_port_context(second).unwrap(),
            &state.session_context_for_id(second).await.unwrap()
        ));

        // A workspace write must not replace it.
        let snapshot = held.workspace.snapshot().await;
        state
            .replace_workspace_state_and_persist(&held, snapshot)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(
            &held,
            &state.session_context_for_id(never).await.unwrap()
        ));
        assert!(Arc::ptr_eq(
            &held,
            &state.session_port_context(never).unwrap()
        ));

        for id in [never, first, second] {
            state.close_session_port(id).await.unwrap();
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    // A workspace save through a context other than the cached one replaces
    // the cached one. For a session with a port that would leave the port
    // recording into a context nobody else gets: a second writable context.
    #[tokio::test]
    async fn a_workspace_save_through_another_context_does_not_replace_the_ports() {
        let dir = scratch("stale-workspace");
        let state = state_in(&dir);
        let agent = inactive_session(&state, "agent").await;
        state.open_session_port(agent).await.unwrap();
        let held = state.session_port_context(agent).unwrap();
        let other = state.sessions.load_context_read_only(agent).unwrap();
        let snapshot = other.workspace.snapshot().await;

        let saved = state
            .replace_workspace_state_and_persist(&other, snapshot)
            .await;

        assert!(saved.is_err());
        assert!(Arc::ptr_eq(
            &held,
            &state.session_context_for_id(agent).await.unwrap()
        ));
        state.close_session_port(agent).await.unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn opening_a_port_twice_returns_the_open_port() {
        let dir = scratch("twice");
        let state = state_in(&dir);
        let agent = inactive_session(&state, "agent").await;

        let first = state.open_session_port(agent).await.unwrap();
        let second = state.open_session_port(agent).await.unwrap();

        assert_eq!(first, second);
        assert_eq!(state.session_port_status(agent), first);
        state.close_session_port(agent).await.unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn the_session_the_main_listener_records_into_gets_no_port() {
        let dir = scratch("default");
        let state = state_in(&dir);
        let default = state.session().await.id();

        let error = state.open_session_port(default).await.unwrap_err();

        assert!(error.is::<Refused>(), "{error:#}");
        assert!(!state.session_port_status(default).open);
        assert_eq!(state.session_port_status(default).proxy_port, None);
        assert!(!dir.join(NUMBERS_FILE).exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_session_that_does_not_exist_gets_no_port() {
        let dir = scratch("missing-session");
        let state = state_in(&dir);

        let error = state.open_session_port(Uuid::new_v4()).await.unwrap_err();

        assert!(error.to_string().contains("was not found"), "{error:#}");
        assert!(!error.is::<Refused>());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn no_more_ports_open_than_the_limit() {
        let dir = scratch("limit");
        let state = state_in(&dir);
        let mut open = Vec::new();
        for index in 0..MAX_OPEN {
            let id = inactive_session(&state, &format!("agent {index}")).await;
            state.open_session_port(id).await.unwrap();
            open.push(id);
        }
        let extra = inactive_session(&state, "one too many").await;

        let error = state.open_session_port(extra).await.unwrap_err();
        assert!(error.is::<Refused>(), "{error:#}");
        assert_eq!(state.session_port_status(extra).proxy_port, None);

        state.close_session_port(open[0]).await.unwrap();
        assert!(state.open_session_port(extra).await.unwrap().open);

        for id in open.into_iter().skip(1).chain([extra]) {
            state.close_session_port(id).await.unwrap();
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_closed_port_refuses_connections_and_keeps_its_number() {
        let _work = crate::proxy::GLOBAL_PROXY_WORK_TEST_LOCK.lock().await;
        let dir = scratch("close");
        let state = state_in(&dir);
        let agent = inactive_session(&state, "agent").await;
        let upstream = upstream().await;
        let opened = state.open_session_port(agent).await.unwrap();
        let addr = port_addr(&opened);
        assert!(get_through(addr, upstream, "/before").await.contains("200"));

        let closed = state.close_session_port(agent).await.unwrap();

        assert!(!closed.open);
        assert_eq!(closed.proxy_port, opened.proxy_port);
        assert_eq!(closed.proxy_addr, None);
        assert!(TcpStream::connect(addr).await.is_err());
        assert_eq!(state.session_port_context(agent).map(|_| ()), None);
        // Closing again changes nothing.
        assert_eq!(state.close_session_port(agent).await.unwrap(), closed);

        let reopened = state.open_session_port(agent).await.unwrap();
        assert_eq!(reopened, opened);
        assert!(get_through(addr, upstream, "/after").await.contains("200"));
        let session = state.session_context_for_id(agent).await.unwrap();
        assert_eq!(recorded(&session, 2).await, ["/after", "/before"]);

        state.close_session_port(agent).await.unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_number_is_never_given_to_another_session() {
        let dir = scratch("never-reused");
        let state = state_in(&dir);
        let first = inactive_session(&state, "first").await;
        let second = inactive_session(&state, "second").await;
        let first_port = state.open_session_port(first).await.unwrap().proxy_port;
        let second_port = state.open_session_port(second).await.unwrap().proxy_port;
        assert_ne!(first_port, second_port);

        state.close_session_port(first).await.unwrap();
        state.delete_session(first).await.unwrap();
        let third = inactive_session(&state, "third").await;
        let third_port = state.open_session_port(third).await.unwrap().proxy_port;
        assert!(third_port > first_port.max(second_port));
        state.close_session_port(second).await.unwrap();
        state.close_session_port(third).await.unwrap();
        drop(state);

        // After a restart nothing is open, and every session has its number.
        let restarted = state_in(&dir);
        assert!(!restarted.session_port_status(second).open);
        assert_eq!(
            restarted.session_port_status(second).proxy_port,
            second_port
        );
        assert_eq!(
            restarted.open_session_port(third).await.unwrap().proxy_port,
            third_port
        );
        let fourth = inactive_session(&restarted, "fourth").await;
        let fourth_port = restarted
            .open_session_port(fourth)
            .await
            .unwrap()
            .proxy_port;
        assert!(fourth_port > third_port);
        restarted.close_session_port(third).await.unwrap();
        restarted.close_session_port(fourth).await.unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn an_unreadable_numbers_file_keeps_ports_closed_and_nothing_else() {
        let dir = scratch("unreadable-state");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(NUMBERS_FILE), b"not json").unwrap();
        let state = state_in(&dir);
        let agent = inactive_session(&state, "agent").await;

        let error = state.open_session_port(agent).await.unwrap_err();

        assert!(format!("{error:#}").contains(NUMBERS_FILE), "{error:#}");
        assert!(!state.session_port_status(agent).open);
        assert_eq!(std::fs::read(dir.join(NUMBERS_FILE)).unwrap(), b"not json");
        state.activate_session(agent).await.unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    // One feed for each session: a switch then never has a session port's
    // work to wait for or to cut.
    #[tokio::test]
    async fn a_session_with_an_open_port_does_not_become_the_default() {
        let dir = scratch("no-activate");
        let state = state_in(&dir);
        let default = state.session().await.id();
        let agent = inactive_session(&state, "agent").await;
        let opened = state.open_session_port(agent).await.unwrap();

        let error = state.activate_session(agent).await.unwrap_err();

        assert!(error.is::<Refused>(), "{error:#}");
        assert_eq!(state.session().await.id(), default);
        assert_eq!(state.sessions.active_session_id(), default);
        assert_eq!(state.session_port_status(agent), opened);

        state.close_session_port(agent).await.unwrap();
        assert!(state.activate_session(agent).await.unwrap().active);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_session_with_an_open_port_is_not_deleted() {
        let dir = scratch("no-delete");
        let state = state_in(&dir);
        let agent = inactive_session(&state, "agent").await;
        let opened = state.open_session_port(agent).await.unwrap();

        let error = state.delete_session(agent).await.unwrap_err();

        assert!(error.is::<Refused>(), "{error:#}");
        assert!(
            error.to_string().contains("close its port first"),
            "{error:#}"
        );
        assert!(state.sessions.contains_session(agent));
        assert_eq!(state.session_port_status(agent), opened);

        state.close_session_port(agent).await.unwrap();
        state.delete_session(agent).await.unwrap();
        assert_eq!(state.session_port_status(agent).proxy_port, None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_tunnel_on_a_session_port_survives_a_switch_of_the_main_listener() {
        let _work = crate::proxy::GLOBAL_PROXY_WORK_TEST_LOCK.lock().await;
        let dir = scratch("tunnel-switch");
        let state = state_in(&dir);
        let agent = inactive_session(&state, "agent").await;
        let other = inactive_session(&state, "other").await;
        let port = port_addr(&state.open_session_port(agent).await.unwrap());
        let mut tunnel = open_tunnel(port, echo_upstream().await).await;
        assert!(echoes(&mut tunnel, b"\x00\x01before").await);

        state.activate_session(other).await.unwrap();

        assert!(echoes(&mut tunnel, b"\x00\x02after").await);
        drop(tunnel);
        state.close_session_port(agent).await.unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    // Every guard against a connection that leads back into Sniper reads one
    // list, so a port that opens later is known to all of them at once.
    #[tokio::test]
    async fn every_guard_learns_of_a_session_port_when_it_opens() {
        let dir = scratch("own-listeners");
        let state = state_in(&dir);
        let default = state.session().await;
        let agent = inactive_session(&state, "agent").await;
        let main: SocketAddr = "127.0.0.1:18080".parse().unwrap();
        let ui: SocketAddr = "127.0.0.1:18099".parse().unwrap();
        state.set_active_proxy_addr(main).await;
        state.set_active_ui_addr(ui).await;
        assert_eq!(state.own_listeners().proxies(), [main]);

        let port = port_addr(&state.open_session_port(agent).await.unwrap());

        assert_eq!(state.own_listeners().proxies(), [main, port]);
        assert_eq!(state.own_listeners().all(), [ui, main, port]);
        assert!(state.own_listeners().keeps(port.port()));
        assert!(
            crate::proxy::targets_own_listener(&state, &default, "http", &port.to_string()).await
        );
        // A session loaded before the port opened sees it too, in the checks
        // it makes without the state at hand.
        assert_eq!(default.runtime.own_listeners().proxies(), [main, port]);
        let chain = crate::upstream_proxy::UpstreamProxy {
            enabled: true,
            url: format!("http://{port}"),
            ..default.runtime.upstream_proxy().await
        };
        let used = chain.apply(reqwest::Client::builder()).err().unwrap();
        assert!(used.to_string().contains("own listener"), "{used:#}");
        let dialled = chain.connect("example.com", 80).await.err().unwrap();
        assert!(dialled.to_string().contains("own listener"), "{dialled:#}");

        state.close_session_port(agent).await.unwrap();

        assert_eq!(state.own_listeners().proxies(), [main]);
        // The number stays the session's while the port is closed.
        assert!(state.own_listeners().keeps(port.port()));
        assert!(
            !crate::proxy::targets_own_listener(&state, &default, "http", &port.to_string()).await
        );
        assert!(chain.apply(reqwest::Client::builder()).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    // A request whose target is one of Sniper's proxy listeners would be
    // forwarded back into Sniper, again and again.
    #[tokio::test]
    async fn a_request_for_one_of_snipers_proxy_listeners_is_refused_as_a_loop() {
        let _work = crate::proxy::GLOBAL_PROXY_WORK_TEST_LOCK.lock().await;
        let dir = scratch("loop");
        let state = state_in(&dir);
        let agent = inactive_session(&state, "agent").await;
        let main = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let main_addr = main.local_addr().unwrap();
        state.set_active_proxy_addr(main_addr).await;
        let main_task = tokio::spawn(crate::proxy::serve_proxy(main, state.clone()));
        let port = port_addr(&state.open_session_port(agent).await.unwrap());

        for (through, target) in [(main_addr, port), (port, main_addr), (port, port)] {
            let status = get_through(through, target, "/").await;
            assert!(status.contains("508"), "{through} to {target}: {status}");
        }

        state.close_session_port(agent).await.unwrap();
        main_task.abort();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn an_upstream_proxy_that_is_a_session_port_is_not_saved() {
        let dir = scratch("upstream-save");
        let state = state_in(&dir);
        let agent = inactive_session(&state, "agent").await;
        let port = port_addr(&state.open_session_port(agent).await.unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = listener.local_addr().unwrap();
        let router = crate::api::router(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await });

        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(format!("http://{api}/api/runtime"))
            .json(&serde_json::json!({
                "upstream_proxy": { "enabled": true, "url": format!("http://{port}") }
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
        assert!(response.text().await.unwrap().contains("own listener"));
        assert!(!state.session().await.runtime.upstream_proxy().await.enabled);
        server.abort();
        state.close_session_port(agent).await.unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The main listener of `state`, serving as the binaries start it.
    async fn serving_main_listener(state: &Arc<AppState>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        state.set_active_proxy_addr(addr).await;
        state.mark_proxy_listener_online();
        let served = state.clone();
        state
            .set_proxy_task(tokio::spawn(async move {
                let _ = crate::proxy::serve_proxy(listener, served).await;
            }))
            .await;
        addr
    }

    // A request Intercept holds on the port is cut with the port. Its entry
    // must not stay in the queue, where nobody could decide it any more.
    #[tokio::test]
    async fn closing_a_port_removes_the_requests_it_held() {
        let _work = crate::proxy::GLOBAL_PROXY_WORK_TEST_LOCK.lock().await;
        let dir = scratch("close-held");
        let state = state_in(&dir);
        let agent = inactive_session(&state, "agent").await;
        let port = port_addr(&state.open_session_port(agent).await.unwrap());
        let session = state.session_port_context(agent).unwrap();
        session
            .runtime
            .update(crate::runtime::RuntimeSettingsUpdate {
                intercept_enabled: Some(true),
                intercept_scope_only: Some(false),
                ..Default::default()
            })
            .await
            .unwrap();
        let upstream = upstream().await;
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(port).await.unwrap();
            let request =
                format!("GET http://{upstream}/held HTTP/1.1\r\nHost: {upstream}\r\n\r\n");
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut answer = Vec::new();
            let _ = stream.read_to_end(&mut answer).await;
            answer
        });
        for _ in 0..250 {
            if session.intercepts.held().await == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(session.intercepts.held().await, 1);

        state.close_session_port(agent).await.unwrap();

        assert_eq!(session.intercepts.held().await, 0);
        let answer = client.await.unwrap();
        assert!(!String::from_utf8_lossy(&answer).contains("200 OK"));
        // Nothing was forwarded, so nothing was recorded.
        assert!(session.store.list(&ListFilters::default()).await.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    // The API drops a request's future when its client disconnects. A close
    // left half done would be closed in the registry and still serving the
    // connections it had.
    #[tokio::test]
    async fn a_close_whose_caller_goes_away_still_finishes() {
        let _work = crate::proxy::GLOBAL_PROXY_WORK_TEST_LOCK.lock().await;
        let dir = scratch("close-cancelled");
        let state = state_in(&dir);
        let agent = inactive_session(&state, "agent").await;
        let port = port_addr(&state.open_session_port(agent).await.unwrap());
        let session = state.session_port_context(agent).unwrap();
        session
            .runtime
            .update(crate::runtime::RuntimeSettingsUpdate {
                intercept_enabled: Some(true),
                intercept_scope_only: Some(false),
                ..Default::default()
            })
            .await
            .unwrap();
        let upstream = upstream().await;
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(port).await.unwrap();
            let request =
                format!("GET http://{upstream}/held HTTP/1.1\r\nHost: {upstream}\r\n\r\n");
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut answer = Vec::new();
            let _ = stream.read_to_end(&mut answer).await;
        });
        for _ in 0..250 {
            if session.intercepts.held().await == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(session.intercepts.held().await, 1);

        // The close waits for the held request; its caller leaves meanwhile.
        let closing = tokio::spawn({
            let state = state.clone();
            async move { state.close_session_port(agent).await }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        closing.abort();
        let _ = closing.await;

        // A delete waits for the close to finish, and then goes through.
        state.delete_session(agent).await.unwrap();
        assert_eq!(session.intercepts.held().await, 0);
        tokio::time::timeout(Duration::from_secs(5), client)
            .await
            .expect("the held request's connection was cut")
            .unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_tunnel_on_a_session_port_survives_a_rebind_of_the_main_listener() {
        let _work = crate::proxy::GLOBAL_PROXY_WORK_TEST_LOCK.lock().await;
        let dir = scratch("tunnel-rebind");
        let state = state_in(&dir);
        let agent = inactive_session(&state, "agent").await;
        let main = serving_main_listener(&state).await;
        let port = port_addr(&state.open_session_port(agent).await.unwrap());
        let mut tunnel = open_tunnel(port, echo_upstream().await).await;
        assert!(echoes(&mut tunnel, b"\x00\x01before").await);
        let free = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let moved_to = free.local_addr().unwrap();
        drop(free);

        crate::proxy::rebind_proxy(state.clone(), moved_to)
            .await
            .unwrap();

        assert_eq!(state.get_active_proxy_addr().await, moved_to);
        assert!(TcpStream::connect(main).await.is_err());
        assert!(echoes(&mut tunnel, b"\x00\x02after").await);
        drop(tunnel);
        state.close_session_port(agent).await.unwrap();
        state.abort_proxy_task().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    // A shutdown that does not go through must leave Sniper as it was: three
    // places stopped the listeners and then carried on without them.
    #[tokio::test]
    async fn a_cancelled_shutdown_brings_every_listener_back() {
        let _work = crate::proxy::GLOBAL_PROXY_WORK_TEST_LOCK.lock().await;
        let dir = scratch("resume");
        let state = state_in(&dir);
        let agent = inactive_session(&state, "agent").await;
        let main = serving_main_listener(&state).await;
        let opened = state.open_session_port(agent).await.unwrap();
        let port = port_addr(&opened);
        let held = state.session_port_context(agent).unwrap();
        let upstream = upstream().await;

        state.stop_background_jobs().await.unwrap();
        state.stop_proxy_listeners().await;

        assert!(TcpStream::connect(port).await.is_err());
        assert!(TcpStream::connect(main).await.is_err());
        assert!(!state.session_port_status(agent).open);
        // Nothing opens while Sniper is on its way out.
        let error = state.open_session_port(agent).await.unwrap_err();
        assert!(error.is::<Refused>(), "{error:#}");

        state.resume_after_cancelled_shutdown().await;

        assert_eq!(state.session_port_status(agent), opened);
        assert!(Arc::ptr_eq(
            &held,
            &state.session_port_context(agent).unwrap()
        ));
        assert!(get_through(port, upstream, "/port").await.contains("200"));
        assert!(get_through(main, upstream, "/main").await.contains("200"));
        assert!(state.is_proxy_online());
        assert_eq!(recorded(&held, 1).await, ["/port"]);

        // A port whose session was deleted meanwhile stays closed.
        state.stop_proxy_listeners().await;
        state.delete_session(agent).await.unwrap();
        state.resume_after_cancelled_shutdown().await;
        assert!(TcpStream::connect(port).await.is_err());
        assert!(get_through(main, upstream, "/again").await.contains("200"));

        state.abort_proxy_task().await;
        let _ = std::fs::remove_dir_all(dir);
    }

    // The session the main listener records into is saved in full at exit.
    // A session a port fed must not lose what only its memory held.
    #[tokio::test]
    async fn a_shutdown_saves_the_sessions_that_ports_fed() {
        let dir = scratch("shutdown-save");
        let state = state_in(&dir);
        let agent = inactive_session(&state, "agent").await;
        state.open_session_port(agent).await.unwrap();
        let session = state.session_port_context(agent).unwrap();
        session
            .event_log
            .push(
                crate::event_log::EventLevel::Info,
                "test",
                "Kept across the restart",
                "",
            )
            .await;

        state.stop_proxy_listeners().await;
        state.persist_session_port_sessions().await.unwrap();

        let saved = state.sessions.load_context_read_only(agent).unwrap();
        let events = saved.event_log.snapshot(None).await;
        assert!(
            events
                .iter()
                .any(|event| event.title == "Kept across the restart"),
            "{events:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A session that keeps a number while its port is closed.
    async fn session_keeping_a_number(state: &AppState) -> (Uuid, u16) {
        let session = inactive_session(state, "keeps a number").await;
        let port = state
            .open_session_port(session)
            .await
            .unwrap()
            .proxy_port
            .unwrap();
        state.close_session_port(session).await.unwrap();
        (session, port)
    }

    // A client left pointing at a session's number must reach that session or
    // nothing, so nothing else of Sniper's is started on it.
    #[tokio::test]
    async fn the_main_listener_is_not_moved_onto_a_number_a_session_keeps() {
        let _work = crate::proxy::GLOBAL_PROXY_WORK_TEST_LOCK.lock().await;
        let dir = scratch("main-held");
        let state = state_in(&dir);
        let (session, port) = session_keeping_a_number(&state).await;
        let before = state.get_active_proxy_addr().await;
        let saved = state.startup.snapshot().await.proxy_port;

        let error = crate::proxy::rebind_proxy(state.clone(), loopback(port))
            .await
            .unwrap_err();
        assert!(error.contains("session"), "{error}");
        assert_eq!(state.get_active_proxy_addr().await, before);

        // The setting is refused before it is saved.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = listener.local_addr().unwrap();
        let router = crate::api::router(state.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(format!("http://{api}/api/startup-settings"))
            .json(&serde_json::json!({ "proxy_port": port }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
        assert!(response.text().await.unwrap().contains("session"));
        assert_eq!(state.startup.snapshot().await.proxy_port, saved);
        assert_eq!(state.session_port_status(session).proxy_port, Some(port));
        server.abort();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_tcp_relay_listener_does_not_start_on_a_number_a_session_keeps() {
        let dir = scratch("tcp-held");
        let state = state_in(&dir);
        let (_session, port) = session_keeping_a_number(&state).await;
        let target = echo_upstream().await;
        let listener = |protocol| crate::tcp_capture::TcpListenerInput {
            enabled: true,
            settings: crate::tcp_capture::TcpSettings {
                local_port: port,
                target_host: "127.0.0.1".into(),
                target_port: target.port(),
                protocol,
                ..Default::default()
            },
        };
        let capture = state.session().await.tcp_capture.clone();

        let error = capture
            .add_listener(listener(crate::tcp_capture::Protocol::Tcp))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("session"), "{error}");
        assert!(capture.listener_configs().is_empty());

        // A UDP listener takes nothing from a TCP port.
        capture
            .add_listener(listener(crate::tcp_capture::Protocol::Udp))
            .await
            .unwrap();
        capture.stop().await.unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    // The main listener is where the operator put it, the environment
    // included, so there the session gives way.
    #[tokio::test]
    async fn a_main_listener_started_on_a_sessions_number_takes_it_from_the_session() {
        let dir = scratch("claim");
        let state = state_in(&dir);
        let (session, port) = session_keeping_a_number(&state).await;
        let (other, other_port) = session_keeping_a_number(&state).await;
        state.set_active_proxy_addr(loopback(port)).await;

        state.claim_main_listener_port().await;

        assert_eq!(state.session_port_status(session).proxy_port, None);
        assert_eq!(
            state.session_port_status(other).proxy_port,
            Some(other_port)
        );
        assert!(!state.own_listeners().keeps(port));
        let events = state.session().await.event_log.snapshot(None).await;
        assert!(
            events
                .iter()
                .any(|event| event.title == "Session port number released"
                    && event.message.contains(&port.to_string())),
            "{events:?}"
        );
        // It is not given again, to this session or another.
        let next = state.open_session_port(session).await.unwrap().proxy_port;
        assert!(next > Some(port.max(other_port)));
        state.close_session_port(session).await.unwrap();

        // With no session on the main listener's number nothing is said.
        let before = state.session().await.event_log.len().await;
        state.claim_main_listener_port().await;
        assert_eq!(state.session().await.event_log.len().await, before);
        let _ = std::fs::remove_dir_all(dir);
    }

    // The TCP intercept controls reach only the session the main listener
    // records into, so a read held in a session with a port could not be let go.
    #[tokio::test]
    async fn a_session_with_a_port_holds_no_tcp_reads() {
        let dir = scratch("tcp-intercept");
        let state = state_in(&dir);
        let first = state.session().await;
        let expected_revision = first.tcp_capture.policy().revision;
        first
            .tcp_capture
            .set_policy(crate::tcp_capture::PolicyUpdate {
                enabled: true,
                direction: first.tcp_capture.policy().direction,
                expected_revision,
                filter: None,
            })
            .unwrap();
        state.create_session(Some("second".into())).await.unwrap();
        assert!(first.tcp_capture.policy().enabled);

        state.open_session_port(first.id()).await.unwrap();

        assert!(!first.tcp_capture.policy().enabled);
        state.close_session_port(first.id()).await.unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn the_session_list_says_which_port_each_session_has() {
        let dir = scratch("activity");
        let state = state_in(&dir);
        let agent = inactive_session(&state, "agent").await;
        let idle = inactive_session(&state, "idle").await;
        let opened = state.open_session_port(agent).await.unwrap();

        let activity = state.session_activity().await;
        let of = |id: Uuid| activity.iter().find(|entry| entry.id == id).unwrap();
        assert_eq!(of(agent).proxy_port, opened.proxy_port);
        assert!(of(agent).proxy_port_open);
        assert_eq!(of(idle).proxy_port, None);
        assert!(!of(idle).proxy_port_open);

        state.close_session_port(agent).await.unwrap();
        let activity = state.session_activity().await;
        let of = |id: Uuid| activity.iter().find(|entry| entry.id == id).unwrap();
        assert_eq!(of(agent).proxy_port, opened.proxy_port);
        assert!(!of(agent).proxy_port_open);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_missing_file_holds_no_numbers() {
        let dir = scratch("missing");
        let numbers = Numbers::load(&dir.join("session-ports.json")).unwrap();
        assert_eq!(numbers, Numbers::default());
        assert_eq!(numbers.candidates(FIRST_PORT).next(), Some(FIRST_PORT));
    }

    #[test]
    fn numbers_survive_a_restart() {
        let dir = scratch("restart");
        let path = dir.join("session-ports.json");
        let session = Uuid::new_v4();
        let mut numbers = Numbers::default();
        numbers.give(session, 18081);
        crate::session::write_json(&path, &numbers).unwrap();

        let loaded = Numbers::load(&path).unwrap();
        assert_eq!(loaded.of(session), Some(18081));
        assert_eq!(loaded.candidates(FIRST_PORT).next(), Some(18082));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_deleted_sessions_number_is_not_given_again() {
        let (first, second) = (Uuid::new_v4(), Uuid::new_v4());
        let mut numbers = Numbers::default();
        let port = numbers.candidates(FIRST_PORT).next().unwrap();
        numbers.give(first, port);
        assert_eq!(numbers.forget(first), Some(port));

        let next = numbers.candidates(FIRST_PORT).next().unwrap();
        assert_ne!(next, port);
        numbers.give(second, next);
        assert_eq!(numbers.of(first), None);
        assert_eq!(numbers.of(second), Some(port + 1));
    }

    #[test]
    fn a_file_that_cannot_be_read_is_an_error_that_names_it() {
        let dir = scratch("unreadable");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session-ports.json");
        std::fs::write(&path, b"{ not json").unwrap();

        let error = Numbers::load(&path).unwrap_err();
        assert!(error.to_string().contains("session-ports.json"), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_saved_file_without_the_last_number_still_never_reuses_one() {
        let dir = scratch("no-last");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session-ports.json");
        let session = Uuid::new_v4();
        std::fs::write(
            &path,
            format!(r#"{{"last":0,"sessions":{{"{session}":18090}}}}"#),
        )
        .unwrap();

        let numbers = Numbers::load(&path).unwrap();
        assert_eq!(numbers.candidates(FIRST_PORT).next(), Some(18091));
        let _ = std::fs::remove_dir_all(dir);
    }

    // Measured on macOS: with SO_REUSEADDR a loopback bind succeeds beside a
    // listener on every interface and takes its loopback connections.
    #[tokio::test]
    async fn a_port_does_not_open_beside_another_programs_listener() {
        let other = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = other.local_addr().unwrap().port();

        let error = bind_exclusive(SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    }

    #[tokio::test]
    async fn a_closed_port_opens_again_at_once() {
        let listener = bind_exclusive("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        // The listener's side closes first, so its end is the one that waits.
        drop(accepted);
        let mut end = Vec::new();
        client.read_to_end(&mut end).await.unwrap();
        drop(client);
        drop(listener);

        let reopened = bind_exclusive(addr).await.unwrap();
        assert_eq!(reopened.local_addr().unwrap(), addr);
    }
}
