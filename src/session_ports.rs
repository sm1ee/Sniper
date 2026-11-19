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
}

/// The session ports of one Sniper: the saved numbers and what is open now.
/// Opening and closing are serialized by `AppState`, under its activation lock.
pub(crate) struct SessionPorts {
    path: PathBuf,
    /// One writer of the numbers file at a time. The write runs off the
    /// runtime, so the registry's own lock cannot be held across it.
    numbers_write: tokio::sync::Mutex<()>,
    inner: Mutex<Inner>,
    #[cfg(test)]
    test_first_port: std::sync::OnceLock<u16>,
}

impl SessionPorts {
    pub(crate) fn load(data_dir: &Path) -> Self {
        let path = data_dir.join(NUMBERS_FILE);
        let numbers = Numbers::load(&path).map_err(|error| format!("{error:#}"));
        if let Err(error) = &numbers {
            tracing::warn!(%error, "session ports stay closed until the numbers file is readable");
        }
        Self {
            path,
            numbers_write: tokio::sync::Mutex::new(()),
            inner: Mutex::new(Inner {
                numbers,
                open: HashMap::new(),
            }),
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
        let replaced = self.inner().open.insert(
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
    }

    /// Stops the port from accepting and forgets it. The listener is closed
    /// when this returns, so the number can be bound again.
    pub(crate) async fn unregister(&self, session: Uuid) -> Option<SocketAddr> {
        let port = self.inner().open.remove(&session)?;
        port.accept.abort();
        let _ = port.accept.await;
        Some(port.addr)
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
        self.inner().numbers = Ok(numbers);
        Ok(())
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
