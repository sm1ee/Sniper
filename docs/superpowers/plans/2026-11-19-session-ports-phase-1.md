# Session ports, phase 1: the server

> Steps use checkbox (`- [ ]`) syntax for tracking. One commit for each task.

**Goal:** A session can have a loopback proxy port of its own, opened and
closed over the API and `sniper-cli`, that records into that session whichever
session the main listener records into.

**Spec:** `docs/superpowers/specs/2026-11-19-session-proxy-ports-design.md`,
phase 1: decisions 1, 2, 5, 6 and 7; the connections part of 3; the two
refusals and the create flag of 4; the exemption of 8; the port rows of 11.

**Architecture:** `src/session_ports.rs` holds the saved numbers and the
registry of open ports. Each open port owns its accept task, its accepted
connections and the session's one writable `Arc<SessionContext>`.
`proxy::serve_proxy` gains a twin that serves a listener for one fixed session.
One snapshot of Sniper's own listeners (`OwnListeners`) feeds every guard.

## Global constraints

- A session port binds `127.0.0.1` only, numbers from `18081` up, never reused,
  at most `tcp_capture::MAX_LISTENERS` (16) open at once.
- One writable context for each session. Opening never calls
  `session_context_for_id_operation_locked`.
- Lock order: `proxy_rebind_lock` → `session_activation_lock` → the session's
  operation lock → the registry's own mutex. Opening and closing a port never
  take `proxy_rebind_lock`.
- Every write is atomic (`session::write_json`) and off the proxy runtime.
- `SessionSummary` keeps its fields (saved.v1). New fields go on
  `SessionActivity`.
- No new dependency. Fixtures use `example.com` and loopback upstreams.
- A refusal changes nothing.

## Review focus

1. A port opened for a session never switched to since start-up must use the
   context `session_context_for_id` returns (pointer-equal), also after a
   workspace write. → T4, T6.
2. Another program on `*:N`: the port must not open beside it. Closing and
   opening again at once must work although the old connections are in
   TIME_WAIT. → T3.
3. A client that is not loopback reaches no session port, by address or by
   name, by request or by tunnel. → T7.
4. A tunnel held open on a session port survives `session switch` and a rebind
   of the main listener; a delete right after a close succeeds. → T5, T8.
5. A cancelled shutdown brings every listener back; a quit right after a
   capture loses nothing. → T8, T10.

---

### T1: Create a session without moving the main listener

**Files:** `src/state.rs`, `src/api.rs`, `src/bin/sniper-cli.rs`.

**Interfaces:** `AppState::create_session(name: Option<String>, activate: bool)
-> Result<SessionSummary>`. `CreateSessionPayload.activate: Option<bool>`
(absent means true). CLI: `session create --no-activate`.

- [x] Test `creating_a_session_without_activating_moves_nothing` (state.rs):
  the active session id is unchanged, the summary has `active == false`, the
  session is listed.
- [x] Implement; API handler passes `payload.activate.unwrap_or(true)`.
- [x] CLI flag, payload field and preview text; test the payload it sends.

### T2: Saved numbers

**Files:** create `src/session_ports.rs`; `src/lib.rs` (`pub mod`).

**Interfaces:**
- `pub const FIRST_PORT: u16 = 18081;`
- `struct Numbers { last: u16, sessions: BTreeMap<Uuid, u16> }`, saved as
  `session-ports.json` in the data directory.
- `Numbers::load(path) -> Result<Numbers>`: a missing file is empty; a file
  that does not parse is an error that names the file.
- `Numbers::next_candidate(&self) -> Option<u16>`: `max(last + 1, FIRST_PORT)`.

- [x] Tests: missing file is empty; a number survives save and load; a
  forgotten session's number is not given again; an unreadable file is an
  error.

### T3: The exclusive bind

**Files:** `src/session_ports.rs`.

**Interface:** `async fn bind_exclusive(addr: SocketAddr) ->
io::Result<TcpListener>`: refuse when something answers on the address; bind
without `SO_REUSEADDR`; on `AddrInUse` with nothing answering, bind with it
(the port is only waiting out old connections).

- [x] Tests: refuses beside a listener on `0.0.0.0:N`; binds again at once
  after its own listener closed a connection first.

### T4: The registry, the serve loop, open and close

**Files:** `src/session_ports.rs`, `src/proxy.rs`, `src/state.rs`,
`src/session.rs` (`SessionActivity`), `src/api.rs` (routes).

**Interfaces:**
- `proxy::ListenerConnections` (clone-able set of abort handles);
  `proxy::serve_session_port(listener, state, session, connections)`.
- `AppState::open_session_port(id) -> Result<SocketAddr>`,
  `AppState::close_session_port(id) -> Result<bool>`,
  `AppState::session_port_context(id) -> Option<Arc<SessionContext>>`,
  `AppState::session_port_addr(id) -> Option<SocketAddr>`.
- `SessionActivity` gains `proxy_port: Option<u16>` and `proxy_port_open: bool`.
- Routes `POST` and `DELETE /api/sessions/:id/proxy-port`.

- [x] Tests: a request through the port is recorded in its session while
  another session is active; the port's context is pointer-equal to
  `session_context_for_id` for a session never switched to, for one that was,
  and after a workspace write; opening twice returns the same address; the
  default session is refused; the seventeenth port is refused; a closed port
  refuses connections and keeps its number; an unreadable numbers file refuses
  opening and nothing else.

### T5: One feed for each session

**Files:** `src/state.rs`, `src/api.rs`.

- [x] Tests: activating a session with an open port is refused and the port
  stays open; deleting one is refused before its Fuzzer is stopped; both
  answer 409; a tunnel on a session port survives a switch between two other
  sessions.

### T6: Writes follow a session with an open port

**Files:** `src/api.rs`.

- [x] One predicate for the eight checks; a session with an open port is
  exempt and resolves to the registry's context, the two workspace handlers
  included.
- [x] Tests: forward a held request, change runtime settings and save the
  workspace of a session with an open port while it has proxy work.

### T7: Guards know every listener

**Files:** `src/session_ports.rs` (`OwnListeners`), `src/proxy.rs`,
`src/api.rs`, `src/tcp_capture.rs`, `src/runtime.rs`, `src/upstream_proxy.rs`,
`src/state.rs`.

- [x] `OwnListeners`: one snapshot of the UI, the main listener and the open
  session ports. The remote-client guard, the loop guard,
  `targets_own_listener`, Render, the upstream-proxy check (saved and used)
  and TCP capture read it.
- [x] The main listener and a TCP relay listener are not started on a held
  number; the startup-settings API refuses one before it saves; a main
  listener started on one from the environment takes it from the session and
  logs that.
- [x] Tests: a client that is not loopback is refused a session port by
  address and by name; a request to a session port through any listener gets
  508; an upstream proxy that is a session port is refused when saved and when
  used.

### T8: Close, shutdown, resume, rebind

**Files:** `src/session_ports.rs`, `src/proxy.rs`, `src/state.rs`,
`src/lib.rs`, `src/bin/sniper-desktop.rs`.

- [x] Close: stop accepting, wait two seconds, cut the port's connections and
  the session's tunnels and streamed responses, close its WebSocket relays
  through their own handles, `discard_cancelled`, flush the pending save.
- [x] The five shutdown paths stop session ports first and save the fed
  sessions' small components afterwards.
- [x] One resume function for the three cancelled shutdowns.
- [x] Rebind closes the default session's relays and drains the main
  listener's connections only.
- [x] Tests: delete right after a close; a tunnel on a session port survives a
  rebind; a cancelled shutdown brings the ports back.

### T9: CLI and documents

**Files:** `src/bin/sniper-cli.rs`, `docs/guides/cli.md`,
`docs/architecture.md`, `AGENTS.md`, the operator skill.

- [x] `session port open|close|list`.

### T10: Runtime test, deploy, review

- [x] Isolated instance: concurrent capture into three sessions counted for
  each; close, reopen, delete and restart keep the numbers; a client that is
  not loopback is refused; quit right after a capture, restart, count.
- [x] Deploy to `~/Desktop/Sniper.app`. One reviewer.
