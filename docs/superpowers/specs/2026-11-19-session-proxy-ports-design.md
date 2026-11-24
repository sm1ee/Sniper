# A proxy port for each session

Status: design, written after the step 2 spike (`spike/session-ports`,
`f1df80d`, local only) and revised after a builder check, a second review by
the author and an adversarial review. The guard of decision 5 is fixed
(`74c9114`), and phases 1 (`9e6c130` to `fa41681`), 2 (`35ff9d4`, `28ff659`)
and 3 (`5fa0395` to `6b9b1a5`) are built; see "As built" at the end. Phase 4 is
not built.

## Problem

Sniper records into one session at a time. The proxy has one listener, and
`handle_request` gives every request to the active session
(`AppState::session_with_proxy_owner`). The browser launcher keeps one profile
for each browser kind.

Two things people want do not fit that:

- Several agents, or one tester with several accounts, working on the same
  target at once, each in a session of its own.
- Moving between sessions the way Claude or Codex desktop moves between
  conversations: a click shows another session and disturbs nothing.

Today a click on a session activates it. Activation waits for both sessions'
proxy work, closes idle tunnels, refuses or cuts what is left, drops the
requests Intercept holds and stops the old session's TCP relay. It has to,
because the one listener is about to feed another session. Creating a session
activates it too (`AppState::create_session`).

## What the spike showed

The spike bound a second listener to a second session. Measured on an isolated
instance: two sessions captured 60 concurrent requests each with nothing
crossing over; HTTPS through the bound port was intercepted and recorded in its
session; Intercept held a request in one session while the other flowed; both
histories survived a restart.

It also showed what is in the way:

- The proxy chooses the session in one place. Everything below `handle_request`
  already takes the session as an argument.
- API writes that name a session are refused with 409 while that session is
  not active and has proxy work. A session fed by its own port always has
  proxy work, so not even a held request could be forwarded.
- Activation drains and cuts the work of both sessions, whichever listener it
  came from.
- The loop guard, the upstream-proxy check, TCP capture's own-address list, the
  rebind and every shutdown path know only the main listener.

## What other tools do

- **Burp.** Several proxy listeners can run at once, each with its own binding,
  TLS and request-handling settings. They are project settings, and the HTTP
  history has a "Listener port" column. A second project is a second Burp.
- **Caido.** One instance takes several `--proxy-listen` addresses on the CLI.
  To run two at once, its guide starts a second instance with its own port and
  data path.
- **mitmproxy, ZAP.** mitmproxy repeats `--mode`, each with `@port`. ZAP adds
  "as many additional addresses and ports" as wanted. Neither page describes
  sending a listener to a store of its own.

We found no proxy where two listeners of one process record into two projects.
The others run two processes. For Sniper a second process means a second data
directory, so a second CA to trust and a second window, and no one list of
sessions.

## Terms

- **Main listener**: the proxy listener on the configured address, by default
  `127.0.0.1:8080`.
- **Default session**: the session the main listener records into. This is
  today's active session. The registry field, the API and the CLI keep the
  word `active`.
- **Session port**: a loopback proxy listener that records into one session.
- **Fed session**: the default session, or a session with an open session port.
- **Viewed session**: the session a UI client shows. Only that client knows it.

`active` means three things in today's code, and this design separates them:

1. where the main listener records;
2. the session an API call means when it names none;
3. a session that is loaded and live, so it may be written while traffic flows.

The default session keeps 1 and 2. Every fed session gets 3. A check of the
active session in the code is one of these three, and only the third kind
changes.

## Goals

1. A session can have a port of its own. Traffic through it is recorded in
   that session, whichever session is the default.
2. A session with its own port works while it is not the default: Intercept,
   Replay, Fuzzer, rules, tags, workspace.
3. Clicking a session in the UI changes what is shown and nothing else.
4. A browser opened for a session that is not the default uses that session's
   port and a profile of its own. The default session's browser stays the
   shared one, because it follows the main listener.
5. Moving the main listener never touches work that came through a session
   port.
6. Everything above is reachable from `sniper-cli`.
7. Someone who never opens a session port sees no change except goal 3.

## Non-goals

- TCP relay listeners and TCP intercept for a session that is not the default.
  The listeners' ports are fixed by the user, and two sessions may have saved
  the same one. A tunnel on a session port that is neither TLS nor HTTP is
  relayed and recorded, never held.
- OAST polling, Service Map body reads and the recorded-socket-peer setting for
  a session that is not the default. Each serves the active session only today
  (`run_oast_poller_for_state`, the body endpoints near `src/api.rs:6202`,
  `pin_upstream_peer_settings_session`). They are of the third kind above and
  can follow later; until then a fed session sees what an inactive one sees
  now.
- Opening ports again at start-up, and choosing a port's number.
- Session ports beyond loopback. Other devices use the main listener.
- More than one port for a session.
- A record of which listener each request arrived on.
- Step 4 of the plan: refusing writes without `--session-id` while several
  sessions are fed, a rate limit by target host, a stop-everything control.
- Keeping the remote server's state apart. Sessions separate what Sniper
  records, nothing else.

## Anti-goals

These make the work a failure even if it runs.

- A request recorded in a session other than the one its port belongs to.
- Two writable contexts for one session. `docs/persistence-safety.md` holds only
  for the writable contexts `AppState` manages; a second one on the same
  directory shows another request's body with no error.
- A client on another machine reaching the UI, a browser's driver port or a
  proxy listener of Sniper through any chain of connections Sniper opens.
- Viewing a session, moving the main listener or rebinding it cutting another
  session's connections.
- A port that opens without anyone asking for it.
- An operation that fails and still changes something.

## Before this work

Reviewing this design found gaps in the guard against clients on another
machine. They were on the main listener and needed no session port. One was
reproduced on an isolated instance; the others were read in the code. The guard
was fixed first, on its own (`74c9114`), to the rule in decision 5. This
document is not published before that fix is released.

## Decisions

### 1. A session port is opened on request, on loopback, one for each session

`POST /api/sessions/:id/proxy-port` opens it. The address is always
`127.0.0.1`.

- **A number is given once and never reused.** The first open gives the session
  the next number from 18081 up that binds. The session keeps it until it is
  deleted; closing and opening again uses the same number. A deleted session's
  number is not given to another. So a client left pointing at 18081 reaches
  its own session or nothing.
- **Not the numbers next to 8080.** 8081 and its neighbours are where dev
  servers and other proxy tools already listen. A session port there would be
  taken for one of them, or would take the number one of them wants later.
- **The bind is exclusive.** Sniper's usual bind sets `SO_REUSEADDR`
  (`bind_proxy_listener`). On macOS that lets a loopback bind succeed beside
  another program's listener on every interface, and take its loopback
  traffic; this was measured. A session port must fail there.
- The main listener and a TCP relay listener are not started on a number a
  session holds. The startup-settings API refuses one before it saves.
- Not a port for every session: most sessions are never captured into again.
- At most 16 open at once, the limit the TCP relay already uses
  (`tcp_capture::MAX_LISTENERS`). Each one keeps its session loaded.
- A port is open until it is closed or Sniper stops. After a restart nothing is
  open, and opening again gives the same number. Reopening at start-up would
  load every such session on every start and open ports nobody asked for this
  time.

### 2. The listener registry holds the session's one writable context

A registry in `AppState` holds, for each session port: the address, the accept
task, its accepted connections and the session's `Arc<SessionContext>`.
Requests on the port use that context directly.

The rule: a session has one writable context, and the registry holds that same
`Arc`. Opening a port goes in two steps:

1. Before any lock, `session_context_for_id` returns the context. It gives the
   active context for the default session and the cached or newly loaded one
   otherwise, and starts what a loaded session needs.
2. Under `session_activation_lock` and then the session's operation lock, the
   order activation uses, the open checks that the session still exists, that
   shutdown has not begun and that `is_current_session_context` still holds,
   and registers the port.

- `session_context_for_id_operation_locked` must not be the call. It does not
  check the active session, and until the first switch the start-up default
  session is not in `session_contexts` (it starts empty, `src/state.rs:231`),
  so it would load a second writable context.
- The load is outside the locks because `decide_tcp_intercept`, activation and
  shutdown wait on `session_activation_lock`, and the desktop quit waits on it
  from the event loop.
- Not a lookup on every request: `session_context_for_id` takes the session's
  operation lock, which activation holds while it waits for work to drain.
- Three paths remove or replace a cached context: delete, the stale-context
  branch of `replace_workspace_state_and_persist`, and activation writing the
  leaving session's entry (`src/state.rs:1038`). Delete is refused while the
  port is open (decision 6). The stale branch cannot run, because every API
  call resolves a session with an open port to the registry's `Arc`, the two
  workspace handlers included; they resolve the session themselves today.
  Activation writes the same `Arc` back.
- Required test: the port's context is pointer-equal to what
  `session_context_for_id` returns for a session never switched to since
  start-up, for one that has been, and after a workspace write to it.

### 3. Each listener knows its own connections

Every listener keeps the abort handles of the connections it accepted, so one
listener can be drained or cut without touching another. Today they share one
process-wide map (`ACTIVE_PROXY_CONNECTIONS`), and a rebind of the main
listener drains all of it.

While a session has one feed (decision 4), that is enough: a listener's work is
its accepted connections plus the tunnels, WebSocket relays and streamed
responses of its one session, which the registries already list by session.

When a session may have two feeds (phase 4), work must also carry the listener
it arrived on. A task-local set for each accepted connection reaches most of
it, as `CLIENT_ADDRESS` does, and `spawn_tracked_proxy_task` re-scopes it. It
does not reach two places, which must carry the tag in a field, as
`StreamedRecordContext` already carries `client_address`:

- the streamed-response pump, a plain `tokio::spawn` (`src/proxy.rs:4794`),
  and the capture task it starts;
- HTTP/2 inside a tunnel, where hyper spawns a task for each stream
  (`AutoBuilder` with `TokioExecutor`, `src/proxy.rs:3226`).

The tag then goes into every registry that is cut by session today:
connections, tasks, owners, `ACTIVE_STREAMED_RESPONSE_PUMPS` and
`LIVE_WEBSOCKET_RELAYS`. Work with no tag counts for its session and for no
listener. That is safe: a session that stops being fed must still end all its
work, and one that stays fed keeps it.

### 4. The main listener and a session port do not feed the same session, at first

`POST /api/sessions/:id/activate` and `sniper-cli session switch` keep their
names. They mean: the main listener records into this session from the next
connection on.

**Phases 1 to 3: one feed for each session.**

- A port is not opened for the default session (409).
- A session with an open port does not become the default (409).
- No session port is ever drained or cut by activation, because neither
  session it touches has one. In phase 1 activation changes by that one check.
- In phase 3 activation also stops counting, and stops cutting, work the API
  started in the session it moves to. With the UI able to run a Fuzzer in a
  viewed session, that session would otherwise refuse the main listener, and
  `force` would cut the attack (`src/state.rs:958`, `1024`). The session it
  leaves keeps today's rule.

This keeps the first phases almost out of the activation code, which is where a
mistake costs the most.

**Phase 4: both at once.** The two refusals go, and activation counts the main
listener's work alone:

| | Without a session port | With an open session port |
| --- | --- | --- |
| Session the main listener leaves | As today: all its work must end, held requests are dropped, the TCP relay stops, it is saved in full. | Keeps its port's connections and held requests, and stays writable. Only held entries whose request was cut are removed (`discard_cancelled`, not `drop_all`). |
| Session the main listener moves to | As in phase 3. | Not drained and not reloaded. The registry's context becomes the active one. |

For the main listener's own work the steps stay: wait two seconds, close its
idle tunnels so clients reconnect into the new session, then refuse with 409,
or cut when `force` is set.

Phase 4 is the only phase that rewrites activation. It waits until one feed
proves too little: an agent that needs a fixed port into the session the main
listener is on, or a tester who wants the main listener on a session an agent
holds a port to.

**Creating a session.** `POST /api/sessions` gains `activate`, true when
absent. With `false` the session is created and nothing moves. An agent creates
its session this way and then opens a port. The UI keeps creating and
activating.

### 5. A client on another machine reaches nothing Sniper listens on

The proxy's outbound connection comes from this machine, and both the UI and
the proxy's own guard trust this machine. So every port Sniper listens on is a
second hop: a client that makes Sniper connect to one arrives there as a local
client, and from a proxy listener it can go on to the UI.

**Sniper's ports** are the UI, the main listener, every open session port, and
the driver ports of the browsers it opened, those of an earlier run included.

**For a client that is not loopback, Sniper opens no connection to one of its
ports at any address of this machine.**

- Any address of this machine: loopback, unspecified, and every interface
  address. A UI on every interface is announced as `127.0.0.1` while it
  answers on the others and trusts them (`advertise_local_api_addr`,
  `peer_is_same_host`).
- Every path: a proxied request, a CONNECT tunnel whatever it carries
  (`remote_client_targets`), a TCP relay listener (`TcpCapture::guarded`,
  whose list `arm_tcp_capture` copies once and which must follow ports as they
  open and close).
- A name on one of these ports is refused without a lookup. The connection
  looks the name up again, and an upstream proxy looks it up somewhere else,
  so no answer checked here says where the connection lands. The cost: from
  another machine, a site that uses one of Sniper's ports is reached by
  address only, or after the proxy moves to another port.
- The driver ports of browsers that still run are read back from
  `browser-profiles` at start-up (`recover_driver_ports`). They were kept in
  memory from the launch and were gone after a restart.

The check is on the client's address at the first hop. A check at the second
hop cannot work, because there the client is this machine.

**A request whose target is one of Sniper's proxy listeners gets 508, for any
client**, as the main listener's does today. One function gives the list to:

- the loop guard and its DNS variant (`request_targets_own_listener`,
  `name_resolves_to_own_listener`);
- `targets_own_listener`, which Template Scan and the automatic scan use;
- Render's resource fetch and its redirect policy;
- the upstream-proxy setting, when it is saved and again when a connection is
  made through it, because a port can open after the setting was saved.

Required test, with a client that is not loopback: it reaches neither the UI,
a driver port, the main listener nor a session port; by loopback, by an
interface address and by name; by a proxied request and by a tunnel carrying
TLS, HTTP and neither; through the main listener and a TCP relay listener.
The tests beside `remote_client_targets` cover the main listener's part of
this today; session ports join them in phase 1.

### 6. Shutdown, delete and rebind know every listener

- **Shutdown.** Five paths stop the proxy: `src/lib.rs` (headless), the
  self-update in `src/state.rs`, and three in `src/bin/sniper-desktop.rs`. Each
  stops the main accept task and drains. Each must first stop every session
  port from accepting. Afterwards each fed session that is not the default
  saves its small components (`persist_state_only`); its traffic is already in
  the journals. A full save of up to sixteen sessions would hold the desktop's
  event loop for all of them. The default session is saved as today. One
  function does this for all five paths.
- **Cancelled shutdown.** Three places stop and then carry on: a self-update
  whose preparation fails, one whose installer does not start, and a desktop
  quit that a failed save stops. Only the second restores the main listener
  today (`restore_proxy_after_self_update_prepare_failure`); the others reset
  the TCP flag and leave the proxy stopped. One resume function brings back
  the main listener, the TCP relay and the session ports that were open, and
  all three call it.
- **Rebind.** `rebind_proxy_locked` closes every live WebSocket relay and
  drains every connection in the process. Both narrow to the main listener:
  its accepted connections and the default session's work.
- **Close.** Closing a port stops accepting and waits two seconds. It then
  cuts that port's connections and its session's tunnels and streamed
  responses, and closes its WebSocket relays as `close_live_websocket_relays`
  does, through each relay's own handle, so the close is recorded and the
  relay is forgotten. Cutting the outer task, as a forced switch does today,
  leaves the relay registered, and that entry then refuses a delete. Held
  entries whose request was cut are removed (`discard_cancelled`). Work the
  API started is left alone. Close ends by flushing the session's pending
  save, so a delete can follow at once.
- **Delete.** A session with an open port is not deleted (409, "close its port
  first"), and that check comes before delete stops the Fuzzer. Closing the
  port inside the delete would leave it closed when a later check refuses the
  delete. The UI closes the port and then deletes, after one confirmation that
  says both.

### 7. Numbers are saved; ports are not

`session-ports.json` in the data directory holds the last number given and the
number of each session that has one. It is written with `write_json` (temp
file, fsync, rename), off the proxy runtime.

- Not in `registry.json` or `SessionMetadata`: that write path carries the
  commit-status and receipt handling for rename, delete and activation, and a
  port is not session metadata. `SessionSummary` is fixed by saved.v1.
- A number that will not bind when its port is opened is reported to the
  caller, who can try again. Sniper does not give the session another: a
  client set to 18081 gains nothing from 18083.
- A file that cannot be read stops session ports from opening and says which
  file. Without it Sniper cannot know which numbers are taken. Nothing else
  stops.
- If the main listener is started on a session's number from the environment,
  that session loses the number, and the event log says so.

### 8. Writes follow the session id

Eight checks refuse a write that names a session which is not active and has
proxy work: `resolve_session_for_optional_id`, `guard_session_write_operation`,
`begin_session_proxy_operation`, `guard_ws_replay_connection_owner_operation`,
and two each in `update_workspace_state` and its keepalive variant.

Before `5c63b85` the rule answered "active session changed". It catches a
client that still writes to a session the proxy has left. Storage safety does
not come from it: a context has no notion of being active, its save functions
take only its own mutation and persist locks, and Recon and Template Scan
already write to sessions that are not active without it. Safety comes from one
writable context for each session (decision 2). What the rule did keep true is
that a session about to receive the main listener is idle; decision 4 covers
that.

- **Phase 1.** The eight checks call one predicate, and a session with an open
  port is exempt. The spike exempted four of them and never ran a workspace
  write, so phase 1 does.
- **Phase 3.** The rule goes for every session. A UI that views a session with
  no port and sends a Replay from it would otherwise have its own autosave
  refused until the Replay ends. A call that names no session still means the
  default session and is still re-checked after the lock.
- **Phase 3 also.** `update_workspace_state` answers a refused write with the
  active session's snapshot (`src/api.rs:3640`). A write for one session must
  never be answered with another session's workspace.

Removing the rule for every session is the riskiest decision here. Phase 3
begins by proving it: capture, Replay and API writes run together on a session
that is not the default, the process restarts, and every stored body is
compared with what was sent.

### 9. The UI views a session without activating it

- A click on a session row changes the viewed session. The UI runs today's
  leave-and-enter steps (flush drafts, reload the workspace) without the
  activate call. A client starts on the default session.
- Every read and write names the viewed session. The UI stops sending
  `expected_active_session_id`; the server keeps accepting it.
- Starting to view a session loads its writable context first
  (`session_context_for_id`). Otherwise the first save replaces a read-only
  context, the event stream ends, and the workspace reloads.
- An event stream opened for a session no longer ends because the default
  session changed (`should_reconnect_event_stream`). It ends when its session
  is deleted or its context is replaced.
- What follows the active session in `web/app.js` today, and must follow the
  viewed one: `_applySettings`, `loadSessions`, `loadWorkspaceState` (a read
  that names no session), `workspaceSnapshotMatchesActiveSession` and
  `handleExternalSessionChanged`.
- When another client moves the main listener the UI updates the list and
  keeps its view. When the viewed session is deleted it shows the default
  session.
- "New session" creates the session, moves the main listener to it and views
  it, as today.
- The session list runs the full height of the window, and the top strip, the
  tool and the status bar sit beside it. Left is which session; everything to
  its right, the tabs included, is that session. Today the list starts under
  the top strip, which reads as if the tabs were above the sessions.
- The proxy indicator in the top strip says how traffic reaches the viewed
  session: "Proxy :8080", "Proxy :18081" or "Not receiving". It is on every
  tab, and "Not receiving" opens the two actions that fix it. Today it says
  only whether the one listener is up.
- The row of a fed session shows its port at the trailing edge, the main
  listener's for the default session. That label is how the list says where
  the main listener records. The Session tab shows the same beside the name,
  and its "Open" views the session.
- The row's existing menu gains: "Record :8080 here" (the main listener's
  port), "Open a port" or "Close port :18081", and "Copy proxy address". An
  action the server would refuse (decision 4) is not offered.
- Capture adds to that where it already speaks, with no new banner: the capture
  pill reads "Not receiving", and the empty-history message names the session
  the proxy records into and offers the two actions beside the browser button.
  Replay, Fuzzer, Sequence, Scan and Tools send their own requests and need
  nothing more.
- What the non-goals leave with the default session (the TCP relay, OAST,
  Service Map bodies, socket peers) says in one line where it runs, in place of
  today's "open that session first".
- The browser button opens a browser for the viewed session (decision 10).

### 10. A browser for a session that is not the default

`POST /api/browser/launch` takes a `session_id`.

- For the default session it is today's launch: the main listener and the
  shared profile `browser-profiles/<kind>`.
- For any other session the launch opens the session's port if it is closed,
  points the browser at it, and uses the profile
  `browser-profiles/session-<id>/<kind>`.
- Only a browser that can be driven as one instance is opened this way: the
  DevTools port, ego and BrowserOS. Aside is driven through one daemon for the
  whole machine (`aside repl`), so an agent would drive another session's
  window. Aside is refused for a session that is not the default.
- Profiles stay outside the session folder. A session folder that is copied or
  sent to someone must not carry logged-in cookies.
- Deleting a session removes its profiles. One that a running browser still
  holds is removed by a sweep at start-up and at the next launch, which deletes
  every `session-<id>` directory whose session is gone and whose browser is not
  running, as `sweep_stale_fresh_profiles` does for throwaway profiles.
- A browser with a driver port is refused while the main listener is bound
  beyond loopback. `launch_at` reads that from the address it is given
  (`ctx.proxy_addr`), which for a session is the session port and always
  loopback. The refusal must keep looking at the main listener.
- A launch is refused while the proxy is offline (`launch_browser`). For a
  session that means its own port.

### 11. API and CLI

| API | CLI | Does |
| --- | --- | --- |
| `POST /api/sessions` with `activate: false` | `session create --no-activate` | Creates a session and moves nothing. |
| `POST /api/sessions/:id/proxy-port` | `session port open --id <id>` | Opens the port and returns the address. Repeating it returns the open port. |
| `DELETE /api/sessions/:id/proxy-port` | `session port close --id <id>` | Closes it. The number stays the session's. |
| `GET /api/sessions/activity` | `session port list` | Each session gains `proxy_port` and whether it is open. |
| `POST /api/sessions/:id/activate` | `session switch --id <id>` | Unchanged name; decision 4. |
| `POST /api/browser/launch` | `capture browser open --session-id <id>` | Decision 10. |

`SessionSummary` and `runtime-state.json` do not change. `docs/guides/cli.md`,
the operator skill and `docs/architecture.md` describe session ports when
phase 1 ships.

## Phases

Each phase ships working software, has its own plan, and ends with a runtime
test on an isolated instance that includes a restart.

1. **Session ports on the server.** Decisions 1, 2, 5, 6 and 7; the
   connections part of 3; the two refusals and the create flag of 4; the
   exemption of 8; the port rows of 11.
2. **A browser for a session.** Decision 10, in the server and the CLI.
3. **The UI views without activating.** Decision 9, the rest of 8, the
   activation change of 4, and the browser button.
4. **Both feeds at once.** The rest of decisions 3 and 4. Built when needed.

After phase 2 an agent has a session, a port and a browser of its own. Until
phase 3 the UI cannot open a session that has a port, because a click still
activates and that is refused, so phases 1 to 3 are released together. Phase 3
is the only phase that changes what an existing user sees.

## What can go wrong

| Failure | Guard | Proof |
| --- | --- | --- |
| A request lands in the wrong session | A number is given once and never reused; the main listener and TCP relay stay off held numbers; the bind is exclusive | Concurrent capture into three sessions, counted for each; close, reopen, delete and restart never hand a number to another session; a port does not open beside another listener |
| A second writable context | Decision 2 | The pointer-equality test |
| A remote client reaches the UI through a connection Sniper opens | Decision 5 | The non-loopback client test |
| An agent creating a session moves the main listener | `activate: false` (decision 4) | Create with the flag while a tunnel is open on the main listener; the tunnel stays |
| A switch or rebind cuts another session | Decisions 3 and 4 | A tunnel held open on a session port survives `session switch` and a rebind of the main listener |
| The last captures of a session that is not the default are lost at exit | Decision 6 | Capture, quit at once, restart, count |
| A stopped quit leaves listeners down | The resume function (decision 6) | Fail the save on quit; the main listener and the session ports answer again |
| A workspace answer from another session is adopted | Decision 8 | A refused write returns no other session's snapshot |
| A delete right after a close is refused | Close closes relays through their own handles and flushes the pending save (decision 6) | Capture over a WebSocket, close the port, delete at once |
| A full save of one large session delays the others | None: saves share one slot (`PERSIST_IN_FLIGHT`) with a two-second debounce. Captures are journaled as they arrive, so snapshots are delayed, not lost. | Measured in phase 1, and changed only if it hurts |
| Moving the main listener stalls API calls for every session | None: activation holds the `active_session` write lock while it saves the session it leaves and loads the next, and every call that starts with `state.session()` waits. Traffic on session ports keeps flowing, because it uses the registry's context. | Measured in phase 1 with a large session; accepted unless it hurts |

## Left to the builder

- The shape of the listener registry and the name of the task-local.
- How the exclusive bind tells a live listener from a port that is only
  waiting out its last connections, so that closing and opening again works at
  once.
- How TCP capture learns of a port opened after it was armed, and the order of
  the port locks with `proxy_rebind_lock`.
- Whether a CONNECT tunnel on a session port that is neither TLS nor HTTP needs
  more than `arm_tcp_capture` gives the default session.
- The address the special-host page prints when it is read through a session
  port, and the two places the UI prints the proxy address.
- The exact wording and placement of the new menu items and the one-line
  notices, within the minimal-controls convention.

## As built

### Phase 1

What the builder settled, and where the build went past the design.

- **The registry** is `SessionPorts` in `src/session_ports.rs`. Connections stay
  in the process-wide list and say what they belong to: the main listener, a
  session's port, or a session's task. No task-local was needed.
- **The exclusive bind** connects to the address first. Something that answers
  refuses the bind. `SO_REUSEADDR` is used only when the plain bind fails and
  nothing answers, which is a port waiting out old connections. The main
  listener is bound the same way now.
- **One list of own listeners** (`OwnListeners`) feeds every guard. A session
  reaches it through its runtime settings, which is how TCP capture and the
  upstream proxy, when it is used, learn of a port opened later. An address is
  announced to the list before its port is bound: a listener takes connections
  from the moment it listens.
- **Lock order**: `proxy_rebind_lock`, then `session_activation_lock`, then a
  session's operation lock, then the registry's own mutex. A rebind holds the
  activation lock while it drains.
- **A tunnel that is neither TLS nor HTTP**: opening a port gives the session's
  TCP capture the CA and turns its TCP intercept off, so nothing is held where
  no control reaches.
- **The special-host page** read through a session port prints that port.
- **Close** runs in a task of its own, so a caller that disconnects cannot
  leave it half done, and a save that fails afterwards does not make the close
  an error. Writing a number does the same.
- **Shutdown** also tells the registry how much each session a port fed holds.
  Only a full save did, so the session list showed an old count after a
  restart.
- **Measured**: moving the main listener off a 199 MB session took 0.16 s.
  Meanwhile a request through another session's port took 13 ms at most, and
  an API read 140 ms.
- **Not changed**: `sniper-cli` reports a refused `session switch` or `session
  delete` by its status alone, as it does for every session write. The reason
  is in the API's answer and in the guide.

### Phase 2

- **The launch target** is worked out in `browser_launch_target`
  (`src/api.rs`) before anything starts: the main listener for no session or
  for the session it records into, else the session's port, which the launch
  opens. `LaunchContext::for_session` carries the session and the main
  listener's address into `launch_at`.
- **A launch that fails closes the port it opened**, so a refused browser
  leaves nothing changed. A port that was open already stays open. After the
  review: only the call that opened the port closes it, and only while nobody
  else asked for the port since. What a launch refuses for what it asks (Aside
  for a session, a driver port while the proxy is exposed, a URL that is not
  http, a browser that is not installed) is refused before the port opens, so
  the session is given no number for it.
- **A browser that ends at once** is answered 200 with a warning, because a
  hand-off to a running browser looks the same. The port it opened stays open.
- **Aside** is refused by what its driver is (`shared_instance_hint`), not by
  its name, so a later driver of the same kind is refused too. With no browser
  named the saved default or the first installed one is still chosen, and a
  session's launch fails if that is Aside: name another browser.
- **Profiles** of a deleted session are removed at the delete, and by a sweep
  at start-up and before each launch for one a browser still held.
  `recover_driver_ports` reads the session directories as well.
- **Not tested with a real browser.** A script stands in for Chromium, in the
  unit tests and on the isolated instance.

### Review of phase 2

- **A browser that relaunched itself** is named by no record once the process
  Sniper started has ended. Its profile's lock is asked too, so deleting the
  session does not remove the profile under it.
- **The main listener's address** counts as a way back into Sniper only while
  that listener is bound. While it is down another program has the port, and
  that can be the application under test, reached through a session port.
  The review of phase 3 took this back for a client on another machine.
- **A tunnel that could not be recorded** is relayed, and now ends when it is
  closed. A stop waited for it, which held a session switch and a quit.

### Merged with the remote

`origin/release/0.3.6` fixed the remote-client guard on its own
(`2ffc6b5`). The merge (`2b6ee78`) keeps this design's one list of own
listeners, and takes the remote's refusal of a CONNECT to the proxy's own
listener, which now covers a session's port too: a tunnel to any proxy
listener of Sniper's gets 508, for any client.

### Phase 3

- **The proof for decision 8** is a unit test and a runtime test. A Replay
  stays in flight in a session that is not the default while a second Replay,
  a note, a workspace save and a settings change are made in it. After a
  restart every stored body is the one that was sent.
- **Activation** asks only the session the main listener leaves. A session
  with work in flight and no loaded context is refused: loading one there
  would be a second writable context.
- **No new endpoint.** `GET /api/settings?session_id=` is the window's first
  read of a session and loads its writable context. A click sends it before
  the window lets go of the session it shows, so a session that does not load
  leaves the window as it is.
- **The window's session** is `state.activeSession` in `web/app.js`, which
  keeps its name. `state.viewedSessionId` is the session the next load shows.
  A reload reads the settings and the workspace by that id, because its own
  list read can lose to a newer rows-only read.
- **Where the listener records** reaches the window through the activity rows
  (`SessionActivity.active`), read every few seconds.
- **The Capture pill** still toggles recording. It reads "Not receiving" when
  recording is on and nothing arrives; the two actions are on the indicator
  and in the empty history.
- **What stays with the default session** says so: the TCP relay answers a
  change for another session with its own message, and OAST, Service Map
  bodies and socket peers were reworded.
- **The desktop app's own webview** was checked after the review, pressed
  through the accessibility tree: the layout, the port labels, a click that
  shows a session, the indicator's menu and a row's menu, and each action
  (open a port, close it, record here). The window was behind another one,
  where the webview holds its transitions, so the colour of an indicator
  that had just changed was not seen there.

### Review of phase 3

- **Two lists of Sniper's own addresses.** A client on another machine is
  refused the main listener's address also while that listener is down
  (`OwnListeners::refused_to_remote`). The connections the listener accepted
  outlive it, and one could hold a tunnel to the address until the listener
  is back, then arrive on it as a local client. The loop guards still leave
  the address out then (`proxies`, `all`). A rebind announces the new address
  before it binds it.
- **A shutdown** tells the registry what every loaded session holds, not only
  the ones that ports fed, and writes a state save that is still queued
  (`persist_other_loaded_sessions`). A session a window worked in showed the
  counts of its last full save after a restart.
- **A session deleted by another client.** A note still queued for it is
  dropped: kept, it refused every later session change and every close. A
  session deleted while the window loads it gives way to the one the list
  names, at once.
- **What prints a feed** is read again after a change to one, even when a read
  is in flight, and redrawn after a rebind.
- **Left as it is**: a port that two failed launches shared, or one whose
  caller went away before the launch ended, stays open with no browser. It
  shows as open and closes from the session's menu.

### After phase 3: groups, and who made a session

- **A group is a name on the session** (`SessionMetadata.group`), not a record
  of its own: the sessions that carry a name are the group, and the last one
  out ends it. The session list shows sessions in no group first, then each
  group under its name, which folds (`session_groups_collapsed` in the UI
  settings).
- **Who made a session** is the name sniper-cli sends on every request
  (`x-sniper-actor`), kept as `created_by`. The UI sends none. The list draws
  it with the glyph a Replay tab draws for the same name: one definition of
  each, on `[data-actor]`.
- **Both belong to the registry**, as a session's name does. A save of the
  session carries its own copy of the record, and `update_metadata` keeps the
  registry's.
- **A group is renamed in one write** (`POST /api/session-groups/rename`):
  every session of it takes the new name, or none, which ends the group.
- **The order is the UI's.** A person drags a session beside another, onto a
  group's name or onto the list, and a group beside another. Which group a
  session is in goes to the registry; the order of sessions and of groups is
  kept in the UI settings (`session_order`, `session_group_order`). A session
  that was never dragged is ahead of the dragged ones, newest first, so a new
  session shows at the top.
- **sniper-cli** has `session group set|clear|rename|list` and
  `session create --group`. `session list` keeps its fields, which are fixed.
- **Not built**: a group change made by another client shows on the next read
  of the list, not at once. Dragging has no keyboard form; a session's menu
  moves it between groups from the keyboard.

## Constraints

- The persistence invariants in `AGENTS.md` §5: every write atomic, no fsync on
  the proxy runtime, `adopt_written_locators` after any rewrite of
  `transactions.ndjson`, workspace revisions unchanged.
- `SessionSummary` keeps its fields (saved.v1). New fields go on
  `SessionActivity` or new endpoints.
- No new dependency. `tokio::net::TcpSocket` binds without `SO_REUSEADDR`.
- Fixtures use `example.com` and loopback upstreams. No test runs against
  `~/.sniper`, and none starts a real browser.
- Captured traffic is never written to a log, an error or a temp file.
