# Session ports, phase 3: the UI views a session without activating it

> Steps use checkbox (`- [ ]`) syntax for tracking. One commit for each task.

**Goal:** A click on a session shows that session and moves nothing. The window
says how traffic reaches the session on screen, and offers the two actions that
change it.

**Spec:** `docs/superpowers/specs/2026-11-19-session-proxy-ports-design.md`,
phase 3: decision 9, the rest of 8, the activation change of 4, and the browser
button of 10.

**Architecture:** The server stops refusing a write because its session is busy
away from the main listener, and stops counting the work of the session the
main listener moves to. `GET /api/settings` takes a session. In `web/app.js`
`state.activeSession` keeps its name and comes to mean the session this window
shows; `state.viewedSessionId` names the session the next load shows. The
session the main listener records into is read from the session list and from
the activity rows.

## Global constraints

- One writable context for each session. Nothing here loads a context except
  through `session_context_for_id`.
- A write that names a session is never answered with another session's
  workspace.
- A call that names no session still means the default session, and is still
  re-checked after the lock.
- The server keeps accepting `expected_active_session_id`. The UI stops sending
  it.
- `SessionSummary` keeps its fields (saved.v1). A new field goes on
  `SessionActivity`.
- Wording is the approved proposal's: "Proxy :8080", "Proxy :18081",
  "Not receiving", "Record :8080 here", "Open a port", "Close port :18081",
  "Copy proxy address".
- No new dependency. Fixtures use `example.com` and loopback upstreams. No test
  starts a real browser.

## Review focus

1. A Replay in flight in a session that is not the default, with a workspace
   save, an annotation and a settings change beside it: every write lands,
   and after a restart every stored body is the one that was sent. → V1.
2. The main listener moves to a session while the API has work in it: the work
   goes on, is recorded in that session, and no second context is loaded. → V2.
3. The session on screen is deleted by another client: the window shows the
   default session and saves nothing into it from the deleted one. → V5.
4. Another client moves the main listener while this window edits: the window
   keeps its session, its saves keep landing there, and the indicator changes
   to "Not receiving". → V4, V6.
5. A save refused for a session that is gone must not hand back the default
   session's workspace for the window to adopt. → V1.

---

### V1: Writes follow the session id

**Files:** `src/api.rs`.

- [ ] Test `writes_to_a_session_that_is_busy_away_from_the_proxy_are_stored`:
  a session that is not the default and has no port, with a Replay registered
  as in flight. A workspace save, its keepalive variant, an annotation, a
  runtime change and a second Replay all succeed. The context each used is the
  one `session_context_for_id` returns. A fresh `AppState` on the same
  directory reads back each Replay body as it was sent.
- [ ] Test `a_workspace_save_for_a_deleted_session_is_not_answered_with_another_workspace`:
  404 with no snapshot, for both handlers.
- [ ] Remove `busy_away_from_the_proxy` and its eight uses, and
  `session_proxy_work_conflict_response` if nothing else uses it. A workspace
  write whose session does not exist answers 404.
- [ ] Update the tests that pinned the refusal.

### V2: Activation leaves the work of the session it moves to

**Files:** `src/state.rs`.

- [ ] Test `the_main_listener_moves_to_a_session_the_api_works_in`: API work
  registered in the target; `activate_session` succeeds without `force`, the
  work's guard is still held afterwards, and the active context is the one the
  work used (`Arc::ptr_eq`).
- [ ] Test `a_forced_move_does_not_cut_work_in_the_session_it_moves_to`: a
  tracked task of the target survives `force`.
- [ ] In `activate_session_inner` wait for, cut and count only `current_id`.
  A target with work and no loaded context is refused, so a second context is
  never loaded beside it.
- [ ] Update the tests that pinned the refusal for the target.

### V3: Settings for a session; an event stream outlives a move

**Files:** `src/api.rs`, `src/state.rs`, `src/session.rs`.

**Interfaces:**
- `GET /api/settings?session_id=<id>`: `runtime` and `active_session` are that
  session's, and `active_session.active` says whether the main listener
  records into it. The session's writable context is loaded. 404 when unknown.
- `AppState::runtime_info_for(&self, session: &Arc<SessionContext>) -> RuntimeInfo`.
- `SessionActivity.active: bool`.

- [ ] Tests: settings for a session that is not the default return its runtime
  and summary and leave it loaded writable; unknown is 404; no session is the
  default session as before. Activity rows carry `active`.
- [ ] Test `an_event_stream_for_a_session_outlives_a_move_of_the_main_listener`:
  `should_reconnect_event_stream` is false for a named session in every case,
  and true for an unnamed stream once the default differs.
- [ ] Implement.

### V4: The window shows a session without activating it

**Files:** `web/app.js`, `tests/*.test.cjs`.

**Interfaces:**
- `state.viewedSessionId`: the session the next load shows; `null` is the
  default session.
- `viewSessionById(id)`: today's leave steps, no activate call, then
  `reloadSessionWorkspace`.
- `recordMainListenerInto(id, { force })`: the activate call; the view stays.
- `expectedActiveSessionIdForWrite()` returns `null`.

- [ ] Tests: a row click sends no activate call and loads the clicked session;
  `loadSessions` keeps the viewed session when another one is the default;
  settings and the workspace are read with `session_id`; a write carries no
  `expected_active_session_id`.
- [ ] Implement. `loadSessions`, `loadSettings` and `loadWorkspaceState` name
  the viewed session. "New session" still creates, activates and views.

### V5: A deleted or replaced session

**Files:** `web/app.js`, `tests/*.test.cjs`.

- [ ] Tests: `session_deleted` on the stream, and a session list without the
  session on screen, both show the default session without a draft flush;
  deleting the session on screen from its menu does the same.
- [ ] Implement `showDefaultSessionAfterDelete(deletedId)`.

### V6: Where the traffic comes from

**Files:** `web/app.js`, `web/index.html`, `web/styles.css`, `tests/*.test.cjs`.

- [ ] The session list runs the full height; the top strip and the status bar
  sit beside it.
- [ ] `sessionFeed(id) -> { kind: "main" | "port" | "none", port }` from the
  session list, the activity rows and the settings.
- [ ] The proxy indicator: "Proxy :8080", "Proxy :18081", "Not receiving",
  and "Offline" as today. "Not receiving" opens the two actions.
- [ ] The row of a fed session shows its port; the Session tab shows it beside
  the name, its "Open" views, and "Delete" is not offered for a fed session.
- [ ] The row menu: "Record :8080 here", "Open a port" or "Close port :N",
  "Copy proxy address". An action the server refuses is not offered.
- [ ] Capture: the pill reads "Not receiving"; the empty history names the
  session the proxy records into and offers the two actions.

### V7: What stays with the default session; the browser button

**Files:** `web/app.js`, `web/tcp-capture.js`, `web/service-map.js`,
`tests/*.test.cjs`.

- [ ] The browser button sends `session_id` for the session on screen.
- [ ] The TCP relay controls, OAST, Service Map bodies and the socket-peer
  setting say in one line that they run in the session the proxy records into.

### V8: Runtime proof, documents, deploy, review

- [ ] Isolated instance: view three sessions in turn while the main listener
  and a session port both carry traffic; nothing is cut and each request is in
  its own session. Replay, a workspace save and an annotation on a session with
  no feed, then a restart: every body is the one sent.
- [ ] The same in the desktop app's webview.
- [ ] `docs/guides/`, `docs/architecture.md`, `AGENTS.md`, the operator skill,
  the design's "As built".
- [ ] Deploy. One reviewer.
