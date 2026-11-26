# Session sidebar (step 1 of concurrent sessions)

**Goal:** Switch sessions from anywhere in one click, as Claude and Codex list
their conversations, and see which sessions are working or waiting.

**Scope:** UI plus one read-only endpoint. A click still activates the session
(`POST /api/sessions/:id/activate`), so the proxy follows the session on
screen exactly as Session ▸ Open does today. Per-session ports, view switching
without activation and agent binding are later steps.

## Server

- `InterceptQueue::held()` and `ResponseInterceptQueue::held()`: entries in
  each queue, the same entries the Intercept tab lists.
- `SessionContext::activity()`: running kinds (`fuzzer`, `scan`, `recon`) from
  each store's `is_running()`, and held = request + response intercepts + TCP
  reads paused for a decision (`tcp_capture.policy().paused_count`).
- `AppState::session_activity()`: one entry per registry session
  (`id`, `name`, `running`, `held`); sessions not loaded report nothing.
- `GET /api/sessions/activity`. No CLI command: agents read job state from
  `fuzzer`, `scan` and `recon` already.

## Client

- Top strip: icon button before the main tabs toggles the sidebar
  (`aria-expanded`, `aria-controls`). Saved app-wide as
  `session_sidebar_hidden` in `AppUiSettingsSnapshot`.
- Sidebar column between the top strip and the status bar, left of the
  workspace (`.app-shell` grid gains a column). Header "Sessions" and a
  New session button that opens a name field at the top of the list.
- Rows newest created first: name, scope or top hosts below it, then status:
  held count (Findings badge look), running ring, finished dot.
- Click a row: `activateSessionById`. Right-click: the session menu; Rename
  edits in the sidebar row.
- `init` reads activity every 3 s, one read at a time, shown or not, so a job
  that stops while the list is put away still marks its session. A job that
  stops in a session not on screen marks it finished until opened. A list that
  differs in ids or names from `state.sessions` is reloaded with
  `loadSessions({ preserveWorkspaceOwner: true })`.
- Rows are not redrawn while a name is typed in the sidebar: a new field would
  lose IME composition and undo.

## Not in this step

- Keyboard switching: ⌘1–6 tags HTTP history rows; a session shortcut needs
  its own choice.
- ⌘K session search.
