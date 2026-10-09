# Saved HTTP Replay tab close and duplicate

These housekeeping operations affect already saved HTTP Replay tabs only. They
never send requests, connect WebSockets, hydrate bodies, or replace a workspace
with client-supplied state. Captured HTTP history and other tools are unchanged.

## CLI

Canonical operations: `replay.close` and `replay.duplicate`.

```bash
sniper-cli replay close --tab-id 'exact-tab-id' --session-id <session-uuid> --dry-run
sniper-cli replay duplicate --tab-id 'exact-tab-id' --yes
sniper-cli call replay.close --input '{"tab_id":"exact-tab-id"}' --yes
sniper-cli schema input replay.close
sniper-cli schema output replay.duplicate
```

`call` permits exactly `tab_id` (required string) and `session_id` (optional UUID
string; explicit null is rejected). Tab IDs are nonblank and at most 128 UTF-8
bytes. Leading/trailing spaces remain part of the exact ID. Labels, partial IDs,
request fields, caller-provided revisions, and unknown fields are rejected.

Both commands require `--yes`. Dry-run validates local input before discovery and
makes zero requests, including session or workspace reads. Without `session_id`,
the active session is resolved once and pinned. Explicit IDs select saved sessions
without switching the UI's active session.

## API

Read `GET /api/workspace-state?session_id=<uuid>`, then use one of:

- `POST /api/replay/tabs/close`
- `POST /api/replay/tabs/duplicate`

```json
{
  "session_id": "00000000-0000-0000-0000-000000000000",
  "tab_id": "exact-tab-id",
  "expected_workspace_revision": 17
}
```

All three fields are required. Include `expected_active_session_id` when the
selection came from the active session. Unknown fields are rejected. The server
compares the revision and optional active-session guard, transforms its current
saved state, and persists before acknowledging. A conflict applies nothing.

Only `type: "http"` or legacy empty/missing types are accepted. A missing ID,
WebSocket tab, or unknown tab type fails without a write. Close removes only the
exact tab and its saved history. If it was active, the previous pinned-first stable
visual neighbor becomes active, falling back to the next neighbor or null. The
sequence counter retains at least the previous counter and every pre-close tab
sequence, including when the final tab closes.

Duplicate preserves the saved request text, targets, response, history and label.
Only the new tab's ID, pinned flag and sequence change: a fresh UUID, false, and
one above the maximum of the existing counter and all tab sequences. Existing
focus remains unchanged.

Successful close returns exactly:

```json
{"session_id":"00000000-0000-0000-0000-000000000000","revision":18,"closed_tab_id":"exact-tab-id","active_tab_id":null}
```

Successful duplicate returns exactly:

```json
{"session_id":"00000000-0000-0000-0000-000000000000","revision":18,"source_tab_id":"exact-tab-id","new_tab_id":"11111111-1111-4111-8111-111111111111","active_tab_id":"exact-tab-id"}
```

The CLI validates the acknowledgement's exact fields, session, next revision,
target, expected focus, and fresh duplicate UUID before reporting success. It
returns only this metadata, never request/response/history content. Direct
commands return the bare object; `call` uses the ordinary success envelope with
`data` and `meta.session_id`.

## Failure handling

The CLI sends one mutation request. It never retries conflicts, response loss,
malformed/misattributed acknowledgements, or redirects, and never falls back to a
whole-workspace write. Mutation failures report `retryable: false`; ambiguous
outcomes report `details.outcome: "unknown"`. Server error bodies are not echoed
because they may contain saved traffic. Inspect the chosen session's saved tabs
before deciding on another action. These operations are separate from `saved.v1`
and have no durable operation receipts or automatic deduplication.

## Desktop draft conflicts

A clean desktop workspace follows an external saved-tab close. If the desktop
has a dirty or active draft conflict, it preserves the current editor and stops
workspace autosave/unload writes until the conflict is explicitly reconciled.
Copy any unsaved draft before reloading; a reload displays the saved workspace.
