# Saved HTTP Replay tab housekeeping

These operations close, duplicate and pin saved HTTP Replay tabs. They send no
requests and never replace a workspace with client-supplied state.

## CLI

The canonical operations are `replay.close`, `replay.duplicate` and
`replay.set_pinned`.

```bash
sniper-cli replay close --tab-id 'exact-tab-id' --session-id <session-uuid> --dry-run
sniper-cli replay duplicate --tab-id 'exact-tab-id' --yes
sniper-cli replay set-pinned --tab-id 'exact-tab-id' --pinned true --yes
sniper-cli call replay.set_pinned --input '{"tab_id":"exact-tab-id","pinned":false}' --dry-run
```

`tab_id` must match the saved ID exactly, spaces included, and is at most 128
UTF-8 bytes. `session_id` is optional, and `replay.set_pinned` also needs a JSON
boolean `pinned`; any other field is rejected. Every command needs `--yes`, and
`--dry-run` makes no requests. Without `session_id` the CLI pins the active
session; with it, the active session does not change.

## API

Read `GET /api/workspace-state?session_id=<uuid>`, then POST this body to
`/api/replay/tabs/close`, `/api/replay/tabs/duplicate` or
`/api/replay/tabs/set-pinned` (which also needs `pinned`):

```json
{"session_id":"00000000-0000-0000-0000-000000000000","tab_id":"exact-tab-id","expected_workspace_revision":17}
```

Add `expected_active_session_id` when the selection came from the active
session. The server persists the change before answering; a revision or session
conflict changes nothing. Only HTTP tabs, including legacy tabs with an empty or
missing type, are accepted.

- **Close** removes the tab and its history. If it was active, its previous
  neighbor (pinned tabs first) becomes active, else the next one, else none.
- **Duplicate** copies the tab into a new unpinned tab with a fresh UUID and
  leaves focus alone.
- **Set-pinned** changes only the flag. Repeating a value does not toggle it,
  but still advances the revision.

A success returns exactly `session_id`, the new `revision` and `active_tab_id`,
plus `closed_tab_id` (close), `tab_id` and `pinned` (set-pinned), or
`source_tab_id` and `new_tab_id` (duplicate):

```json
{"session_id":"00000000-0000-0000-0000-000000000000","revision":18,"source_tab_id":"exact-tab-id","new_tab_id":"11111111-1111-4111-8111-111111111111","active_tab_id":"exact-tab-id"}
```

The CLI checks this acknowledgement and prints only this metadata, never tab
content.

## Failures

The CLI sends one request and never retries or falls back to a whole-workspace
write. Failures report `retryable: false`, and an ambiguous outcome reports
`details.outcome: "unknown"`. There are no `saved.v1` receipts, so check the
session's saved tabs before acting again.

## Desktop app

A clean desktop workspace follows a tab closed elsewhere. If the desktop has an
unsaved or conflicting draft, it keeps the editor and stops autosaving until the
conflict is resolved; copy the draft before reloading. Pin changes made
elsewhere merge even during an edit, unless the pin was also changed locally.
