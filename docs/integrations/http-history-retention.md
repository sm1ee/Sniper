# HTTP history retention

Each session has one saved retention policy, shared by Capture → Settings →
HTTP History and the CLI: keep the newest N rows, or Off. It is **Off by
default**, including for older sessions, and only an explicit setting turns it
on.

```bash
sniper-cli capture http retention get --session-id <session-uuid>
sniper-cli capture http retention set --max-entries 10000 --session-id <session-uuid> --dry-run
sniper-cli capture http retention set --max-entries 10000 --session-id <session-uuid> --yes
sniper-cli capture http retention set --off --session-id <session-uuid> --yes
sniper-cli call capture.http.retention.set --input '{"max_entries":10000}' --dry-run
```

N is 1–4294967295. In `call` input, pass either `max_entries` (an unsigned JSON
integer) or `off: true`, and optionally `session_id`. Writes need `--yes`;
`--dry-run` is offline and cannot predict how many rows would be deleted.

## What gets deleted

N counts the whole history; cleanup deletes the oldest unprotected rows first.
Rows in progress and originals referenced by Replay tabs saved before cleanup
are protected, so the total can stay above N. Saving a tab later does not bring
back a deleted original. If workspace durability is uncertain, nothing is
deleted. Turning retention Off stops deletion but restores nothing.

Disk space freed by a policy change is reclaimed promptly. At the target, each
new row deletes an old one and that space is reclaimed at the next session
rewrite (after 64 MiB of journal or deleted rows), so `disk_cleanup_pending` can
stay true during capture.

## Responses

Responses contain `session_id`, `config_token`, `config_revision` (a decimal
string), `policy` and `status`. Writes add `changed`: whether the policy
changed, not a deletion count. A saved policy does not mean cleanup is done:

- `total_count`, `protected_count`: current counts
- `pending`: work remains or disk cleanup is queued
- `disk_cleanup_pending`: disk cleanup remains
- `blocked_reason`: null, `protected_records`, `workspace_durability_uncertain`,
  `persistence_error` or `record_identity_conflict` (legacy rows share a UUID;
  cleanup stays pending and Sniper does not rewrite them)

## Writes

An explicit session UUID works without activating that session. Without one, the
CLI pins the active session and fails the write if it changes. Each write sends
a fresh `config_token` in one compare-and-swap request. The CLI never retries,
follows redirects or reads back; an uncertain write reports `retryable: false`
and an unknown outcome, so run `capture http retention get` on the same session
before writing again.

## API

`GET /api/transactions/retention?session_id=UUID` returns the policy and status;
without `session_id` it uses the active session. `POST` takes the same path and
query, plus `expected_active_session_id` when relying on the active session. The
body holds `expected_config_token`, `policy` and an optional `session_id` that
must match the query's:

```json
{"expected_config_token":"<token from the pinned GET>","policy":{"mode":"keep_newest","max_entries":10000}}
```

The other policy is `{"mode":"off"}`.

| Status | Cause |
| --- | --- |
| 400 | Malformed JSON, or the query and body name different sessions |
| 409 | Stale token, or the active session changed |
| 422 | Invalid policy, wrong field type, or unknown field |
| 428 | `expected_config_token` is missing |
| 500 | The policy could not be saved; no cleanup runs |
