# HTTP history retention

Capture → Settings → HTTP History automatic cleanup and the CLI share one persisted
policy per session. **Off is the default**, including for existing sessions with
no saved policy. Existing default-off traffic preservation is unchanged.
Automatic deletion is an explicit, destructive opt-in; neither a history count
nor a legacy runtime memory cap enables it.

```bash
sniper-cli capture http retention get --session-id <session-uuid>
sniper-cli capture http retention set --max-entries 10000 --session-id <session-uuid> --dry-run
sniper-cli capture http retention set --max-entries 10000 --session-id <session-uuid> --yes
sniper-cli capture http retention set --off --session-id <session-uuid> --yes
sniper-cli call capture.http.retention.set --input '{"max_entries":10000}' --dry-run
sniper-cli schema input capture.http.retention.set
sniper-cli schema output capture.http.retention.get
```

`--max-entries N` accepts an integer from 1 through 4294967295. In `call` input,
use `max_entries` with an unsigned JSON integer token, or `off: true`; null,
fractions, exponent notation, zero, overflow, and conflicting choices are rejected.
The only other input is optional `session_id` (null also means active).
All writes require `--yes`. Dry-run is entirely offline and shows the exact
policy; it cannot resolve a session, inspect traffic, or predict deletion counts.

## Protection and cleanup

Keep-newest uses N as a **total-history target**, including protected records.
It deletes the oldest eligible excess rows first. In-progress rows and source
originals referenced by HTTP Replay tabs durably saved before cleanup are
protected. Pinned and unpinned saved HTTP tabs receive the same protection;
unsaved browser state does not establish durable protection. An ordinary workspace
save can accept a tab referring to an original already deleted by cleanup, but
saving that tab does not restore the original and source-dependent operations can
fail. Protected rows can leave the total above N.
When workspace durability is uncertain, cleanup fails closed. Protection does not
turn into a second allowance of N unprotected rows.

Saving a policy and finishing cleanup are separate operations. Responses contain
`session_id`, a policy-configuration `config_token`, a canonical decimal-string
`config_revision`, `policy`, and `status`:

- `total_count` and `protected_count`: current metadata counts
- `pending`: logical work remains or disk cleanup is queued
- `disk_cleanup_pending`: physical disk cleanup remains pending
- `blocked_reason`: null, `protected_records`,
  `workspace_durability_uncertain`, `persistence_error`, or
  `record_identity_conflict`

A record-identity conflict means legacy rows share a UUID and deleting that ID
would remove more rows than the excess permits. Cleanup stays pending without
automatic repair or UUID rewriting.

Writes also return `changed`, indicating whether the saved policy changed.
It is not a deletion count or evidence that disk space has been reclaimed.
Turning retention Off stops further automatic record deletion; pending disk
reclamation for already-deleted records may finish. It does not restore history
already deleted.

## Session, concurrency, and failure contract

Explicit session UUIDs work without activating the session. When omitted, the
CLI resolves the active session once, pins all subsequent requests to its UUID,
and binds the write to that active-session selection. It obtains a fresh token
and submits one compare-and-swap write, including for an unchanged policy.
Traffic counts do not change the token. It is bound to the selected session,
saved policy, and persisted configuration revision. A changed policy advances
the revision; an unchanged policy preserves it. Returning Off → On → Off does
not make an earlier token valid again.

The CLI does not follow redirects, automatically retry, or automatically read
back after an uncertain write. HTTP failure diagnostics are not printed. A lost,
malformed, mismatched, redirected, or unsuccessful write acknowledgement reports
`retryable: false` and conservatively treats the outcome as unknown. Inspect
`capture http retention get --session-id <the same session UUID>` before deciding
whether to issue another write. Retention has no `saved.v1` mutation receipt.
Successful responses validate known types, policy/token/session binding, and
`changed`; additive future fields are accepted but not printed.

Direct commands return the metadata object. `call` wraps it in `data` and returns
`meta.session_id`. `manifest`, `schema`, `examples`, help, and dry-run are offline.

## API metadata contract

GET `/api/transactions/retention?session_id=UUID` returns the saved policy and
status; omission selects the active session. POST uses the same path and session
query. Inferred-active clients additionally pass `expected_active_session_id` in
the query. The body contains `expected_config_token` and `policy`, plus an optional
`session_id`. If supplied in both the query and body, the session UUIDs must match:

```json
{"expected_config_token":"<token from the pinned GET>","policy":{"mode":"keep_newest","max_entries":10000}}
```

The other policy is `{"mode":"off"}`. Malformed JSON syntax returns 400;
well-formed JSON with an invalid policy, wrong field type, or unknown body or policy
field returns 422. A valid policy without `expected_config_token` returns 428.
Explicit query/body session UUID conflicts return 400; stale tokens or
active-session changes return 409. Policy persistence failures return sanitized
500 diagnostics. A policy-save failure must not authorize cleanup. Read the same
session deliberately to establish its current state after any uncertain result.
