# Saved rule settings and Replay labels

These commands edit existing saved configuration. They do not send requests,
connect WebSockets, forward held traffic, or change the runtime intercept switch.
Both direct commands and `call` require `--yes`; dry-run validates input without
API discovery or requests. `--session-id` selects a saved session without changing
the active session. Omission resolves the active session once and guards the write
against an intervening session switch.

## Intercept rules

Canonical operations are `capture.intercept_rule.update` and
`capture.intercept_rule.set_enabled`.

```bash
sniper-cli capture intercept-rule update --id <rule-uuid> --scope both --path-pattern /saved --dry-run
sniper-cli capture intercept-rule update --id <rule-uuid> --method GET --method POST --yes
sniper-cli capture intercept-rule update --id <rule-uuid> --host-pattern '' --clear-methods --yes
sniper-cli capture intercept-rule set-enabled --id <rule-uuid> --enabled false --yes
sniper-cli call capture.intercept_rule.update --input '{"id":"<rule-uuid>","method_filter":[]}' --dry-run
sniper-cli schema input capture.intercept_rule.update
sniper-cli schema output capture.intercept_rule.set_enabled
```

Update requires an existing rule UUID and at least one changed field:

- `scope`: `request`, `response`, or `both`
- `host_pattern` and `path_pattern`: replacement strings; empty strings clear
- `method_filter`: replacement array of strings; an empty array clears
- `clear_methods: true`: an alternative to `method_filter`, including an empty array
- `enabled`: explicit JSON boolean; false is a value, never a toggle

Omission preserves the current value. Null, unknown fields, empty patches and
invalid scopes fail. Direct CLI uses repeated `--method` values or
`--clear-methods`; `call` uses `method_filter` or `clear_methods`. Set-enabled
permits only `id`, optional `session_id`, and required `enabled`.

Both commands use `PATCH /api/intercept-rules/<uuid>` with only supplied rule
fields. Session selection and `expected_active_session_id` use the query string.
The API also accepts `session_id` in JSON and rejects a conflicting query value.
The API does not accept `clear_methods`; the CLI translates it to
`"method_filter": []`.

The server looks up the existing ID and merges while holding the session mutation
lock. Missing IDs return 404 and never create rules. Disjoint concurrent patches
preserve each other's fields; concurrent writes to the same field are applied in
lock order. Persistence completes before success. The response is the complete
updated rule; CLI output also includes the selected `session_id`. Repeating an
enabled assignment preserves the requested value.

## HTTP and WebSocket tab labels

```bash
sniper-cli replay update --tab-id 'exact saved tab ID' --label 'Saved conversation' --dry-run
sniper-cli replay update --tab-id 'exact saved tab ID' --label '' --yes
sniper-cli call replay.update --input '{"tab_id":"11111111-1111-4111-8111-111111111111","label":"Saved conversation"}' --yes
```

A label-only update uses `POST /api/replay/tabs/set-label` with required
`session_id`, exact `tab_id`, `expected_workspace_revision`, and string `label`.
`expected_active_session_id` is included when the selection was implicit. Unknown
fields, missing IDs and unsupported tab types fail. Only HTTP (including legacy
empty types) and WebSocket tabs are accepted.

The server collapses whitespace and takes the first 80 Unicode scalar values
(combining marks count separately). Empty
labels clear the custom label. It changes only the label in its saved workspace,
then performs the existing revision-checked atomic workspace persistence. Requests,
responses, frames, queues, editor state, ordering, pinning, selection, and other
tools are preserved. Revision/client bookkeeping follows the existing saved-tab
metadata update convention. Repeating a label leaves the same label but advances
the revision and requires a fresh revision.

The desktop UI preserves existing saved labels up to this scalar limit when
loading, copying, or renaming tabs. Its inline name input retains the existing
80 UTF-16-code-unit typing limit, which can allow fewer than 80 emoji.

The API responds with `session_id`, the new `revision`, and the full saved `tab`.
The CLI preserves `replay.update` output: the full selected tab plus `session_id`.
That output may include saved traffic, so review it before sharing.

Combining a label with request-file, stdin, scheme, host or port inputs retains
the existing HTTP-only update path. A WebSocket tab rejects those inputs before
reading a request file or stdin and before writing. No WebSocket payload-editing
or execution operation is added.

## Conflicts and uncertain responses

A stale workspace revision or active-session guard rejects the write. Neither
CLI path automatically retries or falls back to creation. A lost response may
mean the write committed: reread the selected session and review current state
before deciding on another write. These operations have no `saved.v1` receipt or
exactly-once retry contract.

A malformed, incomplete, or mismatched success acknowledgement produces
`INVALID_RESPONSE` with `retryable: false` and `details.outcome: "unknown"` rather
than a fabricated rule or tab. The CLI checks fields emitted by the response
serializer, including nested saved history, while accepting additive fields and
omitted nullable or serializer-skipped fields. Inspect current state before any
deliberate retry; acknowledgement validation does not establish that a write
was rolled back.
