# Saved rule settings and Replay labels

These commands edit saved intercept rules and Replay tab labels. They send no
traffic, forward no held requests and leave the runtime intercept switch alone.
They need `--yes`, and `--dry-run` validates offline. `--session-id` edits a
saved session without activating it; without it, the write targets the active
session and fails if that changes.

## Intercept rules

```bash
sniper-cli capture intercept-rule update --id <rule-uuid> --scope both --path-pattern /saved --dry-run
sniper-cli capture intercept-rule update --id <rule-uuid> --method GET --method POST --yes
sniper-cli capture intercept-rule update --id <rule-uuid> --host-pattern '' --clear-methods --yes
sniper-cli capture intercept-rule set-enabled --id <rule-uuid> --enabled false --yes
sniper-cli call capture.intercept_rule.update --input '{"id":"<rule-uuid>","method_filter":[]}' --dry-run
```

`capture.intercept_rule.update` changes at least one field of an existing rule
and keeps the rest:

- `scope`: `request`, `response` or `both`
- `host_pattern`, `path_pattern`: an empty string clears
- `method_filter`: replaces the list (`--method`, repeated); `[]` clears it, as
  does `clear_methods: true` (`--clear-methods`), which cannot be combined with
  `method_filter`
- `enabled`: sets the value; it never toggles

`capture.intercept_rule.set_enabled` takes `id`, optional `session_id` and
`enabled`. Nulls, unknown fields and empty patches fail.

Both send `PATCH /api/intercept-rules/<uuid>` with only the supplied fields and
the session in the query; the API has no `clear_methods`. The server merges the
patch under a session lock and persists it before answering, so concurrent
patches to different fields both survive. A missing ID returns 404 and nothing
is created. The response is the full updated rule.

## Replay tab labels

```bash
sniper-cli replay update --tab-id 'exact saved tab ID' --label 'Saved conversation' --dry-run
sniper-cli replay update --tab-id 'exact saved tab ID' --label '' --yes
sniper-cli call replay.update --input '{"tab_id":"11111111-1111-4111-8111-111111111111","label":"Saved conversation"}' --yes
```

The API is `POST /api/replay/tabs/set-label` with `session_id`, the exact
`tab_id`, `expected_workspace_revision` and `label`, plus
`expected_active_session_id` when the session was implicit. It works on HTTP and
WebSocket tabs. The server collapses whitespace and keeps the first 80 Unicode
scalar values; an empty label clears it. Nothing else in the tab changes, and
each write advances the revision. The desktop name field limits typing to 80
UTF-16 code units, so fewer emoji fit there.

The response has `session_id`, the new `revision` and the full `tab`, which can
include saved traffic; review it before sharing. Request-file, stdin, scheme,
host and port options keep the HTTP-only update path and are rejected for
WebSocket tabs.

## Conflicts

A stale revision or a changed active session rejects the write, and the CLI
never retries. A lost response may mean the write committed, so reread the
session before writing again; there is no `saved.v1` receipt. A malformed or
mismatched acknowledgement returns `INVALID_RESPONSE` with `retryable: false`
and `details.outcome: "unknown"`.
