# Saved-data contract v1

The opt-in `saved.v1.*` operations manage already saved HTTP records and session
names. They do not send requests, change capture/runtime settings, or operate
Replay, Fuzzer, Scanner, or other active testing features. Existing commands,
legacy array output, and the `2026-06-22` call envelope remain unchanged.

Inspect supported input and successful `data` output schemas with:

```sh
sniper-cli schema input saved.v1.http.list
sniper-cli schema output saved.v1.http.list
sniper-cli manifest
```

The seven supported operations are:

| Operation | Purpose |
| --- | --- |
| `saved.v1.http.list` | Bounded saved HTTP summary page |
| `saved.v1.http.select` | Review IDs/count and a session-bound selection token |
| `saved.v1.http.delete` | Delete explicit IDs or a reviewed filtered selection |
| `saved.v1.http.clear` | Clear saved HTTP records in an explicit session |
| `saved.v1.session.list` | Bounded saved session page |
| `saved.v1.session.rename` | Rename an explicit saved session |
| `saved.v1.operation.get` | Read a durable mutation receipt |

Other commands do not gain this contract or receipts. HTTP detail/body reads,
annotations, session creation/deletion, and active session switching retain their
existing interfaces. The v1 HTTP list intentionally has one stable descending
sequence order and no filters; use select to review metadata filters.

## Pages

```sh
sniper-cli call saved.v1.http.list --input '{"limit":50}'
```

`data` contains `contract_version`, the resolved `session_id`, `items`, `limit`,
`has_more`, and `continuation`. Defaults are 50 items; allowed limits are 1–200.
The first request resolves the active session once when `session_id` is omitted.
A page never mixes sessions. Existing summary fields remain intact.

If `has_more` is true, send the returned continuation object unchanged:

```json
{"continuation":{"session_id":"00000000-0000-0000-0000-000000000000","store_generation":"11111111-1111-1111-1111-111111111111","before_sequence":42,"limit":50}}
```

Do not combine `continuation` with top-level `session_id` or `limit`. An exhausted
page has `has_more:false` and `continuation:null`. Empty and exact-limit final
pages terminate the same way. Changing the active session does not redirect a
continuation. Newer inserts do not enter subsequent pages of that traversal.
Deletion can remove rows between pages: this is a live keyset traversal, not a
snapshot. Store reload/restart expires HTTP continuations with the typed
`STALE_CONTINUATION` error, preventing reused sequence numbers from silently
admitting new records into an old traversal. Start a new listing deliberately.

Session listing uses ascending UUID order. Its continuation is an input object
containing `after_id` and `limit`; pass that object directly as the next input.
Session additions/removals can change later pages. A session page does not imply
that its `active` flag or counts remain unchanged after it was read.

Selection previews intentionally return the complete selected ID set and a
count/token, not a page of summaries. A very broad filter can therefore have a
large preview. No deletion is authorized by a list continuation.

The CLI rejects structurally valid read responses that do not match the request:
explicit-ID previews must return the same UUID set, page limits must match the
requested or default limit, and continuation pages must respect the requested
cursor boundary. HTTP next cursors also retain the supplied store generation.
Pages have unique IDs in their documented order. UUID spelling case and explicit
selection input order do not change identity. A mismatch returns
`INVALID_RESPONSE` without presenting the rows as successful data; the CLI does
not automatically retry the request. These checks validate the response, not a
snapshot guarantee for a live traversal.

## Mutations and receipts

Every v1 mutation requires `session_id` and a caller-chosen UUID `operation_id`.
Generate and retain the operation ID **before** sending the request. The existing
CLI `--dry-run` / `--yes` confirmation gate still applies. Dry run validates input
without contacting the API, resolving selections, or reserving the ID.

```sh
sniper-cli call saved.v1.http.delete --dry-run --input '{"session_id":"00000000-0000-0000-0000-000000000000","operation_id":"22222222-2222-2222-2222-222222222222","ids":["11111111-1111-1111-1111-111111111111"]}'
```

After review, `--yes` applies that same request. Filtered deletion additionally
requires the selection token returned by `saved.v1.http.select`; changed matches
or missing explicit IDs reject the entire selection. Clear accepts neither IDs
nor filters and affects only saved HTTP records in the explicit session.

The result has `contract_version`, `receipt`, and `replayed`. Receipt fields are
fully described by the output schema. `receipt.outcome` is authoritative:

- `applied`: the mutation and its result receipt were durably acknowledged
- `not_applied`: this attempted mutation definitively made no change
- `unknown`: evidence is insufficient to establish the mutation's outcome

`ok:true` means a valid receipt or read result was returned. It does **not** imply
that `receipt.outcome` is `applied`. Check that field before reporting success.

A durable unknown intent is saved before starting a mutation. The operation ID
is bound to the operation name, explicit session, and validated input. Reusing
that ID with identical input returns the existing receipt and **never runs the
mutation again**, even when its outcome is unknown. Different input gives
`OPERATION_CONFLICT`. Object key order is ignored; array order and exact string
values are part of input identity. Replaying a clear cannot remove newer rows.

Receipt files are separate from saved session contents, so later session changes
do not remove the operation record. They persist across runtime restarts, for the
lifetime of this data directory. They contain a hash of input, outcome metadata,
counts, or renamed session metadata; captured HTTP contents are not copied into
them. There is no automatic retry, expiry, cleanup, or recovery mutation.

If a response is lost or a request times out, query the original ID:

```sh
sniper-cli call saved.v1.operation.get --input '{"operation_id":"22222222-2222-2222-2222-222222222222"}'
```

Lookup returns `found`, `outcome`, and nullable `receipt`. Missing receipts mean
`found:false,outcome:"unknown"`, not proof that no action happened. Pending
operations remain unknown after an interruption; the server does not infer
success from rows being absent or reapply a deletion. Final-receipt persistence
failure also reports unknown. Inspect saved data and decide deliberately; do not
silently substitute a new ID. Mutation calls are serialized, while receipt
lookup remains available during a pending mutation.

## Schemas and typed errors

All v1 inputs reject unknown members, explicit null optionals, malformed UUIDs,
invalid limits, and incompatible combinations. The CLI and server run the same
schema-based validator. The CLI validates successful output against the
published schema before reporting it as a v1 result. An invalid/missing write
response is classified as unknown rather than automatically retried.

Schemas use JSON Schema 2020-12. Standard validators can validate structural
shape, nested properties, arrays, types, bounds, enums, and required fields.
`x-sniper-*` annotations document additional enforced semantics: unsigned JSON
integer representation (not `1.0`), UTF-8 session-name byte length, trimmed
nonblank names, ordered HTTP status ranges, and valid relative/date filters.
Session rename accepts already trimmed names of at most 256 UTF-8 bytes with no
control characters. An ordinary JSON Schema validator alone does not implement
these annotated checks; the shared runtime validator does.

The v1 CLI error envelope retains `error.code`, `message`, `hint`, `retryable`,
and `details`, with `schema_version:"saved.v1"`. `details` includes mutation
`outcome`, `operation_id`, and `session_id` when parseable. All v1 errors set
`retryable:false`; transport failure does not authorize destructive retry.
Errors are typed at their source and never inferred from matching message text.
The saved-only HTTP client disables both automatic protocol retries and redirects.
Redirects return `REDIRECT_REFUSED`; the original request's receipt must be checked.
Successful output and typed errors are checked against the original operation ID
and explicit/pinned session before their outcomes are attributed to the request.

The local API endpoint is `POST /api/saved/v1/call` with body
`{"operation":"saved.v1.http.list","input":{}}`. It returns the versioned wire
wrapper with `ok` and either `data` or a typed `error`. It remains behind the same
listener authentication and origin checks as the existing local API.
