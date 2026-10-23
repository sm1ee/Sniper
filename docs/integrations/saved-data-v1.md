# Saved-data contract v1

The `saved.v1.*` operations read and change saved HTTP records and session
names. They never send requests or change capture or runtime settings. Other
commands get no receipts, and their output and the `2026-06-22` call envelope
are unchanged.

| Operation | Purpose |
| --- | --- |
| `saved.v1.http.list` | One page of saved HTTP summaries |
| `saved.v1.http.select` | Preview matching IDs and get a selection token |
| `saved.v1.http.delete` | Delete explicit IDs or a previewed selection |
| `saved.v1.http.clear` | Clear saved HTTP records in a session |
| `saved.v1.session.list` | One page of saved sessions |
| `saved.v1.session.rename` | Rename a saved session |
| `saved.v1.operation.get` | Read a mutation receipt |

```sh
sniper-cli manifest
sniper-cli schema input saved.v1.http.list
sniper-cli schema output saved.v1.http.list
```

## Pages

```sh
sniper-cli call saved.v1.http.list --input '{"limit":50}'
```

`data` holds `contract_version`, `session_id`, `items`, `limit`, `has_more` and
`continuation`. `limit` defaults to 50 (1–200). Without `session_id`, the first
request uses the active session and later pages stay on it. HTTP pages run
newest first with no filters; use `select` to filter.

While `has_more` is true, send back the returned continuation unchanged and
without a top-level `session_id` or `limit`:

```json
{"continuation":{"session_id":"00000000-0000-0000-0000-000000000000","store_generation":"11111111-1111-1111-1111-111111111111","before_sequence":42,"limit":50}}
```

The last page has `has_more:false` and `continuation:null`. Session pages run in
ascending UUID order; pass their continuation object (`after_id`, `limit`) as
the next input. Pages are not a snapshot: newer HTTP records never appear,
deleted ones can drop out, and added or removed sessions can change later
session pages. A store reload or restart expires HTTP continuations with
`STALE_CONTINUATION`; start a new listing.

`select` returns every matching ID with a count and token, not a page, so a
broad filter gives a large preview.

## Mutations

Every mutation needs `session_id` and an `operation_id` UUID that you generate
and keep **before** sending. `--dry-run` validates offline; the same request
with `--yes` applies it.

```sh
sniper-cli call saved.v1.http.delete --dry-run --input '{"session_id":"00000000-0000-0000-0000-000000000000","operation_id":"22222222-2222-2222-2222-222222222222","ids":["11111111-1111-1111-1111-111111111111"]}'
```

A filtered delete needs the token from `select`. A delete fails as a whole if
the matches changed or an explicit ID is missing. `clear` takes no IDs or
filters.

The result holds `contract_version`, `receipt` and `replayed`.
`receipt.outcome` says what happened:

- `applied`: the change and its receipt are stored
- `not_applied`: nothing changed
- `unknown`: the outcome cannot be established

`ok:true` and exit status 0 only mean a receipt came back. Check
`receipt.outcome` before reporting success; the CLI adds a `warnings` entry for
`unknown`, `not_applied` or a missing receipt.

## Receipts and lost responses

An operation ID is bound to the operation, session and input. Sending the same
ID and input again returns the stored receipt and **never reruns the mutation**,
even when the outcome is `unknown`. The same ID with different input returns
`OPERATION_CONFLICT`; object key order does not matter, but array order and
exact string values do. Receipts last for the life of the data directory and
hold no captured HTTP content.

If a response is lost or times out, look up the original ID:

```sh
sniper-cli call saved.v1.operation.get --input '{"operation_id":"22222222-2222-2222-2222-222222222222"}'
```

The lookup returns `found`, `outcome` and `receipt`. `found:false` comes with
`outcome:"unknown"` and does not prove nothing happened. An interrupted mutation
also stays `unknown`, and the server never reapplies it. Inspect the saved data
before acting, and never repeat an uncertain mutation under a new operation ID.

## Errors

Inputs reject unknown members, explicit nulls for optional fields, malformed
UUIDs, invalid limits and incompatible combinations. Schemas use JSON Schema
2020-12; `x-sniper-*` annotations mark extra checks, such as integer form and
session names (trimmed, nonblank, at most 256 UTF-8 bytes, no control
characters). Bad input fails before any API call with `INVALID_INPUT`, exit
status 2 and `outcome: "not_applied"`.

The error envelope has `error.code`, `message`, `hint`, `retryable`, `details`
and `schema_version:"saved.v1"`; `details` carries `outcome`, `operation_id` and
`session_id` when known. Every v1 error has `retryable:false`. The CLI never
retries or follows redirects (`REDIRECT_REFUSED`), and returns
`INVALID_RESPONSE` for a response that does not match its request. After a
failed mutation, read its receipt by the original operation ID.

## API

`POST /api/saved/v1/call` with a body such as
`{"operation":"saved.v1.http.list","input":{}}` returns `ok` plus `data` or a
typed `error`. It sits behind the same authentication and origin checks as the
rest of the local API.
