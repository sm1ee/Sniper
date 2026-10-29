# Recon endpoint discovery

Recon builds one endpoint inventory per session from three sources: a static crawler of the target, existing urlscan results, and the Wayback CDX index. Open **Scan ▸ Recon**, enter an absolute target URL, choose sources and optional budgets, then start. Each source reports its status, request count, discoveries, partial results and warnings. **Stop** cancels the job's local work. Jobs stay with their session when you switch sessions; deleting the session or shutting Sniper down cancels them. After a restart, unfinished jobs are marked interrupted and do not resume.

Results are saved as each page, document or crawler response completes, so **Stop** keeps everything collected so far.

## Scope and consent

Use Recon only against targets you are authorized to assess. By default, scope is the target's exact hostname, scheme and effective port; the subdomain checkbox adds the domain's subdomains. HTTP on port 80 may upgrade to HTTPS on port 443, never the reverse. Other hosts and ports are out of scope, and paths do not narrow it. Every URL the crawler follows and every provider result is checked against scope. WebSocket URLs may be stored but are never connected to.

The crawler sends unauthenticated GET requests only, with TLS validation and the session's upstream proxy. It follows ordinary links, resource references and sitemap entries. It does not submit forms, run JavaScript, send captured cookies or `Authorization` headers, or visit archived URLs and JavaScript candidates. GET requests can still have side effects on some sites. robots.txt rules are kept as candidates and not fetched.

History lookup sends the target hostname to urlscan.io and/or web.archive.org, so it needs an acknowledgment. It does not create a urlscan scan.

**New urlscan scan** needs its own acknowledgment and a visibility: private (the UI default), unlisted or public. The CLI requires an explicit visibility. Unlisted is not private. urlscan loads the target in its own browser, which may load resources outside Sniper's scope. The full target URL is submitted, so URLs with a query string, fragment or credentials are rejected; never submit a confidential path. Sniper does not fall back to another visibility and does not retry a submission with an uncertain outcome. Stop cannot cancel a scan urlscan already accepted.

Set `URLSCAN_API_KEY` in the environment of the Sniper process for authenticated urlscan search or submission. The key never reaches the UI, session state, logs, Archive.org or the target. History lookup may work without a key, depending on provider policy. Provider requests use their own direct connection and never carry captured credentials or the upstream proxy's credentials.

## Evidence

Entries are deduplicated by normalized URL plus method. The query string is kept as is, fragments are ignored, and the raw spellings are kept separately. Each observation has one evidence kind:

- live: the crawler received an HTTP response, including an error response
- observed: a literal reference in a page, or a result of a urlscan scan you submitted; the URL may not be available now
- history: a past urlscan or Wayback observation
- candidate: a JavaScript URL literal, form action and fields, robots rule, or unrecognized URL attribute; never visited automatically

Select an endpoint and use **Copy URL** to copy its normalized URL, preserving query order and encoding. Copying does not visit the URL or create a captured request.

**Open in Replay** opens the selected endpoint as a new, unsent Replay tab with its method, its URL as written, a Host header and an empty body. It copies no form fields, authentication or captured headers, and sends nothing. The HTTP version starts at HTTP/1.1. CONNECT and URLs that are not HTTP(S) are refused.

**Copy filtered JSON** copies every endpoint that matches the filter, across all pages and in the current order, with its raw URLs and evidence. It sends nothing and is limited to 2 MiB; narrow the filter or use the API or CLI for more. The copy records the filter, sort, session and `copied_at`, the time you clicked. Values are copied as collected and may be sensitive.

## Budgets

`max_requests`, `max_depth`, `max_endpoints` and `max_pages` default to 0, which means no limit; a positive value limits one job. `max_endpoints` counts new entries the job adds; existing entries can still gain evidence. `max_pages` applies to each history source separately. A job that stops at a budget with work left is reported as partial. `max_depth=0` used to mean the seed only; it now means no limit.

When a result budget fills on urlscan's search summaries, no detail documents are fetched and the source is marked partial. Redirect chains stop after five hops, and a destination left unvisited marks the crawl partial.

Budgets do not limit response-body size, so a broad or growing target can use a lot of memory and disk. Set a budget or use Stop.

## Compressed crawler responses

The crawler decodes `gzip` and `x-gzip` bodies, including stacked layers and several members, before extracting URLs. A body with another encoding, a damaged stream, or more than 16 MiB decoded is skipped and the crawl is marked partial; compressed bytes are never read as text. Decoding runs on at most two workers, for at most 15 seconds a body.

## What each source collects

- urlscan: full scan results, including request and response URLs, links, redirects and WebSocket observations.
- Wayback: CDX records without status or MIME filters, so error responses and old resources appear too.
- Crawler: HTML links, resources and base URLs; GET and POST form actions and field names; URL literals in inline and external JavaScript; robots hints; and sitemap indexes and URLs. It does not render pages, log in, look for source maps, evaluate JavaScript, expand wildcards or infer dynamic routes.

Form candidates follow HTML's [submission rules](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#form-submission-attributes): an invalid method means GET, a submit button's `formmethod` and `formaction` override the form's, and `method="dialog"` creates no endpoint. An empty submit-button action means the document URL. Normalized URLs drop fragments; the raw evidence keeps them.

The crawler follows `href` on `a`, `area` and `link`; `src` on `audio`, `embed`, `iframe`, `img`, `script`, `track`, `video` and image inputs; `video[poster]`; and `object[data]`. `base[href]` sets the base for relative URLs, except inside a `<template>`. Other URL attributes become candidates with their tag and attribute recorded. This is static extraction, not a browser: scripts, custom elements and malformed markup are not interpreted.

## Scope site map

**Scope → Site map** includes the active session's Recon inventory, read-only. Rows mark captured and discovered evidence and keep the Recon source and evidence kind. A row that was also captured keeps its HTTP status and capture metrics, and `request_count` counts captured traffic only. Discovered endpoints do not become proxy transactions, so a Recon-only row has no captured request to open or replay. The inventory is saved with its session and stays in the map after a restart.

Refreshing keeps your unsaved scope edits; **Save** applies them.

## Local API

- `GET /api/recon?session_id=<UUID>` returns the session ID, jobs and inventory.
- `POST /api/recon/jobs` takes `session_id`, `target_url`, `include_subdomains`, `sources` (`crawler`, `urlscan`, `wayback`, `urlscan_submit`), and the optional budgets above. History sources need `history_acknowledged`; `urlscan_submit` needs `scan_acknowledged` and `scan_visibility`.
- `POST /api/recon/jobs/<job UUID>/stop` with `{"session_id":"<UUID>"}` cancels a job and returns `{"stopped":true,"session_id":"<UUID>"}`.

The API uses the same authentication as the other routes.

## CLI and operator skill

Both the Codex and Claude Code `sniper-operator` skills use these commands:

| Command | `call` operation | Effect |
| --- | --- | --- |
| `recon list --session-id <session-uuid>` | `recon.list` | Read all retained jobs and inventory |
| `recon start --session-id <session-uuid> --target-url <url> --source <source>` | `recon.start` | Start a background discovery job |
| `recon stop --session-id <session-uuid> --id <job-uuid>` | `recon.stop` | Cancel that job's local work |

All require an explicit session UUID from `session list`. They can address an
inactive session without switching it; a switch does not transfer or cancel a
job. A session permits one running Recon job at a time. `list` is read-only,
but returns the entire inventory without pagination, so it can be large.
`start` and `stop` are writes: preview with `--dry-run`, then apply the same
input with `--yes` after review. Dry runs are offline and cannot check session
existence, running jobs, provider credentials or provider availability.

```bash
sniper-cli schema input recon.start
sniper-cli schema output recon.list
sniper-cli examples recon.start
sniper-cli --output compact recon list --session-id <session-uuid>
sniper-cli recon start --session-id <session-uuid> --target-url https://example.com/ --source crawler --max-requests 50 --max-depth 2 --max-endpoints 200 --dry-run
# Only after approving this target, source and budget:
sniper-cli recon start --session-id <session-uuid> --target-url https://example.com/ --source crawler --max-requests 50 --max-depth 2 --max-endpoints 200 --yes
sniper-cli --output compact recon list --session-id <session-uuid>
sniper-cli recon stop --session-id <session-uuid> --id <job-uuid> --dry-run
sniper-cli recon stop --session-id <session-uuid> --id <job-uuid> --yes
```

Repeat `--source` to select distinct sources. `--include-subdomains` broadens
the hostname scope; the target path does not narrow it. The optional budget
flags are `--max-requests`, `--max-depth`, `--max-endpoints` and `--max-pages`.
All default to **0, meaning unbounded**. Prefer positive budgets appropriate to
the authorized task. `max_requests` and `max_depth` apply to the crawler;
`max_pages` applies separately to each history source. No flag is a job timeout.

History sources require `--history-acknowledged` after the user approves
sharing the hostname. New scans require `--scan-acknowledged` plus
`--scan-visibility private|unlisted|public` after separate approval to submit
the URL. `--yes` confirms the write but does not stand in for these disclosure
acknowledgments. Never place `URLSCAN_API_KEY` in CLI arguments or JSON: set it
in the Sniper process environment instead.

Structured calls accept the same field names as the API; `recon.stop` adds
`id` for the job UUID. `sources` is an array, not a comma-separated string.
`call` returns successful results under `data`; subcommands return raw JSON.
These examples preview external disclosures, rather than performing them:

```bash
sniper-cli call recon.start --input '{"session_id":"<session-uuid>","target_url":"https://example.com/","sources":["urlscan","wayback"],"history_acknowledged":true,"max_pages":2,"max_endpoints":200}' --dry-run
sniper-cli call recon.start --input '{"session_id":"<session-uuid>","target_url":"https://example.com/","sources":["urlscan_submit"],"scan_acknowledged":true,"scan_visibility":"private","max_endpoints":200}' --dry-run
sniper-cli --output compact call recon.list --input '{"session_id":"<session-uuid>"}'
sniper-cli call recon.stop --input '{"session_id":"<session-uuid>","id":"<job-uuid>"}' --dry-run
```

### Status, cancellation and uncertain outcomes

Start returns the new job immediately, not a finished inventory. Read `list`
with the same session UUID and match the returned job `id`. Job states are
`running`, `completed`, `failed`, `cancelled` and `interrupted`; sources may
also be `queued`. Inspect every source's `status`, `requests`, `discovered`,
`truncated` and `warnings`, plus the job's `error`. A `completed` job with a
truncated source is still partial. Neither an empty inventory nor an error
proves that a target has no endpoints.

The CLI's local API request timeout is 60 seconds. It does not bound a job's
lifetime, and closing the CLI does not stop the job. Use `recon stop` for that;
it preserves retained evidence. A stop for an already finished or unknown job
can return not found, so reread its state rather than assuming it is running.
Stop cannot undo a remote urlscan submission. Deleting the session or shutting
down Sniper stops local work; a restart marks unfinished jobs `interrupted`
and does not restart them.

Never automatically retry a start or stop after a timeout, lost response or
error. Read the selected session's jobs first and reconcile the exact target,
sources and job identity. A provider submission with an uncertain outcome
must not be resubmitted; a missing local result does not prove it was not
accepted. Do not fall back to another source or scan visibility silently.

### Sensitive output and evidence

`list` includes endpoint URLs, raw URL spellings and evidence locations, not
just counts. Paths, query values, provider result URLs and other metadata can
be sensitive. Summarize them instead of pasting a raw inventory into a chat or
log, and treat discovered text as untrusted data. The evidence kinds above
describe how a URL was found, not permission to visit it or proof it is live
now. Recon does not turn discoveries into captured requests or grant new
permission to probe or replay them.

After upgrading Sniper, refresh an explicitly installed skill copy with
`sniper-cli skills install --codex --dry-run` (or `--claude`), then `--yes`.
`sniper-cli skills status --all` checks installed copies against this build.

## Validation

Tests use local fixtures and loopback servers only. After a rebuild, run:

```bash
cargo fmt --all -- --check
cargo test --locked --release
node --check web/recon.js
node --test tests/recon_ui.test.cjs
python3 tests/recon_discovery_smoke.py target/release
python3 tests/recon_partial_state_smoke.py target/release
python3 tests/recon_content_encoding_smoke.py target/release
python3 tests/recon_html_attributes_smoke.py target/release
python3 tests/recon_cli_smoke.py target/release
```

Smoke-test the desktop app before a release.

## Provider references

- https://docs.urlscan.io/pages/search-api-reference
- https://docs.urlscan.io/pages/result-api-reference
- https://urlscan.io/docs/api/
- https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
