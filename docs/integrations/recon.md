# Recon endpoint discovery

Recon builds one endpoint inventory per session from three sources: a static crawler of the target, existing urlscan results, and the Wayback CDX index. Open **Scan ▸ Recon**, enter an absolute target URL, choose sources and optional budgets, then start. Each source reports its status, request count, discoveries, partial results and warnings. **Stop** cancels the job's local work. Jobs stay with their session when you switch sessions; deleting the session or shutting Sniper down cancels them. After a restart, unfinished jobs are marked interrupted and do not resume.

Completed history pages and urlscan result documents are saved to the inventory while collection is still running. Stop keeps those checkpoints; only unfinished provider work may be absent. Checkpointed discoveries retain historical evidence and do not become captured requests or prove that an endpoint is live.

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

**Open in Replay** appends an unsent HTTP draft from the selected normalized URL and inventory method. It preserves raw path/query spelling and explicit authority ports, adds only Host, and leaves the body empty. It does not infer POST fields from evidence, copy authentication or captured headers, look up/create a transaction, send traffic, or start Fuzzer. The existing notice identifies the constructed draft and fixed source/evidence categories; complete evidence remains in Recon. Review the destination, headers and body before sending; availability and an original request/protocol are not established. HTTP/1.1 is an editable default, not an observed protocol. Replay’s existing explicit Fuzzer action remains separate.

The action requires a current loaded selection, with no read, mutation or load error. Stale/detached/session-reset actions do nothing. It preserves a current owned Replay editor (including unfinished raw text); invalid target/version or unfinished hex edits must be resolved before retrying. Stale hidden editor controls are not imported. Unknown/invalid methods, CONNECT and unsafe/non-HTTP(S) URLs are refused, not repaired. Existing 2 MiB request-text/editable-message, 4 KiB target-field and 512-tab limits apply without truncating the inventory. This does not guarantee an already nearly-full aggregate workspace can be saved; normal workspace persistence/error handling still applies.

**Copy filtered JSON** copies every matching endpoint in the current sort order, across all pages, with its raw URLs and all retained evidence. It uses the loaded inventory without sending requests. Empty results, loading, pending mutations and failed refreshes disable the action. The copy is limited to 2 MiB of UTF-8 JSON, checked before constructing the export; oversized or malformed results are refused as a whole. Narrow the filter or use the full API/CLI inventory instead. This is a copy limit, not a collection or retained-inventory limit.

The payload records the filters, sort, session and local click time (`copied_at`), not a server freshness time. Session-wide diagnostic counts use fixed status/source categories, with unknown labels counted generically; they do not attribute jobs to individual endpoints. Global job targets and raw warnings/errors are omitted. An absent response-truncation flag is `null` (unknown), not evidence of completeness. Selected URL/query/evidence values are copied faithfully and may be sensitive.

A pending JSON copy keeps its click-time bytes through paging, row selection and background refreshes. Changing filters/sort, starting or stopping a job, hiding/resetting Recon, changing session, or making a newer eligible copy retires its fallback and notices. This cannot cancel a clipboard write already handed to the platform. Individual **Copy URL** keeps its existing selection/refresh ownership rules.

## Budgets

`max_requests`, `max_depth`, `max_endpoints` and `max_pages` default to 0, which means no limit; a positive value limits one job. `max_endpoints` counts new entries the job adds; existing entries can still gain evidence. `max_pages` applies to each history source separately. A job that stops at a budget with work left is reported as partial. `max_depth=0` used to mean the seed only; it now means no limit.

urlscan retains the in-scope summaries from each completed search page before requesting its detail documents. If an explicit result budget fills on those summaries, they take priority and no further detail request is sent; the source is marked partial.

Redirect chains stop after five hops; an unvisited in-scope destination left behind by that limit marks the crawl partial. A known urlscan search-page limit is reported while that page's detail requests are still pending, not only after they finish.

Completed crawler responses and known partial-state warnings are checkpointed before the next network wait, including redirects and non-text responses. Stop keeps those checkpoints and the attempted-request count; the unfinished response or body may still be absent.

Collection budgets do not cap raw response-body bytes, so a broad or growing target can use a lot of memory and disk. Set a budget or use Stop.

## Compressed crawler responses

The crawler decodes `gzip` and `x-gzip` before static extraction, including repeated/comma-separated encoding fields, stacked gzip layers in reverse order, and concatenated gzip members. Every member must finish with a valid checksum and no trailing non-member bytes. Identity/no-encoding reading is unchanged; request headers and provider/capture decoders are unchanged.

Unsupported or invalid encodings, malformed/truncated streams, and decoding-limit failures skip extraction for that body and mark collection partial with a fixed warning. Compressed bytes are never treated as decoded text. Already observed live responses remain in the inventory, and known partial warnings are checkpointed before the next wait so Stop retains them. Empty 204/205 responses do not require a gzip stream. Unsupported encodings on parseable content are rejected as soon as the headers establish the error (or, for 204/205, the first nonempty chunk), without waiting for an unread body. Binary content outside static extraction keeps its existing handling.

New compressed-work safety limits are 16 MiB decoded output per stage (across all members), two decoding workers, and 15 seconds for queueing plus decoding after the raw body has been read. Worker slots remain occupied until cancelled work actually exits. These are not additional API collection budgets, a new identity/raw-body cap, or a bound on all queued raw-body memory. Stop cancels awaiting work and cooperatively stops running decoding; it does not publish late worker results.

## What each source collects

- urlscan: full scan results, including request and response URLs, links, redirects and WebSocket observations.
- Wayback: CDX records without status or MIME filters, so error responses and old resources appear too.
- Crawler: HTML links, resources and base URLs; GET and POST form actions and field names; URL literals in inline and external JavaScript; robots hints; and sitemap indexes and URLs. It does not render pages, log in, look for source maps, evaluate JavaScript, expand wildcards or infer dynamic routes.

Within the parsed enclosing form/action context, form candidates apply [HTML submission-method defaults](https://html.spec.whatwg.org/dev/form-control-infrastructure.html#form-submission-attributes): invalid methods use GET, omitted overrides inherit the form's method, and dialog submissions do not create HTTP endpoints. Explicit `form=id` ownership and runtime DOM changes are not resolved. These rules do not alter methods in observed provider traffic.

Literal fragment [form actions](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#form-submission-algorithm) retain their method and resolve through the document base; an exactly empty submitter action instead uses the document URL, not the parent action or `base[href]`. Newly recognized empty/fragment submitter actions require the same parsed enclosing form and submit-button context as method-only overrides. They remain passive candidates: normalized URLs omit fragments while raw URL evidence retains them. This does not change ordinary fragment-link filtering or other whitespace/malformed-action handling.

HTML URL attributes use conservative [static element/attribute recognition](https://html.spec.whatwg.org/multipage/indices.html#attributes-3): `href` on `a`, `area`, or `link`; `src` on `audio`, `embed`, `iframe`, `img`, `script`, `track`, or `video`, and image-type `input`; `video[poster]`; and `object[data]`. Parsed HTML `base[href]` sets relative-URL resolution and is not itself fetched.

For HTML (including the empty-content-type fallback), a base inside a literal [`template`](https://html.spec.whatwg.org/multipage/scripting.html#the-template-element) does not set the document base. This limited nesting guard ignores template-like text in comments and recognized raw-text bodies; an unclosed template remains open, including a self-closing-looking HTML `<template/>`. Other extracted template URLs keep their existing evidence and followability. XHTML base handling is unchanged. This does not reinterpret ordinary non-template raw-text base selection.

Other extracted URL attributes remain candidates with their tag and attribute provenance, including custom/prefixed elements, unresolved `source[src]` media-parent context, and literal SVG/MathML subtrees (including `foreignObject` children). A candidate and a recognized link to the same URL retain separate evidence. Custom-component runtime, namespace integration points, general template/inert DOM behavior and malformed-markup recovery are not interpreted: this is source extraction, not browser execution or full HTML conformance.

## Scope site map

**Scope → Site map** includes the active session's Recon inventory, read-only. Rows mark captured and discovered evidence and keep the Recon source and evidence kind. A row that was also captured keeps its HTTP status and capture metrics, and `request_count` counts captured traffic only. Discovered endpoints do not become proxy transactions, so a Recon-only row has no captured request to open or replay. The separate Recon **Open in Replay** action constructs a new draft, not a captured exchange. The inventory is saved with its session and stays in the map after a restart.

Refreshes do not replace a newer accepted runtime/site-map result. Unsaved scope edits owned by the current session are kept when refreshing or returning to Scope; **Save** still applies them explicitly.

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
