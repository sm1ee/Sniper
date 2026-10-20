---
name: sniper-operator
description: Inspect captured HTTP/HTTPS traffic and debug APIs through a local Sniper proxy, driving it with sniper-cli rather than the desktop UI. Covers reviewing captured requests and responses, replaying them with changes, holding and editing live traffic, scope, fuzzer runs, WebSocket frames, match-replace rules, colour tags and notes, opening a browser already wired to Sniper, and session switching. Not for routing LLM API calls or hosting a reverse proxy.
---

# Sniper Operator

Use `sniper-cli` for all Sniper operations. Prefer `--output compact` JSON envelopes and avoid scraping the desktop UI.

## When to use

- List, create, rename, switch, or delete Sniper sessions
- Select and delete saved HTTP records, or explicitly clear one session’s HTTP history
- Read Capture HTTP or Web Socket records
- Change Scope patterns
- Open, update, or send Replay tabs
- Seed Replay or Fuzzer from Capture HTTP history
- Set Fuzzer templates and payloads, then run them
- Toggle request holding and forward or drop held requests
- List or replace auto-replace rules
- Set color tags and notes on HTTP records
- Open a browser that already sends its traffic through Sniper
- Install Sniper skills into Codex or Claude

## Workflow

1. Make sure Sniper Desktop is running, or pass `--api http://127.0.0.1:PORT`.
2. Start with `sniper-cli session list` and switch deliberately before mutating anything.
3. Prefer `sniper-cli call <operation> --input <json|@file|->` for automation; successful `call` output is wrapped in the envelope `data` field. Legacy subcommands keep raw JSON success output. On any failure, use `error.code`, `error.retryable`, and `error.hint`.
4. Prefer `sniper-cli call <operation> --input <json|@file|->` for automation, using operation names from `sniper-cli manifest`.
5. Prefer `--stdin` or `--request-file` for large raw requests.
6. Treat Replay target override fields as the connection target only. The raw `Host:` header stays in the request text.
7. For any manifest operation with `side_effect: "write"`, run `--dry-run` first and use `--yes` only after reviewing the plan.
8. Sniper preserves captured sensitive values such as cookies and authorization headers; summarize large or sensitive JSON responses instead of pasting them in full.
9. To open a browser that already sends its traffic through Sniper, run `sniper-cli capture browser open --dry-run`, review it, then run it with `--yes`, instead of asking the user to set a proxy or trust a certificate. Add `--agent` only when you will drive the browser yourself; leave it off when the person just wants a wired browser to look at, because for a Chromium-family browser it opens a DevTools port, and for BrowserOS neo its MCP server, that any local process can use (and it is refused while the proxy listens beyond loopback). `capture browser list` shows what is installed, what each driver offers, which browser opens now (`default`) and which one the person saved (`preferred`). A browser that is missing has `install_url`, its vendor's download page: point the person to it, and do not try to install it yourself. Leave the saved choice alone unless the person asks you to change it (`capture browser prefer --browser <name|auto>`, a setting that outlives this session). Without `--browser` the saved choice opens, and with none saved ego, Aside or BrowserOS neo when installed, otherwise Chrome or another Chromium-family browser, so do not assume a DevTools endpoint: read `control` in the result. `{"driver":"cdp","endpoint":…}` means attach a CDP client (Playwright `connectOverCDP`, chrome-devtools-mcp `--browserUrl`) to that endpoint. `{"driver":"ego-cli","server_name":…}` means use the ego-browser skill and put `--ego-server-name=<server_name>` on **every** `ego-browser` command; without it you drive the user's own logged-in ego and nothing is captured. `ego-browser` prints script output on stderr, so read it with `2>&1`. `{"driver":"aside-cli","command":…}` means drive it with deterministic steps through `aside repl '<code>'` only; do not run `aside "<task>"` or `aside exec`, which hand the task to Aside's own assistant on the account signed in to Aside. Aside's command cannot be pointed at a window, so make sure no other Aside is running, or what you do there is not captured. `{"driver":"browseros-mcp","endpoint":…}` (only with `--agent`) means connect your MCP client to that address (Streamable HTTP); it reaches this BrowserOS neo and no other. A `--fresh` BrowserOS neo can come back without `control` and with a warning, because the server bundled with the app may not start; open the persistent one instead. Act on the page the way a person does (snapshot, click an `@ref`, wait for the URL) rather than jumping to URLs. If a browser is already open on that profile with the same settings you get another window (`"reused": true`); with different settings the call is refused and says why, and a DevTools port cannot be added to a running browser, so quit it first or add `--fresh`. `--fresh` gives a throwaway profile (up to eight). Read each `warnings` entry and any `hint` before you rely on the browser: one that could not start is still a 200, and `control` is absent when it ended.
10. To find where a value appeared — a token, an id, a field name — use `capture http search --value <text>` instead of fetching records one by one. `capture http list --query` matches metadata only and returns nothing for a value that lives in a body. Treat an empty search as absence only when `complete` is `true`; otherwise `stopped_by` names the limit to raise.

## Passive Service Map

Use `scope service-map` (canonical `target.service_map.get`) to inventory retained
captured origins and method-plus-exact-path endpoints without sending upstream
traffic. Discover its input/output schemas and examples first. Pin `session_id`
explicitly, including for inactive sessions; no switch is needed. Optional
`in_scope_only` uses current shared scope rules. `max_records` defaults to 10000
and is capped at 50000. Optional `origin` is an exact canonical HTTP(S) origin,
without a path, query, credentials, or fragment. Optional `mime_types`,
`status_classes`, `hidden_extensions`, `hide_without_responses` and
`only_parameterized` hide rows exactly as the HTTP history filter does, for
example `hidden_extensions: ["png","css","woff2"]` to drop static CDNs;
`snapshot.filtered_rows` counts them. Omitted, they hide nothing; the GUI's saved
map filter never applies to these reads. Each `header_links[]` entry counts its
rows in `request_count` and sorts them in `request_kinds` (`api`, `navigation`,
`frame`, `script`, `static`, `other`, from `Sec-Fetch-Dest`, else the response
type). A page's image loads declare Referer too, so read the `api` and
`navigation` counts before calling a link a service relationship.
`cors_allowed_count` counts rows whose response allowed the source origin (or
`*`) to read it; `cors_credentials_count`, those that also allowed credentials.
Both describe responses, not a confirmed cross-origin read.
`front_technologies` on an origin lists the front-end frameworks, CMSs, UI
kits, libraries and analytics that retained scripts, pages and asset URLs name
(banners, runtime values such as `window.next`, markup such as `ng-version`,
generator meta, CDN `package@version` paths), with `category` and a `version`
only when one was named; an asset's goes to the page that loaded it. `clients`
lists the clients each row's User-Agent names (fixed names by `kind`: browser,
webview, app, tool, library, bot, unknown), with rows per origin and
`entry_kinds`, the rows a client sent itself with no Origin or Referer. Check `snapshot.complete`, `stopped_by`, counts, limits,
`unavailable`, `deferred`, and warnings before claiming coverage. Counts include duplicate-ID
rows, and even a complete result covers retained captures only.

Grouping numeric or UUID path segments is an inventory hint, not a confirmed
route. Header technology clues are observed headers, not verified software or an
infrastructure chain. A `redirect_instruction` is not evidence of a followed
request or service-to-service call. Origin/Referer links are header declarations,
not proven initiators. Never invent initiators, remote IPs, TLS
certificates, response-body links, or other unavailable data. Never launch a scan,
probe, replay, crawl, or autonomous exploration to complete this passive view.

Optional `technology_observations` on origins and exact evidence rows describe
literal retained response-header declarations. `reported_version` is a reported
value, not verified installed software or a vulnerability judgment. Preserve
conflicting versions separately; never select a newest or authoritative version.
`version_status: "reported"` carries the complete accepted numeric string;
`not_reported` means no version was declared, `unsupported_format` means the
declared version is unsupported, and `non_product_version` identifies a connector
version rather than an installed product version. The latter three keep
`reported_version: null`; never invent or shorten a version. An absent
`technology_observations` extension means unavailable metadata; a present empty
array means no supported declarations in that projection. Neither proves product
absence. Check omission and completeness fields before describing coverage.

The CLI defaults to catalog 2 for map and exact-row evidence reads. Explicit
`--technology-catalog-version 1` or numeric call input
`technology_catalog_version: 1` selects catalog 1. These options set only the
local API header `X-Sniper-Technology-Catalog-Version`, never an outgoing target
header. A missing response `technology_catalog_version` marker means legacy v1
coverage and triggers a warning; it does not establish catalog 2 support. A
present marker must match the requested supported catalog. Catalog selection
adds no target traffic, body reads, fallback reads, or automatic retries. Default
map and evidence reads remain metadata-only apart from scripts and pages read for
front-end technologies, and error and debug responses read for
`server_technologies`: the edge, gateway, platform, servers, backend, language,
database and OS, and the APM agents (`monitoring`), an origin's own headers,
cookie names, session ID shapes and bodies name, and
`exposure` entries (debug pages, stack traces, SQL errors, directory listings,
API documents, a backend address in a BIG-IP cookie, and from scripts and pages
a source map comment, a leaked key or JWT, or a private address, never the
matched value). They are what responses say, not verified identification. The
GUI map covers every retained row, so its counts can exceed a CLI read limited
to `max_records`; `--all-rows` (`all_rows: true`) reads every row too.
`scope service-map parameters --session-id <active-uuid> --origin <origin>
--method <method> --path <path>` lists one endpoint's parameters from its newest
retained rows, and `scope service-map openapi --session-id <active-uuid>
--origin <origin>` describes the origin's API as an OpenAPI 3.1 document: path
templates, parameter and body field names with guessed types, statuses, media
types and the credentials its rows showed, never captured values; each
operation's `x-sniper-newest-transaction` is its newest row for `capture http
get --id`. A client's `versions` are the major versions its rows named.
An origin's `auth` and an endpoint's `auth` name how requests authenticate
(Authorization scheme, API key header, session or JWT cookie, query key,
OAuth, OIDC, SAML) from names and shapes only, never values.

Ordinary-map failures use fixed CLI codes `SERVICE_MAP_BUSY`,
`SERVICE_MAP_SCOPE_WORK_LIMIT`, `SERVICE_MAP_SESSION_CHANGED`,
`SERVICE_MAP_SCOPE_CHANGED`, `SERVICE_MAP_HISTORY_CHANGED`, and
`SERVICE_MAP_BUILD_FAILED`, with `retryable:false` and no automatic retry. Busy
means wait for the running refresh to finish, then deliberately retry. For a
scope work limit, choose a smaller `max_records` / `--max-records` window or
simplify scope rules only with explicit authorization. Session, scope, or history
conflicts require a deliberate refresh of the intended session and current data;
never silently switch sessions. A failed map is not a complete empty inventory.

After a failed GUI refresh, background reads pause and any previous map is stale.
Only an explicit Refresh or actual scope/session change can resume reads.
History events, reconnecting, reopening the view, and local filters do not clear
the pause. Local origin, product/version, method, and path filters issue zero
reads. Product filters select loaded origins; their matching endpoints do not
prove endpoint-level product/version declarations. Supplementary inspections
remain separate, explicit reads and never run automatically on recovery.

For evidence, use `scope service-map-evidence --session-id <returned-session-uuid>
--evidence-id <returned-token>` (`target.service_map.evidence.get`). Pass both
fields unchanged and check `available` before using `row`. Tokens bind an exact
retained row and revision; stale or removed evidence is unavailable. Do not use a
transaction UUID detail read as a substitute: repeated IDs can resolve to another
row. The map and its evidence omit query strings, URL credentials, raw headers,
and bodies. Paths can still be sensitive; summarize responsibly.

Only if requested, add `--include-socket-peer` to exact-row evidence (canonical
`include_socket_peer: true`). The default map/evidence omit it. `socket_peer` is
present only after successful exact-token validation: `observed` has a typed
IP/port, `unavailable` records `remote_addr_unavailable`, and `not_recorded` has
no observation without claiming why. A socket peer may be a proxy, CDN or shared
endpoint; never infer origin ownership, IP edges, or a backend chain. Do not
probe, aggregate peers, enable capture, or use UUID-only fallback for this read.

`capture http upstream-peer get --session-id <active-uuid>` reads settings;
`set --session-id <active-uuid> --enabled true|false --yes` explicitly saves the
switch. Canonical names are `capture.http.upstream_peer.get/set`; both require
`session_id`, and set requires boolean `enabled`. Capture is Off by default and
active-session-only. Dry-run is offline. One pinned GET obtains a feature-bound
token and one fenced POST saves; no automatic retry or uncertain-write readback.
After uncertainty, deliberately read the same active session before another save.
Eligibility is frozen before the first send; eligible in-flight ordinary HTTP(S)
responses may complete after Off, while initially ineligible requests stay so.
No Replay, WebSocket, CONNECT, rendered resources, TLS/DNS details, or backfill.
Observations persist in session files, exports and full-record JSON; Off does not
erase them. Disclose this before enabling or sharing those outputs.

For an explicitly requested one-row response-preview inspection, use
`target service-map body-references --session-id <active-session-uuid>
--evidence-id <returned-token>` (`target.service_map.body_references.get`). Both
fields are required. The session must already be active: an inactive request is
unavailable and never loads or activates the session. Do not switch sessions,
fetch UUID-only details, inspect other rows, batch-read bodies, or start target
requests as a fallback. Default map and metadata evidence reads remain body-free.

Only retained UTF-8 HTML/JavaScript previews with supported content encoding are
inspected, within the reported byte, row, candidate, origin, and offset limits.
No decompression, Base64 decoding, document parsing, or JavaScript execution is
performed. Check `available`, `status`, `complete`, `reasons`, both truncation
flags, and counts. `scanned` covers only `literal_absolute_http_urls`; `partial`
means incomplete, and `unsupported`/`unavailable` must not be treated as empty
successful coverage. Output contains canonical origins and retained UTF-8 preview
byte offsets, never body text, snippets, query strings, paths, or credentials.
Offsets are not full-body or wire offsets. Literal references do not prove calls,
followed links, ownership, or service dependencies; never add them to observed
traffic counts or silently infer an architecture.

For an explicitly requested comparison of retained socket observations, use
`scope service-map socket-peer-matches --session-id <active-session-uuid>
--evidence-id <returned-token>`
(`target.service_map.socket_peer_matches.get`). The exact source must already
have an eligible recorded direct-route address. This read never enables capture
or accepts an arbitrary IP, hostname, or URL. It matches the stored address
family, IP and port exactly; different ports, proxy routes, unknown routes and
interface-ambiguous addresses are not grouped. No DNS, TLS, body, header or
upstream request is performed. Existing retained observations can be inspected
while capture is Off.

Check the retained-versus-considered row counts, latest-sequence window,
`source.in_window`, fixed reasons, output bounds and per-origin sample omissions.
The default is 10,000 retained rows and the hard maximum is 50,000; at most 100
origin groups, three exact samples per group and 256 KiB are returned. The anchor
is separate from other matching-row counts. Duplicate UUID rows count separately.
Do not invent omitted distinct-origin totals or treat `no_matches` as covering
uninspected rows. Scope matching uses the original captured host.

The GUI can explicitly collect up to eight shown body, Link and peer inspections.
Peer groups use distinct canonical recorded-address nodes and undirected observation links;
equal address keys can share a node, but overlapping per-inspection totals are never
summed. Show performs no additional read. An origin outside the default map is
captured in this inspection; its matching-row count is not full-session traffic.
Every sample uses its exact token for verification, without a UUID fallback.
Every transaction event and retained-projection change removes peer groups because
unsampled membership cannot be proved unchanged. No automatic rescan or persistent
aggregate follows. Equal retained address values, including imported history, do
not prove the same physical endpoint, origin ownership or a backend relationship.
Socket addresses may reveal internal infrastructure; consider this before sharing
explicit inspection output.

For explicitly requested retained response-header relationships, use
`scope service-map link-declarations --session-id <active-session-uuid>
--evidence-id <returned-token>` (`target.service_map.link_declarations.get`).
This independent read requires the already-active session and exact row; it reads
only response headers, never body files or linked resources. Version 1 accepts
GET/HEAD 200 responses and literal absolute HTTP(S) declarations with
`service-doc`, `service-desc`, `describedby`, or `preconnect`. Unsupported source
contexts are not empty successful scans. Check `available`, `status`, `complete`,
`reasons`, `retained_header_count`, inspected counters, and every fixed limit.
Accepted partial results remain `status: "scanned"`, `complete: false`.

These are declarations or connection hints from one retained response, not
confirmed calls, API descriptions, installed products, or service ownership.
Output contains canonical target origins and original retained-header UTF-8 byte
spans; it omits target paths, queries, credentials, raw headers and unknown rel
text. Header indices refer to the retained array, not original wire ordering.
An older server may lack this endpoint; no fallback or automatic retry is safe.
In the GUI, Retained relationships selects body or Link evidence without reading
it. Inspect reads only the chosen source; Show explicitly adds one exact inspection
to the session-local collection. Repeating the same kind and full evidence token
updates only that entry; the eight-entry cap rejects additions without eviction.
All origins, pinning, selection and filters preserve the collection. Each entry
has separate provenance, coverage and removal controls, and none is persisted.
Validated events for another record UUID preserve body/Link entries; matching UUIDs
remove them conservatively. A later map poll must still verify the exact source
token under its original origin and generation. Sampling omissions are not proof
of deletion. Unknown events, gaps, retention, source/session/scope changes,
disconnect, refresh failure, Reload or leaving the map retire affected entries.
Never count reference-only targets as captured traffic, infer a physical
infrastructure chain, or fetch declarations.

For a separately requested HTML generator inspection, use
`scope service-map html-generators --session-id <active-session-uuid>
--evidence-id <returned-token>` (`target.service_map.html_generators.get`). The
same exact-row and active-session restrictions apply. This performs one separate
bounded retained-preview read; neither the metadata map nor URL-reference reads
invoke it. Only retained UTF-8 `text/html` previews are eligible. An older server
may not support the endpoint; never retry with body
hydration, another row, or target traffic.

Check `available`, `status`, `complete`, `reasons`, `head_closed`, both truncation
flags, and limits. Accepted partial results use `available: true`,
`status: "scanned"`, and `complete: false`. `scan_prefix_bytes` is the prefix offered to the recognizer,
not a count of fully parsed bytes. A supported explicit head may be closed even
when a trailing preview is truncated; `complete` is then false. Partial,
unsupported, or unavailable inspection cannot establish that a generator is
absent. Version 1 recognizes only literal WordPress/Drupal declarations in an
explicit HTML head, returning numeric versions only when wholly supported.
Unknown or unsupported versions must remain unknown. Treat these as reported
generator claims, never proven installed software, a backend/runtime identity,
or a vulnerable-version judgment. Output contains no raw tags or snippets.
Accepted spans use retained UTF-8 preview byte offsets; the parser stop cursor
may split a UTF-8 character and must never be used to slice text. There is no map
aggregation, automatic body scan, or persistence of this supplementary result.

### Reading the map as an agent

The map is built for a model to read as well as a person. A workable order:

1. Read the map for the session (`scope service-map --session-id <uuid>
   --all-rows`), or one origin with `--origin`. Each origin carries what its
   own responses name, by layer (`server_technologies[].category`: edge,
   gateway, platform, web_server, app_server, backend, monitoring, language,
   database, os, exposure), what its pages load (`front_technologies`, with
   `source_origin`), how its requests authenticate (`auth`), its endpoints
   (`endpoints[]`, each with `path_group`, the path with ID segments as
   `{number}`, `{uuid}` or `{hex}`), and `unnamed`: the `Server` and
   `X-Powered-By` values, header names and cookie names no rule names.
   `clients[]` lists what sent the traffic, with the `addresses` it connected
   from.
2. Treat every entry as a claim with evidence, not as proof. Open the rows
   behind a claim with `scope service-map-evidence` and the tokens from the
   same read, and an endpoint's parameters with `scope service-map
   parameters`.
3. Judge `unnamed` yourself: a banner such as `server: HeRay` or a header such
   as `x-cdn-pop` may name a product the rules do not know. `scope service-map
   unnamed` gathers them across the whole map, most widespread first, each
   with how many origins and rows carried it, a few of those origins, evidence
   tokens, and `named_alongside`: what the map named on the same origins
   (`--kind banners|headers|cookies`, `--limit`). Work down that list. Three
   clues, strongest first:
   - The origins' own domain: a cookie set only on one ad network's hosts is
     that network's; one spread over a company's several domains is that
     company's.
   - `named_alongside`: a header every carrying origin shares with one product
     (`cdn-pullzone` beside BunnyCDN) is likely that product's own.
   - The value: open an evidence row and read the header's value and the
     other headers; a fixed format (`HIT ord 2`) is a stronger sign than a
     name.
   A name many vendors use (`uid`, `x-cache`, `x-trace-id`) names nothing on
   its own; leave it. Say how sure you are and why, and name a product only on
   that evidence, never on a guess.
4. Group endpoints by `path_group` before describing an API; one template
   stands for many concrete IDs. `scope service-map openapi` gives an origin's
   API grouped that way, as OpenAPI 3.1, to hand to another tool.
5. Roles are not in the JSON. An origin that serves HTML pages and API data
   (JSON, XML) is both; one whose typed endpoints are mostly sign-in, token and
   logout paths (OAuth, OIDC, SAML, CAS), or that names an identity provider,
   is an authentication server.
6. Record a conclusion on the row it rests on with `capture http annotate --id
   <transaction-uuid> --note "<what you concluded and why>"`, dry run first, so
   the next reader sees it in history. The transaction UUID is the last part
   of the evidence token.

None of this sends traffic to a target. Probing is a separate, deliberate step:
a request sent from Replay is read by the map whatever its status, so a
deliberate probe (a missing path for the default error page, `/actuator`,
`/.git/config`) names what it reveals on the next read.

## Saved data and session management

### Prefer the saved-data v1 contract

For supported saved-data work, prefer `saved.v1.*` operations discovered through `sniper-cli manifest`; inspect `schema input <operation>` and `schema output <operation>` before constructing requests. The supported operations are `saved.v1.http.list`, `saved.v1.http.select`, `saved.v1.http.delete`, `saved.v1.http.clear`, `saved.v1.session.list`, `saved.v1.session.rename`, and `saved.v1.operation.get`. Detail/body reads, annotations, session creation/deletion, and active-session switching retain their existing interfaces; do not assume they have v1 receipts.

Pin the intended session explicitly with `session_id` for the first HTTP list and selection, and for every mutation. Use UUIDs returned by session discovery, not display names. HTTP list defaults to 50 summaries (maximum 200), has no filters, and returns `data.items`, `data.session_id`, `data.has_more`, and `data.continuation`. Use select for metadata filters.

- For HTTP pagination, preserve the returned continuation object verbatim and pass it as the sole `continuation` member of the next input. Do not add top-level `session_id` or `limit`, rebuild the cursor, or change its `store_generation`. Stop when `has_more:false` and `continuation:null`.
- For session pagination, pass the returned continuation object verbatim as the entire next input: it contains `after_id` and `limit`, without a `continuation` wrapper. Session listing uses ascending UUID order.
- HTTP pages use descending sequence order and stay pinned despite active-session changes. Newer inserts are excluded from later pages, but deletion can remove rows: this is not a snapshot. Store reload/restart returns `STALE_CONTINUATION`. Discard that cursor and deliberately start a fresh listing with the same explicit session UUID; treat it as a new traversal, not a continuation of the old results.

For saved mutations, generate and retain a fresh UUID `operation_id` before sending a newly approved operation. Dry-run validates locally without contacting Sniper, resolving selections, or reserving the ID. After reviewing the plan and obtaining required approval, use `--yes` with the same request. Filtered deletion needs a reviewed `saved.v1.http.select` result and its `selection_token`; a list continuation never authorizes deletion. Read envelope errors at `error.code` (uppercase), but mutation receipt codes at `data.receipt.code` (snake_case). A changed deletion selection returns `ok:true` with `data.receipt.outcome:"not_applied"` and `data.receipt.code:"selection_mismatch"`; selection reads can instead return `error.code:"SELECTION_MISMATCH"`. In either case, reread/select the intended session and review the changed data before deciding on any new operation. On `error.code:"OPERATION_CONFLICT"`, look up the original receipt and compare the original request; do not change input under the same ID or automatically substitute a new one.

Check `data.receipt.outcome` before reporting mutation success: `applied` is durably acknowledged, `not_applied` means this attempt made no change, and `unknown` means the evidence is insufficient. An `ok:true` envelope or `replayed:true` alone does not establish success. Identical reuse of an operation ID returns its receipt without executing again, including for unknown outcomes.

After a lost response, timeout, redirect refusal, or invalid write response, first call `saved.v1.operation.get` with the original `operation_id`. Lookup returns `found`, `outcome`, and nullable `receipt`; `found:false` with `outcome:"unknown"` is not proof that nothing happened. Inspect saved data and decide deliberately. Never automatically retry a mutation or silently mint a replacement ID, even after `not_applied`; all v1 errors report `retryable:false`. Receipts persist across runtime restarts for the lifetime of the data directory and have no automatic expiry or recovery mutation.

These are synthetic examples, not commands to run against real data. Replace the session UUID with one deliberately selected from discovery and generate an operation UUID for each newly approved mutation. The repeated operation UUID below represents the same rename and its later receipt lookup.

```bash
sniper-cli --output compact manifest
sniper-cli --output compact schema input saved.v1.http.list
sniper-cli --output compact schema output saved.v1.http.list
sniper-cli --output compact schema input saved.v1.session.rename
sniper-cli --output compact schema output saved.v1.session.rename
sniper-cli --output compact call saved.v1.session.list --input '{"limit":20}'
sniper-cli --output compact call saved.v1.http.list --input '{"session_id":"00000000-0000-0000-0000-000000000000","limit":20}'
sniper-cli --output compact call saved.v1.http.select --input '{"session_id":"00000000-0000-0000-0000-000000000000","host":"example.com"}'
sniper-cli call saved.v1.session.rename --input '{"session_id":"00000000-0000-0000-0000-000000000000","operation_id":"22222222-2222-2222-2222-222222222222","name":"Archive"}' --dry-run
sniper-cli call saved.v1.session.rename --input '{"session_id":"00000000-0000-0000-0000-000000000000","operation_id":"22222222-2222-2222-2222-222222222222","name":"Archive"}' --yes
sniper-cli --output compact call saved.v1.operation.get --input '{"operation_id":"22222222-2222-2222-2222-222222222222"}'
```

### Opt-in HTTP history retention

`capture http retention get [--session-id <uuid>]` reads saved policy and cleanup metadata. `capture http retention set (--off|--max-entries N) [--session-id <uuid>]` requires `--yes`; `--dry-run` is fully offline and shows the exact policy without predicting deletion counts. Canonical names are `capture.http.retention.get` and `capture.http.retention.set`; call input uses `off: true` or integer `max_entries` (1–4294967295), plus optional `session_id`.

Off is the default and preserves existing traffic. Enabling keep-newest is a destructive opt-in: get explicit user approval before allowing automatic permanent deletion. N is a soft total-history target, including protected rows; oldest unprotected excess rows are removed first. In-progress records and source originals referenced by durably saved HTTP Replay tabs remain protected, even unpinned tabs. Totals may exceed N. Unsaved browser state does not establish protection.

The CLI pins one session, fetches its policy-configuration token, and sends one compare-and-swap write. Prefer an explicit UUID. Saved-policy acknowledgement (`changed`) is separate from status (`pending`, `disk_cleanup_pending`, `blocked_reason`); it does not prove cleanup or disk reclamation is finished. After an uncertain write, deliberately inspect `capture http retention get --session-id <the same UUID>`; never automatically retry, switch sessions, or treat a lost response as no change. Off stops further automatic record deletion; pending disk reclamation for already-deleted records may finish. It does not restore deleted history.

### Existing saved-data commands

Use the existing commands below when the requested operation is outside v1 or the installed version does not support v1. Their raw success output and retry semantics do not acquire the v1 receipt contract.

These operations manage local saved data. Start with `session list` and use the returned UUIDs. `session create --name "Review"` creates and immediately activates a new session. `session rename --id <session-uuid> --name "Archive"` changes only its display name; the UUID and storage location stay the same. Names must be nonblank after trimming, at most 256 UTF-8 bytes, and contain no control characters.

`session switch --id <session-uuid>` respects busy-session checks. `session delete --id <session-uuid>` refuses to delete the active session; deliberately switch to another session first. Do not bypass live-capture, proxy-work, or pending-persistence safeguards. Deleting a session removes its saved data.

Session create, rename, switch, and delete send one mutation request without following redirects or retrying it. Rename and switch reject a returned UUID that differs from the requested UUID. A mismatch, lost response, or invalid acknowledgement leaves the outcome uncertain: inspect `session list` and current state before deliberately issuing another write. These commands have no `saved.v1` mutation receipts.

For saved HTTP records:

- Single or multiple records: `capture http delete --session-id <session-uuid> --id <record-uuid>`; repeat `--id` or comma-separate UUIDs. In `call` JSON, use the `ids` array. Missing IDs, including IDs belonging to another session, reject the entire selection
- Filtered records: first run `capture http select --session-id <session-uuid> --host example.com`. Review its `count`, `ids`, and `selection_token`. Then pass the same filters and `--selection-token <returned-token>` to `capture http delete`. The token covers the session, selected IDs, and metadata summaries, not full bodies. A changed selection is rejected; select and review again rather than automatically retrying
- Supported filters are `query`, `method`, `host`, `status`, `status_range`, `since`, and `mime`; all provided criteria must match. Query searches metadata, not bodies; host and MIME filters are case-insensitive substring matches. `status` and `status_range` cannot be combined. IDs and filters cannot be mixed. Empty, unknown, or invalid filters are rejected. Select/delete require an explicit session UUID
- Entire history: `capture http clear --session-id <session-uuid>` is a separate operation and accepts no IDs or filters. It deletes all saved HTTP records in that session; WebSockets, findings, and workspace tabs remain. Omitting the session UUID pins the active session at execution, so prefer an explicit UUID
- Every write uses the common `--dry-run` / `--yes` confirmation contract. Dry-run validates and describes the request without contacting Sniper; it does not resolve matches. `capture http select` is the read-only command that resolves the exact selection
- Deletions are durable before success is reported. They cannot be undone through the CLI; obtain the user's approval for the selected data. On a failure or lost response, inspect current data before deciding on another action; never automatically retry a mutation

```bash
sniper-cli --output compact session list
sniper-cli session create --name "Review" --dry-run
sniper-cli session create --name "Review" --yes
sniper-cli session rename --id <session-uuid> --name "Archive" --dry-run
sniper-cli session rename --id <session-uuid> --name "Archive" --yes
sniper-cli session delete --id <inactive-session-uuid> --dry-run
sniper-cli session delete --id <inactive-session-uuid> --yes
sniper-cli capture http delete --session-id <session-uuid> --id <record-uuid> --dry-run
sniper-cli capture http delete --session-id <session-uuid> --id <record-uuid> --yes
sniper-cli --output compact call capture.http.select --input '{"session_id":"<session-uuid>","host":"example.com","status_range":"4xx"}'
sniper-cli call capture.http.delete --input '{"session_id":"<session-uuid>","host":"example.com","status_range":"4xx","selection_token":"<returned-token>"}' --dry-run
sniper-cli call capture.http.delete --input '{"session_id":"<session-uuid>","host":"example.com","status_range":"4xx","selection_token":"<returned-token>"}' --yes
sniper-cli call capture.http.clear --input '{"session_id":"<session-uuid>"}' --dry-run
sniper-cli call capture.http.clear --input '{"session_id":"<session-uuid>"}' --yes
```

### Existing intercept rules and saved labels

Use `capture.intercept_rule.update` to patch an existing rule by UUID and
`capture.intercept_rule.set_enabled` to assign its explicit `enabled` boolean.
Both require `--yes`, accept `session_id`, and support offline `--dry-run`.
Omitted update fields preserve current values. Empty `host_pattern` or
`path_pattern` clears that matcher; `method_filter: []` or direct
`--clear-methods` clears the method list. Direct `--method` may be repeated to
replace the entire list. A missing rule ID fails without creating a rule; the
server merges the patch atomically so unrelated concurrent edits survive.
`set-enabled --enabled false` remains false if repeated. Neither command changes
the runtime intercept switch or forwards queued traffic.

A label-only `replay.update` supports saved HTTP and WebSocket tabs. The server
changes only `custom_label` under workspace revision checks; all other saved
fields are preserved. `label: ""` clears it; whitespace is collapsed and the
label is limited to 80 characters. Request/target inputs remain HTTP-only,
including when combined with a label. These operations send no replay traffic.
Prefer an explicit session UUID, inspect the result, and reread saved state after
a conflict or uncertain response rather than automatically retrying. They do not
use `saved.v1` receipts. See `schema` and `examples` for the installed contract.

## Common commands

```bash
sniper-cli --output compact manifest
sniper-cli --output compact schema input replay.send
sniper-cli --output compact call capture.http.list --input '{"limit":20,"page":true}'
sniper-cli --output compact call replay.send --input '{"tab_id":"<tab-id>"}' --dry-run
sniper-cli --output compact call replay.send --input '{"tab_id":"<tab-id>"}' --yes
sniper-cli --output compact session list
sniper-cli session switch --id <uuid> --dry-run
sniper-cli session switch --id <uuid> --yes
sniper-cli --output compact capture http list --limit 20
sniper-cli --output compact capture http get --id <uuid>
sniper-cli --output compact capture http search --value <text> --side response-body
sniper-cli --output compact capture browser list
sniper-cli capture browser open --dry-run
sniper-cli --output compact capture browser open --yes
sniper-cli --output compact capture browser open --agent --dry-run
sniper-cli --output compact capture browser open --agent --yes
sniper-cli capture browser prefer --browser <name|auto> --dry-run
sniper-cli capture browser prefer --browser <name|auto> --yes
sniper-cli capture http replay --id <uuid> --dry-run
sniper-cli capture http replay --id <uuid> --yes
sniper-cli capture http fuzzer --id <uuid> --dry-run
sniper-cli capture http fuzzer --id <uuid> --yes
sniper-cli capture http annotate --id <uuid> --color red --note "suspicious" --dry-run
sniper-cli capture http annotate --id <uuid> --color red --note "suspicious" --yes
sniper-cli scope get-scope
sniper-cli scope set-scope --pattern '*.example.com' --dry-run
sniper-cli scope set-scope --pattern '*.example.com' --yes
sniper-cli replay list
sniper-cli replay open --transaction-id <uuid> --dry-run
sniper-cli replay open --transaction-id <uuid> --yes
sniper-cli replay update --tab-id <tab-id> --label "IDOR: other user's profile" --yes
sniper-cli replay send --tab-id <tab-id> --dry-run
sniper-cli replay send --tab-id <tab-id> --yes
sniper-cli fuzzer set-template --transaction-id <uuid> --dry-run
sniper-cli fuzzer set-template --transaction-id <uuid> --yes
sniper-cli fuzzer set-payloads --file payloads.txt --dry-run
sniper-cli fuzzer set-payloads --file payloads.txt --yes
sniper-cli fuzzer run --dry-run
sniper-cli fuzzer run --yes
sniper-cli capture intercept on --dry-run
sniper-cli capture intercept on --yes
sniper-cli capture intercept list
sniper-cli --output compact call capture.intercept.get --input '{"id":"<uuid>"}'
sniper-cli --output compact call capture.intercept.wait --input '{"timeout":30,"poll_interval":200}'
sniper-cli --output compact call capture.response_intercept.wait --input '{"timeout":30,"poll_interval":200}'
sniper-cli capture intercept forward --id <uuid> --dry-run
sniper-cli capture intercept forward --id <uuid> --yes
sniper-cli capture web-socket list --limit 20
sniper-cli capture web-socket get --id <uuid>
sniper-cli capture auto-replace list
sniper-cli capture auto-replace set --file rules.json --dry-run
sniper-cli capture auto-replace set --file rules.json --yes
sniper-cli capture oast configure --provider custom --url https://oast.example --token-stdin --dry-run
printf "%s" "$OAST_TOKEN" | sniper-cli capture oast configure --provider custom --url https://oast.example --token-stdin --yes
sniper-cli skills install --codex --dry-run
sniper-cli skills install --codex --yes
```

## Skill maintenance

Use `sniper-cli skills status --all` to compare active installed files with the
bundle, or `sniper-cli skills update-preview --all` to inspect enrollment and
update eligibility. These are local, read-only operations; inspect each row's
state/error rather than treating exit zero as proof every file is current.
The experimental `skills.enroll` and `skills.stage_update` operations must be
discovered through `manifest`, `schema`, and `examples` before using them.
Enrollment records an explicit local baseline; it does not enable automatic updates.
Staging requires confirmation and a new output directory, writes only a candidate
and receipt, and returns `activated:false`. Never claim staging updated the active
skill or the agent's loaded context.

Explicit activation is a partial milestone. Discover `skills.apply_update`,
`skills.update_result`, and `skills.rollback_update` before using them. Select
exactly one agent and preserve its skills root. Apply requires the reviewed stage
to match the unchanged enrollment baseline and the executing binary's bundle;
different bytes require a strictly newer semantic version. Equal precedence with
different bytes, including build-metadata-only differences, is a version conflict.
Unmanaged, edited or mismatched files must be preserved rather than overwritten.

Generate and retain one canonical lowercase hyphenated UUID `operation_id` before
an approved apply. `skills apply-update` requires `--staging-dir`, that
`--operation-id`, and `--yes`; preview with global `--dry-run` first. Dry run is
argument-only and performs no filesystem inspection or API discovery. It cannot
prove the stage is eligible. Successful application records an updated managed
baseline but never enables startup updates or unattended activation, and reports
`allows_automatic_updates:false` and `agent_reloaded:false`. Changing a file does
not prove a running agent reloaded its instructions.

After lost output, interruption or `recovery_required`, use the read-only
`skills update-result` with the same original operation ID, agent and root.
This reads local files but never resumes a mutation. Inspect both `state` and
`current_state`: a historical applied result is separate from today's active
bytes. Preserve all transaction and staging artifacts and displaced objects;
never blindly retry or silently mint a replacement ID. The same bound ID can
resume only proven object placements; a different request under that ID is
refused. Explicit `skills rollback-update --yes` uses that original apply ID to
restore the bound baseline and preserves displaced objects. Unexpected changes
can block rollback; there is no force-overwrite fallback.

Linux exchange has native fixture coverage. Hosted macOS 15 ARM64
[focused policy/transaction tests and native desktop compilation](https://github.com/sm1ee/Sniper/actions/runs/38423109820)
were verified at `e7cbe95`. Actual GUI behavior, Intel Macs and user-installed
skills remain unverified. Windows activation, rollback, result inspection and
host-policy operations are unsupported. There is a cap of
128 retained operations and no automatic pruning. Partial or corrupted preparation
or markers require manual reconciliation while preserving all artifacts.
The legacy `skills install --yes` can overwrite installations; never use it as
an automatic update or recovery fallback.

Automatic updates are Off by default and require separate explicit user approval
of future bundled updates for one unchanged managed installation. Never infer
that approval from enrollment, an app upgrade, startup, or reading this skill.
Discover `skills.auto_update_status`, `skills.enable_auto_updates`,
`skills.disable_auto_updates`, and `skills.auto_update_once` before use.
`auto-update-status` is read-only; enable, disable and one-shot execution require
`--yes`. Enable records consent only and does not immediately update the skill.
Only enable accepts a selected agent's directory override; status, disable and
once always use the recorded target and reject redirection. Select exactly one
agent; `--all` is unsupported for these commands.

Host policy lives under the local Sniper data directory's `host-skill-updates`,
not session data or exports. Remote `--api` is never contacted. The desktop runs
one background pass after its first idle event; headless startup and ordinary
CLI commands do not run it. Candidates come only from the executing binary's
bundle and different bytes need a strictly newer semantic version. No network
fetch, automatic enrollment, adoption of edits, overwrite fallback, pruning or
agent reload is permitted.

Inspect policy `state`, `error_code` and optional retained `pause_reason`;
`enabled:true` can coexist with `paused`.
A pending or uncertain attempt consumes its authorization and is not permission
to retry, invent another ID or resume at startup. Preserve all policy, attempt,
staging and transaction artifacts. After lost output, inspect
`skills auto-update-status` and the original transaction when present. A pause or
disabled policy never re-enables itself. Re-enable only after explicit user
approval and review, supplying the exact current `--policy-revision` from status
and the original target; this creates a new authorization generation. Disable
revokes future work without undoing committed updates. Windows host-policy
operations are unsupported. Dry run remains argument-only with zero filesystem
or API I/O and cannot establish eligibility. For these four operations, canonical
`call --dry-run` requires inline JSON; `@file` and stdin are rejected before reads.

## Guardrails

- If `sniper-cli` is missing from `PATH`, say so briefly instead of falling back to GUI scraping.
- Do not switch sessions silently before changing scope, Replay state, or queued-request decisions.
- Use `capture http get`, `replay list`, or `capture web-socket get` before making assumptions about stored request state.
