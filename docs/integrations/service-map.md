# Service Map

Service Map is a read-only view of the traffic one Sniper session has retained.
The Map tool and `sniper-cli scope service-map` read the same inventory.
Opening or refreshing the map sends nothing to a target: it does not probe,
scan, replay, follow redirects or crawl. It saves no graph and does not change
the active session.

## The map

The Map tool has two views, Service Map and APIs. Service Map shows one card per
origin, with origin search, an **In scope** toggle and an APIs/Details
inspector. Each card leads with what its origin serves:

- **Front**: HTML pages, or a front-end product or CMS that a header names or
  one of its pages loaded.
- **API**: JSON, XML, protobuf, gRPC or GraphQL. An origin with both shows Front
  first.
- **Static**: images, fonts, styles and scripts.
- **Unknown**: no typed response. Hidden unless selected, pinned or searched
  for; the APIs list keeps them.
- **Auth**: an identity provider such as Keycloak, or an origin whose paths are
  mostly sign-in, token and logout endpoints. An app that also signs its users
  in keeps its own role.
- **Ref**: only referenced; no captured rows for it are in this snapshot.
- **Site**: several origins on one card (see
  [Sites and hidden origins](#sites-and-hidden-origins)).

A card's icon is the origin's captured favicon, or else a declared product's
logo; the map never asks a target for an icon. Snapshot counts, coverage and the
row window are under **Details** below the map.

The graph shows at most 24 cards and 40 arrows. Cards are ordered by
relationship and laid out left to right by link depth; polling never moves them.
Relationship and source lists show at most 30 rows per pane, and API lists page
50 entries at a time.

- Minus, the percentage and plus zoom the graph from 10% to 200%. The percentage
  fits the cards, or returns to 100% once fitted. With the map focused, `+` and
  `-` zoom, `0` resets and `F` fits. A trackpad pinch or Ctrl with the wheel
  zooms around the pointer.
- Drag the bar between the map and the inspector to resize the inspector;
  double-click restores it.
- Selecting a card or an API entry changes only the local view. **Details** and
  its sample picker read one exact retained sample (see [Retained packet pair](#retained-packet-pair)); they send nothing to its target.

## How the map is read

The GUI reads every retained row (`all_rows=true`), locking history 8,192 rows
at a time so capture continues. The CLI reads the newest `--max-records` rows
(default 10,000, at most 50,000) unless given `--all-rows`. A windowed read
projects at most 8 MiB of metadata and holds the history lock while it reads,
which can delay capture writes.

While Service Map or APIs is open and visible, the GUI reads the map again five
seconds after each read finishes. The server reuses its last whole-history map
while history is unchanged, or while the map is younger than four times its
build time (at least 1.2 seconds), so a poll can show rows removed since. After
a new capture the GUI sends `fresh=true` to skip that age rule. **Reload** reads
at once and clears shown inspections.

Automatic retention marks the map stale and triggers one follow-up read. The
selection stays, but opened evidence, parameters, API docs and inspections are
cleared. If a read fails, polling stops until **Reload** or a real scope or
session change.

Map reads share one slot. A second read waits up to 20 seconds and then gets
HTTP 429 `busy`; the GUI keeps its map and asks again on the next poll.
Failures carry a marker in the `x-sniper-service-map-error` header, and the CLI
reports each once, with `retryable:false`:

| Status | Marker | CLI code | Cause |
| --- | --- | --- | --- |
| 429 | `busy` | `SERVICE_MAP_BUSY` | Another map read held the slot for 20 seconds. |
| 422 | `scope_work_limit` | `SERVICE_MAP_SCOPE_WORK_LIMIT` | The scope rules went past their limits. |
| 409 | `session_changed` | `SERVICE_MAP_SESSION_CHANGED` | The session changed during the read. |
| 409 | `scope_changed` | `SERVICE_MAP_SCOPE_CHANGED` | The scope rules changed during the read. |
| 409 | `history_changed` | `SERVICE_MAP_HISTORY_CHANGED` | Retained history changed during the read. |
| 500 | `build_failed` | `SERVICE_MAP_BUILD_FAILED` | The read could not complete. |

Scope rules allow 500 entries per include or exclude list and 512 bytes per
pattern, and one read gets 8,388,608 units of matching work. Past either limit
the read fails with `scope_work_limit`; narrow the rules or lower the row window.

## Service Map filter

**Filter** on the map toolbar opens the HTTP history filter dialog for the map's
own settings, saved apart from History's: MIME type, status class, hidden
extensions, responses only, URL query only, notes only, port and advanced
search. The default hides `png,ico,css,woff,woff2,ttf,svg,jpg,jpeg,gif`, so a
page's image and style CDN drops out. Each condition hides exactly the rows it
hides in History, and anything seen only in hidden rows disappears with them;
`snapshot.filtered_rows` counts those rows. The CLI takes the same conditions as
flags but hides nothing unless asked.

**Show only requests with query parameters** (`only_parameterized`) matches a
`?` in the captured URL, including an empty query.
JSON, form and multipart body fields do not match.

## Links by request kind

Origin and Referer links only say which page a request came from. Each
`header_links[]` entry therefore counts its rows (`request_count`) and splits
them by request kind (`request_kinds`), read from `Sec-Fetch-Dest`:

| Kind | `Sec-Fetch-Dest` |
| --- | --- |
| `api` | `empty` (fetch or XHR) |
| `navigation` | `document` |
| `frame` | `iframe`, `frame`, `embed`, `object` or `fencedframe` |
| `script` | `script`, a worker, a worklet or `xslt` |
| `static` | `image`, `style`, `font`, `audio`, `video`, `track` or `manifest` |
| `other` | any other value |

Without `Sec-Fetch-Dest` the response type decides: HTML is `navigation`, API
types are `api`, JavaScript is `script`, and media, fonts and CSS are `static`.
Failing that, a row with an `Origin` header or a method other than GET and HEAD
is `api`, and any other row is `other`.

The legend toggles each kind. Frames, scripts and static files are hidden by
default, so CDN loads draw no arrows. Hiding a kind hides arrows, not cards; use
the [Service Map filter](#service-map-filter) to drop cards. Redirects are always
drawn. The map draws one arrow per direction between two cards, coloured by its
first shown kind and heavier with more rows; hover it to see its rows by kind.
`header_sources[]` counts the same rows per source origin with a request that
carries both headers counted once, and the arrow uses it.

`cors_allowed_count` counts rows whose response let the source origin read it
(an `Access-Control-Allow-Origin` naming it, or `*`). `cors_credentials_count`
counts those that also allowed credentials. Both are omitted when zero.

## Direct relations

The map has two views, **Origins** (the default) and **Flow**. In Origins,
**Direct relations** at the end of the legend shows only the origins and
recorded-address nodes one hop from an anchor, the selected card; press it
again to see every origin. **Focus selection** makes the selected card the
anchor. The anchor stays visible when search or a filter would hide it.

## Flow

**Flow** shows the selected origin's requests in time order. Its lanes are the
client, the origin and up to five origins it links to directly by an Origin or
Referer header or a redirect. Each page load (a navigation) starts a card, the
same request in one page load folds into one arrow with a count, and a redirect
is a dashed arrow back to the client. Each arrow shows the method, path and
status, and the time since the flow's first request; each lane its request
count. The request kinds toggled under **Requests** and the Service Map filter
apply. Click an arrow to open its newest row in HTTP history, or another lane to
follow that origin. The lane headers stay at the top while the flow scrolls.
**Copy Mermaid**, at the end of the legend, copies the flow as a Mermaid
sequence diagram. The copy keeps the row counts, stop reasons and hidden request
kinds, and a cut-off flow is marked **Partial flow**. `considered_rows` is how
many of the newest rows were read; `flow_rows` is how many the steps show, after
the 300-step cap. Links or redirects that could not be read also make a flow
partial.

The view reads the newest 50,000 rows; the CLI reads 10,000 unless told
otherwise:

```bash
sniper-cli --output compact scope service-map flow --origin https://app.example.com
```

## Sites and hidden origins

**Group by site** (on by default) puts two or more origins of one site on one
card. A site is a host's last two labels, or three under common suffixes such
as `co.kr`. **Show origins separately** splits a site. **Hide from map** removes
an origin or a site from the map in every session; the legend's **Hidden** list
brings it back. Grouping and hiding change only the map: the API and the CLI
still return every origin.

## Clients

Each row's `User-Agent`, with Chromium Client Hints, names its client: a kind
(`browser`, `webview`, `app`, `tool`, `library`, `bot` or `unknown`), a name, a
major version and an operating system. Only these names reach the map, never the
header. Clients lead the map in their own column, up to four cards beyond the
origin cap. Each draws a dashed **Direct request** arrow to the cards it
requested itself, with no Origin or Referer, that no other card links to. Each row also keeps the address that sent
it to the proxy (`client_address`). The API and the CLI carry `clients`, at most
16, with their versions, addresses and origins.

## Products on cards

A card shows up to two products declared in its response headers, with `+N` for
the rest; the inspector gives each literal version, header, time and evidence.
The **Products / versions** toolbar filter narrows origins by exact product and
version string (`1`, `01` and `1.0` differ), by **Multiple reported versions**,
or by an unknown-version state. It also narrows the API catalog's origins, makes
no reads, and is cleared by a session change.

## Front-end technologies

The map also names about 150 front-end products (meta-frameworks, CMSs,
frameworks, UI kits, libraries, third-party services and analytics) without
running anything. It reads licence banners and runtime values in scripts
(`/*! jQuery v3.7.1`, `window.next={version:"…"}`), framework markup and
`<meta name="generator">` in pages, and asset URLs (`/npm/vue@3.4.21/`,
`jquery-3.6.0.min.js`, `/_next/static/`, third-party script hosts). An asset's
products go to the page that loaded it (its Referer) when that page is in the
map, so a CDN bundle names the page's framework.

One map reads the bodies of at most 256 rows, 32 MiB in all, and later reads
continue with the rest. Products can therefore keep appearing after
`snapshot.complete` is true. The inspector lists them under **Front-end**, and
the API and the CLI carry `front_technologies`, at most 32 per origin.

## Server technologies and exposures

The map also names the servers behind an origin from its own responses: vendor
header names (`CF-RAY`, `x-envoy-*`), header values the catalog does not name
(`Server: AmazonS3`, `Apache/2.4.52 (Ubuntu)`), cookie names (`JSESSIONID`,
`BIGipServer…`), and default error, gateway, WAF and debug pages, stack traces,
SQL errors and banners. JSON, XML and text bodies are read only for errors (400
or above), an origin's root, API documents, management or debug paths
(`/actuator`, `/.env`, `/server-status`) and requests sent from Replay or the
Fuzzer. Cookie values are not read, except to tell whether a BIG-IP cookie holds
a backend address and which servlet engine shaped a session ID.

An exposure is something a response gives away by mistake: a debug page, a
detailed error or stack trace, an SQL error, a directory listing, Actuator,
Swagger UI, `.git/config` or `.env`, a metrics or status page, a backend address,
and in scripts and pages a source map, an API key, a private key, a JWT or a
private address. Only the finding is reported, never the matched value.

A card's first chip warns of an exposure, and the inspector lists **Exposures**
and **Server**. The API and the CLI carry `server_technologies`, at most 32 per
origin. Each finding's `category` is its layer, outermost first (`edge`,
`gateway`, `platform`, `web_server`, `app_server`, `backend`, `monitoring`,
`language`, `database`, `os`), or `exposure`.

A response header over 4 KiB is skipped on its own. A path over 2,048 bytes
still counts for its origin, but its endpoint is left out, with `path_limit` in
`snapshot.stopped_by`.

## Unnamed signals

What no rule names is kept for a person or an agent to judge: `Server` and
`X-Powered-By` values, unusual response header names, and cookie names. Standard
headers and `Via` values are left out. The inspector lists them under **Unnamed
signals**, and the origin carries them as `unnamed`.

`sniper-cli scope service-map unnamed` gathers them across the map, most
widespread first, with their origins, evidence and `named_alongside`, the
products named on the same origins. `--kind` keeps one kind, and
`omitted_signals` counts only what `--limit` hid.

```bash
sniper-cli scope service-map unnamed --kind headers --limit 50
```

A header that always travels with one product is likely that product's own. A
name many vendors use, such as `uid`, names nothing.

## Authentication

The map names how each row authenticates from names and shapes, never values:
the `Authorization` scheme (`bearer_jwt`, `bearer`, `basic`, `digest`,
`negotiate`, `ntlm`, `aws_sigv4` or `scheme`), API key headers, session and JWT
cookies (`session_cookie`, `jwt_cookie`), `WWW-Authenticate`, credentials in the
URL (`query_key`), signed AWS URLs, and OAuth 2.0, OpenID Connect and SAML
flows. A card's lock chip names the busiest one, the APIs tab leads with
**Authentication**, and the API and the CLI carry `auth` on each origin and
endpoint.

## API lists and parameters

The APIs tab and the API catalog list endpoints by method and path. Paths that
differ only in an ID (up to 18 digits, a UUID, or 16 to 128 hex digits mixing
digits and letters) share one row under a template, carried as `path_group`
(`/web/chats/{number}/posts/{hex}`). Both lists filter the loaded snapshot by
method and path substring, case-sensitive, without new reads.

Opening an endpoint lists its parameters from its newest 200 rows: name, place
(`query`, `form`, top-level `json` or `multipart`), row count, and up to three
values as captured. Bodies are read only while the endpoint is open, in the
active session, up to 64 KiB each; multipart gives names only.

```bash
sniper-cli scope service-map parameters --session-id <active-session-uuid> --origin https://example.com --method GET --path /search
```

## OpenAPI

**API docs**, in the inspector of an API or sign-in origin, opens an OpenAPI 3.1
description of its retained rows: path templates, parameter and body field names
with their types, response statuses and media types, and the credentials seen,
each as an alternative security scheme. No captured value is copied. Each
operation's `x-sniper-requests` counts its rows, and `x-sniper-newest-transaction`
names the newest (`capture http get --id`). **Send newest row to Replay** opens
that row in Replay. **Copy OpenAPI JSON** and **Open in Swagger Editor** export
the document. At most 500 operations are listed; `info.description` says what was
left out.

`x-sniper-parameter-cap-truncated: true` marks an operation whose parameter list
reached the 200-entry cap. Its absence does not prove the list complete:
parameters come from each path variant's newest 20 rows.

```bash
sniper-cli scope service-map openapi --session-id <active-session-uuid> --origin https://api.example.com > api.json
```

## Read through the CLI

```bash
sniper-cli scope service-map --session-id <session-uuid>
sniper-cli scope service-map --session-id <session-uuid> --in-scope-only --max-records 10000
sniper-cli scope service-map --session-id <session-uuid> --all-rows
sniper-cli scope service-map --session-id <session-uuid> --hidden-extensions png,css,woff2 --mime-types html,script,json,other
sniper-cli call target.service_map.get --input '{"session_id":"00000000-0000-0000-0000-000000000000","in_scope_only":false,"max_records":10000}'
```

- `target` is an alias for `scope`. Every Service Map operation is a read and
  needs no `--yes`; `--dry-run` shows the request without sending it.
- `sniper-cli schema output <operation>` lists every field and limit of each
  result.
- Without `--session-id`, the active session is resolved once and used for the
  whole read. An explicit UUID reads an inactive saved session without switching
  to it. Reuse the returned `session_id` for one-row reads.
- `--max-records` and `--all-rows` cannot be combined. `--in-scope-only` is off
  by default.
- `--origin https://example.com` reads one exact canonical origin.
- `--mime-types`, `--status-classes`, `--hidden-extensions`,
  `--hide-without-responses` and `--only-parameterized` are the
  [Service Map filter](#service-map-filter)'s conditions.
- `call` returns the result in `data`, with the session in `meta.session_id`.

## Reading the results

- An origin is the observed scheme, host and port. Scope is checked against each
  row's original host.
- Endpoints keep the exact path without its query string. Paths can contain
  identifiers, so keep exported output private.
- Counts are retained rows, not unique requests.
- A redirect link means a response pointed there, not that anything followed
  it.
- `unavailable` lists what the map cannot know: initiator, remote IP and TLS
  certificate.
- Check `snapshot.complete` and `snapshot.stopped_by` before relying on the
  inventory; retention, scope and limits can leave data out. The window is the
  newest rows by capture sequence, not by time.

## Reported header products and versions

Origins and evidence carry `technology_observations`: products and versions
declared in `Server`, `X-Powered-By` and `X-Generator` headers. Catalog revision
1 covers nginx, Apache, Caddy, Cloudflare, Microsoft-IIS, Envoy, PHP, Jetty,
Apache-Coyote, Apache Tomcat, Express, ASP.NET, WordPress and Drupal. Revision 2
adds Gunicorn, Uvicorn, Waitress, OpenResty, LiteSpeed and Next.js. A version
must be a number or dot-separated numbers, at most 32 bytes. `version_status`
is:

- `reported`: `reported_version` holds the whole value
- `not_reported`: no version was declared
- `unsupported_format`: the version did not fit; `reported_version` is null
- `non_product_version`: an Apache-Coyote connector number, never a Tomcat
  version

Origin observations group by product, header, version and status, with
`row_count`, `first_seen`, `last_seen` and up to three evidence tokens.
Conflicting versions stay separate. Headers can be spoofed, so treat a version as
reported, not installed. Caps of 8 observations per row, 32 per origin, 2,000
per map and 128 header tokens per row each add a `technology_…_limit` marker to
`snapshot.stopped_by`.

## One-row reads

These reads inspect one exact retained row, named by an evidence token from the
map. Copy the token (at most 200 bytes) unchanged. A stale, edited or removed row
returns unavailable, never another row. Check `available` before using a result,
and `complete` and `reasons` for a partial one; a packet read reports each side
instead (see [Retained packet pair](#retained-packet-pair)). None sends a request
to a target.
All except evidence need the active session and never load another.

| Read | CLI | Returns |
| --- | --- | --- |
| Evidence | `scope service-map-evidence` | Safe metadata for the row, with no bodies or raw headers. `--include-socket-peer` adds its recorded socket peer (see [Observed socket peer](observed-socket-peer.md)). |
| Packet | `scope service-map packet --variant current` (or `original`) | Both selected retained messages, ordered headers and body previews under one exact source key. No annotations or reconstructed wire transcript. |
| Body references | `scope service-map body-references` | Canonical origins of literal absolute HTTP(S) URLs in a UTF-8 HTML or JavaScript response preview, with byte offsets. Nothing is decoded, parsed or run, and relative URLs are not resolved. |
| Link declarations | `scope service-map link-declarations` | Target origins of `service-doc`, `service-desc`, `describedby` and `preconnect` in the `Link` headers of a GET or HEAD 200 response. |
| HTML generators | `scope service-map html-generators` | WordPress or Drupal, with any version, from `<meta name="generator">` in a UTF-8 `text/html` preview. It needs explicit `html` and `head` elements, and unusual markup stops it early. |
| Socket peer matches | `scope service-map socket-peer-matches` | See [below](#explicit-recorded-socket-peer-matches). |

```bash
sniper-cli scope service-map-evidence --session-id <returned-session-uuid> --evidence-id <returned-evidence-token>
sniper-cli scope service-map body-references --session-id <active-session-uuid> --evidence-id <returned-evidence-token>
sniper-cli scope service-map packet --session-id <active-session-uuid> --evidence-id <returned-evidence-token> --variant current
```

In the GUI, **Details** picks the retained sample, and **Inspect** and **Find
matching peer** run the reads above on it; picking a sample runs none of them.
Offsets and spans count UTF-8 bytes of the retained preview or header value, not
of the wire. A generator `parser_stop.byte_cursor` can fall inside a character,
so do not slice text with it.

## Retained packet pair

**Details** shows one retained request and response in the packet viewer,
starting in **Raw**; its sample picker chooses the row and the current or
original version. The packet menu copies the packet, or opens a complete request
as an unsent Replay or Fuzzer draft. A failed read offers **Retry**.

`GET /api/target/service-map/packet` takes `session_id` (the active session),
`evidence_id` and `variant=current|original`; `scope service-map packet` in the
CLI is the same read. It sends nothing. The reply has `schema_version: 1`,
`available`, `reason`, the source row's id, time and `sequence` (a string), and
`request` and `response`. A side that was not kept is
`{"status": "not_retained", "message": null}`. A kept side has its start line,
its headers in order and a `body` with `body_preview`, `body_encoding`, sizes,
`preview_truncated`, `content_decoded` and `content_type`; an unavailable body
is not an empty string.

These are the stored messages, not wire bytes: a body may be decoded or cut to
the capture preview. An original has only what was kept, and nothing falls back
to the current version.

The token names one exact row. If that row changes or goes, or the session
changes, the read is unavailable rather than another row. The reply is at most
2 MiB, and so is the row read from disk; past either, the read is unavailable
(`packet_view_limit`, `serialized_row_limit`). Reads share one worker and give
up with `read_busy` after 20 seconds in its queue. Captured headers and URLs can
hold credentials, so treat a copied packet as sensitive.

## Explicit recorded socket peer matches

```bash
sniper-cli scope service-map socket-peer-matches --session-id <active-session-uuid> --evidence-id <returned-token> --in-scope-only --max-records 10000
```

From one exact row in the active session, this read finds other retained HTTP
rows whose recorded direct socket observation has the same source, route,
address family, IP and port. It groups them by origin, each group with its row
count, observation times and up to three sample tokens. `status` is `matched`,
`no_matches` or `unavailable`, and `source.in_window` says whether the source
row is inside the window. `max_records` defaults to 10,000 (at most 50,000); a
larger window holds the history lock longer and can delay capture writes.

Only direct unicast observations match. CONNECT, tunnel and upgrade rows, port
zero, and unspecified, multicast, link-local, broadcast and reserved addresses
are excluded, and IPv4 never matches IPv4-mapped IPv6. Groups count responses,
not connections, and a shared address does not mean a shared owner.

## Session-local retained relationship collection (GUI only)

From the selected sample in **Details**, choose **Body references** or
**Link references** under **Inspect**, or use **Find matching peer**, then choose
**Show references on map** or **Show recorded address group** to add the result
to the graph without another read. Up to eight entries can be shown at once in
the current session; a ninth is rejected rather than evicting one. Entries are
never saved. **Shown inspections** lists them, with **View inspected source**,
**Remove inspection** and **Clear all inspections**. A peer overlay sample uses
**Verify source ›** to verify that exact retained row.

Body and Link entries draw typed reference arrows. Peer entries draw undirected
spokes through recorded-address nodes; entries sharing an address share a node
without adding up their totals. A target seen only in an inspection stays
reference-only, with no traffic or API paths. The graph keeps its 24-card and
40-arrow limits.

Entries are removed when their source can no longer be verified:

- A capture event for the same record UUID removes body and Link entries, and so
  does a poll that no longer contains the source's exact token.
- Any capture event or change to retained metadata removes peer entries.
  Pausing HTTP recording keeps them steadier.
- Event gaps, retention, deletion, a session or scope change, a disconnect, a
  failed refresh, **Reload**, and leaving or hiding Service Map clear the whole
  collection.

## Local API

- `GET /api/target/service-map?session_id=<uuid>&in_scope_only=false&max_records=10000`
- `GET /api/target/service-map?session_id=<uuid>&in_scope_only=false&all_rows=true&fresh=true`
- `GET /api/target/service-map/parameters?session_id=<active-uuid>&origin=<origin>&method=<method>&path=<path>`
- `GET /api/target/service-map/openapi?session_id=<active-uuid>&origin=<origin>`
- `GET /api/target/service-map/favicon?session_id=<active-uuid>&evidence_id=<origin-favicon-token>`
- `GET /api/target/service-map/evidence?session_id=<uuid>&evidence_id=<opaque-token>`
- `GET /api/target/service-map/socket-peer-matches?session_id=<active-uuid>&evidence_id=<opaque-token>`
- `GET /api/target/service-map/packet?session_id=<active-uuid>&evidence_id=<opaque-token>&variant=current`
- `GET /api/target/service-map/body-references?session_id=<active-uuid>&evidence_id=<opaque-token>`
- `GET /api/target/service-map/html-generators?session_id=<active-uuid>&evidence_id=<opaque-token>`
- `GET /api/target/service-map/link-declarations?session_id=<active-uuid>&evidence_id=<opaque-token>`

URL-encode the evidence token. The endpoints use the local API's normal access
control, and an older running Sniper may lack some of them.

### Technology catalog negotiation

The map and evidence endpoints take the header
`X-Sniper-Technology-Catalog-Version` with the value `1` or `2`. Without it the
server uses revision 1 and the response has no `technology_catalog_version`
field; with it, that field names the revision used. Any other value returns HTTP
400. A client that asked for 2 and gets no field must treat the result as
revision 1. The Map tool and the CLI ask for 2; `--technology-catalog-version 1`
asks for 1.
