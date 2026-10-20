# Passive retained-history Service Map

Service Map's default inventory is a read-only view of metadata already retained
by one Sniper session. It builds the same inventory for the Map tool and the CLI.
Opening or refreshing it never probes an origin, starts a scan, replays a request,
follows a redirect, crawls a page, or asks an agent to explore a target. It does not
create a persistent graph or change the active session.

## Scope workspace

Scope keeps four views: Rules, Service Map, APIs, and Paths. Service Map uses a
stable card layout with origin search, scope filtering, viewport scrolling, and
an APIs/Evidence inspector. Each card leads with what its origin serves, read
from the response types of its loaded endpoints: **Front** (HTML pages), **API**
(JSON, XML, protobuf, gRPC or GraphQL), **Static** (images, fonts, styles,
scripts), or **Unknown** when no typed response is loaded; **Ref** marks an
origin only referenced, and **Site** a card of grouped origins. An Unknown
origin, often a beacon answering 204, leaves the map unless it is selected,
pinned or searched for; the bounds line counts them (`N with no typed response
hidden`), and the APIs list and the inspector keep them. A front-end
product or CMS (Next.js, React, Vue, WordPress and the like) makes it Front
whatever its endpoints return when a header names it, the origin serves pages, or
one of its pages loaded the script naming it; a CDN that only serves that script
stays Static. An origin that serves pages and API data names both, Front over
API (a manifest or a JSON error is not API data for this). **Auth** marks an
authentication server: an identity provider by product (Keycloak), an origin
whose typed paths are mostly sign-in, token and logout endpoints (OAuth,
OpenID Connect, SAML, CAS) with at least two of them, one a client asked for a
token with OAuth parameters, or one whose host is named for it (`sso.`,
`auth.`, `login.`, `accounts.`, `idp.` and a few more) with such a path. An app
that also signs its users in keeps its own role. A declared application product shows its mark in place of the icon,
and an origin whose own icon was captured shows that instead: the newest GET
answered 200 with a raster image at a `favicon…` or `apple-touch-icon…` path,
kept whole, found even when the display filter hides `ico` and `png` rows. The
map never asks a target for an icon. The card loads it from
`GET /api/target/service-map/favicon`, which serves the active session's
retained bytes only when they are a PNG, ICO, GIF, JPEG or WebP image (never
SVG), with `nosniff` and a sandbox policy; one that fails to load keeps the
mark. The API and the CLI carry its evidence as the origin's `favicon`. Only an error or the first load shows above the map; the snapshot
counts, coverage and window sit under **Details** below it, whose summary names
how many origins the card cap leaves out. Compact 220×84px cards at the default 12px Display
text size share their geometry with all arrow attachments. Larger Display text
grows card height and row spacing together (119px cards at 20px), retaining
legible line boxes, aligned arrows, selection, and the chosen zoom. Minus, the
percentage and plus scale only the graph from 10% to 200%; the inspector and
Scope navigation retain their normal size. The percentage fits the displayed
cards in the map, a one-shot action bounded by those scale limits, and once
fitted returns to 100%. Polling and resizing never refit or change the chosen
zoom. Plus and minus preserve the viewport center where scroll bounds allow.
With the map viewport focused, +/−, 0, and F provide zoom, reset, and fit
shortcuts. The bar between the map and the inspector sets the inspector's width
(drag it, or focus it and use the arrow keys; double-click restores the
default), kept in UI settings as `service_map_detail_width`. A trackpad
pinch, or Ctrl with the mouse wheel, zooms around the pointer instead of zooming
the whole page; a plain wheel still scrolls the map. The selected card's gold
arrows flow from source to target: their own dashes move along the line, and a
solid redirect takes long dashes while selected so it can flow. With reduced
motion requested the lines stay still and only the highlight remains. Zooming is
local and preserves selection, exact-source reads, and session-local shown inspections.
There is no force layout or drag editing in this version. The renderer is separate from metadata normalization and
layout calculation so it can be replaced without changing the read contract.
The navigation strip follows the existing compact Capture-tab sizing. Long
origin, method, and path previews stay bounded; their full text remains available
in accessible text and hover titles, and selected endpoint evidence shows the
complete query-free path.

The graph displays at most 24 cards and 40 arrows, and an arrow needs both of its
cards on screen. When the map opens, and on an explicit Reload, All origins
therefore orders cards by relationship: the best-connected captured origin, then
its neighbours, then each further connected group; unrelated and reference-only
origins follow by name. Linked cards are laid out left to right by link depth:
each card sits one column right of its furthest linked source, so no arrow joins
two cards of one column. A link that closes a cycle points back to the left, and
cards deeper than five columns share the last one. An arrow that skips a column
runs along the gap between two rows rather than behind the cards it passes, and
arrows between neighbouring columns each turn at their own point in the gap.
Cards are placed by the arrows actually drawn, so a card whose links all fall past
the arrow cap joins the unlinked cards, which fill a grid below. Background
polling keeps cards where they are so they do not move under the pointer. All origins keeps at most 100
additional reference-only candidate cards; those cards mean no captured rows are
shown in this snapshot, not that the origin has never been captured. Relationship and
source lists show at most 30 rows per pane, and API lists page through 50 exact
method/path entries at a time. These display caps are separate from server
projection limits, and the UI reports omitted or incomplete data explicitly.

Selecting a card or API entry only changes the local view. Viewing source reads
safe metadata from Sniper's exact-row evidence endpoint. Map and APIs never load
the legacy whole-history Paths response. Removal and retention events invalidate
displayed counts and evidence; other history changes label the previous snapshot
until the next bounded read completes. Exact method/path selection survives a
refresh only while that endpoint remains in the result; source verification is
cleared when its snapshot is invalidated. Local origin search keeps the inspector
and labels a selected origin outside the filter or card limit. Redirect
relationship rows include the query-free target path so different destinations
on the same origin remain distinguishable.

## Bounded ordinary-map refresh

Ordinary map reads share one application-wide worker slot. This slot never
gates proxy forwarding or unrelated API operations. Canceling an HTTP request
does not free the slot while its queued or running worker is still projecting,
aggregating or serializing, and a filter change, Reload or history invalidation
cancels the read it replaces. A second map read therefore waits up to 20 seconds
for the slot; a whole-history read of the same request then usually answers from
the map the first one cached. Only a read still waiting after that receives HTTP
429 with `x-sniper-service-map-error: busy`. The GUI takes a busy answer as
"still running": it keeps the map and its inspections, and its next poll asks
again; five busy answers in a row pause it like any other failure. Admission is
bounded, but Tokio's shared blocking pool does not provide a scheduling deadline.

The default 10,000 / maximum 50,000 considered-row window and 8 MiB metadata
projection limit are unchanged. Metadata projection still takes one coherent
store read lock and can delay store writers; aggregation and JSON serialization
run after releasing that lock. These three stages run on the bounded blocking
worker. The existing initial read-only inactive-session loader remains
synchronous and is outside this offload; this is not a claim that all session
loading or all map work is nonblocking.

Scope uses the shared matcher with at most 500 entries in each include/exclude
list and 512 raw bytes per pattern. Excess preparation input fails explicitly;
no rules are silently truncated. One read has 8,388,608 logical patterned-match
work units, charged before comparisons. This is a deterministic work bound, not
a wall-clock promise. A read-local cache retains completed true/false decisions
for at most 512 exact raw hosts and 128 KiB of key bytes. Reaching cache capacity
only stops further caching; it never drops rows, resets the budget or changes
scope semantics. If preparation or matching exceeds its bound, HTTP 422 with
`scope_work_limit` replaces the entire result. No partial map or guessed coverage
counts are returned. Narrow the scope rules or request a lower row window before
retrying; the application never changes these settings automatically.

After serialization, publication checks validate session/context identity,
frozen scope-list equality and a private destructive-history epoch. Delete,
retention trim, full-record update, store replacement and duplicate-ID hydration
invalidate that epoch under the same store write lock. Pure appends and
annotation/body-storage-only changes do not. The captured window may therefore
remain valid after an append; new appended rows are not added to its counts.
Full response updates elsewhere in the store can conservatively reject a read.
These are validated checkpoints, not an atomic transaction across session,
runtime and history. The private epoch changes no saved format or evidence token.

Fixed failure markers are paired with exact statuses: 429 `busy`, 422
`scope_work_limit`, 409 `session_changed`, `scope_changed` or `history_changed`,
and 500 `build_failed`. GUI and CLI accept only these exact pairs and never echo
server error bodies. Unrecognized, duplicate or mismatched markers use a fixed
generic error; older servers need not supply a marker. Successful legacy/v1/v2
response shapes and catalog negotiation are unchanged.

While Service Map or APIs is open, the GUI rereads retained metadata every
1.2 seconds, skipping overlapping reads. Background reads keep the Reload label,
button geometry, empty-state content and progress presentation steady. The compact
Reload button remains available for an explicit reread or recovery after failure;
initial and manual loads still show a busy state. It does not make target requests.

After a failed refresh, the GUI visibly pauses background reads and offers
**Reload**. Any retained previous map is labeled stale. A source/scope/history
conflict clears verified evidence and supplementary overlays. History events,
reconnects and leaving/reopening the view do not silently restart paused reads.
An explicit Reload or actual scope/session change can resume them. Local origin,
product, method and path filters remain read-free and do not clear the pause.
The CLI reports a fixed failure once without retrying. Its codes are
`SERVICE_MAP_BUSY`, `SERVICE_MAP_SCOPE_WORK_LIMIT`,
`SERVICE_MAP_SESSION_CHANGED`, `SERVICE_MAP_SCOPE_CHANGED`,
`SERVICE_MAP_HISTORY_CHANGED` and `SERVICE_MAP_BUILD_FAILED`; existing status-
based exit codes and `retryable:false` remain unchanged.

## Every retained row in the GUI

The GUI map reads every retained row, not a newest-rows window: it asks for
`all_rows=true`. The server folds each row into the map as it projects it, newest
first, and keeps none, so the 8 MiB projection limit does not apply. It holds the
store lock 8,192 rows at a time, so capture continues while a large session is
read. Appends and updates during the read wait for the next map. Retention at its
limit removes a row with every capture; the read continues below the oldest row
it has read that is still retained, and fails with `history_changed` only if none
of its last 8,192 rows remains. No history check follows the read: the map shows
the history as it read it.

A measured 240,000-row session took about 0.7 seconds to read, so the server
keeps the last whole-history map. A poll is answered from it while history is
unchanged, or while it is younger than four times its build time (at least
1.2 seconds), and may then show rows removed since. Note and color-tag edits,
including rollbacks, also change this history identity because they can change
filtered membership. `fresh=true` bypasses the polling cooldown; an unchanged,
fully read map can still be reused. The GUI sends that on its first read and on
Reload. `sniper-cli` keeps the windowed read and its `max_records` unless
`--all-rows` asks for every row.

## Reported products and local origin filters

Origin cards summarize at most two products from the loaded, validated response-
header observations, with `+N` for further products; hovering `+N`, or focusing
the card, lists them. A product found without a version shows its name alone.
A product's chip carries its logo, and a card with no captured favicon shows
the leading product's logo on its brand colour. The logos come from Simple
Icons 16.35.0, bundled in `web/product-icons.js`: 170 products share 139 icons
released under CC0, MIT, Apache-2.0, BSD or CC-BY, each licence noted in the
file. Icons under a copyleft, non-commercial or custom licence (Vue.js, PHP,
Ruby, Jenkins, Debian, Keycloak, Quasar) are left out, and those products keep
a letter or no mark. Nothing is fetched at run time. Full hover titles and the
inspector retain each literal version, unknown reason, header source, timestamp
and exact evidence link separately. Missing product/version metadata is labeled
unavailable; a present empty observation list says no declarations are loaded.
Neither means that a product is absent. Legacy catalog v1 coverage remains
explicit. Legacy clue strings and optional HTML-generator inspections are not
converted into origin product aggregates.

The collapsed **Products / versions** toolbar disclosure filters only loaded
origins. Product IDs and reported version strings use exact equality. `1`, `01`
and `1.0` remain different; no version is chosen as newest or installed. Multiple
reported versions means two or more distinct literal values for the same product
within one origin. Known and unknown observations can coexist without creating
a version conflict. Unknown-version filters require the corresponding explicit
observation status; missing metadata does not match them. Both selected fields
must match the same product. Changing the product never silently clears the
version; a disappeared choice remains selected with an unavailable/zero-match
notice. Options do not depend on origin search.

These filters affect All origins, direct neighbors, and the global API catalog's
origin membership. Catalog paths belong to matching origins; this does not prove
that each path reported the product/version. The selected inspector and its local
method/path filters remain independent, with an outside-filter notice. Direct
anchors and peer inspected sources stay pinned as labeled context, excluded from
matching-origin counts. Reference-only and peer-only origins cannot inherit a
source's technology. Peer cards use only their exact origin's default loaded
aggregate and label that metadata unavailable when there is no such aggregate;
peer inspection counts remain separate from default-map counts.

Product filters issue no reads and cancel no pending exact-source, body, Link,
HTML-generator or peer inspection. They preserve selection, shown inspections,
graph mode, zoom and exact endpoint page anchors. Clearing a filter can return
the catalog to its still-loaded anchor. Same-session refresh, invalidation and
scope changes retain filters; changing the session clears them. Existing source
and generation invalidation rules still apply. Display details partition loaded,
query-hidden, product-hidden, matching and display-cap-omitted origins. Server
projection omissions remain separate; unloaded products and distinct origins are
not counted or inferred. The primary summary keeps nonzero omissions visible.

## Loaded endpoint navigation and filters

Both API lists share local exact, case-sensitive method selection and literal,
case-sensitive path-substring filtering. These controls inspect only method/path
combinations already present in the loaded snapshot and make no additional reads.
Origin search remains separate. Counts distinguish loaded combinations, matches,
locally hidden combinations, and the server omissions in the snapshot summary;
the loaded lists are not an exhaustive endpoint inventory.

Opening exact evidence and returning to APIs retains the selected endpoint and
page. Refreshes reconcile by origin, method, and path rather than stale array
positions; a removed page anchor keeps the nearest valid previous page. A
transient invalidated snapshot does not erase that fallback. Filtering an endpoint
out leaves its inspector and verified evidence selected with a visible notice.
A selected method absent from a refreshed snapshot remains selected and shows an
explicit empty state instead of silently widening to all methods. Session changes
clear these local filters and page anchors.

## Direct relations view

All origins remains the default graph view. Direct relations is an optional,
local view of origins and recorded-address nodes directly connected to a chosen
anchor by loaded declarations or explicitly shown inspections. It does not traverse
multiple hops or infer service calls. Selecting a different card changes the
inspector; an explicit Focus selection action changes the pinned anchor.
Explicitly shown body, Link and recorded-peer inspections can coexist with
metadata relations, as described below. All origins, Direct relations and Focus
selection preserve the collection and inspector. An address neighbor incident
to a pinned origin remains visible even when that context origin is outside
search/product filters; the anchor is not counted as a filter match.

The anchor is included before the 24-card display cap. Local origin search
filters its neighbors while keeping the anchor visible; the view labels an
anchor outside the search. Counts distinguish all unique loaded neighbors,
query-hidden neighbors, card-cap omissions, and typed arrows among displayed
cards. Multiple captured redirect paths can share one typed origin-to-origin
arrow; their exact paths remain separate in the inspector. The compact summary
keeps nonzero omissions visible; Details exposes complete typed-link counts,
direction definitions, and display limits.

Neighborhood discovery uses the full bounded metadata response, independently
of the All origins view's reference-card cap. It cannot recover metadata omitted
by server projection limits or retention. A reference-only anchor remains a
metadata reference, with no observed traffic count. No loaded neighbors means
only that this snapshot has no directly related other origins for the anchor.

Mode changes, focusing, and card selection send no requests. Scope filtering
still reads fresh retained metadata. Temporary invalidation clears displayed
data, and a fresh result that no longer contains the anchor returns to All
origins. A session change resets the mode and evidence immediately.

## Service Map filter

The map has its own display filter, as Burp keeps one for its site map. **Filter**
on the map toolbar opens the same dialog as HTTP history's filter, editing the
map's settings: MIME type, status class, hidden extensions, rows with responses
only, parameterized rows only, rows with notes only, port and advanced search.
Scope stays on the map's own **In scope** toggle beside it, as in History, and colour tags stay with
History. The two filters are saved apart in UI settings; changing one never
changes the other.

The default hides `png,ico,css,woff,woff2,ttf,svg,jpg,jpeg,gif`, as History's does,
so a page's image and style CDN drops out of the map with its rows. Each condition
hides exactly the rows it hides in HTTP history: the server applies History's own
row matcher while it takes the snapshot. Origins, endpoints, redirect
instructions and Origin/Referer declarations seen only in hidden rows disappear
with them. The GUI filters every retained row. A windowed read (the CLI's)
filters inside the newest-row window and does not widen it.
`snapshot.filtered_rows` counts the hidden rows, and
Details reports them. Changing the filter re-reads the map and ranks the cards
again for the rows that remain; a filter restored from settings does the same on
the next read.

## Links by request kind

An Origin or Referer header says only which page a request came from. A page that
loads forty images from a CDN declares forty Referer links, and they look the same
as its API calls. So each `header_links[]` entry counts its rows (`request_count`)
and sorts them by request kind (`request_kinds`):

| Kind | Rows |
| --- | --- |
| `api` | `Sec-Fetch-Dest: empty` (fetch or XHR) |
| `navigation` | `Sec-Fetch-Dest: document` |
| `frame` | `Sec-Fetch-Dest` of `iframe`, `frame`, `embed`, `object` or `fencedframe` |
| `script` | `Sec-Fetch-Dest` of `script`, a worker, a worklet or `xslt` |
| `static` | `Sec-Fetch-Dest` of `image`, `style`, `font`, `audio`, `video`, `track` or `manifest` |
| `other` | any other value |

Browsers send `Sec-Fetch-Dest`. Without it (an older browser, a non-browser
client), the response type decides: HTML is `navigation`; JSON, XML, protobuf,
gRPC or GraphQL is `api`; JavaScript is `script`; images, fonts, audio, video and
CSS are `static`. A row with neither is `api` when it has an `Origin` header or a
method other than GET and HEAD, and `other` otherwise. Every input is a header the
client or server sent, so a kind describes how a row looked, not what the page
intended.

The legend under the map has one toggle per kind found in the loaded links, with
the number of links that include it. Frames, scripts and static files are hidden
by default, so API calls, page navigations, unclassified requests and redirects
draw arrows, and a page's CDN loads draw none. The rows of a hidden kind do not
draw, rank or weigh a link: a link made only of hidden kinds is not drawn, and a
link with other rows is drawn for those rows only. The map draws one arrow per
direction between two cards: a redirect, Origin and Referer links and a shown
inspection share it, drawn as the first of them, and its tooltip names them all.
Direct relations keeps one arrow per relationship, the typed view it is for.
The arrow takes the colour of its first shown kind in the order of the table
above: API calls a muted blue, half transparent so that many of them do not
flood the map; page navigations, frames and other requests grey; scripts and
static files faint grey; the selected card's arrows gold. So one API call among
a CDN's image loads still reads as an API link. Each legend toggle shows its
colour. More rows draw
a slightly heavier line, from 1.5px for one row to 2.5px from 64 rows, and an
arrowhead takes its line's colour at one size. The tooltip lists the rows by
kind.
The choice is saved in UI settings (`service_map_hidden_link_kinds`). It hides
arrows, not cards: to drop a CDN's cards too, use the
[Service Map filter](#service-map-filter). Redirects are always drawn and count
their rows in `request_count` as well.

Each link also counts the rows whose response let its source origin read it
(`cors_allowed_count`): a single `Access-Control-Allow-Origin` naming that origin
exactly as a browser sends it, or `*`. Of those, `cors_credentials_count` counts
the rows that named the origin and sent `Access-Control-Allow-Credentials: true`,
which lets a page read the response with the user's cookies. Both are omitted
when zero. They describe what the responses allowed, not that a browser read
them across origins.

Pointing at an arrow shows its rows by kind and its CORS counts. Selecting it
selects the origin that recorded it (the target of an Origin or Referer link,
the source of a redirect) and marks the relationship in the inspector, where
View source opens an example row.

## Front-end technologies

Response headers name few products and rarely a version: `X-Powered-By: Next.js`
carries none. Responses say more in three places, and the map reads all three
without running anything:

- **Scripts:** a license banner, such as `/*! jQuery v3.7.1`, or a runtime value,
  such as Next.js's `window.next={version:"…"}`, React DOM's renderer
  registration or Vue's `__v_isRef`.
- **Pages:** markup a framework renders, such as Angular's `ng-version="…"`,
  Vue's `data-v-…` attributes, AngularJS's `ng-app`, Nuxt's `__nuxt` root or
  WordPress's `/wp-content/` paths, and the page's `<meta name="generator">`.
- **Asset URLs:** a CDN's `package@version` path (`/npm/vue@3.4.21/`,
  `/ajax/libs/jquery/3.7.1/`), a versioned file name (`jquery-3.6.0.min.js`), a
  library's own file without a version (`jquery.min.js`, `bootstrap.min.css`),
  the directory a framework builds into (`/_next/static/`, `/_nuxt/`,
  `/_app/immutable/`), or the host a third-party service serves its script
  from (`js.tosspayments.com`, `cdn.amplitude.com`). Paths are matched on any host, so a company's mirror of a
  public CDN counts. A script, stylesheet or image row's own URL is read without
  its body; a page's linked scripts and stylesheets are read from its markup.

About 150 products are covered, in six categories: meta-frameworks (Next.js,
Nuxt, SvelteKit, Remix, Gatsby, Astro), CMSs and site builders (WordPress, Drupal,
Joomla, Magento, Shopify, Wix, Squarespace, and any generator a page names),
frameworks (React, Vue.js, Angular, AngularJS, Svelte, Ember.js, Preact, Lit,
Qwik, Alpine.js, htmx, Turbo, Livewire, Backbone.js, Knockout), UI kits
(Bootstrap, Vuetify, Element Plus, Element UI, Quasar, Font Awesome), libraries
(jQuery and its UI and Migrate, Lodash, Underscore.js, Moment.js, Day.js,
core-js, Axios, Socket.IO, DOMPurify, Chart.js, D3, three.js, Leaflet,
Highcharts, ECharts, GSAP, Swiper, Video.js, hls.js, Select2, Popper,
Handlebars, Modernizr, Zepto, Prototype, MooTools, PDF.js, TinyMCE, CKEditor,
Quill, SweetAlert2, Hammer.js, Sentry, and the third-party services a page
loads: payments (Stripe.js, PayPal, PortOne, Toss Payments, KG Inicis,
NICEPAY), maps (Google Maps, NAVER Maps), CAPTCHAs (reCAPTCHA, hCaptcha,
Cloudflare Turnstile), Firebase, chat (Channel Talk, Intercom, Zendesk),
consent managers (OneTrust, Cookiebot, Didomi, TrustArc, Usercentrics,
Sourcepoint, Quantcast Choice), Polyfill.io, whose domain served malware in
2024, Font Face Observer and the Web Components and Web Animations polyfills) and analytics (Google Tag Manager, Google Analytics, NAVER Analytics,
Tealium, Adobe Launch, Amplitude, Mixpanel, Segment, Hotjar, Microsoft Clarity,
Plausible (and its `pa-…` scripts on a site's own proxy), Matomo, Chartbeat
(and its inline `_sf_async_config`), Akamai mPulse, New Relic, Datadog RUM, HubSpot,
the Meta, TikTok, LinkedIn and X pixels, ad networks, AceCounter, Beusable and
Dable). Wappalyzer's catalogue was the checklist; the rules are Sniper's
own. Only these anchors count: a bundle holds other libraries' `version:"…"`
literals too. Many signals name a product without its version; the card then
shows its name alone.

Script and page bodies are read once per row revision. A repeated URL and size
do not prove that two responses contain the same version: each new response is
read within the budget. Detections are reused only when a SHA-256 hash of the
bounded scan text and its content kind match; file-name-specific source-map
suppression is then applied separately. A page that is not UTF-8, such as an
EUC-KR page, is stored as base64 and read all the same: every
signature is ASCII. One map reads at most 256 rows, whether resident or on
disk, and 32 MiB in all. Resident previews are scanned up to an 8 MiB prefix;
retained serialized rows larger than 8 MiB are skipped. Later maps read rows
that exceeded the per-map budget. An asset's technologies go to the page that
loaded it (its Referer) when that page is in the map, else to the asset's own origin, so a
bundle served from a CDN names the page's framework. A one-origin, in-scope or
origin-capped map leaves the CDN out but keeps what the page took from it, so
it names the same front end the whole map does. A page's own stay with the
page. Scoped whole-history maps first identify their admitted origins using
captured host scope and the display filters, with the same chunked locking and
bounded scope work. Only those origins and assets referring to their pages
spend body reads, so unrelated pages and CDN traffic cannot starve them. A row
counts once for a product, however many of its signals name it.

The card leads with what the site is built with (a meta-framework, then a CMS,
then a framework), then the products its headers declare, then UI kits,
libraries and analytics; a meta-framework, CMS or framework also makes the card
Front. The inspector lists them under **Front-end**, each with View source. The
API and the CLI carry them on the origin as `front_technologies` (`product_id`,
`name`, `category`, `version` when named, `source_origin` where the first naming
row was served, `row_count`, `evidence`), at most 32 per origin, omitted when
nothing names one.

## API paths

The inspector's APIs tab and the API catalog list an origin's endpoints by
method and path. Paths that differ only in an ID share one row: the template
with its ID segments marked, how many paths and rows it stands for, and their
sign-in kinds; opening it lists the paths, each selectable. A segment is an ID
when it is all digits (up to 18), a UUID, or 16 to 128 hex digits with at
least one digit and one letter, as a MongoDB ObjectId or a hash is; the API and
the CLI carry the template as the endpoint's `path_group`
(`/web/chats/{number}/posts/{hex}`), the same as `path` when it has no ID.

## Unnamed signals

What an origin's responses carry that no rule names is kept for a reader to
judge, person or agent: a `Server` or `X-Powered-By` value (`server: HeRay`),
a response header name no server sends by default (`heray-cache-status`), and
a cookie name (`WMONID`). Standard headers, a named header and a catalog
product are left out, and so is a `Via` value, which can name an internal
host; no other header value is kept. The inspector folds them under **Unnamed
signals**, each with View source; the API and the CLI carry them as the
origin's `unnamed` (`banners`, `headers`, `cookies`, each busiest first and at
most 16, with `value`, `row_count` and `evidence`), omitted when everything was
named.

`sniper-cli scope service-map unnamed` gathers them across the session's whole
map, as an agent working through them needs: each signal with how many origins
and rows carried it, up to five of those origins and three evidence tokens,
and `named_alongside`, the products the map named on the same origins with how
many of them, most widespread first, `--kind` keeping one kind and `--limit`
bounding the list. The origins a signal came from are often the best clue to
whose it is; a header that always travels with one product
(`cdn-pullzone` beside BunnyCDN) is likely that product's own. A name many
vendors use (`uid`, `x-trace-id`) names nothing on its own.

The summary carries the source map's `snapshot` unchanged: inspect `complete`,
`stopped_by`, `omitted_rows`, row counts, timestamps and limits before treating
it as exhaustive. `distinct_signals` counts only available signals after
`--kind`; `omitted_signals` counts only those hidden by `--limit`. Zero omitted
signals does not mean the source map was complete. The source keeps at most 16
unnamed signals per row and 16 of each kind per origin; exceeding either marks
`unnamed_signals_per_row_limit` or `unnamed_signals_per_origin_limit` in
`snapshot.stopped_by`. These are signal omissions, so `omitted_rows` may still
be zero. Older servers may not report these unnamed-signal caps. Filtering to
one kind does not recalculate or erase the source map's coverage warnings.

```bash
sniper-cli scope service-map unnamed --kind headers --limit 50
```

## Endpoint parameters

Opening an endpoint reads its parameters at once, with no button to press: the
endpoint's newest 200 retained rows, listing each parameter by name, where it
was sent (`query`, `form`, a top-level `json` field, or a `multipart` field
name), how many rows carried it, and up to three of its values, each cut to 80
characters. Request bodies are read for this only while an endpoint is open,
and only in the active session; a body is parsed from its first 64 KiB. The
values are shown as captured, as in HTTP history. Body formats are selected by
media type, ignoring parameters; JSON includes structured `+json` media types.
Multipart names come only from complete top-level `Content-Disposition:
form-data` part headers within that prefix, using the declared boundary. File
contents and multipart values are never returned; nested multipart is not expanded.
Closing and reopening an endpoint reads its newest rows again. Reload and
history, session or filter invalidation discard the old values and fence late
responses; a still-open endpoint is read again after a current map verifies it.
An unchanged background map refresh does not restart a parameter read.
`GET /api/target/service-map/parameters` with `session_id`, `origin`, `method`
and `path` returns the same result, and so does the CLI:

```bash
sniper-cli scope service-map parameters --session-id <active-session-uuid> --origin https://example.com --method GET --path /search
```

## OpenAPI

**API docs**, in the inspector of an origin that serves API data or signs
users in, opens an OpenAPI 3.1 description of what its retained rows show, laid
out as Swagger UI lays one out: each operation opens to its parameters, request
body, responses and credentials, and **Send newest row to Replay** opens the
newest row it stands for in Replay, as Burp's OpenAPI Parser sends an operation
on to Repeater. **Copy OpenAPI JSON** copies the document for Swagger UI,
Postman, Burp or an agent, as Burp's API Exporter and mitmproxy2swagger build
one from captured traffic. **Open in Swagger Editor** copies it the same way
and opens editor.swagger.io, in the default browser from the desktop app, to
paste it into; the editor cannot read the document from Sniper, and nothing is
sent to it until it is pasted. There is no Try it out: a request goes through
Replay, and so through the proxy. The document lists each method and path
template, with the ID segments as named path parameters (`{number}`, `{uuid}`,
`{hex}`). If ID kinds differ in the same path position, one `{id}` path
parameter accepts the observed kinds and the operations' counts and evidence
are combined. It includes the query, form, top-level JSON and multipart field
names from each observed method/path variant's newest 20 rows. JSON fields keep
their parsed types (including null and mixed types); text fields use types
guessed from their values. It also lists each response status with its media
types and the credentials the rows showed, as security schemes. Each scheme
is one alternative: the rows show what was
sent, not what the server requires. Every retained row of the origin counts,
each operation's `x-sniper-requests` says how many it stands for, and
`x-sniper-newest-transaction` names the newest of them (`capture http get --id`).

No captured value is copied; a type is all that is kept of one. Operations that
only answered with pages or static files, or whose path names one (`.woff2`,
`.png`, `.js` and the like), are left out, and so are OPTIONS
requests, nearly always CORS preflights, and methods OpenAPI cannot hold. At
most 500 operations are listed, the most recently used, and `info.description`
says what was left out. Like the parameters, it reads the active session only.
`GET /api/target/service-map/openapi` with `session_id` and `origin` returns
the document, and so does the CLI:

```bash
sniper-cli scope service-map openapi --session-id <active-session-uuid> --origin https://api.example.com > api.json
```

## Server technologies and exposures

The header catalog below reads three headers for a fixed list of product
literals. An origin's own responses say more about the servers behind it, and
the map now reads four places for that, without sending anything:

- **Vendor header names:** `CF-RAY` (Cloudflare), `X-Amz-Cf-Id` (CloudFront),
  `X-Served-By: cache-…` (Fastly), `x-envoy-*` (Envoy), `x-kong-*` (Kong),
  `X-Varnish`, `x-amz-id-2` (S3), `X-Vercel-Id`, `X-Jenkins: 2.426.1`,
  `kbn-version` (Kibana), Fastly's `X-Timer` and Next-Gen WAF's
  `X-SigSci-RequestID`, Tencent EdgeOne's `EO-Cache-Status`, OVHcloud's
  `X-IPLB-Request-ID`, any `Akamai-…` header and Akamai's `Edge-Cache-Tag`,
  Alibaba Cloud CDN's `Ali-Swift-Global-Savetime` and `EagleId`, Alibaba Cloud
  OSS's `x-oss-request-id`, Azure Front Door's `X-MSEdge-Ref`, F5 BIG-IP's
  `X-Cnection` (its OneConnect marker), Meta's `x-fb-debug`, a Next.js
  server's `x-nextjs-cache`, `X-Redirect-By: WordPress`, an `X-AspNet-Version`
  emptied to hide the version, IIS Express's `X-SourceFiles`, the PageSpeed
  module's `X-Mod-Pagespeed`, a Kubernetes API server's `X-Kubernetes-PF-…`,
  Consul's `X-Consul-Index`, `X-Influxdb-Version`, and about sixty more.
- **Header values the catalog does not name:** `Server: AmazonS3`,
  `awselb/2.0`, `Kestrel`, `Werkzeug/3.0.1 Python/3.12.0`, an operating system
  in parentheses (`Apache/2.4.52 (Ubuntu)`), `Via: 1.1 … (CloudFront)`,
  `X-Powered-By: Servlet/4.0`, `X-AspNet-Version: 4.0.30319`,
  `Payara Server 6.2024.6`, `GlassFish Server Open Source Edition 4.1.2`,
  TmaxSoft `WebtoB`, Google's own front ends (`gws`, `sffe`, `ESF`, `GSE`),
  NAVER's (`nfront`, `Testa/6.2.14`), CDNetworks' `PWS/8.3`, `BunnyCDN-…`,
  Apache Traffic Server's `ATS`, Baidu's `BLB`, ByteDance's `TLB`, Adobe
  Experience Platform's `jag`, JD.com's `jfe`, Meta's `proxygen-bolt`,
  Tencent's `tRPC-Gateway`, Gabia's `gabia server`, Rocky Linux, AlmaLinux,
  Fedora, SUSE, Raspbian or Gentoo in parentheses, Windows behind
  `Microsoft-IIS` or `Microsoft-HTTPAPI`, Ubuntu or Debian in a distribution's
  PHP build (`PHP/7.4.3-4ubuntu2.19`, `PHP/7.4.33-1+deb11u4`), enterprise
  application servers (`Resin`, Oracle iPlanet, `SAP NetWeaver Application
  Server`, `Lotus-Domino`, Zope), Python's own servers (`TwistedWeb`,
  aiohttp, `WSGIServer`, `BaseHTTP`/`SimpleHTTP`), Mojolicious, H2O, Yaws,
  the servers embedded in routers and cameras (Mongoose, GoAhead, Boa,
  thttpd, RomPager, Appweb), Wix's `Pepyaka`, CouchDB, MinIO, Google Cloud
  Storage's `UploadServer`, `tencent-cos`, `nghttpx`, Tencent's `Trpc httpd`, and
  `X-Powered-By: JSF` or `HHVM`.
- **Names of the cookies a response sets:** `JSESSIONID` (Java servlet,
  also under a changed name such as `HH_JSESSIONID`), `PHPSESSID`,
  `ASP.NET_SessionId`, `laravel_session`, `connect.sid` (Express), `AWSALB`,
  `BIGipServer…` (F5), `TS…` (F5 WAF, with a path's own `TS…029`), `__cf_bm`,
  `incap_ses_…`, `ak_bmsc`, `AKA_A2`, `ak-inject-mpulse`, `datadome`,
  `ARRAffinity` (Azure App Service), `SERVERID` (HAProxy), `KEYCLOAK_SESSION`,
  Spring Session's `SESSION` (only when its value is a UUID in base64, as
  Spring writes it; other stacks use the name too), and from Korean sites
  `LENA-UID` (LENA), `egovLatestServerTime` (eGovFrame) and the APM agents'
  `SCOUTER`, `WHATAP` and `elevisor_for_j2ee_uid`. A value is never read,
  except a BIG-IP cookie's, to tell whether it encodes the pool member's
  address, and a session ID's shape, which names the servlet engine that
  issued it: JEUS appends its domain and server in base64, WebLogic a JVM hash
  after `!`, WebSphere a `0000` prefix and a clone ID after `:`, Jetty
  `node0…`. Neither the address nor the server name is reported.
- **Bodies:** default error pages (`<center>nginx/1.25.3</center>`,
  `<address>Apache/… Server at …</address>`, `Apache Tomcat/9.0.83`, Spring
  Boot's Whitelabel page and JSON error, Express's `Cannot GET`, Werkzeug's
  404 text (named Flask, which serves it whatever server runs the app),
  FastAPI's and DRF's `detail`, WildFly's welcome page and Undertow's error
  page, Open Liberty's pages and WebSphere's `SRVE…E` servlet codes, Payara's
  and GlassFish's error reports, Grafana's boot data), gateway and WAF pages (HAProxy,
  Envoy, Varnish, Cloudflare, Akamai, Imperva, ModSecurity, Kong, API Gateway),
  debug pages, stack traces, SQL errors, and banners such as Elasticsearch's.
  Pages are read as for the front end; JSON, XML and plain-text responses are
  read only when they are errors (status 400 or above), an origin's root, an
  `/actuator` path, an API document or another management or debug path
  (`/.git/config`, `/.env`, `/debug/vars`, `/debug/pprof`, `/jolokia`,
  `/metrics`, `/server-status`, `/health`, `/info` and a few more), or when a
  tester sent the request from Replay, whatever its status, so an API's
  successes do not spend the read budget. A Java stack trace counts in a JSON
  error too, where `\tat` escapes the tab before each frame.

The server rules were checked against real servers run in a lab: nginx,
Apache httpd, Tomcat 9 and 10, Jetty, WildFly, Open Liberty, Payara,
OpenResty, Caddy, Traefik, HAProxy, Varnish, Envoy, PHP on Apache,
OpenLiteSpeed, Kestrel, Express, gunicorn, uvicorn, Django's and Flask's
development servers, Kong, Jenkins, Grafana and Elasticsearch, each answering
its root and a missing path. Traefik's not-found page is Go's own, so it reads
as Go. They were then run over 667 public sites' homepages, Korean government,
public, finance, university and company sites among them, visited in a
headless browser through Sniper (Kakao and Daum hosts and private addresses
refused): every header value, cookie name, generator and script path seen on
more than a few origins was traced to its hosts, and those Sniper could name
were added. JEUS, invisible behind a masked `Server` on many Korean sites,
showed in 59 hosts' session IDs; `WMONID`, set by 86, appears beside JEUS and
other engines alike, so it names nothing.

Two later passes worked down the unnamed signals of that crawl and of 358 more
sites (Japanese, Chinese, European, Russian, American and Asia-Pacific sites,
developer tools and CMS vendors), each signal traced to the hosts it came
from. They added Tencent's (`NWS…`, `stgw`, `x-cos-*`), Baidu's (`JSP3`,
`ohc-*`, `BceBos`), ByteDance's Volcengine (`x-tt-logid`, `ImageX`),
Kasada's `x-kpsdk-*`, Atlassian's edge (`AtlassianEdge`, `atl-traceid`),
Automattic's on WordPress.com, Tumblr and WooCommerce (`x-hacker`,
`x-remembering`, an `x-nc` such as `HIT ord 2`), `X-Powered-By: WordPress VIP`,
BunnyCDN's `CDN-PullZone` and the rest of its `CDN-…` headers, Fly.io's
`Fly/…` banner, Arc XP's `x-arc-*`, Sanity's `sanity-*`, Read the Docs'
`x-rtd-*`, Magnolia's `x-magnolia-*`, the imgix, Cloudinary, imgproxy,
Contentful, DataDome and Framer banners, Vercel's `x-matched-path`, a Next.js
server's other `x-nextjs-*` headers, S3's and Cloud Storage's object metadata
(`x-amz-meta-*`, `x-amz-expiration`, `x-goog-meta-*`, `x-guploader-*`), API
Gateway's `x-amzn-Remapped-*`, AppDynamics' `ADRUM` and Dynatrace's
`dtCookie` and `rxVisitor` cookies, ingress-nginx's `INGRESSCOOKIE`, and the
cookies ad and analytics services set on their own hosts (Magnite's `khaos`,
LiveRamp's `pxrc`, Sovrn's `ljt_reader`, PubMatic's `KADUSERCOOKIE`,
StackAdapt's `sa-user-id`, Segment's `ajs_anonymous_id`, Meta's `_fbp`,
server-side Tag Manager's `FPID`, LinkedIn's `bcookie`, X's
`personalization_id`, Adobe Advertising's `everest_g_v2`, Yahoo! JAPAN's
`_yjsu_yjad`, and more). Pages now also name the APM agents and tags they
load: Dynatrace's `ruxitagentjs_…`, AppDynamics' `adrum-…`, Klaviyo, Clearbit,
EthicalAds and Yahoo! JAPAN's `ytag.js`. A name many vendors use (`uid`,
`audit`, `MUID`, a `_gid` that NetEase sets too) was left unnamed, and so were
generic headers such as `X-Cache`, `traceparent` and the rate-limit family,
which no longer show as unnamed signals.

A response header longer than 4 KiB, which a site's Content-Security-Policy
often is, is skipped by itself. The page is still read for its front end and
servers, and its redirect and CORS answer still count. An oversized `Location`
suppresses only the redirect; an oversized `Access-Control-Allow-Origin`
suppresses only the CORS answer. A count or total-byte scan limit still suppresses
both because unread headers could contain duplicates. Before this, one
long policy left the whole page unread: in the two crawls, 123 pages, 13
redirects and 192 CORS answers.

A request target's length no longer drops its row. The query is never read, so
a tracking pixel's 6 KiB query counts like any other row, and a path longer than
2,048 bytes counts for its origin (its rows, products, clients and links) while
only its endpoint is left out, with `path_limit` in `snapshot.stopped_by`.

Each finding gets a layer, outermost first: `edge` (CDN and WAF), `gateway`
(load balancer, API gateway, proxy cache), `platform` (hosting and storage),
`web_server`, `app_server`, `backend` (framework or application),
`monitoring` (APM agents), `language`, `database`, `os`. What a response gives away by mistake is an `exposure`: a
Django, Laravel, Symfony or Rails debug page, the Werkzeug debugger, a
detailed ASP.NET or IIS error, a PHP error or `phpinfo()` page, a Java, .NET,
Python, Node.js or Go stack trace, an SQL error, a directory listing, Spring
Boot Actuator, Swagger UI or an OpenAPI document, an Elasticsearch root
endpoint, a Git repository's `config`, an `.env` file, Go's expvar and pprof,
Jolokia, Apache's `server-status` and `server-info`, nginx's `stub_status`,
Prometheus metrics, an H2 console, a GraphiQL or GraphQL Playground page, a
backend address in a BIG-IP cookie, or an `X-Backend-Server`-style header. Scripts and pages are read for what they give away too: a
`sourceMappingURL` comment (`source_map`; not in a library's own file, such as
`jquery.min.js` saying jQuery, whose map is the library's public source), an
AWS, Google, Slack, GitHub, Stripe or SendGrid key, a Slack webhook, a private
key block with key material
after its header (a PEM parser's bare header constant does not count), a JWT
in a script or an error (a page's is usually the visitor's own token), and a
private (RFC 1918) address in a URL a script calls or anywhere in an error
(`private_ip`). Only the finding is reported, never the matched value; View
source opens the row. These are what the responses say, not verified
identification.

They always belong to the origin that responded, never to the page that
loaded the row. A card's first chip names an exposure in a word or two (`⚠ JWT`,
`⚠ AWS key +1`; hovering it lists them all) and takes one of the two product
places. The products follow, the backend and the servers in front of it first;
the inspector lists **Exposures** and **Server** with View source. The API
and the CLI carry them on the origin as `server_technologies` (`product_id`,
`name`, `category`, `version` when named, `signals`: `header`, `cookie` or
`body`, `row_count`, `evidence`), at most 32 per origin, omitted when none.
ZAP's passive rules, wafw00f's WAF checks and nuclei's technology templates
were the checklist; the rules are Sniper's own.

## Clients

Each row's `User-Agent` names the client that sent it, and for a Chromium
browser the `Sec-CH-UA` and `Sec-CH-UA-Platform` Client Hints name its brand and
platform. A fixed list of rules gives each client a kind, a name, a major
version and an operating system:

| Kind | Names |
| --- | --- |
| `browser` | Chrome, Edge, Safari, Firefox, Samsung Internet, Whale, Opera, Brave, Vivaldi, Yandex Browser, Internet Explorer |
| `webview` | Android WebView, iOS WebView, and the in-app browsers of Instagram, Facebook, LINE, NAVER and WeChat |
| `app` | OkHttp, Android app (Dalvik), Alamofire, Apple app (CFNetwork) |
| `tool` | curl, Wget, HTTPie, Postman, Insomnia, Headless Chrome, sqlmap, Nmap, Nikto, WPScan |
| `library` | python-requests, HTTPX, aiohttp, Python urllib, Go net/http, Apache HttpClient, Java, axios, Node.js |
| `bot` | Googlebot, Bingbot, Yeti, Applebot, DuckDuckBot, Baiduspider, YandexBot, link previews of Facebook, Twitter, Slack, Discord and LinkedIn, GPTBot, ClaudeBot, and any other crawler |
| `unknown` | Other, and No User-Agent |

An app's WebView sends a browser's User-Agent without the browser's own token,
so an in-app browser no rule names is an Android or iOS WebView. Only these
names reach the map; the header itself never does.

The map counts each client's rows per origin, and apart from them the rows it
sent itself, with no Origin or Referer: a typed address or bookmark, a
browser's own background request, an app's or a tool's call. A page's own
requests carry the page in Referer and already have its arrow. Rows of one
kind, name and operating system are one client, whatever versions they named:
a browser that updated during a session is one Chrome, not one per version. In
the GUI the clients lead the map in a column of their own, centred against the
tallest column, up to four cards beside the origin cap; an `unknown` client
draws none. Each client draws a long-dashed **Direct request** arrow to the
shown cards it went to itself that no other shown card links to, where the map
starts; a card a page links to already shows how it was reached, and an app's
background calls to every such card would cover the map. Selecting a client
lists the origins it sent rows to, its versions and the addresses it connected
from, and draws its arrow to every shown card it went to itself. A request kind
hidden in the legend hides those arrows too, and a client left with none draws
no card.

Each captured row keeps the address of the client that sent it to the proxy
(`client_address`): a browser on this machine is `127.0.0.1`, a phone on the
network its own address. A card names that address when there is one, or how
many. Rows Sniper sent itself carry none, nor do rows captured before it was
kept.

The API and the CLI carry `clients`, busiest first and at most 16 (`kind`,
`name`, `versions`, the major versions its rows named, newest first and at most
eight, omitted when none, `os` when known, `request_count`, `addresses`, the IP
addresses it connected from, at most eight, omitted when none, `origins` with
each origin's `request_count` and `entry_kinds`, the client's own rows there by
request kind, at most 64 origins, and `evidence`), omitted when no row was
analyzed.

## Authentication

Each row's request and response say how it authenticates, and the map reads
names and shapes only:

- the `Authorization` scheme: `bearer_jwt` for a token shaped like a JWT,
  `bearer`, `basic`, `digest`, `negotiate`, `ntlm`, `aws_sigv4`, or another
  `scheme`, named only when it is a common spelling (`Token`, `HMAC`, `Hawk`,
  `SharedKey` and a few more) since an unknown first word may be the
  credential itself;
- an API key header by name (`X-API-Key`, `X-Auth-Token`, `X-Goog-Api-Key`,
  `Ocp-Apim-Subscription-Key` and the like), or a vendor's own spelling of one
  ending in `-api-key` or `-token` (`X-Airbnb-API-Key`, `Phantom-Token`); a
  CSRF or CAPTCHA token does not count;
- cookies a request carried or a response set: `session_cookie` when the name
  says session (`JSESSIONID`, `PHPSESSID`, `connect.sid`, `SESSION`), and
  `jwt_cookie` when the value is shaped like a JWT;
- a `WWW-Authenticate` challenge;
- a credential in the URL (`query_key`: `access_token`, `api_key` and a few
  more), and signed AWS URLs;
- OAuth 2.0 (`response_type` with `client_id`), OpenID Connect (`scope=openid`,
  `/.well-known/openid-configuration`) and SAML (`SAMLRequest`, `SAMLResponse`).

No credential value is kept or reported, and login forms are not read: they
would need request bodies. ZAP's authentication and session-management passive
rules were the checklist; the rules are Sniper's own.

A card's lock chip names the busiest credential in a word (`JWT`, `Cookie`,
`Basic`, `API key`), or a sign-in flow when the origin shows no credential, with
`+N` for the rest; hovering it lists them all, and it takes one of the two
product places. The APIs tab leads with **Authentication**, each method with its
rows and View source, and each endpoint names the kinds its own rows showed.
The API and the CLI carry `auth` on the origin (`kind`, `name` when it has one,
`row_count`, `evidence`), busiest first and at most 16, and `auth` kinds on each
endpoint.

## Sites and hidden origins

**Group by site** (on by default) gathers two or more origins of one site onto a
single card, as Caido's sitemap groups subdomains under their root domain. A site
is a host's last two labels, or three under common two-level suffixes such as
`co.kr` and `co.uk`; addresses and single-label hosts never group. The short
suffix list stands in for the Public Suffix List, so a host under an unlisted
suffix, or a hosting suffix such as `github.io`, groups by its last two labels.

Links follow their origins onto the card: links inside the site disappear, and
links of several members share the card's arrow with their rows, kinds and CORS
counts added up. The leading origin's site (the first card, usually the page
under test) keeps a card per origin, as does a site holding the pinned origin or
an inspection. Selecting a site card lists its origins; **Show origins
separately** keeps that site apart, and **Group again** on one of its origins
undoes it.

**Hide from map** on an origin, or **Hide site from map** on a site card, removes
it and its links from the map in every session. The legend's **Hidden** list
shows each entry with a way back, and **Show all** clears it. Grouping and
hiding change the map only: the API and the CLI still return every origin.
Hiding a pinned origin also removes its card, while keeping Direct relations,
its visible neighbors and the inspector. Show restores the same pinned card.
Both are saved in UI settings (`service_map_group_sites`,
`service_map_expanded_sites`, `service_map_hidden`).

## Read through the CLI

Discover the contract offline before reading a running local instance:

```bash
sniper-cli schema input target.service_map.get
sniper-cli schema output target.service_map.get
sniper-cli examples target.service_map.get
sniper-cli scope service-map --session-id <session-uuid>
sniper-cli scope service-map --session-id <session-uuid> --in-scope-only --max-records 10000
sniper-cli scope service-map --session-id <session-uuid> --all-rows
sniper-cli scope service-map --session-id <session-uuid> --hidden-extensions png,css,woff2 --mime-types html,script,json,other
sniper-cli call target.service_map.get --input '{"session_id":"00000000-0000-0000-0000-000000000000","in_scope_only":false,"max_records":10000}'
```

The UUID in the JSON example is synthetic. Select a real session deliberately
from session discovery. `target` remains an alias for the `scope` command group.
All Service Map operations have `side_effect: "read"` and need no `--yes`.
`--dry-run` describes the local API request without contacting it.

`session_id` is optional for the map: omission or null resolves the active session
once, then pins that UUID for the read. An explicit UUID can select an inactive
saved session without switching the desktop. Reuse the returned `session_id` for
evidence reads. Direct commands return the bare result; `call` returns the same
result in `data`, with the pinned session in `meta.session_id`.

`max_records` defaults to 10,000, accepts integers from 1 through 50,000, and bounds
retained metadata rows considered. `--all-rows` (`all_rows: true` in `call`)
reads every retained row instead, as the GUI does, and cannot be combined with
`max_records`. Optional `--origin https://example.com` (or
`origin` in `call`) selects one exact canonical HTTP(S) origin. Supply no path,
query, fragment, credentials, or explicit default port; copy the canonical origin
from a map card. `in_scope_only` defaults to false and uses the
same session scope matcher as other Sniper views. `--mime-types`,
`--status-classes`, `--hidden-extensions`, `--hide-without-responses` and
`--only-parameterized` (or the same fields in `call`) are the
[Service Map filter](#service-map-filter)'s conditions. Omitted, they hide
nothing: the CLI keeps every row unless asked, while the GUI applies its saved
filter. These are read filters, not capture or scope-setting controls. Each
header link carries `request_count` and `request_kinds`, plus
`cors_allowed_count` and `cors_credentials_count` when a response allowed its
source, and each redirect `request_count` (see
[Links by request kind](#links-by-request-kind)); a server older than 0.3.1
omits them. There is no pagination cursor, URL input,
active-discovery option, or automatic retry with a larger limit.

## What the map means

- An origin is an observed scheme, host, and effective port. It is not a discovered
  server, IP address, ownership claim, or infrastructure boundary.
  Scope is evaluated against each original captured authority, as in History.
  If canonical aliases merge into one origin card, `in_scope` means at least one
  analyzed row matched; `in_scope_only` filters individual rows before counting.
- Endpoints preserve the observed method and exact path. Query strings and URL
  credentials are omitted. Numeric and UUID path-segment grouping is only a
  conservative inventory hint; it does not prove a route template or merge
  distinct exact endpoints into one resource. Exact paths can still contain
  application-provided identifiers; keep exported map output private.
- Request counts count retained rows, including rows with duplicate transaction
  UUIDs. They are not unique users, unique requests over all time, or complete
  production traffic totals.
- Status and content-type summaries describe captured metadata. Missing response
  data is not a successful response, and absence of an observation is not evidence
  that a service or endpoint does not exist.
- A redirect relationship means a captured redirect response instructed a client
  to use a Location. It does not establish that any client followed it, that the
  target was contacted, or that the two origins call each other.
- Origin and Referer links are request-header declarations. They do not prove
  which page, browser process, or service initiated a request. Header-only origins
  do not create observed-service cards. A declaration naming the requested origin
  itself is kept in the data but not drawn or listed as a relationship.
- Technology clues are limited observations of response headers. They are not
  verified product/version detection and do not imply an application, proxy, CDN,
  or database chain. Raw header values, including cookie and authorization values,
  and request or response bodies are not included in the map or its safe evidence
  view.

The result lists initiator, remote IP, and TLS certificate in `unavailable`.
The default map continues to list response-body references as `deferred`. The
only bodies it reads are JavaScript and HTML responses, for
[Front-end technologies](#front-end-technologies), and error, root and API-document
responses, for [Server technologies](#server-technologies-and-exposures);
its metadata evidence reads none. A separate,
explicit one-row retained-preview read is described below. It does not enrich the
default inventory automatically. Do not fill unavailable gaps using hostname
guesses or present them as collected evidence.

## Reported header products and versions

New servers add optional `technology_observations` arrays beside the unchanged
legacy `technology_clues`, both on observed origins and exact evidence rows.
An absent extension means the server does not supply this contract; an empty
array means no supported literal declaration was retained in that projection.
The map's `schema_version` remains 1. Existing clients may ignore the extension;
new clients must continue to accept older responses without it.

These observations read only response headers already retained with the row.
They do not read a body, send a request, enable collection, change scope or
settings, resolve DNS, infer an address or TLS identity, or assess vulnerabilities.
Headers can be spoofed, stale, suppressed, or supplied by an intermediary.
Treat a numeric version as a **reported version**, never a verified installation
or an authoritative current version. Catalog categories such as `web_server`,
`application_server`, `language_runtime`, `edge_service`, `cms`, `connector`, and
`unknown` are product labels, not observed physical WEB/WAS or backend roles.

The frozen catalog revision 1 header/product allowlist is:

- `Server`: nginx, Apache, Caddy, Cloudflare, Microsoft-IIS, Envoy, PHP, Jetty,
  Apache-Coyote, and the literal two-word declaration Apache Tomcat
- `X-Powered-By`: PHP, Express, and ASP.NET, at the beginning of the value
- `X-Generator`: WordPress and Drupal, at the beginning of the value

Catalog revision 2 includes revision 1 and exactly these additions:

| Header | Literal | Product ID | Name | Category | Rule ID |
| --- | --- | --- | --- | --- | --- |
| `Server` | `gunicorn` | `gunicorn` | Gunicorn | `application_server` | `server.gunicorn.v1` |
| `Server` | `uvicorn` | `uvicorn` | Uvicorn | `application_server` | `server.uvicorn.v1` |
| `Server` | `waitress` | `waitress` | Waitress | `application_server` | `server.waitress.v1` |
| `Server` | `openresty` | `openresty` | OpenResty | `web_server` | `server.openresty.v1` |
| `Server` | `LiteSpeed` | `litespeed` | LiteSpeed | `web_server` | `server.litespeed.v1` |
| `X-Powered-By` | `Next.js` | `next_js` | Next.js | `application_framework` | `x_powered_by.next_js.v1` |

These additions follow primary-source header declarations in
[Gunicorn](https://github.com/benoitc/gunicorn/blob/master/gunicorn/http/wsgi.py),
[Uvicorn](https://github.com/Kludex/uvicorn/blob/main/uvicorn/config.py),
[Waitress](https://docs.pylonsproject.org/projects/waitress/en/latest/arguments.html),
[OpenResty](https://openresty.org/en/ann-1027001002.html),
[LiteSpeed](https://docs.litespeedtech.com/lscache/tips/), and
[Next.js](https://github.com/vercel/next.js/blob/canary/packages/next/src/server/send-payload.ts).
They use only the existing bare-product and slash-version grammar. A bare product
has `not_reported` version status; an unsupported suffix keeps the product but
returns a null version, never a numeric prefix. No edition, installed version,
companion product, or infrastructure role is inferred. In particular, OpenResty
adds no nginx or Lua observation, LiteSpeed adds no edition or OpenLiteSpeed
observation, and Next.js adds no React or Node.js observation. Rule suffixes
remain `.v1`: catalog revisions and individual rule revisions are independent.

Matching is ASCII case-insensitive, with complete product-name boundaries.
`Server` can supply several whitespace-separated products. Nested and escaped
HTTP comments are skipped, including product-like words inside them. A product
concatenated directly after a comment or `Jetty(...)` is not promoted into an
additional observation. Arbitrary header names, unknown products, hostnames,
body strings, and product-name substrings are not evidence. The legacy clues
still use their original leading-product extraction; a new observation need
not have a matching legacy clue.

Versions use `/` after the product, `Jetty(version)`, or whitespace after a
supported `X-Generator` product. Only a complete nonempty ASCII numeric token
or dot-separated numeric components is accepted, at most 32 UTF-8 bytes.
Suffixes such as `1.2-custom`, `9.4.51.v20230217`, arbitrary strings, empty
components, and overlong values never become a shortened numeric version.
The explicit `version_status` is:

- `reported`: `reported_version` contains the complete accepted numeric value
- `not_reported`: the supported literal declaration has no version separator
- `unsupported_format`: a declared version does not fit the supported grammar;
  `reported_version` is null, and no rejected text is returned
- `non_product_version`: a numeric Apache-Coyote connector declaration is not an
  installed product version; `reported_version` is null

In particular, `Apache-Coyote/1.1` means an Apache-Coyote connector declaration.
It never becomes Tomcat 1.1. Only a literal Apache Tomcat declaration produces
the `apache_tomcat` catalog entry. Unsupported Jetty release suffixes are explicit
unsupported formats, not silently reduced to a numeric prefix.

Each exact-row observation includes stable `product_id`, `name`,
`catalog_category`, nullable `reported_version`, `version_status`, fixed
`source: "response_header"` and `strength: "literal_declaration"`, lowercase
`header_name`, and a fixed allowlisted `rule_id`. Its zero-based `header_index`
addresses the original retained response-header array, including unrelated and
duplicate headers. `product_span` and nullable `version_span` have integer
`start` and exclusive `end` positions with
`offset_basis: "retained_header_value_utf8"`. These are byte offsets into the
original retained value, including leading whitespace and Unicode comments,
not character positions, normalized values, or original wire bytes. Only
accepted reported versions have a version span. Raw headers, comments, snippets,
unrecognized tokens, and rejected version strings are never returned.

Origin observations aggregate by product, header name, reported version, and
version status. Each has `row_count`, `first_seen`, `last_seen`, and up to three
exact evidence tokens. Repeated identical declarations within one row count
once; separate retained rows count separately even when transaction UUIDs repeat.
The timestamps are the minimum and maximum start times of contributing rows.
Conflicting versions remain separate entries. Sorting does not choose a highest,
newest, or authoritative version. Use an entry's exact evidence token to inspect
its retained source row under the normal freshness checks below.

The optional limit fields are `technology_observations_per_row: 8`,
`technology_observations_per_origin: 32`, `technology_observations: 2000`, and
`technology_version_bytes: 32`, plus `technology_token_candidates_per_row: 128`.
The token-work budget is shared across the eligible response headers in one row.
Product candidates, unknown or malformed tokens, and comments all consume it;
whitespace does not. One complete product declaration includes its attached
version, and a nested HTTP comment is one comment candidate. An unseparated
malformed suffix after a comment or `Jetty(...)` is a separate candidate to skip,
never a new product. Candidates are not shortened to fit a remaining budget.
Exactly 128 inspected candidates at the end is complete; a further uninspected
candidate adds `technology_token_scan_limit` to row `omitted` and map
`snapshot.stopped_by`. A partial row can therefore contain zero observations.
This work cap does not stop the existing legacy clue or redirect-header scan.
The existing combined 128-header, 32-KiB
header-byte, 4-KiB header-value, and 8-MiB metadata-projection budgets still apply.
Excess row observations add `technology_observations_limit` to row `omitted`
and map `snapshot.stopped_by`. Origin/map tuple caps report
`technology_observations_per_origin_limit` or `technology_observations_map_limit`
in `stopped_by`. Counts and times for retained tuples continue updating after
aggregate caps; other map metadata continues projecting. Counts still cover
only bounded projected observations, so row/token/header/window omissions must remain
visible. No automatic larger scan follows a partial result.

## Completeness and freshness

The bounded window uses newest capture-sequence order, not wall-clock time.
`first_retained_started_at` and `last_retained_started_at` are timestamps at the
retained sequence boundaries, not an all-history temporal minimum and maximum.
`oldest_considered_at` and `latest_considered_at` describe the considered window.
CONNECT tunnel rows are counted separately in `non_http_rows` and do not become
HTTP endpoint observations.

Read `snapshot.complete`, `snapshot.stopped_by`, the reported row counts, limits,
and warnings before interpreting the inventory. Results are bounded and describe
only the retained rows represented in that result. Retention, deletion, scope
filtering, invalid metadata, and per-result limits can leave data out. A complete
retained-history result is still not a complete network architecture or a record
of traffic that was never captured or has already been removed.

Refreshing computes a new view from current metadata. Counts and scope membership
can change. An evidence token is a locator for a particular row state, not a
promise that its underlying record will remain available indefinitely. Reopening
an inactive session can change its store generation and invalidate an earlier
token. Snapshot IDs are not persistent graph IDs or pagination cursors.

## Exact-row evidence

```bash
sniper-cli schema output target.service_map.evidence.get
sniper-cli scope service-map-evidence --session-id <returned-session-uuid> --evidence-id <returned-evidence-token>
sniper-cli call target.service_map.evidence.get --input '{"session_id":"00000000-0000-0000-0000-000000000000","evidence_id":"<returned-evidence-token>"}'
```

Both fields are required. The token is at most 200 UTF-8 bytes; copy it unchanged from a map evidence
array. It binds the session's retained-store generation, row sequence, transaction
UUID, and row revision. A transaction UUID alone is insufficient when retained
rows share an ID.

Check `available` before using `row`. A stale, edited, removed, or otherwise
unresolvable row returns explicit unavailability rather than silently substituting
another record. The evidence read returns only safe metadata for the exact row.
It does not hydrate bodies, expose raw headers, or call the usual UUID-only HTTP
detail endpoint as a fallback. Refresh the map deliberately if you need current
evidence; do not describe unavailable historical evidence as verified.

## Explicit one-row observed socket peer

The default inventory and evidence response do not include socket peer data.
An explicit `--include-socket-peer` on `scope service-map-evidence`, or boolean
`include_socket_peer: true` on `target.service_map.evidence.get`, adds one optional
`socket_peer` envelope only after exact-row token validation succeeds. The
statuses are `observed`, `not_recorded`, and `unavailable`; check the status and
nullable observation before using an address. False or omission sends no peer
query parameter. No peer is returned for stale or unavailable evidence.

Capture is independently Off by default and requires an explicit active-session
settings save. This read never enables it, backfills rows, probes, or activates a
session. A socket peer can be a proxy, CDN or shared endpoint, not proof of origin
ownership or a backend chain. The default map has no peer fields or IP edges. Retained
observations are included in session files, exports and full-record JSON; Off
does not erase them. See [the complete capture and evidence contract](observed-socket-peer.md).

## Explicit recorded socket peer matches

A selected exact row can explicitly inspect other retained ordinary HTTP rows
whose recorded direct socket observation has the same source, route, address
family, IP and port. This separate active-session-only read is available as:

```bash
sniper-cli scope service-map socket-peer-matches --session-id <active-session-uuid> --evidence-id <returned-token>
sniper-cli scope service-map socket-peer-matches --session-id <active-session-uuid> --evidence-id <returned-token> --in-scope-only --max-records 10000
sniper-cli call target.service_map.socket_peer_matches.get --input '{"session_id":"00000000-0000-0000-0000-000000000000","evidence_id":"<returned-token>"}'
sniper-cli schema input target.service_map.socket_peer_matches.get
sniper-cli schema output target.service_map.socket_peer_matches.get
```

GET `/api/target/service-map/socket-peer-matches` requires `session_id` and
`evidence_id`. Optional `in_scope_only` defaults to false and `max_records` to
10,000 (maximum 50,000, minimum 1). Unknown fields, duplicates, nulls, malformed
booleans and arbitrary IP/hostname filters are rejected with fixed errors that
do not repeat supplied data. The operation neither activates nor loads an
inactive saved session. It never turns capture on, changes settings, performs a
request, reads DNS/TLS, reads bodies/headers, or persists a peer index.

The schema-version-1 response has `available`, `status` (`matched`, `no_matches`
or `unavailable`), `complete`, `reasons`, the exact source token, a typed `peer`
key, a `source`, a point-in-time `snapshot`, diagnostic `counts`, `origins` and
`limits`. An unavailable response clears peer/source/snapshot/groups and counts.
The default map and default evidence shapes are unchanged.

- The seed is separate from matching-row counts. `source.in_window` says whether
  it falls inside the latest retained-sequence window; an older retained seed
  remains inspectable, with `source_outside_window` and `max_records` disclosed.
- Only other matching rows form origin groups, including other rows with the
  seed's own origin. Each group gives its matching-row count, min/max recorded
  observation timestamps, and up to three exact token samples. These are
  response observations, never connection counts or continuous occupancy.
- Duplicate transaction UUIDs retain separate exact tokens and sequences.
  Origin groups absent from the default map are captured origins in this
  inspection; no total traffic count is inferred for them.
- Scope is frozen once and uses the existing matcher on the original captured
  host spelling, exactly like the default map. An out-of-scope seed with
  `in_scope_only=true` returns `source_out_of_scope`. Other equal rows outside
  scope count as exclusions. A returned group's `in_scope` is true if any of its
  represented rows is in scope.
- `retained_rows` and `considered_rows` distinguish the whole retained store from
  the bounded latest-sequence window. Non-source diagnostic buckets are disjoint:
  non-HTTP, not recorded, unavailable observation, non-direct, invalid observation,
  different peer, invalid metadata, scope excluded, and matching. They sum to
  considered rows minus the seed when the seed is in the window.
- `matching_rows = returned_matching_rows + omitted_matching_rows`.
  `returned_matching_rows` is the sum of group counts; `sample_rows` and
  `omitted_sample_rows` sum samples and omissions for returned groups. There is
  no claimed count of distinct omitted origins.

Limits are 100 groups, three samples per group, a conservative 256-KiB projection
budget, a 512-byte captured host and an eight-byte scheme. Typed observations are
compared before bounded origin projection; no full Service Map row, technology
catalog, path or header clues are projected. A group may have zero samples after
the byte budget fills. Rows after the group cap still contribute exact matching
and omission counts within the window; no unbounded distinct-origin set is kept.
Groups/reasons are lexically sorted, samples descend by retained sequence, and
sequence values remain decimal strings. Partial reasons are `max_records`,
`source_outside_window`, `invalid_metadata`, `origin_group_limit`,
`projection_byte_limit` and `sample_limit`. Completeness covers only this
retained-data projection, not infrastructure discovery.

Scope patterns are prepared outside the store lock, with at most 500 entries
per include/exclude list and 512 bytes per pattern. Exact normalized patterns
use an in-memory set; suffix and glob comparisons share an 8,388,608-unit
request budget across the seed and candidate rows. Each patterned comparison
is charged the normalized host bytes plus normalized pattern bytes plus 16
before matching. This is a deterministic logical-work bound, not a wall-clock
promise. `limits.scope_pattern_entries`, `limits.scope_pattern_bytes` and
`limits.scope_work_units` disclose these fixed bounds. If preparation or work
exceeds a bound, the whole inspection is `unavailable` with
`scope_work_limit`, cleared source/peer/snapshot/groups and zero counters.
No partial counts or guessed scope decisions are published. Consider a smaller
`max_records` window or deliberately simpler scope rules; clients never retry
or alter settings automatically.

A direct usable unicast observation is required. CONNECT, tunnel and status-101
upgrade rows are excluded. Proxy/unknown routes, unrecorded observations,
missing addresses and invalid metadata remain diagnostics. Zero ports,
unspecified, multicast, link-local, broadcast/reserved IPv4 and IPv4 0/8
addresses are ineligible, including mapped IPv6 equivalents. Private and loopback
unicast addresses are eligible. IPv4 and IPv4-mapped IPv6 remain different
families and never match each other. Address strings use canonical Rust IP
serialization.

The store freezes membership and revisions under its read lock and revalidates
the seed after scanning; API publication rechecks that seed and the same active
session context. The explicit scan runs off the async executor, but its read
lock can briefly delay store writes. Keep the 10,000-row default for a smaller
inspection; choosing the optional 50,000-row maximum increases bounded work
and possible write contention. This operation is not a nonblocking background
index. This is a revalidated snapshot, not an atomic-through-delivery
claim. Sample tokens can subsequently become stale. Exact sample inspection
must check the returned token, origin and observation; unavailable evidence
never falls back to UUID-only lookup. Because this operation needs only a safe
captured authority, a malformed or oversized path can still make ordinary exact
Service Map evidence return `metadata_unavailable`. Missing body files do not
prevent peer matching.

Equal socket observations do not establish ownership, physical endpoint identity,
shared deployment, service dependencies, backend chains or a current IP address.
The optional UI grouping is temporary and must be explicitly shown after
inspection; it does not enable capture or alter the default inventory.

## Explicit one-row response-body references

This optional read requires a deliberate selection of one exact retained row:

```bash
sniper-cli schema input target.service_map.body_references.get
sniper-cli schema output target.service_map.body_references.get
sniper-cli examples target.service_map.body_references.get
sniper-cli target service-map body-references --session-id <active-session-uuid> --evidence-id <returned-evidence-token>
sniper-cli call target.service_map.body_references.get --input '{"session_id":"00000000-0000-0000-0000-000000000000","evidence_id":"<returned-evidence-token>"}'
```

Both fields are required. Copy the complete evidence token unchanged. The chosen
session must already be active: an inactive session returns `unavailable` with
`inactive_session`, without loading or activating it. No session lookup, switch,
UUID-only detail fallback, body batch, or automatic retry occurs. Session and
row changes during a read invalidate its result. Tokens obtained for an inactive
metadata inventory may become stale if that session is later opened; deliberately
read a fresh map before inspecting one of its rows.

The Scope inspector offers an explicit action for the selected evidence row.
Selecting or expanding an origin, API, relationship, or evidence item does not
read bodies. Body-reference results stay separate from observed traffic and
header-derived links. Closing or changing the selection/session invalidates a
pending inspector response. A completed result does not change the graph unless
the operator separately chooses **Show references on map**.

The reader inspects only the retained response preview of UTF-8 HTML or
JavaScript. Supported media types, ignoring case and parameters, are `text/html`,
`application/xhtml+xml`, `application/javascript`, `text/javascript`,
`application/ecmascript`, `text/ecmascript`, and `application/x-javascript`.
An encoded body is accepted only if capture already decoded it, or all declared
content encodings are `identity`. The read does not decompress content, decode
Base64 or entities/JavaScript escapes, parse a document, execute JavaScript,
resolve relative URLs, or contact any target. Missing, unsupported, stale, and
unverifiable source data are explicit states rather than empty successful scans.

`coverage: "literal_absolute_http_urls"` means bounded literal absolute HTTP(S)
URL references. Scheme matching is ASCII case-insensitive; a start immediately
after an ASCII letter, digit, or underscore is ignored. Candidates end at ASCII
whitespace/control characters, quotes, angle brackets, backticks, backslashes,
parentheses, or braces. The reader parses each bounded candidate as an absolute
HTTP(S) URL, then retains only its canonical origin. A final candidate cut by
capture or prefix truncation is omitted conservatively. It cannot establish
runtime calls, followed links, initiators, ownership, or service dependencies. An
empty complete result means no references were found within this supported
retained-preview grammar, not that the response
has no URLs or that the application makes no other calls.

The response has `schema_version: 1`, the selected `session_id` and `evidence_id`,
`available`, `status`, `complete`, and `reasons`. Status is one of:

- `scanned`: the supported retained preview was inspected within the limits;
  `available: true`, `complete: true`, and no reasons
- `partial`: a capture, prefix, candidate, origin, or offset limit left coverage
  incomplete; `available: true`, `complete: false`, with reasons
- `unsupported`: the retained representation cannot be inspected by this reader;
  `available: false`, `complete: false`
- `unavailable`: the exact retained row or required data cannot be read safely;
  `available: false`, `complete: false`

Available responses identify `source_origin`, decimal-string `source_sequence`,
`source_started_at`, and `retained_preview_bytes`. Source metadata may be omitted
when unavailable. `references` contains only `target_origin`, `occurrences`,
`preview_byte_offsets`, and `omitted_offsets`. Origins are canonical scheme/host/
port values; response text, snippets, paths, queries, fragments, and URL credentials
are never returned. Origin names can still reveal private service information.

Offsets are zero-based UTF-8 byte offsets in the retained preview,
`offset_basis: "retained_utf8_preview"`. They are not offsets in the full body,
compressed response, or wire traffic. Capture truncation and scan-prefix truncation
are reported separately as `capture_preview_truncated` and
`scan_prefix_truncated`; inspect both along with `scanned_bytes`.

The fixed `limits` are:

- `scan_bytes`: 262144 retained UTF-8 preview bytes, ending on a character boundary
- `serialized_row_bytes`: 2097152 bytes for one disk-backed serialized row
- `origins`: 100 distinct referenced origins
- `candidates`: 4096 candidates, counted in `candidates_scanned`
- `candidate_bytes`: 4096 bytes per literal URL candidate
- `offsets_per_origin`: 5 stored offsets per referenced origin

Resident preview length may exceed the disk-row limit; only its bounded prefix is
inspected. An overlarge disk row is refused before hydration. Origin-cap omissions
are counted in `omitted_reference_occurrences` only for validated references;
further candidates beyond the candidate cap have unknown reference coverage.
`omitted_offsets` counts additional occurrences whose offsets were not retained.
Reasons name each applicable cap or unsupported/unavailable state. No automatic
larger read follows a partial result. Even `complete: true` describes only this
supported literal grammar within one retained preview, never all runtime calls.

## Explicit retained response Link declarations

This separate opt-in read inspects one exact retained response's Link headers:

```bash
sniper-cli schema input target.service_map.link_declarations.get
sniper-cli schema output target.service_map.link_declarations.get
sniper-cli examples target.service_map.link_declarations.get
sniper-cli scope service-map link-declarations --session-id <active-session-uuid> --evidence-id <returned-evidence-token>
sniper-cli call target.service_map.link_declarations.get --input '{"session_id":"00000000-0000-0000-0000-000000000000","evidence_id":"<returned-evidence-token>"}'
```

Both fields are required; unknown query fields are rejected. The session must
already be active. The operation never activates or loads an inactive session,
creates a session worker, reads a body or body locator, persists a result, or
uses a UUID-only transaction fallback. It makes no target request, redirect
follow, DNS lookup, TLS connection, probe, URL resolution, or OpenAPI read. The
CLI makes one explicit inspection GET after ordinary local identity checks; it
sends no technology-catalog header and never retries or hydrates another source.
An older server's 404 is an explicit unsupported-feature result, not permission
to generate traffic.

Eligible sources are ordinary retained HTTP(S) GET or HEAD responses with status
200 and response metadata. Other methods, statuses (including 101, 204, 206,
304, and redirects), tunnels, and other schemes return `unsupported` with
`unsupported_source_context`. Missing response metadata is `unavailable` with
`response_unavailable`; invalid canonical source metadata is
`metadata_unavailable`. MIME, compression, preview encoding, preview truncation,
body presence, missing body files, and ambiguous duplicate-UUID body locators do
not change valid retained-header eligibility.

Acquisition resolves the exact session/store generation/sequence/UUID/revision
and copies at most 128 retained headers or 32,768 name-plus-value bytes, in
original order, under the metadata lock. Original header count is retained as
constant-time metadata. Parsing happens outside the lock. Both the row revision
and active session context are revalidated before publication; a mutation,
removal, retention event, generation replacement, or session switch discards
stale results. Annotation-only edits and body-file replacement alone do not
change the exact metadata identity.
The result is a revalidated snapshot; it does not atomically freeze history or
the active session through response delivery.

The fixed grammar recognizes `service-doc`, `service-desc`, `describedby`, and
`preconnect`. The first three are declarations; preconnect is a hint. All use
`source: "response_link_header"` and `strength: "literal_declaration"`. Nothing
here establishes ownership, actual network calls, deployment, or that a target
was contacted. Unknown relation tokens are counted but their text is not
returned. Relation tokens are ASCII case-insensitive. The first `rel` parameter
wins, escaped relation syntax is unsupported, and any `anchor` rejects its whole
member. Complete member framing precedes emission. Malformed framing stops that
field with no search-ahead recovery; independent later header fields can still
be inspected.

Targets must be literal absolute ASCII HTTP(S) URLs. Relative/non-HTTP targets,
userinfo (including empty `@`), controls, backslashes, malformed percent escapes,
ambiguous authorities, and nonstandard numeric-host repairs are rejected before
canonicalization. Output contains only canonical target origins, never raw
headers, paths, queries, fragments, titles, credentials, unknown relation text,
rejected values, or parser diagnostics.

### Link declaration result contract

The strict envelope includes `schema_version: 1`, `relation_catalog_version: 1`,
exact requested `session_id` and `evidence_id`, `available`, `status`, `complete`,
and sorted unique fixed `reasons`. Status is `scanned`, `unsupported`, or
`unavailable`. Accepted partial inspection remains `available: true`,
`status: "scanned"`, `complete: false`; it never claims a complete empty result.
Completeness means no omissions within this bounded literal grammar, not all
resource relationships or service dependencies.

`source_origin`, `source_sequence` (canonical decimal u64 string),
`source_started_at`, `source_method`, `source_status`, and
`retained_header_count` are required nullable fields. Unsupported/unavailable
results have exactly one acquisition reason, all six source fields explicitly
null, zero counts, and no observations. `coverage` is
`absolute_http_link_declarations`; `offset_basis` is
`retained_header_value_utf8`.

The required counts are `headers_inspected`, `header_bytes_admitted`,
`link_fields_inspected`, `candidates_inspected`, `members_framed`,
`parameters_inspected`, `relation_tokens_inspected`, and
`unknown_relation_tokens_inspected`. These count inspected input only. Copied but
uninspected suffixes and skipped tails are not estimated. In particular, a
candidate limit reached before a later header-admission limit does not claim the
later limit was encountered.

Each observation contains relation, canonical target origin, fixed source and
strength, `header_name: "link"`, original zero-based `header_index`, original
`header_value_bytes`, half-open `link_value_span`, `target_span`, and
`relation_span`, fixed `rule_id`, and offset basis. Spans are UTF-8 byte offsets
into the original retained header value, not wire offsets. Target spans exclude
angle brackets. Multiple relations from one member share member/target spans
and preserve their distinct ordered relation spans. Separate members retain
separate provenance even when their origin-only targets coincide. Rules are
`response_link.service_doc.v1`, `response_link.service_desc.v1`,
`response_link.describedby.v1`, and `response_link.preconnect.v1` respectively.

The fixed limits are 128 headers; 32,768 header name/value bytes; 4,096 bytes per
Link field and target; 128 candidates; 32 parameters and 32 relation tokens per
member; 32 observations; and 268 bytes per target origin. A field exceeding its
individual limit is skipped without inspection; no header or field is truncated
and then treated as a complete value.

Acquisition/lifetime reasons are `invalid_evidence_id`, `session_mismatch`,
`stale_generation`, `record_missing`, `record_changed`, `response_unavailable`,
`unsupported_source_context`, `inactive_session`, `session_source_changed`,
`metadata_unavailable`, and `link_inspection_failed`. Admission/parser reasons
are `header_count_limit`, `header_byte_limit`, `link_field_byte_limit`,
`candidate_limit`, `parameter_limit`, `relation_token_limit`, `observation_limit`,
`malformed_field`, `unsupported_target`, `anchor_present`, `missing_relation`,
and `unsupported_relation_syntax`. Neither errors nor unavailable results echo
captured values or underlying diagnostics. Malformed query/exact-token syntax
receives HTTP 400 with a fixed message.

## Explicit retained HTML generator declarations

**Inspect retained HTML generators** is a separate explicit inspection of one
verified exact response in the active session. Selecting evidence, opening or
polling the map, refreshing metadata, zooming, and opening a disclosure never
read response bodies. This action does not enrich map cards, header observations,
the API inventory, or the URL-reference overlay. Inspecting URL references and
HTML generators requires two separate explicit bounded reads.

```bash
sniper-cli schema input target.service_map.html_generators.get
sniper-cli schema output target.service_map.html_generators.get
sniper-cli scope service-map html-generators --session-id <active-session-uuid> --evidence-id <opaque-token>
sniper-cli call target.service_map.html_generators.get --input '{"session_id":"00000000-0000-0000-0000-000000000000","evidence_id":"<opaque-token>"}'
```

Both selection fields are required. The `target` command alias also works.
This read operation needs no `--yes`; `--dry-run` makes no request. An older
server without the endpoint is unsupported; there is no fallback fetch or retry.
The generator catalog is independently fixed at revision 1 and does not use the
header-technology catalog negotiation header.

Only already-retained UTF-8 `text/html` previews are eligible. XHTML, JavaScript,
base64/binary previews, and undecoded non-identity content encodings are refused.
No response is fetched, decoded, replayed, evaluated, or persisted by this action.
The reader copies only bounded metadata and a bounded resident prefix under the
store lock. Lazy rows use a bounded serialized-row read outside that lock,
without hydrating the full transaction. Sequence, UUID, row revision, file
locator/generation, and active-session identity are rechecked before results can
be published. An inactive session is rejected without loading its saved context
or starting its worker. Retention, deletion, mutation, or source replacement
invalidates the result. Existing body-reference behavior and output are unchanged.

This is a deliberately incomplete literal recognizer, not a general HTML parser.
It requires explicit `html` and `head` elements and quoted literal `name` and
`content` values on `meta` declarations. Matching is ASCII case-insensitive.
Only complete WordPress and Drupal product names are returned, as `wordpress` /
`WordPress` or `drupal` / `Drupal`, with `catalog_category: "cms"`. A whole
reported version may follow 1–32 original HTML ASCII whitespace bytes. The
version must contain only nonempty dot-separated ASCII numeric components and
be at most 32 bytes. Unsupported suffixes retain the recognized product with
`version_status: "unsupported_format"`, `reported_version: null`, and
`version_span: null`; no numeric prefix or rejected text is returned. Bare
products have `not_reported`; accepted versions have `reported`.

Unrelated quoted attributes and Boolean attributes remain opaque. Supported
comments and literal title/style/script raw text are skipped safely, without
searching their text for generator tags. There is no entity decoding or HTML
error recovery. Entities in semantic generator fields, malformed tags, duplicate
attributes, unsupported script escapes, templates, foreign content, and ambiguous
contexts stop partial inspection. Unknown products are counted only among
actually inspected quoted generator declarations; their text is never returned.

### Generator result contract

Every result includes `schema_version: 1`, `generator_catalog_version: 1`, the
requested `session_id` and `evidence_id`, `available`, `status`, `complete`, and
fixed-code `reasons`. `status` is `scanned`, `unsupported`, or `unavailable`.
Accepted partial inspections remain `available: true`, `status: "scanned"`,
`complete: false`. Unsupported and unavailable results return no observations,
clear counters/flags, and explicitly null source metadata. Never interpret a
partial or unsupported result as “generator not found.”

Available results contain `source_origin`, decimal-string `source_sequence`,
`source_started_at`, and `retained_preview_bytes`. `scan_prefix_bytes` is the
bounded prefix offered to the recognizer, **not** a claim every byte was parsed.
`capture_preview_truncated` and `scan_prefix_truncated` are independent. When a
bounded retained prefix ends while parsing, the adapter reports `input_limit`;
when only capture is truncated, its stop remains `end_of_preview`, alongside
the capture-truncation reason. `head_closed` means the supported explicit head
closed. It may remain true with `parser_stop: null` when an unparsed trailing
body was truncated; `complete` is still false for any capture or prefix limit.
Parser, tag, attribute, candidate, or observation limits also make it false.
Even true completeness covers only this supported head grammar, never all
possible generators or runtime products.

`coverage` is always `literal_html_generator_explicit_head`. A stopped parser
returns `parser_stop: {reason, byte_cursor}`. The cursor is a raw-byte position
that may fall inside a UTF-8 character at a byte cap and must never be used to
slice text. Accepted `tag_span`, `content_span`, `product_span`, and nullable
`version_span` are half-open, character-boundary-safe byte ranges in the original
retained UTF-8 preview. Both envelope and observations use
`offset_basis: "retained_utf8_preview"`; these are not wire-body offsets.

Each observation has the product/name/category, nullable `reported_version`,
`version_status`, `source: "response_html_meta_generator"`,
`strength: "literal_declaration"`, spans, offset basis, and a fixed rule ID:
`html_meta_generator.wordpress.v1` or `html_meta_generator.drupal.v1`.
There are no raw tags, body snippets, unknown product names, or rejected version
strings. Declarations can be spoofed or stale; they do not establish an installed
version, backend stack, infrastructure role, ownership, or vulnerability.

`tag_candidates_inspected` counts encountered start/end tags and doctype, not
comments or raw-text decoys. `additional_tag_candidate_encountered` becomes true
only when an actual next candidate exceeds the cap.
`additional_observation_encountered` becomes true only for an actual ninth
recognized supported declaration. No uninspected omission count is guessed.
`unknown_product_declarations` is an exact count within the inspected prefix only.

The fixed `limits` object contains:

- `scan_bytes`: 262144 retained UTF-8 bytes, ending on a character boundary
- `serialized_row_bytes`: 2097152 bytes for one disk-backed serialized row
- `tag_candidates`: 4096
- `tag_bytes`: 4096
- `attributes`: 32 per tag
- `observations`: 8 per inspection
- `version_bytes`: 32
- `version_separator_bytes`: 32

The independent UI result has no Show-on-map action. It is cleared when its exact
source/session or retained history is invalidated and is never saved in workspace
state. An unchanged valid metadata poll may preserve it; delayed responses cannot
restore stale evidence. No larger inspection runs automatically after a limit.

## Session-local retained relationship collection (GUI only)

After **View source** verifies an exact retained row, explicitly inspect **Body
URL references**, **Response Link headers**, or **Matching recorded socket
peers**. Then choose **Show references on map** or **Show recorded address
group**. Inspection and visualization remain separate: Show uses only the
already-returned bounded response and never performs another read. There is no
automatic scanning, crawling, URL fetching, DNS/TLS lookup, capture, or replay.
Unsupported/unavailable results cannot be shown. Body and Link results with no
non-self target stay inspectable but do not add an entry.

Up to **eight immutable inspected entries** coexist in memory for the current
session, including different kinds from the same source and the same kind from
different exact sources. Entry identity is kind plus the complete opaque evidence
token (session, store generation, exact decimal sequence, revision and record ID).
Showing that identity again updates only that entry, in place. A ninth distinct
entry is rejected with an explicit notice; existing entries are never silently
evicted. No inspection is written to workspace, session storage or browser storage.

The first body/Link entry opens its source's Direct relations neighborhood. A
second distinct entry, or a peer entry, opens **All origins** so the collected
observations can be seen together with loaded metadata. Search, product/version
filters, zoom, selecting another source, All origins, and Focus selection preserve
the collection. A collapsed **Shown inspections** disclosure holds per-entry
provenance, complete/partial coverage, **View inspected source**, **Remove
inspection**, and **Clear all inspections**. Expanding it uses a bounded scrolling
area; the compact map controls and inspector remain independent.

The collection retains only validated, bounded metadata. Body entries retain
canonical target origins, occurrence counts and preview byte offsets; Link entries
retain typed declarations and retained-header byte spans. Source method,
query-free path, capture time and exact sequence remain attached to each entry.
Repeated graph edges deduplicate by source, target and relationship type, while
all contributing inspection entries and their evidence remain separate. Removing
one entry removes only its contributions; a shared edge survives if another entry
still supports it. Occurrences are not request counts. Body/Link references and
redirect/header declarations do not establish calls, followed links, ownership,
service dependencies or runtime topology. Referenced origins are text only.

Peer entries add **undirected recorded observation spokes** through distinct
recorded-address nodes. Equality uses observation source, direct route, address
family, canonical IP and port. Different ports or IPv4 versus IPv4-mapped IPv6
remain different nodes. Equal addresses across inspections share one visual node
and deduplicated spokes; overlapping per-inspection matching-row totals are never
summed. Each entry retains its own considered window, source observation time,
inspection time, coverage, omission counts and exact samples. Shared addresses do
not establish common ownership, a common backend, continuous occupancy or a
current infrastructure inventory. Products remain attached only to the exact
origin's loaded header aggregate, never inherited through address equality.

A collected target already present in the default projection keeps its actual
captured counts and API paths. Body/Link-only targets stay reference-only without
invented traffic, endpoints or scope membership. Peer-only origins are labeled
captured in that inspection, with per-inspection matching counts and independently
verified exact samples, not default-map traffic totals. The API catalog still
contains only loaded captured endpoints; no body URL path or inferred endpoint is
added. Default metadata/CLI responses and all inspection APIs are unchanged.

Collection limits compose with each inspection's existing bounds: at most eight
entries, each with up to 100 body origins, 32 Link declarations, or 100 peer groups
and three exact samples per group. Peer results remain capped at 256 KiB each.
A shared controller identity checks the unchanged metadata projection for peer
entries; no whole-map serialization is copied into each entry. The graph retains
its shared **24-card / 40-edge** limits, including recorded-address nodes. Source
and address cards receive deterministic priority before inspected neighbors and
ordinary metadata cards. Details report query/product-hidden origins, graph-node
and edge-cap omissions, and inspected links outside displayed cards. These are
separate from inspection omissions and do not count unknown origins or unseen
relationships. Per-origin relationship details remain bounded to 30 declarations;
additional declarations are explicitly reported as omitted.

**Remove inspection** and **Clear all inspections** are local and send no requests.
They retire removed peer sample allowlists, cached provenance and unavailable
sample markers. A row may be a sample in one peer entry and the source of another
entry: failure to verify it removes every entry seeded by that exact token.
Sample-only verification failure marks that sample unavailable in surviving
point-in-time peer results; no substitute UUID lookup occurs.

### Source lifetime and live capture

- A validated transaction event for another record UUID preserves body/Link
  entries. An event for the same UUID removes their entries conservatively,
  including distinct exact tokens sharing that UUID. No event header/body fields
  are stored in the collection.
- The next ordinary metadata poll must still contain each body/Link source's
  exact token under its original origin and generation. Another revision, sequence
  or record with the same path is not a substitute. A token omitted by the bounded
  evidence sample is described as no longer verified in the loaded projection;
  this does not prove that the record was deleted. Polls never recreate entries.
- **Peer entries remain conservative during live traffic:** every transaction
  event and any retained metadata-projection change removes them. Events do not
  distinguish insert from update or carry the revisions of unsampled group rows,
  so their aggregate membership cannot safely be proved unchanged. Accumulating
  stable peer groups during continuously changing capture remains outside this
  milestone. Manually pausing HTTP recording can make inspection steadier, but
  in-flight operations and explicit replay or other history changes may still
  invalidate the result. Show never changes recording settings.
- Unknown/malformed events, event gaps, retention/deletion, history invalidation,
  generation/session/scope changes, disconnect, a failed map refresh, manual
  **Reload**, and leaving/hiding Service Map clear the collection. Refresh failure
  keeps the existing explicit-retry pause; it never starts automatic source reads.
  An unchanged successful metadata poll preserves verified entries.
- Show is disabled while event readiness is lost, the session is inactive, or the
  metadata snapshot is stale/failed. An owned stream reconnection invalidates old
  evidence; metadata polling alone does not restore readiness. Delayed responses,
  reopened views and later polls cannot restore removed entries automatically.

## Local API

- `GET /api/target/service-map?session_id=<uuid>&in_scope_only=false&max_records=10000`
- `GET /api/target/service-map?session_id=<uuid>&in_scope_only=false&all_rows=true&fresh=true`
- `GET /api/target/service-map/parameters?session_id=<active-uuid>&origin=<origin>&method=<method>&path=<path>`
- `GET /api/target/service-map/favicon?session_id=<active-uuid>&evidence_id=<origin-favicon-token>`
- `GET /api/target/service-map/evidence?session_id=<uuid>&evidence_id=<opaque-token>`
- `GET /api/target/service-map/socket-peer-matches?session_id=<active-uuid>&evidence_id=<opaque-token>`
- `GET /api/target/service-map/body-references?session_id=<active-uuid>&evidence_id=<opaque-token>`
- `GET /api/target/service-map/html-generators?session_id=<active-uuid>&evidence_id=<opaque-token>`
- `GET /api/target/service-map/link-declarations?session_id=<active-uuid>&evidence_id=<opaque-token>`

### Technology catalog negotiation

Only the map and exact-row evidence GET endpoints accept the inbound local API
header `X-Sniper-Technology-Catalog-Version`. Its value must be exactly one `1`
or `2`. Omission selects the frozen revision-1 catalog and preserves the legacy
wire shape: there is no `technology_catalog_version` field. Explicit `1` or `2`
selects that catalog before literal parsing, token/row caps, metadata-byte limits,
and origin/map aggregation. Its successful response, including unavailable
exact-row evidence, adds top-level numeric `technology_catalog_version: 1` or
`technology_catalog_version: 2`. Other response fields and `schema_version: 1`
are unchanged. Selecting a catalog never changes exact retained-row tokens.

Duplicate header fields, comma lists, empty values, and malformed or unsupported
values receive HTTP 400 with the fixed message `invalid technology catalog
version header`; the supplied value is never echoed. There is no new API query
parameter and no outgoing target header. The body-reference endpoint and its
projection do not negotiate catalogs and remain unchanged.

Compatibility works in both directions:

- Old clients omit this header. New servers keep revision-1 products, observation
  bytes, and omission behavior, including when new products would otherwise fill
  row or aggregate caps. Expanding the catalog and then filtering is not equivalent.
- New clients request revision 2. An old server may ignore the header and omit
  the response marker. The client then validates strictly against revision 1 and
  reports legacy catalog availability; absence never means revision 2 succeeded.
  This also supports older servers that omit the observation extension itself.
- A present marker must be a supported integer equal to the requested revision.
  Malformed, unsupported, or mismatched markers are rejected before validating
  observations. Neither clients nor servers silently retry with another catalog.

The Map tool requests revision 2 on both metadata reads. The CLI defaults to
revision 2 for map and evidence; `--technology-catalog-version 1` or the numeric
`technology_catalog_version: 1` call input explicitly requests revision 1. These
CLI options become a local request header, not query parameters. CLI dry-run
reports the selected header without contacting the server. A legacy fallback
notice is separate from the machine-readable result. Body-reference commands
send no catalog header and gain no catalog option.

URL-encode the opaque token as a query parameter. These endpoints use the existing
local API access control. Service Map discovery and reads do not follow API
redirects or add automatic retries. The GUI enforces redirect refusal on
metadata, exact-row evidence, recorded socket peer matches, URL-body references,
HTML generators, and response Link declaration reads.
A redirect fails through the existing fixed error message without following its
destination or reading its response body. Successful metadata reads allow normal
polling to continue; a failed refresh pauses background reads until an explicit
Refresh or actual scope/session change. History events, reconnects, reopening the
view, and local filters do not clear that pause. Polling and recovery never repeat
a supplementary inspection; inspection buttons remain explicit ways to request
those reads. Discovery validates the usual
Sniper identity; when it reads local runtime-state, it preserves that file even if it is stale or
invalid and does not create lock or recovery files. A CLI schema describes the installed CLI; an older
running Sniper may not provide the Service Map endpoints. Never fall back to
active traffic generation when a read is unsupported or incomplete.
