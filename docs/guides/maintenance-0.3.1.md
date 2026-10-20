# CLI and saved-workspace maintenance in 0.3.1

This is an overview of maintenance work released in 0.3.1, not a release
announcement; see the release notes for that.

## Passive Service Map

The Map tool and read-only CLI share a bounded inventory built from retained
capture metadata. Origins contain method-plus-exact-path endpoints, observed
counts and safe exact-row evidence. Header clues and redirect instructions are
labeled as observations; they do not establish infrastructure or a followed
request. No scans, probes, replay, or crawling are introduced. Check completeness
and unavailable data before drawing conclusions. See the
[Service Map contract](../integrations/service-map.md).

An optional, explicit one-row body-reference read is available through the
Service Map evidence inspector and `target.service_map.body_references.get`.
It requires the current active session and an exact-row token. Inactive sessions
remain unavailable without being loaded or activated. Only bounded retained
UTF-8 HTML/JavaScript previews are inspected; results expose canonical origins
and retained-preview offsets with separate capture/prefix truncation and cap
reasons. References do not establish calls or ownership. The default map reads
no bodies apart from scripts and pages read for front-end technologies (see below),
metadata evidence reads none,
and nothing sends target requests.

The GUI now collects up to eight explicitly shown body, Link and recorded-peer
inspections in one session-local graph, alongside loaded metadata. Each retains
its exact source, timing and coverage, with separate remove/clear controls.
Reference arrows and undirected address observations remain distinct from traffic
counts and do not prove runtime calls or common ownership. Show, mode changes,
filters and removal add no reads; the collection is never persisted and adds no
API paths. Unrelated UUID events preserve verified body/Link entries, while peer
groups still clear on transaction events because unsampled membership cannot be
proved unchanged. See the
[collection lifetime and display limits](../integrations/service-map.md#session-local-retained-relationship-collection-gui-only).

## Predictable CLI contracts

- Discovery, examples, and schemas describe the corrected saved-data and local
  skill-maintenance inputs and result shapes. Existing accepted UUID spellings
  remain supported where documented.
- Saved-data response checks bind results to the requested session, selection,
  page limit, and continuation boundaries. Continue using explicit session IDs
  and pass returned continuations unchanged.
- Parse and local input-file failures have structured errors. Saved-data input
  errors distinguish unreadable sources, invalid JSON, and schema failures without
  echoing paths or contents, including stderr fallback when output fails.
  Non-Unicode argument bytes are suppressed; ordinary non-saved argument
  diagnostics and file paths may still appear. After API discovery, failed generic
  API reads use the actual HTTP status without echoing server error bodies.
  Some failures consequently have
  different error codes or exit codes; branch on the documented contract, not
  message fragments.
- Legacy session create, rename, switch, and delete send the mutation once without
  following redirects or retrying it. Rename and switch also require the returned
  session UUID to match the requested UUID; equivalent spellings remain accepted.
  A mismatched acknowledgement leaves the mutation outcome unknown. Unsuccessful
  HTTP responses use the received status without reading or echoing error bodies;
  these failures report an unknown outcome and remain non-retryable.
- Rule enable/disable and saved-tab label acknowledgements must contain their
  promised non-null fields before successful output is reported. Malformed,
  incomplete, or mismatched acknowledgements report an unknown write outcome;
  they are not automatically retried. Additive fields and equivalent spellings
  of UUID-typed session and rule IDs remain accepted; tab IDs stay exact strings.
- Applied saved rename receipts bind the result to the original session; a
  rename call also checks its requested name, including historical replay.
  Validated unapplied, uncertain, or missing receipts include recovery warnings
  without changing the returned receipt data or successful lookup status. Do not
  issue a new mutation ID to work around uncertainty.
- Root and `call` help include offline saved-data discovery and a bounded session
  listing example. Session creation help and dry-run previews explicitly say that
  successful creation also activates the new session. Offline schemas describe
  the CLI, not a guarantee of support in the selected running app; a validated
  unsupported-read response now suggests checking that pairing.
- Inspect `saved.v1` mutation receipts after uncertain outcomes. Legacy session
  and saved-tab metadata operations do not provide these receipts. Do not
  automatically repeat a mutation just because its response was lost or invalid.
- `replay open` and `replay update` give a request read from `--request-file` or
  `--stdin`, or the placeholder `replay open` starts from, the target scheme as
  its own. It used to keep the parser's `https`, so `--scheme http` read as a
  target override, which the server refuses for an IP-address host: plain-HTTP
  replay to `127.0.0.1` could not be set up from the CLI. A request opened from a
  captured transaction keeps its scheme, and changing it is still an override.

See the [CLI integration guide](../integrations/codex.md),
[saved-data contract](../integrations/saved-data-v1.md), and
[saved-tab metadata operations](../integrations/saved-replay-tabs.md).

## Local skill maintenance and explicit automatic-update consent

`skills status` compares installed files with the embedded bundle without
returning their text. A differing hash means `modified_or_outdated`; it does not
identify whether a person edited the file. `update-preview` compares an enrolled
baseline, so a manually updated file can be `current` in status and `modified`
in preview. Inspect the row states; exit zero does not mean every file is current.

Explicit enrollment records a baseline; staging writes a separate candidate
while preserving the active file. `skills apply-update --yes` explicitly
activates a reviewed stage bound to that unchanged baseline and the running
binary's bundle. Different bytes require strictly newer semantic-version
precedence. Equal precedence with different bytes is a conflict, even when only
build metadata differs. Changed embedded bytes at the same package version are
intentionally refused as an upgrade; bytes staged by a `0.3.0` build are older
than this `0.3.1` bundle.

Apply uses a retained canonical lowercase operation UUID. After uncertain or
lost output, inspect read-only `skills update-result` with the same original ID,
agent and root; it reads files but never resumes a write. Inspect recorded
`state` separately from `current_state`. A same-ID continuation requires proven
object placements. Explicit `skills rollback-update --yes` restores that bound
transaction's baseline while preserving displaced objects. Do not blindly retry,
invent a replacement ID, or remove artifacts to bypass a blocked transaction.
Incomplete or corrupted preparation or markers need manual reconciliation.
There is a 128-retained-operation cap and no automatic pruning.

Automatic updates remain Off by default. Separate `skills enable-auto-updates
--yes` consent binds one unchanged managed installation and only records
permission; it does not immediately change the active file. Read-only
`auto-update-status`, explicit `auto-update-once --yes`, and
`disable-auto-updates --yes` use that policy's stored target and reject directory
overrides. Existing policies require their exact current `--policy-revision` to
re-enable, creating a fresh authorization generation. Modified, conflicting or
uncertain state pauses and preserves artifacts instead of resuming silently.

The desktop schedules one background pass at its first idle event after the
WebView exists; it is not a repeating timer. Headless startup and ordinary CLI
commands do not trigger it. Candidates come only from the local binary's bundle;
there is no network fetch or agent reload. Only global dry run is argument-only
and performs no filesystem inspection.
Existing legacy installation can overwrite an installed skill and is never a
recovery fallback. Linux exchange has native fixture coverage. Hosted macOS 15
ARM64 [focused policy/transaction tests and native desktop compilation](https://github.com/sm1ee/Sniper/actions/runs/38423109820)
were verified at `e7cbe95`. Actual GUI behavior, Intel Macs and user-installed
skills remain unverified. Windows activation, rollback, result inspection and
host-policy operations are unsupported.

Activation refused every skill file and directory that carried an extended
attribute, and macOS gives each file a process creates `com.apple.provenance`,
naming the app it came from. Every file a downloaded Sniper, or a terminal it
started, writes therefore failed with `metadata_unsupported`; on such a Mac all
97 enrollment, activation and automatic-update tests failed that way. That label
alone is now tolerated on macOS. Any other attribute and every ACL are still
refused, and Linux still refuses all attributes, since it keeps ACLs there.

See [safe skill maintenance](../integrations/skill-maintenance.md) for exact
commands, confirmation requirements, refusal states and recovery limitations.

## CLI PATH setup

Incomplete installation acknowledgements keep the error and recovery controls
visible instead of claiming successful registration. On macOS, Unicode padding
outside a managed command no longer gives that line automatic-edit ownership.
If appending would convert a final lone carriage return into a CRLF ending,
setup leaves that profile unchanged and asks for manual review.

macOS automatic PATH setup recognizes managed command lines without parsing shell
context. A managed-command example inside a here-document can be mistaken for
an existing registration or modified when the app path changes. This limitation
remains unresolved. If a profile contains such examples, use the bundled CLI by
its full path and review the profile manually before choosing automatic setup.

## UI reliability (2026-10-11)

- Display settings can be edited and previewed while their saved baseline loads,
  but Apply waits for a usable baseline. A failed or superseded initial read
  offers Retry without automatically applying the draft. If an explicit Apply
  cannot be confirmed, a warning explains that automatic save retries continue.
- Settings and Filter dialogs keep composition-marked Escape events within the
  text input. Saved-tab renaming likewise ignores composition-marked Enter and
  Escape. Stored labels are normalized to 80 Unicode scalar values without
  splitting supplementary characters; the existing inline typing cap is unchanged.
- A delayed note read no longer opens an editor after the user moves to another
  interaction. Opening and closing an unchanged saved note preserves its original
  line breaks; genuine inline edits still use the existing single-line editor.
  Reopening a row's context menu ignores older diagnostic-note reads.
  Status toasts expose polite announcements without moving focus.
  Clipboard fallback fields are removed even when selection or copying throws.
- Returning to the same finding or session does not revive an older detail
  read. Older list/count reads cannot replace a newer accepted badge count or
  undo an observed finding event; later valid lower counts still apply.
- Arrow keys already handled by the browser chooser no longer also move the
  session, history, finding, or frame selection underneath it. Findings row
  navigation also leaves arrow keys to focused text controls, modifier shortcuts,
  and open dialogs.
- App-update failure resets no longer overwrite a retry's progress or click guard.
- New or missing Notes widths default to 220px; explicit saved widths stay unchanged.

These changes have synthetic production-handler regression coverage. Native
desktop IME behavior, screen-reader announcements, and system clipboard
permission interactions still require manual verification.

Native close also waits for queued or in-flight note saves and refuses to finish
while a currently attached note editor has unqueued text or unfinished IME
composition. Finish or cancel the note edit before closing again. This does not
protect an unqueued draft whose editor has already been detached: virtual
scrolling can replace its row, and session or query resets have a separate editor
lifecycle.
In particular, a blurred composition can have neither a pending save nor a
visible editor after replacement. Finish note edits before these transitions;
recoverable detached-editor handling remains follow-up work. Native close/IME
event ordering has not been manually verified.

## Preserve saved work across failures

Successfully loaded UI settings files with an omitted or zero `server_revision`
receive revision 1 in memory. Loading does not rewrite the valid file. This
protects saved preferences from an uninitialized page's revision-0 snapshot;
clients should fetch the current settings and preserve the returned revision
when saving. A rejected stale write returns HTTP 200 with the existing snapshot,
so HTTP success alone does not prove that the requested changes were applied. Older
clients that never send the revision can now have their first write rejected
against such a file. Existing same-client version ordering remains unchanged.
Fresh-file creation and corrupt-file recovery retain revision 0 for that load;
their resulting valid files receive the same protection on a later restart.

Session metadata operations reconcile in-memory state with a visible registry
replacement even if a later finalization step fails. The original error still
matters: visibility is not proof of crash durability, and callers must not infer
that every failed operation was unapplied.

HTTP history snapshots publish body files and their read offsets together, while
preserving later record edits and annotations. Missing or mismatched stored
bodies stop persistence rather than becoming empty saved bodies. Ambiguous
repeated-ID histories with nonempty recovery journals now refuse loading and
preserve their files for review. See [transaction snapshot safety](../persistence-safety.md)
for cancellation, recovery, and supported session-lifecycle boundaries.

Ordinary and keepalive workspace saves also retain the visible committed revision
when finalization fails. They return HTTP 500 with
`code: "WORKSPACE_COMMIT_UNCERTAIN"`; callers must reload before retrying. When
the open GUI receives this response, it preserves local edits and pauses saves.
Copy newer edits before reloading the app. An unload-only keepalive response is
not observed by the closing page, so no recovery message is guaranteed there.
Pre-commit failures retain the prior workspace and existing error behavior.

Startup refuses ambiguous deletion quarantines before destructive cleanup or
registry repair. Preserve the entire sessions directory for recovery. This
startup safeguard does not automatically restore data or fence subsequent
writes by an already-running process. See
[interrupted session deletion](../architecture.md#interrupted-session-deletion).

Workspace synchronization now preserves confirmed metadata and concurrent
edits when an older save fails. Tab navigation and session create/open preserve
supported rendered workspace-editor drafts and ask the user to finish unsupported
workspace edits before leaving. A session transition also stops if an earlier saved editor
becomes dirty during a later preflight save; edits actually acknowledged by later
saves remain eligible to proceed. External active-session changes preserve
unsupported workspace-editor drafts with their original workspace owner instead of
silently resetting them. Repeated preservation and passive synchronization do
not undo an unchanged HTTP-version selection; genuine edits still take priority.
Uncertain session-action failures refresh session rows without silently
rebinding the active editor. Conflict and recovery messages still require
attention; copy unrepresented local edits before manually reloading a session.

## Observed socket peer capture

A separate Capture Settings card and `capture http upstream-peer get/set` add an
explicit default-Off, active-session-only switch. Future eligible ordinary
HTTP(S) responses may retain one bounded socket observation. Exact Service Map
evidence exposes it only with `--include-socket-peer`; default map/evidence and
transaction summary outputs remain unchanged. No probes, backfill, aggregate IP
map, or origin-ownership inference is added. Observations persist in session
files, exports and full-record JSON, and Off does not erase them. See the
[observed socket peer contract](../integrations/observed-socket-peer.md).

## Passive Service Map robustness

Same-column metadata relationship arrows now stay inside the fixed map canvas,
including reciprocal typed links. Malformed nested source observations show a
safe unavailable state instead of breaking the inspector; a later valid exact
source read can recover normally.

Socket-peer CLI settings discovery uses the same passive identity checks as
Service Map reads. It preserves malformed runtime-state files, creates no
recovery lock or quarantine, redacts invalid API addresses and rejected argument
values, and refuses redirects and retries. Settings writes still require the explicit confirmation and
session-bound configuration token. Exact evidence unavailability accepts only
known protocol reason codes, so unexpected diagnostic text is not printed.

Origin declarations are validated before URL normalization so malformed
authorities and dot-segment paths cannot become relationship evidence. Valid
origin normalization and path-bearing Referer declarations remain supported.
Socket-peer eligibility now copies only its three scalar runtime inputs, avoiding
unrelated settings clones while preserving the existing capture and durability
gates.

All origins picked its 24 cards by name, and an arrow is drawn only between two
shown cards, so related origins usually fell on either side of the cap: a real
session with 67 relationships among 86 origins showed none. Cards now open, and
reorder on an explicit Reload, by relationship: the best-connected origin, its
neighbours, then each further connected group. The graph also dropped its two
fixed columns for a layout by link depth: the same session went from one hub
beside a column of 23 cards, with 17 arrows looping inside that column, to three
columns of 1, 13 and 10 cards with no same-column arrow, about 40% shorter.
Direct relations now reads sources, the pinned origin, then targets. Polling
still keeps cards in place.

Twelve registered cases (sign-in redirect chain, hub fan-out, hub with
sub-hubs, cycles, separate sites, card and arrow caps, reference-only origins,
self links, a dense mutual cluster, body and Link inspections, an eight-hop
redirect chain, recorded address groups) then exposed three drawing faults. An arrow that skipped a column was
drawn straight, behind the cards it passed: a sign-in chain's return redirect
hid under the forward arrows and seemed to start at the card beside its target.
Such arrows now follow the gap between two rows. Arrows between neighbouring
columns all bent at the middle of the gap and fused into one band; each now
turns at its own point, the longest nearest its source. Cards whose links all
fell past the 40-arrow cap were still laid out among linked cards with no
arrow; they now join the unlinked grid. A pinned body/Link star also centers its
source on its neighbours.

The map also gained its own display filter, as Burp has for its site map. It
opens HTTP history's filter dialog on the map's own settings, saved apart in UI
settings, and the server applies History's row matcher while it takes the map
snapshot, so a condition hides exactly the rows it hides in History. The default
hides images, styles and fonts, which removes a page's static CDN and its arrows.
`snapshot.filtered_rows` and the status line count the hidden rows, and
`sniper-cli scope service-map` takes the same conditions as options. The selected
card's gold arrows now flow toward their targets, their own dashes moving; a
selected redirect takes long dashes so it can flow, and reduced motion keeps
them still. A Referer or Origin naming the requested origin itself is no longer
listed as a relationship. A trackpad pinch, or Ctrl with the mouse wheel, zooms
the graph around the pointer.

An Origin or Referer link no longer looks the same for an API call and an image
load. Each link counts its rows and sorts them by request kind (API call, page
navigation, frame, script, static file, other), read from `Sec-Fetch-Dest` and,
without it, from the response type, the `Origin` header and the method. The
legend toggles each kind; frames, scripts and static files are hidden by
default, so a page's CDN loads draw no arrows and rank nothing. An arrow takes
the colour of its leading kind (API calls a muted blue, shown on each legend toggle), so
one API call among image loads still reads as an API link, and grows slightly
heavier with its rows; its head keeps one size in the line's colour. Each link also counts the rows
whose response let its source read it through CORS, and those that allowed
credentials too. Selecting an arrow marks its relationship in the inspector,
with View source for an example row. The links carry `request_count`,
`request_kinds`, `cors_allowed_count` and `cors_credentials_count` in the API
and the CLI, redirects carry `request_count`, and the hidden kinds are saved in
UI settings.

Origins of one site now share a card (Group by site, on by default): a site is a
host's last two labels, or three under common two-level suffixes such as
`co.kr`. Their links share the card's arrow with their counts added up. The
leading origin's site, and sites shown separately, keep a card per origin. An
origin or a whole site can be hidden from the map in every session, and the
legend's Hidden list brings each back. Both are saved in UI settings and change
the map only; the API and the CLI still return every origin.

The map also says less. The snapshot status above it and the explanatory footer
below it are gone: only an error or the first load shows above the map, and the
counts, coverage and window sit under Details, whose summary names the origins
the card cap leaves out. Legend labels are shorter, cards drop the scheme line and
the empty product chip, and the inspector drops its explanatory paragraphs. Each
card instead leads with what its origin serves (Front, API, Static, Unknown, Ref
or Site), read from its endpoints' response types, with a declared application
product's mark, such as Next.js, in place of the icon.

Two reads were added. Headers rarely name a version (`X-Powered-By: Next.js`
carries none), but responses do: script banners and runtime values such as
`window.next={version:"…"}`, page markup such as `ng-version` and `data-v-`
attributes and the generator meta, and asset URLs such as a CDN's
`/npm/vue@3.4.21/` or a `/_next/static/` build directory. The map now reads
these for about 150 front-end frameworks, CMSs, UI kits, libraries,
third-party services and trackers, with Wappalyzer's catalogue as the checklist and Sniper's own rules,
once per row revision and bounded per map. An asset's technologies go to the
page that loaded it; cards lead with what the site is built with, and the
inspector lists them under Front-end (`front_technologies` in the API and the
CLI). Opening an endpoint
reads its newest 200 rows at once and lists each query, form, JSON or multipart
parameter with its row count and up to three values
(`GET /api/target/service-map/parameters`, or `sniper-cli scope service-map
parameters`).

The map also reads what an origin's own responses say about its servers:
vendor header names (`CF-RAY`, `x-envoy-*`), header values the catalog does not
name (`Server: AmazonS3`, an operating system in parentheses), the names of the
cookies it sets (`JSESSIONID`, `AWSALB`, `BIGipServer…`), and error, default and
debug pages, stack traces and SQL errors. Each finding gets a layer from edge to
database, and what a response gives away by mistake is an exposure, shown first
on the card. Scripts and pages are read for exposures too: a source map comment
(but not a library's own, as in `jquery.min.js`), a cloud, chat, code-hosting or
payment key, a private key, a JWT, and a private address in a script's URLs or
an error, reported without the matched value. The API and the CLI carry them as
`server_technologies`.

Each row's User-Agent, with Client Hints for Chromium browsers, now names the
client that sent it: a browser, an app's WebView, an app's HTTP stack, a tool, a
library or a crawler, from a fixed list of rules. The map counts each client's
rows per origin and the requests it made itself, with no Origin or Referer.
One browser, app or tool is one client whatever versions its rows named
(`versions`). In the GUI the clients lead the map in their own column, an
unnamed one draws no card, each draws a Direct request arrow to the cards it
went to itself that nothing else links to, and selecting one draws its arrow to
every card it went to itself; the API and the CLI carry them as `clients`. Only
the fixed names leave the parser, never the header.

Each origin also names how its requests authenticate, from names and shapes
only: the Authorization scheme (telling a JWT from an opaque token), API key
headers, session and JWT cookies, WWW-Authenticate challenges, credentials in
the URL, and OAuth, OpenID Connect and SAML parameters. A card shows it as a
lock chip, the APIs tab lists it first, each endpoint carries its own kinds,
and the API and the CLI carry it as `auth`.

A card shows its origin's captured favicon in place of a letter mark, when
history holds one (`favicon` in the API and the CLI); the map never requests an
icon from a target. Product chips carry the product's logo, bundled from Simple
Icons (`web/product-icons.js`, permissive licences only), and the ⚠ chip names
its exposure in a word or two instead of counting it. A private key now needs key material after
its header, and a JWT counts only in scripts and errors.

The server rules were checked against 26 real web servers and WAS run in a
lab, then against 667 public sites' homepages visited through Sniper. What
they missed was added: WildFly, Undertow, Open Liberty, Payara, GlassFish and
Grafana pages; TmaxSoft WebtoB, Google's and NAVER's front ends, CDNetworks,
BunnyCDN, Apache Traffic Server and a few more by `Server`; APM agents
(Scouter, WhaTap, eLevisor) in a new `monitoring` layer, LENA, eGovFrame,
DataDome and Azure App Service by cookie name; and the servlet engine a
session ID's shape names (JEUS, WebLogic, WebSphere, Jetty). The front end
gained the libraries the crawl loaded most, Korean ones among them
(NetFUNNEL, NAVER Analytics and Login, nProtect), and reads a
`name-version` generator such as `mkdocs-1.6.1`.

A second pass over the same crawl counted each site where its visit landed,
and only the 499 sites that served a homepage; the rest answered the headless
browser with a block or a challenge. It found that a one-origin or in-scope
map left out what a page loaded from a CDN, which the whole map gave the page;
both now name the same front end. It also added Meta's, Tencent's and
OVHcloud's edges, Fastly's timing header, a renamed `JSESSIONID`, F5's
per-path cookies, the third-party services pages load (payments, maps,
CAPTCHAs, chat, consent managers, analytics and ad tags) and library files
named without a version, and reads bundles up to 8 MiB.

Two more passes worked down what no rule named, over that crawl and 358 more
sites from Japan, China, Europe, Russia, the Americas and Asia-Pacific. Each
signal was traced to the hosts it came from and named only when those hosts
said whose it was: Tencent's, Baidu's and ByteDance's clouds, Atlassian's and
Automattic's edges, BunnyCDN's `CDN-…` headers, Fly.io, Arc XP, Sanity, Read the
Docs, image CDNs, S3 and Cloud Storage object metadata, Dynatrace, and the
cookies ad and analytics services set on their own hosts. A name many vendors
use stays unnamed, and generic headers (`X-Cache`, `traceparent`, rate limits)
no longer show as unnamed signals. `scope service-map unnamed` gathers what is
left across the whole map, each signal with its origins, evidence and
`named_alongside`, the products named on the same origins, so an agent can
judge the rest the same way.

A response header over 4 KiB, such as a long Content-Security-Policy, no
longer stops the map from reading the page: only that header is skipped, and
the redirect and CORS answer still count unless it is the `Location` or
`Access-Control-Allow-Origin` itself. It had left 123 crawled pages unread,
a Next.js site among them.

An origin that serves API data opens as API docs, an OpenAPI 3.1 document laid
out as Swagger UI lays one out (**API docs** in its inspector, `GET
/api/target/service-map/openapi`, and `scope service-map openapi` in the CLI):
its path templates, parameter and body field names with guessed types,
response statuses and media types, and the credentials its rows showed, built
from every retained row and holding no captured value. Each operation sends its
newest row to Replay, and the document copies as JSON or opens in Swagger
Editor (editor.swagger.io, to paste it into). The map has its own tool,
**Map**, after Capture, with **Service Map** and **APIs** views; **Scope** again
shows its rules beside the captured hosts and paths on one screen, as before the
map was added. The CLI keeps `scope service-map`, with `target` as an alias of
`scope`. An origin whose rows
carried no typed response now stays off the map unless selected or searched
for.

The overview draws one arrow per direction between two cards, whatever links
them, where an Origin and a Referer link had drawn two. The zoom percentage fits
the map, and fitted returns to 100%, in place of a Fit button; the bar between
the map and the inspector resizes them, and the width is kept. The inspector
leaves out what it had explained at length: an empty observation, a socket peer
not recorded, a matching inspection with no usable address, byte offsets, and
the preambles of the optional inspections, whose limits fold away.

Cards are shorter (84px at the default text size) and a product found without a
version shows its name alone; hovering `+N` lists the products it stands for.
Every map toolbar control has the compact toolbar size, and the scope toggle is
the In scope pill beside Filter, as in HTTP history. While the app updates
itself, the Update button shows a bare ring.

The GUI map also stopped reading only the newest 10,000 rows, where its 8 MiB
projection limit often stopped it near 6,000. It now asks for `all_rows=true`:
the server folds every retained row into the map a chunk at a time without
keeping them, continues past rows that retention removes during the read, and
keeps the last result to answer polls while history is unchanged or the map is
recent. Reload asks for a fresh map. The CLI keeps the windowed read unless
`--all-rows` asks for every row.
