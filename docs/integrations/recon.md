# Recon endpoint discovery

Recon combines an explicitly scoped static crawler, existing urlscan results, and the Wayback CDX index into one session-owned endpoint inventory. Choose the **Recon** tab, enter an absolute target URL, choose sources and limits, then start. Every source reports its own status, request count, discoveries, limits and warnings. Stop cancels in-flight local work. Switching sessions keeps jobs and their results attached to the original session; deleting a session or shutting down cancels its jobs. Restarted unfinished jobs are marked interrupted and never silently resumed.

## Scope and consent

Only use this feature against targets you are authorized to assess. A target is mandatory. The default scope is its exact hostname, scheme and effective port. The optional subdomain checkbox includes that domain and descendants through Sniper's shared host matcher. HTTP on port 80 may upgrade to HTTPS on port 443; HTTPS is never downgraded. All other ports and hosts are excluded. Paths do not narrow scope. The crawler rechecks every redirect, link, resource and sitemap URL. Provider results are filtered by the same boundary. WebSocket URLs may be stored as evidence but are never connected to.

The crawler sends unauthenticated GET requests only, with validated TLS and the session's existing upstream proxy configuration. It does not submit forms, execute JavaScript, copy captured cookies/Authorization headers, replay archived URLs, or automatically visit JavaScript candidates. GET requests can still have site-specific side effects. robots.txt rules are discovery hints, not authorization; they are retained as candidates, not fetched. Ordinary links, resource references and sitemap entries can be followed.

History lookup requires acknowledgment that the target hostname is sent to urlscan.io and/or web.archive.org. It does not create a scan. The separate **New urlscan scan** source requires its own acknowledgment and an explicit visibility: private (default), unlisted, or public. Unlisted is not private. urlscan runs its own browser and may load resources outside Sniper's scope; only imported findings are filtered. Account plan/retention rules apply. The target's full URL is submitted, so query strings/fragments and embedded credentials are rejected for new scans. Never submit confidential paths. No automatic visibility fallback is performed. An uncertain submission is not retried. Stopping local polling cannot cancel a scan already accepted by urlscan.

Set URLSCAN_API_KEY in the backend process environment for authenticated urlscan search or submission. The key is never exposed to the UI, written into session state, included in logs, or sent to Archive.org/target hosts. History may work without a key subject to provider policy. Provider connections use a separate TLS-validating direct client and never inherit captured credentials or the target's upstream proxy credentials.

## Evidence and bounds

Inventory deduplication uses normalized URL plus method, preserving query ordering, values and repeated parameters. Fragments are removed from the comparison key, and raw URL spellings are retained separately. URL parsing may normalize host casing, default ports and dot segments; raw observations are not discarded. Methods inferred from form markup and JavaScript URLs are candidates, not observed HTTP requests.

- live: the local crawler received an HTTP response (including error responses), with observation time and status
- observed: a literal page reference, or evidence from an explicitly submitted urlscan scan; not proof of current availability
- history: a historical urlscan or Wayback observation
- candidate: static JavaScript literal, form action/parameter shape or robots rule; never executed automatically

Defaults are 100 crawl requests, depth 3, 5 provider search pages and 5,000 inventory endpoints. Supported maxima are 1,000 requests, depth 10, 20 pages and 5,000 endpoints per session. Responses are capped at 2 MiB, inventory at approximately 8 MiB, raw spellings at 8 and evidence records at 16 per endpoint, and job history at 20. Static extraction retains at most 10,000 HTML tags, script literals, robots lines, sitemap locations or discoveries per document/pass. Hitting a bound with unexamined content reports a partial source in the API and UI, even when the job finishes normally; a full HTML token budget conservatively treats any remaining text as unexamined. Hitting limits is visible. Provider quotas, missing scan details, archive gaps and urlscan account history windows also limit completeness. This feature does not promise exhaustive discovery.

urlscan search uses cursor pagination and retrieves full scan results, including request/response URLs, lists, links, redirects and WebSocket observations. Wayback uses CDX resume keys without success-status or MIME filters; errors and old resources can be useful endpoints. Static extraction includes HTML links/resources/base URLs, GET/POST form actions and field names, inline/external JavaScript URL literals, robots hints, and sitemap indexes/URLs. It does not implement browser rendering, authentication, source-map discovery, JavaScript evaluation, wildcard expansion, or deducing dynamic route templates. JavaScript and ECMAScript MIME types are recognized case-insensitively, including extensionless script responses and MIME parameters. The `.js` suffix is a fallback only when no MIME type is declared. Relative JavaScript literals are resolved against the containing document/script as a heuristic.

## Local API

- GET /api/recon?session_id=<UUID> returns the session ID, jobs and inventory.
- POST /api/recon/jobs accepts session_id, target_url, include_subdomains, sources (crawler, urlscan, wayback, urlscan_submit), max_requests, max_depth, max_endpoints and max_pages. history_acknowledged is required for history sources; scan_acknowledged and scan_visibility are required for new submissions.
- POST /api/recon/jobs/<job UUID>/stop with {"session_id":"<UUID>"} cancels a job and returns {"stopped":true,"session_id":"<UUID>"}.

There is no dedicated CLI command in this first version. The API uses the same authentication middleware as existing routes. Inventory and jobs are persisted as a backward-compatible defaulted component of session state, without inserting artificial proxy history transactions.

## Validation

Tests use deterministic fixtures and isolated loopback servers only. No real targets or provider scan submissions are part of the test suite. Run cargo fmt --all -- --check, cargo test --locked --release, node --check web/recon.js and node --test tests/recon_ui.test.cjs, and python3 tests/recon_discovery_smoke.py target/release after rebuilding. Desktop/WebView behavior should also be smoke-tested in a built application before release.

## Provider references

- https://docs.urlscan.io/pages/search-api-reference
- https://docs.urlscan.io/pages/result-api-reference
- https://urlscan.io/docs/api/
- https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
