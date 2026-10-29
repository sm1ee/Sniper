# Known vulnerabilities for the versions Sniper detects

Status: design, revised after a builder check and an adversarial review.
Nothing is built yet.

## Problem

Sniper already names products and their versions in captured traffic:
`nginx/1.18.0` in a `Server` header, `jquery-1.12.4.min.js` in a script URL.
The Service Map lists them per origin. It does not say which known
vulnerabilities a version carries, so the tester looks each one up by hand.

Looking them up online is the wrong fix. Per-lookup services need a key, hit
free-tier limits, and send the product and version of someone else's target to
a third party.

## What other tools do

- **Proxies.** Burp and ZAP attach vulnerabilities to JavaScript libraries
  only, from the retire.js data. Burp ships that data inside the app; ZAP
  bundles it in an add-on. They raise one issue per library and version, and
  Burp marks it Tentative. Neither maps a server banner to vulnerabilities out
  of the box; Burp's Vulners extension does, online and with a key. We found
  no Caido feature or plugin for this.
- **Scanners.** Nessus and Greenbone compare banner versions and mark the
  result as less reliable. Greenbone rates a banner check 80%, or 30% for
  open-source products whose distributions backport fixes. Nessus corrects
  distribution banners with a backport list. Shodan tags banner-derived CVEs
  "unverified".
- **How good a version match is.** A USENIX Security 2025 study ("Trust but
  Verify") re-tested Shodan's banner-based CVE tags with Nuclei. For 18 of 21
  CVEs, Nuclei contradicted more than 95% of them.
- **How data stays fresh.** Nuclei, Grype and Trivy download their data on first
  use and update it automatically, with a switch to turn that off; ZAP checks at
  startup. None asks for consent first.

## Goals

1. For each detected product version, list the known vulnerability advisories
   from public data, matched on this machine.
2. Show them where the tester already looks: one Finding per page origin,
   product and version, and a badge on the product in the Service Map.
3. Say plainly that a version match is a lead, not a confirmed vulnerability,
   and offer the step that confirms one: a template from the Templates library.
4. Keep the data current with no service of ours and no per-lookup API.

## Non-goals

- Confirming a vulnerability from a version alone.
- Deciding backports from distribution security trackers (Ubuntu, Debian, Red
  Hat). A distribution banner gets a caveat instead.
- Building or hosting an aggregated index of our own.
- Numeric CVSS scores. None of the sources below carries one; they give a
  severity word or a vector string.
- NVD data before phase 4.
- Products seen without a version.

## Anti-goals

These would make the feature a failure even if it works:

- A wall of High and Critical findings from version guesses.
- A partial version matched as its lowest release. `jquery@3` would get jQuery
  3.0.0's advisories, a KEV mark among them, on a site that loads 3.7.1.
- Any request to a target that the user did not start, and any prefilled
  request to a host outside Scope.
- A target's product or version leaving the machine.
- Matching that slows capture: nothing here may run on a proxy task.

## Decisions

### 1. Data: public sources, downloaded as files

| Source | Use | Phase | URL | Size (2026-10-27) | Terms |
| --- | --- | --- | --- | --- | --- |
| retire.js repository | JavaScript library versions and their advisories | 2 | `https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json` | 0.6 MB | Apache-2.0 |
| CISA KEV | CVEs exploited in the wild | 2 | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 1.8 MB | CC0 |
| FIRST EPSS | Probability that a CVE is exploited | 2 | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (redirects to the day's file on the same host) | 2.8 MB | FIRST EPSS usage agreement: free, attribution requested |
| OSV, Bitnami ecosystem | Server products: version ranges and their advisories | 3, after the gate | `https://osv-vulnerabilities.storage.googleapis.com/Bitnami/all.zip` | 9.9 MB | Apache-2.0 (Bitnami vulndb) |

- **No key and no call per CVE.** The data is not redistributed: each
  user's Sniper fetches it from its source.
- **Attribution.** Each source's terms appear where its data is shown and in
  the docs.
- **No integrity check beyond TLS.** No source publishes a checksum or a
  signature, so the status says "not verified (TLS only)". The SHA-256 Sniper
  records is computed after download; it is not a check.
- **Bitnami archive format.** The archive is a zip, and Sniper has no zip
  reader. In phase 3 the builder chooses between a new dependency and the
  `bitnami/vulndb` GitHub tarball, which the existing tar code reads.

### 2. Updates: the Templates daily update, with four differences

The schedule and switch follow the Templates daily update (`run_daily_update`,
`update_due`, `record_check` in `src/templates/library.rs`):

- Sniper first looks a minute after launch, then every hour.
- The daily update is on by default and has an off switch.
- No consent dialog.
- A failure keeps the data, leaves the state idle and notes the error.
- Requests use the environment's proxy and ignore one that points back at
  this machine.

Where it differs from Templates:

1. **The first fetch is automatic.** With no data, the first look fetches it.
   Templates waits for a Download instead.
2. **Each source keeps its own record.** That record holds when it was fetched,
   its validator (ETag or Last-Modified), its SHA-256 and its last error. A
   source that succeeded waits a day. A source that failed is tried again at
   the next hourly look.
3. **Imported files do not stop updates.** An import loads the files from disk
   for networks that cannot reach these hosts, and the next successful fetch
   replaces them. Turning the switch off stops fetching.
4. **The client is not the GitHub client.** It follows redirects only over
   HTTPS and only within the source's own host (EPSS redirects to the day's
   file). Each source has its own size limits.

The requests reveal the user's address and Sniper's User-Agent to GitHub,
CISA, the EPSS host and Google. They carry nothing about any target. The docs
list these hosts, as ZAP's FAQ does.

### 3. Storage: app-level, untrusted input

- **Location.** `<data dir>/vulndata/`, with a manifest of the per-source
  records. Every session shares it; findings stay per session.
- **Writes are atomic** (`AGENTS.md` §5).
- **Downloaded files are untrusted input.**
  - Parse them under limits on download size, unpacked size and entry
    count, as the Templates import does (`src/templates/library.rs:54-61`).
  - Render every summary as escaped text.
  - Show a link only if it is `https:`.

### 4. Matching is local and fails closed

- **Inputs.** Use the three detectors Sniper already has, and write no new
  one:
  - The header catalog in `service_map_technology.rs`: each
    `TechnologyObservation` whose `version_status` is `reported`. It reads
    `Server: nginx/1.18.0`, `Microsoft-IIS/…`, `X-Powered-By: PHP/…` and
    `X-Generator: Drupal 10`. Exclude `apache_coyote`: its string names a
    Tomcat connector, not a product version.
  - The `Detection`s of `service_map_servers.rs`: error pages, cookies and
    bodies.
  - The `Detection`s of `service_map_libraries.rs`: script URLs and bodies.
- **Partial versions match nothing.**
  - A version with fewer segments than the range bounds it is compared with is
    treated as no version. Examples: `3` from `jquery@3`, `2.4` from
    `Apache/2.4`, `10` from `Drupal 10`.
  - The same applies to a CDN URL's `@<partial version>`, which serves that
    line's newest release.
  - Never pad a partial version with zeros. Note that `src/templates/version.rs`
    pads `1.2` to `1.2.0`, as go-version does. If it is reused, it must check
    the written segment count first.
- **Product names.** A hand-kept table maps a Sniper `product_id` to a list of
  `(source, name, version range)`.
  - One Sniper id can map to several source names. `jquery_ui` maps to four
    retire.js components.
  - The version range keeps lines apart. `ckeditor` maps to retire.js
    `ckeditor` below 5 and to `ckeditor5` from 5 on.
  - A product with no entry gets nothing. The table is tested.
- **Wrong over silent.** A version that does not parse, or a range form the
  comparator does not know, yields no match.

### 5. Every result is a lead

- A version match is tentative. The finding says so in one sentence, with the
  reason: the version string alone.
- A banner that names a distribution build (`(Ubuntu)`, `(Debian)`, `el7` and
  the like) adds "the distribution may have backported fixes".

### 6. Findings: stable, small, and joined with the data when read

- **Granularity.** One finding per page origin, product and version.
- **Severity is Info**, whatever the advisories say. The user chose this on
  2026-10-29: most version matches are not real vulnerabilities, and a
  finding's severity must not claim otherwise.
- **Identity**
  - Category: `known_cve`.
  - `rule_id`: `known-cve:<product_id>`.
  - Title: fixed, for example `Known vulnerabilities: nginx 1.18.0`.
  - Evidence: normalized to `product@version`, so a cache-busting query on a
    script URL does not add findings.
  - Under the existing deduplication key (host, `rule_id`, category, title,
    scope, in `src/scanner.rs:478-497`) this gives exactly one finding per
    host, product and version.
- **What is stored.** Only the product, the version and the evidence. The
  advisory list, its count and the KEV marks are joined from the current data
  when the finding is read. As a result:
  - updated data never duplicates a finding;
  - an open finding never goes stale;
  - `state.json` does not grow with advisory lists (one GitLab version matches
    530 Bitnami advisories).
- **The advisory list**
  - Each row: the advisory id (the CVE when there is one, else the GHSA or
    the source's own id), the source's severity word, KEV, EPSS, summary,
    fixed version and link.
  - Order: KEV first, then EPSS, then severity.
  - The unit is the advisory, not the CVE: 22% of retire.js advisories carry no
    CVE id.
- **Host of a front-end library.** It is the page origin that loaded the
  script (its Referer), as the Service Map attributes front-end technologies.
  The script's own host is used only when no page is known. With the CDN's
  host, the In scope filter would hide every CDN-served library. The finding
  keeps the script's record, so its host and its record's host can differ;
  the builder handles that, along with building an origin (a finding has no
  scheme field).
- **Where it runs.** In passive scanning of each captured response, but never
  on the proxy task:
  - Run it behind a permit with `spawn_blocking`, as passive templates do.
  - Under load a record may be skipped, and a Rescan covers it.
  - Read bodies within the bounds the detectors already use.
  - The third call site, `recover_missing_scanner_findings`
    (`src/session.rs`), runs without app state. The builder decides whether it
    joins in or leaves CVE findings to Rescan.
- **Data that arrives later.** Traffic captured afterwards is matched
  automatically. Older history needs one Rescan, and the data section says so
  after the first fetch.
- **The "Server version disclosure" finding stays.** It shares the evidence
  but not the purpose.

### 7. Service Map: a badge on the product

- **The badge.** A product with matches shows its advisory count beside its
  version, marked when any advisory is in KEV. The badge opens the list or the
  finding.
- **KEV marks.** They appear on the badge and in the rows, never in a title.
- **Shape.** The summary is a separate per-origin field (`known_vulnerabilities`:
  product, version, count, KEV count, highest severity word), joined at read
  time like findings. Existing technology items gain no field.
- **Three contracts reject unknown fields**, so change them together:
  - `TechnologyObservation` and `TechnologyAggregate` deny unknown fields, and
    the CLI deserializes them (`src/service_map_technology.rs:105`, `:126`).
  - The CLI output schemas set `additionalProperties: false`.
  - The UI normalizer's `exactFields` (`web/service-map.js:312`) throws on an
    unknown field.

### 8. Confirming a vulnerability is one press away

- **Which templates count.** A template is offered for an advisory when:
  - its `TemplateMeta.cve` names the advisory's CVE;
  - it can run actively;
  - it does more than compare versions.

  A template whose matchers only call `compare_versions` is a version check;
  about 400 community templates are. It is listed separately as "Version check"
  and never confirms anything. Telling the two kinds apart needs a field in the
  template index and an `ENGINE_VERSION` bump.
- **No automatic send.** "Check with N templates" opens Active Scan's Manual
  scan with the origin and those template ids filled in. Nothing is sent until
  the user presses Start. An origin outside Scope is not filled in, so a
  CDN-served library never sends a request to the CDN.
- **Confirmed.** When the origin has a `nuclei:<template-id>` finding from one
  of the counted templates, the advisory row shows **Confirmed**. A library
  update that renames a template loses that link, which is acceptable.

### 9. API, CLI and settings

- **API.** Status (per source: date, size, terms, error; plus `auto_update`),
  update now, import, and the auto-update switch. A lookup by product and
  version serves agents.
- **CLI.** Every endpoint gets a `sniper-cli` command (`AGENTS.md` §4).
- **Settings.** **Settings ▸ Runtime** gains a **Vulnerability data** section:
  - each source with its date, its terms and "not verified (TLS only)";
  - the **Update daily** switch;
  - **Update now** and **Import** in a ⋯ menu.

## Phases

1. **Measure (gate).**
   - Map Sniper's versioned products to retire.js and Bitnami names.
   - Measure the share of version-bearing detections each source covers, on a
     crawl corpus or a session, not on catalog counts.
   - A preliminary check (2026-10-29) found:
     - retire.js covers 35 of the 110 front-end framework, UI, library and
       meta-framework products.
     - Bitnami has nginx, Apache, PHP, Tomcat, Jenkins, Kibana, Grafana,
       Elasticsearch, WildFly, Python, Ruby, CouchDB, WordPress, Drupal,
       Joomla and Magento.
     - Bitnami lacks IIS, Jetty, gunicorn, Tengine, lighttpd, Squid, Undertow,
       WebtoB, JEUS, Resin, MySQL and OpenSSL.
   - Decide with the user, on these numbers, what phase 3 uses.
2. **Data and JavaScript libraries.**
   - Build the data layer for retire.js, KEV and EPSS: download, daily
     update, import, status, API, CLI and settings.
   - Add retire.js matching, findings and the Service Map badge.
3. **Server products.**
   - Add Bitnami, or what the gate chose, with the distribution caveat.
   - Add the confirmation link to templates.
4. **Later, separately approved.** Add NVD feeds and Anchore's
   `nvd-data-overrides` for products the earlier sources lack.

## Left to the builder

- Whether to keep the raw files or a derived index, and its format.
- The version comparator, as long as it fails closed, never pads, and is tested
  on both sources' range forms (retire.js `atOrAbove`/`below`, OSV `SEMVER`).
- How passive scanning calls the detectors without doing the work twice.
- The API and CLI shapes, within the contracts above.
- Layout of the badge, the advisory list and the settings section.
- Conditional requests (`If-None-Match`, `If-Modified-Since`) for unchanged
  files.
- Zip support or the tarball for Bitnami (phase 3).

## Constraints

- Fixtures and tests use `example.com` and synthetic data only (`AGENTS.md` §7).
  Real data files are not committed.
- Never log captured traffic. A finding's evidence is `product@version`.
- Run every check against an isolated runtime (`AGENTS.md` §3) before calling a
  phase done.
