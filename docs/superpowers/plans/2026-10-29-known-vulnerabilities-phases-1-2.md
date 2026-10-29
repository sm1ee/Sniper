# Known Vulnerabilities, Phases 1–2: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure how well public vulnerability data covers what Sniper detects (phase 1). Then list known advisories for the front-end library versions Sniper detects, as Info findings and Service Map badges, from retire.js, CISA KEV and FIRST EPSS files fetched daily (phase 2).

**Architecture:** A new `src/vulndata/` module owns the downloaded files, their manifest, the daily update and an in-memory `VulnIndex`.
- **Passive scanning and Rescan** call it to make one stable finding per page host, library and version. The finding stores only `product@version`.
- **Read-time joins.** The advisory list is joined from the current index when a finding is read and when the Service Map is built. So new data never duplicates a finding.

**Tech Stack:** Rust (axum, tokio, reqwest, serde, flate2, already in `Cargo.toml`; no new crate), vanilla JS UI, `node --test` fixture tests.

**Spec:** `docs/superpowers/specs/2026-10-29-known-cves-design.md`. Phase 3 (server products, the template confirmation link) is planned separately after the phase-1 numbers.

## Global Constraints

- **Severity.** Every known-vulnerability finding is `Severity::Info`, whatever the advisories say.
- **Identity**
  - Category: `known_cve`.
  - `rule_id`: `known-cve:<product_id>`.
  - Title: `Known vulnerabilities: <name> <version>`.
  - Evidence: `<product_id>@<version>`.
- **What is stored.** A finding stores no advisory list. The list, its count and the KEV marks are joined at read time.
- **Partial versions.** A version whose known segments cannot decide a range bound matches nothing. Never pad a version with zeros.
- **Data sources**
  - Phase 2 fetches only retire.js, KEV and EPSS. Bitnami waits for phase 3.
  - URLs:
    - `https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json`
    - `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
    - `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`
  - Terms: retire.js Apache-2.0; KEV CC0; EPSS FIRST usage agreement (free, attribution: "See EPSS at https://www.first.org/epss").
- **Downloaded data is untrusted.**
  - Parse it under size limits.
  - Keep only `https:` links.
  - The UI renders all text escaped.
  - The status says `not verified (TLS only)`.
- **Network.** No request ever names a target. No per-advisory API.
- **Daily update**
  - First look 60 s after launch, then hourly.
  - A source fetches if it never succeeded, if its last attempt failed, or if 24 h have passed since its last success.
  - On by default; switch off with `auto_update`. No consent dialog.
- **Runtime.** Nothing runs on a proxy task. Matching runs behind a permit with `spawn_blocking`.
- **Tests.** Fixtures and tests use `example.com` and synthetic data only. Real data files are never committed.
- **Repository rules (`AGENTS.md`)**
  - Atomic writes (`crate::session::write_json`).
  - Every API endpoint gets a `sniper-cli` command.
  - `cargo fmt`.
  - No new warnings; `sniper-desktop` stays at 37.
  - Commit with `git commit --only <paths>`, because another session may share this worktree's index.

## Review Focus

These five failure modes are not covered by the spec's own tests. Each has a test in the task named.

1. **One host unreachable.** On first launch the network blocks one host. The other two sources still load, the status shows that source's error, and no dialog appears. *(Test in Task 6.)*
2. **Bad file.** A file is oversized, a gzip bomb or truncated JSON, by download or import. It is refused, and the previous file and index stay. *(Tests in Tasks 4 and 6.)*
3. **Hostile data.** An advisory summary holds `<img src=x onerror=alert(1)>` and a `javascript:` link. The link is dropped, and the text shows escaped in the finding detail and the badge tooltip. *(Tests in Tasks 4 and 9.)*
4. **Data refreshed.** New data arrives while findings exist. There is still one finding per page host, library and version, and its detail shows the new list. *(Test in Task 8.)*
5. **CDN library on a scoped page.** An in-scope page loads a library from a CDN. The finding's host is the page's host, so the "In scope" filter keeps it. *(Test in Task 8.)*

---

### Task 1: Phase 1: measure coverage (gate report)

This task produces numbers, not code. Nothing in it is committed.

**Files:**
- Create (temporary, never committed): an `#[ignore]` test at the end of `src/vulndata/mod.rs`, or of `src/service_map_libraries.rs` if Task 6 has not run yet.
- Create (scratchpad only): `coverage.py`.

**Interfaces:**
- Consumes the detectors as they are:
  - `crate::service_map_libraries::detect_url(url: &str) -> Vec<Detection>`
  - `crate::service_map_libraries::detect(body: &str, kind: Kind) -> Vec<Detection>`
  - `crate::service_map_servers::detect_headers(...)` and `detect_body(body: &str) -> Vec<Detection>`
  - `crate::service_map_technology::observe_header(...)`, keeping `version_status == Reported` and excluding `apache_coyote`.
- Produces a report to the user with two numbers per source: the share of distinct version-bearing `(product_id, version)` detections it covers, and the same share weighted by row count. It also lists the 20 most common uncovered products.

- [ ] **Step 1: Ask the user which corpus to read.** No crawl corpus is left on disk. Offer two choices: a fresh crawl of public sites, or a session's `transactions.ndjson` that they name. Do not open a real session without their yes.
- [ ] **Step 2: Write the ignored test.** It reads `SNIPER_SCAN_CORPUS` row by row, runs the four detectors and writes `product_id,version,rows` lines to `SNIPER_COVERAGE_OUT`. It prints shapes only, never values from the traffic.
- [ ] **Step 3: Run it.**
  - Command: `SNIPER_SCAN_CORPUS=<path> SNIPER_COVERAGE_OUT=<scratchpad>/detections.csv cargo test --release --lib coverage -- --ignored --nocapture`.
  - Expected: the CSV exists, with a header line and at least one row.
- [ ] **Step 4: Compute coverage with `coverage.py` (run with `python3 -I`).**
  - Fetch `jsrepository-v4.json` (0.6 MB) and `Bitnami/all.zip` (9.9 MB) into an empty scratchpad directory. The spec's approval covers these two downloads.
  - Map ids with the table in Task 3 for retire.js. For Bitnami, use the package names from `affected[].package.name`.
  - Print the numbers above.
- [ ] **Step 5: Report the numbers to the user and delete the temporary test.** The user decides phase 3's source. Phase 2 does not wait for that decision.

### Task 2: Version comparison that fails closed

**Files:**
- Create: `src/vulndata/mod.rs` (only `pub mod version;` for now) and `src/vulndata/version.rs`.
- Modify: `src/lib.rs`: add `pub mod vulndata;`.
- Test: the unit tests in `src/vulndata/version.rs`.

**Interfaces:**
- Produces:
  - `pub struct Version { numbers: Vec<u64>, pre: Option<String> }`
  - `pub fn parse(text: &str) -> Option<Version>`, an associated fn on `Version`.
  - `pub fn below(version: &Version, bound: &Version) -> Option<bool>`
  - `pub fn at_or_above(version: &Version, bound: &Version) -> Option<bool>`
  - `pub fn in_range(version: &Version, at_or_above: Option<&Version>, below: &Version) -> Option<bool>`
- `None` means the version's known segments cannot decide the question.

- [ ] **Step 1: Write the failing tests.**

```rust
fn v(text: &str) -> Version { Version::parse(text).unwrap() }

#[test]
fn parses_versions_and_refuses_text() {
    assert!(Version::parse("").is_none());
    assert!(Version::parse("abc").is_none());
    assert!(Version::parse("v1.12.4").is_some());
    assert_eq!(v("1.0.0.beta.3").pre.as_deref(), Some("beta.3"));
    assert_eq!(v("2.0.0-alpha.1").pre.as_deref(), Some("alpha.1"));
}

#[test]
fn a_partial_version_decides_only_what_its_segments_decide() {
    assert_eq!(below(&v("3.4.1"), &v("3.5.0")), Some(true));
    assert_eq!(below(&v("3.5.0"), &v("3.5.0")), Some(false));
    assert_eq!(below(&v("3"), &v("3.5.0")), None); // jquery@3
    assert_eq!(below(&v("2"), &v("3.5.0")), Some(true));
    assert_eq!(below(&v("4"), &v("3.5.0")), Some(false));
    assert_eq!(below(&v("3.5"), &v("3.5.0")), Some(false));
    assert_eq!(below(&v("3.5"), &v("3.5.2")), None);
    assert_eq!(below(&v("2.4"), &v("2.5.0")), Some(true));
    assert_eq!(at_or_above(&v("3"), &v("3.0.0")), Some(true));
    assert_eq!(at_or_above(&v("3"), &v("3.1.0")), None);
    assert_eq!(at_or_above(&v("1.5.1.2"), &v("1.5.1")), Some(true));
    assert_eq!(in_range(&v("3.4.1"), Some(&v("1.0.3")), &v("3.5.0")), Some(true));
    assert_eq!(in_range(&v("3"), Some(&v("1.0.3")), &v("3.5.0")), None);
}

#[test]
fn a_pre_release_ranks_below_its_release() {
    assert_eq!(below(&v("3.5.0-beta"), &v("3.5.0")), Some(true));
    assert_eq!(at_or_above(&v("3.5.0"), &v("3.5.0-beta")), Some(true));
}
```

- [ ] **Step 2: Run the tests and confirm they fail.**
  - Command: `cargo test --release --lib vulndata::version`
  - Expected: they fail to compile, because `Version` and the functions do not exist yet.
- [ ] **Step 3: Implement `version.rs`.** Use this algorithm; the signatures alone do not determine it.
  1. Parse.
     - Strip a leading `v`.
     - Take the leading digits and dots as `numbers`.
     - The rest, after one `-` or `.`, is `pre`.
     - Return `None` when there are no numbers.
  2. Compare position by position over the version's own segments. The bound is padded with zeros where it is shorter.
     - At the first difference, the answer is decided.
     - If the version runs out with every compared segment equal:
       - when the bound's remaining segments are all zero, every completion of the version is at or above the bound;
       - otherwise the answer is `None`.
  3. Pre-releases count only when both number lists are equal and complete:
     - a version with `pre` is below the same numbers without one;
     - two `pre` values compare as strings.
- [ ] **Step 4: Run the tests and confirm they pass.**
  - Command: `cargo test --release --lib vulndata::version`
  - Expected: PASS.
- [ ] **Step 5: Commit.**
  - Command: `git commit --only src/lib.rs src/vulndata -m "Compare versions without guessing missing segments"`. Write a body that explains the `jquery@3` false match.

### Task 3: Map Sniper's products to retire.js components

**Files:**
- Create: `src/vulndata/products.rs`. Add `pub mod products;` to `src/vulndata/mod.rs`.
- Test: the unit tests in `products.rs`.

**Interfaces:**
- Consumes: `Version`, `below` and `at_or_above` (Task 2), and `crate::service_map_libraries::known(id, None)`.
- Produces:
  - `pub struct Component { pub name: &'static str, pub from: Option<&'static str>, pub below: Option<&'static str> }`
  - `pub const RETIRE: &[(&str, &[Component])]`
  - `pub fn retire_components(product_id: &str, version: &Version) -> Vec<&'static str>`. It returns components whose version line holds the version; an undecidable line yields nothing.

**Table values.** Write them exactly. Each Sniper id maps to the retire.js names after the arrow.

| Sniper id | retire.js components |
| --- | --- |
| `jquery` | `jquery` |
| `jquery_ui` | `jquery-ui`, `jquery-ui-dialog`, `jquery-ui-tooltip` |
| `jquery_migrate` | `jquery-migrate` |
| `lodash` | `lodash` |
| `underscore` | `underscore.js` |
| `moment` | `moment.js` |
| `angularjs` | `angularjs` |
| `angular` | `@angular/core` |
| `react` | `react`, `react-dom` (not `react-is` or `scheduler`: their version lines differ) |
| `vue` | `vue` |
| `svelte` | `svelte` |
| `ember` | `ember` |
| `backbone` | `backbone.js` |
| `knockout` | `knockout` |
| `bootstrap` | `bootstrap` |
| `handlebars` | `handlebars` |
| `dompurify` | `DOMPurify` |
| `chart_js` | `chart.js` |
| `highcharts` | `highcharts` |
| `echarts` | `echarts` |
| `swiper` | `swiper` |
| `video_js` | `video.js` |
| `select2` | `select2` |
| `pdf_js` | `pdf.js` |
| `tinymce` | `tinyMCE` |
| `ckeditor` | `ckeditor` (below `5.0.0`), `ckeditor5` (from `10.0.0`) |
| `quill` | `quill` |
| `mootools` | `mootools` |
| `prototype` | `prototypejs` |
| `next_js` | `nextjs` |
| `axios` | `axios` |
| `highlight_js` | `highlightjs` |

Leave `three_js` out. Its revision numbers (`r150`) do not match retire.js's `0.150.0`.

- [ ] **Step 1: Write the failing tests.**
  - `retire_components("react", &v("18.2.0")) == ["react", "react-dom"]`
  - `retire_components("ckeditor", &v("4.22.1")) == ["ckeditor"]`
  - `retire_components("ckeditor", &v("41.0.0")) == ["ckeditor5"]`
  - `retire_components("jquery_ui", &v("1.13.2"))` has 3 names
  - `retire_components("preact", &v("10.0.0")).is_empty()`
  - every id in `RETIRE` satisfies `crate::service_map_libraries::known(id, None).is_some()`
- [ ] **Step 2: Run the tests and confirm they fail.**
  - Command: `cargo test --release --lib vulndata::products`
  - Expected: FAIL.
- [ ] **Step 3: Implement the table and the lookup.**
- [ ] **Step 4: Run the tests and confirm they pass.**
  - Command: `cargo test --release --lib vulndata::products`
  - Expected: PASS.
- [ ] **Step 5: Commit.**
  - Command: `git commit --only src/vulndata -m "Map front-end products to retire.js components"`

### Task 4: Parse the three sources under limits

**Files:**
- Create: `src/vulndata/sources.rs`. Add `pub mod sources;` to `mod.rs`.
- Test: the unit tests in `sources.rs`, with synthetic fixtures built inside the tests.

**Interfaces:**
- Produces:
  - `#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)] #[serde(rename_all = "snake_case")] pub enum SourceId { Retire, Kev, Epss }`, with `pub const ALL: [SourceId; 3]`, `fn url(self) -> &'static str` and `fn license(self) -> &'static str`.
  - `pub struct RetireAdvisory { pub component: String, pub at_or_above: Option<String>, pub below: String, pub severity: String, pub cves: Vec<String>, pub ghsa: Option<String>, pub summary: Option<String>, pub urls: Vec<String> }`
  - `pub fn parse_retire(bytes: &[u8]) -> Result<Vec<RetireAdvisory>>`
  - `pub fn parse_kev(bytes: &[u8]) -> Result<HashSet<String>>`
  - `pub fn parse_epss(bytes: &[u8]) -> Result<HashMap<String, f32>>`. It accepts gzip or plain CSV, skips `#` lines and the `cve,epss,percentile` header.
  - `pub fn identify(bytes: &[u8]) -> Option<SourceId>`. Gzip is EPSS. JSON with a `catalogVersion` key is KEV. A JSON object whose values hold `vulnerabilities` arrays is retire.js.
- Limits:
  - Download or import: retire.js 8 MiB, KEV 8 MiB, EPSS 16 MiB.
  - EPSS unpacked: 128 MiB.
  - At most 20,000 advisories and 400,000 EPSS rows.
- Field rules:
  - CVE ids must match `^CVE-\d{4}-\d{4,}$`; GHSA ids must match `^GHSA(-[2-9cfghjmpqrvwx]{4}){3}$`.
  - Severity outside `low|medium|high|critical` becomes `unknown`.
  - Summary: control characters dropped, cut at 300 characters.
  - URLs: only `https://`, at most 2,048 characters, at most 5 per advisory.

- [ ] **Step 1: Write the failing tests.**
  - `identify` recognises each of three tiny fixtures and returns `None` for `{}`.
  - A retire.js fixture advisory has `info: ["javascript:alert(1)", "http://example.com/a", "https://example.com/b"]` and summary `"<img src=x onerror=alert(1)>\u{7}"`.
    - `urls == ["https://example.com/b"]`
    - `summary == Some("<img src=x onerror=alert(1)>")` (kept as text; display escapes it)
  - KEV drops `"CVE-1-2"` and keeps `"CVE-2020-11023"`.
  - `parse_epss` of a gzip whose unpacked size exceeds 128 MiB returns `Err`. Build it from zeros at test time.
  - Truncated JSON returns `Err`.
- [ ] **Step 2: Run the tests and confirm they fail.**
  - Command: `cargo test --release --lib vulndata::sources`
  - Expected: FAIL.
- [ ] **Step 3: Implement the parsers.** Read gzip through `flate2::read::GzDecoder` with `.take(limit + 1)`, as `src/templates/library.rs` does for archives.
- [ ] **Step 4: Run the tests and confirm they pass.**
  - Command: `cargo test --release --lib vulndata::sources`
  - Expected: PASS.
- [ ] **Step 5: Commit.**
  - Command: `git commit --only src/vulndata -m "Read retire.js, KEV and EPSS files as untrusted input"`

### Task 5: The index and the advisory list

**Files:**
- Create: `src/vulndata/index.rs`. Add `pub mod index;` to `mod.rs`.
- Test: the unit tests in `index.rs`.

**Interfaces:**
- Consumes: Tasks 2 to 4.
- Produces:
  - `pub struct Advisory { pub id: String, pub cves: Vec<String>, pub severity: String, pub summary: Option<String>, pub fixed_in: String, pub urls: Vec<String>, pub kev: bool, pub epss: Option<f32> }`
  - `pub struct Summary { pub count: usize, pub kev_count: usize, pub highest_severity: String }`
  - `pub struct VulnIndex { ..., pub revision: String }`
  - `VulnIndex::build(retire: Vec<RetireAdvisory>, kev: HashSet<String>, epss: HashMap<String, f32>, revision: String) -> Self`
  - `VulnIndex::advisories(&self, product_id: &str, version: &str) -> Vec<Advisory>`
  - `VulnIndex::summary(&self, product_id: &str, version: &str) -> Option<Summary>`, which is `None` when nothing matches.
- Rules:
  - `id` is the first CVE, else the GHSA id, else `retire:<component>:<below>`.
  - Rows from several components with the same `id` appear once.
  - `kev` is true when any of the advisory's CVEs is in KEV. `epss` is the highest EPSS of its CVEs.
  - Order: KEV first, then EPSS (highest first, none last), then severity (critical, high, medium, low, unknown), then `id`.

- [ ] **Step 1: Write the failing tests.** Use synthetic advisories:
  - jQuery `CVE-2020-11023`: `atOrAbove "1.0.3"`, `below "3.5.0"`, medium, in KEV, EPSS 0.94.
  - jQuery `CVE-2019-11358`: `below "3.4.0"`, medium.
  - React `CVE-2018-6341`: listed under both `react` and `react-dom` for 16.0.0.

  Assertions:
  - `advisories("jquery", "3.4.1")` has 1 row, `kev` true, `epss == Some(0.94)`.
  - `advisories("jquery", "3.3.1")` has 2 rows, the KEV one first.
  - `advisories("jquery", "3")` is empty.
  - `advisories("react", "16.0.0")` has 1 row.
  - `summary("jquery", "3.3.1") == Some(Summary { count: 2, kev_count: 1, highest_severity: "medium" })`.
- [ ] **Step 2: Run the tests and confirm they fail.**
  - Command: `cargo test --release --lib vulndata::index`
  - Expected: FAIL.
- [ ] **Step 3: Implement the index.** Key retire.js advisories by component, and resolve components with `products::retire_components`.
- [ ] **Step 4: Run the tests and confirm they pass.**
  - Command: `cargo test --release --lib vulndata::index`
  - Expected: PASS.
- [ ] **Step 5: Commit.**
  - Command: `git commit --only src/vulndata -m "Match library versions to advisories, exploited ones first"`

### Task 6: The store, fetching, import and the daily update

**Files:**
- Modify: `src/vulndata/mod.rs`.
- Modify: `src/state.rs`: add `pub vulndata: Arc<crate::vulndata::VulnData>` next to `templates` (`:99`), and load it in `AppState::new` (`:189`) with `VulnData::load(&config.data_dir)`.
- Modify: `src/lib.rs` (`run_with_config`, beside `run_daily_update` for templates) and `src/bin/sniper-desktop.rs` (beside the templates spawn). Spawn `crate::vulndata::run_daily_update(state.vulndata.clone())`.
- Test: the unit tests in `mod.rs`.

**Interfaces:**
- Consumes: Tasks 4 and 5.
- Produces:
  - `pub struct VulnData`
  - `VulnData::load(data_dir: &Path) -> Arc<Self>`. Files live under `<data_dir>/vulndata/`: `manifest.json`, `retire.json`, `kev.json`, `epss.csv.gz`.
  - `VulnData::index(&self) -> Option<Arc<VulnIndex>>`. It is `None` until all three sources have loaded once.
  - `VulnData::status(&self) -> VulnDataStatus`, serialized as `{ "auto_update": bool, "updating": bool, "revision": string|null, "sources": [{ "id", "url", "license", "verified": false, "fetched_at"?, "origin"? ("download"|"import"), "size"?, "sha256"?, "error"? }] }`.
  - `VulnData::set_auto_update(&self, enabled: bool) -> Result<()>`
  - `VulnData::import_blocking(&self, bytes: &[u8]) -> Result<SourceId>`
  - `VulnData::update_sources<F, Fut>(self: &Arc<Self>, fetch: F)` where `F: Fn(SourceId) -> Fut` and `Fut: Future<Output = Result<Vec<u8>>>`. It updates every due source and keeps per-source errors.
  - `VulnData::update_now(self: &Arc<Self>) -> bool`. It starts a background `update_sources` for every source with the real client, and returns false while one runs.
  - `VulnData::try_permit(&self) -> Option<OwnedSemaphorePermit>`, with 4 permits.
  - `pub async fn run_daily_update(data: Arc<VulnData>)`, at 60 s then every 3,600 s.
  - `fn due(record: &SourceRecord, auto_update: bool, now: DateTime<Utc>) -> bool`
- Client:
  - `reqwest`, rustls, connect timeout 10 s, total timeout 60 s.
  - Redirects only over HTTPS to the same host, at most 5.
  - The environment's proxy unless it targets loopback (`crate::state::release_proxy_env_targets_loopback()`).
  - User-Agent `Sniper/<version>`.
  - The body is streamed under the Task 4 limit.

- [ ] **Step 1: Write the failing tests.**
  - `due`:
    - never fetched → true;
    - success 23 h ago → false;
    - success 24 h ago → true;
    - last attempt failed → true;
    - `auto_update` false → false.
  - `update_sources` with a fake fetch:
    - Setup: KEV returns `Err`, the other two return fixtures.
    - Retire and EPSS have `fetched_at`; KEV has `error`.
    - `index()` stays `None` until KEV loads once. A second call where KEV succeeds yields `Some`.
  - A fake fetch returns oversized bytes for retire.js. The previous `retire.json` and index stay, and `error` is set.
  - `import_blocking(kev_fixture) == Ok(SourceId::Kev)`, and its record's `origin == "import"`.
  - `set_auto_update(false)` survives `VulnData::load` of the same directory.
  - A corrupt `manifest.json` is moved aside and the store starts empty, as `src/templates/library.rs:345-372` does.
- [ ] **Step 2: Run the tests and confirm they fail.**
  - Command: `cargo test --release --lib vulndata::tests`
  - Expected: FAIL.
- [ ] **Step 3: Implement the store, the client, the loop and the wiring.**
  - Write each file atomically, then the manifest.
  - Rebuild the index on `spawn_blocking` after any change.
  - `revision` is the first 12 hex characters of each source's SHA-256, joined with `-`.
- [ ] **Step 4: Run the tests and confirm they pass.**
  - Command: `cargo test --release --lib vulndata`
  - Expected: PASS.
- [ ] **Step 5: Commit.**
  - Command: `git commit --only src/vulndata src/state.rs src/lib.rs src/bin/sniper-desktop.rs -m "Fetch retire.js, KEV and EPSS once a day"`

### Task 7: API, CLI and documentation

**Files:**
- Modify: `src/vulndata/mod.rs`, to add the handlers.
- Modify: `src/api.rs`, to add the routes next to `/api/templates/library*` (`:371-392`).
- Modify: `src/bin/sniper-cli.rs`, to add a `Vulndata` command family. Follow the `TemplatesLibraryCommand` pattern: the enum, `operation_name`, input preview, `api_preview`, the `op(...)` manifest entry, the input schema, allowed keys, dry-run notes, `command_from_operation_input` and the handler.
- Create: `docs/integrations/known-vulnerabilities.md`.
- Modify: `README.md` (a short section after "Nuclei templates"), and both `packaging/skills/{claude,codex}/sniper-operator/SKILL.md`, with the same text in each.

**Interfaces:**

| Route | Behaviour | CLI operation |
| --- | --- | --- |
| `GET /api/vulndata` | Status | `vulndata.status`, `vulndata status`, Read |
| `POST /api/vulndata/update` | 202 with status; 409 while updating | `vulndata.update`, `vulndata update`, Write, needs confirmation; the note names the three hosts |
| `POST /api/vulndata/import` | Body is the file, at most 16 MiB; 200 `{ "source": id, "status": … }`; 400 when not identified | `vulndata.import`, `vulndata import --file <path>`, Write, needs confirmation |
| `POST /api/vulndata/auto-update` | Body `{"enabled": bool}`; returns the status | `vulndata.set_auto_update`, `vulndata auto-update --enabled <true\|false>`, Write, needs confirmation |
| `GET /api/vulndata/lookup?product=<id>&version=<v>` | `{ "product", "version", "advisories": [Advisory] }`; 409 with no index | `vulndata.lookup`, `vulndata lookup --product <id> --version <v>`, Read |

- [ ] **Step 1: Write the failing CLI test, modeled on `the_daily_template_update_switch_names_its_value`.**
  - `vulndata.set_auto_update` without `enabled` is `Err`.
  - `{"enabled": false}` previews `POST /api/vulndata/auto-update` with body `{"enabled": false}` and needs confirmation.
  - `vulndata.lookup` without `version` is `Err`.
  - `Cli::try_parse_from(["sniper-cli", "vulndata", "lookup", "--product", "jquery", "--version", "3.4.1"])` is `Ok`.
- [ ] **Step 2: Run the test and confirm it fails.**
  - Command: `cargo test --release --bin sniper-cli vulndata`
  - Expected: FAIL with "unknown operation".
- [ ] **Step 3: Implement the routes, the CLI and the docs.** The docs list the three hosts Sniper contacts, the update rules, the terms and the API table.
- [ ] **Step 4: Run the tests and confirm they pass.**
  - Command: `cargo test --release --bin sniper-cli vulndata`, then `cargo test --release --test cli_discovery_schema_contract`.
  - Expected: PASS.
- [ ] **Step 5: Commit.**
  - Command: `git commit --only src/vulndata src/api.rs src/bin/sniper-cli.rs docs/integrations/known-vulnerabilities.md README.md packaging/skills -m "Expose vulnerability data in the API and the CLI"`

### Task 8: Findings for library versions

**Files:**
- Create: `src/vulndata/findings.rs`. Add `pub mod findings;` to `mod.rs`.
- Modify `src/scanner.rs`:
  - Add `("known_cve", "Known Vulnerabilities")` to `BUILTIN_RULES` (`:23`).
  - Add `known: Option<Arc<VulnIndex>>` to `Rescan` (`:552`), with `pub fn with_known_vulnerabilities(self, index: Option<Arc<VulnIndex>>) -> Self`.
  - In `Rescan::scan` (`:584`), run `findings::for_record` when `self.config.is_rule_enabled("known_cve")`.
- Modify `src/proxy.rs` `scan_record_for_session` (`:3906`): add `known_vulnerability_findings(&state.vulndata, &config, record)`, modeled on `passive_template_findings` (`:3941`). It takes `try_permit()` and runs on `spawn_blocking`. Without a permit it returns nothing.
- Modify `src/api.rs`:
  - `rescan_findings` (`:4810`) passes `state.vulndata.index()`.
  - `get_finding` (`:4734`) replaces `detail` with `findings::detail(...)` for `rule_id`s that start with `findings::RULE_PREFIX`.
- Test: the unit tests in `findings.rs` and a `Rescan` test in `scanner.rs`.

**Interfaces:**
- Consumes: `VulnIndex` (Task 5) and `service_map_libraries::detect_url` and `detect`.
- Produces:
  - `pub const RULE_PREFIX: &str = "known-cve:";`
  - `pub const CATEGORY: &str = "known_cve";`
  - `pub fn for_record(index: &VulnIndex, record: &TransactionRecord) -> Vec<ScannerFinding>`. It covers the libraries the record's URL and body name, within `service_map_libraries::MAX_ROW_BYTES`, that have at least one advisory.
  - `pub fn detail(index: Option<&VulnIndex>, finding: &ScannerFinding) -> String`
- Host and path come from the record's `Referer` when it is an `http(s)` URL; otherwise they come from the record.
- The stored `detail` is the caveat sentence only.
- `detail` text:
  - Line 1: `Tentative: matched on the version string alone (<name> <version>). Confirm before reporting.`
  - Then one block per advisory: `<id> · <severity>[ · KEV][ · EPSS <0.00>][ · fixed in <below>]`, then the summary, then the links.
  - The last line names the data and terms: `Data: retire.js (Apache-2.0), CISA KEV (CC0), FIRST EPSS (https://www.first.org/epss); fetched <date>.`
  - Without an index, the line after the caveat is `Vulnerability data has not been fetched yet.`

- [ ] **Step 1: Write the failing tests.** Use the Task 5 fixtures.
  - Setup: a script record `GET https://cdn.example.com/npm/jquery@3.4.1/dist/jquery.min.js` with `Referer: https://app.example.com/shop`.
  - It yields one finding:
    - host `app.example.com`, path `/shop`;
    - evidence `jquery@3.4.1`, title `Known vulnerabilities: jQuery 3.4.1`;
    - `Severity::Info`, category `known_cve`, `rule_id` `known-cve:jquery`.
  - The same URL with `jquery@3` yields nothing.
  - Without a `Referer`, the host is `cdn.example.com`.
  - `detail` names `CVE-2020-11023` and `KEV`. After the index is rebuilt with one more matching advisory, the same stored finding's `detail` names both.
  - `rescan_keeps_one_known_vulnerability_finding_per_page_library` in `scanner.rs`: a `Rescan` over two records loading the same library on one page yields one `known_cve` finding. With the `known_cve` rule off, it yields none.
- [ ] **Step 2: Run the tests and confirm they fail.**
  - Command: `cargo test --release --lib -- vulndata::findings known_vulnerability_finding`
  - Expected: FAIL.
- [ ] **Step 3: Implement the module and the three call sites.** Leave `recover_missing_scanner_findings` (`src/session.rs:1705`) untouched. It has no app state, and Rescan covers it.
- [ ] **Step 4: Run the full library suite.**
  - Command: `cargo test --release --lib`
  - Expected: PASS.
- [ ] **Step 5: Commit.**
  - Command: `git commit --only src/vulndata src/scanner.rs src/proxy.rs src/api.rs -m "Raise one finding per page and library version with known advisories"`

### Task 9: The Service Map badge

**Files:**
- Modify `src/service_map.rs`:
  - Add `pub struct KnownVulnerabilities { pub product_id: String, pub name: String, pub version: String, pub count: usize, pub kev_count: usize, pub highest_severity: String }`.
  - Add `ServiceOrigin.known_vulnerabilities: Vec<KnownVulnerabilities>` with `#[serde(default, skip_serializing_if = "Vec::is_empty")]`.
- Modify `src/vulndata/mod.rs`: add `pub fn annotate(map: &mut crate::service_map::ServiceMap, index: &VulnIndex)`. It fills the field from each origin's `front_technologies` that has a version.
- Modify `src/api.rs` `get_target_service_map_impl` (`:5772`):
  - Read `state.vulndata.index()` before the worker.
  - Call `annotate` before both `serde_json::to_vec(&map)`.
  - Append `index.revision` to `cache_key`.
- Modify `src/bin/sniper-cli.rs`: add `origin["properties"]["known_vulnerabilities"]` beside `front_technologies` (`:5740`), an array of the struct above with `maxItems` 32.
- Modify `web/service-map.js`:
  - The normalizer (`:1125-1137`) validates and keeps `known_vulnerabilities`, using the same id and version patterns as `front_technologies`.
  - `reportedProducts` (`:345`) attaches it by product id and version.
  - The card chip and the inspector's Front-end list show a badge.
- Modify: `web/styles.css`.
- Test: a Rust unit test for `annotate`; `tests/service-map-known-vulnerabilities.test.cjs`.

**Interfaces:**
- Consumes: `VulnIndex::summary` (Task 5).
- Produces:
  - Badge text: `<count> advisor{y|ies}`, plus a `KEV` chip when `kev_count > 0`.
  - Tooltip: `<count> known advisories for <name> <version>, <kev_count> exploited (CISA KEV). Tentative: version match only.` Write it to `title`; it is never parsed as HTML.

- [ ] **Step 1: Write the failing tests.**
  - Rust, `annotate_counts_advisories_for_front_end_versions`: `annotate` on a map whose origin has front technology `jquery` `3.3.1` gives `count == 2` and `kev_count == 1`.
  - Node:
    - the normalizer keeps a valid entry;
    - it drops one with `product_id: "<x>"`;
    - the card renders `2 advisories` and `KEV` for it;
    - a `name` of `<img src=x onerror=alert(1)>` appears escaped.
- [ ] **Step 2: Run the tests and confirm they fail.**
  - Command: `cargo test --release --lib vulndata::tests::annotate`, then `node --test tests/service-map-known-vulnerabilities.test.cjs`.
  - Expected: FAIL.
- [ ] **Step 3: Implement the field, `annotate`, the cache key, the CLI schema and the UI.**
- [ ] **Step 4: Run the tests and confirm they pass.**
  - Command: the two commands above, then `cargo test --release --test cli_discovery_schema_contract` and `node --test "tests/*.test.cjs"`.
  - Expected: PASS.
- [ ] **Step 5: Commit.**
  - Command: `git commit --only src/service_map.rs src/vulndata src/api.rs src/bin/sniper-cli.rs web/service-map.js web/styles.css tests/service-map-known-vulnerabilities.test.cjs -m "Badge library versions with known advisories in the Service Map"`

### Task 10: Settings ▸ Runtime, runtime check and deploy

**Files:**
- Modify `web/index.html`: add a **Vulnerability data** `filter-group` section in the Runtime panel, after "Command line" (`:1954`).
- Modify `web/app.js`:
  - Render it from `GET /api/vulndata`.
  - Wire the switch to `POST /api/vulndata/auto-update`.
  - Put **Update now** (`POST /api/vulndata/update`) and **Import…** (a multiple file input, one `POST /api/vulndata/import` per file) in a ⋯ menu.
- Modify: `web/styles.css`.
- Test: `tests/vulndata-settings.test.cjs`.

**Interfaces:**
- Consumes the Task 7 routes.
- Each row shows the source name, `fetched <date>`, `imported` when imported, the terms, and `not verified (TLS only)`.
- A source with an `error` shows `Last update failed` with the error in `title`, and no dialog.
- Once `revision` is set, a help line says: `Traffic captured before the data arrived needs a Findings Rescan.`

- [ ] **Step 1: Write the failing test.**
  - A status with one failed source renders `Last update failed`.
  - The switch posts `{"enabled": false}`.
  - Two files chosen in Import make two POSTs.
- [ ] **Step 2: Run the test and confirm it fails.**
  - Command: `node --test tests/vulndata-settings.test.cjs`
  - Expected: FAIL.
- [ ] **Step 3: Implement the section.**
- [ ] **Step 4: Run every suite.**
  - Command: `cargo fmt`, then `cargo test --release --no-fail-fast`, then `node --test "tests/*.test.cjs"`.
  - Expected: all pass, and `sniper-desktop` still has 37 warnings.
- [ ] **Step 5: Run the runtime check (`AGENTS.md` §3).**
  1. Start an isolated headless `sniper`. Before starting it, write a `vulndata/manifest.json` with `"auto_update": false`, so the check contacts no data host.
  2. Import the three synthetic fixtures through `POST /api/vulndata/import`.
  3. Run a loopback Python upstream that serves `/npm/jquery@3.4.1/dist/jquery.min.js`. Send the script request through the proxy with `Referer: http://127.0.0.1:<page port>/shop`.
  4. Poll `GET /api/findings` until the `known-cve:jquery` finding appears with host `127.0.0.1`.
  5. Expect `GET /api/findings/<id>` to name `CVE-2020-11023`.
  6. Expect the Service Map origin to carry `known_vulnerabilities`.
  7. Restart, and expect the finding and the switch to persist.
  8. Check the badge and the Settings section in the browser pane.
- [ ] **Step 6: Commit, build the app bundle and deploy.**
  - Command: `git commit --only web/index.html web/app.js web/styles.css tests/vulndata-settings.test.cjs -m "Show vulnerability data and its daily update in Settings"`
  - Then run `./packaging/macos/make-app.sh` and copy the bundle with `ditto` into `~/Desktop/Sniper.app`.
