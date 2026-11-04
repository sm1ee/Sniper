// The Service Map named a library's version and nothing known about it; the
// vulnerability data now gives each version an advisory count and a KEV mark.
const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const source = fs.readFileSync(path.join(__dirname, "../web/service-map.js"), "utf8");
const context = vm.createContext({ URL, URLSearchParams, AbortController, console });
vm.runInContext(source, context);
const map = context.SniperServiceMap;

const entry = { product_id: "jquery", name: "jQuery", version: "3.3.1", count: 2, kev_count: 1, highest_severity: "medium" };
const origin = (known) => ({
  origin: "https://app.example.com", in_scope: true, request_count: 2, endpoints: [], technology_clues: [], redirects: [], header_links: [],
  front_technologies: [{ product_id: "jquery", name: "jQuery", category: "library", version: "3.3.1", source_origin: "https://cdn.example.com", row_count: 1, evidence: ["e1"] }],
  known_vulnerabilities: known,
});
const snapshot = (origins) => ({
  schema_version: 1, session_id: "session-one",
  snapshot: { generation: "generation-one", complete: true, stopped_by: [], limits: { records: 10 }, considered_rows: 1, retained_rows: 1, included_rows: 1, excluded_rows: 0, omitted_rows: 0, oldest_considered_at: "2026-11-04T00:00:00Z", latest_considered_at: "2026-11-04T00:00:00Z" },
  origins, unavailable: [], deferred: [], warnings: [],
});
const plain = (value) => JSON.parse(JSON.stringify(value));

test("the map keeps a valid known-vulnerability entry and drops a malformed one", () => {
  const normalized = map.normalizeSnapshot(snapshot([origin([entry, { ...entry, product_id: "<x>" }])]), "session-one");
  assert.deepEqual(plain(normalized.origins[0].known_vulnerabilities), [entry]);
});

test("a product's card chip counts its advisories and marks KEV", () => {
  const normalized = map.normalizeSnapshot(snapshot([origin([entry])]), "session-one");
  const markup = map.productSummaryMarkup(normalized.origins[0]);
  assert.match(markup, />2 advisories</);
  assert.match(markup, />KEV</);
  assert.match(markup, /2 known advisories for jQuery 3\.3\.1, 1 exploited \(CISA KEV\)\. Tentative: version match only\./);
});

test("a name in the data is escaped, never markup", () => {
  const markup = map.productSummaryMarkup(origin([{ ...entry, name: "<img src=x onerror=alert(1)>" }]));
  assert.doesNotMatch(markup, /<img/);
  assert.match(markup, /&lt;img src=x onerror=alert\(1\)&gt;/);
});
