// The Session screen as a dashboard: what each session holds and what was
// done in it, so a session is known without opening it. Synthetic data only.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const overview = (extra = {}) => ({
  scope: [], scope_count: 0, excluded_scope: [], excluded_scope_count: 0, top_hosts: [],
  last_captured_at: null, marked_requests: 0, pinned_replays: [], pinned_replay_count: 0,
  replace_rules: [], replace_rule_count: 0, activity: [], activity_count: 0,
  findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, ...extra,
});
const sessions = [
  {
    id: "s-1", name: "Checkout review", active: true, request_count: 120, websocket_count: 2,
    storage_bytes: 3 * 1024 * 1024, created_at: "2026-10-20T10:00:00Z", storage_path: "/data/s-1",
    overview: overview({
      scope: ["*.example.com", "api.example.net", "pay.example.org"], scope_count: 3,
      excluded_scope: ["static.example.com"], excluded_scope_count: 1,
      top_hosts: [{ host: "api.example.com", requests: 80 }, { host: "www.example.com", requests: 40 }],
      last_captured_at: "2026-10-23T08:30:00Z", marked_requests: 4,
      pinned_replays: ["Login bypass"], pinned_replay_count: 1,
      replace_rules: ["Strip CSP"], replace_rule_count: 1,
      activity: [{ kind: "manual scan", target: "https://app.example.com", started_at: "2026-10-22T12:00:00Z", status: "completed", matched: 2 }],
      activity_count: 1,
      findings: { critical: 0, high: 1, medium: 2, low: 5, info: 0 },
    }),
  },
  {
    id: "s-2", name: "Old run", active: false, request_count: 10, websocket_count: 0,
    storage_bytes: 1024 * 1024, created_at: "2026-10-01T10:00:00Z", storage_path: "/data/s-2",
    overview: overview({ top_hosts: [{ host: "legacy.example.com", requests: 10 }], last_captured_at: "2026-10-02T08:00:00Z" }),
  },
];

function render(selectedSessionId = "s-1", list = sessions) {
  const state = { sessions: list, activeSession: list[0] || null, selectedSessionId };
  const els = new Proxy({}, { get: (object, key) => object[key] ||= { querySelectorAll: () => [] } });
  const c = loadFunctions(["renderDashboard", "sessionFindingCount", "formatSize", "formatSize"], {
    state, els, document: { getElementById: () => null }, getSortedSessions: () => list,
    formatCappedCount: (value) => String(value ?? 0), retainedTransactionsCap() {}, retainedEntriesCap() {},
    formatTimestamp: (value) => `T(${value})`, escapeHtml: (value) => String(value),
  });
  c.renderDashboard();
  return els;
}

test("the tiles add up every session: disk, requests, findings by severity, and the last capture", () => {
  const tiles = render().dashboardTiles.innerHTML;
  assert.match(tiles, /4\.0 MB/);
  assert.match(tiles, />130</);
  assert.match(tiles, />8</);
  assert.match(tiles, /1 high · 2 medium · 5 low/);
  assert.match(tiles, /T\(2026-10-23T08:30:00Z\)/);
  assert.match(tiles, /Checkout review/);
});

test("a row names a session by its scope, or by its hosts without one, with its size and findings", () => {
  const [first, second] = render().dashboardSessionsBody.innerHTML.split("</tr>");
  assert.match(first, /\*\.example\.com, api\.example\.net \+1/);
  assert.match(first, /3\.0 MB/);
  assert.match(first, /<td class="dashboard-findings[^"]*">8<\/td>/);
  assert.match(first, /T\(2026-10-23T08:30:00Z\)/);
  assert.match(second, /legacy\.example\.com/);
  assert.match(second, /<td class="dashboard-findings[^"]*">0<\/td>/);
});

test("the selected session's detail says what was done in it, and leaves out what is empty", () => {
  const detail = render().dashboardDetail.innerHTML;
  for (const text of ["\\*\\.example\\.com", "static\\.example\\.com", "api\\.example\\.com", "4 marked",
    "Login bypass", "Strip CSP", "Manual scan", "2 matched"]) {
    assert.match(detail, new RegExp(text), text);
  }
  const other = render("s-2").dashboardDetail.innerHTML;
  assert.match(other, /legacy\.example\.com/);
  for (const absent of ["Scope", "Pinned", "Replace", "Scans", "Findings"]) {
    assert.doesNotMatch(other, new RegExp(`<h4>${absent}`), absent);
  }
});

test("with no sessions the tiles and the detail are empty", () => {
  const els = render(null, []);
  assert.equal(els.dashboardTiles.innerHTML, "");
  assert.equal(els.dashboardDetail.innerHTML, "");
});
