// Local Findings filtering only. Extract the real input handler and render
// helpers, with synthetic saved metadata and inert timers; never boot the app.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const emptyMessage = "No findings yet. Browse with the proxy to start scanning.";
const filteredMessage = "No findings match your filters.";
const row = (id, title) => Object.freeze({
  id, record_id: `record-${id}`, severity: "info", category: "header", title,
  host: "example.com", path: "/saved", found_at: "2026-10-11T00:00:00Z",
});

function fixture(data = [row("alpha", "Alpha saved entry"), row("beta", "Beta saved entry")]) {
  const rows = Object.freeze(data);
  const timers = new Map(), handlers = new Map();
  let nextTimer = 0, paints = 0, tablePaints = 0;
  const badgeClasses = new Set();
  const shell = { clientHeight: 300, scrollTop: 0 };
  const table = { tHead: { getBoundingClientRect: () => ({ height: 29 }) } };
  const body = {
    innerHTML: "", querySelector: () => null,
    closest: selector => selector === "table" ? table : shell,
  };
  const els = {
    findingsBody: body,
    findingsFilterSeverity: { value: "" },
    findingsFilterCategory: { value: "", options: [{ value: "", dataset: {} }, { value: "header", dataset: {} }] },
    findingsFilterSearch: { value: "", addEventListener: (name, handler) => handlers.set(name, handler) },
    findingsInScopeOnly: { checked: false },
    findingsBadge: { textContent: "", title: "", classList: {
      toggle(name, enabled) { if (enabled) badgeClasses.add(name); else badgeClasses.delete(name); },
    } },
  };
  const state = { activeSession: { id: "session-a" }, _findingsEntries: [] };
  const forbidden = action => () => assert.fail(`Unexpected ${action}`);
  const clearTimeout = id => timers.delete(id);
  const c = loadFunctions([
    "getFilteredFindings", "renderFindings", "updateCategoryFilter", "ensureFindingsCategoryOption",
    "renderFindingsVirtual", "getFindingsRowHeight", "measuredRowPitch", "severityClass", "severityLabel", "escapeHtml",
    "resetFindingsUiState", "clearFindingDetail", "setFindingDetailActionsEnabled", "resetFindingsSearchUi",
    "updateFindingsBadge", "formatCappedCount", "retainedEntriesCap",
  ], {
    state, els, findingsData: rows, selectedFindingId: null, findingsDetailGeneration: 0,
    findingsStateGeneration: 0, findingsLoadGeneration: 0, findingsBadgeCount: rows.length,
    findingsLoadPromise: null, findingsLoadSessionId: null, lastFindingsBadgePollAt: 0,
    findingsBadgeRefreshTimer: 0, findingsListRefreshTimer: 0,
    findingsSortKey: "severity", findingsSortDir: "asc",
    SEVERITY_ORDER: { critical: 0, high: 1, medium: 2, low: 3, info: 4 },
    BUILTIN_FINDING_CATEGORIES: new Set(["header"]), BUILTIN_RULE_LABELS: { header: "Headers" },
    FINDINGS_ROW_HEIGHT: 30, FINDINGS_BUFFER_ROWS: 5, measuredFindingsRowHeight: 30,
    isInScopeHost: host => host === "example.com", formatTimestamp: value => value,
    document: { getElementById: () => null, createElement: forbidden("DOM element creation") },
    getCMView: () => null,
    fetch: forbidden("API call"), loadFindingDetail: forbidden("detail read"),
    window: { clearTimeout }, clearTimeout,
    setTimeout(callback, delay) {
      assert.equal(delay, 200);
      const id = ++nextTimer;
      timers.set(id, callback);
      return id;
    },
  });
  // Bind only the production search input callback, without action controls.
  const start = appSource.indexOf("  if (els.findingsFilterSearch) {", appSource.indexOf("function bindFindingsEvents()"));
  const end = appSource.indexOf("  if (els.findingsInScopeOnly) {", start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(appSource.slice(start, end), c);
  const render = c.renderFindings;
  c.renderFindings = () => { paints++; return render(); };
  const renderTable = c.renderFindingsVirtual;
  c.renderFindingsVirtual = () => { tablePaints++; return renderTable(); };
  c.renderFindings();
  c.updateFindingsBadge();
  return {
    c, els, state, body, rows, timers, badgeClasses, paints: () => paints, tablePaints: () => tablePaints,
    input(value) { els.findingsFilterSearch.value = value; handlers.get("input")(); },
    flush() { for (const [id, callback] of [...timers]) { timers.delete(id); callback(); } },
    ids: () => Array.from(state._findingsEntries, item => item.id),
    assertMessage(message) {
      assert.equal(body.innerHTML, `<tr class="empty-row"><td colspan="6">${message}</td></tr>`);
    },
  };
}

for (const query of ["does-not-match", "別の項目🔎"]) {
  test(`unmatched local Findings search distinguishes filtered results from no saved findings: ${query}`, () => {
    const f = fixture();
    const original = JSON.stringify(f.rows);
    f.input(query);
    f.flush();
    assert.deepEqual(f.ids(), []);
    f.assertMessage(filteredMessage);
    assert.equal(f.c.findingsData, f.rows);
    assert.equal(JSON.stringify(f.rows), original);
    assert.equal(f.els.findingsFilterSearch.value, query);
    assert.equal(f.c.findingsBadgeCount, 2);
    assert.equal(f.els.findingsBadge.textContent, "2");
    assert.equal(f.badgeClasses.has("hidden"), false);
    assert.equal(f.tablePaints(), 1, "empty filtered results do not render table rows");
  });
}

test("clearing an applied unmatched search restores the saved Findings rows", () => {
  const f = fixture();
  f.input("does-not-match"); f.flush();
  f.assertMessage(filteredMessage);
  f.input(""); f.flush();
  assert.deepEqual(f.ids(), ["alpha", "beta"]);
  assert.match(f.body.innerHTML, /data-finding-id="alpha"/);
  assert.match(f.body.innerHTML, /data-finding-id="beta"/);
  assert.doesNotMatch(f.body.innerHTML, /No findings/);
  assert.equal(f.tablePaints(), 2, "clearing the filter renders the saved table again");
  assert.equal(f.c.findingsBadgeCount, 2);
  assert.equal(f.els.findingsBadge.textContent, "2");
});

test("rapid search edits retain the existing debounce and use the latest field text", () => {
  const f = fixture();
  f.input("alpha"); f.input("  BETA  ");
  assert.equal(f.paints(), 1);
  assert.equal(f.timers.size, 1);
  f.flush();
  assert.equal(f.paints(), 2);
  assert.deepEqual(f.ids(), ["beta"]);
  assert.equal(f.els.findingsFilterSearch.value, "  BETA  ");
});

test("clearing a pending unmatched search cancels its debounce without hiding saved rows", () => {
  const f = fixture();
  f.input("does-not-match"); f.input("");
  assert.equal(f.timers.size, 1);
  f.flush();
  assert.deepEqual(f.ids(), ["alpha", "beta"]);
  assert.equal(f.paints(), 2);
  assert.equal(f.timers.size, 0);
  f.flush();
  assert.equal(f.paints(), 2);
});

test("a whitespace-only clear preserves existing local filter controls and saved metadata", () => {
  const f = fixture();
  const original = JSON.stringify(f.rows);
  f.els.findingsFilterCategory.value = "header";
  f.els.findingsFilterSeverity.value = "info";
  f.els.findingsInScopeOnly.checked = true;
  f.input("alpha"); f.flush();
  f.input(" \t "); f.flush();
  assert.deepEqual(f.ids(), ["alpha", "beta"]);
  assert.equal(f.els.findingsFilterCategory.value, "header");
  assert.equal(f.els.findingsFilterSeverity.value, "info");
  assert.equal(f.els.findingsInScopeOnly.checked, true);
  assert.equal(JSON.stringify(f.rows), original);
});

for (const query of ["", "does-not-match"]) {
  test(`genuinely empty Findings retain the existing empty message with query ${JSON.stringify(query)}`, () => {
    const f = fixture([]);
    f.assertMessage(emptyMessage);
    f.input(query); f.flush();
    f.assertMessage(emptyMessage);
    assert.deepEqual(f.ids(), []);
  });
}

for (const pending of [false, true]) {
  test(`session reset uses the genuinely empty message with ${pending ? "pending" : "applied"} unmatched search`, () => {
    const f = fixture();
    f.input("does-not-match");
    if (!pending) { f.flush(); f.assertMessage(filteredMessage); }
    f.state.activeSession = { id: "session-b" };
    f.c.resetFindingsUiState();
    f.assertMessage(emptyMessage);
    assert.deepEqual(f.ids(), []);
    assert.equal(f.c.findingsData.length, 0);
    assert.equal(f.els.findingsFilterSearch.value, "does-not-match");
    assert.equal(f.c.findingsBadgeCount, 0);
    assert.equal(f.els.findingsBadge.textContent, "");
    assert.equal(f.badgeClasses.has("hidden"), true);
    f.flush();
    f.assertMessage(emptyMessage);
    assert.deepEqual(f.ids(), []);
  });
}
