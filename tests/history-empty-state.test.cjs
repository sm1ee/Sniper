// Synthetic paging and filter fixtures only: no app startup, capture, or network.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const http = { id: "http", method: "GET", host: "http.example.com", path: "/", scheme: "https", status: 200, has_response: true };
const tunnel = { id: "tunnel", method: "CONNECT", host: "tunnel.example.com:443", path: "tunnel.example.com:443", scheme: "https", status: 200, has_response: true };

function fixture(rows = [http, tunnel], query = "") {
  const state = { query, method: "", items: [], historyListError: "", historyColumnOrder: ["method"], sortKey: "index", sortDirection: "desc" };
  const els = { historyMeta: {}, historyTableBody: {} };
  let visibleRows = [], browserLaunchers = 0;
  const c = loadFunctions([
    "createDefaultFilterSettings", "summaryMatchesActiveHistoryFilters", "summaryMatchesStatusFilter",
    "summaryMatchesMimeFilter", "summaryMatchesHiddenExtensions", "summaryMatchesPortFilter",
    "summaryMatchesColorTags", "summaryMatchesAdvancedSearch", "summaryQuickSearchHaystack",
    "selectedStatusClasses", "selectedMimeTypes", "inferMimeType", "extractSummaryPathExtension",
    "formatSize", "effectiveSummaryPort", "defaultSummaryPortForScheme", "extractHostPort",
    "foldHeaderSearchText", "isKnownCount", "countHiddenConnectItems", "renderHistory",
    "humanizeSortKey", "isSessionEmpty", "emptySessionMessage", "historyEmptyMessage", "escapeHtml",
    "createHistoryQueryState", "historyQuerySignature", "isCurrentHistoryQuerySignature",
  ], {
    state, els, formatTimestamp: () => "", isInScopeHost: () => true,
    currentSessionId: () => "fixture-session",
    getVisibleEntries: () => state.items.filter(row => c.summaryMatchesActiveHistoryFilters(row)).map(item => ({ item })),
    renderSortHeaders() {},
    renderHistoryVirtual() { visibleRows = state._historyEntries.map(entry => entry.item.id); },
    mountBrowserLaunchers() { browserLaunchers++; },
    scheduleHistoryBackfill() {},
  });
  state.filterSettings = c.createDefaultFilterSettings();
  // The API's total covers the session; hidden CONNECT counts apply all filters
  // except hide_connect (store.rs list_page), not every tunnel in the session.
  state.items = rows.filter(row => c.summaryMatchesActiveHistoryFilters(row));
  state.historyPaging = {
    querySignature: c.historyQuerySignature(),
    total: rows.length, filteredTotal: state.items.length,
    hiddenConnectTotal: rows.filter(row => row.method === "CONNECT" && c.summaryMatchesActiveHistoryFilters(row, { includeConnect: true })).length,
    fullyLoaded: true, loading: false, hasMore: false,
  };
  return {
    c, state, els,
    render() { c.renderHistory(); return els.historyTableBody.innerHTML || ""; },
    message(hidden = c.countHiddenConnectItems()) { return c.historyEmptyMessage(hidden, state.historyPaging); },
    get visibleRows() { return visibleRows; },
    get browserLaunchers() { return browserLaunchers; },
  };
}

test("a tunnel-only search in a mixed session explains the filter, not CA trust", () => {
  const f = fixture([http, tunnel], "tunnel.example.com");
  assert.deepEqual(f.state.historyPaging, { querySignature: f.c.historyQuerySignature(), total: 2, filteredTotal: 0, hiddenConnectTotal: 1, fullyLoaded: true, loading: false, hasMore: false });
  const html = f.render();
  assert.match(html, /No HTTP traffic matches the current filter settings/);
  assert.match(html, /CONNECT tunnels are hidden/);
  assert.doesNotMatch(html, /Only CONNECT|Root CA|data-browser-launcher/);
});

test("the same mixed session without a filter still displays its captured HTTP row", () => {
  const f = fixture();
  assert.equal(f.state.historyPaging.total, 2);
  assert.equal(f.state.historyPaging.filteredTotal, 1);
  assert.equal(f.state.historyPaging.hiddenConnectTotal, 1);
  assert.equal(f.render(), "");
  assert.deepEqual(Array.from(f.visibleRows), ["http"]);
  assert.equal(f.browserLaunchers, 0);
});

test("exact complete counts allow a conditional CA hint for an entirely tunnel-only session", () => {
  const f = fixture([tunnel]);
  const html = f.render();
  assert.match(html, /Only CONNECT tunnels are retained in this session/);
  assert.match(html, /If you expected decrypted HTTPS traffic/);
  assert.match(html, /Sniper Root CA/);
  assert.doesNotMatch(html, /data-browser-launcher/);
});

for (const [name, overrides, loading] of [
  ["partial", { fullyLoaded: false }, false],
  ["loading", { fullyLoaded: false, loading: true }, true],
  ["loading with previously complete counts", { loading: true }, true],
  ["inconsistent has-more flag", { hasMore: true }, false],
]) {
  test(`${name} paging keeps progress ahead of tunnel-only advice`, () => {
    const f = fixture([tunnel]);
    Object.assign(f.state.historyPaging, overrides);
    assert.equal(f.message(), loading
      ? "No loaded traffic matches yet. Older history is still loading."
      : "No loaded traffic matches yet. Older history will load as needed.");
  });
}

for (const [name, overrides, hidden] of [
  ["unknown exact tunnel count", { hiddenConnectTotal: null }, 1],
  ["unknown filtered count", { filteredTotal: null }, 1],
  ["unknown retained count", { total: null }, 1],
  ["negative retained count", { total: -1 }, 1],
  ["missing query ownership", { querySignature: "" }, 1],
  ["more tunnels than retained rows", { total: 1, hiddenConnectTotal: 2 }, 2],
  ["nonempty filtered HTTP count", { filteredTotal: 1 }, 1],
  ["count argument inconsistent with exact count", {}, 2],
  ["fractional counts", { total: 1.5, hiddenConnectTotal: 1.5 }, 1.5],
  ["unsafe integer counts", { total: Number.MAX_SAFE_INTEGER + 1, hiddenConnectTotal: Number.MAX_SAFE_INTEGER + 1 }, Number.MAX_SAFE_INTEGER + 1],
  ["nonfinite counts", { total: Infinity, hiddenConnectTotal: Infinity }, Infinity],
  ["zero retained but positive hidden count", { total: 0 }, 1],
]) {
  test(`${name} never diagnoses the whole session or calls a fallback count matching`, () => {
    const f = fixture([tunnel]);
    Object.assign(f.state.historyPaging, overrides);
    const message = f.message(hidden);
    assert.match(message, /No HTTP traffic matches the current filter settings/);
    assert.match(message, /CONNECT tunnels are hidden/);
    assert.doesNotMatch(message, /Only CONNECT|Root CA|[Mm]atching CONNECT/);
  });
}

test("counts from a previous query cannot justify a current tunnel-only diagnosis", () => {
  const f = fixture([tunnel]);
  f.state.query = "different-filter";
  assert.doesNotMatch(f.render(), /Only CONNECT|Root CA/);
});

test("a loaded CONNECT fallback is not exact evidence about the whole session", () => {
  const f = fixture([tunnel]);
  f.state.historyPaging.hiddenConnectTotal = null;
  f.state._connectCount = 1;
  assert.equal(f.c.countHiddenConnectItems(), 1);
  assert.doesNotMatch(f.render(), /Only CONNECT|Root CA|[Mm]atching CONNECT/);
});

test("zero retained traffic keeps the capture onboarding message", () => {
  const f = fixture([]);
  const html = f.render();
  assert.match(html, /Nothing captured yet/);
  assert.match(html, /data-browser-launcher/);
  assert.doesNotMatch(html, /Only CONNECT|Root CA/);
});

test("filter errors take precedence over complete and loading tunnel-only states", () => {
  for (const loading of [false, true]) {
    const f = fixture([tunnel]);
    f.state.historyListError = "Synthetic filter error";
    f.state.historyPaging.loading = loading;
    f.state.historyPaging.fullyLoaded = !loading;
    assert.equal(f.message(), "HTTP History filter error: Synthetic filter error");
  }
});

test("an ordinary no-match without hidden tunnels retains its filter explanation", () => {
  const f = fixture([http], "absent");
  assert.equal(f.message(), "No traffic matches the current filter settings.");
  assert.doesNotMatch(f.render(), /Root CA|data-browser-launcher/);
});
