// Passive synthetic history summaries only: no app startup, capture, or network.
const assert = require("node:assert/strict");
const test = require("node:test");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture(extraFunctions = [], extraGlobals = {}) {
  const state = { query: "", method: "", items: [], filterSettings: null,
    selectedId: "selected", selectedRecord: { id: "selected" },
    historyPaging: { total: 0, filteredTotal: 0, hiddenConnectTotal: 0, offset: 0 } };
  const pending = [];
  const c = loadFunctions([
    "createDefaultFilterSettings", "summaryMatchesActiveHistoryFilters",
    "summaryMatchesStatusFilter", "summaryMatchesMimeFilter", "summaryMatchesHiddenExtensions",
    "summaryMatchesPortFilter", "summaryMatchesColorTags", "summaryMatchesAdvancedSearch",
    "summaryQuickSearchHaystack", "selectedStatusClasses", "selectedMimeTypes",
    "inferMimeType", "extractSummaryPathExtension", "formatSize",
    "effectiveSummaryPort", "defaultSummaryPortForScheme", "extractHostPort",
    "buildTransactionsPageUrl", "flushTransactionDeltas",
    ...(appSource.includes("function foldHeaderSearchText(") ? ["foldHeaderSearchText"] : []),
    ...extraFunctions,
  ], {
    state, URLSearchParams, HTTP_HISTORY_PAGE_SIZE: 250,
    _pendingTransactionSummaries: pending, _historyFullLoadInFlight: 0, _searchActiveUntil: 0,
    currentSessionId: () => "fixture-session", isHttpHistoryVisible: () => true,
    canMergeRecentTransactions: () => true, isInScopeHost: (host) => host === "example.com",
    formatTimestamp: () => "Jan 01, 00:00:00", getHistoryItem: (id) => state.items.find((row) => row.id === id),
    isKnownCount: Number.isFinite, renderHistory() {},
    scheduleTransactionDeltaFlush() { throw new Error("Unexpected deferred flush"); },
    scheduleIncrementalRefresh() { throw new Error("Unexpected page reload"); },
    mergeHistoryItems(items) { state.items.unshift(...items); return items.length; },
    ...extraGlobals,
  });
  state.filterSettings = c.createDefaultFilterSettings();
  state.filterSettings.hiddenExtensions = "";
  return { c, state, pending };
}
function row(overrides = {}) {
  return { id: "fixture-row", sequence: 1, method: "GET", scheme: "https", host: "example.com", path: "/",
    started_at: "2026-01-01T00:00:00Z", status: 200, has_response: true,
    header_search_text: "Authorization: Bearer ExampleCredential\nX-Example-Request: RequestValue\nServer: ExampleServer/1.25\nSet-Cookie: first=One\nSet-Cookie: second=Two\nLocation: /example-target",
    ...overrides };
}

for (const term of ["authorization", "examplecredential", "x-example-request", "requestvalue", "server: exampleserver", "set-cookie: second=two", "/example-target"]) {
  test(`quick and advanced history search match captured header text: ${term}`, () => {
    const { c, state } = fixture();
    state.query = term;
    assert.equal(c.summaryMatchesActiveHistoryFilters(row()), true);
    state.query = "";
    state.filterSettings.searchTerm = term;
    assert.equal(c.summaryMatchesActiveHistoryFilters(row()), true);
  });
}

test("header advanced search honors case, regex, and negative matching across both haystacks", () => {
  const { c, state } = fixture();
  const filters = state.filterSettings;
  Object.assign(filters, { searchTerm: "ExampleCredential", caseSensitive: true });
  assert.equal(c.summaryMatchesAdvancedSearch(row(), filters), true);
  filters.searchTerm = "examplecredential";
  assert.equal(c.summaryMatchesAdvancedSearch(row(), filters), false);
  Object.assign(filters, { searchTerm: "Server: ExampleServer/[0-9]+\\.[0-9]+", regex: true });
  assert.equal(c.summaryMatchesAdvancedSearch(row(), filters), true);
  filters.negativeSearch = true;
  assert.equal(c.summaryMatchesAdvancedSearch(row(), filters), false);
  filters.searchTerm = "example\\.com";
  assert.equal(c.summaryMatchesAdvancedSearch(row(), filters), false, "metadata match also excludes");
  filters.searchTerm = "absent-header-value";
  assert.equal(c.summaryMatchesAdvancedSearch(row(), filters), true);
  filters.searchTerm = "[";
  assert.equal(c.summaryMatchesAdvancedSearch(row(), filters), false, "invalid-regex behavior is unchanged");
});

test("plain header search folds ASCII without folding Unicode differently from the server", () => {
  const { c, state } = fixture();
  const item = row({ header_search_text: "X-Example: ÄBC" });
  for (const [query, expected] of [["Äbc", true], ["äbc", false]]) {
    state.query = query;
    assert.equal(c.summaryMatchesActiveHistoryFilters(item), expected, query);
    state.query = "";
    state.filterSettings.searchTerm = query;
    assert.equal(c.summaryMatchesActiveHistoryFilters(item), expected, query);
    state.filterSettings.searchTerm = "";
  }
});

test("header searches do not truncate large values or omit late duplicate headers", () => {
  const { c, state } = fixture();
  const item = row({ header_search_text: `X-Padding: ${"界".repeat(100_000)}\nSet-Cookie: tail=LastHeaderNeedle` });
  state.query = "lastheaderneedle";
  assert.equal(c.summaryMatchesActiveHistoryFilters(item), true);
  state.query = "";
  state.filterSettings.searchTerm = "tail=LastHeaderNeedle";
  state.filterSettings.caseSensitive = true;
  assert.equal(c.summaryMatchesActiveHistoryFilters(item), true);
});

test("headers remain intersected with scope, method, status, and quick/advanced filters", () => {
  const { c, state } = fixture();
  state.query = "examplecredential";
  state.filterSettings.searchTerm = "exampleserver";
  assert.equal(c.summaryMatchesActiveHistoryFilters(row()), true);
  assert.equal(c.summaryMatchesActiveHistoryFilters(row({ header_search_text: "Server: ExampleServer" })), false);
  state.filterSettings.inScopeOnly = true;
  assert.equal(c.summaryMatchesActiveHistoryFilters(row({ host: "outside.example.com" })), false);
  state.method = "POST";
  assert.equal(c.summaryMatchesActiveHistoryFilters(row()), false);
  state.method = "GET";
  state.filterSettings.status.success = false;
  assert.equal(c.summaryMatchesActiveHistoryFilters(row()), false);
});

test("legacy summaries without headers retain existing metadata search behavior", () => {
  const { c, state } = fixture();
  const item = row();
  delete item.header_search_text;
  state.query = "example.com";
  assert.equal(c.summaryMatchesActiveHistoryFilters(item), true);
  state.query = "examplecredential";
  assert.equal(c.summaryMatchesActiveHistoryFilters(item), false);
});

test("UI page requests opt into header search for full and cursor pages", () => {
  const { c } = fixture();
  const queryState = { sessionId: "fixture-session", sortKey: "index", sortDirection: "desc",
    query: "ExampleCredential", statusClasses: ["success"], mimeTypes: ["other"], colorTags: [],
    advancedSearch: "Server", advancedRegex: true, advancedCaseSensitive: true, advancedNegative: true };
  for (const options of [{ offset: 0 }, { beforeSequence: 15 }]) {
    const url = new URL(c.buildTransactionsPageUrl({ ...options, queryState }), "https://example.com");
    assert.equal(url.searchParams.get("search_headers"), "true");
    assert.equal(url.searchParams.get("q"), "ExampleCredential");
    assert.equal(url.searchParams.get("advanced_search"), "Server");
    assert.equal(url.searchParams.get("session_id"), "fixture-session");
    if (options.beforeSequence) assert.equal(url.searchParams.has("offset"), false);
  }
});

test("live header-only matches update counts without disturbing selection or admitting other sessions", () => {
  const { c, state, pending } = fixture();
  state.query = "examplecredential";
  pending.push(
    { sessionId: "fixture-session", summary: row() },
    { sessionId: "fixture-session", summary: row({ id: "miss", sequence: 2, header_search_text: "Server: Other" }) },
    { sessionId: "fixture-session", summary: row({ id: "connect", sequence: 3, method: "CONNECT" }) },
    { sessionId: "another-session", summary: row({ id: "foreign", sequence: 4 }) },
  );
  c.flushTransactionDeltas();
  assert.deepEqual(state.items.map((item) => item.id), ["fixture-row"]);
  assert.equal(state.historyPaging.total, 3);
  assert.equal(state.historyPaging.filteredTotal, 1);
  assert.equal(state.historyPaging.hiddenConnectTotal, 1);
  assert.equal(state.selectedId, "selected");
  assert.equal(state.selectedRecord.id, "selected");
});


test("advanced regex keeps metadata anchors and does not match a missing header block", () => {
  const { c, state } = fixture();
  Object.assign(state.filterSettings, { regex: true, searchTerm: "^$" });
  assert.equal(c.summaryMatchesAdvancedSearch(row({ header_search_text: "" }), state.filterSettings), false);
  state.filterSettings.searchTerm = "^example\\.com GET / $";
  assert.equal(c.summaryMatchesAdvancedSearch(row(), state.filterSettings), true);
  state.filterSettings.searchTerm = "GET[\\s\\S]*ExampleCredential";
  assert.equal(c.summaryMatchesAdvancedSearch(row(), state.filterSettings), false, "metadata and headers are separate search fields");
});

for (const clearHeaders of [false, true]) {
  test(`annotation acknowledgement ${clearHeaders ? "clears omitted" : "preserves complete"} header-search text`, async () => {
    const item = row();
    const updated = { ...item, color_tag: "blue", annotation_revision: 1 };
    if (clearHeaders) delete updated.header_search_text;
    const window = { order: new Map([[item.id, 0]]), editors: new Set() };
    const { c, state } = fixture(["flushPendingAnnotations", "prepareHistoryItem"], {
      fetch: async () => ({ ok: true, json: async () => updated }),
      sessionWritePath(path) {
        assert.equal(path, "/api/transactions/fixture-row/annotations?search_headers=true");
        return "fixture-only:annotations";
      }, observeAnnotationRevision() {},
      currentHistoryNoteEditWindow: () => window,
      getHistoryItemIndex: () => 0, releaseHistoryNoteEdit() {}, syncHistoryNoteEditWindow() {},
      retainFilteredHistoryNote: () => window, adjustHistoryPagingAfterLocalRemoval() {},
      rebuildHistoryItemIndex() {}, refreshHistoryPagingCursorFromItems() {},
      resortLoadedHistoryItemsForCurrentSort: () => false, invalidateVisibleEntriesCache() {},
    });
    state.query = "examplecredential";
    state.items = [item];
    state._itemById = new Map([[item.id, item]]);
    state._pendingAnnotations = new Map([[item.id, { sessionId: "fixture-session", payload: { color_tag: "blue" } }]]);
    state._annotationInFlight = new Set();
    assert.equal(await c.flushPendingAnnotations(item.id), true);
    assert.equal(state.items.length, clearHeaders ? 0 : 1);
    if (!clearHeaders) assert.equal(state.items[0].header_search_text, updated.header_search_text);
  });
}
