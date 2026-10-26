// Offline history detail controller tests: real initialization/click callbacks,
// synthetic DOM/timers, and mocked read-only fetch. No app bootstrap or server.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");
const tick = () => new Promise(setImmediate);
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const record = (id, overrides = {}) => ({
  id, sequence: 1, kind: "http", method: "GET", scheme: "https", host: "example.com", path: `/${id}`,
  status: 200, duration_ms: 1, http_version: "HTTP/1.1", notes: [],
  request: { body_size: 0, headers: [{ name: "x-fixture-request", value: id }] },
  response: { body_size: 0, headers: [{ name: "x-fixture-response", value: id }] },
  ...overrides,
});
const summary = (value) => {
  const { request, response, notes, ...metadata } = value;
  return { ...metadata, request_bytes: request?.body_size || 0, response_bytes: response?.body_size || 0,
    has_response: !!response, note_count: notes?.length || 0 };
};
function fixture() {
  const requests = [], errors = [], timers = new Map(), rows = new Map(), previews = [];
  let timerId = 0;
  const node = () => {
    const handlers = new Map(), classes = new Set();
    return { textContent: "", innerHTML: "", value: "", dataset: {},
      classList: { add: name => classes.add(name), remove: name => classes.delete(name),
        contains: name => classes.has(name), toggle(name, on) { if (on) classes.add(name); else classes.delete(name); } },
      addEventListener(type, callback) { handlers.set(type, callback); },
      dispatch(type, event) { handlers.get(type)?.(event); }, focus() {},
    };
  };
  const els = {};
  for (const name of ["historyTableBody", "trafficRegion", "detailTitle", "detailTags", "protocolStrip", "attributesCount",
    "requestHeaderCount", "responseHeaderCount", "summaryList", "requestHeadersBody", "responseHeadersBody", "notesCard",
    "requestView", "requestLines", "responseView", "responseLines", "requestSearchInput", "responseSearchInput",
    "requestSearchMeta", "responseSearchMeta", "requestMrToggle", "responseMrToggle", "historyMeta", "liveStatus"]) els[name] = node();
  for (const id of ["fixture-a", "fixture-b", "fixture-c"]) {
    const row = node(); row.dataset.id = id; row.closest = selector => selector === ".history-row" ? row : null; rows.set(id, row);
  }
  els.historyTableBody.querySelector = selector => selector === ".history-row.selected"
    ? [...rows.values()].find(row => row.classList.contains("selected"))
    : rows.get(selector.match(/data-id="([^"]+)"/)?.[1]);
  const c = loadFunctions([
    "createHistoryPagingState", "createWebsocketPagingState", "createDefaultFilterSettings", "createDefaultDisplaySettings",
    "selectHistoryTransaction", "loadTransactionDetail", "canReuseSelectedHistoryRecord", "historyRecordSummarySignature",
    "currentSessionId", "transactionPath", "sessionQueryPath", "getHistoryItem", "rebuildHistoryItemIndex", "updateHistorySelection",
    "cancelHistoryDetailLoading", "scheduleHistoryDetailLoading", "renderDetail", "renderEmptyDetail", "renderLoadingDetail",
    "renderMessagePanes", "renderViewTabs", "getHistoryPacketViewer", "createPacketViewerController", "normalizedHeaders", "renderSummaryRows", "renderHeaderList", "renderProtocolStrip",
    "inferProtocolState", "formatTimestamp", "formatSize", "escapeHtml", "buildMessagePresentation", "buildRawRequest",
    "buildRawRequestHead", "buildRawResponse", "buildRawResponseHead", "renderBody", "mergeHeaders", "headerNameEquals",
    "clearHttpHistorySelectionPreview", "clearHttpHistoryLoadedRowsForPendingQuery", "adjustHistoryPagingAfterLocalRemoval",
    "refreshHistoryPagingCursorFromItems", "isKnownCount", "canUseSequenceCursorForHistoryPaging",
    "toggleSort", "defaultSortDirection", "mergeHistoryItems", "trimHistoryCache", "reconcileHistorySelectionAfterTrim",
    "moveHistorySelectionIfMissing", "applyPendingAnnotationsToItems",
  ], {
    els, URLSearchParams, HTTP_HISTORY_PAGE_SIZE: 250, HTTP_HISTORY_MAX_LOADED_ITEMS: 3, WEBSOCKET_PAGE_SIZE: 100,
    DEFAULT_HISTORY_COLUMN_ORDER: [], DETAIL_LOADING_DELAY_MS: 180,
    createDefaultHistoryColumnWidths: () => ({}), createDefaultWsColumnWidths: () => ({}),
    _historyDetailGeneration: 0, _historyDetailLoadingTimer: null, viewTabs: [],
    historyPacketViewer: null,
    document: { querySelectorAll: () => [], getElementById: () => null },
    window: { setTimeout(callback) { const id = ++timerId; timers.set(id, callback); return id; }, clearTimeout(id) { timers.delete(id); } },
    fetch(url, options) {
      assert.equal(options, undefined, "only passive reads are allowed");
      assert.match(url, /^\/api\/transactions\/fixture-[abc]\?session_id=fixture-session-[ab]$/);
      const request = { url, ...deferred() }; requests.push(request); return request.promise;
    },
    console: { ...console, error: error => errors.push(error) }, observeAnnotationRevision() {},
    scrollSelectedHistoryRowIntoView() {}, scrollHistoryToId() {}, invalidateVisibleEntriesCache() {}, renderHistory() {},
    prepareHistoryItem() {}, adjustHistoryScrollAfterHeadTrim() {}, scheduleUiSettingsSave() {}, scheduleRefresh() {},
    updateCodePane(view, _lines, text) { view.textContent = text; return { lineCount: text.split("\n").length, matchCount: 0 }; },
    buildSearchMeta: () => "", renderResponsePreview: (_elements, _active, subject) => previews.push(subject),
    recordPageUrl: () => "https://example.com/",
  });
  const initial = appSource.match(/^const state = \{[^]*?^\};/m);
  assert.ok(initial, "real application state initializer");
  vm.runInContext(initial[0] + "\nglobalThis.fixtureState = state;", c);
  const state = c.fixtureState;
  state.activeSession = { id: "fixture-session-a" };
  state.messageViews = { request: "raw", response: "raw" };
  state.items = [summary(record("fixture-a")), summary(record("fixture-b")), summary(record("fixture-c"))];
  c.rebuildHistoryItemIndex();
  c.precomputeItemIndexes = () => c.rebuildHistoryItemIndex();
  const clickStart = appSource.indexOf('  els.historyTableBody.addEventListener("click",');
  const clickEnd = appSource.indexOf('  els.historyTableBody.addEventListener("dblclick",', clickStart);
  assert.ok(clickStart >= 0 && clickEnd > clickStart);
  vm.runInContext(appSource.slice(clickStart, clickEnd), c);
  c.renderEmptyDetail();
  const click = id => els.historyTableBody.dispatch("click", { target: rows.get(id) });
  const succeed = (index, value) => requests[index].resolve({ ok: true, json: async () => value });
  const runTimers = () => { for (const [id, callback] of [...timers]) { timers.delete(id); callback(); } };
  const view = () => JSON.stringify({ selectedId: state.selectedId, record: state.selectedRecord, loading: state.loadingDetailId,
    request: els.requestView.textContent, response: els.responseView.textContent, summary: els.summaryList.innerHTML,
    requestHeaders: els.requestHeadersBody.innerHTML, responseHeaders: els.responseHeadersBody.innerHTML });
  return { c, state, els, requests, errors, timers, rows, previews, click, succeed, runTimers, view };
}

for (const priorDetail of [false, true]) {
  for (const failure of ["network", "abort", "JSON", "HTTP", "null record", "missing ID", "wrong ID"]) {
    test(`${failure} failure ${priorDetail ? "after a rendered row" : "from initial state"} ends loading and supports a same-row retry`, async () => {
      const f = fixture();
      if (priorDetail) { f.click("fixture-b"); f.succeed(0, record("fixture-b")); await tick(); }
      f.click("fixture-a");
      const request = f.requests.at(-1);
      if (failure === "network") request.reject(new Error("Synthetic transport failure"));
      if (failure === "abort") { const error = new Error("Synthetic abort"); error.name = "AbortError"; request.reject(error); }
      if (failure === "null record") request.resolve({ ok: true, json: async () => null });
      if (failure === "missing ID") request.resolve({ ok: true, json: async () => ({}) });
      if (failure === "wrong ID") request.resolve({ ok: true, json: async () => record("fixture-b") });
      if (failure === "JSON") request.resolve({ ok: true, json: async () => { throw new Error("Synthetic JSON failure"); } });
      if (failure === "HTTP") request.resolve({ ok: false, status: 503 });
      await tick();
      assert.equal(f.state.loadingDetailId, null);
      assert.equal(f.timers.size, 0, "failure cancels the delayed loading placeholder");
      assert.match(f.els.requestView.textContent, /Failed to load selected transaction/);
      assert.match(f.els.responseView.textContent, /Select the row again to retry/);
      assert.match(f.els.summaryList.innerHTML, /Failed to load selected transaction/);
      assert.doesNotMatch(f.view(), /x-fixture-(?:request|response)/, "previous row cannot masquerade as failed detail");
      const failedView = f.view(); f.runTimers(); assert.equal(f.view(), failedView);
      f.click("fixture-a"); f.succeed(f.requests.length - 1, record("fixture-a")); await tick();
      assert.equal(f.state.selectedRecord.id, "fixture-a");
      assert.match(f.els.requestView.textContent, /x-fixture-request: fixture-a/);
      assert.match(f.els.responseView.textContent, /x-fixture-response: fixture-a/);
      assert.doesNotMatch(f.view(), /Failed to load/);
    });
  }
}

for (const result of ["success", "network failure", "JSON failure", "HTTP failure", "wrong ID"]) {
  for (const change of ["another row", "A-B-A", "session", "session round trip", "clear selection"]) {
    test(`late ${result} cannot alter the current detail or timer after ${change}`, async () => {
      const f = fixture(), body = deferred();
      f.click("fixture-a");
      if (result === "JSON failure") {
        f.requests[0].resolve({ ok: true, json: () => body.promise }); await tick();
      }
      if (change === "another row" || change === "A-B-A") f.click("fixture-b");
      if (change === "A-B-A") f.click("fixture-a");
      if (change.startsWith("session")) {
        // Execute the actual HTTP part of session reset, without initializing
        // unrelated tools or invoking their operations or workspace save paths.
        const resetStart = appSource.indexOf("  cancelHistoryDetailLoading();", appSource.indexOf("function resetSessionScopedUiState()"));
        const resetEnd = appSource.indexOf("  state.intercepts = [];", resetStart);
        assert.ok(resetStart >= 0 && resetEnd > resetStart);
        vm.runInContext(appSource.slice(resetStart, resetEnd) + "renderEmptyDetail();", f.c);
        f.state.activeSession = { id: "fixture-session-b" };
        if (change === "session round trip") f.state.activeSession = { id: "fixture-session-a" };
        f.click("fixture-a");
      }
      if (change === "clear selection") f.c.clearHttpHistorySelectionPreview();
      // Keep the newest spinner pending; stale completion must not cancel it.
      const before = f.view(), timersBefore = [...f.timers.keys()];
      if (result === "success") f.succeed(0, record("fixture-a"));
      if (result === "network failure") f.requests[0].reject(new Error("Stale synthetic error"));
      if (result === "JSON failure") body.reject(new Error("Stale synthetic body error"));
      if (result === "HTTP failure") f.requests[0].resolve({ ok: false, status: 503 });
      if (result === "wrong ID") f.succeed(0, record("fixture-c"));
      await tick();
      assert.equal(f.view(), before);
      assert.deepEqual([...f.timers.keys()], timersBefore);
      for (let i = 1; i < f.requests.length; i++) {
        const id = f.requests[i].url.match(/transactions\/(fixture-[abc])/)[1];
        f.succeed(i, record(id));
      }
      await tick();
      if (change !== "clear selection") {
        const id = change === "another row" ? "fixture-b" : "fixture-a";
        assert.equal(f.state.selectedRecord.id, id);
        assert.match(f.els.requestView.textContent, new RegExp(`x-fixture-request: ${id}`));
        assert.match(f.els.responseView.textContent, new RegExp(`x-fixture-response: ${id}`));
      }
    });
  }
}

test("an older success cannot erase the newest same-row failure or restore its response preview", async () => {
  const f = fixture();
  f.click("fixture-a"); f.click("fixture-b"); f.click("fixture-a");
  f.requests[2].reject(new Error("Current failure")); await tick();
  const before = f.view();
  f.succeed(0, record("fixture-a")); f.succeed(1, record("fixture-b")); await tick();
  assert.equal(f.view(), before);
  assert.match(f.previews.at(-1).note, /Failed to load/);
  f.state.messageViews.response = "render"; f.c.renderMessagePanes();
  assert.match(f.previews.at(-1).note, /Select the row again to retry/);
  f.c.clearHttpHistorySelectionPreview();
  assert.equal(f.state.historyDetailError || "", "");
  assert.doesNotMatch(f.els.requestView.textContent, /Failed to load/);
});

test("a confirmed 404 still removes only the selected missing row and loads its neighbor", async () => {
  const f = fixture();
  f.click("fixture-a"); f.requests[0].resolve({ ok: false, status: 404 }); await tick();
  assert.equal(f.c.getHistoryItem("fixture-a"), null);
  assert.equal(f.state.selectedId, "fixture-b");
  assert.equal(f.requests.length, 2);
  f.succeed(1, record("fixture-b")); await tick();
  assert.equal(f.state.selectedRecord.id, "fixture-b");
  assert.equal(f.state.historyDetailError || "", "");
});

test("error text is generic and plain text is escaped in inspector markup", () => {
  const f = fixture();
  f.c.renderEmptyDetail('<synthetic-fixture value="quoted">');
  assert.equal(f.els.requestView.textContent, '<synthetic-fixture value="quoted">');
  assert.match(f.els.requestHeadersBody.innerHTML, /&lt;synthetic-fixture value=&quot;quoted&quot;&gt;/);
  assert.doesNotMatch(f.els.summaryList.innerHTML, /<synthetic-fixture/);
});

for (const failure of ["network", "JSON", "HTTP"]) {
  test(`stale ${failure} failure does not cancel the actual delayed timer for a newer selection`, async () => {
    const f = fixture(), body = deferred();
    f.click("fixture-a");
    if (failure === "JSON") { f.requests[0].resolve({ ok: true, json: () => body.promise }); await tick(); }
    f.click("fixture-b"); f.succeed(1, record("fixture-b")); await tick();
    f.click("fixture-c");
    assert.equal(f.timers.size, 1, "newer row starts with a delayed placeholder after rendered detail");
    const timer = [...f.timers.keys()][0], before = f.view();
    if (failure === "network") f.requests[0].reject(new Error("Old synthetic failure"));
    if (failure === "JSON") body.reject(new Error("Old synthetic body failure"));
    if (failure === "HTTP") f.requests[0].resolve({ ok: false, status: 503 });
    await tick();
    assert.equal(f.view(), before);
    assert.equal(f.timers.has(timer), true);
    f.runTimers(); assert.equal(f.state.loadingDetailId, "fixture-c");
    f.succeed(2, record("fixture-c")); await tick();
    assert.equal(f.state.selectedRecord.id, "fixture-c");
    assert.match(f.els.requestView.textContent, /x-fixture-request: fixture-c/);
    assert.match(f.els.responseView.textContent, /x-fixture-response: fixture-c/);
  });
}

for (const transition of ["sort", "filter", "page trim"]) {
  test(`${transition} supersedes a pending detail and clears its error state`, async () => {
    const f = fixture(); f.click("fixture-a");
    if (transition === "sort") f.c.toggleSort("path");
    if (transition === "filter") {
      // The search control callback is loaded verbatim; settings persistence and
      // refresh scheduling stay inert in this passive fixture.
      const control = { value: "fixture-b", addEventListener(_type, callback) { this.callback = callback; } };
      f.els.searchInput = control; f.c.clearTimeout = () => {};
      const start = appSource.indexOf('  els.searchInput.addEventListener("search",');
      const end = appSource.indexOf('  els.requestSearchInput.addEventListener(', start);
      vm.runInContext('let _searchDebounce = 0;\n' + appSource.slice(start, end), f.c);
      control.callback();
      assert.equal(f.state.query, "fixture-b");
    }
    if (transition === "page trim") {
      f.state.items = [summary(record("fixture-a")), summary(record("fixture-b"))];
      f.c.rebuildHistoryItemIndex(); f.c.HTTP_HISTORY_MAX_LOADED_ITEMS = 2;
      f.c.mergeHistoryItems([summary(record("fixture-c"))]);
      assert.equal(f.state.selectedId, "fixture-b");
    }
    const before = f.view(); f.requests[0].reject(new Error("Superseded read")); await tick();
    assert.equal(f.view(), before);
    assert.equal(f.state.historyDetailError || "", "");
    if (transition === "page trim") { f.succeed(1, record("fixture-b")); await tick(); assert.equal(f.state.selectedRecord.id, "fixture-b"); }
    else assert.equal(f.state.selectedId, null);
  });
}

test("omitted summary fields force a fresh detail and cannot keep old note, tag, or response", async () => {
  const f = fixture();
  const before = record("fixture-a", { user_note: "Synthetic old note", color_tag: "blue", annotation_revision: 2 });
  f.state.items[0] = { ...summary(before), has_user_note: true }; f.c.rebuildHistoryItemIndex();
  f.click("fixture-a"); f.succeed(0, before); await tick();
  assert.equal(f.c.canReuseSelectedHistoryRecord("fixture-a"), true);
  const after = record("fixture-a", { annotation_revision: 3 });
  delete after.response; delete after.status; delete after.duration_ms;
  f.state.items[0] = summary(after); f.c.rebuildHistoryItemIndex();
  assert.equal(f.c.canReuseSelectedHistoryRecord("fixture-a"), false);
  f.click("fixture-a"); f.succeed(1, after); await tick();
  assert.equal(f.state.selectedRecord, after);
  assert.doesNotMatch(f.els.summaryList.innerHTML, /Synthetic old note|Color tag/);
  assert.doesNotMatch(f.els.responseHeadersBody.innerHTML, /x-fixture-response/);
  assert.equal(f.els.responseView.textContent, "No response was captured for this exchange.");
});
