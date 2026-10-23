// Offline saved WebSocket readers: actual state, selection/filter callbacks and
// renderers, synthetic DOM/timers, and deferred GET responses. No app bootstrap.
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
const frame = (index, body = `Saved frame ${index}`) => ({ index, body, body_preview: body,
  direction: "server_to_client", kind: "text", body_size: body.length });
const record = (id, extra = {}) => ({ id, host: "example.com", path: `/${id}`, status: 101,
  request: { headers: [{ name: "x-fixture-request", value: id }] },
  response: { headers: [{ name: "x-fixture-response", value: id }] },
  frames: [frame(0), frame(1)], frame_count: 2, retained_frame_count: 2, last_frame_index: 1,
  ...extra });
function fixture() {
  const requests = [], errors = [], timers = new Map(), rows = new Map(), frameRows = new Map();
  let timerId = 0;
  function node() {
    const handlers = new Map(), classes = new Set();
    return { innerHTML: "", textContent: "", value: "", dataset: {},
      classList: { add: name => classes.add(name), remove: name => classes.delete(name),
        contains: name => classes.has(name), toggle(name, on) { if (on) classes.add(name); else classes.delete(name); } },
      addEventListener(type, callback) { handlers.set(type, callback); },
      dispatch(type, event) { return handlers.get(type)?.(event); },
      querySelector: () => null, querySelectorAll: () => [], contains: () => true, closest: () => null,
    };
  }
  const els = {};
  for (const name of ["websocketTableBody", "websocketSearchInput", "websocketRequestView", "websocketResponseView",
    "websocketHandshakeCM", "websocketFramesBody", "frameDetailMeta", "frameDetailBody", "frameDetailPanel", "frameDetailResizer"]) els[name] = node();
  for (const id of ["fixture-a", "fixture-b", "fixture-c"]) {
    const row = node(); row.dataset.id = id; row.closest = selector => selector === ".history-row" ? row : null; rows.set(id, row);
  }
  for (const index of [0, 1, 2, 3]) {
    const row = node(); row.dataset.frameIndex = String(index);
    row.closest = selector => selector === ".history-row[data-frame-index]" ? row : null; frameRows.set(index, row);
  }
  els.websocketFramesBody.querySelectorAll = selector => [...frameRows.values()].filter(row =>
    selector === ".frame-selected" && row.classList.contains("frame-selected"));
  const c = loadFunctions([
    "createHistoryPagingState", "createWebsocketPagingState", "createDefaultFilterSettings", "createDefaultDisplaySettings",
    "currentSessionId", "sessionQueryPath", "websocketDetailRequestPath", "loadWebsocketDetail", "selectWebsocketSession",
    "cancelWebsocketDetailLoading", "scheduleWebsocketDetailLoading", "renderWebsocketSessions", "renderWebsocketFrameTable",
    "buildRawWebsocketRequest", "buildRawWebsocketResponse", "mergeHeaders", "normalizedHeaders", "headerNameEquals",
    "getSortedWebsocketEntries", "getVisibleWebsocketSessions", "getWebsocketFrames", "normalizeWebsocketFrames",
    "normalizeWebsocketFrame", "normalizeWebsocketFrameIndex", "normalizeWebsocketCount", "websocketRetainedFrameCount",
    "websocketFirstRetainedFrameIndex", "mergeWebsocketFrameWindows", "capWebsocketFrameWindow", "websocketFramesAreTruncated",
    "websocketFramesShell", "resetWebsocketFrameScroll", "websocketRenderedFrameWindow", "renderFramePreview",
    "selectWebsocketFrameRow", "showFrameDetail", "hideFrameDetail", "escapeHtml", "formatSize", "countLines",
    "clearWebsocketSelectionPreview", "applySelectedWebsocketSummary", "syncVisibleWebsocketSelection",
    "selectedWebsocketDetailMeetsRefreshTarget", "mergeWebsocketDetailRefreshTarget", "scheduleSelectedWebsocketDetailRefresh",
    "adjustWebsocketPagingAfterLocalRemoval", "isKnownCount", "websocketLoadedWindowCanHideSelection",
    "loadOlderWebsocketFrames", "newestWebsocketFrameIndexes",
  ], {
    els, URLSearchParams, HTTP_HISTORY_PAGE_SIZE: 250, WEBSOCKET_PAGE_SIZE: 100, DEFAULT_HISTORY_COLUMN_ORDER: [],
    createDefaultHistoryColumnWidths: () => ({}), createDefaultWsColumnWidths: () => ({}), DETAIL_LOADING_DELAY_MS: 180,
    WEBSOCKET_DETAIL_FRAME_LIMIT: 2, WEBSOCKET_MAX_LOADED_FRAMES: 20, WEBSOCKET_FRAME_ROW_HEIGHT: 25,
    WEBSOCKET_MAX_RENDERED_FRAME_ROWS: 20, WEBSOCKET_FRAME_ROW_PREVIEW_CHARS: 120, measuredWebsocketFrameRowHeight: 25,
    _websocketDetailGeneration: 0, _websocketDetailPendingId: null, _websocketDetailPendingSessionId: null,
    _websocketDetailPendingPromise: null, _websocketDetailLoadingTimer: null, _websocketDetailRefreshNeeded: null,
    _websocketDetailRefreshTimer: null, _websocketSearchReloadTimer: null,
    _websocketLoadGeneration: 0, _websocketSummaryMutationGeneration: 0, _websocketSummaryMutationById: new Map(),
    _websocketSummaryEventTimer: null, _websocketSummaryEventBuffer: new Map(),
    document: { getElementById: () => null },
    window: { setTimeout(callback) { const id = ++timerId; timers.set(id, callback); return id; }, clearTimeout(id) { timers.delete(id); } },
    fetch(url, options) {
      assert.equal(options, undefined, "only passive GETs are allowed");
      assert.match(url, /^\/api\/websockets\/fixture-[abc]\?frame_limit=2&(?:before_index=\d+&)?session_id=fixture-session-[ab]$/);
      const request = { url, ...deferred() }; requests.push(request); return request.promise;
    },
    console: { ...console, error: error => errors.push(error) }, renderWebsocketSessionTable() {},
    showToast: message => errors.push(message),
    updateCodePaneCM(_key, pane, text) { pane.textContent = text; }, updateWsHandshakeLineNumbers() {}, updateWsHandshakeSearch() {},
    prettyJsonText: text => text, highlightBodyLine: text => text.replaceAll("<", "&lt;"),
    scheduleUiSettingsSave() {}, clearWebsocketQueryBackfill() {}, clearFilteredWebsocketReload() {}, clearWebsocketSearchReload() {},
    scrollSelectedWebsocketRowIntoView() {}, ensureWebsocketSessionInView() {},
  });
  const initial = appSource.match(/^const state = \{[^]*?^\};/m);
  assert.ok(initial, "real application state initializer");
  vm.runInContext(initial[0] + "\nglobalThis.fixtureState = state;", c);
  const state = c.fixtureState;
  state.activeSession = { id: "fixture-session-a" };
  state.activeTool = "proxy"; state.activeProxyTab = "websockets-history";
  state.websocketSessions = [record("fixture-a"), record("fixture-b"), record("fixture-c")];
  const start = appSource.indexOf('  els.websocketTableBody?.addEventListener("click",');
  const end = appSource.indexOf('  els.websocketFramesBody?.addEventListener("contextmenu",', start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(appSource.slice(start, end), c);
  const searchStart = appSource.indexOf('  els.websocketSearchInput.addEventListener("input",');
  const searchEnd = appSource.indexOf('  let websocketScrollRaf', searchStart);
  vm.runInContext(appSource.slice(searchStart, searchEnd), c);
  c.hideFrameDetail(); c.renderWebsocketSessions();
  const click = id => els.websocketTableBody.dispatch("click", { target: rows.get(id) });
  const clickFrame = index => els.websocketFramesBody.dispatch("click", { target: frameRows.get(index) });
  const clickOlder = () => els.websocketFramesBody.dispatch("click", { target: {
    closest: selector => selector === "[data-ws-load-older-frames]" ? {} : null,
  } });
  const succeed = (index, value) => requests[index].resolve({ ok: true, json: async () => value });
  const view = () => JSON.stringify({ selected: state.selectedWebsocketId, record: state.selectedWebsocketRecord,
    error: state.selectedWebsocketDetailError, frame: state.selectedFrameIdx, handshake: els.websocketHandshakeCM.textContent,
    frames: els.websocketFramesBody.innerHTML, frameBody: els.frameDetailBody.innerHTML,
    hidden: els.frameDetailPanel.classList.contains("hidden") });
  const reset = sessionId => {
    // Run only the real passive WebSocket reset slice; unrelated tools and
    // workspace persistence are never initialized or executed by this fixture.
    const resetStart = appSource.indexOf("  state.websocketSessions = [];", appSource.indexOf("function resetSessionScopedUiState()"));
    const resetEnd = appSource.indexOf("  resetEventLogUiState();", resetStart);
    assert.ok(resetStart >= 0 && resetEnd > resetStart);
    vm.runInContext(appSource.slice(resetStart, resetEnd) + "renderWebsocketSessions(); hideFrameDetail();", c);
    state.activeSession = { id: sessionId }; state.websocketSessions = [record("fixture-a"), record("fixture-b")];
  };
  return { c, state, els, requests, errors, timers, click, clickFrame, clickOlder, succeed, view, reset };
}

for (const [label, payload] of [["null", null], ["empty object", {}], ["array", []], ["wrong ID", record("fixture-b")]]) {
  test(`${label} detail cannot masquerade as the selected saved connection and supports retry`, async () => {
    const f = fixture(); f.click("fixture-a"); f.succeed(0, payload); await tick();
    assert.equal(f.state.selectedWebsocketRecord, null);
    assert.match(f.els.websocketHandshakeCM.textContent, /Failed to load selected WebSocket session/);
    assert.match(f.els.websocketFramesBody.innerHTML, /Select the session again/);
    assert.equal(f.c._websocketDetailPendingPromise, null);
    f.click("fixture-a"); f.succeed(1, record("fixture-a")); await tick();
    assert.equal(f.state.selectedWebsocketRecord.id, "fixture-a");
    assert.match(f.els.websocketHandshakeCM.textContent, /x-fixture-request: fixture-a/);
  });
}

for (const failure of ["network", "JSON", "HTTP"]) {
  test(`current ${failure} refresh failure dismisses the selected frame preview and retries cleanly`, async () => {
    const f = fixture(); f.click("fixture-a"); f.succeed(0, record("fixture-a")); await tick(); f.clickFrame(1);
    assert.equal(f.state.selectedFrameIdx, 1); assert.equal(f.els.frameDetailPanel.classList.contains("hidden"), false);
    const refresh = f.c.loadWebsocketDetail("fixture-a");
    if (failure === "network") f.requests[1].reject(new Error("Synthetic failure"));
    if (failure === "JSON") f.requests[1].resolve({ ok: true, json: async () => { throw new Error("Synthetic failure"); } });
    if (failure === "HTTP") f.requests[1].resolve({ ok: false, status: 503 });
    await refresh;
    assert.equal(f.state.selectedWebsocketRecord, null);
    assert.equal(f.state.selectedFrameIdx, null, "an unavailable record cannot keep a selected frame");
    assert.equal(f.els.frameDetailPanel.classList.contains("hidden"), true);
    assert.match(f.els.websocketHandshakeCM.textContent, /Failed to load selected WebSocket session/);
    f.click("fixture-a"); f.succeed(2, record("fixture-a")); await tick(); f.clickFrame(0);
    assert.equal(f.state.selectedFrameIdx, 0); assert.equal(f.els.frameDetailPanel.classList.contains("hidden"), false);
  });
}

for (const outcome of ["success", "network", "JSON", "HTTP"]) {
  for (const change of ["A-B-A", "session round trip", "search clear", "search return"]) {
    test(`late ${outcome} cannot alter current connection/frame state after ${change}`, async () => {
      const f = fixture(), body = deferred(); f.click("fixture-a");
      if (outcome === "JSON") { f.requests[0].resolve({ ok: true, json: () => body.promise }); await tick(); }
      if (change === "A-B-A") { f.click("fixture-b"); f.click("fixture-a"); }
      if (change === "session round trip") { f.reset("fixture-session-b"); f.reset("fixture-session-a"); f.click("fixture-a"); }
      if (change.startsWith("search")) {
        f.els.websocketSearchInput.value = "fixture"; f.els.websocketSearchInput.dispatch("input", {});
        if (change === "search return") f.click("fixture-a");
      }
      const before = f.view(), beforeTimers = [...f.timers.keys()];
      if (outcome === "success") f.succeed(0, record("fixture-a"));
      if (outcome === "network") f.requests[0].reject(new Error("Old synthetic failure"));
      if (outcome === "JSON") body.reject(new Error("Old synthetic JSON failure"));
      if (outcome === "HTTP") f.requests[0].resolve({ ok: false, status: 503 });
      await tick();
      assert.equal(f.view(), before);
      assert.deepEqual([...f.timers.keys()], beforeTimers);
      for (let i = 1; i < f.requests.length; i++) f.succeed(i, record(f.requests[i].url.match(/websockets\/(fixture-[abc])/)[1]));
      await tick();
      if (change !== "search clear") {
        assert.equal(f.state.selectedWebsocketRecord.id, "fixture-a");
        f.clickFrame(0); assert.equal(f.state.selectedFrameIdx, 0);
      }
    });
  }
}

test("repeated same-owner selection deduplicates pending reads without losing its valid completion", async () => {
  const f = fixture(); f.click("fixture-a"); f.click("fixture-a");
  const keyboard = f.c.selectWebsocketSession("fixture-a");
  assert.equal(f.requests.length, 1);
  f.succeed(0, record("fixture-a")); await keyboard; await tick();
  assert.equal(f.state.selectedWebsocketRecord.id, "fixture-a");
  f.clickFrame(1); f.click("fixture-a");
  assert.equal(f.requests.length, 1); assert.equal(f.state.selectedFrameIdx, 1);
});

test("omitted optional fields clear summary metadata and the refreshed handshake", async () => {
  const f = fixture();
  const prior = record("fixture-a", { closed_at: "2026-10-18T00:00:00Z", duration_ms: 20, note_count: 1 });
  f.click("fixture-a"); f.succeed(0, prior); await tick(); f.clickFrame(1);
  f.c.applySelectedWebsocketSummary({ id: "fixture-a", frame_count: 2, retained_frame_count: 2, last_frame_index: 1 });
  assert.equal(f.state.selectedWebsocketRecord.closed_at, undefined);
  assert.equal(f.state.selectedWebsocketRecord.duration_ms, undefined);
  assert.equal(f.state.selectedWebsocketRecord.note_count, undefined);
  const next = record("fixture-a"); delete next.response;
  const refresh = f.c.loadWebsocketDetail("fixture-a"); f.succeed(1, next); await refresh;
  assert.equal(f.state.selectedWebsocketRecord.response, undefined);
  assert.equal(f.c.buildRawWebsocketResponse(f.state.selectedWebsocketRecord), "No handshake response was captured.");
  assert.equal(f.state.selectedFrameIdx, 1, "a valid same-owner refresh keeps the selected retained frame");
});

test("empty frames render a completed empty state instead of a loading or failure state", async () => {
  const f = fixture(); f.click("fixture-a");
  f.succeed(0, record("fixture-a", { frames: [], frame_count: 0, retained_frame_count: 0, last_frame_index: undefined })); await tick();
  assert.equal(f.state.selectedWebsocketRecord.id, "fixture-a");
  assert.match(f.els.websocketFramesBody.innerHTML, /No frames recorded yet/);
  assert.equal(f.state.selectedWebsocketDetailError, "");
  assert.equal(f.timers.size, 0);
});

for (const trigger of ["row click", "keyboard selection", "scheduled refresh"]) {
  test(`${trigger} retry replaces the previous failure with a loading state immediately`, async () => {
    const f = fixture(); f.click("fixture-a"); f.requests[0].reject(new Error("Synthetic failure")); await tick();
    assert.match(f.els.websocketHandshakeCM.textContent, /Failed to load/);
    let loading;
    if (trigger === "row click") f.click("fixture-a");
    if (trigger === "keyboard selection") loading = f.c.selectWebsocketSession("fixture-a");
    if (trigger === "scheduled refresh") {
      f.c.scheduleSelectedWebsocketDetailRefresh("fixture-a", 1);
      const id = f.c._websocketDetailRefreshTimer, callback = f.timers.get(id); f.timers.delete(id); callback();
    }
    assert.match(f.els.websocketHandshakeCM.textContent, /Loading selected WebSocket session/);
    assert.match(f.els.websocketFramesBody.innerHTML, /Loading captured frames/);
    assert.equal(f.requests.length, 2);
    f.succeed(1, record("fixture-a")); if (loading) await loading; await tick();
    assert.equal(f.state.selectedWebsocketRecord.id, "fixture-a");
    assert.equal(f.state.selectedWebsocketDetailError, "");
  });
}

for (const selected of [true, false]) {
  test(`a confirmed 404 still reconciles a ${selected ? "selected" : "nonselected"} missing connection`, async () => {
    const f = fixture(); f.click("fixture-a");
    if (!selected) { f.click("fixture-b"); f.succeed(1, record("fixture-b")); await tick(); f.clickFrame(1); }
    f.requests[0].resolve({ ok: false, status: 404 }); await tick();
    assert.deepEqual(Array.from(f.state.websocketSessions, row => row.id), ["fixture-b", "fixture-c"]);
    assert.equal(f.state.selectedWebsocketId, "fixture-b");
    if (selected) { f.succeed(1, record("fixture-b")); await tick(); }
    else assert.equal(f.state.selectedFrameIdx, 1, "removing another connection preserves the current frame");
    assert.equal(f.state.selectedWebsocketRecord.id, "fixture-b");
    assert.equal(f.state.selectedWebsocketDetailError, "");
  });
}

for (const frames of [undefined, null, {}, [null, false, 1, frame(0)]]) {
  test(`malformed or omitted frame containers normalize safely (${JSON.stringify(frames)})`, async () => {
    const f = fixture(); f.click("fixture-a"); f.succeed(0, record("fixture-a", { frames })); await tick();
    assert.equal(f.state.selectedWebsocketRecord.id, "fixture-a");
    assert.equal(f.state.selectedWebsocketDetailError, "");
    assert.equal(f.state.selectedWebsocketRecord.frames.length, Array.isArray(frames) ? 1 : 0);
    assert.equal(f.c._websocketDetailPendingPromise, null);
    assert.equal(f.timers.size, 0);
  });
}

for (const outcome of ["success", "network", "HTTP", "JSON success", "JSON failure", "wrong ID"]) {
  for (const change of ["A-B-A", "search return", "session round trip"]) {
    test(`late ${outcome} preserves an already displayed replacement frame after ${change}`, async () => {
      const f = fixture(), body = deferred(); f.click("fixture-a");
      if (outcome.startsWith("JSON")) { f.requests[0].resolve({ ok: true, json: () => body.promise }); await tick(); }
      if (change === "A-B-A") f.click("fixture-b");
      if (change === "search return") { f.els.websocketSearchInput.value = "fixture"; f.els.websocketSearchInput.dispatch("input", {}); }
      if (change === "session round trip") { f.reset("fixture-session-b"); f.reset("fixture-session-a"); }
      f.click("fixture-a");
      for (let i = 1; i < f.requests.length; i++) f.succeed(i, record(f.requests[i].url.match(/websockets\/(fixture-[abc])/)[1]));
      await tick(); f.clickFrame(1);
      assert.equal(f.state.selectedFrameIdx, 1); assert.equal(f.els.frameDetailPanel.classList.contains("hidden"), false);
      const before = f.view(), beforeTimers = [...f.timers.keys()];
      if (outcome === "success") f.succeed(0, record("fixture-a", { frames: [frame(0, "Old fixture")] }));
      if (outcome === "network") f.requests[0].reject(new Error("Old fixture failure"));
      if (outcome === "HTTP") f.requests[0].resolve({ ok: false, status: 503 });
      if (outcome === "JSON success") body.resolve(record("fixture-a", { frames: [frame(0, "Old fixture")] }));
      if (outcome === "JSON failure") body.reject(new Error("Old fixture JSON failure"));
      if (outcome === "wrong ID") f.succeed(0, record("fixture-c"));
      await tick(); assert.equal(f.view(), before); assert.deepEqual([...f.timers.keys()], beforeTimers);
    });
  }
}

for (const failure of ["network", "HTTP", "JSON"]) {
  test(`stale ${failure} cannot cancel the actual delayed loading timer for a newer row`, async () => {
    const f = fixture(), body = deferred(); f.click("fixture-a");
    if (failure === "JSON") { f.requests[0].resolve({ ok: true, json: () => body.promise }); await tick(); }
    f.click("fixture-b"); f.succeed(1, record("fixture-b")); await tick(); f.clickFrame(1); f.click("fixture-c");
    assert.equal(f.els.frameDetailPanel.classList.contains("hidden"), true);
    assert.equal(f.timers.size, 1);
    const timer = f.c._websocketDetailLoadingTimer, before = f.view();
    if (failure === "network") f.requests[0].reject(new Error("Old fixture failure"));
    if (failure === "HTTP") f.requests[0].resolve({ ok: false, status: 503 });
    if (failure === "JSON") body.reject(new Error("Old fixture JSON failure"));
    await tick(); assert.equal(f.view(), before); assert.equal(f.timers.has(timer), true);
    const callback = f.timers.get(timer); f.timers.delete(timer); callback();
    assert.match(f.els.websocketHandshakeCM.textContent, /Loading selected WebSocket session/);
    f.succeed(2, record("fixture-c")); await tick();
    assert.equal(f.state.selectedWebsocketRecord.id, "fixture-c");
    assert.equal(f.c._websocketDetailLoadingTimer, null);
  });
}

for (const [label, payload] of [["null", null], ["empty object", {}], ["array", []],
  ["wrong ID", record("fixture-b", { frames: [frame(0, "Unrelated frame"), frame(1, "Unrelated frame")] })]]) {
  test(`${label} older-frame detail preserves the current frame window and remains retryable`, async () => {
    const f = fixture();
    const saved = record("fixture-a", { frames: [frame(2), frame(3)], frame_count: 4, retained_frame_count: 4, last_frame_index: 3 });
    f.state.websocketSessions[0] = saved; f.click("fixture-a"); f.succeed(0, saved); await tick(); f.clickFrame(3);
    assert.equal(f.state.selectedWebsocketRecord.older_frames_exhausted, false);
    const beforeBody = f.els.frameDetailBody.innerHTML;
    f.clickOlder(); assert.equal(f.requests.length, 2); assert.match(f.requests[1].url, /before_index=2/);
    f.succeed(1, payload); await tick();
    assert.deepEqual(Array.from(f.state.selectedWebsocketRecord.frames, frame => frame.index), [2, 3]);
    assert.equal(f.state.selectedWebsocketRecord.older_frames_loading, false);
    assert.equal(f.state.selectedWebsocketRecord.older_frames_exhausted, false);
    assert.equal(f.state.selectedFrameIdx, 3); assert.equal(f.els.frameDetailBody.innerHTML, beforeBody);
    assert.equal(f.els.frameDetailPanel.classList.contains("hidden"), false);
    assert.ok(f.errors.length > 0, "a malformed page must report a read failure");
    f.clickOlder(); assert.equal(f.requests.length, 3, "the older page must remain retryable");
    f.succeed(2, record("fixture-a")); await tick();
    assert.deepEqual(Array.from(f.state.selectedWebsocketRecord.frames, frame => frame.index), [0, 1, 2, 3]);
    assert.equal(f.state.selectedFrameIdx, 3); assert.equal(f.els.frameDetailBody.innerHTML, beforeBody);
  });
}
