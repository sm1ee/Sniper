// Offline handshake search: run the production input/tab registrations, saved
// record renderer, and shipped CodeMirror search state against synthetic controls.
// No app bootstrap, DOM EditorView, connection, or API request is performed.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");
const bundle = vm.createContext({ console, setTimeout, clearTimeout });
vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/codemirror.bundle.js"), "utf8"), bundle);
const { CM } = bundle;

function productionSlice(startMarker, endMarker) {
  const start = appSource.indexOf(startMarker);
  const end = appSource.indexOf(endMarker, start);
  assert.ok(start >= 0 && end > start, `Missing production block: ${startMarker}`);
  return appSource.slice(start, end);
}
function control() {
  const handlers = new Map(), classes = new Set();
  const node = {
    value: "", innerHTML: "", textContent: "", scrollTop: 0,
    classList: { add: name => classes.add(name), remove: name => classes.delete(name), contains: name => classes.has(name) },
    addEventListener(type, callback) { const callbacks = handlers.get(type) || []; callbacks.push(callback); handlers.set(type, callbacks); },
    dispatch(type, hit = true) {
      for (const callback of handlers.get(type) || []) callback({ target: { closest: () => hit ? {} : null } });
    },
    querySelectorAll: () => [],
  };
  return node;
}
function savedRecord(value, responseValue = value) {
  return { id: "synthetic-saved", path: "/saved", status: 101,
    request: { headers: [{ name: "x-synthetic", value }] },
    response: { headers: [{ name: "x-synthetic", value: responseValue }] },
  };
}
function fixture(record = savedRecord("foo foo ", "foo  foo  ")) {
  const views = {}, els = {};
  for (const name of ["wsHandshakeSearchInput", "wsHandshakeSearchMeta", "wsHandshakeLines", "websocketHandshakeCM",
    "websocketRequestView", "websocketResponseView", "websocketFramesBody"]) els[name] = control();
  const requestButton = control(), responseButton = control();
  requestButton.classList.add("active");
  const state = { selectedWebsocketId: record.id, selectedWebsocketRecord: record, websocketSessions: [record] };
  const c = loadFunctions([
    "normalizeSearchClasses", "normalizeSearchEffectValue", "forEachCodeSearchMatch", "buildSearchDecorations",
    "getCMView", "updateCodePaneCM", "buildSearchMeta", "initCMSearchNavigation", "initSearchHitNavigation",
    "updateWsHandshakeSearch", "updateWsHandshakeLineNumbers", "renderWebsocketSessions",
    "buildRawWebsocketRequest", "buildRawWebsocketResponse", "mergeHeaders", "normalizedHeaders", "headerNameEquals",
    "countLines", "buildLineNumbers", "titleCase",
  ], {
    CM, els, state, _cmViews: views, cmProgrammaticViews: new WeakSet(),
    CM_SEARCH_DECORATION_LIMIT: 5000, CM_DEFAULT_SEARCH_CLASSES: { hit: "tok-search-hit", active: "tok-search-active" },
    MutationObserver: class { observe() {} },
    document: { getElementById: id => ({ wsHandshakeReqBtn: requestButton, wsHandshakeResBtn: responseButton })[id] || null },
    getSortedWebsocketEntries: () => [], renderWebsocketSessionTable() {}, renderWebsocketFrameTable() {},
    cancelWebsocketDetailLoading() {}, hideFrameDetail() {},
    fetch() { assert.fail("Search must never request data"); },
  });
  vm.runInContext(productionSlice("const setSearchQuery = CM.StateEffect.define();", "// Changed-line decoration:"), c);
  vm.runInContext(productionSlice("class SniperCodeView {", "// CodeMirror-based code pane instances") + "\nglobalThis.CodeView = SniperCodeView;", c);
  const field = vm.runInContext("searchDecoField", c);
  const cv = Object.create(c.CodeView.prototype);
  cv._searchNavIndex = -1; cv._hlMode = "http"; cv._editable = false;
  cv.applyChangedLines = () => {};
  cv.view = {
    state: CM.EditorState.create({ doc: "", extensions: [field] }),
    dispatch(transaction) { this.state = this.state.update(transaction).state; },
  };
  views.wsHandshake = cv;
  vm.runInContext(productionSlice("  // WS Handshake search\n", "  bindMessagePaneActivation();"), c);
  vm.runInContext(productionSlice("  // WS Handshake Request/Response tab toggle\n", "  // WS pane swap button"), c);
  c.renderWebsocketSessions();
  const snapshot = () => {
    const value = cv.view.state.field(field);
    return { query: value.query, count: value.matchCount,
      ranges: Array.from(value.matchPositions, (from, i) => [from, value.matchEnds[i]]) };
  };
  const type = query => { els.wsHandshakeSearchInput.value = query; els.wsHandshakeSearchInput.dispatch("input"); };
  const navigate = () => {
    els.wsHandshakeSearchMeta.dispatch("click");
    const selection = cv.view.state.selection.main;
    return [selection.anchor, selection.head];
  };
  return { c, cv, state, els, requestButton, responseButton, snapshot, type, navigate };
}

for (const query of [" ", "  ", " foo", "foo ", " foo ", "\t", "\u00a0"]) {
  test(`typing ${JSON.stringify(query)} uses the same literal search as redraw and Request/Response switching`, () => {
    const f = fixture(savedRecord("foo \t foo  \u00a0", "foo  \t foo \u00a0"));
    f.type(query);
    const typed = f.snapshot(), meta = f.els.wsHandshakeSearchMeta.innerHTML;
    assert.equal(typed.query, query);
    f.c.renderWebsocketSessions();
    assert.deepEqual(f.snapshot(), typed);
    assert.equal(f.els.wsHandshakeSearchMeta.innerHTML, meta);
    f.responseButton.dispatch("click");
    assert.equal(f.snapshot().query, query);
    f.requestButton.dispatch("click");
    assert.deepEqual(f.snapshot(), typed);
    assert.equal(f.els.wsHandshakeSearchInput.value, query);
    for (const range of typed.ranges) assert.deepEqual(f.navigate(), range);
    if (typed.count) assert.deepEqual(f.navigate(), typed.ranges[0], "Next cycles to the first original-text range");
  });
}

for (const query of ["[a.*]", "\\", "<img src=x onerror='fixture'>", "&lt;", "İ", "😀x", "𐐨", "missing", ""]) {
  test(`handshake input preserves literal ${JSON.stringify(query)} and clears active navigation`, () => {
    const f = fixture(savedRecord("[A.*] \\ <img src=x onerror='fixture'> &lt; İ i\u0307 😀X 𐐀"));
    f.type(query);
    const typed = f.snapshot();
    assert.equal(typed.query, query);
    assert.equal(typed.count, query === "missing" || query === "" ? 0 : query === "İ" ? 2 : 1);
    for (const range of typed.ranges) assert.deepEqual(f.navigate(), range);
    f.responseButton.dispatch("click");
    f.type("");
    assert.deepEqual(f.snapshot(), { query: "", count: 0, ranges: [] });
    assert.equal(f.cv.nextSearchMatch(), -1);
    assert.match(f.els.wsHandshakeSearchMeta.innerHTML, /^No highlights/);
    f.requestButton.dispatch("click");
    f.c.renderWebsocketSessions();
    assert.deepEqual(f.snapshot(), { query: "", count: 0, ranges: [] });
  });
}

test("record replacement and missing response rebuild search ranges without retaining old matches", () => {
  const f = fixture(savedRecord("old old", "old"));
  f.type("old"); f.navigate(); f.navigate();
  f.state.selectedWebsocketRecord = savedRecord("new", "new");
  f.c.renderWebsocketSessions();
  assert.equal(f.snapshot().count, 0);
  assert.equal(f.cv.nextSearchMatch(), -1);
  f.state.selectedWebsocketRecord = savedRecord("old");
  delete f.state.selectedWebsocketRecord.response;
  f.c.renderWebsocketSessions();
  assert.equal(f.snapshot().count, 1);
  assert.deepEqual(f.navigate(), f.snapshot().ranges[0]);
  f.responseButton.dispatch("click");
  assert.equal(f.cv.getContent(), "No handshake response was captured.");
  assert.equal(f.snapshot().count, 0);
  f.state.selectedWebsocketId = null; f.state.selectedWebsocketRecord = null; f.state.websocketSessions = [];
  f.c.renderWebsocketSessions();
  assert.equal(f.cv.getContent(), "Select a WebSocket session.");
  assert.equal(f.snapshot().query, "old");
  assert.equal(f.snapshot().count, 0);
});
