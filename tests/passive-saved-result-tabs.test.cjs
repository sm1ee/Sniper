// Passive view controls only; extract no execution, request, or workflow handlers.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");
const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");

function classes(initial = "") {
  const set = new Set(initial.split(/\s+/).filter(Boolean));
  return {
    contains: value => set.has(value),
    add: value => set.add(value), remove: value => set.delete(value),
    toggle(value, on = !set.has(value)) { if (on) set.add(value); else set.delete(value); },
  };
}

function fixture() {
  const tabs = [...html.matchAll(/<button\b([^>]*\bclass="[^"]*\bview-tab\b[^"]*"[^>]*)>/g)].map(([, attrs]) => {
    const dataset = {}, handlers = [];
    for (const [, key, value] of attrs.matchAll(/data-([a-z-]+)="([^"]*)"/g)) {
      dataset[key.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
    }
    return {
      dataset, handlers, classList: classes(attrs.match(/class="([^"]*)"/)[1]),
      addEventListener(type, callback) { assert.equal(type, "click"); handlers.push(callback); },
      click() { handlers.forEach(callback => callback()); },
    };
  });
  const http = tabs.filter(tab => "target" in tab.dataset);
  const saved = tabs.filter(tab => "fuzzerDetailTarget" in tab.dataset);
  // Pretty, Raw and Hex on both sides, plus Render on the response.
  assert.equal(http.length, 7);
  assert.equal(saved.length, 7);
  const state = {
    activeTool: "fuzzer", selectedId: "synthetic-http", selectedRecord: null,
    messageViews: { request: "raw", response: "hex" }, showOriginal: { request: false, response: false },
    _fuzzerDetailRecord: { id: "synthetic-result" },
  };
  const modes = { request: "raw", response: "hex" };
  const renders = { http: 0, saved: 0 };
  const els = {};
  for (const name of [
    "detailTitle", "detailTags", "attributesCount", "protocolStrip", "summaryList", "requestHeaderCount",
    "responseHeaderCount", "requestHeadersBody", "responseHeadersBody", "notesCard", "requestMrToggle", "responseMrToggle",
  ]) els[name] = { classList: classes() };
  const document = {
    querySelectorAll(selector) {
      if (selector === ".view-tab") return tabs;
      if (selector === ".view-tab[data-target][data-view]") return http;
      if (selector === ".mr-btn") return [];
      if (selector === ".fuzzer-detail-view-tab") return saved;
      const match = selector.match(/^\.fuzzer-detail-view-tab\[data-fuzzer-detail-target="(request|response)"\]$/);
      if (match) return saved.filter(tab => tab.dataset.fuzzerDetailTarget === match[1]);
      assert.fail(`Unexpected selector: ${selector}`);
    },
  };
  const pending = [];
  const c = loadFunctions(["renderViewTabs", "syncFuzzerDetailTabs", "loadTransactionDetail", "renderDetail"], {
    state, els, document, _fuzzerDetailViewModes: modes, _historyDetailGeneration: 0,
    renderMessagePanes() { renders.http += 1; },
    renderFuzzerDetailPanes() { renders.saved += 1; c.syncFuzzerDetailTabs(); },
    currentSessionId: () => "synthetic-session", transactionPath: () => "/synthetic-only",
    fetch() { return new Promise(resolve => pending.push(resolve)); },
    observeAnnotationRevision() {}, cancelHistoryDetailLoading() {}, inferProtocolState: () => ({}),
    normalizedHeaders: () => [], formatTimestamp: () => "-", formatSize: () => "0 B",
    renderProtocolStrip: () => "", renderSummaryRows: () => "", renderHeaderList: () => "",
  });
  const declaration = appSource.match(/^const viewTabs = .+;$/m)?.[0];
  assert.ok(declaration);
  vm.runInContext(declaration, c);
  const start = appSource.indexOf("  viewTabs.forEach((tab) => {", appSource.indexOf("function bindEvents()"));
  const end = appSource.indexOf('\n  document.querySelectorAll(".mr-btn")', start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(appSource.slice(start, end), c);
  const savedStart = appSource.indexOf('  document.querySelectorAll(".fuzzer-detail-view-tab").forEach((btn) => {');
  const savedEnd = appSource.indexOf('\n  onClickWithProgress(document.getElementById("newSequenceButton")', savedStart);
  assert.ok(savedStart >= 0 && savedEnd > savedStart);
  vm.runInContext(appSource.slice(savedStart, savedEnd), c);
  c.syncFuzzerDetailTabs();
  return { c, http, saved, state, modes, renders, pending };
}

function activeSaved(f) {
  return f.saved.filter(tab => tab.classList.contains("active"))
    .map(tab => `${tab.dataset.fuzzerDetailTarget}/${tab.dataset.fuzzerDetailView}`);
}

test("actual markup view controls each receive only their own passive click callback", () => {
  const f = fixture();
  for (const tab of [...f.http, ...f.saved]) assert.equal(tab.handlers.length, 1);
});

for (const side of ["request", "response"]) {
  for (const mode of ["pretty", "raw", "hex"]) {
    test(`saved-result ${side} ${mode} click preserves HTTP view state and rendering`, () => {
      const f = fixture();
      const previous = Object.keys(f.state.messageViews);
      const values = JSON.stringify(f.state.messageViews);
      f.saved.find(tab => tab.dataset.fuzzerDetailTarget === side && tab.dataset.fuzzerDetailView === mode).click();
      assert.deepEqual(Object.keys(f.state.messageViews), previous);
      assert.equal(JSON.stringify(f.state.messageViews), values);
      assert.equal(f.renders.http, 0);
      assert.equal(f.renders.saved, 1);
      assert.equal(f.modes[side], mode);
      assert.deepEqual(activeSaved(f), [`request/${f.modes.request}`, `response/${f.modes.response}`]);
    });

    test(`HTTP ${side} ${mode} click preserves saved-result modes and active tabs`, () => {
      const f = fixture();
      f.http.find(tab => tab.dataset.target === side && tab.dataset.view === mode).click();
      assert.equal(f.state.messageViews[side], mode);
      assert.equal(f.renders.http, 1);
      assert.equal(f.renders.saved, 0);
      assert.deepEqual(activeSaved(f), ["request/raw", "response/hex"]);
      const activeHttp = f.http.filter(tab => tab.classList.contains("active"));
      assert.equal(activeHttp.length, 2);
      assert.ok(activeHttp.some(tab => tab.dataset.target === side && tab.dataset.view === mode));
    });
  }
}

test("HTTP response render click preserves saved-result modes and active tabs", () => {
  const f = fixture();
  f.http.find(tab => tab.dataset.target === "response" && tab.dataset.view === "render").click();
  assert.equal(f.state.messageViews.response, "render");
  assert.equal(f.renders.http, 1);
  assert.equal(f.renders.saved, 0);
  assert.deepEqual(activeSaved(f), ["request/raw", "response/hex"]);
});

test("saved-result response render click preserves HTTP view state", () => {
  const f = fixture();
  const values = JSON.stringify(f.state.messageViews);
  f.saved.find(tab => tab.dataset.fuzzerDetailTarget === "response" && tab.dataset.fuzzerDetailView === "render").click();
  assert.equal(JSON.stringify(f.state.messageViews), values);
  assert.equal(f.renders.http, 0);
  assert.equal(f.renders.saved, 1);
  assert.equal(f.modes.response, "render");
});

test("HTTP detail rendering leaves visible saved-result mode highlights alone", () => {
  const f = fixture();
  f.c.renderDetail({ id: "synthetic-http", request: {}, response: {} });
  assert.equal(f.state.activeTool, "fuzzer");
  assert.deepEqual(activeSaved(f), ["request/raw", "response/hex"]);
});

test("a delayed HTTP detail completion preserves the newer visible saved-result highlights", async () => {
  const f = fixture();
  f.state.activeTool = "proxy";
  const reading = f.c.loadTransactionDetail("synthetic-http");
  f.state.activeTool = "fuzzer";
  f.c.syncFuzzerDetailTabs();
  f.pending[0]({ ok: true, json: async () => ({ id: "synthetic-http", request: {}, response: {} }) });
  await reading;
  assert.equal(f.state.selectedRecord.id, "synthetic-http");
  assert.equal(f.state.activeTool, "fuzzer");
  assert.deepEqual(activeSaved(f), ["request/raw", "response/hex"]);
});
