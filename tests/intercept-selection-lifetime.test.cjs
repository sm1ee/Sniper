// Production initialization and selection/tab callbacks with synthetic records,
// deferred read-only fetches, and inert actions. No app bootstrap or server.
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
function record(id, body = id) {
  return {
    id, scheme: "https", host: "example.com", method: "GET", path: `/${id}`,
    status: 200, peer_addr: "127.0.0.1:10000", started_at: "2026-01-01T00:00:00Z",
    request: { scheme: "https", host: "example.com", method: "GET", path: `/${body}`,
      headers: [], body: "", body_encoding: "utf8" },
    response: { status: 200, headers: [], body, body_encoding: "utf8" },
  };
}
const modes = {
  request: { queue: "intercepts", selected: "selectedInterceptId", record: "selectedInterceptRecord",
    seed: "interceptEditorSeedId", editor: "interceptRequestEditor", key: "interceptReq",
    table: "interceptTableBody", load: "loadIntercepts", detail: "loadInterceptDetail", render: "renderIntercepts",
    tab: "interceptQueueTabRequest", button: "forwardInterceptButton", build: "buildEditableRawRequest" },
  response: { queue: "responseIntercepts", selected: "selectedResponseInterceptId", record: "selectedResponseInterceptRecord",
    seed: "responseInterceptEditorSeedId", editor: "interceptResponseEditor", key: "interceptRes",
    table: "responseInterceptTableBody", load: "loadResponseIntercepts", detail: "loadResponseInterceptDetail", render: "renderResponseIntercepts",
    tab: "interceptQueueTabResponse", button: "forwardResponseInterceptButton", build: "buildEditableRawResponse" },
};
function fixture(mode, cm = true) {
  const requests = [], errors = [], actions = [], views = new Map();
  const node = () => {
    const handlers = new Map(), classes = new Set();
    return { value: "", innerHTML: "", textContent: "", disabled: false, dataset: {},
      classList: { contains: value => classes.has(value), toggle(value, on) { if (on) classes.add(value); else classes.delete(value); } },
      addEventListener: (type, fn) => handlers.set(type, fn),
      click() { if (!this.disabled) handlers.get("click")?.({ target: this }); },
      querySelectorAll() {
        this.rows = [...this.innerHTML.matchAll(/data-id="([^"]+)"/g)].map(([, id]) => {
          const row = node(); row.dataset.id = id; return row;
        });
        return this.rows;
      },
    };
  };
  const els = {};
  for (const name of [
    "interceptTableBody", "responseInterceptTableBody", "interceptDetailPath", "interceptDetailTitle", "interceptMeta",
    "forwardInterceptButton", "dropInterceptButton", "forwardResponseInterceptButton", "dropResponseInterceptButton",
    "interceptRequestEditor", "interceptResponseEditor", "interceptQueueTabRequest", "interceptQueueTabResponse",
    "interceptRequestTable", "responseInterceptTable", "interceptRequestEditorPanel", "interceptResponseEditorPanel",
    "interceptRequestActions", "responseInterceptActions", "interceptSearchInput", "interceptSearchMeta",
  ]) els[name] = node();
  if (cm) { els.interceptRequestCM = node(); els.interceptResponseCM = node(); }
  const c = loadFunctions([
    "loadIntercepts", "loadInterceptDetail", "loadResponseIntercepts", "loadResponseInterceptDetail",
    "renderIntercepts", "renderResponseIntercepts", "getVisibleRequestInterceptSummaries", "getVisibleResponseInterceptSummaries",
    "reconcileRequestInterceptSelection", "reconcileResponseInterceptSelection", "refreshInterceptDetailsForCurrentSelection",
    "applyInterceptScopeFilterLocally", "switchInterceptQueueTab", "updateInterceptQueueBadges",
    "activeInterceptCMKey", "updateInterceptSearch", "setInterceptPaneContent",
    "buildEditableRawRequest", "buildEditableRawResponse", "normalizedHeaders", "mergeHeaders", "headerNameEquals",
    "currentSessionId", "sessionQueryPath", "jsonArray",
    "createHistoryPagingState", "createWebsocketPagingState", "createDefaultFilterSettings", "createDefaultDisplaySettings",
  ], {
    els, URL, URLSearchParams, TextEncoder, document: { getElementById: () => null },
    HTTP_HISTORY_PAGE_SIZE: 250, WEBSOCKET_PAGE_SIZE: 100, DEFAULT_HISTORY_COLUMN_ORDER: [],
    createDefaultHistoryColumnWidths: () => ({}), createDefaultWsColumnWidths: () => ({}),
    console: { ...console, error: error => errors.push(error) },
    getCMView: key => views.get(key),
    updateCodePaneCM(key, _container, text) {
      views.set(key, { text, getContent: () => text, applySearch: () => ({ matchCount: 0 }), view: { state: { doc: { lines: 1 } } } });
      return { lineCount: 1, matchCount: 0 };
    },
    buildSearchMeta: () => "", escapeHtml: value => value, formatTimestamp: value => value,
    renderInterceptRequestHighlight() {}, renderInterceptResponseHighlight() {}, renderInterceptRules() {},
    isInScopeHost: host => host === "example.com", showToast: () => assert.fail("No toast expected"),
    requireOkResponse: async response => { if (!response.ok) throw new Error("Fixture read failed"); },
    fetch(url, options) {
      assert.equal(options, undefined, "only read-only fetches are permitted");
      assert.match(url, /^\/api\/(?:response-)?intercepts(?:\/held-[ab])?\?session_id=session-[ab]$/);
      const request = { url, ...deferred() }; requests.push(request); return request.promise;
    },
  });
  const initial = appSource.match(/^const state = \{[^]*?^\};/m);
  assert.ok(initial, "real state initializer");
  vm.runInContext(initial[0] + "\nglobalThis.fixtureState = state;", c);
  const state = c.fixtureState, config = modes[mode];
  state.activeSession = { id: "session-a" };
  for (const name of ["forwardSelectedIntercept", "dropSelectedIntercept", "forwardSelectedResponseIntercept", "dropSelectedResponseIntercept"]) {
    c[name] = async () => actions.push(name);
  }
  const start = appSource.indexOf('  els.forwardInterceptButton.addEventListener("click",');
  const end = appSource.indexOf('\n  if (els.interceptSearchInput)', start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(appSource.slice(start, end), c);
  const click = id => els[config.table].rows.find(row => row.dataset.id === id).click();
  const respond = (index, value) => requests[index].resolve({ ok: true, json: async () => value });
  const content = () => cm ? views.get(config.key)?.text || "" : els[config.editor].value;
  const labels = () => JSON.stringify([els.interceptDetailPath.textContent, els.interceptDetailTitle.textContent, els.interceptMeta.textContent]);
  const reset = () => {
    const source = appSource.match(/^function resetSessionScopedUiState\([^]*?^\}/m)[0];
    const start = source.indexOf("  state.intercepts = [];");
    const end = source.indexOf("  state.websocketSessions = [];", start);
    assert.ok(start >= 0 && end > start);
    vm.runInContext(source.slice(start, end), c);
  };
  const show = (records = [record("held-a"), record("held-b")]) => {
    state[config.queue] = records; c[config.render](); els[config.tab].click();
  };
  const ready = async () => { show(); click("held-a"); respond(requests.length - 1, record("held-a")); await tick(); };
  return { c, state, config, els, views, requests, errors, actions, click, respond, content, labels, reset, show, ready,
    load: () => c[config.load](), detail: id => c[config.detail](id), raw: value => c[config.build](value[mode]) };
}

for (const mode of Object.keys(modes)) for (const cm of [true, false]) {
  const label = `${mode} ${cm ? "CodeMirror" : "fallback"}`;
  test(`${label}: older queue snapshots cannot resurrect a removed record`, async () => {
    const f = fixture(mode, cm); await f.ready();
    const older = f.load(), newer = f.load();
    f.respond(2, []); await newer;
    assert.equal(f.content(), "");
    f.respond(1, [record("held-a")]); await tick();
    // Settle any unwanted old-detail read so baseline failures stay bounded.
    if (f.requests[3]) f.respond(3, record("held-a"));
    await older;
    assert.equal(f.state[f.config.queue].length, 0);
    assert.equal(f.content(), ""); assert.equal(f.els[f.config.button].disabled, true);
  });

  test(`${label}: a pending or failed newer queue read does not discard a usable older snapshot`, async () => {
    const f = fixture(mode, cm);
    const older = f.load(), newer = f.load();
    const failed = assert.rejects(newer, /Fixture network failure/);
    f.requests[1].reject(new Error("Fixture network failure")); await failed;
    f.respond(0, [record("held-a")]); await tick();
    f.respond(2, record("held-a")); await older;
    assert.equal(f.content(), f.raw(record("held-a")));
    const first = f.load(), pending = f.load();
    f.respond(3, [record("held-b")]); await tick(); f.respond(5, record("held-b")); await first;
    assert.equal(f.state[f.config.selected], "held-b");
    f.respond(4, []); await pending; assert.equal(f.content(), "");
  });

  for (const late of ["success", "http-error", "network-error", "body-error"]) {
    test(`${label}: stale queue ${late} cannot change a newer empty queue`, async () => {
      const f = fixture(mode, cm), body = deferred();
      const older = f.load();
      if (late === "success" || late === "body-error") {
        f.requests[0].resolve({ ok: true, json: () => body.promise }); await tick();
      }
      const newer = f.load(); f.respond(1, []); await newer;
      if (late === "success") body.resolve([record("held-a")]);
      if (late === "http-error") f.requests[0].resolve({ ok: false });
      if (late === "network-error") f.requests[0].reject(new Error("Old fixture failure"));
      if (late === "body-error") body.reject(new Error("Old fixture body failure"));
      await tick();
      if (f.requests[2]) f.respond(2, record("held-a"));
      await older;
      assert.equal(f.requests.length, 2); assert.equal(f.state[f.config.queue].length, 0);
      assert.equal(f.content(), "");
    });
  }

  for (const late of ["success", "http-error", "network-error", "body-error"]) {
    test(`${label}: late ${late} cannot replace a newer same-ID detail`, async () => {
      const f = fixture(mode, cm); f.show(); f.click("held-a");
      const body = deferred();
      if (late === "body-error") { f.requests[0].resolve({ ok: true, json: () => body.promise }); await tick(); }
      f.click("held-a");
      f.respond(1, record("held-a", "current")); await tick();
      const before = f.content(), labels = f.labels();
      if (late === "success") f.respond(0, record("held-a", "stale"));
      if (late === "http-error") f.requests[0].resolve({ ok: false });
      if (late === "network-error") f.requests[0].reject(new Error("Old fixture failure"));
      if (late === "body-error") body.reject(new Error("Old fixture body failure"));
      await tick();
      assert.equal(f.state[f.config.record].request.path, "/current");
      assert.equal(f.content(), before); assert.equal(f.labels(), labels); assert.equal(f.errors.length, 0);
    });
  }

  test(`${label}: A to B to A selection ignores the first A before current A loads`, async () => {
    const f = fixture(mode, cm); f.show(); f.click("held-a"); f.click("held-b"); f.click("held-a");
    f.respond(0, record("held-a", "stale")); await tick();
    assert.equal(f.content(), ""); assert.equal(f.els[f.config.button].disabled, true);
    f.respond(2, record("held-a", "current")); f.respond(1, record("held-b")); await tick();
    assert.equal(f.content(), f.raw(record("held-a", "current")));
  });

  test(`${label}: session return invalidates an old same-session queue and detail`, async () => {
    const f = fixture(mode, cm); f.show(); f.click("held-a"); const loading = f.load();
    f.state.activeSession = { id: "session-b" }; f.reset();
    f.state.activeSession = { id: "session-a" }; f.reset(); f.show();
    f.respond(0, record("held-a", "stale")); f.respond(1, [record("held-b")]); await tick();
    if (f.requests[2]) f.respond(2, record("held-b"));
    await loading;
    assert.equal(f.state[f.config.selected], "held-a"); assert.equal(f.content(), "");
    assert.equal(f.els[f.config.button].disabled, true);
  });

  test(`${label}: omitted optional metadata is replaced without discarding the editor draft`, async () => {
    const f = fixture(mode, cm); f.show(); f.click("held-a");
    const initial = record("held-a"); initial.is_websocket = true; initial.request.preview_truncated = true;
    f.respond(0, initial); await tick();
    const draft = "local synthetic draft";
    if (cm) f.views.get(f.config.key).text = draft; else f.els[f.config.editor].value = draft;
    const pending = f.detail("held-a"); f.respond(1, record("held-a")); await pending;
    assert.equal(f.state[f.config.record].is_websocket, undefined);
    assert.equal(f.state[f.config.record].request.preview_truncated, undefined);
    assert.equal(f.content(), draft);
    assert.doesNotMatch(f.els.interceptMeta.textContent, /WebSocket|preview-truncated/);
  });
}

for (const cm of [true, false]) {
  test(`request refreshes cannot change response-tab labels (${cm ? "CodeMirror" : "fallback"})`, async () => {
    const f = fixture("response", cm); await f.ready();
    const before = f.labels();
    f.state.intercepts = [record("held-b")]; f.c.renderIntercepts();
    assert.equal(f.labels(), before, "empty request detail must not own response labels");
    f.state.selectedInterceptRecord = record("held-b"); f.c.renderIntercepts();
    assert.equal(f.labels(), before, "loaded request detail must not own response labels");
  });

  test(`hidden response editor is cleared when its owner is removed (${cm ? "CodeMirror" : "fallback"})`, async () => {
    const f = fixture("response", cm); await f.ready();
    f.els.interceptQueueTabRequest.click();
    f.state.responseIntercepts = []; f.c.renderResponseIntercepts();
    assert.equal(f.content(), ""); assert.equal(f.state.responseInterceptEditorSeedId, null);
    f.els.interceptQueueTabResponse.click(); assert.equal(f.content(), "");
    assert.equal(f.actions.length, 0, "all action callbacks remain inert");
  });
}
