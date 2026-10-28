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
  const document = { activeElement: null, body: { tagName: "BODY" }, getElementById: () => null };
  const node = () => {
    const handlers = new Map(), classes = new Set();
    let text = "", textWrites = 0, disabled = false;
    const attributes = new Map();
    return { value: "", innerHTML: "", dataset: {},
      get disabled() { return disabled; },
      set disabled(value) {
        disabled = value;
        // Model the native-button blur observed in the root browser. ARIA does
        // not suppress native clicks or remove the element from Tab order.
        if (value && document.activeElement === this) document.activeElement = document.body;
      },
      focus() { if (!disabled && !classes.has("hidden")) document.activeElement = this; },
      getAttribute: name => attributes.get(name) ?? null,
      setAttribute: (name, value) => attributes.set(name, value),
      get textContent() { return text; }, set textContent(value) { textWrites++; text = value; },
      get textWrites() { return textWrites; },
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
    "interceptDetailRetryButton", "interceptDetailStatus",
    "forwardInterceptButton", "dropInterceptButton", "forwardResponseInterceptButton", "dropResponseInterceptButton",
    "interceptRequestEditor", "interceptResponseEditor", "interceptQueueTabRequest", "interceptQueueTabResponse",
    "interceptRequestTable", "responseInterceptTable", "interceptRequestEditorPanel", "interceptResponseEditorPanel",
    "interceptRequestActions", "responseInterceptActions", "interceptSearchInput", "interceptSearchMeta",
  ]) els[name] = node();
  if (cm) { els.interceptRequestCM = node(); els.interceptResponseCM = node(); }
  const c = loadFunctions([
    "loadIntercepts", "loadInterceptDetail", "loadResponseIntercepts", "loadResponseInterceptDetail",
    "renderIntercepts", "renderResponseIntercepts", "getVisibleRequestInterceptSummaries", "getVisibleResponseInterceptSummaries",
    "getInterceptDraftRecovery", "captureInterceptDraftRecoveryOwners", "handleInterceptDraftReadFailure", "takeInterceptDraftRecovery",
    "selectInterceptQueueItem", "getInterceptDetailRead", "updateInterceptDetailFeedback", "retrySelectedInterceptDetail", "updateInterceptQueueSelectionStatus", "scrollSelectedInterceptRowIntoView",
    "reconcileRequestInterceptSelection", "reconcileResponseInterceptSelection", "refreshInterceptDetailsForCurrentSelection",
    "applyInterceptScopeFilterLocally", "switchInterceptQueueTab", "updateInterceptQueueBadges",
    "activeInterceptCMKey", "updateInterceptSearch", "setInterceptPaneContent",
    "buildEditableRawRequest", "buildEditableRawResponse", "normalizedHeaders", "mergeHeaders", "headerNameEquals",
    "currentSessionId", "sessionQueryPath", "jsonArray",
    "createHistoryPagingState", "createWebsocketPagingState", "createDefaultFilterSettings", "createDefaultDisplaySettings",
  ], {
    els, URL, URLSearchParams, TextEncoder, document, workspaceStateGeneration: 0,
    HTTP_HISTORY_PAGE_SIZE: 250, WEBSOCKET_PAGE_SIZE: 100, DEFAULT_HISTORY_COLUMN_ORDER: [],
    createDefaultHistoryColumnWidths: () => ({}), createDefaultWsColumnWidths: () => ({}),
    console: { ...console, error: error => errors.push(error) },
    getCMView: key => views.get(key),
    updateCodePaneCM(key, _container, text, options) {
      views.set(key, { text, options, getContent: () => text, applySearch: () => ({ matchCount: 0 }), view: { state: { doc: { lines: 1 } } } });
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
  return { c, state, config, els, views, requests, errors, actions, document, click, respond, content, labels, reset, show, ready,
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
      const before = f.content(), labels = f.labels(), status = f.els.interceptDetailStatus.textContent;
      if (late === "success") f.respond(0, record("held-a", "stale"));
      if (late === "http-error") f.requests[0].resolve({ ok: false });
      if (late === "network-error") f.requests[0].reject(new Error("Old fixture failure"));
      if (late === "body-error") body.reject(new Error("Old fixture body failure"));
      await tick();
      assert.equal(f.state[f.config.record].request.path, "/current");
      assert.equal(f.content(), before); assert.equal(f.labels(), labels); assert.equal(f.errors.length, 0);
      assert.equal(f.els.interceptDetailStatus.textContent, status);
      assert.equal(f.els.interceptDetailRetryButton.classList.contains("hidden"), true);
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


// Detail feedback uses the same production selection/read/render paths as the
// lifetime cases above. All retries remain deferred reads with inert actions.
for (const mode of Object.keys(modes)) for (const cm of [true, false]) {
  const label = `${mode} ${cm ? "CodeMirror" : "fallback"} detail feedback`;
  test(`${label}: empty, selected pending and ready are distinct`, async () => {
    const f = fixture(mode, cm); f.show([]);
    assert.equal(f.els.interceptDetailTitle.textContent, `No ${mode} selected`);
    assert.equal(f.els.interceptDetailRetryButton.classList.contains("hidden"), true);
    f.show(); f.click("held-b");
    assert.equal(f.els.interceptDetailTitle.textContent, `Loading ${mode}…`);
    assert.equal(f.els.interceptMeta.textContent, `Loading selected ${mode} details.`);
    assert.equal(f.els.interceptDetailStatus.textContent, `Loading selected ${mode} details.`);
    assert.equal(f.els[f.config.button].disabled, true);
    if (cm) assert.equal(f.views.get(f.config.key).options.placeholder, `Loading selected ${mode} details…`);
    else assert.equal(f.els[f.config.editor].placeholder, `Loading selected ${mode} details…`);
    const announcements = f.els.interceptDetailStatus.textWrites;
    f.c[f.config.render](); f.c[f.config.render]();
    assert.equal(f.els.interceptDetailStatus.textWrites, announcements, "identical pending renders do not announce again");
    f.respond(0, record("held-b")); await tick();
    assert.equal(f.els.interceptDetailStatus.textContent, "");
    assert.equal(f.els.interceptDetailRetryButton.classList.contains("hidden"), true);
    assert.equal(f.content(), f.raw(record("held-b")));
    if (!cm) assert.equal(f.els[f.config.editor].placeholder, "");
    assert.equal(f.els[f.config.button].disabled, false);
    assert.equal(f.actions.length, 0);
  });

  for (const failure of ["HTTP", "network", "JSON"]) test(`${label}: ${failure} error offers one keyboard-reachable, deduplicated retry`, async () => {
    const f = fixture(mode, cm); f.show([record("held-a")]); f.click("held-a");
    if (failure === "HTTP") f.requests[0].resolve({ ok: false, text: () => assert.fail("Never read a raw failure body") });
    if (failure === "network") f.requests[0].reject(new Error("synthetic private failure text"));
    if (failure === "JSON") f.requests[0].resolve({ ok: true, json: async () => { throw new Error("synthetic private JSON text"); } });
    await tick();
    assert.equal(f.els.interceptDetailTitle.textContent, `Could not load ${mode}`);
    assert.equal(f.els.interceptMeta.textContent, `Could not load ${mode} details. Retry to try again.`);
    assert.doesNotMatch(f.labels(), /private/);
    for (const error of f.errors) assert.doesNotMatch(String(error), /private/, "reported detail errors never expose parser or transport text");
    const button = f.els.interceptDetailRetryButton;
    assert.equal(button.classList.contains("hidden"), false); assert.equal(button.disabled, false);
    assert.equal(button.getAttribute("aria-disabled"), "false");
    assert.equal(button.textContent, "Retry detail");
    assert.equal(f.els[f.config.button].disabled, true);
    const announcements = f.els.interceptDetailStatus.textWrites;
    f.c[f.config.render](); f.c[f.config.render]();
    assert.equal(f.els.interceptDetailStatus.textWrites, announcements);
    button.click(); button.click(); f.c.retrySelectedInterceptDetail();
    assert.equal(f.requests.length, 2, "repeated retry activation cannot duplicate its pending GET");
    assert.equal(button.disabled, false); assert.equal(button.classList.contains("hidden"), false);
    assert.equal(button.getAttribute("aria-disabled"), "true");
    assert.equal(button.getAttribute("aria-busy"), "true");
    assert.equal(button.textContent, "Retrying…");
    assert.equal(f.els.interceptDetailTitle.textContent, `Loading ${mode}…`);
    f.respond(1, record("held-a")); await tick();
    assert.equal(button.classList.contains("hidden"), true); assert.equal(f.content(), f.raw(record("held-a")));
    assert.equal(button.textContent, "Retry detail");
    assert.equal(f.actions.length, 0);
  });

  test(`${label}: stale selection/session failure cannot own the current feedback or retry`, async () => {
    const f = fixture(mode, cm); f.show(); f.click("held-a"); f.click("held-b");
    f.requests[0].resolve({ ok: false }); await tick();
    assert.equal(f.els.interceptDetailTitle.textContent, `Loading ${mode}…`);
    assert.equal(f.els.interceptDetailRetryButton.classList.contains("hidden"), true);
    f.state.activeSession = { id: "session-b" }; f.reset();
    f.state.activeSession = { id: "session-a" }; f.reset(); f.show(); f.click("held-a");
    f.requests[1].reject(new Error("retired failure")); await tick();
    assert.equal(f.els.interceptDetailTitle.textContent, `Loading ${mode}…`);
    assert.equal(f.els.interceptDetailRetryButton.classList.contains("hidden"), true);
    f.respond(2, record("held-a")); await tick();
    assert.equal(f.els.interceptDetailStatus.textContent, ""); assert.equal(f.errors.length, 0);
    f.show([]); const count = f.requests.length; await f.c.retrySelectedInterceptDetail();
    assert.equal(f.requests.length, count); assert.equal(f.els.interceptDetailTitle.textContent, `No ${mode} selected`);
  });

  test(`${label}: same-ID background reads retain draft, actions and quiet feedback`, async () => {
    const f = fixture(mode, cm); await f.ready();
    const draft = "local synthetic draft";
    if (cm) f.views.get(f.config.key).text = draft; else f.els[f.config.editor].value = draft;
    const before = f.labels(), announcements = f.els.interceptDetailStatus.textWrites;
    const pending = f.detail("held-a");
    assert.equal(f.content(), draft); assert.equal(f.labels(), before); assert.equal(f.els[f.config.button].disabled, false);
    f.respond(1, record("held-a")); await pending;
    assert.equal(f.content(), draft); assert.equal(f.els.interceptDetailStatus.textWrites, announcements);
    assert.equal(f.actions.length, 0);
  });

  for (const failure of ["HTTP", "network", "JSON"]) test(`${label}: failed same-ID ${failure} refresh preserves baseline draft/action rules`, async () => {
    const f = fixture(mode, cm); await f.ready();
    const draft = "local synthetic draft";
    if (cm) f.views.get(f.config.key).text = draft; else f.els[f.config.editor].value = draft;
    const pending = f.detail("held-a");
    const settled = failure === "HTTP" ? pending : assert.rejects(pending, (error) => {
      assert.doesNotMatch(String(error), /private/); assert.match(String(error), /Could not load/); return true;
    });
    if (failure === "HTTP") f.requests[1].resolve({ ok: false, text: () => assert.fail("Never read a raw failure body") });
    if (failure === "network") f.requests[1].reject(new Error("synthetic private refresh error"));
    if (failure === "JSON") f.requests[1].resolve({ ok: true, json: async () => { throw new Error("synthetic private refresh JSON"); } });
    await settled;
    // HTTP failures already invalidate the actionable record; this feedback-only
    // change must not enable forwarding an unavailable held item.
    assert.equal(f.content(), failure === "HTTP" ? "" : draft);
    assert.equal(f.els[f.config.button].disabled, failure === "HTTP");
    assert.equal(f.els.interceptDetailRetryButton.disabled, false);
    assert.equal(f.els.interceptDetailRetryButton.classList.contains("hidden"), false);
    assert.equal(f.els.interceptMeta.textContent, `Could not ${failure === "HTTP" ? "load" : "refresh"} ${mode} details. Retry to try again.`);
    const retry = f.c.retrySelectedInterceptDetail();
    assert.equal(f.requests.length, 3); f.respond(2, record("held-a")); await retry;
    assert.equal(f.content(), failure === "HTTP" ? f.raw(record("held-a")) : draft);
    assert.equal(f.els[f.config.button].disabled, false); assert.equal(f.actions.length, 0);
  });

  test(`${label}: repeated background failures do not reannounce the same error`, async () => {
    const f = fixture(mode, cm); f.show([record("held-a")]); f.click("held-a");
    f.requests[0].resolve({ ok: false }); await tick();
    const status = f.els.interceptDetailStatus.textContent, announcements = f.els.interceptDetailStatus.textWrites;
    const pending = f.detail("held-a");
    assert.equal(f.els.interceptDetailStatus.textContent, status);
    assert.equal(f.els.interceptDetailRetryButton.disabled, false);
    assert.equal(f.els.interceptDetailRetryButton.getAttribute("aria-disabled"), "true");
    assert.equal(f.els.interceptDetailRetryButton.textContent, "Retrying…");
    f.requests[1].resolve({ ok: false }); await pending;
    assert.equal(f.els.interceptDetailRetryButton.textContent, "Retry detail");
    assert.equal(f.els.interceptDetailStatus.textWrites, announcements);
    const retry = f.c.retrySelectedInterceptDetail();
    assert.equal(f.els.interceptDetailStatus.textContent, `Loading selected ${mode} details.`);
    f.respond(2, record("held-a")); await retry;
    assert.equal(f.els.interceptDetailStatus.textContent, "");
  });

  test(`${label}: hidden failure cannot replace the other queue feedback`, async () => {
    const f = fixture(mode, cm); f.show(); f.click("held-a");
    f.c.switchInterceptQueueTab(mode === "request" ? "response" : "request");
    const before = f.labels(), status = f.els.interceptDetailStatus.textContent;
    f.requests[0].resolve({ ok: false }); await tick();
    assert.equal(f.labels(), before); assert.equal(f.els.interceptDetailStatus.textContent, status);
    assert.equal(f.els.interceptDetailRetryButton.classList.contains("hidden"), true);
    f.c.switchInterceptQueueTab(mode);
    assert.equal(f.els.interceptDetailTitle.textContent, `Could not load ${mode}`);
    assert.equal(f.els.interceptDetailRetryButton.classList.contains("hidden"), false);
  });
}

test("detail retry is a native button and status is polite, atomic and scoped to detail", () => {
  const html = require("node:fs").readFileSync(require.resolve("../web/index.html"), "utf8");
  assert.match(html, /<button[^>]*class="[^"]*hidden[^"]*"[^>]*id="interceptDetailRetryButton"[^>]*type="button"[^>]*>Retry detail<\/button>/);
  assert.match(html, /id="interceptDetailStatus"[^>]*role="status"[^>]*aria-live="polite"[^>]*aria-atomic="true"/);
});

// Capture only the shipped interval callback, not app initialization. Each tick
// runs the real auxiliary poll and both real queue loaders against deferred reads.
function auxiliaryInterval(f) {
  f.state.activeTool = "proxy"; f.state.activeProxyTab = "intercept";
  Object.assign(f.c, { isWebsocketHistoryVisible: () => false, shouldPollFindingsBadge: () => false,
    _interceptToggleInFlight: true });
  vm.runInContext(appSource.match(/^async function pollAuxiliaryData\([^]*?^\}/m)[0], f.c);
  let callback, period;
  f.c.window = { setInterval(fn, milliseconds) { callback = fn; period = milliseconds; return 1; } };
  const start = appSource.indexOf("  auxTimer = window.setInterval(");
  const end = appSource.indexOf("\n  renderToolPanels();", start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(appSource.slice(start, end), f.c);
  assert.equal(period, 1200, "keep the shipped polling cadence unchanged");
  return { callback, period };
}

for (const mode of Object.keys(modes)) for (const outcome of ["success", "HTTP 503", "JSON success"]) {
  test(`${mode}: actual 1200 ms interval cannot starve a 6000 ms detail ${outcome}`, async () => {
    const f = fixture(mode), { callback, period } = auxiliaryInterval(f);
    let now = 0, accepted = 0;
    const fetch = f.c.fetch;
    f.c.fetch = (url, options) => { const promise = fetch(url, options); f.requests.at(-1).started = now; return promise; };
    const isDetail = request => /\/held-[ab]\?/.test(request.url);
    const settle = request => {
      request.settled = true;
      if (outcome === "JSON success") request.body.resolve(record("held-b"));
      else request.resolve(outcome === "success" ? { ok: true, json: async () => record("held-b") } : { ok: false, status: 503 });
    };
    f.show(); f.click("held-b");
    for (let step = 1; step <= 14; step++) {
      now = step * period; callback();
      for (const request of f.requests.filter(request => !isDetail(request) && !request.settled)) {
        request.settled = true;
        const requestQueue = !request.url.includes("response-intercepts");
        request.resolve({ ok: true, json: async () => requestQueue === (mode === "request") ? [record("held-a"), record("held-b")] : [] });
      }
      await tick();
      if (outcome === "JSON success") {
        for (const request of f.requests.filter(request => isDetail(request) && !request.body)) {
          request.body = deferred(); request.resolve({ ok: true, json: () => request.body.promise });
        }
        await tick();
      }
      const due = f.requests.filter(request => isDetail(request) && !request.settled && now - request.started >= 6000);
      for (const request of due) settle(request);
      await tick();
      if (due.length) {
        accepted++;
        if (outcome !== "HTTP 503") {
          assert.equal(f.state[f.config.record]?.id, "held-b", "the completed slow read must own the selected detail");
          assert.equal(f.content(), f.raw(record("held-b")));
          assert.equal(f.els[f.config.button].disabled, false);
        } else {
          assert.equal(f.els.interceptDetailTitle.textContent, `Could not load ${mode}`);
          assert.equal(f.els.interceptDetailRetryButton.classList.contains("hidden"), false);
          assert.equal(f.els.interceptDetailRetryButton.disabled, false);
          assert.equal(f.els[f.config.button].disabled, true);
        }
      }
    }
    assert.equal(accepted, 2, "both slow outcomes become visible while interval polling continues");
    assert.equal(f.requests.filter(isDetail).length, 3, "background ticks reuse the owned pending detail rather than superseding it");
    for (const request of f.requests.filter(request => isDetail(request) && !request.settled)) settle(request);
    await tick(); assert.equal(f.actions.length, 0);
  });
}

for (const mode of Object.keys(modes)) {
  test(`${mode}: only same-owner background reads are deduplicated; selection/session start fresh reads`, async () => {
    const f = fixture(mode); f.show(); f.click("held-a");
    const duplicateA = f.detail("held-a"); assert.equal(f.requests.length, 1); await duplicateA;
    f.click("held-b"); assert.equal(f.requests.length, 2, "a new explicit selection owns its read immediately");
    const duplicateB = f.detail("held-b"); assert.equal(f.requests.length, 2); await duplicateB;
    f.click("held-b"); assert.equal(f.requests.length, 3, "an explicit same-row selection can supersede a pending read");
    f.requests[1].resolve({ ok: false }); await tick();
    assert.equal(f.els.interceptDetailTitle.textContent, `Loading ${mode}…`);
    f.state.activeSession = { id: "session-b" }; f.reset(); f.show();
    const fresh = f.detail("held-a"); assert.equal(f.requests.length, 4, "a new session is not deduplicated against the old session");
    assert.match(f.requests[3].url, /session_id=session-b$/);
    f.requests[0].resolve({ ok: false }); f.respond(2, record("held-b")); await tick();
    assert.equal(f.els.interceptDetailTitle.textContent, `Loading ${mode}…`);
    f.respond(3, record("held-a")); await fresh;
    assert.equal(f.content(), f.raw(record("held-a"))); assert.equal(f.actions.length, 0);
  });

  test(`${mode}: explicit retry survives overlapping background reads and can be superseded by another explicit selection`, async () => {
    const f = fixture(mode); f.show(); f.click("held-a"); f.requests[0].resolve({ ok: false }); await tick();
    const retry = f.c.retrySelectedInterceptDetail();
    assert.equal(f.requests.length, 2); const duplicate = f.detail("held-a");
    assert.equal(f.requests.length, 2, "an automatic duplicate cannot retire the explicit retry"); await duplicate;
    await f.c.retrySelectedInterceptDetail(); assert.equal(f.requests.length, 2, "pending retry remains deduplicated");
    f.click("held-a"); assert.equal(f.requests.length, 3, "existing explicit pointer supersession remains");
    f.requests[1].resolve({ ok: false }); await retry;
    assert.equal(f.els.interceptDetailTitle.textContent, `Loading ${mode}…`);
    f.respond(2, record("held-a")); await tick();
    assert.equal(f.content(), f.raw(record("held-a"))); assert.equal(f.actions.length, 0);
  });
}


for (const mode of Object.keys(modes)) for (const cm of [true, false]) {
  test(`${mode} ${cm ? "CM" : "fallback"}: pending/error retry cycles retain native focus without stealing newer focus`, async () => {
    const f = fixture(mode, cm); f.show([record("held-a")]); f.click("held-a");
    f.requests[0].resolve({ ok: false }); await tick();
    const button = f.els.interceptDetailRetryButton;
    button.focus(); assert.equal(f.document.activeElement === button, true);
    const announcements = f.els.interceptDetailStatus.textWrites;
    for (let cycle = 0; cycle < 3; cycle++) {
      const pending = f.detail("held-a"), count = f.requests.length;
      assert.equal(button.disabled, false, "pending feedback must not natively disable and blur the button");
      assert.equal(button.getAttribute("aria-disabled"), "true");
      assert.equal(button.getAttribute("aria-busy"), "true");
      assert.equal(button.textContent, "Retrying…");
      assert.equal(f.document.activeElement === button, true);
      // aria-disabled still dispatches native click (also generated by Enter or
      // Space). The actual bound handler, not a fixture disabled gate, dedups it.
      button.click(); button.click(); await tick();
      assert.equal(f.requests.length, count);
      f.requests[count - 1].resolve({ ok: false }); await pending;
      assert.equal(f.document.activeElement === button, true);
      assert.equal(button.getAttribute("aria-disabled"), "false");
      assert.equal(button.getAttribute("aria-busy"), "false");
      assert.equal(button.textContent, "Retry detail");
    }
    assert.equal(f.els.interceptDetailStatus.textWrites, announcements);
    button.click(); const count = f.requests.length;
    assert.equal(button.getAttribute("aria-disabled"), "true");
    assert.equal(f.document.activeElement === button, true);
    button.click(); button.click(); await tick(); assert.equal(f.requests.length, count);
    f.els.interceptSearchInput.focus();
    f.requests[count - 1].resolve({ ok: false }); await tick();
    assert.equal(f.document.activeElement === f.els.interceptSearchInput, true, "completion cannot restore stale retry focus");
    assert.equal(button.getAttribute("aria-disabled"), "false");
    button.focus(); button.click(); const retired = f.requests.length - 1;
    f.state.activeSession = { id: "session-b" }; f.reset(); f.els.interceptSearchInput.focus();
    f.requests[retired].resolve({ ok: false }); await tick();
    assert.equal(f.document.activeElement === f.els.interceptSearchInput, true);
    assert.equal(button.classList.contains("hidden"), true);
    assert.equal(f.actions.length, 0);
  });
}

test("focusable pending Retry has scoped unavailable styling rather than native disable", () => {
  const fs = require("node:fs");
  const html = fs.readFileSync(require.resolve("../web/index.html"), "utf8");
  const button = html.match(/<button[^>]*id="interceptDetailRetryButton"[^>]*>/)?.[0];
  assert.ok(button); assert.doesNotMatch(button, /\sdisabled(?:\s|=|>)/);
  const css = fs.readFileSync(require.resolve("../web/styles.css"), "utf8");
  assert.match(css, /#interceptDetailRetryButton\[aria-disabled="true"\]\s*\{[^}]*cursor:\s*wait;[^}]*opacity:/);
});
