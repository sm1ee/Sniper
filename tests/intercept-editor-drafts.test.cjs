// Real intercept controllers and raw HTTP parsing with synthetic DOM/CodeMirror
// and in-memory API replies. No browser, proxy, or network is started.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const copy = value => JSON.parse(JSON.stringify(value));
const tick = () => new Promise(resolve => setImmediate(resolve));
const modes = {
  request: {
    queue: "intercepts", selected: "selectedInterceptId", record: "selectedInterceptRecord",
    seed: "interceptEditorSeedId", editor: "interceptRequestEditor", key: "interceptReq",
    table: "interceptTableBody", load: "loadIntercepts", detail: "loadInterceptDetail",
    render: "renderIntercepts", forward: "forwardSelectedIntercept", drop: "dropSelectedIntercept",
    button: "forwardInterceptButton", build: "buildEditableRawRequest",
  },
  response: {
    queue: "responseIntercepts", selected: "selectedResponseInterceptId", record: "selectedResponseInterceptRecord",
    seed: "responseInterceptEditorSeedId", editor: "interceptResponseEditor", key: "interceptRes",
    table: "responseInterceptTableBody", load: "loadResponseIntercepts", detail: "loadResponseInterceptDetail",
    render: "renderResponseIntercepts", forward: "forwardSelectedResponseIntercept", drop: "dropSelectedResponseIntercept",
    button: "forwardResponseInterceptButton", build: "buildEditableRawResponse",
  },
};

function record(id) {
  return {
    id, scheme: "https", host: "example.com", method: "GET", path: `/${id}`,
    status: 200, peer_addr: "127.0.0.1:10000", started_at: "2026-01-01T00:00:00Z",
    request: {
      scheme: "https", host: "example.com", method: "GET", path: `/${id}`,
      headers: [], body: "", body_encoding: "utf8",
    },
    response: { status: 200, headers: [], body: id, body_encoding: "utf8" },
  };
}

function element() {
  return {
    value: "", textContent: "", innerHTML: "", disabled: false,
    classList: { toggle() {} },
    querySelectorAll() {
      this.rows = [...this.innerHTML.matchAll(/data-id="([^"]+)"/g)].map(([, id]) => ({
        dataset: { id }, listeners: {},
        addEventListener(name, listener) { this.listeners[name] = listener; },
      }));
      return this.rows;
    },
  };
}

function fixture(mode, cm) {
  const config = modes[mode];
  const state = {
    activeSession: { id: "session-a" }, interceptQueueTab: mode,
    intercepts: [], responseIntercepts: [],
    selectedInterceptId: null, selectedInterceptRecord: null, interceptEditorSeedId: null,
    selectedResponseInterceptId: null, selectedResponseInterceptRecord: null, responseInterceptEditorSeedId: null,
  };
  const els = {};
  for (const name of [
    "interceptTableBody", "responseInterceptTableBody", "interceptDetailPath", "interceptDetailTitle", "interceptMeta",
    "forwardInterceptButton", "dropInterceptButton", "forwardResponseInterceptButton", "dropResponseInterceptButton",
    "interceptRequestEditor", "interceptResponseEditor", "interceptQueueTabRequest", "interceptQueueTabResponse",
    "interceptRequestTable", "responseInterceptTable", "interceptRequestEditorPanel", "interceptResponseEditorPanel",
    "interceptRequestActions", "responseInterceptActions", "interceptSearchInput", "interceptSearchMeta",
  ]) els[name] = element();
  if (cm) {
    els.interceptRequestCM = element();
    els.interceptResponseCM = element();
  }
  const views = new Map(), writes = [], requests = [], toasts = [];
  const server = { request: [record("held-a"), record("held-b")], response: [] };
  if (mode === "response") [server.request, server.response] = [server.response, server.request];
  const document = { activeElement: null, getElementById: () => null };
  const context = loadFunctions([
    "loadIntercepts", "loadInterceptDetail", "loadResponseIntercepts", "loadResponseInterceptDetail",
    "renderIntercepts", "renderResponseIntercepts", "getVisibleRequestInterceptSummaries", "getVisibleResponseInterceptSummaries",
    "reconcileRequestInterceptSelection", "reconcileResponseInterceptSelection", "refreshInterceptDetailsForCurrentSelection",
    "applyInterceptScopeFilterLocally", "switchInterceptQueueTab", "updateInterceptQueueBadges",
    "activeInterceptCMKey", "updateInterceptSearch", "setInterceptPaneContent",
    "forwardSelectedIntercept", "dropSelectedIntercept", "forwardSelectedResponseIntercept", "dropSelectedResponseIntercept",
    "buildEditableRawRequest", "buildEditableRawResponse", "parseEditableRawRequest", "parseEditableRawResponse",
    "normalizedHeaders", "mergeHeaders", "headerNameEquals", "headerValue", "splitRawHttpMessage",
    "parseReplayHttpVersionToken", "normalizeReplayHttpVersion", "editableRequestBodyLength", "editableResponseBodyLength",
    "validateRawHttpBodyFraming", "responseMustNotIncludeBody", "responseStatusMustNotIncludeBody",
    "responseContentLengthMayDescribeRepresentation", "currentSessionId", "sessionQueryPath", "sessionWritePath",
    "expectedActiveSessionIdForWrite", "jsonArray",
  ], {
    state, els, document, URL, URLSearchParams, TextEncoder, workspaceStateGeneration: 0,
    getCMView: key => views.get(key),
    updateCodePaneCM(key, _container, text) {
      writes.push({ key, text });
      if (!views.has(key)) views.set(key, {
        text: "", view: { hasFocus: false, state: { doc: { lines: 1 } } },
        getContent() { return this.text; }, applySearch() { return { matchCount: 0 }; },
      });
      views.get(key).text = text;
      return { lineCount: 1, matchCount: 0 };
    },
    buildSearchMeta: () => "", escapeHtml: value => value, formatTimestamp: value => value,
    renderInterceptRequestHighlight() {}, renderInterceptResponseHighlight() {}, renderInterceptRules() {},
    isInScopeHost: host => host === "example.com", scheduleRefresh() {},
    showToast: (...args) => toasts.push(args),
    requireOkResponse: async response => assert.equal(response.ok, true),
    async fetch(url, options = {}) {
      requests.push({ url, options });
      const path = new URL(url, "https://example.com").pathname;
      const match = path.match(/^\/api\/(intercepts|response-intercepts)(?:\/([^/]+))?(?:\/(forward|drop))?$/);
      assert.ok(match, `Unexpected request: ${url}`);
      const kind = match[1] === "intercepts" ? "request" : "response";
      const [, , id, action] = match;
      if (action) server[kind] = server[kind].filter(item => item.id !== id);
      const payload = action ? {} : id ? server[kind].find(item => item.id === id) : server[kind];
      return { ok: payload !== undefined, json: async () => copy(payload) };
    },
  });
  const content = () => cm ? views.get(config.key)?.text : els[config.editor].value;
  const edit = text => {
    document.activeElement = els[config.editor];
    if (cm) { views.get(config.key).view.hasFocus = true; views.get(config.key).text = text; }
    else els[config.editor].value = text;
  };
  const blur = () => {
    document.activeElement = els.interceptSearchInput;
    for (const view of views.values()) view.view.hasFocus = false;
  };
  const raw = item => context[config.build](item[mode]);
  return { context, config, state, els, views, writes, requests, server, toasts, content, edit, blur, raw,
    load: () => context[config.load](), render: () => context[config.render](),
    draft: mode === "request" ? "GET /edited HTTP/1.1\nHost: example.com" : "HTTP/1.1 201\r\n\r\nedited body",
  };
}

for (const mode of Object.keys(modes)) for (const cm of [true, false]) {
  const label = `${mode} ${cm ? "CodeMirror" : "fallback"}`;

  test(`${label}: repeated same-ID polling preserves a draft after focus moves to search`, async () => {
    const f = fixture(mode, cm);
    await f.load();
    assert.equal(f.content(), f.raw(f.server[mode][0]));
    f.edit(f.draft);
    await f.load();
    assert.equal(f.content(), f.draft);
    f.blur();
    const writes = f.writes.length;
    for (let poll = 0; poll < 3; poll++) await f.load();
    assert.equal(f.content(), f.draft);
    assert.equal(f.writes.length, writes, "polling must not reset CodeMirror search, cursor, or undo state");
    assert.equal(f.state[f.config.seed], "held-a");
  });

  test(`${label}: queue-tab switches and same-row clicks retain the selected draft`, async () => {
    const f = fixture(mode, cm);
    await f.load(); f.edit(f.draft); f.blur();
    f.context.switchInterceptQueueTab(mode === "request" ? "response" : "request");
    await f.load();
    f.context.switchInterceptQueueTab(mode);
    f.els[f.config.table].rows[0].listeners.click();
    await tick();
    assert.equal(f.content(), f.draft);
  });

  test(`${label}: selecting another row clears the old draft and seeds the new owner`, async () => {
    const f = fixture(mode, cm);
    await f.load(); f.edit(f.draft);
    f.els[f.config.table].rows[1].listeners.click();
    assert.equal(f.content(), "", "do not leave the previous owner's text actionable while loading");
    assert.equal(f.els[f.config.button].disabled, true);
    await tick();
    assert.equal(f.content(), f.raw(f.server[mode][1]));
    assert.equal(f.state[f.config.seed], "held-b");
  });

  test(`${label}: removal and empty queues discard ownership before a reused ID appears`, async () => {
    const f = fixture(mode, cm);
    await f.load(); f.edit(f.draft); f.blur();
    f.server[mode].shift();
    await f.load();
    assert.equal(f.content(), f.raw(f.server[mode][0]));
    f.server[mode] = [];
    await f.load();
    assert.equal(f.content(), "");
    assert.equal(f.state[f.config.seed], null);
    assert.equal(f.els[f.config.button].disabled, true);
    f.server[mode] = [record("held-a")];
    await f.load();
    assert.equal(f.content(), f.raw(f.server[mode][0]));
  });

  test(`${label}: forwarding sends the preserved edit and seeds the next held record`, async () => {
    const f = fixture(mode, cm);
    await f.load(); f.edit(f.draft); f.blur(); await f.load();
    await f.context[f.config.forward]();
    const sent = f.requests.find(item => item.options.method === "POST");
    assert.match(sent.url, /\/held-a\/forward\?session_id=session-a&expected_active_session_id=session-a$/);
    const body = JSON.parse(sent.options.body);
    assert.equal(body.edited, true);
    if (mode === "request") assert.equal(body.request.path, "/edited");
    else { assert.equal(body.response.status, 201); assert.equal(body.response.body, "edited body"); }
    assert.equal(f.content(), f.raw(f.server[mode][0]));
    assert.equal(f.state[f.config.seed], "held-b");
  });

  test(`${label}: dropping a held record clears its draft without submitting it`, async () => {
    const f = fixture(mode, cm);
    await f.load(); f.edit(f.draft); f.blur();
    await f.context[f.config.drop]();
    const sent = f.requests.find(item => item.options.method === "POST");
    assert.match(sent.url, /\/held-a\/drop\?/);
    assert.equal(sent.options.body, undefined);
    assert.equal(f.content(), f.raw(f.server[mode][0]));
  });

  test(`${label}: cancelled invalid forwarding leaves the draft available for correction`, async () => {
    const f = fixture(mode, cm);
    await f.load();
    const invalid = mode === "request" ? "invalid request line in editor" : "HTTP/1.1 invalid";
    f.edit(invalid); f.blur(); await f.load();
    await assert.rejects(f.context[f.config.forward](), /Invalid .* line/);
    assert.equal(f.content(), invalid);
    assert.equal(f.requests.filter(item => item.options.method === "POST").length, 0);
    assert.equal(f.state[f.config.seed], "held-a");
  });

  test(`${label}: session reset rejects a late detail response and never reuses the old draft`, async () => {
    const f = fixture(mode, cm);
    await f.load(); f.edit(f.draft); f.blur();
    const fetch = f.context.fetch;
    let finish;
    f.context.fetch = () => new Promise(resolve => { finish = resolve; });
    const pending = f.context[f.config.detail]("held-a");
    f.state.activeSession = { id: "session-b" };
    // Execute the intercept section of the production session reset; unrelated
    // history, Replay, and other tool resets are covered by their own fixtures.
    const reset = appSource.match(/^function resetSessionScopedUiState\([^]*?^\}/m)[0];
    const start = reset.indexOf("  state.intercepts = [];");
    const end = reset.indexOf("  state.websocketSessions = [];", start);
    assert.ok(start >= 0 && end > start);
    vm.runInContext(reset.slice(start, end), f.context);
    assert.equal(f.content(), "");
    assert.equal(f.state[f.config.seed], null);
    finish({ ok: true, json: async () => record("held-a") });
    await pending;
    assert.equal(f.content(), "");
    f.context.fetch = fetch;
    await f.load();
    assert.equal(f.content(), f.raw(f.server[mode][0]));
    assert.equal(f.state[f.config.seed], "held-a");
  });
}
