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
    recovery: "interceptDraftRecovery",
  },
  response: {
    queue: "responseIntercepts", selected: "selectedResponseInterceptId", record: "selectedResponseInterceptRecord",
    seed: "responseInterceptEditorSeedId", editor: "interceptResponseEditor", key: "interceptRes",
    table: "responseInterceptTableBody", load: "loadResponseIntercepts", detail: "loadResponseInterceptDetail",
    render: "renderResponseIntercepts", forward: "forwardSelectedResponseIntercept", drop: "dropSelectedResponseIntercept",
    button: "forwardResponseInterceptButton", build: "buildEditableRawResponse",
    recovery: "responseInterceptDraftRecovery",
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
    "getInterceptDraftRecovery", "captureInterceptDraftRecoveryOwners", "handleInterceptDraftReadFailure", "takeInterceptDraftRecovery",
    "selectInterceptQueueItem", "getInterceptDetailRead", "updateInterceptDetailFeedback", "retrySelectedInterceptDetail", "updateInterceptQueueSelectionStatus", "scrollSelectedInterceptRowIntoView",
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
      text = text.replace(/\r\n?/g, "\n");
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
    if (cm) { views.get(config.key).view.hasFocus = true; views.get(config.key).text = text.replace(/\r\n?/g, "\n"); }
    else els[config.editor].value = text;
  };
  const blur = () => {
    document.activeElement = els.interceptSearchInput;
    for (const view of views.values()) view.view.hasFocus = false;
  };
  const raw = item => {
    const text = context[config.build](item[mode]);
    return cm ? text.replace(/\r\n?/g, "\n") : text;
  };
  return { context, config, state, els, views, writes, requests, server, toasts, content, edit, blur, raw,
    load: () => context[config.load](), render: () => context[config.render](),
    draft: mode === "request" ? "GET /edited HTTP/1.1\nHost: example.com"
      : cm ? "HTTP/1.1 201\n\nedited body" : "HTTP/1.1 201\r\n\r\nedited body",
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

function deferredRead(f, queue = false) {
  const fetch = f.context.fetch;
  let finish;
  f.context.fetch = () => new Promise(resolve => { finish = resolve; });
  const pending = queue ? f.load() : f.context[f.config.detail](f.state[f.config.selected], { explicit: true });
  f.context.fetch = fetch;
  return { pending, finish };
}

async function failDetail(f, status = 503) {
  const read = deferredRead(f);
  read.finish({ ok: false, status, text: () => assert.fail("Do not inspect failure bodies") });
  await read.pending;
}

function resetInterceptState(f) {
  const reset = appSource.match(/^function resetSessionScopedUiState\([^]*?^\}/m)[0];
  const start = reset.indexOf("  state.intercepts = [];");
  const end = reset.indexOf("  state.websocketSessions = [];", start);
  vm.runInContext(reset.slice(start, end), f.context);
}

for (const mode of Object.keys(modes)) for (const cm of [true, false]) {
  const label = `${mode} ${cm ? "CodeMirror" : "fallback"} recovery`;

  for (const status of [500, 502, 503, 504]) test(`${label}: repeated HTTP ${status} keeps only edited text until a fresh detail succeeds`, async () => {
    const f = fixture(mode, cm);
    await f.load(); f.edit(f.draft); f.blur();
    await failDetail(f, status);
    const slot = f.state[f.config.recovery];
    assert.equal(slot?.text, f.draft);
    assert.deepEqual(Object.keys(slot).sort(), ["id", "owner", "sessionId", "text", "workspaceGeneration"]);
    const owner = f.context.captureInterceptDraftRecoveryOwners().find(owner => owner.queue === mode);
    assert.equal(owner.token, slot.owner); assert.deepEqual(Object.keys(owner.token), []);
    assert.equal(owner.draft, undefined, "pending reads must not retain retired recovery text");
    assert.equal(f.state[f.config.record], null);
    assert.equal(f.state[f.config.seed], null);
    assert.equal(f.content(), "");
    assert.equal(f.els[f.config.button].disabled, true);
    await f.context[f.config.forward](); await f.context[f.config.drop]();
    assert.equal(f.requests.filter(item => item.options.method === "POST").length, 0);
    await failDetail(f, status);
    assert.equal(f.state[f.config.recovery], slot, "a repeated failure must not capture the blank unavailable editor");
    await f.context[f.config.detail]("held-a", { explicit: true });
    assert.equal(f.content(), f.draft);
    assert.equal(f.state[f.config.recovery], null, "restoration consumes the text-only slot");
    assert.equal(f.els[f.config.button].disabled, false);
    f.edit(f.draft + "\n"); await f.load();
    assert.equal(f.content(), f.draft + "\n", "later polls must not restore the older snapshot again");
  });

  for (const edited of ["", "invalid"]) test(`${label}: ${edited || "empty"} text is restored verbatim without parsing or truthiness fallback`, async () => {
    const f = fixture(mode, cm); await f.load();
    const text = edited ? (mode === "request" ? "invalid request line in editor" : "HTTP/1.1 invalid") : "";
    f.edit(text); await failDetail(f);
    assert.equal(f.state[f.config.recovery]?.text, text);
    await f.context[f.config.detail]("held-a");
    assert.equal(f.content(), text);
    if (edited) {
      await assert.rejects(f.context[f.config.forward](), /Invalid .* line/);
      assert.equal(f.requests.filter(item => item.options.method === "POST").length, 0);
      assert.equal(f.content(), text, "failed validation must not silently send or seed the original");
    }
  });

  test(`${label}: captures edits made during the pending read, but not an unchanged packet`, async () => {
    const f = fixture(mode, cm); await f.load();
    const read = deferredRead(f);
    f.edit(f.draft); read.finish({ ok: false, status: 503 }); await read.pending;
    assert.equal(f.state[f.config.recovery]?.text, f.draft);
    await f.context[f.config.detail]("held-a");
    f.edit(f.raw(f.server[mode][0])); await failDetail(f);
    assert.equal(f.state[f.config.recovery] ?? null, null);
    await f.context[f.config.detail]("held-a");
    assert.equal(f.content(), f.raw(f.server[mode][0]));
  });

  for (const status of [400, 404, 408, 409, 429, 499, 600]) test(`${label}: HTTP ${status} retires recovery without classifying retryability`, async () => {
    const f = fixture(mode, cm); await f.load(); f.edit(f.draft); await failDetail(f);
    await failDetail(f, status);
    assert.equal(f.state[f.config.recovery], null);
    await f.context[f.config.detail]("held-a");
    assert.equal(f.content(), f.raw(f.server[mode][0]));
  });

  for (const boundary of ["selection ABA", "removal", "scope", "session", "same-session reset", "workspace", "reset selection"]) {
    test(`${label}: ${boundary} retires text before the same ID reappears`, async () => {
      const f = fixture(mode, cm); await f.load(); f.edit(f.draft); await failDetail(f);
      if (boundary === "selection ABA") {
        await f.context.selectInterceptQueueItem(mode, "held-b");
        await f.context.selectInterceptQueueItem(mode, "held-a");
      } else if (boundary === "removal") {
        f.server[mode] = []; await f.load(); f.server[mode] = [record("held-a")]; await f.load();
      } else if (boundary === "scope") {
        f.context.isInScopeHost = () => false; f.state.interceptInScopeOnly = true;
        await f.context.applyInterceptScopeFilterLocally();
        f.state.interceptInScopeOnly = false; await f.context.applyInterceptScopeFilterLocally();
      } else if (boundary === "session" || boundary === "same-session reset") {
        if (boundary === "session") f.state.activeSession = { id: "session-b" };
        resetInterceptState(f);
        f.state.activeSession = { id: "session-a" }; await f.load();
      } else if (boundary === "workspace") {
        f.context.workspaceStateGeneration++; f.render(); await f.context[f.config.detail]("held-a");
      } else {
        await f.context[f.config.load](false);
      }
      assert.equal(f.state[f.config.recovery], null);
      assert.equal(f.content(), f.raw(record("held-a")));
    });
  }

  test(`${label}: stale detail failure after selection ABA cannot capture or erase the newer draft`, async () => {
    const f = fixture(mode, cm); await f.load(); f.edit("retired draft");
    const stale = deferredRead(f);
    await f.context.selectInterceptQueueItem(mode, "held-b");
    await f.context.selectInterceptQueueItem(mode, "held-a");
    f.edit(f.draft); await failDetail(f);
    const slot = f.state[f.config.recovery];
    stale.finish({ ok: false, status: 401 }); await stale.pending;
    assert.equal(f.state[f.config.recovery], slot);
    await f.context[f.config.detail]("held-a"); assert.equal(f.content(), f.draft);
  });

  test(`${label}: late success after removal cannot resurrect recovery for a reused ID`, async () => {
    const f = fixture(mode, cm); await f.load(); f.edit(f.draft); await failDetail(f);
    const stale = deferredRead(f);
    f.server[mode] = []; await f.load(); f.server[mode] = [record("held-a")]; await f.load();
    stale.finish({ ok: true, json: async () => record("held-a") }); await stale.pending;
    assert.equal(f.state[f.config.recovery], null);
    assert.equal(f.content(), f.raw(record("held-a")));
  });

  test(`${label}: network and JSON retry errors retain only the already-owned recovery slot`, async () => {
    const f = fixture(mode, cm); await f.load(); f.edit(f.draft); await failDetail(f);
    const slot = f.state[f.config.recovery], fetch = f.context.fetch;
    for (const kind of ["network", "JSON"]) {
      f.context.fetch = async () => {
        if (kind === "network") throw new Error("synthetic transport failure");
        return { ok: true, json: async () => { throw new Error("synthetic parse failure"); } };
      };
      await assert.rejects(f.context[f.config.detail]("held-a"), /Could not load/);
      assert.equal(f.state[f.config.recovery], slot);
      assert.equal(f.state[f.config.record], null);
      assert.equal(f.els[f.config.button].disabled, true);
    }
    f.context.fetch = fetch; await f.context[f.config.detail]("held-a"); assert.equal(f.content(), f.draft);
  });

  test(`${label}: restoration still uses normal validation and sends the edit only after detail succeeds`, async () => {
    const f = fixture(mode, cm); await f.load(); f.edit(f.draft); await failDetail(f);
    await f.context[f.config.forward]();
    assert.equal(f.requests.filter(item => item.options.method === "POST").length, 0);
    await f.context[f.config.detail]("held-a"); await f.context[f.config.forward]();
    const posts = f.requests.filter(item => item.options.method === "POST");
    assert.equal(posts.length, 1);
    const sent = JSON.parse(posts[0].options.body); assert.equal(sent.edited, true);
    if (mode === "request") assert.equal(sent.request.path, "/edited");
    else { assert.equal(sent.response.status, 201); assert.equal(sent.response.body, "edited body"); }
  });
}

for (const cm of [true, false]) test(`response ${cm ? "CodeMirror" : "fallback"} recovery: hidden response waits for its normal visible seed`, async () => {
  const f = fixture("response", cm); await f.load(); f.edit(f.draft); await failDetail(f);
  f.context.switchInterceptQueueTab("request");
  await f.context.loadResponseInterceptDetail("held-a");
  assert.equal(f.content(), ""); assert.equal(f.state.responseInterceptDraftRecovery?.text, f.draft);
  f.context.switchInterceptQueueTab("response");
  assert.equal(f.content(), f.draft); assert.equal(f.state.responseInterceptDraftRecovery, null);
});

async function suspendBothQueues(f, cm) {
  for (const queue of ["request", "response"]) {
    const config = modes[queue];
    f.server[queue] = [record("held-a"), record("held-b")];
    f.context.switchInterceptQueueTab(queue); await f.context[config.load]();
    if (cm) f.views.get(config.key).text = `synthetic ${queue} draft`;
    else f.els[config.editor].value = `synthetic ${queue} draft`;
    await failDetail({ ...f, config });
    assert.equal(f.state[config.recovery]?.text, `synthetic ${queue} draft`);
  }
  f.context.switchInterceptQueueTab(f.state.interceptQueueTab);
}

for (const mode of Object.keys(modes)) for (const cm of [true, false]) {
  for (const status of [401, 403]) for (const queue of [false, true]) {
    test(`${mode} ${cm ? "CodeMirror" : "fallback"} recovery: current ${queue ? "queue" : "detail"} HTTP ${status} clears both text slots`, async () => {
      const f = fixture(mode, cm); await suspendBothQueues(f, cm);
      const read = deferredRead(f, queue);
      const settled = queue ? assert.rejects(read.pending) : read.pending;
      read.finish({ ok: false, status }); await settled;
      assert.equal(f.state.interceptDraftRecovery, null);
      assert.equal(f.state.responseInterceptDraftRecovery, null);
    });
  }

  test(`${mode} ${cm ? "CodeMirror" : "fallback"} recovery: obsolete queue auth failure cannot erase a newer selected owner after ABA`, async () => {
    const f = fixture(mode, cm); await suspendBothQueues(f, cm);
    const old = deferredRead(f, true), settled = assert.rejects(old.pending);
    f.context.switchInterceptQueueTab(mode);
    await f.context.selectInterceptQueueItem(mode, "held-b");
    await f.context.selectInterceptQueueItem(mode, "held-a");
    f.edit(f.draft); await failDetail(f);
    const own = f.state[f.config.recovery], other = f.state[modes[mode === "request" ? "response" : "request"].recovery];
    old.finish({ ok: false, status: 401 }); await settled;
    assert.equal(f.state[f.config.recovery], own);
    assert.ok(other);
    assert.equal(f.state[modes[mode === "request" ? "response" : "request"].recovery], null,
      "the unchanged captured opposite owner still retires");
  });

  test(`${mode} ${cm ? "CodeMirror" : "fallback"} recovery: obsolete queue auth failure after a newer poll cannot erase its recovery slot`, async () => {
    const f = fixture(mode, cm); await f.load();
    const old = deferredRead(f, true), settled = old.pending;
    await f.load(); f.edit(f.draft); await failDetail(f);
    const slot = f.state[f.config.recovery];
    old.finish({ ok: false, status: 403 }); await settled;
    assert.equal(f.state[f.config.recovery], slot);
  });

  test(`${mode} ${cm ? "CodeMirror" : "fallback"} recovery: an old-workspace detail failure cannot capture an earlier draft`, async () => {
    const f = fixture(mode, cm); await f.load(); f.edit(f.draft);
    const old = deferredRead(f); f.context.workspaceStateGeneration++;
    old.finish({ ok: false, status: 503 }); await old.pending;
    assert.equal(f.state[f.config.recovery] ?? null, null);
    await f.context[f.config.detail]("held-a");
    assert.equal(f.content(), f.raw(record("held-a")));
  });

  test(`${mode} ${cm ? "CodeMirror" : "fallback"} recovery: newer pending polls do not starve captured-owner auth cleanup`, async () => {
    const f = fixture(mode, cm); await suspendBothQueues(f, cm);
    const old = deferredRead(f, true), newer = [deferredRead(f, true), deferredRead(f, true)];
    const oldSettled = assert.rejects(old.pending), newerSettled = newer.map(read => assert.rejects(read.pending));
    old.finish({ ok: false, status: 401 }); await oldSettled;
    assert.equal(f.state.interceptDraftRecovery, null); assert.equal(f.state.responseInterceptDraftRecovery, null);
    newer.forEach(read => read.finish({ ok: false, status: 503 })); await Promise.all(newerSettled);
  });

  for (const queue of [false, true]) test(`${mode} ${cm ? "CodeMirror" : "fallback"} recovery: delayed ${queue ? "queue" : "detail"} auth protects the opposite queue's replacement after ABA`, async () => {
    const f = fixture(mode, cm); await suspendBothQueues(f, cm);
    const old = deferredRead(f, queue), settled = queue ? assert.rejects(old.pending) : old.pending;
    const other = mode === "request" ? "response" : "request", config = modes[other];
    f.context.switchInterceptQueueTab(other);
    await f.context.selectInterceptQueueItem(other, "held-b");
    await f.context.selectInterceptQueueItem(other, "held-a");
    if (cm) f.views.get(config.key).text = "new opposite draft";
    else f.els[config.editor].value = "new opposite draft";
    await failDetail({ ...f, config }); const replacement = f.state[config.recovery];
    old.finish({ ok: false, status: 403 }); await settled;
    assert.equal(f.state[config.recovery], replacement);
    assert.equal(f.state[f.config.recovery], null, "the original issuing-queue slot still retires");
  });

  test(`${mode} ${cm ? "CodeMirror" : "fallback"} recovery: a newer accepted opposite queue snapshot protects its still-pending slot`, async () => {
    const f = fixture(mode, cm); await suspendBothQueues(f, cm);
    const other = mode === "request" ? "response" : "request", config = modes[other];
    const pendingDetail = deferredRead({ ...f, config });
    const old = deferredRead(f, true), settled = assert.rejects(old.pending);
    const slot = f.state[config.recovery];
    await f.context[config.load]();
    assert.equal(f.state[config.recovery], slot, "deduplicated pending detail leaves text unconsumed");
    old.finish({ ok: false, status: 401 }); await settled;
    assert.equal(f.state[config.recovery], slot);
    assert.equal(f.state[f.config.recovery], null);
    pendingDetail.finish({ ok: false, status: 503 }); await pendingDetail.pending;
  });

  test(`${mode} ${cm ? "CodeMirror" : "fallback"} recovery: an auth read cannot retire a slot first created after it began`, async () => {
    const f = fixture(mode, cm); await f.load();
    const old = deferredRead(f, true), settled = assert.rejects(old.pending);
    f.edit(f.draft); await failDetail(f); const slot = f.state[f.config.recovery];
    old.finish({ ok: false, status: 401 }); await settled;
    assert.equal(f.state[f.config.recovery], slot);
  });

  for (const status of [404, 429, 503]) test(`${mode} ${cm ? "CodeMirror" : "fallback"} recovery: queue HTTP ${status} changes only eligible captured recovery, never accepted data or loaded actions`, async () => {
    const f = fixture(mode, cm); await f.load(); f.edit(f.draft);
    const record = f.state[f.config.record], entries = f.state[f.config.queue];
    const loadedFailure = deferredRead(f, true), loadedSettled = assert.rejects(loadedFailure.pending);
    loadedFailure.finish({ ok: false, status }); await loadedSettled;
    assert.equal(f.state[f.config.record], record); assert.equal(f.state[f.config.queue], entries);
    assert.equal(f.content(), f.draft); assert.equal(f.els[f.config.button].disabled, false);
    await failDetail(f); const slot = f.state[f.config.recovery];
    const suspendedFailure = deferredRead(f, true), suspendedSettled = assert.rejects(suspendedFailure.pending);
    suspendedFailure.finish({ ok: false, status }); await suspendedSettled;
    assert.equal(f.state[f.config.recovery], status === 503 ? slot : null);
    assert.equal(f.state[f.config.queue], entries); assert.equal(f.els[f.config.button].disabled, true);
  });

  test(`${mode} ${cm ? "CodeMirror" : "fallback"} recovery: reverting to original while the read is pending does not create a slot`, async () => {
    const f = fixture(mode, cm); await f.load(); f.edit(f.draft);
    const pending = deferredRead(f); f.edit(f.raw(f.server[mode][0]));
    pending.finish({ ok: false, status: 503 }); await pending.pending;
    assert.equal(f.state[f.config.recovery] ?? null, null);
  });

  for (const status of [404, 429]) test(`${mode} ${cm ? "CodeMirror" : "fallback"} recovery: current detail HTTP ${status} retires its slot despite a newer accepted list`, async () => {
    const f = fixture(mode, cm); await f.load(); f.edit(f.draft); await failDetail(f);
    const slot = f.state[f.config.recovery], pending = deferredRead(f);
    await f.load(); assert.equal(f.state[f.config.recovery], slot);
    pending.finish({ ok: false, status }); await pending.pending;
    assert.equal(f.state[f.config.recovery], null);
    await f.context[f.config.detail]("held-a"); assert.equal(f.content(), f.raw(record("held-a")));
  });

  test(`${mode} ${cm ? "CodeMirror" : "fallback"} recovery: old-session auth cannot erase new same-ID recovery after a session ABA`, async () => {
    const f = fixture(mode, cm); await suspendBothQueues(f, cm);
    const old = deferredRead(f, true);
    f.state.activeSession = { id: "session-b" }; resetInterceptState(f);
    f.state.activeSession = { id: "session-a" }; resetInterceptState(f);
    await suspendBothQueues(f, cm);
    const request = f.state.interceptDraftRecovery, response = f.state.responseInterceptDraftRecovery;
    old.finish({ ok: false, status: 403 }); await old.pending;
    assert.equal(f.state.interceptDraftRecovery, request); assert.equal(f.state.responseInterceptDraftRecovery, response);
  });
}

for (const cm of [true, false]) test(`response ${cm ? "CodeMirror" : "fallback"} recovery: hidden success and repeated 5xx preserve text but protect it from older opposite auth`, async () => {
  const f = fixture("request", cm); await suspendBothQueues(f, cm);
  f.context.switchInterceptQueueTab("request");
  const old = deferredRead(f, true), settled = assert.rejects(old.pending);
  const before = f.state.responseInterceptDraftRecovery;
  await f.context.loadResponseInterceptDetail("held-a");
  assert.notEqual(f.state.responseInterceptDraftRecovery, before);
  await failDetail({ ...f, config: modes.response }); await failDetail({ ...f, config: modes.response });
  old.finish({ ok: false, status: 403 }); await settled;
  assert.equal(f.state.responseInterceptDraftRecovery?.text, "synthetic response draft");
  await f.context.loadResponseInterceptDetail("held-a");
  f.context.switchInterceptQueueTab("response");
  assert.equal(cm ? f.views.get("interceptRes").text : f.els.interceptResponseEditor.value, "synthetic response draft");
  assert.equal(f.state.responseInterceptDraftRecovery, null);
});
