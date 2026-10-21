// Actual History and pane menu bindings with synthetic records, reads and
// clipboard sinks only. No app bootstrap, browser, server or real clipboard.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function element(dataset = {}) {
  const handlers = new Map(), classes = new Set(["hidden"]);
  return { dataset, style: {}, offsetWidth: 100, offsetHeight: 100,
    classList: { add: value => classes.add(value), remove: value => classes.delete(value),
      contains: value => classes.has(value), toggle() {} },
    addEventListener(type, callback) {
      if (!handlers.has(type)) handlers.set(type, []);
      handlers.get(type).push(callback);
    },
    dispatch(type, extra = {}) {
      for (const handler of handlers.get(type) || []) handler({ target: this, preventDefault() {}, ...extra });
    },
    contains(other) { return other === this; }, querySelectorAll: () => [],
  };
}
function record(id = "a") {
  return { id, kind: "http", method: "POST", scheme: "https", host: "example.com", path: `/${id}`,
    request: { headers: [{ name: "X-Fixture", value: id }], body_preview: `request-${id}`, body_encoding: "utf8" },
    response: { status: 200, headers: [{ name: "X-Fixture", value: id }], body_preview: `response-${id}`, body_encoding: "utf8" },
  };
}
const functions = [
  "createTransactionRecordMenuTarget", "loadMenuTargetRecord", "loadTransactionRecordById", "currentSessionId",
  "sessionQueryPath", "transactionPath", "openContextMenu", "closeContextMenu", "positionContextMenu", "contextMenuSessionIsCurrent",
  "recordToFormat", "historyRequestExportBlockedReason", "buildRawRequest", "buildRawRequestHead", "buildRawResponse", "buildRawResponseHead",
  "renderBody", "mergeHeaders", "normalizedHeaders", "headerNameEquals", "normalizeReplayHttpVersion",
  "parseRequestForExport", "parseHeaderLineForExport", "exportHeaderValue", "exportableHeaderCandidates",
  "buildUrlFromTarget", "normalizeRepeaterTargetInput", "authorityToTargetState", "stripIpv6Brackets",
  "normalizePortValue", "defaultHttpPortForScheme", "isDefaultPortForScheme", "joinAuthority",
  "requestToPython", "requestToFetch", "requestToPowerShell", "requestToCurl", "shellQuote", "curlHttpVersionFlag",
  "urlNeedsPathAsIs", "rawPathFromUrlString", "exportableHeaders", "exportableHeadersForUrl", "isHttpPseudoHeaderName",
  "hostHeaderDiffersFromUrl", "httpRequestAuthoritiesEquivalent", "normalizeHttpRequestAuthority",
  "fetchExportBlockedReason", "requestFormatExportBlockedReason", "copyTextToClipboard", "handleClipboardActionError",
  "copyResponseContentForRecord", "copyMenuTargetUrl", "transactionUrlFromSource",
  "openInterceptContextMenu", "closeInterceptContextMenu", "runInterceptMenuAction",
  "loadInterceptForMenu", "interceptRecordAsTransactionShape",
];
function fixture(surface, { cached = false, fallbackResult = true } = {}) {
  const requests = [], writes = [], fallback = [], toasts = [], errors = [], attached = new Set();
  const els = Object.fromEntries(["contextMenu", "interceptContextMenu", "requestView", "responseView", "requestViewCM", "responseViewCM"].map(name => [name, element()]));
  const pane = element(), document = element();
  const actions = new Map(["curl", "python", "fetch", "powershell"].map(format => [`copy-as-${format}`, element({ action: `copy-as-${format}`, interceptAction: `copy-as-${format}` })]));
  actions.set("copy-url", element({ action: "copy-url" }));
  els.contextMenu.querySelectorAll = selector => selector === ".context-menu-item" ? [...actions.values()] : [];
  els.interceptContextMenu.querySelectorAll = selector => selector === "[data-intercept-action]" ? [...actions.values()] : [];
  document.getElementById = id => id === "paneContextMenu" ? pane : null;
  document.body = { appendChild: node => attached.add(node) };
  document.createElement = tag => {
    assert.equal(tag, "textarea");
    return { value: "", style: {}, setAttribute() {}, select() {}, remove() { attached.delete(this); } };
  };
  document.execCommand = command => {
    assert.equal(command, "copy");
    fallback.push([...attached][0].value);
    return fallbackResult;
  };
  const state = { activeSession: { id: "session-a" }, selectedId: "a", selectedRecord: cached ? record() : null, activeTool: "proxy" };
  // Load additions only when present so this same regression file runs red on
  // the exact pre-fix revision, through its original production callbacks.
  const additions = ["createRecordClipboardOwner", "copyMenuTargetRecord"]
    .filter(name => appSource.includes(`function ${name}(`));
  const context = loadFunctions(["retireFindingActionProgress", ...functions, ...additions], {
    state, els, document, URL, TextEncoder,
    workspaceStateGeneration: 0, workspaceLoaded: true, clearReplaySendInFlight() {},
    window: { innerWidth: 800, innerHeight: 600 },
    navigator: { clipboard: { writeText(text) { const write = { text, ...deferred() }; writes.push(write); return write.promise; } } },
    console: { error: error => errors.push(error) }, showToast: (...args) => toasts.push(args),
    getHistoryItem: id => record(id), renderContextMenuNotes() {}, loadUserNote() {},
    async requireOkResponse(result) { if (!result.ok) throw new Error("Synthetic read failure"); },
    fetch(url, options) {
      assert.equal(options, undefined);
      assert.match(url, /^\/api\/(?:transactions|intercepts)\/[ab]\?session_id=session-[ab]$/);
      const request = { url, ...deferred() }; requests.push(request); return request.promise;
    },
  });
  function bind(startMarker, endMarker) {
    const start = appSource.indexOf(startMarker), end = appSource.indexOf(endMarker, start);
    assert.ok(start >= 0 && end > start, `Missing production binding: ${startMarker}`);
    vm.runInContext(appSource.slice(start, end), context);
  }
  bind("let contextMenuTargetId = null;", "function openContextMenu(");
  bind("let interceptContextMenuTargetId = null;", "function openInterceptContextMenu(");
  if (surface === "intercept") bind('els.interceptContextMenu?.querySelectorAll("[data-intercept-action]")', "decorateContextMenuShortcuts();");
  if (surface !== "intercept") bind('els.contextMenu.querySelectorAll(".context-menu-item").forEach', "/* ─── WS Frame context menu ─── */");
  bind('  // Pane context menu (right-click on Request/Response code-view)', '\n  els.sendReplayButton.addEventListener');
  // Exercise the real reset prefix, not a test-written owner invalidation.
  const resetStart = appSource.indexOf("function resetSessionScopedUiState() {");
  const resetEnd = appSource.indexOf("  window.clearTimeout(refreshTimer);", resetStart);
  assert.ok(resetStart >= 0 && resetEnd > resetStart);
  vm.runInContext(`${appSource.slice(resetStart, resetEnd)}\n}`, context);
  function open(id = "a") {
    if (surface === "intercept") context.openInterceptContextMenu(20, 20, id);
    else if (surface === "history") context.openContextMenu(20, 20, id);
    else { state.selectedId = id; els.requestView.dispatch("contextmenu", { clientX: 20, clientY: 20 }); }
  }
  function click(action = "copy-as-curl") {
    if (surface === "history" || surface === "intercept") actions.get(action).dispatch("click");
    else pane.dispatch("click", { target: { closest: () => ({ dataset: { paneAction: action } }) } });
  }
  function setSession(id) { state.activeSession = { id }; context.resetSessionScopedUiState(); state.selectedRecord = null; }
  function navigate() { state.selectedId = "b"; state.selectedRecord = record("b"); state.activeTool = "target"; }
  function close() {
    if (surface === "intercept") context.closeInterceptContextMenu();
    else if (surface === "history") context.closeContextMenu();
    else document.dispatch("click");
  }
  return { context, state, requests, writes, fallback, toasts, errors, attached, open, click, setSession, navigate, close };
}
const response = value => ({ ok: true, json: async () => value });
async function pendingRead(f, stage) {
  f.open(); f.click();
  const pending = stage === "fetch" ? f.requests[0] : deferred();
  if (stage === "JSON") { f.requests[0].resolve({ ok: true, json: () => pending.promise }); await tick(); }
  return {
    succeed: () => pending.resolve(stage === "fetch" ? response(record()) : record()),
    fail: () => pending.reject(new Error("Synthetic read failure")),
  };
}

for (const surface of ["history", "pane"]) {
  for (const stage of ["fetch", "JSON"]) {
    test(`${surface}: explicit copy keeps the captured record and format after ${stage} and ordinary navigation`, async () => {
      const f = fixture(surface); const pending = await pendingRead(f, stage);
      f.navigate(); pending.succeed(); await tick();
      assert.equal(f.writes.length, 1);
      assert.match(f.writes[0].text, /https:\/\/example\.com\/a/);
      assert.match(f.writes[0].text, /request-a/); assert.doesNotMatch(f.writes[0].text, /request-b/);
      f.writes[0].resolve(); await tick(); assert.deepEqual(f.toasts, [["Copied as curl"]]);
      assert.equal(f.state.selectedId, "b");
    });
    for (const boundary of ["session switch", "session round trip"]) for (const outcome of ["success", "failure"]) {
      test(`${surface}: ${boundary} cancels late ${stage} ${outcome} without stale feedback`, async () => {
        const f = fixture(surface); const pending = await pendingRead(f, stage);
        f.setSession("session-b"); if (boundary === "session round trip") f.setSession("session-a");
        if (outcome === "success") pending.succeed(); else pending.fail(); await tick();
        assert.deepEqual(f.writes, []); assert.deepEqual(f.toasts, []); assert.deepEqual(f.errors, []);
      });
    }
  }
  test(`${surface}: cached-record callback cannot start writing after the session changes`, async () => {
    const f = fixture(surface, { cached: true }); f.open(); f.click(); f.setSession("session-b"); await tick();
    assert.deepEqual(f.writes, []); assert.deepEqual(f.toasts, []);
  });
  for (const outcome of ["success", "failure"]) for (const roundTrip of [false, true]) {
    test(`${surface}: submitted copy ${outcome} cannot add stale feedback or fallback after reset (round trip ${roundTrip})`, async () => {
      const f = fixture(surface, { cached: true }); f.open(); f.click(); await tick();
      assert.equal(f.writes.length, 1);
      f.setSession("session-b"); if (roundTrip) f.setSession("session-a");
      if (outcome === "success") f.writes[0].resolve(); else f.writes[0].reject(new Error("Synthetic clipboard denial"));
      await tick(); assert.deepEqual(f.fallback, []); assert.deepEqual(f.toasts, []); assert.equal(f.attached.size, 0);
    });
  }
  for (const outcome of ["read rejection", "HTTP error", "missing record", "wrong record"]) {
    test(`${surface}: current ${outcome} reports failure and never copies a replacement selection`, async () => {
      const f = fixture(surface); f.open(); f.click(); f.navigate();
      if (outcome === "read rejection") f.requests[0].reject(new Error("Synthetic failed read"));
      else if (outcome === "HTTP error") f.requests[0].resolve({ ok: false });
      else f.requests[0].resolve(response(outcome === "missing record" ? null : record("b")));
      await tick(); assert.deepEqual(f.writes, []);
      assert.deepEqual(f.toasts, [["Selected transaction could not be loaded.", "error"]]);
    });
  }
  test(`${surface}: dismissing the menu without choosing an action never copies`, async () => {
    const f = fixture(surface); f.open(); f.close(); f.requests[0].resolve(response(record())); await tick();
    assert.deepEqual(f.writes, []); assert.deepEqual(f.toasts, []);
  });
  for (const format of ["curl", "python", "fetch", "powershell"]) {
    test(`${surface}: production ${format} action preserves its captured format`, async () => {
      const f = fixture(surface); f.open(); f.click(`copy-as-${format}`); f.navigate();
      f.requests[0].resolve(response(record())); await tick();
      assert.equal(f.writes[0].text, f.context.recordToFormat(record(), format));
      f.writes[0].resolve(); await tick(); assert.deepEqual(f.toasts, [[`Copied as ${format}`]]);
    });
  }
}

for (const surface of ["history", "pane"]) {
  for (const copied of [true, false]) {
    test(`${surface}: current rejected modern copy reports fallback result ${copied} accurately`, async () => {
      const f = fixture(surface, { cached: true, fallbackResult: copied }); f.open(); f.click(); await tick();
      f.writes[0].reject(new Error("Synthetic clipboard denial")); await tick();
      assert.equal(f.fallback.length, 1); assert.equal(f.attached.size, 0);
      assert.deepEqual(f.toasts, copied ? [["Copied as curl"]] : [["Clipboard copy failed", "error"]]);
    });
  }
  test(`${surface}: same-session workspace hydration preserves an explicit pending export`, async () => {
    const f = fixture(surface); const pending = await pendingRead(f, "fetch");
    const start = appSource.indexOf("function applyWorkspaceState(snapshot) {");
    const end = appSource.indexOf("  for (const tab of state.replayTabs || [])", start);
    assert.ok(start >= 0 && end > start);
    f.context.workspaceSnapshotMatchesActiveSession = () => true;
    vm.runInContext(`${appSource.slice(start, end)}\n}`, f.context);
    f.context.applyWorkspaceState({ session_id: "session-a" });
    assert.equal(f.context.workspaceStateGeneration, 1);
    pending.succeed(); await tick(); assert.equal(f.writes.length, 1);
    f.writes[0].resolve(); await tick(); assert.deepEqual(f.toasts, [["Copied as curl"]]);
  });
  for (const outcome of ["success", "failure"]) {
    test(`${surface}: URL copy keeps its original target through ordinary navigation (${outcome})`, async () => {
      const f = fixture(surface, { cached: true }); f.open(); f.navigate(); f.click("copy-url");
      assert.equal(f.writes[0].text, "https://example.com/a");
      if (outcome === "success") f.writes[0].resolve(); else f.writes[0].reject(new Error("Synthetic clipboard denial"));
      await tick(); assert.deepEqual(f.toasts, [["Copied URL"]]);
    });
    test(`${surface}: URL copy suppresses session-round-trip ${outcome} and fallback`, async () => {
      const f = fixture(surface, { cached: true }); f.open(); f.click("copy-url");
      f.setSession("session-b"); f.setSession("session-a");
      if (outcome === "success") f.writes[0].resolve(); else f.writes[0].reject(new Error("Synthetic clipboard denial"));
      await tick(); assert.deepEqual(f.fallback, []); assert.deepEqual(f.toasts, []);
    });
  }
}

for (const [format, label] of [["headers", "Copied headers"], ["body", "Copied body"], ["raw", "Copied raw response"]]) {
  test(`pane: response ${format} follows its captured record after navigation`, async () => {
    const f = fixture("pane"); f.open(); f.click(`copy-response-${format}`); f.navigate();
    f.requests[0].resolve(response(record())); await tick();
    assert.equal(f.writes.length, 1);
    assert.match(f.writes[0].text, format === "body" ? /response-a/ : /X-Fixture: a/);
    assert.doesNotMatch(f.writes[0].text, /response-b|X-Fixture: b/);
    f.writes[0].resolve(); await tick(); assert.deepEqual(f.toasts, [[label]]);
  });
  for (const stage of ["read", "clipboard"]) for (const outcome of ["success", "failure"]) {
    test(`pane: response ${format} cancels stale ${stage} ${outcome} after a session round trip`, async () => {
      const f = fixture("pane"); f.open(); f.click(`copy-response-${format}`);
      if (stage === "clipboard") { f.requests[0].resolve(response(record())); await tick(); assert.equal(f.writes.length, 1); }
      f.setSession("session-b"); f.setSession("session-a");
      const pending = stage === "read" ? f.requests[0] : f.writes[0];
      if (outcome === "success") pending.resolve(stage === "read" ? response(record()) : undefined);
      else pending.reject(new Error("Synthetic delayed failure"));
      await tick(); assert.deepEqual(f.fallback, []); assert.deepEqual(f.toasts, []); assert.equal(f.attached.size, 0);
      if (stage === "read") assert.deepEqual(f.writes, []);
    });
  }
}

// Held-request menu checks invoke only copy-format actions. No forward, drop,
// send, editor, interception configuration, or other mutation callback is used.
function heldRecord(id = "a") {
  const source = record(id);
  return { id, request: { method: source.method, scheme: source.scheme, host: source.host, path: source.path,
    headers: source.request.headers, body: source.request.body_preview, body_encoding: "utf8" } };
}
async function pendingHeldRead(f, stage) {
  f.open(); f.click();
  assert.equal(f.requests[0].url, "/api/intercepts/a?session_id=session-a");
  const pending = stage === "fetch" ? f.requests[0] : deferred();
  if (stage === "JSON") { f.requests[0].resolve({ ok: true, json: () => pending.promise }); await tick(); }
  return {
    succeed: () => pending.resolve(stage === "fetch" ? response(heldRecord()) : heldRecord()),
    fail: () => pending.reject(new Error("Synthetic read failure")),
  };
}
for (const stage of ["fetch", "JSON"]) {
  test(`held request: explicit copy preserves its target through ${stage} and navigation`, async () => {
    const f = fixture("intercept"); const pending = await pendingHeldRead(f, stage); f.navigate();
    pending.succeed(); await tick();
    assert.equal(f.writes.length, 1); assert.match(f.writes[0].text, /https:\/\/example\.com\/a/);
    assert.match(f.writes[0].text, /request-a/); assert.doesNotMatch(f.writes[0].text, /request-b/);
    f.writes[0].resolve(); await tick(); assert.deepEqual(f.toasts, [["Copied as curl"]]);
  });
  for (const roundTrip of [false, true]) for (const outcome of ["success", "failure"]) {
    test(`held request: cancels ${stage} ${outcome} after session change (round trip ${roundTrip})`, async () => {
      const f = fixture("intercept"); const pending = await pendingHeldRead(f, stage);
      f.setSession("session-b"); if (roundTrip) f.setSession("session-a");
      if (outcome === "success") pending.succeed(); else pending.fail(); await tick();
      assert.deepEqual(f.writes, []); assert.deepEqual(f.toasts, []); assert.deepEqual(f.errors, []);
    });
  }
}
for (const roundTrip of [false, true]) for (const outcome of ["success", "failure"]) {
  test(`held request: late clipboard ${outcome} stays silent after session change (round trip ${roundTrip})`, async () => {
    const f = fixture("intercept"); const pending = await pendingHeldRead(f, "fetch");
    pending.succeed(); await tick(); assert.equal(f.writes.length, 1);
    f.setSession("session-b"); if (roundTrip) f.setSession("session-a");
    if (outcome === "success") f.writes[0].resolve(); else f.writes[0].reject(new Error("Synthetic clipboard denial"));
    await tick(); assert.deepEqual(f.fallback, []); assert.deepEqual(f.toasts, []);
  });
}
for (const format of ["curl", "python", "fetch", "powershell"]) {
  test(`held request: production ${format} action keeps its captured format`, async () => {
    const f = fixture("intercept"); f.open(); f.click(`copy-as-${format}`); f.navigate();
    f.requests[0].resolve(response(heldRecord())); await tick();
    assert.equal(f.writes[0].text, f.context.recordToFormat(record(), format));
    f.writes[0].resolve(); await tick(); assert.deepEqual(f.toasts, [[`Copied as ${format}`]]);
  });
}
for (const outcome of ["rejection", "HTTP error"]) {
  test(`held request: current read ${outcome} reports failure without copying`, async () => {
    const f = fixture("intercept"); f.open(); f.click();
    if (outcome === "rejection") f.requests[0].reject(new Error("Synthetic read failure"));
    else f.requests[0].resolve({ ok: false });
    await tick(); assert.deepEqual(f.writes, []); assert.deepEqual(f.toasts, [["Synthetic read failure", "error"]]);
  });
}
for (const roundTrip of [false, true]) {
  test(`held request: a menu opened before a session change cannot initiate a later read (round trip ${roundTrip})`, async () => {
    const f = fixture("intercept"); f.open(); f.setSession("session-b"); if (roundTrip) f.setSession("session-a");
    f.click(); await tick(); assert.deepEqual(f.requests, []); assert.deepEqual(f.writes, []); assert.deepEqual(f.toasts, []);
  });
}
