// Production action and input callbacks; all reads are deferred in memory.
// No app bootstrap, browser, server, traffic, or credentials.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");
const tick = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const response = (id = "record-a") => ({ ok: true, json: async () => ({ id }) });
function button() {
  const classes = new Set();
  return { disabled: false, dataset: {}, listeners: {},
    classList: { add: (...names) => names.forEach(name => classes.add(name)),
      remove: (...names) => names.forEach(name => classes.delete(name)) },
    addEventListener(name, callback) { this.listeners[name] = callback; },
    click() { if (!this.disabled) this.listeners.click?.({}); } };
}
function fixture() {
  const state = { activeSession: { id: "session-a" }, activeTool: "proxy", activeProxyTab: "findings" };
  const reads = [], opens = [], errors = [], actions = [];
  const buttons = { findingsDetailSendReplay: button(), findingsDetailSendFuzzer: button() };
  const els = { findingsDetailJump: button() };
  els.findingsDetailJump.dataset.recordId = "record-a";
  const c = loadFunctions([
    "runFindingAction", "sendFindingToReplay", "sendFindingToFuzzer", "openFuzzerFromRecordLoader",
    "setActiveTool", "setActiveProxyTab", "clearFindingDetail", "setFindingDetailActionsEnabled",
    "onClickWithProgress", "withButtonProgress", "requireOkResponse", "readApiErrorMessage",
    "formatStructuredApiErrorMessage",
  ], {
    state, els, workspaceStateGeneration: 0, selectedFindingId: "finding-a",
    findingsDetailGeneration: 0, findingActionPending: null, BUTTON_PROGRESS_DELAY_MS: 180,
    currentSessionId: () => state.activeSession.id,
    transactionPath: (id, session) => `/api/transactions/${id}?session_id=${session}`,
    fetch(url) { const read = { url, ...deferred() }; reads.push(read); return read.promise; },
    openTransactionRecordInReplay(record) { opens.push(["replay", record.id]); c.setActiveTool("replay"); },
    openFuzzerFromRecord(record) { opens.push(["fuzzer", record.id]); c.setActiveTool("fuzzer"); },
    handleFindingActionError: error => errors.push(error.message),
    sanitizeActiveTool: value => value, sanitizeActiveProxyTab: value => value,
    scheduleUiSettingsSave() {}, closeScannerSettings() {}, resetFindingsSearchUi() {},
    getCMView: () => null, document: { getElementById: id => buttons[id] || null },
    setTimeout, clearTimeout,
  });
  for (const name of ["sendFindingToReplay", "sendFindingToFuzzer"]) {
    const original = c[name];
    c[name] = (...args) => { const pending = original(...args); actions.push(pending); return pending; };
  }
  // Wire exactly the production mouse and keyboard handlers.
  const bindStart = appSource.indexOf('  const findingsReplayBtn =', appSource.indexOf("function bindFindingsEvents()"));
  const bindEnd = appSource.indexOf("  if (els.findingsRescanButton)", bindStart);
  assert.ok(bindStart > 0 && bindEnd > bindStart);
  vm.runInContext(appSource.slice(bindStart, bindEnd), c);
  const keyStart = appSource.indexOf("    // Cmd+R on Findings tab");
  const firstIf = appSource.indexOf("\n    if (", keyStart);
  const keyEnd = appSource.indexOf("\n    if (", firstIf + 1);
  assert.ok(keyStart > 0 && keyEnd > keyStart);
  vm.runInContext(`function shortcut(event) {${appSource.slice(keyStart, keyEnd)}}`, c);
  function select(id = "a") {
    c.selectedFindingId = `finding-${id}`;
    c.findingsDetailGeneration += 1;
    els.findingsDetailJump.dataset.recordId = `record-${id}`;
    c.setFindingDetailActionsEnabled(true);
  }
  function begin(kind = "replay", route = "direct") {
    const name = kind === "replay" ? "sendFindingToReplay" : "sendFindingToFuzzer";
    if (route === "direct") return c[name](els.findingsDetailJump.dataset.recordId);
    if (route === "mouse") buttons[kind === "replay" ? "findingsDetailSendReplay" : "findingsDetailSendFuzzer"].click();
    else c.shortcut({ metaKey: true, key: "r", preventDefault() {} });
    return actions.at(-1);
  }
  return { c, state, els, reads, opens, errors, buttons, actions, select, begin };
}

function wireSettingsSnapshot(f) {
  for (const name of [
    "updateUiSettingsServerRevision", "sanitizeDisplaySettings", "sanitizeHistoryColumnWidths",
    "sanitizeHistoryColumnOrder", "sanitizeHttpQuery", "sanitizeHttpMethod", "sanitizeHttpSortKey",
    "sanitizeHttpSortDirection", "sanitizeHttpFilterSettings", "sanitizeWorkbenchHeight",
    "sanitizeWorkbenchPaneWidths", "sanitizeWebsocketPaneWidth", "sanitizeServiceMapDetailWidth",
    "applyServiceMapDetailWidth", "sanitizeWebsocketQuery", "sanitizeWebsocketSortKey",
    "sanitizeWebsocketSortDirection", "sanitizeWebsocketStackHeight", "sanitizeWsReplayLeftWidth",
    "sanitizeWsReplayFrameDetailHeight", "hydrateFilterForm", "syncColorTagFilterUI",
    "syncHttpInScopePill", "syncHttpCapturePill", "hydrateDisplaySettingsForm",
    "previewDisplaySettingsFromForm", "applyDisplaySettingsState", "renderHistoryHeader",
    "applyHistoryColumnWidths", "applyWsColumnWidths", "updateWebsocketSortIndicators",
    "applySavedWorkbenchPaneWidths", "applySavedWebsocketPaneWidth", "applySavedWebsocketStackHeight",
    "applySavedWsReplayLayout", "applyWorkbenchStackHeight",
  ]) f.c[name] = value => value;
  f.c.isModalVisible = () => false;
  f.c.displaySettingsReady = false;
  f.c.displaySettingsPreviewActive = false;
  vm.runInContext(appSource.match(/^function applyUiSettingsSnapshot\([^]*?^\}/m)[0], f.c);
}

function crossBoundary(f, boundary) {
  if (boundary === "close") f.c.clearFindingDetail();
  if (boundary === "reselect") f.select("b");
  if (boundary === "selection-aba") { f.select("b"); f.select("a"); }
  if (boundary === "tool-leave" || boundary === "tool-aba") {
    f.c.setActiveTool("map");
    if (boundary === "tool-aba") f.c.setActiveTool("proxy");
  }
  if (boundary === "tab-aba") { f.c.setActiveProxyTab("http-history"); f.c.setActiveProxyTab("findings"); }
  if (boundary === "session-aba") {
    f.state.activeSession.id = "session-b"; f.c.workspaceStateGeneration += 1;
    f.state.activeSession.id = "session-a"; f.c.workspaceStateGeneration += 1;
  }
  if (boundary === "workspace") f.c.workspaceStateGeneration += 1;
  if (boundary.startsWith("settings-")) {
    wireSettingsSnapshot(f);
    f.c.applyUiSettingsSnapshot(boundary === "settings-tool-aba"
      ? { active_tool: "map", active_proxy_tab: "findings" }
      : { active_tool: "proxy", active_proxy_tab: "http-history" });
    f.c.applyUiSettingsSnapshot({ active_tool: "proxy", active_proxy_tab: "findings" });
  }
}

for (const kind of ["replay", "fuzzer"]) {
  for (const stage of ["fetch", "json"]) {
    for (const outcome of ["success", "failure"]) {
      for (const boundary of ["close", "reselect", "selection-aba", "tool-leave", "tool-aba",
        "tab-aba", "session-aba", "workspace", "settings-tool-aba", "settings-tab-aba"]) {
        test(`${kind} ignores ${stage} ${outcome} after ${boundary}`, async () => {
          const f = fixture(), pending = f.begin(kind), body = deferred();
          let deferredRead = f.reads[0];
          if (stage === "json") {
            deferredRead.resolve({ ok: true, json: () => body.promise }); await tick();
            deferredRead = body;
          }
          crossBoundary(f, boundary);
          if (outcome === "failure") deferredRead.reject(new Error("Obsolete read failed."));
          else deferredRead.resolve(stage === "json" ? { id: "record-a" } : response());
          assert.equal(await pending, false);
          assert.deepEqual(f.opens, []);
          assert.deepEqual(f.errors, []);
        });
      }
    }
  }
  for (const stage of ["fetch", "json", "status"]) {
    test(`${kind} reports a current ${stage} error and permits retry`, async () => {
      const f = fixture(), pending = f.begin(kind);
      if (stage === "fetch") f.reads[0].reject(new Error("Current read failed."));
      else if (stage === "json") f.reads[0].resolve({ ok: true, json: async () => { throw new Error("Current body failed."); } });
      else f.reads[0].resolve({ ok: false, headers: { get: () => "text/plain" }, text: async () => "Current transaction failed." });
      await assert.rejects(pending, /Current/);
      assert.equal(f.c.findingActionPending, null);
      const retry = f.begin(kind); f.reads[1].resolve(response());
      assert.equal(await retry, true);
      assert.deepEqual(f.opens, [[kind, "record-a"]]);
    });
  }
  test(`${kind} allows same-view settings and no-op navigation during an action`, async () => {
    const f = fixture(), pending = f.begin(kind);
    f.c.setActiveTool("proxy"); f.c.setActiveProxyTab("findings"); wireSettingsSnapshot(f);
    f.c.applyUiSettingsSnapshot({ active_tool: "proxy", active_proxy_tab: "findings" });
    f.reads[0].resolve(response()); assert.equal(await pending, true);
    assert.deepEqual(f.opens, [[kind, "record-a"]]);
  });
  test(`${kind} permits a new selection before the older action settles`, async () => {
    const f = fixture(), old = f.begin(kind); f.select("b");
    const newer = f.begin(kind); f.reads[0].reject(new Error("Old request failed."));
    assert.equal(await old, false);
    assert.notEqual(f.c.findingActionPending, null, "old cleanup cannot clear the newer owner");
    f.reads[1].resolve(response("record-b")); assert.equal(await newer, true);
    assert.deepEqual(f.opens, [[kind, "record-b"]]);
  });
  for (const boundary of ["close", "reselect", "tool-aba", "session-aba"]) {
    test(`${kind} ignores a delayed HTTP error body after ${boundary}`, async () => {
      const f = fixture(), pending = f.begin(kind), body = deferred();
      f.reads[0].resolve({ ok: false, headers: { get: () => "text/plain" }, text: () => body.promise });
      await tick(); crossBoundary(f, boundary);
      body.resolve("Obsolete HTTP error.");
      assert.equal(await pending, false);
      assert.deepEqual(f.opens, []); assert.deepEqual(f.errors, []);
    });
  }
}

for (const routes of [["keyboard", "keyboard"], ["mouse", "mouse"], ["keyboard", "mouse"], ["mouse", "keyboard"]]) {
  for (const outcome of ["success", "failure"]) {
    test(`Replay ${routes.join(" then ")} is single-flight on ${outcome}`, async () => {
      const f = fixture(); f.begin("replay", routes[0]); f.begin("replay", routes[1]);
      assert.equal(f.reads.length, 1);
      if (outcome === "success") f.reads[0].resolve(response());
      else f.reads[0].reject(new Error("Current request failed."));
      await Promise.allSettled(f.actions); await tick();
      assert.equal(f.opens.length, outcome === "success" ? 1 : 0);
      assert.deepEqual(f.errors, outcome === "failure" ? ["Current request failed."] : []);
    });
  }
}

for (const kinds of [["replay", "fuzzer"], ["fuzzer", "replay"]]) {
  test(`newer ${kinds[1]} supersedes pending ${kinds[0]}`, async () => {
    const f = fixture(), old = f.begin(kinds[0]), newer = f.begin(kinds[1]);
    f.reads[1].resolve(response()); assert.equal(await newer, true);
    f.reads[0].resolve(response()); assert.equal(await old, false);
    assert.deepEqual(f.opens, [[kinds[1], "record-a"]]);
  });
}

test("Fuzzer duplicate calls share one read without superseding the first", async () => {
  const f = fixture(), first = f.begin("fuzzer"), duplicate = f.begin("fuzzer");
  assert.equal(await duplicate, false); assert.equal(f.reads.length, 1);
  f.reads[0].resolve(response()); assert.equal(await first, true);
  assert.deepEqual(f.opens, [["fuzzer", "record-a"]]);
});

test("an inactive or closed Findings view cannot start an action", async () => {
  const f = fixture(); f.c.setActiveTool("map");
  assert.equal(await f.c.sendFindingToReplay("record-a"), false);
  assert.equal(await f.c.sendFindingToFuzzer("record-a"), false);
  f.c.setActiveTool("proxy"); f.c.clearFindingDetail();
  assert.equal(await f.c.sendFindingToReplay("record-a"), false);
  assert.equal(await f.c.sendFindingToFuzzer("record-a"), false);
  assert.equal(f.reads.length, 0);
});
