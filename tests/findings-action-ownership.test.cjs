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
  return { disabled: false, dataset: {}, listeners: {}, classes,
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
    "retireFindingActionProgress", "invalidateFindingNavigation", "setActiveTool", "setActiveProxyTab", "clearFindingDetail", "renderFindingDetailLoading", "setFindingDetailActionsEnabled",
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


for (const kind of ["replay", "fuzzer"]) {
  for (const boundary of ["close", "loading"]) {
    test(`${kind} progress cannot re-enable a ${boundary} detail`, async () => {
      const f = fixture();
      const button = f.buttons[kind === "replay" ? "findingsDetailSendReplay" : "findingsDetailSendFuzzer"];
      const pending = f.begin(kind, "mouse");
      assert.equal(button.disabled, true);
      assert.equal(button.classes.has("is-working"), true);
      if (boundary === "close") f.c.clearFindingDetail();
      else { f.c.findingsDetailGeneration += 1; f.c.renderFindingDetailLoading(); }
      f.reads[0].resolve(response());
      await pending; await tick();
      assert.equal(button.disabled, true, "detail state still owns the disabled button");
      assert.equal(button.classes.size, 0);
      assert.deepEqual(f.opens, []);
    });
  }
  test(`${kind} old cleanup cannot clear a newer selected finding's progress`, async () => {
    const f = fixture();
    const button = f.buttons[kind === "replay" ? "findingsDetailSendReplay" : "findingsDetailSendFuzzer"];
    const old = f.begin(kind, "mouse");
    f.select("b");
    const newer = f.begin(kind, "mouse");
    assert.equal(f.reads.length, 2);
    f.reads[0].resolve(response()); await old; await tick();
    assert.equal(button.disabled, true);
    assert.equal(button.classes.has("is-working"), true);
    f.reads[1].resolve(response("record-b")); await newer; await tick();
    assert.equal(button.disabled, false);
    assert.equal(button.classes.size, 0);
    assert.deepEqual(f.opens, [[kind, "record-b"]]);
  });
}


for (const kind of ["replay", "fuzzer"]) {
  for (const boundary of ["tool-aba", "tab-aba", "settings-tool-aba", "settings-tab-aba"]) {
    for (const stage of ["fetch", "json"]) {
      for (const outcome of ["success", "failure"]) {
        test(`${kind} ${boundary} retires ${stage} progress before obsolete ${outcome}`, async () => {
          const f = fixture();
          const button = f.buttons[kind === "replay" ? "findingsDetailSendReplay" : "findingsDetailSendFuzzer"];
          const old = f.begin(kind, "mouse"), body = deferred();
          let oldRead = f.reads[0];
          if (stage === "json") {
            oldRead.resolve({ ok: true, json: () => body.promise }); await tick(); oldRead = body;
          }
          crossBoundary(f, boundary);
          assert.equal(button.disabled, false, "returning to a retained detail permits a fresh action");
          assert.equal(button.classes.size, 0, "obsolete progress no longer owns the retained button");
          const newer = f.begin(kind, "mouse");
          assert.equal(f.reads.length, 2);
          if (outcome === "failure") oldRead.reject(new Error("Obsolete request failed."));
          else oldRead.resolve(stage === "json" ? { id: "record-a" } : response());
          await old; await tick();
          assert.equal(button.disabled, true, "late cleanup cannot retire the newer action");
          assert.equal(button.classes.has("is-working"), true);
          f.reads[1].resolve(response()); await newer; await tick();
          assert.equal(button.disabled, false); assert.equal(button.classes.size, 0);
          assert.deepEqual(f.opens, [[kind, "record-a"]]); assert.deepEqual(f.errors, []);
        });
      }
    }
  }
  test(`${kind} no-op navigation and same-view settings retain current progress`, async () => {
    const f = fixture();
    const button = f.buttons[kind === "replay" ? "findingsDetailSendReplay" : "findingsDetailSendFuzzer"];
    const pending = f.begin(kind, "mouse");
    f.c.setActiveTool("proxy"); f.c.setActiveProxyTab("findings"); wireSettingsSnapshot(f);
    f.c.applyUiSettingsSnapshot({ active_tool: "proxy", active_proxy_tab: "findings" });
    assert.equal(button.disabled, true); assert.equal(button.classes.has("is-working"), true);
    f.begin(kind, "mouse"); assert.equal(f.reads.length, 1);
    f.reads[0].resolve(response()); await pending; await tick();
    assert.deepEqual(f.opens, [[kind, "record-a"]]);
  });
  for (const state of ["closed", "loading"]) {
    test(`${kind} navigation does not enable an intrinsically ${state} detail`, async () => {
      const f = fixture();
      const button = f.buttons[kind === "replay" ? "findingsDetailSendReplay" : "findingsDetailSendFuzzer"];
      const pending = f.begin(kind, "mouse");
      if (state === "closed") f.c.clearFindingDetail();
      else { f.c.findingsDetailGeneration += 1; f.c.renderFindingDetailLoading(); }
      crossBoundary(f, "tool-aba");
      assert.equal(button.disabled, true); assert.equal(button.classes.size, 0);
      f.reads[0].resolve(response()); await pending; await tick();
      assert.equal(button.disabled, true); assert.deepEqual(f.opens, []);
    });
  }
}


for (const kinds of [["replay", "fuzzer"], ["fuzzer", "replay"]]) {
  for (const oldStage of ["fetch", "json"]) {
    for (const newStage of ["fetch", "json"]) {
      for (const oldOutcome of ["success", "failure"]) {
        for (const newOutcome of ["success", "failure"]) {
          test(`${kinds.join(" then ")} retires old ${oldStage} ${oldOutcome} before new ${newStage} ${newOutcome}`, async () => {
            const f = fixture();
            const control = kind => f.buttons[kind === "replay" ? "findingsDetailSendReplay" : "findingsDetailSendFuzzer"];
            const old = f.begin(kinds[0], "mouse"), oldBody = deferred(), newBody = deferred();
            let oldRead = f.reads[0];
            if (oldStage === "json") {
              oldRead.resolve({ ok: true, json: () => oldBody.promise }); await tick(); oldRead = oldBody;
            }
            const newer = f.begin(kinds[1], "mouse");
            let newRead = f.reads[1];
            if (newStage === "json") {
              newRead.resolve({ ok: true, json: () => newBody.promise }); await tick(); newRead = newBody;
            }
            assert.equal(control(kinds[0]).disabled, false, "superseded progress must not block a retry");
            assert.equal(control(kinds[0]).classes.size, 0);
            assert.equal(control(kinds[1]).disabled, true);
            assert.equal(control(kinds[1]).classes.has("is-working"), true);
            if (newOutcome === "failure") newRead.reject(new Error("Current request failed."));
            else newRead.resolve(newStage === "json" ? { id: "record-a" } : response());
            if (newOutcome === "failure") await assert.rejects(newer, /Current request failed/);
            else await newer;
            await tick();
            let retry;
            if (newOutcome === "failure") {
              retry = f.begin(kinds[0], "mouse"); assert.equal(f.reads.length, 3);
              assert.equal(control(kinds[0]).disabled, true);
            }
            if (oldOutcome === "failure") oldRead.reject(new Error("Obsolete request failed."));
            else oldRead.resolve(oldStage === "json" ? { id: "record-a" } : response());
            await old; await tick();
            if (retry) {
              assert.equal(control(kinds[0]).disabled, true, "old cleanup cannot finish the retry");
              assert.equal(control(kinds[0]).classes.has("is-working"), true);
              f.reads[2].resolve(response()); await retry; await tick();
            }
            assert.deepEqual(f.opens, [[newOutcome === "failure" ? kinds[0] : kinds[1], "record-a"]]);
            assert.deepEqual(f.errors, newOutcome === "failure" ? ["Current request failed."] : []);
            for (const button of Object.values(f.buttons)) {
              assert.equal(button.disabled, false); assert.equal(button.classes.size, 0);
            }
          });
        }
      }
    }
  }
}

test("keyboard Replay retires a mouse Fuzzer owner without creating button progress", async () => {
  const f = fixture(), old = f.begin("fuzzer", "mouse"), newer = f.begin("replay", "keyboard");
  assert.equal(f.buttons.findingsDetailSendFuzzer.disabled, false);
  assert.equal(f.buttons.findingsDetailSendFuzzer.classes.size, 0);
  assert.equal(f.buttons.findingsDetailSendReplay.disabled, false);
  f.reads[1].reject(new Error("Current keyboard request failed."));
  await assert.rejects(newer, /Current keyboard request failed/); await tick();
  const retry = f.begin("fuzzer", "mouse"); assert.equal(f.reads.length, 3);
  f.reads[0].resolve(response()); await old; await tick();
  assert.equal(f.buttons.findingsDetailSendFuzzer.disabled, true);
  f.reads[2].resolve(response()); await retry; await tick();
  assert.deepEqual(f.opens, [["fuzzer", "record-a"]]);
  assert.deepEqual(f.errors, ["Current keyboard request failed."]);
});

test("a mouse Fuzzer action supersedes keyboard Replay without retiring its own progress", async () => {
  const f = fixture(), old = f.begin("replay", "keyboard"), newer = f.begin("fuzzer", "mouse");
  assert.equal(f.buttons.findingsDetailSendFuzzer.disabled, true);
  assert.equal(f.buttons.findingsDetailSendFuzzer.classes.has("is-working"), true);
  f.reads[0].reject(new Error("Obsolete keyboard request failed.")); await old; await tick();
  assert.equal(f.buttons.findingsDetailSendFuzzer.disabled, true);
  f.reads[1].resolve(response()); await newer; await tick();
  assert.deepEqual(f.opens, [["fuzzer", "record-a"]]); assert.deepEqual(f.errors, []);
});


for (const kinds of [["replay", "fuzzer", "replay"], ["fuzzer", "replay", "fuzzer"]]) {
  for (const order of [[0, 1], [1, 0]]) {
    for (const outcome of ["success", "failure"]) {
      test(`${kinds.join("/")} keeps the third owner after ${order.join("/")} ${outcome}`, async () => {
        const f = fixture(), pending = kinds.map(kind => f.begin(kind, "mouse"));
        assert.equal(f.reads.length, 3);
        const button = f.buttons[kinds[2] === "replay" ? "findingsDetailSendReplay" : "findingsDetailSendFuzzer"];
        for (const index of order) {
          if (outcome === "failure") f.reads[index].reject(new Error("Obsolete request failed."));
          else f.reads[index].resolve(response());
          await pending[index]; await tick();
          assert.equal(button.disabled, true); assert.equal(button.classes.has("is-working"), true);
          assert.deepEqual(f.opens, []); assert.deepEqual(f.errors, []);
        }
        f.reads[2].resolve(response()); await pending[2]; await tick();
        assert.equal(button.disabled, false); assert.equal(button.classes.size, 0);
        assert.deepEqual(f.opens, [[kinds[2], "record-a"]]);
      });
    }
  }
}
