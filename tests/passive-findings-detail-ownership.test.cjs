// Saved-detail presentation only. Actual row/close callbacks and detail helpers
// run in a VM; every fetch is synthetic deferred metadata, with no live runtime.
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
function element() {
  const classes = new Set();
  return { textContent: "", innerHTML: "", dataset: {}, listeners: {}, disabled: false,
    classList: { add: name => classes.add(name), remove: name => classes.delete(name), contains: name => classes.has(name) },
    addEventListener(name, callback) { this.listeners[name] = callback; } };
}
function fixture() {
  const requests = [], reads = [], errors = [];
  const rows = ["a", "b"].map(id => ({ ...element(), dataset: { findingId: id, recordId: `saved-${id}` } }));
  const els = Object.fromEntries([
    "findingsBody", "findingsDetailPanel", "findingsDetailPlaceholder", "findingsDetailContent",
    "findingsDetailTitle", "findingsDetailCategory", "findingsDetailSeverity", "findingsDetailDesc",
    "findingsDetailJump", "findingsDetailClose", "findingsReqView", "findingsResView",
  ].map(name => [name, element()]));
  els.findingsBody.querySelector = selector => selector === ".history-row.selected"
    ? rows.find(row => row.classList.contains("selected"))
    : rows.find(row => selector === `tr[data-finding-id="${row.dataset.findingId}"]`);
  const state = { activeSession: { id: "session-a" }, _findingsEntries: [] };
  const context = loadFunctions([
    "currentSessionId", "sessionQueryPath", "transactionPath", "loadFindingDetail", "clearFindingDetail",
    "renderFindingDetailLoading", "setFindingDetailActionsEnabled", "showFindingDetail",
    "updateFindingsSelection", "resetFindingsUiState", "severityClass", "severityLabel",
  ], { refreshHistoryFindings() {},
    state, els, selectedFindingId: null, findingsDetailGeneration: 0,
    findingsStateGeneration: 0, findingsLoadGeneration: 0, findingsData: [], findingsBadgeCount: 0,
    findingsLoadPromise: null, findingsLoadSessionId: null, lastFindingsBadgePollAt: 0,
    findingsBadgeRefreshTimer: 0, findingsListRefreshTimer: 0,
    document: { getElementById: () => null }, console: { error: (...args) => errors.push(args) },
    getCMView: () => null, resetFindingsSearchUi() {}, renderFindings() {}, updateFindingsBadge() {},
    renderFindingDescription(finding) { els.findingsDetailDesc.textContent = finding.detail || ""; },
    buildFindingsRawMessage: (record, side) => `${record.label} ${side}`,
    renderFindingsCodePane(container, lines, text) { container.innerHTML = text; },
    fallbackFindingLocationFromPaneResults() {}, scrollFindingLocationIntoView() {},
    fetch(url, options) {
      assert.equal(options, undefined, "detail reads never write or dispatch an action");
      const request = { url, ...deferred() }; requests.push(request); return request.promise;
    },
  });
  const load = context.loadFindingDetail;
  context.loadFindingDetail = id => { const promise = load(id); reads.push(promise); return promise; };
  // Bind the actual production click and close handlers without unrelated actions.
  const bindings = appSource.slice(appSource.indexOf("  // Event delegation for findings table rows", appSource.indexOf("function bindFindingsEvents()")));
  const clickEnd = bindings.indexOf('    els.findingsBody.addEventListener("dblclick"');
  vm.runInContext(`${bindings.slice(0, clickEnd)}  }`, context);
  const closeStart = bindings.indexOf("  if (els.findingsDetailClose) {");
  const closeEnd = bindings.indexOf("  if (els.findingsDetailJump) {", closeStart);
  vm.runInContext(bindings.slice(closeStart, closeEnd), context);
  function click(id = "a") {
    const row = rows.find(row => row.dataset.findingId === id);
    els.findingsBody.listeners.click({ target: { closest: selector => selector === "tr[data-finding-id]" ? row : null } });
    return reads.at(-1);
  }
  const finding = (label, id = "a") => ({ id, record_id: `saved-${label}`, title: label, category: "saved", severity: "info", detail: `${label} detail` });
  const response = body => ({ ok: true, json: async () => body });
  async function finishLatest(label = "newest") {
    requests.at(-1).resolve(response(finding(label, context.selectedFindingId)));
    await tick();
    requests.at(-1).resolve(response({ label }));
    await reads.at(-1);
  }
  function snapshot() {
    return { selected: context.selectedFindingId, title: els.findingsDetailTitle.textContent,
      highlighted: rows.filter(row => row.classList.contains("selected")).map(row => row.dataset.findingId),
      category: els.findingsDetailCategory.textContent, detail: els.findingsDetailDesc.textContent,
      recordId: els.findingsDetailJump.dataset.recordId, disabled: els.findingsDetailJump.disabled,
      request: els.findingsReqView.innerHTML, response: els.findingsResView.innerHTML,
      contentHidden: els.findingsDetailContent.classList.contains("hidden"),
      placeholderHidden: els.findingsDetailPlaceholder.classList.contains("hidden") };
  }
  return { context, state, els, rows, requests, reads, errors, click, finding, response, finishLatest, snapshot,
    close: () => els.findingsDetailClose.listeners.click() };
}

const stages = ["finding headers", "finding JSON", "transaction headers", "transaction JSON"];
async function pauseRead(f, stage) {
  const reading = f.click(), first = f.requests.at(-1);
  let pending = first, jsonCalls = 0;
  if (stage === "finding JSON") {
    pending = deferred(); first.resolve({ ok: true, json: () => { jsonCalls++; return pending.promise; } });
    await tick();
  } else if (stage.startsWith("transaction")) {
    first.resolve(f.response(f.finding("older"))); await tick();
    pending = f.requests.at(-1);
    if (stage === "transaction JSON") {
      const body = deferred(); pending.resolve({ ok: true, json: () => { jsonCalls++; return body.promise; } });
      pending = body; await tick();
    }
  }
  async function settle(outcome) {
    const before = f.requests.length;
    if (outcome === "rejection") pending.reject(new Error("Synthetic older read failed"));
    else if (outcome === "non-OK") pending.resolve({ ok: false, json() { throw new Error("Non-OK response must not be decoded"); } });
    else if (stage.endsWith("headers")) pending.resolve({ ok: true, json: async () => {
      jsonCalls++; return stage === "finding headers" ? f.finding("older") : { label: "older" };
    } });
    else pending.resolve(stage === "finding JSON" ? f.finding("older") : { label: "older" });
    await tick();
    // Let the pre-fix path terminate if it wrongly starts a stale transaction read.
    for (const request of f.requests.slice(before)) request.resolve(f.response({ label: "older" }));
    await reading;
  }
  return { settle, jsonCalls: () => jsonCalls };
}

for (const stage of stages) {
  for (const outcome of ["success", "rejection", ...(stage.endsWith("headers") ? ["non-OK"] : [])]) {
    test(`actual A→B→A row clicks preserve newest detail after older ${stage} ${outcome}`, async () => {
      const f = fixture(), old = await pauseRead(f, stage);
      f.click("b"); const middle = f.requests.at(-1);
      f.click("a"); await f.finishLatest();
      const before = f.snapshot(), count = f.requests.length, decoded = old.jsonCalls();
      assert.equal(before.selected, "a"); assert.equal(before.title, "newest");
      await old.settle(outcome);
      assert.deepEqual(f.snapshot(), before);
      assert.equal(f.requests.length, count, "superseded reads must not request another transaction");
      assert.equal(old.jsonCalls(), decoded, "superseded response headers must not start decoding");
      assert.equal(f.errors.length, 0, "superseded failures stay silent");
      middle.reject(new Error("Synthetic unselected read failed")); await Promise.all(f.reads);
      assert.deepEqual(f.snapshot(), before);
    });
  }
}

for (const transition of ["close", "session reset"]) {
  for (const reopen of [false, true]) {
    for (const outcome of ["success", "rejection"]) {
      test(`actual ${transition}${reopen ? " and reopen same ID" : ""} invalidates pending detail ${outcome}`, async () => {
        const f = fixture(), old = await pauseRead(f, "transaction JSON");
        if (transition === "close") f.close();
        else {
          f.state.activeSession = { id: "session-b" }; f.context.resetFindingsUiState();
          f.state.activeSession = { id: "session-a" }; f.context.resetFindingsUiState();
        }
        assert.equal(f.context.selectedFindingId, null);
        assert.deepEqual(f.snapshot().highlighted, [], "dismissal clears the visible row selection too");
        if (reopen) { f.click(); await f.finishLatest(); }
        const before = f.snapshot(); await old.settle(outcome);
        assert.deepEqual(f.snapshot(), before); assert.equal(f.errors.length, 0);
      });
    }
  }
}

for (const transaction of ["available", "non-OK", "fetch rejection", "JSON rejection"]) {
  test(`actual row click keeps ordinary detail with ${transaction} transaction`, async () => {
    const f = fixture(), reading = f.click();
    assert.equal(f.els.findingsDetailTitle.textContent, "Loading finding...");
    assert.equal(f.els.findingsDetailJump.disabled, true);
    assert.equal(f.els.findingsDetailJump.dataset.recordId, undefined);
    f.requests[0].resolve(f.response(f.finding("ordinary"))); await tick();
    const transactionRead = f.requests[1];
    if (transaction === "fetch rejection") transactionRead.reject(new Error("Synthetic unavailable transaction"));
    else if (transaction === "JSON rejection") transactionRead.resolve({ ok: true, json: async () => { throw new Error("Synthetic unavailable metadata"); } });
    else transactionRead.resolve({ ...f.response({ label: "ordinary" }), ok: transaction === "available" });
    await reading;
    assert.equal(f.context.selectedFindingId, "a"); assert.equal(f.els.findingsDetailTitle.textContent, "ordinary");
    assert.equal(f.els.findingsDetailJump.dataset.recordId, "saved-ordinary");
    assert.equal(f.els.findingsDetailJump.disabled, false);
    for (const side of ["Req", "Res"]) assert.match(f.els[`findings${side}View`].innerHTML,
      transaction === "available" ? /ordinary/ : /Transaction not available\./);
    assert.equal(f.errors.length, 0); assert.equal(f.requests.length, 2);
  });
}

for (const outcome of ["non-OK", "fetch rejection", "JSON rejection"]) {
  test(`actual row click keeps current finding ${outcome} failure behavior`, async () => {
    const f = fixture(); f.click(); await f.finishLatest("initial");
    const reading = f.click("b"), request = f.requests.at(-1);
    if (outcome === "fetch rejection") request.reject(new Error("Synthetic current read failed"));
    else if (outcome === "JSON rejection") request.resolve({ ok: true, json: async () => { throw new Error("Synthetic current decode failed"); } });
    else request.resolve({ ok: false });
    await reading;
    assert.equal(f.context.selectedFindingId, null); assert.equal(f.els.findingsDetailTitle.textContent, "");
    assert.deepEqual(f.snapshot().highlighted, [], "a failed detail read must not leave a selected row");
    assert.equal(f.els.findingsDetailJump.dataset.recordId, undefined); assert.equal(f.els.findingsDetailJump.disabled, true);
    assert.equal(f.els.findingsDetailContent.classList.contains("hidden"), true);
    assert.equal(f.els.findingsDetailPlaceholder.classList.contains("hidden"), false);
    assert.equal(f.errors.length, outcome === "non-OK" ? 0 : 1);
  });
}

test("older success cannot repopulate detail after the newest same-ID failure", async () => {
  const f = fixture(), old = await pauseRead(f, "transaction JSON");
  const latest = f.click(); f.requests.at(-1).reject(new Error("Synthetic latest failure")); await latest;
  const before = f.snapshot(); await old.settle("success");
  assert.deepEqual(f.snapshot(), before); assert.equal(f.context.selectedFindingId, null);
  assert.equal(f.errors.length, 1);
});

test("closing loaded detail clears its row highlight and repeated close remains inert", async () => {
  const f = fixture();
  f.click("b"); await f.finishLatest();
  assert.deepEqual(f.snapshot().highlighted, ["b"]);
  const requestCount = f.requests.length;
  f.close();
  assert.equal(f.context.selectedFindingId, null);
  assert.deepEqual(f.snapshot().highlighted, []);
  const closed = f.snapshot();
  f.close();
  assert.deepEqual(f.snapshot(), closed);
  assert.equal(f.requests.length, requestCount);

  f.click("a"); await f.finishLatest();
  assert.equal(f.context.selectedFindingId, "a");
  assert.deepEqual(f.snapshot().highlighted, ["a"]);
});

for (const revisit of [false, true]) {
  for (const outcome of ["success", "rejection"]) {
    test(`older detail ${outcome} leaves ${revisit ? "same-ID" : "different-ID"} newest request loading`, async () => {
      const f = fixture(), old = await pauseRead(f, "finding JSON");
      f.click(revisit ? "a" : "b");
      const before = f.snapshot(), count = f.requests.length;
      assert.equal(before.title, "Loading finding...");
      assert.equal(before.disabled, true);
      await old.settle(outcome);
      assert.deepEqual(f.snapshot(), before); assert.equal(f.requests.length, count);
      assert.equal(f.errors.length, 0);
      await f.finishLatest();
      assert.equal(f.els.findingsDetailTitle.textContent, "newest");
      assert.equal(f.context.selectedFindingId, revisit ? "a" : "b");
    });
  }
}

test("a changed session alone makes a pending detail failure ineligible", async () => {
  const f = fixture(), reading = f.click(), before = f.snapshot();
  f.state.activeSession = { id: "session-b" };
  f.requests[0].reject(new Error("Synthetic previous-session failure")); await reading;
  assert.deepEqual(f.snapshot(), before); assert.equal(f.errors.length, 0);
});
