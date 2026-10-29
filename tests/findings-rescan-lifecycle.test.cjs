// Invoke the shipped Rescan/filter/detail callbacks with deferred in-memory
// responses. No bootstrap, server, scanner, socket, persistence or live traffic.
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
const response = body => ({ ok: true, json: async () => body });
const finding = (id, title = id) => ({
  id, record_id: `saved-${id}`, title, category: "header", severity: "info",
  host: "example.com", path: "/saved", found_at: "2026-10-18T00:00:00Z", detail: `${title} detail`,
});
function element() {
  const classes = new Set();
  return { value: "", dataset: {}, innerHTML: "", textContent: "", disabled: false, listeners: {},
    classList: {
      add(...names) { names.forEach(name => classes.add(name)); },
      remove(...names) { names.forEach(name => classes.delete(name)); },
      contains: name => classes.has(name),
      toggle(name, enabled) { if (enabled) classes.add(name); else classes.delete(name); },
    },
    addEventListener(name, callback) { this.listeners[name] = callback; },
  };
}
function fixture() {
  const requests = [], works = [], reads = [], errors = [], toasts = [], timers = new Map();
  let timerId = 0;
  const els = Object.fromEntries([
    "findingsRescanButton", "findingsClearButton", "findingsBody", "findingsFilterSeverity",
    "findingsFilterCategory", "findingsFilterSearch", "findingsInScopeOnly", "findingsBadge",
    "findingsDetailPanel", "findingsDetailClose", "findingsDetailJump", "findingsDetailTitle",
    "findingsDetailSeverity", "findingsDetailCategory", "findingsDetailDesc", "findingsDetailContent",
    "findingsDetailPlaceholder", "findingsReqView", "findingsResView",
  ].map(name => [name, element()]));
  els.findingsFilterCategory.options = ["", "header"].map(value => ({ value, dataset: {} }));
  const rows = new Map();
  const row = id => {
    if (!rows.has(id)) rows.set(id, { ...element(), dataset: { findingId: id, recordId: `saved-${id}` } });
    return rows.get(id);
  };
  els.findingsBody.querySelector = selector => selector === ".history-row.selected"
    ? [...rows.values()].find(item => item.classList.contains("selected")) || null
    : [...rows.values()].find(item => selector === `tr[data-finding-id="${item.dataset.findingId}"]`) || null;
  const shell = { scrollTop: 0, clientHeight: 300 };
  const table = { tHead: { getBoundingClientRect: () => ({ height: 30 }) } };
  els.findingsBody.closest = selector => selector === "table" ? table : shell;
  const state = { activeSession: { id: "session-a" }, activeTool: "proxy", activeProxyTab: "findings", _findingsEntries: [] };
  const clearTimeout = id => timers.delete(id);
  const c = loadFunctions([
    "currentSessionId", "sessionQueryPath", "sessionWritePath", "expectedActiveSessionIdForWrite", "transactionPath",
    "onClickWithProgress", "withButtonProgress", "requireOkResponse", "readApiErrorMessage", "formatStructuredApiErrorMessage",
    "loadFindings", "fetchFindingsCount", "commitFindingsBadgeCount", "jsonArray", "resetFindingsUiState",
    "renderFindings", "getFilteredFindings", "updateCategoryFilter", "ensureFindingsCategoryOption", "renderFindingsVirtual",
    "getFindingsRowHeight", "measuredRowPitch", "severityClass", "severityLabel", "escapeHtml", "updateFindingsBadge",
    "retainedEntriesCap", "formatCappedCount", "clearFindingDetail", "updateFindingsSelection", "loadFindingDetail",
    "renderFindingDetailLoading", "setFindingDetailActionsEnabled", "showFindingDetail", "resetFindingsSearchUi",
  ], { refreshHistoryFindings() {},
    state, els, URLSearchParams, BUTTON_PROGRESS_DELAY_MS: 180,
    findingsData: [], findingsBadgeCount: 0, findingsLoadPromise: null, findingsLoadSessionId: null,
    findingsStateGeneration: 0, findingsLoadGeneration: 0, findingsCountReadGeneration: 0, findingsCountAcceptedGeneration: 0,
    findingsEventEpoch: 0, findingsBadgeRefreshTimer: 0, findingsListRefreshTimer: 0, lastFindingsBadgePollAt: 0,
    selectedFindingId: null, findingsDetailGeneration: 0, findingsSortKey: "title", findingsSortDir: "asc",
    FINDINGS_LIST_LIMIT: 5000, FINDINGS_ROW_HEIGHT: 30, FINDINGS_BUFFER_ROWS: 5, measuredFindingsRowHeight: 30,
    SEVERITY_ORDER: { critical: 0, high: 1, medium: 2, low: 3, info: 4 },
    BUILTIN_FINDING_CATEGORIES: new Set(["header"]), BUILTIN_RULE_LABELS: { header: "Headers" },
    document: { getElementById: () => null, createElement() { assert.fail("Unexpected category creation"); } },
    console: { error: (...args) => errors.push(args) }, showToast: (...args) => toasts.push(args),
    getCMView: () => null, clearSearchHighlights() {}, isInScopeHost: host => host === "example.com", formatTimestamp: value => value,
    renderFindingDescription(item) { els.findingsDetailDesc.textContent = item.detail; },
    buildFindingsRawMessage: (record, side) => `${record.label} ${side}`,
    renderFindingsCodePane(container, lines, text) { container.innerHTML = text; },
    fallbackFindingLocationFromPaneResults() {}, scrollFindingLocationIntoView() {},
    fetch(url, options) {
      // These objects never leave the fixture. Unexpected traffic is a failure.
      assert.match(url, /^\/api\/(findings|transactions)(?:[/?]|$)/);
      if (options) {
        assert.match(url, /^\/api\/findings\/(rescan|clear)\?/);
        assert.deepEqual({ ...options }, { method: "POST" });
      }
      const request = { url, options, ...deferred() }; requests.push(request); return request.promise;
    },
    setTimeout(callback, delay) { const id = ++timerId; timers.set(id, { callback, delay }); return id; },
    clearTimeout, window: { clearTimeout },
  });
  const progress = c.withButtonProgress;
  c.withButtonProgress = (button, callback) => { const p = progress(button, callback); works.push(p); return p; };
  const read = c.loadFindingDetail;
  c.loadFindingDetail = id => { const p = read(id); reads.push(p); return p; };
  const bindings = appSource.slice(appSource.indexOf("function bindFindingsEvents()"));
  const start = bindings.indexOf("  if (els.findingsRescanButton) {");
  const end = bindings.indexOf("  // Arrow key navigation", start);
  assert.ok(start > 0 && end > start);
  vm.runInContext(bindings.slice(start, end), c, { filename: "production-findings-rescan-clear-filter-bindings" });
  const clickStart = bindings.indexOf("  // Event delegation for findings table rows");
  const clickEnd = bindings.indexOf('    els.findingsBody.addEventListener("dblclick"', clickStart);
  vm.runInContext(`${bindings.slice(clickStart, clickEnd)}  }`, c);
  const closeStart = bindings.indexOf("  if (els.findingsDetailClose) {");
  const closeEnd = bindings.indexOf("  if (els.findingsDetailJump) {", closeStart);
  vm.runInContext(bindings.slice(closeStart, closeEnd), c);
  function prime(label = "initial") {
    c.findingsData = [finding(label)]; row(label); c.findingsBadgeCount = 1;
    c.renderFindings(); c.updateFindingsBadge();
  }
  const click = (name = "findingsRescanButton") => { els[name].listeners.click({}); return works.at(-1); };
  function select(id) {
    const selected = row(id);
    els.findingsBody.listeners.click({ target: { closest: () => selected } });
    return reads.at(-1);
  }
  async function loadDetail(id) {
    const work = select(id);
    requests.at(-1).resolve(response(finding(id))); await tick();
    requests.at(-1).resolve(response({ label: id })); await work;
  }
  function snapshot() {
    return JSON.stringify({
      data: c.findingsData, ids: state._findingsEntries.map(item => item.id), stateGeneration: c.findingsStateGeneration,
      selected: c.selectedFindingId, title: els.findingsDetailTitle.textContent,
      target: els.findingsDetailJump.dataset.recordId, disabled: els.findingsDetailJump.disabled,
      contentHidden: els.findingsDetailContent.classList.contains("hidden"),
      request: els.findingsReqView.innerHTML, response: els.findingsResView.innerHTML,
      table: els.findingsBody.innerHTML, badge: els.findingsBadge.textContent,
      filters: [els.findingsFilterSearch.value, els.findingsFilterSeverity.value, els.findingsFilterCategory.value, els.findingsInScopeOnly.classList.contains("active")],
    });
  }
  async function acknowledge(request = requests.find(item => item.options?.method === "POST")) {
    request.resolve(response({ scanned: 3, unreadable: 0, findings: 1 })); await tick();
  }
  async function finishList(label = "fresh", pair = requests.slice(-2)) {
    assert.match(pair[0].url, /^\/api\/findings\/count\?/);
    assert.match(pair[1].url, /^\/api\/findings\?limit=5000&session_id=/);
    pair[0].resolve(response({ count: 1 })); pair[1].resolve(response([finding(label)])); await tick();
  }
  function fire(delay) {
    for (const [id, timer] of [...timers]) if (timer.delay === delay) { timers.delete(id); timer.callback(); }
  }
  prime();
  return { c, state, els, requests, works, reads, errors, toasts, timers, prime, click, select, loadDetail, snapshot, acknowledge, finishList, fire };
}
function errorResponse(text) {
  return { ok: false, headers: { get: () => "text/plain" }, text: typeof text === "function" ? text : async () => text };
}
async function replace(f, transition) {
  if (transition === "different session") f.state.activeSession = { id: "session-b" };
  else if (transition === "session reset") { f.state.activeSession = { id: "session-b" }; f.c.resetFindingsUiState(); }
  else if (transition === "A→B→A") {
    f.state.activeSession = { id: "session-b" }; f.c.resetFindingsUiState();
    f.state.activeSession = { id: "session-a" }; f.c.resetFindingsUiState();
  } else if (transition === "same-session reset") f.c.resetFindingsUiState();
  else {
    const clearing = f.click("findingsClearButton");
    f.requests.at(-1).resolve(response({})); await clearing;
  }
  f.prime("newest"); await f.loadDetail("newest");
}

for (const transition of ["different session", "session reset", "A→B→A", "same-session reset", "Clear callback"]) {
  for (const outcome of ["success", "fetch rejection", "HTTP error", "delayed error body"]) {
    test(`pending Rescan ${outcome} cannot replace newer view or feedback after ${transition}`, async () => {
      const f = fixture(), pending = f.click(), request = f.requests[0];
      let body;
      if (outcome === "delayed error body") {
        body = deferred(); request.resolve(errorResponse(() => body.promise)); await tick();
      }
      await replace(f, transition);
      const before = f.snapshot(), requestCount = f.requests.length;
      if (body) body.resolve("Synthetic obsolete rescan error");
      else if (outcome === "fetch rejection") request.reject(new Error("Synthetic obsolete transport error"));
      else if (outcome === "HTTP error") request.resolve(errorResponse("Synthetic obsolete rescan error"));
      else request.resolve(response({}));
      await tick();
      // Permit a buggy baseline to finish its unintended list load, then assert.
      if (f.requests.length > requestCount) await f.finishList("obsolete");
      await pending;
      assert.equal(f.snapshot(), before, "old completion must not clear or repaint the newer finding/detail");
      assert.equal(f.requests.length, requestCount, "old acknowledgement must not start a new list/count read");
      assert.equal(f.errors.length, 0, "obsolete failures must stay silent");
      assert.equal(f.toasts.length, 0, "obsolete failures must not appear in the new view");
      assert.equal(f.els.findingsRescanButton.disabled, false);
      assert.equal(f.els.findingsRescanButton.classList.contains("is-working"), false);
      assert.equal(f.timers.size, 0);
    });
  }
}

for (const navigation of ["filter input", "close detail", "new detail", "other tab"]) {
  test(`ordinary same-session ${navigation} does not cancel the requested Rescan refresh`, async () => {
    const f = fixture(); await f.loadDetail("initial");
    const pending = f.click(), request = f.requests.at(-1);
    if (navigation === "filter input") {
      f.els.findingsFilterSearch.value = "fresh"; f.els.findingsFilterSearch.listeners.input(); f.fire(200);
    } else if (navigation === "close detail") f.els.findingsDetailClose.listeners.click();
    else if (navigation === "new detail") { f.prime("newest"); await f.loadDetail("newest"); }
    else f.state.activeProxyTab = "http-history";
    const generation = f.c.findingsStateGeneration;
    await f.acknowledge(request);
    assert.equal(f.c.findingsStateGeneration, generation + 1);
    assert.equal(f.c.selectedFindingId, null);
    await f.finishList(); await pending;
    assert.deepEqual(Array.from(f.c.findingsData, item => item.id), ["fresh"]);
    assert.equal(f.els.findingsFilterSearch.value, navigation === "filter input" ? "fresh" : "");
    assert.equal(f.errors.length, 0); assert.equal(f.toasts.length, 0);
  });
}

test("Rescan progress survives POST, list JSON and count waits, then allows a later click", async () => {
  const f = fixture(), button = f.els.findingsRescanButton, pending = f.click();
  assert.equal(button.disabled, true); assert.equal(button.classList.contains("is-working-shown"), false);
  f.fire(180); assert.equal(button.classList.contains("is-working-shown"), true);
  await f.acknowledge();
  const pair = f.requests.slice(-2), listBody = deferred();
  pair[1].resolve({ ok: true, json: () => listBody.promise }); await tick();
  await f.click(); assert.equal(f.requests.length, 3); assert.equal(button.disabled, true);
  listBody.resolve([finding("fresh")]); await tick();
  await f.click(); assert.equal(f.requests.length, 3); assert.equal(button.disabled, true);
  pair[0].resolve(response({ count: 1 })); await pending;
  assert.equal(button.disabled, false); assert.equal(button.classList.contains("is-working"), false);
  assert.equal(button.classList.contains("is-working-shown"), false); assert.equal(f.timers.size, 0);
  const next = f.click(); assert.equal(f.requests.length, 4);
  f.requests.at(-1).reject(new Error("Synthetic new request failed")); await next;
  assert.equal(f.toasts.length, 1); assert.equal(button.disabled, false);
});

for (const outcome of ["plain error", "empty error", "error-body rejection"]) {
  test(`current Rescan ${outcome} keeps feedback, view and loading ownership while decoding`, async () => {
    const f = fixture(); await f.loadDetail("initial");
    const before = f.snapshot(), pending = f.click(), body = deferred();
    f.requests.at(-1).resolve(errorResponse(() => body.promise)); await tick(); f.fire(180);
    assert.equal(f.els.findingsRescanButton.disabled, true); assert.equal(f.toasts.length, 0);
    if (outcome === "error-body rejection") body.reject(new Error("Synthetic body failure"));
    else body.resolve(outcome === "plain error" ? "Synthetic disabled scan" : "");
    await pending;
    assert.equal(f.snapshot(), before); assert.equal(f.errors.length, 1);
    assert.deepEqual(f.toasts, [[outcome === "plain error" ? "Synthetic disabled scan" : "Failed to rescan findings.", "error"]]);
    assert.equal(f.els.findingsRescanButton.disabled, false); assert.equal(f.timers.size, 0);
  });
}

for (const outcome of ["success", "rejection"]) {
  test(`accepted Rescan reset prevents older detail transaction ${outcome} from reopening cleared detail`, async () => {
    const f = fixture(), reading = f.select("initial");
    f.requests.at(-1).resolve(response(finding("initial"))); await tick();
    const oldTransaction = f.requests.at(-1), body = deferred();
    oldTransaction.resolve({ ok: true, json: () => body.promise }); await tick();
    const pending = f.click(); await f.acknowledge(); await f.finishList(); await pending;
    const before = f.snapshot();
    if (outcome === "success") body.resolve({ label: "obsolete" }); else body.reject(new Error("Synthetic stale detail failure"));
    await reading; assert.equal(f.snapshot(), before); assert.equal(f.c.selectedFindingId, null);
    assert.equal(f.errors.length, 0); assert.equal(f.toasts.length, 0);
  });
}

for (const stage of ["list JSON", "count JSON"]) {
  test(`session replacement during the post-Rescan ${stage} wait keeps newest data and detail`, async () => {
    const f = fixture(), pending = f.click(); await f.acknowledge();
    const pair = f.requests.slice(-2), body = deferred();
    if (stage === "list JSON") {
      pair[0].resolve(response({ count: 1 })); pair[1].resolve({ ok: true, json: () => body.promise });
    } else {
      pair[0].resolve({ ok: true, json: () => body.promise }); pair[1].resolve(response([finding("obsolete")]));
    }
    await tick(); await replace(f, "A→B→A"); const before = f.snapshot();
    body.resolve(stage === "list JSON" ? [finding("obsolete")] : { count: 99 }); await pending;
    assert.equal(f.snapshot(), before); assert.equal(f.errors.length, 0); assert.equal(f.toasts.length, 0);
    assert.equal(f.els.findingsRescanButton.disabled, false);
  });
}

for (const outcome of ["success", "rejection"]) {
  test(`session replacement cannot submit a newer Rescan until the older ${outcome} releases its own progress`, async () => {
    const f = fixture(), button = f.els.findingsRescanButton, old = f.click(), request = f.requests[0];
    f.fire(180); await replace(f, "A→B→A");
    const requestCount = f.requests.length, view = f.snapshot();
    await f.click(); assert.equal(f.requests.length, requestCount, "the production disabled guard rejects overlapping clicks");
    assert.equal(button.disabled, true); assert.equal(button.classList.contains("is-working-shown"), true);
    if (outcome === "success") request.resolve(response({})); else request.reject(new Error("Synthetic obsolete rescan failure"));
    await old;
    assert.equal(f.snapshot(), view); assert.equal(f.toasts.length, 0); assert.equal(button.disabled, false);
    const newer = f.click(), newerRequest = f.requests.at(-1);
    assert.equal(button.disabled, true); assert.equal(button.classList.contains("is-working"), true);
    assert.equal(button.classList.contains("is-working-shown"), false, "old reveal state is not retained on retry");
    assert.equal(f.timers.size, 1); f.fire(180);
    await tick(); assert.equal(button.disabled, true); assert.equal(button.classList.contains("is-working-shown"), true);
    newerRequest.reject(new Error("Synthetic newest failure")); await newer;
    assert.deepEqual(f.toasts, [["Synthetic newest failure", "error"]]); assert.equal(button.disabled, false);
    assert.equal(f.timers.size, 0); f.fire(180); assert.equal(button.classList.contains("is-working-shown"), false);
  });
}

test("an orphaned older count cannot finish a newer Rescan or replace its eventual feedback", async () => {
  const f = fixture(), button = f.els.findingsRescanButton, first = f.click();
  await f.acknowledge(); const oldCount = f.requests.at(-2), oldList = f.requests.at(-1);
  oldList.resolve({ ok: false }); await first;
  assert.equal(button.disabled, false);
  assert.deepEqual(f.toasts, [[refreshFailureMessage, "error"]]);
  const newer = f.click(), newerRequest = f.requests.at(-1); f.fire(180);
  const before = f.snapshot(); oldCount.resolve(response({ count: 99 })); await tick();
  assert.equal(f.snapshot(), before); assert.equal(button.disabled, true);
  assert.equal(button.classList.contains("is-working-shown"), true); assert.equal(f.toasts.length, 1);
  newerRequest.reject(new Error("Synthetic newest rescan failure")); await newer;
  assert.deepEqual(f.toasts, [[refreshFailureMessage, "error"], ["Synthetic newest rescan failure", "error"]]); assert.equal(button.disabled, false);
  assert.equal(f.timers.size, 0);
});

test("an already-obsolete Rescan response does not decode its error body", async () => {
  const f = fixture(), pending = f.click(), request = f.requests[0];
  await replace(f, "A→B→A"); let decoded = 0;
  request.resolve(errorResponse(async () => { decoded++; return "Synthetic obsolete error"; }));
  await pending;
  assert.equal(decoded, 0); assert.equal(f.errors.length, 0); assert.equal(f.toasts.length, 0);
});

test("same-owner structured Rescan error retains its server feedback and precise session write guard", async () => {
  const f = fixture(); f.state.activeSession = { id: "session a/b" };
  const before = f.snapshot(), pending = f.click(), request = f.requests[0];
  assert.equal(request.url, "/api/findings/rescan?session_id=session+a%2Fb&expected_active_session_id=session+a%2Fb");
  request.resolve({ ok: false, headers: { get: () => "application/json" },
    clone: () => ({ json: async () => ({ error: "Synthetic conflicting owner", owner_session_id: "session-b" }) }),
    text: async () => { assert.fail("structured errors must not consume the plain-text body"); },
  });
  await pending;
  assert.deepEqual(f.toasts, [["Synthetic conflicting owner (owner_session_id session-b)", "error"]]);
  assert.equal(f.snapshot(), before); assert.equal(f.els.findingsRescanButton.disabled, false);
});

const refreshFailureMessage = "Rescan completed, but findings could not be refreshed. Reopen the Findings tab to retry.";
async function failList(request, outcome) {
  if (outcome === "HTTP error") request.resolve({ ok: false });
  else if (outcome === "fetch rejection") request.reject(new Error("Synthetic findings refresh failure"));
  else request.resolve({ ok: true, json: async () => { throw new Error("Synthetic findings decode failure"); } });
  await tick();
}
for (const outcome of ["HTTP error", "fetch rejection", "JSON rejection"]) {
  test(`current Rescan refresh ${outcome} reports a read failure and releases the button without waiting for count`, async () => {
    const f = fixture(), pending = f.click(); await f.acknowledge();
    const pair = f.requests.slice(-2), joined = f.c.loadFindings();
    assert.equal(f.requests.length, 3, "coalesced refreshes share the same read pair");
    f.fire(180); await failList(pair[1], outcome); await pending;
    assert.equal(await joined, false, "callers can distinguish list failure from a real empty list");
    assert.deepEqual(f.toasts, [[refreshFailureMessage, "error"]]);
    assert.equal(f.els.findingsRescanButton.disabled, false); assert.equal(f.timers.size, 0);
    assert.deepEqual(Array.from(f.c.findingsData), []);
    const before = f.snapshot(); pair[0].resolve(response({ count: 99 })); await tick();
    assert.equal(f.snapshot(), before); assert.equal(f.toasts.length, 1);
    const retry = f.click(), retryRequest = f.requests.at(-1);
    await f.acknowledge(retryRequest); await f.finishList("retried"); await retry;
    assert.deepEqual(Array.from(f.c.findingsData, item => item.id), ["retried"]);
    assert.equal(f.toasts.length, 1, "successful retry does not add a failure notice");
    assert.equal(f.els.findingsRescanButton.disabled, false);
  });
}
for (const transition of ["session reset", "A→B→A", "Clear callback"]) {
  for (const outcome of ["HTTP error", "fetch rejection", "JSON rejection"]) {
    test(`obsolete Rescan refresh ${outcome} stays silent after ${transition}`, async () => {
      const f = fixture(), pending = f.click(); await f.acknowledge();
      const pair = f.requests.slice(-2); let body;
      if (outcome === "JSON rejection") {
        body = deferred(); pair[1].resolve({ ok: true, json: () => body.promise }); await tick();
      }
      await replace(f, transition); const before = f.snapshot();
      if (body) body.reject(new Error("Synthetic obsolete refresh decode failure"));
      else await failList(pair[1], outcome);
      await pending; pair[0].resolve(response({ count: 99 })); await tick();
      assert.equal(f.snapshot(), before); assert.equal(f.toasts.length, 0);
      assert.equal(f.errors.length, 0, "invalidated list failures must not leak feedback");
      assert.equal(f.els.findingsRescanButton.disabled, false); assert.equal(f.timers.size, 0);
    });
  }
}
for (const countResult of ["zero", "HTTP error", "fetch rejection", "JSON rejection"]) {
  test(`valid empty Rescan list remains successful with ${countResult} count`, async () => {
    const f = fixture(), pending = f.click(); await f.acknowledge();
    const pair = f.requests.slice(-2), joined = f.c.loadFindings();
    if (countResult === "zero") pair[0].resolve(response({ count: 0 }));
    else await failList(pair[0], countResult);
    pair[1].resolve(response([])); await pending;
    assert.notEqual(await joined, false); assert.equal(f.toasts.length, 0); assert.equal(f.errors.length, 0);
    assert.deepEqual(Array.from(f.c.findingsData), []); assert.equal(f.c.findingsBadgeCount, 0);
    assert.match(f.els.findingsBody.innerHTML, /No findings yet/); assert.equal(f.els.findingsRescanButton.disabled, false);
  });
}

test("a successful nonempty Rescan refresh uses list length when only its count read fails", async () => {
  const f = fixture(), pending = f.click(); await f.acknowledge();
  const pair = f.requests.slice(-2); pair[0].reject(new Error("Synthetic count failure"));
  pair[1].resolve(response([finding("fresh")])); await pending;
  assert.equal(f.c.findingsBadgeCount, 1); assert.equal(f.els.findingsBadge.textContent, "1");
  assert.deepEqual(Array.from(f.state._findingsEntries, item => item.id), ["fresh"]);
  assert.equal(f.toasts.length, 0); assert.equal(f.errors.length, 0);
});
