// Extract only passive metadata handlers. No UI, server, scanner, or real data runs.
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
const rows = (count, label = "saved") => Array.from({ length: count }, (_, index) => ({ id: `${label}-${index}` }));
function fixture() {
  const requests = [], rendered = [], errors = [], timers = new Map(), badgeWrites = [];
  let nextTimer = 0;
  const hidden = new Set();
  const state = { activeSession: { id: "session-a" }, activeTool: "proxy", activeProxyTab: "http-history", settings: {} };
  const els = { findingsBadge: { textContent: "", title: "", classList: {
    toggle(name, enabled) { if (enabled) hidden.add(name); else hidden.delete(name); },
  } }, findingsClearButton: {} };
  const names = ["currentSessionId", "sessionQueryPath", "jsonArray", "loadFindings", "updateFindingsBadgeOnly",
    "fetchFindingsCount", "updateFindingsBadge", "formatCappedCount", "retainedEntriesCap", "handleFindingEvent",
    "scheduleFindingsBadgeRefresh", "scheduleFindingsListRefresh", "resetFindingsUiState"];
  // Also run the production commit helper once it exists; the pre-fix run tests the old handlers.
  if (/^function commitFindingsBadgeCount\(/m.test(appSource)) names.push("commitFindingsBadgeCount");
  const context = loadFunctions(names, { refreshHistoryFindings() {},
    state, els, console: { error: (...args) => errors.push(args) },
    clearFindingDetail() {},
    renderFindings() { rendered.push(Array.from(read("findingsData"), item => item.id)); },
    window: {
      setTimeout(callback, delay) { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
      clearTimeout(id) { timers.delete(id); },
    },
    fetch(url, options) {
      assert.equal(options, undefined, "metadata fetches are read-only");
      const request = { url, ...deferred() }; requests.push(request); return request.promise;
    },
  });
  const start = appSource.indexOf("let findingsData = [];");
  const end = appSource.indexOf("let scannerConfigCache = null;", start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(appSource.slice(start, end), context);
  vm.runInContext(appSource.match(/^const FINDINGS_LIST_LIMIT = \d+;$/m)[0], context);
  const read = name => vm.runInContext(name, context);
  const update = context.updateFindingsBadge;
  context.updateFindingsBadge = () => { update(); badgeWrites.push(read("findingsBadgeCount")); };
  function setBadge(value) { vm.runInContext(`findingsBadgeCount = ${Number(value)}; updateFindingsBadge();`, context); }
  function standalone() {
    const promise = context.updateFindingsBadgeOnly();
    return { promise, count: requests.at(-1) };
  }
  function list() {
    const before = requests.length, promise = context.loadFindings(), added = requests.slice(before);
    if (!added.length) return { promise, coalesced: true };
    assert.equal(added.length, 2, "one new list read starts one list/count pair");
    assert.match(added[0].url, /\/api\/findings\/count\?session_id=session-/);
    assert.match(added[1].url, /\/api\/findings\?limit=5000&session_id=session-/);
    return { promise, count: added[0], list: added[1] };
  }
  function event(id = "synthetic-event") { context.handleFindingEvent({ data: JSON.stringify({ id }) }); }
  async function runTimers() {
    for (const [id, timer] of [...timers]) { timers.delete(id); timer.callback(); }
    await tick();
  }
  function snapshot() {
    return { count: read("findingsBadgeCount"), text: els.findingsBadge.textContent,
      title: els.findingsBadge.title, hidden: hidden.has("hidden") };
  }
  function bindMockAcknowledgedClear() {
    // Exercise the real clear acknowledgement callback using an in-memory response only.
    const start = appSource.indexOf("  if (els.findingsClearButton) {", appSource.indexOf("function bindFindingsEvents()"));
    const end = appSource.indexOf("\n  // Filters", start);
    assert.ok(start >= 0 && end > start);
    const reads = context.fetch;
    context.fetch = (url, options) => {
      if (!options) return reads(url);
      assert.equal(url, "/api/findings/clear"); assert.deepEqual({ ...options }, { method: "POST" });
      return Promise.resolve(response({}));
    };
    context.sessionWritePath = path => path;
    context.requireOkResponse = async result => assert.equal(result.ok, true);
    context.onClickWithProgress = (button, callback) => { button.click = callback; };
    context.showToast = () => assert.fail("The mocked acknowledgement must succeed");
    vm.runInContext(appSource.slice(start, end), context);
    return els.findingsClearButton.click;
  }
  return { context, state, els, requests, rendered, errors, timers, badgeWrites, read, setBadge,
    standalone, list, event, runTimers, snapshot, bindMockAcknowledgedClear };
}
async function complete(read, count, listRows = rows(1)) {
  read.count.resolve(response({ count }));
  if (read.list) read.list.resolve(response(listRows));
  await read.promise;
}
async function fail(request, kind) {
  if (kind === "network") request.reject(new Error("Synthetic unavailable metadata"));
  if (kind === "HTTP") request.resolve({ ok: false, json() { assert.fail("Non-OK JSON is not decoded"); } });
  if (kind === "JSON") request.resolve({ ok: true, json: async () => { throw new Error("Synthetic invalid metadata"); } });
  await tick();
}

for (const [olderCount, newerCount] of [[2, 3], [4, 2]]) {
  test(`older standalone ${olderCount} cannot overwrite newer accepted ${newerCount}`, async () => {
    const f = fixture(), older = f.standalone(), newer = f.standalone();
    await complete(newer, newerCount); const before = f.snapshot();
    await complete(older, olderCount);
    assert.deepEqual(f.snapshot(), before); assert.deepEqual(f.badgeWrites, [newerCount]);
  });
}
for (const failure of ["network", "HTTP", "JSON"]) {
  test(`newer standalone ${failure} failure does not supersede an older valid count`, async () => {
    const f = fixture(); f.setBadge(9);
    const older = f.standalone(), newer = f.standalone();
    await fail(newer.count, failure); await newer.promise;
    assert.equal(f.snapshot().count, 9);
    await complete(older, 2); assert.equal(f.snapshot().count, 2);
    assert.equal(f.errors.length, 0);
  });
}
test("an older success may display while a newer read is pending, then the newer lower count wins", async () => {
  const f = fixture(), older = f.standalone(), newer = f.standalone();
  await complete(older, 4); assert.equal(f.snapshot().count, 4);
  await complete(newer, 2); assert.equal(f.snapshot().count, 2);
  assert.deepEqual(f.badgeWrites, [4, 2]);
});
for (const order of ["list first", "standalone first"]) {
  for (const [olderCount, newerCount] of [[2, 3], [4, 2]]) {
    test(`${order}: shared count ownership preserves newer ${newerCount} over older ${olderCount}`, async () => {
      const f = fixture(), older = order === "list first" ? f.list() : f.standalone();
      const newer = order === "list first" ? f.standalone() : f.list();
      await complete(newer, newerCount); const before = f.snapshot();
      await complete(older, olderCount);
      assert.deepEqual(f.snapshot(), before);
      assert.equal(f.rendered.length, 1, "valid list rows render independently of badge ownership");
      assert.deepEqual(f.rendered[0], ["saved-0"]);
    });
  }
}
for (const order of ["list first", "standalone first"]) {
  for (const failure of ["network", "HTTP", "JSON"]) {
    test(`${order}: list-length fallback after ${failure} has shared count ownership`, async () => {
      const f = fixture(), older = order === "list first" ? f.list() : f.standalone();
      const newer = order === "list first" ? f.standalone() : f.list();
      const list = older.list ? older : newer;
      await fail(list.count, failure);
      if (newer.list) { newer.list.resolve(response(rows(2))); await newer.promise; }
      else await complete(newer, 3);
      const before = f.snapshot();
      if (older.list) { older.list.resolve(response(rows(4))); await older.promise; }
      else await complete(older, 4);
      assert.deepEqual(f.snapshot(), before);
      assert.equal(f.snapshot().count, newer.list ? 2 : 3);
      assert.equal(f.rendered.length, 1);
    });
  }
}
for (const failure of ["network", "HTTP", "JSON"]) {
  test(`newer list ${failure} failure cannot claim its successful sibling count`, async () => {
    const f = fixture(); f.setBadge(9);
    const older = f.standalone(), newer = f.list();
    newer.count.resolve(response({ count: 8 })); await fail(newer.list, failure); await newer.promise;
    assert.equal(f.snapshot().count, 9); assert.equal(f.rendered.length, 0);
    await complete(older, 2); assert.equal(f.snapshot().count, 2);
    assert.equal(f.read("findingsLoadPromise"), null);
  });
}
for (const kind of ["standalone", "list"]) {
  for (const stage of ["count headers", "count JSON", ...(kind === "list" ? ["list headers", "list JSON"] : [])]) {
    test(`accepted event invalidates earlier ${kind} read pending at ${stage}`, async () => {
      const f = fixture(); f.setBadge(2);
      const reading = kind === "list" ? f.list() : f.standalone();
      let pending;
      if (stage === "count JSON") {
        pending = deferred(); reading.count.resolve({ ok: true, json: () => pending.promise });
        if (reading.list) reading.list.resolve(response(rows(1)));
      } else if (stage === "list JSON") {
        pending = deferred(); reading.count.resolve(response({ count: 1 }));
        reading.list.resolve({ ok: true, json: () => pending.promise });
      } else if (stage === "list headers") reading.count.resolve(response({ count: 1 }));
      else if (reading.list) reading.list.resolve(response(rows(1)));
      await tick(); f.event(); const before = f.snapshot(); assert.equal(before.count, 3);
      if (pending) pending.resolve(stage === "list JSON" ? rows(1) : { count: 1 });
      else if (stage === "list headers") reading.list.resolve(response(rows(1)));
      else reading.count.resolve(response({ count: 1 }));
      await reading.promise;
      assert.deepEqual(f.snapshot(), before);
      if (reading.list) assert.deepEqual(f.rendered, [["saved-0"]]);
      assert.equal(f.requests.length, kind === "list" ? 2 : 1);
      assert.equal(f.timers.size, 1, "no extra recovery timer is scheduled by a stale read");
    });
  }
}
test("the actual event timer coalesces an in-flight list without granting its old count new ownership", async () => {
  const f = fixture(); f.state.activeProxyTab = "findings"; f.setBadge(2);
  const older = f.list(); f.event(); f.event("another-event");
  assert.equal(f.snapshot().count, 4); assert.equal(f.timers.size, 1);
  assert.equal([...f.timers.values()][0].delay, 250);
  await f.runTimers(); assert.equal(f.requests.length, 2, "coalescing starts no extra count/list pair");
  await complete(older, 2); await tick();
  assert.equal(f.snapshot().count, 4); assert.deepEqual(f.rendered, [["saved-0"]]);
  assert.equal(f.timers.size, 0, "coalesced work does not schedule a follow-on refresh");
  const later = f.list(); assert.equal(f.requests.length, 4);
  await complete(later, 3); assert.equal(f.snapshot().count, 3);
});
test("coalesced list requests do not supersede a standalone accepted while the list is pending", async () => {
  const f = fixture(), older = f.list(), newer = f.standalone();
  assert.equal(f.list().coalesced, true); assert.equal(f.requests.length, 3);
  await complete(newer, 3); await complete(older, 4);
  assert.equal(f.snapshot().count, 3); assert.deepEqual(f.rendered, [["saved-0"]]);
});
test("the non-Findings event timer starts an authoritative post-event count which may decrease", async () => {
  const f = fixture(); f.setBadge(4); const older = f.standalone(); f.event();
  assert.equal([...f.timers.values()][0].delay, 1000);
  await f.runTimers(); assert.equal(f.requests.length, 2);
  f.requests[1].resolve(response({ count: 2 })); await tick();
  assert.equal(f.snapshot().count, 2); await complete(older, 9); assert.equal(f.snapshot().count, 2);
});
for (const invalid of ['{"id":null}', '{}', 'null', 'invalid-json']) {
  test(`invalid event ${invalid} preserves a pending count's ownership`, async () => {
    const f = fixture(), reading = f.standalone();
    f.context.handleFindingEvent({ data: invalid }); await complete(reading, 2);
    assert.equal(f.snapshot().count, 2);
  });
}
for (const kind of ["standalone", "list"]) {
  for (const transition of ["reset", "away and back", "acknowledged clear"]) {
    test(`${transition} invalidates old ${kind} reads and allows later authoritative zero`, async () => {
      const f = fixture(); f.setBadge(9);
      const reading = kind === "list" ? f.list() : f.standalone();
      const body = deferred(); reading.count.resolve({ ok: true, json: () => body.promise });
      if (reading.list) reading.list.resolve(response(rows(2)));
      await tick();
      if (transition === "acknowledged clear") await f.bindMockAcknowledgedClear()();
      else if (transition === "away and back") {
        f.state.activeSession = { id: "session-b" }; f.context.resetFindingsUiState();
        f.state.activeSession = { id: "session-a" }; f.context.resetFindingsUiState();
      } else f.context.resetFindingsUiState();
      assert.equal(f.snapshot().count, 0); assert.equal(f.snapshot().hidden, true);
      const before = f.snapshot(), renderCount = f.rendered.length;
      body.resolve({ count: 9 }); await reading.promise;
      assert.deepEqual(f.snapshot(), before); assert.equal(f.rendered.length, renderCount);
      f.event(); assert.equal(f.snapshot().count, 1);
      const later = f.standalone(); await complete(later, 0);
      assert.equal(f.snapshot().count, 0); assert.equal(f.snapshot().hidden, true);
    });
  }
}
for (const kind of ["standalone", "list"]) {
  test(`a session change without reset rejects old ${kind} results`, async () => {
    const f = fixture(); f.setBadge(3); const reading = kind === "list" ? f.list() : f.standalone();
    f.state.activeSession = { id: "session-b" }; await complete(reading, 9);
    assert.equal(f.snapshot().count, 3); assert.equal(f.rendered.length, 0);
  });
}
for (const count of ["3", 0, -1, "invalid", null, undefined]) {
  test(`count decoding remains compatible for ${String(count)}`, async () => {
    const f = fixture(); f.setBadge(9); const reading = f.standalone(); await complete(reading, count);
    assert.equal(f.snapshot().count, count === "3" ? 3 : 0);
  });
}
test("list badge keeps the larger of its decoded count and list length, with no previous-badge maximum", async () => {
  const f = fixture(); f.setBadge(9);
  await complete(f.list(), 1, rows(3)); assert.equal(f.snapshot().count, 3);
  await complete(f.list(), 4, rows(2)); assert.equal(f.snapshot().count, 4);
  await complete(f.list(), 0, []); assert.equal(f.snapshot().count, 0);
});
test("count remains session-global and capped display remains unchanged", async () => {
  const f = fixture(); f.state.settings.max_entries = 3;
  f.els.findingsFilterSearch = { value: "hidden locally" }; f.els.findingsFilterSeverity = { value: "info" };
  await complete(f.list(), 3, rows(1));
  assert.equal(f.snapshot().text, "3+"); assert.match(f.snapshot().title, /^3 findings retained/);
  assert.equal(f.requests.length, 2);
  for (const request of f.requests) assert.doesNotMatch(request.url, /severity|category|search|scope/);
});
