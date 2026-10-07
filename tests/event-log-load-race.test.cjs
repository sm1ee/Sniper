// Passive event-log reads use synthetic responses only; the app never starts.
const assert = require("node:assert/strict");
const test = require("node:test");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const entry = id => ({ id, captured_at: "2026-01-01", level: "info", source: "fixture", title: id, message: "Saved event" });
const response = entries => ({ ok: true, json: async () => entries });
const nextTurn = () => new Promise(resolve => setImmediate(resolve));
function fixture() {
  const state = { eventLog: [entry("fixture-saved")] };
  const requests = [], rendered = [], timers = new Map();
  let nextTimer = 0;
  const els = { eventLogStatus: {}, eventLogTableBody: {} };
  const context = loadFunctions([
    "loadEventLog", "resetEventLogUiState", "applyEventLogEntry", "clearEventLog", "mergeEventLogEntries",
    "jsonArray", "requireOkResponse", "renderEventLog", "escapeHtml", "withButtonProgress",
  ], {
    state, els, session: "fixture-session-a", EVENT_LOG_LIMIT: 500,
    _eventLogLoadGeneration: 0, _eventLogMutationGeneration: 0, _eventLogClearGeneration: 0,
    BUTTON_PROGRESS_DELAY_MS: 180,
    fetch(path, options) { const request = { path, options, ...deferred() }; requests.push(request); return request.promise; },
    sessionQueryPath: (path, session) => `${session}:${path}`,
    sessionWritePath: (path, session) => `${session}:${path}`,
    readApiErrorMessage: async () => "Event log unavailable",
    formatTimestamp: value => value,
    setTimeout(callback) { const id = ++nextTimer; timers.set(id, callback); return id; },
    clearTimeout(id) { timers.delete(id); },
  });
  context.currentSessionId = () => context.session;
  const render = context.renderEventLog;
  context.renderEventLog = () => { render(); rendered.push(state.eventLog.map(item => item.id)); };
  context.renderEventLog();
  const resolve = (index, entries) => requests[index].resolve(response(entries));
  return { context, state, requests, rendered, els, timers, resolve };
}
const ids = f => Array.from(f.state.eventLog, item => item.id);

test("an older event-log read cannot replace a newer displayed snapshot", async () => {
  const f = fixture();
  const older = f.context.loadEventLog();
  const newer = f.context.loadEventLog();
  f.resolve(1, [entry("fixture-new"), entry("fixture-old")]);
  await newer;
  f.resolve(0, [entry("fixture-old")]);
  await older;
  assert.deepEqual(ids(f), ["fixture-new", "fixture-old"]);
  assert.equal(f.els.eventLogStatus.textContent, "2 entries");
  assert.equal(f.rendered.length, 2);
});

test("an older event-log read does not render while its replacement is pending", async () => {
  const f = fixture();
  const older = f.context.loadEventLog();
  const newer = f.context.loadEventLog();
  f.resolve(0, [entry("fixture-old")]);
  await older;
  assert.deepEqual(ids(f), ["fixture-saved"]);
  f.resolve(1, [entry("fixture-new")]);
  await newer;
  assert.deepEqual(ids(f), ["fixture-new"]);
});

test("event-log parsing completed after a newer read stays stale", async () => {
  const f = fixture(), body = deferred();
  const older = f.context.loadEventLog();
  f.requests[0].resolve({ ok: true, json: () => body.promise });
  await nextTurn();
  const newer = f.context.loadEventLog();
  f.resolve(1, [entry("fixture-new")]);
  await newer;
  body.resolve([entry("fixture-old")]);
  await older;
  assert.deepEqual(ids(f), ["fixture-new"]);
  assert.equal(f.rendered.length, 2);
});

for (const duringParsing of [false, true]) {
  test(`switching sessions rejects old event-log data ${duringParsing ? "during parsing" : "before the response"}`, async () => {
    const f = fixture(), body = deferred();
    const loading = f.context.loadEventLog();
    if (duringParsing) {
      f.requests[0].resolve({ ok: true, json: () => body.promise });
      await nextTurn();
    }
    f.context.session = "fixture-session-b";
    if (duringParsing) body.resolve([entry("fixture-old-session")]);
    else f.resolve(0, [entry("fixture-old-session")]);
    await loading;
    assert.deepEqual(ids(f), ["fixture-saved"]);
    assert.equal(f.rendered.length, 1);
    assert.match(f.requests[0].path, /^fixture-session-a:/);
  });
}

test("resetting and returning to the same session invalidates an earlier event-log read", async () => {
  const f = fixture();
  const loading = f.context.loadEventLog();
  f.context.session = "fixture-session-b";
  f.context.resetEventLogUiState();
  f.context.session = "fixture-session-a";
  f.context.resetEventLogUiState();
  f.resolve(0, [entry("fixture-old-session")]);
  await loading;
  assert.deepEqual(ids(f), []);
  assert.equal(f.rendered.length, 1);
  const sessionReset = appSource.match(/^function resetSessionScopedUiState\(\) \{[^]*?^\}/m)[0];
  assert.match(sessionReset, /\bresetEventLogUiState\(\);/, "session transitions must invalidate event-log reads");
});

for (const failure of ["network", "HTTP", "JSON"]) {
  test(`current event-log ${failure} failure retains saved data, rejects, and can retry`, async () => {
    const f = fixture();
    const loading = f.context.loadEventLog();
    const rejected = assert.rejects(loading, /unavailable/i);
    if (failure === "network") f.requests[0].reject(new Error("Network unavailable"));
    if (failure === "HTTP") f.requests[0].resolve({ ok: false });
    if (failure === "JSON") f.requests[0].resolve({ ok: true, json: async () => { throw new Error("JSON unavailable"); } });
    await rejected;
    assert.deepEqual(ids(f), ["fixture-saved"]);
    assert.equal(f.rendered.length, 1);
    assert.equal(f.els.eventLogStatus.textContent, "1 entry");
    const retry = f.context.loadEventLog();
    f.resolve(1, [entry("fixture-retry")]);
    await retry;
    assert.deepEqual(ids(f), ["fixture-retry"]);
  });
}

for (const failure of ["network", "HTTP", "JSON"]) {
  for (const supersededBy of ["newer read", "session switch", "acknowledged clear"]) {
    test(`stale event-log ${failure} failure is ignored after ${supersededBy}`, async () => {
      const f = fixture(), delayed = deferred();
      const older = f.context.loadEventLog();
      if (failure === "HTTP") {
        f.context.readApiErrorMessage = () => delayed.promise;
        f.requests[0].resolve({ ok: false });
      }
      if (failure === "JSON") f.requests[0].resolve({ ok: true, json: () => delayed.promise });
      if (failure !== "network") await nextTurn();
      if (supersededBy === "newer read") {
        const newer = f.context.loadEventLog();
        f.resolve(1, [entry("fixture-new")]);
        await newer;
      } else if (supersededBy === "session switch") {
        f.context.session = "fixture-session-b";
      } else {
        const clearing = f.context.clearEventLog();
        f.requests[1].resolve({ ok: true });
        await clearing;
      }
      const before = ids(f), renderedCount = f.rendered.length, status = f.els.eventLogStatus.textContent;
      if (failure === "network") f.requests[0].reject(new Error("Old network failure"));
      if (failure === "HTTP") delayed.resolve("Old HTTP failure");
      if (failure === "JSON") delayed.reject(new Error("Old JSON failure"));
      await assert.doesNotReject(older);
      assert.deepEqual(ids(f), before);
      assert.equal(f.rendered.length, renderedCount);
      assert.equal(f.els.eventLogStatus.textContent, status);
    });
  }
}

test("an old success after the latest read fails cannot silently replace retained data", async () => {
  const f = fixture();
  const older = f.context.loadEventLog();
  const newer = f.context.loadEventLog();
  const rejected = assert.rejects(newer, /latest failure/);
  f.requests[1].reject(new Error("latest failure"));
  await rejected;
  f.resolve(0, [entry("fixture-old")]);
  await older;
  assert.deepEqual(ids(f), ["fixture-saved"]);
  assert.equal(f.rendered.length, 1);
});

test("an acknowledged clear cannot be undone by a pending read", async () => {
  const f = fixture(), body = deferred();
  const loading = f.context.loadEventLog();
  f.requests[0].resolve({ ok: true, json: () => body.promise });
  await nextTurn();
  const clearing = f.context.clearEventLog();
  f.requests[1].resolve({ ok: true });
  await clearing;
  body.resolve([entry("fixture-old")]);
  await loading;
  assert.deepEqual(ids(f), []);
  assert.equal(f.els.eventLogStatus.textContent, "0 entries");
  assert.equal(f.rendered.length, 2);
});

test("live entries received during the current read keep precedence and remain deduplicated", async () => {
  const f = fixture();
  const loading = f.context.loadEventLog();
  f.context.applyEventLogEntry({ ...entry("fixture-live"), message: "Latest display text" });
  f.resolve(0, [entry("fixture-live"), entry("fixture-saved"), entry("fixture-older")]);
  await loading;
  assert.deepEqual(ids(f), ["fixture-live", "fixture-saved", "fixture-older"]);
  assert.equal(f.state.eventLog[0].message, "Latest display text");
  assert.equal(f.els.eventLogStatus.textContent, "3 entries");
});

test("an empty current snapshot and the retained-entry limit still apply", async () => {
  const f = fixture();
  f.context.EVENT_LOG_LIMIT = 2;
  const loading = f.context.loadEventLog();
  f.resolve(0, [entry("fixture-1"), entry("fixture-2"), entry("fixture-3")]);
  await loading;
  assert.deepEqual(ids(f), ["fixture-1", "fixture-2"]);
  const empty = f.context.loadEventLog();
  f.resolve(1, []);
  await empty;
  assert.deepEqual(ids(f), []);
  assert.equal(f.els.eventLogStatus.textContent, "0 entries");
});

function button() {
  const classes = new Set();
  return {
    disabled: false, classes,
    classList: { add: (...names) => names.forEach(name => classes.add(name)), remove: (...names) => names.forEach(name => classes.delete(name)) },
  };
}

test("a stale read cannot end the newer button load's progress or overwrite its status", async () => {
  const f = fixture(), control = button();
  const older = f.context.loadEventLog();
  const newer = f.context.withButtonProgress(control, () => f.context.loadEventLog());
  for (const callback of f.timers.values()) callback();
  f.resolve(0, [entry("fixture-old")]);
  await older;
  assert.equal(control.disabled, true);
  assert.equal(control.classes.has("is-working-shown"), true);
  assert.equal(f.els.eventLogStatus.textContent, "1 entry");
  f.resolve(1, [entry("fixture-new"), entry("fixture-new-2")]);
  await newer;
  assert.equal(control.disabled, false);
  assert.equal(control.classes.size, 0);
  assert.equal(f.timers.size, 0);
  assert.equal(f.els.eventLogStatus.textContent, "2 entries");
});

test("a current failed button load clears its progress without clearing saved events", async () => {
  const f = fixture(), control = button();
  const loading = f.context.withButtonProgress(control, () => f.context.loadEventLog());
  const rejected = assert.rejects(loading, /unavailable/);
  f.requests[0].reject(new Error("unavailable"));
  await rejected;
  assert.equal(control.disabled, false);
  assert.equal(control.classes.size, 0);
  assert.equal(f.timers.size, 0);
  assert.deepEqual(ids(f), ["fixture-saved"]);
});
