// Explicit Event log navigation/read errors, using synthetic buttons and reads.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const entry = id => ({ id, captured_at: "2026-01-01", level: "info", source: "fixture", title: id, message: "Saved event" });
function fixture() {
  const state = { activeTool: "dashboard", eventLog: [entry("saved-old")] };
  const requests = [], actions = [], toasts = [], panels = [], timers = new Map(), classes = new Set();
  let timerId = 0, listener;
  const button = { disabled: false, addEventListener(_type, callback) { listener = callback; },
    classList: { add: (...values) => values.forEach(value => classes.add(value)), remove: (...values) => values.forEach(value => classes.delete(value)) } };
  const els = { openEventLogButton: button, eventLogStatus: {}, eventLogTableBody: {} };
  const c = loadFunctions([
    "onClickWithProgress", "withButtonProgress", "setActiveTool", "loadEventLog", "jsonArray",
    "renderEventLog", "escapeHtml", "mergeEventLogEntries",
  ], {
    state, els, session: "saved-session", BUTTON_PROGRESS_DELAY_MS: 180, EVENT_LOG_LIMIT: 500,
    _eventLogLoadGeneration: 0, _eventLogMutationGeneration: 0, _eventLogClearGeneration: 0,
    sanitizeActiveTool: value => value, scheduleUiSettingsSave() {},
    renderToolPanels() { panels.push(state.activeTool); },
    fetch(path) { const request = { path, ...deferred() }; requests.push(request); return request.promise; },
    sessionQueryPath: (path, session) => `${session}:${path}`,
    requireOkResponse: async response => { if (!response.ok) throw new Error("Fixture HTTP failure"); },
    formatTimestamp: value => value, showToast(message, type) { toasts.push({ message, type }); },
    console: { error() {} }, setTimeout(callback) { const id = ++timerId; timers.set(id, callback); return id; }, clearTimeout(id) { timers.delete(id); },
  });
  c.currentSessionId = () => c.session;
  const withProgress = c.withButtonProgress;
  c.withButtonProgress = (control, work) => {
    const action = withProgress(control, work);
    actions.push(action);
    action.catch(() => {}); // Observe pre-fix rejection without losing its outcome.
    return action;
  };
  const start = appSource.indexOf('  onClickWithProgress(els.openEventLogButton,');
  const end = appSource.indexOf('  onClickWithProgress(els.dashboardReloadSessionsButton,', start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(appSource.slice(start, end), c);
  c.renderEventLog();
  const click = () => listener({ target: button });
  return { c, state, requests, actions, toasts, panels, timers, classes, button, click, els };
}

test("opening Event log displays its panel immediately while the read is pending", async () => {
  const f = fixture();
  f.click();
  const before = [...f.panels];
  f.requests[0].resolve({ ok: true, json: async () => [entry("saved-new")] });
  await Promise.allSettled(f.actions);
  assert.deepEqual(before, ["logger"]);
  assert.deepEqual(f.panels, ["logger"]);
  assert.equal(f.state.eventLog[0].id, "saved-new");
});

for (const failure of ["network", "HTTP", "body"]) {
  test(`explicit Event log ${failure} failure stays on its panel, reports, and allows retry`, async () => {
    const f = fixture();
    f.click();
    if (failure === "network") f.requests[0].reject(new Error("Fixture network failure"));
    if (failure === "HTTP") f.requests[0].resolve({ ok: false });
    if (failure === "body") f.requests[0].resolve({ ok: true, json: async () => { throw new Error("Fixture body failure"); } });
    assert.deepEqual((await Promise.allSettled(f.actions)).map(result => result.status), ["fulfilled"]);
    assert.equal(f.state.activeTool, "logger");
    assert.deepEqual(f.panels, ["logger"]);
    assert.equal(f.toasts.length, 1);
    assert.equal(f.toasts[0].type, "error");
    assert.match(f.toasts[0].message, /failure/i);
    assert.equal(f.state.eventLog[0].id, "saved-old");
    assert.equal(f.button.disabled, false);
    assert.equal(f.classes.size, 0);
    assert.equal(f.timers.size, 0);
    f.click();
    f.requests[1].resolve({ ok: true, json: async () => [entry("saved-retry")] });
    await Promise.all(f.actions);
    assert.equal(f.state.eventLog[0].id, "saved-retry");
    assert.equal(f.toasts.length, 1);
  });
}

test("navigation away while Event log loads is not repainted by its delayed completion", async () => {
  const f = fixture();
  f.click();
  f.c.setActiveTool("dashboard");
  f.c.renderToolPanels();
  f.requests[0].resolve({ ok: true, json: async () => [entry("saved-new")] });
  await Promise.all(f.actions);
  assert.equal(f.state.activeTool, "dashboard");
  assert.deepEqual(f.panels, ["logger", "dashboard"]);
});

test("superseded Event log errors remain silent through the button boundary", async () => {
  const f = fixture();
  f.click();
  const newer = f.c.loadEventLog();
  f.requests[1].resolve({ ok: true, json: async () => [entry("saved-new")] });
  await newer;
  f.requests[0].reject(new Error("Stale read failure"));
  await Promise.all(f.actions);
  assert.deepEqual(f.toasts, []);
  assert.equal(f.state.eventLog[0].id, "saved-new");
});
