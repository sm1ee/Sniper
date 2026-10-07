// Offline saved-session UI checks. All responses are synthetic; no API runs.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const session = (id, active = false) => ({ id, name: `Session ${id}`, active });
const response = body => ({ ok: true, json: async () => body });
function fixture() {
  const active = session("fixture-active", true);
  const state = { sessions: [active, session("fixture-stored")], activeSession: active };
  const errors = [], rendered = [];
  const context = loadFunctions(["loadSessions", "jsonArray"], {
    state, currentSessionId: () => state.activeSession?.id,
    sessionsLoadGeneration: 0, sessionsAppliedLoadGeneration: 0,
    fetch: async () => response([]),
    requireOkResponse: async res => { if (!res.ok) throw new Error("Failed to load sessions."); },
    renderDashboard: () => rendered.push([...state.sessions]),
    handleWorkspaceActionError: error => errors.push(error),
    console: { error() {} },
  });
  return { state, errors, rendered, context };
}

for (const payload of [null, {}, { error: "unavailable" }, "bad response", [null], [{}], [{ id: "bad", name: "Bad" }]]) {
  test(`malformed session list ${JSON.stringify(payload)} preserves saved sessions`, async () => {
    const f = fixture();
    const previous = f.state.sessions, active = f.state.activeSession;
    f.context.fetch = async () => response(payload);
    await assert.rejects(f.context.loadSessions());
    assert.equal(f.state.sessions, previous);
    assert.equal(f.state.activeSession, active);
    assert.equal(f.rendered.length, 0);
  });
}

for (const failure of ["HTTP", "network", "JSON"]) {
  test(`dashboard Reload reports ${failure} failure and can retry`, async () => {
    const f = fixture();
    const previous = f.state.sessions;
    f.context.fetch = async () => {
      if (failure === "network") throw new Error("Connection lost");
      return failure === "HTTP" ? { ok: false } : { ok: true, json: async () => { throw new Error("Bad JSON"); } };
    };
    f.context.els = { dashboardReloadSessionsButton: {} };
    f.context.onClickWithProgress = (_, handler) => { f.context.reload = handler; };
    const start = appSource.indexOf("  onClickWithProgress(els.dashboardReloadSessionsButton,");
    const end = appSource.indexOf("  onClickWithProgress(els.dashboardCreateSessionButton,", start);
    assert.ok(start !== -1 && end > start);
    vm.runInContext(appSource.slice(start, end), f.context);
    await f.context.reload();
    assert.equal(f.state.sessions, previous);
    assert.equal(f.errors.length, 1, "failure must reach the visible error handler");
    const latest = [session("fixture-active", true), session("fixture-new")];
    f.context.fetch = async () => response(latest);
    await f.context.reload();
    assert.equal(f.state.sessions, latest);
    assert.equal(f.errors.length, 1);
  });
}

test("a genuinely empty session list remains valid", async () => {
  const f = fixture();
  await f.context.loadSessions();
  assert.equal(f.state.sessions.length, 0);
  assert.equal(f.state.activeSession, null);
});

function dashboardFixture(sessions, selectedSessionId) {
  const state = { sessions, activeSession: sessions.find(s => s.active) || null, selectedSessionId };
  const els = new Proxy({}, { get: (obj, key) => obj[key] ||= { querySelectorAll: () => [] } });
  const context = loadFunctions(["renderDashboard"], {
    state, els, document: { getElementById: () => null }, getSortedSessions: () => sessions,
    formatCappedCount: value => String(value ?? 0), retainedTransactionsCap() {}, retainedEntriesCap() {},
    formatTimestamp: () => "-", escapeHtml: value => String(value),
  });
  return { state, els, context };
}

test("refreshing away a selected saved session selects the displayed active session", () => {
  const f = dashboardFixture([session("fixture-active", true)], "fixture-removed");
  f.context.renderDashboard();
  assert.equal(f.state.selectedSessionId, "fixture-active", "Open storage must target the session that is displayed");
  assert.equal(f.els.dashboardCurrentSessionName.textContent, "Session fixture-active");
});

test("refresh preserves a selected saved session that still exists", () => {
  const f = dashboardFixture([session("fixture-active", true), session("fixture-stored")], "fixture-stored");
  f.context.renderDashboard();
  assert.equal(f.state.selectedSessionId, "fixture-stored");
  assert.equal(f.els.dashboardCurrentSessionName.textContent, "Session fixture-stored");
});

test("an empty refreshed list clears an obsolete selection", () => {
  const f = dashboardFixture([], "fixture-removed");
  f.context.renderDashboard();
  assert.equal(f.state.selectedSessionId, null);
});

test("a refreshed dashboard never restores a removed selection from a stale workspace session", () => {
  const f = dashboardFixture([session("fixture-new-active", true)], "fixture-removed");
  // External session reload keeps the old workspace until pending drafts save.
  f.state.activeSession = session("fixture-old-active", true);
  f.context.renderDashboard();
  assert.equal(f.state.selectedSessionId, "fixture-new-active");
  assert.equal(f.els.dashboardCurrentSessionName.textContent, "Session fixture-new-active");
  assert.equal(f.state.activeSession.id, "fixture-old-active", "render must not change workspace write ownership");
});

test("a refreshed dashboard does not label the previous workspace session as still active", () => {
  const f = dashboardFixture([session("fixture-new-active", true), session("fixture-old-active")], "fixture-old-active");
  f.state.activeSession = session("fixture-old-active", true);
  f.context.renderDashboard();
  assert.equal(f.state.selectedSessionId, "fixture-old-active");
  assert.equal(f.els.dashboardCurrentSessionStatus.textContent, "Stored");
});

// Promise ordering is controlled here; these never call a real API or session action.
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const nextTurn = () => new Promise(resolve => setImmediate(resolve));
function raceFixture() {
  const f = fixture();
  f.requests = [];
  f.context.fetch = (path, options) => {
    assert.equal(path, "/api/sessions");
    assert.equal(options, undefined, "list refresh must remain a read");
    const request = deferred();
    f.requests.push(request);
    return request.promise;
  };
  return f;
}

for (const duringParsing of [false, true]) {
  test(`older session list cannot replace newer rows ${duringParsing ? "after delayed JSON" : "after delayed headers"}`, async () => {
    const f = raceFixture(), body = deferred();
    const older = f.context.loadSessions();
    if (duringParsing) {
      f.requests[0].resolve({ ok: true, json: () => body.promise });
      await nextTurn();
    }
    const newer = f.context.loadSessions();
    const latest = [session("fixture-active", true), session("fixture-latest")];
    f.requests[1].resolve(response(latest));
    await newer;
    if (duringParsing) body.resolve([session("fixture-active", true), session("fixture-obsolete")]);
    else f.requests[0].resolve(response([session("fixture-active", true), session("fixture-obsolete")]));
    await older;
    assert.equal(f.state.sessions, latest);
    assert.equal(f.state.activeSession, latest[0]);
    assert.equal(f.rendered.length, 1);
  });
}

for (const failure of ["network", "HTTP", "JSON", "shape"]) {
  test(`superseded session-list ${failure} failure cannot report an obsolete error`, async () => {
    const f = raceFixture(), body = deferred();
    const older = f.context.loadSessions();
    if (failure === "JSON") {
      f.requests[0].resolve({ ok: true, json: () => body.promise });
      await nextTurn();
    }
    const newer = f.context.loadSessions();
    const latest = [session("fixture-active", true), session("fixture-latest")];
    f.requests[1].resolve(response(latest));
    await newer;
    if (failure === "network") f.requests[0].reject(new Error("Old network failure"));
    if (failure === "HTTP") f.requests[0].resolve({ ok: false });
    if (failure === "JSON") body.reject(new Error("Old JSON failure"));
    if (failure === "shape") f.requests[0].resolve(response({ obsolete: true }));
    await assert.doesNotReject(older);
    assert.equal(f.state.sessions, latest);
    assert.equal(f.rendered.length, 1);
  });
}

test("a session-list read still supplies its awaited result while a newer read is pending", async () => {
  const f = raceFixture();
  const older = f.context.loadSessions(), newer = f.context.loadSessions();
  const first = [session("fixture-active", true), session("fixture-first")];
  f.requests[0].resolve(response(first));
  await older;
  assert.equal(f.state.sessions, first);
  const latest = [session("fixture-active", true), session("fixture-latest")];
  f.requests[1].resolve(response(latest));
  await newer;
  assert.equal(f.state.sessions, latest);
  assert.equal(f.rendered.length, 2);
});

test("a failed newer session-list read does not discard a successful older read", async () => {
  const f = raceFixture();
  const older = f.context.loadSessions(), newer = f.context.loadSessions();
  const rejected = assert.rejects(newer, /Newest read unavailable/);
  f.requests[1].reject(new Error("Newest read unavailable"));
  await rejected;
  const first = [session("fixture-active", true), session("fixture-first")];
  f.requests[0].resolve(response(first));
  await older;
  assert.equal(f.state.sessions, first);
  assert.equal(f.rendered.length, 1);
});

test("an obsolete list cannot resurrect rows after a newer empty list", async () => {
  const f = raceFixture();
  const older = f.context.loadSessions(), newer = f.context.loadSessions();
  f.requests[1].resolve(response([]));
  await newer;
  f.requests[0].resolve(response([session("fixture-active", true)]));
  await older;
  assert.equal(f.state.sessions.length, 0);
  assert.equal(f.state.activeSession, null);
  assert.equal(f.rendered.length, 1);
});

test("a superseded read cannot announce a stale active-session change", async () => {
  const f = raceFixture(), changes = [];
  f.context.handleExternalSessionChanged = async id => changes.push(id);
  const older = f.context.loadSessions({ reloadOnActiveChange: true });
  const newer = f.context.loadSessions({ reloadOnActiveChange: true });
  const latest = [session("fixture-active", true), session("fixture-latest")];
  f.requests[1].resolve(response(latest));
  await newer;
  f.requests[0].resolve(response([session("fixture-obsolete", true)]));
  await older;
  assert.deepEqual(changes, []);
  assert.equal(f.state.sessions, latest);
});

test("errors from a current external-session handler are not swallowed by a newer list", async () => {
  const f = raceFixture(), change = deferred();
  f.context.handleExternalSessionChanged = () => change.promise;
  const first = f.context.loadSessions({ reloadOnActiveChange: true });
  f.requests[0].resolve(response([session("fixture-new-active", true)]));
  await nextTurn();
  const newer = f.context.loadSessions();
  f.requests[1].resolve(response([session("fixture-active", true)]));
  await newer;
  const rejected = assert.rejects(first, /Fixture transition error/);
  change.reject(new Error("Fixture transition error"));
  await rejected;
});
