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
