// Saved-session dashboard presentation only, using a synthetic empty DOM.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");
const session = (id, active = false) => ({ id, name: `Saved ${id}`, active });
function fixture(sessions, activeSession, selectedSessionId) {
  const state = { sessions, activeSession, selectedSessionId };
  const els = new Proxy({}, { get: (object, key) => object[key] ||= { querySelectorAll: () => [] } });
  const c = loadFunctions(["renderDashboard", "sessionFindingCount", "formatSize"], {
    state, els, document: { getElementById: () => null }, getSortedSessions: () => sessions,
    formatCappedCount: value => String(value ?? 0), retainedTransactionsCap() {}, retainedEntriesCap() {},
    formatTimestamp: () => "-", escapeHtml: value => String(value),
  });
  return { c, state, els };
}
for (const activeSession of [null, undefined, session("old-active", true)]) {
  test(`empty dashboard has a neutral status with ${JSON.stringify(activeSession)} workspace metadata`, () => {
    const f = fixture([], activeSession, "old-selection");
    f.c.renderDashboard();
    assert.equal(f.els.dashboardCurrentSessionName.textContent, "No active session");
    assert.equal(f.els.dashboardCurrentSessionStorage.hidden, true);
    assert.equal(f.state.selectedSessionId, null);
    assert.equal(f.state.activeSession, activeSession, "rendering must not change workspace ownership");
  });
}

test("an active selected saved session keeps its active mark", () => {
  const active = session("current", true);
  const f = fixture([active], active, active.id);
  f.c.renderDashboard();
  assert.match(f.els.dashboardSessionsBody.innerHTML, /class="history-row selected session-active" data-id="current"/);
});

test("a stored selected session carries no active mark", () => {
  const active = session("current", true), stored = session("stored");
  const f = fixture([active, stored], active, stored.id);
  f.c.renderDashboard();
  assert.match(f.els.dashboardSessionsBody.innerHTML, /class="history-row selected" data-id="stored"/);
  assert.match(f.els.dashboardSessionsBody.innerHTML, /class="history-row session-active" data-id="current"/);
});

test("clearing the dashboard list removes a previously active mark", () => {
  const active = session("current", true);
  const f = fixture([active], active, active.id);
  f.c.renderDashboard();
  f.state.sessions.splice(0);
  f.c.renderDashboard();
  assert.doesNotMatch(f.els.dashboardSessionsBody.innerHTML, /session-active/);
  assert.equal(f.els.dashboardCurrentSessionStorage.hidden, true);
  assert.equal(f.state.activeSession, active);
});
