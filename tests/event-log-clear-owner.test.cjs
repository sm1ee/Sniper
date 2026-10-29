// Initialized Logger ownership only. Extracted production handlers and inert
// deferred fetches: no app bootstrap, real Clear, transport, or storage.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const response = payload => ({ ok: true, json: async () => payload });
const entry = id => ({ id, captured_at: "2026-01-01", level: "info", source: "fixture", title: id, message: "Saved event" });
const fallback = "Failed to clear event log.";

function fixture() {
  const requests = [], reads = [], actions = [], renders = [], toasts = [], errors = [], timers = new Map();
  const state = { activeSession: { id: "session-a", name: "Active A", active: true },
    sessions: [], selectedSessionId: "session-a", replayTabs: [], _itemsVersion: 0,
    activeTool: "logger", activeProxyTab: "http-history", eventLog: [entry("saved-a")] };
  let serverSession = { ...state.activeSession }, nextTimer = 0;
  const classes = new Set(), listeners = new Map();
  const button = { disabled: false, classes,
    classList: { add: (...names) => names.forEach(name => classes.add(name)), remove: (...names) => names.forEach(name => classes.delete(name)) },
    addEventListener: (name, callback) => listeners.set(name, callback),
  };
  const els = { clearEventLogButton: button, eventLogStatus: {}, eventLogTableBody: {} };
  const c = loadFunctions([
    "clearEventLog", "resetEventLogUiState", "loadEventLog", "mergeEventLogEntries", "jsonArray",
    "currentSessionId", "expectedActiveSessionIdForWrite", "sessionWritePath", "sessionQueryPath",
    "requireOkResponse", "readApiErrorMessage", "formatStructuredApiErrorMessage",
    "handleExternalSessionChanged", "reloadSessionWorkspace", "resetSessionScopedUiState", "loadSessions",
    "hasPendingWorkspaceStateSave", "canLeaveSessionAfterDraftPreflight", "onClickWithProgress", "withButtonProgress",
    "renderEventLog", "escapeHtml",
  ], {
    state, els, URLSearchParams, EVENT_LOG_LIMIT: 500, BUTTON_PROGRESS_DELAY_MS: 180,
    _eventLogLoadGeneration: 0, _eventLogMutationGeneration: 3, _eventLogClearGeneration: 2,
    workspaceLoaded: true, workspaceStateGeneration: 7, workspaceSaveDirty: false, workspaceSaveTimer: null,
    workspaceSaveInFlight: false, workspaceSaveLoopPromise: null, workspaceSaveConflictPending: false,
    wsTranscriptSaveTimer: null, sessionsLoadGeneration: 0, sessionsAppliedLoadGeneration: 0,
    refreshTimer: null, _incrementalTimer: 0, _transactionDeltaTimer: 0,
    _pendingTransactionSummaries: [], _historyDetailGeneration: 0,
    _websocketLoadGeneration: 0, _websocketDetailGeneration: 0, _websocketDetailRefreshTimer: null,
    _websocketSummaryMutationGeneration: 0, _websocketSummaryMutationById: new Map(),
    _websocketSummaryEventTimer: 0, _websocketSummaryEventBuffer: new Map(),
    window: { clearTimeout() {} }, console: { error: error => errors.push(error) },
    setTimeout(callback) { timers.set(++nextTimer, callback); return nextTimer; },
    clearTimeout: id => timers.delete(id),
    preserveActiveHttpReplayDraftBeforeSessionChange: () => true,
    showToast: (...args) => toasts.push(args), formatTimestamp: value => value,
    fetch(path, options) {
      if (options) {
        assert.equal(options.method, "DELETE");
        assert.match(path, /^\/api\/event-log\?/);
        const request = { path, options, ...deferred() }; requests.push(request); return request.promise;
      }
      reads.push(path);
      if (path === "/api/sessions") return Promise.resolve(response([{ ...serverSession }]));
      assert.match(path, /^\/api\/event-log\?limit=500&session_id=/);
      return Promise.resolve(response([entry(`fresh-${serverSession.id}`)]));
    },
  });
  // Clean initialized owners have no drafts or live replay connections to flush.
  for (const name of ["flushSequenceDraftBeforeExternalSessionReload", "flushTargetScopeDraft", "flushMatchReplaceDraft"]) c[name] = async () => true;
  for (const name of ["flushAllPendingAnnotations", "cleanupWsReplayTabsBeforeStateReset"]) c[name] = async () => {};
  for (const name of [
    "clearReplaySendInFlight", "closeContextMenu", "clearCompareState", "createHistoryPagingState",
    "createWebsocketPagingState", "clearHistoryBackfill", "cancelHistoryDetailLoading", "invalidateVisibleEntriesCache",
    "renderIntercepts", "renderResponseIntercepts", "renderInterceptRules", "updateInterceptQueueBadges",
    "resetWebsocketFrameScroll", "cancelWebsocketDetailLoading", "clearWebsocketQueryBackfill",
    "clearFilteredWebsocketReload", "clearWebsocketSearchReload", "resetOastUiState", "resetScannerConfigUiState",
    "resetFindingsUiState", "clearFuzzerAttackRecord", "renderHistory", "renderEmptyDetail", "renderWebsocketSessions",
    "hideFrameDetail", "renderMatchReplaceRules", "renderTarget", "renderFindings", "renderFuzzer",
    "renderSequencePanel", "renderReplayClearedState", "renderDashboard", "renderToolPanels",
  ]) c[name] = () => {};
  // Keep production session/reset/Logger readers. Unrelated readers and the
  // successful hydration hook stay outside startup/failure ownership behavior.
  for (const name of ["loadSettings", "loadTransactions", "loadIntercepts", "loadResponseIntercepts",
    "loadInterceptRules", "loadWebsockets", "loadMatchReplaceRules", "loadSequences", "loadTargetSiteMap",
    "refreshScannerQuickToggle", "connectEvents"]) c[name] = async () => {};
  c.loadWorkspaceState = async () => { c.workspaceLoaded = true; };
  const render = c.renderEventLog;
  c.renderEventLog = () => { render(); renders.push(Array.from(state.eventLog, item => item.id)); };
  c.renderEventLog();
  const progress = c.withButtonProgress;
  c.withButtonProgress = (...args) => { const pending = progress(...args); actions.push(pending); return pending; };
  const start = appSource.indexOf("  onClickWithProgress(els.clearEventLogButton, () => {");
  const end = appSource.indexOf("\n  });", start) + 6;
  assert.ok(start >= 0 && end > start);
  vm.runInContext(appSource.slice(start, end), c);
  function click() {
    listeners.get("click")({ currentTarget: button });
    return actions.at(-1);
  }
  async function change(id) {
    assert.equal(c.workspaceLoaded, true);
    const previous = c.currentSessionId(), generation = c.workspaceStateGeneration;
    serverSession = { id, name: `Active ${id}`, active: true };
    await c.handleExternalSessionChanged(previous);
    assert.equal(c.currentSessionId(), id);
    assert.equal(c.workspaceLoaded, true);
    assert.equal(c.workspaceStateGeneration, generation + 1, "production reset must advance the owner generation");
    assert.deepEqual(Array.from(state.eventLog, item => item.id), [`fresh-${id}`]);
  }
  return { c, state, els, button, requests, reads, actions, renders, toasts, errors, timers, click, change };
}

function take(f) {
  return { events: f.state.eventLog, rendered: f.renders.length,
    mutation: f.c._eventLogMutationGeneration, clear: f.c._eventLogClearGeneration,
    load: f.c._eventLogLoadGeneration, status: f.els.eventLogStatus.textContent, html: f.els.eventLogTableBody.innerHTML };
}
function assertIdle(f) {
  assert.equal(f.button.disabled, false); assert.equal(f.button._buttonProgress, undefined);
  assert.equal(f.button.classes.size, 0); assert.equal(f.timers.size, 0);
}
const changes = {
  "A to B": f => f.change("session-b"),
  "same-ID initialized reload": f => f.change("session-a"),
  "A to B to A": async f => { await f.change("session-b"); await f.change("session-a"); },
};

for (const [name, change] of Object.entries(changes)) test(`late Clear success after ${name} preserves the current array, counters, and render`, async () => {
  const f = fixture(), pending = f.click(); await change(f);
  const before = take(f);
  f.requests[0].resolve({ ok: true, json: () => assert.fail("Clear success has no JSON body to read") });
  await pending;
  assert.deepEqual(take(f), before); assert.equal(f.state.eventLog, before.events);
  assert.deepEqual(f.toasts, []); assert.deepEqual(f.errors, []); assert.equal(f.requests.length, 1); assertIdle(f);
});

const failureMessages = {
  network: "Synthetic network failure",
  text: "Synthetic text failure",
  JSON: "Synthetic JSON failure (owner_session_id session-a)",
  "JSON fallback": "Synthetic fallback text failure",
  "text rejection fallback": fallback,
  "empty text fallback": fallback,
};
async function settleFailureLater(request, kind) {
  if (kind === "network") return () => request.reject(new Error(failureMessages.network));
  const reading = deferred(), body = deferred(), json = kind.startsWith("JSON");
  request.resolve({ ok: false,
    headers: { get: () => json ? "application/json" : "text/plain" },
    clone: () => ({ json() { reading.resolve(); return body.promise; } }),
    text() {
      if (json) return Promise.resolve(failureMessages["JSON fallback"]);
      reading.resolve(); return body.promise;
    },
  });
  await reading.promise;
  if (kind === "JSON") return () => body.resolve({ error: "Synthetic JSON failure", owner_session_id: "session-a" });
  if (kind === "JSON fallback" || kind === "text rejection fallback") return () => body.reject(new Error("Synthetic body failure"));
  return () => body.resolve(kind === "empty text fallback" ? "   " : failureMessages.text);
}

for (const kind of Object.keys(failureMessages)) {
  for (const [name, change] of Object.entries(changes)) test(`late Clear ${kind} after ${name} stays silent and preserves the current owner`, async () => {
    const f = fixture(), pending = f.click(), finish = await settleFailureLater(f.requests[0], kind);
    await change(f); const before = take(f);
    finish(); await pending;
    assert.deepEqual(take(f), before); assert.equal(f.state.eventLog, before.events);
    assert.deepEqual(f.toasts, []); assert.deepEqual(f.errors, []); assert.equal(f.requests.length, 1); assertIdle(f);
  });
  test(`current Clear ${kind} reports unchanged feedback without clearing events`, async () => {
    const f = fixture(), before = take(f), pending = f.click();
    const finish = await settleFailureLater(f.requests[0], kind); finish(); await pending;
    assert.deepEqual(take(f), before); assert.equal(f.state.eventLog, before.events);
    assert.deepEqual(f.toasts, [[failureMessages[kind], "error"]]); assert.equal(f.errors.length, 1); assertIdle(f);
  });
}

test("current Clear targets its captured session once, advances counters, and releases progress", async () => {
  const f = fixture(), before = take(f), pending = f.click();
  assert.equal(f.button.disabled, true);
  [...f.timers.values()][0](); assert.equal(f.button.classes.has("is-working-shown"), true);
  await f.click(); assert.equal(f.requests.length, 1, "progress prevents double dispatch");
  assert.equal(f.requests[0].path, "/api/event-log?session_id=session-a&expected_active_session_id=session-a");
  f.requests[0].resolve({ ok: true }); await pending;
  assert.equal(f.state.eventLog.length, 0); assert.notEqual(f.state.eventLog, before.events);
  assert.equal(f.c._eventLogMutationGeneration, before.mutation + 1);
  assert.equal(f.c._eventLogClearGeneration, before.clear + 1);
  assert.equal(f.c._eventLogLoadGeneration, before.load);
  assert.equal(f.renders.length, before.rendered + 1); assert.equal(f.els.eventLogStatus.textContent, "0 entries");
  assert.deepEqual(f.toasts, []); assertIdle(f);
});

test("an ordinary same-workspace Logger refresh does not retire its pending Clear", async () => {
  const f = fixture(), pending = f.click(), generation = f.c.workspaceStateGeneration;
  await f.c.loadEventLog(); const before = take(f);
  assert.equal(f.c.workspaceStateGeneration, generation);
  f.requests[0].resolve({ ok: true }); await pending;
  assert.equal(f.state.eventLog.length, 0); assert.equal(f.c._eventLogClearGeneration, before.clear + 1);
  assert.equal(f.c._eventLogMutationGeneration, before.mutation + 1); assert.equal(f.renders.length, before.rendered + 1); assertIdle(f);
});

test("current Clear rethrows the original network error for its existing caller", async () => {
  const f = fixture(), before = take(f), error = new Error("Synthetic original failure");
  const pending = f.c.clearEventLog(), rejected = assert.rejects(pending, caught => caught === error);
  f.requests[0].reject(error); await rejected;
  assert.deepEqual(take(f), before); assert.deepEqual(f.toasts, []); assert.deepEqual(f.errors, []);
});
