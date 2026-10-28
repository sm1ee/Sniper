// Storage-folder UI only. Production callbacks run against synthetic DOM/session
// metadata and deferred in-memory responses; no API, native opener, or app starts.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const tick = () => new Promise(resolve => setImmediate(resolve));
const unknownResult = "Could not confirm the session folder opened. Reload sessions before trying again.";
const session = (index, active = false) => ({
  id: `00000000-0000-0000-0000-${String(index).padStart(12, "0")}`,
  name: `Synthetic session ${index}`, active, storage_path: `/synthetic/session-${index}`,
  created_at: `2026-10-0${index}T12:00:00Z`, last_opened_at: `2026-10-0${index}T12:00:00Z`,
});
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const response = body => ({ ok: true, status: 200, json: async () => body });
const httpError = (status, message) => ({
  ok: false, status, headers: { get: () => "text/plain" }, text: async () => message,
});

function node() {
  const listeners = new Map(), classes = new Set();
  return {
    disabled: false, dataset: {}, style: {}, textContent: "", innerHTML: "",
    classList: {
      add: (...names) => names.forEach(name => classes.add(name)),
      remove: (...names) => names.forEach(name => classes.delete(name)),
      contains: name => classes.has(name),
    },
    addEventListener(type, handler) { listeners.set(type, [...(listeners.get(type) || []), handler]); },
    dispatch(type, props = {}) {
      const event = { target: this, stopPropagation() { this.stopped = true; }, preventDefault() {}, ...props };
      for (const handler of listeners.get(type) || []) handler(event);
      return event;
    },
    querySelectorAll: () => [], getBoundingClientRect: () => ({ width: 100, height: 100 }),
    remove() { this.removed = true; },
  };
}

function fixture({ render = true } = {}) {
  const a = session(1, true), b = session(2);
  const state = { sessions: [a, b], activeSession: a, selectedSessionId: a.id, activeTool: "dashboard" };
  const requests = [], toasts = [], errors = [], timers = new Map(), menus = [];
  let timerId = 0, rows = [];
  const button = node(), body = node();
  Object.defineProperty(body, "innerHTML", { set(value) {
    rows = [...value.matchAll(/<tr class="history-row[^"]*" data-id="([^"]+)">/g)].map(match => {
      const row = node(); row.dataset.id = match[1];
      row.open = node(); row.open.closest = () => row;
      row.delete = node(); row.delete.closest = () => row;
      return row;
    });
  } });
  body.querySelectorAll = selector => {
    if (selector === "tr[data-id]") return rows;
    if (selector === ".session-open-button") return rows.filter(row => !state.sessions.find(s => s.id === row.dataset.id).active).map(row => row.open);
    if (selector === ".session-delete-button") return rows.map(row => row.delete);
    assert.fail(`Unexpected dashboard selector: ${selector}`);
  };
  const els = new Proxy({ dashboardOpenStorageBtn: button, dashboardSessionsBody: body }, {
    get: (objects, key) => objects[key] ||= node(),
  });
  const document = {
    getElementById: () => null, createElement: () => node(),
    body: { appendChild: element => menus.push(element) },
  };
  const clearTimeout = id => timers.delete(id);
  const context = loadFunctions([
    "renderDashboard", "sessionFindingCount", "formatSize", "getSortedSessions", "revealSessionFolder", "requireOkResponse", "readApiErrorMessage",
    "onClickWithProgress", "withButtonProgress", "showSessionContextMenu", "closeSessionContextMenu",
    "activateSessionById", "reloadSessionWorkspace", "resetSessionScopedUiState", "loadSessions", "currentSessionId",
    "canReloadWorkspaceAfterSessionAction", "canLeaveSessionAfterDraftPreflight", "hasPendingWorkspaceStateSave",
  ], {
    state, els, document, sessionActivationIntent: null,
    window: { innerWidth: 1000, innerHeight: 1000, clearTimeout },
    sessionContextMenuEl: null,
    formatCappedCount: value => String(value ?? 0), retainedTransactionsCap() {}, retainedEntriesCap() {},
    formatTimestamp: () => "-", escapeHtml: String,
    fetch: (url, options) => { const request = { url, options, ...deferred() }; requests.push(request); return request.promise; },
    showToast: (...args) => toasts.push(args), console: { error: error => errors.push(error), warn() {} },
    handleWorkspaceActionError: error => errors.push(error),
    deleteSessionById() { assert.fail("Folder controls must not delete sessions"); },
    BUTTON_PROGRESS_DELAY_MS: 180, setTimeout: callback => { timers.set(++timerId, callback); return timerId; }, clearTimeout,
    workspaceStateGeneration: 0, workspaceSaveVersion: 0, sessionsLoadGeneration: 0, sessionsAppliedLoadGeneration: 0,
    workspaceSaveDirty: false, workspaceSaveTimer: null, workspaceSaveInFlight: false, workspaceSaveLoopPromise: null,
    workspaceSaveConflictPending: false, workspaceSaveConflictLatest: null, wsTranscriptSaveTimer: null,
    preserveActiveHttpReplayDraftBeforeSessionChange: () => true,
    flushTargetScopeDraft: async () => true, flushMatchReplaceDraft: async () => true, flushSequenceDraft: async () => true,
    flushAllPendingAnnotations: async () => {}, flushWorkspaceState: async () => {}, cleanupWsReplayTabsBeforeStateReset: async () => {},
    reconcileSessionsAfterActionError() { assert.fail("The synthetic activation itself succeeds"); },
    // Execute every production reset mutation; only unrelated editors/painters and
    // the subsequent workspace loaders are inert. In particular, do not stub renderDashboard.
    refreshTimer: null, _incrementalTimer: 0, _transactionDeltaTimer: 0, _pendingTransactionSummaries: [],
    _historyDetailGeneration: 0, _websocketLoadGeneration: 0, _websocketDetailGeneration: 0,
    _websocketDetailRefreshTimer: null, _websocketSummaryMutationGeneration: 0,
    _websocketSummaryMutationById: new Map(), _websocketSummaryEventTimer: null, _websocketSummaryEventBuffer: new Map(),
    createHistoryPagingState: () => ({}), createWebsocketPagingState: () => ({}),
  });
  for (const name of [
    "clearReplaySendInFlight", "closeContextMenu", "clearHistoryBackfill", "cancelHistoryDetailLoading",
    "invalidateVisibleEntriesCache", "renderIntercepts", "renderResponseIntercepts", "renderInterceptRules",
    "updateInterceptQueueBadges", "resetWebsocketFrameScroll", "cancelWebsocketDetailLoading",
    "clearWebsocketQueryBackfill", "clearFilteredWebsocketReload", "clearWebsocketSearchReload", "resetEventLogUiState",
    "resetOastUiState", "resetScannerConfigUiState", "resetFindingsUiState", "clearFuzzerAttackRecord", "clearCompareState",
    "renderHistory", "renderEmptyDetail", "renderWebsocketSessions", "hideFrameDetail", "renderEventLog",
    "renderMatchReplaceRules", "renderTarget", "renderFindings", "renderReplayClearedState", "renderFuzzer", "renderSequencePanel",
    "loadSettings", "loadWorkspaceState", "loadTransactions", "loadIntercepts", "loadResponseIntercepts", "loadInterceptRules",
    "loadWebsockets", "loadEventLog", "loadMatchReplaceRules", "loadSequences", "loadTargetSiteMap",
    "refreshScannerQuickToggle", "connectEvents", "renderToolPanels",
  ]) context[name] = () => {};
  const start = appSource.indexOf("  onClickWithProgress(els.dashboardOpenStorageBtn,");
  const end = appSource.indexOf("\n\n  // Session table sort headers", start);
  assert.ok(start >= 0 && end > start, "Missing actual storage-folder click binding");
  vm.runInContext(appSource.slice(start, end), context);
  function row(id) { const found = rows.find(item => item.dataset.id === id); assert.ok(found, id); return found; }
  function select(id) { row(id).dispatch("click"); }
  function openMenu(id) {
    row(id).dispatch("contextmenu", { clientX: 20, clientY: 20 });
    const menu = menus.at(-1);
    menu.dispatch("click", { target: { closest: () => ({ dataset: { action: "folder" } }) } });
    assert.equal(menu.removed, true, "Context menu closes after its action");
  }
  function open() { button.dispatch("click"); }
  function assertIdle() {
    assert.equal(button.disabled, false);
    assert.equal(button.classList.contains("is-working"), false);
    assert.equal(button.classList.contains("is-working-shown"), false);
    assert.equal(timers.size, 0);
  }
  function assertTarget(index, target) {
    assert.equal(requests[index].url, `/api/sessions/${encodeURIComponent(target.id)}/reveal`);
    assert.equal(requests[index].options.method, "POST");
    assert.deepEqual(Object.keys(requests[index].options), ["method"], "No browser path is sent to the native endpoint");
  }
  function succeed(index, target) { requests[index].resolve(response({ ok: true, path: target.storage_path })); }
  if (render) context.renderDashboard();
  return { a, b, state, context, els, button, requests, toasts, errors, timers, row, select, open, openMenu, assertIdle, assertTarget, succeed };
}

test("storage Open follows actual rendered A → B → A row selection without activating sessions", async () => {
  const f = fixture();
  for (const target of [f.a, f.b, f.a]) {
    f.select(target.id);
    assert.equal(f.els.dashboardCurrentSessionPath.textContent, target.storage_path);
    const index = f.requests.length;
    f.open(); f.assertTarget(index, target); f.succeed(index, target); await tick(); f.assertIdle();
    assert.equal(f.state.activeSession, f.a);
  }
  assert.deepEqual(f.toasts, [f.a, f.b, f.a].map(target => [`Opened ${target.storage_path}`]));
});

test("storage Open has no hidden workspace fallback before the dashboard is rendered", async () => {
  const f = fixture({ render: false });
  f.open(); await tick();
  assert.equal(f.requests.length, 0); assert.deepEqual(f.toasts, []); f.assertIdle();
});

test("an empty rendered dashboard cannot open its stale workspace owner", async () => {
  const f = fixture();
  f.state.sessions = [];
  f.context.renderDashboard();
  assert.equal(f.els.dashboardCurrentSessionStorage.hidden, true);
  f.open(); await tick();
  assert.equal(f.requests.length, 0); assert.equal(f.state.activeSession, f.a); f.assertIdle();
});

async function beginActivation(f) {
  // Exercise the row's production activation binding, including stopPropagation.
  const event = f.row(f.b.id).open.dispatch("click");
  assert.equal(event.stopped, true);
  await tick();
  assert.equal(f.requests[0].url, `/api/sessions/${f.b.id}/activate`);
  f.requests[0].resolve(response({ ...f.b, active: true }));
  await tick();
  assert.equal(f.requests[1].url, "/api/sessions");
  assert.equal(f.state.selectedSessionId, f.b.id);
  assert.equal(f.context.workspaceStateGeneration, 1, "Actual workspace reset ran");
  assert.equal(f.els.dashboardCurrentSessionPath.textContent, f.a.storage_path);
}

test("storage Open stays with the visible path during activation reload and follows the recovered render", async () => {
  const f = fixture(); await beginActivation(f);
  f.open(); f.assertTarget(2, f.a); f.succeed(2, f.a); await tick();
  f.requests[1].resolve(response([{ ...f.a, active: false }, { ...f.b, active: true }]));
  await tick();
  assert.equal(f.els.dashboardCurrentSessionPath.textContent, f.b.storage_path);
  assert.equal(f.state.activeSession.id, f.b.id);
  f.open(); f.assertTarget(3, f.b); f.succeed(3, f.b); await tick(); f.assertIdle();
});

for (const failure of ["network", "HTTP", "JSON", "shape"]) {
  test(`failed ${failure} activation reload keeps Open with the displayed session; explicit reload recovers`, async () => {
    const f = fixture(); await beginActivation(f);
    if (failure === "network") f.requests[1].reject(new Error("Synthetic session-list failure"));
    if (failure === "HTTP") f.requests[1].resolve(httpError(500, "Synthetic session-list failure"));
    if (failure === "JSON") f.requests[1].resolve({ ok: true, json: async () => { throw new SyntaxError("Synthetic session-list failure"); } });
    if (failure === "shape") f.requests[1].resolve(response(null));
    await tick();
    assert.equal(f.errors.length, 1);
    assert.equal(f.els.dashboardCurrentSessionName.textContent, f.a.name);
    assert.equal(f.state.selectedSessionId, f.b.id, "Folder binding must not revert activation selection");
    f.open(); f.assertTarget(2, f.a); f.succeed(2, f.a); await tick();
    const reload = f.context.loadSessions();
    f.requests[3].resolve(response([{ ...f.a, active: false }, { ...f.b, active: true }]));
    await reload;
    f.open(); f.assertTarget(4, f.b); f.succeed(4, f.b); await tick(); f.assertIdle();
    assert.equal(f.state.activeSession.id, f.b.id);
  });
}

for (const outcome of ["success", "error"]) {
  test(`late folder ${outcome} cannot change a newer displayed session`, async () => {
    const f = fixture(); f.open(); f.assertTarget(0, f.a); f.select(f.b.id);
    if (outcome === "success") f.succeed(0, f.a);
    else f.requests[0].resolve(httpError(500, `Synthetic native launch failure for ${f.a.storage_path}`));
    await tick();
    assert.equal(f.els.dashboardCurrentSessionPath.textContent, f.b.storage_path);
    assert.equal(f.state.selectedSessionId, f.b.id);
    assert.equal(f.state.activeSession, f.a);
    assert.deepEqual(f.toasts, outcome === "success"
      ? [[`Opened ${f.a.storage_path}`]] : [[`Synthetic native launch failure for ${f.a.storage_path}`, "error"]]);
    f.open(); f.assertTarget(1, f.b); f.succeed(1, f.b); await tick(); f.assertIdle();
  });
}

test("late completion after an empty render cannot restore a stale folder target", async () => {
  const f = fixture(); f.open(); f.state.sessions = []; f.context.renderDashboard();
  f.succeed(0, f.a); await tick(); f.open(); await tick();
  assert.equal(f.requests.length, 1);
  assert.equal(f.els.dashboardCurrentSessionStorage.hidden, true); f.assertIdle();
});

test("double clicks issue one open request and progress clears even after its delayed indicator appears", async () => {
  const f = fixture(); f.open(); f.open();
  assert.equal(f.requests.length, 1); assert.equal(f.button.disabled, true);
  for (const callback of f.timers.values()) callback();
  assert.equal(f.button.classList.contains("is-working-shown"), true);
  f.succeed(0, f.a); await tick(); f.assertIdle();
});

const malformed = [
  ["null", null], ["missing fields", {}], ["array", []], ["string", "synthetic payload marker"],
  ["false acknowledgement", { ok: false, path: "/synthetic/payload-marker" }],
  ["string acknowledgement", { ok: "true", path: "/synthetic/payload-marker" }],
  ["missing acknowledgement", { path: "/synthetic/payload-marker" }],
  ["missing path", { ok: true }], ["null path", { ok: true, path: null }],
  ["numeric path", { ok: true, path: 17 }], ["object path", { ok: true, path: { marker: "synthetic payload marker" } }],
  ["empty path", { ok: true, path: "" }], ["whitespace path", { ok: true, path: " \n\t\u00a0" }],
];

for (const control of ["dashboard", "context menu"]) {
  const trigger = f => control === "dashboard" ? f.open() : f.openMenu(f.a.id);
  for (const [label, payload] of malformed) {
    test(`${control} rejects ${label} reveal acknowledgement without success, payload snippets, or automatic retry`, async () => {
      const f = fixture(); trigger(f); f.assertTarget(0, f.a);
      f.requests[0].resolve(response(payload)); await tick();
      assert.deepEqual(f.toasts, [[unknownResult, "error"]]);
      assert.equal(f.errors[0].message, unknownResult); assert.equal(f.requests.length, 1); f.assertIdle();
      trigger(f); f.succeed(1, f.a); await tick();
      assert.deepEqual(f.toasts[1], [`Opened ${f.a.storage_path}`]); f.assertIdle();
    });
  }

  test(`${control} rejects truncated JSON with a fixed confirmation error`, async () => {
    const f = fixture(); trigger(f);
    f.requests[0].resolve({ ok: true, json: async () => { throw new SyntaxError('Unexpected token in synthetic-payload-marker'); } });
    await tick();
    assert.deepEqual(f.toasts, [[unknownResult, "error"]]); assert.equal(f.errors[0].message, unknownResult);
    assert.equal(f.requests.length, 1); f.assertIdle();
  });

  for (const failure of ["network", 400, 404, 500]) {
    test(`${control} reports ${failure} failure, preserves its displayed session, and permits explicit retry`, async () => {
      const f = fixture(); trigger(f);
      // Mirrors the native endpoint: invalid UUID 400, missing session 404, failed spawn 500.
      const message = failure === 500 ? `failed to reveal session folder ${f.a.storage_path}: Synthetic native launch failure` : `Synthetic ${failure} failure`;
      if (failure === "network") f.requests[0].reject(new Error(message));
      else f.requests[0].resolve(httpError(failure, message));
      await tick();
      assert.deepEqual(f.toasts, [[message, "error"]]); assert.equal(f.requests.length, 1); f.assertIdle();
      assert.equal(f.els.dashboardCurrentSessionPath.textContent, f.a.storage_path);
      trigger(f); f.succeed(1, f.a); await tick(); f.assertIdle();
    });
  }

  for (const path of ["/synthetic/space 한글 é/session-a", "C:\\synthetic\\space 한글 é\\session-a", "/synthetic/session-a "]) {
    test(`${control} preserves successful native path ${JSON.stringify(path)} exactly`, async () => {
      const f = fixture(); f.a.storage_path = path; f.context.renderDashboard(); trigger(f);
      f.assertTarget(0, f.a); f.succeed(0, f.a); await tick();
      assert.deepEqual(f.toasts, [[`Opened ${path}`]]);
      assert.equal(f.els.dashboardCurrentSessionPath.textContent, path); f.assertIdle();
    });
  }
}
