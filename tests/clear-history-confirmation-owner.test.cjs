// Initialized-session confirmation ownership only. Extracted production handlers,
// a synthetic DOM, and deferred fake fetches: no bootstrap, transport or storage.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");
const canceled = "Clear canceled because the active workspace changed. Reopen Clear history to try again.";
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const response = payload => ({ ok: true, json: async () => payload });

function fixture() {
  const requests = [], actions = [], toasts = [], paints = [], timers = new Map();
  const state = { activeSession: { id: "session-a", name: "Active A" }, sessions: [],
    selectedSessionId: "preview-b", activeTool: "proxy", activeProxyTab: "http-history",
    replayTabs: [], _itemsVersion: 0, selectedId: "row-a", selectedRecord: { id: "row-a" } };
  const document = { activeElement: null };
  function node(tagName = "BUTTON") {
    const listeners = new Map(), classes = new Set();
    const el = { tagName, tabIndex: 0, isConnected: true, disabled: false, children: [], classes,
      classList: { add: (...xs) => xs.forEach(x => classes.add(x)), remove: (...xs) => xs.forEach(x => classes.delete(x)), contains: x => classes.has(x) },
      addEventListener: (type, callback) => listeners.set(type, callback),
      dispatch(type, extra = {}) { return listeners.get(type)?.({ target: el, currentTarget: el, ...extra }); },
      focus() { document.activeElement = el; }, getClientRects: () => [1],
      querySelectorAll: () => el.children,
      remove() { el.isConnected = false; el.children.forEach(child => { child.isConnected = false; }); },
    };
    return el;
  }
  const button = node(); document.activeElement = button;
  document.getElementById = id => id === "clearHistoryButton" ? button : null;
  document.querySelector = () => button;
  document.body = { appendChild() {} };
  document.createElement = () => {
    const modal = node("DIV"), cancel = node(), ok = node();
    modal.children = [cancel, ok];
    modal.querySelector = selector => selector === ".confirm-dialog-cancel" ? cancel : ok;
    return modal;
  };
  let nextTimer = 0, serverSession = { id: "session-b", name: "Active B", active: true };
  const c = loadFunctions([
    "showConfirmDialog", "restoreModalFocus", "getActiveModalAction", "isModalVisible", "trapModalFocus", "escapeHtml",
    "withButtonProgress", "currentSessionId", "expectedActiveSessionIdForWrite", "sessionWritePath",
    "requireOkResponse", "readApiErrorMessage", "formatStructuredApiErrorMessage",
    "handleExternalSessionChanged", "reloadSessionWorkspace", "resetSessionScopedUiState", "loadSessions",
    "hasPendingWorkspaceStateSave", "canLeaveSessionAfterDraftPreflight", "closeContextMenu", "clearCompareState",
  ], {
    state, document, els: { contextMenu: node() }, URLSearchParams, console: { error() {} },
    window: { clearTimeout: id => timers.delete(id), getComputedStyle: () => ({ visibility: "visible" }) },
    setTimeout(callback) { timers.set(++nextTimer, callback); return nextTimer; }, clearTimeout: id => timers.delete(id),
    BUTTON_PROGRESS_DELAY_MS: 180, activeConfirmDialog: null, compareLoadGeneration: 0,
    workspaceLoaded: true, workspaceStateGeneration: 7, workspaceSaveDirty: false, workspaceSaveTimer: null,
    workspaceSaveInFlight: false, workspaceSaveLoopPromise: null, workspaceSaveConflictPending: false, wsTranscriptSaveTimer: null,
    sessionsLoadGeneration: 0, sessionsAppliedLoadGeneration: 0, refreshTimer: null,
    _incrementalTimer: 0, _transactionDeltaTimer: 0, _pendingTransactionSummaries: [], _historyDetailGeneration: 0,
    _websocketLoadGeneration: 0, _websocketDetailGeneration: 0, _websocketDetailRefreshTimer: null,
    _websocketSummaryMutationGeneration: 0, _websocketSummaryMutationById: new Map(),
    _websocketSummaryEventTimer: 0, _websocketSummaryEventBuffer: new Map(),
    preserveActiveHttpReplayDraftBeforeSessionChange: () => true,
    showToast: (...args) => toasts.push(args),
    clearHttpHistorySelectionPreview: () => paints.push("selection"), scheduleRefresh: options => paints.push({ ...options }),
    targetServiceMapController: { reset() {}, invalidate: () => paints.push("map") },
    fetch(path, options) {
      if (path === "/api/sessions") {
        assert.equal(options, undefined);
        return Promise.resolve(response([{ ...serverSession }]));
      }
      assert.match(path, /^\/api\/transactions(?:\?|$)/);
      assert.equal(options.method, "DELETE");
      const request = { path, options, ...deferred() }; requests.push(request); return request.promise;
    },
  });
  // Clean initialized sessions have no drafts to flush. Keep the production
  // transition/reset and session-list adoption, omitting unrelated painters.
  for (const name of ["flushSequenceDraftBeforeExternalSessionReload", "flushTargetScopeDraft", "flushMatchReplaceDraft"]) c[name] = async () => true;
  for (const name of ["flushAllPendingAnnotations", "cleanupWsReplayTabsBeforeStateReset"]) c[name] = async () => {};
  for (const name of [
    "clearReplaySendInFlight", "createHistoryPagingState", "createWebsocketPagingState", "clearHistoryBackfill",
    "cancelHistoryDetailLoading", "invalidateVisibleEntriesCache", "renderIntercepts", "renderResponseIntercepts", "renderInterceptRules",
    "updateInterceptQueueBadges", "resetWebsocketFrameScroll", "cancelWebsocketDetailLoading", "clearWebsocketQueryBackfill",
    "clearFilteredWebsocketReload", "clearWebsocketSearchReload", "resetEventLogUiState", "resetOastUiState",
    "resetScannerConfigUiState", "resetFindingsUiState", "clearFuzzerAttackRecord", "renderHistory", "renderEmptyDetail",
    "renderWebsocketSessions", "hideFrameDetail", "renderEventLog", "renderMatchReplaceRules", "renderTarget",
    "renderFindings", "renderFuzzer", "renderSequencePanel", "renderReplayClearedState", "renderDashboard", "renderToolPanels",
  ]) c[name] = () => {};
  // Successful initialized reload only, not startup/settings ownership behavior.
  for (const name of ["loadSettings", "loadTransactions", "loadIntercepts", "loadResponseIntercepts", "loadInterceptRules",
    "loadWebsockets", "loadEventLog", "loadMatchReplaceRules", "loadSequences", "loadTargetSiteMap", "refreshScannerQuickToggle", "connectEvents"]) c[name] = async () => {};
  c.loadWorkspaceState = async () => { c.workspaceLoaded = true; };
  const progress = c.withButtonProgress;
  c.withButtonProgress = (...args) => { const pending = progress(...args); actions.push(pending); return pending; };
  const start = appSource.indexOf('  document.getElementById("clearHistoryButton")?.addEventListener');
  const end = appSource.indexOf('\n\n  onClickWithProgress', start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(appSource.slice(start, end), c);
  document.addEventListener = (_, handler) => { c.keydown = handler; };
  const keyStart = appSource.indexOf('  document.addEventListener("keydown", (event) => {\n    const activeModalAction');
  const keyEnd = appSource.indexOf('    if (\n      !event.defaultPrevented', keyStart);
  assert.ok(keyStart >= 0 && keyEnd > keyStart);
  vm.runInContext(appSource.slice(keyStart, keyEnd) + "  });", c);
  function open() { button.dispatch("click"); return c.activeConfirmDialog?.modal; }
  function confirm(modal) { modal.querySelector(".confirm-dialog-ok").dispatch("click"); return actions.at(-1); }
  async function change(id = "session-b") {
    const previous = c.currentSessionId(); serverSession = { id, name: `Active ${id}`, active: true };
    await c.handleExternalSessionChanged(previous);
    assert.equal(c.currentSessionId(), id); assert.equal(c.workspaceLoaded, true);
  }
  function key(key) {
    const event = { key, target: document.activeElement, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } };
    c.keydown(event);
    if (key === "Enter" && !event.defaultPrevented) document.activeElement.dispatch("click");
  }
  return { c, state, document, button, requests, actions, toasts, paints, timers, open, confirm, change, key };
}

function assertIdle(f) {
  assert.equal(f.button.disabled, false); assert.equal(f.button._buttonProgress, undefined);
  assert.equal(f.button.classes.has("is-working"), false); assert.equal(f.button.classes.has("is-working-shown"), false);
  assert.equal(f.timers.size, 0);
}
const changes = {
  "A to B": f => f.change(),
  "A to B to A": async f => { await f.change(); await f.change("session-a"); },
  "same-ID workspace reset": f => f.change("session-a"),
};
for (const [name, change] of Object.entries(changes)) {
  test(`${name} leaves the real modal open but cancels its old confirmation before dispatch`, async () => {
    const f = fixture(), modal = f.open(); await change(f);
    assert.equal(modal.isConnected, true); assert.equal(f.c.activeConfirmDialog.modal, modal);
    const pending = f.confirm(modal);
    assert.equal(f.requests.length, 0); assert.deepEqual(f.toasts, [[canceled, "error"]]);
    await pending;
    assert.deepEqual(f.paints, []); assertIdle(f);
  });
}

for (const activeSession of [null, { id: "", name: "No ID" }]) test("unknown active session cannot open a destructive confirmation or dispatch after a session appears", () => {
  const f = fixture(); f.state.activeSession = activeSession;
  const modal = f.open(); f.state.activeSession = { id: "session-b", name: "Active B" };
  if (modal) f.confirm(modal);
  assert.equal(f.requests.length, 0); assert.equal(modal, undefined); assertIdle(f);
});

test("losing the active session cancels an already-open confirmation", async () => {
  const f = fixture(), modal = f.open(); f.state.activeSession = null;
  await f.confirm(modal);
  assert.equal(f.requests.length, 0); assert.deepEqual(f.toasts, [[canceled, "error"]]); assertIdle(f);
});

test("reopening Clear after a canceled stale confirmation captures the new active target", async () => {
  const f = fixture(), modal = f.open(); await f.change(); await f.confirm(modal);
  const currentModal = f.open(), pending = f.confirm(currentModal);
  assert.match(currentModal.innerHTML, /Active session-b/);
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].path, "/api/transactions?session_id=session-b&expected_active_session_id=session-b");
  f.requests[0].resolve(response({ removed: 0 })); await pending;
  assert.equal(f.toasts.at(-1)[0], "Cleared 0 captured requests."); assertIdle(f);
});

for (const name of ['Active <A> & "quoted"', "", "   ", null]) test(`dialog names its captured active target safely: ${JSON.stringify(name)}`, () => {
  const f = fixture(); f.state.activeSession.name = name;
  f.state.sessions = [{ id: "preview-b", name: "Selected preview B" }];
  const modal = f.open();
  assert.match(modal.innerHTML, name?.trim() ? /Active &lt;A&gt; &amp; &quot;quoted&quot;/ : /session-a/);
  assert.doesNotMatch(modal.innerHTML, /Selected preview B|<A>/);
  f.state.activeSession.name = "Renamed after opening";
  assert.doesNotMatch(modal.innerHTML, /Renamed after opening/);
  modal.querySelector(".confirm-dialog-cancel").dispatch("click"); assert.equal(f.requests.length, 0);
});

for (const control of ["Cancel", "Escape", "backdrop", "Enter on initially focused Cancel"]) test(`${control} dismisses without dispatch and restores focus`, () => {
  const f = fixture(), modal = f.open();
  assert.equal(f.document.activeElement, modal.querySelector(".confirm-dialog-cancel"));
  if (control === "Cancel") modal.querySelector(".confirm-dialog-cancel").dispatch("click");
  else if (control === "backdrop") modal.dispatch("click");
  else f.key(control === "Escape" ? "Escape" : "Enter");
  assert.equal(modal.isConnected, false); assert.equal(f.c.activeConfirmDialog, null);
  assert.equal(f.document.activeElement, f.button); assert.equal(f.requests.length, 0); assertIdle(f);
});

test("Enter on the explicit Clear control confirms its current target", async () => {
  const f = fixture(), modal = f.open(); modal.querySelector(".confirm-dialog-ok").focus(); f.key("Enter");
  assert.equal(f.requests.length, 1); assert.equal(modal.isConnected, false);
  f.requests[0].resolve(response({ removed: 0 })); await f.actions.at(-1); assertIdle(f);
});

test("current failure without a message preserves fallback feedback and cleanup", async () => {
  const f = fixture(), pending = f.confirm(f.open()); f.requests[0].reject(new Error("")); await pending;
  assert.deepEqual(f.toasts, [["Failed to clear the history.", "error"]]); assertIdle(f);
});

for (const removed of [1, 2]) test(`current confirmation targets A once, reports ${removed} removed, and releases progress`, async () => {
  const f = fixture(), modal = f.open(), pending = f.confirm(modal);
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].path, "/api/transactions?session_id=session-a&expected_active_session_id=session-a");
  assert.equal(modal.isConnected, false); assert.equal(f.button.disabled, true);
  [...f.timers.values()][0](); assert.equal(f.button.classes.has("is-working-shown"), true);
  await f.confirm(f.open()); assert.equal(f.requests.length, 1, "progress still blocks duplicate confirmation");
  f.requests[0].resolve(response({ removed })); await pending;
  assert.equal(f.state.selectedId, null); assert.equal(f.state.selectedRecord, null);
  assert.deepEqual(f.paints, ["map", "selection", { resetScroll: true }]);
  assert.deepEqual(f.toasts, [[`Cleared ${removed} captured request${removed === 1 ? "" : "s"}.`, "info"]]); assertIdle(f);
});

async function settleLater(request, kind) {
  if (kind === "network") return () => request.reject(new Error("Synthetic network failure"));
  if (kind === "success response") return () => request.resolve(response({ removed: 2 }));
  const body = deferred(), reading = deferred(), http = kind.startsWith("HTTP");
  request.resolve(http
    ? { ok: false, headers: { get: () => "text/plain" }, text() { reading.resolve(); return body.promise; } }
    : { ok: true, json() { reading.resolve(); return body.promise; } });
  await reading.promise;
  if (kind === "success JSON body") return () => body.resolve({ removed: 2 });
  if (kind === "HTTP") return () => body.resolve("Synthetic HTTP failure");
  return () => body.reject(new Error(`Synthetic ${kind} failure`));
}
for (const kind of ["network", "HTTP", "HTTP body", "JSON", "success response", "success JSON body"]) {
  for (const [name, change] of Object.entries(changes)) test(`late ${kind} after ${name} stays silent and leaves the current view alone`, async () => {
    const f = fixture(), pending = f.confirm(f.open()), finish = await settleLater(f.requests[0], kind);
    await change(f); f.state.selectedId = "new-row"; f.state.selectedRecord = { id: "new-row" };
    finish(); await pending;
    assert.equal(f.state.selectedId, "new-row"); assert.equal(f.state.selectedRecord.id, "new-row");
    assert.deepEqual(f.toasts, []); assert.deepEqual(f.paints, []); assertIdle(f);
  });
  if (!kind.startsWith("success")) test(`same-owner ${kind} failure reports feedback without clearing selection and releases progress`, async () => {
    const f = fixture(), pending = f.confirm(f.open()), finish = await settleLater(f.requests[0], kind);
    finish(); await pending;
    assert.equal(f.state.selectedId, "row-a"); assert.equal(f.state.selectedRecord.id, "row-a");
    const message = kind === "HTTP body" ? "Failed to clear the history." : `Synthetic ${kind} failure`;
    assert.deepEqual(f.toasts, [[message, "error"]]); assert.deepEqual(f.paints, []); assertIdle(f);
  });
}
