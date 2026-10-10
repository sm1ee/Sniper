// Passive lifecycle/save races only. Fetches are deferred VM fixtures; no server
// starts and no replay/request execution or live connection is exercised.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { fixture } = require('./replay-workspace-fixture.cjs');
const { appSource } = require('./frontend-test-helpers.cjs');
const settled = () => new Promise(resolve => setImmediate(resolve));

function setup() {
  const f = fixture();
  f.old = f.tab('old'); f.b = f.tab('B'); f.otherB = f.tab('other B');
  f.seed([f.old]);
  f.sessionB = f.remote([f.b, f.otherB], 3); f.sessionB.session_id = 'session-b';
  for (const name of ['activateSessionById', 'reloadSessionWorkspace', 'loadSessions',
    'loadWorkspaceState', 'applyWorkspaceState', 'toggleReplayTabPin', 'commitReplayTabRename']) {
    vm.runInContext(appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, 'm'))[0], f.context);
  }
  f.errors = [];
  Object.assign(f.context, {
    sessionsLoadGeneration: 0, sessionsAppliedLoadGeneration: 0,
    handleWorkspaceActionError: error => f.errors.push(error),
    requireOkResponse: async response => assert.equal(response.ok, true),
    flushTargetScopeDraft: async () => true, flushMatchReplaceDraft: async () => true,
    flushSequenceDraft: async () => true, flushAllPendingAnnotations: async () => {},
    cleanupWsReplayTabsBeforeStateReset: async () => {}, loadSettings: async () => {},
    renderDashboard() {}, normalizeFuzzerAttackRecord: () => null,
    setFuzzerAttackRecord() {}, fuzzerWorkspaceAttackRecordId: () => null,
    clearReplaySendInFlight() {}, closeContextMenu() {}, refreshTimer: null,
    loadTransactions: async () => {}, loadIntercepts: async () => {}, loadResponseIntercepts: async () => {},
    loadInterceptRules: async () => {}, loadWebsockets: async () => {}, loadEventLog: async () => {},
    loadMatchReplaceRules: async () => {}, loadSequences: async () => {}, loadTargetSiteMap: async () => {},
    refreshScannerQuickToggle: async () => {}, connectEvents() {}, renderToolPanels: () => f.syncDom(),
  });
  // Execute the production workspace reset prefix, omitting unrelated panels.
  // The actual loader below still hydrates the new tabs and advances generation.
  const start = appSource.indexOf('function resetSessionScopedUiState() {');
  const end = appSource.indexOf('  clearHistoryBackfill();', start);
  assert.ok(end > start);
  vm.runInContext(`${appSource.slice(start, end)}\n}`, f.context);
  return f;
}

async function startSwitch(f, id = 'session-b') {
  const index = f.requests.length, switching = f.context.activateSessionById(id);
  await settled();
  assert.equal(f.requests[index].url, `/api/sessions/${id}/activate`);
  return { index, switching };
}

async function finishSwitch(f, pending, snapshot = f.sessionB) {
  const index = f.requests.length;
  f.succeed(pending.index, {}); await settled();
  assert.equal(f.requests[index].url, '/api/sessions');
  f.succeed(index, [{ id: snapshot.session_id, name: snapshot.session_id, active: true }]);
  await settled();
  assert.equal(f.requests[index + 1].url, '/api/workspace-state');
  f.succeed(index + 1, snapshot); await pending.switching;
  assert.equal(f.state.activeSession.id, snapshot.session_id);
}

function settleOldSave(f, index, outcome) {
  if (outcome === 'success') f.succeed(index, { session_id: 'session-a', revision: 11 });
  else f.requests[index].reject(new Error('old session save failed'));
}

for (const oldOutcome of ['success', 'failure']) {
  for (const currentOutcome of ['success', 'failure']) {
    test(`new session pin, rename and close await their own ${currentOutcome} after old ${oldOutcome}`, async () => {
      const f = setup(), switching = await startSwitch(f);
      // The session activation has passed preflight but its response is pending.
      // The old UI can still accept metadata edits during this real await.
      f.context.toggleReplayTabPin(f.old.id);
      assert.equal(JSON.parse(f.requests[1].options.body).session_id, 'session-a');
      await finishSwitch(f, switching);
      assert.equal(f.context.workspaceStateGeneration, 2);
      const closingTab = f.state.replayTabs.find(tab => tab.id === f.b.id);
      const other = f.state.replayTabs.find(tab => tab.id === f.otherB.id);
      const draft = 'GET /unsaved-new-session-draft HTTP/1.1\r\nHost: example.com\r\n\r\n';
      f.els.replayRequestHighlight.innerText = draft;
      f.context.toggleReplayTabPin(other.id);
      f.state.replayRenamingTabId = other.id;
      f.context.commitReplayTabRename(other.id, 'new label');
      const closing = f.context.closeRepeaterTab(closingTab.id);
      let closeSettled = false; closing.then(() => { closeSettled = true; });
      assert.equal(closingTab.requestText, draft);
      assert.equal(f.requests.length, 4, 'all three new actions join the old loop');
      const renders = f.renders.length;
      settleOldSave(f, 1, oldOutcome); await settled();
      assert.equal(closeSettled, false, 'the old response cannot confirm the new close');
      assert.equal(f.requests.length, 5, 'new waiters share one serialized current POST');
      assert.equal(f.renders.length, renders, 'old metadata callbacks cannot redraw this session');
      assert.equal(f.errors.length, 0);
      assert.equal(f.state.workspaceRevision, 3);
      assert.equal(f.context.workspacePendingReplayCloses.has(closingTab.id), true);
      const snapshot = JSON.parse(f.requests[4].options.body);
      assert.equal(snapshot.session_id, 'session-b');
      assert.equal(snapshot.replay.tabs.some(tab => tab.id === closingTab.id), false);
      assert.equal(snapshot.replay.tabs[0].pinned, true);
      assert.equal(snapshot.replay.tabs[0].custom_label, 'new label');
      if (currentOutcome === 'success') f.succeed(4, { session_id: 'session-b', revision: 4 });
      else f.requests[4].reject(new Error('current session save failed'));
      await closing; await settled();
      assert.equal(f.context.workspacePendingReplayCloses.size, 0);
      assert.equal(f.state.replayTabs.includes(closingTab), currentOutcome === 'failure');
      assert.equal(f.context.workspaceSaveConflictPending, currentOutcome === 'failure');
      if (currentOutcome === 'failure') {
        assert.equal(closingTab.requestText, draft);
        assert.equal(other.pinned, false); assert.equal(other.customLabel, 'other B');
      } else {
        assert.equal(other.pinned, true); assert.equal(other.customLabel, 'new label');
        assert.equal(f.state.workspaceRevision, 4); assert.equal(f.context.workspaceSaveDirty, false);
      }
    });
  }

  test(`repeated actual switches preserve only the current close after old ${oldOutcome}`, async () => {
    const f = setup(), c = f.tab('C'), otherC = f.tab('other C');
    const sessionC = f.remote([c, otherC], 7); sessionC.session_id = 'session-c';
    const switchB = await startSwitch(f), switchC = await startSwitch(f, 'session-c');
    f.context.toggleReplayTabPin(f.old.id);
    await finishSwitch(f, switchB);
    f.els.replayRequestHighlight.innerText = 'GET /B-draft HTTP/1.1';
    const closeB = f.context.closeRepeaterTab(f.b.id);
    await finishSwitch(f, switchC, sessionC);
    assert.equal(f.context.workspaceStateGeneration, 4);
    const closingTab = f.state.replayTabs.find(tab => tab.id === c.id);
    f.els.replayRequestHighlight.innerText = 'GET /C-draft HTTP/1.1';
    f.context.toggleReplayTabPin(otherC.id);
    const closeC = f.context.closeRepeaterTab(c.id);
    let closeSettled = false; closeC.then(() => { closeSettled = true; });
    const renders = f.renders.length;
    settleOldSave(f, 2, oldOutcome); await settled(); await closeB;
    assert.equal(closeSettled, false); assert.equal(f.requests.length, 8);
    assert.equal(f.renders.length, renders); assert.equal(f.errors.length, 0);
    assert.equal(f.state.workspaceRevision, 7);
    assert.equal(JSON.parse(f.requests[7].options.body).session_id, 'session-c');
    f.requests[7].reject(new Error('current close failed')); await closeC;
    assert.equal(f.state.replayTabs.includes(closingTab), true);
    assert.equal(closingTab.requestText, 'GET /C-draft HTTP/1.1');
    assert.equal(f.state.replayTabs.some(tab => tab.id === f.b.id), false);
    assert.equal(f.context.workspaceSaveConflictPending, true);
    assert.equal(f.context.workspacePendingReplayCloses.size, 0);
  });

  for (const waitingOn of ['first save', 'bypassed retry']) {
    test(`old bypass options cannot touch a newer conflict after ${waitingOn} ${oldOutcome}`, async () => {
      const f = setup(), switching = await startSwitch(f);
      f.context.scheduleWorkspaceStateSave();
      const flushing = f.context.flushWorkspaceState({ sessionId: 'session-a', bypassExpectedActiveSessionGuard: true });
      const result = flushing.then(() => null, error => error);
      let oldIndex = 1;
      if (waitingOn === 'bypassed retry') {
        f.requests[1].resolve({ ok: false, status: 409, json: async () => ({ error: 'active session changed' }) });
        await settled(); oldIndex = 2;
        assert.equal(f.requests.length, 3);
        assert.equal(JSON.parse(f.requests[2].options.body).session_id, 'session-a');
      }
      await finishSwitch(f, switching);
      const latest = { error: 'active session changed', current_session_id: 'session-c' };
      f.context.workspaceSaveConflictPending = true;
      f.context.workspaceSaveConflictLatest = latest;
      f.context.workspaceSaveDirty = true;
      const requests = f.requests.length, baseline = f.context.workspaceSaveCommittedSnapshot;
      settleOldSave(f, oldIndex, oldOutcome); await settled();
      assert.equal(f.requests.length, requests, 'old options must never POST new tab data under the old session ID');
      assert.equal(await result, null, 'an old caller must not receive the new workspace conflict');
      assert.equal(f.context.workspaceSaveConflictPending, true);
      assert.equal(f.context.workspaceSaveConflictLatest, latest);
      assert.equal(f.context.workspaceSaveCommittedSnapshot, baseline);
      assert.equal(f.state.workspaceRevision, 3); assert.equal(f.context.workspaceSaveDirty, true);
      assert.equal(f.context.workspaceSaveLoopPromise, null);
    });
  }
}
