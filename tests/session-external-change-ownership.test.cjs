// Passive session ownership only. All fetches are deferred synthetic responses.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { fixture, deferred } = require('./replay-workspace-fixture.cjs');
const { appSource } = require('./frontend-test-helpers.cjs');
const source = name => appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}$`, 'm'))[0];
const tick = () => new Promise(resolve => setImmediate(resolve));
function setup() {
  const f = fixture();
  f.a = f.tab('stored-a'); f.b = f.tab('stored-b'); f.seed([f.a]);
  f.reloads = []; f.errors = []; f.log = [];
  for (const name of ['handleExternalSessionChanged', 'hasPendingWorkspaceStateSave',
    'expectedActiveSessionIdForWrite', 'retireFindingActionProgress', 'applyWorkspaceState', 'cleanupWsReplayTabsBeforeStateReset',
    'createSession', 'activateSessionById', 'loadSessions']) vm.runInContext(source(name), f.context);
  for (const name of ['flushSequenceDraftBeforeExternalSessionReload', 'flushTargetScopeDraft',
    'flushMatchReplaceDraft', 'flushSequenceDraft', 'flushAllPendingAnnotations']) {
    f.context[name] = async () => { f.log.push(name); return true; };
  }
  Object.assign(f.context, {
    sessionsLoadGeneration: 0, sessionsAppliedLoadGeneration: 0,
    requireOkResponse: async response => assert.equal(response.ok, true), renderDashboard() {},
    normalizeFuzzerAttackRecord: () => null, setFuzzerAttackRecord() {}, fuzzerWorkspaceAttackRecordId: () => null,
    handleSequenceActionError: error => f.errors.push(error), handleWorkspaceActionError: error => f.errors.push(error),
    reconcileSessionsAfterActionError: async () => assert.fail('unexpected mutation failure'),
    cleanupWsReplayTab: async () => {},
  });
  f.els.dashboardCreateSessionName = { value: 'new session' };
  f.replace = (id = 'session-b', dirty = true) => {
    f.state.activeSession = { id };
    const snapshot = f.remote([f.b], 20); snapshot.session_id = id;
    f.context.applyWorkspaceState(snapshot); f.context.workspaceLoaded = true; f.syncDom();
    if (dirty) {
      f.context.getActiveReplayTab().requestText = 'GET /new-workspace-unsaved HTT';
      f.syncDom(); f.context.scheduleWorkspaceStateSave();
    }
  };
  // Model an accepted reload with production hydration; unrelated loaders and UI painters stay out.
  f.context.reloadSessionWorkspace = async options => { f.reloads.push(options); f.replace('session-b', false); };
  f.take = () => ({ owner: f.state.activeSession.id, generation: f.context.workspaceStateGeneration,
    tabs: f.state.replayTabs, active: f.state.activeReplayTabId, text: f.els.replayRequestHighlight.innerText,
    dirty: f.context.workspaceSaveDirty, baseline: f.context.workspaceSaveCommittedSnapshot,
    version: f.context.workspaceSaveVersion, conflict: f.context.workspaceSaveConflictPending });
  f.assertRetained = before => {
    const after = f.take();
    for (const key of Object.keys(before)) assert.equal(after[key], before[key], key);
    assert.equal(f.reloads.length, 0); assert.equal(f.errors.length, 0); assert.equal(f.toasts.length, 0);
  };
  return f;
}
test('stale event entry cannot touch a different current workspace', async () => {
  const f = setup(); f.replace(); const before = f.take();
  const pending = f.context.handleExternalSessionChanged('session-a');
  await tick();
  assert.equal(f.requests.length, 0, 'stale owner must never label a newer draft as A');
  await pending; f.assertRetained(before);
});

const phases = {
  sequence: 'flushSequenceDraftBeforeExternalSessionReload', target: 'flushTargetScopeDraft',
  match: 'flushMatchReplaceDraft', annotations: 'flushAllPendingAnnotations', cleanup: 'cleanupWsReplayTabsBeforeStateReset',
};
for (const [phase, name] of Object.entries(phases)) for (const change of ['owner', 'generation']) {
  test(`${phase} await cannot resume into a newer ${change}`, async () => {
    const f = setup(), gate = deferred();
    f.context[name] = () => gate.promise;
    const pending = f.context.handleExternalSessionChanged('session-a'); await tick();
    f.replace(change === 'owner' ? 'session-b' : 'session-a'); const before = f.take();
    gate.resolve(true); await tick();
    assert.equal(f.requests.length, 0, 'resuming old preflight must not POST newer workspace under old options');
    await pending; f.assertRetained(before);
  });
}
for (const phase of ['sequence', 'annotations', 'cleanup']) test(`stale ${phase} rejection cannot report against the new workspace`, async () => {
  const f = setup(), gate = deferred(); f.context[phases[phase]] = () => gate.promise;
  const pending = f.context.handleExternalSessionChanged('session-a'); await tick();
  f.replace(); const before = f.take(); gate.reject(new Error('old phase failure')); await pending;
  f.assertRetained(before); assert.equal(f.requests.length, 0);
});
test('current sequence refusal still asks the user to finish saving without reloading', async () => {
  const f = setup(); f.context.flushSequenceDraftBeforeExternalSessionReload = async () => false;
  await f.context.handleExternalSessionChanged('session-a');
  assert.equal(f.requests.length, 0); assert.equal(f.reloads.length, 0);
  assert.equal(f.state.activeSession.id, 'session-a'); assert.equal(f.state.replayTabs[0], f.a);
  assert.match(f.toasts[0][0], /Sequence draft finished saving/);
});
for (const phase of ['sequence', 'annotations', 'workspace', 'cleanup']) test(`current ${phase} failure still reports without reloading`, async () => {
  const f = setup(), error = new Error('current preflight failure');
  if (phase === 'workspace') f.context.scheduleWorkspaceStateSave();
  f.context[phase === 'workspace' ? 'flushWorkspaceState' : phases[phase]] = async () => { throw error; };
  await f.context.handleExternalSessionChanged('session-a');
  assert.equal(f.errors.length, 1); assert.equal(f.errors[0], error);
  assert.equal(f.requests.length, 0); assert.equal(f.reloads.length, 0);
  assert.equal(f.state.activeSession.id, 'session-a'); assert.equal(f.state.replayTabs[0], f.a);
});
for (const outcome of ['success', 'failure']) test(`old workspace ${outcome} cannot proceed to cleanup or reload`, async () => {
  const f = setup(); f.context.scheduleWorkspaceStateSave();
  const pending = f.context.handleExternalSessionChanged('session-a'); await tick();
  assert.equal(f.requests.length, 1); assert.equal(JSON.parse(f.requests[0].options.body).session_id, 'session-a');
  f.replace(); const before = f.take();
  if (outcome === 'success') f.succeed(0, { session_id: 'session-a', revision: 11 });
  else f.requests[0].reject(new Error('old save failure'));
  // The old save loop legitimately schedules the new owner's pending autosave.
  const version = before.version; delete before.version;
  await pending; f.assertRetained(before); assert.equal(f.requests.length, 1);
  assert.equal(f.context.workspaceSaveVersion, version + 1);
});
for (const change of ['owner', 'generation']) test(`actual cleanup inner await cannot flush newer ${change} with old options`, async () => {
  const f = setup(), gate = deferred();
  const ws = { id: 'stored-ws', type: 'websocket', wsStatus: 'connected', wsSessionId: 'session-a' };
  f.state.replayTabs.push(ws);
  f.context.cleanupWsReplayTab = () => gate.promise;
  const pending = f.context.handleExternalSessionChanged('session-a'); await tick();
  f.replace(change === 'owner' ? 'session-b' : 'session-a'); const before = f.take();
  gate.resolve(); await tick();
  assert.equal(f.requests.length, 0, 'cleanup must recheck ownership before its internal workspace flush');
  await pending; f.assertRetained(before);
});
test('overlapping same-owner events cause only one workspace reload', async () => {
  const f = setup(), gate = deferred();
  f.context.flushSequenceDraftBeforeExternalSessionReload = () => gate.promise;
  const first = f.context.handleExternalSessionChanged('session-a');
  const second = f.context.handleExternalSessionChanged('session-a');
  gate.resolve(true); await Promise.all([first, second]);
  assert.equal(f.reloads.length, 1); assert.equal(f.state.activeSession.id, 'session-b');
  assert.equal(f.requests.length, 0);
});
for (const dirty of [false, true]) test(`valid same-owner ${dirty ? 'dirty' : 'clean'} event keeps its existing flush/reload flow`, async () => {
  const f = setup(); if (dirty) f.context.scheduleWorkspaceStateSave();
  const pending = f.context.handleExternalSessionChanged('session-a'); await tick();
  if (dirty) {
    assert.equal(f.requests.length, 1);
    const body = JSON.parse(f.requests[0].options.body);
    assert.equal(body.session_id, 'session-a'); assert.equal(body.expected_active_session_id, null);
    assert.equal(body.replay.tabs[0].id, f.a.id);
    f.succeed(0, { session_id: 'session-a', revision: 11 });
  }
  await pending; assert.equal(f.reloads.length, 1); assert.equal(f.state.activeSession.id, 'session-b');
  assert.equal(f.requests.length, dirty ? 1 : 0); assert.equal(f.errors.length, 0);
});
test('manual list refresh after a missed event still flushes the prior owner before reload', async () => {
  const f = setup(); f.context.scheduleWorkspaceStateSave();
  const pending = f.context.loadSessions({ reloadOnActiveChange: true });
  f.succeed(0, [{ id: 'session-b', name: 'B', active: true }]); await tick();
  assert.equal(f.state.activeSession.id, 'session-a');
  assert.equal(f.requests.length, 2);
  const body = JSON.parse(f.requests[1].options.body);
  assert.equal(body.session_id, 'session-a'); assert.equal(body.expected_active_session_id, null);
  f.succeed(1, { session_id: 'session-a', revision: 11 }); await pending;
  assert.equal(f.reloads.length, 1); assert.equal(f.state.activeSession.id, 'session-b');
});
for (const operation of ['create', 'activate']) test(`event preflight cannot retag drafts after explicit ${operation} finishes`, async () => {
  const f = setup(), gate = deferred();
  const action = operation === 'create' ? f.context.createSession() : f.context.activateSessionById('session-b');
  await tick(); assert.equal(f.requests.length, 1);
  f.context.flushSequenceDraftBeforeExternalSessionReload = () => gate.promise;
  const event = f.context.handleExternalSessionChanged('session-a');
  f.succeed(0, {}); await action;
  assert.equal(f.reloads.length, 1); f.reloads.length = 0;
  f.context.getActiveReplayTab().requestText = 'GET /new-workspace-unsaved HTT'; f.syncDom(); f.context.scheduleWorkspaceStateSave();
  const before = f.take(); gate.resolve(true); await tick();
  assert.equal(f.requests.length, 1, 'only the explicit action should have issued a request');
  await event; f.assertRetained(before);
});

test('same-owner cleanup still flushes edits made while its per-tab cleanup waits', async () => {
  const f = setup(), gate = deferred(), flushes = [];
  f.state.replayTabs.push({ id: 'stored-ws', type: 'websocket', wsStatus: 'connected', wsSessionId: 'session-a' });
  f.context.cleanupWsReplayTab = () => gate.promise;
  f.context.flushWorkspaceState = async options => { flushes.push(options); };
  const pending = f.context.cleanupWsReplayTabsBeforeStateReset({ sessionId: 'session-a', bypassExpectedActiveSessionGuard: true });
  f.context.scheduleWorkspaceStateSave(); gate.resolve(); await pending;
  assert.equal(flushes.length, 1); assert.equal(flushes[0].sessionId, 'session-a');
  assert.equal(flushes[0].bypassExpectedActiveSessionGuard, true);
});


// Saved definitions only: empty steps, no sequence execution or request dispatch.
function installSequenceDraftPersistence(f) {
  for (const name of ['flushSequenceDraftBeforeExternalSessionReload', 'flushSequenceDraft', 'saveCurrentSequence']) {
    vm.runInContext(source(name), f.context);
  }
  f.context.syncSequenceStepFromDom = () => {};
  f.context.currentSequenceSessionId = () => f.context.currentSessionId();
  f.state.sequenceDirty = true; f.state.sequenceDraftVersion = 1;
  f.state.editingSequence = { id: 'definition-a', name: 'Stored A', steps: [] };
}
const staleWriteOptions = { sessionId: 'session-a', bypassExpectedActiveSessionGuard: true };
for (const change of ['owner', 'generation']) for (const versionChanged of [false, true]) {
  test(`saved-definition completion retains new ${change} and ${versionChanged ? 'changed' : 'equal'} draft version`, async () => {
    const f = setup(); installSequenceDraftPersistence(f);
    const pending = f.context.flushSequenceDraftBeforeExternalSessionReload(staleWriteOptions);
    assert.equal(f.requests.length, 1);
    const oldBody = JSON.parse(f.requests[0].options.body);
    assert.equal(oldBody.session_id, 'session-a'); assert.equal(oldBody.id, 'definition-a');
    assert.deepEqual(oldBody.steps, []);
    f.replace(change === 'owner' ? 'session-b' : 'session-a');
    const next = { id: 'definition-b', name: 'Stored B', steps: [] };
    f.state.editingSequence = next; f.state.sequenceDraftVersion = versionChanged ? 2 : 1;
    f.state.sequenceDirty = !versionChanged;
    f.succeed(0, {}); await tick();
    assert.equal(f.requests.length, 1, 'old options must never submit the next workspace definition');
    assert.equal(await pending, false);
    assert.equal(f.state.editingSequence, next); assert.equal(f.state.sequenceDirty, !versionChanged);
    assert.equal(f.state.sequenceDraftVersion, versionChanged ? 2 : 1);
  });
}
test('saved-definition external flush rejects an already-mismatched owner before any save', async () => {
  const f = setup(); installSequenceDraftPersistence(f); f.replace();
  const pending = f.context.flushSequenceDraftBeforeExternalSessionReload(staleWriteOptions);
  await tick();
  assert.equal(f.requests.length, 0); assert.equal(f.state.sequenceDirty, true);
  assert.equal(await pending, false);
});
for (const edited of [false, true]) test(`same-owner saved definition ${edited ? 'retries a newer edit' : 'finishes normally'}`, async () => {
  const f = setup(); installSequenceDraftPersistence(f);
  const pending = f.context.flushSequenceDraftBeforeExternalSessionReload(staleWriteOptions);
  if (edited) { f.state.editingSequence.name = 'Updated A'; f.state.sequenceDraftVersion += 1; }
  f.succeed(0, {}); await tick();
  if (edited) {
    assert.equal(f.requests.length, 2);
    const body = JSON.parse(f.requests[1].options.body);
    assert.equal(body.session_id, 'session-a'); assert.equal(body.id, 'definition-a');
    assert.equal(body.name, 'Updated A'); assert.deepEqual(body.steps, []);
    f.succeed(1, {});
  }
  assert.equal(await pending, true); assert.equal(f.state.sequenceDirty, false);
  assert.equal(f.requests.length, edited ? 2 : 1);
});
