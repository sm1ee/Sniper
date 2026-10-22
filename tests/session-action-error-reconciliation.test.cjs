// Passive saved-session metadata fixtures only. Production handlers are extracted
// without app startup; every fetch is a deferred local response, never network I/O.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { fixture } = require('./replay-workspace-fixture.cjs');
const { appSource } = require('./frontend-test-helpers.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
const session = (id, active = false) => ({ id, name: `Session ${id}`, active });
const originalMessage = 'Synthetic session finalization failed';

function setup() {
  const f = fixture();
  f.a = session('session-a', true); f.b = session('session-b'); f.c = session('session-c');
  f.state.activeSession = f.a; f.state.sessions = [f.a, f.b]; f.state.selectedSessionId = f.b.id;
  f.old = f.tab('saved-a'); f.seed([f.old]);
  f.reloads = []; f.errors = []; f.warnings = [];
  f.els.dashboardCreateSessionName = { value: 'New stored session' };
  for (const key of ['dashboardCurrentSessionName', 'dashboardCurrentSessionStorage', 'dashboardCurrentSessionPath',
    'dashboardSessionsBody']) f.els[key] = { querySelectorAll: () => [] };
  Object.assign(f.context, {
    sessionsLoadGeneration: 0, sessionsAppliedLoadGeneration: 0, resetFindingsUiState() {},
    requireOkResponse: async response => { if (!response.ok) throw new Error('Synthetic session read failed'); },
    flushTargetScopeDraft: async () => true, flushMatchReplaceDraft: async () => true,
    flushSequenceDraft: async () => true, flushAllPendingAnnotations: async () => {},
    cleanupWsReplayTabsBeforeStateReset: async () => {},
    reloadSessionWorkspace: async options => f.reloads.push(options),
    handleExternalSessionChanged: async () => { throw new Error('Reconciliation must not reload or save workspace'); },
    handleWorkspaceActionError: error => f.errors.push(error),
    showConfirmDialog: (_, cb) => { f.confirm = cb; },
    getSortedSessions: () => f.state.sessions, formatCappedCount: value => String(value ?? 0),
    retainedTransactionsCap() {}, retainedEntriesCap() {}, formatTimestamp: () => '-', escapeHtml: String,
    console: { error() {}, warn: (...args) => f.warnings.push(args) },
  });
  for (const name of ['createSession', 'activateSessionById', 'deleteSessionById', 'loadSessions',
    'reconcileSessionsAfterActionError', 'renderDashboard', 'toggleReplayTabPin', 'expectedActiveSessionIdForWrite']) {
    const source = appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, 'm'));
    // Keep the fixture behavioral: baseline handlers do not yet use this helper.
    if (!source && name === 'reconcileSessionsAfterActionError') continue;
    assert.ok(source, name); vm.runInContext(source[0], f.context);
  }
  f.fail = index => f.requests[index].resolve({ ok: false, status: 500, text: async () => originalMessage });
  return f;
}

// Returning a wrapper prevents async dispatch from adopting the action promise.
async function start(f, operation) {
  let pending;
  if (operation === 'create') pending = f.context.createSession();
  else if (operation === 'activate') pending = f.context.activateSessionById(f.b.id);
  else { await f.context.deleteSessionById(f.b.id); pending = f.confirm(); }
  const result = pending.catch(error => error);
  await tick();
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].options.method, operation === 'delete' ? 'DELETE' : 'POST');
  return { result };
}

function assertOriginalError(f, operation, result) {
  if (operation === 'delete') assert.ok(f.toasts.some(([message]) => message === originalMessage));
  else assert.equal(result.message, originalMessage);
}

for (const operation of ['create', 'activate', 'delete']) {
  test(`${operation} error reconciles committed rows without rebinding drafts or clearing conflicts`, async () => {
    const f = setup(), { result } = await start(f, operation);
    const owner = f.state.activeSession, tabs = f.state.replayTabs, baseline = f.context.workspaceSaveCommittedSnapshot;
    const conflict = { error: 'Synthetic existing workspace conflict' };
    f.old.requestText = 'GET /synthetic-unsaved-draft HTTP/1.1\r\nHost: example.com\r\n\r\n';
    const draft = f.old.requestText;
    f.els.replayRequestHighlight.innerText = 'Synthetic DOM-only draft';
    f.els.replayPortInput.value = '8x';
    f.context.workspaceSaveDirty = true; f.context.workspaceSaveConflictPending = true;
    f.context.workspaceSaveConflictLatest = conflict;
    f.fail(0); await tick();
    assert.equal(f.requests.length, 2); assert.equal(f.requests[1].url, '/api/sessions');
    assert.equal(f.requests[1].options, undefined, 'reconciliation is one read only');
    const rows = operation === 'create' ? [f.a, f.b, f.c]
      : operation === 'activate' ? [session('session-a'), session('session-b', true)] : [f.a];
    f.succeed(1, rows); assertOriginalError(f, operation, await result);
    assert.deepEqual(f.plain(f.state.sessions), rows);
    assert.equal(f.state.activeSession, owner); assert.equal(f.state.replayTabs, tabs);
    assert.equal(f.old.requestText, draft); assert.equal(f.state.workspaceRevision, 10);
    assert.equal(f.els.replayRequestHighlight.innerText, 'Synthetic DOM-only draft');
    assert.equal(f.els.replayPortInput.value, '8x');
    assert.equal(f.context.workspaceStateGeneration, 0); assert.equal(f.context.workspaceLoaded, true);
    assert.equal(f.context.workspaceSaveCommittedSnapshot, baseline);
    assert.equal(f.context.workspaceSaveConflictLatest, conflict); assert.equal(f.context.workspaceSaveConflictPending, true);
    assert.equal(f.context.workspaceSaveDirty, true); assert.equal(f.reloads.length, 0); assert.equal(f.requests.length, 2);
    if (operation === 'create') assert.equal(f.els.dashboardCreateSessionName.value, 'New stored session');
    if (operation === 'delete') assert.equal(f.state.selectedSessionId, 'session-a');
    if (operation === 'activate') {
      assert.match(f.toasts[0][0], /active session changed.*Keep a copy of unsaved edits.*Reload sessions/);
      assert.match(f.els.dashboardSessionsBody.innerHTML, /session-active" data-id="session-b"/);
    } else assert.match(f.toasts[0][0], /may have completed/);
  });

  for (const failure of ['network', 'body']) {
    test(`${operation} ${failure} failure reads rows once and preserves the original exception`, async () => {
      const f = setup(), { result } = await start(f, operation), original = new Error(originalMessage);
      if (failure === 'network') f.requests[0].reject(original);
      else f.requests[0].resolve({ ok: false, status: 500, text: async () => { throw original; } });
      await tick(); assert.equal(f.requests[1].url, '/api/sessions');
      f.succeed(1, [f.a, f.b]);
      const error = await result; assertOriginalError(f, operation, error);
      if (operation !== 'delete') assert.equal(error, original);
      assert.equal(f.requests.length, 2); assert.equal(f.reloads.length, 0);
    });
  }

  for (const failure of ['network', 'HTTP', 'JSON', 'shape']) {
    test(`${operation} reconciliation ${failure} failure preserves rows, drafts, and original error`, async () => {
      const f = setup(), { result } = await start(f, operation);
      const rows = f.state.sessions, owner = f.state.activeSession, tabs = f.state.replayTabs;
      f.fail(0); await tick();
      if (failure === 'network') f.requests[1].reject(new Error('Synthetic read unavailable'));
      if (failure === 'HTTP') f.requests[1].resolve({ ok: false });
      if (failure === 'JSON') f.requests[1].resolve({ ok: true, json: async () => { throw new Error('Synthetic bad JSON'); } });
      if (failure === 'shape') f.succeed(1, { error: 'Synthetic malformed list' });
      assertOriginalError(f, operation, await result);
      assert.equal(f.state.sessions, rows); assert.equal(f.state.activeSession, owner); assert.equal(f.state.replayTabs, tabs);
      assert.match(f.toasts[0][0], /may have completed.*could not be refreshed.*Keep a copy of unsaved edits.*Reload sessions/);
      assert.equal(f.warnings.length, 1); assert.equal(f.requests.length, 2); assert.equal(f.reloads.length, 0);
    });
  }

  for (const change of ['owner', 'generation']) {
    for (const phase of ['mutation', 'read']) {
      test(`${operation} old ${phase} completion cannot reconcile or announce after ${change} changes`, async () => {
        const f = setup(), { result } = await start(f, operation);
        if (phase === 'read') { f.fail(0); await tick(); assert.equal(f.requests.length, 2); }
        if (change === 'owner') f.state.activeSession = session('session-new', true);
        else f.context.workspaceStateGeneration += 1;
        const rows = [session('session-new', true)]; f.state.sessions = rows;
        if (phase === 'mutation') f.fail(0);
        else f.succeed(1, [f.a, f.b]);
        assertOriginalError(f, operation, await result);
        assert.equal(f.state.sessions, rows); assert.equal(f.reloads.length, 0);
        assert.equal(f.toasts.length, operation === 'delete' ? 1 : 0, 'only the original operation error may be reported');
        assert.equal(f.requests.length, phase === 'read' ? 2 : 1);
      });
    }
  }

  test(`${operation} normal success remains unchanged and does not reconcile an error`, async () => {
    const f = setup(), { result } = await start(f, operation);
    f.succeed(0, {}); assert.equal(await result, undefined);
    assert.equal(f.requests.length, 1); assert.equal(f.toasts.length, 0);
    assert.equal(f.reloads.length, operation === 'delete' ? 0 : 1);
    if (operation === 'create') assert.equal(f.els.dashboardCreateSessionName.value, '');
    if (operation === 'activate') assert.equal(f.state.selectedSessionId, 'session-b');
    if (operation === 'delete') {
      assert.equal(f.state.sessions.length, 1); assert.equal(f.state.selectedSessionId, 'session-a');
    }
  });
}

for (const newerMode of ['full', 'list-only']) {
  test(`newer accepted ${newerMode} list wins over the other mode's delayed response`, async () => {
    const f = setup(), owner = f.state.activeSession, tabs = f.state.replayTabs;
    const older = f.context.loadSessions({ preserveWorkspaceOwner: newerMode === 'full' });
    const newer = f.context.loadSessions({ preserveWorkspaceOwner: newerMode !== 'full' });
    const latest = [session('session-a', true), f.c];
    f.succeed(1, latest); await newer;
    const acceptedOwner = f.state.activeSession;
    f.succeed(0, [session('session-obsolete', true)]); await older;
    assert.deepEqual(f.plain(f.state.sessions), latest); assert.equal(f.state.activeSession, acceptedOwner);
    assert.equal(f.state.replayTabs, tabs); assert.equal(f.context.sessionsAppliedLoadGeneration, 2);
    if (newerMode === 'list-only') assert.equal(f.state.activeSession, owner);
  });
}

test('an awaited full list still applies while a newer list-only read is pending', async () => {
  const f = setup(), full = f.context.loadSessions();
  const listOnly = f.context.loadSessions({ preserveWorkspaceOwner: true });
  f.succeed(0, [session('session-a', true), f.c]); await full;
  const owner = f.state.activeSession;
  assert.equal(f.context.sessionsAppliedLoadGeneration, 1);
  f.succeed(1, [session('session-b', true)]); await listOnly;
  assert.equal(f.state.activeSession, owner); assert.equal(f.state.sessions[0].id, 'session-b');
});

test('reconciled active rows never change the saved-workspace owner or bypass its conflict guard', async () => {
  const f = setup(), { result } = await start(f, 'activate');
  f.fail(0); await tick(); f.succeed(1, [session('session-a'), session('session-b', true)]); await result;
  f.old.requestText = 'GET /unsaved-A HTTP/1.1\r\nHost: example.com\r\n\r\n';
  const draft = f.old.requestText;
  f.context.toggleReplayTabPin(f.old.id); await tick();
  const body = JSON.parse(f.requests[2].options.body);
  assert.equal(f.requests[2].url, '/api/workspace-state');
  assert.equal(body.session_id, 'session-a'); assert.equal(body.expected_active_session_id, 'session-a');
  f.requests[2].resolve({ ok: false, status: 409, json: async () => ({ error: 'active session changed', session_id: 'session-b' }) });
  await tick();
  assert.equal(f.old.requestText, draft); assert.equal(f.old.pinned, false);
  assert.equal(f.context.workspaceSaveConflictPending, true); assert.equal(f.context.workspaceSaveDirty, true);
  assert.equal(f.requests.length, 3); assert.equal(f.timers.size, 0);
  const retry = await f.context.activateSessionById('session-b').catch(error => error);
  assert.equal(retry.name, 'WorkspaceStateConflictError'); assert.equal(f.requests.length, 3);
});

test('busy activation confirmation retains its existing behavior without reconciliation', async () => {
  const f = setup(), { result } = await start(f, 'activate');
  f.requests[0].resolve({ ok: false, status: 409, text: async () => 'proxy activity is still running' });
  assert.equal(await result, undefined); assert.equal(typeof f.confirm, 'function');
  assert.equal(f.requests.length, 1); assert.equal(f.reloads.length, 0); assert.equal(f.toasts.length, 0);
});

for (const operation of ['create', 'activate']) {
  test(`${operation} preflight conflict cannot start mutation or reconciliation`, async () => {
    const f = setup(); f.context.workspaceSaveConflictPending = true;
    const error = await (operation === 'create' ? f.context.createSession() : f.context.activateSessionById(f.b.id)).catch(error => error);
    assert.equal(error.name, 'WorkspaceStateConflictError'); assert.equal(f.requests.length, 0); assert.equal(f.toasts.length, 0);
  });
  test(`${operation} successful mutation with failed normal reload is not reclassified as a mutation error`, async () => {
    const f = setup(), original = new Error('Synthetic workspace read failure');
    f.context.reloadSessionWorkspace = async () => { throw original; };
    const { result } = await start(f, operation); f.succeed(0, {});
    assert.equal(await result, original); assert.equal(f.requests.length, 1); assert.equal(f.toasts.length, 0);
  });
}

function installWorkspaceReload(f) {
  for (const name of ['reloadSessionWorkspace', 'loadSettings', 'loadWorkspaceState', 'retireFindingActionProgress', 'applyWorkspaceState']) {
    vm.runInContext(appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, 'm'))[0], f.context);
  }
  vm.runInContext(appSource.match(/^class WorkspaceSessionMismatchError[^]*?^\}/m)[0], f.context);
  // Execute production identity/reset prefixes while omitting unrelated panels.
  const resetStart = appSource.indexOf('function resetSessionScopedUiState() {');
  const resetEnd = appSource.indexOf('  clearHistoryBackfill();', resetStart);
  vm.runInContext(`${appSource.slice(resetStart, resetEnd)}\n}`, f.context);
  const settingsStart = appSource.indexOf('async function _applySettings(response) {');
  const settingsEnd = appSource.indexOf('  // Sync intercept scope pill', settingsStart);
  vm.runInContext(`${appSource.slice(settingsStart, settingsEnd)}\n}`, f.context);
  Object.assign(f.context, {
    syncHttpCapturePill() {}, clearReplaySendInFlight() {}, closeContextMenu() {}, refreshTimer: null,
    normalizeFuzzerAttackRecord: () => null, setFuzzerAttackRecord() {}, fuzzerWorkspaceAttackRecordId: () => null,
    loadTransactions: async () => {}, loadIntercepts: async () => {}, loadResponseIntercepts: async () => {},
    loadInterceptRules: async () => {}, loadWebsockets: async () => {}, loadEventLog: async () => {},
    loadMatchReplaceRules: async () => {}, loadSequences: async () => {}, loadTargetSiteMap: async () => {},
    refreshScannerQuickToggle: async () => {}, connectEvents() {}, renderToolPanels: () => f.syncDom(),
  });
  const bTab = f.tab('saved-b');
  f.workspaceB = f.remote([bTab], 3); f.workspaceB.session_id = 'session-b';
  f.appliedOwners = [];
  const apply = f.context.applyWorkspaceState;
  f.context.applyWorkspaceState = snapshot => {
    f.appliedOwners.push({ owner: f.context.currentSessionId(), snapshot: snapshot.session_id });
    return apply(snapshot);
  };
}

async function finishReloadReads(f, settingsIndex, settingsOwner = 'session-b') {
  assert.equal(f.requests[settingsIndex].url, '/api/settings');
  f.succeed(settingsIndex, { active_session: session(settingsOwner, true), runtime: {} }); await tick();
  assert.equal(f.requests[settingsIndex + 1].url, '/api/workspace-state');
  f.succeed(settingsIndex + 1, f.workspaceB); await tick();
  if (settingsOwner !== 'session-b') {
    assert.equal(f.requests[settingsIndex + 2].url, '/api/sessions', 'workspace mismatch must repair identity before applying');
    f.succeed(settingsIndex + 2, [session('session-a'), session('session-b', true)]); await tick();
  }
}

for (const settingsOwner of ['session-b', 'session-a']) {
  test(`full workspace reload stays correctly bound after newer list-only acceptance with settings ${settingsOwner}`, async () => {
    const f = setup(); installWorkspaceReload(f);
    const reload = f.context.reloadSessionWorkspace(); await tick();
    assert.equal(f.requests[0].url, '/api/sessions'); assert.equal(f.context.workspaceLoaded, false);
    const listOnly = f.context.loadSessions({ preserveWorkspaceOwner: true });
    f.succeed(1, [session('session-a'), session('session-b', true)]); await listOnly;
    assert.equal(f.state.activeSession.id, 'session-a', 'list-only acceptance must not retag the workspace');
    f.succeed(0, [session('session-a'), session('session-b', true)]); await tick();
    assert.equal(f.state.activeSession.id, 'session-a', 'older full list is superseded, so settings/workspace reads must resolve ownership');
    await finishReloadReads(f, 2, settingsOwner); await reload;
    assert.deepEqual(f.appliedOwners, [{ owner: 'session-b', snapshot: 'session-b' }]);
    assert.equal(f.state.activeSession.id, 'session-b'); assert.equal(f.context.workspaceLoaded, true);
    assert.equal(f.state.workspaceRevision, 3); assert.equal(f.state.replayTabs[0].customLabel, 'saved-b');
    assert.equal(f.context.workspaceSaveCommittedSnapshot.session_id, 'session-b');
    assert.ok(f.requests.every(request => request.options === undefined), 'reload composition must remain read-only in this fixture');
  });
}

test('newer full workspace reload supersedes list-only read without losing its new model or editor draft', async () => {
  const f = setup(); installWorkspaceReload(f);
  const listOnly = f.context.loadSessions({ preserveWorkspaceOwner: true });
  const reload = f.context.reloadSessionWorkspace(); await tick();
  assert.equal(f.requests[1].url, '/api/sessions');
  f.succeed(1, [session('session-a'), session('session-b', true)]); await tick();
  await finishReloadReads(f, 2); await reload;
  const tabs = f.state.replayTabs, baseline = f.context.workspaceSaveCommittedSnapshot;
  tabs[0].requestText = 'Synthetic new-session model draft';
  f.els.replayRequestHighlight.innerText = 'Synthetic new-session DOM-only draft';
  f.els.replayPortInput.value = '8x';
  f.context.workspaceSaveDirty = true;
  f.succeed(0, [session('session-a', true)]); await listOnly;
  assert.deepEqual(f.appliedOwners, [{ owner: 'session-b', snapshot: 'session-b' }]);
  assert.equal(f.state.activeSession.id, 'session-b'); assert.equal(f.state.sessions.find(s => s.active).id, 'session-b');
  assert.equal(f.state.replayTabs, tabs); assert.equal(tabs[0].requestText, 'Synthetic new-session model draft');
  assert.equal(f.els.replayRequestHighlight.innerText, 'Synthetic new-session DOM-only draft');
  assert.equal(f.els.replayPortInput.value, '8x'); assert.equal(f.context.workspaceSaveDirty, true);
  assert.equal(f.context.workspaceSaveCommittedSnapshot, baseline); assert.equal(f.requests.length, 4);
});
