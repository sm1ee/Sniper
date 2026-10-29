// Production full-workspace loading and shipped CodeMirror state/history.
// Only unrelated painters/reads and the browser view are synthetic; no traffic.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { editorFixture, source, CM } = require('./replay-editor-fixture.cjs');
const { appSource } = require('./frontend-test-helpers.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));

function fixture() {
  const f = editorFixture();
  const Base = f.context.CM.EditorView;
  f.context.CM.EditorView = class extends Base {
    constructor(options) { super(options); this.contentDOM.setAttribute = () => {}; }
  };
  function control() {
    return { value: '', listeners: {}, classList: { toggle() {}, add() {}, remove() {} },
      addEventListener(type, listener) { this.listeners[type] = listener; },
      cloneNode() { return control(); }, replaceWith() {}, focus() {},
      input(value) { this.value = value; this.listeners.input?.(); },
      setAttribute() {}, removeAttribute() {},
    };
  }
  f.control = control;
  Object.assign(f.els, { fuzzerRequestCM: {}, fuzzerPayloadsEditor: control(), fuzzerMeta: control(),
    startFuzzerButton: control(), resetFuzzerButton: control() });
  for (const name of [
    'renderFuzzerResultsWorkflow', 'renderFuzzerSetup', 'renderEmptyFuzzerResults',
    'wireFuzzerMarkerSelection', 'scheduleFuzzerSetupRender', 'retireFindingActionProgress',
    'createHistoryPagingState', 'createWebsocketPagingState', 'closeContextMenu',
    'clearHistoryBackfill', 'cancelHistoryDetailLoading', 'invalidateVisibleEntriesCache',
    'renderIntercepts', 'renderResponseIntercepts', 'renderInterceptRules', 'updateInterceptQueueBadges',
    'resetWebsocketFrameScroll', 'cancelWebsocketDetailLoading', 'clearWebsocketQueryBackfill',
    'clearFilteredWebsocketReload', 'clearWebsocketSearchReload', 'resetEventLogUiState',
    'resetOastUiState', 'resetScannerConfigUiState', 'resetFindingsUiState', 'clearFuzzerAttackRecord',
    'clearCompareState', 'renderHistory', 'renderEmptyDetail', 'renderWebsocketSessions', 'hideFrameDetail',
    'renderEventLog', 'renderMatchReplaceRules', 'renderTarget', 'renderFindings',
    'renderSequencePanel', 'renderReplayClearedState', 'clearReplaySendInFlight',
  ]) f.context[name] = () => {};
  for (const name of [
    'cleanupWsReplayTabsBeforeStateReset', 'loadSettings', 'loadTransactions', 'loadIntercepts',
    'loadResponseIntercepts', 'loadInterceptRules', 'loadWebsockets', 'loadEventLog',
    'loadMatchReplaceRules', 'loadSequences', 'loadTargetSiteMap', 'refreshScannerQuickToggle', 'connectEvents',
  ]) f.context[name] = async () => {};
  Object.assign(f.context, {
    refreshTimer: null, _incrementalTimer: 0, _transactionDeltaTimer: 0,
    _pendingTransactionSummaries: [], _historyDetailGeneration: 0, _websocketLoadGeneration: 0,
    _websocketDetailGeneration: 0, _websocketDetailPendingId: null, _websocketDetailPendingSessionId: null,
    _websocketDetailPendingPromise: null, _websocketDetailRefreshTimer: null,
    _websocketDetailRefreshNeeded: null, _websocketSummaryMutationGeneration: 0,
    _websocketSummaryMutationById: new Map(), _websocketSummaryEventTimer: null,
    _websocketSummaryEventBuffer: new Map(), _lastWebsocketFallbackPoll: 0, _lastWebsocketPageRefreshAt: 0,
  });
  for (const name of ['renderFuzzer', 'renderFuzzerPayloadsEditor', 'updateFuzzerRequestText',
    'updateFuzzerPayloadsText', 'markFuzzerDraftChanged', 'loadWorkspaceState',
    'applyWorkspaceState', 'reloadSessionWorkspace', 'resetSessionScopedUiState']) {
    vm.runInContext(source(name), f.context);
  }
  vm.runInContext(appSource.match(/^class WorkspaceSessionMismatchError[^]*?^\}/m)[0], f.context);
  f.context.loadSessions = async () => { f.state.activeSession = { id: 'session-b' }; };
  f.context.renderToolPanels = () => f.context.renderFuzzer();
  f.state.activeTool = 'fuzzer'; f.state.fuzzerPayloadsText = '';
  f.state.fuzzerRequestText = 'GET /old HTTP/1.1\nHost: example.com\n\n';
  f.cv = () => f.context.getCMView('fuzzerReq');
  f.render = () => f.context.renderFuzzer();
  f.render();
  f.snapshot = (text = '', payloads = '') => ({ session_id: 'session-b', revision: 20,
    replay: { tabs: [] }, fuzzer: { request_text: text, payloads_text: payloads } });
  f.begin = async () => {
    const pending = f.context.reloadSessionWorkspace({ cleanupBeforeReset: false });
    await tick(); f.render(); return { pending };
  };
  return f;
}

for (const text of ['', 'GET /saved HTTP/1.1\nHost: example.com\n\n']) {
  test(`full load blocks new-owner edits until ${text ? 'saved' : 'empty'} destination is adopted`, async () => {
    const f = fixture(), { pending } = await f.begin();
    assert.equal(f.state.activeSession.id, 'session-b'); assert.equal(f.context.workspaceLoaded, false);
    assert.equal(f.cv().view.state.facet(CM.EditorState.readOnly), true);
    assert.equal(f.els.fuzzerPayloadsEditor.disabled, true);
    assert.equal(f.els.startFuzzerButton.disabled, true); assert.equal(f.els.resetFuzzerButton.disabled, true);
    assert.match(f.els.fuzzerMeta.textContent, /Loading session/);
    // A synthetic dispatch bypasses browser readOnly; callbacks must still reject it.
    f.edit(0, 0, 'attempted request'); f.els.fuzzerPayloadsEditor.input('attempted payload');
    assert.equal(f.state.fuzzerRequestText, ''); assert.equal(f.state.fuzzerPayloadsText, '');
    assert.equal(f.context.workspaceSaveDirty, false);
    f.succeed(0, f.snapshot(text)); await pending;
    assert.equal(f.context.workspaceLoaded, true); assert.equal(f.cv().getContent(), text);
    assert.equal(f.cv().view.state.facet(CM.EditorState.readOnly), false);
    assert.equal(f.els.fuzzerPayloadsEditor.disabled, false);
    assert.equal(CM.undo(f.cv().view), false);
    f.edit(0, 0, 'new '); assert.equal(f.state.fuzzerRequestText, `new ${text}`);
    assert.equal(CM.undo(f.cv().view), true); assert.equal(f.state.fuzzerRequestText, text);
    f.els.fuzzerPayloadsEditor.input('fresh'); assert.equal(f.state.fuzzerPayloadsText, 'fresh');
  });
}

test('readOnly transition is applied even with identical owner and text', () => {
  const f = fixture(), owner = f.cv()._owner, text = f.state.fuzzerRequestText;
  f.context.workspaceLoaded = false; f.render();
  assert.equal(f.cv()._owner, owner); assert.equal(f.cv().getContent(), text);
  assert.equal(f.cv().view.state.facet(CM.EditorState.readOnly), true);
  f.context.workspaceLoaded = true; f.render();
  assert.equal(f.cv().view.state.facet(CM.EditorState.readOnly), false);
  f.edit(0, 0, 'new '); assert.equal(CM.undo(f.cv().view), true);
});

test('failed full load remains unavailable with failure notice and successful retry restores editors', async () => {
  const f = fixture(), { pending } = await f.begin();
  const rejected = assert.rejects(pending, /Could not load session workspace/);
  f.requests[0].resolve({ ok: false, text: async () => 'synthetic load failure' }); await rejected;
  assert.equal(f.context.workspaceLoaded, false);
  assert.equal(f.cv().view.state.facet(CM.EditorState.readOnly), true);
  assert.equal(f.els.fuzzerPayloadsEditor.disabled, true);
  assert.doesNotMatch(f.els.fuzzerMeta.textContent, /^Loading session/);
  assert.match(f.els.fuzzerMeta.textContent, /load|unavailable|failed/i);
  const retry = await f.begin();
  assert.match(f.els.fuzzerMeta.textContent, /Loading session/);
  f.succeed(1, f.snapshot()); await retry.pending;
  assert.equal(f.context.workspaceLoaded, true);
  assert.equal(f.cv().view.state.facet(CM.EditorState.readOnly), false);
  assert.equal(f.els.fuzzerPayloadsEditor.disabled, false);
});

test('adoption restores editing before unrelated later history read fails', async () => {
  const f = fixture(); f.context.loadTransactions = async () => { throw new Error('history failed'); };
  const { pending } = await f.begin(), rejected = assert.rejects(pending, /history failed/);
  f.succeed(0, f.snapshot()); await rejected;
  assert.equal(f.context.workspaceLoaded, true);
  assert.equal(f.cv().view.state.facet(CM.EditorState.readOnly), false);
  assert.equal(f.els.fuzzerPayloadsEditor.disabled, false);
});

test('retired pre-load callbacks cannot change newly loaded destination', async () => {
  const f = fixture(), old = f.cv(), payload = f.els.fuzzerPayloadsEditor;
  const listeners = old.view.state.facet(CM.EditorView.updateListener);
  const { pending } = await f.begin(); f.succeed(0, f.snapshot()); await pending;
  for (const listener of listeners) listener({ view: old.view, state: old.view.state, docChanged: true });
  payload.input('stale payload');
  assert.equal(f.state.fuzzerRequestText, ''); assert.equal(f.state.fuzzerPayloadsText, '');
});

test('same-session background refresh keeps editors available and native Undo history', async () => {
  const f = fixture(); f.state.activeSession = { id: 'session-b' }; f.render();
  f.seed([]); const cv = f.cv(), initial = f.state.fuzzerRequestText;
  f.edit(0, 0, 'local '); const refresh = f.context.adoptExternalWorkspace();
  assert.equal(f.context.workspaceLoaded, true); f.render();
  assert.equal(f.cv(), cv); assert.equal(f.cv().view.state.facet(CM.EditorState.readOnly), false);
  assert.equal(f.els.fuzzerPayloadsEditor.disabled, false);
  f.succeed(0, f.remote([], 21)); await refresh; f.render();
  assert.equal(f.cv(), cv); assert.equal(CM.undo(cv.view), true);
  assert.equal(f.state.fuzzerRequestText, initial);
});


test('loading setup disables marker, file, preset, range, options and Start controls', () => {
  const f = fixture(), nodes = {};
  const controls = ['startFuzzerButton', 'fuzzerCandidateSelect', 'fuzzerAttackType',
    'fuzzerUrlEncode', 'fuzzerConcurrency', 'fuzzerMarkSelectionButton', 'fuzzerClearMarkersButton',
    'fuzzerMarkCandidateButton', 'fuzzerImportPayloadButton', 'fuzzerApplyPresetButton',
    'fuzzerGenerateRangeButton', 'fuzzerRemoveMarkerButton', 'fuzzerUndoMarkerButton',
    'fuzzerPayloadFile', 'fuzzerPayloadImportMode', 'fuzzerPayloadPreset',
    'fuzzerRangeStart', 'fuzzerRangeEnd', 'fuzzerRangeStep'];
  for (const id of [...controls, 'fuzzerPreflightSummary', 'fuzzerPreflightNotice']) nodes[id] = f.control();
  Object.assign(f.context, {
    fuzzerSetupNode: id => nodes[id] || null, renderFuzzerPayloadImportStatus() {},
    fuzzerRequestTextForAction: () => f.state.fuzzerRequestText,
    parseFuzzerRequestTemplate: () => ({}),
    fuzzerSetupPreflight: () => ({ valid: true, markerCount: 1, payloadCount: 1, requestCount: 1, warnings: [], errors: [] }),
    fuzzerPayloadCount: () => 1, escapeHtml: value => value,
    SniperFuzzerWorkflow: { candidates: () => [{ label: 'value' }], clearRequestPositions: () => 'clear' },
    fuzzerMarkerRemoval: () => ({ text: 'remove' }),
  });
  for (const name of ['renderFuzzerSetup', 'renderFuzzerRemoveMarkerControl']) vm.runInContext(source(name), f.context);
  f.context.workspaceLoaded = false; f.context.renderFuzzerSetup();
  for (const id of controls) assert.equal(nodes[id].disabled, true, id);
  assert.match(nodes.fuzzerPreflightNotice.textContent + nodes.fuzzerPreflightSummary.textContent, /Loading session/);
});

for (const [name, args] of [
  ['resetFuzzer', []], ['runFuzzerAttack', []],
  ['markFuzzerPosition', [0, 1, '']], ['removeFuzzerEditorPosition', []],
  ['clearFuzzerMarkers', []], ['undoFuzzerMarker', []],
  ['applyFuzzerPayloadList', [['attempted'], 'replace']],
  ['importFuzzerPayloadFile', [{ size: 1, arrayBuffer() { throw new Error('file read must not begin'); } }]],
  ['openFuzzerFromRecord', [{ kind: 'http', id: 'synthetic' }]],
  ['openFuzzerFromRecordLoader', [() => { throw new Error('record read must not begin'); }, () => true, () => { throw new Error('record apply must not begin'); }]],
  ['updateFuzzerRequestText', ['attempted request', { userEdit: true }]],
  ['updateFuzzerPayloadsText', ['attempted payload', { userEdit: true }]],
]) test(`direct ${name} cannot mutate or start work while full workspace is unavailable`, async () => {
  const f = fixture(); vm.runInContext(source(name), f.context);
  f.context.workspaceLoaded = false;
  const before = JSON.stringify(f.state), version = f.context.workspaceSaveVersion;
  try { await f.context[name](...args); }
  catch (error) { assert.match(error.message, /loading|load.*session|workspace.*(ready|available)|session.*(ready|available)/i); }
  assert.equal(JSON.stringify(f.state), before);
  assert.equal(f.context.workspaceSaveVersion, version);
  assert.equal(f.requests.length, 0);
});


for (const name of ['loadSessions', 'loadSettings']) test(`${name} failure before workspace fetch does not leave a permanent loading notice`, async () => {
  const f = fixture();
  f.context[name] = async () => { throw new Error('synthetic pre-load failure'); };
  await assert.rejects(f.context.reloadSessionWorkspace({ cleanupBeforeReset: false }), /synthetic pre-load failure/);
  assert.equal(f.requests.length, 0); assert.equal(f.context.workspaceLoaded, false);
  assert.equal(f.cv().view.state.facet(CM.EditorState.readOnly), true);
  assert.equal(f.els.fuzzerPayloadsEditor.disabled, true);
  assert.doesNotMatch(f.els.fuzzerMeta.textContent, /^Loading session/);
  assert.match(f.els.fuzzerMeta.textContent, /load|unavailable|failed/i);
});

function replaceWithSessionA(f, { loaded = true } = {}) {
  f.context.resetSessionScopedUiState();
  f.state.activeSession = { id: 'session-a' };
  if (loaded) {
    f.context.applyWorkspaceState({ session_id: 'session-a', revision: 40, replay: { tabs: [] },
      fuzzer: { request_text: 'GET /new-a HTTP/1.1', payloads_text: 'new-a-payload' } });
    f.context.workspaceLoaded = true;
  }
  f.render();
}

for (const outcome of ['success', 'error']) {
  for (const loaded of [true, false]) test(`late B workspace ${outcome} cannot replace ${loaded ? 'loaded' : 'loading'} A`, async () => {
    const f = fixture(), { pending } = await f.begin();
    replaceWithSessionA(f, { loaded });
    const before = JSON.stringify(f.state), view = f.cv(), notice = f.els.fuzzerMeta.textContent;
    if (outcome === 'success') f.succeed(0, f.snapshot('GET /late-b HTTP/1.1', 'late-b'));
    else f.requests[0].reject(new Error('late B failure'));
    await pending;
    assert.equal(f.state.activeSession.id, 'session-a'); assert.equal(JSON.stringify(f.state), before);
    assert.equal(f.context.workspaceLoaded, loaded); assert.equal(f.cv(), view);
    assert.equal(f.els.fuzzerMeta.textContent, notice); assert.equal(f.requests.length, 1);
  });
}

for (const phase of ['sessions', 'settings']) test(`late decoded B ${phase} cannot relabel or continue loading after A takes ownership`, async () => {
  const f = fixture();
  if (phase === 'sessions') {
    vm.runInContext(source('loadSessions'), f.context);
    Object.assign(f.context, { sessionsLoadGeneration: 0, sessionsAppliedLoadGeneration: 0,
      requireOkResponse: async () => {}, renderDashboard() {} });
  } else {
    vm.runInContext(source('loadSettings'), f.context);
    vm.runInContext(source('_applySettings'), f.context);
  }
  const { pending } = await f.begin();
  assert.equal(f.requests[0].url, phase === 'sessions' ? '/api/sessions' : '/api/settings');
  let decode;
  f.requests[0].resolve({ ok: true, json: () => new Promise(resolve => { decode = resolve; }) });
  await tick(); assert.equal(typeof decode, 'function');
  replaceWithSessionA(f); const before = JSON.stringify(f.state), view = f.cv();
  decode(phase === 'sessions' ? [{ id: 'session-b', name: 'B', active: true }]
    : { active_session: { id: 'session-b' }, runtime: {} });
  await tick();
  assert.equal(JSON.stringify(f.state), before); assert.equal(f.requests.length, 1);
  await pending;
  assert.equal(JSON.stringify(f.state), before); assert.equal(f.cv(), view); assert.equal(f.requests.length, 1);
});

test('inline retry deduplicates clicks and restores a failed workspace', async () => {
  const f = fixture(); vm.runInContext(source('retryFuzzerWorkspaceLoad'), f.context);
  f.context.workspaceLoaded = false; f.state.workspaceLoadError = 'Could not load session. Editing is unavailable.';
  f.render();
  const first = f.context.retryFuzzerWorkspaceLoad();
  const second = f.context.retryFuzzerWorkspaceLoad(); await tick();
  assert.equal(f.requests.length, 1);
  f.succeed(0, f.snapshot()); await first; await second;
  assert.equal(f.context.workspaceLoaded, true); assert.equal(f.state.workspaceLoadError, '');
  assert.equal(f.cv().view.state.facet(CM.EditorState.readOnly), false);
});

test('late inline retry cleanup cannot disable or relabel replacement A', async () => {
  const f = fixture(); vm.runInContext(source('retryFuzzerWorkspaceLoad'), f.context);
  f.context.workspaceLoaded = false; f.state.workspaceLoadError = 'Could not load session. Editing is unavailable.';
  f.render(); const pending = f.context.retryFuzzerWorkspaceLoad(); await tick();
  replaceWithSessionA(f); const before = JSON.stringify(f.state), view = f.cv();
  f.requests[0].reject(new Error('late retry failure')); await pending;
  assert.equal(JSON.stringify(f.state), before); assert.equal(f.cv(), view);
  assert.equal(f.context.workspaceLoaded, true);
});

for (const phase of ['sessions', 'settings']) test(`late B ${phase} transport failure cannot mark or retry over loading A`, async () => {
  const f = fixture();
  if (phase === 'sessions') {
    vm.runInContext(source('loadSessions'), f.context);
    Object.assign(f.context, { sessionsLoadGeneration: 0, sessionsAppliedLoadGeneration: 0,
      requireOkResponse: async () => {}, renderDashboard() {} });
  } else {
    vm.runInContext(source('loadSettings'), f.context);
    vm.runInContext(source('_applySettings'), f.context);
  }
  const { pending } = await f.begin();
  replaceWithSessionA(f, { loaded: false });
  const before = JSON.stringify(f.state), generation = f.context.workspaceStateGeneration;
  f.requests[0].reject(new Error('obsolete read failed')); await pending;
  assert.equal(JSON.stringify(f.state), before); assert.equal(f.requests.length, 1);
  assert.equal(f.context.workspaceStateGeneration, generation); assert.equal(f.context.workspaceLoaded, false);
});

for (const outcome of ['success', 'error']) test(`B→A→B keeps newer B when original B workspace ${outcome} arrives`, async () => {
  const f = fixture(), old = await f.begin();
  replaceWithSessionA(f);
  const newer = await f.begin();
  f.succeed(1, f.snapshot('GET /newer-b HTTP/1.1', 'newer-b')); await newer.pending;
  const before = JSON.stringify(f.state), generation = f.context.workspaceStateGeneration, view = f.cv();
  if (outcome === 'success') f.succeed(0, f.snapshot('GET /obsolete-b HTTP/1.1', 'obsolete-b'));
  else f.requests[0].reject(new Error('obsolete B failed'));
  await old.pending;
  assert.equal(JSON.stringify(f.state), before); assert.equal(f.cv(), view);
  assert.equal(f.context.workspaceStateGeneration, generation); assert.equal(f.context.workspaceLoaded, true);
  assert.equal(f.requests.length, 2);
});

test('only the latest concurrent full reload may advance the adopted workspace owner', async () => {
  const f = fixture(), old = await f.begin(), newer = await f.begin();
  const generation = f.context.workspaceStateGeneration;
  f.succeed(0, f.snapshot('GET /obsolete HTTP/1.1')); await old.pending;
  assert.equal(f.context.workspaceStateGeneration, generation);
  assert.equal(f.context.workspaceLoaded, false); assert.equal(f.state.fuzzerRequestText, '');
  f.succeed(1, f.snapshot('GET /accepted HTTP/1.1')); await newer.pending;
  assert.equal(f.context.workspaceStateGeneration, generation + 1);
  assert.equal(f.context.workspaceLoaded, true); assert.equal(f.state.fuzzerRequestText, 'GET /accepted HTTP/1.1');
});

test('startup workspace read without a full reload keeps inputs gated until adoption', async () => {
  const f = fixture(); f.context.workspaceLoaded = false;
  f.state.fuzzerRequestText = ''; f.state.fuzzerPayloadsText = ''; f.render();
  assert.equal(f.cv().view.state.facet(CM.EditorState.readOnly), true);
  assert.equal(f.els.fuzzerPayloadsEditor.disabled, true);
  const pending = f.context.loadWorkspaceState();
  const snapshot = f.snapshot('GET /startup HTTP/1.1'); snapshot.session_id = 'session-a';
  f.succeed(0, snapshot); await pending;
  assert.equal(f.context.workspaceLoaded, true); assert.equal(f.cv().getContent(), 'GET /startup HTTP/1.1');
  assert.equal(f.cv().view.state.facet(CM.EditorState.readOnly), false);
  assert.equal(f.els.fuzzerPayloadsEditor.disabled, false);
});

for (const fullReload of [false, true]) test(`${fullReload ? 'full reload' : 'direct load'} propagates own adoption failure after generation advances`, async () => {
  const f = fixture(), failure = new Error('synthetic own adoption failure');
  const apply = f.context.applyWorkspaceState;
  f.context.applyWorkspaceState = snapshot => { apply(snapshot); throw failure; };
  let pending;
  if (fullReload) ({ pending } = await f.begin());
  else {
    f.context.workspaceLoaded = false; f.state.activeSession = { id: 'session-b' }; f.render();
    pending = f.context.loadWorkspaceState();
  }
  const generation = f.context.workspaceStateGeneration;
  const rejected = assert.rejects(pending, error => error === failure);
  f.succeed(0, f.snapshot()); await rejected;
  assert.equal(f.context.workspaceStateGeneration, generation + 1);
  assert.equal(f.context.workspaceLoaded, false);
  assert.match(f.state.workspaceLoadError, /could not load|unavailable/i);
  assert.match(f.els.fuzzerMeta.textContent, /could not load|unavailable/i);
  assert.equal(f.cv().view.state.facet(CM.EditorState.readOnly), true);
  assert.equal(f.els.fuzzerPayloadsEditor.disabled, true);
});

for (const fullReload of [false, true]) test(`${fullReload ? 'full reload' : 'direct load'} propagates own post-adoption render failure without disabling adopted workspace`, async () => {
  const f = fixture(), failure = new Error('synthetic own render failure');
  let pending;
  if (fullReload) ({ pending } = await f.begin());
  else {
    f.context.workspaceLoaded = false; f.state.activeSession = { id: 'session-b' }; f.render();
    pending = f.context.loadWorkspaceState();
  }
  const render = f.context.renderFuzzer;
  f.context.renderFuzzer = () => { render(); if (f.context.workspaceLoaded) throw failure; };
  const rejected = assert.rejects(pending, error => error === failure);
  f.succeed(0, f.snapshot('GET /adopted HTTP/1.1')); await rejected;
  assert.equal(f.context.workspaceLoaded, true); assert.equal(f.state.workspaceLoadError, '');
  assert.equal(f.cv().getContent(), 'GET /adopted HTTP/1.1');
  assert.equal(f.cv().view.state.facet(CM.EditorState.readOnly), false);
  assert.equal(f.els.fuzzerPayloadsEditor.disabled, false);
});

test('startup workspace fetch failure stays unavailable and default-call retry restores editing', async () => {
  const f = fixture(); f.context.workspaceLoaded = false; f.render();
  const first = f.context.loadWorkspaceState(), failure = new Error('startup fetch failed');
  const rejected = assert.rejects(first, error => error === failure);
  f.requests[0].reject(failure); await rejected;
  assert.equal(f.context.workspaceLoaded, false);
  assert.match(f.els.fuzzerMeta.textContent, /could not load|unavailable/i);
  assert.equal(f.cv().view.state.facet(CM.EditorState.readOnly), true);
  assert.equal(f.els.fuzzerPayloadsEditor.disabled, true);
  const retry = f.context.loadWorkspaceState();
  assert.equal(f.state.workspaceLoadError, ''); assert.match(f.els.fuzzerMeta.textContent, /Loading session/);
  const snapshot = f.snapshot('GET /startup-retry HTTP/1.1'); snapshot.session_id = 'session-a';
  f.succeed(1, snapshot); await retry;
  assert.equal(f.context.workspaceLoaded, true); assert.equal(f.state.workspaceLoadError, '');
  assert.equal(f.cv().getContent(), 'GET /startup-retry HTTP/1.1');
  assert.equal(f.cv().view.state.facet(CM.EditorState.readOnly), false);
  assert.equal(f.els.fuzzerPayloadsEditor.disabled, false);
});

test('reset between synchronous adoption and reload continuation cannot be blessed as the old reload owner', async () => {
  const f = fixture(), load = f.context.loadWorkspaceState, later = [];
  let replacementState, replacementView, replacementGeneration;
  for (const name of ['loadTransactions', 'loadIntercepts', 'loadResponseIntercepts', 'loadInterceptRules',
    'loadWebsockets', 'loadEventLog', 'loadMatchReplaceRules', 'loadSequences', 'loadTargetSiteMap',
    'refreshScannerQuickToggle', 'connectEvents', 'renderToolPanels']) {
    f.context[name] = () => { later.push(name); };
  }
  f.context.loadWorkspaceState = async options => {
    const adopted = await load(options);
    // onAdopt already advanced B's owner synchronously. Before its awaiting
    // reload resumes, another owner replaces the workspace in this microtask.
    replaceWithSessionA(f);
    replacementState = JSON.stringify(f.state); replacementView = f.cv();
    replacementGeneration = f.context.workspaceStateGeneration;
    return adopted;
  };
  const { pending } = await f.begin();
  f.succeed(0, f.snapshot('GET /adopted-b HTTP/1.1'));
  assert.equal(await pending, false);
  assert.deepEqual(later, []);
  assert.equal(JSON.stringify(f.state), replacementState); assert.equal(f.cv(), replacementView);
  assert.equal(f.context.workspaceStateGeneration, replacementGeneration);
  assert.equal(f.state.activeSession.id, 'session-a'); assert.equal(f.context.workspaceLoaded, true);
});

for (const path of ['startup', 'full reload']) test(`${path} HTTP failure never exposes raw workspace response through the thrown error or local notice`, async () => {
  const f = fixture(); f.context.workspaceLoaded = false;
  const pending = path === 'startup' ? f.context.loadWorkspaceState() : (await f.begin()).pending;
  const raw = '{"error":"<script>malicious-marker</script>","request":"Authorization: secret-fixture-marker"}';
  let bodyReads = 0;
  const rejected = assert.rejects(pending, error => {
    assert.equal(error.message, 'Could not load session workspace.');
    assert.doesNotMatch(error.message, /malicious-marker|secret-fixture-marker|Authorization/);
    return true;
  });
  f.requests[0].resolve({ ok: false, status: 503, text: async () => { bodyReads++; return raw; } });
  await rejected;
  assert.equal(bodyReads, 0);
  assert.equal(f.context.workspaceLoaded, false);
  assert.doesNotMatch(f.els.fuzzerMeta.textContent, /malicious-marker|secret-fixture-marker|Authorization/);
  assert.match(f.els.fuzzerMeta.textContent, /Could not load session/);
});
