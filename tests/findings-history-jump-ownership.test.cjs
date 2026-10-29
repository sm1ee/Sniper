// Passive Findings-to-History navigation regressions. Extract production functions without app bootstrap.
// No browser, native process, server, sockets, API writes, scanner, or real traffic.
const assert = require('node:assert/strict');
const vm = require('node:vm');
const test = require('node:test');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const response = body => ({ ok: true, json: async () => body });
const record = { id: 'saved-old', sequence: 4, method: 'GET', host: 'example.com', path: '/saved' };
const finding = { id: 'finding-a', record_id: record.id, host: record.host, path: record.path, severity: 'info', category: 'header', title: 'Saved finding' };
const page = { items: [record], total: 100, filtered_total: 100, has_more: true };
function element(id) {
  const classes = new Set();
  return { dataset: { proxyTab: id }, listeners: {}, disabled: false,
    classList: { contains: value => classes.has(value), add: value => classes.add(value), remove: value => classes.delete(value),
      toggle(value, enabled) { if (enabled) classes.add(value); else classes.delete(value); } },
    focus() {},
    addEventListener(name, handler) { this.listeners[name] = handler; },
    click() { if (!this.disabled) this.listeners.click?.({}); } };
}
function fixture() {
  const reads = [], toasts = [], rendered = [], errors = [], findingLoads = [], paints = [], focuses = [];
  const timers = new Map(); let timerId = 0;
  const state = { activeSession: { id: 'session-a' }, activeTool: 'proxy', activeProxyTab: 'findings',
    selectedId: null, selectedRecord: null, sortKey: 'index', sortDirection: 'desc', filterSettings: {},
    items: [{ id: 'recent', sequence: 100 }], _itemsVersion: 0, historyPaging: { generation: 0, pageSize: 500, loading: false },
    historyDirty: false };
  const els = { findingsDetailJump: element(), findingsBody: element(), historyMeta: element(), liveStatus: element(), historyTableBody: element(), searchInput: element() };
  els.historyMeta.textContent = 'Newer history'; els.liveStatus.textContent = 'Live';
  els.liveStatus.classList.add('online'); els.findingsBody.querySelector = () => null;
  els.findingsDetailJump.dataset.recordId = record.id;
  for (const name of ['proxyShell', 'colorTagFilter', 'filterBar', 'trafficRegion', 'historyWorkbenchResizer',
    'lowerWorkbench', 'interceptPanel', 'websocketPanel', 'matchReplacePanel', 'findingsPanel', 'proxySettingsPanel', 'proxySubPlaceholder']) els[name] = element();
  const proxyTabs = ['findings', 'http-history'].map(element);
  const names = ['jumpToTransaction', 'loadTransactionDetail', 'ensureHistoryWindowContainsRecord', 'fetchTransactionPage',
    'sequenceCursorAfter', 'canUseSequenceCursorForHistoryPaging', 'clearHistoryBackfill', 'replaceHistoryItemsForGap',
    'applyPendingAnnotationsToItems', 'getHistoryItem', 'rebuildHistoryItemIndex', 'moveHistorySelectionIfMissing',
    'refreshHistoryPagingCursorFromItems', 'updateHistoryPagingCursor', 'createHistoryQueryState', 'historyQuerySignature',
    'isCurrentHistoryQuerySignature', 'buildTransactionsPageUrl', 'selectedStatusClasses', 'selectedMimeTypes', 'jsonArray',
    'currentSessionId', 'sessionQueryPath', 'transactionPath', 'setActiveTool', 'setActiveProxyTab',
    'invalidateFindingNavigation', 'retireFindingActionProgress', 'renderProxyPanels', 'loadFindings', 'fetchFindingsCount',
    'commitFindingsBadgeCount', 'renderFindings', 'getFilteredFindings', 'updateCategoryFilter',
    'resetSessionScopedUiState', 'applyWorkspaceState', 'workspaceSnapshotMatchesActiveSession', 'createHistoryPagingState',
    'resetFindingsUiState', 'clearFindingDetail', 'setFindingDetailActionsEnabled', 'updateFindingsSelection',
    'selectHistoryTransaction', 'canReuseSelectedHistoryRecord', 'historyRecordSummarySignature', 'clearHttpHistorySelectionPreview',
    'toggleSort'];
  const c = loadFunctions(names, { state, els, proxyTabs, workspaceLoaded: true, workspaceStateGeneration: 7, _historyDetailGeneration: 0,
    _historyPagingGeneration: 0, _historyBackfillTimer: 0, HTTP_HISTORY_PAGE_SIZE: 500, URLSearchParams,
    findingsData: [finding], selectedFindingId: finding.id, findingsLoadPromise: null, findingsLoadSessionId: null,
    findingsStateGeneration: 0, findingsLoadGeneration: 0, findingsCountReadGeneration: 0,
    findingsCountAcceptedGeneration: 0, findingsEventEpoch: 0, findingsBadgeCount: 1, FINDINGS_LIST_LIMIT: 5000,
    findingsSortKey: 'found_at', findingsSortDir: 'desc', SEVERITY_ORDER: {}, findingsDetailGeneration: 0,
    findingsBadgeRefreshTimer: 0, findingsListRefreshTimer: 0, lastFindingsBadgePollAt: 0,
    refreshTimer: null, workspaceSaveTimer: null, wsTranscriptSaveTimer: null,
    _incrementalTimer: 0, _transactionDeltaTimer: 0, _pendingTransactionSummaries: [],
    _websocketLoadGeneration: 0, _websocketDetailGeneration: 0, _websocketDetailRefreshTimer: null,
    _websocketSummaryMutationGeneration: 0, _websocketSummaryMutationById: new Map(),
    _websocketSummaryEventTimer: 0, _websocketSummaryEventBuffer: new Map(),
    window: { clearTimeout: id => timers.delete(id) }, clearTimeout: id => timers.delete(id),
    setTimeout(callback) { timers.set(++timerId, callback); return timerId; },
    getCMView: () => null, resetFindingsSearchUi() {}, dismissWorkspaceConflictNotice() {}, refreshHistoryFindings() {},
    defaultSortDirection: key => key === 'index' ? 'desc' : 'asc',
    updateHistorySelection() {}, scrollSelectedHistoryRowIntoView() {},
    scheduleRefresh() { paints.push('schedule refresh'); },
    readFuzzerWorkspace: () => ({}), applyFuzzerWorkspace() {}, snapshotWorkspaceState: () => ({}),
    cloneWorkspaceSnapshotForBaseline: value => value,
    console: { error: (...args) => errors.push(args) }, document: { getElementById: () => null },
    sanitizeActiveTool: value => value, sanitizeActiveProxyTab: value => value,
    closeScannerSettings() {}, scheduleUiSettingsSave() {}, renderToolPanels() { c.renderProxyPanels(); },
    renderFindingsVirtual() {}, updateFindingsBadge() {},
    scheduleHistoryDetailLoading() {}, observeAnnotationRevision() {}, renderDetail: value => rendered.push(value.id),
    renderEmptyDetail: () => rendered.push('EMPTY'), renderHistory() { paints.push('history'); }, focusHistoryRecord(id) { focuses.push(id); },
    prepareHistoryItem() {}, invalidateVisibleEntriesCache() {},
    showToast: message => toasts.push(message),
    fetch(url, options) {
      assert.equal(options, undefined, 'No writes are permitted; all fetches are fake GET reads.');
      if (url.startsWith('/api/findings')) {
        findingLoads.push(url);
        return Promise.resolve(response(url.includes('/count?') ? { count: 1 } : [finding]));
      }
      const read = { url, ...deferred() }; reads.push(read); return read.promise;
    },
  });
  // Run the complete initialized session reset; only unrelated painters are inert.
  for (const name of ['clearReplaySendInFlight', 'closeContextMenu', 'cancelHistoryDetailLoading',
    'renderIntercepts', 'renderResponseIntercepts', 'renderInterceptRules', 'updateInterceptQueueBadges',
    'createWebsocketPagingState', 'resetWebsocketFrameScroll', 'cancelWebsocketDetailLoading', 'clearWebsocketQueryBackfill',
    'clearFilteredWebsocketReload', 'clearWebsocketSearchReload', 'resetEventLogUiState', 'resetOastUiState',
    'resetScannerConfigUiState', 'clearFuzzerAttackRecord', 'clearCompareState', 'renderWebsocketSessions',
    'hideFrameDetail', 'renderEventLog', 'renderMatchReplaceRules', 'renderTarget', 'renderReplayClearedState',
    'renderFuzzer', 'renderSequencePanel']) c[name] = () => {};
  c.rebuildHistoryItemIndex();
  const jumpStart = appSource.indexOf('  if (els.findingsDetailJump) {', appSource.indexOf('function bindFindingsEvents()'));
  const jumpEnd = appSource.indexOf('  const findingsReplayBtn =', jumpStart);
  assert.ok(jumpStart >= 0 && jumpEnd > jumpStart);
  vm.runInContext(appSource.slice(jumpStart, jumpEnd), c);
  const navStart = appSource.indexOf('  proxyTabs.forEach((tab) => {', appSource.indexOf('function bindEvents()'));
  const navEnd = appSource.indexOf('\n  });', navStart) + '\n  });'.length;
  assert.ok(navStart >= 0 && navEnd > navStart);
  vm.runInContext(appSource.slice(navStart, navEnd), c);
  const doubleStart = appSource.indexOf('    els.findingsBody.addEventListener("dblclick"', appSource.indexOf('function bindFindingsEvents()'));
  const doubleEnd = appSource.indexOf('\n    });', doubleStart) + '\n    });'.length;
  vm.runInContext(appSource.slice(doubleStart, doubleEnd), c);
  const historyStart = appSource.indexOf('  els.historyTableBody.addEventListener("click"');
  const historyEnd = appSource.indexOf('\n  });', historyStart) + '\n  });'.length;
  vm.runInContext(appSource.slice(historyStart, historyEnd), c);
  const sortHeader = element(); sortHeader.dataset.sortKey = 'host'; c.sortHeaders = [sortHeader];
  const sortStart = appSource.indexOf('  sortHeaders.forEach((header) => {');
  const sortEnd = appSource.indexOf('\n  });', sortStart) + '\n  });'.length;
  vm.runInContext(appSource.slice(sortStart, sortEnd), c);
  const searchStart = appSource.indexOf('  let _searchDebounce = 0;');
  const searchEnd = appSource.indexOf('\n\n\n  els.requestSearchInput', searchStart);
  vm.runInContext(appSource.slice(searchStart, searchEnd), c);
  function clickHistory(id) {
    const row = { dataset: { id } };
    els.historyTableBody.listeners.click({ target: { closest: () => row } });
  }
  function doubleClickFinding() {
    const row = { dataset: { findingId: finding.id, recordId: record.id } };
    els.findingsBody.listeners.dblclick({ target: { closest: () => row } });
  }
  function clickJump() { els.findingsDetailJump.click(); assert.equal(state.activeProxyTab, 'http-history'); }
  async function returnToFindings(checkSelected = true) {
    proxyTabs[0].click(); await tick();
    assert.equal(state.activeProxyTab, 'findings'); if (checkSelected) assert.equal(c.selectedFindingId, finding.id);
    if (checkSelected) assert.equal(els.findingsDetailJump.dataset.recordId, record.id);
    assert.equal(state._findingsEntries.length, 1);
  }
  async function finishDetail(index) {
    assert.match(reads[index].url, /^\/api\/transactions\/saved-old\?/);
    reads[index].resolve(response({ ...record })); await tick();
    assert.match(reads[index + 1].url, /^\/api\/transactions-page\?/);
  }
  function snapshot() { return { selectedId: state.selectedId, selectedRecord: state.selectedRecord?.id ?? null,
    history: Array.from(state.items, value => value.id), toasts: [...toasts], loading: state.historyPaging.loading,
    meta: els.historyMeta.textContent, live: els.liveStatus.textContent, online: els.liveStatus.classList.contains('online'),
    rendered: [...rendered], errors: errors.length, paints: paints.length, focuses: [...focuses] }; }
  async function reset(id = 'session-a') {
    assert.equal(c.workspaceLoaded, true, 'Only an already initialized session is reset.');
    state.activeSession = { id }; c.resetSessionScopedUiState();
    c.applyWorkspaceState({ session_id: id, revision: 1, replay: { tabs: [] } });
    c.workspaceLoaded = true; // Successful loadWorkspaceState adoption sets this synchronously.
    c.replaceHistoryItemsForGap([{ id: 'recent', sequence: 100 }]);
  }
  return { c, state, els, reads, toasts, rendered, errors, findingLoads, clickJump, returnToFindings, finishDetail, snapshot,
    clickHistory, doubleClickFinding, reset, paints, focuses, sortHeader };
}
async function pendingReveal(f, stage = 'headers') {
  f.clickJump(); await f.finishDetail(0);
  let pending = f.reads[1], decoded = 0;
  if (stage !== 'headers') {
    const body = deferred();
    pending.resolve(stage === 'JSON'
      ? { ok: true, json() { decoded++; return body.promise; } }
      : { ok: false, text() { decoded++; return body.promise; } });
    pending = body; await tick();
  }
  return async outcome => {
    if (outcome === 'rejection') pending.reject(new Error('Synthetic obsolete failure'));
    else pending.resolve(stage === 'headers' ? response(page) : stage === 'JSON' ? page : 'Synthetic obsolete HTTP failure');
    await tick(); return decoded;
  };
}
async function newerJump(f, completed = true) {
  await f.returnToFindings(false); f.doubleClickFinding();
  const detail = f.reads.length - 1; await f.finishDetail(detail);
  if (completed) { f.reads.at(-1).resolve(response(page)); await tick(); }
}
for (const stage of ['headers', 'JSON', 'HTTP body']) for (const outcome of ['success', 'rejection']) {
  for (const completed of [false, true]) test(`newer same-ID Jump ${completed ? 'success' : 'pending'} survives obsolete ${stage} ${outcome}`, async () => {
    const f = fixture(), settle = await pendingReveal(f, stage);
    await newerJump(f, completed); const before = f.snapshot(); await settle(outcome);
    assert.deepEqual(f.snapshot(), before);
    if (!completed) { f.reads.at(-1).resolve(response(page)); await tick(); assert.equal(f.state.selectedId, record.id); }
  });
  for (const boundary of ['same-session reset', 'session ABA', 'accepted workspace']) test(`${boundary} retires obsolete ${stage} ${outcome}`, async () => {
    const f = fixture(), settle = await pendingReveal(f, stage);
    if (boundary === 'session ABA') { await f.reset('session-b'); await f.reset(); }
    else if (boundary === 'same-session reset') await f.reset();
    else f.c.applyWorkspaceState({ session_id: 'session-a', revision: 2, replay: { tabs: [] } });
    if (boundary !== 'accepted workspace') await newerJump(f);
    const before = f.snapshot(); await settle(outcome);
    // This obsolete request can release only its own loading slot, without painting.
    if (boundary === 'accepted workspace') before.loading = false;
    assert.deepEqual(f.snapshot(), before);
  });
  test(`newer row selection without a reveal retires obsolete ${stage} ${outcome} and releases its loading slot`, async () => {
    const f = fixture(), settle = await pendingReveal(f, stage);
    f.clickHistory('recent'); f.reads.at(-1).resolve(response({ id: 'recent', sequence: 100 })); await tick();
    const before = f.snapshot(); before.loading = false; await settle(outcome);
    assert.deepEqual(f.snapshot(), before);
  });
}
for (const stage of ['headers', 'JSON', 'HTTP body']) for (const change of ['query', 'sort', 'same-query page']) {
  test(`${change} paging supersession without changing the selection token retires ${stage}`, async () => {
    const f = fixture(), settle = await pendingReveal(f, stage), generation = f.state._historySelectionGeneration;
    // Model the accepted background page/query boundary at the production helper seam.
    // Other tests below exercise actual search/sort input handlers, which also clear selection.
    if (change === 'query') f.state.query = 'new filter';
    if (change === 'sort') f.state.sortDirection = 'asc';
    f.state.historyPaging = { ...f.state.historyPaging, generation: 40, loading: false };
    assert.equal(f.state._historySelectionGeneration, generation);
    const before = f.snapshot(); await settle('success'); assert.deepEqual(f.snapshot(), before);
  });
}
for (const change of ['search input', 'sort header']) test(`actual ${change} invalidates pending reveal without stale UI`, async () => {
  const f = fixture(), settle = await pendingReveal(f, 'HTTP body');
  if (change === 'search input') { f.els.searchInput.value = 'new'; f.els.searchInput.listeners.keydown({ key: 'Enter' }); }
  else f.sortHeader.click();
  const before = f.snapshot(); before.loading = false; await settle('success'); assert.deepEqual(f.snapshot(), before);
});
for (const outcome of ['success', 'network failure', 'JSON failure', 'HTTP failure', 'HTTP body rejection', 'filtered out']) {
  test(`current reveal retains ${outcome} feedback and releases loading`, async () => {
    const f = fixture(); f.clickJump(); await f.finishDetail(0);
    if (outcome === 'network failure') f.reads[1].reject(new Error('Synthetic current failure'));
    else if (outcome === 'JSON failure') f.reads[1].resolve({ ok: true, json: async () => { throw new Error('Synthetic current JSON failure'); } });
    else if (outcome === 'HTTP failure') f.reads[1].resolve({ ok: false, text: async () => 'Synthetic current HTTP failure' });
    else if (outcome === 'HTTP body rejection') f.reads[1].resolve({ ok: false, text: async () => { throw new Error('Synthetic current body failure'); } });
    else f.reads[1].resolve(response(outcome === 'filtered out' ? { items: [] } : page));
    await tick(); assert.equal(f.state.historyPaging.loading, false);
    assert.equal(f.state.selectedId, outcome === 'success' ? record.id : null);
    assert.equal(f.toasts.length, outcome === 'success' ? 0 : 1);
    if (outcome === 'HTTP failure') { assert.match(f.els.historyMeta.textContent, /Synthetic current HTTP failure/); assert.equal(f.els.liveStatus.textContent, 'Filter error'); }
    if (outcome !== 'success') { await newerJump(f); assert.equal(f.state.selectedId, record.id); }
  });
}
for (const stage of ['headers', 'JSON']) test(`newer Jump retires old transaction detail ${stage} before reveal`, async () => {
  const f = fixture(); f.clickJump(); let pending = f.reads[0];
  if (stage === 'JSON') { const body = deferred(); pending.resolve({ ok: true, json: () => body.promise }); pending = body; await tick(); }
  await newerJump(f); const before = f.snapshot(), count = f.reads.length;
  pending.resolve(stage === 'headers' ? response(record) : record); await tick();
  assert.deepEqual(f.snapshot(), before); assert.equal(f.reads.length, count);
});
test('background same-row detail refresh does not cancel an intended reveal', async () => {
  const f = fixture(), settle = await pendingReveal(f);
  const refresh = f.c.loadTransactionDetail(record.id); f.reads.at(-1).resolve(response(record)); await refresh;
  await settle('success'); assert.equal(f.state.selectedId, record.id); assert.deepEqual(f.focuses, [record.id]);
});
test('loaded record jump needs no reveal page and preserves existing boundary-key selection semantics', async () => {
  const f = fixture(); f.c.replaceHistoryItemsForGap([record]);
  f.clickJump(); f.reads[0].resolve(response(record)); await tick();
  assert.equal(f.reads.length, 1); assert.equal(f.state.selectedId, record.id); assert.deepEqual(f.focuses, [record.id]);
});
for (const invalid of ['sort', 'sequence']) test(`current unavailable ${invalid} retains its explanatory toast`, async () => {
  const f = fixture(); if (invalid === 'sort') f.state.sortKey = 'host';
  f.clickJump(); f.reads[0].resolve(response(invalid === 'sequence' ? { ...record, sequence: -1 } : record)); await tick();
  assert.equal(f.reads.length, 1); assert.equal(f.state.selectedId, null); assert.equal(f.toasts.length, 1);
});
test('generic page caller without an owner keeps current HTTP error feedback', async () => {
  const f = fixture(), read = f.c.fetchTransactionPage();
  f.reads[0].resolve({ ok: false, text: async () => 'Generic current failure' });
  await assert.rejects(read, /Generic current failure/);
  assert.match(f.els.historyMeta.textContent, /Generic current failure/); assert.equal(f.els.liveStatus.textContent, 'Filter error');
});
test('plain tab navigation keeps an otherwise current Jump intent without navigating back', async () => {
  const f = fixture(), settle = await pendingReveal(f);
  await f.returnToFindings(); await settle('success');
  assert.equal(f.state.activeProxyTab, 'findings'); assert.equal(f.state.selectedId, record.id);
  assert.equal(f.state.selectedRecord.id, record.id); assert.deepEqual(f.focuses, [record.id]);
});
for (const available of [true, false]) test(`retired helper entry cannot ${available ? 'claim cached success' : 'show current-unavailable feedback'}`, async () => {
  const f = fixture(); if (available) f.c.replaceHistoryItemsForGap([record]); else f.state.sortKey = 'host';
  const before = f.snapshot();
  assert.equal(await f.c.ensureHistoryWindowContainsRecord(record, { isCurrent: () => false }), null);
  assert.deepEqual(f.snapshot(), before); assert.equal(f.reads.length, 0);
});
for (const responseKind of ['JSON', 'HTTP text']) test(`retired page headers do not start ${responseKind} decoding or UI feedback`, async () => {
  const f = fixture(); await pendingReveal(f); await newerJump(f);
  const before = f.snapshot(); let decoded = false;
  f.reads[1].resolve(responseKind === 'JSON'
    ? { ok: true, json() { decoded = true; return Promise.resolve(page); } }
    : { ok: false, text() { decoded = true; return Promise.resolve('Synthetic obsolete error'); } });
  await tick(); assert.equal(decoded, false); assert.deepEqual(f.snapshot(), before);
});
for (const stage of ['headers', 'JSON']) for (const outcome of ['success', 'rejection', ...(stage === 'headers' ? ['HTTP 500', 'HTTP 404'] : [])]) {
  for (const boundary of ['accepted workspace', 'same-session reset', 'session ABA']) test(`${boundary} retires transaction detail ${stage} ${outcome} before publication`, async () => {
    const f = fixture(); f.clickJump(); let pending = f.reads[0];
    if (stage === 'JSON') { const body = deferred(); pending.resolve({ ok: true, json: () => body.promise }); pending = body; await tick(); }
    if (boundary === 'session ABA') { await f.reset('session-b'); await f.reset(); }
    else if (boundary === 'same-session reset') await f.reset();
    else f.c.applyWorkspaceState({ session_id: 'session-a', revision: 2, replay: { tabs: [] } });
    const before = f.snapshot(), count = f.reads.length;
    if (outcome === 'rejection') pending.reject(new Error('Synthetic obsolete detail failure'));
    else if (outcome.startsWith('HTTP')) pending.resolve({ ok: false, status: Number(outcome.slice(5)) });
    else pending.resolve(stage === 'headers' ? response(record) : record);
    await tick(); assert.deepEqual(f.snapshot(), before); assert.equal(f.reads.length, count);
  });
}
for (const stage of ['headers', 'JSON']) for (const outcome of ['rejection', ...(stage === 'headers' ? ['HTTP 500'] : [])]) {
  test(`current Jump transaction detail ${stage} ${outcome} keeps its retry placeholder`, async () => {
    const f = fixture(); f.clickJump(); let pending = f.reads[0];
    if (stage === 'JSON') { const body = deferred(); pending.resolve({ ok: true, json: () => body.promise }); pending = body; await tick(); }
    if (outcome === 'rejection') pending.reject(new Error('Synthetic current detail failure'));
    else pending.resolve({ ok: false, status: 500 });
    await tick(); assert.equal(f.state.selectedId, record.id); assert.equal(f.state.selectedRecord, null);
    assert.deepEqual(f.rendered, ['EMPTY']); assert.equal(f.reads.length, 1);
    await newerJump(f); assert.equal(f.state.selectedRecord.id, record.id);
  });
}
test('retired detail helper entry cannot supersede another detail read', async () => {
  const f = fixture(), generation = f.c._historyDetailGeneration, before = f.snapshot();
  const pending = f.c.loadTransactionDetail(record.id, { isCurrent: () => false });
  // Drain a pre-fix read so the regression fails rather than hanging.
  if (f.reads.length) f.reads.at(-1).resolve(response(record));
  assert.equal(await pending, null);
  assert.equal(f.c._historyDetailGeneration, generation); assert.equal(f.reads.length, 0); assert.deepEqual(f.snapshot(), before);
});
