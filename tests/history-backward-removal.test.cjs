const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');

// Passive, offline fixture only: no server, socket, browser, or captured data.
// Most cases scale paging size and cache cap equally from 5000 to 3.
// Race cases also run at the production 5000-row cap.
function fixture(sortKey = 'host', sortDirection = 'asc', rowCount = 9, pageSize = 3) {
  let records = Array.from({ length: rowCount }, (_, i) => ({
    id: `fixture-${i}`, sequence: rowCount - i, method: 'GET',
    host: `${String(i).padStart(6, '0')}.example.com`, has_user_note: true,
  }));
  const requests = [];
  const scheduled = [];
  const state = {
    items: records.slice(0, pageSize), sortKey, sortDirection, selectedId: null,
    _itemsVersion: 0, filterSettings: { onlyNotes: true }, historyColumnOrder: ['index'],
    historyPaging: {
      generation: 1, querySignature: 'fixture-query', pageSize,
      offset: pageSize, beforeSequence: sortKey === 'index' && sortDirection === 'desc' ? rowCount - pageSize + 1 : null,
      total: rowCount, filteredTotal: rowCount, hasMore: rowCount > pageSize,
      fullyLoaded: rowCount <= pageSize, loading: false, trimmedHeadCount: 0, trimmedTailCount: 0,
    },
  };
  const els = { historyMeta: {}, historyTableBody: {} };
  const context = loadFunctions([
    'isKnownCount', 'jsonArray', 'canUseSequenceCursorForHistoryPaging',
    'adjustHistoryPagingAfterLocalRemoval', 'refreshHistoryPagingCursorFromItems',
    'updateHistoryPagingCursor', 'loadMoreTransactions', 'loadNewerTransactions',
    'mergeHistoryItems', 'trimHistoryCache', 'reconcileHistorySelectionAfterTrim',
    'rebuildHistoryItemIndex', 'getHistoryItem', 'renderHistory',
    'countHiddenConnectItems', 'humanizeSortKey', 'isSessionEmpty', 'emptySessionMessage', 'historyEmptyMessage',
    'flushPendingAnnotations',
    'currentHistoryNoteEditWindow', 'syncHistoryNoteEditWindow', 'retainFilteredHistoryNote',
    'releaseHistoryNoteEdit', 'releaseDetachedHistoryNoteEdits', 'inheritPendingHistoryNoteEdit', 'getHistoryItemIndex', 'summaryMatchesActiveHistoryFilters', 'applyPendingAnnotationsToItems',
  ], {
    state, els, HTTP_HISTORY_MAX_LOADED_ITEMS: pageSize,
    createHistoryQueryState: () => ({}), historyQuerySignature: () => 'fixture-query',
    isCurrentHistoryQuerySignature: () => true,
    async fetchTransactionPage(options) {
      requests.push({ ...options });
      const available = options.beforeSequence == null ? records : records.filter(row => row.sequence < options.beforeSequence);
      const offset = options.offset || 0;
      const items = available.slice(offset, offset + pageSize);
      return { items, total: rowCount, filtered_total: options.beforeSequence == null ? records.length : null,
        has_more: offset + items.length < available.length };
    },
    prepareHistoryItem() {},
    invalidateVisibleEntriesCache() {}, adjustHistoryScrollAfterHeadTrim() {},
    getVisibleEntries: () => state.items.map((item, index) => ({ item, index })),
    renderSortHeaders() {}, renderHistoryVirtual() {}, mountBrowserLaunchers() {},
    currentSessionId: () => 'fixture-session', sessionWritePath: path => path,
    observeAnnotationRevision() {}, renderEmptyDetail() {},
    showToast(message) { throw new Error(message); },
    escapeHtml: text => text,
    scheduleHistoryBackfill: (...args) => scheduled.push(args),
  });
  context.rebuildHistoryItemIndex();
  let renders = 0;
  const actualRenderHistory = context.renderHistory;
  context.renderHistory = () => { renders += 1; return actualRenderHistory(); };
  return {
    renderCount: () => renders,
    context, state, requests, scheduled, els,
    ids: () => Array.from(state.items, row => row.id),
    serverIds: () => records.map(row => row.id),
    clearNoteOnServer(id) {
      const row = records.find(row => row.id === id);
      records = records.filter(record => record.id !== id);
      return { ...row, has_user_note: false, note_count: 0, annotation_revision: 1 };
    },
    remove(index) {
      const [row] = state.items.splice(index, 1);
      records = records.filter(record => record.id !== row.id);
      context.adjustHistoryPagingAfterLocalRemoval(1, { decrementTotal: false });
      context.rebuildHistoryItemIndex();
      context.refreshHistoryPagingCursorFromItems();
    },
  };
}

for (const [key, direction] of [['host', 'asc'], ['index', 'desc']]) {
  for (const removedIndex of [0, 1, 2]) {
    test(`${key} ${direction}: backward paging after removing retained position ${removedIndex}`, async () => {
      const f = fixture(key, direction);
      await f.context.loadMoreTransactions();
      f.remove(removedIndex);
      assert.equal(f.state.historyPaging.trimmedHeadCount, 3);
      await f.context.loadNewerTransactions();
      assert.deepEqual(f.ids(), f.serverIds().slice(0, 3));
      assert.equal(f.state.historyPaging.trimmedHeadCount, 0);
      assert.equal(f.state.historyPaging.offset, 3);
      assert.equal(f.state.historyPaging.total, 9);
      assert.equal(f.state.historyPaging.filteredTotal, 8);
      await f.context.loadMoreTransactions();
      assert.deepEqual(f.ids(), f.serverIds().slice(3, 6));
      assert.equal(f.state.historyPaging.trimmedHeadCount, 3);
    });
  }
  test(`${key} ${direction}: backward paging includes partial trimmed head after a prior removal`, async () => {
    const f = fixture(key, direction);
    f.remove(1);
    await f.context.loadMoreTransactions();
    assert.equal(f.state.historyPaging.trimmedHeadCount, 2);
    f.remove(1);
    await f.context.loadNewerTransactions();
    assert.deepEqual(f.ids(), f.serverIds().slice(0, 3));
    assert.equal(f.state.historyPaging.trimmedHeadCount, 0);
    await f.context.loadMoreTransactions();
    assert.deepEqual(f.ids(), f.serverIds().slice(3, 6));
  });
  test(`${key} ${direction}: repeated backward loads after last-page removal reach the first page`, async () => {
    const f = fixture(key, direction);
    await f.context.loadMoreTransactions();
    await f.context.loadMoreTransactions();
    f.remove(1);
    await f.context.loadNewerTransactions();
    assert.deepEqual(f.ids(), f.serverIds().slice(3, 6));
    await f.context.loadNewerTransactions();
    assert.deepEqual(f.ids(), f.serverIds().slice(0, 3));
    assert.equal(f.state.historyPaging.trimmedHeadCount, 0);
  });
}

test('empty final loaded window can be recovered through loadNewerTransactions', async () => {
  const f = fixture();
  await f.context.loadMoreTransactions();
  await f.context.loadMoreTransactions();
  while (f.state.items.length) f.remove(0);
  assert.equal(f.state.historyPaging.trimmedHeadCount, 6);
  assert.equal(f.state.historyPaging.filteredTotal, 6);
  assert.equal(f.state.historyPaging.hasMore, false);
  await f.context.loadNewerTransactions();
  assert.deepEqual(f.ids(), ['fixture-3', 'fixture-4', 'fixture-5']);
});


for (const [key, direction, pageSize] of [['host', 'asc', 3], ['index', 'desc', 3], ['host', 'asc', 5000], ['index', 'desc', 5000]]) {
  test(`${key} ${direction}, pageSize=${pageSize}: a late overlapping backward page does not resurrect a saved filter removal`, async () => {
    const f = fixture(key, direction, pageSize * 3, pageSize);
    f.remove(1);
    await f.context.loadMoreTransactions();
    assert.equal(f.state.historyPaging.trimmedHeadCount, pageSize - 1);
    assert.equal(f.ids()[0], `fixture-${pageSize}`);
    assert.equal(f.ids().length, pageSize);

    const originalFetch = f.context.fetchTransactionPage;
    let releasePage;
    let snapshotReady;
    const ready = new Promise(resolve => { snapshotReady = resolve; });
    let delayed = false;
    f.context.fetchTransactionPage = async options => {
      const page = structuredClone(await originalFetch(options));
      if (!delayed) {
        delayed = true;
        snapshotReady();
        await new Promise(resolve => { releasePage = resolve; });
      }
      return page;
    };
    const requestsBeforeLoad = f.requests.length;
    const loadingNewer = f.context.loadNewerTransactions({ background: true });
    await ready;
    assert.equal(f.state.historyPaging.loading, true);

    const id = `fixture-${pageSize}`;
    f.state.selectedId = id;
    f.state._pendingAnnotations = new Map([[id, {
      sessionId: 'fixture-session', payload: { user_note: '' },
    }]]);
    f.context.fetch = async () => ({ ok: true, json: async () => f.clearNoteOnServer(id) });
    assert.equal(await f.context.flushPendingAnnotations(id), true);
    assert.equal(f.ids().includes(id), false, 'saved only-notes filter removal must remove the row');
    assert.equal(f.state._pendingAnnotations.has(id), false, 'save completed before the older page response');
    assert.equal(f.serverIds().includes(id), false, 'synthetic backend no longer matches the removed row');

    const rendersBeforePage = f.renderCount();
    releasePage();
    await loadingNewer;
    assert.equal(f.requests.length, requestsBeforeLoad + 2, 'changed filter membership requires exactly one fresh backward read');
    assert.deepEqual(f.requests.slice(-2).map(request => request.offset), [0, 0]);
    assert.equal(f.state.historyPaging.filteredTotal, pageSize * 3 - 2, 'retry must replace stale filtered counts');
    assert.equal(f.ids().includes(id), false,
      `A backward-page response captured before the annotation save must not resurrect ${id} after it no longer matches only-notes`);
    assert.equal(f.state.historyPaging.loading, false);
    assert.ok(f.renderCount() > rendersBeforePage, 'completed background paging must render its latest state');
    f.context.fetchTransactionPage = originalFetch;
    await f.context.loadNewerTransactions();
    assert.deepEqual(f.ids(), f.serverIds().slice(0, pageSize));
  });
}

for (const [key, direction, pageSize] of [['host', 'asc', 3], ['index', 'desc', 3], ['host', 'asc', 5000]]) {
  test(`${key} ${direction}, pageSize=${pageSize}: a saved filter removal invalidates an in-flight forward page`, async () => {
    const f = fixture(key, direction, pageSize * 4, pageSize);
    await f.context.loadMoreTransactions();
    const originalFetch = f.context.fetchTransactionPage;
    let releasePage;
    let snapshotReady;
    const ready = new Promise(resolve => { snapshotReady = resolve; });
    let delayed = false;
    f.context.fetchTransactionPage = async options => {
      const page = structuredClone(await originalFetch(options));
      if (!delayed) {
        delayed = true;
        snapshotReady();
        await new Promise(resolve => { releasePage = resolve; });
      }
      return page;
    };
    const loadingOlder = f.context.loadMoreTransactions({ background: true });
    await ready;
    const id = `fixture-${pageSize + 1}`;
    f.state.selectedId = id;
    f.state._pendingAnnotations = new Map([[id, {
      sessionId: 'fixture-session', payload: { user_note: '' },
    }]]);
    f.context.fetch = async () => ({ ok: true, json: async () => f.clearNoteOnServer(id) });
    assert.equal(await f.context.flushPendingAnnotations(id), true);
    const rendersBeforePage = f.renderCount();
    releasePage();
    await loadingOlder;
    if (key !== 'index') {
      assert.deepEqual(f.requests.slice(-2).map(request => request.offset), [pageSize * 2, pageSize * 2 - 1], 'retry must read using the adjusted forward offset');
      assert.equal(f.state.historyPaging.offset, pageSize * 3 - 1);
    }
    assert.equal(f.state.historyPaging.filteredTotal, pageSize * 4 - 1);
    assert.deepEqual(f.ids(), Array.from({length:pageSize}, (_,i) => `fixture-${pageSize * 2 + i}`));
    assert.equal(f.state.historyPaging.loading, false);
    assert.ok(f.renderCount() > rendersBeforePage, 'completed background paging must render its latest state');
    f.context.fetchTransactionPage = originalFetch;
    await f.context.loadMoreTransactions();
    assert.deepEqual(f.ids(), Array.from({length:pageSize}, (_,i) => `fixture-${pageSize * 3 + i}`));
  });
}

for (const change of ['query', 'session']) {
  test(`a backward page invalidated by both removal and ${change} change is rejected without retry`, async () => {
    const f = fixture();
    f.remove(1);
    await f.context.loadMoreTransactions();
    const originalFetch = f.context.fetchTransactionPage;
    let releasePage;
    let snapshotReady;
    const ready = new Promise(resolve => { snapshotReady = resolve; });
    f.context.fetchTransactionPage = async options => {
      const page = structuredClone(await originalFetch(options));
      snapshotReady();
      await new Promise(resolve => { releasePage = resolve; });
      return page;
    };
    const requestsBeforeLoad = f.requests.length;
    const loading = f.context.loadNewerTransactions({ background: true });
    await ready;
    f.remove(1);
    if (change === 'query') {
      f.context.isCurrentHistoryQuerySignature = () => false;
    } else {
      f.state.historyPaging = { ...f.state.historyPaging, generation: 2, loading: false };
      f.state.items = [{ id: 'other-session-row', sequence: 1, method: 'GET', host: 'example.com' }];
      f.context.rebuildHistoryItemIndex();
    }
    const expectedIds = f.ids();
    releasePage();
    assert.equal(await loading, 0);
    assert.equal(f.requests.length, requestsBeforeLoad + 1, 'stale query/session must never be retried');
    assert.deepEqual(f.ids(), expectedIds);
    assert.equal(f.state.historyPaging.loading, false);
  });
}
