// Passive, offline UI regressions. Only selected frontend functions and the
// saved-history click listener run; every fetch uses a synthetic deferred page.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');

const noop = () => {};
const quietConsole = { ...console, error() {} };
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const response = body => ({ ok: true, json: async () => body });
function failRequest(request, kind) {
  if (kind === 'network') request.reject(new Error('Synthetic read failure'));
  else if (kind === 'HTTP') request.resolve({ ok: false, status: 500, text: async () => 'Synthetic read failure' });
  else request.resolve({ ok: true, json: async () => { throw new Error('Synthetic read failure'); } });
}

function historyFixture({ size = 5, start = 0, total = size + 1, cursor = false } = {}) {
  const records = Array.from({ length: total }, (_, index) => ({
    id: `http-${index}`, sequence: total - index, method: 'GET', host: 'example.com', path: '/',
  }));
  const requests = [], selections = [];
  const state = {
    items: records.slice(start, start + size), selectedId: null, selectedRecord: null, _itemsVersion: 0,
    sortKey: cursor ? 'index' : 'host', sortDirection: cursor ? 'desc' : 'asc',
    historyPaging: {
      generation: 1, querySignature: 'query-a', pageSize: size,
      offset: cursor ? size : start + size, beforeSequence: cursor ? total - start - size + 1 : null,
      trimmedHeadCount: start, trimmedTailCount: 0, hasMore: start + size < total,
      fullyLoaded: start + size >= total, loading: false, total, filteredTotal: total,
    },
  };
  const c = loadFunctions([
    'moveHistorySelection', 'selectHistoryTransaction', 'historyRecordSummarySignature', 'canReuseSelectedHistoryRecord',
    'loadMoreTransactions', 'loadNewerTransactions', 'fetchTransactionPage', 'mergeHistoryItems', 'trimHistoryCache',
    'reconcileHistorySelectionAfterTrim', 'moveHistorySelectionIfMissing', 'rebuildHistoryItemIndex', 'getHistoryItem',
    'jsonArray', 'canUseSequenceCursorForHistoryPaging', 'updateHistoryPagingCursor', 'refreshHistoryPagingCursorFromItems',
    'applyPendingAnnotationsToItems', 'clearHttpHistorySelectionPreview',
    'jumpToTransaction', 'ensureHistoryWindowContainsRecord',
  ], {
    state, els: {}, query: 'query-a', session: 'session-a', HTTP_HISTORY_MAX_LOADED_ITEMS: size,
    console: quietConsole, buildTransactionsPageUrl: options => options,
    fetch(options) {
      const available = options.beforeSequence == null ? records : records.filter(row => row.sequence < options.beforeSequence);
      const offset = options.offset || 0;
      const page = { items: available.slice(offset, offset + size), total, filtered_total: total, has_more: offset + size < available.length };
      const request = { options, page, ...deferred() };
      requests.push(request);
      return request.promise;
    },
    updateHistorySelection: noop, scrollSelectedHistoryRowIntoView: noop, scheduleHistoryDetailLoading: noop,
    setActiveTool: noop, setActiveProxyTab: noop, renderProxyPanels: noop, focusHistoryRecord: noop,
    renderEmptyDetail: noop, prepareHistoryItem: noop, invalidateVisibleEntriesCache: noop,
    adjustHistoryScrollAfterHeadTrim: noop, renderHistory: noop,
    async loadTransactionDetail(id) {
      selections.push(id);
      state.selectedRecord = { ...(state.items.find(item => item.id === id) || { id }) };
      return state.selectedRecord;
    },
    getVisibleEntries: () => state.items.map(item => ({ item })),
    clamp: (value, low, high) => Math.max(low, Math.min(high, value)),
  });
  c.currentSessionId = () => c.session;
  c.createHistoryQueryState = () => ({ query: c.query });
  c.historyQuerySignature = (query = c.createHistoryQueryState()) => query.query;
  c.isCurrentHistoryQuerySignature = signature => signature === c.query;
  c.rebuildHistoryItemIndex();
  return { c, state, requests, selections, records };
}

async function startHistoryMove(f, direction) {
  const id = direction > 0 ? f.state.items.at(-1).id : f.state.items[0].id;
  await f.c.selectHistoryTransaction(id);
  const loading = f.c.moveHistorySelection(direction);
  assert.equal(f.requests.length, 1, 'the boundary key must begin a real page-loader read');
  assert.equal(f.state.historyPaging.loading, true);
  return { id, loading };
}
async function finishPage(f, loading, index = 0) {
  f.requests[index].resolve(response(f.requests[index].page));
  await loading;
}

for (const size of [5, 5000]) {
  for (const cursor of [false, true]) {
    for (const direction of [1, -1]) {
      const label = `HTTP ${direction > 0 ? 'forward' : 'backward'}, ${cursor ? 'sequence cursor' : 'offset'}, cap ${size}`;
      const makeFixture = () => historyFixture({ size, start: direction > 0 ? 0 : 1, total: size + 1, cursor });
      test(`${label}: an uninterrupted boundary key selects the adjacent page row`, async () => {
        const f = makeFixture(), { loading } = await startHistoryMove(f, direction);
        await finishPage(f, loading);
        assert.equal(f.state.selectedId, direction > 0 ? `http-${size}` : 'http-0');
        assert.equal(f.state.items.length, size);
        assert.equal(f.state.historyPaging.loading, false);
      });
      test(`${label}: repeated same-direction boundary keys retain the pending move`, async () => {
        const f = makeFixture(), { id, loading } = await startHistoryMove(f, direction);
        await f.c.moveHistorySelection(direction);
        await f.c.moveHistorySelection(direction);
        assert.equal(f.state.selectedId, id, 'repeated keys cannot move beyond the loaded boundary yet');
        assert.equal(f.requests.length, 1, 'repeated keys must reuse the pending page read');
        await finishPage(f, loading);
        assert.equal(f.state.selectedId, direction > 0 ? `http-${size}` : 'http-0');
      });
      test(`${label}: an opposite-direction key supersedes the pending move`, async () => {
        const f = makeFixture(), { loading } = await startHistoryMove(f, direction);
        const expected = f.state.items[direction > 0 ? size - 2 : 1].id;
        await f.c.moveHistorySelection(-direction);
        assert.equal(f.state.selectedId, expected);
        await finishPage(f, loading);
        assert.equal(f.state.selectedId, expected);
        assert.equal(f.requests.length, 1);
      });
      test(`${label}: a newer retained row selection survives the delayed page`, async () => {
        const f = makeFixture(), { loading } = await startHistoryMove(f, direction);
        await f.c.selectHistoryTransaction('http-2');
        await finishPage(f, loading);
        assert.equal(f.state.selectedId, 'http-2');
        assert.equal(f.state.selectedRecord.id, 'http-2');
      });
      test(`${label}: choosing away and back invalidates the earlier boundary key`, async () => {
        const f = makeFixture(), { id, loading } = await startHistoryMove(f, direction);
        await f.c.selectHistoryTransaction('http-2');
        await f.c.selectHistoryTransaction(id);
        await finishPage(f, loading);
        assert.equal(f.state.selectedId, id);
      });
      test(`${label}: explicitly reselecting a cached same row cancels the earlier key`, async () => {
        const f = makeFixture(), { id, loading } = await startHistoryMove(f, direction);
        const reads = f.selections.length;
        assert.equal(f.c.canReuseSelectedHistoryRecord(id), true);
        await f.c.selectHistoryTransaction(id);
        assert.equal(f.selections.length, reads, 'the selector reused its cached detail');
        await finishPage(f, loading);
        assert.equal(f.state.selectedId, id);
      });
      test(`${label}: an explicit saved-record jump to the same loaded row cancels the earlier key`, async () => {
        const f = makeFixture(), { id, loading } = await startHistoryMove(f, direction);
        f.c.jumpToTransaction(id);
        assert.equal(f.state.selectedId, id);
        await finishPage(f, loading);
        assert.equal(f.state.selectedId, id);
        assert.equal(f.state.selectedRecord.id, id);
        assert.equal(f.requests.length, 1, 'the jump reuses the already-loaded history window');
      });
      test(`${label}: clearing selection cannot be undone by the earlier key`, async () => {
        const f = makeFixture(), { loading } = await startHistoryMove(f, direction);
        f.c.clearHttpHistorySelectionPreview();
        await finishPage(f, loading);
        assert.equal(f.state.selectedId, null);
        assert.equal(f.state.selectedRecord, null);
      });
      test(`${label}: a background same-row detail refresh preserves the boundary key`, async () => {
        const f = makeFixture(), { id, loading } = await startHistoryMove(f, direction);
        await f.c.loadTransactionDetail(id);
        await finishPage(f, loading);
        assert.equal(f.state.selectedId, direction > 0 ? `http-${size}` : 'http-0');
      });
    }
  }
  for (const direction of [1, -1]) {
    test(`HTTP cap ${size}: whole-page ${direction > 0 ? 'forward' : 'backward'} eviction keeps its normal fallback`, async () => {
      const f = historyFixture({ size, start: direction > 0 ? 0 : size, total: size * 2 });
      const { loading } = await startHistoryMove(f, direction);
      await finishPage(f, loading);
      assert.equal(f.state.selectedId, `http-${direction > 0 ? size : size - 1}`);
      assert.ok(f.c.getHistoryItem(f.state.selectedId), 'fallback stays in the retained cache');
    });
    test(`HTTP cap ${size}: ${direction > 0 ? 'forward' : 'backward'} eviction onto the old ID does not revive its key`, async () => {
      const start = direction > 0 ? 0 : size - 1;
      const f = historyFixture({ size, start, total: size * 2 - 1 });
      const { id, loading } = await startHistoryMove(f, direction);
      const newerId = `http-${direction > 0 ? size - 2 : size}`;
      await f.c.selectHistoryTransaction(newerId);
      await finishPage(f, loading);
      assert.equal(f.c.getHistoryItem(newerId), null, 'the newer choice was evicted by the real cache trimmer');
      assert.equal(f.state.selectedId, id, 'keep the trimmer fallback without an additional stale keyboard step');
    });
  }
}

for (const direction of [1, -1]) {
  for (const change of ['query', 'session']) {
    test(`HTTP ${direction > 0 ? 'forward' : 'backward'}: ${change} invalidation discards the page and keyboard continuation`, async () => {
      const f = historyFixture({ start: direction > 0 ? 0 : 1 });
      const { loading } = await startHistoryMove(f, direction);
      if (change === 'query') f.c.query = 'query-b';
      else {
        f.c.session = 'session-b';
        f.state.historyPaging = { ...f.state.historyPaging, generation: 2, loading: false };
      }
      f.state.items = [{ id: 'replacement-row', method: 'GET', host: 'example.com' }];
      f.c.rebuildHistoryItemIndex();
      await f.c.selectHistoryTransaction('replacement-row');
      await finishPage(f, loading);
      assert.deepEqual(Array.from(f.state.items, item => item.id), ['replacement-row']);
      assert.equal(f.state.selectedId, 'replacement-row');
      assert.equal(f.requests.length, 1);
    });
  }
  for (const kind of ['network', 'HTTP', 'JSON']) {
    test(`HTTP ${direction > 0 ? 'forward' : 'backward'}: a failed ${kind} read releases loading and a later key works`, async () => {
      const f = historyFixture({ start: direction > 0 ? 0 : 1 });
      const { id, loading } = await startHistoryMove(f, direction);
      failRequest(f.requests[0], kind);
      await loading;
      assert.equal(f.state.selectedId, id);
      assert.equal(f.state.historyPaging.loading, false);
      const retry = f.c.moveHistorySelection(direction);
      assert.equal(f.requests.length, 2);
      await finishPage(f, retry, 1);
      assert.equal(f.state.selectedId, direction > 0 ? 'http-5' : 'http-0');
    });
  }
}

function websocketFixture({ count = 3, pageSize = 3, cap = 10 } = {}) {
  const records = Array.from({ length: count + 1 }, (_, index) => ({
    id: `ws-${index}`, host: 'example.com', frame_count: 0, last_frame_index: -1, status: 101,
  }));
  const state = {
    websocketSessions: records.slice(0, count), selectedWebsocketId: null, selectedWebsocketRecord: null,
    websocketPaging: { hasMore: true, loading: false, limit: count, loadedOffset: count, summaryMutationGeneration: 0 },
  };
  const requests = [], selections = [];
  let click;
  const c = loadFunctions([
    'moveWebsocketSelection', 'selectWebsocketSession', 'loadMoreWebsockets', 'loadWebsockets', 'createWebsocketPagingState',
    'createWebsocketQueryState', 'websocketQuerySignature', 'websocketCursorPagingEnabled', 'websocketAppendAfterId',
    'buildWebsocketsPageUrl', 'jsonArray', 'websocketPagePayload', 'mergeWebsocketAppendPage', 'pruneWebsocketSummaryMutationCache',
    'syncVisibleWebsocketSelection', 'getSortedWebsocketEntries', 'getVisibleWebsocketSessions', 'clearWebsocketSelectionPreview',
    'normalizeWebsocketLoadLimit', 'loadWebsocketsPageRefresh', 'currentWebsocketRefreshLimit',
    'clearWebsocketLoadedSessionsForPendingQuery',
  ], {
    state, URLSearchParams, session: 'session-a', console: quietConsole,
    WEBSOCKET_PAGE_SIZE: pageSize, WEBSOCKET_MAX_LOADED_SESSIONS: cap,
    _websocketLoadGeneration: 0, _websocketSummaryMutationGeneration: 0, _websocketSummaryMutationById: new Map(),
    _websocketDetailRefreshNeeded: null, sessionQueryPath: url => url,
    async requireOkResponse(value) { if (!value.ok) throw new Error(await value.text()); },
    fetch(url) {
      assert.match(url, /^\/api\/websockets-page\?/);
      const params = new URLSearchParams(url.split('?')[1]);
      const offset = Number(params.get('offset') || 0), limit = Number(params.get('limit'));
      const page = { items: records.slice(offset, offset + limit), total: records.length, offset, has_more: offset + limit < records.length };
      const request = { url, page, ...deferred() };
      requests.push(request);
      return request.promise;
    },
    els: { websocketTableBody: {
      contains: () => true,
      addEventListener(type, handler) { assert.equal(type, 'click'); click = handler; },
    } },
    renderWebsocketSessions: noop, renderWebsocketSessionTable: noop, hideFrameDetail: noop,
    resetWebsocketFrameScroll: noop, scheduleWebsocketDetailLoading: noop, cancelWebsocketDetailLoading: noop,
    scrollSelectedWebsocketRowIntoView: noop, resetWebsocketHistoryScroll: noop,
    async loadWebsocketDetail(id) {
      selections.push(id);
      state.selectedWebsocketRecord = { ...records.find(item => item.id === id), id, loaded_last_frame_index: -1 };
    },
    clamp: (value, low, high) => Math.max(low, Math.min(high, value)),
  });
  c.currentSessionId = () => c.session;
  const listener = appSource.match(/^  els\.websocketTableBody\?\.addEventListener\("click", \(event\) => \{[^]*?^  \}\);/m);
  assert.ok(listener, 'saved WebSocket history click listener exists');
  vm.runInContext(listener[0], c, { filename: 'web/app.js:websocketTableBody-click' });
  return {
    c, state, requests, selections, records,
    click(id) { const row = { dataset: { id } }; click({ target: { closest: () => row } }); },
  };
}
async function startWebsocketMove(f) {
  const id = f.state.websocketSessions.at(-1).id;
  await f.c.selectWebsocketSession(id);
  const loading = f.c.moveWebsocketSelection(1);
  assert.equal(f.requests.length, 1);
  assert.equal(f.state.websocketPaging.loading, true);
  return { id, loading };
}

for (const settings of [{ count: 3, pageSize: 3, cap: 10 }, { count: 4999, pageSize: 500, cap: 5000 }]) {
  const label = `WebSocket ${settings.count} loaded, cap ${settings.cap}`;
  test(`${label}: an uninterrupted boundary key selects the appended row`, async () => {
    const f = websocketFixture(settings), { loading } = await startWebsocketMove(f);
    await finishPage(f, loading);
    assert.equal(f.state.selectedWebsocketId, `ws-${settings.count}`);
    assert.equal(f.state.websocketPaging.loading, false);
  });
  test(`${label}: repeated Down keys retain the pending boundary move`, async () => {
    const f = websocketFixture(settings), { id, loading } = await startWebsocketMove(f);
    await f.c.moveWebsocketSelection(1);
    await f.c.moveWebsocketSelection(1);
    assert.equal(f.state.selectedWebsocketId, id, 'repeated keys cannot move beyond the loaded boundary yet');
    assert.equal(f.requests.length, 1, 'repeated keys must reuse the pending page read');
    await finishPage(f, loading);
    assert.equal(f.state.selectedWebsocketId, `ws-${settings.count}`);
  });
  test(`${label}: an Up key supersedes the pending boundary move`, async () => {
    const f = websocketFixture(settings), { loading } = await startWebsocketMove(f);
    const expected = `ws-${settings.count - 2}`;
    await f.c.moveWebsocketSelection(-1);
    assert.equal(f.state.selectedWebsocketId, expected);
    await finishPage(f, loading);
    assert.equal(f.state.selectedWebsocketId, expected);
    assert.equal(f.requests.length, 1);
  });
  for (const input of ['selector', 'click']) {
    for (const action of ['different row', 'away and back', 'same row']) {
      test(`${label}: a newer ${input} choosing ${action} invalidates the earlier key`, async () => {
        const f = websocketFixture(settings), { id, loading } = await startWebsocketMove(f);
        const select = next => input === 'click' ? f.click(next) : f.c.selectWebsocketSession(next);
        if (action !== 'same row') await select('ws-1');
        if (action !== 'different row') await select(id);
        await finishPage(f, loading);
        assert.equal(f.state.selectedWebsocketId, action === 'different row' ? 'ws-1' : id);
      });
    }
  }
  test(`${label}: clearing selection retains ordinary page reconciliation without a stale extra step`, async () => {
    const f = websocketFixture(settings), { loading } = await startWebsocketMove(f);
    f.c.clearWebsocketSelectionPreview();
    await finishPage(f, loading);
    assert.equal(f.state.selectedWebsocketId, 'ws-0', 'append reconciliation chooses the first row when no selection remains');
  });
  test(`${label}: a background detail refresh preserves the boundary key`, async () => {
    const f = websocketFixture(settings), { id, loading } = await startWebsocketMove(f);
    await f.c.loadWebsocketDetail(id);
    await finishPage(f, loading);
    assert.equal(f.state.selectedWebsocketId, `ws-${settings.count}`);
  });
  test(`${label}: background same-ID selection reconciliation preserves the boundary key`, async () => {
    const f = websocketFixture(settings), { loading } = await startWebsocketMove(f);
    await f.c.syncVisibleWebsocketSelection(true);
    await finishPage(f, loading);
    assert.equal(f.state.selectedWebsocketId, `ws-${settings.count}`);
  });
}

for (const change of ['query', 'session']) {
  test(`WebSocket ${change} invalidation discards the append and keyboard continuation`, async () => {
    const f = websocketFixture(), { loading } = await startWebsocketMove(f);
    if (change === 'query') f.state.websocketQuery = 'replacement query';
    else { f.c.session = 'session-b'; f.c._websocketLoadGeneration += 1; }
    f.state.websocketPaging = { ...f.state.websocketPaging, loading: false };
    f.state.websocketSessions = [{ id: 'replacement-row', host: 'example.com' }];
    await f.c.selectWebsocketSession('replacement-row');
    await finishPage(f, loading);
    assert.deepEqual(Array.from(f.state.websocketSessions, item => item.id), ['replacement-row']);
    assert.equal(f.state.selectedWebsocketId, 'replacement-row');
    assert.equal(f.state.websocketPaging.loading, false);
    assert.equal(f.requests.length, 1);
  });
}
for (const kind of ['network', 'HTTP', 'JSON']) {
  test(`WebSocket failed ${kind} read releases loading and a refreshed list permits a later key`, async () => {
    const f = websocketFixture(), { id, loading } = await startWebsocketMove(f);
    failRequest(f.requests[0], kind);
    await assert.rejects(loading, /Synthetic read failure/);
    assert.equal(f.state.selectedWebsocketId, id);
    assert.equal(f.state.websocketPaging.loading, false);
    const refresh = f.c.loadWebsocketsPageRefresh(true);
    await finishPage(f, refresh, 1);
    assert.equal(f.state.websocketPaging.hasMore, true);
    const retry = f.c.moveWebsocketSelection(1);
    await finishPage(f, retry, 2);
    assert.equal(f.state.selectedWebsocketId, 'ws-3');
  });
}


for (const change of ['same-query refresh', 'query change', 'session change']) {
  for (const viaKeyboard of [false, true]) {
    test(`WebSocket ${change}: a superseded ${viaKeyboard ? 'boundary key' : 'append'} cannot claim growth from the newer read`, async () => {
      const f = websocketFixture();
      const originalId = f.state.websocketSessions.at(-1).id;
      await f.c.selectWebsocketSession(originalId);
      const loading = viaKeyboard ? f.c.moveWebsocketSelection(1) : f.c.loadMoreWebsockets();
      assert.equal(f.requests.length, 1);
      if (change === 'query change') {
        f.state.websocketQuery = 'replacement query';
        // The new query legitimately starts on the same ID. Selection identity
        // alone cannot prove that the old page request still owns the result.
        const index = f.records.findIndex(row => row.id === originalId);
        f.records.unshift(...f.records.splice(index, 1));
      } else if (change === 'session change') {
        f.c.session = 'session-b';
      }
      const replacement = f.c.loadWebsockets(true, { limit: 4 });
      await finishPage(f, replacement, 1);
      assert.equal(f.state.websocketSessions.length, 4, 'the newer read grew the list');
      assert.equal(f.state.selectedWebsocketId, originalId, 'newer read legitimately preserves or reuses the selected ID');
      const retainedIds = Array.from(f.state.websocketSessions, row => row.id);
      f.requests[0].resolve(response(f.requests[0].page));
      const added = await loading;
      if (!viaKeyboard) assert.equal(added, 0, 'a superseded append cannot report rows added by a different read');
      assert.equal(f.state.selectedWebsocketId, originalId, 'the old keyboard operation lost page ownership');
      assert.deepEqual(Array.from(f.state.websocketSessions, row => row.id), retainedIds);
      assert.equal(f.state.websocketPaging.loading, false);
      assert.equal(f.requests.length, 2);
    });
  }
}
