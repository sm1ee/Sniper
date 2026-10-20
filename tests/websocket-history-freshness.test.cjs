// Captured-session list controllers only. All responses and timers are synthetic.
const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const noop = () => {};
const row = (id, hour = 8, extra = {}) => ({ id, scheme: 'wss', host: 'example.com', path: `/${id}`,
  status: 101, frame_count: 1, retained_frame_count: 1, last_frame_index: 0, note_count: 0,
  started_at: `2026-10-17T0${hour}:00:00Z`, ...extra });
const close = summary => ({ ...summary, closed_at: '2026-10-17T08:01:00Z', duration_ms: 60000 });
const ids = f => Array.from(f.state.websocketSessions, item => item.id);
function fixture(options = {}) {
  const a = row('fixture-a'), b = row('fixture-b', 7), c = row('fixture-c', 6);
  const state = { websocketSessions: [a, b], websocketQuery: '', websocketSortKey: 'started_at',
    websocketSortDirection: 'desc', websocketLiveOnly: true, websocketInScopeOnly: false,
    selectedWebsocketId: a.id, selectedWebsocketRecord: { ...a, frames: [], loaded_last_frame_index: 0 },
    websocketPaging: { total: 2, filteredTotal: 2, limit: 2, loadedOffset: 2, hasMore: false, loading: false },
    ...options.state };
  const requests = [], refreshes = [], selectionSyncs = [], rendered = [];
  const context = loadFunctions([
    'loadWebsockets', 'loadMoreWebsockets', 'loadWebsocketsPageRefresh', 'currentWebsocketRefreshLimit',
    'createWebsocketQueryState', 'websocketQuerySignature', 'websocketCursorPagingEnabled',
    'normalizeWebsocketLoadLimit', 'createWebsocketPagingState', 'buildWebsocketsPageUrl', 'websocketPagePayload', 'jsonArray',
    'mergeWebsocketPageWithCurrentSummaries', 'mergeWebsocketAppendPage', 'pruneWebsocketSummaryMutationCache',
    'websocketAppendAfterId', 'applyWebsocketSummary', 'websocketServerOrderCanAcceptSummaryEvents',
    'websocketFilterIsActive', 'websocketSummarySignature', 'websocketSummaryMatchesCurrentQuery',
    'websocketSummarySearchHaystack', 'applySelectedWebsocketSummary', 'adjustWebsocketPagingAfterLocalRemoval',
    'noteWebsocketSummaryMutation', 'isKnownCount', 'isWebsocketSummaryFresher', 'websocketSummaryNumber',
    'websocketSummaryTimestamp', 'shouldInsertUnknownWebsocketSummary', 'insertWebsocketSummaryInStartedAtDescOrder',
    'websocketSummaryStartedAtDescInsertIndex', 'websocketSummaryStartedAtDescCompare',
    'syncVisibleWebsocketSelection', 'getVisibleWebsocketSessions', 'websocketLoadedWindowCanHideSelection',
    'selectedWebsocketDetailMeetsRefreshTarget', 'websocketFramesAreTruncated', 'websocketFirstRetainedFrameIndex',
    'websocketRetainedFrameCount', 'normalizeWebsocketCount', 'normalizeWebsocketFrameIndex',
    'clearWebsocketLoadedSessionsForPendingQuery', 'clearWebsocketSelectionPreview',
  ], {
    state, URLSearchParams, _websocketLoadGeneration: 0, _websocketSummaryMutationGeneration: 0,
    _websocketSummaryMutationById: new Map(), _websocketDetailRefreshNeeded: null,
    WEBSOCKET_PAGE_SIZE: 2, WEBSOCKET_MAX_LOADED_SESSIONS: options.cap || 10,
    WEBSOCKET_SORTED_SUMMARY_REFRESH_MIN_MS: 1500, session: 'fixture-session',
    sessionQueryPath: (url, session) => `${url}&session_id=${session}`,
    fetch(url) { const request = { url, ...deferred() }; requests.push(request); return request.promise; },
    async requireOkResponse(response) { if (!response.ok) throw Error('Fixture failed'); },
    isWebsocketHistoryVisible: () => true,
    isInScopeHost: host => host === 'example.com',
    scheduleWebsocketPageRefresh: options => refreshes.push(options),
    scheduleVisibleWebsocketSelectionSync: options => selectionSyncs.push(options),
    scheduleSelectedWebsocketDetailRefresh: noop, hideFrameDetail: noop, resetWebsocketFrameScroll: noop,
    resetWebsocketHistoryScroll: noop, cancelWebsocketDetailLoading: noop,
    renderWebsocketSessions: () => rendered.push(ids({ state })),
    async loadWebsocketDetail(id) { state.selectedWebsocketRecord = { ...state.websocketSessions.find(item => item.id === id), frames: [], loaded_last_frame_index: 0 }; },
  });
  context.currentSessionId = () => context.session;
  state.websocketPaging.querySignature = context.websocketQuerySignature();
  const page = (items = [a, b], extra = {}) => ({ items, total: 2, filtered_total: 2, offset: 0, has_more: false, ...extra });
  return { c: context, state, requests, refreshes, selectionSyncs, rendered, a, b, next: c, page };
}
async function pause(f, boundary, options = {}) {
  const loading = f.c.loadWebsockets(true, options), request = f.requests.at(-1), body = deferred(), entered = deferred();
  if (boundary === 'JSON') {
    request.resolve({ ok: true, json() { entered.resolve(); return body.promise; } });
    await entered.promise;
  }
  return async payload => {
    if (boundary === 'JSON') body.resolve(payload);
    else request.resolve({ ok: true, json: async () => payload });
    await loading;
  };
}

for (const boundary of ['fetch', 'JSON']) {
  for (const filter of ['Hide closed', 'live search']) {
    test(`${filter}: a late ${boundary} page cannot restore a nonmatching summary or its old counts`, async () => {
      const f = fixture();
      if (filter !== 'Hide closed') f.state.websocketLiveOnly = false;
      if (filter === 'live search') f.state.websocketQuery = 'live';
      f.state.websocketPaging.querySignature = f.c.websocketQuerySignature();
      const finish = await pause(f, boundary);
      const latest = close(f.a);
      f.c.applyWebsocketSummary(latest);
      assert.deepEqual(ids(f), [f.b.id]);
      assert.equal(f.state.websocketPaging.total, 2);
      assert.equal(f.state.websocketPaging.filteredTotal, 1);
      assert.equal(f.state.websocketPaging.loading, true, 'summary updates cannot release the page owner');
      f.c.applyWebsocketSummary(latest);
      f.c.applyWebsocketSummary(f.a);
      assert.equal(f.state.websocketPaging.total, 2, 'duplicate/older events do not change the stored total');
      await finish(f.page());
      assert.deepEqual(ids(f), [f.b.id]);
      assert.equal(f.state.websocketPaging.filteredTotal, 1);
      assert.equal(f.state.websocketPaging.loadedOffset, 1);
      assert.equal(f.state.selectedWebsocketId, f.b.id, 'actual selection reconciliation leaves the hidden row');
      assert.equal(f.state.selectedWebsocketRecord.id, f.b.id);
    });
  }
  test(`cursor append: an unseen session closed during ${boundary} stays hidden`, async () => {
    const f = fixture();
    Object.assign(f.state.websocketPaging, { total: 3, filteredTotal: 3, hasMore: true });
    const finish = await pause(f, boundary, { append: true, offset: 2, afterId: f.b.id });
    f.c.applyWebsocketSummary(close(f.next));
    assert.equal(await f.c.loadMoreWebsockets(), 0);
    assert.equal(f.requests.length, 1, 'events cannot start a second load-more owner');
    await finish(f.page([f.next], { total: 3, filtered_total: 3, offset: 2 }));
    assert.deepEqual(ids(f), [f.a.id, f.b.id]);
    assert.equal(f.state.websocketPaging.total, 3);
    assert.equal(f.state.websocketPaging.filteredTotal, 2);
    assert.equal(f.state.websocketPaging.loadedOffset, 2);
  });
  for (const change of ['query', 'session', 'newer read']) {
    test(`${change} supersedes the late ${boundary} page and retains its loading/selection owner`, async () => {
      const f = fixture(), finish = await pause(f, boundary);
      f.c.applyWebsocketSummary(close(f.a));
      if (change === 'query') f.state.websocketQuery = f.b.id;
      if (change === 'session') {
        f.c.session = 'replacement-session';
        f.c._websocketSummaryMutationById.clear();
        f.c._websocketSummaryMutationGeneration += 1;
      }
      const next = f.c.loadWebsockets(true);
      const nextRequest = f.requests[1];
      f.state.selectedWebsocketId = f.b.id;
      await finish(f.page());
      assert.equal(f.state.websocketPaging.loading, true);
      assert.equal(f.state.selectedWebsocketId, f.b.id);
      nextRequest.resolve({ ok: true, json: async () => f.page([f.b], { filtered_total: 1 }) });
      await next;
      assert.deepEqual(ids(f), [f.b.id]);
      assert.equal(f.state.websocketPaging.loading, false);
    });
  }
  test(`a partial ${boundary} page reports unknown matching count and preserves its cursor`, async () => {
    const f = fixture();
    Object.assign(f.state.websocketPaging, { total: 4, filteredTotal: null, hasMore: true });
    const finish = await pause(f, boundary);
    f.c.applyWebsocketSummary(close(f.a));
    await finish(f.page([f.a, f.b], { total: 4, filtered_total: 4, has_more: true }));
    assert.deepEqual(ids(f), [f.b.id]);
    assert.equal(f.state.websocketPaging.total, 4);
    assert.equal(f.state.websocketPaging.filteredTotal, null);
    assert.equal(f.state.websocketPaging.afterId, f.b.id);
    const more = f.c.loadMoreWebsockets();
    assert.match(f.requests[1].url, /after_id=fixture-b/);
    assert.match(f.requests[1].url, /offset=1/);
    f.requests[1].resolve({ ok: true, json: async () => f.page([f.next], { total: 4, filtered_total: 3, offset: 1 }) });
    await more;
    assert.deepEqual(ids(f), [f.b.id, f.next.id]);
  });
}

test('turning Hide closed off reloads the stored closed session without reviving its live state', async () => {
  const f = fixture();
  f.c.applyWebsocketSummary(close(f.a));
  f.state.websocketLiveOnly = false;
  const finish = await pause(f, 'fetch');
  await finish(f.page());
  assert.deepEqual(ids(f), [f.a.id, f.b.id]);
  assert.equal(f.state.websocketSessions[0].closed_at, close(f.a).closed_at);
  assert.equal(f.state.websocketPaging.total, 2);
  assert.equal(f.state.websocketPaging.filteredTotal, 2);
});

test('newer summaries and response snapshots cannot be regressed by delayed events', async () => {
  const f = fixture({ state: { websocketLiveOnly: false } });
  f.c.applyWebsocketSummary({ ...f.a, frame_count: 2, last_frame_index: 1 });
  let finish = await pause(f, 'fetch');
  const latest = { ...close(f.a), frame_count: 4, last_frame_index: 3 };
  await finish(f.page([latest, f.b]));
  f.c.applyWebsocketSummary({ ...f.a, frame_count: 3, last_frame_index: 2 });
  assert.equal(f.state.websocketSessions[0].frame_count, 4);
  assert.equal(f.state.websocketSessions[0].closed_at, latest.closed_at);
  finish = await pause(f, 'JSON');
  await finish(f.page());
  assert.equal(f.state.websocketSessions[0].frame_count, 4);
});

test('search membership can leave and return without counting a stored session twice', () => {
  const f = fixture({ state: { websocketLiveOnly: false, websocketQuery: '60000' } });
  f.a.frame_count = 60000;
  f.b.frame_count = 60000;
  f.c.applyWebsocketSummary({ ...f.a, frame_count: 60001, last_frame_index: 60000 });
  assert.deepEqual(ids(f), [f.b.id]);
  f.c.applyWebsocketSummary({ ...f.a, frame_count: 160000, last_frame_index: 159999 });
  assert.deepEqual(ids(f), [f.a.id, f.b.id]);
  assert.equal(f.state.websocketPaging.total, 2);
  assert.equal(f.state.websocketPaging.filteredTotal, 2);
});

test('a real local deletion still decrements both stored and filtered totals', () => {
  const f = fixture();
  f.state.websocketSessions = [f.b];
  f.c.adjustWebsocketPagingAfterLocalRemoval(1);
  assert.equal(f.state.websocketPaging.total, 1);
  assert.equal(f.state.websocketPaging.filteredTotal, 1);
});

test('bounded mutation evidence invalidates an overlapping read before eviction', async () => {
  const f = fixture({ cap: 2 }), finish = await pause(f, 'JSON');
  f.c.applyWebsocketSummary(close(f.a));
  f.c.applyWebsocketSummary(close(f.b));
  f.c.applyWebsocketSummary(close(f.next));
  assert.equal(f.c._websocketSummaryMutationById.size, 2);
  assert.equal(f.refreshes.length, 1);
  assert.equal(f.state.websocketPaging.loading, false);
  await finish(f.page());
  assert.deepEqual(ids(f), []);
  assert.equal(f.state.websocketPaging.total, 2);
});

for (const alreadyCounted of [false, true]) {
  test(`a previously hidden session entering search is counted ${alreadyCounted ? 'once after a page' : 'when first observed matching'}`, async () => {
    const f = fixture({ state: { websocketLiveOnly: false, websocketQuery: '60000', websocketSessions: [] } });
    f.state.websocketPaging.filteredTotal = 0;
    f.c.applyWebsocketSummary(f.next);
    if (alreadyCounted) {
      const finish = await pause(f, 'fetch');
      await finish(f.page([], { total: 3, filtered_total: 0 }));
    }
    f.c.applyWebsocketSummary(close(f.next));
    assert.deepEqual(ids(f), [f.next.id]);
    assert.equal(f.state.websocketPaging.total, 3);
    assert.equal(f.state.websocketPaging.filteredTotal, 1);
  });
}

test('append reconciliation filters stale rows before enforcing the loaded-session cap', async () => {
  const f = fixture({ cap: 3 });
  Object.assign(f.state.websocketPaging, { total: 4, filteredTotal: 4, hasMore: true });
  const finish = await pause(f, 'JSON', { append: true, offset: 2, afterId: f.b.id });
  f.c.applyWebsocketSummary(close(f.next));
  const d = row('fixture-d', 5);
  await finish(f.page([f.next, d], { total: 4, filtered_total: 4, offset: 2 }));
  assert.deepEqual(ids(f), [f.a.id, f.b.id, d.id]);
  assert.equal(f.state.websocketPaging.filteredTotal, 3);
  assert.equal(f.state.websocketPaging.loadedOffset, 3);
  assert.equal(f.state.websocketPaging.hasMore, false);
});

for (const boundary of ['fetch', 'JSON']) {
  test(`non-cursor sorted append rebases after a ${boundary} summary mutation`, async () => {
    const f = fixture({ state: { websocketSortKey: 'frame_count' } });
    Object.assign(f.state.websocketPaging, { total: 3, filteredTotal: 3, hasMore: true });
    const finish = await pause(f, boundary, { append: true, offset: 2 });
    f.c.applyWebsocketSummary(close(f.a));
    const finishing = finish(f.page([f.next], { total: 3, filtered_total: 3, offset: 2 }));
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(f.requests.length, 2);
    assert.match(f.requests[1].url, /offset=0/);
    f.requests[1].resolve({ ok: true, json: async () => f.page([f.b, f.next], { total: 3, filtered_total: 2 }) });
    await finishing;
    assert.deepEqual(ids(f), [f.b.id, f.next.id]);
    assert.equal(f.state.websocketPaging.total, 3);
    assert.equal(f.state.websocketPaging.filteredTotal, 2);
    assert.equal(f.state.selectedWebsocketId, f.b.id);
  });
}

test('an older close event cannot remove a row with newer captured frames', () => {
  const f = fixture();
  f.c.applyWebsocketSummary({ ...f.a, frame_count: 3, last_frame_index: 2 });
  f.c.applyWebsocketSummary(close({ ...f.a, frame_count: 2, last_frame_index: 1 }));
  assert.deepEqual(ids(f), [f.a.id, f.b.id]);
  assert.equal(f.state.websocketSessions[0].frame_count, 3);
  assert.equal(f.state.websocketSessions[0].closed_at, undefined);
  assert.equal(f.state.websocketPaging.filteredTotal, 2);
});
