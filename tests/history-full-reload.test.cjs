// Offline passive UI regression: no app startup, API, proxy, or network I/O.
// Imports only named functions from the audited checkout through its existing VM helper.
const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function fixture() {
  const original = { id: 'fixture-row', sequence: 1, method: 'GET', host: 'example.com', path: '/', color_tag: 'red', has_user_note: true, note_preview: 'before', annotation_revision: 1 };
  const state = {
    items: [{ ...original }], selectedId: null, selectedRecord: null,
    sortKey: 'index', sortDirection: 'desc',
    _itemsVersion: 0, historyDirty: false, historyListError: '',
    historyPaging: { querySignature: 'query-a' },
    _pendingAnnotations: new Map(), _annotationInFlight: new Set(),
  };
  const requests = [], rendered = [];
  const context = loadFunctions([
    'createHistoryPagingState', 'loadTransactions', 'fetchTransactionPage',
    'applyPendingAnnotationsToItems', 'flushPendingAnnotations',
    'observeAnnotationRevision', 'rebuildHistoryItemIndex', 'getHistoryItemIndex',
    'getHistoryItem', 'clearHttpHistoryLoadedRowsForPendingQuery',
    'clearHttpHistorySelectionPreview', 'isKnownCount',
    'adjustHistoryPagingAfterLocalRemoval', 'refreshHistoryPagingCursorFromItems',
    'canUseSequenceCursorForHistoryPaging',
  ], {
    state, query: 'query-a', session: 'fixture-session', annotationSaveVersion: 1,
    _historyFullLoadInFlight: 0, _historyPagingGeneration: 0,
    _pendingTransactionSummaries: [], HTTP_HISTORY_PAGE_SIZE: 250,
    els: { historyMeta: { textContent: '' }, liveStatus: { textContent: '', classList: { remove() {} } } },
    fetch(url, options) { const request = { url, options, ...deferred() }; requests.push(request); return request.promise; },
    buildTransactionsPageUrl: () => 'fixture-only:page',
    sessionWritePath: (url) => `fixture-only:${url}`,
    clearHistoryBackfill() {},
    jsonArray: (items) => Array.isArray(items) ? items : [],
    updateHistoryPagingCursor() {},
    invalidateVisibleEntriesCache() {}, resetHistoryScrollPosition() {},
    getVisibleEntries: () => state.items.map((item) => ({ item })),
    canReuseSelectedHistoryRecord: () => false,
    async selectHistoryTransaction() {},
    renderHistory() { rendered.push(state.items.map((item) => ({ ...item }))); },
    renderEmptyDetail() {}, updateHistorySelection() {},
    prepareHistoryItem() {}, summaryMatchesActiveHistoryFilters: () => true,
    resortLoadedHistoryItemsForCurrentSort: () => false,
    scheduleTransactionDeltaFlush() {}, showToast() {},
    console: { ...console, error() {} },
  });
  context.currentSessionId = () => context.session;
  context.createHistoryQueryState = () => ({ query: context.query });
  context.historyQuerySignature = (query = context.createHistoryQueryState()) => query.query;
  context.isCurrentHistoryQuerySignature = (signature) => signature === context.query;
  context.precomputeItemIndexes = () => context.rebuildHistoryItemIndex();
  context.rebuildHistoryItemIndex();
  return { context, state, requests, rendered, original };
}
function page(item) { return { items: item ? [{ ...item }] : [], total: item ? 1 : 0, filtered_total: item ? 1 : 0, has_more: false }; }
function response(body) { return { ok: true, json: async () => body }; }
const nextTurn = () => new Promise((resolve) => setImmediate(resolve));
const pages = (requests) => requests.filter((request) => !request.options);
async function saveAnnotation(f, payload, summary) {
  const { context, state, requests, original } = f;
  state._pendingAnnotations.set(original.id, { sessionId: context.session, payload });
  const saving = context.flushPendingAnnotations(original.id);
  requests.at(-1).resolve(response(summary));
  assert.equal(await saving, true);
  assert.equal(state._pendingAnnotations.size, 0);
}
async function finishWithRetry(f, loading, staleResponse, latestPage) {
  staleResponse.resolve(page(f.original));
  await nextTurn();
  const pageRequests = pages(f.requests);
  if (pageRequests[1]) pageRequests[1].resolve(response(latestPage));
  await loading;
  assert.equal(pageRequests.length, 2, 'an annotation acknowledgement overlapping the first page must trigger a fresh page read');
}


for (const change of [
  { name: 'color', payload: { color_tag: 'blue' }, summary: { color_tag: 'blue' }, field: 'color_tag', expected: 'blue' },
  { name: 'note', payload: { user_note: 'saved note' }, summary: { note_preview: 'saved note', has_user_note: true }, field: 'note_preview', expected: 'saved note' },
]) {
  test(`full reload must not overwrite an acknowledged ${change.name} with an older page`, async () => {
    const f = fixture();
    const { context, state, requests, original } = f;
    const loading = context.loadTransactions(true);
    // The list read already has an older snapshot, but its response body has not finished.
    const delayedBody = deferred();
    requests[0].resolve({ ok: true, json: () => delayedBody.promise });
    await Promise.resolve();
    const savedSummary = { ...original, ...change.summary, annotation_revision: 2 };
    await saveAnnotation(f, change.payload, savedSummary);
    assert.equal(state.items[0][change.field], change.expected, 'save success updates the displayed summary');
    await finishWithRetry(f, loading, delayedBody, page(savedSummary));
    assert.equal(context._historyFullLoadInFlight, 0);
    assert.equal(state.historyPaging.loading, false);
    assert.equal(state.items[0][change.field], change.expected, 'late full read must preserve the acknowledged value');
    assert.equal(state.items[0].annotation_revision, 2, 'summary revision must not go backwards');
  });
}


test('saved note removal retries the filtered page and adopts new membership and counts', async () => {
  const f = fixture();
  const { context, state, requests, original } = f;
  context.summaryMatchesActiveHistoryFilters = (item) => !!item.has_user_note;
  const loading = context.loadTransactions(true);
  const delayedBody = deferred();
  requests[0].resolve({ ok: true, json: () => delayedBody.promise });
  await Promise.resolve();
  const savedSummary = { ...original, has_user_note: false, annotation_revision: 2 };
  delete savedSummary.note_preview;
  await saveAnnotation(f, { user_note: null }, savedSummary);
  assert.equal(state.items.length, 0, 'acknowledgement removes the row from notes-only history');
  await finishWithRetry(f, loading, delayedBody, { items: [], total: 1, filtered_total: 0, has_more: false });
  assert.equal(state.items.length, 0, 'the old page must not resurrect the removed row');
  assert.equal(state.historyPaging.total, 1);
  assert.equal(state.historyPaging.filteredTotal, 0);
  assert.equal(state.historyPaging.fullyLoaded, true);
});

test('a save acknowledged after resetScroll clears rows still invalidates the pending page', async () => {
  const f = fixture();
  const { context, state, requests, original } = f;
  state._pendingAnnotations.set(original.id, { sessionId: context.session, payload: { color_tag: 'blue' } });
  const saving = context.flushPendingAnnotations(original.id);
  const loading = context.loadTransactions(true, { resetScroll: true });
  assert.equal(state.items.length, 0);
  const delayedBody = deferred();
  requests[1].resolve({ ok: true, json: () => delayedBody.promise });
  await Promise.resolve();
  const savedSummary = { ...original, color_tag: 'blue', annotation_revision: 2 };
  requests[0].resolve(response(savedSummary));
  assert.equal(await saving, true);
  assert.equal(state._pendingAnnotations.size, 0);
  assert.equal(state.items.length, 0, 'the saved row is absent until the replacement list arrives');
  await finishWithRetry(f, loading, delayedBody, page(savedSummary));
  assert.equal(state.items[0].color_tag, 'blue');
  assert.equal(state.items[0].annotation_revision, 2);
});

test('another acknowledged change during the retry requires a third fresh page', async () => {
  const f = fixture();
  const { context, state, requests, original } = f;
  const loading = context.loadTransactions(true);
  const firstBody = deferred();
  requests[0].resolve({ ok: true, json: () => firstBody.promise });
  await Promise.resolve();
  const firstSaved = { ...original, color_tag: 'blue', annotation_revision: 2 };
  await saveAnnotation(f, { color_tag: 'blue' }, firstSaved);
  firstBody.resolve(page(original));
  await nextTurn();
  const secondRead = pages(requests)[1];
  assert.ok(secondRead, 'first acknowledged change must trigger retry');
  const secondBody = deferred();
  secondRead.resolve({ ok: true, json: () => secondBody.promise });
  await Promise.resolve();
  const lastSaved = { ...original, color_tag: 'green', annotation_revision: 3 };
  await saveAnnotation(f, { color_tag: 'green' }, lastSaved);
  secondBody.resolve(page(firstSaved));
  await nextTurn();
  const thirdRead = pages(requests)[2];
  assert.ok(thirdRead, 'second acknowledged change must trigger another retry');
  assert.equal(state.historyPaging.loading, true);
  thirdRead.resolve(response({ ...page(lastSaved), total: 9, filtered_total: 1 }));
  await loading;
  assert.equal(pages(requests).length, 3);
  assert.equal(state.items[0].color_tag, 'green');
  assert.equal(state.items[0].annotation_revision, 3);
  assert.equal(state.historyPaging.total, 9);
  assert.equal(state.historyPaging.filteredTotal, 1);
  assert.equal(state.historyPaging.loading, false);
  assert.equal(context._historyFullLoadInFlight, 0);
});

test('an acknowledged superseded save invalidates reads while the newer edit remains pending', async () => {
  const f = fixture();
  const { context, state, requests, original } = f;
  const loading = context.loadTransactions(true);
  const firstBody = deferred();
  requests[0].resolve({ ok: true, json: () => firstBody.promise });
  await Promise.resolve();
  state._pendingAnnotations.set(original.id, { sessionId: context.session, payload: { color_tag: 'blue' } });
  const savingFirst = context.flushPendingAnnotations(original.id);
  state._pendingAnnotations.set(original.id, { sessionId: context.session, payload: { color_tag: 'green' } });
  requests[1].resolve(response({ ...original, color_tag: 'blue', annotation_revision: 2 }));
  assert.equal(await savingFirst, true);
  assert.equal(requests[2].options.method, 'PATCH', 'newer pending edit begins saving after first acknowledgement');
  firstBody.resolve(page(original));
  await nextTurn();
  const freshRead = pages(requests)[1];
  assert.ok(freshRead, 'acknowledging an older queued save still invalidates the list snapshot');
  freshRead.resolve(response(page({ ...original, color_tag: 'blue', annotation_revision: 2 })));
  await loading;
  assert.equal(state.items[0].color_tag, 'green', 'newer pending color remains optimistically visible');
  assert.equal(state._pendingAnnotations.size, 1);
  requests[2].resolve(response({ ...original, color_tag: 'green', annotation_revision: 3 }));
  await nextTurn();
  assert.equal(state._pendingAnnotations.size, 0);
  assert.equal(state.items[0].annotation_revision, 3);
});

test('clearing loaded rows also clears lookup indexes for an in-flight save', () => {
  const { context, state, original } = fixture();
  assert.equal(context.getHistoryItemIndex(original.id), 0);
  context.clearHttpHistoryLoadedRowsForPendingQuery();
  assert.equal(state.items.length, 0);
  assert.equal(context.getHistoryItemIndex(original.id), -1);
  assert.equal(context.getHistoryItem(original.id), null);
});

for (const changeQuery of [false, true]) {
  test(`annotation-invalidated load superseded by ${changeQuery ? 'another query' : 'a newer same-query load'} does not retry`, async () => {
    const f = fixture();
    const { context, state, requests, original } = f;
    const olderLoad = context.loadTransactions(true);
    const savedSummary = { ...original, color_tag: 'blue', annotation_revision: 2 };
    await saveAnnotation(f, { color_tag: 'blue' }, savedSummary);
    if (changeQuery) context.query = 'query-b';
    const newerLoad = context.loadTransactions(true);
    pages(requests)[0].resolve(response(page(original)));
    await olderLoad;
    assert.equal(pages(requests).length, 2, 'superseded load must not create a retry');
    assert.equal(state.historyPaging.loading, true, 'newer load owns the loading flag');
    pages(requests)[1].resolve(response(page(savedSummary)));
    await newerLoad;
    assert.equal(state.items[0].color_tag, 'blue');
    assert.equal(state.historyPaging.loading, false);
    assert.equal(context._historyFullLoadInFlight, 0);
  });
}

test('control: a still-pending color is preserved across a full reload', async () => {
  const { context, state, requests, original } = fixture();
  const loading = context.loadTransactions(true);
  state._pendingAnnotations.set(original.id, { sessionId: context.session, payload: { color_tag: 'blue' } });
  requests[0].resolve(response(page(original)));
  await loading;
  assert.equal(state.items[0].color_tag, 'blue');
});

for (const failure of ['network rejection', 'aborted read', 'HTTP failure', 'JSON failure']) {
  test(`current full read recovers its loading state after ${failure}`, async () => {
    const { context, state, requests, original } = fixture();
    const loading = context.loadTransactions(true);
    const rejected = assert.rejects(loading, /fixture failure/);
    if (failure === 'network rejection') requests[0].reject(new Error('fixture failure'));
    if (failure === 'aborted read') { const error = new Error('fixture failure'); error.name = 'AbortError'; requests[0].reject(error); }
    if (failure === 'HTTP failure') requests[0].resolve({ ok: false, text: async () => 'fixture failure' });
    if (failure === 'JSON failure') requests[0].resolve({ ok: true, json: async () => { throw new Error('fixture failure'); } });
    await rejected;
    assert.equal(state.historyPaging.loading, false);
    assert.equal(state.historyPaging.hasMore, false);
    assert.equal(state.historyListError, 'fixture failure');
    assert.equal(context._historyFullLoadInFlight, 0);
    assert.equal(state.items.length, 0);
    assert.equal(context.getHistoryItemIndex(original.id), -1, 'a failed read must not leave stale row indexes');
    const retry = context.loadTransactions(true);
    requests[1].resolve(response(page(original)));
    await retry;
    assert.equal(state.historyPaging.loading, false);
    assert.equal(state.historyListError, '');
    assert.equal(state.items[0].id, original.id);
  });
}

for (const failure of [false, true]) {
  test(`superseded full read ${failure ? 'failure' : 'success'} preserves newer loading ownership`, async () => {
    const { context, state, requests, original } = fixture();
    const oldLoad = context.loadTransactions(true);
    const oldResult = failure ? assert.rejects(oldLoad, /fixture stale failure/) : oldLoad;
    const newerLoad = context.loadTransactions(true);
    const newerGeneration = state.historyPaging.generation;
    if (failure) requests[0].reject(new Error('fixture stale failure'));
    else requests[0].resolve(response(page({ ...original, color_tag: 'red' })));
    await oldResult;
    assert.equal(state.historyPaging.generation, newerGeneration);
    assert.equal(state.historyPaging.loading, true);
    assert.equal(state.historyListError, '');
    requests[1].resolve(response(page({ ...original, color_tag: 'green' })));
    await newerLoad;
    assert.equal(state.historyPaging.loading, false);
    assert.equal(state.items[0].color_tag, 'green');
    assert.equal(context._historyFullLoadInFlight, 0);
  });
}

test('superseded query returns null without clobbering replacement query state', async () => {
  const { context, state, requests, original } = fixture();
  const oldLoad = context.loadTransactions(true);
  context.query = 'query-b';
  const newerLoad = context.loadTransactions(true);
  requests[0].resolve(response(page(original)));
  await oldLoad;
  assert.equal(state.historyPaging.querySignature, 'query-b');
  assert.equal(state.historyPaging.loading, true);
  requests[1].resolve(response(page({ ...original, color_tag: 'green' })));
  await newerLoad;
  assert.equal(state.historyPaging.loading, false);
  assert.equal(state.items[0].color_tag, 'green');
  assert.equal(context._historyFullLoadInFlight, 0);
});
