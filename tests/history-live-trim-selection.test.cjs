// Live capture at the loaded-row cap must not take over the selection, and a
// selection it pushes out must stay usable. Fixtures only: no app startup, API,
// or captured data.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const noop = () => {};
const quietConsole = { ...console, error() {} };

// Rows are newest first (index descending), the order live capture prepends to.
function fixture({ size = 5, total = 12 } = {}) {
  const records = Array.from({ length: total }, (_, index) => ({
    id: `http-${index}`, sequence: total - index, method: "GET", host: "example.com", path: "/",
  }));
  const state = {
    items: records.slice(0, size), selectedId: null, selectedRecord: null, _itemsVersion: 0,
    sortKey: "index", sortDirection: "desc", activeSession: { id: "session-a" },
    historyPaging: {
      generation: 1, querySignature: "query-a", pageSize: size, offset: size,
      beforeSequence: total - size + 1, trimmedHeadCount: 0, trimmedTailCount: 0,
      hasMore: true, fullyLoaded: false, loading: false, total, filteredTotal: total,
    },
  };
  const selections = [];
  const pending = [];
  const timers = [];
  const c = loadFunctions([
    "flushTransactionDeltas", "scheduleIncrementalRefresh", "replaceHistoryItemsForGap",
    "mergeHistoryItems", "trimHistoryCache", "keepLiveEvictedSelection",
    "reconcileHistorySelectionAfterTrim", "moveHistorySelectionIfMissing",
    "moveHistorySelection", "selectHistoryTransaction", "canReuseSelectedHistoryRecord",
    "historyRecordSummarySignature", "loadMoreTransactions", "fetchTransactionPage",
    "rebuildHistoryItemIndex", "getHistoryItem", "jsonArray",
    "canUseSequenceCursorForHistoryPaging", "updateHistoryPagingCursor",
    "refreshHistoryPagingCursorFromItems", "applyPendingAnnotationsToItems",
  ], {
    state, els: {}, console: quietConsole, Date, query: "query-a", session: "session-a",
    HTTP_HISTORY_MAX_LOADED_ITEMS: size,
    _pendingTransactionSummaries: pending, _historyFullLoadInFlight: false,
    _searchActiveUntil: 0, _incrementalTimer: 0,
    window: { setTimeout: (fn) => { timers.push(fn); return timers.length; } },
    isHttpHistoryVisible: () => true,
    canMergeRecentTransactions: () => true,
    summaryMatchesActiveHistoryFilters: () => true,
    isKnownCount: (value) => Number.isFinite(value),
    scheduleTransactionDeltaFlush: noop, scheduleRefresh: noop, scheduleHistoryBackfill: noop,
    buildTransactionsPageUrl: (options) => options,
    async fetch(options) {
      const available = options.beforeSequence == null
        ? records
        : records.filter((row) => row.sequence < options.beforeSequence);
      const offset = options.offset || 0;
      const limit = options.limit || size;
      const items = available.slice(offset, offset + limit);
      return { ok: true, json: async () => ({
        items, total: records.length, filtered_total: records.length,
        has_more: offset + limit < available.length,
      }) };
    },
    updateHistorySelection: noop, scrollSelectedHistoryRowIntoView: noop,
    scheduleHistoryDetailLoading: noop, renderEmptyDetail: noop, prepareHistoryItem: noop,
    invalidateVisibleEntriesCache: noop, adjustHistoryScrollAfterHeadTrim: noop, renderHistory: noop,
    async loadTransactionDetail(id) {
      selections.push(id);
      state.selectedRecord = { ...(records.find((row) => row.id === id) || { id }) };
      return state.selectedRecord;
    },
    getVisibleEntries: () => state.items.map((item) => ({ item })),
    clamp: (value, low, high) => Math.max(low, Math.min(high, value)),
  });
  c.currentSessionId = () => c.session;
  c.createHistoryQueryState = () => ({ query: c.query });
  c.historyQuerySignature = (query = c.createHistoryQueryState()) => query.query;
  c.isCurrentHistoryQuerySignature = (signature) => signature === c.query;
  c.rebuildHistoryItemIndex();
  let nextSequence = total + 1;
  // One captured request arriving through the live path.
  const capture = () => {
    const id = `live-${nextSequence}`;
    const summary = { id, sequence: nextSequence, method: "GET", host: "example.com", path: "/" };
    nextSequence += 1;
    records.unshift(summary);
    pending.push({ sessionId: "session-a", summary });
    c.flushTransactionDeltas();
  };
  const select = async (id) => {
    await c.selectHistoryTransaction(id);
    selections.length = 0;
  };
  return { c, state, selections, capture, select, timers, records };
}

test("live capture that evicts the selected row leaves the selection alone", async () => {
  const f = fixture();
  await f.select("http-4");            // the last loaded row
  f.capture();
  assert.equal(f.c.getHistoryItem("http-4"), null, "the row left the loaded window");
  assert.equal(f.state.selectedId, "http-4", "the inspector keeps the record the person chose");
  assert.deepEqual(f.selections, [], "nothing was selected on the person's behalf");
});

test("later requests leave it alone too, instead of moving it again each time", async () => {
  const f = fixture();
  await f.select("http-4");
  for (let i = 0; i < 6; i += 1) f.capture();
  assert.equal(f.state.selectedId, "http-4");
  assert.deepEqual(f.selections, []);
  assert.equal(f.state.items.length, 5, "the loaded window still holds the cap");
});

test("the incremental refresh's live gap path leaves the selection alone", async () => {
  // Paged far past the newest rows, so the refresh's newest 50 cannot overlap the
  // loaded window and it replaces the window instead of merging into it.
  const f = fixture({ size: 5, total: 70 });
  f.state.items = f.records.slice(60, 65);
  f.state.historyPaging.trimmedHeadCount = 60;
  f.c.rebuildHistoryItemIndex();
  await f.select("http-62");
  f.capture();
  assert.equal(f.timers.length, 1, "the capture was handed to the incremental refresh");
  await f.timers[0]();
  assert.equal(f.c.getHistoryItem("http-62"), null, "the gap replaced the loaded window");
  assert.ok(f.c.getHistoryItem("live-71"), "with the newest rows");
  assert.equal(f.state.selectedId, "http-62");
  assert.deepEqual(f.selections, []);
});

test("arrow keys continue from a selection live capture pushed out", async () => {
  const up = fixture();
  await up.select("http-4");
  up.capture();
  await up.c.moveHistorySelection(-1);
  assert.equal(up.state.selectedId, "http-3", "up is the row just above it, not the far end");

  const down = fixture();
  await down.select("http-4");
  down.capture();
  await down.c.moveHistorySelection(1);
  assert.equal(down.state.selectedId, "http-5", "down loads the next page and lands just below it");
});

test("a backfill that evicts the selection still moves it, as keyboard paging relies on", async () => {
  const f = fixture({ size: 5, total: 20 });
  await f.select("http-0");            // the first row; an older page will push it out
  await f.c.loadMoreTransactions({ background: true });
  assert.equal(f.c.getHistoryItem("http-0"), null);
  assert.notEqual(f.state.selectedId, "http-0", "the paging fallback ran");
  assert.ok(f.c.getHistoryItem(f.state.selectedId), "and chose a loaded row");
});
