const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function createFixture(sortKey = "host", sortDirection = "asc") {
  let records = Array.from({ length: 9 }, (_, index) => ({
    id: `fixture-${index}`,
    sequence: 9 - index,
    method: "GET",
    host: "example.com",
  }));
  const state = {
    items: records.slice(0, 3),
    sortKey,
    sortDirection,
    selectedId: null,
    _itemsVersion: 0,
    historyPaging: {
      generation: 1,
      querySignature: "fixture-query",
      pageSize: 3,
      offset: 3,
      beforeSequence: null,
      total: 9,
      filteredTotal: 9,
      hasMore: true,
      fullyLoaded: false,
      loading: false,
      trimmedHeadCount: 0,
      trimmedTailCount: 0,
    },
  };
  const requestedOffsets = [];
  const context = loadFunctions([
    "isKnownCount",
    "jsonArray",
    "canUseSequenceCursorForHistoryPaging",
    "adjustHistoryPagingAfterLocalRemoval",
    "refreshHistoryPagingCursorFromItems",
    "updateHistoryPagingCursor",
    "loadMoreTransactions",
    "mergeHistoryItems",
    "trimHistoryCache",
    "reconcileHistorySelectionAfterTrim",
    "rebuildHistoryItemIndex",
    "getHistoryItem",
  ], {
    state,
    HTTP_HISTORY_MAX_LOADED_ITEMS: 3,
    createHistoryQueryState: () => ({}),
    historyQuerySignature: () => "fixture-query",
    isCurrentHistoryQuerySignature: () => true,
    async fetchTransactionPage({ offset }) {
      requestedOffsets.push(offset);
      const items = records.slice(offset, offset + 3);
      return { items, total: 9, filtered_total: records.length, has_more: offset + items.length < records.length };
    },
    applyPendingAnnotationsToItems() {},
    prepareHistoryItem() {},
    invalidateVisibleEntriesCache() {},
    adjustHistoryScrollAfterHeadTrim() {},
    renderHistory() {},
  });
  context.rebuildHistoryItemIndex();
  return {
    context,
    state,
    requestedOffsets,
    removeVisibleRow(index, options) {
      const [removed] = state.items.splice(index, 1);
      records = records.filter((item) => item.id !== removed.id);
      context.adjustHistoryPagingAfterLocalRemoval(1, options);
      context.rebuildHistoryItemIndex();
      context.refreshHistoryPagingCursorFromItems();
    },
  };
}

test("removing a filtered row after a history window trim preserves the next-page offset", async () => {
  const fixture = createFixture();
  const { context, state, requestedOffsets } = fixture;
  await context.loadMoreTransactions();
  assert.equal(state.historyPaging.trimmedHeadCount, 3);
  assert.equal(state.historyPaging.offset, 6);

  fixture.removeVisibleRow(1, { decrementTotal: false });
  assert.equal(state.historyPaging.offset, 5);
  assert.equal(state.historyPaging.total, 9);
  assert.equal(state.historyPaging.filteredTotal, 8);

  await context.loadMoreTransactions();
  assert.deepEqual(requestedOffsets, [3, 5]);
  assert.deepEqual(Array.from(state.items, (item) => item.id), ["fixture-6", "fixture-7", "fixture-8"]);
  assert.equal(state.historyPaging.fullyLoaded, true);
});

test("removing a first-page row keeps offset pagination aligned", () => {
  const fixture = createFixture();
  fixture.removeVisibleRow(1);
  assert.equal(fixture.state.historyPaging.offset, 2);
  assert.equal(fixture.state.historyPaging.total, 8);
  assert.equal(fixture.state.historyPaging.filteredTotal, 8);
});

test("removing a cursor-paged row preserves the retained-window cursor", () => {
  const fixture = createFixture("index", "desc");
  fixture.state.historyPaging.offset = 6;
  fixture.state.historyPaging.trimmedHeadCount = 3;
  fixture.removeVisibleRow(1);
  assert.equal(fixture.state.historyPaging.offset, 2);
  assert.equal(fixture.state.historyPaging.beforeSequence, 7);
});
