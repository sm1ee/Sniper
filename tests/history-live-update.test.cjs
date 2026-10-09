// A live summary for a row that is already listed updates that row. A streamed
// response is listed when it starts and again when its body finishes; dropping
// the second left the row on "0 B" and the streaming note. Fixtures only: no app
// startup, API, or captured data.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const noop = () => {};
const STREAMING = "Streaming response capture is still in progress.";

const provisional = (overrides = {}) => ({
  id: "stream-1", sequence: 1, method: "GET", host: "example.com", path: "/page",
  status: 200, response_bytes: 0, note_count: 1, has_response: true,
  note_preview: STREAMING, ...overrides,
});
const completed = (overrides = {}) => ({
  id: "stream-1", sequence: 1, method: "GET", host: "example.com", path: "/page",
  status: 200, response_bytes: 1226, note_count: 0, has_response: true, ...overrides,
});

function fixture(items = []) {
  const state = {
    items: items.map((item) => ({ ...item })), selectedId: null, selectedRecord: null,
    _itemsVersion: 0, sortKey: "index", sortDirection: "desc",
    historyPaging: { trimmedHeadCount: 0, offset: items.length, total: items.length, filteredTotal: items.length },
  };
  const pending = [];
  const reloads = [];
  const c = loadFunctions([
    "flushTransactionDeltas", "applyLiveSummaryUpdate", "mergeHistoryItems",
    "rebuildHistoryItemIndex", "getHistoryItem", "canReuseSelectedHistoryRecord",
    "historyRecordSummarySignature", "applyPendingAnnotationsToItems",
  ], {
    state, _pendingTransactionSummaries: pending, _historyFullLoadInFlight: false, _searchActiveUntil: 0,
    console, Date,
    isHttpHistoryVisible: () => true, canMergeRecentTransactions: () => true,
    summaryMatchesActiveHistoryFilters: () => true, canUseSequenceCursorForHistoryPaging: () => false,
    isKnownCount: (value) => Number.isFinite(value),
    scheduleTransactionDeltaFlush: noop, scheduleIncrementalRefresh: noop,
    prepareHistoryItem: (item) => item, trimHistoryCache: noop,
    invalidateVisibleEntriesCache: noop, resortLoadedHistoryItemsForCurrentSort: noop, renderHistory: noop,
    async loadTransactionDetail(id) { reloads.push(id); return null; },
  });
  c.currentSessionId = () => "session-a";
  c.rebuildHistoryItemIndex();
  const deliver = (...summaries) => {
    for (const summary of summaries) pending.push({ sessionId: "session-a", summary });
    c.flushTransactionDeltas();
  };
  return { c, state, deliver, reloads };
}

test("a streamed response that finishes updates its row", () => {
  const f = fixture([provisional()]);
  f.deliver(completed());
  const row = f.c.getHistoryItem("stream-1");
  assert.equal(f.state.items.length, 1, "updated in place, not listed twice");
  assert.equal(row.response_bytes, 1226);
  assert.equal(row.note_count, 0);
  assert.equal(row.note_preview, null, "the omitted preview clears the streaming note");
});

test("an update leaves the operator's annotations to their own save path", () => {
  const f = fixture([provisional({
    color_tag: "red", has_user_note: true, note_preview: "check this", annotation_revision: 7,
  })]);
  // The server's summary carries no annotation fields here, as when it was built
  // before the note was saved.
  f.deliver(completed());
  const row = f.c.getHistoryItem("stream-1");
  assert.equal(row.response_bytes, 1226);
  assert.equal(row.color_tag, "red");
  assert.equal(row.has_user_note, true);
  assert.equal(row.note_preview, "check this");
  assert.equal(row.annotation_revision, 7);
});

test("a start and a finish in one flush list the finished record once", () => {
  const f = fixture();
  f.deliver(provisional(), completed());
  assert.equal(f.state.items.length, 1);
  assert.equal(f.state.items[0].response_bytes, 1226);
  assert.equal(f.state.items[0].note_preview ?? null, null);
});

test("the inspector reloads a selected record that changed underneath it", () => {
  const f = fixture([provisional()]);
  f.state.selectedId = "stream-1";
  f.state.selectedRecord = { id: "stream-1", sequence: 1, method: "GET", host: "example.com", path: "/page",
    status: 200, response: { body_size: 0 }, notes: [STREAMING] };
  f.deliver(completed());
  assert.deepEqual(f.reloads, ["stream-1"]);
});
