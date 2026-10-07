const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

// Load only the history-cache functions. App startup, network access, and other
// tool workflows are deliberately excluded from this local UI regression test.
const source = fs.readFileSync(path.join(__dirname, "../web/app.js"), "utf8");
const functionNames = [
  "mergeHistoryItems",
  "trimHistoryCache",
  "reconcileHistorySelectionAfterTrim",
  "moveHistorySelectionIfMissing",
  "rebuildHistoryItemIndex",
  "getHistoryItem",
];
const historyFunctions = functionNames.map((name) => {
  const declaration = source.match(new RegExp(`^function ${name}\\([^]*?^}`, "m"));
  assert.ok(declaration, `Missing history function: ${name}`);
  return declaration[0];
}).join("\n");
const limitDeclaration = source.match(/^const HTTP_HISTORY_PAGE_SIZE = (\d+);$/m);
assert.ok(limitDeclaration, "Missing HTTP history page size");
const limit = Number(limitDeclaration[1]);
assert.match(source, /^const HTTP_HISTORY_MAX_LOADED_ITEMS = HTTP_HISTORY_PAGE_SIZE;$/m);

function createFixture(selectedId) {
  const state = {
    items: Array.from({ length: limit }, (_, index) => ({
      id: String(limit - index),
      sequence: limit - index,
      method: "GET",
    })),
    selectedId,
    _itemsVersion: 0,
    historyPaging: { trimmedHeadCount: 0, trimmedTailCount: 0 },
  };
  const selections = [];
  const context = vm.createContext({
    state,
    HTTP_HISTORY_MAX_LOADED_ITEMS: limit,
    console,
    applyPendingAnnotationsToItems() {},
    prepareHistoryItem() {},
    invalidateVisibleEntriesCache() {},
    refreshHistoryPagingCursorFromItems() {},
    adjustHistoryScrollAfterHeadTrim() {},
    async selectHistoryTransaction(id) {
      state.selectedId = id;
      selections.push(id);
    },
  });
  vm.runInContext(historyFunctions, context);
  context.rebuildHistoryItemIndex();
  return { context, state, selections };
}

test("prepending at the cache limit moves an evicted selection to the last retained row", () => {
  const { context, state, selections } = createFixture("1");
  context.mergeHistoryItems([{ id: String(limit + 1), sequence: limit + 1, method: "GET" }], { prepend: true });

  assert.equal(state.items.length, limit);
  assert.equal(context.getHistoryItem("1"), null);
  assert.equal(state.selectedId, "2");
  assert.deepEqual(selections, ["2"]);
});

test("appending at the cache limit moves an evicted selection to the first retained row", () => {
  const { context, state, selections } = createFixture(String(limit));
  context.mergeHistoryItems([{ id: "0", sequence: 0, method: "GET" }]);

  assert.equal(state.items.length, limit);
  assert.equal(context.getHistoryItem(String(limit)), null);
  assert.equal(state.selectedId, String(limit - 1));
  assert.deepEqual(selections, [String(limit - 1)]);
});

test("trimming preserves a selected row that remains in the cache", () => {
  const { context, state, selections } = createFixture("2");
  context.mergeHistoryItems([{ id: String(limit + 1), sequence: limit + 1, method: "GET" }], { prepend: true });

  assert.equal(state.selectedId, "2");
  assert.ok(context.getHistoryItem(state.selectedId));
  assert.deepEqual(selections, []);
});
