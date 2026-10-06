const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function createFixture() {
  const state = { selectedId: null, selectedRecord: null, loadingDetailId: null, items: [] };
  const pending = [];
  const rendered = [];
  const context = loadFunctions(["selectHistoryTransaction", "loadTransactionDetail"], {
    state,
    sessionId: "fixture-session-a",
    _historyDetailGeneration: 0,
    fetch(path) {
      const response = deferred();
      pending.push({ path, ...response });
      return response.promise;
    },
    transactionPath: (id, sessionId) => `${sessionId}/${id}`,
    canReuseSelectedHistoryRecord: () => false,
    updateHistorySelection() {},
    scheduleHistoryDetailLoading() {},
    scrollSelectedHistoryRowIntoView() {},
    observeAnnotationRevision() {},
    renderEmptyDetail() { rendered.push(null); },
    renderDetail(record) { rendered.push(record); },
  });
  context.currentSessionId = () => context.sessionId;
  const resolve = (index, record) => pending[index].resolve({ ok: true, json: async () => record });
  return { context, state, pending, rendered, resolve };
}

test("a detail response for a previous selection does not replace the current record", async () => {
  const { context, state, resolve } = createFixture();
  const first = context.selectHistoryTransaction("fixture-a");
  const second = context.selectHistoryTransaction("fixture-b");
  const current = { id: "fixture-b", marker: "current" };
  resolve(1, current);
  await second;
  resolve(0, { id: "fixture-a", marker: "stale" });
  assert.equal(await first, null);
  assert.equal(state.selectedRecord, current);
});

test("returning to the same row cannot let an earlier detail load overwrite the newest one", async () => {
  const { context, state, resolve, rendered } = createFixture();
  const first = context.selectHistoryTransaction("fixture-a");
  const middle = context.selectHistoryTransaction("fixture-b");
  const latest = context.selectHistoryTransaction("fixture-a");
  const current = { id: "fixture-a", marker: "current" };
  resolve(2, current);
  await latest;
  resolve(1, { id: "fixture-b" });
  await middle;
  resolve(0, { id: "fixture-a", marker: "stale" });
  assert.equal(await first, null);
  assert.equal(state.selectedRecord, current);
  assert.deepEqual(rendered, [current]);
});

test("a stale detail error cannot clear a newer selection of the same row", async () => {
  const { context, state, pending, resolve } = createFixture();
  const first = context.selectHistoryTransaction("fixture-a");
  const latest = context.selectHistoryTransaction("fixture-a");
  const current = { id: "fixture-a", marker: "current" };
  resolve(1, current);
  await latest;
  pending[0].resolve({ ok: false, status: 500 });
  await first;
  assert.equal(state.selectedId, "fixture-a");
  assert.equal(state.selectedRecord, current);
});

test("a response that finishes parsing after a newer load stays stale", async () => {
  const { context, state, pending, resolve } = createFixture();
  const body = deferred();
  const first = context.selectHistoryTransaction("fixture-a");
  pending[0].resolve({ ok: true, json: () => body.promise });
  await Promise.resolve();
  const latest = context.selectHistoryTransaction("fixture-a");
  const current = { id: "fixture-a", marker: "current" };
  resolve(1, current);
  await latest;
  body.resolve({ id: "fixture-a", marker: "stale" });
  assert.equal(await first, null);
  assert.equal(state.selectedRecord, current);
});

for (const duringParsing of [false, true]) {
  test(`a session switch drops stale detail ${duringParsing ? "during parsing" : "before the response"}`, async () => {
    const { context, state, pending, resolve, rendered } = createFixture();
    const body = deferred();
    const first = context.selectHistoryTransaction("fixture-a");
    if (duringParsing) {
      pending[0].resolve({ ok: true, json: () => body.promise });
      await Promise.resolve();
    }
    context.sessionId = "fixture-session-b";
    if (duringParsing) body.resolve({ id: "fixture-a", marker: "stale" });
    else resolve(0, { id: "fixture-a", marker: "stale" });
    assert.equal(await first, null);
    assert.equal(state.selectedRecord, null);
    assert.deepEqual(rendered, []);
  });
}
