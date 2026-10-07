const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function createFixture() {
  const state = {
    selectedWebsocketId: null, selectedWebsocketRecord: null,
    selectedWebsocketDetailError: "", websocketSessions: [], selectedFrameIdx: null,
  };
  const pending = [];
  const rendered = [];
  const context = loadFunctions(["loadWebsocketDetail"], {
    state,
    sessionId: "fixture-session-a",
    _websocketDetailGeneration: 0,
    _websocketDetailPendingId: null,
    _websocketDetailPendingSessionId: null,
    _websocketDetailPendingPromise: null,
    _websocketDetailRefreshNeeded: null,
    WEBSOCKET_DETAIL_FRAME_LIMIT: 1000,
    fetch(path) {
      const response = deferred();
      pending.push({ path, ...response });
      return response.promise;
    },
    websocketDetailRequestPath: (id, sessionId) => `${sessionId}/${id}`,
    mergeWebsocketFrameWindows: (_current, incoming) => incoming || [],
    websocketRetainedFrameCount: (_summary, frames) => frames.length,
    websocketFirstRetainedFrameIndex: () => 0,
    websocketFramesAreTruncated: () => false,
    normalizeWebsocketFrames: frames => frames || [],
    cancelWebsocketDetailLoading() {},
    hideFrameDetail() {},
    renderWebsocketSessions() { rendered.push(state.selectedWebsocketRecord); },
  });
  context.currentSessionId = () => context.sessionId;
  const select = (id) => {
    state.selectedWebsocketId = id;
    state.selectedWebsocketRecord = null;
    return context.loadWebsocketDetail(id);
  };
  const resolve = (index, record) => pending[index].resolve({ ok: true, json: async () => record });
  return { context, state, pending, rendered, select, resolve };
}

test("returning to a WebSocket row rejects its first pending detail response", async () => {
  const { state, select, resolve, rendered } = createFixture();
  const first = select("fixture-a");
  const middle = select("fixture-b");
  const latest = select("fixture-a");
  resolve(2, { id: "fixture-a", marker: "current", frames: [] });
  await latest;
  resolve(1, { id: "fixture-b", frames: [] });
  await middle;
  resolve(0, { id: "fixture-a", marker: "stale", frames: [] });
  await first;
  assert.equal(state.selectedWebsocketRecord.marker, "current");
  assert.equal(rendered.length, 1);
});

test("an older WebSocket detail failure cannot clear the current record", async () => {
  const { state, pending, select, resolve, rendered } = createFixture();
  const first = select("fixture-a");
  const latest = select("fixture-b");
  resolve(1, { id: "fixture-b", frames: [] });
  await latest;
  pending[0].resolve({ ok: false, status: 500 });
  await first;
  assert.equal(state.selectedWebsocketRecord.id, "fixture-b");
  assert.equal(state.selectedWebsocketDetailError, "");
  assert.equal(rendered.length, 1);
});

test("a WebSocket detail body parsed after selection changes stays stale", async () => {
  const { state, pending, select, resolve, rendered } = createFixture();
  const body = deferred();
  const first = select("fixture-a");
  pending[0].resolve({ ok: true, json: () => body.promise });
  await Promise.resolve();
  const latest = select("fixture-b");
  resolve(1, { id: "fixture-b", frames: [] });
  await latest;
  body.resolve({ id: "fixture-a", frames: [] });
  await first;
  assert.equal(state.selectedWebsocketRecord.id, "fixture-b");
  assert.equal(rendered.length, 1);
});

for (const duringParsing of [false, true]) {
  test(`a session switch drops WebSocket detail ${duringParsing ? "during parsing" : "before the response"}`, async () => {
    const { context, state, pending, select, resolve, rendered } = createFixture();
    const body = deferred();
    const first = select("fixture-a");
    if (duringParsing) {
      pending[0].resolve({ ok: true, json: () => body.promise });
      await Promise.resolve();
    }
    context.sessionId = "fixture-session-b";
    if (duringParsing) body.resolve({ id: "fixture-a", frames: [] });
    else resolve(0, { id: "fixture-a", frames: [] });
    await first;
    assert.equal(state.selectedWebsocketRecord, null);
    assert.deepEqual(rendered, []);
  });
}
