// Offline saved-frame window checks, without any socket or HTTP activity.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");
function fixture() {
  const state = { selectedWebsocketId: "saved-fixture", selectedWebsocketRecord: { loaded_last_frame_index: null } };
  const c = loadFunctions([
    "normalizeWebsocketFrameIndex", "normalizeWebsocketCount", "capWebsocketFrameWindow",
    "loadWebsocketDetail", "websocketFramesAreTruncated",
    "mergeWebsocketFrameWindows", "normalizeWebsocketFrames", "normalizeWebsocketFrame",
    "selectedWebsocketDetailMeetsRefreshTarget", "mergeWebsocketDetailRefreshTarget",
    "websocketFirstRetainedFrameIndex", "websocketRetainedFrameCount", "websocketDetailRequestPath",
  ], {
    state, WEBSOCKET_MAX_LOADED_FRAMES: 3, WEBSOCKET_DETAIL_FRAME_LIMIT: 2,
    _websocketDetailRefreshNeeded: null, URLSearchParams,
    sessionQueryPath: path => path,
  });
  return { c, state };
}
const indexes = frames => Array.from(frames, frame => frame.index);
const frames = values => values.map(index => ({ index, kind: "text", body_preview: "Saved fixture" }));

for (const absent of [null, undefined]) {
  test(`an absent selected frame (${String(absent)}) does not pin frame zero`, () => {
    const { c } = fixture();
    assert.deepEqual(indexes(c.capWebsocketFrameWindow(frames([0, 1, 2, 3, 4]),
      { prefer: "latest", preserveIndexes: [absent] })), [2, 3, 4]);
  });
}

test("refreshing the saved frame window without a selection retains the latest contiguous frames", () => {
  const { c } = fixture();
  const current = frames([0, 1, 2]), incoming = frames([3, 4]);
  const before = JSON.stringify([current, incoming]);
  assert.deepEqual(indexes(c.mergeWebsocketFrameWindows(current, incoming,
    { prefer: "latest", preserveIndexes: [null] })), [2, 3, 4]);
  assert.equal(JSON.stringify([current, incoming]), before);
});

test("explicitly selecting frame zero continues to preserve it", () => {
  const { c } = fixture();
  for (const index of [0, "0"]) {
    assert.deepEqual(indexes(c.capWebsocketFrameWindow(frames([0, 1, 2, 3, 4]),
      { prefer: "latest", preserveIndexes: [index] })), [0, 3, 4]);
  }
});

test("an absent loaded last-frame index cannot satisfy a pending first-frame refresh", () => {
  const { c, state } = fixture();
  const target = { id: "saved-fixture", lastFrameIndex: 0 };
  assert.equal(c.selectedWebsocketDetailMeetsRefreshTarget(target), false);
  state.selectedWebsocketRecord.loaded_last_frame_index = 0;
  assert.equal(c.selectedWebsocketDetailMeetsRefreshTarget(target), true);
});

test("an unspecified refresh target stays unknown rather than becoming frame zero", () => {
  const { c, state } = fixture();
  const target = c.mergeWebsocketDetailRefreshTarget("saved-fixture");
  assert.equal(target.lastFrameIndex, null);
  state.selectedWebsocketRecord.loaded_last_frame_index = 4;
  assert.equal(c.selectedWebsocketDetailMeetsRefreshTarget(target), false);
  c._websocketDetailRefreshNeeded = { id: "saved-fixture", lastFrameIndex: 5 };
  assert.equal(c.mergeWebsocketDetailRefreshTarget("saved-fixture", null).lastFrameIndex, 5);
});

test("an absent saved last-frame index falls back to the first retained loaded frame", () => {
  const { c } = fixture();
  assert.equal(c.websocketFirstRetainedFrameIndex({ retained_frame_count: 3, last_frame_index: null },
    frames([40, 41, 42])), 40);
});

test("an absent before-frame cursor is omitted but an explicit zero remains valid", () => {
  const { c } = fixture();
  const absent = c.websocketDetailRequestPath("saved-fixture", "session-fixture", { beforeIndex: null });
  assert.doesNotMatch(absent, /before_index/);
  assert.match(c.websocketDetailRequestPath("saved-fixture", "session-fixture", { beforeIndex: 0 }), /before_index=0/);
});

test("ordinary numeric frame indexes preserve their existing behavior", () => {
  const { c } = fixture();
  for (const value of [0, 1, 42, "0", "42"]) assert.equal(c.normalizeWebsocketFrameIndex(value), Number(value));
  for (const value of [undefined, NaN, Infinity, "missing"]) assert.equal(c.normalizeWebsocketFrameIndex(value), null);
});


test("a first-frame update queued behind stale empty detail schedules a follow-up read", async () => {
  const { c, state } = fixture();
  state.selectedWebsocketRecord = null;
  state.selectedFrameIdx = null;
  state.websocketSessions = [{ id: "saved-fixture", frame_count: 1, retained_frame_count: 1, last_frame_index: 0 }];
  const scheduled = [];
  Object.assign(c, {
    _websocketDetailGeneration: 0, _websocketDetailPendingId: null,
    _websocketDetailPendingSessionId: null, _websocketDetailPendingPromise: null,
    currentSessionId: () => "session-fixture", hideFrameDetail() {},
    cancelWebsocketDetailLoading() {}, renderWebsocketSessions() {},
    scheduleSelectedWebsocketDetailRefresh(id, lastFrameIndex) { scheduled.push({ id, lastFrameIndex }); },
  });
  let resolve;
  c.fetch = () => new Promise(done => { resolve = done; });
  const first = c.loadWebsocketDetail("saved-fixture");
  const queued = c.loadWebsocketDetail("saved-fixture", { force: true, lastFrameIndex: 0 });
  resolve({ ok: true, json: async () => ({ id: "saved-fixture", frames: [] }) });
  await Promise.all([first, queued]);
  assert.equal(state.selectedWebsocketRecord.loaded_last_frame_index, null);
  assert.deepEqual(scheduled, [{ id: "saved-fixture", lastFrameIndex: 0 }]);
  assert.equal(c._websocketDetailRefreshNeeded.lastFrameIndex, 0);
});
