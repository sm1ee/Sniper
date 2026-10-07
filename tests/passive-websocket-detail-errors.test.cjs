// Passive detail-read failures: all responses and timers are synthetic.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function fixture() {
  const state = { selectedWebsocketId: "saved-a", selectedWebsocketRecord: null,
    selectedWebsocketDetailError: "", selectedFrameIdx: null, websocketSessions: [{ id: "saved-a" }] };
  const requests = [], renders = [], timers = new Map();
  let timerId = 0;
  const els = { websocketRequestView: {}, websocketResponseView: {}, websocketFramesBody: {} };
  const c = loadFunctions(["loadWebsocketDetail", "renderWebsocketSessions", "cancelWebsocketDetailLoading", "scheduleWebsocketDetailLoading"], {
    state, els, session: "session-a", _websocketDetailGeneration: 0, _websocketDetailLoadingTimer: null,
    _websocketDetailPendingId: null, _websocketDetailPendingSessionId: null, _websocketDetailPendingPromise: null,
    _websocketDetailRefreshNeeded: null, WEBSOCKET_DETAIL_FRAME_LIMIT: 2, DETAIL_LOADING_DELAY_MS: 180,
    websocketDetailRequestPath: (id, session) => `${session}:${id}`,
    fetch(path) { const request = { path, ...deferred() }; requests.push(request); return request.promise; },
    mergeWebsocketFrameWindows: (_previous, incoming) => incoming || [],
    websocketRetainedFrameCount: (_summary, frames) => frames.length, websocketFirstRetainedFrameIndex: () => 0,
    websocketFramesAreTruncated: () => false, normalizeWebsocketFrames: frames => frames || [],
    getSortedWebsocketEntries: () => state.websocketSessions, renderWebsocketSessionTable() {},
    updateWsHandshakeLineNumbers() {}, updateWsHandshakeSearch() {}, hideFrameDetail() {},
    window: { setTimeout(callback) { const id = ++timerId; timers.set(id, callback); return id; }, clearTimeout(id) { timers.delete(id); } },
  });
  c.currentSessionId = () => c.session;
  const render = c.renderWebsocketSessions;
  c.renderWebsocketSessions = () => {
    renders.push(state.selectedWebsocketDetailError || state.selectedWebsocketRecord?.id || "loading");
    if (!state.selectedWebsocketRecord) render();
  };
  c.scheduleWebsocketDetailLoading("saved-a");
  c.renderWebsocketSessions();
  return { c, state, requests, renders, timers, els };
}

for (const failure of ["network", "body"]) {
  test(`current WebSocket ${failure} failure ends loading, shows retry guidance, and can recover`, async () => {
    const f = fixture();
    const loading = f.c.loadWebsocketDetail("saved-a");
    const settled = Promise.allSettled([loading]);
    if (failure === "network") f.requests[0].reject(new Error("Fixture network failure"));
    else f.requests[0].resolve({ ok: true, json: async () => { throw new Error("Fixture body failure"); } });
    await settled;
    assert.equal(f.els.websocketRequestView.textContent, "Failed to load selected WebSocket session.");
    assert.match(f.els.websocketFramesBody.innerHTML, /Select the session again/);
    assert.doesNotMatch(f.els.websocketFramesBody.innerHTML, /Loading captured frames/);
    assert.equal(f.c._websocketDetailLoadingTimer, null);
    assert.equal(f.timers.size, 0);
    assert.equal(f.c._websocketDetailPendingPromise, null);
    const retry = f.c.loadWebsocketDetail("saved-a");
    f.requests[1].resolve({ ok: true, json: async () => ({ id: "saved-a", frames: [] }) });
    await retry;
    assert.equal(f.state.selectedWebsocketRecord.id, "saved-a");
    assert.equal(f.state.selectedWebsocketDetailError, "");
  });

  for (const change of ["newer selection", "selection return", "session switch"]) {
    test(`stale WebSocket ${failure} failure cannot alter error UI or timers after ${change}`, async () => {
      const f = fixture(), started = deferred(), body = deferred();
      const loading = f.c.loadWebsocketDetail("saved-a");
      const settled = Promise.allSettled([loading]);
      if (failure === "body") {
        f.requests[0].resolve({ ok: true, json() { started.resolve(); return body.promise; } });
        await started.promise;
      }
      if (change === "session switch") f.c.session = "session-b";
      else {
        f.c._websocketDetailGeneration += change === "selection return" ? 2 : 1;
        f.state.selectedWebsocketId = change === "selection return" ? "saved-a" : "saved-b";
      }
      f.state.selectedWebsocketDetailError = "Current view status";
      f.c.scheduleWebsocketDetailLoading(f.state.selectedWebsocketId);
      const timer = f.c._websocketDetailLoadingTimer, before = JSON.stringify(f.renders);
      if (failure === "network") f.requests[0].reject(new Error("Old failure"));
      else body.reject(new Error("Old failure"));
      await settled;
      assert.equal(f.state.selectedWebsocketDetailError, "Current view status");
      assert.equal(f.c._websocketDetailLoadingTimer, timer);
      assert.equal(f.timers.has(timer), true);
      assert.equal(JSON.stringify(f.renders), before);
    });
  }
}

test("deduplicated WebSocket reads share one handled failure and clear their pending owner", async () => {
  const f = fixture();
  const first = f.c.loadWebsocketDetail("saved-a");
  const second = f.c.loadWebsocketDetail("saved-a");
  const settled = Promise.allSettled([first, second]);
  assert.equal(f.requests.length, 1);
  f.requests[0].reject(new Error("Shared fixture failure"));
  assert.deepEqual((await settled).map(result => result.status), ["fulfilled", "fulfilled"]);
  assert.equal(f.renders.filter(value => value === "Failed to load selected WebSocket session.").length, 1);
  assert.equal(f.c._websocketDetailPendingPromise, null);
});
