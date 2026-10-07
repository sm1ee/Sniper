// Passive saved-frame paging races use synthetic deferred responses only.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const frames = values => values.map(index => ({ index, kind: "text", body_preview: "Saved fixture" }));
const record = (values = [2, 3]) => ({
  id: "saved-fixture", frames: frames(values), frame_count: 8, retained_frame_count: 8,
  last_frame_index: 7, older_frames_exhausted: false, older_frames_loading: false,
});
function fixture() {
  const state = { selectedWebsocketId: "saved-fixture", selectedFrameIdx: null, selectedWebsocketRecord: record() };
  const requests = [], rendered = [], errors = [], shell = { scrollHeight: 120, scrollTop: 20 };
  const c = loadFunctions([
    "loadOlderWebsocketFrames", "getWebsocketFrames", "normalizeWebsocketFrames", "normalizeWebsocketFrame",
    "normalizeWebsocketFrameIndex", "normalizeWebsocketCount", "websocketRetainedFrameCount",
    "websocketFirstRetainedFrameIndex", "newestWebsocketFrameIndexes", "mergeWebsocketFrameWindows",
    "capWebsocketFrameWindow", "websocketFramesAreTruncated", "applySelectedWebsocketSummary",
  ], {
    state, _websocketDetailGeneration: 1, session: "session-fixture-a",
    WEBSOCKET_MAX_LOADED_FRAMES: 10, WEBSOCKET_DETAIL_FRAME_LIMIT: 2,
    websocketFramesShell: () => shell,
    websocketDetailRequestPath: (id, session, options) => ({ id, session, ...options }),
    fetch(path) { const request = { path, ...deferred() }; requests.push(request); return request.promise; },
    renderWebsocketFrameTable() { rendered.push("frames"); },
    renderWebsocketSessions() { rendered.push("sessions"); },
    scheduleSelectedWebsocketDetailRefresh() {},
    showToast(message) { errors.push(message); }, console: { error() {} },
  });
  c.currentSessionId = () => c.session;
  return { c, state, requests, rendered, errors, shell };
}
function replaceContext(f, kind) {
  if (kind === "session switch") f.c.session = "session-fixture-b";
  else if (kind === "selection return") {
    f.state.selectedWebsocketId = "other-fixture";
    f.c._websocketDetailGeneration += 1;
    f.state.selectedWebsocketId = "saved-fixture";
    f.c._websocketDetailGeneration += 1;
  } else f.c._websocketDetailGeneration += 1;
  f.state.selectedWebsocketRecord = record([6, 7]);
  f.state.selectedWebsocketRecord.older_frames_loading = true;
  f.shell.scrollTop = 90;
}
function snapshot(f) {
  return JSON.stringify({ record: f.state.selectedWebsocketRecord, rendered: f.rendered, errors: f.errors, scroll: f.shell.scrollTop });
}

for (const kind of ["newer detail", "selection return", "session switch"]) {
  test(`older-frame parsing completed after ${kind} cannot replace its current window`, async () => {
    const f = fixture(), body = deferred(), started = deferred();
    const loading = f.c.loadOlderWebsocketFrames();
    f.requests[0].resolve({ ok: true, json() { started.resolve(); return body.promise; } });
    await started.promise;
    replaceContext(f, kind);
    const before = snapshot(f);
    body.resolve({ frames: frames([0, 1]) });
    await loading;
    assert.equal(snapshot(f), before, "stale data must not change frames, loading state, rendering, or scroll");
  });
  for (const failure of ["network", "HTTP text", "JSON"]) {
    test(`stale older-frame ${failure} failure stays silent after ${kind}`, async () => {
      const f = fixture(), delayed = deferred(), started = deferred();
      const loading = f.c.loadOlderWebsocketFrames();
      if (failure === "HTTP text") f.requests[0].resolve({ ok: false, text() { started.resolve(); return delayed.promise; } });
      if (failure === "JSON") f.requests[0].resolve({ ok: true, json() { started.resolve(); return delayed.promise; } });
      if (failure !== "network") await started.promise;
      replaceContext(f, kind);
      const before = snapshot(f);
      if (failure === "network") f.requests[0].reject(new Error("Old network failure"));
      else if (failure === "HTTP text") delayed.resolve("Old HTTP failure");
      else delayed.reject(new Error("Old JSON failure"));
      await loading;
      assert.equal(snapshot(f), before, "stale failure must not clear newer loading state or display an old error");
    });
  }
}

test("current older-frame success merges the page and clears its loading state", async () => {
  const f = fixture();
  const loading = f.c.loadOlderWebsocketFrames();
  assert.equal(f.state.selectedWebsocketRecord.older_frames_loading, true);
  assert.deepEqual(f.requests[0].path, { id: "saved-fixture", session: "session-fixture-a", beforeIndex: 2 });
  f.requests[0].resolve({ ok: true, json: async () => ({ frames: frames([0, 1]) }) });
  await loading;
  assert.deepEqual(Array.from(f.state.selectedWebsocketRecord.frames, frame => frame.index), [0, 1, 2, 3]);
  assert.equal(f.state.selectedWebsocketRecord.older_frames_loading, false);
  assert.equal(f.state.selectedWebsocketRecord.older_frames_exhausted, true);
  assert.deepEqual(f.errors, []);
});

for (const failure of ["network", "HTTP", "JSON"]) {
  test(`current older-frame ${failure} failure remains visible and can retry`, async () => {
    const f = fixture();
    const loading = f.c.loadOlderWebsocketFrames();
    if (failure === "network") f.requests[0].reject(new Error("Current failure"));
    if (failure === "HTTP") f.requests[0].resolve({ ok: false, text: async () => "Current failure" });
    if (failure === "JSON") f.requests[0].resolve({ ok: true, json: async () => { throw new Error("Current failure"); } });
    await loading;
    assert.equal(f.state.selectedWebsocketRecord.older_frames_loading, false);
    assert.deepEqual(f.errors, ["Current failure"]);
    const retry = f.c.loadOlderWebsocketFrames();
    f.requests[1].resolve({ ok: true, json: async () => ({ frames: frames([0, 1]) }) });
    await retry;
    assert.equal(f.state.selectedWebsocketRecord.older_frames_loading, false);
    assert.deepEqual(Array.from(f.state.selectedWebsocketRecord.frames, frame => frame.index), [0, 1, 2, 3]);
    assert.deepEqual(f.errors, ["Current failure"]);
  });
}

for (const outcome of ["success", "failure"]) {
  test(`a superseded older-frame ${outcome} releases its own retained record for retry`, async () => {
    const f = fixture(), body = deferred(), started = deferred();
    const original = f.state.selectedWebsocketRecord;
    const loading = f.c.loadOlderWebsocketFrames();
    f.requests[0].resolve({ ok: true, json() { started.resolve(); return body.promise; } });
    await started.promise;
    // A newer detail read can fail without replacing the retained record.
    f.c._websocketDetailGeneration += 1;
    if (outcome === "success") body.resolve({ frames: frames([0, 1]) });
    else body.reject(new Error("Stale failure"));
    await loading;
    assert.equal(f.state.selectedWebsocketRecord, original);
    assert.deepEqual(Array.from(original.frames, frame => frame.index), [2, 3]);
    assert.equal(original.older_frames_loading, false, "the completed operation must release its own loading flag");
    assert.deepEqual(f.errors, []);
    const retry = f.c.loadOlderWebsocketFrames();
    assert.equal(f.requests.length, 2, "the retained window must remain retryable");
    f.requests[1].resolve({ ok: true, json: async () => ({ frames: frames([0, 1]) }) });
    await retry;
    assert.deepEqual(Array.from(original.frames, frame => frame.index), [0, 1, 2, 3]);
  });
}


for (const outcome of ["success", "failure"]) {
  test(`a superseded older-frame ${outcome} releases loading ownership through summary clones`, async () => {
    const f = fixture(), body = deferred(), started = deferred();
    const original = f.state.selectedWebsocketRecord;
    const loading = f.c.loadOlderWebsocketFrames();
    f.requests[0].resolve({ ok: true, json() { started.resolve(); return body.promise; } });
    await started.promise;
    f.c.applySelectedWebsocketSummary({ id: "saved-fixture", frame_count: 8, retained_frame_count: 8, last_frame_index: 7 });
    const clone = f.state.selectedWebsocketRecord;
    assert.notEqual(clone, original);
    assert.equal(clone.older_frames_loading, true);
    f.c._websocketDetailGeneration += 1;
    if (outcome === "success") body.resolve({ frames: frames([0, 1]) });
    else body.reject(new Error("Stale failure"));
    await loading;
    assert.equal(f.state.selectedWebsocketRecord, clone);
    assert.deepEqual(Array.from(clone.frames, frame => frame.index), [2, 3]);
    assert.equal(clone.older_frames_loading, false, "summary-only clones share the original page's loading ownership");
    assert.equal(original.older_frames_loading, false);
    assert.deepEqual(f.errors, []);
    const retry = f.c.loadOlderWebsocketFrames();
    assert.equal(f.requests.length, 2);
    f.requests[1].resolve({ ok: true, json: async () => ({ frames: frames([0, 1]) }) });
    await retry;
    assert.deepEqual(Array.from(clone.frames, frame => frame.index), [0, 1, 2, 3]);
  });
}

for (const outcome of ["success", "failure"]) {
  test(`older-frame ${outcome} cannot change a replacement loading owner in the same generation`, async () => {
    const f = fixture(), body = deferred(), started = deferred();
    const loading = f.c.loadOlderWebsocketFrames();
    f.requests[0].resolve({ ok: true, json() { started.resolve(); return body.promise; } });
    await started.promise;
    f.state.selectedWebsocketRecord = { ...record([6, 7]), older_frames_loading: true, _olderFramesLoadToken: {} };
    const owner = f.state.selectedWebsocketRecord._olderFramesLoadToken;
    const before = snapshot(f);
    if (outcome === "success") body.resolve({ frames: frames([0, 1]) });
    else body.reject(new Error("Stale failure"));
    await loading;
    assert.equal(snapshot(f), before);
    assert.equal(f.state.selectedWebsocketRecord._olderFramesLoadToken, owner);
  });
}
