// The shipped Capture binding with deferred in-memory responses only. No
// bootstrap, runtime, settings, proxy, scanner, socket or persistent writes.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function fixture(capturing) {
  const requests = [], actions = [], toasts = [], scopeChanges = [], timers = new Map(), classes = new Set();
  let nextTimer = 0, listener;
  const button = {
    disabled: false, textContent: "", title: "",
    classList: {
      add: (...names) => names.forEach(name => classes.add(name)),
      remove: (...names) => names.forEach(name => classes.delete(name)),
      toggle(name, enabled) { if (enabled) classes.add(name); else classes.delete(name); },
    },
    addEventListener(event, callback) { assert.equal(event, "click"); listener = callback; },
  };
  const state = { activeSession: { id: "session-a" }, runtime: { http_capture_enabled: capturing, marker: "session-a" } };
  const c = loadFunctions([
    "onClickWithProgress", "withButtonProgress", "syncHttpCapturePill", "currentSessionId",
    "sessionWritePath", "expectedActiveSessionIdForWrite", "postRuntimeSettings",
    "requireOkResponse", "readApiErrorMessage", "formatStructuredApiErrorMessage",
  ], {
    state, URLSearchParams, BUTTON_PROGRESS_DELAY_MS: 180,
    document: { getElementById(id) { assert.equal(id, "httpCaptureToggle"); return button; } },
    console: { error() {} }, showToast: (...args) => toasts.push(args),
    targetServiceMapController: { scopeChanged: (...args) => scopeChanges.push(args) },
    fetch(path, options) {
      assert.equal(path, "/api/runtime?session_id=session-a&expected_active_session_id=session-a");
      assert.equal(options.method, "POST");
      assert.deepEqual({ ...options.headers }, { "content-type": "application/json" });
      assert.deepEqual(JSON.parse(options.body), { http_capture_enabled: !capturing });
      const request = { path, options, ...deferred() };
      requests.push(request);
      return request.promise;
    },
    setTimeout(callback, delay) {
      assert.equal(delay, 180);
      timers.set(++nextTimer, callback);
      return nextTimer;
    },
    clearTimeout: id => timers.delete(id),
  });
  const withProgress = c.withButtonProgress;
  c.withButtonProgress = (...args) => {
    const action = withProgress(...args);
    actions.push(action);
    return action;
  };
  const start = appSource.indexOf('  onClickWithProgress(document.getElementById("httpCaptureToggle"),');
  const end = appSource.indexOf('\n\n  document.getElementById("clearHistoryButton")', start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(appSource.slice(start, end), c, { filename: "production-capture-toggle-binding" });
  c.syncHttpCapturePill();
  function click() { listener({ currentTarget: button }); return actions.at(-1); }
  function changeSession() {
    state.activeSession = { id: "session-b" };
    state.runtime = { http_capture_enabled: capturing, marker: "session-b" };
    c.syncHttpCapturePill();
  }
  return { c, state, button, classes, timers, requests, actions, toasts, scopeChanges, click, changeSession };
}

function assertIdle(f, capturing) {
  assert.equal(f.button.disabled, false);
  assert.equal(f.button._buttonProgress, undefined);
  assert.equal(f.classes.has("is-working"), false);
  assert.equal(f.classes.has("is-working-shown"), false);
  assert.equal(f.timers.size, 0);
  assert.equal(f.button.textContent, capturing ? "Capturing" : "Paused");
  assert.equal(f.classes.has("active"), capturing);
  assert.equal(f.classes.has("paused"), !capturing);
  assert.match(f.button.title, capturing ? /Click to pause/ : /Click to resume/);
}

async function deferFailure(request, failure) {
  if (failure === "network") return () => request.reject(new Error("Fixture network failure"));
  const body = deferred(), reading = deferred();
  if (failure.startsWith("HTTP")) {
    request.resolve({ ok: false, headers: { get: () => "text/plain" }, text() { reading.resolve(); return body.promise; } });
  } else {
    request.resolve({ ok: true, json() { reading.resolve(); return body.promise; } });
  }
  await reading.promise;
  if (failure === "HTTP") return () => body.resolve("Fixture HTTP failure");
  return () => body.reject(new Error(`Fixture ${failure} failure`));
}

for (const capturing of [true, false]) {
  const action = capturing ? "pause" : "resume";
  test(`${action} preserves confirmed status and blocks repeat clicks until success`, async () => {
    const f = fixture(capturing), initialRuntime = f.state.runtime;
    const pending = f.click();
    await f.click();
    assert.equal(f.requests.length, 1);
    assert.equal(f.state.runtime, initialRuntime);
    assert.equal(f.button.textContent, capturing ? "Capturing" : "Paused");
    assert.equal(f.button.disabled, true);
    assert.equal(f.classes.has("is-working"), true);
    assert.equal(f.timers.size, 1);
    [...f.timers.values()][0]();
    assert.equal(f.classes.has("is-working-shown"), true);
    const runtime = { http_capture_enabled: !capturing, marker: "confirmed response" };
    f.requests[0].resolve({ ok: true, json: async () => runtime });
    await pending;
    assert.equal(f.state.runtime, runtime);
    assert.equal(f.scopeChanges.length, 1);
    assert.deepEqual(f.toasts, []);
    assertIdle(f, !capturing);
  });

  for (const failure of ["network", "HTTP", "HTTP body", "JSON"]) {
    for (const stale of [false, true]) {
      test(`${action} delayed ${failure} failure ${stale ? "cannot notify a different session" : "reports in its own session"} and releases progress`, async () => {
        const f = fixture(capturing), pending = f.click();
        const fail = await deferFailure(f.requests[0], failure);
        if (stale) f.changeSession();
        const currentRuntime = f.state.runtime;
        [...f.timers.values()][0]();
        await f.click();
        assert.equal(f.requests.length, 1, "pending failure still prevents duplicate writes");
        assert.equal(f.button.disabled, true);
        fail();
        await pending;
        assert.equal(f.state.runtime, currentRuntime);
        assert.deepEqual(f.scopeChanges, []);
        assertIdle(f, capturing);
        const message = failure === "HTTP body" ? "Failed to change capture." : `Fixture ${failure} failure`;
        assert.deepEqual(f.toasts, stale ? [] : [[message, "error"]]);
      });
    }
  }

  test(`${action} current-session failure without a message keeps the fallback feedback`, async () => {
    const f = fixture(capturing), pending = f.click(), currentRuntime = f.state.runtime;
    f.requests[0].reject(new Error(""));
    await pending;
    assert.equal(f.state.runtime, currentRuntime);
    assert.deepEqual(f.toasts, [["Failed to change capture.", "error"]]);
    assertIdle(f, capturing);
  });

  for (const stage of ["response", "JSON body"]) {
    test(`${action} delayed success at ${stage} cannot repaint a different session`, async () => {
      const f = fixture(capturing), pending = f.click();
      const runtime = { http_capture_enabled: !capturing, marker: "old response" };
      let finish;
      if (stage === "JSON body") {
        const body = deferred(), reading = deferred();
        f.requests[0].resolve({ ok: true, json() { reading.resolve(); return body.promise; } });
        await reading.promise;
        finish = () => body.resolve(runtime);
      } else {
        finish = () => f.requests[0].resolve({ ok: true, json: async () => runtime });
      }
      f.changeSession();
      const currentRuntime = f.state.runtime;
      finish();
      await pending;
      assert.equal(f.state.runtime, currentRuntime);
      assert.deepEqual(f.scopeChanges, []);
      assert.deepEqual(f.toasts, []);
      assertIdle(f, capturing);
    });
  }
}
