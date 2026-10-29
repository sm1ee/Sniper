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
  const requests = [], reads = [], paths = [], actions = [], toasts = [], scopeChanges = [], timers = new Map(), classes = new Set();
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
  const state = { activeTool: "proxy", activeSession: { id: "session-a" }, runtime: { http_capture_enabled: capturing, marker: "session-a" } };
  const c = loadFunctions([
    "onClickWithProgress", "withButtonProgress", "syncHttpCapturePill", "currentSessionId",
    "sessionWritePath", "sessionQueryPath", "expectedActiveSessionIdForWrite", "postRuntimeSettings",
    "loadRuntimeSettings", "loadTargetSiteMap", "jsonArray",
    "requireOkResponse", "readApiErrorMessage", "formatStructuredApiErrorMessage",
  ], {
    state, URLSearchParams, BUTTON_PROGRESS_DELAY_MS: 180,
    workspaceStateGeneration: 0,
    els: { targetScopeEditor: { value: "" }, targetScopeExcludeEditor: { value: "" } },
    syncTargetScopeDraft() {}, renderInterceptStatus() {}, renderProxySettings() {}, renderTarget() {},
    document: { getElementById(id) { assert.equal(id, "httpCaptureToggle"); return button; } },
    console: { error() {} }, showToast: (...args) => toasts.push(args),
    targetServiceMapController: { scopeChanged: (...args) => scopeChanges.push(args) },
    fetch(path, options) {
      if (!options) {
        if (path === `/api/target/site-map?session_id=${state.activeSession.id}`) {
          const read = { path, ...deferred() };
          paths.push(read);
          return read.promise;
        }
        assert.equal(path, `/api/runtime?session_id=${state.activeSession.id}`);
        const read = { path, ...deferred() };
        reads.push(read);
        return read.promise;
      }
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
  return { c, state, button, classes, timers, requests, reads, paths, actions, toasts, scopeChanges, click, changeSession };
}

function assertIdle(f, capturing, { unconfirmed = false } = {}) {
  assert.equal(f.button.disabled, false);
  assert.equal(f.button._buttonProgress, undefined);
  assert.equal(f.classes.has("is-working"), false);
  assert.equal(f.classes.has("is-working-shown"), false);
  assert.equal(f.timers.size, 0);
  assert.equal(f.button.textContent, unconfirmed ? "Capture unconfirmed" : capturing ? "Capturing" : "Paused");
  assert.equal(f.classes.has("active"), capturing && !unconfirmed);
  assert.equal(f.classes.has("paused"), !capturing && !unconfirmed);
  if (unconfirmed) {
    assert.match(f.button.title, capturing ? /Last confirmed: Capturing/ : /Last confirmed: Paused/);
    assert.match(f.button.title, capturing ? /Click to request capture off/ : /Click to request capture on/);
  } else {
    assert.match(f.button.title, capturing ? /Click to pause/ : /Click to resume/);
  }
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

async function makeUnconfirmed(f) {
  const pending = f.click();
  const fail = await deferFailure(f.requests.at(-1), "JSON");
  fail();
  await pending;
}

async function deferCaptureBody(f) {
  const pending = f.click(), body = deferred(), reading = deferred();
  f.requests.at(-1).resolve({ ok: true, json() { reading.resolve(); return body.promise; } });
  await reading.promise;
  return { pending, body };
}

for (const capturing of [true, false]) {
  const action = capturing ? "pause" : "resume";
  for (const [shape, runtime] of [
    ["null", null], ["missing field", {}], ["array", []],
    ["null field", { http_capture_enabled: null }],
    ["string field", { http_capture_enabled: "false" }],
    ["numeric field", { http_capture_enabled: 0 }],
  ]) {
    for (const alreadyUnconfirmed of [false, true]) {
      test(`${action} successful ${shape} JSON cannot confirm capture${alreadyUnconfirmed ? " or clear earlier uncertainty" : ""}`, async () => {
        const f = fixture(capturing), lastConfirmed = f.state.runtime;
        if (alreadyUnconfirmed) await makeUnconfirmed(f);
        const pending = f.click();
        f.requests.at(-1).resolve({ ok: true, json: async () => runtime });
        await pending;
        assert.equal(f.state.runtime, lastConfirmed);
        assert.equal(f.scopeChanges.length, 0, "invalid response cannot reach runtime consumers");
        assertIdle(f, capturing, { unconfirmed: true });
        assert.deepEqual(f.toasts.at(-1), ["Capture may have changed, but its current state could not be confirmed.", "error", 7000]);
        assert.equal(f.reads.length, 0);
        assert.equal(f.requests.length, alreadyUnconfirmed ? 2 : 1);
      });
    }

    for (const reader of ["loadRuntimeSettings", "loadTargetSiteMap"]) {
      test(`${action} ${reader} ${shape} JSON cannot replace runtime, clear uncertainty or advance acceptance`, async () => {
        const f = fixture(capturing), lastConfirmed = f.state.runtime;
        await makeUnconfirmed(f);
        f.state._runtimeReadVersion = 7;
        f.state._runtimeReadAcceptedVersion = 7;
        f.state._runtimeReadAcceptedSessionId = "session-a";
        const read = f.c[reader]();
        f.reads[0].resolve({ ok: true, json: async () => runtime });
        await assert.rejects(read, /valid capture state/i);
        assert.equal(f.state.runtime, lastConfirmed);
        assert.equal(f.state._runtimeReadAcceptedVersion, 7);
        assert.equal(f.state._runtimeReadAcceptedSessionId, "session-a");
        assert.equal(f.scopeChanges.length, 0);
        assertIdle(f, capturing, { unconfirmed: true });
      });

      test(`${action} ${reader} ${shape} JSON during pending Capture response cannot suppress its later failure`, async () => {
        const f = fixture(capturing), lastConfirmed = f.state.runtime;
        const { pending, body } = await deferCaptureBody(f);
        const read = f.c[reader]();
        f.reads[0].resolve({ ok: true, json: async () => runtime });
        await assert.rejects(read, /valid capture state/i);
        body.reject(new Error("Delayed Capture response failed"));
        await pending;
        assert.equal(f.state.runtime, lastConfirmed);
        assert.equal(f.state._runtimeReadAcceptedVersion || 0, 0);
        assert.equal(f.state._runtimeReadAcceptedSessionId, undefined);
        assertIdle(f, capturing, { unconfirmed: true });
        assert.equal(f.toasts.length, 1);
      });
    }
  }

  for (const confirmed of [true, false]) {
    test(`${action} minimal successful Boolean ${confirmed} remains a valid Capture response`, async () => {
      const f = fixture(capturing);
      await makeUnconfirmed(f);
      const pending = f.click(), runtime = { http_capture_enabled: confirmed };
      f.requests.at(-1).resolve({ ok: true, json: async () => runtime });
      await pending;
      assert.equal(f.state.runtime, runtime);
      assertIdle(f, confirmed);
      assert.equal(f.toasts.length, 1, "only the earlier unreadable response reports uncertainty");
    });
  }

  test(`${action} invalid Capture response from a stale session cannot disturb its successor`, async () => {
    const f = fixture(capturing), pending = f.click();
    f.changeSession();
    const runtime = f.state.runtime;
    f.requests[0].resolve({ ok: true, json: async () => null });
    await pending;
    assert.equal(f.state.runtime, runtime);
    assert.deepEqual(f.toasts, []);
    assert.equal(f.scopeChanges.length, 0);
    assertIdle(f, capturing);
  });

  for (const reader of ["loadRuntimeSettings", "loadTargetSiteMap"]) {
    for (const owner of ["session", "workspace"]) {
      test(`${action} invalid ${reader} response with stale ${owner} retains existing no-op behavior`, async () => {
        const f = fixture(capturing), runtime = f.state.runtime;
        await makeUnconfirmed(f);
        const read = f.c[reader]();
        if (owner === "session") f.changeSession();
        else f.c.workspaceStateGeneration += 1;
        f.reads[0].resolve({ ok: true, json: async () => ({}) });
        await read;
        if (owner === "session") {
          assertIdle(f, capturing);
          f.state.activeSession = { id: "session-a" };
          f.state.runtime = runtime;
          f.c.syncHttpCapturePill();
        }
        assert.equal(f.state.runtime, runtime);
        assert.equal(f.state._runtimeReadAcceptedVersion || 0, 0);
        assert.equal(f.state._runtimeReadAcceptedSessionId, undefined);
        assert.equal(f.scopeChanges.length, 0);
        assertIdle(f, capturing, { unconfirmed: true });
      });
    }
  }

  test(`${action} invalid compound Scope runtime cannot adopt otherwise successful paths`, async () => {
    const f = fixture(capturing), runtime = f.state.runtime;
    await makeUnconfirmed(f);
    f.state.activeTool = "target";
    const paths = f.state.targetSiteMap = [{ host: "cached.example.com" }];
    const read = f.c.loadTargetSiteMap();
    f.reads[0].resolve({ ok: true, json: async () => ({}) });
    f.paths[0].resolve({ ok: true, json: async () => [{ host: "new.example.com" }] });
    await assert.rejects(read, /valid capture state/i);
    assert.equal(f.state.runtime, runtime);
    assert.equal(f.state.targetSiteMap, paths);
    assert.equal(f.state._runtimeReadAcceptedVersion || 0, 0);
    assert.equal(f.scopeChanges.length, 0);
    assertIdle(f, capturing, { unconfirmed: true });
  });

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
        assertIdle(f, capturing, { unconfirmed: ["network", "JSON"].includes(failure) && !stale });
        const feedback = ["network", "JSON"].includes(failure)
          ? ["Capture may have changed, but its current state could not be confirmed.", "error", 7000]
          : [failure === "HTTP body" ? "Failed to change capture." : `Fixture ${failure} failure`, "error"];
        assert.deepEqual(f.toasts, stale ? [] : [feedback]);
      });
    }
  }

  test(`${action} response-less failure without a message reports uncertainty rather than definite failure`, async () => {
    const f = fixture(capturing), pending = f.click(), currentRuntime = f.state.runtime;
    f.requests[0].reject(new Error(""));
    await pending;
    assert.equal(f.state.runtime, currentRuntime);
    assert.deepEqual(f.toasts, [["Capture may have changed, but its current state could not be confirmed.", "error", 7000]]);
    assertIdle(f, capturing, { unconfirmed: true });
  });

  test(`${action} fake acceptance with no response cannot leave a definitive old pill`, async () => {
    const f = fixture(capturing), runtime = f.state.runtime, pending = f.click();
    await f.click();
    assert.equal(f.requests.length, 1, "repeated click cannot dispatch while outcome is pending");
    const fakeAcceptedState = JSON.parse(f.requests[0].options.body).http_capture_enabled;
    assert.equal(fakeAcceptedState, !capturing);
    f.requests[0].reject(new TypeError("Response lost after fake acceptance"));
    await pending;
    assert.equal(f.state.runtime, runtime, "do not optimistically claim the fake outcome is confirmed");
    assertIdle(f, capturing, { unconfirmed: true });
    f.c.syncHttpCapturePill();
    assertIdle(f, capturing, { unconfirmed: true });
    assert.equal(f.reads.length, 0, "a transport failure never starts a reconciliation read");
    assert.equal(f.requests.length, 1, "a transport failure never retries automatically");
    assert.deepEqual(f.toasts, [["Capture may have changed, but its current state could not be confirmed.", "error", 7000]]);
  });

  test(`${action} transport uncertainty survives a repeated transport failure and definite refusal until explicit success`, async () => {
    const f = fixture(capturing), runtime = f.state.runtime;
    for (let index = 0; index < 2; index++) {
      const pending = f.click();
      f.requests[index].reject(new TypeError("No response"));
      await pending;
      assert.equal(f.state.runtime, runtime);
      assertIdle(f, capturing, { unconfirmed: true });
    }
    const refused = f.click();
    const refuse = await deferFailure(f.requests[2], "HTTP");
    refuse(); await refused;
    assert.deepEqual(f.toasts.at(-1), ["Fixture HTTP failure", "error"]);
    assertIdle(f, capturing, { unconfirmed: true });
    const retry = f.click();
    f.requests[3].resolve({ ok: true, json: async () => ({ http_capture_enabled: !capturing }) });
    await retry;
    assertIdle(f, !capturing);
    assert.equal(f.reads.length, 0);
    assert.equal(f.requests.length, 4, "only the four explicit actions dispatched");
  });

  for (const reader of ["loadRuntimeSettings", "loadTargetSiteMap"]) {
    test(`${action} accepted ${reader} while POST is unresolved cannot settle a later no-response failure`, async () => {
      const f = fixture(capturing), pending = f.click();
      const read = f.c[reader]();
      const runtime = { http_capture_enabled: capturing, marker: "before fake acceptance" };
      f.reads[0].resolve({ ok: true, json: async () => runtime });
      await read;
      assert.equal(f.state._runtimeReadAcceptedVersion, 1);
      assert.equal(f.state._runtimeReadAcceptedSessionId, "session-a");
      // The fake server can apply the POST after this read but lose its reply.
      const fakeAcceptedState = JSON.parse(f.requests[0].options.body).http_capture_enabled;
      assert.equal(fakeAcceptedState, !capturing);
      f.requests[0].reject(new TypeError("Lost response after fake acceptance"));
      await pending;
      assert.equal(f.state.runtime, runtime);
      assertIdle(f, capturing, { unconfirmed: true });
      assert.equal(f.toasts.length, 1);
      assert.equal(f.requests.length, 1);
      assert.equal(f.reads.length, 1);
    });

    test(`${action} old ${reader} finishing after transport failure cannot clear its uncertainty`, async () => {
      const f = fixture(capturing), runtime = f.state.runtime, pending = f.click();
      const oldRead = f.c[reader]();
      f.requests[0].reject(new TypeError("No response"));
      await pending;
      assertIdle(f, capturing, { unconfirmed: true });
      f.reads[0].resolve({ ok: true, json: async () => ({ http_capture_enabled: capturing }) });
      await oldRead;
      assert.equal(f.state.runtime, runtime);
      assert.equal(f.state._runtimeReadAcceptedVersion || 0, 0);
      assertIdle(f, capturing, { unconfirmed: true });
    });

    test(`${action} existing ${reader} started after transport failure can confirm capture`, async () => {
      const f = fixture(capturing), pending = f.click();
      f.requests[0].reject(new TypeError("No response"));
      await pending;
      assertIdle(f, capturing, { unconfirmed: true });
      const read = f.c[reader](), runtime = { http_capture_enabled: !capturing };
      f.reads[0].resolve({ ok: true, json: async () => runtime });
      await read;
      assert.equal(f.state.runtime, runtime);
      assertIdle(f, !capturing);
      assert.equal(f.requests.length, 1);
      assert.equal(f.reads.length, 1);
    });
  }

  test(`${action} a failure after a readable response is not mislabeled as unconfirmed capture`, async () => {
    const f = fixture(capturing), pending = f.click();
    f.c.targetServiceMapController.scopeChanged = () => { throw new Error("Fixture render failure"); };
    f.requests[0].resolve({ ok: true, json: async () => ({ http_capture_enabled: !capturing }) });
    await pending;
    assert.deepEqual(f.toasts, [["Fixture render failure", "error"]]);
    assertIdle(f, capturing);
  });

  test(`${action} uncertainty survives idle rerenders and refusal until a successful explicit retry`, async () => {
    const f = fixture(capturing), lastConfirmed = f.state.runtime;
    await makeUnconfirmed(f);
    assert.equal(f.state.runtime, lastConfirmed);
    assertIdle(f, capturing, { unconfirmed: true });
    f.c.syncHttpCapturePill();
    assertIdle(f, capturing, { unconfirmed: true });
    assert.equal(f.reads.length, 0, "uncertainty never starts a read or automatic retry");
    assert.equal(f.requests.length, 1);
    const refused = f.click();
    const refuse = await deferFailure(f.requests[1], "HTTP");
    refuse(); await refused;
    assertIdle(f, capturing, { unconfirmed: true });
    assert.deepEqual(f.toasts.at(-1), ["Fixture HTTP failure", "error"]);
    assert.equal(f.state.runtime, lastConfirmed);
    const retry = f.click();
    f.requests[2].resolve({ ok: true, json: async () => ({ http_capture_enabled: !capturing }) });
    await retry;
    assertIdle(f, !capturing);
    assert.equal(f.reads.length, 0);
  });

  test(`${action} uncertainty is local to its session and excluded refreshes do not clear it`, async () => {
    const f = fixture(capturing);
    await makeUnconfirmed(f);
    f.changeSession();
    assertIdle(f, capturing);
    f.state.activeSession = { id: "session-a" };
    // Model an already-supplied replacement without invoking held settings or
    // initialization code. Such paths deliberately do not clear the marker.
    f.state.runtime = { http_capture_enabled: capturing, marker: "replacement" };
    f.c.syncHttpCapturePill();
    assertIdle(f, capturing, { unconfirmed: true });
  });

  for (const reader of ["loadRuntimeSettings", "loadTargetSiteMap"]) {
    test(`${action} existing ${reader} clears uncertainty only after an accepted result`, async () => {
      const f = fixture(capturing);
      await makeUnconfirmed(f);
      const read = f.c[reader]();
      const runtime = { http_capture_enabled: !capturing, marker: "confirmed read" };
      f.reads[0].resolve({ ok: true, json: async () => runtime });
      await read;
      assert.equal(f.state.runtime, runtime);
      assertIdle(f, !capturing);
      assert.equal(f.requests.length, 1);
      assert.equal(f.reads.length, 1);
    });

    for (const failure of ["network", "HTTP", "JSON"]) {
      test(`${action} rejected ${reader} ${failure} leaves uncertainty visible`, async () => {
        const f = fixture(capturing);
        await makeUnconfirmed(f);
        const runtime = f.state.runtime, read = f.c[reader]();
        const fail = await deferFailure(f.reads[0], failure);
        fail();
        await assert.rejects(read, /Fixture/);
        assert.equal(f.state.runtime, runtime);
        assertIdle(f, capturing, { unconfirmed: true });
      });
    }

    for (const owner of ["session", "workspace"]) {
      test(`${action} ${reader} with a stale ${owner} cannot clear uncertainty`, async () => {
        const f = fixture(capturing);
        await makeUnconfirmed(f);
        const runtime = f.state.runtime, read = f.c[reader]();
        if (owner === "session") f.changeSession();
        else f.c.workspaceStateGeneration += 1;
        f.reads[0].resolve({ ok: true, json: async () => ({ http_capture_enabled: !capturing }) });
        await read;
        if (owner === "session") {
          assertIdle(f, capturing);
          f.state.activeSession = { id: "session-a" };
          f.state.runtime = runtime;
          f.c.syncHttpCapturePill();
        }
        assert.equal(f.state.runtime, runtime);
        assertIdle(f, capturing, { unconfirmed: true });
      });
    }

    test(`${action} accepted ${reader} during body decoding beats its later failure`, async () => {
      const f = fixture(capturing), { pending, body } = await deferCaptureBody(f);
      const read = f.c[reader]();
      const runtime = { http_capture_enabled: !capturing, marker: "newer confirmation" };
      f.reads[0].resolve({ ok: true, json: async () => runtime });
      await read;
      body.reject(new Error("Old response body failed"));
      await pending;
      assert.equal(f.state.runtime, runtime);
      assertIdle(f, !capturing);
      assert.deepEqual(f.toasts, []);
    });

    test(`${action} accepted ${reader} for another session cannot confirm a returning owner's failed body`, async () => {
      const f = fixture(capturing), runtime = f.state.runtime;
      const { pending, body } = await deferCaptureBody(f);
      f.changeSession();
      const read = f.c[reader]();
      f.reads[0].resolve({ ok: true, json: async () => ({ http_capture_enabled: !capturing, marker: "session-b" }) });
      await read;
      f.state.activeSession = { id: "session-a" };
      f.state.runtime = runtime;
      f.c.syncHttpCapturePill();
      body.reject(new Error("Session A response body failed"));
      await pending;
      assert.equal(f.state.runtime, runtime);
      assertIdle(f, capturing, { unconfirmed: true });
      assert.equal(f.toasts.length, 1);
    });

    test(`${action} failed ${reader} during body decoding does not confirm capture`, async () => {
      const f = fixture(capturing), { pending, body } = await deferCaptureBody(f);
      const read = f.c[reader]();
      f.reads[0].reject(new Error("Fixture read failure"));
      await assert.rejects(read, /Fixture read failure/);
      body.reject(new Error("Response body failed"));
      await pending;
      assertIdle(f, capturing, { unconfirmed: true });
      assert.equal(f.toasts.length, 1);
    });

    test(`${action} ${reader} started before the write cannot confirm its failed response`, async () => {
      const f = fixture(capturing), read = f.c[reader]();
      const { pending, body } = await deferCaptureBody(f);
      f.reads[0].resolve({ ok: true, json: async () => ({ http_capture_enabled: capturing }) });
      await read;
      body.reject(new Error("Response body failed"));
      await pending;
      assertIdle(f, capturing, { unconfirmed: true });
      assert.equal(f.state._runtimeReadAcceptedVersion || 0, 0);
    });

    test(`${action} superseded ${reader} cannot repaint after the newer confirmation`, async () => {
      const f = fixture(capturing);
      await makeUnconfirmed(f);
      const old = f.c[reader](), newer = f.c[reader]();
      const runtime = { http_capture_enabled: !capturing, marker: "newer read" };
      f.reads[1].resolve({ ok: true, json: async () => runtime });
      await newer;
      f.reads[0].resolve({ ok: true, json: async () => ({ http_capture_enabled: capturing }) });
      await old;
      assert.equal(f.state.runtime, runtime);
      assertIdle(f, !capturing);
    });

    test(`${action} ${reader} clears confirmed marker even if the pill is unavailable`, async () => {
      const f = fixture(capturing);
      await makeUnconfirmed(f);
      const getElementById = f.c.document.getElementById;
      f.c.document.getElementById = () => null;
      const read = f.c[reader]();
      f.reads[0].resolve({ ok: true, json: async () => ({ http_capture_enabled: !capturing }) });
      await read;
      f.c.document.getElementById = getElementById;
      f.c.syncHttpCapturePill();
      assertIdle(f, !capturing);
    });
  }

  for (const failure of ["network", "HTTP", "JSON"]) {
    test(`${action} compound Scope ${failure} failure cannot clear an unconfirmed pill`, async () => {
      const f = fixture(capturing);
      await makeUnconfirmed(f);
      f.state.activeTool = "target";
      const runtime = f.state.runtime, read = f.c.loadTargetSiteMap();
      f.reads[0].resolve({ ok: true, json: async () => ({ http_capture_enabled: !capturing }) });
      const fail = await deferFailure(f.paths[0], failure);
      fail();
      await assert.rejects(read, /Fixture/);
      assert.equal(f.state.runtime, runtime);
      assertIdle(f, capturing, { unconfirmed: true });
    });
  }

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
