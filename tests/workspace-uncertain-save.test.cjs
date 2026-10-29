// Passive persistence failures only: production functions in a synthetic VM.
// No server, real workspace, request execution, or live connection is used.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { fixture, deferred } = require("./replay-workspace-fixture.cjs");
const { appSource } = require("./frontend-test-helpers.cjs");

const uncertain = {
  code: "WORKSPACE_COMMIT_UNCERTAIN",
  error: "Workspace save may have committed; reload before retrying.",
};
const settled = () => new Promise(resolve => setImmediate(resolve));

function setup() {
  const f = fixture();
  f.a = f.tab("local");
  f.seed([f.a]);
  f.delays = [];
  const setTimeout = f.context.window.setTimeout;
  f.context.window.setTimeout = (callback, delay) => {
    f.delays.push(delay);
    return setTimeout(callback, delay);
  };
  f.context.console = { error() {}, warn() {} };
  for (const name of ["handleWorkspaceActionError", "toggleReplayTabPin", "commitReplayTabRename"]) {
    vm.runInContext(appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, "m"))[0], f.context);
  }
  f.fail = (index = 0, payload = uncertain, status = 500) => f.requests[index].resolve({
    ok: false, status,
    text: async () => typeof payload === "string" ? payload : JSON.stringify(payload),
    json: async () => payload,
  });
  return f;
}

function startSave(f) {
  f.context.scheduleWorkspaceStateSave();
  const flushing = f.context.flushWorkspaceState();
  return flushing.then(() => null, error => error);
}

function assertUncertain(error) {
  assert.equal(error?.name, "WorkspaceStateConflictError");
  assert.equal(error.commitUncertain, true);
  assert.deepEqual(JSON.parse(JSON.stringify(error.latest)), uncertain);
  assert.match(error.message, /could not be confirmed/i);
  assert.match(error.message, /copy of newer edits/i);
  assert.match(error.message, /reload the app before retrying/i);
}

test("typed postcommit 500 retains drafts and committed baseline behind the reload barrier", async () => {
  const f = setup();
  f.a.requestText = "GET /local-draft HTTP/1.1\r\nHost: example.com\r\n\r\n";
  f.els.replayRequestHighlight.innerText = "GET /newer-editor-draft HTTP/1.1";
  f.state.fuzzerRequestText = "GET /local-fuzzer-draft HTTP/1.1";
  const baseline = f.context.workspaceSaveCommittedSnapshot;
  const result = startSave(f);
  const version = f.context.workspaceSaveVersion;
  f.fail();
  assertUncertain(await result);
  assert.equal(f.context.workspaceSaveConflictPending, true);
  assert.equal(f.context.workspaceSaveDirty, true);
  assert.equal(f.context.workspaceSaveCommittedSnapshot, baseline);
  assert.equal(f.context.workspaceSaveLastSnapshot, null);
  assert.equal(f.context.workspaceSaveVersion, version);
  assert.equal(f.context.workspaceStateGeneration, 0);
  assert.equal(f.state.activeSession.id, "session-a");
  assert.equal(f.state.workspaceRevision, 10);
  assert.match(f.a.requestText, /local-draft/);
  assert.match(f.els.replayRequestHighlight.innerText, /newer-editor-draft/);
  assert.match(f.state.fuzzerRequestText, /local-fuzzer-draft/);
  assert.equal(f.renders.length, 0);
  assert.equal(f.context.workspaceSaveInFlight, false);
  assert.equal(f.context.workspaceSaveLoopPromise, null);
  assert.equal(f.timers.size, 0);
  assert.equal(f.delays.includes(1000), false);
  assert.equal(f.notices.length, 1);
  assert.match(f.notices[0].message, /reload the app before retrying/i);
  assert.equal(f.notices[0].reload, false, "only reloading the app can tell whether it committed");
});

test("newer edits and repeated save callbacks cannot retry an uncertain commit", async () => {
  const f = setup(), result = startSave(f);
  f.a.requestText = "GET /newer-local-edit HTTP/1.1";
  f.context.scheduleWorkspaceStateSave();
  const queuedCallback = f.timers.get(f.context.workspaceSaveTimer);
  f.context.wsTranscriptSaveTimer = f.context.window.setTimeout(() => {
    f.context.flushQueuedWorkspaceStateSave();
  }, 250);
  f.context.wsTranscriptFirstDirtyAt = 42;
  const joining = f.context.flushQueuedWorkspaceStateSave();
  f.fail();
  assertUncertain(await result);
  await joining;
  assert.equal(f.context.wsTranscriptSaveTimer, null);
  assert.equal(f.context.wsTranscriptFirstDirtyAt, 0);
  assert.equal(f.timers.size, 0);
  queuedCallback(); queuedCallback();
  await settled();
  f.a.requestText = "GET /even-newer-local-edit HTTP/1.1";
  f.context.scheduleWorkspaceStateSave();
  for (const [id, callback] of [...f.timers]) { f.timers.delete(id); callback(); }
  await settled();
  await f.context.flushQueuedWorkspaceStateSave();
  const later = await f.context.flushWorkspaceState({ bypassExpectedActiveSessionGuard: true })
    .then(() => null, error => error);
  assertUncertain(later);
  assert.equal(f.a.requestText, "GET /even-newer-local-edit HTTP/1.1");
  assert.equal(f.requests.length, 1);
  assert.equal(f.timers.size, 0);
  assert.equal(f.delays.includes(1000), false);
  assert.equal(f.context.workspaceSaveDirty, true);
  assert.equal(f.notices.length, 1, "callbacks do not repeat the initial barrier notice");
});

test("every flush waiter retains typed uncertainty and refresh guidance", async () => {
  const f = setup(), first = startSave(f);
  const second = f.context.flushWorkspaceState().then(() => null, error => error);
  f.fail();
  assertUncertain(await first);
  assertUncertain(await second);
  const pending = await f.context.flushWorkspaceState().then(() => null, error => error);
  assertUncertain(pending);
  f.context.handleWorkspaceActionError(pending);
  assert.match(f.notices.at(-1).message, /reload the app before retrying/i);
  assert.doesNotMatch(f.notices.at(-1).message, /changed elsewhere/i);
  assert.equal(f.requests.length, 1);
});

for (const [description, payload, status] of [
  ["plain-text 500", "synthetic precommit write failure", 500],
  ["unknown JSON 500", { code: "OTHER_ERROR", error: "synthetic precommit failure" }, 500],
  ["invalid JSON 500", "{not-json", 500],
  ["unrelated status", uncertain, 503],
]) {
  test(`${description} keeps the existing one-second retry`, async () => {
    const f = setup(), result = startSave(f);
    f.fail(0, payload, status);
    const error = await result;
    assert.equal(error.name, "Error");
    assert.equal(error.message, typeof payload === "string" ? payload : JSON.stringify(payload));
    assert.equal(f.context.workspaceSaveConflictPending, false);
    assert.equal(f.context.workspaceSaveDirty, true);
    assert.equal(f.timers.size, 1);
    assert.equal(f.delays.at(-1), 1000);
    const [id, callback] = [...f.timers][0];
    f.timers.delete(id); callback();
    assert.equal(f.requests.length, 2);
    f.succeed(1, { session_id: "session-a", revision: 11 });
    await settled();
    assert.equal(f.state.workspaceRevision, 11);
    assert.equal(f.context.workspaceSaveDirty, false);
    assert.equal(f.timers.size, 0);
  });
}

test("ordinary 409 keeps the conflict barrier and offers Reload", async () => {
  const f = setup(), latest = f.remote([f.a], 11), result = startSave(f);
  f.fail(0, latest, 409);
  const error = await result;
  assert.equal(error.name, "WorkspaceStateConflictError");
  assert.equal(error.commitUncertain, false);
  assert.equal(f.context.workspaceSaveConflictPending, true);
  assert.equal(f.context.workspaceSaveDirty, true);
  assert.equal(f.state.workspaceRevision, 10);
  assert.equal(f.timers.size, 0);
  assert.match(f.notices[0].message, /changed elsewhere/);
  assert.equal(f.notices[0].reload, true);
  f.context.handleWorkspaceActionError(error);
  assert.match(f.notices.at(-1).message, /Reload brings in those changes and keeps your edits/);
  assert.equal(f.toasts.length, 0, "a refused action reuses the notice instead of stacking toasts");
  await f.context.flushQueuedWorkspaceStateSave();
  assert.equal(f.requests.length, 1);
});

test("active-session-changed 409 still permits the existing explicit bypass", async () => {
  const f = setup(), result = startSave(f);
  f.fail(0, { error: "active session changed" }, 409);
  await result;
  const retry = f.context.flushWorkspaceState({ bypassExpectedActiveSessionGuard: true });
  assert.equal(f.requests.length, 2);
  f.succeed(1, { session_id: "session-a", revision: 11 });
  await retry;
  assert.equal(f.context.workspaceSaveConflictPending, false);
  assert.equal(f.context.workspaceSaveDirty, false);
});

for (const change of ["session", "generation"]) {
  for (const phase of ["fetch", "body"]) {
    test(`uncertain error during ${phase} cannot block a newer ${change}`, async () => {
      const f = setup(), result = startSave(f), body = deferred();
      if (phase === "body") {
        f.requests[0].resolve({ ok: false, status: 500, text: () => body.promise });
        await settled();
      }
      if (change === "session") f.state.activeSession = { id: "session-b" };
      else f.context.workspaceStateGeneration++;
      f.a.requestText = "GET /current-owner-draft HTTP/1.1";
      f.state.workspaceRevision = 20;
      const baseline = { currentOwner: true };
      f.context.workspaceSaveCommittedSnapshot = baseline;
      if (phase === "body") body.resolve(JSON.stringify(uncertain));
      else f.fail();
      assert.equal(await result, null);
      assert.equal(f.context.workspaceSaveConflictPending, false);
      assert.equal(f.context.workspaceSaveConflictLatest, null);
      assert.equal(f.context.workspaceSaveCommittedSnapshot, baseline);
      assert.equal(f.state.workspaceRevision, 20);
      assert.equal(f.a.requestText, "GET /current-owner-draft HTTP/1.1");
      assert.equal(f.requests.length, 1);
      assert.equal(f.toasts.length, 0);
      assert.equal(f.timers.size, 0);
    });
  }
}

for (const kind of ["pin", "label"]) {
  for (const newerEdit of [false, true]) {
    test(`${kind} uncertainty retains ${newerEdit ? "newer" : "attempted"} local metadata`, async () => {
      const f = setup(), baseline = f.context.workspaceSaveCommittedSnapshot;
      const edit = value => {
        if (kind === "pin") f.context.toggleReplayTabPin(f.a.id);
        else {
          f.state.replayRenamingTabId = f.a.id;
          f.context.commitReplayTabRename(f.a.id, value);
        }
      };
      edit("attempted");
      if (newerEdit) edit("newer");
      f.a.requestText = "GET /newer-editor-model HTTP/1.1";
      f.els.replayRequestHighlight.innerText = "GET /newer-dom-draft HTTP/1.1";
      const renders = f.renders.length;
      f.fail(); await settled();
      assert.equal(kind === "pin" ? f.a.pinned : f.a.customLabel,
        kind === "pin" ? !newerEdit : newerEdit ? "newer" : "attempted");
      assert.equal(f.a.requestText, "GET /newer-editor-model HTTP/1.1");
      assert.equal(f.els.replayRequestHighlight.innerText, "GET /newer-dom-draft HTTP/1.1");
      assert.equal(f.renders.length, renders, "uncertainty callbacks cannot roll back or redraw metadata");
      assert.equal(f.context.workspaceSaveCommittedSnapshot, baseline);
      assert.equal(f.context.workspaceSaveConflictPending, true);
      assert.equal(f.context.workspaceSaveDirty, true);
      assert.equal(f.timers.size, 0);
      assert.equal(f.requests.length, 1);
    });
  }
}

test("observed uncertainty blocks unload resubmission and requests the unsaved-edit prompt", async () => {
  const f = setup(), result = startSave(f);
  f.fail(); await result;
  assert.equal(f.context.workspaceUnloadPayload(f.context.snapshotWorkspaceState()), null);
  let prevented = 0;
  const event = { type: "beforeunload", preventDefault: () => prevented++ };
  f.context.flushWorkspaceStateOnUnload(event);
  f.context.flushWorkspaceStateOnUnload({ type: "pagehide" });
  assert.equal(prevented, 1);
  assert.equal(event.returnValue, "Unsaved edits");
  assert.equal(f.requests.length, 1);
  assert.equal(f.beacons.length, 0);
});

test("unload-only fetch remains fire-and-forget and cannot claim an observed response", async () => {
  const f = setup();
  f.context.navigator.sendBeacon = () => false;
  f.context.scheduleWorkspaceStateSave();
  f.context.flushWorkspaceStateOnUnload({ type: "pagehide" });
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].options.keepalive, true);
  let bodyReads = 0;
  f.requests[0].resolve({ ok: false, status: 500, text: async () => {
    bodyReads++;
    return JSON.stringify(uncertain);
  } });
  await settled();
  assert.equal(bodyReads, 0);
  assert.equal(f.context.workspaceSaveConflictPending, false);
  assert.equal(f.context.workspaceSaveDirty, true);
  assert.equal(f.state.workspaceRevision, 10);
});

function setupPreflight(action) {
  const f = setup();
  f.restores = [];
  Object.assign(f.context, {
    AbortController,
    setReplayTargetInputValidity() {}, setReplaySending() {},
    parseEditableRawRequest: (_text, fallback) => f.plain(fallback),
    replayEffectiveHttpVersion: () => "HTTP/1.1",
    cloneReplayTabState: tab => f.plain(tab),
    restoreReplayTabConflictState: (tab, snapshot) => {
      f.restores.push(snapshot);
      Object.assign(tab, snapshot);
    },
    redirectTargetsSameOrigin: () => true,
    renderReplayRequestHighlight() {}, renderReplayResponseOnly() {},
    syncReplayToolbar() {}, renderReplayViewTabs() {},
    validateWsReplayTargetInput: () => ({ valid: true }),
    setWsReplayTargetInputValidity() {},
    normalizeWsReplayTargetFields: (scheme, host, port) => ({ scheme, host, port }),
    renderWsStatus() {}, renderWsSetupQueue() {}, renderWsFrameList() {},
    snapshotWsReplayFrames: () => ({ frames: [], truncated: false }),
    limitWsSetupQueueItems: items => ({ items, notice: "" }),
    appendWsSetupNotice: notice => notice,
    normalizeWsMessageType: kind => kind || "text",
    snapshotWsReplaySelectedFrameIndex: () => -1,
    snapshotWsReplayFrameWindowStart: () => null,
  });
  for (const name of [action, "flushWorkspaceStateForReplayAction", "isWsReplayTabAlive", "isReplayTabStillCurrent",
    "buildUrlFromTarget", "joinAuthority", "isDefaultPortForScheme", "isRedirectRequestBodyHeader",
    "parseWsHandshakeHeaders", "wsReplayHostHeaderValue", "defaultWsPortForScheme"]) {
    vm.runInContext(appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, "m"))[0], f.context);
  }
  if (action === "followRedirect") {
    f.a.responseRecord = { status: 302, response: { headers: [{ name: "location", value: "/redirect" }] } };
  }
  if (action === "wsConnect") {
    Object.assign(f.a, {
      type: "websocket", wsScheme: "wss", wsHost: "example.com", wsPort: "443", wsPath: "/saved",
      wsEditorText: "saved editor", wsFrames: [], wsSetupQueue: [], wsLifecycleToken: 0,
    });
    Object.assign(f.els, {
      wsSchemeSelect: { value: "wss" }, wsHostInput: { value: "example.com" },
      wsPortInput: { value: "443" }, wsPathInput: { value: "/saved" },
    });
  }
  // Fail the fixture immediately if a preflight error ever reaches dispatch.
  // The one allowed request is the synthetic metadata save being tested.
  const fetch = f.context.fetch;
  f.context.fetch = (url, options) => {
    assert.equal(url, "/api/workspace-state", "no replay or WebSocket request may be emitted");
    return fetch(url, options);
  };
  return f;
}

for (const action of ["sendReplay", "followRedirect", "wsConnect"]) {
  for (const typed of [true, false]) {
    test(`${action} preflight ${typed ? "uncertainty preserves newer drafts" : "409 keeps existing restoration"} without dispatch`, async () => {
      const f = setupPreflight(action);
      f.context.scheduleWorkspaceStateSave();
      const running = f.context[action]();
      assert.equal(f.requests.length, 1);
      f.a.requestText = "GET /newer-preflight-draft HTTP/1.1";
      f.a.customLabel = "newer metadata";
      f.a.wsEditorText = "newer websocket editor";
      f.els.replayRequestHighlight.innerText = "newer uncommitted DOM";
      f.context.scheduleWorkspaceStateSave();
      f.fail(0, typed ? uncertain : { revision: 11 }, typed ? 500 : 409);
      await running;
      assert.equal(f.requests.length, 1);
      assert.equal(f.restores.length, typed ? 0 : 1);
      if (typed) {
        assert.equal(f.a.requestText, "GET /newer-preflight-draft HTTP/1.1");
        assert.equal(f.a.customLabel, "newer metadata");
        assert.equal(f.a.wsEditorText, "newer websocket editor");
        assert.equal(f.els.replayRequestHighlight.innerText, "newer uncommitted DOM");
        assert.match(f.notices.at(-1).message, /reload the app before retrying/i);
      }
      assert.equal(f.context.workspaceSaveConflictPending, true);
      assert.equal(f.context.workspaceSaveDirty, true);
      assert.equal(f.context._replaySendControllers.size, 0);
      assert.equal(f.timers.size, 0);
    });
  }
}
