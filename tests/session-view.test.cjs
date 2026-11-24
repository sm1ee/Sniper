// A window shows a session without the proxy listener moving to it. Production
// functions run in a VM with deferred in-memory replies; no API is called.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const tick = () => new Promise(resolve => setImmediate(resolve));
const session = (id, active = false) => ({ id, name: `Session ${id}`, active });
const ok = body => ({ ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) });
const refused = (status, message) => ({ ok: false, status, text: async () => message });
// Values made inside the VM have another realm's prototypes.
const plain = value => JSON.parse(JSON.stringify(value));

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function fixture(names, extra = {}) {
  const a = session("a", true), b = session("b");
  const state = { sessions: [a, b], activeSession: a, viewedSessionId: "a", selectedSessionId: "a" };
  const requests = [], reloads = [], toasts = [], confirms = [], calls = [];
  const context = loadFunctions(["currentSessionId", "sessionQueryPath", ...names], {
    state, URLSearchParams, encodeURIComponent,
    workspaceStateGeneration: 0, workspaceSaveVersion: 0, workspaceLoaded: true, sessionActivationIntent: null,
    fetch(url, options) {
      const request = { url, options, ...deferred() };
      requests.push(request);
      return request.promise;
    },
    showToast: (...args) => toasts.push(args),
    showConfirmDialog: (message, confirm, options) => confirms.push({ message, confirm, options }),
    reloadSessionWorkspace: async options => { reloads.push(options); },
    handleWorkspaceActionError: error => calls.push(["error", error.message]),
    ...extra,
  });
  return { a, b, state, context, requests, reloads, toasts, confirms, calls };
}

test("a write names its session and nothing about where the proxy listener records", () => {
  const f = fixture(["expectedActiveSessionIdForWrite", "sessionWritePath"]);
  assert.equal(f.context.expectedActiveSessionIdForWrite("a"), null);
  assert.equal(f.context.sessionWritePath("/api/runtime"), "/api/runtime?session_id=a");
  assert.equal(f.context.sessionWritePath("/api/runtime?x=1", "b"), "/api/runtime?x=1&session_id=b");
});

const preflight = {
  preserveActiveHttpReplayDraftBeforeSessionChange: () => true,
  flushTargetScopeDraft: async () => true, flushMatchReplaceDraft: async () => true,
  flushSequenceDraft: async () => true, flushAllPendingAnnotations: async () => {},
  flushWorkspaceState: async () => {}, cleanupWsReplayTabsBeforeStateReset: async () => {},
  canLeaveSessionAfterDraftPreflight: () => true, canReloadWorkspaceAfterSessionAction: () => true,
};

test("a click on a session loads it on the server, moves nothing, and shows it", async () => {
  const f = fixture(["viewSessionById"], preflight);
  const viewing = f.context.viewSessionById("b");
  await tick();
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].url, "/api/settings?session_id=b");
  assert.equal(f.requests[0].options, undefined, "a read: nothing is activated");
  assert.equal(f.state.viewedSessionId, "a", "the window lets go only once the session is loaded");
  f.requests[0].resolve(ok({}));
  await viewing;
  assert.equal(f.state.viewedSessionId, "b");
  assert.equal(f.state.selectedSessionId, "b");
  assert.deepEqual(plain(f.reloads), [{ cleanupBeforeReset: false }]);
});

test("a session that does not load leaves the window on the one it shows", async () => {
  const lists = [];
  const f = fixture(["viewSessionById"], {
    ...preflight,
    loadSessions: async options => { lists.push(options); },
  });
  const viewing = f.context.viewSessionById("b").catch(error => error);
  await tick();
  f.requests[0].resolve(refused(500, "failed to load session b"));
  const error = await viewing;
  assert.equal(error.message, "failed to load session b");
  assert.equal(f.state.viewedSessionId, "a");
  assert.equal(f.reloads.length, 0);
  assert.deepEqual(plain(lists), [{ preserveWorkspaceOwner: true }], "the rows are read again: the session may be gone");
});

test("edits made while a session loads keep the window where it is", async () => {
  const reconciled = [];
  const f = fixture(["viewSessionById"], {
    ...preflight,
    canReloadWorkspaceAfterSessionAction: () => false,
    reconcileSessionsAfterCompletedAction: async () => { reconciled.push(true); },
  });
  const viewing = f.context.viewSessionById("b");
  await tick();
  f.requests[0].resolve(ok({}));
  await viewing;
  assert.equal(f.state.viewedSessionId, "a");
  assert.equal(f.reloads.length, 0);
  assert.equal(reconciled.length, 1);
});

function feedFixture() {
  const refreshed = [];
  const f = fixture(["recordMainListenerInto", "refreshSessionFeeds"], {
    loadSessions: async options => { refreshed.push(["sessions", options]); },
    loadSessionActivity: async () => { refreshed.push(["activity"]); },
    loadIntercepts: async () => { refreshed.push(["intercepts"]); },
    loadResponseIntercepts: async () => { refreshed.push(["response intercepts"]); },
  });
  return { ...f, refreshed };
}

test("moving the proxy listener leaves the window on its session and refreshes what the move changed", async () => {
  const f = feedFixture();
  const moving = f.context.recordMainListenerInto("b");
  await tick();
  assert.equal(f.requests[0].url, "/api/sessions/b/activate");
  assert.equal(f.requests[0].options.method, "POST");
  f.requests[0].resolve(ok({}));
  await moving;
  assert.equal(f.state.viewedSessionId, "a");
  assert.equal(f.state.activeSession, f.a);
  assert.equal(f.reloads.length, 0, "the workspace on screen is not reloaded");
  assert.deepEqual(f.refreshed.map(entry => entry[0]).sort(), ["activity", "intercepts", "response intercepts", "sessions"]);
  assert.deepEqual(plain(f.refreshed.find(entry => entry[0] === "sessions")[1]), { preserveWorkspaceOwner: true });
});

test("a busy proxy asks before it is moved by force, and cuts nothing until then", async () => {
  const f = feedFixture();
  const moving = f.context.recordMainListenerInto("b");
  await tick();
  f.requests[0].resolve(refused(409, "cannot switch sessions while proxy activity is still running (1 streamed response)"));
  await moving;
  assert.equal(f.requests.length, 1);
  assert.equal(f.confirms.length, 1);
  assert.match(f.confirms[0].message, /Anything still in flight is cut and will not be recorded/);
  assert.deepEqual({ ...f.confirms[0].options }, { title: "Proxy is busy", confirmLabel: "Move anyway" });
  assert.equal(f.refreshed.length, 0);
  f.confirms[0].confirm();
  await tick();
  assert.equal(f.requests[1].url, "/api/sessions/b/activate?force=true");
  f.requests[1].resolve(ok({}));
  await tick();
  assert.equal(f.refreshed.length, 4);
});

test("an older busy answer cannot offer or confirm a move once a newer one was asked for", async () => {
  const f = feedFixture();
  const older = f.context.recordMainListenerInto("b");
  await tick();
  const newer = f.context.recordMainListenerInto("a");
  await tick();
  f.requests[0].resolve(refused(409, "proxy activity is still running"));
  await older;
  assert.equal(f.confirms.length, 0, "the latest request is the one that may ask");
  f.requests[1].resolve(refused(409, "proxy activity is still running"));
  await newer;
  assert.equal(f.confirms.length, 1);
  // A third request while the dialog is open takes the consent with it.
  const third = f.context.recordMainListenerInto("b");
  await tick();
  f.confirms[0].confirm();
  await tick();
  assert.equal(f.requests.length, 3, "no forced request was sent");
  assert.match(f.toasts.at(-1)[0], /newer session action/);
  f.requests[2].resolve(ok({}));
  await third;
});

test("a move the server refuses for another reason says why", async () => {
  const f = feedFixture();
  const moving = f.context.recordMainListenerInto("b").catch(error => error);
  await tick();
  f.requests[0].resolve(refused(409, "this session records from its own port 127.0.0.1:18081; close that port before the proxy records into it"));
  const error = await moving;
  assert.match(error.message, /close that port/);
  assert.equal(f.confirms.length, 0);
  assert.equal(f.refreshed.length, 0);
});

test("the window leaves a deleted session without saving into it", async () => {
  const f = fixture(["showDefaultSessionAfterDelete"]);
  await f.context.showDefaultSessionAfterDelete("b");
  assert.equal(f.reloads.length, 0, "another session's deletion is not this window's");
  await f.context.showDefaultSessionAfterDelete("a");
  assert.equal(f.state.viewedSessionId, null, "the next load takes the session the proxy records into");
  assert.deepEqual(plain(f.reloads), [{ cleanupBeforeReset: false }]);
  assert.equal(f.requests.length, 0, "no draft is flushed into a session that is gone");
  assert.match(f.toasts[0][0], /was deleted/);
});

for (const onScreen of [false, true]) {
  test(`deleting ${onScreen ? "the session on screen moves the window off it" : "another session leaves the window alone"}`, async () => {
    const left = [];
    const f = fixture(["deleteSessionById"], {
      renderDashboard() {},
      reconcileSessionsAfterActionError: async () => assert.fail("the delete succeeds"),
      showDefaultSessionAfterDelete: async id => { left.push(id); },
      console: { error() {} },
    });
    // The proxy listener records into b here, so a can be deleted.
    f.a.active = false; f.b.active = true;
    await f.context.deleteSessionById(onScreen ? "a" : "b");
    const deleting = f.confirms[0].confirm();
    await tick();
    assert.equal(f.requests[0].options.method, "DELETE");
    f.requests[0].resolve(ok({}));
    await deleting;
    assert.deepEqual(left, onScreen ? ["a"] : []);
    assert.equal(f.state.sessions.length, 1);
  });
}

test("settings are read for the session a click asked for, and a late answer for another is dropped", async () => {
  const applied = [];
  const f = fixture(["loadSettings"], {
    _applySettings: async (response, options) => { applied.push(options.sessionId); return true; },
    setTimeout: callback => callback(),
  });
  f.state.viewedSessionId = "b";
  const loading = f.context.loadSettings(0);
  await tick();
  assert.equal(f.requests[0].url, "/api/settings?session_id=b", "the session the reload is for, not the one still on screen");
  f.requests[0].resolve(ok({}));
  await loading;
  assert.deepEqual(applied, ["b"]);

  const g = fixture(["_applySettings"], {});
  g.state.viewedSessionId = "b";
  const answer = { json: async () => ({ active_session: session("a", true), runtime: {} }) };
  assert.equal(await g.context._applySettings(answer, { sessionId: "a" }), false);
  assert.equal(g.state.settings, undefined, "an answer for a session the window has left changes nothing");
});
