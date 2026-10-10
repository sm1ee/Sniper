// Passive VM fixtures only: no server, app data, connections or request execution.
const assert = require("node:assert/strict");
const test = require("node:test");
const { fixture, plain } = require("./replay-workspace-fixture.cjs");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function setup(pinned = false) {
  const f = fixture();
  f.a = f.tab("first", pinned); f.b = f.tab("second");
  f.seed([f.a, f.b], f.a.id);
  return f;
}
function remotePin(f, pinned, revision = 11) {
  const snapshot = f.remote([f.b, f.a], revision);
  snapshot.replay.tabs.find(tab => tab.id === f.a.id).pinned = pinned;
  return snapshot;
}
function baseline(f) {
  return f.context.workspaceReplayTabsById(f.context.workspaceSaveCommittedSnapshot).get(f.a.id);
}

for (const initiallyPinned of [false, true]) {
  test(`external ${initiallyPinned ? "unpin" : "pin"} preserves order, focus, sequence and unrelated baseline`, async () => {
    const f = setup(initiallyPinned), originalBaseline = plain(baseline(f));
    const sequence = f.state.replayTabSequence, focus = f.document.activeElement;
    const fuzzer = f.context.workspaceSaveCommittedSnapshot.fuzzer;
    await f.adopt(remotePin(f, !initiallyPinned));
    assert.equal(f.a.pinned, !initiallyPinned);
    assert.deepEqual(plain(baseline(f)), { ...originalBaseline, pinned: !initiallyPinned });
    assert.equal(f.context.workspaceSaveCommittedSnapshot.fuzzer, fuzzer);
    assert.deepEqual(plain(f.state.replayTabs.map(tab => tab.id)), [f.a.id, f.b.id]);
    assert.equal(f.state.activeReplayTabId, f.a.id);
    assert.equal(f.document.activeElement, focus);
    assert.equal(f.state.replayTabSequence, sequence);
    assert.deepEqual(f.renders.map(render => render.kind), ["strip"]);
    await f.adopt(remotePin(f, !initiallyPinned, 12));
    assert.equal(f.renders.length, 1, "repeated state is idempotent");
    await f.adopt(remotePin(f, initiallyPinned, 13));
    assert.equal(f.a.pinned, initiallyPinned, "a later reverse toggle is not mistaken for a local edit");
    assert.equal(baseline(f).pinned, initiallyPinned);
  });
}

const drafts = {
  "CodeMirror text": f => f.setEditor("GET /unfinished HTTP/1.1"),
  "target control": f => { f.els.replayPortInput.value = "incomplete"; },
  "HTTP version control": f => { f.versionSelect.value = "HTTP/2"; },
  "binary draft": f => { f.a.requestBytes = new Uint8Array([255, 0, 1]); },
  "hex editor": f => { f.state.replayMessageViews.request = "hex"; },
  "pending rename": f => {
    f.state.replayRenamingTabId = f.a.id;
    f.els.renameInput = { value: "unfinished name", selectionStart: 4 };
    f.document.activeElement = f.els.renameInput;
  },
  "sending tab": f => { f.context._replaySendControllers.set(f.a.id, {}); },
};
for (const [name, mutate] of Object.entries(drafts)) {
  test(`remote pin merges independently of ${name}`, async () => {
    const f = setup(); mutate(f);
    const dom = plain(f.els), focus = f.document.activeElement, before = plain(f.a);
    const incoming = remotePin(f, true);
    const tab = incoming.replay.tabs.find(tab => tab.id === f.a.id);
    tab.custom_label = "remote label"; tab.request_text = "GET /remote HTTP/1.1";
    tab.response_record = { id: "remote-response" };
    await f.adopt(incoming);
    assert.deepEqual(plain(f.a), { ...before, pinned: true });
    assert.equal(baseline(f).pinned, true);
    assert.deepEqual(plain(f.els), dom); assert.equal(f.document.activeElement, focus);
    assert.equal(f.renders.some(render => render.kind === "full"), false);
    assert.equal(f.renders.length, name === "pending rename" ? 0 : 1);
    assert.equal(f.context.workspaceSaveConflictPending, false);
  });
}

// Exhaust the boolean three-way merge: two changes from the same baseline
// necessarily converge. A local-only change must remain pending for its save.
for (const committed of [false, true]) for (const local of [false, true]) for (const remote of [false, true]) {
  test(`pin merge baseline=${committed}, local=${local}, remote=${remote}`, async () => {
    const f = setup(committed);
    f.a.pinned = local; f.a.customLabel = "local label";
    f.context.workspaceSaveDirty = true;
    await f.adopt(remotePin(f, remote));
    assert.equal(f.a.pinned, local === committed ? remote : local);
    assert.equal(baseline(f).pinned, remote);
    assert.equal(f.a.customLabel, "local label");
    assert.equal(baseline(f).custom_label, "first");
    assert.equal(f.context.workspaceSaveDirty, true);
    assert.equal(f.context.workspaceSaveConflictPending, false);
  });
}

test("converged local/remote pin advances baseline for a subsequent remote unpin", async () => {
  const f = setup(); f.a.pinned = true;
  await f.adopt(remotePin(f, true));
  assert.equal(baseline(f).pinned, true);
  await f.adopt(remotePin(f, false, 12));
  assert.equal(f.a.pinned, false); assert.equal(baseline(f).pinned, false);
});

for (const pinned of [false, true]) for (const revision of [11, 12]) {
  test(`late save revision ${revision} cannot resurrect pin=${!pinned} in baseline or unload`, async () => {
    const f = setup(!pinned), stale = f.context.snapshotWorkspaceState();
    const saving = f.context.saveWorkspaceState(stale);
    f.context.workspaceSaveLastSnapshot = stale; f.context.workspaceSaveInFlight = true;
    await f.adopt(remotePin(f, pinned, 12));
    f.succeed(0, { session_id: "session-a", revision }); await saving;
    assert.equal(baseline(f).pinned, pinned);
    assert.equal(f.context.workspaceSaveLastSnapshot, null);
    f.context.flushWorkspaceStateOnUnload({ type: "pagehide" });
    const unload = JSON.parse(await f.beacons[0].blob.text());
    assert.equal(unload.replay.tabs.find(tab => tab.id === f.a.id).pinned, pinned);
    assert.equal(unload.revision, 12);
    f.a.customLabel = "next local edit";
    const save = f.context.saveWorkspaceState();
    const posted = JSON.parse(f.requests.at(-1).options.body);
    assert.equal(posted.replay.tabs.find(tab => tab.id === f.a.id).pinned, pinned);
    f.succeed(f.requests.length - 1, { session_id: "session-a", revision: 13 }); await save;
    assert.equal(baseline(f).pinned, pinned);
    assert.equal(baseline(f).custom_label, "next local edit");
  });
}

test("a racing pin save rejected with 409 keeps the existing persistent conflict policy", async () => {
  const f = setup(); f.a.pinned = true;
  f.context.scheduleWorkspaceStateSave();
  const saving = f.context.flushQueuedWorkspaceStateSave();
  const latest = remotePin(f, false, 12);
  f.requests[0].resolve({ ok: false, status: 409, json: async () => latest });
  await saving;
  assert.equal(f.a.pinned, true);
  assert.equal(f.state.workspaceRevision, 10);
  assert.equal(f.context.workspaceSaveConflictPending, true);
  assert.equal(f.context.workspaceSaveDirty, true);
  assert.equal(f.context.workspaceUnloadPayload(f.context.snapshotWorkspaceState()), null);
  await f.adopt(remotePin(f, false, 13));
  assert.equal(f.requests.length, 1, "later external state cannot silently clear a conflict");
  assert.equal(f.toasts.length, 1);
});

test("external HTTP pin adoption does not touch WebSocket pin or live objects", async () => {
  const f = setup(), connection = {};
  const ws = { id: "ws-tab", type: "websocket", pinned: false, connection, wsPollTimer: 42 };
  f.state.replayTabs.push(ws);
  f.context.workspaceSaveCommittedSnapshot.replay.tabs.push({ id: ws.id, type: "websocket", pinned: false });
  const snapshot = remotePin(f, true);
  snapshot.replay.tabs.push({ id: ws.id, type: "websocket", pinned: true });
  await f.adopt(snapshot);
  assert.equal(f.a.pinned, true); assert.equal(ws.pinned, false);
  assert.equal(ws.connection, connection); assert.equal(ws.wsPollTimer, 42);
  assert.equal(f.context.workspaceSaveCommittedSnapshot.replay.tabs.find(tab => tab.id === ws.id).pinned, false);
});

test("GUI pin toggle remains available for both HTTP and WebSocket tabs", () => {
  const tabs = [{ id: "http", type: "http", pinned: false }, { id: "ws", type: "websocket", pinned: false }];
  let saves = 0, renders = 0;
  const context = loadFunctions(["toggleReplayTabPin"], {
    state: { replayTabs: tabs }, scheduleWorkspaceStateSave: () => saves++,
    flushWorkspaceState: () => Promise.resolve(), renderReplayTabs: () => renders++,
  });
  for (const tab of tabs) {
    context.toggleReplayTabPin(tab.id); assert.equal(tab.pinned, true);
    context.toggleReplayTabPin(tab.id); assert.equal(tab.pinned, false);
  }
  assert.equal(saves, 4); assert.equal(renders, 4);
});
