// Passive state/DOM fixtures only; deferred fetches never leave this process.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource } = require("./frontend-test-helpers.cjs");
const { fixture, plain } = require("./replay-workspace-fixture.cjs");

function selectedFixture() {
  const f = fixture();
  f.a = f.tab("first"); f.b = f.tab("second");
  f.seed([f.a, f.b], f.a.id);
  return f;
}

test("external close chooses the previous pinned-first visual neighbor without rewriting other workspace state", async () => {
  const f = fixture();
  const a = f.tab("a"), p = f.tab("p", true), b = f.tab("b"), q = f.tab("q", true);
  f.seed([a, p, b, q], a.id);
  const fuzzerBaseline = f.context.workspaceSaveCommittedSnapshot.fuzzer;
  await f.adopt(f.remote([p, b, q]));
  assert.equal(f.state.activeReplayTabId, q.id);
  assert.deepEqual(plain(f.state.replayTabs.map(tab => tab.id)), [p.id, b.id, q.id]);
  assert.equal(f.state.replayTabs[0], p);
  assert.equal(f.state.fuzzerRequestText, "GET /local-fuzzer HTTP/1.1");
  assert.equal(f.context.workspaceSaveCommittedSnapshot.fuzzer, fuzzerBaseline);
  assert.equal(f.state.workspaceRevision, 11);
  assert.equal(f.context.workspaceReplayTabsById(f.context.workspaceSaveCommittedSnapshot).has(a.id), false);
});

test("closing the first visual tab chooses the next remaining visual tab", async () => {
  const f = fixture();
  const a = f.tab("unpinned"), p = f.tab("first-pinned", true), q = f.tab("next-pinned", true);
  f.seed([a, p, q], p.id);
  await f.adopt(f.remote([a, q]));
  assert.equal(f.state.activeReplayTabId, q.id);
});

test("closing an inactive tab preserves current unsynced CodeMirror text and focus", async () => {
  const f = selectedFixture();
  f.setEditor("GET /unfinished HTTP/1.1");
  const focus = f.document.activeElement;
  await f.adopt(f.remote([f.a]));
  assert.equal(f.state.activeReplayTabId, f.a.id);
  assert.equal(f.context.getCMView().getContent(), "GET /unfinished HTTP/1.1");
  assert.equal(f.document.activeElement, focus);
  assert.deepEqual(f.renders.map(render => render.kind), ["strip"]);
});

test("closing the last saved HTTP tab makes a fresh local draft with monotonic sequence", async () => {
  const f = fixture(), a = f.tab("last");
  f.state.replayTabSequence = 93;
  f.seed([a]);
  await f.adopt(f.remote([]));
  const fresh = f.state.replayTabs[0];
  assert.notEqual(fresh.id, a.id);
  assert.equal(fresh.sequence, 94);
  assert.equal(f.state.replayTabSequence, 94);
  assert.equal(f.context.workspaceSaveCommittedSnapshot.replay.tabs.length, 0);
  await f.adopt(f.remote([], 12));
  assert.equal(f.state.replayTabs[0], fresh, "uncommitted replacement must not be mistaken for an external deletion");
  assert.equal(f.state.replayTabSequence, 94);
  assert.equal(f.context.snapshotWorkspaceState().replay.tabs.some(tab => tab.id === a.id), false);
});

test("omitted local-only drafts and live WebSocket objects are preserved", async () => {
  const f = selectedFixture(), local = f.tab("local");
  const connection = { close() { assert.fail("must not close connections"); } };
  const ws = { id: "ws-tab", type: "websocket", sequence: 4, wsStatus: "connected", connection, wsPollTimer: 91 };
  f.state.replayTabs.push(local, ws);
  f.context.workspaceSaveCommittedSnapshot.replay.tabs.push({ id: ws.id, type: "websocket", sequence: 4 });
  f.state.activeReplayTabId = local.id; f.syncDom();
  const baselineFuzzer = plain(f.context.workspaceSaveCommittedSnapshot.fuzzer);
  await f.adopt(f.remote([f.a]));
  assert.equal(f.state.activeReplayTabId, local.id);
  assert.equal(f.state.replayTabs.find(tab => tab.id === local.id), local);
  assert.equal(f.state.replayTabs.find(tab => tab.id === ws.id), ws);
  assert.equal(ws.connection, connection); assert.equal(ws.wsPollTimer, 91); assert.equal(ws.wsStatus, "connected");
  assert.deepEqual(plain(f.context.workspaceSaveCommittedSnapshot.fuzzer), baselineFuzzer);
});

const conflicts = {
  "state request text": f => { f.a.requestText += "draft"; f.syncDom(); },
  "base request": f => { f.a.baseRequest.path = "/draft"; },
  "custom label": f => { f.a.customLabel = "draft label"; },
  "pin state": f => { f.a.pinned = true; },
  "history": f => { f.a.historyEntries.push({ request: f.a.baseRequest, requestText: f.a.requestText, targetScheme: "https", targetHost: "example.com", targetPort: "443" }); },
  "response": f => { f.a.responseRecord = { id: "local-response" }; },
  "notice": f => { f.a.notice = "Local activity"; },
  "target": f => { f.a.targetHost = "draft.example.com"; f.syncDom(); },
  "source transaction": f => { f.a.sourceTransactionId = "local-source"; },
  "unsynced CodeMirror": f => f.setEditor("GET /draft HTTP/1.1"),
  "unsynced contenteditable": f => { f.els.replayRequestHighlight.innerText = "GET /draft HTTP/1.1"; },
  "unsynced textarea fallback": f => { delete f.els.replayRequestHighlight; f.els.replayRequestEditor.value = "GET /draft HTTP/1.1"; },
  "unsynced host": f => { f.els.replayHostInput.value = "draft.example.com"; },
  "invalid target port": f => { f.els.replayPortInput.value = "not-yet-a-port"; },
  "target scheme": f => { f.els.replaySchemeSelect.value = "http"; },
  "HTTP version control": f => { f.versionSelect.value = "HTTP/2"; },
  "binary bytes": f => { f.a.requestBytes = new Uint8Array([255, 0, 1]); },
  "hex view": f => { f.state.replayMessageViews.request = "hex"; },
  "pending rename": f => { f.state.replayRenamingTabId = f.a.id; f.els.renameInput = { value: "uncommitted label", selectionStart: 3 }; },
  "in-flight activity": f => { f.context._replaySendControllers.set(f.a.id, { abort() { assert.fail("must not abort activity"); } }); },
};
for (const [name, mutate] of Object.entries(conflicts)) {
  test(`deleted-tab ${name} creates a persistent conflict without changing draft, modal, or baseline`, async () => {
    const f = selectedFixture(); mutate(f);
    f.els.modal = { value: "unfinished modal", open: true };
    const baseline = plain(f.context.workspaceSaveCommittedSnapshot), state = plain(f.state), dom = plain(f.els);
    await f.adopt(f.remote([f.b]));
    assert.equal(f.context.workspaceSaveConflictPending, true);
    assert.equal(f.state.workspaceRevision, 10);
    assert.equal(f.state.replayTabs[0], f.a);
    assert.deepEqual(plain(f.state), state); assert.deepEqual(plain(f.els), dom);
    assert.deepEqual(plain(f.context.workspaceSaveCommittedSnapshot), baseline);
    assert.equal(f.renders.length, 0); assert.equal(f.toasts.length, 1);
    assert.match(f.toasts[0][0], /unsaved; copy them before reloading/);
    await f.adopt(f.remote([f.b, f.tab("another")], 13));
    assert.equal(f.requests.length, 1, "later events cannot advance or clear the conflict");
    assert.equal(f.state.workspaceRevision, 10);
  });
}

test("CRLF normalization alone is not a local edit", async () => {
  const f = selectedFixture(); f.setEditor(f.a.requestText.replace(/\r\n/g, "\n"));
  await f.adopt(f.remote([f.b]));
  assert.equal(f.context.workspaceSaveConflictPending, false);
  assert.equal(f.state.activeReplayTabId, f.b.id);
});

test("a conflict blocks queued autosave, direct save, beacon and keepalive payloads", async () => {
  const f = selectedFixture(); f.a.customLabel = "draft";
  await f.adopt(f.remote([f.b]));
  f.context.scheduleWorkspaceStateSave();
  await f.context.flushQueuedWorkspaceStateSave();
  await assert.rejects(f.context.saveWorkspaceState(), { name: "WorkspaceStateConflictError" });
  await assert.rejects(f.context.flushWorkspaceState(), { name: "WorkspaceStateConflictError" });
  const event = { type: "beforeunload", preventDefault() { this.prevented = true; } };
  f.context.flushWorkspaceStateOnUnload(event);
  assert.equal(event.prevented, true); assert.equal(event.returnValue, "Unsaved edits");
  assert.equal(f.context.workspaceUnloadPayload(f.context.snapshotWorkspaceState()), null);
  assert.equal(f.requests.length, 1); assert.equal(f.beacons.length, 0);
  assert.equal(f.context.clearBypassableWorkspaceConflict({ bypassExpectedActiveSessionGuard: true }), false);
});

for (const revision of [10, 11, 19]) {
  test(`late save acknowledgement at revision ${revision} cannot clear an adopted deletion conflict`, async () => {
    const f = selectedFixture();
    f.context.scheduleWorkspaceStateSave();
    const saving = f.context.flushQueuedWorkspaceStateSave();
    f.setEditor("GET /unsynced HTTP/1.1");
    await f.adopt(f.remote([f.b], 12));
    f.succeed(0, { session_id: "session-a", revision }); await saving;
    assert.equal(f.context.workspaceSaveConflictPending, true); assert.equal(f.context.workspaceSaveDirty, true);
    assert.equal(f.state.workspaceRevision, 10); assert.equal(f.context.workspaceSaveConflictLatest.revision, 12);
    assert.equal(f.context.getCMView().getContent(), "GET /unsynced HTTP/1.1");
    assert.equal(f.requests.length, 2);
  });
}

test("a delayed older/equal save acknowledgement cannot restore an adopted deletion baseline", async () => {
  for (const revision of [11, 12]) {
    const f = selectedFixture(), snapshot = f.context.snapshotWorkspaceState();
    const saving = f.context.saveWorkspaceState(snapshot);
    f.context.workspaceSaveLastSnapshot = snapshot; f.context.workspaceSaveInFlight = true;
    await f.adopt(f.remote([f.b], 12));
    f.succeed(0, { session_id: "session-a", revision }); await saving;
    assert.equal(f.state.workspaceRevision, 12);
    assert.equal(f.context.workspaceReplayTabsById(f.context.workspaceSaveCommittedSnapshot).has(f.a.id), false);
    assert.equal(f.context.workspaceSaveLastSnapshot, null);
    f.context.flushWorkspaceStateOnUnload({ type: "pagehide" });
    const posted = JSON.parse(await f.beacons[0].blob.text());
    assert.equal(posted.replay.tabs.some(tab => tab.id === f.a.id), false);
    assert.equal(posted.revision, 12);
  }
});

test("normal save still commits and updates the baseline", async () => {
  const f = selectedFixture(); f.a.customLabel = "local save";
  const saving = f.context.saveWorkspaceState();
  f.succeed(0, { session_id: "session-a", revision: 11 }); await saving;
  assert.equal(f.state.workspaceRevision, 11);
  assert.equal(f.context.workspaceSaveCommittedSnapshot.replay.tabs[0].custom_label, "local save");
});

test("newer accepted fetch wins over a late older fetch, even if its payload claims a newer revision", async () => {
  const f = selectedFixture(), first = f.context.adoptExternalReplayTabs(), second = f.context.adoptExternalReplayTabs();
  f.succeed(1, f.remote([f.b], 12)); await second;
  f.succeed(0, f.remote([f.a, f.b], 13)); await first;
  assert.equal(f.state.workspaceRevision, 12); assert.equal(f.state.replayTabs.some(tab => tab.id === f.a.id), false);
});

test("an older revision fetched after a save is ignored", async () => {
  const f = selectedFixture(), reading = f.context.adoptExternalReplayTabs(), saving = f.context.saveWorkspaceState();
  f.succeed(1, { session_id: "session-a", revision: 12 }); await saving;
  f.succeed(0, f.remote([], 11)); await reading;
  assert.equal(f.state.workspaceRevision, 12); assert.equal(f.state.replayTabs.length, 2);
});

test("A to B to A workspace generation rejects stale adoption and save acknowledgement", async () => {
  const f = selectedFixture(), reading = f.context.adoptExternalReplayTabs(), saving = f.context.saveWorkspaceState();
  const resetStart = appSource.indexOf("function resetSessionScopedUiState() {");
  const resetEnd = appSource.indexOf("  clearReplaySendInFlight();", resetStart);
  assert.ok(resetEnd > resetStart);
  // Run the production reset prefix: generation/loading changes happen before
  // unrelated panel cleanup and do not require constructing those panels.
  const resetPrefix = `${appSource.slice(resetStart, resetEnd)}\n}`;
  vm.runInContext(resetPrefix, f.context);
  f.state.activeSession = { id: "session-b" }; f.context.resetSessionScopedUiState();
  f.state.activeSession = { id: "session-a" }; f.context.resetSessionScopedUiState(); f.context.workspaceLoaded = true;
  f.succeed(0, f.remote([], 20)); f.succeed(1, { session_id: "session-a", revision: 21 });
  await reading; await saving;
  assert.equal(f.state.workspaceRevision, 10); assert.equal(f.state.replayTabs.length, 2);
});

for (const badSnapshot of [f => ({ ...f.remote([]), session_id: "session-b" }), f => ({ ...f.remote([]), replay: {} }), f => ({ ...f.remote([]), revision: 10 })]) {
  test("wrong-session, malformed, or non-newer snapshot cannot delete tabs", async () => {
    const f = selectedFixture(); await f.adopt(badSnapshot(f));
    assert.equal(f.state.replayTabs.length, 2); assert.equal(f.state.workspaceRevision, 10); assert.equal(f.renders.length, 0);
  });
}

test("workspace SSE ignores stale event sessions and echoes before fetching", () => {
  const f = selectedFixture(); let listener;
  f.context.eventSessionId = "session-a";
  f.context.eventSource = { addEventListener: (_, fn) => { listener = fn; } };
  const start = appSource.indexOf('  eventSource.addEventListener("workspace_state",');
  const end = appSource.indexOf("\n  });", start) + 6;
  vm.runInContext(appSource.slice(start, end), f.context);
  listener({ data: JSON.stringify({ client_id: "ui-client" }) });
  listener({ data: JSON.stringify({ client_id: "cli", session_id: "session-b" }) });
  f.state.activeSession = { id: "session-b" };
  listener({ data: JSON.stringify({ client_id: "cli" }) });
  assert.equal(f.requests.length, 0);
});

test("an incoming snapshot does not reopen a baseline tab already closed locally", async () => {
  const f = selectedFixture();
  f.state.replayTabs = [f.b]; f.state.activeReplayTabId = f.b.id; f.syncDom();
  const added = f.tab("remote duplicate");
  await f.adopt(f.remote([f.a, f.b, added]));
  assert.equal(f.state.replayTabs.some(tab => tab.id === f.a.id), false);
  assert.equal(f.state.replayTabs.length, 2); assert.equal(f.state.activeReplayTabId, f.b.id);
});

test("clean externally added and updated HTTP tabs can subsequently be closed", async () => {
  const f = selectedFixture(), added = f.tab("remote duplicate");
  await f.adopt(f.remote([f.a, f.b, added]));
  const updated = f.remote([f.a, f.b, added], 12);
  const incoming = updated.replay.tabs.find(tab => tab.id === added.id);
  incoming.custom_label = "remote rename"; incoming.request_text = "GET /changed HTTP/1.1";
  incoming.base_request.path = "/changed"; incoming.response_record = { id: "saved-response" };
  await f.adopt(updated);
  assert.equal(f.state.replayTabs.find(tab => tab.id === added.id).requestText, incoming.request_text);
  await f.adopt(f.remote([f.a, f.b], 13));
  assert.equal(f.context.workspaceSaveConflictPending, false);
  assert.equal(f.state.replayTabs.some(tab => tab.id === added.id), false);
});

test("a surviving rename defers destructive strip rendering even when selection changes", async () => {
  const f = selectedFixture();
  f.state.replayRenamingTabId = f.b.id;
  f.els.renameInput = { value: "unfinished rename", selectionStart: 5 };
  f.document.activeElement = f.els.renameInput;
  const input = f.els.renameInput;
  await f.adopt(f.remote([f.b]));
  assert.equal(f.state.activeReplayTabId, f.b.id);
  assert.equal(f.document.activeElement, input); assert.equal(input.value, "unfinished rename");
  assert.equal(f.renders[0].options.preserveTabStrip, true);
});


test("new-session autosave resumes when its timer joined an old in-flight loop", async () => {
  const f = selectedFixture();
  f.context.scheduleWorkspaceStateSave();
  const oldLoop = f.context.flushQueuedWorkspaceStateSave();
  f.context.workspaceStateGeneration += 1; f.state.activeSession = { id: "session-b" };
  f.state.workspaceRevision = 3;
  f.context.workspaceSaveCommittedSnapshot = plain(f.context.snapshotWorkspaceState());
  f.context.scheduleWorkspaceStateSave();
  const timer = f.context.workspaceSaveTimer, callback = f.timers.get(timer);
  f.timers.delete(timer); callback();
  f.succeed(0, { session_id: "session-a", revision: 11 }); await oldLoop;
  assert.equal(f.state.workspaceRevision, 3);
  assert.equal(f.context.workspaceSaveDirty, true);
  assert.ok(f.timers.has(f.context.workspaceSaveTimer), "a new timer must remain after the old loop settles");
  const newLoop = f.context.flushQueuedWorkspaceStateSave();
  assert.equal(f.requests.length, 2);
  assert.equal(JSON.parse(f.requests[1].options.body).session_id, "session-b");
  f.succeed(1, { session_id: "session-b", revision: 4 }); await newLoop;
  assert.equal(f.state.workspaceRevision, 4); assert.equal(f.context.workspaceSaveDirty, false);
});


test("a dirty inactive deletion preserves every current editor and leaves clean deletions unapplied", async () => {
  const f = selectedFixture(), clean = f.tab("clean");
  f.seed([clean, f.a, f.b], f.b.id);
  f.a.customLabel = "inactive draft";
  f.setEditor("GET /active-uncommitted HTTP/1.1");
  f.state.replayRenamingTabId = f.b.id;
  f.els.renameInput = { value: "still typing" };
  const baseline = plain(f.context.workspaceSaveCommittedSnapshot);
  const added = f.tab("new-remote");
  const reading = f.context.adoptExternalReplayTabs(), concurrent = f.context.adoptExternalReplayTabs();
  f.succeed(0, f.remote([f.b, added], 11)); await reading;
  f.succeed(1, f.remote([added], 12)); await concurrent;
  assert.equal(f.context.workspaceSaveConflictPending, true);
  assert.equal(f.state.workspaceRevision, 10);
  assert.deepEqual(plain(f.state.replayTabs.map(tab => tab.id)), [clean.id, f.a.id, f.b.id]);
  assert.equal(f.state.activeReplayTabId, f.b.id);
  assert.equal(f.context.getCMView().getContent(), "GET /active-uncommitted HTTP/1.1");
  assert.equal(f.els.renameInput.value, "still typing");
  assert.deepEqual(plain(f.context.workspaceSaveCommittedSnapshot), baseline);
  assert.equal(f.renders.length, 0);
});

test("the existing local close-last flow also preserves tab sequence and generates a new ID", async () => {
  const f = fixture(), last = f.tab("last");
  f.state.replayTabSequence = 80; f.seed([last]);
  const closing = f.context.closeRepeaterTab(last.id);
  assert.equal(f.requests.length, 1);
  const payload = JSON.parse(f.requests[0].options.body);
  assert.equal(payload.replay.tab_sequence, 81);
  assert.equal(payload.replay.tabs[0].sequence, 81);
  assert.notEqual(payload.replay.tabs[0].id, last.id);
  f.succeed(0, { session_id: "session-a", revision: 11 }); await closing;
  assert.equal(f.state.replayTabSequence, 81);
});


for (const closeLocally of [false, true]) {
  test(`${closeLocally ? "local" : "external"} close preserves a legacy tab sequence ahead of its counter`, async () => {
    const f = fixture(), last = f.tab("legacy");
    last.sequence = 50; f.state.replayTabSequence = 1; f.seed([last]);
    if (closeLocally) {
      const closing = f.context.closeRepeaterTab(last.id);
      f.succeed(0, { session_id: "session-a", revision: 11 }); await closing;
    } else {
      await f.adopt(f.remote([]));
    }
    assert.equal(f.state.replayTabs[0].sequence, 51); assert.equal(f.state.replayTabSequence, 51);
  });
}

test("external adoption fetch is pinned to its initiating session in the query", async () => {
  const f = selectedFixture(); f.state.activeSession.id = "session with/slash";
  const reading = f.context.adoptExternalReplayTabs();
  assert.equal(f.requests[0].url, "/api/workspace-state?session_id=session%20with%2Fslash");
  f.succeed(0, f.remote([f.b])); await reading;
  assert.equal(f.state.workspaceRevision, 11);
});
