// Passive close/save races only: no server or outgoing traffic.
const assert = require('node:assert/strict');
const test = require('node:test');
const { fixture, deferred, plain } = require('./replay-workspace-fixture.cjs');
function setup() {
  const f = fixture(); f.a = f.tab('a'); f.b = f.tab('b');
  f.seed([f.a, f.b]); f.context.handleWorkspaceActionError = () => {}; return f;
}
async function fail(f, closing) { f.requests[0].reject(new Error('synthetic connection loss')); await closing; }

test('failed local close does not resurrect a separately externally closed tab', async () => {
  const f = setup(), closing = f.context.closeRepeaterTab(f.a.id);
  await f.adopt(f.remote([f.a], 11));
  const baseline = f.context.workspaceSaveCommittedSnapshot;
  await fail(f, closing);
  assert.equal(f.state.replayTabs.includes(f.a), true);
  assert.equal(f.state.replayTabs.some(t => t.id === f.b.id), false);
  assert.equal(f.context.snapshotWorkspaceState().replay.tabs.some(t => t.id === f.b.id), false);
  assert.equal(f.state.workspaceRevision, 11);
  assert.equal(f.context.workspaceSaveCommittedSnapshot, baseline);
});

test('failure preserves newer local and adopted metadata, identities, sequence, and new tabs', async () => {
  const f = setup(), c = f.tab('c'); f.seed([f.a, f.b, c], c.id);
  const closing = f.context.closeRepeaterTab(f.a.id);
  const incoming = f.remote([f.b, c], 12);
  incoming.replay.tabs[0].custom_label = 'remote label';
  incoming.replay.tabs[0].request_text = 'GET /remote HTTP/1.1';
  incoming.replay.tabs[0].base_request.path = '/remote';
  await f.adopt(incoming);
  c.customLabel = 'new-unsaved'; c.requestText = 'GET /local HTTP/1.1';
  const added = f.tab('new'); f.state.replayTabs.push(added);
  const baseline = plain(f.context.workspaceSaveCommittedSnapshot), sequence = f.state.replayTabSequence;
  await fail(f, closing);
  assert.equal(f.state.replayTabs.find(t => t.id === f.b.id), f.b);
  assert.equal(f.b.customLabel, 'remote label'); assert.equal(f.b.requestText, 'GET /remote HTTP/1.1');
  assert.equal(f.state.replayTabs.find(t => t.id === c.id), c);
  assert.equal(c.customLabel, 'new-unsaved'); assert.equal(c.requestText, 'GET /local HTTP/1.1');
  assert.equal(f.state.replayTabs.includes(added), true);
  assert.equal(f.state.replayTabSequence, sequence); assert.equal(f.state.workspaceRevision, 12);
  assert.deepEqual(plain(f.context.workspaceSaveCommittedSnapshot), baseline);
});

test('pending same-ID close survives two adoptions after its baseline was removed', async () => {
  const f = setup(), closing = f.context.closeRepeaterTab(f.a.id);
  await f.adopt(f.remote([f.b], 11));
  const sameId = f.remote([f.b, f.a], 12); sameId.replay.tabs[1].custom_label = 'remote replacement';
  await f.adopt(sameId);
  assert.equal(f.state.replayTabs.some(t => t.id === f.a.id), false);
  await fail(f, closing);
  assert.equal(f.state.replayTabs.find(t => t.id === f.a.id), f.a);
  assert.equal(f.a.customLabel, 'a'); assert.equal(f.context.workspacePendingReplayCloses.size, 0);
});

for (const order of ['success-first', 'failure-first']) {
  test(`overlapping closes settle ${order} without clearing another marker or replaying old tabs`, async () => {
    const f = setup(), c = f.tab('c'); f.seed([f.a, f.b, c], c.id);
    const a = deferred(), b = deferred(); let count = 0;
    f.context.flushWorkspaceState = () => (++count === 1 ? a.promise : b.promise);
    const closeA = f.context.closeRepeaterTab(f.a.id), closeB = f.context.closeRepeaterTab(f.b.id);
    assert.equal(f.context.workspacePendingReplayCloses.size, 2);
    if (order === 'success-first') {
      a.resolve(); await closeA;
      assert.equal(f.context.workspacePendingReplayCloses.has(f.b.id), true);
      b.reject(new Error('uncertain')); await closeB;
    } else {
      b.reject(new Error('uncertain')); await closeB;
      assert.equal(f.context.workspacePendingReplayCloses.has(f.a.id), true);
      a.resolve(); await closeA;
    }
    assert.deepEqual(plain(f.state.replayTabs.map(t => t.id)), [f.b.id, c.id]);
    assert.equal(f.state.replayTabs[0], f.b); assert.equal(f.state.replayTabs[1], c);
    assert.equal(f.context.workspacePendingReplayCloses.size, 0);
    assert.equal(f.context.workspaceSaveConflictPending, true);
  });
}

test('shared failed save restores both overlapping removed objects without reverting active selection', async () => {
  const f = setup(), c = f.tab('c'); f.seed([f.a, f.b, c], c.id);
  const closeA = f.context.closeRepeaterTab(f.a.id), closeB = f.context.closeRepeaterTab(f.b.id);
  await fail(f, closeA); await closeB;
  assert.deepEqual(plain(f.state.replayTabs.map(t => t.id)), [f.a.id, f.b.id, c.id]);
  assert.equal(f.state.activeReplayTabId, c.id); assert.equal(f.context.workspacePendingReplayCloses.size, 0);
});

test('inactive close and recovery preserve unsynced DOM, rename, modal, focus and active selection', async () => {
  const f = setup(); f.seed([f.a, f.b], f.b.id);
  f.els.replayRequestHighlight.innerText = 'unfinished draft';
  f.state.replayRenamingTabId = f.b.id;
  f.els.renameInput = { value: 'unfinished name', selectionStart: 4 };
  f.els.modal = { open: true, value: 'unfinished modal' };
  f.document.activeElement = f.els.renameInput;
  const dom = plain(f.els), focus = f.document.activeElement;
  const closing = f.context.closeRepeaterTab(f.a.id); await fail(f, closing);
  assert.deepEqual(plain(f.els), dom); assert.equal(f.document.activeElement, focus);
  assert.equal(f.state.activeReplayTabId, f.b.id); assert.equal(f.state.replayRenamingTabId, f.b.id);
  assert.equal(f.renders.length, 0);
});

test('inactive close without rename only refreshes the strip on removal and recovery', async () => {
  const f = setup(); f.seed([f.a, f.b], f.b.id);
  f.els.replayRequestHighlight.innerText = 'unfinished draft';
  const closing = f.context.closeRepeaterTab(f.a.id); await fail(f, closing);
  assert.equal(f.els.replayRequestHighlight.innerText, 'unfinished draft');
  assert.deepEqual(f.renders.map(r => r.kind), ['strip', 'strip']);
});

test('active close keeps the fallback and its newer editor on failure', async () => {
  const f = setup(), closing = f.context.closeRepeaterTab(f.a.id);
  f.els.replayRequestHighlight.innerText = 'new fallback draft';
  await fail(f, closing);
  assert.equal(f.state.activeReplayTabId, f.b.id);
  assert.equal(f.els.replayRequestHighlight.innerText, 'new fallback draft');
  assert.deepEqual(f.renders.map(r => r.kind), ['full', 'strip']);
});

test('last-tab replacement and monotonic sequence survive failure', async () => {
  const f = fixture(), a = f.tab('last'); f.seed([a]);
  const closing = f.context.closeRepeaterTab(a.id), replacement = f.state.replayTabs[0];
  const sequence = f.state.replayTabSequence;
  await fail(f, closing);
  assert.equal(f.state.replayTabs.includes(a), true); assert.equal(f.state.replayTabs.includes(replacement), true);
  assert.equal(f.state.activeReplayTabId, replacement.id); assert.equal(f.state.replayTabSequence, sequence);
});

for (const change of ['generation', 'session']) {
  test(`late close failure after ${change} switch cannot mutate the new workspace`, async () => {
    const f = setup(), closing = f.context.closeRepeaterTab(f.a.id);
    if (change === 'generation') f.context.workspaceStateGeneration += 1;
    else f.state.activeSession = { id: 'session-b' };
    const newer = f.tab('new workspace'); f.seed([newer]);
    const marker = { generation: f.context.workspaceStateGeneration, sessionId: f.state.activeSession.id };
    f.context.workspacePendingReplayCloses.set(f.a.id, marker);
    f.context.workspaceSaveConflictPending = false;
    await fail(f, closing);
    assert.deepEqual(plain(f.state.replayTabs.map(t => t.id)), [newer.id]);
    assert.equal(f.context.workspaceSaveConflictPending, false);
    assert.equal(f.context.workspacePendingReplayCloses.get(f.a.id), marker);
  });
}

test('failure keeps conflict latest, cancels timers and blocks autosave and unload writes', async () => {
  const f = setup(), closing = f.context.closeRepeaterTab(f.a.id);
  f.context.wsTranscriptSaveTimer = f.context.window.setTimeout(() => assert.fail('stale timer'));
  f.context.workspaceSaveConflictLatest = { revision: 30 };
  await fail(f, closing);
  assert.equal(f.context.workspaceSaveConflictLatest.revision, 30);
  assert.equal(f.context.workspaceSaveConflictPending, true); assert.equal(f.context.workspaceSaveDirty, true);
  assert.equal(f.context.workspaceSaveLastSnapshot, null); assert.equal(f.timers.size, 0);
  f.context.scheduleWorkspaceStateSave(); await f.context.flushQueuedWorkspaceStateSave();
  const event = { type: 'beforeunload', preventDefault() { this.prevented = true; } };
  f.context.flushWorkspaceStateOnUnload(event);
  assert.equal(event.prevented, true); assert.equal(f.requests.length, 1); assert.equal(f.beacons.length, 0);
  assert.match(f.toasts.at(-1)[0], /restored locally; changes are unsaved/);
});

test('409 close failure preserves server latest while recovering only its tab', async () => {
  const f = setup(), closing = f.context.closeRepeaterTab(f.a.id), latest = f.remote([f.b], 17);
  f.requests[0].resolve({ ok: false, status: 409, json: async () => latest }); await closing;
  assert.equal(f.context.workspaceSaveConflictLatest, latest);
  assert.equal(f.state.replayTabs.includes(f.a), true); assert.equal(f.context.workspaceSaveConflictPending, true);
});

for (const cap of [false, true]) {
  test(`${cap ? 'tab-cap rejection' : 'success'} keeps close and clears its marker`, async () => {
    const f = setup(), closing = f.context.closeRepeaterTab(f.a.id);
    if (cap) f.requests[0].resolve({ ok: false, status: 400, text: async () => 'too many replay tabs' });
    else f.succeed(0, { session_id: 'session-a', revision: 11 });
    await closing;
    assert.equal(f.state.replayTabs.some(t => t.id === f.a.id), false);
    assert.equal(f.context.workspacePendingReplayCloses.size, 0); assert.equal(f.context.workspaceSaveConflictPending, false);
  });
}


test('shared loop second POST failure preserves newer work after its first POST succeeded', async () => {
  const f = setup(), c = f.tab('c'); f.seed([f.a, f.b, c], c.id);
  const closeA = f.context.closeRepeaterTab(f.a.id), closeB = f.context.closeRepeaterTab(f.b.id);
  f.succeed(0, { session_id: 'session-a', revision: 11 });
  // Drain the known JSON/save promise chain until the queued POST is issued.
  for (let i = 0; i < 10 && f.requests.length < 2; i += 1) await Promise.resolve();
  assert.equal(f.requests.length, 2);
  const baseline = f.context.workspaceSaveCommittedSnapshot;
  c.customLabel = 'newer draft';
  f.requests[1].reject(new Error('second POST uncertain'));
  await Promise.all([closeA, closeB]);
  assert.equal(f.state.workspaceRevision, 11); assert.equal(f.context.workspaceSaveCommittedSnapshot, baseline);
  assert.equal(f.state.replayTabs.includes(f.a), true); assert.equal(f.state.replayTabs.includes(f.b), true);
  assert.equal(f.state.replayTabs.find(t => t.id === c.id), c); assert.equal(c.customLabel, 'newer draft');
  assert.equal(f.context.workspaceSaveConflictPending, true); assert.equal(f.context.workspacePendingReplayCloses.size, 0);
});
