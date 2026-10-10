// Passive metadata/save races only: synthetic VM state, no server or traffic.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { fixture, deferred } = require("./replay-workspace-fixture.cjs");
const { appSource } = require("./frontend-test-helpers.cjs");

function setup(kind, initial = kind === "pin" ? false : "old") {
  const f = fixture();
  f.a = f.tab(kind === "label" ? initial : "old", kind === "pin" ? initial : false);
  f.seed([f.a]);
  f.errors = [];
  f.context.handleWorkspaceActionError = error => f.errors.push(error);
  for (const name of ["toggleReplayTabPin", "commitReplayTabRename"]) {
    vm.runInContext(appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, "m"))[0], f.context);
  }
  f.field = kind === "pin" ? "pinned" : "customLabel";
  f.key = kind === "pin" ? "pinned" : "custom_label";
  f.value = () => f.a[f.field];
  f.edit = value => {
    if (kind === "pin") {
      assert.equal(value, !f.a.pinned, "fixture pin actions are toggles");
      f.context.toggleReplayTabPin(f.a.id);
    } else {
      f.state.replayRenamingTabId = f.a.id;
      f.context.commitReplayTabRename(f.a.id, value);
    }
  };
  f.remoteValue = (value, revision) => {
    const snapshot = f.remote([f.a], revision);
    snapshot.replay.tabs[0][f.key] = value;
    return snapshot;
  };
  return f;
}

const settled = () => new Promise(resolve => setImmediate(resolve));
async function failInitialSave(f) {
  f.requests[0].reject(new Error("synthetic transport loss"));
  await settled();
}
async function retryValue(f, value, revision) {
  assert.equal(f.context.workspaceSaveDirty, true);
  assert.equal(f.context.workspaceSaveConflictPending, false);
  assert.ok(f.timers.size, "the existing automatic retry remains queued");
  const saving = f.context.flushQueuedWorkspaceStateSave();
  const posted = JSON.parse(f.requests.at(-1).options.body);
  assert.equal(posted.revision, revision);
  assert.equal(posted.replay.tabs[0][f.key], value);
  f.succeed(f.requests.length - 1, { session_id: "session-a", revision: revision + 1 });
  await saving;
}

for (const [kind, initial, attempted] of [
  ["pin", false, true], ["pin", true, false], ["label", "old", "new"], ["label", "old", ""],
]) {
  test(`${kind} ${JSON.stringify(initial)} to ${JSON.stringify(attempted)} survives an old failure after external confirmation`, async () => {
    const f = setup(kind, initial);
    f.edit(attempted);
    await f.adopt(f.remoteValue(attempted, 12));
    const baseline = f.context.workspaceReplayTabsById(f.context.workspaceSaveCommittedSnapshot).get(f.a.id);
    assert.equal(baseline[f.key], attempted);
    const renders = f.renders.length;
    await failInitialSave(f);
    assert.equal(f.value(), attempted);
    assert.equal(f.renders.length, renders, "a stale error cannot redraw the current strip");
    await retryValue(f, attempted, 12);
  });

  test(`${kind} retains a later remote reversal when the earlier save fails`, async () => {
    const f = setup(kind, initial);
    f.edit(attempted);
    await f.adopt(f.remoteValue(attempted, 12));
    await f.adopt(f.remoteValue(initial, 13));
    await failInitialSave(f);
    assert.equal(f.value(), initial);
    await retryValue(f, initial, 13);
  });

  test(`${kind} ordinary failure without a newer snapshot still restores its previous value`, async () => {
    const f = setup(kind, initial);
    f.edit(attempted);
    await failInitialSave(f);
    assert.equal(f.value(), initial);
    await retryValue(f, initial, 10);
  });
}

for (const kind of ["pin", "label"]) {
  test(`${kind} rejected revision keeps the existing conflict barrier`, async () => {
    const f = setup(kind), initial = f.value();
    f.edit(kind === "pin" ? true : "local");
    f.requests[0].resolve({ ok: false, status: 409, json: async () => f.remoteValue(initial, 12) });
    await settled();
    assert.equal(f.value(), initial);
    assert.equal(f.context.workspaceSaveConflictPending, true);
    assert.equal(f.context.workspaceSaveDirty, true);
    assert.equal(f.context.workspaceUnloadPayload(f.context.snapshotWorkspaceState()), null);
    await f.context.flushQueuedWorkspaceStateSave();
    assert.equal(f.requests.length, 1);
  });

  test(`${kind} keeps the pending desired value after an unrelated newer workspace revision`, async () => {
    const f = setup(kind), attempted = kind === "pin" ? true : "local";
    const incoming = f.remoteValue(f.value(), 12);
    f.edit(attempted);
    await f.adopt(incoming);
    await failInitialSave(f);
    // A newer revision conservatively invalidates rollback ownership even if
    // this field did not change remotely. Retrying the local intent is deliberate.
    assert.equal(f.value(), attempted);
    await retryValue(f, attempted, 12);
  });

  for (const olderOutcome of ["success", "failure"]) {
    test(`${kind} older ${olderOutcome} cannot clear the newest ABA edit owner`, async () => {
      const f = setup(kind), pending = [deferred(), deferred(), deferred()];
      let next = 0;
      f.context.flushWorkspaceState = () => pending[next++].promise;
      const first = kind === "pin" ? true : "first";
      const second = kind === "pin" ? false : "second";
      f.edit(first); f.edit(second); f.edit(first);
      const renders = f.renders.length;
      if (olderOutcome === "success") pending[0].resolve();
      else pending[0].reject(new Error("old failure"));
      await settled();
      assert.equal(f.value(), first);
      assert.equal(f.renders.length, renders);
      pending[2].reject(new Error("newest failure"));
      await settled();
      assert.equal(f.value(), second, "the newest failure still owns its rollback");
      pending[1].reject(new Error("middle failure arrived last"));
      await settled();
      assert.equal(f.value(), second, "an older callback cannot undo that rollback");
    });
  }

  test(`${kind} older failure cannot roll back a newer successful ABA edit`, async () => {
    const f = setup(kind), pending = [deferred(), deferred(), deferred()];
    let next = 0;
    f.context.flushWorkspaceState = () => pending[next++].promise;
    const first = kind === "pin" ? true : "first";
    f.edit(first); f.edit(kind === "pin" ? false : "second"); f.edit(first);
    pending[2].resolve(); await settled();
    const renders = f.renders.length;
    pending[0].reject(new Error("old failure"));
    pending[1].reject(new Error("middle failure"));
    await settled();
    assert.equal(f.value(), first);
    assert.equal(f.renders.length, renders);
  });

  for (const change of ["generation", "session", "tab identity"]) {
    test(`${kind} failure cannot mutate or redraw a different ${change}`, async () => {
      const f = setup(kind), attempted = kind === "pin" ? true : "new";
      const pending = deferred();
      f.context.flushWorkspaceState = () => pending.promise;
      f.edit(attempted);
      if (change === "generation") f.context.workspaceStateGeneration++;
      else if (change === "session") f.state.activeSession = { id: "session-b" };
      else f.state.replayTabs = [{ ...f.a }];
      const renders = f.renders.length;
      pending.reject(new Error("old session failure")); await settled();
      assert.equal(f.value(), attempted);
      assert.equal(f.state.replayTabs[0][f.field], attempted);
      assert.equal(f.renders.length, renders);
      assert.equal(f.errors.length, 0);
    });
  }
}

test("divergent remote label preserves the existing local-intent retry policy", async () => {
  const f = setup("label");
  f.edit("local");
  await f.adopt(f.remoteValue("remote", 12));
  await failInitialSave(f);
  assert.equal(f.value(), "local");
  assert.equal(f.context.workspaceReplayTabsById(f.context.workspaceSaveCommittedSnapshot).get(f.a.id).custom_label, "old");
  await retryValue(f, "local", 12);
});

test("pin and label edits have independent rollback owners on the same tab", async () => {
  const f = setup("label"), pin = deferred(), label = deferred();
  let next = 0;
  f.context.flushWorkspaceState = () => (next++ ? label : pin).promise;
  f.context.toggleReplayTabPin(f.a.id);
  f.edit("new");
  pin.reject(new Error("pin failure")); await settled();
  assert.equal(f.a.pinned, false);
  assert.equal(f.value(), "new");
  label.reject(new Error("label failure")); await settled();
  assert.equal(f.value(), "old");
});

test("label failure preserves an open rename editor instead of rerendering it", async () => {
  const f = setup("label");
  f.edit("first");
  f.state.replayRenamingTabId = f.a.id;
  f.els.renameInput = { value: "still typing", selectionStart: 5 };
  const input = f.els.renameInput, renders = f.renders.length;
  await failInitialSave(f);
  assert.equal(f.value(), "old");
  assert.equal(f.els.renameInput, input);
  assert.equal(f.renders.length, renders);
});
