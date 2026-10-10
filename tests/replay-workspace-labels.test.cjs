// Synthetic metadata reconciliation only; no app, server or request execution.
const assert = require("node:assert/strict");
const test = require("node:test");
const { fixture, plain } = require("./replay-workspace-fixture.cjs");

function setup(label = "old") {
  const f = fixture();
  f.a = f.tab(label);
  f.seed([f.a]);
  return f;
}
function baseline(f) {
  return f.context.workspaceReplayTabsById(f.context.workspaceSaveCommittedSnapshot).get(f.a.id);
}
function remoteLabel(f, label, revision = 11) {
  const snapshot = f.remote([f.a], revision);
  snapshot.replay.tabs[0].custom_label = label;
  return snapshot;
}

test("converged label advances baseline so a later remote rename follows", async () => {
  const f = setup();
  f.a.customLabel = "shared";
  await f.adopt(remoteLabel(f, "shared"));
  assert.equal(baseline(f).custom_label, "shared");
  assert.equal(f.renders.length, 0, "baseline-only convergence does not rerender");
  await f.adopt(remoteLabel(f, "later", 12));
  assert.equal(f.a.customLabel, "later");
  assert.equal(baseline(f).custom_label, "later");
  assert.equal(f.state.workspaceRevision, 12);
  assert.equal(f.context.snapshotWorkspaceState().replay.tabs[0].custom_label, "later");
});

for (const committed of ["old", ""]) for (const local of [committed, "shared"]) {
  for (const remote of [committed, "shared", "different"]) {
    test(`label merge baseline=${JSON.stringify(committed)}, local=${JSON.stringify(local)}, remote=${JSON.stringify(remote)}`, async () => {
      const f = setup(committed);
      f.a.customLabel = local;
      f.context.workspaceSaveDirty = true;
      await f.adopt(remoteLabel(f, remote));
      const adoptable = local === committed || local === remote;
      assert.equal(f.a.customLabel, adoptable ? remote : local);
      assert.equal(baseline(f).custom_label, adoptable ? remote : committed);
      assert.equal(f.context.workspaceSaveDirty, true);
      assert.equal(f.context.workspaceSaveConflictPending, false);
      await f.adopt(remoteLabel(f, "subsequent", 12));
      assert.equal(f.a.customLabel, adoptable ? "subsequent" : local);
      assert.equal(baseline(f).custom_label, adoptable ? "subsequent" : committed);
    });
  }
}

for (const remote of [undefined, null, "", " \n\t "]) {
  test(`converged default label accepts a subsequent rename (${JSON.stringify(remote)})`, async () => {
    const f = setup();
    f.a.customLabel = "";
    await f.adopt(remoteLabel(f, remote));
    assert.equal(baseline(f).custom_label, "");
    assert.equal(f.renders.length, 0);
    await f.adopt(remoteLabel(f, "later", 12));
    assert.equal(f.a.customLabel, "later");
  });
}

test("label convergence uses normalized whitespace", async () => {
  const f = setup();
  f.a.customLabel = "shared label";
  await f.adopt(remoteLabel(f, " shared\n\tlabel "));
  assert.equal(baseline(f).custom_label, "shared label");
  await f.adopt(remoteLabel(f, "later", 12));
  assert.equal(f.a.customLabel, "later");
});

test("label convergence and later rename preserve unsaved request and body edits", async () => {
  const f = setup(), originalBaseline = plain(baseline(f));
  f.a.customLabel = "shared";
  f.a.requestText = "POST /local HTTP/1.1\r\nHost: example.com\r\n\r\nunsaved body";
  f.a.baseRequest.body = "unsaved body";
  f.syncDom();
  const local = plain(f.a);
  const snapshot = remoteLabel(f, "shared");
  snapshot.replay.tabs[0].request_text = originalBaseline.request_text;
  snapshot.replay.tabs[0].base_request = originalBaseline.base_request;
  await f.adopt(snapshot);
  assert.deepEqual(plain(f.a), local);
  assert.deepEqual(plain(baseline(f)), { ...originalBaseline, custom_label: "shared" });
  snapshot.revision = 12;
  snapshot.replay.tabs[0].custom_label = "later";
  await f.adopt(snapshot);
  assert.deepEqual(plain(f.a), { ...local, customLabel: "later" });
  assert.deepEqual(plain(baseline(f)), { ...originalBaseline, custom_label: "later" });
  assert.equal(f.els.replayRequestEditor.value, local.requestText);
});

test("unsynced editor content still defers label adoption and baseline changes", async () => {
  const f = setup();
  f.a.customLabel = "shared";
  f.setEditor("POST /draft HTTP/1.1\r\n\r\nunsaved body");
  await f.adopt(remoteLabel(f, "shared"));
  await f.adopt(remoteLabel(f, "later", 12));
  assert.equal(f.a.customLabel, "shared");
  assert.equal(baseline(f).custom_label, "old");
  assert.equal(f.context.getCMView().getContent(), "POST /draft HTTP/1.1\r\n\r\nunsaved body");
  assert.equal(f.renders.length, 0);
});
