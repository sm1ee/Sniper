// Passive state fixtures only; deferred fetches never leave this process.
// Another writer (sniper-cli) changing the Fuzzer half of the workspace: this
// client used to take the new revision for its replay tabs alone, so its next
// full save put its older Fuzzer back over the other writer's.
const assert = require("node:assert/strict");
const test = require("node:test");
const { fixture, plain } = require("./replay-workspace-fixture.cjs");

const remoteFuzzer = {
  base_request: null, source_transaction_id: null, target: null, target_request_authority: null,
  notice: "", request_text: "GET /remote-fuzzer HTTP/1.1", payloads_text: "remote-one\nremote-two",
  attack_record_id: null,
};

function seeded() {
  const f = fixture();
  f.a = f.tab("first");
  f.seed([f.a], f.a.id);
  return f;
}

test("another writer's Fuzzer is taken when this client has no Fuzzer edit of its own", async () => {
  const f = seeded();
  await f.adopt({ ...f.remote([f.a]), fuzzer: plain(remoteFuzzer) });
  assert.equal(f.state.fuzzerRequestText, "GET /remote-fuzzer HTTP/1.1");
  assert.equal(f.state.fuzzerPayloadsText, "remote-one\nremote-two");
  assert.equal(f.state.workspaceRevision, 11);
  assert.deepEqual(plain(f.context.workspaceSaveCommittedSnapshot.fuzzer), remoteFuzzer);
  assert.deepEqual(plain(f.context.snapshotWorkspaceState().fuzzer), remoteFuzzer,
    "the next full save carries the other writer's Fuzzer");
  assert.equal(f.context.workspaceSaveConflictPending, false);
});

test("a Fuzzer edit here and another writer's Fuzzer change stop at a conflict instead of overwriting either", async () => {
  const f = seeded();
  f.state.fuzzerPayloadsText = "local-draft";
  await f.adopt({ ...f.remote([f.a]), fuzzer: plain(remoteFuzzer) });
  assert.equal(f.context.workspaceSaveConflictPending, true);
  assert.equal(f.state.fuzzerPayloadsText, "local-draft");
  assert.equal(f.state.workspaceRevision, 10, "a save at the old revision is refused, not taken over theirs");
  assert.equal(f.toasts.length, 1);
  assert.match(f.toasts[0][0], /Fuzzer was changed elsewhere/);
});

test("the same Fuzzer change made here and elsewhere is no conflict", async () => {
  const f = seeded();
  f.state.fuzzerRequestText = remoteFuzzer.request_text;
  f.state.fuzzerPayloadsText = remoteFuzzer.payloads_text;
  f.state.fuzzerNotice = "";
  await f.adopt({ ...f.remote([f.a]), fuzzer: plain(remoteFuzzer) });
  assert.equal(f.context.workspaceSaveConflictPending, false);
  assert.equal(f.state.workspaceRevision, 11);
  assert.deepEqual(plain(f.context.workspaceSaveCommittedSnapshot.fuzzer), remoteFuzzer);
});
