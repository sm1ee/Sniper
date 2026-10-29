// Passive state fixtures only; deferred fetches never leave this process.
// A refused workspace save used to leave the window stuck: every later action
// stacked another error toast, and the only way out was restarting the app.
// Reload now takes the other writer's workspace and keeps the edits made here.
const assert = require("node:assert/strict");
const test = require("node:test");
const { fixture, plain } = require("./replay-workspace-fixture.cjs");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const remoteFuzzer = {
  base_request: null, source_transaction_id: null, target: null, target_request_authority: null,
  notice: "", request_text: "GET /remote-fuzzer HTTP/1.1", payloads_text: "remote",
  attack_record_id: null,
};

async function reload(f, snapshot) {
  const index = f.requests.length;
  const pending = f.context.reconcileWorkspaceConflict();
  if (f.requests.length > index) f.succeed(index, snapshot);
  await pending;
}

function seeded(...labels) {
  const f = fixture();
  const tabs = labels.map(label => f.tab(label));
  f.seed(tabs, tabs[0].id);
  return { f, tabs };
}

test("Reload keeps a tab edited here that was closed elsewhere", async () => {
  const { f, tabs: [a, b] } = seeded("a", "b");
  a.customLabel = "edited here";
  await f.adopt(f.remote([b]));
  assert.equal(f.context.workspaceSaveConflictPending, true);
  assert.equal(f.notices.at(-1).reload, true);

  await reload(f, f.remote([b], 11));
  assert.equal(f.context.workspaceSaveConflictPending, false);
  assert.equal(f.state.workspaceRevision, 11);
  assert.deepEqual([...f.state.replayTabs.map(tab => tab.id)], [a.id, b.id]);
  assert.equal(a.customLabel, "edited here");
  assert.deepEqual(f.notices.at(-1), { dismissed: true });
  assert.equal(f.context.workspaceSaveDirty, true, "the kept tab is saved back");
  assert.deepEqual(plain(f.context.snapshotWorkspaceState().replay.tabs).map(tab => tab.id), [a.id, b.id]);
});

test("Reload keeps the Fuzzer edited here over another writer's Fuzzer", async () => {
  const { f, tabs: [a] } = seeded("a");
  f.state.fuzzerPayloadsText = "local-draft";
  await f.adopt({ ...f.remote([a]), fuzzer: plain(remoteFuzzer) });
  assert.equal(f.context.workspaceSaveConflictPending, true);

  await reload(f, { ...f.remote([a], 11), fuzzer: plain(remoteFuzzer) });
  assert.equal(f.context.workspaceSaveConflictPending, false);
  assert.equal(f.state.workspaceRevision, 11);
  assert.equal(f.state.fuzzerPayloadsText, "local-draft");
  assert.deepEqual(plain(f.context.workspaceSaveCommittedSnapshot.fuzzer), remoteFuzzer);
  assert.equal(f.context.snapshotWorkspaceState().fuzzer.payloads_text, "local-draft");
});

test("Reload after a refused save brings in a tab opened elsewhere and keeps the local edit", async () => {
  const { f, tabs: [a] } = seeded("a");
  const theirs = f.context.createReplayTab({ customLabel: "opened elsewhere", requestText: "GET /cli HTTP/1.1\r\nHost: example.com\r\n\r\n" });
  f.state.replayTabs = f.state.replayTabs.filter(tab => tab.id !== theirs.id);
  const latest = f.remote([plain(f.context.workspaceSaveCommittedSnapshot.replay.tabs[0]), theirs], 11);
  a.customLabel = "local label";
  f.context.scheduleWorkspaceStateSave();
  const saving = f.context.flushQueuedWorkspaceStateSave();
  f.requests[0].resolve({ ok: false, status: 409, json: async () => latest });
  await saving;
  assert.equal(f.context.workspaceSaveConflictPending, true);
  assert.match(f.notices.at(-1).message, /changed elsewhere/);

  await reload(f, latest);
  assert.equal(f.context.workspaceSaveConflictPending, false);
  assert.equal(f.state.workspaceRevision, 11);
  assert.deepEqual([...f.state.replayTabs.map(tab => tab.id)], [a.id, theirs.id]);
  assert.equal(a.customLabel, "local label");
});

test("a save that may have committed offers no Reload and Reload does nothing", async () => {
  const { f } = seeded("a");
  f.context.workspaceSaveConflictPending = true;
  f.context.workspaceSaveConflictLatest = { code: "WORKSPACE_COMMIT_UNCERTAIN" };
  await f.context.reconcileWorkspaceConflict();
  assert.equal(f.requests.length, 0);
  assert.equal(f.context.workspaceSaveConflictPending, true);
});

test("the conflict notice is one element however often it is shown", () => {
  class Element {
    constructor(tag) { Object.assign(this, { tag, children: [], listeners: {}, attributes: {}, isConnected: false }); }
    appendChild(child) { child.isConnected = true; this.children.push(child); return child; }
    replaceChildren(...children) { this.children = children; }
    setAttribute(name, value) { this.attributes[name] = value; }
    addEventListener(type, callback) { this.listeners[type] = callback; }
    remove() { this.isConnected = false; container.children = container.children.filter(child => child !== this); }
  }
  const container = new Element("div");
  let reconciles = 0;
  const context = loadFunctions(["showWorkspaceConflictNotice", "dismissWorkspaceConflictNotice"], {
    document: { getElementById: id => id === "toastContainer" ? container : null, createElement: tag => new Element(tag) },
    workspaceConflictNotice: null,
    reconcileWorkspaceConflict: async () => { reconciles += 1; },
    showToast() {},
  });
  context.showWorkspaceConflictNotice("first");
  context.showWorkspaceConflictNotice("second");
  assert.equal(container.children.length, 1);
  const [text, button] = container.children[0].children;
  assert.equal(text.textContent, "second");
  assert.equal(button.textContent, "Reload");
  button.listeners.click();
  assert.equal(reconciles, 1);
  context.showWorkspaceConflictNotice("reload the app", { reload: false });
  assert.equal(container.children.length, 1);
  assert.equal(container.children[0].children.length, 1);
  context.dismissWorkspaceConflictNotice();
  assert.equal(container.children.length, 0);
});
