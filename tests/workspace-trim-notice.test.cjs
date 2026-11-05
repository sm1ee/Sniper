// A Replay response too large for the saved workspace is left out of every
// save while the tab holds it. The warning about it said so after every save,
// and stacked up. Synthetic workspace; nothing is sent.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource } = require("./frontend-test-helpers.cjs");
const { fixture } = require("./replay-workspace-fixture.cjs");

const WARNING = "A large replay response was not saved to keep the workspace under its size limit.";

test("the large-response warning shows once while the response stays, and again only after it went", async () => {
  const f = fixture();
  // The real trimming, with limits a synthetic response can pass.
  vm.runInContext(appSource.match(/^function boundWorkspaceSnapshotForSave\([^]*?^\}/m)[0], f.context);
  vm.runInContext("var WORKSPACE_SAVE_SAFE_BYTES = 64 * 1024, WORKSPACE_SAVE_RECORD_SAFE_BYTES = 8 * 1024;", f.context);
  const tab = f.tab("big");
  f.seed([tab]);
  const record = (id) => ({ id, method: "GET", scheme: "https", host: "example.com", path: "/big", status: 200,
    request: { headers: [], body_preview: "" }, response: { headers: [], body_preview: "x".repeat(16 * 1024) } });
  let revision = 10;
  const save = async () => {
    f.context.scheduleWorkspaceStateSave();
    const flushing = f.context.flushWorkspaceState();
    await new Promise(setImmediate);
    f.succeed(f.requests.length - 1, { session_id: "session-a", revision: ++revision });
    await flushing;
  };
  const warnings = () => f.toasts.filter(([message]) => message === WARNING).length;

  tab.responseRecord = record("tx-1");
  await save();
  await save();
  await save();
  assert.equal(JSON.parse(f.requests.at(-1).options.body).replay.tabs[0].response_record, null, "still left out");
  assert.equal(warnings(), 1, "once while the large response stays");

  tab.responseRecord = null;
  await save();
  tab.responseRecord = record("tx-2");
  await save();
  assert.equal(warnings(), 2, "again for one that came after the last had gone");
});
