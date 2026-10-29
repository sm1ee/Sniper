// Synthetic attack records only; fetch is a local queue and nothing is sent.
// A saved run that is still sending when it loads (a reload during a long
// attack, or one started from sniper-cli) must be followed to its end, not
// left at the results it had when it loaded.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

test("a saved run still sending when it loads is followed to its end", async () => {
  const state = { activeSession: { id: "session-a" }, fuzzerAttackRecordId: "run-a", fuzzerNotice: "Loading saved fuzzer run..." };
  const row = index => ({ index, payload: `p${index}`, status: 200 });
  const replies = [
    { id: "run-a", running: true, results: [row(0)] },
    { id: "run-a", running: false, status: "completed", results: [row(0), row(1), row(2)] },
  ];
  const urls = [];
  const c = loadFunctions(
    ["followRestoredFuzzerAttack", "hydrateFuzzerAttackRecordById", "followFuzzerAttack", "setFuzzerAttackRecord", "normalizeFuzzerAttackRecord",
      "jsonArray", "sessionQueryPath", "currentSessionId"],
    {
      state, _fuzzerAttackLoadGeneration: 0, FUZZER_POLL_MS: 0, URLSearchParams,
      setTimeout: callback => { callback(); return 0; },
      hideFuzzerDetailPanel() {}, renderFuzzer() {}, scheduleWorkspaceStateSave() {},
      requireOkResponse: async response => assert.equal(response.ok, true),
      fetch: async url => {
        urls.push(url);
        const reply = replies.shift();
        assert.ok(reply, "no more reads expected");
        return { ok: true, status: 200, json: async () => reply };
      },
    },
  );
  await c.hydrateFuzzerAttackRecordById("run-a", "session-a");
  assert.equal(urls.length, 2, "the running record was read again until it ended");
  assert.equal(state.fuzzerAttackRecord.results.length, 3);
  assert.equal(state.fuzzerAttackRecord.running, false);
  assert.equal(state.fuzzerRunningAttackId, null);
});

test("an earlier visit to the same running saved attack cannot retire the newer Stop control", async () => {
  const state = { activeSession: { id: "session-a" }, fuzzerAttackRecordId: "run-a", fuzzerNotice: "" };
  const timers = [], requests = [];
  const tick = () => new Promise(resolve => setImmediate(resolve));
  const c = loadFunctions(
    ["followRestoredFuzzerAttack", "hydrateFuzzerAttackRecordById", "followFuzzerAttack", "setFuzzerAttackRecord", "normalizeFuzzerAttackRecord",
      "jsonArray", "sessionQueryPath", "currentSessionId"],
    {
      state, _fuzzerAttackLoadGeneration: 0, FUZZER_POLL_MS: 0, URLSearchParams,
      setTimeout: callback => { timers.push(callback); return 0; },
      hideFuzzerDetailPanel() {}, renderFuzzer() {}, scheduleWorkspaceStateSave() {},
      requireOkResponse: async response => assert.equal(response.ok, true),
      fetch: () => new Promise(resolve => requests.push(resolve)),
    },
  );
  const reply = (running, count) => ({ ok: true, status: 200, json: async () => ({ id: "run-a", running,
    results: Array.from({ length: count }, (_, index) => ({ index, payload: `p${index}`, status: 200 })) }) });
  const earlier = c.hydrateFuzzerAttackRecordById("run-a", "session-a");
  requests.shift()(reply(true, 1)); await tick();
  const latest = c.hydrateFuzzerAttackRecordById("run-a", "session-a");
  requests.shift()(reply(true, 2)); await tick();
  timers.shift()(); await earlier;
  assert.equal(state.fuzzerRunningAttackId, "run-a", "the latest follow still owns Stop");
  assert.equal(state.fuzzerAttackRecord.results.length, 2);
  timers.shift()(); await tick();
  requests.shift()(reply(false, 3)); await latest;
  assert.equal(state.fuzzerRunningAttackId, null);
  assert.equal(state.fuzzerAttackRecord.results.length, 3);
});
