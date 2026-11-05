// How long a Replay exchange took sits at the foot of its response, beside the
// line count. Over the response, "200 · 249 ms · application/json" left the
// reader guessing which number was which, and the status is the first line of
// the response itself.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture(record) {
  const meta = { innerHTML: "" };
  const context = loadFunctions(["updateReplaySearchPane", "buildSearchMeta"], {
    state: { replayMessageSearch: { response: "" }, replayMessageViews: { response: "pretty" } },
    els: { replayResponseSearchInput: { value: "" }, replayResponseSearchMeta: meta },
    getActiveReplayTab: () => ({ responseRecord: record }),
    getCMView: () => null,
  });
  vm.runInContext("var _replayResponseCMView = { applySearch: () => ({ matchCount: 0 }), view: { state: { doc: { lines: 53 } } } };", context);
  return { context, meta };
}

test("the response's foot says how long the exchange took", () => {
  const f = fixture({ status: 200, duration_ms: 249 });
  f.context.updateReplaySearchPane("response", "");
  assert.equal(f.meta.innerHTML, "53 lines · 249 ms");
  const none = fixture(null);
  none.context.updateReplaySearchPane("response", "");
  assert.equal(none.meta.innerHTML, "53 lines", "nothing sent yet");
});

test("over a response there is no status, time or type, in Replay or the Fuzzer", () => {
  assert.doesNotMatch(appSource, /replayResponseMeta\.textContent = \[\s*`\$\{formatStatus/);
  assert.equal((appSource.match(/els\.replayResponseMeta\.textContent = "";\s*\/\/ The response says its status/g) || []).length, 2);
  assert.doesNotMatch(appSource, /fuzzerDetailResponseMeta\.textContent = `\$\{record\.status/);
});
