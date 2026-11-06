// The Fuzzer's Delay and stop-on-match Options: what a run sends, and a delay
// the server would refuse holding Start back. Synthetic state; nothing is sent.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");
const workflow = require("../web/fuzzer-workflow.js");

function controls(state) {
  return loadFunctions(["fuzzerRunControls"], { state }).fuzzerRunControls();
}

test("Delay takes milliseconds or a range, and a stop text goes as text or regex", () => {
  const plain = (value) => JSON.parse(JSON.stringify(value));
  assert.deepEqual(plain(controls({})), { delay: null, stop_match: null });
  assert.deepEqual(plain(controls({ fuzzerDelayText: "500" })).delay, { min_ms: 500, max_ms: 500 });
  assert.deepEqual(plain(controls({ fuzzerDelayText: " 200 - 800 " })).delay, { min_ms: 200, max_ms: 800 });
  assert.equal(controls({ fuzzerDelayText: "0" }).delay, null, "no wait");
  for (const bad of ["800-200", "60001", "soon", "1.5", "-5"]) {
    assert.match(controls({ fuzzerDelayText: bad }).error, /^Delay is milliseconds/, bad);
  }
  assert.deepEqual(plain(controls({ fuzzerStopMatchText: " Welcome " })).stop_match, { text: "Welcome", regex: false });
  assert.deepEqual(plain(controls({ fuzzerStopMatchText: "role.?admin", fuzzerStopRegex: true })).stop_match,
    { text: "role.?admin", regex: true });
  assert.equal(controls({ fuzzerStopMatchText: "   ", fuzzerStopRegex: true }).stop_match, null);
});

test("a delay the server would refuse is the error beside Start, which stays off", () => {
  const state = { fuzzerPayloadsText: "one", fuzzerAttackType: "sniper", fuzzerUrlEncode: true, fuzzerDelayText: "9-1" };
  const request = { method: "GET", scheme: "https", host: "example.com", port: 443, path: "/?q=§demo§", headers: [], body: "" };
  const c = loadFunctions(["fuzzerSetupPreflight", "fuzzerRunControls", "fuzzerPayloadCount", "splitFuzzerPayloadLines"], {
    state, TextEncoder, SniperFuzzerWorkflow: workflow,
    parseFuzzerRequestTemplate: () => request, activeFuzzerTargetForRequest: () => null, replayHttpVersionFromText: () => null,
  });
  const raw = "GET /?q=§demo§ HTTP/1.1\nHost: example.com\n\n";
  const refused = c.fuzzerSetupPreflight(raw);
  assert.equal(refused.valid, false);
  assert.match(refused.errors[0], /^Delay is milliseconds/);
  state.fuzzerDelayText = "200-800";
  const accepted = c.fuzzerSetupPreflight(raw);
  assert.equal(accepted.valid, true);
  assert.deepEqual(Array.from(accepted.errors || []), []);
});
