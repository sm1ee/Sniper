// Local fetch stubs only; no server, proxy or traffic.
// Intercept turned on or off by sniper-cli or an agent: an open Intercept tab
// kept showing the old toggles while the proxy held traffic, because runtime
// settings were read again only on the Scope and Scan tabs.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function deferred() {
  let resolve;
  const promise = new Promise((yes) => { resolve = yes; });
  return { promise, resolve };
}

function fixture(replies) {
  const state = { activeTool: "proxy", activeProxyTab: "intercept", activeSession: { id: "s-1" },
    runtime: { intercept_enabled: false, intercept_scope_only: true } };
  const reads = [], renders = [];
  const c = loadFunctions(["pollAuxiliaryData", "loadRuntimeSettings", "postRuntimeSettings", "currentSessionId", "sessionQueryPath"], {
    state, workspaceStateGeneration: 0, RUNTIME_POLL_MS: 5000, _lastRuntimePoll: 0, _interceptToggleInFlight: false,
    _lastWebsocketFallbackPoll: 0, _lastHttpHistoryFallbackPoll: 0,
    loadIntercepts: async () => {}, loadResponseIntercepts: async () => {},
    isWebsocketHistoryVisible: () => false, shouldPollFindingsBadge: () => false,
    requireOkResponse: async (response) => assert.equal(response.ok, true),
    renderInterceptStatus: () => renders.push({ ...state.runtime }), renderProxySettings() {},
    fetch: (url, init) => {
      if (init?.method === "POST") return Promise.resolve({ ok: true, json: async () => JSON.parse(init.body) });
      reads.push(url);
      const reply = replies.shift();
      return Promise.resolve(reply).then((body) => ({ ok: true, json: async () => body }));
    },
  });
  return { c, state, reads, renders };
}

test("an open Intercept tab takes runtime changes another client made", async () => {
  const f = fixture([{ intercept_enabled: true, intercept_scope_only: false }]);
  await f.c.pollAuxiliaryData();
  assert.deepEqual(f.reads, ["/api/runtime?session_id=s-1"]);
  assert.equal(f.state.runtime.intercept_enabled, true);
  assert.equal(f.state.runtime.intercept_scope_only, false);
  assert.equal(f.renders.at(-1).intercept_enabled, true, "the toggles show it");
  await f.c.pollAuxiliaryData();
  assert.equal(f.reads.length, 1, "at most one read every few seconds");
});

test("a read that began before this client wrote the runtime does not put back the old value", async () => {
  const late = deferred();
  const f = fixture([late.promise]);
  const polling = f.c.pollAuxiliaryData();
  // The operator turns intercept on while the read is out.
  f.state.runtime = { ...f.state.runtime, intercept_enabled: true };
  await f.c.postRuntimeSettings("/api/runtime", { intercept_enabled: true });
  late.resolve({ intercept_enabled: false, intercept_scope_only: true });
  await polling;
  assert.equal(f.state.runtime.intercept_enabled, true);
});

test("no read starts while an intercept toggle is being sent", async () => {
  const f = fixture([{ intercept_enabled: false }]);
  f.c._interceptToggleInFlight = true;
  await f.c.pollAuxiliaryData();
  assert.equal(f.reads.length, 0);
});
