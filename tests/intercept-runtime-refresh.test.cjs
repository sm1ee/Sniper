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
    runtime: { intercept_enabled: false, intercept_scope_only: true, http_capture_enabled: true } };
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
  const f = fixture([{ intercept_enabled: true, intercept_scope_only: false, http_capture_enabled: true }]);
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
  late.resolve({ intercept_enabled: false, intercept_scope_only: true, http_capture_enabled: true });
  await polling;
  assert.equal(f.state.runtime.intercept_enabled, true);
});

test("no read starts while an intercept toggle is being sent", async () => {
  const f = fixture([{ intercept_enabled: false, http_capture_enabled: true }]);
  f.c._interceptToggleInFlight = true;
  await f.c.pollAuxiliaryData();
  assert.equal(f.reads.length, 0);
});

// It was a red Off pill that said its state in words, as Active Scan's was.
test("Intercept is one labelled switch whose state is aria-checked", () => {
  const html = require("node:fs").readFileSync(require("node:path").join(__dirname, "../web/index.html"), "utf8");
  assert.match(html, /<h2 id="interceptTitle">Intercept<\/h2>/);
  assert.match(html, /<button class="switch" id="interceptStatus" type="button" role="switch" aria-checked="false" aria-labelledby="interceptTitle"><\/button>/);
  const attributes = {};
  const state = { runtime: { intercept_enabled: true } };
  const c = loadFunctions(["renderInterceptStatus"], {
    state, els: { interceptStatus: { setAttribute: (name, value) => { attributes[name] = value; } } },
  });
  c.renderInterceptStatus();
  assert.equal(attributes["aria-checked"], "true");
  state.runtime.intercept_enabled = false;
  c.renderInterceptStatus();
  assert.equal(attributes["aria-checked"], "false");
});

// The switch forwarded both queues itself after turning Intercept off, which
// sniper-cli did not, so traffic held at that moment hung for CLI users. The
// server now forwards it whoever turns Intercept off.
test("turning Intercept off sends one runtime write and reads both queues again", async () => {
  const writes = [], reloads = [];
  const state = { runtime: { intercept_enabled: true } };
  const c = loadFunctions(["toggleIntercept"], {
    state, els: { interceptStatus: { disabled: false } },
    _interceptToggleInFlight: false, _interceptToggleRequestSeq: 0,
    currentSessionId: () => "s-1", expectedActiveSessionIdForWrite: () => "s-1",
    renderInterceptStatus() {}, scheduleRefresh() {}, sessionWritePath: (path) => path,
    postRuntimeSettings: async (path, body) => {
      writes.push(`${path} intercept_enabled=${body.intercept_enabled}`);
      return { ok: true, json: async () => ({ intercept_enabled: false }) };
    },
    fetch: async (url, init) => { writes.push(`${init?.method} ${url}`); return { ok: true }; },
    requireOkResponse: async (response) => assert.equal(response.ok, true),
    loadIntercepts: async () => { reloads.push("requests"); },
    loadResponseIntercepts: async () => { reloads.push("responses"); },
    showToast: (message) => assert.fail(`Unexpected toast: ${message}`), loadRuntimeSettings: async () => {},
  });
  await c.toggleIntercept();
  assert.deepEqual(writes, ["/api/runtime intercept_enabled=false"]);
  assert.deepEqual(reloads, ["requests", "responses"]);
  assert.equal(state.runtime.intercept_enabled, false);
});
