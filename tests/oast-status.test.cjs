// OAST status line under Callbacks: synthetic status and runtime only.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

// Callbacks are polled for the session the proxy listener records into.
let feed = "main";
const context = loadFunctions(["oastStatusLine"], { URL, currentSessionId: () => "session-a", sessionFeed: () => ({ kind: feed }) });
// Copied out of the vm realm, so deepEqual compares values, not prototypes.
const oastStatusLine = (...args) => ({ ...context.oastStatusLine(...args) });
const runtime = (extras = {}) => ({ oast_enabled: true, oast_server_url: "https://oast.example.com", ...extras });

// It read "Custom" alone, whether OAST was off, had no server, or was set up.
test("the OAST status says whether it is off, has no server, or which server it uses", () => {
  assert.deepEqual(oastStatusLine({ provider: "custom" }, runtime({ oast_enabled: false })), { text: "Off", registered: false });
  assert.deepEqual(oastStatusLine({ provider: "custom" }, runtime({ oast_server_url: "  " })), { text: "Custom · No server URL", registered: false });
  assert.deepEqual(oastStatusLine({ provider: "custom" }, runtime()), { text: "Custom · oast.example.com", registered: false });
  assert.deepEqual(oastStatusLine({ provider: "boast" }, runtime()), { text: "BOAST · Not registered", registered: false });
  assert.deepEqual(oastStatusLine({ provider: "interactsh", registered: true, payload_domain: "abc.oast.example.com" }, runtime()),
    { text: "Interactsh · Registered (abc.oast.example.com)", registered: true });
  assert.deepEqual(oastStatusLine({ provider: "custom" }, runtime({ oast_server_url: "not a url" })), { text: "Custom · not a url", registered: false });
  assert.deepEqual(oastStatusLine({}, null), { text: "Off", registered: false });
});

test("the OAST status of a session the proxy does not record into says where callbacks are polled", () => {
  for (const kind of ["port", "none"]) {
    feed = kind;
    assert.deepEqual(oastStatusLine({ provider: "interactsh", registered: true, payload_domain: "abc.oast.example.com" }, runtime()),
      { text: "Polled only in the session the proxy records into", registered: false });
    // Off is still what the session is set to.
    assert.deepEqual(oastStatusLine({ provider: "custom" }, runtime({ oast_enabled: false })), { text: "Off", registered: false });
  }
  feed = "main";
});
