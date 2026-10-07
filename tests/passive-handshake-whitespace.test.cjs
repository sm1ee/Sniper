// Saved handshake presentation only; no WebSocket or network is opened.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");
const c = loadFunctions([
  "buildRawWebsocketRequest", "buildRawWebsocketResponse", "normalizedHeaders", "mergeHeaders", "headerNameEquals",
]);
for (const side of ["request", "response"]) {
  for (const value of ["fixture ", "fixture\t", " \t ", "", "café 😀 \t", "ordinary"]) {
    test(`${side} saved handshake retains last-header value ${JSON.stringify(value)}`, () => {
      const saved = { path: "/saved", status: 101, [side]: { headers: [
        { name: "x-first", value: "unchanged" }, { name: "x-last", value },
      ] } };
      const original = JSON.stringify(saved);
      const head = side === "request" ? "GET /saved HTTP/1.1" : "HTTP/1.1 101";
      const result = side === "request" ? c.buildRawWebsocketRequest(saved) : c.buildRawWebsocketResponse(saved);
      assert.equal(result, `${head}\nx-first: unchanged\nx-last: ${value}`);
      assert.equal(JSON.stringify(saved), original);
    });
  }
}

test("headerless saved handshakes do not gain an artificial trailing newline", () => {
  assert.equal(c.buildRawWebsocketRequest({ path: "/saved", request: { headers: [] } }), "GET /saved HTTP/1.1");
  assert.equal(c.buildRawWebsocketRequest({}), "GET / HTTP/1.1");
  assert.equal(c.buildRawWebsocketResponse({ response: { headers: [] }, status: 101 }), "HTTP/1.1 101");
  assert.equal(c.buildRawWebsocketResponse({ response: {} }), "HTTP/1.1 101");
});

test("missing handshake response keeps its established explanatory message", () => {
  assert.equal(c.buildRawWebsocketResponse({}), "No handshake response was captured.");
});

test("existing request cookie merging preserves the final saved cookie whitespace", () => {
  const saved = { request: { headers: [{ name: "Cookie", value: "a=fixture" }, { name: "cookie", value: "b=fixture \t" }] } };
  assert.equal(c.buildRawWebsocketRequest(saved), "GET / HTTP/1.1\ncookie: a=fixture; b=fixture \t");
});
