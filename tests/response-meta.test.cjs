// The line over a response pane: "200 · 249 ms" read as two numbers that
// could be anything, so the code carries its reason and the time its unit.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

test("the response line names the status, then the time it took, then the type", () => {
  const { responseMetaText } = loadFunctions(["responseMetaText"]);
  const record = (status, duration, type) => ({ status, duration_ms: duration, response: { content_type: type } });
  assert.equal(responseMetaText(record(200, 249, "application/json")), "200 OK · 249 ms · application/json");
  assert.equal(responseMetaText(record(404, 12, "text/html; charset=utf-8")), "404 Not Found · 12 ms · text/html; charset=utf-8");
  assert.equal(responseMetaText(record(599, 3, "")), "599 · 3 ms", "an unlisted code stays a number");
  assert.equal(responseMetaText({ status: null, duration_ms: 40, request: { content_type: "application/json" } }), "No response · 40 ms",
    "no status, and never the request's type");
});

test("Replay and the Fuzzer's result detail use that line", () => {
  const source = require("node:fs").readFileSync(require("node:path").join(__dirname, "../web/app.js"), "utf8");
  assert.equal((source.match(/els\.replayResponseMeta\.textContent = responseMetaText\(tab\.responseRecord\)/g) || []).length, 2);
  assert.match(source, /els\.fuzzerDetailResponseMeta\.textContent = responseMetaText\(record\)/);
});
