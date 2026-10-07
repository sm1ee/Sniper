// Read-only presentation fixtures; no capture, request editing, or real records.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");
const state = { messageViews: { request: "raw", response: "raw" } };
const c = loadFunctions([
  "renderBody", "binaryBodyPlaceholder", "formatSize", "buildMessagePresentation", "buildMessageHexPresentation",
  "buildRawRequest", "buildRawResponse", "buildRawRequestHead", "buildRawResponseHead", "normalizedHeaders",
  "mergeHeaders", "headerNameEquals", "prettyFormat", "prettyJsonText", "toHexDumpFromHttpParts", "toHexDump",
  "toHexDumpFromBytes", "messageBodyBytes", "base64ToBytes",
], { state, TextEncoder, Uint8Array, atob });
function record(target, body_preview, body_encoding, preview_truncated) {
  return { kind: "http", method: "GET", path: "/saved", host: "example.com", status: 200,
    request: { headers: [], body_preview: "", body_size: 0 }, response: { headers: [], body_preview: "", body_size: 0 },
    [target]: { headers: [], body_preview, body_encoding, preview_truncated, body_size: 128,
      content_type: body_encoding === "base64" ? "application/octet-stream" : "text/plain" } };
}
const examples = [["", "utf8"], ["", "base64"], ["AAEC", "base64"], ["café 😀", "utf8"]];
for (const target of ["request", "response"]) {
  for (const mode of ["raw", "pretty"]) {
    for (const [preview, encoding] of examples) {
      test(`${target} ${mode} marks ${encoding} ${JSON.stringify(preview)} as truncated`, () => {
        const saved = record(target, preview, encoding, true);
        const original = JSON.stringify(saved);
        state.messageViews[target] = mode;
        const view = c.buildMessagePresentation(target, saved);
        const head = target === "request" ? c.buildRawRequestHead(saved) : c.buildRawResponseHead(saved);
        const body = !preview ? "" : encoding === "base64" ? c.binaryBodyPlaceholder(saved[target]) : preview;
        assert.equal(view, `${head}\n\n${body}${body ? "\n\n" : ""}[preview truncated]`);
        assert.equal(JSON.stringify(saved), original);
      });
    }
  }
}

test("complete empty, missing, text, and binary body presentations keep their previous behavior", () => {
  for (const body of [null, undefined, {}, { body_preview: "", preview_truncated: false }]) assert.equal(c.renderBody(body), "");
  assert.equal(c.renderBody({ body_preview: "café 😀", body_encoding: "utf8", preview_truncated: false }), "café 😀");
  const binary = { body_preview: "AAEC", body_encoding: "base64", preview_truncated: false, body_size: 3 };
  assert.equal(c.renderBody(binary), c.binaryBodyPlaceholder(binary));
});

test("a missing preview with explicit truncation still displays its metadata notice", () => {
  assert.equal(c.renderBody({ body_encoding: "utf8", preview_truncated: true, body_size: 4 }), "[preview truncated]");
});

test("Hex keeps a single truncation notice outside its byte dump for all preview types", () => {
  for (const target of ["request", "response"]) {
    state.messageViews[target] = "hex";
    for (const [preview, encoding] of examples) {
      const saved = record(target, preview, encoding, true);
      const view = c.buildMessagePresentation(target, saved);
      assert.equal(view.match(/\[preview truncated\]/g)?.length, 1);
      const actual = view.split("\n").filter(line => /^[0-9a-f]{8}  /i.test(line))
        .flatMap(line => (line.slice(10, 59).match(/[0-9a-f]{2}/g) || []).map(hex => parseInt(hex, 16)));
      const head = target === "request" ? c.buildRawRequestHead(saved) : c.buildRawResponseHead(saved);
      const body = Buffer.from(preview, encoding === "base64" ? "base64" : "utf8");
      const expected = Buffer.concat([Buffer.from(head), ...(body.length ? [Buffer.from("\n\n"), body] : [])]);
      assert.deepEqual(actual, Array.from(expected));
    }
  }
});
