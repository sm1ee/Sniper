// Malformed saved-preview fixtures only; no real records or traffic are used.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");
const state = { messageViews: { request: "hex", response: "hex" } };
const c = loadFunctions([
  "buildMessagePresentation", "buildMessageHexPresentation", "buildRawRequest", "buildRawResponse",
  "buildRawRequestHead", "buildRawResponseHead", "normalizedHeaders", "mergeHeaders", "headerNameEquals",
  "renderBody", "binaryBodyPlaceholder", "formatSize", "toHexDumpFromHttpParts", "toHexDump",
  "toHexDumpFromBytes", "messageBodyBytes", "base64ToBytes", "renderHexHtml", "wrapCodeLine", "escapeHtml",
], { state, TextEncoder, Uint8Array, atob });
function record(target, preview, truncated) {
  const message = { headers: [], body_preview: preview, body_encoding: "base64", body_size: 128,
    content_type: "application/octet-stream", preview_truncated: truncated };
  return { kind: "http", method: "GET", path: "/saved", host: "example.com", status: 200,
    request: { headers: [], body_preview: "", body_size: 0 }, response: { headers: [], body_preview: "", body_size: 0 },
    [target]: message };
}
function hexBytes(text) {
  return text.split("\n").filter(line => /^[0-9a-f]{8}  /i.test(line))
    .flatMap(line => (line.slice(10, 59).match(/[0-9a-f]{2}/g) || []).map(hex => parseInt(hex, 16)));
}
for (const target of ["request", "response"]) {
  for (const preview of ["invalid preview!", "a", "AA=A", "===="]) {
    for (const truncated of [false, true]) {
      test(`${target} invalid ${JSON.stringify(preview)} Hex retains headers without inventing body bytes (truncated=${truncated})`, () => {
        const saved = record(target, preview, truncated);
        const before = JSON.stringify(saved);
        const head = target === "request" ? c.buildRawRequestHead(saved) : c.buildRawResponseHead(saved);
        const view = c.buildMessagePresentation(target, saved);
        assert.deepEqual(hexBytes(view), Array.from(Buffer.from(head)), "the explanatory placeholder must not become body bytes");
        assert.match(view, /invalid base64 preview.*body bytes unavailable/i);
        assert.match(c.renderHexHtml(view), /invalid base64 preview.*body bytes unavailable/i);
        assert.equal(view.match(/\[preview truncated\]/g)?.length || 0, truncated ? 1 : 0);
        assert.equal(JSON.stringify(saved), before, "display must not modify the saved fixture");
      });
    }
  }
}
for (const target of ["request", "response"]) {
  test(`${target} valid binary Hex still displays only decoded bytes`, () => {
    for (const preview of ["AAEC/w==", "AAEC\n/w==", ""]) {
      const saved = record(target, preview, false);
      const head = target === "request" ? c.buildRawRequestHead(saved) : c.buildRawResponseHead(saved);
      const bytes = Buffer.from(preview, "base64");
      const expected = Buffer.concat([Buffer.from(head), ...(bytes.length ? [Buffer.from("\n\n"), bytes] : [])]);
      const view = c.buildMessagePresentation(target, saved);
      assert.deepEqual(hexBytes(view), Array.from(expected));
      assert.doesNotMatch(view, /invalid base64 preview/i);
    }
  });
}
