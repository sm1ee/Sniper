// Raw and Pretty show a binary body's bytes as characters. Drawn whole, a
// 5 MB PDF made the editor crawl, so only the first 64 KiB are shown.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const c = loadFunctions(["renderBody", "safeDecodeBase64", "binaryBodyPlaceholder", "formatSize"], { atob });
const base64 = (bytes) => Buffer.from(bytes).toString("base64");

test("a large binary body shows its first 64 KiB and says how much there is", () => {
  const bytes = Buffer.alloc(5 * 1024 * 1024, 0x41);
  bytes.write("%PDF-1.7", 0, "latin1");
  const shown = c.renderBody({ body_preview: base64(bytes), body_encoding: "base64", body_size: bytes.length, content_type: "application/pdf" });
  const [head, notice] = shown.split("\n\n");
  assert.equal(head.length, 64 * 1024);
  assert.ok(head.startsWith("%PDF-1.7AAAA"));
  assert.equal(notice, "[first 64 KB of 5.0 MB shown; Hex shows every byte]");
});

test("a small binary body shows all of itself", () => {
  assert.equal(c.renderBody({ body_preview: base64([0, 1, 2, 255]), body_encoding: "base64", body_size: 4 }), "\u0000\u0001\u0002ÿ");
});

test("a body cut at the preview limit gets both notices", () => {
  const bytes = Buffer.alloc(200 * 1024, 0x42);
  const shown = c.renderBody({ body_preview: base64(bytes), body_encoding: "base64", body_size: 9 * 1024 * 1024, preview_truncated: true });
  assert.ok(shown.endsWith("\n\n[first 64 KB of 9.0 MB shown; Hex shows every byte]\n\n[preview truncated]"), shown.slice(-120));
});
