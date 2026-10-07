// Display-only fixtures; no app runtime, network, or saved records are used.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");
const element = () => ({ innerHTML: "", classList: { remove() {} } });
const els = {
  frameDetailMeta: element(), frameDetailBody: element(),
  frameDetailResizer: element(), frameDetailPanel: element(),
};
const c = loadFunctions([
  "highlightBodyLine", "highlightJsonLine", "escapeHtml", "looksLikeJson", "looksLikeMarkup",
  "looksLikeFormEncoded", "showFrameDetail", "prettyJsonText", "formatSize",
], { els });
function visibleText(html) {
  const entities = { amp: "&", lt: "<", gt: ">", quot: '"', "#039": "'", nbsp: "\u00a0" };
  return html.replace(/<[^>]*>/g, "").replace(/&(amp|lt|gt|quot|#039|nbsp);/g, (_, name) => entities[name]);
}

for (const text of [
  '{"id" :9007199254740993}',
  '  "key"\t\t:\t"value"',
  '"first"   :1,"second"\t :2',
  '"<tag>&amp;" \t: "quoted \\\" text"',
  '"key"  : {"partial"  :',
]) {
  test(`JSON highlighting preserves key separators in ${JSON.stringify(text)}`, () => {
    assert.equal(visibleText(c.highlightJsonLine(text)), text);
    assert.equal(visibleText(c.highlightBodyLine(text, "json")), text);
  });
}

for (const mode of ["plain", "json", "css", "html", "xml", "javascript", "form"]) {
  test(`${mode} body highlighting preserves nonempty whitespace-only lines`, () => {
    for (const line of [" ", "    ", "\t", " \t \t", "\u00a0\u00a0", "\r"]) {
      assert.equal(visibleText(c.highlightBodyLine(line, mode)), line);
    }
    assert.equal(c.highlightBodyLine("", mode), "&nbsp;", "empty lines still occupy visible height");
  });
}

test("captured plain WebSocket detail retains blank-line indentation", () => {
  const body = "first\n \t \nlast";
  c.showFrameDetail({ index: 0, direction: "server_to_client", kind: "text", body_preview: body, body_size: body.length });
  assert.equal(visibleText(els.frameDetailBody.innerHTML), body);
});

test("captured non-JSON WebSocket text retains colon spacing", () => {
  const body = 'prefix "key" \t : "value" suffix';
  c.showFrameDetail({ index: 0, direction: "server_to_client", kind: "text", body_preview: body, body_size: body.length });
  assert.equal(visibleText(els.frameDetailBody.innerHTML), body);
});
