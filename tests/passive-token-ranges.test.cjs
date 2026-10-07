// Exercise display decorations against the shipped CodeMirror bundle, offline.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");
const bundle = vm.createContext({ console, setTimeout, clearTimeout });
vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/codemirror.bundle.js"), "utf8"), bundle);
const { CM } = bundle;
const c = loadFunctions([
  "extractTokenRanges", "mapTokenClass", "buildHttpDecorations", "escapeHtml",
  "highlightJavaScriptLine", "highlightJsonLine", "highlightBodyLine", "looksLikeJson",
  "looksLikeMarkup", "looksLikeFormEncoded", "highlightStartLine", "statusTone",
  "highlightRequestTarget", "highlightQueryString", "highlightHeaderLine", "highlightHeaderValue",
  "highlightCookieValue", "inferBodyHighlightMode", "highlightMarkupLine", "highlightMarkupToken",
  "highlightMarkupAttributes", "highlightMarkupPunctuation",
], { CM });
const mapSource = appSource.match(/^const _tokMap = \{[^]*?^\};/m);
assert.ok(mapSource, "the real class map must be loaded");
vm.runInContext(mapSource[0], c);
function ranges(html, text) {
  return Array.from(c.extractTokenRanges(html, text), ({ cls, from, to }) => ({ cls, from, to }));
}

for (const [line, keyword] of [
  ["returnValue = return;", "return"],
  ["functionName(); function f() {}", "function"],
  ["trueValue; true", "true"],
  ["undefinedValue; undefined", "undefined"],
]) {
  test(`syntax coloring skips earlier unstyled occurrences in ${JSON.stringify(line)}`, () => {
    const from = line.lastIndexOf(keyword);
    assert.deepEqual(ranges(c.highlightJavaScriptLine(line), line).filter(r => r.cls === "tok-kw"),
      [{ cls: "tok-kw", from, to: from + keyword.length }]);
  });
}

for (const value of ["'saved text'", '"&lt;"', '"&gt;"', '"&quot;"', '"&#039;"', '"&amp;lt;"', '"café 😀 <>&\\\""']) {
  test(`syntax coloring decodes escaped display text exactly once for ${JSON.stringify(value)}`, () => {
    assert.deepEqual(ranges(c.highlightJavaScriptLine(value), value),
      [{ cls: "tok-json-str", from: 0, to: value.length }]);
  });
}

test("unstyled escaped gaps and unknown token classes still count toward source offsets", () => {
  const text = "café😀 <>&amp; return return";
  const from = text.lastIndexOf("return");
  const html = `${c.escapeHtml("café😀 <>&amp; ")}<span class="unmapped">return</span> <span class="token-js-keyword">return</span>`;
  assert.deepEqual(ranges(html, text), [{ cls: "tok-kw", from, to: from + 6 }]);
});

test("a mismatched highlighted span cannot be relocated to an unrelated later occurrence", () => {
  assert.deepEqual(ranges('<span class="token-js-keyword">return</span>', "prefix return"), []);
});

test("HTTP decorations color the correct JavaScript token at its document offset", () => {
  const prefix = "HTTP/1.1 200\nContent-Type: application/javascript\n\n";
  const body = "returnValue = return;\nconst saved = '&lt; café 😀';";
  const doc = CM.EditorState.create({ doc: prefix + body }).doc;
  const decorations = c.buildHttpDecorations({ state: { doc } });
  const actual = [];
  for (const cursor = decorations.iter(); cursor.value; cursor.next()) {
    actual.push({ cls: cursor.value.spec.class, from: cursor.from, to: cursor.to });
  }
  const expectedKeyword = prefix.length + body.indexOf("return;");
  assert.ok(actual.some(r => r.cls === "tok-kw" && r.from === expectedKeyword && r.to === expectedKeyword + 6));
  assert.ok(!actual.some(r => r.cls === "tok-kw" && r.from === prefix.length));
  const value = "'&lt; café 😀'";
  const expectedString = prefix.length + body.indexOf(value);
  assert.ok(actual.some(r => r.cls === "tok-json-str" && r.from === expectedString && r.to === expectedString + value.length));
  assert.ok(actual.every(r => r.from >= 0 && r.from < r.to && r.to <= doc.length));
});

test("JSON and markup decorations retain apostrophe and literal entity token boundaries", () => {
  for (const [line, mode, expectedClass, token] of [
    ['{"saved":"&quot;"}', "json", "tok-json-str", '"&quot;"'],
    ["<item value='&lt;'>saved</item>", "html", "tok-markup-str", "'&lt;'"],
  ]) {
    const result = ranges(c.highlightBodyLine(line, mode), line);
    const from = line.indexOf(token);
    assert.ok(result.some(r => r.cls === expectedClass && r.from === from && r.to === from + token.length));
  }
});
