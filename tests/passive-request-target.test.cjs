// Offline display checks: synthetic strings only, without starting the app.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const c = loadFunctions([
  "highlightRequestTarget", "highlightStartLine", "highlightQueryString", "escapeHtml",
  "renderCodeHtml", "renderHttpHtml", "wrapCodeLine", "inferBodyHighlightMode",
]);
function visibleText(html) {
  const entities = { amp: "&", lt: "<", gt: ">", quot: '"', "#039": "'", nbsp: "\u00a0" };
  return html.replace(/<[^>]*>/g, "").replace(/&(amp|lt|gt|quot|#039|nbsp);/g, (_, name) => entities[name]);
}

for (const target of [
  "/path?q=a?b&next=c",
  "/path?first??last",
  "/path??value",
  "/path?q=hello?",
  "/path?q=?&flag&empty=&value=a=b?c",
  "/path?q=café?文😀&quoted=<>&literal=&amp;",
  "/path?q=one%3Ftwo&two=three",
  "/path?",
  "/path",
]) {
  test(`request-target highlighting preserves ${JSON.stringify(target)}`, () => {
    assert.equal(visibleText(c.highlightRequestTarget(target)), target);
  });
}

test("Raw and Pretty HTTP rendering retain a complete multi-question-mark request target", () => {
  const line = "GET /path?q=a?b&next=c HTTP/1.1";
  for (const mode of ["raw", "pretty"]) {
    assert.equal(visibleText(c.renderCodeHtml(line, mode, "request")), line);
  }
});

test("request-target highlighting escapes markup without losing later query components", () => {
  const html = c.highlightRequestTarget('/path?first=<tag>?next="café"&bare');
  assert.doesNotMatch(html, /<tag>/);
  assert.match(html, /&lt;tag&gt;/);
  assert.match(html, /token-query-value/);
  assert.equal(visibleText(html), '/path?first=<tag>?next="café"&bare');
});
