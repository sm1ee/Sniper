// Synthetic display fixtures only; these never construct or send traffic.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");
const c = loadFunctions([
  "highlightStartLine", "highlightHeaderLine", "highlightHeaderValue", "highlightCookieValue",
  "highlightRequestTarget", "highlightQueryString", "escapeHtml", "statusTone",
  "renderCodeHtml", "renderHttpHtml", "wrapCodeLine", "inferBodyHighlightMode",
]);
function visibleText(html) {
  const entities = { amp: "&", lt: "<", gt: ">", quot: '"', "#039": "'", nbsp: "\u00a0" };
  return html.replace(/<[^>]*>/g, "").replace(/&(amp|lt|gt|quot|#039|nbsp);/g, (_, name) => entities[name]);
}

for (const [target, line] of [
  ["request", "GET\t/path?q=a?b\tHTTP/1.1"],
  ["request", "GET   /path   HTTP/1.1"],
  ["request", "GET /path"],
  ["request", "GET\t/path"],
  ["response", "HTTP/1.1\t200\tOK"],
  ["response", "HTTP/2   200   Saved status"],
  ["response", "HTTP/1.1 204   "],
  ["response", "HTTP/1.1\t204"],
]) {
  test(`${target} start-line highlighting preserves ${JSON.stringify(line)}`, () => {
    assert.equal(visibleText(c.highlightStartLine(line, target)), line);
    for (const mode of ["raw", "pretty"]) {
      assert.equal(visibleText(c.renderCodeHtml(line, mode, target)), line);
    }
  });
}

for (const line of [
  "X-Fixture:value", "X-Fixture:   value", "X-Fixture:\t \tvalue", "X-Fixture:",
  "X-Fixture:   ", "X-Fixture:\tvalue  ", "Cookie:session=fixture; mode=local",
  "Cookie:\t session=fixture; bare", "Set-Cookie:   session=fixture; Path=/; HttpOnly",
  "Location:\thttps://example.com/path?q=a?b", "Location:https://example.com/",
  "X-Fixture: <tag>&amp;'\"", "X-Fixture-No-Colon",
]) {
  test(`header highlighting preserves ${JSON.stringify(line)}`, () => {
    assert.equal(visibleText(c.highlightHeaderLine(line)), line);
  });
}

test("ordinary URL and cookie values retain their token colors after whitespace", () => {
  assert.match(c.highlightHeaderLine("Location: \thttps://example.com/"), /token-url/);
  assert.match(c.highlightHeaderLine("Cookie: \t session=fixture"), /token-cookie-name/);
});
