// Pretty laid out JSON only; minified HTML, as a Next.js page ships it, stayed
// one line. HTML and XML now get one tag or text run per line, indented.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const c = loadFunctions(["prettyFormat", "prettyJsonText", "prettyMarkup", "markupTagEnd"]);
const HEAD = "HTTP/1.1 200\ncontent-type: text/html; charset=utf-8";
const html = (body, extra = {}) => c.prettyFormat(`${HEAD}\n\n${body}`, { content_type: "text/html; charset=utf-8", body_encoding: "utf8", ...extra });

test("minified HTML is laid out one tag or text per line, by depth", () => {
  const page = '<!DOCTYPE html><html lang="ko"><head><meta charSet="utf-8"/><title>Guide</title></head>'
    + '<body><div hidden=""><!--$--></div><a href="/gift" title="a > b">Gift</a><br><p>One <b>two</b></p></body></html>';
  assert.equal(html(page), `${HEAD}\n\n${[
    "<!DOCTYPE html>",
    '<html lang="ko">',
    "  <head>",
    '    <meta charSet="utf-8"/>',
    "    <title>",
    "      Guide",
    "    </title>",
    "  </head>",
    "  <body>",
    '    <div hidden="">',
    "      <!--$-->",
    "    </div>",
    '    <a href="/gift" title="a > b">',
    "      Gift",
    "    </a>",
    "    <br>",
    "    <p>",
    "      One",
    "      <b>",
    "        two",
    "      </b>",
    "    </p>",
    "  </body>",
    "</html>",
  ].join("\n")}`);
});

test("script, style, pre and textarea keep their contents as sent", () => {
  const shown = html('<div><script>if (a < b && c > d) { x("</p>") }</script><pre>  keep\n    this</pre><style>a>b{c:d}</style></div>');
  assert.match(shown, /\n    if \(a < b && c > d\) \{ x\("<\/p>"\) \}\n/);
  assert.match(shown, /\n  keep\n    this\n/);
  assert.match(shown, /\n    a>b\{c:d\}\n/);
  assert.match(shown, /\n  <\/script>\n  <pre>\n/);
});

test("a < in text is text, and the truncation notice stays last and unindented", () => {
  assert.match(html("<p>a < b</p>"), /\n<p>\n  a < b\n<\/p>$/);
  assert.match(html("<div><p>cut", { preview_truncated: true }) + "", /<p>\n    cut/);
  const cut = c.prettyFormat(`${HEAD}\n\n<div><p>cut\n\n[preview truncated]`, { content_type: "text/html", body_encoding: "utf8", preview_truncated: true });
  assert.ok(cut.endsWith("\n    cut\n\n[preview truncated]"), cut);
});

test("XML is laid out too, where link is not an empty element", () => {
  const shown = c.prettyFormat('HTTP/1.1 200\n\n<?xml version="1.0"?><rss><channel><link>https://example.com/</link><item/></channel></rss>',
    { content_type: "application/rss+xml", body_encoding: "utf8" });
  assert.equal(shown, `HTTP/1.1 200\n\n${[
    '<?xml version="1.0"?>',
    "<rss>",
    "  <channel>",
    "    <link>",
    "      https://example.com/",
    "    </link>",
    "    <item/>",
    "  </channel>",
    "</rss>",
  ].join("\n")}`);
});

test("the editable request keeps an HTML body as captured", () => {
  const request = "POST /upload HTTP/1.1\ncontent-type: text/html\n\n<p>a</p>";
  assert.equal(c.prettyFormat(request, {}, { jsonLines: false }), request);
});
