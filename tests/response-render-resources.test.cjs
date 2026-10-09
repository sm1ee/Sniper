// Render's opt-in resource pass: which URLs it fetches and how stylesheets are
// inlined. Fake fetchers only; no app startup, API, network or DOM.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const c = loadFunctions(["renderResourceUrl", "recordPageUrl", "inlineCssResources"], {
  URL,
  // Stands in for FileReader, which Node lacks: the type is what the tests check.
  blobDataUrl: async (blob) => (blob ? `data:${blob.type};stub` : null),
});
vm.runInContext(appSource.match(/^const RENDER_CSS_URL_PATTERN = .+;$/m)[0], c);

const fetcher = (files) => ({
  fetched: [],
  async fetchBlob(url) {
    this.fetched.push(url);
    return url in files ? new Blob([files[url].body], { type: files[url].type }) : null;
  },
});

test("only http(s) references are fetched, resolved against the page", () => {
  const page = "https://example.com/dir/page.html";
  assert.equal(c.renderResourceUrl("img/a.png", page), "https://example.com/dir/img/a.png");
  assert.equal(c.renderResourceUrl("//cdn.example.com/x.css", page), "https://cdn.example.com/x.css");
  assert.equal(c.renderResourceUrl("/root.png", page), "https://example.com/root.png");
  for (const skipped of ["data:image/png;base64,AA==", "javascript:alert(1)", "#frag", "ftp://example.com/x", "", null]) {
    assert.equal(c.renderResourceUrl(skipped, page), null, String(skipped));
  }
});

test("the page URL comes from the record", () => {
  assert.equal(c.recordPageUrl({ scheme: "http", host: "localhost:18891", path: "/a?b=1" }), "http://localhost:18891/a?b=1");
  assert.equal(c.recordPageUrl({ path: "/" }), null);
});

test("a stylesheet's images and imports are inlined, each relative to its own file", async () => {
  const files = {
    "https://example.com/css/img/bg.png": { type: "image/png", body: "x" },
    "https://example.com/css/theme.css": { type: "text/css", body: 'h1{background:url("../img/h.png")}' },
    "https://example.com/img/h.png": { type: "image/png", body: "y" },
  };
  const css = await c.inlineCssResources(
    'body{background:url(img/bg.png)} @import "theme.css";',
    "https://example.com/css/site.css",
    fetcher(files),
  );
  assert.match(css, /body\{background:url\("data:image\/png;stub"\)\}/);
  const imported = decodeURIComponent(css.match(/@import url\("data:text\/css;charset=utf-8,([^"]*)"\)/)[1]);
  assert.equal(imported, 'h1{background:url("data:image/png;stub")}');
});

test("an import cycle is cut instead of followed forever", async () => {
  const files = {
    "https://example.com/a.css": { type: "text/css", body: '@import "b.css"; a{}' },
    "https://example.com/b.css": { type: "text/css", body: '@import "a.css"; b{}' },
  };
  const css = await c.inlineCssResources('@import "a.css";', "https://example.com/page.html", fetcher(files));
  assert.match(css, /^@import url\("data:text\/css/);
});

test("a reference that cannot be fetched is left as it was", async () => {
  const css = await c.inlineCssResources("p{background:url(missing.png)}", "https://example.com/", fetcher({}));
  assert.equal(css, "p{background:url(missing.png)}");
});
