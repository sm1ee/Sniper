// The browser menu's rows, as markup. No app startup, API, or DOM.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const { browserMenuRowHtml } = loadFunctions(["escapeHtml", "browserMenuRowHtml"]);

const missing = (overrides = {}) => ({
  browser: "edge",
  installed: false,
  install_url: "https://www.microsoft.com/edge/download",
  ...overrides,
});

test("a browser that is not installed links to its vendor's download page", () => {
  const html = browserMenuRowHtml(missing());
  assert.match(html, /<a class="browser-menu-install" href="https:\/\/www\.microsoft\.com\/edge\/download"/);
  assert.match(html, /target="_blank" rel="noopener noreferrer"/, "opens outside the app, without a handle back");
  assert.match(html, /aria-label="Install edge"/);
  assert.match(html, /data-open="edge"[^>]*disabled/, "the row itself still cannot be opened");
  assert.doesNotMatch(html, /Not installed/, "the link replaces the label");
});

test("only an https address becomes a link", () => {
  for (const url of ["javascript:alert(1)", "http://example.com/", "data:text/html,x", "//example.com/", "", undefined]) {
    const html = browserMenuRowHtml(missing({ install_url: url }));
    assert.doesNotMatch(html, /<a /, `linked ${JSON.stringify(url)}`);
    assert.match(html, /Not installed/, "without a link the row says so");
  }
});

test("an address cannot break out of its attribute", () => {
  const html = browserMenuRowHtml(missing({ install_url: 'https://example.com/"><img src=x onerror=alert(1)>' }));
  assert.doesNotMatch(html, /<img/);
  assert.match(html, /&quot;&gt;&lt;img/);
});

test("an installed browser has no link, whatever the catalog says", () => {
  const html = browserMenuRowHtml({ browser: "chrome", installed: true, default: true, install_url: "https://example.com/" });
  assert.doesNotMatch(html, /<a /);
  assert.match(html, /Default/);
  assert.doesNotMatch(html, /disabled/);
});

test("a saved choice that was uninstalled keeps its Use auto button beside the link", () => {
  const html = browserMenuRowHtml(missing({ browser: "brave", install_url: "https://brave.com/download/", preferred: true }));
  assert.match(html, /data-prefer="auto"/);
  assert.match(html, /<a class="browser-menu-install"/);
  assert.match(html, /browser-menu-row has-pin has-install/);
});

test("names and hints are escaped", () => {
  const html = browserMenuRowHtml(missing({ browser: "<b>x</b>", install_hint: 'say "hi" <now>' }));
  assert.doesNotMatch(html, /<b>/);
  assert.match(html, /title="say &quot;hi&quot; &lt;now&gt;"/);
});

test("a browser built for an agent is marked, a plain CDP one is not", () => {
  assert.match(browserMenuRowHtml({ browser: "ego", installed: true, driver: "ego-cli" }), /browser-menu-agent/);
  assert.doesNotMatch(browserMenuRowHtml({ browser: "chrome", installed: true, driver: "cdp" }), /browser-menu-agent/);
});
