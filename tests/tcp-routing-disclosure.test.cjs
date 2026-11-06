const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");

// The one routing fact a person cannot see: TCP does not go through the
// proxy chain. It is read before Start and announced with the form.
test("TCP listener says it connects directly, before Start", () => {
  const form = html.match(/<form\b[^>]*id="tcpListenerForm"[^>]*>([\s\S]*?)<\/form>/);
  assert.ok(form);
  assert.match(form[0], /aria-describedby="tcpRoutingDisclosure"/);
  const disclosure = form[1].match(/<small id="tcpRoutingDisclosure">([^<]+)<\/small>/);
  assert.ok(disclosure, "disclosure is visible text, not a title or hidden tooltip");
  assert.match(disclosure[1], /directly, without the proxy chain/);
  assert.ok(form[1].indexOf('id="tcpRoutingDisclosure"') < form[1].indexOf('id="tcpStart"'));
});

test("proxy chain fields show only while the chain is on", () => {
  assert.match(html, /<input class="switch-input" id="proxyChainEnabled"[^>]*data-reveals="proxyChainFields"/);
  assert.match(html, /<div class="capture-settings-reveal" id="proxyChainFields">[\s\S]*?id="proxyChainUrl"/);
});
