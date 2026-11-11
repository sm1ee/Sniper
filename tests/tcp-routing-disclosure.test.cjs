const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");

// The one routing fact a person cannot see: which TCP connections go through
// the upstream proxy. It is read before Save and announced with the form.
test("TCP listener says how it reaches its target, before Save", () => {
  const form = html.match(/<form\b[^>]*id="tcpListenerForm"[^>]*>([\s\S]*?)<\/form>/);
  assert.ok(form);
  assert.match(form[0], /aria-describedby="tcpRoutingDisclosure"/);
  const disclosure = form[1].match(/<small id="tcpRoutingDisclosure">([^<]+)<\/small>/);
  assert.ok(disclosure, "disclosure is visible text, not a title or hidden tooltip");
  assert.match(disclosure[1], /upstream proxy when it is on; this machine and bypassed hosts go direct/);
  assert.ok(form[1].indexOf('id="tcpRoutingDisclosure"') < form[1].indexOf('id="tcpSaveListener"'));
});

test("proxy chain fields show only while the chain is on", () => {
  assert.match(html, /<input class="switch-input" id="proxyChainEnabled"[^>]*data-reveals="proxyChainFields"/);
  assert.match(html, /<div class="capture-settings-reveal" id="proxyChainFields">[\s\S]*?id="proxyChainUrl"/);
});
