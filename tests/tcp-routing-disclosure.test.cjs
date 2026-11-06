const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");

test("TCP listener discloses direct routing and rule boundaries before Start", () => {
  const form = html.match(/<form\b[^>]*id="tcpListenerForm"[^>]*>([\s\S]*?)<\/form>/);
  assert.ok(form);
  assert.match(form[0], /aria-describedby="tcpRoutingDisclosure"/);
  const disclosure = form[1].match(/<small id="tcpRoutingDisclosure">([^<]+)<\/small>/);
  assert.ok(disclosure, "disclosure is visible text, not a title or hidden tooltip");
  assert.match(disclosure[1], /connects directly to the target/);
  assert.match(disclosure[1], /resolves hostnames locally/);
  assert.match(disclosure[1], /Proxy chain, Scope and HTTP intercept rules do not apply/);
  assert.ok(form[1].indexOf('id="tcpRoutingDisclosure"') < form[1].indexOf('id="tcpStart"'));
});

test("proxy chain description states its protocol boundary and explicit bypass exception", () => {
  const field = html.match(/<input id="proxyChainUrl"[^>]*\/>\s*<small>([^<]+)<\/small>/);
  assert.ok(field);
  assert.match(field[1], /HTTP\(S\), WebSocket and Replay, not TCP listeners/);
  assert.match(field[1], /Chain failures do not fall back to direct connections/);
  assert.match(field[1], /bypass hosts connect directly/);
  assert.doesNotMatch(field[1], /for captured traffic|never goes direct/);
});
