// Native buttons supply keyboard activation; the existing li handler still
// owns category changes. No browser, clipboard, backend, or network here.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

test("all Tools categories contain native buttons and preserve library li IDs", () => {
  const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
  const strip = html.match(/<ul id="tabs"[^>]*>([^]*?)<\/ul>/)[1];
  const categories = [...strip.matchAll(/<li id="([^"]+)"[^>]*><button type="button" aria-pressed="(true|false)">([^<]+)<\/button><\/li>/g)];
  assert.deepEqual(categories.map(match => match[1]), ["encode", "string", "number", "json", "jwt", "hash", "hmac", "crc", "cipher", "net", "time", "morse", "password"]);
  assert.deepEqual(categories.filter(match => match[2] === "true").map(match => match[1]), ["encode"]);
});

test("a bubbled button click selects its owning category exactly once without changing input", async () => {
  const bindings = [];
  const calls = [];
  const input = { value: "synthetic input", focus() { calls.push("focus"); } };
  const window = {
    tabs: { encode: 7, string: 13 },
    jQuery: selector => ({ on(type, callback) { bindings.push({ selector, type, callback }); } }),
    hasher: { tab: 7, updateUI() { calls.push(this.tab); } },
  };
  const c = loadFunctions(["bootToolsWorkbench"], {
    DECODER_SCRIPT_SOURCES: [], window, state: { toolsReady: false }, els: {},
    document: { getElementById: id => id === "input-value" ? input : null },
    syncDecoderToolMeta() { calls.push("sync"); },
  });
  await c.bootToolsWorkbench();
  calls.length = 0;
  const handlers = bindings.filter(binding => binding.selector === "#tabs li" && binding.type === "click");
  assert.equal(handlers.length, 1);
  const li = { id: "string" };
  handlers[0].callback.call(li, { target: { tagName: "BUTTON", parentElement: li } });
  assert.equal(window.hasher.tab, 13);
  assert.deepEqual(calls, [13, "sync", "focus"]);
  assert.equal(input.value, "synthetic input");
});
