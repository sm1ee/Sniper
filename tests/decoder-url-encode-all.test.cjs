// Tools ▸ Encode: percent-encoding every byte, as Burp's Decoder and its
// "URL-encode all characters" do. Tools-local calculation only.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function load() {
  const context = vm.createContext({
    TextEncoder, TextDecoder, Uint8Array, document: {}, autoScroll() {}, ipCalc: function () {},
    $() { return { val() { return ""; }, hide() { return this; }, removeClass() { return this; },
      attr() { return this; }, text() { return this; }, html() { return this; } }; },
  });
  for (const file of ["lib/cryptojs/components/core-min.js", "lib/cryptojs/components/enc-base64-min.js",
    "lib/snov/rot13.js", "hasher.js"]) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/decoder", file), "utf8"), context,
      { filename: `web/decoder/${file}` });
  }
  return context;
}

test("URL encode (all characters) percent-encodes every UTF-8 byte, letters included", () => {
  const context = load();
  const encode = Object.values(context.hasher.elements).filter(element => element.tab === context.tabs.encode);
  const all = encode.find(element => element.title === "URL encode (all characters)");
  assert.ok(all, "the Encode tab lists it");
  assert.equal(encode[encode.indexOf(all) - 1].title, "encodeURIComponent()", "it sits with the other URL rows");
  for (const [input, expected] of [
    ["i", "%69"],
    ["a b/?=&", "%61%20%62%2F%3F%3D%26"],
    ["é한😀", "%C3%A9%ED%95%9C%F0%9F%98%80"],
    ["\r\n", "%0D%0A"],
    ["", ""],
  ]) {
    const result = context.decoderCalculateResult(all, input, "");
    assert.deepEqual([result.value, result.success], [expected, true], input);
  }
});
