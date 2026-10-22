const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function fixture() {
  const values = new Map([["#input-value", ""], ["#input-password", ""]]);
  const context = vm.createContext({
    TextEncoder, TextDecoder, Uint8Array, document: {}, autoScroll() {},
    $(selector) {
      return {
        val(value) {
          if (arguments.length === 0) return values.get(selector) || "";
          values.set(selector, value);
          return this;
        },
        hide() { return this; }, removeClass() { return this; },
        attr() { return this; },
        text() { return this; },
        html() { return this; },
      };
    },
  });
  for (const file of [
    "lib/cryptojs/components/core-min.js", "lib/cryptojs/components/enc-base64-min.js",
    "lib/cryptojs/rollups/md5.js", "lib/hash/md4.js", "lib/hash/ripemd.js",
    "lib/hash/whirpool.js", "lib/hash/crc.js", "lib/snov/ipcalc.js", "hasher.js",
  ]) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/decoder", file), "utf8"), context,
      { filename: `web/decoder/${file}` });
  }
  return { context, values, elements: context.hasher.elements };
}

test("HTML special-character decoding expands each reference only once", () => {
  const { elements } = fixture();
  for (const input of [
    "&lt;", "&gt;", "&quot;", "&#039;", "&amp;", "&amp;lt;", "&amp;amp;lt;",
    "<tag>&\"' 한글 😀", "&unknown; &#39; &#x3c;", "\ud800 &lt; \udfff",
  ]) {
    assert.equal(elements.e9.calculate(elements.e8.calculate(input)), input, input);
  }
  assert.equal(elements.e9.calculate("&amp;lt; &lt; &amp;quot; &quot;"), "&lt; < &quot; \"");
});

for (const base of ["base32", "base45", "base58"]) {
  test(`${base} preserves all valid UTF-8 text, including a leading U+FEFF`, () => {
    const { elements } = fixture();
    for (const input of ["", "hello", "café 한글 😀", "\ufeff", "\ufeffhello", "\ufeff한글 😀",
      "\ufeff\ufeffhello", "x\ufeffy", "\0hello\0", " \t\n"]) {
      const encoded = elements[`e_${base}_encode`].calculate(input);
      assert.equal(elements[`e_${base}_decode`].calculate(encoded), input, JSON.stringify(input));
    }
  });
}

// UTF-8 known answers independently generated with OpenSSL's legacy provider:
// printf <text> | openssl dgst -provider legacy -md4 / -whirlpool / -md4 -hmac <key>.
// The ASCII MD4 vector is also the RFC 1320 "abc" vector.
const digestVectors = [
  {
    text: "abc", key: "key", md4: "a448017aaf21d8525fc10ae87aa6729d",
    hmac: "32c43d6d6eda7f1e464711473b956b68",
    whirlpool: "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5",
  },
  {
    text: "café", key: "clé", md4: "874e571d26908d3fd6561d39da735bb4",
    hmac: "4fc9af3b6c6d65f249116f9f47676aa8",
    whirlpool: "0164de0fc4d161ff9b0d8b6162b1a28c8bc28cf4231f0518fc314901c53c294d659f66180a865b754d033f2d2c1a179681bf3bf2caadce2188061eaaad9192c9",
  },
  {
    text: "한글", key: "비밀", md4: "d1ad0c39c35c227fe8aa61433be4e8d0",
    hmac: "1ee04c0081ffcea5109261d84f75e6d7",
    whirlpool: "2acf3caf21bf5e5c33ef1436047591e3c0d6514736411ea6fac3637a12c6b11e8647d9392b4003435296e0d35833241f159d52026af74bfb59ab7ba98d09f652",
  },
  {
    text: "😀", key: "🔑", md4: "d60c87f11ac824ea903b6d937e840081",
    hmac: "57a204e63c13a38550a361a190bec710",
    whirlpool: "f6c76df71127b5fb60831e76e7cb943c7edc111d9363724210aa7a06e24e92c7e2cf2068635002612ccc0aca34f4fa219c61a10b79154d6ccf5572fac14980cc",
  },
];

for (const { name, element, field } of [
  { name: "MD4", element: "h7", field: "md4" },
  { name: "Whirlpool", element: "h9", field: "whirlpool" },
  { name: "HMAC-MD4", element: "hm8", field: "hmac" },
]) {
  test(`${name} hashes the UTF-8 bytes of text and keys`, () => {
    const { elements } = fixture();
    for (const vector of digestVectors) {
      assert.equal(String(elements[element].calculate(vector.text, vector.key)), vector[field], vector.text);
    }
  });
}

test("CRC-32 matches independent zlib UTF-8 vectors", () => {
  const { elements } = fixture();
  for (const [input, expected] of [
    ["", "0x00000000"], ["123456789", "0xCBF43926"], ["café", "0x98AD42B5"],
    ["한글", "0x90B9AD65"], ["😀", "0x054DB544"],
  ]) assert.equal(elements.c4.calculate(input), expected, input);
});

test("all legacy CRC tools process UTF-8 bytes instead of UTF-16 code units", () => {
  const { context, elements } = fixture();
  for (const [element, calculator, formatter] of [
    ["c1", "Crc8Str", "Hex8"], ["c2", "Crc16Str", "Hex16"],
    ["c3", "Fcs16Str", "Hex16"], ["c4", "Crc32Str", "Hex32"],
  ]) {
    for (const input of ["", "123456789", "café 한글 😀", "\ufeff\0"]) {
      const bytes = Buffer.from(input, "utf8").toString("latin1");
      assert.equal(elements[element].calculate(input), context[formatter](context[calculator](bytes)), element);
    }
  }
});

test("legacy text digests reject lone surrogates consistently with MD5", () => {
  const { elements } = fixture();
  for (const input of ["\ud800", "\udfff", "a\ud800b"]) {
    assert.throws(() => elements.h1.calculate(input), /URI malformed/);
    for (const element of ["h7", "h9", "hm8", "c1", "c2", "c3", "c4"]) {
      assert.throws(() => elements[element].calculate(input, "valid key"), /URI malformed/, element);
    }
    assert.throws(() => elements.hm8.calculate("valid text", input), /URI malformed/);
  }
});

test("repeated UI updates replace invalid digests and keep the input unchanged", () => {
  const { context, values, elements } = fixture();
  for (const [tab, element, valid] of [["hash", "h7", "café"], ["crc", "c4", "한글"]]) {
    context.hasher.tab = context.tabs[tab];
    const output = `#${elements[element].id}`;
    values.set("#input-value", valid);
    context.hasher.update();
    assert.equal(values.get(output), String(elements[element].calculate(valid)));
    values.set("#input-value", "\ud800");
    context.hasher.update();
    assert.match(values.get(output), /^Error: URI malformed/);
    assert.equal(values.get("#input-value"), "\ud800");
    values.set("#input-value", "abc");
    context.hasher.update();
    assert.equal(values.get(output), String(elements[element].calculate("abc")));
  }
});
