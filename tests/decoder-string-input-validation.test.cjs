// Local text conversion only; no app bootstrap, clipboard, network, or runtime.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function fixture() {
  const values = new Map([["#input-value", ""], ["#input-password", ""]]);
  const context = vm.createContext({
    document: {}, autoScroll() {}, ipCalc: function () {},
    $(selector) {
      return {
        val(value) {
          if (!arguments.length) return values.get(selector) || "";
          values.set(selector, value); return this;
        },
        hide() { return this; }, removeClass() { return this; }, attr() { return this; },
        text() { return this; }, html() { return this; },
      };
    },
  });
  for (const file of ["lib/cryptojs/components/core-min.js", "lib/cryptojs/components/enc-utf16-min.js", "hasher.js"]) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/decoder", file), "utf8"), context,
      { filename: `web/decoder/${file}` });
  }
  return { context, values, elements: context.hasher.elements };
}

for (const element of ["s2", "s4"]) {
  test(`${element} rejects incomplete hexadecimal bytes instead of inventing a final byte`, () => {
    const { elements } = fixture();
    for (const input of ["0", "6", "610", "006", "00000", "6162630", "eab0800"]) {
      assert.equal(elements[element].calculate(input), "NaN", input);
    }
  });
}

test("Hex to UTF-16 rejects incomplete code units instead of padding them with zeros", () => {
  const { elements } = fixture();
  for (const input of ["0", "6", "61", "006", "00000", "006100", "0061006", "d83dde0"]) {
    assert.equal(elements.s6.calculate(input), "NaN", input);
  }
});

for (const element of ["s2", "s4", "s6"]) {
  test(`${element} keeps the existing empty, prefix, whitespace and invalid-alphabet behavior`, () => {
    const { elements } = fixture();
    assert.equal(elements[element].calculate(""), "");
    for (const input of ["0x61", "0X0061", "61 62", "0061\n", "\t0061", "gg", "-001", "0.61", "６１"]) {
      assert.equal(elements[element].calculate(input), "NaN", JSON.stringify(input));
    }
  });
}

test("ASCII/Latin-1 hex conversion preserves every byte including NUL and high bytes", () => {
  const { elements } = fixture();
  const bytes = Uint8Array.from({ length: 256 }, (_, index) => index);
  const input = Buffer.from(bytes).toString("latin1");
  const expected = Buffer.from(bytes).toString("hex");
  assert.equal(elements.s1.calculate(input), expected);
  assert.equal(elements.s2.calculate(expected), input);
  assert.equal(elements.s2.calculate(expected.toUpperCase()), input);
});

test("UTF-8 and UTF-16 hex round trips preserve complete Unicode input and BOMs", () => {
  const { elements } = fixture();
  for (const input of ["", "a", "\0", "\r\n\t", "\ufeff", "\ufeff\ufeffhello", "café 한글 😀",
    "e\u0301", "\u007f\u0080\u07ff\u0800\ud7ff\ue000\uffff", "\u{10000}\u{10ffff}"]) {
    const utf8 = Buffer.from(input, "utf8").toString("hex");
    const utf16 = Buffer.from(input, "utf16le").swap16().toString("hex");
    assert.equal(elements.s3.calculate(input), utf8);
    assert.equal(elements.s5.calculate(input), utf16);
    for (const encoded of [utf8, utf8.toUpperCase()]) assert.equal(elements.s4.calculate(encoded), input);
    for (const encoded of [utf16, utf16.toUpperCase()]) assert.equal(elements.s6.calculate(encoded), input);
  }
});

test("UTF-16 retains existing code-unit behavior for lone surrogates while UTF-8 rejects them", () => {
  const { elements } = fixture();
  for (const input of ["\ud800", "\udfff", "a\ud800b"]) {
    assert.equal(elements.s3.calculate(input), "Parse error");
    assert.equal(elements.s6.calculate(elements.s5.calculate(input)), input);
  }
});

test("Hex to UTF-8 keeps rejecting complete bytes that are not valid UTF-8", () => {
  const { elements } = fixture();
  for (const input of ["80", "ff", "c0af", "eda080", "eab0", "f4908080"]) {
    assert.equal(elements.s4.calculate(input), "Parse error", input);
  }
});

test("repeated Strings updates replace malformed outputs and preserve the original input", () => {
  const { context, values, elements } = fixture();
  context.hasher.tab = context.tabs.string;
  for (const input of ["0061", "610", "61", "gg", "", "d83dde00", "0062"]) {
    values.set("#input-value", input); context.hasher.update();
    for (const element of ["s2", "s4", "s6"]) {
      assert.equal(values.get("#" + elements[element].id), elements[element].calculate(input));
    }
    assert.equal(values.get("#input-value"), input);
  }
});
