// Production Tools calculators and updates only; no browser, runtime or traffic.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture() {
  const values = new Map([["#input-value", ""], ["#input-password", ""]]);
  const context = vm.createContext({
    TextEncoder, TextDecoder, Uint8Array, document: {}, autoScroll() {}, ipCalc: function () {},
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
  for (const file of ["lib/cryptojs/components/core-min.js", "lib/cryptojs/components/enc-base64-min.js",
    "lib/snov/rot13.js", "hasher.js"]) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/decoder", file), "utf8"), context,
      { filename: `web/decoder/${file}` });
  }
  const element = context.hasher.elements.e_base32_decode;
  const classes = new Set();
  const row = {
    querySelector: () => ({ value: values.get("#" + element.id) }),
    classList: {
      toggle(name, on) { if (on) classes.add(name); else classes.delete(name); },
      contains(name) { return classes.has(name); },
    },
  };
  const display = loadFunctions(["decoderOutputShows", "markEmptyDecoderOutputs"], {
    document: { getElementById: () => ({ querySelectorAll: () => [row] }) },
    els: { toolsOutputHint: { classList: { toggle() {} } } },
  });
  return { context, values, element, row, display };
}

const malformed = ["A", "MZX", "MZ5", "MZXW6A", "MZXW6Z", "MZXW6YQAA",
  "MZXW6YTBMZX", "MZXW6YTBMZXW6A"];

test("Base32 rejects impossible payload lengths instead of truncating extra symbols", () => {
  const { element } = fixture();
  for (const input of malformed) {
    assert.ok([1, 3, 6].includes(input.length % 8));
    for (const value of [input, input.toLowerCase() + "===", " \t" + [...input].join("\u00a0\ufeff") + "=\n"]) {
      assert.equal(element.calculate(value), "Invalid Base32 input", JSON.stringify(value));
    }
  }
});

test("valid Base32 remainders retain unpadded, case, whitespace and trailing-padding tolerance", () => {
  const { element } = fixture();
  for (const [input, expected] of [["", ""], ["MY", "f"], ["MZXQ", "fo"], ["MZXW6", "foo"],
    ["MZXW6YQ", "foob"], ["MZXW6YTB", "fooba"], ["MZXW6YTBOI", "foobar"]]) {
    for (const padding of ["", "=", "===", "======", "============"]) {
      for (const value of [input + padding, " \t\r\n\f\v" +
        [...(input.toLowerCase() + padding)].join("\u00a0\ufeff\u2028\u2029") + " \t"]) {
        assert.equal(element.calculate(value), expected, JSON.stringify(value));
      }
    }
  }
});

test("Base32 length validation does not impose canonical unused-bit checks", () => {
  const { element } = fixture();
  for (const [input, expected] of [["MZ", "f"], ["MZXR", "fo"], ["MZXW7", "foo"], ["MZXW6YR", "foob"]]) {
    assert.equal(element.calculate(input), expected);
    assert.equal(element.calculate(input + "========"), expected);
  }
});

test("valid Base32 bytes retain existing text conversion including non-UTF8 replacement", () => {
  const { element } = fixture();
  for (const [input, bytes] of [["AA", [0]], ["74======", [0xff]], ["777Q====", [0xff, 0xff]]]) {
    assert.equal(element.calculate(input), new TextDecoder("utf-8", { ignoreBOM: true }).decode(Uint8Array.from(bytes)));
  }
});

test("actual Tools updates hide malformed Base32 results and recover without changing input", () => {
  const { context, values, element, row, display } = fixture();
  context.hasher.tab = context.tabs.encode;
  for (const invalid of malformed) {
    for (const [input, expected, visible] of [
      ["MZXW6===", "foo", true], [invalid, "Invalid Base32 input", false], ["MZXW6YQ", "foob", true],
      ["", "", false],
    ]) {
      values.set("#input-value", input);
      context.hasher.update();
      display.markEmptyDecoderOutputs();
      assert.equal(values.get("#" + element.id), expected, JSON.stringify(input));
      assert.equal(!row.classList.contains("hidden"), visible, JSON.stringify(input));
      assert.equal(values.get("#input-value"), input);
    }
  }
});
