// Tools-local Base64 calculations and display updates only: no app bootstrap,
// browser, clipboard, runtime, or traffic.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture() {
  const values = new Map([["#input-value", ""], ["#input-password", ""]]);
  const nodes = new Map();
  const context = vm.createContext({
    TextEncoder, TextDecoder, Uint8Array, document: {}, autoScroll() {}, ipCalc: function () {},
    $(selector) {
      if (!nodes.has(selector)) nodes.set(selector, { value: "" });
      const node = nodes.get(selector);
      return {
        0: node,
        val(value) {
          if (!arguments.length) return values.get(selector) || "";
          values.set(selector, value); node.value = String(value).replace(/\r\n?/g, "\n"); return this;
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
  const elements = context.hasher.elements;
  const node = () => {
    const classes = new Set();
    return { classList: {
      toggle(name, on) { if (on) classes.add(name); else classes.delete(name); },
      contains(name) { return classes.has(name); },
    } };
  };
  const rows = [elements.e2, elements.e3].map(element => Object.assign(node(), {
    querySelector: () => nodes.get("#" + element.id),
  }));
  const output = { querySelectorAll: () => rows };
  const hint = node();
  const display = loadFunctions(["decoderOutputShows", "markEmptyDecoderOutputs"], {
    document: { getElementById: () => output }, els: { toolsOutputHint: hint },
  });
  return { context, values, elements, rows, hint, display, nodes };
}

const invalidInputs = [
  "!!!!", "A!A!", "SGVsbG8-", "SGVsbG8_", "SGVsbG8$", "\0AAA", "SGV\u200bsbG8=",
  "Zg==\u0085",
  "A", "AAAAA", "SGVsbG8AA",
  "=", "==", "===", "====", "A=", "A==", "A===", "Zg=", "Zg===", "Zm8==",
  "Zm9v=", "Zm9v====", "Z=g=", "Zg==A", "=Zg==", "Zg==\nZg==", "aGVsbG8=garbage",
];

for (const element of ["e2", "e3"]) {
  test(`${element} rejects invalid Base64 alphabet, length, padding and trailing data`, () => {
    const { elements } = fixture();
    for (const input of invalidInputs) {
      assert.equal(elements[element].calculate(input), "Invalid Base64 input", JSON.stringify(input));
    }
  });
}

test("Base64 text and hex decoding preserve padded, unpadded and supported whitespace input", () => {
  const { elements } = fixture();
  for (const input of ["", "f", "fo", "foo", "foob", "fooba", "foobar", "hello", "\0\r\n",
    "café 한글 😀", "\ufeff", "\ufeff\ufeffhello"]) {
    const encoded = Buffer.from(input, "utf8").toString("base64");
    for (const value of [encoded, encoded.replace(/=+$/, "")]) {
      for (const whitespace of ["", " \t\r\n\f\v", "\u00a0\ufeff\u2028\u2029"]) {
        const spaced = whitespace + [...value].join(whitespace) + whitespace;
        assert.equal(elements.e2.calculate(spaced), input, JSON.stringify(spaced));
        assert.equal(elements.e3.calculate(spaced), Buffer.from(input, "utf8").toString("hex"));
      }
    }
  }
});

test("Base64 validation does not add canonical pad-bit restrictions", () => {
  const { elements } = fixture();
  for (const [input, expected] of [["Zh==", "f"], ["Zh", "f"], ["Zm9=", "fo"], ["Zm9", "fo"]]) {
    assert.equal(elements.e2.calculate(input), expected);
    assert.equal(elements.e3.calculate(input), Buffer.from(expected).toString("hex"));
  }
});

test("valid binary Base64 remains available as exact hex when it is not UTF-8 text", () => {
  const { elements } = fixture();
  for (const bytes of [Buffer.from([0xff]), Buffer.from([0xfb, 0xff]),
    Buffer.from(Array.from({ length: 256 }, (_, index) => index))]) {
    const encoded = bytes.toString("base64");
    assert.equal(elements.e2.calculate(encoded), "");
    assert.equal(elements.e3.calculate(encoded), bytes.toString("hex"));
    assert.equal(elements.e3.calculate(encoded.replace(/=+$/, "")), bytes.toString("hex"));
  }
});

test("actual Tools updates hide fabricated or stale Base64 results and recover without changing input", () => {
  const { context, values, elements, rows, hint, display } = fixture();
  context.hasher.tab = context.tabs.encode;
  const steps = [
    ["aGVsbG8=", "hello", "68656c6c6f", [true, true]],
    ...invalidInputs.map(input => [input, "Invalid Base64 input", "Invalid Base64 input", [false, false]]),
    ["/w==", "", "ff", [false, true]],
    ["", "", "", [false, false]],
    [" \t\r\n\f\v", "", "", [false, false]],
    ["\u00a0\ufeff", "", "", [false, false]],
    ["d29ybGQ", "world", "776f726c64", [true, true]],
  ];
  for (const [input, text, hex, visible] of steps) {
    values.set("#input-value", input);
    context.hasher.update();
    display.markEmptyDecoderOutputs();
    assert.equal(values.get("#" + elements.e2.id), text, JSON.stringify(input));
    assert.equal(values.get("#" + elements.e3.id), hex, JSON.stringify(input));
    assert.deepEqual(rows.map(row => !row.classList.contains("hidden")), visible, JSON.stringify(input));
    assert.equal(hint.classList.contains("hidden"), visible.some(Boolean));
    assert.equal(values.get("#input-value"), input);
  }
});


test("successful Base64 plaintext is not confused with legacy error messages", () => {
  const { context, values, elements, rows, display, nodes } = fixture();
  context.hasher.tab = context.tabs.encode;
  for (const text of ["Error report", "Invalid text", "NaN", "Invalid Base64 input",
    "Parse error", "Out of range", "Error\r\nreport", "Invalid\rtext"]) {
    values.set("#input-value", Buffer.from(text).toString("base64"));
    context.hasher.update(); display.markEmptyDecoderOutputs();
    assert.equal(elements.e2.calculate(values.get("#input-value")), text);
    assert.equal(rows[0].classList.contains("hidden"), false, text);
    const node = nodes.get("#" + elements.e2.id);
    assert.equal(node.decoderResult.value, node.value);
    assert.equal(node.decoderResult.success, true);
  }
});

test("Base64 status follows edits, clearing and repainting, not speculative calculations", () => {
  const { context, values, elements, rows, display, nodes } = fixture();
  context.hasher.tab = context.tabs.encode;
  for (const [input, visible, success] of [["TmFO", true, true], ["!", false, false],
    ["", false, true], ["RXJyb3IgcmVwb3J0", true, true]]) {
    values.set("#input-value", input); context.hasher.update();
    const node = nodes.get("#" + elements.e2.id);
    context.decoderCalculateResult(elements.e2, "!", "");
    display.markEmptyDecoderOutputs();
    assert.equal(rows[0].classList.contains("hidden"), !visible);
    assert.equal(node.decoderResult.success, success);
  }
  const id = "#" + elements.e2.id;
  // A changed value cannot inherit a previous success, even before repaint.
  nodes.get(id).value = "Invalid Base64 input";
  display.markEmptyDecoderOutputs();
  assert.equal(rows[0].classList.contains("hidden"), true);
  // Replacing a DOM node (tab rerender) starts without metadata.
  nodes.set(id, { value: "NaN" });
  display.markEmptyDecoderOutputs();
  assert.equal(rows[0].classList.contains("hidden"), true);
  context.hasher.tab = context.tabs.hash;
  context.hasher.update();
  context.hasher.tab = context.tabs.encode;
  context.hasher.update(); display.markEmptyDecoderOutputs();
  assert.equal(rows[0].classList.contains("hidden"), false);
  assert.equal(nodes.get(id).decoderResult.value, "Error report");
});

test("typed results guide category availability without changing legacy error filtering", () => {
  const { context, elements } = fixture();
  const c = loadFunctions(["decoderOutputShows"]);
  for (const input of ["TmFO", "RXJyb3IgcmVwb3J0", "SW52YWxpZCB0ZXh0"]) {
    const result = context.decoderCalculateResult(elements.e2, input, "");
    assert.equal(c.decoderOutputShows(result.value, result), true);
    assert.equal(c.decoderOutputShows(result.value), false);
  }
  const failed = context.decoderCalculateResult(elements.e2, "!", "");
  assert.equal(c.decoderOutputShows(failed.value, failed), false);
  const legacy = context.decoderCalculateResult({ calculate: () => "Parse error" }, "", "");
  assert.equal(c.decoderOutputShows(legacy.value, legacy), false);
});
