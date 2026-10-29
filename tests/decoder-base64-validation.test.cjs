// Tools-local Base64 calculations and display updates only: no app bootstrap,
// browser, clipboard, runtime, or traffic.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture(rowIds = ["e2", "e3"]) {
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
  const rows = rowIds.map(id => elements[id]).map(element => Object.assign(node(), {
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

const uriIds = ["e4", "e5", "e6", "e7"];
const uriNative = [encodeURI, encodeURIComponent, decodeURI, decodeURIComponent];

for (const [index, id] of uriIds.entries()) {
  test(`${id} preserves successful URI data even when its output resembles an error`, () => {
    const { context, elements } = fixture(uriIds);
    const display = loadFunctions(["decoderOutputShows"]);
    for (const input of ["Error report", "Invalid text", "NaN", "Parse error", "Out of range",
      "Error%20report", "Invalid%20text", "Parse%20error", "", "café 한글 😀", "\ufeff",
      "Error\r\nreport", "%2F", "%3F", "%23", "%25", "https://example.com/a?b=c#d"]) {
      const expected = uriNative[index](input);
      assert.equal(elements[id].calculate(input), expected);
      const result = context.decoderCalculateResult(elements[id], input, "");
      assert.equal(result.value, expected);
      assert.equal(result.success, true);
      assert.equal(display.decoderOutputShows(result.value, result), expected.length > 0);
    }
  });
}

test("URI failures retain legacy strings/throws but receive explicit failure status", () => {
  const { context, elements } = fixture(uriIds);
  for (const id of ["e4", "e5"]) {
    for (const input of ["\ud800", "\udfff", "a\ud800b"]) {
      assert.throws(() => elements[id].calculate(input), { name: "URIError" });
      const result = context.decoderCalculateResult(elements[id], input, "");
      assert.match(result.value, /^Error: /);
      assert.equal(result.success, false);
    }
  }
  for (const id of ["e6", "e7"]) {
    for (const input of ["%", "%G0", "%0", "%FF", "%C0%AF", "%ED%A0%80", "%E2%82", "%F4%90%80%80"]) {
      assert.equal(elements[id].calculate(input), "Parse error");
      const result = context.decoderCalculateResult(elements[id], input, "");
      assert.equal(result.value, "Parse error");
      assert.equal(result.success, false);
    }
    // Native decoders preserve literal lone surrogates; only malformed encoded UTF-8 fails.
    assert.equal(context.decoderCalculateResult(elements[id], "\ud800", "").success, true);
  }
  assert.equal(context.safeUriTransform(decodeURI, "%"), "Parse error");
  assert.equal(context.safeUriTransform(decodeURI, "Parse error"), "Parse error");
  assert.equal(elements.e6.calculate("%2F"), "%2F");
  assert.equal(elements.e7.calculate("%2F"), "/");
});

test("URI render status follows edits, empty input, speculative checks and rebuilt outputs", () => {
  const { context, values, elements, rows, display, nodes } = fixture(uriIds);
  context.hasher.tab = context.tabs.encode;
  const paint = input => {
    values.set("#input-value", input); context.hasher.update(); display.markEmptyDecoderOutputs();
    assert.equal(values.get("#input-value"), input);
  };
  for (const input of ["NaN", "%", "Error report", "\ud800", "Invalid text", "", "Parse error", "Error\r\nreport"]) {
    paint(input);
    for (const [index, id] of uriIds.entries()) {
      const node = nodes.get("#" + elements[id].id);
      const expected = context.decoderCalculateResult(elements[id], input, "");
      assert.equal(node.decoderResult.value, node.value);
      assert.equal(node.decoderResult.success, expected.success);
      assert.equal(rows[index].classList.contains("hidden"), !expected.success || !expected.value.length);
      context.decoderCalculateResult(elements[id], id === "e4" || id === "e5" ? "\ud800" : "%", "");
      assert.equal(node.decoderResult.success, expected.success);
    }
    display.markEmptyDecoderOutputs();
  }
  paint("Error report");
  for (const id of uriIds) nodes.get("#" + elements[id].id).value = "Invalid stale value";
  display.markEmptyDecoderOutputs();
  assert.ok(rows.every(row => row.classList.contains("hidden")));
  for (const id of uriIds) nodes.set("#" + elements[id].id, { value: "NaN" });
  display.markEmptyDecoderOutputs();
  assert.ok(rows.every(row => row.classList.contains("hidden")));
  context.hasher.tab = context.tabs.hash; context.hasher.update();
  context.hasher.tab = context.tabs.encode; paint("NaN");
  assert.ok(rows.every(row => !row.classList.contains("hidden")));
});

// Remaining arbitrary-text outputs in Encode share the same rendered status contract.
const textIds = ["e8", "e9", "e11", "e12", "e_base32_decode", "e_base45_decode", "e_base58_decode"];
const textExamples = ["NaN", "NaN", "\\u004e\\u0061\\u004e", "AnA", "JZQU4===", "++9X1", "TKy7"];

for (const [index, id] of textIds.entries()) {
  test(`${id} displays successful error-like text with current, not speculative, status`, () => {
    const { context, values, elements, rows, display, nodes } = fixture([id]);
    context.hasher.tab = context.tabs.encode;
    const paint = input => {
      values.set("#input-value", input); context.hasher.update(); display.markEmptyDecoderOutputs();
      assert.equal(values.get("#input-value"), input);
    };
    const inputs = [textExamples[index], "", textExamples[index]];
    for (const input of inputs) {
      paint(input);
      const result = context.decoderCalculateResult(elements[id], input, "");
      assert.equal(result.value, input ? "NaN" : "");
      assert.equal(elements[id].calculate(input), result.value);
      assert.equal(result.success, true);
      assert.equal(display.decoderOutputShows(result.value), false, "legacy heuristic hides this value");
      assert.equal(rows[0].classList.contains("hidden"), !input);
      const node = nodes.get("#" + elements[id].id);
      assert.equal(node.decoderResult.success, true);
      context.decoderCalculateResult(elements[id], "!", "");
      display.markEmptyDecoderOutputs();
      assert.equal(rows[0].classList.contains("hidden"), !input);
    }
    const selector = "#" + elements[id].id;
    nodes.get(selector).value = "Invalid stale value";
    display.markEmptyDecoderOutputs();
    assert.equal(rows[0].classList.contains("hidden"), true);
    nodes.set(selector, { value: "NaN" });
    display.markEmptyDecoderOutputs();
    assert.equal(rows[0].classList.contains("hidden"), true);
    context.hasher.tab = context.tabs.hash; context.hasher.update();
    context.hasher.tab = context.tabs.encode; paint(textExamples[index]);
    assert.equal(rows[0].classList.contains("hidden"), false);
  });
}

test("text status preserves HTML single-pass, Unicode code units and ROT13 values", () => {
  const { context, elements, display } = fixture(textIds);
  for (const text of ["Error report", "Invalid text", "Parse error", "Out of range", "NaN",
    "Error\r\nreport", "Invalid\rtext", "\ud800", "\ufeff", "café 한글 😀"]) {
    const inputs = { e8: text, e9: text, e11: context.convertToUnicode(text),
      e12: elements.e12.calculate(text) };
    for (const id of Object.keys(inputs)) {
      const result = context.decoderCalculateResult(elements[id], inputs[id], "");
      assert.equal(result.value, text);
      assert.equal(result.success, true);
      assert.equal(display.decoderOutputShows(result.value, result), true);
    }
  }
  assert.equal(elements.e9.calculate("Error &amp;lt; &lt;"), "Error &lt; <");
  assert.equal(elements.e8.calculate("Error <&>"), "Error &lt;&amp;&gt;");
  assert.equal(elements.e11.calculate("Error \\u004 \\uZZZZ \\u0041"), "Error \\u004 \\uZZZZ A");
});

for (const base of ["32", "45", "58"]) {
  test(`Base${base} separates real failures from identical successful plaintext`, () => {
    const id = `e_base${base}_decode`;
    const { context, values, elements, rows, display, nodes } = fixture([id]);
    context.hasher.tab = context.tabs.encode;
    const failure = `Invalid Base${base} input`;
    const malformed = base === "32" ? ["A", "!"] : base === "45" ? ["A", "::", ":::", "aa"] : ["0", "!", " "];
    const encode = text => elements[`e_base${base}_encode`].calculate(text);
    for (const input of [encode(failure), ...malformed, "", encode("Error\r\nreport"), encode(failure)]) {
      const invalid = malformed.includes(input);
      const result = context.decoderCalculateResult(elements[id], input, "");
      assert.equal(result.success, !invalid);
      assert.equal(result.value, elements[id].calculate(input));
      if (invalid || input === encode(failure)) assert.equal(result.value, failure);
      values.set("#input-value", input); context.hasher.update(); display.markEmptyDecoderOutputs();
      assert.equal(rows[0].classList.contains("hidden"), invalid || !input);
      const node = nodes.get("#" + elements[id].id);
      assert.equal(node.decoderResult.value, node.value);
      assert.equal(node.decoderResult.success, !invalid);
    }
    // Existing nonfatal UTF-8 decoding remains successful replacement text.
    const replacementInput = base === "32" ? "74======" : base === "45" ? "U5" : "5Q";
    const replacement = context.decoderCalculateResult(elements[id], replacementInput, "");
    assert.equal(replacement.value, "\ufffd");
    assert.equal(replacement.success, true);
  });
}

test("unexpected text-transform exceptions still receive central failure status", () => {
  const { context, elements, display } = fixture(textIds);
  for (const id of ["e8", "e9", "e11", "e12"]) {
    elements[id].calculate = () => { throw new Error("synthetic calculation failure"); };
    const result = context.decoderCalculateResult(elements[id], "benign", "");
    assert.equal(result.value, "Error: synthetic calculation failure");
    assert.equal(result.success, false);
    assert.equal(display.decoderOutputShows(result.value, result), false);
  }
});

test("typed Base-N results preserve permissive text and alphabet contracts", () => {
  const { context, elements } = fixture(textIds);
  for (const [id, input, expected] of [
    ["e_base32_decode", " \tj z q u 4=======\n", "NaN"],
    ["e_base45_decode", " 0", "$"],
    ["e_base58_decode", "11TKy7", "\0\0NaN"],
    ["e_base58_decode", "2g", "a"],
    ["e_base58_decode", "2G", "I"],
  ]) {
    const result = context.decoderCalculateResult(elements[id], input, "");
    assert.equal(result.value, expected);
    assert.equal(result.success, true);
    assert.equal(elements[id].calculate(input), expected);
  }
});
