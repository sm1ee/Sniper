// Production Decoder rendering with a synthetic DOM; no browser or app bootstrap.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture() {
  const values = new Map([["#input-value", ""], ["#input-password", ""]]);
  const rows = [];
  const context = vm.createContext({
    TextEncoder, TextDecoder, Uint8Array, document: {}, autoScroll() {}, ipCalc: function () {},
    $(selector) {
      return {
        get 0() { return rows.find(row => "#" + row.textarea.attributes.id === selector)?.textarea; },
        val(value) {
          if (!arguments.length) return values.get(selector) || "";
          values.set(selector, value); return this;
        },
        html(value) { if (selector === "#output") rows.length = 0; return this; },
        append(html) {
          const textareaMarkup = html.match(/<textarea\b([^>]*)><\/textarea>/)[1];
          const attributes = Object.fromEntries([...textareaMarkup.matchAll(/([\w-]+)="([^"]*)"/g)]
            .map(match => [match[1], match[2]]));
          const title = html.match(/<span id="([^"]+)" class="title">([^]*?)<\/span>/);
          const classes = new Set();
          const textarea = { attributes, readonly: /\sreadonly(?:\s|$)/.test(textareaMarkup),
            get value() { return (values.get("#" + attributes.id) || "").replace(/\r\n?/g, "\n"); } };
          values.set("#" + attributes.id, "");
          rows.push({ html, textarea, title: { id: title[1], html: title[2] },
            querySelector: () => textarea,
            classList: {
              toggle(name, on) { if (on) classes.add(name); else classes.delete(name); },
              contains(name) { return classes.has(name); },
            },
          });
          return this;
        },
        hide() { return this; }, show() { return this; }, click() { return this; },
        removeClass() { return this; }, addClass() { return this; },
        attr() { return this; }, text() { return this; },
      };
    },
  });
  for (const file of ["lib/cryptojs/components/core-min.js", "lib/cryptojs/components/enc-base64-min.js",
    "lib/cryptojs/components/enc-utf16-min.js", "lib/snov/rot13.js", "hasher.js"]) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/decoder", file), "utf8"), context,
      { filename: `web/decoder/${file}` });
  }
  const display = loadFunctions(["decoderOutputShows", "markEmptyDecoderOutputs"], {
    document: { getElementById: () => ({ querySelectorAll: () => rows }) },
    els: { toolsOutputHint: { classList: { toggle() {} } } },
  });
  return { context, hasher: context.hasher, rows, values, display };
}

function assertLabels(f) {
  const ids = f.rows.flatMap(row => [...row.html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]));
  assert.equal(new Set(ids).size, ids.length, "every generated ID is unique");
  for (const row of f.rows) {
    const { attributes } = row.textarea;
    assert.equal(attributes["aria-labelledby"], row.title.id, attributes.id);
    assert.equal(ids.filter(id => id === attributes["aria-labelledby"]).length, 1);
    assert.equal(row.title.id, attributes.id + "-title");
    assert.equal(row.textarea.readonly, true);
    assert.equal(attributes.spellcheck, "false");
    assert.equal(attributes["data-autosize"], "decoder");
  }
}

test("every production category gives each readonly output its own existing title", () => {
  const f = fixture();
  const allElements = Object.values(f.hasher.elements);
  assert.equal(new Set(allElements.map(element => element.id)).size, allElements.length);
  for (const tab of Object.values(f.context.tabs)) {
    f.hasher.tab = tab;
    f.hasher.updateUI();
    const elements = allElements.filter(element => element.tab === tab);
    assert.equal(f.rows.length, elements.length);
    assertLabels(f);
    for (const row of f.rows) {
      const element = elements.find(element => element.id === row.textarea.attributes.id);
      assert.equal(row.title.html, element.title);
    }
  }
});

test("category switches and repeated renders recreate unique current title references", () => {
  const f = fixture();
  let previousRows = [];
  for (const tab of [f.context.tabs.encode, f.context.tabs.string, f.context.tabs.encode, f.context.tabs.encode]) {
    f.hasher.tab = tab;
    f.hasher.updateUI();
    assertLabels(f);
    assert.equal(f.rows.some(row => previousRows.includes(row)), false);
    previousRows = [...f.rows];
  }
});

test("labeling leaves invalid outputs hidden through updates and recreation", () => {
  const f = fixture();
  f.hasher.tab = f.context.tabs.encode;
  for (const [input, visible] of [["aGVsbG8=", true], ["!!!!", false], ["!!!!", false], ["d29ybGQ", true]]) {
    f.values.set("#input-value", input);
    f.hasher.updateUI();
    f.display.markEmptyDecoderOutputs();
    assertLabels(f);
    for (const element of [f.hasher.elements.e2, f.hasher.elements.e3]) {
      const row = f.rows.find(row => row.textarea.attributes.id === element.id);
      assert.equal(!row.classList.contains("hidden"), visible);
    }
    assert.equal(f.values.get("#input-value"), input);
  }
});

test("title markup stays in its title span and output remains literal textarea content", () => {
  const f = fixture();
  const title = 'Synthetic "quoted" &amp; &lt;angle&gt; 한글';
  f.hasher.elements = { special: { id: "special-output", title, tab: 1, calculate: input => input } };
  f.hasher.tab = 1;
  const input = '</textarea><b data-example="quoted">& 한글 😀</b>\nsecond line';
  f.values.set("#input-value", input);
  f.hasher.updateUI();
  assertLabels(f);
  const row = f.rows[0];
  assert.equal(row.title.html, title);
  assert.equal(row.textarea.value, input);
  assert.equal(row.html.includes(input), false, "output is assigned by val(), not inserted as HTML");
  assert.equal(row.textarea.attributes["aria-label"], undefined, "title content is not duplicated into an attribute");
  assert.equal(row.textarea.attributes["aria-labelledby"], "special-output-title");
});


test("Strings typed text survives updates, row rebuilds and newline normalization without stale status", () => {
  const f = fixture();
  f.hasher.tab = f.context.tabs.string;
  for (const key of ["s2", "s4", "s6"]) {
    for (const rebuild of [false, true]) {
      f.hasher.updateUI();
      for (const text of ["NaN", "Invalid text", "Error\r\nreport", "Parse error", "Out of range", "", "Error"]) {
        const bytes = Buffer.from(text, key === "s6" ? "utf16le" : "utf8");
        const encoded = (key === "s6" ? bytes.swap16() : bytes).toString("hex");
        for (const input of [encoded, "gg", encoded, "0", ""]) {
          f.values.set("#input-value", input);
          if (rebuild) f.hasher.updateUI(); else f.hasher.update();
          f.display.markEmptyDecoderOutputs();
          const row = f.rows.find(row => row.textarea.attributes.id === f.hasher.elements[key].id);
          const result = f.context.decoderCalculateResult(f.hasher.elements[key], input);
          assert.equal(row.textarea.value, result.value.replace(/\r\n?/g, "\n"));
          assert.equal(row.textarea.decoderResult.value, row.textarea.value);
          assert.equal(row.textarea.decoderResult.success, result.success);
          assert.equal(row.classList.contains("hidden"), !(result.success && result.value.length));
          assert.equal(f.values.get("#input-value"), input);
          assertLabels(f);
          f.values.set("#" + f.hasher.elements[key].id, "Invalid stale value");
          f.display.markEmptyDecoderOutputs();
          assert.equal(row.classList.contains("hidden"), true, "mismatched status falls back rather than blesses new text");
        }
      }
    }
  }
});
