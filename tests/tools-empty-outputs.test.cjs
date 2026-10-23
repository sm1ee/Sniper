// An output row with nothing in it is noise: rows show once they hold a value,
// and until one does the header says where results will appear.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture(values) {
  const node = () => {
    const names = new Set();
    return { classList: { toggle: (n, on) => (on ? names.add(n) : names.delete(n)), contains: (n) => names.has(n) } };
  };
  const rows = values.map((value) => Object.assign(node(), { querySelector: () => ({ value }) }));
  const output = { querySelectorAll: () => rows };
  const els = { toolsOutputHint: node() };
  const c = loadFunctions(["markEmptyDecoderOutputs", "decoderOutputShows"], { document: { getElementById: () => output }, els });
  return { c, rows, hint: els.toolsOutputHint };
}

// The library's words for "does not apply" are as empty as an empty output.
test("empty and failed outputs hide, filled ones show, and the hint goes once one shows", () => {
  const f = fixture(["", "dXNlcg==", "Invalid Base32 input", "NaN"]);
  f.c.markEmptyDecoderOutputs();
  assert.deepEqual(f.rows.map((row) => row.classList.contains("hidden")), [true, false, true, true]);
  assert.equal(f.hint.classList.contains("hidden"), true);
});

test("with every output empty the hint shows", () => {
  const f = fixture(["", ""]);
  f.c.markEmptyDecoderOutputs();
  assert.equal(f.hint.classList.contains("hidden"), false);
});

test("an output shows unless it is empty or the library's word for not applying", () => {
  const c = loadFunctions(["decoderOutputShows"]);
  for (const value of ["", "NaN", "Parse error", "Out of range", "Invalid IP", "Invalid Base32 input",
    "Error: Calculation failed", "Error during Base58 encoding", null, undefined]) {
    assert.equal(c.decoderOutputShows(value), false, String(value));
  }
  for (const value of ["0", "dXNlcg==", "Strength: Weak", "Errors: 0", "Invalidated cache", 1700000000]) {
    assert.equal(c.decoderOutputShows(value), true, String(value));
  }
});

// Dimming a category that has nothing for this input points at the ones that
// do; the category in use stays open, and an empty input dims nothing.
test("a category with nothing to show for the input is idle, except the one in use", () => {
  const items = new Map();
  const node = () => {
    const names = new Set();
    return { classList: { toggle: (n, on) => (on ? names.add(n) : names.delete(n)), contains: (n) => names.has(n) } };
  };
  const inputs = { "input-value": { value: "user=alice" }, "input-password": { value: "" } };
  const document = { getElementById: (id) => inputs[id] || items.get(id) || items.set(id, node()).get(id) };
  const calls = [];
  const element = (tab, value) => ({ tab, calculate: () => { calls.push(tab); if (value instanceof Error) throw value; return value; } });
  const window = {
    tabs: { encode: 1, number: 2, jwt: 3, json: 4 },
    hasher: { tab: 4, elements: {
      a: element(1, "dXNlcg=="), b: element(1, "never computed"),
      c: element(2, "NaN"), d: element(2, new Error("synthetic")),
      e: element(3, ""), f: element(4, ""),
    } },
  };
  const c = loadFunctions(["markIdleDecoderTabs", "decoderOutputShows"], { document, window });
  c.markIdleDecoderTabs();
  const idle = (name) => document.getElementById(name).classList.contains("idle");
  assert.deepEqual(["encode", "number", "jwt", "json"].map(idle), [false, true, true, false]);
  assert.equal(calls.filter((tab) => tab === 1).length, 1, "a category stops at its first output that shows");
  inputs["input-value"].value = "";
  c.markIdleDecoderTabs();
  assert.deepEqual(["encode", "number", "jwt", "json"].map(idle), [false, false, false, false]);
});
