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
  const c = loadFunctions(["markEmptyDecoderOutputs"], { document: { getElementById: () => output }, els });
  return { c, rows, hint: els.toolsOutputHint };
}

test("empty outputs hide, filled ones show, and the hint goes once one shows", () => {
  const f = fixture(["", "dXNlcg==", ""]);
  f.c.markEmptyDecoderOutputs();
  assert.deepEqual(f.rows.map((row) => row.classList.contains("hidden")), [true, false, true]);
  assert.equal(f.hint.classList.contains("hidden"), true);
});

test("with every output empty the hint shows", () => {
  const f = fixture(["", ""]);
  f.c.markEmptyDecoderOutputs();
  assert.equal(f.hint.classList.contains("hidden"), false);
});
