const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

// With collapsed borders the row right after a borderless spacer measures half a
// border short, as Chromium reports it: 26.5px for rows 27px apart. Built on that
// height, every scroll offset drifts by half a pixel per row.
function body(rows) {
  const nodes = rows.map(({ top, height }) => ({
    classList: { contains: (name) => name === "history-row" },
    getBoundingClientRect: () => ({ top, height }),
  }));
  nodes.forEach((node, index) => { node.nextElementSibling = nodes[index + 1] ?? null; });
  return { querySelector: (selector) => (selector === ".history-row" ? nodes[0] ?? null : null) };
}

test("row pitch is the distance between rows, not the first row's height", () => {
  const { measuredRowPitch } = loadFunctions(["measuredRowPitch"], {});
  assert.equal(measuredRowPitch(body([{ top: 100, height: 26.5 }, { top: 127, height: 27 }])), 27);
  assert.equal(measuredRowPitch(body([{ top: 100, height: 30 }])), 30, "a lone row has only its height");
  assert.equal(measuredRowPitch(body([])), 0);
});

test("findings use the row pitch for their scroll geometry", () => {
  const context = loadFunctions(["measuredRowPitch", "getFindingsRowHeight"], {
    els: { findingsBody: body([{ top: 0, height: 26.5 }, { top: 27, height: 27 }]) },
    measuredFindingsRowHeight: 27,
    FINDINGS_ROW_HEIGHT: 27,
    renderFindingsVirtual() {},
  });
  assert.equal(context.getFindingsRowHeight(), 27);
});
