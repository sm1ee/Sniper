// Ctrl+Tab from the last Replay tab made the first one active, but the strip
// stayed scrolled to its far end, so the tab now shown was out of view. The
// active tab's own row is now moved at once, just far enough to show it.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const { revealReplayTab } = loadFunctions(["revealReplayTab"]);

// A row 600px wide, its tab at `tabLeft` in the row's content.
function strip(scrollLeft, tabLeft, tabWidth = 140) {
  const row = { scrollLeft, clientWidth: 600, getBoundingClientRect: () => ({ left: 8 }) };
  const tab = {
    closest: (selector) => (selector === ".replay-tab-list" ? row : null),
    getBoundingClientRect: () => ({ left: 8 + tabLeft - row.scrollLeft, width: tabWidth }),
  };
  return { row, tab };
}

test("wrapping to the first tab brings it into view", () => {
  const { row, tab } = strip(711, 0);
  revealReplayTab(tab);
  assert.equal(row.scrollLeft, 0);
});

test("a tab in view leaves its row where the operator left it", () => {
  const { row, tab } = strip(711, 800);
  revealReplayTab(tab);
  assert.equal(row.scrollLeft, 711);
});

test("a tab past the right edge is brought just into view", () => {
  const { row, tab } = strip(0, 900);
  revealReplayTab(tab);
  assert.equal(row.scrollLeft, 440);
});

test("no tab, no move", () => {
  assert.doesNotThrow(() => revealReplayTab(null));
});
