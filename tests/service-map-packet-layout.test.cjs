// Stylesheet text only: how the map inspector lays out a retained packet.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");
const rule = (selector) => css.match(new RegExp(`^${selector.replace(/[.()[\]]/g, "\\$&")} \\{([^}]*)\\}`, "m"))?.[1] ?? "";

// A long packet once grew its editor to its full length, so the whole
// inspector scrolled and the sample picker went off screen. The panes now keep
// their share of the inspector and scroll inside their editors.
test("Details panes split the inspector, stacked, and scroll inside their editors", () => {
  assert.match(rule(".service-map-detail-body.packet-details"), /display: flex;[^}]*flex-direction: column;/);
  assert.match(rule(".packet-viewer.lower-workbench"), /grid-template-rows: minmax\(0, 1fr\) minmax\(0, 1fr\);/);
  assert.match(rule(".packet-viewer .editor-shell"), /flex: 1 1 0;/);
  assert.doesNotMatch(css, /\.packet-viewer[^{]*\{[^}]*height: 280px/);
});

// Side by side, each pane would be too narrow for a packet in the usual
// inspector width; they sit side by side only when the inspector is wide.
test("Details panes sit side by side only in a wide inspector", () => {
  assert.doesNotMatch(css, /@container \(min-width: 780px\)/);
  assert.match(css, /@container \(min-width: 1100px\) \{\s*\.packet-viewer\.lower-workbench \{ grid-template-columns: minmax\(0, 1fr\) minmax\(0, 1fr\); grid-template-rows: minmax\(0, 1fr\); \}/);
});

test("the sample and Inspect pickers use the app's dark select look", () => {
  const select = rule(".packet-source select,\n.packet-inspect select");
  for (const declaration of ["border: 1px solid var(--line);", "background-color: var(--panel-code);", "color: var(--text);"]) {
    assert.ok(select.includes(declaration), declaration);
  }
});
