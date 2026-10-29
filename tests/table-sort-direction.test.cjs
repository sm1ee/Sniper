// Sort arrows and the sorted column's color, across tables. Saved list
// metadata and stylesheet text only; no scanner, runtime or network calls.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const rows = ["info", "critical", "low", "high", "medium"].map((severity) => ({
  id: severity, severity, found_at: "2026-10-07T00:00:00Z", category: "header",
  title: "Saved entry", host: "example.com", path: "/saved",
}));

function findings() {
  const headers = ["severity", "found_at"].map((key) => {
    const classes = new Set();
    const indicator = { textContent: "↕" };
    return {
      dataset: { findingsSort: key }, indicator, querySelector: () => indicator,
      classList: { toggle: (name, on) => (on ? classes.add(name) : classes.delete(name)), contains: (name) => classes.has(name) },
    };
  });
  const c = loadFunctions(["getFilteredFindings", "toggleFindingsSort", "updateFindingsSortHeaders"], {
    findingsData: rows, findingsSortKey: "found_at", findingsSortDir: "desc", els: {},
    SEVERITY_ORDER: { critical: 0, high: 1, medium: 2, low: 3, info: 4 },
    isInScopeHost: () => true, renderFindings() {},
    document: { querySelectorAll: () => headers },
  });
  return { c, severity: headers[0] };
}

// ↓ means the largest on top everywhere: the newest in HTTP history, and here
// the most severe.
test("Findings sorts the most severe first under ↓, and the reverse under ↑", () => {
  const { c, severity } = findings();
  c.toggleFindingsSort("severity");
  assert.equal(c.findingsSortDir, "desc");
  assert.deepEqual(c.getFilteredFindings().map((row) => row.id), ["critical", "high", "medium", "low", "info"]);
  assert.equal(severity.indicator.textContent, "↓");
  assert.equal(severity.classList.contains("active"), true);
  c.toggleFindingsSort("severity");
  assert.deepEqual(c.getFilteredFindings().map((row) => row.id), ["info", "low", "medium", "high", "critical"]);
  assert.equal(severity.indicator.textContent, "↑");
});

test("HTTP and WebSocket history mark the sorted column in the gold the other tables use", () => {
  const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");
  const rule = (selector) => css.match(new RegExp(`^${selector.replace(/[.]/g, "\\.")} \\{([^}]*)\\}`, "m"))?.[1] ?? "";
  assert.match(css, /\.table-sortable\.active \{\s*color: var\(--point\);/);
  assert.match(rule(".sort-header.active"), /color: var\(--point\);/);
  // The arrow takes the header's gold rather than the dim of an idle arrow.
  assert.match(rule(".sort-header.active .sort-indicator"), /color: inherit;/);
});
