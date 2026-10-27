// Stylesheet text only: how per-row labels read in History and Scope.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");
const rule = (selector) => css.match(new RegExp(`^${selector.replace(/[.()[\]]/g, "\\$&")} \\{([^}]*)\\}`, "m"))?.[1] ?? "";

// A bordered pill on every row was louder than the data, as it was for
// Method and Status before them.
test("History's TLS reads as toned text like Method, not a pill", () => {
  assert.doesNotMatch(css, /^\.tls-badge,$/m, "TLS is no longer in the pill group");
  const tls = rule(".tls-badge");
  assert.match(tls, /font-weight: 600;/);
  assert.doesNotMatch(tls, /border|background|border-radius|padding/);
  assert.match(rule(".tls-badge.empty"), /color: var\(--text-dim\);/);
});

// In scope is gold in the Map inspector; the Scope site map now matches it.
test("Scope's site map marks in-scope hosts in the Map inspector's gold", () => {
  const gold = css.match(/((?:^[^{}\n]+,\n)*^[^{}\n]+) \{ color: var\(--point\); background: var\(--point-soft\); border-color: var\(--point-border\); \}/m)?.[1] ?? "";
  assert.match(gold, /\.service-map-detail \.detail-chip\.ok/);
  assert.match(gold, /\.target-host-actions \.detail-chip\.ok/);
});
