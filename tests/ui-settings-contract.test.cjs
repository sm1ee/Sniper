const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource } = require("./frontend-test-helpers.cjs");

test("every HTTP history column sort can be persisted in UI settings", () => {
  const columns = appSource.match(/^const HISTORY_COLUMN_DEFS = \{[^]*?^\};/m);
  assert.ok(columns, "Missing frontend column definitions");
  const context = vm.createContext({});
  vm.runInContext(`${columns[0]}\nglobalThis.sortKeys = Object.values(HISTORY_COLUMN_DEFS).map(column => column.sortKey);`, context);

  const settingsSource = fs.readFileSync(path.join(__dirname, "../src/ui_settings.rs"), "utf8");
  const allowed = settingsSource.match(/const HTTP_HISTORY_SORT_KEY_OPTIONS: &\[&str\] = &\[([^]*?)\];/);
  assert.ok(allowed, "Missing backend UI-settings sort allowlist");
  const allowedKeys = new Set([...allowed[1].matchAll(/"([^"]+)"/g)].map(match => match[1]));
  for (const sortKey of context.sortKeys) {
    assert.ok(allowedKeys.has(sortKey), `UI settings discards the ${sortKey} history sort`);
  }
});
