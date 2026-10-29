const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const settingsSource = fs.readFileSync(path.join(__dirname, "../src/ui_settings.rs"), "utf8").replace(/\r\n/g, "\n");
const plain = value => JSON.parse(JSON.stringify(value));

test("every HTTP history column sort can be persisted in UI settings", () => {
  const columns = appSource.match(/^const HISTORY_COLUMN_DEFS = \{[^]*?^\};/m);
  assert.ok(columns, "Missing frontend column definitions");
  const context = vm.createContext({});
  vm.runInContext(`${columns[0]}\nglobalThis.sortKeys = Object.values(HISTORY_COLUMN_DEFS).map(column => column.sortKey);`, context);

  const allowed = settingsSource.match(/const HTTP_HISTORY_SORT_KEY_OPTIONS: &\[&str\] = &\[([^]*?)\];/);
  assert.ok(allowed, "Missing backend UI-settings sort allowlist");
  const allowedKeys = new Set([...allowed[1].matchAll(/"([^"]+)"/g)].map(match => match[1]));
  for (const sortKey of context.sortKeys) {
    assert.ok(allowedKeys.has(sortKey), `UI settings discards the ${sortKey} history sort`);
  }
});

function backendHistoryDefaults() {
  const defaults = settingsSource.match(/^fn default_history_column_widths\(\)[^]*?^\}/m);
  assert.ok(defaults, "Missing backend history column defaults");
  const entries = [...defaults[0].matchAll(/\("([^"]+)"\.to_string\(\), (\d+)\)/g)];
  assert.ok(entries.length, "No backend history column defaults were extracted");
  return Object.fromEntries(entries.map(([, key, width]) => [key, Number(width)]));
}

// Only extracted preference helpers and an inert Notes resize handle run here.
function historyLayoutFixture() {
  const state = { historyColumnWidths: {} }, handlers = new Map(), styles = new Map(), saves = [];
  const handle = { dataset: { columnKey: "notes" }, addEventListener: (name, callback) => handlers.set(name, callback), setAttribute() {} };
  const context = loadFunctions([
    "clamp", "createDefaultHistoryColumnWidths", "sanitizeHistoryColumnWidths",
    "bindHistoryColumnResizers", "applyHistoryColumnWidths",
  ], {
    state,
    historyColumnHandles: [handle],
    els: { historyTable: { querySelectorAll: () => [handle], style: { setProperty: (name, value) => styles.set(name, value) } } },
    saveHistoryColumnWidths: () => saves.push({ ...state.historyColumnWidths }),
  });
  const rules = appSource.match(/^const HISTORY_COLUMN_RULES = \{[^]*?^\};/m);
  assert.ok(rules, "Missing frontend history column rules");
  vm.runInContext(`${rules[0]}\nglobalThis.rules = HISTORY_COLUMN_RULES;`, context);
  return { context, state, handlers, styles, saves };
}

test("backend history defaults agree with frontend defaults and legacy missing columns", () => {
  const { context } = historyLayoutFixture(), backend = backendHistoryDefaults();
  const frontend = plain(context.createDefaultHistoryColumnWidths());
  assert.equal(frontend.notes, 220);
  assert.equal(backend.notes, 220, "Fresh settings must use the widened Notes default");
  for (const [key, width] of Object.entries(backend)) {
    assert.equal(width, frontend[key], `Backend default differs for ${key}`);
  }
  // Older backend maps legitimately omit the subsequently added Modified column.
  assert.deepEqual(plain(context.sanitizeHistoryColumnWidths(backend)), frontend);
  const legacy = { ...backend };
  delete legacy.edited;
  delete legacy.notes;
  assert.deepEqual(plain(context.sanitizeHistoryColumnWidths(legacy)), frontend);
});

test("saved Notes widths remain explicit preferences, including the former default", () => {
  const { context } = historyLayoutFixture();
  for (const notes of [90, 321, 640]) {
    const saved = { ...backendHistoryDefaults(), notes, host: 444, edited: 120 };
    const normalized = plain(context.sanitizeHistoryColumnWidths(saved));
    assert.equal(normalized.notes, notes);
    assert.equal(normalized.host, 444);
    assert.equal(normalized.edited, 120);
    assert.deepEqual(plain(context.sanitizeHistoryColumnWidths(plain(normalized))), normalized);
  }
});

test("Notes double-click reset and CSS fallback use the widened default", () => {
  const { context, state, handlers, styles, saves } = historyLayoutFixture();
  state.historyColumnWidths = context.sanitizeHistoryColumnWidths({ ...backendHistoryDefaults(), notes: 90, host: 444 });
  context.bindHistoryColumnResizers();
  handlers.get("dblclick")({ preventDefault() {}, stopPropagation() {} });
  assert.equal(state.historyColumnWidths.notes, 220);
  assert.equal(state.historyColumnWidths.host, 444);
  assert.equal(styles.get("--history-col-notes"), "220px");
  assert.equal(saves.length, 1);
  assert.equal(saves[0].notes, 220);
  const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");
  const notesRule = css.match(/\.history-table \.col-notes\s*\{[^}]*?width:\s*var\(--history-col-notes,\s*(\d+)px\)/);
  assert.ok(notesRule, "Missing Notes CSS fallback");
  assert.equal(Number(notesRule[1]), state.historyColumnWidths.notes);
});
