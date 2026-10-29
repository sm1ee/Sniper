// Offline rendering and preference handlers only; no app startup or requests.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");
const settings = fs.readFileSync(path.join(__dirname, "../src/ui_settings.rs"), "utf8");
const plain = value => JSON.parse(JSON.stringify(value));
const cellContext = () => loadFunctions(["renderHistoryCell", "escapeHtml"]);

for (const sequence of [0, 1, 9999, 10000, 999999]) {
  test(`index ${sequence} keeps its full value and tooltip in a semantic cell`, () => {
    assert.equal(cellContext().renderHistoryCell("index", { sequence }, { index: 7 }),
      `<td class="history-index-cell" title="${sequence}">${sequence}</td>`);
  });
}

for (const sequence of [undefined, null]) {
  test(`${sequence} sequence keeps the one-based loaded-entry fallback`, () => {
    assert.equal(cellContext().renderHistoryCell("index", { sequence }, { index: 9999 }),
      '<td class="history-index-cell" title="10000">10000</td>');
  });
}

test("the full index value is escaped independently of its numeric API contract", () => {
  const value = '\"<span>&\'unsafe</span>';
  const escaped = "&quot;&lt;span&gt;&amp;&#039;unsafe&lt;/span&gt;";
  assert.equal(cellContext().renderHistoryCell("index", { sequence: value }, { index: 0 }),
    `<td class="history-index-cell" title="${escaped}">${escaped}</td>`);
});

test("virtual rows keep the index cell treatment after column reordering", () => {
  const item = { id: "fixture-index", sequence: 10000, host: "example.com", path: "/synthetic" };
  const state = { _historyEntries: [{ item, index: 0 }], historyColumnOrder: ["index", "host", "path"] };
  const shell = { clientHeight: 300, scrollTop: 0 };
  const body = { innerHTML: "" };
  const c = loadFunctions(["renderHistoryVirtual", "renderHistoryCell", "escapeHtml"], {
    state, els: { historyTable: { closest: () => shell }, historyTableBody: body },
    getHistoryRowHeight: () => 27, HISTORY_BUFFER_ROWS: 30, HTTP_HISTORY_SCROLL_PREFETCH_ROWS: 120,
    scheduleHistoryBackfill() {},
  });
  const indexCell = '<td class="history-index-cell" title="10000">10000</td>';
  const hostCell = '<td class="cell-host">example.com</td>';
  const pathCell = '<td class="cell-url">/synthetic</td>';
  c.renderHistoryVirtual();
  assert.ok(body.innerHTML.includes(indexCell + hostCell + pathCell));
  state.historyColumnOrder = ["host", "path", "index"];
  c.renderHistoryVirtual();
  assert.ok(body.innerHTML.includes(hostCell + pathCell + indexCell));
  assert.equal((body.innerHTML.match(/history-index-cell/g) || []).length, 1);
});

test("only semantic index data cells gain horizontal room; headers and row height retain their padding", () => {
  const rule = css.match(/\.history-table td\.history-index-cell\s*\{([^}]+)\}/);
  assert.ok(rule, "Missing scoped index data-cell padding");
  assert.equal(rule[1].trim(), "padding-inline: 4px;");
  assert.match(css, /\.history-table th,\s*\.history-table td\s*\{\s*padding: 5px 12px;/);
  assert.equal((css.match(/history-index-cell/g) || []).length, 1);
});

function eventTarget() {
  const listeners = new Map();
  return {
    addEventListener(type, callback) { listeners.set(type, callback); },
    removeEventListener(type, callback) { if (listeners.get(type) === callback) listeners.delete(type); },
    fire(type, fields = {}) { listeners.get(type)?.({ preventDefault() {}, stopPropagation() {}, ...fields }); },
  };
}

function layoutFixture() {
  const state = { historyColumnWidths: {} }, styles = {}, saves = [];
  const document = eventTarget(), window = eventTarget(), handle = eventTarget();
  document.body = { classList: { add() {}, remove() {} } };
  handle.dataset = { columnKey: "index" };
  handle.setAttribute = () => {};
  handle.classList = { add() {}, remove() {} };
  handle.closest = () => ({ getBoundingClientRect: () => ({ width: state.historyColumnWidths.index }) });
  const c = loadFunctions([
    "clamp", "createDefaultHistoryColumnWidths", "sanitizeHistoryColumnWidths",
    "bindHistoryColumnResizers", "applyHistoryColumnWidths",
  ], {
    state, document, window, historyColumnHandles: [handle],
    els: { historyTable: { querySelectorAll: () => [handle], style: { setProperty(key, value) { styles[key] = value; } } } },
    saveHistoryColumnWidths() { saves.push({ ...state.historyColumnWidths }); },
  });
  vm.runInContext(appSource.match(/^const HISTORY_COLUMN_RULES = \{[^]*?^\};/m)[0]
    + "\nglobalThis.rules = HISTORY_COLUMN_RULES;", c);
  return { c, state, styles, saves, document, handle };
}

test("frontend, CSS and backend index defaults and resize bounds remain unchanged", () => {
  const { c } = layoutFixture();
  assert.deepEqual(plain(c.rules.index), { default: 48, min: 40, max: 88 });
  assert.equal(c.createDefaultHistoryColumnWidths().index, 48);
  assert.equal(c.sanitizeHistoryColumnWidths(undefined).index, 48);
  assert.equal(c.sanitizeHistoryColumnWidths({ host: 444 }).index, 48);
  assert.match(css, /\.history-table \.col-index\s*\{\s*width: var\(--history-col-index, 48px\)/);
  const backendDefaults = settings.match(/fn default_history_column_widths\(\)[^]*?\n\}/)[0];
  assert.match(backendDefaults, /\("index"\.to_string\(\), 48\)/);
});

test("saved narrow and wide index widths remain explicit preferences", () => {
  const { c } = layoutFixture();
  for (const index of [40, 48, 64, 72, 88]) {
    const normalized = c.sanitizeHistoryColumnWidths({ index, host: 444 });
    assert.equal(normalized.index, index);
    assert.equal(normalized.host, 444);
    assert.deepEqual(plain(c.sanitizeHistoryColumnWidths(normalized)), plain(normalized));
  }
});

test("actual index drag and double-click retain width persistence without touching other columns", () => {
  const f = layoutFixture();
  f.state.historyColumnWidths = f.c.sanitizeHistoryColumnWidths({ index: 48, host: 444 });
  f.c.bindHistoryColumnResizers();
  f.handle.fire("mousedown", { clientX: 100, buttons: 1 });
  f.document.fire("mousemove", { clientX: 124, buttons: 1 });
  assert.equal(f.saves.length, 0);
  assert.equal(f.state.historyColumnWidths.index, 72);
  assert.equal(f.styles["--history-col-index"], "72px");
  f.document.fire("mouseup");
  assert.equal(f.saves.length, 1);
  assert.equal(f.saves[0].index, 72);
  f.handle.fire("dblclick");
  assert.equal(f.styles["--history-col-index"], "48px");
  assert.equal(f.saves.length, 2);
  assert.equal(f.saves[1].index, 48);
  assert.equal(f.saves[1].host, 444);
});
