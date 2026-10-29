// Production header/resize bindings with inert DOM and saved preferences only.
// No app startup, backend requests, browser/native keys, or traffic execution.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

function target() {
  const listeners = new Map(), classes = new Set(), attrs = {};
  return {
    attrs, dataset: {}, classList: { add: (...values) => values.forEach(value => classes.add(value)),
      remove: (...values) => values.forEach(value => classes.delete(value)), contains: value => classes.has(value),
      toggle(value, on) { if (on) classes.add(value); else classes.delete(value); } },
    setAttribute(name, value) { attrs[name] = String(value); }, getAttribute: name => attrs[name] ?? null,
    addEventListener(name, callback) { if (!listeners.has(name)) listeners.set(name, new Set()); listeners.get(name).add(callback); },
    removeEventListener(name, callback) { listeners.get(name)?.delete(callback); },
    callbacks: name => [...(listeners.get(name) || [])], count: name => listeners.get(name)?.size || 0,
    fire(name, values = {}) {
      const event = { target: this, clientX: 0, buttons: 1, defaultPrevented: false, stopped: false,
        preventDefault() { this.defaultPrevented = true; }, stopPropagation() { this.stopped = true; }, ...values };
      for (const callback of [...(listeners.get(name) || [])]) callback(event);
      return event;
    },
  };
}

function fixture() {
  const state = { historyColumnWidths: { host: 444, path: 555, index: 48 }, historyColumnOrder: ["host", "path", "index"] };
  const document = target(), window = target(); document.body = target(); document.activeElement = document.body;
  const saves = [], sorts = [], styles = {}, headers = target();
  let cells = [], handles = [], buttons = [], headerWrites = 0, rowRenders = 0;
  const parseAttrs = text => Object.fromEntries([...text.matchAll(/([\w-]+)="([^"]*)"/g)].map(match => [match[1], match[2]]));
  headers.contains = node => cells.some(cell => cell === node || cell.handle === node || cell.button === node);
  headers.querySelectorAll = () => cells;
  Object.defineProperty(headers, "innerHTML", { set(html) {
    if (headers.contains(document.activeElement)) document.activeElement = document.body;
    headerWrites++; headers.markup = html;
    cells = [...html.matchAll(/<th([^>]+)>([^]*?)<\/th>/g)].map(match => {
      const cell = target(), attrs = parseAttrs(match[1]); cell.dataset.columnKey = attrs["data-column-key"];
      cell.getBoundingClientRect = () => ({ left: 0, width: state.historyColumnWidths[cell.dataset.columnKey] });
      const handle = target(), handleTag = match[2].match(/<span class="column-resize-handle"([^>]*)>/)[1];
      Object.assign(handle.attrs, parseAttrs(handleTag)); handle.dataset.columnKey = cell.dataset.columnKey;
      handle.classList.add("column-resize-handle"); handle.closest = () => cell;
      handle.focus = () => { document.activeElement = handle; };
      const button = target(); button.dataset.sortKey = match[2].match(/data-sort-key="([^"]+)"/)[1];
      button.closest = () => cell; button.querySelector = () => ({ textContent: "" });
      button.focus = () => { document.activeElement = button; };
      cell.handle = handle; cell.button = button; return cell;
    });
    handles = cells.map(cell => cell.handle); buttons = cells.map(cell => cell.button);
    headers.afterReplace?.();
  } });
  const table = { style: { setProperty(key, value) { styles[key] = value; } }, querySelector: () => headers,
    querySelectorAll: selector => selector === ".column-resize-handle" ? handles : selector === ".sort-header" ? buttons : [] };
  const c = loadFunctions(["renderHistoryHeader", "bindHistoryColumnResizers", "applyHistoryColumnWidths", "saveHistoryColumnWidths",
    "bindColumnDragAndDrop", "clamp"], {
    state, document, window, els: { historyTable: table }, historyColumnHandles: [], columnDragState: null,
    scheduleUiSettingsSave() { saves.push({ ...state.historyColumnWidths }); },
    toggleSort: key => sorts.push(key), renderSortHeaders() {}, renderHistory() { rowRenders++; },
    requestAnimationFrame: callback => callback(),
  });
  for (const name of ["HISTORY_COLUMN_RULES", "HISTORY_COLUMN_DEFS"]) {
    const declaration = appSource.match(new RegExp(`^const ${name} = \\{[^]*?^\\};`, "m"))[0];
    vm.runInContext(`${declaration}\nglobalThis.${name} = ${name};`, c);
  }
  c.renderHistoryHeader(); c.applyHistoryColumnWidths();
  return { c, state, document, window, saves, sorts, styles, headers,
    handle: key => handles.find(handle => handle.dataset.columnKey === key),
    button: key => buttons.find(button => button.dataset.sortKey === key),
    cell: key => cells.find(cell => cell.dataset.columnKey === key),
    counts: () => ({ headerWrites, rowRenders }),
    key(key, column = "host", values = {}) { return this.handle(column).fire("keydown", { key, ...values }); },
  };
}

test("rendered handles are named focusable vertical separators with live pixel bounds and shared instructions", () => {
  const f = fixture();
  for (const key of f.state.historyColumnOrder) {
    const handle = f.handle(key), rules = f.c.HISTORY_COLUMN_RULES[key];
    assert.equal(handle.getAttribute("role"), "separator");
    assert.equal(handle.getAttribute("tabindex"), "0");
    assert.equal(handle.getAttribute("aria-orientation"), "vertical");
    assert.match(handle.getAttribute("aria-label"), /^Resize .+ column$/);
    assert.equal(handle.getAttribute("aria-hidden"), null);
    assert.equal(handle.getAttribute("aria-valuemin"), String(rules.min));
    assert.equal(handle.getAttribute("aria-valuemax"), String(rules.max));
    assert.equal(handle.getAttribute("aria-valuenow"), String(f.state.historyColumnWidths[key]));
    assert.equal(handle.getAttribute("aria-valuetext"), `${f.state.historyColumnWidths[key]} pixels`);
    assert.equal(handle.getAttribute("aria-describedby"), "historyColumnResizeHelp");
    assert.match(handle.getAttribute("title"), /Left.*Right.*Enter/);
  }
  const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
  assert.match(html, /id="historyColumnResizeHelp"[^>]*>[^<]*Left[^<]*Right[^<]*Enter[^<]*default width/);
  const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");
  assert.match(css, /\.column-resize-handle:focus-visible\s*\{[^}]*outline:/);
});

test("Left and Right resize only the focused column by eight without rerendering, sorting, or losing focus", () => {
  const f = fixture(), handle = f.handle("host"), before = f.counts(); handle.focus();
  for (const [key, width] of [["ArrowRight", 452], ["ArrowLeft", 444]]) {
    const event = f.key(key);
    assert.equal(event.defaultPrevented, true); assert.equal(event.stopped, true);
    assert.equal(f.state.historyColumnWidths.host, width);
    assert.equal(handle.getAttribute("aria-valuenow"), String(width));
    assert.equal(handle.getAttribute("aria-valuetext"), `${width} pixels`);
    assert.equal(f.document.activeElement, handle);
  }
  assert.equal(f.state.historyColumnWidths.path, 555); assert.deepEqual(f.state.historyColumnOrder, ["host", "path", "index"]);
  assert.equal(f.saves.length, 2); assert.deepEqual(f.sorts, []); assert.deepEqual(f.counts(), before);
});

test("keyboard adjustment clamps at the existing bounds and does not save unchanged widths", () => {
  const f = fixture(); f.handle("index").focus();
  f.key("ArrowLeft", "index"); assert.equal(f.state.historyColumnWidths.index, 40);
  f.key("ArrowLeft", "index"); assert.equal(f.saves.length, 1);
  f.state.historyColumnWidths.index = 88; f.c.applyHistoryColumnWidths();
  f.key("ArrowRight", "index"); assert.equal(f.state.historyColumnWidths.index, 88); assert.equal(f.saves.length, 1);
  f.key("ArrowLeft", "index"); assert.equal(f.state.historyColumnWidths.index, 80); assert.equal(f.saves.length, 2);
});

test("Enter resets just its column using existing defaults and is a no-op at that default", () => {
  const f = fixture(), handle = f.handle("host"), before = f.counts(); handle.focus();
  const event = f.key("Enter"); assert.equal(event.defaultPrevented, true); assert.equal(event.stopped, true);
  assert.equal(f.state.historyColumnWidths.host, 320); assert.equal(f.state.historyColumnWidths.path, 555);
  assert.equal(handle.getAttribute("aria-valuenow"), "320"); assert.equal(f.saves.length, 1);
  f.key("Enter"); assert.equal(f.saves.length, 1);
  assert.equal(f.document.activeElement, handle); assert.deepEqual(f.counts(), before); assert.deepEqual(f.sorts, []);
});

for (const key of ["ArrowUp", "ArrowDown"]) test(`${key} stays local without resizing, saving, or preventing native scroll`, () => {
  const f = fixture(), before = JSON.stringify(f.state); f.handle("host").focus();
  const event = f.key(key); assert.equal(event.stopped, true); assert.equal(event.defaultPrevented, false);
  assert.equal(JSON.stringify(f.state), before); assert.equal(f.saves.length, 0);
});

for (const flag of ["defaultPrevented", "isComposing", "ctrlKey", "metaKey", "altKey", "shiftKey"]) {
  test(`${flag} events are left untouched`, () => {
    const f = fixture(), before = JSON.stringify(f.state);
    for (const key of ["ArrowLeft", "ArrowRight", "Enter", "ArrowUp", "ArrowDown"]) {
      const event = f.key(key, "host", { [flag]: true });
      assert.equal(event.stopped, false); assert.equal(event.defaultPrevented, flag === "defaultPrevented");
    }
    assert.equal(JSON.stringify(f.state), before); assert.equal(f.saves.length, 0);
  });
}

test("unassigned keys keep their native behavior", () => {
  const f = fixture();
  for (const key of ["Home", "End", "Tab", " ", "Escape", "x"]) {
    const event = f.key(key); assert.equal(event.defaultPrevented, false); assert.equal(event.stopped, false);
  }
  assert.equal(f.saves.length, 0); assert.equal(f.state.historyColumnWidths.host, 444);
});

test("pointer drag, pointer reset, and applied saved widths refresh the same live values", () => {
  const f = fixture(), handle = f.handle("host");
  handle.fire("mousedown", { clientX: 100 }); f.document.fire("mousemove", { clientX: 124 });
  assert.equal(handle.getAttribute("aria-valuenow"), "468"); assert.equal(f.saves.length, 0);
  f.document.fire("mouseup"); assert.equal(f.saves.length, 1);
  handle.fire("dblclick"); assert.equal(handle.getAttribute("aria-valuenow"), "320"); assert.equal(f.saves.length, 2);
  handle.fire("dblclick"); assert.equal(f.saves.length, 2);
  f.state.historyColumnWidths.host = 600; f.c.applyHistoryColumnWidths();
  assert.equal(handle.getAttribute("aria-valuenow"), "600"); assert.equal(handle.getAttribute("aria-valuetext"), "600 pixels");
  assert.equal(f.saves.length, 2); assert.equal(f.state.historyColumnWidths.path, 555);
});

for (const action of ["ArrowRight", "Enter", "dblclick"]) test(`${action} retires an active pointer drag before applying its new width`, () => {
  const f = fixture(), handle = f.handle("host");
  handle.fire("mousedown", { clientX: 100 }); f.document.fire("mousemove", { clientX: 120 });
  const staleUp = f.document.callbacks("mouseup")[0];
  if (action === "dblclick") handle.fire(action); else f.key(action);
  const width = action === "ArrowRight" ? 472 : 320;
  assert.equal(f.state.historyColumnWidths.host, width);
  assert.equal(f.document.count("mousemove"), 0); assert.equal(f.document.count("mouseup"), 0); assert.equal(f.window.count("blur"), 0);
  assert.equal(handle.classList.contains("active"), false); assert.equal(f.document.body.classList.contains("pane-resizing-x"), false);
  const saves = f.saves.length; f.document.fire("mousemove", { clientX: 400 }); staleUp();
  assert.equal(f.state.historyColumnWidths.host, width); assert.equal(f.saves.length, saves);
});

test("header rebuilding restores only a handle it replaced, by column identity after reorder", () => {
  const f = fixture(), old = f.handle("host"); old.focus(); f.state.historyColumnOrder.reverse();
  f.c.renderHistoryHeader(); assert.notEqual(f.handle("host"), old); assert.equal(f.document.activeElement, f.handle("host"));
  assert.equal(f.handle("host").count("keydown"), 1); f.key("ArrowRight"); assert.equal(f.state.historyColumnWidths.host, 452);
});

test("an initialized settings header rebuild cancels its old drag without saving over the incoming widths", () => {
  const f = fixture(), old = f.handle("host"); old.focus();
  old.fire("mousedown", { clientX: 100 }); f.document.fire("mousemove", { clientX: 120 });
  const oldMove = f.document.callbacks("mousemove")[0], oldUp = f.document.callbacks("mouseup")[0];
  // Model accepted widths in an already-initialized UI, then run its actual
  // header renderer/bindings. No startup, settings request, or pre-init path.
  f.state.historyColumnWidths.host = 600; f.state.historyColumnWidths.path = 666;
  f.c.renderHistoryHeader(); f.c.applyHistoryColumnWidths();
  assert.equal(f.document.count("mousemove"), 0); assert.equal(f.document.count("mouseup"), 0);
  assert.equal(f.window.count("blur"), 0); assert.equal(f.saves.length, 0);
  const replacement = f.handle("host"); assert.equal(f.document.activeElement, replacement);
  f.key("ArrowRight"); assert.equal(f.state.historyColumnWidths.host, 608); assert.equal(f.saves.length, 1);
  f.document.fire("mousemove", { clientX: 500 }); oldMove({ clientX: 500, buttons: 1 }); oldUp();
  assert.equal(f.state.historyColumnWidths.host, 608); assert.equal(f.state.historyColumnWidths.path, 666);
  assert.equal(replacement.getAttribute("aria-valuenow"), "608"); assert.equal(f.saves.length, 1);
  replacement.fire("mousedown", { clientX: 100 });
  oldMove({ clientX: 600, buttons: 1 }); oldUp();
  assert.equal(f.document.count("mousemove"), 1); assert.equal(f.document.body.classList.contains("pane-resizing-x"), true);
  f.document.fire("mousemove", { clientX: 108 }); f.document.fire("mouseup");
  assert.equal(f.state.historyColumnWidths.host, 616); assert.equal(f.saves.length, 2);
});

test("header rebuilding does not steal newer or outside focus or move focus from a sort button to a handle", () => {
  const f = fixture(), outside = target(); f.document.activeElement = outside;
  f.c.renderHistoryHeader(); assert.equal(f.document.activeElement, outside);
  f.handle("host").focus(); f.headers.afterReplace = () => { f.document.activeElement = outside; };
  f.c.renderHistoryHeader(); assert.equal(f.document.activeElement, outside);
  f.headers.afterReplace = null; f.button("host").focus(); f.c.renderHistoryHeader();
  assert.equal(f.document.activeElement, f.document.body);
});

test("native sort siblings and existing drag reorder retain their independent bindings", () => {
  const f = fixture(); f.button("host").fire("click"); assert.deepEqual(f.sorts, ["host"]);
  const widths = { ...f.state.historyColumnWidths };
  const dataTransfer = { setData() {}, effectAllowed: "", dropEffect: "" };
  f.cell("host").fire("dragstart", { dataTransfer });
  f.cell("path").fire("drop", { dataTransfer, clientX: 999 });
  assert.deepEqual(Array.from(f.state.historyColumnOrder), ["path", "host", "index"]);
  assert.deepEqual(f.state.historyColumnWidths, widths); assert.equal(f.counts().rowRenders, 1);
  assert.deepEqual(f.sorts, ["host"]);
});
