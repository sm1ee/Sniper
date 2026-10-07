// Offline column preferences only: extracted callbacks and supplied geometry.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

function eventTarget() {
  const listeners = new Map();
  return {
    addEventListener(type, callback) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type).add(callback);
    },
    removeEventListener(type, callback) { listeners.get(type)?.delete(callback); },
    dispatch(type, values = {}) {
      const event = { type, clientX: 0, button: 0, buttons: 0, preventDefault() {}, stopPropagation() {}, ...values };
      for (const callback of [...(listeners.get(type) || [])]) callback(event);
    },
    count: type => listeners.get(type)?.size || 0,
    callbacks: type => [...(listeners.get(type) || [])],
  };
}

function classList() {
  const set = new Set();
  return { add: value => set.add(value), remove: value => set.delete(value), contains: value => set.has(value) };
}

function fixture(kind) {
  const document = eventTarget(), window = eventTarget();
  const saves = [], writes = [];
  document.body = { classList: classList(), style: { cursor: "progress", userSelect: "text" } };
  document.body.classList.add("existing-body-class");
  const widths = { host: 200, path: 300, status: 100 };
  const state = { historyColumnWidths: widths, wsColumnWidths: widths };
  const table = { style: { setProperty(key, value) { writes.push([key, value]); } } };
  const makeHandle = key => {
    const handle = eventTarget();
    handle.dataset = { columnKey: key, wsColKey: key, findingsCol: key };
    handle.classList = classList();
    handle.classList.add("existing-handle-class");
    handle.closest = () => ({ getBoundingClientRect: () => ({ width: widths[key] }) });
    return handle;
  };
  let handles = ["host", kind === "findings" ? "path" : "status"].map(makeHandle);
  const thead = {};
  Object.defineProperty(thead, "innerHTML", {
    set() { handles = state.historyColumnOrder.map(makeHandle); },
  });
  table.querySelector = () => thead;
  table.querySelectorAll = selector => selector === ".column-resize-handle" ? handles : [];
  document.querySelectorAll = () => handles;
  document.getElementById = () => table;
  const c = loadFunctions([
    "bindHistoryColumnResizers", "bindWsColumnResizers", "bindFindingsColumnResizers",
    "applyHistoryColumnWidths", "applyWsColumnWidths", "applyFindingsColumnWidths", "renderHistoryHeader", "clamp",
  ], {
    document, window, state, findingsColWidths: widths, historyColumnHandles: handles,
    els: { historyTable: table },
    saveHistoryColumnWidths() { saves.push({ ...widths }); },
    scheduleUiSettingsSave() { saves.push({ ...widths }); },
  });
  for (const name of ["HISTORY_COLUMN_RULES", "WS_COLUMN_RULES", "FINDINGS_COL_RULES", "HISTORY_COLUMN_DEFS"]) {
    const match = appSource.match(new RegExp(`^const ${name} = \\{[^]*?^\\};`, "m"));
    assert.ok(match);
    vm.runInContext(`${match[0]}\nglobalThis.${name} = ${name};`, c);
  }
  c[kind === "history" ? "bindHistoryColumnResizers" : kind === "ws" ? "bindWsColumnResizers" : "bindFindingsColumnResizers"]();
  const rules = c[kind === "history" ? "HISTORY_COLUMN_RULES" : kind === "ws" ? "WS_COLUMN_RULES" : "FINDINGS_COL_RULES"];
  return {
    document, window, widths, saves, writes, rules, c,
    get handles() { return handles; },
    down(x = 100, handleIndex = 0, values = {}) { handles[handleIndex].dispatch("mousedown", { clientX: x, buttons: 1, ...values }); },
    move(x, buttons = 1) { document.dispatch("mousemove", { clientX: x, buttons }); },
    up() { document.dispatch("mouseup"); },
    blur() { window.dispatch("blur"); },
    assertClean() {
      assert.equal(document.count("mousemove"), 0);
      assert.equal(document.count("mouseup"), 0);
      assert.equal(window.count("blur"), 0);
      assert.equal(document.body.classList.contains("pane-resizing-x"), false);
      assert.equal(document.body.classList.contains("existing-body-class"), true);
      for (const handle of handles) {
        assert.equal(handle.classList.contains("active"), false);
        assert.equal(handle.classList.contains("existing-handle-class"), true);
      }
      assert.deepEqual(document.body.style, { cursor: "progress", userSelect: "text" });
    },
    assertSaveCount(count) { assert.equal(saves.length, kind === "findings" ? 0 : count); },
  };
}

function runStartupColumnBindings(f) {
  f.c.state.historyColumnOrder = ["host", "status"];
  for (const name of [
    "loadDisplaySettings", "loadHistoryColumnWidths", "loadWorkbenchLayout",
    "bindColumnDragAndDrop", "renderSortHeaders", "bindMessagePaneActivation",
    "bindPaneResizer", "bindWorkbenchStackResizer", "bindWebsocketPaneResizer",
    "bindWebsocketStackResizer", "applyWsColumnWidths", "bindWsColumnResizers",
  ]) f.c[name] = () => {};
  const bindStart = appSource.indexOf("  bindMessagePaneActivation();");
  const bindEnd = appSource.indexOf("  // WS Handshake Request/Response tab toggle", bindStart);
  assert.ok(bindStart >= 0 && bindEnd > bindStart);
  f.c.bindEvents = () => vm.runInContext(appSource.slice(bindStart, bindEnd), f.c);
  const initStart = appSource.indexOf("async function init() {") + "async function init() {".length;
  const initEnd = appSource.indexOf("  resetLayoutTextareas();", initStart);
  assert.ok(initStart > 0 && initEnd > initStart);
  vm.runInContext(appSource.slice(initStart, initEnd), f.c);
}

test("history columns: actual startup ordering binds each rendered handle exactly once", () => {
  const f = fixture("history");
  runStartupColumnBindings(f);
  assert.equal(f.handles[0].count("mousedown"), 1);
  assert.equal(f.handles[0].count("dblclick"), 1);
  f.down(); f.move(125);
  assert.equal(f.document.count("mousemove"), 1);
  assert.equal(f.widths.host, 225);
  f.up(); f.assertClean(); f.assertSaveCount(1);
});

test("history columns: rebuilt headers retain one working owner and one reset callback", () => {
  const f = fixture("history");
  runStartupColumnBindings(f);
  const oldHandle = f.handles[0];
  f.c.renderHistoryHeader();
  assert.notEqual(f.handles[0], oldHandle);
  assert.equal(f.handles[0].count("mousedown"), 1);
  assert.equal(f.handles[0].count("dblclick"), 1);
  f.down(); f.move(125); f.blur();
  assert.equal(f.widths.host, 225);
  f.assertClean(); f.assertSaveCount(1);
  f.handles[0].dispatch("dblclick");
  assert.equal(f.widths.host, f.rules.host.default);
  f.assertSaveCount(2);
});

for (const kind of ["history", "ws", "findings"]) {
  test(`${kind} columns: ordinary drag changes only the chosen width and saves once on mouseup`, () => {
    const f = fixture(kind);
    f.down(); f.move(125);
    assert.equal(f.widths.host, 225);
    assert.equal(f.widths.path, 300);
    assert.equal(f.widths.status, 100);
    assert.ok(f.writes.length > 0);
    f.assertSaveCount(0);
    f.up(); f.assertClean(); f.assertSaveCount(1);
    f.move(300, 0);
    assert.equal(f.widths.host, 225);
  });

  test(`${kind} columns: blur releases listeners and preserves the last pressed width`, () => {
    const f = fixture(kind);
    f.down(); f.move(125); f.blur();
    f.assertClean(); f.assertSaveCount(1);
    f.move(300, 0); f.move(400, 1); f.up(); f.blur();
    assert.equal(f.widths.host, 225);
    f.assertSaveCount(1);
  });

  test(`${kind} columns: unpressed movement finishes without using its coordinates`, () => {
    const f = fixture(kind);
    f.down(); f.move(125); f.move(300, 0);
    assert.equal(f.widths.host, 225);
    f.assertClean(); f.assertSaveCount(1);
    f.up(); f.blur(); f.assertSaveCount(1);
  });

  test(`${kind} columns: repeating the same handle replaces its movement owner`, () => {
    const f = fixture(kind);
    f.down(); f.move(125); f.down(150);
    assert.equal(f.document.count("mousemove"), 1);
    assert.equal(f.document.count("mouseup"), 1);
    assert.equal(f.window.count("blur"), 1);
    f.assertSaveCount(1);
    f.move(160);
    assert.equal(f.widths.host, 235);
    f.up(); f.assertClean(); f.assertSaveCount(2);
  });

  test(`${kind} columns: starting a different handle ends the previous column owner`, () => {
    const f = fixture(kind);
    const secondKey = kind === "findings" ? "path" : "status";
    const initialSecond = f.widths[secondKey];
    f.down(); f.move(125); f.down(150, 1);
    assert.equal(f.document.count("mousemove"), 1);
    assert.equal(f.handles[0].classList.contains("active"), false);
    assert.equal(f.handles[1].classList.contains("active"), true);
    f.move(160);
    assert.equal(f.widths.host, 225);
    assert.equal(f.widths[secondKey], initialSecond + 10);
    f.up(); f.assertClean(); f.assertSaveCount(2);
  });

  test(`${kind} columns: stale completion cannot remove a newer owner's presentation or save twice`, () => {
    const f = fixture(kind);
    f.down(); f.move(125);
    const staleUp = f.document.callbacks("mouseup")[0];
    f.down(150, 1);
    staleUp();
    assert.equal(f.document.body.classList.contains("pane-resizing-x"), true);
    assert.equal(f.handles[1].classList.contains("active"), true);
    assert.equal(f.document.count("mousemove"), 1);
    f.assertSaveCount(1);
    f.up(); staleUp(); f.assertClean(); f.assertSaveCount(2);
  });

  test(`${kind} columns: drag can restart normally after blur or an unpressed move`, () => {
    for (const ending of ["blur", "unpressed"]) {
      const f = fixture(kind);
      f.down(); f.move(125);
      if (ending === "blur") f.blur(); else f.move(400, 0);
      f.down(150); f.move(160); f.up();
      assert.equal(f.widths.host, 235);
      f.assertClean(); f.assertSaveCount(2);
    }
  });

  test(`${kind} columns: undefined and omitted buttons retain legacy movement behavior`, () => {
    const f = fixture(kind);
    f.down();
    f.document.dispatch("mousemove", { clientX: 125, buttons: undefined });
    assert.equal(f.widths.host, 225);
    const move = f.document.callbacks("mousemove")[0];
    move({ clientX: 140 });
    assert.equal(f.widths.host, 240);
    assert.equal(f.document.count("mousemove"), 1);
    f.up(); f.assertClean(); f.assertSaveCount(1);
  });

  test(`${kind} columns: width rounding and minimum/maximum constraints remain unchanged`, () => {
    const f = fixture(kind);
    f.down(); f.move(125.6);
    assert.equal(f.widths.host, 226);
    f.move(-10000);
    assert.equal(f.widths.host, f.rules.host.min);
    f.move(10000);
    assert.equal(f.widths.host, f.rules.host.max);
    f.up(); f.assertClean(); f.assertSaveCount(1);
  });

  test(`${kind} columns: non-primary pressed buttons retain existing drag behavior`, () => {
    const f = fixture(kind);
    f.down(100, 0, { button: 2, buttons: 2 }); f.move(125, 2);
    assert.equal(f.widths.host, 225);
    f.up(); f.assertClean(); f.assertSaveCount(1);
  });

  test(`${kind} columns: finishing without movement retains width and existing completion contract`, () => {
    for (const ending of ["up", "blur", "unpressed"]) {
      const f = fixture(kind);
      f.down();
      if (ending === "unpressed") f.move(400, 0); else f[ending]();
      assert.equal(f.widths.host, 200);
      f.assertClean(); f.assertSaveCount(1);
    }
  });

  test(`${kind} columns: double-click preserves existing default/reset behavior`, () => {
    const f = fixture(kind);
    f.handles[0].dispatch("dblclick");
    assert.equal(f.widths.host, kind === "findings" ? 200 : f.rules.host.default);
    f.assertClean(); f.assertSaveCount(1);
  });
}
