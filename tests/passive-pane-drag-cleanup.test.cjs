// Extracted local pane handlers with synthetic mouse events; no browser or I/O.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function eventTarget() {
  const listeners = new Map();
  return {
    addEventListener(type, callback) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type).add(callback);
    },
    removeEventListener(type, callback) { listeners.get(type)?.delete(callback); },
    dispatch(type, values = {}) {
      const event = { type, clientY: 0, button: 0, buttons: 0, preventDefault() {}, ...values };
      for (const callback of [...(listeners.get(type) || [])]) callback(event);
    },
    count: type => listeners.get(type)?.size || 0,
  };
}

function classList() {
  const set = new Set();
  return { add: value => set.add(value), remove: value => set.delete(value), contains: value => set.has(value) };
}

function fixture(kind, options = {}) {
  const document = eventTarget(), window = eventTarget(), handle = eventTarget();
  document.body = { classList: classList(), style: { cursor: options.cursor || "", userSelect: options.userSelect || "" } };
  handle.classList = classList();
  let detailHeight = 240, tableHeight = 360;
  const writes = [], normalized = [], resets = [];
  const detailStyle = {};
  Object.defineProperty(detailStyle, "flex", {
    get: () => `0 0 ${detailHeight}px`,
    set(value) { detailHeight = Number(value.match(/([\d.]+)px$/)[1]); writes.push(detailHeight); },
  });
  const tableStyle = {};
  Object.defineProperty(tableStyle, "flex", {
    set(value) { tableHeight = Number(value.match(/([\d.]+)px$/)[1]); },
  });
  const detail = { style: detailStyle, getBoundingClientRect: () => ({ height: detailHeight }) };
  const table = { style: tableStyle, getBoundingClientRect: () => ({ height: tableHeight }) };
  handle.parentElement = { getBoundingClientRect: () => ({ height: 600 }) };
  const els = {
    frameDetailResizer: handle, frameDetailPanel: detail,
    findingsDetailResizer: handle, findingsDetailPanel: detail, findingsPanel: { querySelector: () => table },
    trafficRegion: table, lowerWorkbench: detail, historyWorkbenchResizer: handle,
  };
  const c = loadFunctions(["initFrameDetailResizer", "initFindingsResizer", "bindWorkbenchStackResizer", "clamp"], {
    els, document, window, WORKBENCH_STACK_MIN_HEIGHTS: { history: 140, messages: 180 },
    applyWorkbenchStackHeight(value) { detailHeight = value; tableHeight = 600 - value; writes.push(value); },
    normalizeWorkbenchStackHeight(options) { normalized.push(options.persist); },
    resetWorkbenchStackHeight() { resets.push(true); },
  });
  if (kind === "frame") c.initFrameDetailResizer();
  else if (kind === "findings") c.initFindingsResizer();
  else c.bindWorkbenchStackResizer(handle);
  return {
    document, window, handle, writes, normalized, resets,
    get height() { return detailHeight; },
    down(y = 300) { handle.dispatch("mousedown", { clientY: y, buttons: 1 }); },
    move(y, buttons = 1) { document.dispatch("mousemove", { clientY: y, buttons }); },
    up() { document.dispatch("mouseup"); },
    blur() { window.dispatch("blur"); },
    assertClean() {
      assert.equal(document.count("mousemove"), 0);
      assert.equal(document.count("mouseup"), 0);
      assert.equal(window.count("blur"), 0);
      assert.equal(document.body.classList.contains("pane-resizing-y"), false);
      assert.equal(handle.classList.contains("active"), false);
      assert.equal(document.body.style.cursor, options.cursor || "");
      assert.equal(document.body.style.userSelect, options.userSelect || "");
    },
  };
}

for (const kind of ["workbench", "findings", "frame"]) {
  test(`${kind}: unpressed hover before and after a drag does not resize`, () => {
    const f = fixture(kind);
    f.move(100, 0);
    assert.deepEqual(f.writes, []);
    f.down(); f.move(250); f.up();
    assert.deepEqual(f.writes, [290]);
    f.move(100, 0);
    assert.deepEqual(f.writes, [290]);
    f.assertClean();
  });

  test(`${kind}: ordinary mouseup cleans local listeners and resizing presentation`, () => {
    const f = fixture(kind);
    f.down(); f.move(250);
    assert.equal(f.height, 290);
    f.up(); f.assertClean();
    f.up(); f.blur();
    assert.deepEqual(f.normalized, kind === "workbench" ? [true] : []);
  });

  test(`${kind}: blur ends a drag and prevents subsequent hover or pressed movement`, () => {
    const f = fixture(kind);
    f.down(); f.move(250); f.blur();
    f.assertClean();
    f.move(200, 0); f.move(100, 1); f.up(); f.blur();
    assert.deepEqual(f.writes, [290]);
    assert.deepEqual(f.normalized, kind === "workbench" ? [true] : []);
  });

  test(`${kind}: an unpressed move ends a drag without applying its coordinates`, () => {
    const f = fixture(kind);
    f.down(); f.move(250); f.move(200, 0);
    assert.deepEqual(f.writes, [290]);
    f.assertClean();
    f.up(); f.blur();
    assert.deepEqual(f.normalized, kind === "workbench" ? [true] : []);
  });

  test(`${kind}: repeated starts keep only one current movement owner`, () => {
    const f = fixture(kind);
    f.down(); f.move(250);
    f.down(400);
    assert.equal(f.document.count("mousemove"), 1);
    assert.equal(f.document.count("mouseup"), 1);
    assert.equal(f.window.count("blur"), 1);
    f.move(350);
    assert.deepEqual(f.writes, [290, 340]);
    f.up(); f.assertClean();
    assert.deepEqual(f.normalized, kind === "workbench" ? [true, true] : []);
  });

  test(`${kind}: a new drag works normally after blur cleanup`, () => {
    const f = fixture(kind);
    f.down(); f.move(250); f.blur();
    f.down(400); f.move(350); f.up();
    assert.deepEqual(f.writes, [290, 340]);
    f.assertClean();
    assert.deepEqual(f.normalized, kind === "workbench" ? [true, true] : []);
  });

  test(`${kind}: existing minimum and maximum height constraints remain unchanged`, () => {
    const f = fixture(kind);
    f.down(); f.move(10000); f.move(-10000); f.up();
    const bounds = kind === "workbench" ? [180, 460] : kind === "findings" ? [120, 540] : [120, 480];
    assert.deepEqual(f.writes, bounds);
    f.assertClean();
  });

  test(`${kind}: termination restores preexisting inline cursor and selection styles`, () => {
    for (const ending of ["up", "blur", "unpressed", "repeated"]) {
      const f = fixture(kind, { cursor: "progress", userSelect: "text" });
      f.down(); f.move(250);
      if (ending === "repeated") { f.down(400); f.move(350); f.up(); }
      else if (ending === "unpressed") f.move(200, 0);
      else f[ending]();
      f.assertClean();
    }
  });
}

test("workbench double-click retains its existing reset callback", () => {
  const f = fixture("workbench");
  f.handle.dispatch("dblclick");
  assert.deepEqual(f.resets, [true]);
  assert.deepEqual(f.writes, []);
  f.assertClean();
});
