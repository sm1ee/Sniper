// Passive presentation only: extracted functions and synthetic style/bounds.
// The application, browser, network, and server never start. The synthetic
// measurements reflect the CSS's fixed left/right tracks and ws-swapped order;
// they do not claim to test a browser's grid layout implementation.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture({ swapped = false, hidden = false, narrow = false,
  leftWidth = 600, totalWidth = 990, savedWidth = leftWidth } = {}) {
  const properties = new Map([["--websocket-left-pane-width", `${leftWidth}px`]]);
  const writes = [];
  const handleListeners = new Map();
  const documentListeners = new Map();
  let saves = 0;
  const style = {
    getPropertyValue(key) { return properties.get(key) || ""; },
    setProperty(key, value) { properties.set(key, value); writes.push([key, value]); },
    removeProperty(key) { properties.delete(key); },
  };
  const classList = {
    contains(name) { return name === "ws-swapped" && swapped; },
    add() {}, remove() {},
  };
  const currentLeftWidth = () => Number.parseFloat(properties.get("--websocket-left-pane-width"));
  const measure = (left) => ({ width: hidden ? 0 : left ? currentLeftWidth() : totalWidth - currentLeftWidth() });
  const els = {
    websocketWorkbench: { style, classList },
    websocketHandshakeColumn: { getBoundingClientRect() { return measure(!swapped); } },
    websocketFramesColumn: { getBoundingClientRect() { return measure(swapped); } },
  };
  const state = { websocketPaneWidth: savedWidth };
  const context = loadFunctions([
    "clamp", "getWebsocketWorkbenchWidths", "applyWebsocketPaneWidth",
    "applySavedWebsocketPaneWidth", "normalizeWebsocketPaneWidth",
    "resetWebsocketPaneWidth", "bindWebsocketPaneResizer",
  ], {
    els, state,
    // These are horizontal track limits in the existing UI. The separate 220
    // constant is a vertical workbench-height minimum, not a frame-pane width.
    WEBSOCKET_WORKBENCH_MIN_WIDTHS: { handshake: 360, frames: 320 },
    WEBSOCKET_WORKBENCH_BREAKPOINT: "(max-width: 980px)",
    window: { matchMedia() { return { matches: narrow }; } },
    document: {
      body: { classList },
      addEventListener(name, listener) { documentListeners.set(name, listener); },
      removeEventListener(name) { documentListeners.delete(name); },
    },
    scheduleUiSettingsSave() { saves += 1; },
  });
  context.bindWebsocketPaneResizer({
    classList,
    addEventListener(name, listener) { handleListeners.set(name, listener); },
  });
  return {
    context, properties, writes, state, currentLeftWidth,
    get saves() { return saves; },
    drag(delta) {
      handleListeners.get("mousedown")({ clientX: 600, preventDefault() {} });
      documentListeners.get("mousemove")({ clientX: 600 + delta });
      const duringMove = currentLeftWidth();
      documentListeners.get("mouseup")();
      return duringMove;
    },
  };
}

for (const swapped of [false, true]) {
  const orientation = swapped ? "swapped" : "normal";

  test(`${orientation}: measured bounds retain pane identity while summing both tracks`, () => {
    const f = fixture({ swapped });
    const widths = f.context.getWebsocketWorkbenchWidths();
    assert.equal(widths.total, 990);
    assert.equal(widths.handshake, swapped ? 390 : 600);
    assert.equal(widths.frames, swapped ? 600 : 390);
  });

  test(`${orientation}: repeated passive normalization preserves the physical left track`, () => {
    const f = fixture({ swapped });
    f.context.normalizeWebsocketPaneWidth();
    assert.equal(f.currentLeftWidth(), 600);
    f.context.normalizeWebsocketPaneWidth();
    assert.equal(f.currentLeftWidth(), 600);
    assert.equal(f.state.websocketPaneWidth, 600);
    assert.equal(f.saves, 0);
  });

  test(`${orientation}: an explicit state update records the physical left width`, () => {
    const f = fixture({ swapped, savedWidth: 500 });
    f.context.normalizeWebsocketPaneWidth({ updateState: true });
    assert.equal(f.currentLeftWidth(), 600);
    assert.equal(f.state.websocketPaneWidth, 600);
    assert.equal(f.saves, 0);
  });

  test(`${orientation}: passive normalization does not replace the saved width`, () => {
    const f = fixture({ swapped, savedWidth: 500 });
    f.context.normalizeWebsocketPaneWidth({ updateState: false });
    assert.equal(f.state.websocketPaneWidth, 500);
    assert.equal(f.saves, 0);
  });

  test(`${orientation}: restoring a saved left width remains stable after normalization`, () => {
    const f = fixture({ swapped, savedWidth: 540 });
    f.context.applySavedWebsocketPaneWidth();
    assert.equal(f.currentLeftWidth(), 540);
    f.context.normalizeWebsocketPaneWidth();
    assert.equal(f.currentLeftWidth(), 540);
    assert.equal(f.state.websocketPaneWidth, 540);
  });

  test(`${orientation}: saved left width obeys existing physical track minima without overwriting preferences`, () => {
    const f = fixture({ swapped, savedWidth: 100 });
    f.context.applySavedWebsocketPaneWidth();
    assert.equal(f.currentLeftWidth(), 360);
    assert.equal(f.state.websocketPaneWidth, 100);
    f.state.websocketPaneWidth = 900;
    f.context.applySavedWebsocketPaneWidth();
    assert.equal(f.currentLeftWidth(), 670);
    assert.equal(f.state.websocketPaneWidth, 900);
  });

  test(`${orientation}: hidden zero measurements preserve styles and saved preferences`, () => {
    const f = fixture({ swapped, hidden: true, savedWidth: 540 });
    f.context.normalizeWebsocketPaneWidth({ updateState: true });
    f.context.applySavedWebsocketPaneWidth();
    assert.equal(f.currentLeftWidth(), 600);
    assert.equal(f.state.websocketPaneWidth, 540);
    assert.equal(f.writes.length, 0);
  });

  test(`${orientation}: narrow breakpoint removes only the applied width`, () => {
    const f = fixture({ swapped, narrow: true, savedWidth: 540 });
    f.context.normalizeWebsocketPaneWidth({ updateState: true });
    f.context.applySavedWebsocketPaneWidth();
    assert.equal(f.properties.has("--websocket-left-pane-width"), false);
    assert.equal(f.state.websocketPaneWidth, 540);
    assert.equal(f.writes.length, 0);
  });

  test(`${orientation}: a rightward divider drag grows the physical left track`, () => {
    const f = fixture({ swapped });
    assert.equal(f.drag(50), 650);
    assert.equal(f.currentLeftWidth(), 650);
    assert.equal(f.state.websocketPaneWidth, 650);
    assert.equal(f.saves, 1);
  });
}
