// Synthetic passive keyboard checks: no app bootstrap, browser, API, or records.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture(overrides = {}) {
  const document = { activeElement: null };
  class HTMLElement {
    constructor(tagName = "DIV") {
      this.tagName = tagName;
      this.type = tagName === "INPUT" ? "text" : "";
      this.isContentEditable = false;
      this.isConnected = true;
      this.disabled = false;
      this.tabIndex = 0;
      this.children = [];
      this.attributes = {};
      const classes = new Set();
      this.classList = {
        add: (...values) => values.forEach(value => classes.add(value)),
        remove: (...values) => values.forEach(value => classes.delete(value)),
        contains: value => classes.has(value),
      };
    }
    focus() { document.activeElement = this; }
    setAttribute(name, value) { this.attributes[name] = value; }
    remove() { this.isConnected = false; }
    getClientRects() { return [1]; }
    closest() { return null; }
    querySelectorAll(selector) {
      return this.children.filter(child => selector === ".frame-selected"
        ? child.classList.contains("frame-selected")
        : child.classList.contains("selected"));
    }
  }
  const element = tagName => new HTMLElement(tagName);
  const opener = element(), elsewhere = element();
  const els = {
    displaySettingsModal: element(), filterModal: element(), curlImportModal: element(),
    openDisplaySettingsButton: element("BUTTON"), closeDisplaySettingsButton: element("BUTTON"),
    openFilterSettingsButton: element("BUTTON"), closeFilterModalButton: element("BUTTON"),
    frameDetailResizer: element(), frameDetailPanel: element(), websocketFramesBody: element(),
    wsFrameContextMenu: element(),
  };
  for (const key of ["displaySettingsModal", "filterModal", "curlImportModal", "wsFrameContextMenu"]) {
    els[key].classList.add("hidden");
  }
  const row = element(), bubble = element();
  row.classList.add("frame-selected");
  bubble.classList.add("ws-frame-bubble", "selected");
  els.websocketFramesBody.children = [row, bubble];
  document.activeElement = opener;
  document.querySelector = () => elsewhere;
  const state = {
    activeTool: "proxy", activeProxyTab: "websockets-history",
    wsKeyboardFocus: "frames", selectedFrameIdx: 7,
    ...overrides,
  };
  const calls = [];
  const context = loadFunctions([
    "getActiveModalAction", "isModalVisible", "isEditableTarget", "restoreModalFocus",
    "openDisplaySettingsModal", "closeDisplaySettingsModal", "closeCertificateModal",
    "openFilterModal", "closeFilterModal", "hideFrameDetail", "closeWsFrameContextMenu",
    "closeBrowserMenu", "onBrowserMenuKeydown",
  ], {
    state, els, document, HTMLElement,
    activeConfirmDialog: null, compareLoadGeneration: 0, displaySettingsReturnFocus: null, filterSettingsReturnFocus: null, filterSettingsEditedControls: new Set(),
    displaySettingsPreviewActive: false, displaySettingsEditedControls: new Set(), wsFrameContextMenuTarget: null, browserMenu: null,
    window: { getComputedStyle: () => ({ visibility: "visible" }) },
    hydrateDisplaySettingsForm() {}, applyDisplaySettingsState() {}, renderShortcutReference() {}, selectSettingsTab() {},
    hydrateFilterForm() {}, saveDisplaySettingsFromForm() {}, applyFilterSettings() {}, closeCurlImportModal() {},
    closeCompareModal() {},
    moveHistorySelection: async offset => calls.push(["history", offset]),
    moveWebsocketSelection: async offset => calls.push(["websockets", offset]),
    moveFrameSelection: offset => calls.push(["frames", offset]),
    moveSessionSelection: offset => calls.push(["sessions", offset]),
    fetch() { throw new Error("No requests are allowed in this offline fixture"); },
  });
  const keydownHandlers = [];
  document.addEventListener = (name, handler) => {
    assert.equal(name, "keydown");
    keydownHandlers.push(handler);
    context.keydown = handler;
  };
  const menuStart = appSource.indexOf('document.addEventListener("keydown", (event) => {\n  if (event.key === "Escape" && !els.wsFrameContextMenu');
  const menuEnd = appSource.indexOf("\n});", menuStart) + "\n});".length;
  const initCall = appSource.lastIndexOf("\ninit().catch(");
  const initStart = appSource.indexOf("async function init() {");
  const bindCall = appSource.indexOf("  bindEvents();", initStart);
  const firstAwait = appSource.indexOf("  await ", initStart);
  assert.ok(menuStart !== -1 && menuEnd > menuStart, "Missing passive frame-menu keyboard listener");
  assert.ok(menuEnd < initCall && initStart < bindCall && bindCall < firstAwait,
    "The top-level frame-menu listener must register before init invokes bindEvents");
  // Match source registration order without running init or binding the app.
  vm.runInContext(appSource.slice(menuStart, menuEnd), context);
  const start = appSource.indexOf('  document.addEventListener("keydown", (event) => {\n    const activeModalAction');
  const end = appSource.indexOf("    // Arrow keys in WS Replay", start);
  assert.ok(start !== -1 && end > start, "Missing passive document keyboard section");
  const browserInstallCall = appSource.indexOf("  installBrowserMenuDismissal();");
  const browserKeyListener = '  document.addEventListener("keydown", onBrowserMenuKeydown);';
  assert.ok(browserInstallCall > appSource.indexOf("function bindEvents() {") && browserInstallCall < start,
    "Browser chooser dismissal must register before the main keyboard callback");
  assert.ok(appSource.includes(browserKeyListener), "Missing browser chooser keyboard registration");
  vm.runInContext(browserKeyListener, context);
  vm.runInContext(appSource.slice(start, end) + "  });", context);
  function key(options = {}) {
    const event = {
      key: "Escape", target: document.activeElement,
      metaKey: false, ctrlKey: false, altKey: false, shiftKey: false,
      defaultPrevented: false,
      preventDefault() { this.defaultPrevented = true; },
      ...options,
    };
    for (const handler of keydownHandlers) handler(event);
    return event;
  }
  return { state, context, els, document, opener, elsewhere, element, row, bubble, calls, key };
}

function assertFrameUnchanged(f) {
  assert.equal(f.state.selectedFrameIdx, 7);
  assert.equal(f.els.frameDetailPanel.classList.contains("hidden"), false);
  assert.equal(f.row.classList.contains("frame-selected"), true);
  assert.equal(f.bubble.classList.contains("selected"), true);
  assert.deepEqual(f.calls, []);
}

function assertFrameClosed(f) {
  assert.equal(f.state.wsKeyboardFocus, "sessions");
  assert.equal(f.state.selectedFrameIdx, null);
  assert.equal(f.els.frameDetailPanel.classList.contains("hidden"), true);
  assert.equal(f.els.frameDetailResizer.classList.contains("hidden"), true);
  assert.equal(f.row.classList.contains("frame-selected"), false);
  assert.equal(f.bubble.classList.contains("selected"), false);
  assert.deepEqual(f.calls, []);
}

test("Escape leaves passive WebSocket frame detail and returns keyboard navigation to sessions", () => {
  const f = fixture();
  const event = f.key();
  assertFrameClosed(f);
  assert.equal(event.defaultPrevented, true);
  assert.equal(f.document.activeElement, f.opener, "hidden modal cleanup must not steal focus");
});

test("another Escape after leaving frame detail does not navigate a row or steal focus", () => {
  const f = fixture();
  f.key();
  assertFrameClosed(f);
  f.elsewhere.focus();
  const event = f.key();
  assertFrameClosed(f);
  assert.equal(event.defaultPrevented, false);
  assert.equal(f.document.activeElement, f.elsewhere);
});

test("Escape dismisses the open frame context menu before dismissing the passive frame preview", () => {
  const f = fixture();
  f.els.wsFrameContextMenu.classList.remove("hidden");
  f.context.wsFrameContextMenuTarget = { frameIdx: 7 };
  const first = f.key();
  assert.equal(f.els.wsFrameContextMenu.classList.contains("hidden"), true);
  assert.equal(f.context.wsFrameContextMenuTarget, null);
  assert.equal(first.defaultPrevented, true);
  assertFrameUnchanged(f);
  assert.equal(f.state.wsKeyboardFocus, "frames");
  assert.equal(f.document.activeElement, f.opener);
  const second = f.key();
  assertFrameClosed(f);
  assert.equal(second.defaultPrevented, true);
});

test("Escape from a browser chooser link closes only that popup and restores its anchor focus", () => {
  const f = fixture();
  const anchor = f.element("BUTTON"), menu = f.element(), link = f.element("A");
  f.context.browserMenu = { anchor, element: menu };
  link.focus();
  const event = f.key();
  assert.equal(f.context.browserMenu, null);
  assert.equal(menu.isConnected, false);
  assert.equal(anchor.attributes["aria-expanded"], "false");
  assert.equal(f.document.activeElement, anchor);
  assert.equal(event.defaultPrevented, true);
  assertFrameUnchanged(f);
  assert.equal(f.state.wsKeyboardFocus, "frames");
  f.opener.focus();
  f.key();
  assertFrameClosed(f);
});

for (const tagName of ["INPUT", "TEXTAREA", "SELECT", "OPTION", "BUTTON", "contenteditable"]) {
  test(`Escape on a focused ${tagName} preserves passive frame selection`, () => {
    const f = fixture();
    const control = f.element(tagName === "contenteditable" ? "DIV" : tagName);
    control.isContentEditable = tagName === "contenteditable";
    control.focus();
    const event = f.key();
    assertFrameUnchanged(f);
    assert.equal(f.state.wsKeyboardFocus, "frames");
    assert.equal(event.defaultPrevented, false);
    assert.equal(f.document.activeElement, control);
  });
}

for (const modifier of ["metaKey", "ctrlKey", "altKey", "shiftKey"]) {
  test(`${modifier}+Escape preserves passive frame selection`, () => {
    const f = fixture();
    const event = f.key({ [modifier]: true });
    assertFrameUnchanged(f);
    assert.equal(f.state.wsKeyboardFocus, "frames");
    assert.equal(event.defaultPrevented, false);
  });
}

for (const flag of ["defaultPrevented", "isComposing"]) {
  test(`${flag} Escape preserves passive frame selection`, () => {
    const f = fixture();
    f.key({ [flag]: true });
    assertFrameUnchanged(f);
    assert.equal(f.state.wsKeyboardFocus, "frames");
    assert.equal(f.document.activeElement, f.opener);
  });
}

for (const modal of ["display", "filter"]) {
  test(`first Escape closes ${modal} settings and restores focus; next Escape leaves frame detail`, () => {
    const f = fixture();
    const display = modal === "display";
    f.context[display ? "openDisplaySettingsModal" : "openFilterModal"]();
    const node = f.els[display ? "displaySettingsModal" : "filterModal"];
    const first = f.key();
    assert.equal(node.classList.contains("hidden"), true);
    assert.equal(f.document.activeElement, f.opener);
    assert.equal(first.defaultPrevented, true);
    assertFrameUnchanged(f);
    assert.equal(f.state.wsKeyboardFocus, "frames");
    const second = f.key();
    assertFrameClosed(f);
    assert.equal(second.defaultPrevented, true);
    assert.equal(f.document.activeElement, f.opener);
  });
}

test("Escape with session-level keyboard focus does not dismiss an existing frame preview", () => {
  const f = fixture({ wsKeyboardFocus: "sessions" });
  const event = f.key();
  assertFrameUnchanged(f);
  assert.equal(f.state.wsKeyboardFocus, "sessions");
  assert.equal(event.defaultPrevented, false);
});

for (const [label, state] of [
  ["HTTP history", { activeProxyTab: "http-history" }],
  ["Dashboard", { activeTool: "dashboard" }],
  ["event log", { activeTool: "logger" }],
]) {
  test(`Escape in ${label} leaves hidden WebSocket frame selection alone`, () => {
    const f = fixture(state);
    const event = f.key();
    assertFrameUnchanged(f);
    assert.equal(f.state.wsKeyboardFocus, "frames");
    assert.equal(event.defaultPrevented, false);
    assert.equal(f.document.activeElement, f.opener);
  });
}

// Exercise only the two explicit Close bindings, never app initialization.
function paneCloseFixture() {
  const document = { activeElement: null };
  function element(tabIndex = 0, explicitTabindex = null) {
    const classes = new Set();
    return {
      isConnected: true, disabled: false, tabIndex, visible: true, visibility: "visible", children: [], dataset: {},
      classList: { add: value => classes.add(value), remove: value => classes.delete(value), contains: value => classes.has(value) },
      contains(target) { return this === target || this.children.includes(target); },
      getAttribute: name => name === "tabindex" ? explicitTabindex : null,
      getClientRects() { return this.visible ? [1] : []; },
      focus(options) { document.activeElement = this; this.focusOptions = options; },
      querySelectorAll() { return []; },
      addEventListener(type, handler) { assert.equal(type, "click"); this.click = handler; },
    };
  }
  const inspector = element(), closeInspectorButton = element(), inspectorChild = element();
  inspector.children = [closeInspectorButton, inspectorChild];
  closeInspectorButton.closest = selector => { assert.equal(selector, ".inspector-main"); return inspector; };
  const frameDetailPanel = element(), frameDetailClose = element(), frameChild = element();
  frameDetailPanel.children = [frameDetailClose, frameChild];
  const frames = element(-1, "-1"), fallback = element(), outside = element();
  const railTabs = [element(), element()];
  railTabs[0].dataset.inspectorTab = "inspector";
  railTabs[1].dataset.inspectorTab = "notes";
  const els = { closeInspectorButton, frameDetailPanel, frameDetailClose, frameDetailResizer: element(), websocketFramesBody: element() };
  const state = { activeInspectorTab: "inspector", inspectorCollapsed: false, selectedFrameIdx: 7, wsKeyboardFocus: "frames" };
  document.getElementById = id => { assert.equal(id, "websocketFramesColumn"); return frames; };
  document.querySelector = selector => { assert.equal(selector, ".main-tab.active"); return fallback; };
  const context = loadFunctions(["focusPaneCloseTarget", "restoreModalFocus", "hideFrameDetail"], {
    document, els, state, railTabs,
    window: { getComputedStyle: target => ({ visibility: target.visibility }) },
    renderInspectorPanels() { inspector.visible = false; },
  });
  for (const marker of ['  els.closeInspectorButton?.addEventListener("click", () => {', '  els.frameDetailClose.addEventListener("click", () => {']) {
    const start = appSource.indexOf(marker);
    const end = appSource.indexOf("\n  });", start) + "\n  });".length;
    assert.ok(start >= 0 && end > start);
    vm.runInContext(appSource.slice(start, end), context);
  }
  return { document, context, els, state, railTabs, inspector, inspectorChild, frameChild, frames, fallback, outside, element };
}

for (const tab of ["inspector", "notes"]) {
  for (const origin of ["button", "descendant", "outside"]) {
    test(`explicit Inspector Close returns ${origin} focus only when owned, to active ${tab} rail`, () => {
      const f = paneCloseFixture(); f.state.activeInspectorTab = tab;
      const before = origin === "button" ? f.els.closeInspectorButton : origin === "descendant" ? f.inspectorChild : f.outside;
      before.focus(); f.els.closeInspectorButton.click();
      assert.equal(f.state.inspectorCollapsed, true);
      const expected = origin === "outside" ? before : f.railTabs.find(item => item.dataset.inspectorTab === tab);
      assert.equal(f.document.activeElement, expected);
      if (origin !== "outside") assert.equal(expected.focusOptions.preventScroll, true);
    });
  }
}
for (const origin of ["button", "descendant", "outside"]) {
  test(`explicit frame Close restores ${origin} focus only when owned without changing navigation mode`, () => {
    const f = paneCloseFixture();
    const before = origin === "button" ? f.els.frameDetailClose : origin === "descendant" ? f.frameChild : f.outside;
    before.focus(); f.els.frameDetailClose.click();
    assert.equal(f.document.activeElement, origin === "outside" ? before : f.frames);
    assert.equal(f.els.frameDetailPanel.classList.contains("hidden"), true);
    assert.equal(f.state.selectedFrameIdx, null);
    assert.equal(f.state.wsKeyboardFocus, "frames");
    if (origin !== "outside") assert.equal(f.frames.focusOptions.preventScroll, true);
  });
}
for (const invalid of ["disconnected", "disabled", "no-rects", "hidden", "implicit-negative"]) {
  test(`pane Close rejects ${invalid} return target and uses existing fallback`, () => {
    const f = paneCloseFixture();
    if (invalid === "disconnected") f.frames.isConnected = false;
    if (invalid === "disabled") f.frames.disabled = true;
    if (invalid === "no-rects") f.frames.visible = false;
    if (invalid === "hidden") f.frames.visibility = "hidden";
    if (invalid === "implicit-negative") f.frames.getAttribute = () => null;
    f.frameChild.focus(); f.els.frameDetailClose.click();
    assert.equal(f.document.activeElement, f.fallback);
    assert.equal(f.fallback.focusOptions.preventScroll, true);
  });
}
test("generic frame hiding never restores focus, including a focused detail descendant", () => {
  const f = paneCloseFixture(); f.frameChild.focus(); f.context.hideFrameDetail();
  assert.equal(f.document.activeElement, f.frameChild);
  assert.equal(f.state.wsKeyboardFocus, "frames");
});
test("pane Close captures active rail before rendering changes active Inspector state", () => {
  const f = paneCloseFixture(); f.state.activeInspectorTab = "notes";
  f.context.renderInspectorPanels = () => { f.state.activeInspectorTab = "inspector"; };
  f.inspectorChild.focus(); f.els.closeInspectorButton.click();
  assert.equal(f.document.activeElement, f.railTabs[1]);
});
test("explicit pane Close controls are named and Frames is programmatic-only with inset focus styling", () => {
  const fs = require("node:fs"), path = require("node:path");
  const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
  const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");
  assert.match(html, /<button[^>]*id="closeInspectorButton"[^>]*aria-label="Close inspector"/);
  assert.match(html, /<button[^>]*id="frameDetailClose"[^>]*aria-label="Close frame detail"/);
  assert.match(html, /<section[^>]*id="websocketFramesColumn"[^>]*tabindex="-1"[^>]*aria-label="WebSocket frames"/);
  assert.match(css, /#websocketFramesColumn:focus-visible\s*\{[^}]*outline: 2px solid var\(--point\);[^}]*outline-offset: -2px;/);
});
