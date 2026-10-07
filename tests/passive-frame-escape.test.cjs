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
    activeConfirmDialog: null, displaySettingsReturnFocus: null, filterSettingsReturnFocus: null, filterSettingsEditedControls: new Set(),
    displaySettingsPreviewActive: false, wsFrameContextMenuTarget: null, browserMenu: null,
    window: { getComputedStyle: () => ({ visibility: "visible" }) },
    hydrateDisplaySettingsForm() {}, applyDisplaySettingsState() {}, renderShortcutReference() {}, selectSettingsTab() {},
    hydrateFilterForm() {}, saveDisplaySettingsFromForm() {}, applyFilterSettings() {}, closeCurlImportModal() {},
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
