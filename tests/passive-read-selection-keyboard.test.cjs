// Read-selection ownership only. Extract production keyboard registrations with
// synthetic DOM/state and inert selection/render/persistence callbacks. Never
// bootstrap the app or invoke browser, clipboard, scanner, API, or replay actions.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const surfaces = ["http-history", "ws-sessions", "ws-frames", "findings", "ws-replay"];
const scannerModalBlock = `    // Skip if scanner settings modal is open
    if (els.scannerSettingsBackdrop && !els.scannerSettingsBackdrop.classList.contains("hidden")) {
      if (e.key === "Escape") { e.preventDefault(); closeScannerSettings(); }
      if (e.key === "Enter" && !e.target.matches("input, textarea, select")) { e.preventDefault(); saveScannerSettingsFromModal(); }
      return;
    }
`;

function keyboardRegistrations() {
  const mainStart = appSource.indexOf('  document.addEventListener("keydown", (event) => {\n    const activeModalAction');
  // Stop at the end of passive frame selection, before Replay execution shortcuts.
  const mainEnd = appSource.indexOf("    // Ctrl+Tab / Ctrl+Shift+Tab: cycle through Replay tabs", mainStart);
  const findingsStart = appSource.indexOf('  document.addEventListener("keydown", (e) => {\n    // Skip if scanner settings modal is open');
  const findingsEnd = appSource.indexOf("\n\n  // Findings detail search", findingsStart);
  const browser = '  document.addEventListener("keydown", onBrowserMenuKeydown);';
  const bindStart = appSource.indexOf("function bindEvents() {");
  const browserInstall = appSource.indexOf("  installBrowserMenuDismissal();", bindStart);
  const findingsInstall = appSource.indexOf("  bindFindingsEvents();", bindStart);
  assert.ok(mainStart > bindStart && mainEnd > mainStart, "Missing production main read-selection registration");
  assert.ok(findingsStart >= 0 && findingsEnd > findingsStart, "Missing production Findings registration");
  assert.ok(appSource.includes(browser), "Missing production chooser registration");
  assert.ok(browserInstall > bindStart && browserInstall < findingsInstall && findingsInstall < mainStart,
    "Chooser must register before Findings and main keyboard handlers");
  return { browser, findings: appSource.slice(findingsStart, findingsEnd),
    main: appSource.slice(mainStart, mainEnd) + "  });" };
}

function fixture(surface) {
  const document = { activeElement: null };
  class HTMLElement {
    constructor(tagName = "DIV") {
      this.tagName = tagName;
      this.isContentEditable = false;
      this.disabled = false;
      this.type = tagName === "INPUT" ? "text" : "";
      this.classes = new Set();
      this.classList = { contains: name => this.classes.has(name) };
    }
    closest() { return this.editableParent || null; }
    matches(selector) { return selector.split(", ").includes(this.tagName.toLowerCase()); }
    focus() { document.activeElement = this; }
    setAttribute() {}
  }
  const node = tagName => new HTMLElement(tagName);
  const state = {
    activeTool: surface === "ws-replay" ? "replay" : "proxy",
    activeProxyTab: surface.startsWith("ws-") ? "websockets-history" : surface,
    wsKeyboardFocus: surface === "ws-frames" ? "frames" : "sessions",
    activeReplayTabId: "synthetic-ws-tab",
    replayTabs: [{ id: "synthetic-ws-tab", type: "websocket", wsSelectedFrameIndex: 20, wsFrameWindowStart: 0 }],
  };
  const frames = [10, 20, 30].map(index => ({ index }));
  const selected = [], rendered = [], persisted = [], scrolled = [], closed = [];
  const els = {
    wsFrameList: { querySelector(selector) {
      assert.equal(selector, `[data-frame-index="${state.replayTabs[0].wsSelectedFrameIndex}"]`);
      return { scrollIntoView(options) {
        assert.equal(options.block, "nearest");
        scrolled.push(state.replayTabs[0].wsSelectedFrameIndex);
      } };
    } },
  };
  for (const name of ["displaySettingsModal", "filterModal", "curlImportModal", "scannerSettingsBackdrop"]) {
    els[name] = node();
    els[name].classes.add("hidden");
  }
  const anchor = node("BUTTON"), install = node("A"), button = node("BUTTON"), input = node("INPUT");
  const controls = [install, button, input];
  const menu = {
    contains: target => controls.includes(target),
    querySelectorAll(selector) {
      assert.equal(selector, "button:not(:disabled), input, a[href]");
      return controls.filter(control => control.tagName !== "BUTTON" || !control.disabled);
    },
    remove() {},
  };
  const select = name => direction => { selected.push([name, direction]); return Promise.resolve(); };
  const forbidden = name => () => assert.fail(`Read selection must not invoke ${name}`);
  const context = loadFunctions([
    "isEditableTarget", "isModalVisible", "getActiveModalAction", "onBrowserMenuKeydown", "closeBrowserMenu",
  ], {
    state, els, document, HTMLElement, browserMenu: null, activeConfirmDialog: null,
    moveHistorySelection: select("http-history"), moveWebsocketSelection: select("ws-sessions"),
    moveFrameSelection: select("ws-frames"), findingsArrowNav: select("findings"),
    moveSessionSelection: forbidden("Dashboard selection"),
    getWsReplayFrames: tab => tab ? frames : [],
    wsReplayRenderedFrameWindow: inputFrames => ({ frames: inputFrames }),
    scheduleWorkspaceStateSave: () => persisted.push(state.replayTabs[0].wsSelectedFrameIndex),
    renderWsFrameList: () => rendered.push(state.replayTabs[0].wsSelectedFrameIndex),
    hideFrameDetail: () => closed.push("frame-detail"),
    closeDisplaySettingsModal: () => closed.push("settings"),
    closeCertificateModal: () => closed.push("certificate"),
    closeFilterModal: () => closed.push("filter"),
    closeCurlImportModal: forbidden("import close"),
    saveDisplaySettingsFromForm: forbidden("settings save"),
    applyFilterSettings: forbidden("filter apply"),
    closeScannerSettings: forbidden("scanner settings close"),
    saveScannerSettingsFromModal: forbidden("scanner settings save"),
    forwardSelectedIntercept: forbidden("intercept forward"),
    dropSelectedIntercept: forbidden("intercept drop"),
    copyTextToClipboard: forbidden("clipboard"),
    fetch: forbidden("API requests"),
  });
  const handlers = [];
  document.addEventListener = (type, handler) => {
    assert.equal(type, "keydown");
    handlers.push(handler);
  };
  const registrations = keyboardRegistrations();
  for (const name of ["browser", "findings", "main"]) vm.runInContext(registrations[name], context);
  function key(key, target = node(), options = {}) {
    document.activeElement = target;
    const event = {
      key, target, metaKey: false, ctrlKey: false, altKey: false, shiftKey: false,
      defaultPrevented: false,
      preventDefault() { this.defaultPrevented = true; },
      ...options,
    };
    for (const handler of handlers) handler(event);
    return event;
  }
  return { context, state, els, node, document, anchor, install, button, input, controls,
    selected, rendered, persisted, scrolled, closed, key,
    openMenu() { context.browserMenu = { anchor, element: menu }; } };
}

function assertUnchanged(f) {
  assert.deepEqual(f.selected, []);
  assert.equal(f.state.replayTabs[0].wsSelectedFrameIndex, 20);
  assert.deepEqual(f.rendered, []);
  assert.deepEqual(f.persisted, []);
  assert.deepEqual(f.scrolled, []);
}

for (const surface of surfaces) {
  for (const key of ["ArrowUp", "ArrowDown"]) {
    test(`${surface}: consumed chooser ${key} stays in the chooser`, () => {
      const f = fixture(surface);
      f.openMenu();
      const event = f.key(key, f.install);
      assert.equal(event.defaultPrevented, true);
      assert.equal(event.target, f.install, "The original Install target survives the focus move");
      assert.equal(f.document.activeElement, key === "ArrowDown" ? f.button : f.input);
      assertUnchanged(f);
    });

    test(`${surface}: ${key} outside an open chooser dispatches selection once`, () => {
      const f = fixture(surface);
      f.openMenu();
      assert.equal(f.key(key).defaultPrevented, true);
      if (surface === "ws-replay") {
        const expected = key === "ArrowDown" ? 30 : 10;
        assert.deepEqual(f.selected, []);
        assert.equal(f.state.replayTabs[0].wsSelectedFrameIndex, expected);
        assert.deepEqual(f.rendered, [expected]);
        assert.deepEqual(f.persisted, [expected]);
        assert.deepEqual(f.scrolled, [expected]);
      } else {
        assert.deepEqual(f.selected, [[surface, key === "ArrowDown" ? 1 : -1]]);
        assert.deepEqual(f.rendered, []);
        assert.deepEqual(f.persisted, []);
        assert.deepEqual(f.scrolled, []);
      }
    });

    test(`${surface}: already-prevented ${key} does not dispatch selection`, () => {
      const f = fixture(surface);
      assert.equal(f.key(key, f.node(), { defaultPrevented: true }).defaultPrevented, true);
      assertUnchanged(f);
    });
  }
}

for (const key of ["ArrowUp", "ArrowDown"]) {
  test(`Findings: modified ${key} leaves selection alone`, () => {
    for (const modifier of ["metaKey", "ctrlKey", "altKey", "shiftKey"]) {
      const f = fixture("findings");
      assert.equal(f.key(key, f.node(), { [modifier]: true }).defaultPrevented, false);
      assertUnchanged(f);
    }
  });

  test(`Findings: ${key} leaves native controls and contenteditable text alone`, () => {
    for (const tag of ["INPUT", "TEXTAREA", "SELECT", "OPTION", "BUTTON"]) {
      for (const disabled of [false, true]) {
        const f = fixture("findings"), target = f.node(tag);
        target.disabled = disabled;
        assert.equal(f.key(key, target).defaultPrevented, false);
        assertUnchanged(f);
      }
    }
    for (const nested of [false, true]) {
      const f = fixture("findings"), target = f.node();
      if (nested) target.editableParent = Object.assign(f.node(), { isContentEditable: true });
      else target.isContentEditable = true;
      assert.equal(f.key(key, target).defaultPrevented, false);
      assertUnchanged(f);
    }
  });

  test(`Findings: ${key} preserves the caret in read-only selectable CodeMirror text`, () => {
    // Findings detail uses readOnly CodeMirror, whose content remains editable
    // to the DOM so that cursor placement and selection continue to work.
    assert.match(appSource, /if \(options\.readOnly\) \{\s+exts\.push\(CM\.EditorState\.readOnly\.of\(true\)\)/);
    const f = fixture("findings"), target = f.node();
    target.isContentEditable = true;
    target.classes.add("cm-content");
    assert.equal(f.key(key, target).defaultPrevented, false);
    assertUnchanged(f);
  });

  test(`Findings: ${key} cannot navigate behind an active modal`, () => {
    for (const modal of ["confirm", "displaySettingsModal", "filterModal", "curlImportModal", "scannerSettingsBackdrop"]) {
      const f = fixture("findings");
      if (modal === "confirm") f.context.activeConfirmDialog = { modal: f.node() };
      else f.els[modal].classes.delete("hidden");
      assert.equal(f.key(key).defaultPrevented, false);
      assertUnchanged(f);
    }
  });

  test(`Findings: ${key} cannot navigate a hidden table`, () => {
    for (const active of [{ activeTool: "tools" }, { activeProxyTab: "intercept" }]) {
      const f = fixture("findings");
      Object.assign(f.state, active);
      assert.equal(f.key(key).defaultPrevented, false);
      assertUnchanged(f);
    }
  });
}

test("Enter remains unconsumed in read-selection handlers", () => {
  for (const surface of surfaces) {
    for (const tag of ["DIV", "A", "BUTTON", "INPUT", "TEXTAREA", "SELECT"]) {
      const f = fixture(surface);
      f.openMenu();
      assert.equal(f.key("Enter", tag === "A" ? f.install : f.node(tag)).defaultPrevented, false);
      assertUnchanged(f);
    }
  }
});

test("Scanner-modal Escape and Enter block remains byte-for-byte unchanged", () => {
  const { findings } = keyboardRegistrations();
  const start = findings.indexOf("    // Skip if scanner settings modal is open");
  const end = findings.indexOf("    // Only handle when findings tab", start);
  assert.equal(findings.slice(start, end), scannerModalBlock);
});

test("Chooser-consumed Escape does not dismiss WebSocket frame detail", () => {
  const f = fixture("ws-frames");
  f.openMenu();
  assert.equal(f.key("Escape", f.install).defaultPrevented, true);
  assert.equal(f.document.activeElement, f.anchor);
  assert.equal(f.context.browserMenu, null);
  assert.equal(f.state.wsKeyboardFocus, "frames");
  assert.deepEqual(f.closed, []);
  assertUnchanged(f);
});

test("Ordinary Escape still returns WebSocket frame focus to sessions", () => {
  const f = fixture("ws-frames");
  assert.equal(f.key("Escape").defaultPrevented, true);
  assert.equal(f.state.wsKeyboardFocus, "sessions");
  assert.deepEqual(f.closed, ["settings", "certificate", "filter", "frame-detail"]);
  assertUnchanged(f);
});
