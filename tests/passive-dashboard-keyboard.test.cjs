// Dashboard selection only. Production callbacks use synthetic session metadata,
// inert rendering/focus, and no app bootstrap, API, browser, or session actions.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture() {
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
    focus() { document.activeElement = this; }
  }
  const node = tagName => new HTMLElement(tagName);
  const sessions = [1, 2, 3].map(index => ({
    id: `00000000-0000-0000-0000-${String(index).padStart(12, "0")}`,
    name: `Session ${index}`,
    created_at: `2026-10-0${index}T12:00:00Z`,
    updated_at: `2026-10-0${index}T12:00:00Z`,
    last_opened_at: `2026-10-0${index}T12:00:00Z`,
    request_count: 0, websocket_count: 0, event_count: 0, fuzzer_count: 0, rule_count: 0,
    storage_path: `/synthetic/session-${index}`,
    active: index === 2,
  }));
  const state = {
    sessions, activeSession: sessions[1], selectedSessionId: sessions[1].id,
    sessionSortKey: "created_at", sessionSortDir: "asc", activeTool: "dashboard",
    // The rows are in the page's second view.
    sessionPageView: "all",
  };
  const rendered = [], scrolled = [], actions = [];
  const els = {
    dashboardSessionsBody: {
      querySelector(selector) {
        assert.equal(selector, `tr[data-id="${state.selectedSessionId}"]`);
        return { scrollIntoView(options) {
          assert.equal(options.block, "nearest");
          scrolled.push(state.selectedSessionId);
        } };
      },
    },
  };
  for (const key of ["displaySettingsModal", "filterModal", "curlImportModal"]) {
    els[key] = node();
    els[key].classes.add("hidden");
  }
  const anchor = node("BUTTON"), install = node("A"), button = node("BUTTON"), input = node("INPUT");
  const controls = [install, button, input];
  const menu = {
    contains: target => controls.includes(target),
    querySelectorAll(selector) {
      assert.equal(selector, "button:not(:disabled), input, a[href]");
      return controls.filter(control => control.tagName !== "BUTTON" || !control.disabled);
    },
  };
  const action = name => () => { actions.push(name); };
  const context = loadFunctions([
    "getSortedSessions", "moveSessionSelection", "clamp", "isEditableTarget",
    "isModalVisible", "getActiveModalAction", "onBrowserMenuKeydown",
  ], {
    state, els, document, HTMLElement, activeConfirmDialog: null, browserMenu: null,
    renderDashboard: () => rendered.push(state.selectedSessionId),
    activateSessionById: action("activate"), deleteSessionById: action("delete"),
    revealSessionFolder: action("reveal"), createSession: action("create"),
    closeDisplaySettingsModal: action("close settings"),
    closeFilterModal: action("close filters"), closeCurlImportModal: action("close import"),
    saveDisplaySettingsFromForm: action("save settings"), applyFilterSettings: action("apply filters"),
    fetch() { assert.fail("Keyboard selection must not make requests"); },
  });
  const handlers = [];
  document.addEventListener = (type, handler) => {
    assert.equal(type, "keydown");
    handlers.push(handler);
  };
  const start = appSource.indexOf('  document.addEventListener("keydown", (event) => {\n    const activeModalAction');
  const end = appSource.indexOf("    // Arrow keys in WS Replay", start);
  const installCall = appSource.indexOf("  installBrowserMenuDismissal();");
  const browserListener = '  document.addEventListener("keydown", onBrowserMenuKeydown);';
  assert.ok(start >= 0 && end > start, "Missing production Dashboard keyboard callback");
  assert.ok(installCall > appSource.indexOf("function bindEvents() {") && installCall < start,
    "Browser chooser keyboard handling must register before Dashboard handling");
  assert.ok(appSource.includes(browserListener), "Missing production browser chooser registration");
  vm.runInContext(browserListener, context);
  vm.runInContext(appSource.slice(start, end) + "  });", context);
  function key(key, target = node(), options = {}) {
    document.activeElement = target;
    const event = {
      key, target, metaKey: false, ctrlKey: false, altKey: false, shiftKey: false,
      defaultPrevented: false,
      preventDefault() { this.defaultPrevented = true; },
      ...options,
    };
    for (const handler of handlers) handler(event);
    assert.deepEqual(actions, [], "Navigation must not invoke action callbacks");
    return event;
  }
  function openMenu() { context.browserMenu = { anchor, element: menu }; }
  return { context, state, sessions, els, document, node, anchor, install, button, input,
    controls, rendered, scrolled, key, openMenu };
}

function assertUnchanged(f, selected = f.sessions[1].id) {
  assert.equal(f.state.selectedSessionId, selected);
  assert.deepEqual(f.rendered, []);
  assert.deepEqual(f.scrolled, []);
}

for (const key of ["ArrowUp", "ArrowDown"]) {
  test(`${key} consumed on a browser chooser Install link does not change Dashboard selection`, () => {
    const f = fixture();
    f.openMenu();
    const event = f.key(key, f.install);
    assert.equal(event.defaultPrevented, true);
    assert.equal(f.document.activeElement, key === "ArrowDown" ? f.button : f.input);
    assertUnchanged(f);
  });

  test(`${key} in the chooser skips disabled controls without changing Dashboard selection`, () => {
    const f = fixture();
    f.openMenu();
    f.button.disabled = true;
    assert.equal(f.key(key, f.install).defaultPrevented, true);
    assert.equal(f.document.activeElement, f.input);
    assertUnchanged(f);
  });

  test(`${key} from a browser chooser button or input stays within the chooser`, () => {
    for (const type of ["button", "input"]) {
      const f = fixture();
      f.openMenu();
      const start = f.controls.indexOf(f[type]);
      const expected = f.controls[(start + (key === "ArrowDown" ? 1 : -1) + f.controls.length) % f.controls.length];
      assert.equal(f.key(key, f[type]).defaultPrevented, true);
      assert.equal(f.document.activeElement, expected);
      assertUnchanged(f);
    }
  });

  test(`${key} outside an open chooser still navigates the displayed Dashboard order`, () => {
    for (const direction of ["asc", "desc"]) {
      const f = fixture();
      f.openMenu();
      f.state.sessionSortDir = direction;
      const ordered = direction === "asc" ? f.sessions : [...f.sessions].reverse();
      const expected = ordered[key === "ArrowDown" ? 2 : 0].id;
      assert.equal(f.key(key).defaultPrevented, true);
      assert.equal(f.state.selectedSessionId, expected);
      assert.deepEqual(f.rendered, [expected]);
      assert.deepEqual(f.scrolled, [expected]);
    }
  });

  test(`${key} clamps at the Dashboard boundary without wrapping`, () => {
    const f = fixture();
    const expected = f.sessions[key === "ArrowDown" ? 2 : 0].id;
    f.state.selectedSessionId = expected;
    assert.equal(f.key(key).defaultPrevented, true);
    assert.equal(f.state.selectedSessionId, expected);
    assert.deepEqual(f.scrolled, [expected]);
  });

  test(`${key} handles empty lists and missing selections without selecting an unrelated ID`, () => {
    for (const selected of [null, "removed"]) {
      const f = fixture();
      f.state.selectedSessionId = selected;
      const expected = f.sessions[key === "ArrowDown" ? 0 : 2].id;
      f.key(key);
      assert.equal(f.state.selectedSessionId, expected);
      assert.deepEqual(f.scrolled, [expected]);
    }
    const empty = fixture();
    empty.state.sessions = [];
    empty.state.selectedSessionId = null;
    empty.key(key);
    assertUnchanged(empty, null);
  });

  test(`${key} with a modifier leaves Dashboard selection alone`, () => {
    for (const modifier of ["metaKey", "ctrlKey", "altKey", "shiftKey"]) {
      const f = fixture();
      assert.equal(f.key(key, f.node(), { [modifier]: true }).defaultPrevented, false);
      assertUnchanged(f);
    }
  });

  test(`${key} leaves editable controls, disabled buttons, and contenteditable targets alone`, () => {
    for (const tag of ["INPUT", "TEXTAREA", "SELECT", "OPTION", "BUTTON"]) {
      for (const disabled of [false, true]) {
        const f = fixture(), target = f.node(tag);
        target.disabled = disabled;
        assert.equal(f.key(key, target).defaultPrevented, false);
        assertUnchanged(f);
      }
    }
    for (const nested of [false, true]) {
      const f = fixture(), target = f.node();
      if (nested) target.editableParent = f.node("TEXTAREA");
      else target.isContentEditable = true;
      assert.equal(f.key(key, target).defaultPrevented, false);
      assertUnchanged(f);
    }
  });

  test(`${key} cannot change hidden Dashboard selection or navigate behind an active modal`, () => {
    const hidden = fixture();
    hidden.state.activeTool = "tools";
    assert.equal(hidden.key(key).defaultPrevented, false);
    assertUnchanged(hidden);
    // The Overview shows no rows: the selection under it stays.
    const overview = fixture();
    overview.state.sessionPageView = "overview";
    assert.equal(overview.key(key).defaultPrevented, false);
    assertUnchanged(overview);
    for (const modal of ["confirm", "displaySettingsModal", "filterModal", "curlImportModal"]) {
      const f = fixture();
      if (modal === "confirm") f.context.activeConfirmDialog = { modal: f.node() };
      else f.els[modal].classes.delete("hidden");
      assert.equal(f.key(key).defaultPrevented, false);
      assertUnchanged(f);
    }
  });
}
