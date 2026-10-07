// Passive tab routing and modal helper checks only. The extracted callbacks run
// against synthetic DOM objects; no bootstrap, real data, requests, or browser.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");
const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");

function classList(initial = "") {
  const values = new Set(initial.split(/\s+/).filter(Boolean));
  return {
    contains: value => values.has(value),
    add: (...items) => items.forEach(value => values.add(value)),
    remove: (...items) => items.forEach(value => values.delete(value)),
    toggle(value, force = !values.has(value)) {
      if (force) values.add(value); else values.delete(value);
      return force;
    },
  };
}

function tabFixture() {
  const document = { activeElement: null };
  const saved = [], loads = [];
  function node(dataset = {}, classes = "") {
    const handlers = new Map(), attrs = new Map();
    const value = {
      dataset, classList: classList(classes), attrs, style: {},
      isConnected: true, disabled: false, tabIndex: 0, visibility: "visible",
      getClientRects: () => [1],
      setAttribute: (name, content) => attrs.set(name, content),
      focus() { document.activeElement = value; },
      addEventListener(type, callback) {
        if (!handlers.has(type)) handlers.set(type, []);
        handlers.get(type).push(callback);
      },
      click() { handlers.get("click")?.forEach(callback => callback({ target: value })); },
    };
    return value;
  }
  // Build tab membership from actual markup so shared CSS classes cannot hide
  // an accidental binding to another feature's tabs.
  const tabs = [...html.matchAll(/<button\b([^>]*\bclass="[^"]*\bsub-tab\b[^"]*"[^>]*)>/g)].map(([, attrs]) => {
    const dataset = {};
    for (const [, name, value] of attrs.matchAll(/data-([a-z-]+)="([^"]*)"/g)) {
      dataset[name.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
    }
    return node(dataset, attrs.match(/class="([^"]*)"/)[1]);
  });
  const settingsTabs = tabs.filter(tab => "settingsTab" in tab.dataset);
  const compareTabs = tabs.filter(tab => "compareTab" in tab.dataset);
  const captureTabs = tabs.filter(tab => "proxyTab" in tab.dataset);
  assert.equal(settingsTabs.length, 3);
  assert.equal(compareTabs.length, 2);
  assert.ok(captureTabs.length >= 3);
  const panels = ["runtime", "display", "shortcuts"].map(name => node({ settingsPanel: name }));
  const actions = node();
  const els = {};
  for (const name of [
    "colorTagFilter", "filterBar", "trafficRegion", "historyWorkbenchResizer", "lowerWorkbench",
    "interceptPanel", "websocketPanel", "matchReplacePanel", "findingsPanel", "oastPanel",
    "proxySettingsPanel", "proxySubPlaceholder", "footerMode", "closeDisplaySettingsButton", "openDisplaySettingsButton",
  ]) els[name] = node();
  els.displaySettingsModal = node({}, "hidden");
  els.displaySettingsModal.querySelectorAll = selector => {
    if (selector === "[data-settings-tab]") return settingsTabs;
    if (selector === "[data-settings-panel]") return panels;
    assert.fail(`Unexpected modal selector: ${selector}`);
  };
  els.displaySettingsModal.querySelector = selector => selector === ".modal-actions" ? actions : null;
  document.querySelectorAll = selector => {
    if (selector === ".sub-tab") return tabs;
    if ([".sub-tab[data-proxy-tab]", "[data-proxy-tab]", ".sub-tabs .sub-tab"].includes(selector)) return captureTabs;
    if (selector === "[data-compare-tab]") return compareTabs;
    assert.fail(`Unexpected selector: ${selector}`);
  };
  document.querySelector = () => els.openDisplaySettingsButton;
  document.activeElement = els.openDisplaySettingsButton;
  const state = { activeProxyTab: "websockets-history", historyDirty: false };
  const context = loadFunctions([
    "setActiveProxyTab", "sanitizeActiveProxyTab", "renderProxyPanels", "selectSettingsTab",
    "openDisplaySettingsModal", "closeDisplaySettingsModal", "isModalVisible", "restoreModalFocus",
  ], {
    document, els, state,
    IMPLEMENTED_PROXY_TABS: new Set(captureTabs.map(tab => tab.dataset.proxyTab)),
    scheduleUiSettingsSave: delay => saved.push(delay),
    loadWebsocketsPageRefresh: async () => loads.push("websockets"),
    loadTransactions: async () => loads.push("history"),
    consumeHistoryLoadOptions: () => ({}),
    applySavedWebsocketPaneWidth() {}, hydrateDisplaySettingsForm() {}, applyDisplaySettingsState() {}, renderShortcutReference() {},
    displaySettingsReturnFocus: null, displaySettingsPreviewActive: false,
    window: { getComputedStyle: value => ({ visibility: value.visibility }) },
    fetch() { assert.fail("Passive tab tests must not make requests"); },
  });
  const declaration = appSource.match(/^const proxyTabs = .+;$/m)?.[0];
  assert.ok(declaration);
  vm.runInContext(declaration, context);
  const captureStart = appSource.indexOf("  proxyTabs.forEach((tab) => {", appSource.indexOf("function bindEvents()"));
  const captureEnd = appSource.indexOf("\n  viewTabs.forEach", captureStart);
  assert.ok(captureStart >= 0 && captureEnd > captureStart);
  vm.runInContext(appSource.slice(captureStart, captureEnd), context);
  const settingsStart = appSource.indexOf('  els.displaySettingsModal.querySelectorAll("[data-settings-tab]").forEach((tab) => {');
  const settingsEnd = appSource.indexOf("\n  wireReplayHistorySwipe();", settingsStart);
  assert.ok(settingsStart >= 0 && settingsEnd > settingsStart);
  vm.runInContext(appSource.slice(settingsStart, settingsEnd), context);
  return { context, document, els, state, saved, loads, tabs, settingsTabs, compareTabs, captureTabs, panels, actions };
}

for (const name of ["runtime", "display", "shortcuts"]) {
  test(`Settings ${name} selection preserves the underlying Web Socket view and does not schedule a save`, () => {
    const f = tabFixture();
    f.context.renderProxyPanels();
    f.context.openDisplaySettingsModal();
    f.settingsTabs.find(tab => tab.dataset.settingsTab === name).click();
    assert.equal(f.state.activeProxyTab, "websockets-history");
    assert.equal(f.els.websocketPanel.classList.contains("hidden"), false);
    assert.deepEqual(f.saved, []);
    assert.deepEqual(f.loads, []);
    assert.equal(f.settingsTabs.find(tab => tab.dataset.settingsTab === name).classList.contains("active"), true);
    assert.equal(f.panels.find(panel => panel.dataset.settingsPanel === name).classList.contains("settings-panel-off"), false);
  });
}

for (const name of ["runtime", "display", "shortcuts"]) {
  test(`finishing initial Capture rendering preserves the open Settings ${name} selection`, () => {
    const f = tabFixture();
    // init binds events before awaiting startup loads, so Settings can be open
    // when its final renderProxyPanels call runs.
    f.context.openDisplaySettingsModal();
    f.context.selectSettingsTab(name);
    f.context.renderProxyPanels();
    const active = f.settingsTabs.filter(tab => tab.classList.contains("active"));
    assert.deepEqual(active.map(tab => tab.dataset.settingsTab), [name]);
    assert.equal(active[0].attrs.get("aria-selected"), "true");
    assert.equal(f.panels.find(panel => panel.dataset.settingsPanel === name).classList.contains("settings-panel-off"), false);
  });
}

for (const name of ["request", "response"]) {
  test(`Capture rendering preserves Compare ${name} selection`, () => {
    const f = tabFixture();
    f.compareTabs.forEach(tab => tab.classList.toggle("active", tab.dataset.compareTab === name));
    f.context.renderProxyPanels();
    assert.deepEqual(f.compareTabs.filter(tab => tab.classList.contains("active")).map(tab => tab.dataset.compareTab), [name]);
  });
}

test("a real Capture tab still updates its view, schedules one save, and performs its passive load", () => {
  const f = tabFixture(); f.state.activeProxyTab = "http-history";
  f.captureTabs.find(tab => tab.dataset.proxyTab === "websockets-history").click();
  assert.equal(f.state.activeProxyTab, "websockets-history");
  assert.equal(f.els.websocketPanel.classList.contains("hidden"), false);
  assert.equal(f.saved.length, 1);
  assert.deepEqual(f.loads, ["websockets"]);
});

test("Settings selection changes only local panels and Display action visibility", () => {
  const f = tabFixture();
  for (const name of ["runtime", "display", "shortcuts", "display", "runtime"]) {
    f.context.selectSettingsTab(name);
    for (const tab of f.settingsTabs) {
      assert.equal(tab.classList.contains("active"), tab.dataset.settingsTab === name);
      assert.equal(tab.attrs.get("aria-selected"), String(tab.dataset.settingsTab === name));
    }
    for (const panel of f.panels) assert.equal(panel.classList.contains("settings-panel-off"), panel.dataset.settingsPanel !== name);
    assert.equal(f.actions.classList.contains("settings-actions-off"), name !== "display");
  }
  assert.deepEqual(f.saved, []);
  assert.deepEqual(f.loads, []);
});

function focusFixture() {
  const document = { activeElement: null };
  function node(options = {}) {
    const value = {
      isConnected: true, disabled: false, tabIndex: 0, visibility: "visible", rects: [1], focusCalls: [],
      getClientRects() { return value.rects; },
      focus(options) { value.focusCalls.push(options); document.activeElement = value; },
      ...options,
    };
    return value;
  }
  const fallback = node();
  document.querySelector = selector => { assert.equal(selector, ".main-tab.active"); return fallback; };
  const context = loadFunctions(["restoreModalFocus", "trapModalFocus"], {
    document, window: { getComputedStyle: value => ({ visibility: value.visibility }) },
  });
  return { context, document, node, fallback };
}

test("modal restoration focuses the visible connected invoker without scrolling", () => {
  const f = focusFixture(), previous = f.node();
  f.context.restoreModalFocus(previous);
  assert.equal(f.document.activeElement, previous);
  assert.equal(previous.focusCalls.length, 1);
  assert.equal(previous.focusCalls[0].preventScroll, true);
  assert.equal(f.fallback.focusCalls.length, 0);
});

for (const [reason, options] of [
  ["detached", { isConnected: false }], ["disabled", { disabled: true }],
  ["outside tab order", { tabIndex: -1 }], ["not laid out", { rects: [] }],
  ["hidden", { visibility: "hidden" }],
]) {
  test(`modal restoration uses the supplied fallback when the invoker is ${reason}`, () => {
    const f = focusFixture(), previous = f.node(options), supplied = f.node();
    f.context.restoreModalFocus(previous, supplied);
    assert.equal(f.document.activeElement, supplied);
    assert.equal(previous.focusCalls.length, 0);
    assert.equal(supplied.focusCalls[0].preventScroll, true);
  });
}

test("modal restoration tolerates no saved invoker or no available fallback", () => {
  const f = focusFixture();
  f.context.restoreModalFocus(null);
  assert.equal(f.document.activeElement, f.fallback);
  f.document.activeElement = null;
  f.context.restoreModalFocus(undefined, null);
  assert.equal(f.document.activeElement, null);
});

for (const shiftKey of [false, true]) {
  for (const origin of ["boundary", "outside", "hidden"]) {
    test(`${shiftKey ? "Shift+Tab" : "Tab"} wraps from ${origin} to an eligible modal control`, () => {
      const f = focusFixture();
      const first = f.node(), last = f.node();
      const hidden = f.node({ visibility: "hidden" });
      const controls = [f.node({ disabled: true }), first, hidden, f.node({ rects: [] }), f.node({ tabIndex: -1 }), last];
      const modal = { querySelectorAll: () => controls };
      f.document.activeElement = origin === "boundary" ? (shiftKey ? first : last) : origin === "hidden" ? hidden : f.node();
      const event = { shiftKey, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } };
      f.context.trapModalFocus(event, modal);
      assert.equal(event.defaultPrevented, true);
      assert.equal(f.document.activeElement, shiftKey ? last : first);
    });
  }
  test(`${shiftKey ? "Shift+Tab" : "Tab"} leaves native movement between modal controls alone`, () => {
    const f = focusFixture(), controls = [f.node(), f.node(), f.node()];
    f.document.activeElement = controls[1];
    let prevented = false;
    f.context.trapModalFocus({ shiftKey, preventDefault() { prevented = true; } }, { querySelectorAll: () => controls });
    assert.equal(prevented, false);
    assert.equal(f.document.activeElement, controls[1]);
  });
  test(`${shiftKey ? "Shift+Tab" : "Tab"} stays on a modal's only eligible control`, () => {
    const f = focusFixture(), only = f.node();
    f.document.activeElement = only;
    let prevented = false;
    f.context.trapModalFocus({ shiftKey, preventDefault() { prevented = true; } }, { querySelectorAll: () => [only] });
    assert.equal(prevented, true);
    assert.equal(f.document.activeElement, only);
  });
}

function indicatorFixture() {
  const mutationObservers = [], resizeObservers = [], appended = [];
  const strip = {
    classList: classList(), offsetWidth: 400,
    active: { offsetLeft: 35, offsetTop: 1, offsetWidth: 82, offsetHeight: 28 },
    querySelector: selector => { assert.equal(selector, ".active"); return strip.active; },
    appendChild: node => appended.push(node),
  };
  function observer(list) {
    return class {
      constructor(callback) { this.callback = callback; list.push(this); }
      observe(target, options) { this.target = target; this.options = options; }
    };
  }
  const context = loadFunctions(["wireTabIndicator"], {
    MutationObserver: observer(mutationObservers), ResizeObserver: observer(resizeObservers),
    document: { createElement(tag) {
      assert.equal(tag, "span");
      return { attrs: {}, style: {}, offsetWidth: 1, setAttribute(name, value) { this.attrs[name] = value; } };
    } },
  });
  return { context, strip, mutationObservers, resizeObservers, appended };
}

function assertIndicatorPosition(indicator, active) {
  for (const [style, offset] of [["left", "offsetLeft"], ["top", "offsetTop"], ["width", "offsetWidth"], ["height", "offsetHeight"]]) {
    assert.equal(indicator.style[style], `${active[offset]}px`);
  }
}

test("tab indicator wiring is optional and idempotent, with class-only mutation observation", () => {
  const f = indicatorFixture();
  f.context.wireTabIndicator(null);
  f.context.wireTabIndicator(f.strip);
  f.context.wireTabIndicator(f.strip);
  assert.equal(f.appended.length, 1);
  assert.equal(f.mutationObservers.length, 1);
  assert.equal(f.resizeObservers.length, 1);
  assert.equal(f.appended[0].attrs["aria-hidden"], "true");
  assert.equal(f.strip.classList.contains("has-tab-indicator"), true);
  assert.deepEqual([...f.mutationObservers[0].options.attributeFilter], ["class"]);
  assert.equal(f.mutationObservers[0].options.subtree, true);
  assert.equal(f.resizeObservers[0].target, f.strip);
  assertIndicatorPosition(f.appended[0], f.strip.active);
});

test("tab indicator follows active-class changes and strip resize geometry", () => {
  const f = indicatorFixture(); f.context.wireTabIndicator(f.strip);
  f.strip.active = { offsetLeft: 135, offsetTop: 3, offsetWidth: 73, offsetHeight: 30 };
  f.mutationObservers[0].callback();
  assertIndicatorPosition(f.appended[0], f.strip.active);
  f.strip.active.offsetLeft = 151;
  f.strip.active.offsetWidth = 91;
  f.resizeObservers[0].callback();
  assertIndicatorPosition(f.appended[0], f.strip.active);
});

for (const reason of ["hidden strip", "no active tab"]) {
  test(`tab indicator hides for ${reason} and is placed again when usable`, () => {
    const f = indicatorFixture(); f.context.wireTabIndicator(f.strip);
    const active = f.strip.active;
    if (reason === "hidden strip") f.strip.offsetWidth = 0; else f.strip.active = null;
    f.mutationObservers[0].callback();
    assert.equal(f.appended[0].style.opacity, "0");
    f.strip.offsetWidth = 400;
    f.strip.active = active;
    active.offsetLeft = 210;
    f.resizeObservers[0].callback();
    assert.equal(f.appended[0].style.opacity, "1");
    assert.equal(f.appended[0].style.transition, "");
    assertIndicatorPosition(f.appended[0], active);
  });
}

for (const shiftKey of [false, true]) {
  test(`${shiftKey ? "Shift+Tab" : "Tab"} safely returns when a synthetic modal has no eligible control`, () => {
    const f = focusFixture(), previous = f.node();
    f.document.activeElement = previous;
    let prevented = false;
    const controls = [f.node({ disabled: true }), f.node({ visibility: "hidden" }), f.node({ rects: [] })];
    f.context.trapModalFocus({ shiftKey, preventDefault() { prevented = true; } }, { querySelectorAll: () => controls });
    assert.equal(prevented, false);
    assert.equal(f.document.activeElement, previous);
    assert.equal(controls.some(control => control.focusCalls.length), false);
  });
}
