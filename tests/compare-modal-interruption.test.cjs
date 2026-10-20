// Synthetic dialog interruption checks. Run production modal callbacks and
// keyboard listeners with deferred local data; never bootstrap the app or API.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

function deferred() {
  let resolve, reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

function fixture() {
  const nodes = {}, listeners = new Map(), pending = [], rendered = [], actions = [], errors = [];
  const document = { activeElement: null, readyState: "loading" };
  class Element {
    constructor(id, tagName = "DIV", parent = null) {
      Object.assign(this, { id, tagName, parent, children: [], handlers: new Map(), dataset: {},
        attributes: {}, isConnected: true, disabled: false, tabIndex: tagName === "BUTTON" ? 0 : -1,
        visibility: "visible", isContentEditable: false });
      const classes = new Set();
      this.classList = {
        add: (...names) => names.forEach(name => classes.add(name)),
        remove: (...names) => names.forEach(name => classes.delete(name)),
        contains: name => classes.has(name),
        toggle: (name, on = !classes.has(name)) => on ? classes.add(name) : classes.delete(name),
      };
      parent?.children.push(this);
      nodes[id] = this;
    }
    getClientRects() {
      return this.isConnected && !this.classList.contains("hidden")
        && (!this.parent || this.parent.getClientRects().length) ? [1] : [];
    }
    focus() {
      if (!this.disabled && this.getClientRects().length && this.visibility !== "hidden") document.activeElement = this;
    }
    contains(node) { return node === this || this.children.some(child => child.contains(node)); }
    remove() { this.isConnected = false; this.children.forEach(child => child.remove()); }
    addEventListener(type, handler) { this.handlers.set(type, handler); }
    click() { this.handlers.get("click")?.({ target: this }); }
    matches(selector) { return selector.split(", ").includes(this.tagName.toLowerCase()); }
    closest(selector) {
      if (selector.includes(".simple-code-view") && this === nodes.compareDiffView) return this;
      if (selector.includes("contenteditable") && this.isContentEditable) return this;
      return this.parent?.closest(selector) || null;
    }
    setAttribute(name, value) {
      this.attributes[name] = value;
      if (name === "contenteditable") this.isContentEditable = value === "true";
    }
    getAttribute(name) { return this.attributes[name]; }
    querySelectorAll(selector) {
      if (selector === ".code-line") return [];
      return this.children.flatMap(child => [child, ...child.querySelectorAll(selector)]);
    }
    querySelector() { return null; }
  }
  document.body = new Element("body", "BODY");
  document.body.appendChild = () => {};
  document.createElement = () => {
    const modal = new Element("confirm", "DIV", document.body);
    const cancel = new Element("cancel", "BUTTON", modal), ok = new Element("ok", "BUTTON", modal);
    modal.querySelector = selector => selector.includes("cancel") ? cancel : ok;
    return modal;
  };
  document.addEventListener = (type, handler) => {
    if (!listeners.has(type)) listeners.set(type, []);
    listeners.get(type).push(handler);
  };
  document.getElementById = id => nodes[id] || null;
  document.querySelector = () => nodes.mainTab;
  for (const id of ["proxyShell", "dashboardShell", "replayShell", "toolsShell", "fuzzerShell", "sequenceShell", "targetShell", "mapShell", "loggerShell", "reconShell"]) new Element(id, "DIV", document.body);
  for (const id of ["displaySettingsModal", "filterModal", "curlImportModal", "scannerSettingsBackdrop", "compareModal"]) {
    new Element(id, "DIV", id === "scannerSettingsBackdrop" ? nodes.proxyShell : document.body).classList.add("hidden");
  }
  for (const id of ["opener", "mainTab", "openDisplaySettingsButton", "openFilterSettingsButton"]) new Element(id, "BUTTON", document.body);
  new Element("trafficRegion", "SECTION", nodes.proxyShell).tabIndex = 0;
  new Element("findingsSettingsButton", "BUTTON", nodes.proxyShell);
  for (const id of ["colorTagFilter", "filterBar", "historyWorkbenchResizer", "lowerWorkbench", "interceptPanel", "websocketPanel",
    "matchReplacePanel", "findingsPanel", "oastPanel", "proxySettingsPanel", "proxySubPlaceholder", "footerMode"]) new Element(id, "DIV", document.body);
  for (const [id, parent] of [
    ["closeDisplaySettingsButton", "displaySettingsModal"], ["closeFilterModalButton", "filterModal"],
    ["scannerSettingsClose", "scannerSettingsBackdrop"], ["scannerSettingsCancel", "scannerSettingsBackdrop"],
    ["scannerSettingsSave", "scannerSettingsBackdrop"], ["closeCompareButton", "compareModal"],
  ]) new Element(id, "BUTTON", nodes[parent]);
  new Element("scannerBuiltinRules", "DIV", nodes.scannerSettingsBackdrop);
  new Element("findingsFilterSearch", "INPUT", nodes.proxyShell).tabIndex = 0;
  new Element("curlImportInput", "TEXTAREA", nodes.curlImportModal).tabIndex = 0;
  const request = new Element("request", "BUTTON", nodes.compareModal), response = new Element("response", "BUTTON", nodes.compareModal);
  request.dataset.compareTab = "request"; response.dataset.compareTab = "response";
  new Element("compareDiffView", "PRE", nodes.compareModal).tabIndex = 0;
  document.querySelectorAll = selector => selector === "[data-compare-tab]" ? [request, response] : [nodes.compareDiffView];
  document.activeElement = nodes.opener;
  const scannerLoad = deferred();
  const action = name => () => { actions.push(name); return Promise.resolve(); };
  const context = loadFunctions([
    "openCompareModal", "closeCompareModal", "getActiveModalAction", "isModalVisible", "restoreModalFocus", "trapModalFocus", "isEditableTarget",
    "openDisplaySettingsModal", "closeDisplaySettingsModal", "closeCertificateModal", "openFilterModal", "closeFilterModal", "showConfirmDialog",
    "openCurlImportModal", "closeCurlImportModal", "openScannerSettings", "closeScannerSettings", "renderProxyPanels", "retireFindingActionProgress", "invalidateFindingNavigation", "setActiveTool", "setActiveProxyTab", "renderToolPanels",
    "resetScannerConfigUiState", "scannerConfigContextIsCurrent", "onClickWithProgress", "withButtonProgress",
  ], {
    setTimeout: () => 1, clearTimeout() {}, BUTTON_PROGRESS_DELAY_MS: 10,
    document, els: nodes, HTMLElement: Element, Element, console: { error: error => errors.push(error) },
    window: { getComputedStyle: node => ({ visibility: node.visibility }), getSelection: () => null },
    state: { activeTool: "proxy", activeProxyTab: "http-history", selectedId: "target" },
    compareBaseId: "base", compareBaseSessionId: "session-a", compareLoadGeneration: 0,
    compareBaseRecord: null, compareTargetRecord: null, compareActiveTab: "request", compareReturnFocus: null,
    sessionId: "session-a", transactionPath: id => id,
    proxyTabs: [], mainTabs: [], sanitizeActiveTool: value => value, sanitizeActiveProxyTab: value => value, loadFindings() {},
    scheduleUiSettingsSave() {}, renderReplay() {}, duplicateActiveReplayTab: action("duplicate replay"),
    activeConfirmDialog: null, displaySettingsPreviewActive: false, displaySettingsReturnFocus: null, filterSettingsReturnFocus: null,
    displaySettingsEditedControls: new Set(), filterSettingsEditedControls: new Set(),
    hydrateDisplaySettingsForm() {}, applyDisplaySettingsState() {}, renderShortcutReference() {}, selectSettingsTab() {}, hydrateFilterForm() {},
    saveDisplaySettingsFromForm: action("settings apply"), applyFilterSettings: action("filter apply"),
    scannerSettingsBaseline: null, scannerSettingsSessionId: null, scannerSettingsGeneration: 0,
    scannerSettingsSavePending: null, scannerSettingsReturnFocus: null, scannerConfigStateGeneration: 0, scannerConfigLoadGeneration: 0, scannerConfigCache: null, scannerConfigSavePending: null, scannerQuickTogglePending: null,
    scannerConfigSnapshot: config => config, loadScannerConfig: () => scannerLoad.promise, BUILTIN_RULE_LABELS: {}, renderCustomRulesEditor() {},
    saveScannerSettingsFromModal: action("scanner save"), showToast: action("toast"), escapeHtml: text => text,
    findingsArrowNav: action("findings"), moveHistorySelection: action("history"),
    openReplayFromSelection: action("replay"), openFuzzerFromSelection: action("fuzzer"), handleSendActionError: error => { throw error; },
    fetch(path) { const response = deferred(); pending.push({ path, ...response }); return response.promise; },
  });
  context.currentSessionId = () => context.sessionId;
  context.renderCompareModal = () => rendered.push(context.compareTargetRecord.id);
  function register(startMarker, endMarker) {
    const start = appSource.indexOf(startMarker), end = appSource.indexOf(endMarker, start);
    assert.ok(start >= 0 && end > start, startMarker);
    vm.runInContext(appSource.slice(start, end), context);
  }
  // Preserve production listener order and the real read-only caret setup.
  register("(function initCodeViewLineNav() {", "\n\n// ─── CodeMirror 6 Integration");
  const findingsStart = appSource.indexOf("  // Arrow key navigation\n", appSource.indexOf("function bindFindingsEvents()"));
  const findingsEnd = appSource.indexOf("\n\n  // Findings detail search", findingsStart);
  assert.ok(findingsStart >= 0 && findingsEnd > findingsStart);
  vm.runInContext(appSource.slice(findingsStart, findingsEnd), context);
  register("  // Scanner settings modal\n", "\n\n  initFindingsResizer();");
  register('  document.addEventListener("keydown", (event) => {\n    const activeModalAction', '\n\n  document.addEventListener("copy",');
  for (const handler of listeners.get("DOMContentLoaded") || []) handler();
  assert.equal(nodes.compareDiffView.getAttribute("data-readonly-editable"), "1");
  function key(key, target = document.activeElement, options = {}) {
    const event = { key, target, defaultPrevented: false, metaKey: false, ctrlKey: false, altKey: false, shiftKey: false,
      preventDefault() { this.defaultPrevented = true; }, ...options };
    target?.focus?.();
    for (const handler of listeners.get("keydown") || []) handler(event);
    if (!event.defaultPrevented && target?.tagName === "BUTTON" && ["Enter", " "].includes(key)) target.click();
    if (!event.defaultPrevented && target?.tagName === "INPUT" && key.length === 1
      && !event.ctrlKey && !event.metaKey && !event.altKey) target.value = (target.value || "") + key;
    return event;
  }
  function resolvePair(offset = 0, target = "target") {
    pending[offset].resolve({ ok: true, json: async () => ({ id: "base" }) });
    pending[offset + 1].resolve({ ok: true, json: async () => ({ id: target }) });
  }
  async function openDialog(name) {
    if (name === "settings") context.openDisplaySettingsModal();
    if (name === "filter") context.openFilterModal();
    if (name === "confirm") context.showConfirmDialog("Synthetic confirmation", action("confirmed"));
    if (name === "curl") context.openCurlImportModal();
    if (name === "scanner") {
      const opening = context.openScannerSettings();
      scannerLoad.resolve({ rules: {}, custom_rules: [] });
      await opening;
    }
  }
  return { context, nodes, document, key, pending, rendered, actions, errors, resolvePair, openDialog, scannerLoad,
    hidden: () => nodes.compareModal.classList.contains("hidden") };
}

for (const dialog of ["settings", "filter", "confirm", "curl", "scanner"]) {
  for (const dismissal of ["Escape", "close"]) {
    test(`newer ${dialog} opened and ${dismissal}-closed does not revive the pending comparison`, async () => {
      const f = fixture(), loading = f.context.openCompareModal("target");
      await f.openDialog(dialog);
      if (dismissal === "Escape") f.key("Escape");
      else ({ settings: f.context.closeDisplaySettingsModal, filter: f.context.closeFilterModal,
        confirm: () => f.context.activeConfirmDialog.close(), curl: f.context.closeCurlImportModal,
        scanner: f.context.closeScannerSettings })[dialog]();
      f.nodes.mainTab.focus();
      f.resolvePair(); await loading;
      assert.equal(f.hidden(), true);
      assert.deepEqual(f.rendered, []);
      assert.equal(f.document.activeElement, f.nodes.mainTab);
      assert.equal(f.context.compareBaseId, "base", "Cancel only the pending reveal, not the chosen base");
      const fresh = f.context.openCompareModal("fresh");
      f.resolvePair(2, "fresh"); await fresh;
      assert.equal(f.hidden(), false);
      assert.deepEqual(f.rendered, ["fresh"]);
    });
  }
}

test("opening async scanner settings cancels Compare before scanner configuration arrives", async () => {
  const f = fixture(), comparison = f.context.openCompareModal("target");
  const scanner = f.context.openScannerSettings();
  f.resolvePair(); await comparison;
  assert.equal(f.hidden(), true);
  assert.deepEqual(f.rendered, []);
  f.scannerLoad.resolve({ rules: {}, custom_rules: [] }); await scanner;
  assert.equal(f.nodes.scannerSettingsBackdrop.classList.contains("hidden"), false);
});

test("a visible scanner dialog joins modal precedence even when already open before the Compare request", async () => {
  const f = fixture(); await f.openDialog("scanner");
  const loading = f.context.openCompareModal("target");
  f.resolvePair(); await loading;
  assert.equal(f.hidden(), true);
  assert.equal(f.context.getActiveModalAction()?.modal, f.nodes.scannerSettingsBackdrop);
  assert.equal(f.document.activeElement, f.nodes.scannerSettingsClose);
});

for (const key of ["Escape", "Enter"]) {
  test(`a confirmation over scanner settings owns ${key} without closing or saving scanner`, async () => {
    const f = fixture(); await f.openDialog("scanner");
    f.context.showConfirmDialog("Synthetic confirmation", () => f.actions.push("confirmed"));
    f.key(key);
    assert.equal(f.nodes.scannerSettingsBackdrop.classList.contains("hidden"), false);
    assert.equal(f.context.activeConfirmDialog, null);
    assert.deepEqual(f.actions, []);
  });
}

for (const control of ["scannerSettingsClose", "scannerSettingsCancel", "scannerSettingsSave"]) {
  for (const key of ["Enter", " "]) {
    test(`scanner ${control} preserves native ${key === " " ? "Space" : key} activation`, async () => {
      const f = fixture(); await f.openDialog("scanner");
      f.key(key, f.nodes[control]);
      assert.deepEqual(f.actions, control === "scannerSettingsSave" ? ["scanner save"] : []);
      assert.equal(f.nodes.scannerSettingsBackdrop.classList.contains("hidden"), control !== "scannerSettingsSave");
    });
  }
}

for (const options of [{ isComposing: true }, { defaultPrevented: true }]) {
  test(`scanner leaves ${Object.keys(options)[0]} Escape alone`, async () => {
    const f = fixture(); await f.openDialog("scanner");
    f.key("Escape", f.nodes.scannerSettingsClose, options);
    assert.equal(f.nodes.scannerSettingsBackdrop.classList.contains("hidden"), false);
  });
}

for (const shiftKey of [false, true]) {
  test(`scanner confines ${shiftKey ? "Shift+Tab" : "Tab"} to enabled visible controls`, async () => {
    const f = fixture(); await f.openDialog("scanner");
    const target = shiftKey ? f.nodes.scannerSettingsClose : f.nodes.scannerSettingsSave;
    assert.equal(f.key("Tab", target, { shiftKey }).defaultPrevented, true);
    assert.equal(f.document.activeElement, shiftKey ? f.nodes.scannerSettingsSave : f.nodes.scannerSettingsClose);
  });
}

for (const dialog of ["settings", "filter", "confirm", "curl", "scanner"]) {
  test(`newer ${dialog} cancels only a pending replacement and preserves the visible comparison`, async () => {
    const f = fixture(), first = f.context.openCompareModal("first");
    f.resolvePair(0, "first"); await first;
    const parsing = deferred(), replacement = f.context.openCompareModal("late");
    f.pending[2].resolve({ ok: true, json: async () => ({ id: "base" }) });
    f.pending[3].resolve({ ok: true, json: () => parsing.promise });
    await Promise.resolve();
    await f.openDialog(dialog);
    if (dialog === "scanner") {
      // Scanner is async and lower in the DOM: it must not appear underneath
      // an already visible comparison while taking its keyboard ownership.
      assert.equal(f.nodes.scannerSettingsBackdrop.classList.contains("hidden"), true);
    } else f.key("Escape");
    parsing.resolve({ id: "late" }); await replacement;
    assert.equal(f.hidden(), false);
    assert.deepEqual(f.rendered, ["first"]);
    assert.equal(f.context.compareTargetRecord.id, "first");
    f.key("Escape");
    assert.equal(f.hidden(), true);
    assert.equal(f.document.activeElement, f.nodes.opener);
  });
}


test("Compare closing after navigation skips both a hidden invoker and the now-hidden history region", async () => {
  const f = fixture(), loading = f.context.openCompareModal("target");
  // The context menu closes after Compare is requested. Navigation can still
  // hide HTTP history while the two record reads are pending.
  f.nodes.opener.classList.add("hidden");
  f.context.state.activeProxyTab = "findings";
  f.context.renderProxyPanels();
  assert.equal(f.nodes.trafficRegion.getClientRects().length, 0);
  f.resolvePair(); await loading;
  assert.equal(f.hidden(), false);
  f.key("Escape");
  assert.equal(f.hidden(), true);
  assert.equal(f.document.activeElement, f.nodes.mainTab);
});


for (const navigation of ["tool", "proxy tab", "session"]) {
  for (const returnBeforeResponse of [false, true]) {
    test(`scanner config read cannot reopen after ${navigation} navigation${returnBeforeResponse ? " and back" : ""}; a fresh open works`, async () => {
      const f = fixture();
      f.context.state.activeProxyTab = "findings";
      const opening = f.context.openScannerSettings();
      const navigateAway = () => {
        if (navigation === "tool") { f.context.setActiveTool("replay"); f.context.renderToolPanels(); }
        if (navigation === "proxy tab") { f.context.setActiveProxyTab("http-history"); f.context.renderProxyPanels(); }
        if (navigation === "session") { f.context.sessionId = "session-b"; f.context.resetScannerConfigUiState(); }
      };
      const navigateBack = () => {
        if (navigation === "tool") { f.context.setActiveTool("proxy"); f.context.renderToolPanels(); }
        if (navigation === "proxy tab") { f.context.setActiveProxyTab("findings"); f.context.renderProxyPanels(); }
        if (navigation === "session") { f.context.sessionId = "session-a"; f.context.resetScannerConfigUiState(); }
      };
      navigateAway();
      if (returnBeforeResponse) navigateBack();
      f.scannerLoad.resolve({ rules: {}, custom_rules: [] }); await opening;
      assert.equal(f.nodes.scannerSettingsBackdrop.classList.contains("hidden"), true);
      assert.equal(f.context.scannerSettingsBaseline, null);
      assert.equal(f.context.getActiveModalAction(), null);
      if (navigation === "tool" && !returnBeforeResponse) {
        for (const modifier of ["ctrlKey", "metaKey"]) f.key("r", f.nodes.replayShell, { [modifier]: true });
        assert.deepEqual(f.actions, ["duplicate replay", "duplicate replay"]);
      }
      if (!returnBeforeResponse) navigateBack();
      const freshRead = deferred();
      f.context.loadScannerConfig = () => freshRead.promise;
      const fresh = f.context.openScannerSettings();
      freshRead.resolve({ rules: {}, custom_rules: [] }); await fresh;
      assert.equal(f.nodes.scannerSettingsBackdrop.classList.contains("hidden"), false);
      assert.equal(f.context.getActiveModalAction()?.modal, f.nodes.scannerSettingsBackdrop);
      f.context.setActiveTool("proxy"); f.context.setActiveProxyTab("findings");
      assert.equal(f.nodes.scannerSettingsBackdrop.classList.contains("hidden"), false, "Same-view selection preserves the current draft");
      f.key("Escape");
      assert.equal(f.context.getActiveModalAction(), null);
    });
  }
}

test("scanner reveal and modal ownership both require its Capture ancestor to be laid out", async () => {
  const f = fixture(), opening = f.context.openScannerSettings();
  f.nodes.proxyShell.classList.add("hidden");
  f.scannerLoad.resolve({ rules: {}, custom_rules: [] }); await opening;
  assert.equal(f.nodes.scannerSettingsBackdrop.classList.contains("hidden"), true);
  assert.equal(f.context.scannerSettingsBaseline, null);
  f.nodes.proxyShell.classList.remove("hidden");
  await f.context.openScannerSettings();
  assert.equal(f.context.getActiveModalAction()?.modal, f.nodes.scannerSettingsBackdrop);
  f.nodes.proxyShell.classList.add("hidden");
  assert.equal(f.context.getActiveModalAction(), null);
});


test("late scanner config after leaving Findings cannot take focus from a newer Compare", async () => {
  const f = fixture();
  f.context.state.activeProxyTab = "findings";
  const scanner = f.context.openScannerSettings();
  f.context.setActiveProxyTab("http-history"); f.context.renderProxyPanels();
  const comparison = f.context.openCompareModal("target");
  f.resolvePair(); await comparison;
  f.scannerLoad.resolve({ rules: {}, custom_rules: [] }); await scanner;
  assert.equal(f.context.getActiveModalAction()?.modal, f.nodes.compareModal);
  assert.equal(f.nodes.scannerSettingsBackdrop.classList.contains("hidden"), true);
  assert.equal(f.document.activeElement, f.nodes.closeCompareButton);
  f.key("Tab", f.nodes.opener);
  assert.equal(f.document.activeElement, f.nodes.closeCompareButton);
  f.key("Escape");
  assert.equal(f.context.getActiveModalAction(), null);
});

for (const dialog of ["settings", "filter", "confirm", "curl"]) {
  test(`scanner configuration arriving under newer ${dialog} does not reveal another modal`, async () => {
    const f = fixture(), scanner = f.context.openScannerSettings();
    await f.openDialog(dialog);
    const active = f.context.getActiveModalAction();
    const focus = f.document.activeElement;
    f.scannerLoad.resolve({ rules: {}, custom_rules: [] }); await scanner;
    assert.equal(f.nodes.scannerSettingsBackdrop.classList.contains("hidden"), true);
    assert.equal(f.context.scannerSettingsBaseline, null);
    assert.equal(f.context.getActiveModalAction()?.close, active.close);
    assert.equal(f.document.activeElement, focus);
  });
}

for (const dialog of ["settings", "filter", "confirm", "curl"]) {
  for (const dismissal of ["Escape", "close"]) {
    test(`scanner configuration arriving after newer ${dialog} is ${dismissal}-closed stays cancelled`, async () => {
      const f = fixture(), scanner = f.context.openScannerSettings();
      await f.openDialog(dialog);
      if (dismissal === "Escape") f.key("Escape");
      else ({ settings: f.context.closeDisplaySettingsModal, filter: f.context.closeFilterModal,
        confirm: () => f.context.activeConfirmDialog.close(), curl: f.context.closeCurlImportModal })[dialog]();
      f.nodes.mainTab.focus();
      f.scannerLoad.resolve({ rules: {}, custom_rules: [] }); await scanner;
      assert.equal(f.nodes.scannerSettingsBackdrop.classList.contains("hidden"), true);
      assert.equal(f.context.scannerSettingsBaseline, null);
      assert.equal(f.context.getActiveModalAction(), null);
      assert.equal(f.document.activeElement, f.nodes.mainTab);
      await f.context.openScannerSettings();
      assert.equal(f.nodes.scannerSettingsBackdrop.classList.contains("hidden"), false, "a fresh scanner request still opens");
    });
  }
}

test("Escape before scanner configuration arrives cancels its pending reveal", async () => {
  const f = fixture(), scanner = f.context.openScannerSettings();
  f.key("Escape");
  f.scannerLoad.resolve({ rules: {}, custom_rules: [] }); await scanner;
  assert.equal(f.nodes.scannerSettingsBackdrop.classList.contains("hidden"), true);
  assert.equal(f.context.scannerSettingsBaseline, null);
  assert.equal(f.document.activeElement, f.nodes.opener);
});

for (const dialog of ["settings", "filter", "confirm", "curl"]) {
  test(`scanner failure arriving after newer ${dialog} is dismissed stays silent`, async () => {
    const f = fixture(), scanner = f.context.openScannerSettings();
    await f.openDialog(dialog); f.key("Escape");
    f.scannerLoad.reject(new Error("Synthetic old configuration read")); await scanner;
    assert.equal(f.nodes.scannerSettingsBackdrop.classList.contains("hidden"), true);
    assert.deepEqual(f.actions, []);
    assert.deepEqual(f.errors, []);
  });
}

const scannerTick = () => new Promise(resolve => setImmediate(resolve));

test("scanner async reveal moves focus away from background Findings search", async () => {
  const f = fixture(); f.nodes.findingsSettingsButton.focus(); f.nodes.findingsSettingsButton.click();
  assert.equal(f.nodes.findingsSettingsButton.disabled, true, "the real progress wrapper runs");
  f.nodes.findingsFilterSearch.focus();
  f.scannerLoad.resolve({ rules: {}, custom_rules: [] }); await scannerTick();
  assert.equal(f.nodes.findingsSettingsButton.disabled, false);
  assert.equal(f.document.activeElement, f.nodes.scannerSettingsClose);
  assert.equal(f.context.getActiveModalAction()?.modal, f.nodes.scannerSettingsBackdrop);
});

for (const dismissal of ["Escape", "Cancel", "Close", "backdrop"]) {
  test(`scanner ${dismissal} restores its invoker after asynchronous opening`, async () => {
    const f = fixture(); f.nodes.findingsSettingsButton.focus(); f.nodes.findingsSettingsButton.click();
    f.scannerLoad.resolve({ rules: {}, custom_rules: [] }); await scannerTick();
    assert.equal(f.document.activeElement, f.nodes.scannerSettingsClose);
    if (dismissal === "Escape") f.key("Escape");
    if (dismissal === "Cancel") f.nodes.scannerSettingsCancel.click();
    if (dismissal === "Close") f.nodes.scannerSettingsClose.click();
    if (dismissal === "backdrop") { f.document.body.focus(); f.nodes.scannerSettingsBackdrop.click(); }
    assert.equal(f.document.activeElement, f.nodes.findingsSettingsButton);
    assert.equal(f.nodes.scannerSettingsBackdrop.classList.contains("hidden"), true);
    assert.deepEqual(f.actions, []);
  });
}

for (const unavailable of ["hidden", "disabled", "detached"]) {
  test(`scanner dismissal falls back when its original invoker is ${unavailable}`, async () => {
    const f = fixture(); f.nodes.opener.focus(); await f.openDialog("scanner");
    if (unavailable === "hidden") f.nodes.opener.classList.add("hidden");
    if (unavailable === "disabled") f.nodes.opener.disabled = true;
    if (unavailable === "detached") f.nodes.opener.remove();
    f.key("Escape"); assert.equal(f.document.activeElement, f.nodes.findingsSettingsButton);
  });
}

test("closing scanner below a confirmation preserves the newer focus", async () => {
  const f = fixture(); await f.openDialog("scanner"); f.context.showConfirmDialog("Synthetic", () => {});
  const focused = f.document.activeElement;
  f.context.closeScannerSettings(); assert.equal(f.document.activeElement, focused);
});

test("scanner dismissal during workspace navigation does not reclaim the new focus", async () => {
  const f = fixture(); await f.openDialog("scanner"); f.nodes.mainTab.focus();
  f.context.setActiveTool("replay");
  assert.equal(f.document.activeElement, f.nodes.mainTab);
});

test("typing after scanner reveal cannot edit the background Findings search", async () => {
  const f = fixture(); f.nodes.findingsSettingsButton.focus(); f.nodes.findingsSettingsButton.click();
  f.nodes.findingsFilterSearch.value = "before"; f.nodes.findingsFilterSearch.focus();
  f.scannerLoad.resolve({ rules: {}, custom_rules: [] }); await scannerTick();
  f.key("x");
  assert.equal(f.nodes.findingsFilterSearch.value, "before");
  assert.equal(f.document.activeElement, f.nodes.scannerSettingsClose);
});

test("scanner Close uses the active main tab when neither original focus nor its gear is available", async () => {
  const f = fixture(); await f.openDialog("scanner");
  f.nodes.opener.remove(); f.nodes.findingsSettingsButton.disabled = true;
  f.key("Escape"); assert.equal(f.document.activeElement, f.nodes.mainTab);
});
