// Synthetic ordinary modal checks: no app bootstrap, API, or saved data.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture() {
  const nodes = [], writes = [], applied = [];
  const document = { activeElement: null };
  function element(tag = "BUTTON") {
    const handlers = new Map(), classes = new Set();
    const node = {
      tagName: tag, type: tag === "INPUT" ? "text" : "button", tabIndex: 0,
      isConnected: true, disabled: false, children: [], visibility: "visible",
      classList: { add: (...xs) => xs.forEach(x => classes.add(x)), remove: (...xs) => xs.forEach(x => classes.delete(x)), contains: x => classes.has(x) },
      focus() { if (node.isConnected && !node.disabled) document.activeElement = node; },
      getClientRects: () => [1],
      addEventListener(type, callback) { handlers.set(type, callback); },
      dispatch(type, event = {}) { handlers.get(type)?.({ target: node, ...event }); },
      querySelectorAll: () => node.children,
      contains: candidate => node === candidate || node.children.includes(candidate),
      remove() { node.isConnected = false; for (const child of node.children) child.isConnected = false; },
    };
    nodes.push(node);
    return node;
  }
  const opener = element(), fallback = element(), close = element();
  document.activeElement = opener;
  document.querySelector = () => fallback;
  document.body = { appendChild() {} };
  document.createElement = () => {
    const modal = element("DIV"), cancel = element(), ok = element();
    modal.children = [cancel, ok];
    modal.querySelector = selector => selector === ".confirm-dialog-cancel" ? cancel : ok;
    return modal;
  };
  const display = element("DIV"), filter = element("DIV"), curl = element("DIV");
  display.children = [close];
  for (const modal of [display, filter, curl]) modal.classList.add("hidden");
  const els = { displaySettingsModal: display, closeDisplaySettingsButton: close, openDisplaySettingsButton: opener, filterModal: filter, curlImportModal: curl };
  const functions = ["showConfirmDialog", "openDisplaySettingsModal", "closeDisplaySettingsModal", "getActiveModalAction", "isModalVisible"];
  for (const name of ["restoreModalFocus", "trapModalFocus"]) {
    if (appSource.includes(`function ${name}(`)) functions.push(name);
  }
  const context = loadFunctions(functions, {
    document, els, displaySettingsPreviewActive: false, displaySettingsReturnFocus: null, activeConfirmDialog: null,
    hydrateDisplaySettingsForm() {}, renderShortcutReference() {}, selectSettingsTab() {},
    applyDisplaySettingsState: () => applied.push("saved"),
    saveDisplaySettingsFromForm: () => writes.push("settings"),
    applyFilterSettings: () => writes.push("filters"), closeFilterModal() {}, closeCertificateModal() {}, closeCurlImportModal() {},
    escapeHtml: text => String(text).replace(/[&<>"']/g, "_"),
    window: { getComputedStyle: node => ({ visibility: node.visibility }) },
  });
  close.addEventListener("click", context.closeDisplaySettingsModal);
  document.addEventListener = (_, handler) => { context.keydown = handler; };
  const start = appSource.indexOf('  document.addEventListener("keydown", (event) => {\n    const activeModalAction');
  const end = appSource.indexOf('    if (\n      !event.defaultPrevented', start);
  assert.ok(start !== -1 && end > start);
  vm.runInContext(appSource.slice(start, end) + "  });", context);
  function key(key, target = document.activeElement, options = {}) {
    const event = { key, target, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, ...options };
    context.keydown(event);
    if (key === "Enter" && !event.defaultPrevented && target?.tagName === "BUTTON") target.dispatch("click");
    return event;
  }
  return { context, document, element, nodes, writes, applied, opener, fallback, close, display, key };
}

for (const control of ["Close", "Reset", "tab", "link", "select", "textarea"]) {
  test(`Enter on Settings ${control} preserves its native action instead of saving`, () => {
    const f = fixture();
    f.context.openDisplaySettingsModal();
    const target = control === "Close" ? f.close : f.element({ link: "A", select: "SELECT", textarea: "TEXTAREA" }[control] || "BUTTON");
    f.display.children.push(target);
    const event = f.key("Enter", target);
    assert.equal(f.writes.length, 0, "Close or another control must not become Apply");
    assert.equal(event.defaultPrevented, false);
    if (control === "Close") assert.equal(f.display.classList.contains("hidden"), true);
  });
}

test("Enter in the Settings text-size input still applies once", () => {
  const f = fixture();
  f.context.openDisplaySettingsModal();
  const input = f.element("INPUT"); input.type = "number";
  const event = f.key("Enter", input);
  assert.equal(event.defaultPrevented, true);
  assert.equal(f.writes.length, 1);
});

test("an already handled or composing Enter does not apply Settings", () => {
  const f = fixture(); f.context.openDisplaySettingsModal();
  f.key("Enter", f.element("INPUT"), { defaultPrevented: true });
  f.key("Enter", f.element("INPUT"), { isComposing: true });
  assert.equal(f.writes.length, 0);
});

test("Settings opens inside the modal and Close restores the invoker", () => {
  const f = fixture();
  f.context.openDisplaySettingsModal();
  assert.equal(f.document.activeElement, f.close);
  f.context.openDisplaySettingsModal();
  f.context.closeDisplaySettingsModal();
  assert.equal(f.document.activeElement, f.opener, "repeated open must preserve the original invoker");
  const elsewhere = f.element(); elsewhere.focus();
  f.context.closeDisplaySettingsModal();
  assert.equal(f.document.activeElement, elsewhere, "closing an already hidden modal must not steal focus");
});

test("Settings Escape reverts its preview without saving and restores focus", () => {
  const f = fixture(); f.context.openDisplaySettingsModal();
  f.context.displaySettingsPreviewActive = true;
  f.close.focus();
  f.key("Escape", f.close);
  assert.equal(f.display.classList.contains("hidden"), true);
  assert.equal(f.context.displaySettingsPreviewActive, false);
  assert.equal(f.writes.length, 0);
  assert.equal(f.document.activeElement, f.opener);
});

for (const action of ["Escape", "Cancel", "backdrop", "confirm"]) {
  test(`confirmation ${action} closes, restores focus, and invokes only an explicit confirm`, () => {
    const f = fixture(); let confirmed = 0;
    f.context.showConfirmDialog("Synthetic confirmation", () => confirmed++);
    const modal = f.nodes.find(node => node.innerHTML?.includes("confirm-dialog-cancel"));
    const [cancel, ok] = modal.children;
    assert.equal(f.document.activeElement, cancel, "Cancel is the safe initial focus");
    assert.match(modal.innerHTML, /role="(?:alert)?dialog"/);
    assert.match(modal.innerHTML, /aria-modal="true"/);
    assert.match(modal.innerHTML, /aria-describedby="confirm-dialog-message"/);
    assert.match(modal.innerHTML, /id="confirm-dialog-message"/);
    if (action === "Escape") f.key("Escape");
    else if (action === "backdrop") modal.dispatch("click");
    else f.key("Enter", action === "confirm" ? ok : cancel);
    assert.equal(modal.isConnected, false);
    assert.equal(confirmed, action === "confirm" ? 1 : 0);
    assert.equal(f.document.activeElement, f.opener);
    assert.equal(f.context.getActiveModalAction(), null);
  });
}

test("confirmation Tab and Shift+Tab stay within enabled visible controls", () => {
  const f = fixture(); f.context.showConfirmDialog("Synthetic", () => {});
  const modal = f.nodes.find(node => node.innerHTML?.includes("confirm-dialog-cancel"));
  const [cancel, ok] = modal.children;
  cancel.focus(); f.key("Tab", cancel, { shiftKey: true });
  assert.equal(f.document.activeElement, ok);
  ok.focus(); f.key("Tab", ok);
  assert.equal(f.document.activeElement, cancel);
});

test("Settings Tab skips hidden panels and disabled controls", () => {
  const f = fixture(); f.context.openDisplaySettingsModal();
  const last = f.element(), hidden = f.element(), disabled = f.element();
  hidden.visibility = "hidden"; disabled.disabled = true;
  f.display.children.push(last, hidden, disabled);
  last.focus(); f.key("Tab", last);
  assert.equal(f.document.activeElement, f.close);
  f.close.focus(); f.key("Tab", f.close, { shiftKey: true });
  assert.equal(f.document.activeElement, last);
});

test("confirmation Cancel after its invoker is detached uses a visible fallback", () => {
  const f = fixture(); f.context.showConfirmDialog("Synthetic", () => {});
  const modal = f.nodes.find(node => node.innerHTML?.includes("confirm-dialog-cancel"));
  f.opener.remove();
  modal.children[0].dispatch("click");
  assert.equal(f.document.activeElement, f.fallback);
});

test("opening a replacement confirmation cancels the first without invoking it", () => {
  const f = fixture(); let confirmed = 0;
  f.context.showConfirmDialog("First", () => confirmed++);
  const first = f.nodes.find(node => node.innerHTML?.includes("confirm-dialog-cancel"));
  f.context.showConfirmDialog("Second", () => confirmed++);
  assert.equal(first.isConnected, false);
  f.key("Escape");
  assert.equal(confirmed, 0);
  assert.equal(f.document.activeElement, f.opener);
  assert.equal(f.context.getActiveModalAction(), null);
});

for (const shiftKey of [false, true]) {
  test(`Settings ${shiftKey ? "Shift+Tab" : "Tab"} recovers focus from a hidden tab panel`, () => {
    const f = fixture(); f.context.openDisplaySettingsModal();
    const last = f.element(), hidden = f.element();
    hidden.visibility = "hidden";
    f.display.children.push(last, hidden);
    hidden.focus();
    const event = f.key("Tab", hidden, { shiftKey });
    assert.equal(event.defaultPrevented, true);
    assert.equal(f.document.activeElement, shiftKey ? last : f.close);
  });
}
