// Local synthetic modal interactions. Register production callbacks and the
// complete keyboard dispatcher in init order; native Tab/activation are modeled
// from the real cURL control order. No app bootstrap, API or browser starts.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
const indexSource = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');

function fixture() {
  const nodes = new Map(), listeners = new Map(), actions = [];
  const document = { activeElement: null, readyState: 'loading' };
  class Element {
    constructor(id, tagName = 'DIV', parent = null) {
      Object.assign(this, { id, tagName, parentElement: parent, children: [], handlers: new Map(), dataset: {},
        attributes: new Map(), disabled: false, isConnected: true, visibility: 'visible', value: '',
        tabIndex: ['BUTTON', 'TEXTAREA'].includes(tagName) ? 0 : -1 });
      const classes = new Set();
      this.classList = { add: (...xs) => xs.forEach(x => classes.add(x)), remove: (...xs) => xs.forEach(x => classes.delete(x)),
        contains: x => classes.has(x) };
      parent?.children.push(this); nodes.set(id, this);
    }
    getClientRects() {
      return this.isConnected && !this.classList.contains('hidden') && this.visibility !== 'hidden'
        && (!this.parentElement || this.parentElement.getClientRects().length) ? [1] : [];
    }
    focus() { if (!this.disabled && this.getClientRects().length) document.activeElement = this; }
    contains(node) { return this === node || this.children.some(child => child.contains(node)); }
    remove() { this.isConnected = false; this.children.forEach(child => child.remove()); }
    matches(selector) { return selector.split(',').some(part => part.trim() === this.tagName.toLowerCase()); }
    closest(selector) { return this.matches(selector) ? this : this.parentElement?.closest(selector) || null; }
    getAttribute(name) { return this.attributes.get(name); }
    setAttribute(name, value) { this.attributes.set(name, value); }
    querySelectorAll() { return this.children.flatMap(child => [child, ...child.querySelectorAll()]); }
    querySelector(selector) { return this.querySelectorAll().find(node => node.classList.contains(selector.slice(1))) || null; }
    addEventListener(type, callback) {
      if (!this.handlers.has(type)) this.handlers.set(type, []);
      this.handlers.get(type).push(callback);
    }
    click() {
      if (this.disabled) return;
      for (let node = this; node; node = node.parentElement)
        for (const callback of node.handlers.get('click') || []) callback({ target: this });
    }
  }
  document.body = new Element('body', 'BODY');
  document.body.appendChild = () => {};
  document.getElementById = id => nodes.get(id) || null;
  document.addEventListener = (type, callback) => {
    if (!listeners.has(type)) listeners.set(type, []);
    listeners.get(type).push(callback);
  };
  document.querySelectorAll = () => [];
  const mainTab = new Element('mainTab', 'BUTTON', document.body); mainTab.dataset.tool = 'fuzzer';
  const opener = new Element('replayRequestHighlight', 'PRE', document.body); opener.tabIndex = 0;
  const els = {};
  for (const id of ['displaySettingsModal', 'filterModal', 'scannerSettingsBackdrop', 'compareModal', 'curlImportModal']) {
    els[id] = new Element(id, 'DIV', document.body); els[id].classList.add('hidden');
  }
  const modal = els.curlImportModal;
  const markup = indexSource.slice(indexSource.indexOf('<div class="modal-backdrop hidden" id="curlImportModal">'), indexSource.indexOf('<div class="context-menu hidden" id="replayContextMenu">'));
  for (const [, tag, id] of markup.matchAll(/<(textarea|button)[^>]*id="([^"]+)"[^>]*>/g)) new Element(id, tag.toUpperCase(), modal);
  assert.deepEqual(modal.children.map(node => node.id), ['curlImportInput', 'closeCurlImportButton', 'applyCurlImportButton']);
  document.querySelector = () => mainTab;
  document.createElement = () => {
    const confirm = new Element('confirm', 'DIV', document.body);
    for (const name of ['cancel', 'ok']) new Element(name, 'BUTTON', confirm).classList.add(`confirm-dialog-${name}`);
    return confirm;
  };
  document.activeElement = opener;
  const state = { activeTool: 'replay', replayTabs: [], activeReplayTabId: null };
  const context = loadFunctions([
    'openCurlImportModal', 'closeCurlImportModal', 'getActiveModalAction', 'isModalVisible', 'trapModalFocus', 'restoreModalFocus',
    'showConfirmDialog', 'isEditableTarget', 'setActiveTool',
  ], {
    document, els, Element, HTMLElement: Element, state, mainTabs: [mainTab],
    window: { getComputedStyle: node => ({ visibility: node.visibility }), getSelection: () => null },
    compareLoadGeneration: 0, curlImportReturnFocus: null, activeConfirmDialog: null,
    applyCurlImport: () => actions.push('import'), renderToolPanels: () => actions.push('navigate'),
    sanitizeActiveTool: x => x, closeScannerSettings() {}, scheduleUiSettingsSave() {},
    escapeHtml: x => x, closeCompareModal() {}, closeDisplaySettingsModal() {}, closeCertificateModal() {}, closeFilterModal() {},
    duplicateActiveReplayTab: () => actions.push('duplicate'), getSelectedCodePaneText: () => '',
  });
  function register(startMarker, endMarker) {
    const start = appSource.indexOf(startMarker), end = appSource.indexOf(endMarker, start);
    assert.ok(start >= 0 && end > start, startMarker);
    vm.runInContext(appSource.slice(start, end), context);
  }
  register('(function initCodeViewLineNav() {', '\n\n// ─── CodeMirror 6 Integration');
  register('  mainTabs.forEach((tab) => {', '\n\n  proxyTabs.forEach((tab) => {');
  register('  document.getElementById("closeCurlImportButton").addEventListener(', '\n\n  els.applyDisplaySettingsButton.addEventListener(');
  register('  document.addEventListener("keydown", (event) => {\n    const activeModalAction', '\n\n  document.addEventListener("copy",');
  for (const callback of listeners.get('DOMContentLoaded') || []) callback();
  function key(key, options = {}) {
    const target = document.activeElement;
    const event = { key, target, defaultPrevented: false, ctrlKey: false, metaKey: false, altKey: false, shiftKey: false,
      preventDefault() { this.defaultPrevented = true; }, ...options };
    for (let node = target; node; node = node.parentElement)
      for (const callback of node.handlers.get('keydown') || []) callback(event);
    for (const callback of listeners.get('keydown') || []) callback(event);
    if (!event.defaultPrevented && key === 'Tab') {
      const controls = document.body.querySelectorAll().filter(node => !node.disabled && node.tabIndex >= 0 && node.getClientRects().length);
      const offset = event.shiftKey ? -1 : 1;
      controls[(controls.indexOf(document.activeElement) + controls.length + offset) % controls.length]?.focus();
    }
    if (!event.defaultPrevented && ['Enter', ' '].includes(key) && target.tagName === 'BUTTON') target.click();
    if (!event.defaultPrevented && key === 'Enter' && target.tagName === 'TEXTAREA') target.value += '\n';
    return event;
  }
  return { context, nodes, document, modal, mainTab, opener, state, actions, key,
    input: nodes.get('curlImportInput'), cancel: nodes.get('closeCurlImportButton'), apply: nodes.get('applyCurlImportButton') };
}

for (const shiftKey of [false, true]) test(`cURL confines ${shiftKey ? 'Shift+Tab' : 'Tab'} instead of activating the workspace`, () => {
  const f = fixture(); f.context.openCurlImportModal();
  (shiftKey ? f.input : f.apply).focus();
  assert.equal(f.key('Tab', { shiftKey }).defaultPrevented, true);
  assert.equal(f.document.activeElement, shiftKey ? f.apply : f.input);
  assert.ok(f.modal.contains(f.document.activeElement));
  if (!shiftKey) { f.key('Enter'); assert.deepEqual(f.actions, []); }
  assert.equal(f.state.activeTool, 'replay');
});

for (const dismissal of ['Escape', 'Cancel', 'backdrop']) test(`cURL ${dismissal} returns focus to its invoking editor`, () => {
  const f = fixture(); f.context.openCurlImportModal();
  if (dismissal === 'Escape') f.key('Escape');
  if (dismissal === 'Cancel') { f.cancel.focus(); f.key('Enter'); }
  if (dismissal === 'backdrop') { f.document.body.focus(); f.modal.click(); }
  assert.equal(f.modal.classList.contains('hidden'), true);
  assert.equal(f.document.activeElement, f.opener);
  assert.deepEqual(f.actions, []);
});

for (const unavailable of ['detached', 'hidden', 'disabled']) test(`cURL dismissal falls back when the invoking editor is ${unavailable}`, () => {
  const f = fixture(); f.context.openCurlImportModal();
  if (unavailable === 'detached') f.opener.remove();
  if (unavailable === 'hidden') f.opener.classList.add('hidden');
  if (unavailable === 'disabled') f.opener.disabled = true;
  f.key('Escape'); assert.equal(f.document.activeElement, f.mainTab);
});

test('repeated cURL opening preserves its draft and original invoker', () => {
  const f = fixture(); f.context.openCurlImportModal(); f.input.value = 'curl https://example.com/';
  f.cancel.focus(); f.context.openCurlImportModal();
  assert.equal(f.input.value, 'curl https://example.com/');
  assert.equal(f.document.activeElement, f.cancel);
  f.key('Escape'); assert.equal(f.document.activeElement, f.opener);
  f.context.openCurlImportModal(); assert.equal(f.input.value, '', 'a fresh opening still starts a new import');
});

test('closing an already hidden cURL dialog leaves newer focus alone', () => {
  const f = fixture(); f.context.openCurlImportModal(); f.key('Escape');
  f.mainTab.focus(); f.context.closeCurlImportModal(); assert.equal(f.document.activeElement, f.mainTab);
});

test('a newer confirmation keeps focus when the underlying cURL dialog closes', () => {
  const f = fixture(); f.context.openCurlImportModal(); f.context.showConfirmDialog('Synthetic confirmation', () => f.actions.push('confirm'));
  const focused = f.document.activeElement;
  f.context.closeCurlImportModal(); assert.equal(f.document.activeElement, focused);
  f.key('Escape'); assert.equal(f.document.activeElement, f.mainTab, 'the hidden import control cannot receive restored focus');
  assert.deepEqual(f.actions, []);
});

for (const options of [{ isComposing: true }, { defaultPrevented: true }]) test(`cURL preserves ${Object.keys(options)[0]} Escape`, () => {
  const f = fixture(); f.context.openCurlImportModal(); f.key('Escape', options);
  assert.equal(f.modal.classList.contains('hidden'), false); assert.equal(f.document.activeElement, f.input);
});

test('cURL text Enter stays multiline and native Import activates once', () => {
  const f = fixture(); f.context.openCurlImportModal();
  f.key('Enter'); assert.equal(f.input.value, '\n'); assert.deepEqual(f.actions, []);
  f.apply.focus(); f.key('Enter'); assert.deepEqual(f.actions, ['import']);
});

for (const key of ['r', 'f']) test(`cURL blocks background ${key} shortcuts while closed dialogs release them`, () => {
  const f = fixture(); f.context.openCurlImportModal(); f.apply.focus();
  f.key(key, { ctrlKey: true, shiftKey: key === 'f' }); assert.deepEqual(f.actions, []);
  f.key('Escape'); f.key(key, { ctrlKey: true, shiftKey: key === 'f' });
  assert.deepEqual(f.actions, [key === 'f' ? 'navigate' : 'duplicate']);
});

test('Tab followed by Enter at the Import boundary cannot activate a background tool', () => {
  const f = fixture(); f.context.openCurlImportModal(); f.apply.focus();
  f.key('Tab'); f.key('Enter');
  assert.equal(f.state.activeTool, 'replay');
  assert.deepEqual(f.actions, []);
  assert.equal(f.document.activeElement, f.input);
});
