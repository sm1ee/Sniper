// Synthetic DOM and local response sinks only. Run the actual service-map
// controller, app bridge and complete workspace key dispatcher in init order.
// Markup controls are derived from production output, including closed details.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
const serviceSource = fs.readFileSync(path.join(__dirname, '../web/service-map.js'), 'utf8');
const origin = 'https://api.example.com';
const row = '11111111-1111-4111-8111-111111111111';
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function apiDocument() {
  return { openapi: '3.1.0', servers: [{ url: origin }], paths: {
    '/items': { get: { 'x-sniper-newest-transaction': row, responses: { 200: { description: 'OK' } } } },
  } };
}
function fixture() {
  const document = { activeElement: null, readyState: 'loading' }, nodes = new Map();
  const listeners = new Map(), requests = [], copies = [], replays = [], toasts = [];
  document.addEventListener = (type, callback) => {
    if (!listeners.has(type)) listeners.set(type, []);
    listeners.get(type).push(callback);
  };
  class Element {
    constructor(tagName = 'DIV') {
      this.tagName = tagName; this.children = []; this.parentElement = null;
      this.dataset = {}; this.attributes = new Map(); this.handlers = new Map();
      this.disabled = false; this.tabIndex = ['BUTTON', 'SUMMARY'].includes(tagName) ? 0 : -1;
      this.isConnected = true; this.value = ''; this.style = {}; this.open = false;
      this.visibility = 'visible'; this.isContentEditable = false;
      const classes = new Set();
      this.classList = { contains: name => classes.has(name),
        add: name => classes.add(name), remove: name => classes.delete(name),
        toggle(name, on) { if (on) classes.add(name); else classes.delete(name); } };
    }
    setAttribute(name, value) { this.attributes.set(name, value); }
    getAttribute(name) { return this.attributes.get(name); }
    addEventListener(type, fn) {
      if (!this.handlers.has(type)) this.handlers.set(type, []);
      this.handlers.get(type).push(fn);
    }
    append(child) { child.parentElement = this; this.children.push(child); return child; }
    contains(node) { return this === node || this.children.some(child => child.contains(node)); }
    matches(selector) {
      return selector.split(',').some(part => {
        part = part.trim();
        if (/^[a-z]+$/.test(part)) return this.tagName.toLowerCase() === part;
        if (part === '[tabindex]') return this.attributes.has('tabindex');
        if (part.startsWith('.')) return this.classList.contains(part.slice(1));
        const data = part.match(/^\[data-([\w-]+)\]$/);
        if (data) return data[1].replace(/-([a-z])/g, (_, x) => x.toUpperCase()) in this.dataset;
        return false;
      });
    }
    closest(selector) { return this.matches(selector) ? this : this.parentElement?.closest(selector) || null; }
    querySelectorAll(selector) {
      return this.children.flatMap(child => [...(child.matches(selector) ? [child] : []), ...child.querySelectorAll(selector)]);
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    getClientRects() {
      if (!this.isConnected || this.classList.contains('hidden') || this.visibility === 'hidden') return [];
      if (this.parentElement?.tagName === 'DETAILS' && !this.parentElement.open && this.tagName !== 'SUMMARY') return [];
      return !this.parentElement || this.parentElement.getClientRects().length ? [1] : [];
    }
    focus() { if (!this.disabled && this.getClientRects().length) document.activeElement = this; }
    set innerHTML(html) {
      // Removing focused descendants returns focus to body, as native DOM does.
      for (const child of this.children) {
        if (child.contains(document.activeElement)) document.activeElement = document.body;
        const detach = node => { node.isConnected = false; node.children.forEach(detach); };
        detach(child);
      }
      this.children = []; this.html = html;
      if (this.id !== 'serviceMapApiDocs') return;
      const stack = [this];
      for (const [, closing, tag, attributes] of html.matchAll(/<(\/)?([a-z][\w-]*)([^>]*)>/gi)) {
        if (closing) { if (stack.length > 1) stack.pop(); continue; }
        const node = stack.at(-1).append(new Element(tag.toUpperCase()));
        for (const [, name, value = ''] of attributes.matchAll(/([\w-]+)(?:="([^"]*)")?/g)) {
          node.setAttribute(name, value);
          if (name.startsWith('data-')) node.dataset[name.slice(5).replace(/-([a-z])/g, (_, x) => x.toUpperCase())] = value;
          if (name === 'disabled') node.disabled = true;
          if (name === 'class') value.split(' ').forEach(cls => node.classList.add(cls));
          if (name === 'tabindex') node.tabIndex = Number(value);
        }
        if (!['input', 'br', 'hr'].includes(tag)) stack.push(node);
      }
    }
    get innerHTML() { return this.html || ''; }
    click() {
      if (this.disabled) return;
      const event = { target: this };
      for (let node = this; node; node = node.parentElement) {
        for (const callback of node.handlers.get('click') || []) callback(event);
      }
      if (this.tagName === 'SUMMARY') this.parentElement.open = !this.parentElement.open;
    }
  }
  document.body = new Element('BODY');
  document.getElementById = id => {
    if (!nodes.has(id)) { const node = new Element(); node.id = id; nodes.set(id, node); }
    return nodes.get(id);
  };
  const modal = document.getElementById('serviceMapApiDocs'); modal.classList.add('hidden');
  const panel = document.getElementById('targetServiceMapPanel');
  const opener = panel.append(new Element('BUTTON')); opener.dataset.serviceApiDocs = origin;
  const mapTab = new Element('BUTTON'); mapTab.dataset.targetView = 'service-map';
  const apisTab = new Element('BUTTON'); apisTab.dataset.targetView = 'apis';
  const mainTab = new Element('BUTTON'); mainTab.dataset.tool = 'map';
  document.querySelectorAll = selector => selector === '[data-target-view]' ? [mapTab, apisTab] : [];
  document.querySelector = selector => selector === '.main-tab.active' ? mainTab
    : selector.includes('data-target-view') ? [mapTab, apisTab].find(tab => tab.classList.contains('active'))
    : selector.includes('.modal-backdrop') && !modal.classList.contains('hidden') ? modal : null;
  const els = {};
  for (const name of ['displaySettingsModal', 'filterModal', 'curlImportModal', 'scannerSettingsBackdrop', 'compareModal']) {
    els[name] = document.getElementById(name); els[name].classList.add('hidden');
  }
  for (const name of ['dashboardShell', 'proxyShell', 'replayShell', 'toolsShell', 'fuzzerShell', 'sequenceShell', 'targetShell', 'mapShell', 'loggerShell', 'reconShell']) els[name] = new Element();
  els.mapShell.append(panel);
  document.activeElement = opener;
  const state = { activeTool: 'map', activeTargetView: 'service-map' };
  const window = { document, getComputedStyle: node => ({ visibility: node.visibility }) };
  const context = loadFunctions([
    'initializeTargetWorkspace', 'setActiveTargetView', 'retireFindingActionProgress', 'invalidateFindingNavigation', 'setActiveTool', 'renderToolPanels',
    'getActiveModalAction', 'isModalVisible', 'isEditableTarget', 'trapModalFocus', 'restoreModalFocus',
    'openCompareModal',
  ], {
    // This modal/clipboard fixture never mounts retained packets.
    packetViewerMarkup: null, mountServiceMapPacketViewer: null,
    window, document, Element, HTMLElement: Element, URL, URLSearchParams, AbortController, state, els,
    mainTabs: [mainTab], targetServiceMapController: null, activeConfirmDialog: null,
    compareBaseId: 'base', compareBaseSessionId: 'session-one', compareLoadGeneration: 0,
    compareBaseRecord: null, compareTargetRecord: null, compareReturnFocus: null, compareActiveTab: 'request',
    transactionPath: id => `/api/transactions/${id}`, renderCompareModal() {},
    currentSessionId: () => 'session-one', targetServiceMapEventStreamReady: () => true,
    serviceMapFilterQuery: () => ({}), serviceMapFilterSummary: () => null,
    sanitizeActiveTool: value => value, scheduleUiSettingsSave() {}, closeScannerSettings() {},
    renderFuzzer() {}, renderProxyPanels() {}, getSelectedCodePaneText: () => '',
    copyTextToClipboard: text => { copies.push(text); return Promise.resolve(); },
    loadTransactionRecordById: id => { replays.push(id); return Promise.resolve({ id }); },
    openTransactionRecordInReplay() {}, showToast: (...args) => toasts.push(args),
    closeCompareModal() {}, closeDisplaySettingsModal() {}, closeCertificateModal() {}, closeFilterModal() {}, closeCurlImportModal() {},
    saveDisplaySettingsFromForm() {}, applyFilterSettings() {},
    fetch(url, options) { const pending = { url, options, ...deferred() }; requests.push(pending); return pending.promise; },
  });
  vm.runInContext(serviceSource, context);
  // service-map.js loads before app.js; bindEvents initializes the Map before
  // installing the main document key handler. Readonly caret setup is top-level.
  const caretStart = appSource.indexOf('(function initCodeViewLineNav() {');
  const caretEnd = appSource.indexOf('\n\n// ─── CodeMirror 6 Integration', caretStart);
  vm.runInContext(appSource.slice(caretStart, caretEnd), context);
  context.initializeTargetWorkspace();
  const keyStart = appSource.indexOf('  document.addEventListener("keydown", (event) => {\n    const activeModalAction');
  const keyEnd = appSource.indexOf('\n\n  document.addEventListener("copy",', keyStart);
  assert.ok(keyStart >= 0 && keyEnd > keyStart);
  vm.runInContext(appSource.slice(keyStart, keyEnd), context);
  document.readyState = 'interactive';
  for (const callback of listeners.get('DOMContentLoaded') || []) callback();
  function key(key, target = document.activeElement, options = {}) {
    const event = { key, target, ctrlKey: false, metaKey: false, altKey: false, shiftKey: false,
      defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, ...options };
    for (let node = target; node; node = node.parentElement) {
      for (const callback of node.handlers.get('keydown') || []) callback(event);
    }
    for (const callback of listeners.get('keydown') || []) callback(event);
    if (!event.defaultPrevented && ['Enter', ' '].includes(key) && ['BUTTON', 'SUMMARY'].includes(target?.tagName)) target.click();
    return event;
  }
  return { context, document, state, modal, opener, panel, mapTab, apisTab, mainTab, nodes, els, copies, replays, toasts, requests, key, Element,
    controller: context.targetServiceMapController,
    open() { opener.focus(); opener.click(); return requests.at(-1); },
    async load(read) { read.resolve({ ok: true, json: async () => apiDocument() }); await tick(); },
    control(name) { return modal.querySelector(`[data-api-docs-${name}]`); },
  };
}
for (const modifier of ['ctrlKey', 'metaKey']) test(`API Docs blocks ${modifier}+Shift+F background navigation`, async () => {
  const f = fixture(); await f.load(f.open());
  f.key('f', f.control('close'), { [modifier]: true, shiftKey: true });
  assert.equal(f.state.activeTool, 'map');
  assert.ok(f.controller.getState().apiDocs);
});
for (const stage of ['loading', 'loaded', 'error']) for (const shiftKey of [false, true]) test(`API Docs ${stage} confines ${shiftKey ? 'Shift+Tab' : 'Tab'} including summaries`, async () => {
  const f = fixture(), read = f.open();
  if (stage === 'loaded') await f.load(read);
  if (stage === 'error') { read.reject(new Error('Synthetic unavailable')); await tick(); }
  const first = stage === 'loaded' ? f.modal.querySelector('summary') : f.control('close');
  const last = f.control('close');
  (shiftKey ? first : last).focus();
  assert.equal(f.key('Tab', f.document.activeElement, { shiftKey }).defaultPrevented, true);
  assert.equal(f.document.activeElement, shiftKey ? last : first);
});
for (const options of [{ isComposing: true }, { defaultPrevented: true }]) test(`API Docs respects ${Object.keys(options)[0]} Escape`, async () => {
  const f = fixture(); await f.load(f.open());
  f.key('Escape', f.control('close'), options);
  assert.ok(f.controller.getState().apiDocs);
});
for (const action of ['Escape', 'Close', 'backdrop']) test(`API Docs ${action} restores the invoking control`, async () => {
  const f = fixture(); await f.load(f.open());
  if (action === 'Escape') f.key('Escape');
  if (action === 'Close') f.control('close').click();
  if (action === 'backdrop') { f.document.body.focus(); f.modal.click(); }
  assert.equal(f.controller.getState().apiDocs, null);
  assert.equal(f.document.activeElement, f.opener);
});
for (const outcome of ['success', 'error']) test(`late API Docs ${outcome} does not steal focus from a newer confirmation`, async () => {
  const f = fixture(), read = f.open(), newer = new f.Element('BUTTON');
  f.context.activeConfirmDialog = { modal: new f.Element(), close() {} }; newer.focus();
  if (outcome === 'success') await f.load(read);
  else { read.reject(new Error('Synthetic unavailable')); await tick(); }
  assert.equal(f.document.activeElement, newer);
});
for (const key of ['Enter', ' ']) test(`native ${key === ' ' ? 'Space' : key} operates API Docs summaries and buttons`, async () => {
  const f = fixture(); await f.load(f.open());
  const summary = f.modal.querySelector('summary'); summary.focus();
  assert.equal(f.key(key).defaultPrevented, false); assert.equal(summary.parentElement.open, true);
  const replay = f.control('replay'); replay.focus();
  assert.equal(f.key('Tab', replay, { shiftKey: true }).defaultPrevented, false, 'open operation stays in native tab order');
  const copy = f.control('copy'); copy.focus(); assert.equal(f.key(key).defaultPrevented, false);
  await tick(); assert.equal(f.copies.length, 1); assert.equal(f.state.activeTool, 'map');
  f.control('close').focus(); assert.equal(f.key(key).defaultPrevented, false);
  assert.equal(f.controller.getState().apiDocs, null);
});
for (const stage of ['fetch', 'json']) test(`Escape cancels ${stage} without late focus changes and docs reopen`, async () => {
  const f = fixture(), read = f.open(), body = deferred();
  if (stage === 'json') { read.resolve({ ok: true, json: () => body.promise }); await tick(); }
  f.key('Escape');
  await f.load(f.open());
  const current = f.controller.getState().apiDocs, close = f.control('close');
  if (stage === 'json') body.resolve(apiDocument()); else read.resolve({ ok: true, json: async () => apiDocument() });
  await tick(); assert.equal(f.controller.getState().apiDocs, current); assert.equal(f.document.activeElement, close);
});
test('closed API Docs leaves the normal Fuzzer shortcut working', () => {
  const f = fixture();
  f.key('f', f.opener, { ctrlKey: true, shiftKey: true });
  assert.equal(f.state.activeTool, 'fuzzer');
});
for (const boundary of ['tool', 'view']) for (const outcome of ['success', 'error']) test(`${boundary} navigation cancels pending docs and never blocks the new workspace after ${outcome}`, async () => {
  const f = fixture(), read = f.open();
  const next = new f.Element('BUTTON'); next.focus();
  if (boundary === 'tool') { f.context.setActiveTool('fuzzer'); f.context.renderToolPanels(); }
  else f.context.setActiveTargetView('apis');
  assert.equal(f.controller.getState().apiDocs, null);
  assert.equal(f.context.getActiveModalAction(), null);
  assert.equal(f.document.activeElement, next, 'dismissal must not move focus from newer navigation');
  if (boundary === 'tool') { f.context.setActiveTool('map'); f.context.renderToolPanels(); }
  else f.context.setActiveTargetView('service-map');
  if (outcome === 'success') await f.load(read);
  else { read.reject(new Error('Synthetic old request')); await tick(); }
  assert.equal(f.controller.getState().apiDocs, null);
  assert.equal(f.context.getActiveModalAction(), null);
  assert.equal(f.document.activeElement, next);
  await f.load(f.open()); assert.ok(f.controller.getState().apiDocs);
});
test('a backdrop without rendered geometry never owns workspace keyboard handling', async () => {
  const f = fixture(); await f.load(f.open());
  const wrapper = new f.Element(); wrapper.append(f.modal); wrapper.classList.add('hidden');
  assert.equal(f.context.getActiveModalAction(), null);
  f.key('f', f.mainTab, { ctrlKey: true, shiftKey: true });
  assert.equal(f.state.activeTool, 'fuzzer');
  assert.equal(f.controller.getState().apiDocs, null);
});
for (const reason of ['detached', 'hidden', 'disabled']) test(`API Docs Close falls back to its current Map tab if the invoker is ${reason}`, async () => {
  const f = fixture(); await f.load(f.open());
  if (reason === 'detached') f.opener.isConnected = false;
  if (reason === 'hidden') f.opener.classList.add('hidden');
  if (reason === 'disabled') f.opener.disabled = true;
  f.key('Escape');
  assert.equal(f.document.activeElement, f.mapTab);
});
for (const shiftKey of [false, true]) test(`API Docs recovers ${shiftKey ? 'Shift+Tab' : 'Tab'} from outside focus`, async () => {
  const f = fixture(); await f.load(f.open()); f.opener.focus();
  assert.equal(f.key('Tab', f.opener, { shiftKey }).defaultPrevented, true);
  assert.equal(f.document.activeElement, shiftKey ? f.control('close') : f.modal.querySelector('summary'));
});
test('a confirmation keeps Escape priority even if focus was left in API Docs', async () => {
  const f = fixture(); await f.load(f.open()); let closed = 0;
  f.context.activeConfirmDialog = { modal: new f.Element(), close() { closed++; } };
  f.key('Escape', f.control('close'));
  assert.equal(closed, 1); assert.ok(f.controller.getState().apiDocs);
});
test('closing beneath a newer dialog leaves its focus intact', async () => {
  const f = fixture(); await f.load(f.open()); const newer = new f.Element('BUTTON');
  f.context.activeConfirmDialog = { modal: new f.Element(), close() {} }; newer.focus();
  f.control('close').click();
  assert.equal(f.controller.getState().apiDocs, null); assert.equal(f.document.activeElement, newer);
});
for (const docsRemainOpen of [true, false]) test(`API Docs opening ${docsRemainOpen ? 'and staying open' : 'then closing'} cancels an older pending Compare`, async () => {
  const f = fixture();
  f.context.setActiveTool('proxy'); f.context.renderToolPanels();
  const offset = f.requests.length, pendingCompare = f.context.openCompareModal('target');
  f.context.setActiveTool('map'); f.context.renderToolPanels();
  await f.load(f.open());
  if (!docsRemainOpen) f.key('Escape');
  const focused = f.document.activeElement;
  f.requests[offset].resolve({ ok: true, json: async () => ({ id: 'base' }) });
  f.requests[offset + 1].resolve({ ok: true, json: async () => ({ id: 'target' }) });
  await pendingCompare;
  assert.equal(f.els.compareModal.classList.contains('hidden'), true);
  assert.equal(f.document.activeElement, focused);
});
