// Passive saved-tab navigation only. No application, network, runtime, or request execution.
const assert = require('node:assert/strict');
const vm = require('node:vm');
const test = require('node:test');
const { appSource } = require('./frontend-test-helpers.cjs');
const { fixture, plain } = require('./replay-workspace-fixture.cjs');

function source(name) {
  return appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, 'm'))[0];
}
function bindListener(f, marker) {
  const binding = appSource.slice(appSource.indexOf(marker));
  vm.runInContext(binding.slice(0, binding.indexOf('\n  });') + 6), f.context);
}
function setup() {
  const f = fixture();
  Object.assign(f.state, { activeTool: 'replay', _replayUndoStack: [], _replayRedoStack: [], _replayLastSnapshot: null });
  f.a = f.tab('a'); f.b = f.tab('b'); f.seed([f.a, f.b]);
  for (const name of [
    'applyReplayTargetFields', 'setReplayTargetInputValidity', 'startHexByteEdit',
    'beginReplayTabRename', 'commitReplayTabRename', 'toggleReplayTabPin',
    'syncReplayRequestTextFromEditor', 'clearReplayResponseForDraftChange', 'syncReplayToolbar',
    'parseEditableRawRequest', 'splitRawHttpMessage', 'parseReplayHttpVersionToken',
    'headerValue', 'editableRequestBodyLength', 'validateRawHttpBodyFraming', 'renderReplayTabs',
  ]) vm.runInContext(source(name), f.context);
  for (const input of [f.els.replayHostInput, f.els.replayPortInput]) {
    input.listeners = {};
    input.addEventListener = (type, callback) => { input.listeners[type] = callback; };
    input.setCustomValidity = message => { input.validationMessage = message; };
    input.toggleAttribute = (name, value) => { input[name] = value; };
  }
  class Element {
    constructor(selector, parent = null) {
      Object.assign(this, { selector, parent, listeners: {}, value: '', dataset: {} });
    }
    addEventListener(type, callback) { this.listeners[type] = callback; }
    closest(selector) { return selector === this.selector ? this : this.parent?.closest(selector) || null; }
    focus() { f.document.activeElement = this; }
    select() {}
  }
  let rows = [];
  const strip = f.els.replayTabStrip = {
    scrollLeft: 0,
    querySelectorAll: selector => selector === '.replay-tab' ? rows : [],
    querySelector: selector => {
      if (selector.includes('data-replay-tab-id')) {
        return rows.find(row => selector.includes(row.dataset.replayTabId))?.name || null;
      }
      return null;
    },
  };
  Object.defineProperty(strip, 'innerHTML', { set() {
    rows = f.context.getReplayTabVisualOrder().map(tab => {
      const row = new Element('.replay-tab'); row.dataset.replayTabId = tab.id;
      row.button = f.state.replayRenamingTabId === tab.id ? null : new Element('.replay-tab-button', row);
      row.name = f.state.replayRenamingTabId === tab.id ? new Element('.replay-tab-name-input', row) : null;
      if (row.name) row.name.value = tab.customLabel || '';
      row.pin = new Element('.replay-tab-pin-btn', row); row.close = new Element('.replay-tab-close', row);
      row.querySelector = selector => ({
        '.replay-tab-button': row.button, '.replay-tab-name-input': row.name,
        '.replay-tab-pin-btn': row.pin, '.replay-tab-close': row.close,
      }[selector] || null);
      return row;
    });
  } });
  Object.assign(f.context, {
    Element, CSS: { escape: value => value }, escapeHtml: value => String(value),
    replayTabAutoLabel: tab => tab.customLabel, replayTabLabel: tab => tab.customLabel,
    replayTabTooltipLabel: (tab, label) => label,
    wireReplayTabDragReorder() {}, scrollActiveReplayTabIntoView() {}, requestAnimationFrame() {},
    getActiveModalAction: () => null, canNavigateReplayHistory: () => false,
    refreshReplayTabLabel() {}, updateReplaySearchPane() {}, renderReplayEmptyResponse() {}, renderReplayViewContent() {},
    TextDecoder, renderEditableHexHtml: () => '<hex>', bindHexByteHandlers() {}, clearTimeout() {}, setTimeout: () => 1,
  });
  f.flushes = 0; f.context.flushWorkspaceState = async () => { f.flushes++; };
  for (const name of ['sendReplayButton', 'cancelReplayButton', 'replayBackButton', 'replayForwardButton']) f.els[name] = {};
  // Exercise the real render-to-toolbar forwarding while omitting unrelated response painting.
  const toolbarCall = source('renderReplay').match(/  syncReplayToolbar\(tab[^;]*;/)[0];
  vm.runInContext(`function renderSavedToolbar(tab, options = {}) { ${toolbarCall} }`, f.context);
  f.context.renderReplay = options => {
    const tab = f.context.ensureRepeaterTab(); f.renders.push({ kind: 'full', options });
    f.context.renderReplayTabs();
    if (!tab || tab.type === 'websocket') return;
    f.context.renderSavedToolbar(tab, options);
    if (f.state.replayMessageViews.request === 'hex') f.els.replayRequestHighlight.innerHTML = '<hex>';
    else {
      if (f.els.replayRequestHighlight) f.els.replayRequestHighlight.innerText = tab.requestText;
      f.els.replayRequestEditor.value = tab.requestText;
    }
  };
  f.document.addEventListener = (type, callback) => { if (type === 'keydown') f.keyHandler = callback; };
  bindListener(f, '  document.addEventListener("keydown", (event) => {');
  f.context.renderReplayTabs();
  const event = target => ({
    target, defaultPrevented: false,
    preventDefault() { this.defaultPrevented = true; }, stopPropagation() { this.stopped = true; },
  });
  f.row = id => rows.find(row => row.dataset.replayTabId === id);
  // Dispatch registered production handlers; browser default focus movement is not simulated.
  f.click = id => f.row(id).button.listeners.click(event(f.row(id).button));
  f.rename = () => {
    f.click(f.a.id); const input = f.row(f.a.id).name;
    input.value = 'pending name'; input.focus(); return input;
  };
  f.pointer = id => { const row = f.row(id); row.listeners.pointerdown(event(row.button)); };
  f.key = (shift = false, target = new Element('body')) => {
    const keyEvent = { ...event(target), ctrlKey: true, metaKey: false, altKey: false, shiftKey: shift, key: 'Tab' };
    f.keyHandler(keyEvent); return keyEvent;
  };
  f.snapshot = () => ({
    state: plain(f.state), baseline: plain(f.context.workspaceSaveCommittedSnapshot),
    dirty: f.context.workspaceSaveDirty, version: f.context.workspaceSaveVersion,
    lastSnapshot: f.context.workspaceSaveLastSnapshot, timers: [...f.timers.entries()],
    renders: plain(f.renders), flushes: f.flushes, requests: f.requests.length, focus: f.document.activeElement,
    pendingCloses: f.context.workspacePendingReplayCloses.size,
    rename: rows.filter(row => row.name).map(row => [row.dataset.replayTabId, row.name.value]),
    dom: [f.els.replayRequestHighlight?.innerText, f.els.replayRequestEditor.value,
      f.els.replayHostInput.value, f.els.replayPortInput.value, f.els.replaySchemeSelect.value, f.versionSelect.value],
  });
  // Bind the production ordinary target input listener, not a synthetic model write.
  bindListener(f, '  els.replayPortInput.addEventListener("input", () => {');
  f.invalid = async () => {
    f.document.activeElement = f.els.replayPortInput; f.els.replayPortInput.value = '8x';
    f.els.replayPortInput.listeners.input(); await Promise.resolve();
    assert.equal(f.a.targetPort, '443'); assert.ok(f.els.replayPortInput.validationMessage);
  };
  return f;
}
function pendingHex(f, value = 'f', index = 0) {
  f.state.replayMessageViews.request = 'hex';
  f.a.requestBytes = new Uint8Array([255, 15, 0]); f.a.requestOriginalBytes = new Uint8Array(f.a.requestBytes);
  const container = f.els.replayRequestHighlight, delayed = []; let input = null;
  const span = { dataset: { idx: String(index) }, classList: { add() {}, remove() {} },
    appendChild: child => { input = child; }, textContent: 'ff' };
  container.querySelectorAll = selector => selector === '.hex-byte-input' && input ? [input] : [];
  container.querySelector = selector => selector === '.hex-byte-input' ? input : null;
  Object.defineProperty(container, 'innerHTML', { configurable: true, set() { input = null; } });
  f.document.createElement = () => ({
    listeners: {}, addEventListener(type, callback) { this.listeners[type] = callback; },
    focus() { f.document.activeElement = this; }, select() {},
    closest: selector => selector === '.hex-byte' ? span : null, remove() { input = null; },
  });
  f.context.setTimeout = callback => { delayed.push(callback); return delayed.length; };
  const render = f.context.renderReplay;
  f.context.renderReplay = options => { input = null; render(options); };
  f.context.startHexByteEdit(span, f.a, container);
  const original = input; input.value = value; input.listeners.input();
  return { input: original, current: () => input, delayed };
}
function navigate(f, route) {
 if (route === 'click') f.click(f.b.id);
 else if (route === 'rename-pointer') f.pointer(f.b.id);
 else f.key(route === 'ctrl-shift-tab');
}
const routes = ['click', 'ctrl-tab', 'ctrl-shift-tab', 'rename-pointer'];

for (const route of routes) for (const kind of ['invalid target', 'delayed hex']) {
 test(`${route}: ${kind} refuses before model, rename, save, render or focus changes`, async () => {
  const f = setup(); let hex;
  if (kind === 'invalid target') await f.invalid();
  else {
   hex = pendingHex(f); hex.input.listeners.blur();
   // The keyboard case follows blur to another control, before its 100 ms callback.
   if (route.startsWith('ctrl')) f.document.activeElement = f.els.replayPortInput;
  }
  if (route === 'rename-pointer') f.rename();
  const before = f.snapshot();
  navigate(f, route); navigate(f, route);
  assert.deepEqual(f.snapshot(), before);
  assert.equal(f.state.activeReplayTabId, f.a.id);
  assert.match(f.toasts.at(-1)[0], /before switching tabs/);
  if (hex) { assert.equal(hex.current(), hex.input); assert.equal(hex.input.value, 'f'); }
 });
}

for (const shift of [false, true]) test(`Ctrl+${shift ? 'Shift+' : ''}Tab refusal still prevents native tab movement`, async () => {
 const f = setup(); await f.invalid(); const focus = f.document.activeElement;
 const event = f.key(shift, focus);
 assert.equal(event.defaultPrevented, true);
 assert.equal(f.document.activeElement, focus);
 assert.equal(f.els.replayPortInput.value, '8x');
 assert.equal(f.state.activeReplayTabId, f.a.id);
});

test('focused legacy hex input commits its byte before the bubbling Ctrl+Tab shortcut', () => {
 const f = setup(), hex = pendingHex(f);
 const event = { key: 'Tab', ctrlKey: true, shiftKey: false, preventDefault() { this.defaultPrevented = true; } };
 hex.input.listeners.keydown(event);
 assert.equal(f.a.requestBytes[0], 15);
 f.key(false, hex.input);
 assert.equal(f.state.activeReplayTabId, f.b.id);
 assert.equal(f.a.requestBytes[0], 15);
 assert.equal(f.toasts.length, 0);
});

for (const route of routes) {
 test(`${route}: ordinary partial raw input is already model-backed`, () => {
  const f = setup();
  f.els.replayRequestHighlight.addEventListener = (type, callback) => { if (type === 'input') f.rawInput = callback; };
  let binding = appSource.slice(appSource.indexOf('  els.replayRequestHighlight?.addEventListener("input", () => {'));
  binding = binding.slice(0, binding.indexOf('\n  });') + 6);
  vm.runInContext(binding, f.context);
  f.els.replayRequestHighlight.innerText = 'GET /unfinished HTT'; f.rawInput();
  assert.equal(f.a.requestText, 'GET /unfinished HTT');
  if (route === 'rename-pointer') f.rename();
  navigate(f, route); f.click(f.a.id);
  assert.equal(f.els.replayRequestEditor.value, 'GET /unfinished HTT');
 });
 for (const text of ['GET /unsynced HTT', '']) test(`${route}: preserves a DOM-only ${text ? 'partial' : 'empty'} raw draft`, () => {
  const f = setup(); f.els.replayRequestHighlight.innerText = text;
  f.a.responseRecord = { id: 'old' }; f.a.notice = 'old result';
  if (route === 'rename-pointer') f.rename();
  navigate(f, route);
  assert.equal(f.state.activeReplayTabId, f.b.id);
  assert.equal(f.a.requestText, text); assert.equal(f.a.responseRecord, null); assert.equal(f.a.notice, '');
  f.click(f.a.id); assert.equal(f.els.replayRequestEditor.value, text);
 });
 for (const mode of ['clean binary', 'sending', 'WebSocket']) test(`${route}: ${mode} navigation remains available`, () => {
  const f = setup(); let bytes, original, aborts = 0;
  const response = f.a.responseRecord = { id: 'saved' }; f.a.notice = 'saved';
  const controller = { abort() { aborts++; } };
  if (mode === 'clean binary') {
   f.state.replayMessageViews.request = 'hex';
   f.a.requestBytes = bytes = new Uint8Array([255, 128]);
   f.a.requestOriginalBytes = original = new Uint8Array([0, 128]);
  }
  if (mode === 'sending') f.context._replaySendControllers.set(f.a.id, controller);
  if (mode === 'WebSocket') { f.a.type = 'websocket'; f.els.replayPortInput.value = '8x'; }
  if (route === 'rename-pointer') f.rename();
  navigate(f, route);
  assert.equal(f.state.activeReplayTabId, f.b.id);
  assert.equal(f.a.responseRecord, response); assert.equal(f.a.notice, 'saved'); assert.equal(aborts, 0);
  if (mode === 'sending') assert.equal(f.context._replaySendControllers.get(f.a.id), controller);
  if (mode === 'clean binary') { assert.equal(f.a.requestBytes, bytes); assert.equal(f.a.requestOriginalBytes, original); }
 });
}

test('successful rename-pointer selection commits the name after preserving its active request', () => {
 const f = setup(); f.els.replayRequestHighlight.innerText = 'GET /partial HTT'; f.rename();
 let flushedDraft;
 f.context.flushWorkspaceState = async () => { f.flushes++; flushedDraft = f.a.requestText; };
 f.pointer(f.b.id);
 assert.equal(f.a.customLabel, 'pending name'); assert.equal(f.flushes, 1);
 assert.equal(flushedDraft, 'GET /partial HTT'); assert.equal(f.state.replayRenamingTabId, null);
 assert.equal(f.state.activeReplayTabId, f.b.id);
});

test('pinned visual order and reverse wrap remain unchanged', () => {
 const f = setup(), c = f.tab('c', true); f.seed([f.a, f.b, c]); f.context.renderReplayTabs();
 f.key(true); assert.equal(f.state.activeReplayTabId, c.id);
 f.key(); assert.equal(f.state.activeReplayTabId, f.a.id);
 f.key(); assert.equal(f.state.activeReplayTabId, f.b.id);
 f.key(); assert.equal(f.state.activeReplayTabId, c.id);
});

test('Ctrl+Tab from the rename input remains excluded', () => {
 const f = setup(), input = f.rename(), before = f.snapshot();
 const event = f.key(false, input);
 assert.deepEqual(f.snapshot(), before); assert.equal(event.defaultPrevented, false);
});

test('selecting the current tab still begins rename with an invalid target', async () => {
 const f = setup(); await f.invalid(); f.click(f.a.id);
 assert.equal(f.state.replayRenamingTabId, f.a.id);
 assert.equal(f.els.replayPortInput.value, '8x'); assert.equal(f.toasts.length, 0);
});

test('one-tab Ctrl+Tab keeps its previous native behavior', async () => {
 const f = setup(); f.seed([f.a]); await f.invalid(); const before = f.snapshot();
 const event = f.key(); assert.equal(event.defaultPrevented, false); assert.deepEqual(f.snapshot(), before);
});

test('an unchanged one-digit hex input can navigate without a late repaint', () => {
  const f = setup(), hex = pendingHex(f, 'F', 1);
  hex.input.listeners.blur(); f.click(f.b.id);
  assert.equal(f.state.activeReplayTabId, f.b.id);
  assert.equal(hex.current(), null); assert.equal(f.a.requestBytes[1], 15);
  const before = f.snapshot(); hex.delayed[0]();
  assert.deepEqual(f.snapshot(), before);
});

for (const route of routes) test(`${route}: valid target input is model-backed before navigation`, () => {
  const f = setup(); f.document.activeElement = f.els.replayPortInput;
  f.els.replayPortInput.value = '8080'; f.els.replayPortInput.listeners.input();
  assert.equal(f.a.targetPort, '8080');
  f.document.activeElement = null;
  if (route === 'rename-pointer') f.rename();
  navigate(f, route); assert.equal(f.state.activeReplayTabId, f.b.id);
  f.click(f.a.id); assert.equal(f.els.replayPortInput.value, '8080');
});

test('ordinary HTTP version changes are model-backed before navigation', () => {
  const f = setup();
  f.versionSelect.addEventListener = (type, callback) => { if (type === 'change') f.versionChanged = callback; };
  f.context.renderReplayViewContent = () => f.context.renderReplay();
  bindListener(f, '  document.getElementById("replayHttpVersionSelect")?.addEventListener("change", (e) => {');
  f.document.activeElement = f.versionSelect; f.versionSelect.value = 'HTTP/2';
  f.versionChanged({ target: f.versionSelect });
  assert.equal(f.a.httpVersionMode, 'HTTP/2'); assert.match(f.a.requestText, /^GET \/a HTTP\/2/);
  f.document.activeElement = null; f.click(f.b.id); f.click(f.a.id);
  assert.equal(f.versionSelect.value, 'HTTP/2'); assert.match(f.els.replayRequestEditor.value, /^GET \/a HTTP\/2/);
});

test('ordinary CodeMirror document changes synchronously retain a partial raw draft', () => {
  const f = setup(); let updateListener;
  f.context.CM = {
    EditorView: { updateListener: { of: callback => callback } },
    StateEffect: { appendConfig: { of: listener => listener } },
  };
  f.context.cmProgrammaticViews = new WeakSet();
  const view = { dispatch: update => { updateListener = update.effects; } };
  vm.runInContext(source('addCMUpdateListener'), f.context);
  f.context.addCMUpdateListener(view, f.context.syncReplayRequestTextFromEditor);
  f.els.replayRequestHighlight.innerText = 'GET /cm-partial HTT';
  updateListener({ docChanged: true, view, state: { doc: { toString: () => 'GET /cm-partial HTT' } } });
  assert.equal(f.a.requestText, 'GET /cm-partial HTT');
  f.click(f.b.id); f.click(f.a.id);
  assert.equal(f.els.replayRequestEditor.value, 'GET /cm-partial HTT');
});

for (const editor of ['CodeMirror', 'textarea']) test(`selection captures an unsynced ${editor} fallback draft`, () => {
  const f = setup(), text = 'GET /fallback HTT';
  if (editor === 'CodeMirror') f.setEditor(text);
  else { delete f.els.replayRequestHighlight; f.els.replayRequestEditor.value = text; }
  f.click(f.b.id);
  assert.equal(f.state.activeReplayTabId, f.b.id); assert.equal(f.a.requestText, text);
});

test('clean CodeMirror hex stays navigable and retains the original byte arrays', () => {
  const f = setup(); f.state.replayMessageViews.request = 'hex'; f.setEditor('00000000 ff 80');
  const bytes = f.a.requestBytes = new Uint8Array([255, 128]);
  const original = f.a.requestOriginalBytes = new Uint8Array([0, 128]);
  f.click(f.b.id);
  assert.equal(f.state.activeReplayTabId, f.b.id);
  assert.equal(f.a.requestBytes, bytes); assert.equal(f.a.requestOriginalBytes, original);
});

for (const field of ['host', 'port', 'scheme', 'version']) for (const route of routes) {
  test(`${route}: replaces focused ${field} with the selected tab's saved value`, () => {
    const f = setup();
    Object.assign(f.a, { targetHost: 'a.example.com', targetPort: '443', targetScheme: 'https', httpVersionMode: 'HTTP/1.1' });
    Object.assign(f.b, { targetHost: 'b.example.com', targetPort: '8080', targetScheme: 'http', httpVersionMode: 'HTTP/2',
      requestText: 'GET /b HTTP/2\r\nHost: b.example.com\r\n\r\n' });
    f.a.responseRecord = { id: 'a-response' }; f.b.responseRecord = { id: 'b-response' };
    f.seed([f.a, f.b]);
    const controls = { host: f.els.replayHostInput, port: f.els.replayPortInput,
      scheme: f.els.replaySchemeSelect, version: f.versionSelect };
    const values = { host: 'b.example.com', port: '8080', scheme: 'http', version: 'HTTP/2' };
    if (route === 'rename-pointer') f.rename();
    f.document.activeElement = controls[field];
    const before = plain([f.a, f.b]), focus = f.document.activeElement;
    navigate(f, route);
    assert.equal(f.state.activeReplayTabId, f.b.id);
    assert.equal(controls[field].value, values[field]);
    assert.equal(f.document.activeElement, focus);
    f.key(route === 'ctrl-shift-tab', focus);
    assert.equal(f.state.activeReplayTabId, f.a.id);
    if (route === 'rename-pointer') before[0].customLabel = 'pending name';
    assert.deepEqual(plain([f.a, f.b]), before);
    assert.equal(f.document.activeElement, focus);
  });
}
