// Passive editor/save fixtures only. No app startup, server, or outgoing traffic.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { appSource } = require('./frontend-test-helpers.cjs');
const { fixture, plain } = require('./replay-workspace-fixture.cjs');

function setup() {
  const f = fixture();
  for (const name of ['applyReplayTargetFields', 'validateManualRepeaterTargetInput',
    'setReplayTargetInputValidity', 'isLikelyIpv6Literal', 'startHexByteEdit']) {
    const source = appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, 'm'))[0];
    vm.runInContext(source, f.context);
  }
  for (const input of [f.els.replayHostInput, f.els.replayPortInput]) {
    input.setCustomValidity = message => { input.validationMessage = message; };
    input.toggleAttribute = (name, value) => { input[name] = value; };
  }
  f.a = f.tab('a'); f.b = f.tab('b'); f.seed([f.a, f.b]);
  f.context.handleWorkspaceActionError = () => {};
  f.aborts = 0; f.sendingChanges = [];
  f.controller = { abort() { f.aborts += 1; } };
  f.context.setReplaySending = value => f.sendingChanges.push(value);
  return f;
}
async function failClose(f, id = f.a.id) {
  const closing = f.context.closeRepeaterTab(id);
  if (f.requests.length) f.requests.at(-1).reject(new Error('synthetic save failure'));
  await closing;
}
function reselect(f) {
  f.state.activeReplayTabId = f.a.id;
  f.context.renderReplay();
}
function refusalSnapshot(f) {
  return { state: plain(f.state), baseline: plain(f.context.workspaceSaveCommittedSnapshot),
    lastSnapshot: f.context.workspaceSaveLastSnapshot, dirty: f.context.workspaceSaveDirty,
    version: f.context.workspaceSaveVersion, timers: [...f.timers.entries()], focus: f.document.activeElement,
    dom: [f.els.replayRequestHighlight?.innerText, f.els.replayRequestEditor?.value,
      f.els.replayHostInput.value, f.els.replayPortInput.value, f.els.replaySchemeSelect.value, f.versionSelect.value] };
}
function assertRefused(f, before, feedback) {
  assert.deepEqual(refusalSnapshot(f), before);
  assert.equal(f.requests.length, 0); assert.equal(f.renders.length, 0);
  assert.equal(f.context.workspacePendingReplayCloses.size, 0);
  assert.equal(f.context.workspaceSaveConflictPending, false);
  assert.equal(f.context._replaySendControllers.get(f.a.id), f.controller);
  assert.equal(f.aborts, 0); assert.deepEqual(f.sendingChanges, []);
  assert.match(f.toasts.at(-1)[0], feedback);
}
function pendingHex(f, value, index = 1) {
  f.state.replayMessageViews.request = 'hex';
  f.a.requestBytes = new Uint8Array([0xff, 0x0f, 0x00]);
  f.a.requestOriginalBytes = new Uint8Array(f.a.requestBytes);
  const container = f.els.replayRequestHighlight, delayed = [];
  let currentInput = null;
  const span = { dataset: { idx: String(index) }, classList: { add() {}, remove() {} },
    appendChild(input) { currentInput = input; input.parentElement = span; }, textContent: '0f' };
  container.querySelectorAll = selector => selector === '.hex-byte-input' && currentInput ? [currentInput] : [];
  container.querySelector = selector => selector === '.hex-byte-input' ? currentInput : null;
  f.document.createElement = () => ({ listeners: {},
    addEventListener(type, listener) { this.listeners[type] = listener; },
    focus() { f.document.activeElement = this; }, select() {},
    closest(selector) { return selector === '.hex-byte' ? span : null; },
    remove() { currentInput = null; },
  });
  f.context.setTimeout = callback => delayed.push(callback);
  const render = f.context.renderReplay;
  f.context.renderReplay = options => { currentInput = null; render(options); };
  f.context.startHexByteEdit(span, f.a, container);
  const input = currentInput;
  input.value = value; input.listeners.input();
  return { input, delayed, container, getCurrentInput: () => currentInput };
}

test('invalid port rejected by real target handler cannot be lost by active close and failed save', async () => {
  const f = setup();
  f.els.replayPortInput.value = '8x';
  await f.context.applyReplayTargetFields();
  assert.equal(f.a.targetPort, '443');
  f.context._replaySendControllers.set(f.a.id, f.controller);
  const before = refusalSnapshot(f);
  await failClose(f);
  assertRefused(f, before, /target.*before closing/i);
  assert.equal(f.els.replayPortInput.value, '8x');
});

test('single-digit legacy hex draft survives close before its delayed blur commit', async () => {
  const f = setup(), hex = pendingHex(f, 'f', 0);
  hex.input.listeners.blur();
  assert.equal(hex.delayed.length, 1); assert.equal(f.a.requestBytes[0], 0xff);
  f.context._replaySendControllers.set(f.a.id, f.controller);
  const before = refusalSnapshot(f);
  await failClose(f);
  assertRefused(f, before, /byte edit.*before closing/i);
  assert.equal(hex.getCurrentInput(), hex.input); assert.equal(hex.input.value, 'f');
});

for (const editor of ['CodeMirror', 'contenteditable', 'textarea']) {
  test(`unsynced ${editor} draft survives failed close and reselect`, async () => {
    const f = setup(), text = 'GET /unfinished HTTP/1.1\r\nHost: example.com\r\n\r\nbody draft';
    if (editor === 'CodeMirror') f.setEditor(text);
    else if (editor === 'contenteditable') f.els.replayRequestHighlight.innerText = text;
    else { delete f.els.replayRequestHighlight; f.els.replayRequestEditor.value = text; }
    // The hidden textarea deliberately retains old text in the first two cases.
    await failClose(f);
    assert.equal(f.a.requestText, text);
    reselect(f);
    assert.equal(f.els.replayRequestEditor.value, text);
    assert.equal(f.state.replayTabs.find(tab => tab.id === f.a.id), f.a);
  });
}

test('simultaneous text, target and HTTP-version controls are captured before close rendering', async () => {
  const f = setup(); f.setEditor('GET /draft HTTP/1.1\r\nHost: example.com\r\n\r\n');
  f.els.replayHostInput.value = 'draft.example.com'; f.els.replayPortInput.value = '8080';
  f.els.replaySchemeSelect.value = 'http'; f.versionSelect.value = 'HTTP/2';
  await failClose(f); reselect(f);
  assert.equal(f.a.requestText, 'GET /draft HTTP/2\r\nHost: example.com\r\n\r\n');
  assert.equal(f.a.httpVersionMode, 'HTTP/2');
  assert.equal(f.els.replayHostInput.value, 'draft.example.com');
  assert.equal(f.els.replayPortInput.value, '8080'); assert.equal(f.els.replaySchemeSelect.value, 'http');
  assert.equal(f.a.targetManuallyEdited, true);
});

test('invalid target refuses before changing otherwise preservable text and version drafts', async () => {
  const f = setup(); f.setEditor('GET /draft HTTP/1.1');
  f.els.replayHostInput.value = 'unfinished host'; f.versionSelect.value = 'HTTP/2';
  f.context._replaySendControllers.set(f.a.id, f.controller);
  f.state.replayRenamingTabId = f.a.id;
  const before = refusalSnapshot(f);
  await failClose(f);
  assertRefused(f, before, /target.*before closing/i);
});

for (const editor of ['CodeMirror', 'contenteditable']) {
  test(`${editor} CRLF normalization alone keeps the stored text and response intact`, async () => {
    const f = setup(), text = f.a.requestText, response = { id: 'saved-response' };
    f.a.responseRecord = response; f.a.notice = 'saved notice';
    if (editor === 'CodeMirror') f.setEditor(text.replace(/\r\n/g, '\n'));
    else f.els.replayRequestHighlight.innerText = text.replace(/\r\n/g, '\n');
    await failClose(f);
    assert.equal(f.requests.length, 1); assert.equal(f.a.requestText, text);
    assert.equal(f.a.responseRecord, response); assert.equal(f.a.notice, 'saved notice');
  });
}

for (const mode of ['raw', 'legacy hex', 'CodeMirror hex', 'sending']) {
  test(`clean model-backed ${mode} remains closable and keeps byte identity on rollback`, async () => {
    const f = setup();
    f.a.requestBytes = new Uint8Array([0xff, 0x80, 0x00]);
    f.a.requestOriginalBytes = new Uint8Array([0x00, 0x80, 0x00]);
    const bytes = f.a.requestBytes, original = f.a.requestOriginalBytes, text = f.a.requestText;
    if (mode.includes('hex')) f.state.replayMessageViews.request = 'hex';
    if (mode === 'CodeMirror hex') f.setEditor('00000000  ff 80 00');
    if (mode === 'sending') f.context._replaySendControllers.set(f.a.id, f.controller);
    await failClose(f);
    assert.equal(f.requests.length, 1); assert.equal(f.state.activeReplayTabId, f.b.id);
    assert.equal(f.a.requestBytes, bytes); assert.equal(f.a.requestOriginalBytes, original);
    assert.deepEqual([...f.a.requestBytes], [0xff, 0x80, 0]); assert.equal(f.a.requestText, text);
    assert.equal(f.aborts, mode === 'sending' ? 1 : 0);
  });
}

test('unchanged one-digit hex input compares to its indexed model byte and stays closable', async () => {
  const f = setup(); pendingHex(f, 'F', 1);
  await failClose(f);
  assert.equal(f.requests.length, 1); assert.equal(f.state.activeReplayTabId, f.b.id);
  assert.deepEqual([...f.a.requestBytes], [0xff, 0x0f, 0]);
});

test('inactive close does not inspect or synchronize another tab’s invalid target and editor', async () => {
  const f = setup(); f.setEditor('unfinished request'); f.els.replayPortInput.value = '8x';
  f.versionSelect.value = 'HTTP/2';
  const before = refusalSnapshot(f), a = plain(f.a);
  await failClose(f, f.b.id);
  assert.equal(f.requests.length, 1); assert.equal(f.state.activeReplayTabId, f.a.id);
  assert.deepEqual(plain(f.a), a); assert.deepEqual(refusalSnapshot(f).dom, before.dom);
  assert.equal(f.document.activeElement, before.focus);
  assert.deepEqual(f.renders.map(render => render.kind), ['strip', 'strip']);
});

test('an unchanged hex edit’s delayed blur cannot repaint a newly active tab’s input', async () => {
  const f = setup(), hex = pendingHex(f, 'F', 1);
  hex.input.listeners.blur();
  await failClose(f);
  const fallbackInput = { value: '1' };
  hex.container.querySelector = selector => selector === '.hex-byte-input' ? fallbackInput : null;
  f.context.renderEditableHexHtml = () => assert.fail('the old byte input must not repaint the fallback editor');
  hex.delayed[0]();
  assert.equal(hex.container.querySelector('.hex-byte-input'), fallbackInput);
});

for (const version of ['HTTP/2', '']) {
  test(`HTTP version drift to ${version || 'auto'} survives rollback without changing line endings`, async () => {
    const f = setup(); f.versionSelect.value = version;
    await failClose(f); reselect(f);
    assert.equal(f.a.requestText, `GET /a${version ? ` ${version}` : ''}\r\nHost: example.com\r\n\r\n`);
    assert.equal(f.a.httpVersionMode, version); assert.equal(f.versionSelect.value, version);
  });
}

test('version drift alongside binary bytes refuses without capturing a staged valid target', async () => {
  const f = setup(); f.a.requestBytes = new Uint8Array([0xff, 0x80]);
  f.versionSelect.value = 'HTTP/2'; f.els.replayPortInput.value = '8080';
  f.context._replaySendControllers.set(f.a.id, f.controller);
  const before = refusalSnapshot(f), bytes = f.a.requestBytes;
  await failClose(f);
  assertRefused(f, before, /HTTP version change.*before closing/i);
  assert.equal(f.a.requestBytes, bytes);
});

test('partially typed visible text is retained verbatim and invalidates its old response', async () => {
  const f = setup(), text = 'GET /unfinished HTT';
  f.a.responseRecord = { id: 'old-response' }; f.a.notice = 'old result';
  f.els.replayRequestHighlight.innerText = text;
  await failClose(f); reselect(f);
  assert.equal(f.a.requestText, text); assert.equal(f.els.replayRequestEditor.value, text);
  assert.equal(f.a.responseRecord, null); assert.equal(f.a.notice, '');
});

function renameClosePointerdown(f) {
  const render = f.context.renderReplayTabs, listeners = {};
  for (const name of ['renderReplayTabs', 'commitReplayTabRename']) {
    const source = appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, 'm'))[0];
    vm.runInContext(source, f.context);
  }
  const nameInput = { value: 'unfinished rename', selectionStart: 5, addEventListener() {}, focus() {}, select() {} };
  const button = { addEventListener() {} };
  const tabElement = { dataset: { replayTabId: f.a.id },
    addEventListener(type, listener) { listeners[type] = listener; },
    querySelector(selector) { return selector === '.replay-tab-name-input' ? nameInput : button; } };
  f.els.replayTabStrip = { querySelectorAll: () => [tabElement], querySelector: () => nameInput };
  Object.assign(f.context, {
    replayTabAutoLabel: tab => tab.customLabel, replayTabLabel: tab => tab.customLabel,
    replayTabTooltipLabel: (_, label) => label, escapeHtml: value => value,
    wireReplayTabDragReorder() {}, scrollActiveReplayTabIntoView() {}, requestAnimationFrame() {},
    CSS: { escape: value => value },
  });
  f.state.replayRenamingTabId = f.a.id; f.document.activeElement = nameInput;
  f.context.renderReplayTabs();
  f.context.renderReplayTabs = render;
  const close = f.context.closeRepeaterTab;
  f.context.closeRepeaterTab = (...args) => {
    f.pendingClose = close(...args);
    return f.pendingClose;
  };
  return () => listeners.pointerdown({
    target: { closest: selector => selector === '.replay-tab' ? tabElement
      : selector === '.replay-tab-close' ? button : null },
    preventDefault() {}, stopPropagation() {},
  });
}

test('real rename pointerdown close refuses invalid target before rename or save side effects', async () => {
  const f = setup(), pointerdown = renameClosePointerdown(f);
  f.els.replayPortInput.value = '8x';
  f.context._replaySendControllers.set(f.a.id, f.controller);
  const before = refusalSnapshot(f);
  pointerdown();
  if (f.requests.length) f.requests[0].reject(new Error('synthetic save failure'));
  await f.pendingClose;
  assertRefused(f, before, /target.*before closing/i);
  assert.equal(f.document.activeElement.value, 'unfinished rename');
  assert.equal(f.document.activeElement.selectionStart, 5);
});

test('real rename pointerdown close captures HTTP drafts once and still commits the rename', async () => {
  const f = setup(), pointerdown = renameClosePointerdown(f);
  f.setEditor('GET /edited HTTP/1.1\r\nHost: example.com\r\n\r\n');
  f.versionSelect.value = 'HTTP/2'; f.els.replayPortInput.value = '8080';
  f.context.flushWorkspaceState = async () => {};
  pointerdown(); await f.pendingClose;
  assert.equal(f.a.customLabel, 'unfinished rename');
  assert.equal(f.a.requestText, 'GET /edited HTTP/2\r\nHost: example.com\r\n\r\n');
  assert.equal(f.a.httpVersionMode, 'HTTP/2'); assert.equal(f.a.targetPort, '8080');
  assert.equal(f.state.replayRenamingTabId, null);
  assert.equal(f.state.replayTabs.includes(f.a), false);
});

test('an uninitialized CM pane never promotes stale hidden legacy controls into the model', async () => {
  const f = setup(), text = f.a.requestText, response = { id: 'saved-response' };
  const bytes = new Uint8Array([0xff, 0x00]);
  f.a.requestBytes = bytes; f.a.responseRecord = response;
  f.els.replayRequestCM = {};
  f.els.replayRequestHighlight.innerText = 'stale hidden highlight';
  f.els.replayRequestEditor.value = 'stale hidden textarea';
  await failClose(f);
  assert.equal(f.requests.length, 1);
  assert.equal(f.a.requestText, text); assert.equal(f.a.requestBytes, bytes);
  assert.equal(f.a.responseRecord, response);
});
