// Passive saved-tab metadata fixtures only. No app, server or request execution.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { fixture, plain } = require('./replay-workspace-fixture.cjs');
const { appSource } = require('./frontend-test-helpers.cjs');

function setup() {
  const f = fixture();
  for (const name of ['openBlankReplayTab', 'duplicateActiveReplayTab', 'applyReplayTargetFields',
    'setReplayTargetInputValidity', 'startHexByteEdit', 'parseEditableRawRequest', 'splitRawHttpMessage',
    'parseReplayHttpVersionToken', 'headerValue', 'editableRequestBodyLength', 'validateRawHttpBodyFraming']) {
    vm.runInContext(appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, 'm'))[0], f.context);
  }
  for (const input of [f.els.replayHostInput, f.els.replayPortInput]) {
    input.setCustomValidity = message => { input.validationMessage = message; };
    input.toggleAttribute = (name, value) => { input[name] = value; };
  }
  f.context.setActiveTool = tool => { f.state.activeTool = tool; };
  f.context.renderToolPanels = () => f.context.renderReplay();
  f.a = f.tab('a'); f.b = f.tab('b'); f.seed([f.a, f.b]);
  f.aborts = 0;
  f.controller = { abort() { f.aborts += 1; } };
  return f;
}

function snapshot(f) {
  return { state: plain(f.state), baseline: plain(f.context.workspaceSaveCommittedSnapshot),
    lastSnapshot: f.context.workspaceSaveLastSnapshot, dirty: f.context.workspaceSaveDirty,
    version: f.context.workspaceSaveVersion, timers: [...f.timers.entries()], focus: f.document.activeElement,
    dom: [f.els.replayRequestHighlight?.innerText, f.els.replayRequestEditor?.value,
      f.els.replayHostInput.value, f.els.replayPortInput.value, f.els.replaySchemeSelect.value, f.versionSelect.value] };
}

function pendingHex(f, value, index = 0) {
  f.state.replayMessageViews.request = 'hex';
  f.a.requestBytes = new Uint8Array([0xff, 0x0f, 0x00]);
  f.a.requestOriginalBytes = new Uint8Array(f.a.requestBytes);
  const container = f.els.replayRequestHighlight, delayed = [];
  let currentInput = null;
  const span = { dataset: { idx: String(index) }, classList: { add() {}, remove() {} },
    appendChild(input) { currentInput = input; }, textContent: 'ff' };
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
  return { input, delayed, container, current: () => currentInput };
}

for (const [action, feedback] of [
  ['openBlankReplayTab', /before opening a new tab/i],
  ['duplicateActiveReplayTab', /before duplicating this tab/i],
]) {
  test(`${action}: real invalid target handler refuses before any mutation, save or render`, async () => {
    const f = setup();
    f.els.replayPortInput.value = '8x';
    await f.context.applyReplayTargetFields();
    assert.equal(f.a.targetPort, '443'); assert.ok(f.els.replayPortInput.validationMessage);
    f.els.replayRequestHighlight.innerText = 'unfinished request';
    f.versionSelect.value = 'HTTP/2';
    f.context._replaySendControllers.set(f.a.id, f.controller);
    f.state.replayRenamingTabId = f.a.id;
    const before = snapshot(f);
    f.context[action](); f.context[action]();
    assert.deepEqual(snapshot(f), before);
    assert.equal(f.requests.length, 0); assert.equal(f.renders.length, 0); assert.equal(f.aborts, 0);
    assert.equal(f.context._replaySendControllers.get(f.a.id), f.controller);
    assert.match(f.toasts.at(-1)[0], feedback);
  });

  test(`${action}: delayed single-digit hex draft remains in its live input`, () => {
    const f = setup(), hex = pendingHex(f, 'f');
    hex.input.listeners.blur();
    const before = snapshot(f);
    f.context[action]();
    assert.deepEqual(snapshot(f), before);
    assert.equal(hex.current(), hex.input); assert.equal(hex.input.value, 'f');
    assert.equal(hex.delayed.length, 1); assert.equal(f.a.requestBytes[0], 0xff);
    assert.equal(f.renders.length, 0); assert.equal(f.requests.length, 0);
    assert.match(f.toasts.at(-1)[0], feedback);
  });

  for (const editor of ['CodeMirror', 'contenteditable', 'textarea']) {
    test(`${action}: ${editor} partial raw draft survives synthetic save failure`, async () => {
      const f = setup(), text = 'GET /unfinished HTT';
      f.a.responseRecord = { id: 'old-response' }; f.a.notice = 'old notice';
      if (editor === 'CodeMirror') f.setEditor(text);
      else if (editor === 'contenteditable') f.els.replayRequestHighlight.innerText = text;
      else { delete f.els.replayRequestHighlight; f.els.replayRequestEditor.value = text; }
      f.context[action]();
      const added = f.context.getActiveReplayTab();
      assert.equal(f.a.requestText, text); assert.equal(f.a.responseRecord, null); assert.equal(f.a.notice, '');
      if (action === 'duplicateActiveReplayTab') {
        assert.equal(added.requestText, text); assert.equal(added.responseRecord, null); assert.equal(added.notice, '');
      }
      const saving = f.context.flushQueuedWorkspaceStateSave();
      const posted = JSON.parse(f.requests[0].options.body);
      assert.equal(posted.replay.tabs.find(tab => tab.id === f.a.id).request_text, text);
      f.requests[0].reject(new Error('synthetic metadata transport loss'));
      await assert.rejects(saving, /synthetic metadata/);
      assert.equal(f.state.replayTabs.includes(f.a), true); assert.equal(f.state.replayTabs.includes(added), true);
      assert.equal(f.a.requestText, text); assert.equal(f.context.workspaceSaveDirty, true);
      f.state.activeReplayTabId = f.a.id; f.context.renderReplay();
      assert.equal(f.els.replayRequestEditor.value, text);
    });
  }

  test(`${action}: captures text, valid target and version together before switching`, () => {
    const f = setup();
    f.setEditor('GET /draft HTTP/1.1\r\nHost: example.com\r\n\r\n');
    f.els.replayHostInput.value = 'draft.example.com'; f.els.replayPortInput.value = '8080';
    f.els.replaySchemeSelect.value = 'http'; f.versionSelect.value = 'HTTP/2';
    f.context[action]();
    assert.equal(f.a.requestText, 'GET /draft HTTP/2\r\nHost: example.com\r\n\r\n');
    assert.equal(f.a.targetHost, 'draft.example.com'); assert.equal(f.a.targetPort, '8080');
    assert.equal(f.a.targetScheme, 'http'); assert.equal(f.a.httpVersionMode, 'HTTP/2');
    assert.equal(f.a.targetManuallyEdited, true);
    if (action === 'duplicateActiveReplayTab') {
      const duplicate = f.context.getActiveReplayTab();
      assert.equal(duplicate.requestText, f.a.requestText); assert.equal(duplicate.baseRequest.path, '/draft');
      assert.equal(duplicate.targetHost, f.a.targetHost); assert.equal(duplicate.targetPort, f.a.targetPort);
      assert.equal(duplicate.targetScheme, f.a.targetScheme); assert.equal(duplicate.httpVersionMode, 'HTTP/2');
    }
  });

  test(`${action}: intentionally emptied editor remains empty in the source and duplicate`, () => {
    const f = setup(); f.els.replayRequestHighlight.innerText = '';
    f.context[action]();
    assert.equal(f.a.requestText, '');
    if (action === 'duplicateActiveReplayTab') assert.equal(f.context.getActiveReplayTab().requestText, '');
  });

  for (const mode of ['raw', 'legacy hex', 'CodeMirror hex', 'sending']) {
    test(`${action}: clean ${mode} preserves original byte and result identities`, () => {
      const f = setup(), response = { id: 'saved-response' };
      f.a.requestBytes = new Uint8Array([0xff, 0x80, 0x00]);
      f.a.requestOriginalBytes = new Uint8Array([0x00, 0x80, 0x00]);
      f.a.responseRecord = response; f.a.notice = 'saved';
      const bytes = f.a.requestBytes, original = f.a.requestOriginalBytes, text = f.a.requestText;
      if (mode.includes('hex')) f.state.replayMessageViews.request = 'hex';
      if (mode === 'CodeMirror hex') f.setEditor('00000000  ff 80 00');
      if (mode === 'sending') f.context._replaySendControllers.set(f.a.id, f.controller);
      f.context[action]();
      assert.equal(f.state.replayTabs.length, 3); assert.equal(f.a.requestBytes, bytes);
      assert.equal(f.a.requestOriginalBytes, original); assert.equal(f.a.requestText, text);
      assert.equal(f.a.responseRecord, response); assert.equal(f.a.notice, 'saved'); assert.equal(f.aborts, 0);
      if (mode === 'sending') assert.equal(f.context._replaySendControllers.get(f.a.id), f.controller);
    });
  }

  test(`${action}: binary version drift refuses before capturing a valid target`, () => {
    const f = setup(); f.a.requestBytes = new Uint8Array([0xff]);
    f.versionSelect.value = 'HTTP/2'; f.els.replayPortInput.value = '8080';
    const before = snapshot(f);
    f.context[action]();
    assert.deepEqual(snapshot(f), before); assert.equal(f.renders.length, 0);
    assert.match(f.toasts.at(-1)[0], feedback);
  });

  test(`${action}: normalized line endings keep original response and text`, () => {
    const f = setup(), text = f.a.requestText, response = { id: 'saved-response' };
    f.a.responseRecord = response; f.setEditor(text.replace(/\r\n/g, '\n'));
    f.context[action]();
    assert.equal(f.a.requestText, text); assert.equal(f.a.responseRecord, response);
  });

  test(`${action}: repeated clean actions preserve inactive tabs and monotonic sequence`, () => {
    const f = setup(), inactive = plain(f.b), sequence = f.state.replayTabSequence;
    f.context[action](); f.context[action]();
    assert.equal(f.state.replayTabs.length, 4); assert.equal(new Set(f.state.replayTabs.map(tab => tab.id)).size, 4);
    assert.equal(f.state.replayTabSequence, sequence + 2); assert.deepEqual(plain(f.b), inactive);
    assert.equal(f.state.replayTabs[1], f.b);
  });

  test(`${action}: tab-cap save rejection preserves existing local tabs without retry`, async () => {
    const f = setup(); f.context[action]();
    const tabs = [...f.state.replayTabs], sequence = f.state.replayTabSequence;
    const saving = f.context.flushQueuedWorkspaceStateSave();
    f.requests[0].resolve({ ok: false, status: 400, text: async () => 'too many replay tabs' });
    await saving;
    assert.deepEqual([...f.state.replayTabs], tabs); assert.equal(f.state.replayTabSequence, sequence);
    assert.equal(f.context.workspaceSaveDirty, false); assert.equal(f.context.workspaceSaveConflictPending, false);
    assert.equal(f.context.workspaceSaveTimer, null);
  });
}

test('blank creation with no active tab remains available', () => {
  const f = setup(); f.seed([]);
  f.context.openBlankReplayTab();
  assert.equal(f.state.replayTabs.length, 1); assert.equal(f.state.activeReplayTabId, f.state.replayTabs[0].id);
});

test('duplicate without active tab remains a no-op', () => {
  const f = setup(); f.seed([]); const before = snapshot(f);
  f.context.duplicateActiveReplayTab();
  assert.deepEqual(snapshot(f), before); assert.equal(f.renders.length, 0);
});

for (const action of ['openBlankReplayTab', 'duplicateActiveReplayTab']) {
  test(`${action}: WebSocket source does not inspect stale HTTP controls`, () => {
    const f = setup(), ws = { id: 'ws-tab', type: 'websocket', wsScheme: 'wss', wsHost: 'example.com',
      wsPort: 443, wsPath: '/', wsHeaders: [], wsEditorText: 'stored', wsHandshakeEdited: true,
      wsHandshakeText: 'original handshake', customLabel: 'socket' };
    f.state.replayTabs = [ws]; f.state.activeReplayTabId = ws.id;
    f.els.replayPortInput.value = '8x'; f.els.wsHandshakeHeaders = { value: 'edited handshake' };
    const created = [];
    f.context.wsReplayDisplayHandshakeText = tab => tab.wsHandshakeText;
    f.context.getWsReplayFrames = () => [];
    f.context.createWsReplayTab = seed => created.push(seed);
    f.context[action]();
    assert.equal(f.toasts.length, 0);
    if (action === 'duplicateActiveReplayTab') {
      assert.equal(created.length, 1); assert.equal(created[0].handshakeText, 'edited handshake');
      assert.equal(created[0].editorText, 'stored'); assert.equal(ws.wsHandshakeText, 'edited handshake');
    } else assert.equal(f.state.replayTabs.length, 2);
  });
}
