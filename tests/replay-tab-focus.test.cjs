// Real strip rendering/actions with DOM-equivalent focused-descendant removal.
// No bootstrap, requests, persistence, or browser traffic.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');

function fixture() {
  const document = { body: {}, activeElement: null };
  document.activeElement = document.body;
  const focusListeners = new Set();
  document.addEventListener = (type, listener) => { if (type === 'focusin') focusListeners.add(listener); };
  document.removeEventListener = (type, listener) => { if (type === 'focusin') focusListeners.delete(listener); };
  const state = { activeTool: 'replay', activeReplayTabId: 'a', replayRenamingTabId: null,
    replayTabs: [{ id: 'a', customLabel: 'A' }, { id: 'b', customLabel: 'B' }] };
  let rows = [], modal = null, afterReplace = null, sessionId = 'session-a';
  const metadataEdits = [];
  class Control {
    constructor(selector, parent = null) {
      Object.assign(this, { selector, parent, handlers: {}, isConnected: true, disabled: false,
        tabIndex: 0, visible: true, visibility: 'visible', dataset: {} });
    }
    matches(selector) { return selector === this.selector; }
    closest(selector) { return this.matches(selector) ? this : this.parent?.closest(selector); }
    addEventListener(type, callback) { this.handlers[type] = callback; }
    getClientRects() { return this.visible && this.isConnected ? [1] : []; }
    focus() {
      if (document.activeElement === this) return;
      document.activeElement = this;
      [...focusListeners].forEach(listener => listener({ target: this }));
    }
    select() { this.selectCount = (this.selectCount || 0) + 1; }
    click() { this.handlers.click?.({ target: this, stopPropagation() {} }); }
  }
  const strip = {
    scrollLeft: 0,
    classList: { toggle() {} },
    contains: control => rows.some(row => row === control || Object.values(row.controls).includes(control)),
    querySelectorAll: () => rows,
    querySelector: selector => rows.find(row => selector.includes(`"${row.dataset.replayTabId}"`))?.controls['.replay-tab-name-input'] || null,
    set innerHTML(value) {
      if (this.contains(document.activeElement)) document.activeElement = document.body;
      rows.forEach(row => { row.isConnected = false; Object.values(row.controls).forEach(control => control.isConnected = false); });
      rows = state.replayTabs.map(tab => {
        const row = new Control('.replay-tab'); row.dataset.replayTabId = tab.id; row.controls = {};
        const selectors = ['.replay-tab-pin-btn', '.replay-tab-close', state.replayRenamingTabId === tab.id ? '.replay-tab-name-input' : '.replay-tab-button'];
        for (const selector of selectors) row.controls[selector] = new Control(selector, row);
        if (row.controls['.replay-tab-name-input']) row.controls['.replay-tab-name-input'].value = tab.customLabel || '';
        if (!tab.pinned && tab.id !== state.activeReplayTabId) row.controls['.replay-tab-pin-btn'].tabIndex = -1;
        row.querySelector = selector => row.controls[selector] || null;
        return row;
      });
      afterReplace?.();
    },
  };
  const els = { replayTabStrip: strip, newReplayTabButton: new Control('.new') };
  const animationFrames = [];
  const context = loadFunctions(['renderReplayTabs', 'toggleReplayTabPin', 'beginReplayTabRename', 'commitReplayTabRename', 'normalizeReplayTabCustomLabel', 'refreshReplayTabLabel'], {
    state, document, els, workspaceStateGeneration: 1, CSS: { escape: value => value },
    currentSessionId: () => sessionId, getReplayTabVisualOrder: () => state.replayTabs,
    replayTabAutoLabel: tab => tab.customLabel, replayTabLabel: tab => tab.customLabel,
    replayTabTooltipLabel: tab => tab.customLabel, escapeHtml: value => value,
    wireReplayTabDragReorder() {}, scrollActiveReplayTabIntoView() {}, scheduleWorkspaceStateSave() {},
    persistReplayTabMetadataEdit(tab, field, previous) { metadataEdits.push({ tab, field, previous, value: tab[field] }); },
    getActiveReplayTab: () => state.replayTabs.find(tab => tab.id === state.activeReplayTabId),
    preserveActiveHttpReplayDraftBeforeNavigation: () => true,
    getActiveModalAction: () => modal, window: { getComputedStyle: control => ({ visibility: control.visibility }) },
    requestAnimationFrame: callback => animationFrames.push(callback),
  });
  context.renderReplay = () => context.renderReplayTabs();
  context.renderReplayTabs();
  return { context, state, document, els, animationFrames, Control, metadataEdits, focusListenerCount: () => focusListeners.size,
    control: (id, selector = '.replay-tab-button') => rows.find(row => row.dataset.replayTabId === id)?.controls[selector],
    setModal: value => { modal = value; }, setAfterReplace: value => { afterReplace = value; },
    setSession: value => { sessionId = value; } };
}

for (const action of ['select', 'pin', 'background']) test(`${action} redraw retains the logical focused strip control`, () => {
  const f = fixture(), id = action === 'select' ? 'b' : 'a';
  const selector = action === 'pin' ? '.replay-tab-pin-btn' : '.replay-tab-button';
  const old = f.control(id, selector); old.focus();
  if (action === 'background') f.context.renderReplayTabs(); else old.click();
  assert.equal(old.isConnected, false);
  assert.equal(f.document.activeElement, f.control(id, selector));
  if (action === 'select') assert.equal(f.state.activeReplayTabId, 'b');
  if (action === 'pin') {
    assert.equal(f.state.replayTabs[0].pinned, true);
    f.document.activeElement.click();
    assert.equal(f.state.replayTabs[0].pinned, false, 'repeated keyboard activation can undo pin');
  }
});

test('unpinning an inactive tab falls back to its label instead of its non-tab-stop pin', () => {
  const f = fixture(); f.state.replayTabs[1].pinned = true; f.context.renderReplayTabs();
  const pin = f.control('b', '.replay-tab-pin-btn'); pin.focus(); pin.click();
  assert.equal(f.document.activeElement, f.control('b'));
});

for (const empty of [false, true]) test(`removed focused tab falls back to ${empty ? 'New tab' : 'active tab label'}`, () => {
  const f = fixture(); f.control('a', '.replay-tab-close').focus();
  // The synchronous model transition performed by closeRepeaterTab, before its render.
  f.state.replayTabs = empty ? [] : [f.state.replayTabs[1]];
  f.state.activeReplayTabId = empty ? null : 'b'; f.context.renderReplayTabs();
  assert.equal(f.document.activeElement, empty ? f.els.newReplayTabButton : f.control('b'));
});

for (const boundary of ['outside editor', 'newer focus', 'modal', 'other tool']) test(`redraw does not steal focus: ${boundary}`, () => {
  const f = fixture(), outside = new f.Control('.editor'); f.control('a').focus();
  if (boundary === 'outside editor') outside.focus();
  if (boundary === 'newer focus') f.setAfterReplace(() => outside.focus());
  if (boundary === 'modal') f.setModal({ modal: {} });
  if (boundary === 'other tool') f.state.activeTool = 'map';
  f.context.renderReplayTabs();
  assert.equal(f.document.activeElement, boundary.includes('focus') || boundary === 'outside editor' ? outside : f.document.body);
});

test('rename retains its existing deferred input focus and preserves the live input on redraw', () => {
  const f = fixture(); f.control('a').focus(); f.control('a').click();
  assert.equal(f.document.activeElement, f.document.body);
  f.animationFrames.forEach(callback => callback());
  const input = f.control('a', '.replay-tab-name-input'); assert.equal(f.document.activeElement, input);
  f.context.renderReplayTabs(); assert.equal(f.document.activeElement, input); assert.equal(input.isConnected, true);
});

test('invisible restored control is not focused', () => {
  const f = fixture(); f.control('a', '.replay-tab-pin-btn').focus();
  f.setAfterReplace(() => { f.control('a', '.replay-tab-pin-btn').visibility = 'hidden'; });
  f.context.renderReplayTabs(); assert.equal(f.document.activeElement, f.control('a'));
});

function rename(f) {
  f.control('a').focus(); f.control('a').click(); f.animationFrames.splice(0).forEach(callback => callback());
  return f.control('a', '.replay-tab-name-input');
}
function key(input, value, extra = {}) {
  const event = { key: value, preventDefault() { this.defaultPrevented = true; }, ...extra };
  input.handlers.keydown(event); return event;
}

for (const type of ['http', 'websocket']) for (const action of ['Enter', 'Escape']) {
  test(`${type} rename ${action} returns focus to its own label without changing request drafts`, () => {
    const f = fixture(); Object.assign(f.state.replayTabs[0], { type, requestText: 'GET /unfinished HTT' });
    f.state.replayTabs[1].requestText = 'other draft';
    const input = rename(f), tab = f.state.replayTabs[0]; input.value = ' New label ';
    assert.equal(key(input, action).defaultPrevented, true);
    assert.equal(f.document.activeElement, f.control('a')); assert.equal(input.isConnected, false);
    assert.equal(f.state.activeReplayTabId, 'a'); assert.equal(f.state.replayRenamingTabId, null);
    assert.equal(tab.customLabel, action === 'Enter' ? 'New label' : 'A');
    assert.equal(tab.requestText, 'GET /unfinished HTT'); assert.equal(f.state.replayTabs[1].requestText, 'other draft');
    assert.equal(f.metadataEdits.length, action === 'Enter' ? 1 : 0);
    const focus = f.document.activeElement;
    key(input, action); input.handlers.blur();
    assert.equal(f.document.activeElement, focus); assert.equal(f.metadataEdits.length, action === 'Enter' ? 1 : 0);
  });
}

for (const action of ['Enter', 'Escape']) test(`composing rename ${action} retains the focused input`, () => {
  const f = fixture(), input = rename(f); input.value = '한글 draft';
  assert.equal(key(input, action, { isComposing: true }).defaultPrevented, undefined);
  assert.equal(f.document.activeElement, input); assert.equal(f.control('a', '.replay-tab-name-input'), input);
  assert.equal(input.value, '한글 draft'); assert.equal(f.metadataEdits.length, 0);
});

test('rename blur commits once without taking focus back from its destination', () => {
  const f = fixture(), input = rename(f), outside = new f.Control('.editor'); input.value = 'Saved label';
  outside.focus(); input.handlers.blur(); input.handlers.blur();
  assert.equal(f.document.activeElement, outside); assert.equal(f.state.replayTabs[0].customLabel, 'Saved label');
  assert.equal(f.metadataEdits.length, 1);
});

for (const action of ['Enter', 'Escape']) for (const boundary of ['outside focus', 'modal', 'other tool', 'active tab', 'session', 'generation', 'tab object', 'new rename']) {
  test(`${action} rename exit does not reclaim focus across ${boundary}`, () => {
    const f = fixture(), input = rename(f), outside = new f.Control('.newer'); input.value = 'Name';
    f.setAfterReplace(() => {
      if (boundary === 'outside focus') outside.focus();
      if (boundary === 'modal') f.setModal({ modal: {} });
      if (boundary === 'other tool') f.state.activeTool = 'map';
      if (boundary === 'active tab') f.state.activeReplayTabId = 'b';
      if (boundary === 'session') f.setSession('session-b');
      if (boundary === 'generation') f.context.workspaceStateGeneration++;
      if (boundary === 'tab object') f.state.replayTabs[0] = { ...f.state.replayTabs[0] };
      if (boundary === 'new rename') f.state.replayRenamingTabId = 'b';
    });
    key(input, action);
    assert.equal(f.document.activeElement, boundary === 'outside focus' ? outside : f.document.body);
    assert.equal(f.metadataEdits.length, action === 'Enter' ? 1 : 0);
  });
}

for (const unavailable of ['hidden', 'no layout', 'disabled', 'negative tabindex', 'detached', 'missing']) {
  test(`keyboard rename exit never falls back to another control when its label is ${unavailable}`, () => {
    const f = fixture(), input = rename(f);
    f.setAfterReplace(() => {
      const label = f.control('a');
      if (unavailable === 'hidden') label.visibility = 'hidden';
      if (unavailable === 'no layout') label.visible = false;
      if (unavailable === 'disabled') label.disabled = true;
      if (unavailable === 'negative tabindex') label.tabIndex = -1;
      if (unavailable === 'detached') label.isConnected = false;
      if (unavailable === 'missing') delete label.parent.controls['.replay-tab-button'];
    });
    key(input, 'Escape'); assert.equal(f.document.activeElement, f.document.body);
    assert.equal(f.metadataEdits.length, 0);
  });
}

for (const boundary of ['session', 'generation', 'tab object', 'active tab', 'new rename']) {
  test(`stale rename exit cannot focus or change a newer ${boundary}`, () => {
    const f = fixture(), input = rename(f), outside = new f.Control('.newer');
    input.value = 'Old draft';
    if (boundary === 'session') f.setSession('session-b');
    if (boundary === 'generation') f.context.workspaceStateGeneration++;
    if (boundary === 'tab object') f.state.replayTabs[0] = { ...f.state.replayTabs[0] };
    if (boundary === 'active tab') f.state.activeReplayTabId = 'b';
    if (boundary === 'new rename') f.state.replayRenamingTabId = 'b';
    outside.focus(); key(input, 'Enter'); key(input, 'Escape'); input.handlers.blur();
    assert.equal(f.document.activeElement, outside); assert.equal(f.state.replayTabs[0].customLabel, 'A');
    assert.equal(f.metadataEdits.length, 0);
  });
}

test('a rename exit callback that did not own focus does not restore it', () => {
  const f = fixture(), input = rename(f); f.document.activeElement = f.document.body;
  key(input, 'Escape'); assert.equal(f.document.activeElement, f.document.body);
});

function beginPendingRename(f, origin = 'label') {
  if (origin === 'label') f.control('a').focus();
  if (origin === 'editor') new f.Control('.editor').focus();
  f.control('a').click();
  return f.control('a', '.replay-tab-name-input');
}
function flushRenameFocus(f) { f.animationFrames.splice(0).forEach(callback => callback()); }

function installSettingsControls(f) {
  // Native focus changes blur an already focused rename. The base fixture leaves
  // blur explicit so tests can invoke detached callbacks independently.
  const focus = f.Control.prototype.focus;
  f.Control.prototype.focus = function () {
    if (f.document.activeElement !== this) f.document.activeElement?.handlers?.blur?.();
    focus.call(this);
  };
  const classes = new Set(['hidden']);
  f.els.displaySettingsModal = {
    classList: { contains: name => classes.has(name), add: name => classes.add(name), remove: name => classes.delete(name) },
    querySelectorAll: () => [], querySelector: () => null,
  };
  f.els.openDisplaySettingsButton = new f.Control('.settings-open');
  f.els.closeDisplaySettingsButton = new f.Control('.settings-close');
  f.document.querySelector = () => f.els.openDisplaySettingsButton;
  Object.assign(f.context, {
    compareLoadGeneration: 0, displaySettingsReturnFocus: null, displaySettingsPreviewActive: false,
    displaySettingsEditedControls: new Set(), activeConfirmDialog: null,
    hydrateDisplaySettingsForm() {}, applyDisplaySettingsState() {}, renderShortcutReference() {}, loadVulndataStatus() {},
    saveDisplaySettingsFromForm() { assert.fail('No Settings Apply'); }, fetch() { assert.fail('No API request'); },
  });
  for (const name of ['openDisplaySettingsModal', 'closeDisplaySettingsModal', 'selectSettingsTab', 'isModalVisible', 'getActiveModalAction', 'restoreModalFocus']) {
    const match = appSource.match(new RegExp(`^function ${name}\\([^]*?^\\}`, 'm'));
    assert.ok(match, name); vm.runInContext(match[0], f.context);
  }
  for (const action of ['open', 'close']) {
    const binding = `els.${action}DisplaySettingsButton.addEventListener("click", ${action}DisplaySettingsModal);`;
    assert.ok(appSource.includes(binding)); vm.runInContext(binding, f.context);
  }
}

for (const origin of ['body', 'editor', 'label']) test(`uninterrupted ${origin}-origin rename gets initial focus and selects its name once`, () => {
  const f = fixture(), input = beginPendingRename(f, origin);
  flushRenameFocus(f);
  assert.equal(f.document.activeElement, input); assert.equal(input.selectCount, 1);
  assert.equal(f.metadataEdits.length, 0); assert.equal(f.focusListenerCount(), 0);
});

for (const origin of ['body', 'editor', 'label']) for (const close of [false, true]) for (const buttonFocus of [false, true]) {
  test(`${origin}-origin rename respects actual Settings ${close ? 'open/close' : 'open'} with ${buttonFocus ? 'focused' : 'retained-focus'} activation`, () => {
    const f = fixture(); installSettingsControls(f); const input = beginPendingRename(f, origin), initial = f.document.activeElement;
    if (buttonFocus) f.els.openDisplaySettingsButton.focus();
    f.els.openDisplaySettingsButton.click();
    assert.equal(f.document.activeElement, f.els.closeDisplaySettingsButton);
    assert.equal(f.context.getActiveModalAction().modal, f.els.displaySettingsModal);
    if (close) {
      f.els.closeDisplaySettingsButton.click();
      assert.equal(f.context.getActiveModalAction(), null);
      if (origin === 'editor' && !buttonFocus) assert.equal(f.document.activeElement, initial, 'actual Settings close produces the editor ABA case');
    }
    const newerFocus = f.document.activeElement; flushRenameFocus(f);
    assert.equal(f.document.activeElement, newerFocus); assert.equal(input.selectCount || 0, 0);
    assert.equal(f.state.activeTool, 'replay'); assert.equal(f.state.replayRenamingTabId, 'a');
    assert.equal(f.state.replayTabs[0].customLabel, 'A'); assert.equal(f.metadataEdits.length, 0);
    assert.equal(f.focusListenerCount(), 0);
  });
}

test('Settings after initial rename focus still commits ordinary blur once and retains modal focus', () => {
  const f = fixture(); installSettingsControls(f); const input = beginPendingRename(f); flushRenameFocus(f);
  input.value = 'Typed label'; f.els.openDisplaySettingsButton.focus(); f.els.openDisplaySettingsButton.click();
  assert.equal(f.state.replayTabs[0].customLabel, 'Typed label'); assert.equal(f.metadataEdits.length, 1);
  assert.equal(f.state.replayRenamingTabId, null); assert.equal(f.document.activeElement, f.els.closeDisplaySettingsButton);
});

test('already-focused rename input keeps user caret and is not selected again', () => {
  const f = fixture(), input = beginPendingRename(f); input.focus(); input.value = 'User draft';
  input.selectionStart = 2; input.selectionEnd = 4; flushRenameFocus(f);
  assert.equal(f.document.activeElement, input); assert.equal(input.value, 'User draft');
  assert.equal(input.selectionStart, 2); assert.equal(input.selectionEnd, 4); assert.equal(input.selectCount || 0, 0);
  assert.equal(f.focusListenerCount(), 0); assert.equal(f.metadataEdits.length, 0);
});

for (const boundary of ['session', 'generation', 'tab object', 'active tab', 'other tool', 'hidden', 'no layout', 'disabled', 'negative tabindex', 'detached']) {
  test(`queued rename focus retires cleanly after ${boundary}`, () => {
    const f = fixture(), input = beginPendingRename(f), prior = f.document.activeElement;
    if (boundary === 'session') f.setSession('session-b');
    if (boundary === 'generation') f.context.workspaceStateGeneration++;
    if (boundary === 'tab object') f.state.replayTabs[0] = { ...f.state.replayTabs[0] };
    if (boundary === 'active tab') f.state.activeReplayTabId = 'b';
    if (boundary === 'other tool') f.state.activeTool = 'map';
    if (boundary === 'hidden') input.visibility = 'hidden';
    if (boundary === 'no layout') input.visible = false;
    if (boundary === 'disabled') input.disabled = true;
    if (boundary === 'negative tabindex') input.tabIndex = -1;
    if (boundary === 'detached') input.isConnected = false;
    flushRenameFocus(f); assert.equal(f.document.activeElement, prior); assert.equal(input.selectCount || 0, 0);
    assert.equal(f.focusListenerCount(), 0); assert.equal(f.metadataEdits.length, 0);
  });
}

test('actual other-tab click cancels the pending focus listener before its old RAF runs', () => {
  const f = fixture(); beginPendingRename(f); assert.equal(f.focusListenerCount(), 1);
  f.control('b').click(); const newer = f.document.activeElement;
  assert.equal(f.state.activeReplayTabId, 'b'); assert.equal(f.focusListenerCount(), 0);
  flushRenameFocus(f); assert.equal(f.document.activeElement, newer);
});

test('replacement rename owns its listener independently of the old queued callback', () => {
  const f = fixture(), old = beginPendingRename(f), oldFrame = f.animationFrames.shift();
  f.context.workspaceStateGeneration++; f.context.renderReplayTabs();
  const fresh = f.control('a', '.replay-tab-name-input');
  assert.notEqual(old, fresh); assert.equal(f.focusListenerCount(), 1);
  oldFrame(); assert.equal(f.focusListenerCount(), 1); assert.equal(f.document.activeElement, f.document.body);
  flushRenameFocus(f); assert.equal(f.document.activeElement, fresh); assert.equal(f.focusListenerCount(), 0);
});

test('passive rename redraw preserves its one pending initial focus callback', () => {
  const f = fixture(), input = beginPendingRename(f); f.context.renderReplayTabs();
  assert.equal(f.control('a', '.replay-tab-name-input'), input); assert.equal(f.focusListenerCount(), 1);
  assert.equal(f.animationFrames.length, 1); flushRenameFocus(f);
  assert.equal(f.document.activeElement, input); assert.equal(f.focusListenerCount(), 0);
});

test('a captured outside editor removed without focusin is not treated as the removed strip label', () => {
  const f = fixture(), input = beginPendingRename(f, 'editor');
  f.document.activeElement.isConnected = false; f.document.activeElement = f.document.body;
  flushRenameFocus(f); assert.equal(f.document.activeElement, f.document.body);
  assert.equal(input.selectCount || 0, 0); assert.equal(f.focusListenerCount(), 0);
});
