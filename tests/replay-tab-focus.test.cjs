// Real strip rendering/actions with DOM-equivalent focused-descendant removal.
// No bootstrap, requests, persistence, or browser traffic.
const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');

function fixture() {
  const document = { body: {}, activeElement: null };
  document.activeElement = document.body;
  const state = { activeTool: 'replay', activeReplayTabId: 'a', replayRenamingTabId: null,
    replayTabs: [{ id: 'a', customLabel: 'A' }, { id: 'b', customLabel: 'B' }] };
  let rows = [], modal = null, afterReplace = null;
  class Control {
    constructor(selector, parent = null) {
      Object.assign(this, { selector, parent, handlers: {}, isConnected: true, disabled: false,
        tabIndex: 0, visible: true, visibility: 'visible', dataset: {} });
    }
    matches(selector) { return selector === this.selector; }
    closest(selector) { return this.matches(selector) ? this : this.parent?.closest(selector); }
    addEventListener(type, callback) { this.handlers[type] = callback; }
    getClientRects() { return this.visible && this.isConnected ? [1] : []; }
    focus() { document.activeElement = this; }
    select() {}
    click() { this.handlers.click?.({ target: this, stopPropagation() {} }); }
  }
  const strip = {
    scrollLeft: 0,
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
        if (!tab.pinned && tab.id !== state.activeReplayTabId) row.controls['.replay-tab-pin-btn'].tabIndex = -1;
        row.querySelector = selector => row.controls[selector] || null;
        return row;
      });
      afterReplace?.();
    },
  };
  const els = { replayTabStrip: strip, newReplayTabButton: new Control('.new') };
  const animationFrames = [];
  const context = loadFunctions(['renderReplayTabs', 'toggleReplayTabPin', 'beginReplayTabRename', 'refreshReplayTabLabel'], {
    state, document, els, workspaceStateGeneration: 1, CSS: { escape: value => value },
    currentSessionId: () => 'session-a', getReplayTabVisualOrder: () => state.replayTabs,
    replayTabAutoLabel: tab => tab.customLabel, replayTabLabel: tab => tab.customLabel,
    replayTabTooltipLabel: tab => tab.customLabel, escapeHtml: value => value,
    wireReplayTabDragReorder() {}, scrollActiveReplayTabIntoView() {}, scheduleWorkspaceStateSave() {},
    persistReplayTabMetadataEdit() {}, getActiveReplayTab: () => state.replayTabs.find(tab => tab.id === state.activeReplayTabId),
    preserveActiveHttpReplayDraftBeforeNavigation: () => true,
    getActiveModalAction: () => modal, window: { getComputedStyle: control => ({ visibility: control.visibility }) },
    requestAnimationFrame: callback => animationFrames.push(callback),
  });
  context.renderReplay = () => context.renderReplayTabs();
  context.renderReplayTabs();
  return { context, state, document, els, animationFrames, Control,
    control: (id, selector = '.replay-tab-button') => rows.find(row => row.dataset.replayTabId === id)?.controls[selector],
    setModal: value => { modal = value; }, setAfterReplace: value => { afterReplace = value; } };
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
