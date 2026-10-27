// Inert saved history and shipped editor state only; no app, server or request execution.
const assert = require('node:assert/strict');
const vm = require('node:vm');
const test = require('node:test');
const fs = require('node:fs');
const { appSource } = require('./frontend-test-helpers.cjs');
const { editorFixture, source } = require('./replay-editor-fixture.cjs');
const swipeSource = process.env.REPLAY_SWIPE_SOURCE ? fs.readFileSync(process.env.REPLAY_SWIPE_SOURCE, 'utf8') : appSource;

function setup() {
  const f = editorFixture();
  for (const tab of [f.a, f.b]) {
    tab.historyEntries = [0, 1].map(index => ({
      request: { ...tab.baseRequest, path: `/${tab.customLabel}-history-${index}` },
      requestText: `GET /${tab.customLabel}-history-${index} HTTP/1.1\r\nHost: example.com\r\n\r\n`,
    }));
    tab.historyIndex = 1;
  }
  const timers = new Map(); let next = 0;
  Object.assign(f.context, {
    setTimeout: callback => { timers.set(++next, callback); return next; },
    clearTimeout: id => timers.delete(id),
  });
  f.context.window.matchMedia = () => ({ matches: true });
  for (const name of ['normalizeHttpRequestAuthority', 'httpRequestAuthoritiesEquivalent', 'joinAuthority', 'targetStatesEquivalent', 'canNavigateReplayHistory', 'restoreRepeaterHistoryEntry', 'navigateReplayHistory']) {
    vm.runInContext(source(name), f.context);
  }
  vm.runInContext(swipeSource.slice(swipeSource.indexOf('const REPLAY_SWIPE_THRESHOLD_PX'), swipeSource.indexOf('function navigateReplayHistory')), f.context);
  f.render();
  f.timers = timers;
  f.pull = (deltaX = -180) => f.context.onReplaySwipeWheel({ deltaX, deltaY: 0, preventDefault() {} }, {});
  f.settle = () => f.context.settleReplaySwipe();
  return f;
}

test('healthy backward/forward gesture commits once, including harmless redraw/selection', () => {
  const f = setup(); f.pull(); f.render();
  f.cv().view.dispatch({ selection: { anchor: 1 } });
  f.settle(); f.settle();
  assert.equal(f.a.historyIndex, 0);
  f.pull(180); f.settle(); assert.equal(f.a.historyIndex, 1);
  assert.equal(f.requests.length, 0);
});

test('swipe begun on A cannot overwrite unsent request on B', () => {
  const f = setup(); const beforeA = f.a.requestText; const beforeB = f.b.requestText;
  f.pull(); f.switchTo(f.b); f.settle();
  assert.equal(f.b.requestText, beforeB); assert.equal(f.a.requestText, beforeA);
  assert.equal(f.a.historyIndex, 1); assert.equal(f.b.historyIndex, 1);
});

for (const [name, interrupt] of [
  ['tab away and back', f => { f.switchTo(f.b); f.switchTo(f.a); }],
  ['session changed', f => { f.state.activeSession = { id: 'session-b' }; }],
  ['workspace reloaded', f => { f.context.workspaceStateGeneration++; }],
  ['workspace unloaded', f => { f.context.workspaceLoaded = false; }],
  ['tool changed', f => { f.state.activeTool = 'proxy'; }],
  ['tab replaced with same id', f => { f.state.replayTabs[0] = { ...f.a }; }],
  ['new request edit', f => f.edit(5, 6, 'new')],
  ['request edit then undo', f => { f.edit(5, 6, 'new'); f.undo(); }],
  ['new target draft', f => { f.els.replayHostInput.value = 'draft.example.com'; }],
  ['new version draft', f => { f.versionSelect.value = 'HTTP/2'; }],
  ['explicit cancellation', f => f.context.resetReplaySwipe()],
  ['sending began', f => f.context._replaySendControllers.set(f.a.id, {})],
]) {
  test(`pending gesture does not navigate after ${name}`, () => {
    const f = setup(); f.pull(); interrupt(f); const before = f.a.requestText;
    f.settle(); assert.equal(f.a.historyIndex, 1); assert.equal(f.a.requestText, before);
    for (const tab of f.state.replayTabs) assert.equal(tab.historyIndex, 1);
    assert.equal(f.requests.length, 0);
  });
}

test('remaining wheel events cannot re-arm the same stale gesture on another tab', () => {
  const f = setup(); f.pull(); f.switchTo(f.b); f.pull(); f.pull(); f.settle();
  assert.equal(f.b.historyIndex, 1);
  f.pull(); f.settle(); assert.equal(f.b.historyIndex, 0);
});

test('native release and mouseleave cancellation preserve existing behavior', () => {
  const f = setup(); f.context.window.__sniperScrollGesture('began'); f.pull();
  f.context.window.__sniperScrollGesture('ended'); assert.equal(f.a.historyIndex, 0);
  const listeners = {};
  const workbench = { addEventListener: (name, listener) => { listeners[name] = listener; } };
  const getElement = f.document.getElementById;
  f.document.getElementById = id => id === 'httpReplayWorkbench' ? workbench : getElement(id);
  f.context.wireReplayHistorySwipe();
  f.context.window.__sniperScrollGesture('began'); f.pull(180); listeners.mouseleave();
  f.context.window.__sniperScrollGesture('ended'); assert.equal(f.a.historyIndex, 0);
});


test('quiet-wheel timer settles while a short or retreated pull never commits', () => {
  const f = setup(); f.pull(-80); f.settle(); assert.equal(f.a.historyIndex, 1);
  f.pull(); f.pull(100); f.settle(); assert.equal(f.a.historyIndex, 1);
  f.pull(); [...f.timers.values()][0](); assert.equal(f.a.historyIndex, 0);
});

test('in-place hex byte edits invalidate the release without copying on each wheel', () => {
  const f = setup(); f.state.replayMessageViews.request = 'hex'; f.render();
  let snapshots = 0;
  const snapshot = f.context.replaySwipeDraftSnapshot;
  f.context.replaySwipeDraftSnapshot = tab => { snapshots++; return snapshot(tab); };
  f.pull(); f.pull(-10); f.pull(-10); assert.equal(snapshots, 1);
  f.a.requestBytes[5] ^= 1;
  f.settle(); assert.equal(snapshots, 2); assert.equal(f.a.historyIndex, 1);
});

test('legacy uncommitted hex input remains untouched when edited during a pull', () => {
  const f = setup(); f.state.replayMessageViews.request = 'hex';
  f.context.getCMView = () => null; f.els.replayRequestCM = null;
  f.a.requestBytes = new Uint8Array([65]);
  const input = { value: '41' };
  f.els.replayRequestHighlight = { innerText: '', querySelector: () => input };
  f.pull(); input.value = 'f'; f.settle();
  assert.equal(f.a.historyIndex, 1); assert.equal(input.value, 'f');
  assert.equal(f.a.requestBytes[0], 65);
});
