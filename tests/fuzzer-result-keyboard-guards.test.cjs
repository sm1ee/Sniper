// Actual Fuzzer event binding and shared key policy, with inert selection only.
// No run handlers, requests, native app or browser are invoked.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
function fixture(count = 3, initial = 1) {
  class HTMLElement {
    constructor(tagName = 'DIV') { this.tagName = tagName; this.isContentEditable = false; }
    closest() { return this.editableParent || null; }
  }
  const shell = new HTMLElement(), listeners = {}, selections = [];
  const document = { activeElement: shell };
  let selected = initial, modal = null;
  shell.setAttribute = () => {};
  shell.addEventListener = (type, callback) => listeners[type] = callback;
  const c = loadFunctions(['tableArrowStep', 'isEditableTarget'], {
    HTMLElement, document, getActiveModalAction: () => modal,
    els: { fuzzerResultsBody: { closest: () => shell, addEventListener() {} } },
    visibleFuzzerResults: () => Array.from({ length: count }, (_, index) => ({ index })),
    fuzzerSelectedResultIndex: () => selected,
    selectFuzzerResultIndex(index, options) { selected = index; selections.push({ index, scroll: options.scroll }); },
    requestAnimationFrame() {}, renderFuzzerResultsVirtual() {},
  });
  const start = appSource.indexOf('  // Fuzzer results shell (for keyboard navigation + focus)');
  const end = appSource.indexOf('  // Fuzzer detail view mode tabs', start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(`(() => { ${appSource.slice(start, end)} })()`, c);
  return { shell, document, selections, node: tag => new HTMLElement(tag), get selected() { return selected; },
    openModal() { modal = { modal: {} }; },
    key(key, flags = {}) {
      const event = { key, target: shell, defaultPrevented: false, preventCalls: 0,
        preventDefault() { this.defaultPrevented = true; this.preventCalls++; }, ...flags };
      listeners.keydown(event); return event;
    },
  };
}
for (const key of ['ArrowUp', 'ArrowDown']) {
  for (const flag of ['ctrlKey', 'metaKey', 'altKey', 'shiftKey', 'defaultPrevented', 'isComposing']) test(`${key} respects ${flag} without changing selection or consuming the event`, () => {
    const f = fixture(), e = f.key(key, { [flag]: true });
    assert.equal(f.selected, 1); assert.deepEqual(f.selections, []); assert.equal(e.preventCalls, 0);
    assert.equal(e.defaultPrevented, flag === 'defaultPrevented');
  });
  test(`${key} does not act behind an active modal`, () => {
    const f = fixture(); f.openModal(); const e = f.key(key);
    assert.equal(e.preventCalls, 0); assert.deepEqual(f.selections, []);
  });
  for (const tag of ['INPUT', 'TEXTAREA', 'SELECT', 'OPTION', 'BUTTON']) test(`${key} leaves ${tag} descendant keys to the control`, () => {
    const f = fixture(), e = f.key(key, { target: f.node(tag) });
    assert.equal(e.preventCalls, 0); assert.deepEqual(f.selections, []);
  });
  for (const kind of ['contenteditable', 'editable-parent']) test(`${key} leaves ${kind} navigation alone`, () => {
    const f = fixture(), target = f.node('SPAN');
    if (kind === 'contenteditable') target.isContentEditable = true;
    else target.editableParent = f.node('DIV');
    const e = f.key(key, { target }); assert.equal(e.preventCalls, 0); assert.deepEqual(f.selections, []);
  });
  test(`${key} selects once and repeated boundary arrows remain no-ops`, () => {
    const f = fixture(), next = key === 'ArrowUp' ? 0 : 2;
    const e = f.key(key); assert.equal(e.preventCalls, 1);
    assert.deepEqual(f.selections, [{ index: next, scroll: true }]);
    for (let i = 0; i < 5; i++) f.key(key);
    assert.equal(f.selected, next); assert.equal(f.selections.length, 1);
  });
  test(`${key} retains first/last fallback and empty-result default prevention`, () => {
    const f = fixture(3, -1); f.key(key);
    assert.equal(f.selected, key === 'ArrowUp' ? 2 : 0);
    const empty = fixture(0, -1), e = empty.key(key);
    assert.equal(e.preventCalls, 1); assert.deepEqual(empty.selections, []);
  });
}
for (const key of ['Home', 'End', ' ', 'Escape', 'ArrowLeft', 'ArrowRight']) test(`${key} remains outside Fuzzer row navigation`, () => {
  const f = fixture(), e = f.key(key);
  assert.equal(e.preventCalls, 0); assert.deepEqual(f.selections, []);
});

test('Enter reactivates only the currently selected result from the focused shell', () => {
  const f = fixture(), e = f.key('Enter');
  assert.equal(e.preventCalls, 1);
  assert.deepEqual(f.selections, [{ index: 1, scroll: true }]);
  assert.equal(f.selected, 1);
});

for (const flag of ['ctrlKey', 'metaKey', 'altKey', 'shiftKey', 'defaultPrevented', 'isComposing', 'repeat']) {
  test(`Enter respects ${flag} without reactivating or consuming the event`, () => {
    const f = fixture(), e = f.key('Enter', { [flag]: true });
    assert.deepEqual(f.selections, []); assert.equal(e.preventCalls, 0);
    assert.equal(e.defaultPrevented, flag === 'defaultPrevented');
  });
}

test('Enter does not reactivate behind a modal or after focus leaves the shell', () => {
  const modal = fixture(); modal.openModal();
  assert.equal(modal.key('Enter').preventCalls, 0); assert.deepEqual(modal.selections, []);
  const blurred = fixture(); blurred.document.activeElement = blurred.node('BUTTON');
  assert.equal(blurred.key('Enter').preventCalls, 0); assert.deepEqual(blurred.selections, []);
});

for (const tag of ['INPUT', 'TEXTAREA', 'SELECT', 'OPTION', 'BUTTON', 'A', 'SPAN', 'DIV']) {
  test(`Enter from a ${tag} descendant is not result-shell activation`, () => {
    const f = fixture(), target = f.node(tag); f.document.activeElement = target;
    const e = f.key('Enter', { target });
    assert.equal(e.preventCalls, 0); assert.deepEqual(f.selections, []);
  });
}

for (const kind of ['contenteditable', 'editable-parent']) test(`Enter leaves ${kind} shell editing alone`, () => {
  const f = fixture();
  if (kind === 'contenteditable') f.shell.isContentEditable = true;
  else f.shell.editableParent = f.node('DIV');
  assert.equal(f.key('Enter').preventCalls, 0); assert.deepEqual(f.selections, []);
});

for (const [count, selected] of [[3, -1], [0, -1], [0, 1], [3, 3]]) {
  test(`Enter ignores absent or non-visible selection (${count} results, index ${selected})`, () => {
    const f = fixture(count, selected), e = f.key('Enter');
    assert.equal(e.preventCalls, 0); assert.deepEqual(f.selections, []);
  });
}

// End-to-end initialized result handlers and the complete global key dispatcher.
// Fixed completed records and fake retained-detail reads only; no run/bootstrap.
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function resultDetailFixture(count = 1) {
  const document = { activeElement: null }, globalKeys = [];
  class HTMLElement {
    constructor(id) {
      Object.assign(this, { id, tagName: 'DIV', isContentEditable: false, handlers: new Map(),
        attributes: {}, innerHTML: '', textContent: '', scrollTop: 0, clientHeight: 180 });
      const classes = new Set();
      this.classList = { add: x => classes.add(x), remove: x => classes.delete(x), contains: x => classes.has(x) };
    }
    addEventListener(type, callback) { this.handlers.set(type, callback); }
    setAttribute(name, value) { this.attributes[name] = value; }
    closest() { return null; }
    querySelector() { return null; }
    querySelectorAll() { return []; }
    focus() { document.activeElement = this; }
  }
  const ids = ['fuzzerResultsBody', 'fuzzerResultsHead', 'fuzzerDetailPanel', 'fuzzerDetailResizer',
    'fuzzerDetailReqCM', 'fuzzerDetailResCM', 'fuzzerDetailResponseMeta'];
  const els = Object.fromEntries(ids.map(id => [id, new HTMLElement(id)]));
  els.fuzzerDetailPanel.classList.add('hidden'); els.fuzzerDetailResizer.classList.add('hidden');
  const shell = new HTMLElement('result-shell');
  els.fuzzerResultsBody.closest = selector => selector === '.history-table-shell' ? shell : null;
  document.getElementById = id => els[id] || null;
  document.addEventListener = (type, fn) => { assert.equal(type, 'keydown'); globalKeys.push(fn); };
  const entries = Array.from({ length: count }, (_, index) => ({ sourceIndex: index,
    result: Object.freeze({ index, payload: `synthetic-${index}`, transaction_id: `synthetic-tx-${index}`, status: 200 }) }));
  let visibleEntries = entries;
  const state = { activeTool: 'fuzzer', activeSession: { id: 'synthetic-session' },
    fuzzerAttackRecordId: 'synthetic-completed-run', fuzzerAttackRecord: { results: entries.map(e => e.result) },
    _selectedFuzzerResultKey: null };
  const requests = [], panes = new Map(), renders = [];
  const forbidden = () => assert.fail('No run, stop, send, save, clipboard or real request is permitted');
  const c = loadFunctions([
    'tableArrowStep', 'isEditableTarget', 'fuzzerSelectionKeyForResult', 'fuzzerSelectedResultIndex',
    'fuzzerResultsShell', 'renderFuzzerResultsVirtual', 'scrollFuzzerResultToIndex', 'selectFuzzerResultIndex',
    'selectFuzzerRow', 'showFuzzerResultDetail', 'clearFuzzerResponsePane', 'currentSessionId',
    'sessionQueryPath', 'transactionPath', 'escapeHtml', 'formatStatus', 'formatSize',
  ], {
    HTMLElement, Element: HTMLElement, document, els, state, _fuzzerDetailGeneration: 0,
    visibleFuzzerResults: () => visibleEntries, getActiveModalAction: () => null,
    cancelPendingFuzzerComparison() {}, renderFuzzerResultsWorkflow() {}, syncFuzzerResponsePreview() {},
    measuredFuzzerResultRowHeight: 30, FUZZER_RESULT_ROW_HEIGHT: 30, FUZZER_RESULT_BUFFER_ROWS: 1,
    renderFuzzerDetailPanes: record => renders.push(record.id),
    updateCodePaneCM: (key, node, value) => panes.set(key, value),
    requestAnimationFrame: callback => { callback(); return 1; },
    fetch(url, options) {
      assert.equal(options, undefined);
      assert.match(url, /^\/api\/transactions\/synthetic-tx-\d+\?session_id=synthetic-session$/);
      const request = { url, ...deferred() }; requests.push(request); return request.promise;
    },
    startFuzzer: forbidden, stopFuzzerAttack: forbidden, sendReplay: forbidden,
    scheduleWorkspaceStateSave: forbidden, copyTextToClipboard: forbidden,
  });
  let start = appSource.indexOf('  // Fuzzer results shell (for keyboard navigation + focus)');
  let end = appSource.indexOf('  // Fuzzer detail view mode tabs', start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(`(() => {${appSource.slice(start, end)}})()`, c);
  start = appSource.indexOf('  document.addEventListener("keydown", (event) => {\n    const activeModalAction');
  end = appSource.indexOf('\n\n  document.addEventListener("copy",', start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(appSource.slice(start, end), c);
  c.renderFuzzerResultsVirtual(); shell.focus();
  const key = (key, flags = {}) => {
    const event = { key, target: shell, defaultPrevented: false, ctrlKey: false, metaKey: false,
      altKey: false, shiftKey: false, isComposing: false, repeat: false, ...flags,
      preventDefault() { this.defaultPrevented = true; } };
    shell.handlers.get('keydown')(event);
    for (const callback of globalKeys) callback(event);
    return event;
  };
  return { c, state, els, shell, document, requests, panes, renders, key,
    setVisible: indexes => { visibleEntries = indexes.map(index => entries[index]); } };
}
const ok = id => ({ ok: true, status: 200, json: async () => ({ id }) });

test('full dispatcher: arrows open retained details and Enter reopens the selected successful result', async () => {
  const f = resultDetailFixture(2);
  assert.equal(f.shell.attributes.tabindex, '0');
  assert.equal(f.key('ArrowDown').defaultPrevented, true);
  assert.equal(f.state._selectedFuzzerResultKey, 'tx:synthetic-tx-0');
  assert.equal(f.els.fuzzerDetailPanel.classList.contains('hidden'), false);
  assert.equal(f.requests.length, 1);
  f.requests[0].resolve(ok('synthetic-tx-0')); await tick();
  assert.deepEqual(f.renders, ['synthetic-tx-0']);
  assert.equal(f.key('Enter').defaultPrevented, true);
  assert.equal(f.requests.length, 2);
  assert.equal(f.requests[1].url, f.requests[0].url);
  f.requests[1].resolve(ok('synthetic-tx-0')); await tick();
  assert.deepEqual(f.renders, ['synthetic-tx-0', 'synthetic-tx-0']);
  f.key('ArrowDown'); assert.equal(f.requests.length, 3);
  f.requests[2].resolve(ok('synthetic-tx-1')); await tick();
  assert.equal(f.state._fuzzerDetailRecord.id, 'synthetic-tx-1');
});

for (const failure of ['HTTP 503', 'read rejection']) {
  test(`full dispatcher: Enter retries one selected row after ${failure} without repeating or starting a run`, async () => {
    const f = resultDetailFixture(); f.key('ArrowDown');
    for (let i = 0; i < 3; i++) for (const key of ['ArrowUp', 'ArrowDown']) f.key(key);
    assert.equal(f.requests.length, 1, 'boundary arrows retain pending-read protection');
    if (failure === 'HTTP 503') f.requests[0].resolve({ ok: false, status: 503 });
    else f.requests[0].reject(new Error('Synthetic temporary read failure'));
    await tick();
    assert.match(f.panes.get('fuzzerDetailReq'), /Failed to load transaction: 503|Synthetic temporary read failure/);
    for (const key of ['ArrowUp', 'ArrowDown', ' ']) f.key(key);
    assert.equal(f.requests.length, 1);
    assert.equal(f.key('Enter').defaultPrevented, true);
    assert.equal(f.requests.length, 2);
    assert.equal(f.requests[1].url, f.requests[0].url);
    for (let i = 0; i < 5; i++) assert.equal(f.key('Enter', { repeat: true }).defaultPrevented, false);
    assert.equal(f.requests.length, 2, 'held Enter cannot restart the detail read');
    f.requests[1].resolve(ok('synthetic-tx-0')); await tick();
    assert.deepEqual(f.renders, ['synthetic-tx-0']);
    assert.equal(f.state._fuzzerDetailRecord.id, 'synthetic-tx-0');
    assert.equal(f.document.activeElement, f.shell);
  });
}

test('full dispatcher: Enter ignores no selection and a selected row absent from the current visible projection', async () => {
  const f = resultDetailFixture(2);
  assert.equal(f.key('Enter').defaultPrevented, false); assert.equal(f.requests.length, 0);
  f.key('ArrowDown'); f.requests[0].resolve(ok('synthetic-tx-0')); await tick();
  f.setVisible([1]);
  assert.equal(f.key('Enter').defaultPrevented, false); assert.equal(f.requests.length, 1);
  f.setVisible([]);
  assert.equal(f.key('Enter').defaultPrevented, false); assert.equal(f.requests.length, 1);
});
