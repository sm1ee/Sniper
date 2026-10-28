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
  let selected = initial, modal = null;
  shell.setAttribute = () => {};
  shell.addEventListener = (type, callback) => listeners[type] = callback;
  const c = loadFunctions(['tableArrowStep', 'isEditableTarget'], {
    HTMLElement, getActiveModalAction: () => modal,
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
  return { shell, selections, node: tag => new HTMLElement(tag), get selected() { return selected; },
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
for (const key of ['Home', 'End', 'Enter', 'Escape', 'ArrowLeft', 'ArrowRight']) test(`${key} remains outside Fuzzer row navigation`, () => {
  const f = fixture(), e = f.key(key);
  assert.equal(e.preventCalls, 0); assert.deepEqual(f.selections, []);
});
