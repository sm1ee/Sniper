// Lifecycle contracts only: fake controls cannot prove native browser Undo.
// Browser acceptance must type/delete in A, open empty B, and press Undo/Redo.
const assert = require('node:assert/strict');
const test = require('node:test');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');

function fixture() {
  const document = { activeElement: null };
  const state = { activeSession: { id: 'a' }, fuzzerPayloadsText: '' };
  let saves = 0, edits = 0, replacements = 0;
  function control(attributes = { id: 'fuzzerPayloadsEditor', 'aria-describedby': 'fuzzerPayloadHelp', class: 'request-editor', spellcheck: 'false' }) {
    const listeners = [];
    return { attributes: { ...attributes }, value: '', selectionStart: 0, selectionEnd: 0, scrollTop: 0,
      addEventListener(type, handler) { assert.equal(type, 'input'); listeners.push(handler); },
      input(value) { this.value = value; listeners.forEach(handler => handler()); },
      cloneNode(deep) { assert.equal(deep, false); return control(this.attributes); },
      replaceWith(next) { this.replacedBy = next; replacements++; if (document.activeElement === this) document.activeElement = null; },
      focus(options) { assert.deepEqual({ ...options }, { preventScroll: true }); document.activeElement = this; },
      get listenerCount() { return listeners.length; },
    };
  }
  const els = { fuzzerPayloadsEditor: control() };
  const c = loadFunctions(['renderFuzzerPayloadsEditor'], {
    state, els, document, workspaceStateGeneration: 0, currentSessionId: () => state.activeSession?.id || null,
    updateFuzzerPayloadsText(value, options) { assert.equal(options.userEdit, true); edits++; state.fuzzerPayloadsText = value; },
    scheduleWorkspaceStateSave() { saves++; },
  });
  const render = () => c.renderFuzzerPayloadsEditor(); render();
  return { c, state, els, document, render, get saves() { return saves; }, get edits() { return edits; }, get replacements() { return replacements; } };
}

for (const boundary of ['session', 'workspace', 'clear-load', 'A-B-A']) {
  for (const value of ['', 'identical payload']) test(`${boundary} gives ${value ? 'identical' : 'empty'} payload a fresh control`, () => {
    const f = fixture(), old = f.els.fuzzerPayloadsEditor;
    old.input('session-a-private'); old.input(value);
    if (boundary === 'session') f.state.activeSession.id = 'b';
    if (boundary === 'workspace') f.c.workspaceStateGeneration++;
    if (boundary === 'clear-load') {
      f.c.workspaceStateGeneration++; f.state.fuzzerPayloadsText = ''; f.render();
      f.c.workspaceStateGeneration++; f.state.fuzzerPayloadsText = value;
    }
    if (boundary === 'A-B-A') {
      f.state.activeSession.id = 'b'; f.render(); f.state.activeSession.id = 'a';
    }
    f.render(); const fresh = f.els.fuzzerPayloadsEditor;
    assert.notEqual(fresh, old); assert.equal(fresh.value, value);
    assert.deepEqual(fresh.attributes, old.attributes);
    assert.equal(fresh.listenerCount, 1); assert.equal(f.saves, 2);
    old.input('stale callback'); assert.equal(f.state.fuzzerPayloadsText, value); assert.equal(f.saves, 2);
    fresh.input('current payload'); assert.equal(f.state.fuzzerPayloadsText, 'current payload'); assert.equal(f.saves, 3);
  });
}

test('same-owner redraw preserves node, selection, focus, scroll and one input binding', () => {
  const f = fixture(), editor = f.els.fuzzerPayloadsEditor;
  editor.input('payload'); editor.selectionStart = 2; editor.selectionEnd = 4; editor.scrollTop = 30;
  f.document.activeElement = editor; f.render(); f.render();
  assert.equal(f.els.fuzzerPayloadsEditor, editor); assert.equal(f.replacements, 0);
  assert.equal(editor.listenerCount, 1); assert.equal(editor.selectionStart, 2); assert.equal(editor.selectionEnd, 4);
  assert.equal(editor.scrollTop, 30); assert.equal(f.document.activeElement, editor);
  editor.input('later'); assert.equal(f.saves, 2);
});

for (const focused of [false, true]) test(`ownership replacement ${focused ? 'restores payload' : 'does not steal other'} focus`, () => {
  const f = fixture(), old = f.els.fuzzerPayloadsEditor, other = {};
  f.document.activeElement = focused ? old : other;
  f.c.workspaceStateGeneration++; f.render();
  assert.equal(f.document.activeElement, focused ? f.els.fuzzerPayloadsEditor : other);
});

test('old input is ignored between ownership change and redraw', () => {
  const f = fixture(), old = f.els.fuzzerPayloadsEditor;
  f.c.workspaceStateGeneration++; old.input('retired');
  assert.equal(f.state.fuzzerPayloadsText, ''); assert.equal(f.edits, 0); assert.equal(f.saves, 0);
});

test('production render owns initial binding, without an additional setup listener', () => {
  assert.match(appSource, /function renderFuzzer\(\) \{[^]*?renderFuzzerPayloadsEditor\(\);/);
  assert.doesNotMatch(appSource, /els\.fuzzerPayloadsEditor\.addEventListener/);
});
