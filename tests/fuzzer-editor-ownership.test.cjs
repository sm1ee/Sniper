// Production Fuzzer rendering and shipped CodeMirror history; synthetic view only.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { editorFixture, source, CM } = require('./replay-editor-fixture.cjs');

function fixture() {
  const f = editorFixture();
  const OriginalView = f.context.CM.EditorView;
  class View extends OriginalView {
    constructor(options) { super(options); this.contentDOM.setAttribute = () => {}; }
  }
  f.context.CM.EditorView = View;
  Object.assign(f.els, { fuzzerRequestCM: {}, fuzzerPayloadsEditor: { value: '' }, fuzzerMeta: {} });
  f.saves = 0;
  Object.assign(f.context, {
    renderFuzzerResultsWorkflow() {}, renderFuzzerSetup() {}, renderEmptyFuzzerResults() {},
    wireFuzzerMarkerSelection() {}, scheduleFuzzerSetupRender() {},
    scheduleWorkspaceStateSave() { f.saves++; },
  });
  for (const name of ['renderFuzzer', 'updateFuzzerRequestText', 'markFuzzerDraftChanged']) {
    vm.runInContext(source(name), f.context);
  }
  f.cv = () => f.context.getCMView('fuzzerReq');
  f.render = () => f.context.renderFuzzer();
  f.undo = () => CM.undo(f.cv().view);
  f.redo = () => CM.redo(f.cv().view);
  f.state.fuzzerRequestText = 'GET /a HTTP/1.1\nHost: example.com\n\n';
  f.state.fuzzerPayloadsText = '';
  f.render();
  return f;
}

for (const boundary of ['session', 'workspace', 'session-clear', 'A-B-A']) {
  for (const sameText of [false, true]) {
    test(`${boundary} retires history even with ${sameText ? 'identical' : 'different'} text`, () => {
      const f = fixture(); f.edit(5, 6, 'edited');
      const old = f.cv();
      if (boundary === 'session') f.state.activeSession = { id: 'session-b' };
      if (boundary === 'workspace') f.context.workspaceStateGeneration++;
      if (boundary === 'session-clear') {
        f.context.workspaceStateGeneration++;
        f.state.fuzzerRequestText = ''; f.render();
        // applyWorkspaceState advances the generation again when B loads.
        f.context.workspaceStateGeneration++;
      }
      if (boundary === 'A-B-A') {
        f.state.activeSession = { id: 'session-b' }; f.context.workspaceStateGeneration++; f.render();
        f.state.activeSession = { id: 'session-a' }; f.context.workspaceStateGeneration++;
      }
      f.state.fuzzerRequestText = sameText ? 'GET /edited HTTP/1.1\nHost: example.com\n\n' : 'GET /b HTTP/1.1\nHost: example.com\n\n';
      f.render();
      const expected = f.state.fuzzerRequestText, saves = f.saves;
      assert.notEqual(f.cv(), old); assert.equal(old.view.destroyed, true);
      assert.equal(f.undo(), false); assert.equal(f.redo(), false);
      assert.equal(f.state.fuzzerRequestText, expected); assert.equal(f.saves, saves);
      f.edit(5, 6, 'new'); assert.equal(f.saves, saves + 1);
      assert.equal(f.undo(), true); assert.equal(f.state.fuzzerRequestText, expected);
    });
  }
}

test('same-session redraw preserves native Undo/Redo, selection and focus', () => {
  const f = fixture(), original = f.state.fuzzerRequestText, cv = f.cv();
  f.edit(5, 6, 'edited'); const edited = f.state.fuzzerRequestText;
  cv.view.dispatch({ selection: { anchor: 3, head: 8 } }); cv.view.focus();
  const selection = f.selection();
  f.render(); f.render();
  assert.equal(f.cv(), cv); assert.deepEqual(f.selection(), selection);
  assert.equal(f.document.activeElement, cv.view.contentDOM);
  assert.equal(f.undo(), true); assert.equal(f.state.fuzzerRequestText, original);
  assert.equal(f.redo(), true); assert.equal(f.state.fuzzerRequestText, edited);
});

for (const replacement of ['marker', 'reset', 'reuse']) test(`same-session ${replacement} text replacement retains existing Undo semantics`, () => {
  const f = fixture(), cv = f.cv(), original = f.state.fuzzerRequestText;
  f.state.fuzzerRequestText = replacement === 'marker' ? original.replace('/a', '/§a§')
    : replacement === 'reset' ? '' : original.replace('/a', '/reused');
  f.render(); const replaced = f.state.fuzzerRequestText;
  assert.equal(f.cv(), cv);
  assert.equal(f.undo(), true); assert.equal(f.state.fuzzerRequestText, original);
  assert.equal(f.redo(), true); assert.equal(f.state.fuzzerRequestText, replaced);
});

for (const phase of ['before redraw', 'after redraw']) test(`retired session callbacks cannot mutate the draft ${phase}`, () => {
  const f = fixture(), old = f.cv();
  const listeners = old.view.state.facet(CM.EditorView.updateListener);
  f.state.activeSession = { id: 'session-b' }; f.context.workspaceStateGeneration++;
  f.state.fuzzerRequestText = 'GET /b HTTP/1.1\nHost: example.com\n\n';
  if (phase === 'after redraw') f.render();
  const expected = f.state.fuzzerRequestText, saves = f.saves;
  for (const listener of listeners) listener({ view: old.view, state: old.view.state, docChanged: true });
  assert.equal(f.state.fuzzerRequestText, expected); assert.equal(f.saves, saves);
});
