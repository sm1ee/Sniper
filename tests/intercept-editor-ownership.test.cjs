// Production intercept rendering and shipped CM history, with an in-memory view.
// No browser, proxy, or target traffic is started.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { editorFixture, source, CM } = require('./replay-editor-fixture.cjs');

function fixture(mode) {
  const f = editorFixture(), { state, context, els } = f;
  const element = () => ({ value: '', innerHTML: '', textContent: '', querySelectorAll: () => [], classList: { toggle() {} } });
  for (const name of ['interceptTableBody', 'responseInterceptTableBody', 'interceptDetailPath', 'interceptDetailTitle',
    'interceptMeta', 'forwardInterceptButton', 'dropInterceptButton', 'forwardResponseInterceptButton',
    'dropResponseInterceptButton', 'interceptRequestCM', 'interceptResponseCM', 'interceptSearchInput']) els[name] = element();
  els.interceptSearchMeta = null;
  Object.assign(context, { escapeHtml: String, formatTimestamp: String });
  for (const name of ['renderIntercepts', 'renderResponseIntercepts', 'getVisibleRequestInterceptSummaries',
    'selectInterceptQueueItem', 'updateInterceptQueueSelectionStatus', 'scrollSelectedInterceptRowIntoView',
    'getVisibleResponseInterceptSummaries', 'reconcileRequestInterceptSelection', 'reconcileResponseInterceptSelection',
    'setInterceptPaneContent', 'buildEditableRawResponse', 'updateInterceptSearch', 'activeInterceptCMKey']) {
    vm.runInContext(source(name), context);
  }
  const record = id => ({ id, scheme: 'https', peer_addr: '127.0.0.1:1', host: 'example.com', method: 'GET',
    path: `/${id}`, status: 200, started_at: '2026-01-01',
    request: { scheme: 'https', host: 'example.com', port: 443, method: 'GET', path: `/${id}`, headers: [], body: '', body_encoding: 'utf8' },
    response: { status: 200, headers: [], body: id, body_encoding: 'utf8' } });
  f.a = record('a'); f.b = record('b');
  state.interceptQueueTab = mode; state.intercepts = [f.a, f.b]; state.responseIntercepts = [f.a, f.b];
  const prefix = mode === 'request' ? 'selectedIntercept' : 'selectedResponseIntercept';
  const seed = mode === 'request' ? 'interceptEditorSeedId' : 'responseInterceptEditorSeedId';
  f.render = mode === 'request' ? context.renderIntercepts : context.renderResponseIntercepts;
  f.cv = () => context.getCMView(mode === 'request' ? 'interceptReq' : 'interceptRes');
  f.select = record => {
    state[prefix + 'Id'] = record.id; state[prefix + 'Record'] = null; state[seed] = null; f.render();
    state[prefix + 'Record'] = record; f.render();
  };
  f.reseed = () => { state[seed] = null; f.render(); };
  f.edit = text => f.cv().view.dispatch({ changes: { from: f.cv().view.state.doc.length, insert: text }, userEvent: 'input.type' });
  f.undo = () => CM.undo(f.cv().view); f.redo = () => CM.redo(f.cv().view);
  f.select(f.a);
  return f;
}

for (const mode of ['request', 'response']) {
  for (const identical of [false, true]) test(`${mode}: selecting ${identical ? 'identical' : 'different'} held message retires Undo`, () => {
    const f = fixture(mode); f.edit('old draft'); const old = f.cv();
    if (identical) {
      assert.equal(f.undo(), true); // Same displayed text, but old Redo still exists.
      f.b.request = f.a.request; f.b.response = f.a.response;
    }
    f.select(f.b); const baseline = f.cv().getContent();
    assert.notEqual(f.cv(), old); assert.equal(old.view.destroyed, true);
    assert.equal(f.undo(), false); assert.equal(f.redo(), false); assert.equal(f.cv().getContent(), baseline);
    f.edit('new draft'); assert.equal(f.undo(), true); assert.equal(f.cv().getContent(), baseline);
  });
  for (const boundary of ['session', 'workspace', 'A-B-A']) test(`${mode}: ${boundary} retires identical held-record history`, () => {
    const f = fixture(mode); f.edit('old draft'); const old = f.cv();
    if (boundary === 'session') f.state.activeSession = { id: 'session-b' };
    if (boundary === 'workspace') f.context.workspaceStateGeneration++;
    if (boundary === 'A-B-A') {
      f.state.activeSession = { id: 'session-b' }; f.context.workspaceStateGeneration++; f.reseed();
      f.state.activeSession = { id: 'session-a' }; f.context.workspaceStateGeneration++;
    }
    f.reseed(); const baseline = f.cv().getContent();
    assert.notEqual(f.cv(), old); assert.equal(old.view.destroyed, true);
    assert.equal(f.undo(), false); assert.equal(f.redo(), false); assert.equal(f.cv().getContent(), baseline);
  });
  test(`${mode}: same held record polling and search preserve local Undo and focus`, () => {
    const f = fixture(mode), baseline = f.cv().getContent(), cv = f.cv();
    f.edit('local draft'); const edited = cv.getContent(); cv.view.focus();
    f.els.interceptSearchMeta = { innerHTML: '' }; f.els.interceptSearchInput.value = 'draft';
    f.render(); f.context.updateInterceptSearch(); f.render();
    assert.equal(f.cv(), cv); assert.equal(cv.getContent(), edited); assert.equal(cv.view.hasFocus, true);
    assert.equal(f.undo(), true); assert.equal(cv.getContent(), baseline);
    assert.equal(f.redo(), true); assert.equal(cv.getContent(), edited);
  });
}
