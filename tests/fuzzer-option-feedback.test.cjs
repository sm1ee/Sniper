// Actual option listeners, setup renderer and Results renderer, with synthetic
// state/presentation. No Start/run handler, transport, native app or browser.
const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
const workflow = require('../web/fuzzer-workflow.js');
const choices = [
  ['fuzzerAttackType', 'battering_ram', 'sniper'],
  ['fuzzerUrlEncode', false, true],
  ['fuzzerConcurrency', '1', 4],
];
function fixture(extra = {}) {
  const nodes = {};
  for (const id of ['fuzzerPreflightSummary', 'fuzzerPreflightNotice', 'fuzzerAttackType', 'fuzzerConcurrency', 'fuzzerUrlEncode', 'startFuzzerButton']) {
    const classes = new Set();
    nodes[id] = { value: '', checked: false, textContent: '', handlers: {}, classes,
      addEventListener(type, callback) { this.handlers[type] = callback; },
      classList: { toggle(name, active) { if (active) classes.add(name); else classes.delete(name); } },
    };
  }
  const state = { activeSession: { id: 'synthetic' }, fuzzerRequestText: 'GET /?q=§demo§ HTTP/1.1\nHost: example.com\n\n',
    fuzzerPayloadsText: 'one', fuzzerAttackType: 'sniper', fuzzerUrlEncode: true, fuzzerConcurrency: 4,
    fuzzerDraftVersion: 3, fuzzerRunToken: 5, fuzzerNoticeError: true, fuzzerNotice: 'Previous Start failed.', ...extra };
  const els = { fuzzerMeta: { textContent: '' }, fuzzerPayloadsEditor: { value: state.fuzzerPayloadsText }, startFuzzerButton: nodes.startFuzzerButton };
  let emptyText = '', wholeRenders = 0, listRenders = 0;
  const request = { method: 'GET', scheme: 'https', host: 'example.com', port: 443, path: '/?q=§demo§', headers: [], body: '' };
  const c = loadFunctions(['initFuzzerSetupControls', 'finishFuzzerOptionChange', 'renderFuzzerSetup', 'renderFuzzer', 'fuzzerPayloadCount'], {
    workspaceLoaded: true, state, els, TextEncoder, SniperFuzzerWorkflow: workflow,
    fuzzerSetupNode: id => nodes[id] || null, currentSessionId: () => 'synthetic',
    fuzzerRequestTextForAction: () => state.fuzzerRequestText, parseFuzzerRequestTemplate: () => request,
    fuzzerSetupPreflight: () => workflow.preflight(request, state.fuzzerPayloadsText ? [state.fuzzerPayloadsText] : [], { attackType: state.fuzzerAttackType }),
    renderFuzzerPayloadImportStatus() {}, renderFuzzerRemoveMarkerControl() {}, escapeHtml: text => text,
    markFuzzerEditorSelection() {}, removeFuzzerEditorPosition() {}, undoFuzzerMarker() {}, clearFuzzerMarkers() {},
    renderFuzzerResultsWorkflow() { wholeRenders++; }, renderFuzzerPayloadsEditor() {},
    normalizeFuzzerAttackRecord: record => record || null,
    renderEmptyFuzzerResults(text) { emptyText = text; }, renderFuzzerResultsVirtual() { listRenders++; },
    fetch() { assert.fail('Option feedback must not issue requests'); },
  });
  c.initFuzzerSetupControls(); c.renderFuzzer();
  return { c, state, els, nodes, get emptyText() { return emptyText; }, get wholeRenders() { return wholeRenders; }, get listRenders() { return listRenders; },
    change(id, value) { nodes[id].value = String(value); nodes[id].checked = value; nodes[id].handlers.change({ target: nodes[id] }); },
  };
}
for (const [id, changed, same] of choices) {
  test(`${id} semantic change retires settled Start error from setup, metadata and empty results`, () => {
    const f = fixture(), renders = f.wholeRenders;
    assert.equal(f.emptyText, 'Previous Start failed.'); f.change(id, changed);
    assert.equal(f.state.fuzzerDraftVersion, 4); assert.equal(f.state.fuzzerNoticeError, false); assert.equal(f.state.fuzzerNotice, '');
    assert.equal(f.nodes.fuzzerPreflightNotice.textContent, ''); assert.equal(f.els.fuzzerMeta.textContent, '');
    assert.equal(f.emptyText, 'Results appear here after running.'); assert.equal(f.wholeRenders, renders + 1);
    assert.equal(f.state.fuzzerRunToken, 5); assert.equal(f.nodes.startFuzzerButton.disabled, false);
  });
  test(`${id} same normalized value keeps failure feedback and avoids whole Results redraw`, () => {
    const f = fixture(), renders = f.wholeRenders; f.change(id, same);
    assert.equal(f.state.fuzzerDraftVersion, 3); assert.equal(f.state.fuzzerNoticeError, true);
    assert.equal(f.nodes.fuzzerPreflightNotice.textContent, 'Previous Start failed.'); assert.equal(f.emptyText, 'Previous Start failed.');
    assert.equal(f.wholeRenders, renders);
  });
  for (const guard of ['fuzzerRunning', 'fuzzerRunningAttackId', 'fuzzerAttackRecord', 'fuzzerAttackRecordId']) test(`${id} preserves ${guard} warning and historical state`, () => {
    const record = { id: 'saved', status: 'unavailable', running: false, results: [{ note: 'retained' }] };
    const extra = { [guard]: guard === 'fuzzerRunning' ? true : guard === 'fuzzerAttackRecord' ? record : 'saved',
      fuzzerNotice: 'Attack is no longer available. Last received results are shown.',
      _selectedFuzzerResultKey: 'row:0', _fuzzerDetailRecord: { id: 'detail' } };
    const f = fixture(extra), renders = f.wholeRenders, detail = f.state._fuzzerDetailRecord, shown = f.state.fuzzerAttackRecord;
    // Initial rendering normally fills the ID from a record; isolate this guard.
    if (guard === 'fuzzerAttackRecord') f.state.fuzzerAttackRecordId = null;
    f.change(id, changed);
    assert.equal(f.state.fuzzerDraftVersion, 4); assert.equal(f.state.fuzzerNoticeError, true);
    assert.equal(f.state.fuzzerNotice, extra.fuzzerNotice); assert.equal(f.nodes.fuzzerPreflightNotice.textContent, extra.fuzzerNotice);
    assert.equal(f.state.fuzzerAttackRecord, shown); assert.equal(f.state._fuzzerDetailRecord, detail);
    assert.equal(f.state._selectedFuzzerResultKey, 'row:0'); assert.equal(f.wholeRenders, renders);
  });
  test(`${id} cleared old failure does not hide a fresh current preflight error`, () => {
    const f = fixture({ fuzzerPayloadsText: 'x'.repeat(65537) }); f.change(id, changed);
    assert.equal(f.state.fuzzerNoticeError, false);
    assert.match(f.nodes.fuzzerPreflightNotice.textContent, /Payloads line 1 exceeds/);
    assert.equal(f.nodes.fuzzerPreflightNotice.classes.has('fuzzer-notice-error'), true);
    assert.equal(f.nodes.startFuzzerButton.disabled, true);
  });
  test(`${id} non-error notice and retained results are never retired`, () => {
    const record = { id: 'saved', status: 'completed', results: [] };
    const f = fixture({ fuzzerNoticeError: false, fuzzerNotice: 'Informational notice', fuzzerAttackRecord: record, fuzzerAttackRecordId: 'saved' });
    const renders = f.wholeRenders; f.change(id, changed);
    assert.equal(f.state.fuzzerNotice, 'Informational notice'); assert.equal(f.state.fuzzerAttackRecord, record);
    assert.equal(f.wholeRenders, renders);
  });
}
for (const value of ['4.4', 'NaN']) test(`concurrency normalized ${value}→4 remains same-value`, () => {
  const f = fixture(), renders = f.wholeRenders; f.change('fuzzerConcurrency', value);
  assert.equal(f.state.fuzzerConcurrency, 4); assert.equal(f.state.fuzzerDraftVersion, 3);
  assert.equal(f.state.fuzzerNoticeError, true); assert.equal(f.wholeRenders, renders);
});
