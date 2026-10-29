// Actual Fuzzer detail handlers and shipped editor state with in-memory views.
// No app bootstrap, browser/native layout, proxy, or target traffic is used.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { editorFixture, source } = require('./replay-editor-fixture.cjs');
const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
const labels = { Req: 'Fuzzer result request', Res: 'Fuzzer result response' };
function element(id) {
  const tag = html.match(new RegExp(`<[^>]+\\bid="${id}"[^>]*>`))?.[0];
  assert.ok(tag, `Missing ${id}`);
  return { getAttribute: name => tag.match(new RegExp(`\\b${name}="([^"]*)"`))?.[1] ?? null };
}
function setup() {
  const f = editorFixture(), pending = [];
  const MemoryView = f.context.CM.EditorView;
  f.context.CM.EditorView = class extends MemoryView {
    constructor(options) {
      super(options);
      const attributes = new Map();
      this.contentDOM = { setAttribute: (name, value) => attributes.set(name, String(value)),
        getAttribute: name => attributes.get(name) ?? null };
    }
  };
  for (const side of ['Req', 'Res']) f.els[`fuzzerDetail${side}CM`] = element(`fuzzerDetail${side}CM`);
  f.els.fuzzerDetailPanel = { classList: { remove() {} } };
  f.els.fuzzerDetailResponseMeta = { textContent: '' };
  Object.assign(f.state, { fuzzerAttackRecordId: 'synthetic-run', _selectedFuzzerResultKey: 'tx:synthetic' });
  Object.assign(f.context, {
    _fuzzerDetailGeneration: 0, _fuzzerDetailViewModes: { request: 'raw', response: 'raw' },
    syncFuzzerDetailTabs() {}, syncFuzzerResponsePreview() {}, renderFuzzerResultsWorkflow() {},
    buildRawRequest: record => record.request.text, buildRawResponse: record => record.response.text,
    prettyFormat: text => text, buildMessageHexPresentation: (_side, _record, text) => `hex:${text}`,
    transactionPath: id => `/synthetic/${id}`,
    fetch: url => new Promise((resolve, reject) => pending.push({ url, resolve, reject })),
  });
  for (const name of ['renderFuzzerDetailPanes', 'clearFuzzerResponsePane', 'showFuzzerResultDetail'])
    vm.runInContext(source(name), f.context);
  f.detailView = side => f.context.getCMView(`fuzzerDetail${side}`);
  f.assertNames = () => {
    for (const [side, label] of Object.entries(labels)) {
      assert.equal(f.detailView(side).view.contentDOM.getAttribute('aria-label'), label);
      assert.equal(f.detailView(side).view.state.readOnly, true);
      assert.equal(f.detailView(side)._options.readOnly, true);
    }
  };
  f.pending = pending;
  return f;
}
const record = id => ({ id, request: { text: `request-${id}` }, response: { text: `response-${id}` }, status: 200 });
for (const [side, label] of Object.entries(labels)) test(`Fuzzer ${side} container supplies distinct accessible name`, () => {
  assert.equal(element(`fuzzerDetail${side}CM`).getAttribute('data-editor-label'), label);
});
test('Fuzzer names and readonly selection survive redraw and modes recreate correctly', () => {
  const f = setup(); f.context.renderFuzzerDetailPanes(record('a')); f.assertNames();
  const first = f.detailView('Req');
  first.view.dispatch({ selection: { anchor: 1, head: 4 } });
  f.context.renderFuzzerDetailPanes(record('a')); f.assertNames();
  assert.equal(f.detailView('Req'), first);
  assert.equal(first.view.state.selection.main.anchor, 1);
  assert.equal(first.view.state.selection.main.head, 4);
  let previous = first;
  for (const mode of ['pretty', 'hex', 'raw']) {
    f.context._fuzzerDetailViewModes = { request: mode, response: mode };
    f.context.renderFuzzerDetailPanes(record('b')); f.assertNames();
    if (mode === 'pretty') assert.equal(f.detailView('Req'), previous);
    else { assert.notEqual(f.detailView('Req'), previous); assert.equal(previous.view.destroyed, true); }
    assert.equal(f.detailView('Req').getContent(), `${mode === 'hex' ? 'hex:' : ''}request-b`);
    previous = f.detailView('Req');
  }
  assert.equal(f.pending.length, 0);
});
test('Fuzzer missing response and explicitly cleared response retain names without stale content', () => {
  const f = setup(); f.context.renderFuzzerDetailPanes(record('a'));
  f.context.renderFuzzerDetailPanes({ id: 'b', request: { text: 'request-b' } }); f.assertNames();
  assert.equal(f.detailView('Res').getContent(), 'No response captured.');
  assert.equal(f.els.fuzzerDetailResponseMeta.textContent, '');
  f.context.clearFuzzerResponsePane(); f.assertNames();
  assert.equal(f.detailView('Res').getContent(), '');
  assert.equal(f.pending.length, 0);
});
for (const outcome of ['success', 'http-error', 'network-error']) test(`Fuzzer loading and ${outcome} maintain distinct names`, async () => {
  const f = setup();
  const job = f.context.showFuzzerResultDetail('synthetic');
  const loadingNames = ['Req', 'Res'].map(side => f.detailView(side).view.contentDOM.getAttribute('aria-label'));
  assert.equal(f.detailView('Req').getContent(), 'Loading transaction...');
  assert.equal(f.detailView('Res').getContent(), '');
  assert.equal(f.pending.length, 1);
  if (outcome === 'success') f.pending[0].resolve({ ok: true, json: async () => record('synthetic') });
  else if (outcome === 'http-error') f.pending[0].resolve({ ok: false, status: 503 });
  else f.pending[0].reject(new Error('synthetic offline'));
  await job; f.assertNames();
  assert.deepEqual(loadingNames, Object.values(labels));
  assert.equal(f.detailView('Req').getContent(), outcome === 'success' ? 'request-synthetic'
    : outcome === 'http-error' ? 'Failed to load transaction: 503' : 'Error: synthetic offline');
  assert.equal(f.detailView('Res').getContent(), outcome === 'success' ? 'response-synthetic' : '');
});
