// Synthetic DOM/action coverage. Native Enter/Space activation needs browser QA.
const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');

function fixture() {
  const document = { activeElement: null };
  const state = { activeSession: { id: 'session-a' }, sequenceDefinitions: [
    { id: 'a', name: 'Login', steps: [] }, { id: 'b', name: 'Follow-up', steps: [] },
  ], selectedSequenceId: 'a', editingSequence: { id: 'a', name: 'Login', steps: [] }, sequencePastRuns: [] };
  let rows = [];
  const node = () => ({ innerHTML: '', querySelectorAll: () => [], addEventListener() {}, classList: { toggle() {} } });
  const list = node();
  function control(id, action) {
    const c = { dataset: { [action === 'select' ? 'seqSelect' : 'seqDelete']: id },
      closest: selector => selector === '.seq-delete' ? (action === 'delete' ? c : null) : c,
      focus() { document.activeElement = c; } };
    return c;
  }
  Object.defineProperty(list, 'innerHTML', { get() { return this.markup; }, set(html) {
    if (list.contains(document.activeElement)) document.activeElement = null;
    this.markup = html;
    list.afterReplace?.();
    rows = state.sequenceDefinitions.map(def => ({ dataset: { seqId: def.id },
      select: control(def.id, 'select'), delete: control(def.id, 'delete'),
      addEventListener(type, fn) { this[type] = fn; } }));
  } });
  list.contains = c => rows.some(r => r.select === c || r.delete === c);
  list.querySelectorAll = selector => selector === '.history-row' ? rows : rows.map(r => selector === '.seq-select' ? r.select : r.delete);
  const nodes = new Map([['sequenceListBody', list]]);
  document.getElementById = id => nodes.get(id) || nodes.set(id, node()).get(id);
  let flush = async () => true; let saves = 0; let deletes = 0; let errors = 0;
  const c = loadFunctions(['sequenceExtractionGuidance', 'renderSequencePanel', 'renderSequenceList', 'sequenceDisplayName', 'sequenceNameInputValue', 'syncSequenceRunButton', 'selectSequence', 'bumpSequenceDraftVersion'], {
    document, state, escapeHtml: value => String(value).replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;'),
    formatTimestamp: String, normalizeSequenceRunResult: () => null, jsonArray: v => Array.isArray(v) ? v : [],
    flushSequenceDraft: () => { saves++; return flush(); }, syncSequenceStepFromDom() {},
    onClickWithProgress: (btn, fn) => { btn.click = fn; }, deleteSequence: async () => { deletes++; },
    handleSequenceActionError: () => { errors++; },
  });
  c.renderSequencePanel();
  return { c, state, document, list, rows: () => rows, setFlush: fn => { flush = fn; }, counts: () => ({ saves, deletes, errors }) };
}
const settle = () => new Promise(resolve => setImmediate(resolve));

test('names are native named buttons with selected state, and Delete has context', () => {
  const f = fixture();
  assert.match(f.list.innerHTML, /type="button" class="seq-select" data-seq-select="a" aria-pressed="true">Login<\/button>/);
  assert.match(f.list.innerHTML, /data-seq-select="b" aria-pressed="false">Follow-up<\/button>/);
  assert.match(f.list.innerHTML, /aria-label="Delete sequence Follow-up"/);
  f.state.sequenceDefinitions[1].name = '<a "name">'; f.c.renderSequencePanel();
  assert.match(f.list.innerHTML, /aria-label="Delete sequence &lt;a &quot;name&quot;>"/);
});

test('native button activation bubbles once through the row and retains focused identity', async () => {
  const f = fixture(); const row = f.rows()[1]; row.select.focus();
  assert.equal(row.select.click, undefined); // No second listener doubling the row's activation.
  row.click({ target: row.select }); await settle();
  assert.equal(f.counts().saves, 1); assert.equal(f.state.selectedSequenceId, 'b');
  assert.equal(f.document.activeElement, f.rows()[1].select);
  assert.notEqual(f.document.activeElement, row.select);
});

test('row pointer activation selects; Delete bubbling does not select', async () => {
  const f = fixture(); const row = f.rows()[1];
  row.click({ target: { closest: () => null } }); await settle();
  assert.equal(f.state.selectedSequenceId, 'b');
  const first = f.rows()[0]; first.click({ target: first.delete }); await first.delete.click();
  assert.deepEqual(f.counts(), { saves: 1, deletes: 1, errors: 0 });
  assert.equal(f.state.selectedSequenceId, 'b');
});

for (const newer of ['outside', 'another-list-control']) test(`pending save does not steal newer ${newer} focus`, async () => {
  const f = fixture(); let finish; f.setFlush(() => new Promise(resolve => { finish = resolve; }));
  f.rows()[1].select.focus(); const pending = f.c.selectSequence('b');
  const outside = {}; if (newer === 'outside') f.document.activeElement = outside; else f.rows()[0].delete.focus();
  finish(true); await pending;
  assert.equal(f.document.activeElement, newer === 'outside' ? outside : f.rows()[0].delete);
});

test('session boundary does not restore old list focus even with reused sequence IDs', () => {
  const f = fixture(); f.rows()[0].select.focus(); f.state.activeSession.id = 'session-b'; f.c.renderSequencePanel();
  assert.equal(f.document.activeElement, null);
});

for (const outcome of ['false', 'reject']) test(`failed draft flush (${outcome}) preserves draft, selection, and focused live button`, async () => {
  const f = fixture(); const draft = f.state.editingSequence; draft.steps = [{ request_text: 'invalid unsaved draft' }];
  f.state.sequenceDirty = true; const button = f.rows()[1].select; button.focus();
  f.setFlush(async () => { if (outcome === 'reject') throw new Error('Save failed'); return false; });
  f.rows()[1].click({ target: button }); await settle();
  assert.equal(f.state.editingSequence, draft); assert.equal(f.state.selectedSequenceId, 'a');
  assert.equal(f.state.sequenceDirty, true); assert.equal(f.document.activeElement, button);
  assert.equal(f.counts().errors, outcome === 'reject' ? 1 : 0);
});

test('latest selection wins if asynchronous flushes finish out of order', async () => {
  const f = fixture(); f.state.sequenceDefinitions.push({ id: 'c', name: 'Third', steps: [] }); f.c.renderSequencePanel();
  const finish = []; f.setFlush(() => new Promise(resolve => finish.push(resolve)));
  const first = f.c.selectSequence('b'); const last = f.c.selectSequence('c');
  finish[1](true); await last; finish[0](true); await first;
  assert.equal(f.state.selectedSequenceId, 'c');
});

test('selecting current sequence syncs draft without rendering or saving', async () => {
  const f = fixture(); const button = f.rows()[0].select; button.focus(); await f.c.selectSequence('a');
  assert.equal(f.counts().saves, 0); assert.equal(f.document.activeElement, button);
});


test('focus moved by replacement callback is not overwritten', () => {
  const f = fixture(); f.rows()[1].select.focus(); const newer = {};
  f.list.afterReplace = () => { f.document.activeElement = newer; };
  f.c.renderSequencePanel(); assert.equal(f.document.activeElement, newer);
});

test('reselecting the active sequence cancels an earlier pending navigation', async () => {
  const f = fixture(); let finish;
  f.state.sequenceDirty = true;
  const draft = f.state.editingSequence;
  f.setFlush(() => new Promise(resolve => { finish = resolve; }));
  const earlier = f.c.selectSequence('b');
  f.rows()[0].select.focus(); await f.c.selectSequence('a');
  finish(true); await earlier;
  assert.equal(f.state.selectedSequenceId, 'a');
  assert.equal(f.state.editingSequence, draft);
  assert.equal(f.document.activeElement, f.rows()[0].select);
  assert.equal(f.counts().saves, 1);
});

test('compact list prioritizes full names while retaining Steps and accessible Actions header', () => {
  const fs = require('node:fs'); const path = require('node:path');
  const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
  const list = html.match(/<section class="panel-card sequence-list-card">([^]*?)<\/section>/)[1];
  assert.match(list, /<th>Steps<\/th>/);
  assert.match(list, /<th><span class="sequence-actions-heading">Actions<\/span><\/th>/);
  assert.match(css, /\.sequence-list-card \.mini-table td:nth-child\(2\) \{\s*width: 48px;\s*padding-inline: 6px;\s*text-align: center;/);
  assert.match(css, /\.sequence-list-card \.mini-table td:nth-child\(3\) \{\s*width: 32px;\s*padding-inline: 4px;\s*text-align: center;/);
  const name = css.match(/\.sequence-list-card \.seq-select \{([^]*?)\}/)[1];
  assert.match(name, /overflow-wrap: anywhere/); assert.doesNotMatch(name, /ellipsis|nowrap|overflow: hidden/);
  assert.match(css, /\.sequence-list-card \.sequence-actions-heading \{[^]*?clip: rect\(0, 0, 0, 0\);/);
  assert.match(css, /\.sequence-list-card \.seq-delete:focus-visible \{\s*outline: 2px solid var\(--point\);\s*outline-offset: 1px;/);
  const f = fixture(); f.state.sequenceDefinitions[0].steps = Array.from({ length: 123 }, () => ({}));
  f.c.renderSequencePanel(); assert.match(f.list.innerHTML, /<td>123<\/td>/);
});
