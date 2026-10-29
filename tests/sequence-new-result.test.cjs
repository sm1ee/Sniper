// Actual New/row bindings and render logic with deferred in-memory API replies.
// No app bootstrap, real create/save/run requests, or sequence step execution.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));

function fixture({ name = 'New sequence', flush = 'success', delayLoad = false } = {}) {
  const old = { id: 'a', name, steps: [{ id: 'a-step', label: 'Old step', request: {},
    request_text: 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n', extractions: [] }] };
  const other = { id: 'other', name: 'Other sequence', steps: [] };
  const result = { id: 'run-a', sequence_id: 'a', sequence_name: name, status: 'completed',
    step_results: [{ label: 'Old step', status: 200, extracted: { token: 'synthetic-old-value' } }] };
  const history = [{ id: 'run-a', sequence_id: 'a', sequence_name: name, status: 'completed',
    step_count: 1, started_at: '2026-10-29T00:00:00Z' }];
  const state = { activeSession: { id: 'session-a' }, sequenceDefinitions: [old, other],
    selectedSequenceId: 'a', editingSequence: structuredClone(old), sequenceDirty: false,
    sequenceDraftVersion: 0, sequenceRunResult: result, sequencePastRuns: history, sequenceRunning: false };
  const savedDefinitions = structuredClone(state.sequenceDefinitions);
  const nodes = new Map(), requests = [], posts = [], loads = [], pending = [], errors = [];
  let rows = [], uuid = 0, finishFlush;
  const node = () => ({ innerHTML: '', textContent: '', disabled: false, querySelectorAll: () => [],
    listeners: {}, classList: { toggle() {}, add() {}, remove() {} },
    addEventListener(type, callback) { this.listeners[type] = callback; } });
  const list = node();
  Object.defineProperty(list, 'innerHTML', { set(html) {
    this.markup = html;
    rows = state.sequenceDefinitions.map(def => ({ dataset: { seqId: def.id },
      addEventListener(type, callback) { this[type] = callback; } }));
  } });
  list.querySelectorAll = selector => selector === '.history-row' ? rows : [];
  nodes.set('sequenceListBody', list);
  const document = { getElementById: id => nodes.get(id) || nodes.set(id, node()).get(id) };
  const loadResponse = (url, ok = true) => ({ ok,
    json: async () => url.startsWith('/api/sequence-runs') ? structuredClone(history) : structuredClone(savedDefinitions) });
  const c = loadFunctions(['createNewSequence', 'loadSequences', 'currentSequenceSessionId',
    'isCurrentSequenceSession', 'sequenceSessionPath', 'bumpSequenceDraftVersion', 'renderSequencePanel', 'renderSequenceList', 'sequenceDisplayName', 'sequenceNameInputValue',
    'syncSequenceRunButton', 'normalizeSequenceRunResult', 'selectSequence', 'onClickWithProgress',
    'withButtonProgress', 'requireOkResponse', 'handleSequenceActionError'], {
    state, document, generateUuid: () => `new-${++uuid}`,
    flushSequenceDraft: async () => {
      if (flush === 'reject') throw new Error('Synthetic flush failure');
      if (flush === 'pending') return new Promise(resolve => { finishFlush = resolve; });
      return flush !== 'false';
    },
    expectedActiveSessionIdForWrite: id => id,
    fetch: (url, options = {}) => {
      requests.push({ url, options });
      if (options.method === 'POST') return new Promise((resolve, reject) => posts.push({ resolve, reject, body: JSON.parse(options.body) }));
      if (delayLoad) return new Promise((resolve, reject) => loads.push({ url, resolve, reject }));
      return Promise.resolve(loadResponse(url));
    },
    jsonArray: value => Array.isArray(value) ? value : [], escapeHtml: String, formatTimestamp: String,
    normalizeReplayHttpVersion: () => '', syncSequenceStepFromDom() {}, setTimeout: () => 1, clearTimeout() {},
    BUTTON_PROGRESS_DELAY_MS: 180, readApiErrorMessage: async () => 'Synthetic API failure',
    showToast: message => errors.push(message), console: { error() {} },
  });
  const create = c.createNewSequence;
  c.createNewSequence = () => { const promise = create(); pending.push(promise); return promise; };
  for (const id of ['newSequenceButton', 'sequenceEmptyNewButton']) {
    const binding = appSource.match(new RegExp(`  onClickWithProgress\\(document\\.getElementById\\("${id}"\\), \\(\\) =>\\n    createNewSequence\\(\\)\\.catch\\(handleSequenceActionError\\)\\);`));
    assert.ok(binding, `Production ${id} binding exists`); vm.runInContext(binding[0], c);
  }
  c.renderSequencePanel();
  return { c, state, document, history, requests, posts, loads, errors, pending,
    meta: () => document.getElementById('sequenceRunMeta').textContent,
    historyHtml: () => document.getElementById('sequencePastRunsBody').innerHTML,
    async click(id = 'newSequenceButton') {
      const button = document.getElementById(id); assert.equal(button.disabled, false);
      button.listeners.click({}); await tick();
    },
    async post(index = 0, outcome = 'success') {
      const request = posts[index];
      if (outcome === 'network') request.reject(new Error('Synthetic network failure'));
      else {
        if (outcome === 'success') savedDefinitions.push(structuredClone(request.body));
        request.resolve({ ok: outcome === 'success' });
      }
      await tick();
    },
    async load(outcome = 'success', failedIndex = 0) {
      loads.forEach((request, index) => {
        if (index === failedIndex && outcome === 'network') request.reject(new Error('Synthetic load failure'));
        else request.resolve(loadResponse(request.url, index !== failedIndex || outcome === 'success'));
      });
      await tick();
    },
    finish: (index = 0) => pending[index].catch(() => false), finishFlush: value => finishFlush(value),
    async selectOther() { rows.find(row => row.dataset.seqId === 'other').click({ target: { closest: () => null } }); await tick(); },
    adoptOtherSession() {
      state.activeSession = { id: 'session-b' };
      state.selectedSequenceId = 'current'; state.editingSequence = { id: 'current', name: 'Current session', steps: [] };
      state.sequenceDefinitions = [state.editingSequence];
      state.sequenceRunResult = { ...result, sequence_id: 'current', sequence_name: 'Current session' };
      state.sequencePastRuns = [{ ...history[0], sequence_id: 'current', sequence_name: 'Current session' }];
      c.renderSequencePanel();
    },
  };
}

const before = f => ({ selected: f.state.selectedSequenceId, editing: f.state.editingSequence,
  result: f.state.sequenceRunResult, history: f.state.sequencePastRuns, meta: f.meta(), historyHtml: f.historyHtml() });
function unchanged(f, snapshot) {
  assert.equal(f.state.selectedSequenceId, snapshot.selected); assert.equal(f.state.editingSequence, snapshot.editing);
  assert.equal(f.state.sequenceRunResult, snapshot.result); assert.equal(f.state.sequencePastRuns, snapshot.history);
  assert.equal(f.meta(), snapshot.meta); assert.equal(f.historyHtml(), snapshot.historyHtml);
}

for (const name of ['New sequence', 'Login flow']) test(`successful New clears ${name} current results but preserves history`, async () => {
  const f = fixture({ name }); const priorHistory = f.historyHtml(); await f.click(); await f.post();
  assert.equal(await f.finish(), true); assert.equal(f.state.selectedSequenceId, 'new-1');
  assert.equal(f.state.editingSequence.name, 'New sequence'); assert.equal(f.state.editingSequence.steps.length, 0);
  assert.equal(f.state.sequenceRunResult, null); assert.equal(f.meta(), 'No sequence run yet.');
  assert.doesNotMatch(f.document.getElementById('sequenceRunResultsBody').innerHTML, /Old step|synthetic-old-value/);
  assert.equal(f.historyHtml(), priorHistory); assert.equal(f.document.getElementById('runSequenceButton').disabled, true);
});

test('repeated successful default-name creation keeps empty current results and retained history', async () => {
  const f = fixture(); const history = f.historyHtml();
  for (let index = 0; index < 2; index++) {
    await f.click(); await f.post(index); assert.equal(await f.finish(index), true);
    assert.equal(f.state.selectedSequenceId, `new-${index + 1}`); assert.equal(f.state.editingSequence.name, 'New sequence');
    assert.equal(f.state.sequenceRunResult, null); assert.equal(f.historyHtml(), history);
  }
});

test('pending POST and list reload preserve the original result until final adoption', async () => {
  const f = fixture({ delayLoad: true }); const snapshot = before(f);
  await f.click(); unchanged(f, snapshot); await f.post(); unchanged(f, snapshot);
  assert.equal(f.loads.length, 2); await f.load(); assert.equal(await f.finish(), true);
  assert.equal(f.state.sequenceRunResult, null); assert.equal(f.historyHtml(), snapshot.historyHtml);
});

for (const outcome of ['api-error', 'network']) test(`failed create ${outcome} preserves original selection/result/history`, async () => {
  const f = fixture(); const snapshot = before(f); await f.click(); await f.post(0, outcome); await f.finish();
  unchanged(f, snapshot); assert.equal(f.errors.length, 1); assert.equal(f.requests.length, 1);
});

for (const outcome of ['api-error', 'network']) for (const failedIndex of [0, 1]) test(`failed reload ${failedIndex} ${outcome} preserves original result/history`, async () => {
  const f = fixture({ delayLoad: true }); const snapshot = before(f);
  await f.click(); await f.post(); await f.load(outcome, failedIndex); await f.finish();
  unchanged(f, snapshot); assert.equal(f.errors.length, 1);
});

for (const flush of ['false', 'reject']) test(`flush ${flush} preserves result/history without requests`, async () => {
  const f = fixture({ flush }); const snapshot = before(f); await f.click(); await f.finish();
  unchanged(f, snapshot); assert.equal(f.requests.length, 0); assert.equal(f.errors.length, flush === 'reject' ? 1 : 0);
});

test('pending flush does not clear original result before its refusal', async () => {
  const f = fixture({ flush: 'pending' }); const snapshot = before(f); await f.click(); unchanged(f, snapshot);
  f.finishFlush(false); await f.finish(); await tick(); unchanged(f, snapshot); assert.equal(f.requests.length, 0);
});

for (const phase of ['post', 'reload']) test(`stale session during ${phase} preserves the newly current result/history`, async () => {
  const f = fixture({ delayLoad: true }); await f.click(); if (phase === 'reload') await f.post();
  f.adoptOtherSession(); const snapshot = before(f);
  if (phase === 'post') await f.post(); else await f.load();
  assert.equal(await f.finish(), false); unchanged(f, snapshot); assert.equal(f.errors.length, 0);
});

test('ordinary row selection uses the same current-result reset without discarding history', async () => {
  const f = fixture(); const history = f.historyHtml(); await f.selectOther();
  assert.equal(f.state.sequenceRunResult, null); assert.equal(f.meta(), 'No sequence run yet.'); assert.equal(f.historyHtml(), history);
});

test('empty-state New binding still creates a fresh empty selection', async () => {
  const f = fixture(); f.state.sequenceDefinitions = []; f.state.selectedSequenceId = null;
  f.state.editingSequence = null; f.state.sequenceRunResult = null; f.c.renderSequencePanel();
  await f.click('sequenceEmptyNewButton'); await f.post(); assert.equal(await f.finish(), true);
  assert.equal(f.state.selectedSequenceId, 'new-1'); assert.equal(f.state.sequenceRunResult, null);
});
