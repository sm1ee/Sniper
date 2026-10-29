// Production Run, row, and input handlers with in-memory deferred replies only.
// No app bootstrap, real API calls, sequence execution, or session switching.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));

function fixture({ delaySave = false } = {}) {
  const definitions = ['a', 'b'].map(id => ({ id, name: `Sequence ${id}`, steps: [{
    id: `${id}-step`, label: 'Step 1', request: {},
    request_text: 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n', extractions: [],
  }] }));
  const state = { activeSession: { id: 'session-a' }, sequenceDefinitions: definitions,
    selectedSequenceId: 'a', editingSequence: structuredClone(definitions[0]),
    sequenceDraftVersion: 0, sequencePastRuns: [], sequenceRunResult: null,
    sequenceRunning: false, sequenceRunGeneration: 0, sequenceDirty: false };
  const nodes = new Map();
  let rows = [], cards = [], saveResolve, saveReject, renders = 0;
  const requests = [], pending = [], toasts = [];
  const node = () => {
    const classes = new Set();
    return { innerHTML: '', textContent: '', disabled: false, querySelectorAll: () => [],
      classList: { toggle: (name, on) => on ? classes.add(name) : classes.delete(name), contains: name => classes.has(name) },
      addEventListener(type, callback) { this[type] = callback; } };
  };
  const document = { activeElement: null,
    getElementById: id => nodes.get(id) || nodes.set(id, node()).get(id) };
  const list = node();
  Object.defineProperty(list, 'innerHTML', { set(html) {
    this.markup = html;
    rows = state.sequenceDefinitions.map(def => ({ dataset: { seqId: def.id },
      addEventListener(type, callback) { this[type] = callback; } }));
  } });
  list.querySelectorAll = selector => selector === '.history-row' ? rows : [];
  nodes.set('sequenceListBody', list);
  const container = node();
  Object.defineProperty(container, 'innerHTML', { set(html) {
    this.markup = html;
    if (cards.some(card => card.request === document.activeElement)) document.activeElement = null;
    cards = (state.editingSequence?.steps || []).map(step => {
      const request = { value: step.request_text, focus() { document.activeElement = this; } };
      const fields = { '.step-request-text': request, '.step-label': { value: step.label }, '.step-extractions': { open: false } };
      return { dataset: { stepId: step.id }, request,
        querySelector: selector => fields[selector], querySelectorAll: () => [] };
    });
  } });
  container.querySelectorAll = selector => selector === '.sequence-step-card' ? cards : [];
  nodes.set('sequenceStepsContainer', container);
  const c = loadFunctions(['runCurrentSequence', 'renderSequencePanel', 'renderSequenceList', 'syncSequenceRunButton',
    'selectSequence', 'flushSequenceDraft', 'bumpSequenceDraftVersion', 'markSequenceDraftDirty',
    'currentSequenceSessionId', 'isCurrentSequenceSession', 'isCurrentSequenceRun',
    'normalizeSequenceRunResult', 'syncSequenceStepFromDom'], {
    state, document, escapeHtml: String, formatTimestamp: String, normalizeReplayHttpVersion: () => '',
    replayHttpVersionFromText: () => '', parseEditableRawRequest(text) {
      if (text.startsWith('invalid')) throw new Error('Invalid request');
      return { path: text };
    }, jsonArray: value => Array.isArray(value) ? value : [],
    saveCurrentSequence: () => delaySave
      ? new Promise((resolve, reject) => { saveResolve = resolve; saveReject = reject; }) : Promise.resolve(true),
    expectedActiveSessionIdForWrite: id => id,
    fetch: (url, options) => new Promise((resolve, reject) => requests.push({ url, options, resolve, reject })),
    loadSequences: async () => { state.sequencePastRuns = [{ sequence_name: 'Sequence a', status: 'completed', step_count: 1, started_at: 'now' }]; return true; },
    scheduleRefresh() {}, showToast: (...args) => toasts.push(args),
    handleSequenceActionError(error) { throw error; }, readApiErrorMessage: async () => 'Synthetic failure',
  });
  const render = c.renderSequencePanel;
  c.renderSequencePanel = (...args) => { renders++; return render(...args); };
  const run = c.runCurrentSequence;
  c.runCurrentSequence = () => { const promise = run(); pending.push(promise); return promise; };
  const binding = appSource.match(/  document\.getElementById\("runSequenceButton"\)\.addEventListener\("click", \(\) => \{[^]*?\n  \}\);/);
  assert.ok(binding, 'Production Run binding exists');
  vm.runInContext(binding[0], c);
  c.renderSequencePanel();
  const button = document.getElementById('runSequenceButton');
  return { c, state, document, container, requests, pending, toasts, button,
    editor: () => cards[0]?.request, renders: () => renders,
    async start() { assert.equal(button.disabled, false); button.click(); await tick(); },
    async select(id) { rows.find(row => row.dataset.seqId === id).click({ target: { closest: () => null } }); await tick(); },
    settle(index = 0, outcome = 'success') {
      if (outcome === 'network') requests[index].reject(new Error('Synthetic failure'));
      else requests[index].resolve({ ok: outcome === 'success', status: outcome === 'success' ? 200 : 400,
        json: async () => ({ sequence_name: 'Sequence a', status: 'completed', step_results: [{ label: 'Step 1', status: 200 }] }) });
      return pending[index];
    },
    save: value => saveResolve(value), rejectSave: () => saveReject(new Error('Synthetic save failure')),
    resetSequence(sessionId) {
      // Execute the current reset assignments, without assuming they bump run generation.
      const reset = appSource.match(/  state\.sequenceDefinitions = \[\];\n  state\.selectedSequenceId = null;[^]*?  state\.sequencePastRuns = \[\];/);
      assert.ok(reset); vm.runInContext(reset[0], c);
      state.activeSession = { id: sessionId }; state.sequenceDefinitions = structuredClone(definitions);
      c.renderSequencePanel();
    },
  };
}

for (const outcome of ['success', 'api-error', 'network']) {
  test(`A settling with ${outcome} after B selection releases busy without repainting B`, async () => {
    const f = fixture(); await f.start(); await f.select('b');
    const editor = f.editor(); editor.value = 'B model-backed draft'; editor.focus(); f.container.input();
    editor.value = 'B DOM-only draft'; const renders = f.renders();
    await f.settle(0, outcome);
    assert.equal(f.state.sequenceRunning, false); assert.equal(f.button.disabled, false); assert.equal(f.button.textContent, 'Run');
    assert.equal(f.renders(), renders); assert.equal(f.editor(), editor); assert.equal(f.document.activeElement, editor);
    assert.equal(editor.value, 'B DOM-only draft'); assert.equal(f.state.editingSequence.steps[0].request_text, 'B model-backed draft');
    assert.equal(f.state.sequenceRunResult, null); assert.equal(f.toasts.length, 0);
    await f.start(); assert.equal(f.requests.length, 2); await f.settle(1);
  });

  test(`same-owner ${outcome} releases busy and preserves result/error feedback`, async () => {
    const f = fixture(); await f.start(); const renders = f.renders(); await f.settle(0, outcome);
    assert.equal(f.state.sequenceRunning, false); assert.equal(f.button.disabled, false); assert.equal(f.button.textContent, 'Run');
    assert.equal(f.renders(), renders + 1);
    assert.equal(!!f.state.sequenceRunResult, outcome === 'success');
    assert.equal(f.toasts.length, outcome === 'success' ? 0 : 1);
    if (outcome === 'success') {
      assert.match(f.document.getElementById('sequenceRunResultsBody').innerHTML, /Step 1/);
      assert.match(f.document.getElementById('sequencePastRunsBody').innerHTML, /Sequence a/);
    }
  });
}

for (const outcome of ['true', 'false', 'reject']) test(`navigation during save (${outcome}) releases busy without a run request`, async () => {
  const f = fixture({ delaySave: true }); await f.start(); await f.select('b');
  const editor = f.editor(); editor.focus(); editor.value = 'B unsynced draft'; const renders = f.renders();
  if (outcome === 'reject') f.rejectSave(); else f.save(outcome === 'true');
  await f.pending[0];
  assert.equal(f.requests.length, 0); assert.equal(f.state.sequenceRunning, false); assert.equal(f.button.disabled, false);
  assert.equal(f.renders(), renders); assert.equal(f.editor(), editor); assert.equal(f.document.activeElement, editor);
  assert.equal(editor.value, 'B unsynced draft'); assert.equal(f.toasts.length, 0);
});

for (const change of ['newer draft', 'A-B-A']) test(`${change} releases busy but preserves current editor`, async () => {
  const f = fixture(); await f.start();
  if (change === 'A-B-A') { await f.select('b'); await f.select('a'); }
  const editor = f.editor(); editor.focus(); editor.value = 'Current edited draft'; f.container.input();
  editor.value = 'Current DOM-only draft'; const renders = f.renders(); await f.settle();
  assert.equal(f.state.sequenceRunning, false); assert.equal(f.button.disabled, false); assert.equal(f.renders(), renders);
  assert.equal(f.editor(), editor); assert.equal(f.document.activeElement, editor); assert.equal(editor.value, 'Current DOM-only draft');
  assert.equal(f.state.sequenceRunResult, null);
});

for (const selection of ['empty B', 'no sequence']) test(`stale cleanup leaves Run disabled for ${selection}`, async () => {
  const f = fixture(); await f.start();
  if (selection === 'empty B') { f.state.sequenceDefinitions[1].steps = []; await f.select('b'); }
  else f.resetSequence('session-a');
  const hidden = f.button.classList.contains('hidden'); await f.settle();
  assert.equal(f.state.sequenceRunning, false); assert.equal(f.button.disabled, true); assert.equal(f.button.textContent, 'Run');
  assert.equal(f.button.classList.contains('hidden'), hidden);
  assert.equal(hidden, selection === 'no sequence'); assert.equal(f.state.sequenceRunResult, null);
});

for (const sessionId of ['session-a', 'session-b']) test(`old completion cannot settle a newer run after reset into ${sessionId}`, async () => {
  const f = fixture(); await f.start(); f.resetSequence(sessionId); await f.select('b'); await f.start();
  const editor = f.editor(); editor.focus(); const renders = f.renders(); await f.settle(0);
  assert.equal(f.state.sequenceRunning, true); assert.equal(f.button.disabled, true); assert.equal(f.button.textContent, 'Running...');
  assert.equal(f.renders(), renders); assert.equal(f.editor(), editor); assert.equal(f.document.activeElement, editor);
  assert.equal(f.state.sequenceRunResult, null); await f.settle(1); assert.equal(f.state.sequenceRunning, false);
});

for (const transition of ['same session', 'A-B-A']) test(`${transition} reset and reselect without a newer run preserves the fresh editor`, async () => {
  const f = fixture(); await f.start(); const generation = f.state.sequenceRunGeneration;
  if (transition === 'A-B-A') { f.resetSequence('session-b'); await f.select('b'); }
  f.resetSequence('session-a'); await f.select('a');
  assert.equal(f.state.sequenceRunGeneration, generation, 'This fix does not change reset generation semantics');
  const editor = f.editor(); editor.focus(); editor.value = 'Fresh unsynced draft';
  const renders = f.renders(); await f.settle();
  assert.equal(f.state.sequenceRunning, false); assert.equal(f.button.disabled, false); assert.equal(f.renders(), renders);
  assert.equal(f.editor(), editor); assert.equal(f.document.activeElement, editor); assert.equal(editor.value, 'Fresh unsynced draft');
  assert.equal(f.state.sequenceRunResult, null); assert.equal(f.toasts.length, 0);
});

test('preflight parse error releases the control without making save or run requests', async () => {
  const f = fixture({ delaySave: true });
  f.editor().value = 'invalid draft'; f.container.input(); await f.start(); await f.pending[0];
  assert.equal(f.requests.length, 0); assert.equal(f.state.sequenceRunning, false);
  assert.equal(f.button.disabled, false); assert.match(f.toasts[0][0], /Invalid request/);
  assert.equal(f.state.editingSequence.steps[0].request_text, 'invalid draft');
});
