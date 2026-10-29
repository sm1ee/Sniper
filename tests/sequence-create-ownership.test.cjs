// Real New/Run/row/input/import handlers and save/flush paths, with in-memory
// deferred API replies only. No server, sequence execution, or target traffic.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
const keptMessage = 'New sequence created in the list. Kept your current sequence open.';

function fixture() {
  const definition = id => ({ id, name: `Sequence ${id}`, steps: [{ id: `${id}-step`, label: 'Step 1',
    request: {}, request_text: `GET /${id} HTTP/1.1\r\nHost: example.com\r\n\r\n`, extractions: [] }] });
  const remote = new Map(['a', 'b'].map(id => [id, definition(id)]));
  const state = { activeSession: { id: 'session-a' }, sequenceDefinitions: [...remote.values()],
    selectedSequenceId: 'a', editingSequence: structuredClone(remote.get('a')), sequenceDirty: false,
    sequenceDraftVersion: 0, sequenceSelectionGeneration: 0, sequenceRunGeneration: 0,
    sequenceRunResult: { sequence_id: 'a', sequence_name: 'Sequence a', status: 'completed', step_results: [] },
    sequencePastRuns: [], sequenceRunning: false };
  const nodes = new Map(), requests = [], creates = [], saves = [], loads = [], runs = [];
  const newPromises = [], selections = [], runPromises = [], history = [];
  let rows = [], cards = [], delayLoads = false, uuid = 0;
  const node = () => ({ innerHTML: '', textContent: '', disabled: false, writes: 0, children: [], style: {},
    querySelectorAll: () => [], listeners: {}, classList: { toggle() {}, add() {}, remove() {} },
    addEventListener(type, callback) { this.listeners[type] = callback; },
    appendChild(child) { this.children.push(child); } });
  const document = { activeElement: null, body: {}, createElement: node,
    getElementById: id => nodes.get(id) || nodes.set(id, node()).get(id) };
  for (const id of ['sequenceRunResultsBody', 'sequencePastRunsBody']) {
    const element = node();
    Object.defineProperty(element, 'innerHTML', { get() { return this.markup; }, set(html) { this.markup = html; this.writes++; } });
    nodes.set(id, element);
  }
  const list = node();
  Object.defineProperty(list, 'innerHTML', { get() { return this.markup; }, set(html) {
    this.markup = html; this.writes++;
    if (rows.some(row => row.control === document.activeElement)) document.activeElement = document.body;
    rows = state.sequenceDefinitions.map(def => {
      const control = { disabled: false, dataset: { seqSelect: def.id },
        closest: selector => selector === '.seq-delete' ? null : control,
        focus() { document.activeElement = control; } };
      return { dataset: { seqId: def.id }, control, addEventListener(type, callback) { this[type] = callback; } };
    });
  } });
  list.contains = control => rows.some(row => row.control === control);
  list.querySelectorAll = selector => selector === '.history-row' ? rows : selector === '.seq-select' ? rows.map(row => row.control) : [];
  nodes.set('sequenceListBody', list);
  const container = node();
  Object.defineProperty(container, 'innerHTML', { get() { return this.markup; }, set(html) {
    this.markup = html; this.writes++;
    if (cards.some(card => card.request === document.activeElement)) document.activeElement = document.body;
    cards = (state.editingSequence?.steps || []).map(step => {
      const request = { disabled: false, value: step.request_text, selectionStart: 0, selectionEnd: 0,
        focus() { document.activeElement = this; } };
      const fields = { '.step-label': { value: step.label }, '.step-request-text': request, '.step-extractions': { open: false } };
      return { dataset: { stepId: step.id }, request, querySelector: selector => fields[selector], querySelectorAll: () => [] };
    });
  } });
  container.querySelectorAll = selector => selector === '.sequence-step-card' ? cards : [];
  nodes.set('sequenceStepsContainer', container);
  const reply = url => ({ ok: true, json: async () => url.startsWith('/api/sequence-runs')
    ? structuredClone(history) : structuredClone([...remote.values()]) });
  const c = loadFunctions(['createNewSequence', 'loadSequences', 'currentSequenceSessionId', 'isCurrentSequenceSession',
    'sequenceSessionPath', 'bumpSequenceDraftVersion', 'markSequenceDraftDirty', 'renderSequencePanel', 'renderSequenceList', 'sequenceDisplayName', 'sequenceNameInputValue',
    'syncSequenceRunButton', 'normalizeSequenceRunResult', 'selectSequence', 'onClickWithProgress', 'withButtonProgress',
    'flushSequenceDraft', 'syncSequenceStepFromDom', 'requireOkResponse', 'showToast', 'handleSequenceActionError',
    'runCurrentSequence', 'isCurrentSequenceRun', 'sendRecordToSequence'], {
    state, document, generateUuid: () => `new-${++uuid}`, currentSessionId: () => state.activeSession.id,
    workspaceStateGeneration: 1, expectedActiveSessionIdForWrite: id => id,
    fetch: (url, options = {}) => {
      requests.push({ url, options });
      if (url.endsWith('/run')) return new Promise((resolve, reject) => runs.push({ url, resolve, reject }));
      if (options.method === 'POST') {
        const payload = JSON.parse(options.body);
        return new Promise((resolve, reject) => (remote.has(payload.id) ? saves : creates).push({ payload, resolve, reject }));
      }
      if (delayLoads) return new Promise(resolve => loads.push({ url, resolve }));
      return Promise.resolve(reply(url));
    },
    jsonArray: value => Array.isArray(value) ? value : [], escapeHtml: String, formatTimestamp: String,
    normalizeReplayHttpVersion: () => '', replayHttpVersionFromText: () => '', parseEditableRawRequest: text => ({ path: text }),
    readApiErrorMessage: async () => 'Synthetic failure', setTimeout: () => 1, clearTimeout() {}, BUTTON_PROGRESS_DELAY_MS: 180,
    console: { error() {} }, scheduleRefresh() {}, setActiveTool() {}, scheduleWorkspaceStateSave() {}, renderToolPanels() {},
    editableRequestFromRecord: () => ({ scheme: 'https', host: 'example.com', method: 'GET', path: '/imported', headers: [], body: '' }),
    buildEditableRawRequest: () => 'GET /imported HTTP/1.1\r\nHost: example.com\r\n\r\n',
  });
  // Its multiline default argument contains a column-zero brace that is not
  // the function end; require an exact closing-brace line for this extraction.
  vm.runInContext(appSource.match(/^async function saveCurrentSequence\([^]*?^\}$/m)[0], c);
  for (const [name, promises] of [['createNewSequence', newPromises], ['selectSequence', selections], ['runCurrentSequence', runPromises]]) {
    const actual = c[name]; c[name] = (...args) => { const promise = actual(...args); promises.push(promise); return promise; };
  }
  const newBinding = appSource.match(/  onClickWithProgress\(document\.getElementById\("newSequenceButton"\), \(\) =>\n    createNewSequence\(\)\.catch\(handleSequenceActionError\)\);/);
  const runBinding = appSource.match(/  document\.getElementById\("runSequenceButton"\)\.addEventListener\("click", \(\) => \{[^]*?\n  \}\);/);
  assert.ok(newBinding); assert.ok(runBinding); vm.runInContext(newBinding[0], c); vm.runInContext(runBinding[0], c);
  c.renderSequencePanel();
  return { c, state, document, remote, requests, creates, saves, runs, loads, newPromises, selections, runPromises, list, container,
    editor: () => cards[0]?.request, row: id => rows.find(row => row.dataset.seqId === id),
    toasts: () => document.getElementById('toastContainer').children,
    async clickNew() { const button = document.getElementById('newSequenceButton'); assert.equal(button.disabled, false); button.listeners.click({}); await tick(); },
    async clickRun() { const button = document.getElementById('runSequenceButton'); assert.equal(button.disabled, false); button.listeners.click({}); await tick(); },
    async select(id) { const row = rows.find(row => row.dataset.seqId === id); assert.equal(row.control.disabled, false); row.control.focus(); row.click({ target: row.control }); await tick(); },
    edit(text = 'GET /unsaved HTTP/1.1\r\nHost: example.com\r\n\r\n') {
      const editor = cards[0].request; assert.equal(editor.disabled, false); editor.focus(); editor.value = text;
      container.listeners.input(); editor.selectionStart = 1; editor.selectionEnd = 2; return editor;
    },
    async finishCreate({ holdReload = false, ok = true } = {}) {
      if (ok) remote.set(creates[0].payload.id, structuredClone(creates[0].payload));
      delayLoads = holdReload; creates[0].resolve({ ok }); await tick();
    },
    async finishLoads() { delayLoads = false; for (const load of loads) load.resolve(reply(load.url)); await tick(); },
    async finishSave(index = 0) { remote.set(saves[index].payload.id, structuredClone(saves[index].payload)); saves[index].resolve({ ok: true }); await tick(); },
    async finishRun(index = 0) {
      const sequenceId = runs[index].url.match(/\/sequences\/([^/]+)\/run/)[1];
      const sequenceName = remote.get(sequenceId).name;
      history.push({ sequence_id: sequenceId, sequence_name: sequenceName, status: 'completed', step_count: 1, started_at: 'now' });
      runs[index].resolve({ ok: true, json: async () => ({ sequence_id: sequenceId, sequence_name: sequenceName,
        status: 'completed', step_results: [{ label: 'Run result', status: 200 }] }) });
      await runPromises[index];
    },
    adoptOtherSession() {
      state.activeSession = { id: 'session-b' }; state.sequenceDefinitions = [definition('current')];
      state.selectedSequenceId = 'current'; state.editingSequence = structuredClone(state.sequenceDefinitions[0]);
      state.sequenceRunResult = { sequence_id: 'current', status: 'completed', step_results: [] }; c.renderSequencePanel();
    },
  };
}

const snapshot = f => ({ editor: f.editor(), focus: f.document.activeElement, text: f.editor()?.value,
  start: f.editor()?.selectionStart, end: f.editor()?.selectionEnd, selected: f.state.selectedSequenceId,
  editing: f.state.editingSequence, dirty: f.state.sequenceDirty, version: f.state.sequenceDraftVersion,
  result: f.state.sequenceRunResult, editorWrites: f.container.writes,
  resultWrites: f.document.getElementById('sequenceRunResultsBody').writes,
  pastWrites: f.document.getElementById('sequencePastRunsBody').writes });
function retained(f, before, { listFocus = false } = {}) {
  assert.equal(f.editor(), before.editor); assert.equal(f.editor()?.value, before.text);
  assert.equal(f.editor()?.selectionStart, before.start); assert.equal(f.editor()?.selectionEnd, before.end);
  assert.equal(f.state.selectedSequenceId, before.selected); assert.equal(f.state.editingSequence, before.editing);
  assert.equal(f.state.sequenceDirty, before.dirty); assert.equal(f.state.sequenceDraftVersion, before.version);
  assert.equal(f.state.sequenceRunResult, before.result); assert.equal(f.container.writes, before.editorWrites);
  assert.equal(f.document.getElementById('sequenceRunResultsBody').writes, before.resultWrites);
  assert.equal(f.document.getElementById('sequencePastRunsBody').writes, before.pastWrites);
  assert.equal(f.document.activeElement, listFocus ? f.row(before.selected).control : before.focus);
}
function visibleButNotAdopted(f) {
  assert.ok(f.remote.has('new-1')); assert.match(f.list.innerHTML, /data-seq-select="new-1"/);
  assert.equal(f.toasts().length, 1); assert.equal(f.toasts()[0].textContent, keptMessage);
  assert.equal(f.toasts()[0].className, 'toast toast-success');
}

for (const phase of ['post', 'reload']) test(`late New during ${phase} lists the created definition without replacing B's draft or DOM`, async () => {
  const f = fixture(); await f.clickNew(); assert.equal(f.document.getElementById('newSequenceButton').disabled, true);
  if (phase === 'reload') await f.finishCreate({ holdReload: true });
  await f.select('b'); await f.selections[0]; const editor = f.edit(); editor.value = 'B newer DOM-only draft';
  const before = snapshot(f); assert.equal(f.toasts().length, 0);
  if (phase === 'post') await f.finishCreate(); else await f.finishLoads();
  assert.equal(await f.newPromises[0], false); retained(f, before); visibleButNotAdopted(f);
  assert.equal(f.saves.length, 0); assert.doesNotMatch(f.remote.get('b').steps[0].request_text, /unsaved/);
});

test('same-A edit supersedes creation without relying on selection changes', async () => {
  const f = fixture(); await f.clickNew(); const generation = f.state.sequenceSelectionGeneration; f.edit();
  assert.equal(f.state.sequenceSelectionGeneration, generation); const before = snapshot(f); await f.finishCreate();
  assert.equal(await f.newPromises[0], false); retained(f, before); visibleButNotAdopted(f);
});

test('current-row reselect cancels adoption and list-only refresh restores the live row control focus', async () => {
  const f = fixture(); await f.clickNew(); const version = f.state.sequenceDraftVersion;
  await f.select('a'); await f.selections[0]; assert.equal(f.state.sequenceDraftVersion, version);
  const before = snapshot(f); await f.finishCreate(); assert.equal(await f.newPromises[0], false);
  retained(f, before, { listFocus: true }); visibleButNotAdopted(f);
});

test('A-B-A navigation still supersedes New even though the selected ID returns to A', async () => {
  const f = fixture(); await f.clickNew(); await f.select('b'); await f.select('a');
  f.editor().focus(); const before = snapshot(f); await f.finishCreate();
  assert.equal(await f.newPromises[0], false); retained(f, before); visibleButNotAdopted(f);
});

test('own real dirty flush can replace its editor object without invalidating creation', async () => {
  const f = fixture(); f.edit(); const version = f.state.sequenceDraftVersion, original = f.state.editingSequence;
  await f.clickNew(); await f.finishSave(); assert.equal(f.creates.length, 1);
  assert.equal(f.state.sequenceDraftVersion, version); assert.notEqual(f.state.editingSequence, original);
  await f.finishCreate(); assert.equal(await f.newPromises[0], true); assert.equal(f.state.selectedSequenceId, 'new-1');
  assert.equal(f.state.sequenceDirty, false); assert.equal(f.state.sequenceRunResult, null); assert.equal(f.toasts().length, 0);
});

for (const change of ['reselect', 'edit']) test(`newer ${change} during initial flush prevents the New POST`, async () => {
  const f = fixture(); f.edit(); await f.clickNew();
  if (change === 'reselect') await f.select('a'); else f.edit('GET /newer HTTP/1.1\r\nHost: example.com\r\n\r\n');
  const editor = f.editor(); await f.finishSave(); assert.equal(await f.newPromises[0], false);
  assert.equal(f.creates.length, 0); assert.equal(f.state.selectedSequenceId, 'a'); assert.equal(f.editor(), editor);
  assert.equal(f.toasts().length, 0);
});

test('B navigation winning two real flushes preserves its newer draft without creating a sequence', async () => {
  const f = fixture(); f.edit(); await f.clickNew(); await f.select('b'); assert.equal(f.saves.length, 2);
  await f.finishSave(1); await f.selections[0]; f.edit(); const before = snapshot(f); await f.finishSave(0);
  assert.equal(await f.newPromises[0], false); assert.equal(f.creates.length, 0); retained(f, before); assert.equal(f.toasts().length, 0);
});

test('newer New invocation supersedes an older row navigation waiting for its flush', async () => {
  const f = fixture(); f.edit(); await f.select('b'); await f.clickNew(); assert.equal(f.saves.length, 2);
  await f.finishSave(0); await f.selections[0]; assert.equal(f.state.selectedSequenceId, 'a');
  await f.finishSave(1); await f.finishCreate(); assert.equal(await f.newPromises[0], true);
  assert.equal(f.state.selectedSequenceId, 'new-1'); assert.equal(f.toasts().length, 0);
});

for (const completed of [false, true]) test(`newer Run intent (completed=${completed}) keeps A and its run state/results`, async () => {
  const f = fixture(); await f.clickNew(); const selectionGeneration = f.state.sequenceSelectionGeneration;
  const draftVersion = f.state.sequenceDraftVersion; await f.clickRun(); await f.finishSave();
  assert.equal(f.state.sequenceSelectionGeneration, selectionGeneration); assert.equal(f.state.sequenceDraftVersion, draftVersion);
  if (completed) await f.finishRun(); f.editor().focus(); const before = snapshot(f);
  await f.finishCreate(); assert.equal(await f.newPromises[0], false); retained(f, before); visibleButNotAdopted(f);
  assert.equal(f.state.sequenceRunning, !completed);
  assert.equal(f.document.getElementById('runSequenceButton').disabled, !completed);
  if (!completed) await f.finishRun();
  assert.equal(f.state.sequenceRunResult.sequence_id, 'a');
});

test('Run intent during initial New flush prevents creation while the Run continues normally', async () => {
  const f = fixture(); f.edit(); await f.clickNew(); await f.clickRun(); assert.equal(f.saves.length, 2);
  await f.finishSave(0); assert.equal(await f.newPromises[0], false); assert.equal(f.creates.length, 0);
  assert.equal(f.state.sequenceRunning, true); await f.finishSave(1); await f.finishRun();
  assert.equal(f.state.sequenceRunResult.sequence_id, 'a'); assert.equal(f.toasts().length, 0);
});

test('import caller stops on stale creation false without appending to or saving newer B', async () => {
  const f = fixture(); f.state.selectedSequenceId = null; f.state.editingSequence = null; f.state.sequenceRunResult = null; f.c.renderSequencePanel();
  const importing = f.c.sendRecordToSequence({ id: 'synthetic-import', kind: 'request' }); await tick();
  await f.select('b'); f.edit(); const before = snapshot(f), count = f.state.editingSequence.steps.length;
  await f.finishCreate(); await importing; assert.equal(await f.newPromises[0], false);
  retained(f, before); visibleButNotAdopted(f); assert.equal(f.state.editingSequence.steps.length, count); assert.equal(f.saves.length, 0);
});

for (const phase of ['post', 'reload']) test(`stale session during ${phase} cannot refresh or relabel the current workspace`, async () => {
  const f = fixture(); await f.clickNew(); if (phase === 'reload') await f.finishCreate({ holdReload: true });
  f.adoptOtherSession(); f.editor().focus(); const before = snapshot(f), listWrites = f.list.writes;
  if (phase === 'post') await f.finishCreate(); else await f.finishLoads();
  assert.equal(await f.newPromises[0], false); retained(f, before); assert.equal(f.list.writes, listWrites); assert.equal(f.toasts().length, 0);
});

test('failed creation after B editing reports only the existing error without success feedback or repaint', async () => {
  const f = fixture(); await f.clickNew(); await f.select('b'); f.edit(); const before = snapshot(f), listWrites = f.list.writes;
  await f.finishCreate({ ok: false }); await f.newPromises[0].catch(() => {}); await tick();
  retained(f, before); assert.equal(f.list.writes, listWrites); assert.equal(f.toasts().length, 1);
  assert.equal(f.toasts()[0].className, 'toast toast-error'); assert.doesNotMatch(f.toasts()[0].textContent, /created in the list/);
});
