// Static header field with actual input/change/Save/New/Run/row bindings.
// Save, load and execution responses are deferred in memory; no server or traffic.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));

function fixture(name = 'Original name') {
  const definition = (id, title) => ({ id, name: title, steps: [{ id: `${id}-step`, label: 'Step label',
    request: {}, request_text: 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n', extractions: [] }] });
  const remote = new Map([['a', definition('a', name)], ['b', definition('b', 'Other name')]]);
  const history = [{ sequence_id: 'a', sequence_name: name, status: 'completed', step_count: 1, started_at: 'then' }];
  const state = { activeSession: { id: 'session-a' }, selectedSequenceId: 'a', editingSequence: structuredClone(remote.get('a')),
    sequenceDefinitions: structuredClone([...remote.values()]), sequenceDirty: false, sequenceDraftVersion: 0,
    sequenceSelectionGeneration: 0, sequenceRunGeneration: 0, sequenceRunning: false,
    sequenceRunResult: { id: 'old-run', sequence_id: 'a', sequence_name: name, status: 'completed', step_results: [] },
    sequencePastRuns: structuredClone(history) };
  const nodes = new Map(), requests = [], saves = [], creates = [], runs = [], errors = [], notices = [];
  const savePromises = [], newPromises = [], runPromises = [], selections = [];
  let rows = [], cards = [], uuid = 0;
  const node = () => {
    const classes = new Set();
    return { innerHTML: '', textContent: '', disabled: false, listeners: {}, querySelectorAll: () => [],
      classList: { toggle: (key, on) => on ? classes.add(key) : classes.delete(key), contains: key => classes.has(key),
        add: key => classes.add(key), remove: (...keys) => keys.forEach(key => classes.delete(key)) },
      addEventListener(type, callback) { this.listeners[type] = callback; } };
  };
  const document = { activeElement: null, body: {}, getElementById: id => nodes.get(id) || nodes.set(id, node()).get(id) };
  const input = node(); let inputValue = '';
  Object.assign(input, { valueWrites: 0, selectionStart: 0, selectionEnd: 0, focus() { document.activeElement = input; } });
  Object.defineProperty(input, 'value', { get: () => inputValue, set(value) {
    input.valueWrites++; inputValue = String(value).replace(/[\r\n]/g, '');
    input.selectionStart = input.selectionEnd = inputValue.length;
  } });
  nodes.set('sequenceNameInput', input);
  const list = node();
  Object.defineProperty(list, 'innerHTML', { get() { return this.markup; }, set(html) {
    this.markup = html;
    if (rows.some(row => row.control === document.activeElement)) document.activeElement = document.body;
    rows = state.sequenceDefinitions.map(def => {
      const control = { dataset: { seqSelect: def.id }, closest: selector => selector === '.seq-delete' ? null : control,
        focus() { document.activeElement = control; } };
      return { dataset: { seqId: def.id }, control, addEventListener(type, callback) { this[type] = callback; } };
    });
  } });
  list.contains = control => rows.some(row => row.control === control);
  list.querySelectorAll = selector => selector === '.history-row' ? rows : selector === '.seq-select' ? rows.map(row => row.control) : [];
  nodes.set('sequenceListBody', list);
  const container = node(); container.writes = 0;
  Object.defineProperty(container, 'innerHTML', { set(html) {
    this.markup = html; this.writes++;
    if (cards.some(card => card.request === document.activeElement || card.label === document.activeElement)) document.activeElement = document.body;
    cards = (state.editingSequence?.steps || []).map(step => {
      const request = { value: step.request_text }, label = { value: step.label };
      const fields = { '.step-request-text': request, '.step-label': label, '.step-extractions': { open: false } };
      return { dataset: { stepId: step.id }, request, label, querySelector: selector => fields[selector], querySelectorAll: () => [] };
    });
  } });
  container.querySelectorAll = selector => selector === '.sequence-step-card' ? cards : [];
  nodes.set('sequenceStepsContainer', container);
  const c = loadFunctions(['sequenceExtractionGuidance', 'renderSequencePanel', 'renderSequenceList', 'sequenceDisplayName', 'sequenceNameInputValue',
    'updateSequenceNameFromInput', 'syncSequenceRunButton', 'normalizeSequenceRunResult', 'bumpSequenceDraftVersion',
    'markSequenceDraftDirty', 'syncSequenceStepFromDom', 'currentSequenceSessionId', 'isCurrentSequenceSession',
    'sequenceSessionPath', 'loadSequences', 'flushSequenceDraft', 'selectSequence', 'createNewSequence',
    'runCurrentSequence', 'isCurrentSequenceRun', 'onClickWithProgress', 'withButtonProgress', 'requireOkResponse', 'escapeHtml'], {
    state, document, currentSessionId: () => state.activeSession.id, workspaceStateGeneration: 1,
    expectedActiveSessionIdForWrite: id => id, generateUuid: () => `new-${++uuid}`,
    jsonArray: value => Array.isArray(value) ? value : [], formatTimestamp: String, normalizeReplayHttpVersion: () => '',
    replayHttpVersionFromText: () => '', parseEditableRawRequest: text => ({ path: text }),
    fetch: (url, options = {}) => {
      requests.push({ url, options });
      if (url.endsWith('/run')) return new Promise(resolve => runs.push({ resolve }));
      if (options.method === 'POST') {
        const payload = JSON.parse(options.body);
        return new Promise(resolve => (remote.has(payload.id) ? saves : creates).push({ payload, resolve }));
      }
      return Promise.resolve({ ok: true, json: async () => url.startsWith('/api/sequence-runs')
        ? structuredClone(history) : structuredClone([...remote.values()]) });
    },
    readApiErrorMessage: async () => 'Synthetic save failure', handleSequenceActionError: error => errors.push(error.message),
    showToast: (...args) => notices.push(args), setTimeout: () => 1, clearTimeout() {}, BUTTON_PROGRESS_DELAY_MS: 180, scheduleRefresh() {},
  });
  vm.runInContext(appSource.match(/^async function saveCurrentSequence\([^]*?^\}$/m)[0], c);
  for (const [name, promises] of [['saveCurrentSequence', savePromises], ['createNewSequence', newPromises],
    ['runCurrentSequence', runPromises], ['selectSequence', selections]]) {
    const actual = c[name]; c[name] = (...args) => { const promise = actual(...args); promises.push(promise); return promise; };
  }
  for (const event of ['input', 'change']) {
    const binding = appSource.match(new RegExp(`  document\\.getElementById\\("sequenceNameInput"\\)\\.addEventListener\\("${event}", updateSequenceNameFromInput\\);`));
    assert.ok(binding); vm.runInContext(binding[0], c);
  }
  for (const [id, handler] of [['saveSequenceButton', 'saveCurrentSequence'], ['newSequenceButton', 'createNewSequence']]) {
    const binding = appSource.match(new RegExp(`  onClickWithProgress\\(document\\.getElementById\\("${id}"\\), \\(\\) =>\\n    ${handler}\\(\\)\\.catch\\(handleSequenceActionError\\)\\);`));
    assert.ok(binding); vm.runInContext(binding[0], c);
  }
  vm.runInContext(appSource.match(/  document\.getElementById\("runSequenceButton"\)\.addEventListener\("click", \(\) => \{[^]*?\n  \}\);/)[0], c);
  c.renderSequencePanel();
  return { c, state, document, input, list, container, requests, saves, creates, runs, errors, notices, remote,
    savePromises, newPromises, runPromises, selections, card: () => cards[0],
    type(value, event = 'input') { input.value = value; input.focus(); input.selectionStart = 1; input.selectionEnd = 2; input.listeners[event](); },
    async click(id) { document.getElementById(id).listeners.click({}); await tick(); },
    async select(id) { const row = rows.find(row => row.dataset.seqId === id); row.control.focus(); row.click({ target: row.control }); await tick(); },
    async finishSave(index = 0, ok = true) { if (ok) remote.set(saves[index].payload.id, structuredClone(saves[index].payload)); saves[index].resolve({ ok }); await tick(); },
    async finishCreate() { remote.set(creates[0].payload.id, structuredClone(creates[0].payload)); creates[0].resolve({ ok: true }); await tick(); },
    async finishRun() { runs[0].resolve({ ok: true, json: async () => ({ id: 'new-run', sequence_id: 'a', sequence_name: remote.get('a').name,
      status: 'completed', step_results: [] }) }); await runPromises[0]; },
  };
}

function caret(f) { return { input: f.input, writes: f.input.valueWrites, start: f.input.selectionStart, end: f.input.selectionEnd, active: f.document.activeElement }; }
function sameCaret(f, before) {
  assert.equal(f.input, before.input); assert.equal(f.input.valueWrites, before.writes);
  assert.equal(f.input.selectionStart, before.start); assert.equal(f.input.selectionEnd, before.end); assert.equal(f.document.activeElement, before.active);
}

test('field is labelled, static outside step markup, unconstrained, and scoped to a wrapping header', () => {
  const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
  const editor = html.match(/<section class="panel-card sequence-editor-card">([^]*?)<\/section>/)[1];
  assert.match(editor, /<label[^>]*for="sequenceNameInput"[^>]*>\s*<span>Sequence name<\/span>/);
  const input = editor.match(/<input id="sequenceNameInput"[^>]*>/)[0];
  assert.doesNotMatch(input, /required|maxlength|pattern|autofocus/); assert.match(input, /type="text"/);
  assert.ok(editor.indexOf('sequenceNameInput') < editor.indexOf('</header>'));
  assert.ok(editor.indexOf('</header>') < editor.indexOf('sequenceStepsContainer'));
  assert.match(css, /\.sequence-editor-card > \.sequence-editor-header \{\s*flex-wrap: wrap;/);
  assert.match(css, /\.sequence-name-field \{[^]*?flex: 1 0 100%/);
  assert.match(css, /\.sequence-name-field input \{\s*box-sizing: border-box;\s*width: 100%/);
  assert.match(css, /\.sequence-editor-heading \{\s*flex: 1 1 0;\s*min-width: 0;/);
  assert.match(css, /\.sequence-editor-heading h2 \{[^]*?text-overflow: ellipsis;/);
  const list = css.match(/\.sequence-list-card \.seq-select \{([^]*?)\}/)[1];
  assert.match(list, /overflow-wrap: anywhere/); assert.doesNotMatch(list, /ellipsis|nowrap|overflow: hidden/);
});

test('no selection hides/disables the field and ignores input/change', () => {
  const f = fixture(); f.state.editingSequence = null; f.state.selectedSequenceId = null; f.c.renderSequencePanel();
  assert.equal(f.input.disabled, true); assert.equal(f.document.getElementById('sequenceNameField').classList.contains('hidden'), true);
  f.type('Ignored'); f.input.listeners.change(); assert.equal(f.state.editingSequence, null);
  assert.equal(f.state.sequenceDraftVersion, 0); assert.equal(f.requests.length, 0);
});

for (const event of ['input', 'change']) test(`${event} updates name/title only; later same-value event is a no-op`, () => {
  const f = fixture(); const step = f.state.editingSequence.steps[0], request = f.card().request;
  request.value = 'Unrelated DOM-only request'; const writes = f.container.writes;
  f.type('Renamed sequence', event);
  assert.equal(f.state.editingSequence.name, 'Renamed sequence'); assert.equal(f.state.sequenceDirty, true);
  assert.equal(f.state.sequenceDraftVersion, 1); assert.equal(f.document.getElementById('sequenceEditorTitle').textContent, 'Renamed sequence');
  assert.equal(f.container.writes, writes); assert.equal(f.card().request, request); assert.equal(request.value, 'Unrelated DOM-only request');
  assert.equal(step.label, 'Step label'); assert.match(step.request_text, /^GET/); assert.equal(f.requests.length, 0);
  f.input.listeners.input(); f.input.listeners.change(); assert.equal(f.state.sequenceDraftVersion, 1);
});

for (const raw of ['Login\r\nFlow', '\r\n', '  Login\nFlow  ']) test(`loaded ${JSON.stringify(raw)} survives projected no-op events, renders, and unrelated Save`, async () => {
  const f = fixture(raw); const projection = raw.replace(/[\r\n]/g, '');
  assert.equal(f.input.value, projection); f.input.focus(); f.input.selectionStart = 0; f.input.selectionEnd = 1;
  const before = caret(f); f.input.listeners.input(); f.input.listeners.change(); f.c.renderSequencePanel(); f.c.renderSequencePanel();
  assert.equal(f.state.editingSequence.name, raw); assert.equal(f.state.sequenceDraftVersion, 0); assert.equal(f.state.sequenceDirty, false); sameCaret(f, before);
  await f.click('saveSequenceButton'); assert.equal(f.saves[0].payload.name, raw); await f.finishSave(); assert.equal(await f.savePromises[0], true);
  assert.equal(f.state.editingSequence.name, raw); sameCaret(f, before);
  assert.equal(f.state.sequenceRunResult.sequence_name, raw); assert.equal(f.state.sequencePastRuns[0].sequence_name, raw);
});

for (const value of ['', '   ', '\t', '한글 📌', '  spaced  ', '<name "&">', 'Other name']) test(`Save preserves exact ${JSON.stringify(value)} without changing history or step labels`, async () => {
  const f = fixture(); f.type(value); const before = caret(f); await f.click('saveSequenceButton');
  assert.equal(f.saves[0].payload.id, 'a'); assert.equal(f.saves[0].payload.name, value);
  await f.finishSave(); assert.equal(await f.savePromises[0], true); assert.equal(f.state.editingSequence.name, value); sameCaret(f, before);
  const displayed = value.trim() ? value : 'Unnamed sequence';
  assert.equal(f.document.getElementById('sequenceEditorTitle').textContent, displayed);
  assert.equal(f.document.getElementById('sequenceEditorTitle').title, displayed);
  assert.ok(f.list.innerHTML.includes(f.c.escapeHtml(displayed)));
  if (!value.trim()) assert.match(f.list.innerHTML, /aria-label="Delete sequence Unnamed sequence"/);
  assert.equal(f.state.sequenceRunResult.sequence_name, 'Original name'); assert.equal(f.state.sequencePastRuns[0].sequence_name, 'Original name');
  assert.equal(f.state.editingSequence.steps[0].label, 'Step label'); assert.equal(f.input.value, value);
});

test('genuine visible edit intentionally replaces a loaded multiline name', () => {
  const f = fixture('Login\r\nFlow'); f.type('LoginFlow changed');
  assert.equal(f.state.editingSequence.name, 'LoginFlow changed'); assert.equal(f.state.sequenceDraftVersion, 1);
});

test('unchanged long name remains full in model/DOM/tooltip and does not reset active caret', () => {
  const name = 'Long name '.repeat(200); const f = fixture(name); f.input.focus(); f.input.selectionStart = 3; f.input.selectionEnd = 7;
  const before = caret(f); f.c.renderSequencePanel(); sameCaret(f, before);
  assert.equal(f.document.getElementById('sequenceEditorTitle').textContent, name);
  assert.equal(f.document.getElementById('sequenceEditorTitle').title, name); assert.equal(f.state.editingSequence.name, name);
});

test('pending Save cannot overwrite a newer name edit; the next Save persists the newer draft', async () => {
  const f = fixture(); f.type('First name'); await f.click('saveSequenceButton'); f.type('Later name'); const before = caret(f);
  await f.finishSave(); assert.equal(await f.savePromises[0], false); assert.equal(f.state.editingSequence.name, 'Later name');
  assert.equal(f.state.sequenceDirty, true); sameCaret(f, before);
  await f.click('saveSequenceButton'); assert.equal(f.saves[1].payload.name, 'Later name'); await f.finishSave(1);
  assert.equal(await f.savePromises[1], true); assert.match(f.list.innerHTML, />Later name<\/button>/); sameCaret(f, before);
});

test('existing backend failure preserves an over-limit draft instead of truncating or substituting it', async () => {
  const f = fixture(); const value = '한'.repeat(22000); assert.ok(Buffer.byteLength(value) > 64 * 1024);
  f.type(value); await f.click('saveSequenceButton'); assert.equal(f.saves[0].payload.name, value); await f.finishSave(0, false);
  await f.savePromises[0].catch(() => {}); assert.equal(f.state.editingSequence.name, value); assert.equal(f.input.value, value);
  assert.equal(f.state.sequenceDirty, true); assert.equal(f.errors.length, 1);
});

for (const ok of [true, false]) test(`navigation flush (${ok}) uses the name draft without a new write path`, async () => {
  const f = fixture(); f.type('Draft A name'); assert.equal(f.requests.length, 0); await f.select('b');
  assert.equal(f.saves.length, 1); assert.equal(f.saves[0].payload.name, 'Draft A name'); await f.finishSave(0, ok);
  await f.selections[0].catch(() => {});
  assert.equal(f.state.selectedSequenceId, ok ? 'b' : 'a'); assert.equal(f.input.value, ok ? 'Other name' : 'Draft A name');
  assert.equal(f.state.sequenceDirty, !ok); assert.equal(f.errors.length, ok ? 0 : 1);
});

test('session replacement during Save keeps the newly rendered name and subsequent input belongs to it', async () => {
  const f = fixture(); f.type('Session A draft'); await f.click('saveSequenceButton');
  f.state.activeSession = { id: 'session-b' }; f.state.selectedSequenceId = 'b';
  f.state.editingSequence = structuredClone(f.remote.get('b')); f.state.sequenceDirty = false; f.c.renderSequencePanel();
  f.type('Session B draft'); const before = caret(f); await f.finishSave(); assert.equal(await f.savePromises[0], false);
  assert.equal(f.state.editingSequence.id, 'b'); assert.equal(f.state.editingSequence.name, 'Session B draft'); sameCaret(f, before);
});

test('name edit supersedes pending New while list-only completion preserves name focus and selection', async () => {
  const f = fixture(); await f.click('newSequenceButton'); f.type('Newer name draft'); const before = caret(f);
  await f.finishCreate(); assert.equal(await f.newPromises[0], false); assert.equal(f.state.selectedSequenceId, 'a');
  assert.equal(f.state.editingSequence.name, 'Newer name draft'); assert.equal(f.state.sequenceDirty, true); sameCaret(f, before);
  assert.match(f.list.innerHTML, /data-seq-select="new-1"/); assert.equal(f.saves.length, 0);
});

test('name edit supersedes pending Run feedback without resetting the field on completion', async () => {
  const f = fixture(); await f.click('runSequenceButton'); await f.finishSave(); assert.equal(f.runs.length, 1);
  f.type('Newer run-era name'); const before = caret(f); await f.finishRun();
  assert.equal(f.state.sequenceRunResult.id, 'old-run'); assert.equal(f.state.sequenceRunning, false);
  assert.equal(f.state.editingSequence.name, 'Newer run-era name'); sameCaret(f, before);
});

test('projected same-value name events do not invalidate a current Run', async () => {
  const f = fixture('Name\r\nfrom API'); await f.click('runSequenceButton'); await f.finishSave();
  f.input.focus(); f.input.selectionStart = 1; f.input.selectionEnd = 4; const before = caret(f);
  f.input.listeners.input(); f.input.listeners.change(); assert.equal(f.state.sequenceDraftVersion, 0); await f.finishRun();
  assert.equal(f.state.sequenceRunResult.id, 'new-run'); assert.equal(f.state.editingSequence.name, 'Name\r\nfrom API'); sameCaret(f, before);
});

test('step label input remains independent of the sequence name field', () => {
  const f = fixture(); f.card().label.value = 'Renamed step'; f.container.listeners.input();
  assert.equal(f.state.editingSequence.steps[0].label, 'Renamed step'); assert.equal(f.state.editingSequence.name, 'Original name');
  assert.equal(f.input.value, 'Original name'); f.type('Renamed sequence');
  assert.equal(f.state.editingSequence.steps[0].label, 'Renamed step'); assert.equal(f.state.sequenceDraftVersion, 2);
});
