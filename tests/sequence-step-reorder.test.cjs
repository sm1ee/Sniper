// Actual rendered move controls and Save/New/Run bindings in a pure Node DOM.
// API responses are deferred in memory; no bootstrap, server, or target traffic.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));

function fixture(count = 3) {
  const steps = Array.from({ length: count }, (_, index) => ({ id: `step-${index + 1}`, label: `Label ${index + 1}`,
    request: { method: 'GET', path: `/${index + 1}` }, request_text: `GET /${index + 1} HTTP/1.1\r\nHost: example.com\r\n\r\n`,
    source_transaction_id: `source-${index + 1}`, target: { host: 'example.com', port: 443, use_tls: true },
    extractions: [{ variable_name: `token_${index + 1}`, source: 'response_body', pattern: '(.*)', group: 1 }] }));
  const definition = { id: 'a', name: 'Sequence A', steps };
  const remote = new Map([['a', structuredClone(definition)]]);
  const history = [{ sequence_id: 'a', sequence_name: 'Original A', status: 'completed', step_count: count, started_at: 'then' }];
  const state = { activeSession: { id: 'session-a' }, selectedSequenceId: 'a', editingSequence: structuredClone(definition),
    sequenceDefinitions: [structuredClone(definition)], sequencePastRuns: structuredClone(history),
    sequenceDirty: false, sequenceDraftVersion: 0, sequenceSelectionGeneration: 0, sequenceRunGeneration: 0,
    sequenceRunning: false, sequenceRunResult: { id: 'old-run', sequence_name: 'Original A', status: 'completed', step_results: [] } };
  const document = { body: {}, activeElement: null };
  document.activeElement = document.body;
  const node = () => ({ innerHTML: '', textContent: '', disabled: false, listeners: {},
    classList: { toggle() {}, add() {}, remove() {}, contains: () => false }, querySelectorAll: () => [],
    addEventListener(type, callback) { this.listeners[type] = callback; },
    focus() { document.activeElement = this; } });
  const field = (value, tagName = 'INPUT') => Object.assign(node(), { value, tagName,
    selectionStart: tagName === 'SELECT' ? undefined : 0, selectionEnd: tagName === 'SELECT' ? undefined : 0,
    selectionDirection: 'none', setSelectionRange(start, end, direction) {
      this.selectionStart = start; this.selectionEnd = end; this.selectionDirection = direction;
    } });
  const nodes = new Map();
  document.getElementById = id => nodes.get(id) || nodes.set(id, node()).get(id);
  const name = field('Sequence A'); nodes.set('sequenceNameInput', name);
  let cards = [];
  const container = node(); container.writes = 0;
  Object.defineProperty(container, 'innerHTML', { set(html) {
    this.markup = html; this.writes++;
    if (cards.some(card => [...card.fields, ...card.moves].includes(document.activeElement))) document.activeElement = document.body;
    cards = [...html.matchAll(/<div class="sequence-step-card"[^]*?(?=<div class="sequence-step-card"|$)/g)].map(match => {
      const markup = match[0], id = markup.match(/data-step-id="([^"]+)"/)[1];
      const step = state.editingSequence.steps.find(step => step.id === id);
      const label = field(step.label), request = field(step.request_text, 'TEXTAREA');
      const rows = step.extractions.map(rule => {
        const fields = { '.ext-var': field(rule.variable_name), '.ext-source': field(rule.source, 'SELECT'), '.ext-pattern': field(rule.pattern) };
        return { fields, querySelector: selector => fields[selector] };
      });
      const fields = [label, request, ...rows.flatMap(row => Object.values(row.fields))];
      const moves = [...markup.matchAll(/<button class="step-move"([^>]+)>/g)].map(match => {
        const attrs = match[1];
        return Object.assign(node(), { tagName: 'BUTTON', attrs,
          dataset: { moveStep: attrs.match(/data-move-step="([^"]+)"/)[1], moveDirection: attrs.match(/data-move-direction="([^"]+)"/)[1] },
          unavailable: attrs.match(/aria-disabled="([^"]+)"/)[1] === 'true' });
      });
      const details = { open: /<details[^>]*\bopen\b/.test(markup) };
      return { dataset: { stepId: id }, label, request, rows, fields, moves, details, markup,
        querySelector(selector) {
          if (selector === '.step-label') return label;
          if (selector === '.step-request-text') return request;
          if (selector === '.step-extractions') return details;
          const direction = selector.match(/^\.step-move\[data-move-direction="(-?1)"\]$/)?.[1];
          return moves.find(button => button.dataset.moveDirection === direction);
        },
        querySelectorAll: selector => selector === 'input, textarea, select' ? fields
          : selector === '.extraction-row' ? rows : [] };
    });
  } });
  container.querySelectorAll = selector => selector === '.sequence-step-card' ? cards : selector === '.step-move' ? cards.flatMap(card => card.moves) : [];
  nodes.set('sequenceStepsContainer', container);
  const requests = [], saves = [], creates = [], runs = [], errors = [], notices = [];
  const savePromises = [], newPromises = [], runPromises = [];
  let uuid = 0;
  const c = loadFunctions(['moveSequenceStep', 'renderSequencePanel', 'renderSequenceList', 'sequenceDisplayName', 'sequenceNameInputValue',
    'syncSequenceRunButton', 'normalizeSequenceRunResult', 'markSequenceDraftDirty', 'bumpSequenceDraftVersion', 'syncSequenceStepFromDom',
    'currentSequenceSessionId', 'isCurrentSequenceSession', 'sequenceSessionPath', 'loadSequences', 'flushSequenceDraft', 'createNewSequence',
    'runCurrentSequence', 'isCurrentSequenceRun', 'onClickWithProgress', 'withButtonProgress', 'requireOkResponse', 'escapeHtml'], {
    state, document, currentSessionId: () => state.activeSession.id, workspaceStateGeneration: 1,
    expectedActiveSessionIdForWrite: id => id, generateUuid: () => `new-${++uuid}`,
    jsonArray: value => Array.isArray(value) ? value : [], formatTimestamp: String, normalizeReplayHttpVersion: () => '',
    replayHttpVersionFromText: () => '', parseEditableRawRequest(text) {
      if (text.startsWith('invalid')) throw new Error('Invalid request');
      return { path: text.split(' ')[1] };
    },
    fetch(url, options = {}) {
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
  for (const [name, promises] of [['saveCurrentSequence', savePromises], ['createNewSequence', newPromises], ['runCurrentSequence', runPromises]]) {
    const actual = c[name]; c[name] = (...args) => { const promise = actual(...args); promises.push(promise); return promise; };
  }
  for (const [id, handler] of [['saveSequenceButton', 'saveCurrentSequence'], ['newSequenceButton', 'createNewSequence']]) {
    const binding = appSource.match(new RegExp(`  onClickWithProgress\\(document\\.getElementById\\("${id}"\\), \\(\\) =>\\n    ${handler}\\(\\)\\.catch\\(handleSequenceActionError\\)\\);`));
    assert.ok(binding); vm.runInContext(binding[0], c);
  }
  vm.runInContext(appSource.match(/  document\.getElementById\("runSequenceButton"\)\.addEventListener\("click", \(\) => \{[^]*?\n  \}\);/)[0], c);
  c.renderSequencePanel();
  return { c, state, document, name, container, remote, requests, saves, creates, runs, errors, notices,
    savePromises, newPromises, runPromises, cards: () => cards,
    move(index, direction, focus = true) {
      const button = cards[index].moves.find(button => Number(button.dataset.moveDirection) === direction);
      if (focus) button.focus(); button.listeners.click();
    },
    async click(id) { const button = document.getElementById(id); button.focus(); button.listeners.click({}); await tick(); },
    async finishSave(index = 0, ok = true) {
      if (ok) remote.set(saves[index].payload.id, structuredClone(saves[index].payload));
      saves[index].resolve({ ok }); await tick();
    },
    async finishCreate() { remote.set(creates[0].payload.id, structuredClone(creates[0].payload)); creates[0].resolve({ ok: true }); await tick(); },
    async finishRun() {
      runs[0].resolve({ ok: true, json: async () => ({ id: 'new-run', sequence_name: 'Sequence A', status: 'completed', step_results: [] }) });
      await runPromises[0];
    },
  };
}

const ids = f => Array.from(f.state.editingSequence.steps, step => step.id);
const range = field => [field.selectionStart, field.selectionEnd, field.selectionDirection];

test('each step has named native move buttons with focusable aria-disabled boundaries and neutral focus styling', () => {
  const f = fixture();
  f.cards().forEach((card, index) => card.moves.forEach((button, directionIndex) => {
    const direction = directionIndex ? 'down' : 'up';
    assert.match(button.attrs, /type="button"/);
    assert.match(button.attrs, new RegExp(`aria-label="Move step ${index + 1} ${direction}"`));
    assert.doesNotMatch(button.attrs, /(?:^|\s)disabled(?:\s|=|$)|tabindex/);
    assert.equal(button.unavailable, directionIndex ? index === 2 : index === 0);
  }));
  const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
  assert.match(css, /\.step-move:focus-visible\s*\{[^}]*outline:/);
  assert.match(css, /\.step-move\[aria-disabled="true"\]\s*\{[^}]*cursor: not-allowed/);
  assert.match(css, /\.step-move:not\(\[aria-disabled="true"\]\):hover\s*\{[^}]*color: var\(--accent\)/);
  assert.match(css, /\.step-header input\s*\{[^}]*min-width: 0/);
});

for (const [index, direction, expected] of [[1, -1, ['step-2', 'step-1', 'step-3']], [1, 1, ['step-1', 'step-3', 'step-2']]]) {
  test(`actual move binding ${direction} moves the whole step once, with expansion and drafts intact`, () => {
    const f = fixture(), moved = f.state.editingSequence.steps[index];
    const extraction = moved.extractions[0], target = moved.target, request = moved.request;
    const history = JSON.stringify(f.state.sequencePastRuns), run = f.state.sequenceRunResult;
    f.cards()[index].label.value = 'Unsaved label'; f.cards()[index].request.value = 'invalid raw draft <>&';
    f.cards()[index].rows[0].fields['.ext-var'].value = 'unsaved_token';
    f.cards()[index].rows[0].fields['.ext-source'].value = 'response_header';
    f.cards()[index].rows[0].fields['.ext-pattern'].value = 'unsaved_pattern';
    f.cards()[index].details.open = true;
    f.cards()[0].request.value = 'invalid other draft';
    f.move(index, direction);
    assert.deepEqual(ids(f), expected); assert.equal(f.state.editingSequence.steps[index + direction], moved);
    assert.equal(moved.label, 'Unsaved label'); assert.equal(moved.request_text, 'invalid raw draft <>&');
    assert.equal(moved.request_parse_error, 'Invalid request'); assert.equal(moved.request, request);
    assert.equal(moved.target, target); assert.equal(moved.source_transaction_id, 'source-2');
    assert.equal(moved.extractions[0], extraction); assert.equal(extraction.variable_name, 'unsaved_token'); assert.equal(extraction.pattern, 'unsaved_pattern');
    assert.equal(extraction.source, 'response_header');
    assert.equal(f.state.editingSequence.steps.find(step => step.id === 'step-1').request_text, 'invalid other draft');
    assert.equal(f.cards()[index + direction].details.open, true);
    assert.equal(f.state.sequenceDirty, true); assert.equal(f.state.sequenceDraftVersion, 1); assert.equal(f.requests.length, 0);
    assert.equal(f.state.sequenceRunResult.id, run.id); assert.equal(JSON.stringify(f.state.sequencePastRuns), history);
  });
}

for (const args of [[0, -1], [2, 1], [-1, 1], [3, -1], [0.5, 1], [NaN, 1], ['0', 1], [0, 0], [0, 2], [0, '1']]) {
  test(`invalid/boundary move ${JSON.stringify(args)} is a strict no-op before sync, dirty, or render`, () => {
    const f = fixture(), first = f.cards()[0]; first.request.value = 'invalid DOM-only draft';
    const before = JSON.stringify(f.state), writes = f.container.writes;
    assert.equal(f.c.moveSequenceStep(...args), false);
    assert.equal(JSON.stringify(f.state), before); assert.equal(f.container.writes, writes);
    assert.equal(f.cards()[0], first); assert.equal(first.request.value, 'invalid DOM-only draft'); assert.equal(f.requests.length, 0);
  });
}

test('one-step boundaries and no current sequence cannot move or dirty the draft', () => {
  const f = fixture(1); assert.ok(f.cards()[0].moves.every(button => button.unavailable));
  f.move(0, -1); f.move(0, 1); assert.equal(f.state.sequenceDraftVersion, 0); assert.equal(f.state.sequenceDirty, false);
  f.state.editingSequence = null; assert.equal(f.c.moveSequenceStep(0, 1), false); assert.equal(f.requests.length, 0);
});

for (const direction of [-1, 1]) for (const key of ['Enter', 'Space']) test(`repeated ${key}-equivalent native button clicks (${direction}) retain same action at the boundary without typing/reversing`, () => {
  const f = fixture(); f.move(direction === -1 ? 2 : 0, direction);
  let focused = f.document.activeElement;
  assert.equal(focused.tagName, 'BUTTON'); assert.equal(focused.dataset.moveDirection, String(direction)); assert.equal(focused.dataset.moveStep, '1');
  focused.listeners.click(); focused = f.document.activeElement;
  assert.equal(focused.tagName, 'BUTTON'); assert.equal(focused.dataset.moveDirection, String(direction)); assert.equal(focused.dataset.moveStep, direction === -1 ? '0' : '2');
  assert.equal(focused.unavailable, true);
  const before = JSON.stringify(f.state), writes = f.container.writes;
  for (let repeat = 0; repeat < 3; repeat++) f.document.activeElement.listeners.click();
  assert.equal(f.document.activeElement, focused); assert.equal(JSON.stringify(f.state), before); assert.equal(f.container.writes, writes);
  assert.deepEqual(ids(f), direction === -1 ? ['step-3', 'step-1', 'step-2'] : ['step-2', 'step-3', 'step-1']);
});

test('all stored text ranges follow stable IDs while keyboard focus remains on the moved action', () => {
  const f = fixture();
  f.cards().forEach(card => card.fields.forEach(field => {
    if (field.tagName !== 'SELECT') field.setSelectionRange(1, 3, 'backward');
  }));
  f.move(1, -1);
  f.cards().forEach(card => card.fields.forEach(field => {
    if (field.tagName !== 'SELECT') assert.deepEqual(range(field), [1, 3, 'backward']);
  }));
  assert.equal(f.document.activeElement, f.cards()[0].moves[0]);
});

test('mouse activation that genuinely retains prior textarea focus restores its range by step ID', () => {
  const f = fixture(), prior = f.cards()[2].request;
  prior.focus(); prior.setSelectionRange(2, 5, 'forward'); f.move(2, -1, false);
  assert.equal(f.document.activeElement, f.cards()[1].request); assert.deepEqual(range(f.cards()[1].request), [2, 5, 'forward']);
  assert.equal(f.cards()[1].dataset.stepId, 'step-3');
});

test('static Sequence name focus/range is untouched when mouse activation leaves it focused', () => {
  const f = fixture(); f.name.focus(); f.name.setSelectionRange(1, 4, 'backward'); f.move(1, -1, false);
  assert.equal(f.document.activeElement, f.name); assert.deepEqual(range(f.name), [1, 4, 'backward']); assert.equal(f.name.value, 'Sequence A');
});

test('explicit Save serializes new order and invalid drafts through the existing endpoint only', async () => {
  const f = fixture(); f.cards()[1].request.value = 'invalid retained request'; f.move(1, -1);
  assert.equal(f.requests.length, 0); await f.click('saveSequenceButton');
  assert.deepEqual(f.saves[0].payload.steps.map(step => step.id), ['step-2', 'step-1', 'step-3']);
  assert.equal(f.saves[0].payload.steps[0].request_text, 'invalid retained request');
  assert.equal(f.saves[0].payload.steps[0].request_parse_error, 'Invalid request');
  assert.equal(f.requests[0].url, '/api/sequences'); await f.finishSave();
  assert.equal(await f.savePromises[0], true); assert.deepEqual(ids(f), ['step-2', 'step-1', 'step-3']); assert.equal(f.state.sequenceDirty, false);
});

test('a pending older Save cannot replace a newer move; next explicit Save persists it', async () => {
  const f = fixture(); await f.click('saveSequenceButton'); f.move(1, -1);
  const active = f.document.activeElement; await f.finishSave();
  assert.equal(await f.savePromises[0], false); assert.deepEqual(ids(f), ['step-2', 'step-1', 'step-3']);
  assert.equal(f.state.sequenceDirty, true); assert.equal(f.document.activeElement, active);
  await f.click('saveSequenceButton'); assert.deepEqual(f.saves[1].payload.steps.map(step => step.id), ids(f)); await f.finishSave(1);
  assert.equal(await f.savePromises[1], true);
});

test('pending New creation retains newer move and action focus while listing its successful creation', async () => {
  const f = fixture(); await f.click('newSequenceButton'); f.move(1, -1);
  const active = f.document.activeElement; await f.finishCreate();
  assert.equal(await f.newPromises[0], false); assert.deepEqual(ids(f), ['step-2', 'step-1', 'step-3']);
  assert.equal(f.state.selectedSequenceId, 'a'); assert.equal(f.state.sequenceDirty, true); assert.equal(f.document.activeElement, active);
  assert.match(f.document.getElementById('sequenceListBody').innerHTML, /data-seq-select="new-1"/); assert.equal(f.saves.length, 0);
});

test('move during New draft flush prevents creation after the older Save settles', async () => {
  const f = fixture(); f.c.markSequenceDraftDirty(); await f.click('newSequenceButton'); f.move(1, -1);
  await f.finishSave(); assert.equal(await f.newPromises[0], false); assert.equal(f.creates.length, 0);
  assert.deepEqual(ids(f), ['step-2', 'step-1', 'step-3']); assert.equal(f.state.sequenceDirty, true);
});

test('move during Run preflight Save prevents sending the older order', async () => {
  const f = fixture(); await f.click('runSequenceButton'); f.move(1, -1); const active = f.document.activeElement;
  await f.finishSave(); await f.runPromises[0]; assert.equal(f.runs.length, 0); assert.equal(f.state.sequenceRunning, false);
  assert.deepEqual(ids(f), ['step-2', 'step-1', 'step-3']); assert.equal(f.state.sequenceDirty, true); assert.equal(f.document.activeElement, active);
});

test('move supersedes pending Run feedback without changing historical results or repainting controls', async () => {
  const f = fixture(); await f.click('runSequenceButton'); await f.finishSave(); assert.equal(f.runs.length, 1);
  f.move(1, -1); const active = f.document.activeElement, writes = f.container.writes; await f.finishRun();
  assert.equal(f.state.sequenceRunResult.id, 'old-run'); assert.equal(f.state.sequenceRunning, false);
  assert.deepEqual(ids(f), ['step-2', 'step-1', 'step-3']); assert.equal(f.document.activeElement, active); assert.equal(f.container.writes, writes);
});
