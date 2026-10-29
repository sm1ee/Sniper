// Production Sequence input/Run/Save/reorder paths in an inert DOM. Requests are
// controlled in memory: no bootstrap, native app, server or sequence execution.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
const decode = value => value.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
const valid = 'GET /saved HTTP/1.1\r\nHost: example.com\r\n\r\n';
function fixture({ labels = ['Start', 'Sign in', 'Finish'], invalid = [1], storedError = false } = {}) {
  const steps = labels.map((label, index) => ({ id: `step-${index}`, label,
    request: { scheme: 'https', host: 'example.com', method: 'GET', path: '/saved', headers: [], body: '', body_encoding: 'utf8' },
    request_text: invalid.includes(index) ? 'GET' : valid,
    ...(storedError && invalid.includes(index) ? { request_parse_error: 'Invalid request line in editor' } : {}),
    extractions: [{ variable_name: `token_${index}`, source: 'response_body', pattern: '(.*)', group: 1 }] }));
  const definition = { id: 'draft', name: 'Three-step flow', steps };
  const state = { activeSession: { id: 'session-a' }, selectedSequenceId: 'draft', editingSequence: structuredClone(definition),
    sequenceDefinitions: [structuredClone(definition)], sequencePastRuns: [], sequenceRunResult: null,
    sequenceRunGeneration: 4, sequenceDraftVersion: 2, sequenceRunning: false, sequenceDirty: true };
  const document = { body: {}, activeElement: null }; document.activeElement = document.body;
  const nodes = new Map(), requests = [], notices = [], promises = [], saves = [], scrolls = [];
  let cards = [], c, uuid = 0;
  function node() {
    const classes = new Set(), attrs = {};
    return { textContent: '', listeners: {}, disabled: false, attrs, focusCalls: [], scrollCalls: [],
      classList: { add: value => classes.add(value), remove: value => classes.delete(value), contains: value => classes.has(value),
        toggle(value, on = !classes.has(value)) { if (on) classes.add(value); else classes.delete(value); } },
      querySelectorAll: () => [], setAttribute: (key, value) => { attrs[key] = String(value); },
      getAttribute: key => attrs[key] ?? null, removeAttribute: key => { delete attrs[key]; },
      addEventListener(type, callback) { this.listeners[type] = callback; },
      focus(options) { this.focusCalls.push(options); document.activeElement = this; },
      scrollIntoView(options) { this.scrollCalls.push(options); scrolls.push(this); },
      click() { if (!this.disabled) { this.focus(); this.listeners.click?.({}); } } };
  }
  function field(value, tagName = 'INPUT') {
    return Object.assign(node(), { value, tagName, selectionStart: 1, selectionEnd: 2, selectionDirection: 'backward',
      setSelectionRange(start, end, direction) { this.selectionStart = start; this.selectionEnd = end; this.selectionDirection = direction; } });
  }
  document.getElementById = id => nodes.get(id) || nodes.set(id, node()).get(id);
  const name = field(definition.name); nodes.set('sequenceNameInput', name);
  const container = node(); container.writes = 0; nodes.set('sequenceStepsContainer', container);
  Object.defineProperty(container, 'innerHTML', { get() { return this.markup; }, set(html) {
    this.markup = html; this.writes++;
    if (cards.some(card => [...card.fields, ...card.moves].includes(document.activeElement))) document.activeElement = document.body;
    cards = [...html.matchAll(/<div class="sequence-step-card"[^]*?(?=<div class="sequence-step-card"|$)/g)].map(match => {
      const markup = match[0], id = decode(markup.match(/data-step-id="([^"]+)"/)[1]);
      const step = state.editingSequence.steps.find(step => step.id === id);
      const requestMatch = markup.match(/<textarea class="step-request-text"([^>]*)>([^]*?)<\/textarea>/);
      const request = field(decode(requestMatch[2]), 'TEXTAREA'), label = field(step.label);
      for (const [, key, value] of requestMatch[1].matchAll(/(aria-[\w-]+)="([^"]*)"/g)) request.setAttribute(key, decode(value));
      const errorMatch = markup.match(/<p class="step-request-error([^"<]*)"([^>]*)>([^]*?)<\/p>/);
      const error = errorMatch ? node() : null;
      if (error) { error.textContent = decode(errorMatch[3]); error.classList.toggle('hidden', errorMatch[1].includes('hidden'));
        error.id = errorMatch[2].match(/id="([^"]+)"/)?.[1]; }
      const rows = step.extractions.map(rule => {
        const fields = { '.ext-var': field(rule.variable_name), '.ext-source': field(rule.source, 'SELECT'), '.ext-pattern': field(rule.pattern) };
        return { fields, querySelector: selector => fields[selector] };
      });
      const fields = [label, request, ...rows.flatMap(row => Object.values(row.fields))];
      const moves = [...markup.matchAll(/<button class="step-move"([^>]+)>/g)].map(match => {
        const attrs = match[1]; return Object.assign(node(), { dataset: {
          moveStep: attrs.match(/data-move-step="([^"]+)"/)[1], moveDirection: attrs.match(/data-move-direction="([^"]+)"/)[1] } });
      });
      const details = { open: /<details[^>]*\bopen\b/.test(markup) };
      return { dataset: { stepId: id }, request, label, error, rows, fields, moves, details, markup,
        querySelector(selector) {
          if (selector === '.step-request-text') return request;
          if (selector === '.step-label') return label;
          if (selector === '.step-request-error') return error;
          if (selector === '.step-extractions') return details;
          const direction = selector.match(/^\.step-move\[data-move-direction="(-?1)"\]$/)?.[1];
          return moves.find(button => button.dataset.moveDirection === direction) || null;
        }, querySelectorAll: selector => selector === '.extraction-row' ? rows : selector === 'input, textarea, select' ? fields : [] };
    });
  } });
  container.querySelectorAll = selector => selector === '.sequence-step-card' ? cards
    : selector === '.step-move' ? cards.flatMap(card => card.moves) : [];
  const names = ['renderSequencePanel', 'sequenceDisplayName', 'sequenceNameInputValue', 'updateSequenceNameFromInput',
    'syncSequenceRunButton', 'normalizeSequenceRunResult', 'addSequenceStep', 'moveSequenceStep', 'markSequenceDraftDirty',
    'bumpSequenceDraftVersion', 'syncSequenceStepFromDom', 'currentSequenceSessionId', 'isCurrentSequenceSession',
    'isCurrentSequenceRun', 'runCurrentSequence', 'buildEditableRawRequest', 'parseEditableRawRequest', 'splitRawHttpMessage',
    'normalizeReplayHttpVersion', 'replayHttpVersionFromText', 'parseReplayHttpVersionToken', 'headerValue', 'normalizedHeaders',
    'mergeHeaders', 'headerNameEquals', 'editableRequestBodyLength', 'validateRawHttpBodyFraming', 'escapeHtml',
    'onClickWithProgress', 'withButtonProgress'];
  if (/^function sequenceRequestErrorMessage\(/m.test(appSource)) names.push('sequenceRequestErrorMessage');
  c = loadFunctions(names, { state, document, TextEncoder, URL, workspaceLoaded: true, workspaceStateGeneration: 1,
    currentSessionId: () => state.activeSession.id, expectedActiveSessionIdForWrite: id => id,
    generateUuid: () => `added-${++uuid}`, renderSequenceList() {}, jsonArray: value => Array.isArray(value) ? value : [],
    formatTimestamp: String, showToast: message => notices.push(message), scheduleRefresh() {},
    requireOkResponse: async response => { if (!response.ok) throw new Error('Synthetic save failure'); },
    readApiErrorMessage: async response => response.text(), handleSequenceActionError: error => notices.push(error.message),
    loadSequences: async () => { if (saves.length) state.sequenceDefinitions = [structuredClone(saves.at(-1))]; return true; },
    setTimeout: () => 1, clearTimeout() {}, BUTTON_PROGRESS_DELAY_MS: 180,
    fetch(url, options) {
      assert.ok(url === '/api/sequences' || url === '/api/sequences/draft/run');
      assert.equal(options.method, 'POST', 'Only explicitly intercepted in-memory Save/Run controls are allowed.');
      const payload = JSON.parse(options.body); if (url === '/api/sequences') saves.push(payload);
      return new Promise((resolve, reject) => requests.push({ url, payload, resolve, reject }));
    },
  });
  vm.runInContext(appSource.match(/^async function saveCurrentSequence\([^]*?^\}$/m)[0], c);
  for (const name of ['runCurrentSequence', 'saveCurrentSequence']) {
    const original = c[name]; c[name] = (...args) => { const pending = original(...args); promises.push(pending); return pending; };
  }
  vm.runInContext(appSource.match(/  document\.getElementById\("addSequenceStepButton"\)\.addEventListener\("click", addSequenceStep\);/)[0], c);
  vm.runInContext(appSource.match(/  document\.getElementById\("runSequenceButton"\)\.addEventListener\("click", \(\) => \{[^]*?\n  \}\);/)[0], c);
  vm.runInContext(appSource.match(/  onClickWithProgress\(document\.getElementById\("saveSequenceButton"\), \(\) =>\n    saveCurrentSequence\(\)\.catch\(handleSequenceActionError\)\);/)[0], c);
  vm.runInContext(appSource.match(/  document\.getElementById\("sequenceNameInput"\)\.addEventListener\("input", updateSequenceNameFromInput\);/)[0], c);
  c.renderSequencePanel();
  async function run() { document.getElementById('runSequenceButton').click(); await tick(); }
  async function finishSave(ok = true) { requests.find(request => request.url === '/api/sequences').resolve({ ok }); await tick(); }
  return { c, state, document, name, container, nodes, requests, notices, promises, saves, scrolls, cards: () => cards, run, finishSave,
    type(index, value) { cards[index].request.value = value; container.listeners.input(); },
    move(index, direction) { cards[index].moves.find(button => Number(button.dataset.moveDirection) === direction).click(); } };
}
const range = field => [field.selectionStart, field.selectionEnd, field.selectionDirection];
function assertInvalid(card, ordinal, label, reason = 'Invalid request line in editor') {
  const message = `Step ${ordinal}${label.trim() ? ` (${label.trim()})` : ''} raw HTTP request: ${reason}`;
  assert.equal(card.error?.textContent, message); assert.equal(card.error.classList.contains('hidden'), false);
  assert.equal(card.request.getAttribute('aria-invalid'), 'true');
  assert.equal(card.request.getAttribute('aria-describedby'), card.error.id);
  return message;
}
for (const label of ['Sign in', '', '   ', 'Same', '<img src=x onerror="bad()"> & "quoted"', '한글 📌']) {
  test(`local preflight identifies current numbered ${JSON.stringify(label)} step without replacing field or caret`, async () => {
    const f = fixture({ labels: ['Same', label, 'Same'] }), card = f.cards()[1], before = range(card.request), writes = f.container.writes;
    const generation = f.state.sequenceRunGeneration, prior = JSON.stringify(f.state.sequenceRunResult);
    await f.run();
    assert.equal(f.cards()[1], card); assert.equal(f.container.writes, writes); assert.equal(f.document.activeElement, card.request);
    assert.deepEqual(range(card.request), before); assert.equal(f.requests.length, 0);
    assert.equal(f.state.sequenceRunGeneration, generation); assert.equal(f.state.sequenceRunning, false);
    assert.equal(JSON.stringify(f.state.sequenceRunResult), prior); assert.equal(f.nodes.get('runSequenceButton').disabled, false);
    const message = assertInvalid(card, 2, label); assert.deepEqual(f.notices, [`Sequence error: ${message}`]);
    assert.equal(f.state.editingSequence.steps[1].request_parse_error, 'Invalid request line in editor');
  });
}
test('repeated invalid Run keeps exact node/range and does not dispatch or multiply inline regions', async () => {
  const f = fixture(), card = f.cards()[1], error = card.error, writes = f.container.writes;
  for (let i = 0; i < 3; i++) { await f.run(); assert.equal(f.cards()[1], card); assert.equal(card.error, error); assert.deepEqual(range(card.request), [1, 2, 'backward']); }
  assert.equal(f.container.writes, writes); assert.equal(f.requests.length, 0); assert.equal(f.notices.length, 3);
});
test('multiple invalid steps sync all drafts and focus the first; correction exposes the next failing step', async () => {
  const f = fixture({ invalid: [0, 2] }), beforeCards = [...f.cards()];
  f.cards()[2].request.value = 'POST'; f.cards()[2].label.value = 'Later edited label';
  f.cards()[2].rows[0].fields['.ext-var'].value = 'new_token'; f.cards()[2].rows[0].fields['.ext-pattern'].value = '(new)';
  await f.run(); assert.equal(f.document.activeElement, beforeCards[0].request);
  assertInvalid(f.cards()[0], 1, 'Start'); assertInvalid(f.cards()[2], 3, 'Later edited label');
  assert.equal(f.state.editingSequence.steps[2].request_text, 'POST');
  assert.equal(f.state.editingSequence.steps[2].extractions[0].variable_name, 'new_token');
  assert.equal(f.state.editingSequence.steps[2].extractions[0].pattern, '(new)');
  f.type(0, valid); await f.run(); assert.equal(f.document.activeElement, beforeCards[2].request);
  assert.match(f.notices.at(-1), /^Sequence error: Step 3 \(Later edited label\)/); assert.equal(f.requests.length, 0);
});
test('corrected input clears inline/ARIA error without repaint or focus, then valid Run saves and runs once', async () => {
  const f = fixture(); await f.run(); const card = f.cards()[1], writes = f.container.writes;
  f.name.focus(); f.type(1, valid);
  assert.equal(f.cards()[1], card); assert.equal(f.container.writes, writes); assert.equal(f.document.activeElement, f.name);
  assert.equal(card.error?.textContent, ''); assert.equal(card.error.classList.contains('hidden'), true);
  assert.equal(card.request.getAttribute('aria-invalid'), 'false'); assert.equal(f.state.editingSequence.steps[1].request_parse_error, undefined);
  await f.run(); assert.equal(f.requests.length, 1); assert.equal(f.requests[0].url, '/api/sequences');
  assert.equal(f.state.sequenceRunning, true); await f.finishSave();
  assert.equal(f.requests.length, 2); assert.equal(f.requests[1].url, '/api/sequences/draft/run');
  f.requests[1].resolve({ ok: true, json: async () => ({ sequence_name: 'Three-step flow', status: 'completed', step_results: [] }) });
  await Promise.all(f.promises); assert.equal(f.state.sequenceRunning, false); assert.equal(f.nodes.get('runSequenceButton').disabled, false);
});
test('lenient input and Save preserve invalid drafts without showing/focusing errors before Run', async () => {
  const f = fixture({ storedError: true }), card = f.cards()[1];
  assert.equal(card.error?.textContent || '', ''); assert.notEqual(card.request.getAttribute('aria-invalid'), 'true');
  f.name.focus(); f.type(1, 'POST'); assert.equal(f.document.activeElement, f.name); assert.equal(card.error?.textContent || '', '');
  f.nodes.get('saveSequenceButton').click(); await tick();
  assert.equal(f.requests.length, 1); assert.equal(f.saves[0].steps[1].request_text, 'POST');
  assert.equal(f.saves[0].steps[1].request_parse_error, 'Invalid request line in editor');
  await f.finishSave(); await Promise.all(f.promises); assert.equal(f.notices.length, 0);
  assert.equal(f.cards()[1].error?.textContent || '', ''); assert.equal(f.document.activeElement, f.nodes.get('saveSequenceButton'));
});
test('draft name, later request, label and extraction fields survive invalid preflight untouched', async () => {
  const f = fixture(), cards = [...f.cards()], nameRange = range(f.name);
  f.name.value = '  Unsaved name <&>  '; f.name.listeners.input();
  cards[2].request.value = 'GET /later HTTP/1.1\nHost: example.com'; cards[2].label.value = 'Later label';
  cards[2].rows[0].fields['.ext-source'].value = 'response_header'; cards[2].rows[0].fields['.ext-pattern'].value = 'x-session';
  await f.run(); assert.equal(f.name.value, '  Unsaved name <&>  '); assert.deepEqual(range(f.name), nameRange);
  assert.equal(f.state.editingSequence.name, f.name.value); assert.equal(f.cards()[2], cards[2]);
  assert.equal(f.state.editingSequence.steps[2].request_text, cards[2].request.value);
  assert.equal(f.state.editingSequence.steps[2].label, 'Later label');
  assert.equal(f.state.editingSequence.steps[2].extractions[0].source, 'response_header');
  assert.equal(f.state.editingSequence.steps[2].extractions[0].pattern, 'x-session'); assert.equal(f.requests.length, 0);
});
test('shown error follows stable step identity through actual reorder with the new ordinal', async () => {
  const f = fixture(); await f.run(); f.move(1, -1);
  assert.equal(f.cards()[0].dataset.stepId, 'step-1'); assertInvalid(f.cards()[0], 1, 'Sign in');
  const moved = f.cards()[0]; await f.run(); assert.equal(f.cards()[0], moved); assert.equal(f.document.activeElement, moved.request);
  assert.match(f.notices.at(-1), /^Sequence error: Step 1 \(Sign in\)/); assert.equal(f.requests.length, 0);
});
for (const boundary of ['session', 'sequence']) test(`${boundary} cannot inherit shown errors from reused step IDs`, async () => {
  const f = fixture(); await f.run();
  if (boundary === 'session') f.state.activeSession = { id: 'session-b' }; else f.state.editingSequence.id = 'other';
  f.c.renderSequencePanel(); assert.equal(f.cards()[1].error?.textContent || '', '');
  assert.notEqual(f.cards()[1].request.getAttribute('aria-invalid'), 'true');
});
test('a fresh Add Step identifies missing Host; a saved request retains the existing host fallback', async () => {
  const f = fixture({ invalid: [] }); f.nodes.get('addSequenceStepButton').click();
  const card = f.cards()[3]; assert.equal(card.request.value, 'GET / HTTP/1.1'); await f.run();
  assertInvalid(card, 4, 'Step 4', 'Request is missing a Host header'); assert.equal(f.requests.length, 0);
  f.type(3, valid); f.type(1, 'GET /no-host-line HTTP/1.1');
  assert.equal(f.state.editingSequence.steps[1].request.host, 'example.com'); assert.equal(f.state.editingSequence.steps[1].request_parse_error, undefined);
});
test('shown errors update safely after label/request edits and render as escaped text', async () => {
  const f = fixture(); await f.run(); const card = f.cards()[1];
  card.label.value = '<b>"new" & label</b>'; f.type(1, 'GET / HTTP/9');
  assertInvalid(card, 2, card.label.value, 'Unsupported HTTP version: HTTP/9');
  f.c.renderSequencePanel(); const html = f.container.markup;
  assert.match(html, /Step 2 \(&lt;b&gt;&quot;new&quot; &amp; label&lt;\/b&gt;\)/); assert.doesNotMatch(html, /<b>"new"/);
});
for (const failure of ['save', 'run']) test(`stale async ${failure} failure never focuses an old invalid field`, async () => {
  const f = fixture({ invalid: [] }); await f.run();
  if (failure === 'run') await f.finishSave();
  f.state.selectedSequenceId = 'other'; f.state.editingSequence = { id: 'other', name: 'Other', steps: [] };
  f.c.renderSequencePanel(); f.name.focus(); const writes = f.container.writes;
  f.requests.at(-1).reject(new Error('Synthetic obsolete failure')); await Promise.allSettled(f.promises);
  assert.equal(f.document.activeElement, f.name); assert.equal(f.container.writes, writes); assert.equal(f.notices.length, 0);
});
test('visible validation has wrapping error styling and a non-color-only description', () => {
  const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
  assert.ok(/\.step-request-error\s*\{[^}]*overflow-wrap:\s*anywhere/.test(css), 'Error descriptions wrap long text.');
  const f = fixture(); assert.ok(f.cards()[1].error); assert.equal(f.cards()[1].request.getAttribute('aria-describedby'), f.cards()[1].error.id);
});

test('Run reveals the trailing inline explanation after its textarea without changing focus or range', async () => {
  const f = fixture({ invalid: [] }); f.nodes.get('addSequenceStepButton').click();
  const card = f.cards()[3], before = range(card.request);
  await f.run();
  assert.equal(f.cards()[3], card); assert.equal(f.document.activeElement, card.request); assert.deepEqual(range(card.request), before);
  assert.deepEqual(f.scrolls, [card.request, card.error]);
  assert.equal(card.error.classList.contains('hidden'), false);
  for (const target of f.scrolls) {
    assert.equal(target.scrollCalls.length, 1);
    assert.deepEqual({ ...target.scrollCalls[0] }, { block: 'nearest', inline: 'nearest' });
  }
  assert.equal(f.requests.length, 0);
});
