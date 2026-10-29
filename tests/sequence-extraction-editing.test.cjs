// Render and action coverage only: no bootstrap, API writes, or sequence runs.
const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');

function fixture() {
  const document = { activeElement: null };
  const step = id => ({ id, label: id, request: {}, request_text: 'invalid draft', extractions: [
    { variable_name: 'token', source: 'response_body', pattern: '(.*)', group: 1 },
  ] });
  const state = { activeSession: { id: 'session-a' }, sequenceDefinitions: [{ id: 'a', name: 'Login', steps: [] }],
    sequencePastRuns: [], selectedSequenceId: 'a', editingSequence: { id: 'a', name: 'Login', steps: [step('first'), step('second')] } };
  let cards = [];
  const node = () => ({ innerHTML: '', querySelectorAll: () => [], classList: { toggle() {} }, addEventListener() {} });
  const container = node();
  Object.defineProperty(container, 'innerHTML', { set(html) {
    this.renderedHtml = html;
    cards = [...html.matchAll(/<div class="sequence-step-card"[^]*?(?=<div class="sequence-step-card"|$)/g)].map(match => {
      const markup = match[0];
      const stepId = markup.match(/data-step-id="([^"]+)"/)[1];
      const idx = state.editingSequence.steps.findIndex(step => step.id === stepId);
      const step = state.editingSequence.steps[idx];
      const request = { value: step.request_text };
      const add = { dataset: { addExt: String(idx) }, addEventListener(type, fn) { this[type] = fn; } };
      const rows = step.extractions.map(rule => {
        const fields = { '.ext-var': { value: rule.variable_name }, '.ext-source': { value: rule.source }, '.ext-pattern': { value: rule.pattern } };
        return { fields, querySelector: selector => fields[selector] };
      });
      const details = { open: /<details[^>]*\bopen\b/.test(markup) };
      const inputs = [...markup.matchAll(/class="ext-var"/g)].map(() => ({ focus() { document.activeElement = this; } }));
      return { dataset: { stepId }, details, inputs, request, rows, add,
        querySelector: selector => selector === '.step-extractions' ? details : selector === '.step-request-text' ? request : null,
        querySelectorAll: selector => selector === '.ext-var' ? inputs : selector === '.extraction-row' ? rows : [] };
    });
  } });
  container.querySelectorAll = selector => selector === '.sequence-step-card' ? cards : selector === '.ext-add' ? cards.map(card => card.add) : [];
  const nodes = new Map([['sequenceStepsContainer', container]]);
  document.getElementById = id => nodes.get(id) || nodes.set(id, node()).get(id);
  const c = loadFunctions(['renderSequencePanel', 'renderSequenceList', 'sequenceDisplayName', 'sequenceNameInputValue', 'syncSequenceRunButton', 'addExtractionRule', 'removeExtractionRule', 'removeSequenceStep',
    'markSequenceDraftDirty', 'bumpSequenceDraftVersion', 'syncSequenceStepFromDom'], {
    state, document, replayHttpVersionFromText: () => '', parseEditableRawRequest() { throw new Error('Invalid request'); }, escapeHtml: String, formatTimestamp: String, normalizeReplayHttpVersion: () => '',
    normalizeSequenceRunResult: () => null, jsonArray: value => Array.isArray(value) ? value : [],
  });
  c.renderSequencePanel();
  return { c, state, document, container, cards: () => cards };
}

for (const initiallyOpen of [false, true]) test(`Add opens the target and focuses its new variable (initially ${initiallyOpen})`, () => {
  const f = fixture(); f.cards()[0].details.open = initiallyOpen;
  f.c.addExtractionRule(0);
  assert.equal(f.cards()[0].details.open, true);
  assert.equal(f.cards()[1].details.open, false);
  assert.equal(f.document.activeElement, f.cards()[0].inputs[1]);
  assert.equal(f.state.sequenceDirty, true);
  assert.equal(f.state.editingSequence.steps[0].request_text, 'invalid draft');
});

test('Remove rule and ordinary rerender retain expanded sections without stealing focus', () => {
  const f = fixture(); f.cards()[0].details.open = true; f.cards()[1].details.open = true;
  const outside = {}; f.document.activeElement = outside;
  f.c.removeExtractionRule(0, 0); f.c.renderSequencePanel();
  assert.deepEqual(f.cards().map(card => card.details.open), [true, true]);
  assert.equal(f.cards()[0].inputs.length, 0);
  assert.equal(f.document.activeElement, outside);
});

test('Removing an earlier step retains expansion by identity, not old position', () => {
  const f = fixture(); f.cards()[1].details.open = true;
  f.c.removeSequenceStep(0);
  assert.equal(f.cards()[0].dataset.stepId, 'second');
  assert.equal(f.cards()[0].details.open, true);
});

for (const boundary of ['sequence', 'session']) test(`${boundary} switch cannot inherit old expansion with reused step IDs`, () => {
  const f = fixture(); f.cards()[0].details.open = true;
  if (boundary === 'sequence') f.state.editingSequence.id = 'b'; else f.state.activeSession.id = 'session-b';
  f.c.renderSequencePanel();
  assert.equal(f.cards()[0].details.open, false);
});

test('User-collapsed section remains collapsed on rerender', () => {
  const f = fixture(); f.c.addExtractionRule(0); f.cards()[0].details.open = false;
  f.c.renderSequencePanel(); assert.equal(f.cards()[0].details.open, false);
});

test('Repeated Add targets the newest field and keeps another expanded step open', () => {
  const f = fixture(); f.cards()[1].details.open = true;
  f.c.addExtractionRule(0); f.c.addExtractionRule(0);
  assert.equal(f.cards()[0].inputs.length, 3);
  assert.equal(f.document.activeElement, f.cards()[0].inputs[2]);
  assert.deepEqual(f.cards().map(card => card.details.open), [true, true]);
});

test('Actual Add handler syncs unsaved invalid request and extraction fields before rerender', () => {
  const f = fixture(); const card = f.cards()[0];
  card.request.value = 'new invalid raw draft';
  card.rows[0].fields['.ext-var'].value = 'unsaved_token';
  card.rows[0].fields['.ext-pattern'].value = 'unsaved_pattern';
  let prevented = false;
  card.add.click({ preventDefault() { prevented = true; } });
  const step = f.state.editingSequence.steps[0];
  assert.equal(prevented, true);
  assert.equal(step.request_text, 'new invalid raw draft');
  assert.equal(step.request_parse_error, 'Invalid request');
  assert.equal(step.extractions[0].variable_name, 'unsaved_token');
  assert.equal(step.extractions[0].pattern, 'unsaved_pattern');
  assert.equal(f.cards()[0].details.open, true);
  assert.equal(f.document.activeElement, f.cards()[0].inputs[1]);
});

test('Reordering preserves expansion by step identity', () => {
  const f = fixture(); f.cards()[1].details.open = true;
  f.state.editingSequence.steps.reverse(); f.c.renderSequencePanel();
  assert.deepEqual(f.cards().map(card => [card.dataset.stepId, card.details.open]), [['second', true], ['first', false]]);
});


test('Extraction controls have persistent visible associated labels and themed named actions', () => {
  const f = fixture(); const html = f.container.renderedHtml;
  for (const [caption, control] of [['Variable', 'ext-var'], ['Source', 'ext-source'], ['Pattern / header', 'ext-pattern']]) {
    const labels = [...html.matchAll(/<label class="extraction-field">([^]*?)<\/label>/g)].map(match => match[1]);
    assert.ok(labels.some(label => label.includes(`<span>${caption}</span>`) && label.includes(`class="${control}"`)), caption);
  }
  assert.match(html, /class="secondary-action ext-add"[^>]*aria-label="Add extraction to step 1"/);
  assert.match(html, /class="secondary-action ext-remove"[^>]*aria-label="Remove extraction 1 from step 1"/);
  assert.doesNotMatch(html, /class="ext-(?:add|remove)"/);
});
