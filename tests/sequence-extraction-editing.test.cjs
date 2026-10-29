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
  const node = () => ({ innerHTML: '', querySelectorAll: () => [], classList: { toggle() {} }, listeners: {},
    addEventListener(type, callback) { this.listeners[type] = callback; } });
  const container = node(); container.writes = 0;
  Object.defineProperty(container, 'innerHTML', { set(html) {
    container.writes++;
    this.renderedHtml = html;
    cards = [...html.matchAll(/<div class="sequence-step-card"[^]*?(?=<div class="sequence-step-card"|$)/g)].map(match => {
      const markup = match[0];
      const stepId = markup.match(/data-step-id="([^"]+)"/)[1];
      const idx = state.editingSequence.steps.findIndex(step => step.id === stepId);
      const step = state.editingSequence.steps[idx];
      const request = { value: step.request_text };
      const label = { value: step.label };
      const remove = { dataset: { removeStep: String(idx) }, addEventListener(type, fn) { this[type] = fn; } };
      const add = { dataset: { addExt: String(idx) }, addEventListener(type, fn) { this[type] = fn; } };
      const rowMarkup = [...markup.matchAll(/<div class="extraction-row">([^]*?)<\/div>/g)].map(match => match[1]);
      const rows = step.extractions.map((rule, ruleIndex) => {
        const html = rowMarkup[ruleIndex];
        const patternTag = html.match(/<input class="ext-pattern"[^>]*>/)[0];
        const caption = html.match(/<span class="ext-pattern-label">([^]*?)<\/span>/);
        const help = html.match(/<p class="extraction-help" id="([^"]+)">([^]*?)<\/p>/);
        const fields = { '.ext-var': { value: rule.variable_name }, '.ext-source': { value: rule.source },
          '.ext-pattern': { value: rule.pattern, placeholder: patternTag.match(/placeholder="([^"]*)"/)?.[1],
            describedBy: patternTag.match(/aria-describedby="([^"]*)"/)?.[1],
            selectionStart: 1, selectionEnd: 4, selectionDirection: 'backward',
            focus() { document.activeElement = this; } },
          '.ext-pattern-label': caption ? { textContent: caption[1] } : null,
          '.extraction-help': help ? { id: help[1], textContent: help[2] } : null };
        return { fields, markup: html, querySelector: selector => fields[selector] };
      });
      const details = { open: /<details[^>]*\bopen\b/.test(markup) };
      const inputs = [...markup.matchAll(/class="ext-var"/g)].map(() => ({ focus() { document.activeElement = this; } }));
      return { dataset: { stepId }, details, inputs, request, label, remove, rows, add, markup,
        querySelector: selector => selector === '.step-extractions' ? details : selector === '.step-request-text' ? request : selector === '.step-label' ? label : null,
        querySelectorAll: selector => selector === '.ext-var' ? inputs : selector === '.extraction-row' ? rows : [] };
    });
  } });
  container.querySelectorAll = selector => selector === '.sequence-step-card' ? cards : selector === '.ext-add' ? cards.map(card => card.add) : selector === '.step-remove' ? cards.map(card => card.remove) : [];
  const nodes = new Map([['sequenceStepsContainer', container]]);
  document.getElementById = id => nodes.get(id) || nodes.set(id, node()).get(id);
  const c = loadFunctions(['sequenceExtractionGuidance', 'renderSequencePanel', 'renderSequenceList', 'sequenceDisplayName', 'sequenceNameInputValue', 'syncSequenceRunButton', 'addExtractionRule', 'removeExtractionRule', 'removeSequenceStep',
    'markSequenceDraftDirty', 'bumpSequenceDraftVersion', 'syncSequenceStepFromDom', 'escapeHtml'], {
    state, document, replayHttpVersionFromText: () => '', parseEditableRawRequest() { throw new Error('Invalid request'); }, formatTimestamp: String, normalizeReplayHttpVersion: () => '',
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
  for (const [caption, control] of [['Variable name', 'ext-var'], ['Source', 'ext-source'], ['Body regex', 'ext-pattern']]) {
    const labels = [...html.matchAll(/<label class="extraction-field">([^]*?)<\/label>/g)].map(match => match[1]);
    assert.ok(labels.some(label => new RegExp(`<span[^>]*>${caption}</span>`).test(label) && label.includes(`class="${control}"`)), caption);
  }
  assert.match(html, /class="secondary-action ext-add"[^>]*aria-label="Add extraction to step 1"/);
  assert.match(html, /class="secondary-action ext-remove"[^>]*aria-label="Remove extraction 1 from step 1"/);
  assert.doesNotMatch(html, /class="ext-(?:add|remove)"/);
});

function assertStepControlNames(card, number) {
  const controls = [
    ['input', 'step-label', `Step ${number} label`],
    ['textarea', 'step-request-text', `Step ${number} raw HTTP request`],
    ['button', 'step-remove', `Remove step ${number}`],
  ];
  return controls.map(([tag, className, expected]) => {
    const opening = card.markup.match(new RegExp(`<${tag} class="${className}"[^>]*>`))?.[0];
    assert.ok(opening, className);
    const name = opening.match(/\baria-label="([^"]+)"/)?.[1];
    assert.equal(name, expected);
    return name;
  });
}

test('Repeated step labels still expose unique numbered label, raw request, and Remove names', () => {
  const f = fixture();
  f.state.editingSequence.steps.forEach(step => { step.label = 'Same label'; });
  const before = JSON.stringify(f.state.editingSequence);
  f.c.renderSequencePanel();
  const names = f.cards().flatMap((card, idx) => assertStepControlNames(card, idx + 1));
  assert.equal(new Set(names).size, 6);
  assert.equal(JSON.stringify(f.state.editingSequence), before);
  for (const card of f.cards()) {
    assert.match(card.markup, /value="Same label" placeholder="Step label"/);
    assert.match(card.markup, /title="Remove step"[^>]*>&times;<\/button>/);
  }
});

test('Actual local Remove handler reindexes surviving control names and retains unsaved values', () => {
  const f = fixture();
  f.cards()[1].label.value = 'Unsaved surviving label';
  f.cards()[1].request.value = 'unsaved invalid request';
  f.cards()[0].remove.click();
  assert.equal(f.cards().length, 1);
  assert.equal(f.cards()[0].dataset.stepId, 'second');
  assertStepControlNames(f.cards()[0], 1);
  assert.equal(f.state.editingSequence.steps[0].label, 'Unsaved surviving label');
  assert.equal(f.state.editingSequence.steps[0].request_text, 'unsaved invalid request');
  assert.equal(f.state.sequenceDirty, true);
  assert.match(f.cards()[0].markup, /data-remove-step="0"/);
  assert.match(f.cards()[0].markup, /aria-label="Add extraction to step 1"/);
  assert.match(f.cards()[0].markup, /aria-label="Remove extraction 1 from step 1"/);
  assert.doesNotMatch(f.cards()[0].markup, /aria-label="[^"]*step 2"/i);
});

test('Renderer numbers controls by new position after synthetic draft reorder, without renaming steps', () => {
  const f = fixture();
  f.state.editingSequence.steps.reverse();
  const before = JSON.stringify(f.state.editingSequence);
  f.c.renderSequencePanel();
  assert.deepEqual(f.cards().map(card => card.dataset.stepId), ['second', 'first']);
  f.cards().forEach((card, idx) => {
    assertStepControlNames(card, idx + 1);
    assert.match(card.markup, new RegExp(`aria-label="Add extraction to step ${idx + 1}"`));
    assert.match(card.markup, new RegExp(`aria-label="Remove extraction 1 from step ${idx + 1}"`));
  });
  assert.equal(JSON.stringify(f.state.editingSequence), before);
});

test('Numbered control names never interpolate user values or change their existing escaping', () => {
  const f = fixture();
  const label = 'Login "quoted" <tag> & token';
  const raw = 'GET /?a=1&b=2 HTTP/1.1\r\nHost: example.com\r\n\r\n</textarea><script>"x"</script>';
  f.state.editingSequence.steps[0].label = label;
  f.state.editingSequence.steps[0].request_text = raw;
  f.c.renderSequencePanel();
  const card = f.cards()[0];
  assertStepControlNames(card, 1);
  assert.ok(card.markup.includes('value="Login &quot;quoted&quot; &lt;tag&gt; &amp; token"'));
  assert.ok(card.markup.includes('GET /?a=1&amp;b=2 HTTP/1.1\r\nHost: example.com\r\n\r\n&lt;/textarea&gt;&lt;script&gt;&quot;x&quot;&lt;/script&gt;</textarea>'));
  assert.doesNotMatch(card.markup, /<script>/);
  assert.equal(f.state.editingSequence.steps[0].label, label);
  assert.equal(f.state.editingSequence.steps[0].request_text, raw);
});

for (const group of [undefined, 0, 1, 2, 5]) test(`Body guidance reflects saved capture group ${group ?? 'omitted (default 1)'}`, () => {
  const f = fixture(), rule = f.state.editingSequence.steps[0].extractions[0];
  if (group === undefined) delete rule.group; else rule.group = group;
  rule.pattern = 'unchanged draft (';
  const before = JSON.stringify(rule);
  f.c.renderSequencePanel();
  const fields = f.cards()[0].rows[0].fields, effectiveGroup = group ?? 1;
  assert.equal(fields['.ext-pattern-label']?.textContent, 'Body regex');
  assert.equal(fields['.ext-pattern'].placeholder, effectiveGroup === 1 ? 'csrf=([a-z]+)'
    : effectiveGroup === 0 ? 'csrf=[a-z]+' : `Regex with capture group ${effectiveGroup}`);
  assert.equal(fields['.extraction-help']?.textContent, effectiveGroup === 0 ? 'Saves the whole match (group 0).'
    : `Saves capture group ${effectiveGroup}.`);
  assert.equal(JSON.stringify(rule), before);
});

for (const group of [0, 2]) test(`source changes update only guidance, preserving group ${group}, live nodes, caret and invalid drafts`, () => {
  const f = fixture(), rule = f.state.editingSequence.steps[0].extractions[0];
  rule.group = group; f.c.renderSequencePanel();
  const card = f.cards()[0], row = card.rows[0], fields = row.fields;
  const pattern = fields['.ext-pattern'], source = fields['.ext-source'];
  pattern.value = '  invalid regex ( or header: value  '; pattern.focus();
  card.request.value = 'new invalid raw request draft';
  const writes = f.container.writes, other = f.cards()[1].rows[0].fields;
  for (const value of ['response_header', 'response_body', 'response_header']) {
    source.value = value;
    f.container.listeners.change({ target: source });
    assert.equal(fields['.ext-pattern-label']?.textContent, value === 'response_header' ? 'Header name' : 'Body regex');
    assert.equal(fields['.extraction-help']?.textContent, value === 'response_header' ? 'Name only; saves its full value.'
      : group === 0 ? 'Saves the whole match (group 0).' : `Saves capture group ${group}.`);
    if (value === 'response_header') assert.equal(pattern.placeholder, 'X-Example');
    assert.equal(rule.source, value); assert.equal(rule.group, group);
    assert.equal(rule.pattern, pattern.value);
    assert.equal(pattern.value, '  invalid regex ( or header: value  ');
    assert.equal(f.document.activeElement, pattern);
    assert.deepEqual([pattern.selectionStart, pattern.selectionEnd, pattern.selectionDirection], [1, 4, 'backward']);
    assert.equal(f.cards()[0], card); assert.equal(f.cards()[0].rows[0], row);
    assert.equal(f.container.writes, writes);
    assert.equal(f.state.editingSequence.steps[0].request_text, 'new invalid raw request draft');
    assert.equal(f.state.editingSequence.steps[0].request_parse_error, 'Invalid request');
    assert.equal(other['.ext-pattern-label']?.textContent, 'Body regex');
    assert.equal(other['.ext-pattern'].value, '(.*)');
  }
});

test('each rendered pattern references its own helper through step and extraction reorder', () => {
  const f = fixture();
  f.state.editingSequence.steps[0].extractions.push({ variable_name: 'header', source: 'response_header', pattern: 'Content-Type', group: 2 });
  for (let repeat = 0; repeat < 2; repeat++) {
    f.c.renderSequencePanel();
    const rows = f.cards().flatMap(card => card.rows);
    const ids = rows.map(row => row.fields['.extraction-help']?.id);
    assert.ok(ids.every(Boolean)); assert.equal(new Set(ids).size, rows.length);
    for (const row of rows) {
      assert.equal(row.fields['.ext-pattern'].describedBy, row.fields['.extraction-help'].id);
      assert.equal(row.fields['.ext-pattern-label'].textContent,
        row.fields['.ext-source'].value === 'response_header' ? 'Header name' : 'Body regex');
    }
    f.state.editingSequence.steps.reverse();
    f.state.editingSequence.steps.forEach(step => step.extractions.reverse());
  }
});

test('guidance leaves user values escaped and does not validate or replace an invalid extraction pattern', () => {
  const f = fixture(), rule = f.state.editingSequence.steps[0].extractions[0];
  rule.variable_name = 'token "quoted" <tag>&'; rule.pattern = '</p><script>" & ('; rule.group = 2;
  f.c.renderSequencePanel();
  const row = f.cards()[0].rows[0];
  assert.ok(row.markup.includes('value="token &quot;quoted&quot; &lt;tag&gt;&amp;"'));
  assert.ok(row.markup.includes('value="&lt;/p&gt;&lt;script&gt;&quot; &amp; ("'));
  assert.doesNotMatch(row.markup, /<script>/);
  const before = JSON.stringify(rule);
  assert.doesNotThrow(() => f.c.syncSequenceStepFromDom({ allowInvalidRequests: true }));
  assert.equal(JSON.stringify(rule), before);
});

test('Header guidance uses a harmless name example and a scoped full-width wrapping helper', () => {
  const f = fixture(), rule = f.state.editingSequence.steps[0].extractions[0];
  Object.assign(rule, { source: 'response_header', pattern: 'Content-Type', group: 2 });
  const before = JSON.stringify(rule); f.c.renderSequencePanel();
  const row = f.cards()[0].rows[0];
  assert.equal(row.fields['.ext-pattern-label'].textContent, 'Header name');
  assert.equal(row.fields['.ext-pattern'].placeholder, 'X-Example');
  assert.equal(row.fields['.extraction-help'].textContent, 'Name only; saves its full value.');
  assert.equal(JSON.stringify(rule), before);
  assert.equal((row.markup.match(/<label class="extraction-field">/g) || []).length, 3);
  assert.match(row.markup, /<button[^>]*ext-remove[^]*?<\/button>\s*<p class="extraction-help"/);
  const css = require('node:fs').readFileSync(require('node:path').join(__dirname, '../web/styles.css'), 'utf8');
  const help = css.match(/\.sequence-step-card \.extraction-help \{([^]*?)\}/)?.[1];
  assert.ok(help); assert.match(help, /grid-column: 1 \/ -1;/); assert.match(help, /overflow-wrap: anywhere;/);
  assert.doesNotMatch(help, /ellipsis|nowrap|overflow: hidden|max-height|height:/);
});

test('Source keeps a selected-label budget after the shared select arrow padding at both row layouts', () => {
  // Layout-budget contract only, not a browser font measurement. The actual
  // 12px Header label clipped when its 72px column left only 30px for text.
  const css = require('node:fs').readFileSync(require('node:path').join(__dirname, '../web/styles.css'), 'utf8');
  const normal = css.match(/\.sequence-step-card \.extraction-row \{([^]*?)\}/)[1];
  const sourceWidth = Number(normal.match(/grid-template-columns: minmax\(0, 1fr\) (\d+)px minmax\(0, 1\.3fr\) 28px;/)[1]);
  const gap = Number(normal.match(/gap: (\d+)px;/)[1]);
  const select = css.match(/^select:not\(\[multiple\]\) \{([^]*?)\}/m)[1];
  const arrowPadding = Number(select.match(/padding-right: (\d+)px !important;/)[1]);
  const fields = css.match(/\.sequence-step-card \.extraction-row select \{([^]*?)\}/)[1];
  const horizontalPadding = Number(fields.match(/padding: \d+px (\d+)px;/)[1]);
  const border = Number(fields.match(/border: (\d+)px solid/)[1]);
  const textBudget = width => width - 2 * border - horizontalPadding - arrowPadding;
  assert.equal(sourceWidth, 88);
  assert.ok(textBudget(sourceWidth) >= 46);
  const narrow = css.slice(css.indexOf('@container sequence-extractions (max-width: 400px)'));
  assert.match(narrow, /grid-template-columns: minmax\(0, 1fr\) 72px 28px;/);
  assert.match(narrow, /\.extraction-field:nth-child\(2\) \{ grid-column: 2 \/ -1; \}/);
  assert.ok(textBudget(72 + 28 + gap) >= 46, 'narrow Source already spans its own and the action column');
});
