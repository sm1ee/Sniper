// Passive editor metadata only: no traffic, clipboard, browser or real API.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
const plain = value => JSON.parse(JSON.stringify(value));
const tick = () => new Promise(resolve => setImmediate(resolve));
const rule = (extra = {}) => ({ id: 'rule-a', enabled: true, description: '', scope: 'response', target: 'body',
  search: 'example.com', replace: 'replacement.example.com', regex: false, case_sensitive: false, ...extra });
const helpers = ['matchReplaceRuleActivity', 'setMatchReplaceRuleActivity', 'canonicalMatchReplaceRule',
  'matchReplaceRulesPayload', 'matchReplaceRuleActions', 'matchReplaceRuleTitle', 'getMatchReplaceSaveOwner', 'beginMatchReplaceWrite', 'matchReplaceWriteIsCurrent', 'acknowledgeMatchReplaceRules', 'finishMatchReplaceWrite'];
function fixture(rules = [rule()], pending = false) {
  const state = { activeSession: { id: 'session-a' }, matchReplaceRules: plain(rules), matchReplaceSavedRules: plain(rules),
    selectedMatchReplaceRuleId: rules[0]?.id ?? null, matchReplaceDirty: false, matchReplaceDraftVersion: 0,
    matchReplaceSaveToken: 0, matchReplaceEditorSessionId: 'session-a' };
  const classes = () => ({ toggle() {} });
  const field = () => ({ value: '', checked: false, disabled: false, listeners: {}, addEventListener(name, fn) { this.listeners[name] = fn; } });
  const els = Object.fromEntries(['Scope', 'Target', 'Search', 'Replace', 'ReplaceEnabled', 'AnnotationNote', 'AnnotationColor',
    'Regex', 'CaseSensitive'].map(name => [`matchReplace${name}`, field()]));
  const toggles = new Map();
  const toggle = id => { if (!toggles.has(id)) toggles.set(id, { ...field(), dataset: { ruleToggle: id } }); return toggles.get(id); };
  Object.assign(els, { matchReplaceTableBody: { innerHTML: '', querySelectorAll(selector) {
    if (selector === '[data-rule-toggle]') return state.matchReplaceRules.map(r => toggle(r.id));
    return [];
  } }, matchReplaceEditorHeader: { classList: classes() }, matchReplaceForm: { classList: classes() },
  matchReplaceEmpty: { classList: classes() }, matchReplaceEditorPath: {}, matchReplaceEditorTitle: {},
  deleteMatchReplaceRuleButton: {}, saveMatchReplaceRuleButton: {} });
  const requests = [], toasts = [];
  const c = loadFunctions(['renderMatchReplaceRules', 'getSelectedMatchReplaceRule', 'syncMatchReplaceEditor',
    'createNewMatchReplaceRule', 'updateMatchReplaceSaveState', 'matchReplaceRuleUnsaved', 'untouchedNewMatchReplaceRule',
    'saveMatchReplaceSwitch', 'saveMatchReplaceRules', 'loadMatchReplaceRules', 'jsonArray',
    ...helpers.filter(name => appSource.includes(`function ${name}(`))], {
    state, els, TextEncoder, workspaceStateGeneration: 0,
    HTTP_COLOR_TAG_OPTIONS: new Set(['red', 'orange', 'yellow', 'green', 'blue', 'purple']),
    currentSessionId: () => state.activeSession.id, generateUuid: () => 'new-rule',
    sessionWritePath: path => path, sessionQueryPath: path => path,
    escapeHtml: value => String(value).replace(/[&<>"']/g, ch => `&#${ch.charCodeAt(0)};`),
    showToast: (...args) => toasts.push(args), requireOkResponse: async r => { if (!r.ok) throw new Error('synthetic save failure'); },
    fetch: (url, options) => {
      let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; });
      const body = options ? JSON.parse(options.body) : null;
      requests.push({ url, options, body, resolve, reject });
      if (!pending) resolve({ ok: true, json: async () => body?.rules ?? plain(rules) });
      return promise;
    },
  });
  c.renderMatchReplaceRules();
  const edit = (name, value) => { const f = els[`matchReplace${name}`]; f[name === 'ReplaceEnabled' ? 'checked' : 'value'] = value;
    c.syncMatchReplaceEditor(); c.updateMatchReplaceSaveState(); };
  const respond = (i, value) => requests[i].resolve({ ok: true, json: async () => value ?? requests[i].body?.rules ?? plain(rules) });
  const on = (id, checked) => { const f = toggle(id); f.checked = checked; f.listeners.change({ stopPropagation() {} }); };
  return { c, state, els, requests, toasts, edit, respond, on };
}

test('legacy missing/null annotation fields remain clean with Replace checked', () => {
  for (const extra of [{}, { annotation_only_enabled: null, annotation_note: null, annotation_color: null }]) {
    const f = fixture([rule(extra)]);
    assert.equal(f.els.matchReplaceReplaceEnabled.checked, true);
    assert.equal(f.els.matchReplaceReplace.disabled, false);
    f.c.syncMatchReplaceEditor();
    assert.equal(f.c.matchReplaceRuleUnsaved(f.state.matchReplaceRules[0]), false);
    assert.equal(f.state.matchReplaceDirty, false);
  }
});
for (const active of [true, false]) for (const startOnly of [true, false]) {
  test(`Replace transfers activity ${active}, starting annotation-only=${startOnly}`, () => {
    const f = fixture([rule({ enabled: startOnly ? false : active, ...(startOnly ? { annotation_only_enabled: active } : {}) })]);
    f.edit('ReplaceEnabled', startOnly);
    const r = f.state.matchReplaceRules[0];
    assert.equal(r.enabled, startOnly ? active : false);
    assert.equal(r.annotation_only_enabled ?? null, startOnly ? null : active);
    assert.equal(r.replace, 'replacement.example.com');
    assert.equal(f.els.matchReplaceReplace.disabled, !startOnly);
    assert.equal(f.c.matchReplaceRuleUnsaved(r), true);
    f.edit('ReplaceEnabled', !startOnly);
    assert.equal(f.c.matchReplaceRuleUnsaved(r), false, 'mode round-trip returns to saved semantics');
  });
}
for (const active of [true, false]) test(`annotation-only render uses effective On=${active} and no deletion arrow`, () => {
  const f = fixture([rule({ enabled: false, annotation_only_enabled: active, replace: '', annotation_note: 'flag <literal>', annotation_color: 'yellow' })]);
  assert.equal(f.els.matchReplaceReplaceEnabled.checked, false);
  assert.equal(f.els.matchReplaceReplace.disabled, true);
  assert.equal(f.els.matchReplaceAnnotationNote.value, 'flag <literal>');
  assert.equal(f.els.matchReplaceAnnotationColor.value, 'yellow');
  assert.doesNotMatch(f.els.matchReplaceEditorTitle.textContent, /→|∅/);
  assert.match(f.els.matchReplaceTableBody.innerHTML, /flag &#60;literal&#62;/);
  assert.equal(/data-rule-toggle="rule-a" checked/.test(f.els.matchReplaceTableBody.innerHTML), active);
});
for (const [field, value] of [['AnnotationNote', 'literal $1 ${match}'], ['AnnotationColor', 'purple']]) {
  test(`${field} keeps a new otherwise-empty row and marks a saved rule dirty`, () => {
    const f = fixture([]); f.c.createNewMatchReplaceRule(); f.edit(field, value);
    assert.equal(f.c.untouchedNewMatchReplaceRule(), null);
    assert.equal(f.state.matchReplaceDirty, true);
    const saved = fixture(); saved.edit(field, value);
    assert.equal(saved.c.matchReplaceRuleUnsaved(saved.state.matchReplaceRules[0]), true);
    saved.edit(field, ''); assert.equal(saved.c.matchReplaceRuleUnsaved(saved.state.matchReplaceRules[0]), false);
  });
}
test('annotation-only mode alone retains a new row', () => {
  const f = fixture([]); f.c.createNewMatchReplaceRule(); f.edit('ReplaceEnabled', false);
  assert.equal(f.c.untouchedNewMatchReplaceRule(), null);
});
for (const active of [true, false]) test(`full save emits canonical annotation-only ${active}, literal note and color`, async () => {
  const f = fixture([rule({ enabled: active })]);
  f.edit('ReplaceEnabled', false); f.edit('AnnotationNote', '$1 ${match} flag 탐지'); f.edit('AnnotationColor', 'yellow');
  assert.equal(await f.c.saveMatchReplaceRules(), true);
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].body.rules[0].enabled, false);
  assert.equal(f.requests[0].body.rules[0].annotation_only_enabled, active);
  assert.equal(f.requests[0].body.rules[0].annotation_note, '$1 ${match} flag 탐지');
  assert.equal(f.requests[0].body.rules[0].annotation_color, 'yellow');
  assert.equal(f.c.matchReplaceRuleUnsaved(f.state.matchReplaceRules[0]), false);
});
for (const savedOnly of [true, false]) for (const active of [true, false]) {
  test(`mismatched mode On=${active}, saved annotation-only=${savedOnly}: only Off persists`, async () => {
    const f = fixture([rule({ enabled: savedOnly ? false : !active, ...(savedOnly ? { annotation_only_enabled: !active } : {}), annotation_note: 'saved', annotation_color: 'red' })]);
    f.edit('ReplaceEnabled', savedOnly); f.edit('AnnotationNote', 'draft'); f.edit('AnnotationColor', 'blue');
    f.on('rule-a', active); await tick();
    assert.equal(f.requests.length, active ? 0 : 1);
    if (!active) {
      const r = f.requests[0].body.rules[0];
      assert.equal(r.enabled, false); assert.equal(r.annotation_only_enabled ?? null, savedOnly ? false : null);
      assert.equal(r.annotation_note, 'saved'); assert.equal(r.annotation_color, 'red');
    }
    const draft = f.state.matchReplaceRules[0];
    assert.equal(draft.annotation_note, 'draft'); assert.equal(draft.annotation_color, 'blue');
    assert.equal(draft.enabled, savedOnly ? active : false);
    assert.equal(draft.annotation_only_enabled ?? null, savedOnly ? null : active);
    assert.equal(f.c.matchReplaceRuleUnsaved(draft), true); assert.equal(f.state.matchReplaceDirty, true);
  });
}
for (const savedOnly of [true, false]) test(`same-mode switch preserves note/color drafts, annotation-only=${savedOnly}`, async () => {
  const f = fixture([rule({ enabled: !savedOnly, ...(savedOnly ? { annotation_only_enabled: true } : {}), annotation_note: 'saved', annotation_color: 'red' })]);
  f.edit('AnnotationNote', 'draft'); f.edit('AnnotationColor', 'blue'); f.on('rule-a', false); await tick();
  const r = f.requests[0].body.rules[0];
  assert.equal(r.enabled, false); assert.equal(r.annotation_only_enabled ?? null, savedOnly ? false : null);
  assert.equal(r.annotation_note, 'saved'); assert.equal(r.annotation_color, 'red');
  assert.equal(f.state.matchReplaceRules[0].annotation_note, 'draft'); assert.equal(f.state.matchReplaceDirty, true);
});
for (const only of [false, true]) test(`On without drafts retains its mode=${only} across off/on`, async () => {
  const f = fixture([rule({ enabled: !only, ...(only ? { annotation_only_enabled: true } : {}) })]);
  for (const value of [false, true]) {
    f.on('rule-a', value); await tick();
    const r = f.requests.at(-1).body.rules[0];
    assert.equal(r.enabled, only ? false : value);
    assert.equal(r.annotation_only_enabled ?? null, only ? value : null);
  }
});
for (const [name, notes, valid] of [
  ['1024 UTF-8 bytes', ['한'.repeat(341) + 'a'], true], ['1025 UTF-8 bytes', ['한'.repeat(341) + 'ab'], false],
  ['32768 aggregate', Array(32).fill('a'.repeat(1024)), true], ['32769 aggregate', [...Array(32).fill('a'.repeat(1024)), 'a'], false],
  ['whitespace', [' \t\n'], false], ['empty', [''], true],
]) test(`literal note validation ${name}`, async () => {
  const f = fixture(notes.map((note, i) => rule({ id: `rule-${i}`, enabled: false, annotation_note: note })));
  if (valid) { await f.c.saveMatchReplaceRules(); assert.equal(f.requests.length, 1); }
  else { await assert.rejects(f.c.saveMatchReplaceRules()); assert.equal(f.requests.length, 0); }
});
for (const color of ['red', 'orange', 'yellow', 'green', 'blue', 'purple', null]) test(`palette accepts ${color}`, async () => {
  const f = fixture([rule({ annotation_color: color })]); await f.c.saveMatchReplaceRules(); assert.equal(f.requests.length, 1);
});
test('invalid color is refused before mutation', async () => {
  const f = fixture([rule({ annotation_color: 'pink' })]); await assert.rejects(f.c.saveMatchReplaceRules()); assert.equal(f.requests.length, 0);
});
for (const ownership of ['new note', 'mode ABA', 'reset', 'new session']) test(`pending full acknowledgement cannot replace ${ownership}`, async () => {
  const f = fixture(undefined, true); f.edit('AnnotationNote', 'submitted');
  const pending = f.c.saveMatchReplaceRules();
  if (ownership === 'new note') f.edit('AnnotationNote', 'newer');
  if (ownership === 'mode ABA') { f.edit('ReplaceEnabled', false); f.edit('ReplaceEnabled', true); }
  if (ownership === 'reset') f.c.workspaceStateGeneration++;
  if (ownership === 'new session') f.state.activeSession.id = 'session-b';
  const before = plain(f.state.matchReplaceRules); f.respond(0);
  assert.equal(await pending, false); assert.deepEqual(plain(f.state.matchReplaceRules), before);
});
for (const ownership of ['reset', 'new session']) test(`switch-only acknowledgement cannot replace ${ownership}`, async () => {
  const f = fixture([rule({ enabled: false, annotation_only_enabled: true })], true);
  f.edit('AnnotationNote', 'draft'); f.on('rule-a', false);
  if (ownership === 'reset') { f.c.workspaceStateGeneration++; f.state.matchReplaceSavedRules = [rule({ id: 'new-owner' })]; }
  if (ownership === 'new session') { f.state.activeSession.id = 'session-b'; f.state.matchReplaceSavedRules = [rule({ id: 'new-owner' })]; }
  if (ownership === 'newer switch') { f.on('rule-a', true); f.respond(1); await tick(); }
  const before = plain(f.state.matchReplaceSavedRules); f.respond(0); await tick();
  assert.deepEqual(plain(f.state.matchReplaceSavedRules), before);
  assert.equal(f.state.matchReplaceRules[0].annotation_note, 'draft');
});
test('late load cannot overwrite a new annotation draft', async () => {
  const f = fixture(undefined, true); const loading = f.c.loadMatchReplaceRules(); f.edit('AnnotationNote', 'new draft');
  f.respond(0); await loading; assert.equal(f.state.matchReplaceRules[0].annotation_note, 'new draft');
});
test('failed save keeps annotation draft and literal replacement', async () => {
  const f = fixture(undefined, true); f.edit('AnnotationNote', 'draft'); f.edit('ReplaceEnabled', false);
  const saving = f.c.saveMatchReplaceRules(); f.requests[0].resolve({ ok: false });
  await assert.rejects(saving); assert.equal(f.state.matchReplaceRules[0].annotation_note, 'draft');
  assert.equal(f.state.matchReplaceRules[0].replace, 'replacement.example.com'); assert.equal(f.state.matchReplaceDirty, true);
});
test('markup exposes only the requested mode, note and existing palette controls', () => {
  const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  for (const name of ['ReplaceEnabled', 'AnnotationNote', 'AnnotationColor']) assert.equal(html.includes(`id="matchReplace${name}"`), true, name);
  const palette = html.match(/<select id="matchReplaceAnnotationColor">([^]*?)<\/select>/)?.[1] ?? '';
  assert.deepEqual([...palette.matchAll(/value="([^"]*)"/g)].map(m => m[1]), ['', 'red', 'orange', 'yellow', 'green', 'blue', 'purple']);
});

for (const savedOnly of [true, false]) test(`failed mismatched-mode Off keeps saved activity honest, annotation-only=${savedOnly}`, async () => {
  const f = fixture([rule({ enabled: !savedOnly, ...(savedOnly ? { annotation_only_enabled: true } : {}) })], true);
  f.edit('ReplaceEnabled', savedOnly); const saved = plain(f.state.matchReplaceSavedRules);
  f.on('rule-a', false); assert.equal(f.requests.length, 1); f.requests[0].resolve({ ok: false }); await tick();
  assert.deepEqual(plain(f.state.matchReplaceSavedRules), saved);
  assert.equal(f.state.matchReplaceDirty, true); assert.equal(f.toasts.length, 1);
});
for (const savedOnly of [true, false]) test(`pending mismatched Off cannot revert newer On draft, annotation-only=${savedOnly}`, async () => {
  const f = fixture([rule({ enabled: !savedOnly, ...(savedOnly ? { annotation_only_enabled: true } : {}) })], true);
  f.edit('ReplaceEnabled', savedOnly); f.on('rule-a', false); f.on('rule-a', true);
  assert.equal(f.requests.length, 1, 'new On is draft-only'); const draft = plain(f.state.matchReplaceRules);
  f.respond(0); await tick(); assert.deepEqual(plain(f.state.matchReplaceRules), draft);
  assert.equal(f.state.matchReplaceSavedRules[0].enabled, false);
  assert.equal(f.state.matchReplaceSavedRules[0].annotation_only_enabled ?? null, savedOnly ? false : null);
  assert.equal(f.state.matchReplaceDirty, true);
});

test('canonical output masks contradictory in-memory legacy activity without inferring mode from notes', async () => {
  const f = fixture([rule({ enabled: true, annotation_only_enabled: true, annotation_note: 'literal' })]);
  await f.c.saveMatchReplaceRules(); assert.equal(f.requests[0].body.rules[0].enabled, false);
  const legacy = fixture([rule({ enabled: false, annotation_note: 'literal', annotation_color: 'red' })]);
  await legacy.c.saveMatchReplaceRules(); assert.equal(legacy.requests[0].body.rules[0].enabled, false);
  assert.equal(legacy.requests[0].body.rules[0].annotation_only_enabled, undefined);
});
test('same-session reset during pending load leaves replacement editor untouched', async () => {
  const f = fixture(undefined, true); const loading = f.c.loadMatchReplaceRules(); f.c.workspaceStateGeneration++;
  f.state.matchReplaceRules = []; f.state.matchReplaceSavedRules = []; f.state.selectedMatchReplaceRuleId = null;
  f.respond(0); await loading; assert.deepEqual(plain(f.state.matchReplaceRules), []);
});

test('mode change removes deletion title immediately without a rerender or save', () => {
  const f = fixture([rule({ replace: '' })]); assert.match(f.els.matchReplaceEditorTitle.textContent, /→ ∅/);
  f.edit('ReplaceEnabled', false); assert.doesNotMatch(f.els.matchReplaceEditorTitle.textContent, /→|∅/);
  f.edit('ReplaceEnabled', true); assert.match(f.els.matchReplaceEditorTitle.textContent, /→ ∅/);
});
test('actual field input/change bindings update new annotation controls without automatic save', () => {
  const vm = require('node:vm'), f = fixture();
  const marker = '  [\n    els.matchReplaceScope,', binding = appSource.slice(appSource.indexOf(marker));
  vm.runInContext(binding.slice(0, binding.indexOf('\n  });') + 6), f.c);
  f.els.matchReplaceAnnotationNote.value = 'literal'; f.els.matchReplaceAnnotationNote.listeners.input();
  f.els.matchReplaceAnnotationColor.value = 'blue'; f.els.matchReplaceAnnotationColor.listeners.change();
  f.els.matchReplaceReplaceEnabled.checked = false; f.els.matchReplaceReplaceEnabled.listeners.change();
  assert.equal(f.state.matchReplaceRules[0].annotation_note, 'literal');
  assert.equal(f.state.matchReplaceRules[0].annotation_color, 'blue');
  assert.equal(f.state.matchReplaceRules[0].enabled, false);
  assert.equal(f.state.matchReplaceRules[0].annotation_only_enabled, true);
  assert.equal(f.requests.length, 0); assert.equal(f.state.matchReplaceDirty, true);
});

for (const only of [false, true]) for (const order of [[0, 1], [1, 0]]) for (const successes of [[], [0], [1], [0, 1]]) {
  test(`cross-row pending composition: annotation-only=${only}, order=${order}, successes=${successes}`, async () => {
    const f = fixture(['a', 'b'].map(id => rule({ id, enabled: !only, ...(only ? { annotation_only_enabled: true } : {}) })), true);
    f.edit('AnnotationNote', 'unsaved note'); f.on('a', false); f.on('b', false);
    assert.equal(f.requests.length, 2);
    const activity = r => r.annotation_only_enabled ?? r.enabled;
    assert.deepEqual(f.requests[0].body.rules.map(activity), [false, true]);
    assert.deepEqual(f.requests[1].body.rules.map(activity), [false, false]);
    for (const i of order) { if (successes.includes(i)) f.respond(i); else f.requests[i].resolve({ ok: false }); await tick(); }
    const expected = successes.includes(1) ? [false, false] : successes.includes(0) ? [false, true] : [true, true];
    assert.deepEqual(f.state.matchReplaceSavedRules.map(activity), expected);
    assert.equal(f.state.matchReplaceRules[0].annotation_note, 'unsaved note'); assert.equal(f.state.matchReplaceDirty, true);
  });
}

for (const only of [false, true]) test(`failed B toggle cannot drop unresolved A-Off from later C payload, annotation-only=${only}`, async () => {
  const f = fixture(['a', 'b', 'c'].map(id => rule({ id, enabled: !only, ...(only ? { annotation_only_enabled: true } : {}) })), true);
  f.edit('AnnotationNote', 'draft'); f.on('a', false); f.on('b', false);
  f.requests[1].resolve({ ok: false }); await tick(); f.on('c', false);
  const activity = r => r.annotation_only_enabled ?? r.enabled;
  assert.deepEqual(f.requests[2].body.rules.map(activity), [false, true, false]);
  f.respond(2); await tick(); f.respond(0); await tick();
  assert.deepEqual(f.state.matchReplaceSavedRules.map(activity), [false, true, false]);
  assert.equal(f.state.matchReplaceRules[0].annotation_note, 'draft');
});
test('load begun during a pending switch cannot overwrite its acknowledged result', async () => {
  const f = fixture(undefined, true); f.on('rule-a', false);
  const loading = f.c.loadMatchReplaceRules();
  assert.equal(f.requests.length, 1, 'metadata read defers until pending mutation settles');
  await loading; f.respond(0); await tick();
  assert.equal(f.state.matchReplaceSavedRules[0].enabled, false);
});

for (const only of [false, true]) for (const failed of [false, true]) test(`pending safety Off defers same-row On and activating Save: mode=${only}, failed=${failed}`, async () => {
  const f = fixture([rule({ enabled: !only, ...(only ? { annotation_only_enabled: true } : {}) })], true);
  f.edit('AnnotationNote', 'draft'); f.on('rule-a', false); f.on('rule-a', true);
  assert.equal(f.requests.length, 1, 'On is local, not a new write');
  await assert.rejects(f.c.saveMatchReplaceRules()); assert.equal(f.requests.length, 1, 'Save cannot bypass pending Off');
  if (failed) f.requests[0].resolve({ ok: false }); else f.respond(0); await tick();
  const activity = r => r.annotation_only_enabled ?? r.enabled;
  assert.equal(activity(f.state.matchReplaceSavedRules[0]), failed);
  assert.equal(activity(f.state.matchReplaceRules[0]), true); assert.equal(f.state.matchReplaceDirty, true);
  assert.equal(f.requests.length, 1, 'settlement never resends On');
  const saving = f.c.saveMatchReplaceRules(); assert.equal(f.requests.length, 2); f.respond(1); assert.equal(await saving, true);
  assert.equal(activity(f.state.matchReplaceSavedRules[0]), true);
});
for (const only of [false, true]) test(`failed newer repeated Off preserves older pending Off for C: mode=${only}`, async () => {
  const f = fixture(['a', 'c'].map(id => rule({ id, enabled: !only, ...(only ? { annotation_only_enabled: true } : {}) })), true);
  f.edit('AnnotationNote', 'draft'); f.on('a', false); f.on('a', false);
  f.requests[1].resolve({ ok: false }); await tick(); f.on('c', false);
  const activity = r => r.annotation_only_enabled ?? r.enabled;
  assert.deepEqual(f.requests[2].body.rules.map(activity), [false, false]);
  f.respond(2); await tick(); f.respond(0); await tick();
  assert.deepEqual(f.state.matchReplaceSavedRules.map(activity), [false, false]);
});
for (const only of [false, true]) test(`nonactivating full Save also waits for pending writes: mode=${only}`, async () => {
  const f = fixture(['a', 'c'].map(id => rule({ id, enabled: !only, ...(only ? { annotation_only_enabled: true } : {}) })), true);
  f.edit('AnnotationNote', 'draft'); f.on('a', false); f.edit('ReplaceEnabled', only);
  await assert.rejects(f.c.saveMatchReplaceRules()); assert.equal(f.requests.length, 1);
  f.on('c', false); const activity = r => r.annotation_only_enabled ?? r.enabled;
  assert.deepEqual(f.requests[1].body.rules.map(activity), [false, false]);
  assert.equal(f.requests[1].body.rules[0].annotation_only_enabled ?? null, only ? false : null);
  f.respond(1); await tick(); f.respond(0); await tick(); assert.equal(f.state.matchReplaceDirty, true);
  assert.equal(f.requests.length, 2, 'no automatic full Save on settlement');
});
test('an inactive companion row in a pending whole-list save also defers its On', async () => {
  const f = fixture([rule({ id: 'a' }), rule({ id: 'b', enabled: false })], true);
  f.edit('AnnotationNote', 'draft'); f.on('a', false); f.on('b', true);
  assert.equal(f.requests.length, 1); await assert.rejects(f.c.saveMatchReplaceRules());
  f.respond(0); await tick(); assert.equal(f.state.matchReplaceSavedRules[1].enabled, false);
  assert.equal(f.state.matchReplaceRules[1].enabled, true); assert.equal(f.requests.length, 1);
});
for (const failed of [false, true]) test(`old full Save ${failed ? 'failure' : 'success'} cannot replace newer Off ACK`, async () => {
  const f = fixture(undefined, true); f.edit('AnnotationNote', 'submitted'); const saving = f.c.saveMatchReplaceRules();
  f.on('rule-a', false); f.respond(1); await tick();
  const saved = plain(f.state.matchReplaceSavedRules), draft = plain(f.state.matchReplaceRules);
  if (failed) { f.requests[0].resolve({ ok: false }); await assert.rejects(saving); }
  else { f.respond(0); assert.equal(await saving, false); }
  assert.deepEqual(plain(f.state.matchReplaceSavedRules), saved); assert.deepEqual(plain(f.state.matchReplaceRules), draft);
});
for (const carried of [false, true]) test(`healthy pending On survives cross-row Off${carried ? ' and its original request failure' : ''}`, async () => {
  const f = fixture([rule({ id: 'a', enabled: false }), rule({ id: 'b' }), rule({ id: 'c' })], true);
  f.edit('AnnotationNote', 'draft'); f.on('a', true); f.on('b', false);
  assert.equal(f.requests[1].body.rules[0].enabled, true);
  if (carried) { f.requests[0].resolve({ ok: false }); await tick(); }
  f.on('c', false); assert.equal(f.requests[2].body.rules[0].enabled, true);
  f.respond(2); await tick(); f.respond(1); await tick(); if (!carried) { f.respond(0); await tick(); }
  assert.equal(f.state.matchReplaceSavedRules[0].enabled, true);
});
for (const failed of [false, true]) test(`explicit Off retires older On composition after its ${failed ? 'failure' : 'success'}`, async () => {
  const f = fixture([rule({ id: 'a', enabled: false }), rule({ id: 'c' })], true);
  f.edit('AnnotationNote', 'draft'); f.on('a', true); f.on('a', false); f.respond(1); await tick();
  if (failed) f.requests[0].resolve({ ok: false }); else f.respond(0); await tick();
  f.on('c', false); assert.equal(f.requests[2].body.rules[0].enabled, false);
  f.respond(2); await tick(); assert.equal(f.state.matchReplaceSavedRules[0].enabled, false);
});
test('a covering ACK does not retire an older physical Off barrier', async () => {
  const f = fixture([rule({ id: 'a' }), rule({ id: 'b' })], true); f.edit('AnnotationNote', 'draft');
  f.on('a', false); f.on('b', false); f.respond(1); await tick(); f.on('a', true);
  assert.equal(f.requests.length, 2); await assert.rejects(f.c.saveMatchReplaceRules());
  f.respond(0); await tick(); assert.equal(f.requests.length, 2, 'no queued activation');
  const saving = f.c.saveMatchReplaceRules(); f.respond(2); assert.equal(await saving, true);
});
test('new/deleted editor rows never change pending switch membership or submitted fields', async () => {
  const f = fixture([rule({ id: 'a' }), rule({ id: 'b' })], true); f.edit('AnnotationNote', 'draft'); f.on('a', false);
  f.state.matchReplaceRules = [f.state.matchReplaceRules[0], rule({ id: 'new' })]; f.c.renderMatchReplaceRules();
  f.on('new', false); assert.equal(f.requests.length, 1);
  f.on('a', false); assert.deepEqual(f.requests[1].body.rules.map(r => r.id), ['a', 'b']);
  assert.equal(f.requests[1].body.rules[0].annotation_note, undefined);
  f.respond(1); await tick(); f.respond(0); await tick();
  assert.deepEqual(f.state.matchReplaceRules.map(r => r.id), ['a', 'new']);
});
test('duplicate IDs retain existing first-row toggle behavior with positional activity accounting', async () => {
  const f = fixture([rule(), rule({ search: 'second.example.com' })], true); f.edit('AnnotationNote', 'draft'); f.on('rule-a', false);
  assert.deepEqual(f.requests[0].body.rules.map(r => r.enabled), [false, true]);
  f.respond(0); await tick(); assert.deepEqual(f.state.matchReplaceSavedRules.map(r => r.enabled), [false, true]);
});

for (const reset of ['generation', 'session']) test(`old owner settlement cannot decrement a new owner's Off count: ${reset}`, async () => {
  const f = fixture(undefined, true); f.on('rule-a', false); const oldOwner = f.state.matchReplaceSaveOwner;
  if (reset === 'generation') f.c.workspaceStateGeneration++; else f.state.activeSession.id = 'session-b';
  f.state.matchReplaceRules = [rule()]; f.state.matchReplaceSavedRules = [rule()]; f.state.matchReplaceDirty = false;
  f.state.matchReplaceEditorSessionId = f.state.activeSession.id; f.c.renderMatchReplaceRules(); f.on('rule-a', false);
  const owner = f.state.matchReplaceSaveOwner; assert.notEqual(owner, oldOwner); f.respond(0); await tick();
  assert.equal(owner.pendingWriteCount, 1); assert.equal(owner.activity[0].off, 1);
  f.respond(1); await tick(); assert.equal(owner.pendingWriteCount, 0); assert.equal(owner.activity.length, 0);
});
test('pending configuration/counters retain at most 500 rows and release at settlement', async () => {
  const f = fixture(Array.from({ length: 500 }, (_, i) => rule({ id: `r-${i}`, enabled: false })), true);
  f.edit('AnnotationNote', 'draft'); f.on('r-0', false);
  assert.equal(f.state.matchReplaceSaveOwner.rules.length, 500); assert.equal(f.state.matchReplaceSaveOwner.activity.length, 500);
  f.on('r-499', true); assert.equal(f.requests.length, 1);
  f.respond(0); await tick(); assert.equal(f.state.matchReplaceSaveOwner.rules, null); assert.equal(f.state.matchReplaceSaveOwner.activity.length, 0);
  f.state.matchReplaceRules.push(rule({ id: 'over-limit' })); await assert.rejects(f.c.saveMatchReplaceRules());
  assert.equal(f.requests.length, 1);
});
test('an old active settlement never decrements a newer post-Off On epoch', async () => {
  const f = fixture([rule({ id: 'a', enabled: false }), rule({ id: 'c' })], true); f.edit('AnnotationNote', 'draft');
  f.on('a', true); f.on('a', false); f.respond(1); await tick(); f.on('a', true);
  f.requests[0].resolve({ ok: false }); await tick(); f.on('c', false);
  assert.equal(f.requests[3].body.rules[0].enabled, true);
  f.respond(3); await tick(); f.respond(2); await tick(); assert.equal(f.state.matchReplaceSavedRules[0].enabled, true);
});
test('Off remains pending while response JSON is unresolved', async () => {
  const f = fixture(undefined, true); f.on('rule-a', false); let resolve;
  const body = new Promise(r => { resolve = r; }); f.requests[0].resolve({ ok: true, json: () => body }); await tick();
  f.on('rule-a', true); await assert.rejects(f.c.saveMatchReplaceRules()); assert.equal(f.requests.length, 1);
  resolve(f.requests[0].body.rules); await tick(); assert.equal(f.requests.length, 1);
  assert.equal(f.state.matchReplaceRules[0].enabled, true); assert.equal(f.state.matchReplaceSavedRules[0].enabled, false);
});
test('an explicit foreign session save response never adopts into the current editor', async () => {
  const f = fixture(undefined, true); f.state.matchReplaceDirty = false;
  const before = plain(f.state.matchReplaceRules), saving = f.c.saveMatchReplaceRules({ sessionId: 'session-other' });
  f.respond(0, [rule({ id: 'foreign' })]); assert.equal(await saving, false);
  assert.deepEqual(plain(f.state.matchReplaceRules), before); assert.equal(f.state.matchReplaceSavedRules[0].id, 'rule-a');
});
