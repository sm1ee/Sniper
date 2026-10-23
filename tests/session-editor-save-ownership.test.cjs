// Passive editor metadata only. Production persistence/input helpers run in a VM;
// all responses are deferred data. Rules are disabled with empty match/replacement.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { loadFunctions, appSource } = require('./frontend-test-helpers.cjs');
const { deferred } = require('./replay-workspace-fixture.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
const earlierSaveMessage = /earlier (draft|save)|save response belongs/i;
function fixture(kind) {
  const requests = [], toasts = [], renders = [];
  const rule = { id: 'synthetic-rule', enabled: false, description: '', scope: 'request',
    target: 'any', search: '', replace: '', regex: false, case_sensitive: false };
  const state = { activeTool: 'target', activeTargetView: 'paths', activeSession: { id: 'session-a' }, runtime: {}, targetScopeDraft: 'example.com',
    targetScopeExcludeDraft: '', targetScopeDirty: true, targetScopeEditorSessionId: 'session-a',
    targetScopeDraftVersion: 0, matchReplaceRules: [{ ...rule }], selectedMatchReplaceRuleId: rule.id,
    matchReplaceDirty: true, matchReplaceEditorSessionId: 'session-a', matchReplaceDraftVersion: 0 };
  const input = value => ({ value, listeners: {}, addEventListener(name, callback) { this.listeners[name] = callback; } });
  const els = { targetScopeEditor: input('example.com'), targetScopeExcludeEditor: input(''), saveTargetScopeButton: { classList: { remove() {}, toggle() {} } },
    matchReplaceScope: input('request'), matchReplaceTarget: input('any'), matchReplaceSearch: input(''),
    matchReplaceReplace: input(''), matchReplaceRegex: { checked: false }, matchReplaceCaseSensitive: { checked: false } };
  const context = loadFunctions(['currentSessionId', 'expectedActiveSessionIdForWrite', 'sessionWritePath',
    'sessionQueryPath', 'saveTargetScope', 'postRuntimeSettings', 'saveMatchReplaceRules', 'formatScopePatternsText', 'jsonArray',
    'syncMatchReplaceEditor', 'getSelectedMatchReplaceRule', 'flushTargetScopeDraft', 'flushMatchReplaceDraft',
    'loadTargetSiteMap', 'syncTargetScopeDraft', 'deleteSelectedMatchReplaceRule', 'canLeaveSessionAfterDraftPreflight',
    'preserveActiveHttpReplayDraftBeforeSessionChange', 'getRenderedHttpReplayDraftOwner', 'saveMatchReplaceSwitch',
    'matchReplaceRuleUnsaved'], {
    state, els, workspaceStateGeneration: 0, workspaceSaveConflictPending: false, URLSearchParams,
    workspaceLoaded: false, renderedHttpReplayDraftOwner: null, getActiveReplayTab: () => null,
    requireOkResponse: async response => { if (!response.ok) throw response.error; },
    showToast: (...args) => toasts.push(args), console: { error() {} },
    renderMatchReplaceRules: () => renders.push('rules'), renderTarget: () => renders.push('scope'),
    renderInterceptStatus() {}, renderProxySettings() {}, invalidateVisibleEntriesCache() {}, scheduleRefresh() {},
    fetch(url, options) { const request = { url, options, ...deferred() }; requests.push(request); return request.promise; },
  });
  for (const marker of ['  els.targetScopeEditor.addEventListener("input", () => {',
    '  els.targetScopeExcludeEditor?.addEventListener("input", () => {']) {
    const binding = appSource.slice(appSource.indexOf(marker));
    vm.runInContext(binding.slice(0, binding.indexOf('\n  });') + 6), context);
  }
  const edit = value => {
    if (kind === 'scope') { els.targetScopeEditor.value = value; els.targetScopeEditor.listeners.input(); }
    else { els.matchReplaceCaseSensitive.checked = value; context.syncMatchReplaceEditor(); }
  };
  const draft = () => kind === 'scope' ? state.targetScopeDraft : state.matchReplaceRules[0].case_sensitive;
  const dirty = () => kind === 'scope' ? state.targetScopeDirty : state.matchReplaceDirty;
  const save = options => kind === 'scope' ? context.saveTargetScope({ skipReload: true, ...options }) : context.saveMatchReplaceRules(options);
  const flush = () => kind === 'scope' ? context.flushTargetScopeDraft() : context.flushMatchReplaceDraft();
  const success = (index, body) => requests[index].resolve({ ok: true, json: async () => body ?? (kind === 'scope'
    ? { scope_patterns: ['example.com'], excluded_scope_patterns: [] } : [{ ...rule }]) });
  return { context, state, els, requests, toasts, renders, rule, edit, draft, dirty, save, flush, success };
}
for (const kind of ['scope', 'rules']) {
  const original = kind === 'scope' ? 'example.com' : false, newer = kind === 'scope' ? 'new.example.com' : true;
  for (const mode of ['edit', 'edit then revert', 'same-ID generation', 'different owner', 'programmatic model']) {
    test(`${kind}: ${mode} retains current metadata after old success`, async () => {
      const f = fixture(kind), saving = f.save();
      const dispatched = f.requests[0].options.body;
      if (mode === 'different owner') f.state.activeSession = { id: 'session-b' };
      if (mode === 'same-ID generation') f.context.workspaceStateGeneration++;
      if (mode === 'programmatic model') {
        if (kind === 'scope') f.els.targetScopeEditor.value = 'new.example.com';
        else f.state.matchReplaceRules[0].case_sensitive = true;
      } else if (mode === 'edit' || mode === 'edit then revert') {
        f.edit(newer); if (mode === 'edit then revert') f.edit(original);
      }
      const before = { draft: f.draft(), dirty: f.dirty(), rules: f.state.matchReplaceRules,
        text: f.els.targetScopeEditor.value, renders: f.renders.length };
      f.success(0); assert.equal(await saving, false);
      assert.equal(f.requests[0].options.body, dispatched, 'dispatch payload is immutable');
      assert.equal(f.draft(), before.draft); assert.equal(f.dirty(), before.dirty);
      assert.equal(f.state.matchReplaceRules, before.rules); assert.equal(f.els.targetScopeEditor.value, before.text);
      assert.equal(f.renders.length, before.renders); assert.equal(f.requests.length, 1);
      assert.equal(f.toasts.length, ['different owner', 'same-ID generation'].includes(mode) ? 0 : 1);
    });
  }
  test(`${kind}: current unchanged success still acknowledges and clears dirty`, async () => {
    const f = fixture(kind), saving = f.save(); f.success(0); assert.notEqual(await saving, false);
    assert.equal(f.dirty(), false); assert.equal(f.toasts.length, 0);
  });
  test(`${kind}: a newer accepted identical save supersedes older response settlement`, async () => {
    const f = fixture(kind), older = f.save(), latest = f.save();
    f.success(1); assert.notEqual(await latest, false);
    const before = { rules: f.state.matchReplaceRules, runtime: f.state.runtime, renders: f.renders.length };
    f.success(0); assert.equal(await older, false);
    assert.equal(f.state.matchReplaceRules, before.rules); assert.equal(f.state.runtime, before.runtime);
    assert.equal(f.renders.length, before.renders); assert.equal(f.dirty(), false);
  });
  for (const pending of [true, false]) test(`${kind}: newer ${pending ? 'pending' : 'failed'} identical attempt conservatively supersedes older settlement`, async () => {
    const f = fixture(kind), older = f.save(), error = new Error('Synthetic failure');
    const latest = f.save().then(value => value, caught => caught);
    if (!pending) { f.requests[1].reject(error); assert.equal(await latest, error); }
    f.success(0); assert.equal(await older, false); assert.equal(f.dirty(), true); assert.equal(f.toasts.length, 1);
    if (pending) { f.success(1); assert.notEqual(await latest, false); }
  });
  test(`${kind}: older response cannot replace newer acknowledged edits or make them dirty`, async () => {
    const f = fixture(kind), older = f.save(); f.edit(newer); const latest = f.save();
    const response = kind === 'scope' ? { scope_patterns: [newer], excluded_scope_patterns: [] } : [{ ...f.rule, case_sensitive: true }];
    f.success(1, response); assert.notEqual(await latest, false); assert.equal(f.dirty(), false);
    f.success(0); assert.equal(await older, false); assert.equal(f.draft(), newer); assert.equal(f.dirty(), false);
  });
  test(`${kind}: newer edit while response JSON is pending is checked after decoding`, async () => {
    const f = fixture(kind), body = deferred(), saving = f.save();
    f.requests[0].resolve({ ok: true, json: () => body.promise }); await tick(); f.edit(newer);
    body.resolve(kind === 'scope' ? { scope_patterns: ['example.com'] } : [{ ...f.rule }]);
    assert.equal(await saving, false); assert.equal(f.draft(), newer); assert.equal(f.dirty(), true);
  });
  test(`${kind}: flush wrapper propagates superseded false instead of permitting reset`, async () => {
    const f = fixture(kind), flushing = f.flush(); f.edit(newer); f.success(0);
    assert.equal(await flushing, false); assert.equal(f.draft(), newer); assert.equal(f.dirty(), true);
    assert.match(f.toasts[0][0], earlierSaveMessage);
  });
  test(`${kind}: rejected save preserves a newer draft and identical error`, async () => {
    const f = fixture(kind), error = new Error('Synthetic rejected save');
    const saving = f.save().then(() => null, caught => caught); f.edit(newer); f.requests[0].reject(error);
    assert.equal(await saving, error); assert.equal(f.draft(), newer); assert.equal(f.dirty(), true);
  });
}
test('scope: raw whitespace normalization only settles an unchanged draft', async () => {
  const f = fixture('scope'); f.edit('  example.com  '); const saving = f.save();
  f.success(0); assert.notEqual(await saving, false); assert.equal(f.els.targetScopeEditor.value, 'example.com');
  assert.equal(f.state.targetScopeDirty, false); assert.equal(f.toasts.length, 0);
});
for (const value of ['', ' example.com ', 'example.com\n']) test(`scope: raw change ${JSON.stringify(value)} while saving is retained`, async () => {
  const f = fixture('scope'), saving = f.save(); f.edit(value); f.success(0);
  assert.equal(await saving, false); assert.equal(f.els.targetScopeEditor.value, value); assert.equal(f.state.targetScopeDraft, value);
});
test('scope: excluded raw edit and revert increments ownership version', async () => {
  const f = fixture('scope'), saving = f.save();
  for (const value of ['excluded.example.com', '']) { f.els.targetScopeExcludeEditor.value = value; f.els.targetScopeExcludeEditor.listeners.input(); }
  f.success(0); assert.equal(await saving, false); assert.equal(f.state.targetScopeDirty, true);
});
for (const mode of ['same-ID generation', 'new edit', 'newer accepted save', 'DOM-only edit', 'model-only edit']) test(`scope: optional read cannot settle across ${mode}`, async () => {
  const f = fixture('scope'), saving = f.save({ skipReload: false }); f.success(0); await tick();
  assert.equal(f.requests.length, 3);
  if (mode === 'same-ID generation') {
    f.context.workspaceStateGeneration++; f.state.runtime = { scope_patterns: ['fresh.example.com'] };
    f.state.targetScopeDraft = 'fresh.example.com'; f.els.targetScopeEditor.value = 'fresh.example.com';
  } else if (mode === 'DOM-only edit') f.els.targetScopeEditor.value = 'new.example.com';
  else if (mode === 'model-only edit') f.state.targetScopeDraft = 'new.example.com';
  else {
    f.edit('new.example.com');
    if (mode === 'newer accepted save') { const newer = f.save(); f.success(3, { scope_patterns: ['new.example.com'], excluded_scope_patterns: [] }); assert.notEqual(await newer, false); }
  }
  const before = { runtime: f.state.runtime, draft: f.state.targetScopeDraft, dirty: f.state.targetScopeDirty,
    text: f.els.targetScopeEditor.value, renders: f.renders.length };
  f.success(1); f.success(2, []); assert.equal(await saving, false);
  assert.equal(f.state.runtime, before.runtime); assert.equal(f.state.targetScopeDraft, before.draft);
  assert.equal(f.state.targetScopeDirty, before.dirty); assert.equal(f.els.targetScopeEditor.value, before.text);
  assert.equal(f.renders.length, before.renders);
});
test('scope: optional unchanged read permits normal canonicalization and success', async () => {
  const f = fixture('scope'); f.edit('  example.com  '); const saving = f.save({ skipReload: false });
  f.success(0); await tick(); f.success(1); f.success(2, []);
  assert.notEqual(await saving, false); assert.equal(f.state.targetScopeDraft, 'example.com'); assert.equal(f.toasts.length, 0);
});
function bindSaveButton(f, kind) {
  f.els.saveTargetScopeButton = { classList: { remove() {}, toggle() {} } }; f.els.saveMatchReplaceRuleButton = {};
  f.context.onClickWithProgress = (_, handler) => { f.clickSave = handler; };
  f.context.updateMatchReplaceSaveState = () => {};
  const start = kind === 'scope' ? '  onClickWithProgress(els.saveTargetScopeButton, () =>' : '  onClickWithProgress(els.saveMatchReplaceRuleButton, () => {';
  const end = kind === 'scope' ? '  els.targetScopeEditor.addEventListener' : '  els.addMatchReplaceRuleButton.addEventListener';
  const binding = appSource.slice(appSource.indexOf(start)); vm.runInContext(binding.slice(0, binding.indexOf(end)), f.context);
}
for (const kind of ['scope', 'rules']) {
  for (const changed of [false, true]) test(`${kind}: actual Save callback ${changed ? 'does not claim newer draft saved' : 'keeps ordinary success feedback'}`, async () => {
    const f = fixture(kind); bindSaveButton(f, kind); const saving = f.clickSave();
    if (changed) f.edit(kind === 'scope' ? 'new.example.com' : true);
    f.success(0); await tick();
    if (changed) assert.equal(f.requests.length, 1, 'superseded save must not start an extra reload');
    if (kind === 'scope' && !changed) { f.success(1); f.success(2, []); }
    await saving;
    assert.equal(f.toasts.length, 1);
    if (changed) { assert.match(f.toasts[0][0], earlierSaveMessage); assert.equal(f.dirty(), true); }
    else assert.equal(f.toasts[0][0], kind === 'scope' ? 'Scope saved' : 'Rule saved');
  });
  test(`${kind}: a same-value input event leaves an unchanged save eligible`, async () => {
    const f = fixture(kind), saving = f.save(); f.edit(kind === 'scope' ? 'example.com' : false);
    f.success(0); assert.notEqual(await saving, false); assert.equal(f.toasts.length, 0);
  });
  test(`${kind}: current flush rejection keeps existing error feedback and refuses navigation`, async () => {
    const f = fixture(kind), flushing = f.flush(); f.requests[0].reject(new Error('Synthetic original failure'));
    assert.equal(await flushing, false); assert.equal(f.toasts[0][0], 'Synthetic original failure'); assert.equal(f.dirty(), true);
  });
}
for (const changed of [false, true]) test(`rules: Delete ${changed ? 'preserves a later edit without false success' : 'retains its normal success feedback'}`, async () => {
  const f = fixture('rules'); f.state.matchReplaceRules.unshift({ ...f.rule, id: 'synthetic-deleted' });
  f.state.selectedMatchReplaceRuleId = 'synthetic-deleted'; const deleting = f.context.deleteSelectedMatchReplaceRule();
  assert.equal(f.state.matchReplaceDraftVersion, 1);
  assert.equal(JSON.parse(f.requests[0].options.body).rules.every(rule => !rule.enabled && !rule.search && !rule.replace), true);
  if (changed) f.edit(true);
  f.success(0); await deleting; assert.equal(f.toasts.length, 1);
  if (changed) { assert.match(f.toasts[0][0], earlierSaveMessage); assert.equal(f.draft(), true); assert.equal(f.dirty(), true); }
  else assert.equal(f.toasts[0][0], 'Rule deleted');
});
for (const kind of ['scope', 'rules']) for (const changed of [false, true]) {
  test(`${kind}: external reload ${changed ? 'stops on a retained newer edit' : 'keeps a rightful unchanged bypass save'}`, async () => {
    const f = fixture(kind), later = [];
    f.state[kind === 'scope' ? 'matchReplaceDirty' : 'targetScopeDirty'] = false;
    vm.runInContext(appSource.match(/^async function handleExternalSessionChanged\([^]*?^\}/m)[0], f.context);
    Object.assign(f.context, { flushSequenceDraftBeforeExternalSessionReload: async () => true,
      flushAllPendingAnnotations: async () => later.push('annotations'), hasPendingWorkspaceStateSave: () => false,
      cleanupWsReplayTabsBeforeStateReset: async () => later.push('cleanup'), reloadSessionWorkspace: async () => later.push('reload') });
    f.context[kind === 'scope' ? 'flushMatchReplaceDraft' : 'flushTargetScopeDraft'] = async () => true;
    const reloading = f.context.handleExternalSessionChanged('session-a'); await tick();
    if (kind === 'scope') assert.equal(JSON.parse(f.requests[0].options.body).expected_active_session_id, null);
    else assert.equal(new URL(f.requests[0].url, 'http://example.com').searchParams.has('expected_active_session_id'), false);
    if (changed) f.edit(kind === 'scope' ? 'new.example.com' : true);
    f.success(0); await reloading;
    assert.deepEqual(later, changed ? [] : ['annotations', 'cleanup', 'reload']);
    assert.equal(f.dirty(), changed); assert.equal(f.requests.length, 1);
  });
}
for (const changed of [false, true]) test(`scope: ordinary loader ${changed ? 'ignores a prior generation' : 'retains its existing manual read behavior'}`, async () => {
  const f = fixture('scope'); f.state.targetScopeDirty = false;
  const reading = f.context.loadTargetSiteMap(true); if (changed) f.context.workspaceStateGeneration++;
  const before = f.state.runtime; f.success(0, { scope_patterns: ['fresh.example.com'], excluded_scope_patterns: [] }); f.success(1, []);
  await reading;
  if (changed) { assert.equal(f.state.runtime, before); assert.equal(f.state.targetScopeDraft, 'example.com'); }
  else assert.equal(f.state.targetScopeDraft, 'fresh.example.com');
});
for (const failed of [false, true]) test(`scope: optional read stays superseded by a newer ${failed ? 'failed' : 'pending'} identical attempt`, async () => {
  const f = fixture('scope'), old = f.save({ skipReload: false }); f.success(0); await tick();
  const newer = f.save().then(value => value, error => error), error = new Error('Synthetic latest failure');
  if (failed) { f.requests[3].reject(error); assert.equal(await newer, error); }
  const before = f.state.runtime; f.success(1); f.success(2, []);
  assert.equal(await old, false); assert.equal(f.state.runtime, before); assert.equal(f.toasts.length, 1);
  if (!failed) { f.success(3); assert.notEqual(await newer, false); }
});
test('rules: new-rule construction advances version without changing dirty or autosaving', () => {
  const f = fixture('rules'); f.state.matchReplaceDirty = false;
  f.context.generateUuid = () => 'synthetic-new-rule';
  vm.runInContext(appSource.match(/^function createNewMatchReplaceRule\([^]*?^\}/m)[0], f.context);
  f.context.createNewMatchReplaceRule();
  assert.equal(f.state.matchReplaceDraftVersion, 1); assert.equal(f.state.matchReplaceDirty, false);
  assert.equal(f.state.matchReplaceRules.length, 2); assert.equal(f.state.selectedMatchReplaceRuleId, 'synthetic-new-rule');
  assert.equal(f.requests.length, 0, 'construction never dispatches the default enabled definition');
});
test('rules: actual checkbox callback versions mutations but keeps no-op and dirty semantics', async () => {
  const f = fixture('rules'); f.state.matchReplaceDirty = false; let callback, saves = 0;
  f.state.matchReplaceSavedRules = [{ ...f.rule }];
  const toggle = { checked: false, dataset: { ruleToggle: f.rule.id }, addEventListener(_, listener) { callback = listener; } };
  f.els.matchReplaceTableBody = { querySelectorAll: () => [toggle] };
  // Structural UI counter test only: no enabled definition is persisted or run.
  f.context.saveMatchReplaceRules = async () => { saves++; };
  const marker = '  Array.from(els.matchReplaceTableBody.querySelectorAll("[data-rule-toggle]")).forEach((toggle) => {';
  const binding = appSource.slice(appSource.indexOf(marker));
  vm.runInContext(binding.slice(0, binding.indexOf('\n  });') + 6), f.context);
  for (const [checked, version] of [[false, 0], [true, 1], [true, 1], [false, 2]]) {
    toggle.checked = checked; callback({ stopPropagation() {} }); await tick();
    assert.equal(f.state.matchReplaceDraftVersion, version); assert.equal(f.state.matchReplaceDirty, false);
  }
  assert.equal(saves, 4); assert.equal(f.requests.length, 0); assert.equal(f.state.matchReplaceRules[0].enabled, false);
});
