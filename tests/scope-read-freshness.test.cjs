// Exact production readers with deferred responses. No bootstrap, browser or network.
const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const runtime = (fresh = false, scope = 'same.example.com') => ({
  scope_patterns: [scope], excluded_scope_patterns: [], intercept_enabled: fresh,
});
const paths = label => [{ host: `${label}.example.com`, schemes: ['https'], request_count: 0,
  in_scope: false, paths: [{ path: `/${label}`, methods: ['GET'], captured: false,
    discovered: true, recon_sources: ['crawler'], recon_kinds: ['candidate'], status: null }] }];
const pairs = [['scope', 'scope'], ['scope', 'runtime'], ['runtime', 'scope'], ['runtime', 'runtime']];
function fixture() {
  const requests = [], renders = [], scopeChanges = [], toasts = [], refreshes = [];
  const state = { activeTool: 'target', activeSession: { id: 'session-a' }, _runtimeWrites: 0,
    runtime: runtime(), targetSiteMap: paths('cached'), targetExpandedHosts: new Set(['cached.example.com']),
    targetScopeDraft: 'same.example.com', targetScopeExcludeDraft: '', targetScopeDirty: false,
    targetScopeEditorSessionId: 'session-a', targetScopeDraftVersion: 0, targetScopeSaveToken: 0 };
  const els = { targetScopeEditor: { value: 'same.example.com' }, targetScopeExcludeEditor: { value: '' },
    targetTree: { innerHTML: '', dataset: {}, querySelectorAll: () => [] },
    targetShell: { classList: { contains: () => false } },
    saveTargetScopeButton: { classList: { toggle() {} } } };
  const context = loadFunctions(['currentSessionId', 'expectedActiveSessionIdForWrite', 'sessionQueryPath',
    'postRuntimeSettings', 'formatScopePatternsText', 'syncTargetScopeDraft', 'loadRuntimeSettings',
    'loadTargetSiteMap', 'saveTargetScope', 'renderTarget'], {
    state, els, workspaceStateGeneration: 0, document: { activeElement: null, body: {} },
    escapeHtml: String, formatTimestamp: String, formatStatus: String,
    fetch(url, options) { const request = { url, options, ...deferred() }; requests.push(request); return request.promise; },
    requireOkResponse: async response => { if (!response.ok) throw response.error; }, jsonArray: value => value,
    targetServiceMapController: { scopeChanged: (...args) => scopeChanges.push(args), refresh: () => refreshes.push('map') },
    templatesController: { scopeChanged: () => refreshes.push('templates') },
    renderInterceptStatus: () => renders.push('intercept'), renderProxySettings: () => renders.push('proxy'),
    renderTarget: () => renders.push('target'), showToast: (...args) => toasts.push(args),
    invalidateVisibleEntriesCache: () => refreshes.push('cache'), scheduleRefresh: () => refreshes.push('history'),
  });
  const renderTarget = context.renderTarget;
  context.renderTarget = (...args) => { renders.push('target'); return renderTarget(...args); };
  function start(kind, ...args) {
    const offset = requests.length;
    const promise = kind === 'scope' ? context.loadTargetSiteMap(...args)
      : kind === 'runtime' ? context.loadRuntimeSettings() : context.saveTargetScope(...args);
    return { kind, requests: requests.slice(offset), settled: promise.then(value => ({ value }), error => ({ error })) };
  }
  function reply(batch, fresh = false, options = {}) {
    const value = options.runtime || runtime(fresh);
    const map = options.paths || paths(fresh ? 'new' : 'old');
    batch.requests.forEach((request, index) => request.resolve({ ok: true,
      json: () => options.delay && index === options.delayIndex ? options.delay.promise
        : Promise.resolve(request.url.startsWith('/api/target/site-map') ? map : value) }));
  }
  function fail(batch, mode, error = new Error(`Synthetic ${mode} failure`)) {
    batch.requests.forEach((request, index) => {
      if (index !== 0) request.resolve({ ok: true, json: async () => paths('unused') });
      else if (mode === 'network') request.reject(error);
      else request.resolve({ ok: mode !== 'http', error,
        json: async () => { throw error; } });
    });
    return error;
  }
  function edit(value, mode = 'edit') {
    if (mode !== 'model') els.targetScopeEditor.value = value;
    if (mode !== 'dom') state.targetScopeDraft = value;
    if (mode === 'edit') { state.targetScopeDraftVersion++; state.targetScopeDirty = true; }
  }
  return { context, state, els, requests, renders, scopeChanges, toasts, refreshes, start, reply, fail, edit };
}
async function successful(batch) {
  const result = await batch.settled;
  assert.equal(result.error, undefined);
  assert.notEqual(result.value, false, 'Freshness-only suppression is not ownership failure');
  return result.value;
}
for (const [first, second] of pairs) {
  const label = `${first} → ${second}`;
  test(`${label}: newer accepted read wins reverse completion`, async () => {
    const f = fixture(), old = f.start(first), newer = f.start(second);
    f.reply(newer, true); await successful(newer);
    const accepted = { runtime: f.state.runtime, paths: f.state.targetSiteMap, renders: f.renders.length, scopes: f.scopeChanges.length };
    f.reply(old); await successful(old);
    assert.equal(f.state.runtime, accepted.runtime);
    assert.equal(f.state.targetSiteMap, accepted.paths, 'A stale compound read cannot attach old scope badges');
    assert.equal(f.renders.length, accepted.renders);
    assert.equal(f.scopeChanges.length, accepted.scopes);
  });
  test(`${label}: ordinary completion and pending newer body preserve useful results`, async () => {
    const f = fixture(), old = f.start(first), newer = f.start(second), body = deferred();
    f.reply(newer, true, { delay: body, delayIndex: 0 }); await tick();
    f.reply(old); await successful(old);
    assert.equal(f.state.runtime.intercept_enabled, false);
    body.resolve(runtime(true)); await successful(newer);
    assert.equal(f.state.runtime.intercept_enabled, true);
  });
  test(`${label}: delayed older JSON cannot overwrite the newer acceptance`, async () => {
    const f = fixture(), old = f.start(first), body = deferred();
    f.reply(old, false, { delay: body, delayIndex: 0 }); await tick();
    const newer = f.start(second); f.reply(newer, true); await successful(newer);
    const accepted = f.state.runtime;
    body.resolve(runtime()); await successful(old);
    assert.equal(f.state.runtime, accepted);
  });
  for (const mode of ['http', 'json', 'network']) {
    test(`${label}: newer ${mode} failure does not suppress older success or retry`, async () => {
      const f = fixture(), old = f.start(first), newer = f.start(second);
      const error = f.fail(newer, mode); assert.equal((await newer.settled).error, error);
      f.reply(old); await successful(old);
      assert.equal(f.state.runtime.intercept_enabled, false);
      const retry = f.start(second); f.reply(retry, true); await successful(retry);
      assert.equal(f.state.runtime.intercept_enabled, true);
    });
    test(`${label}: obsolete ${mode} error after newer acceptance is a successful no-op`, async () => {
      const f = fixture(), old = f.start(first), newer = f.start(second);
      f.reply(newer, true); await successful(newer);
      const accepted = f.state.runtime, count = f.renders.length;
      f.fail(old, mode); await successful(old);
      assert.equal(f.state.runtime, accepted); assert.equal(f.renders.length, count);
    });
  }
}
for (const kind of ['scope', 'runtime']) {
  for (const change of ['session', 'generation', 'write-start', 'write-finish']) {
    test(`${kind}: ${change} still invalidates an old read`, async () => {
      const f = fixture(), old = f.start(kind), accepted = runtime(true);
      if (change === 'session') f.state.activeSession = { id: 'session-b' };
      if (change === 'generation') f.context.workspaceStateGeneration++;
      if (change === 'write-start') f.state._runtimeWrites++;
      if (change === 'write-finish') f.state._runtimeWrites += 2;
      f.state.runtime = accepted;
      f.reply(old);
      const result = await old.settled;
      assert.equal(result.error, undefined); assert.equal(f.state.runtime, accepted);
      assert.equal(f.renders.length, 0);
      if (kind === 'scope') assert.equal(result.value, false);
    });
  }
}
test('Scope map JSON body has its own post-body freshness guard', async () => {
  const f = fixture(), old = f.start('scope'), body = deferred();
  f.reply(old, false, { delay: body, delayIndex: 1 }); await tick();
  const newer = f.start('scope'); f.reply(newer, true); await successful(newer);
  const accepted = f.state.targetSiteMap;
  body.resolve(paths('old')); await successful(old);
  assert.equal(f.state.targetSiteMap, accepted);
});
test('obsolete forced Scope refresh preserves a dirty draft and current expansion selection', async () => {
  const f = fixture(), old = f.start('scope', true);
  f.edit('unsaved.example.com');
  const newer = f.start('scope'); f.reply(newer, true); await successful(newer);
  f.state.targetExpandedHosts = new Set(['new.example.com']);
  const acceptedPaths = f.state.targetSiteMap, count = f.renders.length;
  f.reply(old, false, { runtime: runtime(false, 'old.example.com') }); await successful(old);
  assert.equal(f.state.targetScopeDraft, 'unsaved.example.com'); assert.equal(f.state.targetScopeDirty, true);
  assert.equal(f.els.targetScopeEditor.value, 'unsaved.example.com');
  assert.equal(f.state.targetSiteMap, acceptedPaths); assert.deepEqual([...f.state.targetExpandedHosts], ['new.example.com']);
  assert.equal(f.renders.length, count);
});
test('hidden Scope stale read is suppressed and return read can reconcile normally', async () => {
  const f = fixture(), old = f.start('scope', true);
  f.state.activeTool = 'templates';
  const newer = f.start('runtime'); f.reply(newer, true); await successful(newer);
  const accepted = f.state.runtime;
  f.reply(old); await successful(old); assert.equal(f.state.runtime, accepted);
  assert.equal(f.state.targetSiteMap[0].host, 'cached.example.com');
  f.state.activeTool = 'target';
  const returning = f.start('scope'); f.reply(returning, true); await successful(returning);
  assert.equal(f.state.targetSiteMap[0].host, 'new.example.com');
});
async function beginSavedRefresh(f) {
  f.state.targetScopeDirty = true;
  const saving = f.start('save');
  assert.equal(saving.requests.length, 1); assert.equal(saving.requests[0].options.method, 'POST');
  f.reply(saving); await tick();
  assert.equal(f.requests.length, 3);
  return { saving, followup: { requests: f.requests.slice(1) } };
}
for (const pollKind of ['scope', 'runtime']) {
  for (const result of ['success', 'http', 'json', 'network']) {
    test(`acknowledged save keeps success after harmless ${pollKind} poll supersedes ${result} follow-up`, async () => {
      const f = fixture(), { saving, followup } = await beginSavedRefresh(f);
      const poll = f.start(pollKind); f.reply(poll, true); await successful(poll);
      if (result === 'success') f.reply(followup); else f.fail(followup, result);
      assert.equal(await successful(saving), true);
      assert.equal(f.state.runtime.intercept_enabled, true); assert.equal(f.state.targetScopeDirty, false);
      assert.equal(f.state.targetScopeDraft, 'same.example.com'); assert.equal(f.toasts.length, 0);
      assert.ok(f.refreshes.includes('history'));
    });
  }
}
for (const mode of ['edit', 'dom', 'model', 'generation', 'save-token']) {
  test(`freshness no-op never masks genuine saved-draft ownership loss: ${mode}`, async () => {
    const f = fixture(), { saving, followup } = await beginSavedRefresh(f);
    const poll = f.start('scope'); f.reply(poll, true); await successful(poll);
    if (mode === 'generation') f.context.workspaceStateGeneration++;
    else if (mode === 'save-token') f.state.targetScopeSaveToken++;
    else f.edit('unsaved.example.com', mode);
    const accepted = { runtime: f.state.runtime, draft: f.state.targetScopeDraft, text: f.els.targetScopeEditor.value };
    f.reply(followup);
    const result = await saving.settled;
    assert.equal(result.error, undefined); assert.equal(result.value, false);
    assert.equal(f.state.runtime, accepted.runtime); assert.equal(f.state.targetScopeDraft, accepted.draft);
    assert.equal(f.els.targetScopeEditor.value, accepted.text);
    assert.equal(f.toasts.length, mode === 'generation' ? 0 : 1);
  });
}

for (const field of ['include', 'exclude']) {
  for (const mode of ['input', 'dom', 'model']) {
    test(`one forced Scope read preserves a later ${field} ${mode} edit through actual renderTarget`, async () => {
      const f = fixture(), reading = f.start('scope', true);
      const key = field === 'include' ? 'targetScopeDraft' : 'targetScopeExcludeDraft';
      const node = field === 'include' ? f.els.targetScopeEditor : f.els.targetScopeExcludeEditor;
      if (mode !== 'model') node.value = 'unsaved.example.com';
      if (mode !== 'dom') f.state[key] = 'unsaved.example.com';
      if (mode === 'input') { f.state.targetScopeDraftVersion++; f.state.targetScopeDirty = true; }
      f.reply(reading, true, { runtime: runtime(true, 'server.example.com') });
      await successful(reading);
      assert.equal(f.state[key], 'unsaved.example.com'); assert.equal(node.value, 'unsaved.example.com');
      assert.equal(f.state.targetScopeDirty, true);
      assert.equal(f.state.runtime.scope_patterns[0], 'server.example.com');
      assert.equal(f.state.targetSiteMap[0].host, 'new.example.com');
      assert.match(f.els.targetTree.innerHTML, /new.example.com/);
    });
  }
}
test('hide and return forced Scope read retains an already-owned dirty draft', async () => {
  const f = fixture(); f.edit('unsaved.example.com');
  f.state.targetScopeExcludeDraft = 'excluded.example.com'; f.els.targetScopeExcludeEditor.value = 'excluded.example.com';
  f.state.activeTool = 'templates'; f.state.activeTool = 'target';
  const reading = f.start('scope', true); f.reply(reading, true, { runtime: runtime(true, 'server.example.com') });
  await successful(reading);
  assert.equal(f.state.targetScopeDraft, 'unsaved.example.com'); assert.equal(f.els.targetScopeEditor.value, 'unsaved.example.com');
  assert.equal(f.state.targetScopeExcludeDraft, 'excluded.example.com'); assert.equal(f.els.targetScopeExcludeEditor.value, 'excluded.example.com');
  assert.equal(f.state.targetScopeDirty, true); assert.equal(f.state.targetScopeEditorSessionId, 'session-a');
  assert.match(f.els.targetTree.innerHTML, /new.example.com/);
});
test('an owned DOM/model drift already present at dispatch remains editable', async () => {
  const f = fixture(); f.els.targetScopeEditor.value = 'unsaved.example.com';
  const reading = f.start('scope', true); f.reply(reading, true); await successful(reading);
  assert.equal(f.state.targetScopeDraft, 'unsaved.example.com'); assert.equal(f.els.targetScopeEditor.value, 'unsaved.example.com');
  assert.equal(f.state.targetScopeDirty, true);
});
for (const owner of ['clean-current', 'stale-different-session']) {
  test(`forced Scope read still reconciles ${owner} editor`, async () => {
    const f = fixture();
    if (owner === 'stale-different-session') {
      f.state.targetScopeEditorSessionId = 'previous-session'; f.state.targetScopeDirty = true;
      f.state.targetScopeDraft = f.els.targetScopeEditor.value = 'previous.example.com';
    }
    const reading = f.start('scope', true); f.reply(reading, true, { runtime: runtime(true, 'server.example.com') });
    await successful(reading);
    assert.equal(f.state.targetScopeDraft, 'server.example.com'); assert.equal(f.els.targetScopeEditor.value, 'server.example.com');
    assert.equal(f.state.targetScopeDirty, false); assert.equal(f.state.targetScopeEditorSessionId, 'session-a');
  });
}
