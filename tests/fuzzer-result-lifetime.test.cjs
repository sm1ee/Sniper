// Passive saved-job display only. No run handler, payload generation, backend,
// transport, timers or workspace writes execute in this fixture.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function element(id, initialClasses = '') {
  const handlers = new Map(), classes = new Set(initialClasses.split(/\s+/).filter(Boolean));
  return { id, value: '', textContent: '', innerHTML: '', dataset: {}, scrollTop: 0, clientHeight: 180,
    classList: { add: value => classes.add(value), remove: value => classes.delete(value),
      contains: value => classes.has(value), toggle(value, on = !classes.has(value)) {
        if (on) classes.add(value); else classes.delete(value);
      } },
    addEventListener(type, handler) { handlers.set(type, handler); },
    dispatch(type, event = {}) { return handlers.get(type)?.({ target: this, preventDefault() {}, ...event }); },
    setAttribute() {}, focus() {}, querySelector: () => null, querySelectorAll: () => [], closest: () => null,
  };
}
const job = (id = 'saved-job-a', status = 'completed') => ({ id, status, payload_count: 3, marker_count: 1,
  results: [
    { index: 0, payload: 'synthetic-row-a', transaction_id: 'saved-tx-a', status: 200, duration_ms: 1, response_bytes: 1 },
    { index: 1, payload: 'synthetic-row-b', transaction_id: 'saved-tx-b', status: 201, duration_ms: 2, response_bytes: 2 },
    { index: 2, payload: 'synthetic-no-transaction', note: 'No saved transaction.' },
  ] });
const record = (id = 'saved-tx-a', label = 'current') => ({ id, kind: 'http', host: 'example.com', method: 'GET',
  path: `/${label}`, status: 200, http_version: 'HTTP/1.1',
  request: { headers: [], body_preview: '' }, response: { headers: [], body_preview: label, content_type: 'text/plain' } });
const response = (value, status = 200) => ({ ok: status < 400, status, json: async () => value,
  headers: { get: () => 'text/plain' }, text: async () => 'Synthetic read error.' });
function fixture() {
  const nodes = new Map(), requests = [], panes = new Map(), previews = [], logs = [];
  for (const [, attrs, id] of html.matchAll(/<[^>]*\b([^>]*\bid="([^"]+)"[^>]*)>/g)) {
    nodes.set(id, element(id, attrs.match(/\bclass="([^"]*)"/)?.[1]));
  }
  const els = Object.fromEntries(nodes), shell = element('resultsShell');
  assert.ok(els.fuzzerDetailPanel.classList.contains('hidden'));
  els.fuzzerResultsBody.closest = selector => selector === '.history-table-shell' ? shell : null;
  const document = { getElementById: id => nodes.get(id), querySelectorAll: () => [] };
  const state = { activeTool: 'fuzzer', activeSession: { id: 'session-a' } };
  // Use the production initial values rather than inventing request tokens.
  vm.runInNewContext(`Object.assign(state, {${appSource.slice(appSource.indexOf('  fuzzerBaseRequest: null,'), appSource.indexOf('  oastTokenClearPending:'))}})`, { state });
  let saves = 0;
  const c = loadFunctions([
    'fuzzerResultsWorkflowState', 'fuzzerResultMetric', 'fuzzerResultFilterValidation', 'visibleFuzzerResults', 'renderFuzzerResultsWorkflow',
    'fuzzerSelectedTransactionId', 'cancelPendingFuzzerComparison',
    'currentSessionId', 'sessionQueryPath', 'transactionPath', 'jsonArray', 'escapeHtml', 'formatStatus', 'formatSize',
    'renderFuzzer', 'fuzzerSelectionKeyForResult', 'fuzzerSelectedResultIndex', 'fuzzerResultsShell',
    'renderEmptyFuzzerResults', 'renderFuzzerResultsVirtual', 'scrollFuzzerResultToIndex', 'selectFuzzerResultIndex',
    'selectFuzzerRow', 'normalizeFuzzerAttackRecord', 'setFuzzerAttackRecord', 'clearFuzzerAttackRecord',
    'fuzzerWorkspaceAttackRecordId', 'applyFuzzerWorkspace', 'hydrateFuzzerAttackRecordById', 'showFuzzerResultDetail', 'hideFuzzerDetailPanel',
    'clearFuzzerResponsePane', 'syncFuzzerResponsePreview', 'syncFuzzerDetailTabs', 'renderFuzzerDetailPanes',
    'buildRawRequest', 'buildRawResponse', 'buildRawRequestHead', 'buildRawResponseHead', 'normalizedHeaders',
    'mergeHeaders', 'headerNameEquals', 'renderBody', 'binaryBodyPlaceholder', 'prettyFormat', 'prettyJsonText',
    'resetFuzzer', 'invalidateFuzzerRun', 'updateFuzzerRequestText', 'markFuzzerDraftChanged',
    'requireOkResponse', 'readApiErrorMessage', 'retireFindingActionProgress', 'invalidateFindingNavigation', 'setActiveTool', 'renderToolPanels',
  ], {
    compareBaseId: null, compareBaseSessionId: null, compareLoadGeneration: 0,
    state, els, document, mainTabs: [], _fuzzerDetailViewModes: { request: 'raw', response: 'raw' },
    FUZZER_RESULT_ROW_HEIGHT: 30, FUZZER_RESULT_BUFFER_ROWS: 5, measuredFuzzerResultRowHeight: 30,
    console: { error: (...args) => logs.push(args) },
    getCMView: () => null, addCMUpdateListener() {},
    updateCodePaneCM: (key, container, text) => panes.set(key, text),
    renderResponsePreview: (...args) => previews.push(args), recordPageUrl: () => 'https://example.com/',
    scheduleWorkspaceStateSave() { saves++; }, scheduleUiSettingsSave() {}, closeScannerSettings() {},
    sanitizeActiveTool: value => value, renderProxyPanels() {},
    requestAnimationFrame: callback => { callback(); return 1; },
    fetch(url, options) {
      assert.equal(options, undefined, 'Only mocked read-only saved-record requests are permitted');
      assert.match(url, /^\/api\/(transactions|fuzzer\/attacks)\/[^?]+\?session_id=/);
      const request = { url, ...deferred() }; requests.push(request); return request.promise;
    },
  });
  for (const name of ['_fuzzerDetailGeneration', '_fuzzerAttackLoadGeneration']) {
    const declaration = appSource.match(new RegExp(`^let ${name} = 0;$`, 'm'))?.[0];
    if (declaration) vm.runInContext(declaration, c);
  }
  const start = appSource.indexOf('  // Fuzzer results shell (for keyboard navigation + focus)');
  const end = appSource.indexOf('  // Fuzzer detail view mode tabs', start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(`(() => { ${appSource.slice(start, end)} })()`, c);
  const resetBinding = appSource.match(/^  els\.resetFuzzerButton\.addEventListener\(\"click\", resetFuzzer\);$/m)?.[0];
  assert.ok(resetBinding); vm.runInContext(resetBinding, c);
  // This is only the saved-result display initialization branch. No snapshot
  // serialization, revision, save, or persistence code is loaded.
  vm.runInContext(`function restoreSavedJob(snapshot) {
    applyFuzzerWorkspace({ fuzzerAttackRecordId: fuzzerWorkspaceAttackRecordId(snapshot.fuzzer), legacyAttackRecord: null }, snapshot.session_id);
    renderFuzzer();
  }`, c);
  const resetStart = appSource.indexOf('  state.fuzzerRunToken =', appSource.indexOf('function resetSessionScopedUiState()'));
  const resetEnd = appSource.indexOf('  state.sequenceDefinitions =', resetStart);
  assert.ok(resetStart >= 0 && resetEnd > resetStart);
  vm.runInContext(`function resetSessionDisplay() { ${appSource.slice(resetStart, resetEnd)} renderFuzzer(); }`, c);
  c.setFuzzerAttackRecord(job()); c.renderToolPanels();
  return { c, state, els, shell, requests, panes, previews, logs, get saves() { return saves; },
    click(index) {
      const rowMatch = [...els.fuzzerResultsBody.innerHTML.matchAll(/<tr class="fuzzer-result-row[^"]*"([^>]+)>/g)]
        .find(([, attrs]) => attrs.includes(`data-row-index="${index}"`));
      assert.ok(rowMatch, `Expected rendered result row ${index}`);
      const dataset = {};
      for (const [, name, value] of rowMatch[1].matchAll(/data-([a-z-]+)="([^"]*)"/g)) {
        dataset[name.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
      }
      els.fuzzerResultsBody.dispatch('click', { target: { closest: () => ({ dataset }) } });
      return requests.at(-1);
    },
    key: key => shell.dispatch('keydown', { key }),
    navigate(tool) { c.setActiveTool(tool); c.renderToolPanels(); },
    restore(id = 'saved-job-a') { c.restoreSavedJob({ session_id: state.activeSession.id, fuzzer: { attack_record_id: id } }); return requests.at(-1); },
    reset() { els.resetFuzzerButton.dispatch('click'); },
    resetSession(id) { state.activeSession = { id }; c.resetSessionDisplay(); },
  };
}
function assertCurrent(f, label = 'current') {
  assert.equal(f.state._fuzzerDetailRecord?.path, `/${label}`);
  assert.match(f.panes.get('fuzzerDetailReq'), new RegExp(`GET /${label} HTTP/1.1`));
  assert.match(f.panes.get('fuzzerDetailRes'), new RegExp(label));
  assert.equal(f.state._selectedFuzzerResultKey, 'tx:saved-tx-a');
}
for (const stage of ['fetch', 'json']) for (const outcome of ['success', 'failure', 'http-error']) {
  if (stage === 'json' && outcome === 'http-error') continue;
  test(`row A → B → A ignores the first ${stage} ${outcome}`, async () => {
    const f = fixture(), old = f.click(0), body = deferred();
    if (stage === 'json') { old.resolve({ ok: true, json: () => body.promise }); await tick(); }
    f.key('ArrowDown'); f.key('ArrowUp');
    assert.equal(f.requests.length, 3);
    f.requests[2].resolve(response(record())); await tick(); assertCurrent(f);
    if (outcome === 'failure') (stage === 'json' ? body : old).reject(new Error('Old detail failure'));
    else if (outcome === 'http-error') old.resolve(response(null, 500));
    else if (stage === 'json') body.resolve(record('saved-tx-a', 'stale'));
    else old.resolve(response(record('saved-tx-a', 'stale')));
    await tick(); assertCurrent(f);
  });
}
for (const stage of ['fetch', 'json']) test(`new session rejects an old ${stage} failure even when the row key matches`, async () => {
  const f = fixture(), old = f.click(0), body = deferred();
  if (stage === 'json') { old.resolve({ ok: true, json: () => body.promise }); await tick(); }
  // A session ID can change before the normal UI reset finishes.
  f.state.activeSession = { id: 'session-b' };
  (stage === 'json' ? body : old).reject(new Error('Old session failure'));
  await tick();
  assert.equal(f.panes.get('fuzzerDetailReq'), 'Loading transaction...');
  assert.equal(f.state._fuzzerDetailRecord, null);
});
for (const boundary of ['reset', 'no-transaction', 'empty-results', 'hide-detail']) test(`${boundary} drops late detail work`, async () => {
  const f = fixture(), old = f.click(0);
  if (boundary === 'reset') f.reset();
  else if (boundary === 'no-transaction') f.click(2);
  else if (boundary === 'empty-results') { f.c.setFuzzerAttackRecord({ ...job(), results: [] }); f.c.renderFuzzer(); }
  else f.c.hideFuzzerDetailPanel();
  const previous = f.panes.get('fuzzerDetailReq');
  old.resolve(response(record('saved-tx-a', 'stale'))); await tick();
  assert.equal(f.state._fuzzerDetailRecord, null);
  assert.equal(f.panes.get('fuzzerDetailReq'), previous);
});
for (const status of ['completed', 'failed']) test(`saved ${status} job keeps its terminal status and enabled controls`, () => {
  const f = fixture(); f.c.setFuzzerAttackRecord(job('saved-job-a', status)); f.c.renderFuzzer();
  assert.equal(f.els.fuzzerMeta.textContent, `3 payloads · 1 position · ${status}`);
  assert.equal(f.els.startFuzzerButton.disabled, false); assert.equal(f.els.resetFuzzerButton.disabled, false);
  assert.equal(f.requests.length, 0);
});
test('switching tools keeps a selected saved result without revealing the hidden Fuzzer', async () => {
  const f = fixture(), read = f.click(0); f.navigate('proxy');
  read.resolve(response(record())); await tick();
  assert.equal(f.state.activeTool, 'proxy'); assert.equal(f.els.fuzzerShell.classList.contains('hidden'), true);
  f.navigate('fuzzer'); assertCurrent(f);
});
test('current read errors stay visible and a later selection clears their pending state', async () => {
  const f = fixture(); f.click(0).resolve(response(null, 404)); await tick();
  assert.equal(f.panes.get('fuzzerDetailReq'), 'Failed to load transaction: 404');
  assert.equal(f.panes.get('fuzzerDetailRes'), '');
  f.click(0).resolve(response(record())); await tick(); assertCurrent(f);
});
test('selection tracks transaction identity when rendering order changes', async () => {
  const f = fixture(); f.click(0).resolve(response(record())); await tick();
  f.c.fuzzerResultsWorkflowState().sort = "index";
  f.c.fuzzerResultsWorkflowState().direction = "desc"; f.c.renderFuzzerResultsVirtual();
  assert.equal(f.c.fuzzerSelectedResultIndex(), 2); assertCurrent(f);
  f.key('ArrowUp'); assert.equal(f.state._selectedFuzzerResultKey, 'tx:saved-tx-b');
});
for (const stage of ['fetch', 'json']) for (const outcome of ['success', 'failure', 'missing']) {
  if (stage === 'json' && outcome === 'missing') continue;
  test(`saved-job A → B → A ignores the first ${stage} ${outcome}`, async () => {
    const f = fixture(), old = f.restore(), body = deferred();
    if (stage === 'json') { old.resolve({ ok: true, json: () => body.promise }); await tick(); }
    f.restore('saved-job-b'); const current = f.restore();
    current.resolve(response(job('saved-job-a', 'failed'))); await tick();
    assert.match(f.els.fuzzerMeta.textContent, /failed$/);
    if (outcome === 'failure') (stage === 'json' ? body : old).reject(new Error('Old job load failure'));
    else if (outcome === 'missing') old.resolve(response(null, 404));
    else if (stage === 'json') body.resolve(job());
    else old.resolve(response(job()));
    await tick(); assert.equal(f.state.fuzzerAttackRecord?.status, 'failed');
    assert.match(f.els.fuzzerMeta.textContent, /failed$/); assert.equal(f.state.fuzzerNotice, '');
  });
}
for (const outcome of ['missing', 'failure']) test(`the current saved-job ${outcome} replaces its loading notice`, async () => {
  const f = fixture(), read = f.restore();
  assert.equal(f.els.fuzzerMeta.textContent, 'Loading saved fuzzer run...');
  if (outcome === 'missing') read.resolve(response(null, 404)); else read.reject(new Error('Current job load failure'));
  await tick(); assert.equal(f.state.fuzzerAttackRecord, null);
  assert.equal(f.els.fuzzerMeta.textContent, outcome === 'missing' ? 'Saved fuzzer run is no longer available.' : 'Current job load failure');
});
test('Reset abandons a saved-job load without a request or late error notice', async () => {
  const f = fixture(), read = f.restore(); f.reset();
  read.reject(new Error('Abandoned job error')); await tick();
  assert.equal(f.requests.length, 1); assert.equal(f.state.fuzzerNotice, '');
  assert.equal(f.els.fuzzerMeta.textContent, '');
});

for (const stage of ['fetch', 'json']) for (const outcome of ['success', 'failure']) {
  test(`session A → B → A fences a former detail ${stage} ${outcome}`, async () => {
    const f = fixture(), old = f.click(0), body = deferred();
    if (stage === 'json') { old.resolve({ ok: true, json: () => body.promise }); await tick(); }
    f.resetSession('session-b'); f.resetSession('session-a');
    f.c.setFuzzerAttackRecord(job()); f.c.renderFuzzer();
    f.click(0).resolve(response(record())); await tick();
    if (outcome === 'failure') (stage === 'json' ? body : old).reject(new Error('Former session error'));
    else if (stage === 'json') body.resolve(record('saved-tx-a', 'stale'));
    else old.resolve(response(record('saved-tx-a', 'stale')));
    await tick(); assertCurrent(f);
  });
}
for (const outcome of ['success', 'failure', 'missing']) test(`session reset fences former saved-job ${outcome}`, async () => {
  const f = fixture(), old = f.restore();
  f.resetSession('session-b'); f.resetSession('session-a');
  f.restore().resolve(response(job('saved-job-a', 'failed'))); await tick();
  if (outcome === 'failure') old.reject(new Error('Former job error'));
  else old.resolve(response(job(), outcome === 'missing' ? 404 : 200));
  await tick(); assert.equal(f.state.fuzzerAttackRecord?.status, 'failed');
  assert.equal(f.state.fuzzerNotice, '');
});
test('a newly loaded saved job rejects detail work owned by the previous job', async () => {
  const f = fixture(), old = f.click(0);
  f.restore('saved-job-b').resolve(response(job('saved-job-b'))); await tick();
  f.click(0).resolve(response(record())); await tick();
  old.resolve(response(record('saved-tx-a', 'stale'))); await tick(); assertCurrent(f);
});
