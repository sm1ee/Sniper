// Synthetic retained-record reads only. The run/transport handlers are never loaded.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function node(id) {
  const listeners = new Map(), classes = new Set(['hidden']);
  return { id, value: '', innerHTML: '', textContent: '', disabled: false, scrollTop: 0, clientHeight: 90,
    addEventListener(type, fn) { listeners.set(type, fn); },
    dispatch(type, event = {}) { return listeners.get(type)?.({ target: this, preventDefault() {}, ...event }); },
    classList: { add: x => classes.add(x), remove: x => classes.delete(x), contains: x => classes.has(x),
      toggle(x, force = !classes.has(x)) { if (force) classes.add(x); else classes.delete(x); return force; } },
    attributes: {}, setAttribute(name, value) { this.attributes[name] = value; }, setCustomValidity(message) { this.validationMessage = message; }, focus() { this.focused = true; }, closest: () => null, querySelector: () => null,
  };
}
const result = (index, status = 200, bytes = index, duration = index) => ({ index, payload: `synthetic-${index}`,
  transaction_id: `tx-${index}`, status, response_bytes: bytes, duration_ms: duration });
const run = (id = 'run-a', results = [result(0), result(1)]) => ({ id, status: 'completed', marker_count: 1,
  payload_count: results.length, results, started_at: '2026-01-01T00:00:00Z',
  template: { scheme: 'https', host: 'example.com', path: '/$payload$', method: 'GET', headers: [], body: '' } });
const response = (body, status = 200) => ({ ok: status < 400, status, json: async () => body,
  headers: { get: () => 'text/plain' }, text: async () => 'Synthetic read failure.' });
function fixture() {
  const ids = ['fuzzerResultStatus', 'fuzzerResultMinBytes', 'fuzzerResultMaxBytes', 'fuzzerResultMinMs', 'fuzzerResultMaxMs',
    'fuzzerResultSort', 'fuzzerResultDirection', 'fuzzerResultFilterCount',
    'fuzzerResultFilterBadge', 'fuzzerResultFilterSummary', 'fuzzerClearResultFiltersButton', 'fuzzerResultStatusRow', 'fuzzerCompareBaseButton', 'fuzzerCompareButton',
    'fuzzerSavedRunSelect', 'fuzzerRefreshRunsButton', 'fuzzerViewRunButton', 'fuzzerReuseRunButton', 'fuzzerSavedRunNotice',
    'fuzzerRequestEditor', 'fuzzerPayloadsEditor', 'fuzzerResultsBody', 'fuzzerDetailPanel', 'fuzzerDetailReqCM',
    'fuzzerDetailResCM', 'fuzzerDetailResponseMeta', 'fuzzerMeta', 'startFuzzerButton', 'resetFuzzerButton',
    'fuzzerDetailResizer', 'compareModal', 'closeCompareButton', 'compareWithBaseBtn'];
  const els = Object.fromEntries(ids.map(id => [id, node(id)])), shell = node('shell');
  els.fuzzerResultsBody.closest = () => shell;
  const state = { activeSession: { id: 'session-a' }, fuzzerDraftVersion: 0, fuzzerRunToken: 0,
    fuzzerRequestText: 'GET /typed HTTP/2\nHost: example.com', fuzzerPayloadsText: 'typed-payload', fuzzerNotice: 'typed notice',
    fuzzerBaseRequest: { host: 'example.com', path: '/typed', method: 'GET' }, fuzzerSourceTransactionId: 'source-draft',
    fuzzerTarget: { host: 'example.com', port: 8443 }, fuzzerTargetRequestText: 'https://example.com' };
  const requests = [], confirmations = [], panes = new Map(), toasts = [];
  let saves = 0, compares = 0;
  const newNames = appSource.slice(appSource.indexOf('function fuzzerResultsWorkflowState()'), appSource.indexOf('function fuzzerSelectionKeyForResult'))
    .match(/^(?:async )?function (\w+)/gm).map(line => line.match(/function (\w+)/)[1]);
  const c = loadFunctions([...newNames,
    'currentSessionId', 'sessionQueryPath', 'transactionPath', 'jsonArray', 'escapeHtml', 'formatStatus', 'formatSize',
    'renderFuzzer', 'fuzzerSelectionKeyForResult', 'fuzzerSelectedResultIndex', 'fuzzerResultsShell', 'renderEmptyFuzzerResults',
    'renderFuzzerResultsVirtual', 'scrollFuzzerResultToIndex', 'selectFuzzerResultIndex', 'selectFuzzerRow',
    'normalizeFuzzerAttackRecord', 'setFuzzerAttackRecord', 'clearFuzzerAttackRecord', 'showFuzzerResultDetail', 'hideFuzzerDetailPanel',
    'clearFuzzerResponsePane', 'invalidateFuzzerRun', 'resetFuzzer', 'updateFuzzerRequestText', 'updateFuzzerPayloadsText', 'markFuzzerDraftChanged',
    'requireOkResponse', 'readApiErrorMessage', 'cloneEditableRequest', 'buildEditableRawRequest', 'normalizedHeaders', 'mergeHeaders', 'headerNameEquals',
    'setCompareBase', 'openCompareModal', 'closeCompareModal', 'splitFuzzerPayloadLines', 'retireFindingActionProgress', 'invalidateFindingNavigation', 'setActiveTool',
  ], { state, els, TextEncoder, document: { getElementById: id => els[id], activeElement: null },
    _fuzzerAttackLoadGeneration: 0, _fuzzerDetailGeneration: 0,
    compareBaseId: null, compareBaseSessionId: null, compareLoadGeneration: 0,
    compareBaseRecord: null, compareTargetRecord: null, compareActiveTab: 'request', compareReturnFocus: null,
    measuredFuzzerResultRowHeight: 30, FUZZER_RESULT_ROW_HEIGHT: 30, FUZZER_RESULT_BUFFER_ROWS: 1,
    sanitizeActiveTool: value => value, closeScannerSettings() {}, scheduleUiSettingsSave() {},
    getCMView: () => null, renderFuzzerRequestHighlight() {}, renderFuzzerDetailPanes() {}, syncFuzzerResponsePreview() {},
    updateCodePaneCM: (key, _, value) => panes.set(key, value), scheduleWorkspaceStateSave: () => saves++,
    showConfirmDialog: (message, confirm, options) => confirmations.push({ message, confirm, options }),
    getHistoryItem: () => null, getActiveModalAction: () => null, isModalVisible: el => !el.classList.contains('hidden'),
    renderCompareModal: () => compares++, clearCompareState() { throw new Error('Unexpected clear'); },
    showToast: message => toasts.push(message), console: { error() {} },
    requestAnimationFrame: callback => { callback(); return 1; },
    fetch(url, options) {
      assert.equal(options, undefined, 'This workflow must not start a run or use mutating requests.');
      assert.match(url, /^\/api\/(?:fuzzer\/attacks(?:\/[^?]+)?|transactions\/[^?]+)\?session_id=/);
      const request = { url, ...deferred() }; requests.push(request); return request.promise;
    },
  });
  c.initFuzzerResultsWorkflow();
  const start = appSource.indexOf('  // Fuzzer results shell (for keyboard navigation + focus)');
  const end = appSource.indexOf('  // Fuzzer detail view mode tabs', start);
  vm.runInContext(`(() => { ${appSource.slice(start, end)} })()`, c);
  c.setFuzzerAttackRecord(run()); c.renderFuzzer();
  return { c, state, els, shell, requests, confirmations, panes, toasts,
    get saves() { return saves; }, get compares() { return compares; },
    setFilter(id, value) { els[id].value = value; els[id].dispatch(/Status|Sort|Direction/.test(id) ? 'change' : 'input'); },
    pick(id) { els.fuzzerSavedRunSelect.value = id; els.fuzzerSavedRunSelect.dispatch('change'); },
    view() { return els.fuzzerViewRunButton.dispatch('click'); }, reuse() { return els.fuzzerReuseRunButton.dispatch('click'); },
    key(key) { shell.dispatch('keydown', { key }); },
    select(index) { c.selectFuzzerResultIndex(index, { scroll: false }); return requests.at(-1); },
    resetSession(id) { state.activeSession = { id }; c.clearFuzzerAttackRecord(); c.renderFuzzer(); },
  };
}
function draft(state) {
  return JSON.stringify(Object.fromEntries(['fuzzerBaseRequest', 'fuzzerSourceTransactionId', 'fuzzerTarget',
    'fuzzerTargetRequestText', 'fuzzerRequestText', 'fuzzerPayloadsText', 'fuzzerNotice', 'fuzzerDraftVersion', 'fuzzerRunToken'].map(key => [key, state[key]])));
}
function indexes(f) { return Array.from(f.c.visibleFuzzerResults(), entry => entry.sourceIndex); }

test('status, byte and time filters are local, inclusive and leave the run untouched', () => {
  const f = fixture(), saved = run('run-a', [result(0, 200, 0, 0), result(1, 204, 10, 5), result(2, 404, 20, 10),
    { index: 3, payload: 'error', status: null, response_bytes: 0, note: 'Not captured.' }, result(4, 503, 30, 20)]);
  f.c.setFuzzerAttackRecord(saved);
  f.setFilter('fuzzerResultStatus', '2xx'); assert.deepEqual(indexes(f), [0, 1]);
  f.setFilter('fuzzerResultMinBytes', '10'); f.setFilter('fuzzerResultMaxBytes', '10'); assert.deepEqual(indexes(f), [1]);
  f.setFilter('fuzzerResultMinMs', '5'); f.setFilter('fuzzerResultMaxMs', '5'); assert.deepEqual(indexes(f), [1]);
  f.setFilter('fuzzerResultStatus', 'error'); assert.deepEqual(indexes(f), []);
  for (const id of ['fuzzerResultMinBytes', 'fuzzerResultMaxBytes', 'fuzzerResultMinMs', 'fuzzerResultMaxMs']) f.setFilter(id, '');
  assert.deepEqual(indexes(f), [3]); assert.equal(f.els.fuzzerResultFilterCount.textContent, '1 of 5 results');
  assert.equal(saved.results.length, 5); assert.equal(f.requests.length, 0); assert.equal(f.saves, 0);
});
for (const [sort, values] of [['status', [200, 404]], ['bytes', [10, 20]], ['duration', [1, 2]]]) {
  test(`${sort} sorting has stable ties and puts unknown metrics last both ways`, () => {
    const f = fixture(), rows = [result(8), result(8), result(8), result(8)];
    const key = { status: 'status', bytes: 'response_bytes', duration: 'duration_ms' }[sort];
    [values[1], null, values[0], values[1]].forEach((value, i) => { rows[i][key] = value; });
    f.c.setFuzzerAttackRecord(run('run-a', rows)); f.setFilter('fuzzerResultSort', sort);
    assert.deepEqual(indexes(f), [2, 0, 3, 1]); f.setFilter('fuzzerResultDirection', 'desc');
    assert.deepEqual(indexes(f), [0, 3, 2, 1]);
  });
}
test('error rows with duplicate legacy indexes keep underlying identity after sort and keyboard navigation', () => {
  const f = fixture(); f.c.setFuzzerAttackRecord(run('run-a', [
    { index: 0, payload: 'first', duration_ms: 5, note: 'First error.' },
    { index: 0, payload: 'second', duration_ms: 10, note: 'Second error.' }, result(2, 200, 1, 1),
  ]));
  f.setFilter('fuzzerResultSort', 'duration'); f.setFilter('fuzzerResultDirection', 'desc');
  f.select(0); assert.equal(f.state._selectedFuzzerResultKey, 'row:1'); assert.equal(f.panes.get('fuzzerDetailReq'), 'Second error.');
  f.key('ArrowDown'); assert.equal(f.state._selectedFuzzerResultKey, 'row:0'); assert.equal(f.panes.get('fuzzerDetailReq'), 'First error.');
  f.setFilter('fuzzerResultDirection', 'asc'); assert.equal(f.c.fuzzerSelectedResultIndex(), 1);
  f.key('ArrowDown'); assert.equal(f.state._selectedFuzzerResultKey, 'row:1'); assert.equal(f.panes.get('fuzzerDetailReq'), 'Second error.');
  assert.equal(f.requests.length, 0);
});
test('filtering the selected row away clears details and rejects its late response', async () => {
  const f = fixture(), read = f.select(0);
  f.setFilter('fuzzerResultMinBytes', '1'); assert.equal(f.state._selectedFuzzerResultKey, null);
  assert.equal(f.els.fuzzerDetailPanel.classList.contains('hidden'), true);
  read.resolve(response({ id: 'tx-0' })); await tick(); assert.equal(f.state._fuzzerDetailRecord, null);
  f.key('ArrowDown'); assert.equal(f.state._selectedFuzzerResultKey, 'tx:tx-1');
});
test('virtualized arrow navigation follows the filtered sorted projection beyond the viewport', () => {
  const f = fixture(); f.c.setFuzzerAttackRecord(run('many', Array.from({ length: 1000 }, (_, i) => result(i))));
  f.setFilter('fuzzerResultMinBytes', '500'); f.setFilter('fuzzerResultSort', 'bytes'); f.setFilter('fuzzerResultDirection', 'desc');
  f.key('ArrowUp'); assert.equal(f.state._selectedFuzzerResultKey, 'tx:tx-500');
  assert.ok(f.shell.scrollTop > 10000); assert.match(f.els.fuzzerResultsBody.innerHTML, /data-source-index="500"/);
  assert.ok((f.els.fuzzerResultsBody.innerHTML.match(/class="fuzzer-result-row/g) || []).length < 10);
  f.key('ArrowUp'); assert.equal(f.state._selectedFuzzerResultKey, 'tx:tx-501');
});
test('with no results there is nothing to compare or count, and one empty message', () => {
  const f = fixture();
  for (const id of ['fuzzerCompareBaseButton', 'fuzzerCompareButton', 'fuzzerResultFilterCount']) {
    assert.equal(f.els[id].classList.contains('hidden'), false, id);
  }
  f.state.fuzzerNotice = '';
  f.c.clearFuzzerAttackRecord(); f.c.renderFuzzer();
  for (const id of ['fuzzerCompareBaseButton', 'fuzzerCompareButton', 'fuzzerResultFilterCount']) {
    assert.equal(f.els[id].classList.contains('hidden'), true, id);
  }
  assert.equal(f.els.fuzzerMeta.textContent, '');
  assert.match(f.els.fuzzerResultsBody.innerHTML, /Results appear here after running\./);
  // The row that holds the count and Clear filters leaves no gap until
  // one of them has something to show.
  assert.equal(f.els.fuzzerResultStatusRow.classList.contains('hidden'), true);
  f.setFilter('fuzzerResultMinBytes', '1');
  assert.equal(f.els.fuzzerResultStatusRow.classList.contains('hidden'), false);
  assert.equal(f.els.fuzzerClearResultFiltersButton.classList.contains('hidden'), false);
});

test('comparison requires a selected fetched transaction and uses existing pinned transaction reads', async () => {
  const f = fixture(); assert.equal(f.els.fuzzerCompareBaseButton.disabled, true);
  f.select(0).resolve(response({ id: 'tx-0' })); await tick();
  await f.els.fuzzerCompareBaseButton.dispatch('click'); assert.equal(f.c.compareBaseId, 'tx-0');
  assert.equal(f.els.fuzzerCompareButton.disabled, true);
  f.select(1); assert.equal(f.els.fuzzerCompareBaseButton.disabled, true);
  f.requests.at(-1).resolve(response({ id: 'tx-1' })); await tick(); assert.equal(f.els.fuzzerCompareButton.disabled, false);
  const compare = f.els.fuzzerCompareButton.dispatch('click');
  assert.match(f.requests.at(-2).url, /transactions\/tx-0\?session_id=session-a/);
  assert.match(f.requests.at(-1).url, /transactions\/tx-1\?session_id=session-a/);
  f.requests.at(-2).resolve(response({ id: 'tx-0' })); f.requests.at(-1).resolve(response({ id: 'tx-1' }));
  await compare; assert.equal(f.compares, 1);
});
test('changing selection while comparison loads prevents delayed modal reveal', async () => {
  const f = fixture(); f.select(0).resolve(response({ id: 'tx-0' })); await tick(); await f.c.useFuzzerComparisonBase();
  f.select(1).resolve(response({ id: 'tx-1' })); await tick(); const compare = f.c.compareSelectedFuzzerResult();
  const pending = f.requests.slice(-2); f.setFilter('fuzzerResultMaxBytes', '0');
  pending[0].resolve(response({ id: 'tx-0' })); pending[1].resolve(response({ id: 'tx-1' })); await compare;
  assert.equal(f.compares, 0);
});
test('Refresh lists only this session and escapes picker content without replacing the draft', async () => {
  const f = fixture(), before = draft(f.state), refresh = f.els.fuzzerRefreshRunsButton.dispatch('click');
  assert.equal(f.requests[0].url, '/api/fuzzer/attacks?session_id=session-a');
  f.requests[0].resolve(response([{ id: 'run-a', host: 'example.com', path: '/<script>', payload_count: 2 }]));
  await refresh; assert.match(f.els.fuzzerSavedRunSelect.innerHTML, /&lt;script&gt;/);
  assert.equal(draft(f.state), before); assert.equal(f.saves, 0);
});
test('View replaces results only, retaining every typed draft and provenance field', async () => {
  const f = fixture(), before = draft(f.state); f.pick('run-b'); const read = f.view();
  f.requests.at(-1).resolve(response(run('run-b'))); await read;
  assert.equal(f.state.fuzzerAttackRecordId, 'run-b'); assert.equal(draft(f.state), before);
  assert.equal(f.confirmations.length, 0); assert.match(f.els.fuzzerSavedRunNotice.textContent, /unchanged/);
});
for (const stage of ['fetch', 'json']) for (const outcome of ['success', 'failure', 'missing']) {
  if (stage === 'json' && outcome === 'missing') continue;
  test(`picker A → B → A ignores old ${stage} ${outcome}`, async () => {
    const f = fixture(); f.pick('run-a'); const first = f.view(), old = f.requests.at(-1), body = deferred();
    if (stage === 'json') { old.resolve({ ok: true, json: () => body.promise }); await tick(); }
    f.pick('run-b'); const second = f.view(); f.requests.at(-1).resolve(response(run('run-b'))); await second;
    f.pick('run-a'); const last = f.view(); f.requests.at(-1).resolve(response({ ...run('run-a'), status: 'failed' })); await last;
    if (outcome === 'failure') (stage === 'json' ? body : old).reject(new Error('Stale read error.'));
    else if (stage === 'json') body.resolve(run('run-a'));
    else old.resolve(response(run('run-a'), outcome === 'missing' ? 404 : 200));
    await first; assert.equal(f.state.fuzzerAttackRecord.status, 'failed');
    assert.doesNotMatch(f.els.fuzzerSavedRunNotice.textContent, /Stale|unavailable/);
  });
}
for (const boundary of ['draft', 'reset', 'session-bounce', 'new-run']) test(`pending View is fenced by ${boundary}`, async () => {
  const f = fixture(); f.pick('run-b'); const read = f.view(), pending = f.requests.at(-1);
  if (boundary === 'draft') f.c.updateFuzzerRequestText('GET /new HTTP/1.1', { userEdit: true });
  if (boundary === 'reset') f.c.resetFuzzer();
  if (boundary === 'session-bounce') { f.resetSession('session-b'); f.resetSession('session-a'); }
  if (boundary === 'new-run') f.state.fuzzerRunToken++;
  const before = draft(f.state); pending.resolve(response(run('run-b'))); await read;
  assert.notEqual(f.state.fuzzerAttackRecordId, 'run-b'); assert.equal(draft(f.state), before);
});
for (const boundary of ['draft', 'reset', 'session-bounce', 'new-run']) test(`pending Refresh is fenced by ${boundary}`, async () => {
  const f = fixture(), pending = f.c.refreshFuzzerSavedRuns(), read = f.requests.at(-1);
  if (boundary === 'draft') f.c.updateFuzzerPayloadsText('new', { userEdit: true });
  if (boundary === 'reset') f.c.resetFuzzer();
  if (boundary === 'session-bounce') { f.resetSession('session-b'); f.resetSession('session-a'); }
  if (boundary === 'new-run') f.state.fuzzerRunToken++;
  read.resolve(response([{ id: 'old-session-run' }])); await pending;
  assert.equal(f.c.fuzzerResultsWorkflowState().runs.length, 0);
});
test('Reuse waits for confirmation, clears unrelated transport/source and retains template HTTP version', async () => {
  const f = fixture(), before = draft(f.state), saved = run('run-b'); saved.template.http_version = 'HTTP/2';
  saved.results = [{ payload: 'a' }, { payload: '' }]; f.pick('run-b'); const read = f.reuse();
  f.requests.at(-1).resolve(response(saved)); await read;
  assert.equal(draft(f.state), before); assert.equal(f.confirmations.length, 1);
  assert.match(f.confirmations[0].message, /original raw formatting, source transaction and target override are unavailable/i);
  f.confirmations[0].confirm();
  assert.equal(f.state.fuzzerSourceTransactionId, null); assert.equal(f.state.fuzzerTarget, null);
  assert.equal(f.state.fuzzerTargetRequestText, null); assert.equal(f.state.fuzzerBaseRequest.http_version, 'HTTP/2');
  assert.match(f.state.fuzzerRequestText, /^GET \/\$payload\$ HTTP\/2/);
  assert.deepEqual(Array.from(f.c.splitFuzzerPayloadLines(f.state.fuzzerPayloadsText)), ['a', '']);
  assert.equal(f.state.fuzzerAttackRecord, null); assert.equal(f.requests.length, 1);
});
test('Reuse of a Sniper run restores its payload list once and its attack options', async () => {
  const f = fixture(), saved = run('run-b');
  // Two positions, each through the list [a, a]: the repeat is the operator's.
  saved.results = [{ payload: 'a', position: 0 }, { payload: 'a', position: 0 }, { payload: 'a', position: 1 }, { payload: 'a', position: 1 }];
  Object.assign(saved, { attack_type: 'sniper', payload_count: 2, marker_count: 2, url_encode: false, concurrency: 8 });
  f.pick('run-b'); const read = f.reuse();
  f.requests.at(-1).resolve(response(saved)); await read;
  f.confirmations[0].confirm();
  assert.deepEqual(Array.from(f.c.splitFuzzerPayloadLines(f.state.fuzzerPayloadsText)), ['a', 'a']);
  assert.deepEqual([f.state.fuzzerAttackType, f.state.fuzzerUrlEncode, f.state.fuzzerConcurrency], ['sniper', false, 8]);
});
for (const boundary of ['draft', 'reset', 'session-bounce', 'new-run', 'picker-bounce', 'new-view']) {
  test(`Reuse confirmation cannot replace newer work after ${boundary}`, async () => {
    const f = fixture(); f.pick('run-b'); const read = f.reuse(); f.requests.at(-1).resolve(response(run('run-b'))); await read;
    if (boundary === 'draft') f.c.updateFuzzerRequestText('GET /new HTTP/1.1', { userEdit: true });
    if (boundary === 'reset') f.c.resetFuzzer();
    if (boundary === 'session-bounce') { f.resetSession('session-b'); f.resetSession('session-a'); }
    if (boundary === 'new-run') f.state.fuzzerRunToken++;
    if (boundary === 'picker-bounce') { f.pick('run-a'); f.pick('run-b'); }
    if (boundary === 'new-view') { const newer = f.view(); f.requests.at(-1).resolve(response(run('run-b'))); await newer; }
    const before = draft(f.state); f.confirmations[0].confirm(); assert.equal(draft(f.state), before);
  });
}
test('current missing/error saved runs leave the visible run and draft intact', async () => {
  for (const status of [404, 500]) {
    const f = fixture(), before = draft(f.state); f.pick('missing'); const read = f.view();
    f.requests.at(-1).resolve(response(null, status)); await read;
    assert.equal(f.state.fuzzerAttackRecordId, 'run-a'); assert.equal(draft(f.state), before);
    assert.match(f.els.fuzzerSavedRunNotice.textContent, status === 404 ? /no longer available/ : /Synthetic read failure/);
    assert.equal(f.els.fuzzerViewRunButton.disabled, false);
  }
});
test('Reuse cannot silently split a retained multiline payload into extra requests', async () => {
  const f = fixture(), before = draft(f.state); f.pick('run-b'); const read = f.reuse();
  f.requests.at(-1).resolve(response(run('run-b', [{ payload: 'one\ntwo' }]))); await read;
  assert.equal(f.confirmations.length, 0); assert.equal(draft(f.state), before);
  assert.match(f.els.fuzzerSavedRunNotice.textContent, /line break/);
});

for (const boundary of ['request-bytes', 'payload-text-bytes', 'payload-count']) test(`Reuse refuses unsupported editor ${boundary} without altering the draft`, async () => {
  const f = fixture(), before = draft(f.state), saved = run('run-b');
  if (boundary === 'request-bytes') saved.template.body = 'a'.repeat(2 * 1024 * 1024);
  else if (boundary === 'payload-text-bytes') saved.results = Array.from({ length: 64 }, () => ({ payload: 'a'.repeat(65536) }));
  else saved.results = Array.from({ length: 5001 }, () => ({ payload: '' }));
  f.pick('run-b'); const read = f.reuse(); f.requests.at(-1).resolve(response(saved)); await read;
  assert.equal(f.confirmations.length, 0);
  assert.equal(draft(f.state), before);
  assert.match(f.els.fuzzerSavedRunNotice.textContent, /editor limits/);
});

for (const [id, value] of [['fuzzerResultMinBytes', '-1'], ['fuzzerResultMaxBytes', '1.5'], ['fuzzerResultMinMs', 'Infinity'], ['fuzzerResultMaxMs', 'oops'], ['fuzzerResultMaxBytes', '9007199254740992']]) {
  test(`invalid result filter ${id}=${value} is visible and cannot silently broaden results`, () => {
    const f = fixture(); f.setFilter(id, value);
    assert.deepEqual(indexes(f), []);
    assert.match(f.els.fuzzerResultFilterCount.textContent, /Invalid filters/);
    assert.equal(f.els[id].attributes['aria-invalid'], 'true');
    assert.ok(f.els[id].validationMessage);
    f.setFilter(id, '');
    assert.deepEqual(indexes(f), [0, 1]);
    assert.equal(f.els[id].attributes['aria-invalid'], 'false');
    assert.equal(f.els[id].validationMessage, '');
  });
}
for (const [min, max] of [['fuzzerResultMinBytes', 'fuzzerResultMaxBytes'], ['fuzzerResultMinMs', 'fuzzerResultMaxMs']]) test(`reversed ${min} range is reported and corrected without stale errors`, () => {
  const f = fixture(); f.setFilter(min, '20'); f.setFilter(max, '10');
  assert.deepEqual(indexes(f), []);
  assert.match(f.els.fuzzerResultFilterCount.textContent, /cannot exceed/);
  assert.equal(f.els[min].attributes['aria-invalid'], 'true');
  assert.equal(f.els[max].attributes['aria-invalid'], 'true');
  f.setFilter(min, '0'); f.setFilter(max, '10');
  assert.deepEqual(indexes(f), [0, 1]);
  assert.equal(f.els[min].attributes['aria-invalid'], 'false');
  assert.equal(f.els[max].attributes['aria-invalid'], 'false');
});
test('browser badInput is not treated as an empty filter and clears after correction', () => {
  const f = fixture(); f.els.fuzzerResultMaxBytes.validity = { badInput: true };
  f.setFilter('fuzzerResultMaxBytes', '');
  assert.deepEqual(indexes(f), []);
  assert.match(f.els.fuzzerResultFilterCount.textContent, /Invalid filters/);
  f.els.fuzzerResultMaxBytes.validity = { badInput: false };
  f.setFilter('fuzzerResultMaxBytes', '1');
  assert.deepEqual(indexes(f), [0, 1]);
});

// Navigation is an ownership boundary even when the user returns to Fuzzer.
for (const action of ['view', 'reuse', 'refresh']) for (const bounce of [false, true]) {
  test(`delayed ${action} ignores tool navigation${bounce ? ' and return' : ''}`, async () => {
    const f = fixture(); f.state.activeTool = 'fuzzer'; f.pick('run-b');
    const pending = action === 'refresh' ? f.c.refreshFuzzerSavedRuns() : f.c.readFuzzerSavedRun(action);
    const request = f.requests.at(-1), before = draft(f.state);
    f.c.setActiveTool('replay'); if (bounce) f.c.setActiveTool('fuzzer');
    request.resolve(response(action === 'refresh' ? [{ id: 'run-b' }] : run('run-b'))); await pending;
    assert.equal(f.confirmations.length, 0); assert.equal(draft(f.state), before);
    assert.equal(f.state.fuzzerAttackRecordId, 'run-a');
    assert.equal(f.c.fuzzerResultsWorkflowState().runs.length, 0);
    assert.equal(f.c.fuzzerResultsWorkflowState().readBusy, false);
    assert.equal(f.c.fuzzerResultsWorkflowState().listBusy, false);
  });
}
for (const outcome of ['success', 'failure']) for (const boundary of ['leave', 'return', 'session', 'cancel', 'reselect']) {
  test(`pending Fuzzer Compare ${outcome} is ignored after ${boundary}`, async () => {
    const f = fixture(); f.state.activeTool = 'fuzzer';
    f.select(0).resolve(response({ id: 'tx-0' })); await tick(); await f.c.useFuzzerComparisonBase();
    f.select(1).resolve(response({ id: 'tx-1' })); await tick();
    const pending = f.c.compareSelectedFuzzerResult(), requests = f.requests.slice(-2);
    if (boundary === 'leave' || boundary === 'return') {
      f.c.setActiveTool('replay'); if (boundary === 'return') f.c.setActiveTool('fuzzer');
    }
    if (boundary === 'session') { f.resetSession('session-b'); f.resetSession('session-a'); }
    if (boundary === 'cancel') f.c.closeCompareModal();
    if (boundary === 'reselect') { f.select(0); f.select(1); }
    if (outcome === 'success') {
      requests[0].resolve(response({ id: 'tx-0' })); requests[1].resolve(response({ id: 'tx-1' }));
    } else { requests[0].reject(new Error('Stale compare error.')); requests[1].resolve(response({ id: 'tx-1' })); }
    await pending;
    assert.equal(f.compares, 0); assert.equal(f.els.compareModal.classList.contains('hidden'), true);
    assert.deepEqual(f.toasts, []);
  });
}
test('repeated Compare keeps only latest read, and intentional cross-tool comparison still works', async () => {
  const f = fixture(); f.state.activeTool = 'fuzzer';
  f.select(0).resolve(response({ id: 'tx-0' })); await tick(); await f.c.useFuzzerComparisonBase();
  f.select(1).resolve(response({ id: 'tx-1' })); await tick();
  const first = f.c.compareSelectedFuzzerResult(), old = f.requests.slice(-2);
  const second = f.c.compareSelectedFuzzerResult(), latest = f.requests.slice(-2);
  latest[0].resolve(response({ id: 'tx-0' })); latest[1].resolve(response({ id: 'tx-1' })); await second;
  old[0].resolve(response({ id: 'tx-0' })); old[1].resolve(response({ id: 'tx-1' })); await first;
  assert.equal(f.compares, 1);
  f.c.setActiveTool('replay');
  const direct = f.c.openCompareModal('tx-2'), cross = f.requests.slice(-2);
  cross[0].resolve(response({ id: 'tx-0' })); cross[1].resolve(response({ id: 'tx-2' })); await direct;
  assert.equal(f.compares, 2);
});
test('Reuse confirmation cannot replace draft after leaving and returning', async () => {
  const f = fixture(); f.state.activeTool = 'fuzzer'; f.pick('run-b');
  const pending = f.reuse(); f.requests.at(-1).resolve(response(run('run-b'))); await pending;
  const before = draft(f.state); f.c.setActiveTool('replay'); f.c.setActiveTool('fuzzer');
  f.confirmations[0].confirm(); assert.equal(draft(f.state), before);
});

for (const action of ['view', 'reuse', 'refresh']) for (const outcome of ['success', 'failure']) {
  test(`delayed ${action} JSON ${outcome} is ignored after leaving and returning`, async () => {
    const f = fixture(); f.state.activeTool = 'fuzzer'; f.pick('run-b');
    const pending = action === 'refresh' ? f.c.refreshFuzzerSavedRuns() : f.c.readFuzzerSavedRun(action);
    const body = deferred(); f.requests.at(-1).resolve({ ok: true, status: 200, json: () => body.promise }); await tick();
    const before = draft(f.state); f.c.setActiveTool('replay'); f.c.setActiveTool('fuzzer');
    if (outcome === 'failure') body.reject(new Error('Stale saved run body.'));
    else body.resolve(action === 'refresh' ? [{ id: 'run-b' }] : run('run-b'));
    await pending;
    assert.equal(f.confirmations.length, 0); assert.equal(draft(f.state), before);
    assert.equal(f.state.fuzzerAttackRecordId, 'run-a');
    assert.equal(f.c.fuzzerResultsWorkflowState().runs.length, 0);
    assert.doesNotMatch(f.els.fuzzerSavedRunNotice.textContent, /Stale/);
  });
}

function wireSettingsSnapshot(f) {
  // Appearance/layout work is inert; navigation uses the full production function.
  const source = appSource.match(/^function applyUiSettingsSnapshot\([^]*?^\}/m)[0];
  for (const name of ['updateUiSettingsServerRevision', 'sanitizeDisplaySettings', 'sanitizeActiveProxyTab',
    'sanitizeHistoryColumnWidths', 'sanitizeHistoryColumnOrder', 'sanitizeHttpQuery', 'sanitizeHttpMethod',
    'sanitizeHttpSortKey', 'sanitizeHttpSortDirection', 'sanitizeHttpFilterSettings', 'sanitizeWorkbenchHeight',
    'sanitizeWorkbenchPaneWidths', 'sanitizeWebsocketPaneWidth', 'sanitizeServiceMapDetailWidth', 'applyServiceMapDetailWidth',
    'sanitizeWebsocketQuery', 'sanitizeWebsocketSortKey', 'sanitizeWebsocketSortDirection', 'sanitizeWebsocketStackHeight',
    'sanitizeWsReplayLeftWidth', 'sanitizeWsReplayFrameDetailHeight', 'hydrateFilterForm', 'syncColorTagFilterUI',
    'syncHttpInScopePill', 'syncHttpCapturePill', 'hydrateDisplaySettingsForm', 'previewDisplaySettingsFromForm',
    'applyDisplaySettingsState', 'renderHistoryHeader', 'applyHistoryColumnWidths', 'applyWsColumnWidths',
    'updateWebsocketSortIndicators', 'applySavedWorkbenchPaneWidths', 'applySavedWebsocketPaneWidth',
    'applySavedWebsocketStackHeight', 'applySavedWsReplayLayout', 'applyWorkbenchStackHeight']) f.c[name] = value => value;
  f.c.isModalVisible = () => false;
  f.c.displaySettingsReady = false; f.c.displaySettingsPreviewActive = false;
  vm.runInContext(source, f.c);
}
for (const action of ['view', 'reuse', 'refresh', 'compare']) for (const bounce of [false, true]) {
  test(`settings-snapshot navigation fences ${action}${bounce ? ' after return' : ''}`, async () => {
    const f = fixture(); f.state.activeTool = 'fuzzer'; wireSettingsSnapshot(f);
    let pending, requests;
    if (action === 'compare') {
      f.select(0).resolve(response({ id: 'tx-0' })); await tick(); await f.c.useFuzzerComparisonBase();
      f.select(1).resolve(response({ id: 'tx-1' })); await tick();
      pending = f.c.compareSelectedFuzzerResult(); requests = f.requests.slice(-2);
    } else {
      f.pick('run-b'); pending = action === 'refresh' ? f.c.refreshFuzzerSavedRuns() : f.c.readFuzzerSavedRun(action);
      requests = [f.requests.at(-1)];
    }
    f.c.applyUiSettingsSnapshot({ active_tool: 'replay' });
    if (bounce) f.c.applyUiSettingsSnapshot({ active_tool: 'fuzzer' });
    if (action === 'compare') {
      requests[0].resolve(response({ id: 'tx-0' })); requests[1].resolve(response({ id: 'tx-1' }));
    } else requests[0].resolve(response(action === 'refresh' ? [{ id: 'run-b' }] : run('run-b')));
    await pending;
    assert.equal(f.confirmations.length, 0); assert.equal(f.compares, 0);
    assert.equal(f.state.fuzzerAttackRecordId, 'run-a');
    assert.equal(f.c.fuzzerResultsWorkflowState().runs.length, 0);
  });
}
test('same-tool settings snapshot preserves an intentional pending Reuse', async () => {
  const f = fixture(); f.state.activeTool = 'fuzzer'; wireSettingsSnapshot(f); f.pick('run-b');
  const pending = f.reuse(); f.c.applyUiSettingsSnapshot({ active_tool: 'fuzzer' });
  f.requests.at(-1).resolve(response(run('run-b'))); await pending;
  assert.equal(f.confirmations.length, 1);
});

test('active filters remain visible when collapsed and clear without touching draft, results, or sort', () => {
  const f = fixture();
  assert.equal(f.els.fuzzerResultFilterBadge.classList.contains('hidden'), true);
  assert.equal(f.els.fuzzerClearResultFiltersButton.classList.contains('hidden'), true);
  const saved = f.state.fuzzerAttackRecord, before = draft(f.state);
  f.setFilter('fuzzerResultStatus', '2xx');
  f.setFilter('fuzzerResultMinBytes', '0');
  f.setFilter('fuzzerResultSort', 'duration'); f.setFilter('fuzzerResultDirection', 'desc');
  assert.equal(f.els.fuzzerResultFilterBadge.textContent, '2 active');
  assert.equal(f.els.fuzzerResultFilterBadge.classList.contains('hidden'), false);
  assert.equal(f.els.fuzzerClearResultFiltersButton.classList.contains('hidden'), false);
  f.state._selectedFuzzerResultKey = 'tx:tx-1';
  f.c.document.activeElement = f.els.fuzzerClearResultFiltersButton;
  f.els.fuzzerClearResultFiltersButton.dispatch('click');
  assert.equal(draft(f.state), before); assert.equal(f.state.fuzzerAttackRecord, saved);
  assert.equal(f.state._selectedFuzzerResultKey, 'tx:tx-1');
  assert.equal(f.c.fuzzerResultsWorkflowState().sort, 'duration');
  assert.equal(f.c.fuzzerResultsWorkflowState().direction, 'desc');
  assert.equal(f.els.fuzzerResultFilterBadge.classList.contains('hidden'), true);
  assert.equal(f.els.fuzzerClearResultFiltersButton.classList.contains('hidden'), true);
  assert.equal(f.els.fuzzerResultFilterSummary.focused, true);
  assert.equal(f.requests.length, 0); assert.equal(f.saves, 0);
});

test('clear filters recovers a later run hidden by retained status filters', () => {
  const f = fixture();
  f.c.setFuzzerAttackRecord(run('earlier', [result(0, 500)]));
  f.setFilter('fuzzerResultStatus', '5xx');
  f.c.setFuzzerAttackRecord(run('later', [result(0, 200), result(1, 204)])); f.c.renderFuzzer();
  assert.equal(f.c.visibleFuzzerResults().length, 0);
  assert.equal(f.els.fuzzerClearResultFiltersButton.classList.contains('hidden'), false);
  f.els.fuzzerClearResultFiltersButton.dispatch('click');
  assert.deepEqual(indexes(f), [0, 1]);
  assert.equal(f.els.fuzzerResultFilterCount.textContent, '2 of 2 results');
  assert.equal(f.requests.length, 0);
});

test('clear filters clears invalid empty numeric input and repeated clicks do not steal unrelated focus', () => {
  const f = fixture();
  f.els.fuzzerResultMinBytes.validity = { badInput: true };
  f.setFilter('fuzzerResultMinBytes', '');
  assert.equal(f.els.fuzzerResultFilterBadge.textContent, '1 active');
  f.c.document.activeElement = f.els.fuzzerPayloadsEditor;
  f.els.fuzzerClearResultFiltersButton.dispatch('click');
  f.els.fuzzerClearResultFiltersButton.dispatch('click');
  assert.equal(f.c.fuzzerResultFilterValidation().valid, true);
  assert.equal(f.c.visibleFuzzerResults().length, 2);
  assert.notEqual(f.els.fuzzerResultFilterSummary.focused, true);
  assert.equal(f.requests.length, 0); assert.equal(f.saves, 0);
});

test('clearing filters does not resurrect a filtered-away selection or its pending read', async () => {
  const f = fixture(), pending = f.select(0);
  f.setFilter('fuzzerResultStatus', '5xx');
  assert.equal(f.state._selectedFuzzerResultKey, null);
  f.els.fuzzerClearResultFiltersButton.dispatch('click');
  pending.resolve(response({ id: 'tx-0' })); await tick();
  assert.equal(f.state._selectedFuzzerResultKey, null);
  assert.equal(f.state._fuzzerDetailRecord, null);
  assert.equal(f.els.fuzzerDetailPanel.classList.contains('hidden'), true);
  assert.equal(f.c.visibleFuzzerResults().length, 2);
});
