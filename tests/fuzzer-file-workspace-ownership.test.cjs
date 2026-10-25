'use strict';
// Passive UI ownership only: synthetic string promises, never a real file,
// decoder, API/server, request execution, application bootstrap or browser.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { appSource } = require('./frontend-test-helpers.cjs');
const { fixture: workspaceFixture, deferred, plain } = require('./replay-workspace-fixture.cjs');

function fixture({ shown = false } = {}) {
  const f = workspaceFixture(), c = f.context;
  Object.assign(f.state, {
    fuzzerRunToken: 4, fuzzerDraftVersion: 7, fuzzerRunning: false,
    fuzzerBaseRequest: { scheme: 'https', host: 'example.com', method: 'GET', path: '/synthetic', headers: [], body: '', body_encoding: 'utf8', preview_truncated: false },
    fuzzerSourceTransactionId: 'source-a', fuzzerTarget: { scheme: 'https', host: 'example.com', port: '8443' },
    fuzzerTargetRequestText: 'https://example.com', fuzzerRequestText: 'synthetic request draft', fuzzerPayloadsText: 'original',
    fuzzerNotice: 'status before import', fuzzerAttackRecord: shown ? { id: 'shown', results: [] } : null,
    fuzzerAttackRecordId: shown ? 'shown' : null,
  });
  const effects = { saves: 0, renders: 0, reads: 0, syntheticConversions: 0, clears: 0, hidden: 0, hydrations: [] };
  c.scheduleWorkspaceStateSave = () => effects.saves++;
  c.renderFuzzer = () => effects.renders++;
  c.clearFuzzerAttackRecord = () => { effects.clears++; f.state.fuzzerAttackRecord = null; f.state.fuzzerAttackRecordId = null; };
  c.hideFuzzerDetailPanel = () => effects.hidden++;
  c.hydrateFuzzerAttackRecordById = (...args) => effects.hydrations.push(args);
  c.TextDecoder = class SyntheticStringReader {
    decode(value) { assert.equal(value.synthetic, true); effects.syntheticConversions++; return value.text; }
  };
  c.SniperFuzzerWorkflow = { validatePayloads: () => ({ valid: true }), payloadText: values => values.join('\n') };
  c.fuzzerPayloadTextWithinLimits = text => text.split('\n');
  for (const name of ['importFuzzerPayloadFile', 'applyFuzzerPayloadList', 'updateFuzzerPayloadsText', 'updateFuzzerRequestText', 'markFuzzerDraftChanged',
    'normalizeFuzzerTargetOverride', 'normalizeFuzzerTargetAuthority', 'fuzzerAuthorityFromSavedValue']) {
    const source = appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, 'm'));
    assert.ok(source, name); vm.runInContext(source[0], c);
  }
  f.seed([]);
  function fields() { return c.readFuzzerWorkspace(plain(c.snapshotFuzzerWorkspace(f.state))); }
  function apply(next) { c.applyFuzzerWorkspace(next, 'session-a', { keepShownRun: true }); }
  function begin(mode = 'replace') {
    const read = deferred();
    const pending = c.importFuzzerPayloadFile({ size: 1, arrayBuffer() { effects.reads++; return read.promise; } }, mode)
      .then(value => ({ value }), error => ({ error }));
    return { read, pending };
  }
  async function finish(job, outcome = 'success', text = 'earlier file') {
    const error = new Error('synthetic file read failure');
    if (outcome === 'success') job.read.resolve({ synthetic: true, byteLength: 1, text });
    else job.read.reject(error);
    return { settled: await job.pending, error };
  }
  return { ...f, c, effects, fields, apply, begin, finish };
}
const changes = {
  request: next => { next.fuzzerRequestText = 'accepted newer request'; },
  payloads: next => { next.fuzzerPayloadsText = 'accepted newer payloads'; },
  base: next => { next.fuzzerBaseRequest = { ...next.fuzzerBaseRequest, path: '/accepted-newer' }; },
  source: next => { next.fuzzerSourceTransactionId = 'source-b'; },
  target: next => { next.fuzzerTarget = { ...next.fuzzerTarget, port: '9443' }; },
  authority: next => { next.fuzzerTargetRequestText = 'https://other.example.com'; },
};
for (const mode of ['append', 'replace']) for (const outcome of ['success', 'error']) {
  for (const [field, change] of Object.entries(changes)) test(`${mode}: accepted ${field} replacement retires earlier file ${outcome}`, async () => {
    const f = fixture({ shown: true }), shown = f.state.fuzzerAttackRecord, job = f.begin(mode), next = f.fields();
    change(next); f.apply(next);
    assert.equal(f.state.fuzzerDraftVersion, 7); assert.equal(f.state.fuzzerRunToken, 4);
    assert.equal(f.state.fuzzerAttackRecord, shown); assert.equal(f.state.fuzzerNotice, 'status before import');
    assert.equal(f.effects.clears, 0); assert.equal(f.effects.hidden, 0);
    const before = JSON.stringify(f.state), effects = { ...f.effects };
    const { settled } = await f.finish(job, outcome);
    assert.equal(settled.value, false, 'earlier intent must retire instead of applying or surfacing its error');
    assert.equal(JSON.stringify(f.state), before); assert.deepEqual(f.effects, effects);
  });
  test(`${mode}: changed→original workspace ABA still retires earlier file ${outcome}`, async () => {
    const f = fixture(), original = f.fields(), job = f.begin(mode), changed = f.fields();
    changes.payloads(changed); f.apply(changed); f.apply(original);
    const before = JSON.stringify(f.state), { settled } = await f.finish(job, outcome);
    assert.equal(settled.value, false); assert.equal(JSON.stringify(f.state), before);
  });
}
const noops = {
  identical() {},
  'cloned and reordered draft objects': next => {
    next.fuzzerBaseRequest = Object.fromEntries(Object.entries(next.fuzzerBaseRequest).reverse());
    next.fuzzerTarget = Object.fromEntries(Object.entries(next.fuzzerTarget).reverse());
  },
  'notice only': next => { next.fuzzerNotice = 'updated status'; },
  'saved-run reference only': next => { next.fuzzerAttackRecordId = 'other-shown-run'; },
  'legacy result metadata only': next => { next.legacyAttackRecord = { id: 'legacy', results: [] }; },
};
for (const [label, change] of Object.entries(noops)) for (const outcome of ['success', 'error']) {
  test(`${label} application keeps current file ${outcome} owned`, async () => {
    const f = fixture(), job = f.begin(), generation = f.state._fuzzerFileGeneration, next = f.fields();
    change(next); f.apply(next); assert.equal(f.state._fuzzerFileGeneration, generation);
    const { settled, error } = await f.finish(job, outcome);
    if (outcome === 'success') { assert.equal(settled.value, true); assert.equal(f.state.fuzzerPayloadsText, 'earlier file'); }
    else { assert.equal(settled.error, error); assert.equal(f.state.fuzzerPayloadsText, 'original'); }
  });
}
test('partial result-only application does not pretend omitted draft fields were cleared', async () => {
  const f = fixture(), job = f.begin(), generation = f.state._fuzzerFileGeneration;
  f.apply({ fuzzerAttackRecordId: 'other-shown-run', legacyAttackRecord: null });
  assert.equal(f.state._fuzzerFileGeneration, generation);
  assert.equal((await f.finish(job)).settled.value, true);
});
for (const mode of ['append', 'replace']) for (const outcome of ['success', 'error']) {
  test(`${mode}: actual accepted external adoption retires old file ${outcome}`, async () => {
    const f = fixture(), job = f.begin(mode), snapshot = f.remote();
    snapshot.fuzzer.payloads_text = 'external newer'; snapshot.fuzzer.request_text = 'external request';
    await f.adopt(snapshot);
    assert.equal(f.state.workspaceRevision, 11); assert.equal(f.c.workspaceSaveConflictPending, false);
    assert.equal(f.requests.length, 1); assert.equal(f.requests[0].options, undefined); assert.equal(f.beacons.length, 0);
    const before = JSON.stringify(f.state), effects = { ...f.effects };
    assert.equal((await f.finish(job, outcome)).settled.value, false);
    assert.equal(JSON.stringify(f.state), before); assert.deepEqual(f.effects, effects);
    assert.equal(f.requests.length, 1); assert.equal(f.beacons.length, 0);
  });
}
for (const outcome of ['success', 'error']) for (const kind of ['unchanged', 'notice only', 'same-change convergence', 'rejected conflict']) {
  test(`actual ${kind} external adoption preserves current file ${outcome}`, async () => {
    const f = fixture();
    if (kind === 'same-change convergence' || kind === 'rejected conflict') f.state.fuzzerPayloadsText = 'local before selection';
    const job = f.begin(), generation = f.state._fuzzerFileGeneration, snapshot = f.remote();
    if (kind === 'notice only') snapshot.fuzzer.notice = 'remote status';
    if (kind === 'same-change convergence') snapshot.fuzzer.payloads_text = 'local before selection';
    if (kind === 'rejected conflict') snapshot.fuzzer.payloads_text = 'conflicting external text';
    await f.adopt(snapshot);
    assert.equal(f.c.workspaceSaveConflictPending, kind === 'rejected conflict');
    assert.equal(f.state.workspaceRevision, kind === 'rejected conflict' ? 10 : 11);
    assert.equal(f.state._fuzzerFileGeneration, generation);
    const { settled, error } = await f.finish(job, outcome);
    if (outcome === 'success') { assert.equal(settled.value, true); assert.equal(f.state.fuzzerPayloadsText, 'earlier file'); }
    else assert.equal(settled.error, error);
    assert.equal(f.requests.length, 1); assert.equal(f.beacons.length, 0);
  });
}
for (const mode of ['append', 'replace']) test(`${mode}: fresh file after accepted replacement remains usable`, async () => {
  const f = fixture(), old = f.begin(mode), next = f.fields(); changes.payloads(next); f.apply(next);
  const fresh = f.begin(mode); assert.equal((await f.finish(old)).settled.value, false);
  assert.equal((await f.finish(fresh, 'success', 'fresh file')).settled.value, true);
  assert.equal(f.state.fuzzerPayloadsText, mode === 'replace' ? 'fresh file' : 'accepted newer payloads\nfresh file');
});
for (const outcome of ['success', 'error']) test(`ordinary manual edit still retires old file ${outcome}`, async () => {
  const f = fixture(), old = f.begin(); f.c.updateFuzzerPayloadsText('manual newer', { userEdit: true });
  assert.equal((await f.finish(old, outcome)).settled.value, false); assert.equal(f.state.fuzzerPayloadsText, 'manual newer');
});
test('even a rejected newer synthetic file choice still retires the older intent', async () => {
  const f = fixture(), old = f.begin();
  await assert.rejects(f.c.importFuzzerPayloadFile({ size: 4194305, arrayBuffer() { assert.fail('Oversize choice must not be read'); } }), /4 MiB/);
  assert.equal((await f.finish(old)).settled.value, false); assert.equal(f.state.fuzzerPayloadsText, 'original');
});
