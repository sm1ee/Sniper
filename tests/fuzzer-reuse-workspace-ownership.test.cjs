// Synthetic retained-run reads and accepted workspace snapshots only. No app
// bootstrap, browser, real fetch, attack start, transport or disk save executes.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { appSource } = require('./frontend-test-helpers.cjs');
const { fixture: workspaceFixture, deferred, plain } = require('./replay-workspace-fixture.cjs');

function fixture({ shown = true } = {}) {
  const f = workspaceFixture(), c = f.context, confirmations = [];
  const effects = { saves: 0, renders: 0, hidden: 0, followed: [] };
  Object.assign(f.state, {
    fuzzerDraftVersion: 7, fuzzerRunToken: 4, fuzzerRunning: false,
    fuzzerBaseRequest: { scheme: 'https', host: 'example.com', method: 'GET', path: '/original',
      headers: [], body: '', body_encoding: 'utf8', preview_truncated: false },
    fuzzerRequestText: 'GET /original HTTP/1.1\r\nHost: example.com\r\n\r\n', fuzzerPayloadsText: 'original payload',
    fuzzerSourceTransactionId: 'source-a', fuzzerTarget: { scheme: 'https', host: 'example.com', port: '8443' },
    fuzzerTargetRequestText: 'https://example.com',
    fuzzerAttackRecordId: shown ? 'shown-a' : null,
    fuzzerAttackRecord: shown ? { id: 'shown-a', results: [] } : null,
  });
  Object.assign(c, {
    _fuzzerAttackLoadGeneration: 0,
    renderFuzzerResultsWorkflow() { effects.renders++; },
    renderFuzzer() { effects.renders++; },
    requireOkResponse: async response => { if (!response.ok) throw new Error('Synthetic read failure.'); },
    hideFuzzerDetailPanel() { effects.hidden++; },
    showConfirmDialog: (message, confirm, options) => confirmations.push({ message, confirm, options }),
    scheduleWorkspaceStateSave() { effects.saves++; },
    followFuzzerAttack(id, sessionId, ownsRun, ownsView) {
      const pending = { id, sessionId, ownsRun, ownsView, ...deferred() };
      effects.followed.push(pending);
      return pending.promise;
    },
  });
  for (const name of ['fuzzerResultsWorkflowState', 'fuzzerSavedReadOwner', 'readFuzzerSavedRun',
    'reusableSniperPayloads', 'normalizeFuzzerAttackRecord', 'jsonArray', 'invalidateFuzzerRun',
    'setFuzzerAttackRecord', 'clearFuzzerAttackRecord', 'followRestoredFuzzerAttack']) {
    const source = appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, 'm'));
    assert.ok(source, name); vm.runInContext(source[0], c);
  }
  const fetch = c.fetch;
  c.fetch = (url, options) => {
    assert.equal(options, undefined, 'Only synthetic read-only requests are allowed.');
    assert.match(url, /^\/api\/(?:workspace-state|fuzzer\/attacks\/[^?]+)\?session_id=/);
    return fetch(url, options);
  };
  f.seed([]);
  const workflow = c.fuzzerResultsWorkflowState();
  function begin(action = 'reuse', id = 'saved-a') {
    workflow.selectedRunId = id;
    const pending = c.readFuzzerSavedRun(action);
    return { pending, request: f.requests.at(-1), id };
  }
  async function finish(job, outcome = 'success') {
    if (outcome === 'failure') job.request.reject(new Error('Obsolete saved-run failure.'));
    else job.request.resolve({ ok: true, status: 200, json: async () => ({
      id: job.id, attack_type: 'battering_ram', payload_count: 1, marker_count: 1,
      results: [{ index: 0, payload: 'saved payload' }],
      template: { scheme: 'https', host: 'example.com', method: 'GET', path: '/saved', headers: [], body: '', body_encoding: 'utf8' },
    }) });
    await job.pending;
  }
  function fields() { return c.readFuzzerWorkspace(plain(c.snapshotFuzzerWorkspace(f.state))); }
  return { ...f, c, workflow, confirmations, effects, begin, finish, fields };
}

const edits = {
  request: saved => { saved.request_text = 'GET /external-newer HTTP/1.1\r\nHost: example.com\r\n\r\n'; },
  payloads: saved => { saved.payloads_text = 'external newer payload'; },
  base: saved => { saved.base_request.path = '/external-base'; },
  source: saved => { saved.source_transaction_id = 'external-source'; },
  target: saved => { saved.target.port = '9443'; },
  authority: saved => { saved.target_request_authority = 'https://other.example.com'; },
};

for (const [field, edit] of Object.entries(edits)) for (const phase of ['read', 'confirmation']) {
  test(`accepted external ${field} retires Reuse ${phase} without any prior file import`, async () => {
    const f = fixture(), shown = f.state.fuzzerAttackRecord, job = f.begin();
    assert.equal(f.state._fuzzerFileGeneration, undefined);
    if (phase === 'confirmation') await f.finish(job);
    const generation = f.workflow.readGeneration, attackGeneration = f.c._fuzzerAttackLoadGeneration;
    const remote = f.remote(); edit(remote.fuzzer); await f.adopt(remote);
    assert.equal(f.state.workspaceRevision, 11); assert.equal(f.c.workspaceSaveConflictPending, false);
    assert.equal(f.workflow.readGeneration, generation + 1); assert.equal(f.workflow.readBusy, false);
    assert.equal(f.workflow.notice, '');
    const accepted = JSON.stringify(f.c.snapshotFuzzerWorkspace(f.state));
    if (phase === 'read') await f.finish(job);
    else f.confirmations[0].confirm();
    assert.equal(f.confirmations.length, phase === 'read' ? 0 : 1);
    assert.equal(JSON.stringify(f.c.snapshotFuzzerWorkspace(f.state)), accepted);
    assert.equal(f.state.fuzzerDraftVersion, 7); assert.equal(f.state.fuzzerRunToken, 4);
    assert.equal(f.state.fuzzerAttackRecord, shown); assert.equal(f.c._fuzzerAttackLoadGeneration, attackGeneration);
    assert.equal(f.effects.saves, 0); assert.equal(f.effects.hidden, 0);
  });
}

for (const shown of [false, true]) for (const phase of ['read', 'confirmation']) {
  test(`accepted change→original ABA retires Reuse ${phase} with ${shown ? 'same' : 'no'} shown run`, async () => {
    const f = fixture({ shown }), original = f.remote().fuzzer, job = f.begin();
    if (phase === 'confirmation') await f.finish(job);
    const remote = f.remote(); edits.payloads(remote.fuzzer); await f.adopt(remote);
    const back = f.remote([], 12); back.fuzzer = original; await f.adopt(back);
    assert.equal(f.state.workspaceRevision, 12);
    if (phase === 'read') await f.finish(job);
    else f.confirmations[0].confirm();
    assert.equal(f.state.fuzzerPayloadsText, 'original payload');
    assert.equal(f.effects.saves, 0); assert.equal(f.workflow.notice, '');
  });
}

for (const kind of ['unchanged', 'status', 'cloned']) for (const phase of ['read', 'confirmation']) {
  test(`accepted ${kind} workspace keeps intended Reuse ${phase}`, async () => {
    const f = fixture(), job = f.begin();
    if (phase === 'confirmation') await f.finish(job);
    const generation = f.workflow.readGeneration, remote = f.remote();
    if (kind === 'status') remote.fuzzer.notice = 'remote status';
    if (kind === 'cloned') remote.fuzzer.base_request = Object.fromEntries(Object.entries(remote.fuzzer.base_request).reverse());
    await f.adopt(remote);
    assert.equal(f.state.workspaceRevision, 11); assert.equal(f.workflow.readGeneration, generation);
    if (phase === 'read') await f.finish(job);
    assert.equal(f.confirmations.length, 1); f.confirmations[0].confirm();
    assert.equal(f.state.fuzzerPayloadsText, 'saved payload'); assert.equal(f.effects.saves, 1);
  });
}

for (const action of ['reuse', 'view']) for (const outcome of ['success', 'failure']) {
  test(`retired ${action} ${outcome} cannot finish a newer read or change its notice`, async () => {
    const f = fixture(), old = f.begin(action), remote = f.remote(); edits.payloads(remote.fuzzer); await f.adopt(remote);
    assert.equal(f.workflow.readBusy, false);
    const fresh = f.begin(action, 'saved-newer'), generation = f.workflow.readGeneration;
    await f.finish(old, outcome);
    assert.equal(f.workflow.readBusy, true); assert.equal(f.workflow.readGeneration, generation);
    assert.equal(f.workflow.notice, 'Loading saved run...'); assert.equal(f.confirmations.length, 0);
    assert.equal(f.state.fuzzerAttackRecordId, 'shown-a');
    await f.finish(fresh); assert.equal(f.workflow.readBusy, false);
    assert.equal(f.state.fuzzerPayloadsText, 'external newer payload');
    if (action === 'reuse') { assert.equal(f.confirmations.length, 1); f.confirmations[0].confirm(); assert.equal(f.state.fuzzerPayloadsText, 'saved payload'); }
    else assert.equal(f.state.fuzzerAttackRecordId, 'saved-newer');
  });
}

for (const action of ['reuse', 'view']) test(`retiring ${action} keeps shown restored-run polling and Stop ownership`, async () => {
  const f = fixture(), job = f.begin(action), shown = f.state.fuzzerAttackRecord;
  shown.running = true;
  const attackGeneration = f.c._fuzzerAttackLoadGeneration;
  const following = f.c.followRestoredFuzzerAttack(shown, 'session-a', () => attackGeneration === f.c._fuzzerAttackLoadGeneration);
  const owner = f.state.fuzzerRestoredRun, poll = f.effects.followed[0], remote = f.remote();
  edits.payloads(remote.fuzzer); await f.adopt(remote);
  assert.equal(f.state.fuzzerAttackRecord, shown); assert.equal(f.c._fuzzerAttackLoadGeneration, attackGeneration);
  assert.equal(f.state.fuzzerRestoredRun, owner); assert.equal(f.state.fuzzerRunningAttackId, 'shown-a');
  assert.equal(poll.ownsRun(), true); assert.equal(poll.ownsView(), true);
  await f.finish(job);
  assert.equal(f.state.fuzzerAttackRecord, shown); assert.equal(f.confirmations.length, 0);
  const ended = { ...shown, running: false, status: 'completed' }; poll.resolve(ended); await following;
  assert.equal(f.state.fuzzerAttackRecord, ended); assert.equal(f.state.fuzzerRestoredRun, null);
  assert.equal(f.state.fuzzerRunningAttackId, null); assert.equal(f.state.fuzzerPayloadsText, 'external newer payload');
});

for (const notice of ['Loading retained runs...', 'Other retained-list status']) {
  test(`retirement preserves unrelated notice: ${notice}`, async () => {
    const f = fixture(), job = f.begin(); f.workflow.notice = notice;
    const remote = f.remote(); edits.payloads(remote.fuzzer); await f.adopt(remote); await f.finish(job);
    assert.equal(f.workflow.notice, notice); assert.equal(f.workflow.readBusy, false);
  });
}

for (const kind of ['status', 'same run', 'different run', 'legacy run']) {
  test(`${kind}-only application does not introduce draft invalidation`, async () => {
    const f = fixture(), job = f.begin(), generation = f.workflow.readGeneration, fields = f.fields();
    if (kind === 'status') fields.fuzzerNotice = 'updated status';
    if (kind === 'different run') fields.fuzzerAttackRecordId = 'another-shown';
    if (kind === 'legacy run') fields.legacyAttackRecord = { id: 'legacy-shown', results: [] };
    const attackGeneration = f.c._fuzzerAttackLoadGeneration;
    f.c.applyFuzzerWorkspace(fields, 'session-a', { keepShownRun: true });
    assert.equal(f.workflow.readGeneration, generation);
    assert.equal(f.c._fuzzerAttackLoadGeneration, attackGeneration + Number(['different run', 'legacy run'].includes(kind)));
    await f.finish(job);
    assert.equal(f.confirmations.length, ['different run', 'legacy run'].includes(kind) ? 0 : 1);
  });
}

test('a foreign session cannot retire another workflow counter, busy flag or notice', () => {
  const f = fixture(), fields = f.fields(); fields.fuzzerPayloadsText = 'foreign draft';
  f.workflow.readBusy = true; f.workflow.readGeneration = 8; f.workflow.notice = 'Loading saved run...';
  f.c.applyFuzzerWorkspace(fields, 'session-b', { keepShownRun: true });
  assert.equal(f.workflow.readGeneration, 8); assert.equal(f.workflow.readBusy, true);
  assert.equal(f.workflow.notice, 'Loading saved run...');
});

test('a stale workflow matching the supplied session is not the active session owner', () => {
  const f = fixture(), fields = f.fields(); fields.fuzzerPayloadsText = 'foreign draft';
  f.state.activeSession.id = 'session-b'; f.workflow.readBusy = true; f.workflow.readGeneration = 8;
  f.c.applyFuzzerWorkspace(fields, 'session-a', { keepShownRun: true });
  assert.equal(f.workflow.readGeneration, 8); assert.equal(f.workflow.readBusy, true);
});
