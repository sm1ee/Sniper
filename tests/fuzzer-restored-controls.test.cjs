// All attack responses are synthetic; no requests leave the test process.
const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions, appSource } = require('./frontend-test-helpers.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
function fixture() {
  const state = { activeSession: { id: 'session-a' }, fuzzerAttackRecordId: 'run-a',
    fuzzerRequestText: 'GET /?q=§x§ HTTP/1.1\r\nHost: example.com\r\n\r\n',
    fuzzerPayloadsText: 'a\nb', fuzzerRunning: false, fuzzerRunToken: 0 };
  const timers = [], requests = [];
  const c = loadFunctions(['hydrateFuzzerAttackRecordById', 'followFuzzerAttack', 'setFuzzerAttackRecord',
    'clearFuzzerAttackRecord', 'normalizeFuzzerAttackRecord', 'jsonArray', 'sessionQueryPath', 'currentSessionId',
    'resetFuzzer', 'invalidateFuzzerRun', 'updateFuzzerRequestText', 'updateFuzzerPayloadsText', 'markFuzzerDraftChanged',
    'runFuzzerAttack', 'stopFuzzerAttack'], {
    state, _fuzzerAttackLoadGeneration: 0, FUZZER_POLL_MS: 0, URLSearchParams,
    setTimeout: callback => { timers.push(callback); return 0; },
    hideFuzzerDetailPanel() {}, renderFuzzer() {}, scheduleWorkspaceStateSave() {}, scheduleFuzzerSetupRender() {},
    requireOkResponse: async response => assert.equal(response.ok, true),
    fetch: (url, options) => new Promise((resolve, reject) => requests.push({ url, options, resolve, reject })),
  });
  const reply = (running, id = 'run-a') => ({ ok: true, status: 200, json: async () => ({ id, running,
    results: [{ index: 0, payload: 'a', status: 200 }], status: running ? 'running' : 'completed' }) });
  const start = async () => {
    const pending = c.hydrateFuzzerAttackRecordById('run-a', 'session-a');
    requests.shift().resolve(reply(true)); await tick();
    return { pending };
  };
  return { state, timers, requests, c, reply, start };
}

test('Reset and Start reject an already-restored running attack without abandoning its poll', async () => {
  const f = fixture(), { pending } = await f.start();
  const before = JSON.stringify(f.state);
  f.c.resetFuzzer(); await f.c.runFuzzerAttack();
  assert.equal(JSON.stringify(f.state), before);
  assert.match(appSource, /els\.resetFuzzerButton\.disabled = attackRunning;/);
  f.timers.shift()(); await tick(); f.requests.shift().resolve(f.reply(false)); await pending;
  assert.equal(f.state.fuzzerRunningAttackId, null);
});

for (const edit of ['request', 'payload', 'retained view', 'retained reuse']) {
  test(`${edit} releases the restored result view but follows the server run to completion`, async () => {
    const f = fixture(), { pending } = await f.start();
    if (edit === 'request') f.c.updateFuzzerRequestText('GET /changed HTTP/1.1\r\nHost: example.com\r\n\r\n', { userEdit: true });
    if (edit === 'payload') f.c.updateFuzzerPayloadsText('new', { userEdit: true });
    if (edit === 'retained view') f.c.setFuzzerAttackRecord({ id: 'other-run', running: false, results: [] });
    if (edit === 'retained reuse') { f.c.invalidateFuzzerRun(); f.c.clearFuzzerAttackRecord(); f.state.fuzzerRequestText = 'reused draft'; }
    const request = f.state.fuzzerRequestText, payloads = f.state.fuzzerPayloadsText, record = f.state.fuzzerAttackRecord;
    f.timers.shift()(); await tick(); f.requests.shift().resolve(f.reply(true)); await tick();
    assert.equal(f.state.fuzzerAttackRecord, record);
    assert.equal(f.state.fuzzerRunningAttackId, 'run-a');
    f.timers.shift()(); await tick(); f.requests.shift().resolve(f.reply(false)); await pending;
    assert.equal(f.state.fuzzerAttackRecord, record);
    assert.equal(f.state.fuzzerRequestText, request); assert.equal(f.state.fuzzerPayloadsText, payloads);
    assert.equal(f.state.fuzzerRunningAttackId, null); assert.equal(f.state.fuzzerRestoredRun, null);
  });
}

for (const change of ['session', 'new local run', 'new restored owner']) {
  test(`an old restored poll cannot retire controls after ${change}`, async () => {
    const f = fixture(), { pending } = await f.start();
    f.timers.shift()(); await tick();
    const oldRequest = f.requests.shift();
    if (change === 'session') { f.state.activeSession = { id: 'session-b' }; f.state.fuzzerRestoredRun = null; }
    if (change === 'new local run') f.state.fuzzerRunning = true;
    if (change === 'new restored owner') f.state.fuzzerRestoredRun = { id: 'run-b', sessionId: 'session-a' };
    f.state.fuzzerRunningAttackId = 'run-b';
    f.c.setFuzzerAttackRecord({ id: 'run-b', running: true, results: [] });
    oldRequest.resolve(f.reply(false)); await pending;
    assert.equal(f.state.fuzzerRunningAttackId, 'run-b'); assert.equal(f.state.fuzzerAttackRecord.id, 'run-b');
  });
}

for (const outcome of ['missing', 'retry and stop']) {
  test(`a detached restored run handles ${outcome} without overwriting the new draft`, async () => {
    const f = fixture(), { pending } = await f.start();
    f.c.updateFuzzerPayloadsText('new draft', { userEdit: true });
    const notice = f.state.fuzzerNotice;
    f.timers.shift()(); await tick();
    if (outcome === 'missing') {
      f.requests.shift().resolve({ ok: false, status: 404 }); await pending;
    } else {
      f.requests.shift().reject(new Error('synthetic read failure')); await tick();
      assert.equal(f.state.fuzzerRunningAttackId, 'run-a');
      assert.equal(f.state.fuzzerNotice, notice);
      const stop = f.c.stopFuzzerAttack();
      const stopRequest = f.requests.shift();
      assert.equal(stopRequest.url, '/api/fuzzer/attacks/run-a/stop');
      assert.equal(stopRequest.options.method, 'POST');
      assert.equal(JSON.parse(stopRequest.options.body).session_id, 'session-a');
      stopRequest.resolve({ ok: true, status: 200 }); await stop;
      assert.equal(f.state.fuzzerRunningAttackId, 'run-a', 'Stop waits for terminal polling');
      f.timers.shift()(); await tick(); f.requests.shift().resolve(f.reply(false)); await pending;
    }
    assert.equal(f.state.fuzzerAttackRecord, null);
    assert.match(f.state.fuzzerNotice, /Start a new run/);
    assert.equal(f.state.fuzzerPayloadsText, 'new draft');
    assert.equal(f.state.fuzzerRunningAttackId, null); assert.equal(f.state.fuzzerRestoredRun, null);
  });
}

for (const replaceNotice of [false, true]) {
  test(`restored completion ${replaceNotice ? 'preserves a newer notice' : 'retires only its active-draft notice'}`, async () => {
    const f = fixture(), { pending } = await f.start();
    f.c.updateFuzzerPayloadsText('new draft', { userEdit: true });
    assert.match(f.state.fuzzerNotice, /current run is still active/);
    if (replaceNotice) f.state.fuzzerNotice = 'A newer draft action notice.';
    f.timers.shift()(); await tick(); f.requests.shift().resolve(f.reply(false)); await pending;
    if (replaceNotice) assert.equal(f.state.fuzzerNotice, 'A newer draft action notice.');
    else assert.match(f.state.fuzzerNotice, /Start a new run/);
  });
}

for (const running of [true, false]) {
  test(`same-ID hydration showing ${running ? 'another running view' : 'a terminal view'} fences an older deferred poll`, async () => {
    const f = fixture(), { pending } = await f.start();
    f.timers.shift()(); await tick();
    const oldPoll = f.requests.shift();
    const oldOwner = f.state.fuzzerRestoredRun;
    const latest = f.c.hydrateFuzzerAttackRecordById('run-a', 'session-a');
    f.requests.shift().resolve(f.reply(running)); await tick();
    const latestRecord = f.state.fuzzerAttackRecord;
    oldPoll.resolve(f.reply(false)); await pending;
    assert.equal(f.state.fuzzerAttackRecord, latestRecord, 'old terminal cannot replace the newly selected view');
    if (running) {
      assert.notEqual(f.state.fuzzerRestoredRun, oldOwner);
      assert.equal(f.state.fuzzerRunningAttackId, 'run-a');
      f.timers.shift()(); await tick(); f.requests.shift().resolve(f.reply(false));
    }
    await latest;
    assert.equal(f.state.fuzzerRunningAttackId, null);
    assert.equal(f.state.fuzzerRestoredRun, null);
  });
}
