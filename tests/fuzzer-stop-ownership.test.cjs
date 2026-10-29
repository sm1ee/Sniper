// Synthetic request promises only; no attack, process or network is started.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function fixture() {
  const state = { activeSession: { id: 'session-a' }, fuzzerRunningAttackId: 'attack-a' };
  const requests = [], notices = [], button = { disabled: false };
  const c = loadFunctions(['stopFuzzerAttack', 'currentSessionId'], {
    state, els: { stopFuzzerButton: button },
    fetch(url, options) { const next = { url, body: JSON.parse(options.body), ...deferred() }; requests.push(next); return next.promise; },
    showToast: notice => notices.push(notice),
    readApiErrorMessage: response => response.text(),
    renderFuzzer() {
      button.disabled = state.fuzzerStopRequest?.sessionId === state.activeSession?.id
        && state.fuzzerStopRequest?.id === state.fuzzerRunningAttackId;
    },
  });
  return { c, state, requests, notices, button };
}
const response = (ok = true, status = 200, message = '') => ({ ok, status, text: async () => message });

test('Stop handles a transport failure without an unhandled rejection', async () => {
  const f = fixture();
  const stopping = f.c.stopFuzzerAttack();
  f.requests[0].reject(new Error('Synthetic Stop transport failure'));
  await assert.doesNotReject(stopping);
  assert.deepEqual(f.notices, []);
  assert.equal(f.state.fuzzerStopError.id, 'attack-a');
  assert.equal(f.state.fuzzerStopError.sessionId, 'session-a');
  assert.equal(f.button.disabled, false);
});

test('repeated Stop while its request is pending sends once', async () => {
  const f = fixture();
  const first = f.c.stopFuzzerAttack();
  const repeated = f.c.stopFuzzerAttack();
  assert.equal(f.requests.length, 1);
  f.requests[0].resolve(response());
  await Promise.all([first, repeated]);
  assert.equal(f.button.disabled, false);
});

for (const boundary of ['session', 'attack']) for (const outcome of ['success', 'error', 'transport']) {
  test(`an old Stop ${outcome} does not affect the next ${boundary}`, async () => {
    const f = fixture();
    const old = f.c.stopFuzzerAttack();
    if (boundary === 'session') f.state.activeSession = { id: 'session-b' };
    else f.state.fuzzerRunningAttackId = 'attack-b';
    const next = f.c.stopFuzzerAttack();
    assert.equal(f.requests.length, 2);
    if (outcome === 'transport') f.requests[0].reject(new Error('Old Stop failure'));
    else f.requests[0].resolve(response(outcome === 'success', outcome === 'success' ? 200 : 500, 'Old Stop failure'));
    await assert.doesNotReject(old);
    assert.equal(f.button.disabled, true, 'the current Stop still owns its progress');
    assert.deepEqual(f.notices, []);
    f.requests[1].resolve(response());
    await next;
    assert.equal(f.button.disabled, false);
  });
}

test('Stop HTTP failure uses local feedback without reading or retaining response content', async () => {
  const f = fixture(), stopping = f.c.stopFuzzerAttack();
  f.requests[0].resolve({ ok: false, status: 500, text() { assert.fail('Stop feedback must not read response content'); } });
  await stopping;
  assert.deepEqual(f.notices, []);
  assert.equal(JSON.stringify(f.state.fuzzerStopError), JSON.stringify({ id: 'attack-a', sessionId: 'session-a' }));
});

test('Stop HTTP failure arriving after a session change cannot set a local error', async () => {
  const f = fixture(), old = f.c.stopFuzzerAttack();
  f.state.activeSession = { id: 'session-b' };
  f.requests[0].resolve(response(false, 500, 'Old response content'));
  await old;
  assert.deepEqual(f.notices, []);
  assert.equal(f.state.fuzzerStopError, null);
});

test('session reset retires the old attack id and pending Stop control', () => {
  const f = fixture();
  f.state.fuzzerRunning = true;
  f.state.fuzzerStopRequest = { sessionId: 'session-a', id: 'attack-a' };
  const start = appSource.indexOf('  state.fuzzerRunToken =', appSource.indexOf('function resetSessionScopedUiState()'));
  const end = appSource.indexOf('  state.sequenceDefinitions =', start);
  assert.ok(start > 0 && end > start);
  f.c.clearFuzzerAttackRecord = () => {};
  vm.runInContext(`(() => { ${appSource.slice(start, end)} })()`, f.c);
  assert.equal(f.state.fuzzerRunningAttackId, null);
  assert.equal(f.state.fuzzerStopRequest, null);
  assert.equal(f.state.fuzzerRunning, false);
});
