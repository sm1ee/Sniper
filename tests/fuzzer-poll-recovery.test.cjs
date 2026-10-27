// Production poller with local promises only; never sends traffic.
const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const record = (count = 1, running = true) => ({ id: 'attack-a', running, status: 'completed', planned: 3,
  results: Array.from({ length: count }, (_, index) => ({ index, payload: `p${index}`, status: 200 })) });
const response = value => ({ ok: true, status: 200, json: async () => value });
function fixture() {
  const timers = [], requests = [];
  const state = { activeSession: { id: 'session-a' }, fuzzerAttackRecord: record(), fuzzerRunningAttackId: 'attack-a',
    fuzzerNotice: '', fuzzerNoticeError: false, _selectedFuzzerResultKey: 'row-0' };
  let owns = true;
  const c = loadFunctions(['followFuzzerAttack', 'normalizeFuzzerAttackRecord', 'jsonArray'], {
    state, FUZZER_POLL_MS: 700, setTimeout(callback) { timers.push(callback); },
    sessionQueryPath: (path, sessionId) => `${path}?session_id=${sessionId}`,
    fetch(url) { const next = { url, ...deferred() }; requests.push(next); return next.promise; },
    requireOkResponse: async value => { if (!value.ok) throw new Error('Synthetic server error'); },
    renderFuzzer() {},
  });
  const following = c.followFuzzerAttack('attack-a', 'session-a', () => owns);
  // Baseline rejection must be observable rather than an unhandled test rejection.
  following.catch(() => {});
  return { state, timers, requests, following, leave() { owns = false; },
    async poll() { assert.ok(timers.length, 'a new read should be scheduled'); timers.shift()(); await tick(); return requests.at(-1); } };
}

for (const failure of ['transport', 'json', 'http', 'mismatched-record']) {
  test(`a ${failure} poll failure retains partial results and Stop, then recovers`, async () => {
    const f = fixture(), prior = f.state.fuzzerAttackRecord;
    const read = await f.poll();
    if (failure === 'transport') read.reject(new Error('Synthetic read failed'));
    else if (failure === 'json') read.resolve({ ok: true, status: 200, json: async () => { throw new Error('Synthetic malformed JSON'); } });
    else if (failure === 'http') read.resolve({ ok: false, status: 503 });
    else read.resolve(response({ ...record(), id: 'another-attack' }));
    await tick();
    assert.equal(f.state.fuzzerAttackRecord, prior);
    assert.equal(f.state.fuzzerRunningAttackId, 'attack-a');
    assert.match(f.state.fuzzerNotice, /Retrying/);
    const recovered = await f.poll(); recovered.resolve(response(record(2))); await tick();
    assert.equal(f.state.fuzzerAttackRecord.results.length, 2);
    assert.equal(f.state.fuzzerNotice, '');
    assert.equal(f.state.fuzzerNoticeError, false);
    assert.equal(f.state._selectedFuzzerResultKey, 'row-0');
    const ended = await f.poll(); ended.resolve(response(record(3, false)));
    assert.equal((await f.following).results.length, 3);
  });
}

test('a removed attack retains the last rows without claiming completion or retrying forever', async () => {
  const f = fixture(), read = await f.poll();
  read.resolve({ ok: false, status: 404 });
  assert.equal(await f.following, null);
  assert.equal(f.state.fuzzerAttackRecord.results.length, 1);
  assert.equal(f.state.fuzzerAttackRecord.running, false);
  assert.equal(f.state.fuzzerAttackRecord.status, 'unavailable');
  assert.equal(f.state.fuzzerRunningAttackId, null);
  assert.equal(f.timers.length, 0);
  assert.match(f.state.fuzzerNotice, /Last received results/);
});

for (const failure of ['transport', 'json', 'http']) test(`a stale ${failure} failure cannot start retries or alter a newer view`, async () => {
  const f = fixture(), read = await f.poll();
  f.leave();
  const current = f.state.fuzzerAttackRecord = { id: 'new-attack', results: [] };
  f.state.fuzzerNotice = 'Current view';
  if (failure === 'transport') read.reject(new Error('Old transport failure'));
  else if (failure === 'json') read.resolve({ ok: true, status: 200, json: async () => { throw new Error('Old JSON failure'); } });
  else read.resolve({ ok: false, status: 503 });
  assert.equal(await f.following, null);
  assert.equal(f.state.fuzzerAttackRecord, current);
  assert.equal(f.state.fuzzerNotice, 'Current view');
  assert.equal(f.timers.length, 0);
});
