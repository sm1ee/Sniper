const test = require('node:test');
const assert = require('node:assert/strict');
const { fixture, scan, deferred, response, settle } = require('./templates-lifecycle-fixture.cjs');

function autoJob(session = 'session-a') { return { ...scan('auto-job', session), auto: true }; }

test('a reconciled auto job leaves manual Start available, and only a click starts it', async () => {
  const f = await fixture(); f.jobs.set('session-a', [autoJob()]); await f.controller.syncSession();
  assert.equal(f.get('ScanStart').disabled, false);
  assert.equal(f.get('ScanStart').textContent, 'Start scan');
  f.runTimers(); await settle();
  assert.equal(f.requests.filter((r) => r.method === 'POST').length, 0);
  f.get('ScanStart').dispatch('click'); await settle();
  const mutations = f.requests.filter((r) => r.method === 'POST');
  assert.equal(mutations.length, 1);
  assert.equal(mutations[0].url, '/api/templates/scans', 'the server owns auto-scan preemption');
  assert.equal(mutations[0].body.acknowledged, true);
  f.controller.dispose();
});

for (const auto of [false, undefined]) {
  test(`a running manual job (${String(auto)}) still blocks Start`, async () => {
    const f = await fixture(); const job = scan('manual-job'); if (auto !== undefined) job.auto = auto;
    f.jobs.set('session-a', [job]); await f.controller.syncSession();
    assert.equal(f.get('ScanStart').disabled, true);
    f.get('ScanStart').dispatch('click'); await settle();
    assert.equal(f.requests.filter((r) => r.method === 'POST').length, 0); f.controller.dispose();
  });
}

test('an unreconciled session cannot start even if its eventual job is automatic', async () => {
  const f = await fixture(), pending = deferred();
  f.intercept((r) => r.url.startsWith('/api/templates/scans?') ? pending.promise : undefined);
  const switching = f.session('session-b'); await settle();
  assert.equal(f.get('ScanStart').disabled, true);
  f.get('ScanStart').dispatch('click'); await settle();
  assert.equal(f.requests.filter((r) => r.method === 'POST').length, 0);
  pending.resolve(response({ session_id: 'session-b', jobs: [autoJob('session-b')] })); await switching;
  assert.equal(f.get('ScanStart').disabled, false); f.controller.dispose();
});

test('an older auto-job read cannot unlock Start during manual preemption', async () => {
  const f = await fixture(), reading = deferred(), starting = deferred(); let holdRead = true;
  f.jobs.set('session-a', [autoJob()]); await f.controller.syncSession();
  f.intercept((r) => r.url.startsWith('/api/templates/scans?') && holdRead ? reading.promise
    : r.url === '/api/templates/scans' && r.method === 'POST' ? starting.promise : undefined);
  const stale = f.controller.syncSession();
  f.get('ScanStart').dispatch('click'); await settle();
  reading.resolve(response({ session_id: 'session-a', jobs: [autoJob()] })); await stale;
  assert.equal(f.get('ScanStart').disabled, true);
  holdRead = false; f.jobs.set('session-a', [scan('manual-job')]);
  starting.resolve(response(scan('manual-job'))); await settle();
  assert.equal(f.get('ScanStart').disabled, true);
  assert.equal(f.requests.filter((r) => r.method === 'POST').length, 1); f.controller.dispose();
});

for (const bad of [null, { ...scan('bad-mode'), auto: 'true' }, { ...autoJob(), status: 'unknown' }]) {
  test(`a malformed job cannot be treated as permission to start (${JSON.stringify(bad)})`, async () => {
    const f = await fixture(); f.jobs.set('session-a', [bad]); await f.controller.syncSession();
    assert.equal(f.get('ScanStart').disabled, true);
    f.get('ScanStart').dispatch('click'); await settle();
    assert.equal(f.requests.filter((r) => r.method === 'POST').length, 0);
    assert.match(f.get('ScanNotice').textContent, /Could not read/); f.controller.dispose();
  });
}

test('manual priority does not bypass the template-library gate', async () => {
  const f = await fixture(); f.jobs.set('session-a', [autoJob()]); await f.controller.syncSession();
  f.intercept((r) => r.url === '/api/templates/library' ? response({ state: 'idle', library: null }) : undefined);
  await f.controller.refresh();
  assert.equal(f.get('ScanStart').disabled, true);
  f.get('ScanStart').dispatch('click'); await settle();
  assert.equal(f.requests.filter((r) => r.method === 'POST').length, 0); f.controller.dispose();
});
