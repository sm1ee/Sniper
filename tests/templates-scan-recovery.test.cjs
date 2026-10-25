const test = require('node:test');
const assert = require('node:assert/strict');
const { fixture, scan, deferred, response, settle } = require('./templates-lifecycle-fixture.cjs');

test('a session must reconcile its jobs before Start, and a failed read retries without starting', async () => {
  const f = await fixture(); f.jobs.set('session-b', [scan('already-running', 'session-b')]);
  f.intercept((r) => r.url.startsWith('/api/templates/scans?') ? Promise.reject(new Error('temporary read failure')) : undefined);
  await f.session('session-b');
  assert.equal(f.get('ScanStart').disabled, true);
  assert.equal(f.timers.size, 1);
  f.get('ScanStart').dispatch('click'); await settle();
  assert.equal(f.requests.filter((r) => r.url === '/api/templates/scans' && r.method === 'POST').length, 0);
  f.intercept(() => undefined); f.runTimers(); await settle();
  assert.equal(f.get('ScanJobs').children[0].dataset.openScan, 'already-running');
  assert.equal(f.get('ScanStart').disabled, true);
  assert.equal(f.get('ScanNotice').textContent, '');
  f.controller.dispose();
});

test('a transient list failure retains the known jobs until a successful retry', async () => {
  const f = await fixture(); f.jobs.set('session-a', [scan('known-job')]); await f.controller.syncSession();
  f.intercept((r) => r.url.startsWith('/api/templates/scans?') ? Promise.reject(new Error('temporarily offline')) : undefined);
  await f.controller.syncSession();
  assert.equal(f.get('ScanJobs').children[0].dataset.openScan, 'known-job');
  assert.equal(f.get('ScanStart').disabled, true);
  f.jobs.set('session-a', []); f.intercept(() => undefined); f.runTimers(); await settle();
  assert.equal(f.get('ScanJobs').children.length, 0);
  assert.equal(f.get('ScanStart').disabled, false);
  assert.equal(f.get('ScanNotice').textContent, '');
  f.controller.dispose();
});

test('failed read retries stop while hidden and reopening first reconciles the session', async () => {
  const f = await fixture();
  f.intercept((r) => r.url.startsWith('/api/templates/scans?') ? Promise.reject(new Error('offline')) : undefined);
  await f.controller.syncSession();
  const retry = [...f.timers.values()][0]; assert.equal(typeof retry, 'function');
  f.controller.setVisible(false); assert.equal(f.timers.size, 0);
  const before = f.requests.length; retry(); await settle(); assert.equal(f.requests.length, before);
  const pending = deferred(); f.intercept((r) => r.url.startsWith('/api/templates/scans?') ? pending.promise : undefined);
  f.controller.setVisible(true); await settle(); assert.equal(f.get('ScanStart').disabled, true);
  pending.resolve(response({ session_id: 'session-a', jobs: [] })); await settle();
  assert.equal(f.get('ScanStart').disabled, false); f.controller.dispose();
});

test('a failure body arriving after a session switch cannot publish an error or retry', async () => {
  const f = await fixture(), body = deferred();
  f.intercept((r) => r.url.startsWith('/api/templates/scans?') && r.url.endsWith('session_id=session-a')
    ? { ok: false, status: 503, text: () => body.promise } : undefined);
  const old = f.controller.syncSession(); await settle(); await f.session('session-b');
  body.resolve('old read failure'); await old;
  assert.equal(f.get('ScanNotice').textContent, ''); assert.equal(f.timers.size, 0);
  assert.equal(f.get('ScanStart').disabled, false); f.controller.dispose();
});

test('manual mutations invalidate prior reads and reconcile before allowing another start', async () => {
  const f = await fixture(), starting = deferred(), reconciled = deferred(); let reconcile = false;
  f.intercept((r) => r.url === '/api/templates/scans' && !r.body.preview ? starting.promise
    : r.url.startsWith('/api/templates/scans?') && reconcile ? reconciled.promise : undefined);
  f.get('ScanStart').dispatch('click'); await settle();
  const reads = f.requests.filter((r) => r.url.startsWith('/api/templates/scans?')).length;
  await f.controller.syncSession();
  assert.equal(f.requests.filter((r) => r.url.startsWith('/api/templates/scans?')).length, reads);
  reconcile = true; starting.resolve(response(scan('started'))); await settle();
  assert.equal(f.get('ScanStart').disabled, true);
  reconciled.resolve(response({ session_id: 'session-a', jobs: [scan('started')] })); await settle();
  assert.equal(f.get('ScanStart').disabled, true); f.controller.dispose();
});

test('malformed scan lists do not erase known jobs or enable another start', async () => {
  const f = await fixture(); f.jobs.set('session-a', [scan('known-job')]); await f.controller.syncSession();
  f.intercept((r) => r.url.startsWith('/api/templates/scans?') ? response({ session_id: 'session-a' }) : undefined);
  await f.controller.syncSession();
  assert.equal(f.get('ScanJobs').children[0]?.dataset.openScan, 'known-job');
  assert.equal(f.get('ScanStart').disabled, true); assert.equal(f.timers.size, 1); f.controller.dispose();
});

test('a failed auto-scan read is retried even when no manual job is known', async () => {
  const f = await fixture();
  f.intercept((r) => r.url.startsWith('/api/templates/auto?') ? Promise.reject(new Error('auto read failure')) : undefined);
  await f.controller.syncSession(); assert.equal(f.timers.size, 1);
  f.intercept(() => undefined); f.runTimers(); await settle();
  assert.equal(f.get('AutoNotice').textContent, ''); f.controller.dispose();
});

test('read retries never repeat a failed Start or erase its refusal', async () => {
  const f = await fixture(); let listFails = true;
  f.intercept((r) => r.url === '/api/templates/scans' && r.method === 'POST'
    ? Promise.reject(new Error('start refused'))
    : listFails && r.url.startsWith('/api/templates/scans?') ? Promise.reject(new Error('list read failed')) : undefined);
  f.get('ScanStart').dispatch('click'); await settle();
  assert.equal(f.get('ScanNotice').textContent, 'start refused');
  f.runTimers(); await settle();
  listFails = false; f.runTimers(); await settle();
  assert.equal(f.requests.filter((r) => r.url === '/api/templates/scans' && r.method === 'POST').length, 1);
  assert.equal(f.get('ScanNotice').textContent, 'start refused');
  f.controller.dispose();
});
