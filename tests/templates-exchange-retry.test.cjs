// Retained-result controller reads only; no runtime, browser or external traffic.
const test = require('node:test');
const assert = require('node:assert/strict');
const { fixture, scan, response, deferred, inside, settle } = require('./templates-lifecycle-fixture.cjs');
const text = f => f.get('Detail').children.map(node => node.textContent).join(' ');
const history = f => f.get('Detail').children.find(node => node.dataset?.recordId);
const row = (id = 'record-a') => ({ at: '2026-10-25T00:00:00Z', template_id: 'synthetic-template', method: 'GET',
  url: `https://example.com/${id}`, record_id: id, status: 200, ms: 1, matched: true });
const captured = (id = 'record-a', path = '/recovered') => response({ id, method: 'GET', path, status: 200 });
const failure = (status = 503) => ({ ok: false, status, text: async () => `Synthetic exchange failure ${status}` });
const reads = f => f.requests.filter(request => request.url.startsWith('/api/transactions/'));
async function select(f, index = 0) {
  f.get('ResultsRows').dispatch('click', { target: inside(f.get('ResultsRows').children[index]) }); await settle();
}
async function setup(intercept, status = 'completed', twoRows = false) {
  const f = await fixture(), job = scan('retained-job', 'session-a', status);
  job.sent = 1; job.matched = 1; job.recent = twoRows ? [row(), row('record-b')] : [row()];
  f.jobs.set('session-a', [job]); f.intercept(intercept);
  await f.controller.syncSession();
  f.get('ScanJobs').dispatch('click', { target: inside(f.get('ScanJobs').children[0]) }); await settle();
  await select(f);
  return f;
}

for (const outcome of ['fetch', 'http', 'json']) test(`same-row selection retries a transient ${outcome} failure and shares its pending read`, async () => {
  let count = 0; const replacement = deferred();
  const f = await setup(request => request.url.startsWith('/api/transactions/') ? (++count > 1 ? replacement.promise
    : outcome === 'fetch' ? Promise.reject(new Error('Synthetic exchange failure'))
      : outcome === 'json' ? { ok: true, json: async () => { throw new Error('Synthetic exchange failure'); } } : failure()) : undefined);
  assert.match(text(f), /Synthetic exchange failure/); assert.equal(history(f), undefined);
  await select(f); assert.equal(count, 2, 'an explicit retry must start a replacement transaction read');
  await select(f); await f.controller.syncSession(); assert.equal(count, 2, 'pending retry is shared');
  replacement.resolve(captured()); await settle();
  assert.match(text(f), /GET \/recovered/); assert.equal(history(f)?.dataset.recordId, 'record-a');
  assert.ok(f.requests.every(request => request.method === 'GET'));
  f.controller.dispose();
});

test('hide and reentry retry a failed exchange once without another click', async () => {
  let count = 0; const replacement = deferred();
  const f = await setup(request => request.url.startsWith('/api/transactions/') ? (++count === 1 ? failure() : replacement.promise) : undefined);
  f.controller.setVisible(false); f.controller.setVisible(true); await settle();
  assert.equal(count, 2);
  f.controller.setVisible(true); await select(f); await f.controller.syncSession(); assert.equal(count, 2);
  replacement.resolve(captured()); await settle(); assert.match(text(f), /GET \/recovered/);
  f.controller.dispose();
});

test('healthy loaded exchanges stay cached across selection, refresh and reentry', async () => {
  const f = await setup(request => request.url.startsWith('/api/transactions/') ? captured() : undefined);
  await select(f); await f.controller.syncSession();
  f.controller.setVisible(false); f.controller.setVisible(true); await settle();
  assert.equal(reads(f).length, 1); assert.match(text(f), /GET \/recovered/);
  f.controller.dispose();
});

test('a permanent 404 does not trigger repeated exchange reads during running-job polling', async () => {
  const f = await setup(request => request.url.startsWith('/api/transactions/') ? failure(404) : undefined, 'running');
  assert.equal(reads(f).length, 1);
  for (let pass = 0; pass < 4; pass++) { f.runTimers(); await settle(); }
  await f.controller.syncSession(); assert.equal(reads(f).length, 1);
  assert.match(text(f), /failure 404/); assert.equal(history(f), undefined);
  assert.equal(f.get('ResultsStop').classList.contains('hidden'), false);
  assert.equal(f.get('ResultsStop').disabled, false);
  assert.equal(f.get('ScanStart').disabled, true, 'known running manual job remains owned');
  assert.ok(f.requests.every(request => request.method === 'GET'));
  f.controller.dispose();
});

test('an exchange error does not block or repeat the known running job Stop', async () => {
  const f = await setup(request => request.url.startsWith('/api/transactions/') ? failure() : undefined, 'running');
  f.intercept(request => {
    if (request.url.startsWith('/api/transactions/')) return failure();
    if (request.method === 'POST' && request.url.endsWith('/stop')) {
      f.jobs.get('session-a')[0].status = 'stopped'; return response(f.jobs.get('session-a')[0]);
    }
  });
  f.get('ResultsStop').dispatch('click'); await settle();
  assert.equal(f.requests.filter(request => request.method === 'POST').length, 1);
  assert.equal(f.requests.find(request => request.method === 'POST').url, '/api/templates/scans/retained-job/stop');
  assert.equal(reads(f).length, 1);
  assert.equal(f.get('ResultsStop').classList.contains('hidden'), true);
  f.runTimers(); await settle(); assert.equal(f.requests.filter(request => request.method === 'POST').length, 1);
  f.controller.dispose();
});

for (const boundary of ['row', 'job', 'session', 'hide', 'dispose']) for (const outcome of ['success', 'error-body']) {
  test(`a retried exchange ${outcome} cannot publish after ${boundary}`, async () => {
    let count = 0; const late = deferred(), body = deferred();
    const f = await setup(request => {
      if (!request.url.startsWith('/api/transactions/')) return;
      if (request.url.includes('/record-b?')) return captured('record-b', '/newer');
      if (++count === 1) return failure();
      if (count === 2) return outcome === 'error-body' ? { ok: false, status: 503, text: () => body.promise } : late.promise;
      return captured('record-a', '/reentered');
    }, 'completed', true);
    await select(f); assert.equal(count, 2, 'the delayed response belongs to the retry');
    if (boundary === 'row') await select(f, 1);
    if (boundary === 'job') {
      const newer = scan('newer-job', 'session-a', 'completed'); newer.recent = [row('record-b')];
      f.jobs.set('session-a', [newer]); await f.controller.syncSession();
      f.get('ScanJobs').dispatch('click', { target: inside(f.get('ScanJobs').children[0]) }); await settle(); await select(f);
    }
    if (boundary === 'session') await f.session('session-b');
    if (boundary === 'hide') f.controller.setVisible(false);
    if (boundary === 'dispose') f.controller.dispose();
    const before = text(f), beforeReads = reads(f).length;
    if (outcome === 'error-body') body.resolve('stale retry error'); else late.resolve(captured('record-a', '/stale'));
    await settle(); assert.equal(text(f), before); assert.equal(reads(f).length, beforeReads);
    assert.doesNotMatch(text(f), /stale retry error|GET \/stale/);
    if (boundary === 'hide') {
      f.controller.setVisible(true); await settle(); assert.equal(count, 3); assert.match(text(f), /GET \/reentered/);
    }
    assert.ok(f.requests.every(request => request.method === 'GET'));
    f.controller.dispose();
  });
}
