const test = require('node:test');
const assert = require('node:assert/strict');
const { fixture, deferred, response, scan, settle, inside } = require('./templates-lifecycle-fixture.cjs');

test('a manual start belongs to its session even if its response arrives after switching', async () => {
  const f = await fixture(), pending = deferred();
  f.intercept((request) => request.url === '/api/templates/scans' && !request.body.preview ? pending.promise : undefined);
  f.get('ScanStart').dispatch('click');
  await settle();
  await f.session('session-b');
  assert.equal(f.get('ScanStart').disabled, false, 'another session is not busy with the old start');
  pending.resolve(response(scan('old-start'))); await settle();
  assert.equal(f.get('ResultsTitle').textContent, '', 'the old scan must not open in the new session');
  assert.equal(f.get('ScanNotice').textContent, '');
  f.controller.dispose();
});

test('an auto-scan save cannot replace another session\'s hosts or toggle', async () => {
  const f = await fixture(), pending = deferred();
  f.intercept((request) => request.url === '/api/templates/auto' && request.method === 'POST' ? pending.promise : undefined);
  f.get('AutoToggle').dispatch('click'); await settle();
  await f.session('session-b');
  assert.equal(f.get('AutoToggle').disabled, false);
  pending.resolve(response({ session_id: 'session-a', enabled: true, hosts: ['old.example.com'], rate: 5, templates: 1 })); await settle();
  assert.equal(f.get('AutoHosts').value, 'session-b.example.com');
  assert.equal(f.get('AutoToggle').getAttribute('aria-checked'), 'false');
  f.controller.dispose();
});

test('the newest scan refresh wins over an earlier response for the same session', async () => {
  const f = await fixture(), first = deferred(), second = deferred(); let reads = 0;
  f.intercept((request) => request.url.startsWith('/api/templates/scans?') ? (++reads === 1 ? first.promise : second.promise) : undefined);
  const older = f.controller.syncSession(); const newer = f.controller.syncSession();
  second.resolve(response({ session_id: 'session-a', jobs: [scan('new-job', 'session-a', 'completed')] })); await newer;
  first.resolve(response({ session_id: 'session-a', jobs: [scan('stale-job')] })); await older;
  assert.equal(f.get('ScanJobs').children[0].dataset.openScan, 'new-job');
  assert.equal(f.get('ScanStart').disabled, false);
  f.controller.dispose();
});

test('a stale session read failure does not report an error in the current session', async () => {
  const f = await fixture(), pending = deferred();
  f.intercept((request) => request.url.endsWith('session_id=session-a') && request.url.startsWith('/api/templates/scans?') ? pending.promise : undefined);
  const old = f.controller.syncSession(); await f.session('session-b');
  pending.reject(new Error('old session failed')); await old;
  assert.equal(f.get('ScanNotice').textContent, '');
  f.controller.dispose();
});

test('a new form edit invalidates an in-flight preview before the debounce runs', async () => {
  const f = await fixture(), pending = deferred();
  f.intercept((request) => request.url === '/api/templates/scans' && request.body.preview ? pending.promise : undefined);
  f.get('ScanTargets').dispatch('input'); f.runTimers(); await settle();
  f.get('ScanTargets').value = 'https://new.example.com'; f.get('ScanTargets').dispatch('input');
  pending.resolve(response({ requests: 1, templates: 1, targets: ['https://old.example.com'] })); await settle();
  assert.equal(f.get('ScanPlan').textContent, '', 'the old target preview is not consent for the new form');
  f.controller.dispose();
});

test('switching away and back does not revive a start or clear a newer action', async () => {
  const f = await fixture(), old = deferred(), current = deferred(); let starts = 0;
  f.intercept((request) => request.url === '/api/templates/scans' && !request.body.preview ? (++starts === 1 ? old.promise : current.promise) : undefined);
  f.get('ScanStart').dispatch('click'); await settle();
  await f.session('session-b'); await f.session('session-a');
  f.get('ScanStart').dispatch('click'); await settle();
  old.resolve(response(scan('old-job'))); await settle();
  assert.equal(f.get('ScanStart').disabled, true, 'the second action still owns busy state');
  assert.equal(f.get('ResultsTitle').textContent, '');
  current.resolve(response(scan('current-job'))); await settle();
  assert.match(f.get('ResultsTitle').textContent, /current-job/);
  f.controller.dispose();
});

test('hiding and reopening Scan leaves a late start for the job list to reconcile', async () => {
  const f = await fixture(), pending = deferred();
  f.intercept((request) => request.url === '/api/templates/scans' && !request.body.preview ? pending.promise : undefined);
  f.get('ScanStart').dispatch('click'); await settle();
  f.controller.setVisible(false); f.controller.setVisible(true); await settle();
  pending.resolve(response(scan('old-job'))); await settle();
  assert.equal(f.get('ResultsTitle').textContent, '');
  f.controller.dispose();
});

test('disposing Scan invalidates reads without restarting polling', async () => {
  const f = await fixture(), pending = deferred();
  f.intercept((request) => request.url.startsWith('/api/templates/scans?') ? pending.promise : undefined);
  const reading = f.controller.syncSession(); f.controller.dispose();
  const count = f.requests.length;
  pending.resolve(response({ session_id: 'session-a', jobs: [scan('late-job')] })); await reading;
  assert.equal(f.get('ScanJobs').children.length, 0);
  assert.equal(f.requests.length, count);
  assert.equal(f.timers.size, 0);
});

test('a previous session\'s start failure cannot erase the current status', async () => {
  const f = await fixture(), pending = deferred();
  f.intercept((request) => request.url === '/api/templates/scans' && !request.body.preview ? pending.promise : undefined);
  f.get('ScanStart').dispatch('click'); await settle(); await f.session('session-b');
  pending.reject(new Error('old start failed')); await settle();
  assert.equal(f.get('ScanNotice').textContent, '');
  assert.equal(f.get('ScanStart').disabled, false);
  f.controller.dispose();
});

test('an earlier auto-scan read cannot overwrite a newer read', async () => {
  const f = await fixture(), first = deferred(), second = deferred(); let reads = 0;
  f.intercept((request) => request.url.startsWith('/api/templates/auto?') ? (++reads === 1 ? first.promise : second.promise) : undefined);
  const old = f.controller.syncSession(); await settle();
  const current = f.controller.syncSession(); await settle();
  second.resolve(response({ session_id: 'session-a', enabled: true, hosts: ['new.example.com'], rate: 5, templates: 1 })); await current;
  first.resolve(response({ session_id: 'session-a', enabled: false, hosts: ['old.example.com'], rate: 10, templates: 1 })); await old;
  assert.equal(f.get('AutoHosts').value, 'new.example.com');
  assert.equal(f.get('AutoToggle').getAttribute('aria-checked'), 'true');
  f.controller.dispose();
});


test('reopening Scan reloads a selected exchange whose earlier read was invalidated', async () => {
  const f = await fixture(), first = deferred(), second = deferred(); let reads = 0;
  const job = scan('selected-job', 'session-a', 'completed');
  job.recent = [{ at: '2026-10-25T00:00:00Z', template_id: 'example-template', method: 'GET', url: 'https://app.example.com/result', record_id: 'record-a', status: 200, ms: 1 }];
  f.jobs.set('session-a', [job]);
  f.intercept((request) => request.url.startsWith('/api/transactions/') ? (++reads === 1 ? first.promise : second.promise) : undefined);
  await f.controller.syncSession();
  f.get('ScanJobs').dispatch('click', { target: inside(f.get('ScanJobs').children[0]) }); await settle();
  f.get('ResultsRows').dispatch('click', { target: inside(f.get('ResultsRows').children[0]) }); await settle();
  assert.equal(reads, 1);
  f.controller.setVisible(false); f.controller.setVisible(true); await settle();
  assert.equal(reads, 2, 'the selected exchange automatically reloads on reentry');
  first.resolve(response({ method: 'GET', path: '/stale', status: 200 })); await settle();
  f.get('ResultsRows').dispatch('click', { target: inside(f.get('ResultsRows').children[0]) }); await settle();
  assert.equal(reads, 2, 'clicking the same row shares its replacement read');
  second.resolve(response({ method: 'GET', path: '/current', status: 200 })); await settle();
  const detail = f.get('Detail').children.map((node) => node.textContent).join(' ');
  assert.match(detail, /GET \/current/);
  assert.doesNotMatch(detail, /Loading|stale/);
  f.controller.dispose();
});

test('a start response does not replace a scan the operator chose while it was pending', async () => {
  const f = await fixture(), pending = deferred();
  const chosen = scan('chosen-job', 'session-a', 'completed'); f.jobs.set('session-a', [chosen]);
  await f.controller.syncSession();
  f.intercept((request) => request.url === '/api/templates/scans' && !request.body.preview ? pending.promise : undefined);
  f.get('ScanStart').dispatch('click'); await settle();
  f.get('ScanJobs').dispatch('click', { target: inside(f.get('ScanJobs').children[0]) }); await settle();
  pending.resolve(response(scan('just-started'))); await settle();
  assert.match(f.get('ResultsTitle').textContent, /chosen-job/);
  assert.doesNotMatch(f.get('ResultsTitle').textContent, /just-started/);
  f.controller.dispose();
});

test('a start response respects an explicit return to the template list', async () => {
  const f = await fixture(), pending = deferred();
  f.intercept((request) => request.url === '/api/templates/scans' && !request.body.preview ? pending.promise : undefined);
  f.get('ScanStart').dispatch('click'); await settle();
  f.get('Views').dispatch('click', { target: inside({ dataset: { templatesView: 'templates' } }) });
  pending.resolve(response(scan('just-started'))); await settle();
  assert.equal(f.get('ResultsTable').classList.contains('hidden'), true);
  f.controller.dispose();
});

test('selecting a template while Start waits keeps that newer template detail open', async () => {
  const f = await fixture(), pending = deferred();
  f.intercept((request) => request.url === '/api/templates/scans' && !request.body.preview ? pending.promise
    : request.url === '/api/templates/example-selected' ? response({ id: 'example-selected', name: 'Selected template', yaml: '' }) : undefined);
  f.get('ScanStart').dispatch('click'); await settle();
  f.get('Rows').dispatch('click', { target: inside({ dataset: { templateId: 'example-selected' } }) }); await settle();
  pending.resolve(response(scan('just-started'))); await settle();
  assert.equal(f.get('ResultsTable').classList.contains('hidden'), true);
  assert.equal(f.get('Detail').children[0].textContent, 'Selected template');
  f.controller.dispose();
});

test('refreshing a template after its On change does not cancel the pending start view', async () => {
  const f = await fixture(), pending = deferred();
  f.intercept((request) => request.url === '/api/templates/scans' && !request.body.preview ? pending.promise
    : request.url === '/api/templates/example-selected' ? response({ id: 'example-selected', name: 'Selected template', yaml: '' }) : undefined);
  f.get('Rows').dispatch('click', { target: inside({ dataset: { templateId: 'example-selected' } }) }); await settle();
  f.get('ScanStart').dispatch('click'); await settle();
  f.get('Rows').dispatch('click', { target: inside({ dataset: { templateToggle: 'example-selected' }, checked: true }) }); await settle();
  pending.resolve(response(scan('just-started'))); await settle();
  assert.equal(f.get('ResultsTable').classList.contains('hidden'), false);
  assert.match(f.get('ResultsTitle').textContent, /just-started/);
  f.controller.dispose();
});
