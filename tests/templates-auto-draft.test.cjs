const test = require('node:test');
const assert = require('node:assert/strict');
const { fixture, deferred, response, settle } = require('./templates-lifecycle-fixture.cjs');

const saved = (hosts) => response({ session_id: 'session-a', enabled: false, hosts, rate: 10, templates: 1 });
function edit(f, value, blur = true) {
  f.get('AutoHosts').value = value; f.get('AutoHosts').dispatch('input');
  if (blur) f.get('AutoHosts').dispatch('change');
}

test('editing auto-scan hosts during a save preserves the newer unsubmitted draft', async () => {
  const f = await fixture(), pending = deferred();
  f.intercept((request) => request.url === '/api/templates/auto' && request.method === 'POST' ? pending.promise : undefined);
  edit(f, 'first.example.com'); await settle();
  edit(f, 'draft.example.com', false);
  pending.resolve(saved(['first.example.com'])); await settle();
  assert.equal(f.get('AutoHosts').value, 'draft.example.com');
  assert.equal(f.requests.filter((r) => r.method === 'POST').length, 1, 'typing alone does not submit the new draft');
  f.controller.dispose();
});

test('a later blur saves its own values after the current auto-scan save finishes', async () => {
  const f = await fixture(), first = deferred(), second = deferred(); let writes = 0;
  f.intercept((request) => request.url === '/api/templates/auto' && request.method === 'POST' ? (++writes === 1 ? first.promise : second.promise) : undefined);
  edit(f, 'first.example.com'); await settle();
  edit(f, 'second.example.com');
  edit(f, 'third-draft.example.com', false);
  first.resolve(saved(['first.example.com'])); await settle();
  const posts = f.requests.filter((r) => r.method === 'POST');
  assert.equal(posts.length, 2);
  assert.deepEqual(posts[1].body.hosts, ['second.example.com'], 'the queued blur must not submit later typing');
  second.resolve(saved(['second.example.com'])); await settle();
  assert.equal(f.get('AutoHosts').value, 'third-draft.example.com');
  f.controller.dispose();
});

test('leaving the session discards queued auto-scan submissions rather than sending them elsewhere', async () => {
  const f = await fixture(), pending = deferred();
  f.intercept((request) => request.url === '/api/templates/auto' && request.method === 'POST' ? pending.promise : undefined);
  edit(f, 'first.example.com'); await settle(); edit(f, 'second.example.com');
  await f.session('session-b'); pending.resolve(saved(['first.example.com'])); await settle();
  assert.equal(f.requests.filter((r) => r.method === 'POST').length, 1);
  assert.equal(f.get('AutoHosts').value, 'session-b.example.com');
  f.controller.dispose();
});

test('editing hosts while enabling auto scan keeps the pending enabled choice', async () => {
  const f = await fixture(), first = deferred(), second = deferred(); let writes = 0;
  f.intercept((request) => request.url === '/api/templates/auto' && request.method === 'POST' ? (++writes === 1 ? first.promise : second.promise) : undefined);
  f.get('AutoToggle').dispatch('click'); await settle(); edit(f, 'changed.example.com');
  first.resolve(response({ session_id: 'session-a', enabled: true, hosts: ['session-a.example.com'], rate: 10, templates: 1 })); await settle();
  const posts = f.requests.filter((r) => r.method === 'POST');
  assert.equal(posts.length, 2);
  assert.equal(posts[1].body.enabled, true);
  assert.equal(posts[1].body.acknowledged, true);
  second.resolve(response({ session_id: 'session-a', enabled: true, hosts: ['changed.example.com'], rate: 10, templates: 1 })); await settle();
  f.controller.dispose();
});

test('polling does not read auto-scan settings while a save is pending', async () => {
  const f = await fixture(), pending = deferred();
  f.intercept((request) => request.url === '/api/templates/auto' && request.method === 'POST' ? pending.promise : undefined);
  edit(f, 'saving.example.com'); await settle();
  const count = f.requests.filter((r) => r.url.startsWith('/api/templates/auto?')).length;
  await f.controller.syncSession();
  assert.equal(f.requests.filter((r) => r.url.startsWith('/api/templates/auto?')).length, count, 'pre-save state must not race the pending settings');
  pending.resolve(saved(['saving.example.com'])); await settle();
  assert.ok(f.requests.filter((r) => r.url.startsWith('/api/templates/auto?')).length > count, 'the saved settings are reread after completion');
  f.controller.dispose();
});
