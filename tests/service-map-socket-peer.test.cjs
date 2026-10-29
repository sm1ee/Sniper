// Synthetic passive metadata and inert DOM; no bootstrap or proxy actions.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../web/service-map.js'), 'utf8');
const context = vm.createContext({ URL, URLSearchParams, AbortController, console });
vm.runInContext(source, context);
const map = context.SniperServiceMap;
const originA = 'https://app.example.com';
const originB = 'https://api.example.com';
const recordId = '11111111-1111-4111-8111-111111111111';
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function response(payload, status = 200) { return { ok: status < 400, status, json: async () => payload }; }
function endpoint(path = '/users', method = 'GET', id = 'evidence-one') { return { method, path, request_count: 2, statuses: [200], content_types: ['application/json'], evidence: [id] }; }
function origin(id, endpoints = [endpoint()]) { return { origin: id, in_scope: true, request_count: 2, endpoints, technology_clues: [], redirects: [], header_links: [] }; }
function snapshot(origins = [origin(originA), origin(originB)], session = 'session-one', extra = {}) {
  return { schema_version: 1, session_id: session, snapshot: { generation: 'generation-one', complete: true, stopped_by: [], limits: { records: 10000 }, considered_rows: 4, retained_rows: 4, included_rows: 4, excluded_rows: 0, omitted_rows: 0, oldest_considered_at: '2026-10-12T01:00:00Z', latest_considered_at: '2026-10-12T02:00:00Z', ...extra }, origins, unavailable: ['initiator', 'remote_ip', 'tls_certificate'], deferred: ['response_body_references'], warnings: [] };
}
function evidence(id = 'evidence-one', rowOrigin = originA, extra = {}) {
  return { schema_version: 1, session_id: 'session-one', evidence_id: id, available: true, source: 'captured_http_metadata', row: { evidence_id: id, origin: rowOrigin, method: 'GET', path: '/users', sequence: '9007199254740993', record_id: recordId, status: 200, started_at: '2026-10-12T01:00:00Z', metadata_complete: true, omitted: [] }, ...extra };
}
function node() {
  const handlers = new Map(), classes = new Set();
  let html = '', replacements = 0;
  return {
    value: '', checked: false, disabled: false, dataset: {}, attributes: {}, textContent: '', scrollTop: 0,
    classList: { toggle(name, value) { if (value) classes.add(name); else classes.delete(name); }, contains: name => classes.has(name) },
    setAttribute(name, value) { this.attributes[name] = value; },
    addEventListener(name, callback) { handlers.set(name, callback); },
    dispatch(name, event = {}) { return handlers.get(name)?.({ target: this, ...event }); },
    contains: () => true, querySelectorAll: () => [],
    get innerHTML() { return html; }, set innerHTML(value) { html = value; replacements += 1; },
    get replacements() { return replacements; },
  };
}
function fixture() {
  let session = 'session-one';
  const requests = [];
  const els = Object.fromEntries(['panel', 'status', 'refresh', 'search', 'scope', 'canvas', 'graphBounds', 'detail', 'content', 'catalog', 'mapControls', 'allOrigins', 'directRelations', 'focusSelection', 'boundsDetails', 'graphDiagnostics', 'overlayStatus'].map(name => [name, node()]));
  const document = { activeElement: null, body: {}, querySelector: () => null };
  const controller = map.createController({ elements: els, getSessionId: () => session, document, request(url, options) { const pending = deferred(); requests.push({ url, options, ...pending }); return pending.promise; } });
  controller.setVisible(true);
  return { controller, els, requests, document, state: controller.getState(), setSession(value) { session = value; }, async load(payload = snapshot()) { const pending = controller.refresh(); requests.at(-1).resolve(response(payload)); await pending; } };
}

const observed = (ip = '192.0.2.10', port = 443, route = 'direct') => ({ status: 'observed', observation: { source: 'http_response_remote_addr', observed_at: '2026-10-12T01:00:01.123456789Z', route, address: { ip, port }, reason: null } });
for (const [ip, port, route, label] of [['192.0.2.10', 443, 'direct', 'Direct'], ['2001:db8::a', 8443, 'http_proxy', 'HTTP proxy'], ['::ffff:192.0.2.20', 1080, 'socks_proxy', 'SOCKS proxy'], ['::1', 0, 'unknown', 'Unknown']]) test(`allowlisted ${route} ${ip} appears only in exact evidence using one opted-in GET`, async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA); const beforeCanvas = f.els.canvas.innerHTML;
  const pending = f.controller.loadEvidence('evidence-one');
  assert.equal(new URL(f.requests.at(-1).url, 'http://example.com').searchParams.get('include_socket_peer'), 'true');
  f.requests.at(-1).resolve(response(evidence('evidence-one', originA, { socket_peer: observed(ip, port, route) }))); await pending;
  assert.equal(f.requests.length, 2); assert.equal(f.els.canvas.innerHTML, beforeCanvas);
  assert.match(f.els.detail.innerHTML, /<summary>Capture info<\/summary>/); assert.match(f.els.detail.innerHTML, /Recorded peer/); assert.ok(f.els.detail.innerHTML.includes(ip));
  assert.ok(f.els.detail.innerHTML.includes(label)); assert.match(f.els.detail.innerHTML, /Response headers observed at/);
  assert.doesNotMatch(f.els.canvas.innerHTML, /192\.0|2001:db8|Upstream socket peer/);
});
for (const [value, phrase, name] of [[{ status: 'not_recorded', observation: null }, null, 'not recorded'], [undefined, null, 'from an older server'], [{ status: 'unavailable', observation: { ...observed().observation, address: null, reason: 'remote_addr_unavailable' } }, 'Unavailable at response headers', 'unavailable']]) test(`a socket peer shows only when one was recorded: ${name}`, async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA); const pending = f.controller.loadEvidence('evidence-one');
  f.requests.at(-1).resolve(response(evidence('evidence-one', originA, { socket_peer: value }))); await pending;
  if (phrase) assert.ok(f.els.detail.innerHTML.includes(phrase)); else assert.doesNotMatch(f.els.detail.innerHTML, /Upstream socket peer|Matching recorded socket peers/);
  assert.doesNotMatch(f.els.detail.innerHTML, /was enabled|was disabled|was Off|capture failed/);
});
const invalid = [null, {}, { status: 'not_recorded', observation: observed().observation }, ...[
  { source: '<img onerror=alert(1)>' }, { route: { raw: 'secret' } }, { observed_at: '<img src=x>' }, { observed_at: 'yesterday' },
  { address: { ip: 'example.com', port: 443 } }, { address: { ip: '999.2.3.4', port: 443 } }, { address: { ip: '192.00.2.1', port: 443 } },
  { address: { ip: '[2001:db8::1]', port: 443 } }, { address: { ip: 'fe80::1%eth0', port: 443 } }, { address: { ip: '2001:::a', port: 443 } },
  { address: { ip: '192.0.2.1', port: '443' } }, { address: { ip: '192.0.2.1', port: 65536 } }, { address: { ip: '192.0.2.1', port: -1 } },
  { reason: 'remote_addr_unavailable' },
].map(patch => ({ status: 'observed', observation: { ...observed().observation, ...patch } }))];
for (const [i, peer] of invalid.entries()) test(`malformed peer ${i} never enters the DOM or invalidates otherwise verified metadata`, async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA); const pending = f.controller.loadEvidence('evidence-one');
  f.requests.at(-1).resolve(response(evidence('evidence-one', originA, { socket_peer: peer }))); assert.equal(await pending, true);
  assert.match(f.els.detail.innerHTML, /Capture info/); assert.match(f.els.detail.innerHTML, /Socket peer details could not be verified/);
  assert.doesNotMatch(f.els.detail.innerHTML, /<img|onerror|\[object Object\]|eth0|999\.2/);
});
test('unexpected raw fields are never copied into normalized observations', () => {
  const peer = observed(); peer.secret = '<raw secret>'; peer.observation.token = 'secret-token'; peer.observation.address.hostname = 'private-host';
  const normalized = map.normalizeSocketPeer(peer);
  assert.equal(normalized.status, 'observed'); assert.equal(JSON.stringify(normalized).includes('secret'), false);
  assert.equal(JSON.stringify(normalized).includes('private-host'), false);
});
for (const action of ['new evidence', 'new origin', 'session ABA', 'generation', 'disconnect', 'transaction']) test(`peer clears with metadata and delayed response cannot return after ${action}`, async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA);
  const first = f.controller.loadEvidence('evidence-one'); const old = f.requests.at(-1);
  if (action === 'new evidence') { const newer = f.controller.loadEvidence('evidence-one'); f.requests.at(-1).resolve(response(evidence('evidence-one', originA, { socket_peer: { status: 'not_recorded', observation: null } }))); await newer; }
  else if (action === 'new origin') f.controller.selectOrigin(originB);
  else if (action === 'session ABA') { f.setSession('session-two'); f.controller.reset(); f.setSession('session-one'); f.controller.reset(); }
  else if (action === 'generation') await f.load(snapshot(undefined, 'session-one', { generation: 'generation-two' }));
  else if (action === 'disconnect') f.controller.disconnect();
  else f.controller.markDirty();
  old.resolve(response(evidence('evidence-one', originA, { socket_peer: observed() }))); assert.equal(await first, false);
  assert.notEqual(f.state.socketPeer?.status, 'observed'); assert.doesNotMatch(f.els.detail.innerHTML, /192\.0\.2\.10/);
});
test('unavailable exact row never displays a peer envelope, even if response tries to supply one', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA); const pending = f.controller.loadEvidence('evidence-one');
  f.requests.at(-1).resolve(response(evidence('evidence-one', originA, { available: false, row: null, socket_peer: observed() }))); await pending;
  assert.equal(f.state.socketPeer, null); assert.doesNotMatch(f.els.detail.innerHTML, /192\.0\.2\.10/);
});

test('hiding retains exact metadata and its peer together without broadening the existing evidence lifecycle', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA);
  const pending = f.controller.loadEvidence('evidence-one'); f.controller.setVisible(false);
  f.requests.at(-1).resolve(response(evidence('evidence-one', originA, { socket_peer: observed() })));
  assert.equal(await pending, true);
  assert.equal(f.state.evidence.evidence_id, 'evidence-one'); assert.equal(f.state.socketPeer.status, 'observed');
  const row = f.state.evidence, peer = f.state.socketPeer, count = f.requests.length;
  f.controller.setVisible(true);
  assert.equal(f.state.evidence, row); assert.equal(f.state.socketPeer, peer); assert.equal(f.requests.length, count);
  assert.match(f.els.detail.innerHTML, /192\.0\.2\.10/);
});
test('hidden pending evidence cannot reappear after its session identity is reset, even on returning to A', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA);
  const pending = f.controller.loadEvidence('evidence-one'), old = f.requests.at(-1); f.controller.setVisible(false);
  f.setSession('session-two'); f.controller.reset(); f.setSession('session-one'); f.controller.reset();
  old.resolve(response(evidence('evidence-one', originA, { socket_peer: observed() }))); assert.equal(await pending, false);
  f.controller.setVisible(true);
  assert.equal(f.state.evidence, null); assert.equal(f.state.socketPeer, null);
  assert.doesNotMatch(f.els.detail.innerHTML, /192\.0\.2\.10/);
});
