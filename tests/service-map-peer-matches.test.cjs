// Synthetic retained observations only. No capture, DNS, proxy, or app bootstrap.
'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const context = vm.createContext({ URL, URLSearchParams, AbortController, console });
vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/service-map.js'), 'utf8'), context);
const map = context.SniperServiceMap;
const SESSION = '11111111-1111-4111-8111-111111111111';
const GENERATION = '22222222-2222-4222-8222-222222222222';
const ROW = '33333333-3333-4333-8333-333333333333';
const REVISION = '44444444-4444-4444-8444-444444444444';
const SNAPSHOT = '55555555-5555-4555-8555-555555555555';
const SOURCE = 'https://source.example.com', OTHER = 'https://other.example.com', MATCH = 'https://match.example.com';
const START = '2026-10-12T01:00:00Z', TIME = '2026-10-12T01:00:01.123456789Z';
const SEQUENCE = 9007199254740993n;
const token = sequence => `v1.${SESSION}.${GENERATION}.${sequence}.${REVISION}.${ROW}`;
const TOKEN = token(SEQUENCE), SAMPLE = token(SEQUENCE + 1n);
const clone = value => JSON.parse(JSON.stringify(value));
const response = (payload, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => payload });
function pending() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function observation(ip = '192.0.2.10', route = 'direct', port = 443, at = TIME) { return { status: 'observed', observation: { source: 'http_response_remote_addr', route, observed_at: at, address: { ip, port }, reason: null } }; }
function evidence(id = TOKEN, origin = SOURCE, peer = observation()) { return { schema_version: 1, session_id: SESSION, evidence_id: id, available: true, source: 'captured_http_metadata', socket_peer: peer,
  row: { evidence_id: id, sequence: id.split('.')[3], record_id: ROW, origin, started_at: START, method: 'GET', path: '/source', status: 200, metadata_complete: true, omitted: [] } }; }
function normalOrigin(id, evidenceId = TOKEN) { return { origin: id, in_scope: true, request_count: 1, endpoints: [{ method: 'GET', path: '/source', request_count: 1, statuses: [200], content_types: ['text/html'], evidence: [evidenceId] }], technology_clues: [], header_links: [], redirects: [] }; }
function snapshot(extra = {}) { return { schema_version: 1, session_id: SESSION, snapshot: { id: SNAPSHOT, generation: GENERATION, captured_at: START, retained_rows: 3, considered_rows: 3, complete: true, stopped_by: [], ...extra }, origins: [normalOrigin(SOURCE), normalOrigin(OTHER, token(SEQUENCE + 2n))], warnings: [] }; }
function matches(size = 1) {
  const origins = Array.from({ length: size }, (_, i) => ({ origin: size === 1 ? MATCH : `https://match-${String(i).padStart(3, '0')}.example.com`, in_scope: true, matching_rows: 1,
    first_observed_at: TIME, last_observed_at: TIME, samples: [{ evidence_id: token(SEQUENCE + BigInt(i + 1)), sequence: String(SEQUENCE + BigInt(i + 1)), started_at: START, observed_at: TIME }], omitted_samples: 0 }));
  return { schema_version: 1, session_id: SESSION, evidence_id: TOKEN, available: true, status: size ? 'matched' : 'no_matches', complete: true, reasons: [], in_scope_only: false,
    coverage: 'retained_direct_socket_peer_equality', peer: { source: 'http_response_remote_addr', route: 'direct', address_family: 'ipv4', address: { ip: '192.0.2.10', port: 443 } },
    source: { evidence_id: TOKEN, sequence: String(SEQUENCE), origin: SOURCE, started_at: START, observed_at: TIME, in_scope: true, in_window: true },
    snapshot: { id: SNAPSHOT, generation: GENERATION, captured_at: START, window_order: 'latest_retained_sequence', retained_rows: size + 1, considered_rows: size + 1, oldest_considered_sequence: String(SEQUENCE), latest_considered_sequence: String(SEQUENCE + BigInt(size)) },
    counts: { non_http_rows: 0, not_recorded_rows: 0, unavailable_observation_rows: 0, non_direct_rows: 0, invalid_observation_rows: 0, different_peer_rows: 0, invalid_metadata_rows: 0, scope_excluded_rows: 0, matching_rows: size, returned_matching_rows: size, omitted_matching_rows: 0, sample_rows: size, omitted_sample_rows: 0 }, origins, limits: { ...map.PEER_MATCH_LIMITS } };
}
function byteLimitedMatches() {
  const value = matches(0), origins = []; let remaining = 262144 - 8192, sequence = SEQUENCE + 1n;
  while (remaining > 5000) {
    const origin = `https://dense-${String(origins.length).padStart(3, '0')}.example.com`, charge = origin.length * 12 + 512 + 3 * 1024;
    const samples = Array.from({ length: 3 }, () => { const current = sequence++; return { evidence_id: token(current), sequence: String(current), started_at: START, observed_at: TIME }; }).reverse();
    origins.push({ origin, in_scope: true, matching_rows: 3, first_observed_at: TIME, last_observed_at: TIME, samples, omitted_samples: 0 }); remaining -= charge;
  }
  const length = Math.floor((remaining - 512 - 512) / 12), origin = `https://${'z'.repeat(length - 20)}.example.com`;
  origins.push({ origin, in_scope: true, matching_rows: 1, first_observed_at: TIME, last_observed_at: TIME, samples: [], omitted_samples: 1 });
  value.origins = origins; value.status = 'matched'; value.complete = false; value.reasons = ['projection_byte_limit'];
  value.counts.matching_rows = value.counts.returned_matching_rows = origins.reduce((sum, group) => sum + group.matching_rows, 0);
  value.counts.sample_rows = value.counts.matching_rows - 1; value.counts.omitted_sample_rows = 1;
  value.snapshot.retained_rows = value.snapshot.considered_rows = value.counts.matching_rows + 1;
  value.snapshot.latest_considered_sequence = String(sequence);
  return value;
}
function unavailable(reason = 'peer_inspection_failed') { const value = matches(0); return { ...value, available: false, status: 'unavailable', complete: false, reasons: [reason], peer: null, source: null, snapshot: null }; }
function normalize(value = matches(), row = evidence().row, peer = map.normalizeSocketPeer(observation()), scope = false) { return map.normalizePeerMatches(value, SESSION, TOKEN, row, peer, scope, GENERATION); }
function element() {
  const handlers = new Map(), classes = new Set(), props = new Map();
  return { textContent: '', innerHTML: '', value: '', checked: false, disabled: false, scrollTop: 0, scrollLeft: 0, clientWidth: 700, clientHeight: 450,
    style: { setProperty(key, value) { props.set(key, value); }, getPropertyValue(key) { return props.get(key); } },
    classList: { toggle(key, value) { value ? classes.add(key) : classes.delete(key); }, contains: key => classes.has(key) },
    attributes: {}, setAttribute(key, value) { this.attributes[key] = value; }, contains: () => true, querySelectorAll: () => [],
    addEventListener(key, handler) { handlers.set(key, handler); }, dispatch(key, value = {}) { return handlers.get(key)?.({ target: this, ...value }); } };
}
function fixture() {
  let session = SESSION, stream = true;
  const els = Object.fromEntries(['panel', 'status', 'refresh', 'search', 'scope', 'canvas', 'graphBounds', 'detail', 'content', 'catalog', 'mapControls', 'allOrigins', 'directRelations', 'focusSelection', 'boundsDetails', 'graphDiagnostics', 'overlayStatus', 'viewport', 'zoomControls', 'zoomFit', 'zoomOut', 'zoomReset', 'zoomIn'].map(key => [key, element()]));
  const requests = [], doc = { activeElement: null, body: {}, querySelector: () => null };
  const controller = map.createController({ elements: els, document: doc, getSessionId: () => session, getEventStreamReady: () => stream,
    request(url, options) { const wait = pending(); requests.push({ url, options, ...wait }); return wait.promise; } });
  controller.setVisible(true);
  return { controller, els, requests, state: controller.getState(), setSession(value) { session = value; }, setStream(value) { stream = value; },
    async load(value = snapshot(), force = false) { const task = controller.refresh({ force }); requests.at(-1).resolve(response(value)); return task; },
    async verify(id = TOKEN, origin = SOURCE, value = evidence(id, origin)) { controller.selectOrigin(origin); const task = controller.loadEvidence(id); requests.at(-1).resolve(response(value)); return task; },
    async inspect(value = matches()) { const task = controller.loadPeerMatches(); requests.at(-1).resolve(response(value)); return task; },
    async show(value = matches()) { await this.load(); await this.verify(); assert.equal(await this.inspect(value), true); assert.equal(controller.showPeerMatchesOnMap(), true); } };
}

test('frozen contract accepts exact decimal sequences above safe JS integer and duplicate UUID records', () => {
  const value = normalize(matches(3)); assert.equal(value.origins.length, 3); assert.equal(value.origins[0].samples[0].evidence_id, SAMPLE);
  assert.equal(new Set(value.origins.map(group => group.samples[0].evidence_id.split('.')[5])).size, 1);
  assert.equal(value.source.sequence, '9007199254740993'); assert.equal(value.origins[2].samples[0].sequence, '9007199254740996');
});
const malformed = [
  v => { v.extra = 'not allowed'; }, v => { v.schema_version = 2; }, v => { v.session_id = ROW; }, v => { v.evidence_id = SAMPLE; },
  v => { v.coverage = 'origin_ip'; }, v => { v.in_scope_only = true; }, v => { v.available = 'yes'; }, v => { v.complete = false; },
  v => { v.peer.route = 'http_proxy'; }, v => { v.peer.source = 'dns'; }, v => { v.peer.address_family = 'ipv6'; }, v => { v.peer.address.port = 8443; },
  v => { v.peer.address.ip = '192.0.2.11'; }, v => { v.peer.address.hostname = 'private.example.com'; }, v => { v.peer.address.port = '443'; },
  v => { v.source.evidence_id = SAMPLE; }, v => { v.source.sequence = '09007199254740993'; }, v => { v.source.sequence = Number(SEQUENCE); },
  v => { v.source.origin = OTHER; }, v => { v.source.started_at = TIME; }, v => { v.source.observed_at = START; }, v => { v.source.in_window = false; },
  v => { v.snapshot.generation = ROW; }, v => { v.snapshot.id = 'not-a-snapshot'; }, v => { v.snapshot.considered_rows = 10001; },
  v => { v.snapshot.latest_considered_sequence = v.snapshot.oldest_considered_sequence; }, v => { v.snapshot.oldest_considered_sequence = String(SEQUENCE + 1n); },
  v => { v.snapshot.captured_at = '2026-02-30T01:00:00Z'; }, v => { v.snapshot.window_order = 'first_seen'; },
  v => { v.counts.non_direct_rows = 1; }, v => { v.counts.omitted_matching_rows = 1; }, v => { v.counts.sample_rows = 0; },
  v => { v.origins[0].origin += '/path'; }, v => { v.origins[0].origin = 'https://user:secret@example.com'; }, v => { v.origins[0].in_scope = 'true'; },
  v => { v.origins[0].samples[0].sequence = Number(SEQUENCE + 1n); }, v => { v.origins[0].samples[0].evidence_id = TOKEN; },
  v => { v.origins[0].samples[0].evidence_id = SAMPLE.replace(REVISION, 'not-a-revision'); }, v => { v.origins[0].samples[0].sequence = '18446744073709551616'; },
  v => { v.origins[0].samples[0].observed_at = START; }, v => { v.origins[0].first_observed_at = START; }, v => { v.origins[0].last_observed_at = '2027-01-01T00:00:00Z'; },
  v => { v.origins[0].samples[0].path = '/private'; }, v => { v.origins[0].omitted_samples = 1; }, v => { v.limits.origin_groups = 101; },
  v => { v.reasons = ['raw error secret']; }, v => { v.counts.raw = 1; }, v => { v.origins.push(clone(v.origins[0])); },
];
for (const [index, mutate] of malformed.entries()) test(`reject malformed exact peer-match contract ${index}`, () => { const value = matches(); mutate(value); assert.throws(() => normalize(value)); });
test('reject unsorted/duplicate reasons, origins, sequences and full-token revision collisions', () => {
  const reordered = matches(2); reordered.origins.reverse(); assert.throws(() => normalize(reordered));
  const duplicate = matches(2); duplicate.origins[1].samples = clone(duplicate.origins[0].samples); assert.throws(() => normalize(duplicate));
  const revisions = matches(2); revisions.origins[1].samples[0] = { ...revisions.origins[0].samples[0], evidence_id: SAMPLE.replace(REVISION, ROW) }; assert.throws(() => normalize(revisions));
  const reasons = matches(); reasons.complete = false; reasons.reasons = ['sample_limit', 'sample_limit']; assert.throws(() => normalize(reasons));
});
for (const [ip, route, port, expected] of [
  ['192.0.2.10', 'direct', 443, true], ['10.2.3.4', 'direct', 443, true], ['127.0.0.1', 'direct', 443, true],
  ['2001:db8::1', 'direct', 443, true], ['::1', 'direct', 443, true], ['::ffff:192.0.2.10', 'direct', 443, true],
  ['192.0.2.10', 'http_proxy', 443, false], ['192.0.2.10', 'socks_proxy', 443, false], ['192.0.2.10', 'unknown', 443, false],
  ['192.0.2.10', 'direct', 0, false], ['0.0.0.0', 'direct', 443, false], ['0.0.0.7', 'direct', 443, false], ['255.255.255.255', 'direct', 443, false],
  ['224.1.2.3', 'direct', 443, false], ['240.1.2.3', 'direct', 443, false], ['169.254.1.2', 'direct', 443, false], ['::', 'direct', 443, false],
  ['fe80::1', 'direct', 443, false], ['ff02::1', 'direct', 443, false], ['::ffff:169.254.1.2', 'direct', 443, false], ['fe80::1%eth0', 'direct', 443, false],
]) test(`address eligibility ${ip}/${route}/${port}`, async () => {
  const peer = map.normalizeSocketPeer(observation(ip, route, port)); assert.equal(map.usableSocketPeer(peer), expected);
  if (!expected) { const f = fixture(); await f.load(); await f.verify(TOKEN, SOURCE, evidence(TOKEN, SOURCE, observation(ip, route, port))); const before = f.requests.length;
    assert.equal(await f.controller.loadPeerMatches(), false); assert.equal(f.requests.length, before); assert.doesNotMatch(f.els.detail.innerHTML, /data-service-peer-matches="inspect"/, 'an unusable address offers no matching'); }
});
test('IPv4-mapped IPv6 stays distinct while Rust dotted and exact peer canonical spelling agree', () => {
  const value = matches(); value.peer.address_family = 'ipv6'; value.peer.address.ip = '::ffff:192.0.2.10';
  assert.equal(normalize(value, evidence().row, map.normalizeSocketPeer(observation('::ffff:c000:20a'))).peer.address_family, 'ipv6');
  assert.throws(() => normalize(value));
});
test('empty, unavailable, scope-only, older seed and zero-sample partial groups are explicit', () => {
  assert.equal(normalize(matches(0)).status, 'no_matches'); assert.equal(normalize(unavailable()).status, 'unavailable');
  assert.throws(() => normalize(unavailable('source_out_of_scope')));
  assert.equal(normalize({ ...unavailable('source_out_of_scope'), in_scope_only: true }, evidence().row, map.normalizeSocketPeer(observation()), true).status, 'unavailable');
  const scope = matches(); scope.in_scope_only = true; assert.equal(normalize(scope, evidence().row, map.normalizeSocketPeer(observation()), true).in_scope_only, true);
  const old = matches(); old.source.in_window = false; old.snapshot.retained_rows = 10001; old.snapshot.considered_rows = 10000; old.snapshot.oldest_considered_sequence = String(SEQUENCE + 1n); old.snapshot.latest_considered_sequence = String(SEQUENCE + 10000n); old.counts.different_peer_rows = 9999; old.complete = false; old.reasons = ['max_records', 'source_outside_window'];
  assert.equal(normalize(old).source.in_window, false);
  const noSample = byteLimitedMatches(); assert.equal(normalize(noSample).origins.at(-1).samples.length, 0);
});
test('one explicit GET with redirect:error; default, polls, selection, search, Fit and Show do not inspect peers', async () => {
  const f = fixture(); await f.load(); await f.verify(); const before = f.requests.length;
  f.els.search.value = 'example'; f.els.search.dispatch('input'); f.controller.displayChanged(); f.controller.setZoom(1.3); f.controller.fitGraph();
  assert.equal(f.requests.length, before); assert.equal(f.controller.showPeerMatchesOnMap(), false);
  const task = f.controller.loadPeerMatches(), request = f.requests.at(-1), url = new URL(request.url, 'http://example.com');
  assert.equal(url.pathname, '/api/target/service-map/socket-peer-matches'); assert.equal(url.searchParams.get('evidence_id'), TOKEN); assert.equal(url.searchParams.get('max_records'), '10000'); assert.equal(url.searchParams.get('in_scope_only'), 'false'); assert.equal(request.options.redirect, 'error');
  assert.equal(url.searchParams.has('ip'), false); request.resolve(response(matches())); assert.equal(await task, true);
  assert.equal(f.els.canvas.innerHTML.includes('192.0.2.10'), false);
  const count = f.requests.length; assert.equal(f.controller.showPeerMatchesOnMap(), true); assert.equal(f.requests.length, count);
  await f.load(snapshot({ id: ROW, captured_at: TIME })); assert.equal(f.state.bodyReferenceOverlay.kind, 'peer');
  assert.equal(f.requests.filter(item => item.url.includes('/socket-peer-matches?')).length, 1);
});
test('peer group renders a distinct endpoint and undirected spokes within shared graph caps', async () => {
  const f = fixture(); await f.show(matches(35)); const canvas = f.els.canvas.innerHTML;
  assert.equal((canvas.match(/class="service-map-card /g) || []).length, 24);
  assert.equal((canvas.match(/service-map-peer-address/g) || []).length, 1);
  assert.equal((canvas.match(/data-relationship="recorded_peer_observation"/g) || []).length, 23);
  assert.doesNotMatch(canvas.match(/<path class="service-map-edge peer-observation[^]*?<\/path>/g).join(''), /marker-end/);
  assert.match(canvas, /source\.example\.com/); assert.match(f.els.overlayStatus.innerHTML, /2026-10-12/);
  assert.match(f.els.graphBounds.textContent, /14 nodes omitted by 24-card cap/);
  f.els.search.value = 'match-034'; f.els.search.dispatch('input');
  assert.equal((f.els.canvas.innerHTML.match(/class="service-map-card /g) || []).length, 2);
  assert.match(f.els.graphBounds.textContent, /36 hidden by query/); assert.equal(f.state.relationLayers.length, 1);
});
test('outside-default-map origin is captured in this inspection, with only matched totals and separately allowlisted evidence', async () => {
  const f = fixture(); await f.show(); f.controller.selectOrigin(MATCH);
  assert.match(f.els.detail.innerHTML, /Captured in this peer inspection/); assert.match(f.els.detail.innerHTML, /1 other matching rows/); assert.doesNotMatch(f.els.detail.innerHTML, /Referenced only|no captured rows|0 sampled HTTP/);
  assert.match(f.els.detail.innerHTML, new RegExp(SAMPLE.replaceAll('.', '\\.')));
  let count = f.requests.length; assert.equal(await f.controller.loadEvidence(SAMPLE), false); assert.equal(f.requests.length, count);
  assert.equal(await f.controller.loadPeerEvidence(SAMPLE.replace(REVISION, ROW), MATCH), false); assert.equal(await f.controller.loadPeerEvidence(SAMPLE, OTHER), false); assert.equal(f.requests.length, count);
  const task = f.controller.loadPeerEvidence(SAMPLE, MATCH); const request = f.requests.at(-1); assert.equal(request.options.redirect, 'error'); assert.match(request.url, /include_socket_peer=true/);
  request.resolve(response(evidence(SAMPLE, MATCH))); assert.equal(await task, true); assert.equal(f.state.evidence.sequence, String(SEQUENCE + 1n));
  assert.match(f.els.detail.innerHTML, /Capture info/); assert.equal(f.requests.length, count + 1);
});
for (const [label, change] of [
  ['UUID', v => { v.row.record_id = REVISION; }], ['full token', v => { v.row.evidence_id = TOKEN; }], ['sequence', v => { v.row.sequence = String(SEQUENCE); }],
  ['origin', v => { v.row.origin = SOURCE; }], ['observed time', v => { v.socket_peer.observation.observed_at = START; }], ['IP', v => { v.socket_peer.observation.address.ip = '192.0.2.11'; }],
  ['route', v => { v.socket_peer.observation.route = 'http_proxy'; }], ['address family', v => { v.socket_peer.observation.address.ip = '::ffff:192.0.2.10'; }], ['captured time', v => { v.row.started_at = TIME; }],
]) test(`matched sample revalidates ${label} and preserves unrelated shown counts on failure`, async () => {
  const f = fixture(); await f.show(); const overlay = f.state.bodyReferenceOverlay; const task = f.controller.loadPeerEvidence(SAMPLE, MATCH), value = evidence(SAMPLE, MATCH); change(value);
  f.requests.at(-1).resolve(response(value)); assert.equal(await task, false); assert.equal(f.state.evidence, null); assert.equal(f.state.bodyReferenceOverlay, overlay); assert.match(f.els.detail.innerHTML, /matched sample is unavailable or changed/);
  const count = f.requests.length; assert.equal(await f.controller.loadPeerEvidence(SAMPLE, MATCH), false); assert.equal(f.requests.length, count);
});
test('metadata-unavailable matched sample stays unavailable, while missing exact seed clears its shown group', async () => {
  const f = fixture(); await f.show(); const task = f.controller.loadPeerEvidence(SAMPLE, MATCH);
  f.requests.at(-1).resolve(response({ ...evidence(SAMPLE, MATCH), available: false, row: null, reason: 'metadata_unavailable' })); assert.equal(await task, false); assert.equal(f.state.bodyReferenceOverlay.kind, 'peer');
  const seed = f.controller.loadPeerEvidence(TOKEN, SOURCE); f.requests.at(-1).resolve(response({ ...evidence(), available: false, row: null })); assert.equal(await seed, false); assert.equal(f.state.bodyReferenceOverlay, null);
});
for (const mode of ['404', 'redirect', 'malformed']) test(`${mode} inspection has no retry and does not discard a valid shown overlay`, async () => {
  const f = fixture(); await f.show(); const overlay = f.state.bodyReferenceOverlay; const count = f.requests.length;
  const task = f.controller.loadPeerMatches(); if (mode === '404') f.requests.at(-1).resolve(response({}, 404)); else if (mode === 'redirect') f.requests.at(-1).reject(new TypeError('redirect refused')); else f.requests.at(-1).resolve(response({ ...matches(), secret: 'raw' }));
  assert.equal(await task, false); assert.equal(f.requests.length, count + 1); assert.equal(f.state.bodyReferenceOverlay, overlay); assert.equal(f.state.peerMatches, null);
  if (mode === '404') assert.match(f.els.detail.innerHTML, /does not support matching recorded/);
});
for (const action of ['origin ABA', 'seed reread', 'All origins', 'Clear', 'force refresh', 'hidden', 'APIs', 'disconnect', 'history', 'scope', 'generation', 'session ABA', 'snapshot changed']) test(`pending peer inspection cancels after ${action}`, async () => {
  const f = fixture(); await f.load(); await f.verify(); const task = f.controller.loadPeerMatches(), old = f.requests.at(-1);
  if (action === 'origin ABA') { f.controller.selectOrigin(OTHER); f.controller.selectOrigin(SOURCE); }
  else if (action === 'seed reread') await f.verify();
  else if (action === 'All origins') f.els.allOrigins.dispatch('click');
  else if (action === 'Clear') f.controller.clearBodyReferenceOverlay();
  else if (action === 'force refresh') await f.load(snapshot(), true);
  else if (action === 'hidden') { f.controller.setVisible(false); f.controller.setVisible(true); }
  else if (action === 'APIs') { f.controller.setVisible(true, 'apis'); f.controller.setVisible(true, 'service-map'); }
  else if (action === 'disconnect') { f.controller.disconnect(); }
  else if (action === 'history') f.controller.markDirty();
  else if (action === 'scope') { f.els.scope.dispatch('click'); f.requests.at(-1).resolve(response(snapshot())); }
  else if (action === 'generation') await f.load(snapshot({ generation: ROW }));
  else if (action === 'session ABA') { f.setSession(ROW); f.controller.reset(); f.setSession(SESSION); f.controller.reset(); }
  else await f.load(snapshot({ retained_rows: 4 }));
  old.resolve(response(matches())); assert.equal(await task, false); assert.equal(f.state.peerMatches, null); assert.equal(f.controller.showPeerMatchesOnMap(), false); assert.equal(old.options.signal.aborted, true);
});
for (const action of ['Clear', 'force refresh', 'hidden', 'disconnect', 'history', 'scope invalidation', 'session ABA']) test(`shown peer allowlist and late sample cannot survive ${action}`, async () => {
  const f = fixture(); await f.show(); const task = f.controller.loadPeerEvidence(SAMPLE, MATCH), old = f.requests.at(-1);
  if (action === 'All origins') f.els.allOrigins.dispatch('click');
  else if (action === 'Clear') f.controller.clearBodyReferenceOverlay();
  else if (action === 'repin') { f.controller.selectOrigin(OTHER); f.els.focusSelection.dispatch('click'); }
  else if (action === 'force refresh') await f.load(snapshot(), true);
  else if (action === 'hidden') { f.controller.setVisible(false); f.controller.setVisible(true); }
  else if (action === 'disconnect') f.controller.disconnect();
  else if (action === 'history') f.controller.markDirty();
  else if (action === 'scope invalidation') { const refresh = f.controller.invalidate(); f.requests.at(-1).resolve(response(snapshot())); await refresh; }
  else { f.setSession(ROW); f.controller.reset(); f.setSession(SESSION); f.controller.reset(); }
  old.resolve(response(evidence(SAMPLE, MATCH))); assert.equal(await task, false); assert.equal(f.state.bodyReferenceOverlay, null); assert.equal(f.state.peerEvidenceBinding, null); assert.equal(f.state.evidence, null);
  const count = f.requests.length; assert.equal(await f.controller.loadPeerEvidence(SAMPLE, MATCH), false); assert.equal(f.requests.length, count);
});
test('source changes and stale A-B-A inspection results never reuse a newer source result', async () => {
  const f = fixture(); await f.load(); await f.verify(); const first = f.controller.loadPeerMatches(), old = f.requests.at(-1);
  await f.verify(token(SEQUENCE + 2n), OTHER); const next = f.controller.loadPeerMatches(), newer = f.requests.at(-1);
  await f.verify(); old.resolve(response(matches())); newer.resolve(response(matches())); assert.equal(await first, false); assert.equal(await next, false); assert.equal(f.state.peerMatches, null);
});
test('new explicit matched-source inspection can replace an older group without default sample expansion', async () => {
  const f = fixture(); await f.show(); const exact = f.controller.loadPeerEvidence(SAMPLE, MATCH); f.requests.at(-1).resolve(response(evidence(SAMPLE, MATCH))); assert.equal(await exact, true);
  const next = matches(0); next.evidence_id = SAMPLE; next.source = { ...next.source, evidence_id: SAMPLE, sequence: String(SEQUENCE + 1n), origin: MATCH };
  next.snapshot.oldest_considered_sequence = next.snapshot.latest_considered_sequence = String(SEQUENCE + 1n);
  assert.equal(await f.inspect(next), true); const count = f.requests.length; assert.equal(f.controller.showPeerMatchesOnMap(), true); assert.equal(f.requests.length, count); assert.equal(f.state.bodyReferenceOverlay.scan.source.origin, MATCH);
  f.controller.clearBodyReferenceOverlay(); assert.equal(f.state.anchorOrigin, null); assert.equal(f.state.selectedOrigin, null);
});
test('20px display grows compact cards and preserves graph-only zoom, bounded geometry, and 24px Scope strip', async () => {
  const geometry = map.graphGeometry(20); assert.equal(geometry.cardWidth, 220); assert.ok(geometry.cardHeight > 104);
  const origins = Array.from({ length: 100 }, (_, i) => ({ origin: `https://n${i}.example.com` }));
  const layout = map.peerGraphLayout(origins, origins[0].origin, geometry); assert.equal(layout.nodes.length, 24); assert.equal(layout.edges.length, 23);
  for (const item of layout.nodes) { assert.ok(item.x >= 0 && item.y >= 0); assert.ok(item.x + geometry.cardWidth <= layout.width); assert.ok(item.y + geometry.cardHeight <= layout.height); }
  const f = fixture(); await f.show(); const detail = f.els.detail.innerHTML, count = f.requests.length; assert.equal(f.controller.setZoom(1.7), true); assert.equal(f.els.detail.innerHTML, detail); assert.equal(f.requests.length, count); assert.equal(f.els.canvas.style.getPropertyValue('--service-map-scale'), '1.7'); assert.equal(f.controller.fitGraph(), true);
  const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8'); assert.match(css, /\.target-workspace-header\s*\{[^}]*min-height: 24px;/); assert.match(css, /\.service-map-card\.service-map-peer-address/);
});
test('ordinary evidence navigation to shown seed still revalidates and clears an unavailable source', async () => {
  const f = fixture(); await f.show(); const task = f.controller.loadEvidence(TOKEN);
  f.requests.at(-1).resolve(response({ ...evidence(), available: false, row: null })); assert.equal(await task, false); assert.equal(f.state.bodyReferenceOverlay, null);
});
test('same-seed matching response that proves source changed clears its overlay, while unrelated source does not', async () => {
  const f = fixture(); await f.show(); const task = f.controller.loadPeerMatches();
  f.requests.at(-1).resolve(response(unavailable('record_changed'))); assert.equal(await task, true); assert.equal(f.state.bodyReferenceOverlay, null);
});
for (const ip of ['2001:0db8::1', '2001:DB8::1', '::ffff:c000:20a']) test(`noncanonical peer IP spelling is rejected: ${ip}`, () => {
  const value = matches(); value.peer.address_family = 'ipv6'; value.peer.address.ip = ip;
  assert.throws(() => normalize(value, evidence().row, map.normalizeSocketPeer(observation(ip))));
});
test('body and peer visualizations coexist and repeat Show updates only its own entry', async () => {
  const f = fixture(); await f.show(); const priorPeer = f.state.bodyReferenceOverlay;
  const task = f.controller.loadBodyReferences();
  f.requests.at(-1).resolve(response({ schema_version: 1, session_id: SESSION, evidence_id: TOKEN, available: true, status: 'scanned', complete: true, reasons: [], source_origin: SOURCE, source_sequence: String(SEQUENCE), source_started_at: START,
    retained_preview_bytes: 200, scanned_bytes: 200, capture_preview_truncated: false, scan_prefix_truncated: false, candidates_scanned: 1, omitted_reference_occurrences: 0, references: [{ target_origin: OTHER, occurrences: 1, preview_byte_offsets: [20], omitted_offsets: 0 }], limits: { ...map.BODY_REFERENCE_LIMITS }, coverage: 'literal_absolute_http_urls', offset_basis: 'retained_utf8_preview' }));
  assert.equal(await task, true); assert.equal(f.state.bodyReferenceOverlay, priorPeer);
  let count = f.requests.length; assert.equal(f.controller.showBodyReferencesOnMap(), true); assert.equal(f.state.bodyReferenceOverlay.kind, 'body'); assert.equal(f.requests.length, count);
  assert.match(f.els.canvas.innerHTML, /service-map-peer-address/); assert.equal(f.state.relationLayers.length, 2); assert.equal(f.state.relationLayers[0], priorPeer);
  await f.verify(); await f.inspect(); count = f.requests.length; assert.equal(f.controller.showPeerMatchesOnMap(), true); assert.equal(f.state.relationLayers[0].kind, 'peer'); assert.equal(f.requests.length, count);
  assert.equal(f.state.relationLayers.length, 2); assert.match(f.els.canvas.innerHTML, /body_url_reference/); assert.match(f.els.canvas.innerHTML, /recorded_peer_observation/);
});
test('unrelated source inspection failure cannot clear the pinned peer group or reuse old matching results', async () => {
  const f = fixture(); await f.show(); const overlay = f.state.bodyReferenceOverlay; await f.verify(token(SEQUENCE + 2n), OTHER);
  assert.equal(f.state.peerMatches, null); assert.equal(f.controller.showPeerMatchesOnMap(), false);
  const task = f.controller.loadPeerMatches(), payload = unavailable('record_changed'); payload.evidence_id = token(SEQUENCE + 2n);
  f.requests.at(-1).resolve(response(payload)); assert.equal(await task, true); assert.equal(f.state.bodyReferenceOverlay, overlay);
});
for (const destination of ['same origin', 'another loopback port']) test(`native fetch refuses matching API redirect to ${destination} without a destination request`, async () => {
  const http = require('node:http');
  let apiHits = 0, destinationHits = 0, destinationUrl;
  const target = http.createServer((_req, res) => { destinationHits++; res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(matches())); });
  const server = http.createServer((req, res) => {
    if (req.url.startsWith('/api/target/service-map/socket-peer-matches?')) { apiHits++; res.writeHead(302, { location: destinationUrl }); res.end(); }
    else { destinationHits++; res.writeHead(200); res.end('{}'); }
  });
  const listen = server => new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const close = server => new Promise(resolve => server.close(resolve));
  try {
    await listen(server); if (destination !== 'same origin') await listen(target);
    const base = `http://127.0.0.1:${server.address().port}`;
    destinationUrl = destination === 'same origin' ? `${base}/redirect-target` : `http://127.0.0.1:${target.address().port}/redirect-target`;
    const f = fixture(); await f.load(); await f.verify();
    const task = f.controller.loadPeerMatches(), request = f.requests.at(-1);
    try { request.resolve(await fetch(`${base}${request.url}`, request.options)); } catch (error) { request.reject(error); }
    assert.equal(await task, false); assert.equal(apiHits, 1); assert.equal(destinationHits, 0); assert.equal(f.state.peerMatches, null); assert.equal(f.requests.length, 3);
  } finally { await close(server); if (target.listening) await close(target); }
});
test('singleton sequence window must have identical extrema even when seed lies between them', () => {
  const value = matches(0); value.snapshot.oldest_considered_sequence = String(SEQUENCE - 1n); value.snapshot.latest_considered_sequence = String(SEQUENCE + 1n); assert.throws(() => normalize(value));
});
test('truthful byte admission and sample-limit reasons are enforced', () => {
  const insufficient = matches(); insufficient.origins[0].samples = []; insufficient.origins[0].omitted_samples = 1; insufficient.counts.sample_rows = 0; insufficient.counts.omitted_sample_rows = 1; insufficient.complete = false; insufficient.reasons = ['projection_byte_limit'];
  assert.throws(() => normalize(insufficient));
  const dense = byteLimitedMatches(); assert.ok(normalize(dense).counts.sample_rows > 100);
  const excessive = clone(dense); excessive.origins.at(-1).origin = `https://${'z'.repeat(500)}.example.com`; assert.throws(() => normalize(excessive));
  const omissions = matches(0); omissions.origins = [{ origin: MATCH, in_scope: true, matching_rows: 4, first_observed_at: TIME, last_observed_at: TIME,
    samples: [3n, 2n, 1n].map(index => ({ evidence_id: token(SEQUENCE + index), sequence: String(SEQUENCE + index), started_at: START, observed_at: TIME })), omitted_samples: 1 }];
  omissions.status = 'matched'; omissions.complete = false; omissions.reasons = ['sample_limit']; omissions.snapshot.retained_rows = omissions.snapshot.considered_rows = 5; omissions.snapshot.latest_considered_sequence = String(SEQUENCE + 4n);
  Object.assign(omissions.counts, { matching_rows: 4, returned_matching_rows: 4, sample_rows: 3, omitted_sample_rows: 1 }); assert.equal(normalize(omissions).counts.omitted_sample_rows, 1);
  omissions.reasons = []; omissions.complete = true; assert.throws(() => normalize(omissions));
});
test('sample_limit in one group cannot conceal a byte-rejected sample in another group', () => {
  const value = byteLimitedMatches();
  value.origins[0].matching_rows += 1; value.origins[0].omitted_samples += 1;
  value.counts.matching_rows += 1; value.counts.returned_matching_rows += 1; value.counts.omitted_sample_rows += 1;
  value.snapshot.retained_rows += 1; value.snapshot.considered_rows += 1;
  value.snapshot.latest_considered_sequence = String(BigInt(value.snapshot.latest_considered_sequence) + 1n);
  value.reasons = ['projection_byte_limit', 'sample_limit'];
  assert.equal(normalize(value).counts.omitted_sample_rows, 2);
  value.reasons = ['sample_limit']; assert.throws(() => normalize(value));
});
test('fully enumerated window extrema must belong to the exact sampled rows and in-window source', () => {
  const value = matches(2); value.snapshot.latest_considered_sequence = String(BigInt(value.snapshot.latest_considered_sequence) + 1n);
  assert.throws(() => normalize(value));
  const low = matches(2); low.snapshot.oldest_considered_sequence = String(SEQUENCE - 1n); assert.throws(() => normalize(low));
});
test('one unknown row cannot supply two distinct unknown window extrema', () => {
  const value = matches(); value.snapshot.retained_rows = value.snapshot.considered_rows = 3; value.counts.different_peer_rows = 1;
  value.snapshot.oldest_considered_sequence = String(SEQUENCE - 1n); value.snapshot.latest_considered_sequence = String(SEQUENCE + 2n);
  assert.throws(() => normalize(value));
  value.snapshot.latest_considered_sequence = String(SEQUENCE + 1n); assert.equal(normalize(value).snapshot.considered_rows, 3);
});
test('one omitted observation cannot supply two absent distinct group timestamp extrema', () => {
  const value = byteLimitedMatches(), group = value.origins[0];
  group.matching_rows++; group.omitted_samples++; value.counts.matching_rows++; value.counts.returned_matching_rows++; value.counts.omitted_sample_rows++;
  value.snapshot.retained_rows++; value.snapshot.considered_rows++; value.snapshot.latest_considered_sequence = String(BigInt(value.snapshot.latest_considered_sequence) + 1n);
  value.reasons = ['projection_byte_limit', 'sample_limit'];
  group.first_observed_at = START; group.last_observed_at = '2026-10-12T01:00:02Z'; assert.throws(() => normalize(value));
  group.first_observed_at = TIME; assert.equal(normalize(value).origins[0].omitted_samples, 1);
});
test('omitted origins cannot conceal a byte-rejected sample when a full sample charge remains', () => {
  const value = byteLimitedMatches(); value.origins[0].samples.pop(); value.origins[0].omitted_samples++;
  value.counts.sample_rows--; value.counts.omitted_sample_rows++;
  value.counts.matching_rows++; value.counts.omitted_matching_rows++;
  value.snapshot.retained_rows++; value.snapshot.considered_rows++; value.snapshot.latest_considered_sequence = String(BigInt(value.snapshot.latest_considered_sequence) + 1n);
  const remaining = 262144 - 8192 - value.origins.reduce((sum, group) => sum + group.origin.length * 12 + 512, 0) - value.counts.sample_rows * 1024;
  assert.ok(remaining >= 1024 && remaining < 7040); assert.throws(() => normalize(value));
});
for (const reason of [['peer_inspection_failed'], ['source_out_of_scope'], [['peer_inspection_failed']], null, {}, 1, true]) test(`reason values never coerce into fixed codes: ${JSON.stringify(reason)}`, () => {
  const value = unavailable(); value.reasons = [reason]; assert.throws(() => normalize(value));
});
for (const reason of ['invalid_evidence_id', 'session_mismatch', 'record_changed', 'record_missing', 'stale_generation', 'session_source_changed']) test(`authoritative ${reason} matching response clears normal verified row, peer and supplements`, async () => {
  const f = fixture(); await f.show(); assert.equal(f.state.peerEvidenceBinding, null); assert.ok(f.state.evidence); assert.ok(f.state.socketPeer);
  const task = f.controller.loadPeerMatches(); f.requests.at(-1).resolve(response(unavailable(reason))); assert.equal(await task, true);
  for (const key of ['evidence', 'socketPeer', 'bodyReferenceOverlay', 'bodyReferences', 'linkDeclarations', 'htmlGenerators', 'peerMatches', 'peerMatchesSource']) assert.equal(f.state[key], null, key);
  assert.doesNotMatch(f.els.detail.innerHTML, /Capture info|Upstream socket peer/); assert.match(f.els.detail.innerHTML, /Source unavailable/);
});
for (const reason of ['invalid_evidence_id', 'session_mismatch', 'record_changed', 'record_missing', 'stale_generation', 'session_source_changed']) test(`authoritative ${reason} before Show invalidates the source without needing an overlay`, async () => {
  const f = fixture(); await f.load(); await f.verify(); assert.equal(f.state.bodyReferenceOverlay, null);
  const task = f.controller.loadPeerMatches(); f.requests.at(-1).resolve(response(unavailable(reason))); assert.equal(await task, true);
  assert.equal(f.state.evidence, null); assert.equal(f.state.socketPeer, null); assert.equal(f.state.peerMatches, null); assert.equal(f.state.bodyReferenceOverlay, null);
  assert.doesNotMatch(f.els.detail.innerHTML, /Capture info|Upstream socket peer/); assert.match(f.els.detail.innerHTML, /Source unavailable/);
});
test('only three-sample omissions cannot claim projection_byte_limit even with very little budget remaining', () => {
  const value = byteLimitedMatches(); value.origins.pop();
  value.origins[0].matching_rows++; value.origins[0].omitted_samples = 1;
  value.reasons = ['sample_limit'];
  const remaining = 262144 - 8192 - value.origins.reduce((sum, group) => sum + group.origin.length * 12 + 512, 0) - value.counts.sample_rows * 1024;
  value.origins[0].origin = value.origins[0].origin.replace('.example.com', `${'z'.repeat(Math.floor((remaining - 504) / 12))}.example.com`);
  const finalRemaining = 262144 - 8192 - value.origins.reduce((sum, group) => sum + group.origin.length * 12 + 512, 0) - value.counts.sample_rows * 1024;
  assert.ok(finalRemaining >= 0 && finalRemaining < 1024); assert.ok(value.origins.every(group => group.samples.length === 3));
  assert.equal(normalize(value).counts.omitted_sample_rows, 1);
  value.reasons = ['projection_byte_limit', 'sample_limit']; assert.throws(() => normalize(value));
});
test('peer-only exact sample offers no supplementary reads it cannot make', async () => {
  const f = fixture(); await f.show(); const task = f.controller.loadPeerEvidence(SAMPLE, MATCH); f.requests.at(-1).resolve(response(evidence(SAMPLE, MATCH))); assert.equal(await task, true);
  const count = f.requests.length;
  assert.equal(await f.controller.loadBodyReferences(), false); assert.equal(await f.controller.loadHtmlGenerators(), false);
  f.controller.setRelationshipKind('link'); assert.equal(await f.controller.loadLinkDeclarations(), false); assert.equal(f.requests.length, count);
  assert.doesNotMatch(f.els.detail.innerHTML, /data-service-(?:body-references|link-declarations|html-generators)="inspect"/);
  assert.match(f.els.detail.innerHTML, /Capture info/); assert.match(f.els.detail.innerHTML, /Recorded peer/); assert.equal(f.state.socketPeer.status, 'observed'); assert.ok(f.els.detail.innerHTML.includes(f.state.socketPeer.ip)); assert.match(f.els.detail.innerHTML, /Find matching peer/);
});
test('scope work limit is a fixed unavailable reason with a fully empty result', () => {
  const value = unavailable('scope_work_limit');
  assert.equal(normalize(value).status, 'unavailable');
  assert.equal(normalize({ ...value, in_scope_only: true }, evidence().row, map.normalizeSocketPeer(observation()), true).status, 'unavailable');
  for (const mutate of [v => { v.available = true; }, v => { v.complete = true; }, v => { v.peer = matches().peer; }, v => { v.source = matches().source; }, v => { v.snapshot = matches().snapshot; }, v => { v.origins = matches().origins; }, v => { v.counts.different_peer_rows = 1; }]) {
    const malformed = clone(value); mutate(malformed); assert.throws(() => normalize(malformed));
  }
  const partial = matches(); partial.complete = false; partial.reasons = ['scope_work_limit']; assert.throws(() => normalize(partial));
});
for (const [field, value] of [['scope_pattern_entries', 500], ['scope_pattern_bytes', 512], ['scope_work_units', 8388608]]) test(`scope limit ${field} is required and exact`, () => {
  assert.equal(map.PEER_MATCH_LIMITS[field], value);
  for (const source of [matches(), unavailable('scope_work_limit')]) {
    const missing = clone(source); delete missing.limits[field]; assert.throws(() => normalize(missing));
    const changed = clone(source); changed.limits[field] = value + 1; assert.throws(() => normalize(changed));
    const coerced = clone(source); coerced.limits[field] = String(value); assert.throws(() => normalize(coerced));
  }
});
for (const kind of ['before Show', 'same shown source', 'unrelated shown source']) test(`scope work limit preserves verified evidence and valid overlay ${kind} without retries`, async () => {
  const f = fixture();
  if (kind === 'before Show') { await f.load(); await f.verify(); } else await f.show();
  if (kind === 'unrelated shown source') await f.verify(token(SEQUENCE + 2n), OTHER);
  const source = f.state.evidence, peer = f.state.socketPeer, overlay = f.state.bodyReferenceOverlay, canvas = f.els.canvas.innerHTML, count = f.requests.length;
  const value = unavailable('scope_work_limit'); value.evidence_id = source.evidence_id;
  assert.equal(await f.inspect(value), true);
  assert.equal(f.requests.length, count + 1); assert.equal(f.state.evidence, source); assert.equal(f.state.socketPeer, peer); assert.equal(f.state.bodyReferenceOverlay, overlay); assert.equal(f.els.canvas.innerHTML, canvas);
  assert.equal(f.state.peerMatches.status, 'unavailable'); assert.equal(f.controller.showPeerMatchesOnMap(), false); assert.equal(f.requests.length, count + 1);
  assert.match(f.els.detail.innerHTML, /Scope matching reached the inspection work limit\. Narrow the scope rules or use a smaller latest-row window in the CLI\./);
  assert.match(f.els.detail.innerHTML, /Capture info/); assert.match(f.els.detail.innerHTML, /Recorded peer/); assert.equal(f.state.socketPeer.status, 'observed'); assert.ok(f.els.detail.innerHTML.includes(f.state.socketPeer.ip));
  assert.equal(f.state.evidenceError, ''); assert.ok(f.requests.every(request => request.options.redirect === 'error' && !request.options.method));
});

for (const marker of ['session_changed', 'scope_changed', 'history_changed']) test(`ordinary map ${marker} clears exact peer evidence and address overlay`, async () => {
  const f = fixture(); await f.show(); const previous = f.state.snapshot;
  const task = f.controller.refresh(); f.requests.at(-1).resolve({ ok: false, status: 409,
    headers: { get: () => marker }, json() { assert.fail('No failure body read'); } });
  assert.equal(await task, false);
  for (const key of ['evidence', 'evidenceId', 'socketPeer', 'peerMatches', 'peerMatchesSource', 'peerEvidenceBinding', 'bodyReferenceOverlay']) assert.equal(f.state[key], null, key);
  assert.equal(f.state.snapshot, previous); assert.equal(f.state.stale, true); assert.equal(f.state.refreshPaused, true);
  const count = f.requests.length; await f.controller.refresh(); assert.equal(f.requests.length, count);
});
