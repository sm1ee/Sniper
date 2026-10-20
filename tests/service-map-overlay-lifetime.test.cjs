// Independent overlay lifetime checks. Synthetic payloads only; no sockets or app bootstrap.
'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const context = vm.createContext({ URL, URLSearchParams, AbortController, console });
vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/service-map.js'), 'utf8'), context);
const map = context.SniperServiceMap;
const SOURCE = 'https://source.example.com';
const OTHER = 'https://other.example.com';
const TARGET = 'https://asset.example.com';
const SESSION = '11111111-1111-4111-8111-111111111111';
const GENERATION = '22222222-2222-4222-8222-222222222222';
const ROW = '33333333-3333-4333-8333-333333333333';
const SEQUENCE = '18446744073709551615';
const TOKEN = `v1.${SESSION}.${GENERATION}.${SEQUENCE}.44444444-4444-4444-8444-444444444444.${ROW}`;
const SECOND_TOKEN = `v1.${SESSION}.${GENERATION}.9007199254740993.55555555-5555-4555-8555-555555555555.${ROW}`;
const STARTED = '2026-10-12T01:00:00Z';
const result = payload => ({ ok: true, json: async () => payload });
function pending() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function element() {
  const handlers = new Map(), classes = new Set();
  return { textContent: '', innerHTML: '', value: '', checked: false, disabled: false,
    classList: { toggle(name, yes) { yes ? classes.add(name) : classes.delete(name); }, contains: name => classes.has(name) },
    setAttribute() {}, addEventListener(name, fn) { handlers.set(name, fn); }, contains: () => false, querySelectorAll: () => [],
    dispatch(name, event = {}) { return handlers.get(name)?.({ target: this, ...event }); } };
}
function origin(id, token = TOKEN) { return { origin: id, in_scope: true, request_count: 1,
  endpoints: [{ method: 'GET', path: '/source', request_count: 1, statuses: [200], content_types: ['text/html'], evidence: [token] }],
  technology_clues: [], redirects: [], header_links: [] }; }
function snapshot(origins = [origin(SOURCE), origin(OTHER, SECOND_TOKEN)], extra = {}) { return { schema_version: 1, session_id: SESSION,
  snapshot: { generation: GENERATION, complete: true, stopped_by: [], retained_rows: 2, considered_rows: 2, included_rows: 2, excluded_rows: 0, omitted_rows: 0, ...extra }, origins, warnings: [] }; }
function evidence(token = TOKEN, id = SOURCE, sequence = SEQUENCE) { return { schema_version: 1, session_id: SESSION, evidence_id: token,
  available: true, source: 'captured_http_metadata', row: { evidence_id: token, origin: id, method: 'GET', path: '/source', record_id: ROW,
    sequence, started_at: STARTED, metadata_complete: true, omitted: [] } }; }
function scan(token = TOKEN, id = SOURCE, sequence = SEQUENCE, targets = [TARGET]) { return { schema_version: 1, session_id: SESSION,
  evidence_id: token, available: true, status: 'scanned', complete: true, reasons: [], source_origin: id, source_sequence: sequence,
  source_started_at: STARTED, retained_preview_bytes: 500, scanned_bytes: 500, capture_preview_truncated: false, scan_prefix_truncated: false,
  candidates_scanned: targets.length, omitted_reference_occurrences: 0, references: targets.map((target_origin, i) => ({ target_origin,
    occurrences: 1, preview_byte_offsets: [20 + i], omitted_offsets: 0 })), limits: { ...map.BODY_REFERENCE_LIMITS },
  coverage: 'literal_absolute_http_urls', offset_basis: 'retained_utf8_preview' }; }
function fixture() {
  let session = SESSION, streamReady = true;
  const requests = [], els = Object.fromEntries(['panel', 'status', 'refresh', 'search', 'scope', 'canvas', 'graphBounds', 'detail', 'content',
    'catalog', 'mapControls', 'allOrigins', 'directRelations', 'focusSelection', 'boundsDetails', 'graphDiagnostics', 'overlayStatus'].map(name => [name, element()]));
  const controller = map.createController({ elements: els, getSessionId: () => session, getEventStreamReady: () => streamReady, document: { activeElement: null, body: {}, querySelector: () => null },
    request(url, options) { const wait = pending(); requests.push({ url, options, ...wait }); return wait.promise; } });
  controller.setVisible(true);
  return { controller, els, requests, state: controller.getState(), setSession(id) { session = id; }, setStreamReady(value) { streamReady = value; },
    async load(data = snapshot()) { const task = controller.refresh(); requests.at(-1).resolve(result(data)); return task; },
    async verify(token = TOKEN, id = SOURCE, sequence = SEQUENCE) { controller.selectOrigin(id); const task = controller.loadEvidence(token);
      requests.at(-1).resolve(result(evidence(token, id, sequence))); return task; },
    async inspect(data = scan()) { const task = controller.loadBodyReferences(); requests.at(-1).resolve(result(data)); return task; },
  };
}
async function displayed() { const f = fixture(); await f.load(); await f.verify(); await f.inspect(); assert.equal(f.controller.showBodyReferencesOnMap(), true); return f; }
function assertAbsent(f) { assert.equal(f.state.bodyReferenceOverlay, null); assert.doesNotMatch(f.els.canvas.innerHTML, /asset\.example\.com/); }

test('Show stores an immutable allowlisted copy with full opaque token and uint64 sequence', async () => {
  const f = fixture(); await f.load(); await f.verify(); const payload = scan(); payload.body = 'PRIVATE_BODY'; payload.headers = { Authorization: 'PRIVATE_HEADER' };
  await f.inspect(payload); const count = f.requests.length; assert.equal(f.controller.showBodyReferencesOnMap(), true);
  const overlay = f.state.bodyReferenceOverlay;
  assert.equal(f.requests.length, count);
  assert.equal(overlay.source.evidenceId, TOKEN); assert.equal(overlay.source.sequence, SEQUENCE);
  assert.ok(Object.isFrozen(overlay)); assert.ok(Object.isFrozen(overlay.source)); assert.ok(Object.isFrozen(overlay.scan));
  assert.ok(Object.isFrozen(overlay.scan.references)); assert.ok(Object.isFrozen(overlay.scan.references[0])); assert.ok(Object.isFrozen(overlay.scan.references[0].preview_byte_offsets));
  assert.notEqual(overlay.scan.references, f.state.bodyReferences.references);
  payload.references[0].target_origin = OTHER; f.state.bodyReferences.references[0].target_origin = OTHER;
  assert.equal(overlay.scan.references[0].target_origin, TARGET);
  assert.doesNotMatch(JSON.stringify(overlay) + f.els.canvas.innerHTML + f.els.overlayStatus.innerHTML, /PRIVATE_BODY|PRIVATE_HEADER|Authorization/);
  assert.equal(new URL(f.requests.find(item => item.url.includes('/body-references')).url, 'https://example.com').searchParams.get('evidence_id'), TOKEN);
});

test('new inspector verification and scan do not silently replace the original shown overlay', async () => {
  const f = await displayed(), shown = f.state.bodyReferenceOverlay;
  await f.verify(SECOND_TOKEN, OTHER, '9007199254740993'); await f.inspect(scan(SECOND_TOKEN, OTHER, '9007199254740993', [SOURCE]));
  assert.equal(f.state.bodyReferenceOverlay, shown); assert.equal(shown.source.origin, SOURCE); assert.equal(f.state.anchorOrigin, SOURCE);
  const count = f.requests.length; await f.load(); assert.equal(f.state.bodyReferenceOverlay, shown); assert.equal(f.requests.length, count + 1);
  assert.equal(f.requests.filter(item => item.url.includes('/body-references')).length, 2);
});

test('polling original token under a different metadata group survives independently of inspector selection', async () => {
  const f = await displayed(), shown = f.state.bodyReferenceOverlay;
  f.controller.selectOrigin(TARGET);
  const moved = origin(SOURCE, SECOND_TOKEN); moved.technology_clues = [{ name: 'server', source: 'response_header', confidence: 'observed_header', evidence: [TOKEN] }];
  await f.load(snapshot([moved, origin(OTHER, SECOND_TOKEN)]));
  assert.equal(f.state.bodyReferenceOverlay, shown); assert.equal(f.state.selectedOrigin, TARGET);
  assert.equal(f.requests.filter(item => item.url.includes('/body-references')).length, 1);
});

for (const variant of ['token retained only under another origin', 'same UUID with another exact token', 'origin no longer retained']) test(`poll clears original overlay when ${variant}`, async () => {
  const f = await displayed(); f.controller.selectOrigin(OTHER);
  const value = variant === 'origin no longer retained' ? snapshot([origin(OTHER, SECOND_TOKEN)])
    : snapshot([origin(SOURCE, SECOND_TOKEN), origin(OTHER, variant === 'token retained only under another origin' ? TOKEN : SECOND_TOKEN)]);
  await f.load(value); assertAbsent(f);
  assert.equal(f.state.selectedOrigin, OTHER); assert.equal(f.requests.filter(item => item.url.includes('/body-references')).length, 1);
  await f.load(); assertAbsent(f); // Metadata restoration cannot recreate a user-cleared overlay.
});

for (const boundary of ['hide', 'reset', 'dirty', 'disconnect', 'force', 'scope']) test(`${boundary} fences delayed JSON before it can restore shown references`, async () => {
  const f = await displayed(); const parsed = pending(); const poll = f.controller.refresh();
  f.requests.at(-1).resolve({ ok: true, json: () => parsed.promise }); await Promise.resolve();
  let follow;
  if (boundary === 'hide') f.controller.setVisible(false);
  if (boundary === 'reset') { f.setSession('new-session'); f.controller.reset(); }
  if (boundary === 'dirty') f.controller.markDirty();
  if (boundary === 'disconnect') f.controller.disconnect();
  if (boundary === 'force') follow = f.controller.refresh({ force: true });
  if (boundary === 'scope') follow = f.controller.scopeChanged({ scope_patterns: [] }, { scope_patterns: ['example.com'] });
  assertAbsent(f); parsed.resolve(snapshot()); await poll; assertAbsent(f);
  if (follow) { f.requests.at(-1).resolve(result(snapshot())); await follow; assertAbsent(f); }
  assert.equal(f.requests.filter(item => item.url.includes('/body-references')).length, 1);
});

test('source-only self references never create an overlay or a false self call', async () => {
  const f = fixture(); await f.load(); await f.verify(); await f.inspect(scan(TOKEN, SOURCE, SEQUENCE, [SOURCE]));
  const count = f.requests.length; assert.equal(f.controller.showBodyReferencesOnMap(), false); assertAbsent(f); assert.equal(f.requests.length, count);
});

test('late failure of a superseded map read cannot clear a newer explicitly shown overlay', async () => {
  const f = await displayed(); const obsolete = f.controller.refresh(), old = f.requests.at(-1);
  const fresh = f.controller.refresh({ force: true }); f.requests.at(-1).resolve(result(snapshot())); await fresh;
  await f.inspect(); assert.equal(f.controller.showBodyReferencesOnMap(), true); const shown = f.state.bodyReferenceOverlay;
  old.reject(new Error('obsolete failure')); await obsolete;
  assert.equal(f.state.bodyReferenceOverlay, shown); assert.equal(f.state.error, '');
});


test('new scans while disconnected cannot show an overlay until the live stream is ready', async () => {
  const f = await displayed(); f.setStreamReady(false); f.controller.disconnect(); assertAbsent(f);
  await f.load(); await f.verify(); await f.inspect(); const count = f.requests.length;
  assert.equal(f.controller.showBodyReferencesOnMap(), false); assertAbsent(f); assert.equal(f.requests.length, count);
  f.setStreamReady(true);
  // Production onopen invalidates existing evidence before the user may inspect again.
  const fresh = f.controller.invalidate(); f.requests.at(-1).resolve(result(snapshot())); await fresh;
  assert.equal(f.controller.showBodyReferencesOnMap(), false);
  await f.verify(); await f.inspect(); assert.equal(f.controller.showBodyReferencesOnMap(), true);
});

for (const boundary of ['hide', 'reset', 'clear']) test(`${boundary} discards references to the immutable overlay from identity caches`, async () => {
  const f = await displayed(), shown = f.state.bodyReferenceOverlay;
  f.controller.selectOrigin(TARGET); f.controller.selectOrigin(SOURCE);
  assert.equal(f.state.neighborhoodOverlay, f.state.relationLayers);
  assert.equal(f.state.graphLayers, f.state.relationLayers);
  if (boundary === 'hide') f.controller.setVisible(false);
  if (boundary === 'reset') { f.setSession('new-session'); f.controller.reset(); }
  if (boundary === 'clear') f.controller.clearBodyReferenceOverlay();
  assertAbsent(f);
  assert.notEqual(f.state.neighborhoodOverlay, shown);
  assert.notEqual(f.state.extraOriginOverlay, shown);
});

for (const boundary of ['refresh failure', 'dirty history']) test(`a newly inspected exact source cannot show references after ${boundary} until metadata revalidation`, async () => {
  const f = await displayed();
  if (boundary === 'refresh failure') { const task = f.controller.refresh(); f.requests.at(-1).reject(new Error('Synthetic failure')); await task; }
  else { f.controller.markDirty(); await f.verify(); }
  assertAbsent(f); await f.inspect(); const count = f.requests.length;
  assert.equal(f.controller.showBodyReferencesOnMap(), false); assertAbsent(f); assert.equal(f.requests.length, count);
  if (boundary === 'refresh failure') {
    const retry = f.controller.refresh({ force: true, retry: true });
    f.requests.at(-1).resolve(result(snapshot())); await retry;
    assertAbsent(f); await f.inspect();
  } else { await f.load(); assertAbsent(f); }
  assert.equal(f.controller.showBodyReferencesOnMap(), true);
  assert.equal(f.requests.length, count + (boundary === 'refresh failure' ? 2 : 1));
});

test('opposite directions, metadata and body links use distinct deterministic curves', () => {
  const a = { ...origin(SOURCE), captured: true }, b = { ...origin(OTHER), captured: true };
  for (const [source, target] of [[a, b], [b, a]]) {
    source.redirects = [{ target_origin: target.origin }];
    source.header_links = ['origin_header', 'referer_header'].map(relationship => ({ source_origin: target.origin, relationship }));
  }
  const bodyEdges = [{ source: SOURCE, target: OTHER, relationship: 'body_url_reference', label: 'Literal body URL reference' }];
  const layout = map.graphLayout([a, b], [SOURCE, OTHER], new Map(), SOURCE, bodyEdges);
  // Metadata is one arrow each way; the inspected body link keeps its own.
  assert.equal(layout.edges.length, 3); assert.equal(layout.edgeCount, 3);
  const geometry = edge => {
    const [x1, y1, c1x, c1y, c2x, c2y, x2, y2] = edge.path.match(/-?\d+(?:\.\d+)?/g).map(Number);
    return [[x1, y1, c1x, c1y, c2x, c2y, x2, y2].join(','), [x2, y2, c2x, c2y, c1x, c1y, x1, y1].join(',')].sort()[0];
  };
  assert.equal(new Set(layout.edges.map(geometry)).size, 3);
  const repeated = map.graphLayout([a, b], [SOURCE, OTHER], layout.slots, SOURCE, bodyEdges);
  assert.equal(JSON.stringify(repeated.edges), JSON.stringify(layout.edges));
});

for (const failure of ['unavailable', 'network error', 'source mismatch']) test(`exact original overlay-source metadata ${failure} clears references immediately`, async () => {
  const f = await displayed(); f.controller.selectOrigin(SOURCE); const task = f.controller.loadEvidence(TOKEN), read = f.requests.at(-1);
  assert.equal(new URL(read.url, 'https://example.com').searchParams.get('evidence_id'), TOKEN);
  if (failure === 'network error') read.reject(new Error('Synthetic metadata failure'));
  else if (failure === 'source mismatch') read.resolve(result(evidence(TOKEN, OTHER)));
  else read.resolve(result({ ...evidence(), available: false, row: null }));
  await task; assertAbsent(f);
  assert.equal(f.requests.filter(item => item.url.includes('/body-references')).length, 1);
});

test('unrelated source metadata failure does not clear or reassign original overlay provenance', async () => {
  const f = await displayed(), shown = f.state.bodyReferenceOverlay;
  f.controller.selectOrigin(OTHER); const task = f.controller.loadEvidence(SECOND_TOKEN);
  f.requests.at(-1).reject(new Error('Unrelated metadata failure')); await task;
  assert.equal(f.state.bodyReferenceOverlay, shown); assert.equal(shown.source.evidenceId, TOKEN); assert.equal(f.state.anchorOrigin, SOURCE);
  assert.equal(f.requests.filter(item => item.url.includes('/body-references')).length, 1);
});

test('View inspected source follows the original token from another inspector without reading bodies', async () => {
  const f = await displayed(), shown = f.state.bodyReferenceOverlay;
  f.controller.selectOrigin(TARGET); const before = f.requests.length;
  assert.match(f.els.overlayStatus.innerHTML, /View inspected source/);
  const origin = f.els.overlayStatus.innerHTML.match(/data-service-relation-origin="([^"]+)"/)[1];
  const token = f.els.overlayStatus.innerHTML.match(/data-service-relation-evidence="([^"]+)"/)[1];
  assert.equal(origin, SOURCE); assert.equal(token, TOKEN);
  f.els.panel.contains = () => true;
  f.els.panel.dispatch('click', { target: { closest: () => ({ dataset: { serviceRelationOrigin: origin, serviceRelationEvidence: token } }) } });
  assert.equal(f.requests.length, before + 1); assert.equal(f.state.selectedOrigin, SOURCE); assert.equal(f.state.evidenceId, TOKEN);
  assert.equal(new URL(f.requests.at(-1).url, 'https://example.com').pathname, '/api/target/service-map/evidence');
  f.requests.at(-1).resolve(result(evidence())); await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.bodyReferenceOverlay, shown); assert.equal(f.requests.filter(item => item.url.includes('/body-references')).length, 1);
});

test('body priority keeps separate metadata omissions and partial coverage visible away from source inspector', async () => {
  const f = fixture(), source = origin(SOURCE);
  source.redirects = Array.from({ length: 25 }, (_, i) => ({ target_origin: `https://metadata-${i}.example.com`, target_path: '/', relationship: 'redirect_instruction', evidence: [TOKEN] }));
  await f.load(snapshot([source, origin(OTHER, SECOND_TOKEN)])); await f.verify();
  const payload = scan(TOKEN, SOURCE, SEQUENCE, Array.from({ length: 100 }, (_, i) => `https://body-${i}.example.com`));
  Object.assign(payload, { status: 'partial', complete: false, reasons: ['origin_limit'], candidates_scanned: 103, omitted_reference_occurrences: 3 });
  await f.inspect(payload); assert.equal(f.controller.showBodyReferencesOnMap(), true); f.controller.selectOrigin(OTHER);
  assert.equal((f.els.canvas.innerHTML.match(/data-service-origin=/g) || []).length, 24);
  assert.equal((f.els.canvas.innerHTML.match(/data-relationship="body_url_reference"/g) || []).length, 23);
  assert.match(f.els.graphDiagnostics.textContent, /Body URL typed arrows: 23 \/ 100 shown · 77 outside displayed cards · 0 omitted by arrow cap/);
  assert.match(f.els.graphDiagnostics.textContent, /Metadata arrows: 0 \/ 25 shown · 25 outside displayed cards · 0 omitted by arrow cap/);
  assert.match(f.els.overlayStatus.innerHTML, /Partial retained-preview scan/);
  assert.match(f.els.overlayStatus.innerHTML, /Origin output limit reached/);
  assert.match(f.els.overlayStatus.innerHTML, /3 reference occurrence\(s\) omitted/);
  assert.equal(f.state.snapshot.origins.length, 2);
});

for (const failure of ['unavailable', 'unsupported', 'source mismatch', 'network error']) test(`explicit body reinspection ${failure} clears its overlay only for a valid identity failure`, async () => {
  const f = await displayed(), shown = f.state.bodyReferenceOverlay, row = f.state.evidence; const task = f.controller.loadBodyReferences(), read = f.requests.at(-1);
  if (failure === 'network error') read.reject(new Error('Synthetic body read failure'));
  else {
    const payload = scan();
    if (failure === 'source mismatch') payload.source_sequence = '9007199254740993';
    else Object.assign(payload, { status: failure, available: false, complete: false, reasons: [failure === 'unavailable' ? 'record_changed' : 'unsupported_content_type'],
      references: [], scanned_bytes: 0, candidates_scanned: 0, source_origin: null, source_sequence: null, source_started_at: null, retained_preview_bytes: null });
    read.resolve(result(payload));
  }
  await task;
  if (failure === 'unavailable') { assertAbsent(f); assert.equal(f.state.evidence, null); }
  else { assert.equal(f.state.bodyReferenceOverlay, shown); assert.equal(f.state.evidence, row); }
  assert.equal(f.requests.length, 4);
});

test('unavailable body inspection on an unrelated source preserves original shown provenance', async () => {
  const f = await displayed(), shown = f.state.bodyReferenceOverlay;
  await f.verify(SECOND_TOKEN, OTHER, '9007199254740993');
  const payload = scan(SECOND_TOKEN, OTHER, '9007199254740993');
  Object.assign(payload, { status: 'unavailable', available: false, complete: false, reasons: ['record_changed'], references: [], scanned_bytes: 0, candidates_scanned: 0 });
  await f.inspect(payload); assert.equal(f.state.bodyReferenceOverlay, shown); assert.equal(shown.source.evidenceId, TOKEN);
});

test('adding another source preserves both immutable inspections and refreshes identity caches', async () => {
  const f = await displayed(), old = f.state.bodyReferenceOverlay;
  f.controller.selectOrigin(TARGET); assert.equal(f.state.graphLayers, f.state.relationLayers);
  await f.verify(SECOND_TOKEN, OTHER, '9007199254740993'); await f.inspect(scan(SECOND_TOKEN, OTHER, '9007199254740993', [SOURCE]));
  assert.equal(f.controller.showBodyReferencesOnMap(), true);
  assert.equal(f.state.relationLayers.length, 2); assert.equal(f.state.relationLayers[0], old); assert.notEqual(f.state.bodyReferenceOverlay, old);
  assert.equal(f.state.bodyReferenceOverlay.source.evidenceId, SECOND_TOKEN); assert.equal(f.state.selectedOrigin, OTHER);
});
