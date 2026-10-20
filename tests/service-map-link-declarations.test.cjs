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
    sequence, started_at: STARTED, status: 200, metadata_complete: true, omitted: [] } }; }
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
const RELATIONS = ['service-doc', 'service-desc', 'describedby', 'preconnect'];
const LINK_TYPES = ['link_service_doc', 'link_service_desc', 'link_describedby', 'link_preconnect'];
function linkScan(members = [{ target: TARGET, relations: RELATIONS }], token = TOKEN, id = SOURCE, sequence = SEQUENCE) {
  const observations = [];
  let bytes = 0, tokens = 0;
  members.forEach(({ target, relations = ['service-doc'] }, header_index) => {
    const targetText = `${target}/private-path?private-query=PRIVATE_TOKEN#fragment`, prefix = `<${targetText}>; rel="`;
    const raw = `${prefix}${relations.join(' ')}"`;
    let position = Buffer.byteLength(prefix); bytes += Buffer.byteLength(raw) + 4;
    for (const relation of relations) {
      observations.push({ relation, target_origin: target, source: 'response_link_header', strength: 'literal_declaration', header_name: 'link',
        header_index, header_value_bytes: Buffer.byteLength(raw), link_value_span: { start: 0, end: Buffer.byteLength(raw) },
        target_span: { start: 1, end: 1 + Buffer.byteLength(targetText) }, relation_span: { start: position, end: position + relation.length },
        rule_id: `response_link.${relation.replaceAll('-', '_')}.v1`, offset_basis: 'retained_header_value_utf8' });
      position += relation.length + 1; tokens++;
    }
  });
  return { schema_version: 1, relation_catalog_version: 1, session_id: SESSION, evidence_id: token, available: true, status: 'scanned', complete: true,
    reasons: [], source_origin: id, source_sequence: sequence, source_started_at: STARTED, source_method: 'GET', source_status: 200,
    retained_header_count: members.length, coverage: 'absolute_http_link_declarations', offset_basis: 'retained_header_value_utf8',
    counts: { headers_inspected: members.length, header_bytes_admitted: bytes, link_fields_inspected: members.length, candidates_inspected: members.length,
      members_framed: members.length, parameters_inspected: members.length, relation_tokens_inspected: tokens, unknown_relation_tokens_inspected: 0 },
    observations, limits: { ...map.LINK_DECLARATION_LIMITS } };
}
const normalize = value => map.normalizeLinkDeclarations(value, SESSION, TOKEN, evidence().row);
function unavailable(reason = 'record_missing', status = 'unavailable') { const value = linkScan([]); Object.assign(value, { available: false, status, complete: false, reasons: [reason] });
  for (const key of ['source_origin', 'source_sequence', 'source_started_at', 'source_method', 'source_status', 'retained_header_count']) value[key] = null;
  return value; }
async function inspectLink(f, value = linkScan()) { f.controller.setRelationshipKind('link'); const task = f.controller.loadLinkDeclarations(); f.requests.at(-1).resolve(result(value)); return task; }
async function readyLink(value = linkScan(), metadata = snapshot()) { const f = fixture(); await f.load(metadata); await f.verify(); await inspectLink(f, value); return f; }
async function displayedLink(value, metadata) { const f = await readyLink(value, metadata); assert.equal(f.controller.showLinkDeclarationsOnMap(), true); return f; }
async function displayedBody() { const f = fixture(); await f.load(); await f.verify(); await f.inspect(); assert.equal(f.controller.showBodyReferencesOnMap(), true); return f; }
const clone = value => JSON.parse(JSON.stringify(value));
const tick = () => new Promise(resolve => setImmediate(resolve));

test('Link strict contract accepts four ordered relation spans in one member and repeated separate members', () => {
  const value = linkScan([{ target: TARGET, relations: RELATIONS }, { target: TARGET, relations: ['service-doc', 'service-doc'] }]);
  const normalized = normalize(value); assert.equal(normalized.observations.length, 6);
  assert.equal(normalized.observations[0].target_span.start, 1); assert.equal(normalized.observations[4].header_index, 1);
  value.observations[0].target_span.end++; value.reasons.push('malformed_field'); value.counts.headers_inspected = 99;
  assert.notEqual(normalized.observations[0].target_span.end, value.observations[0].target_span.end);
  assert.equal(normalized.reasons.length, 0); assert.equal(normalized.counts.headers_inspected, 2);
});

test('Link unavailable and unsupported require exactly one fixed reason with explicit null fields and zero counts', () => {
  for (const reason of ['record_missing', 'metadata_unavailable', 'unsupported_source_context', 'link_inspection_failed']) assert.equal(normalize(unavailable(reason)).complete, false);
  for (const mutate of [v => { delete v.source_origin; }, v => v.source_status = 200, v => v.counts.headers_inspected = 1,
    v => v.reasons = ['record_missing', 'record_changed'], v => v.reasons = ['malformed_field'], v => v.complete = true]) {
    const v = unavailable(); mutate(v); assert.throws(() => normalize(v));
  }
});

const invalidCases = {
  unknownEnvelope: v => v.private_headers = 'PRIVATE_TOKEN', missingNull: v => delete v.source_status,
  version: v => v.relation_catalog_version = 2, status: v => v.status = 'partial', available: v => v.available = 1,
  complete: v => v.complete = false, catalog: v => v.schema_version = 2, session: v => v.session_id = GENERATION,
  token: v => v.evidence_id = SECOND_TOKEN, sequence: v => v.source_sequence = '01', method: v => v.source_method = 'POST',
  statusCode: v => v.source_status = 204, date: v => v.source_started_at = '2026-02-30T01:00:00Z',
  sourceCredential: v => v.source_origin = 'https://user:pass@source.example.com', coverage: v => v.coverage = 'all_dependencies',
  sourcePath: v => v.source_origin += '/private', unknownReason: v => { v.complete = false; v.reasons = ['PRIVATE_TOKEN']; },
  unknownCount: v => v.counts.uninspected = 1, negativeCount: v => v.counts.parameters_inspected = -1,
  fakeCompleteCount: v => v.counts.members_framed = 0, headers: v => v.retained_header_count = 2,
  impossibleBytes: v => v.counts.header_bytes_admitted = 4, candidateCap: v => { v.complete = false; v.reasons = ['candidate_limit']; },
  wrongLimit: v => v.limits.observations = 64, unknownLimit: v => v.limits.other = 1,
  unknownObservation: v => v.observations[0].raw_value = 'PRIVATE_TOKEN', unknownRelation: v => v.observations[0].relation = 'next',
  fakeRule: v => v.observations[0].rule_id = 'response_link.preconnect.v1', wrongStrength: v => v.observations[0].strength = 'confirmed_call',
  targetQuery: v => v.observations[0].target_origin += '?PRIVATE_TOKEN', targetPath: v => v.observations[0].target_origin += '/',
  targetCredentials: v => v.observations[0].target_origin = 'https://user:pass@asset.example.com', numericAlias: v => v.observations[0].target_origin = 'http://127.1',
  hostUnderscore: v => v.observations[0].target_origin = 'https://bad_host.example.com', hostBoundary: v => v.observations[0].target_origin = 'https://-bad.example.com',
  nonAscii: v => v.observations[0].target_origin = 'https://é.example.com', protocol: v => v.observations[0].target_origin = 'ftp://asset.example.com',
  headerIndex: v => v.observations[0].header_index = 128, headerSize: v => v.observations[0].header_value_bytes = 4097,
  fakeOffset: v => v.observations[0].offset_basis = 'original_wire_bytes', spanStart: v => v.observations[0].target_span.start = 0,
  reversedSpan: v => v.observations[0].relation_span.end = 1, overlap: v => v.observations[1].relation_span = { ...v.observations[0].relation_span },
  sameMemberMismatch: v => v.observations[1].target_origin = OTHER, memberOverlap: v => v.observations[1].link_value_span.start = 2,
  duplicateSpan: v => v.observations[1] = clone(v.observations[0]), oversizedOrigin: v => v.observations[0].target_origin = `https://${'a'.repeat(64)}.example.com`,
};
for (const [name, mutate] of Object.entries(invalidCases)) test(`strict Link envelope rejects ${name} safely`, () => {
  const value = linkScan(); mutate(value); assert.throws(() => normalize(value), /Invalid retained Link-declaration response/);
});

test('partial output and empty supported grammar have honest independent coverage', async () => {
  const value = linkScan([]); assert.equal(normalize(value).complete, true);
  value.complete = false; value.reasons = ['malformed_field']; value.retained_header_count = 1;
  value.counts.headers_inspected = value.counts.link_fields_inspected = 1; value.counts.header_bytes_admitted = 12;
  assert.equal(normalize(value).observations.length, 0);
  const f = await readyLink(value); assert.match(f.els.detail.innerHTML, /coverage is partial/); assert.equal(f.controller.showLinkDeclarationsOnMap(), false);
});

test('only explicit Link Inspect issues one exact GET without catalog headers; passive actions and Show are local', async () => {
  const f = fixture(); await f.load(); await f.verify(); const count = f.requests.length;
  f.controller.setRelationshipKind('link'); f.controller.setZoom(1.2); f.controller.displayChanged(); f.controller.fitGraph();
  assert.equal(f.controller.showLinkDeclarationsOnMap(), false); assert.equal(f.requests.length, count);
  const read = f.controller.loadLinkDeclarations(); const request = f.requests.at(-1), url = new URL(request.url, SOURCE);
  assert.equal(await f.controller.loadLinkDeclarations(), false); assert.equal(await f.controller.loadBodyReferences(), false);
  assert.equal(f.requests.length, count + 1); assert.equal(request.options.headers, undefined); assert.equal(request.options.redirect, 'error');
  assert.equal(url.pathname, '/api/target/service-map/link-declarations'); assert.equal(url.searchParams.get('evidence_id'), TOKEN);
  assert.deepEqual([...url.searchParams.keys()], ['session_id', 'evidence_id']);
  request.resolve(result(linkScan())); await read;
  assert.match(f.els.detail.innerHTML, /Retained relationships/); assert.equal((f.els.detail.innerHTML.match(/<select /g) || []).length, 1);
  assert.match(f.els.detail.innerHTML, /Sequence 18446744073709551615/); assert.match(f.els.detail.innerHTML, /Response Link headers · Complete inspection/);
  assert.doesNotMatch(f.els.detail.innerHTML, /Response Link header index/, 'no byte positions in the list');
  assert.doesNotMatch(f.els.detail.innerHTML, /PRIVATE_TOKEN|private-path|private-query|<a\s/);
  assert.equal(f.controller.showLinkDeclarationsOnMap(), true); assert.equal(f.requests.length, count + 1);
  for (const type of LINK_TYPES) assert.match(f.els.canvas.innerHTML, new RegExp(`data-relationship="${type}"`));
  f.controller.selectOrigin(TARGET); assert.equal(f.state.anchorOrigin, SOURCE); assert.match(f.els.detail.innerHTML, /no service role or request count is established/);
  assert.doesNotMatch(f.els.detail.innerHTML, /Header-reported technologies/); assert.equal(f.requests.length, count + 1);
});

for (const direction of ['body-link', 'link-body']) test(`${direction}: Inspect preserves entries and explicit Show accumulates independent immutable kinds`, async () => {
  const f = direction === 'body-link' ? await displayedBody() : await displayedLink(), original = f.state.bodyReferenceOverlay;
  const targetKind = direction === 'body-link' ? 'link' : 'body', count = f.requests.length;
  f.controller.setRelationshipKind(targetKind); assert.equal(f.requests.length, count); assert.equal(f.state.bodyReferenceOverlay, original);
  if (targetKind === 'link') await inspectLink(f); else await f.inspect();
  assert.equal(f.state.bodyReferenceOverlay, original); assert.match(f.els.detail.innerHTML, /Show references on map/);
  const reads = f.requests.length; assert.equal(targetKind === 'link' ? f.controller.showLinkDeclarationsOnMap() : f.controller.showBodyReferencesOnMap(), true);
  assert.equal(f.state.relationLayers.length, 2); assert.equal(f.state.relationLayers[0], original);
  assert.match(f.els.canvas.innerHTML, /body_url_reference/); assert.match(f.els.canvas.innerHTML, /link_service_doc/);
  const overlay = f.state.bodyReferenceOverlay; assert.equal(overlay.kind, targetKind); assert.notEqual(overlay, original); assert.equal(f.requests.length, reads);
  assert.ok(Object.isFrozen(overlay) && Object.isFrozen(overlay.scan));
  if (targetKind === 'link') { assert.ok(Object.isFrozen(overlay.scan.observations[0].relation_span)); f.state.linkDeclarations.observations[0].target_origin = OTHER; assert.equal(overlay.scan.observations[0].target_origin, TARGET); }
});

for (const failure of ['404', '302', 'network', 'invalid', 'unsupported']) test(`Link ${failure} preserves a valid shown body overlay without raw error echo or retry`, async () => {
  const f = await displayedBody(), overlay = f.state.bodyReferenceOverlay; f.controller.setRelationshipKind('link');
  const before = f.requests.length, pendingRead = f.controller.loadLinkDeclarations(); let errorBodyReads = 0;
  if (failure === 'network') f.requests.at(-1).reject(new Error('PRIVATE_TOKEN'));
  else if (failure === 'invalid') f.requests.at(-1).resolve(result({ ...linkScan(), secret: 'PRIVATE_TOKEN' }));
  else if (failure === 'unsupported') f.requests.at(-1).resolve(result(unavailable('unsupported_source_context', 'unsupported')));
  else f.requests.at(-1).resolve({ ok: false, status: Number(failure), json: async () => { errorBodyReads++; return { error: 'PRIVATE_TOKEN' }; } });
  await pendingRead; assert.equal(f.state.bodyReferenceOverlay, overlay); assert.equal(f.requests.length, before + 1); assert.equal(errorBodyReads, 0);
  assert.doesNotMatch(f.els.detail.innerHTML, /PRIVATE_TOKEN/); if (failure === '404') assert.match(f.els.detail.innerHTML, /server does not support retained Link/);
});

for (const boundary of ['kind', 'source', 'session', 'hide', 'dirty', 'disconnect', 'force', 'scope']) for (const stage of ['response', 'json', 'failure']) test(`${boundary} fences late Link ${stage} without restoring output`, async () => {
  const f = fixture(); await f.load(); await f.verify(); f.controller.setRelationshipKind('link');
  const task = f.controller.loadLinkDeclarations(), req = f.requests.at(-1), json = pending();
  if (stage === 'json') { req.resolve({ ok: true, json: () => json.promise }); await Promise.resolve(); }
  let otherTask;
  if (boundary === 'kind') f.controller.setRelationshipKind('body');
  if (boundary === 'source') f.controller.selectOrigin(OTHER);
  if (boundary === 'session') { f.setSession(GENERATION); f.controller.reset(); }
  if (boundary === 'hide') f.controller.setVisible(false);
  if (boundary === 'dirty') f.controller.markDirty();
  if (boundary === 'disconnect') f.controller.disconnect();
  if (boundary === 'force') otherTask = f.controller.refresh({ force: true });
  if (boundary === 'scope') otherTask = f.controller.scopeChanged({ scope_patterns: [] }, { scope_patterns: ['example.com'] });
  assert.equal(req.options.signal.aborted, true);
  if (stage === 'json') json.resolve(linkScan()); else if (stage === 'failure') req.reject(new Error('PRIVATE_TOKEN')); else req.resolve(result(linkScan()));
  await task; assert.equal(f.state.linkDeclarations, null); assert.equal(f.state.linkDeclarationsError, ''); assert.equal(f.state.bodyReferenceOverlay, null);
  if (otherTask) { f.requests.at(-1).resolve(result(snapshot())); await otherTask; }
});

test('kind selection cancels the sole pending body inspection, allows one Link read, and fences delayed body JSON', async () => {
  const f = fixture(); await f.load(); await f.verify(); const body = f.controller.loadBodyReferences(), request = f.requests.at(-1), json = pending();
  request.resolve({ ok: true, json: () => json.promise }); await Promise.resolve();
  f.controller.setRelationshipKind('link'); assert.equal(request.options.signal.aborted, true); await inspectLink(f);
  json.resolve(scan()); await body; assert.equal(f.state.bodyReferences, null); assert.equal(f.state.linkDeclarations.status, 'scanned');
});

test('unchanged polls preserve exact Link result and overlay; same-row method/path changes invalidate them', async () => {
  const f = await displayedLink(), overlay = f.state.bodyReferenceOverlay, inspected = f.state.linkDeclarations;
  await f.load(); assert.equal(f.state.bodyReferenceOverlay, overlay); assert.equal(f.state.linkDeclarations, inspected);
  assert.equal(f.requests.filter(item => item.url.includes('link-declarations')).length, 1);
  const changed = snapshot(); changed.origins[0].endpoints[0].path = '/changed'; await f.load(changed);
  assert.equal(f.state.bodyReferenceOverlay, null); assert.equal(f.state.linkDeclarations, null);
});

for (const reason of ['record_changed', 'record_missing', 'stale_generation', 'session_source_changed']) test(`exact Link lifetime result ${reason} clears either shown kind`, async () => {
  const f = await displayedBody(); await inspectLink(f, unavailable(reason)); assert.equal(f.state.bodyReferenceOverlay, null);
});

test('self declarations remain inspectable and do not create graph arrows', async () => {
  const f = await readyLink(linkScan([{ target: SOURCE, relations: RELATIONS }])); assert.equal(f.controller.showLinkDeclarationsOnMap(), false);
  assert.match(f.els.detail.innerHTML, /Only the source origin was declared/); assert.equal(f.state.bodyReferenceOverlay, null);
});

test('repeated declaration observations retain provenance but arrows deduplicate by pair and type', async () => {
  const f = await displayedLink(linkScan([{ target: TARGET, relations: ['service-doc', 'service-doc'] }, { target: TARGET, relations: ['service-doc'] }]));
  assert.equal(f.state.bodyReferenceOverlay.scan.observations.length, 3);
  assert.equal((f.els.canvas.innerHTML.match(/data-relationship="link_service_doc"/g) || []).length, 1);
  assert.match(f.els.graphBounds.textContent, /1 Link links/);
});

test('32 target observations obey 23-neighbor display cap and independent query omission counts', async () => {
  const f = await displayedLink(linkScan(Array.from({ length: 32 }, (_, i) => ({ target: `https://target-${i}.example.com` }))));
  assert.equal((f.els.canvas.innerHTML.match(/class="service-map-card /g) || []).length, 24);
  assert.match(f.els.graphBounds.textContent, /23 \/ 32 known direct neighbors shown/); assert.match(f.els.graphBounds.textContent, /9 omitted by 24-card cap/);
  assert.match(f.els.graphDiagnostics.textContent, /Link declaration typed arrows: 23 \/ 32 shown · 9 outside displayed cards · 0 omitted by arrow cap/);
  assert.match(f.els.detail.innerHTML, /2 additional relationship declarations omitted from this pane/);
  f.els.search.value = 'target-1.'; f.els.search.dispatch('input');
  assert.match(f.els.graphBounds.textContent, /31 hidden by query/); assert.doesNotMatch(f.els.graphBounds.textContent, /omitted by 24-card cap/);
});

test('up to ten mixed typed and reverse arrows have distinct deterministic geometry within default and 20px cards', () => {
  const a = { ...origin(SOURCE), captured: true }, b = { ...origin(OTHER), captured: true };
  for (const [source, target] of [[a,b], [b,a]]) { source.redirects = [{ target_origin: target.origin }]; source.header_links = ['origin_header', 'referer_header'].map(relationship => ({ source_origin: target.origin, relationship })); }
  const links = LINK_TYPES.map(relationship => ({ source: SOURCE, target: OTHER, relationship, label: relationship }));
  for (const size of [12, 20]) {
    const geometry = map.graphGeometry(size), layout = map.graphLayout([a,b], [SOURCE,OTHER], new Map(), SOURCE, links, geometry);
    assert.equal(layout.edges.length, 10); const paths = new Set();
    for (const edge of layout.edges) { const n = edge.path.match(/-?\d+(?:\.\d+)?/g).map(Number), reverse = [n[6], n[7], n[4], n[5], n[2], n[3], n[0], n[1]];
      paths.add([n.join(','), reverse.join(',')].sort()[0]); assert.ok(n[1] >= 36 && n[1] < 24 + geometry.cardHeight - 8); assert.ok(n.every(Number.isFinite));
      for (let i = 0; i < n.length; i += 2) assert.ok(n[i] >= 0 && n[i] <= layout.width);
    }
    assert.equal(paths.size, 10); assert.equal(JSON.stringify(layout.edges), JSON.stringify(map.graphLayout([a,b], [SOURCE,OTHER], layout.slots, SOURCE, links, geometry).edges));
    assert.equal(geometry.cardWidth, 220); assert.ok(geometry.cardHeight >= 84); if (size === 12) assert.equal(geometry.cardHeight, 84);
  }
});

test('all thirty-two Link observations and metadata keep distinct arrow cap omissions', async () => {
  const source = origin(SOURCE), targets = Array.from({ length: 8 }, (_, i) => `https://target-${i}.example.com`);
  source.redirects = targets.map(target_origin => ({ target_origin, target_path: '/', relationship: 'redirect_instruction', evidence: [TOKEN] }));
  source.header_links = targets.flatMap(source_origin => ['origin_header', 'referer_header'].map(relationship => ({ source_origin, relationship, source: 'request_header_declaration', evidence: [TOKEN] })));
  const f = await displayedLink(linkScan(targets.map(target => ({ target, relations: RELATIONS }))), snapshot([source]));
  assert.equal((f.els.canvas.innerHTML.match(/data-relationship=/g) || []).length, 40);
  assert.match(f.els.graphDiagnostics.textContent, /Link declaration typed arrows: 32 \/ 32 shown · 0 outside displayed cards · 0 omitted by arrow cap/);
  assert.match(f.els.graphDiagnostics.textContent, /Metadata typed arrows: 8 \/ 24 shown · 0 outside displayed cards · 16 omitted by arrow cap/);
});

test('Link eligibility requires fresh verified exact identity without depending on retained body availability', async () => {
  const f = fixture(); await f.load(); await f.verify(); f.controller.setRelationshipKind('link');
  f.setStreamReady(false); assert.equal(await f.controller.loadLinkDeclarations(), false); f.setStreamReady(true);
  f.state.stale = true; assert.equal(await f.controller.loadLinkDeclarations(), false); f.state.stale = false;
  f.state.evidence.body_available = false; await inspectLink(f); assert.equal(f.state.linkDeclarations.status, 'scanned');
});

test('actual backend-serialized synthetic envelope matches the UI contract', () => {
  const value = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/retained-link-declarations.json')));
  const row = { origin: value.source_origin, sequence: value.source_sequence, started_at: value.source_started_at, method: value.source_method, status: value.source_status };
  const normalized = map.normalizeLinkDeclarations(value, value.session_id, value.evidence_id, row);
  assert.equal(normalized.observations.length, 2); assert.equal(normalized.observations[0].header_index, 1);
  assert.equal(normalized.observations[1].relation_span.start, 66);
});

test('a body inspection reporting exact source loss clears a shown Link overlay', async () => {
  const f = await displayedLink(); f.controller.setRelationshipKind('body');
  const value = scan(); Object.assign(value, { available: false, status: 'unavailable', complete: false, reasons: ['record_missing'], references: [], scanned_bytes: 0, candidates_scanned: 0 });
  for (const key of ['source_origin', 'source_sequence', 'source_started_at', 'retained_preview_bytes']) delete value[key];
  await f.inspect(value); assert.equal(f.state.bodyReferenceOverlay, null);
});

for (const marker of ['session_changed', 'scope_changed', 'history_changed']) test(`ordinary map ${marker} clears exact Link evidence and overlay`, async () => {
  const f = await displayedLink(), previous = f.state.snapshot;
  const task = f.controller.refresh(); f.requests.at(-1).resolve({ ok: false, status: 409,
    headers: { get: () => marker }, json() { assert.fail('No failure body read'); } });
  assert.equal(await task, false);
  for (const key of ['evidence', 'evidenceId', 'linkDeclarations', 'linkDeclarationsSource', 'bodyReferenceOverlay']) assert.equal(f.state[key], null, key);
  assert.equal(f.state.snapshot, previous); assert.equal(f.state.stale, true); assert.equal(f.state.refreshPaused, true);
  const count = f.requests.length; await f.controller.refresh(); assert.equal(f.requests.length, count);
});
