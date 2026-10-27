// Source-lifetime regression matrix. Synthetic DTOs only; no sockets or app bootstrap.
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
const SEQUENCE = '9007199254740993';
const TOKEN = `v1.${SESSION}.${GENERATION}.${SEQUENCE}.44444444-4444-4444-8444-444444444444.${ROW}`;
const SECOND_TOKEN = `v1.${SESSION}.${GENERATION}.9007199254740994.55555555-5555-4555-8555-555555555555.${ROW}`;
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
function evidence(token = TOKEN, id = SOURCE, sequence = token.split('.')[3]) { return { schema_version: 1, session_id: SESSION, evidence_id: token,
  available: true, source: 'captured_http_metadata', socket_peer: socketPeer(), row: { evidence_id: token, origin: id, method: 'GET', path: '/source', record_id: ROW,
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
    async load(data = snapshot(), force = false) { const task = controller.refresh({ force }); requests.at(-1).resolve(result(data)); return task; },
    async verify(token = TOKEN, id = SOURCE, sequence = token.split('.')[3]) { controller.selectOrigin(id); const task = controller.loadEvidence(token);
      requests.at(-1).resolve(result(evidence(token, id, sequence))); return task; },
    async inspect(data = scan()) { const task = controller.loadBodyReferences(); requests.at(-1).resolve(result(data)); return task; },
  };
}
const RELATIONS = ['service-doc', 'service-desc', 'describedby', 'preconnect'];
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
const KINDS = ['body', 'link', 'html', 'peer'];
const AUTHORITATIVE = ['invalid_evidence_id', 'session_mismatch', 'stale_generation', 'record_missing', 'record_changed', 'session_source_changed'];
const BROAD = ['stale_generation', 'session_source_changed'];
const NEW_GENERATION = '66666666-6666-4666-8666-666666666666';
const MATCH = 'https://match.example.com';
const PEER_TIME = '2026-10-12T01:00:01Z';
function socketPeer() { return { status: 'observed', observation: { source: 'http_response_remote_addr', route: 'direct', observed_at: PEER_TIME, address: { ip: '192.0.2.10', port: 443 }, reason: null } }; }
function htmlScan(token = TOKEN, id = SOURCE) { return {
  schema_version: 1, generator_catalog_version: 1, session_id: SESSION, evidence_id: token, available: true, status: 'scanned', complete: true,
  reasons: [], source_origin: id, source_sequence: token.split('.')[3], source_started_at: STARTED,
  retained_preview_bytes: 100, scan_prefix_bytes: 100, capture_preview_truncated: false, scan_prefix_truncated: false,
  coverage: 'literal_html_generator_explicit_head', head_closed: true, parser_stop: null, tag_candidates_inspected: 3,
  additional_tag_candidate_encountered: false, additional_observation_encountered: false, unknown_product_declarations: 0,
  observations: [], limits: { ...map.HTML_GENERATOR_LIMITS }, offset_basis: 'retained_utf8_preview',
}; }
function peerScan(token = TOKEN, id = SOURCE, other = OTHER) {
  const otherToken = token === TOKEN ? SECOND_TOKEN : TOKEN;
  const sequences = [token.split('.')[3], otherToken.split('.')[3]].sort((a, b) => BigInt(a) < BigInt(b) ? -1 : 1);
  return { schema_version: 1, session_id: SESSION, evidence_id: token, available: true, status: 'matched', complete: true, reasons: [], in_scope_only: false,
    coverage: 'retained_direct_socket_peer_equality', peer: { source: 'http_response_remote_addr', route: 'direct', address_family: 'ipv4', address: { ip: '192.0.2.10', port: 443 } },
    source: { evidence_id: token, sequence: token.split('.')[3], origin: id, started_at: STARTED, observed_at: PEER_TIME, in_scope: true, in_window: true },
    snapshot: { id: ROW, generation: token.split('.')[2], captured_at: PEER_TIME, window_order: 'latest_retained_sequence', retained_rows: 2, considered_rows: 2,
      oldest_considered_sequence: sequences[0], latest_considered_sequence: sequences[1] },
    counts: { non_http_rows: 0, not_recorded_rows: 0, unavailable_observation_rows: 0, non_direct_rows: 0, invalid_observation_rows: 0, different_peer_rows: 0,
      invalid_metadata_rows: 0, scope_excluded_rows: 0, matching_rows: 1, returned_matching_rows: 1, omitted_matching_rows: 0, sample_rows: 1, omitted_sample_rows: 0 },
    origins: [{ origin: other, in_scope: true, matching_rows: 1, first_observed_at: PEER_TIME, last_observed_at: PEER_TIME,
      samples: [{ evidence_id: otherToken, sequence: otherToken.split('.')[3], started_at: STARTED, observed_at: PEER_TIME }], omitted_samples: 0 }], limits: { ...map.PEER_MATCH_LIMITS } };
}
function successful(kind, token = TOKEN, id = SOURCE) {
  if (kind === 'body') return scan(token, id, token.split('.')[3]);
  if (kind === 'link') return linkScan(undefined, token, id, token.split('.')[3]);
  if (kind === 'html') return htmlScan(token, id);
  return peerScan(token, id, id === OTHER ? SOURCE : OTHER);
}
function missing(kind, reason, token = TOKEN) {
  const value = successful(kind, token);
  Object.assign(value, { available: false, status: 'unavailable', complete: false, reasons: [reason] });
  if (kind === 'peer') {
    Object.assign(value, { peer: null, source: null, snapshot: null, origins: [] });
    for (const key of Object.keys(value.counts)) value.counts[key] = 0;
  } else {
    for (const key of ['source_origin', 'source_sequence', 'source_started_at']) value[key] = null;
    if (kind === 'link') {
      for (const key of ['source_method', 'source_status', 'retained_header_count']) value[key] = null;
      for (const key of Object.keys(value.counts)) value.counts[key] = 0;
      value.observations = [];
    } else {
      value.retained_preview_bytes = null;
      if (kind === 'html') Object.assign(value, { scan_prefix_bytes: 0, head_closed: false, tag_candidates_inspected: 0, observations: [] });
      else Object.assign(value, { scanned_bytes: 0, candidates_scanned: 0, references: [] });
    }
  }
  if (kind !== 'peer' && ['unsupported_metadata', 'metadata_limit', 'unsupported_content_type', 'unsupported_body_encoding', 'unsupported_content_encoding'].includes(reason)) value.status = 'unsupported';
  return value;
}
function begin(f, kind) {
  if (kind === 'body' || kind === 'link') f.controller.setRelationshipKind(kind);
  const before = f.requests.length;
  const task = f.controller[{ body: 'loadBodyReferences', link: 'loadLinkDeclarations', html: 'loadHtmlGenerators', peer: 'loadPeerMatches' }[kind]]();
  assert.equal(f.requests.length, before + 1, `${kind} begins one explicit read`);
  return { task, request: f.requests.at(-1) };
}
async function inspect(f, kind, payload = successful(kind)) {
  const { task, request } = begin(f, kind); request.resolve(result(payload)); assert.equal(await task, true);
}
async function show(f, kind = 'body', token = TOKEN, id = SOURCE) {
  await inspect(f, kind, successful(kind, token, id));
  assert.equal(f.controller[{ body: 'showBodyReferencesOnMap', link: 'showLinkDeclarationsOnMap', peer: 'showPeerMatchesOnMap' }[kind]](), true);
}
async function verified() { const f = fixture(); await f.load(); assert.equal(await f.verify(), true); return f; }
function clickDetailTab(f, tab) {
  const button = { dataset: { serviceDetailTab: tab } };
  f.els.panel.contains = target => target === button;
  f.els.panel.dispatch('click', { target: { closest: selector => selector === 'button' ? button : null } });
  assert.equal(f.state.detailTab, tab);
  assert.match(f.els.detail.innerHTML, new RegExp(`id="serviceMapDetail${tab === 'apis' ? 'Apis' : 'Evidence'}Tab"[^>]*aria-selected="true"`));
}

function noSupplements(f) {
  for (const key of ['bodyReferences', 'linkDeclarations', 'htmlGenerators', 'peerMatches', 'bodyReferencesSource', 'linkDeclarationsSource', 'htmlGeneratorsSource', 'peerMatchesSource']) assert.equal(f.state[key], null, key);
  for (const key of ['bodyReferencesLoading', 'htmlGeneratorsLoading', 'peerMatchesLoading']) assert.equal(f.state[key], false, key);
}
async function blocked(f) {
  const count = f.requests.length;
  for (const kind of KINDS) {
    if (kind === 'body' || kind === 'link') f.controller.setRelationshipKind(kind);
    assert.equal(await f.controller[{ body: 'loadBodyReferences', link: 'loadLinkDeclarations', html: 'loadHtmlGenerators', peer: 'loadPeerMatches' }[kind]](), false, kind);
  }
  for (const method of ['showBodyReferencesOnMap', 'showLinkDeclarationsOnMap', 'showPeerMatchesOnMap']) assert.equal(f.controller[method](), false, method);
  assert.equal(f.requests.length, count, 'blocked actions do not read');
  assert.match(f.els.detail.innerHTML, /session must be active/);
  for (const kind of ['html-generators', 'body-references', 'link-declarations', 'peer-matches']) assert.doesNotMatch(f.els.detail.innerHTML, new RegExp(`data-service-${kind}="inspect"`));
  if (f.els.detail.innerHTML.includes('data-service-packet-inspect')) assert.match(f.els.detail.innerHTML, /data-service-packet-inspect="true"[^>]*disabled/);
  assert.match(f.els.detail.innerHTML, /data-service-packet-peer="true"[^>]*disabled/);
  f.controller.setRelationshipKind('body');
  assert.doesNotMatch(f.els.detail.innerHTML, /data-service-body-references="inspect"/);
}

for (const kind of KINDS) for (const reason of AUTHORITATIVE) for (const overlayKind of [null, 'body', 'link', 'peer']) {
  test(`${kind} ${reason} revokes exact source and ${overlayKind || 'no'} overlay`, async () => {
    const f = await verified(); if (overlayKind) await show(f, overlayKind);
    const snapshotBefore = f.state.snapshot, count = f.requests.length;
    await inspect(f, kind, missing(kind, reason));
    assert.equal(f.requests.length, count + 1, 'no retry or automatic read');
    assert.equal(f.state.evidence, null); assert.equal(f.state.socketPeer, null); assert.equal(f.state.evidenceId, null);
    assert.equal(f.state.bodyReferenceOverlay, null); noSupplements(f);
    assert.equal(f.state.snapshot, snapshotBefore, 'default cards and aggregate snapshot remain');
    assert.doesNotMatch(f.els.detail.innerHTML, /Capture info/);
    assert.match(f.els.detail.innerHTML, /Source unavailable/);
    if (reason === 'session_source_changed') assert.match(f.els.detail.innerHTML, /Session context changed; verify again\./);
    if (['session_source_changed', 'invalid_evidence_id'].includes(reason)) assert.doesNotMatch(f.els.detail.innerHTML, /no longer retained|removed|deleted/);
  });
}
for (const kind of KINDS) for (const reason of AUTHORITATIVE) test(`${kind} ${reason} scopes unrelated overlay by exact token or context`, async () => {
  const f = await verified(); await show(f); const overlay = f.state.bodyReferenceOverlay;
  await f.verify(SECOND_TOKEN, OTHER); await inspect(f, kind, missing(kind, reason, SECOND_TOKEN));
  assert.equal(f.state.evidence, null);
  assert.equal(f.state.bodyReferenceOverlay, BROAD.includes(reason) ? null : overlay);
});
const NONIDENTITY = {
  body: ['response_unavailable', 'body_identity_unverifiable', 'body_storage_unavailable', 'body_read_failed', 'serialized_row_limit', 'malformed_retained_row', 'retained_preview_unavailable', 'metadata_unavailable', 'body_scan_failed', 'unsupported_metadata', 'metadata_limit', 'unsupported_content_type', 'unsupported_body_encoding', 'unsupported_content_encoding'],
  link: ['response_unavailable', 'unsupported_source_context', 'metadata_unavailable', 'link_inspection_failed'],
  html: ['response_unavailable', 'body_identity_unverifiable', 'body_storage_unavailable', 'body_read_failed', 'serialized_row_limit', 'malformed_retained_row', 'retained_preview_unavailable', 'metadata_unavailable', 'body_scan_failed', 'unsupported_metadata', 'metadata_limit', 'unsupported_content_type', 'unsupported_body_encoding', 'unsupported_content_encoding'],
  peer: ['unsupported_source_context', 'observation_not_recorded', 'observation_unavailable', 'non_direct_observation', 'invalid_observation', 'metadata_unavailable', 'scope_work_limit', 'peer_inspection_failed'],
};
const SUPPLEMENT_UNSUPPORTED = {
  html: ['metadata_limit', 'unsupported_content_type', 'unsupported_body_encoding', 'unsupported_content_encoding', 'unsupported_metadata'],
  link: ['unsupported_source_context'],
};
const SUPPLEMENT_ERRORS = {
  html: 'Could not verify retained HTML generators. Retry explicitly, or refresh the map and select the source again.',
  link: 'Could not verify retained Link headers. Retry explicitly, or refresh the map and select the source again.',
};
for (const kind of ['html', 'link']) {
  const normalize = value => map[kind === 'html' ? 'normalizeHtmlGenerators' : 'normalizeLinkDeclarations'](value, SESSION, TOKEN, evidence().row);
  const invalid = kind === 'html' ? /^Invalid retained HTML-generator response$/ : /^Invalid retained Link-declaration response$/;
  const acquisition = [...AUTHORITATIVE, 'inactive_session', ...NONIDENTITY[kind]];
  for (const reason of acquisition) test(`${kind} acquisition reason ${reason} is status-bound while legacy unavailable remains valid`, () => {
    const value = missing(kind, reason); value.status = 'unavailable';
    assert.equal(normalize(value).status, 'unavailable');
    value.status = 'unsupported';
    if (SUPPLEMENT_UNSUPPORTED[kind].includes(reason)) assert.equal(normalize(value).status, 'unsupported');
    else assert.throws(() => normalize(value), { message: invalid });
    const scanned = successful(kind); scanned.complete = false; scanned.reasons = [reason];
    assert.throws(() => normalize(scanned), { message: invalid });
  });
  for (const reason of ['PRIVATE_CONTENT_SENTINEL', ...(kind === 'html' ? SUPPLEMENT_UNSUPPORTED.link : SUPPLEMENT_UNSUPPORTED.html)]) {
    for (const status of ['unavailable', 'unsupported', 'scanned']) test(`${kind} rejects ${status} with an unknown or cross-family reason ${reason}`, () => {
      const value = missing(kind, reason); value.status = status;
      assert.throws(() => normalize(value), { message: invalid });
    });
  }
  for (const status of ['partial', 'UNSUPPORTED', 'unknown']) test(`${kind} rejects an unknown non-scanned status ${status}`, () => {
    const value = missing(kind, SUPPLEMENT_UNSUPPORTED[kind][0]); value.status = status;
    assert.throws(() => normalize(value), { message: invalid });
  });
  for (const reason of [...AUTHORITATIVE, 'inactive_session', 'PRIVATE_CONTENT_SENTINEL']) for (const overlayKind of ['body', 'link', 'peer']) {
    test(`${kind} malformed unsupported ${reason} preserves verified source and ${overlayKind} overlay without echo or extra reads`, async () => {
      const f = await verified(); await show(f, overlayKind);
      const row = f.state.evidence, peer = f.state.socketPeer, snapshotBefore = f.state.snapshot, overlay = f.state.bodyReferenceOverlay;
      const count = f.requests.length, value = missing(kind, reason); value.status = 'unsupported';
      let jsonReads = 0;
      const { task, request } = begin(f, kind);
      request.resolve({ ok: true, json: async () => { jsonReads++; return value; } });
      assert.equal(await task, false);
      await new Promise(resolve => setImmediate(resolve));
      assert.equal(f.requests.length, count + 1, 'only the explicit inspection read; no retry or fallback');
      assert.equal(jsonReads, 1);
      assert.equal(f.state.evidence, row); assert.equal(f.state.evidenceId, TOKEN); assert.equal(f.state.socketPeer, peer);
      assert.equal(f.state.snapshot, snapshotBefore); assert.equal(f.state.bodyReferenceOverlay, overlay); assert.equal(f.state.inactiveSessionId, null);
      assert.equal(f.state[kind === 'html' ? 'htmlGenerators' : 'linkDeclarations'], null);
      assert.equal(f.state[kind === 'html' ? 'htmlGeneratorsError' : 'linkDeclarationsError'], SUPPLEMENT_ERRORS[kind]);
      assert.match(f.els.detail.innerHTML, /Capture info/);
      assert.ok(f.els.detail.innerHTML.includes(SUPPLEMENT_ERRORS[kind]));
      assert.ok(!f.els.detail.innerHTML.includes(reason));
      assert.doesNotMatch(f.els.detail.innerHTML, /PRIVATE_CONTENT_SENTINEL|PRIVATE_TOKEN|Source unavailable|session must be active/);
    });
  }
}
for (const kind of KINDS) for (const reason of NONIDENTITY[kind]) test(`${kind} ${reason} preserves ordinary metadata and existing overlay`, async () => {
  const f = await verified(); await show(f); const overlay = f.state.bodyReferenceOverlay, row = f.state.evidence;
  await inspect(f, kind, missing(kind, reason));
  assert.equal(f.state.evidence, row); assert.equal(f.state.bodyReferenceOverlay, overlay); assert.equal(f.state.inactiveSessionId, null);
  assert.match(f.els.detail.innerHTML, /Capture info/);
});
for (const kind of KINDS) for (const failure of ['HTTP 400', 'HTTP 404', 'network', 'JSON', 'malformed envelope']) test(`${kind} generic ${failure} does not disprove verified source`, async () => {
  const f = await verified(); await show(f); const overlay = f.state.bodyReferenceOverlay, row = f.state.evidence;
  const { task, request } = begin(f, kind);
  if (failure.startsWith('HTTP')) request.resolve({ ok: false, status: Number(failure.slice(5)), json: async () => missing(kind, 'invalid_evidence_id') });
  else if (failure === 'network') request.reject(new Error('Synthetic transport failure'));
  else if (failure === 'JSON') request.resolve({ ok: true, json: async () => { throw new Error('Synthetic JSON failure'); } });
  else request.resolve(result({ ...missing(kind, 'record_missing'), evidence_id: SECOND_TOKEN }));
  assert.equal(await task, false); assert.equal(f.state.evidence, row); assert.equal(f.state.bodyReferenceOverlay, overlay); assert.equal(f.state.inactiveSessionId, null);
});
for (const kind of KINDS) for (const stage of ['response', 'JSON', 'failure']) test(`${kind} late source-A ${stage} cannot clear newly verified B with same origin/UUID/path`, async () => {
  const f = fixture(), value = snapshot(); value.origins[0].endpoints[0].evidence.push(SECOND_TOKEN);
  await f.load(value); await f.verify(); await show(f);
  const { task, request } = begin(f, kind), parsed = pending();
  if (stage === 'JSON') { request.resolve({ ok: true, json: () => parsed.promise }); await Promise.resolve(); }
  await f.verify(SECOND_TOKEN, SOURCE); const row = f.state.evidence, overlay = f.state.bodyReferenceOverlay;
  if (stage === 'failure') request.reject(new Error('Synthetic late failure'));
  else if (stage === 'JSON') parsed.resolve(missing(kind, 'session_source_changed'));
  else request.resolve(result(missing(kind, 'record_missing')));
  assert.equal(await task, false); assert.equal(f.state.evidence, row); assert.equal(f.state.bodyReferenceOverlay, overlay); assert.equal(f.state.inactiveSessionId, null);
});
for (const first of KINDS) for (const sibling of KINDS.filter(kind => kind !== first && !(['body', 'link'].includes(first) && ['body', 'link'].includes(kind)))) {
  for (const reason of ['record_changed', 'inactive_session']) test(`${first} ${reason} fences pending same-source ${sibling}`, async () => {
    const f = await verified(); await show(f); const pendingSibling = begin(f, sibling), failure = begin(f, first);
    clickDetailTab(f, 'apis');
    failure.request.resolve(result(missing(first, reason))); assert.equal(await failure.task, true);
    assert.equal(f.state.detailTab, 'apis', 'failure preserves newer APIs navigation');
    assert.equal(pendingSibling.request.options.signal.aborted, true);
    pendingSibling.request.resolve(result(successful(sibling))); assert.equal(await pendingSibling.task, false);
    assert.equal(f.state.detailTab, 'apis', 'canceled sibling preserves newer APIs navigation');
    noSupplements(f); assert.equal(f.state.bodyReferenceOverlay, null);
    assert.equal(!!f.state.evidence, reason === 'inactive_session');
    clickDetailTab(f, 'evidence');
    assert.match(f.els.detail.innerHTML, reason === 'inactive_session' ? /session must be active/ : /The source row changed/);
    if (reason !== 'inactive_session') assert.doesNotMatch(f.els.detail.innerHTML, /Capture info/);
  });
}
for (const kind of KINDS) test(`${kind} inactive_session preserves ordinary verification and latches every active-only action`, async () => {
  const f = await verified(); await show(f); const row = f.state.evidence, peer = f.state.socketPeer;
  await inspect(f, kind, missing(kind, 'inactive_session'));
  assert.equal(f.state.evidence, row); assert.equal(f.state.socketPeer, peer); assert.equal(f.state.bodyReferenceOverlay, null); noSupplements(f);
  assert.match(f.els.detail.innerHTML, /Capture info/); await blocked(f);
  await f.verify(SECOND_TOKEN, OTHER); await blocked(f);
  await f.verify(); await blocked(f);
});
for (const boundary of ['poll', 'force refresh', 'generation', 'query', 'products', 'scope filter', 'scope event', 'disconnect/reconnect', 'hide/show']) test(`inactive eligibility survives ${boundary}`, async () => {
  const f = await verified(); await inspect(f, 'html', missing('html', 'inactive_session'));
  let value = snapshot(), token = TOKEN;
  if (boundary === 'poll') await f.load(value);
  if (boundary === 'force refresh') await f.load(value, true);
  if (boundary === 'generation') {
    value.snapshot.generation = NEW_GENERATION;
    for (const item of value.origins) item.endpoints[0].evidence = item.endpoints[0].evidence.map(id => id.replace(GENERATION, NEW_GENERATION));
    token = TOKEN.replace(GENERATION, NEW_GENERATION); await f.load(value);
  }
  if (boundary === 'query') { f.els.search.value = 'example'; f.els.search.dispatch('input'); }
  if (boundary === 'products') { f.controller.setProductFilter('product', 'nginx'); f.controller.setProductFilter('product', ''); }
  if (boundary === 'scope filter') { f.els.scope.dispatch('click'); f.requests.at(-1).resolve(result(value)); await new Promise(resolve => setImmediate(resolve)); }
  if (boundary === 'scope event') { const task = f.controller.scopeChanged({}, { scope_patterns: ['example.com'] }); f.requests.at(-1).resolve(result(value)); await task; }
  if (boundary === 'disconnect/reconnect') { f.setStreamReady(false); f.controller.disconnect(); f.setStreamReady(true); const task = f.controller.invalidate(); f.requests.at(-1).resolve(result(value)); await task; }
  if (boundary === 'hide/show') { f.controller.setVisible(false); f.controller.setVisible(true); }
  assert.equal(await f.verify(token), true); await blocked(f);
});
test('actual session reset, switch-away and switch-back release eligibility only with fresh verification', async () => {
  const f = await verified(); await inspect(f, 'peer', missing('peer', 'inactive_session'));
  f.setSession(ROW); f.controller.reset(); assert.equal(f.state.inactiveSessionId, null); assert.equal(f.state.evidence, null);
  f.setSession(SESSION); f.controller.reset(); await f.load();
  const count = f.requests.length; assert.equal(await f.controller.loadHtmlGenerators(), false); assert.equal(f.requests.length, count);
  await f.verify(); await inspect(f, 'html'); assert.equal(f.state.htmlGenerators.status, 'scanned');
  await inspect(f, 'html', missing('html', 'inactive_session')); f.controller.reset(); await f.load(); await f.verify(); await inspect(f, 'html');
});
for (const kind of KINDS) test(`pending map JSON after ${kind} authoritative failure never restores verified evidence or overlay`, async () => {
  const f = await verified(); await show(f); const parsed = pending(), mapRead = f.controller.refresh();
  f.requests.at(-1).resolve({ ok: true, json: () => parsed.promise }); await Promise.resolve();
  await inspect(f, kind, missing(kind, 'record_missing')); parsed.resolve(snapshot()); assert.equal(await mapRead, true);
  assert.equal(f.state.evidence, null); assert.equal(f.state.bodyReferenceOverlay, null); noSupplements(f);
  assert.doesNotMatch(f.els.detail.innerHTML, /Capture info/); assert.match(f.els.detail.innerHTML, /no longer retained/);
});
for (const ordinary of [true, false]) test(`inactive peer-bound ${ordinary ? 'ordinary' : 'peer-only'} source survives only independent default-map support`, async () => {
  const f = await verified(), groupOrigin = ordinary ? OTHER : MATCH;
  await inspect(f, 'peer', peerScan(TOKEN, SOURCE, groupOrigin)); assert.equal(f.controller.showPeerMatchesOnMap(), true);
  const task = f.controller.loadPeerEvidence(SECOND_TOKEN, groupOrigin); f.requests.at(-1).resolve(result(evidence(SECOND_TOKEN, groupOrigin))); assert.equal(await task, true);
  assert.ok(f.state.peerEvidenceBinding); await inspect(f, 'peer', missing('peer', 'inactive_session', SECOND_TOKEN));
  assert.equal(f.state.peerEvidenceBinding, null); assert.equal(f.state.bodyReferenceOverlay, null); assert.equal(!!f.state.evidence, ordinary); noSupplements(f);
  if (ordinary) await blocked(f); else assert.match(f.els.status.textContent, /session must be active/);
});
test('an exact row never inherits its origin products, whether its own were omitted or empty', async () => {
  for (const present of [false, true]) {
    const f = fixture(), metadata = snapshot();
    metadata.origins[0].first_seen = metadata.origins[0].last_seen = STARTED;
    metadata.origins[0].technology_observations = [{ product_id: 'nginx', name: 'nginx', catalog_category: 'web_server', header_name: 'server', source: 'response_header',
      strength: 'literal_declaration', reported_version: '1.26.2', version_status: 'reported', row_count: 1, first_seen: STARTED, last_seen: STARTED, evidence: [TOKEN] }];
    assert.equal(await f.load(metadata), true); f.controller.selectOrigin(SOURCE, 0);
    const task = f.controller.loadEvidence(TOKEN), payload = evidence(); if (present) payload.row.technology_observations = [];
    f.requests.at(-1).resolve(result(payload)); assert.equal(await task, true);
    assert.equal(f.state.evidence.technology_observations_present, present);
    assert.doesNotMatch(f.els.detail.innerHTML, /nginx|1\.26\.2|Header-reported technologies/, 'exact source never inherits its origin aggregate');
  }
});
test('production activation and external session changes use the existing workspace reset chain', () => {
  const { loadFunctions } = require('./frontend-test-helpers.cjs');
  const app = loadFunctions(['activateSessionById', 'handleExternalSessionChanged', 'reloadSessionWorkspace', 'resetSessionScopedUiState']);
  assert.match(String(app.activateSessionById), /await reloadSessionWorkspace\(/);
  assert.match(String(app.handleExternalSessionChanged), /await reloadSessionWorkspace\(/);
  assert.match(String(app.reloadSessionWorkspace), /resetSessionScopedUiState\(\)/);
  assert.match(String(app.resetSessionScopedUiState), /targetServiceMapController\?\.reset\(\)/);
});
for (const kind of KINDS) test(`${kind} bounded partial inspection preserves earlier shown provenance`, async () => {
  const f = await verified(); await show(f); const row = f.state.evidence, overlay = f.state.bodyReferenceOverlay, value = successful(kind);
  value.complete = false;
  if (kind === 'body') { value.status = 'partial'; value.capture_preview_truncated = true; value.reasons = ['capture_preview_truncated']; }
  if (kind === 'link') value.reasons = ['malformed_field'];
  if (kind === 'html') { value.capture_preview_truncated = true; value.reasons = ['capture_preview_truncated']; }
  if (kind === 'peer') { value.reasons = ['invalid_metadata']; value.counts.invalid_metadata_rows = 1; value.snapshot.considered_rows = value.snapshot.retained_rows = 3;
    value.snapshot.latest_considered_sequence = String(BigInt(SEQUENCE) + 2n); }
  await inspect(f, kind, value); assert.equal(f.state.evidence, row); assert.equal(f.state.bodyReferenceOverlay, overlay); assert.equal(f.state.inactiveSessionId, null);
});
test('scope-excluded peer seed preserves metadata and an unrelated shown overlay', async () => {
  const f = fixture(); f.els.scope.dispatch('click'); f.requests.at(-1).resolve(result(snapshot())); await new Promise(resolve => setImmediate(resolve));
  await f.verify(); await show(f); const overlay = f.state.bodyReferenceOverlay;
  await f.verify(SECOND_TOKEN, OTHER); const row = f.state.evidence, value = missing('peer', 'source_out_of_scope', SECOND_TOKEN); value.in_scope_only = true;
  await inspect(f, 'peer', value); assert.equal(f.state.evidence, row); assert.equal(f.state.bodyReferenceOverlay, overlay);
});
for (const reason of AUTHORITATIVE) test(`${reason} does not clear overlay from a different session even with equal token text`, async () => {
  const f = await verified(); await show(f); const overlay = f.state.bodyReferenceOverlay;
  f.state.relationLayers = Object.freeze([Object.freeze({ ...overlay, source: Object.freeze({ ...overlay.source, sessionId: ROW }) })]);
  const foreign = f.state.bodyReferenceOverlay;
  await inspect(f, 'html', missing('html', reason)); assert.equal(f.state.evidence, null); assert.equal(f.state.bodyReferenceOverlay, foreign);
});
for (const kind of KINDS) for (const reason of [...AUTHORITATIVE, 'inactive_session']) test(`pending ${kind}/${reason} keeps newer APIs tab selection`, async () => {
  const f = await verified(); await show(f); const row = f.state.evidence;
  const { task, request } = begin(f, kind); clickDetailTab(f, 'apis');
  const readCount = f.requests.length;
  request.resolve(result(missing(kind, reason))); assert.equal(await task, true);
  assert.equal(f.state.detailTab, 'apis');
  assert.match(f.els.detail.innerHTML, /id="serviceMapDetailApisTab"[^>]*aria-selected="true"/);
  assert.match(f.els.detail.innerHTML, /class="service-map-api-list"/);
  assert.doesNotMatch(f.els.detail.innerHTML, /Capture info/);
  assert.equal(f.state.bodyReferenceOverlay, null); noSupplements(f);
  if (reason === 'inactive_session') {
    assert.equal(f.state.evidence, row); assert.match(f.els.status.textContent, /session must be active/);
  } else {
    assert.equal(f.state.evidence, null); assert.match(f.state.evidenceError, /Source unavailable/);
  }
  clickDetailTab(f, 'evidence');
  if (reason === 'inactive_session') {
    assert.match(f.els.detail.innerHTML, /session must be active/); assert.match(f.els.detail.innerHTML, /Capture info/);
    await blocked(f);
  } else {
    const messages = { invalid_evidence_id: /Source verification unavailable for this evidence token; verify again\./,
      session_mismatch: /Source session does not match; verify again\./, stale_generation: /Retained history changed; verify again\./,
      record_missing: /The source row is no longer retained\./, record_changed: /The source row changed\./,
      session_source_changed: /Session context changed; verify again\./ };
    assert.match(f.els.detail.innerHTML, messages[reason]); assert.doesNotMatch(f.els.detail.innerHTML, /Capture info/);
  }
  assert.equal(f.requests.length, readCount, 'response and tab navigation add no reads');
});

for (const endpoint of [false, true]) for (const shown of [false, true]) for (const mismatch of ['sequence', 'record_id']) {
  test(`exact evidence rejects mismatched ${mismatch}, endpoint=${endpoint}, shown=${shown}`, async () => {
    const f = fixture(); await f.load(); await f.verify();
    if (shown) await show(f);
    f.controller.selectOrigin(SOURCE, endpoint ? 0 : null);
    const payload = evidence();
    payload.row[mismatch] = mismatch === 'sequence' ? '9007199254740994' : NEW_GENERATION;
    const task = f.controller.loadEvidence(TOKEN);
    f.requests.at(-1).resolve(result(payload));
    assert.equal(await task, false);
    assert.equal(f.state.evidence, null);
    assert.equal(f.state.socketPeer, null);
    assert.equal(f.state.bodyReferenceOverlay, null);
    assert.doesNotMatch(f.els.detail.innerHTML, /Exact retained source verified|Capture info/);
    assert.match(f.els.detail.innerHTML, /Source unavailable/);
    const count = f.requests.length;
    assert.equal(await f.controller.loadBodyReferences(), false);
    assert.equal(f.requests.length, count, 'unverified source cannot initiate a body read');
  });
}

for (const [label, mutate] of [
  ['another session', fields => { fields[1] = NEW_GENERATION; }],
  ['another generation', fields => { fields[2] = NEW_GENERATION; }],
  ['noncanonical sequence', fields => { fields[3] = '0' + fields[3]; }],
  ['invalid revision', fields => { fields[4] = 'invalid'; }],
]) test(`exact source rejects versioned evidence with ${label}`, async () => {
  const fields = TOKEN.split('.'); mutate(fields); const id = fields.join('.');
  const f = fixture(); await f.load(snapshot([origin(SOURCE, id)]));
  assert.equal(await f.verify(id), false);
  assert.equal(f.state.evidence, null);
  assert.doesNotMatch(f.els.detail.innerHTML, /Capture info/);
});

test('identity mismatch clears only the affected shown source', async () => {
  const f = fixture(); await f.load(); await f.verify(); await show(f);
  const original = f.state.bodyReferenceOverlay;
  await f.verify(SECOND_TOKEN, OTHER); await show(f, 'body', SECOND_TOKEN, OTHER);
  f.controller.selectOrigin(OTHER);
  const payload = evidence(SECOND_TOKEN, OTHER); payload.row.record_id = NEW_GENERATION;
  const task = f.controller.loadEvidence(SECOND_TOKEN); f.requests.at(-1).resolve(result(payload));
  assert.equal(await task, false);
  assert.equal(f.state.relationLayers.length, 1);
  assert.equal(f.state.relationLayers[0], original);
  const count = f.requests.length;
  for (const load of ['loadBodyReferences', 'loadLinkDeclarations', 'loadHtmlGenerators', 'loadPeerMatches']) {
    assert.equal(await f.controller[load](), false);
  }
  assert.equal(f.requests.length, count);
});

test('exact source preserves uint64 precision through maximum sequence', async () => {
  const sequence = '18446744073709551615', id = TOKEN.replace(SEQUENCE, sequence);
  const f = fixture(); await f.load(snapshot([origin(SOURCE, id)]));
  assert.equal(await f.verify(id), true);
  assert.equal(f.state.evidence.sequence, sequence);
  assert.match(f.els.detail.innerHTML, /Capture info/);
});
