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
  row: { evidence_id: id, sequence: id.split('.')[3], record_id: id.split('.')[5], origin, started_at: START, method: 'GET', path: '/source', status: 200, metadata_complete: true, omitted: [] } }; }
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


function linkScan(members = [{ target: OTHER, relations: ['service-doc'] }], token = TOKEN, id = SOURCE, sequence = SEQUENCE) {
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
    reasons: [], source_origin: id, source_sequence: sequence, source_started_at: START, source_method: 'GET', source_status: 200,
    retained_header_count: members.length, coverage: 'absolute_http_link_declarations', offset_basis: 'retained_header_value_utf8',
    counts: { headers_inspected: members.length, header_bytes_admitted: bytes, link_fields_inspected: members.length, candidates_inspected: members.length,
      members_framed: members.length, parameters_inspected: members.length, relation_tokens_inspected: tokens, unknown_relation_tokens_inspected: 0 },
    observations, limits: { ...map.LINK_DECLARATION_LIMITS } };
}
const UUID_B = '66666666-6666-4666-8666-666666666666';
const UUID_C = '77777777-7777-4777-8777-777777777777';
const B = token(SEQUENCE + 1n).replace(ROW, UUID_B), C = token(SEQUENCE + 2n).replace(ROW, UUID_C);
function bodyScan(id = TOKEN, origin = SOURCE, targets = [OTHER]) {
  return { schema_version: 1, session_id: SESSION, evidence_id: id, available: true, status: 'scanned', complete: true, reasons: [], source_origin: origin,
    source_sequence: id.split('.')[3], source_started_at: START, retained_preview_bytes: 2000, scanned_bytes: 2000, capture_preview_truncated: false,
    scan_prefix_truncated: false, candidates_scanned: targets.length, omitted_reference_occurrences: 0,
    references: targets.map((target_origin, i) => ({ target_origin, occurrences: 1, preview_byte_offsets: [20 + i], omitted_offsets: 0 })),
    limits: { ...map.BODY_REFERENCE_LIMITS }, coverage: 'literal_absolute_http_urls', offset_basis: 'retained_utf8_preview' };
}
function sourceSnapshot() { const value = snapshot(); value.origins = [normalOrigin(SOURCE), normalOrigin(OTHER, B), normalOrigin(MATCH, C)]; return value; }
async function showBody(f, id = TOKEN, origin = SOURCE, targets = [OTHER]) {
  assert.equal(await f.verify(id, origin), true); f.controller.setRelationshipKind('body');
  const task = f.controller.loadBodyReferences(); f.requests.at(-1).resolve(response(bodyScan(id, origin, targets))); assert.equal(await task, true);
  return f.controller.showBodyReferencesOnMap();
}
async function showLink(f, id = B, origin = OTHER, targets = [MATCH]) {
  assert.equal(await f.verify(id, origin), true); f.controller.setRelationshipKind('link');
  const task = f.controller.loadLinkDeclarations(); f.requests.at(-1).resolve(response(linkScan(targets.map(target => ({ target })), id, origin, id.split('.')[3]))); assert.equal(await task, true);
  return f.controller.showLinkDeclarationsOnMap();
}
function peerScan(id = TOKEN, origin = SOURCE, samples = [{ id: B, origin: OTHER }], ip = '192.0.2.10', port = 443) {
  const value = matches(samples.length), seq = id.split('.')[3]; value.evidence_id = id;
  value.source = { ...value.source, evidence_id: id, sequence: seq, origin };
  value.peer.address.ip = ip; value.peer.address.port = port; value.peer.address_family = ip.includes(':') ? 'ipv6' : 'ipv4';
  value.origins = samples.map(sample => ({ origin: sample.origin, in_scope: true, matching_rows: 1, first_observed_at: TIME, last_observed_at: TIME,
    samples: [{ evidence_id: sample.id, sequence: sample.id.split('.')[3], started_at: START, observed_at: TIME }], omitted_samples: 0 })).sort((a,b) => a.origin.localeCompare(b.origin));
  const seqs = [BigInt(seq), ...samples.map(item => BigInt(item.id.split('.')[3]))].sort((a,b) => a < b ? -1 : a > b ? 1 : 0);
  value.snapshot.oldest_considered_sequence = String(seqs[0]); value.snapshot.latest_considered_sequence = String(seqs.at(-1)); return value;
}
async function showPeer(f, id = TOKEN, origin = SOURCE, samples, ip, port = 443) {
  assert.equal(await f.verify(id, origin, evidence(id, origin, observation(ip, 'direct', port))), true);
  const task = f.controller.loadPeerMatches(); f.requests.at(-1).resolve(response(peerScan(id, origin, samples, ip, port))); assert.equal(await task, true);
  return f.controller.showPeerMatchesOnMap();
}
function remove(f, layer) { const button = { dataset: { serviceRemoveInspection: `${layer.kind}:${layer.source.evidenceId}` } }; f.els.panel.dispatch('click', { target: { closest: () => button } }); }
const paths = f => [...f.els.canvas.innerHTML.matchAll(/<path class="service-map-edge[^]*?<\/path>/g)].map(item => item[0]);
const nodes = f => [...f.els.canvas.innerHTML.matchAll(/class="service-map-card /g)].length;
const event = id => ({ data: JSON.stringify({ id, sequence: 9007199254740993, kind: 'http', header_search_text: 'PRIVATE_EVENT_SECRET' }) });

test('body, Link, metadata and peer evidence coexist across sources with independent provenance and no extra reads', async () => {
  const f = fixture(), value = sourceSnapshot(); value.origins[0].redirects = [{ target_origin: MATCH, target_path: '/next', relationship: 'redirect_instruction', evidence: [TOKEN] }];
  await f.load(value); assert.equal(await showBody(f), true); assert.equal(await showLink(f), true); assert.equal(await showPeer(f), true);
  assert.equal(f.state.relationLayers.length, 3); assert.equal(f.state.anchorOrigin, null);
  for (const type of ['body_url_reference','link_service_doc','recorded_peer_observation','redirect_instruction']) assert.match(f.els.canvas.innerHTML, new RegExp(`data-relationship="${type}"`));
  for (const spoke of paths(f).filter(item => item.includes('recorded_peer_observation'))) assert.doesNotMatch(spoke, /marker-end/);
  assert.match(f.els.overlayStatus.innerHTML, /3 \/ 8/); assert.match(f.els.overlayStatus.innerHTML, /2026-10-12/);
  assert.doesNotMatch(JSON.stringify(f.state.relationLayers) + f.els.canvas.innerHTML + f.els.overlayStatus.innerHTML, /PRIVATE_TOKEN|private-path|private-query|PRIVATE_EVENT_SECRET/);
  const count = f.requests.length, layers = f.state.relationLayers;
  f.controller.selectOrigin(MATCH); f.els.allOrigins.dispatch('click'); f.els.directRelations.dispatch('click'); f.els.focusSelection.dispatch('click');
  f.els.search.value = 'match'; f.els.search.dispatch('input'); f.controller.setZoom(0.7); f.controller.fitGraph(); f.controller.setProductFilter('product', 'nginx');
  assert.equal(f.state.relationLayers, layers); assert.equal(f.requests.length, count);
  remove(f, layers[1]); assert.equal(f.state.relationLayers.length, 2); assert.equal(f.requests.length, count); assert.equal(f.state.relationLayers[0], layers[0]);
});

test('same typed edge keeps independent source provenance when one inspection is removed', async () => {
  const f = fixture(), value = sourceSnapshot(); value.origins[0].endpoints[0].evidence.push(B); await f.load(value);
  assert.equal(await showBody(f, TOKEN, SOURCE, [MATCH]), true); assert.equal(await showBody(f, B, SOURCE, [MATCH]), true);
  assert.equal(paths(f).filter(path => path.includes('body_url_reference')).length, 1); assert.match(f.els.canvas.innerHTML, /2 inspected sources/);
  const count = f.requests.length, first = f.state.relationLayers[0], second = f.state.relationLayers[1]; remove(f, first);
  assert.equal(paths(f).filter(path => path.includes('body_url_reference')).length, 1); assert.match(f.els.canvas.innerHTML, /1 inspected source(?!s)/);
  assert.equal(f.state.relationLayers[0], second); assert.equal(f.requests.length, count); assert.doesNotMatch(f.els.overlayStatus.innerHTML, new RegExp(TOKEN.replaceAll('.', '\\.')));
});

test('eight-entry limit is explicit; duplicate Show updates in place without eviction or extra reads', async () => {
  const f = fixture(), value = sourceSnapshot(); const ids = Array.from({ length: 9 }, (_,i) => token(SEQUENCE + BigInt(i + 10)));
  value.origins[0].endpoints[0].evidence = ids; await f.load(value);
  for (const id of ids.slice(0,8)) assert.equal(await showBody(f,id,SOURCE,[MATCH]),true);
  const before = [...f.state.relationLayers]; assert.equal(await showBody(f,ids[8],SOURCE,[OTHER]),false);
  assert.equal(f.state.relationLayers.length,8); assert.ok(f.state.relationLayers.every((item,i) => item === before[i])); assert.match(f.els.overlayStatus.innerHTML,/limit 8 reached.*nothing was replaced/);
  assert.equal(await showBody(f,ids[2],SOURCE,[OTHER]),true); assert.equal(f.state.relationLayers.length,8); assert.notEqual(f.state.relationLayers[2],before[2]);
  assert.equal(f.state.relationLayers[0],before[0]); assert.equal(f.state.relationLayers[7],before[7]);
  const reads=f.requests.length; remove(f,f.state.relationLayers[2]); assert.equal(f.state.relationLayers.length,7); assert.equal(f.requests.length,reads);
});

test('unrelated validated UUID preserves body/Link, removes peer aggregates, and never retains event headers', async () => {
  const f=fixture(), value=sourceSnapshot(); await f.load(value); await showBody(f); await showLink(f); await showPeer(f);
  const [body,link]=f.state.relationLayers, reads=f.requests.length; f.controller.markDirty(event(UUID_C));
  assert.equal(f.state.relationLayers.length,2); assert.equal(f.state.relationLayers[0],body); assert.equal(f.state.relationLayers[1],link);
  assert.equal(f.state.stale,true); assert.equal(f.requests.length,reads); assert.doesNotMatch(JSON.stringify(f.state),/PRIVATE_EVENT_SECRET/);
  await f.load(value); assert.equal(f.state.stale,false); assert.equal(f.state.relationLayers[0],body); assert.equal(f.state.relationLayers[1],link);
  f.controller.markDirty(event(UUID_B)); assert.equal(f.state.relationLayers.length,1); assert.equal(f.state.relationLayers[0],body);
  await f.load(value); assert.equal(f.state.relationLayers.length,1); f.controller.markDirty(event(ROW.toUpperCase())); assert.equal(f.state.relationLayers.length,0);
});

for(const eventData of [undefined,{data:'{'},{data:'null'},{data:'{"id":"ambiguous"}'},{data:'[]'}]) test(`unknown event ${eventData?.data} clears every collection entry`,async()=>{
  const f=fixture(); await f.load(sourceSnapshot()); await showBody(f); await showLink(f); const reads=f.requests.length; f.controller.markDirty(eventData);
  assert.equal(f.state.relationLayers.length,0); assert.equal(f.requests.length,reads);
});

test('exact revision/sample disappearance removes only affected retained reference sources and cannot restore them by later poll',async()=>{
  const f=fixture(),value=sourceSnapshot(); await f.load(value); await showBody(f); await showLink(f); const link=f.state.relationLayers[1];
  value.origins[0].endpoints[0].evidence=[TOKEN.replace(REVISION,UUID_C)]; await f.load(value);
  assert.equal(f.state.relationLayers.length,1); assert.equal(f.state.relationLayers[0],link); assert.match(f.els.overlayStatus.innerHTML,/no longer verified in the loaded projection/);
  await f.load(sourceSnapshot()); assert.equal(f.state.relationLayers.length,1);
});

for(const change of ['generation','scope','disconnect','hide','reload','session','gap']) test(`${change} retires all collection entries and cached peer identities`,async()=>{
  const f=fixture(); await f.load(sourceSnapshot()); await showBody(f); await showLink(f); await showPeer(f);
  if(change==='generation') await f.load({...sourceSnapshot(),snapshot:{...sourceSnapshot().snapshot,generation:UUID_B}});
  else if(change==='scope'){ f.els.scope.dispatch('click'); f.requests.at(-1).resolve(response(sourceSnapshot())); await Promise.resolve(); }
  else if(change==='disconnect') f.controller.disconnect();
  else if(change==='hide') f.controller.setVisible(false);
  else if(change==='reload') await f.load(sourceSnapshot(),true);
  else if(change==='session'){f.setSession(UUID_C);f.controller.reset();}
  else {const task=f.controller.invalidate();f.requests.at(-1).resolve(response(sourceSnapshot()));await task;}
  assert.equal(f.state.relationLayers.length,0); assert.equal(f.state.peerUnavailableTokens.size,0); assert.equal(f.state.peerProjection,null);
});

test('canonical shared address merges spokes without summing overlapping peer-window totals',async()=>{
  const f=fixture(); await f.load(sourceSnapshot()); await showPeer(f); const first=f.state.relationLayers[0]; await showPeer(f,B,OTHER,[{id:TOKEN,origin:SOURCE}]);
  const second=f.state.relationLayers[1]; assert.equal(typeof first.source.mapKey,'object'); assert.equal(first.source.mapKey,second.source.mapKey); assert.deepEqual(Object.keys(first.source.mapKey),[]);
  assert.equal((f.els.canvas.innerHTML.match(/service-map-peer-address/g)||[]).length,1); assert.equal(paths(f).filter(path=>path.includes('recorded_peer_observation')).length,2);
  f.controller.selectOrigin(SOURCE); assert.equal((f.els.detail.innerHTML.match(/other matching rows</g)||[]).length,2); assert.doesNotMatch(f.els.detail.innerHTML,/2 other matching rows</);
  remove(f,first); assert.equal(paths(f).filter(path=>path.includes('recorded_peer_observation')).length,2); assert.equal(f.state.relationLayers[0],second);
  f.controller.clearBodyReferenceOverlay(); assert.equal(f.state.peerProjection,null);
});

test('different ports and address families remain distinct nodes and never create origin-to-origin peer arrows',async()=>{
  const f=fixture(); await f.load(sourceSnapshot()); await showPeer(f,TOKEN,SOURCE,[]); await showPeer(f,B,OTHER,[], '192.0.2.10',8443); await showPeer(f,C,MATCH,[],'::ffff:192.0.2.10');
  assert.equal((f.els.canvas.innerHTML.match(/service-map-peer-address/g)||[]).length,3); assert.match(f.els.canvas.innerHTML,/192\.0\.2\.10:8443/); assert.match(f.els.canvas.innerHTML,/\[::ffff:192\.0\.2\.10\]:443/);
  for(const path of paths(f)) assert.doesNotMatch(path,/marker-end/);
});

test('unavailable overlapping sample removes every inspection seeded by that token and bounds disabled sample state',async()=>{
  const f=fixture(); await f.load(sourceSnapshot()); await showPeer(f); await showPeer(f,B,OTHER,[{id:TOKEN,origin:SOURCE}]); await showBody(f,B,OTHER,[MATCH]); await showLink(f,B,OTHER,[MATCH]);
  assert.equal(f.state.relationLayers.length,4); const task=f.controller.loadPeerEvidence(B,OTHER); f.requests.at(-1).resolve(response({...evidence(B,OTHER),available:false,row:null})); assert.equal(await task,false);
  assert.equal(f.state.relationLayers.length,1); assert.equal(f.state.relationLayers[0].source.evidenceId,TOKEN); assert.equal(f.state.peerUnavailableTokens.size,1);
  f.controller.reset(); assert.equal(f.state.relationLayers.length,0); assert.equal(f.state.peerUnavailableTokens.size,0); assert.equal(f.state.peerProjection,null);
});

test('direct peer address remains incident to filtered pinned context with no new reads',async()=>{
  const f=fixture(); await f.load(sourceSnapshot()); await showPeer(f); f.controller.selectOrigin(SOURCE); f.els.directRelations.dispatch('click'); const reads=f.requests.length;
  assert.equal(nodes(f),2); assert.equal(paths(f).length,1); f.els.search.value='unmatched';f.els.search.dispatch('input');f.controller.setProductFilter('product','nginx');
  assert.equal(nodes(f),2); assert.equal(paths(f).length,1); assert.match(f.els.graphBounds.textContent,/1 \/ 1 known direct neighbors shown/); assert.equal(f.requests.length,reads);
});

test('removing an inspection fences its delayed peer source read without affecting other entries',async()=>{
  const f=fixture();await f.load(sourceSnapshot());await showBody(f);await showPeer(f);const body=f.state.relationLayers[0],peer=f.state.relationLayers[1];
  const task=f.controller.loadPeerEvidence(B,OTHER), request=f.requests.at(-1);remove(f,peer);request.resolve(response(evidence(B,OTHER)));assert.equal(await task,false);
  assert.equal(f.state.relationLayers.length,1);assert.equal(f.state.relationLayers[0],body);assert.equal(f.state.evidence,null);
});

test('shared display caps are deterministic and source coverage stays separate from graph omissions',async()=>{
  const f=fixture(); await f.load(sourceSnapshot());await showBody(f,TOKEN,SOURCE,Array.from({length:100},(_,i)=>`https://body-${String(i).padStart(3,'0')}.example.com`));await showLink(f,B,OTHER,Array.from({length:32},(_,i)=>`https://link-${String(i).padStart(3,'0')}.example.com`));await showPeer(f);
  assert.equal(nodes(f),24);assert.ok(paths(f).length<=40);const canvas=f.els.canvas.innerHTML,reads=f.requests.length;f.controller.displayChanged();assert.equal(f.els.canvas.innerHTML,canvas);assert.equal(f.requests.length,reads);
  assert.match(f.els.graphBounds.textContent,/nodes omitted by 24-card cap/);assert.match(f.els.graphBounds.textContent,/inspected links outside displayed cards/);
  assert.match(f.els.overlayStatus.innerHTML,/Complete.*inspection/);assert.equal(f.state.relationLayers.length,3);
});

for (const mixed of [false, true]) test(`hidden pinned origin keeps accurate ${mixed ? 'mixed collection' : 'peer'} counts and reversible Show`, async () => {
  const f = fixture(); await f.load(sourceSnapshot());
  if (mixed) await showBody(f);
  await showPeer(f); f.controller.selectOrigin(SOURCE); f.els.directRelations.dispatch('click');
  f.els.search.value = 'unmatched'; f.els.search.dispatch('input'); f.controller.setProductFilter('product', 'nginx');
  const layers = f.state.relationLayers, reads = f.requests.length;
  const click = dataset => f.els.panel.dispatch('click', { target: { closest: () => ({ dataset }) } });
  click({ serviceHide: SOURCE });
  assert.equal(nodes(f), 1); assert.equal(paths(f).length, 0);
  assert.doesNotMatch(f.els.canvas.innerHTML, /data-service-origin="https:\/\/source.example.com"/);
  assert.match(f.els.graphBounds.textContent, new RegExp(`1 / ${mixed ? 2 : 1} known direct neighbors shown`));
  assert.match(f.els.graphBounds.textContent, /Pinned anchor is hidden/);
  assert.doesNotMatch(f.els.graphBounds.textContent, /remains visible/);
  assert.equal(f.state.anchorOrigin, SOURCE); assert.equal(f.state.selectedOrigin, SOURCE); assert.equal(f.state.relationLayers, layers);
  click({ serviceUnhide: SOURCE });
  assert.equal(nodes(f), 2); assert.equal(paths(f).length, 1);
  assert.match(f.els.graphBounds.textContent, /Pinned anchor is outside the search query and remains visible/);
  assert.doesNotMatch(f.els.graphBounds.textContent, /Pinned anchor is hidden/); assert.equal(f.requests.length, reads);
});
