// Synthetic passive metadata and inert DOM; no bootstrap or proxy actions.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../web/service-map.js'), 'utf8');
const resizeObservers = [];
const context = vm.createContext({ URL, URLSearchParams, AbortController, console, getComputedStyle: element => ({ getPropertyValue: name => element.style.values[name] || "" }), ResizeObserver: class { constructor(callback) { this.callback = callback; resizeObservers.push(this); } observe(element) { this.element = element; } } });
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
    value: '', checked: false, disabled: false, dataset: {}, attributes: {}, textContent: '', scrollTop: 0, scrollLeft: 0, clientWidth: 0, clientHeight: 0,
    style: { values: {}, setProperty(name, value) { this.values[name] = value; } },
    classList: { toggle(name, value) { if (value) classes.add(name); else classes.delete(name); }, contains: name => classes.has(name) },
    setAttribute(name, value) { this.attributes[name] = value; },
    addEventListener(name, callback) { handlers.set(name, callback); },
    dispatch(name, event = {}) { return handlers.get(name)?.({ target: this, ...event }); },
    contains: () => true, querySelectorAll: () => [],
    get innerHTML() { return html; }, set innerHTML(value) { html = value; replacements += 1; },
    get replacements() { return replacements; },
  };
}
function fixture(options = {}) {
  let session = 'session-one';
  const requests = [];
  const els = Object.fromEntries(['panel', 'apiDocs', 'status', 'refresh', 'search', 'scope', 'canvas', 'graphBounds', 'detail', 'content', 'catalog', 'mapControls', 'allOrigins', 'directRelations', 'flow', 'flowMermaid', 'linkKinds', 'focusSelection', 'boundsDetails', 'graphDiagnostics', 'overlayStatus', 'viewport', 'zoomControls', 'zoomFit', 'zoomOut', 'zoomReset', 'zoomIn'].map(name => [name, node()]));
  els.viewport.clientWidth = 620; els.viewport.clientHeight = 500;
  const document = { activeElement: null, body: {}, documentElement: node(), querySelector: () => null };
  document.documentElement.style.setProperty("--ui-root-size", "12px");
  // Opening an endpoint reads its parameters; these tests are about the other
  // reads, so that one is kept apart and left pending.
  const parameterRequests = [];
  const controller = map.createController({ elements: els, getSessionId: () => session, document, request(url, options) { const pending = deferred(); (url.startsWith('/api/target/service-map/parameters?') ? parameterRequests : requests).push({ url, options, ...pending }); return pending.promise; }, ...options });
  controller.setVisible(true);
  return { controller, els, requests, parameterRequests, document, state: controller.getState(), setSession(value) { session = value; }, async load(payload = snapshot()) { const pending = controller.refresh(); requests.at(-1).resolve(response(payload)); await pending; } };
}

test('every map toolbar control uses the standard compact toolbar sizing, and Reload a fixed label', () => {
  const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
  assert.match(html, /<button class="secondary-action service-map-reload" id="serviceMapRefresh"[^>]*>Reload<\/button>/);
  assert.match(html, /<button class="scope-pill" id="serviceMapScopeOnly" type="button" aria-pressed="false"[^>]*>In scope<\/button>/);
  assert.ok(html.indexOf('id="serviceMapSearch"') < html.indexOf('id="serviceMapScopeOnly"') && html.indexOf('id="serviceMapScopeOnly"') < html.indexOf('id="serviceMapFilterButton"'), 'search, scope and filter sit together, as in HTTP history');
  const [, selectors, compact] = css.match(/\.service-map-toolbar :is\(([^)]+)\) \{([^}]+)\}/) || [];
  const standard = css.match(/\.toolbar-actions \.secondary-action \{([^}]+)\}/)?.[1];
  assert.ok(compact); assert.ok(standard);
  for (const control of ['.secondary-action', '.scope-pill', '.service-map-mode', '.service-map-search', '.service-map-product-filters > summary']) assert.ok(selectors.split(', ').includes(control), control);
  for (const declaration of ['min-height: var(--control-h);', 'padding: 4px 14px;', 'font-size: var(--font-xs);', 'border-radius: 6px;']) {
    assert.ok(compact.includes(declaration)); assert.ok(standard.includes(declaration));
  }
  const reload = css.match(/\.service-map-reload \{([^}]+)\}/)?.[1];
  assert.match(reload, /flex: 0 0 auto;/); assert.match(reload, /white-space: nowrap;/);
  assert.match(css, /\.service-map-reload\.service-map-background-refresh:disabled \{[^}]*opacity: 1;/);
});
test('the map or the API list fills the workspace whichever siblings are hidden', () => {
  const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
  const workspace = css.match(/^\.service-map-workspace \{([^}]+)\}/m)?.[1];
  assert.match(workspace, /display: flex; flex-direction: column;/);
  assert.match(css, /^\.service-map-content, \.service-map-api-catalog \{ flex: 1; \}/m);
});
test('map is lazy: construction/hidden refresh cause no request', async () => {
  const f = fixture(); f.controller.setVisible(false); await f.controller.refresh();
  assert.equal(f.requests.length, 0); assert.equal(f.state.snapshot, null);
});
test('only passive local GET requests; map selection stays local and exact evidence uses opaque token', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA);
  assert.equal(f.requests.length, 1);
  const pending = f.controller.loadEvidence('evidence-one');
  assert.match(f.requests[1].url, /^\/api\/target\/service-map\/evidence\?/);
  assert.match(f.requests[1].url, /evidence_id=evidence-one/);
  assert.equal(f.requests[1].options.method, undefined);
  f.requests[1].resolve(response(evidence())); await pending;
  assert.equal(f.state.evidence.sequence, '9007199254740993');
  assert.match(f.els.detail.innerHTML, /Capture info/);
  assert.doesNotMatch(f.requests.map(request => request.url).join(' '), /\/api\/transactions\/|replay|scan|capture/);
});
test('selection survives endpoint insertion/reordering by case-sensitive method and exact path', async () => {
  const f = fixture(); await f.load(snapshot([origin(originA, [endpoint('/a'), endpoint('/z', 'get', 'z')])]));
  f.controller.selectOrigin(originA, 1);
  await f.load(snapshot([origin(originA, [endpoint('/new'), endpoint('/z', 'GET'), endpoint('/z', 'get', 'z'), endpoint('/a')])]));
  assert.equal(f.state.endpointIndex, 2);
  assert.match(f.els.detail.innerHTML, /<span>get <strong>\/z<\/strong><\/span>/);
  await f.load(snapshot([origin(originA, [endpoint('/new'), endpoint('/z', 'GET')])]));
  assert.equal(f.state.endpointIndex, null); assert.equal(f.state.evidence, null);
});
test('removed selected origin clears selection without selecting a neighbor', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originB);
  await f.load(snapshot([origin(originA)]));
  assert.equal(f.state.selectedOrigin, null); assert.match(f.els.detail.innerHTML, /Select an origin/);
});
test('newer map request wins even if older request ignores abort and finishes last', async () => {
  const f = fixture(); const a = f.controller.refresh(); const b = f.controller.refresh({ force: true });
  f.requests[1].resolve(response(snapshot([origin(originB)]))); await b;
  f.requests[0].resolve(response(snapshot([origin(originA)]))); await a;
  assert.equal(f.state.snapshot.origins[0].origin, originB);
});
test('late map JSON parse cannot resurrect old session data', async () => {
  const f = fixture(), parse = deferred(); const pending = f.controller.refresh();
  f.requests[0].resolve({ ok: true, json: () => parse.promise }); await Promise.resolve();
  f.setSession('session-two'); f.controller.reset();
  parse.resolve(snapshot()); await pending;
  assert.equal(f.state.snapshot, null); assert.equal(f.state.selectedOrigin, null);
  assert.doesNotMatch(f.els.canvas.innerHTML, /app\.example/);
});
test('removal/gap invalidation clears counts and evidence immediately, rejects old map response', async () => {
  const f = fixture(); await f.load(); const old = f.controller.refresh();
  const current = f.controller.invalidate();
  assert.equal(f.state.snapshot, null); assert.doesNotMatch(f.els.status.textContent, /4 rows considered/);
  f.requests[1].resolve(response(snapshot())); await old;
  assert.equal(f.state.snapshot, null);
  f.requests[2].resolve(response(snapshot([]))); await current;
  assert.equal(f.state.snapshot.origins.length, 0);
});
test('live changes label stale counts and clear verified evidence; next stable read clears stale status', async () => {
  const f = fixture(); await f.load();
  f.controller.markDirty(); assert.match(f.els.status.textContent, /previous snapshot/);
  const pending = f.controller.refresh(); f.controller.markDirty();
  f.requests.at(-1).resolve(response(snapshot())); await pending;
  assert.equal(f.state.stale, true);
  await f.load(); assert.equal(f.state.stale, false);
});
test('scope filter forces new read; old-filter responses cannot replace it', async () => {
  const f = fixture(); const old = f.controller.refresh();
  f.els.scope.dispatch('click');
  assert.match(f.requests.at(-1).url, /in_scope_only=true/);
  f.requests[1].resolve(response(snapshot([origin(originB)]))); await new Promise(resolve => setImmediate(resolve));
  f.requests[0].resolve(response(snapshot([origin(originA)]))); await old;
  assert.equal(f.state.snapshot.origins[0].origin, originB);
});
test('late evidence after origin selection/session transition is discarded', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA);
  const pending = f.controller.loadEvidence('evidence-one'); f.controller.selectOrigin(originB);
  f.requests.at(-1).resolve(response(evidence())); await pending; assert.equal(f.state.evidence, null);
  const second = f.controller.loadEvidence('evidence-one'); f.setSession('session-two'); f.controller.reset();
  f.requests.at(-1).resolve(response(evidence('evidence-one', originB))); await second;
  assert.equal(f.state.evidence, null);
});
for (const [name, change] of [
  ['wrong schema', value => { value.schema_version = 2; }],
  ['wrong envelope token', value => { value.evidence_id = 'other'; }],
  ['wrong row token', value => { value.row.evidence_id = 'other'; }],
  ['wrong origin', value => { value.row.origin = originB; }],
  ['wrong method', value => { value.row.method = 'POST'; }],
  ['wrong path', value => { value.row.path = '/other'; }],
  ['numeric sequence without exact decimal string', value => { value.row.sequence = 9007199254740993; }],
  ['wrong source type', value => { value.source = 'unverified'; }],
]) test(`evidence rejects ${name} without fallback to UUID detail`, async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA, 0);
  const pending = f.controller.loadEvidence('evidence-one'); const value = evidence(); change(value);
  f.requests.at(-1).resolve(response(value)); await pending;
  assert.equal(f.state.evidence, null); assert.match(f.els.detail.innerHTML, /Source unavailable/); assert.equal(f.requests.length, 2);
});
test('unavailable source is honest and repeated evidence clicks latest-win', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA);
  const a = f.controller.loadEvidence('evidence-one'), b = f.controller.loadEvidence('evidence-one');
  f.requests[2].resolve(response(evidence('evidence-one', originA, { available: false, row: null, reason: 'row_revision_changed' }))); await b;
  f.requests[1].resolve(response(evidence())); await a;
  assert.equal(f.state.evidence, null); assert.match(f.state.evidenceError, /Source unavailable/);
});
test('background refresh keeps Reload label and presentation stable while retaining its request guard', async () => {
  const f = fixture(); await f.load();
  const summary = f.els.status.textContent, canvasReplacements = f.els.canvas.replacements;
  for (let i = 0; i < 3; i += 1) {
    const pending = pollRealTargetMap(f);
    assert.equal(f.els.status.textContent, summary, 'polling must not add a line or move the graph');
    assert.doesNotMatch(f.els.status.textContent, /Reloading/);
    assert.equal(f.els.refresh.textContent, 'Reload');
    assert.equal(f.els.refresh.disabled, true); assert.equal(f.els.panel.attributes['aria-busy'], 'false');
    assert.equal(f.els.refresh.classList.contains('service-map-background-refresh'), true);
    assert.equal(f.els.refresh.classList.contains('is-working'), false);
    assert.equal(f.els.refresh.classList.contains('is-working-shown'), false, 'no ring while polling');
    assert.equal(f.els.canvas.replacements, canvasReplacements);
    f.requests.at(-1).resolve(response(snapshot())); await pending;
    assert.equal(f.els.status.textContent, summary);
    assert.equal(f.els.refresh.textContent, 'Reload');
    assert.equal(f.els.refresh.disabled, false); assert.equal(f.els.panel.attributes['aria-busy'], 'false');
  }
});
test('loaded empty map and catalog remain unchanged through background polls and local redraws', async () => {
  const f = fixture(); await f.load(snapshot([]));
  const canvas = f.els.canvas.innerHTML, catalog = f.els.catalog.innerHTML;
  const replacements = [f.els.canvas.replacements, f.els.catalog.replacements];
  for (let i = 0; i < 3; i++) {
    const task = pollRealTargetMap(f);
    f.controller.setVisible(true);
    assert.equal(f.els.canvas.innerHTML, canvas);
    assert.equal(f.els.catalog.innerHTML, catalog);
    assert.deepEqual([f.els.canvas.replacements, f.els.catalog.replacements], replacements);
    assert.equal(f.els.refresh.textContent, 'Reload');
    f.requests.at(-1).resolve(response(snapshot([]))); await task;
    assert.deepEqual([f.els.canvas.replacements, f.els.catalog.replacements], replacements);
  }
});
test('initial and manual Reload keep the label fixed, show busy state and resume automatic reads', async () => {
  const f = fixture(); const initial = f.controller.refresh();
  assert.equal(f.els.refresh.textContent, 'Reload');
  assert.equal(f.els.panel.attributes['aria-busy'], 'true');
  assert.equal(f.els.refresh.classList.contains('is-working'), true);
  f.requests.at(-1).resolve(response(snapshot())); await initial;
  const manual = f.els.refresh.dispatch('click');
  assert.equal(f.els.refresh.textContent, 'Reload');
  assert.equal(f.els.refresh.disabled, true);
  assert.equal(f.els.refresh.classList.contains('service-map-background-refresh'), false);
  assert.equal(f.els.refresh.classList.contains('is-working'), true);
  assert.equal(f.els.refresh.classList.contains('is-working-shown'), true, 'the ring turns in place of the label');
  assert.equal(f.els.panel.attributes['aria-busy'], 'true');
  assert.equal(await f.controller.refresh(), false);
  assert.equal(f.requests.length, 2);
  f.requests.at(-1).resolve(response(snapshot())); await manual;
  assert.equal(f.els.refresh.disabled, false);
  assert.equal(f.els.refresh.classList.contains('is-working'), false);
  assert.equal(f.els.refresh.classList.contains('is-working-shown'), false);
  assert.equal(f.els.panel.attributes['aria-busy'], 'false');
  await f.load(); assert.equal(f.requests.length, 3);
});
for (const outcome of ['resolve', 'reject']) test(`late background ${outcome} cannot change newer manual Reload presentation`, async () => {
  const f = fixture(); await f.load();
  const background = f.controller.refresh(), old = f.requests.at(-1);
  const manual = f.controller.refresh({ force: true, retry: true });
  if (outcome === 'resolve') old.resolve(response(snapshot()));
  else old.reject(new Error('Superseded background read'));
  await background;
  assert.equal(f.els.refresh.textContent, 'Reload');
  assert.equal(f.els.refresh.disabled, true);
  assert.equal(f.els.refresh.classList.contains('service-map-background-refresh'), false);
  assert.equal(f.els.refresh.classList.contains('is-working'), true);
  assert.equal(f.els.panel.attributes['aria-busy'], 'true');
  f.requests.at(-1).resolve(response(snapshot())); await manual;
  assert.equal(f.els.refresh.disabled, false);
  assert.equal(f.els.refresh.classList.contains('is-working'), false);
  assert.equal(f.els.panel.attributes['aria-busy'], 'false');
});
for (const boundary of ['reset', 'disconnect']) test(`${boundary} clears pending Reload presentation without a late response restoring it`, async () => {
  const f = fixture(); await f.load();
  const pending = f.controller.refresh({ force: true, retry: true });
  f.controller[boundary]();
  const assertIdle = () => {
    assert.equal(f.els.refresh.textContent, 'Reload');
    assert.equal(f.els.refresh.disabled, false);
    assert.equal(f.els.refresh.classList.contains('service-map-background-refresh'), false);
    assert.equal(f.els.refresh.classList.contains('is-working'), false);
    assert.equal(f.els.panel.attributes['aria-busy'], 'false');
  };
  assertIdle();
  f.requests.at(-1).resolve(response(snapshot())); await pending;
  assertIdle();
});
test('refresh progress change preserves initial loading, stale summary and failure semantics', async () => {
  const f = fixture(); const initial = f.controller.refresh();
  assert.equal(f.els.status.textContent, 'Loading retained HTTP metadata…');
  f.requests.at(-1).resolve(response(snapshot())); await initial;
  f.controller.markDirty(); const stale = f.els.status.textContent;
  assert.match(stale, /History changed: counts are from the previous snapshot/);
  const pending = f.controller.refresh(); assert.equal(f.els.status.textContent, stale);
  f.requests.at(-1).reject(new Error('Synthetic refresh failure')); await pending;
  assert.match(f.els.status.textContent, /Reload failed.*previous snapshot/);
  assert.match(f.els.status.textContent, /Stale snapshot/);
  assert.equal(f.els.status.classList.contains('service-map-error'), true);
  assert.equal(f.els.refresh.textContent, 'Reload'); assert.equal(f.els.refresh.disabled, false);
});
test('network errors keep prior map explicitly labelled; no payload text leaks', async () => {
  const f = fixture(); await f.load(); const pending = f.controller.refresh();
  f.requests.at(-1).reject(new Error('secret header body')); await pending;
  assert.match(f.els.status.textContent, /previous snapshot/); assert.match(f.els.status.textContent, /4 rows considered/);
  assert.doesNotMatch(f.els.status.textContent, /secret/); assert.equal(f.els.refresh.disabled, false);
});
test('incomplete bounds and latest window are visible, graph capped independently of snapshot', async () => {
  const f = fixture(); const origins = Array.from({ length: 80 }, (_, i) => origin(`https://node${i}.example.com`));
  await f.load(snapshot(origins, 'session-one', { complete: false, retained_rows: 20000, considered_rows: 10000, stopped_by: ['max_records'], omitted_rows: 2 }));
  assert.equal((f.els.canvas.innerHTML.match(/data-service-origin=/g) || []).length, 24);
  assert.match(boundsText(f), /24 \/ 80/); assert.match(f.els.status.textContent, /max_records/);
  assert.match(f.els.status.textContent, /20,000 retained/); assert.match(f.els.status.textContent, /2026-10-12T01/);
  f.els.search.value = 'node79.'; f.els.search.dispatch('input'); assert.match(f.els.canvas.innerHTML, /node79/);
});
test('reference-only nodes carry no captured counts, no invented relationships; header direction is explicit', async () => {
  const f = fixture(), target = origin(originB); target.header_links = [{ source_origin: originA, relationship: 'origin_header', source: 'request_header_declaration', evidence: ['header'] }];
  await f.load(snapshot([target]));
  assert.match(f.els.canvas.innerHTML, /Referenced only in this snapshot/);
  assert.match(f.els.canvas.innerHTML, /app.example.com.*→.*api.example.com.*Origin header/s);
  f.controller.selectOrigin(originA); assert.match(f.els.detail.innerHTML, /No captured rows are shown/);
  assert.equal(f.requests.length, 1);
});
test('markup escapes captured strings and omits query/fragment/userinfo; no external links emitted', async () => {
  const f = fixture(), data = origin('https://user:password@example.com', [endpoint('/<img onerror="bad">?token=secret#frag', '<script>', 'x" onclick="bad')]);
  data.technology_clues = [{ name: '<img src=x onerror=bad>', source: 'response_header', confidence: 'observed_header', evidence: [] }];
  await f.load(snapshot([data]));
  const html = f.els.canvas.innerHTML + f.els.detail.innerHTML + f.els.catalog.innerHTML;
  assert.doesNotMatch(html, /<img|<script|token=secret|password|<a\b|href=/);
  assert.match(html, /&lt;img/); assert.match(html, /&lt;script&gt;/);
});
test('unchanged refresh preserves card DOM and stable order, with additions appended', async () => {
  const f = fixture(); await f.load(); const replacements = f.els.canvas.replacements;
  await f.load(); assert.equal(f.els.canvas.replacements, replacements);
  const order = [...f.state.order]; await f.load(snapshot([origin('https://aaa.example.com'), origin(originA), origin(originB)]));
  assert.deepEqual([...f.state.order].slice(0, 2), order);
});
test('API catalog and selected-origin lists are independently paginated at 50', async () => {
  const f = fixture(); await f.load(snapshot([origin(originA, Array.from({ length: 130 }, (_, i) => endpoint(`/path-${i}`)))]));
  assert.equal((f.els.catalog.innerHTML.match(/data-service-endpoint=/g) || []).length, 50);
  assert.equal((f.els.detail.innerHTML.match(/data-service-endpoint=/g) || []).length, 50);
});
test('graph layout has an explicit edge cap and only supported metadata relations', () => {
  const origins = Array.from({ length: 24 }, (_, i) => ({ ...origin(`https://node${i}.example.com`), captured: true }));
  origins.forEach(item => { item.redirects = origins.map(target => ({ target_origin: target.origin })); });
  const layout = map.graphLayout(origins, origins.map(item => item.origin));
  assert.equal(layout.edges.length, 40); assert.equal(layout.edgeCount, 24 * 23);
});

test('stable focus keys use exact origin/method/path rather than a mutable row index', async () => {
  const f = fixture(); await f.load(snapshot([origin(originA, [endpoint('/a'), endpoint('/z', 'get')])]));
  const before = f.els.catalog.innerHTML.match(/data-service-focus="([^"]+)"[^>]*><span class="service-map-method get"[^>]*>get/)[1];
  await f.load(snapshot([origin(originA, [endpoint('/new'), endpoint('/a'), endpoint('/z', 'get')])]));
  const after = f.els.catalog.innerHTML.match(/data-service-focus="([^"]+)"[^>]*><span class="service-map-method get"[^>]*>get/)[1];
  assert.equal(before, after); assert.match(after, /\/z/);
});
test('filtered/bounded referenced cards do not assert the origin was never captured', async () => {
  const f = fixture(), target = origin(originB); target.header_links = [{ source_origin: originA, relationship: 'referer_header', source: 'request_header_declaration', evidence: ['ref'] }];
  await f.load(snapshot([target], 'session-one', { complete: false, stopped_by: ['max_records'] }));
  f.controller.selectOrigin(originA);
  assert.match(f.els.detail.innerHTML, /Scope and projection bounds may omit captured history/);
  assert.doesNotMatch(f.els.detail.innerHTML + f.els.canvas.innerHTML, /not captured|uncaptured/i);
});
test('exact evidence includes source observations and any incomplete-metadata notice', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA);
  const pending = f.controller.loadEvidence('evidence-one'), value = evidence();
  Object.assign(value.row, { metadata_complete: false, omitted: ['header_limit'], header_links: [{ source_origin: originB, relationship: 'origin_header' }], redirect: { target_origin: originB, target_path: '/next?private=omitted' }, technology_clues: [{ name: 'nginx', header_name: 'server' }] });
  f.requests.at(-1).resolve(response(value)); await pending;
  assert.match(f.els.detail.innerHTML, /header_limit/);
  assert.deepEqual(JSON.parse(JSON.stringify(f.state.evidence.header_links)), [{source_origin: originB, relationship: 'origin_header'}]);
  assert.deepEqual(JSON.parse(JSON.stringify(f.state.evidence.redirect)), {target_origin: originB, target_path: '/next'}); assert.doesNotMatch(f.els.detail.innerHTML, /private=omitted/);
});

const { loadFunctions, appSource } = require('./frontend-test-helpers.cjs');
// Scope shows its paths beside its rules; the Service Map tool never loads them.
for (const tool of ['target', 'map']) test(`${tool} loader only requests legacy paths for Scope, which shows them`, async () => {
  const requests = [], state = { activeTool: tool, activeTargetView: 'service-map', targetScopeDraftVersion: 0, targetScopeSaveToken: 0, targetScopeDirty: false };
  const ctx = loadFunctions(['loadTargetSiteMap'], {
    state, currentSessionId: () => 'session-one', workspaceStateGeneration: 0,
    els: { targetScopeEditor: { value: '' }, targetScopeExcludeEditor: { value: '' } },
    sessionQueryPath: (path, id) => `${path}?session_id=${id}`,
    fetch: async url => { requests.push(url); return response(url.startsWith('/api/runtime') ? {} : []); },
    requireOkResponse: async () => {}, jsonArray: value => value, syncTargetScopeDraft() {}, renderInterceptStatus() {}, renderProxySettings() {}, renderTarget() {},
  });
  await ctx.loadTargetSiteMap();
  assert.equal(requests.some(url => url.startsWith('/api/target/site-map')), tool === 'target');
});
test('map/APIs auxiliary polling leaves reads to the controller and bypasses legacy paths', async () => {
  for (const view of ['service-map', 'apis']) {
    let refreshes = 0;
    const ctx = loadFunctions(['pollAuxiliaryData'], {
      state: { activeTool: 'map', activeTargetView: view },
      targetServiceMapController: { refresh: async () => { refreshes++; } },
      isWebsocketHistoryVisible: () => false, shouldPollFindingsBadge: () => false,
      loadTargetSiteMap() { assert.fail('Legacy path loader must not run in the bounded map'); },
    });
    await ctx.pollAuxiliaryData(); assert.equal(refreshes, 0);
  }
});
test('integration wires session, removal, gap and owned transaction invalidation', () => {
  assert.match(appSource, /function resetSessionScopedUiState\(\)[\s\S]*?targetServiceMapController\?\.reset\(\)/);
  assert.match(appSource, /function applyConfirmedHistoryRemoval\([^]*?targetServiceMapController\?\.invalidate\(\)/);
  assert.match(appSource, /function invalidateHistoryAfterEventGap\([^]*?targetServiceMapController\?\.invalidate\(\)/);
  assert.match(appSource, /addEventListener\("transaction", \(event\) => \{\s*if \(!ownsHistoryEvents\(\)\) \{\s*return;\s*\}\s*if \(typeof targetServiceMapController[^]*?markDirty\(event\)/);
});

test('reference-card work is cached and capped independently of the 24-card viewport', async () => {
  const f = fixture(), target = origin(originB);
  target.header_links = Array.from({ length: 200 }, (_, i) => ({ source_origin: `https://source${i}.example.com`, relationship: 'origin_header', source: 'request_header_declaration', evidence: [] }));
  await f.load(snapshot([target]));
  assert.equal(f.state.graphOriginsCache.length, 101);
  assert.equal(f.state.omittedGraphReferences, 100);
  const cached = f.state.graphOriginsCache;
  f.controller.selectOrigin(originB); assert.equal(f.state.graphOriginsCache, cached);
  assert.match(boundsText(f), /Reference-card cap 100/);
});

test('source-first layout puts declared sources left of destinations and preserves slots on refresh', async () => {
  const f = fixture(), app = origin(originA), api = origin(originB), auth = origin('https://auth.example.com');
  app.redirects = [{ target_origin: auth.origin, target_path: '/', relationship: 'redirect_instruction', evidence: ['evidence-one'] }];
  api.header_links = [{ source_origin: app.origin, relationship: 'origin_header', source: 'request_header_declaration', evidence: ['evidence-one'] }];
  await f.load(snapshot([api, app, auth]));
  assert.equal(f.state.layoutSlots.get(app.origin).column, 0);
  assert.equal(f.state.layoutSlots.get(api.origin).column, 1);
  assert.equal(f.state.layoutSlots.get(auth.origin).column, 1);
  const slots = JSON.stringify([...f.state.layoutSlots]);
  f.controller.selectOrigin(auth.origin); assert.equal(JSON.stringify([...f.state.layoutSlots]), slots);
  await f.load(snapshot([app, auth, api])); assert.equal(JSON.stringify([...f.state.layoutSlots]), slots);
});
test('individual relationship click reads the source token owned by the captured origin', async () => {
  const f = fixture(), target = origin(originB);
  target.header_links = [{ source_origin: originA, relationship: 'origin_header', source: 'request_header_declaration', evidence: ['declared-source'] }];
  await f.load(snapshot([target])); f.controller.selectOrigin(originA);
  assert.match(f.els.detail.innerHTML, /data-service-relation-evidence="declared-source"/);
  assert.match(f.els.detail.innerHTML, /Origin header declaration/);
  const button = { dataset: { serviceRelationOrigin: originB, serviceRelationEvidence: 'declared-source' } };
  f.els.panel.dispatch('click', { target: { closest: () => button } });
  assert.equal(f.state.selectedOrigin, originB); assert.equal(f.state.evidenceId, 'declared-source');
  f.requests.at(-1).resolve(response(evidence('declared-source', originB))); await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.evidence.origin, originB);
});

test('front-end technology evidence stays bound to each serving origin', async () => {
  const sources = [
    ['https://cdn-a.example.com', 'asset-a'],
    ['https://cdn-b.example.com', 'asset-b'],
  ];
  const page = origin(originA);
  page.front_technologies = sources.map(([source_origin, id]) => ({
    product_id: 'react', name: 'React', category: 'framework', version: '18.2.0',
    source_origin, row_count: 1, evidence: [id],
  }));
  const f = fixture();
  await f.load(snapshot([page, ...sources.map(([source, id]) => origin(source, [endpoint('/users', 'GET', id)]))]));
  const normalized = f.state.snapshot.origins.find(item => item.origin === originA);
  assert.equal(normalized.front_technologies.length, 2);
  // A brand that opens with a digit is kept like any other.
  const digit = origin(originA);
  digit.front_technologies = [{ product_id: 'sixsense', name: '6sense', category: 'analytics', source_origin: originA, row_count: 1, evidence: ['six'] }];
  const g = fixture();
  await g.load(snapshot([digit]));
  assert.deepEqual(g.state.snapshot.origins[0].front_technologies.map(item => item.name), ['6sense']);
  const products = map.reportedProducts(normalized);
  assert.equal(products.length, 1);
  assert.equal(products[0].id, 'react');
  assert.deepEqual([...products[0].versions], ['18.2.0']);
  for (const [source, id] of sources) {
    f.controller.selectOrigin(originA);
    const rendered = [...f.els.detail.innerHTML.matchAll(/data-service-relation-origin="([^"]+)" data-service-relation-evidence="([^"]+)"/g)]
      .find(match => match[2] === id);
    assert.ok(rendered, 'each retained source has a rendered evidence button');
    assert.equal(rendered[1], source);
    const before = f.requests.length;
    const button = { dataset: { serviceRelationOrigin: rendered[1], serviceRelationEvidence: rendered[2] } };
    f.els.panel.dispatch('click', { target: { closest: () => button } });
    assert.equal(f.state.selectedOrigin, source);
    assert.equal(f.requests.length, before + 1);
    assert.equal(new URL(f.requests.at(-1).url, originA).searchParams.get('evidence_id'), id);
    f.requests.at(-1).resolve(response(evidence(id, source)));
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(f.state.evidenceId, id);
    assert.equal(f.state.evidence.origin, source);
    assert.match(f.els.detail.innerHTML, /Capture info/);
  }
});

for (const hidden of [false, true]) test(`a scope-rule save fences old map data even while ${hidden ? 'hidden' : 'a map read is running'}`, async () => {
  const f = fixture(); await f.load(); const oldMap = f.controller.refresh();
  if (hidden) f.controller.setVisible(false);
  const runtime = deferred();
  const appState = { runtime: { scope_patterns: ['*.example.com'], excluded_scope_patterns: [] }, targetScopeEditorSessionId: 'session-one', targetScopeDraft: 'api.example.com', targetScopeExcludeDraft: '', targetScopeDraftVersion: 0, targetScopeSaveToken: 0 };
  const ctx = loadFunctions(['saveTargetScope', 'postRuntimeSettings', 'formatScopePatternsText'], {
    state: appState, els: { targetScopeEditor: { value: 'api.example.com' }, targetScopeExcludeEditor: { value: '' } },
    currentSessionId: () => 'session-one', workspaceStateGeneration: 1, targetServiceMapController: f.controller,
    expectedActiveSessionIdForWrite: id => id, fetch: () => runtime.promise, showToast() {}, renderInterceptStatus() {}, renderProxySettings() {}, invalidateVisibleEntriesCache() {}, scheduleRefresh() {},
  });
  const save = ctx.saveTargetScope({ skipReload: true });
  runtime.resolve(response({ scope_patterns: ['api.example.com'], excluded_scope_patterns: [] }));
  await save;
  assert.equal(f.state.snapshot, null, 'old scope classifications clear immediately');
  assert.equal(f.requests[1].options.signal.aborted, true);
  f.requests[1].resolve(response(snapshot())); await oldMap;
  assert.equal(f.state.snapshot, null, 'old response cannot resurrect scope badges');
  if (hidden) { assert.equal(f.requests.length, 2); f.controller.setVisible(true); }
  const fresh = hidden ? f.controller.refresh() : null;
  const scoped = origin(originB); f.requests.at(-1).resolve(response(snapshot([scoped])));
  if (fresh) await fresh; else await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.snapshot.origins[0].origin, originB);
});
test('unchanged include/exclude rules do not invalidate an in-flight map', async () => {
  const f = fixture(); await f.load(); const pending = f.controller.refresh();
  assert.equal(f.controller.scopeChanged({ scope_patterns: ['example.com'] }, { scope_patterns: ['example.com'], excluded_scope_patterns: [], intercept_enabled: true }), false);
  assert.equal(f.requests.at(-1).options.signal.aborted, false);
  f.requests.at(-1).resolve(response(snapshot())); await pending;
  assert.notEqual(f.state.snapshot, null);
});

for (const transition of ['scope filter', 'history invalidation']) test(`${transition} preserves exact endpoint identity through an empty snapshot`, async () => {
  const f = fixture();
  await f.load(snapshot([origin(originA, [endpoint('/first'), endpoint('/selected', 'get', 'selected')])]));
  f.controller.selectOrigin(originA, 1);
  const oldEvidence = f.controller.loadEvidence('selected');
  let refresh;
  if (transition === 'scope filter') {
    f.els.scope.dispatch('click');
  } else refresh = f.controller.invalidate();
  assert.equal(f.state.snapshot, null);
  assert.equal(f.state.evidence, null);
  f.requests[1].resolve(response(evidence('selected', originA, { row: { ...evidence().row, evidence_id: 'selected', method: 'get', path: '/selected' } })));
  await oldEvidence;
  assert.equal(f.state.evidence, null, 'old source cannot return during the invalidated snapshot');
  f.requests.at(-1).resolve(response(snapshot([origin(originA, [endpoint('/selected', 'GET'), endpoint('/other'), endpoint('/selected', 'get', 'selected')])])));
  if (refresh) await refresh; else await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.endpointIndex, 2);
  assert.match(f.els.detail.innerHTML, /packet-source[^]*?<span>get <strong>\/selected<\/strong>/);
  assert.equal(f.state.evidence, null, 'a refreshed selection does not claim a newly verified source');
});

test('invalidating a removed endpoint clears its selection instead of selecting the replacement index', async () => {
  const f = fixture(); await f.load(snapshot([origin(originA, [endpoint('/selected')])]));
  f.controller.selectOrigin(originA, 0);
  const refresh = f.controller.invalidate();
  f.requests.at(-1).resolve(response(snapshot([origin(originA, [endpoint('/replacement')])])));
  await refresh;
  assert.equal(f.state.endpointIndex, null);
  assert.doesNotMatch(f.els.detail.innerHTML, /service-map-endpoint-summary/);
});

test('origin search keeps selected exact evidence and explains when its card is filtered out', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA, 0);
  const pending = f.controller.loadEvidence('evidence-one');
  f.requests.at(-1).resolve(response(evidence())); await pending;
  const verified = f.state.evidence;
  for (const query of ['api.example.com', 'no-matching.example.com']) {
    f.els.search.value = query; f.els.search.dispatch('input');
    assert.equal(f.state.selectedOrigin, originA);
    assert.equal(f.state.evidence, verified);
    assert.match(f.els.detail.innerHTML, /Capture info/);
    assert.match(boundsText(f), /Selected origin is outside this filter/);
  }
  f.els.search.value = ''; f.els.search.dispatch('input');
  assert.doesNotMatch(boundsText(f), /outside this filter/);
  assert.equal(f.requests.length, 2, 'origin search never fetches new metadata');
});

test('selection beyond the card cap remains inspectable and explains the display limit', async () => {
  const f = fixture(), origins = Array.from({ length: 30 }, (_, i) => origin(`https://node${String(i).padStart(2, '0')}.example.com`));
  await f.load(snapshot(origins));
  f.controller.selectOrigin(origins.at(-1).origin, 0);
  assert.equal((f.els.canvas.innerHTML.match(/data-service-origin=/g) || []).length, 24);
  assert.match(boundsText(f), /Selected origin is outside the 24-card display/);
  assert.match(f.els.detail.innerHTML, /node29.example.com/);
});

test('redirect relationships distinguish exact target paths and have distinct stable focus keys', async () => {
  const f = fixture(), source = origin(originA);
  source.redirects = ['/first?secret=omitted', '/second'].map((target_path, i) => ({ target_origin: originB, target_path, relationship: 'redirect_instruction', evidence: [`redirect-${i}`] }));
  await f.load(snapshot([source]));
  f.controller.selectOrigin(originA);
  assert.match(f.els.detail.innerHTML, /api.example.com\/first/);
  assert.match(f.els.detail.innerHTML, /api.example.com\/second/);
  assert.doesNotMatch(f.els.detail.innerHTML, /secret=omitted/);
  const keys = [...f.els.detail.innerHTML.matchAll(/data-service-focus="(relation:[^"]+)"/g)].map(match => match[1]);
  assert.equal(keys.length, 2);
  assert.equal(new Set(keys).size, 2);
});

test('long captured and reference-only origins retain full identities behind bounded header previews', async () => {
  const host = `${['a'.repeat(50), 'b'.repeat(50), 'c'.repeat(50), 'd'.repeat(50)].join('.')}.example.com`;
  const fullOrigin = `https://${host}`;
  for (const captured of [true, false]) {
    const f = fixture(), owner = origin(captured ? fullOrigin : originA);
    if (!captured) owner.header_links = [{ source_origin: fullOrigin, relationship: 'origin_header', source: 'request_header_declaration', evidence: [] }];
    await f.load(snapshot([owner])); f.controller.selectOrigin(fullOrigin);
    assert.ok(f.els.detail.innerHTML.includes(`<h3 title="${host}">${host}</h3>`));
    assert.ok(f.els.detail.innerHTML.includes(`<p title="${fullOrigin}">${fullOrigin}</p>`));
  }
});

test('bounded API previews preserve full escaped method and exact path in text and titles', async () => {
  const f = fixture(), method = 'EXPERIMENTAL_METHOD_WITH_32_CHARS!'.slice(0, 32);
  assert.equal(method.length, 32);
  const exactPath = `/catalog/${'long-segment-'.repeat(22)}"quoted"&<safe>`;
  const escapedPath = exactPath.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  await f.load(snapshot([origin(originA, [endpoint(exactPath, method)])]));
  for (const html of [f.els.detail.innerHTML, f.els.catalog.innerHTML]) {
    assert.ok(html.includes(`title="${method}">${method}</span>`));
    assert.ok(html.includes(`<span title="${escapedPath}">${escapedPath}</span>`));
    assert.doesNotMatch(html, /<safe>|title="[^"]*"quoted"/);
  }
  f.controller.selectOrigin(originA, 0);
  assert.ok(f.els.detail.innerHTML.includes(`<strong>${escapedPath}</strong>`), 'the selected endpoint body keeps the complete path');
});

test('map preview styles bound headers and long method/path rows without removing their text', () => {
  const styles = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
  const header = styles.match(/\.service-map-detail-header h3\s*\{([^}]+)\}/)[1];
  assert.match(header, /-webkit-line-clamp:\s*2/);
  assert.match(header, /max-height:\s*2\.6em/);
  const method = styles.match(/\.service-map-api-row \.service-map-method\s*\{([^}]+)\}/)[1];
  assert.match(method, /max-width:\s*min\(8em,\s*32%\)/);
  const pathPreview = styles.match(/\.service-map-api-copy > span\s*\{([^}]+)\}/)[1];
  assert.match(pathPreview, /-webkit-line-clamp:\s*2/);
  assert.match(pathPreview, /max-height:\s*2\.8em/);
  assert.match(styles, /\.service-map-detail-header p, \.service-map-api-copy > small\s*\{[^}]*text-overflow:\s*ellipsis;[^}]*white-space:\s*nowrap/);
});

function redirect(target, target_path = '/', id = 'evidence-one') { return { target_origin: target, target_path, relationship: 'redirect_instruction', evidence: [id] }; }
function header(source, relationship = 'origin_header', id = 'evidence-one') { return { source_origin: source, relationship, source: 'request_header_declaration', evidence: [id] }; }
function boundsText(f) { return `${f.els.graphBounds.textContent} ${f.els.graphDiagnostics.textContent}`; }
function cardIds(f) { return [...f.els.canvas.innerHTML.matchAll(/data-service-origin="([^"]+)"/g)].map(match => match[1]); }
function pin(f, id) { f.controller.selectOrigin(id); f.els.directRelations.dispatch('click'); }

test('All origins is default; direct controls are local, optional and hidden in standalone APIs', async () => {
  const f = fixture();
  assert.equal(f.els.allOrigins.attributes['aria-pressed'], 'true');
  assert.equal(f.els.directRelations.disabled, true);
  f.els.directRelations.dispatch('click'); assert.equal(f.state.anchorOrigin, null);
  await f.load(); pin(f, originA);
  assert.equal(f.state.anchorOrigin, originA);
  assert.equal(f.els.directRelations.attributes['aria-pressed'], 'true');
  const catalog = f.els.catalog.innerHTML;
  f.controller.setVisible(true, 'apis');
  assert.equal(f.els.mapControls.classList.contains('hidden'), true);
  assert.equal(f.els.catalog.innerHTML, catalog);
  f.controller.setVisible(true, 'service-map');
  assert.equal(f.els.mapControls.classList.contains('hidden'), false);
  f.els.allOrigins.dispatch('click');
  assert.equal(f.state.anchorOrigin, null);
  assert.deepEqual(new Set(cardIds(f)), new Set([originA, originB]));
  assert.equal(f.requests.length, 1);
});

test('direct mode pins beyond-card-cap anchors and never expands transitively', async () => {
  const f = fixture(), rows = Array.from({ length: 30 }, (_, i) => origin(`https://node${String(i).padStart(2, '0')}.example.com`));
  rows[29].redirects = [redirect(rows[0].origin)];
  rows[0].redirects = [redirect(rows[1].origin)];
  await f.load(snapshot(rows)); pin(f, rows[29].origin);
  assert.deepEqual(new Set(cardIds(f)), new Set([rows[29].origin, rows[0].origin]));
  assert.match(f.els.canvas.innerHTML, /title="Pinned anchor · /);
  assert.match(boundsText(f), /1 known direct neighbors/);
  assert.equal(f.requests.length, 1);
});

test('card and relationship selections never move a pinned anchor; Focus selection preserves exact evidence', async () => {
  const f = fixture(), app = origin(originA), api = origin(originB);
  app.redirects = [redirect(originB)]; await f.load(snapshot([app, api])); pin(f, originA);
  const slots = JSON.stringify([...f.state.layoutSlots]);
  f.els.panel.dispatch('click', { target: { closest: () => ({ dataset: { serviceOrigin: originB } }) } });
  assert.equal(f.state.anchorOrigin, originA);
  assert.equal(JSON.stringify([...f.state.layoutSlots]), slots);
  f.els.directRelations.dispatch('click'); assert.equal(f.state.anchorOrigin, null, 'a second press turns it off and never repins');
  pin(f, originA);
  f.controller.selectOrigin(originB, 0);
  const pending = f.controller.loadEvidence('evidence-one');
  f.requests.at(-1).resolve(response(evidence('evidence-one', originB))); await pending;
  const selectedEvidence = f.state.evidence, endpointIdentity = f.state.endpointSelection, detail = f.els.detail.innerHTML;
  f.els.focusSelection.dispatch('click');
  assert.equal(f.state.anchorOrigin, originB);
  assert.equal(f.state.endpointIndex, 0);
  assert.equal(f.state.endpointSelection, endpointIdentity);
  assert.equal(f.state.evidence, selectedEvidence);
  assert.equal(f.els.detail.innerHTML, detail);
  assert.equal(f.state.detailTab, 'evidence');
  f.els.allOrigins.dispatch('click');
  assert.equal(f.state.evidence, selectedEvidence);
  assert.equal(f.state.endpointSelection, endpointIdentity);
  assert.equal(f.requests.length, 2, 'only map load and explicit source verification fetch');
});

test('search filters direct neighbors without hiding the anchor, with separate query/card omissions', async () => {
  const f = fixture(), app = origin(originA);
  app.redirects = Array.from({ length: 30 }, (_, i) => redirect(`https://neighbor${String(i).padStart(2, '0')}.example.com`));
  await f.load(snapshot([app])); pin(f, originA);
  assert.equal(cardIds(f).length, 24);
  assert.equal(cardIds(f)[0], originA);
  assert.match(boundsText(f), /30 known direct neighbors/);
  assert.match(boundsText(f), /30 loaded neighbors · 0 query-hidden · 0 product\/version-hidden · 30 matching · 23 shown · 7 omitted by 24-card cap/);
  f.els.search.value = 'neighbor2'; f.els.search.dispatch('input');
  assert.equal(cardIds(f).length, 11);
  assert.equal(cardIds(f)[0], originA);
  assert.match(boundsText(f), /30 known direct neighbors/);
  assert.match(boundsText(f), /30 loaded neighbors · 20 query-hidden · 0 product\/version-hidden · 10 matching · 10 shown · 0 omitted/);
  assert.match(boundsText(f), /Pinned anchor is outside the search query/);
  f.els.search.value = 'missing'; f.els.search.dispatch('input');
  assert.deepEqual(cardIds(f), [originA]);
  assert.match(boundsText(f), /30 loaded neighbors · 30 query-hidden · 0 product\/version-hidden · 0 matching · 0 shown/);
  assert.doesNotMatch(boundsText(f), /No direct neighbors appear/);
  assert.equal(f.requests.length, 1);
});

test('in-contract direct neighbors remain available beyond the global 100 and pane 30 caps', async () => {
  const f = fixture(), app = origin(originA), budgetOwner = origin(originB);
  budgetOwner.redirects = Array.from({ length: 100 }, (_, i) => redirect(`https://reference${String(i).padStart(3, '0')}.example.com`, `/target-${i}`));
  app.redirects = Array.from({ length: 100 }, (_, i) => redirect(`https://reference${String(i + 100).padStart(3, '0')}.example.com`, `/target-${i + 100}`));
  await f.load(snapshot([budgetOwner, app])); pin(f, originA);
  assert.equal(f.state.graphOriginsCache.length, 102);
  assert.equal(f.state.relationsByOrigin.get(originA).items.length, 30);
  assert.match(boundsText(f), /100 known direct neighbors/);
  assert.match(boundsText(f), /100 loaded neighbors · 0 query-hidden · 0 product\/version-hidden · 100 matching · 23 shown · 77 omitted/);
  f.els.search.value = 'reference199'; f.els.search.dispatch('input');
  const extra = 'https://reference199.example.com';
  assert.deepEqual(cardIds(f), [originA, extra]);
  f.controller.selectOrigin(extra);
  assert.match(f.els.detail.innerHTML, /Referenced only in this snapshot/);
  assert.match(f.els.detail.innerHTML, /reference199.example.com\/target-199/);
  assert.equal(f.state.anchorOrigin, originA);
  f.els.focusSelection.dispatch('click'); assert.equal(f.state.anchorOrigin, extra);
  assert.match(boundsText(f), /Reference-only anchor/);
  assert.match(boundsText(f), /1 known direct neighbors/);
  f.els.allOrigins.dispatch('click');
  assert.equal(f.state.selectedOrigin, extra);
  assert.match(f.els.detail.innerHTML, /reference199.example.com/);
  assert.match(boundsText(f), /100-reference-card limit/);
  f.els.search.value = ''; f.els.search.dispatch('input');
  await f.load(snapshot([budgetOwner, app]));
  assert.equal(f.state.selectedOrigin, extra, 'refresh retains a still-loaded reference beyond the All origins budget');
  assert.match(boundsText(f), /100-reference-card limit/);
});

test('direct arrows include only anchor-incident metadata, count distinct types, draw one arrow per direction and exclude self links', async () => {
  const f = fixture(), a = origin(originA), b = origin(originB), c = origin('https://third.example.com');
  a.redirects = [redirect(originB, '/one'), redirect(originB, '/two'), redirect(originA)];
  b.redirects = [redirect(c.origin)];
  b.header_links = [header(originA), header(originA, 'referer_header')];
  a.header_links = [header(c.origin, 'referer_header')];
  await f.load(snapshot([a, b, c])); pin(f, originA);
  assert.match(boundsText(f), /2 known direct neighbors/);
  assert.match(boundsText(f), /Non-self distinct typed links: 1 incoming \/ 3 outgoing · 1 redirect \/ 1 Origin \/ 2 Referer/);
  // The redirects, Origin and Referer from A to B share one arrow.
  assert.match(boundsText(f), /2 \/ 2 arrows between displayed cards \(cap 40\)/);
  assert.doesNotMatch(f.els.canvas.innerHTML, /api.example.com → https:\/\/third.example.com/);
  assert.match(f.els.detail.innerHTML, /api.example.com\/one/);
  assert.match(f.els.detail.innerHTML, /api.example.com\/two/);
});

test('direct arrow cap reports visible-card eligible arrows separately from off-card arrows', async () => {
  const f = fixture(), app = origin(originA), peers = Array.from({ length: 30 }, (_, i) => origin(`https://peer${i}.example.com`));
  // Each peer and the anchor point at each other: two arrows a peer.
  peers.forEach(peer => { peer.header_links = [header(originA), header(originA, 'referer_header')]; peer.redirects = [redirect(originA)]; app.redirects.push(redirect(peer.origin)); });
  await f.load(snapshot([app, ...peers])); pin(f, originA);
  assert.match(boundsText(f), /40 \/ 46 arrows between displayed cards \(cap 40\) · 14 arrows outside displayed cards/);
  assert.equal((f.els.canvas.innerHTML.match(/marker-end=/g) || []).length, 40);
});

test('reference-only anchors preserve metadata direction and exact captured-owner evidence routing', async () => {
  const f = fixture(), api = origin(originB); api.header_links = [header(originA, 'referer_header', 'source')];
  await f.load(snapshot([api])); pin(f, originA);
  assert.match(boundsText(f), /0 incoming \/ 1 outgoing/);
  assert.match(boundsText(f), /Reference-only anchor/);
  const button = { dataset: { serviceRelationOrigin: originB, serviceRelationEvidence: 'source' } };
  f.els.panel.dispatch('click', { target: { closest: () => button } });
  assert.equal(f.state.anchorOrigin, originA);
  assert.equal(f.state.selectedOrigin, originB);
  assert.equal(f.state.evidenceId, 'source');
  f.requests.at(-1).resolve(response(evidence('source', originB))); await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.evidence.origin, originB);
});

test('inspector notices distinguish outside-neighborhood, search, card cap and reference cap', async () => {
  const f = fixture(), app = origin(originA), unrelated = origin('https://unrelated.example.com');
  app.redirects = Array.from({ length: 30 }, (_, i) => redirect(`https://peer${String(i).padStart(2, '0')}.example.com`));
  await f.load(snapshot([app, unrelated])); pin(f, originA);
  f.controller.selectOrigin(unrelated.origin, 0);
  assert.match(boundsText(f), /outside this direct neighborhood/);
  assert.doesNotMatch(boundsText(f), /outside this filter/);
  f.controller.selectOrigin('https://peer29.example.com');
  assert.match(boundsText(f), /outside the 24-card display/);
  f.els.search.value = 'peer00'; f.els.search.dispatch('input');
  assert.match(boundsText(f), /outside this filter/);
  f.els.focusSelection.dispatch('click');
  assert.equal(f.state.anchorOrigin, 'https://peer29.example.com');
  assert.doesNotMatch(boundsText(f), /Selected origin is outside/);
});

test('no-neighbor and incomplete snapshots retain the pinned origin with bounded claims', async () => {
  const f = fixture(); await f.load(snapshot([origin(originA)], 'session-one', { complete: false, stopped_by: ['max_records'] })); pin(f, originA);
  assert.deepEqual(cardIds(f), [originA]);
  assert.match(boundsText(f), /0 known direct neighbors/);
  assert.match(boundsText(f), /No direct neighbors appear in loaded metadata/);
  assert.match(boundsText(f), /Known neighborhood is incomplete/);
  assert.doesNotMatch(boundsText(f), /complete architecture|service calls observed/);
});

for (const transition of ['history', 'scope']) test(`direct anchor survives transient ${transition} invalidation and exact endpoint identity survives reorder`, async () => {
  const f = fixture(), app = origin(originA, [endpoint('/first'), endpoint('/selected', 'get', 'selected')]);
  app.redirects = [redirect(originB)]; await f.load(snapshot([app, origin(originB)])); pin(f, originA);
  f.controller.selectOrigin(originA, 1);
  const oldEvidence = f.controller.loadEvidence('selected'), oldMap = f.controller.refresh();
  let current;
  if (transition === 'history') current = f.controller.invalidate();
  else { f.els.scope.dispatch('click'); }
  assert.equal(f.state.snapshot, null);
  assert.equal(f.state.anchorOrigin, originA);
  assert.equal(f.state.neighborhood, null);
  assert.doesNotMatch(boundsText(f), /known direct neighbors/);
  f.requests[1].resolve(response(evidence('selected'))); await oldEvidence;
  f.requests[2].resolve(response(snapshot())); await oldMap;
  assert.equal(f.state.snapshot, null);
  const fresh = origin(originA, [endpoint('/selected', 'GET'), endpoint('/selected', 'get', 'selected')]);
  fresh.redirects = [redirect(originB)]; fresh.in_scope = false;
  f.requests.at(-1).resolve(response(snapshot([fresh, origin(originB)])));
  if (current) await current; else await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.anchorOrigin, originA);
  assert.equal(f.state.endpointIndex, 1);
  assert.equal(f.state.endpointSelection.method, 'get');
  assert.equal(f.state.evidence, null);
  assert.match(f.els.detail.innerHTML, /Out of scope/);
  assert.equal(cardIds(f)[0], originA, 'anchor visibility is independent of new classification');
});

test('missing anchors clear mode only on current successful snapshot; stale responses cannot resurrect it', async () => {
  const f = fixture(); await f.load(); pin(f, originA);
  const old = f.controller.refresh(), current = f.controller.invalidate();
  assert.equal(f.state.anchorOrigin, originA);
  f.requests.at(-1).resolve(response(snapshot([origin(originB)]))); await current;
  assert.equal(f.state.anchorOrigin, null);
  assert.equal(f.els.allOrigins.attributes['aria-pressed'], 'true');
  assert.match(boundsText(f), /pinned origin is absent/);
  f.requests[1].resolve(response(snapshot())); await old;
  assert.equal(f.state.anchorOrigin, null);
  assert.doesNotMatch(f.els.canvas.innerHTML, /app.example.com/);
});

test('session reset clears direct mode immediately and pending parse cannot restore it', async () => {
  const f = fixture(); await f.load(); pin(f, originA);
  const parse = deferred(), pending = f.controller.refresh();
  f.requests.at(-1).resolve({ ok: true, json: () => parse.promise }); await Promise.resolve();
  f.setSession('session-two'); f.controller.reset();
  assert.equal(f.state.anchorOrigin, null);
  assert.equal(f.state.neighborhood, null);
  parse.resolve(snapshot()); await pending;
  assert.equal(f.state.snapshot, null);
  assert.equal(f.state.anchorOrigin, null);
});

for (const action of ['directRelations', 'focusSelection']) test(`${action} rejects a session switch before a UI reset without fetching`, async () => {
  const f = fixture(); await f.load(); if (action === 'focusSelection') pin(f, originA);
  f.setSession('session-two'); f.els[action].dispatch('click');
  assert.equal(f.state.anchorOrigin, null);
  assert.equal(f.state.snapshot, null);
  assert.equal(f.requests.length, 1);
});

test('dirty and refresh-failure states keep the stable anchor and label previous data without re-verifying evidence', async () => {
  const f = fixture(), app = origin(originA); app.redirects = [redirect(originB)];
  await f.load(snapshot([app, origin(originB)])); pin(f, originA);
  const slots = JSON.stringify([...f.state.layoutSlots]); f.controller.markDirty();
  assert.equal(f.state.anchorOrigin, originA);
  assert.match(f.els.status.textContent, /previous snapshot/);
  const pending = f.controller.refresh(); f.requests.at(-1).reject(new Error('fixture failure')); await pending;
  assert.equal(f.state.anchorOrigin, originA);
  assert.equal(JSON.stringify([...f.state.layoutSlots]), slots);
  assert.match(f.els.status.textContent, /Reload failed/);
  assert.equal(f.requests.length, 2);
});

test('direct mode changes preserve an in-flight exact source read and its identity', async () => {
  const f = fixture(), app = origin(originA); app.redirects = [redirect(originB)];
  await f.load(snapshot([app, origin(originB)]));
  f.controller.selectOrigin(originA, 0);
  const pending = f.controller.loadEvidence('evidence-one'), sourceRequest = f.requests.at(-1);
  f.els.directRelations.dispatch('click');
  f.els.allOrigins.dispatch('click');
  f.els.directRelations.dispatch('click');
  assert.equal(sourceRequest.options.signal.aborted, false);
  sourceRequest.resolve(response(evidence())); await pending;
  assert.equal(f.state.evidence.origin, originA);
  assert.equal(f.state.endpointSelection.path, '/users');
  assert.equal(f.state.endpointIndex, 0);
  assert.equal(f.requests.length, 2);
});

test('Focus selection can repin while exact evidence is loading without aborting the read', async () => {
  const f = fixture(), app = origin(originA); app.redirects = [redirect(originB)];
  await f.load(snapshot([app, origin(originB)])); pin(f, originA);
  f.controller.selectOrigin(originB, 0);
  const pending = f.controller.loadEvidence('evidence-one'), sourceRequest = f.requests.at(-1);
  f.els.focusSelection.dispatch('click');
  assert.equal(sourceRequest.options.signal.aborted, false);
  sourceRequest.resolve(response(evidence('evidence-one', originB))); await pending;
  assert.equal(f.state.anchorOrigin, originB);
  assert.equal(f.state.evidence.origin, originB);
  assert.equal(f.requests.length, 2);
});

test('direct neighborhood cache ignores inspector changes and rebuilds from fresh metadata while keeping slots', async () => {
  const f = fixture(), app = origin(originA), api = origin(originB); app.redirects = [redirect(originB)];
  await f.load(snapshot([app, api])); pin(f, originA);
  const cached = f.state.neighborhood, slots = JSON.stringify([...f.state.layoutSlots]);
  f.controller.selectOrigin(originB);
  assert.equal(f.state.neighborhood, cached);
  f.controller.selectOrigin(originA);
  const replacements = f.els.canvas.replacements;
  await f.load(snapshot([api, app]));
  assert.notEqual(f.state.neighborhood, cached);
  assert.equal(JSON.stringify([...f.state.layoutSlots]), slots);
  assert.equal(f.els.canvas.replacements, replacements);
  const updated = origin(originA); updated.redirects = [redirect('https://changed.example.com')];
  await f.load(snapshot([updated, api]));
  assert.equal(f.state.anchorOrigin, originA);
  assert.deepEqual(new Set(cardIds(f)), new Set([originA, 'https://changed.example.com']));
  assert.doesNotMatch(f.els.canvas.innerHTML, /api.example.com/);
});

test('a current empty snapshot clears anchor mode and its count notices', async () => {
  const f = fixture(); await f.load(); pin(f, originA);
  await f.load(snapshot([]));
  assert.equal(f.state.anchorOrigin, null);
  assert.equal(f.state.neighborhood, null);
  assert.equal(f.els.directRelations.disabled, true);
  assert.match(f.els.canvas.innerHTML, /No retained HTTP origins/);
  assert.match(boundsText(f), /pinned origin is absent/);
  assert.doesNotMatch(boundsText(f), /known direct neighbors/);
});

test('standalone APIs remain query-filtered across pinning, including unrelated origins', async () => {
  const f = fixture(), app = origin(originA), unrelated = origin('https://unrelated.example.com');
  app.redirects = [redirect(originB)];
  await f.load(snapshot([app, origin(originB), unrelated])); pin(f, originA);
  f.els.search.value = 'unrelated'; f.els.search.dispatch('input');
  f.controller.setVisible(true, 'apis');
  assert.match(f.els.catalog.innerHTML, /unrelated.example.com/);
  assert.doesNotMatch(f.els.catalog.innerHTML, /app.example.com|api.example.com/);
  const button = { dataset: { serviceOrigin: unrelated.origin, serviceEndpoint: '0' } };
  f.els.panel.dispatch('click', { target: { closest: () => button } });
  assert.equal(f.state.view, 'service-map');
  assert.equal(f.state.selectedOrigin, unrelated.origin);
  assert.equal(f.state.anchorOrigin, originA);
  assert.match(boundsText(f), /outside this direct neighborhood/);
  assert.equal(f.requests.length, 1);
});

test('routine projection advisories do not imply an incomplete direct neighborhood', async () => {
  const f = fixture(), data = snapshot([origin(originA)]);
  data.warnings = ['Retained rows only.', 'Header declarations are not initiator proof.', 'Technology clues are not verified architecture.'];
  await f.load(data); pin(f, originA);
  assert.match(f.els.status.textContent, /3 metadata notice/);
  assert.match(boundsText(f), /Loaded metadata only; no transitive links or confirmed calls/);
  assert.doesNotMatch(boundsText(f), /Known neighborhood is incomplete/);
  data.snapshot.complete = false; data.snapshot.stopped_by = ['max_records'];
  await f.load(data);
  assert.match(boundsText(f), /Known neighborhood is incomplete/);
});

test('direct primary summary stays compact while native disclosure retains all count and limit details', async () => {
  const f = fixture(), app = origin(originA); app.redirects = [redirect(originB)];
  await f.load(snapshot([app, origin(originB)])); pin(f, originA);
  assert.equal(f.els.boundsDetails.classList.contains('hidden'), false);
  assert.match(f.els.graphBounds.textContent, /^1 \/ 1 known direct neighbors shown · 0 incoming \/ 1 outgoing links$/);
  assert.doesNotMatch(f.els.graphBounds.textContent, /Non-self|typed|0 query-hidden|0 omitted|cap 40/);
  assert.match(f.els.graphDiagnostics.textContent, /1 redirect \/ 0 Origin \/ 0 Referer/);
  assert.match(f.els.graphDiagnostics.textContent, /1 \/ 1 arrows between displayed cards \(cap 40\)/);
  assert.match(f.els.graphDiagnostics.textContent, /self-links are excluded/);
  f.els.allOrigins.dispatch('click');
  assert.equal(f.els.boundsDetails.classList.contains('hidden'), false);
  assert.match(f.els.graphDiagnostics.textContent, /2 loaded origins · 0 query-hidden · 0 product\/version-hidden · 2 matching/);
  const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  assert.match(html, /<details[^>]*id="serviceMapBoundsDetails"><summary id="serviceMapDetailsSummary">Details<\/summary><p class="service-map-status" id="serviceMapStatus"><\/p><p id="serviceMapGraphBounds"><\/p><p id="serviceMapGraphDiagnostics"><\/p><\/details>/, 'counts and coverage sit under Details');
});

test('primary direct summary keeps meaningful omissions visible without opening details', async () => {
  const f = fixture(), app = origin(originA), peers = Array.from({ length: 30 }, (_, i) => origin(`https://peer${String(i).padStart(2, '0')}.example.com`));
  peers.forEach(peer => { peer.header_links = [header(originA), header(originA, 'referer_header')]; peer.redirects = [redirect(originA)]; app.redirects.push(redirect(peer.origin)); });
  await f.load(snapshot([app, ...peers])); pin(f, originA);
  assert.match(f.els.graphBounds.textContent, /7 omitted by 24-card cap/);
  assert.match(f.els.graphBounds.textContent, /6 arrows omitted by 40-arrow cap/);
  f.els.search.value = 'peer2'; f.els.search.dispatch('input');
  assert.match(f.els.graphBounds.textContent, /20 hidden by query/);
  assert.match(f.els.graphBounds.textContent, /Pinned anchor is outside the search query/);
  assert.doesNotMatch(f.els.graphBounds.textContent, /\b0 omitted|\b0 hidden/);
});

function bodyReferences(overrides = {}) {
  return { schema_version: 1, session_id: 'session-one', evidence_id: 'evidence-one', available: true,
    status: 'scanned', complete: true, reasons: [], source_origin: originA, source_sequence: '9007199254740993',
    source_started_at: '2026-10-12T01:00:00Z', retained_preview_bytes: 300, scanned_bytes: 300,
    capture_preview_truncated: false, scan_prefix_truncated: false, candidates_scanned: 2,
    omitted_reference_occurrences: 0, references: [{ target_origin: 'https://assets.example.com', occurrences: 2, preview_byte_offsets: [24, 148], omitted_offsets: 0 }],
    limits: { ...map.BODY_REFERENCE_LIMITS }, coverage: 'literal_absolute_http_urls', offset_basis: 'retained_utf8_preview', ...overrides };
}
async function verifiedBodyFixture() {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA, 0);
  const pending = f.controller.loadEvidence('evidence-one'); f.requests.at(-1).resolve(response(evidence())); await pending;
  return f;
}
async function resolveBodyReferences(f, payload = bodyReferences()) {
  const pending = f.controller.loadBodyReferences(); f.requests.at(-1).resolve(response(payload)); return pending;
}

test('body inspection is opt-in: map, source verification, tabs, filters and refresh never request bodies', async () => {
  const f = fixture(); await f.controller.loadBodyReferences(); assert.equal(f.requests.length, 0);
  await f.load(); await f.controller.loadBodyReferences(); assert.equal(f.requests.length, 1);
  assert.doesNotMatch(f.els.detail.innerHTML, /data-service-body-references/);
  f.controller.selectOrigin(originA, 0);
  const sourceRead = f.controller.loadEvidence('evidence-one');
  assert.doesNotMatch(f.els.detail.innerHTML, /data-service-body-references/);
  f.requests.at(-1).resolve(response(evidence())); await sourceRead;
  assert.doesNotMatch(f.els.detail.innerHTML, /data-service-body-references="inspect"|class="service-map-body-references/);
  f.els.search.value = 'app'; f.els.search.dispatch('input');
  f.controller.setVisible(false); f.controller.setVisible(true); await f.load();
  assert.equal(f.requests.length, 3);
  assert.ok(f.requests.every(item => !item.url.includes('/body-references')));
  f.els.panel.dispatch('change', { target: { dataset: { servicePacketInspect: 'true' }, value: 'body' } });
  assert.equal(f.requests.length, 4);
  const read = f.requests.at(-1), url = new URL(read.url, 'http://localhost');
  assert.equal(url.pathname, '/api/target/service-map/body-references');
  assert.deepEqual(Object.fromEntries(url.searchParams), { session_id: 'session-one', evidence_id: 'evidence-one' });
  assert.equal(read.options.method, undefined);
  read.resolve(response(bodyReferences())); await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.bodyReferences.status, 'scanned');
});

test('body references remain supplemental plaintext evidence', async () => {
  const f = await verifiedBodyFixture(), graph = f.els.canvas.innerHTML, graphBounds = boundsText(f);
  const payload = bodyReferences({ raw_body: 'private synthetic content', response: { body_preview: 'not for the inspector' } });
  await resolveBodyReferences(f, payload);
  assert.match(f.els.detail.innerHTML, /2 literal URL occurrences/);
  assert.match(f.els.detail.innerHTML, /https:\/\/assets\.example\.com/);
  assert.match(f.els.detail.innerHTML, /2 occurrences</);
  assert.match(f.els.detail.innerHTML, /Complete retained-preview scan/);
  assert.match(f.els.detail.innerHTML, /zero-based bytes relative to the retained UTF-8 preview/);
  assert.doesNotMatch(f.els.detail.innerHTML, /href=|src=|private synthetic|not for the inspector/);
  assert.doesNotMatch(JSON.stringify(f.state.bodyReferences), /raw_body|response|private synthetic/);
  assert.equal(f.els.canvas.innerHTML, graph); assert.equal(boundsText(f), graphBounds);
  assert.equal(f.requests.length, 3);
});

test('body inspection deduplicates loading clicks and retries only on an explicit request', async () => {
  const f = await verifiedBodyFixture(); const first = f.controller.loadBodyReferences();
  assert.equal(f.state.bodyReferencesLoading, true);
  assert.match(f.els.detail.innerHTML, /aria-busy="true"/);
  await f.controller.loadBodyReferences(); await f.controller.loadBodyReferences();
  assert.equal(f.requests.length, 3);
  f.requests.at(-1).reject(new Error('private synthetic body')); await first;
  assert.match(f.els.detail.innerHTML, /Could not verify retained body references/);
  assert.doesNotMatch(f.els.detail.innerHTML, /data-service-body-references="inspect"/);
  assert.doesNotMatch(f.els.detail.innerHTML, /private synthetic body/);
  f.els.search.dispatch('input'); f.controller.setVisible(true);
  assert.equal(f.requests.length, 3);
  await resolveBodyReferences(f); assert.equal(f.requests.length, 4);
  assert.equal(f.state.bodyReferencesError, '');
});

for (const [name, change] of [
  ['wrong schema', p => { p.schema_version = 2; }],
  ['wrong session', p => { p.session_id = 'session-two'; }],
  ['wrong exact token', p => { p.evidence_id = 'other-evidence'; }],
  ['wrong source origin', p => { p.source_origin = originB; }],
  ['missing source origin', p => { delete p.source_origin; }],
  ['wrong exact sequence', p => { p.source_sequence = '9007199254740992'; }],
  ['numeric sequence', p => { p.source_sequence = 9007199254740993; }],
  ['changed capture time', p => { p.source_started_at = '2026-10-12T02:00:00Z'; }],
  ['unknown status', p => { p.status = 'complete'; }],
  ['wrong available flag', p => { p.available = false; }],
  ['wrong complete flag', p => { p.complete = false; }],
  ['wrong coverage', p => { p.coverage = 'inferred_urls'; }],
  ['wrong offset basis', p => { p.offset_basis = 'raw_response'; }],
  ['noncanonical target with credentials', p => { p.references[0].target_origin = 'https://user:pass@assets.example.com'; }],
  ['noncanonical target path', p => { p.references[0].target_origin = 'https://assets.example.com/path?private=value'; }],
  ['noncanonical target case', p => { p.references[0].target_origin = 'https://ASSETS.example.com'; }],
  ['non-HTTP target', p => { p.references[0].target_origin = 'javascript:alert(1)'; }],
  ['duplicate origins', p => { p.references.push({ ...p.references[0] }); }],
  ['too many origins', p => { p.references = Array.from({ length: 101 }, (_, i) => ({ ...p.references[0], target_origin: `https://r${i}.example.com` })); }],
  ['too many offsets', p => { p.references[0].preview_byte_offsets = [1, 2, 3, 4, 5, 6]; }],
  ['negative offset', p => { p.references[0].preview_byte_offsets[0] = -1; }],
  ['out-of-range offset', p => { p.references[0].preview_byte_offsets[1] = 300; }],
  ['unordered offsets', p => { p.references[0].preview_byte_offsets = [148, 24]; }],
  ['unsafe occurrence count', p => { p.references[0].occurrences = Number.MAX_SAFE_INTEGER + 1; }],
  ['wrong omitted offset count', p => { p.references[0].omitted_offsets = 1; }],
  ['wrong scan limit', p => { p.limits.scan_bytes += 1; }],
  ['oversized scan', p => { p.scanned_bytes = 262145; }],
  ['unsafe retained preview count', p => { p.retained_preview_bytes = Number.MAX_SAFE_INTEGER + 1; }],
  ['scan beyond retained preview', p => { p.retained_preview_bytes = 299; }],
  ['too many candidates', p => { p.candidates_scanned = 4097; }],
  ['too many omitted references', p => { p.omitted_reference_occurrences = 100; }],
  ['reference count exceeds candidates', p => { p.candidates_scanned = 1; }],
  ['raw content in reason', p => { p.reasons = ['https://private.example.com/raw']; }],
  ['truncated scan called complete', p => { p.capture_preview_truncated = true; }],
  ['partial without reason', p => { p.status = 'partial'; p.complete = false; }],
  ['partial with acquisition failure', p => { p.status = 'partial'; p.complete = false; p.reasons = ['record_missing']; }],
  ['partial with unknown lowercase reason', p => { p.status = 'partial'; p.complete = false; p.reasons = ['synthetic_private_value']; }],
  ['unsupported with references', p => { p.status = 'unsupported'; p.available = false; p.complete = false; }],
]) test(`retained body-reference validation rejects ${name}`, async () => {
  const f = await verifiedBodyFixture(), p = bodyReferences(); change(p);
  await resolveBodyReferences(f, p);
  assert.equal(f.state.bodyReferences, null);
  assert.match(f.state.bodyReferencesError, /Could not verify/);
  assert.doesNotMatch(f.els.detail.innerHTML, /user:pass|private\.example|alert\(1\)/);
  assert.equal(f.requests.length, 3);
});

for (const [name, change] of [
  ['origin selection', f => f.controller.selectOrigin(originB)],
  ['endpoint selection', f => f.controller.selectOrigin(originA)],
  ['another evidence request', f => f.controller.loadEvidence('evidence-one')],
  ['session reset', f => { f.setSession('session-two'); f.controller.reset(); }],
  ['unannounced session transition', f => f.setSession('session-two')],
  ['history changes', f => f.controller.markDirty()],
  ['retention invalidation', f => f.controller.invalidate()],
  ['scope change', f => { f.els.scope.dispatch('click'); }],
  ['map refresh', f => f.controller.refresh({ force: true })],
  ['hidden map', f => f.controller.setVisible(false)],
]) test(`late body-reference responses cannot publish after ${name}`, async () => {
  const f = await verifiedBodyFixture(), parsing = deferred();
  const pending = f.controller.loadBodyReferences(), request = f.requests.at(-1);
  request.resolve({ ok: true, json: () => parsing.promise }); await Promise.resolve();
  change(f); parsing.resolve(bodyReferences()); await pending;
  assert.equal(f.state.bodyReferences, null);
  assert.doesNotMatch(f.els.detail.innerHTML, /assets\.example\.com/);
  if (name !== 'unannounced session transition') assert.equal(request.options.signal.aborted, true);
});

test('previous body-reference result clears immediately when exact source is invalidated', async () => {
  const f = await verifiedBodyFixture(); await resolveBodyReferences(f);
  f.controller.markDirty();
  assert.equal(f.state.bodyReferences, null); assert.equal(f.state.evidence, null);
  assert.doesNotMatch(f.els.detail.innerHTML, /data-service-body-references|assets\.example\.com/);
});

test('a newer body-reference read wins even if the cancelled read finishes last', async () => {
  const f = await verifiedBodyFixture(), first = f.controller.loadBodyReferences(), old = f.requests.at(-1);
  const sourceRead = f.controller.loadEvidence('evidence-one'); f.requests.at(-1).resolve(response(evidence())); await sourceRead;
  await resolveBodyReferences(f, bodyReferences({ candidates_scanned: 0, references: [] }));
  old.resolve(response(bodyReferences())); await first;
  assert.equal(f.state.bodyReferences.references.length, 0);
  assert.match(f.els.detail.innerHTML, /No literal absolute HTTP\(S\) URL references found/);
});

for (const status of ['unsupported', 'unavailable']) test(`${status} retained previews are distinct from a successful zero-reference scan`, async () => {
  const f = await verifiedBodyFixture();
  const p = bodyReferences({ status, available: false, complete: false, reasons: [status === 'unsupported' ? 'unsupported_content_type' : 'body_storage_unavailable'],
    references: [], scanned_bytes: 0, candidates_scanned: 0 });
  delete p.retained_preview_bytes; delete p.source_origin; delete p.source_sequence; delete p.source_started_at;
  await resolveBodyReferences(f, p);
  assert.equal(f.state.bodyReferences.status, status);
  assert.match(f.els.detail.innerHTML, new RegExp(`Retained preview is ${status}`));
  assert.doesNotMatch(f.els.detail.innerHTML, /No literal absolute HTTP\(S\) URL references found|Complete retained-preview scan/);
});

test('partial output exposes truncation, omissions, long origins and full independent limits', async () => {
  const f = await verifiedBodyFixture(), longOrigin = `https://${['a'.repeat(50), 'b'.repeat(50), 'c'.repeat(50), 'd'.repeat(50)].join('.')}.example.com`;
  const refs = Array.from({ length: 100 }, (_, i) => ({ target_origin: i ? `https://reference${i}.example.com` : longOrigin, occurrences: 7, preview_byte_offsets: [1, 25, 55, 80, 140], omitted_offsets: 2 }));
  await resolveBodyReferences(f, bodyReferences({ status: 'partial', complete: false,
    reasons: ['candidate_limit', 'capture_preview_truncated', 'offset_limit', 'origin_limit', 'scan_prefix_truncated'],
    retained_preview_bytes: 300000, scanned_bytes: 262144, candidates_scanned: 4096, omitted_reference_occurrences: 30,
    capture_preview_truncated: true, scan_prefix_truncated: true, references: refs }));
  assert.equal(f.state.bodyReferences.references.length, 100);
  assert.match(f.els.detail.innerHTML, /100 referenced origins · 700 literal URL occurrences/);
  assert.match(f.els.detail.innerHTML, /Partial retained-preview scan/);
  assert.match(f.els.detail.innerHTML, /30 reference occurrences omitted/);
  assert.match(f.els.detail.innerHTML, /Scan: 262,144 bytes · Serialized row read: 2,097,152 bytes · Origins: 100 · URL candidates: 4,096 · Candidate: 4,096 bytes · Offsets per origin: 5/);
  assert.ok(f.els.detail.innerHTML.includes(longOrigin));
  assert.equal((f.els.detail.innerHTML.match(/class="service-map-body-reference-origin"/g) || []).length, 100);
  assert.equal(f.state.snapshot.origins.length, 2);
  const styles = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
  assert.match(styles, /\.service-map-body-reference-list \{[^}]*max-height: 300px;[^}]*overflow: auto;/);
  assert.match(styles, /\.service-map-body-reference-list span \{[^}]*overflow-wrap: anywhere;/);
});


test('resident previews can exceed the serialized disk-read ceiling while scanning remains bounded', async () => {
  const f = await verifiedBodyFixture();
  await resolveBodyReferences(f, bodyReferences({ status: 'partial', complete: false, reasons: ['scan_prefix_truncated'],
    retained_preview_bytes: 3000000, scanned_bytes: 262144, scan_prefix_truncated: true }));
  assert.equal(f.state.bodyReferences.retained_preview_bytes, 3000000);
  assert.match(f.els.detail.innerHTML, /262,144 \/ 3,000,000 UTF-8 preview bytes inspected/);
});

test('canonical omitted references cannot exceed the inspected candidate budget', async () => {
  const f = await verifiedBodyFixture();
  await resolveBodyReferences(f, bodyReferences({ status: 'partial', complete: false, reasons: ['origin_limit'],
    retained_preview_bytes: 100000, scanned_bytes: 100000, candidates_scanned: 4096, omitted_reference_occurrences: 4095 }));
  assert.equal(f.state.bodyReferences, null);
  assert.match(f.state.bodyReferencesError, /Could not verify/);
});

function pollRealTargetMap(f) {
  // The controller now owns periodic reads. Its deterministic clock lifecycle
  // is exercised separately in service-map-auto-refresh.test.cjs.
  return f.controller.refresh();
}

function clickBodyInspector(f) {
  f.els.panel.dispatch('change', { target: { dataset: { servicePacketInspect: 'true' }, value: 'body' } });
}
test('real app background polling preserves body results produced by the delegated Inspect click', async () => {
  const f = await verifiedBodyFixture(); clickBodyInspector(f);
  f.requests.at(-1).resolve(response(bodyReferences())); await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.bodyReferences.status, 'scanned');
  const replacements = f.els.detail.replacements;
  for (let i = 0; i < 4; i++) {
    const poll = pollRealTargetMap(f);
    f.requests.at(-1).resolve(response(snapshot())); await poll;
    assert.equal(f.state.bodyReferences?.status, 'scanned');
    assert.equal(f.els.detail.replacements, replacements);
  }
  assert.match(f.els.detail.innerHTML, /https:\/\/assets\.example\.com/);
  assert.equal(f.requests.filter(item => item.url.includes('/body-references')).length, 1);
});


test('delegated Inspect during a background poll stays enabled and can finish after repeated unchanged polls', async () => {
  const f = await verifiedBodyFixture(); const firstPoll = pollRealTargetMap(f), mapRead = f.requests.at(-1);
  assert.equal(f.state.loading, true);
  assert.doesNotMatch(f.els.detail.innerHTML, /data-service-body-references="inspect"[^>]*disabled/);
  clickBodyInspector(f); const bodyRead = f.requests.at(-1);
  assert.match(bodyRead.url, /body-references/); assert.equal(f.state.bodyReferencesLoading, true);
  mapRead.resolve(response(snapshot())); await firstPoll;
  for (let i = 0; i < 3; i++) {
    const poll = pollRealTargetMap(f); f.requests.at(-1).resolve(response(snapshot())); await poll;
    assert.equal(bodyRead.options.signal.aborted, false); assert.equal(f.state.bodyReferencesLoading, true);
  }
  bodyRead.resolve(response(bodyReferences())); await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.bodyReferences.status, 'scanned');
  assert.equal(f.requests.filter(item => item.url.includes('/body-references')).length, 1);
});

test('explicit force refresh clears a completed inspection without starting a body read', async () => {
  const f = await verifiedBodyFixture(); await resolveBodyReferences(f);
  const refresh = f.controller.refresh({ force: true });
  assert.equal(f.state.bodyReferences, null); assert.doesNotMatch(f.els.detail.innerHTML, /assets\.example\.com/);
  f.requests.at(-1).resolve(response(snapshot())); await refresh;
  assert.equal(f.requests.filter(item => item.url.includes('/body-references')).length, 1);
});

for (const change of ['generation', 'exact token']) test(`background poll changing ${change} clears the source and fences pending body inspection`, async () => {
  const f = await verifiedBodyFixture(); clickBodyInspector(f); const bodyRead = f.requests.at(-1);
  const view = nativeInspectorModel(f), previous = view();
  previous.limits.open = true; previous.body.scrollTop = 350; previous.summary.focus();
  const value = change === 'generation' ? snapshot(undefined, 'session-one', { generation: 'generation-two' })
    : snapshot([origin(originA, [endpoint('/users', 'GET', 'new-exact-token')]), origin(originB)]);
  const poll = pollRealTargetMap(f); f.requests.at(-1).resolve(response(value)); await poll;
  assert.equal(f.state.evidence, null); assert.equal(bodyRead.options.signal.aborted, true);
  assert.notEqual(view(), previous); assert.equal(previous.summary.isConnected, false);
  assert.equal(view().limits, null); assert.equal(view().body.scrollTop, 0);
  bodyRead.resolve(response(bodyReferences())); await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.bodyReferences, null); assert.doesNotMatch(f.els.detail.innerHTML, /assets\.example\.com/);
});

test('newly re-verified exact source can be inspected while only the map counts remain stale', async () => {
  const f = await verifiedBodyFixture(); f.controller.markDirty();
  assert.equal(f.state.evidence, null); assert.equal(f.state.stale, true);
  const verify = f.controller.loadEvidence('evidence-one'); f.requests.at(-1).resolve(response(evidence())); await verify;
  clickBodyInspector(f); const bodyRead = f.requests.at(-1);
  assert.match(bodyRead.url, /body-references/);
  bodyRead.resolve(response(bodyReferences())); await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.bodyReferences.status, 'scanned');
  assert.equal(f.state.stale, true);
});

test('native Coverage open attribute survives unchanged polling without replacing inspector DOM', async () => {
  const f = await verifiedBodyFixture(); await resolveBodyReferences(f);
  const nativeOpenHtml = f.els.detail.innerHTML.replace('<details class="service-map-body-reference-limits">', '<details class="service-map-body-reference-limits" open="">');
  f.els.detail.innerHTML = nativeOpenHtml;
  const replacements = f.els.detail.replacements;
  for (let i = 0; i < 3; i++) {
    const poll = pollRealTargetMap(f); f.requests.at(-1).resolve(response(snapshot())); await poll;
    assert.equal(f.els.detail.innerHTML, nativeOpenHtml);
    assert.equal(f.els.detail.replacements, replacements);
  }
});

// Model native DOM-owned state separately from generated markup. Replacing
// innerHTML creates fresh elements and loses focus/scroll/open, as a browser does.
function nativeInspectorModel(f) {
  const descriptor = Object.getOwnPropertyDescriptor(f.els.detail, 'innerHTML');
  const fresh = html => ({
    body: html.includes('service-map-detail-body') ? { scrollTop: 0 } : null,
    list: html.includes('class="service-map-body-reference-list"') ? { scrollTop: 0 } : null,
    limits: html.includes('class="service-map-body-reference-limits"') ? { open: false } : null,
    summary: html.includes('data-service-focus="body-references:limits"') ? {
      dataset: { serviceFocus: 'body-references:limits' }, isConnected: true,
      getClientRects: () => [{}], focus() { f.document.activeElement = this; },
    } : null,
  });
  let current = fresh(f.els.detail.innerHTML);
  f.els.detail.querySelector = selector => current[{
    '.service-map-detail-body': 'body', '.service-map-body-reference-list': 'list', '.service-map-body-reference-limits': 'limits',
  }[selector]] || null;
  f.els.detail.querySelectorAll = () => current.summary ? [current.summary] : [];
  Object.defineProperty(f.els.detail, 'innerHTML', {
    get: descriptor.get,
    set(html) {
      if (current.summary) current.summary.isConnected = false;
      if (f.document.activeElement === current.summary) f.document.activeElement = f.document.body;
      descriptor.set.call(this, html); current = fresh(html);
    },
  });
  return () => current;
}

test('unchanged polls preserve nested scroll and native-normalized loading markup', async () => {
  const f = await verifiedBodyFixture(); clickBodyInspector(f); const bodyRead = f.requests.at(-1);
  const view = nativeInspectorModel(f); view().limits.open = true; view().body.scrollTop = 240;
  // Boolean attributes and insignificant spaces normalize when assigned to DOM.
  f.els.detail.innerHTML = f.els.detail.innerHTML.replace(/ disabled>/g, ' disabled="">').replace(/inspect" >/g, 'inspect">');
  view().limits.open = true; view().body.scrollTop = 240;
  const before = f.els.detail.replacements;
  const poll = pollRealTargetMap(f); f.requests.at(-1).resolve(response(snapshot())); await poll;
  assert.equal(f.els.detail.replacements, before);
  assert.equal(view().limits.open, true); assert.equal(view().body.scrollTop, 240);
  bodyRead.resolve(response(bodyReferences())); await new Promise(resolve => setImmediate(resolve));
  assert.equal(view().limits.open, true); assert.equal(view().body.scrollTop, 240);
});

test('explicit inspector pagination returns 50-to-5 and Previous to the endpoint header while polls retain scroll', async () => {
  const f = fixture(), data = snapshot([origin(originA, Array.from({ length: 55 }, (_, index) => endpoint(`/path-${index}`)))]);
  const view = nativeInspectorModel(f); await f.load(data);
  view().body.scrollTop = 2800; f.els.viewport.scrollTop = 95; f.els.catalog.scrollTop = 150;
  const clickPage = page => { const target = { dataset: { serviceDetailPage: String(page) }, closest: () => target }; f.els.panel.dispatch('click', { target }); };
  clickPage(1);
  assert.equal(f.state.detailPage, 1); assert.equal(view().body.scrollTop, 0);
  assert.equal((f.els.detail.innerHTML.match(/data-service-endpoint=/g) || []).length, 5);
  view().body.scrollTop = 210;
  const current = view(); await f.load(data);
  assert.equal(view(), current); assert.equal(view().body.scrollTop, 210);
  data.origins[0].request_count += 1; await f.load(data);
  assert.notEqual(view(), current); assert.equal(view().body.scrollTop, 210, 'same-source changed polls retain scroll too');
  clickPage(0);
  assert.equal(f.state.detailPage, 0); assert.equal(view().body.scrollTop, 0);
  assert.equal((f.els.detail.innerHTML.match(/data-service-endpoint=/g) || []).length, 50);
  assert.equal(f.els.viewport.scrollTop, 95); assert.equal(f.els.catalog.scrollTop, 150);
  assert.equal(f.requests.length, 3, 'pagination stays local');
});

test('same-source output changes retain Coverage keyboard focus, disclosure and both scroll positions', async () => {
  const f = await verifiedBodyFixture(); await resolveBodyReferences(f);
  const view = nativeInspectorModel(f), previous = view();
  previous.limits.open = true; previous.body.scrollTop = 350; previous.list.scrollTop = 110;
  f.document.activeElement = previous.summary;
  const data = snapshot(); data.origins[0].in_scope = false;
  const poll = pollRealTargetMap(f); f.requests.at(-1).resolve(response(data)); await poll;
  assert.notEqual(view(), previous);
  assert.equal(view().limits.open, true);
  assert.equal(view().body.scrollTop, 350); assert.equal(view().list.scrollTop, 110);
  assert.equal(f.document.activeElement, view().summary);
  assert.match(f.els.detail.innerHTML, /data-service-focus="body-references:limits"/);
  assert.match(f.els.detail.innerHTML, /Out of scope/);
});

test('source invalidation resets Coverage and nested scroll instead of transferring native state', async () => {
  const f = await verifiedBodyFixture(); await resolveBodyReferences(f);
  const view = nativeInspectorModel(f);
  view().limits.open = true; view().list.scrollTop = 110; view().body.scrollTop = 350;
  f.controller.markDirty(); assert.equal(view().limits, null);
  const verify = f.controller.loadEvidence('evidence-one'); f.requests.at(-1).resolve(response(evidence())); await verify;
  assert.equal(view().limits, null); assert.equal(view().body.scrollTop, 0);
  await resolveBodyReferences(f);
  assert.equal(view().limits.open, false); assert.equal(view().list.scrollTop, 0);
});

test('the existing native Relation details footer stays open through metadata polling', async () => {
  const f = await verifiedBodyFixture(); pin(f, originA);
  f.els.boundsDetails.open = true;
  const before = f.els.boundsDetails.replacements;
  const poll = pollRealTargetMap(f); f.requests.at(-1).resolve(response(snapshot())); await poll;
  assert.equal(f.els.boundsDetails.open, true); assert.equal(f.els.boundsDetails.replacements, before);
  assert.equal(f.els.boundsDetails.classList.contains('hidden'), false);
});

test('same exact source keeps native inspector state when its selected endpoint moves to another index', async () => {
  const f = await verifiedBodyFixture(); await resolveBodyReferences(f);
  const view = nativeInspectorModel(f);
  f.els.detail.innerHTML = f.els.detail.innerHTML.replace('<details class="service-map-body-reference-limits">', '<details class="service-map-body-reference-limits" open="">');
  const previous = view(); previous.limits.open = true; previous.list.scrollTop = 110; previous.body.scrollTop = 350;
  f.document.activeElement = previous.summary;
  const replacements = f.els.detail.replacements;
  const data = snapshot([origin(originA, [endpoint('/inserted', 'GET', 'inserted-source'), endpoint()]), origin(originB)]);
  const poll = pollRealTargetMap(f); f.requests.at(-1).resolve(response(data)); await poll;
  assert.equal(f.state.endpointIndex, 1); assert.equal(f.state.endpointSelection.path, '/users');
  assert.equal(f.state.evidenceId, 'evidence-one'); assert.equal(f.state.bodyReferences.status, 'scanned');
  assert.equal(f.els.detail.replacements, replacements); assert.equal(view(), previous);
  assert.equal(view().limits.open, true); assert.equal(view().list.scrollTop, 110); assert.equal(view().body.scrollTop, 350);
  assert.equal(f.document.activeElement, previous.summary);
  assert.equal(f.requests.filter(item => item.url.includes('/body-references')).length, 1);
});


test('the map carries no explanatory footer; only errors and the first load show above it', () => {
  const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  assert.doesNotMatch(html, /service-map-notice|Explicitly inspect a source/);
  assert.match(html, /<div class="service-map-alert hidden" id="serviceMapAlert" role="status" aria-live="polite"><\/div>/);
  assert.doesNotMatch(html, /they are not added to this map/);
  assert.doesNotMatch(html, /Response-body reference extraction is deferred/);
});

function clickOverlay(f, action = 'show') {
  const dataset = action === 'show' ? { serviceShowBodyReferences: 'show' } : { serviceClearBodyReferences: 'clear' };
  f.els.panel.dispatch('click', { target: { closest: () => ({ dataset }) } });
}
function bodyTargets(ids) {
  return ids.map((target_origin, i) => ({ target_origin, occurrences: 1, preview_byte_offsets: [i + 1], omitted_offsets: 0 }));
}
async function inspectSource(f, id = 'evidence-one', source = originA, extra = {}) {
  f.controller.selectOrigin(source);
  const read = f.controller.loadEvidence(id); f.requests.at(-1).resolve(response(evidence(id, source, extra))); await read;
}

test('explicit Show and Clear are local, keep All origins default, and remove only a selected overlay-only target', async () => {
  const f = await verifiedBodyFixture(); await resolveBodyReferences(f);
  assert.equal(f.state.anchorOrigin, null); assert.equal(f.state.bodyReferenceOverlay, null);
  assert.doesNotMatch(f.els.canvas.innerHTML, /assets.example.com/);
  const reads = f.requests.length; clickOverlay(f);
  assert.equal(f.state.anchorOrigin, originA);
  assert.equal(f.state.bodyReferenceOverlay.source.evidenceId, 'evidence-one');
  assert.equal(f.els.allOrigins.attributes['aria-pressed'], 'true', 'pinned is still the Origins view');
  assert.equal(f.els.directRelations.attributes['aria-pressed'], 'true');
  assert.deepEqual(new Set(cardIds(f)), new Set([originA, 'https://assets.example.com']));
  assert.match(f.els.canvas.innerHTML, /data-relationship="body_url_reference"/);
  f.controller.selectOrigin('https://assets.example.com');
  assert.equal(f.state.bodyReferences, null, 'inspector is independent from the copied overlay');
  assert.match(f.els.detail.innerHTML, /Literal body URL reference/);
  assert.match(f.els.detail.innerHTML, /[Ss]equence 9007199254740993/);
  clickOverlay(f, 'clear');
  assert.equal(f.state.bodyReferenceOverlay, null); assert.equal(f.state.selectedOrigin, null);
  assert.equal(f.state.anchorOrigin, originA);
  assert.match(f.els.detail.innerHTML, /Select an origin/);
  assert.match(f.els.overlayStatus.innerHTML, /Showing loaded metadata only/);
  assert.deepEqual(cardIds(f), [originA]);
  assert.equal(f.requests.length, reads);
  assert.equal(f.controller.showBodyReferencesOnMap(), false, 'clearing cannot resurrect discarded inspector data');
});

test('overlay owns an immutable allowlisted exact source, safe provenance, and partial scan copy', async () => {
  const f = fixture(); await f.load();
  const row = { ...evidence().row, path: '/users?private=secret#fragment', private_header: 'never-copy' };
  await inspectSource(f, 'evidence-one', originA, { row });
  const payload = bodyReferences({ status: 'partial', complete: false, reasons: ['capture_preview_truncated'], capture_preview_truncated: true,
    raw_url: 'https://user:password@assets.example.com/private?secret=1', raw_body: 'never-copy' });
  await resolveBodyReferences(f, payload); clickOverlay(f);
  const overlay = f.state.bodyReferenceOverlay;
  assert.equal(overlay.source.sequence, '9007199254740993');
  assert.equal(overlay.source.path, '/users');
  assert.equal(overlay.source.sessionId, 'session-one'); assert.equal(overlay.source.generation, 'generation-one');
  for (const item of [overlay, overlay.source, overlay.scan, overlay.scan.references, overlay.scan.references[0], overlay.scan.references[0].preview_byte_offsets, overlay.scan.reasons]) assert.equal(Object.isFrozen(item), true);
  assert.doesNotMatch(JSON.stringify(overlay), /secret|password|never-copy|private_header|raw_url|raw_body/);
  assert.match(f.els.overlayStatus.innerHTML, /Partial retained-preview scan/);
  assert.match(f.els.overlayStatus.innerHTML, /2026-10-12T01:00:00Z/);
  assert.doesNotMatch(f.els.overlayStatus.innerHTML, /secret|fragment/);
  f.state.bodyReferences.references[0].target_origin = 'https://mutated.example.com';
  f.state.evidence.path = '/different'; payload.references[0].preview_byte_offsets[0] = 10;
  f.controller.selectOrigin(originB);
  assert.equal(f.state.bodyReferenceOverlay, overlay);
  assert.equal(overlay.scan.references[0].target_origin, 'https://assets.example.com');
  assert.equal(overlay.scan.references[0].preview_byte_offsets[0], 24);
  assert.equal(overlay.source.path, '/users');
});

for (const [name, refs, hint] of [
  ['zero', [], /There are no referenced origins/],
  ['self-only', bodyTargets([originA]), /Only the source origin was referenced; self-links are not drawn/],
]) test(`${name} scan omits unusable Show with useful copy and never creates an overlay`, async () => {
  const f = await verifiedBodyFixture();
  await resolveBodyReferences(f, bodyReferences({ candidates_scanned: refs.length, references: refs }));
  assert.doesNotMatch(f.els.detail.innerHTML, /data-service-show-body-references="show"/);
  assert.match(f.els.detail.innerHTML, hint);
  const reads = f.requests.length; clickOverlay(f);
  assert.equal(f.state.bodyReferenceOverlay, null); assert.equal(f.state.anchorOrigin, null);
  assert.equal(f.requests.length, reads);
});

test('100 body origins retain the source and prioritize 23 reference cards with honest unique counts', async () => {
  const f = fixture(), source = origin(originA);
  source.redirects = Array.from({ length: 100 }, (_, i) => redirect(`https://metadata${String(i).padStart(3, '0')}.example.com`));
  await f.load(snapshot([source])); await inspectSource(f);
  const refs = bodyTargets(Array.from({ length: 100 }, (_, i) => `https://body${String(i).padStart(3, '0')}.example.com`));
  await resolveBodyReferences(f, bodyReferences({ references: refs, candidates_scanned: 100 })); clickOverlay(f);
  assert.equal(cardIds(f).length, 24); assert.equal(cardIds(f)[0], originA);
  assert.ok(cardIds(f).slice(1).every(id => id.includes('body')));
  assert.match(boundsText(f), /200 known direct neighbors/);
  assert.match(boundsText(f), /100 metadata \/ 100 body URL links/);
  assert.match(boundsText(f), /177 omitted by 24-card cap/);
  assert.equal((f.els.canvas.innerHTML.match(/data-relationship="body_url_reference"/g) || []).length, 23);
  assert.equal(f.state.graphOriginsCache.length, 201, 'inspected targets coexist with the 100 metadata reference slots');
  f.els.search.value = 'body099'; f.els.search.dispatch('input');
  assert.deepEqual(cardIds(f), [originA, refs[99].target_origin]);
  f.controller.selectOrigin(refs[99].target_origin);
  assert.match(f.els.detail.innerHTML, /Literal body URL reference/);
  assert.doesNotMatch(f.els.detail.innerHTML, /sampled HTTP rows|sampled rows|API paths/);
  assert.doesNotMatch(f.els.catalog.innerHTML, /body099/);
  clickOverlay(f, 'clear'); assert.equal(f.state.selectedOrigin, null);
  assert.equal(f.requests.length, 3);
});

test('body arrows keep their type and metadata arrows merge per direction, with bounded distinct curves under 40 arrows', async () => {
  const f = fixture(), source = origin(originA), peers = Array.from({ length: 23 }, (_, i) => origin(`https://peer${String(i).padStart(2, '0')}.example.com`));
  peers.forEach(peer => { peer.header_links = [header(originA), header(originA, 'referer_header')]; source.redirects.push(redirect(peer.origin)); });
  await f.load(snapshot([source, ...peers])); await inspectSource(f);
  await resolveBodyReferences(f, bodyReferences({ references: bodyTargets(peers.map(item => item.origin)), candidates_scanned: 23 })); clickOverlay(f);
  assert.match(boundsText(f), /23 known direct neighbors/);
  assert.match(boundsText(f), /69 metadata \/ 23 body URL links/);
  assert.match(boundsText(f), /40 \/ 46 arrows/);
  assert.match(boundsText(f), /6 arrows omitted by 40-arrow cap/);
  const arrows = [...f.els.canvas.innerHTML.matchAll(/<path class="service-map-edge ([^"]*)" data-relationship="([^"]+)"(?: style="[^"]*")? d="([^"]+)"[^>]*><title>([^<]+)<\/title>/g)];
  assert.equal(arrows.length, 40);
  assert.equal(arrows.filter(item => item[2] === 'body_url_reference').length, 23);
  f.els.search.value = 'peer00'; f.els.search.dispatch('input');
  const pair = [...f.els.canvas.innerHTML.matchAll(/<path class="service-map-edge ([^"]*)" data-relationship="([^"]+)"(?: style="[^"]*")? d="([^"]+)"[^>]*><title>([^<]+)<\/title>/g)];
  assert.equal(pair.length, 2, 'the body arrow, and one arrow for the redirect, Origin and Referer');
  assert.equal(new Set(pair.map(item => item[3])).size, 2, 'same directed pair has distinct bounded curves');
  assert.equal(new Set(pair.map(item => item[2])).size, 2);
  f.controller.selectOrigin(peers[0].origin);
  assert.match(f.els.detail.innerHTML, /2 sampled HTTP rows/);
  const reads = f.requests.length; clickOverlay(f, 'clear');
  assert.equal(f.state.selectedOrigin, peers[0].origin, 'captured target persists after Clear');
  assert.equal(f.requests.length, reads);
});

test('Show pins a source beyond the All origins card cap and search without transferring to inspected targets', async () => {
  const f = fixture(), origins = Array.from({ length: 30 }, (_, i) => origin(`https://node${String(i).padStart(2, '0')}.example.com`));
  const source = origins.at(-1).origin;
  await f.load(snapshot(origins)); await inspectSource(f, 'evidence-one', source);
  await resolveBodyReferences(f, bodyReferences({ source_origin: source }));
  f.els.search.value = 'assets'; f.els.search.dispatch('input'); clickOverlay(f);
  assert.deepEqual(cardIds(f), [source, 'https://assets.example.com']);
  assert.match(boundsText(f), /Pinned anchor is outside the search query/);
  const overlay = f.state.bodyReferenceOverlay;
  f.controller.selectOrigin('https://assets.example.com');
  assert.equal(f.state.anchorOrigin, source); assert.equal(f.state.bodyReferenceOverlay, overlay);
  f.els.search.value = 'missing'; f.els.search.dispatch('input');
  assert.deepEqual(cardIds(f), [source]); assert.match(boundsText(f), /1 hidden by query/);
  assert.equal(f.requests.length, 3);
});

for (const [name, clear] of [
  ['hidden map', f => f.controller.setVisible(false)],
  ['standalone APIs', f => f.controller.setVisible(true, 'apis')],
  ['transaction event', f => f.controller.markDirty()],
  ['disconnect', f => f.controller.disconnect()],
]) test(`${name} clears the overlay immediately without a body read or automatic recreation`, async () => {
  const f = await verifiedBodyFixture(); await resolveBodyReferences(f); clickOverlay(f);
  const reads = f.requests.length; clear(f);
  assert.equal(f.state.bodyReferenceOverlay, null);
  assert.doesNotMatch(f.els.canvas.innerHTML, /body_url_reference/);
  assert.match(f.els.overlayStatus.innerHTML, /(?:Shown|Affected) inspections (?:cleared|removed)/);
  f.controller.setVisible(true, 'service-map');
  assert.equal(f.state.bodyReferenceOverlay, null); assert.equal(f.requests.length, reads);
});

test('manual Clear preserves native inspector disclosure, focus and nested scroll', async () => {
  const f = await verifiedBodyFixture(), view = nativeInspectorModel(f);
  await resolveBodyReferences(f); clickOverlay(f);
  view().limits.open = true; view().body.scrollTop = 170; view().list.scrollTop = 65;
  f.document.activeElement = view().summary;
  clickOverlay(f, 'clear');
  assert.equal(view().limits.open, true); assert.equal(view().body.scrollTop, 170); assert.equal(view().list.scrollTop, 65);
  assert.equal(f.document.activeElement, view().summary);
  assert.equal(f.state.bodyReferences.status, 'scanned');
  assert.equal(f.requests.length, 3);
});

test('opposite-direction metadata and body links use bounded, non-overpainting attachment offsets', () => {
  const a = origin(originA), b = origin(originB);
  a.redirects = [redirect(originB)]; b.redirects = [redirect(originA)];
  a.header_links = [header(originB), header(originB, 'referer_header')];
  b.header_links = [header(originA), header(originA, 'referer_header')];
  const data = map.normalizeSnapshot(snapshot([a, b]), 'session-one');
  const layout = map.graphLayout(data.origins, [originA, originB], new Map(), originA,
    [{ source: originA, target: originB, relationship: 'body_url_reference', label: 'Literal body URL reference' }]);
  // Each direction's metadata is one arrow; the inspected body link keeps its own.
  assert.equal(layout.edges.length, 3);
  const offsets = layout.edges.map(edge => {
    const source = layout.nodes.find(node => node.origin === edge.source);
    return Number(edge.path.match(/^M [-\d.]+ ([-\d.]+)/)[1]) - source.y - map.GRAPH_GEOMETRY.cardHeight / 2;
  });
  assert.equal(new Set(offsets).size, 3);
  assert.ok(offsets.every(value => Math.abs(value) <= map.GRAPH_GEOMETRY.cardHeight * 0.3 + 0.001));
  assert.equal(layout.edges.filter(edge => edge.source === originA).length, 2);
  assert.equal(layout.edges.filter(edge => edge.source === originB).length, 1);
});

test('overlay direct star keeps the pinned source opposite every incoming and outgoing neighbor', async () => {
  const f = fixture(), a = origin(originA), b = origin(originB);
  a.header_links = [header(originB)]; a.redirects = [redirect(originB)];
  b.header_links = [header(originA), header(originA, 'referer_header')];
  await f.load(snapshot([a, b])); await inspectSource(f);
  await resolveBodyReferences(f, bodyReferences({ references: bodyTargets([originB, 'https://assets.example.com']), candidates_scanned: 2 }));
  clickOverlay(f);
  assert.equal(f.state.layoutSlots.get(originA).column, 0);
  for (const id of cardIds(f).filter(id => id !== originA)) assert.equal(f.state.layoutSlots.get(id).column, 1);
  const slots = JSON.stringify([...f.state.layoutSlots]);
  f.controller.selectOrigin(originB); assert.equal(JSON.stringify([...f.state.layoutSlots]), slots);
  await f.load(snapshot([a, b])); assert.equal(JSON.stringify([...f.state.layoutSlots]), slots);
});

function assertCanvasContainsGeometry(layout) {
  const { padding, columnPitch, cardWidth } = map.GRAPH_GEOMETRY;
  const columns = Math.max(1, ...[...layout.slots.values()].map(slot => slot.column));
  assert.equal(layout.width, padding * 2 + columns * columnPitch + cardWidth, 'the canvas is as wide as its columns; loop routing never widens it');
  for (const node of layout.nodes) {
    assert.ok(node.x >= 0 && node.x + map.GRAPH_GEOMETRY.cardWidth <= layout.width);
    assert.ok(node.y >= 0 && node.y + map.GRAPH_GEOMETRY.cardHeight <= layout.height);
  }
  for (const edge of layout.edges) {
    const points = edge.path.match(/-?\d+(?:\.\d+)?/g).map(Number);
    assert.equal(points.length, 8);
    // A cubic stays inside its control-point hull. Endpoint clearance also
    // includes the existing 8×8 arrow marker, regardless of its orientation.
    for (let i = 0; i < points.length; i += 2) {
      assert.ok(points[i] >= 8 && points[i] <= layout.width - 8, edge.path);
      assert.ok(points[i + 1] >= 8 && points[i + 1] <= layout.height - 8, edge.path);
    }
    for (const i of [0, 6]) assert.ok(points[i] >= 9 && points[i] <= layout.width - 9, edge.path);
    assert.notEqual(edge.source, edge.target, 'self links remain excluded');
  }
}

test('metadata chain reads left to right, one column per link, inside its canvas', () => {
  const a = origin('https://a.example.com'), b = origin('https://b.example.com'), c = origin('https://c.example.com');
  a.redirects = [redirect(b.origin)]; b.redirects = [redirect(c.origin)];
  c.header_links = [header(b.origin), header(b.origin, 'referer_header')];
  const data = map.normalizeSnapshot(snapshot([a, b, c]), 'session-one');
  const order = [a.origin, b.origin, c.origin];
  const layout = map.graphLayout(data.origins, order);
  assert.deepEqual([a, b, c].map(item => layout.slots.get(item.origin).column), [0, 1, 2]);
  assert.equal(layout.edges.length, 2, 'one arrow per direction'); assert.equal(new Set(layout.edges.map(edge => edge.path)).size, 2);
  assert.deepEqual([...layout.edges.map(edge => [...edge.relationships])], [['redirect_instruction'], ['redirect_instruction', 'origin_header', 'referer_header']]);
  assertCanvasContainsGeometry(layout);
  const refreshed = map.graphLayout(data.origins, order, layout.slots);
  assert.deepEqual([...refreshed.slots], [...layout.slots]);
  assertCanvasContainsGeometry(refreshed);
});

function flowStep(origin, method, path, status, kind, count = 1, extra = {}) {
  return { origin, method, path, status, request_kind: kind, count, first_seen: '2026-10-20T00:00:00Z', last_seen: '2026-10-20T00:00:01Z', evidence: ['evidence-one'], record_id: recordId, ...extra };
}
function flowPayload(session = 'session-one') {
  return { schema_version: 1, session_id: session, origin: originA, lanes: [originA, originB], considered_rows: 10, flow_rows: 7, complete: true, phases: [
    { page: { origin: originA, path: '/' }, steps: [flowStep(originA, 'GET', '/', 200, 'navigation'), flowStep(originB, 'GET', '/v1/config', 200, 'api', 3), flowStep(originB, 'GET', '/logo.png', 200, 'static', 2)] },
    { page: { origin: originB, path: '/login' }, steps: [flowStep(originB, 'GET', '/login', 302, 'navigation', 1, { redirect: { origin: originA, path: '/callback' } })] },
  ] };
}

test('a flow keeps its lanes, folds repeats, hides hidden kinds and draws a redirect back to the client', () => {
  const flow = map.normalizeFlow(flowPayload(), 'session-one', originA);
  assert.deepEqual([...flow.lanes], [originA, originB]);
  const layout = map.flowLayout(flow, ['static']);
  assert.equal(layout.bands.length, 2);
  assert.equal(layout.arrows.filter(arrow => !arrow.redirect).length, 3, 'the static step is hidden');
  assert.equal(layout.arrows.filter(arrow => arrow.redirect).length, 1);
  const markup = map.flowMarkup(layout);
  assert.match(markup, /GET \/v1\/config ×3 200/);
  assert.match(markup, /302 to app\.example\.com\/callback/);
  assert.doesNotMatch(markup, /logo\.png/);
  assert.match(markup, new RegExp(`data-service-flow-record="${recordId}"`));
  const mermaid = map.flowMermaid(flow, ['static']);
  assert.match(mermaid, /^sequenceDiagram\n/);
  assert.match(mermaid, /C->>O1: GET \/v1\/config ×3 200/);
  assert.match(mermaid, /O1-->>C: 302 to app\.example\.com\/callback/);
  assert.match(mermaid, /Note over C,O1: Page load: api\.example\.com\/login/);
  assert.equal(map.normalizeFlow({ ...flowPayload(), origin: originB }, 'session-one', originA), null, 'another origin');
  assert.equal(map.normalizeFlow(flowPayload('session-two'), 'session-one', originA), null, 'another session');
});

test('a flow draws method and status pills, each lane\'s requests and the time since the first request', () => {
  const payload = flowPayload();
  payload.phases[0].steps[1].first_seen = '2026-10-20T00:00:01.500Z';
  payload.phases[1].steps[0].first_seen = '2026-10-20T00:01:05Z';
  const markup = map.flowMarkup(map.flowLayout(map.normalizeFlow(payload, 'session-one', originA), ['static']));
  assert.match(markup, /service-map-flow-pill method-get/);
  assert.match(markup, /service-map-flow-pill status-ok/);
  assert.match(markup, /service-map-flow-pill status-info/, 'the 302');
  assert.match(markup, />×3</);
  assert.match(markup, />5 requests</, 'the client sent every shown request');
  assert.match(markup, />4 requests</, 'the API lane: the config three times and the login');
  for (const time of ['+0ms', '+1.5s', '+1m05s']) assert.ok(markup.includes(`>${time}<`), time);
  // WebKit draws no context-stroke marker, so heads are paths of their own.
  assert.doesNotMatch(markup, /marker-end/);
  assert.match(markup, /class="service-map-flow-head"/);
});

test('a flow draws its lane headers last, on a backdrop, so they can stay in view', () => {
  const markup = map.flowMarkup(map.flowLayout(map.normalizeFlow(flowPayload(), 'session-one', originA), []));
  const heads = markup.indexOf('class="service-map-flow-heads"');
  assert.ok(heads > markup.lastIndexOf('class="service-map-flow-step'), 'the headers paint over the steps');
  assert.match(markup.slice(heads), /service-map-flow-heads-backdrop/);
  assert.match(markup.slice(heads), />Client</);
  // Scrolled 300px down at half size, the headers move 600 flow units.
  assert.equal(map.flowHeadsOffset(100, -200, 0.5), 600);
  assert.equal(map.flowHeadsOffset(100, 140, 1), 0, 'not yet scrolled past');
});

test('Origins and Flow are the views; Direct relations and Copy Mermaid sit in the view they belong to', async () => {
  const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  const toolbar = html.slice(html.indexOf('id="serviceMapViewControls"'), html.indexOf('id="serviceMapZoomControls"'));
  assert.match(toolbar, /id="serviceMapAllOrigins"[^>]*>Origins</);
  assert.match(toolbar, /id="serviceMapFlow"/);
  assert.doesNotMatch(toolbar, /serviceMapDirectRelations|serviceMapFocusSelection|serviceMapFlowMermaid/);
  const legend = html.slice(html.indexOf('class="service-map-legend"'), html.indexOf('id="serviceMapResizer"'));
  for (const id of ['serviceMapDirectRelations', 'serviceMapFocusSelection', 'serviceMapFlowMermaid']) assert.match(legend, new RegExp(`id="${id}"`), id);
  const f = fixture();
  await f.load(); f.controller.selectOrigin(originA);
  f.els.directRelations.dispatch('click');
  assert.equal(f.state.anchorOrigin, originA);
  f.els.directRelations.dispatch('click');
  assert.equal(f.state.anchorOrigin, null, 'a second press turns it off');
  f.els.flow.dispatch('click');
  f.requests.at(-1).resolve(response(flowPayload()));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.els.allOrigins.attributes['aria-pressed'], 'false');
  assert.equal(f.els.directRelations.classList.contains('hidden'), true);
  assert.equal(f.els.flowMermaid.classList.contains('hidden'), false);
  f.els.allOrigins.dispatch('click');
  assert.equal(f.els.flowMermaid.classList.contains('hidden'), true);
  assert.equal(f.els.directRelations.classList.contains('hidden'), false);
});

test('in Flow the kind toggles count the flow\'s requests and the legend shows Flow lines', async () => {
  const f = fixture();
  const legend = node();
  f.els.linkKinds.parentElement = legend;
  await f.load(); f.controller.selectOrigin(originA);
  f.els.flow.dispatch('click');
  f.requests.at(-1).resolve(response(flowPayload()));
  await new Promise(resolve => setImmediate(resolve));
  assert.match(f.els.linkKinds.innerHTML, /Requests:/);
  assert.match(f.els.linkKinds.innerHTML, /API calls 3/);
  assert.match(f.els.linkKinds.innerHTML, /Static files 2/);
  assert.equal(legend.classList.contains('flow-active'), true);
  f.els.allOrigins.dispatch('click');
  assert.doesNotMatch(f.els.linkKinds.innerHTML, /Requests:/);
  assert.equal(legend.classList.contains('flow-active'), false);
});

test('Flow reads the selected origin and opens a step in HTTP history', async () => {
  const opened = [];
  const f = fixture({ openInHistory: id => opened.push(id) });
  await f.load(); f.controller.selectOrigin(originA);
  f.els.flow.dispatch('click');
  const request = f.requests.at(-1);
  assert.match(request.url, /^\/api\/target\/service-map\/flow\?/);
  const params = new URL(request.url, 'http://localhost').searchParams;
  assert.deepEqual([params.get('origin'), params.get('session_id'), params.get('max_records')], [originA, 'session-one', '50000']);
  request.resolve(response(flowPayload()));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.els.flow.attributes['aria-pressed'], 'true');
  assert.match(f.els.canvas.innerHTML, /service-map-flow/);
  const step = { dataset: { serviceFlowRecord: recordId }, closest: selector => selector.includes('[data-service-flow-record]') ? step : null };
  f.els.panel.dispatch('click', { target: step });
  assert.deepEqual(opened, [recordId]);
  f.els.allOrigins.dispatch('click');
  assert.equal(f.els.flow.attributes['aria-pressed'], 'false');
  assert.doesNotMatch(f.els.canvas.innerHTML, /service-map-flow/);
});

test('an arrow for Origin and Referer counts each request once', () => {
  const a = origin('https://a.example.com'), b = origin('https://b.example.com');
  b.header_links = [header(a.origin), header(a.origin, 'referer_header')].map(link => ({ ...link, request_count: 3, request_kinds: { api: 3 } }));
  b.header_sources = [{ source_origin: a.origin, request_count: 3, request_kinds: { api: 3 } }];
  const data = map.normalizeSnapshot(snapshot([a, b]), 'session-one');
  for (const anchor of [null, b.origin]) {
    const [edge] = map.graphLayout(data.origins, [a.origin, b.origin], new Map(), anchor).edges;
    assert.deepEqual([...edge.relationships], ['origin_header', 'referer_header']);
    assert.equal(edge.count, 3, 'three requests, not six');
    assert.deepEqual({ ...edge.kinds }, { api: 3 });
  }
});

test('reciprocal metadata curves and direct relations remain unclipped without body overlays or self arrows', () => {
  const a = origin('https://a.example.com'), b = origin('https://b.example.com'), c = origin('https://c.example.com');
  a.redirects = [redirect(b.origin)]; b.redirects = [redirect(c.origin), redirect(b.origin)]; c.redirects = [redirect(b.origin)];
  b.header_links = [header(c.origin), header(c.origin, 'referer_header'), header(b.origin)];
  c.header_links = [header(b.origin), header(b.origin, 'referer_header')];
  const data = map.normalizeSnapshot(snapshot([a, b, c]), 'session-one');
  // The overview and Direct relations both draw one arrow per direction.
  for (const [anchor, arrows] of [[null, 3], [b.origin, 3]]) {
    const layout = map.graphLayout(data.origins, [a.origin, b.origin, c.origin], new Map(), anchor);
    assert.equal(layout.edges.length, arrows); assert.equal(layout.edgeCount, arrows);
    assert.equal(layout.edges.filter(edge => edge.source !== a.origin).length, arrows - 1);
    assert.equal(new Set(layout.edges.map(edge => edge.path)).size, arrows);
    assertCanvasContainsGeometry(layout);
  }
});

for (const [name, patch] of [
  ['null header clue', { technology_clues: [null] }],
  ['null header link', { header_links: [null] }],
  ['non-array clues', { technology_clues: {} }],
  ['over-cap clues', { technology_clues: Array.from({ length: 9 }, () => ({ name: 'nginx', header_name: 'server' })) }],
  ['over-cap header declarations', { header_links: Array.from({ length: 3 }, () => ({ source_origin: originB, relationship: 'origin_header' })) }],
  ['object clue name', { technology_clues: [{ name: {}, header_name: 'server' }] }],
  ['unsupported declaration', { header_links: [{ source_origin: originB, relationship: 'invented_call' }] }],
  ['malformed redirect', { redirect: { target_origin: originB, target_path: null } }],
  ['non-text omission', { omitted: [null] }],
]) test(`malformed evidence observations fail closed and recover without poisoned inspector state: ${name}`, async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA, 0);
  const pending = f.controller.loadEvidence('evidence-one'), value = evidence();
  Object.assign(value.row, patch);
  value.socket_peer = { status: 'observed', observation: { source: 'http_response_remote_addr', route: 'direct', observed_at: '2026-10-12T01:00:00Z', address: { ip: '192.0.2.10', port: 443 }, reason: null } };
  f.requests.at(-1).resolve(response(value));
  assert.equal(await pending, false);
  assert.equal(f.state.evidence, null); assert.equal(f.state.socketPeer, null);
  assert.match(f.els.detail.innerHTML, /Source unavailable/);
  assert.doesNotMatch(f.els.detail.innerHTML, /Capture info|192\.0\.2\.10|invented_call/);
  assert.equal(await f.controller.loadBodyReferences(), false); assert.equal(f.requests.length, 2);
  assert.doesNotThrow(() => f.controller.setVisible(true));
  const retry = f.controller.loadEvidence('evidence-one'); f.requests.at(-1).resolve(response(evidence()));
  assert.equal(await retry, true); assert.match(f.els.detail.innerHTML, /Capture info/);
});

test('evidence render failure clears a published row and peer before rendering the safe error state', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA);
  const descriptor = Object.getOwnPropertyDescriptor(f.els.detail, 'innerHTML');
  let failOnce = true;
  Object.defineProperty(f.els.detail, 'innerHTML', { get: descriptor.get, set(value) {
    if (failOnce && value.includes('Capture info')) { failOnce = false; throw new Error('Synthetic render failure'); }
    descriptor.set.call(this, value);
  } });
  const pending = f.controller.loadEvidence('evidence-one');
  f.requests.at(-1).resolve(response(evidence('evidence-one', originA, { socket_peer: { status: 'not_recorded', observation: null } })));
  assert.equal(await pending, false); assert.equal(f.state.evidence, null); assert.equal(f.state.socketPeer, null);
  assert.match(f.els.detail.innerHTML, /Source unavailable/); assert.doesNotMatch(f.els.detail.innerHTML, /Capture info/);
  assert.doesNotThrow(() => f.controller.setVisible(true));
});

test('nested evidence observations retain only display fields while exact row identity stays checked first', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA, 0);
  const pending = f.controller.loadEvidence('evidence-one'), value = evidence();
  Object.assign(value.row, { technology_clues: [{ name: 'nginx', header_name: 'server', raw_header: 'never-copy' }],
    header_links: [{ source_origin: originB, relationship: 'origin_header', raw_header: 'never-copy' }],
    redirect: { target_origin: originB, target_path: '/next?secret=hidden', raw_header: 'never-copy' } });
  f.requests.at(-1).resolve(response(value)); assert.equal(await pending, true);
  assert.doesNotMatch(JSON.stringify(f.state.evidence), /never-copy|secret=hidden/);
  const substituted = f.controller.loadEvidence('evidence-one'); value.row.path = '/another-row';
  f.requests.at(-1).resolve(response(value)); assert.equal(await substituted, false);
  assert.equal(f.state.evidence, null); assert.match(f.els.detail.innerHTML, /Source unavailable/);
});

// Strict header-only extension contracts. These fixtures contain catalog
// metadata and byte positions, never raw response headers or retained bodies.
const technologySession = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const technologyGeneration = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const technologyRevision = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const technologyTime = '2026-10-12T01:00:00Z';
const technologyLast = '2026-10-12T02:00:00Z';
const technologyToken = (sequence = '1') => `v1.${technologySession}.${technologyGeneration}.${sequence}.${technologyRevision}.${recordId}`;
const technologyProducts = [
  ['nginx', 'nginx', 'web_server', 'nginx', 'server'],
  ['apache_http_server', 'Apache', 'web_server', 'Apache', 'server'],
  ['caddy', 'Caddy', 'web_server', 'Caddy', 'server'],
  ['cloudflare', 'Cloudflare', 'edge_service', 'Cloudflare', 'server'],
  ['microsoft_iis', 'Microsoft IIS', 'web_server', 'Microsoft-IIS', 'server'],
  ['envoy', 'Envoy', 'edge_service', 'Envoy', 'server'],
  ['php', 'PHP', 'language_runtime', 'PHP', 'server'],
  ['jetty', 'Jetty', 'application_server', 'Jetty', 'server'],
  ['apache_coyote', 'Apache-Coyote', 'connector', 'Apache-Coyote', 'server'],
  ['apache_tomcat', 'Apache Tomcat', 'application_server', 'Apache Tomcat', 'server'],
  ['php', 'PHP', 'language_runtime', 'PHP', 'x-powered-by'],
  ['express', 'Express', 'application_framework', 'Express', 'x-powered-by'],
  ['asp_net', 'ASP.NET', 'application_framework', 'ASP.NET', 'x-powered-by'],
  ['wordpress', 'WordPress', 'cms', 'WordPress', 'x-generator'],
  ['drupal', 'Drupal', 'cms', 'Drupal', 'x-generator'],
];
function technologyRow(product = technologyProducts[0], version = '1.26.2', patch = {}) {
  const [product_id, name, catalog_category, literal, header_name] = product;
  return { product_id, name, catalog_category, reported_version: version, version_status: version === null ? 'not_reported' : 'reported', source: 'response_header', strength: 'literal_declaration', header_name, header_index: 0,
    product_span: { start: 0, end: literal.length }, version_span: version === null ? null : { start: literal.length + 1, end: literal.length + 1 + version.length }, offset_basis: 'retained_header_value_utf8', rule_id: `${header_name.replaceAll('-', '_')}.${product_id}.v1`, ...patch };
}
function technologyAggregate(row = technologyRow(), patch = {}) {
  const { header_index, product_span, version_span, offset_basis, rule_id, ...base } = row;
  return { ...base, row_count: 1, first_seen: technologyTime, last_seen: technologyTime, evidence: [technologyToken()], ...patch };
}
function technologySnapshot(items = [technologyAggregate()]) {
  const item = { ...origin(originA, [endpoint('/users', 'GET', technologyToken())]), first_seen: technologyTime, last_seen: technologyLast, technology_observations: items };
  return snapshot([item], technologySession, { generation: technologyGeneration });
}
function technologyEvidence(items = [technologyRow()], id = technologyToken()) {
  const value = evidence(id, originA, { session_id: technologySession });
  Object.assign(value.row, { sequence: id.split('.')[3], technology_observations: items });
  return value;
}
async function technologyFixture(payload = technologySnapshot()) {
  const f = fixture(); f.setSession(technologySession); await f.load(payload); return f;
}
async function resolveTechnologySource(f, value = technologyEvidence()) {
  const pending = f.controller.loadEvidence(value.evidence_id); f.requests.at(-1).resolve(response(value)); return pending;
}

test('old-server absence and new empty technology arrays remain independently compatible with legacy clues', async () => {
  const f = fixture(); const value = snapshot(); value.origins[0].technology_clues = [{ name: 'nginx', header_name: 'server', source: 'response_header', confidence: 'observed_header', evidence: ['evidence-one'] }];
  await f.load(value); f.controller.selectOrigin(originA);
  assert.equal(f.state.snapshot.origins[0].technology_observations.length, 0);
  const pending = f.controller.loadEvidence('evidence-one'); f.requests.at(-1).resolve(response(evidence())); assert.equal(await pending, true);
  assert.equal(f.state.evidence.technology_observations.length, 0); assert.doesNotMatch(f.els.detail.innerHTML, /Observed header clues/);
  assert.equal(f.state.snapshot.origins[0].technology_clues[0].name, 'nginx');
  assert.doesNotMatch(f.els.detail.innerHTML, /Header-reported technologies|Reported version/);
  value.origins[0].technology_observations = []; await f.load(value);
  assert.equal(f.state.snapshot.origins[0].technology_observations.length, 0);
});

test('all exact catalog products, both PHP headers and complete numeric versions normalize without product invention', () => {
  for (const product of technologyProducts) {
    const row = technologyRow(product, product[0] === 'apache_coyote' ? null : '10.2.003');
    const parsed = map.normalizeRowTechnologies([row]);
    assert.equal(JSON.stringify(parsed[0]), JSON.stringify(row));
    assert.equal(map.normalizeSnapshot(technologySnapshot([technologyAggregate(row)]), technologySession).origins[0].technology_observations[0].product_id, product[0]);
  }
  for (const version of ['0', '001', '2.4.62', '1'.repeat(32)]) assert.equal(map.normalizeRowTechnologies([technologyRow(undefined, version)])[0].reported_version, version);
});

test('Apache plus PHP remains two source observations and no inferred stack relationship', async () => {
  const apache = technologyRow(technologyProducts[1], '2.4.62'), php = technologyRow(technologyProducts[6], '8.3.12', { product_span: { start: 14, end: 17 }, version_span: { start: 18, end: 24 } });
  const f = await technologyFixture(technologySnapshot([technologyAggregate(apache), technologyAggregate(php)]));
  assert.match(f.els.detail.innerHTML, /<strong>Apache 2\.4\.62<\/strong>/); assert.match(f.els.detail.innerHTML, /<strong>PHP 8\.3\.12<\/strong>/);
  assert.match(f.els.detail.innerHTML, /Web server · server header · 1 row/); assert.match(f.els.detail.innerHTML, /Language runtime · /);
  assert.equal(f.requests.length, 1); assert.equal(await resolveTechnologySource(f, technologyEvidence([apache, php])), true);
  assert.deepEqual(JSON.parse(JSON.stringify(f.state.evidence.technology_observations)), [apache, php], 'both exact observations remain separate for the packet span adapter');
  assert.doesNotMatch(f.els.detail.innerHTML, /service-map-verified/);
  assert.doesNotMatch(f.els.detail.innerHTML, /WEB.?→.?WAS|vulnerable|raw_header|<a\b|href=/);
  assert.equal(f.requests.length, 2); assert.doesNotMatch(f.requests.map(r => r.url).join(' '), /body-references|transactions|replay|scan|capture/);
});

test('conflicting versions stay separate, each with exact View source navigation', async () => {
  const first = technologyAggregate(technologyRow(undefined, '1.24.0'));
  const second = technologyAggregate(technologyRow(undefined, '1.26.2'), { first_seen: technologyLast, last_seen: technologyLast, evidence: [technologyToken('2')] });
  const f = await technologyFixture(technologySnapshot([first, second]));
  assert.equal(f.state.snapshot.origins[0].technology_observations.length, 2);
  assert.match(f.els.detail.innerHTML, /<strong>nginx 1\.24\.0<\/strong>/); assert.match(f.els.detail.innerHTML, /<strong>nginx 1\.26\.2<\/strong>/);
  assert.match(f.els.detail.innerHTML, /Web server · server header · 1 row/);
  f.els.panel.dispatch('click', { target: { closest: () => ({ dataset: { serviceRelationOrigin: originA, serviceRelationEvidence: technologyToken('2') } }) } });
  assert.equal(f.requests.length, 2); assert.equal(new URL(f.requests.at(-1).url, originA).searchParams.get('evidence_id'), technologyToken('2'));
  f.requests.at(-1).resolve(response(technologyEvidence([technologyRow()], technologyToken('2')))); await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.evidence.sequence, '2'); assert.equal(f.state.detailTab, 'evidence');
  assert.equal(f.state.snapshot.origins[0].technology_observations.length, 2);
  assert.doesNotMatch(f.requests.map(r => r.url).join(' '), /body-references|transactions/);
});

for (const [status, product] of [
  ['not_reported', technologyProducts[0]],
  ['unsupported_format', technologyProducts[0]],
  ['non_product_version', technologyProducts[8]],
]) test(`an unreported version shows the product alone in aggregate and exact source: ${status}`, async () => {
  const row = technologyRow(product, null, { version_status: status }), expected = `<strong>${product[1]}</strong>`;
  const f = await technologyFixture(technologySnapshot([technologyAggregate(row)]));
  assert.ok(f.els.detail.innerHTML.includes(expected));
  assert.equal(await resolveTechnologySource(f, technologyEvidence([row])), true);
  assert.equal(f.state.evidence.technology_observations[0].name, product[1]);
  assert.equal(f.state.evidence.technology_observations[0].version_status, status);
  assert.equal(f.state.evidence.technology_observations[0].reported_version, null);
  assert.doesNotMatch(f.els.detail.innerHTML, /service-map-verified/);
});

test('Unicode prefixes use retained UTF-8 byte offsets and header index rather than JS character positions', () => {
  const prefixBytes = Buffer.byteLength('é 🛰 ', 'utf8');
  const row = technologyRow(undefined, '1.26.2', { header_index: 127, product_span: { start: prefixBytes, end: prefixBytes + 5 }, version_span: { start: prefixBytes + 6, end: prefixBytes + 12 } });
  const value = map.normalizeRowTechnologies([row])[0];
  assert.equal(value.product_span.start, 8); assert.equal(value.header_index, 127); assert.equal(value.offset_basis, 'retained_header_value_utf8');
  assert.equal(JSON.stringify(value).includes('🛰'), false);
});

test('Jetty parenthesized rule and whitespace-separated generator versions preserve supported span semantics', () => {
  const jetty = technologyRow(technologyProducts[7], '12.0.9', { rule_id: 'server.jetty_parenthesized.v1' });
  const generator = technologyRow(technologyProducts[13], '6.6', { header_index: 1, product_span: { start: 8, end: 17 }, version_span: { start: 20, end: 23 } });
  assert.equal(map.normalizeRowTechnologies([jetty, generator]).length, 2);
});

const malformedTechnologyRows = [
  ['null entry', rows => { rows[0] = null; }],
  ['non-array extension', rows => rows.splice(0)],
  ['invented product', rows => { rows[0].product_id = 'custom_webserver'; }],
  ['injected display name', rows => { rows[0].name = '<img src=x onerror=bad>'; }],
  ['mismatched catalog', rows => { rows[0].catalog_category = 'application_server'; }],
  ['invented catalog', rows => { rows[0].catalog_category = '__proto__'; }],
  ['request header source', rows => { rows[0].source = 'request_header'; }],
  ['inferred strength', rows => { rows[0].strength = 'confirmed'; }],
  ['unknown status', rows => { rows[0].version_status = 'verified'; }],
  ['private header name', rows => { rows[0].header_name = 'authorization'; }],
  ['wrong header case', rows => { rows[0].header_name = 'Server'; }],
  ['wrong product/header pair', rows => { rows[0].header_name = 'x-generator'; }],
  ['negative header index', rows => { rows[0].header_index = -1; }],
  ['excess header index', rows => { rows[0].header_index = 128; }],
  ['fractional header index', rows => { rows[0].header_index = 1.5; }],
  ['string header index', rows => { rows[0].header_index = '0'; }],
  ['negative span', rows => { rows[0].product_span = { start: -1, end: 4 }; }],
  ['fractional span', rows => { rows[0].product_span = { start: 0.5, end: 5.5 }; }],
  ['oversized span', rows => { rows[0].product_span = { start: 4092, end: 4097 }; }],
  ['wrong token length', rows => { rows[0].product_span.end = 6; }],
  ['empty span', rows => { rows[0].product_span.end = 0; }],
  ['injected nested span field', rows => { rows[0].product_span.raw_header = 'must-not-publish'; }],
  ['missing version', rows => { delete rows[0].reported_version; }],
  ['missing nullable span', rows => { delete rows[0].version_span; }],
  ['reported null version', rows => { rows[0].reported_version = null; }],
  ['reported null span', rows => { rows[0].version_span = null; }],
  ['overlapping version span', rows => { rows[0].version_span = { start: 1, end: 7 }; }],
  ['non-adjacent server version', rows => { rows[0].version_span = { start: 7, end: 13 }; }],
  ['wrong version span length', rows => { rows[0].version_span.end += 1; }],
  ['UTF-16 offset basis', rows => { rows[0].offset_basis = 'utf16'; }],
  ['arbitrary rule', rows => { rows[0].rule_id = 'body.nginx.v1'; }],
  ['Jetty rule for nginx', rows => { rows[0].rule_id = 'server.jetty_parenthesized.v1'; }],
  ['raw header extension', rows => { rows[0].raw_header = 'must-not-publish'; }],
  ['empty numeric version', rows => { rows[0].reported_version = ''; }],
  ['truncated suffix version', rows => { rows[0].reported_version = '1.26.2-beta'; }],
  ['Unicode digits', rows => { rows[0].reported_version = '１.２'; }],
  ['Unicode payload', rows => { rows[0].reported_version = '1.26.2🛰'; }],
  ['leading dot', rows => { rows[0].reported_version = '.1.26'; }],
  ['trailing dot', rows => { rows[0].reported_version = '1.26.'; }],
  ['empty component', rows => { rows[0].reported_version = '1..26'; }],
  ['oversized version', rows => { rows[0].reported_version = '1'.repeat(33); rows[0].version_span.end = 39; }],
  ['status-null mismatch', rows => { rows[0].version_status = 'not_reported'; }],
  ['Coyote product-version claim', rows => { rows[0] = technologyRow(technologyProducts[8]); }],
  ['non-product nginx version', rows => { rows[0] = technologyRow(undefined, null, { version_status: 'non_product_version' }); }],
  ['Jetty parenthesized bare status', rows => { rows[0] = technologyRow(technologyProducts[7], null, { rule_id: 'server.jetty_parenthesized.v1' }); }],
  ['duplicate source position', rows => { rows.push({ ...rows[0] }); }],
  ['row observation cap', rows => { rows.splice(0, 1, ...Array.from({ length: 9 }, (_, header_index) => technologyRow(undefined, '1.26.2', { header_index }))); }],
];
for (const [name, change] of malformedTechnologyRows) test(`malformed reported technology fails closed before exact source publication: ${name}`, async () => {
  const f = await technologyFixture(), value = technologyEvidence(); change(value.row.technology_observations);
  if (name === 'non-array extension') value.row.technology_observations = {};
  assert.equal(await resolveTechnologySource(f, value), false);
  assert.equal(f.state.evidence, null); assert.equal(f.state.socketPeer, null); assert.match(f.els.detail.innerHTML, /Source unavailable/);
  assert.doesNotMatch(f.els.detail.innerHTML, /must-not-publish|<img|Capture info|１\.２|1\.26\.2🛰/);
  assert.equal(await f.controller.loadBodyReferences(), false); assert.equal(f.requests.length, 2);
});

for (const [name, change] of [
  ['null extension', value => { value.origins[0].technology_observations = null; }],
  ['missing nullable version', value => { delete value.origins[0].technology_observations[0].reported_version; }],
  ['empty evidence', value => { value.origins[0].technology_observations[0].evidence = []; }],
  ['oversized evidence', value => { value.origins[0].technology_observations[0].evidence = [1, 2, 3, 4].map(i => technologyToken(String(i))); }],
  ['duplicate evidence', value => { value.origins[0].technology_observations[0].evidence = [technologyToken(), technologyToken()]; value.origins[0].technology_observations[0].row_count = 2; }],
  ['evidence from other session', value => { value.origins[0].technology_observations[0].evidence = [technologyToken().replace(technologySession, recordId)]; }],
  ['evidence from other generation', value => { value.origins[0].technology_observations[0].evidence = [technologyToken().replace(technologyGeneration, recordId)]; }],
  ['oversized sequence', value => { value.origins[0].technology_observations[0].evidence = [technologyToken('18446744073709551616')]; }],
  ['noncanonical sequence', value => { value.origins[0].technology_observations[0].evidence = [technologyToken('01')]; }],
  ['injected token', value => { value.origins[0].technology_observations[0].evidence = ['<script>bad</script>']; }],
  ['zero rows', value => { value.origins[0].technology_observations[0].row_count = 0; }],
  ['excess rows', value => { value.origins[0].technology_observations[0].row_count = 3; }],
  ['fractional rows', value => { value.origins[0].technology_observations[0].row_count = 0.5; }],
  ['inverted observation times', value => { value.origins[0].technology_observations[0].first_seen = technologyLast; }],
  ['outside origin times', value => { value.origins[0].technology_observations[0].first_seen = '2026-10-11T01:00:00Z'; }],
  ['injected timestamp', value => { value.origins[0].technology_observations[0].last_seen = '<img onerror=bad>'; }],
  ['raw header field', value => { value.origins[0].technology_observations[0].raw_header = 'must-not-publish'; }],
  ['row-only span', value => { value.origins[0].technology_observations[0].product_span = { start: 0, end: 5 }; }],
  ['duplicate aggregate identity', value => { value.origins[0].technology_observations.push({ ...value.origins[0].technology_observations[0] }); }],
  ['per-origin cap', value => { value.origins[0].technology_observations = Array.from({ length: 33 }, (_, i) => technologyAggregate(technologyRow(undefined, String(i)))); }],
]) test(`malformed origin reported technology is rejected before map publication: ${name}`, async () => {
  const f = await technologyFixture(), previous = f.state.snapshot, payload = technologySnapshot(); change(payload);
  await f.load(payload); assert.equal(f.state.snapshot, previous); assert.match(f.els.status.textContent, /Reload failed/);
  assert.doesNotMatch(f.els.detail.innerHTML, /must-not-publish|<img|<script>/);
});

test('aggregate extension caps permit 32 per origin and 2000 overall but reject the next observation', () => {
  const items = Array.from({ length: 32 }, (_, index) => technologyAggregate(technologyRow(undefined, String(index))));
  const payload = technologySnapshot(items), base = payload.origins[0];
  payload.origins = Array.from({ length: 63 }, (_, i) => ({ ...base, origin: `https://node${i}.example.com`, endpoints: [], technology_observations: (i === 62 ? items.slice(0, 16) : items).map(item => ({ ...item, evidence: [technologyToken(String(i + 1))] })) }));
  assert.equal(map.normalizeSnapshot(payload, technologySession).origins.reduce((n, item) => n + item.technology_observations.length, 0), 2000);
  payload.origins[62].technology_observations = items.slice(0, 17).map(item => ({ ...item, evidence: [technologyToken('63')] }));
  assert.throws(() => map.normalizeSnapshot(payload, technologySession), /Invalid retained technology observations/);
});

test('row technology cap omission is honest and mandatory metadata completeness remains coherent', async () => {
  const items = Array.from({ length: 8 }, (_, header_index) => technologyRow(undefined, '1.26.2', { header_index }));
  const f = await technologyFixture(), value = technologyEvidence(items);
  value.row.metadata_complete = false; value.row.omitted = ['technology_observations_limit'];
  assert.equal(await resolveTechnologySource(f, value), true); assert.match(f.els.detail.innerHTML, /technology_observations_limit/);
  value.row.technology_observations.pop(); assert.equal(await resolveTechnologySource(f, value), false);
  value.row.technology_observations = []; value.row.omitted = []; assert.equal(await resolveTechnologySource(f, value), false);
});

test('header evidence polls preserve exact source; observation removal clears it even when another version remains', async () => {
  const payload = technologySnapshot([technologyAggregate(), technologyAggregate(technologyRow(undefined, '1.24.0'), { evidence: [technologyToken('2')] })]);
  const f = await technologyFixture(payload);
  assert.equal(await resolveTechnologySource(f, technologyEvidence([technologyRow(undefined, '1.24.0')], technologyToken('2'))), true);
  const exact = f.state.evidence, count = f.requests.length, replacements = f.els.detail.replacements;
  await f.load(payload); assert.equal(f.state.evidence, exact); assert.equal(f.els.detail.replacements, replacements); assert.equal(f.requests.length, count + 1);
  await f.load(technologySnapshot()); assert.equal(f.state.evidence, null); assert.equal(f.state.evidenceId, null);
  assert.doesNotMatch(f.els.detail.innerHTML, /Capture info|nginx 1\.24\.0/);
});

for (const transition of ['selection', 'session', 'deletion', 'generation', 'dirty', 'disconnect']) test(`late header evidence cannot republish after ${transition}`, async () => {
  const payload = technologySnapshot(); payload.origins.push({ ...origin(originB), first_seen: technologyTime, last_seen: technologyLast });
  const f = await technologyFixture(payload), pending = f.controller.loadEvidence(technologyToken()), request = f.requests.at(-1);
  if (transition === 'selection') f.controller.selectOrigin(originB);
  if (transition === 'session') { f.setSession(recordId); f.controller.reset(); }
  if (transition === 'deletion') { const refresh = f.controller.invalidate(); const empty = technologySnapshot(); empty.origins = []; f.requests.at(-1).resolve(response(empty)); await refresh; }
  if (transition === 'generation') { const next = technologySnapshot([]); next.snapshot.generation = recordId; await f.load(next); }
  if (transition === 'dirty') f.controller.markDirty();
  if (transition === 'disconnect') f.controller.disconnect();
  request.resolve(response(technologyEvidence())); assert.equal(await pending, false); assert.equal(f.state.evidence, null);
  assert.doesNotMatch(f.els.detail.innerHTML, /Capture info|UTF-8 product bytes/);
  assert.equal(f.requests.some(r => /body-references|transactions|replay|scan|capture/.test(r.url)), false);
});

test('aggregate time windows retain nanosecond precision and reject impossible calendar dates', () => {
  const payload = technologySnapshot(), item = payload.origins[0].technology_observations[0];
  payload.origins[0].first_seen = '2026-10-12T01:00:00.000000002Z';
  item.first_seen = '2026-10-12T01:00:00.000000001Z'; item.last_seen = '2026-10-12T01:00:00.000000003Z';
  assert.throws(() => map.normalizeSnapshot(payload, technologySession), /Invalid retained technology observations/);
  item.first_seen = '2026-10-12T01:00:00.000000002Z';
  assert.equal(map.normalizeSnapshot(payload, technologySession).origins[0].technology_observations.length, 1);
  payload.origins[0].first_seen = '2026-02-01T00:00:00Z'; item.first_seen = '2026-02-30T00:00:00Z';
  assert.throws(() => map.normalizeSnapshot(payload, technologySession), /Invalid retained technology observations/);
});

test('technology source samples reject distinct revisions of one sequence and sequence reuse across origins', () => {
  const payload = technologySnapshot(), item = payload.origins[0].technology_observations[0];
  item.row_count = 2; item.evidence.push(technologyToken().replace(technologyRevision, recordId));
  assert.throws(() => map.normalizeSnapshot(payload, technologySession), /Invalid retained technology observations/);
  item.evidence.pop();
  payload.origins.push({ ...payload.origins[0], origin: originB });
  assert.throws(() => map.normalizeSnapshot(payload, technologySession), /Invalid retained technology observations/);
});

for (const [key, value] of Object.entries({ technology_observations_per_row: 8, technology_observations_per_origin: 32, technology_observations: 2000, technology_version_bytes: 32 })) test(`optional technology limit is verified when present: ${key}`, () => {
  const payload = technologySnapshot(); payload.snapshot.limits[key] = value;
  assert.equal(map.normalizeSnapshot(payload, technologySession).origins.length, 1);
  payload.snapshot.limits[key] = value + 1;
  assert.throws(() => map.normalizeSnapshot(payload, technologySession), /Invalid retained technology observations/);
});

for (const field of ['revision', 'record']) test(`different aggregate tuples cannot reuse a sequence with a different ${field} token`, () => {
  const changedToken = field === 'revision' ? technologyToken().replace(technologyRevision, recordId) : technologyToken().replace(recordId, '22222222-2222-4222-8222-222222222222');
  const payload = technologySnapshot([technologyAggregate(), technologyAggregate(technologyRow(undefined, '1.24.0'), { evidence: [changedToken] })]);
  assert.throws(() => map.normalizeSnapshot(payload, technologySession), /Invalid retained technology observations/);
  payload.origins[0].technology_observations[1].evidence = [technologyToken()];
  assert.equal(map.normalizeSnapshot(payload, technologySession).origins[0].technology_observations.length, 2);
});

for (const collection of ['endpoints', 'technology_clues', 'redirects', 'header_links']) test(`new header observations retain exact token identity with legacy ${collection} sources`, () => {
  const payload = technologySnapshot(), item = payload.origins[0];
  item[collection] = [{ evidence: [technologyToken().replace(technologyRevision, recordId)] }];
  assert.throws(() => map.normalizeSnapshot(payload, technologySession), /Invalid retained technology observations/);
});

test('one retained response header index cannot claim multiple header names while multi-product Server remains valid', () => {
  const first = technologyRow();
  const second = technologyRow(technologyProducts[10], '8.3', { product_span: { start: 14, end: 17 }, version_span: { start: 18, end: 21 } });
  assert.throws(() => map.normalizeRowTechnologies([first, second]), /Invalid retained technology observations/);
  second.header_name = 'server'; second.rule_id = 'server.php.v1';
  assert.equal(map.normalizeRowTechnologies([first, second]).length, 2);
});

test('nonidentical product and version spans cannot overlap within one retained header value', () => {
  const nginx = technologyRow();
  for (const start of [3, 8]) {
    const php = technologyRow(technologyProducts[6], '8.3', { product_span: { start, end: start + 3 }, version_span: { start: start + 4, end: start + 7 } });
    assert.throws(() => map.normalizeRowTechnologies([nginx, php]), /Invalid retained technology observations/);
  }
  const wordpress = technologyRow(technologyProducts[13], '6.6', { version_span: { start: 20, end: 23 } });
  const drupal = technologyRow(technologyProducts[14], '9.1', { product_span: { start: 10, end: 16 }, version_span: { start: 21, end: 24 } });
  assert.throws(() => map.normalizeRowTechnologies([wordpress, drupal]), /Invalid retained technology observations/);
  drupal.product_span = { start: 9, end: 15 }; drupal.version_span = { start: 23, end: 26 };
  assert.equal(map.normalizeRowTechnologies([wordpress, drupal]).length, 2, 'half-open ranges may share endpoints');
  drupal.header_index = 1; drupal.product_span = { start: 0, end: 6 }; drupal.version_span = { start: 7, end: 10 };
  assert.equal(map.normalizeRowTechnologies([wordpress, drupal]).length, 2, 'different header values have independent byte ranges');
});


test('compact cards and arrow attachments share geometry at every scale', async () => {
  const f = fixture(), a = origin(originA), b = origin(originB);
  a.redirects = [redirect(originB)]; await f.load(snapshot([a, b]));
  const geometry = map.GRAPH_GEOMETRY;
  assert.equal(geometry.cardWidth, 220); assert.equal(geometry.cardHeight, 84);
  assert.equal(geometry.rowPitch, 104); assert.equal(geometry.columnPitch, 300);
  const layout = map.graphLayout(f.state.snapshot.origins, f.state.order);
  assertCanvasContainsGeometry(layout);
  const points = layout.edges[0].path.match(/-?\d+(?:\.\d+)?/g).map(Number);
  const from = layout.nodes.find(node => node.origin === originA), to = layout.nodes.find(node => node.origin === originB);
  assert.equal(points[0], from.x + geometry.cardWidth); assert.equal(points[1], from.y + geometry.cardHeight / 2);
  assert.equal(points[6], to.x); assert.equal(points[7], to.y + geometry.cardHeight / 2);
  assert.match(f.els.canvas.innerHTML, /--service-map-card-width:220px;--service-map-card-height:84px/);
  for (const scale of [0.1, 0.5, 1, 2]) {
    f.controller.setZoom(scale);
    assert.equal(f.els.canvas.style.values['--service-map-scaled-width'], `${layout.width * scale}px`);
    assert.equal(f.els.canvas.style.values['--service-map-scaled-height'], `${layout.height * scale}px`);
    assert.equal(f.els.canvas.style.values['--service-map-scale'], String(scale));
  }
});

test('zoom and Fit never replace graph or inspector, alter selection, abort evidence, or issue reads', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA, 0);
  const pending = f.controller.loadEvidence('evidence-one'), read = f.requests.at(-1);
  const before = { canvas: f.els.canvas.replacements, detail: f.els.detail.replacements, slots: JSON.stringify([...f.state.layoutSlots]), requests: f.requests.length, evidenceRequestId: f.state.evidenceRequestId };
  const focused = { dataset: { serviceFocus: 'origin:synthetic' } }; f.document.activeElement = focused;
  for (const name of ['zoomOut', 'zoomIn', 'zoomReset']) f.els[name].dispatch('click');
  assert.equal(f.state.selectedOrigin, originA); assert.equal(f.state.endpointIndex, 0);
  assert.equal(f.state.evidenceRequestId, before.evidenceRequestId); assert.equal(read.options.signal.aborted, false);
  assert.equal(f.els.canvas.replacements, before.canvas); assert.equal(f.els.detail.replacements, before.detail);
  assert.equal(f.requests.length, before.requests); assert.equal(JSON.stringify([...f.state.layoutSlots]), before.slots);
  assert.equal(f.document.activeElement, focused);
  read.resolve(response(evidence())); await pending; assert.ok(f.state.evidence);
});

test('zoom preserves pinned overlay, native inspector state, and an in-flight body read', async () => {
  const f = await verifiedBodyFixture(); await resolveBodyReferences(f); clickOverlay(f);
  const overlay = f.state.bodyReferenceOverlay, view = nativeInspectorModel(f);
  view().limits.open = true; view().body.scrollTop = 180; view().list.scrollTop = 80;
  f.document.activeElement = view().summary;
  const pending = f.controller.loadBodyReferences(), read = f.requests.at(-1);
  const requestCount = f.requests.length, generation = f.state.bodyReferencesRequestId, inspector = f.els.detail.replacements;
  f.controller.setZoom(0.6); f.controller.fitGraph(); f.controller.setZoom(1);
  assert.equal(f.state.bodyReferenceOverlay, overlay); assert.equal(f.state.anchorOrigin, originA);
  assert.equal(f.state.bodyReferencesRequestId, generation); assert.equal(read.options.signal.aborted, false);
  assert.equal(f.els.detail.replacements, inspector); assert.equal(f.requests.length, requestCount);
  assert.equal(view().limits.open, true); assert.equal(view().body.scrollTop, 180);
  read.resolve(response(bodyReferences())); await pending;
  assert.equal(f.state.bodyReferenceOverlay, overlay); assert.ok(f.state.bodyReferences);
});

test('plus and minus preserve the viewport center with bounded scale and reset', async () => {
  const f = fixture(); await f.load(snapshot(Array.from({ length: 24 }, (_, i) => origin(`https://node${i}.example.com`))));
  f.els.viewport.clientWidth = 300; f.els.viewport.clientHeight = 300;
  f.els.viewport.scrollLeft = 120; f.els.viewport.scrollTop = 480;
  f.els.zoomIn.dispatch('click'); assert.equal(f.state.zoomScale, 1.1);
  assert.ok(Math.abs(f.els.viewport.scrollLeft - 147) < 0.001);
  assert.ok(Math.abs(f.els.viewport.scrollTop - 543) < 0.001);
  f.els.zoomOut.dispatch('click'); assert.equal(f.state.zoomScale, 1);
  assert.ok(Math.abs(f.els.viewport.scrollLeft - 120) < 0.001);
  assert.ok(Math.abs(f.els.viewport.scrollTop - 480) < 0.001);
  f.controller.setZoom(99); assert.equal(f.state.zoomScale, 2); assert.equal(f.els.zoomIn.disabled, true);
  f.controller.setZoom(-10); assert.equal(f.state.zoomScale, 0.1); assert.equal(f.els.zoomOut.disabled, true);
  assert.equal(f.els.viewport.scrollLeft, 0); assert.equal(f.els.viewport.scrollTop, 0);
  f.els.zoomReset.dispatch('click'); assert.ok(f.state.zoomScale > 0.1 && f.state.zoomScale < 1, 'the percentage fits the map');
  f.els.zoomReset.dispatch('click'); assert.equal(f.state.zoomScale, 1, 'fitted, it returns to 100%'); assert.equal(f.els.zoomReset.textContent, '100%');
  assert.equal(f.controller.setZoom(NaN), false); assert.equal(f.controller.setZoom(Infinity), false);
});

test('Fit is safe for empty, one-origin, and dense maps and never changes display caps', async () => {
  const f = fixture(); await f.load(snapshot([]));
  assert.equal(f.controller.fitGraph(), false); assert.equal(f.state.zoomScale, 1); assert.equal(f.els.zoomReset.disabled, true);
  await f.load(snapshot([origin(originA)])); f.controller.fitGraph(); assert.equal(f.state.zoomScale, 1);
  const nodes = Array.from({ length: 30 }, (_, i) => origin(`https://node${i}.example.com`));
  nodes.forEach(node => { node.redirects = nodes.filter(other => other !== node).map(other => redirect(other.origin)); });
  await f.load(snapshot(nodes)); const html = f.els.canvas.innerHTML;
  f.controller.fitGraph(); assert.ok(f.state.zoomScale >= 0.1 && f.state.zoomScale < 1);
  assert.equal((html.match(/data-service-origin=/g) || []).length, 24); assert.equal((html.match(/data-relationship=/g) || []).length, 40);
  assert.ok(Number.parseFloat(f.els.canvas.style.values['--service-map-scaled-width']) <= f.els.viewport.clientWidth);
  assert.ok(Number.parseFloat(f.els.canvas.style.values['--service-map-scaled-height']) <= f.els.viewport.clientHeight);
  assert.equal(f.els.canvas.innerHTML, html); assert.match(f.els.graphBounds.textContent, /24 \/ 30.*40 \/ /);
});

test('zero-size, hidden, and API views cannot change zoom; resize and polling never refit', async () => {
  const f = fixture(); await f.load(); f.controller.setZoom(0.7);
  const observer = resizeObservers.at(-1); assert.equal(observer.element, f.els.viewport);
  f.els.viewport.clientWidth = 0; observer.callback(); assert.equal(f.els.zoomReset.disabled, true);
  assert.equal(f.controller.fitGraph(), false); assert.equal(f.controller.setZoom(1.5), false);
  f.els.viewport.clientWidth = 350; observer.callback(); assert.equal(f.els.zoomReset.disabled, false); assert.equal(f.state.zoomScale, 0.7);
  f.controller.setVisible(false); assert.equal(f.controller.setZoom(1.5), false);
  f.controller.setVisible(true, 'apis'); assert.equal(f.controller.fitGraph(), false); assert.equal(f.els.zoomControls.classList.contains('hidden'), true);
  f.controller.setVisible(true, 'service-map'); assert.equal(f.state.zoomScale, 0.7);
  const count = f.requests.length, replacements = f.els.canvas.replacements;
  await f.load(); assert.equal(f.state.zoomScale, 0.7); assert.equal(f.requests.length, count + 1);
  assert.equal(f.els.canvas.replacements, replacements);
  f.els.viewport.clientHeight = 0; observer.callback(); assert.equal(f.controller.setZoom(1), false);
  f.els.viewport.clientHeight = 800; observer.callback(); assert.equal(f.state.zoomScale, 0.7);
  f.setSession('session-two'); f.controller.reset(); assert.equal(f.state.zoomScale, 1); assert.equal(f.els.zoomReset.disabled, true);
});

test('map keyboard shortcuts are local and accessible toolbar controls use native buttons', async () => {
  const f = fixture(); await f.load(); let prevented = 0;
  const press = (key, extra = {}) => f.els.viewport.dispatch('keydown', { key, preventDefault() { prevented++; }, ...extra });
  press('+'); assert.equal(f.state.zoomScale, 1.1); press('-'); assert.equal(f.state.zoomScale, 1);
  press('='); assert.equal(f.state.zoomScale, 1.1); press('0'); assert.equal(f.state.zoomScale, 1);
  press('F'); assert.equal(f.state.zoomScale, 1); assert.equal(prevented, 5);
  for (const extra of [{ ctrlKey: true }, { metaKey: true }, { altKey: true }, { target: f.els.search }]) press('+', extra);
  press('ArrowDown'); assert.equal(prevented, 5); assert.equal(f.requests.length, 1);
  const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  for (const id of ['serviceMapZoomOut', 'serviceMapZoomReset', 'serviceMapZoomIn']) assert.match(html, new RegExp(`<button[^>]+id="${id}"[^>]+type="button"`));
  assert.doesNotMatch(html, /id="serviceMapZoomFit"/, 'the percentage fits the map; no Fit button beside it');
  assert.match(html, /<div class="pane-resizer service-map-resizer" id="serviceMapResizer" role="separator" aria-orientation="vertical"[^>]*tabindex="0"/);
  assert.match(html, /id="serviceMapViewport" tabindex="0" aria-label=/);
});


test('display text geometry keeps compact defaults and grows card, pitch, and arrows together at 20px', () => {
  const base = map.graphGeometry(12), large = map.graphGeometry(20);
  assert.equal(base.cardHeight, 84); assert.equal(base.rowPitch, 104);
  assert.equal(large.cardWidth, 220); assert.equal(large.cardHeight, 119); assert.equal(large.rowPitch, 139);
  for (const size of [8, 12, 14, 16, 18, 20]) {
    const geometry = map.graphGeometry(size), title = Math.max(10, size - 1), small = Math.max(9, size - 2);
    assert.ok(geometry.cardHeight >= (title + small * 2) * geometry.lineHeight + 36);
    assert.equal(geometry.rowPitch - geometry.cardHeight, 20);
    const a = origin(originA), b = origin(originB), c = origin('https://assets.example.com');
    a.redirects = [redirect(b.origin)]; b.redirects = [redirect(c.origin)]; c.header_links = [header(b.origin), header(b.origin, 'referer_header')];
    const layout = map.graphLayout([a, b, c], [a.origin, b.origin, c.origin], new Map(), null, [], geometry);
    assert.equal(layout.width, geometry.padding * 2 + 2 * geometry.columnPitch + geometry.cardWidth, 'text size never widens the three-column chain');
    for (const node of layout.nodes) assert.ok(node.y + geometry.cardHeight + geometry.padding <= layout.height);
    for (const edge of layout.edges) {
      const points = edge.path.match(/-?\d+(?:\.\d+)?/g).map(Number);
      const from = layout.nodes.find(node => node.origin === edge.source), to = layout.nodes.find(node => node.origin === edge.target);
      assert.ok(points[1] > from.y && points[1] < from.y + geometry.cardHeight);
      assert.ok(points[7] > to.y && points[7] < to.y + geometry.cardHeight);
      for (let i = 0; i < points.length; i += 2) {
        assert.ok(points[i] >= 8 && points[i] <= layout.width - 8);
        assert.ok(points[i + 1] >= 8 && points[i + 1] <= layout.height - 8);
      }
    }
  }
});

test('12 to 20 to 12 display change keeps overlay, exact selection, inspector, slots, zoom and reads intact', async () => {
  const f = await verifiedBodyFixture(); await resolveBodyReferences(f); clickOverlay(f); f.controller.setZoom(0.7);
  const overlay = f.state.bodyReferenceOverlay, evidenceRow = f.state.evidence, source = f.state.bodyReferencesSource;
  const slots = JSON.stringify([...f.state.layoutSlots]), requests = f.requests.length, inspector = f.els.detail.replacements;
  const defaultHeight = f.els.canvas.style.values['--service-map-scaled-height'];
  for (const size of [20, 12]) {
    f.document.documentElement.style.setProperty('--ui-root-size', `${size}px`); f.controller.displayChanged();
    const geometry = map.graphGeometry(size);
    assert.match(f.els.canvas.innerHTML, new RegExp(`--service-map-card-height:${geometry.cardHeight}px`));
    assert.equal(f.state.zoomScale, 0.7); assert.equal(f.state.bodyReferenceOverlay, overlay);
    assert.equal(f.state.evidence, evidenceRow); assert.equal(f.state.bodyReferencesSource, source);
    assert.equal(f.state.selectedOrigin, originA); assert.equal(f.state.endpointIndex, 0);
    assert.equal(f.requests.length, requests); assert.equal(f.els.detail.replacements, inspector);
    assert.equal(JSON.stringify([...f.state.layoutSlots]), slots);
    if (size === 20) assert.ok(parseFloat(f.els.canvas.style.values['--service-map-scaled-height']) > parseFloat(defaultHeight));
    else assert.equal(f.els.canvas.style.values['--service-map-scaled-height'], defaultHeight);
  }
});

test('Display settings notify the existing map and graph line boxes follow shared font-aware geometry', () => {
  const app = fs.readFileSync(path.join(__dirname, '../web/app.js'), 'utf8'), css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
  assert.match(app, /function applyDisplaySettingsState[\s\S]*?targetServiceMapController\?\.displayChanged\?\.\(\)/);
  for (const selector of ['.service-map-card-copy strong', '.service-map-card-scheme, .service-map-card-meta', '.service-map-clues > span']) {
    const rule = css.slice(css.indexOf(selector), css.indexOf('}', css.indexOf(selector)));
    assert.match(rule, /line-height: var\(--service-map-line-height\)/);
  }
});

for (const value of [0, 127, 129, 128.5, '128', null]) test(`optional technology token-candidate limit rejects unsupported value: ${JSON.stringify(value)}`, () => {
  const payload = technologySnapshot(); payload.snapshot.limits.technology_token_candidates_per_row = value;
  assert.throws(() => map.normalizeSnapshot(payload, technologySession), /Invalid retained technology observations/);
});

test('128 technology token candidates is a supported optional limit and old-server absence stays valid', () => {
  const payload = technologySnapshot(); payload.snapshot.limits.technology_token_candidates_per_row = 128;
  assert.equal(map.normalizeSnapshot(payload, technologySession).origins.length, 1);
  delete payload.snapshot.limits.technology_token_candidates_per_row;
  delete payload.origins[0].technology_observations;
  assert.equal(map.normalizeSnapshot(payload, technologySession).origins[0].technology_observations.length, 0);
});

for (const items of [[], [technologyRow()]]) test(`token-budget partial scan is honest with ${items.length} observations and needs no body read`, async () => {
  const payload = technologySnapshot(items.map(row => technologyAggregate(row)));
  Object.assign(payload.snapshot, { complete: false, stopped_by: ['technology_token_scan_limit'], omitted_rows: 1 });
  payload.snapshot.limits.technology_token_candidates_per_row = 128;
  const f = await technologyFixture(payload), value = technologyEvidence(items);
  Object.assign(value.row, { metadata_complete: false, omitted: ['technology_token_scan_limit'] });
  assert.match(f.els.status.textContent, /Incomplete: technology_token_scan_limit/);
  assert.match(f.els.status.textContent, /Header technology scan partial: token candidate limit reached/);
  assert.equal(await resolveTechnologySource(f, value), true);
  assert.equal(f.state.evidence.technology_observations.length, items.length);
  assert.match(f.els.detail.innerHTML, /Header technology scan is partial: token candidate limit reached/);
  assert.match(f.els.detail.innerHTML, /Additional declarations may be omitted/);
  if (!items.length) assert.doesNotMatch(f.els.detail.innerHTML, /Header-reported technologies|No technologies|No products/);
  assert.equal(f.requests.length, 2); assert.equal(f.requests.some(request => /body-references|transactions|replay|scan|capture/.test(request.url)), false);
});

for (const complete of [true, undefined, null, 'false']) test(`candidate-limited map rejects false completeness: ${String(complete)}`, () => {
  const payload = technologySnapshot([]); payload.snapshot.stopped_by = ['technology_token_scan_limit'];
  if (complete === undefined) delete payload.snapshot.complete; else payload.snapshot.complete = complete;
  assert.throws(() => map.normalizeSnapshot(payload, technologySession), /Invalid retained technology observations/);
});

for (const extension of [true, false]) test(`candidate-limited exact row rejects metadata_complete true with extension ${extension ? 'present' : 'absent'}`, async () => {
  const f = await technologyFixture(), value = technologyEvidence([]);
  value.row.omitted = ['technology_token_scan_limit'];
  if (!extension) delete value.row.technology_observations;
  assert.equal(await resolveTechnologySource(f, value), false); assert.equal(f.state.evidence, null);
  assert.match(f.els.detail.innerHTML, /Source unavailable/);
});

// Catalog negotiation is per metadata response: a single GET, no downgrade
// retry, and no capability remembered across sessions or inspected sources.
const catalogV2Products = [
  ['gunicorn', 'Gunicorn', 'application_server', 'gunicorn', 'server'],
  ['uvicorn', 'Uvicorn', 'application_server', 'uvicorn', 'server'],
  ['waitress', 'Waitress', 'application_server', 'waitress', 'server'],
  ['openresty', 'OpenResty', 'web_server', 'openresty', 'server'],
  ['litespeed', 'LiteSpeed', 'web_server', 'LiteSpeed', 'server'],
  ['next_js', 'Next.js', 'application_framework', 'Next.js', 'x-powered-by'],
];
const withCatalog = (payload, version = 2) => ({ ...payload, technology_catalog_version: version });
const legacyCatalogNotice = 'Legacy server: catalog v1; additional declarations were not inspected.';
const requestedCatalog = request => request.options.headers?.['X-Sniper-Technology-Catalog-Version'];

test('GUI map and exact source request catalog 2 on exactly one GET each, without query negotiation', async () => {
  const f = await technologyFixture(withCatalog(technologySnapshot()));
  assert.equal(f.requests.length, 1); assert.equal(requestedCatalog(f.requests[0]), '2');
  assert.equal(f.state.snapshot.technologyCatalogVersion, 2); assert.equal(f.state.snapshot.legacyCatalog, false);
  assert.equal(await resolveTechnologySource(f, withCatalog(technologyEvidence())), true);
  assert.equal(f.requests.length, 2); assert.equal(f.state.evidenceCatalogVersion, 2); assert.equal(f.state.evidenceLegacyCatalog, false);
  for (const request of f.requests) {
    assert.equal(request.options.method || 'GET', 'GET'); assert.equal(requestedCatalog(request), '2');
    assert.doesNotMatch(request.url, /catalog|version=|body-references|transactions|replay|scan|capture/);
  }
  assert.doesNotMatch(f.els.status.textContent + f.els.detail.innerHTML, /Legacy server/);
});

test('old server ignores catalog header and strict unmarked v1 succeeds without fallback GET', async () => {
  const f = await technologyFixture();
  assert.equal(f.requests.length, 1); assert.equal(requestedCatalog(f.requests[0]), '2');
  assert.equal(f.state.snapshot.technologyCatalogVersion, 1); assert.equal(f.state.snapshot.legacyCatalog, true);
  assert.ok(f.els.status.textContent.includes(legacyCatalogNotice));
  assert.equal(await resolveTechnologySource(f), true); assert.equal(f.requests.length, 2);
  assert.equal(f.state.evidenceCatalogVersion, 1); assert.equal(f.state.evidenceLegacyCatalog, true);
  assert.ok(f.els.detail.innerHTML.includes(legacyCatalogNotice));
});

test('normalization accepts explicit matching v1/v2 and unmarked v1, while markers must match the request', () => {
  for (const version of [1, 2]) {
    const value = map.normalizeSnapshot(withCatalog(technologySnapshot(), version), technologySession, version);
    assert.equal(value.technologyCatalogVersion, version); assert.equal(value.legacyCatalog, false);
  }
  for (const requested of [1, 2]) {
    assert.equal(map.normalizeSnapshot(technologySnapshot(), technologySession, requested).technologyCatalogVersion, 1);
    assert.throws(() => map.normalizeSnapshot(withCatalog(technologySnapshot(), requested === 1 ? 2 : 1), technologySession, requested), /catalog version/);
  }
  for (const requested of [0, 3, '2', null]) assert.throws(() => map.normalizeSnapshot(technologySnapshot(), technologySession, requested), /requested technology catalog/);
});

for (const marker of [undefined, null, '2', '1', 0, 1, 3, 2.5, true, {}, [], [2]]) {
  test(`map rejects present malformed or mismatched catalog marker without retry: ${JSON.stringify(marker)}`, async () => {
    const f = fixture(); f.setSession(technologySession);
    await f.load(withCatalog(technologySnapshot(), 2));
    const previous = f.state.snapshot, pending = f.controller.refresh();
    const payload = technologySnapshot(); payload.technology_catalog_version = marker;
    f.requests.at(-1).resolve(response(payload)); assert.equal(await pending, false);
    assert.equal(f.requests.length, 2); assert.equal(f.state.snapshot, previous); assert.match(f.state.error, /Reload failed/);
  });
  test(`exact source rejects present malformed or mismatched catalog marker without retry: ${JSON.stringify(marker)}`, async () => {
    const f = await technologyFixture(withCatalog(technologySnapshot()));
    const payload = technologyEvidence(); payload.technology_catalog_version = marker;
    assert.equal(await resolveTechnologySource(f, payload), false);
    assert.equal(f.requests.length, 2); assert.equal(f.state.evidence, null); assert.equal(f.state.evidenceCatalogVersion, null);
    assert.equal(f.state.evidenceLegacyCatalog, false); assert.match(f.state.evidenceError, /Source unavailable/);
  });
}

for (const product of catalogV2Products) test(`v2 literal ${product[0]} is scoped to catalog 2, with unchanged reported/unknown versions`, async () => {
  for (const [version, status] of [['10.2.003', 'reported'], [null, 'not_reported'], [null, 'unsupported_format']]) {
    const row = technologyRow(product, version, { version_status: status });
    const payload = withCatalog(technologySnapshot([technologyAggregate(row)]));
    assert.equal(map.normalizeRowTechnologies([row], 2)[0].product_id, product[0]);
    assert.throws(() => map.normalizeRowTechnologies([row]), /Invalid retained technology observations/);
    assert.throws(() => map.normalizeSnapshot({ ...payload, technology_catalog_version: 1 }, technologySession, 1), /Invalid retained technology observations/);
    const unmarked = { ...payload }; delete unmarked.technology_catalog_version;
    assert.throws(() => map.normalizeSnapshot(unmarked, technologySession), /Invalid retained technology observations/);
    const f = await technologyFixture(payload);
    assert.equal(await resolveTechnologySource(f, withCatalog(technologyEvidence([row]))), true);
    assert.equal(f.state.evidence.technology_observations.length, 1);
    assert.equal(f.state.evidence.technology_observations[0].product_id, product[0]);
    assert.deepEqual(JSON.parse(JSON.stringify(f.state.evidence.technology_observations[0])), row);
    assert.doesNotMatch(f.els.detail.innerHTML, /service-map-verified/);
    assert.equal(await resolveTechnologySource(f, technologyEvidence([row])), false, 'a v2 map never permits v2 evidence in an unmarked response');
    assert.equal(f.requests.length, 3);
  }
});

test('v2 observations do not invent language runtimes, frameworks, proxies, or companion products', async () => {
  const rows = catalogV2Products.map((product, header_index) => technologyRow(product, null, { header_index }));
  const f = await technologyFixture(withCatalog(technologySnapshot(rows.map(row => technologyAggregate(row)))));
  assert.equal(await resolveTechnologySource(f, withCatalog(technologyEvidence(rows))), true);
  assert.deepEqual(Array.from(f.state.evidence.technology_observations, item => item.product_id), catalogV2Products.map(product => product[0]));
  assert.deepEqual(Array.from(f.state.snapshot.origins[0].technology_observations, item => item.product_id), catalogV2Products.map(product => product[0]));
  assert.doesNotMatch(f.els.detail.innerHTML, /Python|Node\.js|React|nginx|load balancer|reverse proxy/);
  assert.equal(f.state.snapshot.origins[0].technology_clues.length, 0);
});

for (const [name, patch] of [
  ['v2 rule suffix', { rule_id: 'server.gunicorn.v2' }],
  ['invented category', { catalog_category: 'language_runtime' }],
  ['wrong literal span', { product_span: { start: 0, end: 7 } }],
  ['wrong header', { header_name: 'x-powered-by', rule_id: 'x_powered_by.gunicorn.v1' }],
  ['unsupported reported suffix', { reported_version: '2.1-beta' }],
  ['invented non-product status', { reported_version: null, version_status: 'non_product_version', version_span: null }],
]) test(`v2 retains closed identity/span/version checks: ${name}`, async () => {
  const row = technologyRow(catalogV2Products[0], '2.1', patch);
  const f = await technologyFixture(withCatalog(technologySnapshot()));
  assert.equal(await resolveTechnologySource(f, withCatalog(technologyEvidence([row]))), false);
  assert.equal(f.requests.length, 2);
});

for (const kind of ['map', 'evidence']) for (const failure of ['http', 'network', 'json']) test(`${kind} ${failure} failure adds no catalog retry`, async () => {
  const f = fixture();
  if (kind === 'evidence') { await f.load(withCatalog(snapshot())); f.controller.selectOrigin(originA); }
  const baseline = f.requests.length;
  const pending = kind === 'map' ? f.controller.refresh() : f.controller.loadEvidence('evidence-one');
  const request = f.requests.at(-1);
  if (failure === 'http') request.resolve(response({}, 400));
  if (failure === 'network') request.reject(new Error('offline'));
  if (failure === 'json') request.resolve({ ok: true, json: async () => { throw new Error('bad JSON'); } });
  assert.equal(await pending, false); assert.equal(f.requests.length, baseline + 1);
  assert.equal(requestedCatalog(request), '2');
});

test('newest map response owns catalog state even when old-server JSON completes last', async () => {
  const f = fixture(), parse = deferred(), old = f.controller.refresh();
  f.requests[0].resolve({ ok: true, json: () => parse.promise }); await Promise.resolve();
  const current = f.controller.refresh({ force: true });
  f.requests[1].resolve(response(withCatalog(snapshot()))); await current;
  parse.resolve(snapshot()); await old;
  assert.equal(f.state.snapshot.technologyCatalogVersion, 2); assert.equal(f.state.snapshot.legacyCatalog, false);
  assert.doesNotMatch(f.els.status.textContent, /Legacy server/); assert.equal(f.requests.length, 2);
});

test('source catalog is validated independently and a later inspection clears fallback state', async () => {
  const f = await technologyFixture(withCatalog(technologySnapshot()));
  assert.equal(await resolveTechnologySource(f), true); assert.equal(f.state.evidenceLegacyCatalog, true);
  const pending = f.controller.loadEvidence(technologyToken());
  assert.equal(f.state.evidenceLegacyCatalog, false); assert.equal(f.state.evidenceCatalogVersion, null);
  f.requests.at(-1).resolve(response(withCatalog(technologyEvidence()))); await pending;
  assert.equal(f.state.evidenceLegacyCatalog, false); assert.equal(f.state.evidenceCatalogVersion, 2);
  assert.doesNotMatch(f.els.detail.innerHTML, /Legacy server/); assert.equal(f.requests.length, 3);
});

test('map catalog transition invalidates an in-flight source and does not cache old-server capability', async () => {
  const f = await technologyFixture(withCatalog(technologySnapshot()));
  const pending = f.controller.loadEvidence(technologyToken()), old = f.requests.at(-1);
  await f.load(technologySnapshot());
  old.resolve(response(withCatalog(technologyEvidence()))); assert.equal(await pending, false);
  assert.equal(f.state.evidence, null); assert.equal(f.state.evidenceCatalogVersion, null);
  assert.equal(f.state.snapshot.technologyCatalogVersion, 1);
  await f.load(withCatalog(technologySnapshot()));
  assert.equal(f.state.snapshot.technologyCatalogVersion, 2);
  assert.equal(f.requests.length, 4); assert.ok(f.requests.every(request => requestedCatalog(request) === '2'));
});

test('session changes discard pending catalog data and the next session negotiates afresh', async () => {
  const f = await technologyFixture(withCatalog(technologySnapshot()));
  const pending = f.controller.loadEvidence(technologyToken()), old = f.requests.at(-1), parse = deferred();
  old.resolve({ ok: true, json: () => parse.promise }); await Promise.resolve();
  f.setSession('session-two'); f.controller.reset();
  assert.equal(f.state.snapshot, null); assert.equal(f.state.evidenceCatalogVersion, null);
  await f.load(snapshot(undefined, 'session-two'));
  parse.resolve(withCatalog(technologyEvidence())); assert.equal(await pending, false);
  assert.equal(f.state.evidence, null); assert.equal(f.state.snapshot.technologyCatalogVersion, 1);
  f.setSession(technologySession); await f.load(withCatalog(technologySnapshot()));
  assert.equal(f.state.snapshot.technologyCatalogVersion, 2); assert.equal(f.state.snapshot.legacyCatalog, false);
  assert.equal(f.requests.length, 4); assert.ok(f.requests.every(request => requestedCatalog(request) === '2'));
});

test('catalog header never reaches the existing explicit body-reference request and unchanged polls preserve it', async () => {
  const f = fixture(); await f.load(withCatalog(snapshot())); f.controller.selectOrigin(originA, 0);
  const pending = f.controller.loadEvidence('evidence-one'); f.requests.at(-1).resolve(response(withCatalog(evidence()))); await pending;
  assert.equal(f.requests.length, 2);
  assert.equal(await resolveBodyReferences(f), true); const result = f.state.bodyReferences;
  assert.equal(f.requests.length, 3); assert.equal(f.requests[2].options.headers, undefined);
  await f.load(withCatalog(snapshot()));
  assert.equal(f.requests.length, 4); assert.equal(f.state.bodyReferences, result);
  assert.equal(requestedCatalog(f.requests[3]), '2');
});

// Independent HTML-generator inspection: all payloads below are synthetic.
function htmlGeneratorObservation(product = 'wordpress', version = '6.8.1', start = 12, status = version === null ? 'not_reported' : 'reported') {
  const name = product === 'wordpress' ? 'WordPress' : 'Drupal', productStart = start + 32, productEnd = productStart + name.length;
  const end = status === 'reported' ? productEnd + 1 + version.length : status === 'unsupported_format' ? productEnd + 6 : productEnd;
  return { product_id: product, name, catalog_category: 'cms', reported_version: version, version_status: status,
    source: 'response_html_meta_generator', strength: 'literal_declaration', rule_id: `html_meta_generator.${product}.v1`,
    tag_span: { start, end: end + 2 }, content_span: { start: productStart, end }, product_span: { start: productStart, end: productEnd },
    version_span: status === 'reported' ? { start: productEnd + 1, end } : null, offset_basis: 'retained_utf8_preview' };
}
function htmlGenerators(patch = {}) {
  return { schema_version: 1, generator_catalog_version: 1, session_id: technologySession, evidence_id: technologyToken(),
    available: true, status: 'scanned', complete: true, reasons: [], source_origin: originA, source_sequence: '1', source_started_at: technologyTime,
    retained_preview_bytes: 1024, scan_prefix_bytes: 1024, capture_preview_truncated: false, scan_prefix_truncated: false,
    coverage: 'literal_html_generator_explicit_head', head_closed: true, parser_stop: null, tag_candidates_inspected: 4,
    additional_tag_candidate_encountered: false, additional_observation_encountered: false, unknown_product_declarations: 0,
    observations: [htmlGeneratorObservation()], limits: { ...map.HTML_GENERATOR_LIMITS }, offset_basis: 'retained_utf8_preview', ...patch };
}
function missingHtmlGenerators(status = 'unavailable', reason = 'record_missing') {
  return htmlGenerators({ available: false, status, complete: false, reasons: [reason], source_origin: null, source_sequence: null,
    source_started_at: null, retained_preview_bytes: null, scan_prefix_bytes: 0, head_closed: false, tag_candidates_inspected: 0, observations: [] });
}
async function htmlGeneratorFixture() {
  const f = await technologyFixture(withCatalog(technologySnapshot()));
  await resolveTechnologySource(f, withCatalog(technologyEvidence())); return f;
}
async function resolveHtmlGenerators(f, value = htmlGenerators()) {
  const pending = f.controller.loadHtmlGenerators(); f.requests.at(-1).resolve(response(value)); return pending;
}
function clickHtmlInspector(f) {
  f.els.panel.dispatch('change', { target: { dataset: { servicePacketInspect: 'true' }, value: 'generator' } });
}
function htmlSection(f) { return f.els.detail.innerHTML.match(/<section[^>]*service-map-html-generators[\s\S]*?<\/section>/)?.[0] || ''; }

test('HTML generator action is independent, explicit and uses one exact token GET without catalog negotiation', async () => {
  const f = await technologyFixture(withCatalog(technologySnapshot()));
  assert.equal(await f.controller.loadHtmlGenerators(), false); assert.equal(f.requests.length, 1);
  await resolveTechnologySource(f, withCatalog(technologyEvidence()));
  assert.equal(htmlSection(f), ''); assert.equal(f.state.htmlGenerators, null);
  const count = f.requests.length; f.controller.setZoom(1.2); f.controller.fitGraph(); f.controller.displayChanged();
  f.controller.selectOrigin(originA, 0); await resolveTechnologySource(f, withCatalog(technologyEvidence()));
  assert.equal(f.requests.length, count + 1); assert.equal(f.requests.filter(r => /html-generators|body-references/.test(r.url)).length, 0);
  clickHtmlInspector(f); clickHtmlInspector(f); assert.equal(await f.controller.loadHtmlGenerators(), false);
  const request = f.requests.at(-1), url = new URL(request.url, originA);
  assert.equal(url.pathname, '/api/target/service-map/html-generators'); assert.equal(url.searchParams.get('session_id'), technologySession);
  assert.equal(url.searchParams.get('evidence_id'), technologyToken()); assert.equal([...url.searchParams.keys()].length, 2);
  assert.equal(request.options.method || 'GET', 'GET'); assert.equal(request.options.headers, undefined); assert.equal(request.options.redirect, 'error');
  assert.match(htmlSection(f), /aria-busy="true"/);
  request.resolve(response(htmlGenerators())); await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.htmlGenerators.status, 'scanned'); assert.equal(f.state.bodyReferences, null); assert.equal(f.state.bodyReferenceOverlay, null);
  assert.equal(f.requests.filter(r => r.url.includes('/html-generators')).length, 1);
  assert.doesNotMatch(htmlSection(f), /data-service-show|Show references on map/);
});

test('HTML generators retain conflicting literal reports, each named with its version', async () => {
  const f = await htmlGeneratorFixture();
  const observations = [htmlGeneratorObservation(), htmlGeneratorObservation('wordpress', '6.7.2', 90),
    htmlGeneratorObservation('drupal', null, 170), htmlGeneratorObservation('drupal', null, 240, 'unsupported_format')];
  assert.equal(await resolveHtmlGenerators(f, htmlGenerators({ observations, tag_candidates_inspected: 7 })), true);
  const html = htmlSection(f);
  for (const text of ['<strong>WordPress 6.8.1</strong>', '<strong>WordPress 6.7.2</strong>', 'meta generator']) assert.ok(html.includes(text), text);
  assert.equal((html.match(/<strong>Drupal<\/strong>/g) || []).length, 2, 'an unreported or unsupported version names the product alone');
  assert.equal(f.state.htmlGenerators.observations.length, 4); assert.doesNotMatch(html, /<meta|<script|Show references on map/);
});

for (const [name, patch, expected] of [
  ['complete head', {}, /Complete supported-head inspection/],
  ['capture-truncated body after closed head', { capture_preview_truncated: true, complete: false, reasons: ['capture_preview_truncated'] }, /Partial retained-preview coverage/],
  ['prefix-truncated body after closed head', { scan_prefix_truncated: true, retained_preview_bytes: 300000, scan_prefix_bytes: 262144, complete: false, reasons: ['scan_prefix_truncated'] }, /Partial retained-preview coverage/],
  ['both truncation flags after closed head', { capture_preview_truncated: true, scan_prefix_truncated: true, retained_preview_bytes: 300000, scan_prefix_bytes: 262144, complete: false, reasons: ['capture_preview_truncated', 'scan_prefix_truncated'] }, /Partial retained-preview coverage/],
]) test(`HTML generator ${name} labels head and overall coverage separately`, async () => {
  const f = await htmlGeneratorFixture(); assert.equal(await resolveHtmlGenerators(f, htmlGenerators(patch)), true);
  assert.match(htmlSection(f), expected); assert.match(htmlSection(f), /Supported explicit head closed: yes/);
  assert.match(htmlSection(f), /offered to the parser/);
});

for (const reason of ['end_of_preview', 'input_limit', 'tag_candidate_limit', 'tag_byte_limit', 'attribute_limit', 'observation_limit',
  'unsupported_document_context', 'unsupported_head_context', 'unsupported_doctype', 'unsupported_comment', 'unsupported_script_escape',
  'unsupported_entity', 'unsupported_self_closing', 'malformed_tag', 'duplicate_attribute', 'null_byte']) test(`HTML generator partial parser stop is bounded and honest: ${reason}`, async () => {
  const f = await htmlGeneratorFixture(), value = htmlGenerators({ complete: false, head_closed: false, parser_stop: { reason, byte_cursor: 900 }, reasons: [reason], observations: [] });
  if (reason === 'input_limit') { value.scan_prefix_truncated = true; value.retained_preview_bytes = 300000; value.scan_prefix_bytes = 262144; value.parser_stop.byte_cursor = 262144; value.reasons = ['input_limit', 'scan_prefix_truncated']; }
  if (reason === 'end_of_preview') value.parser_stop.byte_cursor = value.scan_prefix_bytes;
  if (reason === 'tag_candidate_limit') { value.additional_tag_candidate_encountered = true; value.tag_candidates_inspected = 4096; value.retained_preview_bytes = 262144; value.scan_prefix_bytes = 262144; value.parser_stop.byte_cursor = 262100; }
  if (reason === 'observation_limit') { value.additional_observation_encountered = true; value.tag_candidates_inspected = 11; value.observations = Array.from({ length: 8 }, (_, i) => htmlGeneratorObservation('wordpress', '6.8.1', 12 + i * 70)); }
  assert.equal(await resolveHtmlGenerators(f, value), true);
  assert.match(htmlSection(f), /Partial retained-preview coverage/); assert.match(htmlSection(f), /Supported explicit head closed: no/);
  assert.doesNotMatch(htmlSection(f), /not found|No supported WordPress or Drupal generator declarations in the inspected head/);
  assert.match(htmlSection(f), /Uninspected declarations are not counted/);
});

test('HTML generator empty proven preview remains partial without inventing declarations or skipped totals', async () => {
  const f = await htmlGeneratorFixture(); const value = htmlGenerators({ complete: false, head_closed: false, retained_preview_bytes: 0, scan_prefix_bytes: 0,
    parser_stop: { reason: 'end_of_preview', byte_cursor: 0 }, reasons: ['end_of_preview'], tag_candidates_inspected: 0, observations: [] });
  assert.equal(await resolveHtmlGenerators(f, value), true); assert.match(htmlSection(f), /coverage is partial/); assert.doesNotMatch(htmlSection(f), /not found/);
});
for (const [status, reason] of [['unsupported', 'unsupported_content_type'], ['unavailable', 'retained_preview_unavailable']]) test(`HTML generator ${status} has no source or false negative report`, async () => {
  const f = await htmlGeneratorFixture(); assert.equal(await resolveHtmlGenerators(f, missingHtmlGenerators(status, reason)), true);
  assert.match(htmlSection(f), /Generator declarations were not inspected/); assert.doesNotMatch(htmlSection(f), /not found|Source: https|Sequence 1|Complete supported-head/);
  assert.equal(f.state.htmlGenerators.source_origin, null); assert.equal(f.state.htmlGenerators.observations.length, 0);
});

test('old-server HTML generator 404 is unsupported without response-body parsing, retries or raw errors', async () => {
  const f = await htmlGeneratorFixture(), count = f.requests.length, pending = f.controller.loadHtmlGenerators();
  f.requests.at(-1).resolve({ ok: false, status: 404, json() { assert.fail('Never parse old-server errors'); }, text() { assert.fail('Never echo old-server errors'); } });
  assert.equal(await pending, false); assert.equal(f.requests.length, count + 1); assert.equal(f.state.htmlGenerators, null);
  assert.match(htmlSection(f), /This server does not support retained HTML generator inspection/);
  const poll = f.controller.refresh(); f.requests.at(-1).resolve(response(withCatalog(technologySnapshot()))); await poll;
  assert.equal(f.requests.filter(r => r.url.includes('/html-generators')).length, 1);
});

for (const [name, mutate] of [
  ['schema', v => v.schema_version = 2], ['catalog', v => v.generator_catalog_version = 2], ['session', v => v.session_id = 'other'],
  ['evidence', v => v.evidence_id = technologyToken('2')], ['availability', v => v.available = false], ['status', v => v.status = 'partial'],
  ['non-boolean complete', v => v.complete = 'true'], ['false complete', v => v.complete = false], ['coverage', v => v.coverage = 'all_html'],
  ['offset basis', v => v.offset_basis = 'response'], ['omitted nullable stop', v => delete v.parser_stop], ['raw body', v => v.body = 'PRIVATE_BODY'],
  ['raw diagnostic', v => v.diagnostic = 'PRIVATE_DIAGNOSTIC'], ['origin', v => v.source_origin = originB], ['uncanonical origin', v => v.source_origin += '/'],
  ['numeric sequence', v => v.source_sequence = 1], ['wrong sequence', v => v.source_sequence = '2'], ['time', v => v.source_started_at = technologyLast],
  ['invalid time', v => v.source_started_at = '2026-02-30T00:00:00Z'], ['preview null', v => v.retained_preview_bytes = null],
  ['prefix exceeds preview', v => v.scan_prefix_bytes = 1025], ['prefix exceeds limit', v => { v.scan_prefix_bytes = 262145; v.retained_preview_bytes = 262145; }],
  ['fractional prefix', v => v.scan_prefix_bytes = 1.5], ['limit', v => v.limits.attributes = 33], ['additional limit key', v => v.limits.unknown = 1],
  ['unallowlisted reason', v => v.reasons = ['PRIVATE_BODY']], ['capture flag without reason', v => v.capture_preview_truncated = true],
  ['prefix flag without reason', v => v.scan_prefix_truncated = true], ['non-boolean head', v => v.head_closed = 1], ['missing stop for partial head', v => v.head_closed = false],
  ['tag count', v => v.tag_candidates_inspected = 4097], ['unknown count', v => v.unknown_product_declarations = 5],
  ['unproven extra tag', v => v.additional_tag_candidate_encountered = true], ['unproven extra observation', v => v.additional_observation_encountered = true],
  ['arbitrary product', v => v.observations[0].product_id = 'private-product'], ['product alias', v => v.observations[0].name = 'WORDPRESS'],
  ['category', v => v.observations[0].catalog_category = 'runtime'], ['source', v => v.observations[0].source = 'response_header'],
  ['strength', v => v.observations[0].strength = 'verified'], ['rule', v => v.observations[0].rule_id = 'unknown'],
  ['raw tag', v => v.observations[0].raw_tag = '<meta PRIVATE_BODY>'], ['version suffix', v => v.observations[0].reported_version = '6.8-PRIVATE_BODY'],
  ['version whitespace', v => v.observations[0].reported_version = '6.8.1 '], ['version unicode', v => v.observations[0].reported_version = '٦.٨.١'],
  ['version status', v => v.observations[0].version_status = 'verified'], ['hidden rejected version', v => v.observations[0].version_status = 'unsupported_format'],
  ['tag before prefix', v => v.observations[0].tag_span.start = -1], ['tag exceeds prefix', v => v.observations[0].tag_span.end = 1025],
  ['reversed tag', v => v.observations[0].tag_span.end = 1], ['raw span key', v => v.observations[0].tag_span.raw = 'PRIVATE_BODY'],
  ['content outside tag', v => v.observations[0].content_span.end = 61], ['wrong product start', v => v.observations[0].product_span.start++],
  ['wrong product length', v => v.observations[0].product_span.end++], ['overlapping version', v => v.observations[0].version_span.start = 53],
  ['wrong version length', v => v.observations[0].version_span.start++], ['version outside content', v => v.observations[0].version_span.end++],
  ['overlapping declarations', v => v.observations.push(htmlGeneratorObservation())], ['output overflow', v => v.observations = Array(9).fill(v.observations[0])],
]) test(`HTML generator envelope rejects ${name} without publishing private content`, async () => {
  const f = await htmlGeneratorFixture(), value = htmlGenerators(); mutate(value);
  assert.equal(await resolveHtmlGenerators(f, value), false); assert.equal(f.state.htmlGenerators, null);
  assert.match(htmlSection(f), /Could not verify retained HTML generators/);
  assert.doesNotMatch(JSON.stringify(f.state.htmlGenerators) + htmlSection(f), /PRIVATE_BODY|PRIVATE_DIAGNOSTIC|private-product|6\.8-PRIVATE/);
});

for (const key of ['source_origin', 'source_sequence', 'source_started_at', 'retained_preview_bytes', 'parser_stop']) test(`HTML generator unavailable requires explicit null ${key}`, () => {
  const value = missingHtmlGenerators(); delete value[key];
  assert.throws(() => map.normalizeHtmlGenerators(value, technologySession, technologyToken(), technologyEvidence().row), /Invalid retained HTML-generator response/);
});

for (const [name, mutate] of [
  ['source metadata', v => v.source_origin = originA], ['observation', v => v.observations = [htmlGeneratorObservation()]],
  ['scan bytes', v => v.scan_prefix_bytes = 1], ['tags', v => v.tag_candidates_inspected = 1], ['truncation', v => v.capture_preview_truncated = true],
  ['parser reason', v => v.reasons = ['end_of_preview']], ['no reason', v => v.reasons = []],
]) test(`HTML generator unavailable rejects leftover ${name}`, () => {
  const value = missingHtmlGenerators(); mutate(value);
  assert.throws(() => map.normalizeHtmlGenerators(value, technologySession, technologyToken(), technologyEvidence().row), /Invalid retained HTML-generator response/);
});

test('HTML generator pending and result survive real app unchanged polls without repeated inspection reads', async () => {
  const f = await htmlGeneratorFixture(); clickHtmlInspector(f); const request = f.requests.at(-1), initial = f.els.detail.replacements;
  for (let i = 0; i < 3; i++) {
    const poll = pollRealTargetMap(f); f.requests.at(-1).resolve(response(withCatalog(technologySnapshot()))); await poll;
    assert.equal(request.options.signal.aborted, false); assert.equal(f.state.htmlGeneratorsLoading, true); assert.equal(f.els.detail.replacements, initial);
  }
  request.resolve(response(htmlGenerators())); await new Promise(resolve => setImmediate(resolve));
  const result = f.state.htmlGenerators, source = f.state.htmlGeneratorsSource;
  const nativeHtml = f.els.detail.innerHTML.replace('<details class="service-map-html-generator-limits">', '<details class="service-map-html-generator-limits" open="">');
  f.els.detail.innerHTML = nativeHtml; const replacements = f.els.detail.replacements;
  const poll = pollRealTargetMap(f); f.requests.at(-1).resolve(response(withCatalog(technologySnapshot()))); await poll;
  assert.equal(f.state.htmlGenerators, result); assert.equal(f.state.htmlGeneratorsSource, source);
  assert.equal(f.els.detail.replacements, replacements); assert.equal(f.els.detail.innerHTML, nativeHtml);
  assert.equal(f.requests.filter(r => r.url.includes('/html-generators')).length, 1);
});

for (const change of ['token', 'generation', 'source path', 'source method', 'origin removed', 'refresh failure', 'force refresh', 'history invalidation', 'source reinspection', 'hide', 'disconnect', 'session']) test(`HTML generator late result is fenced after ${change}`, async () => {
  const f = await htmlGeneratorFixture(); const pending = f.controller.loadHtmlGenerators(), request = f.requests.at(-1);
  if (['token', 'generation', 'source path', 'source method', 'origin removed', 'refresh failure', 'force refresh'].includes(change)) {
    const payload = withCatalog(technologySnapshot());
    if (change === 'token') { payload.origins[0].endpoints[0].evidence = [technologyToken('2')]; payload.origins[0].technology_observations = []; }
    if (change === 'generation') { payload.snapshot.generation = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'; payload.origins[0].technology_observations = []; }
    if (change === 'source path') payload.origins[0].endpoints[0].path = '/changed';
    if (change === 'source method') payload.origins[0].endpoints[0].method = 'POST';
    if (change === 'origin removed') payload.origins = [];
    const poll = f.controller.refresh({ force: change === 'force refresh' });
    if (change === 'refresh failure') f.requests.at(-1).reject(new Error('PRIVATE_BODY'));
    else f.requests.at(-1).resolve(response(payload));
    await poll;
  } else if (change === 'history invalidation') f.controller.markDirty();
  else if (change === 'source reinspection') { const verify = f.controller.loadEvidence(technologyToken()); f.requests.at(-1).resolve(response(withCatalog(technologyEvidence()))); await verify; }
  else if (change === 'hide') f.controller.setVisible(false);
  else if (change === 'disconnect') f.controller.disconnect();
  else { f.setSession('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'); f.controller.reset(); }
  assert.equal(request.options.signal.aborted, true); assert.equal(f.state.htmlGeneratorsSource, null);
  request.resolve(response(htmlGenerators())); assert.equal(await pending, false); assert.equal(f.state.htmlGenerators, null);
  assert.equal(f.state.htmlGeneratorsLoading, false); assert.doesNotMatch(htmlSection(f), /Reported version: 6\.8\.1/);
});

test('HTML and URL-reference pending reads, results and overlay are independent in either completion order', async () => {
  for (const htmlFirst of [true, false]) {
    const f = await htmlGeneratorFixture(), html = f.controller.loadHtmlGenerators(), htmlRead = f.requests.at(-1);
    const body = f.controller.loadBodyReferences(), bodyRead = f.requests.at(-1);
    const bodyValue = bodyReferences({ session_id: technologySession, evidence_id: technologyToken(), source_sequence: '1' });
    if (htmlFirst) { htmlRead.resolve(response(htmlGenerators())); await html; bodyRead.resolve(response(bodyValue)); await body; }
    else { bodyRead.resolve(response(bodyValue)); await body; assert.equal(f.controller.showBodyReferencesOnMap(), true); htmlRead.resolve(response(htmlGenerators())); await html; }
    assert.equal(f.state.htmlGenerators.observations.length, 1); assert.equal(f.state.bodyReferences.references.length, 1);
    assert.equal(f.controller.showBodyReferencesOnMap(), true); const overlay = f.state.bodyReferenceOverlay;
    await resolveHtmlGenerators(f, missingHtmlGenerators('unavailable', 'body_storage_unavailable')); assert.equal(f.state.bodyReferenceOverlay, overlay);
    assert.equal(f.state.bodyReferences.references.length, 1); f.controller.clearBodyReferenceOverlay();
    assert.equal(f.state.htmlGenerators.status, 'unavailable'); assert.equal(f.requests.filter(r => r.url.includes('/body-references')).length, 1);
    assert.equal(f.requests.filter(r => r.url.includes('/html-generators')).length, 2);
  }
});

test('HTML generator rejects malformed verified-token identities before issuing an inspection request', async () => {
  const f = await verifiedBodyFixture(), count = f.requests.length;
  assert.equal(await f.controller.loadHtmlGenerators(), false); assert.equal(f.requests.length, count);
  for (const mutate of [row => row.sequence = '2', row => row.record_id = technologyGeneration, row => row.started_at = 'invalid', row => row.origin += '/']) {
    const good = await htmlGeneratorFixture(), count = good.requests.length; mutate(good.state.evidence);
    assert.equal(await good.controller.loadHtmlGenerators(), false); assert.equal(good.requests.length, count);
  }
});

function nativeHtmlGeneratorModel(f) {
  const descriptor = Object.getOwnPropertyDescriptor(f.els.detail, 'innerHTML');
  const fresh = html => ({
    body: html.includes('service-map-detail-body') ? { scrollTop: 0 } : null,
    limits: html.includes('class="service-map-html-generator-limits"') ? { open: false } : null,
    bodyLimits: html.includes('class="service-map-body-reference-limits"') ? { open: false } : null,
    summary: html.includes('data-service-focus="html-generators:limits"') ? { dataset: { serviceFocus: 'html-generators:limits' }, isConnected: true,
      getClientRects: () => [{}], focus() { f.document.activeElement = this; } } : null,
  });
  let current = fresh(f.els.detail.innerHTML);
  f.els.detail.querySelector = selector => current[{ '.service-map-detail-body': 'body', '.service-map-html-generator-limits': 'limits', '.service-map-body-reference-limits': 'bodyLimits' }[selector]] || null;
  f.els.detail.querySelectorAll = () => current.summary ? [current.summary] : [];
  Object.defineProperty(f.els.detail, 'innerHTML', { get: descriptor.get, set(html) {
    if (current.summary) current.summary.isConnected = false;
    if (f.document.activeElement === current.summary) f.document.activeElement = f.document.body;
    descriptor.set.call(this, html); current = fresh(html);
  } });
  return () => current;
}

test('selected HTML generator completion preserves focus and disclosure without a second default result', async () => {
  const f = await htmlGeneratorFixture(), view = nativeHtmlGeneratorModel(f);
  const pending = f.controller.loadHtmlGenerators();
  view().limits.open = true; assert.equal(view().bodyLimits, null); view().body.scrollTop = 360; f.document.activeElement = view().summary;
  f.requests.at(-1).resolve(response(htmlGenerators())); await pending;
  assert.equal(view().limits.open, true); assert.equal(view().bodyLimits, null); assert.equal(view().body.scrollTop, 360); assert.equal(f.document.activeElement, view().summary);
  const result = f.state.htmlGenerators, previous = view(), payload = withCatalog(technologySnapshot()); payload.origins[0].in_scope = false;
  const poll = f.controller.refresh(); f.requests.at(-1).resolve(response(payload)); await poll;
  assert.notEqual(view(), previous); assert.equal(f.state.htmlGenerators, result);
  assert.equal(view().limits.open, true); assert.equal(view().bodyLimits, null); assert.equal(view().body.scrollTop, 360); assert.equal(f.document.activeElement, view().summary);
  const verify = f.controller.loadEvidence(technologyToken()); f.requests.at(-1).resolve(response(withCatalog(technologyEvidence()))); await verify;
  assert.equal(f.state.htmlGenerators, null); assert.equal(view().limits, null); assert.equal(view().bodyLimits, null); assert.equal(view().body.scrollTop, 0);
  assert.notEqual(f.document.activeElement, previous.summary);
  const again = f.controller.loadHtmlGenerators(); assert.equal(view().limits.open, false);
  f.requests.at(-1).resolve(response(htmlGenerators())); await again;
  assert.equal(view().limits.open, false); assert.equal(view().bodyLimits, null);
});

test('HTML generator normalization copies every mutable output span and reasons array', () => {
  const payload = htmlGenerators(), normalized = map.normalizeHtmlGenerators(payload, technologySession, technologyToken(), technologyEvidence().row);
  payload.observations[0].tag_span.start = 1; payload.observations[0].content_span.start = 1; payload.observations[0].product_span.start = 1;
  payload.observations[0].version_span.start = 1; payload.reasons.push('PRIVATE_BODY'); payload.observations.push(htmlGeneratorObservation('drupal', '10.3', 200));
  assert.equal(normalized.observations.length, 1); assert.equal(normalized.observations[0].tag_span.start, 12);
  assert.equal(normalized.observations[0].content_span.start, 44); assert.equal(normalized.observations[0].product_span.start, 44);
  assert.equal(normalized.observations[0].version_span.start, 54); assert.equal(normalized.reasons.length, 0);
});

for (const mutate of [v => v.parser_stop.byte_cursor = 1025, v => v.parser_stop.byte_cursor = 60, v => v.parser_stop.reason = 'PRIVATE_DIAGNOSTIC',
  v => v.parser_stop.raw = 'PRIVATE_BODY', v => v.reasons = ['unsupported_head_context', 'unsupported_head_context'],
  v => v.reasons = ['unsupported_head_context', 'capture_preview_truncated'], v => v.head_closed = true]) test('HTML generator rejects inconsistent parser coverage metadata', () => {
  const value = htmlGenerators({ complete: false, head_closed: false, parser_stop: { reason: 'unsupported_head_context', byte_cursor: 100 }, reasons: ['unsupported_head_context'] }); mutate(value);
  assert.throws(() => map.normalizeHtmlGenerators(value, technologySession, technologyToken(), technologyEvidence().row), /Invalid retained HTML-generator response/);
});

for (const [name, mutate] of [
  ['zero-byte closed head', v => { v.retained_preview_bytes = 0; v.scan_prefix_bytes = 0; v.tag_candidates_inspected = 0; v.observations = []; }],
  ['two-tag closed head', v => { v.tag_candidates_inspected = 2; v.observations = []; }],
  ['missing consumed document tags', v => v.tag_candidates_inspected = 3],
  ['short non-capped prefix', v => { v.retained_preview_bytes = 200; v.scan_prefix_bytes = 100; v.scan_prefix_truncated = true; v.complete = false; v.reasons = ['scan_prefix_truncated']; }],
  ['over-short capped prefix', v => { v.retained_preview_bytes = 300000; v.scan_prefix_bytes = 262140; v.scan_prefix_truncated = true; v.complete = false; v.reasons = ['scan_prefix_truncated']; }],
  ['EOF before prefix boundary', v => { v.complete = false; v.head_closed = false; v.reasons = ['end_of_preview']; v.parser_stop = { reason: 'end_of_preview', byte_cursor: 900 }; }],
  ['input-limit before prefix boundary', v => { v.complete = false; v.head_closed = false; v.scan_prefix_truncated = true; v.retained_preview_bytes = 300000; v.scan_prefix_bytes = 262144; v.reasons = ['input_limit', 'scan_prefix_truncated']; v.parser_stop = { reason: 'input_limit', byte_cursor: 262143 }; }],
  ['tags exceed prefix bytes', v => { v.observations = []; v.tag_candidates_inspected = 1025; }],
  ['tags exceed stop cursor', v => { v.complete = false; v.head_closed = false; v.observations = []; v.reasons = ['unsupported_document_context']; v.parser_stop = { reason: 'unsupported_document_context', byte_cursor: 0 }; }],
]) test(`HTML generator rejects impossible bounded coverage: ${name}`, () => {
  const value = htmlGenerators(); mutate(value); assert.throws(() => map.normalizeHtmlGenerators(value, technologySession, technologyToken(), technologyEvidence().row), /Invalid retained HTML-generator response/);
});
for (const bytes of [262141, 262142, 262143, 262144]) test(`HTML generator accepts capped UTF-8 prefix boundary ${bytes}`, () => {
  const value = htmlGenerators({ retained_preview_bytes: 300000, scan_prefix_bytes: bytes, scan_prefix_truncated: true, complete: false, reasons: ['scan_prefix_truncated'] });
  assert.equal(map.normalizeHtmlGenerators(value, technologySession, technologyToken(), technologyEvidence().row).scan_prefix_bytes, bytes);
});
test('HTML generator actual ninth declaration consumes a candidate in addition to explicit document tags', () => {
  const value = htmlGenerators({ observations: Array.from({ length: 8 }, (_, i) => htmlGeneratorObservation('wordpress', '6.8.1', 12 + i * 70)),
    tag_candidates_inspected: 10, additional_observation_encountered: true, complete: false, head_closed: false,
    parser_stop: { reason: 'observation_limit', byte_cursor: 900 }, reasons: ['observation_limit'] });
  assert.throws(() => map.normalizeHtmlGenerators(value, technologySession, technologyToken(), technologyEvidence().row), /Invalid retained HTML-generator response/);
  value.tag_candidates_inspected = 11; assert.equal(map.normalizeHtmlGenerators(value, technologySession, technologyToken(), technologyEvidence().row).observations.length, 8);
});
test('HTML generator unavailable has exactly one acquisition reason', () => {
  const value = missingHtmlGenerators(); value.reasons = ['record_missing', 'session_mismatch'];
  assert.throws(() => map.normalizeHtmlGenerators(value, technologySession, technologyToken(), technologyEvidence().row), /Invalid retained HTML-generator response/);
});

for (const suffix of ['\n', '\r', '\u2028', '\u2029', '\t', ' ']) test(`HTML generator numeric version rejects terminal whitespace ${JSON.stringify(suffix)} even with consistent spans`, () => {
  const value = htmlGenerators(), item = value.observations[0]; item.reported_version += suffix;
  item.version_span.end++; item.content_span.end++; item.tag_span.end++;
  assert.throws(() => map.normalizeHtmlGenerators(value, technologySession, technologyToken(), technologyEvidence().row), /Invalid retained HTML-generator response/);
});
for (const mutate of [parts => parts[5] += '\n', parts => parts[3] += '\n', parts => parts[2] = parts[2].toUpperCase(), parts => parts[1] = parts[1].toUpperCase()]) test('HTML generator evidence token requires canonical lowercase full UUID and numeric segments', () => {
  const parts = technologyToken().split('.'); mutate(parts); const token = parts.join('.'), value = htmlGenerators({ evidence_id: token });
  assert.throws(() => map.normalizeHtmlGenerators(value, technologySession, token, technologyEvidence().row), /Invalid retained HTML-generator response/);
});

// The shared transport boundary applies only to these four local retained-data
// reads. Native-fetch cases below use disposable loopback fixtures, never Sniper.
const passiveReads = [
  { name: 'metadata', path: '/api/target/service-map', start: f => f.controller.refresh(),
    payload: () => withCatalog(technologySnapshot()), result: 'snapshot', loading: 'loading', error: 'error' },
  { name: 'exact evidence', path: '/api/target/service-map/evidence', start: f => f.controller.loadEvidence(technologyToken()),
    payload: () => withCatalog(technologyEvidence()), result: 'evidence', loading: 'evidenceLoading', error: 'evidenceError' },
  { name: 'URL body references', path: '/api/target/service-map/body-references', start: f => f.controller.loadBodyReferences(),
    payload: () => bodyReferences({ session_id: technologySession, evidence_id: technologyToken(), source_sequence: '1' }),
    result: 'bodyReferences', loading: 'bodyReferencesLoading', error: 'bodyReferencesError' },
  { name: 'HTML generators', path: '/api/target/service-map/html-generators', start: f => f.controller.loadHtmlGenerators(),
    payload: () => htmlGenerators(), result: 'htmlGenerators', loading: 'htmlGeneratorsLoading', error: 'htmlGeneratorsError' },
];

function assertPassiveReadRequest(request, read, { fresh = false } = {}) {
  const url = new URL(request.url, originA);
  assert.equal(url.pathname, read.path); assert.equal(request.options.redirect, 'error');
  assert.equal(request.options.method || 'GET', 'GET'); assert.equal(request.options.body, undefined);
  assert.ok(request.options.signal instanceof AbortSignal); assert.equal(request.options.signal.aborted, false);
  const metadata = read.name === 'metadata', evidenceRead = read.name === 'exact evidence';
  assert.deepEqual(Object.fromEntries(url.searchParams), metadata
    ? { session_id: technologySession, in_scope_only: 'false', all_rows: 'true', ...(fresh ? { fresh: 'true' } : {}) }
    : { session_id: technologySession, evidence_id: technologyToken(), ...(evidenceRead ? { include_socket_peer: 'true' } : {}) });
  assert.deepEqual(request.options.headers && { ...request.options.headers }, metadata || evidenceRead
    ? { 'X-Sniper-Technology-Catalog-Version': '2' } : undefined);
}

function assertPassiveReadFailure(f, read, previousSnapshot) {
  assert.equal(f.state[read.loading], false); assert.ok(f.state[read.error]);
  assert.equal(f.state[read.result], read.name === 'metadata' ? previousSnapshot : null);
  assert.doesNotMatch(f.els.status.textContent + f.els.detail.innerHTML,
    /PRIVATE_REDIRECT|PRIVATE_ERROR|redirect-destination|http:\/\/127\.0\.0\.1/);
}

for (const read of passiveReads) {
  test(`${read.name} shares enforced redirect refusal without changing exact request or local search`, async () => {
    const f = await htmlGeneratorFixture(), before = f.requests.length, pending = read.start(f), request = f.requests.at(-1);
    assertPassiveReadRequest(request, read); assert.equal(f.requests.length, before + 1);
    f.els.search.value = 'not-visible.example.com'; f.els.search.dispatch('input');
    assert.equal(f.requests.length, before + 1); assert.equal(request.options.signal.aborted, false);
    request.resolve(response(read.payload())); assert.equal(await pending, true);
    assert.ok(f.state[read.result]); assert.equal(f.state[read.loading], false); assert.equal(f.requests.length, before + 1);
  });

  for (const failure of ['redirect rejection', 'non-success 302']) {
    test(`${read.name} ${failure} uses safe errors and cannot add a fallback read`, async () => {
      const f = await htmlGeneratorFixture(), before = f.requests.length, previous = f.state.snapshot;
      const pending = read.start(f), request = f.requests.at(-1); assertPassiveReadRequest(request, read);
      if (failure === 'redirect rejection') request.reject(new TypeError('PRIVATE_ERROR http://127.0.0.1/redirect-destination?PRIVATE_REDIRECT'));
      else request.resolve({ ok: false, status: 302,
        json() { assert.fail('Never parse redirect JSON'); }, text() { assert.fail('Never read redirect text'); } });
      assert.equal(await pending, false); await new Promise(resolve => setImmediate(resolve));
      assertPassiveReadFailure(f, read, previous); assert.equal(f.requests.length, before + 1);
      assert.equal(f.state.bodyReferenceOverlay, null);
      assert.doesNotMatch(f.requests.map(item => item.url).join(' '), /transactions|replay|scan|capture|redirect-destination/);
    });
  }

  for (const boundary of ['session', 'scope']) {
    test(`${read.name} late redirect rejection remains fenced after ${boundary} replacement`, async () => {
      const f = await htmlGeneratorFixture(), pending = read.start(f), old = f.requests.at(-1);
      if (boundary === 'session') { f.setSession('session-two'); f.controller.reset(); await f.load(snapshot(undefined, 'session-two')); }
      else {
        f.els.scope.dispatch('click');
        f.requests.at(-1).resolve(response(withCatalog(technologySnapshot()))); await new Promise(resolve => setImmediate(resolve));
      }
      assert.equal(old.options.signal.aborted, true);
      const stateBefore = JSON.stringify(f.state), before = f.requests.length;
      old.reject(new TypeError('PRIVATE_ERROR redirect refusal')); assert.equal(await pending, false);
      assert.equal(JSON.stringify(f.state), stateBefore); assert.equal(f.requests.length, before);
    });
  }

  test(`${read.name} refusal ${read.name === 'metadata' ? 'pauses' : 'preserves'} normal polling and permits exactly one explicit next read`, async () => {
    const f = await htmlGeneratorFixture(), before = f.requests.length, pending = read.start(f);
    f.requests.at(-1).reject(new TypeError('PRIVATE_ERROR redirect refusal')); assert.equal(await pending, false);
    const countForPath = () => f.requests.filter(item => new URL(item.url, originA).pathname === read.path).length;
    const failedReads = countForPath(), poll = pollRealTargetMap(f);
    if (read.name === 'metadata') {
      await poll;
      assert.equal(f.requests.length, before + 1);
      assert.equal(f.state.refreshPaused, true);
    } else {
      assert.equal(f.requests.length, before + 2);
      assert.equal(new URL(f.requests.at(-1).url, originA).pathname, '/api/target/service-map');
      assert.equal(f.requests.at(-1).options.redirect, 'error');
      f.requests.at(-1).resolve(response(withCatalog(technologySnapshot()))); await poll;
    }
    assert.equal(countForPath(), failedReads);
    const next = read.name === 'metadata' ? f.controller.refresh({ force: true, retry: true }) : read.start(f);
    const expected = before + (read.name === 'metadata' ? 2 : 3);
    // The explicit metadata retry is a Reload, which asks for a fresh map.
    assert.equal(f.requests.length, expected); assertPassiveReadRequest(f.requests.at(-1), read, { fresh: read.name === 'metadata' });
    f.requests.at(-1).resolve(response(read.payload())); assert.equal(await next, true);
    assert.equal(f.requests.length, expected);
  });
}

test('initial metadata redirect refusal leaves an empty map and an enabled manual Reload', async () => {
  const f = fixture(), pending = f.controller.refresh();
  assert.equal(f.requests[0].options.redirect, 'error'); f.requests[0].reject(new TypeError('PRIVATE_ERROR'));
  assert.equal(await pending, false); assert.equal(f.requests.length, 1); assert.equal(f.state.snapshot, null);
  assert.match(f.els.status.textContent, /Could not load the service map\. Automatic refresh paused\. Use Reload to retry/);
  assert.equal(f.els.refresh.disabled, false); assert.doesNotMatch(f.els.status.textContent, /PRIVATE_ERROR/);
  f.els.refresh.dispatch('click'); assert.equal(f.requests.length, 2);
  f.requests[1].resolve(response(snapshot())); await new Promise(resolve => setImmediate(resolve));
  assert.ok(f.state.snapshot); assert.equal(f.state.error, '');
});

async function syntheticRedirectServer(t, handler) {
  const server = require('node:http').createServer(handler);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  t.after(async () => {
    const closed = new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    server.closeAllConnections(); await closed;
  });
  return `http://127.0.0.1:${server.address().port}`;
}

for (const read of passiveReads) for (const destination of ['same origin', 'other loopback port']) {
  test(`${read.name} native fetch refuses a 302 to ${destination} with one API hit and zero destination hits`, async t => {
    const f = await htmlGeneratorFixture(), before = f.requests.length, previous = f.state.snapshot;
    const apiRequests = []; let destinationHits = 0;
    const destinationHandler = (_request, result) => {
      destinationHits++; result.writeHead(200, { 'Content-Type': 'application/json' }); result.end(JSON.stringify(read.payload()));
    };
    const otherOrigin = destination === 'other loopback port' ? await syntheticRedirectServer(t, destinationHandler) : '';
    const location = `${otherOrigin}/redirect-destination?PRIVATE_REDIRECT`;
    const localOrigin = await syntheticRedirectServer(t, (request, result) => {
      if (new URL(request.url, 'http://127.0.0.1').pathname !== read.path) return destinationHandler(request, result);
      apiRequests.push({ url: request.url, method: request.method, catalog: request.headers['x-sniper-technology-catalog-version'] });
      result.writeHead(302, { Location: location, 'Content-Type': 'text/plain' }); result.end('PRIVATE_REDIRECT');
    });
    const pending = read.start(f), request = f.requests.at(-1);
    // Keep the production relative path/options intact; only the test transport
    // supplies the disposable loopback origin that a browser normally supplies.
    request.resolve(fetch(new URL(request.url, localOrigin), request.options));
    assert.equal(await pending, false); await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(apiRequests, [{ url: request.url, method: 'GET',
      catalog: ['metadata', 'exact evidence'].includes(read.name) ? '2' : undefined }]);
    assert.equal(destinationHits, 0); assert.equal(f.requests.length, before + 1);
    assertPassiveReadFailure(f, read, previous);
  });
}

// Ordinary-map bounded failure markers never interpret or display response bodies.
const boundedMapFailures = [
  [429, 'busy', 'Service map is busy.'],
  [422, 'scope_work_limit', 'Scope matching exceeded the service map work limit. Simplify scope rules or use a smaller CLI --max-records window.'],
  [409, 'session_changed', 'The selected session source changed while the service map was being built.'],
  [409, 'scope_changed', 'Scope rules changed while the service map was being built.'],
  [409, 'history_changed', 'Retained history changed while the service map was being built.'],
  [500, 'build_failed', 'The service map could not be built.'],
];
function boundedMapError(status, marker, headers) {
  return { ok: false, status, headers: headers || { get(name) { assert.equal(name, 'x-sniper-service-map-error'); return marker; } },
    json() { assert.fail('Error JSON must never be read'); }, text() { assert.fail('Error text must never be read'); } };
}
async function rejectMap(f, status = 500, marker = 'build_failed', headers) {
  const task = f.controller.refresh(); f.requests.at(-1).resolve(boundedMapError(status, marker, headers));
  assert.equal(await task, false);
}
// Busy only means another read outlasted the server's wait for it.
const pausingMapFailures = boundedMapFailures.filter(([, marker]) => marker !== 'busy');
test('a busy map read keeps the map and its inspections, and the next poll asks again', async () => {
  const f = await htmlGeneratorFixture(), previous = f.state.snapshot;
  await resolveBodyReferences(f, bodyReferences({ session_id: technologySession, evidence_id: technologyToken(), source_sequence: '1' }));
  assert.equal(f.controller.showBodyReferencesOnMap(), true);
  await resolveHtmlGenerators(f);
  await rejectMap(f, 429, 'busy');
  assert.equal(f.state.snapshot, previous); assert.equal(f.state.refreshPaused, false); assert.equal(f.state.error, '');
  assert.ok(f.state.bodyReferenceOverlay); assert.ok(f.state.htmlGenerators);
  assert.doesNotMatch(f.els.status.textContent, /busy|paused/i);
  const before = f.requests.length; pollRealTargetMap(f); assert.equal(f.requests.length, before + 1);
  f.requests.at(-1).resolve(response(withCatalog(technologySnapshot()))); await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.busyRetries, 0); assert.equal(f.state.refreshPaused, false);
});
test('busy answers in a row pause after five, and Reload starts the count again', async () => {
  const f = fixture(); await f.load();
  for (let i = 0; i < 5; i++) { await rejectMap(f, 429, 'busy'); assert.equal(f.state.refreshPaused, false, `answer ${i + 1}`); }
  await rejectMap(f, 429, 'busy');
  assert.equal(f.state.refreshPaused, true); assert.ok(f.state.error.startsWith('Service map is busy.'));
  const reload = f.controller.refresh({ retry: true }); f.requests.at(-1).resolve(boundedMapError(429, 'busy')); await reload;
  assert.equal(f.state.refreshPaused, false, 'Reload gets its own five');
});
test('an initial busy read keeps loading and the next poll asks again', async () => {
  const f = fixture(); await rejectMap(f, 429, 'busy');
  assert.equal(f.state.snapshot, null); assert.equal(f.state.refreshPaused, false); assert.equal(f.state.error, '');
  await rejectMap(f, 429, 'busy'); assert.equal(f.requests.length, 2);
});
for (const [status, marker, message] of pausingMapFailures) test(`ordinary map ${marker} keeps a stale map and pauses real polling until one manual Reload`, async () => {
  const f = await htmlGeneratorFixture(), previous = f.state.snapshot, verified = f.state.evidence;
  await resolveBodyReferences(f, bodyReferences({ session_id: technologySession, evidence_id: technologyToken(), source_sequence: '1' }));
  assert.equal(f.controller.showBodyReferencesOnMap(), true);
  await resolveHtmlGenerators(f);
  assert.ok(f.state.htmlGenerators);
  await rejectMap(f, status, marker);
  assert.equal(f.state.snapshot, previous); assert.equal(f.state.stale, true); assert.equal(f.state.refreshPaused, true);
  assert.ok(f.state.error.startsWith(message)); assert.match(f.els.status.textContent, /previous snapshot as stale/);
  assert.equal(f.els.refresh.textContent, 'Reload'); assert.equal(f.els.refresh.disabled, false);
  assert.equal(f.state.bodyReferenceOverlay, null); assert.equal(f.state.bodyReferences, null); assert.equal(f.state.htmlGenerators, null);
  assert.equal(f.state.evidence, status === 409 ? null : verified);
  if (status === 409) { assert.equal(f.state.evidenceId, null); assert.equal(f.state.socketPeer, null); }
  const before = f.requests.length;
  for (let i = 0; i < 4; i++) await pollRealTargetMap(f);
  assert.equal(f.requests.length, before);
  // The production button is the only automatic-pause bypass.
  f.els.refresh.dispatch('click'); assert.equal(f.requests.length, before + 1);
  assert.equal(f.requests.at(-1).options.redirect, 'error');
  assert.equal(new URL(f.requests.at(-1).url, originA).pathname, '/api/target/service-map');
  f.requests.at(-1).resolve(response(withCatalog(technologySnapshot()))); await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.refreshPaused, false); assert.equal(f.state.stale, false); assert.equal(f.state.error, '');
  assert.equal(f.requests.length, before + 1);
});
for (const [name, status, marker, headers] of [
  ['missing header', 429, null], ['unknown marker', 429, 'PRIVATE_ERROR'], ['empty marker', 429, ''],
  ['comma separated', 429, 'busy, scope_changed'], ['duplicate marker', 429, 'busy, busy'],
  ['status mismatch', 500, 'busy'], ['wrong case', 429, 'Busy'], ['trailing whitespace', 429, 'busy '],
  ['leading whitespace', 429, ' busy'], ['no Headers object', 429, undefined, {}],
]) test(`ordinary map ${name} uses fixed generic text without reading the body`, async () => {
  const f = fixture(); await f.load(); await rejectMap(f, status, marker, headers);
  assert.equal(f.state.error, 'Reload failed.');
  assert.match(f.els.status.textContent, /^Reload failed\. Automatic refresh paused\. Showing the previous snapshot as stale; use Reload to retry\./);
  const before = f.requests.length; await pollRealTargetMap(f); assert.equal(f.requests.length, before);
  assert.doesNotMatch(f.els.status.textContent, /PRIVATE_ERROR|scope_changed/);
});
test('native Headers joins duplicated markers and cannot satisfy the single-token contract', async () => {
  const headers = new Headers(); headers.append('x-sniper-service-map-error', 'busy'); headers.append('x-sniper-service-map-error', 'busy');
  const f = fixture(); await f.load(); await rejectMap(f, 429, null, headers);
  assert.match(f.state.error, /^Reload failed\./);
});
for (const [status, marker, message] of pausingMapFailures) test(`initial ${marker} failure is explicit, empty, paused and manually retryable`, async () => {
  const f = fixture(); await rejectMap(f, status, marker);
  assert.equal(f.state.snapshot, null); assert.equal(f.state.refreshPaused, true);
  assert.equal(f.els.status.textContent, `${message} Automatic refresh paused. Use Reload to retry.`);
  assert.equal(f.els.refresh.disabled, false); await f.controller.refresh(); assert.equal(f.requests.length, 1);
});
test('paused map local origin/product/version/method/path filters add zero reads and preserve exact selection', async () => {
  const f = await htmlGeneratorFixture(); f.controller.selectOrigin(originA, 0);
  await resolveTechnologySource(f, withCatalog(technologyEvidence()));
  await rejectMap(f); const before = f.requests.length, source = f.state.evidence, selection = f.state.endpointSelection;
  f.els.search.value = 'not-loaded'; f.els.search.dispatch('input');
  f.controller.setProductFilter('product', 'nginx'); f.controller.setProductFilter('version', 'reported:99.0');
  f.els.panel.dispatch('change', { target: { dataset: { serviceEndpointFilter: 'method' }, value: 'POST' } });
  f.els.panel.dispatch('input', { target: { dataset: { serviceEndpointFilter: 'path' }, value: '/absent' } });
  assert.equal(f.state.evidence, source); assert.equal(f.state.endpointSelection, selection); assert.equal(f.state.refreshPaused, true);
  await pollRealTargetMap(f); assert.equal(f.requests.length, before);
});
for (const boundary of ['visibility', 'apis', 'force-only navigation', 'unchanged scope', 'history dirty', 'history invalidation', 'disconnect/reconnect']) test(`paused map does not retry after ${boundary}`, async () => {
  const f = fixture(); await f.load(); await rejectMap(f); const before = f.requests.length;
  if (boundary === 'visibility') { f.controller.setVisible(false); f.controller.setVisible(true); }
  if (boundary === 'apis') { f.controller.setVisible(true, 'apis'); f.controller.setVisible(true); }
  if (boundary === 'force-only navigation') await f.controller.refresh({ force: true });
  if (boundary === 'unchanged scope') assert.equal(f.controller.scopeChanged({ scope_patterns: ['example.com'] }, { scope_patterns: ['example.com'] }), false);
  if (boundary === 'history dirty') f.controller.markDirty();
  if (boundary === 'history invalidation') await f.controller.invalidate();
  if (boundary === 'disconnect/reconnect') { f.controller.disconnect(); await f.controller.invalidate(); }
  await pollRealTargetMap(f); assert.equal(f.requests.length, before); assert.equal(f.state.refreshPaused, true);
  assert.equal(f.els.refresh.disabled, false);
  if (boundary === 'history invalidation' || boundary === 'disconnect/reconnect') {
    assert.equal(f.state.snapshot, null);
    assert.doesNotMatch(f.els.status.textContent, /Showing the previous snapshot|rows considered/);
    assert.match(f.els.status.textContent, /Automatic refresh paused\. Use Reload to retry\./);
  }
});
for (const boundary of ['scope rules', 'scope toggle', 'session reset', 'session detection']) test(`actual ${boundary} clears pause and permits one normal map read`, async () => {
  const f = fixture(); await f.load(); await rejectMap(f); const before = f.requests.length;
  let task, session = 'session-one';
  if (boundary === 'scope rules') task = f.controller.scopeChanged({ scope_patterns: [] }, { scope_patterns: ['example.com'] });
  if (boundary === 'scope toggle') { f.els.scope.dispatch('click'); }
  if (boundary.startsWith('session')) {
    session = 'session-two'; f.setSession(session);
    if (boundary === 'session reset') f.controller.reset();
    task = f.controller.refresh();
  }
  assert.equal(f.requests.length, before + 1); assert.equal(f.state.refreshPaused, false);
  f.requests.at(-1).resolve(response(snapshot(undefined, session))); await task; await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state.error, ''); assert.equal(f.state.sessionId, session);
});
for (const boundary of ['force replacement', 'scope toggle', 'scope rules', 'session', 'session ABA']) test(`late bounded error after ${boundary} cannot pause or invalidate the replacement`, async () => {
  const f = fixture(); await f.load(); const oldTask = f.controller.refresh(), old = f.requests.at(-1);
  let task, session = 'session-one';
  if (boundary === 'force replacement') task = f.controller.refresh({ force: true });
  if (boundary === 'scope toggle') { f.els.scope.dispatch('click'); }
  if (boundary === 'scope rules') task = f.controller.scopeChanged({ scope_patterns: [] }, { scope_patterns: ['example.com'] });
  if (boundary.startsWith('session')) {
    session = 'session-two'; f.setSession(session); f.controller.reset();
    if (boundary === 'session ABA') { session = 'session-one'; f.setSession(session); f.controller.reset(); }
    task = f.controller.refresh();
  }
  f.requests.at(-1).resolve(response(snapshot(undefined, session))); await task; await new Promise(resolve => setImmediate(resolve));
  const before = JSON.stringify(f.state); old.resolve(boundedMapError(409, 'history_changed'));
  assert.equal(await oldTask, false); assert.equal(JSON.stringify(f.state), before); assert.equal(f.state.refreshPaused, false);
});
for (const marker of ['session_changed', 'scope_changed', 'history_changed']) test(`${marker} fences a late exact-evidence success`, async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(originA);
  const evidenceTask = f.controller.loadEvidence('evidence-one'), old = f.requests.at(-1);
  await rejectMap(f, 409, marker); assert.equal(old.options.signal.aborted, true);
  old.resolve(response(evidence())); assert.equal(await evidenceTask, false);
  assert.equal(f.state.evidence, null); assert.equal(f.state.evidenceId, null); assert.equal(f.state.refreshPaused, true);
});
test('a failed explicit retry pauses again without automatic fallback', async () => {
  const f = fixture(); await f.load(); await rejectMap(f);
  const before = f.requests.length; f.els.refresh.dispatch('click');
  f.requests.at(-1).resolve(boundedMapError(500, 'build_failed')); await new Promise(resolve => setImmediate(resolve));
  await pollRealTargetMap(f); await f.controller.refresh({ force: true });
  assert.equal(f.requests.length, before + 1); assert.equal(f.state.refreshPaused, true);
});

const apiDocument = {
  openapi: '3.1.0', info: { title: originB, version: 'observed', description: 'Observed by Sniper in 3 captured requests to it.' }, servers: [{ url: originB }],
  paths: {
    '/v1/items': { post: { requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string' } } } } } }, responses: { default: { description: 'No response was captured' } }, 'x-sniper-requests': 1, 'x-sniper-newest-transaction': '<b>' } },
    '/v1/items/{number}': { parameters: [{ name: 'number', in: 'path', required: true, schema: { type: 'integer' } }],
      get: { parameters: [{ name: '<q>', in: 'query', schema: { type: 'string' } }], responses: { 200: { description: 'OK', content: { 'application/json': {} } } }, security: [{ bearer_jwt: [] }], 'x-sniper-requests': 2, 'x-sniper-newest-transaction': '22222222-2222-4222-8222-222222222222' } },
  },
  components: { securitySchemes: { bearer_jwt: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } } },
};
const newerRow = '22222222-2222-4222-8222-222222222222';
function apiDocsFixture() {
  const copies = [], replays = [];
  const f = fixture({ copyText(text, label) { copies.push({ text, label }); }, sendToReplay(id) { replays.push(id); } });
  return { f, copies, replays };
}
const items = () => origin(originB, [endpoint('/v1/items/12'), endpoint('/v1/items', 'POST', 'evidence-post')]);
test('API docs read the selected origin and lay out its OpenAPI document, escaped', async () => {
  const { f, copies, replays } = apiDocsFixture();
  await f.load(snapshot([origin(originA), items()])); f.controller.selectOrigin(originB);
  assert.match(f.els.detail.innerHTML, /data-service-api-docs="https:\/\/api\.example\.com"[^>]*>API docs</);
  assert.equal(f.els.apiDocs.classList.contains('hidden'), true, 'closed until asked for');
  f.els.panel.dispatch('click', { target: { closest: () => ({ dataset: { serviceApiDocs: originB } }) } });
  assert.equal(f.els.apiDocs.classList.contains('hidden'), false);
  assert.match(f.els.apiDocs.innerHTML, /Reading retained rows/);
  const read = f.requests.at(-1);
  assert.equal(read.url, '/api/target/service-map/openapi?session_id=session-one&origin=https%3A%2F%2Fapi.example.com');
  assert.equal(read.options.redirect, 'error');
  read.resolve(response(apiDocument)); await new Promise(resolve => setImmediate(resolve));
  const html = f.els.apiDocs.innerHTML;
  assert.match(html, /<h2 id="serviceMapApiDocsTitle"[^>]*>https:\/\/api\.example\.com<\/h2>/);
  assert.match(html, /Observed by Sniper in 3 captured requests/);
  assert.match(html, /<code>bearer_jwt<\/code><\/td><td>HTTP bearer \(JWT\)/);
  assert.match(html, /Operations · 2/);
  assert.match(html, /class="service-map-method post">POST<\/span><code title="\/v1\/items">\/v1\/items<\/code>[^]*?1 row</);
  assert.match(html, /<code>name<\/code><\/td><td>string/);
  assert.match(html, /class="service-map-method get">GET<\/span><code title="\/v1\/items\/\{number\}">/);
  assert.match(html, /<code>number<\/code> <span class="service-map-muted">required<\/span><\/td><td>path<\/td><td>integer/);
  assert.match(html, /<code>&lt;q&gt;<\/code><\/td><td>query/, 'escaped');
  assert.doesNotMatch(html, /<q>/);
  assert.match(html, /<td>200<\/td><td>OK<\/td><td><code>application\/json<\/code>/);
  assert.match(html, /Credentials sent<\/h5><p><code>bearer_jwt<\/code>/);
  assert.equal((html.match(/data-api-docs-replay=/g) || []).length, 1, 'only a transaction ID is sent on');
  assert.match(html, new RegExp(`data-api-docs-replay="${newerRow}"`), 'the newest row of the template');
  f.els.apiDocs.dispatch('click', { target: { closest: () => ({ dataset: { apiDocsCopy: '' } }) } });
  assert.deepEqual(copies, [{ text: JSON.stringify(apiDocument, null, 2), label: 'Copied OpenAPI' }]);
  f.els.apiDocs.dispatch('click', { target: { closest: () => ({ dataset: { apiDocsReplay: newerRow } }) } });
  assert.deepEqual(replays, [newerRow]);
  assert.equal(f.els.apiDocs.classList.contains('hidden'), true, 'Replay takes over from the docs');
});
test('API docs close on Escape and name an inactive session, and only API origins offer them', async () => {
  const { f } = apiDocsFixture();
  await f.load(snapshot([items()])); f.controller.selectOrigin(originB);
  f.els.panel.dispatch('click', { target: { closest: () => ({ dataset: { serviceApiDocs: originB } }) } });
  f.requests.at(-1).resolve(response({}, 409)); await new Promise(resolve => setImmediate(resolve));
  assert.match(f.els.apiDocs.innerHTML, /API docs are read from the active session only\./);
  assert.match(f.els.apiDocs.innerHTML, /data-api-docs-copy disabled/);
  f.els.apiDocs.dispatch('keydown', { key: 'Escape' });
  assert.equal(f.els.apiDocs.classList.contains('hidden'), true);
  assert.equal(f.els.apiDocs.innerHTML, '');
  const page = origin('https://www.example.com', [{ method: 'GET', path: '/', request_count: 1, statuses: [200], content_types: ['text/html'], evidence: ['page-one'] }]);
  await f.load(snapshot([page])); f.controller.selectOrigin('https://www.example.com');
  assert.match(f.els.detail.innerHTML, /Hide from map/);
  assert.doesNotMatch(f.els.detail.innerHTML, /data-service-api-docs/);
});
