// Synthetic retained snapshots and inert DOM only. No app bootstrap or network.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../web/service-map.js'), 'utf8');
const context = vm.createContext({ URL, URLSearchParams, AbortController, console });
vm.runInContext(source, context);
const A = 'https://app.example.com', B = 'https://api.example.com';
const record = '11111111-1111-4111-8111-111111111111';
const endpoint = (value, method = 'GET') => ({ method, path: value, request_count: 1, statuses: [200], content_types: ['application/json'], evidence: [method + value] });
const many = () => Array.from({ length: 130 }, (_, index) => endpoint(`/path-${index}`));
const origin = (id, endpoints = many()) => ({ origin: id, in_scope: true, request_count: endpoints.length, endpoints, technology_clues: [], redirects: [], header_links: [] });
const snapshot = (origins = [origin(A)], extra = {}) => ({ schema_version: 1, session_id: 'synthetic-session', snapshot: { generation: 'synthetic-generation', complete: true, considered_rows: 130, retained_rows: 130, included_rows: 130, excluded_rows: 0, omitted_rows: 0, stopped_by: [], ...extra }, origins });
const response = (value) => ({ ok: true, json: async () => value });
function node() {
  const handlers = new Map(), classes = new Set();
  let html = '';
  return { value: '', dataset: {}, attributes: {}, style: { setProperty() {} }, scrollTop: 0, scrollLeft: 0, clientWidth: 800, clientHeight: 600,
    classList: { toggle(name, on) { on ? classes.add(name) : classes.delete(name); }, contains: name => classes.has(name) },
    addEventListener(name, callback) { handlers.set(name, callback); },
    dispatch(name, event = {}) { return handlers.get(name)?.({ target: this, ...event }); },
    setAttribute(name, value) { this.attributes[name] = value; }, contains: () => true, querySelectorAll: () => [],
    get innerHTML() { return html; }, set innerHTML(value) { html = value; },
  };
}
function fixture() {
  const els = Object.fromEntries(['panel', 'status', 'refresh', 'search', 'scope', 'canvas', 'graphBounds', 'detail', 'content', 'catalog', 'viewport'].map(name => [name, node()]));
  const requests = [], document = { activeElement: null, body: {}, querySelector: () => null };
  // Opening an endpoint reads its parameters; these tests are about the other
  // reads, so that one is kept apart and left pending.
  const controller = context.SniperServiceMap.createController({ elements: els, document, getSessionId: () => 'synthetic-session', request(url, options) {
    let resolve; const promise = new Promise(done => { resolve = done; });
    if (!url.startsWith('/api/target/service-map/parameters?')) requests.push({ url, options, resolve });
    return promise;
  } });
  controller.setVisible(true);
  const state = controller.getState();
  function click(dataset) { const target = { dataset, closest: () => target }; els.panel.dispatch('click', { target }); }
  function filter(kind, value) { els.panel.dispatch(kind === 'method' ? 'change' : 'input', { target: { value, dataset: { serviceEndpointFilter: kind } } }); }
  function search(value) { els.search.value = value; els.search.dispatch('input'); }
  async function load(value = snapshot()) { const pending = controller.refresh(); requests.at(-1).resolve(response(value)); await pending; }
  async function verify(ep) {
    const id = ep.evidence[0], pending = controller.loadEvidence(id);
    requests.at(-1).resolve(response({ schema_version: 1, session_id: 'synthetic-session', evidence_id: id, available: true, source: 'captured_http_metadata', row: { evidence_id: id, origin: state.selectedOrigin, method: ep.method, path: ep.path, sequence: '9007199254740993', record_id: record, metadata_complete: true, omitted: [] } }));
    await pending;
  }
  return { controller, state, requests, els, document, click, filter, search, load, verify };
}
const rows = element => [...element.innerHTML.matchAll(/data-service-endpoint="(\d+)"/g)].map(match => Number(match[1]));
const tab = (f, value) => f.click({ serviceDetailTab: value });

test('page 3 endpoint evidence/APIs roundtrip keeps exact endpoint and page without a read', async () => {
  const f = fixture(); await f.load(); f.click({ serviceDetailPage: '2' });
  f.click({ serviceOrigin: A, serviceEndpoint: '110' });
  assert.equal(f.state.detailTab, 'evidence'); assert.equal(f.state.detailPage, 2);
  await f.verify(many()[110]); const verified = f.state.evidence;
  for (let index = 0; index < 3; index++) {
    tab(f, 'apis'); assert.equal(f.state.endpointSelection.path, '/path-110');
    assert.equal(f.state.detailPage, 2); assert.deepEqual(rows(f.els.detail), Array.from({ length: 30 }, (_, i) => 100 + i));
    assert.match(f.els.detail.innerHTML, /service-map-api-row selected[^]*?data-service-endpoint="110"/);
    tab(f, 'evidence'); assert.equal(f.state.evidence, verified);
  }
  assert.equal(f.requests.length, 2);
});

test('paths that differ only in an ID share one row, opened to list them', async () => {
  const ids = [
    { ...endpoint('/web/chats/481708212407212/posts'), path_group: '/web/chats/{number}/posts', request_count: 5 },
    { ...endpoint('/web/chats/445871621677916/posts'), path_group: '/web/chats/{number}/posts', request_count: 1 },
    { ...endpoint('/web/chats/481708212407212/posts/6ac5f9f2e9cba87a1381140d'), path_group: '/web/chats/{number}/posts/{hex}', request_count: 2 },
    endpoint('/health'),
  ];
  const f = fixture(); await f.load(snapshot([origin(A, ids)]));
  f.controller.selectOrigin(A);
  const html = f.els.detail.innerHTML;
  assert.match(html, /data-service-endpoint-group="[^"]+"[^>]*>[^]*?\/web\/chats\/<span class="service-map-path-id">\{number\}<\/span>\/posts<\/span><small>2 paths<\/small>[^]*?>6</, 'one row, its rows summed');
  assert.deepEqual(rows(f.els.detail), [2, 3], 'closed, and a template seen once keeps its own path');
  assert.match(html, /1–3 \/ 3 matching \(4 paths\) · 4 loaded · 0 hidden by endpoint filters/);
  const key = JSON.stringify([A, 'GET', '/web/chats/{number}/posts']);
  f.click({ serviceEndpointGroup: key });
  assert.deepEqual(rows(f.els.detail), [0, 1, 2, 3], 'open, it lists its paths');
  f.click({ serviceEndpointGroup: key });
  assert.deepEqual(rows(f.els.detail), [2, 3]);
  f.controller.selectOrigin(A, 1); tab(f, 'apis');
  assert.deepEqual(rows(f.els.detail), [0, 1, 2, 3], 'the selected path keeps its group open');
});

test('keyboard API/Evidence tabs keep selected identity and page', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(A, 110);
  const target = { closest: () => ({ dataset: { serviceDetailTab: 'evidence' } }) };
  for (const key of ['Home', 'End', 'ArrowLeft', 'ArrowRight']) {
    let prevented = false;
    f.els.panel.dispatch('keydown', { target, key, preventDefault() { prevented = true; } });
    assert.equal(prevented, true); assert.equal(f.state.detailPage, 2); assert.equal(f.state.endpointSelection.path, '/path-110');
  }
  assert.equal(f.requests.length, 1);
});

test('catalog page and inspector page survive roundtrip independently', async () => {
  const f = fixture(); await f.load(snapshot([origin(B), origin(A)]));
  f.controller.setVisible(true, 'apis'); f.click({ servicePage: '4' });
  f.click({ serviceOrigin: A, serviceEndpoint: '110' });
  assert.equal(f.state.page, 4); assert.equal(f.state.detailPage, 2); assert.equal(f.state.view, 'service-map');
  tab(f, 'apis'); f.controller.setVisible(true, 'apis');
  assert.equal(f.state.page, 4); assert.equal(f.state.detailPage, 2); assert.ok(rows(f.els.catalog).includes(110));
  assert.equal(f.requests.length, 1);
});

test('refresh remaps selected endpoint page by exact case-sensitive method/path', async () => {
  const f = fixture(), old = many(); old[110] = endpoint('/Selected', 'get');
  await f.load(snapshot([origin(A, old)])); f.controller.selectOrigin(A, 110); tab(f, 'apis');
  const reordered = [endpoint('/Selected', 'GET'), old[110], ...old.filter((_, index) => index !== 110)];
  await f.load(snapshot([origin(A, reordered)]));
  assert.equal(f.state.endpointIndex, 1); assert.equal(f.state.detailPage, 0); assert.equal(f.state.endpointSelection.method, 'get');
  tab(f, 'evidence'); assert.match(f.els.detail.innerHTML, /<span>get <strong>\/Selected/);
});

test('refresh remaps independent page anchors without selecting their old array offsets', async () => {
  const f = fixture(), old = many(); await f.load(snapshot([origin(A, old)]));
  f.click({ serviceDetailPage: '2' }); f.click({ servicePage: '1' });
  const reversed = [...old].reverse(); await f.load(snapshot([origin(A, reversed)]));
  assert.equal(f.state.detailPage, 0); assert.equal(f.state.page, 1);
  assert.equal(f.state.detailPageAnchor.path, '/path-100'); assert.equal(f.state.pageAnchor.path, '/path-50');
  assert.equal(f.state.endpointSelection, null);
});

test('missing page anchor clamps safely and does not choose a replacement endpoint', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(A, 110); tab(f, 'apis');
  await f.load(snapshot([origin(A, [endpoint('/replacement')])]));
  assert.equal(f.state.detailPage, 0); assert.equal(f.state.endpointIndex, null); assert.equal(f.state.endpointSelection, null);
  assert.match(f.els.detail.innerHTML, /\/replacement/);
});

test('exact method filter distinguishes GET, get, unknown methods and literal asterisks', async () => {
  const f = fixture(), methods = ['GET', 'get', 'G*', 'CUSTOM-METHOD-' + 'X'.repeat(180)];
  await f.load(snapshot([origin(A, methods.map(method => endpoint('/same', method)))]));
  for (const [index, method] of methods.entries()) {
    f.filter('method', method); assert.deepEqual(rows(f.els.detail), [index]); assert.deepEqual(rows(f.els.catalog), [index]);
    assert.equal(f.state.endpointMethod, method); assert.match(f.els.detail.innerHTML, /Method \(exact\)/);
  }
  f.filter('method', 'G'); assert.deepEqual(rows(f.els.detail), []); assert.equal(f.requests.length, 1);
});

test('path filter is literal case-sensitive substring including whitespace and regexp symbols', async () => {
  const f = fixture(), endpoints = ['/users/A', '/Users/A', '/users/[x]', '/a b', '/public?hidden-token#fragment'].map(value => endpoint(value));
  await f.load(snapshot([origin(A, endpoints)]));
  for (const [query, expected] of [['users/', [0, 2]], ['Users/', [1]], ['[x]', [2]], [' b', [3]], ['.*', []], ['hidden-token', []], ['fragment', []], ['/public', [4]]]) {
    f.filter('path', query); assert.deepEqual(rows(f.els.detail), expected); assert.deepEqual(rows(f.els.catalog), expected);
  }
  assert.equal(f.requests.length, 1);
});

test('combined local filters preserve original endpoint indexes and selected method/path', async () => {
  const f = fixture(); await f.load(snapshot([origin(A, [endpoint('/same'), endpoint('/other', 'POST'), endpoint('/same', 'POST')])]));
  f.filter('method', 'POST'); f.filter('path', '/same'); assert.deepEqual(rows(f.els.detail), [2]);
  f.click({ serviceEndpoint: '2', serviceOrigin: A });
  assert.equal(f.state.endpointIndex, 2); assert.equal(f.state.endpointSelection.method, 'POST'); assert.equal(f.state.endpointSelection.path, '/same');
  assert.equal(f.requests.length, 1);
});

test('filters reset both pages but preserve verified evidence and graph state outside filters', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(A, 110); await f.verify(many()[110]);
  f.click({ servicePage: '2' }); f.controller.setZoom(1.5);
  const verified = f.state.evidence, graph = f.els.canvas.innerHTML, zoom = f.state.zoomScale;
  f.filter('method', 'POST'); f.filter('path', '/nothing');
  assert.equal(f.state.page, 0); assert.equal(f.state.detailPage, 0); assert.equal(f.state.evidence, verified);
  assert.equal(f.state.endpointSelection.path, '/path-110'); assert.equal(f.els.canvas.innerHTML, graph); assert.equal(f.state.zoomScale, zoom);
  assert.match(f.els.detail.innerHTML, /outside the loaded endpoint filters/); assert.match(f.els.detail.innerHTML, /Capture info/);
  tab(f, 'apis'); assert.match(f.els.detail.innerHTML, /No loaded endpoints match/);
  f.click({ serviceEndpointFilterClear: 'true' }); assert.equal(f.state.endpointMethod, ''); assert.equal(f.state.endpointPath, '');
  assert.equal(f.state.evidence, verified); assert.doesNotMatch(f.els.detail.innerHTML, /outside the loaded endpoint filters/);
  assert.equal(f.requests.length, 2);
});

test('filters and tab switches do not abort an in-flight exact source read', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(A, 110);
  const pending = f.verify(many()[110]); f.filter('path', '/no-match'); tab(f, 'apis');
  assert.equal(f.requests.at(-1).options.signal.aborted, false); await pending;
  assert.equal(f.state.evidence.path, '/path-110'); assert.equal(f.state.detailTab, 'apis');
  tab(f, 'evidence'); assert.match(f.els.detail.innerHTML, /Capture info/); assert.equal(f.requests.length, 2);
});

test('origin search remains independent and local counts disclose each filter separately', async () => {
  const f = fixture(); await f.load(snapshot([origin(A, [endpoint('/keep'), endpoint('/hide')]), origin(B, [endpoint('/keep')])]));
  f.controller.selectOrigin(A, 0); f.search('api.example.com'); f.filter('path', '/keep');
  assert.equal(f.state.query, 'api.example.com'); assert.equal(f.state.endpointSelection.path, '/keep');
  assert.match(f.els.catalog.innerHTML, /1 matching · 3 loaded · 0 hidden by endpoint filters · 2 hidden by origin search/);
  assert.match(f.els.detail.innerHTML, /Selected origin is outside the origin search/);
  tab(f, 'apis'); assert.match(f.els.detail.innerHTML, /1 matching · 2 loaded · 1 hidden by endpoint filters/);
  f.search('/keep'); assert.deepEqual(rows(f.els.catalog), []); assert.deepEqual(rows(f.els.detail), [0]);
  assert.equal(f.state.endpointPath, '/keep'); assert.equal(f.requests.length, 1);
});

test('loaded-filter zero results never imply server omissions or exhaustive inventory', async () => {
  const f = fixture(); await f.load(snapshot([origin(A)], { complete: false, stopped_by: ['max_records', 'endpoint_limit'], retained_rows: 20000, considered_rows: 10000, omitted_rows: 900 }));
  const status = f.els.status.textContent; f.filter('path', '/absent');
  assert.match(f.els.detail.innerHTML, /0–0 \/ 0 matching · 130 loaded · 130 hidden by endpoint filters/);
  assert.equal(f.els.status.textContent, status); assert.match(status, /900 omitted/); assert.equal(f.requests.length, 1);
});

test('disappearing selected method stays selected as explicit empty filter after refresh', async () => {
  const f = fixture(); await f.load(snapshot([origin(A, [endpoint('/custom', 'get')])])); f.filter('method', 'get');
  await f.load(snapshot([origin(A, [endpoint('/custom', 'GET')])]));
  assert.equal(f.state.endpointMethod, 'get'); assert.match(f.els.detail.innerHTML, /<option value="get" selected>get/);
  assert.match(f.els.detail.innerHTML, /Selected method is absent from the loaded snapshot/); assert.deepEqual(rows(f.els.detail), []);
  await f.load(snapshot([origin(A, [endpoint('/custom', 'get')])]));
  assert.deepEqual(rows(f.els.detail), [0]); assert.doesNotMatch(f.els.detail.innerHTML, /Selected method is absent/);
});

test('filter state and exact pagination survive history invalidation while stale evidence is cleared', async () => {
  const f = fixture(); await f.load(); f.filter('path', '/path-'); f.controller.selectOrigin(A, 110); await f.verify(many()[110]);
  const pending = f.controller.invalidate(); assert.equal(f.state.evidence, null); assert.equal(f.state.endpointPath, '/path-');
  const endpoints = many().reverse(); f.requests.at(-1).resolve(response(snapshot([origin(A, endpoints)]))); await pending;
  assert.equal(f.state.endpointIndex, 19); assert.equal(f.state.detailPage, 0); assert.equal(f.state.endpointSelection.path, '/path-110');
  assert.equal(f.state.evidence, null); assert.equal(f.requests.length, 3);
});

test('session reset clears local endpoint filters, page anchors and exact selection', async () => {
  const f = fixture(); await f.load(); f.filter('method', 'GET'); f.filter('path', '/path-'); f.controller.selectOrigin(A, 110);
  f.controller.reset();
  for (const name of ['endpointMethod', 'endpointPath']) assert.equal(f.state[name], '');
  for (const name of ['pageAnchor', 'detailPageAnchor', 'endpointSelection']) assert.equal(f.state[name], null);
  assert.equal(f.requests.length, 1);
});

test('captured method and path filter markup stays escaped', async () => {
  const f = fixture(); await f.load(snapshot([origin(A, [endpoint('/<img>', '<script>')])]));
  f.filter('method', '<script>'); f.filter('path', '" onfocus="bad');
  const html = f.els.detail.innerHTML + f.els.catalog.innerHTML;
  assert.doesNotMatch(html, /<script>|<img>|value="" onfocus=/); assert.match(html, /&lt;script&gt;/); assert.match(html, /&quot; onfocus=&quot;bad/);
});

test('path filter rerenders restore the owned input caret without stealing another control focus', async () => {
  const f = fixture(); await f.load();
  const old = { dataset: { serviceFocus: 'serviceMapDetail:path', serviceEndpointFilter: 'path' }, selectionStart: 2, selectionEnd: 4, selectionDirection: 'backward', isConnected: false };
  const restored = { dataset: old.dataset, getClientRects: () => [1], focus() { f.document.activeElement = this; }, setSelectionRange(...value) { this.caret = value; } };
  f.els.detail.querySelectorAll = () => [restored]; f.document.activeElement = old;
  f.els.catalog.contains = () => false;
  f.filter('path', '/path'); assert.equal(f.document.activeElement, restored); assert.deepEqual(restored.caret, [2, 4, 'backward']);
  const unrelated = {}; f.document.activeElement = unrelated; f.filter('path', '/other'); assert.equal(f.document.activeElement, unrelated);
});

test('filter controls are contained in API lists and bounded at narrow widths, without Scope strip changes', () => {
  const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
  const toolbar = html.slice(html.indexOf('<div class="service-map-toolbar">'), html.indexOf('<div class="service-map-status"'));
  assert.doesNotMatch(toolbar, /endpoint-filter|Path contains|Method \(exact\)/);
  assert.match(css, /\.service-map-endpoint-filters \{ min-inline-size: 0/);
  assert.match(css, /grid-template-columns: minmax\(0, 1fr\) minmax\(0, 1.4fr\) auto/);
  assert.match(css, /service-map-endpoint-filter-controls select \{ width: 100%; min-width: 0; max-width: 100%/);
});

for (const transition of ['ordinary refresh', 'history invalidation']) test(`missing page anchor preserves the same fallback page after ${transition}`, async () => {
  const f = fixture(); await f.load();
  f.click({ serviceDetailPage: '2' }); f.click({ servicePage: '2' });
  assert.equal(f.state.pageAnchor.path, '/path-100'); assert.equal(f.state.detailPageAnchor.path, '/path-100');
  const updated = many(); updated[100] = endpoint('/replacement');
  if (transition === 'history invalidation') {
    const pending = f.controller.invalidate();
    assert.equal(f.state.snapshot, null); assert.equal(f.state.page, 2); assert.equal(f.state.detailPage, 2);
    assert.match(f.els.catalog.innerHTML, /data-service-page="1" disabled/);
    f.requests.at(-1).resolve(response(snapshot([origin(A, updated)]))); await pending;
  } else await f.load(snapshot([origin(A, updated)]));
  assert.equal(f.state.page, 2); assert.equal(f.state.detailPage, 2);
  assert.equal(f.state.pageAnchor.path, '/replacement'); assert.equal(f.state.detailPageAnchor.path, '/replacement');
  assert.deepEqual(rows(f.els.catalog), Array.from({ length: 30 }, (_, i) => 100 + i));
  assert.deepEqual(rows(f.els.detail), Array.from({ length: 30 }, (_, i) => 100 + i));
  assert.equal(f.state.endpointSelection, null);
});

test('a truly empty fresh result clamps both pages after transient invalidation', async () => {
  const f = fixture(); await f.load(); f.click({ serviceDetailPage: '2' }); f.click({ servicePage: '2' });
  const pending = f.controller.invalidate(); assert.equal(f.state.page, 2); assert.equal(f.state.detailPage, 2);
  f.requests.at(-1).resolve(response(snapshot([origin(A, [])]))); await pending;
  assert.equal(f.state.page, 0); assert.equal(f.state.detailPage, 0);
  assert.equal(f.state.pageAnchor, null); assert.equal(f.state.detailPageAnchor, null);
  assert.deepEqual(rows(f.els.catalog), []); assert.deepEqual(rows(f.els.detail), []);
  assert.match(f.els.catalog.innerHTML, /0–0 \/ 0 matching · 0 loaded/);
});
