// The map draws at most MAX_CARDS cards and an arrow only between two shown
// cards. Picked by name, related origins fell on either side of the cap, and a
// real session with 67 relationships among 86 origins drew no arrow at all.
// Cards are laid out by link depth, so links run between columns, not inside one.
// Trackpad pinch zooms the graph around the fingers. An Origin/Referer link is
// drawn for the kinds of request behind it, so image loads can stay hidden.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '../web/service-map.js'), 'utf8');
const context = vm.createContext({ URL, URLSearchParams, AbortController, console, getComputedStyle: element => ({ getPropertyValue: name => element.style.values[name] || '' }), ResizeObserver: class { observe() {} } });
vm.runInContext(source, context);
const map = context.SniperServiceMap;

function deferred() { let resolve; const promise = new Promise(yes => { resolve = yes; }); return { promise, resolve }; }
function response(payload) { return { ok: true, status: 200, json: async () => payload }; }
function origin(id, extra = {}) {
  return { origin: id, in_scope: true, request_count: 1, endpoints: [{ method: 'GET', path: '/', request_count: 1, statuses: [200], content_types: ['text/html'], evidence: [`evidence-${id}`] }], technology_clues: [], redirects: [], header_links: [], ...extra };
}
const referer = (sourceOrigin) => ({ source: 'request_header_declaration', source_origin: sourceOrigin, relationship: 'referer_header', evidence: ['evidence-header'] });
const redirect = (target) => ({ target_origin: target, target_path: '/', relationship: 'redirect_instruction', evidence: ['evidence-redirect'] });
function snapshot(origins) {
  return { schema_version: 1, session_id: 'session-one', snapshot: { generation: 'generation-one', complete: true, stopped_by: [], limits: { records: 10000 }, considered_rows: origins.length, retained_rows: origins.length, included_rows: origins.length, excluded_rows: 0, omitted_rows: 0, oldest_considered_at: '2026-10-12T01:00:00Z', latest_considered_at: '2026-10-12T02:00:00Z' }, origins, unavailable: ['initiator', 'remote_ip', 'tls_certificate'], deferred: ['response_body_references'], warnings: [] };
}
function node() {
  const handlers = new Map(), classes = new Set();
  let html = '';
  return {
    value: '', checked: false, disabled: false, dataset: {}, attributes: {}, textContent: '', scrollTop: 0, scrollLeft: 0, clientWidth: 0, clientHeight: 0,
    style: { values: {}, setProperty(name, value) { this.values[name] = value; } },
    classList: { toggle(name, value) { if (value) classes.add(name); else classes.delete(name); }, contains: name => classes.has(name) },
    setAttribute(name, value) { this.attributes[name] = value; },
    addEventListener(name, callback) { handlers.set(name, callback); },
    dispatch(name, event = {}) { return handlers.get(name)?.({ target: this, preventDefault() {}, ...event }); },
    contains: () => true, querySelectorAll: () => [],
    get innerHTML() { return html; }, set innerHTML(value) { html = value; },
  };
}
function fixture(options = {}, sniperMap = map) {
  const requests = [];
  const els = Object.fromEntries(['panel', 'status', 'filterSummary', 'refresh', 'search', 'scope', 'canvas', 'graphBounds', 'detail', 'content', 'catalog', 'mapControls', 'allOrigins', 'directRelations', 'focusSelection', 'boundsDetails', 'graphDiagnostics', 'overlayStatus', 'viewport', 'zoomControls', 'zoomFit', 'zoomOut', 'zoomReset', 'zoomIn', 'linkKinds', 'siteControls', 'alert', 'detailsSummary'].map(name => [name, node()]));
  els.viewport.clientWidth = 300; els.viewport.clientHeight = 300;
  const document = { activeElement: null, body: {}, documentElement: node(), querySelector: () => null };
  document.documentElement.style.setProperty('--ui-root-size', '12px');
  const controller = sniperMap.createController({ ...options, elements: els, getSessionId: () => 'session-one', document, request(path) { const pending = deferred(); pending.path = path; requests.push(pending); return pending.promise; } });
  controller.setVisible(true);
  return { controller, els, requests, state: controller.getState(), async load(payload) { const pending = controller.refresh(); requests.at(-1).resolve(response(payload)); await pending; } };
}
const arrows = (html) => (html.match(/data-relationship=/g) || []).length;

// 24 unrelated origins sort first by name; the related ones sort last.
const unrelated = Array.from({ length: 24 }, (_, i) => `https://a${String(i).padStart(2, '0')}.example.com`);
const app = 'https://x-app.example.com', api = 'https://x-api.example.com', cdn = 'https://x-cdn.example.com', login = 'https://y-login.example.com';
function relatedOrigins() {
  return [...unrelated.map(id => origin(id)),
    origin(app, { redirects: [] }),
    origin(api, { header_links: [referer(app)] }),
    origin(cdn, { header_links: [referer(app)] }),
    origin(login, { redirects: [redirect(app)] })];
}

test('related origins lead the order, best connected first, so their arrows fit under the card cap', () => {
  const origins = relatedOrigins();
  const byName = origins.map(item => item.origin).sort();
  assert.equal(map.graphLayout(origins, byName).edges.length, 0, 'by name, every related origin is past the cap');
  const order = map.relationshipOrder(origins);
  assert.deepEqual([...order.slice(0, 4)], [app, api, cdn, login], 'the hub, then its neighbours');
  assert.deepEqual([...order.slice(4)], unrelated, 'unrelated origins follow by name');
  const layout = map.graphLayout(origins, order);
  assert.equal(layout.edges.length, 3);
  const at = id => [layout.slots.get(id).column, layout.slots.get(id).row];
  assert.deepEqual([login, app, api, cdn].map(at), [[0, 0], [1, 0], [2, 0], [2, 1]], 'each link moves one column right');
  assert.ok(unrelated.slice(0, 20).every(id => layout.slots.get(id).row >= 2), 'unlinked cards sit below the linked ones');
});

const columnOf = (layout, id) => layout.slots.get(id).column;
const sameColumnArrows = layout => layout.edges.filter(edge => columnOf(layout, edge.source) === columnOf(layout, edge.target)).length;

test('a hub whose targets also link to each other spreads over columns without same-column loops', () => {
  // The real session's shape: one page, its targets, and two of those targets
  // calling further origins and one shared target.
  const id = name => `https://${name}.example.com`;
  const hub = origin(id('hub')), targets = Array.from({ length: 6 }, (_, i) => origin(id(`t${i}`), { header_links: [referer(hub.origin)] }));
  const shared = origin(id('shared'), { header_links: [referer(hub.origin), referer(targets[0].origin), referer(targets[1].origin)] });
  const deep = origin(id('deep'), { header_links: [referer(targets[0].origin)] });
  const origins = [hub, ...targets, shared, deep];
  const layout = map.graphLayout(origins, map.relationshipOrder(origins));
  assert.equal(columnOf(layout, hub.origin), 0);
  assert.ok(targets.every(item => columnOf(layout, item.origin) === 1));
  assert.deepEqual([shared, deep].map(item => columnOf(layout, item.origin)), [2, 2], 'a target of the hub and of its targets sits past both');
  assert.equal(sameColumnArrows(layout), 0);
  assert.equal(layout.slots.get(hub.origin).row, 2, 'a short column is centered on the tallest');
});

test('a cycle turns one link around, and a long chain stops at five columns', () => {
  const a = origin('https://a.example.com', { redirects: [redirect('https://b.example.com')] });
  const b = origin('https://b.example.com', { redirects: [redirect(a.origin)] });
  const loop = map.graphLayout([a, b], [a.origin, b.origin]);
  assert.deepEqual([a, b].map(item => columnOf(loop, item.origin)), [0, 1]);
  assert.equal(loop.edges.length, 2, 'both directions keep their arrow');
  assert.equal(sameColumnArrows(loop), 0);

  const chain = Array.from({ length: 8 }, (_, i) => origin(`https://c${i}.example.com`));
  chain.forEach((item, i) => { if (chain[i + 1]) item.redirects = [redirect(chain[i + 1].origin)]; });
  const long = map.graphLayout(chain, chain.map(item => item.origin));
  assert.deepEqual(chain.map(item => columnOf(long, item.origin)), [0, 1, 2, 3, 4, 4, 4, 4]);
  assert.deepEqual(chain.slice(4).map(item => long.slots.get(item.origin).row), [0, 1, 2, 3], 'the shared last column keeps chain order');
  assert.equal(long.width, 2 * map.GRAPH_GEOMETRY.padding + 4 * map.GRAPH_GEOMETRY.columnPitch + map.GRAPH_GEOMETRY.cardWidth);
});

test('a self declaration links nothing and reference-only origins stay after captured ones', () => {
  const origins = [origin('https://b.example.com', { header_links: [referer('https://b.example.com')] }), origin('https://a.example.com'),
    { ...origin('https://z.example.com'), captured: false }, { ...origin('https://c.example.com'), captured: false }];
  assert.deepEqual([...map.relationshipOrder(origins)], ['https://a.example.com', 'https://b.example.com', 'https://c.example.com', 'https://z.example.com']);
});

test('the first map shows related origins with their arrows, and Reload re-ranks later relationships', async () => {
  const f = fixture();
  await f.load(snapshot(relatedOrigins()));
  assert.equal(arrows(f.els.canvas.innerHTML), 3);

  // Polling keeps the order it opened with, so relationships that appear later
  // between cards past the cap stay hidden until an explicit Reload.
  const g = fixture();
  await g.load(snapshot([...unrelated.map(id => origin(id)), origin(app), origin(api)]));
  await g.load(snapshot(relatedOrigins()));
  assert.equal(arrows(g.els.canvas.innerHTML), 0);
  const reload = g.els.refresh.dispatch('click');
  g.requests.at(-1).resolve(response(snapshot(relatedOrigins()))); await reload;
  assert.equal(arrows(g.els.canvas.innerHTML), 3);
});

test('an origin naming itself in Referer is not listed as a relationship of that origin', async () => {
  const f = fixture();
  await f.load(snapshot([origin(app, { header_links: [referer(app), referer(api)] }), origin(api)]));
  const labels = (f.state.relationsByOrigin.get(app)?.items || []).map(item => `${item.sourceOrigin} -> ${item.targetOrigin}`);
  assert.deepEqual([...labels], [`${api} -> ${app}`]);
});

// Points along an SVG path of M, L and C commands, in layout pixels.
function pathPoints(d, steps = 40) {
  const tokens = d.match(/[MLC]|-?\d+(?:\.\d+)?/g), points = [];
  let i = 0, x = 0, y = 0, command = 'M';
  const num = () => Number(tokens[i++]);
  while (i < tokens.length) {
    if (/[MLC]/.test(tokens[i])) command = tokens[i++];
    if (command === 'M') { x = num(); y = num(); points.push([x, y]); command = 'L'; continue; }
    const [ax, ay, bx, by, nx, ny] = command === 'L' ? [x, y, x, y, num(), num()] : [num(), num(), num(), num(), num(), num()];
    const lerp = command === 'L';
    for (let s = 1; s <= steps; s++) {
      const t = s / steps, u = 1 - t;
      points.push(lerp ? [x + (nx - x) * t, y + (ny - y) * t]
        : [u ** 3 * x + 3 * u * u * t * ax + 3 * u * t * t * bx + t ** 3 * nx, u ** 3 * y + 3 * u * u * t * ay + 3 * u * t * t * by + t ** 3 * ny]);
    }
    x = nx; y = ny;
  }
  return points;
}
function cardsCrossed(layout, edge) {
  const { cardWidth, cardHeight } = layout.geometry, points = pathPoints(edge.path);
  return Array.from(layout.nodes).filter(node => node.origin !== edge.source && node.origin !== edge.target
    && points.some(([x, y]) => x > node.x + 1 && x < node.x + cardWidth - 1 && y > node.y + 1 && y < node.y + cardHeight - 1)).map(node => node.origin);
}

test('an arrow that skips a column runs between rows instead of behind the cards it passes', () => {
  // A sign-in chain that returns to its start: every card is on one row, so a
  // straight return arrow would run through both middle cards and under the
  // forward arrows.
  const chain = Array.from({ length: 4 }, (_, i) => origin(`https://s${i}.example.com`));
  chain.forEach((item, i) => { item.redirects = [redirect(chain[(i + 1) % 4].origin)]; });
  const layout = map.graphLayout(chain, chain.map(item => item.origin));
  assert.deepEqual(chain.map(item => columnOf(layout, item.origin)), [0, 1, 2, 3]);
  const back = layout.edges.find(edge => edge.source === chain[3].origin);
  assert.ok(back.path.includes(' L '), 'the return arrow follows a lane');
  const { padding, cardHeight, rowPitch } = layout.geometry;
  const laneY = Number(back.path.split(' L ')[1].split(' ')[1]);
  assert.ok(laneY > padding + cardHeight && laneY < padding + rowPitch, 'the lane is the gap below the row');
  for (const edge of layout.edges) assert.deepEqual(cardsCrossed(layout, edge), [], edge.path);

  // The real session's shape: the hub also declares the targets of its targets.
  const id = name => `https://${name}.example.com`;
  const hub = origin(id('hub')), mid = Array.from({ length: 5 }, (_, i) => origin(id(`m${i}`), { header_links: [referer(hub.origin)] }));
  const far = Array.from({ length: 4 }, (_, i) => origin(id(`f${i}`), { header_links: [referer(hub.origin), referer(mid[i].origin)] }));
  const shaped = map.graphLayout([hub, ...mid, ...far], map.relationshipOrder([hub, ...mid, ...far]));
  assert.equal(shaped.edges.filter(edge => Math.abs(columnOf(shaped, edge.target) - columnOf(shaped, edge.source)) > 1).length, 4);
  for (const edge of shaped.edges) assert.deepEqual(cardsCrossed(shaped, edge), [], edge.path);
});

test('arrows between neighbouring columns turn at their own points, the longest nearest the source', () => {
  const hub = origin('https://hub.example.com');
  const targets = Array.from({ length: 5 }, (_, i) => origin(`https://t${i}.example.com`, { header_links: [referer(hub.origin)] }));
  const layout = map.graphLayout([hub, ...targets], [hub.origin, ...targets.map(item => item.origin)]);
  const bend = edge => Number(edge.path.match(/C (-?[\d.]+)/)[1]);
  const span = edge => Math.abs(layout.slots.get(edge.target).row - layout.slots.get(edge.source).row);
  const bent = layout.edges.filter(edge => span(edge) > 0);
  assert.equal(new Set(bent.map(bend)).size, bent.length, 'no two vertical runs share a track');
  const [longest] = [...bent].sort((a, b) => span(b) - span(a));
  assert.equal(bend(longest), Math.min(...bent.map(bend)));
});

test('cards whose arrows all fall past the arrow cap sit with the unlinked cards', () => {
  // Each target and the hub link both ways: two arrows each, past the cap.
  const targets = Array.from({ length: 20 }, (_, i) => origin(`https://t${String(i).padStart(2, '0')}.example.com`, { header_links: [referer('https://hub.example.com')] }));
  const hub = origin('https://hub.example.com', { header_links: targets.map(target => referer(target.origin)) });
  const p = origin('https://p.example.com'), q = origin('https://q.example.com', { header_links: [referer('https://p.example.com')] });
  const origins = [hub, ...targets, p, q];
  const layout = map.graphLayout(origins, map.relationshipOrder(origins));
  assert.equal(layout.edgeCount, 41); assert.equal(layout.edges.length, 40);
  assert.ok([p, q].every(item => layout.slots.get(item.origin).row >= 20), 'below the 20 linked targets, not beside them');
});

test('a pinned star centers its source on its neighbors', () => {
  const source = origin('https://source.example.com'), neighbors = Array.from({ length: 5 }, (_, i) => origin(`https://n${i}.example.com`));
  const bodyEdges = neighbors.map(item => ({ source: source.origin, target: item.origin, relationship: 'body_url_reference', label: 'Literal body URL reference' }));
  const layout = map.graphLayout([source, ...neighbors], [source.origin, ...neighbors.map(item => item.origin)], new Map(), source.origin, bodyEdges);
  assert.deepEqual([layout.slots.get(source.origin).column, layout.slots.get(source.origin).row], [0, 2]);
  for (const edge of layout.edges) assert.deepEqual(cardsCrossed(layout, edge), [], edge.path);
});

test('the Service Map filter rides on every read; changing it re-reads, re-ranks and reports hidden rows', async () => {
  let filter = { hidden_extensions: 'png,css' };
  const f = fixture({ getFilterQuery: () => filter, getFilterSummary: () => ({ text: 'hiding png, css', detail: 'Service Map filter: hiding png, css' }) });
  await f.load(snapshot(relatedOrigins()));
  assert.match(f.requests.at(-1).path, /hidden_extensions=png%2Ccss/);
  assert.match(f.requests.at(-1).path, /session_id=session-one/);
  assert.equal(f.els.filterSummary.textContent, 'hiding png, css');

  // A filter restored from settings, with no dialog: the next poll re-ranks.
  filter = { hidden_extensions: 'png' };
  f.state.order = ['https://stale.example.com'];
  await f.load(snapshot(relatedOrigins()));
  assert.equal(f.state.order[0], app);

  filter = { mime_types: 'html,json' };
  f.state.order = ['https://stale.example.com'];
  const reading = f.controller.filterChanged();
  assert.match(f.requests.at(-1).path, /mime_types=html%2Cjson/);
  assert.doesNotMatch(f.requests.at(-1).path, /hidden_extensions/);
  const payload = snapshot(relatedOrigins());
  payload.snapshot.filtered_rows = 7;
  f.requests.at(-1).resolve(response(payload)); await reading;
  assert.deepEqual([...f.state.order.slice(0, 4)], [app, api, cdn, login], 'cards are ranked again for the rows that remain');
  assert.match(f.els.status.textContent, /7 hidden by the Service Map filter/);
});

test("the selected card's own gold arrows flow toward their targets, and only when motion is allowed", async () => {
  const f = fixture();
  await f.load(snapshot(relatedOrigins()));
  const selected = () => (f.els.canvas.innerHTML.match(/class="service-map-edge [^"]*\bselected\b/g) || []).length;
  f.controller.selectOrigin(app);
  assert.equal(selected(), 3, 'the hub: two Referer targets and the redirect into it');
  f.controller.selectOrigin(api);
  assert.equal(selected(), 1);
  assert.doesNotMatch(f.els.canvas.innerHTML, /service-map-flow/, 'no second line is drawn over the arrow');
  const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
  const motion = css.match(/@media \(prefers-reduced-motion: no-preference\) \{([^]*?)\n\}/)?.[1] || '';
  assert.match(motion, /\.service-map-edge\.selected:not\(\.peer-observation\) \{ animation: service-map-flow-18/);
  assert.match(motion, /data-relationship="redirect_instruction"\] \{ stroke-dasharray: 14 4; \}/, 'a solid redirect takes dashes so it can flow');
  assert.match(css, /@keyframes service-map-flow-11 \{ to \{ stroke-dashoffset: -11; \} \}/, 'one Referer dash period per cycle');
  assert.doesNotMatch(css.replace(motion, ''), /\.service-map-edge\.selected[^{]*\{[^}]*animation/, 'no animation outside the motion-allowed block');
});

test('ctrl+wheel and WebKit pinch gestures zoom around the fingers; a plain wheel only scrolls', async () => {
  const f = fixture();
  await f.load(snapshot(unrelated.map(id => origin(id))));
  f.els.viewport.getBoundingClientRect = () => ({ left: 100, top: 50 });
  f.els.viewport.scrollLeft = 120; f.els.viewport.scrollTop = 480;
  let prevented = 0;
  const wheel = (extra) => f.els.viewport.dispatch('wheel', { deltaY: -10, deltaMode: 0, clientX: 100, clientY: 50, preventDefault() { prevented += 1; }, ...extra });

  wheel({ ctrlKey: false });
  assert.equal(f.state.zoomScale, 1); assert.equal(prevented, 0, 'a plain wheel is left to scroll the map');

  wheel({ ctrlKey: true });
  assert.ok(Math.abs(f.state.zoomScale - Math.exp(0.1)) < 1e-4); assert.equal(prevented, 1);
  // The fingers are at the viewport's top-left corner, so that graph point stays put.
  assert.ok(Math.abs(f.els.viewport.scrollLeft - 120 * f.state.zoomScale) < 0.01);
  assert.ok(Math.abs(f.els.viewport.scrollTop - 480 * f.state.zoomScale) < 0.01);

  wheel({ ctrlKey: true, deltaY: 1000 });
  assert.ok(Math.abs(f.state.zoomScale - Math.round(Math.exp(0.1) * Math.exp(-0.2) * 10000) / 10000) < 1e-4, 'one mouse notch is capped near a button step');

  f.controller.setZoom(1);
  f.els.viewport.dispatch('gesturestart', { preventDefault() { prevented += 1; } });
  f.els.viewport.dispatch('gesturechange', { scale: 1.5, clientX: 250, clientY: 200, preventDefault() { prevented += 1; } });
  assert.equal(f.state.zoomScale, 1.5);
  wheel({ ctrlKey: true });
  assert.equal(f.state.zoomScale, 1.5, 'a ctrl+wheel arriving during a gesture does not zoom twice');
  f.els.viewport.dispatch('gesturechange', { scale: 9, preventDefault() {} });
  assert.equal(f.state.zoomScale, 2, 'pinching stays within the zoom limits');
  f.els.viewport.dispatch('gestureend', { preventDefault() {} });
  f.els.viewport.dispatch('gesturechange', { scale: 0.5, preventDefault() {} });
  assert.equal(f.state.zoomScale, 2, 'a change after the gesture ended is ignored');
  assert.equal(f.requests.length, 1, 'zooming reads nothing');
});

// What each Origin/Referer link stood for: an API call, a page load, a frame,
// or a script or static file the page pulled in.
const kinded = (sourceOrigin, kinds) => ({ ...referer(sourceOrigin), request_count: Object.values(kinds).reduce((sum, rows) => sum + rows, 0), request_kinds: kinds });
function kindedOrigins() {
  // The page's own reloads name itself; that is no link and counts in no toggle.
  return [origin(app, { header_links: [kinded(app, { navigation: 2 })] }),
    origin(api, { header_links: [kinded(app, { api: 3 })] }),
    origin(cdn, { header_links: [kinded(app, { script: 1, static: 4 })] }),
    origin(login, { header_links: [kinded(app, { navigation: 1, frame: 2 })] })];
}

test('a link is drawn for the request kinds behind it: hidden kinds drop it, the leading kind colors it, rows weigh it', () => {
  const normalized = map.normalizeSnapshot(snapshot([origin(app), origin(api, { header_links: [{ ...kinded(app, { api: 2 }), request_kinds: { api: 2, bogus: 5, static: 0 } }] })]), 'session-one');
  const link = normalized.origins.find(item => item.origin === api).header_links[0];
  assert.deepEqual({ ...link.request_kinds }, { api: 2 }, 'unknown and empty kinds are dropped');
  assert.equal(link.request_count, 2);

  const origins = kindedOrigins();
  const edge = (layout, id) => layout.edges.find(item => item.target === id);
  const resourcesHidden = map.graphLayout(origins, map.relationshipOrder(origins, ['script', 'static']), new Map(), null, [], undefined, ['script', 'static']);
  assert.equal(resourcesHidden.edges.length, 2, 'the CDN link stood only for a script and images');
  assert.equal(edge(resourcesHidden, cdn), undefined);
  assert.deepEqual([edge(resourcesHidden, api).kind, edge(resourcesHidden, api).count], ['api', 3]);
  assert.deepEqual([edge(resourcesHidden, login).kind, edge(resourcesHidden, login).count], ['navigation', 3], 'a page load leads its frames, however many');
  assert.equal(map.relationshipOrder(origins, ['script', 'static']).indexOf(cdn), 3, 'a hidden link ranks nothing');

  const everything = map.graphLayout(origins, map.relationshipOrder(origins), new Map(), null, [], undefined, []);
  assert.deepEqual([edge(everything, cdn).kind, edge(everything, cdn).count, { ...edge(everything, cdn).kinds }], ['script', 5, { script: 1, static: 4 }]);
  const mixed = [origin(app), origin(api, { header_links: [kinded(app, { api: 1, static: 9 })] })];
  assert.equal(map.graphLayout(mixed, [app, api], new Map(), null, [], undefined, []).edges[0].kind, 'api', 'one API call among nine image loads still reads as an API link');
  const noFrames = map.graphLayout(origins, map.relationshipOrder(origins), new Map(), null, [], undefined, ['frame']);
  assert.deepEqual([edge(noFrames, login).kind, edge(noFrames, login).count], ['navigation', 1], 'the rows of a hidden kind no longer count');
  const older = map.graphLayout([origin(app), origin(api, { header_links: [referer(app)] })], [app, api], new Map(), null, [], undefined, ['script', 'static']);
  assert.deepEqual([older.edges[0].kind, older.edges[0].count], ['other', 1], 'a link from an older server is drawn as other requests');
});

test('the legend toggles links by request kind: the map redraws, ranks again and saves the choice', async () => {
  let hidden = ['script', 'static'];
  const saves = [];
  const f = fixture({ getHiddenLinkKinds: () => hidden, setHiddenLinkKinds: kinds => { hidden = kinds; saves.push([...kinds]); } });
  await f.load(snapshot(kindedOrigins()));
  const toggles = () => Object.fromEntries([...f.els.linkKinds.innerHTML.matchAll(/data-link-kind="(\w+)"[^>]*aria-pressed="(\w+)"[^>]*><span class="service-map-kind-swatch"[^>]*><\/span>([^<]*)</g)].map(([, kind, pressed, label]) => [kind, `${pressed} ${label}`]));
  assert.deepEqual(toggles(), { api: 'true API calls 1', navigation: 'true Page navigations 1', frame: 'true Frames 1', script: 'false Scripts 1', static: 'false Static files 1' });
  assert.equal(arrows(f.els.canvas.innerHTML), 2);
  assert.match(f.els.canvas.innerHTML, /class="service-map-edge header-declaration kind-api [^"]*" data-relationship="referer_header" style="--edge-weight:1.76px"/, 'three rows draw a slightly heavier line');
  assert.match(f.els.canvas.innerHTML, /3 requests \(API calls 3\)<\/title>/);

  const click = kind => f.els.linkKinds.dispatch('click', { target: { closest: () => ({ dataset: { linkKind: kind } }) } });
  click('static');
  assert.deepEqual(saves, [['script']]);
  assert.equal(toggles().static, 'true Static files 1');
  assert.equal(arrows(f.els.canvas.innerHTML), 3, 'the CDN link returns for its images');
  assert.match(f.els.canvas.innerHTML, /kind-static [^"]*" data-relationship="referer_header" style="--edge-weight:1.83px"/);
  assert.match(f.els.canvas.innerHTML, /4 requests \(Static files 4\)<\/title>/, 'the hidden script row is not counted');
  click('bogus');
  assert.equal(saves.length, 1, 'only a known kind toggles');

  // A choice made in another window arrives with settings: the next read ranks again.
  hidden = ['api', 'navigation', 'frame', 'script', 'static', 'other'];
  f.state.order = ['https://stale.example.com'];
  await f.load(snapshot(kindedOrigins()));
  assert.equal(arrows(f.els.canvas.innerHTML), 0);
  assert.notEqual(f.state.order[0], 'https://stale.example.com');
});

test('an arrow names its CORS rows, and selecting it marks its entry in the inspector', async () => {
  const f = fixture();
  const cors = { ...kinded(app, { api: 3 }), cors_allowed_count: 2, cors_credentials_count: 1 };
  await f.load(snapshot([origin(app), origin(api, { header_links: [cors] }), origin(login, { header_links: [kinded(app, { frame: 2 })] })]));
  assert.equal(arrows(f.els.canvas.innerHTML), 1, 'frames, scripts and static files are hidden by default');
  assert.match(f.els.canvas.innerHTML, /3 requests \(API calls 3\) · CORS allowed 2 of 3 rows, 1 with credentials<\/title>/);
  const hits = [...f.els.canvas.innerHTML.matchAll(/<path class="service-map-hit" data-service-edge="(\d+)"[^>]*><title>([^<]*)<\/title>/g)];
  assert.equal(hits.length, 1, 'one pointer target per recorded arrow');

  f.controller.selectOrigin(login);
  assert.match(f.els.canvas.innerHTML, /markerUnits="userSpaceOnUse"/, 'an arrowhead keeps its size on a heavy line');
  assert.match(f.els.canvas.innerHTML, /kind-api "[^>]*marker-end="url\(#service-map-arrow-api\)"/, 'an API arrow ends in a blue head');
  f.els.panel.dispatch('click', { target: { closest: selector => selector === '[data-service-edge]' ? { dataset: { serviceEdge: hits[0][1] } } : null } });
  assert.equal(f.state.selectedOrigin, api, 'the Referer link is recorded on the origin it was sent to');
  assert.match(f.els.canvas.innerHTML, /kind-api selected"[^>]*marker-end="url\(#service-map-arrow-selected\)"/, "the selected card's arrows end in gold heads");
  assert.match(f.els.detail.innerHTML, /service-map-relation highlighted"[^]*?API calls 3 · CORS allowed 2 of 3 rows, 1 with credentials/);
  assert.equal((f.els.detail.innerHTML.match(/highlighted/g) || []).length, 1);
  f.controller.selectOrigin(app);
  assert.doesNotMatch(f.els.detail.innerHTML, /highlighted/, 'another selection clears the mark');
});

// Two sites: the leading origin's example.com, and example.net with two origins.
const imgCdn = 'https://img.example.net', cssCdn = 'https://css.example.net';
function siteOrigins() {
  return [origin(app),
    origin(api, { header_links: [kinded(app, { api: 2 })] }),
    origin(imgCdn, { header_links: [kinded(app, { api: 1, static: 3 })] }),
    origin(cssCdn, { header_links: [kinded(app, { api: 2 })], redirects: [redirect(imgCdn)] })];
}
const press = (f, dataset) => f.els.panel.dispatch('click', { target: { closest: selector => selector === 'button' ? { dataset } : null } });

test('site keys take the last two host labels, three under listed suffixes, and never an address', () => {
  assert.deepEqual(['https://shop-images.example.net', 'https://www.example.co.kr', 'https://example.com', 'http://127.0.0.1:8080', 'http://[::1]:80', 'http://localhost:3000'].map(map.siteKey),
    ['example.net', 'example.co.kr', 'example.com', null, null, null]);
});

test('site keys ignore one DNS root dot before applying the existing suffix rules', () => {
  for (const [host, expected] of [
    ['example.com', 'example.com'], ['a.example.com', 'example.com'],
    ['a.example.co.uk', 'example.co.uk'], ['b.example.org.uk', 'example.org.uk'],
    ['a.example.co.kr', 'example.co.kr'], ['a.example.com.au', 'example.com.au'],
    ['co.uk', 'co.uk'], ['a.example.co.test', 'co.test'],
    ['localhost', null], ['127.0.0.1', null], ['0x7f000001', null],
    ['bücher.example.com', 'example.com'],
  ]) {
    for (const suffix of ['', '.']) {
      assert.equal(map.siteKey(`https://${host}${suffix}:8443`), expected, `${host}${suffix}`);
    }
  }
  assert.equal(map.siteKey('https://A.EXAMPLE.CO.UK.:8443'), 'example.co.uk');
  assert.equal(map.siteKey('https://a.example.com\u3002'), 'example.com', 'URL parsing normalizes the Unicode root dot');
  assert.equal(map.siteKey('http://[::1]:8080'), null);
  assert.equal(map.siteKey('http://[::ffff:192.0.2.1]:8080'), null);
  for (const origin of ['not a URL', 'https://.', 'https://..', 'https://example.com..', 'https://a..example.com']) {
    assert.equal(map.siteKey(origin), null, 'empty hostname labels must not merge unrelated origins');
  }
});

test('site grouping keeps root-dotted public suffixes separate and retains exact origin identities', () => {
  const ids = ['https://a.example.co.uk.', 'https://b.example.co.uk', 'http://a.example.co.uk.:8080',
    'https://a.example.org.uk.', 'https://b.example.org.uk.', 'http://localhost.', 'http://127.0.0.1', 'http://[::1]'];
  const origins = ids.map(id => origin(id));
  origins[3].header_links = [referer(ids[0])];
  const grouped = map.groupSites(origins);
  assert.deepEqual([...grouped.cards].map(item => item.origin),
    ['site:example.co.uk', 'site:example.org.uk', ...ids.slice(5)]);
  assert.deepEqual([...grouped.cards[0].members].map(item => item.origin), ids.slice(0, 3));
  assert.deepEqual([...grouped.cards[1].members].map(item => item.origin), ids.slice(3, 5));
  assert.equal(grouped.cards[1].header_links[0].source_origin, 'site:example.co.uk');
  assert.deepEqual(origins.map(item => item.origin), ids, 'site display normalization never rewrites captured origins');
  assert.equal(origins[3].header_links[0].source_origin, ids[0], 'original relationship evidence stays exact');
  const apart = map.groupSites(origins, site => site === 'example.co.uk');
  assert.deepEqual([...apart.cards].map(item => item.origin), [...ids.slice(0, 3), 'site:example.org.uk', ...ids.slice(5)]);
});

test('root-dotted site selection, expand, hide and regroup stay local to the correct site', async () => {
  let display = { groupSites: true, expandedSites: [], hidden: [] };
  const f = fixture({ getSiteDisplay: () => display, setSiteDisplay: next => { display = next; } });
  const leading = 'https://app.example.com';
  const uk = ['https://a.example.co.uk.', 'https://b.example.co.uk'];
  const org = ['https://a.example.org.uk.', 'https://b.example.org.uk.'];
  const data = snapshot([origin(leading), ...[...uk, ...org].map(id => origin(id, { header_links: [referer(leading)] }))]);
  await f.load(data);
  const html = () => f.els.canvas.innerHTML;
  assert.match(html(), /data-service-site="example\.co\.uk"/);
  assert.match(html(), /data-service-site="example\.org\.uk"/);
  assert.doesNotMatch(html(), /data-service-site="uk\."/);
  assert.equal(arrows(html()), 2, 'separate sites keep separate relationship arrows');

  press(f, { serviceSite: 'example.co.uk' });
  assert.equal(f.state.selectedSite, 'example.co.uk');
  assert.ok(f.els.detail.innerHTML.includes(uk[0]));
  assert.ok(f.els.detail.innerHTML.includes(uk[1]));
  assert.ok(!f.els.detail.innerHTML.includes(org[0]));
  press(f, { serviceOrigin: uk[0] });
  assert.equal(f.state.selectedOrigin, uk[0], 'inspector uses the exact root-dotted origin');
  press(f, { serviceSiteExpand: 'example.co.uk' });
  assert.deepEqual([...display.expandedSites], ['example.co.uk']);
  assert.match(html(), /data-service-origin="https:\/\/a\.example\.co\.uk\."/);
  assert.match(html(), /data-service-site="example\.org\.uk"/);
  assert.equal(arrows(html()), 3);

  press(f, { serviceHide: 'example.co.uk' });
  assert.doesNotMatch(html(), /example\.co\.uk/);
  assert.match(html(), /data-service-site="example\.org\.uk"/);
  press(f, { serviceUnhide: 'example.co.uk' });
  press(f, { serviceSiteCollapse: 'example.co.uk' });
  assert.match(html(), /data-service-site="example\.co\.uk"/);
  assert.equal(arrows(html()), 2);
  assert.equal(f.requests.length, 1, 'site display actions do not fetch or probe origins');

  await f.load(snapshot([...data.origins].reverse()));
  assert.equal(f.state.selectedOrigin, uk[0], 'refresh preserves exact origin selection');
  assert.match(html(), /data-service-site="example\.co\.uk"/);
  press(f, { serviceGroupSites: 'toggle' });
  for (const id of [...uk, ...org]) assert.ok(html().includes(`data-service-origin="${id}"`));
  assert.equal(arrows(html()), 4);
  assert.equal(f.requests.length, 2, 'only explicit map refreshes read metadata');
});

test("a site's origins share one card and one arrow, and the leading origin's site keeps a card per origin", async () => {
  let display = { groupSites: true, expandedSites: [], hidden: [] };
  const saves = [];
  const f = fixture({ getSiteDisplay: () => display, setSiteDisplay: next => { display = next; saves.push(next); } });
  await f.load(snapshot(siteOrigins()));
  const html = () => f.els.canvas.innerHTML;
  assert.match(html(), /data-service-site="example\.net"/);
  assert.doesNotMatch(html(), /data-service-origin="https:\/\/img\.example\.net"/);
  assert.match(html(), /data-service-origin="https:\/\/x-api\.example\.com"/, "the leading origin's site is not grouped");
  assert.equal(arrows(html()), 2, 'the redirect inside the site is gone');
  assert.match(html(), /→ \*\.example\.net · Referer header · referer_header · 3 requests \(API calls 3\)<\/title>/, 'both links share the arrow and add up');

  press(f, { serviceSite: 'example.net' });
  assert.match(f.els.detail.innerHTML, /\*\.example\.net[^]*2 origins grouped by site/);
  assert.match(html(), /service-map-site\s+selected/);
  press(f, { serviceOrigin: imgCdn });
  assert.equal(f.state.selectedOrigin, imgCdn);
  assert.match(html(), /service-map-site\s+selected/, 'a member keeps its site card selected');

  press(f, { serviceSiteExpand: 'example.net' });
  assert.deepEqual([...display.expandedSites], ['example.net']);
  assert.equal(arrows(html()), 4, 'each origin has its card and arrows again');
  assert.match(f.els.detail.innerHTML, /data-service-site-collapse="example\.net"/, 'an expanded site can be grouped again');

  press(f, { serviceHide: 'example.net' });
  assert.deepEqual([...display.hidden], ['example.net']);
  assert.doesNotMatch(html(), /example\.net/);
  assert.match(f.els.siteControls.innerHTML, /Hidden 1[^]*data-service-unhide="example\.net"/);
  press(f, { serviceUnhideAll: 'all' });
  assert.match(html(), /img\.example\.net/);

  press(f, { serviceGroupSites: 'toggle' });
  assert.equal(display.groupSites, false);
  assert.match(f.els.siteControls.innerHTML, /data-service-group-sites="toggle"[^>]*aria-pressed="false"/);
  assert.equal(saves.length, 4, 'expand, hide, show all and the toggle each save once');
});

test('a card leads with what its origin serves, or with a declared front-end product', () => {
  const typed = (types, extra = {}) => ({ origin: 'https://a.example.com', captured: true, endpoints: types.map(type => ({ content_types: [type] })), technology_observations_present: true, technology_observations: [], ...extra });
  assert.deepEqual([typed(['text/html', 'application/json']), typed(['application/json']), typed(['image/svg+xml', 'text/css']), typed([]), typed(['text/plain']), typed([], { captured: false })].map(map.originRole),
    ['front', 'api', 'static', 'unknown', 'unknown', 'ref']);
  const failing = { origin: 'https://a.example.com', captured: true, technology_observations_present: true, technology_observations: [],
    endpoints: [{ content_types: ['application/json'], statuses: [200] }, { content_types: ['text/html'], statuses: [500] }, { content_types: ['text/html'], statuses: [404, 502] }] };
  assert.equal(map.originRole(failing), 'api', "an API's HTML error pages do not make it Front");
  assert.equal(map.originRole({ ...failing, endpoints: [...failing.endpoints, { content_types: ['text/html'], statuses: [200, 404] }] }), 'front', 'a page that once loaded does');
  const next = typed(['application/json'], { technology_observations: [{ product_id: 'next_js', name: 'Next.js', version_status: 'not_reported' }] });
  assert.equal(map.originRole(next), 'front', 'Next.js names the front end however its endpoints respond');
  const react = (origin, types) => typed(types, { front_technologies: [{ product_id: 'react', name: 'React', category: 'framework', version: '18.2.0', source_origin: origin, row_count: 1, evidence: 'e' }] });
  assert.equal(map.originRole(react('https://a.example.com', ['application/javascript'])), 'static', 'a CDN serving React is not the page');
  assert.equal(map.originRole(react('https://cdn.example.com', ['application/json'])), 'front', 'a page that loaded React is');
  assert.equal(map.originRole(react('https://a.example.com', ['text/html', 'application/javascript', 'application/javascript'])), 'front');
  const loads = (category) => typed(['application/json'], { front_technologies: [{ product_id: 'x', name: 'X', category, source_origin: 'https://cdn.example.com', row_count: 1, evidence: [] }] });
  assert.deepEqual(['cms', 'library', 'analytics'].map((category) => map.originRole(loads(category))), ['front', 'api', 'api'], 'a library or tracker a page loads is not what it is built with');
});

test('an authentication server is Auth, and an origin serving pages and API data names both', () => {
  const at = (origin, paths, extra = {}) => ({ origin, captured: true, technology_observations_present: true, technology_observations: [],
    endpoints: paths.map(([path, type, status = 200]) => ({ path, content_types: [type], statuses: [status] })), ...extra });
  const roles = (origin) => [...map.originRoles(origin)];
  const idp = at('https://idp.example.net', [['/oauth2/authorize', 'text/html'], ['/oauth2/token', 'application/json'], ['/login', 'text/html'], ['/css/site.css', 'text/css'], ['/js/app.js', 'application/javascript']]);
  assert.equal(map.originRole(idp), 'auth', 'its typed paths are sign-in and token endpoints; its assets do not count');
  const app = at('https://app.example.com', [['/login', 'text/html'], ['/logout', 'text/html'], ['/', 'text/html'], ['/orders', 'text/html'], ['/cart', 'text/html'], ['/api/items', 'application/json']]);
  assert.notEqual(map.originRole(app), 'auth', 'an app that also signs its users in keeps its own role');
  assert.equal(map.originRole(at('https://app.example.com', [['/login', 'text/html']])), 'front', 'one login page is not enough');
  assert.equal(map.originRole(at('https://sso.example.com', [['/login', 'text/html'], ['/home', 'text/html']])), 'auth', 'a host named for sign-in with a sign-in path');
  assert.equal(map.originRole(at('https://www.example.com', [['/authorize', 'text/html'], ['/', 'text/html'], ['/a', 'text/html']], { auth: [{ kind: 'oauth2', name: null, row_count: 1, evidence: [] }] })), 'auth', 'a client asked it for a token');
  assert.equal(map.originRole(at('https://www.example.com', [['/', 'text/html']], { server_technologies: [{ product_id: 'keycloak', name: 'Keycloak', category: 'app_server', signals: ['cookie'], row_count: 1, evidence: [] }] })), 'auth', 'an identity provider by product');
  assert.deepEqual(roles(at('https://a.example.com', [['/', 'text/html'], ['/api/items', 'application/json']])), ['front', 'api']);
  assert.deepEqual(roles(at('https://a.example.com', [['/', 'text/html'], ['/manifest.json', 'application/manifest+json'], ['/api/missing', 'application/json', 404]])), ['front'], 'a manifest or a JSON error is not an API');
  assert.deepEqual(roles(at('https://a.example.com', [['/v1/items', 'application/json'], ['/v1/users', 'application/json'], ['/docs', 'text/html']])), ['front', 'api']);
  assert.deepEqual(roles(idp), ['auth']);
});

test('only an error or the first load shows above the map; counts sit under Details', async () => {
  const f = fixture();
  const reading = f.controller.refresh();
  assert.equal(f.els.alert.textContent, 'Loading retained HTTP metadata…');
  f.requests.at(-1).resolve(response(snapshot(relatedOrigins()))); await reading;
  assert.equal(f.els.alert.textContent, '');
  assert.match(f.els.status.textContent, /rows considered/, 'the full status stays under Details');
  assert.match(f.els.canvas.innerHTML, /service-map-card-role role-front"[^]*?>Front</, 'each card names its role');
  assert.equal(f.els.detailsSummary.textContent, 'Details · 24 / 28 origins shown');
  const failing = f.controller.refresh({ force: true });
  f.requests.at(-1).resolve({ ok: false, status: 500, json: async () => ({}) }); await failing;
  assert.notEqual(f.els.alert.textContent, '');
  assert.equal(f.els.alert.classList.contains('service-map-error'), true);
});

test('front-end technologies show on the card by what the site is built with, and in the inspector', async () => {
  const named = { product_id: 'next_js', name: 'Next.js', category: 'meta_framework', version: '14.2.3', source_origin: cdn, row_count: 2, evidence: ['evidence-script'] };
  const react = { product_id: 'react', name: 'React', category: 'framework', version: '18.2.0', source_origin: cdn, row_count: 2, evidence: ['evidence-react'] };
  const core = { product_id: 'core_js', name: 'core-js', category: 'library', version: '3.38.1', source_origin: cdn, row_count: 1, evidence: [] };
  const tracker = { product_id: 'google_tag_manager', name: 'Google Tag Manager', category: 'analytics', source_origin: cdn, row_count: 1, evidence: [] };
  const header = { technology_observations_present: true, technology_observations: [{ product_id: 'next_js', name: 'Next.js', version_status: 'not_reported' }], front_technologies: [named] };
  const [product] = map.reportedProducts(header);
  assert.deepEqual([[...product.versions], [...product.statuses]], [['14.2.3'], []], 'a declared version supersedes a header that named none');
  assert.match(map.productSummaryMarkup(header), />Next\.js 14\.2\.3</);
  assert.match(map.productSummaryMarkup({ front_technologies: [tracker] }), />Google Tag Manager</, 'a product found without a version is its name alone');
  assert.doesNotMatch(map.productSummaryMarkup({ front_technologies: [tracker] }), /version unknown/);

  const f = fixture();
  await f.load(snapshot([origin(app, { front_technologies: [tracker, core, react, named, { ...named, version: '<b>' }, { ...react, product_id: 'Bad-Id' }, { ...core, category: 'server' }] }), origin(api, { header_links: [referer(app)] })]));
  assert.equal(f.state.snapshot.origins.find(item => item.origin === app).front_technologies.length, 4, 'unsafe entries are dropped');
  assert.match(f.els.canvas.innerHTML, /role-front"[^]*?service-map-mark[^>]*>N<[^]*?>Next\.js 14\.2\.3<[^]*?>React 18\.2\.0</, 'the meta-framework leads: its mark, then its chip, then the framework');
  f.controller.selectOrigin(app);
  assert.match(f.els.detail.innerHTML, /<h4>Front-end<\/h4>[^]*?Next\.js<\/strong> · 14\.2\.3[^]*?2 retained rows from https:\/\/x-cdn\.example\.com/);
  assert.match(f.els.detail.innerHTML, /Google Tag Manager<\/strong><p/, 'no version, no version text');
  assert.match(f.els.detail.innerHTML, /data-service-relation-origin="https:\/\/x-cdn\.example\.com" data-service-relation-evidence="evidence-react"/);
});

test('opening an endpoint shows its parameters: name, where sent, rows and values', async () => {
  const f = fixture();
  await f.load(snapshot([origin(app, { endpoints: [{ method: 'GET', path: '/search', request_count: 2, statuses: [200], content_types: ['application/json'], evidence: ['evidence-search'] }] })]));
  const before = f.requests.length;
  f.controller.selectOrigin(app, 0);
  assert.equal(f.requests.length, before + 1, 'read on opening, with no button to press');
  assert.equal(f.requests.at(-1).path, '/api/target/service-map/parameters?session_id=session-one&origin=https%3A%2F%2Fx-app.example.com&method=GET&path=%2Fsearch');
  assert.match(f.els.detail.innerHTML, /Reading parameters…/);
  assert.doesNotMatch(f.els.detail.innerHTML, /Show parameters/);
  f.controller.selectOrigin(app, 0);
  assert.equal(f.requests.length, before + 1, 'reopening the endpoint being read reads nothing more');
  f.requests.at(-1).resolve(response({ schema_version: 1, session_id: 'session-one', available: true, origin: app, method: 'GET', path: '/search', rows: 2, more_rows: false, omitted_parameters: 0,
    parameters: [{ name: 'q', location: 'query', rows: 2, examples: ['shoes', '<b>'] }, { name: 'x', location: 'cookie', rows: 1, examples: [] }] }));
  await new Promise(resolve => setImmediate(resolve));
  assert.match(f.els.detail.innerHTML, /<li><div><span class="service-map-parameter-name">q<\/span><span class="service-map-muted">query · 2 rows<\/span><\/div><div class="service-map-parameter-values"><code>shoes<\/code><code>&lt;b&gt;<\/code><\/div><\/li>/);
  assert.doesNotMatch(f.els.detail.innerHTML, /service-map-parameter-name">x</, 'an unknown location is dropped');
  assert.doesNotMatch(f.els.detail.innerHTML, /From the newest/, 'every row was read: nothing to note');
  assert.doesNotMatch(f.els.detail.innerHTML, /<table/, 'no table to squeeze a name beside long values');
});

test('the map reads every retained row, and asks for a fresh map only on the first read and Reload', async () => {
  const f = fixture();
  await f.load(snapshot(relatedOrigins()));
  assert.match(f.requests.at(-1).path, /[?&]all_rows=true(&|$)/);
  assert.doesNotMatch(f.requests.at(-1).path, /max_records=/);
  assert.match(f.requests.at(-1).path, /[?&]fresh=true(&|$)/, 'the first read');
  await f.load(snapshot(relatedOrigins()));
  assert.doesNotMatch(f.requests.at(-1).path, /fresh=/, 'a poll may be served from the cache');
  const reload = f.controller.refresh({ force: true });
  assert.match(f.requests.at(-1).path, /[?&]fresh=true(&|$)/, 'Reload');
  f.requests.at(-1).resolve(response(snapshot(relatedOrigins()))); await reload;
});

test('one arrow per direction carries every relationship between two cards', () => {
  const a = origin(app, { redirects: [redirect(api)] }), b = origin(api, { header_links: [referer(app), { ...referer(app), relationship: 'origin_header' }] });
  const layout = map.graphLayout([a, b], [app, api]);
  assert.equal(layout.edges.length, 1);
  assert.deepEqual([...layout.edges[0].relationships], ['redirect_instruction', 'referer_header', 'origin_header']);
  assert.equal(layout.edges[0].relationship, 'redirect_instruction', 'drawn as the first of them');
  const pinned = map.graphLayout([a, b], [app, api], new Map(), app);
  assert.equal(pinned.edges.length, 3, 'Direct relations keeps each relationship apart');
});

test('clients lead the map in their own column and point at the cards where it starts', async () => {
  const chrome = { kind: 'browser', name: 'Chrome', versions: [141, 140], os: 'macOS', request_count: 5, evidence: [],
    origins: [{ origin: api, request_count: 3 }, { origin: app, request_count: 2, entry_kinds: { navigation: 1 } }] };
  const okhttp = { kind: 'app', name: 'OkHttp', versions: [4], request_count: 2, evidence: [], origins: [{ origin: api, request_count: 2, entry_kinds: { api: 2 } }] };
  const curl = { kind: 'tool', name: 'curl', versions: [8], request_count: 1, evidence: [], origins: [{ origin: cdn, request_count: 1, entry_kinds: { static: 1 } }] };
  const other = { kind: 'unknown', name: 'Other', request_count: 9, evidence: [], origins: [{ origin: api, request_count: 9, entry_kinds: { api: 9 } }] };
  let hidden = ['static'];
  const f = fixture({ getHiddenLinkKinds: () => hidden, setHiddenLinkKinds: kinds => { hidden = kinds; } });
  await f.load({ ...snapshot([origin(app), origin(api, { header_links: [referer(app)] }), origin(cdn)]),
    clients: [chrome, okhttp, curl, other, { ...curl, kind: 'server' }, { ...okhttp, name: '<b>' }] });
  assert.equal(f.state.snapshot.clients.length, 4, 'unsafe clients are dropped');
  assert.deepEqual([...f.state.snapshot.clients[0].versions], [141, 140]);
  const html = f.els.canvas.innerHTML;
  assert.match(html, /data-service-client="client:browser:Chrome:macOS"[^]*?>Chrome<[^]*?macOS · 5 rows/, 'one card per browser, whatever its versions');
  assert.match(html, /data-service-client="client:app:OkHttp:"[^]*?>App</);
  assert.doesNotMatch(html, /data-service-client="client:tool:curl/, 'a client whose own requests are all of a hidden kind draws no card');
  assert.doesNotMatch(html, /data-service-client="client:unknown/, 'an unnamed User-Agent draws no card');
  assert.equal((html.match(/data-relationship="client_request"/g) || []).length, 1, 'unselected, a client points only at cards nothing else links to');
  assert.match(html, /Chrome → https:\/\/x-app\.example\.com · Direct request/);
  assert.doesNotMatch(html, /OkHttp → /, 'the app page already links to the API it called');
  // The client column sits left of the cards it points at.
  const left = (markup, attribute, id) => Number(markup.split(`${attribute}="${id}"`)[1]?.match(/left:(\d+)px/)?.[1]);
  assert.ok(left(html, 'data-service-client', 'client:browser:Chrome:macOS') < left(html, 'data-service-origin', app));
  assert.ok(left(html, 'data-service-origin', app) < left(html, 'data-service-origin', api));
  assert.equal(f.els.detailsSummary.textContent, 'Details', 'clients are not counted as origins');

  f.els.panel.dispatch('click', { target: { closest: () => ({ dataset: { serviceClient: 'client:browser:Chrome:macOS' } }) } });
  assert.equal(f.state.selectedClient, 'client:browser:Chrome:macOS');
  const selected = f.els.canvas.innerHTML;
  assert.equal((selected.match(/data-relationship="client_request"/g) || []).length, 1, 'Chrome went to the app page itself');
  assert.match(selected, /class="service-map-edge client-request kind-navigation[^"]*"[^>]*>[^]*?Chrome → https:\/\/x-app\.example\.com · Direct request/);
  for (const [attribute, id] of [['data-service-client', 'client:browser:Chrome:macOS'], ['data-service-origin', app], ['data-service-origin', api]])
    assert.equal(left(selected, attribute, id), left(html, attribute, id), 'selecting a client moves no card');
  assert.match(f.els.detail.innerHTML, /<h3>Chrome<\/h3><p>Browser · macOS · Versions 141, 140<\/p>[^]*?https:\/\/x-api\.example\.com<br>3 rows[^]*?https:\/\/x-app\.example\.com<br>2 rows · 1 direct/);
  assert.match(selected, />OkHttp<[^]*?2 rows</);
  f.els.panel.dispatch('click', { target: { closest: () => ({ dataset: { serviceClient: 'client:app:OkHttp:' } }) } });
  assert.match(f.els.canvas.innerHTML, /OkHttp → https:\/\/x-api\.example\.com · Direct request/, 'selected, a client points at every card it called');
  f.els.panel.dispatch('click', { target: { closest: () => ({ dataset: { serviceOrigin: api } }) } });
  assert.equal(f.state.selectedClient, null, 'inspecting an origin leaves the client');
  assert.doesNotMatch(f.els.canvas.innerHTML, /OkHttp → /);
  assert.match(f.els.canvas.innerHTML, /Chrome → https:\/\/x-app\.example\.com/);
});

test('the inspector folds away what no rule names, each with its source', async () => {
  const f = fixture();
  await f.load(snapshot([origin(api, { unnamed: {
    banners: [{ value: 'server: HeRay', row_count: 2, evidence: ['evidence-heray'] }],
    headers: [{ value: '<b>x-cdn-pop</b>', row_count: 1, evidence: ['evidence-pop'] }, { value: 'bad\u0001', row_count: 1, evidence: [] }],
  } })]));
  f.controller.selectOrigin(api);
  const detail = f.els.detail.innerHTML;
  assert.match(detail, /<details class="service-map-technologies service-map-unnamed"><summary[^>]*>Unnamed signals · 2<\/summary>/, 'a control character drops one');
  assert.match(detail, /data-service-relation-evidence="evidence-heray"[^>]*><span><code>server: HeRay<\/code> · 2 rows/);
  assert.match(detail, /<code>&lt;b&gt;x-cdn-pop&lt;\/b&gt;<\/code>/, 'escaped');
});

test('a client card names the address it connected from, and the inspector every one', async () => {
  const client = (name, addresses) => ({ kind: 'app', name, versions: [], request_count: 2, evidence: [], addresses,
    origins: [{ origin: api, request_count: 2, entry_kinds: { api: 2 } }] });
  const f = fixture();
  await f.load({ ...snapshot([origin(api)]), clients: [client('OkHttp', ['192.168.0.12', '<b>']), client('Alamofire', ['10.0.0.2', '10.0.0.3'])] });
  assert.deepEqual([...f.state.snapshot.clients[0].addresses], ['192.168.0.12'], 'only IP addresses are kept');
  const html = f.els.canvas.innerHTML;
  assert.match(html, />OkHttp<[^]*?192\.168\.0\.12 · 2 rows/);
  assert.match(html, />Alamofire<[^]*?2 addresses · 2 rows/);
  f.els.panel.dispatch('click', { target: { closest: () => ({ dataset: { serviceClient: 'client:app:Alamofire:' } }) } });
  assert.match(f.els.detail.innerHTML, /<h4>Connected from<\/h4><p><code>10\.0\.0\.2<\/code> <code>10\.0\.0\.3<\/code><\/p>/);
});

test('the client column sits level with the middle of the map, not above it', async () => {
  const chrome = { kind: 'browser', name: 'Chrome', versions: [141], os: 'macOS', request_count: 2, evidence: [],
    origins: [{ origin: app, request_count: 2, entry_kinds: { navigation: 2 } }] };
  const others = Array.from({ length: 8 }, (_, index) => `https://n${index}.example.com`);
  const f = fixture();
  await f.load({ ...snapshot([origin(app), ...others.map(id => origin(id))]), clients: [chrome] });
  const html = f.els.canvas.innerHTML;
  const top = (attribute, id) => Number(html.split(`${attribute}="${id}"`)[1]?.match(/top:(\d+)px/)?.[1]);
  const rows = [...new Set([app, ...others].map(id => top('data-service-origin', id)).filter(Number.isFinite))].sort((a, b) => a - b);
  assert.ok(rows.length >= 3, `${rows.length} rows to centre against`);
  assert.equal(top('data-service-client', 'client:browser:Chrome:macOS'), rows[Math.floor((rows.length - 1) / 2)]);
});

test("a card shows its origin's captured icon once the image has loaded, and keeps its mark otherwise", async () => {
  const images = [];
  const iconContext = vm.createContext({ URL, URLSearchParams, AbortController, console, setTimeout, getComputedStyle: element => ({ getPropertyValue: name => element.style.values[name] || '' }),
    ResizeObserver: class { observe() {} }, Image: class { constructor() { images.push(this); } } });
  vm.runInContext(source, iconContext);
  const uuid = (n) => `00000000-0000-0000-0000-00000000000${n}`;
  const token = (record) => `v1.${uuid(1)}.${uuid(2)}.7.${uuid(3)}.${uuid(record)}`;
  const f = fixture({}, iconContext.SniperServiceMap);
  await f.load(snapshot([origin(app, { favicon: token(4) }), origin(api, { favicon: token(5) }), origin(cdn, { favicon: 'v1.<img src=x>' })]));
  assert.equal(f.state.snapshot.origins.find(item => item.origin === cdn).favicon, undefined, 'a malformed token is dropped');
  assert.doesNotMatch(f.els.canvas.innerHTML, /service-map-favicon/, 'nothing shows before it loads');
  assert.deepEqual(images.map(image => image.src).sort(), [token(4), token(5)].map(id => `/api/target/service-map/favicon?session_id=${uuid(1)}&evidence_id=${encodeURIComponent(id)}`));
  images.find(image => image.src.endsWith(token(4))).onload();
  await new Promise(resolve => setTimeout(resolve, 0));
  const card = (id) => f.els.canvas.innerHTML.split(`data-service-origin="${id}"`)[1].split('</button>')[0];
  assert.match(card(app), /<img class="service-map-favicon" src="\/api\/target\/service-map\/favicon\?session_id=[^"]+&amp;evidence_id=v1\.[^"]+" alt="">/);
  assert.doesNotMatch(card(api), /service-map-favicon/, 'an icon that never loaded keeps the mark');
  f.controller.selectOrigin(api);
  assert.equal(images.length, 2, 'a redraw loads nothing again');
});

test('a card, the inspector and each endpoint name how requests authenticate', async () => {
  const rust = fs.readFileSync(path.join(__dirname, '../src/service_map_auth.rs'), 'utf8');
  const kinds = rust.slice(rust.indexOf('pub const KINDS'), rust.indexOf('];', rust.indexOf('pub const KINDS'))).match(/"([a-z0-9_]+)"/g).map(kind => kind.slice(1, -1));
  assert.deepEqual([...map.AUTH_KINDS], kinds, 'the same kinds, in the same order, as the server');
  const method = (kind, row_count, name) => ({ kind, row_count, evidence: [`evidence-${kind}`], ...(name ? { name } : {}) });
  const f = fixture();
  await f.load(snapshot([origin(api, {
    endpoints: [{ method: 'GET', path: '/v1/me', request_count: 3, statuses: [200], content_types: ['application/json'], evidence: ['evidence-me'], auth: ['bearer_jwt', 'session_cookie', 'nope'] },
      { method: 'GET', path: '/v1/public', request_count: 1, statuses: [200], content_types: ['application/json'], evidence: ['evidence-public'] }],
    auth: [method('oauth2', 9), method('bearer_jwt', 3), method('session_cookie', 2, 'JSESSIONID'), method('session_cookie', 1, 'bad name'), method('magic', 1)],
  })]));
  const normalized = f.state.snapshot.origins[0];
  assert.deepEqual(normalized.auth.map(item => [item.kind, item.name]), [['oauth2', undefined], ['bearer_jwt', undefined], ['session_cookie', 'JSESSIONID']], 'unknown kinds and unsafe names are dropped');
  assert.deepEqual([...normalized.endpoints[0].auth], ['bearer_jwt', 'session_cookie']);
  const card = f.els.canvas.innerHTML.split(`data-service-origin="${api}"`)[1].split('</button>')[0];
  assert.match(card, /class="service-map-auth" aria-label="Authentication: OAuth 2\.0, Bearer JWT, Session cookie" data-more="OAuth 2\.0\nBearer JWT\nSession cookie \(JSESSIONID\)" title=""><svg[^]*?<\/svg>JWT \+2<\/span>/, 'a credential leads a sign-in flow');
  f.controller.selectOrigin(api);
  const detail = f.els.detail.innerHTML;
  assert.ok(detail.indexOf('<h4>Authentication</h4>') < detail.indexOf('service-map-api-list'), 'it leads the APIs tab');
  assert.match(detail, /<strong>Session cookie<\/strong> · <code>JSESSIONID<\/code><p class="service-map-muted">2 rows<\/p>[^]*?data-service-relation-evidence="evidence-session_cookie"/);
  assert.match(detail, /\/v1\/me<\/span><\/span><span class="service-map-api-auth" title="Bearer JWT, Session cookie"><svg[^]*?<\/svg>JWT · Cookie<\/span>/);
  assert.doesNotMatch(detail.split('/v1/public')[1].split('</button>')[0], /service-map-api-auth/, 'an endpoint whose rows named none has no tag');
});

test('every exposure the server can report has a short card label', () => {
  const rust = fs.readFileSync(path.join(__dirname, '../src/service_map_servers.rs'), 'utf8');
  const ids = [...rust.matchAll(/\(\s*"([a-z0-9_]+)",\s*"[^"]+",\s*EXPOSURE,?\s*\)/g)].map(match => match[1]);
  assert.ok(ids.length >= 30, `${ids.length} exposures found`);
  assert.deepEqual(ids.filter(id => !map.EXPOSURE_LABELS[id]), []);
  assert.ok(Object.values(map.EXPOSURE_LABELS).every(label => label.length <= 13), 'short enough to leave a product beside it');
});

test('a product chip carries its logo, and the card mark is the logo on its brand colour', async () => {
  const iconContext = vm.createContext({ URL, URLSearchParams, AbortController, console, getComputedStyle: element => ({ getPropertyValue: name => element.style.values[name] || '' }), ResizeObserver: class { observe() {} } });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/product-icons.js'), 'utf8'), iconContext);
  vm.runInContext(source, iconContext);
  const f = fixture({}, iconContext.SniperServiceMap);
  await f.load(snapshot([origin(app, {
    front_technologies: [{ product_id: 'next_js', name: 'Next.js', category: 'meta_framework', version: '14.2.3', source_origin: app, row_count: 1, evidence: ['evidence-next'] }],
    server_technologies: [{ product_id: 'apache_tomcat', name: 'Apache Tomcat', category: 'app_server', signals: ['header'], row_count: 1, evidence: ['evidence-tomcat'] }],
  }), origin(api, {
    server_technologies: [{ product_id: 'werkzeug', name: 'Werkzeug', category: 'app_server', signals: ['header'], row_count: 1, evidence: ['evidence-werkzeug'] }],
  })]));
  const card = (id) => f.els.canvas.innerHTML.split(`data-service-origin="${id}"`)[1].split('</button>')[0];
  assert.match(card(app), /<span class="service-map-mark" style="background:#000000" title="Next\.js"><svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#fff" d="M[^"]+"\/><\/svg><\/span>/, 'white on Next.js black');
  const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
  assert.match(css, /\.service-map-card-symbol svg \{[^}]*stroke: currentColor/, 'role icons are outlines');
  assert.match(css, /\.service-map-card-symbol \.service-map-mark svg \{[^}]*stroke: none/, 'a logo mark is not outlined in the accent colour');
  assert.match(card(app), /<svg class="service-map-product-icon" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M[^"]+"\/><\/svg>Next\.js 14\.2\.3</, 'black would vanish on the dark theme');
  assert.match(card(app), /<path fill="#F8DC75" d="[^"]+"\/><\/svg>Apache Tomcat</, "Tomcat's own yellow");
  assert.match(card(api), /<span title="[^"]*">Werkzeug<\/span>/, 'a product with no allowed logo keeps its bare name');
  assert.doesNotMatch(card(api), /service-map-mark/, 'and its card keeps the role icon');
});

test('server technologies show on the card after the backend, exposures first, and in the inspector', async () => {
  const server = (product_id, name, category, extra = {}) => ({ product_id, name, category, signals: ['body'], row_count: 1, evidence: [`evidence-${product_id}`], ...extra });
  const f = fixture();
  await f.load(snapshot([origin(api, { endpoints: [{ method: 'GET', path: '/v1', request_count: 1, statuses: [404], content_types: ['application/json'], evidence: ['evidence-api'] }],
    server_technologies: [
      server('java_stack_trace', 'Java stack trace', 'exposure'),
      server('cloudflare', 'Cloudflare', 'edge', { signals: ['header'] }),
      server('spring_boot', 'Spring Boot', 'backend'),
      server('apache_tomcat', 'Apache Tomcat', 'app_server', { version: '9.0.83' }),
      server('bad', '<b>', 'backend'),
      server('worse', 'Worse', 'kernel'),
      server('quiet', 'Quiet', 'backend', { signals: [] }),
    ] })]));
  const normalized = f.state.snapshot.origins[0].server_technologies;
  assert.deepEqual(normalized.map(item => item.product_id), ['java_stack_trace', 'cloudflare', 'spring_boot', 'apache_tomcat'], 'unsafe entries are dropped');
  const card = f.els.canvas.innerHTML;
  assert.match(card, /class="service-map-exposure" aria-label="Exposures: Java stack trace" data-more="Java stack trace" title="">⚠ Stack trace<\/span><span[^>]*>Spring Boot<\/span><span class="service-map-products-more"[^>]*data-more="Apache Tomcat 9\.0\.83\nCloudflare"[^>]*>\+2</,
    'the exposure leads with a short name and takes a product place; the app server and the edge wait behind +N');
  assert.match(card, /service-map-mark[^>]*>S</, "the backend's mark replaces the role icon");
  f.controller.selectOrigin(api);
  const detail = f.els.detail.innerHTML;
  assert.match(detail, /<h4>Exposures<\/h4>[^]*?Java stack trace[^]*?<h4>Server<\/h4>[^]*?Cloudflare<\/strong> <span class="service-map-muted">Edge<\/span><p class="service-map-muted">1 row · header/);
  assert.match(detail, /data-service-relation-origin="https:\/\/x-api\.example\.com" data-service-relation-evidence="evidence-spring_boot"/);
  assert.ok(map.reportedProducts(f.state.snapshot.origins[0]).every(product => product.id !== 'java_stack_trace'), 'an exposure is not a product');
});

test('an origin whose rows carried no typed response leaves the map until it is selected or searched for', async () => {
  const beacon = 'https://x-log.example.com';
  const untyped = origin(beacon, { endpoints: [{ method: 'POST', path: '/log', request_count: 3, statuses: [204], content_types: [], evidence: ['evidence-log'] }] });
  const f = fixture();
  await f.load(snapshot([origin(app), untyped]));
  const card = /data-service-origin="https:\/\/x-log\.example\.com"/;
  assert.doesNotMatch(f.els.canvas.innerHTML, card);
  assert.match(f.els.graphBounds.textContent, /1 \/ 1 matching origins · 1 with no typed response hidden/);
  f.els.search.value = 'x-log'; f.els.search.dispatch('input');
  assert.match(f.els.canvas.innerHTML, card, 'searched for, it shows');
  f.els.search.value = ''; f.els.search.dispatch('input');
  assert.doesNotMatch(f.els.canvas.innerHTML, card);
  f.controller.selectOrigin(beacon);
  assert.match(f.els.canvas.innerHTML, card, 'selected, it shows');
  assert.match(f.els.canvas.innerHTML, />Unknown</);
});
