// Real Map controller, deterministic timers, synthetic retained metadata only.
// No application bootstrap, capture, real network, or shared runtime.
'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
const source = fs.readFileSync(path.join(__dirname, '../web/service-map.js'), 'utf8');
const A = 'https://app.example.com', B = 'https://api.example.com';
const tick = () => new Promise(resolve => setImmediate(resolve));
const response = payload => ({ ok: true, json: async () => payload });
const fail = (status = 500, tag = 'build_failed') => ({ ok: false, status, headers: { get: () => tag } });
function events() {
  const handlers = new Map();
  return { handlers,
    addEventListener(type, callback) { if (!handlers.has(type)) handlers.set(type, new Set()); handlers.get(type).add(callback); },
    removeEventListener(type, callback) { handlers.get(type)?.delete(callback); },
    dispatch(type, event = {}) { return [...handlers.get(type) || []].map(callback => callback({ target: this, ...event })); },
    listenerCount() { return [...handlers.values()].reduce((sum, set) => sum + set.size, 0); },
  };
}
function node() {
  const classes = new Set(); let html = '';
  return { ...events(), value: '', dataset: {}, attributes: {}, textContent: '', replacements: 0, styleWrites: 0,
    scrollTop: 0, scrollLeft: 0, clientWidth: 800, clientHeight: 600,
    get innerHTML() { return html; }, set innerHTML(value) { html = value; this.replacements++; },
    style: { setProperty() {} }, classList: { toggle(name, on) { on ? classes.add(name) : classes.delete(name); }, contains: name => classes.has(name) },
    setAttribute(name, value) { this.attributes[name] = value; }, contains: () => true, querySelectorAll: () => [], querySelector: () => null,
  };
}
function snapshot(id = 'snapshot-one', rows = 1, { session = 'session-one', complete = true, origins = [A], enriched = false } = {}) {
  return { schema_version: 1, session_id: session, snapshot: { id, generation: 'generation-one', retained_rows: rows, considered_rows: rows,
    included_rows: rows, excluded_rows: 0, omitted_rows: 0, complete, stopped_by: complete ? [] : ['origin_limit'] },
  origins: origins.map(origin => ({ origin, in_scope: true, request_count: rows, endpoints: [{ method: 'GET', path: '/items', request_count: rows,
    statuses: [200], content_types: ['application/json'], evidence: [] }], technology_clues: [], redirects: [], header_links: [],
    ...(enriched ? { front_technologies: [{ product_id: 'jquery', name: 'jQuery', category: 'library', version: '3.7.1', source_origin: origin, row_count: 1, evidence: [] }] } : {}) })) };
}
function fixture() {
  let now = 0, serial = 0, session = 'session-one', filter = {}, hiddenKinds = ['frame', 'script', 'static'], display = { groupSites: true, expandedSites: [], hidden: [] };
  const timers = new Map(), requests = [], root = events();
  const doc = { ...events(), hidden: false, activeElement: null, body: {}, querySelector: () => null };
  const els = Object.fromEntries(['panel', 'status', 'refresh', 'search', 'scope', 'canvas', 'graphBounds', 'detail', 'content', 'catalog', 'viewport', 'allOrigins', 'directRelations', 'focusSelection', 'graphDiagnostics', 'siteControls'].map(key => [key, node()]));
  els.canvas.style.setProperty = () => els.canvas.styleWrites++;
  const context = vm.createContext({ URL, URLSearchParams, AbortController, console, ...root,
    setTimeout(callback, ms) { const id = ++serial; timers.set(id, { callback, due: now + ms }); return id; },
    clearTimeout(id) { timers.delete(id); },
  });
  vm.runInContext(source, context);
  const options = { elements: els, document: doc, getSessionId: () => session, getFilterQuery: () => filter,
    getHiddenLinkKinds: () => hiddenKinds, getSiteDisplay: () => display,
    request(url, options) {
      let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
      const read = { url, options, resolve, reject }; requests.push(read); return promise;
    } };
  const controller = context.SniperServiceMap.createController(options);
  controller.setVisible(true);
  const maps = () => requests.filter(read => read.url.startsWith('/api/target/service-map?'));
  return { controller, state: controller.getState(), els, doc, context, timers, requests, maps,
    options, setSession(value) { session = value; }, setFilter(value) { filter = value; }, setKinds(value) { hiddenKinds = value; }, setDisplay(value) { display = value; },
    async advance(ms) {
      const end = now + ms;
      for (;;) {
        const entry = [...timers].filter(([, timer]) => timer.due <= end).sort((a, b) => a[1].due - b[1].due)[0];
        if (!entry) break;
        const [id, timer] = entry; timers.delete(id); now = timer.due; timer.callback(); await tick();
      }
      now = end; await tick();
    },
    async load(payload = snapshot()) { const pending = controller.refresh(); maps().at(-1).resolve(response(payload)); await pending; },
    async finish(payload = snapshot()) { maps().at(-1).resolve(response(payload)); await tick(); },
    visibility(hidden) { doc.hidden = hidden; doc.dispatch('visibilitychange'); },
    page(type) { context.dispatch(type); },
  };
}
const fresh = read => new URL(read.url, A).searchParams.get('fresh');
function dirty(f) { f.controller.markDirty({ data: JSON.stringify({ id: '11111111-1111-4111-8111-111111111111' }) }); }

test('automatic lifecycle starts one five-second timer and never overlaps a slow map read', async () => {
  const f = fixture();
  for (let i = 0; i < 30; i++) f.controller.setVisible(true);
  assert.equal(f.timers.size, 1);
  await f.advance(4999); assert.equal(f.maps().length, 0);
  await f.advance(1); assert.equal(f.maps().length, 1); assert.equal(fresh(f.maps()[0]), 'true');
  await f.advance(30000); assert.equal(f.maps().length, 1); assert.equal(f.timers.size, 0);
  await f.finish(); assert.equal(f.timers.size, 1);
  await f.advance(4999); assert.equal(f.maps().length, 1);
  await f.advance(1); assert.equal(f.maps().length, 2); assert.equal(fresh(f.maps()[1]), null);
  f.controller.destroy(); assert.equal(f.timers.size, 0);
});

test('capture events bypass stale cache cooldown without manual resets; events during a read coalesce', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(A, 0);
  const parameterRead = f.requests.at(-1); assert.match(parameterRead.url, /\/parameters\?/);
  f.els.viewport.scrollTop = 87; f.els.viewport.scrollLeft = 91; f.controller.setZoom(1.3);
  const zoom = f.state.zoomScale, left = f.els.viewport.scrollLeft, top = f.els.viewport.scrollTop;
  const eventDraws = f.els.canvas.styleWrites;
  dirty(f); assert.equal(f.els.canvas.styleWrites, eventDraws, 'a new capture does not lay out unchanged graph data');
  await f.advance(5000);
  assert.equal(f.maps().length, 2); assert.equal(fresh(f.maps().at(-1)), 'true');
  assert.equal(parameterRead.options.signal.aborted, false, 'background freshness must not act like Reload');
  for (let i = 0; i < 20; i++) dirty(f);
  await f.advance(20000); assert.equal(f.maps().length, 2);
  await f.finish(snapshot('snapshot-two', 2));
  assert.equal(f.state.snapshot.snapshot.retained_rows, 2); assert.equal(f.state.stale, true);
  assert.equal(f.state.selectedOrigin, A); assert.equal(f.state.endpointSelection.path, '/items');
  assert.equal(f.state.zoomScale, zoom); assert.equal(f.els.viewport.scrollLeft, left); assert.equal(f.els.viewport.scrollTop, top);
  await f.advance(5000); assert.equal(f.maps().length, 3); assert.equal(fresh(f.maps().at(-1)), 'true');
  await f.finish(snapshot('snapshot-three', 3)); assert.equal(f.state.stale, false);
  f.controller.destroy();
});

test('clean cached snapshots preserve DOM, selection, scroll and filters while clean polls continue enrichment', async () => {
  const f = fixture(); const payload = snapshot('cached', 5, { complete: false }); await f.load(payload);
  f.els.search.value = 'app'; f.els.search.dispatch('input');
  f.els.viewport.scrollLeft = 45; f.els.viewport.scrollTop = 67; f.els.catalog.scrollTop = 123;
  f.state.endpointMethod = 'GET'; f.state.endpointPath = 'items';
  const before = f.state.snapshot, draws = f.els.canvas.styleWrites, replacements = f.els.canvas.replacements;
  await f.advance(5000); assert.equal(fresh(f.maps().at(-1)), null); await f.finish(payload);
  assert.equal(f.state.snapshot, before); assert.equal(f.els.canvas.styleWrites, draws); assert.equal(f.els.canvas.replacements, replacements);
  assert.equal(f.state.query, 'app'); assert.equal(f.state.endpointMethod, 'GET'); assert.equal(f.state.endpointPath, 'items');
  assert.equal(f.els.viewport.scrollLeft, 45); assert.equal(f.els.viewport.scrollTop, 67); assert.equal(f.els.catalog.scrollTop, 123);
  assert.match(f.els.status.textContent, /Incomplete: origin_limit/);
  // Public projection completeness neither stops nor forces enrichment reads.
  await f.advance(5000); assert.equal(fresh(f.maps().at(-1)), null);
  await f.finish(snapshot('enriched', 5, { complete: true, enriched: true }));
  assert.equal(f.state.snapshot.origins[0].front_technologies[0].version, '3.7.1');
  await f.advance(5000); assert.equal(f.maps().length, 4); assert.equal(fresh(f.maps().at(-1)), null);
  f.controller.destroy();
});

for (const boundary of ['document', 'page', 'tool', 'view', 'destroy']) test(`${boundary} transition cancels old timer/read and prevents late publication`, async () => {
  const f = fixture(); await f.load(); await f.advance(5000); const old = f.maps().at(-1), previous = f.state.snapshot;
  if (boundary === 'document') f.visibility(true);
  if (boundary === 'page') f.page('pagehide');
  if (boundary === 'tool') f.controller.setVisible(false);
  if (boundary === 'view') f.controller.setVisible(true, 'apis');
  if (boundary === 'destroy') f.controller.destroy();
  assert.equal(old.options.signal.aborted, true);
  if (boundary !== 'view') assert.equal(f.timers.size, 0);
  old.resolve(response(snapshot('obsolete', 99))); await tick(); assert.equal(f.state.snapshot, previous);
  if (boundary === 'document') f.visibility(false);
  if (boundary === 'page') f.page('pageshow');
  if (boundary === 'tool') f.controller.setVisible(true);
  if (boundary === 'destroy') {
    const before = f.els.canvas.replacements;
    f.els.scope.dispatch('click'); f.els.search.dispatch('input'); f.controller.setVisible(true);
    assert.equal(f.els.canvas.replacements, before); assert.equal(f.doc.listenerCount(), 0); assert.equal(f.context.listenerCount(), 0);
    await f.advance(30000); assert.equal(f.maps().length, 2); return;
  }
  assert.equal(f.timers.size, 1); await f.advance(5000); assert.equal(f.maps().length, 3);
  await f.finish(snapshot('current', 2)); assert.equal(f.state.snapshot.snapshot.retained_rows, 2);
  f.controller.destroy();
});

test('replacing a destroyed controller on the same elements leaves only the new handlers/timer', async () => {
  const f = fixture(); await f.load(); f.controller.destroy();
  const next = f.context.SniperServiceMap.createController(f.options); next.setVisible(true);
  assert.equal(f.doc.listenerCount(), 1); assert.equal(f.context.listenerCount(), 2); assert.equal(f.timers.size, 1);
  f.els.scope.dispatch('click'); assert.equal(f.maps().length, 2); assert.equal(next.getState().scopeOnly, true); assert.equal(f.state.scopeOnly, false);
  next.destroy(); assert.equal(f.timers.size, 0); assert.equal(f.doc.listenerCount(), 0);
});

for (const boundary of ['session', 'filter', 'scope', 'manual']) test(`${boundary} changes fence late responses without duplicate scheduled work`, async () => {
  const f = fixture(); await f.load(); await f.advance(5000); const old = f.maps().at(-1);
  if (boundary === 'session') { f.setSession('session-two'); f.controller.reset(); await f.advance(5000); }
  if (boundary === 'filter') { f.setFilter({ search: 'changed' }); f.controller.filterChanged(); }
  if (boundary === 'scope') f.els.scope.dispatch('click');
  if (boundary === 'manual') f.els.refresh.dispatch('click');
  const current = f.maps().at(-1); assert.notEqual(current, old); assert.equal(old.options.signal.aborted, true);
  current.resolve(response(snapshot('current', 2, { session: boundary === 'session' ? 'session-two' : 'session-one' }))); await tick();
  const currentSnapshot = f.state.snapshot;
  old.resolve(response(snapshot('obsolete', 99))); await tick(); assert.equal(f.state.snapshot, currentSnapshot);
  assert.equal(f.timers.size, 1); await f.advance(4999); assert.equal(f.maps().length, 3);
  f.controller.destroy();
});

test('externally replaced filters reject a late response even without filterChanged', async () => {
  const f = fixture(); await f.load(); const previous = f.state.snapshot; await f.advance(5000);
  f.setFilter({ search: 'new-settings' }); await f.finish(snapshot('obsolete', 99)); assert.equal(f.state.snapshot, previous);
  assert.equal(f.state.loading, false); await f.advance(5000);
  assert.equal(new URL(f.maps().at(-1).url, A).searchParams.get('search'), 'new-settings');
  await f.finish(snapshot('new-settings', 2)); assert.equal(f.state.snapshot.snapshot.retained_rows, 2);
  f.controller.destroy();
});

test('same snapshot ID cannot hide changed metadata or loaded presentation settings', async () => {
  const f = fixture(); await f.load(snapshot('same'));
  await f.advance(5000); await f.finish(snapshot('same', 2)); assert.equal(f.state.snapshot.snapshot.retained_rows, 2);
  const previous = f.els.canvas.styleWrites;
  f.setKinds([]); f.setDisplay({ groupSites: false, hidden: [], expandedSites: [] });
  await f.advance(5000); await f.finish(snapshot('same', 2)); assert.ok(f.els.canvas.styleWrites > previous);
  f.controller.destroy();
});

test('SSE disconnect still checks fresh data, and strict reconnect/gap invalidation rejects the replaced read', async () => {
  const f = fixture(); await f.load(); await f.advance(5000); const old = f.maps().at(-1);
  f.controller.disconnect(); assert.equal(old.options.signal.aborted, true); assert.equal(f.state.stale, true);
  await f.advance(5000); assert.equal(fresh(f.maps().at(-1)), 'true'); await f.finish(snapshot('missed-event', 2));
  await f.advance(5000); const beforeGap = f.maps().at(-1); f.controller.invalidate();
  assert.equal(beforeGap.options.signal.aborted, true); assert.equal(f.state.snapshot, null);
  await f.finish(snapshot('after-gap', 3)); beforeGap.resolve(response(snapshot('obsolete', 99))); old.resolve(response(snapshot('obsolete', 99))); await tick();
  assert.equal(f.state.snapshot.snapshot.retained_rows, 3); assert.equal(f.timers.size, 1); f.controller.destroy();
});

test('failure pauses automatic work across visibility/events; explicit Reload recovers one timer', async () => {
  const f = fixture(); await f.load(); await f.advance(5000); f.maps().at(-1).resolve(fail()); await tick();
  assert.equal(f.state.refreshPaused, true); assert.equal(f.timers.size, 0);
  dirty(f); f.visibility(true); f.visibility(false); f.controller.disconnect();
  await f.advance(60000); assert.equal(f.maps().length, 2); assert.equal(f.timers.size, 0);
  f.els.refresh.dispatch('click'); await f.finish(snapshot('recovered', 2));
  assert.equal(f.state.refreshPaused, false); assert.equal(f.timers.size, 1);
  await f.advance(5000); assert.equal(f.maps().length, 4); f.controller.destroy();
});

test('busy answers retry at completion cadence and retain the bounded five-retry pause', async () => {
  const f = fixture(); await f.load();
  for (let i = 0; i < 6; i++) { await f.advance(5000); f.maps().at(-1).resolve(fail(429, 'busy')); await tick(); }
  assert.equal(f.maps().length, 7); assert.equal(f.state.refreshPaused, true); assert.equal(f.timers.size, 0);
  f.controller.destroy();
});

test('automatic retention bursts never abort/starve the running map and coalesce one fresh follow-up', async () => {
  const f = fixture(); await f.load(snapshot('initial', 10, { origins: [A, B] })); f.controller.selectOrigin(A, 0);
  const parameters = f.requests.at(-1); f.els.viewport.scrollLeft = 100; f.els.viewport.scrollTop = 70;
  await f.advance(5000); const running = f.maps().at(-1), eventDraws = f.els.canvas.styleWrites;
  for (let i = 0; i < 100; i++) { f.controller.retentionChanged(); dirty(f); }
  assert.equal(f.els.canvas.styleWrites, eventDraws, 'retention bursts do not rebuild unchanged graph layouts');
  assert.equal(running.options.signal.aborted, false); assert.equal(parameters.options.signal.aborted, true);
  assert.equal(f.state.selectedOrigin, A); assert.equal(f.state.endpointSelection.path, '/items');
  await f.advance(30000); assert.equal(f.maps().length, 2);
  await f.finish(snapshot('retained-window', 10, { origins: [A, B] }));
  assert.equal(f.state.snapshot.snapshot.id, 'retained-window'); assert.equal(f.state.stale, true);
  assert.equal(f.state.selectedOrigin, A); assert.equal(f.els.viewport.scrollLeft, 100); assert.equal(f.els.viewport.scrollTop, 70);
  for (let i = 0; i < 100; i++) f.controller.retentionChanged();
  await f.advance(5000); assert.equal(f.maps().length, 3); assert.equal(fresh(f.maps().at(-1)), 'true');
  await f.finish(snapshot('selected-removed', 10, { origins: [B] }));
  assert.equal(f.state.selectedOrigin, null); assert.equal(f.state.endpointSelection, null);
  assert.equal(f.state.stale, false); assert.equal(f.timers.size, 1); f.controller.destroy();
});

test('auxiliary poll no longer duplicates Map reads, and only automatic cleanup uses coalescing', async () => {
  let reads = 0;
  const app = loadFunctions(['pollAuxiliaryData'], { state: { activeTool: 'map' }, targetServiceMapController: { refresh() { reads++; } },
    isWebsocketHistoryVisible: () => false, shouldPollFindingsBadge: () => false, loadTargetSiteMap() { assert.fail('No legacy map read'); } });
  await app.pollAuxiliaryData(); assert.equal(reads, 0);
  const calls = [], noop = () => {};
  const actions = loadFunctions(['applyConfirmedHistoryRemoval'], { currentSessionId: () => 'session-one',
    targetServiceMapController: { retentionChanged() { calls.push('retention'); }, invalidate() { calls.push('strict'); } },
    state: { items: [], historyPaging: {}, _itemsVersion: 0 }, document: { querySelectorAll: () => [] }, els: {},
    pendingHistoryNoteRead: null, contextMenuTargetId: null, _pendingTransactionSummaries: [], _historyPagingGeneration: 0, _historyDetailGeneration: 0,
    clearHistoryBackfill: noop, cancelHistoryDetailLoading: noop, precomputeItemIndexes: noop, invalidateVisibleEntriesCache: noop,
    refreshHistoryPagingCursorFromItems: noop, renderHistory: noop, scheduleRefresh: noop });
  actions.applyConfirmedHistoryRemoval(['row'], 'session-one', 'automatic_cleanup'); actions.applyConfirmedHistoryRemoval(['row']);
  assert.deepEqual(calls, ['retention', 'strict']);
});


test('document hiding during delayed JSON parsing fences the response and clears busy status on return', async () => {
  const f = fixture(); await f.load(); await f.advance(5000); const old = f.maps().at(-1), previous = f.state.snapshot;
  let parse; old.resolve({ ok: true, json: () => new Promise(resolve => { parse = resolve; }) }); await tick();
  f.visibility(true); parse(snapshot('late-json', 99)); await tick(); assert.equal(f.state.snapshot, previous);
  f.visibility(false); assert.equal(f.els.refresh.disabled, false); assert.equal(f.timers.size, 1);
  await f.advance(5000); assert.equal(f.maps().length, 3); f.controller.destroy();
});
