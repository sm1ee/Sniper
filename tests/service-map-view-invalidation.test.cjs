// Real controller lifetimes with synthetic retained snapshots and an inert DOM.
// No app bootstrap, target requests, or captured user traffic.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
const context = vm.createContext({ URL, URLSearchParams, AbortController, console });
vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/service-map.js'), 'utf8'), context);
const A = 'https://app.example.com', B = 'https://api.example.net';
const tick = () => new Promise(resolve => setImmediate(resolve));
const response = payload => ({ ok: true, json: async () => payload });
const endpoint = (path = '/search', method = 'GET') => ({ method, path, request_count: 2, statuses: [200], content_types: ['application/json'], evidence: [] });
const origin = (id, endpoints = [endpoint()]) => ({ origin: id, in_scope: true, request_count: 2, endpoints, technology_clues: [], redirects: [], header_links: [] });
const snapshot = (origins = [origin(A), origin(B)], generation = 'generation-one', session = 'session-one') => ({ schema_version: 1, session_id: session,
  snapshot: { generation, complete: true, stopped_by: [], considered_rows: 4, retained_rows: 4, included_rows: 4, excluded_rows: 0, omitted_rows: 0 }, origins });
const parameters = (value = 'current-value', extra = {}) => ({ schema_version: 1, session_id: 'session-one', available: true, origin: A, method: 'GET', path: '/search', rows: 1,
  parameters: [{ name: 'query', location: 'query', rows: 1, examples: [value] }], ...extra });
function node() {
  const handlers = new Map(), classes = new Set();
  return { value: '', dataset: {}, attributes: {}, innerHTML: '', textContent: '', scrollTop: 0, scrollLeft: 0, clientWidth: 800, clientHeight: 600,
    style: { setProperty() {} }, classList: { toggle(name, on) { on ? classes.add(name) : classes.delete(name); }, contains: name => classes.has(name) },
    addEventListener(name, handler) { handlers.set(name, handler); }, dispatch(name, event = {}) { return handlers.get(name)?.({ target: this, ...event }); },
    setAttribute(name, value) { this.attributes[name] = value; }, contains: () => true, querySelectorAll: () => [],
  };
}
function fixture() {
  let session = 'session-one', filter = {};
  const els = Object.fromEntries(['panel', 'status', 'refresh', 'search', 'scope', 'canvas', 'graphBounds', 'detail', 'content', 'catalog', 'viewport', 'allOrigins', 'directRelations', 'focusSelection', 'graphDiagnostics', 'siteControls'].map(name => [name, node()]));
  const requests = [], parameterRequests = [];
  const controller = context.SniperServiceMap.createController({ elements: els, getSessionId: () => session, getFilterQuery: () => filter,
    document: { activeElement: null, body: {}, querySelector: () => null }, request(url, options) {
      let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
      (url.startsWith('/api/target/service-map/parameters?') ? parameterRequests : requests).push({ url, options, resolve, reject });
      return promise;
    } });
  controller.setVisible(true);
  const f = { controller, els, requests, parameterRequests, state: controller.getState(), getSession: () => session, setSession(value) { session = value; }, setFilter(value) { filter = value; },
    click(dataset) { const target = { dataset, closest: () => target }; els.panel.dispatch('click', { target }); },
    async load(payload = snapshot()) { const pending = controller.refresh(); requests.at(-1).resolve(response(payload)); await pending; },
    async completeParameters(value = 'current-value', extra) { parameterRequests.at(-1).resolve(response(parameters(value, extra))); await tick(); },
  };
  return f;
}
// Parameters intentionally live in APIs; use the real tab callback and prove it is local.
function parametersHtml(f) {
  const count = f.requests.length, reads = f.parameterRequests.length, endpoint = f.state.endpointSelection;
  const aborts = f.parameterRequests.map(read => !!read.options?.signal?.aborted);
  f.click({ serviceDetailTab: 'apis' });
  assert.equal(f.requests.length, count); assert.equal(f.parameterRequests.length, reads);
  assert.equal(f.state.endpointSelection, endpoint);
  assert.deepEqual(f.parameterRequests.map(read => !!read.options?.signal?.aborted), aborts);
  return f.els.detail.innerHTML;
}
const cards = f => [...f.els.canvas.innerHTML.matchAll(/data-service-origin="([^"]+)"/g)].map(match => match[1]);
const bounds = f => `${f.els.graphBounds.textContent} ${f.els.graphDiagnostics.textContent}`;
async function open(f) { await f.load(); f.controller.selectOrigin(A, 0); }
function historyActions(f) {
  const noop = () => {};
  const globals = { currentSessionId: f.getSession,
    targetServiceMapController: { invalidate() { f.historyPending = f.controller.invalidate(); }, retentionChanged() { f.controller.retentionChanged(); } },
    state: { items: [], historyPaging: {}, _itemsVersion: 0 }, document: { querySelectorAll: () => [] }, els: {},
    pendingHistoryNoteRead: null, contextMenuTargetId: null, _pendingTransactionSummaries: [], _historyPagingGeneration: 0, _historyDetailGeneration: 0,
    clearHistoryBackfill: noop, cancelHistoryDetailLoading: noop, precomputeItemIndexes: noop, invalidateVisibleEntriesCache: noop,
    refreshHistoryPagingCursorFromItems: noop, renderHistory: noop, scheduleRefresh: noop,
  };
  return loadFunctions(['applyConfirmedHistoryRemoval', 'applyHistoryRetentionDeletedEvent', 'invalidateHistoryAfterEventGap'], globals);
}

for (const reason of ['delete', 'event gap']) test(`${reason} invalidation discards cached values and rereads the same surviving endpoint`, async () => {
  const f = fixture(); await open(f); await f.completeParameters('removed-value');
  const actions = historyActions(f);
  if (reason === 'delete') actions.applyConfirmedHistoryRemoval(['removed-row']);
  else if (reason === 'retention') actions.applyHistoryRetentionDeletedEvent({ data: JSON.stringify({ session_id: f.getSession(), generation: 'retained', event_sequence: 1, ids: ['removed-row'] }), lastEventId: '1' });
  else actions.invalidateHistoryAfterEventGap();
  assert.equal(f.state.parameters, null, 'discard values before the map response');
  assert.equal(f.state.parametersKey, null);
  f.requests.at(-1).resolve(response(snapshot())); await f.historyPending;
  assert.equal(f.parameterRequests.length, 2, 'same endpoint is read again without changing inspector');
  await f.completeParameters('surviving-value');
  assert.match(parametersHtml(f), /surviving-value/);
  assert.doesNotMatch(parametersHtml(f), /removed-value/);
});

function clearHistoryAction(f, { success = true, confirm = true, beforeResponse = () => {} } = {}) {
  const button = node();
  let pending;
  const start = appSource.indexOf('  document.getElementById("clearHistoryButton")?.addEventListener');
  const end = appSource.indexOf('\n  onClickWithProgress(document.getElementById("interceptInScopeToggle")', start);
  assert.ok(start > 0 && end > start, 'the real Clear callback is loaded without bootstrapping the app');
  const context = vm.createContext({ console: { error() {} }, state: {}, currentSessionId: f.getSession, workspaceStateGeneration: 0,
    document: { getElementById: () => button }, targetServiceMapController: f.controller,
    showConfirmDialog(_message, callback) { if (confirm) pending = callback(); }, withButtonProgress(_button, callback) { return callback(); },
    sessionWritePath: path => path, fetch: async () => { beforeResponse(); return { ok: success, json: async () => ({ removed: 2 }) }; },
    requireOkResponse: async result => { if (!result.ok) throw new Error('synthetic failure'); },
    clearHttpHistorySelectionPreview() {}, scheduleRefresh() {}, showToast() {},
  });
  vm.runInContext(appSource.slice(start, end), context);
  button.dispatch('click', { currentTarget: button });
  return pending;
}

test('confirmed Clear invalidates parameters immediately before its fresh map finishes', async () => {
  const f = fixture(); await open(f); await f.completeParameters('cleared-value');
  await clearHistoryAction(f);
  assert.equal(f.state.parameters, null); assert.equal(f.state.snapshot, null);
  assert.equal(f.requests.length, 2); assert.doesNotMatch(parametersHtml(f), /cleared-value/);
  f.requests.at(-1).resolve(response(snapshot([], 'generation-cleared'))); await tick();
  assert.equal(f.state.endpointSelection, null);
  await f.load(); f.controller.selectOrigin(A, 0); await f.completeParameters('new-capture');
  assert.match(parametersHtml(f), /new-capture/);
});

for (const outcome of ['cancelled', 'failed', 'old session']) test(`${outcome} Clear cannot discard current parameter state`, async () => {
  const f = fixture(); await open(f); await f.completeParameters(); const current = f.state.parameters;
  await clearHistoryAction(f, { confirm: outcome !== 'cancelled', success: outcome !== 'failed', beforeResponse() { if (outcome === 'old session') f.setSession('session-two'); } });
  assert.equal(f.state.parameters, current); assert.equal(f.requests.length, 1);
});

test('Reload immediately discards values and rereads the still-open endpoint after the map', async () => {
  const f = fixture(); await open(f); await f.completeParameters('before-reload');
  const pending = f.els.refresh.dispatch('click');
  assert.equal(f.state.parameters, null); assert.doesNotMatch(parametersHtml(f), /before-reload/);
  f.requests.at(-1).resolve(response(snapshot())); await pending;
  assert.equal(f.parameterRequests.length, 2); await f.completeParameters('after-reload');
  assert.match(parametersHtml(f), /after-reload/);
});

test('clear history snapshot discards completed values before the same endpoint can return', async () => {
  const f = fixture(); await open(f); await f.completeParameters('cleared-value');
  await f.load(snapshot([], 'generation-cleared'));
  assert.equal(f.state.parameters, null); assert.equal(f.state.parametersKey, null);
  await f.load(snapshot()); f.controller.selectOrigin(A, 0);
  assert.equal(f.parameterRequests.length, 2); await f.completeParameters('new-capture');
  assert.doesNotMatch(parametersHtml(f), /cleared-value/); assert.match(parametersHtml(f), /new-capture/);
});

test('reopening an endpoint reads its newest rows even without a map generation change', async () => {
  const f = fixture(); await open(f); await f.completeParameters('older-row');
  f.controller.selectOrigin(A); f.controller.selectOrigin(A, 0);
  assert.equal(f.parameterRequests.length, 2);
  await f.completeParameters('newest-row'); assert.match(parametersHtml(f), /newest-row/);
});

const boundaries = {
  'history invalidation': f => f.controller.invalidate(),
  Reload: f => f.controller.refresh({ force: true }),
  'Service Map filter': f => { f.setFilter({ search: 'fresh' }); return f.controller.filterChanged(); },
  'scope filter': f => f.els.scope.dispatch('click'),
  'scope rules': f => f.controller.scopeChanged({ scope_patterns: [] }, { scope_patterns: ['example.com'] }),
  disconnect: f => f.controller.disconnect(),
  'session reset': f => { f.setSession('session-two'); f.controller.reset(); },
  'endpoint closed': f => f.controller.selectOrigin(A),
  'another origin': f => f.controller.selectOrigin(B),
  'map hidden': f => f.controller.setVisible(false),
};
for (const [name, change] of Object.entries(boundaries)) test(`late parameter values cannot repopulate state after ${name}`, async () => {
  const f = fixture(); await open(f); const old = f.parameterRequests[0];
  change(f);
  assert.equal(f.state.parametersLoading, false);
  assert.equal(old.options.signal.aborted, true);
  old.resolve(response(parameters('obsolete-value'))); await tick();
  assert.equal(f.state.parameters, null); assert.equal(f.state.parametersKey, null);
  assert.equal(f.state.parametersLoading, false); assert.equal(f.state.parametersError, '');
  assert.doesNotMatch(parametersHtml(f), /obsolete-value/);
});

test('late parameter JSON and rejected reads cannot overwrite a newer successful read', async () => {
  for (const reject of [false, true]) {
    const f = fixture(); await open(f); const old = f.parameterRequests[0];
    let finish; const parsing = new Promise(resolve => { finish = resolve; });
    if (!reject) { old.resolve({ ok: true, json: () => parsing }); await tick(); }
    const pending = f.controller.invalidate(); f.requests.at(-1).resolve(response(snapshot())); await pending;
    await f.completeParameters('newer-value');
    if (reject) old.reject(new Error('obsolete failure')); else finish(parameters('obsolete-value'));
    await tick();
    assert.match(parametersHtml(f), /newer-value/); assert.doesNotMatch(parametersHtml(f), /obsolete-value/);
    assert.equal(f.state.parametersError, ''); assert.equal(f.state.parametersLoading, false);
  }
});

test('a clear or missing endpoint cancels a pending read even when map generation is unchanged', async () => {
  for (const origins of [[], [origin(A, [endpoint('/other')])]]) {
    const f = fixture(); await open(f); const old = f.parameterRequests[0];
    await f.load(snapshot(origins));
    old.resolve(response(parameters('removed-value'))); await tick();
    assert.equal(f.state.parameters, null); assert.equal(f.state.parametersKey, null); assert.equal(f.state.endpointSelection, null);
  }
});

test('new map generation rereads an open endpoint but an ordinary same-generation poll does not', async () => {
  const f = fixture(); await open(f); await f.completeParameters('old-generation');
  await f.load(); assert.equal(f.parameterRequests.length, 1);
  await f.load(snapshot(undefined, 'generation-two'));
  assert.equal(f.parameterRequests.length, 2); assert.equal(f.state.parameters, null);
  await f.completeParameters('new-generation'); assert.match(parametersHtml(f), /new-generation/);
});

test('repeated clicks, same-source polling and local presentation changes preserve a pending read', async () => {
  const f = fixture(); await open(f); const pending = f.parameterRequests[0];
  f.controller.selectOrigin(A, 0); await f.load();
  f.els.search.value = 'no-match'; f.els.search.dispatch('input');
  f.click({ serviceDetailTab: 'apis' }); f.click({ serviceDetailTab: 'evidence' });
  f.click({ serviceHide: A }); f.click({ serviceUnhide: A });
  f.controller.setZoom(1.2);
  assert.equal(f.parameterRequests.length, 1); assert.equal(pending.options.signal.aborted, false);
  await f.completeParameters(); assert.match(parametersHtml(f), /current-value/);
});

// Every captured row marks the map dirty. The open endpoint keeps its values
// and its pending read, or the panel would empty and reread each poll.
test('a captured row keeps an open endpoint\'s parameters and starts no reread', async () => {
  const f = fixture(); await open(f); await f.completeParameters();
  const pending = f.controller.refresh(); f.controller.markDirty();
  f.requests.at(-1).resolve(response(snapshot())); await pending;
  await f.load(); f.controller.markDirty(); await f.load();
  assert.equal(f.parameterRequests.length, 1); assert.match(parametersHtml(f), /current-value/);
});
test('a captured row leaves a pending parameter read running', async () => {
  const f = fixture(); await open(f); const pending = f.parameterRequests[0];
  f.controller.markDirty(); await f.load();
  assert.equal(pending.options.signal.aborted, false); assert.equal(f.parameterRequests.length, 1);
  await f.completeParameters(); assert.match(parametersHtml(f), /current-value/);
});

test('filter change while hidden still cancels old parameters without starting hidden reads', async () => {
  const f = fixture(); await open(f); f.controller.setVisible(false); const count = f.requests.length;
  f.setFilter({ search: 'new-filter' }); await f.controller.filterChanged();
  assert.equal(f.requests.length, count); assert.equal(f.state.parametersKey, null);
  f.parameterRequests[0].resolve(response(parameters('old-filter'))); await tick();
  f.controller.setVisible(true); await f.load(); assert.equal(f.parameterRequests.length, 2);
  await f.completeParameters('current-filter'); assert.doesNotMatch(parametersHtml(f), /old-filter/);
});

test('a map response received while hidden never starts a parameter read', async () => {
  const f = fixture(); await open(f);
  const pending = f.controller.refresh(); f.controller.setVisible(false);
  f.requests.at(-1).resolve(response(snapshot())); await pending;
  assert.equal(f.parameterRequests.length, 1); assert.equal(f.state.parametersKey, null);
  f.controller.setVisible(true); await f.load(); assert.equal(f.parameterRequests.length, 2);
});

test('hidden filter change rejects an earlier map response before it can restore the old projection', async () => {
  const f = fixture(); await open(f);
  const pending = f.controller.refresh(); f.controller.setVisible(false);
  f.setFilter({ search: 'different' }); await f.controller.filterChanged();
  f.requests.at(-1).resolve(response(snapshot())); await pending;
  assert.equal(f.state.snapshot, null); assert.equal(f.state.endpointIndex, null); assert.equal(f.parameterRequests.length, 1);
});

test('parameter response must match session and exact origin, method and path', async () => {
  for (const extra of [{ session_id: 'session-two' }, { origin: B }, { method: 'get' }, { path: '/Search' }]) {
    const f = fixture(); await open(f); await f.completeParameters('wrong-identity', extra);
    assert.equal(f.state.parameters, null); assert.equal(f.state.parametersError, 'Parameters unavailable.');
    assert.doesNotMatch(parametersHtml(f), /wrong-identity/);
  }
});

function relatedSnapshot(neighbors = [B]) {
  const app = origin(A); app.redirects = neighbors.map(target_origin => ({ target_origin, target_path: '/', relationship: 'redirect_instruction', evidence: [] }));
  return snapshot([app, ...neighbors.map(id => origin(id))]);
}
for (const hidden of [A, 'example.com']) test(`hiding pinned ${hidden === A ? 'origin' : 'site'} preserves inspector and mode while removing its card`, async () => {
  const f = fixture(); await f.load(relatedSnapshot()); f.controller.selectOrigin(A, 0);
  f.els.directRelations.dispatch('click'); await f.completeParameters();
  const inspected = f.state.parameters, identity = f.state.endpointSelection, reads = f.parameterRequests.length;
  f.click({ serviceHide: hidden });
  assert.deepEqual(cards(f), [B]); assert.equal(f.state.anchorOrigin, A); assert.equal(f.state.selectedOrigin, A);
  assert.equal(f.state.parameters, inspected); assert.equal(f.state.endpointSelection, identity);
  assert.equal(f.els.directRelations.attributes['aria-pressed'], 'true');
  assert.match(parametersHtml(f), /Show .*on map/); assert.match(bounds(f), /Pinned anchor is hidden/);
  assert.match(bounds(f), /1 \/ 1 known direct neighbors shown/);
  assert.doesNotMatch(f.els.canvas.innerHTML, /data-relationship=/);
  await f.load(relatedSnapshot()); assert.deepEqual(cards(f), [B], 'polling cannot unhide the pin');
  f.click({ serviceUnhide: hidden });
  assert.deepEqual(cards(f), [A, B]); assert.equal(f.state.anchorOrigin, A);
  assert.match(parametersHtml(f), /Hide from map/); assert.doesNotMatch(bounds(f), /Pinned anchor is hidden/);
  assert.equal(f.parameterRequests.length, reads);
});

test('hidden pin uses no card slot and the neighbor/card counts remain accurate', async () => {
  const f = fixture(), neighbors = Array.from({ length: 30 }, (_, i) => `https://peer${i}.example.net`);
  await f.load(relatedSnapshot(neighbors)); f.click({ serviceGroupSites: 'toggle' }); f.controller.selectOrigin(A); f.els.directRelations.dispatch('click');
  f.click({ serviceHide: A });
  assert.equal(cards(f).length, 24); assert.ok(!cards(f).includes(A));
  assert.match(bounds(f), /24 \/ 30 known direct neighbors shown/);
  assert.match(bounds(f), /6 omitted by 24-card cap/);
  f.click({ serviceUnhideAll: 'all' }); assert.equal(cards(f).length, 24); assert.ok(cards(f).includes(A));
  assert.match(bounds(f), /23 \/ 30 known direct neighbors shown/);
});

test('hiding an isolated pin renders a truthful empty state and Show restores the same selection', async () => {
  const f = fixture(); await f.load(relatedSnapshot([])); f.controller.selectOrigin(A); f.els.directRelations.dispatch('click');
  f.click({ serviceHide: A });
  assert.deepEqual(cards(f), []); assert.equal(f.state.anchorOrigin, A); assert.equal(f.state.selectedOrigin, A);
  assert.match(f.els.canvas.innerHTML, /No visible origins/);
  assert.match(bounds(f), /Pinned anchor is hidden/);
  assert.doesNotMatch(bounds(f), /fresh snapshot verifies|-[0-9]/);
  f.click({ serviceUnhide: A }); assert.deepEqual(cards(f), [A]); assert.equal(f.state.selectedOrigin, A);
});

for (const conflict of ['history_changed', 'session_changed', 'scope_changed']) {
  for (const complete of [false, true]) test(`${conflict} conflict clears ${complete ? 'completed' : 'pending'} parameters before a late response can revive them`, async () => {
    const f = fixture(); await open(f);
    if (complete) await f.completeParameters('obsolete-value');
    const pending = f.controller.refresh();
    f.requests.at(-1).resolve({ ok: false, status: 409, headers: { get: () => conflict } }); await pending;
    if (!complete) await f.completeParameters('obsolete-value');
    assert.equal(f.state.parameters, null); assert.equal(f.state.parametersKey, null); assert.equal(f.state.parametersLoading, false);
    assert.doesNotMatch(parametersHtml(f), /obsolete-value/); assert.equal(f.state.refreshPaused, true);
    const reads = f.requests.length; await f.controller.refresh(); assert.equal(f.requests.length, reads);
    const retry = f.els.refresh.dispatch('click'); f.requests.at(-1).resolve(response(snapshot())); await retry;
    assert.equal(f.parameterRequests.length, 2); await f.completeParameters('after-retry'); assert.match(parametersHtml(f), /after-retry/);
  });
}

for (const failure of [{ status: 429, tag: 'busy' }, { status: 500, tag: 'build_failed' }]) test(`${failure.tag} does not discard an independent pending parameter read`, async () => {
  const f = fixture(); await open(f); const parametersRequest = f.parameterRequests[0];
  const pending = f.controller.refresh();
  f.requests.at(-1).resolve({ ok: false, status: failure.status, headers: { get: () => failure.tag } }); await pending;
  assert.equal(parametersRequest.options.signal.aborted, false); assert.equal(f.state.parametersLoading, true);
  await f.completeParameters(); assert.match(parametersHtml(f), /current-value/);
  // Busy only means another read is still running; the next poll asks again.
  const pauses = failure.tag !== 'busy';
  assert.equal(f.state.stale, pauses); assert.equal(f.state.refreshPaused, pauses);
});
