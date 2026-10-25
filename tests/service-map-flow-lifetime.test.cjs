// Real Flow controller with inert DOM and deferred local metadata reads.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const context = vm.createContext({ URL, URLSearchParams, AbortController, console });
vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/service-map.js'), 'utf8'), context);
const origin = 'https://app.example.com', record = '11111111-1111-4111-8111-111111111111';
const tick = () => new Promise(resolve => setImmediate(resolve));
const response = value => ({ ok: true, json: async () => value });
const snapshot = () => ({ schema_version: 1, session_id: 'session-one',
  snapshot: { generation: 'generation-one', complete: true, stopped_by: [], considered_rows: 1, retained_rows: 1, included_rows: 1, excluded_rows: 0, omitted_rows: 0 },
  origins: [{ origin, in_scope: true, request_count: 1, endpoints: [], technology_clues: [], redirects: [], header_links: [] }] });
const payload = () => ({ schema_version: 1, session_id: 'session-one', origin, lanes: [origin], considered_rows: 1, flow_rows: 1, complete: true,
  phases: [{ page: null, steps: [{ origin, method: 'GET', path: '/config', status: 200, request_kind: 'api', count: 1, record_id: record }] }] });
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
  const els = Object.fromEntries(['panel', 'status', 'refresh', 'search', 'scope', 'canvas', 'graphBounds', 'detail', 'content', 'catalog', 'viewport', 'allOrigins', 'directRelations', 'flow', 'flowMermaid', 'linkKinds', 'focusSelection', 'graphDiagnostics'].map(name => [name, node()]));
  const requests = [], copied = [], opened = [];
  const controller = context.SniperServiceMap.createController({ elements: els, getSessionId: () => session, getFilterQuery: () => filter,
    document: { activeElement: null, body: {}, querySelector: () => null }, copyText: value => copied.push(value), openInHistory: value => opened.push(value),
    request(url, options) { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); requests.push({ url, options, resolve, reject }); return promise; } });
  controller.setVisible(true);
  return { controller, els, requests, copied, opened, state: controller.getState(), setSession(value) { session = value; }, setFilter(value) { filter = value; },
    async load() { const pending = controller.refresh(); requests.at(-1).resolve(response(snapshot())); await pending; controller.selectOrigin(origin); },
    async flow(complete = true) { els.flow.dispatch('click'); const request = requests.at(-1); if (complete) { request.resolve(response(payload())); await tick(); } return request; },
    clickRecord(id = record) { const target = { dataset: { serviceFlowRecord: id }, closest: selector => selector.includes('[data-service-flow-record]') ? target : null }; els.panel.dispatch('click', { target }); },
  };
}

const boundaries = [
  ['display filter', f => { f.setFilter({ status_classes: 'success' }); f.controller.filterChanged(); }],
  ['scope filter', f => f.els.scope.dispatch('click')],
  ['history deletion', f => f.controller.invalidate()],
  ['disconnect', f => f.controller.disconnect()],
  ['retention', f => f.controller.retentionChanged()],
  ['hidden map', f => f.controller.setVisible(false)],
  ['API view', f => f.controller.setVisible(true, 'apis')],
  ['destroyed controller', f => f.controller.destroy()],
];
for (const [name, invalidate] of boundaries) {
  test(`${name} clears the completed Flow and prevents copying or opening its removed rows`, async () => {
    const f = fixture(); await f.load(); await f.flow();
    assert.ok(f.state.flow);
    invalidate(f);
    assert.equal(f.state.flow, null);
    f.els.flowMermaid.dispatch('click'); f.clickRecord();
    assert.deepEqual(f.copied, []); assert.deepEqual(f.opened, []);
  });
  test(`${name} aborts and fences a late Flow response`, async () => {
    const f = fixture(); await f.load(); const old = await f.flow(false);
    invalidate(f);
    assert.equal(old.options.signal.aborted, true);
    old.resolve(response(payload())); await tick();
    assert.equal(f.state.flow, null);
    assert.equal(f.state.flowLoading, false);
  });
}

test('the new filter can read a fresh flow after an older response was discarded', async () => {
  const f = fixture(); await f.load(); const old = await f.flow(false);
  f.setFilter({ status_classes: 'success' });
  const refresh = f.controller.filterChanged(), nextMap = f.requests.at(-1);
  old.resolve(response(payload())); await tick();
  assert.equal(f.state.flow, null);
  nextMap.resolve(response(snapshot())); await refresh;
  const nextFlow = f.requests.at(-1);
  assert.match(nextFlow.url, /\/flow\?/); assert.match(nextFlow.url, /status_classes=success/);
  nextFlow.resolve(response(payload())); await tick();
  assert.ok(f.state.flow); f.els.flowMermaid.dispatch('click'); f.clickRecord();
  assert.equal(f.copied.length, 1); assert.deepEqual(f.opened, [record]);
});

test('returning to the Flow view restarts its canceled initial read', async () => {
  const f = fixture(); await f.load(); const old = await f.flow(false);
  f.controller.setVisible(false); f.controller.setVisible(true);
  const current = f.requests.at(-1);
  assert.notEqual(current, old); assert.match(current.url, /\/flow\?/);
  old.resolve(response(payload())); await tick(); assert.equal(f.state.flow, null);
  current.resolve(response(payload())); await tick(); assert.ok(f.state.flow);
});

test('Flow actions cannot use a prior session or a record outside the loaded diagram', async () => {
  const f = fixture(); await f.load(); await f.flow();
  f.clickRecord('22222222-2222-4222-8222-222222222222'); assert.deepEqual(f.opened, []);
  f.setSession('session-two'); f.els.flowMermaid.dispatch('click'); f.clickRecord();
  assert.deepEqual(f.copied, []); assert.deepEqual(f.opened, []);
});

test('a delayed response body cannot republish the Flow after its filter changed', async () => {
  const f = fixture(); await f.load(); const old = await f.flow(false);
  let resolveBody;
  old.resolve({ ok: true, json: () => new Promise(resolve => { resolveBody = resolve; }) }); await tick();
  f.setFilter({ status_classes: 'success' }); f.controller.filterChanged();
  resolveBody(payload()); await tick();
  assert.equal(f.state.flow, null); assert.equal(f.state.flowLoading, false);
});

test('same-context polling keeps the diagram stable but cannot export or open it until revalidated', async () => {
  const f = fixture(); await f.load(); await f.flow();
  const displayed = f.state.flow;
  const pending = f.controller.refresh();
  f.requests.at(-1).resolve(response(snapshot())); await pending;
  assert.equal(f.state.flow, displayed); assert.equal(f.state.flowLoading, true);
  f.els.flowMermaid.dispatch('click'); f.clickRecord();
  assert.deepEqual(f.copied, []); assert.deepEqual(f.opened, []);
  f.requests.at(-1).resolve(response(payload())); await tick();
  f.els.flowMermaid.dispatch('click'); f.clickRecord();
  assert.equal(f.copied.length, 1); assert.deepEqual(f.opened, [record]);
});

test('a response for a filter changed by another writer cannot leave Flow stuck loading', async () => {
  const f = fixture(); await f.load(); const old = await f.flow(false);
  f.setFilter({ status_classes: 'success' });
  old.resolve(response(payload())); await tick();
  assert.equal(f.state.flow, null); assert.equal(f.state.flowLoading, false);
});

for (const reason of ['session_changed', 'scope_changed', 'history_changed']) test(`${reason} map conflict fences an independent pending Flow`, async () => {
  const f = fixture(); await f.load(); const old = await f.flow(false);
  const pending = f.controller.refresh();
  f.requests.at(-1).resolve({ ok: false, status: 409, headers: { get: () => reason } }); await pending;
  assert.equal(old.options.signal.aborted, true);
  old.resolve(response(payload())); await tick();
  assert.equal(f.state.flow, null); assert.equal(f.state.flowLoading, false);
});

test('an origin outside the newest-row window keeps its coverage and does not blame request-kind toggles', async () => {
  const f = fixture(); await f.load(); const current = await f.flow(false);
  current.resolve(response({ ...payload(), phases: [], flow_rows: 0, considered_rows: 50000, complete: false, stopped_by: ['max_records'] })); await tick();
  assert.match(f.els.canvas.innerHTML, /No matching requests in this row window/);
  assert.doesNotMatch(f.els.canvas.innerHTML, /Turn more kinds on/);
  assert.match(f.els.graphBounds.textContent, /0 of the newest 50000 rows/);
  assert.match(f.els.graphBounds.textContent, /older rows left out/);
  f.els.flowMermaid.dispatch('click');
  assert.equal(f.copied.length, 1); assert.match(f.copied[0], /Partial flow/);
});

test('a flow whose returned requests are hidden points to the kind toggles and keeps coverage', async () => {
  const f = fixture(); await f.load(); const current = await f.flow(false);
  const value = payload(); value.phases[0].steps[0].request_kind = 'static';
  current.resolve(response(value)); await tick();
  assert.match(f.els.canvas.innerHTML, /Turn more kinds on under Requests/);
  assert.match(f.els.graphBounds.textContent, /1 of the newest 1 rows/);
});
