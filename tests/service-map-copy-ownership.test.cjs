// Real Map controller and application clipboard callbacks, with inert DOM and
// deferred synthetic sinks only. No browser/native clipboard or network access.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = path.resolve(__dirname, '..');
const { loadFunctions } = require(path.join(source, 'tests/frontend-test-helpers.cjs'));
const origin = 'https://api.example.com';
const record = '11111111-1111-4111-8111-111111111111';
const tick = () => new Promise(resolve => setImmediate(resolve));
const response = value => ({ ok: true, status: 200, json: async () => value });
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function node() {
  const handlers = new Map(), classes = new Set();
  return { value: '', disabled: false, dataset: {}, textContent: '', innerHTML: '', scrollTop: 0, scrollLeft: 0,
    clientWidth: 800, clientHeight: 600, style: { setProperty() {} },
    classList: { add: name => classes.add(name), remove: name => classes.delete(name),
      toggle(name, on) { on ? classes.add(name) : classes.delete(name); }, contains: name => classes.has(name) },
    getClientRects: () => classes.has('hidden') ? [] : [1],
    setAttribute() {}, contains: () => true, querySelectorAll: () => [], querySelector: () => null,
    addEventListener(name, handler) { handlers.set(name, handler); }, removeEventListener(name) { handlers.delete(name); },
    dispatch(name, event = {}) { return handlers.get(name)?.({ target: this, ...event }); } };
}
function fixture({ modern = true } = {}) {
  let fallbackResult = true;
  let session = 'session-one', filter = {}, clipboard = '';
  const nodes = new Map(), requests = [], writes = [], fallback = [], toasts = [], opened = [], attached = new Set();
  const docEvents = new Map(), windowEvents = new Map();
  const events = handlers => ({ addEventListener(name, handler) { handlers.set(name, handler); }, removeEventListener(name) { handlers.delete(name); }, dispatch(name) { handlers.get(name)?.(); } });
  const document = { ...events(docEvents), hidden: false, activeElement: null, querySelectorAll: () => [], querySelector: () => null,
    getElementById(id) { if (!nodes.has(id)) nodes.set(id, node()); return nodes.get(id); },
    body: { appendChild(element) { attached.add(element); } },
    createElement(tag) {
      assert.equal(tag, 'textarea');
      return { value: '', style: {}, setAttribute() {}, select() {}, remove() { attached.delete(this); } };
    },
    execCommand(command) {
      assert.equal(command, 'copy'); assert.equal(attached.size, 1);
      const text = [...attached][0].value; fallback.push(text); if (fallbackResult) clipboard = text; return fallbackResult;
    },
  };
  const context = loadFunctions(['copyTextToClipboard', 'initializeTargetWorkspace', 'getActiveModalAction', 'isModalVisible'], {
    document, window: { ...events(windowEvents), document, open(...args) { opened.push(args); } },
    URL, URLSearchParams, AbortController,
    navigator: modern ? { clipboard: { writeText(text) { const write = { text, ...deferred() }; writes.push(write); return write.promise; } } } : {},
    currentSessionId: () => session, targetServiceMapEventStreamReady: () => true,
    serviceMapFilterQuery: () => filter, serviceMapFilterSummary: () => null,
    state: {}, els: {}, activeConfirmDialog: null, compareLoadGeneration: 0,
    scheduleUiSettingsSave() {}, setActiveTargetView() {}, restoreModalFocus() {},
    showToast: (...args) => toasts.push(args),
    fetch(url, options) { assert.match(url, /^\/api\//); const read = { url, options, ...deferred() }; requests.push(read); return read.promise; },
  });
  vm.runInContext(fs.readFileSync(path.join(source, 'web/service-map.js'), 'utf8'), context);
  context.initializeTargetWorkspace();
  const controller = context.targetServiceMapController;
  controller.setVisible(true);
  const click = (id, dataset) => nodes.get(id).dispatch('click', { target: { closest: () => ({ dataset }) } });
  const map = () => ({ schema_version: 1, session_id: session,
    snapshot: { generation: 'synthetic-generation', complete: true, stopped_by: [], considered_rows: 1, retained_rows: 1, included_rows: 1, excluded_rows: 0, omitted_rows: 0 },
    origins: [origin, 'https://other.example.com'].map(origin => ({ origin, in_scope: true, request_count: 1, endpoints: [], technology_clues: [], redirects: [], header_links: [] })) });
  const flow = (label, sourceOrigin = origin) => ({ schema_version: 1, session_id: session, origin: sourceOrigin, lanes: [sourceOrigin], considered_rows: 1, flow_rows: 1, complete: true,
    phases: [{ page: null, steps: [{ origin: sourceOrigin, method: 'GET', path: '/' + label, status: 200, request_kind: 'api', count: 1, record_id: record }] }] });
  return { controller, nodes, requests, writes, fallback, toasts, opened, attached,
    get clipboard() { return clipboard; },
    resolveWrite(index) { clipboard = writes[index].text; writes[index].resolve(); },
    setSession(value) { session = value; },
    setFilter(value) { filter = value; },
    setFallbackResult(value) { fallbackResult = value; },
    visibility(hidden) { document.hidden = hidden; document.dispatch('visibilitychange'); },
    page(name) { context.window.dispatch(name); },
    toggleKind() { click('serviceMapLinkKinds', { linkKind: 'api' }); },
    externalKinds(kinds) { context.state.serviceMapHiddenLinkKinds = kinds; controller.displayChanged(); },
    async changeFlowOrigin(next) { controller.selectOrigin(next); nodes.get('serviceMapFlow').dispatch('click'); requests.at(-1).resolve(response(flow('origin-change', next))); await tick(); },
    async loadFlow(label = 'old-flow') {
      // Restoration may already have a pending filter/scope read. Explicitly
      // own and await the new map instead of refresh() returning early as busy.
      const pending = controller.refresh({ force: true }); requests.at(-1).resolve(response(map())); await pending;
      controller.selectOrigin(origin);
      nodes.get('serviceMapFlow').dispatch('click');
      assert.match(requests.at(-1).url, /\/flow\?/);
      requests.at(-1).resolve(response(flow(label))); await tick();
      assert.ok(controller.getState().flow);
    },
    async revalidateFlow() {
      const pending = controller.refresh(); requests.at(-1).resolve(response(map())); await pending;
      assert.match(requests.at(-1).url, /\/flow\?/);
      requests.at(-1).resolve(response(flow('old-flow'))); await tick();
      assert.ok(controller.getState().flow);
    },
    copyFlow() { nodes.get('serviceMapFlowMermaid').dispatch('click'); },
    invalidateFilter() { filter = { status_classes: 'success' }; return controller.filterChanged(); },
    async finishFilter(read) {
      read.resolve(response(map())); await tick();
      if (/\/flow\?/.test(requests.at(-1).url)) { requests.at(-1).resolve(response(flow('new-flow'))); await tick(); }
    },
    async openDocs(label = 'new-openapi') {
      click('targetServiceMapPanel', { serviceApiDocs: origin });
      assert.match(requests.at(-1).url, /\/openapi\?/);
      requests.at(-1).resolve(response({ openapi: '3.1.0', info: { description: label }, servers: [{ url: origin }], paths: {} })); await tick();
    },
    copyDocs() { click('serviceMapApiDocs', { apiDocsCopy: '' }); },
    editDocs() { click('serviceMapApiDocs', { apiDocsEditor: '' }); },
    closeDocs() { click('serviceMapApiDocs', { apiDocsClose: '' }); },
  };
}

const flowLabel = 'Copied the flow as a Mermaid sequence diagram';
const boundaries = [
  ['hidden Map', f => f.controller.setVisible(false)],
  ['hidden and reentered Map', async f => { f.controller.setVisible(false); f.controller.setVisible(true); await f.loadFlow(); }],
  ['view away and back', async f => { f.controller.setVisible(true, 'apis'); f.controller.setVisible(true, 'service-map'); await f.loadFlow(); }],
  ['destroy', f => f.controller.destroy()],
  ['session changes before reset', f => f.setSession('session-two')],
  ['session ABA', async f => { f.setSession('session-two'); f.controller.reset(); f.setSession('session-one'); f.controller.reset(); await f.loadFlow(); }],
  ['filter change', f => { f.invalidateFilter(); }],
  ['filter ABA with identical new data', async f => { f.invalidateFilter(); f.setFilter({}); f.controller.filterChanged(); await f.loadFlow(); }],
  ['scope ABA', async f => { f.nodes.get('serviceMapScopeOnly').dispatch('click'); f.nodes.get('serviceMapScopeOnly').dispatch('click'); await f.loadFlow(); }],
  ['history deletion', f => { f.controller.invalidate(); }],
  ['retention', f => f.controller.retentionChanged()],
  ['disconnect', f => f.controller.disconnect()],
  ['explicit Reload', f => { f.controller.refresh({ force: true }); }],
  ['hidden document and return', async f => { f.visibility(true); f.visibility(false); await f.loadFlow(); }],
  ['pagehide and pageshow', async f => { f.page('pagehide'); f.page('pageshow'); await f.loadFlow(); }],
  ['hidden request-kind ABA', f => { f.toggleKind(); f.toggleKind(); }],
  ['external request-kind ABA', f => { f.externalKinds(['api']); f.externalKinds([]); }],
  ['Flow re-read with identical data', f => f.revalidateFlow()],
  ['Flow origin away and back', async f => { await f.changeFlowOrigin('https://other.example.com'); await f.changeFlowOrigin(origin); }],
];
for (const [name, boundary] of boundaries) for (const outcome of ['success', 'rejected']) {
  test(`Flow ${name} retires pending clipboard ${outcome}`, async () => {
    const f = fixture(); await f.loadFlow(); f.copyFlow();
    assert.equal(f.writes.length, 1);
    await boundary(f);
    if (outcome === 'success') f.resolveWrite(0);
    else f.writes[0].reject(new Error('Synthetic delayed clipboard denial'));
    await tick();
    assert.deepEqual(f.fallback, [], 'no JS fallback may run for a retired owner');
    assert.deepEqual(f.toasts, [], 'the OS write may settle, but stale feedback is suppressed');
    assert.equal(f.attached.size, 0); f.controller.destroy();
  });
}

for (const modern of [false, true]) for (const fallbackResult of [false, true]) {
  test(`current Flow fallback ${fallbackResult}, modern clipboard ${modern}`, async () => {
    const f = fixture({ modern }); await f.loadFlow(); f.setFallbackResult(fallbackResult); f.copyFlow();
    if (modern) f.writes[0].reject(new Error('Synthetic clipboard denial'));
    await tick();
    assert.equal(f.fallback.length, 1); assert.match(f.fallback[0], /old-flow/);
    assert.deepEqual(f.toasts, [fallbackResult ? [flowLabel] : ['Failed to copy', 'error']]);
    assert.equal(f.attached.size, 0); f.controller.destroy();
  });
}
for (const [name, unchanged] of [
  ['captured row', f => f.controller.markDirty({ data: JSON.stringify({ id: record }) })],
  ['background Map read starts', f => { f.controller.refresh(); }],
  ['unrelated inspector selection', f => f.controller.selectOrigin('https://other.example.com')],
  ['same display settings', f => f.controller.displayChanged()],
]) {
  test(`${name} preserves current Flow fallback before its object or binding changes`, async () => {
    const f = fixture(); await f.loadFlow(); f.copyFlow(); const flow = f.controller.getState().flow;
    unchanged(f); assert.equal(f.controller.getState().flow, flow);
    f.writes[0].reject(new Error('Synthetic clipboard denial')); await tick();
    assert.deepEqual(f.fallback, [f.writes[0].text]); assert.deepEqual(f.toasts, [[flowLabel]]);
    f.controller.destroy();
  });
}
test('invalid-before-click Flow remains a no-op', async () => {
  const f = fixture(); await f.loadFlow(); f.controller.setVisible(false); f.copyFlow();
  assert.equal(f.writes.length, 0); assert.deepEqual(f.fallback, []); assert.deepEqual(f.toasts, []);
  f.controller.destroy();
});

for (const newerType of ['Flow', 'OpenAPI']) for (const newerOutcome of ['modern success', 'fallback success', 'fallback failure']) for (const olderOutcome of ['success', 'rejected']) {
  test(`newer ${newerType} ${newerOutcome} owns feedback over older Flow ${olderOutcome}`, async () => {
    const f = fixture(); await f.loadFlow(); f.copyFlow();
    if (newerType === 'OpenAPI') { await f.openDocs(); f.copyDocs(); }
    else f.copyFlow();
    assert.equal(f.writes.length, 2);
    if (newerOutcome === 'modern success') f.resolveWrite(1);
    else {
      f.setFallbackResult(newerOutcome === 'fallback success');
      f.writes[1].reject(new Error('Synthetic newer write denial'));
    }
    await tick();
    const fallback = [...f.fallback], toasts = [...f.toasts], clipboard = f.clipboard;
    assert.deepEqual(toasts, [newerOutcome === 'fallback failure' ? ['Failed to copy', 'error'] : [newerType === 'Flow' ? flowLabel : 'Copied OpenAPI']]);
    if (olderOutcome === 'success') f.resolveWrite(0);
    else f.writes[0].reject(new Error('Synthetic older write denial'));
    await tick();
    assert.deepEqual(f.fallback, fallback, 'latest failed copy must not revive an older fallback');
    assert.deepEqual(f.toasts, toasts);
    if (olderOutcome === 'rejected') assert.equal(f.clipboard, clipboard, 'JS fallback cannot replace newer output');
    // No assertion about native clipboard ordering after an issued write succeeds.
    assert.equal(f.attached.size, 0); f.controller.destroy();
  });
}

for (const action of ['copyDocs', 'editDocs']) {
  test(`OpenAPI ${action} rejects a document from the previous session before dispatch`, async () => {
    const f = fixture(); await f.openDocs(); f.setSession('session-two'); f[action](); await tick();
    assert.equal(f.writes.length, 0); assert.deepEqual(f.fallback, []); assert.deepEqual(f.toasts, []); assert.deepEqual(f.opened, []);
    f.controller.destroy();
  });
}
for (const [name, bounce] of [
  ['page', f => { f.page('pagehide'); f.page('pageshow'); }],
  ['document', f => { f.visibility(true); f.visibility(false); }],
]) for (const outcome of ['success', 'rejected']) {
  test(`OpenAPI ${name} lifecycle bounce cannot revive pending copy ${outcome}`, async () => {
    const f = fixture(); await f.openDocs(); f.copyDocs(); bounce(f);
    if (outcome === 'success') f.resolveWrite(0);
    else f.writes[0].reject(new Error('Synthetic clipboard denial'));
    await tick();
    assert.deepEqual(f.fallback, []); assert.deepEqual(f.toasts, []); f.controller.destroy();
  });
}
test('unrelated Flow kind changes do not retire a current OpenAPI copy', async () => {
  const f = fixture(); await f.loadFlow(); await f.openDocs(); f.copyDocs(); f.toggleKind(); f.toggleKind();
  f.writes[0].reject(new Error('Synthetic clipboard denial')); await tick();
  assert.deepEqual(f.fallback, [f.writes[0].text]); assert.deepEqual(f.toasts, [['Copied OpenAPI']]); f.controller.destroy();
});

for (const newerOutcome of ['modern success', 'fallback failure']) for (const olderOutcome of ['success', 'rejected']) {
  test(`newer Flow callback ${newerOutcome} supersedes pending OpenAPI callback ${olderOutcome}`, async () => {
    const f = fixture(); await f.loadFlow(); await f.openDocs(); f.copyDocs();
    // Exercise both real dispatch callbacks against the same sink, without
    // claiming browser pointer reachability through a modal from this VM.
    f.copyFlow(); assert.equal(f.writes.length, 2);
    if (newerOutcome === 'modern success') f.resolveWrite(1);
    else { f.setFallbackResult(false); f.writes[1].reject(new Error('Synthetic newer denial')); }
    await tick();
    const fallback = [...f.fallback], toasts = [...f.toasts];
    if (olderOutcome === 'success') f.resolveWrite(0);
    else f.writes[0].reject(new Error('Synthetic older denial'));
    await tick();
    assert.deepEqual(f.fallback, fallback); assert.deepEqual(f.toasts, toasts);
    f.controller.destroy();
  });
}
test('unrelated Map read starts without retiring the current OpenAPI fallback', async () => {
  const f = fixture(); await f.loadFlow(); await f.openDocs(); f.copyDocs(); f.controller.refresh();
  f.writes[0].reject(new Error('Synthetic clipboard denial')); await tick();
  assert.deepEqual(f.fallback, [f.writes[0].text]); assert.deepEqual(f.toasts, [['Copied OpenAPI']]);
  f.controller.destroy();
});

