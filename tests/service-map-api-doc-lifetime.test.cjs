// Synthetic retained metadata and inert DOM only; no app bootstrap or proxy.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const context = vm.createContext({ URL, URLSearchParams, AbortController, console });
vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/service-map.js'), 'utf8'), context);
const origin = 'https://api.example.com';
const oldRow = '11111111-1111-4111-8111-111111111111';
const newRow = '22222222-2222-4222-8222-222222222222';
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const response = (value, status = 200) => ({ ok: status < 400, status, json: async () => value });
function snapshot(session = 'session-one', generation = 'generation-one') {
  return { schema_version: 1, session_id: session,
    snapshot: { generation, complete: true, stopped_by: [], limits: { records: 10000 }, considered_rows: 1, retained_rows: 1, included_rows: 1, excluded_rows: 0, omitted_rows: 0 },
    origins: [{ origin, in_scope: true, request_count: 1, endpoints: [{ method: 'GET', path: '/items', request_count: 1, statuses: [200], content_types: ['application/json'], evidence: [] }], technology_clues: [], redirects: [], header_links: [] }],
    unavailable: [], deferred: [], warnings: [] };
}
function apiDocument(row = oldRow) {
  return { openapi: '3.1.0', info: { description: `Synthetic observation ${row}` }, servers: [{ url: origin }],
    paths: { '/items': { get: { 'x-sniper-requests': 1, 'x-sniper-newest-transaction': row, responses: { 200: { description: 'OK' } } } } } };
}
function node() {
  const handlers = new Map(), classes = new Set();
  return { value: '', disabled: false, dataset: {}, textContent: '', innerHTML: '', scrollTop: 0, scrollLeft: 0,
    classList: { toggle(name, on) { if (on) classes.add(name); else classes.delete(name); }, contains: name => classes.has(name) },
    setAttribute() {}, contains: () => true, querySelectorAll: () => [],
    addEventListener(name, handler) { handlers.set(name, handler); },
    dispatch(name, event = {}) { return handlers.get(name)?.({ target: this, ...event }); } };
}
function fixture() {
  let session = 'session-one';
  const requests = [], copies = [], replays = [], opened = [];
  const els = Object.fromEntries(['panel', 'apiDocs', 'status', 'refresh', 'search', 'scope', 'canvas', 'graphBounds', 'detail', 'content', 'catalog', 'mapControls', 'allOrigins', 'directRelations', 'focusSelection', 'boundsDetails', 'graphDiagnostics', 'overlayStatus'].map(name => [name, node()]));
  const controller = context.SniperServiceMap.createController({ elements: els, getSessionId: () => session,
    document: { activeElement: null }, copyText: (...args) => copies.push(args), sendToReplay: id => replays.push(id), openUrl: url => opened.push(url),
    request(url, options) { const read = { url, options, ...deferred() }; requests.push(read); return read.promise; } });
  controller.setVisible(true);
  return { controller, els, requests, copies, replays, opened, state: controller.getState(), setSession(value) { session = value; },
    async load(generation = 'generation-one') {
      const pending = controller.refresh();
      requests.at(-1).resolve(response(snapshot(session, generation))); await pending;
    },
    async finishBoundary(start) {
      for (const read of requests.slice(start)) {
        assert.match(read.url, /^\/api\/target\/service-map\?/);
        read.resolve(response(snapshot(session, 'generation-two')));
      }
      await tick();
    } };
}
function openDocs(f) {
  const before = f.requests.length;
  f.els.panel.dispatch('click', { target: { closest: () => ({ dataset: { serviceApiDocs: origin } }) } });
  assert.equal(f.requests.length, before + 1);
  const read = f.requests.at(-1);
  assert.match(read.url, /^\/api\/target\/service-map\/openapi\?/);
  assert.equal(read.options.redirect, 'error');
  return read;
}
function clickDocs(f, dataset) {
  f.els.apiDocs.dispatch('click', { target: { closest: () => ({ dataset }) } });
}
function assertClosed(f) {
  assert.equal(f.state.apiDocs, null);
  assert.equal(f.els.apiDocs.classList.contains('hidden'), true);
  assert.equal(f.els.apiDocs.innerHTML, '');
}
async function prepareDocs(f, stage) {
  const read = openDocs(f);
  if (stage === 'loaded') { read.resolve(response(apiDocument())); await tick(); return { complete() {} }; }
  if (stage === 'json') {
    const json = deferred();
    read.resolve({ ok: true, json: () => json.promise }); await tick();
    return { complete: () => json.resolve(apiDocument()), fail: () => json.reject(new Error('Old JSON failed')) };
  }
  return { complete: () => read.resolve(response(apiDocument())), fail: () => read.reject(new Error('Old fetch failed')) };
}
const boundaries = [
  ['history invalidation', f => f.controller.invalidate()],
  ['scope rules', f => f.controller.scopeChanged({ scope_patterns: [] }, { scope_patterns: ['example.com'] })],
  ['row filter', f => f.controller.filterChanged()],
  ['scope filter', f => f.els.scope.dispatch('click')],
  ['explicit Reload', f => f.els.refresh.dispatch('click')],
  ['event disconnect', f => f.controller.disconnect()],
  ['hidden map', f => f.controller.setVisible(false)],
  ['view change', f => f.controller.setVisible(true, 'apis')],
  ['Close', f => clickDocs(f, { apiDocsClose: '' })],
  ['Escape', f => f.els.apiDocs.dispatch('keydown', { key: 'Escape' })],
  ['session reset', f => { f.setSession('session-two'); f.controller.reset(); }],
  ['session ABA', f => { f.setSession('session-two'); f.controller.reset(); f.setSession('session-one'); f.controller.reset(); }],
];
for (const [name, change] of boundaries) {
  for (const stage of ['loaded', 'fetch', 'json']) test(`API docs close at ${name}, including ${stage} results, and reopen fresh`, async () => {
    const f = fixture(); await f.load(); const old = await prepareDocs(f, stage);
    const start = f.requests.length; change(f); assertClosed(f);
    await f.finishBoundary(start); old.complete(); await tick(); assertClosed(f);
    const reads = f.requests.length; clickDocs(f, { apiDocsCopy: '' });
    assert.deepEqual(f.copies, []); assert.equal(f.requests.length, reads);
    f.controller.setVisible(true, 'service-map'); await f.load('generation-two');
    openDocs(f).resolve(response(apiDocument(newRow))); await tick();
    assert.equal(f.state.apiDocs.document.paths['/items'].get['x-sniper-newest-transaction'], newRow);
    assert.match(f.els.apiDocs.innerHTML, new RegExp(newRow)); assert.doesNotMatch(f.els.apiDocs.innerHTML, new RegExp(oldRow));
    const beforeCopy = f.requests.length;
    clickDocs(f, { apiDocsCopy: '' });
    assert.deepEqual(f.copies, [[JSON.stringify(apiDocument(newRow), null, 2), 'Copied OpenAPI']]);
    assert.equal(f.requests.length, beforeCopy, 'copy uses the loaded document synchronously');
    clickDocs(f, { apiDocsReplay: newRow }); assert.deepEqual(f.replays, [newRow]); assertClosed(f);
  });
}
// Every captured row marks the map dirty; open docs and their pending read
// stay, or the dialog would close while traffic flows.
for (const event of [undefined, { data: JSON.stringify({ id: oldRow }) }]) for (const stage of ['loaded', 'fetch', 'json']) {
  test(`a captured row leaves ${stage} API docs open${event ? ' (identified)' : ''}`, async () => {
    const f = fixture(); await f.load(); const old = await prepareDocs(f, stage);
    const id = f.state.apiDocsRequestId;
    f.controller.markDirty(event); old.complete(); await tick();
    assert.equal(f.state.apiDocsRequestId, id);
    assert.equal(f.els.apiDocs.classList.contains('hidden'), false);
    assert.equal(f.state.apiDocs.document.paths['/items'].get['x-sniper-newest-transaction'], oldRow);
  });
}
for (const boundary of ['invalidate']) for (const stage of ['fetch', 'json']) {
  for (const outcome of ['success', 'error']) test(`old API-doc ${stage} ${outcome} cannot replace reopened docs after ${boundary}`, async () => {
    const f = fixture(); await f.load(); const old = await prepareDocs(f, stage);
    const start = f.requests.length; f.controller[boundary](); assertClosed(f); await f.finishBoundary(start);
    openDocs(f).resolve(response(apiDocument(newRow))); await tick();
    const current = f.state.apiDocs, html = f.els.apiDocs.innerHTML;
    if (outcome === 'error') old.fail(); else old.complete();
    await tick(); assert.equal(f.state.apiDocs, current); assert.equal(f.els.apiDocs.innerHTML, html);
  });
}
for (const stage of ['loaded', 'fetch', 'json']) test(`a changed polled generation closes ${stage} API docs`, async () => {
  const f = fixture(); await f.load(); const old = await prepareDocs(f, stage);
  await f.load('generation-two'); assertClosed(f); old.complete(); await tick(); assertClosed(f);
});
for (const stage of ['loaded', 'fetch', 'json']) test(`an unchanged background poll preserves ${stage} API docs`, async () => {
  const f = fixture(); await f.load(); const old = await prepareDocs(f, stage);
  const before = f.state.apiDocs, id = f.state.apiDocsRequestId;
  await f.load(); assert.equal(f.state.apiDocs, before); assert.equal(f.state.apiDocsRequestId, id);
  old.complete(); await tick(); assert.equal(f.state.apiDocs.document.paths['/items'].get['x-sniper-newest-transaction'], oldRow);
});
for (const reason of ['session_changed', 'scope_changed', 'history_changed']) for (const stage of ['loaded', 'fetch', 'json']) test(`a ${reason} map conflict closes ${stage} API docs`, async () => {
  const f = fixture(); await f.load(); const old = await prepareDocs(f, stage);
  const pending = f.controller.refresh();
  f.requests.at(-1).resolve({ ok: false, status: 409, headers: { get: () => reason }, json() { assert.fail('Do not parse a conflicting map response'); } });
  await pending;
  assertClosed(f); old.complete(); await tick(); assertClosed(f);
});
test('unchanged visibility and scope rules preserve the open document', async () => {
  const f = fixture(); await f.load(); await prepareDocs(f, 'loaded');
  const before = f.state.apiDocs, id = f.state.apiDocsRequestId;
  f.controller.setVisible(true);
  assert.equal(f.controller.scopeChanged({ scope_patterns: ['example.com'] }, { scope_patterns: ['example.com'] }), false);
  assert.equal(f.state.apiDocs, before); assert.equal(f.state.apiDocsRequestId, id);
});
test('closing API docs does not cancel an independent endpoint parameter read', async () => {
  const f = fixture(); await f.load(); f.controller.selectOrigin(origin, 0);
  const parameters = f.requests.at(-1); assert.match(parameters.url, /\/parameters\?/);
  const parameterRequestId = f.state.parametersRequestId;
  await prepareDocs(f, 'loaded'); clickDocs(f, { apiDocsClose: '' }); assertClosed(f);
  assert.equal(f.state.parametersRequestId, parameterRequestId);
  assert.notEqual(parameters.options.signal?.aborted, true);
  parameters.resolve(response({ schema_version: 1, session_id: 'session-one', origin, method: 'GET', path: '/items', available: true, rows: 1, parameters: [{ name: 'query', location: 'query', rows: 1, examples: ['synthetic'] }] }));
  await tick(); assert.equal(f.state.parameters.items[0].name, 'query');
});
// Swagger Editor cannot read this app's API, so the click copies the document
// to paste there, and sends nothing anywhere itself.
test('Open in Swagger Editor copies the loaded document and opens the editor', async () => {
  const f = fixture(); await f.load(); await prepareDocs(f, 'loaded');
  assert.match(f.els.apiDocs.innerHTML, /data-api-docs-editor/);
  const reads = f.requests.length;
  clickDocs(f, { apiDocsEditor: '' });
  assert.deepEqual(f.copies, [[JSON.stringify(apiDocument(), null, 2), 'Copied OpenAPI; paste it into Swagger Editor']]);
  assert.deepEqual(f.opened, ['https://editor.swagger.io/']);
  assert.equal(f.requests.length, reads);
});
test('Open in Swagger Editor waits for a loaded document', async () => {
  const f = fixture(); await f.load(); await prepareDocs(f, 'fetch');
  clickDocs(f, { apiDocsEditor: '' });
  assert.deepEqual(f.opened, []); assert.deepEqual(f.copies, []);
});
