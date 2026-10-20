// Backend-shaped synthetic OpenAPI documents and inert DOM only; no proxy or app bootstrap.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const context = vm.createContext({ URL, URLSearchParams, AbortController, console });
vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/service-map.js'), 'utf8'), context);
const origin = 'https://api.example.com';
const oldRow = '11111111-1111-4111-8111-111111111111';
const newestRow = '22222222-2222-4222-8222-222222222222';
const tick = () => new Promise(resolve => setImmediate(resolve));
const response = value => ({ ok: true, json: async () => value });
function deferred() {
  let resolve;
  const promise = new Promise(yes => { resolve = yes; });
  return { promise, resolve };
}
function node() {
  const handlers = new Map(), classes = new Set();
  return { value: '', disabled: false, dataset: {}, textContent: '', innerHTML: '', scrollTop: 0, scrollLeft: 0,
    classList: { toggle(name, on) { if (on) classes.add(name); else classes.delete(name); }, contains: name => classes.has(name) },
    setAttribute() {}, contains: () => true, querySelectorAll: () => [],
    addEventListener(name, handler) { handlers.set(name, handler); },
    dispatch(name, event = {}) { return handlers.get(name)?.({ target: this, ...event }); } };
}
function snapshot() {
  return { schema_version: 1, session_id: 'session-one',
    snapshot: { generation: 'generation-one', complete: true, stopped_by: [], limits: { records: 10000 }, considered_rows: 2, retained_rows: 2, included_rows: 2, excluded_rows: 0, omitted_rows: 0 },
    origins: [{ origin, in_scope: true, request_count: 2, endpoints: [{ method: 'GET', path: '/items/{number}', request_count: 2, statuses: [200], content_types: ['application/json'], evidence: [] }], technology_clues: [], redirects: [], header_links: [] }],
    unavailable: [], deferred: [], warnings: [] };
}
// path_template walks a BTreeSet: {hex}, {number}, then {uuid}. The union
// belongs to the path item's parameters, rather than the operation's query parameters.
const pairSchema = () => ({ anyOf: [{ type: 'integer' }, { type: 'string', format: 'uuid' }] });
const tripleSchema = () => ({ anyOf: [{ type: 'string', pattern: '^[0-9A-Fa-f]+$' }, { type: 'integer' }, { type: 'string', format: 'uuid' }] });
function apiDocument(schema = pairSchema(), { fields, row = newestRow } = {}) {
  const operation = {
    'x-sniper-requests': 2, 'x-sniper-newest-transaction': row,
    parameters: [{ name: 'page', in: 'query', schema: { type: 'integer' } }],
    responses: { 200: { description: 'OK', content: { 'application/json': {} } } },
  };
  if (fields) operation.requestBody = { content: { 'application/json': { schema: { type: 'object', properties: fields } } } };
  return { openapi: '3.1.0', info: { title: origin, version: 'observed', description: 'Synthetic retained observations; no captured value is included.' },
    servers: [{ url: origin }], paths: { '/items/{id}': {
      parameters: [{ name: 'id', in: 'path', required: true, schema }], get: operation,
    } } };
}
function freeze(value) {
  if (value && typeof value === 'object') {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}
function fixture() {
  const requests = [], copies = [], replays = [], opened = [];
  const els = Object.fromEntries(['panel', 'apiDocs', 'status', 'refresh', 'search', 'scope', 'canvas', 'graphBounds', 'detail', 'content', 'catalog', 'mapControls', 'allOrigins', 'directRelations', 'focusSelection', 'boundsDetails', 'graphDiagnostics', 'overlayStatus'].map(name => [name, node()]));
  const controller = context.SniperServiceMap.createController({ elements: els, getSessionId: () => 'session-one',
    document: { activeElement: null }, copyText: (text, label) => copies.push([text, label]), sendToReplay: id => replays.push(id), openUrl: url => opened.push(url),
    request(url, options) { const read = { url, options, ...deferred() }; requests.push(read); return read.promise; } });
  controller.setVisible(true);
  return { controller, els, requests, copies, replays, opened, state: controller.getState(),
    async load() {
      const pending = controller.refresh();
      requests.at(-1).resolve(response(snapshot())); await pending;
    } };
}
function openDocs(f) {
  const count = f.requests.length;
  f.els.panel.dispatch('click', { target: { closest: () => ({ dataset: { serviceApiDocs: origin } }) } });
  assert.equal(f.requests.length, count + 1);
  const read = f.requests.at(-1);
  const url = new URL(read.url, origin);
  assert.equal(url.pathname, '/api/target/service-map/openapi');
  assert.equal(url.searchParams.get('origin'), origin);
  assert.equal(read.options.redirect, 'error');
  return read;
}
function clickDocs(f, dataset) {
  f.els.apiDocs.dispatch('click', { target: { closest: () => ({ dataset }) } });
}
async function render(document) {
  const f = fixture(); await f.load();
  openDocs(f).resolve(response(document)); await tick();
  assert.equal(f.state.apiDocs.document, document);
  return f;
}
function typeCell(f, name) {
  const rows = [...f.els.apiDocs.innerHTML.matchAll(/<tr>(.*?)<\/tr>/gs)]
    .map(match => [...match[1].matchAll(/<td>(.*?)<\/td>/gs)].map(cell => cell[1]));
  const row = rows.find(cells => cells[0]?.startsWith(`<code>${name}</code>`));
  assert.ok(row, `Missing rendered schema row: ${name}`);
  return row.at(-1);
}
function assertCopy(f, document) {
  const reads = f.requests.length;
  clickDocs(f, { apiDocsCopy: '' });
  assert.deepEqual(f.copies.at(-1), [JSON.stringify(document, null, 2), 'Copied OpenAPI']);
  assert.equal(f.requests.length, reads, 'copy must use the loaded document without another read');
}

test('merged numeric and UUID path parameters render their backend anyOf in emitted order', async () => {
  const f = await render(apiDocument());
  assert.equal(typeCell(f, 'id'), 'integer | string · uuid');
  assert.equal(typeCell(f, 'page'), 'integer');
  assert.match(f.els.apiDocs.innerHTML, /<code>id<\/code> <span class="service-map-muted">required<\/span><\/td><td>path<\/td>/);
  assert.match(f.els.apiDocs.innerHTML, /<code title="\/items\/\{id\}">\/items\/\{id\}<\/code>/);
});

test('merged hex, numeric and UUID path parameters preserve all three emitted alternatives', async () => {
  const f = await render(apiDocument(tripleSchema()));
  assert.equal(typeCell(f, 'id'), 'string | integer | string · uuid');
});

test('ordinary scalar, format-only and unconstrained schema labels remain unchanged', async () => {
  const fields = Object.fromEntries(['integer', 'number', 'string', 'boolean', 'null', 'array', 'object'].map(type => [type, { type }]));
  Object.assign(fields, { uuid: { type: 'string', format: 'uuid' }, binary: { format: 'binary' }, unknown: {} });
  const f = await render(apiDocument(pairSchema(), { fields }));
  for (const type of ['integer', 'number', 'string', 'boolean', 'null', 'array', 'object']) assert.equal(typeCell(f, type), type);
  assert.equal(typeCell(f, 'uuid'), 'string · uuid');
  assert.equal(typeCell(f, 'binary'), 'binary');
  assert.equal(typeCell(f, 'unknown'), 'any');
});

test('backend JSON type arrays remain meaningful and share union labels with request parameters', async () => {
  const document = freeze(apiDocument({ type: ['integer', 'string'] }, {
    fields: {
      mixed: { type: ['integer', 'string'] },
      nullable: { type: ['null', 'string'] },
      formatted: { type: ['string', 'null', 'string'], format: 'uuid' },
      nestedTypes: { anyOf: [{ type: ['integer', 'string'] }, { type: 'integer' }, { type: ['string', 'null'] }] },
    },
  }));
  const f = await render(document);
  assert.equal(typeCell(f, 'id'), 'integer | string');
  assert.equal(typeCell(f, 'mixed'), 'integer | string');
  assert.equal(typeCell(f, 'nullable'), 'null | string');
  assert.equal(typeCell(f, 'formatted'), 'string · uuid | null · uuid');
  assert.equal(typeCell(f, 'nestedTypes'), 'integer | string | null');
  assertCopy(f, document);
});

test('malformed type-array entries remain unknown even when the schema has a format', async () => {
  const invalidTypes = ['string', null, {}, ['integer'], 0, false, ''];
  const f = await render(apiDocument({ type: invalidTypes }, {
    fields: { formattedTypes: { type: invalidTypes, format: 'uuid' }, emptyTypes: { type: [] } },
  }));
  assert.equal(typeCell(f, 'id'), 'string | any');
  assert.equal(typeCell(f, 'formattedTypes'), 'string · uuid | any');
  assert.equal(typeCell(f, 'emptyTypes'), 'any');
});

test('nested anyOf labels are flattened and deduplicated in first-observed order', async () => {
  const schema = { anyOf: [{ type: 'string', format: 'uuid' },
    { anyOf: [{ type: 'integer' }, { type: 'string', format: 'uuid' }, { anyOf: [{ type: 'string' }] }] },
    { type: 'integer' }] };
  const f = await render(apiDocument(schema, { fields: { nested: schema } }));
  assert.equal(typeCell(f, 'id'), 'string · uuid | integer | string');
  assert.equal(typeCell(f, 'nested'), 'string · uuid | integer | string');
});

test('explicit type and format labels keep precedence over anyOf alternatives', async () => {
  const f = await render(apiDocument({ type: 'string', format: 'uuid', anyOf: [{ type: 'integer' }] }, {
    fields: { formatted: { format: 'binary', anyOf: [{ type: 'boolean' }] } },
  }));
  assert.equal(typeCell(f, 'id'), 'string · uuid');
  assert.equal(typeCell(f, 'formatted'), 'binary');
});

test('malformed and empty schema values render as unknown without breaking the document', async () => {
  const schemas = [null, false, true, 42, 'integer', [], {}, { anyOf: [] }, { anyOf: {} }, { anyOf: 'string' },
    { type: {} }, { type: 42, format: false }, { type: '', format: '' }];
  const fields = Object.fromEntries(schemas.map((schema, index) => [`malformed${index}`, schema]));
  const f = await render(apiDocument(pairSchema(), { fields }));
  for (const name of Object.keys(fields)) assert.equal(typeCell(f, name), 'any', name);
  assert.equal(typeCell(f, 'id'), 'integer | string · uuid');
});

test('unknown union members remain visible alongside typed alternatives and are deduplicated', async () => {
  const schema = { anyOf: [{ type: 'integer' }, null, { anyOf: [] }, false, { type: 'string', format: 'uuid' }, {}] };
  const f = await render(apiDocument(schema));
  assert.equal(typeCell(f, 'id'), 'integer | any | string · uuid');
});

test('union types and formats are escaped as text in parameter and request-body tables', async () => {
  const schema = { anyOf: [{ type: '<img src=x onerror="boom()">', format: 'uuid<&\"\'' }, { type: 'integer' }] };
  const document = freeze(apiDocument(schema, { fields: { escaped: schema } }));
  const f = await render(document);
  const escaped = '&lt;img src=x onerror=&quot;boom()&quot;&gt; · uuid&lt;&amp;&quot;&#039; | integer';
  assert.equal(typeCell(f, 'id'), escaped);
  assert.equal(typeCell(f, 'escaped'), escaped);
  assert.doesNotMatch(f.els.apiDocs.innerHTML, /<img|<svg|<script/);
  assertCopy(f, document);
});

test('deep anyOf trees stop with an honest truncation marker and preserve later shallow alternatives', async () => {
  let deep = { type: 'never-reached' };
  for (let i = 0; i < 64; i++) deep = { anyOf: [deep] };
  const document = freeze(apiDocument({ anyOf: [{ type: 'integer' }, deep, { type: 'string', format: 'uuid' }] }));
  const f = await render(document);
  assert.equal(typeCell(f, 'id'), 'integer | … | string · uuid');
  assertCopy(f, document);
});

test('wide anyOf trees have bounded rendered labels and do not change copied JSON', async () => {
  const schema = { anyOf: Array.from({ length: 1000 }, (_, index) => ({ type: 'string', format: `variant-${index}` })) };
  const document = freeze(apiDocument(schema));
  const f = await render(document), label = typeCell(f, 'id');
  const labels = label.split(' | ');
  assert.equal(labels[0], 'string · variant-0');
  assert.equal(labels.at(-1), '…');
  assert.ok(labels.length <= 32, 'the node budget must also bound visible alternatives');
  assert.doesNotMatch(label, /variant-999/);
  assertCopy(f, document);
});

test('oversized type and format components are bounded independently without mutating the document', async () => {
  const document = freeze(apiDocument({ anyOf: [{ type: 't'.repeat(5000), format: 'f'.repeat(5000) }] }));
  const f = await render(document), label = typeCell(f, 'id');
  assert.match(label, /^t+… · f+…$/);
  assert.ok(label.length <= 163, 'each component must fit its 80-character display budget');
  assertCopy(f, document);
});

test('rendering union labels preserves exact Copy JSON, Swagger Editor copy and newest-row Replay', async () => {
  const document = freeze(apiDocument(tripleSchema(), { fields: { mixed: pairSchema() } }));
  const before = JSON.stringify(document, null, 2), f = await render(document);
  assert.equal(typeCell(f, 'id'), 'string | integer | string · uuid');
  assert.equal(typeCell(f, 'mixed'), 'integer | string · uuid');
  assertCopy(f, document);
  const reads = f.requests.length;
  clickDocs(f, { apiDocsEditor: '' });
  assert.deepEqual(f.copies.at(-1), [before, 'Copied OpenAPI; paste it into Swagger Editor']);
  assert.deepEqual(f.opened, ['https://editor.swagger.io/']);
  assert.equal(f.requests.length, reads);
  assert.equal(JSON.stringify(document, null, 2), before);
  const replay = f.els.apiDocs.innerHTML.match(/data-api-docs-replay="([^"]+)"/);
  assert.equal(replay?.[1], newestRow);
  clickDocs(f, { apiDocsReplay: replay[1] });
  assert.deepEqual(f.replays, [newestRow]);
  assert.equal(f.state.apiDocs, null);
  assert.equal(f.els.apiDocs.innerHTML, '');
});

for (const stage of ['loaded', 'fetch', 'json']) test(`a captured row preserves ${stage} union docs and their copy source`, async () => {
  const f = fixture(); await f.load();
  const document = apiDocument(), read = openDocs(f), json = deferred();
  if (stage === 'loaded') { read.resolve(response(document)); await tick(); }
  if (stage === 'json') { read.resolve({ ok: true, json: () => json.promise }); await tick(); }
  const requestId = f.state.apiDocsRequestId;
  f.controller.markDirty({ data: JSON.stringify({ id: oldRow }) });
  if (stage === 'fetch') read.resolve(response(document));
  if (stage === 'json') json.resolve(document);
  await tick();
  assert.equal(f.state.apiDocsRequestId, requestId);
  assert.equal(f.els.apiDocs.classList.contains('hidden'), false);
  assert.equal(typeCell(f, 'id'), 'integer | string · uuid');
  assertCopy(f, document);
});

test('closed union docs cannot be resurrected by late parsing or replace a newly opened document', async () => {
  const f = fixture(); await f.load();
  const json = deferred();
  openDocs(f).resolve({ ok: true, json: () => json.promise }); await tick();
  clickDocs(f, { apiDocsClose: '' });
  assert.equal(f.state.apiDocs, null);
  assert.equal(f.els.apiDocs.innerHTML, '');
  clickDocs(f, { apiDocsCopy: '' });
  assert.deepEqual(f.copies, []);
  const current = apiDocument(tripleSchema());
  openDocs(f).resolve(response(current)); await tick();
  const html = f.els.apiDocs.innerHTML;
  json.resolve(apiDocument(pairSchema(), { row: oldRow })); await tick();
  assert.equal(f.state.apiDocs.document, current);
  assert.equal(f.els.apiDocs.innerHTML, html);
  assert.equal(typeCell(f, 'id'), 'string | integer | string · uuid');
  assertCopy(f, current);
  assert.doesNotMatch(html, new RegExp(oldRow));
});
