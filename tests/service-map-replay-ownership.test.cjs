// Run the real Map controller, app bridge, record reader and Replay opener with
// deferred synthetic responses. No app bootstrap, network or saved workspace.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
const origin = 'https://api.example.com';
const first = '11111111-1111-4111-8111-111111111111';
const second = '22222222-2222-4222-8222-222222222222';
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const response = (value, status = 200) => ({ ok: status < 400, status, json: async () => value });
const record = (id = first) => ({ id, kind: 'http', method: 'GET', host: 'api.example.com', path: '/items', request: { headers: [] } });
const apiDocument = (id = first) => ({ openapi: '3.1.0', servers: [{ url: origin }], paths: {
  '/items': { get: { 'x-sniper-newest-transaction': id, responses: { 200: { description: 'OK' } } } },
} });
function node() {
  const handlers = new Map(), classes = new Set();
  return { value: '', disabled: false, dataset: {}, textContent: '', innerHTML: '', scrollTop: 0, scrollLeft: 0,
    classList: { add: name => classes.add(name), remove: name => classes.delete(name),
      toggle(name, on) { if (on) classes.add(name); else classes.delete(name); }, contains: name => classes.has(name) },
    getClientRects: () => classes.has('hidden') ? [] : [1], setAttribute() {},
    contains: () => true, querySelectorAll: () => [], querySelector: () => null,
    addEventListener(name, handler) { handlers.set(name, handler); },
    dispatch(name, event = {}) { return handlers.get(name)?.({ target: this, ...event }); } };
}
function fixture() {
  let session = 'session-one', nextTab = 0, saves = 0;
  const nodes = new Map(), requests = [], toasts = [], wsTabs = [], callbacks = {};
  const document = { activeElement: null, querySelectorAll: () => [], querySelector: () => null,
    getElementById(id) { if (!nodes.has(id)) nodes.set(id, node()); return nodes.get(id); } };
  const window = { document };
  const snapshot = generation => ({ schema_version: 1, session_id: session,
    snapshot: { generation, complete: true, stopped_by: [], limits: {}, considered_rows: 1, retained_rows: 1, included_rows: 1 },
    origins: [{ origin, request_count: 1, endpoints: [], technology_clues: [], redirects: [], header_links: [] }],
    unavailable: [], deferred: [], warnings: [] });
  const state = { activeTool: 'map', activeTargetView: 'service-map', replayTabs: [] };
  const els = Object.fromEntries(['dashboardShell', 'proxyShell', 'replayShell', 'toolsShell', 'fuzzerShell', 'sequenceShell', 'targetShell', 'mapShell', 'loggerShell', 'reconShell', 'footerMode'].map(name => [name, node()]));
  const context = loadFunctions(['initializeTargetWorkspace', 'setActiveTargetView', 'retireFindingActionProgress', 'invalidateFindingNavigation', 'setActiveTool', 'renderToolPanels',
    'loadTransactionRecordById', 'openTransactionRecordInReplay'], {
    window, document, URL, URLSearchParams, AbortController, state, els, mainTabs: [],
    workspaceStateGeneration: 1, compareLoadGeneration: 0, targetServiceMapController: null,
    currentSessionId: () => session, targetServiceMapEventStreamReady: () => true,
    serviceMapFilterQuery: () => ({}), serviceMapFilterSummary: () => null,
    sanitizeActiveTool: value => value, scheduleUiSettingsSave() {}, closeScannerSettings() {},
    renderFuzzer() {}, renderReplay() {}, getActiveModalAction: () => null, restoreModalFocus() {},
    transactionPath: (id, sessionId) => `/api/transactions/${id}?session_id=${sessionId}`,
    showToast: (...args) => toasts.push(args),
    isWebSocketUpgradeRecord: value => value.status === 101,
    authorityToTargetState: () => ({ host: 'api.example.com', port: 443 }), normalizePortValue: value => value,
    normalizedHeaders: value => value, createWsReplayTab: value => wsTabs.push(value),
    editableRequestFromRecord: value => value.request,
    createReplayTab: value => ({ id: `replay-${++nextTab}`, ...value }),
    isRequestPreviewTruncated: () => false, buildEditableRawRequest: () => 'GET /items HTTP/1.1\nHost: api.example.com\n\n',
    scheduleWorkspaceStateSave() { saves++; },
    fetch(url, options) { const read = { url, options, ...deferred() }; requests.push(read); return read.promise; },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/service-map.js'), 'utf8'), context);
  const createController = window.SniperServiceMap.createController;
  window.SniperServiceMap.createController = options => {
    callbacks.sendToReplay = options.sendToReplay;
    return createController(options);
  };
  context.initializeTargetWorkspace();
  const controller = context.targetServiceMapController;
  const panel = nodes.get('targetServiceMapPanel'), modal = nodes.get('serviceMapApiDocs');
  const click = (element, dataset) => element.dispatch('click', { target: { closest: () => ({ dataset }) } });
  return { context, state, controller, nodes, requests, toasts, wsTabs, callbacks,
    get saves() { return saves; }, setSession(value) { session = value; },
    async loadMap(generation = 'one') {
      const pending = controller.refresh(); requests.at(-1).resolve(response(snapshot(generation))); await pending;
    },
    click: dataset => click(modal, dataset), panelClick: dataset => click(panel, dataset),
    navigate(tool) { context.setActiveTool(tool); context.renderToolPanels(); },
    async open(id = first) {
      click(panel, { serviceApiDocs: origin });
      const read = requests.at(-1); assert.match(read.url, /\/service-map\/openapi\?/);
      read.resolve(response(apiDocument(id))); await tick();
    },
    send(id = first) {
      const before = requests.length; click(modal, { apiDocsReplay: id });
      assert.equal(requests.length, before + 1); assert.match(requests.at(-1).url, /\/transactions\//);
      return requests.at(-1);
    },
  };
}
function assertNoReplay(f) {
  assert.equal(f.state.replayTabs.length, 0); assert.equal(f.wsTabs.length, 0); assert.equal(f.saves, 0);
  assert.deepEqual(f.toasts, []);
}
const boundaries = [
  ['Fuzzer navigation', f => f.navigate('fuzzer')],
  ['tool away and back', f => { f.navigate('fuzzer'); f.navigate('map'); }],
  ['view away and back', f => { f.context.setActiveTargetView('apis', { refresh: false }); f.context.setActiveTargetView('service-map', { refresh: false }); }],
  ['newer document', f => f.open(second)],
  ['newer document then Close', async f => { await f.open(second); f.click({ apiDocsClose: '' }); }],
  ['newer Map action', f => f.panelClick({ serviceDetailTab: 'relationships' })],
  ['origin search', f => { const search = f.nodes.get('serviceMapSearch'); search.value = 'other'; search.dispatch('input'); }],
  ['product filter', f => f.controller.setProductFilter('clear')],
  ['endpoint filter', f => f.nodes.get('targetServiceMapPanel').dispatch('input', { target: { dataset: { serviceEndpointFilter: 'path' }, value: '/other' } })],
  ['relationship choice', f => f.controller.setRelationshipKind('link')],
  ['detail-tab keyboard', f => f.nodes.get('targetServiceMapPanel').dispatch('keydown', { key: 'End', preventDefault() {}, target: { closest: () => ({ dataset: { serviceDetailTab: 'apis' } }) } })],
  ['explicit Reload', f => f.controller.refresh({ force: true })],
  ['row filter', f => f.controller.filterChanged()],
  ['selection away and back', f => {
    f.controller.getState().snapshot = f.context.window.SniperServiceMap.normalizeSnapshot({ schema_version: 1, session_id: 'session-one',
      snapshot: { generation: 'one', complete: true, stopped_by: [], limits: {}, considered_rows: 2, retained_rows: 2, included_rows: 2 },
      origins: [origin, 'https://other.example.com'].map(value => ({ origin: value, request_count: 1, endpoints: [], technology_clues: [], redirects: [], header_links: [] })),
      unavailable: [], deferred: [], warnings: [] }, 'session-one');
    f.controller.selectOrigin('https://other.example.com'); f.controller.selectOrigin(origin);
  }],
  ['session changes before reset', f => f.setSession('session-two')],
  ['session ABA with reset', f => { f.setSession('session-two'); f.controller.reset(); f.setSession('session-one'); f.controller.reset(); }],
  ['workspace generation change', f => f.context.workspaceStateGeneration++],
  ['disconnect', f => f.controller.disconnect()],
  ['history invalidation', f => f.controller.invalidate()],
];
for (const [name, boundary] of boundaries) for (const stage of ['fetch', 'json']) for (const outcome of ['success', 'failure']) {
  test(`${name} fences late ${stage} ${outcome}`, async () => {
    const f = fixture(); await f.open(); const read = f.send(), json = deferred();
    if (stage === 'json') { read.resolve({ ok: true, json: () => json.promise }); await tick(); }
    // Some boundaries start unrelated retained-metadata reads; they need not
    // finish to abandon this Replay intent.
    const pending = boundary(f);
    if (name.startsWith('newer document')) await pending;
    const tool = f.state.activeTool;
    if (outcome === 'success') {
      if (stage === 'json') json.resolve(record()); else read.resolve(response(record()));
    } else {
      if (stage === 'json') json.reject(new Error('Synthetic invalid JSON')); else read.reject(new Error('Synthetic read failure'));
    }
    await tick(); assert.equal(f.state.activeTool, tool); assertNoReplay(f);
  });
}
for (const kind of ['http', 'websocket']) test(`same owner opens one ${kind} Replay after its intentional dialog close`, async () => {
  const f = fixture(); await f.open(); const read = f.send();
  assert.equal(f.controller.getState().apiDocs, null); assert.equal(f.state.activeTool, 'map');
  read.resolve(response({ ...record(), ...(kind === 'websocket' ? { status: 101 } : {}) })); await tick();
  assert.equal(f.state.activeTool, 'replay'); assert.equal(f.saves, 1);
  assert.equal(f.state.replayTabs.length, kind === 'http' ? 1 : 0); assert.equal(f.wsTabs.length, kind === 'websocket' ? 1 : 0);
  if (kind === 'http') assert.equal(f.state.replayTabs[0].sourceTransactionId, first);
  assert.deepEqual(f.toasts, []);
});
for (const outcome of ['success', 'failure']) test(`newer send wins when older read completes with ${outcome}`, async () => {
  const f = fixture(); await f.open(); const old = f.send(); await f.open(second); const latest = f.send(second);
  if (outcome === 'success') old.resolve(response(record())); else old.reject(new Error('Synthetic old failure'));
  await tick(); assertNoReplay(f);
  latest.resolve(response(record(second))); await tick();
  assert.equal(f.state.replayTabs.length, 1); assert.equal(f.state.replayTabs[0].sourceTransactionId, second);
  assert.equal(f.saves, 1); assert.deepEqual(f.toasts, []);
});
for (const failure of ['404', 'network', 'json', 'wrong row', 'tunnel']) test(`current ${failure} reports failure without creating Replay`, async () => {
  const f = fixture(); await f.open(); const read = f.send();
  if (failure === '404') read.resolve(response({}, 404));
  if (failure === 'network') read.reject(new Error('Synthetic read failure'));
  if (failure === 'json') read.resolve({ ok: true, json: async () => { throw new Error('Synthetic invalid JSON'); } });
  if (failure === 'wrong row') read.resolve(response(record(second)));
  if (failure === 'tunnel') read.resolve(response({ ...record(), kind: 'tunnel' }));
  await tick(); assert.equal(f.state.activeTool, 'map'); assert.equal(f.saves, 0); assert.equal(f.state.replayTabs.length, 0);
  assert.equal(f.toasts.length, 1); assert.equal(f.toasts[0][1], 'error');
});
for (const reason of ['Close', 'already sent', 'not in document', 'source session changed']) test(`${reason} cannot submit a stale document action`, async () => {
  const f = fixture(); await f.open();
  if (reason === 'Close') f.click({ apiDocsClose: '' });
  if (reason === 'already sent') f.send();
  if (reason === 'source session changed') f.setSession('session-two');
  const before = f.requests.length;
  f.click({ apiDocsReplay: reason === 'not in document' ? second : first });
  assert.equal(f.requests.length, before); assertNoReplay(f);
});
test('captured traffic and unchanged view redraw preserve the chosen document row', async () => {
  const f = fixture(); await f.open(); const read = f.send();
  f.controller.markDirty({ data: JSON.stringify({ id: second }) }); f.context.renderToolPanels();
  read.resolve(response(record())); await tick();
  assert.equal(f.state.replayTabs[0].sourceTransactionId, first); assert.equal(f.saves, 1);
});
for (const kind of ['http', 'websocket']) test(`existing ${kind} Replay opener return remains undefined`, () => {
  const f = fixture();
  assert.equal(f.context.openTransactionRecordInReplay({ ...record(), ...(kind === 'websocket' ? { status: 101 } : {}) }), undefined);
  assert.equal(f.saves, 1);
});

for (const generation of ['one', 'two']) test(`background ${generation === 'one' ? 'same' : 'changed'} snapshot preserves the pending explicit Replay row`, async () => {
  const f = fixture(); await f.loadMap(); await f.open(); const read = f.send();
  await f.loadMap(generation); read.resolve(response(record())); await tick();
  assert.equal(f.state.replayTabs[0].sourceTransactionId, first); assert.equal(f.saves, 1);
});
for (const stage of ['fetch', 'json']) for (const outcome of ['success', 'failure']) test(`document source session is fixed across delayed ${stage} ${outcome}`, async () => {
  const f = fixture(); f.panelClick({ serviceApiDocs: origin }); const read = f.requests.at(-1), json = deferred();
  if (stage === 'json') { read.resolve({ ok: true, json: () => json.promise }); await tick(); }
  f.setSession('session-two');
  if (outcome === 'success') {
    if (stage === 'json') json.resolve(apiDocument()); else read.resolve(response(apiDocument()));
  } else {
    if (stage === 'json') json.reject(new Error('Synthetic old JSON')); else read.reject(new Error('Synthetic old read'));
  }
  await tick(); assert.equal(f.controller.getState().apiDocs.document, null);
  assert.equal(f.controller.getState().apiDocs.error, '');
  const before = f.requests.length; f.click({ apiDocsReplay: first });
  assert.equal(f.requests.length, before); assertNoReplay(f);
});
for (const outcome of ['success', 'failure']) test(`newer completed send survives the old read's ${outcome}`, async () => {
  const f = fixture(); await f.open(); const old = f.send(); await f.open(second); const latest = f.send(second);
  latest.resolve(response(record(second))); await tick();
  if (outcome === 'success') old.resolve(response(record())); else old.reject(new Error('Synthetic old failure'));
  await tick(); assert.equal(f.state.replayTabs.length, 1); assert.equal(f.state.replayTabs[0].sourceTransactionId, second);
  assert.equal(f.saves, 1); assert.deepEqual(f.toasts, []);
});
test('bridge preserves its successful void result instead of interpreting the opener return as failure', async () => {
  const f = fixture(); const sending = f.callbacks.sendToReplay(first);
  f.requests.at(-1).resolve(response(record()));
  assert.equal(await sending, undefined); assert.equal(f.state.replayTabs.length, 1); assert.deepEqual(f.toasts, []);
});

function attachSettings(f) {
  const context = f.context;
  context.els.displaySettingsModal = node(); context.els.displaySettingsModal.classList.add('hidden');
  context.els.closeDisplaySettingsButton = { focus() {} }; context.els.openDisplaySettingsButton = node();
  Object.assign(context, { displaySettingsReturnFocus: null, displaySettingsPreviewActive: false,
    displaySettingsEditedControls: new Set(), hydrateDisplaySettingsForm() {}, applyDisplaySettingsState() {},
    renderShortcutReference() {}, selectSettingsTab() {}, isModalVisible: element => !element.classList.contains('hidden') });
  for (const name of ['openDisplaySettingsModal', 'closeDisplaySettingsModal']) {
    const match = appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, 'm'));
    assert.ok(match); vm.runInContext(match[0], context);
  }
  context.getActiveModalAction = () => context.isModalVisible(context.els.displaySettingsModal) ? { modal: context.els.displaySettingsModal } : null;
}
for (const close of [false, true]) for (const stage of ['fetch', 'json']) for (const outcome of ['success', 'failure']) {
  test(`new Settings ${close ? 'opened then closed' : 'kept open'} supersedes delayed ${stage} ${outcome}`, async () => {
    const f = fixture(); attachSettings(f); await f.open(); const read = f.send(), json = deferred();
    if (stage === 'json') { read.resolve({ ok: true, json: () => json.promise }); await tick(); }
    f.context.openDisplaySettingsModal();
    if (close) f.context.closeDisplaySettingsModal();
    if (outcome === 'success') {
      if (stage === 'json') json.resolve(record()); else read.resolve(response(record()));
    } else {
      if (stage === 'json') json.reject(new Error('Synthetic old JSON')); else read.reject(new Error('Synthetic old read'));
    }
    await tick(); assert.equal(f.state.activeTool, 'map'); assertNoReplay(f);
  });
}
