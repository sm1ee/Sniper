// Actual controller and app callbacks, with only synthetic clipboard, fetch,
// DOM and external-page sinks. No app bootstrap or browser navigation.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
const origin = 'https://api.example.com';
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function node() {
  const handlers = new Map(), classes = new Set();
  return { value: '', disabled: false, dataset: {}, textContent: '', innerHTML: '', scrollTop: 0, scrollLeft: 0,
    classList: { toggle(name, on) { if (on) classes.add(name); else classes.delete(name); }, contains: name => classes.has(name) },
    getClientRects: () => classes.has('hidden') ? [] : [1],
    setAttribute() {}, contains: () => true, querySelectorAll: () => [], querySelector: () => null,
    addEventListener(name, handler) { handlers.set(name, handler); },
    dispatch(name, event = {}) { return handlers.get(name)?.({ target: this, ...event }); } };
}
function apiDocument(label, server = origin) {
  return { openapi: '3.1.0', info: { description: label }, servers: [{ url: server }], paths: {} };
}
const response = value => ({ ok: true, status: 200, json: async () => value });
function fixture({ modern = true, fallbackResult = true } = {}) {
  let session = 'session-one';
  const nodes = new Map(), requests = [], writes = [], fallback = [], toasts = [], opened = [], attached = new Set();
  const document = { activeElement: null, querySelectorAll: () => [],
    getElementById(id) { if (!nodes.has(id)) nodes.set(id, node()); return nodes.get(id); },
    body: { appendChild(element) { attached.add(element); } },
    createElement(tag) {
      assert.equal(tag, 'textarea');
      return { value: '', style: {}, setAttribute() {}, select() {}, remove() { attached.delete(this); } };
    },
    execCommand(command) { assert.equal(command, 'copy'); assert.equal(attached.size, 1); fallback.push([...attached][0].value); return fallbackResult; },
  };
  const window = { open(...args) { opened.push(args); return null; } };
  const context = loadFunctions(['copyTextToClipboard', 'initializeTargetWorkspace', 'getActiveModalAction', 'isModalVisible'], {
    document, window, URL, URLSearchParams, AbortController,
    navigator: modern ? { clipboard: { writeText(text) { const write = { text, ...deferred() }; writes.push(write); return write.promise; } } } : {},
    currentSessionId: () => session, targetServiceMapEventStreamReady: () => true,
    serviceMapFilterQuery: () => ({}), serviceMapFilterSummary: () => null,
    state: {}, els: {}, activeConfirmDialog: null, compareLoadGeneration: 0, scheduleUiSettingsSave() {}, setActiveTargetView() {},
    showToast: (...args) => toasts.push(args),
    fetch(url, options) { const read = { url, options, ...deferred() }; requests.push(read); return read.promise; },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/service-map.js'), 'utf8'), context);
  context.initializeTargetWorkspace();
  const controller = context.targetServiceMapController;
  controller.setVisible(true);
  const panel = nodes.get('targetServiceMapPanel'), modal = nodes.get('serviceMapApiDocs');
  return { controller, nodes, requests, writes, fallback, toasts, opened, attached, context,
    setSession(value) { session = value; },
    click(dataset) { modal.dispatch('click', { target: { closest: () => ({ dataset }) } }); },
    async open(label, server = origin) {
      panel.dispatch('click', { target: { closest: () => ({ dataset: { serviceApiDocs: server } }) } });
      requests.at(-1).resolve(response(apiDocument(label, server))); await tick();
    } };
}

test('a closed document cannot fall back over a newer document copy', async () => {
  const f = fixture();
  await f.open('old document'); f.click({ apiDocsCopy: '' });
  f.click({ apiDocsClose: '' });
  await f.open('new document'); f.click({ apiDocsCopy: '' });
  f.writes[1].resolve(); await tick();
  f.writes[0].reject(new Error('Synthetic delayed clipboard denial')); await tick();
  assert.deepEqual(f.fallback, [], 'the old copy must not write after its document was closed');
  assert.deepEqual(f.toasts, [['Copied OpenAPI']]);
  assert.equal(f.attached.size, 0);
});

test('a closed document does not announce late clipboard success', async () => {
  const f = fixture();
  await f.open('old document'); f.click({ apiDocsCopy: '' });
  f.click({ apiDocsClose: '' });
  f.writes[0].resolve(); await tick();
  assert.deepEqual(f.toasts, []);
});

const actions = [
  [{ apiDocsCopy: '' }, 'Copied OpenAPI'],
  [{ apiDocsEditor: '' }, 'Copied OpenAPI; paste it into Swagger Editor'],
];
const boundaries = [
  ['Close', f => f.click({ apiDocsClose: '' })],
  ['Escape', f => f.nodes.get('serviceMapApiDocs').dispatch('keydown', { key: 'Escape' })],
  ['row filter', f => f.controller.filterChanged()],
  ['history invalidation', f => f.controller.invalidate()],
  ['event disconnect', f => f.controller.disconnect()],
  ['hidden map', f => f.controller.setVisible(false)],
  ['view change', f => f.controller.setVisible(true, 'apis')],
  ['session reset', f => { f.setSession('session-two'); f.controller.reset(); }],
  ['session ABA', f => { f.setSession('session-two'); f.controller.reset(); f.setSession('session-one'); f.controller.reset(); }],
  ['session changes before reset', f => f.setSession('session-two')],
  ['another document', f => f.open('other document', 'https://other.example.com')],
];
for (const [action, label] of actions) for (const [name, boundary] of boundaries) for (const outcome of ['success', 'rejected']) {
  test(`${label}: ${name} fences late clipboard ${outcome}`, async () => {
    const f = fixture(); await f.open('old document'); f.click(action);
    assert.equal(f.writes.length, 1, 'start the browser write synchronously in the click');
    const opened = [...f.opened];
    boundary(f); await tick();
    if (outcome === 'success') f.writes[0].resolve();
    else f.writes[0].reject(new Error('Synthetic delayed denial'));
    await tick();
    assert.deepEqual(f.fallback, []);
    assert.deepEqual(f.toasts, []);
    assert.deepEqual(f.opened, opened, 'completion cannot reopen Swagger Editor');
    assert.equal(f.attached.size, 0);
  });
}

for (const [action, label] of actions) {
  test(`${label}: current modern success reports the exact copied document`, async () => {
    const f = fixture(); await f.open('current document'); f.click(action);
    assert.equal(f.writes[0].text, JSON.stringify(apiDocument('current document'), null, 2));
    assert.deepEqual(f.toasts, []);
    if (action.apiDocsEditor !== undefined) {
      assert.deepEqual(f.opened, [['https://editor.swagger.io/', '_blank', 'noopener,noreferrer']]);
    } else assert.deepEqual(f.opened, []);
    f.writes[0].resolve(); await tick();
    assert.deepEqual(f.toasts, [[label]]);
    assert.deepEqual(f.fallback, []);
  });
  for (const modern of [false, true]) for (const fallbackResult of [false, true]) {
    test(`${label}: current fallback ${fallbackResult ? 'success' : 'failure'}, modern API ${modern ? 'rejected' : 'absent'}`, async () => {
      const f = fixture({ modern, fallbackResult }); await f.open('current document'); f.click(action);
      if (modern) f.writes[0].reject(new Error('Synthetic denied clipboard'));
      await tick();
      assert.deepEqual(f.fallback, [JSON.stringify(apiDocument('current document'), null, 2)]);
      assert.deepEqual(f.toasts, [fallbackResult ? [label] : ['Failed to copy', 'error']]);
      assert.equal(f.attached.size, 0);
    });
  }
  for (const outcome of ['success', 'rejected']) {
    test(`${label}: captured rows preserve the pending copy after ${outcome}`, async () => {
      const f = fixture(); await f.open('current document'); f.click(action);
      const current = f.controller.getState().apiDocs;
      f.controller.markDirty({ data: JSON.stringify({ id: '11111111-1111-4111-8111-111111111111' }) });
      assert.equal(f.controller.getState().apiDocs, current);
      if (outcome === 'success') f.writes[0].resolve();
      else f.writes[0].reject(new Error('Synthetic denied clipboard'));
      await tick();
      assert.deepEqual(f.toasts, [[label]]);
      assert.equal(f.fallback.length, outcome === 'success' ? 0 : 1);
    });
  }
}
for (const [firstAction] of actions) for (const [nextAction, nextLabel] of actions) for (const outcome of ['success', 'rejected']) {
  test(`a newer same-document ${nextLabel} owns feedback after older ${Object.keys(firstAction)[0]} ${outcome}`, async () => {
    const f = fixture(); await f.open('current document'); f.click(firstAction); f.click(nextAction);
    assert.equal(f.writes.length, 2);
    f.writes[1].resolve(); await tick();
    if (outcome === 'success') f.writes[0].resolve();
    else f.writes[0].reject(new Error('Synthetic delayed denial'));
    await tick();
    assert.deepEqual(f.toasts, [[nextLabel]]);
    assert.deepEqual(f.fallback, []);
  });
}
test('an older rejected copy cannot fall back while the newer copy is still pending', async () => {
  const f = fixture(); await f.open('current document');
  f.click({ apiDocsEditor: '' }); f.click({ apiDocsCopy: '' });
  f.writes[0].reject(new Error('Synthetic delayed denial')); await tick();
  assert.deepEqual(f.fallback, []); assert.deepEqual(f.toasts, []);
  f.writes[1].resolve(); await tick();
  assert.deepEqual(f.toasts, [['Copied OpenAPI']]);
});
