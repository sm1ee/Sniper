// Pure production-function fixtures. All requests and run responses stay in memory.
const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
const workflow = require('../web/fuzzer-workflow.js');
const plain = value => JSON.parse(JSON.stringify(value));
const deferred = () => { let resolve; const promise = new Promise(yes => { resolve = yes; }); return { promise, resolve }; };
const tick = () => new Promise(resolve => setImmediate(resolve));
const rawRequest = (port = ':8080', absolute = false) => `GET ${absolute ? `http://example.com${port}` : ''}/?q=§x§ HTTP/1.1\r\nHost: example.com${port}\r\n\r\n`;
const parserNames = ['parseFuzzerRequestTemplate', 'parseEditableRawRequest', 'splitRawHttpMessage',
  'editableRequestBodyLength', 'decodedBase64Length', 'parseReplayHttpVersionToken', 'normalizeReplayHttpVersion',
  'headerValue', 'headerNameEquals', 'normalizedHeaders', 'validateRawHttpBodyFraming', 'buildEditableRawRequest',
  'mergeHeaders', 'createDefaultEditableRequest', 'httpRequestAuthoritiesEquivalent', 'normalizeHttpRequestAuthority',
  'authorityToTargetState', 'stripIpv6Brackets', 'normalizePortValue', 'defaultHttpPortForScheme',
  'normalizeRepeaterTargetInput', 'normalizeFuzzerTargetOverride', 'normalizeFuzzerTargetAuthority',
  'fuzzerRequestAuthorityFromText', 'fuzzerAuthorityFromSavedValue', 'activeFuzzerTargetForRequest',
  'fuzzerTargetAuthorityFromRequestText', 'fuzzerTargetAuthorityFromEditableRequest', 'joinAuthority'];
const transportNames = ['fuzzerTransportState', 'renderFuzzerTransport', 'setFuzzerTransport',
  'fuzzerRequestTextForAction', 'fuzzerSetupNode', 'markFuzzerDraftChanged'];
function control() {
  const classes = new Set(), listeners = {};
  return { value: '', disabled: false, textContent: '', listeners,
    addEventListener(type, callback) { listeners[type] = callback; },
    classList: { toggle(name, on) { if (on) classes.add(name); else classes.delete(name); }, contains: name => classes.has(name) } };
}
function fixture(extraNames = []) {
  const state = { activeSession: { id: 'session-a' }, fuzzerBaseRequest: null, fuzzerTarget: null,
    fuzzerTargetRequestText: null, fuzzerRequestText: rawRequest(), fuzzerPayloadsText: 'one',
    fuzzerDraftVersion: 0, fuzzerRunToken: 3, fuzzerRunning: false };
  const nodes = { fuzzerTransportSelect: control(), fuzzerTransportHelp: control() };
  const els = { fuzzerPayloadsEditor: { value: 'one' } };
  let saves = 0, renders = 0;
  const c = loadFunctions([...parserNames, ...transportNames, ...extraNames], {
    state, els, workspaceLoaded: true, URL, URLSearchParams, TextEncoder, atob, SniperFuzzerWorkflow: workflow,
    document: { getElementById: id => nodes[id] || null }, getCMView: () => null,
    currentSessionId: () => state.activeSession.id,
    scheduleWorkspaceStateSave() { saves++; }, renderFuzzer() { renders++; c.renderFuzzerTransport(); },
    clearFuzzerAttackRecord() { state.fuzzerAttackRecord = null; state.fuzzerAttackRecordId = null; },
    hideFuzzerDetailPanel() {}, scheduleFuzzerSetupRender() {},
    normalizeFuzzerAttackRecord: value => value, fuzzerWorkspaceAttackRecordId: value => value.attack_record_id || null,
  });
  return { c, state, nodes, els, get saves() { return saves; }, get renders() { return renders; },
    model: () => workflow.preflight(c.parseFuzzerRequestTemplate(state.fuzzerRequestText), ['one'],
      { target: c.activeFuzzerTargetForRequest(state.fuzzerRequestText), attackType: 'sniper' }),
    override(target = { scheme: 'https', host: '127.0.0.1', port: '8443' }) {
      state.fuzzerTarget = target; state.fuzzerTargetRequestText = c.fuzzerTargetAuthorityFromRequestText(state.fuzzerRequestText);
      return target;
    } };
}

test('fresh origin-form defaults to HTTPS; selecting HTTP changes only the cloned base scheme', () => {
  const f = fixture(); f.c.renderFuzzerTransport();
  assert.equal(f.nodes.fuzzerTransportSelect.value, 'https'); assert.equal(f.nodes.fuzzerTransportSelect.disabled, false);
  const raw = f.state.fuzzerRequestText;
  assert.equal(f.c.setFuzzerTransport('http'), true);
  assert.equal(f.state.fuzzerBaseRequest.scheme, 'http'); assert.equal(f.state.fuzzerRequestText, raw);
  assert.equal(f.model().effectiveTarget, 'http://example.com:8080');
  assert.equal(f.state.fuzzerDraftVersion, 1); assert.equal(f.state.fuzzerRunToken, 3); assert.equal(f.saves, 1);
  assert.equal(f.c.setFuzzerTransport('http'), false); assert.equal(f.saves, 1);
});

test('imported HTTP origin-form is shown accurately and retains all other source fields', () => {
  const f = fixture(), base = { ...f.c.createDefaultEditableRequest(), scheme: 'http', host: 'example.com:8080', http_version: 'HTTP/1.1' };
  f.state.fuzzerBaseRequest = base; f.c.renderFuzzerTransport();
  assert.equal(f.nodes.fuzzerTransportSelect.value, 'http');
  f.c.setFuzzerTransport('https');
  assert.notEqual(f.state.fuzzerBaseRequest, base); assert.equal(base.scheme, 'http');
  assert.deepEqual(plain(f.state.fuzzerBaseRequest), { ...plain(base), scheme: 'https' });
});

for (const port of [':8080', ':443', ':80', '']) test(`origin-form ${port || 'absent'} port follows existing explicit/default semantics`, () => {
  const f = fixture(); f.state.fuzzerRequestText = rawRequest(port);
  f.c.setFuzzerTransport('http');
  assert.equal(f.state.fuzzerRequestText, rawRequest(port));
  assert.equal(f.model().effectiveTarget, `http://example.com${port || ':80'}`);
  f.c.setFuzzerTransport('https');
  assert.equal(f.model().effectiveTarget, `https://example.com${port || ':443'}`);
});

test('absolute-form without override shows its parsed scheme and a visible URL-edit route', () => {
  const f = fixture(); f.state.fuzzerRequestText = rawRequest(':8080', true); f.c.renderFuzzerTransport();
  assert.equal(f.nodes.fuzzerTransportSelect.value, 'http'); assert.equal(f.nodes.fuzzerTransportSelect.disabled, true);
  assert.match(f.nodes.fuzzerTransportHelp.textContent, /edit.*request URL/i);
  const before = JSON.stringify(f.state);
  assert.equal(f.c.setFuzzerTransport('https'), false); assert.equal(JSON.stringify(f.state), before); assert.equal(f.saves, 0);
});

for (const absolute of [false, true]) for (const port of ['8080', '443']) test(`active ${absolute ? 'absolute' : 'origin'} override preserves explicit port ${port} and request binding`, () => {
  const f = fixture(); f.state.fuzzerRequestText = rawRequest(':8080', absolute);
  const target = f.override({ scheme: 'https', host: '127.0.0.1', port });
  const binding = f.state.fuzzerTargetRequestText, raw = f.state.fuzzerRequestText, base = f.state.fuzzerBaseRequest;
  f.c.renderFuzzerTransport(); assert.equal(f.nodes.fuzzerTransportSelect.disabled, false);
  assert.equal(f.nodes.fuzzerTransportSelect.value, 'https');
  assert.equal(f.c.setFuzzerTransport('http'), true);
  assert.notEqual(f.state.fuzzerTarget, target); assert.equal(target.scheme, 'https');
  assert.deepEqual(plain(f.state.fuzzerTarget), { scheme: 'http', host: '127.0.0.1', port });
  assert.equal(f.state.fuzzerTargetRequestText, binding); assert.equal(f.state.fuzzerRequestText, raw);
  assert.equal(f.state.fuzzerBaseRequest, base); assert.equal(f.model().effectiveTarget, `http://127.0.0.1:${port}`);
});

test('materialized default override port is preserved; a scheme-only override keeps its absent port', () => {
  const f = fixture();
  f.override(f.c.normalizeFuzzerTargetOverride({ scheme: 'https', host: '127.0.0.1', port: '' }));
  assert.equal(f.state.fuzzerTarget.port, '443'); f.c.setFuzzerTransport('http');
  assert.equal(f.state.fuzzerTarget.port, '443'); assert.equal(f.model().effectiveTarget, 'http://127.0.0.1:443');
  f.state.fuzzerRequestText = rawRequest(''); f.override({ scheme: 'https', host: '', port: '' });
  f.c.setFuzzerTransport('http'); assert.equal(f.state.fuzzerTarget.port, '');
  assert.equal(f.model().effectiveTarget, 'http://example.com:80');
});

test('changing a draft scheme does not reactivate an old inactive target override', () => {
  const f = fixture();
  f.state.fuzzerTarget = { scheme: 'https', host: '127.0.0.1', port: '9443' };
  f.state.fuzzerTargetRequestText = 'http://example.com:8080';
  assert.equal(f.c.activeFuzzerTargetForRequest(f.state.fuzzerRequestText), null);
  f.c.setFuzzerTransport('http');
  assert.equal(f.state.fuzzerTarget, null); assert.equal(f.state.fuzzerTargetRequestText, null);
  assert.equal(f.model().effectiveTarget, 'http://example.com:8080');
});

test('an override for an old host is also retired rather than carried into a new transport choice', () => {
  const f = fixture(); f.override();
  f.state.fuzzerRequestText = f.state.fuzzerRequestText.replace('Host: example.com', 'Host: other.example.com');
  f.c.setFuzzerTransport('http');
  assert.equal(f.state.fuzzerTarget, null); assert.equal(f.state.fuzzerTargetRequestText, null);
  assert.equal(f.model().effectiveTarget, 'http://other.example.com:8080');
});

for (const condition of ['loading', 'empty', 'invalid', 'oversized', 'invalid-choice']) test(`${condition} guards both displayed transport and direct handler`, () => {
  const f = fixture();
  if (condition === 'loading') f.c.workspaceLoaded = false;
  if (condition === 'empty') f.state.fuzzerRequestText = '';
  if (condition === 'invalid') f.state.fuzzerRequestText = 'not a raw HTTP request';
  if (condition === 'oversized') f.state.fuzzerRequestText += 'a'.repeat(2 * 1024 * 1024);
  const before = JSON.stringify(f.state); f.c.renderFuzzerTransport();
  if (condition !== 'invalid-choice') assert.equal(f.nodes.fuzzerTransportSelect.disabled, true);
  assert.equal(f.c.setFuzzerTransport(condition === 'invalid-choice' ? 'ftp' : 'http'), false);
  assert.equal(JSON.stringify(f.state), before); assert.equal(f.saves, 0);
});

for (const override of [false, true]) test(`existing workspace round-trip restores ${override ? 'override' : 'base'} transport`, () => {
  const f = fixture(['snapshotFuzzerWorkspace', 'readFuzzerWorkspace', 'cloneEditableRequest']);
  if (override) f.override(); f.c.setFuzzerTransport('http');
  const snapshot = plain(f.c.snapshotFuzzerWorkspace(f.state));
  Object.assign(f.state, { fuzzerBaseRequest: null, fuzzerTarget: null, fuzzerTargetRequestText: null });
  Object.assign(f.state, f.c.readFuzzerWorkspace(snapshot)); f.c.renderFuzzerTransport();
  assert.equal(f.nodes.fuzzerTransportSelect.value, 'http');
  assert.deepEqual(plain(f.c.snapshotFuzzerWorkspace(f.state)), snapshot);
});

for (const payloads of ['', 'a'.repeat(65537)]) test(`actual setup render keeps valid request transport editable with ${payloads ? 'invalid' : 'missing'} payloads and no markers`, () => {
  const f = fixture(['renderFuzzerSetup', 'renderFuzzerPayloadImportStatus', 'fuzzerSetupPreflight',
    'fuzzerPayloadCount', 'splitFuzzerPayloadLines', 'replayHttpVersionFromText', 'escapeHtml']);
  for (const id of ['fuzzerPreflightSummary', 'fuzzerPreflightNotice', 'fuzzerTargetSummary', 'startFuzzerButton']) f.nodes[id] = control();
  f.c.renderFuzzerRemoveMarkerControl = () => {};
  f.state.fuzzerRequestText = rawRequest().replace('§x§', 'x'); f.state.fuzzerPayloadsText = payloads;
  f.c.renderFuzzerSetup();
  assert.equal(f.nodes.startFuzzerButton.disabled, true);
  assert.equal(f.nodes.fuzzerTransportSelect.disabled, false);
  assert.equal(f.c.setFuzzerTransport('http'), true); f.c.renderFuzzerSetup();
  assert.equal(f.nodes.fuzzerTransportSelect.value, 'http');
  assert.match(f.nodes.fuzzerTargetSummary.textContent, /^http:\/\/example.com:8080/);
});

test('handler rechecks a request changed to absolute-form since its last render', () => {
  const f = fixture(); f.c.renderFuzzerTransport(); assert.equal(f.nodes.fuzzerTransportSelect.disabled, false);
  f.state.fuzzerRequestText = rawRequest(':8080', true);
  assert.equal(f.c.setFuzzerTransport('https'), false);
  assert.equal(f.nodes.fuzzerTransportSelect.disabled, true); assert.equal(f.nodes.fuzzerTransportSelect.value, 'http');
  assert.equal(f.state.fuzzerBaseRequest, null); assert.equal(f.saves, 0);
});

for (const phase of ['pending-start', 'running', 'restored-running']) test(`${phase} transport edits apply to next draft without abandoning active ownership`, () => {
  const f = fixture(); f.state.fuzzerRunning = phase !== 'restored-running';
  if (phase !== 'pending-start') {
    f.state.fuzzerRunningAttackId = 'active-run'; f.state.fuzzerAttackRecord = { id: 'active-run', running: true };
    f.state.fuzzerAttackRecordId = 'active-run';
  }
  if (phase === 'restored-running') f.state.fuzzerRestoredRun = { id: 'active-run' };
  const token = f.state.fuzzerRunToken, running = f.state.fuzzerRunning, restored = f.state.fuzzerRestoredRun;
  f.c.renderFuzzerTransport(); assert.equal(f.nodes.fuzzerTransportSelect.disabled, false);
  assert.match(f.nodes.fuzzerTransportHelp.textContent, /next/i);
  f.c.setFuzzerTransport('http');
  assert.equal(f.state.fuzzerRunToken, token); assert.equal(f.state.fuzzerRunning, running);
  assert.equal(f.state.fuzzerRestoredRun, restored);
  if (phase !== 'pending-start') {
    assert.equal(f.state.fuzzerRunningAttackId, 'active-run'); assert.equal(f.state.fuzzerAttackRecord, null);
    assert.match(f.state.fuzzerNotice, /next run/);
  }
});

function startFixture() {
  const f = fixture(['runFuzzerAttack', 'isCurrentFuzzerRun', 'splitFuzzerPayloadLines', 'fuzzerPayloadCount',
    'fuzzerPayloadTextWithinLimits', 'replayHttpVersionFromText']);
  const flushed = deferred(), replied = deferred(), followed = deferred(), requests = [];
  Object.assign(f.c, { expectedActiveSessionIdForWrite: value => value,
    flushWorkspaceStateForReplayAction: () => flushed.promise,
    fetch: async (url, options) => { requests.push({ url, body: JSON.parse(options.body) }); return replied.promise; },
    setFuzzerAttackRecord(record) { f.state.fuzzerAttackRecord = record; f.state.fuzzerAttackRecordId = record?.id || null; },
    followFuzzerAttack: () => followed.promise, scheduleRefresh() {}, showToast() {},
    WorkspaceStateConflictError: class WorkspaceStateConflictError extends Error {}, console: { error() {} },
  });
  return Object.assign(f, { flushed, replied, followed, requests });
}

test('transport edit during pending workspace flush prevents the stale run POST', async () => {
  const f = startFixture(), job = f.c.runFuzzerAttack();
  f.c.setFuzzerTransport('http'); f.flushed.resolve(7); await job;
  assert.equal(f.requests.length, 0); assert.equal(f.state.fuzzerBaseRequest.scheme, 'http');
});

for (const editWhen of ['before response', 'while running']) for (const override of [false, true]) test(`${editWhen} ${override ? 'override' : 'base'} transport edit survives accepted run completion`, async () => {
  const f = startFixture(); if (override) f.override();
  const job = f.c.runFuzzerAttack(); f.flushed.resolve(7);
  await tick();
  assert.equal(f.requests[0].body.template.scheme, 'https');
  if (editWhen === 'before response') f.c.setFuzzerTransport('http');
  f.replied.resolve({ ok: true, json: async () => ({ id: 'run-a', running: true, results: [] }) });
  await tick();
  assert.equal(f.state.fuzzerRunningAttackId, 'run-a');
  if (editWhen === 'while running') f.c.setFuzzerTransport('http');
  assert.equal(f.state.fuzzerRunningAttackId, 'run-a');
  f.followed.resolve({ id: 'run-a', running: false, results: [] }); await job;
  assert.equal(override ? f.state.fuzzerTarget.scheme : f.state.fuzzerBaseRequest.scheme, 'http');
  assert.equal(f.state.fuzzerRequestText, rawRequest()); assert.equal(f.state.fuzzerRunningAttackId, null);
});

test('restored-run transport edit retains the real poll and Stop ownership until terminal status', async () => {
  const f = fixture(['followRestoredFuzzerAttack', 'followFuzzerAttack', 'stopFuzzerAttack', 'sessionQueryPath']);
  const timers = [], requests = [];
  Object.assign(f.c, { FUZZER_POLL_MS: 0, setTimeout: callback => timers.push(callback),
    requireOkResponse: async response => assert.equal(response.ok, true),
    fetch: (url, options) => { const pending = deferred(); requests.push({ url, options, ...pending }); return pending.promise; },
  });
  f.state.fuzzerAttackRecord = { id: 'restored-run', running: true, results: [] }; f.state.fuzzerAttackRecordId = 'restored-run';
  const follow = f.c.followRestoredFuzzerAttack(f.state.fuzzerAttackRecord, 'session-a', () => f.state.fuzzerAttackRecordId === 'restored-run');
  const token = f.state.fuzzerRunToken; f.c.setFuzzerTransport('http');
  assert.equal(f.state.fuzzerRunToken, token); assert.equal(f.state.fuzzerRunningAttackId, 'restored-run');
  timers.shift()(); await tick();
  const poll = requests.shift(); assert.match(poll.url, /\/restored-run\?session_id=session-a$/);
  const stop = f.c.stopFuzzerAttack(), stopRequest = requests.shift();
  assert.match(stopRequest.url, /\/restored-run\/stop$/); assert.equal(stopRequest.options.method, 'POST');
  stopRequest.resolve({ ok: true, status: 200 }); await stop;
  assert.equal(f.state.fuzzerRunningAttackId, 'restored-run');
  poll.resolve({ ok: true, status: 200, json: async () => ({ id: 'restored-run', running: false, stopped: true, results: [] }) });
  await follow;
  assert.equal(f.state.fuzzerRunningAttackId, null); assert.equal(f.state.fuzzerRestoredRun, null);
  assert.equal(f.state.fuzzerBaseRequest.scheme, 'http'); assert.equal(f.state.fuzzerAttackRecord, null);
});

test('native selector change is wired to transport edit and guarded after loading changes', () => {
  const f = fixture(['initFuzzerSetupControls']);
  for (const name of ['markFuzzerEditorSelection', 'removeFuzzerEditorPosition', 'renderFuzzerRemoveMarkerControl',
    'undoFuzzerMarker', 'clearFuzzerMarkers']) f.c[name] = () => {};
  f.c.initFuzzerSetupControls();
  const select = f.nodes.fuzzerTransportSelect;
  select.value = 'http'; select.listeners.change({ target: select });
  assert.equal(f.state.fuzzerBaseRequest.scheme, 'http');
  f.c.workspaceLoaded = false; select.value = 'https'; select.listeners.change({ target: select });
  assert.equal(f.state.fuzzerBaseRequest.scheme, 'http');
});
