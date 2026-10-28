// Synthetic production-function fixtures only. fetch is an in-memory assertion;
// no process, socket, runtime, saved user traffic, or external request is used.
const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
const workflow = require('../web/fuzzer-workflow.js');
const plain = value => JSON.parse(JSON.stringify(value));
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const raw = 'POST /items?id=one&id=two%2Fthree HTTP/1.0\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\na=1';
const parserNames = ['parseFuzzerRequestTemplate', 'parseEditableRawRequest', 'splitRawHttpMessage', 'editableRequestBodyLength', 'decodedBase64Length', 'parseReplayHttpVersionToken', 'normalizeReplayHttpVersion', 'headerValue', 'headerNameEquals', 'normalizedHeaders', 'validateRawHttpBodyFraming', 'buildEditableRawRequest', 'mergeHeaders', 'httpRequestAuthoritiesEquivalent', 'normalizeHttpRequestAuthority', 'authorityToTargetState', 'stripIpv6Brackets', 'defaultHttpPortForScheme', 'createDefaultEditableRequest'];
const names = [...parserNames, 'renderFuzzerSetup', 'renderFuzzerPayloadImportStatus', 'fuzzerSetupNode', 'escapeHtml', 'initFuzzerSetupControls', 'finishFuzzerOptionChange', 'fuzzerRequestTextForAction', 'fuzzerRawOffsetForEditorOffset', 'splitFuzzerPayloadLines', 'fuzzerPayloadCount', 'fuzzerPayloadTextWithinLimits', 'fuzzerSetupPreflight', 'markFuzzerPosition', 'markFuzzerEditorSelection', 'fuzzerMarkerRemoval', 'renderFuzzerRemoveMarkerControl', 'removeFuzzerEditorPosition', 'undoFuzzerMarker', 'clearFuzzerMarkers', 'applyFuzzerPayloadList', 'importFuzzerPayloadFile', 'updateFuzzerRequestText', 'updateFuzzerPayloadsText', 'markFuzzerDraftChanged', 'invalidateFuzzerRun', 'openFuzzerFromRecord', 'openFuzzerFromReplay', 'runFuzzerAttack', 'followFuzzerAttack', 'isCurrentFuzzerRun', 'replayHttpVersionFromText', 'validateManualRepeaterTargetInput', 'explicitAuthorityPort', 'normalizePortValue', 'isLikelyIpv6Literal', 'setReplayTargetInputValidity'];
function fixture() {
  const state = { activeSession: { id: 'session-a' }, fuzzerBaseRequest: { scheme: 'https', host: 'example.com', method: 'POST', path: '/items', body: 'a=1', body_encoding: 'utf8', preview_truncated: false }, fuzzerRequestText: raw, fuzzerPayloadsText: 'x', fuzzerDraftVersion: 0, fuzzerRunToken: 0, fuzzerRunning: false, fuzzerSourceTransactionId: 'source-a' };
  const els = { fuzzerPayloadsEditor: { value: 'x' } };
  const target = { scheme: 'https', host: '127.0.0.1', port: '8443' };
  const pending = deferred(), requests = [];
  let editor = null, renders = 0, saves = 0;
  const c = loadFunctions(names, { workspaceLoaded: true, state, els, TextEncoder, TextDecoder, URL, atob, SniperFuzzerWorkflow: workflow,
    document: { getElementById: () => null }, getCMView: () => editor,
    currentSessionId: () => state.activeSession?.id || null,
    renderFuzzer() { renders++; els.fuzzerPayloadsEditor.value = state.fuzzerPayloadsText; },
    scheduleWorkspaceStateSave() { saves++; }, hideFuzzerDetailPanel() {}, showToast() {},
    clearFuzzerAttackRecord() { state.fuzzerAttackRecord = null; state.fuzzerAttackRecordId = null; },
    setFuzzerAttackRecord(value) { state.fuzzerAttackRecord = value; }, normalizeFuzzerAttackRecord: value => value,
    setActiveTool() {}, renderToolPanels() {}, scheduleRefresh() {},
    activeFuzzerTargetForRequest: () => ({ ...target }),
    fuzzerTargetAuthorityFromRequestText: () => 'https://example.com',
    editableRequestFromRecord: record => ({ ...state.fuzzerBaseRequest, ...record.request }),
    isRequestPreviewTruncated: () => false, buildTruncatedBodyNotice: () => 'Truncated',
    normalizeFuzzerTargetOverride: value => value,
    getRepeaterTargetConfig: () => target, replayTargetOverridePayload: () => target,
    flushWorkspaceStateForReplayAction: () => pending.promise,
    expectedActiveSessionIdForWrite: value => value,
    fetch: async (url, options) => { requests.push({ url, body: JSON.parse(options.body) }); return { ok: true, json: async () => ({ id: 'run-a', status: 'completed', results: [] }) }; },
    WorkspaceStateConflictError: class WorkspaceStateConflictError extends Error {}, console: { error() {} },
  });
  return { c, state, els, target, pending, requests, get saves() { return saves; }, get renders() { return renders; }, setEditor(value) { editor = value; } };
}

test('Fuzzer normalizes derived Content-Length without changing raw source, duplicates, encoding, or HTTP version', () => {
  const f = fixture();
  const text = raw.replace('a=1', 'a=$payload$');
  const request = f.c.parseFuzzerRequestTemplate(text);
  assert.equal(request.body, 'a=$payload$');
  assert.equal(request.headers.find(h => h.name === 'Content-Length').value, '11');
  assert.equal(request.path, '/items?id=one&id=two%2Fthree');
  assert.equal(request.http_version, 'HTTP/1.0');
  assert.equal(f.state.fuzzerRequestText, raw);
  const expanded = workflow.expandTemplate(request, '문 😀');
  assert.equal(expanded.headers.find(h => h.name === 'Content-Length').value, String(Buffer.byteLength('a=문 😀')));
});
for (const headers of ['Content-Length: nope', 'Content-Length: 3\r\nContent-Length: 4', 'Content-Length: 3\r\nTransfer-Encoding: chunked']) {
  test(`framing guard remains for ${headers.replaceAll('\r\n', ' / ')}`, () => {
    const f = fixture();
    assert.throws(() => f.c.parseFuzzerRequestTemplate(raw.replace('Content-Length: 3', headers)));
  });
}
test('unchanged CodeMirror line normalization retains source CRLF bytes and maps selection offsets exactly', () => {
  const f = fixture(), text = raw.replace('a=1', 'a=1\r\nlast\r');
  f.state.fuzzerRequestText = text;
  f.setEditor({ getContent: () => text.replace(/\r\n?/g, '\n') });
  assert.equal(f.c.fuzzerRequestTextForAction(), text);
  const index = text.indexOf('two%2Fthree');
  const offset = text.slice(0, index).replace(/\r\n?/g, '\n').length;
  assert.equal(f.c.fuzzerRawOffsetForEditorOffset(text, offset), index);
  assert.throws(() => f.c.fuzzerRawOffsetForEditorOffset(text, 10000));
});
test('candidate marking changes only its exact duplicate value and undo restores raw bytes', () => {
  const f = fixture(), candidate = workflow.candidates(raw)[1];
  f.c.markFuzzerPosition(candidate.start, candidate.end, raw);
  assert.equal(f.state.fuzzerRequestText, raw.replace('two%2Fthree', '§two%2Fthree§'));
  assert.equal(f.state.fuzzerPayloadsText, 'x');
  f.c.undoFuzzerMarker();
  assert.equal(f.state.fuzzerRequestText, raw);
});
test('stale candidate and undo cannot overwrite newer editor content', () => {
  const f = fixture(), candidate = workflow.candidates(raw)[0];
  f.state.fuzzerRequestText += '\n';
  assert.throws(() => f.c.markFuzzerPosition(candidate.start, candidate.end, raw), /changed/);
  f.state.fuzzerRequestText = raw;
  f.c.markFuzzerPosition(candidate.start, candidate.end, raw);
  f.state.fuzzerRequestText += '\n';
  assert.throws(() => f.c.undoFuzzerMarker(), /changed/);
});
for (const kind of ['base64', 'truncated']) test(`${kind} source body is not offered for marking`, () => {
  const f = fixture();
  if (kind === 'base64') { f.state.fuzzerBaseRequest.body_encoding = 'base64'; f.state.fuzzerBaseRequest.body = 'YQ=='; f.state.fuzzerRequestText = raw.replace('a=1', 'YQ=='); }
  else f.state.fuzzerBaseRequest.preview_truncated = true;
  const text = f.state.fuzzerRequestText;
  assert.throws(() => f.c.markFuzzerPosition(text.length - 1, text.length, text), /complete UTF-8/);
  assert.equal(f.state.fuzzerRequestText, text);
});
test('append and replace preserve empty, whitespace, literal-dollar and trailing-empty payloads', () => {
  const f = fixture();
  f.state.fuzzerPayloadsText = '  \n\n';
  f.c.applyFuzzerPayloadList(['$&', '', '$payload$', '']);
  assert.deepEqual(Array.from(f.c.splitFuzzerPayloadLines(f.state.fuzzerPayloadsText)), ['  ', '', '$&', '', '$payload$', '']);
  f.c.applyFuzzerPayloadList([''], 'replace');
  assert.equal(f.state.fuzzerPayloadsText, '\n');
});
test('workspace text budget includes delimiters and a rejected load leaves the draft intact', () => {
  const f = fixture(), payloads = Array(64).fill('a'.repeat(65536));
  assert.equal(workflow.validatePayloads(payloads).valid, true);
  assert.throws(() => f.c.applyFuzzerPayloadList(payloads, 'replace'), /including line separators/);
  assert.equal(f.state.fuzzerPayloadsText, 'x');
  assert.throws(() => f.c.fuzzerPayloadTextWithinLimits('\n'.repeat(5001)), /5000/);
});
test('UTF-8 file preserves BOM, bare CR GUI delimiters, empty entries and literal whitespace', async () => {
  const f = fixture(), text = '\ufeffa\r\n \r\r$&\n';
  await f.c.importFuzzerPayloadFile({ size: Buffer.byteLength(text), arrayBuffer: async () => new TextEncoder().encode(text) }, 'replace');
  assert.deepEqual(Array.from(f.c.splitFuzzerPayloadLines(f.state.fuzzerPayloadsText)), ['\ufeffa', ' ', '', '$&']);
});
test('invalid UTF-8 and oversized files are rejected without altering the draft', async () => {
  const f = fixture(); let read = false;
  await assert.rejects(f.c.importFuzzerPayloadFile({ size: 4194305, arrayBuffer: async () => { read = true; } }), /4 MiB/);
  assert.equal(read, false);
  await assert.rejects(f.c.importFuzzerPayloadFile({ size: 2, arrayBuffer: async () => new Uint8Array([255, 255]) }), /UTF-8/);
  assert.equal(f.state.fuzzerPayloadsText, 'x');
});
for (const boundary of ['draft', 'session', 'run-token', 'new-import']) for (const outcome of ['success', 'error']) {
  test(`file import ignores stale ${boundary} ${outcome}`, async () => {
    const f = fixture(), read = deferred();
    const job = f.c.importFuzzerPayloadFile({ size: 1, arrayBuffer: () => read.promise });
    if (boundary === 'draft') f.state.fuzzerDraftVersion++;
    else if (boundary === 'session') f.state.activeSession.id = 'session-b';
    else if (boundary === 'run-token') f.state.fuzzerRunToken++;
    else f.state._fuzzerFileGeneration++;
    if (outcome === 'success') read.resolve(new Uint8Array([97])); else read.reject(new Error('old file'));
    assert.equal(await job, false);
    assert.equal(f.state.fuzzerPayloadsText, 'x');
  });
}
for (const origin of ['record', 'replay']) test(`${origin} handoff preserves prepared payloads`, async () => {
  const f = fixture(); f.state.fuzzerPayloadsText = ' \n\n$&';
  if (origin === 'record') f.c.openFuzzerFromRecord({ id: 'source-b', kind: 'http', request: { path: '/other' } });
  else { f.c.getActiveReplayTab = () => ({ requestText: raw, sourceTransactionId: 'source-b', baseRequest: f.state.fuzzerBaseRequest }); await f.c.openFuzzerFromReplay(); }
  assert.equal(f.state.fuzzerPayloadsText, ' \n\n$&');
  assert.equal(f.state.fuzzerSourceTransactionId, 'source-b');
  assert.equal(f.state.fuzzerDraftVersion, 1);
});
for (const boundary of ['draft', 'session', 'run-token', 'source', 'target', 'visible-payload']) {
  test(`post-flush ownership prevents stale ${boundary} POST`, async () => {
    const f = fixture(); f.state.fuzzerRequestText = raw.replace('one', '$payload$');
    const job = f.c.runFuzzerAttack();
    assert.equal(f.state.fuzzerRunning, true);
    if (boundary === 'draft') f.state.fuzzerDraftVersion++;
    else if (boundary === 'session') f.state.activeSession.id = 'session-b';
    else if (boundary === 'run-token') f.state.fuzzerRunToken++;
    else if (boundary === 'source') f.state.fuzzerSourceTransactionId = 'source-b';
    else if (boundary === 'target') f.target.port = '9443';
    else f.els.fuzzerPayloadsEditor.value = 'new';
    f.pending.resolve(7); await job;
    assert.equal(f.requests.length, 0);
  });
}
test('unchanged run posts exactly one captured request with original protocol, source and override', async () => {
  const f = fixture(); f.state.fuzzerRequestText = raw.replace('one', '$payload$');
  const job = f.c.runFuzzerAttack(); f.pending.resolve(7); await job;
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].url, '/api/fuzzer/attacks');
  assert.equal(f.requests[0].body.source_transaction_id, 'source-a');
  assert.equal(f.requests[0].body.http_version, 'HTTP/1.0');
  assert.deepEqual(f.requests[0].body.target, f.target);
  assert.equal(f.requests[0].body.expected_workspace_revision, 7);
  assert.equal(f.state.fuzzerRunning, false);
});

test('a started attack is followed to its end with the chosen options, then shown as before', async () => {
  const f = fixture(); f.state.fuzzerRequestText = raw.replace('one', '§one§');
  const reads = [];
  Object.assign(f.c, {
    FUZZER_POLL_MS: 1, setTimeout,
    sessionQueryPath: (path, session) => `${path}?session_id=${session}`,
    requireOkResponse: async () => {},
    fetch: async (url, options = {}) => {
      if (options.method === 'POST') {
        f.requests.push({ url, body: JSON.parse(options.body) });
        return { ok: true, json: async () => ({ id: 'run-a', running: true, planned: 2, results: [] }) };
      }
      reads.push(url);
      const running = reads.length < 2;
      return { ok: true, json: async () => ({ id: 'run-a', running, status: 'completed', planned: 2, results: running ? [{ index: 0 }] : [{ index: 0 }, { index: 1 }] }) };
    },
  });
  const job = f.c.runFuzzerAttack(); f.pending.resolve(7); await job;
  assert.deepEqual([f.requests[0].body.attack_type, f.requests[0].body.url_encode, f.requests[0].body.concurrency], ['sniper', true, 4]);
  assert.deepEqual(reads, Array(2).fill('/api/fuzzer/attacks/run-a?session_id=session-a'));
  assert.equal(f.state.fuzzerAttackRecord.results.length, 2);
  assert.equal(f.state.fuzzerRunning, false);
  assert.equal(f.state.fuzzerRunningAttackId, null);
});

test('render enables exact candidates and recomputes safety when source flags change with identical raw text', () => {
  const f = fixture();
  const ids = ['fuzzerMarkSelectionButton', 'startFuzzerButton', 'fuzzerPreflightSummary', 'fuzzerPositionCount', 'fuzzerPayloadCount', 'fuzzerClearMarkersButton', 'fuzzerTargetSummary', 'fuzzerPreflightNotice', 'fuzzerPreviewSamples', 'fuzzerCandidateSelect', 'fuzzerUndoMarkerButton'];
  const nodes = Object.fromEntries(ids.map(id => [id, { value: '', textContent: '', innerHTML: '', disabled: true }]));
  f.c.document.getElementById = id => nodes[id] || null;
  f.c.renderFuzzerSetup();
  assert.equal(nodes.fuzzerCandidateSelect.disabled, false);
  assert.equal(nodes.fuzzerCandidateSelect._fuzzerCandidates.length, 3);
  assert.match(nodes.fuzzerPreflightSummary.textContent, /1 payload.*0 planned requests/);
  f.state.fuzzerBaseRequest.preview_truncated = true;
  f.c.renderFuzzerSetup();
  assert.equal(nodes.fuzzerCandidateSelect._fuzzerCandidates.length, 2);
  assert.match(nodes.fuzzerPreflightNotice.textContent, /truncated/);
  f.state.fuzzerRunning = true;
  f.c.renderFuzzerSetup();
  assert.equal(nodes.fuzzerCandidateSelect.disabled, true);
});

for (const outcome of ['success', 'error']) test(`rejected oversized replacement invalidates an earlier pending file ${outcome}`, async () => {
  const f = fixture(), old = deferred();
  const pending = f.c.importFuzzerPayloadFile({ size: 1, arrayBuffer: () => old.promise }, 'replace');
  await assert.rejects(f.c.importFuzzerPayloadFile({ size: 4194305, arrayBuffer: () => { throw new Error('Must not read'); } }, 'replace'), /4 MiB/);
  if (outcome === 'success') old.resolve(new Uint8Array([97])); else old.reject(new Error('old file read failed'));
  assert.equal(await pending, false);
  assert.equal(f.state.fuzzerPayloadsText, 'x');
  assert.equal(f.saves, 0);
});

function setupNodes(f) {
  const ids = ['fuzzerMarkSelectionButton', 'startFuzzerButton', 'fuzzerPreflightSummary', 'fuzzerPositionCount', 'fuzzerPayloadCount', 'fuzzerClearMarkersButton', 'fuzzerTargetSummary', 'fuzzerPreflightNotice', 'fuzzerPreviewSamples', 'fuzzerPreviewNotes', 'fuzzerCandidateSelect', 'fuzzerMarkCandidateButton', 'fuzzerRequestHelp'];
  const nodes = Object.fromEntries(ids.map(id => [id, { value: '', textContent: '', innerHTML: '', disabled: true, listeners: {},
    addEventListener(name, callback) { this.listeners[name] = callback; } }]));
  f.c.document.getElementById = id => nodes[id] || null;
  return nodes;
}

for (const body of ['$payload$', '§YQ==§', 'not base64!']) test(`base64 body guidance explains invalid ${JSON.stringify(body)} without modifying the draft`, () => {
  const f = fixture(), nodes = setupNodes(f);
  f.state.fuzzerBaseRequest.body_encoding = 'base64';
  f.state.fuzzerBaseRequest.body = 'YQ==';
  f.state.fuzzerRequestText = raw.replace('one', '§one§').replace('a=1', body);
  const before = f.state.fuzzerRequestText;
  const message = 'Request body must be valid base64. Restore valid base64 in Request; use header or query positions instead of body markers.';
  assert.throws(() => f.c.parseFuzzerRequestTemplate(before), { message });
  f.c.renderFuzzerSetup();
  assert.equal(nodes.startFuzzerButton.disabled, true);
  assert.equal(nodes.fuzzerPreflightNotice.textContent, message);
  assert.equal(nodes.fuzzerRequestHelp.textContent, 'Raw HTTP request · Body format: base64. Select a header or query value, then Add §.');
  assert.match(nodes.fuzzerPreviewNotes.textContent, /Body format: base64/);
  assert.equal(f.state.fuzzerRequestText, before);
  assert.equal(f.state.fuzzerPayloadsText, 'x');
  assert.equal(f.state.fuzzerBaseRequest.body, 'YQ==');
  assert.equal(f.saves, 0);
  assert.equal(f.requests.length, 0);
  f.state.fuzzerRequestText = raw.replace('one', '§one§').replace('a=1', 'YQ==');
  f.c.renderFuzzerSetup();
  assert.equal(nodes.startFuzzerButton.disabled, false);
  assert.equal(nodes.fuzzerPreflightNotice.textContent, '');
  assert.equal(nodes.fuzzerRequestHelp.textContent, 'Raw HTTP request · Body format: base64. Select a header or query value, then Add §.');
});

test('base64 guidance does not tighten decoding or replace unrelated parser errors', () => {
  const f = fixture();
  f.state.fuzzerBaseRequest.body_encoding = 'base64';
  for (const body of ['', 'YQ==', 'YQ', ' YQ==\r\n']) {
    const before = raw.replace('a=1', body);
    assert.equal(f.c.parseFuzzerRequestTemplate(before).body, body);
  }
  const valid = raw.replace('a=1', 'YQ==');
  for (const [text, message] of [
    [valid.replace('POST /items?id=one&id=two%2Fthree HTTP/1.0', 'not-a-request'), 'Invalid request line in editor'],
    [valid.replace('/items?id=one&id=two%2Fthree', 'https://other.example.com/items'), 'Absolute-form request target does not match Host header'],
    [valid.replace('Content-Length: 3', 'Transfer-Encoding: chunked'), 'Raw HTTP input with Transfer-Encoding: chunked is not supported'],
    [valid.replace('Content-Length: 3', 'Content-Length: nope'), 'Invalid or conflicting Content-Length headers in the request template.'],
  ]) assert.throws(() => f.c.parseFuzzerRequestTemplate(text), { message });
});

for (const position of ['query', 'header']) test(`base64 request ${position} positions stay available and preserve the encoded body`, () => {
  const f = fixture(), nodes = setupNodes(f);
  f.state.fuzzerBaseRequest.body_encoding = 'base64';
  f.state.fuzzerBaseRequest.body = 'YQ==';
  const before = raw.replace('a=1', 'YQ==');
  f.state.fuzzerRequestText = before;
  const value = position === 'query' ? 'one' : 'application/x-www-form-urlencoded';
  const start = before.indexOf(value);
  f.c.markFuzzerPosition(start, start + value.length, before);
  const marked = f.state.fuzzerRequestText;
  assert.equal(marked, before.slice(0, start) + `§${value}§` + before.slice(start + value.length));
  const template = f.c.parseFuzzerRequestTemplate(marked);
  assert.equal(template.body, 'YQ==');
  assert.equal(template.body_encoding, 'base64');
  f.c.renderFuzzerSetup();
  assert.equal(nodes.startFuzzerButton.disabled, false);
  assert.equal(nodes.fuzzerPreflightNotice.textContent, '');
  assert.equal(nodes.fuzzerRequestHelp.textContent, 'Raw HTTP request · Body format: base64. Select a header or query value, then Add §.');
  assert.match(nodes.fuzzerPreviewNotes.textContent, /header or query positions instead of body markers/);
  assert.equal(f.state.fuzzerRequestText, marked);
  f.state.fuzzerBaseRequest.body_encoding = 'utf8';
  f.c.renderFuzzerSetup();
  assert.equal(nodes.fuzzerRequestHelp.textContent, 'Raw HTTP request · select a value, then Add §');
  assert.doesNotMatch(nodes.fuzzerPreviewNotes.textContent, /base64/);
});

for (const [prefix, line] of [['', 1], ['small\n', 2], ['\r\n', 2], [' \r\n\r\n', 3]]) test(`oversized Payloads line ${line} with prefix ${JSON.stringify(prefix)} disables Start without rewriting input`, () => {
  const f = fixture(), nodes = setupNodes(f);
  f.state.fuzzerRequestText = raw.replace('one', '§one§');
  f.state.fuzzerPayloadsText = prefix + 'a'.repeat(65537) + '\r\n';
  const before = f.state.fuzzerPayloadsText;
  f.c.renderFuzzerSetup();
  assert.equal(nodes.startFuzzerButton.disabled, true);
  assert.equal(nodes.fuzzerPreflightNotice.textContent, `Payloads line ${line} exceeds 64 KiB (65536 bytes). Shorten this line.`);
  assert.equal(f.state.fuzzerPayloadsText, before);
  assert.equal(f.saves, 0);
  assert.equal(f.requests.length, 0);
});

test('ready setup keeps target, count and protocol visible with details off the main action path', () => {
  const f = fixture(), nodes = setupNodes(f);
  f.state.fuzzerRequestText = raw.replace('one', '$payload$');
  f.c.renderFuzzerSetup();
  assert.match(nodes.fuzzerPreflightSummary.textContent, /1 payload → 1 planned request/);
  assert.equal(nodes.fuzzerPositionCount.textContent, '1 position');
  assert.match(nodes.fuzzerTargetSummary.textContent, /127\.0\.0\.1:8443.*HTTP\/1\.0/);
  assert.equal(nodes.fuzzerPreflightNotice.textContent, '');
  assert.match(nodes.fuzzerPreviewNotes.textContent, /Match and Replace/);
  f.state.fuzzerRequestText = raw.replace('one', '$payload$').replace('two%2Fthree', '$payload$');
  f.c.renderFuzzerSetup();
  assert.match(nodes.fuzzerPreflightSummary.textContent, /1 payload → 2 planned requests/);
  f.state.fuzzerAttackType = 'battering_ram';
  f.c.renderFuzzerSetup();
  assert.match(nodes.fuzzerPreflightSummary.textContent, /1 payload → 1 planned request/);
});
test('empty setup gives one actionable next step; running state remains honest', () => {
  const f = fixture(), nodes = setupNodes(f);
  f.state.fuzzerRequestText = ''; f.state.fuzzerPayloadsText = '';
  f.c.renderFuzzerSetup();
  assert.equal(nodes.fuzzerPreflightNotice.textContent, 'Paste a raw HTTP request, or send one from History / Replay.');
  f.state.fuzzerRequestText = raw; f.c.renderFuzzerSetup();
  assert.equal(nodes.fuzzerPreflightNotice.textContent, 'Select a value to replace.');
  f.state.fuzzerRequestText = raw.replace('one', '$payload$'); f.c.renderFuzzerSetup();
  assert.equal(nodes.fuzzerPreflightNotice.textContent, 'Add payloads.');
  f.state.fuzzerPayloadsText = 'x'; f.state.fuzzerRunning = true; f.c.renderFuzzerSetup();
  assert.equal(nodes.fuzzerPreflightNotice.textContent, 'Starting…');
  f.state.fuzzerAttackRecord = { running: true, planned: 4, results: [{}, {}] }; f.c.renderFuzzerSetup();
  assert.equal(nodes.fuzzerPreflightNotice.textContent, 'Sending… 2 of 4');
});
test('the value row and the preview wait until there is something to show', () => {
  const f = fixture(), nodes = setupNodes(f);
  for (const id of ['fuzzerValueRow', 'fuzzerPreviewDisclosure']) {
    const classes = new Set();
    nodes[id] = { classList: { contains: x => classes.has(x), toggle: (x, on) => (on ? classes.add(x) : classes.delete(x), on) } };
  }
  f.state.fuzzerRequestText = ''; f.c.renderFuzzerSetup();
  assert.equal(nodes.fuzzerValueRow.classList.contains('hidden'), true);
  assert.equal(nodes.fuzzerPreviewDisclosure.classList.contains('hidden'), true);
  f.state.fuzzerRequestText = raw; f.c.renderFuzzerSetup();
  assert.equal(nodes.fuzzerValueRow.classList.contains('hidden'), false);
  assert.equal(nodes.fuzzerPreviewDisclosure.classList.contains('hidden'), false);
});
test('value action waits for a chosen value and is disabled again while running', () => {
  const f = fixture(), nodes = setupNodes(f);
  f.c.initFuzzerSetupControls(); f.c.renderFuzzerSetup();
  assert.equal(nodes.fuzzerMarkCandidateButton.disabled, true);
  nodes.fuzzerCandidateSelect.value = '0';
  nodes.fuzzerCandidateSelect.listeners.change({ target: nodes.fuzzerCandidateSelect });
  assert.equal(nodes.fuzzerMarkCandidateButton.disabled, false);
  f.state.fuzzerRunning = true; f.c.renderFuzzerSetup();
  assert.equal(nodes.fuzzerMarkCandidateButton.disabled, true);
});

for (const rawHeader of ['$payload$: new.example.com', 'Host: $payload$']) test(`authority-changing ${rawHeader} keeps a visible warning beside the template target`, () => {
  const f = fixture(), nodes = setupNodes(f);
  f.state.fuzzerBaseRequest = { ...f.state.fuzzerBaseRequest, host: 'old.example.com', body: '' };
  f.state.fuzzerRequestText = `GET / HTTP/1.1\r\n${rawHeader}\r\n\r\n`;
  f.state.fuzzerPayloadsText = rawHeader.startsWith('$payload$') ? 'Host' : 'new.example.com';
  f.c.activeFuzzerTargetForRequest = () => null;
  f.c.renderFuzzerSetup();
  assert.match(nodes.fuzzerTargetSummary.textContent, /Template target:/);
  assert.equal(nodes.fuzzerPreflightNotice.textContent, 'Request authority or framing may change. Check Preview.');
  assert.match(nodes.fuzzerPreviewSamples.innerHTML, /https:\/\/new\.example\.com:443/);
});


test('Start follows preflight validity and still respects the active attack ID', () => {
  const f = fixture(), nodes = setupNodes(f);
  for (const [text, payloads, expected] of [["", "x", true], [raw, "x", true], [raw.replace('one', '§one§'), "", true], [raw.replace('one', '§one§'), "x", false]]) {
    f.state.fuzzerRequestText = text; f.state.fuzzerPayloadsText = payloads;
    f.c.renderFuzzerSetup(); assert.equal(nodes.startFuzzerButton.disabled, expected);
    assert.equal(nodes.fuzzerMarkSelectionButton.disabled, !text.trim());
  }
  f.state.fuzzerRunningAttackId = 'active-run';
  f.c.renderFuzzerSetup(); assert.equal(nodes.startFuzzerButton.disabled, true);
});

test('Clear removes recognized delimiters only, keeps CRLF and original values, and Undo restores exact bytes', () => {
  const f = fixture();
  const before = raw.replace('one', '§one§').replace('two%2Fthree', '$payload$').replace('a=1', 'a=§1§&literal=§');
  f.state.fuzzerRequestText = before;
  f.c.clearFuzzerMarkers();
  assert.equal(f.state.fuzzerRequestText, raw.replace('two%2Fthree', '').replace('a=1', 'a=1&literal=§'));
  assert.equal(f.state.fuzzerPayloadsText, 'x');
  f.c.undoFuzzerMarker(); assert.equal(f.state.fuzzerRequestText, before);
  f.c.clearFuzzerMarkers();
  const saves = f.saves; f.c.clearFuzzerMarkers(); assert.equal(f.saves, saves);
});

for (const fence of ['session', 'run', 'draft']) test(`Clear undo rejects changed ${fence} ownership`, () => {
  const f = fixture(); f.state.fuzzerRequestText = raw.replace('one', '§one§');
  f.c.clearFuzzerMarkers();
  if (fence === 'session') f.state.activeSession.id = 'other';
  if (fence === 'run') f.state.fuzzerRunToken++;
  if (fence === 'draft') f.state.fuzzerRequestText += 'new';
  const current = f.state.fuzzerRequestText;
  assert.throws(() => f.c.undoFuzzerMarker(), /changed/);
  assert.equal(f.state.fuzzerRequestText, current);
});

test('caret Add inserts an empty position and leaves the caret between markers after a CRLF header', () => {
  const f = fixture(), at = raw.indexOf('a=1') + 2;
  const visible = raw.replace(/\r\n?/g, '\n'), offset = raw.slice(0, at).replace(/\r\n?/g, '\n').length;
  let selection, focused = 0;
  f.setEditor({ getContent: () => visible, view: { state: { selection: { main: { empty: true, from: offset, to: offset } } }, dispatch(value) { selection = value.selection; }, focus() { focused++; } } });
  f.c.markFuzzerEditorSelection();
  assert.equal(f.state.fuzzerRequestText, raw.slice(0, at) + '§§' + raw.slice(at));
  assert.deepEqual(plain(selection), { anchor: offset + 1, head: offset + 1 }); assert.equal(focused, 1);
});

test('Clear is disabled during a run and Add rejects a caret at an opaque body start', () => {
  const f = fixture(); f.state.fuzzerRequestText = raw.replace('one', '§one§'); f.state.fuzzerRunning = true;
  assert.throws(() => f.c.clearFuzzerMarkers(), /Wait/);
  f.state.fuzzerRunning = false; f.state.fuzzerBaseRequest.preview_truncated = true;
  const at = f.state.fuzzerRequestText.indexOf('a=1');
  assert.throws(() => f.c.markFuzzerPosition(at, at), /complete UTF-8/);
});


test('Undo returns keyboard focus to the existing request editor', () => {
  const f = fixture(); let focused = 0;
  f.state.fuzzerRequestText = raw.replace('one', '§one§');
  f.setEditor({ getContent: () => f.state.fuzzerRequestText.replace(/\r\n?/g, '\n'), view: { focus() { focused++; } } });
  f.c.clearFuzzerMarkers(); assert.equal(focused, 1);
  f.c.undoFuzzerMarker(); assert.equal(focused, 2);
  assert.equal(f.state.fuzzerRequestText, raw.replace('one', '§one§'));
});

test('Clear never pairs literal section signs across different engine fields', () => {
  const f = fixture(), nodes = setupNodes(f);
  const text = 'GET /literal§ HTTP/1.1\r\nHost: example.com\r\nX-Note: lone§\r\n\r\n';
  f.state.fuzzerRequestText = text;
  f.c.renderFuzzerSetup(); assert.equal(nodes.fuzzerPositionCount.textContent, '0 positions');
  assert.equal(nodes.fuzzerClearMarkersButton.disabled, true);
  f.c.clearFuzzerMarkers(); assert.equal(f.state.fuzzerRequestText, text); assert.equal(f.saves, 0);
});

test('Clear preserves literal delimiters across header names, values and body while removing real positions', () => {
  const f = fixture();
  const text = 'GET /§kept§/literal§ HTTP/1.1\r\nHost: example.com\r\nX-§: lone§\r\n\r\nbody§';
  f.state.fuzzerRequestText = text;
  f.c.clearFuzzerMarkers(); assert.equal(f.state.fuzzerRequestText, text.replace('§kept§', 'kept'));
  f.c.undoFuzzerMarker(); assert.equal(f.state.fuzzerRequestText, text);
});

test('Add cannot create a position spanning engine fields or invalid request syntax', () => {
  const f = fixture();
  assert.throws(() => f.c.markFuzzerPosition(raw.indexOf('two%2Fthree'), raw.indexOf('Host') + 4), /one request field/);
  assert.throws(() => f.c.markFuzzerPosition(0, 4), /request line/);
  assert.equal(f.state.fuzzerRequestText, raw); assert.equal(f.saves, 0);
});

test('restored active attack blocks Add, Clear and Undo even without local running flag', () => {
  const f = fixture(), nodes = setupNodes(f);
  f.state.fuzzerRequestText = raw.replace('one', '§one§');
  f.c.clearFuzzerMarkers(); f.state.fuzzerRunningAttackId = 'restored-active';
  assert.throws(() => f.c.clearFuzzerMarkers(), /Wait/);
  assert.throws(() => f.c.markFuzzerPosition(raw.indexOf('one'), raw.indexOf('one') + 3), /Wait/);
  assert.throws(() => f.c.undoFuzzerMarker(), /changed/);
  f.c.renderFuzzerSetup(); assert.equal(nodes.fuzzerClearMarkersButton.disabled, true);
});

for (const edit of ['request', 'payloads', 'markers', 'preset']) test(`${edit} edit clears the previous start failure and shows current setup guidance`, () => {
  const f = fixture(), nodes = setupNodes(f);
  f.state.fuzzerNotice = 'Previous start failed'; f.state.fuzzerNoticeError = true;
  f.c.renderFuzzerSetup();
  assert.equal(nodes.fuzzerPreflightNotice.textContent, 'Previous start failed');
  if (edit === 'request') f.c.updateFuzzerRequestText(raw.replace('one', 'changed'), { userEdit: true });
  if (edit === 'payloads') f.c.updateFuzzerPayloadsText('', { userEdit: true });
  if (edit === 'markers') f.c.markFuzzerPosition(raw.indexOf('one'), raw.indexOf('one') + 3);
  if (edit === 'preset') f.c.applyFuzzerPayloadList(['fresh']);
  f.c.renderFuzzerSetup();
  assert.equal(f.state.fuzzerNoticeError, false);
  assert.equal(f.state.fuzzerNotice, '');
  assert.equal(nodes.fuzzerPreflightNotice.textContent, edit === 'markers' ? '' : 'Select a value to replace.');
});

test('unchanged text and non-user synchronization preserve the current start failure', () => {
  const f = fixture(); f.state.fuzzerNotice = 'Previous start failed'; f.state.fuzzerNoticeError = true;
  f.c.updateFuzzerRequestText(raw, { userEdit: true });
  f.c.updateFuzzerPayloadsText('x', { userEdit: true });
  f.c.updateFuzzerRequestText(raw.replace('one', 'synced'));
  assert.equal(f.state.fuzzerNoticeError, true); assert.equal(f.state.fuzzerNotice, 'Previous start failed');
});

test('editing a shown failed run retains the new-draft explanation without marking it as an error', () => {
  const f = fixture(), nodes = setupNodes(f);
  f.state.fuzzerAttackRecord = { id: 'old' }; f.state.fuzzerAttackRecordId = 'old';
  f.state.fuzzerNotice = 'Previous poll failed'; f.state.fuzzerNoticeError = true;
  f.c.updateFuzzerPayloadsText('new', { userEdit: true }); f.c.renderFuzzerSetup();
  assert.equal(f.state.fuzzerNoticeError, false);
  assert.match(f.state.fuzzerNotice, /draft changed/);
  assert.equal(nodes.fuzzerPreflightNotice.textContent, 'Select a value to replace.');
});

test('clearing a failed request removes error styling from the empty-editor guidance', () => {
  const f = fixture(), nodes = setupNodes(f), classes = new Set();
  nodes.fuzzerPreflightNotice.classList = { toggle(name, on) { if (on) classes.add(name); else classes.delete(name); } };
  f.state.fuzzerNotice = 'Previous start failed'; f.state.fuzzerNoticeError = true;
  f.c.renderFuzzerSetup(); assert.equal(classes.has('fuzzer-notice-error'), true);
  f.c.updateFuzzerRequestText('', { userEdit: true }); f.c.renderFuzzerSetup();
  assert.equal(nodes.fuzzerPreflightNotice.textContent, 'Paste a raw HTTP request, or send one from History / Replay.');
  assert.equal(classes.has('fuzzer-notice-error'), false);
  f.c.updateFuzzerRequestText('not a request', { userEdit: true }); f.c.renderFuzzerSetup();
  assert.equal(classes.has('fuzzer-notice-error'), true);
});

for (const field of ['Request', 'Payloads']) test(`${field} correction clears the old failure from the actual Results render, not just setup`, () => {
  const state = { fuzzerRequestText: raw, fuzzerPayloadsText: 'x', fuzzerNotice: 'Previous start failed', fuzzerNoticeError: true };
  const els = { fuzzerPayloadsEditor: { value: 'x' }, fuzzerMeta: { textContent: '' } };
  let resultText = '', emptyRenders = 0;
  const c = loadFunctions(['updateFuzzerRequestText', 'updateFuzzerPayloadsText', 'markFuzzerDraftChanged', 'renderFuzzer'], {
    workspaceLoaded: true, state, els, renderFuzzerResultsWorkflow() {}, renderFuzzerSetup() {},
    renderFuzzerPayloadsEditor() { els.fuzzerPayloadsEditor.value = state.fuzzerPayloadsText; },
    normalizeFuzzerAttackRecord: value => value || null,
    renderEmptyFuzzerResults(text) { resultText = text; emptyRenders++; },
  });
  c.renderFuzzer();
  assert.equal(resultText, 'Previous start failed'); assert.equal(els.fuzzerMeta.textContent, resultText);
  c[`updateFuzzer${field}Text`](field === 'Request' ? raw + '\n' : 'corrected', { userEdit: true });
  assert.equal(resultText, 'Results appear here after running.');
  assert.equal(els.fuzzerMeta.textContent, ''); assert.equal(emptyRenders, 2);
  // Further typing without an error does not repeatedly repaint the Results area.
  c[`updateFuzzer${field}Text`]('another edit', { userEdit: true }); assert.equal(emptyRenders, 2);
});

for (const action of ['range', 'preset']) for (const outcome of ['success', 'error']) {
  test(`same-text ${action} replacement retires an earlier file ${outcome} without retiring results`, async () => {
    const f = fixture(), read = deferred();
    const values = action === 'range' ? workflow.numericRange(1, 3, 1) : [...workflow.presets[0].payloads];
    f.state.fuzzerPayloadsText = workflow.payloadText(values);
    const shown = { id: 'shown-run', results: [] };
    f.state.fuzzerAttackRecord = shown;
    f.state.fuzzerAttackRecordId = shown.id;
    f.state.fuzzerNotice = 'Existing run notice';
    const version = f.state.fuzzerDraftVersion, token = f.state.fuzzerRunToken;
    const pending = f.c.importFuzzerPayloadFile({ size: 3, arrayBuffer: () => read.promise }, 'replace');
    f.c.applyFuzzerPayloadList(values, 'replace');
    if (outcome === 'success') read.resolve(new TextEncoder().encode('old'));
    else read.reject(new Error('older file failed'));
    assert.equal(await pending, false);
    assert.equal(f.state.fuzzerPayloadsText, workflow.payloadText(values));
    assert.equal(f.state.fuzzerDraftVersion, version);
    assert.equal(f.state.fuzzerRunToken, token);
    assert.equal(f.state.fuzzerAttackRecord, shown);
    assert.equal(f.state.fuzzerAttackRecordId, shown.id);
    assert.equal(f.state.fuzzerNotice, 'Existing run notice');
  });
}
for (const invalid of ['range', 'payload-count', 'payload-size', 'combined-size']) {
  test(`rejected ${invalid} list action leaves the pending file owned`, async () => {
    const f = fixture(), read = deferred();
    const pending = f.c.importFuzzerPayloadFile({ size: 5, arrayBuffer: () => read.promise }, 'replace');
    const generation = f.state._fuzzerFileGeneration;
    assert.throws(() => {
      if (invalid === 'range') f.c.applyFuzzerPayloadList(workflow.numericRange(1, 3, 0), 'replace');
      else if (invalid === 'payload-count') f.c.applyFuzzerPayloadList(Array(5001).fill('a'), 'replace');
      else if (invalid === 'payload-size') f.c.applyFuzzerPayloadList(['a'.repeat(65537)], 'replace');
      else f.c.applyFuzzerPayloadList(Array(64).fill('a'.repeat(65536)), 'replace');
    });
    assert.equal(f.state._fuzzerFileGeneration, generation);
    assert.equal(f.state.fuzzerPayloadsText, 'x');
    read.resolve(new TextEncoder().encode('fresh'));
    assert.equal(await pending, true);
    assert.equal(f.state.fuzzerPayloadsText, 'fresh');
  });
}


test('targeted removal maps normalized editor offsets, preserves CRLF, saves and supports Undo', () => {
  const f = fixture(), text = raw.replace('a=1', 'a=§한😀글§');
  f.state.fuzzerRequestText = text;
  const visible = text.replace(/\r\n?/g, '\n'), offset = visible.indexOf('한');
  const selection = { from: offset, to: offset + 1 }, dispatched = [];
  let focused = 0;
  f.setEditor({ getContent: () => f.state.fuzzerRequestText.replace(/\r\n?/g, '\n'), view: {
    state: { selection: { main: selection } }, dispatch: value => dispatched.push(value), focus() { focused++; },
  } });
  f.c.removeFuzzerEditorPosition();
  assert.equal(f.state.fuzzerRequestText, text.replace('§한😀글§', '한😀글'));
  assert.equal(f.saves, 1);
  assert.equal(focused, 1);
  assert.deepEqual(plain(dispatched[0].selection), { anchor: offset - 1, head: offset + 3 });
  f.c.undoFuzzerMarker();
  assert.equal(f.state.fuzzerRequestText, text);
});

test('targeted removal rejects partial selection and active runs without mutation or saves', () => {
  const f = fixture(), text = raw.replace('a=1', 'a=§one§&b=§two§');
  f.state.fuzzerRequestText = text;
  const visible = text.replace(/\r\n?/g, '\n');
  const selection = { from: visible.lastIndexOf('one') + 1, to: visible.lastIndexOf('two') + 4 };
  f.setEditor({ getContent: () => visible, view: { state: { selection: { main: selection } } } });
  assert.throws(() => f.c.removeFuzzerEditorPosition(), /whole marked position/);
  selection.from = visible.lastIndexOf('one'); selection.to = selection.from;
  for (const flag of ['fuzzerRunning', 'fuzzerRunningAttackId']) {
    f.state[flag] = true;
    assert.throws(() => f.c.removeFuzzerEditorPosition(), /current run/);
    f.state[flag] = false;
  }
  assert.equal(f.state.fuzzerRequestText, text);
  assert.equal(f.saves, 0);
});


test('Remove button follows current selection and active-run state without mutating the draft', () => {
  const f = fixture(), button = { disabled: true };
  f.c.document.getElementById = id => id === 'fuzzerRemoveMarkerButton' ? button : null;
  const text = raw.replace('a=1', 'a=§one§');
  f.state.fuzzerRequestText = text;
  const visible = text.replace(/\r\n?/g, '\n');
  const selection = { from: 0, to: 0 };
  f.setEditor({ getContent: () => visible, view: { state: { selection: { main: selection } } } });
  f.c.renderFuzzerRemoveMarkerControl(); assert.equal(button.disabled, true);
  selection.from = selection.to = visible.lastIndexOf('one');
  f.c.renderFuzzerRemoveMarkerControl(); assert.equal(button.disabled, false);
  f.state.fuzzerRunningAttackId = 'active';
  f.c.renderFuzzerRemoveMarkerControl(); assert.equal(button.disabled, true);
  assert.equal(f.saves, 0); assert.equal(f.state.fuzzerRequestText, text);
});


test('textarea removal fallback keeps values and clear-all still ignores the selection', () => {
  const f = fixture(), text = raw.replace('a=1', 'a=§one§&b=§two§');
  f.state.fuzzerRequestText = text;
  const visible = text.replace(/\r\n?/g, '\n');
  const at = visible.lastIndexOf('one');
  let focused = 0, restored = null;
  f.els.fuzzerRequestEditor = { value: visible, selectionStart: at, selectionEnd: at,
    setSelectionRange(from, to) { restored = [from, to]; }, focus() { focused++; } };
  f.c.removeFuzzerEditorPosition();
  assert.equal(f.state.fuzzerRequestText, text.replace('§one§', 'one'));
  assert.deepEqual(restored, [at - 1, at + 2]); assert.equal(focused, 1);
  f.els.fuzzerRequestEditor.value = text.replace(/\r\n?/g, '\n');
  f.state.fuzzerRequestText = text;
  f.c.clearFuzzerMarkers();
  assert.equal(f.state.fuzzerRequestText, text.replace('§one§', 'one').replace('§two§', 'two'));
});


test('CodeMirror selection listener is installed once and refreshes only the Remove control', () => {
  let dispatches = 0, refreshes = 0, listener;
  const c = loadFunctions(['wireFuzzerMarkerSelection'], {
    CM: { StateEffect: { appendConfig: { of: value => value } }, EditorView: { updateListener: { of: callback => callback } } },
    renderFuzzerRemoveMarkerControl() { refreshes++; },
  });
  const editor = { view: { dispatch(value) { dispatches++; listener = value.effects; } } };
  c.wireFuzzerMarkerSelection(editor); c.wireFuzzerMarkerSelection(editor);
  assert.equal(dispatches, 1);
  listener({ selectionSet: true, docChanged: false });
  listener({ selectionSet: false, docChanged: true });
  listener({ selectionSet: false, docChanged: false });
  assert.equal(refreshes, 2); assert.equal(dispatches, 1);
  c.wireFuzzerMarkerSelection({ view: { dispatch() { dispatches++; } } });
  assert.equal(dispatches, 2);
});


test('raw offset LF fast path preserves UTF-16 coordinates and rejects invalid offsets', () => {
  const f = fixture(), text = 'GET /😀 HTTP/1.1\nHost: example.com\n\n한😀글';
  for (let offset = 0; offset <= text.length; offset++) assert.equal(f.c.fuzzerRawOffsetForEditorOffset(text, offset), offset);
  for (const offset of [-1, 0.5, NaN, Infinity, text.length + 1]) assert.throws(() => f.c.fuzzerRawOffsetForEditorOffset(text, offset), /selection changed/);
  assert.equal(f.c.fuzzerRawOffsetForEditorOffset('a\r\nb', 2), 3);
  assert.throws(() => f.c.fuzzerRawOffsetForEditorOffset('a\r\nb', 4), /selection changed/);
});

for (const nl of ['\n', '\r\n']) for (const value of ['😀한e\u0301', 'oneone']) {
  test(`actual marker actions create Undo records and preserve raw bytes (${JSON.stringify({ nl, value })})`, () => {
    const f = fixture();
    const before = `POST /?q=${value}&q=${value} HTTP/1.1${nl}Host: example.com${nl}X-Repeat: ${value}${nl}${nl}body=${value}`;
    f.state.fuzzerRequestText = before;
    // Textarea fallback exposes normalized coordinates, as the browser editor does.
    const input = f.els.fuzzerRequestEditor = {
      value: before.replace(/\r\n/g, '\n'), selectionStart: 0, selectionEnd: 0,
      focus() {}, setSelectionRange(from, to) { this.selectionStart = from; this.selectionEnd = to; },
    };
    const render = f.c.renderFuzzer;
    f.c.renderFuzzer = () => {
      render();
      input.value = f.state.fuzzerRequestText.replace(/\r\n/g, '\n');
    };
    const start = before.indexOf('body=') + 5, end = start + value.length;
    const select = (text, from, to) => {
      input.value = text.replace(/\r\n/g, '\n');
      input.selectionStart = text.slice(0, from).replace(/\r\n/g, '\n').length;
      input.selectionEnd = text.slice(0, to).replace(/\r\n/g, '\n').length;
    };
    const marked = before.slice(0, start) + '§' + value + '§' + before.slice(end);
    select(before, start, end);
    f.c.markFuzzerEditorSelection();
    assert.equal(f.state.fuzzerRequestText, marked);
    assert.equal(f.state._fuzzerMarkerUndo.before, before);
    assert.equal(f.state._fuzzerMarkerUndo.after, marked);
    f.c.undoFuzzerMarker();
    assert.equal(f.state.fuzzerRequestText, before);
    assert.equal(f.state._fuzzerMarkerUndo, null);
    select(before, start, end);
    f.c.markFuzzerEditorSelection();
    select(marked, start, end + 2);
    f.c.removeFuzzerEditorPosition();
    assert.equal(f.state.fuzzerRequestText, before);
    assert.equal(f.state._fuzzerMarkerUndo.before, marked);
    assert.equal(f.state._fuzzerMarkerUndo.after, before);
    f.c.undoFuzzerMarker();
    assert.equal(f.state.fuzzerRequestText, marked);
    assert.equal(f.state._fuzzerMarkerUndo, null);
    input.value = marked.replace(/\r\n/g, '\n');
    f.c.clearFuzzerMarkers();
    assert.equal(f.state.fuzzerRequestText, before);
    f.c.undoFuzzerMarker();
    assert.equal(f.state.fuzzerRequestText, marked);
    assert.equal(f.state._fuzzerMarkerUndo, null);
  });
}
