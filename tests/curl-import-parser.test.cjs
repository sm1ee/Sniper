// Ordinary synthetic strings only. Load the production parser, importer and
// registered modal callbacks without app bootstrap, HTTP, cURL or Replay sends.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');

function fixture() {
  const nodes = new Map(), toasts = [], renders = [];
  const document = { activeElement: null, getElementById: id => nodes.get(id) || null };
  for (const id of ['curlImportModal', 'curlImportInput', 'closeCurlImportButton', 'applyCurlImportButton']) {
    const classes = new Set(id === 'curlImportModal' ? ['hidden'] : []);
    nodes.set(id, { id, value: '', handlers: new Map(),
      classList: { add: x => classes.add(x), remove: x => classes.delete(x), contains: x => classes.has(x) },
      focus() { document.activeElement = this; },
      addEventListener(type, callback) { this.handlers.set(type, callback); },
      click() { this.handlers.get('click')?.({ target: this }); },
    });
  }
  const modal = nodes.get('curlImportModal');
  const state = { replayTabs: [], activeReplayTabId: null, activeTool: 'history' };
  let nextId = 1;
  const c = loadFunctions([
    'parseCurlCommand', 'splitShellWords', 'decodeAnsiCStringEscape', 'shellQuote',
    'encodeCurlDataUrlencode', 'curlDataBinaryBodyIsPlainText', 'appendCurlGetQuery',
    'defaultHttpPortForScheme', 'rawPathFromUrlString', 'normalizedHeaders', 'headerNameEquals', 'headerValue',
    'applyCurlImport', 'openCurlImportModal', 'closeCurlImportModal', 'normalizeReplayHttpVersion',
    'normalizeRepeaterTargetInput', 'authorityToTargetState', 'stripIpv6Brackets', 'normalizePortValue',
    'hostHeaderDiffersFromUrl', 'httpRequestAuthoritiesEquivalent', 'normalizeHttpRequestAuthority',
    'buildUrlFromTarget', 'isDefaultPortForScheme', 'joinAuthority',
  ], {
    document, URL, TextEncoder, TextDecoder, state, compareLoadGeneration: 0, curlImportReturnFocus: null,
    HTTP_METHOD_TOKEN_RE: /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/,
    showToast: (...args) => toasts.push(args), createReplayTab: () => ({ id: `synthetic-${nextId++}` }),
    setActiveTool: tool => { state.activeTool = tool; },
    renderToolPanels: () => renders.push(JSON.parse(JSON.stringify(state.replayTabs.at(-1)))),
    scheduleWorkspaceStateSave() {}, // Explicitly inert: this fixture never saves a workspace.
    isModalVisible: node => !node.classList.contains('hidden'),
    getActiveModalAction: () => ({ modal }), restoreModalFocus() {},
  });
  const start = appSource.indexOf('  document.getElementById("closeCurlImportButton").addEventListener(');
  const end = appSource.indexOf('\n\n  els.applyDisplaySettingsButton.addEventListener(', start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(appSource.slice(start, end), c);
  const markup = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  assert.match(markup, /id="applyCurlImportButton"[^>]*type="button"/);
  function importText(text) {
    nodes.get('curlImportInput').value = text;
    nodes.get('applyCurlImportButton').click();
  }
  return { c, state, nodes, modal, toasts, renders, importText };
}

function parsed(c, text) {
  const result = c.parseCurlCommand(text);
  assert.ok(result && !result.error, result?.error || 'Import failed');
  return result;
}
function headers(result, name) {
  return Array.from(result.headers).filter(h => h.name.toLowerCase() === name).map(h => h.value);
}

for (const option of ['-X MiXeD', '-XMiXeD', '--request MiXeD', '--request=MiXeD']) {
  test(`explicit method preserves the supplied token (${option})`, () => {
    const { c } = fixture();
    const result = parsed(c, `curl https://example.com/synthetic ${option} --data-raw ''`);
    assert.equal(result.method, 'MiXeD');
    assert.match(result.requestText, /^MiXeD \/synthetic HTTP\/1\.1\n/);
  });
}

for (const options of ['-X PATCH --head', '--head -X PATCH', '--request=PATCH -I', '-I --request=PATCH']) {
  test(`explicit method wins over HEAD mode in either order (${options})`, () => {
    const { c } = fixture();
    assert.equal(parsed(c, `curl https://example.com/synthetic ${options}`).method, 'PATCH');
  });
}

test('empty assignment methods fail like empty separate arguments', () => {
  const { c } = fixture();
  for (const options of ["--request=''", '--request=', "--request ''", "-X ''"]) {
    assert.match(c.parseCurlCommand(`curl https://example.com/synthetic ${options}`)?.error || '', /requires a value/);
  }
});

test('method inference, repeated explicit methods and invalid method feedback stay intact', () => {
  const { c } = fixture();
  for (const [options, method] of [['', 'GET'], ['--head', 'HEAD'], ["--data-raw ''", 'POST'],
    ["--data-raw '' --get", 'GET'], ['--get -X PATCH', 'PATCH'], ['-X POST --request PATCH', 'PATCH']]) {
    assert.equal(parsed(c, `curl https://example.com/synthetic ${options}`).method, method);
  }
  assert.match(c.parseCurlCommand("curl https://example.com/synthetic --request 'NOT A METHOD'").error, /Invalid HTTP method/);
});

for (const options of [
  `--json '{"x":1}' -H 'content-type: application/problem+json' -H 'ACCEPT: application/custom+json'`,
  `-H 'content-type: application/problem+json' -H 'ACCEPT: application/custom+json' --json '{"x":1}'`,
  `--json '{"x":' --header='content-type: application/problem+json' --json '1}' --header='ACCEPT: application/custom+json'`,
]) {
  test(`JSON default headers yield to explicit headers (${options})`, () => {
    const { c } = fixture();
    const result = parsed(c, `curl https://example.com/synthetic ${options}`);
    assert.deepEqual(headers(result, 'content-type'), ['application/problem+json']);
    assert.deepEqual(headers(result, 'accept'), ['application/custom+json']);
    assert.equal(result.body, '{"x":1}');
  });
}

test('JSON keeps repeated explicit headers in order and supplies only missing defaults', () => {
  const { c } = fixture();
  const result = parsed(c, `curl https://example.com/synthetic --json '{}' -H 'Accept: one' -H 'accept: two' -H 'X-Note: first' -H 'X-Note: second'`);
  assert.deepEqual(headers(result, 'accept'), ['one', 'two']);
  assert.deepEqual(headers(result, 'content-type'), ['application/json']);
  assert.deepEqual(headers(result, 'x-note'), ['first', 'second']);
  const defaults = parsed(c, `curl https://example.com/synthetic --json '{}' --json ''`);
  assert.deepEqual(headers(defaults, 'content-type'), ['application/json']);
  assert.deepEqual(headers(defaults, 'accept'), ['application/json']);
});

test('registered Import callback displays the current parse and never reuses an older successful result', () => {
  const f = fixture(); f.c.openCurlImportModal();
  f.importText(`curl https://example.com/first --json '{"x":1}' -H 'Content-Type: application/problem+json'`);
  assert.equal(f.state.replayTabs.length, 1);
  assert.equal(f.renders.length, 1);
  const first = JSON.stringify(f.state.replayTabs[0]);
  assert.deepEqual(headers(f.renders[0].baseRequest, 'content-type'), ['application/problem+json']);
  assert.equal(f.modal.classList.contains('hidden'), true);

  f.c.openCurlImportModal();
  assert.equal(f.nodes.get('curlImportInput').value, '');
  for (const text of ["curl https://example.com/second --data-raw 'unfinished", 'curl https://example.com/second --request=']) {
    f.importText(text);
    assert.equal(f.state.replayTabs.length, 1);
    assert.equal(f.renders.length, 1);
    assert.equal(JSON.stringify(f.state.replayTabs[0]), first);
    assert.equal(f.modal.classList.contains('hidden'), false);
    assert.equal(f.toasts.at(-1)[1], 'error');
  }
  f.importText(`curl --data-raw 'https://example.com/body-only?note=hello world' --url 'https://example.com/second?q=one' -X MiXeD`);
  assert.equal(f.state.replayTabs.length, 2);
  assert.equal(f.state.activeReplayTabId, f.state.replayTabs[1].id);
  assert.equal(f.renders[1].baseRequest.method, 'MiXeD');
  assert.equal(f.renders[1].baseRequest.path, '/second?q=one');
  assert.equal(f.renders[1].baseRequest.body, 'https://example.com/body-only?note=hello world');
  assert.equal(JSON.stringify(f.state.replayTabs[0]), first);
});

test('ordinary quoting, empty values, URL/body separation and malformed feedback remain explicit', () => {
  const f = fixture();
  for (const text of [
    `curl 'https://example.com/synthetic?q=one' --data-raw 'hello world'`,
    `curl --data-raw "hello world" --url="https://example.com/synthetic?q=one"`,
    `curl --data-raw hello' 'world https://example.com/synthetic?q=one`,
  ]) {
    const result = parsed(f.c, text);
    assert.equal(result.path, '/synthetic?q=one'); assert.equal(result.body, 'hello world');
  }
  for (const option of ['--data-raw', '--json']) {
    const result = parsed(f.c, `curl https://example.com/synthetic ${option} ''`);
    assert.equal(result.body, ''); assert.equal(result.method, 'POST'); assert.ok(result.requestText.endsWith('\n\n'));
  }
  f.c.openCurlImportModal();
  for (const text of ['', 'echo hello', "curl https://example.com/synthetic -H 'missing colon'",
    'curl https://example.com/synthetic --data-raw', 'curl https://example.com/synthetic --http3',
    'curl https://example.com/synthetic --data @fixture.txt', 'curl https://example.com/synthetic --form field=value']) {
    f.importText(text);
    assert.equal(f.state.replayTabs.length, 0);
    assert.equal(f.modal.classList.contains('hidden'), false);
    assert.equal(f.toasts.at(-1)[1], 'error');
  }
});

for (const option of ["-H 'X-Empty;'", "-H'X-Empty;'", "--header 'X-Empty;'", "--header='X-Empty;'"]) {
  test(`documented empty header form survives Import callback (${option})`, () => {
    const f = fixture(); f.c.openCurlImportModal();
    f.importText(`curl https://example.com/synthetic ${option} -H 'X-Note: first' -H 'x-empty;' --json '{}' -H 'Content-Type;'`);
    assert.equal(f.state.replayTabs.length, 1, f.toasts.at(-1)?.[0]);
    const request = f.state.replayTabs[0].baseRequest;
    assert.deepEqual(headers(request, 'x-empty'), ['', '']);
    assert.deepEqual(headers(request, 'x-note'), ['first']);
    assert.deepEqual(headers(request, 'content-type'), ['']);
    assert.deepEqual(headers(request, 'accept'), ['application/json']);
    assert.match(f.state.replayTabs[0].requestText, /X-Empty: \nX-Note: first\nx-empty: /);
    assert.equal(f.modal.classList.contains('hidden'), true);
  });
}

test('unsupported colon-only header suppression stays explicit without creating a tab', () => {
  const f = fixture(); f.c.openCurlImportModal();
  for (const option of ["-H 'X-Empty:'", "-H 'Accept: '", "--header='Content-Type:'", "-H 'Host:'"]) {
    f.importText(`curl https://example.com/synthetic --json '{}' ${option}`);
    assert.equal(f.state.replayTabs.length, 0);
    assert.equal(f.modal.classList.contains('hidden'), false);
    assert.match(f.toasts.at(-1)?.[0] || '', /header suppression.*not supported/i);
  }
});

test('empty-field support does not accept malformed or file-backed header arguments', () => {
  const f = fixture();
  for (const value of [';', 'missing header;', 'X-Empty;extra;', '@fixture.txt', 'missing colon']) {
    assert.ok(f.c.parseCurlCommand(`curl https://example.com/synthetic -H '${value}'`).error);
  }
});
