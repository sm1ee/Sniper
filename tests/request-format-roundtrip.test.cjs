// Pure production conversion only: generated commands are inspected as text,
// never executed. No app bootstrap, requests, clipboard or workspace writes.
const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
const toasts = [];
const c = loadFunctions([
  'parseRequestForExport', 'parseHeaderLineForExport', 'normalizeReplayHttpVersion',
  'exportHeaderValue', 'exportableHeaderCandidates', 'buildUrlFromTarget',
  'normalizeRepeaterTargetInput', 'authorityToTargetState', 'stripIpv6Brackets',
  'normalizePortValue', 'defaultHttpPortForScheme', 'isDefaultPortForScheme', 'joinAuthority',
  'requestToCurl', 'curlHttpVersionFlag', 'urlNeedsPathAsIs', 'rawPathFromUrlString',
  'shellQuote', 'exportableHeaders', 'exportableHeadersForUrl', 'isHttpPseudoHeaderName',
  'hostHeaderDiffersFromUrl', 'httpRequestAuthoritiesEquivalent', 'normalizeHttpRequestAuthority',
  'requestToPython', 'requestToFetch', 'requestToPowerShell', 'fetchExportBlockedReason', 'requestFormatExportBlockedReason',
  'parseCurlCommand', 'splitShellWords', 'decodeAnsiCStringEscape',
  'encodeCurlDataUrlencode', 'curlDataBinaryBodyIsPlainText', 'appendCurlGetQuery',
  'parseEditableRawRequest', 'splitRawHttpMessage', 'parseReplayHttpVersionToken',
  'headerValue', 'normalizedHeaders', 'headerNameEquals', 'editableRequestBodyLength', 'validateRawHttpBodyFraming',
  'replayRequestToFormat', 'replayRequestToCurl', 'replayExportBlockedReason', 'getReplayExportTarget',
  'deriveRepeaterRequest', 'getRepeaterTargetConfig', 'cloneEditableRequest',
  'recordToFormat', 'historyRequestExportBlockedReason', 'buildRawRequest', 'buildRawRequestHead', 'renderBody', 'mergeHeaders',
], {
  URL, TextEncoder, TextDecoder, document: { getElementById: () => null },
  HTTP_METHOD_TOKEN_RE: /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/,
  showToast: (...args) => toasts.push(args),
});

function tab(requestText) {
  return { requestText, targetScheme: 'https', targetHost: 'example.com', targetPort: '443',
    baseRequest: { scheme: 'https', host: 'example.com', method: 'GET', path: '/',
      headers: [{ name: 'Host', value: 'example.com' }], body: '', body_encoding: 'utf8' } };
}

for (const newline of ['\n', '\r\n']) {
  for (const method of ['GET', 'HEAD', 'MiXeD']) {
    test(`${method} single ${JSON.stringify(newline)} head terminator does not invent a body`, () => {
      const raw = `${method} /ordinary?key=one&key=two HTTP/1.1${newline}Host: example.com${newline}X-Note: fixture${newline}`;
      const parsed = c.parseRequestForExport(raw, 'https', '', '');
      assert.equal(c.splitRawHttpMessage(raw).body, '');
      assert.equal(c.parseEditableRawRequest(raw, { scheme: 'https' }).body, '');
      assert.equal(parsed.bodyProvided, false);
      assert.equal(parsed.body, '');
      assert.equal(parsed.method, method);
      assert.equal(parsed.headers.length, 2);
      const replayTab = tab(raw);
      const snapshot = JSON.stringify(replayTab);
      for (const format of ['curl', 'python', 'fetch', 'powershell']) {
        const output = c.replayRequestToFormat(format, replayTab);
        assert.ok(output, `${format}: ${toasts.at(-1)?.[0]}`);
        assert.doesNotMatch(output, /--data-raw|data =|body:|-Body /);
      }
      const imported = c.parseCurlCommand(c.replayRequestToCurl(replayTab));
      assert.equal(imported.method, method);
      assert.equal(imported.path, '/ordinary?key=one&key=two');
      assert.equal(c.parseRequestForExport(imported.requestText, imported.scheme, imported.host, imported.port).bodyProvided, false);
      assert.equal(JSON.stringify(replayTab), snapshot);
    });
  }
  test(`a request line alone with ${JSON.stringify(newline)} remains bodyless`, () => {
    assert.equal(c.parseRequestForExport(`GET / HTTP/1.1${newline}`, 'https', 'example.com', '').bodyProvided, false);
  });
  for (const body of ['', '\r\n', '\n\n', '\t café 文 😀\r\nlast\r', "'quoted' C:\\temp\\notes\n"]) {
    test(`an actual ${JSON.stringify(newline)} blank separator retains ${JSON.stringify(body)}`, () => {
      const raw = `MiXeD /ordinary HTTP/1.1${newline}Host: example.com${newline}Content-Type: text/plain${newline}${newline}${body}`;
      const parsed = c.parseRequestForExport(raw, 'https', '', '');
      assert.equal(parsed.bodyProvided, true);
      assert.deepEqual(Buffer.from(parsed.body), Buffer.from(body));
      const command = c.replayRequestToFormat('curl', tab(raw));
      assert.match(command, /--data-raw/);
      const imported = c.parseCurlCommand(command);
      assert.ok(imported && !imported.error);
      assert.equal(imported.method, 'MiXeD');
      assert.deepEqual(Buffer.from(imported.body), Buffer.from(body));
      assert.equal(c.parseRequestForExport(imported.requestText, imported.scheme, imported.host, imported.port).bodyProvided, true);
      assert.deepEqual(Buffer.from(c.parseEditableRawRequest(imported.requestText, { scheme: 'https' }).body), Buffer.from(body));
    });
  }
}

for (const path of ['/plain', '/a/../b?key=one&key=two', '/a/./b', '/a//b', '/%2f/%2F/%41/%7e?q=%2f&empty=', '/path?q=one?two&x=2']) {
  test(`History cURL round trip retains supported target ${path}`, () => {
    const record = { kind: 'http', method: 'MiXeD', scheme: 'https', host: 'example.com:8443', path, http_version: 'HTTP/1.0',
      request: { headers: [{ name: 'X-Note', value: 'one' }, { name: 'X-Between', value: "café's note" }, { name: 'x-note', value: 'two' }],
        body_preview: '', body_encoding: 'utf8', body_size: 0, preview_truncated: false } };
    const snapshot = JSON.stringify(record);
    const command = c.recordToFormat(record, 'curl');
    const imported = c.parseCurlCommand(command);
    assert.ok(imported && !imported.error);
    assert.equal(imported.path, path);
    assert.equal(imported.method, record.method);
    assert.equal(imported.httpVersion, record.http_version);
    assert.equal(imported.host, record.host);
    assert.deepEqual(Array.from(imported.headers).filter(h => h.name.toLowerCase() !== 'host').map(h => [h.name, h.value]), record.request.headers.map(h => [h.name, h.value]));
    assert.equal(JSON.stringify(record), snapshot);
  });
}

test('explicit empty GET bodies retain their existing Fetch warning', () => {
  const raw = 'GET / HTTP/1.1\nHost: example.com\n\n';
  assert.equal(c.replayRequestToFormat('fetch', tab(raw)), '');
  assert.match(toasts.at(-1)[0], /GET or HEAD requests with a body/);
});

// cURL's documented empty-field representation is Name;, whereas Name:
// suppresses a field. Inspect arguments only; never execute the output.
// https://curl.se/docs/manpage.html#-H
for (const surface of ['history', 'replay']) {
  test(`${surface} cURL export round-trips empty and repeated header fields`, () => {
    const headers = [
      { name: 'X-Empty', value: '' }, { name: 'X-Note', value: "café's note" },
      { name: 'x-empty', value: '' }, { name: 'Content-Type', value: '' },
    ];
    const raw = 'POST /ordinary HTTP/1.1\nHost: example.com\n'
      + headers.map(h => `${h.name}: ${h.value}`).join('\n') + '\n\nhello 文\r\n';
    const record = { kind: 'http', method: 'POST', scheme: 'https', host: 'example.com', path: '/ordinary', http_version: 'HTTP/1.1',
      request: { headers, body_preview: 'hello 文\r\n', body_encoding: 'utf8', body_size: 11, preview_truncated: false } };
    const command = surface === 'history' ? c.recordToFormat(record, 'curl') : c.replayRequestToFormat('curl', tab(raw));
    const words = Array.from(c.splitShellWords(command));
    const headerArgs = words.flatMap((word, index) => word === '-H' ? [words[index + 1]] : []);
    assert.deepEqual(headerArgs, ['X-Empty;', "X-Note: café's note", 'x-empty;', 'Content-Type;']);
    const imported = c.parseCurlCommand(command);
    assert.ok(imported && !imported.error, imported?.error);
    assert.deepEqual(Array.from(imported.headers).filter(h => h.name.toLowerCase() !== 'host').map(h => [h.name, h.value]), headers.map(h => [h.name, h.value]));
    assert.equal(imported.body, 'hello 文\r\n');
    assert.equal(c.parseEditableRawRequest(imported.requestText, { scheme: 'https' }).body, imported.body);
  });
}
