// Synthetic conversion only. Generated command strings are never executed.
// Set SNIPER_APP_SOURCE to test these same probes against an exact source snapshot.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const source = fs.readFileSync(process.env.SNIPER_APP_SOURCE || path.join(__dirname, '../web/app.js'), 'utf8').replace(/\r\n/g, '\n');
const c = vm.createContext({ URL, TextEncoder, TextDecoder,
  document: { getElementById: () => null },
  HTTP_METHOD_TOKEN_RE: /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/,
});
for (const name of [
  'parseRequestForExport', 'parseHeaderLineForExport', 'normalizeReplayHttpVersion',
  'exportHeaderValue', 'exportableHeaderCandidates', 'buildUrlFromTarget',
  'normalizeRepeaterTargetInput', 'authorityToTargetState', 'stripIpv6Brackets',
  'normalizePortValue', 'defaultHttpPortForScheme', 'isDefaultPortForScheme', 'joinAuthority',
  'requestToCurl', 'curlHttpVersionFlag', 'urlNeedsPathAsIs', 'rawPathFromUrlString',
  'shellQuote', 'exportableHeaders', 'exportableHeadersForUrl', 'isHttpPseudoHeaderName',
  'hostHeaderDiffersFromUrl', 'httpRequestAuthoritiesEquivalent', 'normalizeHttpRequestAuthority',
  'parseCurlCommand', 'splitShellWords', 'decodeAnsiCStringEscape',
  'encodeCurlDataUrlencode', 'curlDataBinaryBodyIsPlainText', 'appendCurlGetQuery',
  'headerValue', 'normalizedHeaders', 'headerNameEquals',
]) {
  const match = source.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, 'm'));
  assert.ok(match, `Missing production function ${name}`);
  vm.runInContext(match[0], c, { filename: `web/app.js:${name}` });
}

function importUrl(target, options = '') {
  const result = c.parseCurlCommand(`curl ${options} ${c.shellQuote(`https://example.com${target}`)}`);
  assert.ok(result && !result.error, result?.error || 'Import failed');
  return result;
}
function exportTarget(target) {
  const parsed = c.parseRequestForExport(`GET ${target} HTTP/1.1\nHost: example.com`, 'https', '', '');
  assert.ok(parsed);
  assert.equal(parsed.url, `https://example.com${target}`);
  return c.requestToCurl(parsed);
}

// curl 8.13+ removes complete literal/encoded dot segments by default.
// A captured/raw HTTP target must opt out; merely emitting its URL is insufficient.
const dotTargets = [
  '/ordinary/./next', '/ordinary/../next', '/ordinary/.', '/ordinary/..',
  '/ordinary/%2e/next', '/ordinary/%2E/next', '/ordinary/%2e%2e/next',
  '/ordinary/%2E%2e/next', '/ordinary/.%2e/next', '/ordinary/%2E./next',
  '/%2e/ordinary', '/%2E%2E/ordinary', '/ordinary/%2e', '/ordinary/%2e%2E',
  '/ordinary//%2e/next', '/ordinary/%2e%2e/next?q=%2e%2e&empty=',
];
for (const target of dotTargets) {
  test(`cURL export protects complete dot segments: ${target}`, () => {
    const command = exportTarget(target);
    assert.ok(c.splitShellWords(command).includes('--path-as-is'));
    assert.equal(c.parseCurlCommand(command).path, target);
  });
  test(`explicit path-as-is import retains the raw target: ${target}`, () => {
    const result = importUrl(`${target}#section`, '--path-as-is');
    assert.equal(result.path, target);
    assert.equal(result.requestText.split('\n')[0], `GET ${target} HTTP/1.1`);
  });
}

for (const [target, expected] of [
  ['/ordinary/./next', '/ordinary/next'], ['/ordinary/../next', '/next'],
  ['/ordinary/%2e/next', '/ordinary/next'], ['/ordinary/%2E%2e/next', '/next'],
  ['/ordinary/.%2e/next', '/next'], ['/ordinary/%2E./next', '/next'],
  ['/ordinary/%2e', '/ordinary/'], ['/ordinary/%2e%2e', '/'],
  ['/ordinary/%2e%2e/next?q=%2e%2e#section', '/next?q=%2e%2e'],
]) {
  test(`default cURL import still normalizes dot segments: ${target}`, () => {
    assert.equal(importUrl(target).path, expected);
  });
}

for (const target of [
  '/ordinary', '/ordinary/file%2ename', '/ordinary/%2e%2e%2e/next',
  '/ordinary/%252e%252e/next', '/ordinary/%2e%2fnext', '/ordinary/%2f%2E%2f/next',
  '/ordinary?q=%2e%2e', '/ordinary?next=/%2e%2e/next',
  '/ordinary?x=%23section&x=%3Fnext&x=%2F&x=+',
]) {
  test(`non-dot path and query bytes are not path-normalized: ${target}`, () => {
    const command = exportTarget(target);
    assert.ok(!c.splitShellWords(command).includes('--path-as-is'));
    assert.equal(c.parseCurlCommand(command).path, target);
  });
}

test('existing literal-dot query flag decisions preserve raw query text', () => {
  for (const target of [
    '/ordinary?next=/../next', "/ordinary?next=/../next&note=it's",
    "/ordinary?next=/./next&note='quote'", '/ordinary?next=/../next&note=%27quote%27',
  ]) {
    const command = exportTarget(target);
    assert.ok(c.splitShellWords(command).includes('--path-as-is'));
    assert.equal(c.parseCurlCommand(command).path, target);
  }
});

test('fragments are excluded, while encoded query and fragment delimiters stay literal', () => {
  for (const option of ['', '--path-as-is']) {
    assert.equal(importUrl('/ordinary%23name?note=%23section%3Fvalue#ignored?x=1', option).path,
      '/ordinary%23name?note=%23section%3Fvalue');
    assert.equal(importUrl('#section', option).path, '/');
  }
});

test('declared unsupported import options remain rejected', () => {
  for (const option of ['--http3', '--http3-only', '--form field=value', '--data @fixture.txt']) {
    assert.ok(c.parseCurlCommand(`curl https://example.com/ordinary ${option}`).error);
  }
});
