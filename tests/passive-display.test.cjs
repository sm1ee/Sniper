const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
const noop = () => {};
const element = () => ({ innerHTML: '', classList: { remove: noop, add: noop } });
const els = {
  frameDetailMeta: element(), frameDetailBody: element(),
  frameDetailResizer: element(), frameDetailPanel: element(),
};
const state = { messageViews: { request: 'pretty', response: 'pretty' } };
const c = loadFunctions([
  'prettyJsonText', 'prettyFormat', 'renderBody', 'binaryBodyPlaceholder', 'formatSize', 'formatTimestamp',
  'normalizedHeaders', 'headerNameEquals', 'mergeHeaders', 'buildRawRequestHead',
  'buildRawResponseHead', 'buildRawRequest', 'buildRawResponse', 'buildMessagePresentation',
  'buildMessageHexPresentation', 'toHexDumpFromHttpParts', 'messageBodyBytes', 'base64ToBytes',
  'toHexDumpFromBytes', 'toHexDump', 'renderBinaryFrameDetailText', 'renderFramePreview',
  'showFrameDetail', 'normalizeWebsocketFrame', 'normalizeWebsocketFrames', 'escapeHtml',
  'highlightBodyLine', 'looksLikeJson', 'looksLikeMarkup', 'looksLikeFormEncoded',
  'highlightJsonLine', 'highlightMarkupLine', 'highlightMarkupToken', 'highlightMarkupAttributes',
  'highlightMarkupPunctuation', 'highlightCssLine', 'highlightCssValue', 'highlightJavaScriptLine',
  'highlightQueryString', 'renderHexHtml', 'wrapCodeLine',
], {
  state, els, TextEncoder, TextDecoder, atob, Uint8Array,
  WEBSOCKET_FRAME_ROW_PREVIEW_CHARS: 160,
  HISTORY_TIME_FORMATTER: new Intl.DateTimeFormat('en', { timeZone: 'UTC' }),
});
function message(body_preview, extras = {}) {
  return { headers: [], body_preview, body_encoding: 'utf8', body_size: Buffer.byteLength(body_preview),
    preview_truncated: false, content_type: 'application/json', ...extras };
}
function record(body, extras = {}) {
  return { kind: 'http', method: 'GET', path: '/', host: 'example.com', status: 200,
    request: message(''), response: message(body, extras) };
}

test('HTTP Pretty preserves a large numeric ID exactly', () => {
  const view = c.buildMessagePresentation('response', record('{"id":9007199254740993}'));
  assert.match(view, /9007199254740993/, 'Pretty must not round captured IDs');
});
test('WebSocket detail preserves a large numeric ID exactly', () => {
  c.showFrameDetail({ index: 0, kind: 'text', direction: 'server_to_client',
    ...message('{"id":9007199254740993}') });
  assert.match(els.frameDetailBody.innerHTML, /9007199254740993/, 'Opening frame detail must not round IDs');
});
test('truncated text Hex contains only stored preview bytes', () => {
  const msg = message('abc', { body_size: 1024, preview_truncated: true });
  assert.deepEqual(Array.from(c.messageBodyBytes(msg)), Array.from(Buffer.from('abc')),
    'The truncation notice is UI metadata, not captured bytes');
});
test('truncated binary Hex makes incompleteness visible', () => {
  state.messageViews.response = 'hex';
  try {
    const view = c.buildMessagePresentation('response', record('AAEC/w==', {
      body_encoding: 'base64', body_size: 1024, content_type: 'application/octet-stream', preview_truncated: true,
    }));
    assert.match(view, /truncat|incomplete|preview/i, 'A partial binary dump needs a visible truncation notice');
  } finally { state.messageViews.response = 'pretty'; }
});
test('empty and missing body metadata render without exceptions', () => {
  for (const msg of [null, {}, message('')]) {
    assert.equal(c.renderBody(msg), '');
    assert.equal(c.messageBodyBytes(msg).length, 0);
  }
});
test('Unicode text stays byte-exact in raw and hex preparation', () => {
  const body = 'café 文 😀 e\u0301\nline two\tend';
  const msg = message(body, { content_type: 'text/plain' });
  assert.equal(c.renderBody(msg), body);
  assert.deepEqual(Array.from(c.messageBodyBytes(msg)), Array.from(Buffer.from(body)));
});
test('large ordinary text stays byte-exact', () => {
  const body = 'abcdef 文 😀\n'.repeat(8192);
  const msg = message(body, { content_type: 'text/plain' });
  assert.equal(c.renderBody(msg), body);
  assert.deepEqual(Array.from(c.messageBodyBytes(msg)), Array.from(Buffer.from(body)));
});
test('complete binary hex preserves all byte values', () => {
  const bytes = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
  assert.deepEqual(Array.from(c.messageBodyBytes(message(bytes.toString('base64'), { body_encoding: 'base64' }))), Array.from(bytes));
});
test('invalid saved base64 detail shows a useful notice without throwing', () => {
  const text = c.renderBinaryFrameDetailText({ body_preview: 'ordinary invalid base64', body_size: 10 });
  assert.match(text, /Invalid base64 preview/);
});
test('missing and harmless malformed header metadata normalizes safely', () => {
  assert.equal(c.normalizedHeaders(null).length, 0);
  assert.equal(c.normalizedHeaders({}).length, 0);
  assert.deepEqual(JSON.parse(JSON.stringify(c.normalizedHeaders([null, {}, { name: 'x-example', value: 0 }]))), [{ name: 'x-example', value: '0' }]);
});
test('missing and invalid saved sizes and timestamps use neutral labels', () => {
  for (const value of [undefined, null, '', 'unknown']) assert.equal(c.formatTimestamp(value), '-');
  for (const value of [undefined, null, '', -1, 'unknown']) assert.equal(c.formatSize(value), '0 B');
  assert.equal(c.formatSize('1024'), '1.0 KB');
});
test('harmless malformed frame collection normalizes safely', () => {
  assert.equal(c.normalizeWebsocketFrames(null).length, 0);
  const frames = c.normalizeWebsocketFrames([null, 1, 'old data', { body_preview: 42 }]);
  assert.equal(frames.length, 1);
  assert.equal(frames[0].body_preview, '42');
});
test('invalid JSON stays intact in Pretty', () => {
  const text = 'HTTP/1.1 200\n\n{"part":';
  assert.equal(c.prettyFormat(text, message('{"part":')), text);
});
test('ordinary Unicode JSON formats correctly', () => {
  const body = '{"text":"café 文 😀","ok":true,"n":42}';
  const text = c.prettyFormat('HTTP/1.1 200\n\n' + body, message(body));
  assert.equal(text, 'HTTP/1.1 200\n\n' + JSON.stringify(JSON.parse(body), null, 2));
});

function visibleText(html) {
  return html.replace(/<[^>]+>/g, '').replace(/&nbsp;/g, '\u00a0').replace(/&#039;/g, "'").replace(/&quot;/g, '"').replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&amp;/g, '&');
}
function frameText(body) {
  c.showFrameDetail({ index: 0, kind: 'text', direction: 'server_to_client', ...message(body) });
  return visibleText(els.frameDetailBody.innerHTML);
}
test('plain WebSocket key-value text preserves extra equals', () => {
  assert.equal(frameText('message=hello=world'), 'message=hello=world');
});
test('plain WebSocket text preserves base64 padding', () => {
  assert.equal(frameText('YQ=='), 'YQ==');
});
test('Unicode and empty WebSocket detail render without exceptions', () => {
  assert.equal(frameText('café 文 😀'), 'café 文 😀');
  assert.equal(frameText(''), '(empty)');
});
test('large Unicode WebSocket detail stays intact through real highlighting', () => {
  const body = 'café 文 😀 line\n'.repeat(4096).trimEnd();
  assert.equal(frameText(body), body);
});

test('Pretty preserves numeric lexemes, duplicate keys, and property order', () => {
  const body = '{"2":9007199254740993,"1":-0,"id":1e400,"id":1E-400,"decimal":0.12345678901234567890}';
  assert.equal(c.prettyJsonText(body), [
    '{', '  "2": 9007199254740993,', '  "1": -0,', '  "id": 1e400,',
    '  "id": 1E-400,', '  "decimal": 0.12345678901234567890', '}',
  ].join('\n'));
});
test('Pretty preserves escaped string lexemes and punctuation inside strings', () => {
  const token = String.raw`"quotes \" braces {[]},: backslash \\ newline \n unicode \uD83D\uDE00"`;
  assert.equal(c.prettyJsonText(`{"text":${token}}`), `{\n  "text": ${token}\n}`);
});
test('Pretty handles scalar JSON and empty nested collections', () => {
  for (const body of ['null', 'true', 'false', '-0', '1e400', '"😀"', '{}', '[]']) {
    assert.equal(c.prettyJsonText(` \t${body}\r\n`), body);
  }
  assert.equal(c.prettyJsonText('{"a":[],"b":{},"c":[{},[]]}'),
    '{\n  "a": [],\n  "b": {},\n  "c": [\n    {},\n    []\n  ]\n}');
});
test('Pretty leaves deeply nested valid JSON intact instead of expanding indentation', () => {
  const body = '['.repeat(101) + '9007199254740993' + ']'.repeat(101);
  assert.equal(c.prettyJsonText(body), body);
});
test('Pretty auto-detection also preserves exact numeric lexemes', () => {
  const text = 'HTTP/1.1 200\n\n{"id":9007199254740993}';
  assert.equal(c.prettyFormat(text, message('', { content_type: 'text/plain' })),
    'HTTP/1.1 200\n\n{\n  "id": 9007199254740993\n}');
});
test('large ordinary JSON formats consistently without modifying its source', () => {
  const value = { rows: Array.from({ length: 2000 }, (_, i) => ({ i, text: 'café 文 😀' })) };
  const body = JSON.stringify(value);
  assert.equal(c.prettyJsonText(body), JSON.stringify(value, null, 2));
});

function bytesFromHex(text) {
  return text.split('\n').filter(line => /^[0-9a-f]{8}  /i.test(line))
    .flatMap(line => (line.slice(10, 59).match(/[0-9a-f]{2}/g) || []).map(hex => parseInt(hex, 16)));
}
test('request and response Hex keep truncation notices outside both text and binary byte dumps', () => {
  for (const target of ['request', 'response']) {
    for (const [preview, body_encoding, bytes] of [
      ['abc 文 😀', 'utf8', Buffer.from('abc 文 😀')],
      ['AAEC/w==', 'base64', Buffer.from([0, 1, 2, 255])],
      ['', 'utf8', Buffer.alloc(0)],
      ['', 'base64', Buffer.alloc(0)],
    ]) {
      const r = record('');
      r[target] = message(preview, { body_encoding, body_size: 1024, preview_truncated: true });
      state.messageViews[target] = 'hex';
      try {
        const view = c.buildMessagePresentation(target, r);
        const head = target === 'request' ? c.buildRawRequestHead(r) : c.buildRawResponseHead(r);
        const expected = Buffer.concat([Buffer.from(head), ...(bytes.length ? [Buffer.from('\n\n'), bytes] : [])]);
        assert.deepEqual(bytesFromHex(view), Array.from(expected));
        assert.equal(view.match(/\[preview truncated\]/g)?.length, 1);
        assert.ok(visibleText(c.renderHexHtml(view)).endsWith('[preview truncated]'));
      } finally { state.messageViews[target] = 'pretty'; }
    }
  }
});
test('complete Hex does not acquire a truncation notice', () => {
  const r = record('abc', { content_type: 'text/plain' });
  assert.doesNotMatch(c.buildMessageHexPresentation('response', r, c.buildRawResponse(r)), /preview truncated/);
});
test('CodeMirror Hex decorations leave the standalone notice untouched', () => {
  const h = loadFunctions(['buildHexDecorations'], { CM: { Decoration: {
    none: [], set: ranges => ranges,
    mark: () => ({ range: (from, to) => ({ from, to }) }),
  } } });
  const dump = c.toHexDump('abc');
  const text = `${dump}\n\n[preview truncated]`;
  const ranges = h.buildHexDecorations({ state: { doc: { toString: () => text } } });
  assert.ok(ranges.length > 0);
  assert.ok(ranges.every(range => range.to <= dump.length));
});
test('plain WebSocket key-value text preserves bare components and surrounding whitespace', () => {
  for (const body of ['flag=one&bare&&name=two=three', '  message=hello=world  ', '=value==', '===']) {
    assert.equal(frameText(body), body);
  }
});
