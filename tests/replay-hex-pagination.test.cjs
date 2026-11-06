// Fixture-only Hex pagination. No target traffic or user session is touched.
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
const { editorFixture } = require('./replay-editor-fixture.cjs');

function dumpBytes(text) {
  return Buffer.from(text.split('\n').filter(line => /^[\da-f]{8}  /.test(line))
    .flatMap(line => (line.slice(10, 59).match(/[\da-f]{2}/g) || []).map(byte => parseInt(byte, 16))));
}
function fixture() {
  const state = { replayMessageViews: { request: 'hex', response: 'hex' } };
  const tab = { id: 'tab', requestText: '', baseRequest: { body_encoding: 'base64' } };
  let active = tab, session = 'one';
  const roots = {};
  for (const target of ['Request', 'Response']) {
    const nodes = Object.fromEntries(['[data-hex-range]', 'input', '[data-hex-pages]', '[data-hex-previous]', '[data-hex-next]'].map(key => [key, {}]));
    roots[`replay${target}HexPager`] = { hidden: true, nodes, querySelector: key => nodes[key] };
  }
  const c = loadFunctions(['replayRequestHexText', 'toHexDumpFromBytes', 'buildRawResponseHead', 'buildRawResponse', 'normalizedHeaders', 'renderBody', 'binaryBodyPlaceholder', 'formatSize'], {
    state, TextDecoder, Uint8Array, workspaceStateGeneration: 1,
    getActiveReplayTab: () => active, currentSessionId: () => session,
    document: { getElementById: id => roots[id] },
    els: { replayRequestSearchInput: {}, replayResponseSearchInput: {} },
  });
  c.renderReplayViewContent = target => c.replayHexPageText(target, active);
  return { c, tab, state, roots, setActive: value => { active = value; }, setSession: value => { session = value; } };
}

for (const encoding of ['utf8', 'base64']) for (const size of [0, 1, 4095, 4096, 4097, 8193, 65537]) {
  test(`${encoding}: every page concatenates to exactly ${size} body bytes`, () => {
    const f = fixture(), head = 'POST /synthetic HTTP/1.1\r\nHost: example.com\r\n\r\n';
    const bytes = Buffer.from(Array.from({ length: size }, (_, i) => encoding === 'utf8' ? 32 + i % 95 : i % 256));
    f.tab.baseRequest.body_encoding = encoding;
    f.tab.requestText = head + bytes.toString(encoding === 'base64' ? 'base64' : 'utf8');
    const before = JSON.stringify(f.tab), output = [];
    let text = f.c.replayRequestHexText(f.tab), page = f.c.replayHexPageText.pages.request;
    const count = Math.max(1, Math.ceil(page.total / page.size));
    for (let i = 0; i < count; i++) {
      page.index = i; text = f.c.replayRequestHexText(f.tab);
      assert.ok(text.length <= 19711); assert.ok(dumpBytes(text).length <= 4096);
      assert.equal(text.slice(0, 8), (i * 4096).toString(16).padStart(8, '0'));
      output.push(dumpBytes(text));
    }
    assert.deepEqual(Buffer.concat(output), Buffer.concat([Buffer.from(head), bytes]));
    assert.equal(JSON.stringify(f.tab), before);
    assert.equal(f.roots.replayRequestHexPager.hidden, page.total <= 4096);
  });
}

test('UTF-8 page boundaries, surrogate pairs and lone surrogates match TextEncoder', () => {
  const c = loadFunctions(['replayHexTextSource'], { Uint8Array });
  const text = 'A'.repeat(4095) + '🙂é文\ud800\udc00\ud800x\udfff'.repeat(1500);
  const expected = Buffer.from(text), source = c.replayHexTextSource(text);
  assert.equal(source.length, expected.length);
  for (const start of [0, 4094, 4095, 4096, 4097, 8191, 16000, expected.length - 7]) {
    assert.deepEqual(Buffer.from(source.read(start, 4096)), expected.subarray(start, start + 4096));
  }
});

test('strict request and permissive saved response match their existing Base64 rules', () => {
  const c = loadFunctions(['replayHexTextSource'], { Uint8Array });
  let seed = 42;
  const alphabet = 'ABZaz019+/= \r\n\t\f_-é';
  for (let i = 0; i < 3000; i++) {
    let value = '';
    for (let j = 0; j < i % 13; j++) { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; value += alphabet[seed % alphabet.length]; }
    for (const strict of [true, false]) {
      let expected = null;
      try { const decoded = atob(value); if (!strict || btoa(decoded) === value) expected = Buffer.from(decoded, 'binary'); } catch (_) {}
      const source = c.replayHexTextSource(value, 'base64', strict);
      assert.equal(source === null, expected === null, `${strict}: ${JSON.stringify(value)}`);
      if (source) assert.deepEqual(Buffer.from(source.read(0, source.length)), expected);
    }
  }
});

test('whitespace-heavy saved Base64 is indexed and every page decodes exactly', () => {
  const c = loadFunctions(['replayHexTextSource'], { Uint8Array });
  const expected = Buffer.from(Array.from({ length: 25000 }, (_, i) => i % 256));
  const text = expected.toString('base64').split('').join(' \r\n\t\f');
  const source = c.replayHexTextSource(text, 'base64');
  assert.equal(source.length, expected.length);
  for (let start = 0; start < expected.length; start += 4096) assert.deepEqual(Buffer.from(source.read(start, 4096)), expected.subarray(start, start + 4096));
});

test('large invalid suffix never displays a valid-looking prefix body', () => {
  const f = fixture(), head = 'POST / HTTP/1.1\n\n';
  for (const suffix of ['!', 'AB==', 'AAB=', 'AA==\n']) {
    f.tab.requestText = head + 'AAAA'.repeat(350000) + suffix;
    const text = f.c.replayRequestHexText(f.tab);
    assert.match(text, /Invalid Base64 body/); assert.deepEqual(dumpBytes(text), Buffer.from(head));
  }
});

test('10 MiB first and final pages allocate at most a page and retain every original byte', () => {
  const f = fixture(), sizes = [];
  class BoundedBytes extends Uint8Array { constructor(size) { sizes.push(size); assert.ok(size <= 4096); super(size); } }
  f.c.Uint8Array = BoundedBytes;
  const head = 'POST / HTTP/1.1\n\n', body = Buffer.alloc(10 * 1024 * 1024, 0xff);
  f.tab.requestText = head + body.toString('base64'); const draft = f.tab.requestText;
  f.c.replayRequestHexText(f.tab); const page = f.c.replayHexPageText.pages.request;
  assert.equal(page.total, Buffer.byteLength(head) + body.length);
  page.index = Math.ceil(page.total / page.size) - 1;
  const tail = dumpBytes(f.c.replayRequestHexText(f.tab));
  assert.deepEqual(tail, body.subarray(body.length - tail.length));
  assert.equal(f.tab.requestText, draft); assert.equal(f.tab.requestBytes, undefined);
  assert.ok(sizes.length > 0);
});

test('pager navigation, direct jump, bounds and scoped search are explicit', () => {
  const f = fixture(); f.tab.requestText = 'POST / HTTP/1.1\n\n' + Buffer.alloc(18000).toString('base64');
  f.c.replayRequestHexText(f.tab);
  const root = f.roots.replayRequestHexPager, n = root.nodes, page = f.c.replayHexPageText.pages.request;
  assert.equal(root.hidden, false); assert.match(n['[data-hex-range]'].textContent, /^Bytes 1–4096 of 18017$/);
  assert.equal(n['[data-hex-previous]'].disabled, true); assert.equal(f.c.els.replayRequestSearchInput.placeholder, 'Search this hex page');
  n['[data-hex-next]'].onclick(); assert.equal(page.index, 1);
  n.input.value = '9999'; n.input.onchange(); assert.equal(page.index, 4); assert.equal(n['[data-hex-next]'].disabled, true);
  n.input.value = '0'; n.input.onchange(); assert.equal(page.index, 0);
  n.input.value = 'bad'; n.input.onchange(); assert.equal(page.index, 0);
  n.input.value = '3'; n.input.onkeydown({ key: 'Enter', preventDefault() {} }); assert.equal(page.index, 2);
});

for (const change of ['tab', 'session', 'generation', 'draft', 'mode']) test(`page resets and stale controls cannot cross ${change}`, () => {
  const f = fixture(); f.tab.requestText = 'POST / HTTP/1.1\n\n' + Buffer.alloc(12000).toString('base64');
  f.c.replayRequestHexText(f.tab); const old = f.c.replayHexPageText.pages.request;
  const stale = f.roots.replayRequestHexPager.nodes['[data-hex-next]'].onclick; old.index = 2;
  let current = f.tab;
  if (change === 'tab') { current = { ...f.tab }; f.setActive(current); }
  if (change === 'session') f.setSession('two');
  if (change === 'generation') f.c.workspaceStateGeneration++;
  if (change === 'draft') f.tab.requestText += 'AAAA';
  if (change === 'mode') { f.state.replayMessageViews.request = 'raw'; f.c.syncReplayHexPager('request'); f.state.replayMessageViews.request = 'hex'; }
  if (change !== 'mode') { stale(); assert.equal(old.index, 2); }
  f.c.replayRequestHexText(current); assert.equal(f.c.replayHexPageText.pages.request.index, 0);
  stale(); assert.equal(f.c.replayHexPageText.pages.request.index, 0);
});

test('response pages retain truncated and malformed notices and reset on replacement', () => {
  const f = fixture(), bytes = Buffer.alloc(14000, 0xfe);
  f.tab.responseRecord = { status: 200, response_http_version: 'HTTP/2', response: { headers: [], body_encoding: 'base64', body_preview: bytes.toString('base64'), preview_truncated: true } };
  const original = JSON.stringify(f.tab.responseRecord);
  const first = f.c.replayHexPageText('response', f.tab); assert.match(first, /\[preview truncated\]/);
  assert.match(f.roots.replayResponseHexPager.nodes['[data-hex-range]'].textContent, /available$/);
  const page = f.c.replayHexPageText.pages.response; page.index = 3;
  const tail = f.c.replayHexPageText('response', f.tab); assert.match(tail, /\[preview truncated\]/);
  assert.equal(JSON.stringify(f.tab.responseRecord), original);
  f.tab.responseRecord.response = { ...f.tab.responseRecord.response, body_preview: 'AAAA'.repeat(4000) + '!', preview_truncated: false };
  const bad = f.c.replayHexPageText('response', f.tab); assert.match(bad, /Invalid base64 preview/); assert.doesNotMatch(bad, /preview truncated/);
  assert.equal(f.c.replayHexPageText.pages.response.index, 0); assert.equal(f.roots.replayResponseHexPager.hidden, true);
});

test('large request pagination preserves CodeMirror editable undo and exact send representation', () => {
  const f = editorFixture(); f.a.baseRequest.body_encoding = 'base64';
  f.a.requestText = 'POST /a HTTP/1.1\nHost: example.com\nContent-Type: application/octet-stream\n\n' + Buffer.alloc(20000, 0xff).toString('base64');
  f.render(); const index = f.cv().getContent().indexOf('/a'); f.edit(index, index + 2, '/b');
  const draft = f.a.requestText, expected = JSON.stringify(f.context.parseEditableRawRequest(draft, f.a.baseRequest)), owner = f.cv()._owner;
  for (let i = 0; i < 3; i++) {
    f.state.replayMessageViews.request = 'hex'; f.context.renderReplayViewContent('request');
    const page = f.context.replayHexPageText.pages.request; page.index = 4;
    f.context.renderReplayViewContent('request'); assert.equal(f.cv().getContent().slice(0, 8), '00004000');
    assert.equal(f.a.requestBytes, null); assert.equal(f.a.requestText, draft);
    assert.equal(JSON.stringify(f.context.parseEditableRawRequest(f.a.requestText, f.a.baseRequest)), expected);
    f.state.replayMessageViews.request = 'raw'; f.context.renderReplayViewContent('request');
    assert.equal(f.cv()._owner, owner); assert.equal(f.undo(), true); assert.match(f.a.requestText, /^POST \/a /);
    assert.equal(f.redo(), true); assert.equal(f.a.requestText, draft);
  }
});

test('passive redraw preserves an unfinished focused page jump; submit and owner replacement refresh it', () => {
  const f = fixture(); f.tab.requestText = 'POST / HTTP/1.1\n\n' + Buffer.alloc(14000).toString('base64');
  f.c.replayRequestHexText(f.tab);
  const input = f.roots.replayRequestHexPager.nodes.input;
  f.c.document.activeElement = input; input.value = '3';
  f.c.replayRequestHexText(f.tab); assert.equal(input.value, '3');
  input.onchange(); assert.equal(input.value, '3'); assert.equal(f.c.replayHexPageText.pages.request.index, 2);
  input.value = '999'; input.onchange(); assert.equal(input.value, '4');
  input.value = '2'; f.tab.requestText = f.tab.requestText.replace('POST /', 'PUT /'); f.c.replayRequestHexText(f.tab); assert.equal(input.value, '1');
});

test('hidden controls release retired source and event closures', () => {
  const f = fixture(); f.tab.requestText = 'POST / HTTP/1.1\n\n' + Buffer.alloc(12000).toString('base64');
  f.c.replayRequestHexText(f.tab);
  const n = f.roots.replayRequestHexPager.nodes;
  assert.ok(n.input._replayHexPage); assert.equal(typeof n['[data-hex-next]'].onclick, 'function');
  f.setActive({ type: 'websocket' }); f.c.syncReplayHexPager('request');
  assert.equal(f.c.replayHexPageText.pages.request, undefined);
  assert.equal(n.input._replayHexPage, null); assert.equal(n.input.onchange, null); assert.equal(n.input.onkeydown, null);
  assert.equal(n['[data-hex-previous]'].onclick, null); assert.equal(n['[data-hex-next]'].onclick, null);
});
