const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
const { editorFixture, source } = require('./replay-editor-fixture.cjs');

const context = loadFunctions(['replayRequestHexText', 'toHexDumpFromBytes'], {
  TextEncoder, TextDecoder, Uint8Array, atob, btoa,
});
const header = 'POST /binary HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/octet-stream\r\n\r\n';
function bytesFromHex(text) {
  return Buffer.from(text.split('\n').filter(line => /^[0-9a-f]{8}  /.test(line))
    .flatMap(line => (line.slice(10, 59).match(/[0-9a-f]{2}/g) || []).map(byte => parseInt(byte, 16))));
}
function tabFor(bytes, head = header) {
  return { baseRequest: { body_encoding: 'base64' }, requestText: head + Buffer.from(bytes).toString('base64') };
}

for (const bytes of [[], [0, 255, 128, 13, 10], Array.from({ length: 256 }, (_, i) => i)]) {
  for (const cached of [false, true]) test(`binary Hex displays decoded ${bytes.length} bytes, cache=${cached}`, () => {
    const tab = tabFor(bytes);
    if (cached) {
      tab.requestBytes = new TextEncoder().encode(tab.requestText);
      tab.requestOriginalBytes = new Uint8Array(tab.requestBytes);
    }
    const before = JSON.stringify(tab), cache = tab.requestBytes;
    assert.deepEqual(bytesFromHex(context.replayRequestHexText(tab)), Buffer.concat([Buffer.from(header), Buffer.from(bytes)]));
    assert.equal(JSON.stringify(tab), before);
    assert.equal(tab.requestBytes, cache);
  });
}
for (const mime of ['application/protobuf', 'application/msgpack', 'application/cbor', 'application/grpc', 'text/plain', 'application/json', 'unknown/type']) {
  test(`Base64 representation determines Hex decoding independently of ${mime}`, () => {
    const head = header.replace('application/octet-stream', mime), tab = tabFor([8, 1], head);
    assert.deepEqual(bytesFromHex(context.replayRequestHexText(tab)), Buffer.concat([Buffer.from(head), Buffer.from([8, 1])]));
  });
}
for (const malformed of ['!', 'A', 'AA', 'AAA', 'AAAA=', '=AAA', 'AA=A', 'AA===', 'AB==', 'AAB=', 'AA==\n', ' AA==', 'AA-_', 'é', '<script>']) {
  test(`invalid Base64 ${JSON.stringify(malformed)} never becomes apparent body bytes`, () => {
    const tab = tabFor([]); tab.requestText += malformed;
    const text = context.replayRequestHexText(tab);
    assert.match(text, /Invalid Base64 body; decoded bytes unavailable/);
    assert.deepEqual(bytesFromHex(text), Buffer.from(header));
    assert.equal(tab.requestText, header + malformed);
  });
}
test('UTF-8 body is never decoded just because it looks like Base64 or has binary MIME', () => {
  const tab = { baseRequest: { body_encoding: 'utf8' }, requestText: header + 'CAE=\r\n한글🙂' };
  assert.deepEqual(bytesFromHex(context.replayRequestHexText(tab)), Buffer.from(tab.requestText));
});
test('draft without a body separator is unchanged, even when incomplete', () => {
  const tab = tabFor([]); tab.requestText = 'POST / HTTP/1.1\nHost:';
  assert.deepEqual(bytesFromHex(context.replayRequestHexText(tab)), Buffer.from(tab.requestText));
});

function fixture() {
  const f = editorFixture();
  // Use browser-compatible strict atob, not Buffer's permissive test decoder.
  Object.assign(f.context, { atob, btoa });
  f.a.baseRequest.body_encoding = 'base64';
  f.a.requestText = 'POST /a HTTP/1.1\nHost: example.com\nContent-Type: application/octet-stream\nContent-Length: 3\n\nAP+A';
  f.render();
  return f;
}
for (const mode of ['raw', 'pretty']) test(`${mode}: decoded Hex keeps bytes, send request, history and owner unchanged`, () => {
  const f = fixture();
  f.state.replayMessageViews.request = mode; f.context.renderReplayViewContent('request');
  const i = f.cv().getContent().indexOf('/a'); f.edit(i, i + 2, '/b');
  const draft = f.a.requestText, parsed = JSON.stringify(f.context.parseEditableRawRequest(draft, f.a.baseRequest));
  const owner = f.cv()._owner;
  for (let cycle = 0; cycle < 3; cycle++) {
    f.state.replayMessageViews.request = 'hex'; f.context.renderReplayViewContent('request');
    assert.deepEqual(bytesFromHex(f.cv().getContent()), Buffer.concat([Buffer.from(draft.slice(0, draft.indexOf('\n\n') + 2)), Buffer.from([0, 255, 128])]));
    const cache = f.a.requestBytes;
    assert.equal(new TextDecoder().decode(cache), draft, 'cache must still contain editable Base64 text');
    assert.equal(JSON.stringify(f.context.parseEditableRawRequest(f.a.requestText, f.a.baseRequest)), parsed);
    f.render(); assert.equal(f.a.requestBytes, cache); assert.equal(f.a.requestText, draft);
    f.state.replayMessageViews.request = mode; f.context.renderReplayViewContent('request');
    assert.equal(f.a.requestText, draft); assert.equal(f.cv()._owner, owner);
    assert.equal(f.undo(), true); assert.match(f.a.requestText, /^POST \/a /);
    assert.equal(f.undo(), false); assert.equal(f.redo(), true); assert.equal(f.a.requestText, draft);
  }
});
test('invalid Base64 Hex preserves draft and undo, without stale decoded bytes', () => {
  const f = fixture(), original = f.a.requestText, n = f.cv().getContent().length;
  f.edit(n - 4, n, '???');
  f.state.replayMessageViews.request = 'hex'; f.context.renderReplayViewContent('request');
  assert.match(f.cv().getContent(), /Invalid Base64 body/); assert.equal(f.a.requestText, original.slice(0, -4) + '???');
  f.state.replayMessageViews.request = 'raw'; f.context.renderReplayViewContent('request');
  assert.equal(f.undo(), true); assert.equal(f.a.requestText, original);
});
for (const render of ['renderReplay', 'renderReplayViewContent']) test(`legacy binary ${render} is read-only decoded Hex; text editing is retained`, () => {
  const f = fixture(); delete f.els.replayRequestCM;
  let binds = 0;
  f.els.replayRequestHighlight = { removeAttribute() {}, setAttribute() {}, innerHTML: '', querySelectorAll: () => [] };
  Object.assign(f.context, { bindHexByteHandlers: () => { binds++; }, renderEditableHexHtml: () => 'EDITABLE', renderHexHtml: text => `READONLY:${text}`, updateReplaySearchPane() {} });
  f.state.replayMessageViews.request = 'hex'; const before = f.a.requestText;
  f.context[render]('request');
  assert.match(f.els.replayRequestHighlight.innerHTML, /^READONLY:/); assert.equal(binds, 0);
  assert.deepEqual(bytesFromHex(f.els.replayRequestHighlight.innerHTML.slice(9)), Buffer.concat([Buffer.from(before.slice(0, before.indexOf('\n\n') + 2)), Buffer.from([0, 255, 128])]));
  assert.equal(f.a.requestText, before); assert.equal(new TextDecoder().decode(f.a.requestBytes), before);
  f.a.baseRequest.body_encoding = 'utf8'; f.a.requestText = 'GET / HTTP/1.1\nHost: example.com'; f.a.requestBytes = null;
  f.context[render]('request'); assert.equal(f.els.replayRequestHighlight.innerHTML, 'EDITABLE'); assert.equal(binds, 1);
});
