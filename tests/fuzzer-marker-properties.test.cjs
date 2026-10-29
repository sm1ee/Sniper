// Deterministic, synthetic transformations only: no network or application bootstrap.
const assert = require('node:assert/strict');
const test = require('node:test');
const workflow = require('../web/fuzzer-workflow.js');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
const map = loadFunctions(['fuzzerRawOffsetForEditorOffset']).fuzzerRawOffsetForEditorOffset;
const values = ['', 'oneone', '한글', '😀한😀', 'e\u0301', '👩‍💻', '$&$1', 'a%20b'];
function request(value, nl, absolute) {
  const raw = `POST ${absolute ? 'https://example.com' : ''}/?q=${value}&q=${value} HTTP/1.1${nl}Host: example.com${nl}X-Value: ${value}${nl}X-Literal: §${nl}Y-Literal: §${nl}${nl}first=${value}${nl}again=${value}`;
  const spans = ['?q=', '&q=', 'X-Value: ', 'first=', 'again='].map(prefix => {
    const from = raw.indexOf(prefix) + prefix.length;
    return { from, to: from + value.length };
  });
  return { raw, spans };
}
function boundaries(value) {
  const positions = [0];
  for (const cp of value) positions.push(positions.at(-1) + cp.length);
  return positions;
}
for (const nl of ['\n', '\r\n']) for (const absolute of [false, true]) for (const value of values) {
  test(`marker splice and selection invariants: ${JSON.stringify({ nl, absolute, value })}`, () => {
    const { raw, spans } = request(value, nl, absolute);
    assert.equal(workflow.clearRequestPositions(raw), raw); // Isolated literal § are not a pair across fields.
    for (const span of spans) {
      // Whole value, caret, and code-point suffixes cover distinct offsets without a quadratic matrix.
      for (const offset of boundaries(value)) {
        const start = span.from + offset, end = span.to;
        const marked = workflow.markRequestSelection(raw, start, end);
        const expected = raw.slice(0, start) + '§' + raw.slice(start, end) + '§' + raw.slice(end);
        assert.equal(marked, expected); // Independent splice oracle, not another workflow helper.
        assert.equal(workflow.clearRequestPositions(marked), raw);
        const removed = workflow.removeRequestSelection(marked, start, end + 2);
        assert.equal(removed.text, raw);
        assert.equal(removed.from, start);
        assert.equal(removed.to, end);
        for (const pos of [start, end]) {
          // Prefix normalization supplies an independent editor-coordinate oracle.
          assert.equal(map(raw, raw.slice(0, pos).replace(/\r\n/g, '\n').length), pos);
        }
      }
    }
    // Add in reverse source order so offsets do not depend on production position discovery.
    let marked = raw;
    for (const { from, to } of [...spans].reverse()) marked = workflow.markRequestSelection(marked, from, to);
    let expected = '', cursor = 0;
    for (const { from, to } of spans) {
      expected += raw.slice(cursor, from) + '§' + raw.slice(from, to) + '§';
      cursor = to;
    }
    expected += raw.slice(cursor);
    assert.equal(marked, expected);
    assert.equal(workflow.clearRequestPositions(marked), raw);
    const all = workflow.removeRequestSelection(marked, spans[0].from, spans.at(-1).to + spans.length * 2);
    assert.equal(all.text, raw);
    assert.equal(all.from, spans[0].from);
    assert.equal(all.to, spans.at(-1).to);
    for (let rank = 0; rank < spans.length; rank++) {
      const { from, to } = spans[rank], start = from + rank * 2, end = to + rank * 2 + 2;
      const removed = workflow.removeRequestSelection(marked, start, end);
      assert.equal(removed.text, marked.slice(0, start) + raw.slice(from, to) + marked.slice(end));
      assert.equal(removed.from, start);
      assert.equal(removed.to, end - 2);
      assert.equal(workflow.clearRequestPositions(removed.text), raw);
    }
  });
}
test('Add rejects selection endpoints inside surrogate pairs or CRLF', () => {
  const raw = 'GET /?q=😀 HTTP/1.1\r\nHost: example.com\r\n\r\n😀\r\nend';
  for (const pos of [raw.indexOf('😀'), raw.lastIndexOf('😀')]) {
    assert.throws(() => workflow.markRequestSelection(raw, pos, pos + 1));
    assert.throws(() => workflow.markRequestSelection(raw, pos + 1, pos + 2));
  }
  for (const cr of [raw.indexOf('\r\n'), raw.lastIndexOf('\r\n')]) {
    assert.throws(() => workflow.markRequestSelection(raw, cr + 1, cr + 1));
  }
});
