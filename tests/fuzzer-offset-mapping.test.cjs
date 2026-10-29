// Pure raw/editor coordinate mapping: no DOM, traffic, timers or saved data.
const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
const map = loadFunctions(['fuzzerRawOffsetForEditorOffset']).fuzzerRawOffsetForEditorOffset;
// Reference mapper before the bounded CRLF-pair fast path (0805c849).
function reference(raw, offset) {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > raw.length) throw new Error('The selection changed. Select a value again.');
  if (!raw.includes('\r')) return offset;
  let visibleOffset = 0;
  for (let index = 0; index < raw.length; index++) {
    if (visibleOffset === offset) return index;
    if (raw[index] === '\r' && raw[index + 1] === '\n') index++;
    visibleOffset++;
  }
  if (visibleOffset === offset) return raw.length;
  throw new Error('The selection changed. Select a value again.');
}
function outcome(fn, raw, offset) {
  try { return ['ok', fn(raw, offset)]; } catch (error) { return ['error', error.message]; }
}
function equivalent(raw) {
  for (let offset = 0; offset <= raw.length + 1; offset++) assert.deepEqual(outcome(map, raw, offset), outcome(reference, raw, offset));
}
test('bounded CRLF mapping preserves every offset around the pair budget and raw end', () => {
  for (const count of [0, 1, 127, 128, 129, 256]) {
    equivalent(('a\r\n😀\r한\n').repeat(count));
    equivalent('\r\n'.repeat(count));
  }
});
test('mixed newline and Unicode mapping remains equivalent on exhaustive short strings', () => {
  const alphabet = ['a', '\r', '\n', '😀', '한', '\uD800', '\uDC00'];
  function visit(raw, depth) {
    equivalent(raw);
    if (depth) for (const value of alphabet) visit(raw + value, depth - 1);
  }
  visit('', 4);
});
test('invalid offsets keep exact errors on both fast and fallback inputs', () => {
  for (const raw of ['', '😀\n한', 'a\r\nb', '\r\n'.repeat(129)]) {
    for (const offset of [-1, -0.5, 0.5, NaN, Infinity, -Infinity, undefined, null, '0', '2', {}, [], true, 1n, raw.length + 1]) {
      assert.deepEqual(outcome(map, raw, offset), outcome(reference, raw, offset));
    }
  }
});
