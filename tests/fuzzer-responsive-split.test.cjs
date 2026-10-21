// Source-function geometry and CSS contracts, not native browser layout verification.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');

function node(width) {
  const listeners = new Map(), properties = new Map(), classes = new Set();
  return { offsetWidth: width, listeners, properties,
    style: { setProperty: (key, value) => properties.set(key, value), removeProperty: key => properties.delete(key) },
    classList: { add: key => classes.add(key), remove: key => classes.delete(key), contains: key => classes.has(key) },
    addEventListener: (type, callback) => listeners.set(type, callback),
  };
}
function fixture(templateWidth = 700, payloadWidth = 290) {
  const handle = node(10), top = node(templateWidth + payloadWidth + 10);
  const template = node(templateWidth), payload = node(payloadWidth), body = node(0), listeners = new Map();
  const document = { body, getElementById: id => id === 'fuzzerColResizer' ? handle : null,
    querySelector: selector => ({ '.fuzzer-top-row': top, '.fuzzer-template-card': template, '.fuzzer-payloads-card': payload })[selector],
    addEventListener: (type, callback) => listeners.set(type, callback), removeEventListener: type => listeners.delete(type) };
  const c = loadFunctions(['initFuzzerResizers'], { document, els: { fuzzerDetailPanel: null } });
  c.initFuzzerResizers();
  return { handle, top, template, payload, body, listeners,
    drag(delta) { handle.listeners.get('mousedown')({ clientX: 500, preventDefault() {} }); listeners.get('mousemove')?.({ clientX: 500 + delta }); listeners.get('mouseup')?.(); },
    share() { return Number(top.properties.get('--fuzzer-request-share')); } };
}

test('drag records a ratio rather than fixed pixel widths that overflow a narrower window', () => {
  const f = fixture(); f.drag(50);
  assert.equal(f.share(), 750 / 990);
  f.top.offsetWidth = 600;
  assert.equal(f.share(), 750 / 990);
  assert.equal(f.template.style.flex, undefined); assert.equal(f.payload.style.flex, undefined);
  assert.equal(f.listeners.size, 0); assert.equal(f.body.classList.contains('pane-resizing-x'), false);
  assert.match(css, /\.fuzzer-template-card\s*\{\s*flex: var\(--fuzzer-request-share, 0\.72\) 1 0px;/);
  assert.match(css, /\.fuzzer-payloads-card\s*\{\s*flex: calc\(1 - var\(--fuzzer-request-share, 0\.72\)\) 1 0px;/);
});

test('dragging honors both editor minimums and double-click restores the default split', () => {
  const f = fixture(); f.drag(-10000); assert.equal(f.share(), 240 / 990);
  f.drag(10000); assert.equal(f.share(), 830 / 990);
  f.handle.listeners.get('dblclick')(); assert.equal(f.top.properties.has('--fuzzer-request-share'), false);
  assert.match(css, /\.fuzzer-template-card\s*\{[^}]*min-width: 240px;/);
  assert.match(css, /\.fuzzer-payloads-card\s*\{[^}]*min-width: 160px;/);
});

test('zero-width hidden editors do not begin a resize or store an invalid ratio', () => {
  const f = fixture(0, 0); f.drag(50);
  assert.equal(f.top.properties.has('--fuzzer-request-share'), false);
  assert.equal(f.listeners.size, 0); assert.equal(f.body.classList.contains('pane-resizing-x'), false);
});

test('every stacked breakpoint hides ineffective drag handles and keeps editor minimums', () => {
  const start = css.indexOf('@media (max-width: 1240px)');
  const end = css.indexOf('@media (max-width: 760px)', start);
  assert.ok(start >= 0 && end > start, 'Expected the complete 1240px breakpoint block');
  const stacked = css.slice(start, end);
  assert.match(stacked, /\.fuzzer-top-row\s*\{[^}]*flex-direction: column;[^}]*height: auto !important;/);
  assert.match(stacked, /\.fuzzer-payloads-card\s*\{[^}]*flex: none !important;[^}]*min-height: 220px;/);
  assert.match(stacked, /\.fuzzer-col-resizer,\s*\.fuzzer-row-resizer\s*\{\s*display: none;/);
  const narrow = css.slice(css.lastIndexOf('@media (max-width: 620px)'));
  assert.match(narrow, /\.fuzzer-top-row > \.fuzzer-payloads-card\s*\{[^}]*min-width: 0;/);
});
