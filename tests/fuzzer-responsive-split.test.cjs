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
  const c = loadFunctions(['initFuzzerResizers'], { document, window: { addEventListener() {}, removeEventListener() {} }, els: { fuzzerDetailPanel: null } });
  c.initFuzzerResizers();
  return { handle, top, template, payload, body, listeners,
    drag(delta) { handle.listeners.get('mousedown')({ clientX: 500, preventDefault() {} }); listeners.get('mousemove')?.({ clientX: 500 + delta, buttons: 1 }); listeners.get('mouseup')?.(); },
    share() { return Number(top.properties.get('--fuzzer-request-share')); } };
}

test('drag records a ratio rather than fixed pixel widths that overflow a narrower window', () => {
  const f = fixture(); f.drag(50);
  assert.equal(f.share(), 750 / 990);
  f.top.offsetWidth = 600;
  assert.equal(f.share(), 750 / 990);
  assert.equal(f.template.style.flex, undefined); assert.equal(f.payload.style.flex, undefined);
  assert.equal(f.listeners.size, 0); assert.equal(f.body.classList.contains('pane-resizing-x'), false);
  assert.match(css, /\.fuzzer-template-card\s*\{\s*flex: var\(--fuzzer-request-share, 0\.65\) 1 0px;/);
  assert.match(css, /\.fuzzer-payloads-card\s*\{\s*flex: calc\(1 - var\(--fuzzer-request-share, 0\.65\)\) 1 0px;/);
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
  const start = css.indexOf('@media (max-width: 900px)');
  const end = css.length;
  assert.ok(start >= 0 && end > start, 'Expected the complete 900px breakpoint block');
  const stacked = css.slice(start, end);
  assert.match(stacked, /\.fuzzer-top-row\s*\{[^}]*flex-direction: column;[^}]*height: auto !important;/);
  assert.match(stacked, /\.fuzzer-payloads-card\s*\{[^}]*flex: none !important;[^}]*min-height: 220px;/);
  assert.match(stacked, /\.fuzzer-col-resizer,\s*\.fuzzer-row-resizer\s*\{\s*display: none;/);
  const narrow = css.slice(css.lastIndexOf('@media (max-width: 620px)'));
  assert.match(narrow, /\.fuzzer-top-row > \.fuzzer-payloads-card\s*\{[^}]*min-width: 0;/);
});

test('retained runs reserve table navigation beside selected detail rather than collapsing rows', () => {
  assert.match(css, /\.fuzzer-shell:not\(\.fuzzer-results-empty\) \.fuzzer-top-row\s*\{[^}]*height: 32%;[^}]*min-height: 180px;/);
  assert.match(css, /\.fuzzer-shell:not\(\.fuzzer-results-empty\) \.fuzzer-results-card\s*\{[^}]*flex: 1 0 360px;/);
  assert.match(css, /\.fuzzer-results-card > \.history-table-shell\s*\{[^}]*min-height: 132px !important;/);
  assert.match(css, /\.fuzzer-detail-panel\s*\{\s*flex: 0 1 160px;/);
});

test('detail resize reserves measured chrome and a usable table viewport', () => {
  const handle = node(0), detail = node(0), chrome = node(0), table = node(0), body = node(0);
  handle.offsetHeight = 8; detail.offsetHeight = 180; chrome.offsetHeight = 110;
  table.classList.add('history-table-shell');
  detail.parentElement = { offsetHeight: 420, children: [chrome, table, handle, detail] };
  const listeners = new Map();
  const document = { body, getElementById: id => id === 'fuzzerDetailResizer' ? handle : null,
    querySelector: () => null,
    addEventListener: (type, callback) => listeners.set(type, callback), removeEventListener: type => listeners.delete(type) };
  const c = loadFunctions(['initFuzzerResizers'], { document, window: { addEventListener() {}, removeEventListener() {} }, els: { fuzzerDetailPanel: detail } });
  c.initFuzzerResizers();
  handle.listeners.get('mousedown')({ clientY: 500, preventDefault() {} });
  listeners.get('mousemove')({ clientY: -5000, buttons: 1 });
  assert.equal(detail.style.flex, '0 0 170px');
  listeners.get('mousemove')({ clientY: 5000, buttons: 1 });
  assert.equal(detail.style.flex, '0 0 140px');
  listeners.get('mouseup')(); assert.equal(listeners.size, 0);
  handle.listeners.get('dblclick')(); assert.equal(detail.style.flex, '');
});

test('one-time nearest scrolling keeps the selected row above the fold after detail opens', () => {
  const shell = { clientHeight: 132, scrollTop: 0 }; let renders = 0;
  const c = loadFunctions(['scrollFuzzerResultToIndex'], {
    fuzzerResultsShell: () => shell, measuredFuzzerResultRowHeight: 32, FUZZER_RESULT_ROW_HEIGHT: 27,
    els: { fuzzerResultsHead: { offsetHeight: 32 } }, renderFuzzerResultsVirtual() { renders++; },
  });
  c.scrollFuzzerResultToIndex(3, { nearest: true }); assert.equal(shell.scrollTop, 28);
  c.scrollFuzzerResultToIndex(2, { nearest: true }); assert.equal(shell.scrollTop, 28);
  c.scrollFuzzerResultToIndex(0, { nearest: true }); assert.equal(shell.scrollTop, 0);
  assert.equal(renders, 3);
});

test('selected detail headers wrap their modes instead of clipping the last control', () => {
  const header = css.match(/\.fuzzer-detail-panel \.pane-header\s*\{([^}]+)\}/)?.[1] ?? '';
  assert.match(header, /flex-wrap:\s*wrap;/);
  assert.match(header, /flex-shrink:\s*0;/);
  assert.match(header, /min-width:\s*0;/);
  const tabs = css.match(/\.fuzzer-detail-panel \.view-tabs\s*\{([^}]+)\}/)?.[1] ?? '';
  assert.match(tabs, /flex-wrap:\s*wrap;/);
  assert.match(tabs, /min-width:\s*0;/);
  assert.match(tabs, /max-width:\s*100%;/);
  assert.match(tabs, /margin-left:\s*auto;/);
});

test('response metadata is bounded without consuming the detail editor or removing modes', () => {
  const meta = css.match(/#fuzzerDetailResponseMeta\s*\{([^}]+)\}/)?.[1] ?? '';
  assert.match(meta, /min-width:\s*0;/);
  assert.match(meta, /display:\s*block;/);
  assert.match(meta, /max-width:\s*100%;/);
  assert.match(meta, /overflow:\s*hidden;/);
  assert.match(meta, /text-overflow:\s*ellipsis;/);
  assert.match(meta, /white-space:\s*nowrap;/);
  const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  const modes = [...html.matchAll(/<button\b[^>]*data-fuzzer-detail-target="response"[^>]*data-fuzzer-detail-view="([^"]+)"[^>]*>/g)].map(match => match[1]);
  assert.deepEqual(modes, ['pretty', 'raw', 'hex', 'render']);
});

test('results card vertical scrolling wins over generic panel clipping without changing sizing', () => {
  // Check the effective late override, not the earlier overflow:auto which lost
  // to .panel-card's later shorthand and left a focus-scrolled header hidden.
  const selector = '.fuzzer-shell .fuzzer-results-card';
  const rule = [...css.matchAll(/\.fuzzer-shell \.fuzzer-results-card\s*\{([^}]+)\}/g)].at(-1);
  assert.ok(rule, 'Expected a scoped results-card scrolling override');
  assert.ok(rule.index > css.lastIndexOf('.panel-card {'), 'Override follows generic panel-card clipping');
  assert.deepEqual(rule[1].trim().split(';').map(s => s.trim()).filter(Boolean), ['overflow-y: auto', 'overflow-x: hidden']);
  assert.equal(css.lastIndexOf(selector + ' {'), rule.index, 'No later identical selector supersedes the override');
  const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  assert.match(html, /class="history-table-shell" style="flex:1;min-height:0;overflow:auto"/);
});
