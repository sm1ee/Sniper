// Actual Fuzzer divider handlers with synthetic geometry and events only.
// No browser, native app, file persistence, or request traffic.
const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
function target() {
  const listeners = new Map();
  return { listeners,
    addEventListener(type, callback) { if (!listeners.has(type)) listeners.set(type, new Set()); listeners.get(type).add(callback); },
    removeEventListener(type, callback) { listeners.get(type)?.delete(callback); },
    emit(type, event = {}) { for (const callback of [...(listeners.get(type) || [])]) callback(event); },
    count(type) { return listeners.get(type)?.size || 0; },
  };
}
function node(width = 0, height = 0) {
  const classes = new Set(), properties = new Map();
  return { ...target(), offsetWidth: width, offsetHeight: height, classes, properties,
    style: { setProperty: (key, value) => properties.set(key, value), removeProperty: key => properties.delete(key) },
    classList: { add: key => classes.add(key), remove: key => classes.delete(key), contains: key => classes.has(key) },
  };
}
function fixture() {
  const handles = { col: node(8, 8), row: node(8, 8), detail: node(8, 8) };
  const top = node(1000, 220), template = node(650), payload = node(350), detail = node(0, 180), body = node();
  const chrome = node(0, 110), table = node(0, 132); table.classList.add('history-table-shell');
  top.closest = () => ({ offsetHeight: 800 });
  detail.parentElement = { offsetHeight: 600, children: [chrome, table, handles.detail, detail] };
  const window = target(), document = { ...target(), body,
    getElementById: id => ({ fuzzerColResizer: handles.col, fuzzerRowResizer: handles.row, fuzzerDetailResizer: handles.detail })[id],
    querySelector: selector => ({ '.fuzzer-top-row': top, '.fuzzer-template-card': template, '.fuzzer-payloads-card': payload })[selector],
  };
  const c = loadFunctions(['initFuzzerResizers'], { document, window, els: { fuzzerDetailPanel: detail } }); c.initFuzzerResizers();
  const start = kind => handles[kind].emit('mousedown', { clientX: 500, clientY: 500, preventDefault() {} });
  const move = (dx, dy, buttons = 1) => document.emit('mousemove', { clientX: 500 + dx, clientY: 500 + dy, buttons });
  const geometry = () => JSON.stringify([top.properties.get('--fuzzer-request-share'), top.style.height, detail.style.flex]);
  const assertStopped = () => {
    assert.equal(document.count('mousemove'), 0); assert.equal(document.count('mouseup'), 0); assert.equal(window.count('blur'), 0);
    assert.deepEqual([...body.classes], []);
    for (const handle of Object.values(handles)) assert.equal(handle.classList.contains('active'), false);
  };
  return { handles, top, template, payload, detail, body, window, document, start, move, geometry, assertStopped };
}
for (const kind of ['col', 'row', 'detail']) {
  for (const interruption of ['blur', 'no-buttons', 'mouseup']) test(`${kind} drag ends on ${interruption} without an extra geometry mutation`, () => {
    const f = fixture(); f.start(kind); f.move(20, -20);
    const before = f.geometry();
    if (interruption === 'no-buttons') f.move(100, 100, 0);
    else if (interruption === 'blur') f.window.emit('blur');
    else f.document.emit('mouseup');
    f.assertStopped(); assert.equal(f.geometry(), before);
    f.move(300, 300, 0); assert.equal(f.geometry(), before);
    f.window.emit('blur'); f.document.emit('mouseup'); f.assertStopped();
  });
  for (const next of [kind, kind === 'col' ? 'row' : 'col']) test(`${kind} drag is retired before new ${next} drag; stale callbacks cannot cancel or alter the new drag`, () => {
    const f = fixture(); f.start(kind);
    const oldMove = [...f.document.listeners.get('mousemove')][0], oldUp = [...f.document.listeners.get('mouseup')][0];
    f.start(next);
    assert.equal(f.document.count('mousemove'), 1); assert.equal(f.document.count('mouseup'), 1); assert.equal(f.window.count('blur'), 1);
    const before = f.geometry(); oldMove({ clientX: 999, clientY: 999, buttons: 0 }); oldUp();
    assert.equal(f.geometry(), before); assert.equal(f.document.count('mousemove'), 1);
    assert.equal(f.handles[next].classList.contains('active'), true);
    f.move(40, -40); assert.notEqual(f.geometry(), before);
    f.document.emit('mouseup'); f.assertStopped();
  });
}
test('valid Fuzzer divider movement, bounds and double-click defaults stay unchanged', () => {
  const f = fixture();
  f.start('col'); f.move(100, 0); assert.equal(f.top.properties.get('--fuzzer-request-share'), '0.75');
  f.move(-10000, 0); assert.equal(f.top.properties.get('--fuzzer-request-share'), '0.24');
  f.move(10000, 0); assert.equal(f.top.properties.get('--fuzzer-request-share'), '0.84'); f.document.emit('mouseup');
  f.handles.col.emit('dblclick'); assert.equal(f.top.properties.has('--fuzzer-request-share'), false);
  f.start('row'); f.move(0, 50); assert.equal(f.top.style.height, '270px');
  f.move(0, -10000); assert.equal(f.top.style.height, '180px');
  f.move(0, 10000); assert.equal(f.top.style.height, '440px'); f.document.emit('mouseup');
  f.handles.row.emit('dblclick'); assert.equal(f.top.style.height, '');
  f.start('detail'); f.move(0, -50); assert.equal(f.detail.style.flex, '0 0 230px');
  f.move(0, 10000); assert.equal(f.detail.style.flex, '0 0 140px');
  f.move(0, -10000); assert.equal(f.detail.style.flex, '0 0 350px'); f.document.emit('mouseup');
  f.handles.detail.emit('dblclick'); assert.equal(f.detail.style.flex, ''); f.assertStopped();
});
test('hidden zero-width column cannot leave an earlier drag active', () => {
  const f = fixture(); f.start('row'); f.template.offsetWidth = f.payload.offsetWidth = 0;
  f.start('col'); f.assertStopped(); assert.equal(f.top.properties.has('--fuzzer-request-share'), false);
});
