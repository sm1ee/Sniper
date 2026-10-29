// Pure planning/rendering fixtures; no browser or requests.
const assert = require('node:assert/strict');
const test = require('node:test');
const workflow = require('../web/fuzzer-workflow.js');
const request = body => ({ scheme: 'http', host: 'example.com', method: 'POST', path: '/', headers: [], body, body_encoding: 'utf8', preview_truncated: false });
const fields = value => ['scheme', 'host', 'method', 'path', 'body'].reduce((n, key) => n + Buffer.byteLength(value[key]), 0)
  + value.headers.reduce((n, header) => n + Buffer.byteLength(header.name) + Buffer.byteLength(header.value), 0);

test('Sniper sizing permits one 64 KiB payload in 65 empty positions without charging them all together', () => {
  const template = request('$payload$'.repeat(65)), payload = 'x'.repeat(64 * 1024);
  assert.equal(fields(workflow.expandTemplate(template, payload, { position: 0 })), 65556);
  const model = workflow.preflight(template, [payload], { attackType: 'sniper' });
  assert.equal(model.valid, true, model.errors.join(' '));
  assert.equal(model.requestCount, 65);
  assert.equal(workflow.preflight(template, [payload], { attackType: 'battering_ram' }).valid, false);
});

test('Sniper sizing preserves distinct original UTF8 path header and body values', () => {
  const template = request('§' + 'body😀'.repeat(128) + '§');
  template.path = '/§a§/§éé§'; template.headers.push({ name: 'X-Value', value: '§original-header§' });
  for (const urlEncode of [false, true]) {
    const payload = 'é😀';
    const model = workflow.preflight(template, [payload], { attackType: 'sniper', urlEncode });
    const rendered = workflow.planRequests('sniper', model.markerCount, 1).map(([position]) => fields(workflow.expandTemplate(template, payload, { position, urlEncode })));
    assert.ok(model.maxExpandedRequestBytes >= Math.max(...rendered), `${model.maxExpandedRequestBytes} < ${Math.max(...rendered)}`);
  }
});

test('Sniper preview budgets retained originals before constructing each sample', () => {
  const template = request('$payload$§' + 'r'.repeat(48 * 1024) + '§');
  const model = workflow.preflight(template, ['x', 'y', 'z'], { attackType: 'sniper' });
  assert.equal(model.valid, true);
  assert.ok(model.samples.reduce((n, sample) => n + fields(sample.request), 0) <= workflow.limits.sampleBytes);
  assert.equal(model.samples.length + model.samplesOmitted, 3);
  assert.ok(model.samplesOmitted > 0);
});

test('Battering ram retains all-position replacement and field accounting for ordinary templates', () => {
  const template = request('$payload$§' + 'r'.repeat(4096) + '§');
  const model = workflow.preflight(template, ['x'], { attackType: 'battering_ram' });
  assert.equal(model.valid, true);
  assert.equal(model.maxExpandedRequestBytes, fields(workflow.expandTemplate(template, 'x')));
  assert.equal(model.maxExpandedRequestBytes, 22);
});

test('scheme remains literal in sizing while Host and Content-Length normalize after filling', () => {
  const template = request('$payload$'); template.scheme = 'http§literal§';
  const model = workflow.preflight(template, ['x'], { attackType: 'sniper' });
  assert.equal(model.markerCount, 1);
  assert.ok(model.maxExpandedRequestBytes >= fields(workflow.expandTemplate(template, 'x', { position: 0 })));
  const host = request(''); host.headers.push({ name: '$payload$', value: 'other.example.com' });
  assert.equal(workflow.expandTemplate(host, 'Host', { position: 0 }).host, 'other.example.com');
  const length = request('é😀'); length.headers.push({ name: '$payload$', value: '99999' });
  assert.deepEqual(workflow.expandTemplate(length, 'Content-Length', { position: 0 }).headers, [{ name: 'Content-Length', value: '6' }]);
});

test('selected preview sizes follow method path authority header name value and body order', () => {
  const template = request('§body©§');
  template.method = '§GET§'; template.path = '/§pathé§'; template.host = '§example.com§';
  template.headers.push({ name: '§X-Test§', value: '§value😀§' });
  for (const urlEncode of [false, true]) {
    const model = workflow.preflight(template, ['x'], { attackType: 'sniper', urlEncode });
    assert.equal(model.markerCount, 6);
    for (const sample of model.samples) {
      assert.equal(sample.estimatedBytes, fields(sample.request) + (urlEncode && sample.position === 1 ? 2 : 0));
    }
    // Move the header/body positions into the three-sample window without
    // changing their distinct originals; aggregate maximum alone misses order.
    const tail = { ...template, method: 'GET', path: '/', host: 'example.com' };
    const tailModel = workflow.preflight(tail, ['x'], { attackType: 'sniper', urlEncode });
    assert.deepEqual(tailModel.samples.map(sample => sample.position), [0, 1, 2]);
    for (const sample of tailModel.samples) assert.equal(sample.estimatedBytes, fields(sample.request));
  }
});

test('Sniper estimates can shrink every original without clamping to the original template', () => {
  const template = request('§long-original§');
  const model = workflow.preflight(template, ['x'], { attackType: 'sniper' });
  assert.equal(model.maxExpandedRequestBytes, 21);
  assert.equal(model.samples[0].estimatedBytes, 21);
});

test('preview construction allowance bounds dynamic Host copies and normalized Content-Length', () => {
  for (const payload of ['Host', 'Content-Length']) {
    const template = request('é😀'.repeat(100));
    template.headers.push({ name: '$payload$', value: payload === 'Host' ? 'h'.repeat(30 * 1024) : '0' });
    const model = workflow.preflight(template, [payload, payload, payload], { attackType: 'sniper' });
    assert.ok(model.samples.length > 0);
    assert.equal(model.samples.length + model.samplesOmitted, 3);
    assert.ok(model.samples.reduce((n, sample) => n + fields(sample.request), 0) <= workflow.limits.sampleBytes);
    for (const sample of model.samples) {
      assert.ok(fields(sample.request) <= 2 * sample.estimatedBytes + Buffer.byteLength(payload) + 256 + 32 * template.headers.length);
    }
  }
});
