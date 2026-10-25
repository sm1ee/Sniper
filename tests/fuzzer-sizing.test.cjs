// Pure planning/rendering fixtures; no browser or requests.
const assert = require('node:assert/strict');
const test = require('node:test');
const workflow = require('../web/fuzzer-workflow.js');
const request = body => ({ scheme: 'http', host: 'example.com', method: 'POST', path: '/', headers: [], body, body_encoding: 'utf8', preview_truncated: false });
const fields = value => ['scheme', 'host', 'method', 'path', 'body'].reduce((n, key) => n + Buffer.byteLength(value[key]), 0)
  + value.headers.reduce((n, header) => n + Buffer.byteLength(header.name) + Buffer.byteLength(header.value), 0);

test('Sniper sizing permits one64KiB payload in65 empty positions without charging them all together', () => {
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
