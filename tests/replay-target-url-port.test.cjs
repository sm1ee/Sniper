// Production target validation/application only. No app, network, or Send calls.
const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');

function fixture(host, port) {
  const response = { id: 'prior-response', status: 200 };
  const tab = {
    id: 'replay-a', type: 'http', targetScheme: 'https',
    targetHost: 'old.example.com', targetPort: '8443', targetManuallyEdited: true,
    requestText: 'GET /draft\r\nHost: origin.example.com\r\n\r\n', httpVersionMode: '',
    baseRequest: { scheme: 'https', host: 'origin.example.com', method: 'GET', path: '/draft' },
    responseRecord: response, notice: 'Prior response notice',
  };
  const input = value => ({ value, validationMessage: '', attributes: {},
    setCustomValidity(message) { this.validationMessage = message; },
    toggleAttribute(name, enabled) { this.attributes[name] = enabled; },
  });
  const els = {
    replayHostInput: input(host), replayPortInput: input(port), replaySchemeSelect: input('https'),
  };
  let saves = 0, renders = 0;
  const context = loadFunctions([
    'applyReplayTargetFields', 'setReplayTargetInputValidity', 'validateManualRepeaterTargetInput',
    'normalizeRepeaterTargetInput', 'authorityToTargetState', 'explicitAuthorityPort',
    'normalizePortValue', 'defaultHttpPortForScheme', 'stripIpv6Brackets', 'isLikelyIpv6Literal',
  ], {
    URL, els, getActiveReplayTab: () => tab,
    scheduleWorkspaceStateSave() { saves++; }, renderReplay() { renders++; },
  });
  return { context, tab, response, els, counts: () => ({ saves, renders }) };
}

for (const [host, port, explicitPort] of [
  ['https://example.com:443', '8443', '443'],
  ['HTTPS://EXAMPLE.COM:443', '8443', '443'],
  ['http://example.com:80', '8080', '80'],
  ['https://example.com:00443', '08443', '443'],
  ['http://example.com:00080/', '08080', '80'],
  ['https://[2001:db8::1]:443', '8443', '443'],
  ['http://[2001:db8::1]:80/', '8080', '80'],
  ['https://example.com:9443', '8443', '9443'],
]) {
  test(`conflicting target URL ${host} and Port ${port} preserve the entire draft`, async () => {
    const f = fixture(host, port), before = JSON.stringify(f.tab);
    await f.context.applyReplayTargetFields();
    assert.equal(JSON.stringify(f.tab), before);
    assert.equal(f.tab.responseRecord, f.response);
    assert.deepEqual(f.counts(), { saves: 0, renders: 0 });
    assert.equal(f.els.replayHostInput.value, host);
    assert.equal(f.els.replayPortInput.value, port);
    assert.equal(f.els.replaySchemeSelect.value, 'https');
    assert.equal(f.els.replayHostInput.validationMessage, '');
    assert.equal(f.els.replayPortInput.validationMessage, `Port conflicts with target URL port ${explicitPort}.`);
    assert.equal(f.els.replayPortInput.attributes['aria-invalid'], true);
  });
}

for (const [host, port, scheme, targetHost, targetPort] of [
  ['https://example.com:443', '443', 'https', 'example.com', '443'],
  ['HTTPS://EXAMPLE.COM:00443', '0443', 'https', 'example.com', '443'],
  ['http://example.com:80', '80', 'http', 'example.com', '80'],
  ['https://example.com:00443', '000443', 'https', 'example.com', '443'],
  ['http://example.com:00080/', '0080', 'http', 'example.com', '80'],
  ['https://example.com:443', '', 'https', 'example.com', '443'],
  ['http://example.com:80', '', 'http', 'example.com', '80'],
  ['https://example.com:9443', '', 'https', 'example.com', '9443'],
  ['https://example.com', '8443', 'https', 'example.com', '8443'],
  ['http://example.com', '8080', 'http', 'example.com', '8080'],
  ['https://example.com', '', 'https', 'example.com', '443'],
  ['http://example.com', '', 'http', 'example.com', '80'],
  ['https://[2001:db8::1]:443', '00443', 'https', '2001:db8::1', '443'],
  ['http://[2001:db8::1]:80/', '', 'http', '2001:db8::1', '80'],
  ['https://[2001:db8::1]', '8443', 'https', '2001:db8::1', '8443'],
]) {
  test(`compatible target URL ${host} and Port ${port || '(blank)'} retain existing semantics`, async () => {
    const f = fixture(host, port), requestText = f.tab.requestText, baseRequest = f.tab.baseRequest;
    await f.context.applyReplayTargetFields();
    assert.equal(f.tab.targetScheme, scheme);
    assert.equal(f.tab.targetHost, targetHost);
    assert.equal(f.tab.targetPort, targetPort);
    assert.equal(f.tab.requestText, requestText);
    assert.equal(f.tab.baseRequest, baseRequest);
    assert.equal(f.tab.httpVersionMode, '');
    assert.equal(f.tab.targetManuallyEdited, true);
    assert.deepEqual(f.counts(), { saves: 1, renders: 1 });
    assert.equal(f.els.replayHostInput.validationMessage, '');
    assert.equal(f.els.replayPortInput.validationMessage, '');
    assert.equal(f.els.replayPortInput.attributes['aria-invalid'], false);
  });
}

for (const [host, port, field, message] of [
  ['https:///example.com:443', '8443', 'replayHostInput', 'Target host is not a valid URL.'],
  ['https:////example.com:443', '8443', 'replayHostInput', 'Target host is not a valid URL.'],
  ['http:///example.com:80', '8080', 'replayHostInput', 'Target host is not a valid URL.'],
  ['http:////example.com:80', '8080', 'replayHostInput', 'Target host is not a valid URL.'],
  ['https://example.com:443/path', '8443', 'replayHostInput', 'Target host must not include path, query, fragment, or credentials.'],
  ['https://user@example.com:443', '8443', 'replayHostInput', 'Target host must not include whitespace, user info, or URL components.'],
  ['ftp://example.com:21', '8443', 'replayHostInput', 'Target URL scheme must be HTTP or HTTPS.'],
  ['https://example.com:443', '65536', 'replayPortInput', 'Port must be a number from 1 to 65535.'],
  ['https://example.com:443', 'bad', 'replayPortInput', 'Port must be a number from 1 to 65535.'],
]) {
  test(`target ${host} and Port ${port} keep existing validation feedback`, async () => {
    const f = fixture(host, port), before = JSON.stringify(f.tab);
    await f.context.applyReplayTargetFields();
    assert.equal(JSON.stringify(f.tab), before);
    assert.deepEqual(f.counts(), { saves: 0, renders: 0 });
    assert.equal(f.els[field].validationMessage, message);
    assert.equal(f.els[field].attributes['aria-invalid'], true);
  });
}

test('correcting a URL port conflict clears validation and applies only the corrected target', async () => {
  const f = fixture('https://example.com:443', '8443');
  await f.context.applyReplayTargetFields();
  assert.equal(f.tab.responseRecord, f.response);
  assert.ok(f.els.replayPortInput.validationMessage);
  f.els.replayPortInput.value = '443';
  await f.context.applyReplayTargetFields();
  assert.equal(f.els.replayPortInput.validationMessage, '');
  assert.equal(f.els.replayPortInput.attributes['aria-invalid'], false);
  assert.equal(f.tab.targetHost, 'example.com');
  assert.equal(f.tab.targetPort, '443');
  assert.equal(f.tab.responseRecord, null);
  assert.equal(f.tab.notice, '');
  assert.deepEqual(f.counts(), { saves: 1, renders: 1 });
});
