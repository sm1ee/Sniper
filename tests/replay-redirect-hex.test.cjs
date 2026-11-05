// Real Replay rendering and shipped CM state; transport is synthetic only.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { editorFixture, source } = require('./replay-editor-fixture.cjs');
const { deferred } = require('./replay-workspace-fixture.cjs');

function setup() {
  const f = editorFixture();
  f.pendingResponse = deferred(); f.sent = [];
  Object.assign(f.context, {
    AbortController, REPEATER_HISTORY_LIMIT: 100,
    flushWorkspaceStateForReplayAction: async () => 10,
    renderReplayResponseOnly() {}, scheduleRefresh() {}, formatStatus: status => String(status),
    fetch: async (_url, options) => {
      f.sent.push(JSON.parse(options.body));
      return { ok: true, json: () => f.pendingResponse.promise };
    },
  });
  for (const name of [
    'followRedirect', 'isReplayTabStillCurrent', 'setReplaySending', 'cancelReplaySend',
    'replayEffectiveHttpVersion', 'buildUrlFromTarget', 'joinAuthority', 'isDefaultPortForScheme',
    'redirectTargetsSameOrigin', 'isRedirectCredentialHeader', 'isRedirectRequestBodyHeader',
    'httpRequestAuthoritiesEquivalent', 'normalizeHttpRequestAuthority',
    'replaySentDraftUnchanged', 'applyReplaySentDraftIfUnchanged', 'targetStatesEquivalent',
    'replayTargetOverridePayload', 'recordRepeaterHistory',
  ]) vm.runInContext(source(name), f.context);
  f.a.responseRecord = { id: 'redirect', status: 302, request: {},
    response: { headers: [{ name: 'location', value: '/next' }] } };
  // Avoid response presentation (not the subject of this fixture).
  f.context.buildRawResponse = () => '';
  f.state.replayMessageViews.request = 'hex'; f.render();
  f.start = () => f.context.followRedirect();
  f.finish = async pending => { f.pendingResponse.resolve({ id: 'next-response', status: 200, request: {}, response: { headers: [] } }); await pending; };
  return f;
}

for (const nextMode of ['raw', 'pretty']) {
  test(`Follow in Hex keeps the redirect request through ${nextMode} and tab round-trips`, async () => {
    const f = setup(); const pending = f.start();
    assert.equal(f.cv()._editable, false);
    assert.equal(new TextDecoder().decode(f.a.requestBytes), f.a.requestText);
    assert.equal(f.cv().getContent(), f.context.toHexDumpFromBytes(f.a.requestBytes));
    await f.finish(pending);
    assert.equal(f.sent[0].request.path, '/next');
    f.state.replayMessageViews.request = nextMode;
    f.context.renderReplayViewContent('request');
    assert.match(f.a.requestText, /^GET \/next /);
    assert.equal(f.a.responseRecord.id, 'next-response');
    f.switchTo(f.b); f.switchTo(f.a);
    assert.match(f.cv().getContent(), /^GET \/next /);
  });
}

test('a newer editable draft remains current when the Hex redirect completes', async () => {
  const f = setup(); const pending = f.start();
  f.state.replayMessageViews.request = 'raw'; f.context.renderReplayViewContent('request');
  f.edit(5, 9, 'newer'); const draft = f.a.requestText;
  await f.finish(pending);
  assert.equal(f.a.requestText, draft); assert.match(draft, /^GET \/newer /);
  assert.equal(f.a.responseRecord, null);
  assert.equal(f.a.historyEntries.at(-1).responseRecord.id, 'next-response');
});

test('switching tabs during a Hex redirect does not replace the new owner editor', async () => {
  const f = setup(); const pending = f.start(); f.switchTo(f.b);
  const cv = f.cv(), text = cv.getContent();
  await f.finish(pending);
  assert.equal(f.cv(), cv); assert.equal(cv.getContent(), text);
  assert.equal(f.a.responseRecord.id, 'next-response');
});

test('cancelling a Hex redirect keeps its draft and ignores a late response', async () => {
  const f = setup(); const pending = f.start();
  f.context.cancelReplaySend(); await f.finish(pending);
  assert.equal(f.a.notice, 'Cancelled.'); assert.equal(f.a.responseRecord, null);
  f.state.replayMessageViews.request = 'raw'; f.context.renderReplayViewContent('request');
  assert.match(f.cv().getContent(), /^GET \/next /);
});

test('a definite workspace conflict restores the pre-redirect Hex draft and both byte caches', async () => {
  const f = setup(); const preflight = deferred(); const errors = [];
  f.context.flushWorkspaceStateForReplayAction = () => preflight.promise;
  f.context.handleWorkspaceActionError = error => errors.push(error);
  for (const name of ['restoreReplayTabState', 'restoreReplayTabConflictState']) {
    vm.runInContext(source(name), f.context);
  }
  const original = f.a.requestText;
  const bytes = Array.from(f.a.requestBytes);
  const originalBytes = Array.from(f.a.requestOriginalBytes);
  const displayed = f.cv().getContent();
  const pending = f.start(); assert.match(f.a.requestText, /^GET \/next /);
  const conflict = vm.runInContext('new WorkspaceStateConflictError({ revision: 11 })', f.context);
  preflight.reject(conflict); await pending;
  assert.equal(f.sent.length, 0); assert.equal(errors[0], conflict);
  assert.equal(f.a.requestText, original);
  assert.deepEqual(Array.from(f.a.requestBytes), bytes);
  assert.deepEqual(Array.from(f.a.requestOriginalBytes), originalBytes);
  assert.equal(f.cv().getContent(), displayed); assert.equal(f.cv()._editable, false);
  assert.equal(f.a.responseRecord.id, 'redirect');
  f.state.replayMessageViews.request = 'raw'; f.context.renderReplayViewContent('request');
  assert.equal(f.cv().getContent(), original.replace(/\r\n/g, '\n'));
  assert.equal(f.a.requestText, original);
});
