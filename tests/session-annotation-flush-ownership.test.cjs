// Passive note metadata only. Production queue/drain/URL helpers run in a VM;
// every PATCH and timer is deferred data, with no app, server, or network startup.
const assert = require('node:assert/strict');
const test = require('node:test');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
const { deferred } = require('./replay-workspace-fixture.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
function fixture() {
  const requests = [], timers = new Map(), toasts = [];
  const state = { activeSession: { id: 'session-a' }, items: [], selectedRecord: null,
    _pendingAnnotations: new Map(), _annotationInFlight: new Set(), historyPaging: {} };
  let timer = 0, version = 0;
  const context = loadFunctions(['currentSessionId', 'sessionWritePath', 'expectedActiveSessionIdForWrite',
    'flushAllPendingAnnotations', 'flushPendingAnnotations', 'updateAnnotations', 'releaseHistoryNoteEdit'], {
    state, workspaceStateGeneration: 0, URLSearchParams,
    annotationClientId: 'synthetic-note-client', nextAnnotationClientVersion: () => ++version,
    observeAnnotationRevision() {}, currentHistoryNoteEditWindow: () => null, getHistoryItemIndex: () => -1,
    loadTransactions: async () => {}, showToast: (...args) => toasts.push(args),
    console: { error() {} },
    window: { setTimeout(callback) { timers.set(++timer, callback); return timer; } },
    fetch(url, options) { const request = { url, options, ...deferred() }; requests.push(request); return request.promise; },
  });
  const entry = (id, sessionId = state.activeSession.id) => {
    const pending = { sessionId, payload: { user_note: `Synthetic ${id} note` } };
    state._pendingAnnotations.set(id, pending); return pending;
  };
  const replace = sameId => { state.activeSession = { id: sameId ? 'session-a' : 'session-b' }; context.workspaceStateGeneration++; };
  const succeed = (index, id) => requests[index].resolve({ ok: true, json: async () => ({ id, annotation_revision: 1 }) });
  const fail = index => requests[index].resolve({ ok: false, text: async () => 'Synthetic annotation failure' });
  const nextTimer = async () => {
    assert.equal(timers.size, 1); const [id, callback] = timers.entries().next().value;
    timers.delete(id); callback(); await tick();
  };
  const url = index => new URL(requests[index].url, 'http://example.com');
  return { context, state, requests, timers, toasts, entry, replace, succeed, fail, nextTimer, url };
}
const externalOptions = { sessionId: 'session-a', bypassExpectedActiveSessionGuard: true };

test('an already-mismatched drain cannot inspect or save a newer pending entry', async () => {
  const f = fixture(); f.replace(false); const next = f.entry('note-b');
  const draining = f.context.flushAllPendingAnnotations(externalOptions); await tick();
  assert.equal(f.requests.length, 0); await draining;
  assert.equal(f.state._pendingAnnotations.get('note-b'), next); assert.equal(f.timers.size, 0);
});
for (const sameId of [false, true]) for (const outcome of ['success', 'failure']) {
  test(`batch ${outcome} crossing ${sameId ? 'generation' : 'owner'} cannot consume a newer entry`, async () => {
    const f = fixture(); f.entry('note-a');
    const draining = f.context.flushAllPendingAnnotations(externalOptions).then(() => null, error => error);
    assert.equal(f.url(0).searchParams.get('session_id'), 'session-a');
    assert.equal(f.url(0).searchParams.has('expected_active_session_id'), false);
    f.replace(sameId); const next = f.entry('note-b');
    if (outcome === 'success') f.succeed(0, 'note-a'); else f.fail(0);
    await tick(); assert.equal(f.requests.length, 1); assert.equal(f.timers.size, 0);
    assert.equal(await draining, null, 'an obsolete drain must not report against the replacement workspace');
    assert.equal(f.state._pendingAnnotations.get('note-b'), next);
    assert.equal(f.state._pendingAnnotations.has('note-a'), outcome === 'failure');
  });
}
for (const sameId of [false, true]) test(`timer wait crossing ${sameId ? 'generation' : 'owner'} stops before its next pending scan`, async () => {
  const f = fixture(); f.state._annotationInFlight.add('old-in-flight');
  const draining = f.context.flushAllPendingAnnotations(externalOptions); await tick();
  f.replace(sameId); f.state._annotationInFlight.clear(); const next = f.entry('note-b');
  await f.nextTimer(); assert.equal(f.requests.length, 0); await draining;
  assert.equal(f.state._pendingAnnotations.get('note-b'), next); assert.equal(f.timers.size, 0);
});
test('last permitted timer cannot throw a timeout after workspace replacement', async () => {
  const f = fixture(); f.state._annotationInFlight.add('old-in-flight');
  const draining = f.context.flushAllPendingAnnotations(externalOptions).then(() => null, error => error);
  await tick(); for (let attempt = 0; attempt < 39; attempt++) await f.nextTimer();
  f.replace(false); f.state._annotationInFlight.clear(); const next = f.entry('note-b');
  await f.nextTimer(); assert.equal(await draining, null);
  assert.equal(f.state._pendingAnnotations.get('note-b'), next); assert.equal(f.requests.length, 0);
});
test('current-owner timeout retains its original failure', async () => {
  const f = fixture(); f.state._annotationInFlight.add('still-in-flight');
  const draining = f.context.flushAllPendingAnnotations(externalOptions).then(() => null, error => error);
  await tick(); for (let attempt = 0; attempt < 40; attempt++) await f.nextTimer();
  assert.equal((await draining).message, 'Timed out saving pending annotations.');
  assert.equal(f.requests.length, 0); assert.equal(f.state._annotationInFlight.has('still-in-flight'), true);
});
test('current-owner failed batch keeps its pending edit and original error', async () => {
  const f = fixture(), pending = f.entry('note-a');
  const draining = f.context.flushAllPendingAnnotations(externalOptions).then(() => null, error => error);
  f.fail(0); assert.equal((await draining).message, 'Synthetic annotation failure');
  assert.equal(f.state._pendingAnnotations.get('note-a'), pending); assert.equal(f.requests.length, 1);
});
test('rightful current-owner external drain still uses its bypass and removes only the acknowledged edit', async () => {
  const f = fixture(); f.entry('note-a'); const draining = f.context.flushAllPendingAnnotations(externalOptions);
  assert.equal(f.url(0).searchParams.get('session_id'), 'session-a');
  assert.equal(f.url(0).searchParams.has('expected_active_session_id'), false);
  f.succeed(0, 'note-a'); await draining;
  assert.equal(f.state._pendingAnnotations.size, 0); assert.equal(f.requests.length, 1);
});
test('old drain cannot reuse its bypass for an actual newer failed note retry', async () => {
  const f = fixture(); await f.context.updateAnnotations('note-a', { user_note: 'Synthetic A note' });
  const draining = f.context.flushAllPendingAnnotations(externalOptions); await tick();
  f.replace(false); await f.context.updateAnnotations('note-b', { user_note: 'Synthetic B note' });
  const next = f.state._pendingAnnotations.get('note-b');
  assert.equal(f.url(1).searchParams.has('expected_active_session_id'), false);
  f.fail(1); await tick(); f.succeed(0, 'note-a'); await tick();
  await f.nextTimer(); assert.equal(f.requests.length, 2); await draining;
  assert.equal(f.state._pendingAnnotations.get('note-b'), next);
  const retry = f.context.flushPendingAnnotations('note-b');
  assert.equal(f.url(2).searchParams.get('session_id'), 'session-b');
  assert.equal(f.url(2).searchParams.has('expected_active_session_id'), false);
  assert.equal(JSON.parse(f.requests[2].options.body).user_note, 'Synthetic B note');
  f.succeed(2, 'note-b'); assert.equal(await retry, true); assert.equal(f.state._pendingAnnotations.size, 0);
});
for (const sameId of [false, true]) for (const outcome of ['success', 'failure']) {
  test(`same transaction replacement survives old ${outcome} across ${sameId ? 'generation' : 'owner'} with an ordinary retry`, async () => {
    const f = fixture(); f.entry('same-note');
    const draining = f.context.flushAllPendingAnnotations(externalOptions).then(() => null, error => error);
    f.replace(sameId); await f.context.updateAnnotations('same-note', { user_note: 'Synthetic new note' });
    const next = f.state._pendingAnnotations.get('same-note'); assert.equal(f.requests.length, 1);
    if (outcome === 'success') f.succeed(0, 'same-note'); else f.fail(0);
    await tick(); assert.equal(f.timers.size, 0);
    assert.equal(await draining, null); assert.equal(f.requests.length, 2);
    assert.equal(f.state._pendingAnnotations.get('same-note'), next);
    assert.equal(f.url(1).searchParams.get('session_id'), f.state.activeSession.id);
    assert.equal(f.url(1).searchParams.has('expected_active_session_id'), false);
    assert.equal(JSON.parse(f.requests[1].options.body).user_note, 'Synthetic new note');
    f.succeed(1, 'same-note'); await tick(); assert.equal(f.state._pendingAnnotations.size, 0);
  });
}
