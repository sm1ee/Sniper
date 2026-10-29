// Passive Replay request Pretty view only. No application, network, runtime, or request execution.
const assert = require('node:assert/strict');
const vm = require('node:vm');
const test = require('node:test');
const { appSource } = require('./frontend-test-helpers.cjs');
const { fixture } = require('./replay-workspace-fixture.cjs');

const BODY = '{"query":"{ a b }","page":0}';
const RAW = `POST /graphql HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: ${BODY.length}\r\n\r\n${BODY}`;

function source(name) {
  return appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, 'm'))[0];
}
function setup() {
  const f = fixture();
  for (const name of [
    'syncReplayRequestTextFromEditor', 'clearReplayResponseForDraftChange', 'changeReplayMethod',
    'syncReplayRequestEditorForTab', 'getReplayTabById', 'requestTextWithMethod', 'parseEditableRawRequest', 'splitRawHttpMessage',
    'parseReplayHttpVersionToken', 'headerValue', 'editableRequestBodyLength', 'validateRawHttpBodyFraming',
  ]) vm.runInContext(source(name), f.context);
  Object.assign(f.context, { syncReplayToolbar() {}, refreshReplayTabLabel() {}, updateReplaySearchPane() {} });
  f.state.replayMessageViews.request = 'pretty';
  f.tab = f.context.createReplayTab({
    customLabel: 'json',
    baseRequest: { scheme: 'https', host: 'example.com', method: 'POST', path: '/graphql', headers: [], body: '', body_encoding: 'utf8', preview_truncated: false },
    requestText: RAW,
  });
  f.tab.responseRecord = { id: 'response-1' };
  f.seed([f.tab]);
  f.shown = f.context.replayRequestEditorText(RAW);
  f.editor = { content: f.shown, getContent() { return this.content; }, setContent(value) { this.content = value; } };
  f.context.getCMView = () => f.editor;
  return f;
}

test('Pretty view formats a JSON request body and Raw view shows the draft as stored', () => {
  const f = setup();
  assert.match(f.shown, /\n\n\{\n  "query": "\{ a b \}",\n  "page": 0\n\}$/);
  assert.ok(f.context.replayEditorShowsDraft(f.shown, RAW));
  f.state.replayMessageViews.request = 'raw';
  assert.equal(f.context.replayRequestEditorText(RAW), RAW);
  assert.equal(f.context.replayEditorShowsDraft(f.shown, RAW), false);
});

test('an untouched Pretty rendering keeps the captured bytes and the response', () => {
  const f = setup();
  f.context.syncReplayRequestTextFromEditor(f.shown);
  assert.equal(f.context.replayTabHasUncommittedEditorState(f.tab), false);
  assert.equal(f.context.preserveActiveHttpReplayDraftBeforeNavigation(f.tab, 'switching tabs'), true);
  assert.equal(f.tab.requestText, RAW);
  assert.deepEqual(f.tab.responseRecord, { id: 'response-1' });
});

test('an edit in Pretty view becomes the draft that is sent', () => {
  const f = setup();
  const edited = f.shown.replace('{ a b }', '{ a c }');
  f.context.syncReplayRequestTextFromEditor(edited);
  assert.equal(f.tab.requestText, edited);
  assert.equal(f.tab.responseRecord, null);
});

test('changing the method from an untouched Pretty rendering keeps the body bytes', () => {
  const f = setup();
  f.context.changeReplayMethod('PUT', f.tab.id);
  assert.equal(f.tab.requestText, RAW.replace(/^POST/, 'PUT'));
  assert.equal(f.editor.content, f.context.replayRequestEditorText(f.tab.requestText));
  assert.notEqual(f.editor.content, f.tab.requestText);
});
