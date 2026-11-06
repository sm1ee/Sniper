// Passive production admission/edit/save logic with shipped CodeMirror state.
// Runtime/restart coverage lives in replay-request-size-runtime.py.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { fixture } = require('./replay-workspace-fixture.cjs');
const { editorFixture, source } = require('./replay-editor-fixture.cjs');
const LIMIT = 2 * 1024 * 1024;
const plain = value => JSON.parse(JSON.stringify(value));
const request = (body = '', encoding = 'utf8') => ({
  scheme: 'http', host: 'example.com', method: 'POST', path: '/size',
  headers: [{ name: 'Host', value: 'example.com' }],
  body, body_encoding: encoding, preview_truncated: false,
});
const raw = body => `POST /size HTTP/1.1\nHost: example.com\n\n${body}`;
function assertRefusal(f, before, action) {
  assert.equal(action(), null);
  assert.deepEqual(plain({tabs:f.state.replayTabs,active:f.state.activeReplayTabId,sequence:f.state.replayTabSequence}), before);
  assert.match(f.toasts.at(-1)[0], /2 MiB/);
  assert.match(f.toasts.at(-1)[0], /Nothing was truncated/);
  assert.match(f.toasts.at(-1)[0], /use a smaller request/);
  assert.equal(f.requests.length, 0);
}

for (const [name, body, encoding] of [
  ['2.25 MiB ASCII capture', 'A'.repeat(2304 * 1024), 'utf8'],
  ['Base64 expansion of a 1.6 MiB binary body', Buffer.alloc(1600 * 1024, 0xff).toString('base64'), 'base64'],
  ['JSON escaping below the request text cap', '"'.repeat(1100 * 1024), 'utf8'],
  ['UTF-8 multibyte body', '😀'.repeat(550000), 'utf8'],
]) {
  test(`${name}: refusal is atomic and does not schedule a save`, () => {
    const f = fixture(); const a=f.tab('existing'); f.seed([a]);
    const before=plain({tabs:f.state.replayTabs,active:f.state.activeReplayTabId,sequence:f.state.replayTabSequence});
    const req=request(body,encoding);const text=raw(body);const original=JSON.stringify(req);
    assertRefusal(f,before,()=>f.context.createReplayTab({baseRequest:req,requestText:text}));
    assert.equal(JSON.stringify(req),original);
    assert.equal(f.context.workspaceSaveDirty,false);
    assert.equal(f.timers.size,0);
  });
}

test('the UTF-8 request text cap is inclusive and independent of the base JSON cap', () => {
  const f=fixture(), req=request();
  assert.equal(f.context.replayRequestSizeError('x'.repeat(LIMIT),req),'');
  assert.match(f.context.replayRequestSizeError('x'.repeat(LIMIT+1),req),/request text/);
  assert.equal(f.context.replayRequestSizeError('é'.repeat(LIMIT/2),req),'');
  assert.match(f.context.replayRequestSizeError('é'.repeat(LIMIT/2)+'x',req),/request text/);
});

test('the base JSON cap is inclusive and counts metadata, escapes and serde defaults', () => {
  const f=fixture(), req=request();
  req.body='a'.repeat(LIMIT-Buffer.byteLength(JSON.stringify(req)));
  assert.equal(Buffer.byteLength(JSON.stringify(req)),LIMIT);
  assert.equal(f.context.replayRequestSizeError('short',req),'');
  req.body+='a';
  assert.match(f.context.replayRequestSizeError('short',req),/stored request/);
  const escaped=request('"'.repeat(1100*1024));
  assert.ok(Buffer.byteLength(raw(escaped.body))<LIMIT);
  assert.match(f.context.replayRequestSizeError(raw(escaped.body),escaped),/stored request/);
  const defaults={...request()};delete defaults.body_encoding;delete defaults.preview_truncated;
  defaults.body='a'.repeat(LIMIT-Buffer.byteLength(JSON.stringify({...defaults,body_encoding:'utf8',preview_truncated:false}))+1);
  assert.match(f.context.replayRequestSizeError('short',defaults),/stored request/);
});

test('capture import refuses before tab, selection, tool or save mutation', () => {
  const f=editorFixture();f.render();
  for(const name of ['openTransactionRecordInReplay','editableRequestFromRecord','isWebSocketUpgradeRecord','isRequestPreviewTruncated'])vm.runInContext(source(name),f.context);
  const record={id:'synthetic-source',kind:'http',scheme:'http',host:'example.com',method:'POST',path:'/size',request:{body_preview:'A'.repeat(2304*1024),body_encoding:'utf8',headers:[],preview_truncated:false}};
  const before=plain({tabs:f.state.replayTabs,active:f.state.activeReplayTabId,sequence:f.state.replayTabSequence});
  const cv=f.cv();const editor=cv.view.state;
  assert.equal(f.context.openTransactionRecordInReplay(record),false);
  assert.deepEqual(plain({tabs:f.state.replayTabs,active:f.state.activeReplayTabId,sequence:f.state.replayTabSequence}),before);
  assert.equal(f.cv(),cv);assert.equal(f.cv().view.state,editor);assert.equal(f.timers.size,0);
  assert.equal(record.request.body_preview.length,2304*1024);
});

test('cURL refusal retains the full modal text without creating a blank tab', () => {
  const f=fixture();let creates=0,closes=0;
  const text='curl synthetic retained input';
  f.context.document={getElementById:()=>({value:text})};
  f.context.parseCurlCommand=value=>{assert.equal(value,text);return{...request('"'.repeat(1100*1024)),requestText:raw('"'.repeat(1100*1024))};};
  f.context.createReplayTab=()=>{creates++;return{};};
  f.context.closeCurlImportModal=()=>closes++;
  vm.runInContext(source('applyCurlImport'),f.context);
  f.context.applyCurlImport();
  assert.equal(creates,0);assert.equal(closes,0);assert.equal(f.timers.size,0);
  assert.match(f.toasts.at(-1)[0],/import this cURL request/);
});

for (const [name, body] of [['raw text','A'.repeat(2304*1024)],['parsed JSON escaping','"'.repeat(1100*1024)],['Unicode','😀'.repeat(550000)]]) {
  test(`CodeMirror rejects oversized ${name} edit atomically, keeping Undo/Redo and selection`, () => {
    const f=editorFixture(); f.render();
    const path=f.cv().getContent().indexOf('/a');f.edit(path,path+2,'/edited');
    const accepted=f.a.requestText;
    f.cv().view.dispatch({selection:{anchor:2,head:7}});
    const selection=f.selection(),editor=f.cv().getContent();
    const before=plain(f.a), timerCount=f.timers.size;
    f.edit(0,editor.length,raw(body));
    assert.equal(f.cv().getContent(),editor);assert.equal(f.a.requestText,accepted);
    assert.deepEqual(plain(f.a),before);assert.deepEqual(f.selection(),selection);
    assert.equal(f.timers.size,timerCount);assert.match(f.toasts.at(-1)[0],/Nothing was truncated/);
    assert.equal(f.undo(),true);assert.match(f.a.requestText,/GET \/a HTTP/);
    assert.equal(f.redo(),true);assert.equal(f.a.requestText,accepted);
    f.switchTo(f.b);f.edit(0,3,'PUT');assert.match(f.b.requestText,/^PUT/);
  });
}

test('programmatic field edit synchronization rejects a complete oversized draft without changing the model', () => {
  const f=editorFixture();f.render();const before=plain(f.a);
  assert.equal(f.context.syncReplayRequestTextFromEditor(raw('A'.repeat(2304*1024))),false);
  assert.deepEqual(plain(f.a),before);assert.equal(f.cv().getContent(),before.requestText.replace(/\r\n/g,'\n'));
});

test('an unseen oversized DOM draft blocks navigation rather than overwriting valid saved work', () => {
  const f=fixture(),a=f.tab('existing');f.seed([a]);
  f.els.replayRequestHighlight.innerText=raw('A'.repeat(2304*1024));
  const before=plain(a);
  assert.equal(f.context.preserveActiveHttpReplayDraftBeforeNavigation(a,'switching tabs'),false);
  assert.deepEqual(plain(a),before);assert.equal(f.timers.size,0);
  assert.equal(f.els.replayRequestHighlight.innerText.length,raw('A'.repeat(2304*1024)).length);
});

test('defensive save refuses invalid request without POST, retry timer, baseline change or clearing unsaved state',async()=>{
  const f=fixture(),a=f.tab('existing');f.seed([a]);
  const baseline=f.context.workspaceSaveCommittedSnapshot;
  a.requestText=raw('A'.repeat(2304*1024));
  f.context.scheduleWorkspaceStateSave();
  await assert.rejects(f.context.flushWorkspaceState(),/request text exceeds 2 MiB/);
  assert.equal(f.requests.length,0);assert.equal(f.timers.size,0);assert.equal(f.context.workspaceSaveDirty,true);
  assert.equal(f.context.workspaceSaveCommittedSnapshot,baseline);
  assert.match(f.toasts.at(-1)[0],/Workspace was not saved/);
  const event={type:'beforeunload',preventDefault(){this.prevented=true;}};
  f.context.flushWorkspaceStateOnUnload(event);assert.equal(event.prevented,true);
  a.requestText=raw('small');f.context.scheduleWorkspaceStateSave();
  const saving=f.context.flushWorkspaceState();assert.equal(f.requests.length,1);
  f.succeed(0,{session_id:'session-a',revision:11});await saving;
  assert.equal(f.context.workspaceSaveDirty,false);assert.equal(f.state.workspaceRevision,11);
});

for(const status of [400,413,422])test(`server validation ${status} is visible and does not retry unchanged data`,async()=>{
  const f=fixture(),a=f.tab('existing');f.seed([a]);f.context.scheduleWorkspaceStateSave();
  const saving=f.context.flushWorkspaceState();
  f.requests[0].resolve({ok:false,status,text:async()=> 'synthetic workspace limit'});
  await assert.rejects(saving,/synthetic workspace limit/);
  assert.equal(f.context.workspaceSaveDirty,true);assert.equal(f.timers.size,0);
  assert.equal(f.context.workspaceSaveConflictPending,false);assert.match(f.toasts.at(-1)[0],/Workspace was not saved/);
  assert.equal(f.requests.length,1);
});

test('a complete smaller edit repairs an older oversized base without changing ordinary Reset baselines',async()=>{
  const f=editorFixture();
  const oldBody='"'.repeat(1100*1024);
  f.a.baseRequest=request(oldBody);f.a.requestText=raw(oldBody);f.render();
  const smaller=raw('small');
  f.edit(0,f.cv().getContent().length,smaller);
  assert.equal(f.a.requestText,smaller);assert.equal(f.a.baseRequest.body,'small');
  assert.equal(f.context.replayRequestSizeError(f.a.requestText,f.a.baseRequest),'');
  f.undo(); // CodeMirror reports a handled command even when its transaction is rejected.
  assert.equal(f.a.requestText,smaller,'undo cannot reinstall an unsavable older request');
  assert.equal(f.cv().getContent(),smaller);
  const baseline=f.a.baseRequest;
  f.edit(f.cv().getContent().length-5,f.cv().getContent().length,'other');
  assert.equal(f.a.baseRequest,baseline,'ordinary edits preserve the reset base');
});

test('repairing an out-of-band oversized base may undo to an earlier valid draft, never the oversized one',()=>{
  const f=editorFixture();f.render();
  const original=f.cv().getContent();
  const oldBody='"'.repeat(1100*1024);
  f.a.baseRequest=request(oldBody);f.a.requestText=raw(oldBody);f.render();
  f.edit(0,f.cv().getContent().length,raw('small'));
  assert.equal(f.a.baseRequest.body,'small');
  f.undo();
  assert.equal(f.a.requestText,original);
  assert.equal(f.context.replayRequestSizeError(f.a.requestText,f.a.baseRequest),'');
  assert.equal(f.cv().getContent(),original);
});

test('navigation can retain a complete smaller DOM edit that repairs an older oversized base',()=>{
  const f=fixture(),a=f.tab('old');f.seed([a]);
  a.baseRequest=request('"'.repeat(1100*1024));a.requestText=raw(a.baseRequest.body);f.syncDom();
  f.els.replayRequestHighlight.innerText=raw('small');
  assert.equal(f.context.preserveActiveHttpReplayDraftBeforeNavigation(a,'switching tabs'),true);
  assert.equal(a.baseRequest.body,'small');assert.equal(a.requestText,raw('small'));
});

test('sequential closes recover multiple invalid tabs without a false conflict barrier',async()=>{
  const f=fixture(),a=f.tab('a'),b=f.tab('b'),good=f.tab('good');f.seed([a,b,good]);
  a.requestText='x'.repeat(LIMIT+1);b.requestText='x'.repeat(LIMIT+1);f.syncDom();
  await f.context.closeRepeaterTab(a.id);
  assert.equal(f.state.replayTabs.length,2);assert.equal(f.context.workspaceSaveConflictPending,false);
  assert.equal(f.context.workspaceSaveDirty,true);assert.equal(f.requests.length,0);assert.equal(f.timers.size,0);
  const closing=f.context.closeRepeaterTab(b.id);
  assert.equal(f.requests.length,1);f.succeed(0,{session_id:'session-a',revision:11});await closing;
  assert.deepEqual(f.state.replayTabs.map(t=>t.id),[good.id]);assert.equal(f.context.workspaceSaveDirty,false);
});

test('aggregate request/history overflow refuses without silently removing history',()=>{
  const f=fixture();vm.runInContext(source('boundWorkspaceSnapshotForSave'),f.context);
  Object.assign(f.context,{WORKSPACE_SAVE_SAFE_BYTES:1024,WORKSPACE_SAVE_RECORD_SAFE_BYTES:512});
  const snapshot={replay:{tabs:[{request_text:'a'.repeat(700),base_request:request(),response_record:{body:'b'.repeat(700)},history_entries:[{request_text:'c'.repeat(700),request:request()}],history_index:0}]}};
  const before=JSON.stringify(snapshot);
  assert.throws(()=>f.context.boundWorkspaceSnapshotForSave(snapshot),error=>error.workspaceValidation&&/history was not removed/.test(error.message));
  assert.equal(JSON.stringify(snapshot),before);assert.equal(f.toasts.length,0);
});

test('a newer correction queued during a failed validation save is still saved once',async()=>{
  const f=fixture(),a=f.tab('existing');f.seed([a]);f.context.scheduleWorkspaceStateSave();
  const saving=f.context.flushWorkspaceState();
  a.requestText=raw('corrected while saving');f.context.scheduleWorkspaceStateSave();
  f.requests[0].resolve({ok:false,status:400,text:async()=> 'synthetic stale validation failure'});
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(f.requests.length,2);assert.equal(JSON.parse(f.requests[1].options.body).replay.tabs[0].request_text,a.requestText);
  f.succeed(1,{session_id:'session-a',revision:11});await saving;
  assert.equal(f.context.workspaceSaveDirty,false);assert.equal(f.timers.size,0);assert.equal(f.toasts.length,0);
});
