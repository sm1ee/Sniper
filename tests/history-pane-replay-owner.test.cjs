'use strict';
// Passive History pane Replay ownership regression. No app bootstrap, real transport, browser,
// clipboard, filesystem picker, body decoder, server, or request execution.
const assert = require('node:assert/strict');
const vm = require('node:vm');
const test = require('node:test');
const {appSource} = require('./frontend-test-helpers.cjs');
const {fixture: workspaceFixture, deferred} = require('./replay-workspace-fixture.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
const record = {id:'record-a',kind:'http',status:200,scheme:'https',host:'example.com',method:'GET',path:'/ordinary',request:{headers:[],body_preview:'',body_encoding:'utf8',preview_truncated:false}};
function element(dataset = {}) {
  const handlers = new Map(), classes = new Set(['hidden']);
  return {dataset,style:{},offsetWidth:10,offsetHeight:10,
    classList:{add:x=>classes.add(x),remove:x=>classes.delete(x),contains:x=>classes.has(x)},
    addEventListener:(type,fn)=>handlers.set(type,fn),dispatch:(type,event={})=>handlers.get(type)?.({preventDefault(){},...event})};
}
function fixture(cached = false, surface = 'requestView') {
  const f = workspaceFixture(), c = f.context, a = f.tab('original'), b = f.tab('newer');
  f.seed([a],a.id);
  Object.assign(f.state,{activeTool:'proxy',activeProxyTab:'http-history',selectedId:record.id,selectedRecord:cached?record:null,_recordClipboardSessionGeneration:0});
  const created=[],saved=[],rendered=[],errors=[],details=[];
  const menu=element(), pane=element(), doc=element(); menu.querySelectorAll=()=>[];
  f.els.contextMenu=menu;
  for(const key of ['requestView','responseView','requestViewCM','responseViewCM'])f.els[key]=element();
  const oldGetElement=f.document.getElementById;f.document.getElementById=id=>id==='paneContextMenu'?pane:oldGetElement(id);
  f.document.addEventListener=doc.addEventListener;
  Object.assign(c,{URLSearchParams,window:{...c.window,innerWidth:1000,innerHeight:800},
    clearReplaySendInFlight(){},retireFindingActionProgress(){},
    cleanupWsReplayTab(){assert.fail('No WebSocket path permitted');},
    createReplayTab(options){created.push({options,session:f.state.activeSession.id});return{id:'created-'+created.length,...options};},
    buildEditableRawRequest(request){assert.equal(request.host,'example.com');assert.equal(request.body,'');return'SYNTHETIC EDITOR TEXT';},
    setActiveTool:tool=>{f.state.activeTool=tool;},
    scheduleWorkspaceStateSave:()=>saved.push({session:f.state.activeSession.id,tabIds:f.state.replayTabs.map(t=>t.id)}),
    renderToolPanels:()=>rendered.push(f.state.activeTool),
    console:{error:error=>errors.push(error.message),warn(){}},
    renderEmptyDetail:()=>details.push(null),renderDetail:value=>details.push(value.id),
    getHistoryItem:()=>record,renderContextMenuNotes(){},loadUserNote(){},
    copyTextToClipboard(){assert.fail('No clipboard operation permitted');},recordToFormat(){assert.fail('No export operation permitted');},
  });
  const inertFetch=c.fetch;
  c.fetch=(url,options)=>{assert.equal(options,undefined);assert.match(url,/^\/api\/(?:transactions\/record-a|workspace-state)\?session_id=session-[ab]$/);return inertFetch(url,options);};
  const functions=['createRecordClipboardOwner','copyMenuTargetRecord','copyMenuTargetUrl','loadTransactionRecordById','transactionPath','createTransactionRecordMenuTarget','loadMenuTargetRecord','openTransactionRecordInReplay','editableRequestFromRecord','isWebSocketUpgradeRecord','isRequestPreviewTruncated','handleSendActionError','closeContextMenu','applyWorkspaceState'];
  for(const name of functions){const match=appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`,'m'));assert.ok(match,name);vm.runInContext(match[0],c);}
  vm.runInContext('let contextMenuTargetId=null; let contextMenuSessionId=null; let contextMenuRecordTarget=null;',c);
  const paneStart=appSource.indexOf('  // Pane context menu (right-click on Request/Response code-view)'),paneEnd=appSource.indexOf('\n  els.sendReplayButton.addEventListener',paneStart);
  assert.ok(paneStart>=0&&paneEnd>paneStart);vm.runInContext(appSource.slice(paneStart,paneEnd),c);
  const resetStart=appSource.indexOf('function resetSessionScopedUiState() {'),resetEnd=appSource.indexOf('  window.clearTimeout(refreshTimer);',resetStart);
  assert.ok(resetStart>=0&&resetEnd>resetStart);vm.runInContext(appSource.slice(resetStart,resetEnd)+'\n}',c);
  function open(){f.els[surface].dispatch('contextmenu',{clientX:10,clientY:10});}
  function click(action='send-to-replay'){pane.dispatch('click',{target:{closest:()=>({dataset:{paneAction:action}})}});doc.dispatch('click');}
  function start(){open();click();}
  function reset(change){
    if(change==='session B'){f.state.activeSession={id:'session-b'};c.resetSessionScopedUiState();}
    if(change==='ABA'){f.state.activeSession={id:'session-b'};c.resetSessionScopedUiState();f.state.activeSession={id:'session-a'};c.resetSessionScopedUiState();}
    if(change==='same-session reset')c.resetSessionScopedUiState();
    // These assignments model later reset/reload state, not a full UI session
    // switch. The pane's lexical target remains separate from row selection.
    f.state.selectedId=null;f.state.selectedRecord=null;
    f.state.replayTabs=[b];f.state.activeReplayTabId=b.id;f.state.activeTool='dashboard';
  }
  function fullApply(){const generation=c.workspaceStateGeneration;c.applyWorkspaceState(f.remote([b]));assert.equal(c.workspaceStateGeneration,generation+1);assert.equal(f.state.activeReplayTabId,b.id);}
  async function merge(){const generation=c.workspaceStateGeneration,snapshot=f.remote([a]);snapshot.replay.tabs[0].pinned=true;await f.adopt(snapshot);assert.equal(c.workspaceStateGeneration,generation);assert.equal(f.state.replayTabs[0],a);assert.equal(a.pinned,true);}
  function observed(){return{created:created.length,saved:saved.length,rendered:rendered.length,errors:[...errors],toasts:f.toasts,readCount:f.requests.length,saveSessions:saved.map(v=>v.session),sourceIds:created.map(v=>v.options.sourceTransactionId),activeTool:f.state.activeTool,selectedId:f.state.selectedId,selectedRecordId:f.state.selectedRecord?.id||null,detailRendered:details};}
  return {...f,c,a,b,menu,pane,doc,created,saved,rendered,errors,details,open,click,start,reset,fullApply,merge,observed};
}
async function pending(f,stage){
  f.start();assert.equal(f.requests.length,1);assert.equal(f.requests[0].url,'/api/transactions/record-a?session_id=session-a');
  const body=deferred();if(stage==='JSON'){f.requests[0].resolve({ok:true,json:()=>body.promise});await tick();}
  return async outcome=>{const target=stage==='fetch'?f.requests[0]:body;
    if(outcome==='failure')target.reject(new Error('Synthetic delayed read failure'));
    else target.resolve(stage==='fetch'?{ok:true,json:async()=>record}:record);
    await tick();};
}
const silent=f=>f.created.length===0&&f.saved.length===0&&f.rendered.length===0&&f.errors.length===0&&f.toasts.length===0;
const successful=f=>f.created.length===1&&f.saved.length===1&&f.rendered.length===1&&f.created[0].options.sourceTransactionId===record.id&&f.created[0].options.baseRequest.path==='/ordinary'&&f.errors.length===0&&f.toasts.length===0;
const visibleError=f=>f.created.length===0&&f.saved.length===0&&f.errors.length===1&&f.toasts.length===1;

function assertRetired(f, before) {
  assert.equal(f.created.length,0,'retired pane intent must not create a Replay draft');
  assert.equal(f.saved.length,0,'retired pane intent must not schedule a save');
  assert.equal(f.rendered.length,0);assert.deepEqual(f.errors,[]);assert.deepEqual(f.toasts,[]);
  assert.deepEqual(f.details,[]);assert.equal(JSON.stringify(f.b),before,'newer draft stays unchanged');
}
function assertCurrent(f,outcome) {
  if(outcome==='success') {
    assert.equal(successful(f),true);assert.equal(f.created[0].options.sourceTransactionId,record.id);
    assert.equal(f.saved[0].session,'session-a');
  } else assert.equal(visibleError(f),true);
}
for(const surface of ['requestView','responseView'])for(const stage of ['fetch','JSON']) {
  for(const change of ['session B','ABA','same-session reset'])for(const outcome of ['success','failure'])test(`${surface} ${stage} ${outcome} retires after ${change}`,async()=>{
    const f=fixture(false,surface),finish=await pending(f,stage);f.reset(change);const before=JSON.stringify(f.b);
    await finish(outcome);assertRetired(f,before);
  });
  for(const outcome of ['success','failure'])test(`${surface} current ${stage} ${outcome} remains usable`,async()=>{
    const f=fixture(false,surface),finish=await pending(f,stage);await finish(outcome);assertCurrent(f,outcome);
  });
  for(const update of ['full apply','ordinary merge'])test(`${surface} ${stage} intent survives same-session ${update}`,async()=>{
    const f=fixture(false,surface),finish=await pending(f,stage);if(update==='full apply')f.fullApply();else await f.merge();
    const retained=f.state.replayTabs[0],before=JSON.stringify(retained);await finish('success');assertCurrent(f,'success');
    assert.equal(f.state.replayTabs[0],retained);assert.equal(JSON.stringify(retained),before);
  });
  test(`${surface} ${stage} preserves captured target across row and tool navigation`,async()=>{
    const f=fixture(false,surface),finish=await pending(f,stage);f.state.selectedId='record-b';f.state.selectedRecord=null;f.state.activeTool='dashboard';
    await finish('success');assertCurrent(f,'success');
  });
  for(const kind of ['missing','tunnel'])test(`${surface} current ${stage} ${kind} is still reported`,async()=>{
    const f=fixture(false,surface);f.start();assert.equal(f.requests.length,1);const body=deferred();
    if(stage==='JSON'){f.requests[0].resolve({ok:true,json:()=>body.promise});await tick();}
    const value=kind==='missing'?null:{...record,kind:'tunnel'};
    if(stage==='fetch')f.requests[0].resolve({ok:true,json:async()=>value});else body.resolve(value);
    await tick();assertCurrent(f,'failure');assert.match(f.errors[0],kind==='missing'?/could not be loaded/:/Tunnel records/);
  });
}
for(const surface of ['requestView','responseView'])for(const change of ['session B','ABA','same-session reset']) {
  test(`${surface} cached menu opened before external ${change} cannot create a draft`,async()=>{
    const f=fixture(true,surface);f.open();f.reset(change);const before=JSON.stringify(f.b);f.click();await tick();
    assert.equal(f.requests.length,0);assert.equal(f.created.length,0);assert.equal(f.saved.length,0);
    if(change==='session B')assert.deepEqual(f.toasts,[['The selected session changed. Open the menu again.','error']]);
    else assertRetired(f,before);
  });
  test(`${surface} document click closes menu across ${change}`,async()=>{
    const f=fixture(true,surface);f.open();f.reset(change);f.doc.dispatch('click');assert.equal(f.pane.classList.contains('hidden'),true);
    const before=JSON.stringify(f.b);f.click();await tick();assertRetired(f,before);assert.equal(f.requests.length,0);
  });
  // This models an external reset without a document click, not the browser's
  // event sequence for an ordinary session-selector click.
  for(const stage of ['fetch','JSON'])test(`${surface} pending-at-open ${stage} survives only as an inert read after external ${change}`,async()=>{
    const f=fixture(false,surface);f.open();assert.equal(f.requests.length,1);const body=deferred();
    if(stage==='JSON'){f.requests[0].resolve({ok:true,json:()=>body.promise});await tick();}
    f.reset(change);const before=JSON.stringify(f.b);f.click();assert.equal(f.requests.length,1,'opening already prefetched; clicking must not add a read');
    if(stage==='fetch')f.requests[0].resolve({ok:true,json:async()=>record});else body.resolve(record);
    await tick();assert.equal(f.requests.length,1,'the fence does not claim cancellation of the issued read');
    if(change==='session B') {
      assert.equal(f.created.length,0);assert.equal(f.saved.length,0);assert.equal(f.rendered.length,0);assert.deepEqual(f.errors,[]);
      assert.deepEqual(f.toasts,[['The selected session changed. Open the menu again.','error']]);assert.equal(JSON.stringify(f.b),before);
    } else assertRetired(f,before);
  });
}
for(const surface of ['requestView','responseView']) {
  for(const change of ['ABA','same-session reset'])test(`${surface} existing cached copy-url remains retired after ${change}`,async()=>{
    const f=fixture(true,surface);f.open();f.reset(change);const before=JSON.stringify(f.b);f.click('copy-url');await tick();
    assertRetired(f,before);assert.equal(f.requests.length,0);
  });
  test(`${surface} full same-session application before a new click preserves intent`,async()=>{
    const f=fixture(true,surface);f.open();f.fullApply();const retained=f.state.replayTabs[0],before=JSON.stringify(retained);f.click();await tick();
    assertCurrent(f,'success');assert.equal(f.state.replayTabs[0],retained);assert.equal(JSON.stringify(retained),before);
  });
  test(`${surface} fresh post-reset intent succeeds`,async()=>{
    const f=fixture(false,surface);f.reset('same-session reset');f.state.selectedId=record.id;const finish=await pending(f,'fetch');await finish('success');assertCurrent(f,'success');
  });
  for(const kind of ['http','tunnel'])test(`${surface} current cached ${kind} keeps its existing outcome`,async()=>{
    const f=fixture(true,surface);f.state.selectedRecord={...record,kind};f.start();await tick();assertCurrent(f,kind==='http'?'success':'failure');assert.equal(f.requests.length,0);
  });
}
for(const stage of ['fetch','JSON'])test(`pending copy-as ${stage} remains retired after ABA`,async()=>{
  const f=fixture();f.open();f.click('copy-as-curl');assert.equal(f.requests.length,1);const body=deferred();
  if(stage==='JSON'){f.requests[0].resolve({ok:true,json:()=>body.promise});await tick();}
  f.reset('ABA');const before=JSON.stringify(f.b);if(stage==='fetch')f.requests[0].resolve({ok:true,json:async()=>record});else body.resolve(record);
  await tick();assertRetired(f,before);
});
for(const surface of ['requestViewCM','responseViewCM']) {
  test(`${surface} current cached callback succeeds`,async()=>{const f=fixture(true,surface);f.start();await tick();assertCurrent(f,'success');assert.equal(f.requests.length,0);});
  test(`${surface} delayed JSON callback retires after ABA`,async()=>{
    const f=fixture(false,surface),finish=await pending(f,'JSON');f.reset('ABA');const before=JSON.stringify(f.b);await finish('success');assertRetired(f,before);
  });
}
// Synthetic same-stack reset before microtasks; not evidence of normal browser
// user-event interleaving. These ensure cached continuations also recheck owner.
for(const surface of ['requestView','responseView'])for(const change of ['session B','ABA','same-session reset'])test(`synthetic ${surface} cached microtask retires after synchronous ${change}`,async()=>{
  const f=fixture(true,surface);f.start();f.reset(change);const before=JSON.stringify(f.b);await tick();assertRetired(f,before);assert.equal(f.requests.length,0);
});
