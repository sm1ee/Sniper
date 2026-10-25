'use strict';
// Passive History destination ownership regression. No app bootstrap, real transport, browser,
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
    addEventListener:(type,fn)=>handlers.set(type,fn),click:()=>handlers.get('click')?.()};
}
function fixture(cached = false) {
  const f = workspaceFixture(), c = f.context, a = f.tab('original'), b = f.tab('newer');
  f.seed([a],a.id);
  Object.assign(f.state,{activeTool:'proxy',activeProxyTab:'http-history',selectedId:record.id,selectedRecord:cached?record:null,_recordClipboardSessionGeneration:0});
  const created=[],saved=[],rendered=[],errors=[],details=[];
  const menu=element(), item=element({action:'send-to-replay'});
  menu.querySelectorAll=selector=>selector==='.context-menu-item'?[item]:[];
  f.els.contextMenu=menu;
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
  });
  const inertFetch=c.fetch;
  c.fetch=(url,options)=>{assert.equal(options,undefined);assert.match(url,/^\/api\/(?:transactions\/record-a|workspace-state)\?session_id=session-[ab]$/);return inertFetch(url,options);};
  const functions=['createRecordClipboardOwner','loadSelectedTransactionRecord','loadTransactionRecordById','transactionPath','createTransactionRecordMenuTarget','loadMenuTargetRecord','openReplayFromSelection','openTransactionRecordInReplay','editableRequestFromRecord','isWebSocketUpgradeRecord','isRequestPreviewTruncated','handleSendActionError','openContextMenu','closeContextMenu','positionContextMenu','contextMenuSessionIsCurrent','applyWorkspaceState'];
  for(const name of functions){const match=appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`,'m'));assert.ok(match,name);vm.runInContext(match[0],c);}
  vm.runInContext('let contextMenuTargetId=null; let contextMenuSessionId=null; let contextMenuRecordTarget=null; let contextMenuAnchor={x:0,y:0};',c);
  const menuStart=appSource.indexOf('els.contextMenu.querySelectorAll(".context-menu-item").forEach'),menuEnd=appSource.indexOf('/* ─── WS Frame context menu ─── */',menuStart);
  assert.ok(menuStart>=0&&menuEnd>menuStart);vm.runInContext(appSource.slice(menuStart,menuEnd),c);
  const keyEnd=appSource.indexOf('    // Cmd+R on the Intercept tab');
  const keyStart=appSource.lastIndexOf('    if (',keyEnd);
  const branch=appSource.slice(keyStart,keyEnd);assert.ok(branch.includes('state.activeProxyTab === "http-history"')&&branch.includes('openReplayFromSelection().catch(handleSendActionError)'));
  vm.runInContext('function actualHistoryKeyboard(event){\n'+branch+'\n}',c);
  const resetStart=appSource.indexOf('function resetSessionScopedUiState() {'),resetEnd=appSource.indexOf('  window.clearTimeout(refreshTimer);',resetStart);
  assert.ok(resetStart>=0&&resetEnd>resetStart);vm.runInContext(appSource.slice(resetStart,resetEnd)+'\n}',c);
  function open(){c.openContextMenu(10,10,record.id);}
  function start(route){if(route==='menu'){open();item.click();}else{let prevented=false;c.actualHistoryKeyboard({ctrlKey:true,metaKey:false,shiftKey:false,altKey:false,key:'r',preventDefault(){prevented=true;}});assert.equal(prevented,true);}}
  function reset(change,reselect=false){
    if(change==='session B'){f.state.activeSession={id:'session-b'};c.resetSessionScopedUiState();}
    if(change==='ABA'){f.state.activeSession={id:'session-b'};c.resetSessionScopedUiState();f.state.activeSession={id:'session-a'};c.resetSessionScopedUiState();}
    if(change==='same-session reset')c.resetSessionScopedUiState();
    // These assignments model later reset/reload state, not a full UI session
    // switch. Reselection is explicit only in labeled ABA keyboard scenarios.
    f.state.selectedId=reselect?record.id:null;f.state.selectedRecord=null;
    f.state.replayTabs=[b];f.state.activeReplayTabId=b.id;f.state.activeTool='dashboard';
  }
  function fullApply(){const generation=c.workspaceStateGeneration;c.applyWorkspaceState(f.remote([b]));assert.equal(c.workspaceStateGeneration,generation+1);assert.equal(f.state.activeReplayTabId,b.id);}
  async function merge(){const generation=c.workspaceStateGeneration,snapshot=f.remote([a]);snapshot.replay.tabs[0].pinned=true;await f.adopt(snapshot);assert.equal(c.workspaceStateGeneration,generation);assert.equal(f.state.replayTabs[0],a);assert.equal(a.pinned,true);}
  function observed(){return{created:created.length,saved:saved.length,rendered:rendered.length,errors:[...errors],toasts:f.toasts,readCount:f.requests.length,saveSessions:saved.map(v=>v.session),sourceIds:created.map(v=>v.options.sourceTransactionId),activeTool:f.state.activeTool,selectedId:f.state.selectedId,selectedRecordId:f.state.selectedRecord?.id||null,detailRendered:details};}
  return {...f,c,a,b,menu,item,created,saved,rendered,errors,details,open,start,reset,fullApply,merge,observed};
}
async function pending(f,route,stage){
  f.start(route);assert.equal(f.requests.length,1);assert.equal(f.requests[0].url,'/api/transactions/record-a?session_id=session-a');
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
  assert.deepEqual(f.details, [], 'retired read must not publish selected detail or empty state');
  assert.equal(f.state.selectedRecord, null, 'retired read must not replace selected record');
  assert.equal(f.created.length, 0, 'retired read must not create a Replay tab');
  assert.equal(f.saved.length, 0, 'retired read must not schedule a save');
  assert.equal(f.rendered.length, 0);
  assert.deepEqual(f.errors, []);
  assert.deepEqual(f.toasts, []);
  assert.equal(JSON.stringify(f.b), before, 'existing draft stays unchanged');
}
function assertCurrent(f, outcome) {
  if(outcome==='success') {
    assert.equal(successful(f), true);
    assert.equal(f.created[0].options.sourceTransactionId, record.id);
    assert.equal(f.saved[0].session, 'session-a');
  } else assert.equal(visibleError(f), true);
}
for(const route of ['menu','keyboard']) for(const stage of ['fetch','JSON']) {
  for(const change of ['session B','ABA','same-session reset']) for(const outcome of ['success','failure']) {
    test(`${route} ${stage} ${outcome} is retired after ${change}`, async()=>{
      const f=fixture(), finish=await pending(f,route,stage); f.reset(change);
      const before=JSON.stringify(f.b); await finish(outcome); assertRetired(f,before);
    });
  }
  for(const outcome of ['success','failure']) test(`${route} current ${stage} ${outcome} remains usable`,async()=>{
    const f=fixture(), finish=await pending(f,route,stage); await finish(outcome); assertCurrent(f,outcome);
  });
  for(const update of ['full apply','ordinary merge']) test(`${route} ${stage} intent survives same-session ${update}`,async()=>{
    const f=fixture(), finish=await pending(f,route,stage);
    if(update==='full apply') f.fullApply(); else await f.merge();
    const retained=f.state.replayTabs[0], before=JSON.stringify(retained);
    await finish('success'); assertCurrent(f,'success');
    assert.equal(f.state.replayTabs[0],retained); assert.equal(JSON.stringify(retained),before);
  });
  test(`${route} ${stage} intent preserves ordinary navigation policy`,async()=>{
    const f=fixture(), finish=await pending(f,route,stage); f.state.activeTool='dashboard';
    if(route==='menu') {f.state.selectedId='record-b';f.state.selectedRecord=null;}
    await finish('success'); assertCurrent(f,'success');
  });
}
for(const stage of ['fetch','JSON']) {
  test(`keyboard ${stage} after ABA and reselection publishes neither stale detail nor Replay tab`,async()=>{
    const f=fixture(), finish=await pending(f,'keyboard',stage);f.reset('ABA',true);
    const before=JSON.stringify(f.b);await finish('success');assertRetired(f,before);
  });
  test(`keyboard ${stage} missing record after ABA and reselection cannot publish stale empty detail`,async()=>{
    const f=fixture();f.start('keyboard');assert.equal(f.requests.length,1);
    const body=deferred();if(stage==='JSON'){f.requests[0].resolve({ok:true,json:()=>body.promise});await tick();}
    f.reset('ABA',true);const before=JSON.stringify(f.b);
    if(stage==='fetch')f.requests[0].resolve({ok:false});else body.resolve(null);
    await tick();assertRetired(f,before);
  });
  test(`keyboard ${stage} changed-row cancellation retains its existing policy`,async()=>{
    const f=fixture(),finish=await pending(f,'keyboard',stage);f.state.selectedId='record-b';f.state.selectedRecord=null;
    await finish('success');assertCurrent(f,'failure');assert.equal(f.state.selectedId,'record-b');assert.deepEqual(f.details,[]);
  });
}
for(const change of ['session B','ABA','same-session reset'])test(`generic menu closes before stale cached click after ${change}`,async()=>{
  const f=fixture(true);f.open();f.reset(change);const before=JSON.stringify(f.b);f.item.click();await tick();
  assertRetired(f,before);assert.equal(f.requests.length,0);
});
for(const route of ['menu','keyboard'])test(`fresh ${route} intent after reset still succeeds`,async()=>{
  const f=fixture();f.reset('same-session reset');f.state.selectedId=record.id;f.state.activeTool='proxy';
  const finish=await pending(f,route,'fetch');await finish('success');assertCurrent(f,'success');
});
// Synthetic same-stack reset before the next microtask. These robustness checks
// are not evidence that two ordinary browser user events interleave this way.
for(const route of ['menu','keyboard'])for(const change of ['session B','ABA','same-session reset'])test(`synthetic cached ${route} microtask is retired after synchronous ${change}`,async()=>{
  const f=fixture(true);f.start(route);f.reset(change);const before=JSON.stringify(f.b);await tick();
  assertRetired(f,before);assert.equal(f.requests.length,0);
});
// Default callers (including Sequence) do not opt into the Replay action owner.
test('default selected-record loader keeps its cached fast path',async()=>{
  const f=fixture(true);const value=await f.c.loadSelectedTransactionRecord();
  assert.equal(value,record);assert.equal(f.requests.length,0);assert.deepEqual(f.details,[]);
});
for(const stage of ['fetch','JSON'])for(const outcome of ['success','missing','failure','changed row'])test(`default selected-record loader preserves ${stage} ${outcome}`,async()=>{
  const f=fixture(), promise=f.c.loadSelectedTransactionRecord(), body=deferred();assert.equal(f.requests.length,1);
  if(stage==='JSON'){f.requests[0].resolve({ok:true,json:()=>body.promise});await tick();}
  if(outcome==='changed row')f.state.selectedId='record-b';
  const target=stage==='fetch'?f.requests[0]:body;
  if(outcome==='failure')target.reject(new Error('Synthetic default read failure'));
  else if(outcome==='missing')target.resolve(stage==='fetch'?{ok:false}:null);
  else target.resolve(stage==='fetch'?{ok:true,json:async()=>record}:record);
  if(outcome==='failure')await assert.rejects(promise,/Synthetic default read failure/);
  else {
    const value=await promise;assert.equal(value,outcome==='success'?record:null);
    assert.deepEqual(f.details,outcome==='success'?[record.id]:outcome==='missing'?[null]:[]);
    assert.equal(f.state.selectedRecord,outcome==='success'?record:null);
  }
  assert.equal(f.created.length,0);assert.equal(f.saved.length,0);
});
