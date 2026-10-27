'use strict';
// UI destination ownership only. Synthetic deferred responses, ordinary empty
// request body and inert tab/render/save callbacks; no actual transport or send.
const assert=require('node:assert/strict'),test=require('node:test'),vm=require('node:vm');
const {appSource}=require('./frontend-test-helpers.cjs');
const {fixture:workspaceFixture,deferred}=require('./replay-workspace-fixture.cjs');
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const held={id:'held-a',request:{scheme:'https',host:'example.com',method:'GET',path:'/ordinary',headers:[],body:'',body_encoding:'utf8',preview_truncated:false}};
function node(dataset={}){const handlers=new Map(),classes=new Set(['hidden']);return{dataset,style:{},offsetWidth:10,offsetHeight:10,classList:{add:x=>classes.add(x),remove:x=>classes.delete(x),contains:x=>classes.has(x)},addEventListener:(type,fn)=>handlers.set(type,fn),click:()=>handlers.get('click')?.()};}
function fixture(){
 const f=workspaceFixture(),c=f.context,a=f.tab('original'),b=f.tab('replacement');f.seed([a],a.id);
 Object.assign(f.state,{activeTool:'proxy',activeProxyTab:'intercept',selectedInterceptRecord:held,_recordClipboardSessionGeneration:0});
 const created=[],saved=[],rendered=[],errors=[];const items=new Map(['send-to-replay','copy-url'].map(action=>[action,node({interceptAction:action})]));
 const menu=node();menu.querySelectorAll=selector=>{assert.equal(selector,'[data-intercept-action]');return[...items.values()]};
 Object.assign(f.els,{interceptContextMenu:menu,contextMenu:node()});
 Object.assign(c,{URLSearchParams,window:{...c.window,innerWidth:1000,innerHeight:800},
  contextMenuTargetId:null,contextMenuSessionId:null,contextMenuRecordTarget:null,clearReplaySendInFlight(){},
  retireFindingActionProgress(){},cleanupWsReplayTab(){assert.fail('No WebSocket action permitted');},
  createReplayTab(options){created.push({options,sessionId:f.state.activeSession.id,generation:c.workspaceStateGeneration});return{id:'synthetic-created-'+created.length,...options};},
  buildEditableRawRequest(request){assert.equal(request.host,'example.com');assert.equal(request.body,'');return'SYNTHETIC EDITOR TEXT';},
  setActiveTool(tool){f.state.activeTool=tool;},scheduleWorkspaceStateSave(){saved.push({sessionId:f.state.activeSession.id,generation:c.workspaceStateGeneration,tabIds:f.state.replayTabs.map(t=>t.id)});},
  renderToolPanels(){rendered.push(f.state.activeTool);},console:{error:error=>errors.push(error.message),warn(){}},
  copyTextToClipboard(){assert.fail('No clipboard operation permitted');},recordToFormat(){assert.fail('No export operation permitted');},
 });
 const inertFetch=c.fetch;c.fetch=(path,options)=>{assert.equal(options,undefined);assert.match(path,/^\/api\/(?:intercepts\/held-a|workspace-state)\?session_id=session-[ab]$/);return inertFetch(path,options);};
 for(const name of ['runInterceptMenuAction','loadInterceptForMenu','createRecordClipboardOwner','openInterceptContextMenu','closeInterceptContextMenu','closeContextMenu','requireOkResponse','readApiErrorMessage','formatStructuredApiErrorMessage','handleClipboardActionError','applyWorkspaceState']){
  const match=appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`,'m'));assert.ok(match,name);vm.runInContext(match[0],c);
 }
 vm.runInContext('let interceptContextMenuTargetId = null; let interceptContextMenuClipboardOwner = null;',c);
 const menuStart=appSource.indexOf('els.interceptContextMenu?.querySelectorAll("[data-intercept-action]")'),menuEnd=appSource.indexOf('decorateContextMenuShortcuts();',menuStart);assert.ok(menuStart>=0&&menuEnd>menuStart);vm.runInContext(appSource.slice(menuStart,menuEnd),c);
 const keyStart=appSource.indexOf('    // Cmd+R on the Intercept tab'),keyEnd=appSource.indexOf('    // Cmd+R on WebSocket tab',keyStart);assert.ok(keyStart>=0&&keyEnd>keyStart);vm.runInContext('function actualKeyboardBranch(event) {\n'+appSource.slice(keyStart,keyEnd)+'\n}',c);
 const resetStart=appSource.indexOf('function resetSessionScopedUiState() {'),resetEnd=appSource.indexOf('  window.clearTimeout(refreshTimer);',resetStart);assert.ok(resetStart>=0&&resetEnd>resetStart);vm.runInContext(appSource.slice(resetStart,resetEnd)+'\n}',c);
 function start(route){if(route==='menu'){c.openInterceptContextMenu(10,10,'held-a');items.get('send-to-replay').click();}else{let prevented=false;c.actualKeyboardBranch({ctrlKey:true,metaKey:false,shiftKey:false,altKey:false,key:'r',preventDefault(){prevented=true}});assert.equal(prevented,true);}}
 function reset(kind){
  if(kind==='session B'){f.state.activeSession={id:'session-b'};c.resetSessionScopedUiState();}
  if(kind==='ABA'){f.state.activeSession={id:'session-b'};c.resetSessionScopedUiState();f.state.activeSession={id:'session-a'};c.resetSessionScopedUiState();}
  if(kind==='same-session reset')c.resetSessionScopedUiState();
  f.state.replayTabs=[b];f.state.activeReplayTabId=b.id;f.state.activeTool='dashboard';f.state.selectedInterceptRecord={id:'held-b'};
 }
 function fullApply(incoming=b){
  const before=c.workspaceStateGeneration;c.applyWorkspaceState(f.remote([incoming]));
  assert.equal(c.workspaceStateGeneration,before+1);assert.equal(f.state.activeReplayTabId,incoming.id);
  assert.notEqual(f.state.replayTabs[0],a);assert.equal(f.state.workspaceRevision,11);
 }
 async function merge(){
  const before=c.workspaceStateGeneration,snapshot=f.remote([a]);snapshot.replay.tabs[0].pinned=true;
  await f.adopt(snapshot);assert.equal(c.workspaceStateGeneration,before);assert.equal(f.state.replayTabs[0],a);
  assert.equal(a.pinned,true);assert.equal(f.state.workspaceRevision,11);assert.equal(c.workspaceSaveConflictPending,false);
 }
 return{...f,c,a,b,menu,items,created,saved,rendered,errors,start,reset,fullApply,merge};
}
async function pending(f,route,stage){
 f.start(route);assert.equal(f.requests.length,1);assert.equal(f.requests[0].url,'/api/intercepts/held-a?session_id=session-a');const body=deferred();
 if(stage==='JSON'){f.requests[0].resolve({ok:true,json:()=>body.promise});await tick();}
 if(stage==='error body'){f.requests[0].resolve({ok:false,headers:{get:()=> 'text/plain'},text:()=>body.promise});await tick();}
 return async outcome=>{
  if(stage==='error body')body.resolve('Synthetic delayed read failure');
  else if(outcome==='failure')(stage==='fetch'?f.requests[0]:body).reject(new Error('Synthetic delayed read failure'));
  else if(stage==='fetch')f.requests[0].resolve({ok:true,json:async()=>held});else body.resolve(held);
  await tick();
 };
}
const waits=[['fetch','success'],['fetch','failure'],['JSON','success'],['JSON','failure'],['error body','failure']];
function assertRetired(f,before){assert.equal(f.created.length,0,'retired intent must not create a tab');assert.equal(f.saved.length,0,'retired intent must not schedule save');assert.equal(f.rendered.length,0);assert.deepEqual(f.errors,[]);assert.deepEqual(f.toasts,[]);assert.equal(JSON.stringify(f.state),before);}
function assertCurrent(f,outcome){
 if(outcome==='success'){assert.equal(f.created.length,1);assert.equal(f.created[0].options.sourceTransactionId,null);assert.equal(f.created[0].options.baseRequest.path,'/ordinary');assert.equal(f.saved.length,1);assert.equal(f.saved[0].sessionId,'session-a');assert.equal(f.rendered.length,1);assert.deepEqual(f.errors,[]);}
 else{assert.equal(f.created.length,0);assert.equal(f.saved.length,0);assert.equal(f.errors.length,1);assert.equal(f.toasts.length,1);}
}
for(const route of ['menu','keyboard'])for(const [stage,outcome] of waits){
 for(const change of ['session B','ABA','same-session reset'])test(`${route} ${stage} ${outcome} is retired after ${change}`,async()=>{
  const f=fixture(),finish=await pending(f,route,stage);f.reset(change);const before=JSON.stringify(f.state);await finish(outcome);assertRetired(f,before);
 });
 test(`${route} ${stage} ${outcome} survives actual full same-session workspace application`,async()=>{
  const f=fixture(),finish=await pending(f,route,stage);f.fullApply();const applied=f.state.replayTabs[0],before=JSON.stringify(applied);await finish(outcome);assertCurrent(f,outcome);assert.equal(f.state.replayTabs[0],applied);assert.equal(JSON.stringify(applied),before);
 });
 test(`${route} ${stage} ${outcome} survives ordinary accepted workspace merge`,async()=>{
  const f=fixture(),finish=await pending(f,route,stage);await f.merge();await finish(outcome);assertCurrent(f,outcome);assert.equal(f.state.replayTabs[0],f.a);assert.equal(f.requests.length,2);assert.equal(f.beacons.length,0);
 });
}
for(const route of ['menu','keyboard'])for(const stage of ['fetch','JSON'])test(`${route} explicit ${stage} send survives same-owner selection and tool navigation`,async()=>{
 const f=fixture(),finish=await pending(f,route,stage);f.state.selectedInterceptRecord={id:'held-b'};f.state.activeTool='dashboard';const before=f.a.requestText;await finish('success');assertCurrent(f,'success');assert.equal(f.state.replayTabs[0],f.a);assert.equal(f.a.requestText,before);
});
for(const route of ['menu','keyboard'])for(const stage of ['fetch','JSON','error body'])test(`${route} current ${stage} error remains visible`,async()=>{
 const f=fixture(),finish=await pending(f,route,stage);await finish('failure');assertCurrent(f,'failure');
});
for(const change of ['session B','ABA','same-session reset'])for(const action of ['send-to-replay','copy-url'])test(`menu opened before ${change} refuses stale ${action} before read`,async()=>{
 const f=fixture();f.c.openInterceptContextMenu(10,10,'held-a');f.reset(change);f.items.get(action).click();await tick();assert.equal(f.requests.length,0);assert.equal(f.created.length,0);assert.deepEqual(f.toasts,[]);
});
for(const stage of ['fetch','JSON'])test(`new menu click after earlier full same-session application still owns its ${stage} read`,async()=>{
 const f=fixture();f.c.openInterceptContextMenu(10,10,'held-a');f.fullApply();f.items.get('send-to-replay').click();assert.equal(f.requests.length,1);
 const body=deferred();if(stage==='JSON'){f.requests[0].resolve({ok:true,json:()=>body.promise});await tick();body.resolve(held);}else f.requests[0].resolve({ok:true,json:async()=>held});await tick();assertCurrent(f,'success');assert.equal(f.created[0].generation,1);
});
test('clipboard ownership deliberately survives full same-session application but not reset',()=>{
 const f=fixture(),owner=f.c.createRecordClipboardOwner();f.fullApply();assert.equal(owner(),true);f.reset('same-session reset');assert.equal(owner(),false);
});

for(const route of ['menu','keyboard'])for(const stage of ['fetch','JSON'])test(`${route} ${stage} send survives identical same-session full application`,async()=>{
 const f=fixture(),finish=await pending(f,route,stage);f.fullApply(f.a);const applied=f.state.replayTabs[0],before=JSON.stringify(applied);await finish('success');assertCurrent(f,'success');assert.equal(f.state.replayTabs[0],applied);assert.equal(JSON.stringify(applied),before);
});
for(const route of ['menu','keyboard'])for(const stage of ['fetch','JSON'])test(`${route} fresh ${stage} intent after same-session reset still succeeds`,async()=>{
 const f=fixture();f.reset('same-session reset');f.state.activeTool='proxy';f.state.selectedInterceptRecord=held;const finish=await pending(f,route,stage);await finish('success');assertCurrent(f,'success');assert.equal(f.state.replayTabs[0],f.b);
});
