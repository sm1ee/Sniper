'use strict';
// Synthetic production-function regression fixtures. Inert HTTP specimens only;
// all fetches resolve in memory. No app execution, Cargo, sockets or network.
const assert = require('node:assert/strict');
const test = require('node:test');
const {loadFunctions, appSource} = require('./frontend-test-helpers.cjs');
const vm = require('node:vm');
const tick = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => {let resolve, reject; const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
const rec = (id='finding-a', path='/finding-a') => ({id,kind:'http',scheme:'https',host:'example.com',method:'GET',path,http_version:'HTTP/1.1',request:{headers:[],body_preview:'',body_encoding:'utf8'}});
const response = record => ({ok:true,status:200,json:async()=>record});
function fixture() {
 const state={activeSession:{id:'session-a'},activeTool:'proxy',activeProxyTab:'findings',selectedId:'history-a',selectedRecord:null,
   fuzzerBaseRequest:{scheme:'https',host:'example.com',method:'GET',path:'/old?id=$payload$',headers:[]},
   fuzzerRequestText:'GET /old?id=$payload$ HTTP/1.1\nHost: example.com',fuzzerPayloadsText:'prepared-one\nprepared-two',
   fuzzerTarget:{scheme:'https',host:'example.com',port:'8443'},fuzzerTargetRequestText:'https://example.com',fuzzerSourceTransactionId:'old',
   fuzzerDraftVersion:3,fuzzerRunToken:7,fuzzerRunning:false,fuzzerAttackRecord:{id:'old-run'},fuzzerAttackRecordId:'old-run'};
 const reads=[],posts=[],effects=[];
 const els={fuzzerPayloadsEditor:{value:state.fuzzerPayloadsText}};
 const c=loadFunctions(['runFindingAction','openFuzzerFromRecordLoader','sendFindingToFuzzer','openFuzzerFromSelection','openFuzzerFromRecord','loadSelectedTransactionRecord','loadTransactionRecordById','createTransactionRecordMenuTarget','loadMenuTargetRecord','updateFuzzerRequestText','updateFuzzerPayloadsText','markFuzzerDraftChanged','invalidateFuzzerRun','isCurrentFuzzerRun','runFuzzerAttack','currentSessionId','transactionPath','sessionQueryPath','editableRequestFromRecord','buildEditableRawRequest','normalizedHeaders','headerNameEquals','mergeHeaders','isRequestPreviewTruncated','invalidateFindingNavigation', 'setActiveTool','setActiveProxyTab'],{
  state,els,TextEncoder,workspaceStateGeneration:0,document:{getElementById:()=>null},
  selectedFindingId:'finding-a',findingsDetailGeneration:0,findingActionPending:null,
  sanitizeActiveTool:value=>value,sanitizeActiveProxyTab:value=>value,closeScannerSettings(){},scheduleUiSettingsSave(){},
  fetch(url,options){assert.match(url,/^\/api\/(transactions\/[^?]+\?session_id=|fuzzer\/attacks$)/);const item={url,options,...deferred()};(options?posts:reads).push(item);return item.promise;},
  requireOkResponse:async r=>{assert.equal(r.ok,true);},
  buildTruncatedBodyNotice:()=> 'Truncated request',clearFuzzerAttackRecord(){state.fuzzerAttackRecord=null;state.fuzzerAttackRecordId=null;},
  setFuzzerAttackRecord(r){state.fuzzerAttackRecord=r;state.fuzzerAttackRecordId=r.id;},normalizeFuzzerAttackRecord:r=>r,
  hideFuzzerDetailPanel(){effects.push('hide-detail');},
  scheduleWorkspaceStateSave(){effects.push('save');},renderToolPanels(){els.fuzzerPayloadsEditor.value=state.fuzzerPayloadsText;effects.push('render-panels');},renderFuzzer(){els.fuzzerPayloadsEditor.value=state.fuzzerPayloadsText;},
  renderEmptyDetail(){effects.push('empty-history-detail');},renderDetail(r){effects.push('render-history:'+r.id);},
  fuzzerRequestTextForAction:()=>state.fuzzerRequestText,parseFuzzerRequestTemplate:()=>({...state.fuzzerBaseRequest}),
  fuzzerPayloadTextWithinLimits:value=>value.split('\n'),SniperFuzzerWorkflow:{preflight:()=>({valid:true})},
  fuzzerTargetAuthorityFromRequestText:()=> 'https://example.com',activeFuzzerTargetForRequest:()=>state.fuzzerTarget,replayHttpVersionFromText:()=> 'HTTP/1.1',
  flushWorkspaceStateForReplayAction:async()=>1,expectedActiveSessionIdForWrite:v=>v,
  scheduleRefresh(){effects.push('refresh');},WorkspaceStateConflictError:class extends Error{},console,
 });
 // Same reset assignments as the production session reset, plus the production
 // workspace generation and history selection lifetime invalidations.
 const start=appSource.indexOf('  state.fuzzerRunToken =',appSource.indexOf('function resetSessionScopedUiState()'));
 const end=appSource.indexOf('  state.sequenceDefinitions =',start);
 assert.ok(start>=0&&end>start);
 vm.runInContext(`function sessionReset() {workspaceStateGeneration += 1; state.selectedId = null; state.selectedRecord = null; ${appSource.slice(start,end)} }`,c);
 return {c,state,els,reads,posts,effects};
}

const begin = (f, route) => {
  if (route === 'findings') return f.c.sendFindingToFuzzer('finding-a');
  if (route === 'history') return f.c.openFuzzerFromSelection();
  const target = f.c.createTransactionRecordMenuTarget('history-a');
  return f.c.openFuzzerFromRecordLoader(() => f.c.loadMenuTargetRecord(target));
};
const source = route => rec(route === 'findings' ? 'finding-a' : 'history-a');

test('Findings import preserves prepared payload bytes, replaces request source and clears old target', async () => {
 const f=fixture(),p=begin(f,'findings');f.reads[0].resolve(response(rec()));assert.equal(await p,true);
 assert.equal(f.state.fuzzerPayloadsText,'prepared-one\nprepared-two');assert.equal(f.els.fuzzerPayloadsEditor.value,f.state.fuzzerPayloadsText);
 assert.equal(f.state.fuzzerTarget,null);assert.equal(f.state.fuzzerTargetRequestText,null);assert.equal(f.state.fuzzerSourceTransactionId,'finding-a');
});

test('Findings cannot invalidate a running Fuzzer, and the original result remains owned', async () => {
 const f=fixture(),run=f.c.runFuzzerAttack();await tick();const token=f.state.fuzzerRunToken;
 await assert.rejects(begin(f,'findings'),/Wait for the current Fuzzer run/);assert.equal(f.reads.length,0);
 assert.equal(f.state.fuzzerRunToken,token);assert.equal(f.state.fuzzerRunning,true);
 f.posts[0].resolve(response({id:'completed-live-run',status:'completed',results:[{index:0,status:200}]}));await run;
 assert.equal(f.state.fuzzerAttackRecord.id,'completed-live-run');
});

for(const route of ['findings','history','menu']) for(const stage of ['fetch','json']) {
 for(const boundary of ['draft','new-import','session-aba','workspace','navigation-aba','proxy-tab-aba','run']) {
  test(`${route} ${stage} completion cannot cross ${boundary}`, async () => {
   const f=fixture(),p=begin(f,route),body=deferred();
   if(stage==='json'){f.reads[0].resolve({ok:true,json:()=>body.promise});await tick();}
   if(boundary==='draft')f.c.updateFuzzerRequestText('GET /newer-draft HTTP/1.1\nHost: example.com',{userEdit:true});
   if(boundary==='new-import')f.c.openFuzzerFromRecord(rec('newer','/newer'));
   if(boundary==='session-aba'){f.state.activeSession={id:'session-b'};f.c.sessionReset();f.state.activeSession={id:'session-a'};f.c.sessionReset();}
   if(boundary==='workspace')f.c.workspaceStateGeneration++;
   if(boundary==='navigation-aba'){f.c.setActiveTool('decoder');f.c.setActiveTool('proxy');}
   if(boundary==='proxy-tab-aba'){f.c.setActiveProxyTab('http-history');f.c.setActiveProxyTab('findings');}
   if(boundary==='run'){f.state.fuzzerRunToken++;f.state.fuzzerRunning=true;}
   const before=JSON.stringify(f.state);
   if(stage==='json')body.resolve(source(route));else f.reads[0].resolve(response(source(route)));
   assert.equal(await p,false);assert.equal(JSON.stringify(f.state),before);
  });
 }
 for(const failure of ['fetch','json'])test(`${route} ignores stale ${failure} errors after navigation`,async()=>{
  const f=fixture(),p=begin(f,route),body=deferred();
  if(failure==='json'){f.reads[0].resolve({ok:true,json:()=>body.promise});await tick();}
  f.c.setActiveTool('decoder');
  if(failure==='json')body.reject(new Error('old error'));else f.reads[0].reject(new Error('old error'));
  assert.equal(await p,false);assert.equal(f.state.activeTool,'decoder');
 });
}

test('newer async import wins even when the old fetch completes last',async()=>{
 const f=fixture(),a=begin(f,'findings'),b=f.c.sendFindingToFuzzer('finding-b');
 f.reads[1].resolve(response(rec('finding-b','/newer-b')));assert.equal(await b,true);
 f.c.updateFuzzerPayloadsText('payloads-for-b',{userEdit:true});const before=JSON.stringify(f.state);
 f.reads[0].resolve(response(rec('finding-a','/stale-a')));assert.equal(await a,false);assert.equal(JSON.stringify(f.state),before);
});

test('History selection A-B-A retires the older shortcut import',async()=>{
 const f=fixture(),p=begin(f,'history');f.state.selectedId='history-b';f.state._historySelectionGeneration=1;
 f.state.selectedId='history-a';f.state._historySelectionGeneration=2;
 f.reads[0].resolve(response(rec('history-a')));assert.equal(await p,false);assert.equal(f.state.fuzzerSourceTransactionId,'old');
});

test('explicit History menu import retains clicked row identity despite a later selection',async()=>{
 const f=fixture(),p=begin(f,'menu');f.state.selectedId='history-b';f.state._historySelectionGeneration=1;
 f.reads[0].resolve(response(rec('history-a')));assert.equal(await p,true);assert.equal(f.state.fuzzerSourceTransactionId,'history-a');
});

test('unchanged cached History import uses captured record without a fetch',async()=>{
 const f=fixture();f.state.selectedRecord=rec('history-a');assert.equal(await begin(f,'history'),true);
 assert.equal(f.reads.length,0);assert.equal(f.state.fuzzerSourceTransactionId,'history-a');
});

for(const kind of ['missing','tunnel','current-error'])test(`current ${kind} import fails without changing the draft`,async()=>{
 const f=fixture(),p=begin(f,'findings');const before=f.state.fuzzerRequestText;
 if(kind==='current-error')f.reads[0].reject(new Error('current read failed'));
 else f.reads[0].resolve(response(kind==='missing'?null:{...rec(),kind:'tunnel'}));
 await assert.rejects(p);assert.equal(f.state.fuzzerRequestText,before);assert.equal(f.state.fuzzerPayloadsText,'prepared-one\nprepared-two');
});

test('both History menu bindings use the owned Fuzzer loader',()=>{
 assert.match(appSource,/action === "send-to-fuzzer"\) \{\s+openFuzzerFromRecordLoader\(\(\) => loadMenuTargetRecord\(target\)\)/);
 assert.match(appSource,/action === "send-to-fuzzer"\) \{\s+openFuzzerFromRecordLoader\(loadTargetRecord\)/);
});
