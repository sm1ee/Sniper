'use strict';
// Actual pure builder and app functions with inert editors; no app bootstrap,
// request transport, clipboard, server or browser. Candidate-only contract cases.
const test=require('node:test'), assert=require('node:assert/strict'), vm=require('node:vm');
const recon=require('../web/recon.js');
const {appSource}=require('./frontend-test-helpers.cjs');
const {fixture:workspaceFixture,plain}=require('./replay-workspace-fixture.cjs');
const endpoint=(overrides={})=>({method:'GET',url:'https://example.com/a?b=2&a=%2F',evidence:[{source:'crawler',kind:'candidate',location:'DO_NOT_PARSE password=secret'}],...overrides});
const build=(value)=>recon.buildReplayDraft(value);
for(const [url,scheme,host,path] of [
 ['http://example.com','http','example.com','/'],
 ['https://example.com?','https','example.com','/?'],
 ['https://EXAMPLE.com:443/a/../b?x=&x=%2f&x=2','https','EXAMPLE.com:443','/a/../b?x=&x=%2f&x=2'],
 ['http://example.com:80/%2e%2E/./a?','http','example.com:80','/%2e%2E/./a?'],
 ['https://example.com:8443//a?b=2&a=1','https','example.com:8443','//a?b=2&a=1'],
 ['http://[::1]:80/a','http','[::1]:80','/a'],
 ['https://[2001:db8::1]:8443/a?name=&other=','https','[2001:db8::1]:8443','/a?name=&other='],
 ['https://example.com/한글?x=🙂&q="','https','example.com','/한글?x=🙂&q="'],
])for(const method of ['GET','POST','custom-METHOD'])test(`Recon draft preserves ${method} ${url}`,()=>{
 const input=endpoint({url,method}),before=JSON.stringify(input),{request,notice}=build(input);
 assert.deepEqual(request,{scheme,host,method,path,headers:[{name:'Host',value:host}],body:'',body_encoding:'utf8',preview_truncated:false});
 assert.equal(notice,'Draft from Recon. Not sent yet.');assert.equal(JSON.stringify(input),before);
});
for(const method of [undefined,null,'','UNKNOWN','unknown','CONNECT','connect','G ET','GET\r\nHost:x','GET:','GÉT'])test(`Recon draft refuses invalid method ${JSON.stringify(method)}`,()=>assert.throws(()=>build(endpoint({method})),/safe HTTP/));
for(const url of [undefined,null,'','example.com/a','//example.com/a','ftp://example.com/','ws://example.com/','https://user:pass@example.com/','https://@example.com/','https://*.example.com/','https://%2a.example.com/','https:///x','https://example.com:0/','https://example.com:/','https://example.com:65536/','https://example.com:abc/','https://::1/a','https://[invalid]/','https://example.com/#x','https://example.com/#','https://example.com/with space',' https://example.com/','https://example.com/\nX','https://example.com/\u0085','https://example.com/\u00a0','https://example.com/\\x','https://example.com/\ud800'])test(`Recon draft refuses unsafe URL ${JSON.stringify(url)}`,()=>assert.throws(()=>build(endpoint({url})),/safe HTTP/));
// Replay shows its notice in the response header and body alike, so it stays
// as short as Replay's own; the evidence remains in Recon.
test('Recon draft notice is fixed text whatever the evidence holds',()=>{
 const {notice}=build(endpoint({evidence:[{source:'wayback',kind:'history',location:'SECRET'},{source:'__proto__',kind:'constructor'},{source:{},kind:[]},null],raw_urls:['SECRET'],jobs:[{target:'SECRET'}]}));
 assert.equal(notice,'Draft from Recon. Not sent yet.');
});
test('Recon request serialized size accepts exact2MiB and refuses one byte over',()=>{
 const limit=2*1024*1024,small=build(endpoint({url:'https://example.com/'}));
 const overhead=Buffer.byteLength(JSON.stringify(small.request));
 const url='https://example.com/'+'a'.repeat(limit-overhead);
 assert.equal(Buffer.byteLength(JSON.stringify(build(endpoint({url})).request)),limit);
 assert.throws(()=>build(endpoint({url:url+'a'})),/limits/);
});
test('Recon escaped Unicode counts match exact JSON at boundary',()=>{
 const limit=2*1024*1024,prefix='https://example.com/한🙂"',small=build(endpoint({url:prefix}));
 const extra=limit-Buffer.byteLength(JSON.stringify(small.request));const url=prefix+'a'.repeat(extra);
 assert.equal(Buffer.byteLength(JSON.stringify(build(endpoint({url})).request)),limit);assert.throws(()=>build(endpoint({url:url+'"'})),/limits/);
});
test('Recon admission rejects oversized original strings before URL or JSON leaf allocation',()=>{
 const huge='x'.repeat(2*1024*1024+1);assert.throws(()=>build(endpoint({url:huge})),/limits/);assert.throws(()=>build(endpoint({method:huge})),/limits/);
 assert.throws(()=>build(endpoint({url:'https://'+'x'.repeat(4097)+'/'})),/limits/);
});
test('Recon admission does not touch unrelated or raw evidence fields',()=>{
 const e=endpoint();for(const key of ['raw_urls','jobs','body','headers'])Object.defineProperty(e,key,{get(){assert.fail('unselected '+key);}});
 Object.defineProperty(e.evidence[0],'location',{get(){assert.fail('raw evidence text');}});assert.equal(build(e).request.body,'');
});
function fixture(){
 const f=workspaceFixture(),c=f.context,a=f.tab('original');f.seed([a]);f.a=a;
 const saves=[],navigations=[],renders=[];
 Object.assign(c,{window:{...c.window,SniperRecon:recon},setActiveTool:tool=>{navigations.push(tool);f.state.activeTool=tool;},scheduleWorkspaceStateSave:()=>saves.push(f.state.replayTabs.map(t=>t.id)),renderToolPanels:()=>renders.push(true),fetch:()=>assert.fail('No transport permitted')});
 f.state.activeTool='scan';f.state._recordClipboardSessionGeneration=0;
 for(const name of ['createRecordClipboardOwner','appendUnsentReplayDraft','openReconEndpointInReplay']){const match=appSource.match(new RegExp(`^function ${name}\\([^]*?^\\}`,'m'));assert.ok(match,'feature function '+name);vm.runInContext(match[0],c);}
 f.own=()=>{c.renderedHttpReplayDraftOwner={tab:a,sessionId:'session-a',generation:c.workspaceStateGeneration};};
 f.open=(value=endpoint(),current=()=>true)=>c.openReconEndpointInReplay(value,current);
 return {...f,c,saves,navigations,renders};
}
test('actual app wiring binds the Recon handoff callback',()=>assert.match(appSource,/openInReplay:\s*openReconEndpointInReplay/));
test('actual app appends one unsent null-identity draft without replacing old model',()=>{
 const f=fixture(),before=JSON.stringify(f.a);assert.equal(f.open(endpoint({method:'POST',url:'https://example.com:443/form?x='})),true);
 assert.equal(f.state.replayTabs.length,2);assert.equal(JSON.stringify(f.a),before);const tab=f.state.replayTabs[1];
 assert.equal(tab.sourceTransactionId,null);assert.equal(tab.responseRecord,null);assert.deepEqual(plain(tab.historyEntries),[]);assert.equal(tab.baseRequest.host,'example.com:443');
 assert.equal(tab.requestText,'POST /form?x= HTTP/1.1\nHost: example.com:443');assert.equal(tab.baseRequest.body,'');assert.equal(f.saves.length,1);assert.deepEqual(f.navigations,['replay']);assert.equal(f.renders.length,1);assert.equal(f.requests.length,0);
});
for(const owner of ['owned','missing','wrong tab','wrong session','wrong generation'])test(`actual app preserves invalid raw editor text only for ${owner} owner`,()=>{
 const f=fixture(),before=f.a.requestText;f.own();
 if(owner==='missing')f.c.renderedHttpReplayDraftOwner=null;
 if(owner==='wrong tab')f.c.renderedHttpReplayDraftOwner.tab=f.tab('other');
 if(owner==='wrong session')f.c.renderedHttpReplayDraftOwner.sessionId='session-b';
 if(owner==='wrong generation')f.c.renderedHttpReplayDraftOwner.generation++;
 f.els.replayRequestHighlight.innerText='unfinished invalid raw request';
 assert.equal(f.open(),true);assert.equal(f.a.requestText,owner==='owned'?'unfinished invalid raw request':before);assert.equal(f.saves.length,owner==='owned'?2:1);
});
for(const invalid of ['target','version','hex'])test(`actual app ${invalid} refusal retains current tab and permits explicit retry`,()=>{
 const f=fixture();f.own();const before=JSON.stringify(f.a);
 if(invalid==='target')f.els.replayHostInput.value='bad host';
 if(invalid==='version')f.versionSelect.value='HTTP/bad';
 if(invalid==='hex'){f.state.replayMessageViews.request='hex';f.a.requestBytes=new Uint8Array([1]);f.els.replayRequestHighlight.querySelector=()=>({value:'?',closest:()=>({dataset:{idx:'0'}})});}
 const stable=JSON.stringify(f.a);assert.equal(f.open(),false);assert.equal(JSON.stringify(f.a),stable);assert.equal(f.state.replayTabs.length,1);assert.equal(f.saves.length,0);assert.equal(f.navigations.length,0);
 f.syncDom();f.state.replayMessageViews.request='raw';f.a.requestBytes=null;assert.equal(f.open(),true);assert.equal(f.state.replayTabs.length,2);
});
test('actual app preserves changed valid target and version together',()=>{
 const f=fixture();f.own();f.els.replayHostInput.value='other.example.com';f.els.replayPortInput.value='8443';f.versionSelect.value='HTTP/2';
 assert.equal(f.open(),true);assert.equal(f.a.targetHost,'other.example.com');assert.equal(f.a.targetPort,'8443');assert.equal(f.a.httpVersionMode,'HTTP/2');assert.match(f.a.requestText,/HTTP\/2/);
});
for(const kind of ['no tab','WebSocket'])test(`actual app ${kind} has no hidden HTTP editor import`,()=>{
 const f=fixture();if(kind==='no tab'){f.state.replayTabs=[];f.state.activeReplayTabId=null;}else{f.a.type='websocket';f.own();}
 Object.defineProperty(f.els.replayHostInput,'value',{get(){assert.fail('must not read hidden HTTP controls');}});
 assert.equal(f.open(),true);assert.equal(f.saves.length,1);
});
for(const reason of ['unloaded','no session','view stale','tabs full','invalid discovery'])test(`actual app refuses ${reason} before mutating old draft`,()=>{
 const f=fixture();f.own();f.els.replayRequestHighlight.innerText='UNCOMMITTED';const before=JSON.stringify(f.a),sequence=f.state.replayTabSequence;
 if(reason==='unloaded')f.c.workspaceLoaded=false;
 if(reason==='no session')f.state.activeSession=null;
 if(reason==='tabs full')f.state.replayTabs=Array(512).fill(f.a);
 const run=()=>f.open(reason==='invalid discovery'?endpoint({method:'UNKNOWN'}):endpoint(),()=>reason!=='view stale');
 if(['tabs full','invalid discovery'].includes(reason))assert.throws(run);else assert.equal(run(),false);
 assert.equal(JSON.stringify(f.a),before);assert.equal(f.state.replayTabSequence,sequence);assert.equal(f.saves.length,0);assert.equal(f.navigations.length,0);
});
for(const change of ['session','reset ABA','view'])test(`actual app rechecks ${change} owner before append`,()=>{
 const f=fixture();let calls=0;
 const current=()=>{calls++;if(calls===2){if(change==='session')f.state.activeSession={id:'session-b'};if(change==='reset ABA')f.state._recordClipboardSessionGeneration++;if(change==='view')return false;}return true;};
 assert.equal(f.open(endpoint(),current),false);assert.equal(f.state.replayTabs.length,1);assert.equal(f.saves.length,0);
});

test('Recon authority admits exact4KiB and refuses one byte over',()=>{
 const host='a'.repeat(4096);assert.equal(build(endpoint({url:'https://'+host+'/'})).request.host,host);
 assert.throws(()=>build(endpoint({url:'https://'+host+'a/'})),/limits/);
});
test('Recon draft serialized escaping refusal does not inspect evidence or mutate input',()=>{
 const e=endpoint({url:'https://example.com/'+'"'.repeat(1024*1024)});
 Object.defineProperty(e,'evidence',{get(){assert.fail('overlimit must refuse before evidence traversal');}});
 assert.throws(()=>build(e),/limits/);
});
test('actual app permits the512th tab but refuses a513th without consuming sequence',()=>{
 const f=fixture();f.state.replayTabs=Array(511).fill(f.a);assert.equal(f.open(),true);assert.equal(f.state.replayTabs.length,512);
 const sequence=f.state.replayTabSequence;assert.throws(()=>f.open(),/Close a Replay tab/);assert.equal(f.state.replayTabSequence,sequence);assert.equal(f.saves.length,1);
});
test('actual app rechecks owner after successful editor preservation without appending to replacement workspace',()=>{
 const f=fixture();f.own();f.els.replayRequestHighlight.innerText='unfinished preserved';
 f.c.scheduleWorkspaceStateSave=()=>{f.state._recordClipboardSessionGeneration++;};
 assert.equal(f.open(),false);assert.equal(f.a.requestText,'unfinished preserved');assert.equal(f.state.replayTabs.length,1);assert.equal(f.navigations.length,0);
});

for (const method of ['M-SEARCH', 'custom-METHOD', '!token']) test(`actual Recon tab uses explicit HTTP/1.1 editing default for ${method}`,()=>{
 const f=fixture();assert.equal(f.open(endpoint({method})),true);const tab=f.state.replayTabs.at(-1);
 assert.equal(tab.baseRequest.method,method);assert.ok(tab.requestText.startsWith(`${method} /a?b=2&a=%2F HTTP/1.1\n`));
 assert.equal(tab.httpVersionMode,'HTTP/1.1');assert.equal(Object.hasOwn(tab.baseRequest,'http_version'),false);
 assert.equal(tab.sourceTransactionId,null);assert.equal(f.requests.length,0);
});
test('shared append refuses stale owner before cap, editor read or sequence mutation',()=>{
 const f=fixture();f.state.replayTabs=Array(512).fill(f.a);f.own();
 Object.defineProperty(f.els.replayHostInput,'value',{get(){assert.fail('stale helper must not read editor');}});
 const sequence=f.state.replayTabSequence;
 assert.equal(f.c.appendUnsentReplayDraft({},()=>false,'test stale handoff'),false);
 assert.equal(f.state.replayTabSequence,sequence);assert.equal(f.saves.length,0);assert.equal(f.navigations.length,0);
});
