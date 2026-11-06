'use strict';
// Driven by replay-request-size-runtime.py using an isolated loopback server.
// Real frontend functions and shipped CodeMirror state/history; no native DOM.
// Input is a line-delimited private stdin protocol, never captured-body files.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto');
const root=require('node:path').resolve(__dirname,'..'), {editorFixture,source}=require(root+'/tests/replay-editor-fixture.cjs');
const readline=require('node:readline').createInterface({input:process.stdin}),lines=readline[Symbol.asyncIterator]();
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
const report={checks:[],requests:[],timers:[],errors:[],loadedAppSha256:sha(require(root+'/tests/frontend-test-helpers.cjs').appSource)};
const check=(name,yes,detail={})=>{assert.ok(yes,name);report.checks.push({name,...detail});};
(async()=>{
 const input=JSON.parse((await lines.next()).value),f=editorFixture(),c=f.context;
 Object.assign(c,{AbortController,WORKSPACE_SAVE_SAFE_BYTES:46*1024*1024,WORKSPACE_SAVE_RECORD_SAFE_BYTES:15*1024*1024,WORKSPACE_UNLOAD_HISTORY_ENTRIES_MAX_BYTES:12*1024,WORKSPACE_UNLOAD_RESPONSE_RECORD_MAX_BYTES:12*1024,REPEATER_HISTORY_LIMIT:100,HTTP_METHOD_TOKEN_RE:/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/,
  console:{error:e=>report.errors.push(e.message||String(e)),warn:e=>report.errors.push(String(e))},atob,btoa,
  renderReplayResponseOnly(){},scheduleRefresh(){},
  fetch:async(url,options)=>{assert.ok(['/api/workspace-state','/api/replay/send'].includes(url));const r=await fetch(input.url+url,options);report.requests.push({url,status:r.status});return r;}});
 const timeout=c.window.setTimeout;c.window.setTimeout=(fn,delay)=>{report.timers.push(delay);return timeout(fn);};
 const names=['openTransactionRecordInReplay','editableRequestFromRecord','isWebSocketUpgradeRecord','isRequestPreviewTruncated','sendReplay','isReplayTabStillCurrent','setReplaySending','replayEffectiveHttpVersion','flushWorkspaceStateForReplayAction','flushWorkspaceState','handleWorkspaceActionError','boundWorkspaceSnapshotForSave','workspaceUnloadSnapshotPayload','changedWorkspaceReplayTabIds','activeAndChangedReplayTabIds','replayTabTextSaveShape','changedReplayTabsIncludeTextChanges','compactWorkspaceUnloadSnapshot','compactWorkspaceUnloadReplayTab','compactWorkspaceUnloadCompleteArray','compactWorkspaceUnloadJsonValue','compactWorkspaceUnloadEditableRequest','compactWorkspaceUnloadText','compactWorkspaceUnloadFuzzer','readReplaySendError','isWorkspaceRevisionConflictPayload','replaySentDraftUnchanged','applyReplaySentDraftIfUnchanged','targetStatesEquivalent','replayTargetOverridePayload','recordRepeaterHistory','httpRequestAuthoritiesEquivalent','normalizeHttpRequestAuthority','buildUrlFromTarget','joinAuthority','isDefaultPortForScheme','parseCurlCommand','splitShellWords','decodeAnsiCStringEscape','applyCurlImport','curlDataBinaryBodyIsPlainText','appendCurlGetQuery','encodeCurlDataUrlencode','hostHeaderDiffersFromUrl','truncateUtf8','truncateUtf8Preview'];
 for(const name of names)vm.runInContext(source(name),c);
 f.state.activeSession={id:input.session};f.state.workspaceRevision=input.revision;
 f.a.baseRequest={...f.a.baseRequest,scheme:'http',host:input.authority,method:'POST',body:'S',headers:[{name:'Content-Length',value:'1'}]};
 f.a.requestText=`POST /baseline HTTP/1.1\nHost: ${input.authority}\nContent-Length: 1\n\nS`;f.a.targetScheme='http';f.a.targetHost='127.0.0.1';f.a.targetPort=String(input.port);f.seed([f.a]);f.render();
 c.scheduleWorkspaceStateSave();await c.flushWorkspaceState();check('small baseline native save succeeds',report.requests.at(-1).status===200);
 const shape=()=>sha(JSON.stringify({tabs:f.state.replayTabs,active:f.state.activeReplayTabId,sequence:f.state.replayTabSequence,tool:f.state.activeTool,editor:f.cv().getContent(),selection:f.selection(),owner:f.cv()._owner}));
 for(const {name,record} of input.records){
  const before=shape(),recordHash=sha(JSON.stringify(record)),count=report.requests.length,toasts=f.toasts.length,version=c.workspaceSaveVersion;
  const req=c.editableRequestFromRecord(record),text=c.buildEditableRawRequest(req);c.openTransactionRecordInReplay(record);await c.flushWorkspaceState();
  check(`${name}: import refused before tab/editor/session mutation`,shape()===before&&c.workspaceSaveVersion===version&&report.requests.length===count&&sha(JSON.stringify(record))===recordHash&&f.toasts.length===toasts+1,
    {textBytes:Buffer.byteLength(text),baseBytes:Buffer.byteLength(JSON.stringify(req)),toast:f.toasts.at(-1)[0]});
  if(name==='JSON escaping')check('JSON escaping refusal is stored-base-only',Buffer.byteLength(text)<2097152&&f.toasts.at(-1)[0].includes('stored request'));
  if(name==='Unicode')check('Unicode refusal counts UTF-8, not JavaScript characters',text.length<2097152&&Buffer.byteLength(text)>2097152);
 }
 check('refused imports issue no 400 or retry timers',report.requests.every(r=>r.status===200)&&!report.timers.includes(1000));
 // Actual cURL parser; only simple POSIX quotes containing synthetic input.
 const curl={value:`curl http://${input.authority}/curl --data-raw '${'A'.repeat(2304*1024)}'`},oldGet=f.document.getElementById;let modalClosed=false;
 f.document.getElementById=id=>id==='curlImportInput'?curl:oldGet(id);c.closeCurlImportModal=()=>{modalClosed=true;};
 let before=shape(),count=report.requests.length;c.applyCurlImport();
 check('oversized cURL import refused without closing modal or changing draft',shape()===before&&!modalClosed&&report.requests.length===count&&f.toasts.at(-1)[0].includes('Cannot import this cURL request'));
 // Actual CodeMirror transaction filter rejects oversized edit before model/undo.
 let i=f.cv().getContent().indexOf('/baseline');f.edit(i,i+9,'/allowed');const allowed=f.a.requestText,selection=JSON.stringify(f.selection()),owner=f.cv()._owner;
 for(const [name,text] of [['ASCII',`POST /huge HTTP/1.1\nHost: ${input.authority}\n\n${'A'.repeat(2304*1024)}`],['JSON escaping',`POST /huge HTTP/1.1\nHost: ${input.authority}\n\n${'"'.repeat(1280*1024)}`],['Unicode',`POST /huge HTTP/1.1\nHost: ${input.authority}\n\n${'漢'.repeat(768*1024)}`]]){
  const toasts=f.toasts.length;f.edit(0,f.cv().getContent().length,text);check(`${name}: oversized CM transaction refused without changing text/selection/owner`,f.a.requestText===allowed&&f.cv().getContent()===allowed&&JSON.stringify(f.selection())===selection&&f.cv()._owner===owner&&f.toasts.length===toasts+1);
 }
 check('undo/redo of prior legitimate edit survives refused imports and edits',f.undo()&&f.a.requestText.includes('/baseline')&&f.redo()&&f.a.requestText===allowed);
 await c.flushWorkspaceState();await c.sendReplay();await c.flushWorkspaceState();
 check('unrelated safe draft save and UI send succeed after refusals',report.requests.some(r=>r.url==='/api/replay/send'&&r.status===200)&&f.a.responseRecord?.status===200&&f.a.notice==='');
 const good=await(await fetch(input.url+'/api/workspace-state?session_id='+input.session)).json();
 check('successful replay history persists',good.replay.tabs[0].history_entries.length===1&&good.replay.tabs[0].request_text.includes('/allowed'));
 // Controlled native validation failure outside the new request guard.
 f.a.notice='N'.repeat(2097153);c.scheduleWorkspaceStateSave();const postBefore=report.requests.length;
 await assert.rejects(c.flushWorkspaceState(),/replay tab notice cannot exceed 2097152 bytes/);
 check('native validation400 is visible and does not retry unchanged snapshot',report.requests.length===postBefore+1&&report.requests.at(-1).status===400&&c.workspaceSaveDirty&&c.workspaceSaveTimer===null&&!report.timers.includes(1000)&&f.toasts.at(-1)[0].startsWith('Workspace was not saved:'));
 const event={type:'beforeunload',preventDefault(){this.prevented=true;}};c.flushWorkspaceStateOnUnload(event);check('failed save still requests unload protection',event.prevented===true&&f.beacons.length===0);
 console.log(JSON.stringify({phase:'restart-ready',revision:good.revision,tabId:f.a.id}));
 input.url=JSON.parse((await lines.next()).value).url;readline.close();
 f.a.notice='';c.scheduleWorkspaceStateSave();await c.flushWorkspaceState();
 check('correcting invalid field after restart recovers native saving',report.requests.at(-1).status===200&&!c.workspaceSaveDirty);
 report.toasts=f.toasts;fs.writeFileSync(input.report,JSON.stringify(report,null,2));console.log(JSON.stringify({phase:'done',checks:report.checks.length,requests:report.requests,errors:report.errors}));
})().catch(e=>{console.error(e.stack);process.exitCode=1;readline.close();});
