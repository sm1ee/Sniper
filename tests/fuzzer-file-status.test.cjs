'use strict';
// Inert synthetic files and DOM only; no browser, server or real traffic.
const assert = require('node:assert/strict');
const test = require('node:test');
const {loadFunctions, appSource} = require('./frontend-test-helpers.cjs');
const workflow = require('../web/fuzzer-workflow.js');
const deferred = () => { let resolve, reject; const promise = new Promise((a,b) => {resolve=a;reject=b;}); return {promise,resolve,reject}; };
function fixture() {
  const state = {activeTool:'fuzzer', activeSession:{id:'a'}, fuzzerPayloadsText:'original', fuzzerDraftVersion:1, fuzzerRunToken:2};
  const classes = new Set(['hidden']);
  const notice = {textContent:'', classList:{toggle(name,on){if(on)classes.add(name);else classes.delete(name);}}};
  const nodes = {fuzzerPayloadImportStatus:notice};
  const effects = {toasts:0,focus:0};
  const c = loadFunctions(['renderFuzzerPayloadImportStatus','fuzzerSetupNode','importFuzzerPayloadFile','applyFuzzerPayloadList','updateFuzzerPayloadsText','markFuzzerDraftChanged','fuzzerPayloadTextWithinLimits','fuzzerPayloadCount','splitFuzzerPayloadLines','initFuzzerSetupControls'], {
    state,TextEncoder,TextDecoder,SniperFuzzerWorkflow:workflow,document:{getElementById:id=>nodes[id] || null},
    currentSessionId:()=>state.activeSession.id, renderFuzzer(){c.renderFuzzerPayloadImportStatus();},scheduleWorkspaceStateSave(){},
    scheduleFuzzerSetupRender(){c.renderFuzzerPayloadImportStatus();},showToast(){effects.toasts++;},
    markFuzzerEditorSelection(){},undoFuzzerMarker(){},clearFuzzerMarkers(){},fuzzerSetupError(){effects.toasts++;},
  });
  function begin(mode='replace') {const d=deferred();const promise=c.importFuzzerPayloadFile({size:5,arrayBuffer:()=>d.promise},mode);return {...d,promise};}
  return {c,state,notice,classes,nodes,effects,begin};
}
const bytes = text=>new TextEncoder().encode(text);
test('background success survives tool navigation and clears local loading status',async()=>{
 const f=fixture(), job=f.begin(); assert.match(f.notice.textContent,/Reading/);assert.equal(f.classes.has('hidden'),false);
 f.state.activeTool='decoder';f.state._fuzzerNavigationGeneration=3;job.resolve(bytes('fresh'));
 assert.equal(await job.promise,true);assert.equal(f.state.fuzzerPayloadsText,'fresh');assert.equal(f.classes.has('hidden'),true);assert.equal(f.notice.textContent,'');
});
test('failure remains local across navigation and rerender, retry clears it and success hides status',async()=>{
 const f=fixture(), job=f.begin();f.state.activeTool='decoder';job.reject(new Error('Synthetic read failure'));
 await assert.rejects(job.promise,/Synthetic/);f.state.activeTool='fuzzer';f.c.renderFuzzerPayloadImportStatus();
 assert.match(f.notice.textContent,/Import failed.*Synthetic/);assert.equal(f.classes.has('fuzzer-notice-error'),true);
 assert.equal(f.effects.toasts,0);assert.equal(f.state.fuzzerPayloadsText,'original');
 const retry=f.begin();assert.match(f.notice.textContent,/Reading/);assert.equal(f.classes.has('fuzzer-notice-error'),false);
 retry.resolve(bytes('fresh'));await retry.promise;assert.equal(f.classes.has('hidden'),true);
});
for(const outcome of ['success','error'])test(`old ${outcome} cannot clear a newer import status`,async()=>{
 const f=fixture(), old=f.begin(), fresh=f.begin();const status=f.notice.textContent;
 if(outcome==='success')old.resolve(bytes('old'));else old.reject(new Error('old failure'));
 assert.equal(await old.promise,false);assert.equal(f.notice.textContent,status);
 fresh.reject(new Error('new failure'));await assert.rejects(fresh.promise,/new failure/);assert.match(f.notice.textContent,/new failure/);
});
for(const boundary of ['draft','session','run','generation'])test(`${boundary} replacement clears retained error on render`,async()=>{
 const f=fixture(), job=f.begin();job.reject(new Error('failure'));await assert.rejects(job.promise);
 if(boundary==='draft')f.state.fuzzerDraftVersion++;if(boundary==='session')f.state.activeSession.id='b';
 if(boundary==='run')f.state.fuzzerRunToken++;if(boundary==='generation')f.state._fuzzerFileGeneration++;
 f.c.renderFuzzerPayloadImportStatus();assert.equal(f.notice.textContent,'');assert.equal(f.classes.has('hidden'),true);
});
test('cancel/no file leaves current pending import and captured append mode alone',async()=>{
 const f=fixture(), job=f.begin('append'), status=f.notice.textContent;
 await f.c.importFuzzerPayloadFile(null,'replace');assert.equal(f.notice.textContent,status);
 job.resolve(bytes('fresh'));await job.promise;assert.equal(f.state.fuzzerPayloadsText,'original\nfresh');
});
test('immediate size refusal has retained local error and does not read file',async()=>{
 const f=fixture();await assert.rejects(f.c.importFuzzerPayloadFile({size:4194305,arrayBuffer(){assert.fail('no read');}}),/4 MiB/);
 assert.match(f.notice.textContent,/Import failed.*4 MiB/);assert.equal(f.classes.has('hidden'),false);
});
test('file change handler resets picker for retry and handles rejection without global toast',async()=>{
 const f=fixture(), listeners={};const d=deferred();
 f.nodes.fuzzerPayloadFile={value:'same.txt',files:[{size:5,arrayBuffer:()=>d.promise}],addEventListener:(type,fn)=>listeners[type]=fn};
 f.nodes.fuzzerPayloadImportMode={value:'replace'};f.c.initFuzzerSetupControls();listeners.change({target:f.nodes.fuzzerPayloadFile});
 assert.equal(f.nodes.fuzzerPayloadFile.value,'');d.reject(new Error('failure'));await new Promise(resolve=>setImmediate(resolve));
 assert.match(f.notice.textContent,/Import failed/);assert.equal(f.effects.toasts,0);
});
test('session reset discards transient file status',()=>{
 const reset=appSource.match(/^function resetSessionScopedUiState\([^]*?^\}/m)[0];
 assert.match(reset,/state\._fuzzerPayloadImportStatus = null/);
});

test('cancelled retry preserves the last failure until a file is actually chosen', async () => {
 const f=fixture(), job=f.begin();job.reject(new Error('read failure'));await assert.rejects(job.promise);
 const message=f.notice.textContent;await f.c.importFuzzerPayloadFile(undefined);
 f.c.renderFuzzerPayloadImportStatus();assert.equal(f.notice.textContent,message);
});
test('changing the picker mode does not change or cancel a pending file operation', async () => {
 const f=fixture(), listeners={}, d=deferred();
 f.nodes.fuzzerPayloadFile={value:'synthetic.txt',files:[{size:5,arrayBuffer:()=>d.promise}],addEventListener:(type,fn)=>listeners[type]=fn};
 f.nodes.fuzzerPayloadImportMode={value:'append'};f.c.initFuzzerSetupControls();listeners.change({target:f.nodes.fuzzerPayloadFile});
 f.nodes.fuzzerPayloadImportMode.value='replace';assert.match(f.notice.textContent,/append/);
 d.resolve(bytes('fresh'));await new Promise(resolve=>setImmediate(resolve));
 assert.equal(f.state.fuzzerPayloadsText,'original\nfresh');assert.equal(f.classes.has('hidden'),true);
});
