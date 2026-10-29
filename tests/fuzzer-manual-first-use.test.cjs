// Initialized first-use integration: shipped CodeMirror state, actual input/action
// callbacks and real local preflight. No Start helper, browser or network.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { editorFixture, source, CM } = require('./replay-editor-fixture.cjs');
const workflow = require('../web/fuzzer-workflow.js');
function control() {
  const listeners = {}, classes = new Set();
  return { value:'', disabled:false, textContent:'', innerHTML:'', listeners,
    addEventListener(k,f){listeners[k]=f;}, input(value){this.value=value;listeners.input?.();},
    classList:{toggle(k,on){if(on)classes.add(k);else classes.delete(k);},contains:k=>classes.has(k)},
    setAttribute(){}, cloneNode(){return control();}, replaceWith(){}, focus(){} };
}
function fixture() {
  const f=editorFixture(), c=f.context;
  const Base=c.CM.EditorView;
  c.CM.EditorView=class extends Base { constructor(options){super(options);this.contentDOM.setAttribute=()=>{};} };
  Object.assign(f.state,{activeTool:'fuzzer',fuzzerBaseRequest:null,fuzzerTarget:null,fuzzerTargetRequestText:null,
    fuzzerSourceTransactionId:null,fuzzerRequestText:'',fuzzerPayloadsText:'',fuzzerRunToken:0,fuzzerDraftVersion:0,
    fuzzerRunning:false,fuzzerRunningAttackId:null,fuzzerAttackRecord:null,fuzzerAttackRecordId:null});
  const nodes={};
  for(const id of ['fuzzerRequestHelp','fuzzerPreflightSummary','fuzzerPreflightNotice','fuzzerTargetSummary',
    'fuzzerPreviewSamples','fuzzerPreviewNotes','fuzzerTransportSelect','fuzzerTransportHelp','startFuzzerButton',
    'resetFuzzerButton','fuzzerPayloadsEditor','fuzzerMeta','fuzzerMarkSelectionButton']) nodes[id]=control();
  Object.assign(f.els,nodes,{fuzzerRequestCM:{}});
  f.document.getElementById=id=>nodes[id]||null;
  let saves=0, requests=0, timer=null;
  Object.assign(c,{workspaceLoaded:true,workspaceStateGeneration:7,SniperFuzzerWorkflow:workflow,URL,atob,
    fetch(){requests++;throw Error('No fetch authorized in first-use proof');},
    setTimeout(callback){timer=callback;return 1;},clearTimeout(){timer=null;},
    renderFuzzerResultsWorkflow(){},renderEmptyFuzzerResults(){},wireFuzzerMarkerSelection(){},
    renderFuzzerRemoveMarkerControl(){},normalizeFuzzerAttackRecord:value=>value,
    scheduleWorkspaceStateSave(){saves++;},clearFuzzerAttackRecord(){f.state.fuzzerAttackRecord=null;f.state.fuzzerAttackRecordId=null;},
    hideFuzzerDetailPanel(){}, showToast(message){assert.fail(message);},
  });
  for(const name of ['renderFuzzer','renderFuzzerPayloadsEditor','renderFuzzerSetup','renderFuzzerPayloadImportStatus',
    'escapeHtml','fuzzerRequestTextForAction','parseFuzzerRequestTemplate','fuzzerSetupNode','fuzzerSetupPreflight','fuzzerPayloadCount',
    'splitFuzzerPayloadLines','fuzzerTransportState','renderFuzzerTransport','setFuzzerTransport',
    'updateFuzzerRequestText','updateFuzzerPayloadsText','markFuzzerDraftChanged','scheduleFuzzerSetupRender',
    'decodedBase64Length','httpRequestAuthoritiesEquivalent','normalizeHttpRequestAuthority','normalizeFuzzerTargetOverride','normalizeFuzzerTargetAuthority','fuzzerRequestAuthorityFromText',
    'fuzzerAuthorityFromSavedValue','activeFuzzerTargetForRequest','fuzzerTargetAuthorityFromRequestText',
    'fuzzerTargetAuthorityFromEditableRequest','initFuzzerSetupControls','fuzzerSetupError',
    'markFuzzerEditorSelection','markFuzzerPosition','fuzzerRawOffsetForEditorOffset',
    'removeFuzzerEditorPosition','undoFuzzerMarker','clearFuzzerMarkers']) {
    vm.runInContext(source(name),c);
  }
  c.initFuzzerSetupControls();
  const cv=()=>c.getCMView('fuzzerReq');
  const flush=()=>{const callback=timer;timer=null;callback?.();};
  c.renderFuzzer();
  return {...f,c,nodes,cv,flush,
    type(raw){cv().view.dispatch({changes:{from:0,to:cv().view.state.doc.length,insert:raw},userEvent:'input.paste'});flush();},
    payload(text){f.els.fuzzerPayloadsEditor.input(text);flush();},
    transport(scheme){nodes.fuzzerTransportSelect.value=scheme;nodes.fuzzerTransportSelect.listeners.change({target:nodes.fuzzerTransportSelect});},
    get requests(){return requests;},get saves(){return saves;}};
}
const origin='GET /?q=demo HTTP/1.1\nHost: example.com\n';
test('manual first use joins initialized editor inputs to preflight without an import or Start',()=>{
  const f=fixture();
  assert.equal(f.cv().view.state.facet(CM.EditorState.readOnly),false);
  assert.equal(f.nodes.startFuzzerButton.disabled,true);
  assert.match(f.nodes.fuzzerPreflightNotice.textContent,/Paste a raw HTTP request.*History \/ Replay/);
  f.type('https://example.com/synthetic');
  assert.equal(f.state.fuzzerRequestText,'https://example.com/synthetic');
  assert.equal(f.nodes.fuzzerPreflightNotice.textContent,'Invalid request line in editor');
  assert.equal(f.nodes.startFuzzerButton.disabled,true);
  f.type('GET /synthetic HTTP/1.1');
  assert.equal(f.nodes.fuzzerPreflightNotice.textContent,'Request is missing a Host header');
  assert.equal(f.nodes.fuzzerTransportSelect.disabled,true);
  f.type(origin);
  assert.equal(f.nodes.fuzzerPreflightNotice.textContent,'Select a value to replace.');
  assert.equal(f.nodes.fuzzerTransportSelect.value,'https');assert.equal(f.nodes.fuzzerTransportSelect.disabled,false);
  assert.match(f.nodes.fuzzerTargetSummary.textContent,/^https:\/\/example.com:443/);
  const start=f.cv().getContent().indexOf('demo');
  f.cv().view.dispatch({selection:{anchor:start,head:start+4}});
  f.nodes.fuzzerMarkSelectionButton.listeners.click(); f.flush();
  assert.equal(f.state.fuzzerRequestText,origin.replace('demo','§demo§'));
  assert.equal(f.cv().getContent(),f.state.fuzzerRequestText);
  assert.equal(f.nodes.fuzzerPreflightNotice.textContent,'Add payloads.');assert.equal(f.nodes.startFuzzerButton.disabled,true);
  f.payload('alpha\nbeta');
  assert.equal(f.nodes.startFuzzerButton.disabled,false);assert.equal(f.nodes.fuzzerPreflightNotice.textContent,'');
  assert.match(f.nodes.fuzzerPreflightSummary.textContent,/2 payloads → 2 planned requests/);
  assert.match(f.nodes.fuzzerPreviewSamples.innerHTML,/GET \/\?q=alpha HTTP\/1\.1/);
  assert.equal(f.state.fuzzerBaseRequest,null);assert.equal(f.state.fuzzerSourceTransactionId,null);
  const raw=f.state.fuzzerRequestText;
  f.transport('http');assert.equal(f.state.fuzzerRequestText,raw);assert.equal(f.state.fuzzerBaseRequest.scheme,'http');
  assert.match(f.nodes.fuzzerTargetSummary.textContent,/^http:\/\/example.com:80/);
  assert.equal(f.state.fuzzerPayloadsText,'alpha\nbeta');
  assert.equal(f.state.fuzzerSourceTransactionId,null);
  assert.ok(f.saves>0, 'Actual edit callbacks schedule persistence');
  assert.equal(typeof f.c.runFuzzerAttack,'undefined');
  assert.equal(f.requests,0);
});
