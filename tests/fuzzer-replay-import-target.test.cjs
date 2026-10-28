// Synthetic source-only audit: no app boot, sockets, fetch, or user data.
const assert = require('node:assert/strict');
const test = require('node:test');
const {loadFunctions} = require('./frontend-test-helpers.cjs');
const parserNames = ['parseEditableRawRequest', 'splitRawHttpMessage', 'editableRequestBodyLength', 'decodedBase64Length', 'parseReplayHttpVersionToken', 'normalizeReplayHttpVersion', 'headerValue', 'headerNameEquals', 'normalizedHeaders', 'validateRawHttpBodyFraming', 'buildEditableRawRequest', 'mergeHeaders', 'httpRequestAuthoritiesEquivalent', 'normalizeHttpRequestAuthority', 'createDefaultEditableRequest'];
const names = [...parserNames, 'defaultHttpPortForScheme', 'getActiveReplayTab', 'openFuzzerFromReplay', 'invalidateFuzzerRun', 'applyReplayTargetFields', 'setReplayTargetInputValidity', 'validateManualRepeaterTargetInput', 'getRepeaterTargetConfig', 'replayTargetOverridePayload', 'normalizeFuzzerTargetOverride', 'authorityToTargetState', 'normalizeRepeaterTargetInput', 'normalizePortValue', 'stripIpv6Brackets', 'explicitAuthorityPort', 'isLikelyIpv6Literal', 'targetStatesEquivalent', 'joinAuthority', 'fuzzerTargetAuthorityFromRequestText', 'fuzzerRequestAuthorityFromText'];
const raw='GET /items?id=one HTTP/1.0\r\nHost: example.com\r\n\r\n';
function fixture(port) {
 const tab={id:'replay-a',type:'http',requestText:raw,baseRequest:{scheme:'https',host:'example.com',method:'GET',path:'/items?id=one',headers:[],body:'',body_encoding:'utf8'},targetScheme:'https',targetHost:'old.example.com',targetPort:'8443',sourceTransactionId:'source-a'};
 const state={activeTool:'replay',activeReplayTabId:tab.id,replayTabs:[tab],fuzzerRequestText:'prior draft',fuzzerPayloadsText:'a\n b',fuzzerRunToken:4,fuzzerDraftVersion:9};
 const input=value=>({value,setCustomValidity(s){this.error=s},toggleAttribute(){}});
 const els={replayHostInput:input('new.example.com'),replayPortInput:input(port),replaySchemeSelect:input('https')};
 const c=loadFunctions(names,{workspaceLoaded:true,state,els,URL,TextEncoder,TextDecoder,atob,document:{getElementById:()=>null},scheduleWorkspaceStateSave(){},renderReplay(){},clearFuzzerAttackRecord(){},hideFuzzerDetailPanel(){},setActiveTool(tool){state.activeTool=tool},renderToolPanels(){}});
 return{c,state,els,tab};
}
test('valid Replay import retains committed destination, exact payloads, source, and HTTP version', async()=>{
 const f=fixture('9443'); await f.c.applyReplayTargetFields(); await f.c.openFuzzerFromReplay();
 assert.equal(f.state.fuzzerTarget.host,'new.example.com');assert.equal(f.state.fuzzerTarget.port,'9443');
 assert.equal(f.state.fuzzerPayloadsText,'a\n b');assert.equal(f.state.fuzzerSourceTransactionId,'source-a');
 assert.equal(f.state.fuzzerBaseRequest.http_version,'HTTP/1.0');assert.equal(f.state.fuzzerRequestText,raw);
});
for(const [host,port,field] of [['new.example.com','70000','Port'],['new.example.com','bad','Port'],['new.example.com','0','Port'],['new.example.com/path','8443','Target host'],['bad host','8443','Target host'],['user@example.com','8443','Target host']]) {
 test(`invalid visible Replay target ${host}:${port} cannot import retained target`,async()=>{
  const f=fixture(port);f.els.replayHostInput.value=host;await f.c.applyReplayTargetFields();
  assert.equal(f.tab.targetHost,'old.example.com');const before=JSON.stringify(f.state);
  await assert.rejects(f.c.openFuzzerFromReplay(),new RegExp(field));assert.equal(JSON.stringify(f.state),before);
  assert.equal(f.state.activeTool,'replay');assert.equal(f.state.fuzzerPayloadsText,'a\n b');
 });
}
test('correcting a rejected port imports the corrected target on the next attempt',async()=>{
 const f=fixture('70000');await f.c.applyReplayTargetFields();await assert.rejects(f.c.openFuzzerFromReplay(),/Port/);
 f.els.replayPortInput.value='9443';await f.c.applyReplayTargetFields();await f.c.openFuzzerFromReplay();
 assert.equal(f.state.fuzzerTarget.host,'new.example.com');assert.equal(f.state.fuzzerTarget.port,'9443');assert.equal(f.state.activeTool,'fuzzer');
});
