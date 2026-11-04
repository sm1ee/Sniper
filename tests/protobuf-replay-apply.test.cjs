const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm');
const {editorFixture,source}=require('./replay-editor-fixture.cjs');
const {appSource}=require('./frontend-test-helpers.cjs');
function fixture(auto=false, msgpack=false){
 const f=editorFixture();let provider;
 Object.assign(f.context,{btoa:s=>Buffer.from(s,'binary').toString('base64'),atob:s=>Buffer.from(s,'base64').toString('binary'),SniperProtobufFields:{init:p=>provider=p,editBlockReason:require('../web/protobuf-fields.js').editBlockReason,sync(){}}});
 for(const name of ['decodedBase64Length','buildEditableRawRequest','normalizedHeaders','mergeHeaders']) {try{vm.runInContext(source(name),f.context);}catch(e){if(!f.context[name])throw e;}}
 const get=f.document.getElementById;f.document.getElementById=id=>id==='proxySettingAutoContentLength'?{checked:auto}:get(id);
 f.a.baseRequest.body_encoding='base64'; f.a.requestText='POST /a HTTP/1.1\nHost: a.test\nContent-Type: application/protobuf\nContent-Length: 2\n\nCAE=';
 if(msgpack)f.a.requestText=f.a.requestText.replace('application/protobuf',msgpack==='cbor'?'application/cbor':'application/msgpack').replace('CAE=','oWE=');
 f.render();
 const start=appSource.indexOf('globalThis.SniperProtobufFields?.init(() => {');const end=appSource.indexOf('\n  bindWsReplayEvents();',start);
 vm.runInContext(appSource.slice(start,end),f.context);
 return {...f,provider:()=>provider(),snapshot:()=>{const s=provider();return {owner:s.owner,revision:s.revision,requestText:s.requestText};}};
}
test('real Replay setter preserves body encoding and CodeMirror undo redo; auto length updates',()=>{
 const f=fixture(true),before=f.a.requestText,s=f.snapshot();
 f.provider().applyFields(s,Uint8Array.from([8,128,1]));
 assert.match(f.a.requestText,/Content-Length: 3/);assert.match(f.a.requestText,/CIAB$/);assert.equal(f.a.baseRequest.body_encoding,'base64');
 assert.equal(f.undo(),true);assert.equal(f.a.requestText,before);assert.equal(f.a.baseRequest.body_encoding,'base64');
 assert.equal(f.redo(),true);assert.match(f.a.requestText,/CIAB$/);
});
test('auto length off rejects size change before state/editor mutation',()=>{
 const f=fixture(false),before=f.a.requestText;
 assert.throws(()=>f.provider().applyFields(f.snapshot(),Uint8Array.from([8,128,1])),/Content-Length/);
 assert.equal(f.a.requestText,before);assert.equal(f.cv().getContent(),before);assert.equal(f.undo(),false);
});
test('owner and edit-and-revert revision prevent stale apply',()=>{
 const f=fixture(true),s=f.snapshot();f.edit(f.cv().getContent().length,f.cv().getContent().length,' ');f.undo();
 assert.throws(()=>f.provider().applyFields(s,Uint8Array.from([8,2])),/stale-source/);
 const current=f.snapshot();f.switchTo(f.b);
 assert.throws(()=>f.provider().applyFields(current,Uint8Array.from([8,2])),/stale-source/);
});

test('MessagePack actual Replay apply uses encoding framing and undo',()=>{
 const f=fixture(true,true);
 const before=f.a.requestText,s={...f.snapshot(),format:'msgpack'};
 f.provider().applyFields(s,Uint8Array.from([0xa2,97,98]));assert.match(f.a.requestText,/Content-Length: 3/);assert.match(f.a.requestText,/omFi$/);
 assert.equal(f.undo(),true);assert.equal(f.a.requestText,before);assert.equal(f.redo(),true);
});
test('real CodeMirror input refreshes Fields MIME visibility without response or notice',()=>{
 const f=fixture(true), oldQuery=f.document.querySelectorAll;
 const button={dataset:{fieldsTarget:'request'},hidden:true,
   setAttribute(){},addEventListener(){},classList:{remove(){},add(){}}};
 const card={append(){},classList:{remove(){}},querySelectorAll:()=>[]};
 button.closest=()=>card;
 f.document.querySelectorAll=selector=>selector==='.replay-fields-tab'?[button]:oldQuery(selector);
 f.document.createElement=()=>({hidden:true,setAttribute(){}});
 vm.runInContext(require('node:fs').readFileSync(require('node:path').join(__dirname,'../web/protobuf-fields.js'),'utf8'),f.context);
 f.context.SniperProtobufFields.init(f.provider);
 f.a.responseRecord=null;f.a.notice='';
 assert.equal(button.hidden,false);
 function mime(from,to){const text=f.cv().getContent(),start=text.indexOf(from);assert.ok(start>=0);f.edit(start,start+from.length,to);}
 mime('application/protobuf','application/json');assert.equal(button.hidden,true);
 mime('application/json','application/msgpack');assert.equal(button.hidden,false);
 mime('application/msgpack','application/octet-stream');assert.equal(button.hidden,true);
 assert.equal(f.undo(),true);assert.equal(button.hidden,false);
 assert.equal(f.redo(),true);assert.equal(button.hidden,true);
});

test('CBOR actual Replay apply preserves framing undo and stale guards',()=>{
 const f=fixture(true,'cbor'),before=f.a.requestText,s={...f.snapshot(),format:'cbor'};
 f.provider().applyFields(s,Uint8Array.from([0x62,97,98]));assert.match(f.a.requestText,/Content-Length: 3/);assert.match(f.a.requestText,/YmFi$/);
 assert.equal(f.undo(),true);assert.equal(f.a.requestText,before);assert.equal(f.redo(),true);
 assert.throws(()=>f.provider().applyFields(s,Uint8Array.from([1])),/stale-source/);
 const g=fixture(false,'cbor');assert.throws(()=>g.provider().applyFields({...g.snapshot(),format:'cbor'},Uint8Array.from([0x62,97,98])),/Content-Length/);
});
