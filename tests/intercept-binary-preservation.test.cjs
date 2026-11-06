const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const {loadFunctions}=require('./frontend-test-helpers.cjs');
const sandbox=vm.createContext({console,setTimeout,clearTimeout});vm.runInContext(fs.readFileSync('web/codemirror.bundle.js','utf8'),sandbox);
const {EditorState,history,undo,redo}=sandbox.CM;
const c=loadFunctions(['buildEditableRawResponse','parseEditableRawResponse','normalizedHeaders','headerNameEquals','splitRawHttpMessage','editableResponseBodyLength','decodedBase64Length','validateRawHttpBodyFraming','responseMustNotIncludeBody','responseStatusMustNotIncludeBody','responseContentLengthMayDescribeRepresentation'],{TextEncoder,atob,btoa,document:{getElementById:()=>({checked:true})}});
for(const hex of ['0a03410d0a','0080ff0d0a','', 'eab0800d0a']) test(`response binary survives CodeMirror/header/body/undo ${hex}`,()=>{
 const body=Buffer.from(hex,'hex').toString('base64'),r={status:200,headers:[{name:'Content-Type',value:'application/protobuf'},{name:'Content-Length',value:String(hex.length/2)}],body,body_encoding:'base64'};
 let s=EditorState.create({doc:c.buildEditableRawResponse(r),extensions:[history({newGroupDelay:0})]});
 assert.equal(c.parseEditableRawResponse(s.doc.toString(),r).body,body);
 let pos=s.doc.toString().indexOf('200');s=s.update({changes:{from:pos,to:pos+3,insert:'201'}}).state;
 let parsed=c.parseEditableRawResponse(s.doc.toString(),r);assert.equal(parsed.status,201);assert.equal(parsed.body,body);assert.equal(parsed.headers.find(h=>h.name==='Content-Length').value,String(hex.length/2));
 const before=s;let at=s.doc.length-body.length;s=s.update({changes:{from:at,to:s.doc.length,insert:'CgNCDQo='}}).state;
 assert.equal(c.parseEditableRawResponse(s.doc.toString(),r).body,'CgNCDQo=');
 const view={get state(){return s;},dispatch(t){s=t.state;}};
 assert.equal(undo(view),true);assert.equal(c.parseEditableRawResponse(s.doc.toString(),r).body,body);
 assert.equal(redo(view),true);assert.equal(c.parseEditableRawResponse(s.doc.toString(),r).body,'CgNCDQo=');
});
test('invalid Base64 is rejected, not re-encoded as a different response',()=>{
 assert.throws(()=>c.parseEditableRawResponse('HTTP/1.1 200\n\n%%%25',{body_encoding:'base64'}));
});
test('ordinary response UTF8 is unchanged',()=>{
 assert.equal(c.parseEditableRawResponse('HTTP/1.1 200\n\nhello',{body_encoding:'utf8'}).body,'hello');
});
test('request intercept MIME guard uses shared native classifier',()=>{
 const src=fs.readFileSync('src/proxy.rs','utf8');assert.match(src,/crate::model::is_binary_body_content_type\(Some\(&header.value\)\)/);assert.match(src,/if !binary_mime && is_raw_request_body_utf8/);
});

test('legacy UTF8 binary response migrates before CodeMirror and survives MIME edit',()=>{
 const r={status:200,headers:[{name:'Content-Type',value:'application/protobuf'}],body:'\n\x03A\r\n',body_encoding:'utf8'};
 const raw=EditorState.create({doc:c.buildEditableRawResponse(r)}).doc.toString();
 const out=c.parseEditableRawResponse(raw.replace('application/protobuf','application/json'),r);
 assert.equal(out.body_encoding,'base64');assert.equal(Buffer.from(out.body,'base64').toString('hex'),'0a03410d0a');
});
test('unmodified binary response forwards edited=false after CodeMirror normalization',async()=>{
 const r={status:200,headers:[{name:'Content-Type',value:'application/protobuf'}],body:'CgNBDQo=',body_encoding:'base64'};
 const raw=EditorState.create({doc:c.buildEditableRawResponse(r)}).doc.toString();let sent;
 const f=loadFunctions(['forwardSelectedResponseIntercept'],{
 state:{selectedResponseInterceptId:'one',selectedResponseInterceptRecord:{id:'one',response:r,method:'POST'},responseIntercepts:[{id:'one'}]},els:{},
 currentSessionId:()=> 'session',getCMView:()=>({getContent:()=>raw}),parseEditableRawResponse:c.parseEditableRawResponse,buildEditableRawResponse:c.buildEditableRawResponse,
 getVisibleResponseInterceptSummaries:()=>[],renderResponseIntercepts(){},updateInterceptQueueBadges(){},sessionWritePath:p=>p,
 async fetch(url,opts){sent=JSON.parse(opts.body);return {ok:true};},async requireOkResponse(){},async loadResponseIntercepts(){},scheduleRefresh(){},showToast(){},
 });await f.forwardSelectedResponseIntercept();assert.equal(sent.edited,false);assert.equal(sent.response.body,'CgNBDQo=');
});
test('legacy request intercept safe rendering, MIME edits, body edits and history',()=>{
 const r={scheme:'http',host:'example.test',path:'/a',method:'POST',headers:[{name:'Content-Type',value:'application/protobuf'},{name:'Content-Length',value:'5'}],body:'\n\x03A\r\n',body_encoding:'utf8'};
 const q=loadFunctions(['buildEditableRawRequest','parseEditableRawRequest','mergeHeaders','normalizedHeaders','headerNameEquals','headerValue','splitRawHttpMessage','parseReplayHttpVersionToken','normalizeReplayHttpVersion','editableRequestBodyLength','decodedBase64Length','validateRawHttpBodyFraming'],{TextEncoder,atob,btoa,URL,document:{getElementById:()=>({checked:true})}});
 let s=EditorState.create({doc:q.buildEditableRawRequest(r,true),extensions:[history({newGroupDelay:0})]});
 const parse=()=>q.parseEditableRawRequest(s.doc.toString(),r,true);
 assert.equal(parse().body,'CgNBDQo=');assert.equal(parse().body_encoding,'base64');
 r.preview_truncated=true;assert.equal(parse().preview_truncated,true);r.preview_truncated=false;
 let i=s.doc.toString().indexOf('application/protobuf');s=s.update({changes:{from:i,to:i+20,insert:'application/json'}}).state;
 i=s.doc.toString().indexOf('/a');s=s.update({changes:{from:i,to:i+2,insert:'/b'}}).state;
 assert.equal(parse().body,'CgNBDQo=');assert.equal(parse().path,'/b');
 i=s.doc.toString().indexOf('CgNBDQo=');s=s.update({changes:{from:i,to:i+8,insert:'CgNCDQo='}}).state;
 assert.equal(parse().body,'CgNCDQo=');assert.equal(parse().headers.find(h=>h.name==='Content-Length').value,'5');
 const v={get state(){return s;},dispatch(t){s=t.state;}};assert.equal(undo(v),true);assert.equal(parse().body,'CgNBDQo=');assert.equal(redo(v),true);assert.equal(parse().body,'CgNCDQo=');
});
test('unmodified legacy binary request forwards edited=false with exact bytes',async()=>{
 const r={scheme:'http',host:'example.test',path:'/a',method:'POST',headers:[{name:'Content-Type',value:'application/protobuf'}],body:'\n\x03A\r\n',body_encoding:'utf8'};
 const q=loadFunctions(['buildEditableRawRequest','parseEditableRawRequest','mergeHeaders','normalizedHeaders','headerNameEquals','headerValue','splitRawHttpMessage','parseReplayHttpVersionToken','normalizeReplayHttpVersion','editableRequestBodyLength','decodedBase64Length','validateRawHttpBodyFraming'],{TextEncoder,atob,btoa,URL,document:{getElementById:()=>({checked:true})}});
 const raw=EditorState.create({doc:q.buildEditableRawRequest(r,true)}).doc.toString();let sent;
 const f=loadFunctions(['forwardSelectedIntercept'],{state:{selectedInterceptId:'one',selectedInterceptRecord:{id:'one',request:r},intercepts:[{id:'one'}]},els:{},currentSessionId:()=> 'session',getCMView:()=>({getContent:()=>raw}),parseEditableRawRequest:q.parseEditableRawRequest,buildEditableRawRequest:q.buildEditableRawRequest,getVisibleRequestInterceptSummaries:()=>[],renderIntercepts(){},updateInterceptQueueBadges(){},sessionWritePath:p=>p,async fetch(url,opts){sent=JSON.parse(opts.body);return {ok:true};},async requireOkResponse(){},async loadIntercepts(){},scheduleRefresh(){},showToast(){}});
 await f.forwardSelectedIntercept();assert.equal(sent.edited,false);assert.equal(sent.request.body,'CgNBDQo=');assert.equal(sent.request.body_encoding,'base64');
});
