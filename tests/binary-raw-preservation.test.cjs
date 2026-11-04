const test=require('node:test'),assert=require('node:assert/strict');
const vm=require('node:vm');
const {editorFixture,source}=require('./replay-editor-fixture.cjs');
for(const mime of ['application/protobuf','application/x-msgpack','application/cbor','application/grpc+json','application/grpc-web+proto','Application/Protobuf; charset=utf-8']) {
 test(`${mime} legacy utf8 body survives header-only edit and undo redo`,()=>{
  const f=editorFixture();const body='\n\x03A\r\n';
  f.a.baseRequest.body_encoding='utf8';
  f.a.requestText=`POST /a HTTP/1.1\nHost: a.test\nContent-Type: ${mime}\nContent-Length: 5\n\n${body}`;
  f.render();let i=f.cv().getContent().indexOf('/a');f.edit(i,i+2,'/b');
  assert.equal(f.context.splitRawHttpMessage(f.a.requestText).body,Buffer.from(body).toString('base64'));
  assert.equal(f.context.parseEditableRawRequest(f.a.requestText,f.a.baseRequest).body,Buffer.from(body).toString('base64'));
  f.undo();assert.equal(f.context.splitRawHttpMessage(f.a.requestText).body,Buffer.from(body).toString('base64'));
  f.redo();assert.equal(f.context.splitRawHttpMessage(f.a.requestText).body,Buffer.from(body).toString('base64'));
 });
}
test('binary base64 draft remains base64 and header edit preserves exact bytes',()=>{
 const f=editorFixture();f.context.atob=s=>Buffer.from(s,'base64').toString('binary');vm.runInContext(source('decodedBase64Length'),f.context);f.a.baseRequest.body_encoding='base64';
 f.a.requestText='POST /a HTTP/1.1\nHost: a.test\nContent-Type: application/protobuf\nContent-Length: 5\n\nCgNBDQo=';
 f.render();const i=f.cv().getContent().indexOf('/a');f.edit(i,i+2,'/b');
 assert.equal(f.context.splitRawHttpMessage(f.a.requestText).body,'CgNBDQo=');
 assert.equal(f.context.parseEditableRawRequest(f.a.requestText,f.a.baseRequest).body_encoding,'base64');
});
test('ordinary text edits still adopt intentional editor body changes',()=>{
 const f=editorFixture();f.a.baseRequest.body_encoding='utf8';
 f.a.requestText='POST /a HTTP/1.1\nHost: a.test\nContent-Type: text/plain\n\nhello';f.render();
 const text=f.cv().getContent();f.edit(text.length-5,text.length,'world');
 assert.equal(f.context.splitRawHttpMessage(f.a.requestText).body,'world');
 f.undo();assert.equal(f.context.splitRawHttpMessage(f.a.requestText).body,'hello');
});

test('legacy binary origin survives MIME changes and subsequent edits/undo',()=>{
 const f=editorFixture(),body='\n\x03A\r\n';f.a.baseRequest.body_encoding='utf8';
 f.a.requestText=`POST /a HTTP/1.1\nHost: a.test\nContent-Type: application/protobuf\n\n${body}`;f.render();
 let i=f.cv().getContent().indexOf('application/protobuf');f.edit(i,i+20,'application/json');
 i=f.cv().getContent().indexOf('/a');f.edit(i,i+2,'/b');
 assert.equal(f.context.splitRawHttpMessage(f.a.requestText).body,Buffer.from(body).toString('base64'));
 f.undo();f.undo();f.redo();f.redo();assert.equal(f.context.splitRawHttpMessage(f.a.requestText).body,Buffer.from(body).toString('base64'));
 f.switchTo(f.b);f.switchTo(f.a);i=f.cv().getContent().indexOf('/b');f.edit(i,i+2,'/c');
 assert.equal(f.context.splitRawHttpMessage(f.a.requestText).body,Buffer.from(body).toString('base64'));
});

test('legacy migration permits safe body editing and exact undo after MIME change and reload',()=>{
 const f=editorFixture(),body='\n\x03A\r\n';f.a.baseRequest.body_encoding='utf8';
 f.a.requestText=`POST /a HTTP/1.1\nHost: a.test\nContent-Type: application/protobuf\nContent-Length: 5\n\n${body}`;f.render();
 assert.equal(f.a.baseRequest.body_encoding,'base64');
 const original=Buffer.from(body).toString('base64'),replacement=Buffer.from('\n\x03B\r\n').toString('base64');
 let text=f.cv().getContent(),i=text.indexOf(original);f.edit(i,i+original.length,replacement);
 assert.equal(Buffer.from(f.context.splitRawHttpMessage(f.a.requestText).body,'base64').toString('hex'),'0a03420d0a');
 assert.equal(f.undo(),true);assert.equal(f.context.splitRawHttpMessage(f.a.requestText).body,original);
 assert.equal(f.redo(),true);assert.equal(f.context.splitRawHttpMessage(f.a.requestText).body,replacement);
 text=f.cv().getContent();i=text.indexOf('application/protobuf');f.edit(i,i+20,'application/json');
 const saved=JSON.parse(JSON.stringify(f.a));const g=editorFixture();Object.assign(g.a,saved);g.render();
 assert.equal(g.a.baseRequest.body_encoding,'base64');assert.equal(g.context.splitRawHttpMessage(g.a.requestText).body,replacement);
 text=g.cv().getContent();i=text.indexOf('/a');g.edit(i,i+2,'/b');
 assert.equal(g.context.splitRawHttpMessage(g.a.requestText).body,replacement);
});
