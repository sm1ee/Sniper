// Production Fuzzer rendering and shipped CodeMirror history; synthetic view only.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { editorFixture, source, CM } = require('./replay-editor-fixture.cjs');

function fixture() {
  const f = editorFixture();
  const OriginalView = f.context.CM.EditorView;
  class View extends OriginalView {
    constructor(options) { super(options); this.contentDOM.setAttribute = () => {}; }
  }
  f.context.CM.EditorView = View;
  Object.assign(f.els, { fuzzerRequestCM: {}, fuzzerPayloadsEditor: { value: '' }, fuzzerMeta: {} });
  f.saves = 0;
  Object.assign(f.context, {
    renderFuzzerResultsWorkflow() {}, renderFuzzerSetup() {}, renderEmptyFuzzerResults() {},
    renderFuzzerPayloadsEditor() { f.els.fuzzerPayloadsEditor.value = f.state.fuzzerPayloadsText; },
    wireFuzzerMarkerSelection() {}, scheduleFuzzerSetupRender() {},
    scheduleWorkspaceStateSave() { f.saves++; },
  });
  for (const name of ['renderFuzzer', 'updateFuzzerRequestText', 'markFuzzerDraftChanged']) {
    vm.runInContext(source(name), f.context);
  }
  f.cv = () => f.context.getCMView('fuzzerReq');
  f.render = () => f.context.renderFuzzer();
  f.undo = () => CM.undo(f.cv().view);
  f.redo = () => CM.redo(f.cv().view);
  f.state.fuzzerRequestText = 'GET /a HTTP/1.1\nHost: example.com\n\n';
  f.state.fuzzerPayloadsText = '';
  f.render();
  return f;
}


for (const mime of ['application/protobuf','application/cbor','application/msgpack','application/grpc+proto','application/grpc-web']) test(mime + ' legacy Fuzzer preserves bytes',()=>{
 const f=fixture(); const body='\n\x03A\r\n';
 f.state.fuzzerBaseRequest={body_encoding:'utf8',headers:[{name:'Content-Type',value:mime}]};
 f.state.fuzzerRequestText=`POST /a HTTP/1.1\nHost: a.test\nContent-Type: ${mime}\n\n${body}`;
 f.render(); assert.equal(f.state.fuzzerBaseRequest.body_encoding,'base64');
 const expected=Buffer.from(body).toString('base64');
 assert.equal(f.state.fuzzerRequestText.split('\n\n')[1],expected);
 let i=f.cv().getContent().indexOf('/a'); f.edit(i,i+2,'/b');
 assert.equal(f.state.fuzzerRequestText.split('\n\n')[1],expected);
 f.undo(); f.redo(); assert.equal(f.state.fuzzerRequestText.split('\n\n')[1],expected);
 i=f.cv().getContent().indexOf(expected); f.edit(i,i+expected.length,'CgNCDQo=');
 assert.equal(f.state.fuzzerRequestText.split('\n\n')[1],'CgNCDQo='); f.undo();
 assert.equal(f.state.fuzzerRequestText.split('\n\n')[1],expected);
 const saved=JSON.parse(JSON.stringify(f.state)); const g=fixture();Object.assign(g.state,saved);g.render();
 assert.equal(g.state.fuzzerRequestText.split('\n\n')[1],expected);
});
test('legacy body markers fail closed without changing bytes or consuming markers',()=>{
 const f=fixture(); f.state.fuzzerBaseRequest={body_encoding:'utf8',headers:[{name:'Content-Type',value:'application/protobuf'}]};
 const raw='POST / HTTP/1.1\nHost: a.test\n\n\n\x03§A§\r\n'; f.state.fuzzerRequestText=raw; f.render();
 assert.equal(f.state.fuzzerRequestText,raw);assert.equal(f.state.fuzzerBaseRequest.body_encoding,'utf8');assert.equal(f.cv()._editable,false);
 vm.runInContext(source('parseFuzzerRequestTemplate'),f.context);
 assert.throws(()=>f.context.parseFuzzerRequestTemplate(raw,f.state.fuzzerBaseRequest),/Legacy binary body/);
});
test('migration retires only request history, never restores old utf8 draft',()=>{
 const f=fixture(); const old=f.cv(); f.edit(5,6,'changed');
 f.state.fuzzerBaseRequest={body_encoding:'utf8',headers:[{name:'Content-Type',value:'application/protobuf'}]};
 f.state.fuzzerRequestText='POST /a HTTP/1.1\nHost: a.test\n\n\n\x03A\r\n';f.render();
 assert.notEqual(f.cv(),old);assert.equal(f.undo(),false);assert.equal(f.state.fuzzerBaseRequest.body_encoding,'base64');
});

for (const marker of ['$payload$', '§A§', '§unfinished', '§§']) test('legacy body marker guard: ' + marker, () => {
 const f=fixture();
 f.state.fuzzerBaseRequest={body_encoding:'utf8',headers:[{name:'Content-Type',value:'application/protobuf'}]};
 const raw=`POST /$payload$ HTTP/1.1\nHost: example.com\nX-Seed: §header§\n\n\n${marker}\r\n`;
 f.state.fuzzerRequestText=raw; f.render();
 assert.equal(f.state.fuzzerRequestText,raw);
 assert.equal(f.state.fuzzerBaseRequest.body_encoding,'utf8');
 assert.equal(f.cv()._editable,false);
 assert.match(f.state.fuzzerNotice,/Legacy binary body/);
 vm.runInContext(source('parseFuzzerRequestTemplate'),f.context);
 assert.throws(()=>f.context.parseFuzzerRequestTemplate(raw,f.state.fuzzerBaseRequest),/Legacy binary body/);
 const saved=JSON.parse(JSON.stringify(f.state)); const g=fixture(); Object.assign(g.state,saved);g.render();
 assert.equal(g.state.fuzzerRequestText,raw); assert.equal(g.cv()._editable,false);
});
test('header and query markers remain usable while unmarked binary body migrates',()=>{
 const f=fixture();f.state.fuzzerBaseRequest={body_encoding:'utf8',headers:[{name:'Content-Type',value:'application/protobuf'}]};
 const head='POST /?q=$payload$ HTTP/1.1\nHost: example.com\nX-Seed: §seed§';
 const body='\n\x03A\r\n'; f.state.fuzzerRequestText=head+'\n\n'+body;f.render();
 assert.equal(f.state.fuzzerRequestText,head+'\n\n'+Buffer.from(body).toString('base64'));
 assert.equal(f.cv()._editable,true);
 vm.runInContext(source('parseFuzzerRequestTemplate'),f.context);
 const req=f.context.parseFuzzerRequestTemplate(f.state.fuzzerRequestText,f.state.fuzzerBaseRequest);
 assert.equal(req.body_encoding,'base64'); assert.equal(req.body,Buffer.from(body).toString('base64'));
 assert.match(req.path,/\$payload\$/); assert.equal(req.headers.find(h=>h.name==='X-Seed').value,'§seed§');
});
