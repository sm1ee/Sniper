const test = require('node:test');
const assert = require('node:assert/strict');
const { editorFixture, CM } = require('./replay-editor-fixture.cjs');
const limit = 2 * 1024 * 1024;
function counts(f) {
  const calls = { accept: 0, parse: 0 };
  for (const [name, key] of [['acceptReplayRequestEdit','accept'],['replayRequestEditCandidate','parse']]) {
    const fn = f.context[name];
    f.context[name] = (...args) => { calls[key]++; return fn(...args); };
  }
  return calls;
}
function editTransaction(f) {
  const view=f.cv().view;
  return view.state.update({changes:{from:0,to:3,insert:'PUT'},userEvent:'input.type'});
}
test('one ordinary transaction parses and validates once, including undo and redo', () => {
  const f=editorFixture(); f.render(); const n=counts(f);
  f.edit(0,3,'PUT'); assert.deepEqual(n,{accept:1,parse:1});
  assert.match(f.a.requestText,/^PUT/);
  f.undo(); assert.deepEqual(n,{accept:2,parse:2});
  f.redo(); assert.deepEqual(n,{accept:3,parse:3});
});
for (const [label, mutate] of [
  ['body changed in place', f=>{f.a.baseRequest.body='new base body';}],
  ['header changed in place', f=>{f.a.baseRequest.headers.push({name:'X-New',value:'new'});}],
  ['base object replaced', f=>{f.a.baseRequest={...f.a.baseRequest};}],
  ['request draft changed', f=>{f.a.requestText=f.a.requestText.replace('/a','/different');}],
  ['revision changed', f=>{f.a.protobufEditRevision=99;}],
  ['workspace generation changed', f=>{f.context.workspaceStateGeneration++;}],
  ['mode changed', f=>{f.state.replayMessageViews.request='pretty';}],
]) test(`changed validation input falls back: ${label}`, () => {
  const f=editorFixture();f.render();const n=counts(f),tr=editTransaction(f);
  assert.equal(n.accept,1);mutate(f);f.cv().view.dispatch(tr);
  assert.equal(n.accept,2);assert.equal(n.parse,2);
});
test('filter rejection does not leave a token for the following edit', () => {
  const f=editorFixture();f.render();const n=counts(f),before=f.a.requestText;
  f.edit(0,f.cv().getContent().length,`POST /a HTTP/1.1\nHost: example.com\n\n${'a'.repeat(limit+1)}`);
  assert.equal(f.a.requestText,before);assert.equal(n.accept,1);assert.equal(n.parse,0);
  f.edit(0,3,'PUT'); assert.equal(n.accept,2);assert.equal(n.parse,1);
});
test('a replaced transaction document forces new validation', () => {
  const f=editorFixture();f.render();const view=f.cv().view,n=counts(f);
  editTransaction(f); // Accepted but not dispatched.
  const changed=view.state.update({changes:{from:0,to:view.state.doc.length,
    insert:'POST /a HTTP/1.1\nHost: example.com\n\n'+'x'.repeat(limit+1)},filter:false});
  const before=f.a.requestText;view.dispatch(changed);
  assert.equal(f.a.requestText,before);assert.equal(n.accept,2);
});
test('programmatic update has no reusable validation for subsequent user edit', () => {
  const f=editorFixture();f.render();const n=counts(f);
  f.cv().setContent('GET /programmatic HTTP/1.1\nHost: example.com\n\n');
  assert.equal(n.accept,0);
  f.edit(0,3,'PUT');assert.equal(n.accept,1);assert.equal(n.parse,1);
});
test('Hex history recreation preserves guard correctness when handoff falls back', () => {
  const f=editorFixture();f.render(); f.edit(0,3,'PUT');
  f.state.replayMessageViews.request='hex';f.context.renderReplayViewContent('request');
  f.state.replayMessageViews.request='raw';f.context.renderReplayViewContent('request');
  const before=f.a.requestText;
  f.edit(0,f.cv().getContent().length,'a'.repeat(limit+1));assert.equal(f.a.requestText,before);
  assert.equal(f.undo(),true);assert.match(f.a.requestText,/^GET/);
});

test('restored editable history still validates and parses only once', () => {
  const f=editorFixture();f.render();f.edit(0,3,'PUT');
  f.state.replayMessageViews.request='hex';f.context.renderReplayViewContent('request');
  f.state.replayMessageViews.request='raw';f.context.renderReplayViewContent('request');
  const n=counts(f);f.edit(0,3,'GET');assert.deepEqual(n,{accept:1,parse:1});
  f.undo();assert.deepEqual(n,{accept:2,parse:2});
});

test('session or automatic length setting changes invalidate the one-shot handoff', () => {
  for(const change of ['session','auto-length']) {
    const f=editorFixture();f.render();const n=counts(f),tr=editTransaction(f);
    if(change==='session') f.state.activeSession={id:'another-session'};
    else {const get=f.document.getElementById.bind(f.document);f.document.getElementById=id=>id==='proxySettingAutoContentLength'?{checked:true}:get(id);}
    f.cv().view.dispatch(tr);assert.equal(n.accept,2);assert.equal(n.parse,2);
  }
});
test('multi-transaction update cannot consume a single-transaction validation', () => {
  const f=editorFixture();f.render();const view=f.cv().view,n=counts(f),tr=editTransaction(f);
  const listener=view.state.facet(CM.EditorView.updateListener).at(-1);
  listener({view,docChanged:true,state:tr.state,transactions:[tr,tr]});
  assert.equal(n.accept,2);assert.equal(n.parse,2);
});
test('a retired editor listener never synchronizes the next document owner', () => {
  const f=editorFixture();f.render();const old=f.cv().view;
  const listener=old.state.facet(CM.EditorView.updateListener).at(-1);
  f.switchTo(f.b);const before=f.b.requestText;
  listener({view:old,docChanged:true,state:{doc:{toString:()=> 'PUT /stale HTTP/1.1\nHost: example.com\n\n'}},transactions:[]});
  assert.equal(f.b.requestText,before);
});
