const test = require('node:test');
const assert = require('node:assert/strict');
const tcp = require(process.env.TCP_CAPTURE_MODULE || '../web/tcp-capture.js');
const tick = () => new Promise(resolve => setImmediate(resolve));
const policy = {enabled:true,direction:'both',revision:1,pending_count:1,paused_count:1,forwarding_count:0};
const pending = {pending_id:'p1',sequence:1,revision:0,state:'pending',direction:'client_to_server',original_base64:'AP8=',original_length:2,selected_length:2,edited:false,preview_truncated:false};
const connection = {id:'c1',status:'open',intercept_events:[]};
function fixture() {
  const nodes = new Map(), requests = [];
  const node = () => ({value:'',textContent:'',children:[],dataset:{},listeners:{},attributes:{},classList:{toggle(){}},setAttribute(k,v){this.attributes[k]=v;},addEventListener(k,v){this.listeners[k]=v;},append(v){this.children.push(v);},replaceChildren(){this.children=[];},querySelectorAll(){return [];}});
  const document = {getElementById(id){if(!nodes.has(id))nodes.set(id,node());return nodes.get(id);},createElement:node};
  let session = 'a';
  const controller = tcp.createInterceptController({document,sessionId:()=>session,readPath:p=>p,writePath:p=>p,request(path,options){let resolve;const promise=new Promise(r=>resolve=r);requests.push({path,options,resolve(data,status=200){resolve({ok:status>=200&&status<300,status,json:async()=>data});}});return promise;}});
  return {controller,requests,get:id=>document.getElementById(id),session:value=>session=value};
}
async function respond(f, items, status=200) {
  f.requests.at(-2).resolve(policy);f.requests.at(-1).resolve({items},status);await tick();
}
async function ready(f,items=[pending]) {f.controller.setConnection(connection);await respond(f,items);}
async function refresh(f,items,status=200) {const promise=f.controller.refresh();await respond(f,items,status);await promise;}
const forwarding = change => ({...pending,state:'forwarding',revision:1,...change});

test('edited forwarding shows accepted selected bytes read-only and retains original evidence', async()=>{
  const f=fixture();await ready(f,[forwarding({edited:true,selected_length:3,selected_base64:'QQD/'})]);
  assert.equal(f.get('tcpPendingHex').value,'41 00 ff');
  assert.equal(f.get('tcpPendingHex').readOnly,true);assert.equal(f.get('tcpPendingHex').disabled,false,'read-only evidence remains selectable');
  assert.match(f.get('tcpPendingHex').attributes['aria-label'],/being forwarded/);
  assert.equal(f.get('tcpPendingMeta').textContent,'Client → Server · 2 B · forwarding 3 B');
  assert.equal(f.get('tcpPendingOriginal').hidden,false);assert.equal(f.get('tcpPendingOriginal').open,false);
  assert.equal(f.get('tcpPendingOriginalHex').textContent,'00 ff');
  for(const id of ['tcpForward','tcpDrop','tcpPendingReset'])assert.equal(f.get(id).disabled,true);
  f.get('tcpForward').listeners.click();f.get('tcpDrop').listeners.click();assert.equal(f.requests.length,2);
});

test('unchanged forwarding reuses only explicitly verified complete originals', async()=>{
  const f=fixture();await ready(f,[forwarding({selected_base64:null})]);
  assert.equal(f.get('tcpPendingHex').value,'00 ff');
  for(const change of [{edited:undefined},{edited:true},{preview_truncated:undefined},{preview_truncated:true},{original_base64:null},{selected_length:3},{original_length:3,selected_length:3}]) {
    await refresh(f,[forwarding(change)]);
    assert.equal(f.get('tcpPendingHex').value,'');
    assert.equal(f.get('tcpPendingHex').placeholder,'Preview unavailable');
    assert.equal(f.get('tcpPendingHex').disabled,true);
    assert.match(f.get('tcpPendingMeta').textContent,/forwarding/);
  }
});

test('authoritative external forwarding replaces local draft without sending or retaining that draft',async()=>{
  const f=fixture();await ready(f);f.get('tcpPendingHex').value='aa';f.get('tcpPendingHex').listeners.input();
  await refresh(f,[forwarding({edited:true,selected_base64:'Qg==',selected_length:1})]);
  assert.equal(f.get('tcpPendingHex').value,'42');
  assert.equal(f.get('tcpPendingHex').readOnly,true);
  await refresh(f,[pending]);assert.equal(f.get('tcpPendingHex').value,'00 ff');
  assert.equal(f.requests.filter(r=>r.options).length,0);
});

test('accepted local forward retains its own read-only selection but never selects following bytes',async()=>{
  for(const edited of [false,true]) {
    const f=fixture();await ready(f);
    if(edited){f.get('tcpPendingHex').value='41';f.get('tcpPendingHex').listeners.input();}
    f.get('tcpForward').listeners.click();
    assert.deepEqual(JSON.parse(f.requests.at(-1).options.body),{action:'forward',expected_revision:0,...(edited?{replacement_base64:'QQ=='}:{})});
    f.requests.at(-1).resolve({state:'forwarding'});await tick();
    await respond(f,[forwarding({edited,selected_length:edited?1:2,selected_base64:edited?'QQ==':null})]);
    assert.equal(f.get('tcpPendingPicker').value,'p1');assert.equal(f.get('tcpPendingHex').value,edited?'41':'00 ff');
    assert.equal(f.get('tcpPendingHex').readOnly,true);assert.match(f.get('tcpPendingMeta').textContent,/forwarding/);
    await refresh(f,[{...pending,pending_id:'p2',sequence:2,original_base64:'Qg==',original_length:1}]);
    assert.equal(f.get('tcpPendingPicker').value,'');assert.equal(f.get('tcpPendingHex').value,'');assert.equal(f.get('tcpPendingOriginal').hidden,true);
    assert.equal(f.get('tcpForward').disabled,true);assert.equal(f.requests.filter(r=>r.options).length,1);
  }
});

test('Drop ignores drafts and has no selected bytes, forwarding claim or auto-selection',async()=>{
  const f=fixture();await ready(f);f.get('tcpPendingHex').value='aa';f.get('tcpPendingHex').listeners.input();
  f.get('tcpDrop').listeners.click();assert.deepEqual(JSON.parse(f.requests.at(-1).options.body),{action:'drop',expected_revision:0});
  f.requests.at(-1).resolve({state:'dropped'});await tick();await respond(f,[{...pending,state:'dropped',selected_length:0}]);
  assert.equal(f.get('tcpPendingPicker').value,'');
  f.get('tcpPendingPicker').value='p1';f.get('tcpPendingPicker').listeners.change();
  assert.equal(f.get('tcpPendingHex').value,'');assert.equal(f.get('tcpPendingHex').placeholder,'Dropped');
  assert.equal(f.get('tcpPendingMeta').textContent,'Client → Server · 2 B · dropping');
  assert.doesNotMatch(f.get('tcpPendingMeta').textContent,/forwarding|paused/);assert.equal(f.get('tcpPendingOriginalHex').textContent,'00 ff');
  assert.equal(f.get('tcpPendingHex').disabled,true);
});

test('polling retains original disclosure only for the same range; state loss and navigation hide it',async()=>{
  const f=fixture(), item=forwarding({edited:true,selected_base64:'QQ==',selected_length:1});await ready(f,[item]);
  f.get('tcpPendingOriginal').open=true;await refresh(f,[item]);assert.equal(f.get('tcpPendingOriginal').open,true);
  await refresh(f,[item],500);assert.equal(f.get('tcpPendingOriginal').hidden,true);assert.equal(f.get('tcpPendingOriginal').open,false);
  assert.equal(f.get('tcpPendingHex').disabled,true);assert.equal(f.get('tcpPendingMeta').textContent,'');
  await refresh(f,[item]);assert.equal(f.get('tcpPendingOriginal').hidden,false);
  f.controller.setConnection({...connection,status:'stopped'});assert.equal(f.get('tcpPendingOriginal').hidden,true);assert.equal(f.get('tcpPendingHex').disabled,true);
  f.controller.setConnection({...connection,id:'c2'});assert.equal(f.get('tcpPendingHex').value,'');assert.equal(f.get('tcpPendingOriginalHex').textContent,'');
  await respond(f,[item]);assert.equal(f.get('tcpPendingOriginal').open,false);
  f.session('b');f.controller.reset();assert.equal(f.get('tcpPendingHex').value,'');assert.equal(f.get('tcpPendingOriginalHex').textContent,'');assert.equal(f.get('tcpPendingOriginal').hidden,true);
});

test('stale forwarding response cannot replace a new connection or reset session',async()=>{
  for(const reset of [false,true]) {
    const f=fixture();await ready(f);const old=f.controller.refresh(), requests=f.requests.slice(-2);
    if(reset){f.session('b');f.controller.reset();}else f.controller.setConnection({...connection,id:'c2'});
    requests[0].resolve(policy);requests[1].resolve({items:[forwarding({edited:true,selected_base64:'QQ=='})]});await old;
    assert.equal(f.get('tcpPendingHex').value,'');assert.equal(f.get('tcpPendingOriginal').hidden,true);
  }
});

test('unknown pending state does not present original or local draft as selected bytes',async()=>{
  const f=fixture();await ready(f,[{...pending,state:'unknown'}]);
  assert.equal(f.get('tcpPendingHex').value,'');assert.equal(f.get('tcpPendingHex').disabled,true);
  assert.match(f.get('tcpPendingMeta').textContent,/state unavailable/);
  assert.equal(f.get('tcpPendingOriginal').hidden,true);
});

test('original evidence uses bounded, keyboard-accessible disclosure without replacing selected bytes',()=>{
  const fs=require('node:fs'),path=require('node:path');
  const html=fs.readFileSync(path.join(__dirname,'../web/index.html'),'utf8'),css=fs.readFileSync(path.join(__dirname,'../web/styles.css'),'utf8');
  assert.match(html,/<details id="tcpPendingOriginal" hidden><summary>Original bytes<\/summary><pre id="tcpPendingOriginalHex" tabindex="0" aria-label="Original bytes as hex">/);
  assert.match(css,/#tcpPendingOriginalHex \{[^}]*max-height: 120px;[^}]*overflow: auto;/);
  assert.match(css,/\.tcp-pending-surface \{ overflow-y: auto; \}/);
  assert.match(css,/\.tcp-pending-surface > \.tcp-pending-bar \{ flex-shrink: 0; \}/);
});

test('uncertain Forward outcome uses later authoritative selected bytes without retrying or losing the warning',async()=>{
  for(const status of [409,500]) {
    const f=fixture();await ready(f);f.get('tcpPendingHex').value='aa';f.get('tcpPendingHex').listeners.input();f.get('tcpForward').listeners.click();
    f.requests.at(-1).resolve({},status);await tick();await respond(f,[forwarding({edited:true,selected_base64:'Qg==',selected_length:1})]);
    assert.equal(f.get('tcpPendingHex').value,'42');assert.equal(f.get('tcpPendingHex').readOnly,true);
    assert.match(f.get('tcpInterceptError').textContent,status === 409 ? /bytes changed/ : /Outcome unknown; not retried/);
    await refresh(f,[{...pending,pending_id:'p2'}]);assert.equal(f.get('tcpPendingPicker').value,'');assert.equal(f.get('tcpPendingHex').value,'');
    assert.equal(f.requests.filter(r=>r.options).length,1);
  }
});
