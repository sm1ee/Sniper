#!/usr/bin/env node
// Production controller against a real native loopback backend. The Python
// harness holds the upstream socket unread to keep accepted writes in flight.
const assert = require('node:assert/strict');
const tcp = require('../web/tcp-capture.js');
const [url, cid, mode] = process.argv.slice(2);
const nodes = new Map();
function node() { return {value:'', textContent:'', children:[], dataset:{}, listeners:{}, attributes:{}, classList:{toggle(){}}, setAttribute(k,v){this.attributes[k]=v;}, addEventListener(k,v){this.listeners[k]=v;}, append(n){this.children.push(n);}, replaceChildren(){this.children=[];}, querySelectorAll(){return [];}}; }
const document = {getElementById(id){if(!nodes.has(id))nodes.set(id,node());return nodes.get(id);}, createElement:node};
const el = id => document.getElementById(id), delay = ms => new Promise(resolve=>setTimeout(resolve,ms));
async function read(path) { const response=await fetch(url+path);assert.ok(response.ok);return response.json(); }
async function until(check) { const end=Date.now()+10000;while(Date.now()<end){if(await check())return;await delay(10);}throw Error('Native controller timeout'); }
(async()=>{
  const session=(await read('/api/sessions')).find(s=>s.active).id;
  let writes=0;
  const c=tcp.createInterceptController({document,sessionId:()=>session,readPath:p=>p+'?session_id='+session,writePath:p=>p+'?session_id='+session+'&expected_active_session_id='+session,
    request:(p,o)=>{if(o?.method)writes++;return fetch(url+p,o);}});
  c.setConnection(await read('/api/tcp/connections/'+cid));await c.refresh();el('tcpPendingTab').listeners.click();
  if(mode==='drop') {
    await until(async()=>{await c.refresh();return !el('tcpDrop').disabled;});
    el('tcpPendingHex').value='ff';el('tcpPendingHex').listeners.input();el('tcpDrop').listeners.click();
    await until(()=>el('tcpInterceptNotice').textContent.startsWith('Drop accepted'));
    await until(async()=>{await c.refresh();return (await read('/api/tcp/connections/'+cid)).intercept_events.some(e=>e.state==='dropped');});
    const event=(await read('/api/tcp/connections/'+cid)).intercept_events.find(e=>e.state==='dropped');
    assert.equal(event.selected_length,0);assert.equal(event.written_bytes,0);assert.equal(event.selected_base64,null);
    assert.equal(el('tcpPendingHex').value,'');assert.equal(el('tcpPendingOriginal').hidden,true);assert.equal(writes,1);
    console.log(JSON.stringify({mode,dropWrites:0,decisions:writes}));return;
  }
  let blocked;
  for(let n=0;n<500;n++) {
    await until(async()=>{await c.refresh();const items=(await read('/api/tcp/connections/'+cid+'/pending')).items;if(!items.length)return false;
      if(!el('tcpPendingPicker').value){el('tcpPendingPicker').value=items[0].pending_id;el('tcpPendingPicker').listeners.change();}return !el('tcpForward').disabled;});
    const original=el('tcpPendingHex').value;
    if(mode==='edited'){el('tcpPendingHex').value='ff '.repeat(16384);el('tcpPendingHex').listeners.input();}
    el('tcpForward').listeners.click();await until(()=>el('tcpInterceptNotice').textContent.startsWith('Forward accepted'));
    await delay(20);await c.refresh();
    let item=(await read('/api/tcp/connections/'+cid+'/pending')).items.find(i=>i.state==='forwarding');
    if(!item)continue;
    await delay(200);await c.refresh();item=(await read('/api/tcp/connections/'+cid+'/pending')).items.find(i=>i.pending_id===item.pending_id&&i.state==='forwarding');
    if(!item)continue;
    assert.equal(el('tcpPendingPicker').value,item.pending_id,'own accepted range stays selected');
    const expected=Buffer.from(item.selected_base64||item.original_base64,'base64');
    assert.deepEqual(Buffer.from(tcp.parseHex(el('tcpPendingHex').value)),expected);
    if(mode==='edited'){assert.equal(expected.length,16384);assert.ok(expected.every(b=>b===255));assert.notEqual(el('tcpPendingHex').value,original);}else assert.equal(item.selected_base64,null);
    assert.equal(el('tcpPendingHex').readOnly,true);assert.equal(el('tcpPendingHex').disabled,false);
    assert.equal(el('tcpPendingOriginalHex').textContent,original);assert.equal(el('tcpPendingOriginal').hidden,false);
    assert.match(el('tcpPendingMeta').textContent,/Forwarding; delivery not confirmed/);
    for(const id of ['tcpForward','tcpDrop','tcpPendingReset'])assert.equal(el(id).disabled,true);
    const before=writes;el('tcpForward').listeners.click();el('tcpDrop').listeners.click();assert.equal(writes,before);
    blocked={mode,stableForwarding:true,selectedBytes:expected.length,selectedPrefix:expected.subarray(0,8).toString('hex'),originalPrefix:Buffer.from(item.original_base64,'base64').subarray(0,8).toString('hex'),readOnly:el('tcpPendingHex').readOnly,copyable:!el('tcpPendingHex').disabled,meta:el('tcpPendingMeta').textContent,decisions:writes,pendingId:item.pending_id};break;
  }
  assert.ok(blocked,'real socket backpressure must leave forwarding in flight');console.log(JSON.stringify(blocked));
})().catch(error=>{console.error(error);process.exitCode=1;});
