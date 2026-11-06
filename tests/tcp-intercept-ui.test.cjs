const test = require('node:test');
const assert = require('node:assert/strict');
const tcp = require('../web/tcp-capture.js');
const tick = () => new Promise(r => setImmediate(r));
const policy = { enabled:true, direction:'both', revision:7, pending_count:1, paused_count:1, forwarding_count:0 };
const pending = {pending_id:'p1',sequence:1,revision:0,direction:'client_to_server',original_base64:'AP8=',original_length:2,state:'pending'};
const connection = {id:'c1',status:'open',intercept_events:[]};
function fixture() {
  const nodes = new Map(), requests = [];
  function node() {return {value:'',children:[],dataset:{},listeners:{},textContent:'',disabled:false,hidden:false,attributes:{},classList:{toggle(){}},setAttribute(k,v){this.attributes[k]=v},addEventListener(e,f){this.listeners[e]=f},append(...n){this.children.push(...n)},replaceChildren(){this.children=[]},querySelectorAll(){return []}};}
  const document = {getElementById(id){if(!nodes.has(id))nodes.set(id,node());return nodes.get(id)},createElement:node};
  let session = 'a';
  const controller = tcp.createInterceptController({document,sessionId:()=>session,readPath:(p,s)=>p+'?session_id='+s,writePath:(p,s)=>p+'?session_id='+s+'&expected_active_session_id='+s,
    request(path,options){let resolve;const promise=new Promise(r=>resolve=r);requests.push({path,options,resolve(data,status=200){resolve({ok:status>=200&&status<300,status,json:async()=>data})}});return promise}});
  return {controller,requests,get:id=>document.getElementById(id),session:s=>session=s};
}
async function ready(f, items=[pending]) { f.controller.setConnection(connection);f.requests[0].resolve(policy);f.requests[1].resolve({connection_id:'c1',items});await tick(); }
async function resolveRefresh(f, items=[], nextPolicy=policy) {const i=f.requests.length-2; f.requests[i].resolve(nextPolicy);f.requests[i+1].resolve({items});await tick();}
test('Hex parsing preserves byte values and rejects ambiguous, empty, oversized edits',()=>{
  assert.deepEqual([...tcp.parseHex('00 ff\nC3 a9')],[0,255,195,169]);
  for(const x of ['', '0', 'xx', '0x00', '00 '.repeat(16385)])assert.throws(()=>tcp.parseHex(x));
});
test('pending editor uses raw bytes, direction labels, and one explicit revision-guarded decision',async()=>{
  const f=fixture();await ready(f);
  assert.equal(f.get('tcpPendingHex').value,'00 ff');
  assert.equal(f.get('tcpForward').disabled,false);
  f.get('tcpPendingHex').value='41 00 ff';f.get('tcpPendingHex').listeners.input();
  f.get('tcpForward').listeners.click();f.get('tcpForward').listeners.click();
  assert.equal(f.requests.length,3);
  assert.match(f.requests[2].path,/c1\/pending\/p1\/decision\?session_id=a&expected_active_session_id=a/);
  assert.deepEqual(JSON.parse(f.requests[2].options.body),{action:'forward',expected_revision:0,replacement_base64:'QQD/'});
  assert.equal(f.get('tcpDrop').disabled,true);
  f.requests[2].resolve({state:'forwarding'});await tick();
  // The Stream shows what was written; a forward needs no notice of its own.
  assert.equal(f.get('tcpInterceptNotice').textContent,'');
  await resolveRefresh(f,[{...pending,pending_id:'p2',sequence:2}]);
  assert.equal(f.get('tcpForward').disabled,true,'next chunk must be explicitly selected after decision');
  assert.equal(f.get('tcpPendingHex').value,'');
});
test('unchanged forward omits replacement, drop never sends editor content',async()=>{
  for(const action of ['tcpForward','tcpDrop']){
    const f=fixture();await ready(f);f.get(action).listeners.click();
    assert.deepEqual(JSON.parse(f.requests[2].options.body),{action:action==='tcpForward'?'forward':'drop',expected_revision:0});
    f.requests[2].resolve({});await tick();await resolveRefresh(f);
  }
});
test('Off only changes policy, retains pending, and does not forward bytes',async()=>{
  const f=fixture();await ready(f);f.get('tcpInterceptToggle').listeners.click();
  assert.match(f.requests[2].path,/\/api\/tcp\/intercept\?/);
  assert.deepEqual(JSON.parse(f.requests[2].options.body),{enabled:false,direction:'both',expected_revision:7});
  f.requests[2].resolve({...policy,enabled:false,revision:8});await tick();
  await resolveRefresh(f,[pending],{...policy,enabled:false,revision:8});
  assert.equal(f.get('tcpPendingHex').value,'00 ff');assert.equal(f.get('tcpForward').disabled,false);
  assert.match(f.get('tcpInterceptStatus').textContent,/1 paused/);
  assert.equal(f.requests.filter(r=>r.options?.method==='POST').length,0);
});
test('polling preserves edited draft, stale selection and session responses cannot restore old bytes',async()=>{
  const f=fixture();await ready(f);f.get('tcpPendingHex').value='aa bb';f.get('tcpPendingHex').listeners.input();
  const poll=f.controller.refresh();f.requests[2].resolve(policy);f.requests[3].resolve({items:[pending]});await poll;
  assert.equal(f.get('tcpPendingHex').value,'aa bb');
  f.controller.setConnection({...connection,id:'c2'});const old=f.requests.slice(-2);
  f.controller.setConnection({...connection,id:'c3'});const newer=f.requests.slice(-2);
  newer[0].resolve(policy);newer[1].resolve({items:[{...pending,pending_id:'new',original_base64:'Qg=='}]});await tick();
  old[0].resolve(policy);old[1].resolve({items:[pending]});await tick();assert.equal(f.get('tcpPendingHex').value,'42');
  const late=f.controller.refresh();f.session('b');f.controller.reset();
  f.requests.at(-2).resolve(policy);f.requests.at(-1).resolve({items:[pending]});await late;
  assert.equal(f.get('tcpPendingHex').value,'');assert.equal(f.get('tcpForward').disabled,true);
});
test('failed reads disable mutations and stale decision conflicts do not auto-retry',async()=>{
  const f=fixture();await ready(f);f.get('tcpForward').listeners.click();f.requests[2].resolve({},409);await tick();await resolveRefresh(f,[]);
  assert.match(f.get('tcpInterceptError').textContent,/bytes changed/);assert.equal(f.requests.length,5);
  const poll=f.controller.refresh();f.requests[5].resolve(policy);f.requests[6].resolve({},500);await poll;
  assert.equal(f.get('tcpCloseConnection').disabled,true);assert.equal(f.get('tcpForward').disabled,true);
});
test('close accepts 204 without claiming closed or persistence; history has original/selected/written',async()=>{
  const f=fixture();await ready(f);f.get('tcpCloseConnection').listeners.click();assert.match(f.requests[2].path,/c1\/close\?/);
  f.requests[2].resolve(null,204);await tick();await resolveRefresh(f,[]);
  assert.match(f.get('tcpInterceptNotice').textContent,/Closing/);
  f.controller.setConnection({...connection,status:'closed',intercept_events:[{...pending,sequence:2,state:'dropped',selected_length:0,written_bytes:0,original_offset:2,destination_offset:2},{...pending,pending_id:'first',sequence:1,state:'forwarded',selected_length:3,written_bytes:3,selected_base64:'QQD/',original_offset:0,destination_offset:0}]});
  assert.equal(f.get('tcpCloseConnection').disabled,true);assert.equal(f.get('tcpForward').disabled,true);
  const rows=f.get('tcpInterceptHistory').children;assert.match(rows[0].children[0].textContent,/#1.*2 B → 3 B$/);
  assert.match(rows[0].children[1].children[0].textContent,/Original.*\n00 ff/s);
  assert.match(rows[0].children[1].children[1].textContent,/Sent\n41 00 ff/);
});
test('invalid editor cannot send; forwarding state stays read-only; choosing other direction is explicit',async()=>{
  const f=fixture();await ready(f,[pending,{...pending,pending_id:'s1',direction:'server_to_client',state:'forwarding'}]);
  f.get('tcpPendingHex').value='f';f.get('tcpForward').listeners.click();assert.equal(f.requests.length,2);assert.match(f.get('tcpInterceptError').textContent,/whole hex byte pairs/);
  f.get('tcpPendingPicker').value='s1';f.get('tcpPendingPicker').listeners.change();assert.equal(f.get('tcpForward').disabled,true);assert.match(f.get('tcpForward').textContent,/client/);
});

test('external resolution never silently selects the following pending bytes', async () => {
  const f = fixture(); await ready(f);
  assert.equal(f.get('tcpPendingHex').value, '00 ff');
  const poll = f.controller.refresh();
  f.requests[2].resolve(policy);
  f.requests[3].resolve({items:[{...pending,pending_id:'p2',sequence:2,original_base64:'QUI='}]});
  await poll;
  assert.equal(f.get('tcpPendingPicker').value, '');
  assert.equal(f.get('tcpPendingHex').value, '');
  assert.equal(f.get('tcpPendingPicker').hidden, false, 'a range left unchosen is chosen in the picker');
  assert.equal(f.get('tcpPendingHex').placeholder, 'Choose bytes');
  assert.equal(f.get('tcpForward').disabled, true);
  f.get('tcpForward').listeners.click();
  assert.equal(f.requests.length, 4, 'even a stale queued click cannot send replacement bytes');
  f.get('tcpPendingPicker').value = 'p2'; f.get('tcpPendingPicker').listeners.change();
  assert.equal(f.get('tcpPendingHex').value, '41 42');
  f.get('tcpForward').listeners.click();
  assert.match(f.requests[4].path, /pending\/p2\/decision/);
  f.requests[4].resolve({state:'forwarding'}); await tick(); await resolveRefresh(f);
});

test('successful polling clears only transient read errors, retaining unresolved mutation errors', async () => {
  const f = fixture(); await ready(f);
  const fail = f.controller.refresh();
  f.requests[2].resolve(policy); f.requests[3].resolve({}, 500); await fail;
  assert.match(f.get('tcpInterceptError').textContent, /500/);
  const recover = f.controller.refresh();
  f.requests[4].resolve(policy); f.requests[5].resolve({items:[pending]}); await recover;
  assert.equal(f.get('tcpInterceptError').textContent, '');
  f.get('tcpForward').listeners.click(); f.requests[6].resolve({}, 409); await tick();
  f.requests[7].resolve(policy); f.requests[8].resolve({}, 502); await tick();
  assert.match(f.get('tcpInterceptError').textContent, /bytes changed/);
  const recoverAgain = f.controller.refresh();
  f.requests[9].resolve(policy); f.requests[10].resolve({items:[pending]}); await recoverAgain;
  assert.match(f.get('tcpInterceptError').textContent, /bytes changed/);
  assert.doesNotMatch(f.get('tcpInterceptError').textContent, /502/);
});

test('expanded history gets flexible space and original/selected byte columns', async () => {
  const f = fixture(); await ready(f);
  let expanded = false;
  f.get('tcpInterceptHistory').classList.toggle = (name, value) => { if (name === 'expanded') expanded = value; };
  f.controller.setConnection({...connection,intercept_events:[{...pending,selected_base64:'QUI=',selected_length:2,written_bytes:2,state:'forwarded',original_offset:0,destination_offset:0}]});
  const row = f.get('tcpInterceptHistory').children[0];
  assert.equal(expanded, false);
  row.open = true; row.listeners.toggle(); assert.equal(expanded, true);
  assert.equal(row.children[1].className, 'tcp-event-bytes');
  assert.equal(row.children[1].children.length, 2);
  row.open = false; row.listeners.toggle(); assert.equal(expanded, false);
});

test('empty editor placeholders distinguish no connection, unavailable state, and empty queue', async () => {
  const f = fixture();
  assert.equal(f.get('tcpPendingHex').placeholder, 'Select a connection');
  f.controller.setConnection(connection);
  assert.equal(f.get('tcpPendingHex').placeholder, 'Pending bytes unavailable');
  f.requests[0].resolve(policy); f.requests[1].resolve({items:[]}); await tick();
  assert.equal(f.get('tcpPendingHex').placeholder, 'No pending bytes');
});

test('TCP table scrolls sideways inside a keyboard-accessible area and keeps all its columns', () => {
  const fs = require('node:fs'), path = require('node:path');
  const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
  const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  assert.match(css, /\.tcp-table \{ table-layout: fixed; min-width: 760px; \}/);
  assert.match(css, /\.tcp-history \.history-table-shell \{ flex: 1; min-height: 0; overflow: auto; \}/);
  const panel = html.slice(html.indexOf('id="tcpPanel"'), html.indexOf('id="websocketPanel"'));
  assert.match(panel, /class="history-table-shell" tabindex="0" aria-label="TCP connections"/);
  assert.equal((panel.match(/<th\b/g) || []).length, 8, 'all columns remain');
});

test('truncated intercept history discloses missing events as well as missing byte previews', async () => {
  const f = fixture(); await ready(f);
  f.controller.setConnection({...connection,intercept_truncated:true,intercept_events:[]});
  assert.equal(f.get('tcpInterceptHistory').children.at(-1).textContent, 'Some intercepted bytes are missing.');
});

test('unedited successful forwarding reuses verified original bytes, never infers through missing metadata or truncation', async () => {
  const f = fixture(); await ready(f);
  const original = {...pending,state:'forwarded',edited:false,preview_truncated:false,selected_length:2,written_bytes:2,selected_base64:null,original_offset:0,destination_offset:0};
  const display = event => {
    f.controller.setConnection({...connection,intercept_events:[event]});
    return f.get('tcpInterceptHistory').children[0].children[1].children[1].textContent;
  };
  assert.match(display(original), /^Sent\nUnchanged$/);
  for (const change of [
    {preview_truncated:true,original_base64:null},
    {preview_truncated:true}, {original_base64:null}, {edited:undefined},
    {state:'cancelled',written_bytes:0}, {state:'failed',written_bytes:1},
    {selected_length:3}, {original_length:3,selected_length:3,written_bytes:3}
  ]) {
    const rendered = display({...original,...change});
    assert.doesNotMatch(rendered, /Unchanged/);
    assert.match(rendered, /Preview unavailable/);
  }
  assert.match(display({...original,state:'dropped',selected_length:0,written_bytes:0}), /^Sent\nDropped$/);
  assert.match(display({...original,edited:true,selected_base64:'QUI='}), /\n41 42$/);
});

test('Off distinguishes global paused and forwarding counts without guessing from selected connection', async()=>{
  const f=fixture();await ready(f);
  for (const [paused,forwarding,expected] of [[0,1,'1 forwarding'],[1,0,'1 paused'],[2,3,'2 paused · 3 forwarding'],[0,0,'']]) {
    const poll=f.controller.refresh();
    await resolveRefresh(f, [{...pending,state:'forwarding'}], {...policy,enabled:false,pending_count:paused+forwarding,paused_count:paused,forwarding_count:forwarding});
    await poll;
    assert.equal(f.get('tcpInterceptStatus').textContent,expected);
    assert.doesNotMatch(f.get('tcpInterceptStatus').textContent,/Still paused/);
  }
  assert.ok(f.requests.every(r=>!r.options), 'polling never makes decisions');
});
test('legacy unresolved count never claims every range is paused', async()=>{
  const f=fixture();await ready(f);
  const poll=f.controller.refresh();
  await resolveRefresh(f,[{...pending,state:'forwarding'}],{enabled:false,direction:'both',revision:8,pending_count:4}); await poll;
  assert.equal(f.get('tcpInterceptStatus').textContent,'4 unresolved');
});
test('session reset rejects stale forwarding aggregate', async()=>{
  const f=fixture();await ready(f);
  const poll=f.controller.refresh();const index=f.requests.length-2;
  f.session('b'); f.controller.reset();
  f.requests[index].resolve({...policy,paused_count:0,forwarding_count:9});f.requests[index+1].resolve({items:[{...pending,state:'forwarding'}]});await poll;
  assert.equal(f.get('tcpInterceptStatus').textContent,'');
});

test('in-flight dropped range remains unresolved until owner removes it', async()=>{
  const f=fixture();await ready(f);
  const poll=f.controller.refresh();
  await resolveRefresh(f,[],{...policy,enabled:false,pending_count:1,paused_count:0,forwarding_count:0});await poll;
  assert.equal(f.get('tcpInterceptStatus').textContent,'1 unresolved');
});

test('paused age uses received_at, refreshes without replacing the draft or sending bytes', async () => {
  const originalNow = Date.now;
  let now = Date.parse('2026-11-04T17:00:00Z');
  Date.now = () => now;
  try {
    const f = fixture(), held = {...pending, received_at:'2026-11-04T16:58:00Z'};
    await ready(f, [held]);
    assert.equal(f.get('tcpPendingMeta').textContent, 'Client → Server · 2 B · paused 2m');
    f.get('tcpPendingHex').value = 'aa bb'; f.get('tcpPendingHex').listeners.input();
    now += 60000;
    const poll = f.controller.refresh();
    f.requests.at(-2).resolve(policy); f.requests.at(-1).resolve({items:[held]}); await poll;
    assert.equal(f.get('tcpPendingMeta').textContent, 'Client → Server · 2 B · paused 3m');
    assert.equal(f.get('tcpPendingHex').value, 'aa bb');
    assert.equal(f.requests.filter(r => r.options?.method).length, 0);
  } finally { Date.now = originalNow; }
});

test('missing, malformed, and future pause timestamps do not invent an age', async () => {
  for (const received_at of [undefined, null, '', 'invalid', 0, '2999-01-01T00:00:00Z']) {
    const f = fixture(); await ready(f, [{...pending, received_at}]);
    assert.equal(f.get('tcpPendingMeta').textContent, 'Client → Server · 2 B · paused —');
  }
});

test('pause age formats sub-minute and hour durations', async () => {
  const originalNow = Date.now; Date.now = () => Date.parse('2026-11-04T17:00:00Z');
  try {
    for (const [received_at, age] of [['2026-11-04T16:59:55Z','5s'], ['2026-11-04T15:55:00Z','1h 5m']]) {
      const f = fixture(); await ready(f, [{...pending, received_at}]);
      assert.match(f.get('tcpPendingMeta').textContent, new RegExp('paused ' + age + '$'));
    }
  } finally { Date.now = originalNow; }
});

test('forwarding, ended and unavailable states never show a stale paused age', async () => {
  const f = fixture(); await ready(f, [{...pending, received_at:'2026-11-04T16:58:00Z', state:'forwarding'}]);
  assert.match(f.get('tcpPendingMeta').textContent, /forwarding$/);
  assert.doesNotMatch(f.get('tcpPendingMeta').textContent, /paused/);
  f.controller.setConnection({...connection,status:'stopped'});
  assert.equal(f.get('tcpPendingMeta').textContent, 'Connection ended');
  assert.equal(f.get('tcpForward').disabled, true);
  const poll = f.controller.refresh();
  f.requests.at(-2).resolve(policy); f.requests.at(-1).resolve({}, 500); await poll;
  assert.equal(f.get('tcpPendingMeta').textContent, '');
  assert.equal(f.get('tcpPendingHex').placeholder, 'Pending bytes unavailable');
});

test('Close says it closes both directions', () => {
  const html = require('node:fs').readFileSync(require('node:path').join(__dirname, '../web/index.html'), 'utf8');
  assert.match(html, /id="tcpCloseConnection"[^>]*title="Close both directions"[^>]*>Close connection</);
});

test('Close waits through empty pending polls and clears only on authoritative terminal detail', async () => {
  for (const status of ['closed', 'stopped', 'failed', 'interrupted']) {
    const f = fixture(); await ready(f);
    f.get('tcpCloseConnection').listeners.click(); f.requests[2].resolve(null, 204);
    await tick(); await resolveRefresh(f, []);
    assert.match(f.get('tcpInterceptNotice').textContent, /Closing/);
    f.controller.setConnection({...connection, status:'open', pending_count:0});
    assert.match(f.get('tcpInterceptNotice').textContent, /Closing/);
    f.controller.setConnection({...connection, status:'unknown'});
    assert.match(f.get('tcpInterceptNotice').textContent, /Closing/);
    f.controller.setConnection({...connection, status, durable:status !== 'failed'});
    assert.equal(f.get('tcpInterceptNotice').textContent, '');
  }
});

test('terminal detail arriving before Close response cannot resurrect waiting notice', async () => {
  const f = fixture(); await ready(f); f.get('tcpCloseConnection').listeners.click();
  f.controller.setConnection({...connection, status:'stopped', durable:true});
  f.requests[2].resolve(null, 204); await tick(); await resolveRefresh(f, []);
  assert.equal(f.get('tcpInterceptNotice').textContent, '');
});

test('failed pending poll keeps Close waiting and terminal reconciliation preserves read error', async () => {
  const f = fixture(); await ready(f); f.get('tcpCloseConnection').listeners.click();
  f.requests[2].resolve(null, 204); await tick();
  f.requests[3].resolve(policy); f.requests[4].resolve({}, 500); await tick();
  assert.match(f.get('tcpInterceptNotice').textContent, /Closing/);
  const error = f.get('tcpInterceptError').textContent;
  f.controller.setConnection({...connection, status:'stopped'});
  assert.equal(f.get('tcpInterceptNotice').textContent, '');
  assert.equal(f.get('tcpInterceptError').textContent, error);
});

test('uncertain Close error is retained after terminal detail and never becomes success notice', async () => {
  const f = fixture(); await ready(f); f.get('tcpCloseConnection').listeners.click();
  f.requests[2].resolve({}, 500); await tick(); await resolveRefresh(f, []);
  const error = f.get('tcpInterceptError').textContent; assert.match(error, /Outcome unknown; not retried/);
  f.controller.setConnection({...connection, status:'stopped'});
  assert.equal(f.get('tcpInterceptError').textContent, error);
  assert.equal(f.get('tcpInterceptNotice').textContent, '');
  assert.equal(f.requests.filter(r => r.options?.method === 'POST').length, 1);
});

test('Close response after navigating away and back is not shown on a new selection', async () => {
  const f = fixture(); await ready(f); f.get('tcpCloseConnection').listeners.click();
  f.controller.setConnection({...connection, id:'c2'});
  f.controller.setConnection(connection);
  f.requests[2].resolve(null, 204); await tick();
  assert.equal(f.get('tcpInterceptNotice').textContent, '');
});

test('Close response from a prior session cannot restore a notice or change the new session', async () => {
  const f = fixture(); await ready(f); f.get('tcpCloseConnection').listeners.click();
  f.session('b'); f.controller.reset(); f.controller.setConnection(connection);
  f.requests[2].resolve(null, 204); await tick();
  assert.equal(f.get('tcpInterceptNotice').textContent, '');
  assert.equal(f.get('tcpInterceptError').textContent, '');
});

async function selectDraftConnection(f, id, items = [pending]) {
  f.controller.setConnection({...connection, id});
  await resolveRefresh(f, items);
}
function editDraft(f, value) {
  f.get('tcpPendingHex').value = value;
  f.get('tcpPendingHex').listeners.input();
}

test('an unsent edit survives more than 128 edited, resolved chunks on another connection', async () => {
  const f = fixture(); await ready(f); editDraft(f, 'bb');
  await selectDraftConnection(f, 'c2', []);
  for (let i = 0; i < 140; i++) {
    const item = {...pending, pending_id:'other-' + i};
    const poll = f.controller.refresh(); await resolveRefresh(f, [item]); await poll;
    f.get('tcpPendingPicker').value = item.pending_id; f.get('tcpPendingPicker').listeners.change();
    editDraft(f, 'cc'); f.get('tcpForward').listeners.click();
    assert.equal(JSON.parse(f.requests.at(-1).options.body).replacement_base64, 'zA==');
    f.requests.at(-1).resolve({state:'forwarding'}); await tick(); await resolveRefresh(f, []);
  }
  await selectDraftConnection(f, 'c1');
  assert.equal(f.get('tcpPendingHex').value, 'bb');
  assert.equal(f.get('tcpForward').disabled, false);
  assert.equal(f.get('tcpInterceptError').textContent, '');
  f.get('tcpForward').listeners.click();
  assert.equal(JSON.parse(f.requests.at(-1).options.body).replacement_base64, 'uw==');
  f.requests.at(-1).resolve({state:'forwarding'}); await tick(); await resolveRefresh(f, []);
});

test('drafts belong to a connection and empty or invalid unfinished edits survive navigation', async () => {
  const f = fixture(); await ready(f); editDraft(f, '');
  await selectDraftConnection(f, 'c2');
  assert.equal(f.get('tcpPendingHex').value, '00 ff', 'even an identical pending ID cannot reuse another connection draft');
  editDraft(f, '0');
  await selectDraftConnection(f, 'c1'); assert.equal(f.get('tcpPendingHex').value, '');
  await selectDraftConnection(f, 'c2'); assert.equal(f.get('tcpPendingHex').value, '0');
  f.get('tcpPendingReset').listeners.click(); assert.equal(f.get('tcpPendingHex').value, '00 ff');
  await selectDraftConnection(f, 'c1'); assert.equal(f.get('tcpPendingHex').value, '');
});

test('failed reads and uncertain decisions retain edits until authoritative resolution', async () => {
  for (const status of [409, 500]) {
    const f = fixture(); await ready(f); editDraft(f, 'aa bb');
    f.get('tcpForward').listeners.click(); f.requests.at(-1).resolve({}, status); await tick();
    f.requests.at(-2).resolve(policy); f.requests.at(-1).resolve({}, 500); await tick();
    assert.equal(f.get('tcpPendingHex').value, 'aa bb');
    assert.equal(f.get('tcpForward').disabled, true);
    const recover = f.controller.refresh(); await resolveRefresh(f, [pending]); await recover;
    assert.equal(f.get('tcpPendingHex').value, 'aa bb');
    // A conflict refused the decision; any other failure may have reached the socket.
    assert.match(f.get('tcpInterceptError').textContent, status === 409 ? /bytes changed/ : /Outcome unknown; not retried/);
    assert.equal(f.requests.filter(r => r.options?.method === 'POST').length, 1);
    const resolved = f.controller.refresh(); await resolveRefresh(f, []); await resolved;
    await selectDraftConnection(f, 'other', []); await selectDraftConnection(f, 'c1');
    assert.equal(f.get('tcpPendingHex').value, '00 ff', 'resolved bytes no longer retain the draft');
  }
});

test('external forwarding, terminal details, and terminal list records retire only their own drafts', async () => {
  for (const resolve of ['forwarding', 'detail', 'list']) {
    const f = fixture(); await ready(f); editDraft(f, 'aa');
    await selectDraftConnection(f, 'c2'); editDraft(f, 'bb');
    if (resolve === 'forwarding') {
      const poll = f.controller.refresh(); await resolveRefresh(f, [{...pending, state:'forwarding'}]); await poll;
    } else if (resolve === 'detail') f.controller.setConnection({...connection, id:'c2', status:'closed'});
    else f.controller.reconcileConnections([{...connection, id:'c2', status:'closed'}]);
    await selectDraftConnection(f, 'c1'); assert.equal(f.get('tcpPendingHex').value, 'aa');
    f.controller.reconcileConnections([{...connection, pending_count:0}]);
    await selectDraftConnection(f, 'c2'); assert.equal(f.get('tcpPendingHex').value, '00 ff');
    await selectDraftConnection(f, 'c1'); assert.equal(f.get('tcpPendingHex').value, 'aa', 'an older zero-count list must not discard a current edit');
  }
});

test('stale pending reads cannot retire another connection or newer drafts', async () => {
  const f = fixture(); await ready(f); editDraft(f, 'aa');
  const stale = f.controller.refresh(), old = f.requests.slice(-2);
  await selectDraftConnection(f, 'c2'); editDraft(f, 'bb');
  await selectDraftConnection(f, 'c1');
  old[0].resolve(policy); old[1].resolve({items:[]}); await stale;
  assert.equal(f.get('tcpPendingHex').value, 'aa');
  await selectDraftConnection(f, 'c2'); assert.equal(f.get('tcpPendingHex').value, 'bb');
});

test('successful decisions retire their draft even when response arrives after navigation', async () => {
  for (const action of ['tcpForward', 'tcpDrop']) {
    const f = fixture(); await ready(f); editDraft(f, 'aa');
    f.get(action).listeners.click(); const decision = f.requests.at(-1);
    f.controller.setConnection({...connection, id:'c2'});
    decision.resolve({state:action === 'tcpForward' ? 'forwarding' : 'dropped'}); await tick();
    await resolveRefresh(f, [pending]); editDraft(f, 'bb');
    await selectDraftConnection(f, 'c1'); assert.equal(f.get('tcpPendingHex').value, '00 ff');
    await selectDraftConnection(f, 'c2'); assert.equal(f.get('tcpPendingHex').value, 'bb');
  }
});

test('oversized text is rejected explicitly without truncating or losing an existing draft', async () => {
  const f = fixture(); await ready(f); editDraft(f, 'aa');
  editDraft(f, 'bb' + ' '.repeat(65535));
  assert.equal(f.get('tcpPendingHex').value, 'aa');
  assert.match(f.get('tcpInterceptError').textContent, /Edit not kept: at most 16 KiB/);
  await selectDraftConnection(f, 'c2'); await selectDraftConnection(f, 'c1');
  assert.equal(f.get('tcpPendingHex').value, 'aa');
  const max = 'ab '.repeat(16384); editDraft(f, max);
  assert.equal(f.get('tcpInterceptError').textContent, '');
  await selectDraftConnection(f, 'c2'); await selectDraftConnection(f, 'c1');
  assert.equal(f.get('tcpPendingHex').value, max, 'maximum-size byte payload fits without normalization');
});

test('draft capacity rejects a new edit visibly and never evicts unsent edits; reset frees capacity', async () => {
  const f = fixture(); await ready(f); editDraft(f, 'aa');
  for (let i = 2; i <= 128; i++) { await selectDraftConnection(f, 'c' + i); editDraft(f, 'aa'); }
  await selectDraftConnection(f, 'overflow'); editDraft(f, 'bb');
  assert.equal(f.get('tcpPendingHex').value, '00 ff');
  assert.match(f.get('tcpInterceptError').textContent, /Edit not kept: too many unsent edits/);
  await selectDraftConnection(f, 'c1'); assert.equal(f.get('tcpPendingHex').value, 'aa');
  f.get('tcpPendingReset').listeners.click();
  await selectDraftConnection(f, 'overflow'); editDraft(f, 'bb');
  assert.equal(f.get('tcpPendingHex').value, 'bb');
  assert.equal(f.get('tcpInterceptError').textContent, '');
  f.session('new'); f.controller.reset();
  await selectDraftConnection(f, 'overflow'); assert.equal(f.get('tcpPendingHex').value, '00 ff');
});
