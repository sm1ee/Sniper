const test = require("node:test");
const assert = require("node:assert/strict");
const tcp = require("../web/tcp-capture.js");
test("listener validates ports and host without coercion", () => {
  assert.deepEqual(tcp.validateSettings("9000", " 127.0.0.1 ", "9100"), {local_port:9000,target_host:"127.0.0.1",target_port:9100});
  for (const value of ["", "1e3", "3.5", "-1", "65536", "0"]) assert.throws(() => tcp.validateSettings(value, "example.com", "80"));
  for (const host of ["", "http://example.com", "a b", "a\0b", "a@b"]) assert.throws(() => tcp.validateSettings("9000", host, "80"));
});
test("binary concatenation is directional, byte exact and offset checked", () => {
  const chunk = (direction, offset, bytes) => ({direction,offset,data_base64:Buffer.from(bytes).toString("base64")});
  const record = {chunks:[chunk("client_to_server",0,[0,255]), chunk("server_to_client",0,[12]), chunk("client_to_server",2,[195,169])]};
  assert.deepEqual([...tcp.streamBytes(record,"client_to_server")],[0,255,195,169]);
  assert.deepEqual([...tcp.streamBytes(record,"server_to_client")],[12]);
  record.chunks[2].offset = 3;
  assert.throws(() => tcp.streamBytes(record,"client_to_server"), /Missing bytes/);
});
test("Hex shows original bytes; text is clearly a lossy display projection", () => {
  const bytes = Uint8Array.from([0,255,60,62,27,10]);
  assert.match(tcp.formatHex(bytes),/00 ff 3c 3e 1b 0a/);
  assert.equal(tcp.formatText(bytes),"\\x00�<>\\x1b\n");
});
// A fake node's textContent is its own text only, so the stream is read
// through its children, as the DOM's textContent would join them.
const shown = node => [node.textContent, ...node.children.map(shown)].join("");
function fixture(options = {}) {
  const nodes = new Map(), requests = [], focusCalls = [], documentListeners = {};
  function node() {
    return { value:"", children:[], dataset:{}, listeners:{}, textContent:"", disabled:false,
      classList:{toggle(){}}, setAttribute(){}, addEventListener(e,fn){this.listeners[e]=fn},
      append(...n){this.children.push(...n)}, replaceChildren(){this.children=[]},querySelectorAll(){return []},
      focus(options){focusCalls.push(options); document.activeElement = this}};
  }
  const document = {getElementById(id){if(!nodes.has(id))nodes.set(id,node());return nodes.get(id)}, createElement:node, addEventListener(type,fn){documentListeners[type]=fn}};
  let session = "a";
  document.getElementById("tcpDirection").value="client_to_server";
  const controller = tcp.createController({document,sessionId:()=>session,readPath:(p,s)=>p+"?session_id="+s,writePath:(p,s)=>p+"?session_id="+s+"&expected_active_session_id="+s,
    request(path,options){let resolve,reject;const promise=new Promise((r,j)=>{resolve=r;reject=j});requests.push({path,options,reject,resolve(data,status=200){resolve({ok:status===200,status,json:async()=>data,text:async()=>typeof data === "string" ? data : JSON.stringify(data)})}});return promise},openSettings(){},...options});
  return {controller,nodes,requests,document,focusCalls,session(id){session=id},get: id=>document.getElementById(id), keydown: event => documentListeners.keydown?.({preventDefault(){}, ...event})};
}
const status = {enabled:false,listeners:[],history_count:0,history_limit:256};
const listener = (id, port, extra = {}) => ({id, enabled:true, running:true, settings:{local_port:port,target_host:"127.0.0.1",target_port:9100}, ...extra});
const tick = () => new Promise(r=>setImmediate(r));
test("poll deduplicates and session reset rejects old responses", async () => {
  const f=fixture(), pending=f.controller.refresh(); f.controller.refresh();
  assert.equal(f.requests.length,2);
  f.session("b");f.controller.reset();
  f.requests[0].resolve({...status,enabled:true,listeners:[listener("l1",9999)]});
  f.requests[1].resolve([{id:"old"}]);await pending;
  assert.equal(f.get("tcpListenerStatus").textContent,"Unavailable");
  assert.equal(f.get("tcpHistoryRows").children.length,1);
  const next=f.controller.refresh(); assert.match(f.requests[2].path,/session_id=b/);
  f.requests[2].resolve(status);f.requests[3].resolve([]);await next;
  assert.equal(f.get("tcpAddListener").disabled,false);
});
test("selection races cannot replace the newer stream",async()=>{
  const f=fixture(), first=f.controller.select("first"), second=f.controller.select("second");
  f.requests[1].resolve({id:"second",target:"second",status:"closed",durable:true,chunks:[]});await second;
  f.requests[0].resolve({id:"first",target:"first",status:"closed",chunks:[]});await first;
  assert.equal(f.get("tcpStreamTitle").textContent,"second");
});
test("Add is explicit, session guarded, duplicate submits blocked and errors persist",async()=>{
  const f=fixture(), read=f.controller.refresh();
  f.requests[0].resolve(status);f.requests[1].resolve([]);await read;
  assert.equal(f.get("tcpListenerForm").hidden,true);
  f.get("tcpAddListener").listeners.click();
  assert.equal(f.get("tcpListenerForm").hidden,false);
  assert.equal(f.get("tcpLocalPort").value,"9000");
  f.get("tcpTargetHost").value="127.0.0.1";f.get("tcpTargetPort").value="9100";
  f.get("tcpListenerForm").listeners.submit({preventDefault(){}});
  f.get("tcpListenerForm").listeners.submit({preventDefault(){}});
  assert.equal(f.requests.length,3);
  assert.match(f.requests[2].path,/^\/api\/tcp\/listeners\?session_id=a&expected_active_session_id=a$/);
  assert.equal(f.requests[2].options.method,"POST");
  assert.deepEqual(JSON.parse(f.requests[2].options.body),{enabled:true,settings:{local_port:9000,target_host:"127.0.0.1",target_port:9100}});
  assert.equal(f.get("tcpSaveListener").disabled,true);
  f.requests[2].resolve({},409);await tick();
  f.requests[3].resolve(status);f.requests[4].resolve([]);await tick();
  assert.match(f.get("tcpSettingsError").textContent,/409/);
  assert.equal(f.get("tcpListenerForm").hidden,false,"the form stays open with the error");
  assert.equal(f.get("tcpSaveListener").disabled,false);
});
test("partial history and storage errors remain visible",async()=>{
  const f=fixture(), pending=f.controller.refresh();
  f.requests[0].resolve({...status,persistence_error:true});f.requests[1].resolve([{id:"x",target:"<script>",peer:"127.0.0.1",status:"closed",client_bytes:200,server_bytes:0,capture_truncated:true}]);await pending;
  assert.match(f.get("tcpHistoryStatus").textContent,/storage/);
  const row=f.get("tcpHistoryRows").children[0];
  assert.equal(row.children[2].textContent,"<script>");
  assert.equal(row.children[4].textContent,"Closed · partial · not saved");
});
test("a listener's switch turns it off for this session, and a late answer is ignored",async()=>{
  const f=fixture(), pending=f.controller.refresh();
  f.requests[0].resolve(runningStatus);f.requests[1].resolve([]);await pending;
  const toggle=f.get("tcpListenerRows").children[0].children[0].children[0];
  assert.equal(toggle.dataset.listenerToggle,"l1");
  f.get("tcpListenerRows").listeners.click({target:{closest:selector=>selector==="[data-listener-toggle]"?toggle:null}});
  assert.match(f.requests[2].path,/^\/api\/tcp\/listeners\/l1\?session_id=a&expected_active_session_id=a$/);
  assert.equal(f.requests[2].options.method,"PUT");
  assert.deepEqual(JSON.parse(f.requests[2].options.body),{enabled:false,settings:runningStatus.listeners[0].settings});
  f.session("b");f.controller.reset();
  f.requests[2].resolve(status);await tick();
  assert.equal(f.requests.length,3);
  assert.equal(f.get("tcpListenerStatus").textContent,"Unavailable");
});
test("invalid or excessive captured bytes fail closed",()=>{
  assert.throws(()=>tcp.streamBytes({chunks:[{direction:"client_to_server",offset:0,data_base64:"%%%"}]},"client_to_server"));
  assert.throws(()=>tcp.streamBytes({chunks:[{direction:"client_to_server",offset:0,data_base64:Buffer.alloc(1048577).toString("base64")}]},"client_to_server"),/too large/);
});
test("newer poll detail wins over older selection detail for the same connection",async()=>{
  const f=fixture(), first=f.controller.select("x"), poll=f.controller.refresh();
  f.requests[1].resolve(status);f.requests[2].resolve([{id:"x",target:"127.0.0.1",status:"open"}]);await tick();
  f.requests[3].resolve({id:"x",target:"127.0.0.1",status:"closed",durable:true,capture_truncated:true,chunks:[{direction:"client_to_server",offset:0,data_base64:"TkVX"}]});await poll;
  assert.match(shown(f.get("tcpStreamBytes")),/4e 45 57/);
  f.requests[0].resolve({id:"x",target:"127.0.0.1",status:"open",durable:false,chunks:[{direction:"client_to_server",offset:0,data_base64:"Tw=="}]});await first;
  assert.match(shown(f.get("tcpStreamBytes")),/4e 45 57/);
  assert.match(f.get("tcpStreamMeta").textContent,/Partial/);
});
test("old detail errors are ignored and current detail failure does not erase listener status",async()=>{
  const f=fixture(), old=f.controller.select("x"), poll=f.controller.refresh();
  f.requests[1].resolve(runningStatus);
  f.requests[2].resolve([{id:"x",target:"127.0.0.1",status:"open"}]);await tick();
  f.requests[3].resolve({},404);await poll;
  assert.match(f.get("tcpHistoryError").textContent,/404/);
  assert.match(f.get("tcpListenerStatus").textContent,/1 listening/);
  f.requests[0].resolve({},500);await old;
  assert.match(f.get("tcpHistoryError").textContent,/404/);
  assert.doesNotMatch(f.get("tcpHistoryError").textContent,/500/);
});
test("only live stream duration advances; interrupted duration stays unknown", async () => {
  const f = fixture(), originalNow = Date.now;
  let now = Date.parse("2026-01-01T00:00:10Z");
  Date.now = () => now;
  const records = ["interrupted", "closed", "failed", "stopped", "open", "connecting"].map(status => ({
    id: status, target: status, status, started_at: "2026-01-01T00:00:00Z", ended_at: null,
    client_bytes: 0, server_bytes: 0
  }));
  records.push({...records[1], id:"known-end", ended_at:"2026-01-01T00:00:03Z"});
  try {
    for (const liveDuration of ["10.0 s", "70.0 s"]) {
      const pending = f.controller.refresh(), index = f.requests.length - 2;
      f.requests[index].resolve(status); f.requests[index + 1].resolve(records); await pending;
      const durations = f.get("tcpHistoryRows").children.map(row => row.children[7].textContent);
      assert.deepEqual(durations, ["—", "—", "—", "—", liveDuration, liveDuration, "3.0 s"]);
      now += 60000;
    }
  } finally { Date.now = originalNow; }
});

test('connection list marks truncated intercept events partial without losing durability status', async () => {
  const f = fixture(), read = f.controller.refresh();
  const base = {target:'example.com:9000',peer:'127.0.0.1:9001',client_bytes:0,server_bytes:0,capture_truncated:false,intercept_truncated:true};
  f.requests[0].resolve(status);
  f.requests[1].resolve([
    {...base,id:'saved',status:'closed',durable:true},
    {...base,id:'unsaved',status:'closed',durable:false},
    {...base,id:'live',status:'open',durable:false}
  ]);
  await read;
  assert.deepEqual(f.get('tcpHistoryRows').children.map(row=>row.children[4].textContent),
    ['Closed · partial','Closed · partial · not saved','Open · partial']);
});

const runningStatus = {...status, enabled:true, listeners:[listener("l1",9000)]};
async function pollStatus(f, nextStatus, records = []) {
  const poll = f.controller.refresh(), index = f.requests.length - 2;
  f.requests[index].resolve(nextStatus); f.requests[index + 1].resolve(records); await poll;
}
test("full history distinguishes listener on from new accepts and retains pending rows without mutations", async () => {
  const f = fixture();
  await pollStatus(f, {...runningStatus,history_count:256}, [{id:"live",target:"127.0.0.1",status:"open",pending_count:2,pending_directions:["client_to_server"],client_bytes:3,server_bytes:0}]);
  assert.equal(f.get("tcpListenerStatus").textContent,"History full (256/256)");
  assert.match(f.get("tcpHistoryStatus").textContent,/History full/);
  assert.match(f.get("tcpHistoryRows").children[0].children[4].textContent,/2 paused/);
  assert.match(f.get("tcpSettingsError").textContent,/relayed but not recorded/);
  assert.equal(f.requests.length,2);
  assert.ok(f.requests.every(r => !r.options));
});
test("normal listener, stopped full history and storage recovery have truthful status", async () => {
  const f = fixture();
  await pollStatus(f, {...runningStatus,history_count:255});
  assert.equal(f.get("tcpListenerStatus").textContent,"1 listening");
  assert.equal(f.get("tcpSettingsError").textContent,"");
  await pollStatus(f, {...status,history_count:256});
  assert.equal(f.get("tcpListenerStatus").textContent,"History full (256/256)");
  await pollStatus(f, {...runningStatus,persistence_error:true});
  assert.equal(f.get("tcpListenerStatus").textContent,"History storage unavailable");
  await pollStatus(f, runningStatus);
  assert.equal(f.get("tcpSettingsError").textContent,"");
  assert.doesNotMatch(f.get("tcpHistoryStatus").textContent,/blocked|storage/);
});
test("newer rows at cap override a pre-cap status snapshot", async () => {
  const f=fixture();
  await pollStatus(f, {...runningStatus,history_count:255}, Array.from({length:256},(_,i)=>({id:String(i),status:"closed"})));
  assert.match(f.get("tcpListenerStatus").textContent,/History full \(256\/256\)/);
});
test("session switch clears cap and pending counts and ignores stale full response", async () => {
  const f=fixture();
  await pollStatus(f, {...runningStatus,history_count:256}, [{id:"old",status:"open",pending_count:1}]);
  const stale=f.controller.refresh(), index=f.requests.length-2;
  f.session("b"); f.controller.reset();
  assert.doesNotMatch(f.get("tcpHistoryStatus").textContent,/blocked|pending|Listener off/);
  await pollStatus(f,status);
  f.requests[index].resolve({...runningStatus,history_count:256}); f.requests[index+1].resolve([{id:"old",pending_count:9}]); await stale;
  assert.equal(f.get("tcpListenerStatus").textContent,"No listeners");
  assert.equal(f.get("tcpSettingsError").textContent,"");
  assert.doesNotMatch(f.get("tcpHistoryStatus").textContent,/blocked|pending/);
});
test("empty filtered history does not suggest configuring another listener", async () => {
  const f=fixture();
  await pollStatus(f,{...runningStatus,history_count:256},Array.from({length:256},(_,i)=>({id:String(i),status:"closed"})));
  f.get("tcpLiveOnly").listeners.click();
  assert.equal(f.get("tcpHistoryRows").children[0].children[0].textContent,"No live connections");
  assert.match(f.get("tcpHistoryStatus").textContent,/History full \(256\/256\)/);
  f.get("tcpLiveOnly").listeners.click();
  await pollStatus(f,status);
  assert.equal(f.get("tcpHistoryRows").children[0].children[0].textContent,"No TCP connections");
});
test("history counts above the cap remain blocked rather than appearing recovered", async () => {
  const f=fixture();
  await pollStatus(f,{...runningStatus,history_count:257});
  assert.equal(f.get("tcpListenerStatus").textContent,"History full (257/256)");
});
test("TCP admission warnings wrap instead of hiding behind an ellipsis", () => {
  const css=require("node:fs").readFileSync(require("node:path").join(__dirname,"../web/styles.css"),"utf8");
  assert.match(css,/#tcpHistoryStatus\s*\{[^}]*white-space:\s*normal;[^}]*overflow-wrap:\s*anywhere;/);
});
test("listener normalizes IPv6 and rejects host:port and malformed brackets", () => {
  for (const host of ["::1", "[::1]", "[0:0:0:0:0:0:0:1]"]) assert.equal(tcp.validateSettings("9000",host,"9100").target_host,"::1");
  for (const host of ["localhost:1234","127.0.0.1:80","[::1]:80","[localhost]","[::1","::1]","[[::1]]","fe80::1%eth0"]) assert.throws(()=>tcp.validateSettings("9000",host,"9100"));
});
test("configuration errors reveal only recognized actionable messages", async () => {
  const conflict="Local port 9000 is already in use. Choose another Local port or stop the listener using it.";
  assert.equal(await tcp.requestError({status:400,text:async()=>conflict}),conflict);
  for (const body of ["<script>alert(1)</script>","secret upstream traffic",conflict+"\n", "x".repeat(10000)]) assert.match(await tcp.requestError({status:400,text:async()=>body}),/TCP request failed/);
  assert.match(await tcp.requestError({status:400,text:async()=>{throw Error()}}),/400/);
  assert.match(await tcp.requestError({status:409,text:async()=>conflict}),/409/);
});

test("a new listener's bind conflict is shown and nothing is retried",async()=>{
  const f=fixture(), read=f.controller.refresh();
  f.requests[0].resolve(status);f.requests[1].resolve([]);await read;
  f.get("tcpAddListener").listeners.click();
  f.get("tcpLocalPort").value="9000";f.get("tcpTargetHost").value="[::1]";f.get("tcpTargetPort").value="9100";
  f.get("tcpListenerForm").listeners.submit({preventDefault(){}});
  assert.equal(JSON.parse(f.requests[2].options.body).settings.target_host,"::1");
  const error="Local port 9000 is already in use. Choose another Local port or stop the listener using it.";
  f.requests[2].resolve(error,400);await tick();
  f.requests[3].resolve(status);f.requests[4].resolve([]);await tick();
  assert.equal(f.get("tcpSettingsError").textContent,error);
  assert.equal(f.requests.filter(r=>r.options?.method==="POST").length,1);
});

test("failure labels are fixed, contextual and unknown-safe", () => {
  for (const [code, label] of [["tls_failed","TLS handshake failed"],["proxy_failed","Upstream proxy failed"],["resolution_timeout","Name lookup timed out"],["resolution_failed","Name lookup failed"],["connect_timeout","Connection timed out"],["connection_refused","Connection refused"],["connect_failed","Connection failed"],["self_target","Target is this listener"],["relay_failed","Stream interrupted"],["storage_failed","History storage failed"]]) {
    assert.equal(tcp.statusLabel({status:"failed",failure:code}),"Failed · "+label);
    assert.equal(tcp.statusLabel({status:"stopped",failure:code}),"Stopped");
  }
  for(const failure of [undefined,null,"future_code","<img src=x onerror=secret>","__proto__","constructor"]) assert.equal(tcp.statusLabel({status:"failed",failure}),"Failed");
});
test("failure appears in history and detail without exposing unknown strings", async () => {
  const f=fixture(), read=f.controller.refresh();
  f.requests[0].resolve(status); f.requests[1].resolve([{id:"x",target:"loopback",peer:"local",status:"failed",failure:"connection_refused",client_bytes:0,server_bytes:0}]); await read;
  assert.match(f.get("tcpHistoryRows").children[0].children[4].textContent,/Connection refused/);
  const selected=f.controller.select("x");f.requests[2].resolve({id:"x",target:"loopback",status:"failed",failure:"connection_refused",chunks:[]});await selected;
  assert.equal(f.get("tcpStreamTitle").textContent,"loopback");
});

test('active cap shows waiting admission, preserves controls and clears after slot frees', async()=>{
  const f=fixture();
  await pollStatus(f,{...runningStatus,active_count:32,active_limit:32});
  assert.equal(f.get('tcpListenerStatus').textContent,'32 of 32 connections; new ones wait');
  assert.match(f.get('tcpHistoryStatus').textContent,/new ones wait/);
  assert.equal(f.get('tcpSettingsError').textContent,'');
  assert.ok(f.requests.every(r=>!r.options));
  await pollStatus(f,{...runningStatus,active_count:31,active_limit:32});
  assert.equal(f.get('tcpListenerStatus').textContent,'1 listening');
  await pollStatus(f,{...runningStatus,active_count:32,active_limit:32,history_count:256});
  assert.match(f.get('tcpListenerStatus').textContent,/History full/);
  assert.doesNotMatch(f.get('tcpListenerStatus').textContent,/new ones wait/);
  await pollStatus(f,{...status,active_count:32,active_limit:32});
  assert.equal(f.get('tcpListenerStatus').textContent,'No listeners');
});
test('session switch clears active cap and rejects late status', async()=>{
  const f=fixture(); await pollStatus(f,{...runningStatus,active_count:32,active_limit:32});
  const poll=f.controller.refresh(),index=f.requests.length-2;
  f.session('b');f.controller.reset();await pollStatus(f,status);
  f.requests[index].resolve({...runningStatus,active_count:32,active_limit:32});f.requests[index+1].resolve([]);await poll;
  assert.equal(f.get('tcpListenerStatus').textContent,'No listeners');
  assert.doesNotMatch(f.get('tcpHistoryStatus').textContent,/new ones wait/);
});


test("unsaved records offer Stop and retry saving, which clears once saved", async () => {
  const f = fixture();
  await pollStatus(f, {...status, persistence_error:true, history_count:1}, [{id:"saved-later",status:"stopped",durable:false}]);
  assert.equal(f.get("tcpRetrySaving").hidden,false);
  assert.match(f.get("tcpSettingsError").textContent,/Restore storage, then stop and retry saving/);
  f.get("tcpRetrySaving").listeners.click();
  assert.match(f.requests[2].path,/^\/api\/tcp\/stop\?/);
  assert.equal(f.get("tcpRetrySaving").disabled,true);
  f.requests[2].resolve({...status,persistence_error:false}); await tick();
  f.requests[3].resolve({...status,persistence_error:false}); f.requests[4].resolve([{id:"saved-later",status:"stopped",durable:true}]); await tick();
  assert.equal(f.get("tcpRetrySaving").hidden,true);
  assert.equal(f.get("tcpSettingsError").textContent,"");
});
test("safe persistence and shutdown messages survive response filtering", async () => {
  const unsaved="TCP capture stopped, but 2 connection record(s) are not saved. Keep Sniper open, restore storage, then retry saving.";
  const shutdown="TCP capture cannot start while Sniper is shutting down";
  assert.equal(await tcp.requestError({status:500,text:async()=>unsaved}),unsaved);
  assert.equal(await tcp.requestError({status:503,text:async()=>shutdown}),shutdown);
  for (const status of [500,503]) {
    assert.match(await tcp.requestError({status,text:async()=>"private storage path or captured payload"}),/TCP request failed/);
  }
});

test("a retry that failed is cleared once another window saves the records", async () => {
  const f=fixture();
  const failed={...status,persistence_error:true,history_count:1};
  await pollStatus(f,failed);
  f.get("tcpRetrySaving").listeners.click();
  f.requests[2].resolve("TCP capture stopped, but 1 connection record(s) are not saved. Keep Sniper open, restore storage, then retry saving.",500);await tick();
  f.requests[3].resolve(failed);f.requests[4].resolve([{id:"x",status:"stopped",durable:false}]);await tick();
  assert.match(f.get("tcpSettingsError").textContent,/not saved/);
  await pollStatus(f,{...status,persistence_error:false},[{id:"x",status:"stopped",durable:true}]);
  assert.equal(f.get("tcpSettingsError").textContent,"");
});


test("↑/↓ move the selection through the rows as shown, and a poll keeps it", async () => {
  const f = fixture({arrowStep: event => event.step || 0});
  const rows = [{id:"c2", target:"example.com:9001", status:"open", client_bytes:0, server_bytes:0},
    {id:"c1", target:"example.com:9000", status:"closed", client_bytes:0, server_bytes:0}];
  await pollStatus(f, status, rows);
  assert.deepEqual(f.get("tcpHistoryRows").children.map(row => row.children[0].textContent), ["2", "1"]);
  const detail = () => f.requests.at(-1).path;
  f.keydown({step:1}); assert.match(detail(), /connections\/c2\?/);
  f.keydown({step:1}); assert.match(detail(), /connections\/c1\?/);
  const count = f.requests.length;
  f.keydown({step:1}); assert.equal(f.requests.length, count, "no row past the end");
  f.keydown({step:0}); assert.equal(f.requests.length, count, "a key the app keeps does not move");
  const poll = f.controller.refresh(), index = f.requests.length - 2;
  f.requests[index].resolve(status); f.requests[index + 1].resolve(rows); await tick();
  assert.match(detail(), /connections\/c1\?/, "the poll reads the row still selected");
  f.requests.at(-1).resolve({...rows[1], chunks: []}); await poll;
});

// Both directions read as one conversation, in the order Sniper read them, as
// Wireshark's Follow TCP Stream shows a connection.
test("the stream reads as one conversation in the order it was read", async () => {
  const chunk = (sequence, direction, offset, text) => ({sequence, direction, offset, at:"2026-01-01T00:00:00.250Z", data_base64:Buffer.from(text).toString("base64")});
  const record = {id:"x", target:"example.com:9000", status:"closed", durable:true, client_bytes:7, server_bytes:6,
    chunks:[chunk(3,"client_to_server",4,"GET\n"), chunk(1,"client_to_server",0,"HI\n\n"), chunk(2,"server_to_client",0,"HELLO\n")]};
  assert.deepEqual(tcp.conversation(record).map(part => [part.direction, Buffer.from(part.bytes).toString()]),
    [["client_to_server","HI\n\n"],["server_to_client","HELLO\n"],["client_to_server","GET\n"]]);
  assert.deepEqual(tcp.conversation(record, "server_to_client").map(part => Buffer.from(part.bytes).toString()), ["HELLO\n"]);
  const f = fixture(); f.get("tcpDirection").value = "both";
  const selected = f.controller.select("x"); f.requests[0].resolve(record); await selected;
  const blocks = f.get("tcpStreamBytes").children;
  assert.deepEqual(blocks.map(block => block.className), ["tcp-chunk tcp-chunk-out", "tcp-chunk tcp-chunk-in", "tcp-chunk tcp-chunk-out"]);
  assert.match(blocks[0].children[0].textContent, /^→ 4 B · \d\d:\d\d:\d\d\.250$/);
  assert.match(blocks[1].children[0].textContent, /^← 6 B/);
  assert.match(blocks[2].children[1].textContent, /^00000004 /, "offsets continue within a direction");
  assert.equal(f.get("tcpStreamMeta").textContent, "7 B sent · 6 B received");
});

test("a header click sorts the list, and a second click reverses it", async () => {
  const f = fixture();
  const rows = [{id:"a", target:"b.example.com:1", status:"closed", client_bytes:300, server_bytes:0},
    {id:"b", target:"a.example.com:1", status:"closed", client_bytes:20, server_bytes:0},
    {id:"c", target:"c.example.com:1", status:"open", client_bytes:1000, server_bytes:0}];
  await pollStatus(f, status, rows);
  const click = key => f.get("tcpHistoryHead").listeners.click({target:{closest: selector => selector === "[data-sort]" ? {dataset:{sort:key}} : null}});
  const order = () => f.get("tcpHistoryRows").children.map(row => row.children[2].textContent);
  assert.deepEqual(order(), ["b.example.com:1", "a.example.com:1", "c.example.com:1"], "newest first by #");
  click("client_bytes"); assert.deepEqual(order(), ["a.example.com:1", "b.example.com:1", "c.example.com:1"]);
  click("client_bytes"); assert.deepEqual(order(), ["c.example.com:1", "b.example.com:1", "a.example.com:1"]);
  click("target"); assert.deepEqual(order(), ["a.example.com:1", "b.example.com:1", "c.example.com:1"]);
  f.get("tcpLiveOnly").listeners.click(); assert.deepEqual(order(), ["c.example.com:1"]);
});

const twoListeners = {...status, enabled:true, listeners:[
  listener("l2", 9001, {running:false, error:"Local port 9001 is already in use. Choose another Local port or stop the listener using it."}),
  listener("l1", 9000), listener("l3", 9002, {enabled:false, running:false})]};
const listenerRows = f => f.get("tcpListenerRows").children.map(row => row.children.slice(1).map(cell => cell.textContent));
test("listener rows show where they listen, where they go and why one is not running", async () => {
  const f = fixture();
  await pollStatus(f, twoListeners);
  assert.deepEqual(listenerRows(f), [
    ["127.0.0.1:9000", "127.0.0.1:9100", "Listening"],
    ["127.0.0.1:9001", "127.0.0.1:9100", "Local port 9001 is already in use. Choose another Local port or stop the listener using it."],
    ["127.0.0.1:9002", "127.0.0.1:9100", "Off"]]);
  assert.equal(f.get("tcpListenerRows").children[1].children[3].className, "tcp-listener-error");
  assert.equal(f.get("tcpListenerStatus").textContent, "1 listening");
  await pollStatus(f, status);
  assert.equal(f.get("tcpListenerRows").children[0].children[0].textContent, "No listeners");
});
test("a row click edits a listener; Save keeps it on or off; Remove deletes it", async () => {
  const f = fixture();
  await pollStatus(f, twoListeners);
  const click = id => f.get("tcpListenerRows").listeners.click({target:{closest: selector => selector === "tr[data-listener-id]" ? {dataset:{listenerId:id}} : null}});
  click("l3");
  assert.equal(f.get("tcpListenerForm").hidden, false);
  assert.equal(f.get("tcpRemoveListener").hidden, false);
  assert.equal(f.get("tcpLocalPort").value, "9002");
  f.get("tcpTargetPort").value = "9200";
  f.get("tcpListenerForm").listeners.submit({preventDefault(){}});
  assert.match(f.requests[2].path, /^\/api\/tcp\/listeners\/l3\?/);
  assert.equal(f.requests[2].options.method, "PUT");
  assert.deepEqual(JSON.parse(f.requests[2].options.body), {enabled:false, settings:{local_port:9002, target_host:"127.0.0.1", target_port:9200}});
  f.requests[2].resolve(twoListeners); await tick();
  f.requests[3].resolve(twoListeners); f.requests[4].resolve([]); await tick(); await tick();
  assert.equal(f.get("tcpListenerForm").hidden, true, "a saved edit closes the form");
  click("l1");
  f.get("tcpRemoveListener").listeners.click();
  assert.match(f.requests[5].path, /^\/api\/tcp\/listeners\/l1\?/);
  assert.equal(f.requests[5].options.method, "DELETE");
});
test("the toolbar names one listener, counts several, or says off", async () => {
  const f = fixture();
  await pollStatus(f, runningStatus);
  assert.equal(f.get("tcpOpenSettings").textContent, "127.0.0.1:9000 → 127.0.0.1:9100");
  await pollStatus(f, {...status, enabled:true, listeners:[listener("l1", 9000), listener("l2", 9001)]});
  assert.equal(f.get("tcpOpenSettings").textContent, "2 listeners");
  await pollStatus(f, {...status, listeners:[listener("l1", 9000, {enabled:false, running:false})]});
  assert.equal(f.get("tcpOpenSettings").textContent, "Listener off");
});
test("history names each connection's listener port", async () => {
  const f = fixture();
  await pollStatus(f, status, [{id:"new", local_port:9001, target:"example.com:1", status:"closed"}, {id:"old", target:"example.com:1", status:"closed"}]);
  assert.deepEqual(f.get("tcpHistoryRows").children.map(row => row.children[1].textContent), ["9001", "—"]);
});
test("↑/↓ move through listeners while their list has focus, and a header click sorts them", async () => {
  const f = fixture({arrowStep: event => event.step || 0});
  await pollStatus(f, twoListeners);
  const key = step => f.get("tcpListenerShell").listeners.keydown({step, preventDefault(){}});
  key(1); assert.equal(f.get("tcpLocalPort").value, "9000");
  key(1); assert.equal(f.get("tcpLocalPort").value, "9001");
  key(-1); assert.equal(f.get("tcpLocalPort").value, "9000");
  const sort = key => f.get("tcpListenerHead").listeners.click({target:{closest: selector => selector === "[data-sort]" ? {dataset:{sort:key}} : null}});
  sort("local_port");
  assert.deepEqual(listenerRows(f).map(row => row[0]), ["127.0.0.1:9002", "127.0.0.1:9001", "127.0.0.1:9000"]);
  sort("status");
  assert.deepEqual(listenerRows(f).map(row => row[2]).slice(0, 2), ["Listening", "Local port 9001 is already in use. Choose another Local port or stop the listener using it."]);
});
test("Clear asks first, then removes ended connections; unrecorded ones are counted", async () => {
  const asked = [];
  const f = fixture({confirm: (message, run, options) => asked.push({message, run, options})});
  await pollStatus(f, {...runningStatus, history_count:256, unrecorded_count:3}, [{id:"a", status:"closed"}, {id:"b", status:"open"}]);
  assert.match(f.get("tcpHistoryStatus").textContent, /3 not recorded/);
  assert.equal(f.get("tcpClearHistory").disabled, false);
  f.get("tcpClearHistory").listeners.click();
  assert.equal(f.requests.length, 2, "nothing is removed before the answer");
  assert.equal(asked[0].options.title, "Clear TCP history");
  asked[0].run();
  assert.match(f.requests[2].path, /^\/api\/tcp\/connections\?session_id=a&expected_active_session_id=a$/);
  assert.equal(f.requests[2].options.method, "DELETE");
  await pollStatus(f, runningStatus, [{id:"b", status:"open"}]);
  assert.equal(f.get("tcpClearHistory").disabled, true, "live connections are not cleared");
});
test("detail says when a connection went through the proxy, and what a self-target means", async () => {
  const f = fixture(); f.get("tcpDirection").value = "both";
  let selected = f.controller.select("p");
  f.requests[0].resolve({id:"p", target:"db.example.com:5432", status:"closed", durable:true, via_proxy:true, client_bytes:0, server_bytes:0, chunks:[]}); await selected;
  assert.match(f.get("tcpStreamMeta").textContent, /Through the upstream proxy/);
  selected = f.controller.select("s");
  f.requests[1].resolve({id:"s", target:"db.example.com:5432", status:"failed", failure:"self_target", durable:true, client_bytes:0, server_bytes:0, chunks:[]}); await selected;
  assert.match(f.get("tcpStreamMeta").textContent, /hosts entry/);
});
test("a listener can decrypt TLS: the editor sends it, the list and the detail show it", async () => {
  const f = fixture();
  await pollStatus(f, status);
  f.get("tcpAddListener").listeners.click();
  assert.equal(f.get("tcpListenerTls").value, "off");
  f.get("tcpTargetHost").value = "db.example.com"; f.get("tcpTargetPort").value = "5432"; f.get("tcpListenerTls").value = "decrypt";
  f.get("tcpListenerForm").listeners.submit({preventDefault(){}});
  assert.equal(JSON.parse(f.requests[2].options.body).settings.tls, "decrypt");
  const tlsListener = listener("t1", 9000, {settings:{local_port:9000, target_host:"db.example.com", target_port:5432, tls:"decrypt"}});
  f.requests[2].resolve({...status, enabled:true, listeners:[tlsListener]}); await tick();
  f.requests[3].resolve({...status, enabled:true, listeners:[tlsListener]}); f.requests[4].resolve([]); await tick(); await tick();
  assert.equal(listenerRows(f)[0][1], "db.example.com:5432 · decrypt TLS");
  f.get("tcpListenerRows").listeners.click({target:{closest: selector => selector === "tr[data-listener-id]" ? {dataset:{listenerId:"t1"}} : null}});
  assert.equal(f.get("tcpListenerTls").value, "decrypt");
  const selected = f.controller.select("x");
  f.requests.at(-1).resolve({id:"x", target:"db.example.com:5432", status:"closed", durable:true, client_tls:true, server_tls:true, client_bytes:0, server_bytes:0, chunks:[]}); await selected;
  assert.match(f.get("tcpStreamMeta").textContent, /TLS decrypted/);
});
test("search asks the server, lists only matching connections, and says when it stopped early", async () => {
  const f = fixture();
  await pollStatus(f, status, [{id:"a", target:"example.com:1", status:"closed"}, {id:"b", target:"example.com:2", status:"closed"}]);
  f.get("tcpSearch").value = "PI NG"; f.get("tcpSearchKind").value = "text";
  f.get("tcpSearch").listeners.change();
  const asked = f.requests.at(-1);
  assert.equal(asked.path, "/api/tcp/search?session_id=a&contains=PI%20NG&kind=text");
  asked.resolve({ids:["b"], truncated:false}); await tick(); await tick();
  assert.deepEqual(f.get("tcpHistoryRows").children.map(row => row.children[2].textContent), ["example.com:2"]);
  assert.match(f.get("tcpHistoryStatus").textContent, /1 match/);
  f.get("tcpSearch").value = "zz"; f.get("tcpSearch").listeners.change();
  f.requests.at(-1).resolve({ids:[], truncated:true}); await tick(); await tick();
  assert.match(f.get("tcpHistoryStatus").textContent, /search stopped early/);
  const count = f.requests.length;
  f.get("tcpSearch").value = ""; f.get("tcpSearch").listeners.change();
  assert.equal(f.requests.length, count, "clearing the search asks nothing");
  assert.equal(f.get("tcpHistoryRows").children.length, 2);
});
test("the stream's ⋯ menu saves one direction's bytes and copies the stream as hex", async () => {
  const saved = [], copied = [];
  const f = fixture({download: url => saved.push(url), copy: text => copied.push(text)});
  f.get("tcpDirection").value = "both";
  const selected = f.controller.select("x");
  f.requests[0].resolve({id:"x", target:"example.com:1", status:"closed", durable:true, client_bytes:2, server_bytes:1,
    chunks:[{sequence:0, direction:"client_to_server", offset:0, data_base64:"AP8="}, {sequence:1, direction:"server_to_client", offset:0, data_base64:"QQ=="}]});
  await selected;
  f.get("tcpSaveClient").listeners.click();
  f.get("tcpSaveServer").listeners.click();
  assert.deepEqual(saved, ["/api/tcp/connections/x/raw?session_id=a&direction=client_to_server", "/api/tcp/connections/x/raw?session_id=a&direction=server_to_client"]);
  f.get("tcpCopyHex").listeners.click();
  assert.match(copied[0], /^→ 00000000  00 ff/m);
  assert.match(copied[0], /^← 00000000  41/m);
});

