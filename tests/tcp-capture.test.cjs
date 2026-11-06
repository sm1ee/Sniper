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
  assert.throws(() => tcp.streamBytes(record,"client_to_server"), /gap/);
});
test("Hex shows original bytes; text is clearly a lossy display projection", () => {
  const bytes = Uint8Array.from([0,255,60,62,27,10]);
  assert.match(tcp.formatHex(bytes),/00 ff 3c 3e 1b 0a/);
  assert.equal(tcp.formatText(bytes),"\\x00�<>\\x1b\n");
});
function fixture() {
  const nodes = new Map(), requests = [], focusCalls = [];
  function node() {
    return { value:"", children:[], dataset:{}, listeners:{}, textContent:"", disabled:false,
      classList:{toggle(){}}, setAttribute(){}, addEventListener(e,fn){this.listeners[e]=fn},
      append(n){this.children.push(n)}, replaceChildren(){this.children=[]},querySelectorAll(){return []},
      focus(options){focusCalls.push(options); document.activeElement = this}};
  }
  const document = {getElementById(id){if(!nodes.has(id))nodes.set(id,node());return nodes.get(id)}, createElement:node};
  let session = "a";
  document.getElementById("tcpStateFilter").value="all";
  document.getElementById("tcpDirection").value="client_to_server";
  const controller = tcp.createController({document,sessionId:()=>session,readPath:(p,s)=>p+"?session_id="+s,writePath:(p,s)=>p+"?session_id="+s+"&expected_active_session_id="+s,
    request(path,options){let resolve,reject;const promise=new Promise((r,j)=>{resolve=r;reject=j});requests.push({path,options,reject,resolve(data,status=200){resolve({ok:status===200,status,json:async()=>data,text:async()=>typeof data === "string" ? data : JSON.stringify(data)})}});return promise},openSettings(){}});
  return {controller,nodes,requests,document,focusCalls,session(id){session=id},get: id=>document.getElementById(id)};
}
const status = {enabled:false,settings:null,history_count:0,history_limit:256};
const tick = () => new Promise(r=>setImmediate(r));
test("poll deduplicates and session reset rejects old responses", async () => {
  const f=fixture(), pending=f.controller.refresh(); f.controller.refresh();
  assert.equal(f.requests.length,2);
  f.session("b");f.controller.reset();
  f.requests[0].resolve({...status,enabled:true,settings:{local_port:9999}});
  f.requests[1].resolve([{id:"old"}]);await pending;
  assert.equal(f.get("tcpListenerStatus").textContent,"Unavailable");
  assert.equal(f.get("tcpHistoryRows").children.length,1);
  const next=f.controller.refresh(); assert.match(f.requests[2].path,/session_id=b/);
  f.requests[2].resolve(status);f.requests[3].resolve([]);await next;
  assert.equal(f.get("tcpStart").disabled,false);
});
test("selection races cannot replace the newer stream",async()=>{
  const f=fixture(), first=f.controller.select("first"), second=f.controller.select("second");
  f.requests[1].resolve({id:"second",target:"second",status:"closed",durable:true,chunks:[]});await second;
  f.requests[0].resolve({id:"first",target:"first",status:"closed",chunks:[]});await first;
  assert.equal(f.get("tcpStreamTitle").textContent,"second · closed");
});
test("start is explicit, session guarded, duplicate submits blocked and errors persist",async()=>{
  const f=fixture(), read=f.controller.refresh();
  f.requests[0].resolve(status);f.requests[1].resolve([]);await read;
  f.get("tcpLocalPort").value="9000";f.get("tcpTargetHost").value="127.0.0.1";f.get("tcpTargetPort").value="9100";
  f.get("tcpListenerForm").listeners.submit({preventDefault(){}});
  f.get("tcpListenerForm").listeners.submit({preventDefault(){}});
  assert.equal(f.requests.length,3);
  assert.match(f.requests[2].path,/expected_active_session_id=a/);
  assert.equal(f.requests[2].options.method,"POST");
  assert.equal(f.get("tcpStart").disabled,true);
  f.requests[2].resolve({},409);await tick();
  f.requests[3].resolve(status);f.requests[4].resolve([]);await tick();
  assert.match(f.get("tcpSettingsError").textContent,/409/);
  assert.equal(f.get("tcpStart").disabled,false);
});
test("partial history and storage errors remain visible",async()=>{
  const f=fixture(), pending=f.controller.refresh();
  f.requests[0].resolve({...status,persistence_error:true});f.requests[1].resolve([{id:"x",target:"<script>",peer:"127.0.0.1",status:"closed",client_bytes:200,server_bytes:0,capture_truncated:true}]);await pending;
  assert.equal(f.get("tcpStart").disabled,true);
  assert.match(f.get("tcpHistoryStatus").textContent,/storage/);
  const row=f.get("tcpHistoryRows").children[0];
  assert.equal(row.children[0].children[0].textContent,"<script>");
  assert.equal(row.children[7].textContent,"Partial · Not saved");
});
test("running listener locks fields; Stop is explicit and retains history",async()=>{
  const f=fixture(), pending=f.controller.refresh();
  const running={...status,enabled:true,settings:{local_port:9000,target_host:"127.0.0.1",target_port:9100}};
  f.requests[0].resolve(running);f.requests[1].resolve([]);await pending;
  assert.equal(f.requests.length,2);
  assert.equal(f.get("tcpTargetHost").disabled,true);
  assert.equal(f.get("tcpStart").disabled,true);
  assert.equal(f.get("tcpStop").disabled,false);
  f.get("tcpStop").listeners.click();
  assert.match(f.requests[2].path,/\/stop\?session_id=a&expected_active_session_id=a/);
  f.session("b");f.controller.reset();
  f.requests[2].resolve(status);await tick();
  assert.equal(f.requests.length,3);
  assert.equal(f.get("tcpListenerStatus").textContent,"Unavailable");
});
test("invalid or excessive captured bytes fail closed",()=>{
  assert.throws(()=>tcp.streamBytes({chunks:[{direction:"client_to_server",offset:0,data_base64:"%%%"}]},"client_to_server"));
  assert.throws(()=>tcp.streamBytes({chunks:[{direction:"client_to_server",offset:0,data_base64:Buffer.alloc(262145).toString("base64")}]},"client_to_server"),/limit/);
});
test("newer poll detail wins over older selection detail for the same connection",async()=>{
  const f=fixture(), first=f.controller.select("x"), poll=f.controller.refresh();
  f.requests[1].resolve(status);f.requests[2].resolve([{id:"x",target:"127.0.0.1",status:"open"}]);await tick();
  f.requests[3].resolve({id:"x",target:"127.0.0.1",status:"closed",durable:true,capture_truncated:true,chunks:[{direction:"client_to_server",offset:0,data_base64:"TkVX"}]});await poll;
  assert.match(f.get("tcpStreamBytes").textContent,/4e 45 57/);
  f.requests[0].resolve({id:"x",target:"127.0.0.1",status:"open",durable:false,chunks:[{direction:"client_to_server",offset:0,data_base64:"Tw=="}]});await first;
  assert.match(f.get("tcpStreamBytes").textContent,/4e 45 57/);
  assert.match(f.get("tcpStreamTitle").textContent,/closed/);
  assert.match(f.get("tcpStreamMeta").textContent,/Partial/);
});
test("old detail errors are ignored and current detail failure does not erase listener status",async()=>{
  const f=fixture(), old=f.controller.select("x"), poll=f.controller.refresh();
  f.requests[1].resolve({...status,enabled:true,settings:{local_port:9000,target_host:"127.0.0.1",target_port:9100}});
  f.requests[2].resolve([{id:"x",target:"127.0.0.1",status:"open"}]);await tick();
  f.requests[3].resolve({},404);await poll;
  assert.match(f.get("tcpHistoryError").textContent,/404/);
  assert.equal(f.get("tcpStop").disabled,false);
  assert.match(f.get("tcpListenerStatus").textContent,/Listening/);
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
      const durations = f.get("tcpHistoryRows").children.map(row => row.children[5].textContent);
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
  assert.deepEqual(f.get('tcpHistoryRows').children.map(row=>row.children[7].textContent),
    ['Partial · Saved','Partial · Not saved','Partial · Live · memory']);
});

const runningStatus = {...status, enabled:true, settings:{local_port:9000,target_host:"127.0.0.1",target_port:9100}};
async function pollStatus(f, nextStatus, records = []) {
  const poll = f.controller.refresh(), index = f.requests.length - 2;
  f.requests[index].resolve(nextStatus); f.requests[index + 1].resolve(records); await poll;
}
test("full history distinguishes listener on from new accepts and retains pending rows without mutations", async () => {
  const f = fixture();
  await pollStatus(f, {...runningStatus,history_count:256}, [{id:"live",target:"127.0.0.1",status:"open",pending_count:2,pending_directions:["client_to_server"],client_bytes:3,server_bytes:0}]);
  assert.equal(f.get("tcpListenerStatus").textContent,"Listener on · New connections blocked (256/256)");
  assert.match(f.get("tcpHistoryStatus").textContent,/2 active intercepts/);
  assert.match(f.get("tcpHistoryRows").children[0].children[2].textContent,/2 active intercepts/);
  assert.match(f.get("tcpSettingsError").textContent,/Session → New session/);
  assert.match(f.get("tcpSettingsError").textContent,/Switching sessions closes existing TCP connections; pending bytes are not forwarded/);
  assert.match(f.get("tcpSettingsError").textContent,/History is retained/);
  assert.equal(f.get("tcpStop").disabled,false);
  assert.equal(f.get("tcpStart").disabled,true);
  assert.equal(f.requests.length,2);
  assert.ok(f.requests.every(r => !r.options));
});
test("normal listener, stopped full history and storage recovery have truthful status", async () => {
  const f = fixture();
  await pollStatus(f, {...runningStatus,history_count:255});
  assert.equal(f.get("tcpListenerStatus").textContent,"Listening on 127.0.0.1:9000");
  assert.equal(f.get("tcpSettingsError").textContent,"");
  await pollStatus(f, {...status,history_count:256});
  assert.equal(f.get("tcpListenerStatus").textContent,"Listener off · New connections blocked (256/256)");
  assert.equal(f.get("tcpStart").disabled,true);
  assert.equal(f.get("tcpStop").disabled,true);
  await pollStatus(f, {...runningStatus,persistence_error:true});
  assert.equal(f.get("tcpListenerStatus").textContent,"Listener on · New connections blocked (storage unavailable)");
  await pollStatus(f, runningStatus);
  assert.equal(f.get("tcpSettingsError").textContent,"");
  assert.doesNotMatch(f.get("tcpHistoryStatus").textContent,/blocked|storage/);
});
test("newer rows at cap override a pre-cap status snapshot", async () => {
  const f=fixture();
  await pollStatus(f, {...runningStatus,history_count:255}, Array.from({length:256},(_,i)=>({id:String(i),status:"closed"})));
  assert.match(f.get("tcpListenerStatus").textContent,/blocked \(256\/256\)/);
});
test("session switch clears cap and pending counts and ignores stale full response", async () => {
  const f=fixture();
  await pollStatus(f, {...runningStatus,history_count:256}, [{id:"old",status:"open",pending_count:1}]);
  const stale=f.controller.refresh(), index=f.requests.length-2;
  f.session("b"); f.controller.reset();
  assert.doesNotMatch(f.get("tcpHistoryStatus").textContent,/blocked|pending|Listener off/);
  await pollStatus(f,status);
  f.requests[index].resolve({...runningStatus,history_count:256}); f.requests[index+1].resolve([{id:"old",pending_count:9}]); await stale;
  assert.equal(f.get("tcpListenerStatus").textContent,"Stopped");
  assert.equal(f.get("tcpSettingsError").textContent,"");
  assert.equal(f.get("tcpStart").disabled,false);
  assert.doesNotMatch(f.get("tcpHistoryStatus").textContent,/blocked|pending/);
});
test("empty filtered history does not suggest configuring another listener", async () => {
  const f=fixture();
  await pollStatus(f,{...runningStatus,history_count:256},Array.from({length:256},(_,i)=>({id:String(i),status:"closed"})));
  f.get("tcpStateFilter").value="live"; f.get("tcpStateFilter").listeners.change();
  assert.equal(f.get("tcpHistoryRows").children[0].children[0].textContent,"No live TCP connections. Choose All states to view history.");
  assert.match(f.get("tcpHistoryStatus").textContent,/blocked \(256\/256\)/);
  await pollStatus(f,runningStatus,[{id:"active",status:"open"}]);
  f.get("tcpStateFilter").value="closed"; f.get("tcpStateFilter").listeners.change();
  assert.equal(f.get("tcpHistoryRows").children[0].children[0].textContent,"No closed TCP connections. Choose All states to view history.");
  await pollStatus(f,status);
  assert.match(f.get("tcpHistoryRows").children[0].children[0].textContent,/^No TCP connections\./);
});
test("history counts above the cap remain blocked rather than appearing recovered", async () => {
  const f=fixture();
  await pollStatus(f,{...runningStatus,history_count:257});
  assert.equal(f.get("tcpListenerStatus").textContent,"Listener on · New connections blocked (257/256)");
  assert.equal(f.get("tcpStart").disabled,true);
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

test("listener displays actionable bind conflict while leaving Start retry explicit",async()=>{
  const f=fixture(), read=f.controller.refresh();
  f.requests[0].resolve(status);f.requests[1].resolve([]);await read;
  f.get("tcpLocalPort").value="9000";f.get("tcpTargetHost").value="[::1]";f.get("tcpTargetPort").value="9100";
  f.get("tcpListenerForm").listeners.submit({preventDefault(){}});
  assert.equal(JSON.parse(f.requests[2].options.body).target_host,"::1");
  const error="Local port 9000 is already in use. Choose another Local port or stop the listener using it.";
  f.requests[2].resolve(error,400);await tick();
  f.requests[3].resolve(status);f.requests[4].resolve([]);await tick();
  assert.equal(f.get("tcpSettingsError").textContent,error);
  assert.equal(f.get("tcpStart").disabled,false);
  assert.equal(f.requests.filter(r=>r.options?.method==="POST").length,1);
});

test("failure labels are fixed, contextual and unknown-safe", () => {
  for (const [code, label] of [["resolution_timeout","Name lookup timed out"],["resolution_failed","Name lookup failed"],["connect_timeout","Connection timed out"],["connection_refused","Connection refused"],["connect_failed","Connection failed"],["self_target","Target is this listener"],["relay_failed","Stream interrupted"],["storage_failed","History storage failed"]]) {
    assert.equal(tcp.statusLabel({status:"failed",failure:code}),"failed · "+label);
    assert.equal(tcp.statusLabel({status:"stopped",failure:code}),"stopped");
  }
  for(const failure of [undefined,null,"future_code","<img src=x onerror=secret>","__proto__","constructor"]) assert.equal(tcp.statusLabel({status:"failed",failure}),"failed");
});
test("failure appears in history and detail without exposing unknown strings", async () => {
  const f=fixture(), read=f.controller.refresh();
  f.requests[0].resolve(status); f.requests[1].resolve([{id:"x",target:"loopback",peer:"local",status:"failed",failure:"connection_refused",client_bytes:0,server_bytes:0}]); await read;
  assert.match(f.get("tcpHistoryRows").children[0].children[2].textContent,/Connection refused/);
  const selected=f.controller.select("x");f.requests[2].resolve({id:"x",target:"loopback",status:"failed",failure:"connection_refused",chunks:[]});await selected;
  assert.equal(f.get("tcpStreamTitle").textContent,"loopback · failed · Connection refused");
});

test('active cap shows waiting admission, preserves controls and clears after slot frees', async()=>{
  const f=fixture();
  await pollStatus(f,{...runningStatus,active_count:32,active_limit:32});
  assert.equal(f.get('tcpListenerStatus').textContent,'Listener on · At connection limit (32/32) · New connections wait. Close an unneeded connection to free a slot.');
  assert.match(f.get('tcpHistoryStatus').textContent,/At connection limit/);
  assert.equal(f.get('tcpSettingsError').textContent,'');
  assert.equal(f.get('tcpStop').disabled,false);
  assert.ok(f.requests.every(r=>!r.options));
  await pollStatus(f,{...runningStatus,active_count:31,active_limit:32});
  assert.equal(f.get('tcpListenerStatus').textContent,'Listening on 127.0.0.1:9000');
  await pollStatus(f,{...runningStatus,active_count:32,active_limit:32,history_count:256});
  assert.match(f.get('tcpListenerStatus').textContent,/New connections blocked/);
  assert.doesNotMatch(f.get('tcpListenerStatus').textContent,/connections wait/);
  await pollStatus(f,{...status,active_count:32,active_limit:32});
  assert.equal(f.get('tcpListenerStatus').textContent,'Stopped');
});
test('session switch clears active cap and rejects late status', async()=>{
  const f=fixture(); await pollStatus(f,{...runningStatus,active_count:32,active_limit:32});
  const poll=f.controller.refresh(),index=f.requests.length-2;
  f.session('b');f.controller.reset();await pollStatus(f,status);
  f.requests[index].resolve({...runningStatus,active_count:32,active_limit:32});f.requests[index+1].resolve([]);await poll;
  assert.equal(f.get('tcpListenerStatus').textContent,'Stopped');
  assert.doesNotMatch(f.get('tcpHistoryStatus').textContent,/connection limit/);
});


test("failed stop exposes a retry while off and clears after saving", async () => {
  const f = fixture();
  await pollStatus(f, {...status, persistence_error:true, history_count:1}, [{id:"saved-later",status:"stopped",durable:false}]);
  assert.equal(f.get("tcpStop").disabled,false);
  assert.equal(f.get("tcpStop").textContent,"Retry saving");
  assert.match(f.get("tcpSettingsError").textContent,/Keep Sniper open.*restore storage.*Retry saving/);
  assert.equal(f.get("tcpStart").disabled,true);
  f.get("tcpStop").listeners.click();
  assert.match(f.requests[2].path,/\/stop\?/);
  assert.equal(f.get("tcpStop").disabled,true);
  f.requests[2].resolve({...status,persistence_error:false}); await tick();
  f.requests[3].resolve({...status,persistence_error:false}); f.requests[4].resolve([{id:"saved-later",status:"stopped",durable:true}]); await tick();
  assert.equal(f.get("tcpStop").disabled,true);
  assert.equal(f.get("tcpStop").textContent,"Stop");
  assert.equal(f.get("tcpStart").disabled,false);
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

test("external successful retry clears only the recovered persistence action error", async () => {
  const f=fixture();
  const failed={...status,persistence_error:true,history_count:1};
  await pollStatus(f,runningStatus);
  f.get("tcpStop").listeners.click();
  f.requests[2].resolve("TCP capture stopped, but 1 connection record(s) are not saved. Keep Sniper open, restore storage, then retry saving.",500);await tick();
  f.requests[3].resolve(failed);f.requests[4].resolve([{id:"x",status:"stopped",durable:false}]);await tick();
  assert.match(f.get("tcpSettingsError").textContent,/not saved/);
  await pollStatus(f,{...status,persistence_error:false},[{id:"x",status:"stopped",durable:true}]);
  assert.equal(f.get("tcpSettingsError").textContent,"");
  assert.equal(f.get("tcpStop").disabled,true);
});


test("polling restores the focused TCP row without changing vertical or horizontal scroll", async () => {
  const f = fixture();
  const record = {id:"c1", target:"example.com:9000", status:"open", client_bytes:0, server_bytes:0};
  const first = f.controller.refresh(); f.requests[0].resolve(status); f.requests[1].resolve([record]); await first;
  const body = f.get("tcpHistoryRows");
  body.querySelectorAll = () => body.children.map(row => row.children[0].children[0]);
  f.document.activeElement = body.querySelectorAll()[0];
  const poll = f.controller.refresh();
  f.requests[2].resolve(status); f.requests[3].resolve([{...record, client_bytes:1}]); await poll;
  assert.deepEqual(f.focusCalls, [{preventScroll:true}]);
  assert.equal(f.document.activeElement, body.querySelectorAll()[0]);
  assert.equal(f.document.activeElement.dataset.tcpId, "c1");
});

const bindConflict = port => `Local port ${port} is already in use. Choose another Local port or stop the listener using it.`;
async function failStart(f, message = bindConflict(9000), responseStatus = 400) {
  await pollStatus(f, {...status, persistence_error:false});
  f.get("tcpLocalPort").value = "9000";
  f.get("tcpTargetHost").value = "127.0.0.1";
  f.get("tcpTargetPort").value = "9100";
  const index = f.requests.length;
  f.get("tcpListenerForm").listeners.submit({preventDefault(){}});
  f.requests[index].resolve(message, responseStatus); await tick();
  f.requests[index + 1].resolve({...status, persistence_error:false});
  f.requests[index + 2].resolve([]); await tick();
}

test("external matching Start clears a recovered bind error without retrying the write", async () => {
  for (const message of [bindConflict(9000), "Could not bind local port 9000. Check the port and local permissions."]) {
    const f = fixture(); await failStart(f, message);
    assert.equal(f.get("tcpSettingsError").textContent, message);
    await pollStatus(f, {...runningStatus, persistence_error:false});
    assert.equal(f.get("tcpSettingsError").textContent, "");
    assert.equal(f.get("tcpListenerStatus").textContent, "Listening on 127.0.0.1:9000");
    assert.equal(f.get("tcpStart").disabled, true);
    assert.equal(f.get("tcpStop").disabled, false);
    for (let i = 0; i < 3; i++) await pollStatus(f, runningStatus);
    await pollStatus(f, status);
    assert.equal(f.get("tcpSettingsError").textContent, "", "a recovered error must not reappear after Stop");
    assert.equal(f.requests.filter(request => request.options?.method === "POST").length, 1);
  }
});

test("healthy stopped polls retain the bind failure and untouched dirty form", async () => {
  const f = fixture(); await failStart(f);
  const dirty = ["12345", "draft.example.com", "3x"];
  ["tcpLocalPort", "tcpTargetHost", "tcpTargetPort"].forEach((id, index) => { f.get(id).value = dirty[index]; });
  for (let i = 0; i < 3; i++) await pollStatus(f, {...status, persistence_error:false});
  assert.equal(f.get("tcpSettingsError").textContent, bindConflict(9000));
  assert.deepEqual(["tcpLocalPort", "tcpTargetHost", "tcpTargetPort"].map(id => f.get(id).value), dirty);
  assert.equal(f.get("tcpStart").disabled, false);
  assert.equal(f.requests.filter(request => request.options?.method === "POST").length, 1);
});

for (const [name, settings] of [
  ["local port", {...runningStatus.settings, local_port:9001}],
  ["target host", {...runningStatus.settings, target_host:"example.com"}],
  ["target port", {...runningStatus.settings, target_port:9101}],
  ["invalid host", {...runningStatus.settings, target_host:"[::1]:80"}],
  ["missing settings", null],
  ["partial settings", {local_port:9000}]
]) {
  test(`external Start with different ${name} cannot clear the failed operation`, async () => {
    const f = fixture(); await failStart(f);
    await pollStatus(f, {...runningStatus, settings, persistence_error:false});
    assert.equal(f.get("tcpSettingsError").textContent, bindConflict(9000));
    await pollStatus(f, runningStatus);
    assert.equal(f.get("tcpSettingsError").textContent, "", "recovery matches the original request rather than fields overwritten by another listener");
  });
}

test("Start recovery uses submitted normalized settings, not a later form draft", async () => {
  const f = fixture(); await pollStatus(f, status);
  f.get("tcpLocalPort").value = "09000";
  f.get("tcpTargetHost").value = " [0:0:0:0:0:0:0:1] ";
  f.get("tcpTargetPort").value = "09100";
  f.get("tcpListenerForm").listeners.submit({preventDefault(){}});
  f.requests[2].resolve(bindConflict(9000), 400); await tick();
  f.requests[3].resolve(status); f.requests[4].resolve([]); await tick();
  f.get("tcpTargetHost").value = "example.com";
  await pollStatus(f, {...runningStatus, settings:{...runningStatus.settings, target_host:"::1"}});
  assert.equal(f.get("tcpSettingsError").textContent, "");
  assert.equal(f.get("tcpTargetHost").value, "::1", "running fields still show the authoritative listener");
});

for (const [responseStatus, message] of [
  [409, "active session changed"], [500, "private server output"],
  [503, "TCP capture cannot start while Sniper is shutting down"],
  [400, "invalid target host"], [400, bindConflict(9001)]
]) {
  test(`matching Start preserves unrelated ${responseStatus} error: ${message}`, async () => {
    const f = fixture(); await failStart(f, message, responseStatus);
    const error = f.get("tcpSettingsError").textContent;
    assert.ok(error);
    await pollStatus(f, {...runningStatus, persistence_error:false});
    assert.equal(f.get("tcpSettingsError").textContent, error);
  });
}

test("validation errors replace failed-operation identity and survive running-state polls", async () => {
  const f = fixture(); await failStart(f);
  f.get("tcpTargetPort").value = "invalid";
  f.get("tcpListenerForm").listeners.submit({preventDefault(){}});
  const validation = f.get("tcpSettingsError").textContent;
  assert.match(validation, /whole numbers/);
  await pollStatus(f, runningStatus);
  assert.equal(f.get("tcpSettingsError").textContent, validation);
  assert.equal(f.requests.filter(request => request.options?.method === "POST").length, 1);
});

test("clearing a recovered bind failure reveals current storage and capacity warnings", async () => {
  for (const [next, expected] of [
    [{...runningStatus, persistence_error:true}, /not saved.*Keep Sniper open/],
    [{...runningStatus, load_error:true}, /storage is unavailable/],
    [{...runningStatus, history_count:256}, /History full/]
  ]) {
    const f = fixture(); await failStart(f);
    await pollStatus(f, next);
    assert.match(f.get("tcpSettingsError").textContent, expected);
    assert.doesNotMatch(f.get("tcpSettingsError").textContent, /already in use/);
  }
});

test("failed refresh cannot clear a bind error using its unadopted partial response", async () => {
  const f = fixture(); await failStart(f);
  const read = f.controller.refresh(), index = f.requests.length - 2;
  f.requests[index].resolve(runningStatus); f.requests[index + 1].resolve({}, 500); await read;
  assert.match(f.get("tcpSettingsError").textContent, /500/);
  assert.equal(f.get("tcpStart").disabled, true);
  await pollStatus(f, status);
  assert.equal(f.get("tcpSettingsError").textContent, bindConflict(9000));
  await pollStatus(f, runningStatus);
  assert.equal(f.get("tcpSettingsError").textContent, "");
});

test("pre-action running poll cannot clear a newer failed Start", async () => {
  const f = fixture(); await pollStatus(f, status);
  const old = f.controller.refresh();
  f.get("tcpLocalPort").value = "9000"; f.get("tcpTargetHost").value = "127.0.0.1"; f.get("tcpTargetPort").value = "9100";
  f.get("tcpListenerForm").listeners.submit({preventDefault(){}});
  f.requests[4].resolve(bindConflict(9000), 400); await tick();
  f.requests[5].resolve(status); f.requests[6].resolve([]); await tick();
  f.requests[2].resolve(runningStatus); f.requests[3].resolve([]); await old;
  assert.equal(f.get("tcpSettingsError").textContent, bindConflict(9000));
  assert.equal(f.get("tcpListenerStatus").textContent, "Stopped");
});

test("reconciliation does not apply a known error to a different operation", async () => {
  const f = fixture(); await pollStatus(f, runningStatus);
  f.get("tcpStop").listeners.click();
  f.requests[2].resolve(bindConflict(9000), 400); await tick();
  f.requests[3].resolve(runningStatus); f.requests[4].resolve([]); await tick();
  assert.equal(f.get("tcpSettingsError").textContent, bindConflict(9000));
  const g = fixture();
  const unsaved = "TCP capture stopped, but 1 connection record(s) are not saved. Keep Sniper open, restore storage, then retry saving.";
  await failStart(g, unsaved, 500);
  await pollStatus(g, {...runningStatus, persistence_error:false});
  assert.equal(g.get("tcpSettingsError").textContent, unsaved);
});


test("network failures survive matching running status until an explicit successful action", async () => {
  const f = fixture(); await pollStatus(f, status);
  f.get("tcpLocalPort").value = "9000"; f.get("tcpTargetHost").value = "127.0.0.1"; f.get("tcpTargetPort").value = "9100";
  f.get("tcpListenerForm").listeners.submit({preventDefault(){}});
  f.requests[2].reject(new Error("Synthetic connection failed")); await tick();
  f.requests[3].resolve(status); f.requests[4].resolve([]); await tick();
  await pollStatus(f, runningStatus);
  assert.equal(f.get("tcpSettingsError").textContent, "Synthetic connection failed");
  const index = f.requests.length;
  f.get("tcpStop").listeners.click(); f.requests[index].resolve(status); await tick();
  f.requests[index + 1].resolve(status); f.requests[index + 2].resolve([]); await tick();
  assert.equal(f.get("tcpSettingsError").textContent, "");
});

test("reset clears failure identity and rejects late recovery across sessions", async () => {
  const f = fixture(); await failStart(f);
  const old = f.controller.refresh(), index = f.requests.length - 2;
  f.session("b"); f.controller.reset();
  await pollStatus(f, status);
  f.get("tcpTargetPort").value = "invalid";
  f.get("tcpListenerForm").listeners.submit({preventDefault(){}});
  const validation = f.get("tcpSettingsError").textContent;
  f.requests[index].resolve(runningStatus); f.requests[index + 1].resolve([]); await old;
  assert.equal(f.get("tcpSettingsError").textContent, validation);
  assert.equal(f.get("tcpListenerStatus").textContent, "Stopped");
});


test("matching Start canonicalizes backend IPv4-mapped IPv6 spelling without equating other hosts", async () => {
  const f = fixture(); await pollStatus(f, status);
  f.get("tcpLocalPort").value = "9000"; f.get("tcpTargetHost").value = "::ffff:127.0.0.1"; f.get("tcpTargetPort").value = "9100";
  f.get("tcpListenerForm").listeners.submit({preventDefault(){}});
  assert.equal(JSON.parse(f.requests[2].options.body).target_host, "::ffff:7f00:1");
  f.requests[2].resolve(bindConflict(9000), 400); await tick();
  f.requests[3].resolve(status); f.requests[4].resolve([]); await tick();
  await pollStatus(f, {...runningStatus, settings:{...runningStatus.settings, target_host:"::ffff:127.0.0.2"}});
  assert.equal(f.get("tcpSettingsError").textContent, bindConflict(9000));
  await pollStatus(f, {...runningStatus, settings:{...runningStatus.settings, target_host:"::ffff:127.0.0.1"}});
  assert.equal(f.get("tcpSettingsError").textContent, "");
});


test("malformed status hosts cannot match request hostnames through coercion", async () => {
  for (const host of [undefined, null, 123]) {
    const f = fixture(); await pollStatus(f, status);
    f.get("tcpLocalPort").value = "9000"; f.get("tcpTargetHost").value = String(host); f.get("tcpTargetPort").value = "9100";
    f.get("tcpListenerForm").listeners.submit({preventDefault(){}});
    f.requests[2].resolve(bindConflict(9000), 400); await tick();
    f.requests[3].resolve(status); f.requests[4].resolve([]); await tick();
    await pollStatus(f, {...runningStatus, settings:{...runningStatus.settings, target_host:host}});
    assert.equal(f.get("tcpSettingsError").textContent, bindConflict(9000));
    await pollStatus(f, {...runningStatus, settings:{...runningStatus.settings, target_host:String(host)}});
    assert.equal(f.get("tcpSettingsError").textContent, "");
  }
});
