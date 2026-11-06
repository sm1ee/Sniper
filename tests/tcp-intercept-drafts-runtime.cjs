// Run against a rebuilt, isolated native server: node tests/tcp-intercept-drafts-runtime.cjs [binary] [evidence-directory]
const fs = require('node:fs'), path = require('node:path'), os = require('node:os');
const cp = require('node:child_process'), net = require('node:net'), assert = require('node:assert/strict');
const tcp = require('../web/tcp-capture.js');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function poll(fn) {
  for (let n = 0; n < 500; n++) { const value = await fn(); if (value) return value; await pause(10); }
  throw Error('Timed out waiting for native TCP state');
}
async function unusedPort() {
  const server = net.createServer(); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port;
}
(async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tcp-draft-regression-'));
  const evidenceDir = process.argv[3] ? path.resolve(process.argv[3]) : root;
  fs.mkdirSync(evidenceDir, {recursive:true}); fs.mkdirSync(path.join(root, 'templates'));
  fs.writeFileSync(path.join(root, 'templates/templates.json'), '{"auto_update":false}');
  const [UI, PROXY, RELAY] = await Promise.all([unusedPort(), unusedPort(), unusedPort()]);
  const upstream = net.createServer(socket => socket.on('data', bytes => socket.write(bytes)));
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
  const ECHO = upstream.address().port, sockets = [], calls = [];
  const log = fs.openSync(path.join(evidenceDir, 'native-drafts.log'), 'w');
  const binary = path.resolve(process.argv[2] || 'target/release/sniper');
  const processHandle = cp.spawn(binary, [], {env:{...process.env, SNIPER_DATA_DIR:root, SNIPER_UI_ADDR:`127.0.0.1:${UI}`, SNIPER_PROXY_ADDR:`127.0.0.1:${PROXY}`, RUST_LOG:'warn'}, stdio:['ignore', log, log]});
  let failedRead = false, staleDecision = false;
  const nodes = new Map();
  function node() { return {value:'', children:[], dataset:{}, listeners:{}, textContent:'', disabled:false, hidden:false, attributes:{}, classList:{toggle(){}}, setAttribute(k,v){this.attributes[k]=v}, addEventListener(e,f){this.listeners[e]=f}, append(n){this.children.push(n)}, replaceChildren(){this.children=[]}, querySelectorAll(){return []}}; }
  const document = {getElementById(id){if (!nodes.has(id)) nodes.set(id, node()); return nodes.get(id)}, createElement:node};
  const el = id => document.getElementById(id);
  async function api(endpoint, body, method) {
    const response = await fetch(`http://127.0.0.1:${UI}${endpoint}`, {method:method || (body ? 'POST' : 'GET'), ...(body ? {headers:{'content-type':'application/json'}, body:JSON.stringify(body)} : {})});
    if (!response.ok) throw Error(`Native request failed: ${response.status} ${endpoint}`);
    return response.status === 204 ? null : response.json();
  }
  try {
    await poll(async () => {try {return await api('/api/tcp/status')} catch (_) {return false}});
    const asset = await fetch(`http://127.0.0.1:${UI}/tcp-capture.js`);
    assert.equal(asset.status, 200);
    assert.equal(await asset.text(), fs.readFileSync(path.join(__dirname, '../web/tcp-capture.js'), 'utf8'), 'native binary must embed the current controller; rebuild before testing');
    await api('/api/tcp/start', {local_port:RELAY, target_host:'127.0.0.1', target_port:ECHO});
    const policy = await api('/api/tcp/intercept');
    await api('/api/tcp/intercept', {enabled:true, direction:'client_to_server', expected_revision:policy.revision}, 'PUT');
    const sid = (await api('/api/sessions')).find(session => session.active).id;
    const controller = tcp.createInterceptController({document, sessionId:() => sid,
      readPath:(endpoint,session) => endpoint + '?session_id=' + session,
      writePath:(endpoint,session) => endpoint + '?session_id=' + session + '&expected_active_session_id=' + session,
      request:async (endpoint,options) => {
        calls.push({endpoint, method:options?.method});
        if (failedRead && /\/pending\?/.test(endpoint)) {failedRead = false; return {ok:false, status:500};}
        if (staleDecision && /\/decision\?/.test(endpoint)) {
          staleDecision = false;
          const body = JSON.parse(options.body); body.expected_revision++;
          options = {...options, body:JSON.stringify(body)};
        }
        return fetch(`http://127.0.0.1:${UI}${endpoint}`, options);
      }});
    async function connect() {
      const socket = net.connect(RELAY, '127.0.0.1'); socket.received = [];
      socket.on('data', bytes => socket.received.push(bytes)); sockets.push(socket);
      await new Promise(resolve => socket.once('connect', resolve)); return socket;
    }
    const pending = async id => (await api(`/api/tcp/connections/${id}/pending`)).items[0];
    const connectionFor = socket => poll(async () => (await api('/api/tcp/connections')).find(record => record.peer.endsWith(':' + socket.localPort) && record.pending_count === 1));
    const aSocket = await connect(); aSocket.write(Buffer.from([0xaa]));
    const a = await connectionFor(aSocket), original = await pending(a.id);
    controller.setConnection(a); await controller.refresh();
    el('tcpPendingHex').value = 'bb'; el('tcpPendingHex').listeners.input();
    const bSocket = await connect(); bSocket.write(Buffer.from([1]));
    const b = await connectionFor(bSocket); controller.setConnection(b); await controller.refresh();
    for (let n = 0; n < 128; n++) {
      if (n) bSocket.write(Buffer.from([n % 256]));
      const item = await poll(() => pending(b.id)); await controller.refresh();
      el('tcpPendingPicker').value = item.pending_id; el('tcpPendingPicker').listeners.change();
      el('tcpPendingHex').value = 'cc'; el('tcpPendingHex').listeners.input();
      await api(`/api/tcp/connections/${b.id}/pending/${item.pending_id}/decision`, {action:'forward', expected_revision:item.revision});
      await poll(async () => !(await pending(b.id))); await controller.refresh();
    }
    assert.equal((await pending(a.id)).pending_id, original.pending_id);
    assert.equal(aSocket.received.length, 0, 'draft bytes remain unsent');
    controller.setConnection(a); await controller.refresh();
    assert.equal(el('tcpPendingHex').value, 'bb');
    failedRead = true; await controller.refresh();
    assert.equal(el('tcpPendingHex').value, 'bb'); assert.equal(el('tcpForward').disabled, true);
    await controller.refresh(); assert.equal(el('tcpPendingHex').value, 'bb');
    const before = calls.filter(call => call.method === 'POST').length;
    staleDecision = true; el('tcpForward').listeners.click();
    await poll(() => !el('tcpForward').disabled && /state changed/.test(el('tcpInterceptError').textContent));
    assert.equal(el('tcpPendingHex').value, 'bb'); assert.equal((await pending(a.id)).pending_id, original.pending_id);
    assert.equal(calls.filter(call => call.method === 'POST').length, before + 1, 'conflict never auto-retries');
    el('tcpForward').listeners.click();
    await poll(() => Buffer.concat(aSocket.received).length === 1);
    assert.equal(Buffer.concat(aSocket.received).toString('hex'), 'bb', 'server receives the retained edited byte');
    await poll(async () => !(await pending(a.id))); await controller.refresh();
    const evidence = {passed:true, binary, embeddedControllerMatches:true, fixture:root, connections:2, otherChunksReviewed:128,
      draftBefore:'bb', draftAfter:'bb', upstreamEcho:'bb', failedReadRetainedDraft:true,
      realRevisionConflictRetainedDraft:true, automaticRetries:0, apiCalls:calls.length};
    fs.writeFileSync(path.join(evidenceDir, 'native-drafts.json'), JSON.stringify(evidence, null, 2));
    console.log(JSON.stringify(evidence, null, 2));
  } finally {
    sockets.forEach(socket => socket.destroy());
    await api('/api/tcp/stop', {}, 'POST').catch(() => {});
    if (processHandle.exitCode === null && processHandle.signalCode === null) {
      const exited = new Promise(resolve => processHandle.once('exit', resolve)); processHandle.kill('SIGTERM'); await exited;
    }
    await new Promise(resolve => upstream.close(resolve)); fs.closeSync(log);
  }
})().catch(error => {console.error(error); process.exitCode = 1});
