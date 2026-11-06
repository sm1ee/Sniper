// node tests/tcp-settings-recovery-runtime.cjs [rebuilt-binary] [evidence-directory]
const fs = require('node:fs'), net = require('node:net'), cp = require('node:child_process');
const path = require('node:path'), os = require('node:os'), assert = require('node:assert/strict');
const tcp = require('../web/tcp-capture.js');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
async function poll(fn) {
  for (let i = 0; i < 300; i++) { const value = await fn(); if (value) return value; await pause(20); }
  throw Error('Timed out waiting for native listener state');
}
async function listen(port = 0) {
  const server = net.createServer();
  await new Promise((resolve, reject) => {server.once('error', reject); server.listen(port, '127.0.0.1', resolve);});
  return server;
}
async function close(server) { if (server?.listening) await new Promise(resolve => server.close(resolve)); }
async function unusedPort() { const server = await listen(), port = server.address().port; await close(server); return port; }
function fixture(base, sid) {
  const nodes = new Map(), calls = [];
  const node = () => ({value:'', children:[], dataset:{}, listeners:{}, textContent:'', disabled:false,
    classList:{toggle(){}}, setAttribute(){}, addEventListener(event, fn){this.listeners[event] = fn;},
    append(child){this.children.push(child);}, replaceChildren(){this.children = [];}, querySelectorAll(){return [];}});
  const document = {getElementById(id){if (!nodes.has(id)) nodes.set(id, node()); return nodes.get(id);}, createElement:node};
  const get = id => document.getElementById(id);
  get('tcpStateFilter').value = 'all'; get('tcpDirection').value = 'client_to_server';
  const f = {get, calls, conflictWrites:false};
  f.controller = tcp.createController({document, sessionId:() => sid,
    readPath:(p, s) => p + '?session_id=' + s,
    writePath:(p, s) => p + '?session_id=' + s + '&expected_active_session_id=' + (f.conflictWrites ? '00000000-0000-4000-8000-000000000000' : s),
    request:(p, options) => { calls.push({path:p, method:options?.method}); return fetch(base + p, options); }, openSettings(){}});
  return f;
}
function submit(f, local, target = 1, host = '127.0.0.1') {
  f.get('tcpLocalPort').value = String(local); f.get('tcpTargetHost').value = host; f.get('tcpTargetPort').value = String(target);
  f.get('tcpListenerForm').listeners.submit({preventDefault(){}});
}
const state = f => ({status:f.get('tcpListenerStatus').textContent, error:f.get('tcpSettingsError').textContent,
  startDisabled:f.get('tcpStart').disabled, stopDisabled:f.get('tcpStop').disabled});
(async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tcp-settings-recovery-'));
  const evidence = path.resolve(process.argv[3] || root); fs.mkdirSync(evidence, {recursive:true});
  fs.mkdirSync(path.join(root, 'templates')); fs.writeFileSync(path.join(root, 'templates/templates.json'), '{"auto_update":false}');
  const UI = await unusedPort(), PROXY = await unusedPort();
  let occupied = await listen(); const local = occupied.address().port;
  const binary = path.resolve(process.argv[2] || 'target/release/sniper');
  const log = fs.openSync(path.join(evidence, 'native-settings.log'), 'w');
  const proc = cp.spawn(binary, [], {stdio:['ignore', log, log], env:{...process.env,
    SNIPER_INSTALL_AGENT_SKILLS:'0', SNIPER_INSTALL_CLI_PATH:'0', SNIPER_DATA_DIR:root,
    SNIPER_UI_ADDR:`127.0.0.1:${UI}`, SNIPER_PROXY_ADDR:`127.0.0.1:${PROXY}`, RUST_LOG:'warn'}});
  const base = `http://127.0.0.1:${UI}`;
  async function stop(f) {
    f.get('tcpStop').listeners.click();
    await poll(() => f.get('tcpListenerStatus').textContent === 'Stopped' && !f.get('tcpStart').disabled);
  }
  async function start(f, target = 1, host = '127.0.0.1') {
    await f.controller.refresh(); submit(f, local, target, host);
    await poll(() => f.get('tcpListenerStatus').textContent.startsWith('Listening') && !f.get('tcpStop').disabled);
  }
  try {
    await poll(async () => {try {return (await fetch(base + '/api/tcp/status')).ok;} catch (_) {return false;}});
    assert.equal(await (await fetch(base + '/tcp-capture.js')).text(), fs.readFileSync(path.join(__dirname, '../web/tcp-capture.js'), 'utf8'));
    const sid = (await (await fetch(base + '/api/sessions')).json()).find(s => s.active).id;
    const a = fixture(base, sid), b = fixture(base, sid);
    await Promise.all([a.controller.refresh(), b.controller.refresh()]);
    submit(a, local);
    await poll(() => a.get('tcpSettingsError').textContent.includes('already in use') && !a.get('tcpStart').disabled);
    const before = state(a);
    a.get('tcpTargetHost').value = 'draft.example.com'; a.get('tcpTargetPort').value = '3x';
    for (let i = 0; i < 3; i++) await a.controller.refresh();
    assert.equal(a.get('tcpTargetHost').value, 'draft.example.com'); assert.equal(a.get('tcpTargetPort').value, '3x');
    assert.equal(a.get('tcpSettingsError').textContent, before.error);
    await close(occupied); occupied = null;
    await start(b); await a.controller.refresh();
    const after = state(a);
    assert.match(after.status, /Listening/); assert.equal(after.error, '');
    assert.equal(after.startDisabled, true); assert.equal(after.stopDisabled, false);
    for (let i = 0; i < 3; i++) await a.controller.refresh();
    assert.equal(a.get('tcpSettingsError').textContent, '');
    assert.equal(a.calls.filter(call => call.method === 'POST').length, 1, 'window A never automatically retries');

    await stop(b); await a.controller.refresh(); occupied = await listen(local);
    submit(a, local); await poll(() => a.get('tcpSettingsError').textContent.includes('already in use') && !a.get('tcpStart').disabled);
    await close(occupied); occupied = null;
    await start(b, 2); await a.controller.refresh();
    assert.match(a.get('tcpSettingsError').textContent, /already in use/, 'a different target does not recover the original Start');
    await stop(b); await a.controller.refresh();
    await start(b); await a.controller.refresh();
    assert.equal(a.get('tcpSettingsError').textContent, '', 'matching original settings clear despite an intervening different listener');

    await stop(b); await a.controller.refresh(); a.conflictWrites = true;
    submit(a, local); await poll(() => a.get('tcpSettingsError').textContent.includes('409') && !a.get('tcpStart').disabled);
    await start(b); await a.controller.refresh();
    assert.match(a.get('tcpSettingsError').textContent, /409/, 'authoritative running status cannot dismiss a session conflict');
    await stop(b); await a.controller.refresh(); a.conflictWrites = false;
    const writes = a.calls.filter(call => call.method === 'POST').length;
    submit(a, local, '3x'); assert.match(a.get('tcpSettingsError').textContent, /whole numbers/);
    await start(b); await a.controller.refresh();
    assert.match(a.get('tcpSettingsError').textContent, /whole numbers/);
    assert.equal(a.calls.filter(call => call.method === 'POST').length, writes);
    await stop(b);
    await a.controller.refresh(); occupied = await listen(local);
    submit(a, local, 1, '::ffff:127.0.0.1');
    await poll(() => a.get('tcpSettingsError').textContent.includes('already in use') && !a.get('tcpStart').disabled);
    await close(occupied); occupied = null;
    await start(b, 1, '::ffff:7f00:1'); await a.controller.refresh();
    assert.equal(a.get('tcpTargetHost').value, '::ffff:127.0.0.1', 'native status uses Rust mapped-IPv6 spelling');
    assert.equal(a.get('tcpSettingsError').textContent, '', 'equivalent mapped-IPv6 spelling must recover');
    await stop(b);
    const result = {passed:true, binary, isolatedDataDirectory:root, servedControllerMatchesSource:true,
      twoIndependentControllers:true, before, after, repeatedPolls:3, stoppedDirtyFormPreserved:true,
      mismatchedTargetErrorRetained:true, realSessionConflictRetained:true, validationErrorRetained:true, mappedIpv6Recovery:true, automaticRetries:0};
    fs.writeFileSync(path.join(evidence, 'native-settings.json'), JSON.stringify(result, null, 2));
    console.log(JSON.stringify(result, null, 2));
  } finally {
    await close(occupied);
    if (proc.exitCode === null && proc.signalCode === null) {
      const exited = new Promise(resolve => proc.once('exit', resolve)); proc.kill('SIGTERM'); await exited;
    }
    fs.closeSync(log);
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
