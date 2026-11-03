// Offline synthetic controls and deferred fetches; no capture or runtime changes.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
const TOKEN_A = 'a'.repeat(64), TOKEN_B = 'b'.repeat(64);
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function control() { const classes = new Set(); return { checked: false, disabled: false, textContent: '', classList: { toggle(name, value) { value ? classes.add(name) : classes.delete(name); }, contains: (name) => classes.has(name) } }; }
function snapshot(enabled = false, token = TOKEN_A, blocked = null, extra = {}) {
  return { session_id: 'session-a', enabled, config_token: token, config_revision: token === TOKEN_A ? '0' : '1',
    status: { effective_enabled: enabled && blocked === null, blocked_reason: blocked }, ...extra };
}
function response(payload, status = 200) { return { ok: status < 400, status, json: async () => payload, text: async () => typeof payload === 'string' ? payload : 'rejected' }; }
function fixture() {
  const state = { activeSession: { id: 'session-a', name: 'Synthetic session A' } }, requests = [];
  const els = Object.fromEntries(['Section', 'Session', 'Enabled', 'Error', 'Status', 'Save', 'Cancel', 'Refresh'].map(key => [`upstreamPeer${key}`, control()]));
  const names = ['upstreamPeerSettingsState', 'validateUpstreamPeerSnapshot', 'validateUpstreamPeerAcknowledgement', 'adoptUpstreamPeerSnapshot', 'loadUpstreamPeerSettings', 'editUpstreamPeerSettings', 'cancelUpstreamPeerSettings', 'saveUpstreamPeerSettings', 'renderUpstreamPeerSettings'];
  const context = loadFunctions(names, { state, els, workspaceStateGeneration: 0,
    currentSessionId: () => state.activeSession?.id || null,
    sessionQueryPath: (url, id) => `${url}?session_id=${id}`,
    sessionWritePath: (url, id) => `${url}?session_id=${id}&expected_active_session_id=${id}`,
    async requireOkResponse(res) { if (!res.ok) throw new Error(await res.text()); },
    fetch(url, options) { const request = { url, options, ...deferred() }; requests.push(request); return request.promise; },
  });
  async function load(payload = snapshot()) { const promise = context.loadUpstreamPeerSettings(); requests.at(-1).resolve(response(payload)); await promise; }
  function edit(enabled = true) { els.upstreamPeerEnabled.checked = enabled; context.editUpstreamPeerSettings(); }
  function move(id) { state.activeSession = { id, name: `Synthetic ${id}` }; context.workspaceStateGeneration += 1; context.renderUpstreamPeerSettings(); }
  return { context, state, els, requests, load, edit, move };
}
test('card is independent, default Off, disclosed and absent from the compact Scope strip', () => {
  const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  const start = html.indexOf('id="proxySettingsPanel"'), end = html.indexOf('id="replayShell"');
  const section = html.slice(start, end);
  // Off by default is checked below; the disclosure keeps what is stored, that
  // it may not be the origin, where it goes, and that turning it off keeps it.
  assert.match(section, /Upstream socket peer/); assert.match(section, /<span>Record upstream socket peer<\/span>/);
  assert.match(section, /upstream IP address and port with new HTTP\(S\) exchanges/);
  assert.match(section, /internal or proxy address rather than the origin/); assert.match(section, /session exports and full-record JSON/);
  assert.match(section, /stay when this is turned off/);
  assert.match(section, /id="upstreamPeerStatus" role="status" aria-live="polite"/);
  assert.match(section, /id="upstreamPeerRefresh" type="button">Check status/);
  const saveRuntime = appSource.match(/^async function saveProxySettings\([^]*?^\}/m)[0];
  assert.doesNotMatch(saveRuntime, /upstreamPeer|upstream.peer|socket.peer/);
  assert.match(appSource, /state.upstreamPeerSettings = null/);
});
test('initial, saved Off and editing make no writes; card has own Save and hidden recovery', async () => {
  const f = fixture(); f.context.renderUpstreamPeerSettings();
  assert.equal(f.els.upstreamPeerEnabled.checked, false); assert.equal(f.els.upstreamPeerEnabled.disabled, true);
  assert.equal(f.requests.length, 0); await f.load(); f.edit();
  assert.equal(f.requests.length, 1); assert.equal(f.els.upstreamPeerSession.textContent, 'Synthetic session A');
  assert.equal(f.els.upstreamPeerRefresh.classList.contains('hidden'), true);
  assert.match(f.els.upstreamPeerStatus.textContent, /Saved setting: Off.*Unsaved changes/);
});
test('explicit Save uses only exact boolean and token, pins active session, and validates acknowledgement', async () => {
  const f = fixture(); await f.load(); f.edit();
  const saving = f.context.saveUpstreamPeerSettings(), request = f.requests.at(-1);
  assert.equal(request.url, '/api/transactions/upstream-peer-settings?session_id=session-a&expected_active_session_id=session-a');
  assert.deepEqual(JSON.parse(request.options.body), { enabled: true, expected_config_token: TOKEN_A });
  assert.equal(await f.context.saveUpstreamPeerSettings(), false);
  request.resolve(response(snapshot(true, TOKEN_B, 'http_capture_paused', { changed: true })));
  assert.equal(await saving, true); assert.equal(f.state.upstreamPeerSettings.dirty, false);
  assert.match(f.els.upstreamPeerStatus.textContent, /HTTP capture is paused/);
  assert.match(f.els.upstreamPeerStatus.textContent, /Setting saved/);
  assert.equal(f.requests.length, 2);
});
for (const code of [500, 503, 'network', 'bad-ack']) test(`unknown ${code} save keeps draft, needs explicit check, never auto retries`, async () => {
  const f = fixture(); await f.load(); f.edit(); const saving = f.context.saveUpstreamPeerSettings();
  if (code === 'network') f.requests.at(-1).reject(new Error('Synthetic connection lost'));
  else f.requests.at(-1).resolve(response(code === 'bad-ack' ? snapshot(true, TOKEN_B, null, { changed: false }) : {}, typeof code === 'number' ? code : 200));
  assert.equal(await saving, false); assert.equal(f.requests.length, 2);
  assert.ok(f.state.upstreamPeerSettings.uncertain); assert.equal(f.els.upstreamPeerSave.disabled, true);
  assert.equal(f.els.upstreamPeerRefresh.classList.contains('hidden'), false);
  assert.doesNotMatch(f.els.upstreamPeerStatus.textContent, /Setting saved/);
  assert.equal(await f.context.saveUpstreamPeerSettings(), false); assert.equal(f.requests.length, 2);
  await f.load(snapshot(true, TOKEN_B, 'persistence_uncertain'));
  assert.equal(f.state.upstreamPeerSettings.uncertain, null);
  assert.match(f.els.upstreamPeerStatus.textContent, /Storage is unconfirmed/);
  assert.doesNotMatch(f.els.upstreamPeerStatus.textContent, /Setting saved|Saved setting: On/);
  assert.equal(f.els.upstreamPeerSave.disabled, false); assert.equal(f.els.upstreamPeerSave.textContent, 'Retry save');
  const retry = f.context.saveUpstreamPeerSettings();
  assert.deepEqual(JSON.parse(f.requests.at(-1).options.body), { enabled: true, expected_config_token: TOKEN_B });
  f.requests.at(-1).resolve(response(snapshot(true, TOKEN_B, null, { changed: false })));
  assert.equal(await retry, true); assert.match(f.els.upstreamPeerStatus.textContent, /Setting saved/);
});
test('known prewrite persistence failure can check unchanged Off then explicitly retry the retained On draft', async () => {
  const f = fixture(); await f.load(); f.edit(); const saving = f.context.saveUpstreamPeerSettings();
  f.requests.at(-1).resolve(response({}, 500)); await saving;
  await f.load(snapshot(false, TOKEN_A, 'persistence_uncertain'));
  assert.equal(f.state.upstreamPeerSettings.draft, true); assert.equal(f.state.upstreamPeerSettings.dirty, true);
  assert.equal(f.els.upstreamPeerSave.disabled, false);
});
test('Cancel and newer edits during a delayed save are not overwritten by its successful acknowledgement', async () => {
  const f = fixture(); await f.load(); f.edit(); const saving = f.context.saveUpstreamPeerSettings();
  f.context.cancelUpstreamPeerSettings(); assert.equal(f.state.upstreamPeerSettings.draft, false);
  f.requests.at(-1).resolve(response(snapshot(true, TOKEN_B, null, { changed: true }))); await saving;
  assert.equal(f.state.upstreamPeerSettings.draft, false); assert.equal(f.state.upstreamPeerSettings.saved.enabled, true);
  assert.equal(f.state.upstreamPeerSettings.dirty, true); assert.equal(f.els.upstreamPeerSave.disabled, false);
});
test('Cancel during unknown outcome stays pending until Check and preserves newer draft', async () => {
  const f = fixture(); await f.load(); f.edit(); const saving = f.context.saveUpstreamPeerSettings();
  f.requests.at(-1).reject(new Error('Synthetic disconnect')); await saving; f.context.cancelUpstreamPeerSettings();
  assert.ok(f.state.upstreamPeerSettings.uncertain); assert.equal(f.els.upstreamPeerSave.disabled, true);
  await f.load(snapshot(true, TOKEN_B));
  assert.equal(f.state.upstreamPeerSettings.draft, false); assert.equal(f.state.upstreamPeerSettings.dirty, true);
  assert.doesNotMatch(f.els.upstreamPeerStatus.textContent, /Setting saved/);
});
test('409 stays fenced until checked and cancelled; rechecking does not silently rebase a dirty draft', async () => {
  const f = fixture(); await f.load(); f.edit(); const saving = f.context.saveUpstreamPeerSettings();
  f.requests.at(-1).resolve(response({}, 409)); await saving;
  assert.equal(f.state.upstreamPeerSettings.writeConflict, true); assert.equal(f.requests.length, 2);
  await f.load(snapshot(true, TOKEN_B));
  assert.equal(f.els.upstreamPeerSave.disabled, true); assert.equal(f.state.upstreamPeerSettings.baselineToken, TOKEN_A);
  f.context.cancelUpstreamPeerSettings();
  assert.equal(f.state.upstreamPeerSettings.baselineToken, TOKEN_B); assert.equal(f.state.upstreamPeerSettings.draft, true);
  assert.equal(f.state.upstreamPeerSettings.conflict, false);
});
for (const status of [400, 428]) test(`known ${status} rejection preserves draft without claiming uncertainty or success`, async () => {
  const f = fixture(); await f.load(); f.edit(); const saving = f.context.saveUpstreamPeerSettings();
  f.requests.at(-1).resolve(response('Synthetic request rejected', status)); await saving;
  assert.equal(f.state.upstreamPeerSettings.uncertain, null); assert.equal(f.state.upstreamPeerSettings.draft, true);
  assert.match(f.els.upstreamPeerStatus.textContent, /Setting was not saved/);
});
for (const kind of ['read', 'write']) test(`${kind} result from session A cannot survive A to B to A or workspace reload`, async () => {
  const f = fixture(); await f.load(); f.edit();
  const pending = kind === 'read' ? f.context.loadUpstreamPeerSettings() : f.context.saveUpstreamPeerSettings();
  const old = f.requests.at(-1); f.move('session-b'); f.move('session-a');
  await f.load(snapshot(false));
  old.resolve(response(snapshot(true, TOKEN_B, null, { changed: true }))); assert.equal(await pending, false);
  assert.equal(f.state.upstreamPeerSettings.saved.enabled, false); assert.equal(f.state.upstreamPeerSettings.draft, false);
  assert.doesNotMatch(f.els.upstreamPeerStatus.textContent, /Setting saved/);
});
test('overlapping reads use ownership and do not clobber a newer edit', async () => {
  const f = fixture(); await f.load(); const a = f.context.loadUpstreamPeerSettings(), old = f.requests.at(-1);
  const b = f.context.loadUpstreamPeerSettings(), newer = f.requests.at(-1); f.edit();
  newer.resolve(response(snapshot())); await b; old.resolve(response(snapshot(true, TOKEN_B))); await a;
  assert.equal(f.state.upstreamPeerSettings.saved.enabled, false); assert.equal(f.state.upstreamPeerSettings.draft, true);
});
test('inactive read and invalid configuration cannot enable controls or mutate settings', async () => {
  const f = fixture(); const load = f.context.loadUpstreamPeerSettings(); f.requests.at(-1).resolve(response({}, 409)); await load;
  assert.equal(f.els.upstreamPeerEnabled.disabled, true); assert.equal(f.els.upstreamPeerRefresh.classList.contains('hidden'), false);
  await f.load(snapshot(false, TOKEN_A, 'invalid_configuration')); assert.equal(f.els.upstreamPeerEnabled.disabled, true);
  f.edit(); assert.equal(await f.context.saveUpstreamPeerSettings(), false); assert.equal(f.requests.length, 2);
});
test('saved false durability no-op retry is available without enabling capture', async () => {
  const f = fixture(); await f.load(snapshot(false, TOKEN_A, 'persistence_uncertain'));
  const saving = f.context.saveUpstreamPeerSettings();
  assert.deepEqual(JSON.parse(f.requests.at(-1).options.body), { enabled: false, expected_config_token: TOKEN_A });
  f.requests.at(-1).resolve(response(snapshot(false, TOKEN_A, null, { changed: false }))); assert.equal(await saving, true);
});
for (const patch of [{ enabled: 'true' }, { config_revision: 1 }, { config_revision: '01' }, { config_revision: '18446744073709551616' }, { config_token: '' }, { session_id: 'other' }, { status: { effective_enabled: true, blocked_reason: null } }, { status: { effective_enabled: false, blocked_reason: 'unknown' } }]) test(`malformed snapshot rejected: ${JSON.stringify(patch)}`, async () => {
  const f = fixture(); await f.load({ ...snapshot(), ...patch }); assert.equal(f.state.upstreamPeerSettings.saved, null); assert.equal(f.els.upstreamPeerEnabled.disabled, true);
});
test('failed or inactive later reads cannot leave a previously loaded draft saveable', async () => {
  const f = fixture(); await f.load(); f.edit(); const read = f.context.loadUpstreamPeerSettings();
  f.requests.at(-1).resolve(response({}, 409)); await read;
  assert.equal(f.state.upstreamPeerSettings.readFailed, true); assert.equal(f.state.upstreamPeerSettings.writeConflict, true);
  assert.equal(f.els.upstreamPeerSave.disabled, true); assert.equal(await f.context.saveUpstreamPeerSettings(), false);
  f.context.cancelUpstreamPeerSettings(); f.edit(); assert.equal(f.els.upstreamPeerSave.disabled, true);
  await f.load(); assert.equal(f.state.upstreamPeerSettings.readFailed, false); assert.equal(f.els.upstreamPeerSave.disabled, false);
});

test('inconsistent effective false with enabled true and no reason is rejected on GET and successful-looking POST', async () => {
  const f = fixture();
  const inconsistent = { ...snapshot(true), status: { effective_enabled: false, blocked_reason: null } };
  await f.load(inconsistent); assert.equal(f.state.upstreamPeerSettings.saved, null);
  await f.load(); f.edit(); const saving = f.context.saveUpstreamPeerSettings();
  f.requests.at(-1).resolve(response({ ...inconsistent, config_token: TOKEN_B, config_revision: '1', changed: true }));
  assert.equal(await saving, false); assert.ok(f.state.upstreamPeerSettings.uncertain);
  assert.equal(f.state.upstreamPeerSettings.saved.enabled, false);
  assert.doesNotMatch(f.els.upstreamPeerStatus.textContent, /Setting saved/);
});
test('Cancel after POST 409 cannot make a dirty draft saveable without a fresh successful status check', async () => {
  const f = fixture(); await f.load(); f.edit(); const saving = f.context.saveUpstreamPeerSettings();
  f.requests.at(-1).resolve(response({}, 409)); await saving;
  f.context.cancelUpstreamPeerSettings(); f.edit();
  assert.equal(f.state.upstreamPeerSettings.readFailed, true);
  assert.equal(f.els.upstreamPeerRefresh.classList.contains('hidden'), false);
  assert.equal(f.els.upstreamPeerSave.disabled, true);
  assert.equal(await f.context.saveUpstreamPeerSettings(), false); assert.equal(f.requests.length, 2);
  await f.load(); assert.equal(f.state.upstreamPeerSettings.readFailed, false);
  assert.equal(f.els.upstreamPeerSave.disabled, false);
});
test('exhausted configuration is disabled with honest copy and no suggested reset or repair', async () => {
  const f = fixture(); await f.load(snapshot(true, TOKEN_A, 'invalid_configuration', { config_revision: '18446744073709551615' }));
  assert.equal(f.els.upstreamPeerEnabled.disabled, true); assert.equal(f.els.upstreamPeerSave.disabled, true);
  assert.match(f.els.upstreamPeerStatus.textContent, /invalid or exhausted/);
  assert.match(f.els.upstreamPeerStatus.textContent, /Peer recording is off/);
  assert.doesNotMatch(f.els.upstreamPeerStatus.textContent, /repair|reset/i);
});

for (const token of ['opaque-token', 'a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), 'g'.repeat(64)]) test(`malformed config token is rejected on read and cannot acknowledge a save: ${token.slice(0, 16)}/${token.length}`, async () => {
  const f = fixture(); await f.load(snapshot(false, token)); assert.equal(f.state.upstreamPeerSettings.saved, null);
  await f.load(); f.edit(); const saving = f.context.saveUpstreamPeerSettings();
  f.requests.at(-1).resolve(response(snapshot(true, token, null, { changed: true })));
  assert.equal(await saving, false); assert.ok(f.state.upstreamPeerSettings.uncertain);
  assert.doesNotMatch(f.els.upstreamPeerStatus.textContent, /Setting saved/);
});

test('verification guidance remains visible after conflict Cancel and a newer checkbox edit', async () => {
  const f = fixture(); await f.load(); f.edit(); const saving = f.context.saveUpstreamPeerSettings();
  f.requests.at(-1).resolve(response({}, 409)); await saving;
  f.context.cancelUpstreamPeerSettings();
  assert.match(f.els.upstreamPeerStatus.textContent, /Check status before saving/);
  f.edit(); assert.equal(f.els.upstreamPeerSave.disabled, true);
  assert.match(f.els.upstreamPeerStatus.textContent, /Check status before saving\./);
  assert.equal(f.els.upstreamPeerRefresh.classList.contains('hidden'), false);
  assert.equal(f.requests.length, 2);
});
