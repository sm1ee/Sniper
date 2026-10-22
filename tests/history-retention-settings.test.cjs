// Offline settings contracts: extracted handlers, synthetic controls, and fetch.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');
const TOKEN_A = 'a'.repeat(64), TOKEN_B = 'b'.repeat(64);
const tick = () => new Promise((resolve) => setImmediate(resolve));
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function control() {
  const classes = new Set();
  return { checked: false, disabled: false, value: '', textContent: '', attributes: {},
    classList: { toggle(name, value) { if (value) classes.add(name); else classes.delete(name); }, contains: (name) => classes.has(name) },
    setAttribute(key, value) { this.attributes[key] = value; }, focus() { this.focused = true; } };
}
function snapshot(policy = { mode: 'off' }, token = TOKEN_A, extra = {}) {
  return { session_id: 'session-a', config_token: token, config_revision: token === TOKEN_A ? "0" : "1", policy, changed: token !== TOKEN_A,
    status: { total_count: 12000, protected_count: 1, pending: false, blocked_reason: null, disk_cleanup_pending: false, ...extra } };
}
function response(payload, status = 200) { return { ok: status < 400, status, json: async () => payload, text: async () => typeof payload === 'string' ? payload : 'rejected' }; }
function fixture() {
  const state = { activeSession: { id: 'session-a', name: 'Fixture session' } }, requests = [];
  const els = Object.fromEntries(['Section', 'Session', 'Enabled', 'Preset', 'Custom', 'CustomField', 'Error', 'Status', 'Save', 'Cancel', 'Refresh'].map((key) => [`historyRetention${key}`, control()]));
  const names = ['historyRetentionSettingsState', 'historyRetentionDraftFromPolicy', 'historyRetentionPolicyFromDraft', 'validateHistoryRetentionSnapshot', 'validateHistoryRetentionAcknowledgement', 'historyRetentionDraftIsDirty', 'adoptHistoryRetentionSnapshot', 'loadHistoryRetentionSettings', 'editHistoryRetentionSettings', 'cancelHistoryRetentionSettings', 'saveHistoryRetentionSettings', 'renderHistoryRetentionSettings'];
  const context = loadFunctions(names, { state, els, workspaceStateGeneration: 0,
    currentSessionId: () => state.activeSession?.id || null,
    sessionQueryPath: (url, id) => `${url}?session_id=${id}`,
    sessionWritePath: (url, id) => `${url}?session_id=${id}&expected_active_session_id=${id}`,
    async requireOkResponse(res) { if (!res.ok) throw new Error(await res.text()); },
    fetch(url, options) { const request = { url, options, ...deferred() }; requests.push(request); return request.promise; },
  });
  async function load(payload = snapshot()) { const promise = context.loadHistoryRetentionSettings(); requests.at(-1).resolve(response(payload)); await promise; }
  function edit(mode = 'keep_newest', preset = '10000', custom = '') { els.historyRetentionEnabled.checked = mode === 'keep_newest'; els.historyRetentionPreset.value = preset; els.historyRetentionCustom.value = custom; context.editHistoryRetentionSettings(); }
  return { context, state, els, requests, load, edit };
}

test('cleanup section is in Capture Settings with independent native labels and irreversible warning', () => {
  const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  const section = html.slice(html.indexOf('id="proxySettingsPanel"'), html.indexOf('id="proxySubPlaceholder"'));
  assert.match(section, /HTTP History automatic cleanup/);
  assert.match(section, /<fieldset[^>]*aria-describedby="historyRetentionWarning historyRetentionProtection"/);
  assert.match(section, /<legend>Saved HTTP History limit<\/legend>/);
  assert.match(section, /permanently deletes the oldest unprotected entries above the total target/);
  assert.match(section, /Original records referenced by durably saved HTTP tabs and in-progress stored records are protected/);
  assert.match(section, /Unsaved tabs and note edits do not protect records/);
  assert.match(section, /id="historyRetentionStatus" role="status" aria-live="polite"/);
  assert.match(section, /id="historyRetentionCustom"[^>]*aria-describedby="historyRetentionCustomHelp historyRetentionError"/);
  assert.match(section, /id="historyRetentionCancel" type="button"/);
  const settingsSave = appSource.slice(appSource.indexOf('async function saveProxySettings('), appSource.indexOf('function renderProxySettings('));
  assert.doesNotMatch(settingsSave, /await saveHistoryRetentionSettings\(/);
});

test('initial and saved default Off do not write; session is named', async () => {
  const f = fixture();
  f.context.renderHistoryRetentionSettings();
  assert.equal(f.els.historyRetentionEnabled.checked, false);
  assert.equal(f.els.historyRetentionEnabled.disabled, true);
  assert.equal(f.requests.length, 0);
  await f.load();
  assert.equal(f.els.historyRetentionSession.textContent, 'Fixture session');
  assert.equal(f.els.historyRetentionSave.disabled, true);
  assert.match(f.els.historyRetentionStatus.textContent, /Saved policy: Off/);
});

for (const value of ['10000', '50000', '100000', '250000', '1', '4294967295', '12345']) {
  test(`explicit Save submits exact preset/custom total ${value} and pinned CAS`, async () => {
    const f = fixture(); await f.load();
    const custom = !['10000', '50000', '100000', '250000'].includes(value);
    f.edit('keep_newest', custom ? 'custom' : value, custom ? value : '');
    assert.equal(f.requests.length, 1, 'editing does not autosave');
    const saving = f.context.saveHistoryRetentionSettings();
    const request = f.requests.at(-1);
    assert.equal(request.options.method, 'POST');
    assert.equal(request.url, '/api/transactions/retention?session_id=session-a&expected_active_session_id=session-a');
    assert.deepEqual(JSON.parse(request.options.body), { expected_config_token: TOKEN_A, policy: { mode: 'keep_newest', max_entries: Number(value) } });
    request.resolve(response({ ...snapshot({ mode: 'keep_newest', max_entries: Number(value) }, TOKEN_B, { pending: true }), changed: true }));
    assert.equal(await saving, true);
    assert.equal(f.state.historyRetentionSettings.dirty, false);
    assert.match(f.els.historyRetentionStatus.textContent, /Policy saved. Cleanup runs in the background/);
    assert.match(f.els.historyRetentionStatus.textContent, /Cleanup pending/);
    assert.doesNotMatch(f.els.historyRetentionStatus.textContent, /deleted.*12,000|cleanup complete/i);
  });
}

for (const value of ['', '0', '-1', '1.2', '1e4', '0x10', 'Infinity', 'NaN', '4294967296', ' 12', '12 ', '+1', '1,000', '１２']) {
  test(`custom invalid input ${JSON.stringify(value)} never sends a write`, async () => {
    const f = fixture(); await f.load(); f.edit('keep_newest', 'custom', value);
    assert.equal(f.els.historyRetentionSave.disabled, true);
    assert.equal(f.els.historyRetentionCustom.attributes['aria-invalid'], 'true');
    assert.equal(await f.context.saveHistoryRetentionSettings(), false);
    assert.equal(f.requests.length, 1);
    assert.match(f.els.historyRetentionError.textContent, /whole number/);
  });
}

test('Off explicitly saves only on Save; Cancel never writes', async () => {
  const f = fixture(); await f.load(snapshot({ mode: 'keep_newest', max_entries: 50000 }));
  f.edit('off', '50000'); f.context.cancelHistoryRetentionSettings();
  assert.equal(f.els.historyRetentionEnabled.checked, true);
  assert.equal(f.requests.length, 1);
  f.edit('off', '50000'); const saving = f.context.saveHistoryRetentionSettings();
  assert.deepEqual(JSON.parse(f.requests.at(-1).options.body).policy, { mode: 'off' });
  f.requests.at(-1).resolve(response(snapshot({ mode: 'off' }, TOKEN_B))); await saving;
  assert.equal(f.els.historyRetentionEnabled.checked, false);
});

test('background read and render preserve a dirty custom draft and its original CAS baseline', async () => {
  const f = fixture(); await f.load(); f.edit('keep_newest', 'custom', '12345');
  f.context.renderHistoryRetentionSettings();
  await f.load(snapshot({ mode: 'off' }, TOKEN_A, { total_count: 13000 }));
  assert.equal(f.els.historyRetentionCustom.value, '12345');
  assert.equal(f.state.historyRetentionSettings.dirty, true);
  await f.load(snapshot({ mode: 'keep_newest', max_entries: 50000 }, TOKEN_B));
  assert.equal(f.state.historyRetentionSettings.baselineToken, TOKEN_A);
  assert.equal(f.state.historyRetentionSettings.conflict, true);
  assert.equal(f.els.historyRetentionCustom.value, '12345');
  assert.equal(f.els.historyRetentionSave.disabled, true);
  f.context.cancelHistoryRetentionSettings();
  assert.equal(f.els.historyRetentionPreset.value, '50000');
  assert.equal(f.state.historyRetentionSettings.baselineToken, TOKEN_B);
});

test('a newer draft or Cancel while Save is pending is not overwritten by its acknowledgement', async () => {
  for (const cancel of [false, true]) {
    const f = fixture(); await f.load(); f.edit('keep_newest', '10000');
    const saving = f.context.saveHistoryRetentionSettings(); const request = f.requests.at(-1);
    if (cancel) f.context.cancelHistoryRetentionSettings(); else f.edit('keep_newest', 'custom', '12345');
    request.resolve(response(snapshot({ mode: 'keep_newest', max_entries: 10000 }, TOKEN_B))); await saving;
    assert.equal(f.state.historyRetentionSettings.dirty, true);
    assert.equal(f.state.historyRetentionSettings.baselineToken, TOKEN_B);
    assert.equal(f.els.historyRetentionEnabled.checked, !cancel);
    if (!cancel) assert.equal(f.els.historyRetentionCustom.value, '12345');
  }
});

for (const sameSession of [false, true]) {
  test(`session reset drops old reads and writes (${sameSession ? 'same ID generation' : 'different ID'})`, async () => {
    const f = fixture(); await f.load(); f.edit('keep_newest', '10000');
    const saving = f.context.saveHistoryRetentionSettings(); const request = f.requests.at(-1);
    f.context.workspaceStateGeneration += 1;
    f.state.historyRetentionSettings = null;
    if (!sameSession) f.state.activeSession = { id: 'session-b', name: 'Other session' };
    f.context.renderHistoryRetentionSettings();
    request.resolve(response(snapshot({ mode: 'keep_newest', max_entries: 10000 }, TOKEN_B)));
    assert.equal(await saving, false);
    assert.equal(f.els.historyRetentionEnabled.checked, false);
    assert.equal(f.state.historyRetentionSettings.saved, null);
    const loading = f.context.loadHistoryRetentionSettings(); const read = f.requests.at(-1);
    f.context.workspaceStateGeneration += 1; f.state.historyRetentionSettings = null;
    read.resolve(response({ ...snapshot(), session_id: f.state.activeSession.id }));
    assert.equal(await loading, false);
    assert.equal(f.state.historyRetentionSettings, null);
  });
}

test('a superseded read cannot overwrite the newer read', async () => {
  const f = fixture(); const first = f.context.loadHistoryRetentionSettings(); const older = f.requests.at(-1);
  const second = f.context.loadHistoryRetentionSettings(); const newer = f.requests.at(-1);
  newer.resolve(response(snapshot({ mode: 'keep_newest', max_entries: 50000 }, TOKEN_B))); await second;
  older.resolve(response(snapshot())); assert.equal(await first, false);
  assert.equal(f.els.historyRetentionPreset.value, '50000');
});

test('409 keeps draft and reads status without retrying; Cancel adopts latest', async () => {
  const f = fixture(); await f.load(); f.edit('keep_newest', '10000');
  const saving = f.context.saveHistoryRetentionSettings(); f.requests.at(-1).resolve(response('stale token', 409));
  await tick(); assert.equal(f.requests.at(-1).options, undefined);
  f.requests.at(-1).resolve(response(snapshot({ mode: 'keep_newest', max_entries: 50000 }, TOKEN_B)));
  assert.equal(await saving, false);
  assert.equal(f.els.historyRetentionPreset.value, '10000');
  assert.equal(f.state.historyRetentionSettings.conflict, true);
  assert.equal(f.requests.filter((r) => r.options).length, 1);
  f.context.cancelHistoryRetentionSettings(); assert.equal(f.els.historyRetentionPreset.value, '50000');
});

for (const matched of [false, true]) {
  test(`unknown write outcome is verified by GET, never retried (matched=${matched})`, async () => {
    const f = fixture(); await f.load(); f.edit('keep_newest', '10000');
    const saving = f.context.saveHistoryRetentionSettings(); f.requests.at(-1).reject(new Error('network interrupted'));
    await tick(); assert.equal(f.els.historyRetentionSave.disabled, true);
    assert.equal(f.requests.at(-1).options, undefined);
    f.requests.at(-1).resolve(response(snapshot(matched ? { mode: 'keep_newest', max_entries: 10000 } : { mode: 'off' }, matched ? TOKEN_B : TOKEN_A)));
    assert.equal(await saving, false);
    assert.equal(f.requests.filter((r) => r.options).length, 1);
    assert.equal(f.state.historyRetentionSettings.uncertain, null);
    assert.equal(f.state.historyRetentionSettings.dirty, !matched);
    assert.match(f.els.historyRetentionStatus.textContent, matched ? /Saved policy verified/ : /earlier save could not be confirmed/);
  });
}

test('failed verification leaves write blocked until a later explicit status check', async () => {
  const f = fixture(); await f.load(); f.edit('keep_newest', '10000');
  const saving = f.context.saveHistoryRetentionSettings(); f.requests.at(-1).resolve(response('storage failure', 500));
  await tick(); f.requests.at(-1).reject(new Error('offline')); await saving;
  assert.ok(f.state.historyRetentionSettings.uncertain);
  assert.equal(f.els.historyRetentionSave.disabled, true);
  f.context.cancelHistoryRetentionSettings();
  assert.ok(f.state.historyRetentionSettings.uncertain);
  const count = f.requests.length; await f.context.saveHistoryRetentionSettings(); assert.equal(f.requests.length, count);
  await f.load(); assert.equal(f.state.historyRetentionSettings.uncertain, null);
});

test('a conclusive 400 rejection keeps the draft without claiming unknown or doing a status retry', async () => {
  const f = fixture(); await f.load(); f.edit(); const saving = f.context.saveHistoryRetentionSettings();
  f.requests.at(-1).resolve(response('Invalid policy.', 400)); await saving;
  assert.equal(f.requests.length, 2); assert.equal(f.state.historyRetentionSettings.uncertain, null);
  assert.equal(f.state.historyRetentionSettings.dirty, true); assert.match(f.els.historyRetentionStatus.textContent, /Policy was not saved/);
});

test('protected soft limits, durability/storage blocking and deferred disk reclamation are distinct statuses', async () => {
  const f = fixture();
  await f.load(snapshot({ mode: 'keep_newest', max_entries: 1 }, TOKEN_A, { protected_count: 2, blocked_reason: 'protected_records', pending: true }));
  assert.match(f.els.historyRetentionStatus.textContent, /2 protected.*Protected records prevent reaching the target. The limit is soft/);
  await f.load(snapshot({ mode: 'off' }, TOKEN_B, { blocked_reason: 'workspace_durability_uncertain', disk_cleanup_pending: true }));
  assert.match(f.els.historyRetentionStatus.textContent, /saved HTTP tab protection is durable/);
  assert.match(f.els.historyRetentionStatus.textContent, /disk space reclamation is pending/);
  await f.load(snapshot({ mode: 'off' }, TOKEN_B, { blocked_reason: 'persistence_error' }));
  assert.match(f.els.historyRetentionStatus.textContent, /storage error/);
});

for (const mutate of [
  (p) => { p.session_id = 'session-other'; }, (p) => { delete p.config_token; },
  (p) => { p.policy.mode = 'unknown'; }, (p) => { p.policy = { mode: 'keep_newest', max_entries: 0 }; },
  (p) => { p.status.total_count = '10'; }, (p) => { p.status.pending = 'true'; },
  (p) => { delete p.status.disk_cleanup_pending; }, (p) => { p.status.blocked_reason = 'unknown'; },
]) {
  test('malformed or wrong-session response cannot enable Save', async () => {
    const f = fixture(); const payload = snapshot(); mutate(payload); await f.load(payload);
    assert.equal(f.state.historyRetentionSettings.saved, null);
    assert.equal(f.els.historyRetentionSave.disabled, true);
    assert.match(f.els.historyRetentionError.textContent, /Invalid automatic cleanup response/);
  });
}

const malformedKnownRetentionFields = [
  ['protected count above total', (p) => { p.status.protected_count = p.status.total_count + 1; }],
  ['Off with a numeric max_entries', (p) => { p.policy.max_entries = 10000; }],
  ['Off with a null max_entries', (p) => { p.policy.max_entries = null; }],
];
for (const [description, mutate] of malformedKnownRetentionFields) {
  for (const loaded of [false, true]) {
    test(`malformed GET ${description} preserves ${loaded ? 'the saved baseline and local draft' : 'the unloaded state'}`, async () => {
      const f = fixture();
      if (loaded) { await f.load(); f.edit('keep_newest', 'custom', '12345'); }
      const settings = f.context.historyRetentionSettingsState();
      const saved = settings.saved, baseline = settings.baselineToken;
      const draft = JSON.stringify(settings.draft);
      const loading = f.context.loadHistoryRetentionSettings();
      const payload = snapshot({ mode: 'off' }, TOKEN_B); mutate(payload);
      f.requests.at(-1).resolve(response(payload));
      assert.equal(await loading, false);
      assert.equal(settings.saved, saved);
      assert.equal(settings.baselineToken, baseline);
      assert.equal(JSON.stringify(settings.draft), draft);
      assert.equal(settings.dirty, loaded);
      assert.match(f.els.historyRetentionError.textContent, /Invalid automatic cleanup response/);
      if (!loaded) assert.equal(f.els.historyRetentionSave.disabled, true);
      assert.equal(f.requests.filter((r) => r.options).length, 0);
    });
  }

  test(`successful-write acknowledgement with ${description} stays unknown and never retries`, async () => {
    const f = fixture(); await f.load(snapshot({ mode: 'keep_newest', max_entries: 50000 }));
    const settings = f.state.historyRetentionSettings, saved = settings.saved;
    f.edit('off'); const saving = f.context.saveHistoryRetentionSettings();
    const write = f.requests.at(-1);
    f.edit('keep_newest', 'custom', '12345');
    const ack = snapshot({ mode: 'off' }, TOKEN_B); mutate(ack);
    write.resolve(response(ack)); await tick();
    assert.ok(settings.uncertain);
    assert.equal(settings.saved, saved);
    assert.equal(settings.baselineToken, TOKEN_A);
    assert.equal(f.els.historyRetentionSave.disabled, true);
    assert.equal(f.els.historyRetentionCustom.value, '12345');
    assert.match(f.els.historyRetentionError.textContent, /Invalid automatic cleanup response/);
    assert.match(f.els.historyRetentionStatus.textContent, /will not be retried automatically/);
    assert.doesNotMatch(f.els.historyRetentionStatus.textContent, /Policy saved\./);
    const verification = f.requests.at(-1);
    assert.notEqual(verification, write);
    assert.equal(verification.options, undefined);
    assert.equal(await f.context.saveHistoryRetentionSettings(), false);
    assert.equal(f.requests.at(-1), verification);
    verification.resolve(response(snapshot({ mode: 'off' }, TOKEN_B)));
    assert.equal(await saving, false);
    assert.equal(settings.uncertain, null);
    assert.equal(settings.baselineToken, TOKEN_B);
    assert.equal(settings.dirty, true);
    assert.equal(f.els.historyRetentionCustom.value, '12345');
    assert.equal(f.requests.filter((r) => r.options?.method === 'POST').length, 1);
  });
}

for (const mode of ['off', 'keep_newest']) {
  for (const count of [0, 12000]) {
    test(`additive response fields and protected=total=${count} are accepted for ${mode} reads and acknowledgements`, async () => {
      const f = fixture();
      const policy = mode === 'off' ? { mode } : { mode, max_entries: 10000 };
      const baselinePolicy = mode === 'off' ? { mode: 'keep_newest', max_entries: 50000 } : { mode: 'off' };
      const withFutureFields = (payload) => ({
        ...payload, future_metadata: { version: 2 },
        policy: { ...payload.policy, future_policy_field: 'supported later' },
        status: { ...payload.status, total_count: count, protected_count: count, future_status_field: true },
      });
      await f.load(withFutureFields(snapshot(policy)));
      assert.equal(f.els.historyRetentionError.textContent, '');
      assert.deepEqual(JSON.parse(JSON.stringify(f.state.historyRetentionSettings.saved.policy)), policy);
      await f.load(withFutureFields(snapshot(baselinePolicy)));
      f.edit(mode);
      const saving = f.context.saveHistoryRetentionSettings();
      f.requests.at(-1).resolve(response(withFutureFields(snapshot(policy, TOKEN_B))));
      assert.equal(await saving, true);
      assert.deepEqual(JSON.parse(JSON.stringify(f.state.historyRetentionSettings.saved.policy)), policy);
      assert.equal(f.state.historyRetentionSettings.dirty, false);
      assert.equal(f.requests.length, 3);
    });
  }
}

for (const revision of ['0', '9007199254740993', '18446744073709551615']) {
  test(`canonical u64 revision ${revision} is retained exactly`, async () => {
    const f = fixture(); await f.load({ ...snapshot(), config_revision: revision });
    assert.equal(f.state.historyRetentionSettings.saved.config_revision, revision);
    assert.equal(f.els.historyRetentionError.textContent, '');
  });
}
for (const revision of [0, 1, null, '', '00', '01', '-1', '+1', '1.0', '1e3', ' 1', '18446744073709551616', '999999999999999999999']) {
  test(`invalid/precision-losing revision ${JSON.stringify(revision)} blocks loading`, async () => {
    const f = fixture(); await f.load({ ...snapshot(), config_revision: revision });
    assert.equal(f.state.historyRetentionSettings.saved, null);
    assert.match(f.els.historyRetentionError.textContent, /Invalid automatic cleanup response/);
  });
}
for (const token of ['', 'a', 'A'.repeat(64), 'x'.repeat(64), 'a'.repeat(65)]) {
  test(`malformed opaque token ${token.length} chars is rejected`, async () => {
    const f = fixture(); await f.load({ ...snapshot(), config_token: token });
    assert.equal(f.state.historyRetentionSettings.saved, null);
  });
}

test('successful changed acknowledgement increments a >2^53 revision without losing precision', async () => {
  const f = fixture(); await f.load({ ...snapshot(), config_revision: '9007199254740993' }); f.edit();
  const saving = f.context.saveHistoryRetentionSettings();
  f.requests.at(-1).resolve(response({ ...snapshot({ mode: 'keep_newest', max_entries: 10000 }, TOKEN_B), config_revision: '9007199254740994' }));
  assert.equal(await saving, true);
  assert.equal(f.state.historyRetentionSettings.saved.config_revision, '9007199254740994');
});

for (const change of [
  (p) => { delete p.changed; }, (p) => { p.changed = false; }, (p) => { p.changed = 'true'; },
  (p) => { p.config_revision = '0'; }, (p) => { p.config_revision = '2'; },
  (p) => { p.config_token = TOKEN_A; }, (p) => { p.policy.max_entries = 50000; },
]) {
  test('malformed changed acknowledgement is unknown and verified without automatic POST retry', async () => {
    const f = fixture(); await f.load(); f.edit(); const saving = f.context.saveHistoryRetentionSettings();
    const ack = snapshot({ mode: 'keep_newest', max_entries: 10000 }, TOKEN_B); change(ack);
    f.requests.at(-1).resolve(response(ack)); await tick();
    assert.ok(f.state.historyRetentionSettings.uncertain);
    assert.equal(f.requests.at(-1).options, undefined);
    f.requests.at(-1).resolve(response(snapshot({ mode: 'keep_newest', max_entries: 10000 }, TOKEN_B)));
    assert.equal(await saving, false);
    assert.equal(f.requests.filter((r) => r.options?.method === 'POST').length, 1);
    assert.match(f.els.historyRetentionStatus.textContent, /Saved policy verified/);
  });
}

test('no-op acknowledgement requires unchanged revision and token', () => {
  const f = fixture(); const baseline = snapshot();
  assert.equal(f.context.validateHistoryRetentionAcknowledgement({ ...baseline, changed: false }, baseline, baseline.policy).config_revision, '0');
  assert.throws(() => f.context.validateHistoryRetentionAcknowledgement({ ...baseline, changed: false, config_revision: '1' }, baseline, baseline.policy), /Invalid save acknowledgement/);
  assert.throws(() => f.context.validateHistoryRetentionAcknowledgement({ ...baseline, changed: false, config_token: TOKEN_B }, baseline, baseline.policy), /Invalid save acknowledgement/);
  assert.throws(() => f.context.validateHistoryRetentionAcknowledgement({ ...baseline, changed: true }, baseline, baseline.policy), /Invalid save acknowledgement/);
});

test('Off → On → Off ABA keeps stale draft and CAS baseline for explicit cancel/review', async () => {
  const f = fixture(); await f.load(); f.edit('keep_newest', '10000');
  const saving = f.context.saveHistoryRetentionSettings(); const submitted = f.requests.at(-1);
  assert.equal(JSON.parse(submitted.options.body).expected_config_token, TOKEN_A);
  submitted.resolve(response('stale revision', 409)); await tick();
  const latest = { ...snapshot({ mode: 'off' }, 'c'.repeat(64)), config_revision: '2', changed: false };
  f.requests.at(-1).resolve(response(latest)); await saving;
  assert.equal(f.state.historyRetentionSettings.conflict, true);
  assert.equal(f.state.historyRetentionSettings.baselineToken, TOKEN_A);
  assert.equal(f.els.historyRetentionEnabled.checked, true);
  assert.equal(f.requests.filter((r) => r.options).length, 1);
  f.context.cancelHistoryRetentionSettings();
  assert.equal(f.els.historyRetentionEnabled.checked, false);
  assert.equal(f.state.historyRetentionSettings.saved.config_revision, '2');
  assert.equal(f.state.historyRetentionSettings.baselineToken, 'c'.repeat(64));
});

test('uncertain save verified as clean storage error permits one explicit no-op durability retry', async () => {
  const f = fixture(); await f.load(); f.edit(); const firstSave = f.context.saveHistoryRetentionSettings();
  f.requests.at(-1).resolve(response('RETENTION_COMMIT_UNCERTAIN', 500)); await tick();
  const stored = snapshot({ mode: 'keep_newest', max_entries: 10000 }, TOKEN_B, { blocked_reason: 'persistence_error', pending: true });
  f.requests.at(-1).resolve(response(stored)); await firstSave;
  assert.equal(f.state.historyRetentionSettings.dirty, false);
  assert.equal(f.els.historyRetentionSave.textContent, 'Retry policy save');
  assert.equal(f.els.historyRetentionSave.disabled, false);
  assert.equal(f.requests.filter((r) => r.options).length, 1);
  const retry = f.context.saveHistoryRetentionSettings(); const request = f.requests.at(-1);
  assert.deepEqual(JSON.parse(request.options.body), { expected_config_token: TOKEN_B, policy: stored.policy });
  request.resolve(response({ ...stored, changed: false, status: { ...stored.status, blocked_reason: null } }));
  assert.equal(await retry, true);
  assert.equal(f.state.historyRetentionSettings.saved.config_revision, '1');
  assert.equal(f.els.historyRetentionSave.disabled, true);
  assert.equal(f.requests.filter((r) => r.options).length, 2);
});

test('repeated explicit durability save failure stays visible with no automatic POST loop', async () => {
  const f = fixture(); const stored = snapshot({ mode: 'off' }, TOKEN_A, { blocked_reason: 'persistence_error' }); await f.load(stored);
  const retry = f.context.saveHistoryRetentionSettings(); f.requests.at(-1).resolve(response('storage unavailable', 500)); await tick();
  f.requests.at(-1).resolve(response(stored)); await retry;
  assert.equal(f.requests.filter((r) => r.options).length, 1);
  assert.equal(f.els.historyRetentionSave.textContent, 'Retry policy save');
  assert.equal(f.els.historyRetentionSave.disabled, false);
  assert.match(f.els.historyRetentionStatus.textContent, /Cleanup paused after a storage error/);
  assert.match(f.els.historyRetentionStatus.textContent, /cleanup may still be blocked/);
});

test('active-session 409 remains a visible review boundary even when GET returns the same token', async () => {
  const f = fixture(); await f.load(); f.edit(); const saving = f.context.saveHistoryRetentionSettings();
  f.requests.at(-1).resolve(response('active session changed', 409)); await tick();
  f.requests.at(-1).resolve(response(snapshot())); await saving;
  assert.equal(f.state.historyRetentionSettings.conflict, true);
  assert.equal(f.els.historyRetentionSave.disabled, true);
  assert.match(f.els.historyRetentionError.textContent, /active session moved/);
  assert.doesNotMatch(f.els.historyRetentionStatus.textContent, /Saving policy/);
  f.context.cancelHistoryRetentionSettings();
  assert.equal(f.state.historyRetentionSettings.conflict, false);
  assert.equal(f.els.historyRetentionEnabled.checked, false);
});

test('duplicate-record identity conflict is visible without inventing a repair action', async () => {
  const f = fixture(); await f.load(snapshot({ mode: 'keep_newest', max_entries: 1 }, TOKEN_A, { blocked_reason: 'record_identity_conflict', pending: true }));
  assert.match(f.els.historyRetentionStatus.textContent, /Duplicate record IDs prevent further automatic cleanup/);
  assert.equal(f.els.historyRetentionSave.disabled, true);
  assert.doesNotMatch(f.els.historyRetentionSave.textContent, /Retry|Repair/);
  assert.equal(f.requests.length, 1);
});

test('HTTP session counts remain exact at/above the legacy global limit; non-HTTP capped counts are unchanged', () => {
  const sessions = [
    { id: 'session-a', active: true, name: 'Active', request_count: 250000, websocket_count: 250, event_count: 250 },
    { id: 'session-b', active: false, name: 'Stored', request_count: 500001, websocket_count: 251, event_count: 300 },
  ];
  const state = { sessions, activeSession: sessions[0], settings: { max_transaction_entries: 250000, max_entries: 250 } };
  const els = new Proxy({}, { get: (obj, key) => obj[key] ||= { querySelectorAll: () => [] } });
  const context = loadFunctions(['renderDashboard', 'formatCappedCount', 'retainedEntriesCap'], {
    state, els, document: { getElementById: () => null }, getSortedSessions: () => sessions,
    formatTimestamp: () => '-', escapeHtml: String,
  });
  context.renderDashboard();
  assert.match(els.dashboardSessionsBody.innerHTML, /<td>250000<\/td>\s*<td>250\+<\/td>\s*<td>250\+<\/td>/);
  assert.match(els.dashboardSessionsBody.innerHTML, /<td>500001<\/td>/);
  assert.doesNotMatch(els.dashboardSessionsBody.innerHTML, /250000\+|500001\+/);
  assert.match(els.dashboardSessionsBody.innerHTML, /<td>500001<\/td>\s*<td>251\+<\/td>\s*<td>300\+<\/td>/);
});

test('global capture/settings information only reports body preview size, never a legacy HTTP retention limit', async () => {
  const state = {}, elements = {};
  const els = new Proxy({}, { get: (obj, key) => obj[key] ||= control() });
  const document = { getElementById(id) { return elements[id] ||= control(); }, activeElement: null };
  const context = loadFunctions(['_applySettings', 'currentSessionId', 'formatSize'], {
    state, els, document, resetFindingsUiState() {}, syncHttpCapturePill() {}, updateProxyStatusIndicator() {}, updateRemoteUiIndicator() {},
    formatTimestamp: () => '-', escapeHtml: String, renderInterceptStatus() {}, renderProxySettings() {}, renderDashboard() {},
  });
  const settings = { body_preview_bytes: 65536, max_transaction_entries: 250000, runtime: {}, active_session: { id: 'session-a' },
    certificate: { special_host_http: 'http://example.com', special_host_https: 'https://example.com' } };
  await context._applySettings(response(settings));
  // Execute the actual label assignment from the independent runtime panel.
  const assignment = appSource.match(/^  els\.proxySettingsCaptureCap\.textContent = .*;$/m)[0];
  require('node:vm').runInContext(assignment, context);
  assert.equal(els.proxySettingsCaptureCap.textContent, '64 KB body preview cap');
  assert.doesNotMatch(appSource, /configuredTransactionEntryLimit|retainedTransactionsCap/);
});
