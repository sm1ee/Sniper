// Passive configuration only: extracted frontend functions, synthetic editor
// nodes and deferred fetch responses. No app, server, proxy or traffic starts.
const assert = require("node:assert/strict");
const test = require("node:test");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const nextTurn = () => new Promise(resolve => setImmediate(resolve));
const plain = value => JSON.parse(JSON.stringify(value));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function rule(id, name = id) {
  return { id, name, enabled: true, target: "response_body", header_name: "", pattern: "fixture", severity: "info", category: "custom", description: "Synthetic rule" };
}
function snapshot(overrides = {}) {
  return { session_id: "session-a", config_token: "a".repeat(64), enabled: true, rules: { jwt: true, header: false, future_builtin: false }, custom_rules: [rule("first"), rule("second")], ...overrides };
}
const decode = value => value.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");

function fixture() {
  const requests = [], toasts = [], errors = [], classes = new Set(["hidden"]);
  let builtins = [], cards = [], deleteButtons = [], uuid = 0;
  const builtinNode = {
    set innerHTML(html) {
      builtins = [...html.matchAll(/<input type="checkbox" data-rule-id="([^"]*)"([^>]*)>/g)].map(match => ({ dataset: { ruleId: match[1] }, checked: /\bchecked\b/.test(match[2]) }));
    },
    querySelectorAll: () => builtins,
  };
  const customNode = {
    set innerHTML(html) {
      cards = [...html.matchAll(/<div class="scanner-custom-rule-card" data-custom-idx="(\d+)" data-rule-id="([^"]*)">([^]*?)(?=<div class="scanner-custom-rule-card"|$)/g)].map(match => {
        const fields = {};
        for (const name of ["enabled", "name", "header-name", "pattern", "category", "description"]) {
          const markup = match[3].match(new RegExp(`<input[^>]*class="custom-rule-${name}(?: [^"]*)?"[^>]*>`))[0];
          fields[`.custom-rule-${name}`] = { checked: /\bchecked\b/.test(markup), value: decode(markup.match(/value="([^"]*)"/)?.[1] || "") };
        }
        for (const name of ["target", "severity"]) {
          const markup = match[3].match(new RegExp(`<select class="custom-rule-${name}">([^]*?)</select>`))[1];
          fields[`.custom-rule-${name}`] = { value: markup.match(/<option value="([^"]*)" selected/)?.[1] || markup.match(/<option value="([^"]*)"/)[1] };
        }
        return { dataset: { ruleId: decode(match[2]) }, querySelector: selector => fields[selector] };
      });
      deleteButtons = cards.map((_, index) => ({ dataset: { delIdx: String(index) }, addEventListener(_, handler) { this.click = handler; } }));
    },
    querySelectorAll: selector => selector === ".scanner-custom-rule-card" ? cards : deleteButtons,
  };
  const els = {
    scannerBuiltinRules: builtinNode, scannerCustomRules: customNode,
    scannerQuickToggle: { checked: true, disabled: false },
    scannerSettingsBackdrop: { classList: { add: name => classes.add(name), remove: name => classes.delete(name), contains: name => classes.has(name) } },
  };
  const context = loadFunctions([
    "resetScannerConfigUiState", "scannerConfigContextIsCurrent", "scannerConfigSnapshot", "loadScannerConfig", "saveScannerConfig",
    "openScannerSettings", "renderCustomRulesEditor", "collectCustomRulesFromEditor", "customRuleId", "collectScannerConfig", "closeScannerSettings", "saveScannerSettingsFromModal",
    "refreshScannerQuickToggle", "saveScannerQuickToggle", "syncQuickToggle", "sessionQueryPath", "sessionWritePath", "expectedActiveSessionIdForWrite",
    "requireOkResponse", "readApiErrorMessage", "formatStructuredApiErrorMessage",
  ], {
    els, URLSearchParams, sessionId: "session-a", scannerConfigCache: null,
    scannerConfigStateGeneration: 0, scannerConfigLoadGeneration: 0, scannerConfigSavePending: null,
    scannerSettingsSessionId: null, scannerSettingsBaseline: null, scannerSettingsGeneration: 0, scannerSettingsSavePending: null, scannerQuickTogglePending: null,
    BUILTIN_RULE_LABELS: { jwt: "JWT Analysis", header: "Security Headers" },
    generateUuid: () => `fixture-${++uuid}`,
    escapeHtml: value => String(value).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/'/g, "&#39;").replace(/</g, "&lt;").replace(/>/g, "&gt;"),
    showToast: (message, type = "success") => toasts.push({ message, type }),
    console: { error: error => errors.push(error) },
    fetch(url, options) {
      assert.match(url, /^\/api\/scanner-config\?/);
      const request = { url, options, ...deferred() };
      requests.push(request);
      return request.promise;
    },
  });
  context.currentSessionId = () => context.sessionId;
  const payload = index => JSON.parse(requests[index].options.body);
  const succeed = (index, config = snapshot()) => requests[index].resolve({ ok: true, status: 200, json: async () => plain(config) });
  const fail = (index, status = 500, message = "Synthetic unavailable") => requests[index].resolve({ ok: false, status, headers: new Headers(), text: async () => message });
  const ack = (index, overrides = {}) => {
    const { expected_config_token, ...config } = payload(index);
    succeed(index, { ...config, session_id: context.sessionId, config_token: "b".repeat(64), ...overrides });
  };
  const open = async (config = snapshot()) => {
    const index = requests.length, opening = context.openScannerSettings();
    succeed(index, config);
    await opening;
  };
  const switchSession = id => { context.sessionId = id; context.resetScannerConfigUiState(); };
  return { context, els, requests, toasts, errors, payload, succeed, fail, ack, open, switchSession,
    hidden: () => classes.has("hidden"), cards: () => cards, builtins: () => builtins, deleteButtons: () => deleteButtons,
    draft: () => plain(context.collectScannerConfig()),
  };
}

test("modal keeps an independent opening snapshot and preserves unknown built-ins and ordered IDs", async () => {
  const f = fixture();
  await f.open(snapshot({ enabled: false }));
  const baseline = f.context.scannerSettingsBaseline;
  assert.notEqual(baseline, f.context.scannerConfigCache);
  assert.notEqual(baseline.rules, f.context.scannerConfigCache.rules);
  assert.notEqual(baseline.custom_rules[0], f.context.scannerConfigCache.custom_rules[0]);
  f.context.scannerConfigCache.rules.future_builtin = true;
  f.context.scannerConfigCache.custom_rules[0].name = "Cache changed";
  f.els.scannerQuickToggle.checked = true;
  f.builtins()[0].checked = false;
  f.cards()[1].querySelector(".custom-rule-name").value = " Edited second ";
  const draft = f.draft();
  assert.equal(draft.enabled, false);
  assert.deepEqual(draft.rules, { jwt: false, header: false, future_builtin: false });
  assert.deepEqual(draft.custom_rules.map(item => [item.id, item.name]), [["first", "first"], ["second", "Edited second"]]);
  assert.equal(baseline.custom_rules[0].name, "first");
});

test("modal posts its opening token and master enabled without a fresh GET or metadata", async () => {
  const f = fixture();
  await f.open(snapshot({ enabled: false, builtins: [{ id: "jwt" }] }));
  const refresh = f.context.refreshScannerQuickToggle();
  f.succeed(1, snapshot({ config_token: "c".repeat(64), enabled: true }));
  await refresh;
  f.builtins()[0].checked = false;
  const saving = f.context.saveScannerSettingsFromModal();
  assert.equal(f.requests.length, 3);
  assert.equal(f.requests[2].options.method, "POST");
  assert.equal(f.requests[2].url, "/api/scanner-config?session_id=session-a&expected_active_session_id=session-a");
  assert.deepEqual(Object.keys(f.payload(2)).sort(), ["custom_rules", "enabled", "expected_config_token", "rules"]);
  assert.equal(f.payload(2).expected_config_token, "a".repeat(64));
  assert.equal(f.payload(2).enabled, false);
  assert.equal(f.payload(2).rules.future_builtin, false);
  f.fail(2, 409);
  await saving;
  assert.equal(f.hidden(), false);
  assert.equal(f.context.scannerSettingsBaseline.config_token, "a".repeat(64));
  assert.equal(f.draft().rules.jwt, false);
  assert.match(f.toasts.at(-1).message, /changed elsewhere.*draft is still here/);
  assert.equal(f.requests.length, 3, "Conflict must not refetch or retry");
});

test("successful modal save consumes the acknowledged snapshot and closes only that modal", async () => {
  const f = fixture(); await f.open();
  const saving = f.context.saveScannerSettingsFromModal();
  f.ack(1, { config_token: "d".repeat(64), enabled: false });
  await saving;
  assert.equal(f.hidden(), true);
  assert.equal(f.context.scannerSettingsBaseline, null);
  assert.equal(f.context.scannerConfigCache.config_token, "d".repeat(64));
  assert.equal(f.els.scannerQuickToggle.checked, false);
  assert.equal(f.toasts.at(-1).message, "Scanner settings saved");
});

for (const failure of ["network", "JSON", "invalid acknowledgement", "wrong session", 400, 409, 428, 500]) {
  test(`modal ${failure} failure retains the complete draft and original token without retrying`, async () => {
    const f = fixture(); await f.open();
    f.cards()[0].querySelector(".custom-rule-pattern").value = "edited fixture";
    const before = f.draft(), saving = f.context.saveScannerSettingsFromModal();
    if (failure === "network") f.requests[1].reject(new Error("Synthetic network failure"));
    else if (failure === "JSON") f.requests[1].resolve({ ok: true, status: 200, json: async () => { throw new Error("Synthetic JSON failure"); } });
    else if (failure === "invalid acknowledgement") f.succeed(1, {});
    else if (failure === "wrong session") f.ack(1, { session_id: "session-b" });
    else f.fail(1, failure);
    await saving;
    assert.deepEqual(f.draft(), before);
    assert.equal(f.hidden(), false);
    assert.equal(f.context.scannerSettingsBaseline.config_token, "a".repeat(64));
    assert.equal(f.context.scannerSettingsSavePending, null);
    assert.equal(f.context.scannerConfigSavePending, null);
    assert.equal(f.toasts.at(-1).type, "error");
    assert.match(f.toasts.at(-1).message, /draft is still here/);
    assert.equal(f.requests.length, 2);
  });
}

test("repeated modal saves share one pending operation and manual conflict retry keeps the stale token", async () => {
  const f = fixture(); await f.open();
  const first = f.context.saveScannerSettingsFromModal();
  await f.context.saveScannerSettingsFromModal();
  assert.equal(f.requests.length, 2);
  f.fail(1, 409); await first;
  const retry = f.context.saveScannerSettingsFromModal();
  assert.equal(f.payload(2).expected_config_token, "a".repeat(64));
  f.fail(2, 409); await retry;
  assert.equal(f.requests.length, 3);
  assert.equal(f.hidden(), false);
});

test("edits made during a successful save remain open and use only its acknowledged token on next save", async () => {
  const f = fixture(); await f.open();
  const saving = f.context.saveScannerSettingsFromModal();
  f.cards()[0].querySelector(".custom-rule-name").value = "Newer draft";
  f.builtins()[1].checked = true;
  f.ack(1); await saving;
  assert.equal(f.hidden(), false);
  assert.equal(f.draft().custom_rules[0].name, "Newer draft");
  assert.equal(f.draft().rules.header, true);
  assert.equal(f.context.scannerSettingsBaseline.config_token, "b".repeat(64));
  assert.match(f.toasts.at(-1).message, /newer edits are still here/);
  const second = f.context.saveScannerSettingsFromModal();
  assert.equal(f.payload(2).expected_config_token, "b".repeat(64));
  assert.equal(f.payload(2).custom_rules[0].name, "Newer draft");
  f.ack(2); await second;
  assert.equal(f.hidden(), true);
});

test("custom rule deletion and addition preserve remaining IDs, current field edits and order", async () => {
  const f = fixture(); await f.open();
  f.cards()[1].querySelector(".custom-rule-name").value = "Edited survivor";
  f.deleteButtons()[0].click();
  const rules = plain(f.context.collectCustomRulesFromEditor());
  rules.push(rule(f.context.customRuleId(), "Added"));
  f.context.renderCustomRulesEditor(rules);
  const first = f.draft().custom_rules, second = f.draft().custom_rules;
  assert.deepEqual(first.map(item => item.id), ["second", "custom_fixture-1"]);
  assert.deepEqual(first, second);
  assert.equal(first[0].name, "Edited survivor");
});

for (const invalid of [null, [], {}, { config_token: "" }, { config_token: null }, { session_id: "session-b" }, { enabled: "true" }, { rules: [] }, { rules: { jwt: "false" } }, { custom_rules: null }, { custom_rules: [null] }, { custom_rules: [{}] }, { custom_rules: [rule(" ")] }, { custom_rules: [{ ...rule("fixture"), enabled: "true" }] }]) {
  test(`invalid load ${JSON.stringify(invalid)} cannot open a writable modal`, async () => {
    const f = fixture(), opening = f.context.openScannerSettings();
    f.succeed(0, invalid && !Array.isArray(invalid) && Object.keys(invalid).length ? snapshot(invalid) : invalid);
    await opening;
    assert.equal(f.hidden(), true);
    assert.equal(f.context.scannerSettingsBaseline, null);
    assert.equal(f.context.scannerConfigCache, null);
    await f.context.saveScannerSettingsFromModal();
    assert.equal(f.requests.length, 1);
    assert.equal(f.toasts.at(-1).type, "error");
  });
}

for (const phase of ["response", "JSON", "error"]) {
  test(`closing a pending modal ${phase} load prevents late reopening or error toasts`, async () => {
    const f = fixture(), body = deferred(), opening = f.context.openScannerSettings();
    if (phase === "JSON") {
      f.requests[0].resolve({ ok: true, status: 200, json: () => body.promise });
      await nextTurn();
    }
    f.context.closeScannerSettings();
    if (phase === "JSON") body.resolve(snapshot());
    else if (phase === "error") f.fail(0);
    else f.succeed(0);
    await opening;
    assert.equal(f.hidden(), true);
    assert.equal(f.context.scannerSettingsBaseline, null);
    assert.equal(f.toasts.length, 0);
  });
}

for (const failure of [false, true]) {
  test(`a late older modal ${failure ? "failure" : "response"} cannot replace the newest opening`, async () => {
    const f = fixture(), older = f.context.openScannerSettings(), newer = f.context.openScannerSettings();
    f.succeed(1, snapshot({ config_token: "b".repeat(64), custom_rules: [rule("newer")] }));
    await newer;
    if (failure) f.fail(0); else f.succeed(0);
    await older;
    assert.equal(f.context.scannerSettingsBaseline.config_token, "b".repeat(64));
    assert.equal(f.draft().custom_rules[0].id, "newer");
    assert.equal(f.context.scannerConfigCache.config_token, "b".repeat(64));
    assert.equal(f.toasts.length, 0);
  });
}

test("reopening an already open modal leaves its draft and token untouched", async () => {
  const f = fixture(); await f.open();
  f.cards()[0].querySelector(".custom-rule-name").value = "Keep me";
  await f.context.openScannerSettings();
  assert.equal(f.requests.length, 1);
  assert.equal(f.draft().custom_rules[0].name, "Keep me");
});

for (const failure of [false, true]) {
  test(`late modal save ${failure ? "failure" : "success"} cannot affect a reopened draft`, async () => {
    const f = fixture(); await f.open();
    const saving = f.context.saveScannerSettingsFromModal();
    f.context.closeScannerSettings();
    await f.open(snapshot({ config_token: "c".repeat(64), custom_rules: [rule("reopened")] }));
    if (failure) f.fail(1); else f.ack(1);
    await saving;
    assert.equal(f.hidden(), false);
    assert.equal(f.context.scannerSettingsBaseline.config_token, "c".repeat(64));
    assert.equal(f.draft().custom_rules[0].id, "reopened");
    assert.equal(f.toasts.length, 0);
  });
}

for (const operation of ["load", "save"]) {
  for (const phase of ["response", "JSON", "error"]) {
    test(`session A to B to A invalidates an older ${operation} ${phase}`, async () => {
      const f = fixture(), body = deferred();
      if (operation === "save") await f.open();
      const index = f.requests.length;
      const pending = operation === "save" ? f.context.saveScannerSettingsFromModal() : f.context.openScannerSettings();
      if (phase === "JSON") {
        f.requests[index].resolve({ ok: true, status: 200, json: () => body.promise });
        await nextTurn();
      }
      f.switchSession("session-b"); f.switchSession("session-a");
      await f.open(snapshot({ config_token: "c".repeat(64), custom_rules: [rule("current")] }));
      if (phase === "JSON") body.resolve(snapshot());
      else if (phase === "error") f.fail(index);
      else f.succeed(index);
      await pending;
      assert.equal(f.context.scannerConfigCache.config_token, "c".repeat(64));
      assert.equal(f.context.scannerSettingsBaseline.config_token, "c".repeat(64));
      assert.equal(f.draft().custom_rules[0].id, "current");
      assert.equal(f.hidden(), false);
      assert.equal(f.toasts.length, 0);
    });
  }
}

for (const startDuringSave of [false, true]) {
  test(`a background read started ${startDuringSave ? "during" : "before"} a save cannot replace its acknowledgement`, async () => {
    const f = fixture(); await f.open();
    let refresh, saving, refreshIndex, saveIndex;
    if (startDuringSave) { saving = f.context.saveScannerSettingsFromModal(); saveIndex = 1; refresh = f.context.refreshScannerQuickToggle(); refreshIndex = 2; }
    else { refresh = f.context.refreshScannerQuickToggle(); refreshIndex = 1; saving = f.context.saveScannerSettingsFromModal(); saveIndex = 2; }
    f.ack(saveIndex, { enabled: false }); await saving;
    f.succeed(refreshIndex); await refresh;
    assert.equal(f.context.scannerConfigCache.config_token, "b".repeat(64));
    assert.equal(f.els.scannerQuickToggle.checked, false);
  });
}

test("quick toggle performs a fresh read then CAS while preserving all current rules", async () => {
  const f = fixture(); await f.open();
  const baseline = plain(f.context.scannerSettingsBaseline);
  f.els.scannerQuickToggle.checked = false;
  const toggling = f.context.saveScannerQuickToggle();
  assert.equal(f.els.scannerQuickToggle.disabled, true);
  const fresh = snapshot({ config_token: "c".repeat(64), rules: { jwt: false, future_builtin: true }, custom_rules: [rule("fresh-second"), rule("fresh-first")] });
  f.succeed(1, fresh); await nextTurn();
  assert.equal(f.requests.length, 3);
  assert.deepEqual(f.payload(2), { enabled: false, rules: fresh.rules, custom_rules: fresh.custom_rules, expected_config_token: fresh.config_token });
  assert.equal(f.context.scannerConfigCache.enabled, true, "The unsaved toggle must not mutate the read cache");
  f.ack(2); await toggling;
  assert.equal(f.els.scannerQuickToggle.checked, false);
  assert.equal(f.els.scannerQuickToggle.disabled, false);
  assert.deepEqual(plain(f.context.scannerSettingsBaseline), baseline);
});

for (const failure of ["network", "HTTP", "missing token"]) {
  test(`quick toggle ${failure} read failure does not post and restores the prior display`, async () => {
    const f = fixture(); f.els.scannerQuickToggle.checked = false;
    const toggling = f.context.saveScannerQuickToggle();
    if (failure === "network") f.requests[0].reject(new Error("Synthetic network failure"));
    else if (failure === "HTTP") f.fail(0);
    else f.succeed(0, snapshot({ config_token: "" }));
    await toggling;
    assert.equal(f.requests.length, 1);
    assert.equal(f.els.scannerQuickToggle.checked, true);
    assert.equal(f.els.scannerQuickToggle.disabled, false);
    assert.equal(f.toasts.at(-1).type, "error");
  });
}

test("quick toggle conflict does not retry or disturb an open modal draft", async () => {
  const f = fixture(); await f.open();
  f.cards()[0].querySelector(".custom-rule-name").value = "Keep draft";
  f.els.scannerQuickToggle.checked = false;
  const toggling = f.context.saveScannerQuickToggle(); f.succeed(1); await nextTurn();
  f.fail(2, 409); await toggling;
  assert.equal(f.requests.length, 3);
  assert.equal(f.els.scannerQuickToggle.checked, true);
  assert.equal(f.els.scannerQuickToggle.disabled, false);
  assert.equal(f.draft().custom_rules[0].name, "Keep draft");
  assert.equal(f.context.scannerSettingsBaseline.config_token, "a".repeat(64));
  assert.match(f.toasts.at(-1).message, /changed elsewhere/);
});

test("repeated quick-toggle changes issue only one read and one write", async () => {
  const f = fixture(); f.els.scannerQuickToggle.checked = false;
  const first = f.context.saveScannerQuickToggle();
  f.els.scannerQuickToggle.checked = true;
  await f.context.saveScannerQuickToggle();
  assert.equal(f.requests.length, 1);
  assert.equal(f.els.scannerQuickToggle.checked, false);
  f.succeed(0); await nextTurn();
  await f.context.saveScannerQuickToggle();
  assert.equal(f.requests.length, 2);
  f.ack(1); await first;
});

test("background refresh cannot reset a pending quick-toggle selection", async () => {
  const f = fixture(); f.els.scannerQuickToggle.checked = false;
  const toggling = f.context.saveScannerQuickToggle(), refresh = f.context.refreshScannerQuickToggle();
  f.succeed(1); await refresh;
  assert.equal(f.els.scannerQuickToggle.checked, false);
  f.succeed(0); await nextTurn();
  f.ack(2); await toggling;
  assert.equal(f.els.scannerQuickToggle.checked, false);
});

for (const phase of ["read", "write", "write JSON", "write error"]) {
  test(`late quick-toggle ${phase} cannot reset a new session's pending toggle`, async () => {
    const f = fixture(), body = deferred(); f.els.scannerQuickToggle.checked = false;
    const older = f.context.saveScannerQuickToggle();
    let oldIndex = 0;
    if (phase !== "read") { f.succeed(0); await nextTurn(); oldIndex = 1; }
    if (phase === "write JSON") {
      f.requests[1].resolve({ ok: true, status: 200, json: () => body.promise });
      await nextTurn();
    }
    f.switchSession("session-b");
    f.els.scannerQuickToggle.checked = true;
    const newIndex = f.requests.length, current = f.context.saveScannerQuickToggle();
    if (phase === "write JSON") body.resolve(snapshot({ enabled: false }));
    else if (phase === "write error") f.fail(oldIndex);
    else f.succeed(oldIndex, snapshot({ enabled: false }));
    await older;
    assert.equal(f.els.scannerQuickToggle.disabled, true);
    assert.equal(f.els.scannerQuickToggle.checked, true);
    assert.equal(f.toasts.length, 0);
    f.succeed(newIndex, snapshot({ session_id: "session-b", enabled: false })); await nextTurn();
    assert.match(f.requests[newIndex + 1].url, /expected_active_session_id=session-b/);
    f.ack(newIndex + 1); await current;
    assert.equal(f.els.scannerQuickToggle.disabled, false);
    assert.equal(f.els.scannerQuickToggle.checked, true);
  });
}

test("modal and quick toggle cannot issue overlapping configuration POSTs", async () => {
  const f = fixture(); await f.open();
  f.els.scannerQuickToggle.checked = false;
  const toggling = f.context.saveScannerQuickToggle(); f.succeed(1); await nextTurn();
  await f.context.saveScannerSettingsFromModal();
  assert.equal(f.requests.length, 3);
  assert.equal(f.hidden(), false);
  assert.match(f.toasts.at(-1).message, /already being saved.*draft is still here/);
  f.ack(2); await toggling;
  assert.equal(f.context.scannerSettingsBaseline.config_token, "a".repeat(64));
});

test("missing token or missing session never produces an unguarded write", async () => {
  const f = fixture();
  await assert.rejects(f.context.saveScannerConfig(snapshot(), "session-a", null), /version is missing/);
  f.context.sessionId = null;
  assert.equal(await f.context.saveScannerConfig(snapshot(), null, "a".repeat(64)), null);
  assert.equal(await f.context.loadScannerConfig(null), null);
  assert.equal(f.requests.length, 0);
});

test("scanner session reset and UI actions are wired to the guarded helpers", () => {
  assert.match(appSource, /function resetSessionScopedUiState\(\)[^]*?resetScannerConfigUiState\(\);/);
  assert.match(appSource, /scannerQuickToggle\.addEventListener\("change", \(\) => saveScannerQuickToggle\(\)\)/);
  assert.doesNotMatch(appSource, /preserveEnabled/);
});


test("custom rule IDs survive the editor byte-for-byte, including stored spacing", async () => {
  const f = fixture(); await f.open(snapshot({ custom_rules: [rule(' spaced "fixture" ')] }));
  assert.equal(f.draft().custom_rules[0].id, ' spaced "fixture" ');
  f.context.renderCustomRulesEditor(f.context.collectCustomRulesFromEditor());
  assert.equal(f.draft().custom_rules[0].id, ' spaced "fixture" ');
});

for (const newerAction of ["read", "save"]) {
  test(`a late background read failure cannot show an error after a newer ${newerAction}`, async () => {
    const f = fixture(), body = deferred(); await f.open();
    const older = f.context.refreshScannerQuickToggle();
    f.requests[1].resolve({ ok: false, status: 500, headers: new Headers(), text: () => body.promise });
    await nextTurn();
    const current = newerAction === "read" ? f.context.refreshScannerQuickToggle() : f.context.saveScannerSettingsFromModal();
    if (newerAction === "read") f.succeed(2); else f.ack(2);
    await current;
    const toastsBefore = f.toasts.length;
    body.resolve("Old read failed"); await older;
    assert.equal(f.toasts.length, toastsBefore);
  });
}

test("quick toggle without an active session restores its display and never reads or writes", async () => {
  const f = fixture(); f.switchSession(null); f.els.scannerQuickToggle.checked = false;
  await f.context.saveScannerQuickToggle();
  assert.equal(f.requests.length, 0);
  assert.equal(f.els.scannerQuickToggle.checked, true);
  assert.equal(f.els.scannerQuickToggle.disabled, false);
  assert.match(f.toasts.at(-1).message, /Select a session/);
});
