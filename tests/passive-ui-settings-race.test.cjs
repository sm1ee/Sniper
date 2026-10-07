// Preference persistence only: extracted functions, synthetic settings, fake
// fetch responses and timers. The application and server never start.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const nextTurn = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function fixture() {
  const requests = [], timers = new Map(), errors = [], appliedSnapshots = [];
  let timerId = 0;
  const state = {
    displaySettings: { sizePx: 12, theme: "paper", uiFont: "plex", monoFont: "jetbrains" },
    historyColumnWidths: { host: 210 }, historyColumnOrder: ["host"], wsColumnWidths: {},
    workbenchHeight: 320, workbenchPaneWidths: { requestPercent: 45 },
    websocketPaneWidth: null, websocketStackHeight: null,
  };
  const context = loadFunctions([
    "persistUiSettings", "snapshotUiSettings", "nextUiSettingsSnapshot",
    "scheduleUiSettingsSave", "scheduleUiSettingsRetry", "updateUiSettingsServerRevision",
  ], {
    state, uiSettingsClientId: "fixture-local", uiSettingsSaveVersion: 0,
    uiSettingsServerRevision: 3, uiSettingsSaveTimer: null, uiSettingsDirty: false,
    uiSettingsInFlight: false, uiSettingsSavePromise: null, lastUiSettingsPayload: null,
    console: { error(error) { errors.push(error); } },
    window: {
      setTimeout(callback, delay) {
        const id = ++timerId;
        timers.set(id, { callback, delay });
        return id;
      },
      clearTimeout(id) { timers.delete(id); },
    },
    fetch(url, options) {
      assert.equal(url, "/api/ui-settings");
      assert.equal(options.method, "POST");
      const request = { url, options, ...deferred() };
      requests.push(request);
      return request.promise;
    },
    // Fields outside appearance and layout are inert fixture values. No filter,
    // navigation, replay or capture function is executed by these tests.
    sanitizeActiveTool: () => "proxy", sanitizeActiveProxyTab: () => "http-history",
    sanitizeHttpQuery: () => "", sanitizeHttpMethod: () => "",
    sanitizeHttpSortKey: () => "index", sanitizeHttpSortDirection: () => "desc",
    serializeHttpFilterSettings: () => ({}),
    serializeWorkbenchPaneWidths: () => ({ request_percent: state.workbenchPaneWidths.requestPercent }),
    sanitizeWebsocketQuery: () => "", sanitizeWebsocketSortKey: () => "started_at",
    sanitizeWebsocketSortDirection: () => "desc",
    applyUiSettingsSnapshot: snapshot => appliedSnapshots.push(snapshot),
  });
  const payload = index => JSON.parse(requests[index].options.body);
  const succeed = (index, revision = 4) => requests[index].resolve({
    ok: true, json: async () => ({ ...payload(index), server_revision: revision }),
  });
  function runTimers() {
    for (const [id, timer] of [...timers]) {
      timers.delete(id);
      timer.callback();
    }
  }
  function startSave() {
    context.uiSettingsDirty = true;
    return context.persistUiSettings();
  }
  function assertRetryPending() {
    assert.equal(context.uiSettingsDirty, true, "A failed save must remain dirty");
    assert.equal(context.uiSettingsInFlight, false);
    assert.equal(context.uiSettingsSavePromise, null);
    assert.equal(timers.size, 1, "A failed save must retain one future retry");
    assert.ok(timers.has(context.uiSettingsSaveTimer));
  }
  return { context, state, requests, timers, errors, appliedSnapshots, payload, succeed, runTimers, startSave, assertRetryPending };
}

test("valid preference acknowledgement clears dirty state and advances the revision", async () => {
  const f = fixture(), saving = f.startSave();
  assert.equal(f.context.uiSettingsInFlight, true);
  assert.equal(f.payload(0).display_settings.theme, "paper");
  assert.equal(f.payload(0).workbench_height, 320);
  assert.equal(f.payload(0).server_revision, 3);
  assert.equal(f.payload(0).client_version, 1);
  f.succeed(0, 7);
  await saving;
  assert.equal(f.context.uiSettingsServerRevision, 7);
  assert.equal(f.context.uiSettingsDirty, false);
  assert.equal(f.context.uiSettingsInFlight, false);
  assert.equal(f.context.uiSettingsSavePromise, null);
  assert.equal(f.timers.size, 0);
  assert.equal(f.appliedSnapshots.length, 0);
});

test("concurrent preference saves share one in-flight request", async () => {
  const f = fixture(), first = f.startSave(), second = f.context.persistUiSettings();
  assert.equal(f.requests.length, 1);
  f.succeed(0);
  await Promise.all([first, second]);
  assert.equal(f.requests.length, 1);
  assert.equal(f.context.uiSettingsSavePromise, null);
});

test("malformed successful preference JSON retains dirty state and a retry", async () => {
  const f = fixture(), saving = f.startSave();
  const rejected = assert.rejects(saving, /synthetic JSON unavailable/);
  f.requests[0].resolve({ ok: true, json: async () => { throw new Error("synthetic JSON unavailable"); } });
  await rejected;
  f.assertRetryPending();
  assert.equal(f.state.displaySettings.theme, "paper");
  assert.equal(f.context.uiSettingsServerRevision, 3);
});

for (const [kind, snapshot] of [["null", null], ["array", []], ["string", "unavailable"], ["number", 42], ["boolean", false]]) {
  test(`invalid preference acknowledgement (${kind}) retains dirty state and a retry`, async () => {
    const f = fixture(), saving = f.startSave();
    const rejected = assert.rejects(saving);
    f.requests[0].resolve({ ok: true, json: async () => snapshot });
    await rejected;
    f.assertRetryPending();
    assert.equal(f.state.displaySettings.theme, "paper");
    assert.equal(f.context.uiSettingsServerRevision, 3);
    assert.equal(f.appliedSnapshots.length, 0, "Invalid acknowledgements must not be applied as server snapshots");
  });
}

const invalidMetadata = [
  ["empty object", {}],
  ["missing revision", { client_id: "fixture-local", client_version: 1 }],
  ["null revision", { server_revision: null }],
  ["string revision", { server_revision: "4" }],
  ["fractional revision", { server_revision: 4.5 }],
  ["negative revision", { server_revision: -1 }],
  ["boolean revision", { server_revision: true }],
  ["null client ID", { server_revision: 4, client_id: null }],
  ["numeric client ID", { server_revision: 4, client_id: 42 }],
  ["array client ID", { server_revision: 4, client_id: [] }],
  ["null client version", { server_revision: 4, client_version: null }],
  ["string client version", { server_revision: 4, client_version: "2" }],
  ["fractional client version", { server_revision: 4, client_version: 2.5 }],
  ["negative client version", { server_revision: 4, client_version: -1 }],
  ["boolean client version", { server_revision: 4, client_version: true }],
];
for (const [kind, snapshot] of invalidMetadata) {
  test(`invalid preference acknowledgement metadata (${kind}) cannot acknowledge or apply a save`, async () => {
    const f = fixture(), saving = f.startSave();
    const rejected = assert.rejects(saving);
    f.requests[0].resolve({ ok: true, json: async () => snapshot });
    await rejected;
    f.assertRetryPending();
    assert.equal(f.context.uiSettingsServerRevision, 3);
    assert.equal(f.appliedSnapshots.length, 0);
    assert.equal(f.state.displaySettings.theme, "paper");
  });
}

test("partial object conflict acknowledgements retain the existing server-wins policy", async () => {
  const f = fixture(), saving = f.startSave();
  const snapshot = { client_id: "fixture-remote", client_version: 2, server_revision: 4 };
  f.requests[0].resolve({ ok: true, json: async () => snapshot });
  await saving;
  assert.equal(f.appliedSnapshots.length, 1);
  assert.deepEqual(f.appliedSnapshots[0], snapshot);
  assert.equal(f.context.uiSettingsDirty, false);
  assert.equal(f.context.uiSettingsServerRevision, 4);
  assert.equal(f.timers.size, 0);
});

for (const [kind, snapshot] of [
  ["omitted legacy identity", { server_revision: 4 }],
  ["empty legacy identity and zero version", { client_id: "", client_version: 0, server_revision: 4 }],
]) {
  test(`anonymous preference conflicts permit ${kind}`, async () => {
    const f = fixture(), saving = f.startSave();
    f.requests[0].resolve({ ok: true, json: async () => snapshot });
    await saving;
    assert.equal(f.appliedSnapshots.length, 1);
    assert.deepEqual(f.appliedSnapshots[0], snapshot);
    assert.equal(f.context.uiSettingsDirty, false);
    assert.equal(f.context.uiSettingsServerRevision, 4);
    assert.equal(f.timers.size, 0);
  });
}

test("zero revision remains valid for a local preference acknowledgement", async () => {
  const f = fixture(), saving = f.startSave();
  f.succeed(0, 0);
  await saving;
  assert.equal(f.context.uiSettingsDirty, false);
  assert.equal(f.appliedSnapshots.length, 0);
  assert.equal(f.timers.size, 0);
});

for (const failure of ["network", "HTTP", "error text"]) {
  test(`preference ${failure} failure retains dirty state and a retry`, async () => {
    const f = fixture(), saving = f.startSave();
    const rejected = assert.rejects(saving, /synthetic unavailable/);
    if (failure === "network") f.requests[0].reject(new Error("synthetic unavailable"));
    if (failure === "HTTP") f.requests[0].resolve({ ok: false, text: async () => "synthetic unavailable" });
    if (failure === "error text") {
      f.requests[0].resolve({ ok: false, text: async () => { throw new Error("synthetic unavailable"); } });
    }
    await rejected;
    f.assertRetryPending();
    assert.equal(f.state.displaySettings.theme, "paper");
    assert.equal(f.state.workbenchHeight, 320);
  });
}

for (const rejectText of [false, true]) {
  test(`delayed ${rejectText ? "rejected" : "resolved"} HTTP error text cannot consume the only preference retry`, async () => {
    const f = fixture(), body = deferred(), saving = f.startSave();
    const rejected = assert.rejects(saving, /synthetic unavailable/);
    f.requests[0].resolve({ ok: false, text: () => body.promise });
    await nextTurn();
    // Simulate every timer reaching its deadline while error-body parsing is
    // pending. A retry must still exist once the original attempt finally ends.
    f.runTimers();
    await nextTurn();
    assert.equal(f.requests.length, 1);
    assert.equal(f.context.uiSettingsInFlight, true);
    if (rejectText) body.reject(new Error("synthetic unavailable"));
    else body.resolve("synthetic unavailable");
    await rejected;
    f.assertRetryPending();
  });
}

test("a preference retry saves the latest local theme and layout after a network failure", async () => {
  const f = fixture(), saving = f.startSave();
  const rejected = assert.rejects(saving, /synthetic unavailable/);
  f.state.displaySettings.theme = "ivory";
  f.state.workbenchHeight = 480;
  f.context.scheduleUiSettingsSave();
  f.requests[0].reject(new Error("synthetic unavailable"));
  await rejected;
  f.assertRetryPending();
  f.runTimers();
  assert.equal(f.requests.length, 2);
  assert.equal(f.payload(1).display_settings.theme, "ivory");
  assert.equal(f.payload(1).workbench_height, 480);
  assert.equal(f.payload(1).client_version, 2);
  f.succeed(1, 8);
  await nextTurn();
  assert.equal(f.context.uiSettingsDirty, false);
  assert.equal(f.context.uiSettingsSavePromise, null);
  assert.equal(f.context.uiSettingsServerRevision, 8);
  assert.equal(f.timers.size, 0);
});

test("a newer local preference edit still gets a retry when its timer expires during slow HTTP failure", async () => {
  const f = fixture(), body = deferred(), saving = f.startSave();
  const rejected = assert.rejects(saving, /synthetic unavailable/);
  f.state.displaySettings.theme = "ivory";
  f.state.workbenchHeight = 480;
  f.context.scheduleUiSettingsSave();
  f.requests[0].resolve({ ok: false, text: () => body.promise });
  await nextTurn();
  f.runTimers();
  body.resolve("synthetic unavailable");
  await rejected;
  f.assertRetryPending();
  f.runTimers();
  assert.equal(f.payload(1).display_settings.theme, "ivory");
  assert.equal(f.payload(1).workbench_height, 480);
  f.succeed(1, 8);
  await nextTurn();
  assert.equal(f.context.uiSettingsDirty, false);
  assert.equal(f.context.uiSettingsSavePromise, null);
  assert.equal(f.timers.size, 0);
});

test("valid acknowledgement preserves and then saves a newer in-flight local theme edit", async () => {
  const f = fixture(), saving = f.startSave();
  f.state.displaySettings.theme = "ivory";
  f.state.workbenchHeight = 480;
  f.context.uiSettingsDirty = true;
  f.succeed(0, 7);
  await nextTurn();
  assert.equal(f.requests.length, 2);
  assert.equal(f.payload(1).display_settings.theme, "ivory");
  assert.equal(f.payload(1).workbench_height, 480);
  assert.equal(f.payload(1).client_version, 2);
  assert.equal(f.payload(1).server_revision, 7);
  f.succeed(1, 8);
  await saving;
  assert.equal(f.context.uiSettingsDirty, false);
  assert.equal(f.context.uiSettingsSavePromise, null);
  assert.equal(f.timers.size, 0);
});

test("a malformed preference acknowledgement can recover on its scheduled retry", async () => {
  const f = fixture(), saving = f.startSave();
  const rejected = assert.rejects(saving, /synthetic JSON unavailable/);
  f.requests[0].resolve({ ok: true, json: async () => { throw new Error("synthetic JSON unavailable"); } });
  await rejected;
  f.assertRetryPending();
  f.runTimers();
  assert.equal(f.requests.length, 2);
  assert.equal(f.payload(1).display_settings.theme, "paper");
  assert.equal(f.payload(1).client_version, 2);
  f.succeed(1, 8);
  await nextTurn();
  assert.equal(f.context.uiSettingsDirty, false);
  assert.equal(f.context.uiSettingsSavePromise, null);
  assert.equal(f.timers.size, 0);
});
