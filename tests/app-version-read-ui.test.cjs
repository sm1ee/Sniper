// Application-version reads only. Run the real startup and Settings callbacks
// against synthetic DOM and deferred reads. The update action is a tripwire;
// no real app, release lookup, URL opener, updater, installer, or save runs.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
const nextTurn = () => new Promise(resolve => setImmediate(resolve));
const AVAILABLE = {
  current_version: "0.3.2", latest_version: "v9.9.9",
  update_available: true, self_update_supported: true,
  releases_url: "https://example.com/releases",
  latest_release_url: "https://example.com/releases/v9.9.9",
};

function fixture() {
  const document = { activeElement: null };
  function element(id, initialClasses = "") {
    const classes = new Set(initialClasses.split(/\s+/).filter(Boolean));
    const attributes = new Map(), listeners = new Map();
    const node = {
      id, textContent: "", title: "", style: {}, isConnected: true, tabIndex: 0, disabled: false,
      classList: {
        add: (...names) => names.forEach(name => classes.add(name)),
        remove: (...names) => names.forEach(name => classes.delete(name)),
        contains: name => classes.has(name),
        toggle(name, force = !classes.has(name)) {
          if (force) classes.add(name); else classes.delete(name);
          return force;
        },
      },
      setAttribute: (name, value) => attributes.set(name, String(value)),
      getAttribute: name => attributes.get(name) ?? null,
      addEventListener(name, callback) {
        listeners.set(name, [...(listeners.get(name) || []), callback]);
      },
      dispatch(name, event = {}) {
        for (const callback of listeners.get(name) || []) callback({ target: node, ...event });
      },
      listeners,
      focus() { document.activeElement = node; },
      getClientRects: () => [1],
      querySelectorAll: () => [],
      querySelector: () => null,
      set innerHTML(_) { assert.fail("Version reads must not insert HTML"); },
    };
    return node;
  }
  const els = {};
  for (const name of ["appVersionLabel", "openUpdateButton", "openDisplaySettingsButton", "closeDisplaySettingsButton", "displaySettingsModal"]) {
    const markup = html.match(new RegExp(`<[^>]*\\bid="${name}"[^>]*>`));
    assert.ok(markup, `Missing markup: ${name}`);
    els[name] = element(name, markup[0].match(/\bclass="([^"]*)"/)?.[1]);
  }
  els.appVersionLabel.textContent = "v...";
  els.appVersionLabel.title = "Current version";
  els.openUpdateButton.textContent = "Update";
  document.activeElement = els.openDisplaySettingsButton;
  document.getElementById = () => null;
  document.querySelector = () => els.openDisplaySettingsButton;
  document.querySelectorAll = () => [];

  const requests = [], errors = [], intervals = [], timers = [], calls = [];
  const state = { appVersion: null, activeProxyTab: "history" };
  const globals = {
    state, els, document,
    console: { error: (...args) => errors.push(args) },
    localStorage: { getItem() { assert.fail("Unrelated local settings must be stubbed"); } },
    compareLoadGeneration: 0, displaySettingsReturnFocus: null, displaySettingsPreviewActive: false,
    displaySettingsEditedControls: new Set(),
    fetch(url, options = {}) {
      assert.equal(url, "/api/app-version", "Only the mocked version read is allowed");
      assert.ok(!options.method || options.method === "GET", "No mutation requests");
      return new Promise((resolve, reject) => requests.push({ url, options, resolve, reject }));
    },
    performSelfUpdate() { assert.fail("This read-only fixture must never start an update"); },
    scheduleUiSettingsSave() { assert.fail("No settings save is allowed"); },
    scheduleWorkspaceStateSave() { assert.fail("No workspace save is allowed"); },
    window: {
      open() { assert.fail("No release URL may be opened"); },
      setInterval(callback, delay) { intervals.push({ callback, delay }); return intervals.length; },
      getComputedStyle: () => ({ visibility: "visible" }),
    },
    setTimeout(callback, delay) { timers.push({ callback, delay }); return timers.length; },
    isHttpHistoryVisible: () => false,
    isWebsocketHistoryVisible: () => false,
  };
  // Other startup subsystems stay inert. init itself and version reading run
  // unmodified, including its non-blocking .catch and Promise.allSettled path.
  for (const name of [
    "loadDisplaySettings", "loadHistoryColumnWidths", "loadWorkbenchLayout", "renderHistoryHeader",
    "resetLayoutTextareas", "hydrateFilterForm", "syncHttpInScopePill", "syncHttpCapturePill",
    "loadUiSettings", "hydrateDisplaySettingsForm", "loadSessions", "loadSettings",
    "loadWorkspaceState", "loadTransactions", "loadIntercepts", "loadResponseIntercepts", "loadInterceptRules",
    "loadWebsockets", "loadEventLog", "loadMatchReplaceRules", "loadSequences", "loadTargetSiteMap",
    "connectEvents", "pollAuxiliaryData", "renderToolPanels", "renderProxyPanels", "renderInspectorPanels",
    "renderViewTabs", "renderSortHeaders", "renderProxySettings", "renderIntercepts", "renderWebsocketSessions",
    "renderReplay", "renderDashboard", "renderEventLog", "renderMatchReplaceRules", "renderTarget", "renderFuzzer",
    "normalizeWorkbenchStackHeight", "initCliPathOnboarding", "applyDisplaySettingsState", "renderShortcutReference",
    "mountBrowserLaunchers", "installBrowserMenuDismissal", "bindCliPathControls",
    "wireReplayHistorySwipe", "wireTabIndicator",
  ]) globals[name] = () => { calls.push(name); return Promise.resolve(); };

  const context = loadFunctions([
    "init", "loadAppVersionInfo", "openDisplaySettingsModal", "closeDisplaySettingsModal",
    "isModalVisible", "selectSettingsTab", "restoreModalFocus",
  ], globals);
  const bindStart = appSource.indexOf('  els.openDisplaySettingsButton.addEventListener("click", openDisplaySettingsModal);');
  const bindEnd = appSource.indexOf('  els.openFilterSettingsButton.addEventListener', bindStart);
  assert.ok(bindStart > appSource.indexOf("function bindEvents() {") && bindEnd > bindStart);
  context.bindEvents = () => vm.runInContext(appSource.slice(bindStart, bindEnd), context);

  function json(index, payload) {
    requests[index].resolve({ ok: true, json: async () => payload });
  }
  async function read(payload) {
    const pending = context.loadAppVersionInfo();
    json(requests.length - 1, payload);
    await pending;
  }
  function snapshot() {
    return {
      state: JSON.stringify(state.appVersion),
      label: els.appVersionLabel.textContent, labelTitle: els.appVersionLabel.title,
      button: els.openUpdateButton.textContent, buttonTitle: els.openUpdateButton.title,
      hidden: els.openUpdateButton.classList.contains("hidden"),
      busy: els.openUpdateButton.getAttribute("aria-busy"),
      disabled: els.openUpdateButton.getAttribute("aria-disabled"),
    };
  }
  return { context, els, state, document, requests, errors, intervals, timers, calls, json, read, snapshot };
}

test("actual startup completes with one pending read and keeps the update action hidden", async () => {
  const f = fixture();
  await f.context.init();
  assert.equal(f.requests.length, 1);
  assert.equal(f.state.appVersion, null);
  assert.equal(f.els.appVersionLabel.textContent, "v...");
  assert.equal(f.els.openUpdateButton.classList.contains("hidden"), true);
  assert.equal(f.els.openUpdateButton.listeners.get("click").length, 1);
  assert.equal(f.els.openUpdateButton.listeners.get("click")[0], f.context.performSelfUpdate);
  assert.ok(f.calls.includes("connectEvents"));
  assert.ok(f.calls.includes("initCliPathOnboarding"));
  assert.equal(f.intervals.length, 1);
  f.json(0, AVAILABLE); await nextTurn();
  assert.equal(f.els.appVersionLabel.textContent, "v0.3.2");
  assert.equal(f.els.appVersionLabel.title, "Current version 0.3.2");
  assert.equal(f.els.openUpdateButton.title, "Update to v9.9.9");
  assert.equal(f.els.openUpdateButton.classList.contains("hidden"), false);
  assert.equal(f.els.openUpdateButton.getAttribute("aria-busy"), null);
  assert.equal(f.els.openUpdateButton.getAttribute("aria-disabled"), null);
  assert.equal(f.requests.length, 1);
  assert.deepEqual(f.errors, []);
});

test("startup read failure is caught without failing application initialization or revealing Update", async () => {
  const f = fixture();
  await f.context.init();
  const initial = f.snapshot();
  f.requests[0].reject(new Error("Synthetic offline metadata"));
  await nextTurn();
  assert.deepEqual(f.snapshot(), initial);
  assert.equal(f.errors.length, 1);
  assert.match(f.errors[0][0].message, /Synthetic offline metadata/);
  assert.ok(f.calls.includes("renderDashboard"));
  assert.equal(f.requests.length, 1);
});

test("sequential reads replace optional version data and keep current and available versions distinct", async () => {
  const f = fixture();
  await f.read({ ...AVAILABLE });
  await f.read({ current_version: "0.3.2", update_available: false, self_update_supported: false });
  assert.equal(f.state.appVersion.latest_version, undefined);
  assert.equal(f.state.appVersion.latest_release_url, undefined);
  assert.equal(f.els.openUpdateButton.classList.contains("hidden"), true);
  assert.equal(f.els.appVersionLabel.textContent, "v0.3.2");
  await f.read({ ...AVAILABLE, latest_version: "v10.0.0", self_update_supported: false });
  assert.equal(f.els.openUpdateButton.title, "Update to v10.0.0");
  assert.equal(f.els.openUpdateButton.classList.contains("hidden"), false);
  assert.equal(f.state.appVersion.self_update_supported, false);
  assert.equal(f.requests.length, 3);
});

for (const latest of [undefined, null, ""]) {
  test(`missing/empty optional latest version (${String(latest)}) uses the generic available tooltip`, async () => {
    const f = fixture();
    const payload = { ...AVAILABLE, latest_version: latest };
    if (latest === undefined) delete payload.latest_version;
    delete payload.latest_release_url;
    await f.read(payload);
    assert.equal(f.els.openUpdateButton.title, "Update available");
    assert.equal(f.els.appVersionLabel.textContent, "v0.3.2");
    assert.equal(f.els.openUpdateButton.classList.contains("hidden"), false);
    assert.equal(f.requests.length, 1);
  });
}

for (const supported of [true, false]) {
  test(`explicit self-update support=${supported} survives reads without starting a platform action`, async () => {
    const f = fixture();
    await f.read({ ...AVAILABLE, self_update_supported: supported });
    assert.equal(f.state.appVersion.self_update_supported, supported);
    assert.equal(f.els.openUpdateButton.textContent, "Update");
    assert.equal(f.els.openUpdateButton.getAttribute("aria-busy"), null);
    assert.equal(f.requests.length, 1);
  });
}

for (const url of [undefined, null, "", "not a URL", 42, { unexpected: true }]) {
  test(`optional release URL ${JSON.stringify(url)} is never interpreted by status display`, async () => {
    const f = fixture();
    await f.read({ ...AVAILABLE, latest_release_url: url, self_update_supported: false });
    assert.equal(f.els.openUpdateButton.title, "Update to v9.9.9");
    assert.equal(f.els.appVersionLabel.textContent, "v0.3.2");
    assert.equal(f.requests.length, 1);
  });
}

test("optional release title is displayed literally without inserting markup", async () => {
  const f = fixture();
  await f.read({ ...AVAILABLE, latest_version: '<b>v9.9.9</b> "synthetic"' });
  assert.equal(f.els.openUpdateButton.title, 'Update to <b>v9.9.9</b> "synthetic"');
  assert.equal(f.els.appVersionLabel.textContent, "v0.3.2");
});

for (const failure of ["network", "http", "json"]) {
  test(`${failure} failure preserves the last valid displayed identity and does not retry`, async () => {
    const f = fixture();
    await f.read({ ...AVAILABLE, self_update_supported: false });
    const initial = f.snapshot();
    const pending = f.context.loadAppVersionInfo();
    if (failure === "network") f.requests[1].reject(new Error("Synthetic network failure"));
    else if (failure === "http") f.requests[1].resolve({ ok: false, text: async () => "Synthetic HTTP failure" });
    else f.requests[1].resolve({ ok: true, json: async () => { throw new Error("Synthetic JSON failure"); } });
    await assert.rejects(pending, /Synthetic .* failure/);
    assert.deepEqual(f.snapshot(), initial);
    assert.equal(f.requests.length, 2);
  });
}

test("an earlier rejected read cannot overwrite a later successful read", async () => {
  const f = fixture();
  const older = f.context.loadAppVersionInfo();
  const rejected = assert.rejects(older, /Synthetic older failure/);
  await f.read({ ...AVAILABLE, latest_version: "v10.0.0" });
  const current = f.snapshot();
  f.requests[0].reject(new Error("Synthetic older failure"));
  await rejected;
  assert.deepEqual(f.snapshot(), current);
  assert.equal(f.requests.length, 2);
});

for (const completion of ["success", "failure"]) {
  test(`Settings close/reopen while startup status is pending preserves focus on ${completion}`, async () => {
    const f = fixture();
    await f.context.init();
    const open = f.els.openDisplaySettingsButton, close = f.els.closeDisplaySettingsButton;
    open.dispatch("click");
    assert.equal(f.document.activeElement, close);
    close.dispatch("click");
    assert.equal(f.document.activeElement, open);
    open.dispatch("click");
    assert.equal(f.document.activeElement, close);
    if (completion === "success") f.json(0, AVAILABLE);
    else f.requests[0].reject(new Error("Synthetic deferred status failure"));
    await nextTurn();
    assert.equal(f.document.activeElement, close);
    assert.equal(f.els.displaySettingsModal.classList.contains("hidden"), false);
    assert.equal(f.els.openUpdateButton.classList.contains("hidden"), completion === "failure");
    // The registered backdrop callback uses the same close path.
    f.els.displaySettingsModal.dispatch("click");
    assert.equal(f.els.displaySettingsModal.classList.contains("hidden"), true);
    assert.equal(f.document.activeElement, open);
    assert.equal(f.requests.length, 1, "Opening Settings does not refresh version status");
  });
}

test("repeated Settings open/close after a successful read neither reloads nor changes version feedback", async () => {
  const f = fixture();
  await f.context.init(); f.json(0, AVAILABLE); await nextTurn();
  const initial = f.snapshot();
  for (let n = 0; n < 3; n += 1) {
    f.els.openDisplaySettingsButton.dispatch("click");
    f.els.closeDisplaySettingsButton.dispatch("click");
  }
  assert.deepEqual(f.snapshot(), initial);
  assert.equal(f.requests.length, 1);
});
