// Synthetic filter dialog and persistence checks; no app bootstrap or traffic.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");
const indexSource = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");

function fixture() {
  const writes = [], refreshes = [], notices = [], timers = new Map();
  let timerId = 0, selectionClears = 0;
  const document = { activeElement: null, getElementById: () => null };
  function element(tagName = "INPUT") {
    const classes = new Set(), handlers = new Map();
    const node = {
      tagName, type: tagName === "INPUT" ? "text" : "button", value: "", checked: false,
      tabIndex: 0, disabled: false, isConnected: true, visibility: "visible", children: [],
      classList: {
        add: value => classes.add(value), remove: value => classes.delete(value), contains: value => classes.has(value),
        toggle(value, enabled) { if (enabled ?? !classes.has(value)) classes.add(value); else classes.delete(value); },
      },
      focus() { document.activeElement = node; }, getClientRects: () => [1],
      querySelectorAll: selector => selector === "input" ? node.children.filter(child => child.tagName === "INPUT") : node.children,
      addEventListener(type, callback) {
        if (!handlers.has(type)) handlers.set(type, []);
        handlers.get(type).push(callback);
      },
      listenerCount: type => handlers.get(type)?.length || 0,
      dispatch(type, event = {}) {
        let result;
        for (const handler of handlers.get(type) || []) result = handler({ target: node, ...event });
        return result;
      },
    };
    return node;
  }
  const els = {};
  for (const key of [
    "filterInScopeOnly", "filterHideWithoutResponses", "filterOnlyParameterized", "filterOnlyNotes",
    "filterSearchTerm", "filterRegex", "filterCaseSensitive", "filterNegativeSearch",
    "filterMimeHtml", "filterMimeScript", "filterMimeJson", "filterMimeCss", "filterMimeImage", "filterMimeWebsocket", "filterMimeOther",
    "filterStatus2xx", "filterStatus3xx", "filterStatus4xx", "filterStatus5xx", "filterStatusOther",
    "filterHiddenExtensions", "filterPort",
  ]) {
    els[key] = element();
    const input = indexSource.match(new RegExp(`<input id="${key}" type="([^"]+)"`));
    assert.ok(input, `Missing Filter input: ${key}`);
    els[key].type = input[1];
  }
  for (const key of ["closeFilterModalButton", "openFilterSettingsButton", "resetFilterSettingsButton", "applyFilterSettingsButton"])
    els[key] = element("BUTTON");
  for (const key of ["filterModal", "displaySettingsModal", "curlImportModal"]) {
    els[key] = element("DIV"); els[key].classList.add("hidden");
  }
  els.filterModal.children = [els.closeFilterModalButton, ...Object.values(els).filter(node => node.tagName === "INPUT"), els.resetFilterSettingsButton, els.applyFilterSettingsButton];
  els.historyMeta = element("DIV");
  els.historyMeta.textContent = "Filter settings: saved summary";
  els.colorTagFilter = element("DIV");
  els.colorTagFilter.children = ["red", "blue"].map(color => ({ ...element("BUTTON"), dataset: { color } }));
  document.activeElement = els.openFilterSettingsButton;
  document.querySelector = () => els.openFilterSettingsButton;
  const state = { displaySettings: {}, historyColumnWidths: {}, historyColumnOrder: [], wsColumnWidths: {} };
  const context = loadFunctions([
    "createDefaultFilterSettings", "openFilterModal", "closeFilterModal", "isModalVisible", "restoreModalFocus", "trapModalFocus", "getActiveModalAction",
    "hydrateFilterForm", "applyFilterSettings", "syncColorTagFilterUI", "truncateUiSettingsText", "sanitizeHttpFilterSettings", "sanitizeHttpBooleanMap", "sanitizeHttpColorTags", "serializeHttpFilterSettings",
    "loadUiSettings", "applyUiSettingsSnapshot", "updateUiSettingsServerRevision", "snapshotUiSettings", "nextUiSettingsSnapshot", "scheduleUiSettingsSave", "scheduleUiSettingsRetry", "persistUiSettings",
  ], {
    state, els, document, activeConfirmDialog: null, filterSettingsReturnFocus: null, filterSettingsEditedControls: new Set(),
    uiSettingsClientId: "fixture-client", uiSettingsSaveVersion: 0, uiSettingsServerRevision: 0,
    uiSettingsDirty: false, uiSettingsInFlight: false, uiSettingsSavePromise: null, uiSettingsSaveTimer: null, lastUiSettingsPayload: null,
    HTTP_COLOR_TAG_OPTIONS: new Set(["red", "orange", "yellow", "green", "blue", "purple"]), WS_COLUMN_RULES: {},
    window: {
      setTimeout(callback) { timers.set(++timerId, callback); return timerId; },
      clearTimeout(id) { timers.delete(id); }, getComputedStyle: node => ({ visibility: node.visibility }),
    },
    fetch: async (url, options) => { writes.push(JSON.parse(options.body)); return { ok: true, json: async () => writes.at(-1) }; },
    showToast: (...args) => notices.push(args), scheduleRefresh: options => refreshes.push(options),
    clearHttpHistorySelectionPreview: () => selectionClears++, syncHttpInScopePill() {}, syncHttpCapturePill() {},
    sanitizeDisplaySettings: value => value, sanitizeActiveTool: value => value || "proxy", sanitizeActiveProxyTab: value => value || "http-history",
    sanitizeHistoryColumnWidths: value => value || {}, sanitizeHistoryColumnOrder: value => value || [],
    sanitizeHttpQuery: value => value || "", sanitizeHttpMethod: value => value || "", sanitizeHttpSortKey: value => value || "index", sanitizeHttpSortDirection: value => value || "desc",
    sanitizeWorkbenchHeight: () => null, sanitizeWorkbenchPaneWidths: () => null, sanitizeWebsocketPaneWidth: () => null,
    sanitizeWebsocketQuery: () => "", sanitizeWebsocketSortKey: () => "started_at", sanitizeWebsocketSortDirection: () => "desc",
    sanitizeWebsocketStackHeight: () => null, sanitizeWsReplayLeftWidth: () => null, sanitizeWsReplayFrameDetailHeight: () => null,
    serializeWorkbenchPaneWidths: () => ({}), applyDisplaySettingsState() {}, renderHistoryHeader() {}, applyHistoryColumnWidths() {}, applyWsColumnWidths() {},
    updateWebsocketSortIndicators() {}, applySavedWorkbenchPaneWidths() {}, applySavedWebsocketPaneWidth() {}, applySavedWebsocketStackHeight() {}, applySavedWsReplayLayout() {},
  });
  state.filterSettings = context.createDefaultFilterSettings();
  state.filterSettings.searchTerm = "saved";
  state.filterSettings.onlyNotes = true;
  state.filterSettings.colorTags.add("red");
  const start = appSource.indexOf('  els.openFilterSettingsButton.addEventListener("click",');
  const end = appSource.indexOf('  document.getElementById("closeCompareButton")', start);
  assert.ok(start !== -1 && end > start);
  vm.runInContext(appSource.slice(start, end), context);
  document.addEventListener = (_, handler) => { context.keydown = handler; };
  const keyStart = appSource.indexOf('  document.addEventListener("keydown", (event) => {\n    const activeModalAction');
  const keyEnd = appSource.indexOf('    if (\n      !event.defaultPrevented', keyStart);
  vm.runInContext(appSource.slice(keyStart, keyEnd) + "  });", context);
  return {
    context, state, els, document, timers, writes, refreshes, notices,
    get selectionClears() { return selectionClears; },
    async save() { context.uiSettingsDirty = true; await context.persistUiSettings(); },
    key(key, target = document.activeElement, options = {}) {
      const event = { key, target, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, ...options };
      context.keydown(event);
      if (key === "Enter" && !event.defaultPrevented && target?.tagName === "BUTTON") target.dispatch("click");
      return event;
    },
  };
}

test("Filter Close discards edits, and reopening restores the applied settings", () => {
  const f = fixture(); f.context.openFilterModal();
  f.els.filterSearchTerm.value = "unapplied"; f.els.filterOnlyNotes.checked = false;
  f.context.closeFilterModal(); f.context.openFilterModal();
  assert.equal(f.els.filterSearchTerm.value, "saved"); assert.equal(f.els.filterOnlyNotes.checked, true);
  assert.equal(f.context.uiSettingsDirty, false); assert.equal(f.refreshes.length, 0);
});

test("Filter Apply saves validated values once and preserves toolbar color tags", async () => {
  const f = fixture(); f.context.openFilterModal();
  f.els.filterSearchTerm.value = "  applied  "; f.els.filterOnlyNotes.checked = false;
  f.context.applyFilterSettings();
  assert.equal(f.els.filterModal.classList.contains("hidden"), true);
  assert.equal(f.state.filterSettings.searchTerm, "applied"); assert.equal(f.state.filterSettings.onlyNotes, false);
  assert.deepEqual([...f.state.filterSettings.colorTags], ["red"]);
  assert.equal(f.refreshes.length, 1); assert.equal(f.selectionClears, 1);
  await f.context.persistUiSettings();
  assert.equal(f.writes.length, 1); assert.equal(f.writes[0].http_filter_settings.search_term, "applied");
});

for (const invalid of ["status", "MIME", "regex"]) {
  test(`invalid ${invalid} Filter Apply leaves the draft open without saving`, () => {
    const f = fixture(); f.context.openFilterModal();
    if (invalid === "status") for (const [key, node] of Object.entries(f.els)) if (key.startsWith("filterStatus")) node.checked = false;
    if (invalid === "MIME") for (const [key, node] of Object.entries(f.els)) if (key.startsWith("filterMime")) node.checked = false;
    if (invalid === "regex") { f.els.filterRegex.checked = true; f.els.filterSearchTerm.value = "["; }
    f.context.applyFilterSettings();
    assert.equal(f.els.filterModal.classList.contains("hidden"), false);
    assert.equal(f.state.filterSettings.searchTerm, "saved"); assert.equal(f.context.uiSettingsDirty, false);
    assert.equal(f.refreshes.length, 0); assert.equal(f.notices.length, 1);
  });
}

test("Filter Reset immediately applies defaults, and Close keeps that reset", async () => {
  const f = fixture(); f.context.openFilterModal();
  f.els.filterSearchTerm.value = "unapplied";
  f.els.resetFilterSettingsButton.dispatch("click");
  assert.equal(f.state.filterSettings.searchTerm, ""); assert.equal(f.els.filterSearchTerm.value, "");
  assert.equal(f.state.filterSettings.colorTags.size, 0); assert.equal(f.refreshes.length, 1);
  assert.equal(f.els.filterModal.classList.contains("hidden"), false);
  f.context.closeFilterModal(); await f.context.persistUiSettings();
  assert.equal(f.writes[0].http_filter_settings.search_term, "");
});

for (const failure of ["network", "server"]) {
  test(`a ${failure} settings-save failure preserves applied filters and a reopened draft through retry`, async () => {
    const f = fixture(); f.context.openFilterModal(); f.els.filterSearchTerm.value = "applied"; f.context.applyFilterSettings();
    let calls = 0;
    f.context.fetch = async (_, options) => {
      const payload = JSON.parse(options.body); f.writes.push(payload);
      if (++calls === 1) {
        if (failure === "network") throw new Error("Synthetic network failure");
        return { ok: false, text: async () => "Synthetic server failure" };
      }
      return { ok: true, json: async () => payload };
    };
    await assert.rejects(f.context.persistUiSettings(), /Synthetic/);
    assert.equal(f.context.uiSettingsDirty, true); assert.equal(f.context.uiSettingsSavePromise, null);
    f.context.openFilterModal(); assert.equal(f.els.filterSearchTerm.value, "applied");
    f.els.filterSearchTerm.value = "new draft";
    await f.context.persistUiSettings();
    assert.equal(f.els.filterSearchTerm.value, "new draft"); assert.equal(f.state.filterSettings.searchTerm, "applied");
    assert.equal(f.writes.at(-1).http_filter_settings.search_term, "applied"); assert.equal(f.context.uiSettingsDirty, false);
  });
}

test("a retry conflict adopts saved settings without replacing an open Filter draft", async () => {
  const f = fixture(); f.context.openFilterModal(); f.els.filterSearchTerm.value = "applied"; f.context.applyFilterSettings();
  f.context.fetch = async () => { throw new Error("Synthetic network failure"); };
  await assert.rejects(f.context.persistUiSettings(), /Synthetic/);
  f.context.openFilterModal(); f.els.filterSearchTerm.value = "new draft"; f.els.filterOnlyNotes.checked = false;
  f.context.fetch = async () => ({ ok: true, json: async () => ({ client_id: "another-client", client_version: 2, server_revision: 3, http_filter_settings: { search_term: "other saved", only_notes: true } }) });
  await f.context.persistUiSettings();
  assert.equal(f.state.filterSettings.searchTerm, "other saved", "retain the existing server conflict policy");
  assert.equal(f.els.filterSearchTerm.value, "new draft", "a background response must not erase unsubmitted edits");
  assert.equal(f.els.filterOnlyNotes.checked, false);
  f.context.closeFilterModal(); f.context.openFilterModal();
  assert.equal(f.els.filterSearchTerm.value, "other saved"); assert.equal(f.els.filterOnlyNotes.checked, true);
});

test("reopening an already open Filter dialog preserves its draft", () => {
  const f = fixture(); f.context.openFilterModal(); f.els.filterSearchTerm.value = "new draft";
  f.context.openFilterModal(); assert.equal(f.els.filterSearchTerm.value, "new draft");
});

test("Filter opens with focus inside, traps Tab, and restores focus on dismissal", () => {
  const f = fixture(); f.context.openFilterModal();
  assert.equal(f.document.activeElement, f.els.closeFilterModalButton);
  f.els.applyFilterSettingsButton.focus(); f.key("Tab");
  assert.equal(f.document.activeElement, f.els.closeFilterModalButton);
  f.key("Tab", f.document.activeElement, { shiftKey: true });
  assert.equal(f.document.activeElement, f.els.applyFilterSettingsButton);
  f.key("Escape"); assert.equal(f.document.activeElement, f.els.openFilterSettingsButton);
  assert.equal(f.els.filterModal.classList.contains("hidden"), true); assert.equal(f.context.uiSettingsDirty, false);
});

test("a background settings snapshot keeps an open draft until explicit Apply", async () => {
  const f = fixture(); f.context.openFilterModal();
  f.els.filterSearchTerm.value = "new draft"; f.els.filterOnlyNotes.checked = false;
  f.context.applyUiSettingsSnapshot({ server_revision: 7, http_filter_settings: { search_term: "loaded", only_notes: true } });
  assert.equal(f.els.filterSearchTerm.value, "new draft"); assert.equal(f.els.filterOnlyNotes.checked, false);
  f.context.applyFilterSettings(); await f.context.persistUiSettings();
  assert.equal(f.writes[0].server_revision, 7);
  assert.equal(f.writes[0].http_filter_settings.search_term, "new draft");
  assert.equal(f.writes[0].http_filter_settings.only_notes, false);
});

test("a settings snapshot still hydrates a closed Filter dialog", () => {
  const f = fixture();
  f.context.applyUiSettingsSnapshot({ http_filter_settings: { search_term: "loaded", only_notes: true } });
  assert.equal(f.els.filterSearchTerm.value, "loaded"); assert.equal(f.els.filterOnlyNotes.checked, true);
});

test("a settings snapshot updates toolbar colors while preserving the open Filter draft", () => {
  const f = fixture(); f.context.openFilterModal(); f.els.filterSearchTerm.value = "new draft";
  const [red, blue] = f.els.colorTagFilter.children;
  assert.equal(red.classList.contains("active"), true);
  f.context.applyUiSettingsSnapshot({ http_filter_settings: { search_term: "loaded", color_tags: ["blue"] } });
  assert.equal(f.els.filterSearchTerm.value, "new draft");
  assert.equal(red.classList.contains("active"), false); assert.equal(blue.classList.contains("active"), true);
  f.context.applyFilterSettings();
  assert.deepEqual([...f.state.filterSettings.colorTags], ["blue"]);
});

for (const action of ["Close", "backdrop", "Escape"]) {
  test(`${action} dismisses Filter without applying its draft or stealing focus later`, () => {
    const f = fixture(); f.context.openFilterModal(); f.els.filterSearchTerm.value = "unapplied";
    if (action === "Close") f.key("Enter", f.els.closeFilterModalButton);
    else if (action === "backdrop") f.els.filterModal.dispatch("click");
    else f.key("Escape");
    assert.equal(f.state.filterSettings.searchTerm, "saved"); assert.equal(f.context.uiSettingsDirty, false);
    assert.equal(f.els.filterModal.classList.contains("hidden"), true);
    assert.equal(f.document.activeElement, f.els.openFilterSettingsButton);
    f.els.historyMeta.focus(); f.context.closeFilterModal();
    assert.equal(f.document.activeElement, f.els.historyMeta);
  });
}

test("Enter in Filter search applies once, while Enter on Reset keeps its own action", () => {
  const f = fixture(); f.context.openFilterModal(); f.els.filterSearchTerm.value = "applied";
  f.key("Enter", f.els.filterSearchTerm);
  assert.equal(f.refreshes.length, 1); assert.equal(f.state.filterSettings.searchTerm, "applied");
  f.context.openFilterModal(); f.key("Enter", f.els.resetFilterSettingsButton);
  assert.equal(f.refreshes.length, 2); assert.equal(f.state.filterSettings.searchTerm, "");
  assert.equal(f.els.filterModal.classList.contains("hidden"), false);
});

test("Filter Close restores a valid fallback when its original invoker is detached", () => {
  const f = fixture(); f.els.historyMeta.focus(); f.context.openFilterModal();
  f.els.historyMeta.isConnected = false; f.context.closeFilterModal();
  assert.equal(f.document.activeElement, f.els.openFilterSettingsButton);
});


const savedInitialFilters = {
  in_scope_only: true, hide_without_responses: true, only_parameterized: true, only_notes: true,
  search_term: "saved search", regex: true, case_sensitive: true, negative_search: true,
  mime: { html: false, script: true, json: false, css: false, image: false, websocket: false, other: true },
  status: { success: false, redirect: true, client_error: false, server_error: false, other: true },
  hidden_extensions: "png,css", port: "8443", color_tags: ["blue"],
};

function startInitialSettingsLoad(f, filters = savedInitialFilters) {
  let resolveResponse;
  const response = new Promise(resolve => { resolveResponse = resolve; });
  const post = f.context.fetch;
  f.context.fetch = (url, options) => options?.method === "POST" ? post(url, options) : response;
  const pending = f.context.loadUiSettings();
  return async () => {
    resolveResponse({ ok: true, json: async () => ({ server_revision: 7, http_filter_settings: filters }) });
    await pending;
  };
}

function startupFixture() {
  const f = fixture();
  f.state.filterSettings = f.context.createDefaultFilterSettings();
  return f;
}

function editControl(f, key, value, event = "input") {
  const control = f.els[key];
  control[control.type === "checkbox" ? "checked" : "value"] = value;
  control.dispatch(event);
}

test("the initial settings GET fills every untouched control in an already open Filter draft", async () => {
  const f = startupFixture(), finishLoad = startInitialSettingsLoad(f);
  f.els.openFilterSettingsButton.dispatch("click");
  await finishLoad();
  assert.equal(f.writes.length, 0); assert.equal(f.refreshes.length, 0);
  assert.equal(f.context.uiSettingsDirty, false);
  assert.equal(f.document.activeElement, f.els.closeFilterModalButton);
  assert.equal(f.els.filterModal.classList.contains("hidden"), false);
  f.els.applyFilterSettingsButton.dispatch("click"); await f.context.persistUiSettings();
  assert.equal(f.writes.length, 1);
  assert.equal(f.writes[0].server_revision, 7);
  assert.deepEqual(f.writes[0].http_filter_settings, savedInitialFilters);
});

test("the initial settings GET merges untouched fields with explicit Filter edits", async () => {
  const f = startupFixture(), finishLoad = startInitialSettingsLoad(f);
  f.context.openFilterModal();
  editControl(f, "filterSearchTerm", "typed search");
  editControl(f, "filterOnlyNotes", true, "change");
  editControl(f, "filterOnlyNotes", false, "change");
  editControl(f, "filterHiddenExtensions", "jpg");
  editControl(f, "filterHiddenExtensions", "");
  editControl(f, "filterMimeHtml", false, "change");
  editControl(f, "filterMimeHtml", true, "change");
  editControl(f, "filterStatus2xx", false, "change");
  editControl(f, "filterStatus2xx", true, "change");
  await finishLoad();
  f.context.applyFilterSettings(); await f.context.persistUiSettings();
  assert.deepEqual(f.writes[0].http_filter_settings, {
    ...savedInitialFilters, search_term: "typed search", only_notes: false, hidden_extensions: "",
    mime: { ...savedInitialFilters.mime, html: true }, status: { ...savedInitialFilters.status, success: true },
  });
});

const filterControlPaths = [
  ["filterInScopeOnly", "in_scope_only"], ["filterHideWithoutResponses", "hide_without_responses"],
  ["filterOnlyParameterized", "only_parameterized"], ["filterOnlyNotes", "only_notes"],
  ["filterSearchTerm", "search_term"], ["filterRegex", "regex"], ["filterCaseSensitive", "case_sensitive"],
  ["filterNegativeSearch", "negative_search"], ["filterHiddenExtensions", "hidden_extensions"], ["filterPort", "port"],
  ["filterMimeHtml", "mime", "html"], ["filterMimeScript", "mime", "script"], ["filterMimeJson", "mime", "json"],
  ["filterMimeCss", "mime", "css"], ["filterMimeImage", "mime", "image"],
  ["filterMimeWebsocket", "mime", "websocket"], ["filterMimeOther", "mime", "other"],
  ["filterStatus2xx", "status", "success"], ["filterStatus3xx", "status", "redirect"],
  ["filterStatus4xx", "status", "client_error"], ["filterStatus5xx", "status", "server_error"],
  ["filterStatusOther", "status", "other"],
];

for (const [controlKey, field, nestedField] of filterControlPaths) {
  for (const event of ["input", "change"]) {
    test(`initial settings merge preserves ${controlKey} edited back to its default via ${event}`, async () => {
      const f = startupFixture();
      const expected = structuredClone(savedInitialFilters);
      if (nestedField) expected[field][nestedField] = false;
      const finishLoad = startInitialSettingsLoad(f, expected);
      f.context.openFilterModal();
      const control = f.els[controlKey];
      const original = control.type === "checkbox" ? control.checked : control.value;
      editControl(f, controlKey, typeof original === "boolean" ? !original : "temporary", event);
      editControl(f, controlKey, original, event);
      await finishLoad();
      assert.equal(control.type === "checkbox" ? control.checked : control.value, original);
      if (nestedField) expected[field][nestedField] = original;
      else expected[field] = original;
      f.context.applyFilterSettings(); await f.context.persistUiSettings();
      assert.deepEqual(f.writes[0].http_filter_settings, expected);
    });
  }
}

test("Reset remains explicit for every Filter control when the initial settings GET completes", async () => {
  const f = startupFixture(), finishLoad = startInitialSettingsLoad(f);
  f.context.openFilterModal(); editControl(f, "filterSearchTerm", "draft");
  f.els.resetFilterSettingsButton.dispatch("click");
  const defaults = JSON.parse(JSON.stringify(f.context.serializeHttpFilterSettings()));
  await finishLoad();
  assert.equal(f.els.filterSearchTerm.value, ""); assert.equal(f.els.filterOnlyNotes.checked, false);
  f.context.applyFilterSettings(); await f.context.persistUiSettings();
  assert.deepEqual(f.writes[0].http_filter_settings, { ...defaults, color_tags: ["blue"] });
});

test("closing and reopening before the initial GET discards the old Filter draft intent", async () => {
  const f = startupFixture(), finishLoad = startInitialSettingsLoad(f);
  f.context.openFilterModal(); editControl(f, "filterSearchTerm", "discarded");
  f.context.closeFilterModal(); f.context.openFilterModal(); await finishLoad();
  assert.equal(f.els.filterSearchTerm.value, "saved search");
  f.context.applyFilterSettings(); await f.context.persistUiSettings();
  assert.deepEqual(f.writes[0].http_filter_settings, savedInitialFilters);
});

test("reopening an already visible Filter keeps explicit edit tracking until initial GET completes", async () => {
  const f = startupFixture(), finishLoad = startInitialSettingsLoad(f);
  f.context.openFilterModal(); editControl(f, "filterSearchTerm", "typed");
  f.context.openFilterModal(); await finishLoad();
  assert.equal(f.els.filterSearchTerm.value, "typed"); assert.equal(f.els.filterPort.value, "8443");
});

test("a save-conflict snapshot still protects untouched open Filter draft controls", async () => {
  const f = fixture(); f.context.openFilterModal();
  f.context.applyUiSettingsSnapshot({ server_revision: 8, http_filter_settings: savedInitialFilters });
  assert.equal(f.els.filterSearchTerm.value, "saved"); assert.equal(f.els.filterPort.value, "");
  assert.equal(f.els.filterHideWithoutResponses.checked, false);
});


test("Filter edit listeners register once and draft intent clears on Close and Apply", async () => {
  const f = startupFixture();
  for (let i = 0; i < 3; i++) {
    f.context.openFilterModal(); editControl(f, "filterSearchTerm", `draft ${i}`);
    assert.equal(f.context.filterSettingsEditedControls.size, 1);
    f.context.closeFilterModal();
    assert.equal(f.context.filterSettingsEditedControls.size, 0);
  }
  for (const control of f.els.filterModal.querySelectorAll("input")) {
    assert.equal(control.listenerCount("input"), 1); assert.equal(control.listenerCount("change"), 1);
  }
  f.context.openFilterModal(); editControl(f, "filterSearchTerm", "applied");
  f.context.applyFilterSettings();
  assert.equal(f.context.filterSettingsEditedControls.size, 0);
  const finishLoad = startInitialSettingsLoad(f); await finishLoad();
  assert.equal(f.els.filterSearchTerm.value, "saved search");
});

test("Reset replaces earlier edit tracking with every control and Close clears that intent", () => {
  const f = startupFixture();
  f.context.openFilterModal(); editControl(f, "filterSearchTerm", "draft");
  f.els.resetFilterSettingsButton.dispatch("click");
  assert.equal(f.context.filterSettingsEditedControls.size, f.els.filterModal.querySelectorAll("input").length);
  f.context.closeFilterModal();
  assert.equal(f.context.filterSettingsEditedControls.size, 0);
  f.context.openFilterModal();
  assert.equal(f.context.filterSettingsEditedControls.size, 0);
});

test("retrying a failed initial settings GET merges untouched controls and preserves explicit edits", async () => {
  const f = startupFixture();
  f.context.console = { error() {} };
  f.context.fetch = async () => { throw new Error("Synthetic load failure"); };
  f.context.openFilterModal(); editControl(f, "filterSearchTerm", "typed before retry");
  await f.context.loadUiSettings();
  assert.equal(f.els.filterSearchTerm.value, "typed before retry");
  f.context.fetch = async (_, options) => {
    f.writes.push(JSON.parse(options.body)); return { ok: true, json: async () => f.writes.at(-1) };
  };
  const finishLoad = startInitialSettingsLoad(f); await finishLoad();
  assert.equal(f.els.filterPort.value, "8443"); assert.equal(f.els.filterSearchTerm.value, "typed before retry");
  f.context.applyFilterSettings(); await f.context.persistUiSettings();
  assert.deepEqual(f.writes[0].http_filter_settings, { ...savedInitialFilters, search_term: "typed before retry" });
});

test("Apply before the initial GET keeps its existing save and late-snapshot behavior", async () => {
  const f = startupFixture(), finishLoad = startInitialSettingsLoad(f);
  f.context.openFilterModal(); editControl(f, "filterSearchTerm", "early apply");
  f.context.applyFilterSettings(); await f.context.persistUiSettings();
  assert.equal(f.writes.length, 1); assert.equal(f.writes[0].http_filter_settings.search_term, "early apply");
  assert.equal(f.writes[0].server_revision, 0);
  await finishLoad();
  assert.equal(f.state.filterSettings.searchTerm, "saved search");
  assert.equal(f.els.filterSearchTerm.value, "saved search");
  assert.equal(f.writes.length, 1); assert.equal(f.context.uiSettingsDirty, false);
});
