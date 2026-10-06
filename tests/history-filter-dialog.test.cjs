// Synthetic filter dialog and persistence checks; no app bootstrap or traffic.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

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
      querySelectorAll: () => node.children,
      addEventListener(type, callback) { handlers.set(type, callback); },
      dispatch(type, event = {}) { return handlers.get(type)?.({ target: node, ...event }); },
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
  ]) els[key] = element();
  for (const key of ["closeFilterModalButton", "openFilterSettingsButton", "resetFilterSettingsButton", "applyFilterSettingsButton"])
    els[key] = element("BUTTON");
  for (const key of ["filterModal", "displaySettingsModal", "curlImportModal"]) {
    els[key] = element("DIV"); els[key].classList.add("hidden");
  }
  els.filterModal.children = [els.closeFilterModalButton, els.filterSearchTerm, els.resetFilterSettingsButton, els.applyFilterSettingsButton];
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
    "applyUiSettingsSnapshot", "updateUiSettingsServerRevision", "snapshotUiSettings", "nextUiSettingsSnapshot", "scheduleUiSettingsSave", "scheduleUiSettingsRetry", "persistUiSettings",
  ], {
    state, els, document, activeConfirmDialog: null, filterSettingsReturnFocus: null,
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

test("a delayed settings load keeps an open draft until explicit Apply", async () => {
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
