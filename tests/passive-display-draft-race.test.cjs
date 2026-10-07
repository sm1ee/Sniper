// Appearance form drafts only. DOM and snapshots are synthetic; no app starts.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

function modal() {
  const classes = new Set(["hidden"]);
  return { classList: {
    add: name => classes.add(name), remove: name => classes.delete(name),
    contains: name => classes.has(name),
  } };
}
function fixture() {
  const state = {
    displaySettings: { sizePx: 12, theme: "paper", uiFont: "plex", monoFont: "jetbrains" },
    wsColumnWidths: {},
  };
  const rootStyles = new Map(), writes = [], restored = [];
  const opener = {}, close = {};
  const document = {
    activeElement: opener, getElementById: () => null,
    documentElement: { style: { setProperty: (key, value) => rootStyles.set(key, value) } },
    body: { dataset: {} },
  };
  close.focus = () => { document.activeElement = close; };
  const els = {
    displaySettingsModal: modal(), filterModal: modal(),
    openDisplaySettingsButton: opener, closeDisplaySettingsButton: close,
    displayThemeSelect: {}, displaySizeInput: {}, displayUiFontSelect: {}, displayMonoFontSelect: {},
  };
  const globals = {
    state, els, document, displaySettingsPreviewActive: false, displaySettingsReturnFocus: null,
    uiSettingsServerRevision: 0, uiSettingsDirty: false, uiSettingsSaveTimer: null,
    window: { clearTimeout() {} }, WS_COLUMN_RULES: {},
    DISPLAY_THEME_OPTIONS: new Set(["charcoal", "paper", "ivory"]),
    DISPLAY_UI_FONT_OPTIONS: new Set(["plex", "system", "notokr"]),
    DISPLAY_MONO_FONT_OPTIONS: new Set(["jetbrains", "sfmono", "plexmono"]),
    clamp: (value, min, max) => Math.min(max, Math.max(min, value)),
    renderShortcutReference() {}, selectSettingsTab() {},
    restoreModalFocus: target => { restored.push(target); document.activeElement = target; },
    persistUiSettings: async () => { writes.push({ ...state.displaySettings }); },
    sanitizeHistoryColumnWidths: value => value || {}, sanitizeHistoryColumnOrder: value => value || [],
  };
  for (const name of [
    "sanitizeActiveTool", "sanitizeActiveProxyTab", "sanitizeHttpQuery", "sanitizeHttpMethod",
    "sanitizeHttpSortKey", "sanitizeHttpSortDirection", "sanitizeHttpFilterSettings",
    "sanitizeWorkbenchHeight", "sanitizeWorkbenchPaneWidths", "sanitizeWebsocketPaneWidth",
    "sanitizeWebsocketQuery", "sanitizeWebsocketSortKey", "sanitizeWebsocketSortDirection",
    "sanitizeWebsocketStackHeight", "sanitizeWsReplayLeftWidth", "sanitizeWsReplayFrameDetailHeight",
  ]) globals[name] = value => value;
  for (const name of [
    "hydrateFilterForm", "syncColorTagFilterUI", "syncHttpInScopePill", "syncHttpCapturePill",
    "renderHistoryHeader", "applyHistoryColumnWidths", "applyWsColumnWidths", "updateWebsocketSortIndicators",
    "applySavedWorkbenchPaneWidths", "applySavedWebsocketPaneWidth", "applySavedWebsocketStackHeight",
    "applySavedWsReplayLayout", "applyWorkbenchStackHeight",
  ]) globals[name] = () => {};
  const context = loadFunctions([
    "createDefaultDisplaySettings", "sanitizeDisplaySettings", "openDisplaySettingsModal", "closeDisplaySettingsModal",
    "hydrateDisplaySettingsForm", "collectDisplaySettingsFormValues", "previewDisplaySettingsFromForm",
    "saveDisplaySettingsFromForm", "applyDisplaySettingsState", "applyUiSettingsSnapshot",
    "updateUiSettingsServerRevision", "isModalVisible",
  ], globals);
  const remote = {
    server_revision: 7,
    display_settings: { size_px: 16, theme: "charcoal", ui_font: "notokr", mono_font: "plexmono" },
  };
  function draft(preview = true) {
    context.openDisplaySettingsModal();
    els.displayThemeSelect.value = "ivory";
    els.displaySizeInput.value = "18";
    els.displayUiFontSelect.value = "system";
    els.displayMonoFontSelect.value = "sfmono";
    if (preview) context.previewDisplaySettingsFromForm();
  }
  const values = () => [els.displayThemeSelect.value, els.displaySizeInput.value, els.displayUiFontSelect.value, els.displayMonoFontSelect.value];
  return { context, state, els, document, rootStyles, writes, restored, opener, remote, draft, values };
}

test("reopening visible display settings preserves draft, preview, and focus", () => {
  const f = fixture(); f.draft();
  f.document.activeElement = f.els.displaySizeInput;
  f.context.openDisplaySettingsModal();
  assert.deepEqual(f.values(), ["ivory", "18", "system", "sfmono"]);
  assert.equal(f.context.displaySettingsPreviewActive, true);
  assert.equal(f.document.body.dataset.theme, "ivory");
  assert.equal(f.document.activeElement, f.els.displaySizeInput);
  assert.equal(f.context.displaySettingsReturnFocus, f.opener);
  assert.equal(f.writes.length, 0);
});

test("a background settings snapshot preserves the open appearance preview", () => {
  const f = fixture(); f.draft();
  f.context.applyUiSettingsSnapshot(f.remote);
  assert.deepEqual(f.values(), ["ivory", "18", "system", "sfmono"]);
  assert.equal(f.document.body.dataset.theme, "ivory");
  assert.equal(f.document.body.dataset.uiFont, "system");
  assert.equal(f.document.body.dataset.monoFont, "sfmono");
  assert.equal(f.rootStyles.get("--ui-root-size"), "16px", "unapplied text size is not a live preview");
  assert.equal(f.state.displaySettings.theme, "charcoal", "the server winner remains the committed baseline");
  assert.equal(f.context.uiSettingsServerRevision, 7);
  assert.equal(f.writes.length, 0);
});

for (const preview of [false, true]) {
  test(`late startup hydration preserves an open ${preview ? "preview" : "unpreviewed"} appearance draft`, async () => {
    const f = fixture(); f.draft(preview);
    f.context.loadUiSettings = async () => f.context.applyUiSettingsSnapshot(f.remote);
    const start = appSource.indexOf("  await loadUiSettings();");
    const end = appSource.indexOf("  await loadSessions();", start);
    assert.ok(start !== -1 && end > start);
    await vm.runInContext(`(async () => {${appSource.slice(start, end)}})()`, f.context);
    assert.deepEqual(f.values(), ["ivory", "18", "system", "sfmono"]);
    if (preview) assert.equal(f.document.body.dataset.theme, "ivory");
    assert.equal(f.writes.length, 0);
  });
}

test("late startup hydration still refreshes a closed appearance form", async () => {
  const f = fixture();
  f.context.loadUiSettings = async () => f.context.applyUiSettingsSnapshot(f.remote);
  const start = appSource.indexOf("  await loadUiSettings();");
  const end = appSource.indexOf("  await loadSessions();", start);
  await vm.runInContext(`(async () => {${appSource.slice(start, end)}})()`, f.context);
  assert.deepEqual(f.values(), ["charcoal", "16", "notokr", "plexmono"]);
  assert.equal(f.document.body.dataset.theme, "charcoal");
});

test("closing a preserved preview restores the latest committed appearance", () => {
  const f = fixture(); f.draft();
  f.context.applyUiSettingsSnapshot(f.remote);
  f.context.closeDisplaySettingsModal();
  assert.equal(f.context.displaySettingsPreviewActive, false);
  assert.equal(f.document.body.dataset.theme, "charcoal");
  assert.equal(f.rootStyles.get("--ui-root-size"), "16px");
  assert.deepEqual(f.values(), ["charcoal", "16", "notokr", "plexmono"]);
  assert.equal(f.context.isModalVisible(f.els.displaySettingsModal), false);
  assert.equal(f.document.activeElement, f.opener);
  assert.equal(f.writes.length, 0);
});

test("Apply commits a preserved appearance draft exactly once", () => {
  const f = fixture(); f.draft();
  f.context.applyUiSettingsSnapshot(f.remote);
  f.context.saveDisplaySettingsFromForm();
  assert.equal(f.writes.length, 1);
  assert.deepEqual(f.writes[0], { sizePx: 18, theme: "ivory", uiFont: "system", monoFont: "sfmono" });
  assert.equal(f.document.body.dataset.theme, "ivory");
  assert.equal(f.rootStyles.get("--ui-root-size"), "18px");
  assert.equal(f.context.displaySettingsPreviewActive, false);
  assert.equal(f.context.isModalVisible(f.els.displaySettingsModal), false);
});

test("a closed appearance form ignores a stale preview flag", () => {
  const f = fixture();
  f.context.displaySettingsPreviewActive = true;
  f.context.applyUiSettingsSnapshot(f.remote);
  assert.equal(f.document.body.dataset.theme, "charcoal");
  assert.equal(f.rootStyles.get("--ui-root-size"), "16px");
});
