function createDefaultFilterSettings() {
  return {
    inScopeOnly: false,
    hideWithoutResponses: false,
    onlyParameterized: false,
    onlyNotes: false,
    searchTerm: "",
    regex: false,
    caseSensitive: false,
    negativeSearch: false,
    mime: {
      html: true,
      script: true,
      json: true,
      css: true,
      image: true,
      other: true,
    },
    status: {
      success: true,
      redirect: true,
      clientError: true,
      serverError: true,
      other: true,
    },
    hiddenExtensions: "png,ico,css,woff,woff2,ttf,svg,jpg,jpeg,gif",
    port: "",
    colorTags: new Set(),
  };
}

function createDefaultDisplaySettings() {
  return {
    sizePx: 12,
    theme: "charcoal",
    uiFont: "plex",
    monoFont: "jetbrains",
  };
}

function createDefaultHistoryColumnWidths() {
  return Object.fromEntries(
    Object.entries(HISTORY_COLUMN_RULES).map(([key, limits]) => [key, limits.default]),
  );
}

const DISPLAY_THEME_OPTIONS = new Set([
  "charcoal",
  "black",
  "graphite",
  "midnight",
  "slate",
  "obsidian",
  "dusk",
  "white",
  "paper",
]);
const DISPLAY_UI_FONT_OPTIONS = new Set(["plex", "system", "pretendard", "notokr", "applekr", "nanumgothic"]);
const DISPLAY_MONO_FONT_OPTIONS = new Set([
  "jetbrains",
  "sfmono",
  "plexmono",
  "d2coding",
  "nanumgothiccoding",
  "notomonokr",
]);
const HISTORY_COLUMN_RULES = {
  index: { default: 48, min: 40, max: 88 },
  host: { default: 320, min: 160, max: 720 },
  method: { default: 110, min: 90, max: 180 },
  path: { default: 420, min: 180, max: 1200 },
  status: { default: 110, min: 94, max: 180 },
  length: { default: 104, min: 82, max: 180 },
  mime: { default: 128, min: 100, max: 260 },
  notes: { default: 90, min: 74, max: 140 },
  tls: { default: 92, min: 72, max: 140 },
  started_at: { default: 176, min: 132, max: 260 },
};
const HISTORY_COLUMN_DEFS = {
  index: { label: "#", cssClass: "col-index", sortKey: "index" },
  host: { label: "Host", cssClass: "col-host", sortKey: "host" },
  method: { label: "Method", cssClass: "col-method", sortKey: "method" },
  path: { label: "URL", cssClass: "col-url", sortKey: "path" },
  status: { label: "Status", cssClass: "col-status", sortKey: "status" },
  length: { label: "Length", cssClass: "col-length col-center", sortKey: "length" },
  mime: { label: "MIME", cssClass: "col-type col-center", sortKey: "mime" },
  notes: { label: "Notes", cssClass: "col-notes", sortKey: "notes" },
  tls: { label: "TLS", cssClass: "col-tls", sortKey: "tls" },
  started_at: { label: "Time", cssClass: "col-time", sortKey: "started_at" },
};
const DEFAULT_HISTORY_COLUMN_ORDER = ["index", "host", "method", "path", "status", "length", "mime", "notes", "tls", "started_at"];
const WORKBENCH_STACK_MIN_HEIGHTS = {
  history: 140,
  messages: 180,
};
const REPEATER_HISTORY_LIMIT = 30;
const IMPLEMENTED_TOOLS = new Set(["dashboard", "target", "proxy", "fuzzer", "replay", "tools", "logger"]);
const DECODER_SCRIPT_SOURCES = [
  "/decoder/lib/jquery-1.7.2.min.js",
  "/decoder/lib/cryptojs/components/core-min.js",
  "/decoder/lib/cryptojs/components/enc-base64-min.js",
  "/decoder/lib/cryptojs/components/enc-utf16-min.js",
  "/decoder/lib/cryptojs/rollups/md5.js",
  "/decoder/lib/cryptojs/rollups/sha1.js",
  "/decoder/lib/cryptojs/rollups/sha224.js",
  "/decoder/lib/cryptojs/rollups/sha256.js",
  "/decoder/lib/cryptojs/rollups/sha384.js",
  "/decoder/lib/cryptojs/rollups/sha512.js",
  "/decoder/lib/cryptojs/rollups/hmac-md5.js",
  "/decoder/lib/cryptojs/rollups/hmac-sha1.js",
  "/decoder/lib/cryptojs/rollups/hmac-sha224.js",
  "/decoder/lib/cryptojs/rollups/hmac-sha256.js",
  "/decoder/lib/cryptojs/rollups/hmac-sha384.js",
  "/decoder/lib/cryptojs/rollups/hmac-sha512.js",
  "/decoder/lib/cryptojs/rollups/aes.js",
  "/decoder/lib/cryptojs/rollups/tripledes.js",
  "/decoder/lib/cryptojs/rollups/rabbit.js",
  "/decoder/lib/cryptojs/rollups/rc4.js",
  "/decoder/lib/hash/md4.js",
  "/decoder/lib/hash/ripemd.js",
  "/decoder/lib/hash/whirpool.js",
  "/decoder/lib/hash/crc.js",
  "/decoder/lib/snov/numbers.js",
  "/decoder/lib/snov/romanconverter.js",
  "/decoder/lib/snov/rot13.js",
  "/decoder/lib/snov/ipcalc.js",
  "/decoder/lib/xmorse.min.js",
  "/decoder/lib/custom-jwt.js",
  "/decoder/lib/custom-json.js",
  "/decoder/lib/textarea.js",
  "/decoder/hasher.js",
];

function showToast(message, type = "success", durationMs = 2000) {
  const container = document.getElementById("toastContainer");
  if (!container) return;
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  }, durationMs);
}

const state = {
  items: [],
  selectedId: null,
  selectedRecord: null,
  sessions: [],
  activeSession: null,
  activeTool: "proxy",
  activeProxyTab: "http-history",
  activeInspectorTab: "inspector",
  inspectorCollapsed: true,
  query: "",
  method: "",
  sortKey: "started_at",
  sortDirection: "desc",
  settings: null,
  appVersion: null,
  runtime: null,
  messageViews: {
    request: "pretty",
    response: "pretty",
  },
  messageSearch: {
    request: "",
    response: "",
  },
  replayMessageSearch: {
    request: "",
    response: "",
  },
  activeMessagePane: null,
  displaySettings: createDefaultDisplaySettings(),
  historyColumnWidths: createDefaultHistoryColumnWidths(),
  historyColumnOrder: [...DEFAULT_HISTORY_COLUMN_ORDER],
  filterSettings: createDefaultFilterSettings(),
  targetScopeDraft: "",
  targetScopeDirty: false,
  targetExpandedHosts: new Set(),
  intercepts: [],
  selectedInterceptId: null,
  selectedInterceptRecord: null,
  websocketSessions: [],
  websocketQuery: "",
  selectedWebsocketId: null,
  selectedWebsocketRecord: null,
  replayTabs: [],
  activeReplayTabId: null,
  replayTabSequence: 0,
  interceptEditorSeedId: null,
  eventLog: [],
  matchReplaceRules: [],
  selectedMatchReplaceRuleId: null,
  targetSiteMap: [],
  fuzzerBaseRequest: null,
  fuzzerSourceTransactionId: null,
  fuzzerNotice: "",
  fuzzerRequestText: "",
  fuzzerPayloadsText: "",
  fuzzerAttackRecord: null,
  toolsReady: false,
  workbenchHeight: null,
};

const els = {
  dashboardShell: document.getElementById("dashboardShell"),
  dashboardCurrentSessionName: document.getElementById("dashboardCurrentSessionName"),
  dashboardCurrentSessionStatus: document.getElementById("dashboardCurrentSessionStatus"),
  dashboardCurrentSessionPath: document.getElementById("dashboardCurrentSessionPath"),
  dashboardCurrentSessionRequests: document.getElementById("dashboardCurrentSessionRequests"),
  dashboardCurrentSessionWebsockets: document.getElementById("dashboardCurrentSessionWebsockets"),
  dashboardCurrentSessionEvents: document.getElementById("dashboardCurrentSessionEvents"),
  dashboardCurrentSessionFuzzer: document.getElementById("dashboardCurrentSessionFuzzer"),
  dashboardCurrentSessionRules: document.getElementById("dashboardCurrentSessionRules"),
  dashboardCurrentSessionCreated: document.getElementById("dashboardCurrentSessionCreated"),
  dashboardCurrentSessionOpened: document.getElementById("dashboardCurrentSessionOpened"),
  dashboardCreateSessionName: document.getElementById("dashboardCreateSessionName"),
  dashboardCreateSessionButton: document.getElementById("dashboardCreateSessionButton"),
  dashboardReloadSessionsButton: document.getElementById("dashboardReloadSessionsButton"),
  dashboardSessionsBody: document.getElementById("dashboardSessionsBody"),
  proxyStatusIndicator: document.getElementById("proxyStatusIndicator"),
  proxyStatusLabel: document.getElementById("proxyStatusLabel"),
  appVersionLabel: document.getElementById("appVersionLabel"),
  openUpdateButton: document.getElementById("openUpdateButton"),
  proxyAddr: document.getElementById("proxyAddr"),
  uiAddr: document.getElementById("uiAddr"),
  liveStatus: document.getElementById("liveStatus"),
  historyMeta: document.getElementById("historyMeta"),
  historyTable: document.getElementById("historyTable"),
  historyTableBody: document.getElementById("historyTableBody"),
  searchInput: document.getElementById("searchInput"),
  methodFilter: document.getElementById("methodFilter"),
  proxyShell: document.getElementById("proxyShell"),
  replayShell: document.getElementById("replayShell"),
  toolsShell: document.getElementById("toolsShell"),
  toolsMeta: document.getElementById("toolsMeta"),
  toolsClearButton: document.getElementById("toolsClearButton"),
  toolsActiveToolTitle: document.getElementById("toolsActiveToolTitle"),
  toolsOutputMeta: document.getElementById("toolsOutputMeta"),
  replayTabStrip: document.getElementById("replayTabStrip"),
  newReplayTabButton: document.getElementById("newReplayTabButton"),
  fuzzerShell: document.getElementById("fuzzerShell"),
  targetShell: document.getElementById("targetShell"),
  loggerShell: document.getElementById("loggerShell"),
  filterBar: document.getElementById("filterBar"),
  trafficRegion: document.getElementById("trafficRegion"),
  historyWorkbenchResizer: document.getElementById("historyWorkbenchResizer"),
  lowerWorkbench: document.getElementById("lowerWorkbench"),
  requestColumn: document.getElementById("requestColumn"),
  responseColumn: document.getElementById("responseColumn"),
  inspectorColumn: document.querySelector(".inspector-column"),
  proxySubPlaceholder: document.getElementById("proxySubPlaceholder"),
  proxySubPath: document.getElementById("proxySubPath"),
  proxySubTitle: document.getElementById("proxySubTitle"),
  proxySubDescription: document.getElementById("proxySubDescription"),
  interceptPanel: document.getElementById("interceptPanel"),
  websocketPanel: document.getElementById("websocketPanel"),
  matchReplacePanel: document.getElementById("matchReplacePanel"),
  proxySettingsPanel: document.getElementById("proxySettingsPanel"),
  requestView: document.getElementById("requestView"),
  requestLines: document.getElementById("requestLines"),
  responseView: document.getElementById("responseView"),
  responseLines: document.getElementById("responseLines"),
  requestSearchInput: document.getElementById("requestSearchInput"),
  responseSearchInput: document.getElementById("responseSearchInput"),
  requestSearchMeta: document.getElementById("requestSearchMeta"),
  responseSearchMeta: document.getElementById("responseSearchMeta"),
  requestResponseResizer: document.getElementById("requestResponseResizer"),
  responseInspectorResizer: document.getElementById("responseInspectorResizer"),
  detailTitle: document.getElementById("detailTitle"),
  detailTags: document.getElementById("detailTags"),
  protocolStrip: document.getElementById("protocolStrip"),
  summaryList: document.getElementById("summaryList"),
  attributesCount: document.getElementById("attributesCount"),
  requestHeaderCount: document.getElementById("requestHeaderCount"),
  responseHeaderCount: document.getElementById("responseHeaderCount"),
  requestHeadersBody: document.getElementById("requestHeadersBody"),
  responseHeadersBody: document.getElementById("responseHeadersBody"),
  inspectorContent: document.getElementById("inspectorContent"),
  notesPanel: document.getElementById("notesPanel"),
  notesCard: document.getElementById("notesCard"),
  captureMode: document.getElementById("captureMode"),
  footerMode: document.getElementById("footerMode"),
  openEventLogButton: document.getElementById("openEventLogButton"),
  eventLogStatus: document.getElementById("eventLogStatus"),
  displaySettingsModal: document.getElementById("displaySettingsModal"),
  openDisplaySettingsButton: document.getElementById("openDisplaySettingsButton"),
  closeDisplaySettingsButton: document.getElementById("closeDisplaySettingsButton"),
  applyDisplaySettingsButton: document.getElementById("applyDisplaySettingsButton"),
  resetDisplaySettingsButton: document.getElementById("resetDisplaySettingsButton"),
  displayThemeSelect: document.getElementById("displayThemeSelect"),
  displaySizeInput: document.getElementById("displaySizeInput"),
  displayUiFontSelect: document.getElementById("displayUiFontSelect"),
  displayMonoFontSelect: document.getElementById("displayMonoFontSelect"),
  settingsSpecialHostHttp: document.getElementById("settingsSpecialHostHttp"),
  certificateName: document.getElementById("certificateName"),
  certificateExpiry: document.getElementById("certificateExpiry"),
  certificatePemPath: document.getElementById("certificatePemPath"),
  certificateDerPath: document.getElementById("certificateDerPath"),
  specialHostHttps: document.getElementById("specialHostHttps"),
  dataDir: document.getElementById("dataDir"),
  certificateNote: document.getElementById("certificateNote"),
  downloadPemButton: document.getElementById("downloadPemButton"),
  downloadDerButton: document.getElementById("downloadDerButton"),
  closeInspectorButton: document.getElementById("closeInspectorButton"),
  interceptStatus: document.getElementById("interceptStatus"),
  openFilterSettingsButton: document.getElementById("openFilterSettingsButton"),
  filterModal: document.getElementById("filterModal"),
  closeFilterModalButton: document.getElementById("closeFilterModalButton"),
  applyFilterSettingsButton: document.getElementById("applyFilterSettingsButton"),
  resetFilterSettingsButton: document.getElementById("resetFilterSettingsButton"),
  filterInScopeOnly: document.getElementById("filterInScopeOnly"),
  filterHideWithoutResponses: document.getElementById("filterHideWithoutResponses"),
  filterOnlyParameterized: document.getElementById("filterOnlyParameterized"),
  filterOnlyNotes: document.getElementById("filterOnlyNotes"),
  filterSearchTerm: document.getElementById("filterSearchTerm"),
  filterRegex: document.getElementById("filterRegex"),
  filterCaseSensitive: document.getElementById("filterCaseSensitive"),
  filterNegativeSearch: document.getElementById("filterNegativeSearch"),
  filterMimeHtml: document.getElementById("filterMimeHtml"),
  filterMimeScript: document.getElementById("filterMimeScript"),
  filterMimeJson: document.getElementById("filterMimeJson"),
  filterMimeCss: document.getElementById("filterMimeCss"),
  filterMimeImage: document.getElementById("filterMimeImage"),
  filterMimeOther: document.getElementById("filterMimeOther"),
  filterStatus2xx: document.getElementById("filterStatus2xx"),
  filterStatus3xx: document.getElementById("filterStatus3xx"),
  filterStatus4xx: document.getElementById("filterStatus4xx"),
  filterStatus5xx: document.getElementById("filterStatus5xx"),
  filterStatusOther: document.getElementById("filterStatusOther"),
  filterHiddenExtensions: document.getElementById("filterHiddenExtensions"),
  filterPort: document.getElementById("filterPort"),
  colorTagFilter: document.getElementById("colorTagFilter"),
  interceptTableBody: document.getElementById("interceptTableBody"),
  interceptDetailPath: document.getElementById("interceptDetailPath"),
  interceptDetailTitle: document.getElementById("interceptDetailTitle"),
  interceptRequestHighlight: document.getElementById("interceptRequestHighlight"),
  interceptRequestEditor: document.getElementById("interceptRequestEditor"),
  interceptMeta: document.getElementById("interceptMeta"),
  refreshInterceptsButton: document.getElementById("refreshInterceptsButton"),
  forwardInterceptButton: document.getElementById("forwardInterceptButton"),
  dropInterceptButton: document.getElementById("dropInterceptButton"),
  websocketMeta: document.getElementById("websocketMeta"),
  websocketSearchInput: document.getElementById("websocketSearchInput"),
  websocketTableBody: document.getElementById("websocketTableBody"),
  websocketDetailTitle: document.getElementById("websocketDetailTitle"),
  websocketRequestView: document.getElementById("websocketRequestView"),
  websocketResponseView: document.getElementById("websocketResponseView"),
  websocketFramesBody: document.getElementById("websocketFramesBody"),
  refreshWebsocketsButton: document.getElementById("refreshWebsocketsButton"),
  websocketWorkbench: document.getElementById("websocketWorkbench"),
  websocketHandshakeColumn: document.getElementById("websocketHandshakeColumn"),
  websocketFramesColumn: document.getElementById("websocketFramesColumn"),
  websocketSplitResizer: document.getElementById("websocketSplitResizer"),
  proxySettingIntercept: document.getElementById("proxySettingIntercept"),
  proxySettingWebsocketCapture: document.getElementById("proxySettingWebsocketCapture"),
  proxySettingScopePatterns: document.getElementById("proxySettingScopePatterns"),
  proxySettingPassthroughHosts: document.getElementById("proxySettingPassthroughHosts"),
  proxySettingBindHost: document.getElementById("proxySettingBindHost"),
  proxySettingPort: document.getElementById("proxySettingPort"),
  proxySettingListenerHelp: document.getElementById("proxySettingListenerHelp"),
  saveProxySettingsButton: document.getElementById("saveProxySettingsButton"),
  reloadProxySettingsButton: document.getElementById("reloadProxySettingsButton"),
  proxySettingsPemButton: document.getElementById("proxySettingsPemButton"),
  proxySettingsDerButton: document.getElementById("proxySettingsDerButton"),
  proxySettingsProxyAddr: document.getElementById("proxySettingsProxyAddr"),
  proxySettingsNextProxyAddr: document.getElementById("proxySettingsNextProxyAddr"),
  proxySettingsUiAddr: document.getElementById("proxySettingsUiAddr"),
  proxySettingsCaptureCap: document.getElementById("proxySettingsCaptureCap"),
  proxySettingsBootstrap: document.getElementById("proxySettingsBootstrap"),
  proxySettingsDataDir: document.getElementById("proxySettingsDataDir"),
  proxySettingsStartupPath: document.getElementById("proxySettingsStartupPath"),
  proxySettingsCertificateName: document.getElementById("proxySettingsCertificateName"),
  replaySchemeSelect: document.getElementById("replaySchemeSelect"),
  replayHostInput: document.getElementById("replayHostInput"),
  replayPortInput: document.getElementById("replayPortInput"),
  replayRequestHighlight: document.getElementById("replayRequestHighlight"),
  replayRequestEditor: document.getElementById("replayRequestEditor"),
  replayRequestSearchInput: document.getElementById("replayRequestSearchInput"),
  replayRequestSearchMeta: document.getElementById("replayRequestSearchMeta"),
  replayResponseMeta: document.getElementById("replayResponseMeta"),
  replayResponseView: document.getElementById("replayResponseView"),
  replayResponseSearchInput: document.getElementById("replayResponseSearchInput"),
  replayResponseSearchMeta: document.getElementById("replayResponseSearchMeta"),
  sendReplayButton: document.getElementById("sendReplayButton"),
  resetReplayButton: document.getElementById("resetReplayButton"),
  replayBackButton: document.getElementById("replayBackButton"),
  replayForwardButton: document.getElementById("replayForwardButton"),
  eventLogTableBody: document.getElementById("eventLogTableBody"),
  clearEventLogButton: document.getElementById("clearEventLogButton"),
  matchReplaceTableBody: document.getElementById("matchReplaceTableBody"),
  matchReplaceEditorPath: document.getElementById("matchReplaceEditorPath"),
  matchReplaceEditorTitle: document.getElementById("matchReplaceEditorTitle"),
  matchReplaceEnabled: document.getElementById("matchReplaceEnabled"),
  matchReplaceDescription: document.getElementById("matchReplaceDescription"),
  matchReplaceScope: document.getElementById("matchReplaceScope"),
  matchReplaceTarget: document.getElementById("matchReplaceTarget"),
  matchReplaceSearch: document.getElementById("matchReplaceSearch"),
  matchReplaceReplace: document.getElementById("matchReplaceReplace"),
  matchReplaceRegex: document.getElementById("matchReplaceRegex"),
  matchReplaceCaseSensitive: document.getElementById("matchReplaceCaseSensitive"),
  saveMatchReplaceRuleButton: document.getElementById("saveMatchReplaceRuleButton"),
  deleteMatchReplaceRuleButton: document.getElementById("deleteMatchReplaceRuleButton"),
  targetScopeEditor: document.getElementById("targetScopeEditor"),
  saveTargetScopeButton: document.getElementById("saveTargetScopeButton"),
  reloadTargetButton: document.getElementById("reloadTargetButton"),
  targetTree: document.getElementById("targetTree"),
  fuzzerRequestHighlight: document.getElementById("fuzzerRequestHighlight"),
  fuzzerRequestEditor: document.getElementById("fuzzerRequestEditor"),
  fuzzerPayloadsEditor: document.getElementById("fuzzerPayloadsEditor"),
  fuzzerMeta: document.getElementById("fuzzerMeta"),
  fuzzerResultsBody: document.getElementById("fuzzerResultsBody"),
  startFuzzerButton: document.getElementById("startFuzzerButton"),
  resetFuzzerButton: document.getElementById("resetFuzzerButton"),
  contextMenu: document.getElementById("contextMenu"),
  contextMenuNote: document.getElementById("contextMenuNote"),
};

const mainTabs = Array.from(document.querySelectorAll(".main-tab"));
const proxyTabs = Array.from(document.querySelectorAll(".sub-tab"));
const viewTabs = Array.from(document.querySelectorAll(".view-tab"));
const railTabs = Array.from(document.querySelectorAll(".rail-tab"));
const sectionToggles = Array.from(document.querySelectorAll(".section-toggle"));
let sortHeaders = Array.from(document.querySelectorAll(".sort-header"));
let historyColumnHandles = Array.from(document.querySelectorAll(".column-resize-handle"));

let refreshTimer = null;
let auxTimer = null;
let eventSource = null;
let workspaceSaveTimer = null;
let uiSettingsSaveTimer = null;
let toolsBootPromise = null;
let displaySettingsPreviewActive = false;

const WORKBENCH_STACK_BREAKPOINT = "(max-width: 1260px)";
const WORKBENCH_MIN_WIDTHS = {
  request: 320,
  response: 320,
  inspector: 300,
};
const WEBSOCKET_WORKBENCH_BREAKPOINT = "(max-width: 980px)";
const WEBSOCKET_WORKBENCH_MIN_WIDTHS = {
  handshake: 360,
  frames: 320,
};

const LAYOUT_TEXTAREA_IDS = [
  "interceptRequestEditor",
  "proxySettingScopePatterns",
  "proxySettingPassthroughHosts",
  "fuzzerPayloadsEditor",
  "targetScopeEditor",
];

init().catch((error) => {
  console.error(error);
  els.historyMeta.textContent = "Failed to load Sniper.";
  els.liveStatus.textContent = "Error";
  els.liveStatus.classList.remove("online");
});

async function init() {
  loadDisplaySettings();
  loadHistoryColumnWidths();
  loadWorkbenchLayout();
  renderHistoryHeader();
  bindEvents();
  resetLayoutTextareas();
  hydrateFilterForm();
  await loadUiSettings();
  hydrateDisplaySettingsForm();
  const loads = [
    loadSessions(),
    loadSettings(),
    loadWorkspaceState(),
    loadTransactions(false),
    loadIntercepts(false),
    loadWebsockets(false),
    loadEventLog(),
    loadMatchReplaceRules(),
    loadTargetSiteMap(),
  ];
  loadAppVersionInfo().catch((error) => console.error(error));
  const results = await Promise.allSettled(loads);
  for (const result of results) {
    if (result.status === "rejected") {
      console.error("init load failed:", result.reason);
    }
  }
  connectEvents();
  auxTimer = window.setInterval(() => {
    pollAuxiliaryData().catch((error) => console.error(error));
  }, 1200);
  renderToolPanels();
  renderProxyPanels();
  renderInspectorPanels();
  renderViewTabs();
  renderSortHeaders();
  renderProxySettings();
  renderIntercepts();
  renderWebsocketSessions();
  renderReplay();
  renderDashboard();
  renderEventLog();
  renderMatchReplaceRules();
  renderTarget();
  renderFuzzer();
  normalizeWorkbenchStackHeight();
}

function resetLayoutTextareas() {
  for (const key of LAYOUT_TEXTAREA_IDS) {
    const element = els[key];
    if (!(element instanceof HTMLTextAreaElement)) {
      continue;
    }

    element.style.height = "";
    element.style.overflowY = "";
  }
}

function bindEvents() {
  window.addEventListener("resize", resetLayoutTextareas);

  mainTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      state.activeTool = tab.dataset.tool;
      renderToolPanels();
      if (state.activeTool === "dashboard") {
        loadSessions().catch((error) => console.error(error));
      }
      if (state.activeTool === "target") {
        loadTargetSiteMap(true).catch((error) => console.error(error));
      }
      if (state.activeTool === "logger") {
        loadEventLog().catch((error) => console.error(error));
      }
    });
  });

  proxyTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      state.activeProxyTab = tab.dataset.proxyTab;
      renderProxyPanels();
      if (state.activeProxyTab === "intercept") {
        loadIntercepts(true).catch((error) => console.error(error));
      }
      if (state.activeProxyTab === "websockets-history") {
        loadWebsockets(true).catch((error) => console.error(error));
      }
      if (state.activeProxyTab === "proxy-settings") {
        loadRuntimeSettings().catch((error) => console.error(error));
      }
      if (state.activeProxyTab === "replace") {
        loadMatchReplaceRules().catch((error) => console.error(error));
      }
    });
  });

  viewTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const target = tab.dataset.target;
      state.messageViews[target] = tab.dataset.view;
      renderViewTabs();
      renderMessagePanes();
    });
  });

  railTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      state.activeInspectorTab = tab.dataset.inspectorTab;
      state.inspectorCollapsed = false;
      renderInspectorPanels();
    });
  });

  sectionToggles.forEach((toggle) => {
    toggle.addEventListener("click", () => {
      toggle.parentElement.classList.toggle("collapsed");
    });
  });

  els.searchInput.addEventListener("input", () => {
    state.query = els.searchInput.value.trim();
    scheduleRefresh();
  });

  els.requestSearchInput.addEventListener("input", () => {
    state.messageSearch.request = els.requestSearchInput.value;
    renderMessagePanes();
  });

  els.responseSearchInput.addEventListener("input", () => {
    state.messageSearch.response = els.responseSearchInput.value;
    renderMessagePanes();
  });

  els.replayRequestSearchInput.addEventListener("input", () => {
    state.replayMessageSearch.request = els.replayRequestSearchInput.value;
    updateReplaySearchPane("request", els.replayRequestEditor.value || "");
  });

  els.replayResponseSearchInput.addEventListener("input", () => {
    state.replayMessageSearch.response = els.replayResponseSearchInput.value;
    updateReplaySearchPane("response", els.replayResponseView.textContent || "");
  });

  els.websocketSearchInput.addEventListener("input", () => {
    state.websocketQuery = els.websocketSearchInput.value.trim();
    syncVisibleWebsocketSelection(true).catch((error) => console.error(error));
  });

  els.methodFilter.addEventListener("change", () => {
    state.method = els.methodFilter.value;
    scheduleRefresh();
  });

  els.colorTagFilter.addEventListener("click", (event) => {
    const btn = event.target.closest(".color-dot-btn");
    if (!btn) return;
    const color = btn.dataset.color;
    if (state.filterSettings.colorTags.has(color)) {
      state.filterSettings.colorTags.delete(color);
      btn.classList.remove("active");
    } else {
      state.filterSettings.colorTags.add(color);
      btn.classList.add("active");
    }
    scheduleRefresh();
  });

  els.openDisplaySettingsButton.addEventListener("click", openDisplaySettingsModal);
  els.toolsClearButton.addEventListener("click", clearToolsInputs);
  els.closeDisplaySettingsButton.addEventListener("click", closeDisplaySettingsModal);
  els.displaySettingsModal.addEventListener("click", (event) => {
    if (event.target === els.displaySettingsModal) {
      closeDisplaySettingsModal();
    }
  });

  els.openFilterSettingsButton.addEventListener("click", openFilterModal);
  els.historyMeta.addEventListener("click", openFilterModal);
  els.closeFilterModalButton.addEventListener("click", closeFilterModal);
  els.filterModal.addEventListener("click", (event) => {
    if (event.target === els.filterModal) {
      closeFilterModal();
    }
  });
  els.applyFilterSettingsButton.addEventListener("click", applyFilterSettings);
  els.resetFilterSettingsButton.addEventListener("click", () => {
    state.filterSettings = createDefaultFilterSettings();
    hydrateFilterForm();
    scheduleRefresh();
  });
  els.applyDisplaySettingsButton.addEventListener("click", saveDisplaySettingsFromForm);
  els.resetDisplaySettingsButton.addEventListener("click", () => {
    const defaults = createDefaultDisplaySettings();
    els.displayThemeSelect.value = defaults.theme;
    els.displaySizeInput.value = String(defaults.sizePx);
    els.displayUiFontSelect.value = defaults.uiFont;
    els.displayMonoFontSelect.value = defaults.monoFont;
    previewDisplaySettingsFromForm();
  });
  [els.displayThemeSelect, els.displayUiFontSelect, els.displayMonoFontSelect].forEach((element) => {
    element.addEventListener("change", previewDisplaySettingsFromForm);
  });
  els.displaySizeInput.addEventListener("input", previewDisplaySettingsFromForm);
  els.displaySizeInput.addEventListener("change", previewDisplaySettingsFromForm);

  els.downloadPemButton.addEventListener("click", () => downloadCertificate("pem"));
  els.downloadDerButton.addEventListener("click", () => downloadCertificate("der"));
  els.proxySettingsPemButton.addEventListener("click", () => downloadCertificate("pem"));
  els.proxySettingsDerButton.addEventListener("click", () => downloadCertificate("der"));
  els.openEventLogButton.addEventListener("click", async () => {
    state.activeTool = "logger";
    await loadEventLog();
    renderToolPanels();
  });
  els.dashboardReloadSessionsButton?.addEventListener("click", () => {
    loadSessions().catch((error) => console.error(error));
  });
  els.dashboardCreateSessionButton?.addEventListener("click", () => {
    createSession().catch((error) => console.error(error));
  });
  els.clearEventLogButton.addEventListener("click", () => {
    clearEventLog().catch((error) => console.error(error));
  });

  els.closeInspectorButton?.addEventListener("click", () => {
    state.inspectorCollapsed = true;
    renderInspectorPanels();
  });

  els.refreshInterceptsButton.addEventListener("click", () => {
    loadIntercepts(true).catch((error) => console.error(error));
  });
  els.refreshWebsocketsButton.addEventListener("click", () => {
    loadWebsockets(true).catch((error) => console.error(error));
  });
  els.forwardInterceptButton.addEventListener("click", () => {
    forwardSelectedIntercept().catch((error) => console.error(error));
  });
  els.dropInterceptButton.addEventListener("click", () => {
    dropSelectedIntercept().catch((error) => console.error(error));
  });

  els.interceptStatus.addEventListener("click", () => {
    toggleIntercept().catch((error) => console.error(error));
  });
  els.saveProxySettingsButton.addEventListener("click", () => {
    saveProxySettings()
      .then(() => showToast("Proxy settings saved"))
      .catch((error) => { console.error(error); showToast("Failed to save proxy settings", "error"); });
  });
  els.reloadProxySettingsButton.addEventListener("click", () => {
    loadSettings().catch((error) => console.error(error));
  });

  els.sendReplayButton.addEventListener("click", () => {
    sendReplay().catch((error) => console.error(error));
  });
  els.newReplayTabButton.addEventListener("click", () => {
    openBlankReplayTab();
  });
  els.resetReplayButton.addEventListener("click", resetReplay);
  els.replayBackButton.addEventListener("click", () => {
    navigateReplayHistory(-1);
  });
  els.replayForwardButton.addEventListener("click", () => {
    navigateReplayHistory(1);
  });
  els.saveMatchReplaceRuleButton.addEventListener("click", () => {
    if (!state.selectedMatchReplaceRuleId) {
      createNewMatchReplaceRule();
    }
    saveMatchReplaceRules()
      .then(() => showToast("Rule saved"))
      .catch((error) => { console.error(error); showToast("Failed to save rule", "error"); });
  });
  els.deleteMatchReplaceRuleButton.addEventListener("click", deleteSelectedMatchReplaceRule);
  [
    els.matchReplaceEnabled,
    els.matchReplaceDescription,
    els.matchReplaceScope,
    els.matchReplaceTarget,
    els.matchReplaceSearch,
    els.matchReplaceReplace,
    els.matchReplaceRegex,
    els.matchReplaceCaseSensitive,
  ].forEach((element) => {
    element.addEventListener("input", syncMatchReplaceEditor);
    element.addEventListener("change", syncMatchReplaceEditor);
  });
  els.saveTargetScopeButton.addEventListener("click", () => {
    saveTargetScope()
      .then(() => showToast("Scope saved"))
      .catch((error) => { console.error(error); showToast("Failed to save scope", "error"); });
  });
  els.targetScopeEditor.addEventListener("input", () => {
    state.targetScopeDraft = els.targetScopeEditor.value;
    state.targetScopeDirty = true;
  });
  els.reloadTargetButton.addEventListener("click", () => {
    loadTargetSiteMap(true).catch((error) => console.error(error));
  });
  els.startFuzzerButton.addEventListener("click", () => {
    runFuzzerAttack().catch((error) => console.error(error));
  });
  els.resetFuzzerButton.addEventListener("click", resetFuzzer);
  els.replayRequestEditor.addEventListener("input", () => {
    const tab = getActiveReplayTab();
    if (!tab) {
      return;
    }
    tab.requestText = els.replayRequestEditor.value;
    renderReplayRequestHighlight(tab.requestText);
    updateReplaySearchPane("request", tab.requestText);
    syncReplayToolbar(tab);
    renderReplayTabs();
    scheduleWorkspaceStateSave();
  });
  els.replayRequestEditor.addEventListener("scroll", syncReplayRequestHighlightScroll);
  els.replaySchemeSelect.addEventListener("change", () => {
    applyReplayTargetFields().catch((error) => console.error(error));
  });
  els.replayHostInput.addEventListener("input", () => {
    applyReplayTargetFields().catch((error) => console.error(error));
  });
  els.replayPortInput.addEventListener("input", () => {
    applyReplayTargetFields().catch((error) => console.error(error));
  });
  els.fuzzerRequestEditor.addEventListener("input", () => {
    state.fuzzerRequestText = els.fuzzerRequestEditor.value;
    renderFuzzerRequestHighlight(state.fuzzerRequestText);
    scheduleWorkspaceStateSave();
  });
  els.fuzzerRequestEditor.addEventListener("scroll", syncFuzzerRequestHighlightScroll);
  els.fuzzerPayloadsEditor.addEventListener("input", () => {
    state.fuzzerPayloadsText = els.fuzzerPayloadsEditor.value;
    scheduleWorkspaceStateSave();
  });
  els.interceptRequestEditor.addEventListener("input", () => {
    if (state.selectedInterceptRecord) {
      state.interceptEditorSeedId = state.selectedInterceptRecord.id;
    }
    renderInterceptRequestHighlight(els.interceptRequestEditor.value);
  });
  els.interceptRequestEditor.addEventListener("scroll", syncInterceptRequestHighlightScroll);

  document.addEventListener("keydown", (event) => {
    const activeModalAction = getActiveModalAction();
    if (activeModalAction) {
      if (event.key === "Escape") {
        event.preventDefault();
        activeModalAction.close();
        return;
      }

      if (
        event.key === "Enter" &&
        !event.metaKey &&
        !event.ctrlKey &&
        !event.altKey &&
        !event.shiftKey &&
        !event.isComposing
      ) {
        event.preventDefault();
        activeModalAction.apply();
        return;
      }
    } else if (event.key === "Escape") {
      closeDisplaySettingsModal();
      closeCertificateModal();
      closeFilterModal();
      return;
    }

    if (
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "a" &&
      isSelectableTextTarget(event.target)
    ) {
      event.preventDefault();
      selectEditableTargetContents(event.target);
      return;
    }

    if (
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "c" &&
      !isEditableTarget(event.target)
    ) {
      const selectedText = getSelectedCodePaneText();
      if (selectedText) {
        event.preventDefault();
        copyTextToClipboard(selectedText).catch((error) => console.error(error));
        return;
      }
    }

    if (
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "a" &&
      state.activeTool === "proxy" &&
      state.activeProxyTab === "http-history" &&
      !isEditableTarget(event.target)
    ) {
      const targetPane = getActiveMessagePane();
      if (targetPane) {
        event.preventDefault();
        selectCodePaneContents(targetPane);
        return;
      }
    }

    if (
      (event.metaKey || event.ctrlKey) &&
      !event.altKey &&
      event.key === "Enter" &&
      state.activeTool === "proxy" &&
      state.activeProxyTab === "intercept" &&
      state.selectedInterceptRecord
    ) {
      event.preventDefault();
      if (event.shiftKey) {
        dropSelectedIntercept().catch((error) => console.error(error));
      } else {
        forwardSelectedIntercept().catch((error) => console.error(error));
      }
      return;
    }

    if (
      !event.metaKey &&
      !event.ctrlKey &&
      !event.altKey &&
      !event.shiftKey &&
      state.activeTool === "proxy" &&
      !isEditableTarget(event.target)
    ) {
      if (state.activeProxyTab === "http-history") {
        if (event.key === "ArrowUp") {
          event.preventDefault();
          moveHistorySelection(-1).catch((error) => console.error(error));
          return;
        }

        if (event.key === "ArrowDown") {
          event.preventDefault();
          moveHistorySelection(1).catch((error) => console.error(error));
          return;
        }
      }

      if (state.activeProxyTab === "websockets-history") {
        if (event.key === "ArrowUp") {
          event.preventDefault();
          moveWebsocketSelection(-1).catch((error) => console.error(error));
          return;
        }

        if (event.key === "ArrowDown") {
          event.preventDefault();
          moveWebsocketSelection(1).catch((error) => console.error(error));
          return;
        }
      }
    }

    if (
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "r" &&
      state.activeTool === "replay"
    ) {
      event.preventDefault();
      duplicateActiveReplayTab();
      return;
    }

    if (
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "r" &&
      state.activeTool === "proxy" &&
      state.activeProxyTab === "http-history" &&
      state.selectedId
    ) {
      event.preventDefault();
      openReplayFromSelection().catch((error) => console.error(error));
    }

    if (
      event.metaKey &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "i" &&
      state.activeTool === "proxy" &&
      state.activeProxyTab === "http-history" &&
      state.selectedId
    ) {
      event.preventDefault();
      openFuzzerFromSelection().catch((error) => console.error(error));
    }
  });

  document.addEventListener("copy", (event) => {
    if (isEditableTarget(event.target)) {
      return;
    }

    const selectedText = getSelectedCodePaneText();
    if (!selectedText || !event.clipboardData) {
      return;
    }

    event.preventDefault();
    event.clipboardData.setData("text/plain", selectedText);
  });

  bindCodePaneScroll(els.requestView, els.requestLines);
  bindCodePaneScroll(els.responseView, els.responseLines);
  bindMessagePaneActivation();
  bindPaneResizer(els.requestResponseResizer, "request-response");
  bindPaneResizer(els.responseInspectorResizer, "response-inspector");
  bindWorkbenchStackResizer(els.historyWorkbenchResizer);
  bindWebsocketPaneResizer(els.websocketSplitResizer);
  bindHistoryColumnResizers();
  window.addEventListener("resize", () => {
    normalizeWorkbenchPaneWidths();
    normalizeWebsocketPaneWidth();
    normalizeWorkbenchStackHeight();
  });
}

async function loadSettings() {
  const response = await fetch("/api/settings");
  if (!response.ok) {
    throw new Error(`loadSettings failed: ${response.status}`);
  }
  state.settings = await response.json();
  state.runtime = state.settings.runtime;
  state.activeSession = state.settings.active_session;

  els.proxyAddr.textContent = state.settings.proxy_addr;
  els.uiAddr.textContent = state.settings.ui_addr;
  els.captureMode.textContent = `${formatSize(state.settings.body_preview_bytes)} preview cap / ${state.settings.max_entries} entries`;
  els.settingsSpecialHostHttp.textContent = state.settings.certificate.special_host_http;

  updateProxyStatusIndicator(state.settings.proxy_online);

  const certificate = state.settings.certificate;
  els.certificateName.textContent = certificate.common_name;
  els.certificateExpiry.textContent = formatTimestamp(certificate.expires_at);
  els.certificatePemPath.textContent = certificate.pem_path;
  els.certificateDerPath.textContent = certificate.der_path;
  els.specialHostHttps.textContent = certificate.special_host_https;
  els.dataDir.textContent = state.settings.data_dir;
  els.certificateNote.innerHTML = `
    Download the local root certificate here, or visit <code>${escapeHtml(certificate.special_host_https)}</code>
    from a proxied client. Trust the CA before expecting clean HTTPS flows.
  `;

  renderInterceptStatus();
  renderProxySettings();
  renderDashboard();
}

async function loadAppVersionInfo() {
  const response = await fetch("/api/app-version");
  if (!response.ok) {
    throw new Error(await response.text());
  }

  state.appVersion = await response.json();
  els.appVersionLabel.textContent = `v${state.appVersion.current_version}`;
  els.appVersionLabel.title = `Current version ${state.appVersion.current_version}`;

  const updateUrl = state.appVersion.latest_release_url || state.appVersion.releases_url;
  if (state.appVersion.update_available && updateUrl) {
    els.openUpdateButton.href = updateUrl;
    els.openUpdateButton.title = state.appVersion.latest_version
      ? `Open latest release (${state.appVersion.latest_version})`
      : "Open latest release";
    els.openUpdateButton.classList.remove("hidden");
  } else {
    els.openUpdateButton.classList.add("hidden");
  }
}

async function loadSessions() {
  const response = await fetch("/api/sessions");
  state.sessions = await response.json();
  if (!state.activeSession || !state.sessions.some((session) => session.id === state.activeSession.id)) {
    state.activeSession = state.sessions.find((session) => session.active) || state.sessions[0] || null;
  }
  renderDashboard();
}

async function loadWorkspaceState() {
  const response = await fetch("/api/workspace-state");
  if (!response.ok) {
    throw new Error(await response.text());
  }
  applyWorkspaceState(await response.json());
}

function applyWorkspaceState(snapshot) {
  const replayWS = snapshot?.replay || {};
  const tabs = Array.isArray(replayWS.tabs)
    ? replayWS.tabs.map((tab) => hydrateReplayTab(tab)).filter(Boolean)
    : [];

  state.replayTabs = tabs;
  state.replayTabSequence = Math.max(
    Number.isFinite(replayWS.tab_sequence) ? replayWS.tab_sequence : 0,
    ...tabs.map((tab) => tab.sequence || 0),
    0,
  );
  state.activeReplayTabId = tabs.some((tab) => tab.id === replayWS.active_tab_id)
    ? replayWS.active_tab_id
    : tabs[0]?.id ?? null;

  const fuzzerWS = snapshot?.fuzzer || {};
  state.fuzzerBaseRequest = fuzzerWS.base_request ? cloneEditableRequest(fuzzerWS.base_request) : null;
  state.fuzzerSourceTransactionId = fuzzerWS.source_transaction_id || null;
  state.fuzzerNotice = fuzzerWS.notice || "";
  state.fuzzerRequestText = fuzzerWS.request_text || "";
  state.fuzzerPayloadsText = fuzzerWS.payloads_text || "";
  state.fuzzerAttackRecord = fuzzerWS.attack_record || null;
}

function hydrateReplayTab(tab) {
  if (!tab || typeof tab !== "object") {
    return null;
  }

  const fallbackRequest = tab.base_request ? cloneEditableRequest(tab.base_request) : createDefaultEditableRequest();
  const fallbackTarget = authorityToTargetState(fallbackRequest.host, fallbackRequest.scheme);
  const historyEntries = Array.isArray(tab.history_entries)
    ? tab.history_entries.map((entry) => hydrateRepeaterHistoryEntry(entry, fallbackRequest)).filter(Boolean)
    : [];
  const historyIndex = normalizeRepeaterHistoryIndex(tab.history_index, historyEntries.length);
  const normalizedTarget = normalizeRepeaterTargetInput(
    tab.target_host ?? fallbackTarget.host,
    tab.target_port ?? fallbackTarget.port,
    tab.target_scheme || fallbackTarget.scheme,
  );
  return {
    id: typeof tab.id === "string" && tab.id ? tab.id : crypto.randomUUID(),
    sequence: Number.isFinite(tab.sequence) ? tab.sequence : state.replayTabSequence + 1,
    baseRequest: fallbackRequest,
    sourceTransactionId: tab.source_transaction_id || null,
    notice: tab.notice || "",
    requestText: tab.request_text || buildEditableRawRequest(fallbackRequest),
    responseRecord: tab.response_record || null,
    targetScheme: normalizedTarget.scheme,
    targetHost: normalizedTarget.host,
    targetPort: normalizedTarget.port,
    historyEntries,
    historyIndex,
  };
}

function hydrateRepeaterHistoryEntry(entry, fallbackRequest) {
  if (!entry || typeof entry !== "object") {
    return null;
  }

  const request = entry.request ? cloneEditableRequest(entry.request) : cloneEditableRequest(fallbackRequest);
  const fallbackTarget = authorityToTargetState(request.host, request.scheme);
  const normalizedTarget = normalizeRepeaterTargetInput(
    entry.target_host ?? fallbackTarget.host,
    entry.target_port ?? fallbackTarget.port,
    entry.target_scheme || fallbackTarget.scheme,
  );
  return {
    request,
    requestText: entry.request_text || buildEditableRawRequest(request),
    responseRecord: entry.response_record || null,
    notice: entry.notice || "",
    targetScheme: normalizedTarget.scheme,
    targetHost: normalizedTarget.host,
    targetPort: normalizedTarget.port,
  };
}

function snapshotWorkspaceState() {
  return {
    replay: {
      tabs: state.replayTabs.map((tab) => ({
        id: tab.id,
        sequence: tab.sequence,
        base_request: tab.baseRequest ? cloneEditableRequest(tab.baseRequest) : null,
        source_transaction_id: tab.sourceTransactionId || null,
        notice: tab.notice || "",
        request_text: tab.requestText || "",
        response_record: tab.responseRecord || null,
        target_scheme: tab.targetScheme || "https",
        target_host: tab.targetHost || "",
        target_port: normalizePortValue(tab.targetPort),
        history_entries: (tab.historyEntries || []).map((entry) => ({
          request: cloneEditableRequest(entry.request),
          request_text: entry.requestText || "",
          response_record: entry.responseRecord || null,
          notice: entry.notice || "",
          target_scheme: entry.targetScheme || "https",
          target_host: entry.targetHost || "",
          target_port: normalizePortValue(entry.targetPort),
        })),
        history_index: normalizeRepeaterHistoryIndex(tab.historyIndex, (tab.historyEntries || []).length),
      })),
      active_tab_id: state.activeReplayTabId,
      tab_sequence: state.replayTabSequence,
    },
    fuzzer: {
      base_request: state.fuzzerBaseRequest ? cloneEditableRequest(state.fuzzerBaseRequest) : null,
      source_transaction_id: state.fuzzerSourceTransactionId || null,
      notice: state.fuzzerNotice || "",
      request_text: state.fuzzerRequestText || "",
      payloads_text: state.fuzzerPayloadsText || "",
      attack_record: state.fuzzerAttackRecord || null,
    },
  };
}

function scheduleWorkspaceStateSave() {
  if (!state.activeSession) {
    return;
  }

  window.clearTimeout(workspaceSaveTimer);
  workspaceSaveTimer = window.setTimeout(() => {
    workspaceSaveTimer = null;
    saveWorkspaceState().catch((error) => console.error(error));
  }, 250);
}

async function saveWorkspaceState() {
  if (!state.activeSession) {
    return;
  }

  const response = await fetch("/api/workspace-state", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(snapshotWorkspaceState()),
  });

  if (!response.ok) {
    throw new Error(await response.text());
  }
}

async function flushWorkspaceState() {
  window.clearTimeout(workspaceSaveTimer);
  workspaceSaveTimer = null;
  await saveWorkspaceState();
}

function resetSessionScopedUiState() {
  window.clearTimeout(refreshTimer);
  window.clearTimeout(workspaceSaveTimer);
  workspaceSaveTimer = null;
  state.items = [];
  state.selectedId = null;
  state.selectedRecord = null;
  state.intercepts = [];
  state.selectedInterceptId = null;
  state.selectedInterceptRecord = null;
  state.websocketSessions = [];
  state.selectedWebsocketId = null;
  state.selectedWebsocketRecord = null;
  state.eventLog = [];
  state.matchReplaceRules = [];
  state.selectedMatchReplaceRuleId = null;
  state.targetSiteMap = [];
  state.targetScopeDraft = "";
  state.targetScopeDirty = false;
  state.targetExpandedHosts = new Set();
  state.replayTabs = [];
  state.activeReplayTabId = null;
  state.replayTabSequence = 0;
  state.fuzzerBaseRequest = null;
  state.fuzzerSourceTransactionId = null;
  state.fuzzerNotice = "";
  state.fuzzerRequestText = "";
  state.fuzzerPayloadsText = "";
  state.fuzzerAttackRecord = null;
}

async function reloadSessionWorkspace() {
  resetSessionScopedUiState();
  await loadSessions();
  await loadSettings();
  await loadWorkspaceState();
  await loadTransactions(false);
  await loadIntercepts(false);
  await loadWebsockets(false);
  await loadEventLog();
  await loadMatchReplaceRules();
  await loadTargetSiteMap(true);
  connectEvents();
  renderToolPanels();
}

async function createSession() {
  await flushWorkspaceState();
  const name = els.dashboardCreateSessionName.value.trim();
  const response = await fetch("/api/sessions", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({ name: name || null }),
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  els.dashboardCreateSessionName.value = "";
  await reloadSessionWorkspace();
}

async function activateSessionById(id) {
  await flushWorkspaceState();
  const response = await fetch(`/api/sessions/${id}/activate`, {
    method: "POST",
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  await reloadSessionWorkspace();
}

async function loadRuntimeSettings() {
  const response = await fetch("/api/runtime");
  state.runtime = await response.json();
  renderInterceptStatus();
  renderProxySettings();
}

async function loadTransactions(preserveSelection = true) {
  const limit = state.settings?.max_entries ?? 500;
  const response = await fetch(`/api/transactions?limit=${limit}`);
  state.items = await response.json();

  const visibleItems = getVisibleItems();
  if (!preserveSelection || !visibleItems.some((item) => item.id === state.selectedId)) {
    state.selectedId = visibleItems[0]?.id ?? null;
  }

  renderHistory();
  if (state.selectedId) {
    if (preserveSelection && state.selectedRecord && state.selectedRecord.id === state.selectedId) {
      return;
    }
    await loadTransactionDetail(state.selectedId);
  } else {
    renderEmptyDetail();
  }
}

async function loadTransactionDetail(id) {
  const response = await fetch(`/api/transactions/${id}`);
  if (!response.ok) {
    renderEmptyDetail();
    return;
  }

  state.selectedRecord = await response.json();
  renderDetail(state.selectedRecord);
}

async function loadIntercepts(preserveSelection = true) {
  const response = await fetch("/api/intercepts");
  state.intercepts = await response.json();

  if (!preserveSelection || !state.intercepts.some((item) => item.id === state.selectedInterceptId)) {
    state.selectedInterceptId = state.intercepts[0]?.id ?? null;
  }

  renderIntercepts();
  if (state.selectedInterceptId) {
    await loadInterceptDetail(state.selectedInterceptId);
  } else {
    state.selectedInterceptRecord = null;
    renderIntercepts();
  }
}

async function loadInterceptDetail(id) {
  const response = await fetch(`/api/intercepts/${id}`);
  if (!response.ok) {
    state.selectedInterceptRecord = null;
    renderIntercepts();
    return;
  }

  state.selectedInterceptRecord = await response.json();
  renderIntercepts();
}

async function loadWebsockets(preserveSelection = true) {
  const response = await fetch("/api/websockets?limit=200");
  state.websocketSessions = await response.json();
  await syncVisibleWebsocketSelection(preserveSelection);
}

async function loadWebsocketDetail(id) {
  const response = await fetch(`/api/websockets/${id}`);
  if (!response.ok) {
    if (state.selectedWebsocketId !== id) {
      return;
    }
    state.selectedWebsocketRecord = null;
    renderWebsocketSessions();
    return;
  }

  const detail = await response.json();
  if (state.selectedWebsocketId !== id) {
    return;
  }
  state.selectedWebsocketRecord = detail;
  renderWebsocketSessions();
}

async function loadEventLog() {
  const response = await fetch("/api/event-log?limit=200");
  state.eventLog = await response.json();
  renderEventLog();
}

async function clearEventLog() {
  await fetch("/api/event-log", { method: "DELETE" });
  state.eventLog = [];
  renderEventLog();
}

async function loadMatchReplaceRules() {
  const response = await fetch("/api/match-replace");
  state.matchReplaceRules = await response.json();
  if (!state.matchReplaceRules.some((rule) => rule.id === state.selectedMatchReplaceRuleId)) {
    state.selectedMatchReplaceRuleId = state.matchReplaceRules[0]?.id ?? null;
  }
  renderMatchReplaceRules();
}

async function saveMatchReplaceRules() {
  const response = await fetch("/api/match-replace", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({ rules: state.matchReplaceRules }),
  });
  state.matchReplaceRules = await response.json();
  if (!state.matchReplaceRules.some((rule) => rule.id === state.selectedMatchReplaceRuleId)) {
    state.selectedMatchReplaceRuleId = state.matchReplaceRules[0]?.id ?? null;
  }
  renderMatchReplaceRules();
}

function formatScopePatternsText(patterns) {
  return (patterns || []).join("\n");
}

function syncTargetScopeDraft(force = false) {
  const runtimeText = formatScopePatternsText(state.runtime?.scope_patterns);
  if (force || !state.targetScopeDirty) {
    state.targetScopeDraft = runtimeText;
    state.targetScopeDirty = false;
  }
}

async function loadTargetSiteMap(forceScopeSync = false) {
  const [runtimeResponse, siteMapResponse] = await Promise.all([
    fetch("/api/runtime"),
    fetch("/api/target/site-map"),
  ]);
  state.runtime = await runtimeResponse.json();
  state.targetSiteMap = await siteMapResponse.json();
  syncTargetScopeDraft(forceScopeSync);
  renderInterceptStatus();
  renderProxySettings();
  renderTarget();
}

async function pollAuxiliaryData() {
  const tasks = [];

  if (state.activeTool === "proxy" && state.activeProxyTab === "intercept") {
    tasks.push(loadIntercepts(true));
  }

  if (state.activeTool === "proxy" && state.activeProxyTab === "websockets-history") {
    tasks.push(loadWebsockets(true));
  }

  if (state.activeTool === "proxy" && state.activeProxyTab === "http-history") {
    tasks.push(loadTransactions(true));
  }

  if (state.activeTool === "logger") {
    tasks.push(loadEventLog());
  }

  if (state.activeTool === "target") {
    tasks.push(loadTargetSiteMap());
  }

  if (!tasks.length) {
    return;
  }

  await Promise.allSettled(tasks);
}

function connectEvents() {
  if (eventSource) {
    eventSource.close();
  }
  eventSource = new EventSource("/api/events");

  eventSource.addEventListener("transaction", () => {
    els.liveStatus.textContent = "Proxy live";
    els.liveStatus.classList.add("online");
    scheduleRefresh();
  });

  eventSource.addEventListener("event_log", () => {
    if (state.activeTool === "logger") {
      loadEventLog().catch((error) => console.error(error));
    } else {
      els.eventLogStatus.textContent = "New activity";
    }
  });

  eventSource.onerror = () => {
    els.liveStatus.textContent = "Retrying";
    els.liveStatus.classList.remove("online");
  };
}

function scheduleRefresh() {
  if (refreshTimer) {
    return;
  }
  refreshTimer = window.setTimeout(() => {
    refreshTimer = null;
    loadTransactions(true).catch((error) => console.error(error));
  }, 160);
}

function renderToolPanels() {
  if (!IMPLEMENTED_TOOLS.has(state.activeTool)) {
    state.activeTool = "proxy";
  }

  mainTabs.forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.tool === state.activeTool);
  });

  const dashboardVisible = state.activeTool === "dashboard";
  const proxyVisible = state.activeTool === "proxy";
  const replayVisible = state.activeTool === "replay";
  const decoderVisible = state.activeTool === "tools";
  const fuzzerVisible = state.activeTool === "fuzzer";
  const targetVisible = state.activeTool === "target";
  const loggerVisible = state.activeTool === "logger";
  els.dashboardShell.classList.toggle("hidden", !dashboardVisible);
  els.proxyShell.classList.toggle("hidden", !proxyVisible);
  els.replayShell.classList.toggle("hidden", !replayVisible);
  els.toolsShell.classList.toggle("hidden", !decoderVisible);
  els.fuzzerShell.classList.toggle("hidden", !fuzzerVisible);
  els.targetShell.classList.toggle("hidden", !targetVisible);
  els.loggerShell.classList.toggle("hidden", !loggerVisible);

  if (dashboardVisible) {
    renderDashboard();
    els.footerMode.textContent = "Session active";
    return;
  }

  if (proxyVisible) {
    renderProxyPanels();
    return;
  }

  if (replayVisible) {
    renderReplay();
    els.footerMode.textContent = "Replay active";
    return;
  }

  if (decoderVisible) {
    ensureDecoderWorkbench().catch((error) => {
      console.error(error);
      els.toolsMeta.textContent = "Failed to load decoder tools.";
    });
    els.footerMode.textContent = "Tools active";
    return;
  }

  if (fuzzerVisible) {
    renderFuzzer();
    els.footerMode.textContent = "Fuzzer active";
    return;
  }

  if (targetVisible) {
    renderTarget();
    els.footerMode.textContent = "Scope active";
    return;
  }

  if (loggerVisible) {
    renderEventLog();
    els.footerMode.textContent = "Event log active";
    return;
  }
}

async function ensureDecoderWorkbench() {
  if (state.toolsReady) {
    syncDecoderToolMeta();
    return;
  }

  if (!toolsBootPromise) {
    toolsBootPromise = bootToolsWorkbench();
  }

  await toolsBootPromise;
}

async function bootToolsWorkbench() {
  els.toolsMeta.textContent = "Loading decoder tools...";

  for (const source of DECODER_SCRIPT_SOURCES) {
    await loadScriptOnce(source);
  }

  if (!window.hasher || !window.tabs || !window.jQuery) {
    throw new Error("Decoder assets did not initialize correctly.");
  }

  const $ = window.jQuery;
  const refreshOutputs = () => {
    window.hasher.update();
    syncDecoderToolMeta();
    if (typeof window.autoScroll === "function") {
      window.autoScroll(els.toolsShell);
    }
  };

  $("#input-value, #input-password, #input-url").on("input", refreshOutputs);

  $("#tabs li").on("click", function () {
    const nextTab = window.tabs[this.id];
    if (nextTab == null) {
      return;
    }

    window.hasher.tab = nextTab;
    window.hasher.updateUI();
    syncDecoderToolMeta();
    document.getElementById("input-value")?.focus();
  });

  window.hasher.updateUI();
  syncDecoderToolMeta();
  if (typeof window.autoScroll === "function") {
    window.autoScroll(els.toolsShell);
  }
  state.toolsReady = true;
  els.toolsMeta.textContent = "Core decoder tools are ready. Click any result to copy it.";
}

function syncDecoderToolMeta() {
  const activeTab = document.querySelector("#tabs li.on");
  const activeLabel = activeTab?.textContent?.trim() || "Decoder";
  els.toolsActiveToolTitle.textContent = `${activeLabel} outputs`;
  els.toolsOutputMeta.textContent = "Click any result to copy it.";
}

function clearToolsInputs() {
  const input = document.getElementById("input-value");
  const password = document.getElementById("input-password");
  const url = document.getElementById("input-url");

  if (input) input.value = "";
  if (password) password.value = "";
  if (url) url.value = "";

  if (typeof window.resizeTextarea === "function" && input) {
    window.resizeTextarea(input);
  }

  if (state.toolsReady && window.hasher) {
    window.hasher.update();
    syncDecoderToolMeta();
  }
}

async function pasteIntoDecoder() {
  try {
    const text = await navigator.clipboard.readText();
    const input = document.getElementById("input-value");
    if (!input) {
      return;
    }

    input.value = text;
    input.focus();
    if (typeof window.resizeTextarea === "function") {
      window.resizeTextarea(input);
    }

    if (state.toolsReady && window.hasher) {
      window.hasher.update();
      syncDecoderToolMeta();
    }
  } catch (error) {
    console.error(error);
    els.toolsMeta.textContent = "Clipboard paste failed. Paste directly into the input field.";
  }
}

function loadScriptOnce(source) {
  const existing = document.querySelector(`script[data-dynamic-src="${source}"]`);
  if (existing) {
    if (existing.dataset.loaded === "true") {
      return Promise.resolve();
    }

    return new Promise((resolve, reject) => {
      existing.addEventListener("load", () => resolve(), { once: true });
      existing.addEventListener("error", () => reject(new Error(`Failed to load ${source}`)), { once: true });
    });
  }

  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = source;
    script.async = false;
    script.defer = true;
    script.dataset.dynamicSrc = source;
    script.addEventListener(
      "load",
      () => {
        script.dataset.loaded = "true";
        resolve();
      },
      { once: true },
    );
    script.addEventListener("error", () => reject(new Error(`Failed to load ${source}`)), { once: true });
    document.head.appendChild(script);
  });
}

function renderDashboard() {
  const current = state.activeSession || state.sessions.find((session) => session.active) || null;
  els.dashboardCurrentSessionName.textContent = current?.name || "No active session";
  els.dashboardCurrentSessionStatus.textContent = current?.active ? "Active" : "Unavailable";
  els.dashboardCurrentSessionStatus.className = `detail-chip ${current?.active ? "info" : "none"}`;
  els.dashboardCurrentSessionPath.textContent = current?.storage_path || "No storage path";
  els.dashboardCurrentSessionRequests.textContent = String(current?.request_count ?? 0);
  els.dashboardCurrentSessionWebsockets.textContent = String(current?.websocket_count ?? 0);
  els.dashboardCurrentSessionEvents.textContent = String(current?.event_count ?? 0);
  els.dashboardCurrentSessionFuzzer.textContent = String(current?.fuzzer_count ?? 0);
  els.dashboardCurrentSessionRules.textContent = String(current?.rule_count ?? 0);
  els.dashboardCurrentSessionCreated.textContent = current ? formatTimestamp(current.created_at) : "-";
  els.dashboardCurrentSessionOpened.textContent = current ? formatTimestamp(current.last_opened_at) : "-";

  els.dashboardSessionsBody.innerHTML = state.sessions.length
    ? state.sessions
        .map((session) => `
          <tr class="history-row ${session.active ? "selected" : ""}" data-id="${session.id}">
            <td>${escapeHtml(session.name)}</td>
            <td>${session.request_count}</td>
            <td>${session.websocket_count}</td>
            <td>${session.event_count}</td>
            <td>${session.rule_count}</td>
            <td>${escapeHtml(formatTimestamp(session.last_opened_at))}</td>
            <td>${session.active ? "<span class=\"detail-chip info\">Active</span>" : "<span class=\"detail-chip none\">Stored</span>"}</td>
            <td>
              <button class="secondary-action session-open-button" type="button" ${session.active ? "disabled" : ""}>
                ${session.active ? "Open" : "Activate"}
              </button>
            </td>
          </tr>
        `)
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="8">No sessions are available yet.</td>
        </tr>
      `;

  Array.from(els.dashboardSessionsBody.querySelectorAll("tr[data-id]")).forEach((row) => {
    row.addEventListener("click", () => {
      const { id } = row.dataset;
      if (!id || row.classList.contains("selected")) {
        return;
      }
      activateSessionById(id).catch((error) => console.error(error));
    });
  });
}

function renderProxyPanels() {
  proxyTabs.forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.proxyTab === state.activeProxyTab);
  });

  const showHistory = state.activeProxyTab === "http-history";
  const showIntercept = state.activeProxyTab === "intercept";
  const showWebsockets = state.activeProxyTab === "websockets-history";
  const showMatchReplace = state.activeProxyTab === "replace";
  const showProxySettings = state.activeProxyTab === "proxy-settings";
  const showPlaceholder = !showHistory && !showIntercept && !showWebsockets && !showMatchReplace && !showProxySettings;

  els.colorTagFilter.classList.toggle("hidden", !showHistory);
  els.filterBar.classList.toggle("hidden", !showHistory);
  els.trafficRegion.classList.toggle("hidden", !showHistory);
  els.historyWorkbenchResizer.classList.toggle("hidden", !showHistory);
  els.lowerWorkbench.classList.toggle("hidden", !showHistory);
  els.interceptPanel.classList.toggle("hidden", !showIntercept);
  els.websocketPanel.classList.toggle("hidden", !showWebsockets);
  els.matchReplacePanel.classList.toggle("hidden", !showMatchReplace);
  els.proxySettingsPanel.classList.toggle("hidden", !showProxySettings);
  els.proxySubPlaceholder.classList.toggle("hidden", !showPlaceholder);

  if (showHistory) {
    els.footerMode.textContent = "HTTP active";
    return;
  }

  if (showIntercept) {
    els.footerMode.textContent = "Intercept active";
    return;
  }

  if (showWebsockets) {
    els.footerMode.textContent = "Web Socket active";
    return;
  }

  if (showMatchReplace) {
    renderMatchReplaceRules();
    els.footerMode.textContent = "Replace active";
    return;
  }

  if (showProxySettings) {
    els.footerMode.textContent = "Settings active";
    return;
  }

  const label = humanizeProxyTab(state.activeProxyTab);
  els.proxySubPath.textContent = `Proxy / ${label}`;
  els.proxySubTitle.textContent = `${label} is planned next`;
  els.proxySubDescription.textContent = `${label} will plug into the same capture store and message workbench.`;
  els.footerMode.textContent = `${label} placeholder active`;
}

function renderInspectorPanels() {
  if (!els.lowerWorkbench) {
    return;
  }
  els.lowerWorkbench.classList.toggle("inspector-collapsed", state.inspectorCollapsed);
}

function renderInterceptStatus() {
  const enabled = Boolean(state.runtime?.intercept_enabled);
  els.interceptStatus.textContent = enabled ? "Intercept is on" : "Intercept is off";
  els.interceptStatus.classList.toggle("online", enabled);
}

function updateProxyStatusIndicator(online) {
  if (!els.proxyStatusIndicator) return;
  const isOnline = Boolean(online);
  els.proxyStatusIndicator.classList.toggle("online", isOnline);
  els.proxyStatusIndicator.classList.toggle("offline", !isOnline);
  els.proxyStatusLabel.textContent = isOnline ? "Proxy" : "Offline";
  els.proxyStatusIndicator.title = isOnline
    ? `Proxy listening on ${state.settings?.proxy_addr || "..."}`
    : `Proxy failed to bind on ${state.settings?.proxy_addr || "..."}. Restart the app after freeing the port.`;
}

function renderHistory() {
  const visibleEntries = getVisibleEntries();
  const visibleItems = visibleEntries.map((entry) => entry.item);
  const hiddenConnectCount = countHiddenConnectItems();
  const summary = [];
  summary.push(`${visibleItems.length} item(s) visible`);
  if (hiddenConnectCount) summary.push(`${hiddenConnectCount} CONNECT tunnel(s) hidden`);
  if (state.query) summary.push(`search: "${state.query}"`);
  if (state.method) summary.push(`method: ${state.method}`);
  if (state.filterSettings.inScopeOnly) summary.push("scope only");
  if (state.filterSettings.hideWithoutResponses) summary.push("responses only");
  if (state.filterSettings.onlyParameterized) summary.push("parameterized only");
  if (state.filterSettings.onlyNotes) summary.push("notes only");
  if (state.filterSettings.searchTerm) summary.push(`advanced: ${state.filterSettings.searchTerm}`);
  if (state.filterSettings.colorTags?.size) summary.push(`color: ${[...state.filterSettings.colorTags].join(", ")}`);
  summary.push(`sort: ${humanizeSortKey(state.sortKey)} ${state.sortDirection}`);
  els.historyMeta.textContent = `Filter settings: ${summary.join(" | ")}`;
  renderSortHeaders();

  if (!visibleItems.length) {
    els.historyTableBody.innerHTML = `
      <tr class="empty-row">
        <td colspan="10">${hiddenConnectCount ? "Only CONNECT tunnels were captured, and they are hidden from HTTP history. Trust the Sniper Root CA and retry the HTTPS client if you expect decrypted traffic." : "No traffic matches the current filter settings."}</td>
      </tr>
    `;
    return;
  }

  els.historyTableBody.innerHTML = visibleEntries
    .map((entry) => {
      const item = entry.item;
      const selected = item.id === state.selectedId ? "selected" : "";
      const tagClass = item.color_tag ? ` tagged-${escapeHtml(item.color_tag)}` : "";
      const cells = state.historyColumnOrder.map((colKey) => renderHistoryCell(colKey, item, entry)).join("");
      return `<tr class="history-row ${selected}${tagClass}" data-id="${item.id}">${cells}</tr>`;
    })
    .join("");

  Array.from(els.historyTableBody.querySelectorAll(".history-row")).forEach((row) => {
    row.addEventListener("click", () => {
      state.selectedId = row.dataset.id;
      renderHistory();
      scrollSelectedHistoryRowIntoView();
      loadTransactionDetail(state.selectedId).catch((error) => console.error(error));
    });
    row.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      state.selectedId = row.dataset.id;
      renderHistory();
      openContextMenu(event.clientX, event.clientY, row.dataset.id);
    });
  });
}

async function moveHistorySelection(offset) {
  const visibleEntries = getVisibleEntries();
  if (!visibleEntries.length) {
    return;
  }

  const currentIndex = visibleEntries.findIndex((entry) => entry.item.id === state.selectedId);
  const fallbackIndex = offset > 0 ? 0 : visibleEntries.length - 1;
  const nextIndex = clamp(
    currentIndex === -1 ? fallbackIndex : currentIndex + offset,
    0,
    visibleEntries.length - 1,
  );
  const nextId = visibleEntries[nextIndex]?.item.id;
  if (!nextId) {
    return;
  }

  state.selectedId = nextId;
  renderHistory();
  scrollSelectedHistoryRowIntoView();
  await loadTransactionDetail(nextId);
}

function scrollSelectedHistoryRowIntoView() {
  const selectedRow = els.historyTableBody.querySelector(".history-row.selected");
  selectedRow?.scrollIntoView({ block: "nearest" });
}

async function moveWebsocketSelection(offset) {
  const visibleSessions = getVisibleWebsocketSessions();
  if (!visibleSessions.length) {
    return;
  }

  const currentIndex = visibleSessions.findIndex((session) => session.id === state.selectedWebsocketId);
  const fallbackIndex = offset > 0 ? 0 : visibleSessions.length - 1;
  const nextIndex = clamp(
    currentIndex === -1 ? fallbackIndex : currentIndex + offset,
    0,
    visibleSessions.length - 1,
  );
  const nextId = visibleSessions[nextIndex]?.id;
  if (!nextId) {
    return;
  }

  state.selectedWebsocketId = nextId;
  renderWebsocketSessions();
  scrollSelectedWebsocketRowIntoView();
  await loadWebsocketDetail(nextId);
}

function scrollSelectedWebsocketRowIntoView() {
  const selectedRow = els.websocketTableBody.querySelector(".history-row.selected");
  selectedRow?.scrollIntoView({ block: "nearest" });
}

function isEditableTarget(target) {
  if (!(target instanceof HTMLElement)) {
    return false;
  }

  if (target.isContentEditable) {
    return true;
  }

  const tagName = target.tagName.toLowerCase();
  if (["input", "textarea", "select", "option", "button"].includes(tagName)) {
    return true;
  }

  return Boolean(target.closest("input, textarea, select, [contenteditable='true']"));
}

function isSelectableTextTarget(target) {
  if (!(target instanceof HTMLElement)) {
    return false;
  }

  if (target.isContentEditable) {
    return true;
  }

  const direct =
    target instanceof HTMLTextAreaElement
    || (
      target instanceof HTMLInputElement
      && ["text", "search", "password", "url", "email", "tel", "number", ""].includes(
        (target.type || "").toLowerCase(),
      )
    );

  if (direct) {
    return true;
  }

  return Boolean(
    target.closest(
      "textarea, input[type='text'], input[type='search'], input[type='password'], input[type='url'], input[type='email'], input[type='tel'], input[type='number'], input:not([type]), [contenteditable='true']",
    ),
  );
}

function selectEditableTargetContents(target) {
  if (!(target instanceof HTMLElement)) {
    return;
  }

  const element =
    target.closest(
      "textarea, input[type='text'], input[type='search'], input[type='password'], input[type='url'], input[type='email'], input[type='tel'], input[type='number'], input:not([type]), [contenteditable='true']",
    ) || target;

  if (element instanceof HTMLTextAreaElement || element instanceof HTMLInputElement) {
    element.focus();
    element.select();
    return;
  }

  if (element instanceof HTMLElement && element.isContentEditable) {
    const selection = window.getSelection();
    if (!selection) {
      return;
    }
    const range = document.createRange();
    range.selectNodeContents(element);
    selection.removeAllRanges();
    selection.addRange(range);
  }
}

function getActiveMessagePane() {
  if (document.activeElement === els.requestView) {
    return "request";
  }

  if (document.activeElement === els.responseView) {
    return "response";
  }

  const selection = window.getSelection();
  const anchorNode = selection?.anchorNode;
  if (anchorNode instanceof Node) {
    if (els.requestView?.contains(anchorNode)) {
      return "request";
    }

    if (els.responseView?.contains(anchorNode)) {
      return "response";
    }
  }

  return state.activeMessagePane;
}

function getSelectedCodePaneText() {
  const selection = window.getSelection();
  if (!selection || selection.isCollapsed || !selection.toString()) {
    return "";
  }

  if (!selection.rangeCount) {
    return "";
  }

  const range = selection.getRangeAt(0);
  const container = range.commonAncestorContainer;
  if (
    els.requestView?.contains(container)
    || els.responseView?.contains(container)
  ) {
    return selection.toString();
  }

  const anchorNode = selection.anchorNode;
  const focusNode = selection.focusNode;
  if (
    (anchorNode instanceof Node && (els.requestView?.contains(anchorNode) || els.responseView?.contains(anchorNode)))
    || (focusNode instanceof Node && (els.requestView?.contains(focusNode) || els.responseView?.contains(focusNode)))
  ) {
    return selection.toString();
  }

  return "";
}

async function copyTextToClipboard(text) {
  if (!text) {
    return;
  }

  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "true");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  textarea.style.pointerEvents = "none";
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand("copy");
  textarea.remove();
}

function selectCodePaneContents(targetPane) {
  const viewElement = targetPane === "response" ? els.responseView : els.requestView;
  if (!viewElement) {
    return;
  }

  viewElement.focus({ preventScroll: true });
  const range = document.createRange();
  range.selectNodeContents(viewElement);

  const selection = window.getSelection();
  selection?.removeAllRanges();
  selection?.addRange(range);
}

function renderDetail(record) {
  if (!els.detailTitle) return;
  els.detailTitle.textContent = "Inspector";
  els.detailTags.innerHTML = "";

  const protocolState = inferProtocolState(record);

  const attributes = [
    { label: "Method", value: record.method },
    { label: "Path", value: record.path || "/" },
    ["Started", formatTimestamp(record.started_at)],
    ["Duration", `${record.duration_ms} ms`],
    ["Host", record.host],
    ["Request size", formatSize(record.request.body_size)],
    ["Response size", formatSize(record.response?.body_size ?? 0)],
    ["MIME type", record.response?.content_type || record.request.content_type || "n/a"],
    ["Notes", `${record.notes.length}`],
    ...(record.color_tag ? [["Color tag", record.color_tag]] : []),
    ...(record.user_note ? [["User note", record.user_note]] : []),
  ];

  els.attributesCount.textContent = String(attributes.length);
  els.protocolStrip.innerHTML = renderProtocolStrip(protocolState);
  els.summaryList.innerHTML = renderSummaryRows(attributes);

  els.requestHeaderCount.textContent = String(record.request.headers.length);
  els.responseHeaderCount.textContent = String(record.response?.headers?.length ?? 0);
  els.requestHeadersBody.innerHTML = renderHeaderList(record.request.headers);
  els.responseHeadersBody.innerHTML = record.response
    ? renderHeaderList(record.response.headers)
    : "<p class=\"empty-copy\">No response headers were captured.</p>";

  const noteParts = [];
  if (record.user_note) {
    noteParts.push(`<p class="user-note-display"><strong>Note:</strong> ${escapeHtml(record.user_note)}</p>`);
  }
  if (record.notes.length) {
    noteParts.push(...record.notes.map((note) => `<p>${escapeHtml(note)}</p>`));
  }
  els.notesCard.innerHTML = noteParts.length
    ? noteParts.join("")
    : "<p>No anomalies were recorded for this transaction.</p>";

  renderMessagePanes();
}

function renderEmptyDetail() {
  state.selectedRecord = null;
  els.detailTitle.textContent = "Inspector";
  els.detailTags.innerHTML = "";
  els.protocolStrip.innerHTML = renderProtocolStrip({ current: "HTTP/1", supportsHttp2: false });
  els.attributesCount.textContent = "0";
  els.requestHeaderCount.textContent = "0";
  els.responseHeaderCount.textContent = "0";
  els.summaryList.innerHTML = renderSummaryRows([
    { label: "Status", value: "Select a transaction to inspect it." },
  ]);
  els.requestHeadersBody.innerHTML = "<p class=\"empty-copy\">Select a transaction from HTTP.</p>";
  els.responseHeadersBody.innerHTML = "<p class=\"empty-copy\">No response selected.</p>";
  els.notesCard.innerHTML = "<p>No anomalies were recorded for this transaction.</p>";
  renderMessagePanes();
}

function renderMessagePanes() {
  const requestText = state.selectedRecord
    ? buildMessagePresentation("request", state.selectedRecord)
    : "Select a transaction from HTTP.";
  const responseText = state.selectedRecord
    ? buildMessagePresentation("response", state.selectedRecord)
    : "No response selected.";

  const requestPane = updateCodePane(
    els.requestView,
    els.requestLines,
    requestText,
    state.messageViews.request,
    "request",
  );
  const responsePane = updateCodePane(
    els.responseView,
    els.responseLines,
    responseText,
    state.messageViews.response,
    "response",
  );
  if (els.requestSearchInput.value !== state.messageSearch.request) {
    els.requestSearchInput.value = state.messageSearch.request;
  }
  if (els.responseSearchInput.value !== state.messageSearch.response) {
    els.responseSearchInput.value = state.messageSearch.response;
  }
  els.requestSearchMeta.textContent = buildSearchMeta(
    requestPane.lineCount,
    state.messageViews.request,
    requestPane.matchCount,
  );
  els.responseSearchMeta.textContent = buildSearchMeta(
    responsePane.lineCount,
    state.messageViews.response,
    responsePane.matchCount,
  );
}

function renderViewTabs() {
  const record = state.selectedRecord;
  const hasRequestDiff = Boolean(record?.original_request);
  const hasResponseDiff = Boolean(record?.original_response);
  viewTabs.forEach((tab) => {
    const target = tab.dataset.target;
    tab.classList.toggle("active", state.messageViews[target] === tab.dataset.view);
    if (tab.dataset.view === "diff") {
      const hasDiff = target === "request" ? hasRequestDiff : hasResponseDiff;
      tab.classList.toggle("hidden", !hasDiff);
    }
  });
}

function renderIntercepts() {
  els.interceptTableBody.innerHTML = state.intercepts.length
    ? state.intercepts
        .map((item) => {
          const selected = item.id === state.selectedInterceptId ? "selected" : "";
          return `
            <tr class="history-row ${selected}" data-id="${item.id}">
              <td>${escapeHtml(item.method)}</td>
              <td>${escapeHtml(item.host)}</td>
              <td>${escapeHtml(item.path || "/")}</td>
              <td>${item.is_websocket ? "WebSocket" : "HTTP"}</td>
              <td>${escapeHtml(formatTimestamp(item.started_at))}</td>
            </tr>
          `;
        })
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="5">Intercept queue is empty.</td>
        </tr>
      `;

  Array.from(els.interceptTableBody.querySelectorAll(".history-row")).forEach((row) => {
    row.addEventListener("click", () => {
      state.selectedInterceptId = row.dataset.id;
      loadInterceptDetail(row.dataset.id).catch((error) => console.error(error));
    });
  });

  if (!state.selectedInterceptRecord) {
    state.interceptEditorSeedId = null;
    els.interceptDetailPath.textContent = "Intercept";
    els.interceptDetailTitle.textContent = "No request selected";
    els.interceptRequestEditor.value = "";
    renderInterceptRequestHighlight("");
    els.interceptMeta.textContent = state.runtime?.intercept_enabled
      ? "Intercept is on. New requests will queue here."
      : "Intercept is off. Toggle it on to pause requests before forwarding.";
    els.forwardInterceptButton.disabled = true;
    els.dropInterceptButton.disabled = true;
    return;
  }

  els.interceptDetailPath.textContent = `${state.selectedInterceptRecord.request.scheme.toUpperCase()} / ${state.selectedInterceptRecord.peer_addr}`;
  els.interceptDetailTitle.textContent = `${state.selectedInterceptRecord.request.method} ${state.selectedInterceptRecord.request.host}`;
  if (state.interceptEditorSeedId !== state.selectedInterceptRecord.id || document.activeElement !== els.interceptRequestEditor) {
    els.interceptRequestEditor.value = buildEditableRawRequest(state.selectedInterceptRecord.request);
    state.interceptEditorSeedId = state.selectedInterceptRecord.id;
  }
  renderInterceptRequestHighlight(els.interceptRequestEditor.value);
  els.interceptMeta.textContent = [
    state.selectedInterceptRecord.is_websocket ? "WebSocket upgrade" : "HTTP request",
    `queued at ${formatTimestamp(state.selectedInterceptRecord.started_at)}`,
    state.selectedInterceptRecord.request.preview_truncated ? "captured request body is preview-truncated" : "body captured in memory",
  ].join(" · ");
  els.forwardInterceptButton.disabled = false;
  els.dropInterceptButton.disabled = false;
}

function renderWebsocketSessions() {
  const visibleSessions = getVisibleWebsocketSessions();
  if (els.websocketSearchInput.value !== state.websocketQuery) {
    els.websocketSearchInput.value = state.websocketQuery;
  }
  els.websocketMeta.textContent = buildWebsocketFilterSummary(
    visibleSessions.length,
    state.websocketSessions.length,
    state.websocketQuery,
  );

  els.websocketTableBody.innerHTML = visibleSessions.length
    ? visibleSessions
        .map((session) => {
          const selected = session.id === state.selectedWebsocketId ? "selected" : "";
          return `
            <tr class="history-row ${selected}" data-id="${session.id}">
              <td>${escapeHtml(session.host)}</td>
              <td>${escapeHtml(session.path)}</td>
              <td>${escapeHtml(formatStatus(session.status))}</td>
              <td>${session.frame_count}</td>
              <td>${session.duration_ms == null ? "live" : `${session.duration_ms} ms`}</td>
              <td>${escapeHtml(formatTimestamp(session.started_at))}</td>
            </tr>
          `;
        })
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="6">${
            state.websocketSessions.length
              ? "No WebSocket sessions match the current filter."
              : "No WebSocket sessions have been captured yet."
          }</td>
        </tr>
      `;

  Array.from(els.websocketTableBody.querySelectorAll(".history-row")).forEach((row) => {
    row.addEventListener("click", () => {
      state.selectedWebsocketId = row.dataset.id;
      loadWebsocketDetail(row.dataset.id).catch((error) => console.error(error));
    });
  });

  if (!state.selectedWebsocketRecord) {
    els.websocketDetailTitle.textContent = "No session selected";
    els.websocketRequestView.textContent = state.websocketSessions.length && !visibleSessions.length
      ? "No WebSocket session matches the current filter."
      : "Select a WebSocket session.";
    els.websocketResponseView.textContent = "No response selected.";
    els.websocketFramesBody.innerHTML = `
      <tr class="empty-row">
        <td colspan="5">${
          state.websocketSessions.length && !visibleSessions.length
            ? "Clear or adjust the filter to inspect captured frames."
            : "Frame capture will appear here after a WebSocket handshake completes."
        }</td>
      </tr>
    `;
    return;
  }

  const session = state.selectedWebsocketRecord;
  els.websocketDetailTitle.textContent = `${session.host}${session.path}`;
  els.websocketRequestView.innerHTML = renderHttpHtml(buildRawWebsocketRequest(session), "request");
  els.websocketResponseView.innerHTML = renderHttpHtml(buildRawWebsocketResponse(session), "response");
  els.websocketFramesBody.innerHTML = session.frames.length
    ? session.frames
        .map((frame) => `
          <tr>
            <td>${frame.index}</td>
            <td>${frame.direction.replaceAll("_", " ")}</td>
            <td>${frame.kind}</td>
            <td>${escapeHtml(formatSize(frame.body_size))}</td>
            <td class="cell-url">${escapeHtml(renderFramePreview(frame))}</td>
          </tr>
        `)
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="5">Handshake captured, but no frames have been recorded yet.</td>
        </tr>
      `;
}

function buildWebsocketFilterSummary(visibleCount, totalCount, query) {
  const summary = `${visibleCount} session(s) visible`;
  const total = totalCount ? `${totalCount} total captured` : "No sessions captured yet";
  if (!query) {
    return `${summary} · ${total}`;
  }
  return `${summary} · filter: ${query} · ${total}`;
}

function getVisibleWebsocketSessions() {
  const normalizedQuery = state.websocketQuery.trim().toLowerCase();
  if (!normalizedQuery) {
    return state.websocketSessions;
  }

  return state.websocketSessions.filter((session) => {
    const haystack = [
      session.host,
      session.path,
      formatStatus(session.status),
      String(session.frame_count),
      session.duration_ms == null ? "live" : `${session.duration_ms} ms`,
      formatTimestamp(session.started_at),
    ]
      .filter(Boolean)
      .join("\n")
      .toLowerCase();
    return haystack.includes(normalizedQuery);
  });
}

async function syncVisibleWebsocketSelection(preserveSelection = true) {
  const visibleSessions = getVisibleWebsocketSessions();
  if (!preserveSelection || !visibleSessions.some((item) => item.id === state.selectedWebsocketId)) {
    state.selectedWebsocketId = visibleSessions[0]?.id ?? null;
  }

  if (!state.selectedWebsocketId) {
    state.selectedWebsocketRecord = null;
    renderWebsocketSessions();
    return;
  }

  if (state.selectedWebsocketRecord?.id !== state.selectedWebsocketId) {
    state.selectedWebsocketRecord = null;
  }
  renderWebsocketSessions();
  await loadWebsocketDetail(state.selectedWebsocketId);
}

function renderProxySettings() {
  if (!state.settings || !state.runtime) {
    return;
  }

  const startup = state.settings.startup;
  els.proxySettingIntercept.checked = Boolean(state.runtime.intercept_enabled);
  els.proxySettingWebsocketCapture.checked = Boolean(state.runtime.websocket_capture_enabled);
  els.proxySettingScopePatterns.value = (state.runtime.scope_patterns || []).join("\n");
  els.proxySettingPassthroughHosts.value = (state.runtime.passthrough_hosts || []).join("\n");
  if (startup && document.activeElement !== els.proxySettingBindHost) {
    els.proxySettingBindHost.value = startup.proxy_bind_host;
  }
  if (startup && document.activeElement !== els.proxySettingPort) {
    els.proxySettingPort.value = String(startup.proxy_port);
  }
  els.proxySettingsProxyAddr.textContent = state.settings.proxy_addr;
  els.proxySettingsNextProxyAddr.textContent = startup?.proxy_addr || state.settings.proxy_addr;
  els.proxySettingsUiAddr.textContent = state.settings.ui_addr;
  els.proxySettingsCaptureCap.textContent = `${formatSize(state.settings.body_preview_bytes)} preview / ${state.settings.max_entries} entries`;
  els.proxySettingsBootstrap.textContent = state.settings.certificate.special_host_https;
  els.proxySettingsDataDir.textContent = state.settings.data_dir;
  els.proxySettingsStartupPath.textContent = startup?.file_path || state.settings.data_dir;
  els.proxySettingsCertificateName.textContent = `${state.settings.certificate.common_name} · expires ${formatTimestamp(state.settings.certificate.expires_at)}`;
  els.proxySettingListenerHelp.textContent = startup
    ? startup.restart_required
      ? `Saved ${startup.proxy_addr} for the next launch. Restart Sniper to replace the active listener ${startup.active_proxy_addr}.`
      : `Proxy listener is already running on ${startup.active_proxy_addr}. Changes here apply on the next launch.`
    : "Changes are saved for the next app start.";
}

function renderReplay() {
  const tab = ensureRepeaterTab();
  renderReplayTabs();

  if (!tab) {
    els.replayRequestEditor.value = "";
    renderReplayRequestHighlight("");
    els.replayHostInput.value = "";
    els.replayPortInput.value = "";
    els.replaySchemeSelect.value = "https";
    els.replayResponseMeta.textContent = "No response yet.";
    renderReplayResponseView("Send a request from Replay to capture the response here.");
    updateReplaySearchPane("request", "");
    updateReplaySearchPane("response", "Send a request from Replay to capture the response here.");
    els.replayBackButton.disabled = true;
    els.replayForwardButton.disabled = true;
    return;
  }

  syncReplayToolbar(tab);
  if (els.replayRequestEditor.value !== tab.requestText) {
    els.replayRequestEditor.value = tab.requestText;
  }
  renderReplayRequestHighlight(tab.requestText);
  updateReplaySearchPane("request", tab.requestText);

  if (!tab.responseRecord) {
    const notice = tab.notice || "Send a request from Replay to capture the response here.";
    els.replayResponseMeta.textContent = tab.notice || "No response yet.";
    renderReplayResponseView(notice);
    updateReplaySearchPane("response", notice);
    return;
  }

  els.replayResponseMeta.textContent = [
    `${formatStatus(tab.responseRecord.status)}`,
    `${tab.responseRecord.duration_ms} ms`,
    tab.responseRecord.response?.content_type || tab.responseRecord.request.content_type || "n/a",
  ].join(" · ");

  const responseText = prettyFormat(
    buildRawResponse(tab.responseRecord),
    tab.responseRecord.response,
  );
  renderReplayResponseView(responseText);
  updateReplaySearchPane("response", responseText);
}

function renderReplayRequestHighlight(text) {
  if (!els.replayRequestHighlight) {
    return;
  }

  els.replayRequestHighlight.innerHTML = renderCodeHtml(text, "pretty", "request");
  syncReplayRequestHighlightScroll();
}

function syncReplayRequestHighlightScroll() {
  if (!els.replayRequestHighlight || !els.replayRequestEditor) {
    return;
  }

  els.replayRequestHighlight.scrollTop = els.replayRequestEditor.scrollTop;
  els.replayRequestHighlight.scrollLeft = els.replayRequestEditor.scrollLeft;
}

function renderInterceptRequestHighlight(text) {
  if (!els.interceptRequestHighlight) {
    return;
  }

  els.interceptRequestHighlight.innerHTML = renderCodeHtml(text, "pretty", "request");
  syncInterceptRequestHighlightScroll();
}

function syncInterceptRequestHighlightScroll() {
  if (!els.interceptRequestHighlight || !els.interceptRequestEditor) {
    return;
  }

  els.interceptRequestHighlight.scrollTop = els.interceptRequestEditor.scrollTop;
  els.interceptRequestHighlight.scrollLeft = els.interceptRequestEditor.scrollLeft;
}

function renderFuzzerRequestHighlight(text) {
  if (!els.fuzzerRequestHighlight) {
    return;
  }

  els.fuzzerRequestHighlight.innerHTML = renderCodeHtml(text, "pretty", "request");
  syncFuzzerRequestHighlightScroll();
}

function syncFuzzerRequestHighlightScroll() {
  if (!els.fuzzerRequestHighlight || !els.fuzzerRequestEditor) {
    return;
  }

  els.fuzzerRequestHighlight.scrollTop = els.fuzzerRequestEditor.scrollTop;
  els.fuzzerRequestHighlight.scrollLeft = els.fuzzerRequestEditor.scrollLeft;
}

function renderReplayResponseView(text) {
  els.replayResponseView.innerHTML = renderCodeHtml(text, "pretty", "response");
}

function updateReplaySearchPane(target, text) {
  const isRequest = target === "request";
  const query = state.replayMessageSearch[target];
  const input = isRequest ? els.replayRequestSearchInput : els.replayResponseSearchInput;
  const meta = isRequest ? els.replayRequestSearchMeta : els.replayResponseSearchMeta;
  const view = isRequest ? els.replayRequestHighlight : els.replayResponseView;

  if (input && input.value !== query) {
    input.value = query;
  }

  if (!view || !meta) {
    return;
  }

  const searchResult = applyCodeSearch(view, query);
  meta.textContent = buildSearchMeta(countLines(text), "pretty", searchResult.count);
}

function syncReplayToolbar(tab) {
  const request = deriveRepeaterRequest(tab);
  const target = getRepeaterTargetConfig(tab, request);
  if (document.activeElement !== els.replayHostInput && els.replayHostInput.value !== target.host) {
    els.replayHostInput.value = target.host;
  }
  if (document.activeElement !== els.replayPortInput && els.replayPortInput.value !== target.port) {
    els.replayPortInput.value = target.port;
  }
  if (document.activeElement !== els.replaySchemeSelect && els.replaySchemeSelect.value !== target.scheme) {
    els.replaySchemeSelect.value = target.scheme;
  }
  els.replayBackButton.disabled = !canNavigateReplayHistory(tab, -1);
  els.replayForwardButton.disabled = !canNavigateReplayHistory(tab, 1);
  return target;
}

function renderEventLog() {
  els.eventLogStatus.textContent = `${state.eventLog.length} entr${state.eventLog.length === 1 ? "y" : "ies"}`;
  els.eventLogTableBody.innerHTML = state.eventLog.length
    ? state.eventLog
        .map((entry) => `
          <tr>
            <td>${escapeHtml(formatTimestamp(entry.captured_at))}</td>
            <td>${escapeHtml(entry.level)}</td>
            <td>${escapeHtml(entry.source)}</td>
            <td>${escapeHtml(entry.title)}</td>
            <td>${escapeHtml(entry.message)}</td>
          </tr>
        `)
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="5">No runtime events have been recorded yet.</td>
        </tr>
      `;
}

function renderMatchReplaceRules() {
  const selected = getSelectedMatchReplaceRule();
  els.matchReplaceTableBody.innerHTML = state.matchReplaceRules.length
    ? state.matchReplaceRules
        .map((rule) => {
          const active = rule.id === state.selectedMatchReplaceRuleId ? "selected" : "";
          return `
            <tr class="history-row ${active}" data-id="${rule.id}">
              <td><label class="mini-toggle"><input type="checkbox" data-rule-toggle="${rule.id}" ${rule.enabled ? "checked" : ""} /><span class="mini-toggle-track"></span></label></td>
              <td>${escapeHtml(rule.description || "Untitled rule")}</td>
              <td>${escapeHtml(rule.scope)}</td>
              <td>${escapeHtml(rule.target)}</td>
            </tr>
          `;
        })
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="4">No replace rules are configured.</td>
        </tr>
      `;

  Array.from(els.matchReplaceTableBody.querySelectorAll(".history-row")).forEach((row) => {
    row.addEventListener("click", (event) => {
      if (event.target.closest(".mini-toggle")) return;
      state.selectedMatchReplaceRuleId = row.dataset.id;
      renderMatchReplaceRules();
    });
  });

  Array.from(els.matchReplaceTableBody.querySelectorAll("[data-rule-toggle]")).forEach((toggle) => {
    toggle.addEventListener("change", (event) => {
      event.stopPropagation();
      const rule = state.matchReplaceRules.find((r) => r.id === toggle.dataset.ruleToggle);
      if (rule) {
        rule.enabled = toggle.checked;
        saveMatchReplaceRules().catch(console.error);
      }
    });
  });

  if (!selected) {
    els.matchReplaceEditorPath.textContent = "Rule";
    els.matchReplaceEditorTitle.textContent = "New rule";
    els.matchReplaceEnabled.checked = true;
    els.matchReplaceDescription.value = "";
    els.matchReplaceScope.value = "request";
    els.matchReplaceTarget.value = "any";
    els.matchReplaceSearch.value = "";
    els.matchReplaceReplace.value = "";
    els.matchReplaceRegex.checked = false;
    els.matchReplaceCaseSensitive.checked = false;
    els.deleteMatchReplaceRuleButton.disabled = true;
    els.saveMatchReplaceRuleButton.textContent = "Add";
    return;
  }

  els.matchReplaceEditorPath.textContent = `${selected.scope} / ${selected.target}`;
  els.matchReplaceEditorTitle.textContent = selected.description || "Edit rule";
  els.matchReplaceEnabled.checked = Boolean(selected.enabled);
  els.matchReplaceDescription.value = selected.description || "";
  els.matchReplaceScope.value = selected.scope;
  els.matchReplaceTarget.value = selected.target;
  els.matchReplaceSearch.value = selected.search;
  els.matchReplaceReplace.value = selected.replace;
  els.matchReplaceRegex.checked = Boolean(selected.regex);
  els.matchReplaceCaseSensitive.checked = Boolean(selected.case_sensitive);
  els.deleteMatchReplaceRuleButton.disabled = false;
  els.saveMatchReplaceRuleButton.textContent = "Save";
}

function renderTarget() {
  if (!state.targetScopeDirty) {
    state.targetScopeDraft = formatScopePatternsText(state.runtime?.scope_patterns);
  }

  if (
    document.activeElement !== els.targetScopeEditor
    && els.targetScopeEditor.value !== state.targetScopeDraft
  ) {
    els.targetScopeEditor.value = state.targetScopeDraft;
  }

  const liveHosts = new Set(state.targetSiteMap.map((host) => host.host));
  state.targetExpandedHosts = new Set(
    Array.from(state.targetExpandedHosts).filter((host) => liveHosts.has(host)),
  );

  els.targetTree.innerHTML = state.targetSiteMap.length
    ? state.targetSiteMap
        .map((host) => `
          <section class="target-host-card">
            <button
              class="target-host-toggle ${state.targetExpandedHosts.has(host.host) ? "expanded" : ""}"
              type="button"
              data-target-host="${escapeHtml(host.host)}"
              aria-expanded="${state.targetExpandedHosts.has(host.host) ? "true" : "false"}"
            >
              <div class="target-host-copy">
                <div class="target-host-title">${escapeHtml(host.host)}</div>
                <div class="target-path-meta">${host.request_count} request(s) · ${host.paths.length} path(s) · ${host.schemes.join(", ") || "http"}</div>
              </div>
              <div class="target-host-actions">
                <span class="detail-chip ${host.in_scope ? "ok" : "none"}">${host.in_scope ? "In scope" : "Out of scope"}</span>
                <span class="target-host-chevron" aria-hidden="true">▾</span>
              </div>
            </button>
            <div class="target-path-list" ${state.targetExpandedHosts.has(host.host) ? "" : "hidden"}>
              ${host.paths.map((path) => `
                <div class="target-path-item">
                  <div class="target-path-title">${escapeHtml(path.path || "/")}</div>
                  <div class="target-path-meta">
                    ${escapeHtml(path.methods.join(", "))} · ${escapeHtml(formatStatus(path.status))} · ${escapeHtml(formatTimestamp(path.last_seen))}${path.is_websocket ? " · websocket" : ""}${path.note_count ? ` · ${path.note_count} note(s)` : ""}
                  </div>
                </div>
              `).join("")}
            </div>
          </section>
        `)
        .join("")
    : "<p class=\"empty-copy\">No captured targets yet. Send traffic through the proxy to build a site map.</p>";

  Array.from(els.targetTree.querySelectorAll(".target-host-toggle")).forEach((button) => {
    button.addEventListener("click", () => {
      const host = button.dataset.targetHost;
      if (!host) {
        return;
      }

      if (state.targetExpandedHosts.has(host)) {
        state.targetExpandedHosts.delete(host);
      } else {
        state.targetExpandedHosts.add(host);
      }

      renderTarget();
    });
  });
}

function renderFuzzer() {
  if (els.fuzzerRequestEditor.value !== state.fuzzerRequestText) {
    els.fuzzerRequestEditor.value = state.fuzzerRequestText;
  }
  renderFuzzerRequestHighlight(state.fuzzerRequestText);
  if (els.fuzzerPayloadsEditor.value !== state.fuzzerPayloadsText) {
    els.fuzzerPayloadsEditor.value = state.fuzzerPayloadsText;
  }

  if (!state.fuzzerAttackRecord) {
    els.fuzzerMeta.textContent = state.fuzzerNotice || "No fuzz run has been started yet.";
    els.fuzzerResultsBody.innerHTML = `
      <tr class="empty-row">
        <td colspan="6">${escapeHtml(state.fuzzerNotice || "Use Command+I from HTTP or paste a template with markers to run the fuzzer.")}</td>
      </tr>
    `;
    return;
  }

  els.fuzzerMeta.textContent = [
    `${state.fuzzerAttackRecord.payload_count} payload(s)`,
    `${state.fuzzerAttackRecord.marker_count} marker(s)`,
    state.fuzzerAttackRecord.status,
  ].join(" · ");
  els.fuzzerResultsBody.innerHTML = state.fuzzerAttackRecord.results
    .map((result) => `
      <tr>
        <td>${result.index + 1}</td>
        <td class="cell-url">${escapeHtml(result.payload)}</td>
        <td>${escapeHtml(formatStatus(result.status))}</td>
        <td>${result.duration_ms == null ? "-" : `${result.duration_ms} ms`}</td>
        <td>${escapeHtml(formatSize(result.response_bytes))}</td>
        <td>${result.transaction_id ? escapeHtml(String(result.transaction_id).slice(0, 8)) : escapeHtml(result.note || "-")}</td>
      </tr>
    `)
    .join("");
}

function createNewMatchReplaceRule() {
  const rule = {
    id: crypto.randomUUID(),
    enabled: true,
    description: "",
    scope: "request",
    target: "any",
    search: "",
    replace: "",
    regex: false,
    case_sensitive: false,
  };
  state.matchReplaceRules = [rule, ...state.matchReplaceRules];
  state.selectedMatchReplaceRuleId = rule.id;
  renderMatchReplaceRules();
}

function getSelectedMatchReplaceRule() {
  return state.matchReplaceRules.find((rule) => rule.id === state.selectedMatchReplaceRuleId) || null;
}

function syncMatchReplaceEditor() {
  const rule = getSelectedMatchReplaceRule();
  if (!rule) {
    return;
  }

  rule.enabled = els.matchReplaceEnabled.checked;
  rule.description = els.matchReplaceDescription.value.trim();
  rule.scope = els.matchReplaceScope.value;
  rule.target = els.matchReplaceTarget.value;
  rule.search = els.matchReplaceSearch.value;
  rule.replace = els.matchReplaceReplace.value;
  rule.regex = els.matchReplaceRegex.checked;
  rule.case_sensitive = els.matchReplaceCaseSensitive.checked;
}

function deleteSelectedMatchReplaceRule() {
  if (!state.selectedMatchReplaceRuleId) {
    return;
  }

  state.matchReplaceRules = state.matchReplaceRules.filter((rule) => rule.id !== state.selectedMatchReplaceRuleId);
  state.selectedMatchReplaceRuleId = state.matchReplaceRules[0]?.id ?? null;
  renderMatchReplaceRules();
}

async function saveTargetScope() {
  const scopePatterns = els.targetScopeEditor.value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const response = await fetch("/api/runtime", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      scope_patterns: scopePatterns,
      intercept_enabled: state.runtime?.intercept_enabled,
      websocket_capture_enabled: state.runtime?.websocket_capture_enabled,
    }),
  });
  if (!response.ok) {
    throw new Error(`saveTargetScope failed: ${response.status}`);
  }
  state.runtime = await response.json();
  state.targetScopeDraft = formatScopePatternsText(state.runtime?.scope_patterns);
  state.targetScopeDirty = false;
  if (els.targetScopeEditor.value !== state.targetScopeDraft) {
    els.targetScopeEditor.value = state.targetScopeDraft;
  }
  renderInterceptStatus();
  renderProxySettings();
  await loadTargetSiteMap();
  renderHistory();
}

async function openFuzzerFromSelection() {
  let record = state.selectedRecord;
  if (!record && state.selectedId) {
    const response = await fetch(`/api/transactions/${state.selectedId}`);
    if (response.ok) {
      record = await response.json();
    }
  }

  if (!record || record.kind === "tunnel") {
    return;
  }

  const request = editableRequestFromRecord(record);
  state.fuzzerBaseRequest = request;
  state.fuzzerSourceTransactionId = record.id;
  state.fuzzerNotice = record.request.preview_truncated
    ? buildTruncatedBodyNotice(record, "Fuzzer")
    : "";
  state.fuzzerRequestText = buildEditableRawRequest(request);
  state.fuzzerPayloadsText = "";
  state.fuzzerAttackRecord = null;
  state.activeTool = "fuzzer";
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

function resetFuzzer() {
  state.fuzzerRequestText = state.fuzzerBaseRequest
    ? buildEditableRawRequest(state.fuzzerBaseRequest)
    : "";
  state.fuzzerPayloadsText = "";
  state.fuzzerAttackRecord = null;
  scheduleWorkspaceStateSave();
  renderFuzzer();
}

async function runFuzzerAttack() {
  const fallback = state.fuzzerBaseRequest || {
    scheme: "https",
    host: "",
    method: "GET",
    path: "/",
    headers: [],
    body: "",
    body_encoding: "utf8",
    preview_truncated: false,
  };
  const template = parseEditableRawRequest(els.fuzzerRequestEditor.value, fallback);
  const payloads = els.fuzzerPayloadsEditor.value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const response = await fetch("/api/fuzzer/attacks", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({ template, payloads, source_transaction_id: state.fuzzerSourceTransactionId }),
  });
  if (!response.ok) {
    state.fuzzerAttackRecord = null;
    state.fuzzerNotice = await response.text();
    scheduleWorkspaceStateSave();
    renderFuzzer();
    return;
  }
  state.fuzzerBaseRequest = template;
  state.fuzzerNotice = "";
  state.fuzzerRequestText = els.fuzzerRequestEditor.value;
  state.fuzzerPayloadsText = els.fuzzerPayloadsEditor.value;
  state.fuzzerAttackRecord = await response.json();
  scheduleWorkspaceStateSave();
  renderFuzzer();
  scheduleRefresh();
}

async function toggleIntercept() {
  if (!state.runtime) {
    return;
  }

  const turningOff = state.runtime.intercept_enabled;

  const response = await fetch("/api/runtime", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      intercept_enabled: !state.runtime.intercept_enabled,
    }),
  });
  state.runtime = await response.json();

  if (turningOff) {
    await fetch("/api/intercepts/forward-all", { method: "POST" });
    await loadIntercepts(false);
    scheduleRefresh();
  }

  renderInterceptStatus();
  renderProxySettings();
}

async function saveProxySettings() {
  const scopePatterns = els.proxySettingScopePatterns.value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const passthroughHosts = els.proxySettingPassthroughHosts.value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  const bindHost = els.proxySettingBindHost.value.trim();
  const proxyPort = Number.parseInt(els.proxySettingPort.value, 10);

  const runtimeResponse = await fetch("/api/runtime", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      intercept_enabled: els.proxySettingIntercept.checked,
      websocket_capture_enabled: els.proxySettingWebsocketCapture.checked,
      scope_patterns: scopePatterns,
      passthrough_hosts: passthroughHosts,
    }),
  });

  if (!runtimeResponse.ok) {
    throw new Error(await runtimeResponse.text());
  }

  const startupResponse = await fetch("/api/startup-settings", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      proxy_bind_host: bindHost || undefined,
      proxy_port: Number.isFinite(proxyPort) ? proxyPort : undefined,
    }),
  });

  if (!startupResponse.ok) {
    throw new Error(await startupResponse.text());
  }

  state.runtime = await runtimeResponse.json();
  state.settings.startup = await startupResponse.json();
  renderInterceptStatus();
  renderProxySettings();
  renderHistory();
}

async function forwardSelectedIntercept() {
  if (!state.selectedInterceptRecord) {
    return;
  }

  const request = parseEditableRawRequest(
    els.interceptRequestEditor.value,
    state.selectedInterceptRecord.request,
  );
  const response = await fetch(`/api/intercepts/${state.selectedInterceptRecord.id}/forward`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({ request }),
  });

  if (!response.ok) {
    throw new Error(await response.text());
  }

  state.selectedInterceptRecord = null;
  state.interceptEditorSeedId = null;
  await loadIntercepts(false);
  scheduleRefresh();
}

async function dropSelectedIntercept() {
  if (!state.selectedInterceptRecord) {
    return;
  }

  const response = await fetch(`/api/intercepts/${state.selectedInterceptRecord.id}/drop`, {
    method: "POST",
  });

  if (!response.ok) {
    throw new Error(await response.text());
  }

  state.selectedInterceptRecord = null;
  state.interceptEditorSeedId = null;
  await loadIntercepts(false);
  scheduleRefresh();
}

async function openReplayFromSelection() {
  let record = state.selectedRecord;
  if (!record && state.selectedId) {
    const response = await fetch(`/api/transactions/${state.selectedId}`);
    if (response.ok) {
      record = await response.json();
    }
  }

  if (!record || record.kind === "tunnel") {
    return;
  }

  const request = editableRequestFromRecord(record);
  const tab = createReplayTab({
    baseRequest: request,
    sourceTransactionId: record.id,
    notice: record.request.preview_truncated ? buildTruncatedBodyNotice(record, "Replay") : "",
    requestText: buildEditableRawRequest(request),
  });
  state.replayTabs.push(tab);
  state.activeReplayTabId = tab.id;
  state.activeTool = "replay";
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

function resetReplay() {
  const tab = getActiveReplayTab();
  if (!tab) {
    return;
  }

  const activeHistoryEntry = getActiveRepeaterHistoryEntry(tab);
  if (activeHistoryEntry) {
    restoreRepeaterHistoryEntry(tab, activeHistoryEntry);
  } else {
    const fallback = tab.baseRequest || createDefaultEditableRequest();
    const target = authorityToTargetState(fallback.host, fallback.scheme);
    tab.requestText = buildEditableRawRequest(fallback);
    tab.targetScheme = target.scheme;
    tab.targetHost = target.host;
    tab.targetPort = target.port;
    tab.notice = "";
  }
  tab.responseRecord = null;
  scheduleWorkspaceStateSave();
  renderReplay();
}

async function sendReplay() {
  const tab = getActiveReplayTab();
  if (!tab) {
    return;
  }

  const fallback = tab.baseRequest || createDefaultEditableRequest();
  const request = parseEditableRawRequest(els.replayRequestEditor.value, fallback);
  const requestText = els.replayRequestEditor.value;
  const target = getRepeaterTargetConfig(tab, request);
  const response = await fetch("/api/replay/send", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      request,
      target: {
        scheme: target.scheme,
        host: target.host,
        port: target.port,
      },
      source_transaction_id: tab.sourceTransactionId,
    }),
  });

  if (!response.ok) {
    tab.responseRecord = null;
    tab.notice = await response.text();
    tab.baseRequest = cloneEditableRequest(request);
    tab.targetScheme = target.scheme;
    tab.targetHost = target.host;
    tab.targetPort = target.port;
    tab.requestText = requestText;
    recordRepeaterHistory(tab, {
      request,
      requestText,
      responseRecord: null,
      notice: tab.notice,
      target,
    });
    scheduleWorkspaceStateSave();
    renderReplay();
    return;
  }

  tab.baseRequest = cloneEditableRequest(request);
  tab.targetScheme = target.scheme;
  tab.targetHost = target.host;
  tab.targetPort = target.port;
  tab.notice = "";
  tab.requestText = requestText;
  tab.responseRecord = await response.json();
  recordRepeaterHistory(tab, {
    request,
    requestText,
    responseRecord: tab.responseRecord,
    notice: "",
    target,
  });
  scheduleWorkspaceStateSave();
  renderReplay();
  scheduleRefresh();
}

function openBlankReplayTab() {
  const tab = createReplayTab();
  state.replayTabs.push(tab);
  state.activeReplayTabId = tab.id;
  state.activeTool = "replay";
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

function duplicateActiveReplayTab() {
  const tab = getActiveReplayTab();
  if (!tab) {
    return;
  }

  const fallback = tab.baseRequest || createDefaultEditableRequest();
  const requestText = els.replayRequestEditor?.value || tab.requestText || buildEditableRawRequest(fallback);
  let request = cloneEditableRequest(fallback);
  try {
    request = parseEditableRawRequest(requestText, fallback);
  } catch (_error) {
    request = cloneEditableRequest(fallback);
  }

  const target = normalizeRepeaterTargetInput(
    els.replayHostInput?.value || tab.targetHost,
    els.replayPortInput?.value || tab.targetPort,
    els.replaySchemeSelect?.value || tab.targetScheme || request.scheme || "https",
  );

  tab.baseRequest = cloneEditableRequest(request);
  tab.requestText = requestText;
  tab.targetScheme = target.scheme;
  tab.targetHost = target.host;
  tab.targetPort = target.port;

  const historyEntries = Array.isArray(tab.historyEntries)
    ? tab.historyEntries.map(cloneRepeaterHistoryEntry)
    : [];
  const duplicate = createReplayTab({
    baseRequest: request,
    sourceTransactionId: tab.sourceTransactionId,
    notice: tab.notice,
    requestText,
    responseRecord: cloneTransactionRecord(tab.responseRecord),
    targetScheme: target.scheme,
    targetHost: target.host,
    targetPort: target.port,
    historyEntries,
    historyIndex: normalizeRepeaterHistoryIndex(tab.historyIndex, historyEntries.length),
  });

  state.replayTabs.push(duplicate);
  state.activeReplayTabId = duplicate.id;
  scheduleWorkspaceStateSave();
  renderReplay();
}

function createReplayTab(seed = {}) {
  state.replayTabSequence += 1;
  const baseRequest = seed.baseRequest ? cloneEditableRequest(seed.baseRequest) : createDefaultEditableRequest();
  const target = authorityToTargetState(baseRequest.host, baseRequest.scheme);
  const normalizedTarget = normalizeRepeaterTargetInput(
    seed.targetHost ?? target.host,
    seed.targetPort ?? target.port,
    seed.targetScheme || target.scheme,
  );
  return {
    id: crypto.randomUUID(),
    sequence: state.replayTabSequence,
    baseRequest,
    sourceTransactionId: seed.sourceTransactionId || null,
    notice: seed.notice || "",
    requestText: seed.requestText || buildEditableRawRequest(baseRequest),
    responseRecord: cloneTransactionRecord(seed.responseRecord),
    targetScheme: normalizedTarget.scheme,
    targetHost: normalizedTarget.host,
    targetPort: normalizedTarget.port,
    historyEntries: Array.isArray(seed.historyEntries) ? seed.historyEntries.map(cloneRepeaterHistoryEntry) : [],
    historyIndex: normalizeRepeaterHistoryIndex(seed.historyIndex, Array.isArray(seed.historyEntries) ? seed.historyEntries.length : 0),
  };
}

function ensureRepeaterTab() {
  if (!state.replayTabs.length) {
    state.replayTabSequence = 0;
    const tab = createReplayTab();
    state.replayTabs = [tab];
    state.activeReplayTabId = tab.id;
    return tab;
  }

  if (!state.replayTabs.some((tab) => tab.id === state.activeReplayTabId)) {
    state.activeReplayTabId = state.replayTabs[0].id;
  }

  return getActiveReplayTab();
}

function getActiveReplayTab() {
  return state.replayTabs.find((tab) => tab.id === state.activeReplayTabId) || null;
}

function renderReplayTabs() {
  els.replayTabStrip.innerHTML = state.replayTabs
    .map((tab) => {
      const active = tab.id === state.activeReplayTabId ? "active" : "";
      return `
        <div class="replay-tab ${active}" data-replay-tab-id="${tab.id}">
          <button class="replay-tab-button" type="button">${escapeHtml(replayTabLabel(tab))}</button>
          <button class="replay-tab-close" type="button" aria-label="Close replay tab">×</button>
        </div>
      `;
    })
    .join("");

  Array.from(els.replayTabStrip.querySelectorAll(".replay-tab")).forEach((tabElement) => {
    const id = tabElement.dataset.repeaterTabId;
    tabElement.querySelector(".replay-tab-button")?.addEventListener("click", () => {
      state.activeReplayTabId = id;
      scheduleWorkspaceStateSave();
      renderReplay();
    });
    tabElement.querySelector(".replay-tab-close")?.addEventListener("click", (event) => {
      event.stopPropagation();
      closeRepeaterTab(id);
    });
  });
}

function closeRepeaterTab(id) {
  const index = state.replayTabs.findIndex((tab) => tab.id === id);
  if (index === -1) {
    return;
  }

  state.replayTabs.splice(index, 1);
  if (!state.replayTabs.length) {
    state.replayTabSequence = 0;
    const replacement = createReplayTab();
    state.replayTabs = [replacement];
    state.activeReplayTabId = replacement.id;
  } else if (state.activeReplayTabId === id) {
    state.activeReplayTabId = state.replayTabs[Math.max(0, index - 1)].id;
  }
  scheduleWorkspaceStateSave();
  renderReplay();
}

function replayTabLabel(tab) {
  const request = deriveRepeaterRequest(tab);
  const target = getRepeaterTargetConfig(tab, request);
  const authority = joinAuthority(target.host, target.port) || "draft";
  return `${tab.sequence}. ${request.method} ${authority}`;
}

function deriveRepeaterRequest(tab) {
  const fallback = tab.baseRequest || createDefaultEditableRequest();
  try {
    return parseEditableRawRequest(tab.requestText, fallback);
  } catch (_error) {
    return cloneEditableRequest(fallback);
  }
}

async function applyReplayTargetFields() {
  const tab = getActiveReplayTab();
  if (!tab) {
    return;
  }

  const normalizedTarget = normalizeRepeaterTargetInput(
    els.replayHostInput.value,
    els.replayPortInput.value,
    els.replaySchemeSelect.value || "https",
  );
  tab.targetScheme = normalizedTarget.scheme;
  tab.targetHost = normalizedTarget.host;
  tab.targetPort = normalizedTarget.port;
  tab.responseRecord = null;
  scheduleWorkspaceStateSave();
  renderReplay();
}

function applyRepeaterTargetOverride(request, target) {
  request.scheme = target.scheme || request.scheme;
  const authority = joinAuthority(target.host, target.port);
  if (authority) {
    request.host = authority;
  }
}

function getRepeaterTargetConfig(tab, request = null) {
  const fallback = request || deriveRepeaterRequest(tab);
  const derived = authorityToTargetState(fallback.host, fallback.scheme);
  const normalizedOverride = normalizeRepeaterTargetInput(
    tab.targetHost,
    tab.targetPort,
    tab.targetScheme || derived.scheme,
  );
  return {
    scheme: normalizedOverride.scheme || derived.scheme,
    host: normalizedOverride.host || derived.host,
    port: normalizedOverride.port || derived.port,
  };
}

function authorityToTargetState(authority, scheme = "https") {
  const fallbackScheme = scheme || "https";
  if (!authority) {
    return { scheme: fallbackScheme, host: "", port: "" };
  }

  try {
    const parsed = new URL(`${fallbackScheme}://${authority}`);
    return {
      scheme: fallbackScheme,
      host: parsed.hostname ? stripIpv6Brackets(parsed.hostname) : authority,
      port: parsed.port || "",
    };
  } catch (_error) {
    return {
      scheme: fallbackScheme,
      host: authority,
      port: "",
    };
  }
}

function joinAuthority(host, port) {
  const normalizedHost = String(host || "").trim();
  const normalizedPort = normalizePortValue(port);
  if (!normalizedHost) {
    return "";
  }

  let authorityHost = normalizedHost;
  if (authorityHost.includes(":") && !authorityHost.startsWith("[") && !authorityHost.endsWith("]")) {
    authorityHost = `[${authorityHost}]`;
  }

  return normalizedPort ? `${authorityHost}:${normalizedPort}` : authorityHost;
}

function normalizeRepeaterTargetInput(host, port, scheme = "https") {
  const normalizedScheme = scheme || "https";
  const normalizedHost = String(host || "").trim();
  const parsedHost = authorityToTargetState(normalizedHost, normalizedScheme);
  return {
    scheme: normalizedScheme,
    host: normalizedHost ? parsedHost.host : "",
    port: normalizePortValue(port) || (normalizedHost ? parsedHost.port : ""),
  };
}

function stripIpv6Brackets(host) {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

function normalizePortValue(value) {
  const normalized = String(value ?? "").trim();
  if (!normalized) {
    return "";
  }

  const parsed = Number.parseInt(normalized, 10);
  if (!Number.isFinite(parsed) || parsed < 1 || parsed > 65535) {
    return "";
  }

  return String(parsed);
}

function normalizeRepeaterHistoryIndex(index, length) {
  if (!Number.isFinite(index) || length <= 0) {
    return null;
  }

  return clamp(Math.trunc(index), 0, length - 1);
}

function cloneRepeaterHistoryEntry(entry) {
  const normalizedTarget = normalizeRepeaterTargetInput(
    entry.targetHost,
    entry.targetPort,
    entry.targetScheme || "https",
  );
  return {
    request: cloneEditableRequest(entry.request),
    requestText: entry.requestText || "",
    responseRecord: cloneTransactionRecord(entry.responseRecord),
    notice: entry.notice || "",
    targetScheme: normalizedTarget.scheme,
    targetHost: normalizedTarget.host,
    targetPort: normalizedTarget.port,
  };
}

function recordRepeaterHistory(tab, snapshot) {
  const entry = {
    request: cloneEditableRequest(snapshot.request),
    requestText: snapshot.requestText || "",
    responseRecord: cloneTransactionRecord(snapshot.responseRecord),
    notice: snapshot.notice || "",
    targetScheme: snapshot.target.scheme || "https",
    targetHost: snapshot.target.host || "",
    targetPort: normalizePortValue(snapshot.target.port),
  };

  const baseEntries = Array.isArray(tab.historyEntries) ? tab.historyEntries : [];
  const currentIndex = normalizeRepeaterHistoryIndex(tab.historyIndex, baseEntries.length);
  const trimmedEntries = currentIndex == null ? baseEntries : baseEntries.slice(0, currentIndex + 1);
  trimmedEntries.push(entry);
  if (trimmedEntries.length > REPEATER_HISTORY_LIMIT) {
    trimmedEntries.splice(0, trimmedEntries.length - REPEATER_HISTORY_LIMIT);
  }

  tab.historyEntries = trimmedEntries;
  tab.historyIndex = trimmedEntries.length - 1;
}

function getActiveRepeaterHistoryEntry(tab) {
  if (!Array.isArray(tab.historyEntries) || !tab.historyEntries.length) {
    return null;
  }

  const index = normalizeRepeaterHistoryIndex(tab.historyIndex, tab.historyEntries.length);
  return index == null ? null : tab.historyEntries[index];
}

function restoreRepeaterHistoryEntry(tab, entry) {
  const fallbackTarget = authorityToTargetState(entry.request.host, entry.request.scheme);
  const normalizedTarget = normalizeRepeaterTargetInput(
    entry.targetHost || fallbackTarget.host,
    entry.targetPort || fallbackTarget.port,
    entry.targetScheme || entry.request.scheme || "https",
  );
  tab.baseRequest = cloneEditableRequest(entry.request);
  tab.requestText = entry.requestText || buildEditableRawRequest(entry.request);
  tab.responseRecord = entry.responseRecord || null;
  tab.notice = entry.notice || "";
  tab.targetScheme = normalizedTarget.scheme;
  tab.targetHost = normalizedTarget.host;
  tab.targetPort = normalizedTarget.port;
}

function canNavigateReplayHistory(tab, direction) {
  if (!Array.isArray(tab.historyEntries) || tab.historyEntries.length <= 1) {
    return false;
  }

  const index = normalizeRepeaterHistoryIndex(tab.historyIndex, tab.historyEntries.length);
  if (index == null) {
    return false;
  }

  const nextIndex = index + direction;
  return nextIndex >= 0 && nextIndex < tab.historyEntries.length;
}

function navigateReplayHistory(direction) {
  const tab = getActiveReplayTab();
  if (!tab || !canNavigateReplayHistory(tab, direction)) {
    return;
  }

  const nextIndex = clamp(tab.historyIndex + direction, 0, tab.historyEntries.length - 1);
  const entry = tab.historyEntries[nextIndex];
  if (!entry) {
    return;
  }

  tab.historyIndex = nextIndex;
  restoreRepeaterHistoryEntry(tab, entry);
  scheduleWorkspaceStateSave();
  renderReplay();
}

function createDefaultEditableRequest() {
  return {
    scheme: "https",
    host: "",
    method: "GET",
    path: "/",
    headers: [],
    body: "",
    body_encoding: "utf8",
    preview_truncated: false,
  };
}

function cloneEditableRequest(request) {
  return {
    scheme: request.scheme,
    host: request.host,
    method: request.method,
    path: request.path,
    headers: request.headers.map((header) => ({ name: header.name, value: header.value })),
    body: request.body,
    body_encoding: request.body_encoding,
    preview_truncated: request.preview_truncated,
  };
}

function cloneTransactionRecord(record) {
  return record ? JSON.parse(JSON.stringify(record)) : null;
}

function buildTruncatedBodyNotice(record, tool) {
  const previewCap = state.settings?.body_preview_bytes || record.request.body_preview.length;
  return `${tool} cannot safely resend this capture yet. The original request body is ${formatSize(record.request.body_size)}, but only a ${formatSize(previewCap)} preview was captured. Increase the preview cap and capture it again, or paste the full body manually before sending.`;
}

function openCertificateModal() {
  openDisplaySettingsModal();
}

function closeCertificateModal() {
  closeDisplaySettingsModal();
}

function openDisplaySettingsModal() {
  hydrateDisplaySettingsForm();
  applyDisplaySettingsState();
  displaySettingsPreviewActive = false;
  els.displaySettingsModal.classList.remove("hidden");
}

function closeDisplaySettingsModal() {
  if (displaySettingsPreviewActive) {
    hydrateDisplaySettingsForm();
    applyDisplaySettingsState();
    displaySettingsPreviewActive = false;
  }
  els.displaySettingsModal.classList.add("hidden");
}

function openFilterModal() {
  hydrateFilterForm();
  els.filterModal.classList.remove("hidden");
}

function closeFilterModal() {
  els.filterModal.classList.add("hidden");
}

function isModalVisible(modal) {
  return Boolean(modal) && !modal.classList.contains("hidden");
}

function getActiveModalAction() {
  if (isModalVisible(els.displaySettingsModal)) {
    return {
      close: closeDisplaySettingsModal,
      apply: saveDisplaySettingsFromForm,
    };
  }

  if (isModalVisible(els.filterModal)) {
    return {
      close: closeFilterModal,
      apply: applyFilterSettings,
    };
  }

  return null;
}

function loadDisplaySettings() {
  state.displaySettings = createDefaultDisplaySettings();
  applyDisplaySettingsState();
}

function sanitizeDisplaySettings(candidate) {
  const defaults = createDefaultDisplaySettings();
  const parsedSize = Number(candidate?.sizePx);
  return {
    sizePx: Number.isFinite(parsedSize) ? clamp(Math.round(parsedSize), 8, 20) : defaults.sizePx,
    theme: DISPLAY_THEME_OPTIONS.has(candidate?.theme) ? candidate.theme : defaults.theme,
    uiFont: DISPLAY_UI_FONT_OPTIONS.has(candidate?.uiFont) ? candidate.uiFont : defaults.uiFont,
    monoFont: DISPLAY_MONO_FONT_OPTIONS.has(candidate?.monoFont) ? candidate.monoFont : defaults.monoFont,
  };
}

function loadHistoryColumnWidths() {
  state.historyColumnWidths = createDefaultHistoryColumnWidths();
  state.historyColumnOrder = [...DEFAULT_HISTORY_COLUMN_ORDER];
  applyHistoryColumnWidths();
}

function sanitizeHistoryColumnWidths(candidate) {
  return Object.fromEntries(
    Object.entries(HISTORY_COLUMN_RULES).map(([key, limits]) => {
      const parsed = Number(candidate?.[key]);
      const next = Number.isFinite(parsed) ? parsed : limits.default;
      return [key, clamp(Math.round(next), limits.min, limits.max)];
    }),
  );
}

function saveHistoryColumnWidths() {
  scheduleUiSettingsSave();
}

function applyHistoryColumnWidths() {
  if (!els.historyTable) {
    return;
  }

  let totalWidth = 0;
  Object.entries(state.historyColumnWidths).forEach(([key, width]) => {
    els.historyTable.style.setProperty(`--history-col-${key}`, `${width}px`);
    totalWidth += width;
  });
  els.historyTable.style.setProperty("--history-table-width", `${Math.max(totalWidth, 1160)}px`);
}

function sanitizeHistoryColumnOrder(candidate) {
  if (!Array.isArray(candidate) || candidate.length === 0) {
    return [...DEFAULT_HISTORY_COLUMN_ORDER];
  }
  const validKeys = new Set(Object.keys(HISTORY_COLUMN_DEFS));
  const seen = new Set();
  const order = [];
  for (const key of candidate) {
    if (validKeys.has(key) && !seen.has(key)) {
      order.push(key);
      seen.add(key);
    }
  }
  for (const key of DEFAULT_HISTORY_COLUMN_ORDER) {
    if (!seen.has(key)) {
      order.push(key);
    }
  }
  return order;
}

function renderHistoryHeader() {
  const thead = els.historyTable?.querySelector("thead tr");
  if (!thead) return;

  thead.innerHTML = state.historyColumnOrder
    .map((colKey) => {
      const def = HISTORY_COLUMN_DEFS[colKey];
      if (!def) return "";
      return `
        <th class="${def.cssClass}" data-column-key="${colKey}" draggable="true">
          <button class="sort-header" data-sort-key="${def.sortKey}" type="button">
            <span>${def.label}</span>
            <span class="sort-indicator" aria-hidden="true">\u2195</span>
          </button>
          <span class="column-resize-handle" data-column-key="${colKey}" aria-hidden="true"></span>
        </th>
      `;
    })
    .join("");

  sortHeaders = Array.from(els.historyTable.querySelectorAll(".sort-header"));
  historyColumnHandles = Array.from(els.historyTable.querySelectorAll(".column-resize-handle"));

  sortHeaders.forEach((header) => {
    header.addEventListener("click", () => {
      toggleSort(header.dataset.sortKey);
    });
  });

  bindHistoryColumnResizers();
  bindColumnDragAndDrop();
  renderSortHeaders();
}

function renderHistoryCell(colKey, item, entry) {
  switch (colKey) {
    case "index":
      return `<td>${entry.index + 1}</td>`;
    case "host":
      return `<td class="cell-host">${escapeHtml(item.host)}</td>`;
    case "method":
      return `<td><span class="method-pill ${methodTone(item.method)}">${escapeHtml(item.method)}</span></td>`;
    case "path":
      return `<td class="cell-url">${escapeHtml(item.path || "(CONNECT tunnel)")}</td>`;
    case "status":
      return `<td><span class="status-pill-row ${statusTone(item.status)}">${escapeHtml(formatStatus(item.status))}</span></td>`;
    case "length":
      return `<td class="col-center">${escapeHtml(formatSize((item.request_bytes ?? 0) + (item.response_bytes ?? 0)))}</td>`;
    case "mime":
      return `<td class="col-center">${escapeHtml(inferMimeType(item))}</td>`;
    case "notes": {
      const tagDot = item.color_tag ? `<span class="row-color-tag row-color-tag-${escapeHtml(item.color_tag)}"></span>` : "";
      const noteIndicator = item.has_user_note ? `<span class="note-icon" title="Has note">\ud83d\udcdd</span>` : "";
      return `<td>${tagDot}${noteIndicator}${item.note_count ? ` ${item.note_count}` : ""}</td>`;
    }
    case "tls": {
      const tls = isTlsRecord(item) ? '<span class="tls-badge">TLS</span>' : '<span class="tls-badge empty">-</span>';
      return `<td class="tls-cell">${tls}</td>`;
    }
    case "started_at":
      return `<td>${escapeHtml(formatTimestamp(item.started_at))}</td>`;
    default:
      return "<td></td>";
  }
}

let columnDragState = null;

function bindColumnDragAndDrop() {
  const headerRow = els.historyTable?.querySelector("thead tr");
  if (!headerRow) return;

  const headers = Array.from(headerRow.querySelectorAll("th[draggable]"));
  headers.forEach((th) => {
    th.addEventListener("dragstart", (event) => {
      columnDragState = th.dataset.columnKey;
      event.dataTransfer.effectAllowed = "move";
      event.dataTransfer.setData("text/plain", columnDragState);
      th.classList.add("column-dragging");
      requestAnimationFrame(() => {
        headers.forEach((h) => h.classList.add("column-drag-active"));
      });
    });

    th.addEventListener("dragend", () => {
      th.classList.remove("column-dragging");
      headers.forEach((h) => {
        h.classList.remove("column-drag-active", "column-drag-over", "column-drag-over-left", "column-drag-over-right");
      });
      columnDragState = null;
    });

    th.addEventListener("dragover", (event) => {
      if (!columnDragState || columnDragState === th.dataset.columnKey) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = "move";
      const rect = th.getBoundingClientRect();
      const midX = rect.left + rect.width / 2;
      const isLeft = event.clientX < midX;
      th.classList.toggle("column-drag-over-left", isLeft);
      th.classList.toggle("column-drag-over-right", !isLeft);
      th.classList.add("column-drag-over");
    });

    th.addEventListener("dragleave", () => {
      th.classList.remove("column-drag-over", "column-drag-over-left", "column-drag-over-right");
    });

    th.addEventListener("drop", (event) => {
      event.preventDefault();
      const fromKey = columnDragState;
      const toKey = th.dataset.columnKey;
      if (!fromKey || fromKey === toKey) return;

      const order = [...state.historyColumnOrder];
      const fromIdx = order.indexOf(fromKey);
      const toIdx = order.indexOf(toKey);
      if (fromIdx === -1 || toIdx === -1) return;

      const rect = th.getBoundingClientRect();
      const midX = rect.left + rect.width / 2;
      const dropLeft = event.clientX < midX;

      order.splice(fromIdx, 1);
      let insertIdx = order.indexOf(toKey);
      if (!dropLeft) insertIdx += 1;
      order.splice(insertIdx, 0, fromKey);

      state.historyColumnOrder = order;
      renderHistoryHeader();
      applyHistoryColumnWidths();
      renderHistory();
      scheduleUiSettingsSave();
    });
  });
}

function loadWorkbenchLayout() {
  state.workbenchHeight = null;
}

function persistWorkbenchLayout(height) {
  state.workbenchHeight = Math.round(height);
  scheduleUiSettingsSave();
}

function hydrateDisplaySettingsForm() {
  els.displayThemeSelect.value = state.displaySettings.theme;
  els.displaySizeInput.value = String(state.displaySettings.sizePx);
  els.displayUiFontSelect.value = state.displaySettings.uiFont;
  els.displayMonoFontSelect.value = state.displaySettings.monoFont;
}

function collectDisplaySettingsFormValues() {
  return sanitizeDisplaySettings({
    sizePx: els.displaySizeInput.value,
    theme: els.displayThemeSelect.value,
    uiFont: els.displayUiFontSelect.value,
    monoFont: els.displayMonoFontSelect.value,
  });
}

function previewDisplaySettingsFromForm() {
  applyDisplaySettingsState(collectDisplaySettingsFormValues());
  displaySettingsPreviewActive = true;
}

function saveDisplaySettingsFromForm() {
  state.displaySettings = collectDisplaySettingsFormValues();
  applyDisplaySettingsState();
  displaySettingsPreviewActive = false;
  window.clearTimeout(uiSettingsSaveTimer);
  uiSettingsSaveTimer = null;
  persistUiSettings().catch((error) => console.error(error));
  closeDisplaySettingsModal();
}

function applyDisplaySettingsState(settings = state.displaySettings) {
  document.documentElement.style.setProperty("--ui-root-size", `${settings.sizePx}px`);
  document.body.dataset.theme = settings.theme;
  document.body.dataset.uiFont = settings.uiFont;
  document.body.dataset.monoFont = settings.monoFont;
}

async function loadUiSettings() {
  try {
    const response = await fetch("/api/ui-settings");
    if (!response.ok) {
      throw new Error(await response.text());
    }
    applyUiSettingsSnapshot(await response.json());
  } catch (error) {
    console.error(error);
  }
}

function applyUiSettingsSnapshot(snapshot) {
  state.displaySettings = sanitizeDisplaySettings({
    sizePx: snapshot?.display_settings?.size_px,
    theme: snapshot?.display_settings?.theme,
    uiFont: snapshot?.display_settings?.ui_font,
    monoFont: snapshot?.display_settings?.mono_font,
  });
  state.historyColumnWidths = sanitizeHistoryColumnWidths(snapshot?.history_column_widths);
  state.historyColumnOrder = sanitizeHistoryColumnOrder(snapshot?.history_column_order);
  state.workbenchHeight = sanitizeWorkbenchHeight(snapshot?.workbench_height);
  applyDisplaySettingsState();
  renderHistoryHeader();
  applyHistoryColumnWidths();

  if (state.workbenchHeight) {
    applyWorkbenchStackHeight(state.workbenchHeight, false);
  } else {
    els.proxyShell?.style.removeProperty("--workbench-pane-height");
  }
}

function snapshotUiSettings() {
  return {
    display_settings: {
      size_px: state.displaySettings.sizePx,
      theme: state.displaySettings.theme,
      ui_font: state.displaySettings.uiFont,
      mono_font: state.displaySettings.monoFont,
    },
    history_column_widths: { ...state.historyColumnWidths },
    history_column_order: [...state.historyColumnOrder],
    workbench_height: state.workbenchHeight,
  };
}

function scheduleUiSettingsSave(delay = 180) {
  window.clearTimeout(uiSettingsSaveTimer);
  uiSettingsSaveTimer = window.setTimeout(() => {
    uiSettingsSaveTimer = null;
    persistUiSettings().catch((error) => console.error(error));
  }, delay);
}

async function persistUiSettings() {
  const response = await fetch("/api/ui-settings", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(snapshotUiSettings()),
  });

  if (!response.ok) {
    throw new Error(await response.text());
  }
}

function sanitizeWorkbenchHeight(candidate) {
  const parsed = Number(candidate);
  return Number.isFinite(parsed) && parsed > 0 ? Math.round(parsed) : null;
}

function hydrateFilterForm() {
  const filters = state.filterSettings;
  els.filterInScopeOnly.checked = filters.inScopeOnly;
  els.filterHideWithoutResponses.checked = filters.hideWithoutResponses;
  els.filterOnlyParameterized.checked = filters.onlyParameterized;
  els.filterOnlyNotes.checked = filters.onlyNotes;
  els.filterSearchTerm.value = filters.searchTerm;
  els.filterRegex.checked = filters.regex;
  els.filterCaseSensitive.checked = filters.caseSensitive;
  els.filterNegativeSearch.checked = filters.negativeSearch;
  els.filterMimeHtml.checked = filters.mime.html;
  els.filterMimeScript.checked = filters.mime.script;
  els.filterMimeJson.checked = filters.mime.json;
  els.filterMimeCss.checked = filters.mime.css;
  els.filterMimeImage.checked = filters.mime.image;
  els.filterMimeOther.checked = filters.mime.other;
  els.filterStatus2xx.checked = filters.status.success;
  els.filterStatus3xx.checked = filters.status.redirect;
  els.filterStatus4xx.checked = filters.status.clientError;
  els.filterStatus5xx.checked = filters.status.serverError;
  els.filterStatusOther.checked = filters.status.other;
  els.filterHiddenExtensions.value = filters.hiddenExtensions;
  els.filterPort.value = filters.port;
  syncColorTagFilterUI();
}

function applyFilterSettings() {
  state.filterSettings = {
    inScopeOnly: els.filterInScopeOnly.checked,
    hideWithoutResponses: els.filterHideWithoutResponses.checked,
    onlyParameterized: els.filterOnlyParameterized.checked,
    onlyNotes: els.filterOnlyNotes.checked,
    searchTerm: els.filterSearchTerm.value.trim(),
    regex: els.filterRegex.checked,
    caseSensitive: els.filterCaseSensitive.checked,
    negativeSearch: els.filterNegativeSearch.checked,
    mime: {
      html: els.filterMimeHtml.checked,
      script: els.filterMimeScript.checked,
      json: els.filterMimeJson.checked,
      css: els.filterMimeCss.checked,
      image: els.filterMimeImage.checked,
      other: els.filterMimeOther.checked,
    },
    status: {
      success: els.filterStatus2xx.checked,
      redirect: els.filterStatus3xx.checked,
      clientError: els.filterStatus4xx.checked,
      serverError: els.filterStatus5xx.checked,
      other: els.filterStatusOther.checked,
    },
    hiddenExtensions: els.filterHiddenExtensions.value.trim(),
    port: els.filterPort.value.trim(),
    colorTags: state.filterSettings.colorTags,
  };
  closeFilterModal();
  scheduleRefresh();
}

async function downloadCertificate(format) {
  const path = format === "pem"
    ? state.settings.certificate.pem_download_path
    : state.settings.certificate.der_download_path;
  const filename = format === "pem" ? "sniper-root-ca.pem" : "sniper-root-ca.der";
  const response = await fetch(path);
  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(objectUrl);
}

function buildMessagePresentation(target, record) {
  const mode = state.messageViews[target];

  if (mode === "diff") {
    return buildDiffPresentation(target, record);
  }

  const text = target === "request" ? buildRawRequest(record) : buildRawResponse(record);

  if (mode === "hex") {
    return toHexDump(text);
  }

  if (mode === "pretty") {
    return prettyFormat(text, target === "request" ? record.request : record.response);
  }

  return text;
}

function buildDiffPresentation(target, record) {
  const originalField = target === "request" ? "original_request" : "original_response";
  const original = record[originalField];
  if (!original) {
    return target === "request"
      ? "No match-replace rules were applied to the request."
      : "No match-replace rules were applied to the response.";
  }

  const fakeOriginal = { ...record };
  if (target === "request") {
    fakeOriginal.request = original;
  } else {
    fakeOriginal.response = original;
  }
  const originalText = target === "request" ? buildRawRequest(fakeOriginal) : buildRawResponse(fakeOriginal);
  const modifiedText = target === "request" ? buildRawRequest(record) : buildRawResponse(record);

  const originalLines = originalText.split("\n");
  const modifiedLines = modifiedText.split("\n");
  const result = [];
  const maxLen = Math.max(originalLines.length, modifiedLines.length);

  result.push("--- Original");
  result.push("+++ Modified");
  result.push("");

  for (let i = 0; i < maxLen; i++) {
    const oLine = i < originalLines.length ? originalLines[i] : undefined;
    const mLine = i < modifiedLines.length ? modifiedLines[i] : undefined;
    if (oLine === mLine) {
      result.push("  " + (oLine ?? ""));
    } else {
      if (oLine !== undefined) result.push("- " + oLine);
      if (mLine !== undefined) result.push("+ " + mLine);
    }
  }

  return result.join("\n");
}

function buildRawRequest(record) {
  const startLine = record.kind === "tunnel"
    ? `CONNECT ${record.host} HTTP/1.1`
    : `${record.method} ${record.path || "/"} HTTP/1.1`;
  const headers = record.request.headers
    .map((header) => `${header.name}: ${header.value}`)
    .join("\n");
  const body = renderBody(record.request);
  return `${startLine}\n${headers}\n\n${body}`.trim();
}

function buildRawResponse(record) {
  if (!record.response) {
    return "No response was captured for this exchange.";
  }

  const headers = record.response.headers
    .map((header) => `${header.name}: ${header.value}`)
    .join("\n");
  const body = renderBody(record.response);
  return `HTTP/1.1 ${record.status ?? 0}\n${headers}\n\n${body}`.trim();
}

function buildRawWebsocketRequest(session) {
  const headers = session.request.headers
    .map((header) => `${header.name}: ${header.value}`)
    .join("\n");
  return `GET ${session.path || "/"} HTTP/1.1\n${headers}`.trim();
}

function buildRawWebsocketResponse(session) {
  if (!session.response) {
    return "No handshake response was captured.";
  }

  const headers = session.response.headers
    .map((header) => `${header.name}: ${header.value}`)
    .join("\n");
  return `HTTP/1.1 ${session.status ?? 101}\n${headers}`.trim();
}

function renderBody(message) {
  if (!message || !message.body_preview) {
    return "";
  }

  if (message.body_encoding === "base64") {
    return message.body_preview;
  }

  return message.preview_truncated
    ? `${message.body_preview}\n\n[preview truncated]`
    : message.body_preview;
}

function prettyFormat(text, message) {
  if (!message || message.body_encoding === "base64") {
    return text;
  }

  const divider = "\n\n";
  const boundary = text.indexOf(divider);
  if (boundary === -1) {
    return text;
  }

  const head = text.slice(0, boundary);
  const body = text.slice(boundary + divider.length);
  const contentType = (message.content_type || "").toLowerCase();
  if (!contentType.includes("json")) {
    return text;
  }

  try {
    return `${head}${divider}${JSON.stringify(JSON.parse(body), null, 2)}`;
  } catch (_error) {
    return text;
  }
}

function editableRequestFromRecord(record) {
  return {
    scheme: record.scheme,
    host: record.host,
    method: record.method,
    path: record.path || "/",
    headers: [...record.request.headers],
    body: record.request.body_preview || "",
    body_encoding: record.request.body_encoding,
    preview_truncated: record.request.preview_truncated,
  };
}

function buildEditableRawRequest(request) {
  const headers = [...request.headers];
  if (!headers.some((header) => header.name.toLowerCase() === "host") && request.host) {
    headers.unshift({ name: "host", value: request.host });
  }
  const head = `${request.method} ${request.path || "/"} HTTP/1.1`;
  const headerBlock = headers.map((header) => `${header.name}: ${header.value}`).join("\n");
  const body = request.body || "";
  return `${head}\n${headerBlock}\n\n${body}`.trimEnd();
}

function parseEditableRawRequest(text, fallback) {
  const normalized = String(text || "").replace(/\r\n/g, "\n");
  const boundary = normalized.indexOf("\n\n");
  const head = boundary === -1 ? normalized : normalized.slice(0, boundary);
  const body = boundary === -1 ? "" : normalized.slice(boundary + 2);
  const lines = head.split("\n").filter((line) => line.length > 0);
  const [startLine = "GET / HTTP/1.1", ...headerLines] = lines;
  const match = startLine.match(/^([A-Z]+)\s+(\S+)(?:\s+HTTP\/[0-9.]+)?$/i);

  if (!match) {
    throw new Error("Invalid request line in editor");
  }

  let [, method, target] = match;
  let scheme = fallback?.scheme || "https";
  let host = fallback?.host || "";
  let path = target;
  const headers = headerLines
    .map((line) => {
      const index = line.indexOf(":");
      if (index === -1) {
        return null;
      }
      return {
        name: line.slice(0, index).trim(),
        value: line.slice(index + 1).trim(),
      };
    })
    .filter(Boolean);

  if (/^https?:\/\//i.test(target)) {
    const absolute = new URL(target);
    scheme = absolute.protocol.replace(":", "");
    host = absolute.host;
    path = `${absolute.pathname || "/"}${absolute.search || ""}`;
  }

  const hostHeader = headerValue(headers, "host");
  if (hostHeader) {
    host = hostHeader;
  }

  if (!path.startsWith("/")) {
    path = `/${path}`;
  }

  if (!host) {
    throw new Error("Request is missing a Host header");
  }

  return {
    scheme,
    host,
    method: method.toUpperCase(),
    path,
    headers,
    body,
    body_encoding: fallback?.body_encoding === "base64" ? "base64" : "utf8",
    preview_truncated: false,
  };
}

function headerValue(headers, name) {
  return headers.find((header) => header.name.toLowerCase() === name.toLowerCase())?.value || null;
}

function renderFramePreview(frame) {
  if (!frame.body_preview) {
    return "(empty)";
  }
  return frame.body_encoding === "base64"
    ? `[base64] ${frame.body_preview}`
    : frame.body_preview;
}

function toHexDump(text) {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(text);
  const rows = [];

  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = Array.from(bytes.slice(offset, offset + 16));
    const hex = chunk
      .map((value) => value.toString(16).padStart(2, "0"))
      .join(" ")
      .padEnd(47, " ");
    const ascii = chunk
      .map((value) => (value >= 32 && value <= 126 ? String.fromCharCode(value) : "."))
      .join("");
    rows.push(`${offset.toString(16).padStart(4, "0")}  ${hex}  ${ascii}`);
  }

  return rows.join("\n") || "0000";
}

function updateCodePane(viewElement, lineElement, text, mode, target) {
  const lineCount = countLines(text);
  viewElement.innerHTML = renderCodeHtml(text, mode, target);
  lineElement.textContent = buildLineNumbers(lineCount);
  const searchResult = applyCodeSearch(viewElement, state.messageSearch[target]);
  if (searchResult.firstMatch) {
    viewElement.scrollTop = Math.max(searchResult.firstMatch.offsetTop - 24, 0);
  } else {
    viewElement.scrollTop = 0;
  }
  lineElement.scrollTop = viewElement.scrollTop;
  return {
    lineCount,
    matchCount: searchResult.count,
  };
}

function renderCodeHtml(text, mode, target) {
  if (!text) {
    return '<span class="code-line code-line-empty">&nbsp;</span>';
  }

  if (mode === "hex") {
    return renderHexHtml(text);
  }

  if (mode === "diff") {
    return renderDiffHtml(text);
  }

  return renderHttpHtml(text, target);
}

function renderDiffHtml(text) {
  const lines = String(text).split("\n");
  return lines
    .map((line) => {
      const escaped = escapeHtml(line);
      if (line.startsWith("--- ") || line.startsWith("+++ ")) {
        return wrapCodeLine(escaped, "code-line diff-line-header");
      }
      if (line.startsWith("+ ")) {
        return wrapCodeLine(escaped, "code-line diff-line-added");
      }
      if (line.startsWith("- ")) {
        return wrapCodeLine(escaped, "code-line diff-line-removed");
      }
      return wrapCodeLine(escaped, "code-line");
    })
    .join("");
}

function renderHttpHtml(text, target) {
  const lines = String(text).split("\n");
  let inBody = false;
  let contentType = "";
  let bodyMode = "plain";

  return lines
    .map((line, index) => {
      if (!inBody && line === "") {
        inBody = true;
        bodyMode = inferBodyHighlightMode(contentType);
        return wrapCodeLine("&nbsp;", "code-line code-line-gap");
      }

      if (!inBody) {
        if (index === 0) {
          return wrapCodeLine(highlightStartLine(line, target), "code-line code-line-start");
        }

        const headerMatch = line.match(/^([^:]+):(.*)$/);
        if (headerMatch && headerMatch[1].trim().toLowerCase() === "content-type") {
          contentType = headerMatch[2].trim();
        }

        return wrapCodeLine(highlightHeaderLine(line), "code-line");
      }

      return wrapCodeLine(highlightBodyLine(line, bodyMode), "code-line code-line-body");
    })
    .join("");
}

function renderHexHtml(text) {
  return String(text)
    .split("\n")
    .map((line) => {
      const match = line.match(/^([0-9a-f]{4})\s{2}(.{47})\s{2}(.*)$/i);
      if (!match) {
        return wrapCodeLine(escapeHtml(line), "code-line");
      }

      return wrapCodeLine(
        `<span class="token-hex-offset">${escapeHtml(match[1])}</span>  <span class="token-hex-bytes">${escapeHtml(match[2])}</span>  <span class="token-hex-ascii">${escapeHtml(match[3])}</span>`,
        "code-line",
      );
    })
    .join("");
}

function wrapCodeLine(content, className) {
  return `<span class="${className}">${content || "&nbsp;"}</span>`;
}

function bindCodePaneScroll(viewElement, lineElement) {
  viewElement.addEventListener("scroll", () => {
    lineElement.scrollTop = viewElement.scrollTop;
  });
}

function bindMessagePaneActivation() {
  document.addEventListener("pointerdown", (event) => {
    if (!(event.target instanceof HTMLElement)) {
      state.activeMessagePane = null;
      return;
    }

    if (event.target.closest("#requestColumn")) {
      state.activeMessagePane = "request";
      return;
    }

    if (event.target.closest("#responseColumn")) {
      state.activeMessagePane = "response";
      return;
    }

    state.activeMessagePane = null;
  });

  els.requestView?.addEventListener("focus", () => {
    state.activeMessagePane = "request";
  });

  els.responseView?.addEventListener("focus", () => {
    state.activeMessagePane = "response";
  });
}

function bindHistoryColumnResizers() {
  historyColumnHandles.forEach((handle) => {
    handle.addEventListener("dblclick", (event) => {
      event.preventDefault();
      event.stopPropagation();
      const key = handle.dataset.columnKey;
      if (!key || !HISTORY_COLUMN_RULES[key]) {
        return;
      }
      state.historyColumnWidths[key] = HISTORY_COLUMN_RULES[key].default;
      applyHistoryColumnWidths();
      saveHistoryColumnWidths();
    });

    handle.addEventListener("mousedown", (event) => {
      const key = handle.dataset.columnKey;
      const limits = HISTORY_COLUMN_RULES[key];
      if (!key || !limits) {
        return;
      }

      event.preventDefault();
      event.stopPropagation();

      const header = handle.closest("th");
      const startWidth = header?.getBoundingClientRect().width ?? limits.default;
      document.body.classList.add("pane-resizing-x");
      handle.classList.add("active");

      const onMove = (moveEvent) => {
        const delta = moveEvent.clientX - event.clientX;
        state.historyColumnWidths[key] = clamp(
          Math.round(startWidth + delta),
          limits.min,
          limits.max,
        );
        applyHistoryColumnWidths();
      };

      const onUp = () => {
        document.body.classList.remove("pane-resizing-x");
        handle.classList.remove("active");
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        saveHistoryColumnWidths();
      };

      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  });
}

function bindWorkbenchStackResizer(handle) {
  if (!handle) {
    return;
  }

  handle.addEventListener("dblclick", () => {
    resetWorkbenchStackHeight();
  });

  handle.addEventListener("mousedown", (event) => {
    if (!els.trafficRegion || !els.lowerWorkbench || els.historyWorkbenchResizer.classList.contains("hidden")) {
      return;
    }

    event.preventDefault();
    const start = {
      history: els.trafficRegion.getBoundingClientRect().height,
      messages: els.lowerWorkbench.getBoundingClientRect().height,
    };
    const combinedHeight = start.history + start.messages;

    document.body.classList.add("pane-resizing-y");
    handle.classList.add("active");

    const onMove = (moveEvent) => {
      const delta = moveEvent.clientY - event.clientY;
      const nextMessages = clamp(
        start.messages - delta,
        WORKBENCH_STACK_MIN_HEIGHTS.messages,
        combinedHeight - WORKBENCH_STACK_MIN_HEIGHTS.history,
      );
      applyWorkbenchStackHeight(nextMessages);
    };

    const onUp = () => {
      document.body.classList.remove("pane-resizing-y");
      handle.classList.remove("active");
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      normalizeWorkbenchStackHeight();
    };

    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  });
}

function bindPaneResizer(handle, mode) {
  if (!handle) {
    return;
  }

  handle.addEventListener("dblclick", () => {
    resetWorkbenchPaneWidths();
  });

  handle.addEventListener("mousedown", (event) => {
    if (window.matchMedia(WORKBENCH_STACK_BREAKPOINT).matches) {
      return;
    }

    event.preventDefault();
    const start = getWorkbenchWidths();
    if (!start) {
      return;
    }

    document.body.classList.add("pane-resizing-x");
    handle.classList.add("active");

    const onMove = (moveEvent) => {
      const delta = moveEvent.clientX - event.clientX;
      if (mode === "request-response") {
        const combinedWidth = start.request + start.response;
        const nextRequest = clamp(
          start.request + delta,
          WORKBENCH_MIN_WIDTHS.request,
          combinedWidth - WORKBENCH_MIN_WIDTHS.response,
        );
        applyWorkbenchPaneWidths(nextRequest, combinedWidth - nextRequest, start.total);
        return;
      }
    };

    const onUp = () => {
      document.body.classList.remove("pane-resizing-x");
      handle.classList.remove("active");
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      normalizeWorkbenchPaneWidths();
    };

    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  });
}

function getWorkbenchWidths() {
  if (!els.lowerWorkbench || !els.requestColumn || !els.responseColumn) {
    return null;
  }

  return {
    total: els.lowerWorkbench.getBoundingClientRect().width,
    request: els.requestColumn.getBoundingClientRect().width,
    response: els.responseColumn.getBoundingClientRect().width,
  };
}

function applyWorkbenchPaneWidths(requestWidth, responseWidth, totalWidth = els.lowerWorkbench.getBoundingClientRect().width) {
  if (!totalWidth) {
    return;
  }

  const requestPercent = clamp((requestWidth / totalWidth) * 100, 18, 72);
  const responsePercent = clamp((responseWidth / totalWidth) * 100, 18, 72);
  els.lowerWorkbench.style.setProperty("--request-pane-width", `${requestPercent}%`);
  els.lowerWorkbench.style.setProperty("--response-pane-width", `${responsePercent}%`);
}

function normalizeWorkbenchPaneWidths() {
  if (!els.lowerWorkbench || window.matchMedia(WORKBENCH_STACK_BREAKPOINT).matches) {
    return;
  }

  const hasCustomWidths = els.lowerWorkbench.style.getPropertyValue("--request-pane-width")
    || els.lowerWorkbench.style.getPropertyValue("--response-pane-width");
  if (!hasCustomWidths) {
    return;
  }

  const bounds = getWorkbenchWidths();
  if (!bounds) {
    return;
  }

  const visibleHandleWidth = 10;
  const maxRequestAndResponse = Math.max(
    WORKBENCH_MIN_WIDTHS.request + WORKBENCH_MIN_WIDTHS.response,
    bounds.total - visibleHandleWidth,
  );
  const currentCombined = bounds.request + bounds.response;
  const combinedWidth = Math.min(currentCombined, maxRequestAndResponse);
  const requestRatio = currentCombined ? bounds.request / currentCombined : 0.5;
  const requestWidth = clamp(
    combinedWidth * requestRatio,
    WORKBENCH_MIN_WIDTHS.request,
    combinedWidth - WORKBENCH_MIN_WIDTHS.response,
  );
  const responseWidth = combinedWidth - requestWidth;
  applyWorkbenchPaneWidths(requestWidth, responseWidth, bounds.total);
}

function resetWorkbenchPaneWidths() {
  els.lowerWorkbench.style.removeProperty("--request-pane-width");
  els.lowerWorkbench.style.removeProperty("--response-pane-width");
}

function bindWebsocketPaneResizer(handle) {
  if (!handle) {
    return;
  }

  handle.addEventListener("dblclick", () => {
    resetWebsocketPaneWidth();
  });

  handle.addEventListener("mousedown", (event) => {
    if (window.matchMedia(WEBSOCKET_WORKBENCH_BREAKPOINT).matches) {
      return;
    }

    event.preventDefault();
    const start = getWebsocketWorkbenchWidths();
    if (!start) {
      return;
    }

    document.body.classList.add("pane-resizing-x");
    handle.classList.add("active");

    const onMove = (moveEvent) => {
      const delta = moveEvent.clientX - event.clientX;
      const combinedWidth = start.handshake + start.frames;
      const nextHandshake = clamp(
        start.handshake + delta,
        WEBSOCKET_WORKBENCH_MIN_WIDTHS.handshake,
        combinedWidth - WEBSOCKET_WORKBENCH_MIN_WIDTHS.frames,
      );
      applyWebsocketPaneWidth(nextHandshake);
    };

    const onUp = () => {
      document.body.classList.remove("pane-resizing-x");
      handle.classList.remove("active");
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      normalizeWebsocketPaneWidth();
    };

    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  });
}

function getWebsocketWorkbenchWidths() {
  if (!els.websocketWorkbench || !els.websocketHandshakeColumn || !els.websocketFramesColumn) {
    return null;
  }

  return {
    total: els.websocketHandshakeColumn.getBoundingClientRect().width
      + els.websocketFramesColumn.getBoundingClientRect().width,
    handshake: els.websocketHandshakeColumn.getBoundingClientRect().width,
    frames: els.websocketFramesColumn.getBoundingClientRect().width,
  };
}

function applyWebsocketPaneWidth(handshakeWidth) {
  if (!els.websocketWorkbench) {
    return;
  }
  els.websocketWorkbench.style.setProperty("--websocket-left-pane-width", `${Math.round(handshakeWidth)}px`);
}

function normalizeWebsocketPaneWidth() {
  if (!els.websocketWorkbench || window.matchMedia(WEBSOCKET_WORKBENCH_BREAKPOINT).matches) {
    resetWebsocketPaneWidth();
    return;
  }

  const customWidth = els.websocketWorkbench.style.getPropertyValue("--websocket-left-pane-width");
  if (!customWidth) {
    return;
  }

  const bounds = getWebsocketWorkbenchWidths();
  if (!bounds) {
    return;
  }

  const nextHandshake = clamp(
    bounds.handshake,
    WEBSOCKET_WORKBENCH_MIN_WIDTHS.handshake,
    bounds.total - WEBSOCKET_WORKBENCH_MIN_WIDTHS.frames,
  );
  applyWebsocketPaneWidth(nextHandshake);
}

function resetWebsocketPaneWidth() {
  els.websocketWorkbench?.style.removeProperty("--websocket-left-pane-width");
}

function applyWorkbenchStackHeight(height, persist = true) {
  const roundedHeight = Math.round(height);
  els.proxyShell.style.setProperty("--workbench-pane-height", `${roundedHeight}px`);
  if (persist) {
    persistWorkbenchLayout(roundedHeight);
  }
}

function normalizeWorkbenchStackHeight() {
  if (
    !els.proxyShell
    || !els.trafficRegion
    || !els.lowerWorkbench
    || els.historyWorkbenchResizer?.classList.contains("hidden")
  ) {
    return;
  }

  const rawHeight = els.proxyShell.style.getPropertyValue("--workbench-pane-height");
  if (!rawHeight) {
    return;
  }

  const historyHeight = els.trafficRegion.getBoundingClientRect().height;
  const messagesHeight = els.lowerWorkbench.getBoundingClientRect().height;
  const combinedHeight = historyHeight + messagesHeight;
  const nextMessages = clamp(
    messagesHeight,
    WORKBENCH_STACK_MIN_HEIGHTS.messages,
    combinedHeight - WORKBENCH_STACK_MIN_HEIGHTS.history,
  );
  applyWorkbenchStackHeight(nextMessages);
}

function resetWorkbenchStackHeight() {
  els.proxyShell.style.removeProperty("--workbench-pane-height");
  state.workbenchHeight = null;
  scheduleUiSettingsSave();
}

function applyCodeSearch(viewElement, query) {
  const normalizedQuery = String(query || "").trim();
  if (!normalizedQuery) {
    return { count: 0, firstMatch: null };
  }

  const lowerQuery = normalizedQuery.toLowerCase();
  const walker = document.createTreeWalker(
    viewElement,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode(node) {
        if (!node.nodeValue || !node.nodeValue.trim()) {
          return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      },
    },
  );

  const textNodes = [];
  while (walker.nextNode()) {
    textNodes.push(walker.currentNode);
  }

  let count = 0;
  let firstMatch = null;

  textNodes.forEach((node) => {
    const value = node.nodeValue;
    const haystack = value.toLowerCase();
    let cursor = 0;
    let matchIndex = haystack.indexOf(lowerQuery, cursor);
    if (matchIndex === -1 || !node.parentNode) {
      return;
    }

    const fragment = document.createDocumentFragment();
    while (matchIndex !== -1) {
      if (matchIndex > cursor) {
        fragment.appendChild(document.createTextNode(value.slice(cursor, matchIndex)));
      }
      const mark = document.createElement("mark");
      mark.className = "search-hit";
      mark.textContent = value.slice(matchIndex, matchIndex + normalizedQuery.length);
      fragment.appendChild(mark);
      if (!firstMatch) {
        firstMatch = mark;
      }
      count += 1;
      cursor = matchIndex + normalizedQuery.length;
      matchIndex = haystack.indexOf(lowerQuery, cursor);
    }

    if (cursor < value.length) {
      fragment.appendChild(document.createTextNode(value.slice(cursor)));
    }

    node.parentNode.replaceChild(fragment, node);
  });

  return { count, firstMatch };
}

function buildSearchMeta(lineCount, mode, matchCount) {
  const searchCopy = matchCount ? `${matchCount} highlight${matchCount === 1 ? "" : "s"}` : "No highlights";
  return `${searchCopy} · ${lineCount} lines · ${titleCase(mode)} view`;
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function toggleSort(key) {
  if (state.sortKey === key) {
    state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
  } else {
    state.sortKey = key;
    state.sortDirection = defaultSortDirection(key);
  }

  renderHistory();
}

function renderSortHeaders() {
  sortHeaders.forEach((header) => {
    const active = header.dataset.sortKey === state.sortKey;
    const indicator = header.querySelector(".sort-indicator");
    header.classList.toggle("active", active);
    header.dataset.direction = active ? state.sortDirection : "none";
    if (indicator) {
      indicator.textContent = active ? (state.sortDirection === "asc" ? "↑" : "↓") : "↕";
    }
    header
      .closest("th")
      ?.setAttribute("aria-sort", active ? (state.sortDirection === "asc" ? "ascending" : "descending") : "none");
  });
}

function highlightStartLine(line, target) {
  const requestMatch = line.match(/^([A-Z]+)\s+(\S+)(?:\s+(HTTP\/[0-9.]+))?$/);
  if (target === "request" && requestMatch) {
    const [, method, path, version = "HTTP/1.1"] = requestMatch;
    return `<span class="token-method">${escapeHtml(method)}</span> ${highlightRequestTarget(path)} <span class="token-version">${escapeHtml(version)}</span>`;
  }

  const responseMatch = line.match(/^(HTTP\/[0-9.]+)\s+(\d{3})(?:\s+(.*))?$/);
  if (target === "response" && responseMatch) {
    const [, version, status, detail = ""] = responseMatch;
    return `<span class="token-version">${escapeHtml(version)}</span> <span class="token-status ${statusTone(Number(status))}">${escapeHtml(status)}</span>${detail ? ` <span class="token-plain">${escapeHtml(detail)}</span>` : ""}`;
  }

  return `<span class="token-plain">${escapeHtml(line)}</span>`;
}

function highlightRequestTarget(rawTarget) {
  const [pathPart, queryPart] = rawTarget.split("?", 2);
  if (!queryPart) {
    return `<span class="token-target">${escapeHtml(rawTarget)}</span>`;
  }

  return `<span class="token-target">${escapeHtml(pathPart)}</span><span class="token-punctuation">?</span>${highlightQueryString(queryPart)}`;
}

function highlightHeaderLine(line) {
  const separator = line.indexOf(":");
  if (separator === -1) {
    return `<span class="token-plain">${escapeHtml(line)}</span>`;
  }

  const name = line.slice(0, separator);
  const value = line.slice(separator + 1).trimStart();
  return `<span class="token-header">${escapeHtml(name)}</span><span class="token-punctuation">:</span> ${highlightHeaderValue(value)}`;
}

function highlightHeaderValue(value) {
  if (!value) {
    return '<span class="token-plain"></span>';
  }

  if (value.startsWith("http://") || value.startsWith("https://")) {
    return `<span class="token-url">${escapeHtml(value)}</span>`;
  }

  if (value.includes("=") && value.includes("&") && !value.includes(" ")) {
    return highlightQueryString(value);
  }

  return `<span class="token-plain">${escapeHtml(value)}</span>`;
}

function inferBodyHighlightMode(contentType) {
  const normalized = String(contentType || "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();

  if (!normalized) {
    return "plain";
  }

  if (normalized.includes("json") || normalized.endsWith("+json")) {
    return "json";
  }

  if (
    normalized === "text/html"
    || normalized === "application/xhtml+xml"
  ) {
    return "html";
  }

  if (
    normalized === "text/xml"
    || normalized === "application/xml"
    || normalized === "image/svg+xml"
    || normalized.endsWith("+xml")
  ) {
    return "xml";
  }

  if (normalized === "text/css") {
    return "css";
  }

  if (
    normalized === "application/javascript"
    || normalized === "text/javascript"
    || normalized === "application/x-javascript"
    || normalized.includes("javascript")
    || normalized.includes("ecmascript")
  ) {
    return "javascript";
  }

  if (normalized === "application/x-www-form-urlencoded") {
    return "form";
  }

  return "plain";
}

function highlightBodyLine(line, mode = "plain") {
  const trimmed = line.trim();

  if (!trimmed) {
    return "&nbsp;";
  }

  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    return `<span class="token-meta">${escapeHtml(line)}</span>`;
  }

  if (mode === "json") {
    return highlightJsonLine(line);
  }

  if (mode === "form" && looksLikeFormEncoded(trimmed)) {
    return highlightQueryString(trimmed);
  }

  if (mode === "html" || mode === "xml") {
    return highlightMarkupLine(line);
  }

  if (mode === "css") {
    return highlightCssLine(line);
  }

  if (mode === "javascript") {
    return highlightJavaScriptLine(line);
  }

  if (looksLikeJson(trimmed)) {
    return highlightJsonLine(line);
  }

  if (looksLikeMarkup(trimmed)) {
    return highlightMarkupLine(line);
  }

  if (looksLikeFormEncoded(trimmed)) {
    return highlightQueryString(trimmed);
  }

  return `<span class="token-plain">${escapeHtml(line)}</span>`;
}

function looksLikeJson(line) {
  return /^[\s,[\]{}"]/u.test(line) || /:\s*/u.test(line);
}

function looksLikeMarkup(line) {
  return /^<\/?[a-z!?][^>]*>$/iu.test(line) || /^<!DOCTYPE/i.test(line);
}

function looksLikeFormEncoded(line) {
  return line.includes("=") && !/\s/u.test(line);
}

function highlightJsonLine(line) {
  const regex = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?/g;
  let cursor = 0;
  let html = "";
  let match;

  while ((match = regex.exec(line)) !== null) {
    html += escapeHtml(line.slice(cursor, match.index));

    if (match[1]) {
      html += match[2]
        ? `<span class="token-json-key">${escapeHtml(match[1])}</span><span class="token-punctuation">:</span>`
        : `<span class="token-json-string">${escapeHtml(match[1])}</span>`;
    } else if (match[3]) {
      html += `<span class="token-json-boolean">${escapeHtml(match[3])}</span>`;
    } else {
      html += `<span class="token-json-number">${escapeHtml(match[0])}</span>`;
    }

    cursor = regex.lastIndex;
  }

  html += escapeHtml(line.slice(cursor));
  return html || `<span class="token-plain">${escapeHtml(line)}</span>`;
}

function highlightMarkupLine(line) {
  const tagPattern = /<!--.*?-->|<!DOCTYPE[^>]*>|<\?[^>]*\?>|<\/?[\w:-]+(?:\s+[\w:-]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?)*\s*\/?>/g;
  let cursor = 0;
  let html = "";
  let match;

  while ((match = tagPattern.exec(line)) !== null) {
    html += escapeHtml(line.slice(cursor, match.index));
    html += highlightMarkupToken(match[0]);
    cursor = tagPattern.lastIndex;
  }

  html += escapeHtml(line.slice(cursor));
  return html || `<span class="token-plain">${escapeHtml(line)}</span>`;
}

function highlightMarkupToken(token) {
  if (token.startsWith("<!--") || token.startsWith("<!") || token.startsWith("<?")) {
    return `<span class="token-markup-meta">${escapeHtml(token)}</span>`;
  }

  const tagMatch = token.match(/^(<\/?)([\w:-]+)([\s\S]*?)(\/?>)$/);
  if (!tagMatch) {
    return `<span class="token-markup-tag">${escapeHtml(token)}</span>`;
  }

  const [, open, name, attributes, close] = tagMatch;
  return `${highlightMarkupPunctuation(open)}<span class="token-markup-tag">${escapeHtml(name)}</span>${highlightMarkupAttributes(attributes)}${highlightMarkupPunctuation(close)}`;
}

function highlightMarkupAttributes(attributes) {
  if (!attributes) {
    return "";
  }

  const attributePattern = /([\w:-]+)(\s*=\s*)(".*?"|'.*?'|[^\s"'=<>`]+)/g;
  let cursor = 0;
  let html = "";
  let match;

  while ((match = attributePattern.exec(attributes)) !== null) {
    html += escapeHtml(attributes.slice(cursor, match.index));
    html += `<span class="token-markup-attr">${escapeHtml(match[1])}</span>${highlightMarkupPunctuation(match[2])}<span class="token-markup-string">${escapeHtml(match[3])}</span>`;
    cursor = attributePattern.lastIndex;
  }

  html += escapeHtml(attributes.slice(cursor));
  return html;
}

function highlightMarkupPunctuation(value) {
  return `<span class="token-punctuation">${escapeHtml(value)}</span>`;
}

function highlightCssLine(line) {
  const trimmed = line.trim();

  if (!trimmed) {
    return "&nbsp;";
  }

  if (trimmed.startsWith("/*") || trimmed.startsWith("*") || trimmed.endsWith("*/")) {
    return `<span class="token-meta">${escapeHtml(line)}</span>`;
  }

  const propertyMatch = line.match(/^(\s*)([\w-]+)(\s*:\s*)(.*?)(\s*;?\s*)$/);
  if (propertyMatch) {
    const [, indent, property, separator, value, suffix] = propertyMatch;
    return `${escapeHtml(indent)}<span class="token-css-property">${escapeHtml(property)}</span><span class="token-punctuation">${escapeHtml(separator)}</span>${highlightCssValue(value)}${highlightMarkupPunctuation(suffix)}`;
  }

  const selectorMatch = line.match(/^(\s*)([^{}]+?)(\s*)([{}])(\s*)$/);
  if (selectorMatch) {
    const [, indent, selector, innerSpace, brace, suffix] = selectorMatch;
    return `${escapeHtml(indent)}<span class="token-css-selector">${escapeHtml(selector)}</span>${escapeHtml(innerSpace)}<span class="token-punctuation">${escapeHtml(brace)}</span>${escapeHtml(suffix)}`;
  }

  const atRuleMatch = line.match(/^(\s*)(@[\w-]+)(.*)$/);
  if (atRuleMatch) {
    const [, indent, keyword, rest] = atRuleMatch;
    return `${escapeHtml(indent)}<span class="token-css-keyword">${escapeHtml(keyword)}</span>${highlightCssValue(rest)}`;
  }

  if (trimmed === "{" || trimmed === "}") {
    return `<span class="token-punctuation">${escapeHtml(line)}</span>`;
  }

  return `<span class="token-plain">${escapeHtml(line)}</span>`;
}

function highlightCssValue(value) {
  const tokenPattern = /(".*?"|'.*?'|#[0-9a-f]{3,8}\b|-?\d+(?:\.\d+)?(?:px|em|rem|%|vh|vw|ms|s|deg)?)/gi;
  let cursor = 0;
  let html = "";
  let match;

  while ((match = tokenPattern.exec(value)) !== null) {
    html += escapeHtml(value.slice(cursor, match.index));
    if (match[0].startsWith('"') || match[0].startsWith("'")) {
      html += `<span class="token-markup-string">${escapeHtml(match[0])}</span>`;
    } else {
      html += `<span class="token-json-number">${escapeHtml(match[0])}</span>`;
    }
    cursor = tokenPattern.lastIndex;
  }

  html += escapeHtml(value.slice(cursor));
  return html || `<span class="token-plain">${escapeHtml(value)}</span>`;
}

function highlightJavaScriptLine(line) {
  const tokenPattern = /\/\/.*$|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|\b(?:const|let|var|function|return|if|else|for|while|true|false|null|undefined|class|new|await|async|import|export|switch|case|break|continue|throw|try|catch|finally)\b|-?\d+(?:\.\d+)?/gm;
  let cursor = 0;
  let html = "";
  let match;

  while ((match = tokenPattern.exec(line)) !== null) {
    html += escapeHtml(line.slice(cursor, match.index));
    const token = match[0];

    if (token.startsWith("//")) {
      html += `<span class="token-meta">${escapeHtml(token)}</span>`;
    } else if (token.startsWith('"') || token.startsWith("'") || token.startsWith("`")) {
      html += `<span class="token-js-string">${escapeHtml(token)}</span>`;
    } else if (/^-?\d/u.test(token)) {
      html += `<span class="token-json-number">${escapeHtml(token)}</span>`;
    } else {
      html += `<span class="token-js-keyword">${escapeHtml(token)}</span>`;
    }

    cursor = tokenPattern.lastIndex;
  }

  html += escapeHtml(line.slice(cursor));
  return html || `<span class="token-plain">${escapeHtml(line)}</span>`;
}

function highlightQueryString(query) {
  return query
    .split("&")
    .map((pair) => {
      const [key, value = ""] = pair.split("=", 2);
      return `<span class="token-query-key">${escapeHtml(key)}</span><span class="token-punctuation">=</span><span class="token-query-value">${escapeHtml(value)}</span>`;
    })
    .join('<span class="token-punctuation">&amp;</span>');
}

function buildLineNumbers(count) {
  return Array.from({ length: Math.max(count, 1) }, (_value, index) => index + 1).join("\n");
}

function countLines(text) {
  return String(text || "").split("\n").length;
}

function renderHeaderList(headers) {
  if (!headers.length) {
    return "<p class=\"empty-copy\">No headers were captured.</p>";
  }

  return headers
    .map(
      (header) => `
        <div class="header-row">
          <span>${escapeHtml(header.name)}</span>
          <strong>${escapeHtml(header.value)}</strong>
        </div>
      `,
    )
    .join("");
}

function renderSummaryRows(rows) {
  return rows
    .map((row) => {
      const label = Array.isArray(row) ? row[0] : row.label;
      const value = Array.isArray(row) ? row[1] : row.value;
      const isHtml = !Array.isArray(row) && row.html === true;
      return `
        <dt>${escapeHtml(String(label))}</dt>
        <dd>${isHtml ? value : escapeHtml(String(value))}</dd>
      `;
    })
    .join("");
}

function inferProtocolState(record) {
  const headerNames = record.request.headers.map((header) => header.name);
  const looksLikeHttp2 = headerNames.some((name) => name.startsWith(":"));
  return {
    current: looksLikeHttp2 ? "HTTP/2" : "HTTP/1",
    supportsHttp2: looksLikeHttp2,
  };
}

function renderProtocolStrip(protocolState) {
  const current = protocolState?.current || "HTTP/1";
  const supportsHttp2 = Boolean(protocolState?.supportsHttp2);
  return `
    <div class="protocol-strip-label">Protocol</div>
    <div class="protocol-pill-group" aria-label="Captured protocol">
      <span class="protocol-pill ${current === "HTTP/1" ? "active" : ""}">HTTP/1</span>
      <span class="protocol-pill ${current === "HTTP/2" ? "active" : ""} ${supportsHttp2 ? "" : "muted"}">HTTP/2</span>
    </div>
  `;
}

function inferMimeType(item) {
  const contentType = (item.content_type || "").toLowerCase();
  if (contentType.includes("html")) return "html";
  if (contentType.includes("javascript")) return "script";
  if (contentType.includes("json") || contentType.includes("text")) return "json";
  if (contentType.includes("css")) return "css";
  if (contentType.includes("image")) return "image";
  const path = (item.path || "").toLowerCase();
  if (path.endsWith(".js")) return "script";
  if (path.endsWith(".css")) return "css";
  if (path.endsWith(".json")) return "json";
  if (path.endsWith(".html")) return "html";
  if (/\.(png|jpg|jpeg|gif|svg|ico)$/i.test(path)) return "image";
  if (item.is_websocket) return "websocket";
  return "other";
}

function isTlsRecord(item) {
  return item.kind === "tunnel" || item.scheme === "https";
}

function getVisibleItems() {
  return getVisibleEntries().map((entry) => entry.item);
}

function getVisibleEntries() {
  const direction = state.sortDirection === "asc" ? 1 : -1;

  return state.items
    .filter((item) => item.method !== "CONNECT")
    .filter(matchesQuickFilters)
    .filter(matchesAdvancedFilters)
    .map((item, index) => ({ item, index }))
    .sort((left, right) => {
      if (state.sortKey === "index") {
        return (left.index - right.index) * direction;
      }

      const comparison = compareSortValues(
        getSortValue(left.item, state.sortKey),
        getSortValue(right.item, state.sortKey),
      );

      if (comparison !== 0) {
        return comparison * direction;
      }

      return left.index - right.index;
    })
}

function matchesQuickFilters(item) {
  const methodMatch = !state.method || item.method === state.method;
  if (!methodMatch) {
    return false;
  }

  if (!state.query) {
    return true;
  }

  const haystack = `${item.host} ${item.method} ${item.path || ""}`.toLowerCase();
  return haystack.includes(state.query.toLowerCase());
}

function matchesAdvancedFilters(item) {
  const filters = state.filterSettings;

  if (filters.inScopeOnly && !isInScopeHost(item.host)) {
    return false;
  }

  if (filters.hideWithoutResponses && !item.has_response) {
    return false;
  }

  if (filters.onlyParameterized && !(item.path || "").includes("?")) {
    return false;
  }

  if (filters.onlyNotes && !(item.note_count > 0)) {
    return false;
  }

  if (!matchesStatusFilter(item)) {
    return false;
  }

  if (!matchesMimeFilter(item)) {
    return false;
  }

  if (!matchesExtensionFilter(item)) {
    return false;
  }

  if (!matchesPortFilter(item)) {
    return false;
  }

  if (!matchesColorTagFilter(item)) {
    return false;
  }

  return matchesAdvancedSearch(item);
}

function matchesStatusFilter(item) {
  const status = item.status;
  if (status >= 200 && status < 300) return state.filterSettings.status.success;
  if (status >= 300 && status < 400) return state.filterSettings.status.redirect;
  if (status >= 400 && status < 500) return state.filterSettings.status.clientError;
  if (status >= 500 && status < 600) return state.filterSettings.status.serverError;
  return state.filterSettings.status.other;
}

function matchesMimeFilter(item) {
  const mime = inferMimeType(item);
  switch (mime) {
    case "html":
      return state.filterSettings.mime.html;
    case "script":
      return state.filterSettings.mime.script;
    case "json":
      return state.filterSettings.mime.json;
    case "css":
      return state.filterSettings.mime.css;
    case "image":
      return state.filterSettings.mime.image;
    default:
      return state.filterSettings.mime.other;
  }
}

function matchesExtensionFilter(item) {
  const path = item.path || "";
  const extension = extractPathExtension(path);
  if (!extension) {
    return true;
  }

  const hidden = state.filterSettings.hiddenExtensions
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);

  return !hidden.includes(extension);
}

function matchesPortFilter(item) {
  if (!state.filterSettings.port) {
    return true;
  }

  const port = item.host.split(":")[1] || "";
  return port === state.filterSettings.port;
}

function matchesColorTagFilter(item) {
  const tags = state.filterSettings.colorTags;
  if (!tags || tags.size === 0) {
    return true;
  }
  return tags.has(item.color_tag);
}

function syncColorTagFilterUI() {
  const tags = state.filterSettings.colorTags;
  els.colorTagFilter.querySelectorAll(".color-dot-btn").forEach((btn) => {
    btn.classList.toggle("active", tags.has(btn.dataset.color));
  });
}

function matchesAdvancedSearch(item) {
  if (!state.filterSettings.searchTerm) {
    return true;
  }

  const haystack = `${item.host} ${item.method} ${item.path || ""} ${item.content_type || ""}`;
  let matched = false;

  if (state.filterSettings.regex) {
    try {
      const flags = state.filterSettings.caseSensitive ? "u" : "iu";
      matched = new RegExp(state.filterSettings.searchTerm, flags).test(haystack);
    } catch (_error) {
      matched = true;
    }
  } else {
    const left = state.filterSettings.caseSensitive ? haystack : haystack.toLowerCase();
    const right = state.filterSettings.caseSensitive
      ? state.filterSettings.searchTerm
      : state.filterSettings.searchTerm.toLowerCase();
    matched = left.includes(right);
  }

  return state.filterSettings.negativeSearch ? !matched : matched;
}

function isInScopeHost(host) {
  const patterns = state.runtime?.scope_patterns || [];
  if (!patterns.length) {
    return true;
  }

  const hostname = host.split(":")[0].toLowerCase();
  return patterns.some((pattern) => {
    const normalized = pattern.toLowerCase();
    if (normalized.startsWith("*.")) {
      const suffix = normalized.slice(2);
      return hostname === suffix || hostname.endsWith(`.${suffix}`);
    }
    return hostname === normalized;
  });
}

function extractPathExtension(path) {
  const clean = path.split("?")[0];
  const match = clean.match(/\.([a-z0-9]+)$/i);
  return match ? match[1].toLowerCase() : "";
}

function countHiddenConnectItems() {
  return state.items.filter((item) => item.method === "CONNECT").length;
}

function humanizeProxyTab(value) {
  return value
    .split("-")
    .map((segment) => titleCase(segment))
    .join(" ");
}

function humanizeSortKey(key) {
  switch (key) {
    case "index":
      return "#";
    case "started_at":
      return "time";
    case "path":
      return "url";
    default:
      return key.replaceAll("_", " ");
  }
}

function defaultSortDirection(key) {
  return ["index", "started_at", "status", "length", "notes", "tls"].includes(key) ? "desc" : "asc";
}

function getSortValue(item, key) {
  switch (key) {
    case "host":
      return item.host.toLowerCase();
    case "method":
      return item.method;
    case "path":
      return (item.path || "").toLowerCase();
    case "status":
      return item.status ?? -1;
    case "length":
      return (item.request_bytes ?? 0) + (item.response_bytes ?? 0);
    case "mime":
      return inferMimeType(item);
    case "notes":
      return item.note_count ?? 0;
    case "tls":
      return isTlsRecord(item) ? 1 : 0;
    case "started_at":
      return Date.parse(item.started_at) || 0;
    default:
      return "";
  }
}

function compareSortValues(left, right) {
  if (typeof left === "number" && typeof right === "number") {
    return left - right;
  }

  return String(left).localeCompare(String(right), undefined, {
    numeric: true,
    sensitivity: "base",
  });
}

function formatKind(kind) {
  return kind === "tunnel" ? "CONNECT tunnel" : "HTTP exchange";
}

function formatStatus(status) {
  if (status == null) return "n/a";
  return String(status);
}

function statusTone(status) {
  if (status == null || Number.isNaN(status)) return "none";
  if (status >= 200 && status < 300) return "ok";
  if (status >= 300 && status < 400) return "info";
  if (status >= 400 && status < 500) return "warn";
  return "error";
}

function methodTone(method) {
  switch (method) {
    case "GET":
      return "is-get";
    case "POST":
      return "is-post";
    case "PUT":
      return "is-put";
    case "PATCH":
      return "is-patch";
    case "DELETE":
      return "is-delete";
    default:
      return "is-generic";
  }
}

function formatTimestamp(value) {
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(value));
}

function formatSize(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let size = bytes;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(size >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
}

function titleCase(value) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/* ─── Context menu (color tags & notes) ─── */
let contextMenuTargetId = null;
let contextMenuNoteTimer = null;

function openContextMenu(x, y, transactionId) {
  contextMenuTargetId = transactionId;
  const menu = els.contextMenu;
  menu.classList.remove("hidden");

  const item = state.items.find((i) => i.id === transactionId);
  const currentColor = item?.color_tag || "";

  menu.querySelectorAll(".color-dot").forEach((dot) => {
    dot.classList.toggle("active", dot.dataset.color === currentColor);
  });

  els.contextMenuNote.value = "";
  if (transactionId) {
    loadUserNote(transactionId);
  }

  const menuWidth = menu.offsetWidth;
  const menuHeight = menu.offsetHeight;
  const maxX = window.innerWidth - menuWidth - 8;
  const maxY = window.innerHeight - menuHeight - 8;
  menu.style.left = `${Math.min(x, maxX)}px`;
  menu.style.top = `${Math.min(y, maxY)}px`;
}

function closeContextMenu() {
  els.contextMenu.classList.add("hidden");
  contextMenuTargetId = null;
}

async function loadUserNote(transactionId) {
  try {
    const response = await fetch(`/api/transactions/${transactionId}`);
    if (response.ok) {
      const record = await response.json();
      if (contextMenuTargetId === transactionId) {
        els.contextMenuNote.value = record.user_note || "";
      }
    }
  } catch { /* ignore */ }
}

async function updateAnnotations(transactionId, payload) {
  try {
    const response = await fetch(`/api/transactions/${transactionId}/annotations`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (response.ok) {
      const summary = await response.json();
      const index = state.items.findIndex((i) => i.id === transactionId);
      if (index !== -1) {
        Object.assign(state.items[index], summary);
        renderHistory();
      }
      if (state.selectedRecord && state.selectedRecord.id === transactionId) {
        if (payload.color_tag !== undefined) {
          state.selectedRecord.color_tag = payload.color_tag;
        }
        if (payload.user_note !== undefined) {
          state.selectedRecord.user_note = payload.user_note;
        }
      }
    }
  } catch (error) {
    console.error("Failed to update annotations:", error);
  }
}

document.addEventListener("click", (event) => {
  if (!els.contextMenu.contains(event.target)) {
    closeContextMenu();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !els.contextMenu.classList.contains("hidden")) {
    closeContextMenu();
  }
});

els.contextMenu.querySelectorAll(".color-dot").forEach((dot) => {
  dot.addEventListener("click", () => {
    if (!contextMenuTargetId) return;
    const color = dot.dataset.color || null;
    updateAnnotations(contextMenuTargetId, { color_tag: color });
    els.contextMenu.querySelectorAll(".color-dot").forEach((d) => {
      d.classList.toggle("active", d.dataset.color === (color || ""));
    });
  });
});

els.contextMenu.querySelectorAll(".context-menu-item").forEach((item) => {
  item.addEventListener("click", () => {
    const action = item.dataset.action;
    if (!contextMenuTargetId) return;
    state.selectedId = contextMenuTargetId;
    closeContextMenu();
    if (action === "send-to-replay") {
      openReplayFromSelection().catch((error) => console.error(error));
    } else if (action === "send-to-fuzzer") {
      openFuzzerFromSelection().catch((error) => console.error(error));
    }
  });
});

els.contextMenuNote.addEventListener("input", () => {
  if (!contextMenuTargetId) return;
  clearTimeout(contextMenuNoteTimer);
  const id = contextMenuTargetId;
  const value = els.contextMenuNote.value;
  contextMenuNoteTimer = setTimeout(() => {
    updateAnnotations(id, { user_note: value || null });
  }, 500);
});

els.contextMenuNote.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    if (!contextMenuTargetId) return;
    const value = els.contextMenuNote.value;
    clearTimeout(contextMenuNoteTimer);
    updateAnnotations(contextMenuTargetId, { user_note: value || null });
    closeContextMenu();
  }
  event.stopPropagation();
});
