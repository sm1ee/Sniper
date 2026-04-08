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

function createDefaultWsColumnWidths() {
  return Object.fromEntries(
    Object.entries(WS_COLUMN_RULES).filter(([, r]) => r.max > 0).map(([key, r]) => [key, r.default]),
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
const WS_COLUMN_RULES = {
  index:       { default: 48,  min: 36,  max: 80 },
  host:        { default: 260, min: 120, max: 600 },
  path:        { default: 0,   min: 0,   max: 0 },   // flex column, not resizable
  status:      { default: 62,  min: 50,  max: 120 },
  frame_count: { default: 72,  min: 50,  max: 140 },
  duration_ms: { default: 90,  min: 60,  max: 180 },
  started_at:  { default: 150, min: 110, max: 260 },
};

const FINDINGS_COL_RULES = {
  severity: { default: 88, min: 60, max: 150 },
  category: { default: 96, min: 60, max: 180 },
  title:    { default: 200, min: 100, max: 600 },
  host:     { default: 180, min: 80, max: 500 },
  path:     { default: 260, min: 80, max: 700 },
  time:     { default: 120, min: 80, max: 260 },
};
let findingsColWidths = Object.fromEntries(
  Object.entries(FINDINGS_COL_RULES).map(([k, v]) => [k, v.default])
);
const WORKBENCH_STACK_MIN_HEIGHTS = {
  history: 140,
  messages: 180,
};
const REPEATER_HISTORY_LIMIT = 30;
const HISTORY_ROW_HEIGHT = 27;
const HISTORY_BUFFER_ROWS = 30;
const FINDINGS_ROW_HEIGHT = 27;
const FINDINGS_BUFFER_ROWS = 20;
const IMPLEMENTED_TOOLS = new Set(["dashboard", "target", "proxy", "fuzzer", "sequence", "replay", "tools", "logger"]);
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
  selectedSessionId: null,
  sessionSortKey: "created_at",
  sessionSortDir: "desc",
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
  _settingsLoadPending: false,
  messageViews: {
    request: "pretty",
    response: "pretty",
  },
  showOriginal: {
    request: false,
    response: false,
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
  wsColumnWidths: createDefaultWsColumnWidths(),
  filterSettings: createDefaultFilterSettings(),
  targetScopeDraft: "",
  targetScopeDirty: false,
  targetExpandedHosts: new Set(),
  intercepts: [],
  responseIntercepts: [],
  interceptRules: [],
  interceptQueueTab: "request",
  selectedInterceptId: null,
  selectedInterceptRecord: null,
  selectedResponseInterceptId: null,
  selectedResponseInterceptRecord: null,
  responseInterceptEditorSeedId: null,
  websocketSessions: [],
  websocketQuery: "",
  websocketSortKey: "started_at",
  websocketSortDirection: "desc",
  selectedWebsocketId: null,
  selectedWebsocketRecord: null,
  selectedFrameIdx: null,
  wsKeyboardFocus: "sessions",
  replayTabs: [],
  activeReplayTabId: null,
  replayTabSequence: 0,
  replayMessageViews: { request: "pretty", response: "pretty" },
  interceptEditorSeedId: null,
  interceptInScopeOnly: false,
  eventLog: [],
  matchReplaceRules: [],
  selectedMatchReplaceRuleId: null,
  targetSiteMap: [],
  oastCallbacks: [],
  selectedOastId: null,
  sequenceDefinitions: [],
  selectedSequenceId: null,
  editingSequence: null,
  sequenceRunResult: null,
  sequencePastRuns: [],
  fuzzerBaseRequest: null,
  fuzzerSourceTransactionId: null,
  fuzzerNotice: "",
  fuzzerRequestText: "",
  fuzzerPayloadsText: "",
  fuzzerAttackRecord: null,
  _cachedVisibleEntries: null,
  _historyEntries: null,
  toolsReady: false,
  workbenchHeight: null,
  _cachedVisibleEntries: null,
};

const els = {
  dashboardShell: document.getElementById("dashboardShell"),
  dashboardCurrentSessionName: document.getElementById("dashboardCurrentSessionName"),
  dashboardCurrentSessionStatus: document.getElementById("dashboardCurrentSessionStatus"),
  dashboardCurrentSessionPath: document.getElementById("dashboardCurrentSessionPath"),
  dashboardOpenStorageBtn: document.getElementById("dashboardOpenStorageBtn"),
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
  toolsActiveToolTitle: document.getElementById("toolsActiveToolTitle"),
  replayTabStrip: document.getElementById("replayTabStrip"),
  newReplayTabButton: document.getElementById("newReplayTabButton"),
  fuzzerShell: document.getElementById("fuzzerShell"),
  sequenceShell: document.getElementById("sequenceShell"),
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
  findingsPanel: document.getElementById("findingsPanel"),
  findingsBody: document.getElementById("findingsBody"),
  findingsBadge: document.getElementById("findingsBadge"),
  findingsDetailResizer: document.getElementById("findingsDetailResizer"),
  findingsDetailPanel: document.getElementById("findingsDetailPanel"),
  findingsDetailContent: document.getElementById("findingsDetailContent"),
  findingsDetailPlaceholder: document.getElementById("findingsDetailPlaceholder"),
  findingsDetailTitle: document.getElementById("findingsDetailTitle"),
  findingsDetailSeverity: document.getElementById("findingsDetailSeverity"),
  findingsDetailCategory: document.getElementById("findingsDetailCategory"),
  findingsDetailDesc: document.getElementById("findingsDetailDesc"),
  findingsDetailJump: document.getElementById("findingsDetailJump"),
  findingsDetailClose: document.getElementById("findingsDetailClose"),
  findingsReqView: document.getElementById("findingsReqView"),
  findingsReqLines: document.getElementById("findingsReqLines"),
  findingsResView: document.getElementById("findingsResView"),
  findingsResLines: document.getElementById("findingsResLines"),
  findingsReqSearchInput: document.getElementById("findingsReqSearchInput"),
  findingsReqSearchMeta: document.getElementById("findingsReqSearchMeta"),
  findingsResSearchInput: document.getElementById("findingsResSearchInput"),
  findingsResSearchMeta: document.getElementById("findingsResSearchMeta"),
  findingsClearButton: document.getElementById("findingsClearButton"),
  findingsSettingsButton: document.getElementById("findingsSettingsButton"),
  findingsFilterSeverity: document.getElementById("findingsFilterSeverity"),
  findingsFilterCategory: document.getElementById("findingsFilterCategory"),
  findingsFilterSearch: document.getElementById("findingsFilterSearch"),
  scannerSettingsBackdrop: document.getElementById("scannerSettingsBackdrop"),
  scannerSettingsClose: document.getElementById("scannerSettingsClose"),
  scannerSettingsCancel: document.getElementById("scannerSettingsCancel"),
  scannerSettingsSave: document.getElementById("scannerSettingsSave"),
  scannerEnabledToggle: document.getElementById("scannerEnabledToggle"),
  scannerBuiltinRules: document.getElementById("scannerBuiltinRules"),
  scannerCustomRules: document.getElementById("scannerCustomRules"),
  scannerAddCustomRule: document.getElementById("scannerAddCustomRule"),
  scannerQuickToggle: document.getElementById("scannerQuickToggle"),
  findingsInScopeOnly: document.getElementById("findingsInScopeOnly"),
  oastPanel: document.getElementById("oastPanel"),
  oastTableBody: document.getElementById("oastTableBody"),
  oastBadge: document.getElementById("oastBadge"),
  oastGenerateButton: document.getElementById("oastGenerateButton"),
  oastClearButton: document.getElementById("oastClearButton"),
  oastPayloadDisplay: document.getElementById("oastPayloadDisplay"),
  oastPayloadText: document.getElementById("oastPayloadText"),
  oastCopyPayloadButton: document.getElementById("oastCopyPayloadButton"),
  oastDetailTitle: document.getElementById("oastDetailTitle"),
  oastDetailView: document.getElementById("oastDetailView"),
  proxySettingsPanel: document.getElementById("proxySettingsPanel"),
  requestView: document.getElementById("requestView"),
  requestLines: document.getElementById("requestLines"),
  responseView: document.getElementById("responseView"),
  responseLines: document.getElementById("responseLines"),
  requestViewCM: document.getElementById("requestViewCM"),
  responseViewCM: document.getElementById("responseViewCM"),
  requestSearchInput: document.getElementById("requestSearchInput"),
  responseSearchInput: document.getElementById("responseSearchInput"),
  requestSearchMeta: document.getElementById("requestSearchMeta"),
  responseSearchMeta: document.getElementById("responseSearchMeta"),
  requestMrToggle: document.getElementById("requestMrToggle"),
  responseMrToggle: document.getElementById("responseMrToggle"),
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
  forwardInterceptButton: document.getElementById("forwardInterceptButton"),
  dropInterceptButton: document.getElementById("dropInterceptButton"),
  interceptRequestTable: document.getElementById("interceptRequestTable"),
  responseInterceptTable: document.getElementById("responseInterceptTable"),
  responseInterceptTableBody: document.getElementById("responseInterceptTableBody"),
  interceptRequestEditorPanel: document.getElementById("interceptRequestEditorPanel"),
  interceptResponseEditorPanel: document.getElementById("interceptResponseEditorPanel"),
  interceptResponseHighlight: document.getElementById("interceptResponseHighlight"),
  interceptResponseEditor: document.getElementById("interceptResponseEditor"),
  interceptRequestActions: document.getElementById("interceptRequestActions"),
  responseInterceptActions: document.getElementById("responseInterceptActions"),
  forwardResponseInterceptButton: document.getElementById("forwardResponseInterceptButton"),
  dropResponseInterceptButton: document.getElementById("dropResponseInterceptButton"),
  interceptQueueTabRequest: document.getElementById("interceptQueueTabRequest"),
  interceptQueueTabResponse: document.getElementById("interceptQueueTabResponse"),
  websocketMeta: document.getElementById("websocketMeta"),
  websocketSearchInput: document.getElementById("websocketSearchInput"),
  websocketTableBody: document.getElementById("websocketTableBody"),
  websocketDetailTitle: document.getElementById("websocketDetailTitle"),
  websocketRequestView: document.getElementById("websocketRequestView"),
  websocketResponseView: document.getElementById("websocketResponseView"),
  websocketFramesBody: document.getElementById("websocketFramesBody"),
  frameDetailPanel: document.getElementById("frameDetailPanel"),
  frameDetailResizer: document.getElementById("frameDetailResizer"),
  frameDetailMeta: document.getElementById("frameDetailMeta"),
  frameDetailBody: document.getElementById("frameDetailBody"),
  frameDetailClose: document.getElementById("frameDetailClose"),
  refreshWebsocketsButton: document.getElementById("refreshWebsocketsButton"),
  websocketWorkbench: document.getElementById("websocketWorkbench"),
  websocketHandshakeColumn: document.getElementById("websocketHandshakeColumn"),
  websocketFramesColumn: document.getElementById("websocketFramesColumn"),
  websocketSplitResizer: document.getElementById("websocketSplitResizer"),
  websocketStackResizer: document.getElementById("websocketStackResizer"),
  proxySettingIntercept: document.getElementById("proxySettingIntercept"),
  proxySettingWebsocketCapture: document.getElementById("proxySettingWebsocketCapture"),
  proxySettingUpstreamInsecure: document.getElementById("proxySettingUpstreamInsecure"),
  proxySettingScopePatterns: document.getElementById("proxySettingScopePatterns"),
  proxySettingPassthroughHosts: document.getElementById("proxySettingPassthroughHosts"),
  proxySettingBindHost: document.getElementById("proxySettingBindHost"),
  proxySettingPort: document.getElementById("proxySettingPort"),
  proxySettingListenerHelp: document.getElementById("proxySettingListenerHelp"),
  saveProxySettingsButton: document.getElementById("saveProxySettingsButton"),
  reloadProxySettingsButton: document.getElementById("reloadProxySettingsButton"),
  openCertFolderButton: document.getElementById("openCertFolderButton"),
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
  replayResponseView: document.getElementById("replayResponseView"), // legacy, may be null
  replayResponseCM: document.getElementById("replayResponseCM"),
  replayResponseSearchInput: document.getElementById("replayResponseSearchInput"),
  replayResponseSearchMeta: document.getElementById("replayResponseSearchMeta"),
  sendReplayButton: document.getElementById("sendReplayButton"),
  cancelReplayButton: document.getElementById("cancelReplayButton"),
  replayBackButton: document.getElementById("replayBackButton"),
  replayForwardButton: document.getElementById("replayForwardButton"),
  replayFollowRedirectButton: document.getElementById("replayFollowRedirectButton"),
  eventLogTableBody: document.getElementById("eventLogTableBody"),
  clearEventLogButton: document.getElementById("clearEventLogButton"),
  matchReplaceTableBody: document.getElementById("matchReplaceTableBody"),
  matchReplaceEditorPath: document.getElementById("matchReplaceEditorPath"),
  matchReplaceEditorTitle: document.getElementById("matchReplaceEditorTitle"),
  matchReplaceDescription: document.getElementById("matchReplaceDescription"),
  matchReplaceScope: document.getElementById("matchReplaceScope"),
  matchReplaceTarget: document.getElementById("matchReplaceTarget"),
  matchReplaceSearch: document.getElementById("matchReplaceSearch"),
  matchReplaceReplace: document.getElementById("matchReplaceReplace"),
  matchReplaceRegex: document.getElementById("matchReplaceRegex"),
  matchReplaceCaseSensitive: document.getElementById("matchReplaceCaseSensitive"),
  saveMatchReplaceRuleButton: document.getElementById("saveMatchReplaceRuleButton"),
  addMatchReplaceRuleButton: document.getElementById("addMatchReplaceRuleButton"),
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
  wsFrameContextMenu: document.getElementById("wsFrameContextMenu"),
  httpReplayToolbar: document.getElementById("httpReplayToolbar"),
  httpReplayWorkbench: document.getElementById("httpReplayWorkbench"),
  wsReplayPanel: document.getElementById("wsReplayPanel"),
  wsSchemeSelect: document.getElementById("wsSchemeSelect"),
  wsHostInput: document.getElementById("wsHostInput"),
  wsPortInput: document.getElementById("wsPortInput"),
  wsPathInput: document.getElementById("wsPathInput"),
  wsConnectButton: document.getElementById("wsConnectButton"),
  wsDisconnectButton: document.getElementById("wsDisconnectButton"),
  wsStatusIndicator: document.getElementById("wsStatusIndicator"),
  wsStatusText: document.getElementById("wsStatusText"),
  wsMessageEditor: document.getElementById("wsMessageEditor"),
  wsSendButton: document.getElementById("wsSendButton"),
  wsMessageType: document.getElementById("wsMessageType"),
  wsHandshakeHeaders: document.getElementById("wsHandshakeHeaders"),
  wsFrameList: document.getElementById("wsFrameList"),
  wsFrameCount: document.getElementById("wsFrameCount"),
  wsFrameDetailPath: document.getElementById("wsFrameDetailPath"),
  wsFrameDetailTitle: document.getElementById("wsFrameDetailTitle"),
  wsFrameDetailView: document.getElementById("wsFrameDetailView"),
  wsReplayPaneResizer: document.getElementById("wsReplayPaneResizer"),
  wsReplayFrameResizer: document.getElementById("wsReplayFrameResizer"),
  wsHandshakeLines: document.getElementById("wsHandshakeLines"),
  wsHandshakeSearchInput: document.getElementById("wsHandshakeSearchInput"),
  wsHandshakeSearchMeta: document.getElementById("wsHandshakeSearchMeta"),
  wsMessageHighlight: document.getElementById("wsMessageHighlight"),
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

const WEBSOCKET_STACK_MIN_HEIGHTS = {
  sessions: 160,
  workbench: 220,
};

const LAYOUT_TEXTAREA_IDS = [
  "interceptRequestEditor",
  "proxySettingScopePatterns",
  "proxySettingPassthroughHosts",
  "fuzzerPayloadsEditor",
  "targetScopeEditor",
  "wsMessageEditor",
  "wsHandshakeHeaders",
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
  syncHttpInScopePill();
  const aclInit = document.getElementById("proxySettingAutoContentLength");
  if (aclInit) aclInit.checked = localStorage.getItem("sniper_auto_content_length") !== "false";
  await loadUiSettings();
  hydrateDisplaySettingsForm();
  const loads = [
    loadSessions(),
    loadSettings(),
    loadWorkspaceState(),
    loadTransactions(false),
    loadIntercepts(false),
    loadResponseIntercepts(false),
    loadWebsockets(false),
    loadEventLog(),
    loadMatchReplaceRules(),
    loadSequences(),
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
  // Sync active tabs from DOM in case WKWebView restored a cached page state
  const domActiveTool = document.querySelector(".tool-tab.active");
  if (domActiveTool?.dataset?.tool && domActiveTool.dataset.tool !== state.activeTool) {
    state.activeTool = domActiveTool.dataset.tool;
  }
  const domActiveProxyTab = document.querySelector(".sub-tab.active");
  if (domActiveProxyTab?.dataset?.proxyTab && domActiveProxyTab.dataset.proxyTab !== state.activeProxyTab) {
    state.activeProxyTab = domActiveProxyTab.dataset.proxyTab;
  }
  renderToolPanels();
  renderProxyPanels();
  renderInspectorPanels();
  renderViewTabs();
  renderSortHeaders();
  renderProxySettings();
  // Ensure Settings tab data loads on startup if it's the active tab
  if (state.activeProxyTab === "proxy-settings") {
    loadRuntimeSettings().catch((error) => console.error(error));
  }
  renderIntercepts();
  renderWebsocketSessions();
  renderReplay();
  renderDashboard();
  renderEventLog();
  renderMatchReplaceRules();
  renderTarget();
  renderFuzzer();
  normalizeWorkbenchStackHeight();
  // Safety: re-render settings after a short delay to cover WKWebView timing issues
  setTimeout(() => {
    if (state.settings && state.runtime) {
      renderProxySettings();
    }
  }, 800);
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
        loadResponseIntercepts(true).catch((error) => console.error(error));
        loadInterceptRules().catch((error) => console.error(error));
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

  document.querySelectorAll(".mr-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.target;
      state.showOriginal[target] = btn.dataset.mr === "original";
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

  // Virtual scroll for HTTP history table
  const historyShell = els.historyTable.closest(".history-table-shell");
  if (historyShell) {
    let historyScrollRaf = 0;
    historyShell.addEventListener("scroll", () => {
      if (historyScrollRaf) return;
      historyScrollRaf = requestAnimationFrame(() => {
        historyScrollRaf = 0;
        renderHistoryVirtual();
      });
    });
  }

  // Event delegation for HTTP history table rows (click & contextmenu)
  els.historyTableBody.addEventListener("click", (event) => {
    const row = event.target.closest(".history-row");
    if (!row) return;
    state.selectedId = row.dataset.id;
    updateHistorySelection(state.selectedId);
    scrollSelectedHistoryRowIntoView();
    loadTransactionDetail(state.selectedId).catch((error) => console.error(error));
    // Keep focus on the table so arrow keys navigate rows, not code-view lines
    els.trafficRegion.focus({ preventScroll: true });
  });
  els.historyTableBody.addEventListener("contextmenu", (event) => {
    const row = event.target.closest(".history-row");
    if (!row) return;
    event.preventDefault();
    state.selectedId = row.dataset.id;
    updateHistorySelection(state.selectedId);
    openContextMenu(event.clientX, event.clientY, row.dataset.id);
  });

  els.searchInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      state.query = els.searchInput.value.trim();
      scheduleRefresh();
    }
  });
  els.searchInput.addEventListener("search", () => {
    // Triggered when user clears the search field via the X button
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

  // Search hit navigation: click counter to cycle through matches
  initSearchHitNavigation(els.requestSearchMeta, () => els.requestView);
  initSearchHitNavigation(els.responseSearchMeta, () => els.responseView);
  initSearchHitNavigation(els.replayRequestSearchMeta, () => els.replayRequestHighlight);
  initSearchHitNavigation(els.replayResponseSearchMeta, () => els.replayResponseView);

  els.websocketSearchInput.addEventListener("input", () => {
    state.websocketQuery = els.websocketSearchInput.value.trim();
    syncVisibleWebsocketSelection(true).catch((error) => console.error(error));
  });
  document.getElementById("wsInScopeOnly")?.addEventListener("click", (e) => {
    e.currentTarget.classList.toggle("active");
    syncVisibleWebsocketSelection(true).catch((error) => console.error(error));
  });
  document.getElementById("wsHideClosed")?.addEventListener("click", (e) => {
    e.currentTarget.classList.toggle("active");
    syncVisibleWebsocketSelection(true).catch((error) => console.error(error));
  });
  document.getElementById("httpInScopeToggle")?.addEventListener("click", (e) => {
    e.currentTarget.classList.toggle("active");
    state.filterSettings.inScopeOnly = e.currentTarget.classList.contains("active");
    scheduleRefresh();
  });
  document.getElementById("interceptInScopeToggle")?.addEventListener("click", (e) => {
    e.currentTarget.classList.toggle("active");
    const scopeOnly = e.currentTarget.classList.contains("active");
    state.interceptInScopeOnly = scopeOnly;
    // Sync to server so intercept engine respects scope setting
    fetch("/api/runtime", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ intercept_scope_only: scopeOnly }),
    }).catch((err) => console.error("Failed to update intercept scope:", err));
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
  els.openUpdateButton.addEventListener("click", performSelfUpdate);
  if (els.toolsClearButton) els.toolsClearButton.addEventListener("click", clearToolsInputs);
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
  document.getElementById("closeCompareButton").addEventListener("click", closeCompareModal);
  document.getElementById("compareModal").addEventListener("click", (event) => {
    if (event.target.id === "compareModal") closeCompareModal();
  });
  document.querySelectorAll("[data-compare-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      compareActiveTab = btn.dataset.compareTab;
      renderCompareModal();
    });
  });

  document.getElementById("closeCurlImportButton").addEventListener("click", closeCurlImportModal);
  document.getElementById("applyCurlImportButton").addEventListener("click", applyCurlImport);
  document.getElementById("curlImportModal").addEventListener("click", (event) => {
    if (event.target.id === "curlImportModal") closeCurlImportModal();
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

  els.openCertFolderButton.addEventListener("click", () => openCertificateFolder());
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
  els.dashboardOpenStorageBtn?.addEventListener("click", () => {
    const sessionId = state.selectedSessionId || state.activeSession?.id || state.sessions.find((s) => s.active)?.id;
    if (sessionId) {
      fetch(`/api/sessions/${encodeURIComponent(sessionId)}/reveal`, { method: "POST" }).catch(console.error);
    }
  });

  // Session table sort headers
  document.querySelectorAll("#dashboardSessionsTable thead th[data-sort-key]").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sortKey;
      if (state.sessionSortKey === key) {
        state.sessionSortDir = state.sessionSortDir === "asc" ? "desc" : "asc";
      } else {
        state.sessionSortKey = key;
        state.sessionSortDir = key === "name" ? "asc" : "desc";
      }
      renderDashboard();
    });
  });

  els.clearEventLogButton.addEventListener("click", () => {
    clearEventLog().catch((error) => console.error(error));
  });

  els.closeInspectorButton?.addEventListener("click", () => {
    state.inspectorCollapsed = true;
    renderInspectorPanels();
  });

  document.getElementById("addInterceptRuleButton")?.addEventListener("click", () => {
    addInterceptRule().catch((error) => console.error(error));
  });
  document.getElementById("interceptRulesList").addEventListener("click", (event) => {
    const deleteBtn = event.target.closest("[data-rule-delete]");
    if (deleteBtn) { deleteInterceptRule(deleteBtn.dataset.ruleDelete).catch((e) => console.error(e)); return; }
    const saveBtn = event.target.closest("[data-rule-save]");
    if (saveBtn) { saveInterceptRuleFromRow(saveBtn.dataset.ruleSave).catch((e) => console.error(e)); return; }
    const row = event.target.closest("[data-rule-id]");
    if (row && !event.target.closest("input") && !event.target.closest("button")) { editInterceptRule(row.dataset.ruleId); }
  });
  document.getElementById("interceptRulesList").addEventListener("change", (event) => {
    const toggle = event.target.closest("[data-rule-toggle]");
    if (toggle) { toggleInterceptRuleEnabled(toggle.dataset.ruleToggle, toggle.checked).catch((e) => console.error(e)); }
  });
  document.getElementById("interceptRulesList").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      const row = event.target.closest("[data-rule-id]");
      if (row) { saveInterceptRuleFromRow(row.dataset.ruleId).catch((e) => console.error(e)); }
    }
  });
  if (els.refreshWebsocketsButton) {
    els.refreshWebsocketsButton.addEventListener("click", () => {
      loadWebsockets(true).catch((error) => console.error(error));
    });
  }
  els.frameDetailClose.addEventListener("click", hideFrameDetail);
  initFrameDetailResizer();
  document.querySelectorAll(".ws-sort").forEach((btn) => {
    btn.addEventListener("click", () => toggleWebsocketSort(btn.dataset.wsSortKey));
  });
  els.forwardInterceptButton.addEventListener("click", () => {
    forwardSelectedIntercept().catch((error) => console.error(error));
  });
  els.dropInterceptButton.addEventListener("click", () => {
    dropSelectedIntercept().catch((error) => console.error(error));
  });
  els.forwardResponseInterceptButton.addEventListener("click", () => {
    forwardSelectedResponseIntercept().catch((error) => console.error(error));
  });
  els.dropResponseInterceptButton.addEventListener("click", () => {
    dropSelectedResponseIntercept().catch((error) => console.error(error));
  });
  els.interceptQueueTabRequest.addEventListener("click", () => switchInterceptQueueTab("request"));
  els.interceptQueueTabResponse.addEventListener("click", () => switchInterceptQueueTab("response"));

  els.interceptStatus.addEventListener("click", () => {
    toggleIntercept().catch((error) => console.error(error));
  });
  els.saveProxySettingsButton.addEventListener("click", () => {
    saveProxySettings()
      .then((result) => {
        if (result?.rebound === true) {
          showToast(`Proxy listener moved to ${result.active_proxy_addr}`);
        } else if (result?.rebound === false && result?.rebind_error) {
          showToast(result.rebind_error, "error");
        } else {
          showToast("Proxy settings saved");
        }
      })
      .catch((error) => { console.error(error); showToast("Failed to save proxy settings", "error"); });
  });
  els.reloadProxySettingsButton.addEventListener("click", () => {
    loadSettings().catch((error) => console.error(error));
  });
  document.getElementById("proxySettingAutoContentLength")?.addEventListener("change", (e) => {
    localStorage.setItem("sniper_auto_content_length", e.target.checked);
  });

  // Pane context menu (right-click on Request/Response code-view)
  const paneCtx = document.getElementById("paneContextMenu");
  if (paneCtx) {
    [els.requestView, els.responseView].forEach((view) => {
      if (!view) return;
      view.addEventListener("contextmenu", (e) => {
        if (!state.selectedId) return;
        e.preventDefault();
        paneCtx.classList.remove("hidden");
        const mw = paneCtx.offsetWidth, mh = paneCtx.offsetHeight;
        paneCtx.style.left = `${Math.min(e.clientX, window.innerWidth - mw - 8)}px`;
        paneCtx.style.top = `${Math.min(e.clientY, window.innerHeight - mh - 8)}px`;
      });
    });
    document.addEventListener("click", () => paneCtx.classList.add("hidden"));
    paneCtx.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-pane-action]");
      if (!btn || !state.selectedId) return;
      const action = btn.dataset.paneAction;
      paneCtx.classList.add("hidden");
      if (action === "copy-url") copySelectedTransactionUrl();
      else if (action === "send-to-replay") openReplayFromSelection().catch(console.error);
      else if (action === "send-to-fuzzer") openFuzzerFromSelection().catch(console.error);
      else if (action.startsWith("copy-response-")) copyResponseContent(action.replace("copy-", ""));
      else if (action.startsWith("copy-as-")) {
        const fmt = action.replace("copy-as-", "");
        const text = selectedRecordToFormat(fmt);
        if (text) { copyTextToClipboard(text); showToast(`Copied as ${fmt}`); }
      }
    });
  }

  els.sendReplayButton.addEventListener("click", () => {
    sendReplay().catch((error) => console.error(error));
  });
  els.newReplayTabButton.addEventListener("click", () => {
    openBlankReplayTab();
  });
  els.cancelReplayButton.addEventListener("click", cancelReplaySend);
  els.replayBackButton.addEventListener("click", () => {
    navigateReplayHistory(-1);
  });
  els.replayForwardButton.addEventListener("click", () => {
    navigateReplayHistory(1);
  });
  els.replayFollowRedirectButton.addEventListener("click", () => {
    followRedirect().catch((error) => console.error(error));
  });
  els.saveMatchReplaceRuleButton.addEventListener("click", () => {
    if (!state.selectedMatchReplaceRuleId) {
      createNewMatchReplaceRule();
    }
    syncMatchReplaceEditor();
    saveMatchReplaceRules()
      .then(() => showToast("Rule saved"))
      .catch((error) => { console.error(error); showToast("Failed to save rule", "error"); });
  });
  els.addMatchReplaceRuleButton.addEventListener("click", () => {
    syncMatchReplaceEditor();
    createNewMatchReplaceRule();
    // Don't save immediately — let user fill in fields first
    renderMatchReplaceRules();
  });
  els.deleteMatchReplaceRuleButton.addEventListener("click", deleteSelectedMatchReplaceRule);
  [
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

  document.getElementById("newSequenceButton").addEventListener("click", () => {
    createNewSequence().catch((e) => console.error(e));
  });
  document.getElementById("addSequenceStepButton").addEventListener("click", addSequenceStep);
  document.getElementById("saveSequenceButton").addEventListener("click", () => {
    saveCurrentSequence().catch((e) => console.error(e));
  });
  document.getElementById("runSequenceButton").addEventListener("click", () => {
    runCurrentSequence().catch((e) => console.error(e));
  });

  // The replay request editor uses a contenteditable <pre> for editing so that
  // native text selection works over syntax-highlighted text (WKWebView renders
  // textarea selection in an opaque native layer that cannot be hidden).
  // The hidden <textarea> is kept as a data store only.
  state._replayUndoStack = [];
  state._replayRedoStack = [];
  state._replayLastSnapshot = null;

  els.replayRequestHighlight.addEventListener("input", () => {
    if (state.replayMessageViews.request === "hex") return;
    const tab = getActiveReplayTab();
    if (!tab) return;
    const text = els.replayRequestHighlight.innerText || "";
    if (state._replayLastSnapshot !== null && state._replayLastSnapshot !== text) {
      state._replayUndoStack.push(state._replayLastSnapshot);
      if (state._replayUndoStack.length > 200) state._replayUndoStack.shift();
      state._replayRedoStack.length = 0;
    }
    state._replayLastSnapshot = text;
    els.replayRequestEditor.value = text;
    tab.requestText = text;
    // Debounce re-render so syntax highlighting refreshes without losing cursor
    clearTimeout(els.replayRequestHighlight._renderTimer);
    els.replayRequestHighlight._renderTimer = setTimeout(() => {
      replayHighlightRerender(text);
    }, 400);
    updateReplaySearchPane("request", text);
    syncReplayToolbar(tab);
    renderReplayTabs();
    scheduleWorkspaceStateSave();
  });
  els.replayRequestHighlight.addEventListener("keydown", (e) => {
    if (state.replayMessageViews.request === "hex") return;
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "z" && !e.altKey) {
      e.preventDefault();
      const stack = e.shiftKey ? state._replayRedoStack : state._replayUndoStack;
      const opposite = e.shiftKey ? state._replayUndoStack : state._replayRedoStack;
      if (!stack.length) return;
      opposite.push(state._replayLastSnapshot || els.replayRequestHighlight.innerText || "");
      const restored = stack.pop();
      state._replayLastSnapshot = restored;
      let undoHtml = renderCodeHtml(restored, state.replayMessageViews.request, "request");
      els.replayRequestHighlight.innerHTML = undoHtml;
      // Clamp caret to beginning of text after undo — avoids jumping to trailing whitespace
      const maxOffset = restored.length;
      const savedCaret = saveContentEditableCaret(els.replayRequestHighlight);
      const clampedPos = savedCaret
        ? { start: Math.min(savedCaret.start, maxOffset), end: Math.min(savedCaret.end, maxOffset) }
        : { start: 0, end: 0 };
      restoreContentEditableCaret(els.replayRequestHighlight, clampedPos);
      els.replayRequestEditor.value = restored;
      const tab = getActiveReplayTab();
      if (tab) tab.requestText = restored;
      updateReplaySearchPane("request", restored);
      syncReplayToolbar(tab);
      renderReplayTabs();
      scheduleWorkspaceStateSave();
    }
  });
  els.replayRequestHighlight.addEventListener("paste", (e) => {
    e.preventDefault();
    const text = e.clipboardData.getData("text/plain");
    document.execCommand("insertText", false, text);
  });
  els.replayRequestHighlight.addEventListener("contextmenu", showReplayContextMenu);
  initReplayContextMenu();
  // Replay Pretty/Raw/Hex view tabs
  document.querySelectorAll(".replay-view-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.replayTarget;
      const view = btn.dataset.replayView;
      state.replayMessageViews[target] = view;
      renderReplayViewTabs();
      renderReplayViewContent(target);
    });
  });

  bindWsReplayEvents();
  bindFindingsEvents();

  // OAST
  const oastProviderSelect = document.getElementById("proxySettingOastProvider");
  if (oastProviderSelect) {
    oastProviderSelect.addEventListener("change", () => renderProxySettings());
  }
  if (els.oastGenerateButton) {
    els.oastGenerateButton.addEventListener("click", () => {
      generateOastPayload().catch(console.error);
    });
  }
  if (els.oastClearButton) {
    els.oastClearButton.addEventListener("click", () => {
      clearOastCallbacks().catch(console.error);
    });
  }
  if (els.oastCopyPayloadButton) {
    els.oastCopyPayloadButton.addEventListener("click", () => {
      const text = els.oastPayloadText?.value;
      if (text) { copyTextToClipboard(text); showToast("Copied OAST payload"); }
    });
  }
  if (els.oastTableBody) {
    els.oastTableBody.addEventListener("click", (event) => {
      const row = event.target.closest("tr[data-oast-id]");
      if (!row) return;
      state.selectedOastId = row.dataset.oastId;
      loadOastDetail(row.dataset.oastId).catch(console.error);
      renderOastCallbacks();
    });
  }
  els.replaySchemeSelect.addEventListener("change", () => {
    applyReplayTargetFields().catch((error) => console.error(error));
  });
  document.getElementById("replayHttpVersionSelect")?.addEventListener("change", (e) => {
    const ver = e.target.value;
    if (!ver) return; // "Auto" selected — don't modify request text
    const hl = els.replayRequestHighlight;
    if (!hl) return;
    const text = hl.innerText || "";
    const lines = text.split("\n");
    if (lines.length > 0) {
      // Replace HTTP version in first line: "GET /path HTTP/1.1" → "GET /path HTTP/2"
      lines[0] = lines[0].replace(/\s+HTTP\/[0-9.]+\s*$/i, ` ${ver}`);
      if (!lines[0].match(/HTTP\//i)) lines[0] += ` ${ver}`;
      const newText = lines.join("\n");
      hl.innerText = newText;
      hl.dispatchEvent(new Event("input"));
    }
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
  els.interceptResponseEditor.addEventListener("input", () => {
    if (state.selectedResponseInterceptRecord) {
      state.responseInterceptEditorSeedId = state.selectedResponseInterceptRecord.id;
    }
    renderInterceptResponseHighlight(els.interceptResponseEditor.value);
  });
  els.interceptResponseEditor.addEventListener("scroll", () => {
    els.interceptResponseHighlight.scrollTop = els.interceptResponseEditor.scrollTop;
    els.interceptResponseHighlight.scrollLeft = els.interceptResponseEditor.scrollLeft;
  });

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

    // Cmd+1~6: color tag selected HTTP item
    if (
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      state.activeTool === "proxy" &&
      state.activeProxyTab === "http-history" &&
      state.selectedId &&
      event.key >= "1" && event.key <= "6"
    ) {
      event.preventDefault();
      const colors = ["red", "orange", "yellow", "green", "blue", "purple"];
      const color = colors[parseInt(event.key) - 1];
      const item = state.items.find((i) => i.id === state.selectedId);
      const newColor = item?.color_tag === color ? null : color;
      if (item) item.color_tag = newColor;
      invalidateVisibleEntriesCache();
      renderHistory();
      updateAnnotations(state.selectedId, { color_tag: newColor });
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
        if (event.key === "Escape" && state.wsKeyboardFocus === "frames") {
          event.preventDefault();
          state.wsKeyboardFocus = "sessions";
          hideFrameDetail();
          return;
        }

        if (event.key === "ArrowUp") {
          event.preventDefault();
          if (state.wsKeyboardFocus === "frames") {
            moveFrameSelection(-1);
          } else {
            moveWebsocketSelection(-1).catch((error) => console.error(error));
          }
          return;
        }

        if (event.key === "ArrowDown") {
          event.preventDefault();
          if (state.wsKeyboardFocus === "frames") {
            moveFrameSelection(1);
          } else {
            moveWebsocketSelection(1).catch((error) => console.error(error));
          }
          return;
        }
      }
    }

    // Arrow keys in Dashboard: navigate session rows
    if (
      !event.metaKey &&
      !event.ctrlKey &&
      !event.altKey &&
      !event.shiftKey &&
      state.activeTool === "dashboard" &&
      !isEditableTarget(event.target)
    ) {
      if (event.key === "ArrowUp") {
        event.preventDefault();
        moveSessionSelection(-1);
        return;
      }
      if (event.key === "ArrowDown") {
        event.preventDefault();
        moveSessionSelection(1);
        return;
      }
    }

    // Arrow keys in WS Replay: navigate frames
    if (
      (event.key === "ArrowUp" || event.key === "ArrowDown") &&
      !event.metaKey && !event.ctrlKey && !event.altKey && !event.shiftKey &&
      state.activeTool === "replay" &&
      !isEditableTarget(event.target)
    ) {
      const tab = state.replayTabs.find(t => t.id === state.activeReplayTabId);
      if (tab && tab.type === "websocket" && tab.wsFrames.length > 0) {
        event.preventDefault();
        const cur = tab.wsSelectedFrameIndex ?? -1;
        const next = event.key === "ArrowDown"
          ? Math.min(cur + 1, tab.wsFrames.length - 1)
          : Math.max(cur - 1, 0);
        tab.wsSelectedFrameIndex = next;
        els.wsFrameList.querySelectorAll(".ws-frame-bubble").forEach(b => b.classList.remove("selected"));
        const target = els.wsFrameList.querySelector(`[data-frame-index="${next}"]`);
        if (target) { target.classList.add("selected"); target.scrollIntoView({ block: "nearest" }); }
        renderWsFrameDetail();
        return;
      }
    }

    // Ctrl+Tab / Ctrl+Shift+Tab: cycle through Replay tabs
    if (
      event.ctrlKey &&
      !event.metaKey &&
      !event.altKey &&
      event.key === "Tab" &&
      state.activeTool === "replay" &&
      state.replayTabs.length > 1
    ) {
      event.preventDefault();
      const visualOrder = getReplayTabVisualOrder();
      const idx = visualOrder.findIndex((t) => t.id === state.activeReplayTabId);
      const len = visualOrder.length;
      const next = event.shiftKey ? (idx - 1 + len) % len : (idx + 1) % len;
      state.activeReplayTabId = visualOrder[next].id;
      scheduleWorkspaceStateSave();
      renderReplay();
      return;
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

    // Cmd+R on WebSocket tab — send selected frame to WS Replay
    if (
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "r" &&
      state.activeTool === "proxy" &&
      state.activeProxyTab === "websockets-history" &&
      state.selectedWebsocketRecord
    ) {
      event.preventDefault();
      sendWsFrameToReplay(state.selectedFrameIdx ?? 0);
    }

    // Cmd+R on Findings tab — send selected finding to Replay
    if (
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "r" &&
      state.activeTool === "proxy" &&
      state.activeProxyTab === "findings"
    ) {
      const recordId = els.findingsDetailJump?.dataset.recordId;
      if (recordId) {
        event.preventDefault();
        sendFindingToReplay(recordId).catch((error) => console.error(error));
      }
    }

    if (
      event.metaKey &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "i"
    ) {
      if (state.activeTool === "proxy" && state.activeProxyTab === "http-history" && state.selectedId) {
        event.preventDefault();
        openFuzzerFromSelection().catch(console.error);
      } else if (state.activeTool === "replay" && state.activeReplayTabId) {
        event.preventDefault();
        openFuzzerFromReplay().catch(console.error);
      }
    }

    // Cmd+Shift+F: send to Fuzzer (with content if in HTTP history or Replay)
    if (
      (event.metaKey || event.ctrlKey) &&
      event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "f"
    ) {
      event.preventDefault();
      if (state.activeTool === "proxy" && state.activeProxyTab === "http-history" && state.selectedId) {
        openFuzzerFromSelection().catch(console.error);
      } else if (state.activeTool === "replay" && state.activeReplayTabId) {
        openFuzzerFromReplay().catch(console.error);
      } else {
        state.activeTool = "fuzzer";
        renderToolPanels();
      }
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
  // WS Handshake scroll sync
  if (els.wsHandshakeLines) {
    bindCodePaneScroll(els.websocketRequestView, els.wsHandshakeLines);
    bindCodePaneScroll(els.websocketResponseView, els.wsHandshakeLines);
  }
  // WS Handshake search
  if (els.wsHandshakeSearchInput) {
    els.wsHandshakeSearchInput.addEventListener("input", () => {
      updateWsHandshakeSearch();
    });
    initSearchHitNavigation(els.wsHandshakeSearchMeta, () => {
      const resBtn = document.getElementById("wsHandshakeResBtn");
      return resBtn?.classList.contains("active") ? els.websocketResponseView : els.websocketRequestView;
    });
  }
  bindMessagePaneActivation();
  bindPaneResizer(els.requestResponseResizer, "request-response");
  bindPaneResizer(els.responseInspectorResizer, "response-inspector");
  bindWorkbenchStackResizer(els.historyWorkbenchResizer);
  bindWebsocketPaneResizer(els.websocketSplitResizer);
  bindWebsocketStackResizer(els.websocketStackResizer);
  bindHistoryColumnResizers();
  applyWsColumnWidths();
  bindWsColumnResizers();

  // WS Handshake Request/Response tab toggle
  const wsReqBtn = document.getElementById("wsHandshakeReqBtn");
  const wsResBtn = document.getElementById("wsHandshakeResBtn");
  if (wsReqBtn && wsResBtn) {
    wsReqBtn.addEventListener("click", () => {
      wsReqBtn.classList.add("active");
      wsResBtn.classList.remove("active");
      els.websocketRequestView.classList.remove("hidden");
      els.websocketResponseView.classList.add("hidden");
      updateWsHandshakeLineNumbers();
      updateWsHandshakeSearch();
    });
    wsResBtn.addEventListener("click", () => {
      wsResBtn.classList.add("active");
      wsReqBtn.classList.remove("active");
      els.websocketResponseView.classList.remove("hidden");
      els.websocketRequestView.classList.add("hidden");
      updateWsHandshakeLineNumbers();
      updateWsHandshakeSearch();
    });
  }

  // WS pane swap button
  const wsSwapBtn = document.getElementById("wsSwapPanes");
  if (wsSwapBtn && els.websocketWorkbench) {
    wsSwapBtn.addEventListener("click", () => {
      els.websocketWorkbench.classList.toggle("ws-swapped");
    });
  }

  window.addEventListener("resize", () => {
    normalizeWorkbenchPaneWidths();
    normalizeWebsocketPaneWidth();
    normalizeWorkbenchStackHeight();
  });

  // Event delegation for history table rows (Phase 1 perf optimization)
  els.historyTableBody.addEventListener("click", (event) => {
    const row = event.target.closest(".history-row");
    if (!row || !row.dataset.id) return;
    const id = row.dataset.id;
    state.selectedId = id;
    updateHistorySelection(id);
    scrollSelectedHistoryRowIntoView();
    loadTransactionDetail(id).catch((error) => console.error(error));
  });
  els.historyTableBody.addEventListener("contextmenu", (event) => {
    const row = event.target.closest(".history-row");
    if (!row || !row.dataset.id) return;
    event.preventDefault();
    const id = row.dataset.id;
    state.selectedId = id;
    updateHistorySelection(id);
    openContextMenu(event.clientX, event.clientY, id);
  });
}

async function loadSettings(retries = 5) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const response = await fetch("/api/settings");
      if (!response.ok) {
        throw new Error(`loadSettings failed: ${response.status}`);
      }
      return await _applySettings(response);
    } catch (err) {
      if (attempt < retries) {
        await new Promise((r) => setTimeout(r, 300 * (attempt + 1)));
        continue;
      }
      throw err;
    }
  }
}

async function _applySettings(response) {
  state.settings = await response.json();
  state.runtime = state.settings.runtime;
  state.activeSession = state.settings.active_session;
  // Sync intercept scope pill with server state
  const interceptScopePill = document.getElementById("interceptInScopeToggle");
  if (interceptScopePill) {
    const scopeOnly = state.runtime?.intercept_scope_only ?? true;
    interceptScopePill.classList.toggle("active", scopeOnly);
    state.interceptInScopeOnly = scopeOnly;
  }

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

  if (state.appVersion.update_available) {
    els.openUpdateButton.title = state.appVersion.latest_version
      ? `Update to ${state.appVersion.latest_version}`
      : "Update available";
    els.openUpdateButton.classList.remove("hidden");
  } else {
    els.openUpdateButton.classList.add("hidden");
  }
}

async function performSelfUpdate() {
  if (els.openUpdateButton.disabled) return;
  els.openUpdateButton.disabled = true;

  // Show inline progress bar
  els.openUpdateButton.innerHTML =
    '<span class="update-label">Updating...</span>' +
    '<span class="update-bar"><span class="update-bar-fill"></span></span>';

  const fill = els.openUpdateButton.querySelector(".update-bar-fill");
  const label = els.openUpdateButton.querySelector(".update-label");

  const es = new EventSource("/api/self-update");
  es.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.step.startsWith("error:")) {
        es.close();
        label.textContent = "Update failed";
        fill.style.width = "0%";
        els.openUpdateButton.disabled = false;
        setTimeout(() => {
          els.openUpdateButton.textContent = "Update";
        }, 3000);
        console.error("Self-update failed:", data.step);
        return;
      }
      if (data.percent != null) {
        fill.style.width = data.percent + "%";
        const mb = (data.downloaded / 1048576).toFixed(1);
        const totalMb = (data.total / 1048576).toFixed(1);
        label.textContent = `${mb} / ${totalMb} MB`;
      } else {
        label.textContent = data.step;
        if (data.step === "Installing update...") fill.style.width = "90%";
        if (data.step === "Restarting...") fill.style.width = "100%";
      }
    } catch (_) {}
  };
  es.onerror = () => {
    es.close();
    // Connection lost probably means the app is restarting — that's OK
    label.textContent = "Restarting...";
    fill.style.width = "100%";
  };
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
  state.fuzzerRequestText = (fuzzerWS.request_text || "").trimEnd();
  state.fuzzerPayloadsText = fuzzerWS.payloads_text || "";
  state.fuzzerAttackRecord = fuzzerWS.attack_record || null;
}

function hydrateReplayTab(tab) {
  if (!tab || typeof tab !== "object") {
    return null;
  }

  if (tab.type === "websocket") {
    return {
      id: typeof tab.id === "string" && tab.id ? tab.id : crypto.randomUUID(),
      type: "websocket",
      sequence: Number.isFinite(tab.sequence) ? tab.sequence : state.replayTabSequence + 1,
      pinned: !!tab.pinned,
      label: `WS ${tab.ws_host || "draft"}`,
      wsScheme: tab.ws_scheme || "wss",
      wsHost: tab.ws_host || "",
      wsPort: tab.ws_port || 443,
      wsPath: tab.ws_path || "/",
      wsHeaders: tab.ws_headers || [],
      wsHandshakeText: tab.ws_handshake_text || "",
      wsSetupQueue: Array.isArray(tab.ws_setup_queue)
        ? tab.ws_setup_queue.map((item) => ({
            label: item.label || "",
            body: item.body || "",
            autoSend: !!item.autoSend,
          }))
        : [],
      wsStatus: "disconnected",
      wsFrames: [],
      wsSelectedFrameIndex: -1,
      wsEditorText: "",
      wsError: null,
      wsPollTimer: null,
    };
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
    pinned: !!tab.pinned,
    baseRequest: fallbackRequest,
    sourceTransactionId: tab.source_transaction_id || null,
    notice: tab.notice || "",
    requestText: (tab.request_text || buildEditableRawRequest(fallbackRequest)).trimEnd(),
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
    requestText: (entry.request_text || buildEditableRawRequest(request)).trimEnd(),
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
      tabs: state.replayTabs.map((tab) => {
        if (tab.type === "websocket") {
          return {
            id: tab.id,
            type: "websocket",
            sequence: tab.sequence,
            pinned: !!tab.pinned,
            ws_scheme: tab.wsScheme || "wss",
            ws_host: tab.wsHost || "",
            ws_port: tab.wsPort || 443,
            ws_path: tab.wsPath || "/",
            ws_headers: tab.wsHeaders || [],
            ws_handshake_text: tab.wsHandshakeText || "",
            ws_setup_queue: (tab.wsSetupQueue || []).map((item) => ({
              label: item.label || "",
              body: item.body || "",
              autoSend: !!item.autoSend,
            })),
          };
        }
        return {
          id: tab.id,
          sequence: tab.sequence,
          pinned: !!tab.pinned,
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
        };
      }),
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
  state.responseIntercepts = [];
  state.selectedInterceptId = null;
  state.selectedInterceptRecord = null;
  state.selectedResponseInterceptId = null;
  state.selectedResponseInterceptRecord = null;
  state.responseInterceptEditorSeedId = null;
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
  state.replayTabs.forEach((tab) => {
    if (tab.type === "websocket") stopWsPoll(tab);
  });
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
  await loadResponseIntercepts(false);
  await loadWebsockets(false);
  await loadEventLog();
  await loadMatchReplaceRules();
  await loadSequences();
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
  const response = await fetch("/api/transactions?limit=0");
  const freshItems = await response.json();

  // Preserve in-flight annotation changes (optimistic updates)
  if (state._pendingAnnotations) {
    for (const [id, patch] of state._pendingAnnotations) {
      const item = freshItems.find((i) => i.id === id);
      if (item) Object.assign(item, patch);
    }
  }
  state.items = freshItems;
  invalidateVisibleEntriesCache();

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
  updateInterceptQueueBadges();
  // Auto-switch to Request Queue when requests arrive and Response Queue is empty
  if (state.intercepts.length > 0 && state.responseIntercepts.length === 0 && state.interceptQueueTab === "response") {
    switchInterceptQueueTab("request");
  }
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

/* ─── Intercept Rules ─── */

async function loadInterceptRules() {
  const response = await fetch("/api/intercept-rules");
  state.interceptRules = await response.json();
  renderInterceptRules();
}

function renderInterceptRules() {
  const container = document.getElementById("interceptRulesList");
  if (!container) return;
  const rules = state.interceptRules || [];
  if (!rules.length) {
    container.innerHTML = `<div class="intercept-rules-empty">No rules — all in-scope requests &amp; responses will be intercepted.</div>`;
    return;
  }
  container.innerHTML = rules.map((rule) => {
    const methods = rule.method_filter?.length ? rule.method_filter.join(", ") : "Any";
    const host = rule.host_pattern || "*";
    const path = rule.path_pattern || "*";
    const scope = rule.scope || "request";
    const scopeLabel = scope === "both" ? "Req+Res" : scope === "response" ? "Res" : "Req";
    return `<div class="intercept-rule-row${rule.enabled ? "" : " disabled"}" data-rule-id="${rule.id}">
      <label class="intercept-rule-toggle" title="Enable/disable">
        <input type="checkbox" ${rule.enabled ? "checked" : ""} data-rule-toggle="${rule.id}" />
      </label>
      <span class="intercept-rule-scope">${escapeHtml(scopeLabel)}</span>
      <span class="intercept-rule-methods">${escapeHtml(methods)}</span>
      <span class="intercept-rule-host">${escapeHtml(host)}</span>
      <span class="intercept-rule-path">${escapeHtml(path)}</span>
      <button class="intercept-rule-delete" data-rule-delete="${rule.id}" title="Delete rule">&times;</button>
    </div>`;
  }).join("");
}

async function addInterceptRule() {
  const rule = {
    id: crypto.randomUUID(),
    enabled: true,
    scope: "request",
    host_pattern: "",
    path_pattern: "",
    method_filter: [],
  };
  await fetch("/api/intercept-rules", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(rule),
  });
  await loadInterceptRules();
  editInterceptRule(rule.id);
}

function editInterceptRule(ruleId) {
  const rule = (state.interceptRules || []).find((r) => r.id === ruleId);
  if (!rule) return;
  const container = document.getElementById("interceptRulesList");
  const row = container.querySelector(`[data-rule-id="${ruleId}"]`);
  if (!row) return;
  const scope = rule.scope || "request";
  row.innerHTML = `
    <label class="intercept-rule-toggle"><input type="checkbox" ${rule.enabled ? "checked" : ""} data-rule-toggle="${rule.id}" /></label>
    <select class="intercept-rule-input intercept-rule-scope-select" data-field="scope">
      <option value="request"${scope === "request" ? " selected" : ""}>Request</option>
      <option value="response"${scope === "response" ? " selected" : ""}>Response</option>
      <option value="both"${scope === "both" ? " selected" : ""}>Both</option>
    </select>
    <input class="intercept-rule-input" data-field="method_filter" placeholder="Methods (e.g. GET,POST)" value="${escapeHtml((rule.method_filter || []).join(", "))}" />
    <input class="intercept-rule-input" data-field="host_pattern" placeholder="Host (e.g. *.example.com)" value="${escapeHtml(rule.host_pattern || "")}" />
    <input class="intercept-rule-input" data-field="path_pattern" placeholder="Path contains (e.g. /api/)" value="${escapeHtml(rule.path_pattern || "")}" />
    <button class="intercept-rule-save" data-rule-save="${rule.id}">&#10003;</button>
    <button class="intercept-rule-delete" data-rule-delete="${rule.id}">&times;</button>
  `;
}

async function saveInterceptRuleFromRow(ruleId) {
  const container = document.getElementById("interceptRulesList");
  const row = container.querySelector(`[data-rule-id="${ruleId}"]`);
  if (!row) return;
  const rule = (state.interceptRules || []).find((r) => r.id === ruleId);
  if (!rule) return;
  const methodInput = row.querySelector('[data-field="method_filter"]');
  const hostInput = row.querySelector('[data-field="host_pattern"]');
  const pathInput = row.querySelector('[data-field="path_pattern"]');
  const scopeInput = row.querySelector('[data-field="scope"]');
  const toggleInput = row.querySelector(`[data-rule-toggle="${ruleId}"]`);
  const updated = {
    id: ruleId,
    enabled: toggleInput?.checked ?? rule.enabled,
    scope: scopeInput?.value || rule.scope || "request",
    host_pattern: hostInput?.value?.trim() || "",
    path_pattern: pathInput?.value?.trim() || "",
    method_filter: (methodInput?.value || "").split(",").map((m) => m.trim().toUpperCase()).filter(Boolean),
  };
  await fetch("/api/intercept-rules", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(updated),
  });
  await loadInterceptRules();
}

async function deleteInterceptRule(ruleId) {
  await fetch(`/api/intercept-rules/${ruleId}`, { method: "DELETE" });
  await loadInterceptRules();
}

async function toggleInterceptRuleEnabled(ruleId, enabled) {
  const rule = (state.interceptRules || []).find((r) => r.id === ruleId);
  if (!rule) return;
  rule.enabled = enabled;
  await fetch("/api/intercept-rules", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(rule),
  });
  await loadInterceptRules();
}

async function loadWebsockets(preserveSelection = true) {
  const response = await fetch("/api/websockets?limit=5000");
  state.websocketSessions = await response.json();
  await syncVisibleWebsocketSelection(preserveSelection);
}

async function loadWebsocketDetail(id) {
  if (state.selectedWebsocketId !== id) {
    hideFrameDetail();
  }
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
    tasks.push(loadResponseIntercepts(true));
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

  if (state.activeTool === "proxy" && state.activeProxyTab === "findings") {
    tasks.push(loadFindings());
  } else {
    // Always update badge count even when not on Findings tab
    tasks.push(updateFindingsBadgeOnly());
  }

  if (state.activeTool === "proxy" && state.activeProxyTab === "oast") {
    tasks.push(loadOastCallbacks());
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
  invalidateVisibleEntriesCache();
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
  const sequenceVisible = state.activeTool === "sequence";
  const targetVisible = state.activeTool === "target";
  const loggerVisible = state.activeTool === "logger";
  els.dashboardShell.classList.toggle("hidden", !dashboardVisible);
  els.proxyShell.classList.toggle("hidden", !proxyVisible);
  els.replayShell.classList.toggle("hidden", !replayVisible);
  els.toolsShell.classList.toggle("hidden", !decoderVisible);
  els.fuzzerShell.classList.toggle("hidden", !fuzzerVisible);
  els.sequenceShell.classList.toggle("hidden", !sequenceVisible);
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
      // Tools load failed
    });
    els.footerMode.textContent = "Tools active";
    return;
  }

  if (fuzzerVisible) {
    renderFuzzer();
    els.footerMode.textContent = "Fuzzer active";
    return;
  }

  if (sequenceVisible) {
    renderSequencePanel();
    els.footerMode.textContent = "Sequence active";
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
}

function syncDecoderToolMeta() {
  const activeTab = document.querySelector("#tabs li.on");
  const activeLabel = activeTab?.textContent?.trim() || "Decoder";
  els.toolsActiveToolTitle.textContent = `${activeLabel} output`;
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
    console.warn("Clipboard paste failed. Paste directly into the input field.");
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
  // Ensure selectedSessionId defaults to active session
  const activeSession = state.activeSession || state.sessions.find((session) => session.active) || null;
  if (!state.selectedSessionId && activeSession) {
    state.selectedSessionId = activeSession.id;
  }
  const current = state.sessions.find((s) => s.id === state.selectedSessionId) || activeSession;
  els.dashboardCurrentSessionName.textContent = current?.name || "No active session";
  const isActive = current?.active || current?.id === activeSession?.id;
  els.dashboardCurrentSessionStatus.textContent = isActive ? "Active" : "Stored";
  els.dashboardCurrentSessionStatus.className = `detail-chip ${isActive ? "active-badge" : "none"}`;
  els.dashboardCurrentSessionPath.textContent = current?.storage_path || "No storage path";
  els.dashboardCurrentSessionRequests.textContent = String(current?.request_count ?? 0);
  els.dashboardCurrentSessionWebsockets.textContent = String(current?.websocket_count ?? 0);
  els.dashboardCurrentSessionEvents.textContent = String(current?.event_count ?? 0);
  els.dashboardCurrentSessionFuzzer.textContent = String(current?.fuzzer_count ?? 0);
  els.dashboardCurrentSessionRules.textContent = String(current?.rule_count ?? 0);
  els.dashboardCurrentSessionCreated.textContent = current ? formatTimestamp(current.created_at) : "-";
  els.dashboardCurrentSessionOpened.textContent = current ? formatTimestamp(current.last_opened_at) : "-";

  // Sort sessions
  const sortedSessions = getSortedSessions();

  // Render sort arrows in headers
  const sessTable = document.getElementById("dashboardSessionsTable");
  if (sessTable) {
    sessTable.querySelectorAll("thead th[data-sort-key]").forEach((th) => {
      const existing = th.querySelector(".sort-arrow");
      if (existing) existing.remove();
      if (th.dataset.sortKey === state.sessionSortKey) {
        const arrow = document.createElement("span");
        arrow.className = "sort-arrow";
        arrow.textContent = state.sessionSortDir === "asc" ? "\u25B2" : "\u25BC";
        th.appendChild(arrow);
      }
    });
  }

  els.dashboardSessionsBody.innerHTML = sortedSessions.length
    ? sortedSessions
        .map((session) => `
          <tr class="history-row ${session.id === state.selectedSessionId ? "selected" : ""}" data-id="${session.id}">
            <td>${escapeHtml(session.name)}</td>
            <td>${session.request_count}</td>
            <td>${session.websocket_count}</td>
            <td>${session.event_count}</td>
            <td>${session.rule_count}</td>
            <td>${escapeHtml(formatTimestamp(session.created_at))}</td>
            <td>${escapeHtml(formatTimestamp(session.last_opened_at))}</td>
            <td>
              <div class="session-actions">
                ${session.active
                  ? `<button class="session-active-badge" type="button" disabled>Active</button>`
                  : `<button class="secondary-action session-open-button" type="button">Open</button>`}
                <button class="session-delete-button" type="button" ${session.active ? "disabled" : ""}>Delete</button>
              </div>
            </td>
          </tr>
        `)
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="8">No sessions are available yet.</td>
        </tr>
      `;

  // Row click = select (update workspace info panel)
  Array.from(els.dashboardSessionsBody.querySelectorAll("tr[data-id]")).forEach((row) => {
    row.addEventListener("click", () => {
      const { id } = row.dataset;
      if (!id) return;
      state.selectedSessionId = id;
      renderDashboard();
    });
  });

  // Activate button = switch session
  Array.from(els.dashboardSessionsBody.querySelectorAll(".session-open-button")).forEach((btn) => {
    btn.addEventListener("click", (event) => {
      event.stopPropagation();
      const row = btn.closest("tr[data-id]");
      if (!row) return;
      const { id } = row.dataset;
      if (!id) return;
      activateSessionById(id).catch((error) => console.error(error));
    });
  });

  // Right-click context menu on session rows
  Array.from(els.dashboardSessionsBody.querySelectorAll("tr[data-id]")).forEach((row) => {
    row.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      const { id } = row.dataset;
      if (!id) return;
      state.selectedSessionId = id;
      renderDashboard();
      showSessionContextMenu(event, id);
    });
  });

  // Delete button
  Array.from(els.dashboardSessionsBody.querySelectorAll(".session-delete-button")).forEach((btn) => {
    btn.addEventListener("click", (event) => {
      event.stopPropagation();
      const row = btn.closest("tr[data-id]");
      if (!row) return;
      const { id } = row.dataset;
      if (!id) return;
      deleteSessionById(id);
    });
  });
}

// ── Session context menu ──
let sessionContextMenuEl = null;

function showSessionContextMenu(event, sessionId) {
  closeSessionContextMenu();
  const session = state.sessions.find((s) => s.id === sessionId);
  if (!session) return;

  const menu = document.createElement("div");
  menu.className = "context-menu session-context-menu";
  menu.innerHTML = `
    <button class="context-menu-item" data-action="folder">Open session folder</button>
    ${session.active ? "" : `<button class="context-menu-item danger" data-action="delete">Delete session</button>`}
  `;
  document.body.appendChild(menu);

  const rect = menu.getBoundingClientRect();
  let x = event.clientX;
  let y = event.clientY;
  if (x + rect.width > window.innerWidth) x = window.innerWidth - rect.width - 4;
  if (y + rect.height > window.innerHeight) y = window.innerHeight - rect.height - 4;
  menu.style.left = `${x}px`;
  menu.style.top = `${y}px`;
  sessionContextMenuEl = menu;

  menu.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-action]");
    if (!btn) return;
    const action = btn.dataset.action;
    if (action === "folder") {
      fetch(`/api/sessions/${encodeURIComponent(sessionId)}/reveal`, { method: "POST" }).catch(console.error);
    } else if (action === "delete") {
      deleteSessionById(sessionId);
    }
    closeSessionContextMenu();
  });
}

function closeSessionContextMenu() {
  if (sessionContextMenuEl) {
    sessionContextMenuEl.remove();
    sessionContextMenuEl = null;
  }
}

document.addEventListener("click", () => closeSessionContextMenu());
document.addEventListener("contextmenu", () => closeSessionContextMenu());

function showConfirmDialog(message, onConfirm) {
  const backdrop = document.createElement("div");
  backdrop.className = "modal-backdrop confirm-dialog-backdrop";
  backdrop.innerHTML = `
    <div class="modal-card" style="width: min(400px, 90%);">
      <div class="modal-header" style="padding: 16px 20px;">
        <h3 style="margin:0; font-size: var(--font-md);">Confirm</h3>
      </div>
      <div class="modal-body" style="padding: 16px 20px;">
        <p style="margin:0; white-space: pre-line; color: var(--text-dim);">${escapeHtml(message)}</p>
      </div>
      <div style="display:flex; justify-content:flex-end; gap:8px; padding: 12px 20px; border-top: 1px solid var(--line);">
        <button class="secondary-action confirm-dialog-cancel" type="button" style="min-height:34px; padding:0 14px; font-size:var(--font-xs);">Cancel</button>
        <button class="danger-action confirm-dialog-ok" type="button" style="min-height:34px; padding:0 14px; font-size:var(--font-xs);">Delete</button>
      </div>
    </div>
  `;
  document.body.appendChild(backdrop);
  const close = () => backdrop.remove();
  backdrop.querySelector(".confirm-dialog-cancel").addEventListener("click", close);
  backdrop.querySelector(".confirm-dialog-ok").addEventListener("click", () => { close(); onConfirm(); });
  backdrop.addEventListener("click", (e) => { if (e.target === backdrop) close(); });
}

async function deleteSessionById(id) {
  const session = state.sessions.find((s) => s.id === id);
  const name = session ? session.name : id;
  showConfirmDialog(`Delete session "${name}"?\nThis will permanently remove all session data.`, async () => {
    try {
      const res = await fetch(`/api/sessions/${encodeURIComponent(id)}`, { method: "DELETE" });
      if (!res.ok) throw new Error(await res.text());
      state.sessions = state.sessions.filter((s) => s.id !== id);
      if (state.selectedSessionId === id) state.selectedSessionId = null;
      renderDashboard();
    } catch (error) {
      console.error("Failed to delete session:", error);
    }
  });
}

function moveSessionSelection(offset) {
  const sortedSessions = getSortedSessions();
  if (!sortedSessions.length) return;
  const currentIndex = sortedSessions.findIndex((s) => s.id === state.selectedSessionId);
  const fallbackIndex = offset > 0 ? 0 : sortedSessions.length - 1;
  const nextIndex = clamp(
    currentIndex === -1 ? fallbackIndex : currentIndex + offset,
    0,
    sortedSessions.length - 1,
  );
  state.selectedSessionId = sortedSessions[nextIndex].id;
  renderDashboard();
  const selectedRow = els.dashboardSessionsBody.querySelector(`tr[data-id="${state.selectedSessionId}"]`);
  if (selectedRow) selectedRow.scrollIntoView({ block: "nearest" });
}

function getSortedSessions() {
  return [...state.sessions].sort((a, b) => {
    const key = state.sessionSortKey || "created_at";
    const dir = state.sessionSortDir || "desc";
    let va = a[key], vb = b[key];
    if (key === "name") {
      va = (va || "").toLowerCase();
      vb = (vb || "").toLowerCase();
      const cmp = va < vb ? -1 : va > vb ? 1 : 0;
      return dir === "asc" ? cmp : -cmp;
    }
    if (key === "last_opened_at" || key === "created_at") {
      va = va ? new Date(va).getTime() : 0;
      vb = vb ? new Date(vb).getTime() : 0;
    }
    if (key === "active") {
      va = va ? 1 : 0;
      vb = vb ? 1 : 0;
    }
    const diff = (va ?? 0) - (vb ?? 0);
    return dir === "asc" ? diff : -diff;
  });
}

// ── Findings (Passive Scanner) ──

let findingsData = [];
let scannerConfigCache = null;
let findingsSortKey = "found_at";
let findingsSortDir = "desc";

const BUILTIN_RULE_LABELS = {
  jwt: "JWT Analysis",
  header: "Security Headers",
  cookie: "Cookie Flags",
  disclosure: "Sensitive Data Exposure",
  cors: "CORS Misconfiguration",
  server: "Server Disclosure",
  error: "Error Messages",
};

let selectedFindingId = null;

async function loadFindings() {
  try {
    const response = await fetch("/api/findings?limit=5000");
    if (!response.ok) return;
    findingsData = await response.json();
    renderFindings();
    updateFindingsBadge();
  } catch (error) {
    console.error("Failed to load findings:", error);
  }
}

async function updateFindingsBadgeOnly() {
  try {
    const response = await fetch("/api/findings?limit=5000");
    if (!response.ok) return;
    findingsData = await response.json();
    updateFindingsBadge();
  } catch (e) { /* silent */ }
}

function updateFindingsBadge() {
  if (!els.findingsBadge) return;
  const count = findingsData.length;
  els.findingsBadge.textContent = count > 0 ? String(count) : "";
  els.findingsBadge.classList.toggle("hidden", count === 0);
}

function severityClass(severity) {
  switch (severity) {
    case "critical": return "severity-critical";
    case "high": return "severity-high";
    case "medium": return "severity-medium";
    case "low": return "severity-low";
    default: return "severity-info";
  }
}

function severityLabel(severity) {
  switch (severity) {
    case "critical": return "Critical";
    case "high": return "High";
    case "medium": return "Medium";
    case "low": return "Low";
    default: return "Info";
  }
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function getFilteredFindings() {
  const sevFilter = els.findingsFilterSeverity ? els.findingsFilterSeverity.value : "";
  const catFilter = els.findingsFilterCategory ? els.findingsFilterCategory.value : "";
  const searchTerm = els.findingsFilterSearch ? els.findingsFilterSearch.value.toLowerCase().trim() : "";
  const inScopeOnly = els.findingsInScopeOnly ? els.findingsInScopeOnly.checked : false;

  let filtered = findingsData.filter((f) => {
    if (inScopeOnly && !isInScopeHost(f.host)) return false;
    if (sevFilter) {
      const threshold = SEVERITY_ORDER[sevFilter] ?? 5;
      const fLevel = SEVERITY_ORDER[f.severity] ?? 5;
      if (fLevel > threshold) return false;
    }
    if (catFilter && f.category !== catFilter) return false;
    if (searchTerm) {
      const haystack = `${f.title} ${f.host} ${f.path} ${f.category}`.toLowerCase();
      if (!haystack.includes(searchTerm)) return false;
    }
    return true;
  });

  // Sort
  const dir = findingsSortDir === "asc" ? 1 : -1;
  filtered.sort((a, b) => {
    let va, vb;
    if (findingsSortKey === "severity") {
      va = SEVERITY_ORDER[a.severity] ?? 5;
      vb = SEVERITY_ORDER[b.severity] ?? 5;
    } else if (findingsSortKey === "found_at") {
      va = a.found_at || "";
      vb = b.found_at || "";
    } else {
      va = (a[findingsSortKey] || "").toLowerCase();
      vb = (b[findingsSortKey] || "").toLowerCase();
    }
    if (va < vb) return -1 * dir;
    if (va > vb) return 1 * dir;
    return 0;
  });

  return filtered;
}

function toggleFindingsSort(key) {
  if (findingsSortKey === key) {
    findingsSortDir = findingsSortDir === "asc" ? "desc" : "asc";
  } else {
    findingsSortKey = key;
    findingsSortDir = key === "severity" ? "asc" : (key === "found_at" ? "desc" : "asc");
  }
  updateFindingsSortHeaders();
  renderFindings();
}

function updateFindingsSortHeaders() {
  document.querySelectorAll(".findings-sortable").forEach((th) => {
    const key = th.dataset.findingsSort;
    const active = key === findingsSortKey;
    th.classList.toggle("active", active);
    const indicator = th.querySelector(".findings-sort-indicator");
    if (indicator) {
      indicator.textContent = active ? (findingsSortDir === "asc" ? "↑" : "↓") : "↕";
    }
  });
}

function updateCategoryFilter() {
  if (!els.findingsFilterCategory) return;
  const current = els.findingsFilterCategory.value;
  const builtinCats = new Set(["jwt", "header", "cookie", "disclosure", "cors", "error"]);
  const extraCats = new Set();
  for (const f of findingsData) {
    if (!builtinCats.has(f.category)) extraCats.add(f.category);
  }
  // Remove old custom options
  Array.from(els.findingsFilterCategory.options).forEach((opt) => {
    if (opt.dataset.custom) opt.remove();
  });
  for (const cat of extraCats) {
    const opt = document.createElement("option");
    opt.value = cat;
    opt.textContent = cat;
    opt.dataset.custom = "1";
    els.findingsFilterCategory.appendChild(opt);
  }
  els.findingsFilterCategory.value = current;
}

function renderFindings() {
  if (!els.findingsBody) return;
  updateCategoryFilter();
  state._findingsEntries = getFilteredFindings();

  if (!state._findingsEntries.length) {
    els.findingsBody.innerHTML = `<tr class="empty-row"><td colspan="6">No findings yet. Browse with the proxy to start scanning.</td></tr>`;
    return;
  }

  renderFindingsVirtual();
}

function renderFindingsVirtual() {
  const entries = state._findingsEntries;
  if (!entries || !entries.length) return;

  const shell = els.findingsBody.closest(".history-table-shell");
  if (!shell) return;

  const scrollTop = shell.scrollTop;
  const viewportHeight = shell.clientHeight;
  const totalCount = entries.length;

  const startIdx = Math.max(0, Math.floor(scrollTop / FINDINGS_ROW_HEIGHT) - FINDINGS_BUFFER_ROWS);
  const endIdx = Math.min(totalCount, Math.ceil((scrollTop + viewportHeight) / FINDINGS_ROW_HEIGHT) + FINDINGS_BUFFER_ROWS);

  const topPadding = startIdx * FINDINGS_ROW_HEIGHT;
  const bottomPadding = Math.max(0, (totalCount - endIdx) * FINDINGS_ROW_HEIGHT);

  const rows = [];
  for (let i = startIdx; i < endIdx; i++) {
    const f = entries[i];
    const selected = f.id === selectedFindingId ? " selected" : "";
    rows.push(`<tr class="history-row${selected}" data-finding-id="${f.id}" data-record-id="${f.record_id}">
      <td class="findings-col-severity"><span class="severity-badge ${severityClass(f.severity)}">${severityLabel(f.severity)}</span></td>
      <td class="findings-col-category"><span class="detail-chip">${escapeHtml(f.category)}</span></td>
      <td class="findings-col-title">${escapeHtml(f.title)}</td>
      <td class="findings-col-host">${escapeHtml(f.host)}</td>
      <td class="findings-col-path">${escapeHtml(f.path)}</td>
      <td class="findings-col-time">${escapeHtml(formatTimestamp(f.found_at))}</td>
    </tr>`);
  }

  els.findingsBody.innerHTML =
    (topPadding > 0 ? `<tr class="virtual-spacer"><td colspan="6" style="height:${topPadding}px;padding:0;border:none"></td></tr>` : "") +
    rows.join("") +
    (bottomPadding > 0 ? `<tr class="virtual-spacer"><td colspan="6" style="height:${bottomPadding}px;padding:0;border:none"></td></tr>` : "");
}

async function loadFindingDetail(id) {
  try {
    const res = await fetch(`/api/findings/${encodeURIComponent(id)}`);
    if (!res.ok) return;
    const finding = await res.json();
    // Also fetch the transaction record for request/response
    let record = null;
    try {
      const tRes = await fetch(`/api/transactions/${encodeURIComponent(finding.record_id)}`);
      if (tRes.ok) record = await tRes.json();
    } catch (_) { /* silent */ }
    showFindingDetail(finding, record);
  } catch (error) {
    console.error("Failed to load finding detail:", error);
  }
}

function showFindingDetail(finding, record) {
  if (!els.findingsDetailPanel) return;
  if (els.findingsDetailPlaceholder) els.findingsDetailPlaceholder.classList.add("hidden");
  if (els.findingsDetailContent) els.findingsDetailContent.classList.remove("hidden");

  // Header info
  els.findingsDetailSeverity.className = `severity-badge ${severityClass(finding.severity)}`;
  els.findingsDetailSeverity.textContent = severityLabel(finding.severity);
  els.findingsDetailCategory.textContent = finding.category;
  els.findingsDetailTitle.textContent = finding.title;

  // Description + evidence
  els.findingsDetailDesc.innerHTML = `<span class="findings-desc-text">${escapeHtml(finding.detail)}</span>`;

  // Jump button — store record_id
  els.findingsDetailJump.dataset.recordId = finding.record_id;

  // Render request/response with highlight
  const evidence = finding.evidence || "";
  if (record) {
    const reqText = buildFindingsRawMessage(record, "request");
    const resText = buildFindingsRawMessage(record, "response");
    renderFindingsCodePane(els.findingsReqView, els.findingsReqLines, reqText, evidence, "request", finding);
    renderFindingsCodePane(els.findingsResView, els.findingsResLines, resText, evidence, "response", finding);
  } else {
    els.findingsReqView.innerHTML = '<span class="code-line code-line-empty">Transaction not available.</span>';
    els.findingsReqLines.textContent = "";
    els.findingsResView.innerHTML = '<span class="code-line code-line-empty">Transaction not available.</span>';
    els.findingsResLines.textContent = "";
  }
}

function renderFindingsCodePane(viewEl, lineEl, text, evidence, target, finding) {
  if (!text) {
    viewEl.innerHTML = '<span class="code-line code-line-empty">&nbsp;</span>';
    lineEl.textContent = "";
    return;
  }
  const html = renderHttpHtml(text, target);
  viewEl.innerHTML = html;
  lineEl.textContent = buildLineNumbers(countLines(text));
  if (window._enableReadonlyCaret) window._enableReadonlyCaret(viewEl);

  // Highlight evidence — line background + inline mark
  highlightFindingLines(viewEl, evidence, finding);

  // Clear search when new finding is loaded
  const isReq = (viewEl === els.findingsReqView);
  const searchInput = isReq ? els.findingsReqSearchInput : els.findingsResSearchInput;
  const searchMeta = isReq ? els.findingsReqSearchMeta : els.findingsResSearchMeta;
  if (searchInput) searchInput.value = "";
  if (searchMeta) searchMeta.innerHTML = buildSearchMeta(countLines(text), "raw", 0);

  // Scroll sync
  viewEl.addEventListener("scroll", () => { lineEl.scrollTop = viewEl.scrollTop; });
}

function highlightFindingLines(container, evidence, finding) {
  const codeLines = container.querySelectorAll(".code-line");
  let scrollTarget = null;

  // 1) If evidence exists, highlight lines containing the evidence text
  if (evidence && evidence.length >= 3) {
    const escapedEvidence = evidence.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    let pattern;
    try { pattern = new RegExp(`(${escapedEvidence})`, "gi"); } catch (_) { pattern = null; }

    if (pattern) {
      codeLines.forEach((line) => {
        pattern.lastIndex = 0;
        if (pattern.test(line.textContent)) {
          line.classList.add("findings-line-hit");
          if (!scrollTarget) scrollTarget = line;

          // Also inline-mark the exact text
          const walker = document.createTreeWalker(line, NodeFilter.SHOW_TEXT, null);
          const textNodes = [];
          while (walker.nextNode()) textNodes.push(walker.currentNode);
          textNodes.forEach((node) => {
            const txt = node.nodeValue;
            pattern.lastIndex = 0;
            if (!pattern.test(txt)) return;
            pattern.lastIndex = 0;
            const frag = document.createDocumentFragment();
            let lastIdx = 0;
            let m;
            while ((m = pattern.exec(txt)) !== null) {
              if (m.index > lastIdx) frag.appendChild(document.createTextNode(txt.slice(lastIdx, m.index)));
              const mark = document.createElement("mark");
              mark.className = "findings-highlight";
              mark.textContent = m[1];
              frag.appendChild(mark);
              lastIdx = pattern.lastIndex;
            }
            if (lastIdx < txt.length) frag.appendChild(document.createTextNode(txt.slice(lastIdx)));
            node.parentNode.replaceChild(frag, node);
          });
        }
      });
    }
  }

  // 2) For "missing" findings (no evidence), highlight related header lines
  if (!scrollTarget && finding) {
    const keywords = extractFindingKeywords(finding);
    if (keywords.length) {
      codeLines.forEach((line) => {
        const text = line.textContent.toLowerCase();
        if (keywords.some((kw) => text.includes(kw))) {
          line.classList.add("findings-line-related");
          if (!scrollTarget) scrollTarget = line;
        }
      });
    }
  }

  // Scroll to first highlighted line
  if (scrollTarget) {
    setTimeout(() => scrollTarget.scrollIntoView({ block: "center", behavior: "smooth" }), 50);
  }
}

function extractFindingKeywords(finding) {
  const title = (finding.title || "").toLowerCase();
  const keywords = [];

  // Missing header findings → highlight related headers
  if (title.includes("content-security-policy")) keywords.push("content-security-policy");
  if (title.includes("strict-transport-security")) keywords.push("strict-transport-security");
  if (title.includes("x-content-type-options")) keywords.push("x-content-type-options");
  if (title.includes("x-frame-options")) keywords.push("x-frame-options", "frame-ancestors");
  if (title.includes("httponly")) keywords.push("set-cookie", "httponly");
  if (title.includes("secure flag")) keywords.push("set-cookie", "secure");
  if (title.includes("samesite")) keywords.push("set-cookie", "samesite");
  if (title.includes("cors")) keywords.push("access-control-allow-origin", "access-control-allow-credentials");
  if (title.includes("server version")) keywords.push("server:", "x-powered-by:");
  if (title.includes("jwt")) keywords.push("authorization:", "bearer");
  if (title.includes("cookie") && !keywords.length) keywords.push("set-cookie", "cookie");

  return keywords;
}

function jumpToTransaction(recordId) {
  state.activeProxyTab = "http-history";
  state.selectedId = recordId;
  renderProxyPanels();
  loadTransactionDetail(recordId).then(() => {
    const row = document.querySelector(`.history-row[data-id="${recordId}"]`);
    if (row) {
      updateHistorySelection(recordId);
      row.scrollIntoView({ block: "center", behavior: "smooth" });
    }
  }).catch((error) => console.error(error));
}

async function sendFindingToReplay(recordId) {
  const response = await fetch(`/api/transactions/${recordId}`);
  if (!response.ok) return;
  const record = await response.json();
  if (!record || record.kind === "tunnel") return;
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

async function sendFindingToFuzzer(recordId) {
  const response = await fetch(`/api/transactions/${recordId}`);
  if (!response.ok) return;
  const record = await response.json();
  if (!record || record.kind === "tunnel") return;
  const request = editableRequestFromRecord(record);
  state.fuzzerBaseRequest = request;
  state.fuzzerSourceTransactionId = record.id;
  state.fuzzerRequestText = buildEditableRawRequest(request);
  state.fuzzerNotice = record.request.preview_truncated ? buildTruncatedBodyNotice(record, "Fuzzer") : "";
  state.activeTool = "fuzzer";
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

// ── Scanner Settings Modal ──

async function loadScannerConfig() {
  try {
    const res = await fetch("/api/scanner-config");
    if (!res.ok) return null;
    scannerConfigCache = await res.json();
    return scannerConfigCache;
  } catch (e) {
    console.error("Failed to load scanner config:", e);
    return null;
  }
}

async function saveScannerConfig(config) {
  try {
    await fetch("/api/scanner-config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(config),
    });
    scannerConfigCache = config;
  } catch (e) {
    console.error("Failed to save scanner config:", e);
  }
}

async function openScannerSettings() {
  const config = await loadScannerConfig();
  if (!config) return;

  // Render built-in rules
  els.scannerBuiltinRules.innerHTML = Object.entries(BUILTIN_RULE_LABELS)
    .map(([id, label]) => {
      const checked = config.rules[id] !== false ? "checked" : "";
      return `<div class="scanner-rule-item">
        <label><input type="checkbox" data-rule-id="${id}" ${checked} /> ${escapeHtml(label)}</label>
      </div>`;
    })
    .join("");

  // Render custom rules
  renderCustomRulesEditor(config.custom_rules || []);

  els.scannerSettingsBackdrop.classList.remove("hidden");
}

function renderCustomRulesEditor(customRules) {
  els.scannerCustomRules.innerHTML = customRules
    .map((rule, idx) => `
      <div class="scanner-custom-rule-card" data-custom-idx="${idx}">
        <div class="scanner-custom-rule-header">
          <label><input type="checkbox" class="custom-rule-enabled" ${rule.enabled ? "checked" : ""} /></label>
          <input type="text" class="custom-rule-name" value="${escapeHtml(rule.name)}" placeholder="Rule name" style="margin: 0 6px;" />
          <button class="secondary-action scanner-custom-rule-delete" type="button" data-del-idx="${idx}">&times;</button>
        </div>
        <div class="scanner-custom-rule-fields">
          <select class="custom-rule-target">
            <option value="response_body" ${rule.target === "response_body" ? "selected" : ""}>Response Body</option>
            <option value="response_header" ${rule.target === "response_header" ? "selected" : ""}>Response Header</option>
            <option value="request_header" ${rule.target === "request_header" ? "selected" : ""}>Request Header</option>
          </select>
          <input type="text" class="custom-rule-header-name" value="${escapeHtml(rule.header_name || "")}" placeholder="Header name (optional)" />
          <input type="text" class="custom-rule-pattern scanner-custom-rule-fullrow" value="${escapeHtml(rule.pattern)}" placeholder="Regex pattern" />
          <select class="custom-rule-severity">
            <option value="critical" ${rule.severity === "critical" ? "selected" : ""}>Critical</option>
            <option value="high" ${rule.severity === "high" ? "selected" : ""}>High</option>
            <option value="medium" ${rule.severity === "medium" ? "selected" : ""}>Medium</option>
            <option value="low" ${rule.severity === "low" ? "selected" : ""}>Low</option>
            <option value="info" ${rule.severity === "info" ? "selected" : ""}>Info</option>
          </select>
          <input type="text" class="custom-rule-category" value="${escapeHtml(rule.category)}" placeholder="Category" />
          <input type="text" class="custom-rule-description scanner-custom-rule-fullrow" value="${escapeHtml(rule.description)}" placeholder="Description" />
        </div>
      </div>
    `)
    .join("");

  // Delete button events
  els.scannerCustomRules.querySelectorAll(".scanner-custom-rule-delete").forEach((btn) => {
    btn.addEventListener("click", () => {
      const rules = collectCustomRulesFromEditor();
      rules.splice(parseInt(btn.dataset.delIdx, 10), 1);
      renderCustomRulesEditor(rules);
    });
  });
}

function collectCustomRulesFromEditor() {
  const cards = els.scannerCustomRules.querySelectorAll(".scanner-custom-rule-card");
  return Array.from(cards).map((card, idx) => ({
    id: `custom_${idx}_${Date.now()}`,
    enabled: card.querySelector(".custom-rule-enabled").checked,
    name: card.querySelector(".custom-rule-name").value.trim() || `Custom Rule ${idx + 1}`,
    target: card.querySelector(".custom-rule-target").value,
    header_name: card.querySelector(".custom-rule-header-name").value.trim(),
    pattern: card.querySelector(".custom-rule-pattern").value,
    severity: card.querySelector(".custom-rule-severity").value,
    category: card.querySelector(".custom-rule-category").value.trim() || "custom",
    description: card.querySelector(".custom-rule-description").value.trim(),
  }));
}

function collectScannerConfig() {
  const rules = {};
  els.scannerBuiltinRules.querySelectorAll("input[data-rule-id]").forEach((input) => {
    rules[input.dataset.ruleId] = input.checked;
  });
  return {
    enabled: els.scannerQuickToggle ? els.scannerQuickToggle.checked : true,
    rules,
    custom_rules: collectCustomRulesFromEditor(),
  };
}

function closeScannerSettings() {
  els.scannerSettingsBackdrop.classList.add("hidden");
}

async function saveScannerSettingsFromModal() {
  const config = collectScannerConfig();
  await saveScannerConfig(config);
  syncQuickToggle(config.enabled);
  closeScannerSettings();
}

function syncQuickToggle(enabled) {
  if (els.scannerQuickToggle) {
    els.scannerQuickToggle.checked = enabled;
  }
}

function updateFindingsSelection(newId) {
  const prev = els.findingsBody.querySelector(".history-row.selected");
  if (prev) prev.classList.remove("selected");
  if (newId) {
    const next = els.findingsBody.querySelector(`tr[data-finding-id="${newId}"]`);
    if (next) {
      next.classList.add("selected");
    } else {
      scrollFindingsToId(newId);
    }
  }
}

function scrollFindingsToId(targetId) {
  const entries = state._findingsEntries;
  if (!entries) return;
  const idx = entries.findIndex((f) => f.id === targetId);
  if (idx === -1) return;
  const shell = els.findingsBody.closest(".history-table-shell");
  if (!shell) return;
  shell.scrollTop = Math.max(0, idx * FINDINGS_ROW_HEIGHT - shell.clientHeight / 2);
}

function findingsArrowNav(direction) {
  const entries = state._findingsEntries;
  if (!entries || !entries.length) return;
  const currentIdx = entries.findIndex((f) => f.id === selectedFindingId);
  let nextIdx;
  if (currentIdx < 0) {
    nextIdx = 0;
  } else {
    nextIdx = currentIdx + direction;
    if (nextIdx < 0) nextIdx = 0;
    if (nextIdx >= entries.length) nextIdx = entries.length - 1;
  }
  const f = entries[nextIdx];
  selectedFindingId = f.id;
  updateFindingsSelection(f.id);

  // Scroll into view
  const shell = els.findingsBody.closest(".history-table-shell");
  if (shell) {
    const rowTop = nextIdx * FINDINGS_ROW_HEIGHT;
    const rowBottom = rowTop + FINDINGS_ROW_HEIGHT;
    const viewTop = shell.scrollTop;
    const viewBottom = viewTop + shell.clientHeight;
    if (rowTop < viewTop) {
      shell.scrollTop = rowTop;
    } else if (rowBottom > viewBottom) {
      shell.scrollTop = rowBottom - shell.clientHeight;
    }
  }
  loadFindingDetail(f.id);
}

async function loadOastCallbacks() {
  const [cbRes, statusRes] = await Promise.all([
    fetch("/api/oast/callbacks"),
    fetch("/api/oast/status"),
  ]);
  state.oastCallbacks = await cbRes.json();
  renderOastCallbacks();
  updateOastBadge();
  // Update registration status display
  try {
    const status = await statusRes.json();
    const el = document.getElementById("oastStatusText");
    if (el) {
      if (status.registered) {
        el.textContent = `${status.provider} · Registered (${status.payload_domain || status.correlation_id || ""})`;
        el.className = "oast-status-text registered";
      } else if (status.provider && status.provider !== "custom") {
        el.textContent = `${status.provider} · Not registered`;
        el.className = "oast-status-text not-registered";
      } else {
        el.textContent = status.provider || "Not configured";
        el.className = "oast-status-text not-registered";
      }
    }
  } catch (_) { /* ignore status fetch errors */ }
}

function renderOastCallbacks() {
  if (!els.oastTableBody) return;
  els.oastTableBody.innerHTML = state.oastCallbacks.length
    ? state.oastCallbacks.map((cb) => {
        const selected = cb.id === state.selectedOastId ? "selected" : "";
        return `<tr class="history-row ${selected}" data-oast-id="${cb.id}">
          <td>${escapeHtml(formatTimestamp(cb.received_at))}</td>
          <td>${escapeHtml(cb.protocol)}</td>
          <td>${escapeHtml(cb.remote_addr)}</td>
          <td>${escapeHtml(cb.correlation_id)}</td>
        </tr>`;
      }).join("")
    : '<tr class="empty-row"><td colspan="4">No OAST callbacks received yet. Generate a payload and use it in your tests.</td></tr>';
}

function updateOastBadge() {
  if (!els.oastBadge) return;
  const count = state.oastCallbacks.length;
  els.oastBadge.textContent = count > 0 ? String(count) : "";
  els.oastBadge.classList.toggle("hidden", count === 0);
}

async function loadOastDetail(id) {
  const response = await fetch(`/api/oast/callbacks/${id}`);
  if (!response.ok) return;
  const cb = await response.json();
  if (els.oastDetailTitle) els.oastDetailTitle.textContent = `${cb.protocol} from ${cb.remote_addr}`;
  if (els.oastDetailView) {
    els.oastDetailView.textContent = [
      `Protocol: ${cb.protocol}`,
      `Remote: ${cb.remote_addr}`,
      `Correlation ID: ${cb.correlation_id}`,
      `Received: ${cb.received_at}`,
      '',
      '--- Raw Data ---',
      cb.raw_data || '(empty)',
    ].join('\n');
  }
}

async function generateOastPayload() {
  const serverUrl = (state.runtime.oast_server_url || "").trim();
  if (!serverUrl) {
    showToast("Set an OAST server URL in Settings first", "error");
    return;
  }
  const response = await fetch("/api/oast/generate", { method: "POST" });
  const data = await response.json();
  if (els.oastPayloadText) els.oastPayloadText.value = data.payload;
  showToast(`OAST payload: ${data.payload}`);
}

async function clearOastCallbacks() {
  await fetch("/api/oast/callbacks/clear", { method: "POST" });
  state.oastCallbacks = [];
  state.selectedOastId = null;
  renderOastCallbacks();
  updateOastBadge();
  if (els.oastDetailView) els.oastDetailView.textContent = "Select an OAST callback to view details.";
  if (els.oastDetailTitle) els.oastDetailTitle.textContent = "Select a callback";
}

function bindFindingsEvents() {
  // Sort headers
  document.querySelectorAll(".findings-sortable").forEach((th) => {
    th.addEventListener("click", () => toggleFindingsSort(th.dataset.findingsSort));
  });

  // Virtual scroll for findings table
  const findingsShell = els.findingsBody ? els.findingsBody.closest(".history-table-shell") : null;
  if (findingsShell) {
    let findingsScrollRaf = 0;
    findingsShell.addEventListener("scroll", () => {
      if (findingsScrollRaf) return;
      findingsScrollRaf = requestAnimationFrame(() => {
        findingsScrollRaf = 0;
        renderFindingsVirtual();
      });
    });
  }

  // Event delegation for findings table rows
  if (els.findingsBody) {
    els.findingsBody.addEventListener("click", (event) => {
      const row = event.target.closest("tr[data-finding-id]");
      if (!row) return;
      const id = row.dataset.findingId;
      selectedFindingId = id;
      updateFindingsSelection(id);
      loadFindingDetail(id);
    });
    els.findingsBody.addEventListener("dblclick", (event) => {
      const row = event.target.closest("tr[data-finding-id]");
      if (!row) return;
      const recordId = row.dataset.recordId;
      if (recordId) jumpToTransaction(recordId);
    });
  }

  if (els.findingsDetailClose) {
    els.findingsDetailClose.addEventListener("click", () => {
      if (els.findingsDetailContent) els.findingsDetailContent.classList.add("hidden");
      if (els.findingsDetailPlaceholder) els.findingsDetailPlaceholder.classList.remove("hidden");
      selectedFindingId = null;
    });
  }
  if (els.findingsDetailJump) {
    els.findingsDetailJump.addEventListener("click", () => {
      const recordId = els.findingsDetailJump.dataset.recordId;
      if (recordId) jumpToTransaction(recordId);
    });
  }
  const findingsReplayBtn = document.getElementById("findingsDetailSendReplay");
  if (findingsReplayBtn) {
    findingsReplayBtn.addEventListener("click", () => {
      const recordId = els.findingsDetailJump?.dataset.recordId;
      if (recordId) sendFindingToReplay(recordId);
    });
  }
  const findingsFuzzerBtn = document.getElementById("findingsDetailSendFuzzer");
  if (findingsFuzzerBtn) {
    findingsFuzzerBtn.addEventListener("click", () => {
      const recordId = els.findingsDetailJump?.dataset.recordId;
      if (recordId) sendFindingToFuzzer(recordId);
    });
  }
  if (els.findingsClearButton) {
    els.findingsClearButton.addEventListener("click", async () => {
      await fetch("/api/findings/clear", { method: "POST" });
      findingsData = [];
      selectedFindingId = null;
      renderFindings();
      updateFindingsBadge();
      if (els.findingsDetailContent) els.findingsDetailContent.classList.add("hidden");
      if (els.findingsDetailPlaceholder) els.findingsDetailPlaceholder.classList.remove("hidden");
    });
  }

  // Filters
  if (els.findingsFilterSeverity) {
    els.findingsFilterSeverity.addEventListener("change", () => renderFindings());
  }
  if (els.findingsFilterCategory) {
    els.findingsFilterCategory.addEventListener("change", () => renderFindings());
  }
  if (els.findingsFilterSearch) {
    let debounce = null;
    els.findingsFilterSearch.addEventListener("input", () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => renderFindings(), 200);
    });
  }
  if (els.findingsInScopeOnly) {
    els.findingsInScopeOnly.addEventListener("change", () => renderFindings());
  }

  // Arrow key navigation
  document.addEventListener("keydown", (e) => {
    // Skip if scanner settings modal is open
    if (els.scannerSettingsBackdrop && !els.scannerSettingsBackdrop.classList.contains("hidden")) {
      if (e.key === "Escape") { e.preventDefault(); closeScannerSettings(); }
      if (e.key === "Enter" && !e.target.matches("input, textarea, select")) { e.preventDefault(); saveScannerSettingsFromModal(); }
      return;
    }
    // Only handle when findings tab is active and not focused on input
    if (state.activeTool !== "proxy" || state.activeProxyTab !== "findings") return;
    if (e.target.matches("input, textarea, select")) return;
    if (e.key === "ArrowDown") { e.preventDefault(); findingsArrowNav(1); }
    if (e.key === "ArrowUp") { e.preventDefault(); findingsArrowNav(-1); }
  });

  // Findings detail search
  if (els.findingsReqSearchInput) {
    els.findingsReqSearchInput.addEventListener("input", () => {
      const query = els.findingsReqSearchInput.value;
      const { count } = applyCodeSearch(els.findingsReqView, query);
      const lines = els.findingsReqView.querySelectorAll(".code-line").length;
      els.findingsReqSearchMeta.innerHTML = buildSearchMeta(lines, "raw", count);
    });
  }
  if (els.findingsResSearchInput) {
    els.findingsResSearchInput.addEventListener("input", () => {
      const query = els.findingsResSearchInput.value;
      const { count } = applyCodeSearch(els.findingsResView, query);
      const lines = els.findingsResView.querySelectorAll(".code-line").length;
      els.findingsResSearchMeta.innerHTML = buildSearchMeta(lines, "raw", count);
    });
  }
  initSearchHitNavigation(els.findingsReqSearchMeta, () => els.findingsReqView);
  initSearchHitNavigation(els.findingsResSearchMeta, () => els.findingsResView);

  // Quick toggle (on/off in toolbar)
  if (els.scannerQuickToggle) {
    els.scannerQuickToggle.addEventListener("change", async () => {
      const enabled = els.scannerQuickToggle.checked;
      const config = await loadScannerConfig();
      if (config) {
        config.enabled = enabled;
        await saveScannerConfig(config);
      }
    });
    // Sync initial state from server
    loadScannerConfig().then((config) => {
      if (config) syncQuickToggle(config.enabled);
    });
  }

  // Scanner settings modal
  if (els.findingsSettingsButton) {
    els.findingsSettingsButton.addEventListener("click", () => openScannerSettings());
  }
  if (els.scannerSettingsClose) {
    els.scannerSettingsClose.addEventListener("click", () => closeScannerSettings());
  }
  if (els.scannerSettingsCancel) {
    els.scannerSettingsCancel.addEventListener("click", () => closeScannerSettings());
  }
  if (els.scannerSettingsSave) {
    els.scannerSettingsSave.addEventListener("click", () => saveScannerSettingsFromModal());
  }
  if (els.scannerAddCustomRule) {
    els.scannerAddCustomRule.addEventListener("click", () => {
      const rules = collectCustomRulesFromEditor();
      rules.push({
        id: `custom_${Date.now()}`,
        enabled: true,
        name: "",
        target: "response_body",
        header_name: "",
        pattern: "",
        severity: "medium",
        category: "custom",
        description: "",
      });
      renderCustomRulesEditor(rules);
    });
  }
  if (els.scannerSettingsBackdrop) {
    els.scannerSettingsBackdrop.addEventListener("click", (e) => {
      if (e.target === els.scannerSettingsBackdrop) closeScannerSettings();
    });
  }

  initFindingsResizer();
  applyFindingsColumnWidths();
  bindFindingsColumnResizers();
}

function applyFindingsColumnWidths() {
  const table = document.getElementById("findingsTable");
  if (!table) return;
  let total = 0;
  for (const [key, w] of Object.entries(findingsColWidths)) {
    table.style.setProperty(`--fc-${key}`, `${w}px`);
    total += w;
  }
  table.style.setProperty("--findings-table-width", `${Math.max(total, 800)}px`);
}

function bindFindingsColumnResizers() {
  document.querySelectorAll(".findings-col-resize").forEach((handle) => {
    handle.addEventListener("mousedown", (event) => {
      const key = handle.dataset.findingsCol;
      const limits = FINDINGS_COL_RULES[key];
      if (!key || !limits) return;

      event.preventDefault();
      event.stopPropagation();

      const header = handle.closest("th");
      const startWidth = header?.getBoundingClientRect().width ?? limits.default;
      document.body.classList.add("pane-resizing-x");
      handle.classList.add("active");

      const onMove = (moveEvent) => {
        const delta = moveEvent.clientX - event.clientX;
        findingsColWidths[key] = Math.max(limits.min, Math.min(Math.round(startWidth + delta), limits.max));
        applyFindingsColumnWidths();
      };

      const onUp = () => {
        document.body.classList.remove("pane-resizing-x");
        handle.classList.remove("active");
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
      };

      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
  });
}

function initFindingsResizer() {
  const resizer = els.findingsDetailResizer;
  if (!resizer) return;

  resizer.addEventListener("mousedown", (event) => {
    if (!els.findingsPanel || !els.findingsDetailPanel || resizer.classList.contains("hidden")) {
      return;
    }

    event.preventDefault();
    const tableShell = els.findingsPanel.querySelector(".history-table-shell");
    const start = {
      table: tableShell.getBoundingClientRect().height,
      detail: els.findingsDetailPanel.getBoundingClientRect().height,
    };
    const combinedHeight = start.table + start.detail;

    document.body.classList.add("pane-resizing-y");
    resizer.classList.add("active");

    const onMove = (moveEvent) => {
      const delta = moveEvent.clientY - event.clientY;
      const nextDetail = Math.max(120, Math.min(start.detail - delta, combinedHeight - 60));
      const nextTable = combinedHeight - nextDetail;
      tableShell.style.flex = "0 0 " + Math.round(nextTable) + "px";
      els.findingsDetailPanel.style.flex = "0 0 " + Math.round(nextDetail) + "px";
    };

    const onUp = () => {
      document.body.classList.remove("pane-resizing-y");
      resizer.classList.remove("active");
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    };

    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
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
  const showFindings = state.activeProxyTab === "findings";
  const showOast = state.activeProxyTab === "oast";
  const showProxySettings = state.activeProxyTab === "proxy-settings";
  const showPlaceholder = !showHistory && !showIntercept && !showWebsockets && !showMatchReplace && !showFindings && !showOast && !showProxySettings;

  els.colorTagFilter.classList.toggle("hidden", !showHistory);
  els.filterBar.classList.toggle("hidden", !showHistory);
  els.trafficRegion.classList.toggle("hidden", !showHistory);
  els.historyWorkbenchResizer.classList.toggle("hidden", !showHistory);
  els.lowerWorkbench.classList.toggle("hidden", !showHistory);
  els.interceptPanel.classList.toggle("hidden", !showIntercept);
  els.websocketPanel.classList.toggle("hidden", !showWebsockets);
  els.matchReplacePanel.classList.toggle("hidden", !showMatchReplace);
  els.findingsPanel.classList.toggle("hidden", !showFindings);
  if (els.oastPanel) els.oastPanel.classList.toggle("hidden", state.activeProxyTab !== "oast");
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

  if (showFindings) {
    loadFindings();
    els.footerMode.textContent = "Findings active";
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
  els.interceptStatus.textContent = enabled ? "On" : "Off";
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

function updateHistorySelection(newId) {
  const prev = els.historyTableBody.querySelector(".history-row.selected");
  if (prev) prev.classList.remove("selected");
  if (newId) {
    const next = els.historyTableBody.querySelector(`.history-row[data-id="${newId}"]`);
    if (next) next.classList.add("selected");
  }
}

function renderHistory() {
  invalidateVisibleEntriesCache();
  const visibleEntries = getVisibleEntries();
  const visibleItems = visibleEntries.map((entry) => entry.item);
  const hiddenConnectCount = countHiddenConnectItems();
  const summary = [];
  const totalCount = visibleItems.length;
  summary.push(`${totalCount} item(s) visible`);
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

  // Store entries for virtual scroll
  state._historyEntries = visibleEntries;

  if (!visibleItems.length) {
    els.historyTableBody.innerHTML = `
      <tr class="empty-row">
        <td colspan="${state.historyColumnOrder.length}">${hiddenConnectCount ? "Only CONNECT tunnels were captured, and they are hidden from HTTP history. Trust the Sniper Root CA and retry the HTTPS client if you expect decrypted traffic." : "No traffic matches the current filter settings."}</td>
      </tr>
    `;
    return;
  }

  renderHistoryVirtual();
}

function renderHistoryVirtual() {
  const entries = state._historyEntries;
  if (!entries || !entries.length) return;

  const shell = els.historyTable.closest(".history-table-shell");
  if (!shell) return;

  const scrollTop = shell.scrollTop;
  const viewportHeight = shell.clientHeight;
  const totalCount = entries.length;
  const colCount = state.historyColumnOrder.length;

  const startIdx = Math.max(0, Math.floor(scrollTop / HISTORY_ROW_HEIGHT) - HISTORY_BUFFER_ROWS);
  const endIdx = Math.min(totalCount, Math.ceil((scrollTop + viewportHeight) / HISTORY_ROW_HEIGHT) + HISTORY_BUFFER_ROWS);

  const topPadding = startIdx * HISTORY_ROW_HEIGHT;
  const bottomPadding = Math.max(0, (totalCount - endIdx) * HISTORY_ROW_HEIGHT);

  const rows = [];
  for (let i = startIdx; i < endIdx; i++) {
    const entry = entries[i];
    const item = entry.item;
    const selected = item.id === state.selectedId ? "selected" : "";
    const tagClass = item.color_tag ? ` tagged-${escapeHtml(item.color_tag)}` : "";
    const cells = state.historyColumnOrder.map((colKey) => renderHistoryCell(colKey, item, entry)).join("");
    rows.push(`<tr class="history-row ${selected}${tagClass}" data-id="${item.id}">${cells}</tr>`);
  }

  els.historyTableBody.innerHTML =
    (topPadding > 0 ? `<tr class="virtual-spacer"><td colspan="${colCount}" style="height:${topPadding}px;padding:0;border:none"></td></tr>` : "") +
    rows.join("") +
    (bottomPadding > 0 ? `<tr class="virtual-spacer"><td colspan="${colCount}" style="height:${bottomPadding}px;padding:0;border:none"></td></tr>` : "");
}

function updateHistorySelection(newId) {
  const prev = els.historyTableBody.querySelector(".history-row.selected");
  if (prev) prev.classList.remove("selected");
  if (newId) {
    const next = els.historyTableBody.querySelector(`.history-row[data-id="${newId}"]`);
    if (next) {
      next.classList.add("selected");
    } else {
      // Row not in DOM (outside virtual scroll window) — scroll to it
      scrollHistoryToId(newId);
    }
  }
}

function scrollHistoryToId(targetId) {
  const entries = state._historyEntries;
  if (!entries) return;
  const idx = entries.findIndex((e) => e.item.id === targetId);
  if (idx === -1) return;

  const shell = els.historyTable.closest(".history-table-shell");
  if (!shell) return;

  // Scroll so that target row is near center of viewport
  const targetTop = idx * HISTORY_ROW_HEIGHT;
  shell.scrollTop = Math.max(0, targetTop - shell.clientHeight / 2);
  // renderHistoryVirtual will be called by scroll event
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
  updateHistorySelection(nextId);
  scrollSelectedHistoryRowIntoView();
  await loadTransactionDetail(nextId);
}

function scrollSelectedHistoryRowIntoView() {
  const selectedRow = els.historyTableBody.querySelector(".history-row.selected");
  if (selectedRow) {
    selectedRow.scrollIntoView({ block: "nearest" });
    return;
  }
  // Row not in DOM — use virtual scroll position
  if (!state.selectedId || !state._historyEntries) return;
  const idx = state._historyEntries.findIndex((e) => e.item.id === state.selectedId);
  if (idx === -1) return;
  const shell = els.historyTable.closest(".history-table-shell");
  if (!shell) return;
  const rowTop = idx * HISTORY_ROW_HEIGHT;
  const rowBottom = rowTop + HISTORY_ROW_HEIGHT;
  const viewTop = shell.scrollTop;
  const viewBottom = viewTop + shell.clientHeight;
  if (rowTop < viewTop) {
    shell.scrollTop = rowTop;
  } else if (rowBottom > viewBottom) {
    shell.scrollTop = rowBottom - shell.clientHeight;
  }
}

async function moveWebsocketSelection(offset) {
  const sortedEntries = getSortedWebsocketEntries();
  if (!sortedEntries.length) return;

  const currentIndex = sortedEntries.findIndex(({ session }) => session.id === state.selectedWebsocketId);
  const fallbackIndex = offset > 0 ? 0 : sortedEntries.length - 1;
  const nextIndex = clamp(
    currentIndex === -1 ? fallbackIndex : currentIndex + offset,
    0,
    sortedEntries.length - 1,
  );
  const nextId = sortedEntries[nextIndex]?.session?.id;
  if (!nextId) return;

  state.selectedWebsocketId = nextId;
  renderWebsocketSessions();
  scrollSelectedWebsocketRowIntoView();
  await loadWebsocketDetail(nextId);
}

function scrollSelectedWebsocketRowIntoView() {
  const selectedRow = els.websocketTableBody.querySelector(".history-row.selected");
  selectedRow?.scrollIntoView({ block: "nearest" });
}

function moveFrameSelection(offset) {
  const session = state.selectedWebsocketRecord;
  if (!session || !session.frames || !session.frames.length) return;

  const current = state.selectedFrameIdx;
  const fallback = offset > 0 ? 0 : session.frames.length - 1;
  const nextIdx = clamp(
    current == null ? fallback : current + offset,
    0,
    session.frames.length - 1,
  );

  state.selectedFrameIdx = nextIdx;
  const frame = session.frames[nextIdx];
  if (!frame) return;

  // Update selection highlight — find by data attribute, not DOM index
  els.websocketFramesBody.querySelectorAll(".frame-selected").forEach((r) => r.classList.remove("frame-selected"));
  const target = els.websocketFramesBody.querySelector(`.history-row[data-frame-idx="${nextIdx}"]`);
  if (target) {
    target.classList.add("frame-selected");
    target.scrollIntoView({ block: "nearest" });
  }

  showFrameDetail(frame);
}

function isEditableTarget(target) {
  if (!(target instanceof HTMLElement)) {
    return false;
  }

  // Truly editable elements (replay editor, ws message editor) block table nav.
  // Readonly code-view panels with data-readonly-editable also block table nav
  // when they have focus — arrow keys should navigate lines, not history rows.
  if (target.isContentEditable) {
    return true;
  }

  const tagName = target.tagName.toLowerCase();
  if (["input", "textarea", "select", "option", "button"].includes(tagName)) {
    return true;
  }

  const editableParent = target.closest("input, textarea, select, [contenteditable='true']");
  if (editableParent) {
    return true;
  }

  return false;
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

  // Try modern Clipboard API first, fall back to textarea+execCommand
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch (_) {
      // Clipboard API rejected (common in WKWebView) — fall through to fallback
    }
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
  state.showOriginal.request = false;
  state.showOriginal.response = false;
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

  renderViewTabs();
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
  renderViewTabs();
  renderMessagePanes();
}

function renderMessagePanes() {
  const record = state.selectedRecord;
  const requestRecord = record && state.showOriginal.request && record.original_request
    ? { ...record, request: record.original_request }
    : record;
  const responseRecord = record && state.showOriginal.response && record.original_response
    ? { ...record, response: record.original_response }
    : record;
  const requestText = requestRecord
    ? buildMessagePresentation("request", requestRecord)
    : "Select a transaction from HTTP.";
  const responseText = responseRecord
    ? buildMessagePresentation("response", responseRecord)
    : "No response selected.";

  const requestPane = els.requestViewCM
    ? updateCodePaneCM("request", els.requestViewCM, requestText)
    : updateCodePane(els.requestView, els.requestLines, requestText, state.messageViews.request, "request");
  const responsePane = els.responseViewCM
    ? updateCodePaneCM("response", els.responseViewCM, responseText)
    : updateCodePane(els.responseView, els.responseLines, responseText, state.messageViews.response, "response");
  if (els.requestSearchInput.value !== state.messageSearch.request) {
    els.requestSearchInput.value = state.messageSearch.request;
  }
  if (els.responseSearchInput.value !== state.messageSearch.response) {
    els.responseSearchInput.value = state.messageSearch.response;
  }
  els.requestSearchMeta.innerHTML = buildSearchMeta(
    requestPane.lineCount,
    state.messageViews.request,
    requestPane.matchCount,
  );
  els.responseSearchMeta.innerHTML = buildSearchMeta(
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
  });
  els.requestMrToggle.classList.toggle("hidden", !hasRequestDiff);
  els.responseMrToggle.classList.toggle("hidden", !hasResponseDiff);
  // sync active states on mr-toggle buttons
  document.querySelectorAll(".mr-btn").forEach((btn) => {
    const target = btn.dataset.target;
    const showOriginal = state.showOriginal?.[target] || false;
    const isOriginal = btn.dataset.mr === "original";
    btn.classList.toggle("active", isOriginal === showOriginal);
  });
  // reset showOriginal when no diff
  if (!hasRequestDiff && state.showOriginal) state.showOriginal.request = false;
  if (!hasResponseDiff && state.showOriginal) state.showOriginal.response = false;
}

function renderIntercepts() {
  const filteredIntercepts = state.interceptInScopeOnly
    ? state.intercepts.filter((item) => isInScopeHost(item.host))
    : state.intercepts;
  els.interceptTableBody.innerHTML = filteredIntercepts.length
    ? filteredIntercepts
        .map((item) => {
          const selected = item.id === state.selectedInterceptId ? "selected" : "";
          return `
            <tr class="history-row ${selected}" data-id="${item.id}">
              <td class="iq-col-method">${escapeHtml(item.method)}</td>
              <td class="iq-col-host text-truncate">${escapeHtml(item.host)}</td>
              <td class="iq-col-path text-truncate">${escapeHtml(item.path || "/")}</td>
              <td class="iq-col-time">${escapeHtml(formatTimestamp(item.started_at))}</td>
            </tr>
          `;
        })
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="4">Intercept queue is empty.</td>
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
  const sortedEntries = getSortedWebsocketEntries();
  if (els.websocketSearchInput.value !== state.websocketQuery) {
    els.websocketSearchInput.value = state.websocketQuery;
  }
  els.websocketMeta.textContent = buildWebsocketFilterSummary(
    sortedEntries.length,
    state.websocketSessions.length,
    state.websocketQuery,
  );

  updateWebsocketSortIndicators();

  els.websocketTableBody.innerHTML = sortedEntries.length
    ? sortedEntries.slice(0, 500)
        .map(({ session, index }) => {
          const selected = session.id === state.selectedWebsocketId ? "selected" : "";
          return `
            <tr class="history-row ${selected}" data-id="${session.id}">
              <td>${index + 1}</td>
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
          <td colspan="7">${
            state.websocketSessions.length
              ? "No WebSocket sessions match the current filter."
              : "No WebSocket sessions have been captured yet."
          }</td>
        </tr>
      `;

  Array.from(els.websocketTableBody.querySelectorAll(".history-row")).forEach((row) => {
    row.addEventListener("click", () => {
      state.wsKeyboardFocus = "sessions";
      state.selectedWebsocketId = row.dataset.id;
      loadWebsocketDetail(row.dataset.id).catch((error) => console.error(error));
    });
  });

  if (!state.selectedWebsocketRecord) {
    els.websocketRequestView.textContent = state.websocketSessions.length && !sortedEntries.length
      ? "No WebSocket session matches the current filter."
      : "Select a WebSocket session.";
    els.websocketResponseView.textContent = "No response selected.";
    els.websocketFramesBody.innerHTML = `
      <div class="ws-frame-empty">${
        state.websocketSessions.length && !sortedEntries.length
          ? "Clear or adjust the filter to inspect captured frames."
          : "Frame capture will appear here after a WebSocket handshake completes."
      }</div>
    `;
    return;
  }

  const session = state.selectedWebsocketRecord;
  const reqText = buildRawWebsocketRequest(session);
  const resText = buildRawWebsocketResponse(session);
  const savedReqFocus = window._saveCodeViewFocus?.(els.websocketRequestView);
  const savedResFocus = window._saveCodeViewFocus?.(els.websocketResponseView);
  els.websocketRequestView.innerHTML = renderHttpHtml(reqText, "request");
  els.websocketResponseView.innerHTML = renderHttpHtml(resText, "response");
  window._restoreCodeViewFocus?.(els.websocketRequestView, savedReqFocus);
  window._restoreCodeViewFocus?.(els.websocketResponseView, savedResFocus);
  // Preserve current handshake tab selection (default to Request)
  const resBtn = document.getElementById("wsHandshakeResBtn");
  const showingResponse = resBtn?.classList.contains("active");
  els.websocketRequestView.classList.toggle("hidden", !!showingResponse);
  els.websocketResponseView.classList.toggle("hidden", !showingResponse);
  // Update line numbers for active handshake view
  const activeHandshakeText = showingResponse ? resText : reqText;
  const hsLineCount = countLines(activeHandshakeText);
  if (els.wsHandshakeLines) {
    els.wsHandshakeLines.textContent = buildLineNumbers(hsLineCount);
  }
  // Apply handshake search
  updateWsHandshakeSearch();
  els.websocketFramesBody.innerHTML = session.frames.length
    ? session.frames
        .map((frame, idx) => {
          const dir = frame.direction === "client_to_server" ? "\u2192" : "\u2190";
          const dirClass = frame.direction === "client_to_server" ? "dir-client" : "dir-server";
          return `
          <tr class="history-row${idx === state.selectedFrameIdx ? ' frame-selected' : ''}" data-frame-idx="${idx}">
            <td class="cell-narrow">${idx + 1}</td>
            <td class="cell-narrow ${dirClass}">${dir}</td>
            <td class="cell-narrow">${frame.kind}</td>
            <td class="cell-narrow">${escapeHtml(formatSize(frame.body_size))}</td>
            <td class="cell-url">${escapeHtml(renderFramePreview(frame))}</td>
          </tr>`;
        })
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="5">No frames recorded yet.</td>
        </tr>
      `;

  // Frame click + context menu handlers
  Array.from(els.websocketFramesBody.querySelectorAll(".history-row[data-frame-idx]")).forEach((row) => {
    row.addEventListener("click", () => {
      const idx = parseInt(row.dataset.frameIdx, 10);
      const frame = session.frames[idx];
      if (!frame) return;

      state.selectedFrameIdx = idx;
      state.wsKeyboardFocus = "frames";

      // Highlight selected row
      els.websocketFramesBody.querySelectorAll(".frame-selected").forEach((r) => r.classList.remove("frame-selected"));
      row.classList.add("frame-selected");

      // Show detail panel
      showFrameDetail(frame);
    });

    // Right-click on frame → show context menu
    row.addEventListener("contextmenu", (e) => {
      const idx = parseInt(row.dataset.frameIdx, 10);
      if (isNaN(idx)) return;
      e.preventDefault();
      state.selectedFrameIdx = idx;
      openWsFrameContextMenu(e.clientX, e.clientY);
    });
  });
}

function buildWebsocketFilterSummary(visibleCount, totalCount, query) {
  const parts = [`${visibleCount} session(s) visible`];
  const filters = [];
  if (document.getElementById("wsInScopeOnly")?.classList.contains("active")) filters.push("in scope");
  if (document.getElementById("wsHideClosed")?.classList.contains("active")) filters.push("live only");
  if (query) filters.push(query);
  if (filters.length) parts.push(`filter: ${filters.join(", ")}`);
  parts.push(totalCount ? `${totalCount} total captured` : "No sessions captured yet");
  return parts.join(" · ");
}

function getVisibleWebsocketSessions() {
  const normalizedQuery = state.websocketQuery.trim().toLowerCase();
  const inScopeOnly = document.getElementById("wsInScopeOnly")?.classList.contains("active") ?? false;
  const liveOnly = document.getElementById("wsHideClosed")?.classList.contains("active") ?? false;

  return state.websocketSessions.filter((session) => {
    if (inScopeOnly && !isInScopeHost(session.host)) return false;
    if (liveOnly && session.duration_ms != null) return false;
    if (normalizedQuery) {
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
      if (!haystack.includes(normalizedQuery)) return false;
    }
    return true;
  });
}

function getSortedWebsocketEntries() {
  const filtered = getVisibleWebsocketSessions();
  const direction = state.websocketSortDirection === "asc" ? 1 : -1;

  return filtered
    .map((session, index) => ({ session, index }))
    .sort((a, b) => {
      if (state.websocketSortKey === "index") {
        return (a.index - b.index) * direction;
      }

      const av = getWebsocketSortValue(a.session, state.websocketSortKey);
      const bv = getWebsocketSortValue(b.session, state.websocketSortKey);
      const cmp = compareSortValues(av, bv);
      return cmp !== 0 ? cmp * direction : a.index - b.index;
    });
}

function getWebsocketSortValue(session, key) {
  switch (key) {
    case "host": return session.host.toLowerCase();
    case "path": return (session.path || "").toLowerCase();
    case "status": return session.status ?? -1;
    case "frame_count": return session.frame_count ?? 0;
    case "duration_ms": return session.duration_ms ?? Infinity;
    case "started_at": return Date.parse(session.started_at) || 0;
    default: return "";
  }
}

function toggleWebsocketSort(key) {
  if (state.websocketSortKey === key) {
    state.websocketSortDirection = state.websocketSortDirection === "asc" ? "desc" : "asc";
  } else {
    state.websocketSortKey = key;
    state.websocketSortDirection = key === "index" ? "asc" : "desc";
  }
  renderWebsocketSessions();
}

function updateWebsocketSortIndicators() {
  document.querySelectorAll(".ws-sort").forEach((btn) => {
    const key = btn.dataset.wsSortKey;
    const active = key === state.websocketSortKey;
    const indicator = btn.querySelector(".sort-indicator");
    if (indicator) {
      indicator.textContent = active ? (state.websocketSortDirection === "asc" ? "↑" : "↓") : "↕";
    }
    btn.closest("th")?.setAttribute("aria-sort", active ? (state.websocketSortDirection === "asc" ? "ascending" : "descending") : "none");
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
    // Data not ready — schedule a background load to self-heal
    if (!state._settingsLoadPending) {
      state._settingsLoadPending = true;
      loadSettings()
        .then(() => { state._settingsLoadPending = false; renderProxySettings(); })
        .catch(() => { state._settingsLoadPending = false; });
    }
    return;
  }

  const startup = state.settings.startup;
  els.proxySettingIntercept.checked = Boolean(state.runtime.intercept_enabled);
  els.proxySettingWebsocketCapture.checked = Boolean(state.runtime.websocket_capture_enabled);
  els.proxySettingUpstreamInsecure.checked = state.runtime.upstream_insecure !== false;
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
  // Auto Content-Length (local UI setting, not server-side)
  const aclEl = document.getElementById("proxySettingAutoContentLength");
  if (aclEl) aclEl.checked = localStorage.getItem("sniper_auto_content_length") !== "false";

  const oastEnabled = document.getElementById("proxySettingOastEnabled");
  const oastProvider = document.getElementById("proxySettingOastProvider");
  const oastUrl = document.getElementById("proxySettingOastServerUrl");
  const oastToken = document.getElementById("proxySettingOastToken");
  const oastInterval = document.getElementById("proxySettingOastInterval");
  const oastUrlHint = document.getElementById("oastServerUrlHint");
  const oastTokenField = document.getElementById("oastTokenField");
  if (oastEnabled) oastEnabled.checked = Boolean(state.runtime.oast_enabled);
  if (oastProvider && document.activeElement !== oastProvider) oastProvider.value = state.runtime.oast_provider || "custom";
  if (oastUrl && document.activeElement !== oastUrl) oastUrl.value = state.runtime.oast_server_url || "";
  if (oastToken && document.activeElement !== oastToken) oastToken.value = state.runtime.oast_token || "";
  if (oastInterval && document.activeElement !== oastInterval) oastInterval.value = state.runtime.oast_polling_interval_secs || 5;
  // Update UI based on provider
  const prov = oastProvider?.value || "custom";
  if (oastUrl) {
    const placeholders = { interactsh: "https://oast.fun", boast: "https://your-boast:1337", custom: "https://your-server" };
    oastUrl.placeholder = placeholders[prov] || placeholders.custom;
  }
  if (oastUrlHint) {
    const hints = {
      interactsh: "Interactsh server. Sniper auto-registers with RSA encryption and polls for callbacks.",
      boast: "BOAST server. Sniper polls the /events endpoint for callbacks.",
      custom: "Custom OAST server. Sniper polls {url}/poll for JSON callbacks.",
    };
    oastUrlHint.textContent = hints[prov] || hints.custom;
  }
  if (oastTokenField) {
    oastTokenField.style.display = prov === "boast" ? "none" : "";
  }

  els.proxySettingsDataDir.textContent = state.settings.data_dir;
  els.proxySettingsStartupPath.textContent = startup?.file_path || state.settings.data_dir;
  els.proxySettingsCertificateName.textContent = `${state.settings.certificate.common_name} · expires ${formatTimestamp(state.settings.certificate.expires_at)}`;
  els.proxySettingListenerHelp.textContent = startup
    ? startup.rebound === true
      ? `Proxy listener is now running on ${startup.active_proxy_addr}.`
      : startup.rebind_error
        ? `${startup.rebind_error} Saved ${startup.proxy_addr} for the next launch.`
        : startup.restart_required
          ? `Saved ${startup.proxy_addr} for the next launch. Restart Sniper to replace the active listener ${startup.active_proxy_addr}.`
          : `Proxy listener is running on ${startup.active_proxy_addr}.`
    : "Changes are saved for the next app start.";
}

function renderReplay() {
  const tab = ensureRepeaterTab();
  renderReplayTabs();

  const isWsTab = tab && tab.type === "websocket";

  // Toggle HTTP vs WS panels
  if (els.httpReplayToolbar) els.httpReplayToolbar.classList.toggle("hidden", isWsTab);
  if (els.httpReplayWorkbench) els.httpReplayWorkbench.classList.toggle("hidden", isWsTab);
  if (els.wsReplayPanel) els.wsReplayPanel.classList.toggle("hidden", !isWsTab);

  if (isWsTab) {
    renderWsReplay();
    return;
  }

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
    els.replayFollowRedirectButton.classList.add("hidden");
    return;
  }

  syncReplayToolbar(tab);
  const reqMode = state.replayMessageViews.request;
  if (reqMode === "hex") {
    els.replayRequestHighlight.removeAttribute("contenteditable");
    if (!tab.requestBytes) {
      tab.requestBytes = new TextEncoder().encode(tab.requestText);
      tab.requestOriginalBytes = new Uint8Array(tab.requestBytes);
    }
    els.replayRequestHighlight.innerHTML = renderEditableHexHtml(tab.requestBytes, tab.requestOriginalBytes);
    bindHexByteHandlers(els.replayRequestHighlight, tab);
    updateReplaySearchPane("request", toHexDumpFromBytes(tab.requestBytes));
  } else {
    // Sync bytes back to text when leaving hex mode
    if (tab.requestBytes) {
      tab.requestText = new TextDecoder().decode(tab.requestBytes);
      els.replayRequestEditor.value = tab.requestText;
      tab.requestBytes = null;
      tab.requestOriginalBytes = null;
    }
    if (!els.replayRequestHighlight.isContentEditable) {
      els.replayRequestHighlight.setAttribute("contenteditable", "plaintext-only");
    }
    let displayText = tab.requestText;
    if (reqMode === "pretty") {
      const fakeMsg = { content_type: headerValue(tab.baseRequest?.headers || [], "content-type") };
      displayText = prettyFormat(tab.requestText, fakeMsg);
    } else if (reqMode === "raw") {
      displayText = compactFormat(tab.requestText);
    }
    els.replayRequestEditor.value = tab.requestText;
    renderReplayRequestHighlight(displayText);
    updateReplaySearchPane("request", displayText);
  }

  if (!tab.responseRecord) {
    const notice = tab.notice || "Send a request from Replay to capture the response here.";
    els.replayResponseMeta.textContent = tab.notice || "No response yet.";
    renderReplayResponseView(notice);
    updateReplaySearchPane("response", notice);
    els.replayFollowRedirectButton.classList.add("hidden");
    return;
  }

  // Show/hide Follow button for redirect responses
  const isRedirect = [301, 302, 303, 307, 308].includes(tab.responseRecord.status);
  const hasLocation = tab.responseRecord.response?.headers?.some((h) => h.name.toLowerCase() === "location");
  els.replayFollowRedirectButton.classList.toggle("hidden", !(isRedirect && hasLocation));

  els.replayResponseMeta.textContent = [
    `${formatStatus(tab.responseRecord.status)}`,
    `${tab.responseRecord.duration_ms} ms`,
    tab.responseRecord.response?.content_type || tab.responseRecord.request.content_type || "n/a",
  ].join(" · ");

  const rawResponseText = buildRawResponse(tab.responseRecord);
  const respMode = state.replayMessageViews.response;
  let responseText;
  if (respMode === "hex") {
    responseText = toHexDump(rawResponseText);
  } else if (respMode === "pretty") {
    responseText = prettyFormat(rawResponseText, tab.responseRecord.response);
  } else {
    responseText = compactFormat(rawResponseText);
  }
  renderReplayResponseView(responseText);
  updateReplaySearchPane("response", responseText);
  renderReplayViewTabs();
}

function renderReplayRequestHighlight(text) {
  if (!els.replayRequestHighlight) {
    return;
  }
  const mode = state.replayMessageViews.request;
  els.replayRequestHighlight.innerHTML = renderCodeHtml(text, mode, "request");
  // Reset undo history when switching tabs
  state._replayUndoStack = [];
  state._replayRedoStack = [];
  state._replayLastSnapshot = text;
}

// Re-render syntax highlighting while preserving cursor position in the
// contenteditable replay editor.
function replayHighlightRerender(text) {
  if (!els.replayRequestHighlight) return;
  const mode = state.replayMessageViews.request;
  const saved = saveContentEditableCaret(els.replayRequestHighlight);
  els.replayRequestHighlight.innerHTML = renderCodeHtml(text, mode, "request");
  restoreContentEditableCaret(els.replayRequestHighlight, saved);
}

function saveContentEditableCaret(el) {
  const sel = window.getSelection();
  if (!sel.rangeCount || !el.contains(sel.anchorNode)) return null;
  const range = sel.getRangeAt(0);
  const pre = document.createRange();
  pre.selectNodeContents(el);
  pre.setEnd(range.startContainer, range.startOffset);
  const start = pre.toString().length;
  pre.setEnd(range.endContainer, range.endOffset);
  const end = pre.toString().length;
  return { start, end };
}

function restoreContentEditableCaret(el, pos) {
  if (!pos) return;
  const sel = window.getSelection();
  const range = document.createRange();
  const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
  let offset = 0;
  let startSet = false;
  while (walker.nextNode()) {
    const node = walker.currentNode;
    if (!startSet && offset + node.length >= pos.start) {
      range.setStart(node, pos.start - offset);
      startSet = true;
    }
    if (startSet && offset + node.length >= pos.end) {
      range.setEnd(node, pos.end - offset);
      break;
    }
    offset += node.length;
  }
  if (startSet) {
    sel.removeAllRanges();
    sel.addRange(range);
  }
}

function syncReplayRequestHighlightScroll() {
  // No longer needed — the contenteditable pre scrolls natively.
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

function renderInterceptResponseHighlight(text) {
  if (!els.interceptResponseHighlight) return;
  els.interceptResponseHighlight.innerHTML = renderCodeHtml(text, "pretty", "response");
  els.interceptResponseHighlight.scrollTop = els.interceptResponseEditor.scrollTop;
  els.interceptResponseHighlight.scrollLeft = els.interceptResponseEditor.scrollLeft;
}

function renderFuzzerRequestHighlight(text) {
  if (!els.fuzzerRequestHighlight) {
    return;
  }

  let html = renderCodeHtml(text, "pretty", "request");
  // Highlight payload placeholders: $payload$ and {{PAYLOAD}}
  html = html.replace(/(\$payload\$|\{\{PAYLOAD\}\})/gi, '<span class="hl-payload-placeholder">$1</span>');
  els.fuzzerRequestHighlight.innerHTML = html;
  syncFuzzerRequestHighlightScroll();
}

function syncFuzzerRequestHighlightScroll() {
  if (!els.fuzzerRequestHighlight || !els.fuzzerRequestEditor) {
    return;
  }

  els.fuzzerRequestHighlight.scrollTop = els.fuzzerRequestEditor.scrollTop;
  els.fuzzerRequestHighlight.scrollLeft = els.fuzzerRequestEditor.scrollLeft;
}

let _replayResponseCMView = null;
function renderReplayResponseView(text) {
  // Use CodeMirror if container exists
  if (els.replayResponseCM) {
    if (!_replayResponseCMView) {
      _replayResponseCMView = new SniperCodeView(els.replayResponseCM, { readOnly: true });
    }
    _replayResponseCMView.setContent(text || "");
    return;
  }
  // Fallback to legacy
  const mode = state.replayMessageViews.response;
  if (els.replayResponseView) els.replayResponseView.innerHTML = renderCodeHtml(text, mode, "response");
}

/** Update only the response pane + meta after a send — preserves request cursor/scroll. */
function renderReplayResponseOnly(tab) {
  if (!tab.responseRecord) {
    const notice = tab.notice || "Send a request from Replay to capture the response here.";
    els.replayResponseMeta.textContent = tab.notice || "No response yet.";
    renderReplayResponseView(notice);
    updateReplaySearchPane("response", notice);
    els.replayFollowRedirectButton.classList.add("hidden");
    return;
  }
  const isRedirect = [301, 302, 303, 307, 308].includes(tab.responseRecord.status);
  const hasLocation = tab.responseRecord.response?.headers?.some((h) => h.name.toLowerCase() === "location");
  els.replayFollowRedirectButton.classList.toggle("hidden", !(isRedirect && hasLocation));
  els.replayResponseMeta.textContent = [
    `${formatStatus(tab.responseRecord.status)}`,
    `${tab.responseRecord.duration_ms} ms`,
    tab.responseRecord.response?.content_type || tab.responseRecord.request.content_type || "n/a",
  ].join(" · ");
  const rawResponseText = buildRawResponse(tab.responseRecord);
  const respMode = state.replayMessageViews.response;
  let responseText;
  if (respMode === "hex") {
    responseText = toHexDump(rawResponseText);
  } else if (respMode === "pretty") {
    responseText = prettyFormat(rawResponseText, tab.responseRecord.response);
  } else {
    responseText = compactFormat(rawResponseText);
  }
  renderReplayResponseView(responseText);
  updateReplaySearchPane("response", responseText);
}

function renderReplayViewTabs() {
  document.querySelectorAll(".replay-view-tab").forEach((btn) => {
    const target = btn.dataset.replayTarget;
    const view = btn.dataset.replayView;
    btn.classList.toggle("active", state.replayMessageViews[target] === view);
  });
}

function renderReplayViewContent(target) {
  const tab = getActiveReplayTab();
  if (!tab || tab.type === "websocket") return;

  if (target === "request") {
    const mode = state.replayMessageViews.request;
    if (mode === "hex") {
      els.replayRequestHighlight.removeAttribute("contenteditable");
      if (!tab.requestBytes) {
        tab.requestBytes = new TextEncoder().encode(tab.requestText);
        tab.requestOriginalBytes = new Uint8Array(tab.requestBytes);
      }
      els.replayRequestHighlight.innerHTML = renderEditableHexHtml(tab.requestBytes, tab.requestOriginalBytes);
      bindHexByteHandlers(els.replayRequestHighlight, tab);
      updateReplaySearchPane("request", toHexDumpFromBytes(tab.requestBytes));
    } else {
      if (tab.requestBytes) {
        tab.requestText = new TextDecoder().decode(tab.requestBytes);
        els.replayRequestEditor.value = tab.requestText;
        tab.requestBytes = null;
      tab.requestOriginalBytes = null;
      }
      if (!els.replayRequestHighlight.isContentEditable) {
        els.replayRequestHighlight.setAttribute("contenteditable", "plaintext-only");
      }
      let displayText = tab.requestText;
      if (mode === "pretty") {
        const fakeMsg = { content_type: headerValue(tab.baseRequest?.headers || [], "content-type") };
        displayText = prettyFormat(tab.requestText, fakeMsg);
      } else if (mode === "raw") {
        displayText = compactFormat(tab.requestText);
      }
      renderReplayRequestHighlight(displayText);
      updateReplaySearchPane("request", displayText);
    }
  }

  if (target === "response") {
    if (!tab.responseRecord) return;
    const mode = state.replayMessageViews.response;
    const rawText = buildRawResponse(tab.responseRecord);
    let displayText;
    if (mode === "hex") {
      displayText = toHexDump(rawText);
    } else if (mode === "pretty") {
      displayText = prettyFormat(rawText, tab.responseRecord.response);
    } else {
      displayText = rawText;
    }
    renderReplayResponseView(displayText);
    updateReplaySearchPane("response", displayText);
  }
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
  const mode = state.replayMessageViews[target] || "pretty";
  meta.innerHTML = buildSearchMeta(countLines(text), mode, searchResult.count);
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
              <td>${escapeHtml(rule.scope)}</td>
              <td>${escapeHtml(rule.target)}</td>
              <td class="text-truncate">${escapeHtml(rule.search || "—")}</td>
              <td class="text-truncate">${escapeHtml(rule.replace || "—")}</td>
              <td>${rule.regex ? "✓" : ""}</td>
              <td>${rule.case_sensitive ? "✓" : ""}</td>
            </tr>
          `;
        })
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="7">No replace rules are configured.</td>
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
    els.matchReplaceScope.value = "request";
    els.matchReplaceTarget.value = "any";
    els.matchReplaceSearch.value = "";
    els.matchReplaceReplace.value = "";
    els.matchReplaceRegex.checked = false;
    els.matchReplaceCaseSensitive.checked = false;
    els.deleteMatchReplaceRuleButton.disabled = true;
    els.saveMatchReplaceRuleButton.textContent = "Save";
    return;
  }

  els.matchReplaceEditorPath.textContent = `${selected.scope} / ${selected.target}`;
  els.matchReplaceEditorTitle.textContent = selected.search ? `${selected.search} → ${selected.replace || "∅"}` : "Edit rule";
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

  rule.description = "";
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

async function openFuzzerFromReplay() {
  const tab = getActiveReplayTab();
  if (!tab) return;
  const request = parseEditableRawRequest(tab.requestText, tab.baseRequest);
  state.fuzzerBaseRequest = request;
  state.fuzzerSourceTransactionId = tab.sourceTransactionId || null;
  state.fuzzerNotice = "";
  state.fuzzerRequestText = tab.requestText;
  state.fuzzerPayloadsText = "";
  state.fuzzerAttackRecord = null;
  state.activeTool = "fuzzer";
  scheduleWorkspaceStateSave();
  renderToolPanels();
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

async function sendToSequenceFromSelection() {
  let record = state.selectedRecord;
  if (!record && state.selectedId) {
    const response = await fetch(`/api/transactions/${state.selectedId}`);
    if (response.ok) record = await response.json();
  }
  if (!record || record.kind === "tunnel") return;

  const request = editableRequestFromRecord(record);
  if (!state.editingSequence) {
    await createNewSequence();
  }
  state.editingSequence.steps.push({
    id: crypto.randomUUID(),
    label: `${request.method} ${request.path}`,
    request,
    target: null,
    extractions: [],
  });
  state.activeTool = "sequence";
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

/* ─── Sequence/Macro ─── */

async function loadSequences() {
  const [defsResp, runsResp] = await Promise.all([
    fetch("/api/sequences"),
    fetch("/api/sequence-runs?limit=20"),
  ]);
  state.sequenceDefinitions = await defsResp.json();
  state.sequencePastRuns = await runsResp.json();
}

async function createNewSequence() {
  const def = {
    id: crypto.randomUUID(),
    name: "New Sequence",
    steps: [],
  };
  await fetch("/api/sequences", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(def),
  });
  await loadSequences();
  state.selectedSequenceId = def.id;
  state.editingSequence = JSON.parse(JSON.stringify(def));
  renderSequencePanel();
}

function selectSequence(id) {
  state.selectedSequenceId = id;
  const def = state.sequenceDefinitions.find((d) => d.id === id);
  state.editingSequence = def ? JSON.parse(JSON.stringify(def)) : null;
  state.sequenceRunResult = null;
  renderSequencePanel();
}

function addSequenceStep() {
  if (!state.editingSequence) return;
  state.editingSequence.steps.push({
    id: crypto.randomUUID(),
    label: `Step ${state.editingSequence.steps.length + 1}`,
    request: {
      scheme: "https", host: "", method: "GET", path: "/",
      headers: [], body: "", body_encoding: "utf8", preview_truncated: false,
    },
    target: null,
    extractions: [],
  });
  renderSequencePanel();
}

function removeSequenceStep(index) {
  if (!state.editingSequence) return;
  state.editingSequence.steps.splice(index, 1);
  renderSequencePanel();
}

function addExtractionRule(stepIndex) {
  if (!state.editingSequence) return;
  const step = state.editingSequence.steps[stepIndex];
  if (!step) return;
  step.extractions.push({
    variable_name: "",
    source: "response_body",
    pattern: "",
    group: 1,
  });
  renderSequencePanel();
}

function removeExtractionRule(stepIndex, ruleIndex) {
  if (!state.editingSequence) return;
  const step = state.editingSequence.steps[stepIndex];
  if (!step) return;
  step.extractions.splice(ruleIndex, 1);
  renderSequencePanel();
}

function syncSequenceStepFromDom() {
  if (!state.editingSequence) return;
  const container = document.getElementById("sequenceStepsContainer");
  if (!container) return;
  const cards = container.querySelectorAll(".sequence-step-card");
  cards.forEach((card, i) => {
    const step = state.editingSequence.steps[i];
    if (!step) return;
    const labelInput = card.querySelector(".step-label");
    if (labelInput) step.label = labelInput.value;
    const reqTextarea = card.querySelector(".step-request-text");
    if (reqTextarea) {
      const parsed = parseEditableRawRequest(reqTextarea.value, step.request);
      Object.assign(step.request, parsed);
    }
    card.querySelectorAll(".extraction-row").forEach((row, j) => {
      const rule = step.extractions[j];
      if (!rule) return;
      const varInput = row.querySelector(".ext-var");
      const sourceSelect = row.querySelector(".ext-source");
      const patternInput = row.querySelector(".ext-pattern");
      if (varInput) rule.variable_name = varInput.value;
      if (sourceSelect) rule.source = sourceSelect.value;
      if (patternInput) rule.pattern = patternInput.value;
    });
  });
}

async function saveCurrentSequence() {
  if (!state.editingSequence) return;
  syncSequenceStepFromDom();
  await fetch("/api/sequences", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(state.editingSequence),
  });
  await loadSequences();
  renderSequencePanel();
}

async function deleteSequence(id) {
  await fetch(`/api/sequences/${id}`, { method: "DELETE" });
  if (state.selectedSequenceId === id) {
    state.selectedSequenceId = null;
    state.editingSequence = null;
  }
  await loadSequences();
  renderSequencePanel();
}

async function runCurrentSequence() {
  if (!state.editingSequence) return;
  syncSequenceStepFromDom();
  await saveCurrentSequence();

  const runBtn = document.getElementById("runSequenceButton");
  runBtn.disabled = true;
  runBtn.textContent = "Running...";

  try {
    const response = await fetch(`/api/sequences/${state.editingSequence.id}/run`, {
      method: "POST",
    });
    if (!response.ok) {
      const errText = await response.text();
      showToast(`Sequence failed: ${errText}`, "error");
      return;
    }
    state.sequenceRunResult = await response.json();
    await loadSequences();
    scheduleRefresh();
  } catch (err) {
    showToast(`Sequence error: ${err.message}`, "error");
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = "Run";
    renderSequencePanel();
  }
}

function renderSequencePanel() {
  const listBody = document.getElementById("sequenceListBody");
  const editorTitle = document.getElementById("sequenceEditorTitle");
  const stepsContainer = document.getElementById("sequenceStepsContainer");
  const addStepBtn = document.getElementById("addSequenceStepButton");
  const saveBtn = document.getElementById("saveSequenceButton");
  const runBtn = document.getElementById("runSequenceButton");
  const runMeta = document.getElementById("sequenceRunMeta");
  const resultsBody = document.getElementById("sequenceRunResultsBody");
  const pastBody = document.getElementById("sequencePastRunsBody");

  // List
  listBody.innerHTML = state.sequenceDefinitions.length
    ? state.sequenceDefinitions.map((def) => {
        const selected = def.id === state.selectedSequenceId ? "selected" : "";
        return `<tr class="history-row ${selected}" data-seq-id="${def.id}">
          <td>${escapeHtml(def.name)}</td>
          <td>${def.steps.length}</td>
          <td><button class="secondary-action seq-delete" data-seq-delete="${def.id}" style="font-size:0.7rem;padding:2px 6px">&times;</button></td>
        </tr>`;
      }).join("")
    : `<tr class="empty-row"><td colspan="3">No sequences yet.</td></tr>`;

  listBody.querySelectorAll(".history-row").forEach((row) => {
    row.addEventListener("click", (e) => {
      if (e.target.closest(".seq-delete")) return;
      selectSequence(row.dataset.seqId);
    });
  });
  listBody.querySelectorAll(".seq-delete").forEach((btn) => {
    btn.addEventListener("click", () => deleteSequence(btn.dataset.seqDelete).catch((e) => console.error(e)));
  });

  // Editor
  const editing = state.editingSequence;
  const hasSequence = !!editing;
  addStepBtn.disabled = !hasSequence;
  saveBtn.disabled = !hasSequence;
  runBtn.disabled = !hasSequence || !editing?.steps?.length;
  editorTitle.textContent = hasSequence ? editing.name : "No sequence selected";

  if (hasSequence) {
    stepsContainer.innerHTML = editing.steps.map((step, idx) => {
      const reqText = buildEditableRawRequest(step.request);
      const extractionsHtml = step.extractions.map((rule, rIdx) => `
        <div class="extraction-row">
          <input class="ext-var" placeholder="Variable name" value="${escapeHtml(rule.variable_name)}" />
          <select class="ext-source">
            <option value="response_body"${rule.source === "response_body" ? " selected" : ""}>Body</option>
            <option value="response_header"${rule.source === "response_header" ? " selected" : ""}>Header</option>
          </select>
          <input class="ext-pattern" placeholder="Regex / header name" value="${escapeHtml(rule.pattern)}" />
          <button class="ext-remove" data-step="${idx}" data-rule="${rIdx}" title="Remove">&times;</button>
        </div>
      `).join("");

      return `<div class="sequence-step-card" data-step-idx="${idx}">
        <div class="step-header">
          <span class="step-number">#${idx + 1}</span>
          <input class="step-label" value="${escapeHtml(step.label)}" placeholder="Step label" />
          <button class="step-remove" data-remove-step="${idx}" title="Remove step">&times;</button>
        </div>
        <textarea class="step-request-text" spellcheck="false">${escapeHtml(reqText)}</textarea>
        <details class="step-extractions">
          <summary>Extractions (${step.extractions.length}) <button class="ext-add" data-add-ext="${idx}" style="font-size:0.7rem;margin-left:8px">+ Extract</button></summary>
          ${extractionsHtml}
        </details>
      </div>`;
    }).join("");

    stepsContainer.querySelectorAll(".step-remove").forEach((btn) => {
      btn.addEventListener("click", () => {
        syncSequenceStepFromDom();
        removeSequenceStep(parseInt(btn.dataset.removeStep, 10));
      });
    });
    stepsContainer.querySelectorAll(".ext-add").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        syncSequenceStepFromDom();
        addExtractionRule(parseInt(btn.dataset.addExt, 10));
      });
    });
    stepsContainer.querySelectorAll(".ext-remove").forEach((btn) => {
      btn.addEventListener("click", () => {
        syncSequenceStepFromDom();
        removeExtractionRule(parseInt(btn.dataset.step, 10), parseInt(btn.dataset.rule, 10));
      });
    });
  } else {
    stepsContainer.innerHTML = `<div style="padding:20px;color:var(--text-muted);font-size:0.85rem">Select or create a sequence to start building steps.</div>`;
  }

  // Run results
  const run = state.sequenceRunResult;
  if (run) {
    runMeta.textContent = `${run.sequence_name} — ${run.status} — ${run.step_results.length} steps`;
    resultsBody.innerHTML = run.step_results.map((sr, i) => {
      const extracted = Object.entries(sr.extracted || {}).map(([k, v]) => `${k}=${v}`).join(", ");
      return `<tr>
        <td>${i + 1}</td>
        <td>${escapeHtml(sr.label)}</td>
        <td>${sr.error ? `<span style="color:var(--danger)">${escapeHtml(sr.error)}</span>` : escapeHtml(String(sr.status ?? "-"))}</td>
        <td>${sr.duration_ms != null ? `${sr.duration_ms} ms` : "-"}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${escapeHtml(extracted || "-")}</td>
      </tr>`;
    }).join("");
  } else {
    runMeta.textContent = "No sequence run yet.";
    resultsBody.innerHTML = `<tr class="empty-row"><td colspan="5">Run a sequence to see results.</td></tr>`;
  }

  // Past runs
  pastBody.innerHTML = state.sequencePastRuns.length
    ? state.sequencePastRuns.map((r) => `<tr>
        <td>${escapeHtml(r.sequence_name)}</td>
        <td>${escapeHtml(r.status)}</td>
        <td>${r.step_count}</td>
        <td>${escapeHtml(formatTimestamp(r.started_at))}</td>
      </tr>`).join("")
    : `<tr class="empty-row"><td colspan="4">No past runs.</td></tr>`;
}

async function toggleIntercept() {
  if (!state.runtime) {
    return;
  }

  const turningOff = state.runtime.intercept_enabled;
  // Optimistic UI update — render immediately, sync in background
  state.runtime.intercept_enabled = !state.runtime.intercept_enabled;
  renderInterceptStatus();

  fetch("/api/runtime", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ intercept_enabled: state.runtime.intercept_enabled }),
  }).then((r) => r.json()).then((rt) => { state.runtime = rt; }).catch(console.error);

  if (turningOff) {
    Promise.all([
      fetch("/api/intercepts/forward-all", { method: "POST" }),
      fetch("/api/response-intercepts/forward-all", { method: "POST" }),
    ]).then(() => Promise.all([loadIntercepts(false), loadResponseIntercepts(false)]))
      .then(() => scheduleRefresh())
      .catch(console.error);
  }
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
      upstream_insecure: els.proxySettingUpstreamInsecure.checked,
      scope_patterns: scopePatterns,
      passthrough_hosts: passthroughHosts,
      oast_enabled: document.getElementById("proxySettingOastEnabled")?.checked ?? false,
      oast_provider: document.getElementById("proxySettingOastProvider")?.value || "custom",
      oast_server_url: document.getElementById("proxySettingOastServerUrl")?.value?.trim() || "",
      oast_token: document.getElementById("proxySettingOastToken")?.value?.trim() || "",
      oast_polling_interval_secs: parseInt(document.getElementById("proxySettingOastInterval")?.value) || 5,
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
  const startupResult = await startupResponse.json();
  state.settings.startup = startupResult;

  // If proxy was rebound, update the main proxy_addr in settings too
  if (startupResult.rebound === true) {
    state.settings.proxy_addr = startupResult.active_proxy_addr;
  }

  renderInterceptStatus();
  renderProxySettings();
  renderHistory();
  return startupResult;
}

async function forwardSelectedIntercept() {
  if (!state.selectedInterceptRecord) {
    return;
  }

  const id = state.selectedInterceptRecord.id;
  const request = parseEditableRawRequest(
    els.interceptRequestEditor.value,
    state.selectedInterceptRecord.request,
  );

  // Optimistic: remove from UI immediately
  state.intercepts = state.intercepts.filter((i) => i.id !== id);
  state.selectedInterceptRecord = null;
  state.interceptEditorSeedId = null;
  state.selectedInterceptId = state.intercepts[0]?.id ?? null;
  renderIntercepts();
  updateInterceptQueueBadges();

  fetch(`/api/intercepts/${id}/forward`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ request }),
  }).then(() => { loadIntercepts(true).catch(console.error); scheduleRefresh(); })
    .catch((e) => { console.error(e); loadIntercepts(false).catch(console.error); });
}

async function dropSelectedIntercept() {
  if (!state.selectedInterceptRecord) {
    return;
  }

  const id = state.selectedInterceptRecord.id;

  // Optimistic: remove from UI immediately
  state.intercepts = state.intercepts.filter((i) => i.id !== id);
  state.selectedInterceptRecord = null;
  state.interceptEditorSeedId = null;
  state.selectedInterceptId = state.intercepts[0]?.id ?? null;
  renderIntercepts();
  updateInterceptQueueBadges();

  fetch(`/api/intercepts/${id}/drop`, { method: "POST" })
    .then(() => { loadIntercepts(true).catch(console.error); scheduleRefresh(); })
    .catch((e) => { console.error(e); loadIntercepts(false).catch(console.error); });
}

/* ─── Response Intercept ─── */

async function loadResponseIntercepts(preserveSelection = true) {
  const response = await fetch("/api/response-intercepts");
  state.responseIntercepts = await response.json();

  if (!preserveSelection || !state.responseIntercepts.some((item) => item.id === state.selectedResponseInterceptId)) {
    state.selectedResponseInterceptId = state.responseIntercepts[0]?.id ?? null;
  }

  renderResponseIntercepts();
  updateInterceptQueueBadges();
  // Auto-switch to Response Queue when responses arrive and Request Queue is empty
  if (state.responseIntercepts.length > 0 && state.intercepts.length === 0 && state.interceptQueueTab === "request") {
    switchInterceptQueueTab("response");
  }
  if (state.selectedResponseInterceptId) {
    await loadResponseInterceptDetail(state.selectedResponseInterceptId);
  } else {
    state.selectedResponseInterceptRecord = null;
    renderResponseIntercepts();
  }
}

async function loadResponseInterceptDetail(id) {
  const response = await fetch(`/api/response-intercepts/${id}`);
  if (!response.ok) {
    state.selectedResponseInterceptRecord = null;
    renderResponseIntercepts();
    return;
  }

  state.selectedResponseInterceptRecord = await response.json();
  renderResponseIntercepts();
}

function buildEditableRawResponse(resp) {
  let text = `HTTP/1.1 ${resp.status}\r\n`;
  for (const h of resp.headers || []) {
    text += `${h.name}: ${h.value}\r\n`;
  }
  text += "\r\n";
  if (resp.body_encoding === "base64") {
    try {
      text += atob(resp.body);
    } catch {
      text += resp.body;
    }
  } else {
    text += resp.body || "";
  }
  return text;
}

function parseEditableRawResponse(text, original) {
  const lines = text.split(/\r?\n/);
  const statusLine = lines[0] || "";
  const statusMatch = statusLine.match(/^HTTP\/[\d.]+ (\d+)/);
  const status = statusMatch ? parseInt(statusMatch[1], 10) : (original?.status || 200);

  const headers = [];
  let bodyStart = 1;
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (line === "" || line === "\r") {
      bodyStart = i + 1;
      break;
    }
    const colonIdx = line.indexOf(":");
    if (colonIdx > 0) {
      headers.push({
        name: line.substring(0, colonIdx).trim(),
        value: line.substring(colonIdx + 1).trim(),
      });
      bodyStart = i + 1;
    } else {
      bodyStart = i;
      break;
    }
  }

  const bodyText = lines.slice(bodyStart).join("\n");
  const isText = !original || original.body_encoding === "utf8";

  // Auto-update Content-Length if enabled
  if (document.getElementById("proxySettingAutoContentLength")?.checked && bodyText) {
    const bodyBytes = new TextEncoder().encode(bodyText).length;
    const clIdx = headers.findIndex((h) => h.name.toLowerCase() === "content-length");
    if (clIdx !== -1) {
      headers[clIdx].value = String(bodyBytes);
    }
  }

  return {
    status,
    headers,
    body: isText ? bodyText : btoa(bodyText),
    body_encoding: isText ? "utf8" : "base64",
  };
}

function renderResponseIntercepts() {
  const filteredResponseIntercepts = state.interceptInScopeOnly
    ? state.responseIntercepts.filter((item) => isInScopeHost(item.host))
    : state.responseIntercepts;
  els.responseInterceptTableBody.innerHTML = filteredResponseIntercepts.length
    ? filteredResponseIntercepts
        .map((item) => {
          const selected = item.id === state.selectedResponseInterceptId ? "selected" : "";
          return `
            <tr class="history-row ${selected}" data-id="${item.id}">
              <td class="iq-col-status">${escapeHtml(String(item.status))}</td>
              <td class="iq-col-method">${escapeHtml(item.method)}</td>
              <td class="iq-col-host text-truncate">${escapeHtml(item.host)}</td>
              <td class="iq-col-path text-truncate">${escapeHtml(item.path || "/")}</td>
              <td class="iq-col-time">${escapeHtml(formatTimestamp(item.started_at))}</td>
            </tr>
          `;
        })
        .join("")
    : `
        <tr class="empty-row">
          <td colspan="5">Response intercept queue is empty.</td>
        </tr>
      `;

  Array.from(els.responseInterceptTableBody.querySelectorAll(".history-row")).forEach((row) => {
    row.addEventListener("click", () => {
      state.selectedResponseInterceptId = row.dataset.id;
      loadResponseInterceptDetail(row.dataset.id).catch((error) => console.error(error));
    });
  });

  if (!state.selectedResponseInterceptRecord) {
    state.responseInterceptEditorSeedId = null;
    if (state.interceptQueueTab === "response") {
      els.interceptDetailPath.textContent = "Response Intercept";
      els.interceptDetailTitle.textContent = "No response selected";
      els.interceptResponseEditor.value = "";
      renderInterceptResponseHighlight("");
      els.interceptMeta.textContent = state.runtime?.intercept_enabled
        ? "Intercept is on. Matched responses will queue here."
        : "Intercept is off. Toggle it on to pause responses before forwarding.";
    }
    els.forwardResponseInterceptButton.disabled = true;
    els.dropResponseInterceptButton.disabled = true;
    return;
  }

  const rec = state.selectedResponseInterceptRecord;
  if (state.interceptQueueTab === "response") {
    els.interceptDetailPath.textContent = `${rec.scheme.toUpperCase()} / ${rec.method} ${rec.host}${rec.path}`;
    els.interceptDetailTitle.textContent = `${rec.status} Response`;
    if (state.responseInterceptEditorSeedId !== rec.id || document.activeElement !== els.interceptResponseEditor) {
      els.interceptResponseEditor.value = buildEditableRawResponse(rec.response);
      state.responseInterceptEditorSeedId = rec.id;
    }
    renderInterceptResponseHighlight(els.interceptResponseEditor.value);
    els.interceptMeta.textContent = `Response queued at ${formatTimestamp(rec.started_at)}`;
  }
  els.forwardResponseInterceptButton.disabled = false;
  els.dropResponseInterceptButton.disabled = false;
}

async function forwardSelectedResponseIntercept() {
  if (!state.selectedResponseInterceptRecord) return;

  const id = state.selectedResponseInterceptRecord.id;
  const editedResponse = parseEditableRawResponse(
    els.interceptResponseEditor.value,
    state.selectedResponseInterceptRecord.response,
  );

  // Optimistic UI
  state.responseIntercepts = state.responseIntercepts.filter((i) => i.id !== id);
  state.selectedResponseInterceptRecord = null;
  state.responseInterceptEditorSeedId = null;
  state.selectedResponseInterceptId = state.responseIntercepts[0]?.id ?? null;
  renderResponseIntercepts();
  updateInterceptQueueBadges();

  fetch(`/api/response-intercepts/${id}/forward`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ response: editedResponse }),
  }).then(() => { loadResponseIntercepts(true).catch(console.error); scheduleRefresh(); })
    .catch((e) => { console.error(e); loadResponseIntercepts(false).catch(console.error); });
}

async function dropSelectedResponseIntercept() {
  if (!state.selectedResponseInterceptRecord) return;

  const id = state.selectedResponseInterceptRecord.id;

  // Optimistic UI
  state.responseIntercepts = state.responseIntercepts.filter((i) => i.id !== id);
  state.selectedResponseInterceptRecord = null;
  state.responseInterceptEditorSeedId = null;
  state.selectedResponseInterceptId = state.responseIntercepts[0]?.id ?? null;
  renderResponseIntercepts();
  updateInterceptQueueBadges();

  fetch(`/api/response-intercepts/${id}/drop`, { method: "POST" })
    .then(() => { loadResponseIntercepts(true).catch(console.error); scheduleRefresh(); })
    .catch((e) => { console.error(e); loadResponseIntercepts(false).catch(console.error); });
}

function updateInterceptQueueBadges() {
  const reqCount = state.intercepts.length;
  const resCount = state.responseIntercepts.length;
  els.interceptQueueTabRequest.textContent = reqCount > 0 ? `Request Queue (${reqCount})` : "Request Queue";
  els.interceptQueueTabResponse.textContent = resCount > 0 ? `Response Queue (${resCount})` : "Response Queue";
}

function switchInterceptQueueTab(tab) {
  state.interceptQueueTab = tab;
  els.interceptQueueTabRequest.classList.toggle("active", tab === "request");
  els.interceptQueueTabResponse.classList.toggle("active", tab === "response");

  els.interceptRequestTable.classList.toggle("hidden", tab !== "request");
  els.responseInterceptTable.classList.toggle("hidden", tab !== "response");

  els.interceptRequestEditorPanel.classList.toggle("hidden", tab !== "request");
  els.interceptResponseEditorPanel.classList.toggle("hidden", tab !== "response");

  els.interceptRequestActions.classList.toggle("hidden", tab !== "request");
  els.responseInterceptActions.classList.toggle("hidden", tab !== "response");

  if (tab === "request") {
    renderIntercepts();
  } else {
    renderResponseIntercepts();
  }
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

  // If this is a WebSocket upgrade (status 101), open as WS Replay
  if (record.status === 101 || record.request?.headers?.some(
    (h) => h.name.toLowerCase() === "upgrade" && h.value.toLowerCase() === "websocket"
  )) {
    const scheme = record.scheme === "https" ? "wss" : record.scheme === "http" ? "ws" : record.scheme || "wss";
    createWsReplayTab({
      scheme,
      host: record.host?.replace(/:443$|:80$/, "") || "",
      port: record.host?.includes(":") ? parseInt(record.host.split(":").pop()) : (scheme === "wss" ? 443 : 80),
      path: record.path || "/",
      headers: record.request?.headers || [],
    });
    state.activeTool = "replay";
    scheduleWorkspaceStateSave();
    renderToolPanels();
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
  if (!tab || tab.type === "websocket") {
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

let _replayAbortController = null;

function setReplaySending(sending) {
  els.sendReplayButton.disabled = sending;
  els.cancelReplayButton.disabled = !sending;
  els.replayBackButton.disabled = sending;
  els.replayForwardButton.disabled = sending;
}

function cancelReplaySend() {
  if (_replayAbortController) {
    _replayAbortController.abort();
    _replayAbortController = null;
  }
  setReplaySending(false);
  els.replayResponseMeta.textContent = "Cancelled.";
  renderReplayResponseView("");
}

async function sendReplay() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type === "websocket") {
    return;
  }

  // Enter sending state immediately
  tab.responseRecord = null;
  tab.notice = "";
  els.replayResponseMeta.textContent = "";
  renderReplayResponseView("");
  setReplaySending(true);

  let request, requestText, target;
  try {
    const fallback = tab.baseRequest || createDefaultEditableRequest();
    request = parseEditableRawRequest(els.replayRequestEditor.value, fallback);
    requestText = els.replayRequestEditor.value;
    target = getRepeaterTargetConfig(tab, request);
  } catch (e) {
    setReplaySending(false);
    els.replayResponseMeta.textContent = "Error";
    renderReplayResponseView(e.message || "Failed to parse request.");
    return;
  }

  // HTTP version: prefer dropdown selection, fall back to request line
  const versionDropdown = document.getElementById("replayHttpVersionSelect")?.value;
  let httpVersion = versionDropdown || undefined;
  if (!httpVersion) {
    const firstLine = (requestText || "").split(/\r?\n/)[0] || "";
    const verMatch = firstLine.match(/^[A-Z]+\s+\S+\s+(HTTP\/[0-9.]+)$/i);
    httpVersion = verMatch ? verMatch[1] : undefined;
  }

  _replayAbortController = new AbortController();

  let response;
  try {
    response = await fetch("/api/replay/send", {
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
        http_version: httpVersion,
      }),
      signal: _replayAbortController.signal,
    });
  } catch (e) {
    if (e.name === "AbortError") return; // cancelled
    throw e;
  } finally {
    _replayAbortController = null;
    setReplaySending(false);
  }

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
    renderReplayResponseOnly(tab);
    syncReplayToolbar(tab);
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
  // Only update response side — don't re-render request to preserve cursor/scroll
  renderReplayResponseOnly(tab);
  syncReplayToolbar(tab);
  renderReplayViewTabs();
  scheduleRefresh();
}

async function followRedirect() {
  const tab = getActiveReplayTab();
  if (!tab || !tab.responseRecord) return;

  const resp = tab.responseRecord.response;
  if (!resp) return;

  const status = tab.responseRecord.status;
  const locationHeader = resp.headers.find((h) => h.name.toLowerCase() === "location");
  if (!locationHeader) return;

  // Parse location URL
  const location = locationHeader.value;
  let newScheme = tab.targetScheme;
  let newHost = tab.targetHost;
  let newPort = tab.targetPort;
  let newPath = location;

  if (/^https?:\/\//i.test(location)) {
    try {
      const url = new URL(location);
      newScheme = url.protocol.replace(":", "");
      newHost = url.hostname;
      newPort = url.port || (newScheme === "https" ? "443" : "80");
      newPath = `${url.pathname || "/"}${url.search || ""}`;
    } catch (_) {
      newPath = location;
    }
  } else if (location.startsWith("/")) {
    newPath = location;
  } else {
    // Relative path
    const currentPath = tab.baseRequest?.path || "/";
    const base = currentPath.substring(0, currentPath.lastIndexOf("/") + 1);
    newPath = base + location;
  }

  // Build new request from current request
  const fallback = tab.baseRequest || createDefaultEditableRequest();
  const currentRequest = parseEditableRawRequest(els.replayRequestEditor.value, fallback);

  // 301/302/303 → GET (drop body), 307/308 → keep method
  const useGet = status === 301 || status === 302 || status === 303;
  const newMethod = useGet ? "GET" : currentRequest.method;
  const newBody = useGet ? "" : currentRequest.body;

  // Collect Set-Cookie from response
  const setCookies = resp.headers
    .filter((h) => h.name.toLowerCase() === "set-cookie")
    .map((h) => {
      // Extract just the cookie name=value (before ;)
      const raw = h.value.split(";")[0].trim();
      return raw;
    })
    .filter(Boolean);

  // Merge with existing cookies
  let existingCookies = [];
  const cookieHeader = currentRequest.headers.find((h) => h.name.toLowerCase() === "cookie");
  if (cookieHeader) {
    existingCookies = cookieHeader.value.split(";").map((c) => c.trim()).filter(Boolean);
  }

  // Override existing cookies with new ones (by name)
  const cookieMap = new Map();
  for (const c of existingCookies) {
    const eqIdx = c.indexOf("=");
    const name = eqIdx > 0 ? c.substring(0, eqIdx) : c;
    cookieMap.set(name, c);
  }
  for (const c of setCookies) {
    const eqIdx = c.indexOf("=");
    const name = eqIdx > 0 ? c.substring(0, eqIdx) : c;
    cookieMap.set(name, c);
  }

  // Build new headers
  const newHeaders = currentRequest.headers
    .filter((h) => h.name.toLowerCase() !== "cookie" && h.name.toLowerCase() !== "host")
    .map((h) => ({ name: h.name, value: h.value }));

  // Add updated host
  newHeaders.unshift({ name: "host", value: newHost + (newPort && newPort !== "443" && newPort !== "80" ? `:${newPort}` : "") });

  // Add merged cookies
  if (cookieMap.size > 0) {
    newHeaders.push({ name: "cookie", value: Array.from(cookieMap.values()).join("; ") });
  }

  const newRequest = {
    scheme: newScheme,
    host: newHost,
    method: newMethod,
    path: newPath,
    headers: newHeaders,
    body: newBody,
    body_encoding: "utf8",
    preview_truncated: false,
  };

  // Update tab target
  tab.targetScheme = newScheme;
  tab.targetHost = newHost;
  tab.targetPort = newPort;

  // Build raw request text and set in editor
  const requestText = buildEditableRawRequest(newRequest);
  tab.requestText = requestText;
  tab.baseRequest = cloneEditableRequest(newRequest);
  els.replayRequestEditor.value = requestText;
  renderReplayRequestHighlight(requestText);

  // Send the follow request
  const target = { scheme: newScheme, host: newHost, port: newPort };
  const response = await fetch("/api/replay/send", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ request: newRequest, target, source_transaction_id: tab.sourceTransactionId }),
  });

  if (!response.ok) {
    tab.responseRecord = null;
    tab.notice = await response.text();
    recordRepeaterHistory(tab, { request: newRequest, requestText, responseRecord: null, notice: tab.notice, target });
    scheduleWorkspaceStateSave();
    renderReplay();
    return;
  }

  tab.notice = "";
  tab.responseRecord = await response.json();
  recordRepeaterHistory(tab, { request: newRequest, requestText, responseRecord: tab.responseRecord, notice: "", target });
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

  if (tab.type === "websocket") {
    createWsReplayTab({
      scheme: tab.wsScheme,
      host: tab.wsHost,
      port: tab.wsPort,
      path: tab.wsPath,
      headers: [...(tab.wsHeaders || [])],
      handshakeText: tab.wsHandshakeText || "",
    });
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
    pinned: !!seed.pinned,
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

function getReplayTabVisualOrder() {
  return [...state.replayTabs].sort((a, b) => {
    if (a.pinned && !b.pinned) return -1;
    if (!a.pinned && b.pinned) return 1;
    return 0;
  });
}

function renderReplayTabs() {
  const sortedTabs = getReplayTabVisualOrder();

  els.replayTabStrip.innerHTML = sortedTabs
    .map((tab) => {
      const isActive = tab.id === state.activeReplayTabId;
      const active = isActive ? "active" : "";
      const pinned = tab.pinned ? "pinned" : "";
      const showPinBtn = isActive || tab.pinned;
      const pinBtn = showPinBtn ? `<button class="replay-tab-pin-btn ${tab.pinned ? "on" : ""}" type="button" aria-label="Pin tab">\uD83D\uDCCC</button>` : "";
      return `
        <div class="replay-tab ${active} ${pinned}" data-replay-tab-id="${tab.id}">
          ${pinBtn}
          <button class="replay-tab-button" type="button">${escapeHtml(replayTabLabel(tab))}</button>
          <button class="replay-tab-close" type="button" aria-label="Close replay tab">\u00d7</button>
        </div>
      `;
    })
    .join("");

  Array.from(els.replayTabStrip.querySelectorAll(".replay-tab")).forEach((tabElement) => {
    const id = tabElement.dataset.replayTabId;
    tabElement.querySelector(".replay-tab-button")?.addEventListener("click", () => {
      state.activeReplayTabId = id;
      scheduleWorkspaceStateSave();
      renderReplay();
    });
    tabElement.querySelector(".replay-tab-pin-btn")?.addEventListener("click", (event) => {
      event.stopPropagation();
      toggleReplayTabPin(id);
    });
    tabElement.querySelector(".replay-tab-close")?.addEventListener("click", (event) => {
      event.stopPropagation();
      closeRepeaterTab(id);
    });
  });

  // Scroll active tab into view
  scrollActiveReplayTabIntoView();
}

function toggleReplayTabPin(id) {
  const tab = state.replayTabs.find((t) => t.id === id);
  if (!tab) return;
  tab.pinned = !tab.pinned;
  // Flush immediately so pin state survives quick app quit
  saveWorkspaceState().catch((error) => console.error(error));
  renderReplayTabs();
}


function scrollActiveReplayTabIntoView() {
  const activeTab = els.replayTabStrip.querySelector(".replay-tab.active");
  if (activeTab) {
    activeTab.scrollIntoView({ behavior: "smooth", inline: "nearest", block: "nearest" });
  }
}

function closeRepeaterTab(id) {
  const index = state.replayTabs.findIndex((tab) => tab.id === id);
  if (index === -1) {
    return;
  }

  const closingTab = state.replayTabs[index];
  if (closingTab.type === "websocket") {
    stopWsPoll(closingTab);
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
  if (tab.type === "websocket") {
    const host = tab.wsHost || "draft";
    return `${tab.sequence}. WS ${host}`;
  }
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
  // Clear hex state so it re-generates from the new requestText
  tab.requestBytes = null;
  tab.requestOriginalBytes = null;
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
      return `<td>${item.sequence != null ? item.sequence + 1 : entry.index + 1}</td>`;
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
  if (snapshot?.ws_column_widths && typeof snapshot.ws_column_widths === "object") {
    Object.entries(snapshot.ws_column_widths).forEach(([k, v]) => {
      if (WS_COLUMN_RULES[k] && WS_COLUMN_RULES[k].max > 0 && typeof v === "number") {
        state.wsColumnWidths[k] = clamp(v, WS_COLUMN_RULES[k].min, WS_COLUMN_RULES[k].max);
      }
    });
  }
  state.workbenchHeight = sanitizeWorkbenchHeight(snapshot?.workbench_height);
  applyDisplaySettingsState();
  renderHistoryHeader();
  applyHistoryColumnWidths();
  applyWsColumnWidths();

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
    ws_column_widths: { ...state.wsColumnWidths },
    workbench_height: state.workbenchHeight > 0 ? state.workbenchHeight : null,
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

function syncHttpInScopePill() {
  const pill = document.getElementById("httpInScopeToggle");
  if (pill) pill.classList.toggle("active", !!state.filterSettings.inScopeOnly);
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
  syncHttpInScopePill();
  scheduleRefresh();
}

async function openCertificateFolder() {
  try {
    await fetch("/api/certificates/reveal", { method: "POST" });
  } catch (error) {
    console.error("Failed to open certificate folder:", error);
  }
}

function buildMessagePresentation(target, record) {
  const mode = state.messageViews[target];
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
  return target === "request" ? buildRawRequest(fakeOriginal) : buildRawResponse(fakeOriginal);
}

function buildRawRequest(record) {
  const httpVer = record.http_version || "HTTP/1.1";
  const startLine = record.kind === "tunnel"
    ? `CONNECT ${record.host} ${httpVer}`
    : `${record.method} ${record.path || "/"} ${httpVer}`;
  const merged = mergeHeaders(record.request.headers);
  // Ensure a host header is present — the proxy stores the host separately
  // and some tunnelled HTTPS requests omit Host from the captured headers.
  if (record.host && !merged.some((h) => h.name.toLowerCase() === "host")) {
    merged.unshift({ name: "host", value: record.host });
  }
  const headers = merged
    .map((header) => `${header.name}: ${header.value}`)
    .join("\n");
  const body = renderBody(record.request);
  return `${startLine}\n${headers}\n\n${body}`.trim();
}

function mergeHeaders(headers) {
  const merged = [];
  const cookieParts = [];
  for (const h of headers) {
    if (h.name.toLowerCase() === "cookie") {
      cookieParts.push(h.value);
    } else {
      merged.push(h);
    }
  }
  if (cookieParts.length) {
    merged.push({ name: "cookie", value: cookieParts.join("; ") });
  }
  return merged;
}

function buildRawResponse(record) {
  if (!record.response) {
    return "No response was captured for this exchange.";
  }

  const headers = record.response.headers
    .map((header) => `${header.name}: ${header.value}`)
    .join("\n");
  const body = renderBody(record.response);
  const httpVer = record.http_version || "HTTP/1.1";
  return `${httpVer} ${record.status ?? 0}\n${headers}\n\n${body}`.trim();
}

function buildFindingsRawMessage(record, side) {
  const msg = side === "request" ? record.request : record.response;
  const httpVer = record.http_version || "HTTP/1.1";
  if (side === "request") {
    const startLine = record.kind === "tunnel"
      ? `CONNECT ${record.host} ${httpVer}`
      : `${record.method} ${record.path || "/"} ${httpVer}`;
    const merged = mergeHeaders(record.request.headers);
    if (record.host && !merged.some((h) => h.name.toLowerCase() === "host")) {
      merged.unshift({ name: "host", value: record.host });
    }
    const headers = merged.map((h) => `${h.name}: ${h.value}`).join("\n");
    const body = findingsBodyPlaceholder(msg);
    return `${startLine}\n${headers}\n\n${body}`.trim();
  }
  if (!msg) return "No response was captured for this exchange.";
  const headers = msg.headers.map((h) => `${h.name}: ${h.value}`).join("\n");
  const body = findingsBodyPlaceholder(msg);
  return `${httpVer} ${record.status ?? 0}\n${headers}\n\n${body}`.trim();
}

function findingsBodyPlaceholder(msg) {
  if (!msg || !msg.body_preview) return "";
  if (msg.body_encoding === "base64") {
    const ct = msg.content_type || "binary";
    return `[${ct}, ${formatSize(msg.body_size)}]`;
  }
  if (msg.body_preview.length > 16000) {
    return msg.body_preview.slice(0, 16000) + "\n\n[preview truncated for performance]";
  }
  return msg.preview_truncated
    ? `${msg.body_preview}\n\n[preview truncated]`
    : msg.body_preview;
}

function buildRawWebsocketRequest(session) {
  const headers = mergeHeaders(session.request.headers)
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

  if (contentType.includes("json")) {
    try {
      return `${head}${divider}${JSON.stringify(JSON.parse(body), null, 2)}`;
    } catch (_error) {
      return text;
    }
  }

  // Fallback: try to detect JSON even if Content-Type doesn't say json
  const trimmed = body.trimStart();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      return `${head}${divider}${JSON.stringify(JSON.parse(body), null, 2)}`;
    } catch (_error) {
      // not valid JSON, return as-is
    }
  }

  return text;
}

function compactFormat(text) {
  const divider = "\n\n";
  const boundary = text.indexOf(divider);
  if (boundary === -1) return text;
  const head = text.slice(0, boundary);
  const body = text.slice(boundary + divider.length);
  const trimmed = body.trimStart();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      return `${head}${divider}${JSON.stringify(JSON.parse(body))}`;
    } catch (_) { /* not valid JSON */ }
  }
  return text;
}

function editableRequestFromRecord(record) {
  return {
    scheme: record.scheme,
    host: record.host,
    method: record.method,
    path: record.path || "/",
    http_version: record.http_version,
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
  const httpVer = request.http_version || "HTTP/1.1";
  const head = `${request.method} ${request.path || "/"} ${httpVer}`;
  const headerBlock = mergeHeaders(headers).map((header) => `${header.name}: ${header.value}`).join("\n");
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

  // Auto-update Content-Length if enabled
  if (document.getElementById("proxySettingAutoContentLength")?.checked && body) {
    const bodyBytes = new TextEncoder().encode(body).length;
    const clIdx = headers.findIndex((h) => h.name.toLowerCase() === "content-length");
    if (clIdx !== -1) {
      headers[clIdx].value = String(bodyBytes);
    }
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

function showFrameDetail(frame) {
  const isClient = frame.direction === "client_to_server";
  const dirClass = isClient ? "dir-client" : "dir-server";
  const dirLabel = isClient ? "client \u2192" : "\u2190 server";
  els.frameDetailMeta.innerHTML = `
    <span>#${(frame.index ?? 0) + 1}</span>
    <span class="${dirClass}">${dirLabel}</span>
    <span>${escapeHtml(frame.kind)}</span>
    <span>${escapeHtml(formatSize(frame.body_size))}</span>
  `;

  let body = frame.body_preview || "(empty)";
  if (frame.body_encoding === "base64") {
    try {
      body = atob(frame.body_preview);
    } catch {
      body = `[base64] ${frame.body_preview}`;
    }
  }

  // Try to pretty-print JSON
  try {
    const parsed = JSON.parse(body);
    body = JSON.stringify(parsed, null, 2);
  } catch {
    // not JSON, keep as-is
  }

  // Syntax-highlight the body (auto-detect per line)
  const highlighted = body
    .split("\n")
    .map((line) => highlightBodyLine(line))
    .join("\n");
  els.frameDetailBody.innerHTML = highlighted;
  els.frameDetailResizer.classList.remove("hidden");
  els.frameDetailPanel.classList.remove("hidden");
}

function hideFrameDetail() {
  els.frameDetailResizer.classList.add("hidden");
  els.frameDetailPanel.classList.add("hidden");
  els.websocketFramesBody.querySelectorAll(".ws-frame-bubble.selected").forEach((r) => r.classList.remove("selected"));
}

function initFrameDetailResizer() {
  const resizer = els.frameDetailResizer;
  if (!resizer) return;
  const container = resizer.parentElement;

  let startY = 0;
  let startHeight = 0;

  resizer.addEventListener("mousedown", (e) => {
    e.preventDefault();
    startY = e.clientY;
    startHeight = els.frameDetailPanel.getBoundingClientRect().height;
    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
    document.body.style.cursor = "row-resize";
    document.body.style.userSelect = "none";
  });

  function onMouseMove(e) {
    const delta = startY - e.clientY;
    const newHeight = Math.max(120, startHeight + delta);
    const maxHeight = container.getBoundingClientRect().height * 0.8;
    const h = Math.min(newHeight, maxHeight);
    els.frameDetailPanel.style.flex = "0 0 " + h + "px";
  }

  function onMouseUp() {
    document.removeEventListener("mousemove", onMouseMove);
    document.removeEventListener("mouseup", onMouseUp);
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
  }
}

function initFrameDetailResizer() {
  const resizer = els.frameDetailResizer;
  if (!resizer) return;
  const container = resizer.parentElement;

  let startY = 0;
  let startHeight = 0;

  resizer.addEventListener("mousedown", (e) => {
    e.preventDefault();
    startY = e.clientY;
    startHeight = els.frameDetailPanel.getBoundingClientRect().height;
    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
    document.body.style.cursor = "row-resize";
    document.body.style.userSelect = "none";
  });

  function onMouseMove(e) {
    const delta = startY - e.clientY;
    const newHeight = Math.max(120, startHeight + delta);
    const maxHeight = container.getBoundingClientRect().height * 0.8;
    const h = Math.min(newHeight, maxHeight);
    els.frameDetailPanel.style.flex = "0 0 " + h + "px";
  }

  function onMouseUp() {
    document.removeEventListener("mousemove", onMouseMove);
    document.removeEventListener("mouseup", onMouseUp);
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
  }
}

function toHexDump(text) {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(text);
  const rows = [];

  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = Array.from(bytes.slice(offset, offset + 16));
    // Group bytes: first 8 | space | next 8
    const left = chunk.slice(0, 8).map((v) => v.toString(16).padStart(2, "0")).join(" ");
    const right = chunk.slice(8).map((v) => v.toString(16).padStart(2, "0")).join(" ");
    const hex = (left + "  " + right).padEnd(49, " ");
    const ascii = chunk
      .map((value) => (value >= 32 && value <= 126 ? String.fromCharCode(value) : "."))
      .join("");
    rows.push(`${offset.toString(16).padStart(8, "0")}  ${hex} ${ascii}`);
  }

  return rows.join("\n") || "00000000";
}

function toHexDumpFromBytes(bytes) {
  const rows = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = Array.from(bytes.slice(offset, offset + 16));
    const left = chunk.slice(0, 8).map((v) => v.toString(16).padStart(2, "0")).join(" ");
    const right = chunk.slice(8).map((v) => v.toString(16).padStart(2, "0")).join(" ");
    const hex = (left + "  " + right).padEnd(49, " ");
    const ascii = chunk
      .map((value) => (value >= 32 && value <= 126 ? String.fromCharCode(value) : "."))
      .join("");
    rows.push(`${offset.toString(16).padStart(8, "0")}  ${hex} ${ascii}`);
  }
  return rows.join("\n") || "00000000";
}

function renderEditableHexHtml(bytes, originalBytes) {
  const lines = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = Array.from(bytes.slice(offset, offset + 16));
    const offsetStr = offset.toString(16).padStart(8, "0");

    // Build hex bytes as individual clickable spans, highlight modified
    const hexSpans = chunk.map((b, i) => {
      const globalIdx = offset + i;
      const gap = (i === 8) ? " " : "";
      const modified = originalBytes && globalIdx < originalBytes.length && b !== originalBytes[globalIdx] ? " hex-byte-modified" : "";
      return `${gap}<span class="hex-byte${modified}" data-idx="${globalIdx}" tabindex="0">${b.toString(16).padStart(2, "0")}</span>`;
    }).join(" ");

    // Pad if less than 16 bytes
    const totalChars = chunk.length * 3 - 1 + (chunk.length > 8 ? 1 : 0);
    const pad = " ".repeat(Math.max(0, 49 - totalChars));

    const ascii = chunk
      .map((v) => (v >= 32 && v <= 126 ? escapeHtml(String.fromCharCode(v)) : "."))
      .join("");

    lines.push(wrapCodeLine(
      `<span class="hex-col hex-col-offset">${offsetStr}</span><span class="hex-col hex-col-bytes">${hexSpans}${pad}</span><span class="hex-col hex-col-ascii">${ascii}</span>`,
      "code-line code-line-hex",
    ));
  }
  return lines.join("") || wrapCodeLine("00000000", "code-line code-line-hex");
}

function bindHexByteHandlers(container, tab) {
  container.querySelectorAll(".hex-byte").forEach((span) => {
    span.addEventListener("click", (e) => {
      e.stopPropagation();
      startHexByteEdit(span, tab, container);
    });
  });
}

function startHexByteEdit(span, tab, container) {
  // Remove any existing edit input
  container.querySelectorAll(".hex-byte-input").forEach((el) => el.remove());
  container.querySelectorAll(".hex-byte.editing").forEach((el) => el.classList.remove("editing"));

  const idx = parseInt(span.dataset.idx, 10);
  if (isNaN(idx) || !tab.requestBytes) return;

  span.classList.add("editing");
  const input = document.createElement("input");
  input.type = "text";
  input.className = "hex-byte-input";
  input.maxLength = 2;
  input.value = tab.requestBytes[idx].toString(16).padStart(2, "0");
  input.size = 2;

  span.textContent = "";
  span.appendChild(input);
  input.focus();
  input.select();

  function commit() {
    const val = parseInt(input.value, 16);
    if (!isNaN(val) && val >= 0 && val <= 255) {
      tab.requestBytes[idx] = val;
    }
    // Re-render the entire hex view with modification highlights
    container.innerHTML = renderEditableHexHtml(tab.requestBytes, tab.requestOriginalBytes);
    bindHexByteHandlers(container, tab);
    // Sync text
    tab.requestText = new TextDecoder().decode(tab.requestBytes);
    if (els.replayRequestEditor) els.replayRequestEditor.value = tab.requestText;
  }

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === "Tab") {
      e.preventDefault();
      commit();
      // Move to next/prev byte
      const nextIdx = e.shiftKey ? idx - 1 : idx + 1;
      const nextSpan = container.querySelector(`.hex-byte[data-idx="${nextIdx}"]`);
      if (nextSpan) startHexByteEdit(nextSpan, tab, container);
    } else if (e.key === "Escape") {
      e.preventDefault();
      commit();
    } else if (e.key === "ArrowRight") {
      e.preventDefault();
      commit();
      const nextSpan = container.querySelector(`.hex-byte[data-idx="${idx + 1}"]`);
      if (nextSpan) startHexByteEdit(nextSpan, tab, container);
    } else if (e.key === "ArrowLeft") {
      e.preventDefault();
      commit();
      const prevSpan = container.querySelector(`.hex-byte[data-idx="${idx - 1}"]`);
      if (prevSpan) startHexByteEdit(prevSpan, tab, container);
    }
  });

  input.addEventListener("input", () => {
    // Only allow hex characters
    input.value = input.value.replace(/[^0-9a-fA-F]/g, "").substring(0, 2);
    // Auto-advance after 2 chars
    if (input.value.length === 2) {
      commit();
      const nextSpan = container.querySelector(`.hex-byte[data-idx="${idx + 1}"]`);
      if (nextSpan) startHexByteEdit(nextSpan, tab, container);
    }
  });

  input.addEventListener("blur", () => {
    // Delay to allow click on another byte
    setTimeout(() => {
      if (!container.querySelector(".hex-byte-input")) return;
      commit();
    }, 100);
  });
}

function updateCodePane(viewElement, lineElement, text, mode, target) {
  const lineCount = countLines(text);
  const savedFocus = window._saveCodeViewFocus?.(viewElement);
  viewElement.innerHTML = renderCodeHtml(text, mode, target);
  lineElement.textContent = buildLineNumbers(lineCount);
  const searchResult = applyCodeSearch(viewElement, state.messageSearch[target]);
  if (savedFocus) {
    window._restoreCodeViewFocus?.(viewElement, savedFocus);
  } else if (searchResult.firstMatch) {
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

  // Both "pretty" and "raw" use the same HTTP syntax highlighting.
  // The difference is in data preparation: "pretty" applies prettyFormat (JSON body formatting).
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
      if (line.length < 10) {
        return wrapCodeLine(escapeHtml(line), "code-line code-line-hex");
      }
      const offset = line.substring(0, 8);
      const hex = line.substring(10, 59);
      const ascii = line.substring(60);
      return wrapCodeLine(
        `<span class="hex-col hex-col-offset">${escapeHtml(offset)}</span><span class="hex-col hex-col-bytes">${escapeHtml(hex)}</span><span class="hex-col hex-col-ascii">${escapeHtml(ascii)}</span>`,
        "code-line code-line-hex",
      );
    })
    .join("");
}

function wrapCodeLine(content, className) {
  return `<span class="${className}">${content || "&nbsp;"}</span>`;
}

function bindCodePaneScroll(viewElement, lineElement) {
  if (!viewElement || !lineElement) return;
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

function applyWsColumnWidths() {
  const table = document.getElementById("websocketTable");
  if (!table) return;
  Object.entries(state.wsColumnWidths).forEach(([key, width]) => {
    table.style.setProperty(`--ws-col-${key}`, `${width}px`);
  });
}

function bindWsColumnResizers() {
  const handles = document.querySelectorAll("#websocketTable .ws-col-resize-handle");
  handles.forEach((handle) => {
    handle.addEventListener("dblclick", (event) => {
      event.preventDefault();
      event.stopPropagation();
      const key = handle.dataset.wsColKey;
      if (!key || !WS_COLUMN_RULES[key] || WS_COLUMN_RULES[key].max === 0) return;
      state.wsColumnWidths[key] = WS_COLUMN_RULES[key].default;
      applyWsColumnWidths();
      scheduleUiSettingsSave();
    });

    handle.addEventListener("mousedown", (event) => {
      const key = handle.dataset.wsColKey;
      const limits = WS_COLUMN_RULES[key];
      if (!key || !limits || limits.max === 0) return;

      event.preventDefault();
      event.stopPropagation();

      const header = handle.closest("th");
      const startWidth = header?.getBoundingClientRect().width ?? limits.default;
      document.body.classList.add("pane-resizing-x");
      handle.classList.add("active");

      const onMove = (moveEvent) => {
        const delta = moveEvent.clientX - event.clientX;
        state.wsColumnWidths[key] = clamp(Math.round(startWidth + delta), limits.min, limits.max);
        applyWsColumnWidths();
      };

      const onUp = () => {
        document.body.classList.remove("pane-resizing-x");
        handle.classList.remove("active");
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        scheduleUiSettingsSave();
      };

      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
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

function bindWebsocketStackResizer(handle) {
  if (!handle) return;
  const stackPanel = handle.parentElement;
  if (!stackPanel) return;

  const sessionsCard = stackPanel.querySelector(".panel-card-top");

  handle.addEventListener("dblclick", () => {
    if (sessionsCard) {
      sessionsCard.style.flex = "";
      sessionsCard.style.height = "";
    }
  });

  handle.addEventListener("mousedown", (event) => {
    event.preventDefault();
    const workbench = els.websocketWorkbench;
    if (!sessionsCard || !workbench) return;

    const startY = event.clientY;
    const startSessions = sessionsCard.getBoundingClientRect().height;
    const combinedHeight = startSessions + workbench.getBoundingClientRect().height;

    document.body.classList.add("pane-resizing-y");
    handle.classList.add("active");

    const onMove = (moveEvent) => {
      const delta = moveEvent.clientY - startY;
      const nextSessions = clamp(
        startSessions + delta,
        WEBSOCKET_STACK_MIN_HEIGHTS.sessions,
        combinedHeight - WEBSOCKET_STACK_MIN_HEIGHTS.workbench,
      );
      sessionsCard.style.flex = "none";
      sessionsCard.style.height = `${Math.round(nextSessions)}px`;
    };

    const onUp = () => {
      document.body.classList.remove("pane-resizing-y");
      handle.classList.remove("active");
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
    };

    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  });
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
  // Remove any previous search highlights first
  clearSearchHighlights(viewElement);

  const normalizedQuery = String(query || "").trim();
  if (!normalizedQuery) {
    return { count: 0, firstMatch: null };
  }

  // Build a flat text map across all text nodes so we can match across
  // element boundaries (e.g. "<span>accept-encoding</span>: gzip").
  const lowerQuery = normalizedQuery.toLowerCase();
  const walker = document.createTreeWalker(viewElement, NodeFilter.SHOW_TEXT, null);
  const textNodes = [];
  let fullText = "";
  const nodeOffsets = []; // { node, start }
  while (walker.nextNode()) {
    const node = walker.currentNode;
    nodeOffsets.push({ node, start: fullText.length });
    fullText += node.nodeValue;
    textNodes.push(node);
  }

  const lowerFull = fullText.toLowerCase();
  const matches = []; // { start, end } in fullText coordinates
  let cursor = 0;
  while (true) {
    const idx = lowerFull.indexOf(lowerQuery, cursor);
    if (idx === -1) break;
    matches.push({ start: idx, end: idx + normalizedQuery.length });
    cursor = idx + 1;
  }

  if (!matches.length) {
    return { count: 0, firstMatch: null };
  }

  // Wrap each match in <mark class="search-hit"> using Range API.
  // Process matches in reverse order to preserve earlier node offsets.
  let firstMatch = null;
  for (let m = matches.length - 1; m >= 0; m--) {
    const match = matches[m];

    // Find start node/offset
    let startNode = null, startOffset = 0;
    let endNode = null, endOffset = 0;
    for (let i = 0; i < nodeOffsets.length; i++) {
      const entry = nodeOffsets[i];
      const nodeEnd = entry.start + entry.node.nodeValue.length;
      if (!startNode && match.start < nodeEnd) {
        startNode = entry.node;
        startOffset = match.start - entry.start;
      }
      if (match.end <= nodeEnd) {
        endNode = entry.node;
        endOffset = match.end - entry.start;
        break;
      }
    }
    if (!startNode || !endNode) continue;

    const range = document.createRange();
    range.setStart(startNode, startOffset);
    range.setEnd(endNode, endOffset);

    const mark = document.createElement("mark");
    mark.className = "search-hit";
    try {
      range.surroundContents(mark);
    } catch (_) {
      // surroundContents fails when the range spans partial elements.
      // Fall back to extractContents + insertion.
      const fragment = range.extractContents();
      mark.appendChild(fragment);
      range.insertNode(mark);
    }
    firstMatch = mark;

    // Rebuild nodeOffsets after DOM mutation for earlier matches
    if (m > 0) {
      nodeOffsets.length = 0;
      fullText = "";
      const w2 = document.createTreeWalker(viewElement, NodeFilter.SHOW_TEXT, null);
      while (w2.nextNode()) {
        nodeOffsets.push({ node: w2.currentNode, start: fullText.length });
        fullText += w2.currentNode.nodeValue;
      }
    }
  }

  return { count: matches.length, firstMatch };
}

function clearSearchHighlights(viewElement) {
  const marks = viewElement.querySelectorAll("mark.search-hit");
  marks.forEach((mark) => {
    const parent = mark.parentNode;
    while (mark.firstChild) {
      parent.insertBefore(mark.firstChild, mark);
    }
    parent.removeChild(mark);
    parent.normalize(); // merge adjacent text nodes back together
  });
}

function buildSearchMeta(lineCount, mode, matchCount) {
  const searchCopy = matchCount
    ? `<span class="search-hit-count">${matchCount} highlight${matchCount === 1 ? "" : "s"}</span>`
    : "No highlights";
  return `${searchCopy} · ${lineCount} lines · ${titleCase(mode)} view`;
}

function initSearchHitNavigation(metaElement, getViewFn) {
  if (!metaElement) return;
  let currentIndex = -1;
  metaElement.addEventListener("click", (e) => {
    if (!e.target.closest(".search-hit-count")) return;
    const view = getViewFn();
    if (!view) return;
    const marks = view.querySelectorAll("mark.search-hit");
    if (!marks.length) return;
    // Remove active class from previous
    const prev = view.querySelector("mark.search-hit-active");
    if (prev) prev.classList.remove("search-hit-active");
    // Advance to next
    currentIndex = (currentIndex + 1) % marks.length;
    const target = marks[currentIndex];
    target.classList.add("search-hit-active");
    // Scroll the view container to bring the match into view
    const container = target.closest(".code-view, .simple-code-view, .replay-highlight-editable, .replay-response-view") || view;
    const targetTop = target.offsetTop - container.offsetTop;
    container.scrollTop = Math.max(targetTop - 40, 0);
  });
  // Reset index when search changes (observer on innerHTML changes)
  new MutationObserver(() => { currentIndex = -1; }).observe(metaElement, { childList: true, subtree: true });
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

  invalidateVisibleEntriesCache();
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
  const lowerName = name.trim().toLowerCase();
  if (lowerName === "cookie" || lowerName === "set-cookie") {
    return `<span class="token-header">${escapeHtml(name)}</span><span class="token-punctuation">:</span> ${highlightCookieValue(value)}`;
  }
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

function highlightCookieValue(value) {
  // Cookie: name1=val1; name2=val2  OR  Set-Cookie: name=val; Path=/; HttpOnly
  const parts = value.split(";");
  return parts.map((part, i) => {
    const eqIdx = part.indexOf("=");
    const sep = i < parts.length - 1 ? `<span class="token-cookie-sep">;</span>` : "";
    if (eqIdx === -1) {
      // Flags like HttpOnly, Secure
      return `<span class="token-cookie-flag">${escapeHtml(part)}</span>${sep}`;
    }
    const name = part.slice(0, eqIdx);
    const val = part.slice(eqIdx + 1);
    return `<span class="token-cookie-name">${escapeHtml(name)}</span><span class="token-punctuation">=</span><span class="token-cookie-value">${escapeHtml(val)}</span>${sep}`;
  }).join("");
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

function updateWsHandshakeLineNumbers() {
  if (!els.wsHandshakeLines) return;
  const resBtn = document.getElementById("wsHandshakeResBtn");
  const showingResponse = resBtn?.classList.contains("active");
  const activeView = showingResponse ? els.websocketResponseView : els.websocketRequestView;
  const lineCount = activeView.querySelectorAll(".code-line").length || 1;
  els.wsHandshakeLines.textContent = buildLineNumbers(lineCount);
}

function updateWsHandshakeSearch() {
  const resBtn = document.getElementById("wsHandshakeResBtn");
  const showingResponse = resBtn?.classList.contains("active");
  const activeView = showingResponse ? els.websocketResponseView : els.websocketRequestView;
  const query = els.wsHandshakeSearchInput?.value || "";
  const result = applyCodeSearch(activeView, query);
  const lineCount = activeView.querySelectorAll(".code-line").length || 1;
  if (els.wsHandshakeSearchMeta) {
    els.wsHandshakeSearchMeta.innerHTML = buildSearchMeta(lineCount, "pretty", result.count);
  }
}

function setWsMessageHighlightText(text) {
  if (!els.wsMessageHighlight) return;
  els.wsMessageHighlight.textContent = text;
  applyWsMessageJsonHighlight();
}

function applyWsMessageJsonHighlight() {
  if (!els.wsMessageHighlight) return;
  const text = els.wsMessageHighlight.innerText || "";
  // Only apply JSON highlighting if it looks like JSON
  const trimmed = text.trim();
  if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
    // Save cursor position
    const sel = window.getSelection();
    let cursorOffset = 0;
    if (sel.rangeCount > 0 && els.wsMessageHighlight.contains(sel.anchorNode)) {
      const range = document.createRange();
      range.selectNodeContents(els.wsMessageHighlight);
      range.setEnd(sel.anchorNode, sel.anchorOffset);
      cursorOffset = range.toString().length;
    }

    els.wsMessageHighlight.innerHTML = highlightJson(text);

    // Restore cursor position
    if (document.activeElement === els.wsMessageHighlight && cursorOffset > 0) {
      restoreCursorPosition(els.wsMessageHighlight, cursorOffset);
    }
  }
}

function highlightJson(text) {
  // Tokenize and highlight JSON
  return text.replace(
    /("(?:[^"\\]|\\.)*")\s*:|("(?:[^"\\]|\\.)*")|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b|(true|false)\b|(null)\b|([{}[\]:,])/g,
    (match, key, str, num, bool, nul, punct) => {
      if (key) return `<span class="json-key">${escapeHtml(key)}</span>:`;
      if (str) return `<span class="json-string">${escapeHtml(str)}</span>`;
      if (num) return `<span class="json-number">${escapeHtml(num)}</span>`;
      if (bool) return `<span class="json-bool">${escapeHtml(bool)}</span>`;
      if (nul) return `<span class="json-null">${escapeHtml(nul)}</span>`;
      if (punct) return `<span class="json-punct">${escapeHtml(punct)}</span>`;
      return escapeHtml(match);
    }
  );
}

function restoreCursorPosition(element, offset) {
  const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, null);
  let remaining = offset;
  let node;
  while ((node = walker.nextNode())) {
    if (remaining <= node.textContent.length) {
      const sel = window.getSelection();
      const range = document.createRange();
      range.setStart(node, remaining);
      range.collapse(true);
      sel.removeAllRanges();
      sel.addRange(range);
      return;
    }
    remaining -= node.textContent.length;
  }
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

function invalidateVisibleEntriesCache() {
  state._cachedVisibleEntries = null;
}

function getVisibleEntries() {
  if (state._cachedVisibleEntries) return state._cachedVisibleEntries;

  const direction = state.sortDirection === "asc" ? 1 : -1;

  state._cachedVisibleEntries = state.items
    .filter((item) => item.method !== "CONNECT")
    .filter(matchesQuickFilters)
    .filter(matchesAdvancedFilters)
    .map((item, index) => ({ item, index }))
    .sort((left, right) => {
      const leftSeq = left.item.sequence ?? left.index;
      const rightSeq = right.item.sequence ?? right.index;

      if (state.sortKey === "index") {
        return (leftSeq - rightSeq) * direction;
      }

      const comparison = compareSortValues(
        getSortValue(left.item, state.sortKey),
        getSortValue(right.item, state.sortKey),
      );

      if (comparison !== 0) {
        return comparison * direction;
      }

      return leftSeq - rightSeq;
    });

  return state._cachedVisibleEntries;
}

function matchesQuickFilters(item) {
  const methodMatch = !state.method || item.method === state.method;
  if (!methodMatch) {
    return false;
  }

  if (!state.query) {
    return true;
  }

  const q = state.query.toLowerCase();
  const haystack = `${item.host} ${item.method} ${item.path || ""} ${item.status || ""} ${inferMimeType(item)} ${formatSize((item.request_bytes ?? 0) + (item.response_bytes ?? 0))} ${item.sequence != null ? item.sequence + 1 : ""} ${formatTimestamp(item.started_at || "")}`.toLowerCase();
  return haystack.includes(q);
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

/* ─── WebSocket Replay ─── */

function createWsReplayTab(seed = {}) {
  state.replayTabSequence += 1;
  const tab = {
    id: crypto.randomUUID(),
    type: "websocket",
    sequence: state.replayTabSequence,
    label: `WS ${seed.host || "draft"}`,
    wsScheme: seed.scheme || "wss",
    wsHost: seed.host || "",
    wsPort: seed.port || (seed.scheme === "ws" ? 80 : 443),
    wsPath: seed.path || "/",
    wsHeaders: seed.headers || [],
    wsHandshakeText: seed.handshakeText || "",
    wsStatus: "disconnected",
    wsFrames: [],
    wsSelectedFrameIndex: -1,
    wsEditorText: "",
    wsError: null,
    wsPollTimer: null,
    wsSetupQueue: (seed.capturedFrames || [])
      .filter((f) => f.direction === "client_to_server" && f.kind === "text")
      .map((f) => {
        const text = f.body_encoding === "base64" ? atob(f.body_preview || f.body || "") : (f.body_preview || f.body || "");
        return { body: text, autoSend: true, sent: false, label: truncateSetupLabel(text) };
      }),
  };
  state.replayTabs.push(tab);
  state.activeReplayTabId = tab.id;
  scheduleWorkspaceStateSave();
  renderReplay();
  return tab;
}

function truncateSetupLabel(body) {
  try {
    const parsed = JSON.parse(body);
    if (parsed.event) return parsed.event;
    if (parsed.topic) return parsed.topic;
    if (parsed.type) return parsed.type;
  } catch (e) {}
  return body.length > 30 ? body.substring(0, 30) + "…" : body;
}

async function wsConnect() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return;

  // Sync fields from UI
  tab.wsScheme = els.wsSchemeSelect.value;
  tab.wsHost = els.wsHostInput.value;
  tab.wsPort = parseInt(els.wsPortInput.value) || (tab.wsScheme === "wss" ? 443 : 80);
  tab.wsPath = els.wsPathInput.value;

  tab.wsStatus = "connecting";
  tab.wsFrames = [];
  tab.wsSelectedFrameIndex = -1;
  tab.wsError = null;
  renderWsStatus();
  renderWsFrameList();

  try {
    const headers = parseWsHandshakeHeaders(tab);
    const resp = await fetch("/api/replay/ws-connect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        id: tab.id,
        scheme: tab.wsScheme,
        host: tab.wsHost,
        port: Number(tab.wsPort),
        path: tab.wsPath,
        headers,
      }),
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => "Connection failed");
      throw new Error(text);
    }
    startWsPoll(tab);
    renderReplayTabs();

    // Auto-send setup queue after connection
    await runSetupQueue(tab);
  } catch (e) {
    tab.wsStatus = "error";
    tab.wsError = e.message;
    renderWsStatus();
  }
}

async function runSetupQueue(tab) {
  if (!tab.wsSetupQueue || !tab.wsSetupQueue.length) return;

  // Wait for connection to be established
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 150));
    if (tab.wsStatus === "connected") break;
    if (tab.wsStatus === "error" || tab.wsStatus === "disconnected") return;
  }
  if (tab.wsStatus !== "connected") return;

  for (const item of tab.wsSetupQueue) {
    if (!item.autoSend || item.sent) continue;
    if (tab.wsStatus !== "connected") break;

    try {
      const resp = await fetch("/api/replay/ws-send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: tab.id, body: item.body, binary: false }),
      });
      if (resp.ok) {
        item.sent = true;
        renderWsSetupQueue();
      }
    } catch (e) {
      break;
    }
    // Small delay between messages
    await new Promise((r) => setTimeout(r, 100));
  }
}

function parseWsHandshakeHeaders(tab) {
  const headers = [];
  const text = els.wsHandshakeHeaders ? els.wsHandshakeHeaders.value : (tab.wsHandshakeText || "");
  if (text.trim()) {
    for (const line of text.split("\n")) {
      const colonIdx = line.indexOf(":");
      if (colonIdx > 0) {
        headers.push({
          name: line.slice(0, colonIdx).trim(),
          value: line.slice(colonIdx + 1).trim(),
        });
      }
    }
  }
  // Merge with any pre-set headers from seed
  const merged = [...headers];
  for (const h of (tab.wsHeaders || [])) {
    if (!merged.some(m => m.name.toLowerCase() === h.name.toLowerCase())) {
      merged.push(h);
    }
  }
  return merged;
}

async function wsSend() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket" || tab.wsStatus !== "connected") return;

  const body = els.wsMessageEditor.value;
  if (!body.trim()) return;

  const binary = els.wsMessageType.value === "binary";

  try {
    const resp = await fetch("/api/replay/ws-send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: tab.id, body, binary }),
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => "Send failed");
      showToast(text, "error");
    }
  } catch (e) {
    showToast(`Send failed: ${e.message}`, "error");
  }
}

async function wsDisconnect() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return;

  stopWsPoll(tab);
  try {
    await fetch("/api/replay/ws-disconnect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: tab.id }),
    });
  } catch (e) {
    // ignore disconnect errors
  }
  tab.wsStatus = "disconnected";
  renderWsStatus();
}

function startWsPoll(tab) {
  stopWsPoll(tab);
  let sinceIndex = 0;
  tab.wsPollTimer = setInterval(async () => {
    try {
      const resp = await fetch(`/api/replay/ws-frames/${tab.id}?since=${sinceIndex}`);
      if (!resp.ok) return;
      const data = await resp.json();

      if (data.frames && data.frames.length > 0) {
        tab.wsFrames.push(...data.frames);
        sinceIndex = tab.wsFrames.length;
        // Only re-render if this tab is still active
        if (state.activeReplayTabId === tab.id) {
          renderWsFrameList();
        }
      }

      if (data.status && data.status !== tab.wsStatus) {
        tab.wsStatus = data.status;
        if (data.error) tab.wsError = data.error;
        if (state.activeReplayTabId === tab.id) {
          renderWsStatus();
        }
        if (data.status === "disconnected" || data.status === "error") {
          stopWsPoll(tab);
        }
      }
    } catch (_e) {
      // ignore poll errors
    }
  }, 200);
}

function stopWsPoll(tab) {
  if (tab && tab.wsPollTimer) {
    clearInterval(tab.wsPollTimer);
    tab.wsPollTimer = null;
  }
}

function renderWsReplay() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return;

  els.wsSchemeSelect.value = tab.wsScheme;
  els.wsHostInput.value = tab.wsHost;
  els.wsPortInput.value = tab.wsPort;
  els.wsPathInput.value = tab.wsPath;

  // Restore handshake headers
  if (els.wsHandshakeHeaders) {
    if (tab.wsHandshakeText) {
      els.wsHandshakeHeaders.value = tab.wsHandshakeText;
    } else if (tab.wsHeaders && tab.wsHeaders.length > 0) {
      els.wsHandshakeHeaders.value = tab.wsHeaders
        .map(h => `${h.name}: ${h.value}`)
        .join("\n");
    } else {
      els.wsHandshakeHeaders.value = "";
    }
  }

  // Restore editor text
  els.wsMessageEditor.value = tab.wsEditorText || "";
  setWsMessageHighlightText(tab.wsEditorText || "");

  renderWsStatus();
  renderWsSetupQueue();
  renderWsFrameList();
}

function renderWsSetupQueue() {
  const container = document.getElementById("wsSetupQueue");
  if (!container) return;
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket" || !tab.wsSetupQueue || !tab.wsSetupQueue.length) {
    container.classList.add("hidden");
    return;
  }
  container.classList.remove("hidden");

  const listEl = document.getElementById("wsSetupQueueList");
  if (!listEl) return;

  listEl.innerHTML = tab.wsSetupQueue.map((item, i) => {
    const sentClass = item.sent ? "sent" : "";
    const checked = item.autoSend ? "checked" : "";
    return `<div class="ws-setup-row ${sentClass}" data-idx="${i}">
      <input type="checkbox" class="ws-setup-check" data-idx="${i}" ${checked} />
      <span class="ws-setup-index">#${i + 1}</span>
      <span class="ws-setup-label">${escapeHtml(item.label)}</span>
      <button class="ws-setup-send" data-idx="${i}" title="Send this message">▶</button>
      ${item.sent ? '<span class="ws-setup-sent-badge">✓</span>' : ""}
    </div>`;
  }).join("");

  // Checkbox toggle
  listEl.querySelectorAll(".ws-setup-check").forEach((cb) => {
    cb.addEventListener("change", () => {
      const idx = parseInt(cb.dataset.idx);
      tab.wsSetupQueue[idx].autoSend = cb.checked;
      scheduleWorkspaceStateSave();
    });
  });

  // Individual send button
  listEl.querySelectorAll(".ws-setup-send").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const idx = parseInt(btn.dataset.idx);
      const item = tab.wsSetupQueue[idx];
      if (!item || tab.wsStatus !== "connected") return;
      try {
        const resp = await fetch("/api/replay/ws-send", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id: tab.id, body: item.body, binary: false }),
        });
        if (resp.ok) {
          item.sent = true;
          renderWsSetupQueue();
        }
      } catch (e) {
        console.error(e);
      }
    });
  });

  // Click row to load into editor
  listEl.querySelectorAll(".ws-setup-row").forEach((row) => {
    row.addEventListener("dblclick", () => {
      const idx = parseInt(row.dataset.idx);
      const item = tab.wsSetupQueue[idx];
      if (item) {
        els.wsMessageEditor.value = item.body;
        tab.wsEditorText = item.body;
        setWsMessageHighlightText(item.body);
      }
    });
  });
}

function renderWsStatus() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return;

  const status = tab.wsStatus;
  els.wsStatusIndicator.className = `ws-status-dot ${status}`;
  els.wsStatusText.textContent = status === "connected" ? "Connected"
    : status === "connecting" ? "Connecting..."
    : status === "error" ? `Error: ${tab.wsError || "unknown"}`
    : "Disconnected";

  els.wsConnectButton.disabled = status === "connected" || status === "connecting";
  els.wsDisconnectButton.disabled = status !== "connected";
  els.wsSendButton.disabled = status !== "connected";
}

function renderWsFrameList() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return;

  const frames = tab.wsFrames;
  els.wsFrameCount.textContent = `${frames.length} frame${frames.length === 1 ? "" : "s"}`;

  if (!frames.length) {
    els.wsFrameList.innerHTML = '<div class="empty-copy">Connect to start a WebSocket conversation.</div>';
    renderWsFrameDetail();
    return;
  }

  els.wsFrameList.innerHTML = frames.map((frame) => {
    const isClient = frame.direction === "client_to_server";
    const dirClass = isClient ? "client" : "server";
    const dirLabel = isClient ? "you" : "server";
    const selected = tab.wsSelectedFrameIndex === frame.index ? "selected" : "";
    const rawBody = frame.body_encoding === "base64"
      ? `[binary ${formatWsFrameSize(frame.body_size)}]`
      : (frame.body || "").substring(0, 120);
    const time = frame.captured_at
      ? new Date(frame.captured_at).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false })
      : "";
    const size = formatWsFrameSize(frame.body_size);

    return `<div class="ws-frame-bubble ${dirClass} ${selected}" data-frame-index="${frame.index}">
      <div class="ws-frame-bubble-meta"><span>${dirLabel}</span><span>${size} · ${time}</span></div>
      <div class="ws-frame-bubble-body">${escapeHtml(rawBody)}</div>
    </div>`;
  }).join("");

  // Auto-scroll to bottom
  els.wsFrameList.scrollTop = els.wsFrameList.scrollHeight;

  // Add click handlers
  els.wsFrameList.querySelectorAll(".ws-frame-bubble").forEach((bubble) => {
    bubble.addEventListener("click", () => {
      const idx = parseInt(bubble.dataset.frameIndex);
      tab.wsSelectedFrameIndex = idx;
      els.wsFrameList.querySelectorAll(".ws-frame-bubble").forEach(b => b.classList.remove("selected"));
      bubble.classList.add("selected");
      renderWsFrameDetail();
    });
    bubble.addEventListener("dblclick", () => {
      const idx = parseInt(bubble.dataset.frameIndex);
      const frame = tab.wsFrames.find(f => f.index === idx);
      if (frame && frame.direction === "client_to_server") {
        const decoded = decodeWsFrameBody(frame);
        els.wsMessageEditor.value = decoded;
        tab.wsEditorText = decoded;
        setWsMessageHighlightText(decoded);
      }
    });
  });

  renderWsFrameDetail();
}

function renderWsFrameDetail() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return;

  const frame = tab.wsFrames.find(f => f.index === tab.wsSelectedFrameIndex);
  if (!frame) {
    els.wsFrameDetailPath.textContent = "DETAIL";
    els.wsFrameDetailTitle.textContent = "Select a frame";
    els.wsFrameDetailView.innerHTML = "";
    return;
  }

  const isClient = frame.direction === "client_to_server";
  const sizeStr = formatWsFrameSize(frame.body_size);
  const dirClass = isClient ? "dir-client" : "dir-server";
  const dirLabel = isClient ? "client \u2192" : "\u2190 server";
  els.wsFrameDetailPath.innerHTML = `<span class="${dirClass}">${dirLabel}</span> · ${escapeHtml(frame.kind || "")} · ${escapeHtml(sizeStr)}`;
  els.wsFrameDetailTitle.textContent = `Frame #${frame.index + 1}`;

  let text = decodeWsFrameBody(frame);

  // Try to pretty-print JSON
  try {
    const parsed = JSON.parse(text);
    text = JSON.stringify(parsed, null, 2);
  } catch (_e) { /* not JSON */ }

  els.wsFrameDetailView.innerHTML = renderCodeHtml(text, "pretty", "response");
}

function decodeWsFrameBody(frame) {
  if (!frame || !frame.body) return "";
  if (frame.body_encoding === "base64") {
    try {
      return atob(frame.body);
    } catch (_e) {
      return frame.body;
    }
  }
  return frame.body;
}

function formatWsFrameSize(bytes) {
  if (bytes == null) return "";
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

function bindWsReplayEvents() {
  if (!els.wsConnectButton) return;

  els.wsConnectButton.addEventListener("click", () => {
    wsConnect().catch((error) => console.error(error));
  });
  els.wsDisconnectButton.addEventListener("click", () => {
    wsDisconnect().catch((error) => console.error(error));
  });
  els.wsSendButton.addEventListener("click", () => {
    wsSend().catch((error) => console.error(error));
  });

  els.wsSchemeSelect.addEventListener("change", () => {
    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      tab.wsScheme = els.wsSchemeSelect.value;
      tab.wsPort = tab.wsScheme === "wss" ? 443 : 80;
      els.wsPortInput.value = tab.wsPort;
      renderReplayTabs();
      scheduleWorkspaceStateSave();
    }
  });
  els.wsHostInput.addEventListener("input", () => {
    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      tab.wsHost = els.wsHostInput.value;
      renderReplayTabs();
      scheduleWorkspaceStateSave();
    }
  });
  els.wsPortInput.addEventListener("change", () => {
    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      tab.wsPort = parseInt(els.wsPortInput.value) || (tab.wsScheme === "wss" ? 443 : 80);
      scheduleWorkspaceStateSave();
    }
  });
  els.wsPathInput.addEventListener("input", () => {
    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      tab.wsPath = els.wsPathInput.value;
      scheduleWorkspaceStateSave();
    }
  });
  els.wsHandshakeHeaders.addEventListener("input", () => {
    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      tab.wsHandshakeText = els.wsHandshakeHeaders.value;
      scheduleWorkspaceStateSave();
    }
  });
  // WS Message highlight editor: input → sync to hidden textarea + JSON highlight
  els.wsMessageHighlight.addEventListener("input", () => {
    const plainText = els.wsMessageHighlight.innerText || "";
    els.wsMessageEditor.value = plainText;
    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      tab.wsEditorText = plainText;
    }
    applyWsMessageJsonHighlight();
  });

  // Cmd+Enter to send in WS editor
  els.wsMessageHighlight.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      wsSend().catch((error) => console.error(error));
    }
  });

  // WS Replay pane resizer (left/right)
  if (els.wsReplayPaneResizer) {
    let startX = 0;
    let startW = 0;
    const onMove = (e) => {
      const delta = e.clientX - startX;
      const panel = els.wsReplayPanel;
      const total = panel.getBoundingClientRect().width - 10;
      const newW = Math.max(280, Math.min(total - 280, startW + delta));
      panel.style.setProperty("--ws-replay-left-width", `${newW}px`);
    };
    const onUp = () => {
      document.body.classList.remove("pane-resizing-x");
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    els.wsReplayPaneResizer.addEventListener("mousedown", (e) => {
      e.preventDefault();
      startX = e.clientX;
      const left = els.wsReplayPanel.querySelector(".ws-replay-left");
      startW = left ? left.getBoundingClientRect().width : 400;
      document.body.classList.add("pane-resizing-x");
      window.addEventListener("mousemove", onMove);
      window.addEventListener("mouseup", onUp);
    });
    els.wsReplayPaneResizer.addEventListener("dblclick", () => {
      els.wsReplayPanel.style.removeProperty("--ws-replay-left-width");
    });
  }

  // WS Replay frame detail resizer (vertical)
  if (els.wsReplayFrameResizer) {
    let startY = 0;
    let startH = 0;
    const onMove = (e) => {
      const delta = startY - e.clientY;
      const right = els.wsReplayPanel.querySelector(".ws-replay-right");
      const total = right ? right.getBoundingClientRect().height : 600;
      const newH = Math.max(120, Math.min(total * 0.8, startH + delta));
      const detail = right.querySelector(".ws-frame-detail");
      if (detail) detail.style.flex = `0 0 ${newH}px`;
    };
    const onUp = () => {
      document.body.classList.remove("pane-resizing-y");
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    els.wsReplayFrameResizer.addEventListener("mousedown", (e) => {
      e.preventDefault();
      startY = e.clientY;
      const detail = els.wsReplayPanel.querySelector(".ws-frame-detail");
      startH = detail ? detail.getBoundingClientRect().height : 200;
      document.body.classList.add("pane-resizing-y");
      window.addEventListener("mousemove", onMove);
      window.addEventListener("mouseup", onUp);
    });
  }

}

/* ─── WS Send to Replay (from captured frame) ─── */

function sendWsFrameToReplay(frameIdx) {
  const session = state.selectedWebsocketRecord;
  if (!session) return;

  const frame = session.frames[frameIdx];
  const rawBody = frame ? (frame.body_preview || frame.body || "") : "";
  const editorText = frame
    ? (frame.body_encoding === "base64" ? atob(rawBody) : rawBody)
    : "";

  // Try JSON pretty-print for editor
  let prettyText = editorText;
  try { prettyText = JSON.stringify(JSON.parse(editorText), null, 2); } catch (e) {}

  // Detect scheme: wss/ws from session, or infer from https/host:443
  let scheme = session.scheme || "";
  if (scheme === "wss" || scheme === "ws") { /* keep */ }
  else if (scheme === "https" || session.host?.endsWith(":443")) scheme = "wss";
  else scheme = "wss"; // default safe

  const hostRaw = session.host || "";
  const hostClean = hostRaw.replace(/:443$|:80$/, "");
  const port = hostRaw.includes(":") ? parseInt(hostRaw.split(":").pop()) : (scheme === "ws" ? 80 : 443);

  const tab = createWsReplayTab({
    scheme,
    host: hostClean,
    port,
    path: session.path || "/",
    headers: session.request?.headers || [],
    capturedFrames: session.frames || [],
  });
  tab.wsEditorText = prettyText;
  state.activeTool = "replay";
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

/* ─── Compare / Diff ─── */
let compareBaseId = null;
let compareActiveTab = "request";
let compareBaseRecord = null;
let compareTargetRecord = null;

function computeUnifiedDiff(linesA, linesB, labelA, labelB) {
  const result = [`--- ${labelA}`, `+++ ${labelB}`];
  const maxLen = Math.max(linesA.length, linesB.length);
  for (let i = 0; i < maxLen; i++) {
    const a = i < linesA.length ? linesA[i] : undefined;
    const b = i < linesB.length ? linesB[i] : undefined;
    if (a === b) {
      result.push(`  ${a}`);
    } else {
      if (a !== undefined) result.push(`- ${a}`);
      if (b !== undefined) result.push(`+ ${b}`);
    }
  }
  return result.join("\n");
}

async function setCompareBase(transactionId) {
  compareBaseId = transactionId;
  const btn = document.getElementById("compareWithBaseBtn");
  if (btn) btn.disabled = false;
  const item = state.items.find((i) => i.id === transactionId);
  if (btn && item) btn.textContent = `Compare with #${item.index ?? "?"}`;
}

async function openCompareModal(targetId) {
  if (!compareBaseId || compareBaseId === targetId) return;
  const [baseRes, targetRes] = await Promise.all([
    fetch(`/api/transactions/${compareBaseId}`).then((r) => r.ok ? r.json() : null),
    fetch(`/api/transactions/${targetId}`).then((r) => r.ok ? r.json() : null),
  ]);
  if (!baseRes || !targetRes) return;
  compareBaseRecord = baseRes;
  compareTargetRecord = targetRes;
  compareActiveTab = "request";
  renderCompareModal();
  document.getElementById("compareModal").classList.remove("hidden");
}

function renderCompareModal() {
  if (!compareBaseRecord || !compareTargetRecord) return;
  const baseItem = state.items.find((i) => i.id === compareBaseRecord.id);
  const targetItem = state.items.find((i) => i.id === compareTargetRecord.id);
  const baseLabel = `#${baseItem?.index ?? "?"} ${compareBaseRecord.method} ${compareBaseRecord.host}${compareBaseRecord.path}`;
  const targetLabel = `#${targetItem?.index ?? "?"} ${compareTargetRecord.method} ${compareTargetRecord.host}${compareTargetRecord.path}`;
  document.getElementById("compareKicker").textContent = `${baseLabel}  vs  ${targetLabel}`;
  document.getElementById("compareTitle").textContent = compareActiveTab === "request" ? "Request Diff" : "Response Diff";
  document.querySelectorAll("[data-compare-tab]").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.compareTab === compareActiveTab);
  });
  let textA, textB;
  if (compareActiveTab === "request") {
    textA = buildRawRequest(compareBaseRecord);
    textB = buildRawRequest(compareTargetRecord);
  } else {
    textA = buildRawResponse(compareBaseRecord);
    textB = buildRawResponse(compareTargetRecord);
  }
  const linesA = textA.split("\n");
  const linesB = textB.split("\n");
  const diff = computeUnifiedDiff(linesA, linesB, "base", "target");
  document.getElementById("compareDiffView").innerHTML = renderDiffHtml(diff);
}

function closeCompareModal() {
  document.getElementById("compareModal").classList.add("hidden");
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

/* ─── WS Frame Context Menu ─── */

function openWsFrameContextMenu(x, y) {
  const menu = els.wsFrameContextMenu;
  if (!menu) return;
  menu.classList.remove("hidden");
  const maxX = window.innerWidth - menu.offsetWidth - 8;
  const maxY = window.innerHeight - menu.offsetHeight - 8;
  menu.style.left = `${Math.min(x, maxX)}px`;
  menu.style.top = `${Math.min(y, maxY)}px`;
}

function closeWsFrameContextMenu() {
  if (els.wsFrameContextMenu) els.wsFrameContextMenu.classList.add("hidden");
}

if (els.wsFrameContextMenu) {
  document.getElementById("wsFrameToReplayBtn").addEventListener("click", () => {
    closeWsFrameContextMenu();
    sendWsFrameToReplay(state.selectedFrameIdx ?? 0);
  });
  document.addEventListener("click", (e) => {
    if (!els.wsFrameContextMenu.contains(e.target)) closeWsFrameContextMenu();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeWsFrameContextMenu();
  });
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
  if (!state._pendingAnnotations) state._pendingAnnotations = new Map();
  const pending = state._pendingAnnotations;
  pending.set(transactionId, { ...pending.get(transactionId), ...payload });

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
        invalidateVisibleEntriesCache();
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
  } finally {
    pending.delete(transactionId);
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
    } else if (action === "send-to-sequence") {
      sendToSequenceFromSelection().catch((error) => console.error(error));
    } else if (action === "copy-url") {
      copyTransactionUrl(contextMenuTargetId);
    } else if (action?.startsWith("copy-as-")) {
      const format = action.replace("copy-as-", "");
      // Use selectedRecord if available (sync, preserves user gesture for clipboard)
      if (state.selectedRecord && state.selectedRecord.id === contextMenuTargetId) {
        const text = selectedRecordToFormat(format);
        if (text) { copyTextToClipboard(text); showToast(`Copied as ${format}`); }
      } else {
        historyRequestToFormat(contextMenuTargetId, format).then((text) => {
          if (text) { copyTextToClipboard(text); showToast(`Copied as ${format}`); }
        });
      }
    } else if (action === "compare-set-base") {
      setCompareBase(contextMenuTargetId);
    } else if (action === "compare-with-base") {
      openCompareModal(contextMenuTargetId).catch((error) => console.error(error));
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

/* ─── WS Frame context menu ─── */

function openWsFrameContextMenu(x, y) {
  const menu = els.wsFrameContextMenu;
  menu.classList.remove("hidden");
  const menuWidth = menu.offsetWidth;
  const menuHeight = menu.offsetHeight;
  const maxX = window.innerWidth - menuWidth - 8;
  const maxY = window.innerHeight - menuHeight - 8;
  menu.style.left = `${Math.min(x, maxX)}px`;
  menu.style.top = `${Math.min(y, maxY)}px`;
}

function closeWsFrameContextMenu() {
  els.wsFrameContextMenu.classList.add("hidden");
}

document.getElementById("wsFrameToReplayBtn").addEventListener("click", () => {
  closeWsFrameContextMenu();
  sendWsFrameToReplay(state.selectedFrameIdx);
});

document.addEventListener("click", (event) => {
  if (!els.wsFrameContextMenu.contains(event.target)) {
    closeWsFrameContextMenu();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !els.wsFrameContextMenu.classList.contains("hidden")) {
    closeWsFrameContextMenu();
  }
});

function sendWsFrameToReplay(frameIdx) {
  const session = state.selectedWebsocketRecord;
  if (!session || frameIdx == null) return;
  const frame = session.frames[frameIdx];
  if (!frame) return;

  // Determine WS scheme
  let wsScheme;
  if (session.scheme === "wss" || session.scheme === "ws") {
    wsScheme = session.scheme;
  } else if (session.scheme === "https" || (session.host && session.host.endsWith(":443"))) {
    wsScheme = "wss";
  } else {
    wsScheme = "ws";
  }

  // Build frame body
  let body = frame.body_preview || "";
  if (frame.body_encoding === "base64") {
    try {
      body = atob(frame.body_preview);
    } catch {
      body = frame.body_preview;
    }
  }

  // Try to pretty-print JSON
  try {
    const parsed = JSON.parse(body);
    body = JSON.stringify(parsed, null, 2);
  } catch {
    // not JSON, keep as-is
  }

  const host = session.host?.replace(/:443$|:80$/, "") || "";
  const port = session.host?.includes(":") ? parseInt(session.host.split(":").pop()) : (wsScheme === "wss" ? 443 : 80);
  createWsReplayTab({
    scheme: wsScheme,
    host,
    port,
    path: session.path || "/",
    headers: session.request?.headers || [],
  });
  state.activeTool = "replay";
  renderToolPanels();
}

// duplicate removed — renderWsReplay() at line ~9443 is the canonical version

/* ─── Replay request context menu ─── */

// Lazy-initialised: the element may not yet exist when top-level code runs,
// and bindEvents() → initReplayContextMenu() is called early in init().
function getReplayContextMenu() {
  if (!getReplayContextMenu._el) {
    getReplayContextMenu._el = document.getElementById("replayContextMenu");
  }
  return getReplayContextMenu._el;
}

function showReplayContextMenu(event) {
  event.preventDefault();
  const tab = getActiveReplayTab();
  if (!tab) return;

  // Highlight current method
  const currentMethod = (tab.requestText.match(/^([A-Z]+)\s/)?.[1] || "GET").toUpperCase();
  getReplayContextMenu().querySelectorAll(".method-btn").forEach((btn) => {
    btn.classList.toggle("active-method", btn.dataset.method === currentMethod);
  });

  getReplayContextMenu().classList.remove("hidden");
  const x = Math.min(event.clientX, window.innerWidth - 240);
  const y = Math.min(event.clientY, window.innerHeight - 300);
  getReplayContextMenu().style.left = `${x}px`;
  getReplayContextMenu().style.top = `${y}px`;
}

function closeReplayContextMenu() {
  getReplayContextMenu().classList.add("hidden");
}

function changeReplayMethod(newMethod) {
  const tab = getActiveReplayTab();
  if (!tab) return;

  const text = tab.requestText || els.replayRequestEditor.value || "";
  const updated = text.replace(/^[A-Z]+(\s)/i, newMethod + "$1");
  tab.requestText = updated;
  els.replayRequestEditor.value = updated;
  renderReplayRequestHighlight(updated);
  updateReplaySearchPane("request", updated);
  syncReplayToolbar(tab);
  renderReplayTabs();
  scheduleWorkspaceStateSave();
}

function replayRequestToCurl() {
  const tab = getActiveReplayTab();
  if (!tab) return "";

  const text = tab.requestText || "";
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const [startLine = "GET / HTTP/1.1", ...rest] = lines;
  const match = startLine.match(/^([A-Z]+)\s+(\S+)/i);
  if (!match) return "";

  const method = match[1];
  const path = match[2];
  const scheme = tab.targetScheme || "https";
  const host = tab.targetHost || "localhost";
  const port = tab.targetPort || "";
  const portSuffix = port && !(scheme === "https" && port === "443") && !(scheme === "http" && port === "80") ? `:${port}` : "";
  const url = `${scheme}://${host}${portSuffix}${path}`;

  const parts = [`curl -X ${method}`];

  // Separate headers and body
  let bodyIdx = rest.indexOf("");
  if (bodyIdx === -1) {
    for (let i = 0; i < rest.length; i++) {
      const c = rest[i].charAt(0);
      if (c === "{" || c === "[" || c === "<" || c === '"') { bodyIdx = i; break; }
      if (!rest[i].includes(":")) { bodyIdx = i; break; }
    }
  }
  const headerLines = (bodyIdx === -1 ? rest : rest.slice(0, bodyIdx)).filter((l) => l.includes(":"));
  const body = bodyIdx === -1 ? "" : (rest[bodyIdx] === "" ? rest.slice(bodyIdx + 1) : rest.slice(bodyIdx)).join("\n");

  for (const h of headerLines) {
    const idx = h.indexOf(":");
    if (idx === -1) continue;
    const name = h.slice(0, idx).trim();
    const value = h.slice(idx + 1).trim();
    parts.push(`-H '${name}: ${value}'`);
  }

  if (body.trim()) {
    parts.push(`-d '${body.replace(/'/g, "'\\''")}'`);
  }

  parts.push(`'${url}'`);
  return parts.join(" \\\n  ");
}

function parseRequestForExport(rawText, scheme, host, port) {
  const lines = String(rawText || "").replace(/\r\n/g, "\n").split("\n");
  const [startLine = "GET / HTTP/1.1", ...rest] = lines;
  const match = startLine.match(/^([A-Z]+)\s+(\S+)/i);
  if (!match) return null;
  const method = match[1];
  const path = match[2];
  const portSuffix = port && !(scheme === "https" && port === "443") && !(scheme === "http" && port === "80") ? `:${port}` : "";
  const url = `${scheme}://${host}${portSuffix}${path}`;
  let bodyIdx = rest.indexOf("");
  if (bodyIdx === -1) {
    for (let i = 0; i < rest.length; i++) {
      const c = rest[i].charAt(0);
      if (c === "{" || c === "[" || c === "<" || c === '"') { bodyIdx = i; break; }
      if (!rest[i].includes(":")) { bodyIdx = i; break; }
    }
  }
  const headerLines = bodyIdx === -1 ? rest : rest.slice(0, bodyIdx);
  const body = bodyIdx === -1 ? "" : (rest[bodyIdx] === "" ? rest.slice(bodyIdx + 1) : rest.slice(bodyIdx)).join("\n");
  const headers = headerLines.map((h) => {
    const idx = h.indexOf(":");
    return idx === -1 ? null : { name: h.slice(0, idx).trim(), value: h.slice(idx + 1).trim() };
  }).filter(Boolean);
  return { method, url, headers, body };
}

function requestToPython(parsed) {
  if (!parsed) return "";
  const esc = (s) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const lines = [`import requests`, ""];
  const hasBody = parsed.body.trim();
  const headerObj = parsed.headers.filter((h) => h.name.toLowerCase() !== "host" && h.name.toLowerCase() !== "content-length");
  if (headerObj.length) {
    lines.push("headers = {");
    for (const h of headerObj) lines.push(`    "${esc(h.name)}": "${esc(h.value)}",`);
    lines.push("}");
    lines.push("");
  }
  if (hasBody) {
    lines.push(`data = """${parsed.body}"""`);
    lines.push("");
  }
  const args = [`"${esc(parsed.url)}"`];
  if (headerObj.length) args.push("headers=headers");
  if (hasBody) args.push("data=data");
  lines.push(`response = requests.${parsed.method.toLowerCase()}(${args.join(", ")})`);
  lines.push(`print(response.status_code)`);
  lines.push(`print(response.text)`);
  return lines.join("\n");
}

function requestToFetch(parsed) {
  if (!parsed) return "";
  const esc = (s) => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
  const headerObj = parsed.headers.filter((h) => h.name.toLowerCase() !== "host" && h.name.toLowerCase() !== "content-length");
  const opts = [];
  if (parsed.method !== "GET") opts.push(`  method: "${parsed.method}"`);
  if (headerObj.length) {
    const hLines = headerObj.map((h) => `    "${esc(h.name)}": "${esc(h.value)}"`).join(",\n");
    opts.push(`  headers: {\n${hLines}\n  }`);
  }
  if (parsed.body.trim()) {
    opts.push(`  body: ${JSON.stringify(parsed.body)}`);
  }
  if (!opts.length) return `fetch("${esc(parsed.url)}")\n  .then(res => res.text())\n  .then(console.log);`;
  return `fetch("${esc(parsed.url)}", {\n${opts.join(",\n")}\n})\n  .then(res => res.text())\n  .then(console.log);`;
}

function requestToPowerShell(parsed) {
  if (!parsed) return "";
  const esc = (s) => s.replace(/'/g, "''");
  const parts = [`Invoke-WebRequest -Uri '${esc(parsed.url)}'`];
  if (parsed.method !== "GET") parts.push(`-Method ${parsed.method}`);
  const headerObj = parsed.headers.filter((h) => h.name.toLowerCase() !== "host" && h.name.toLowerCase() !== "content-length");
  if (headerObj.length) {
    const hLines = headerObj.map((h) => `'${esc(h.name)}'='${esc(h.value)}'`).join("; ");
    parts.push(`-Headers @{${hLines}}`);
  }
  if (parsed.body.trim()) {
    parts.push(`-Body '${esc(parsed.body)}'`);
  }
  return parts.join(" `\n  ");
}

function replayRequestToFormat(format) {
  const tab = getActiveReplayTab();
  if (!tab) return "";
  const parsed = parseRequestForExport(tab.requestText, tab.targetScheme || "https", tab.targetHost || "localhost", tab.targetPort || "");
  if (format === "curl") return replayRequestToCurl();
  if (format === "python") return requestToPython(parsed);
  if (format === "fetch") return requestToFetch(parsed);
  if (format === "powershell") return requestToPowerShell(parsed);
  return "";
}

function copySelectedTransactionUrl() {
  const record = state.selectedRecord;
  if (!record) return;
  const scheme = record.scheme || "https";
  const host = record.host || "";
  const path = record.path || "/";
  const url = `${scheme}://${host}${path}`;
  copyTextToClipboard(url);
  showToast("Copied URL");
}

function copyResponseContent(format) {
  const record = state.selectedRecord;
  if (!record?.response) return;
  let text = "";
  if (format === "response-headers") {
    text = `HTTP/1.1 ${record.status || 200}\r\n`;
    for (const h of record.response.headers || []) text += `${h.name}: ${h.value}\r\n`;
  } else if (format === "response-body") {
    text = record.response.body_encoding === "base64"
      ? atob(record.response.body_preview || "")
      : (record.response.body_preview || "");
  } else {
    text = buildRawResponse(record);
  }
  const label = format === "response-headers" ? "Copied headers" : format === "response-body" ? "Copied body" : "Copied raw response";
  copyTextToClipboard(text);
  showToast(label);
}

// Synchronous version using already-loaded selectedRecord (preserves user gesture for clipboard)
function selectedRecordToFormat(format) {
  const record = state.selectedRecord;
  if (!record) return "";
  const rawText = buildRawRequest(record);
  const scheme = record.scheme || "https";
  const hostHeader = record.request?.headers?.find((h) => h.name.toLowerCase() === "host");
  const host = hostHeader?.value || record.host || "";
  const parsed = parseRequestForExport(rawText, scheme, host, "");
  if (!parsed) return "";
  if (format === "curl") {
    const esc = (s) => s.replace(/'/g, "'\\''");
    const parts = [`curl -X ${parsed.method}`];
    for (const h of parsed.headers) parts.push(`-H '${h.name}: ${esc(h.value)}'`);
    if (parsed.body.trim()) parts.push(`-d '${esc(parsed.body)}'`);
    parts.push(`'${parsed.url}'`);
    return parts.join(" \\\n  ");
  }
  if (format === "python") return requestToPython(parsed);
  if (format === "fetch") return requestToFetch(parsed);
  if (format === "powershell") return requestToPowerShell(parsed);
  return "";
}

async function historyRequestToFormat(transactionId, format) {
  const response = await fetch(`/api/transactions/${transactionId}`);
  if (!response.ok) return "";
  const record = await response.json();
  const rawText = buildRawRequest(record);
  const scheme = record.scheme || "https";
  const hostHeader = record.request?.headers?.find((h) => h.name.toLowerCase() === "host");
  const host = hostHeader?.value || record.host || "";
  const parsed = parseRequestForExport(rawText, scheme, host, "");
  if (!parsed) return "";
  if (format === "curl") {
    const esc = (s) => s.replace(/'/g, "'\\''");
    const parts = [`curl -X ${parsed.method}`];
    for (const h of parsed.headers) parts.push(`-H '${h.name}: ${esc(h.value)}'`);
    if (parsed.body.trim()) parts.push(`-d '${esc(parsed.body)}'`);
    parts.push(`'${parsed.url}'`);
    return parts.join(" \\\n  ");
  }
  if (format === "python") return requestToPython(parsed);
  if (format === "fetch") return requestToFetch(parsed);
  if (format === "powershell") return requestToPowerShell(parsed);
  return "";
}

function copyTransactionUrl(transactionId) {
  const item = state.items.find((i) => i.id === transactionId);
  if (!item) return;
  const scheme = item.scheme || "https";
  const host = item.host || "";
  const path = item.path || "/";
  const url = `${scheme}://${host}${path}`;
  copyTextToClipboard(url).then(() => showToast("Copied URL")).catch(() => {});
}

function copyReplayUrl() {
  const tab = getActiveReplayTab();
  if (!tab) return;
  const scheme = tab.targetScheme || "https";
  const host = tab.targetHost || "localhost";
  const port = tab.targetPort || "";
  const portSuffix = port && !(scheme === "https" && port === "443") && !(scheme === "http" && port === "80") ? `:${port}` : "";
  const text = tab.requestText || "";
  const match = text.match(/^[A-Z]+\s+(\S+)/i);
  const path = match ? match[1] : "/";
  const url = `${scheme}://${host}${portSuffix}${path}`;
  copyTextToClipboard(url).then(() => showToast("Copied URL")).catch(() => {});
}

function parseCurlCommand(text) {
  const normalized = text.replace(/\\\s*\n/g, " ").trim();
  if (!normalized.toLowerCase().startsWith("curl")) return null;
  const tokens = [];
  let i = 4; // skip "curl"
  while (i < normalized.length) {
    while (i < normalized.length && normalized[i] === " ") i++;
    if (i >= normalized.length) break;
    let token = "";
    const ch = normalized[i];
    if (ch === "'" || ch === '"') {
      const quote = ch;
      i++;
      while (i < normalized.length && normalized[i] !== quote) {
        if (normalized[i] === "\\" && quote === '"') { i++; token += normalized[i] || ""; }
        else token += normalized[i];
        i++;
      }
      i++; // skip closing quote
    } else {
      while (i < normalized.length && normalized[i] !== " ") { token += normalized[i]; i++; }
    }
    tokens.push(token);
  }
  let method = "GET";
  let url = "";
  const headers = [];
  let body = "";
  for (let t = 0; t < tokens.length; t++) {
    const tok = tokens[t];
    if (tok === "-X" || tok === "--request") { method = (tokens[++t] || "GET").toUpperCase(); }
    else if (tok === "-H" || tok === "--header") {
      const hVal = tokens[++t] || "";
      const ci = hVal.indexOf(":");
      if (ci > 0) headers.push({ name: hVal.slice(0, ci).trim(), value: hVal.slice(ci + 1).trim() });
    }
    else if (tok === "-d" || tok === "--data" || tok === "--data-raw" || tok === "--data-binary") { body = tokens[++t] || ""; if (!method || method === "GET") method = "POST"; }
    else if (tok === "-u" || tok === "--user") {
      const cred = tokens[++t] || "";
      headers.push({ name: "Authorization", value: `Basic ${btoa(cred)}` });
    }
    else if (tok === "--compressed" || tok === "-k" || tok === "--insecure" || tok === "-s" || tok === "--silent" || tok === "-v" || tok === "--verbose" || tok === "-L" || tok === "--location") { /* skip flags */ }
    else if (!tok.startsWith("-") && !url) { url = tok; }
  }
  if (!url) return null;
  let scheme = "https";
  let host = "";
  let path = "/";
  try {
    const parsed = new URL(url);
    scheme = parsed.protocol.replace(":", "");
    host = parsed.host;
    path = `${parsed.pathname || "/"}${parsed.search || ""}`;
  } catch (_) { return null; }
  const hasHost = headers.some((h) => h.name.toLowerCase() === "host");
  if (!hasHost) headers.unshift({ name: "Host", value: host });
  const headerText = headers.map((h) => `${h.name}: ${h.value}`).join("\n");
  const requestText = body ? `${method} ${path} HTTP/1.1\n${headerText}\n\n${body}` : `${method} ${path} HTTP/1.1\n${headerText}`;
  return { scheme, host, port: "", method, path, headers, body, requestText };
}

function openCurlImportModal() {
  const modal = document.getElementById("curlImportModal");
  document.getElementById("curlImportInput").value = "";
  modal.classList.remove("hidden");
  document.getElementById("curlImportInput").focus();
}

function closeCurlImportModal() {
  document.getElementById("curlImportModal").classList.add("hidden");
}

function applyCurlImport() {
  const text = document.getElementById("curlImportInput").value;
  const result = parseCurlCommand(text);
  if (!result) return;
  const tab = createReplayTab();
  tab.requestText = result.requestText;
  tab.targetScheme = result.scheme;
  tab.targetHost = result.host.replace(/:\d+$/, "");
  tab.targetPort = result.host.includes(":") ? result.host.split(":").pop() : "";
  tab.baseRequest = {
    scheme: result.scheme,
    host: result.host,
    method: result.method,
    path: result.path,
    headers: result.headers,
    body: result.body,
    body_encoding: "utf8",
    preview_truncated: false,
  };
  state.replayTabs.push(tab);
  state.activeReplayTabId = tab.id;
  state.activeTool = "replay";
  closeCurlImportModal();
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

function initReplayContextMenu() {
  // Method buttons
  getReplayContextMenu().querySelectorAll(".method-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      changeReplayMethod(btn.dataset.method);
      closeReplayContextMenu();
    });
  });

  // Action buttons
  getReplayContextMenu().querySelectorAll("[data-replay-action]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const action = btn.dataset.replayAction;
      const tab = getActiveReplayTab();
      if (!tab) { closeReplayContextMenu(); return; }

      if (action === "toggle-body") {
        const text = tab.requestText || "";
        if (text.includes("\n\n")) {
          // Remove body
          tab.requestText = text.split("\n\n")[0];
        } else {
          // Add empty body section
          tab.requestText = text + "\n\n";
        }
        els.replayRequestEditor.value = tab.requestText;
        renderReplayRequestHighlight(tab.requestText);
        scheduleWorkspaceStateSave();
      } else if (action === "add-content-type-json") {
        setReplayHeader("Content-Type", "application/json");
      } else if (action === "add-content-type-form") {
        setReplayHeader("Content-Type", "application/x-www-form-urlencoded");
      } else if (action === "copy-url") {
        copyReplayUrl();
      } else if (action === "copy-as-curl" || action === "copy-as-python" || action === "copy-as-fetch" || action === "copy-as-powershell") {
        const format = action.replace("copy-as-", "");
        const text = replayRequestToFormat(format);
        copyTextToClipboard(text).then(() => showToast(`Copied as ${format}`)).catch(() => {});
      } else if (action === "import-curl") {
        openCurlImportModal();
      }

      closeReplayContextMenu();
    });
  });

  // Close on outside click
  document.addEventListener("click", (event) => {
    if (!getReplayContextMenu().contains(event.target)) {
      closeReplayContextMenu();
    }
  });
}

function setReplayHeader(name, value) {
  const tab = getActiveReplayTab();
  if (!tab) return;

  const text = tab.requestText || "";
  const normalized = text.replace(/\r\n/g, "\n");
  const bodyIdx = normalized.indexOf("\n\n");
  const head = bodyIdx === -1 ? normalized : normalized.slice(0, bodyIdx);
  const body = bodyIdx === -1 ? "" : normalized.slice(bodyIdx);
  const lines = head.split("\n");

  // Check if header already exists (case-insensitive)
  const lowerName = name.toLowerCase();
  const existingIdx = lines.findIndex((l, i) => i > 0 && l.toLowerCase().startsWith(lowerName + ":"));

  if (existingIdx !== -1) {
    lines[existingIdx] = `${name}: ${value}`;
  } else {
    lines.push(`${name}: ${value}`);
  }

  tab.requestText = lines.join("\n") + body;
  els.replayRequestEditor.value = tab.requestText;
  renderReplayRequestHighlight(tab.requestText);
  updateReplaySearchPane("request", tab.requestText);
  scheduleWorkspaceStateSave();
}

/* ─── Code-view line keyboard navigation + cursor + Cmd+C ─── */

(function initCodeViewLineNav() {
  const READONLY_ATTR = "data-readonly-editable";

  // Make read-only code-views show a text cursor by enabling contenteditable
  // but blocking all mutations so the content stays untouched.
  function enableReadonlyCaret(view) {
    if (view.getAttribute(READONLY_ATTR)) return;
    // Skip views that are already editable for editing purposes (replay editor, ws message)
    if (view.dataset.placeholder) return;
    view.setAttribute("contenteditable", "true");
    view.setAttribute(READONLY_ATTR, "1");
    view.addEventListener("beforeinput", (e) => e.preventDefault());
    view.addEventListener("paste", (e) => e.preventDefault());
    view.addEventListener("drop", (e) => e.preventDefault());
  }

  // Auto-enable for all code-view / simple-code-view with tabindex
  function initAllReadonlyCarets() {
    document.querySelectorAll(".code-view[tabindex], .simple-code-view[tabindex]").forEach((v) => {
      if (!v.dataset.placeholder) enableReadonlyCaret(v);
    });
  }
  // Run once at load and observe DOM for late-added panels
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initAllReadonlyCarets);
  } else {
    initAllReadonlyCarets();
  }
  // Expose helpers so render functions can re-enable after innerHTML swap
  // and preserve line focus across re-renders.
  window._enableReadonlyCaret = enableReadonlyCaret;

  // Save current focus state for a code-view (call before innerHTML swap)
  window._saveCodeViewFocus = function(view) {
    if (!view) return null;
    const focused = view.querySelector(".code-line.line-focus");
    if (!focused) return null;
    const lines = getCodeLines(view);
    const idx = lines.indexOf(focused);
    const wasActive = (document.activeElement === view);
    return { viewId: view.id, lineIndex: idx, wasActive };
  };

  // Restore focus state after innerHTML swap
  window._restoreCodeViewFocus = function(view, saved) {
    if (!view || !saved || saved.lineIndex < 0) return;
    enableReadonlyCaret(view);
    const lines = getCodeLines(view);
    if (saved.lineIndex < lines.length) {
      // Only restore visual highlight — never steal focus from other elements
      clearFocus(view);
      lines[saved.lineIndex].classList.add("line-focus");
      if (saved.wasActive) {
        setFocus(view, lines[saved.lineIndex], true);
      }
    }
  };

  function isReadonlyView(el) {
    return el && el.getAttribute(READONLY_ATTR) === "1";
  }

  function getCodeLines(view) {
    return Array.from(view.querySelectorAll(".code-line"));
  }

  function clearFocus(view) {
    const prev = view.querySelector(".code-line.line-focus");
    if (prev) prev.classList.remove("line-focus");
  }

  function setFocus(view, line, moveCaret) {
    clearFocus(view);
    line.classList.add("line-focus");
    line.scrollIntoView({ block: "nearest" });
    // Only move caret on arrow-key navigation or restore; clicks keep natural position
    if (moveCaret) {
      try {
        const sel = window.getSelection();
        const textNode = line.firstChild;
        if (sel && textNode) {
          const range = document.createRange();
          range.setStart(textNode, 0);
          range.collapse(true);
          sel.removeAllRanges();
          sel.addRange(range);
        }
      } catch (_) { /* ignore if range fails */ }
    }
  }

  function focusedIndex(lines) {
    return lines.findIndex((l) => l.classList.contains("line-focus"));
  }

  // Click: set line focus and ensure the view has keyboard focus
  document.addEventListener("click", (event) => {
    const view = event.target.closest(".code-view, .simple-code-view");
    if (!view || !isReadonlyView(view)) return;
    const line = event.target.closest(".code-line");
    if (line && view.contains(line)) {
      setFocus(view, line, false);
      if (document.activeElement !== view) view.focus({ preventScroll: true });
    }
  });

  // ArrowUp/Down/Home/End: line navigation
  document.addEventListener("keydown", (event) => {
    if (event.key !== "ArrowUp" && event.key !== "ArrowDown" && event.key !== "Home" && event.key !== "End") return;
    let view = document.activeElement;
    if (view && !isReadonlyView(view)) {
      view = view.closest?.(".code-view, .simple-code-view");
    }
    if (!view || !isReadonlyView(view)) return;
    const lines = getCodeLines(view);
    if (!lines.length) return;
    event.preventDefault();
    if (event.key === "Home") {
      setFocus(view, lines[0], true);
      return;
    }
    if (event.key === "End") {
      setFocus(view, lines[lines.length - 1], true);
      return;
    }
    let idx = focusedIndex(lines);
    if (idx === -1) {
      setFocus(view, lines[0], true);
      return;
    }
    const next = event.key === "ArrowDown" ? idx + 1 : idx - 1;
    if (next >= 0 && next < lines.length) {
      setFocus(view, lines[next], true);
    }
  });

  // Cmd+C / Ctrl+C: copy focused line when no text selection
  document.addEventListener("keydown", (event) => {
    if (!(event.metaKey || event.ctrlKey) || event.key.toLowerCase() !== "c") return;
    let view = document.activeElement;
    if (view && !isReadonlyView(view)) {
      view = view.closest?.(".code-view, .simple-code-view");
    }
    if (!view || !isReadonlyView(view)) return;
    const sel = window.getSelection();
    if (sel && sel.toString().length > 0) return; // native copy handles selected text
    const focused = view.querySelector(".code-line.line-focus");
    if (!focused) return;
    event.preventDefault();
    copyTextToClipboard(focused.textContent).catch(() => {});
  });
})();

// ─── CodeMirror 6 Integration ───────────────────────────────────────────────

const sniperCMTheme = CM.EditorView.theme({
  "&": {
    fontSize: "var(--font-xs, 10px)",
    fontFamily: "var(--mono, monospace)",
    backgroundColor: "var(--panel-code, #161616)",
    color: "var(--text, #f1f1f1)",
    height: "100%",
  },
  ".cm-content": {
    padding: "12px 14px",
    caretColor: "var(--accent, #e0a050)",
    lineHeight: "1.48",
    fontFamily: "var(--mono, monospace)",
    color: "var(--text, #f1f1f1)",
  },
  ".cm-gutters": {
    backgroundColor: "var(--code-gutter-bg, rgba(12,12,12,0.78))",
    color: "var(--code-gutter-text, rgba(255,255,255,0.28))",
    border: "none",
    minWidth: "36px",
  },
  ".cm-gutter.cm-lineNumbers .cm-gutterElement": {
    padding: "0 6px 0 12px",
    fontSize: "var(--font-xs)",
    fontFamily: "var(--mono)",
  },
  ".cm-activeLine": {
    backgroundColor: "transparent",
  },
  ".cm-selectionBackground, ::selection": {
    backgroundColor: "rgba(255,255,255,0.12) !important",
  },
  ".cm-cursor": {
    borderLeftColor: "var(--accent, #e0a050)",
  },
  ".cm-scroller": {
    overflow: "auto",
    fontFamily: "var(--mono)",
  },
  ".cm-specialChar": {
    color: "#d19a66",
    backgroundColor: "rgba(209,154,102,0.15)",
    borderRadius: "2px",
    padding: "0 1px",
  },
  ".cm-line": {
    padding: "0",
  },
  "&.cm-focused .cm-selectionBackground": {
    backgroundColor: "rgba(255,255,255,0.15) !important",
  },
  "&.cm-focused": {
    outline: "none",
  },
}, { dark: true });

const sniperHighlightStyle = CM.syntaxHighlighting(CM.HighlightStyle.define([
  { tag: CM.tags.keyword, color: "var(--token-method-color, #22863a)" },           // HTTP method
  { tag: CM.tags.url, color: "var(--token-url-color, #e0a050)" },                  // URL path
  { tag: CM.tags.comment, color: "var(--token-version-color, #6a737d)" },          // HTTP version
  { tag: CM.tags.number, color: "var(--token-info-color, #e0a050)" },              // status code
  { tag: CM.tags.propertyName, color: "var(--token-header-color, #6cb6d9)" },      // header name
  { tag: CM.tags.string, color: "var(--token-plain-color, #f1f1f1)" },             // header value
  { tag: CM.tags.punctuation, color: "var(--token-punctuation-color, #888)" },     // colon, braces
  { tag: CM.tags.labelName, color: "var(--token-json-key-color, #c9a96e)" },       // JSON key
  { tag: CM.tags.bool, color: "var(--token-json-key-color, #c9a96e)" },            // JSON bool
  { tag: CM.tags.null, color: "var(--token-json-key-color, #c9a96e)" },            // JSON null
]));

function createBaseExtensions(options = {}) {
  const exts = [
    sniperCMTheme,
    sniperHighlightStyle,
    CM.lineNumbers(),
    CM.highlightSpecialChars(),
    CM.drawSelection(),
    CM.EditorView.lineWrapping,
    CM.highlightSelectionMatches(),
  ];
  if (options.readOnly) {
    exts.push(CM.EditorState.readOnly.of(true));
    exts.push(CM.EditorView.editable.of(false));
  } else {
    exts.push(CM.history());
    exts.push(CM.keymap.of([...CM.defaultKeymap, ...CM.historyKeymap, ...CM.searchKeymap]));
  }
  if (options.placeholder) {
    exts.push(CM.placeholder(options.placeholder));
  }
  return exts;
}

/** Reusable CodeMirror wrapper for Sniper code views. */
class SniperCodeView {
  constructor(container, options = {}) {
    this._langCompartment = new CM.Compartment();
    this._readOnlyCompartment = new CM.Compartment();
    this._options = options;
    this.view = new CM.EditorView({
      state: CM.EditorState.create({
        doc: "",
        extensions: [
          ...createBaseExtensions(options),
          this._langCompartment.of([]),
        ],
      }),
      parent: container,
    });
  }

  setContent(text) {
    const { view } = this;
    view.dispatch({
      changes: { from: 0, to: view.state.doc.length, insert: text || "" },
    });
  }

  getContent() {
    return this.view.state.doc.toString();
  }

  destroy() {
    this.view.destroy();
  }
}

// CodeMirror-based code pane instances (lazy-initialized)
const _cmViews = {};

function updateCodePaneCM(key, container, text) {
  if (!_cmViews[key]) {
    _cmViews[key] = new SniperCodeView(container, { readOnly: true });
  }
  _cmViews[key].setContent(text || "");
  const lineCount = (text || "").split("\n").length;
  return { lineCount, matchCount: 0 };
}
