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
      websocket: true,
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
  "snow",
  "ivory",
  "frost",
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
const OAST_TOKEN_REDACTION = "********";
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HISTORY_COLUMN_RULES = {
  index: { default: 48, min: 40, max: 88 },
  host: { default: 320, min: 160, max: 720 },
  method: { default: 110, min: 90, max: 180 },
  path: { default: 420, min: 180, max: 1200 },
  status: { default: 110, min: 94, max: 180 },
  length: { default: 104, min: 82, max: 180 },
  mime: { default: 128, min: 100, max: 260 },
  notes: { default: 220, min: 74, max: 640 },
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
const HTTP_HISTORY_SORT_KEYS = new Set(Object.keys(HISTORY_COLUMN_RULES));
const HTTP_METHOD_FILTER_OPTIONS = new Set(["", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const HTTP_COLOR_TAG_OPTIONS = new Set(["red", "orange", "yellow", "green", "blue", "purple"]);
// Index order behind the Cmd+1~6 (tag) and Ctrl+Cmd+1~6 (filter) shortcuts.
const HTTP_COLOR_TAG_ORDER = ["red", "orange", "yellow", "green", "blue", "purple"];
const DEFAULT_HISTORY_COLUMN_ORDER = ["index", "host", "method", "path", "status", "length", "mime", "notes", "tls", "started_at"];
const HISTORY_TIME_FORMATTER = new Intl.DateTimeFormat("en-US", {
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});
const HISTORY_SORT_COLLATOR = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });
const HTTP_HISTORY_PAGE_SIZE = 5000;
const HTTP_HISTORY_MAX_LOADED_ITEMS = HTTP_HISTORY_PAGE_SIZE;
const HTTP_HISTORY_BACKFILL_DELAY_MS = 80;
const HTTP_HISTORY_SCROLL_PREFETCH_ROWS = 120;
const HTTP_HISTORY_POLL_FALLBACK_MS = 30000;
const WEBSOCKET_POLL_FALLBACK_MS = 30000;
const WEBSOCKET_PAGE_SIZE = 500;
const WEBSOCKET_MAX_LOADED_SESSIONS = 5000;
const WEBSOCKET_SCROLL_PREFETCH_PX = 240;
const WEBSOCKET_QUERY_BACKFILL_DELAY_MS = 100;
const WEBSOCKET_SUMMARY_EVENT_BATCH_MS = 250;
const WEBSOCKET_DETAIL_FRAME_LIMIT = 1000;
const WEBSOCKET_MAX_LOADED_FRAMES = 5000;
const WEBSOCKET_FRAME_ROW_PREVIEW_CHARS = 160;
const FINDINGS_BADGE_POLL_INTERVAL_MS = 30000;
const EVENT_LOG_LIMIT = 200;
const WS_REPLAY_MAX_LOADED_FRAMES = 10000;
const WS_REPLAY_MAX_RENDERED_FRAMES = 1000;
const WS_REPLAY_MAX_PERSISTED_FRAMES = 1000;
const WS_REPLAY_MAX_PERSISTED_FRAME_BODY_BYTES = 16 * 1024;
const WS_REPLAY_MAX_PERSISTED_TOTAL_FRAMES = 2000;
const WS_REPLAY_MAX_PERSISTED_TOTAL_BODY_BYTES = 12 * 1024 * 1024;
const WS_REPLAY_MAX_SETUP_QUEUE_ITEMS = 250;
const WS_REPLAY_TRANSCRIPT_SAVE_DELAY_MS = 2000;
const WS_REPLAY_TRANSCRIPT_SAVE_MAX_WAIT_MS = 5000;
const WEBSOCKET_SORTED_SUMMARY_REFRESH_MIN_MS = 2000;
const WORKSPACE_UNLOAD_KEEPALIVE_MAX_BYTES = 60 * 1024;
const WORKSPACE_UNLOAD_HISTORY_ENTRIES_MAX_BYTES = 12 * 1024;
const WORKSPACE_UNLOAD_RESPONSE_RECORD_MAX_BYTES = 12 * 1024;
const WORKSPACE_UNLOAD_WS_SETUP_QUEUE_MAX_BYTES = 12 * 1024;
const WORKSPACE_UNLOAD_WS_FRAMES_MAX_BYTES = 24 * 1024;
const WORKSPACE_UNLOAD_UNSAVED_MESSAGE = "Large Replay edits have not finished saving.";
const MAX_ANNOTATION_NOTE_BYTES = 32 * 1024;
const WS_REPLAY_FINAL_POLL_INTERVAL_MS = 100;
const WS_REPLAY_FINAL_POLL_TIMEOUT_MS = 2200;
const HTTP_METHOD_TOKEN_RE = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;
const WS_COLUMN_RULES = {
  index:       { default: 48,  min: 36,  max: 80 },
  host:        { default: 260, min: 120, max: 600 },
  path:        { default: 0,   min: 0,   max: 0 },   // flex column, not resizable
  status:      { default: 62,  min: 50,  max: 120 },
  frame_count: { default: 72,  min: 50,  max: 140 },
  duration_ms: { default: 90,  min: 60,  max: 180 },
  started_at:  { default: 150, min: 110, max: 260 },
};
const WEBSOCKET_SORT_KEYS = new Set(Object.keys(WS_COLUMN_RULES));

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
const DETAIL_LOADING_DELAY_MS = 120;
const REPEATER_HISTORY_LIMIT = 30;
const HISTORY_ROW_HEIGHT = 27;
let measuredHistoryRowHeight = HISTORY_ROW_HEIGHT;
const HISTORY_BUFFER_ROWS = 30;
const FUZZER_RESULT_ROW_HEIGHT = 27;
let measuredFuzzerResultRowHeight = FUZZER_RESULT_ROW_HEIGHT;
const FUZZER_RESULT_BUFFER_ROWS = 30;
const FINDINGS_ROW_HEIGHT = 27;
const FINDINGS_BUFFER_ROWS = 20;
const IMPLEMENTED_TOOLS = new Set(["dashboard", "target", "proxy", "fuzzer", "sequence", "replay", "tools", "logger"]);
const IMPLEMENTED_PROXY_TABS = new Set(["intercept", "http-history", "websockets-history", "replace", "findings", "oast", "proxy-settings"]);
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

function safeDecodeBase64(value, fallback = "") {
  if (!value) return "";
  try {
    return atob(value);
  } catch (_error) {
    return fallback || value;
  }
}

function safeEncodeBase64(value) {
  try {
    return btoa(value);
  } catch (_error) {
    const bytes = new TextEncoder().encode(value || "");
    let binary = "";
    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }
    return btoa(binary);
  }
}

function decodedBase64Length(value) {
  return atob(value || "").length;
}

function editableRequestBodyLength(body, bodyEncoding) {
  if (bodyEncoding === "base64") {
    return decodedBase64Length(body);
  }
  return new TextEncoder().encode(body || "").length;
}

function editableResponseBodyLength(bodyText, bodyEncoding) {
  if (bodyEncoding === "base64") {
    return decodedBase64Length(safeEncodeBase64(bodyText || ""));
  }
  return new TextEncoder().encode(bodyText || "").length;
}

function isBase64Text(value) {
  const normalized = String(value || "").replace(/\s+/g, "");
  if (!normalized || normalized.length % 4 !== 0) return false;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(normalized)) return false;
  try {
    atob(normalized);
    return true;
  } catch (_error) {
    return false;
  }
}

function wsReplayBodyForSend(body, kind, bodyIsEncoded = false) {
  const messageKind = normalizeWsMessageType(kind);
  if (messageKind === "text") return body;
  return bodyIsEncoded ? String(body || "").replace(/\s+/g, "") : safeEncodeBase64(body);
}

function defaultWsPortForScheme(scheme) {
  return scheme === "ws" ? 80 : 443;
}

function jsonArray(value) {
  return Array.isArray(value) ? value : [];
}

function websocketPagePayload(value) {
  if (Array.isArray(value)) {
    return {
      items: value,
      total: value.length,
      limit: value.length,
      has_more: false,
    };
  }
  const payload = value && typeof value === "object" ? value : {};
  const items = jsonArray(payload.items);
  return {
    items,
    total: Number.isFinite(Number(payload.total)) ? Number(payload.total) : items.length,
    filteredTotal: Number.isFinite(Number(payload.filtered_total)) ? Number(payload.filtered_total) : null,
    offset: Number.isFinite(Number(payload.offset)) ? Number(payload.offset) : 0,
    limit: Number.isFinite(Number(payload.limit)) ? Number(payload.limit) : items.length,
    has_more: Boolean(payload.has_more),
  };
}

function createHistoryPagingState() {
  return {
    generation: 0,
    querySignature: "",
    pageSize: HTTP_HISTORY_PAGE_SIZE,
    offset: 0,
    beforeSequence: null,
    total: 0,
    filteredTotal: null,
    hasMore: true,
    loading: false,
    fullyLoaded: false,
    backfillScheduled: false,
    trimmedHeadCount: 0,
    trimmedTailCount: 0,
    hiddenConnectTotal: null,
  };
}

function createWebsocketPagingState() {
  return {
    querySignature: "",
    total: 0,
    filteredTotal: null,
    limit: WEBSOCKET_PAGE_SIZE,
    loadedOffset: 0,
    offset: 0,
    afterId: null,
    hasMore: false,
    capReached: false,
    loading: false,
    summaryMutationGeneration: 0,
  };
}

const state = {
  items: [],
  selectedId: null,
  selectedRecord: null,
  loadingDetailId: null,
  historyPaging: createHistoryPagingState(),
  historyListError: "",
  historyDirty: false,
  historyResetScrollOnNextLoad: false,
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
  sortKey: "index",
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
  targetScopeEditorSessionId: null,
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
  websocketPaging: createWebsocketPagingState(),
  websocketListError: "",
  websocketHistoryDirty: false,
  websocketQuery: "",
  websocketSortKey: "started_at",
  websocketSortDirection: "desc",
  websocketInScopeOnly: false,
  websocketLiveOnly: false,
  websocketStackHeight: null,
  selectedWebsocketId: null,
  selectedWebsocketRecord: null,
  selectedWebsocketDetailError: "",
  selectedFrameIdx: null,
  wsKeyboardFocus: "sessions",
  replayTabs: [],
  workspaceRevision: 0,
  activeReplayTabId: null,
  replayTabSequence: 0,
  replayRenamingTabId: null,
  replayMessageViews: { request: "pretty", response: "pretty" },
  interceptEditorSeedId: null,
  interceptInScopeOnly: false,
  eventLog: [],
  matchReplaceRules: [],
  selectedMatchReplaceRuleId: null,
  matchReplaceDirty: false,
  matchReplaceEditorSessionId: null,
  targetSiteMap: [],
  oastCallbacks: [],
  selectedOastId: null,
  sequenceDefinitions: [],
  selectedSequenceId: null,
  editingSequence: null,
  sequenceSelectionGeneration: 0,
  sequenceRunGeneration: 0,
  sequenceRunning: false,
  sequenceDirty: false,
  sequenceDraftVersion: 0,
  sequenceRunResult: null,
  sequencePastRuns: [],
  fuzzerBaseRequest: null,
  fuzzerSourceTransactionId: null,
  fuzzerTarget: null,
  fuzzerTargetRequestText: null,
  fuzzerNotice: "",
  fuzzerRequestText: "",
  fuzzerPayloadsText: "",
  fuzzerAttackRecordId: null,
  fuzzerAttackRecord: null,
  fuzzerRunning: false,
  fuzzerDraftVersion: 0,
  fuzzerRunToken: 0,
  oastTokenClearPending: false,
  _cachedVisibleEntries: null,
  _cachedVisibleEntriesKey: "",
  _visibleEntriesSearchCache: null,
  _historyEntries: null,
  _itemById: new Map(),
  _itemIndexById: new Map(),
  _itemsVersion: 0,
  toolsReady: false,
  workbenchHeight: null,
  workbenchPaneWidths: null,
  websocketPaneWidth: null,
  wsReplayLeftWidth: null,
  wsReplayFrameDetailHeight: null,
};

let _historyPagingGeneration = 0;
let _historyDetailLoadingTimer = null;
let _websocketLoadGeneration = 0;
let _websocketDetailGeneration = 0;
let _eventLogMutationGeneration = 0;
let _eventLogClearGeneration = 0;
let _websocketDetailPendingId = null;
let _websocketDetailPendingSessionId = null;
let _websocketDetailPendingPromise = null;
let _websocketDetailLoadingTimer = null;
let _websocketDetailRefreshTimer = null;
let _websocketDetailRefreshNeeded = null;
let _websocketSummaryMutationGeneration = 0;
let _websocketSummaryMutationById = new Map();
let _websocketSummaryEventBuffer = new Map();
let _websocketSummaryEventTimer = 0;
let _websocketVisibleSyncTimer = null;
let _websocketVisibleSyncEnsureSelected = false;
let _websocketVisibleSyncDeferStaleDetail = false;
let _websocketQueryBackfillTimer = 0;
let _websocketQueryBackfillGeneration = 0;
let _websocketFilteredReloadTimer = 0;
let _websocketFilteredReloadDueAt = 0;
let _websocketSearchReloadTimer = 0;
let _lastHttpHistoryFallbackPoll = Date.now();
let _lastWebsocketFallbackPoll = Date.now();
let _lastWebsocketPageRefreshAt = 0;
let _interceptToggleRequestSeq = 0;
let _interceptToggleInFlight = false;

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
  filterMimeWebsocket: document.getElementById("filterMimeWebsocket"),
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
  interceptSearchInput: document.getElementById("interceptSearchInput"),
  interceptSearchMeta: document.getElementById("interceptSearchMeta"),
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
  proxySettingOastClearToken: document.getElementById("proxySettingOastClearToken"),
  proxySettingOastTokenHint: document.getElementById("proxySettingOastTokenHint"),
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
  curlImportModal: document.getElementById("curlImportModal"),
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
  fuzzerDetailPanel: document.getElementById("fuzzerDetailPanel"),
  fuzzerDetailReqCM: document.getElementById("fuzzerDetailReqCM"),
  fuzzerDetailResCM: document.getElementById("fuzzerDetailResCM"),
  fuzzerDetailResponseMeta: document.getElementById("fuzzerDetailResponseMeta"),
  startFuzzerButton: document.getElementById("startFuzzerButton"),
  resetFuzzerButton: document.getElementById("resetFuzzerButton"),
  contextMenu: document.getElementById("contextMenu"),
  contextMenuNote: document.getElementById("contextMenuNote"),
  contextMenuNotes: document.getElementById("contextMenuNotes"),
  contextMenuNotesSection: document.getElementById("contextMenuNotesSection"),
  contextMenuNotesDivider: document.getElementById("contextMenuNotesDivider"),
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
  // CodeMirror containers
  findingsReqCM: document.getElementById("findingsReqCM"),
  findingsResCM: document.getElementById("findingsResCM"),
  websocketHandshakeCM: document.getElementById("websocketHandshakeCM"),
  interceptRequestCM: document.getElementById("interceptRequestCM"),
  interceptResponseCM: document.getElementById("interceptResponseCM"),
  replayRequestCM: document.getElementById("replayRequestCM"),
  fuzzerRequestCM: document.getElementById("fuzzerRequestCM"),
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
let wsTranscriptSaveTimer = null;
let wsTranscriptFirstDirtyAt = 0;
let workspaceSaveInFlight = false;
let workspaceSaveDirty = false;
let workspaceSaveVersion = 0;
let workspaceSaveLastSnapshot = null;
let workspaceSaveCommittedSnapshot = null;
const workspaceClientId = createWorkspaceClientId();
let workspaceSaveLoopPromise = null;
let workspaceSaveConflictPending = false;
let workspaceSaveConflictLatest = null;
const uiSettingsClientId = createWorkspaceClientId();
let uiSettingsSaveVersion = 0;
let uiSettingsServerRevision = 0;
const annotationClientId = createWorkspaceClientId();
let annotationSaveVersion = 0;
let uiSettingsSaveTimer = null;
let uiSettingsDirty = false;
let uiSettingsInFlight = false;
let uiSettingsSavePromise = null;
let lastUiSettingsPayload = null;
let proxySettingsSaveInFlight = false;
let proxySettingsSavePromise = null;
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
const WEBSOCKET_MAX_RENDERED_SESSION_ROWS = 500;
const WEBSOCKET_MAX_RENDERED_FRAME_ROWS = 1000;
const WEBSOCKET_SESSION_ROW_HEIGHT = 28;
let measuredWebsocketSessionRowHeight = WEBSOCKET_SESSION_ROW_HEIGHT;
const WEBSOCKET_FRAME_ROW_HEIGHT = 28;
let measuredWebsocketFrameRowHeight = WEBSOCKET_FRAME_ROW_HEIGHT;
const WEBSOCKET_SESSION_BUFFER_ROWS = 30;
const WEBSOCKET_FRAME_BUFFER_ROWS = 30;

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
  await loadSessions();
  await loadSettings();
  const shouldLoadInitialHttpHistory = isHttpHistoryVisible();
  const shouldLoadInitialWebsocketHistory = isWebsocketHistoryVisible();
  if (!shouldLoadInitialHttpHistory) {
    state.historyDirty = true;
  }
  if (!shouldLoadInitialWebsocketHistory) {
    state.websocketHistoryDirty = true;
  }
  const loads = [
    loadWorkspaceState(),
    shouldLoadInitialHttpHistory ? loadTransactions(false) : Promise.resolve(),
    loadIntercepts(false),
    loadResponseIntercepts(false),
    loadInterceptRules(),
    shouldLoadInitialWebsocketHistory ? loadWebsockets(false) : Promise.resolve(),
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

function setActiveTool(tool, options = {}) {
  state.activeTool = sanitizeActiveTool(tool);
  if (options.persist !== false) {
    scheduleUiSettingsSave(options.delay);
  }
  return state.activeTool;
}

function setActiveProxyTab(tab, options = {}) {
  state.activeProxyTab = sanitizeActiveProxyTab(tab);
  if (options.persist !== false) {
    scheduleUiSettingsSave(options.delay);
  }
  return state.activeProxyTab;
}

function bindEvents() {
  window.addEventListener("resize", resetLayoutTextareas);
  document.addEventListener("visibilitychange", flushWorkspaceStateBeforeHidden);
  window.addEventListener("pagehide", flushWorkspaceStateOnUnload);
  window.addEventListener("beforeunload", flushWorkspaceStateOnUnload);
  window.addEventListener("pagehide", flushUiSettingsOnUnload);
  window.addEventListener("beforeunload", flushUiSettingsOnUnload);
  window.addEventListener("pagehide", flushAnnotationsOnUnload);
  window.addEventListener("beforeunload", flushAnnotationsOnUnload);

  mainTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      setActiveTool(tab.dataset.tool);
      renderToolPanels();
      if (state.activeTool === "dashboard") {
        loadSessions({ reloadOnActiveChange: true }).catch((error) => console.error(error));
      }
      if (state.activeTool === "target") {
        loadTargetSiteMap(true).catch((error) => console.error(error));
      }
      if (state.activeTool === "logger") {
        loadEventLog().catch((error) => console.error(error));
      }
      if (state.activeTool === "proxy" && state.activeProxyTab === "http-history") {
        if (state.historyDirty) loadTransactions(true, consumeHistoryLoadOptions()).catch((error) => console.error(error));
      }
      if (state.activeTool === "proxy" && state.activeProxyTab === "websockets-history") {
        if (state.websocketHistoryDirty) loadWebsocketsPageRefresh(true).catch((error) => console.error(error));
      }
    });
  });

  proxyTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      setActiveProxyTab(tab.dataset.proxyTab);
      renderProxyPanels();
      if (state.activeProxyTab === "intercept") {
        loadIntercepts(true).catch((error) => console.error(error));
        loadResponseIntercepts(true).catch((error) => console.error(error));
        loadInterceptRules().catch((error) => console.error(error));
      }
      if (state.activeProxyTab === "websockets-history") {
        loadWebsocketsPageRefresh(true).catch((error) => console.error(error));
      }
      if (state.activeProxyTab === "http-history") {
        if (state.historyDirty) loadTransactions(true, consumeHistoryLoadOptions()).catch((error) => console.error(error));
      }
      if (state.activeProxyTab === "proxy-settings") {
        loadRuntimeSettings().catch((error) => console.error(error));
      }
      if (state.activeProxyTab === "replace") {
        flushMatchReplaceDraft()
          .then((ok) => {
            if (ok) return loadMatchReplaceRules();
            return null;
          })
          .catch((error) => console.error(error));
      }
      if (state.activeProxyTab === "oast") {
        loadOastCallbacks().catch((error) => console.error(error));
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
    selectHistoryTransaction(row.dataset.id, { scroll: true }).catch((error) => console.error(error));
    // Keep focus on the table so arrow keys navigate rows, not code-view lines
    els.trafficRegion.focus({ preventScroll: true });
    // Clicking a Notes cell that has notes opens them. The inspector column
    // that normally shows notes is hidden below 1481px, so this is the only
    // always-available way to read them. stopPropagation keeps the document
    // click handler from closing the menu we are opening.
    const notesCell = event.target.closest('td.notes-cell-actionable[data-col="notes"]');
    if (notesCell) {
      event.stopPropagation();
      const rect = notesCell.getBoundingClientRect();
      openContextMenu(rect.left, rect.bottom + 4, row.dataset.id);
    }
  });
  els.historyTableBody.addEventListener("contextmenu", (event) => {
    const row = event.target.closest(".history-row");
    if (!row) return;
    event.preventDefault();
    selectHistoryTransaction(row.dataset.id).catch((error) => console.error(error));
    openContextMenu(event.clientX, event.clientY, row.dataset.id);
  });

  let _searchDebounce = 0;
  els.searchInput.addEventListener("input", () => {
    // Pause incremental refresh while user is actively typing
    _searchActiveUntil = Date.now() + 800;
    clearTimeout(_searchDebounce);
    _searchDebounce = setTimeout(() => {
      state.query = els.searchInput.value.trim();
      scheduleUiSettingsSave();
      clearHttpHistorySelectionPreview();
      scheduleRefresh({ resetScroll: true });
    }, 60);
  });
  els.searchInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      clearTimeout(_searchDebounce);
      state.query = els.searchInput.value.trim();
      scheduleUiSettingsSave();
      clearHttpHistorySelectionPreview();
      scheduleRefresh({ resetScroll: true });
    }
  });
  els.searchInput.addEventListener("search", () => {
    // Triggered when user clears the search field via the X button
    clearTimeout(_searchDebounce);
    state.query = els.searchInput.value.trim();
    scheduleUiSettingsSave();
    clearHttpHistorySelectionPreview();
    scheduleRefresh({ resetScroll: true });
  });

  els.requestSearchInput.addEventListener("input", () => {
    state.messageSearch.request = els.requestSearchInput.value;
    updateMessagePaneSearch("request");
  });

  els.responseSearchInput.addEventListener("input", () => {
    state.messageSearch.response = els.responseSearchInput.value;
    updateMessagePaneSearch("response");
  });

  els.replayRequestSearchInput.addEventListener("input", () => {
    state.replayMessageSearch.request = els.replayRequestSearchInput.value;
    const cv = getCMView("replayReq");
    const reqText = cv ? cv.getContent() : (els.replayRequestEditor ? els.replayRequestEditor.value : "") || "";
      updateReplaySearchPane("request", reqText);
  });

  els.replayResponseSearchInput.addEventListener("input", () => {
    state.replayMessageSearch.response = els.replayResponseSearchInput.value;
    const resText = _replayResponseCMView
      ? _replayResponseCMView.view.state.doc.toString()
      : (els.replayResponseView ? els.replayResponseView.textContent : "") || "";
    updateReplaySearchPane("response", resText);
  });

  // Search hit navigation: click counter to cycle through matches
  initSearchHitNavigation(els.requestSearchMeta, () => els.requestView);
  initSearchHitNavigation(els.responseSearchMeta, () => els.responseView);
  // CM search navigation: click counter cycles through CM matches
  initCMSearchNavigation(els.requestSearchMeta, "request");
  initCMSearchNavigation(els.responseSearchMeta, "response");
  initSearchHitNavigation(els.replayRequestSearchMeta, () => els.replayRequestHighlight);
  initSearchHitNavigation(els.replayResponseSearchMeta, () => els.replayResponseView);
  initCMSearchNavigation(els.replayRequestSearchMeta, "replayReq");
  initReplayResponseCMSearchNavigation();

  els.websocketSearchInput.addEventListener("input", () => {
    state.websocketQuery = els.websocketSearchInput.value.trim();
    scheduleUiSettingsSave();
    clearWebsocketQueryBackfill();
    clearWebsocketSelectionPreview({ render: true });
    if (_websocketSearchReloadTimer) {
      window.clearTimeout(_websocketSearchReloadTimer);
    }
    _websocketSearchReloadTimer = window.setTimeout(() => {
      _websocketSearchReloadTimer = 0;
      loadWebsocketsPageRefresh(true, { resetWindow: true }).catch((error) => console.error(error));
    }, 160);
  });
  let websocketScrollRaf = 0;
  document.querySelector("#websocketTable")?.closest(".history-table-shell")?.addEventListener("scroll", (event) => {
    const scroller = event.currentTarget;
    if (!scroller || state.activeProxyTab !== "websockets-history") {
      return;
    }
    if (!websocketScrollRaf) {
      websocketScrollRaf = requestAnimationFrame(() => {
        websocketScrollRaf = 0;
        renderWebsocketSessionTable();
      });
    }
    if (scroller.scrollTop + scroller.clientHeight >= scroller.scrollHeight - WEBSOCKET_SCROLL_PREFETCH_PX) {
      loadMoreWebsockets().catch((error) => console.error(error));
    }
  });
  els.websocketTableBody?.addEventListener("click", (event) => {
    const row = event.target.closest(".history-row");
    if (!row || !els.websocketTableBody.contains(row)) {
      return;
    }
    state.wsKeyboardFocus = "sessions";
    if (
      state.selectedWebsocketId === row.dataset.id
      && state.selectedWebsocketRecord?.id === row.dataset.id
      && !state.selectedWebsocketDetailError
    ) {
      return;
    }
    const hadRenderedWebsocketDetail = Boolean(state.selectedWebsocketRecord?.id);
    if (state.selectedWebsocketId !== row.dataset.id) {
      state.selectedFrameIdx = null;
      state.selectedWebsocketRecord = null;
      state.selectedWebsocketDetailError = "";
      hideFrameDetail();
      resetWebsocketFrameScroll();
    }
    state.selectedWebsocketId = row.dataset.id;
    renderWebsocketSessionTable();
    scheduleWebsocketDetailLoading(row.dataset.id, {
      immediate: !hadRenderedWebsocketDetail,
    });
    loadWebsocketDetail(row.dataset.id).catch((error) => console.error(error));
  });
  els.websocketFramesBody?.addEventListener("click", (event) => {
    const loadOlderButton = event.target.closest("[data-ws-load-older-frames]");
    if (loadOlderButton && els.websocketFramesBody.contains(loadOlderButton)) {
      loadOlderWebsocketFrames().catch((error) => console.error(error));
      return;
    }
    const row = event.target.closest(".history-row[data-frame-index]");
    if (!row || !els.websocketFramesBody.contains(row)) {
      return;
    }
    selectWebsocketFrameRow(row);
  });
  els.websocketFramesBody?.addEventListener("contextmenu", (event) => {
    const row = event.target.closest(".history-row[data-frame-index]");
    if (!row || !els.websocketFramesBody.contains(row)) {
      return;
    }
    event.preventDefault();
    if (selectWebsocketFrameRow(row)) {
      openWsFrameContextMenu(event.clientX, event.clientY);
    }
  });
  let websocketFrameScrollRaf = 0;
  els.websocketFramesBody?.closest(".history-table-shell")?.addEventListener("scroll", () => {
    if (state.activeProxyTab !== "websockets-history" || !state.selectedWebsocketRecord) {
      return;
    }
    if (!websocketFrameScrollRaf) {
      websocketFrameScrollRaf = requestAnimationFrame(() => {
        websocketFrameScrollRaf = 0;
        renderWebsocketFrameTable();
      });
    }
  });
  document.getElementById("wsInScopeOnly")?.addEventListener("click", (e) => {
    state.websocketInScopeOnly = e.currentTarget.classList.toggle("active");
    scheduleUiSettingsSave();
    clearWebsocketQueryBackfill();
    clearWebsocketSelectionPreview({ render: true });
    loadWebsocketsPageRefresh(true, { resetWindow: true }).catch((error) => console.error(error));
  });
  document.getElementById("wsHideClosed")?.addEventListener("click", (e) => {
    state.websocketLiveOnly = e.currentTarget.classList.toggle("active");
    scheduleUiSettingsSave();
    clearWebsocketQueryBackfill();
    clearWebsocketSelectionPreview({ render: true });
    loadWebsocketsPageRefresh(true, { resetWindow: true }).catch((error) => console.error(error));
  });
  document.getElementById("httpInScopeToggle")?.addEventListener("click", (e) => {
    e.currentTarget.classList.toggle("active");
    state.filterSettings.inScopeOnly = e.currentTarget.classList.contains("active");
    scheduleUiSettingsSave();
    clearHttpHistorySelectionPreview();
    scheduleRefresh({ resetScroll: true });
  });
  document.getElementById("interceptInScopeToggle")?.addEventListener("click", async (e) => {
    const toggle = e.currentTarget;
    const sessionId = currentSessionId();
    const previousScopeOnly = Boolean(state.interceptInScopeOnly);
    const nextScopeOnly = !toggle.classList.contains("active");
    toggle.classList.toggle("active", nextScopeOnly);
    toggle.disabled = true;
    state.interceptInScopeOnly = nextScopeOnly;
    try {
      await applyInterceptScopeFilterLocally();
      const response = await fetch("/api/runtime", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          session_id: sessionId,
          expected_active_session_id: expectedActiveSessionIdForWrite(sessionId),
          intercept_scope_only: nextScopeOnly,
        }),
      });
      await requireOkResponse(response, "Failed to update intercept scope.");
      const runtime = await response.json();
      if (sessionId !== currentSessionId()) {
        return;
      }
      state.runtime = runtime;
      const savedScopeOnly = state.runtime?.intercept_scope_only ?? nextScopeOnly;
      state.interceptInScopeOnly = savedScopeOnly;
      toggle.classList.toggle("active", savedScopeOnly);
      await applyInterceptScopeFilterLocally();
    } catch (err) {
      if (sessionId !== currentSessionId()) {
        return;
      }
      console.error("Failed to update intercept scope:", err);
      showToast(err?.message || "Failed to update intercept scope.", "error");
      state.interceptInScopeOnly = previousScopeOnly;
      toggle.classList.toggle("active", previousScopeOnly);
      await applyInterceptScopeFilterLocally();
    } finally {
      toggle.disabled = false;
    }
  });

  els.methodFilter.addEventListener("change", () => {
    state.method = els.methodFilter.value;
    scheduleUiSettingsSave();
    clearHttpHistorySelectionPreview();
    scheduleRefresh({ resetScroll: true });
  });

  els.colorTagFilter.addEventListener("click", (event) => {
    const btn = event.target.closest(".color-dot-btn");
    if (!btn) return;
    toggleColorTagFilter(btn.dataset.color);
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
    syncHttpInScopePill();
    scheduleUiSettingsSave();
    clearHttpHistorySelectionPreview();
    scheduleRefresh({ resetScroll: true });
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
    setActiveTool("logger");
    await loadEventLog();
    renderToolPanels();
  });
  els.dashboardReloadSessionsButton?.addEventListener("click", () => {
    loadSessions({ reloadOnActiveChange: true }).catch((error) => console.error(error));
  });
  els.dashboardCreateSessionButton?.addEventListener("click", () => {
    createSession().catch(handleWorkspaceActionError);
  });
  els.dashboardOpenStorageBtn?.addEventListener("click", () => {
    const sessionId = state.selectedSessionId || state.activeSession?.id || state.sessions.find((s) => s.active)?.id;
    if (sessionId) {
      revealSessionFolder(sessionId).catch((error) => {
        console.error(error);
        showToast(error?.message || "Failed to open session folder.", "error");
      });
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
    clearEventLog().catch((error) => {
      console.error(error);
      showToast(error?.message || "Failed to clear event log.", "error");
    });
  });

  els.closeInspectorButton?.addEventListener("click", () => {
    state.inspectorCollapsed = true;
    renderInspectorPanels();
  });

  document.getElementById("addInterceptRuleButton")?.addEventListener("click", () => {
    addInterceptRule().catch(handleInterceptRuleError);
  });
  document.getElementById("interceptRulesList").addEventListener("click", (event) => {
    const deleteBtn = event.target.closest("[data-rule-delete]");
    if (deleteBtn) { deleteInterceptRule(deleteBtn.dataset.ruleDelete).catch(handleInterceptRuleError); return; }
    const saveBtn = event.target.closest("[data-rule-save]");
    if (saveBtn) { saveInterceptRuleFromRow(saveBtn.dataset.ruleSave).catch(handleInterceptRuleError); return; }
    const row = event.target.closest("[data-rule-id]");
    if (row && !event.target.closest("input") && !event.target.closest("button")) { editInterceptRule(row.dataset.ruleId); }
  });
  document.getElementById("interceptRulesList").addEventListener("change", (event) => {
    const toggle = event.target.closest("[data-rule-toggle]");
    if (toggle) { toggleInterceptRuleEnabled(toggle.dataset.ruleToggle, toggle.checked).catch(handleInterceptRuleError); }
  });
  document.getElementById("interceptRulesList").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      const row = event.target.closest("[data-rule-id]");
      if (row) { saveInterceptRuleFromRow(row.dataset.ruleId).catch(handleInterceptRuleError); }
    }
  });
  if (els.refreshWebsocketsButton) {
    els.refreshWebsocketsButton.addEventListener("click", () => {
      loadWebsocketsPageRefresh(true).catch((error) => console.error(error));
    });
  }
  els.frameDetailClose.addEventListener("click", hideFrameDetail);
  initFrameDetailResizer();
  document.querySelectorAll(".ws-sort").forEach((btn) => {
    btn.addEventListener("click", () => toggleWebsocketSort(btn.dataset.wsSortKey));
  });
  els.forwardInterceptButton.addEventListener("click", () => {
    forwardSelectedIntercept().catch((error) => {
      console.error(error);
      showToast(error?.message || "Failed to forward request.", "error");
    });
  });
  els.dropInterceptButton.addEventListener("click", () => {
    dropSelectedIntercept().catch((error) => {
      console.error(error);
      showToast(error?.message || "Failed to drop request.", "error");
    });
  });
  els.forwardResponseInterceptButton.addEventListener("click", () => {
    forwardSelectedResponseIntercept().catch((error) => {
      console.error(error);
      showToast(error?.message || "Failed to forward response.", "error");
    });
  });
  els.dropResponseInterceptButton.addEventListener("click", () => {
    dropSelectedResponseIntercept().catch((error) => {
      console.error(error);
      showToast(error?.message || "Failed to drop response.", "error");
    });
  });
  els.interceptQueueTabRequest.addEventListener("click", () => switchInterceptQueueTab("request"));
  els.interceptQueueTabResponse.addEventListener("click", () => switchInterceptQueueTab("response"));

  if (els.interceptSearchInput) {
    els.interceptSearchInput.addEventListener("input", updateInterceptSearch);
  }
  if (els.interceptSearchMeta) {
    // Same match-cycling as initCMSearchNavigation, but the target pane depends
    // on the active queue tab, so the key is resolved per click.
    els.interceptSearchMeta.addEventListener("click", (event) => {
      if (!event.target.closest(".search-hit-count")) return;
      const cv = getCMView(activeInterceptCMKey());
      if (cv) cv.nextSearchMatch();
    });
  }

  els.interceptStatus.addEventListener("click", () => {
    toggleIntercept().catch((error) => console.error(error));
  });
  els.saveProxySettingsButton.addEventListener("click", () => {
    if (proxySettingsSaveInFlight) return;
    proxySettingsSaveInFlight = true;
    els.saveProxySettingsButton.disabled = true;
    proxySettingsSavePromise = saveProxySettings();
    proxySettingsSavePromise
      .then((result) => {
        if (result?.rebound === true) {
          showToast(`Proxy listener moved to ${result.active_proxy_addr}`);
        } else if (result?.rebound === false && result?.rebind_error) {
          showToast(result.rebind_error, "error");
        } else {
          showToast("Proxy settings saved");
        }
      })
      .catch((error) => {
        console.error(error);
        showToast(error?.message || "Failed to save proxy settings", "error");
      })
      .finally(() => {
        proxySettingsSaveInFlight = false;
        proxySettingsSavePromise = null;
        els.saveProxySettingsButton.disabled = false;
      });
  });
  els.reloadProxySettingsButton.addEventListener("click", () => {
    loadSettings()
      .then(renderProxySettings)
      .catch((error) => console.error(error));
  });
  document.getElementById("proxySettingAutoContentLength")?.addEventListener("change", (e) => {
    localStorage.setItem("sniper_auto_content_length", e.target.checked);
  });

  // Pane context menu (right-click on Request/Response code-view)
  const paneCtx = document.getElementById("paneContextMenu");
  if (paneCtx) {
    let paneContextMenuTarget = null;
    [els.requestView, els.responseView, els.requestViewCM, els.responseViewCM].forEach((view) => {
      if (!view) return;
      view.addEventListener("contextmenu", (e) => {
        if (!state.selectedId) return;
        e.preventDefault();
        paneContextMenuTarget = createTransactionRecordMenuTarget(
          state.selectedId,
          currentSessionId(),
        );
        paneCtx.classList.remove("hidden");
        const mw = paneCtx.offsetWidth, mh = paneCtx.offsetHeight;
        paneCtx.style.left = `${Math.min(e.clientX, window.innerWidth - mw - 8)}px`;
        paneCtx.style.top = `${Math.min(e.clientY, window.innerHeight - mh - 8)}px`;
      });
    });
    document.addEventListener("click", () => {
      paneCtx.classList.add("hidden");
      paneContextMenuTarget = null;
    });
    paneCtx.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-pane-action]");
      const target = paneContextMenuTarget;
      if (!btn || !target?.id) return;
      const action = btn.dataset.paneAction;
      paneCtx.classList.add("hidden");
      paneContextMenuTarget = null;
      if (target.sessionId !== currentSessionId()) {
        showToast("The selected session changed. Open the menu again.", "error");
        return;
      }
      if (action === "copy-url") copyMenuTargetUrl(target);
      else if (action === "send-to-replay") {
        loadMenuTargetRecord(target)
          .then((record) => {
            if (!record) throw new Error("Selected transaction could not be loaded.");
            if (record.kind === "tunnel") throw new Error("Tunnel records cannot be sent to Replay.");
            openTransactionRecordInReplay(record);
          })
          .catch(handleSendActionError);
      } else if (action === "send-to-fuzzer") {
        loadMenuTargetRecord(target)
          .then((record) => {
            if (!record) throw new Error("Selected transaction could not be loaded.");
            openFuzzerFromRecord(record);
          })
          .catch(handleSendActionError);
      } else if (action === "send-to-sequence") {
        loadMenuTargetRecord(target)
          .then((record) => {
            if (!record) throw new Error("Selected transaction could not be loaded.");
            return sendRecordToSequence(record);
          })
          .catch(handleSendActionError);
      } else if (action.startsWith("copy-response-")) {
        loadMenuTargetRecord(target)
          .then((record) => {
            if (!record) throw new Error("Selected transaction could not be loaded.");
            return copyResponseContentForRecord(record, action.replace("copy-", ""));
          })
          .catch(handleClipboardActionError);
      }
      else if (action.startsWith("copy-as-")) {
        const fmt = action.replace("copy-as-", "");
        loadMenuTargetRecord(target)
          .then((record) => {
            if (!record) throw new Error("Selected transaction could not be loaded.");
            const text = recordToFormat(record, fmt);
            if (!text) return null;
            return copyTextToClipboard(text).then(() => showToast(`Copied as ${fmt}`));
          })
          .catch(handleClipboardActionError);
      }
    });
  }

  els.sendReplayButton.addEventListener("click", () => {
    sendReplay().catch(handleReplayActionError);
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
    followRedirect().catch(handleReplayActionError);
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
  els.deleteMatchReplaceRuleButton.addEventListener("click", () => {
    deleteSelectedMatchReplaceRule().catch((error) => {
      console.error(error);
      showToast(error?.message || "Failed to delete rule", "error");
      loadMatchReplaceRules().catch(console.error);
    });
  });
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
      .catch((error) => { console.error(error); showToast(error?.message || "Failed to save scope", "error"); });
  });
  els.targetScopeEditor.addEventListener("input", () => {
    state.targetScopeDraft = els.targetScopeEditor.value;
    state.targetScopeDirty = true;
    state.targetScopeEditorSessionId = currentSessionId();
  });
  els.reloadTargetButton.addEventListener("click", () => {
    reloadTargetSiteMapFromButton().catch((error) => console.error(error));
  });
  els.startFuzzerButton.addEventListener("click", () => {
    runFuzzerAttack().catch((error) => {
      console.error("Fuzzer start error:", error);
    });
  });
  els.resetFuzzerButton.addEventListener("click", resetFuzzer);

  // Fuzzer layout resizers
  initFuzzerResizers();

  // Fuzzer results shell (for keyboard navigation + focus)
  const fuzzerResultsShell = els.fuzzerResultsBody.closest(".history-table-shell");

  // Fuzzer result row click → show detail
  els.fuzzerResultsBody.addEventListener("click", (e) => {
    const row = e.target.closest(".fuzzer-result-row");
    if (row) {
      selectFuzzerRow(row);
      if (fuzzerResultsShell) fuzzerResultsShell.focus({ preventScroll: true });
    }
  });

  // Fuzzer results keyboard navigation (↑↓)
  if (fuzzerResultsShell) {
    fuzzerResultsShell.setAttribute("tabindex", "0");
    let fuzzerScrollRaf = 0;
    fuzzerResultsShell.addEventListener("scroll", () => {
      if (fuzzerScrollRaf) return;
      fuzzerScrollRaf = requestAnimationFrame(() => {
        fuzzerScrollRaf = 0;
        renderFuzzerResultsVirtual();
      });
    });
    fuzzerResultsShell.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowUp" && e.key !== "ArrowDown") return;
      e.preventDefault();
      const totalCount = jsonArray(state.fuzzerAttackRecord?.results).length;
      if (!totalCount) return;
      const selectedIndex = fuzzerSelectedResultIndex();
      const fallbackIndex = e.key === "ArrowDown" ? 0 : totalCount - 1;
      const nextIndex = selectedIndex < 0
        ? fallbackIndex
        : (e.key === "ArrowDown"
          ? Math.min(selectedIndex + 1, totalCount - 1)
          : Math.max(selectedIndex - 1, 0));
      selectFuzzerResultIndex(nextIndex, { scroll: true });
    });
  }

  // Fuzzer detail view mode tabs (Pretty/Raw/Hex)
  document.querySelectorAll(".fuzzer-detail-view-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.fuzzerDetailTarget;
      const view = btn.dataset.fuzzerDetailView;
      _fuzzerDetailViewModes[target] = view;
      // Update tab active state
      document.querySelectorAll(`.fuzzer-detail-view-tab[data-fuzzer-detail-target="${target}"]`).forEach((b) => {
        b.classList.toggle("active", b.dataset.fuzzerDetailView === view);
      });
      // Re-render with current record
      if (state._fuzzerDetailRecord) {
        renderFuzzerDetailPanes(state._fuzzerDetailRecord);
      }
    });
  });

  document.getElementById("newSequenceButton").addEventListener("click", () => {
    createNewSequence().catch(handleSequenceActionError);
  });
  document.getElementById("addSequenceStepButton").addEventListener("click", addSequenceStep);
  document.getElementById("saveSequenceButton").addEventListener("click", () => {
    saveCurrentSequence().catch(handleSequenceActionError);
  });
  document.getElementById("runSequenceButton").addEventListener("click", () => {
    runCurrentSequence().catch(handleSequenceActionError);
  });

  // The replay request editor uses a contenteditable <pre> for editing so that
  // native text selection works over syntax-highlighted text (WKWebView renders
  // textarea selection in an opaque native layer that cannot be hidden).
  // The hidden <textarea> is kept as a data store only.
  state._replayUndoStack = [];
  state._replayRedoStack = [];
  state._replayLastSnapshot = null;

  els.replayRequestHighlight?.addEventListener("input", () => {
    if (els.replayRequestCM) return; // CM handles editing
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
    syncReplayRequestTextFromEditor(text);
    const renderedText = tab.requestText || text;
    // Debounce re-render so syntax highlighting refreshes without losing cursor
    clearTimeout(els.replayRequestHighlight._renderTimer);
    els.replayRequestHighlight._renderTimer = setTimeout(() => {
      replayHighlightRerender(renderedText);
    }, 400);
  });
  els.replayRequestHighlight?.addEventListener("keydown", (e) => {
    if (els.replayRequestCM) return; // CM handles editing
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
      if (tab) {
        tab.requestText = restored;
        clearReplayResponseForDraftChange(tab);
      }
      updateReplaySearchPane("request", restored);
      syncReplayToolbar(tab);
      renderReplayTabs();
      scheduleWorkspaceStateSave();
    }
  });
  els.replayRequestHighlight?.addEventListener("paste", (e) => {
    if (els.replayRequestCM) return; // CM handles paste
    e.preventDefault();
    const text = e.clipboardData.getData("text/plain");
    document.execCommand("insertText", false, text);
  });
  els.replayRequestHighlight?.addEventListener("contextmenu", showReplayContextMenu);
  els.replayRequestCM?.addEventListener("contextmenu", showReplayContextMenu);
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
    oastProviderSelect.addEventListener("change", () => renderOastSettingsControls());
  }
  if (els.proxySettingOastClearToken) {
    els.proxySettingOastClearToken.addEventListener("click", () => {
      state.oastTokenClearPending = true;
      const oastToken = document.getElementById("proxySettingOastToken");
      if (oastToken) {
        oastToken.value = "";
      }
      renderOastSettingsControls();
    });
  }
  const oastTokenInput = document.getElementById("proxySettingOastToken");
  if (oastTokenInput) {
    oastTokenInput.addEventListener("input", () => {
      if (oastTokenInput.value.trim()) {
        state.oastTokenClearPending = false;
        renderOastSettingsControls();
      }
    });
  }
  if (els.oastGenerateButton) {
    els.oastGenerateButton.addEventListener("click", () => {
      generateOastPayload().catch(handleOastActionError);
    });
  }
  if (els.oastClearButton) {
    els.oastClearButton.addEventListener("click", () => {
      clearOastCallbacks().catch((error) => {
        console.error(error);
        showToast(error?.message || "Failed to clear OAST callbacks.", "error");
      });
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
      const id = row.dataset.oastId;
      if (state.selectedOastId !== id) {
        renderOastDetailLoading();
      }
      state.selectedOastId = id;
      loadOastDetail(id).catch(handleOastActionError);
      renderOastCallbacks();
    });
  }
  els.replaySchemeSelect.addEventListener("change", () => {
    applyReplayTargetFields().catch((error) => console.error(error));
  });
  document.getElementById("replayHttpVersionSelect")?.addEventListener("change", (e) => {
    const ver = e.target.value;
    const tab = getActiveReplayTab();
    if (!tab || tab.type === "websocket") return;
    tab.httpVersionMode = ver || "";
    const cv = getCMView("replayReq");
    const text = tab.requestBytes
      ? new TextDecoder().decode(tab.requestBytes)
      : (tab.requestText || "");
    const lines = text.split("\n");
    if (lines.length > 0) {
      lines[0] = ver
        ? lines[0].replace(/\s+HTTP\/[0-9.]+\s*$/i, ` ${ver}`)
        : lines[0].replace(/\s+HTTP\/[0-9.]+\s*$/i, "");
      if (ver && !lines[0].match(/HTTP\//i)) lines[0] += ` ${ver}`;
      const newText = lines.join("\n");
      tab.requestText = newText;
      tab.requestBytes = null;
      tab.requestOriginalBytes = null;
      clearReplayResponseForDraftChange(tab);
      syncReplayToolbar(tab);
      renderReplayTabs();
      scheduleWorkspaceStateSave();
      if (cv && state.replayMessageViews.request !== "hex") {
        cv.setContent(newText);
        updateReplaySearchPane("request", newText);
        return;
      }
      renderReplayViewContent("request");
      return;
    }
    if (cv) {
      return;
    }
    // Legacy path
    const hl = els.replayRequestHighlight;
    if (!hl) return;
    const legacyText = hl.innerText || "";
    const legacyLines = legacyText.split("\n");
    if (legacyLines.length > 0) {
      legacyLines[0] = ver
        ? legacyLines[0].replace(/\s+HTTP\/[0-9.]+\s*$/i, ` ${ver}`)
        : legacyLines[0].replace(/\s+HTTP\/[0-9.]+\s*$/i, "");
      if (ver && !legacyLines[0].match(/HTTP\//i)) legacyLines[0] += ` ${ver}`;
      const newText = legacyLines.join("\n");
      hl.innerText = newText;
      hl.dispatchEvent(new Event("input"));
      tab.requestText = newText;
      clearReplayResponseForDraftChange(tab);
      updateReplaySearchPane("request", newText);
      syncReplayToolbar(tab);
      renderReplayTabs();
      scheduleWorkspaceStateSave();
    }
  });
  els.replayHostInput.addEventListener("input", () => {
    applyReplayTargetFields().catch((error) => console.error(error));
  });
  els.replayPortInput.addEventListener("input", () => {
    applyReplayTargetFields().catch((error) => console.error(error));
  });
  if (els.fuzzerRequestEditor) {
    els.fuzzerRequestEditor.addEventListener("input", () => {
      if (els.fuzzerRequestCM) return; // CM handles it
      updateFuzzerRequestText(els.fuzzerRequestEditor.value, { userEdit: true });
      renderFuzzerRequestHighlight(state.fuzzerRequestText);
      scheduleWorkspaceStateSave();
    });
    els.fuzzerRequestEditor.addEventListener("scroll", syncFuzzerRequestHighlightScroll);
  }
  els.fuzzerPayloadsEditor.addEventListener("input", () => {
    updateFuzzerPayloadsText(els.fuzzerPayloadsEditor.value, { userEdit: true });
    scheduleWorkspaceStateSave();
  });
  if (els.interceptRequestEditor) {
    els.interceptRequestEditor.addEventListener("input", () => {
      if (els.interceptRequestCM) return; // CM handles it
      if (state.selectedInterceptRecord) {
        state.interceptEditorSeedId = state.selectedInterceptRecord.id;
      }
      renderInterceptRequestHighlight(els.interceptRequestEditor.value);
    });
    els.interceptRequestEditor.addEventListener("scroll", syncInterceptRequestHighlightScroll);
  }
  if (els.interceptResponseEditor) {
    els.interceptResponseEditor.addEventListener("input", () => {
      if (els.interceptResponseCM) return; // CM handles it
      if (state.selectedResponseInterceptRecord) {
        state.responseInterceptEditorSeedId = state.selectedResponseInterceptRecord.id;
      }
      renderInterceptResponseHighlight(els.interceptResponseEditor.value);
    });
    els.interceptResponseEditor.addEventListener("scroll", () => {
      if (els.interceptResponseHighlight) {
        els.interceptResponseHighlight.scrollTop = els.interceptResponseEditor.scrollTop;
        els.interceptResponseHighlight.scrollLeft = els.interceptResponseEditor.scrollLeft;
      }
    });
  }

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
        typeof activeModalAction.apply === "function" &&
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
      !event.defaultPrevented &&
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "a" &&
      isSelectableTextTarget(event.target) &&
      !event.target.closest?.(".cm-editor")
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

    // Ctrl+Cmd+1~6: show only rows carrying that colour tag; press again to clear.
    if (
      event.metaKey &&
      event.ctrlKey &&
      !event.shiftKey &&
      !event.altKey &&
      state.activeTool === "proxy" &&
      state.activeProxyTab === "http-history" &&
      event.key >= "1" && event.key <= "6"
    ) {
      event.preventDefault();
      toggleColorTagFilter(HTTP_COLOR_TAG_ORDER[parseInt(event.key, 10) - 1]);
      return;
    }

    // Cmd+1~6: color tag selected HTTP item
    if (
      (event.metaKey || event.ctrlKey) &&
      // Ctrl+Cmd is the filter shortcut above, not a tag.
      !(event.metaKey && event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      state.activeTool === "proxy" &&
      state.activeProxyTab === "http-history" &&
      state.selectedId &&
      event.key >= "1" && event.key <= "6"
    ) {
      event.preventDefault();
      const color = HTTP_COLOR_TAG_ORDER[parseInt(event.key, 10) - 1];
      const item = getHistoryItem(state.selectedId);
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
      const frames = getWsReplayFrames(tab);
      if (tab && tab.type === "websocket" && frames.length > 0) {
        event.preventDefault();
        const currentPosition = frames.findIndex((frame) => frame.index === tab.wsSelectedFrameIndex);
        const visibleFrames = wsReplayRenderedFrameWindow(
          frames,
          tab.wsSelectedFrameIndex,
          tab.wsFrameWindowStart,
        ).frames;
        const nextPosition = currentPosition === -1
          ? frames.findIndex((frame) => frame.index === (
            event.key === "ArrowDown"
              ? visibleFrames[0]?.index
              : visibleFrames[visibleFrames.length - 1]?.index
          ))
          : event.key === "ArrowDown"
            ? Math.min(currentPosition + 1, frames.length - 1)
            : Math.max(currentPosition - 1, 0);
        if (nextPosition < 0) return;
        const nextFrameIndex = frames[nextPosition].index;
        tab.wsSelectedFrameIndex = nextFrameIndex;
        scheduleWorkspaceStateSave();
        renderWsFrameList();
        const target = els.wsFrameList.querySelector(`[data-frame-index="${nextFrameIndex}"]`);
        if (target) { target.scrollIntoView({ block: "nearest" }); }
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
      state.replayTabs.length > 1 &&
      !(event.target instanceof Element && event.target.closest(".replay-tab-name-input"))
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
      openReplayFromSelection().catch(handleSendActionError);
    }

    // Cmd+R on WebSocket tab — send selected frame to WS Replay
    if (
      (event.metaKey || event.ctrlKey) &&
      !event.shiftKey &&
      !event.altKey &&
      event.key.toLowerCase() === "r" &&
      state.activeTool === "proxy" &&
      state.activeProxyTab === "websockets-history" &&
      state.selectedWebsocketRecord &&
      state.selectedFrameIdx != null
    ) {
      event.preventDefault();
      sendWsFrameToReplay(state.selectedFrameIdx);
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
        sendFindingToReplay(recordId).catch(handleFindingActionError);
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
        openFuzzerFromSelection().catch(handleSendActionError);
      } else if (state.activeTool === "replay" && state.activeReplayTabId) {
        event.preventDefault();
        openFuzzerFromReplay().catch(handleSendActionError);
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
        openFuzzerFromSelection().catch(handleSendActionError);
      } else if (state.activeTool === "replay" && state.activeReplayTabId) {
        openFuzzerFromReplay().catch(handleSendActionError);
      } else {
        setActiveTool("fuzzer");
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
      // CM path
      const cv = getCMView("wsHandshake");
      if (cv) {
        const query = (els.wsHandshakeSearchInput.value || "").trim();
        const result = cv.applySearch(query);
        if (els.wsHandshakeSearchMeta) {
          els.wsHandshakeSearchMeta.innerHTML = buildSearchMeta(cv.view.state.doc.lines, "raw", result.matchCount);
        }
        return;
      }
      updateWsHandshakeSearch();
    });
    initSearchHitNavigation(els.wsHandshakeSearchMeta, () => {
      const resBtn = document.getElementById("wsHandshakeResBtn");
      return resBtn?.classList.contains("active") ? els.websocketResponseView : els.websocketRequestView;
    });
    initCMSearchNavigation(els.wsHandshakeSearchMeta, "wsHandshake");
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
      if (els.websocketHandshakeCM && state.selectedWebsocketRecord) {
        const text = buildRawWebsocketRequest(state.selectedWebsocketRecord);
        updateCodePaneCM("wsHandshake", els.websocketHandshakeCM, text, { mode: "http" });
      } else {
        els.websocketRequestView?.classList.remove("hidden");
        els.websocketResponseView?.classList.add("hidden");
      }
      updateWsHandshakeLineNumbers();
      updateWsHandshakeSearch();
    });
    wsResBtn.addEventListener("click", () => {
      wsResBtn.classList.add("active");
      wsReqBtn.classList.remove("active");
      if (els.websocketHandshakeCM && state.selectedWebsocketRecord) {
        const text = buildRawWebsocketResponse(state.selectedWebsocketRecord);
        updateCodePaneCM("wsHandshake", els.websocketHandshakeCM, text, { mode: "http" });
      } else {
        els.websocketResponseView?.classList.remove("hidden");
        els.websocketRequestView?.classList.add("hidden");
      }
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
  state.oastTokenClearPending = false;
  // Sync intercept scope pill with server state
  const interceptScopePill = document.getElementById("interceptInScopeToggle");
  if (interceptScopePill) {
    const scopeOnly = state.runtime?.intercept_scope_only ?? true;
    interceptScopePill.classList.toggle("active", scopeOnly);
    state.interceptInScopeOnly = scopeOnly;
  }

  els.proxyAddr.textContent = state.settings.proxy_addr;
  els.uiAddr.textContent = state.settings.ui_addr;
  els.captureMode.textContent = `${formatSize(state.settings.body_preview_bytes)} preview cap / ${configuredTransactionEntryLimit()} HTTP entries`;
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

  const handleProgress = (data) => {
    if (data.step?.startsWith("error:")) {
      label.textContent = "Update failed";
      fill.style.width = "0%";
      els.openUpdateButton.disabled = false;
      setTimeout(() => {
        els.openUpdateButton.textContent = "Update";
      }, 3000);
      console.error("Self-update failed:", data.step);
      return false;
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
    return true;
  };

  const markRestarting = () => {
    label.textContent = "Restarting...";
    fill.style.width = "100%";
  };

  try {
    const response = await fetch("/api/self-update", { method: "POST" });
    await requireOkResponse(response, "Failed to start update.");
    if (!response.body) {
      markRestarting();
      return;
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const events = buffer.split("\n\n");
      buffer = events.pop() || "";
      for (const eventText of events) {
        const dataText = eventText
          .split("\n")
          .filter((line) => line.startsWith("data:"))
          .map((line) => line.slice(5).trimStart())
          .join("\n");
        if (!dataText) continue;
        try {
          if (!handleProgress(JSON.parse(dataText))) return;
        } catch (_error) {
          // Ignore malformed progress frames.
        }
      }
    }
    markRestarting();
  } catch (error) {
    // Connection loss usually means the app is restarting after replacement.
    if (label.textContent === "Restarting..." || fill.style.width === "100%") {
      markRestarting();
      return;
    }
    label.textContent = "Update failed";
    fill.style.width = "0%";
    els.openUpdateButton.disabled = false;
    setTimeout(() => {
      els.openUpdateButton.textContent = "Update";
    }, 3000);
    console.error("Self-update failed:", error);
  }
}

async function loadSessions({ reloadOnActiveChange = false } = {}) {
  const response = await fetch("/api/sessions");
  await requireOkResponse(response, "Failed to load sessions.");
  const sessions = jsonArray(await response.json());
  const previousActiveSessionId = currentSessionId();
  const nextActiveSession = sessions.find((session) => session.active) || sessions[0] || null;
  if (
    reloadOnActiveChange
    && previousActiveSessionId
    && nextActiveSession?.id
    && nextActiveSession.id !== previousActiveSessionId
  ) {
    state.sessions = sessions;
    renderDashboard();
    await handleExternalSessionChanged(previousActiveSessionId);
    return;
  }
  state.sessions = sessions;
  state.activeSession = nextActiveSession;
  renderDashboard();
}

async function loadWorkspaceState() {
  const response = await fetch("/api/workspace-state");
  if (!response.ok) {
    throw new Error(await response.text());
  }
  const snapshot = await response.json();
  if (!workspaceSnapshotMatchesActiveSession(snapshot)) {
    await loadSessions();
    if (!workspaceSnapshotMatchesActiveSession(snapshot)) {
      throw new WorkspaceSessionMismatchError(snapshot?.session_id || null);
    }
  }
  applyWorkspaceState(snapshot);
}

class WorkspaceSessionMismatchError extends Error {
  constructor(sessionId) {
    super("Workspace state belongs to a different active session.");
    this.name = "WorkspaceSessionMismatchError";
    this.sessionId = sessionId;
  }
}

function applyWorkspaceState(snapshot) {
  if (!workspaceSnapshotMatchesActiveSession(snapshot)) {
    console.warn("Ignoring workspace state for a non-active session", snapshot?.session_id);
    return;
  }
  for (const tab of state.replayTabs || []) {
    if (tab?.type === "websocket") {
      cleanupWsReplayTab(tab, { guardWorkspaceRevision: false }).catch((error) => console.error(error));
    }
  }
  state.workspaceRevision = Number.isFinite(snapshot?.revision) ? snapshot.revision : 0;
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
  state.replayRenamingTabId = null;

  const fuzzerWS = snapshot?.fuzzer || {};
  state.fuzzerBaseRequest = fuzzerWS.base_request ? cloneEditableRequest(fuzzerWS.base_request) : null;
  state.fuzzerSourceTransactionId = fuzzerWS.source_transaction_id || null;
  state.fuzzerTarget = normalizeFuzzerTargetOverride(fuzzerWS.target);
  const savedFuzzerTargetAuthority = fuzzerWS.target_request_authority;
  state.fuzzerTargetRequestText = state.fuzzerTarget ? normalizeFuzzerTargetAuthority(savedFuzzerTargetAuthority) : null;
  if (state.fuzzerTarget && !state.fuzzerTargetRequestText && !String(savedFuzzerTargetAuthority || "").trim()) {
    state.fuzzerTargetRequestText =
      fuzzerTargetAuthorityFromRequestText(fuzzerWS.request_text || "", state.fuzzerBaseRequest)
      || fuzzerTargetAuthorityFromEditableRequest(state.fuzzerBaseRequest);
  }
  if (state.fuzzerTarget && !state.fuzzerTargetRequestText) {
    state.fuzzerTarget = null;
  }
  state.fuzzerNotice = fuzzerWS.notice || "";
  state.fuzzerRequestText = fuzzerWS.request_text || "";
  state.fuzzerPayloadsText = fuzzerWS.payloads_text || "";
  const legacyFuzzerAttackRecord = normalizeFuzzerAttackRecord(fuzzerWS.attack_record);
  setFuzzerAttackRecord(legacyFuzzerAttackRecord);
  state.fuzzerAttackRecordId = fuzzerWorkspaceAttackRecordId(fuzzerWS, legacyFuzzerAttackRecord);
  if (legacyFuzzerAttackRecord) {
    scheduleWorkspaceStateSave();
  } else if (state.fuzzerAttackRecordId) {
    state.fuzzerNotice = state.fuzzerNotice || "Loading saved fuzzer run...";
    hydrateFuzzerAttackRecordById(state.fuzzerAttackRecordId, snapshot?.session_id || currentSessionId());
  }
  workspaceSaveCommittedSnapshot = cloneWorkspaceSnapshotForBaseline(snapshotWorkspaceState());
}

// Pick up replay tabs committed by another client — typically
// `sniper-cli replay open`. Only tabs we do not already have are added: an open
// tab may be mid-edit, and replacing it from a background fetch would discard
// the user's work. A tab the CLI *modified* is therefore left alone.
async function adoptExternalReplayTabs() {
  const response = await fetch("/api/workspace-state");
  if (!response.ok) return;
  const snapshot = await response.json();
  if (!workspaceSnapshotMatchesActiveSession(snapshot)) return;

  // Follow the writer's revision, otherwise our next save looks stale and the
  // server rejects it as a conflict.
  if (Number.isFinite(snapshot?.revision)) {
    state.workspaceRevision = snapshot.revision;
  }

  const incoming = Array.isArray(snapshot?.replay?.tabs) ? snapshot.replay.tabs : [];
  const known = new Set((state.replayTabs || []).map((tab) => tab?.id));
  const added = incoming
    .filter((tab) => tab?.id && !known.has(tab.id))
    .map((tab) => hydrateReplayTab(tab))
    .filter(Boolean);
  if (!added.length) return;

  state.replayTabs = [...(state.replayTabs || []), ...added];
  state.replayTabSequence = Math.max(
    state.replayTabSequence || 0,
    ...added.map((tab) => tab.sequence || 0),
  );
  if (!state.activeReplayTabId) {
    state.activeReplayTabId = added[0].id;
  }
  renderReplay();
  showToast(`${added.length} replay tab${added.length === 1 ? "" : "s"} added from another client.`, "info");
}

// Toggle the history filter for one colour tag. Shared by the colour dots in
// the toolbar and the Ctrl+Cmd+1~6 shortcuts.
function toggleColorTagFilter(color) {
  if (!HTTP_COLOR_TAG_OPTIONS.has(color)) return;
  const button = els.colorTagFilter?.querySelector(`.color-dot-btn[data-color="${color}"]`);
  if (state.filterSettings.colorTags.has(color)) {
    state.filterSettings.colorTags.delete(color);
    button?.classList.remove("active");
  } else {
    state.filterSettings.colorTags.add(color);
    button?.classList.add("active");
  }
  scheduleUiSettingsSave();
  clearHttpHistorySelectionPreview();
  scheduleRefresh({ resetScroll: true });
}

function workspaceSnapshotMatchesActiveSession(snapshot) {
  const snapshotSessionId = snapshot?.session_id || null;
  const activeSessionId = state.activeSession?.id || null;
  if (!snapshotSessionId) return true;
  if (!activeSessionId) return false;
  return snapshotSessionId === activeSessionId;
}

function hydrateReplayTab(tab) {
  if (!tab || typeof tab !== "object") {
    return null;
  }

  if (tab.type === "websocket") {
    const wsScheme = tab.ws_scheme || "wss";
    const wsFrames = normalizeWebsocketFrames(tab.ws_frames);
    const replayTab = {
      id: isUuidString(tab.id) ? tab.id : crypto.randomUUID(),
      type: "websocket",
      sequence: Number.isFinite(tab.sequence) ? tab.sequence : state.replayTabSequence + 1,
      customLabel: normalizeReplayTabCustomLabel(tab.custom_label || ""),
      pinned: !!tab.pinned,
      label: `WS ${tab.ws_host || "draft"}`,
      wsScheme,
      wsHost: tab.ws_host || "",
      wsPort: tab.ws_port || defaultWsPortForScheme(wsScheme),
      wsPath: tab.ws_path || "/",
      wsHeaders: normalizedHeaders(tab.ws_headers),
      wsHandshakeText: tab.ws_handshake_text || "",
      wsHandshakeEdited: !!tab.ws_handshake_edited,
      wsEditorText: tab.ws_editor_text || "",
      wsMessageType: normalizeWsMessageType(tab.ws_message_type),
      wsEditorBodyEncoded: !!tab.ws_editor_body_encoded,
      wsSetupNotice: tab.ws_setup_notice || "",
      wsSetupQueue: Array.isArray(tab.ws_setup_queue)
        ? tab.ws_setup_queue.map((item) => ({ ...normalizeWsSetupItem(item), sent: false }))
        : [],
      wsStatus: "disconnected",
      wsFrames,
      wsFramesTruncated: !!tab.ws_frames_truncated || websocketFramesAreTruncated(wsFrames, null),
      wsSelectedFrameIndex: normalizeWsReplaySavedFrameIndex(wsFrames, tab.ws_selected_frame_index),
      wsFrameWindowStart: normalizeWsReplaySavedFrameWindowStart(wsFrames, tab.ws_frame_window_start),
      wsError: null,
      wsSessionId: null,
      wsPollTimer: null,
      wsLifecycleToken: 0,
      wsSetupPending: false,
      wsSetupRunning: false,
    };
    rebuildWsReplayFrameTracking(replayTab);
    return replayTab;
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
  const requestText = tab.request_text ?? buildEditableRawRequest(fallbackRequest);
  const hasHttpVersionMode = Object.prototype.hasOwnProperty.call(tab, "http_version_mode");
  return {
    id: typeof tab.id === "string" && tab.id ? tab.id : crypto.randomUUID(),
    sequence: Number.isFinite(tab.sequence) ? tab.sequence : state.replayTabSequence + 1,
    customLabel: normalizeReplayTabCustomLabel(tab.custom_label || ""),
    pinned: !!tab.pinned,
    baseRequest: fallbackRequest,
    sourceTransactionId: tab.source_transaction_id || null,
    notice: tab.notice || "",
    requestText,
    httpVersionMode: replayStoredHttpVersionMode(
      fallbackRequest,
      requestText,
      tab.http_version_mode,
      hasHttpVersionMode,
    ),
    responseRecord: tab.response_record || null,
    targetScheme: normalizedTarget.scheme,
    targetHost: normalizedTarget.host,
    targetPort: normalizedTarget.port,
    targetManuallyEdited: !!tab.target_manually_edited,
    historyEntries,
    historyIndex,
  };
}

function hydrateRepeaterHistoryEntry(entry, fallbackRequest) {
  if (!entry || typeof entry !== "object") {
    return null;
  }

  const request = entry.request ? cloneEditableRequest(entry.request) : cloneEditableRequest(fallbackRequest);
  const requestText = entry.request_text ?? buildEditableRawRequest(request);
  const hasHttpVersionMode = Object.prototype.hasOwnProperty.call(entry, "http_version_mode");
  const fallbackTarget = authorityToTargetState(request.host, request.scheme);
  const normalizedTarget = normalizeRepeaterTargetInput(
    entry.target_host ?? fallbackTarget.host,
    entry.target_port ?? fallbackTarget.port,
    entry.target_scheme || fallbackTarget.scheme,
  );
  return {
    request,
    requestText,
    httpVersionMode: replayStoredHttpVersionMode(
      request,
      requestText,
      entry.http_version_mode,
      hasHttpVersionMode,
    ),
    responseRecord: entry.response_record || null,
    notice: entry.notice || "",
    targetScheme: normalizedTarget.scheme,
    targetHost: normalizedTarget.host,
    targetPort: normalizedTarget.port,
  };
}

function normalizeFuzzerTargetOverride(target) {
  if (!target || typeof target !== "object") return null;
  const rawHost = String(target.host || "").trim();
  const rawPort = normalizePortValue(target.port);
  const rawScheme = String(target.scheme || "").trim().toLowerCase();
  const scheme = (rawScheme === "http" || rawScheme === "https") ? rawScheme : "";
  if (!rawHost) {
    if (!scheme && !rawPort) return null;
    return {
      scheme,
      host: "",
      port: rawPort,
    };
  }
  const normalized = normalizeRepeaterTargetInput(rawHost, rawPort, scheme || "https");
  if (!normalized.host) return null;
  return {
    scheme: normalized.scheme || "https",
    host: normalized.host,
    port: normalizePortValue(normalized.port) || (normalized.scheme === "http" ? "80" : "443"),
  };
}

function createWorkspaceClientId() {
  if (window.crypto?.randomUUID) {
    return window.crypto.randomUUID();
  }
  return `client-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}

function observeAnnotationRevision(source) {
  const revision = Number(source?.annotation_revision || 0);
  if (Number.isSafeInteger(revision) && revision > annotationSaveVersion) {
    annotationSaveVersion = revision;
  }
}

function nextAnnotationClientVersion() {
  annotationSaveVersion = Math.max(0, annotationSaveVersion) + 1;
  return annotationSaveVersion;
}

function cloneWorkspaceSnapshotForBaseline(snapshot) {
  if (!snapshot || typeof snapshot !== "object") return null;
  try {
    return JSON.parse(JSON.stringify(snapshot));
  } catch (_error) {
    return null;
  }
}

function isUuidString(value) {
  return typeof value === "string" && UUID_PATTERN.test(value);
}

function createWsReplaySnapshotBudgetAllocator(replayTabs, options = {}) {
  const totalFrames = Number.isFinite(options.wsFrameLimit)
    ? Math.floor(Math.max(0, options.wsFrameLimit))
    : WS_REPLAY_MAX_PERSISTED_TOTAL_FRAMES;
  const totalBodyBytes = Number.isFinite(options.wsBodyByteLimit)
    ? Math.floor(Math.max(0, options.wsBodyByteLimit))
    : WS_REPLAY_MAX_PERSISTED_TOTAL_BODY_BYTES;
  const tabsWithFrames = (Array.isArray(replayTabs) ? replayTabs : [])
    .filter((tab) => tab?.type === "websocket" && getRawWsReplayFrames(tab).length > 0);

  if (!tabsWithFrames.length || totalFrames <= 0 || totalBodyBytes <= 0) {
    return () => ({ frames: 0, bytes: 0 });
  }

  // Full workspace saves replace every Replay tab; keep one active tab from
  // consuming a shared budget and serializing inactive transcripts as empty.
  const frameBase = Math.floor(totalFrames / tabsWithFrames.length);
  const frameRemainder = totalFrames % tabsWithFrames.length;
  const bodyByteBase = Math.floor(totalBodyBytes / tabsWithFrames.length);
  const bodyByteRemainder = totalBodyBytes % tabsWithFrames.length;
  const budgetsByTab = new WeakMap();
  tabsWithFrames.forEach((tab, index) => {
    budgetsByTab.set(tab, {
      frames: Math.min(
        WS_REPLAY_MAX_PERSISTED_FRAMES,
        frameBase + (index < frameRemainder ? 1 : 0),
      ),
      bytes: bodyByteBase + (index < bodyByteRemainder ? 1 : 0),
    });
  });

  return (tab) => budgetsByTab.get(tab) || { frames: 0, bytes: 0 };
}

function snapshotWorkspaceState(options = {}) {
  const sessionId = options.sessionId || state.activeSession?.id || null;
  const replayTabs = Array.isArray(state.replayTabs) ? state.replayTabs : [];
  const wsFrameBudgetForTab = createWsReplaySnapshotBudgetAllocator(replayTabs, options);
  const replayTabSnapshots = new Map();
  const snapshotReplayTab = (tab) => {
    if (tab.type === "websocket") {
      const wsFramesSnapshot = snapshotWsReplayFrames(tab, wsFrameBudgetForTab(tab));
      const wsFrames = wsFramesSnapshot.frames;
      const wsSetupQueueSnapshot = limitWsSetupQueueItems(
        Array.isArray(tab.wsSetupQueue)
          ? tab.wsSetupQueue.map((item) => normalizeWsSetupItem(item))
          : [],
      );
      return {
        id: tab.id,
        type: "websocket",
        sequence: tab.sequence,
        custom_label: tab.customLabel || "",
        pinned: !!tab.pinned,
        ws_scheme: tab.wsScheme || "wss",
        ws_host: tab.wsHost || "",
        ws_port: tab.wsPort || defaultWsPortForScheme(tab.wsScheme),
        ws_path: tab.wsPath || "/",
        ws_headers: normalizedHeaders(tab.wsHeaders),
        ws_handshake_text: tab.wsHandshakeText || "",
        ws_handshake_edited: !!tab.wsHandshakeEdited,
        ws_editor_text: tab.wsEditorText || "",
        ws_message_type: normalizeWsMessageType(tab.wsMessageType),
        ws_editor_body_encoded: !!tab.wsEditorBodyEncoded,
        ws_setup_notice: appendWsSetupNotice(tab.wsSetupNotice || "", wsSetupQueueSnapshot.notice),
        ws_setup_queue: wsSetupQueueSnapshot.items.map((item) => ({
          label: item.label || "",
          body: item.body || "",
          kind: normalizeWsMessageType(item.kind),
          body_encoded: !!item.bodyEncoded,
          autoSend: !!item.autoSend,
        })),
        ws_frames: wsFrames,
        ws_frames_complete: !wsFramesSnapshot.truncated,
        ws_frames_truncated: !!tab.wsFramesTruncated || wsFramesSnapshot.truncated,
        ws_selected_frame_index: snapshotWsReplaySelectedFrameIndex(tab, wsFrames),
        ws_frame_window_start: snapshotWsReplayFrameWindowStart(tab, wsFrames),
      };
    }
    const historyEntries = Array.isArray(tab.historyEntries)
      ? tab.historyEntries.filter((entry) => entry && typeof entry === "object")
      : [];
    return {
      id: tab.id,
      sequence: tab.sequence,
      custom_label: tab.customLabel || "",
      pinned: !!tab.pinned,
      base_request: tab.baseRequest ? cloneEditableRequest(tab.baseRequest) : null,
      source_transaction_id: tab.sourceTransactionId || null,
      notice: tab.notice || "",
      request_text: tab.requestText || "",
      http_version_mode: normalizeReplayHttpVersionMode(tab.httpVersionMode),
      response_record: tab.responseRecord || null,
      target_scheme: tab.targetScheme || "https",
      target_host: tab.targetHost || "",
      target_port: normalizePortValue(tab.targetPort),
      target_manually_edited: !!tab.targetManuallyEdited,
      history_entries: historyEntries.map((entry) => ({
        request: cloneEditableRequest(entry.request),
        request_text: entry.requestText || "",
        http_version_mode: normalizeReplayHttpVersionMode(entry.httpVersionMode),
        response_record: entry.responseRecord || null,
        notice: entry.notice || "",
        target_scheme: entry.targetScheme || "https",
        target_host: entry.targetHost || "",
        target_port: normalizePortValue(entry.targetPort),
      })),
      history_index: normalizeRepeaterHistoryIndex(tab.historyIndex, historyEntries.length),
    };
  };
  const activeReplayTab = replayTabs.find((tab) => tab.id === state.activeReplayTabId) || null;
  const snapshotOrder = activeReplayTab
    ? [activeReplayTab, ...replayTabs.filter((tab) => tab !== activeReplayTab)]
    : replayTabs;
  for (const tab of snapshotOrder) {
    replayTabSnapshots.set(tab.id, snapshotReplayTab(tab));
  }
  return {
    revision: state.workspaceRevision || 0,
    session_id: sessionId,
    expected_active_session_id: expectedActiveSessionIdForWrite(sessionId, options),
    client_id: workspaceClientId,
    client_version: workspaceSaveVersion,
    replay: {
      tabs: replayTabs.map((tab) => replayTabSnapshots.get(tab.id)),
      active_tab_id: state.activeReplayTabId,
      tab_sequence: state.replayTabSequence,
    },
    fuzzer: {
      base_request: state.fuzzerBaseRequest ? cloneEditableRequest(state.fuzzerBaseRequest) : null,
      source_transaction_id: state.fuzzerSourceTransactionId || null,
      target: normalizeFuzzerTargetOverride(state.fuzzerTarget),
      target_request_authority: state.fuzzerTarget ? normalizeFuzzerTargetAuthority(state.fuzzerTargetRequestText) : null,
      notice: state.fuzzerNotice || "",
      request_text: state.fuzzerRequestText || "",
      payloads_text: state.fuzzerPayloadsText || "",
      attack_record_id: state.fuzzerAttackRecordId || state.fuzzerAttackRecord?.id || null,
    },
  };
}

function scheduleWorkspaceStateSave() {
  if (!state.activeSession) {
    return;
  }

  window.clearTimeout(wsTranscriptSaveTimer);
  wsTranscriptSaveTimer = null;
  wsTranscriptFirstDirtyAt = 0;
  workspaceSaveDirty = true;
  workspaceSaveVersion += 1;
  window.clearTimeout(workspaceSaveTimer);
  workspaceSaveTimer = window.setTimeout(() => {
    workspaceSaveTimer = null;
    flushQueuedWorkspaceStateSave().catch((error) => console.error(error));
  }, 250);
}

function scheduleWsTranscriptWorkspaceSave() {
  if (!state.activeSession) {
    return;
  }
  workspaceSaveDirty = true;
  workspaceSaveVersion += 1;
  const now = Date.now();
  if (!wsTranscriptFirstDirtyAt) {
    wsTranscriptFirstDirtyAt = now;
  }
  const elapsed = now - wsTranscriptFirstDirtyAt;
  const delay = elapsed >= WS_REPLAY_TRANSCRIPT_SAVE_MAX_WAIT_MS
    ? 0
    : Math.min(
        WS_REPLAY_TRANSCRIPT_SAVE_DELAY_MS,
        WS_REPLAY_TRANSCRIPT_SAVE_MAX_WAIT_MS - elapsed,
      );
  window.clearTimeout(wsTranscriptSaveTimer);
  wsTranscriptSaveTimer = window.setTimeout(() => {
    wsTranscriptSaveTimer = null;
    wsTranscriptFirstDirtyAt = 0;
    window.clearTimeout(workspaceSaveTimer);
    workspaceSaveTimer = window.setTimeout(() => {
      workspaceSaveTimer = null;
      flushQueuedWorkspaceStateSave().catch((error) => console.error(error));
    }, 0);
  }, delay);
}

function isActiveSessionChangedConflict(latest) {
  return latest && typeof latest === "object" && latest.error === "active session changed";
}

function clearBypassableWorkspaceConflict(options = {}) {
  if (
    workspaceSaveConflictPending
    && options.bypassExpectedActiveSessionGuard
    && isActiveSessionChangedConflict(workspaceSaveConflictLatest)
  ) {
    workspaceSaveConflictPending = false;
    workspaceSaveConflictLatest = null;
    workspaceSaveDirty = true;
    return true;
  }
  return false;
}

async function flushQueuedWorkspaceStateSave(options = {}) {
  if (!state.activeSession) {
    return;
  }
  if (workspaceSaveConflictPending && !clearBypassableWorkspaceConflict(options)) {
    return;
  }
  if (workspaceSaveLoopPromise) {
    return workspaceSaveLoopPromise;
  }

  workspaceSaveLoopPromise = runQueuedWorkspaceStateSaves(options)
    .finally(() => {
      workspaceSaveLoopPromise = null;
    });
  return workspaceSaveLoopPromise;
}

async function runQueuedWorkspaceStateSaves(options = {}) {
  while (state.activeSession && workspaceSaveDirty) {
    workspaceSaveDirty = false;
    const version = workspaceSaveVersion;
    const snapshot = snapshotWorkspaceState(options);
    workspaceSaveLastSnapshot = snapshot;
    workspaceSaveInFlight = true;
    try {
      await saveWorkspaceState(snapshot, options);
    } catch (error) {
      if (!(error instanceof WorkspaceStateConflictError)) {
        workspaceSaveDirty = true;
        window.clearTimeout(workspaceSaveTimer);
        workspaceSaveTimer = window.setTimeout(() => {
          workspaceSaveTimer = null;
          flushQueuedWorkspaceStateSave().catch((error) => console.error(error));
        }, 1000);
        throw error;
      }
      workspaceSaveConflictPending = true;
      workspaceSaveConflictLatest = error.latest || null;
      workspaceSaveDirty = true;
      window.clearTimeout(workspaceSaveTimer);
      workspaceSaveTimer = null;
      showToast(
        "Workspace changed elsewhere; local workspace edits were not saved. Reload the workspace to reconcile.",
        "error",
        6000,
      );
      return;
    } finally {
      workspaceSaveInFlight = false;
    }
    if (workspaceSaveVersion !== version) {
      workspaceSaveDirty = true;
    }
    workspaceSaveConflictPending = false;
    workspaceSaveConflictLatest = null;
  }
}

async function saveWorkspaceState(snapshot = null, options = {}) {
  if (!state.activeSession) {
    return;
  }
  if (!snapshot) {
    snapshot = snapshotWorkspaceState(options);
  }

  const response = await fetch("/api/workspace-state", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(snapshot),
  });

  if (!response.ok) {
    if (response.status === 409) {
      const latest = await response.json().catch(() => null);
      throw new WorkspaceStateConflictError(latest);
    }
    throw new Error(await response.text());
  }
  const saved = await response.json();
  const currentSessionId = state.activeSession?.id || null;
  if (
    (snapshot?.session_id && snapshot.session_id !== currentSessionId)
    || (saved?.session_id && saved.session_id !== currentSessionId)
  ) {
    return;
  }
  state.workspaceRevision = Number.isFinite(saved?.revision) ? saved.revision : state.workspaceRevision;
  workspaceSaveCommittedSnapshot = cloneWorkspaceSnapshotForBaseline(snapshot);
  workspaceSaveConflictPending = false;
  workspaceSaveConflictLatest = null;
}

class WorkspaceStateConflictError extends Error {
  constructor(latest) {
    super("Workspace state revision conflict");
    this.name = "WorkspaceStateConflictError";
    this.latest = latest;
  }
}

function handleWorkspaceActionError(error) {
  console.error(error);
  if (error instanceof WorkspaceStateConflictError) {
    showToast(
      "Workspace changed elsewhere. Reload the workspace before switching sessions.",
      "error",
      7000,
    );
    return;
  }
  showToast(error?.message || "Workspace action failed.", "error", 6000);
}

async function flushWorkspaceState(options = {}) {
  const hasQueuedChanges = !!(workspaceSaveDirty || workspaceSaveTimer || wsTranscriptSaveTimer);
  const hasInFlightSave = !!(workspaceSaveInFlight || workspaceSaveLoopPromise);
  const hasPendingConflict = !!workspaceSaveConflictPending;
  window.clearTimeout(wsTranscriptSaveTimer);
  wsTranscriptSaveTimer = null;
  wsTranscriptFirstDirtyAt = 0;
  window.clearTimeout(workspaceSaveTimer);
  workspaceSaveTimer = null;
  if (!state.activeSession || (!hasQueuedChanges && !hasInFlightSave && !hasPendingConflict)) {
    return;
  }
  if (hasPendingConflict && !clearBypassableWorkspaceConflict(options)) {
    throw new WorkspaceStateConflictError(null);
  }
  if (hasQueuedChanges) {
    workspaceSaveDirty = true;
    workspaceSaveVersion += 1;
  }
  await flushQueuedWorkspaceStateSave(options);
  if (workspaceSaveConflictPending) {
    if (clearBypassableWorkspaceConflict(options)) {
      await flushQueuedWorkspaceStateSave(options);
    }
  }
  if (workspaceSaveConflictPending) {
    throw new WorkspaceStateConflictError(null);
  }
}

async function flushWorkspaceStateForReplayAction() {
  await flushWorkspaceState();
  return state.workspaceRevision || 0;
}

async function flushProxySettingsSaveBeforeClose() {
  const pendingSave = proxySettingsSavePromise;
  if (!pendingSave) {
    return;
  }
  try {
    await pendingSave;
  } catch (error) {
    console.error("Failed to finish proxy settings save before close:", error);
  }
}

async function flushWsReplayTabsBeforeClose() {
  const tabs = (state.replayTabs || []).filter((tab) => (
    tab
    && tab.type === "websocket"
    && (tab.wsStatus === "connected" || tab.wsStatus === "connecting")
  ));
  const results = await Promise.allSettled(tabs.map((tab) => cleanupWsReplayTab(tab, {
      markDisconnected: true,
      removeBackend: tab.wsStatus === "connecting",
    })));
  for (const result of results) {
    if (result.status === "rejected") {
      console.warn("Failed to close WebSocket replay tab before native close:", result.reason);
    }
  }
}

async function drainWsReplayFramesBeforeHidden() {
  const tabs = (state.replayTabs || []).filter((tab) => (
    tab
    && tab.type === "websocket"
    && (tab.wsStatus === "connected" || tab.wsStatus === "connecting")
  ));
  const results = await Promise.allSettled(tabs.map((tab) => refreshWsReplayFramesOnce(tab)));
  for (const result of results) {
    if (result.status === "rejected") {
      console.warn("Failed to drain WebSocket replay frames before page hide:", result.reason);
    }
  }
}

async function flushBeforeNativeClose() {
  await flushAllPendingAnnotations();
  await flushProxySettingsSaveBeforeClose();
  await flushSequenceDraft({ preserveSelection: true });
  syncReplayDraftsBeforeWorkspaceClose();
  await flushWsReplayTabsBeforeClose();
  await flushWorkspaceState();
  window.clearTimeout(uiSettingsSaveTimer);
  uiSettingsSaveTimer = null;
  if (uiSettingsDirty || uiSettingsInFlight) {
    await persistUiSettings();
  }
}

window.__sniperFlushBeforeNativeClose = flushBeforeNativeClose;

function flushWorkspaceStateBeforeHidden() {
  if (document.visibilityState !== "hidden") return;
  syncReplayDraftsBeforeWorkspaceClose();
  (async () => {
    await flushSequenceDraft({ preserveSelection: true });
    await drainWsReplayFramesBeforeHidden();
    if (!hasPendingWorkspaceStateSave()) return;
    await flushWorkspaceState();
  })().catch((error) => {
    if (error instanceof WorkspaceStateConflictError) return;
    console.warn("Failed to flush workspace state before page hide:", error);
  });
}

function requestWorkspaceUnloadPrompt(event) {
  if (!event || event.type !== "beforeunload") {
    return;
  }
  event.preventDefault();
  event.returnValue = WORKSPACE_UNLOAD_UNSAVED_MESSAGE;
}

function flushWorkspaceStateOnUnload(event) {
  const hadTranscriptSaveTimer = !!wsTranscriptSaveTimer;
  window.clearTimeout(wsTranscriptSaveTimer);
  wsTranscriptSaveTimer = null;
  wsTranscriptFirstDirtyAt = 0;
  syncReplayDraftsBeforeWorkspaceClose();
  disconnectWsReplayTabsOnUnload();
  if (state.sequenceDirty && state.editingSequence) {
    requestWorkspaceUnloadPrompt(event);
  }
  if (!state.activeSession || (!workspaceSaveDirty && !workspaceSaveTimer && !workspaceSaveInFlight && !hadTranscriptSaveTimer)) {
    return;
  }
  window.clearTimeout(workspaceSaveTimer);
  workspaceSaveTimer = null;
  const snapshot = workspaceSaveDirty || hadTranscriptSaveTimer
    ? snapshotWorkspaceState()
    : (workspaceSaveInFlight && workspaceSaveLastSnapshot
      ? workspaceSaveLastSnapshot
      : snapshotWorkspaceState());
  const unloadPayload = workspaceUnloadPayload(snapshot);
  if (!unloadPayload) {
    workspaceSaveDirty = true;
    requestWorkspaceUnloadPrompt(event);
    console.warn("Skipping unload workspace keepalive save because the full workspace snapshot is too large.");
    return;
  }
  const { payload, endpoint } = unloadPayload;
  const blob = new Blob([payload], { type: "application/json" });
  if (navigator.sendBeacon && navigator.sendBeacon(endpoint, blob)) {
    return;
  }
  fetch(endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: payload,
    keepalive: true,
  }).catch(() => {});
}

function workspaceReplayTabsById(snapshot) {
  return new Map(
    (Array.isArray(snapshot?.replay?.tabs) ? snapshot.replay.tabs : [])
      .filter((tab) => tab && typeof tab.id === "string" && tab.id)
      .map((tab) => [tab.id, tab]),
  );
}

function workspaceSnapshotValueChanged(left, right) {
  try {
    return JSON.stringify(left ?? null) !== JSON.stringify(right ?? null);
  } catch (_error) {
    return true;
  }
}

function changedWorkspaceReplayTabIds(snapshot, baselineSnapshot) {
  const tabs = Array.isArray(snapshot?.replay?.tabs) ? snapshot.replay.tabs : [];
  if (!tabs.length) return new Set();
  if (!baselineSnapshot || typeof baselineSnapshot !== "object") {
    return new Set(tabs.map((tab) => tab?.id).filter((id) => typeof id === "string" && id));
  }
  const baselineById = workspaceReplayTabsById(baselineSnapshot);
  const changed = new Set();
  for (const tab of tabs) {
    if (!tab || typeof tab.id !== "string" || !tab.id) continue;
    if (workspaceSnapshotValueChanged(tab, baselineById.get(tab.id))) {
      changed.add(tab.id);
    }
  }
  return changed;
}

function activeAndChangedReplayTabIds(snapshot) {
  const ids = changedWorkspaceReplayTabIds(snapshot, workspaceSaveCommittedSnapshot);
  const activeTabId = snapshot?.replay?.active_tab_id || null;
  if (activeTabId) {
    ids.add(activeTabId);
  }
  return ids;
}

function replayTabTextSaveShape(tab) {
  if (!tab || typeof tab !== "object") return null;
  if (tab.type === "websocket") {
    return {
      type: "websocket",
      ws_headers: normalizedHeaders(tab.ws_headers),
      ws_handshake_text: tab.ws_handshake_text || "",
      ws_editor_text: tab.ws_editor_text || "",
      ws_message_type: normalizeWsMessageType(tab.ws_message_type),
      ws_editor_body_encoded: !!tab.ws_editor_body_encoded,
    };
  }
  return {
    type: "http",
    base_request: tab.base_request || null,
    request_text: tab.request_text || "",
    http_version_mode: normalizeReplayHttpVersionMode(tab.http_version_mode),
  };
}

function changedReplayTabsIncludeTextChanges(snapshot, tabIds, baselineSnapshot) {
  if (!(tabIds instanceof Set) || !tabIds.size) return false;
  const currentById = workspaceReplayTabsById(snapshot);
  const baselineById = workspaceReplayTabsById(baselineSnapshot);
  for (const id of tabIds) {
    const current = currentById.get(id);
    const baseline = baselineById.get(id);
    if (!current || !baseline) return true;
    if (workspaceSnapshotValueChanged(
      replayTabTextSaveShape(current),
      replayTabTextSaveShape(baseline),
    )) {
      return true;
    }
  }
  return false;
}

function workspaceUnloadSnapshotPayload(snapshot) {
  if (!snapshot) return null;
  const payload = JSON.stringify(snapshot);
  return utf8ByteLength(payload) <= WORKSPACE_UNLOAD_KEEPALIVE_MAX_BYTES
    ? payload
    : null;
}

function syncPendingReplayTabRenameFromDom() {
  const renamingTabId = state.replayRenamingTabId;
  if (!renamingTabId || !els.replayTabStrip) return false;
  const tab = state.replayTabs.find((item) => item.id === renamingTabId);
  if (!tab) return false;
  const tabElement = Array.from(els.replayTabStrip.querySelectorAll(".replay-tab"))
    .find((element) => element.dataset.replayTabId === renamingTabId);
  const input = tabElement?.querySelector(".replay-tab-name-input");
  if (!input) return false;
  const nextLabel = normalizeReplayTabCustomLabel(input.value);
  if ((tab.customLabel || "") === nextLabel) return false;
  tab.customLabel = nextLabel;
  scheduleWorkspaceStateSave();
  return true;
}

function syncActiveHttpReplayDraftFromDom() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type === "websocket") return false;
  let changed = false;
  if (state.replayMessageViews.request !== "hex") {
    const cv = getCMView("replayReq");
    const requestText = cv
      ? cv.getContent()
      : (els.replayRequestEditor?.value ?? els.replayRequestHighlight?.innerText ?? null);
    if (typeof requestText === "string" && requestText !== tab.requestText) {
      syncReplayRequestTextFromEditor(requestText);
      changed = true;
    }
  }
  if (els.replayHostInput && els.replayPortInput) {
    const validation = validateManualRepeaterTargetInput(
      els.replayHostInput.value,
      els.replayPortInput.value,
    );
    setReplayTargetInputValidity(validation);
    if (validation.valid) {
      const normalizedTarget = normalizeRepeaterTargetInput(
        els.replayHostInput.value,
        els.replayPortInput.value,
        els.replaySchemeSelect?.value || tab.targetScheme || "https",
      );
      if (
        tab.targetScheme !== normalizedTarget.scheme
        || tab.targetHost !== normalizedTarget.host
        || tab.targetPort !== normalizedTarget.port
      ) {
        tab.targetScheme = normalizedTarget.scheme;
        tab.targetHost = normalizedTarget.host;
        tab.targetPort = normalizedTarget.port;
        tab.targetManuallyEdited = true;
        clearReplayResponseForDraftChange(tab);
        scheduleWorkspaceStateSave();
        changed = true;
      }
    }
  }
  return changed;
}

function syncActiveWsReplayDraftFromDom() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return false;
  let changed = false;
  if (els.wsSchemeSelect && els.wsHostInput && els.wsPortInput && els.wsPathInput) {
    const rawPort = els.wsPortInput.value.trim();
    const validation = validateWsReplayTargetInput(
      els.wsSchemeSelect.value,
      els.wsHostInput.value,
      rawPort,
      els.wsPathInput.value,
    );
    setWsReplayTargetInputValidity(validation);
    if (validation.valid) {
      const normalizedTarget = normalizeWsReplayTargetFields(
        els.wsSchemeSelect.value,
        els.wsHostInput.value,
        rawPort,
      );
      const nextScheme = normalizedTarget.scheme;
      const nextHost = normalizedTarget.host;
      const nextPort = normalizedTarget.port;
      const nextPath = els.wsPathInput.value.trim();
      if (
        tab.wsScheme !== nextScheme
        || tab.wsHost !== nextHost
        || tab.wsPort !== nextPort
        || tab.wsPath !== nextPath
      ) {
        tab.wsScheme = nextScheme;
        tab.wsHost = nextHost;
        tab.wsPort = nextPort;
        tab.wsPath = nextPath;
        refreshWsHandshakeHeadersForTarget(tab);
        scheduleWorkspaceStateSave();
        changed = true;
      }
    }
  }
  if (els.wsHandshakeHeaders) {
    const handshakeText = els.wsHandshakeHeaders.value;
    if (tab.wsHandshakeEdited) {
      if (tab.wsHandshakeText !== handshakeText) {
        tab.wsHandshakeText = handshakeText;
        scheduleWorkspaceStateSave();
        changed = true;
      }
    } else if (handshakeText !== wsReplayDisplayHandshakeText(tab)) {
      tab.wsHandshakeText = handshakeText;
      tab.wsHandshakeEdited = true;
      scheduleWorkspaceStateSave();
      changed = true;
    }
  }
  const nextMessageType = normalizeWsMessageType(els.wsMessageType?.value || tab.wsMessageType);
  const nextEditorText = els.wsMessageHighlight
    ? (els.wsMessageHighlight.innerText || "")
    : (els.wsMessageEditor?.value ?? null);
  if (
    tab.wsMessageType !== nextMessageType
    || (typeof nextEditorText === "string" && tab.wsEditorText !== nextEditorText)
  ) {
    tab.wsMessageType = nextMessageType;
    if (typeof nextEditorText === "string") {
      tab.wsEditorText = nextEditorText;
    }
    tab.wsEditorBodyEncoded = false;
    scheduleWorkspaceStateSave();
    changed = true;
  }
  return changed;
}

function syncReplayDraftsBeforeWorkspaceClose() {
  syncPendingReplayTabRenameFromDom();
  syncActiveHttpReplayDraftFromDom();
  syncActiveWsReplayDraftFromDom();
}

function workspaceUnloadPayload(primarySnapshot) {
  const primaryPayload = JSON.stringify(primarySnapshot);
  if (utf8ByteLength(primaryPayload) <= WORKSPACE_UNLOAD_KEEPALIVE_MAX_BYTES) {
    return { payload: primaryPayload, endpoint: "/api/workspace-state" };
  }

  const sourceReplayTabById = new Map(
    (Array.isArray(state.replayTabs) ? state.replayTabs : [])
      .filter((tab) => tab && typeof tab.id === "string" && tab.id)
      .map((tab) => [tab.id, tab]),
  );

  const compactSnapshot = compactWorkspaceUnloadSnapshot(primarySnapshot, { sourceReplayTabById });
  if (compactSnapshot) {
    const compactPayload = JSON.stringify(compactSnapshot);
    if (utf8ByteLength(compactPayload) <= WORKSPACE_UNLOAD_KEEPALIVE_MAX_BYTES) {
      return { payload: compactPayload, endpoint: "/api/workspace-state/keepalive" };
    }
  }
  const changedReplayTabIds = activeAndChangedReplayTabIds(primarySnapshot);
  let changedReplayTextFields = false;
  if (changedReplayTabIds.size) {
    const activeTabId = primarySnapshot?.replay?.active_tab_id || null;
    const changedIncludesNonActive = Array.from(changedReplayTabIds)
      .some((id) => id && id !== activeTabId);
    changedReplayTextFields = changedReplayTabsIncludeTextChanges(
      primarySnapshot,
      changedReplayTabIds,
      workspaceSaveCommittedSnapshot,
    );
    const changedTabsSnapshot = compactWorkspaceUnloadSnapshot(primarySnapshot, {
      replayTabIdFilter: changedReplayTabIds,
      sourceReplayTabById,
    });
    const changedTabsPayload = workspaceUnloadSnapshotPayload(changedTabsSnapshot);
    if (changedTabsPayload) {
      return { payload: changedTabsPayload, endpoint: "/api/workspace-state/keepalive" };
    }
    const changedTabsReplayOnlySnapshot = compactWorkspaceUnloadSnapshot(primarySnapshot, {
      replayTabIdFilter: changedReplayTabIds,
      dropFuzzer: true,
      sourceReplayTabById,
    });
    const changedTabsReplayOnlyPayload = workspaceUnloadSnapshotPayload(changedTabsReplayOnlySnapshot);
    if (changedTabsReplayOnlyPayload) {
      return { payload: changedTabsReplayOnlyPayload, endpoint: "/api/workspace-state/keepalive" };
    }
    if (!changedReplayTextFields) {
      const boundedChangedTabsSnapshot = compactWorkspaceUnloadSnapshot(primarySnapshot, {
        replayTabIdFilter: changedReplayTabIds,
        textByteLimit: 8 * 1024,
        wsTextByteLimit: 8 * 1024,
        sourceReplayTabById,
      });
      const boundedChangedTabsPayload = workspaceUnloadSnapshotPayload(boundedChangedTabsSnapshot);
      if (boundedChangedTabsPayload) {
        return { payload: boundedChangedTabsPayload, endpoint: "/api/workspace-state/keepalive" };
      }
      const minimalChangedTabsSnapshot = compactWorkspaceUnloadSnapshot(primarySnapshot, {
        replayTabIdFilter: changedReplayTabIds,
        dropFuzzer: true,
        textByteLimit: 2 * 1024,
        wsTextByteLimit: 2 * 1024,
        sourceReplayTabById,
      });
      const minimalChangedTabsPayload = workspaceUnloadSnapshotPayload(minimalChangedTabsSnapshot);
      if (minimalChangedTabsPayload) {
        return { payload: minimalChangedTabsPayload, endpoint: "/api/workspace-state/keepalive" };
      }
    }
    if (changedIncludesNonActive) {
      return null;
    }
  }
  const activeOnlySnapshot = compactWorkspaceUnloadSnapshot(primarySnapshot, {
    activeOnly: true,
    sourceReplayTabById,
  });
  if (activeOnlySnapshot) {
    const activeOnlyPayload = JSON.stringify(activeOnlySnapshot);
    if (utf8ByteLength(activeOnlyPayload) <= WORKSPACE_UNLOAD_KEEPALIVE_MAX_BYTES) {
      return { payload: activeOnlyPayload, endpoint: "/api/workspace-state/keepalive" };
    }
  }
  const activeOnlyReplaySnapshot = compactWorkspaceUnloadSnapshot(primarySnapshot, {
    activeOnly: true,
    dropFuzzer: true,
    sourceReplayTabById,
  });
  if (activeOnlyReplaySnapshot) {
    const activeOnlyReplayPayload = JSON.stringify(activeOnlyReplaySnapshot);
    if (utf8ByteLength(activeOnlyReplayPayload) <= WORKSPACE_UNLOAD_KEEPALIVE_MAX_BYTES) {
      return { payload: activeOnlyReplayPayload, endpoint: "/api/workspace-state/keepalive" };
    }
  }
  if (changedReplayTextFields) {
    return null;
  }
  const boundedActiveOnlySnapshot = compactWorkspaceUnloadSnapshot(primarySnapshot, {
    activeOnly: true,
    textByteLimit: 8 * 1024,
    wsTextByteLimit: 8 * 1024,
    sourceReplayTabById,
  });
  if (boundedActiveOnlySnapshot) {
    const boundedActiveOnlyPayload = JSON.stringify(boundedActiveOnlySnapshot);
    if (utf8ByteLength(boundedActiveOnlyPayload) <= WORKSPACE_UNLOAD_KEEPALIVE_MAX_BYTES) {
      return { payload: boundedActiveOnlyPayload, endpoint: "/api/workspace-state/keepalive" };
    }
  }
  const minimalActiveReplaySnapshot = compactWorkspaceUnloadSnapshot(primarySnapshot, {
    activeOnly: true,
    dropFuzzer: true,
    textByteLimit: 2 * 1024,
    wsTextByteLimit: 2 * 1024,
    sourceReplayTabById,
  });
  if (minimalActiveReplaySnapshot) {
    const minimalActiveReplayPayload = JSON.stringify(minimalActiveReplaySnapshot);
    if (utf8ByteLength(minimalActiveReplayPayload) <= WORKSPACE_UNLOAD_KEEPALIVE_MAX_BYTES) {
      return { payload: minimalActiveReplayPayload, endpoint: "/api/workspace-state/keepalive" };
    }
  }
  return null;
}

function compactWorkspaceUnloadSnapshot(snapshot, options = {}) {
  if (!snapshot || typeof snapshot !== "object") return null;
  const replay = snapshot.replay && typeof snapshot.replay === "object" ? snapshot.replay : {};
  const activeTabId = replay.active_tab_id || null;
  const sourceTabs = Array.isArray(replay.tabs) ? replay.tabs : [];
  const replayTabIds = sourceTabs
    .map((tab) => tab?.id)
    .filter((id) => typeof id === "string" && id);
  const sourceReplayTabById = options.sourceReplayTabById instanceof Map
    ? options.sourceReplayTabById
    : null;
  const replayTabIdFilter = options.replayTabIdFilter instanceof Set
    ? options.replayTabIdFilter
    : null;
  const selectedTabs = replayTabIdFilter
    ? sourceTabs.filter((tab) => replayTabIdFilter.has(tab?.id))
    : (options.activeOnly && activeTabId
      ? sourceTabs.filter((tab) => tab?.id === activeTabId)
      : sourceTabs);
  const tabs = selectedTabs.map((tab) => compactWorkspaceUnloadReplayTab(
    tab,
    options,
    sourceReplayTabById?.get(tab?.id) || null,
  )).filter(Boolean);
  return {
    revision: snapshot.revision || 0,
    session_id: snapshot.session_id || null,
    expected_active_session_id: expectedActiveSessionIdForWrite(
      snapshot.session_id || state.activeSession?.id || null,
      options,
    ),
    client_id: snapshot.client_id || workspaceClientId,
    client_version: snapshot.client_version || workspaceSaveVersion,
    replay: {
      tabs,
      active_tab_id: activeTabId,
      tab_sequence: replay.tab_sequence || state.replayTabSequence || 0,
    },
    keepalive: {
      replay_tabs_complete: !options.activeOnly && !replayTabIdFilter,
      replay_tab_ids: replayTabIds,
      fuzzer_complete: !options.dropFuzzer,
      text_complete: !Number.isFinite(options.textByteLimit),
      ws_text_complete: !Number.isFinite(options.wsTextByteLimit),
    },
    fuzzer: options.dropFuzzer ? {} : (compactWorkspaceUnloadFuzzer(snapshot.fuzzer, options) || {}),
  };
}

function compactWorkspaceUnloadText(value, options = {}) {
  const text = String(value || "");
  return Number.isFinite(options.textByteLimit)
    ? truncateUtf8(text, options.textByteLimit)
    : text;
}

function compactWorkspaceUnloadWsText(value, options = {}) {
  if (Number.isFinite(options.wsTextByteLimit)) {
    return truncateUtf8(String(value || ""), options.wsTextByteLimit);
  }
  return compactWorkspaceUnloadText(value, options);
}

function compactWorkspaceUnloadEditableRequest(request, options = {}) {
  if (!request || typeof request !== "object") return null;
  const body = compactWorkspaceUnloadText(request.body, options);
  return {
    scheme: request.scheme || "https",
    host: request.host || "",
    method: request.method || "GET",
    path: request.path || "/",
    headers: normalizedHeaders(request.headers),
    body,
    body_encoding: request.body_encoding || "utf8",
    preview_truncated: !!request.preview_truncated || body !== String(request.body || ""),
  };
}

function compactWorkspaceUnloadCompleteArray(items, maxBytes) {
  const source = Array.isArray(items) ? items : [];
  if (!source.length) {
    return { items: [], complete: true };
  }
  return utf8ByteLength(JSON.stringify(source)) <= maxBytes
    ? { items: source, complete: true }
    : { items: [], complete: false };
}

function compactWorkspaceUnloadTailArray(items, maxBytes) {
  const source = Array.isArray(items) ? items : [];
  if (!source.length) {
    return { items: [], complete: true };
  }
  if (utf8ByteLength(JSON.stringify(source)) <= maxBytes) {
    return { items: source, complete: true };
  }
  const tail = [];
  for (let index = source.length - 1; index >= 0; index -= 1) {
    tail.unshift(source[index]);
    if (utf8ByteLength(JSON.stringify(tail)) > maxBytes) {
      tail.shift();
      break;
    }
  }
  return { items: tail, complete: false };
}

function compactWorkspaceUnloadJsonValue(value, maxBytes) {
  if (value === null || value === undefined) {
    return { value: null, complete: true };
  }
  return utf8ByteLength(JSON.stringify(value)) <= maxBytes
    ? { value, complete: true }
    : { value: null, complete: false };
}

function compactWorkspaceUnloadReplayTab(tab, options = {}, liveTab = null) {
  if (!tab || typeof tab !== "object") return null;
  if (tab.type === "websocket") {
    const wsFrames = Array.isArray(tab.ws_frames) ? tab.ws_frames : [];
    const wsSetupQueue = compactWorkspaceUnloadCompleteArray(
      Array.isArray(tab.ws_setup_queue) ? tab.ws_setup_queue : [],
      WORKSPACE_UNLOAD_WS_SETUP_QUEUE_MAX_BYTES,
    );
    const wsFrameTail = compactWorkspaceUnloadTailArray(
      wsFrames,
      WORKSPACE_UNLOAD_WS_FRAMES_MAX_BYTES,
    );
    return {
      id: tab.id,
      type: "websocket",
      sequence: tab.sequence,
      custom_label: tab.custom_label || "",
      pinned: !!tab.pinned,
      ws_scheme: tab.ws_scheme || "wss",
      ws_host: tab.ws_host || "",
      ws_port: tab.ws_port || defaultWsPortForScheme(tab.ws_scheme),
      ws_path: tab.ws_path || "/",
      ws_headers: normalizedHeaders(tab.ws_headers),
      ws_handshake_text: compactWorkspaceUnloadWsText(tab.ws_handshake_text, options),
      ws_handshake_edited: !!tab.ws_handshake_edited,
      ws_editor_text: compactWorkspaceUnloadWsText(tab.ws_editor_text, options),
      ws_message_type: normalizeWsMessageType(tab.ws_message_type),
      ws_editor_body_encoded: !!tab.ws_editor_body_encoded,
      ws_setup_notice: tab.ws_setup_notice || "",
      ws_setup_queue: wsSetupQueue.items,
      ws_setup_queue_complete: wsSetupQueue.complete,
      ws_frames: wsFrameTail.items,
      ws_frames_complete: wsFrameTail.complete,
      ws_frames_truncated: !!tab.ws_frames_truncated
        || !wsFrameTail.complete
        || websocketFramesAreTruncated(wsFrames, null),
      ws_selected_frame_index: tab.ws_selected_frame_index ?? null,
      ws_frame_window_start: tab.ws_frame_window_start ?? null,
    };
  }
  const historyEntries = compactWorkspaceUnloadCompleteArray(
    Array.isArray(tab.history_entries) ? tab.history_entries : [],
    WORKSPACE_UNLOAD_HISTORY_ENTRIES_MAX_BYTES,
  );
  const responseRecord = compactWorkspaceUnloadJsonValue(
    liveTab && typeof liveTab === "object" && Object.prototype.hasOwnProperty.call(liveTab, "responseRecord")
      ? liveTab.responseRecord
      : tab.response_record,
    WORKSPACE_UNLOAD_RESPONSE_RECORD_MAX_BYTES,
  );
  return {
    id: tab.id,
    sequence: tab.sequence,
    custom_label: tab.custom_label || "",
    pinned: !!tab.pinned,
    base_request: compactWorkspaceUnloadEditableRequest(tab.base_request, options),
    source_transaction_id: tab.source_transaction_id || null,
    notice: tab.notice || "",
    request_text: compactWorkspaceUnloadText(tab.request_text, options),
    http_version_mode: normalizeReplayHttpVersionMode(tab.http_version_mode),
    response_record: responseRecord.value,
    response_record_complete: responseRecord.complete,
    target_scheme: tab.target_scheme || "https",
    target_host: tab.target_host || "",
    target_port: normalizePortValue(tab.target_port),
    target_manually_edited: !!tab.target_manually_edited,
    history_entries: historyEntries.items,
    history_entries_complete: historyEntries.complete,
    history_index: historyEntries.complete ? (tab.history_index ?? null) : null,
  };
}

function compactWorkspaceUnloadFuzzer(fuzzer, options = {}) {
  if (!fuzzer || typeof fuzzer !== "object") return null;
  return {
    base_request: compactWorkspaceUnloadEditableRequest(fuzzer.base_request, options),
    source_transaction_id: fuzzer.source_transaction_id || null,
    target: normalizeFuzzerTargetOverride(fuzzer.target),
    target_request_authority: fuzzer.target_request_authority || null,
    notice: fuzzer.notice || "",
    request_text: compactWorkspaceUnloadText(fuzzer.request_text, options),
    payloads_text: compactWorkspaceUnloadText(fuzzer.payloads_text, options),
    attack_record_id: fuzzer.attack_record_id || null,
  };
}

function disconnectWsReplayTabsOnUnload() {
  const activeSessionId = state.activeSession?.id || null;
  if (!activeSessionId) return;
  for (const tab of state.replayTabs || []) {
    if (!tab || tab.type !== "websocket") continue;
    if (tab.wsStatus !== "connected" && tab.wsStatus !== "connecting") continue;
    const sessionId = tab.wsSessionId || activeSessionId;
    const payload = JSON.stringify({
      session_id: sessionId,
      expected_active_session_id: expectedActiveSessionIdForWrite(sessionId),
      expected_workspace_revision: state.workspaceRevision || 0,
      id: tab.id,
      remove: false,
    });
    if (utf8ByteLength(payload) > WORKSPACE_UNLOAD_KEEPALIVE_MAX_BYTES) continue;
    fetch("/api/replay/ws-disconnect", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: payload,
      keepalive: true,
    }).catch(() => {});
    tab.wsStatus = "disconnected";
    tab.wsError = null;
  }
}

function hasPendingWorkspaceStateSave() {
  return !!(workspaceSaveDirty || workspaceSaveTimer || wsTranscriptSaveTimer || workspaceSaveInFlight || workspaceSaveLoopPromise);
}

async function cleanupWsReplayTabsBeforeStateReset(options = {}) {
  const sessionId = options.sessionId || null;
  const tabs = (state.replayTabs || []).filter((tab) => (
    tab
    && tab.type === "websocket"
    && (tab.wsStatus === "connected" || tab.wsStatus === "connecting")
  ));
  if (!tabs.length) return;
  const results = await Promise.allSettled(tabs.map((tab) => cleanupWsReplayTab(tab, {
    markDisconnected: true,
    removeBackend: tab.wsStatus === "connecting",
    bypassExpectedActiveSessionGuard: !!options.bypassExpectedActiveSessionGuard,
    guardWorkspaceRevision: false,
    sessionId,
  })));
  for (const result of results) {
    if (result.status === "rejected") {
      console.warn("Failed to clean up WebSocket replay tab before session reset:", result.reason);
    }
  }
  if (hasPendingWorkspaceStateSave()) {
    await flushWorkspaceState(options);
  }
}

function resetSessionScopedUiState() {
  clearReplaySendInFlight();
  closeContextMenu();
  window.clearTimeout(refreshTimer);
  refreshTimer = null;
  window.clearTimeout(workspaceSaveTimer);
  workspaceSaveTimer = null;
  window.clearTimeout(wsTranscriptSaveTimer);
  wsTranscriptSaveTimer = null;
  wsTranscriptFirstDirtyAt = 0;
  workspaceSaveDirty = false;
  workspaceSaveLastSnapshot = null;
  workspaceSaveCommittedSnapshot = null;
  workspaceSaveConflictPending = false;
  workspaceSaveConflictLatest = null;
  clearHistoryBackfill();
  window.clearTimeout(_incrementalTimer);
  _incrementalTimer = 0;
  window.clearTimeout(_transactionDeltaTimer);
  _transactionDeltaTimer = 0;
  _pendingTransactionSummaries.length = 0;
  cancelHistoryDetailLoading();
  state.items = [];
  state.historyPaging = createHistoryPagingState();
  state.historyListError = "";
  state.selectedId = null;
  state.selectedRecord = null;
  state._connectCount = 0;
  state._itemById = new Map();
  state._itemIndexById = new Map();
  state._itemsVersion += 1;
  invalidateVisibleEntriesCache();
  state.intercepts = [];
  state.responseIntercepts = [];
  state.interceptRules = [];
  state.selectedInterceptId = null;
  state.selectedInterceptRecord = null;
  state.selectedResponseInterceptId = null;
  state.selectedResponseInterceptRecord = null;
  state.responseInterceptEditorSeedId = null;
  renderIntercepts();
  renderResponseIntercepts();
  renderInterceptRules();
  updateInterceptQueueBadges();
  state.websocketSessions = [];
  state.websocketPaging = createWebsocketPagingState();
  state.websocketListError = "";
  state.selectedWebsocketId = null;
  state.selectedWebsocketRecord = null;
  state.selectedWebsocketDetailError = "";
  resetWebsocketFrameScroll();
  _websocketLoadGeneration += 1;
  _websocketDetailGeneration += 1;
  _websocketDetailPendingId = null;
  _websocketDetailPendingSessionId = null;
  _websocketDetailPendingPromise = null;
  cancelWebsocketDetailLoading();
  clearWebsocketQueryBackfill();
  clearFilteredWebsocketReload();
  clearWebsocketSearchReload();
  if (_websocketDetailRefreshTimer) {
    window.clearTimeout(_websocketDetailRefreshTimer);
    _websocketDetailRefreshTimer = null;
  }
  _websocketDetailRefreshNeeded = null;
  _websocketSummaryMutationGeneration += 1;
  _websocketSummaryMutationById.clear();
  if (_websocketSummaryEventTimer) {
    window.clearTimeout(_websocketSummaryEventTimer);
    _websocketSummaryEventTimer = 0;
  }
  _websocketSummaryEventBuffer.clear();
  _lastWebsocketFallbackPoll = Date.now();
  _lastWebsocketPageRefreshAt = 0;
  state.eventLog = [];
  state.matchReplaceRules = [];
  state.selectedMatchReplaceRuleId = null;
  state.matchReplaceDirty = false;
  state.matchReplaceEditorSessionId = null;
  state.targetSiteMap = [];
  resetOastUiState();
  state.targetScopeDraft = "";
  state.targetScopeDirty = false;
  state.targetScopeEditorSessionId = null;
  state.targetExpandedHosts = new Set();
  scannerConfigCache = null;
  scannerSettingsSessionId = null;
  if (els.scannerSettingsBackdrop) {
    closeScannerSettings();
  }
  resetFindingsUiState();
  state.replayTabs = [];
  state.activeReplayTabId = null;
  state.replayTabSequence = 0;
  state.replayRenamingTabId = null;
  state.fuzzerRunToken = (state.fuzzerRunToken || 0) + 1;
  state.fuzzerRunning = false;
  state.fuzzerBaseRequest = null;
  state.fuzzerSourceTransactionId = null;
  state.fuzzerTarget = null;
  state.fuzzerTargetRequestText = null;
  state.fuzzerNotice = "";
  state.fuzzerRequestText = "";
  state.fuzzerPayloadsText = "";
  clearFuzzerAttackRecord();
  state._selectedFuzzerResultKey = null;
  state._fuzzerDetailRecord = null;
  state.sequenceDefinitions = [];
  state.selectedSequenceId = null;
  state.editingSequence = null;
  state.sequenceDirty = false;
  state.sequenceRunning = false;
  state.sequenceRunResult = null;
  state.sequencePastRuns = [];
  clearCompareState();
  renderHistory();
  renderEmptyDetail();
  renderWebsocketSessions();
  hideFrameDetail();
  renderEventLog();
  renderMatchReplaceRules();
  renderTarget();
  renderFindings();
  renderReplayClearedState();
  renderFuzzer();
  renderSequencePanel();
}

function renderReplayClearedState() {
  if (els.replayTabStrip) {
    els.replayTabStrip.innerHTML = "";
  }
  if (els.replayRequestCM) {
    updateCodePaneCM("replayReq", els.replayRequestCM, "", {
      mode: "http", readOnly: false,
      placeholder: "Loading session...",
      onChange: syncReplayRequestTextFromEditor,
    });
  } else {
    if (els.replayRequestEditor) els.replayRequestEditor.value = "";
    renderReplayRequestHighlight("");
  }
  if (els.replayHostInput) els.replayHostInput.value = "";
  if (els.replayPortInput) els.replayPortInput.value = "";
  if (els.replaySchemeSelect) els.replaySchemeSelect.value = "https";
  if (els.replayResponseMeta) els.replayResponseMeta.textContent = "Loading session...";
  renderReplayResponseView("Loading session...");
  updateReplaySearchPane("request", "");
  updateReplaySearchPane("response", "Loading session...");
  if (els.replayBackButton) els.replayBackButton.disabled = true;
  if (els.replayForwardButton) els.replayForwardButton.disabled = true;
  if (els.replayFollowRedirectButton) els.replayFollowRedirectButton.classList.add("hidden");
}

async function reloadSessionWorkspace({ cleanupBeforeReset = true } = {}) {
  if (cleanupBeforeReset) {
    await cleanupWsReplayTabsBeforeStateReset();
  }
  resetSessionScopedUiState();
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await loadSessions();
    await loadSettings();
    try {
      await loadWorkspaceState();
      break;
    } catch (error) {
      if (error instanceof WorkspaceSessionMismatchError && attempt === 0) {
        continue;
      }
      throw error;
    }
  }
  await loadTransactions(false);
  await loadIntercepts(false);
  await loadResponseIntercepts(false);
  await loadInterceptRules();
  await loadWebsockets(false);
  await loadEventLog();
  await loadMatchReplaceRules();
  await loadSequences();
  await loadTargetSiteMap(true);
  if (state.activeTool === "proxy" && state.activeProxyTab === "oast") {
    await loadOastCallbacks();
  }
  await refreshScannerQuickToggle();
  connectEvents();
  renderToolPanels();
}

async function handleExternalSessionChanged(previousSessionId = currentSessionId()) {
  const targetSessionId = previousSessionId || currentSessionId();
  const staleSessionWriteOptions = {
    bypassExpectedActiveSessionGuard: true,
    sessionId: targetSessionId,
  };
  let shouldReload = false;
  try {
    if (!(await flushSequenceDraftBeforeExternalSessionReload(staleSessionWriteOptions))) {
      showToast(
        "Session changed before the Sequence draft finished saving. Save or discard the draft before reloading sessions.",
        "error",
        7000,
      );
      return;
    }
  } catch (error) {
    handleSequenceActionError(error);
    return;
  }
  if (!(await flushTargetScopeDraft(staleSessionWriteOptions))) {
    return;
  }
  if (!(await flushMatchReplaceDraft(staleSessionWriteOptions))) {
    return;
  }
  try {
    await flushAllPendingAnnotations(staleSessionWriteOptions);
  } catch (error) {
    handleWorkspaceActionError(error);
    return;
  }
  if (hasPendingWorkspaceStateSave()) {
    try {
      await flushWorkspaceState(staleSessionWriteOptions);
    } catch (error) {
      handleWorkspaceActionError(error);
      return;
    }
  }
  try {
    await cleanupWsReplayTabsBeforeStateReset(staleSessionWriteOptions);
    shouldReload = true;
  } catch (error) {
    handleWorkspaceActionError(error);
    return;
  }
  if (shouldReload) {
    await reloadSessionWorkspace({ cleanupBeforeReset: false });
  }
}

async function createSession() {
  if (!(await flushTargetScopeDraft())) {
    return;
  }
  if (!(await flushMatchReplaceDraft())) {
    return;
  }
  if (!(await flushSequenceDraft())) {
    return;
  }
  await flushAllPendingAnnotations();
  await flushWorkspaceState();
  await cleanupWsReplayTabsBeforeStateReset();
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
  await reloadSessionWorkspace({ cleanupBeforeReset: false });
}

async function activateSessionById(id) {
  if (!(await flushTargetScopeDraft())) {
    return;
  }
  if (!(await flushMatchReplaceDraft())) {
    return;
  }
  if (!(await flushSequenceDraft())) {
    return;
  }
  await flushAllPendingAnnotations();
  await flushWorkspaceState();
  await cleanupWsReplayTabsBeforeStateReset();
  const response = await fetch(`/api/sessions/${id}/activate`, {
    method: "POST",
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  state.selectedSessionId = id;
  await reloadSessionWorkspace({ cleanupBeforeReset: false });
}

async function loadRuntimeSettings() {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath("/api/runtime", sessionId));
  await requireOkResponse(response, "Failed to load runtime settings.");
  const runtime = await response.json();
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.runtime = runtime;
  renderInterceptStatus();
  renderProxySettings();
}

function currentSessionId() {
  return state.activeSession?.id || null;
}

function sessionQueryPath(path, sessionId = currentSessionId()) {
  if (!sessionId) return path;
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}session_id=${encodeURIComponent(sessionId)}`;
}

function expectedActiveSessionIdForWrite(sessionId = currentSessionId(), options = {}) {
  if (options.bypassExpectedActiveSessionGuard) {
    return null;
  }
  return sessionId && sessionId === currentSessionId() ? sessionId : null;
}

function sessionWritePath(path, sessionId = currentSessionId(), options = {}) {
  const params = new URLSearchParams();
  if (sessionId) {
    params.set("session_id", sessionId);
  }
  const expectedActiveSessionId = expectedActiveSessionIdForWrite(sessionId, options);
  if (expectedActiveSessionId) {
    params.set("expected_active_session_id", expectedActiveSessionId);
  }
  const query = params.toString();
  if (!query) return path;
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}${query}`;
}

function transactionPath(id, sessionId = currentSessionId()) {
  return sessionQueryPath(`/api/transactions/${encodeURIComponent(id)}`, sessionId);
}

function createHistoryQueryState() {
  const filters = state.filterSettings || {};
  const colorTags = filters.colorTags && typeof filters.colorTags[Symbol.iterator] === "function"
    ? [...filters.colorTags].sort()
    : [];
  return {
    sessionId: currentSessionId() || "",
    query: state.query || "",
    method: state.method || "",
    sortKey: state.sortKey || "index",
    sortDirection: state.sortDirection || "desc",
    inScopeOnly: !!filters.inScopeOnly,
    hideWithoutResponses: !!filters.hideWithoutResponses,
    onlyParameterized: !!filters.onlyParameterized,
    onlyNotes: !!filters.onlyNotes,
    statusClasses: selectedStatusClasses(filters),
    mimeTypes: selectedMimeTypes(filters),
    hiddenExtensions: String(filters.hiddenExtensions || "").trim(),
    port: String(filters.port || "").trim(),
    colorTags,
    advancedSearch: String(filters.searchTerm || "").trim(),
    advancedRegex: !!filters.regex,
    advancedCaseSensitive: !!filters.caseSensitive,
    advancedNegative: !!filters.negativeSearch,
  };
}

function historyQuerySignature(queryState = createHistoryQueryState()) {
  return JSON.stringify(queryState);
}

function isCurrentHistoryQuerySignature(querySignature) {
  return querySignature === historyQuerySignature();
}

function buildTransactionsPageUrl({ limit, offset = 0, beforeSequence = null, queryState = createHistoryQueryState() } = {}) {
  const params = new URLSearchParams();
  params.set("limit", String(limit ?? HTTP_HISTORY_PAGE_SIZE));
  if (beforeSequence != null) {
    params.set("before_sequence", String(beforeSequence));
  } else {
    params.set("offset", String(offset));
  }
  params.set("sort_key", queryState.sortKey);
  params.set("sort_direction", queryState.sortDirection);
  if (queryState.sessionId) params.set("session_id", queryState.sessionId);
  params.set("hide_connect", "true");
  if (queryState.query) params.set("q", queryState.query);
  if (queryState.method) params.set("method", queryState.method);
  if (queryState.inScopeOnly) params.set("in_scope_only", "true");
  if (queryState.hideWithoutResponses) params.set("hide_without_responses", "true");
  if (queryState.onlyParameterized) params.set("only_parameterized", "true");
  if (queryState.onlyNotes) params.set("only_notes", "true");
  params.set("status_classes", queryState.statusClasses.join(","));
  params.set("mime_types", queryState.mimeTypes.join(","));
  if (queryState.hiddenExtensions) params.set("hidden_extensions", queryState.hiddenExtensions);
  if (queryState.port) params.set("port", queryState.port);
  if (queryState.colorTags.length) params.set("color_tags", queryState.colorTags.join(","));
  if (queryState.advancedSearch) {
    params.set("advanced_search", queryState.advancedSearch);
    if (queryState.advancedRegex) params.set("advanced_regex", "true");
    if (queryState.advancedCaseSensitive) params.set("advanced_case_sensitive", "true");
    if (queryState.advancedNegative) params.set("advanced_negative", "true");
  }
  return `/api/transactions-page?${params.toString()}`;
}

function selectedStatusClasses(filters) {
  const status = filters.status || {};
  const selected = [];
  if (status.success) selected.push("success");
  if (status.redirect) selected.push("redirect");
  if (status.clientError) selected.push("client_error");
  if (status.serverError) selected.push("server_error");
  if (status.other) selected.push("other");
  return selected;
}

function selectedMimeTypes(filters) {
  const mime = filters.mime || {};
  const selected = [];
  if (mime.html) selected.push("html");
  if (mime.script) selected.push("script");
  if (mime.json) selected.push("json");
  if (mime.css) selected.push("css");
  if (mime.image) selected.push("image");
  if (mime.websocket !== false) selected.push("websocket");
  if (mime.other) selected.push("other");
  return selected;
}

async function fetchTransactionPage(offsetOrOptions = 0) {
  const options = typeof offsetOrOptions === "object"
    ? offsetOrOptions
    : { offset: offsetOrOptions };
  const queryState = options.queryState || createHistoryQueryState();
  const querySignature = options.querySignature || historyQuerySignature(queryState);
  const response = await fetch(buildTransactionsPageUrl({
    limit: state.historyPaging.pageSize,
    offset: options.offset ?? 0,
    beforeSequence: options.beforeSequence ?? null,
    queryState,
  }));
  if (!response.ok) {
    const message = await response.text();
    if (!isCurrentHistoryQuerySignature(querySignature)) {
      return null;
    }
    if (els.historyMeta) els.historyMeta.textContent = `HTTP History filter error: ${message}`;
    if (els.liveStatus) {
      els.liveStatus.textContent = "Filter error";
      els.liveStatus.classList.remove("online");
    }
    throw new Error(message);
  }
  const page = await response.json();
  if (!isCurrentHistoryQuerySignature(querySignature)) {
    return null;
  }
  return page;
}

function applyPendingAnnotationsToItems(items) {
  if (!state._pendingAnnotations) return;
  const sessionId = currentSessionId();
  const freshById = new Map(items.map((item) => [item.id, item]));
  for (const [id, entry] of state._pendingAnnotations) {
    if (entry?.sessionId !== sessionId) continue;
    const item = freshById.get(id);
    if (item) Object.assign(item, entry.payload || {});
  }
}

function updateHistoryPagingCursor(items) {
  if (!canUseSequenceCursorForHistoryPaging()) {
    state.historyPaging.beforeSequence = null;
    return;
  }
  if (!items.length) return;
  let oldest = state.historyPaging.beforeSequence;
  for (const item of items) {
    if (item.sequence == null) continue;
    oldest = oldest == null ? item.sequence : Math.min(oldest, item.sequence);
  }
  state.historyPaging.beforeSequence = oldest;
}

function refreshHistoryPagingCursorFromItems() {
  if (!canUseSequenceCursorForHistoryPaging() || !state.historyPaging) {
    if (state.historyPaging) state.historyPaging.beforeSequence = null;
    return;
  }
  let oldest = null;
  for (const item of state.items) {
    if (item.sequence == null) continue;
    oldest = oldest == null ? item.sequence : Math.min(oldest, item.sequence);
  }
  state.historyPaging.beforeSequence = oldest;
  state.historyPaging.offset = state.items.length;
}

function isKnownCount(value) {
  return Number.isFinite(value);
}

function adjustHistoryPagingAfterLocalRemoval(removedCount = 1, options = {}) {
  const count = Math.max(0, Number(removedCount) || 0);
  if (!count || !state.historyPaging) return;
  const paging = state.historyPaging;
  if (options.decrementTotal !== false && isKnownCount(paging.total)) {
    paging.total = Math.max(state.items.length, Number(paging.total) - count);
  }
  if (options.decrementFilteredTotal !== false && isKnownCount(paging.filteredTotal)) {
    paging.filteredTotal = Math.max(0, Number(paging.filteredTotal) - count);
  }
  paging.offset = state.items.length;
}

async function loadTransactions(preserveSelection = true, options = {}) {
  _historyFullLoadInFlight += 1;
  try {
    const queryState = createHistoryQueryState();
    const querySignature = historyQuerySignature(queryState);
    const previousQuerySignature = state.historyPaging?.querySignature || "";
    const queryChanged = Boolean(previousQuerySignature) && previousQuerySignature !== querySignature;
    clearHistoryBackfill();
    state.historyPaging = createHistoryPagingState();
    state.historyPaging.generation = ++_historyPagingGeneration;
    state.historyPaging.querySignature = querySignature;
    state.historyPaging.loading = true;
    state.historyListError = "";
    const generation = state.historyPaging.generation;
    if (options.resetScroll || queryChanged) {
      clearHttpHistoryLoadedRowsForPendingQuery();
    }
    let page;
    try {
      page = await fetchTransactionPage({ offset: 0, queryState, querySignature });
    } catch (error) {
      if (
        state.historyPaging.generation === generation
        && state.historyPaging.querySignature === querySignature
        && isCurrentHistoryQuerySignature(querySignature)
      ) {
        state.historyPaging.loading = false;
        state.historyPaging.hasMore = false;
        state.historyPaging.fullyLoaded = true;
        state.historyListError = error?.message || "Failed to load HTTP History.";
        clearHttpHistoryLoadedRowsForPendingQuery();
      }
      throw error;
    }
    if (!page) {
      return;
    }
    if (
      state.historyPaging.generation !== generation
      || state.historyPaging.querySignature !== querySignature
      || !isCurrentHistoryQuerySignature(querySignature)
    ) {
      return;
    }
    const freshItems = jsonArray(page.items);

    // Preserve in-flight annotation changes (optimistic updates)
    applyPendingAnnotationsToItems(freshItems);
    state.items = freshItems;
    state._itemsVersion += 1;
    state.historyListError = "";
    // Pre-compute search haystacks and CONNECT count to avoid first-search latency
    precomputeItemIndexes();
    updateHistoryPagingCursor(freshItems);
    state.historyPaging.offset = freshItems.length;
    state.historyPaging.total = page.total ?? freshItems.length;
    state.historyPaging.filteredTotal = page.filtered_total ?? null;
    state.historyPaging.hiddenConnectTotal = page.hidden_connect_total ?? null;
    state.historyPaging.loading = false;
    state.historyPaging.hasMore = Boolean(page.has_more);
    state.historyPaging.fullyLoaded = !state.historyPaging.hasMore;
    state.historyDirty = false;
    invalidateVisibleEntriesCache();
    if (options.resetScroll) {
      resetHistoryScrollPosition();
    }

    const visibleEntries = getVisibleEntries();
    if (!preserveSelection || !visibleEntries.some((entry) => entry.item.id === state.selectedId)) {
      state.selectedId = visibleEntries[0]?.item.id ?? null;
    }

    renderHistory();
    if (state.selectedId) {
      if (preserveSelection && canReuseSelectedHistoryRecord(state.selectedId)) {
        return;
      }
      await selectHistoryTransaction(state.selectedId);
    } else {
      renderEmptyDetail();
    }
  } finally {
    _historyFullLoadInFlight = Math.max(0, _historyFullLoadInFlight - 1);
    if (!_historyFullLoadInFlight && _pendingTransactionSummaries.length) {
      scheduleTransactionDeltaFlush();
    }
  }
}

async function loadTransactionDetail(id) {
  const sessionId = currentSessionId();
  const response = await fetch(transactionPath(id, sessionId));
  if (sessionId !== currentSessionId()) {
    return null;
  }
  if (!response.ok) {
    if (response.status === 404) {
      const index = state.items.findIndex((item) => item.id === id);
      let nextSelectedId = null;
      if (index >= 0) {
        state.items.splice(index, 1);
        nextSelectedId = state.items[Math.min(index, state.items.length - 1)]?.id ?? null;
        state._itemsVersion += 1;
        adjustHistoryPagingAfterLocalRemoval(1);
        precomputeItemIndexes();
        invalidateVisibleEntriesCache();
        refreshHistoryPagingCursorFromItems();
        renderHistory();
      }
      if (state.selectedId === id) {
        await selectHistoryTransaction(nextSelectedId, { scroll: true });
      }
    } else if (state.selectedId === id) {
      state.selectedId = null;
      updateHistorySelection(null);
      renderEmptyDetail();
    }
    return null;
  }

  const record = await response.json();
  if (state.selectedId !== id || sessionId !== currentSessionId()) {
    return null;
  }
  state.loadingDetailId = null;
  observeAnnotationRevision(record);
  state.selectedRecord = record;
  renderDetail(state.selectedRecord);
  return record;
}

function historyRecordSummarySignature(source) {
  if (!source) return "";
  const requestBytes = source.request_bytes ?? source.request?.body_size ?? 0;
  const responseBytes = source.response_bytes ?? source.response?.body_size ?? 0;
  const noteCount = source.note_count ?? (Array.isArray(source.notes) ? source.notes.length : 0);
  const hasResponse = source.has_response ?? Boolean(source.response);
  const hasUserNote = source.has_user_note ?? Boolean(source.user_note);
  return JSON.stringify([
    source.id || "",
    source.kind || "",
    source.sequence ?? 0,
    source.method || "",
    source.scheme || "",
    source.host || "",
    source.path || "",
    source.status ?? null,
    source.duration_ms ?? null,
    source.started_at || "",
    requestBytes,
    responseBytes,
    noteCount,
    Boolean(hasResponse),
    source.content_type || source.response?.content_type || source.request?.content_type || "",
    Boolean(source.is_websocket),
    Boolean(source.has_match_replace),
    source.color_tag || "",
    Boolean(hasUserNote),
    source.annotation_revision ?? 0,
  ]);
}

function canReuseSelectedHistoryRecord(id) {
  return Boolean(
    id
    && state.selectedRecord?.id === id
    && historyRecordSummarySignature(state.selectedRecord) === historyRecordSummarySignature(getHistoryItem(id))
  );
}

async function selectHistoryTransaction(id, options = {}) {
  const nextId = id ?? null;
  if (nextId && state.selectedId === nextId && canReuseSelectedHistoryRecord(nextId)) {
    updateHistorySelection(nextId);
    if (options.scroll) {
      scrollSelectedHistoryRowIntoView();
    }
    return state.selectedRecord;
  }
  const hadRenderedDetail = Boolean(state.selectedRecord?.id);
  state.selectedId = nextId;
  state.selectedRecord = null;
  state.loadingDetailId = null;
  updateHistorySelection(state.selectedId);
  if (!state.selectedId) {
    renderEmptyDetail();
    return null;
  }
  scheduleHistoryDetailLoading(state.selectedId, "Loading selected transaction...", {
    immediate: !hadRenderedDetail,
  });
  if (options.scroll) {
    scrollSelectedHistoryRowIntoView();
  }
  return loadTransactionDetail(state.selectedId);
}

async function loadSelectedTransactionRecord() {
  const id = state.selectedId;
  if (!id) {
    return null;
  }
  if (state.selectedRecord?.id === id) {
    return state.selectedRecord;
  }

  const record = await loadTransactionRecordById(id);
  if (!record) {
    if (state.selectedId === id) {
      renderEmptyDetail();
    }
    return null;
  }

  if (state.selectedId === id) {
    state.selectedRecord = record;
    renderDetail(record);
    return record;
  }
  return null;
}

async function loadTransactionRecordById(id, sessionId = currentSessionId()) {
  if (!id || !sessionId) {
    return null;
  }
  const response = await fetch(transactionPath(id, sessionId));
  if (sessionId !== currentSessionId()) {
    return null;
  }
  if (!response.ok) {
    return null;
  }
  const record = await response.json();
  if (sessionId !== currentSessionId()) {
    return null;
  }
  return record;
}

function createTransactionRecordMenuTarget(id, sessionId = currentSessionId()) {
  const target = {
    id,
    sessionId,
    record: state.selectedRecord?.id === id ? state.selectedRecord : null,
    loadPromise: null,
    loadError: null,
  };
  if (!target.record) {
    target.loadPromise = loadTransactionRecordById(id, sessionId)
      .then((record) => {
        if (record?.id === id && sessionId === currentSessionId()) {
          target.record = record;
        }
        return target.record;
      })
      .catch((error) => {
        target.loadError = error;
        return null;
      });
  }
  return target;
}

function loadMenuTargetRecord(target) {
  if (!target?.id || target.sessionId !== currentSessionId()) {
    return null;
  }
  if (target.record?.id === target.id) {
    return Promise.resolve(target.record);
  }
  return target.loadPromise || loadTransactionRecordById(target.id, target.sessionId);
}

function transactionUrlFromSource(source) {
  if (!source) return "";
  const scheme = source.scheme || "https";
  const host = source.host || "";
  const path = source.path || "/";
  return buildUrlFromTarget(scheme, host, "", path);
}

function copyMenuTargetUrl(target) {
  if (!target?.id || target.sessionId !== currentSessionId()) {
    showToast("The selected session changed. Open the menu again.", "error");
    return;
  }
  const source = target.record || getHistoryItem(target.id);
  const url = transactionUrlFromSource(source);
  if (!url) {
    showToast("Selected transaction could not be loaded.", "error");
    return;
  }
  copyTextToClipboard(url)
    .then(() => showToast("Copied URL"))
    .catch(() => showToast("Failed to copy", "error"));
}

async function loadIntercepts(preserveSelection = true) {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath("/api/intercepts", sessionId));
  await requireOkResponse(response, "Failed to load intercepted requests.");
  const intercepts = jsonArray(await response.json());
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.intercepts = intercepts;

  const visibleIntercepts = getVisibleRequestInterceptSummaries();
  if (!preserveSelection || !visibleIntercepts.some((item) => item.id === state.selectedInterceptId)) {
    state.selectedInterceptId = visibleIntercepts[0]?.id ?? null;
    state.selectedInterceptRecord = null;
    state.interceptEditorSeedId = null;
  }

  renderIntercepts();
  updateInterceptQueueBadges();
  // Auto-switch to Request Queue when requests arrive and Response Queue is empty
  if (visibleIntercepts.length > 0 && getVisibleResponseInterceptSummaries().length === 0 && state.interceptQueueTab === "response") {
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
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath(`/api/intercepts/${id}`, sessionId));
  if (sessionId !== currentSessionId() || state.selectedInterceptId !== id) {
    return;
  }
  if (!response.ok) {
    state.selectedInterceptRecord = null;
    renderIntercepts();
    return;
  }

  const record = await response.json();
  if (sessionId !== currentSessionId() || state.selectedInterceptId !== id) {
    return;
  }
  state.selectedInterceptRecord = record;
  renderIntercepts();
}

/* ─── Intercept Rules ─── */

async function loadInterceptRules() {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath("/api/intercept-rules", sessionId));
  await requireOkResponse(response, "Failed to load intercept rules.");
  const rules = jsonArray(await response.json());
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.interceptRules = rules;
  renderInterceptRules();
}

function handleInterceptRuleError(error) {
  console.error(error);
  showToast(error?.message || "Intercept rule action failed.", "error", 6000);
  loadInterceptRules().catch(console.error);
}

function renderInterceptRules() {
  const container = document.getElementById("interceptRulesList");
  if (!container) return;
  const rules = state.interceptRules || [];
  if (!rules.length) {
    container.innerHTML = `<div class="intercept-rules-empty">No rules: all in-scope requests will be intercepted. Add a response or Req+Res rule to intercept responses.</div>`;
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
  const sessionId = currentSessionId();
  const rule = {
    id: crypto.randomUUID(),
    enabled: false,
    scope: "request",
    host_pattern: "",
    path_pattern: "",
    method_filter: [],
  };
  const response = await fetch(sessionWritePath("/api/intercept-rules", sessionId), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(rule),
  });
  await requireOkResponse(response, "Failed to add intercept rule.");
  if (sessionId !== currentSessionId()) {
    return;
  }
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
  const sessionId = currentSessionId();
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
  const response = await fetch(sessionWritePath("/api/intercept-rules", sessionId), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(updated),
  });
  await requireOkResponse(response, "Failed to save intercept rule.");
  if (sessionId !== currentSessionId()) {
    return;
  }
  await loadInterceptRules();
}

async function deleteInterceptRule(ruleId) {
  const sessionId = currentSessionId();
  const response = await fetch(sessionWritePath(`/api/intercept-rules/${ruleId}`, sessionId), { method: "DELETE" });
  await requireOkResponse(response, "Failed to delete intercept rule.");
  if (sessionId !== currentSessionId()) {
    return;
  }
  await loadInterceptRules();
}

async function toggleInterceptRuleEnabled(ruleId, enabled) {
  const sessionId = currentSessionId();
  const rule = (state.interceptRules || []).find((r) => r.id === ruleId);
  if (!rule) return;
  rule.enabled = enabled;
  const response = await fetch(sessionWritePath("/api/intercept-rules", sessionId), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(rule),
  });
  await requireOkResponse(response, "Failed to update intercept rule.");
  if (sessionId !== currentSessionId()) {
    return;
  }
  await loadInterceptRules();
}

function createWebsocketQueryState() {
  return {
    q: String(state.websocketQuery || "").trim(),
    sortKey: state.websocketSortKey || "started_at",
    sortDirection: state.websocketSortDirection === "asc" ? "asc" : "desc",
    inScopeOnly: Boolean(state.websocketInScopeOnly),
    liveOnly: Boolean(state.websocketLiveOnly),
  };
}

function websocketQuerySignature(queryState = createWebsocketQueryState()) {
  return JSON.stringify(queryState);
}

function websocketCursorPagingEnabled(queryState = createWebsocketQueryState()) {
  return queryState.sortDirection === "desc"
    && (queryState.sortKey === "started_at" || queryState.sortKey === "index");
}

function websocketAppendAfterId() {
  const sessions = Array.isArray(state.websocketSessions) ? state.websocketSessions : [];
  return sessions.length ? (sessions[sessions.length - 1]?.id || null) : null;
}

function buildWebsocketsPageUrl({ limit, offset, afterId, queryState }) {
  const params = new URLSearchParams();
  params.set("limit", String(limit));
  params.set("offset", String(offset));
  if (afterId) params.set("after_id", afterId);
  if (queryState.q) params.set("q", queryState.q);
  if (queryState.sortKey) params.set("sort_key", queryState.sortKey);
  if (queryState.sortDirection) params.set("sort_direction", queryState.sortDirection);
  if (queryState.inScopeOnly) params.set("in_scope_only", "true");
  if (queryState.liveOnly) params.set("live_only", "true");
  return `/api/websockets-page?${params.toString()}`;
}

async function loadWebsockets(preserveSelection = true, options = {}) {
  const generation = ++_websocketLoadGeneration;
  const summaryMutationGeneration = _websocketSummaryMutationGeneration;
  const sessionId = currentSessionId();
  const queryState = createWebsocketQueryState();
  const querySignature = websocketQuerySignature(queryState);
  const append = Boolean(options.append);
  const previousQuerySignature = state.websocketPaging?.querySignature || "";
  const queryChanged = !append
    && Boolean(previousQuerySignature)
    && previousQuerySignature !== querySignature;
  const requestedOffset = append
    ? Math.max(0, Number(options.offset ?? state.websocketPaging?.loadedOffset ?? state.websocketPaging?.limit ?? 0) || 0)
    : 0;
  const requestedLimit = append
    ? WEBSOCKET_PAGE_SIZE
    : normalizeWebsocketLoadLimit(options.limit ?? (queryChanged ? WEBSOCKET_PAGE_SIZE : state.websocketPaging?.limit));
  const requestedAfterId = append && websocketCursorPagingEnabled(queryState)
    ? (options.afterId || websocketAppendAfterId())
    : null;
  const resetWindow = !append && (options.resetWindow === true || queryChanged);
  if (resetWindow) {
    resetWebsocketHistoryScroll();
  }
  state.websocketPaging = {
    ...createWebsocketPagingState(),
    ...(state.websocketPaging || {}),
    querySignature,
    offset: requestedOffset,
    afterId: requestedAfterId,
    loading: true,
  };
  state.websocketListError = "";
  if (resetWindow) {
    clearWebsocketLoadedSessionsForPendingQuery();
  }
  try {
    const response = await fetch(sessionQueryPath(
      buildWebsocketsPageUrl({
        limit: requestedLimit,
        offset: requestedOffset,
        afterId: requestedAfterId,
        queryState,
      }),
      sessionId,
    ));
    await requireOkResponse(response, "Failed to load WebSocket history.");
    const page = websocketPagePayload(await response.json());
    if (
      generation !== _websocketLoadGeneration
      || sessionId !== currentSessionId()
      || querySignature !== websocketQuerySignature()
    ) {
      return;
    }
    const pageItems = jsonArray(page.items);
    const pageOffset = Math.max(0, Number(page.offset ?? requestedOffset) || 0);
    if (
      append
      && !websocketCursorPagingEnabled(queryState)
      && summaryMutationGeneration !== _websocketSummaryMutationGeneration
    ) {
      state.websocketPaging = {
        ...(state.websocketPaging || createWebsocketPagingState()),
        querySignature,
        loading: false,
      };
      await loadWebsocketsPageRefresh(preserveSelection);
      return;
    }
    const loadedOffset = Math.max(
      append ? Number(state.websocketPaging?.loadedOffset ?? 0) || 0 : 0,
      pageOffset + pageItems.length,
    );
    const serverHasMore = Boolean(page.has_more);
    const responsePaging = {
      ...(state.websocketPaging || createWebsocketPagingState()),
      hasMore: serverHasMore,
      capReached: serverHasMore && loadedOffset >= WEBSOCKET_MAX_LOADED_SESSIONS,
    };
    state.websocketSessions = append
      ? mergeWebsocketAppendPage(pageItems, state.websocketSessions, summaryMutationGeneration)
      : (summaryMutationGeneration === _websocketSummaryMutationGeneration
        ? pageItems
        : mergeWebsocketPageWithCurrentSummaries(
          pageItems,
          state.websocketSessions,
          summaryMutationGeneration,
          responsePaging,
        ));
    pruneWebsocketSummaryMutationCache();
    const loadedLimit = Math.min(
      WEBSOCKET_MAX_LOADED_SESSIONS,
      Math.max(loadedOffset, state.websocketSessions.length),
    );
    const capReached = serverHasMore && loadedLimit >= WEBSOCKET_MAX_LOADED_SESSIONS;
    state.websocketPaging = {
      querySignature,
      total: Math.max(Number(page.total || 0), state.websocketSessions.length),
      filteredTotal: page.filteredTotal,
      limit: loadedLimit,
      loadedOffset: loadedLimit,
      offset: pageOffset,
      afterId: websocketAppendAfterId(),
      hasMore: serverHasMore && !capReached,
      capReached,
      loading: false,
      summaryMutationGeneration: _websocketSummaryMutationGeneration,
    };
    state.websocketListError = "";
    state.websocketHistoryDirty = false;
    await syncVisibleWebsocketSelection(preserveSelection);
  } catch (error) {
    if (
      generation === _websocketLoadGeneration
      && sessionId === currentSessionId()
      && querySignature === websocketQuerySignature()
    ) {
      state.websocketPaging = {
        ...(state.websocketPaging || createWebsocketPagingState()),
        querySignature,
        hasMore: false,
        loading: false,
      };
      state.websocketListError = error?.message || "Failed to load WebSocket history.";
      if (!append) {
        clearWebsocketLoadedSessionsForPendingQuery();
      } else {
        renderWebsocketSessions();
      }
    }
    throw error;
  }
}

function currentWebsocketRefreshLimit() {
  const paging = state.websocketPaging || createWebsocketPagingState();
  const loadedCount = Array.isArray(state.websocketSessions) ? state.websocketSessions.length : 0;
  const loadedLimit = Math.max(
    loadedCount,
    Number(paging.loadedOffset ?? paging.limit ?? 0) || 0,
    WEBSOCKET_PAGE_SIZE,
  );
  return normalizeWebsocketLoadLimit(loadedLimit);
}

async function loadWebsocketsPageRefresh(preserveSelection = true, options = {}) {
  const limit = options.resetWindow === true
    ? WEBSOCKET_PAGE_SIZE
    : currentWebsocketRefreshLimit();
  return loadWebsockets(preserveSelection, { ...options, limit });
}

async function loadMoreWebsockets() {
  const paging = state.websocketPaging || createWebsocketPagingState();
  if (paging.loading || !paging.hasMore) {
    return 0;
  }
  const previousCount = (state.websocketSessions || []).length;
  const nextOffset = Math.max(0, Number(paging.loadedOffset ?? paging.limit ?? state.websocketSessions.length) || 0);
  const queryState = createWebsocketQueryState();
  if (
    !websocketCursorPagingEnabled(queryState)
    && Number(paging.summaryMutationGeneration ?? 0) !== _websocketSummaryMutationGeneration
  ) {
    await loadWebsocketsPageRefresh(true);
    return 0;
  }
  const nextAfterId = websocketCursorPagingEnabled(queryState) ? websocketAppendAfterId() : null;
  if (nextOffset >= WEBSOCKET_MAX_LOADED_SESSIONS) {
    state.websocketPaging = { ...paging, hasMore: false, capReached: true };
    renderWebsocketSessions();
    return 0;
  }
  state.websocketPaging = { ...paging, offset: nextOffset, afterId: nextAfterId };
  await loadWebsockets(true, { append: true, offset: nextOffset, afterId: nextAfterId });
  return Math.max(0, (state.websocketSessions || []).length - previousCount);
}

function adjustWebsocketPagingAfterLocalRemoval(removedCount = 1) {
  const count = Math.max(0, Number(removedCount) || 0);
  if (!count) return;
  const paging = state.websocketPaging || createWebsocketPagingState();
  const previousLoadedOffset = Number(paging.loadedOffset ?? paging.limit ?? state.websocketSessions.length + count) || 0;
  const previousLimit = Number(paging.limit ?? previousLoadedOffset) || 0;
  const previousTotal = Number(paging.total || 0) || 0;
  const filteredTotal = isKnownCount(paging.filteredTotal)
    ? Math.max(0, Number(paging.filteredTotal) - count)
    : paging.filteredTotal;
  state.websocketPaging = {
    ...paging,
    total: Math.max(state.websocketSessions.length, previousTotal - count),
    filteredTotal,
    limit: Math.max(0, previousLimit - count),
    loadedOffset: Math.max(0, previousLoadedOffset - count),
    loading: false,
  };
}

function websocketQueryBackfillShouldRun(visibleCount) {
  const paging = state.websocketPaging || createWebsocketPagingState();
  return state.activeProxyTab === "websockets-history"
    && websocketFilterIsActive()
    && visibleCount < websocketQueryBackfillVisibleTarget()
    && Boolean(paging.hasMore)
    && !Boolean(paging.loading)
    && normalizeWebsocketLoadLimit(paging.limit) < WEBSOCKET_MAX_LOADED_SESSIONS;
}

function websocketQueryBackfillVisibleTarget() {
  const shell = document.querySelector("#websocketTable")?.closest(".history-table-shell");
  const rowHeight = measuredWebsocketSessionRowHeight || WEBSOCKET_SESSION_ROW_HEIGHT;
  const viewportRows = shell?.clientHeight
    ? Math.ceil(shell.clientHeight / rowHeight)
    : 1;
  return Math.max(1, Math.min(WEBSOCKET_MAX_RENDERED_SESSION_ROWS, viewportRows + WEBSOCKET_SESSION_BUFFER_ROWS));
}

function websocketFilterIsActive() {
  return Boolean(String(state.websocketQuery || "").trim())
    || Boolean(state.websocketInScopeOnly)
    || Boolean(state.websocketLiveOnly);
}

function websocketSummarySearchHaystack(summary) {
  const durationLabel = summary.duration_ms != null
    ? `${summary.duration_ms} ms`
    : (summary.closed_at == null ? "live" : "closed");
  return [
    summary.scheme || "",
    summary.host || "",
    summary.path || "",
    summary.status == null ? "" : String(summary.status),
    summary.frame_count == null ? "" : String(summary.frame_count),
    durationLabel,
    summary.started_at || "",
  ].join("\n").toLowerCase();
}

function websocketSummaryMatchesCurrentQuery(summary) {
  if (!summary) return false;
  const queryState = createWebsocketQueryState();
  if (queryState.inScopeOnly && !isInScopeHost(summary.host)) return false;
  if (queryState.liveOnly && summary.closed_at != null) return false;
  if (queryState.q) {
    const haystack = websocketSummarySearchHaystack(summary);
    if (!haystack.includes(queryState.q.toLowerCase())) return false;
  }
  return true;
}

function clearFilteredWebsocketReload() {
  if (_websocketFilteredReloadTimer) {
    window.clearTimeout(_websocketFilteredReloadTimer);
    _websocketFilteredReloadTimer = 0;
  }
  _websocketFilteredReloadDueAt = 0;
}

function clearWebsocketSearchReload() {
  if (_websocketSearchReloadTimer) {
    window.clearTimeout(_websocketSearchReloadTimer);
    _websocketSearchReloadTimer = 0;
  }
}

function clearWebsocketSelectionPreview(options = {}) {
  state.selectedWebsocketId = null;
  state.selectedFrameIdx = null;
  state.selectedWebsocketRecord = null;
  state.selectedWebsocketDetailError = "";
  cancelWebsocketDetailLoading();
  hideFrameDetail();
  resetWebsocketFrameScroll();
  if (options.render) {
    renderWebsocketSessions();
  }
}

function clearWebsocketLoadedSessionsForPendingQuery() {
  state.websocketSessions = [];
  clearWebsocketSelectionPreview();
  renderWebsocketSessions();
}

function resetWebsocketHistoryScroll() {
  const shell = document.querySelector("#websocketTable")?.closest(".history-table-shell");
  if (shell) {
    shell.scrollTop = 0;
  }
}

function scheduleWebsocketPageRefresh(options = {}) {
  state.websocketHistoryDirty = true;
  const minDelayMs = Math.max(0, Number(options.minDelayMs) || 0);
  const refreshDelay = minDelayMs
    ? Math.max(0, minDelayMs - (Date.now() - _lastWebsocketPageRefreshAt))
    : 250;
  const dueAt = Date.now() + refreshDelay;
  if (_websocketFilteredReloadTimer) {
    if (minDelayMs || _websocketFilteredReloadDueAt <= dueAt) {
      return;
    }
    window.clearTimeout(_websocketFilteredReloadTimer);
    _websocketFilteredReloadTimer = 0;
  }
  _websocketFilteredReloadDueAt = dueAt;
  _websocketFilteredReloadTimer = window.setTimeout(() => {
    _websocketFilteredReloadTimer = 0;
    _websocketFilteredReloadDueAt = 0;
    if (isWebsocketHistoryVisible()) {
      _lastWebsocketPageRefreshAt = Date.now();
      loadWebsocketsPageRefresh(true).catch((error) => console.error(error));
    }
  }, refreshDelay);
}

function scheduleFilteredWebsocketReload() {
  scheduleWebsocketPageRefresh();
}

function clearWebsocketQueryBackfill() {
  _websocketQueryBackfillGeneration += 1;
  if (_websocketQueryBackfillTimer) {
    window.clearTimeout(_websocketQueryBackfillTimer);
    _websocketQueryBackfillTimer = 0;
  }
}

function scheduleWebsocketQueryBackfill(visibleCount) {
  if (!websocketQueryBackfillShouldRun(visibleCount) || _websocketQueryBackfillTimer) {
    return;
  }
  const generation = _websocketQueryBackfillGeneration;
  const sessionId = currentSessionId();
  _websocketQueryBackfillTimer = window.setTimeout(() => {
    _websocketQueryBackfillTimer = 0;
    if (generation !== _websocketQueryBackfillGeneration || sessionId !== currentSessionId()) {
      return;
    }
    if (!websocketQueryBackfillShouldRun(getVisibleWebsocketSessions().length)) {
      return;
    }
    loadMoreWebsockets().catch((error) => console.error(error));
  }, WEBSOCKET_QUERY_BACKFILL_DELAY_MS);
}

function normalizeWebsocketLoadLimit(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    return WEBSOCKET_PAGE_SIZE;
  }
  return Math.min(
    WEBSOCKET_MAX_LOADED_SESSIONS,
    Math.max(WEBSOCKET_PAGE_SIZE, Math.ceil(numeric)),
  );
}

function websocketSummaryNumber(summary, key, fallback = -1) {
  const value = Number(summary?.[key]);
  return Number.isFinite(value) ? value : fallback;
}

function websocketSummaryTimestamp(summary, key) {
  const raw = summary?.[key];
  if (!raw) return 0;
  const timestamp = Date.parse(raw);
  return Number.isFinite(timestamp) ? timestamp : 0;
}

function isWebsocketSummaryFresher(candidate, baseline) {
  if (!candidate) return false;
  if (!baseline) return true;
  const numericKeys = ["frame_count", "last_frame_index", "note_count"];
  for (const key of numericKeys) {
    const candidateValue = websocketSummaryNumber(candidate, key);
    const baselineValue = websocketSummaryNumber(baseline, key);
    if (candidateValue !== baselineValue) {
      return candidateValue > baselineValue;
    }
  }
  const closedDelta = websocketSummaryTimestamp(candidate, "closed_at") - websocketSummaryTimestamp(baseline, "closed_at");
  if (closedDelta !== 0) return closedDelta > 0;
  const durationDelta = websocketSummaryNumber(candidate, "duration_ms") - websocketSummaryNumber(baseline, "duration_ms");
  if (durationDelta !== 0) return durationDelta > 0;
  return false;
}

function shouldInsertUnknownWebsocketSummary(summary, sessions, paging) {
  if (!summary?.id) return false;
  if (!websocketSummaryMatchesCurrentQuery(summary)) return false;
  if (!Boolean(paging?.hasMore)) return true;
  if (!Array.isArray(sessions) || !sessions.length) return true;
  return websocketSummaryStartedAtDescInsertIndex(summary, sessions) < sessions.length;
}

function websocketSummaryStartedAtDescCompare(left, right) {
  const leftStartedAt = websocketSummaryTimestamp(left, "started_at");
  const rightStartedAt = websocketSummaryTimestamp(right, "started_at");
  if (leftStartedAt !== rightStartedAt) {
    return rightStartedAt - leftStartedAt;
  }
  return String(left?.id || "").localeCompare(String(right?.id || ""));
}

function websocketSummaryStartedAtDescInsertIndex(summary, sessions) {
  if (!Array.isArray(sessions) || !sessions.length) return 0;
  for (let index = 0; index < sessions.length; index += 1) {
    if (websocketSummaryStartedAtDescCompare(summary, sessions[index]) <= 0) {
      return index;
    }
  }
  return sessions.length;
}

function insertWebsocketSummaryInStartedAtDescOrder(sessions, summary) {
  sessions.splice(websocketSummaryStartedAtDescInsertIndex(summary, sessions), 0, summary);
}

function mergeWebsocketPageWithCurrentSummaries(
  pageItems,
  currentItems,
  mutationGenerationAtRequest,
  paging = state.websocketPaging,
) {
  const currentById = new Map((currentItems || []).map((item) => [item.id, item]));
  const seen = new Set();
  const merged = [];
  const preserved = [];
  for (const item of pageItems || []) {
    if (!item?.id || seen.has(item.id)) continue;
    const current = currentById.get(item.id);
    const currentMutatedDuringRequest = (_websocketSummaryMutationById.get(item.id) || 0) > mutationGenerationAtRequest;
    merged.push(
      currentMutatedDuringRequest && isWebsocketSummaryFresher(current, item)
        ? current
        : item,
    );
    seen.add(item.id);
  }
  for (const item of currentItems || []) {
    if (!item?.id || seen.has(item.id)) continue;
    if ((_websocketSummaryMutationById.get(item.id) || 0) <= mutationGenerationAtRequest) continue;
    if (!websocketServerOrderCanAcceptSummaryEvents()) continue;
    if (!shouldInsertUnknownWebsocketSummary(item, pageItems, paging)) continue;
    preserved.push(item);
    seen.add(item.id);
  }
  for (const item of preserved) {
    insertWebsocketSummaryInStartedAtDescOrder(merged, item);
  }
  if (merged.length > WEBSOCKET_MAX_LOADED_SESSIONS) {
    merged.length = WEBSOCKET_MAX_LOADED_SESSIONS;
  }
  return merged;
}

function mergeWebsocketAppendPage(pageItems, currentItems, mutationGenerationAtRequest) {
  const currentById = new Map((currentItems || []).map((item) => [item.id, item]));
  const merged = [];
  const indexById = new Map();
  const seen = new Set();
  for (const item of currentItems || []) {
    if (!item?.id || seen.has(item.id)) continue;
    indexById.set(item.id, merged.length);
    merged.push(item);
    seen.add(item.id);
  }
  for (const item of pageItems || []) {
    if (!item?.id) continue;
    const current = currentById.get(item.id);
    const currentMutatedDuringRequest = (_websocketSummaryMutationById.get(item.id) || 0) > mutationGenerationAtRequest;
    if (current) {
      if (currentMutatedDuringRequest && isWebsocketSummaryFresher(current, item)) continue;
      const index = indexById.get(item.id);
      if (index >= 0) merged[index] = item;
      continue;
    }
    if (seen.has(item.id)) continue;
    indexById.set(item.id, merged.length);
    merged.push(item);
    seen.add(item.id);
  }
  if (merged.length > WEBSOCKET_MAX_LOADED_SESSIONS) {
    merged.length = WEBSOCKET_MAX_LOADED_SESSIONS;
  }
  return merged;
}

function normalizeWebsocketFrameIndex(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

function normalizeWebsocketCount(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric >= 0 ? Math.floor(numeric) : null;
}

function websocketRetainedFrameCount(summary, frames = []) {
  const retained = normalizeWebsocketCount(summary?.retained_frame_count);
  if (retained != null) return retained;
  const fullCount = normalizeWebsocketCount(summary?.frame_count);
  if (fullCount != null) return Math.min(fullCount, frames.length);
  return frames.length;
}

function websocketFirstRetainedFrameIndex(summary, frames = []) {
  const retained = websocketRetainedFrameCount(summary, frames);
  const lastFrameIndex = normalizeWebsocketFrameIndex(summary?.last_frame_index);
  if (lastFrameIndex != null && retained > 0) {
    return Math.max(0, lastFrameIndex - retained + 1);
  }
  const firstFrameIndex = frames.length ? normalizeWebsocketFrameIndex(frames[0]?.index) : null;
  return firstFrameIndex != null ? Math.max(0, firstFrameIndex) : 0;
}

function mergeWebsocketDetailRefreshTarget(id, lastFrameIndex = null) {
  if (!id) return null;
  const nextIndex = normalizeWebsocketFrameIndex(lastFrameIndex);
  const current = _websocketDetailRefreshNeeded?.id === id
    ? normalizeWebsocketFrameIndex(_websocketDetailRefreshNeeded.lastFrameIndex)
    : null;
  return {
    id,
    lastFrameIndex: current == null
      ? nextIndex
      : (nextIndex == null ? current : Math.max(current, nextIndex)),
  };
}

function selectedWebsocketDetailMeetsRefreshTarget(target) {
  if (!target || target.id !== state.selectedWebsocketId) return true;
  const targetIndex = normalizeWebsocketFrameIndex(target.lastFrameIndex);
  if (targetIndex == null) return false;
  const loadedIndex = normalizeWebsocketFrameIndex(
    state.selectedWebsocketRecord?.loaded_last_frame_index,
  );
  return loadedIndex != null && loadedIndex >= targetIndex;
}

function websocketDetailRequestPath(id, sessionId, options = {}) {
  const params = new URLSearchParams();
  params.set("frame_limit", String(WEBSOCKET_DETAIL_FRAME_LIMIT));
  const beforeIndex = normalizeWebsocketFrameIndex(options.beforeIndex);
  if (beforeIndex != null) {
    params.set("before_index", String(beforeIndex));
  }
  return sessionQueryPath(
    `/api/websockets/${encodeURIComponent(id)}?${params.toString()}`,
    sessionId,
  );
}

function capWebsocketFrameWindow(frames, options = {}) {
  const normalizedFrames = Array.isArray(frames) ? frames : [];
  if (normalizedFrames.length <= WEBSOCKET_MAX_LOADED_FRAMES) {
    return normalizedFrames;
  }
  const capped = options.prefer === "older"
    ? normalizedFrames.slice(0, WEBSOCKET_MAX_LOADED_FRAMES)
    : normalizedFrames.slice(normalizedFrames.length - WEBSOCKET_MAX_LOADED_FRAMES);
  const preserveIndexes = Array.isArray(options.preserveIndexes)
    ? options.preserveIndexes
      .map((index) => normalizeWebsocketFrameIndex(index))
      .filter((index) => index != null)
    : [];
  if (!preserveIndexes.length) {
    return capped;
  }
  const cappedIndexes = new Set(capped.map((frame) => normalizeWebsocketFrameIndex(frame?.index)));
  const replacementOffset = options.prefer === "older" ? capped.length - 1 : 0;
  let replacementCount = 0;
  for (const preserveIndex of preserveIndexes) {
    if (cappedIndexes.has(preserveIndex)) continue;
    const preservedFrame = normalizedFrames.find(
      (frame) => normalizeWebsocketFrameIndex(frame?.index) === preserveIndex,
    );
    if (!preservedFrame) continue;
    const replacementIndex = options.prefer === "older"
      ? replacementOffset - replacementCount
      : replacementOffset + replacementCount;
    if (replacementIndex < 0 || replacementIndex >= capped.length) break;
    const replacedIndex = normalizeWebsocketFrameIndex(capped[replacementIndex]?.index);
    capped[replacementIndex] = preservedFrame;
    cappedIndexes.delete(replacedIndex);
    cappedIndexes.add(preserveIndex);
    replacementCount += 1;
  }
  return capped.sort((left, right) => left.index - right.index);
}

function mergeWebsocketFrameWindows(currentFrames, incomingFrames, options = {}) {
  const mergedByIndex = new Map();
  for (const frame of normalizeWebsocketFrames(currentFrames)) {
    mergedByIndex.set(frame.index, frame);
  }
  for (const frame of normalizeWebsocketFrames(incomingFrames)) {
    mergedByIndex.set(frame.index, frame);
  }
  return capWebsocketFrameWindow(
    Array.from(mergedByIndex.values()).sort((left, right) => left.index - right.index),
    options,
  );
}

function newestWebsocketFrameIndexes(frames, limit) {
  const normalizedFrames = normalizeWebsocketFrames(frames);
  const maxCount = Math.max(0, Math.floor(Number(limit) || 0));
  return normalizedFrames
    .slice(Math.max(0, normalizedFrames.length - maxCount))
    .map((frame) => normalizeWebsocketFrameIndex(frame?.index))
    .filter((index) => index != null);
}

async function loadWebsocketDetail(id, options = {}) {
  const force = Boolean(options.force);
  const sessionId = currentSessionId();
  if (
    _websocketDetailPendingId === id
    && _websocketDetailPendingSessionId === sessionId
    && _websocketDetailPendingPromise
  ) {
    if (force) {
      _websocketDetailRefreshNeeded = mergeWebsocketDetailRefreshTarget(id, options.lastFrameIndex);
    }
    return _websocketDetailPendingPromise;
  }
  if (force && _websocketDetailRefreshNeeded?.id === id) {
    _websocketDetailRefreshNeeded = null;
  }
  const generation = ++_websocketDetailGeneration;
  if (state.selectedWebsocketId !== id) {
    hideFrameDetail();
  }

  const pending = (async () => {
    const detailPath = websocketDetailRequestPath(id, sessionId);
    const response = await fetch(detailPath);
    if (sessionId !== currentSessionId()) {
      return;
    }
    if (!response.ok) {
      if (response.status === 404) {
        const wasSelected = state.selectedWebsocketId === id;
        const removedIndex = (state.websocketSessions || []).findIndex((item) => item.id === id);
        const previousLength = (state.websocketSessions || []).length;
        state.websocketSessions = (state.websocketSessions || []).filter((item) => item.id !== id);
        adjustWebsocketPagingAfterLocalRemoval(previousLength - state.websocketSessions.length);
        if (!wasSelected) {
          if (previousLength !== state.websocketSessions.length) {
            renderWebsocketSessions();
          }
          return;
        }
        state.selectedWebsocketId = removedIndex >= 0
          ? (state.websocketSessions[Math.min(removedIndex, state.websocketSessions.length - 1)]?.id ?? null)
          : null;
        state.selectedFrameIdx = null;
        state.selectedWebsocketRecord = null;
        state.selectedWebsocketDetailError = "";
        hideFrameDetail();
        resetWebsocketFrameScroll();
        await syncVisibleWebsocketSelection(true, { ensureSelectedVisible: true });
        return;
      }
      if (generation !== _websocketDetailGeneration || state.selectedWebsocketId !== id) {
        return;
      }
      state.selectedWebsocketRecord = null;
      state.selectedWebsocketDetailError = "Failed to load selected WebSocket session.";
      cancelWebsocketDetailLoading();
      renderWebsocketSessions();
      return;
    }

    if (generation !== _websocketDetailGeneration) {
      return;
    }
    const detail = await response.json();
    if (generation !== _websocketDetailGeneration || sessionId !== currentSessionId() || state.selectedWebsocketId !== id) {
      return;
    }
    const summary = state.websocketSessions.find((item) => item.id === id);
    const previousFrames = state.selectedWebsocketRecord?.id === id
      ? state.selectedWebsocketRecord.frames
      : [];
    const mergedFrames = mergeWebsocketFrameWindows(previousFrames, detail.frames, {
      prefer: "latest",
      preserveIndexes: [state.selectedFrameIdx],
    });
    const loadedFirstFrameIndex = mergedFrames.length
      ? Number(mergedFrames[0]?.index)
      : null;
    const loadedLastFrameIndex = mergedFrames.length
      ? Number(mergedFrames[mergedFrames.length - 1]?.index)
      : null;
    const lastFrameIndex = Number.isFinite(Number(summary?.last_frame_index))
      ? Number(summary.last_frame_index)
      : loadedLastFrameIndex;
    const retainedFrameCount = websocketRetainedFrameCount({
      retained_frame_count: summary?.retained_frame_count,
      frame_count: summary?.frame_count,
      last_frame_index: lastFrameIndex,
    }, mergedFrames);
    const firstRetainedFrameIndex = websocketFirstRetainedFrameIndex({
      retained_frame_count: retainedFrameCount,
      last_frame_index: lastFrameIndex,
    }, mergedFrames);
    state.selectedWebsocketRecord = {
      ...detail,
      frames: mergedFrames,
      frame_count: Number.isFinite(Number(summary?.frame_count))
        ? Number(summary.frame_count)
        : mergedFrames.length,
      retained_frame_count: retainedFrameCount,
      last_frame_index: lastFrameIndex,
      retained_first_frame_index: firstRetainedFrameIndex,
      loaded_first_frame_index: Number.isFinite(loadedFirstFrameIndex)
        ? loadedFirstFrameIndex
        : null,
      loaded_last_frame_index: Number.isFinite(loadedLastFrameIndex)
        ? loadedLastFrameIndex
        : null,
      note_count: Number.isFinite(Number(summary?.note_count))
        ? Number(summary.note_count)
        : (Array.isArray(detail.notes) ? detail.notes.length : 0),
      frames_truncated: websocketFramesAreTruncated(mergedFrames, summary),
      older_frames_loading: false,
      older_frames_exhausted: Number.isFinite(loadedFirstFrameIndex)
        ? loadedFirstFrameIndex <= firstRetainedFrameIndex
          || normalizeWebsocketFrames(detail.frames).length < WEBSOCKET_DETAIL_FRAME_LIMIT
        : true,
    };
    state.selectedWebsocketDetailError = "";
    cancelWebsocketDetailLoading();
    renderWebsocketSessions();
  })();
  _websocketDetailPendingId = id;
  _websocketDetailPendingSessionId = sessionId;
  _websocketDetailPendingPromise = pending;
  try {
    return await pending;
  } finally {
    if (
      _websocketDetailPendingId === id
      && _websocketDetailPendingSessionId === sessionId
      && _websocketDetailPendingPromise === pending
    ) {
      _websocketDetailPendingId = null;
      _websocketDetailPendingSessionId = null;
      _websocketDetailPendingPromise = null;
    }
    const refreshTarget = _websocketDetailRefreshNeeded;
    if (
      refreshTarget?.id === id
      && id === state.selectedWebsocketId
      && !selectedWebsocketDetailMeetsRefreshTarget(refreshTarget)
    ) {
      scheduleSelectedWebsocketDetailRefresh(id, refreshTarget.lastFrameIndex);
    } else if (
      refreshTarget?.id === id
      && selectedWebsocketDetailMeetsRefreshTarget(refreshTarget)
    ) {
      _websocketDetailRefreshNeeded = null;
    }
  }
}

function websocketSummarySignature(summary) {
  if (!summary) return "";
  return [
    summary.id,
    summary.status ?? "",
    summary.frame_count ?? 0,
    summary.last_frame_index ?? "",
    summary.closed_at ?? "",
    summary.duration_ms ?? "",
    summary.note_count ?? 0,
    summary.started_at ?? "",
    summary.host ?? "",
    summary.path ?? "",
  ].join("|");
}

function noteWebsocketSummaryMutation(id) {
  _websocketSummaryMutationGeneration += 1;
  if (id) {
    _websocketSummaryMutationById.set(id, _websocketSummaryMutationGeneration);
  }
  pruneWebsocketSummaryMutationCache();
}

function websocketServerOrderCanAcceptSummaryEvents() {
  return (state.websocketSortKey || "started_at") === "started_at"
    && (state.websocketSortDirection || "desc") === "desc";
}

function flushWebsocketSummaryEvents() {
  _websocketSummaryEventTimer = 0;
  if (!_websocketSummaryEventBuffer.size) {
    return;
  }
  const summaries = Array.from(_websocketSummaryEventBuffer.values());
  _websocketSummaryEventBuffer.clear();
  for (const summary of summaries) {
    applyWebsocketSummary(summary);
  }
}

function queueWebsocketSummaryEvent(event) {
  let summary;
  try {
    summary = JSON.parse(event.data);
  } catch (error) {
    console.error("invalid websocket event", error);
    return;
  }
  if (!summary?.id) return;
  _websocketSummaryEventBuffer.set(summary.id, summary);
  if (_websocketSummaryEventTimer) {
    return;
  }
  _websocketSummaryEventTimer = window.setTimeout(
    flushWebsocketSummaryEvents,
    WEBSOCKET_SUMMARY_EVENT_BATCH_MS,
  );
}

function applyWebsocketSummary(summary) {
  if (!summary?.id) return;
  if (!websocketServerOrderCanAcceptSummaryEvents()) {
    const selectedChanged = applySelectedWebsocketSummary(summary);
    noteWebsocketSummaryMutation(summary.id);
    if (selectedChanged && isWebsocketHistoryVisible()) {
      scheduleVisibleWebsocketSelectionSync({ deferStaleDetail: true });
    }
    scheduleWebsocketPageRefresh({ minDelayMs: WEBSOCKET_SORTED_SUMMARY_REFRESH_MIN_MS });
    return;
  }

  const filtersActive = websocketFilterIsActive();
  const sessions = Array.isArray(state.websocketSessions) ? state.websocketSessions : [];
  const existingIndex = sessions.findIndex((item) => item.id === summary.id);
  const previous = existingIndex >= 0 ? sessions[existingIndex] : null;
  if (websocketSummarySignature(previous) === websocketSummarySignature(summary)) {
    return;
  }
  const summaryMatches = websocketSummaryMatchesCurrentQuery(summary);

  if (filtersActive && existingIndex < 0 && !summaryMatches) {
    const selectedChanged = applySelectedWebsocketSummary(summary);
    if (selectedChanged && isWebsocketHistoryVisible()) {
      scheduleVisibleWebsocketSelectionSync({ deferStaleDetail: true });
    }
    return;
  }

  const nextSessions = sessions.slice();
  let removedVisibleCount = 0;
  if (existingIndex >= 0) {
    if (!summaryMatches) {
      nextSessions.splice(existingIndex, 1);
      removedVisibleCount = 1;
    } else {
      nextSessions[existingIndex] = summary;
    }
  } else {
    const paging = state.websocketPaging || createWebsocketPagingState();
    if (!summaryMatches || !shouldInsertUnknownWebsocketSummary(summary, sessions, paging)) {
      const selectedChanged = applySelectedWebsocketSummary(summary);
      state.websocketPaging = {
        ...paging,
        total: Math.max(Number(paging.total || 0), sessions.length),
        limit: Number(paging.limit ?? paging.loadedOffset ?? 0) || 0,
        loadedOffset: Number(paging.loadedOffset ?? paging.limit ?? 0) || 0,
        capReached: Boolean(paging.capReached),
        loading: false,
      };
      if (selectedChanged && isWebsocketHistoryVisible()) {
        scheduleVisibleWebsocketSelectionSync({ deferStaleDetail: true });
      }
      return;
    }
    insertWebsocketSummaryInStartedAtDescOrder(nextSessions, summary);
    if (nextSessions.length > WEBSOCKET_MAX_LOADED_SESSIONS) {
      nextSessions.length = WEBSOCKET_MAX_LOADED_SESSIONS;
    }
    const knownTotal = Number(paging.total || 0);
    const hasMore = Boolean(paging.hasMore);
    const nextTotal = Math.max(knownTotal + 1, nextSessions.length);
    const capReached = Boolean(paging.capReached)
      || (nextSessions.length >= WEBSOCKET_MAX_LOADED_SESSIONS && nextTotal > nextSessions.length);
    const nextLoadedOffset = Math.min(
      WEBSOCKET_MAX_LOADED_SESSIONS,
      Math.max(
        Number(paging.loadedOffset ?? paging.limit ?? 0) || 0,
        nextSessions.length,
      ),
    );
    state.websocketPaging = {
      ...paging,
      total: nextTotal,
      limit: nextLoadedOffset,
      loadedOffset: nextLoadedOffset,
      hasMore: hasMore && nextSessions.length < WEBSOCKET_MAX_LOADED_SESSIONS,
      capReached,
      loading: false,
    };
  }
  state.websocketSessions = nextSessions;
  if (removedVisibleCount) {
    adjustWebsocketPagingAfterLocalRemoval(removedVisibleCount);
  }
  noteWebsocketSummaryMutation(summary.id);

  const selectedChanged = applySelectedWebsocketSummary(summary);

  if (isWebsocketHistoryVisible()) {
    if (!state.selectedWebsocketId) {
      scheduleVisibleWebsocketSelectionSync();
    } else {
      scheduleVisibleWebsocketSelectionSync({
        ensureSelectedVisible: true,
        deferStaleDetail: true,
      });
    }
  }
}

async function loadOlderWebsocketFrames() {
  const session = state.selectedWebsocketRecord;
  const id = state.selectedWebsocketId;
  if (!session || !id || session.id !== id || session.older_frames_loading) {
    return;
  }
  const frames = getWebsocketFrames(session);
  const firstLoadedFrameIndex = frames.length ? normalizeWebsocketFrameIndex(frames[0]?.index) : null;
  const firstRetainedFrameIndex = websocketFirstRetainedFrameIndex(session, frames);
  if (
    firstLoadedFrameIndex == null
    || firstLoadedFrameIndex <= firstRetainedFrameIndex
    || session.older_frames_exhausted
  ) {
    session.older_frames_exhausted = true;
    renderWebsocketFrameTable();
    return;
  }

  const sessionId = currentSessionId();
  const generation = _websocketDetailGeneration;
  const shell = websocketFramesShell();
  const previousScrollHeight = shell?.scrollHeight || 0;
  const previousScrollTop = shell?.scrollTop || 0;
  const newestAnchorFrameIndexes = newestWebsocketFrameIndexes(frames, WEBSOCKET_DETAIL_FRAME_LIMIT);
  session.older_frames_loading = true;
  renderWebsocketFrameTable();

  try {
    const response = await fetch(websocketDetailRequestPath(id, sessionId, {
      beforeIndex: firstLoadedFrameIndex,
    }));
    if (
      generation !== _websocketDetailGeneration
      || sessionId !== currentSessionId()
      || state.selectedWebsocketId !== id
    ) {
      return;
    }
    if (!response.ok) {
      throw new Error(await response.text().catch(() => "Failed to load older WebSocket frames."));
    }
    const detail = await response.json();
    const incomingFrames = normalizeWebsocketFrames(detail.frames)
      .filter((frame) => frame.index < firstLoadedFrameIndex);
    const current = state.selectedWebsocketRecord;
    if (!current || current.id !== id) {
      return;
    }
    current.frames = mergeWebsocketFrameWindows(current.frames, incomingFrames, {
      prefer: "older",
      preserveIndexes: [
        state.selectedFrameIdx,
        ...newestAnchorFrameIndexes,
      ],
    });
    const mergedFrames = getWebsocketFrames(current);
    const nextFirstFrameIndex = mergedFrames.length
      ? normalizeWebsocketFrameIndex(mergedFrames[0]?.index)
      : null;
    current.loaded_first_frame_index = nextFirstFrameIndex;
    current.loaded_last_frame_index = mergedFrames.length
      ? normalizeWebsocketFrameIndex(mergedFrames[mergedFrames.length - 1]?.index)
      : null;
    const nextFirstRetainedFrameIndex = websocketFirstRetainedFrameIndex(current, mergedFrames);
    current.retained_first_frame_index = nextFirstRetainedFrameIndex;
    current.older_frames_exhausted = incomingFrames.length < WEBSOCKET_DETAIL_FRAME_LIMIT
      || nextFirstFrameIndex == null
      || nextFirstFrameIndex <= nextFirstRetainedFrameIndex;
    current.frames_truncated = websocketFramesAreTruncated(current.frames, current);
    current.older_frames_loading = false;
    renderWebsocketSessions();
    if (shell) {
      const nextScrollHeight = shell.scrollHeight || 0;
      shell.scrollTop = previousScrollTop + Math.max(0, nextScrollHeight - previousScrollHeight);
    }
  } catch (error) {
    const current = state.selectedWebsocketRecord;
    if (current?.id === id) {
      current.older_frames_loading = false;
      renderWebsocketFrameTable();
    }
    console.error("Failed to load older WebSocket frames:", error);
    showToast(error?.message || "Failed to load older WebSocket frames.", "error");
  }
}

function applySelectedWebsocketSummary(summary) {
  const selectedChanged = state.selectedWebsocketId === summary?.id;
  if (!selectedChanged) return false;
  if (state.selectedWebsocketRecord) {
    const loadedLastFrameIndex = state.selectedWebsocketRecord.loaded_last_frame_index ?? null;
    state.selectedWebsocketRecord = {
      ...state.selectedWebsocketRecord,
      status: summary.status,
      closed_at: summary.closed_at,
      duration_ms: summary.duration_ms,
      frame_count: summary.frame_count,
      retained_frame_count: summary.retained_frame_count,
      last_frame_index: summary.last_frame_index,
      retained_first_frame_index: websocketFirstRetainedFrameIndex(summary, state.selectedWebsocketRecord.frames),
      note_count: summary.note_count,
      frames_truncated: websocketFramesAreTruncated(state.selectedWebsocketRecord.frames, summary),
    };
    if (Number(loadedLastFrameIndex ?? -1) !== Number(summary.last_frame_index ?? -1)) {
      scheduleSelectedWebsocketDetailRefresh(summary.id, summary.last_frame_index);
    }
  } else {
    scheduleSelectedWebsocketDetailRefresh(summary.id, summary.last_frame_index);
  }
  return true;
}

function pruneWebsocketSummaryMutationCache() {
  if (!_websocketSummaryMutationById.size) {
    return;
  }
  const visibleIds = new Set((state.websocketSessions || []).map((item) => item?.id).filter(Boolean));
  for (const id of _websocketSummaryMutationById.keys()) {
    if (!visibleIds.has(id)) {
      _websocketSummaryMutationById.delete(id);
    }
  }
}

function scheduleSelectedWebsocketDetailRefresh(id, lastFrameIndex = null) {
  if (id !== state.selectedWebsocketId) {
    return;
  }
  _websocketDetailRefreshNeeded = mergeWebsocketDetailRefreshTarget(id, lastFrameIndex);
  if (_websocketDetailRefreshTimer) {
    return;
  }
  _websocketDetailRefreshTimer = window.setTimeout(() => {
    _websocketDetailRefreshTimer = null;
    const refreshTarget = _websocketDetailRefreshNeeded;
    const refreshId = refreshTarget?.id || null;
    if (
      refreshId
      && refreshId === state.selectedWebsocketId
      && state.activeTool === "proxy"
      && state.activeProxyTab === "websockets-history"
    ) {
      loadWebsocketDetail(refreshId, {
        force: true,
        lastFrameIndex: refreshTarget.lastFrameIndex,
      }).catch((error) => console.error(error));
    }
  }, 750);
}

function scheduleVisibleWebsocketSelectionSync(options = {}) {
  if (!isWebsocketHistoryVisible()) {
    return;
  }
  _websocketVisibleSyncEnsureSelected =
    _websocketVisibleSyncEnsureSelected || options.ensureSelectedVisible === true;
  _websocketVisibleSyncDeferStaleDetail =
    _websocketVisibleSyncDeferStaleDetail || options.deferStaleDetail === true;
  if (_websocketVisibleSyncTimer) {
    return;
  }
  _websocketVisibleSyncTimer = window.setTimeout(() => {
    _websocketVisibleSyncTimer = null;
    const ensureSelectedVisible =
      _websocketVisibleSyncEnsureSelected || Boolean(state.selectedWebsocketId);
    const deferStaleDetail = _websocketVisibleSyncDeferStaleDetail;
    _websocketVisibleSyncEnsureSelected = false;
    _websocketVisibleSyncDeferStaleDetail = false;
    if (!isWebsocketHistoryVisible()) {
      return;
    }
    syncVisibleWebsocketSelection(true, {
      ensureSelectedVisible,
      deferStaleDetail,
    }).catch((error) => console.error(error));
  }, 100);
}

async function loadEventLog() {
  const sessionId = currentSessionId();
  const mutationGeneration = _eventLogMutationGeneration;
  const clearGeneration = _eventLogClearGeneration;
  const response = await fetch(sessionQueryPath(`/api/event-log?limit=${EVENT_LOG_LIMIT}`, sessionId));
  await requireOkResponse(response, "Failed to load event log.");
  const entries = jsonArray(await response.json());
  if (sessionId !== currentSessionId()) {
    return;
  }
  if (clearGeneration !== _eventLogClearGeneration) {
    return;
  }
  state.eventLog = mutationGeneration === _eventLogMutationGeneration
    ? entries.slice(0, EVENT_LOG_LIMIT)
    : mergeEventLogEntries(state.eventLog, entries);
  renderEventLog();
}

function applyEventLogEvent(event) {
  try {
    return applyEventLogEntry(JSON.parse(event.data || "{}"));
  } catch (error) {
    console.error("Failed to parse event log SSE:", error);
    return false;
  }
}

function applyEventLogEntry(entry) {
  if (!entry || typeof entry !== "object" || !entry.id) {
    return false;
  }
  _eventLogMutationGeneration += 1;
  state.eventLog = mergeEventLogEntries([entry], state.eventLog);
  renderEventLog();
  return true;
}

function mergeEventLogEntries(primaryEntries, fallbackEntries) {
  const seen = new Set();
  const merged = [];
  for (const entry of [...jsonArray(primaryEntries), ...jsonArray(fallbackEntries)]) {
    if (!entry?.id || seen.has(entry.id)) {
      continue;
    }
    seen.add(entry.id);
    merged.push(entry);
    if (merged.length >= EVENT_LOG_LIMIT) {
      break;
    }
  }
  return merged;
}

async function clearEventLog() {
  const sessionId = currentSessionId();
  const response = await fetch(sessionWritePath("/api/event-log", sessionId), { method: "DELETE" });
  await requireOkResponse(response, "Failed to clear event log.");
  if (sessionId !== currentSessionId()) {
    return;
  }
  _eventLogMutationGeneration += 1;
  _eventLogClearGeneration += 1;
  state.eventLog = [];
  renderEventLog();
}

async function loadMatchReplaceRules() {
  const sessionId = currentSessionId();
  if (state.matchReplaceDirty && state.matchReplaceEditorSessionId === sessionId) {
    return;
  }
  const response = await fetch(sessionQueryPath("/api/match-replace", sessionId));
  await requireOkResponse(response, "Failed to load match-replace rules.");
  const rules = jsonArray(await response.json());
  if (sessionId !== currentSessionId()) {
    return;
  }
  if (state.matchReplaceDirty && state.matchReplaceEditorSessionId === sessionId) {
    return;
  }
  state.matchReplaceRules = rules;
  if (!state.matchReplaceRules.some((rule) => rule.id === state.selectedMatchReplaceRuleId)) {
    state.selectedMatchReplaceRuleId = state.matchReplaceRules[0]?.id ?? null;
  }
  state.matchReplaceDirty = false;
  state.matchReplaceEditorSessionId = sessionId;
  renderMatchReplaceRules();
}

async function saveMatchReplaceRules(options = {}) {
  const sessionId = options.sessionId || currentSessionId();
  if (!sessionId) {
    return;
  }
  if (
    state.matchReplaceDirty
    && state.matchReplaceEditorSessionId
    && state.matchReplaceEditorSessionId !== sessionId
  ) {
    throw new Error("Match/Replace editor changed sessions. Review the rule and save again.");
  }
  const response = await fetch(sessionWritePath("/api/match-replace", sessionId, options), {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({ session_id: sessionId, rules: state.matchReplaceRules }),
  });
  await requireOkResponse(response, "Failed to save match-replace rules.");
  const rules = jsonArray(await response.json());
  if (sessionId !== currentSessionId()) {
    if (state.matchReplaceEditorSessionId === sessionId) {
      state.matchReplaceDirty = false;
      state.matchReplaceEditorSessionId = null;
    }
    return;
  }
  state.matchReplaceRules = rules;
  if (!state.matchReplaceRules.some((rule) => rule.id === state.selectedMatchReplaceRuleId)) {
    state.selectedMatchReplaceRuleId = state.matchReplaceRules[0]?.id ?? null;
  }
  state.matchReplaceDirty = false;
  state.matchReplaceEditorSessionId = sessionId;
  renderMatchReplaceRules();
}

async function flushMatchReplaceDraft(options = {}) {
  if (!state.matchReplaceDirty) {
    return true;
  }
  try {
    await saveMatchReplaceRules(options);
    return true;
  } catch (error) {
    console.error(error);
    showToast(error?.message || "Failed to save match-replace rule", "error");
    return false;
  }
}

function formatScopePatternsText(patterns) {
  return (patterns || []).join("\n");
}

function syncTargetScopeDraft(force = false) {
  const runtimeText = formatScopePatternsText(state.runtime?.scope_patterns);
  if (force || !state.targetScopeDirty) {
    state.targetScopeDraft = runtimeText;
    state.targetScopeDirty = false;
    if (force) {
      state.targetScopeEditorSessionId = null;
    }
  }
}

async function flushTargetScopeDraft(options = {}) {
  if (!state.targetScopeDirty) {
    return true;
  }
  try {
    await saveTargetScope({
      ...options,
      skipReload: true,
    });
    return true;
  } catch (error) {
    console.error(error);
    showToast(error?.message || "Failed to save scope", "error");
    return false;
  }
}

async function reloadTargetSiteMapFromButton() {
  if (!(await flushTargetScopeDraft())) {
    return;
  }
  await loadTargetSiteMap(true);
}

async function loadTargetSiteMap(forceScopeSync = false) {
  const sessionId = currentSessionId();
  const [runtimeResponse, siteMapResponse] = await Promise.all([
    fetch(sessionQueryPath("/api/runtime", sessionId)),
    fetch(sessionQueryPath("/api/target/site-map", sessionId)),
  ]);
  await requireOkResponse(runtimeResponse, "Failed to load runtime settings.");
  await requireOkResponse(siteMapResponse, "Failed to load target site map.");
  const runtime = await runtimeResponse.json();
  const siteMap = jsonArray(await siteMapResponse.json());
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.runtime = runtime;
  state.targetSiteMap = siteMap;
  syncTargetScopeDraft(forceScopeSync);
  renderInterceptStatus();
  renderProxySettings();
  renderTarget();
}

async function pollAuxiliaryData() {
  const tasks = [];
  const now = Date.now();

  if (state.activeTool === "proxy" && state.activeProxyTab === "intercept") {
    tasks.push(loadIntercepts(true));
    tasks.push(loadResponseIntercepts(true));
  }

  if (isWebsocketHistoryVisible()) {
    if (now - _lastWebsocketFallbackPoll >= WEBSOCKET_POLL_FALLBACK_MS) {
      _lastWebsocketFallbackPoll = now;
      tasks.push(loadWebsocketsPageRefresh(true));
    }
  }

  if (state.activeTool === "proxy" && state.activeProxyTab === "http-history") {
    if (now - _lastHttpHistoryFallbackPoll >= HTTP_HISTORY_POLL_FALLBACK_MS) {
      _lastHttpHistoryFallbackPoll = now;
      scheduleIncrementalRefresh();
    }
  }

  if (state.activeTool === "logger") {
    tasks.push(loadEventLog());
  }

  if (state.activeTool === "target") {
    tasks.push(loadTargetSiteMap());
  }

  if (state.activeTool === "proxy" && state.activeProxyTab === "findings") {
    tasks.push(loadFindings());
  } else if (shouldPollFindingsBadge(now)) {
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
  const eventSessionId = currentSessionId();
  eventSource = new EventSource(sessionQueryPath("/api/events", eventSessionId));
  let openedOnce = false;

  eventSource.onopen = () => {
    els.liveStatus.textContent = "Proxy live";
    els.liveStatus.classList.add("online");
    if (!openedOnce) {
      openedOnce = true;
      return;
    }
    if (eventSessionId !== currentSessionId()) {
      return;
    }
    _lastWebsocketFallbackPoll = Date.now();
    if (isWebsocketHistoryVisible()) {
      loadWebsocketsPageRefresh(true).catch((error) => console.error(error));
    } else {
      state.websocketHistoryDirty = true;
    }
  };

  eventSource.addEventListener("transaction", (event) => {
    if (eventSessionId !== currentSessionId()) {
      return;
    }
    _lastHttpHistoryFallbackPoll = Date.now();
    els.liveStatus.textContent = "Proxy live";
    els.liveStatus.classList.add("online");
    if (!applyTransactionDeltaEvent(event, eventSessionId)) {
      scheduleIncrementalRefresh();
    }
  });

  eventSource.addEventListener("transactions_gap", () => {
    if (eventSessionId !== currentSessionId()) {
      return;
    }
    scheduleRefresh();
  });

  eventSource.addEventListener("event_log", (event) => {
    if (eventSessionId !== currentSessionId()) {
      return;
    }
    if (state.activeTool === "logger") {
      if (!applyEventLogEvent(event)) {
        loadEventLog().catch((error) => console.error(error));
      }
    } else {
      els.eventLogStatus.textContent = "New activity";
    }
  });

  eventSource.addEventListener("event_log_gap", () => {
    if (eventSessionId !== currentSessionId()) {
      return;
    }
    loadEventLog().catch((error) => console.error(error));
  });

  eventSource.addEventListener("finding", (event) => {
    if (eventSessionId !== currentSessionId()) {
      return;
    }
    handleFindingEvent(event);
  });

  eventSource.addEventListener("findings_gap", () => {
    if (eventSessionId !== currentSessionId()) {
      return;
    }
    if (state.activeTool === "proxy" && state.activeProxyTab === "findings") {
      scheduleFindingsListRefresh();
    } else {
      scheduleFindingsBadgeRefresh();
    }
  });

  eventSource.addEventListener("websocket", (event) => {
    if (eventSessionId !== currentSessionId()) {
      return;
    }
    _lastWebsocketFallbackPoll = Date.now();
    queueWebsocketSummaryEvent(event);
  });

  eventSource.addEventListener("websockets_gap", () => {
    if (eventSessionId !== currentSessionId()) {
      return;
    }
    _lastWebsocketFallbackPoll = Date.now();
    if (isWebsocketHistoryVisible()) {
      loadWebsocketsPageRefresh(true).catch((error) => console.error(error));
    } else {
      state.websocketHistoryDirty = true;
    }
  });

  eventSource.addEventListener("session_changed", () => {
    handleExternalSessionChanged(eventSessionId).catch((error) => console.error(error));
  });

  eventSource.addEventListener("workspace_state", (event) => {
    let payload = null;
    try {
      payload = JSON.parse(event.data);
    } catch {
      return;
    }
    // Skip the echo of our own save; only another client's write is news.
    if (!payload || payload.client_id === workspaceClientId) return;
    adoptExternalReplayTabs().catch((error) => console.error(error));
  });

  eventSource.onerror = () => {
    els.liveStatus.textContent = "Retrying";
    els.liveStatus.classList.remove("online");
  };
}

function resetHistoryScrollPosition() {
  const shell = els.historyTable?.closest(".history-table-shell");
  if (shell) {
    shell.scrollTop = 0;
  }
}

function consumeHistoryLoadOptions() {
  const resetScroll = !!state.historyResetScrollOnNextLoad;
  state.historyResetScrollOnNextLoad = false;
  return { resetScroll };
}

function scheduleRefresh(options = {}) {
  invalidateVisibleEntriesCache();
  state.historyDirty = true;
  if (!isHttpHistoryVisible()) {
    if (options.resetScroll) {
      state.historyResetScrollOnNextLoad = true;
    }
    return;
  }
  if (options.resetScroll) {
    state.historyResetScrollOnNextLoad = true;
  }
  if (refreshTimer) {
    return;
  }
  refreshTimer = window.setTimeout(() => {
    refreshTimer = null;
    loadTransactions(true, consumeHistoryLoadOptions()).catch((error) => console.error(error));
  }, 160);
}

function clearHttpHistorySelectionPreview() {
  if (!state.selectedId && !state.selectedRecord) {
    return;
  }
  state.selectedId = null;
  state.selectedRecord = null;
  updateHistorySelection(null);
  renderEmptyDetail();
}

function clearHttpHistoryLoadedRowsForPendingQuery() {
  state.items = [];
  state._itemsVersion += 1;
  state._historyEntries = [];
  state._connectCount = 0;
  invalidateVisibleEntriesCache();
  clearHttpHistorySelectionPreview();
  renderHistory();
}

function mergeHistoryItems(items, { prepend = false } = {}) {
  applyPendingAnnotationsToItems(items);
  const newItems = [];
  const seen = new Set();
  let connectCount = 0;
  for (const item of items) {
    if (!item?.id || seen.has(item.id) || getHistoryItem(item.id)) continue;
    seen.add(item.id);
    prepareHistoryItem(item);
    if (item.method === "CONNECT") connectCount++;
    newItems.push(item);
  }
  if (!newItems.length) return 0;

  if (prepend) {
    state.items = newItems.concat(state.items);
  } else {
    state.items.push(...newItems);
  }
  state._connectCount = (state._connectCount || 0) + connectCount;
  if (state.historyPaging) {
    state.historyPaging._trimmedTailOnLastMerge = false;
  }
  trimHistoryCache(prepend ? "recent" : "older");
  rebuildHistoryItemIndex();
  state._itemsVersion += 1;
  invalidateVisibleEntriesCache();
  return newItems.length;
}

function replaceHistoryItemsForGap(items) {
  applyPendingAnnotationsToItems(items);
  const seen = new Set();
  const freshItems = [];
  let connectCount = 0;
  for (const item of items) {
    if (!item?.id || seen.has(item.id)) continue;
    seen.add(item.id);
    prepareHistoryItem(item);
    if (item.method === "CONNECT") connectCount++;
    freshItems.push(item);
  }

  state.items = freshItems;
  state._connectCount = connectCount;
  rebuildHistoryItemIndex();
  state._itemsVersion += 1;
  invalidateVisibleEntriesCache();
  moveHistorySelectionIfMissing("first");
  refreshHistoryPagingCursorFromItems();
  return freshItems.length;
}

function trimHistoryCache(prefer = "recent") {
  const overflow = state.items.length - HTTP_HISTORY_MAX_LOADED_ITEMS;
  if (overflow <= 0) {
    refreshHistoryPagingCursorFromItems();
    return 0;
  }

  let removed;
  if (prefer === "older") {
    removed = state.items.splice(0, overflow);
    state.historyPaging.trimmedHeadCount += removed.length;
    adjustHistoryScrollAfterHeadTrim(removed.length);
  } else {
    removed = state.items.splice(state.items.length - overflow, overflow);
    state.historyPaging.trimmedTailCount += removed.length;
    state.historyPaging._trimmedTailOnLastMerge = true;
    state.historyPaging.hasMore = true;
    state.historyPaging.fullyLoaded = false;
  }

  state._connectCount = state.items.reduce((count, item) => count + (item.method === "CONNECT" ? 1 : 0), 0);
  reconcileHistorySelectionAfterTrim(removed, prefer === "older" ? "first" : "last");
  refreshHistoryPagingCursorFromItems();
  return removed.length;
}

function reconcileHistorySelectionAfterTrim(removedItems = [], fallback = "first") {
  if (!state.selectedId || !removedItems.some((item) => item?.id === state.selectedId)) {
    return;
  }
  moveHistorySelectionIfMissing(fallback);
}

function moveHistorySelectionIfMissing(fallback = "first") {
  if (!state.selectedId || getHistoryItem(state.selectedId)) {
    return false;
  }
  const nextItem = fallback === "last"
    ? state.items[state.items.length - 1]
    : state.items[0];
  selectHistoryTransaction(nextItem?.id ?? null).catch((error) => console.error(error));
  return true;
}

function adjustHistoryScrollAfterHeadTrim(removedCount) {
  const shell = els.historyTable?.closest(".history-table-shell");
  if (!shell || removedCount <= 0) return;
  shell.scrollTop = Math.max(0, shell.scrollTop - removedCount * (measuredHistoryRowHeight || HISTORY_ROW_HEIGHT));
}

async function loadMoreTransactions({ background = false } = {}) {
  const paging = state.historyPaging || (state.historyPaging = createHistoryPagingState());
  if (paging.loading || !paging.hasMore) {
    return 0;
  }
  const queryState = createHistoryQueryState();
  const querySignature = historyQuerySignature(queryState);
  if (paging.querySignature && paging.querySignature !== querySignature) {
    return 0;
  }
  paging.querySignature = querySignature;

  let shouldRenderAfterLoad = !background;
  let shouldBackfillAfterLoad = false;
  const generation = paging.generation;
  const offset = paging.offset ?? state.items.length;
  paging.loading = true;
  if (!background) renderHistory();
  try {
    const page = paging.beforeSequence == null
      ? await fetchTransactionPage({ offset, queryState, querySignature })
      : await fetchTransactionPage({ beforeSequence: paging.beforeSequence, queryState, querySignature });
    if (!page) {
      return 0;
    }
    if (
      state.historyPaging !== paging
      || state.historyPaging.generation !== generation
      || state.historyPaging.querySignature !== querySignature
      || !isCurrentHistoryQuerySignature(querySignature)
    ) {
      return 0;
    }
    const pageItems = jsonArray(page.items);
    updateHistoryPagingCursor(pageItems);
    const added = mergeHistoryItems(pageItems);
    const hadMore = paging.hasMore;
    paging.offset = canUseSequenceCursorForHistoryPaging()
      ? state.items.length
      : offset + pageItems.length;
    paging.total = page.total ?? paging.total;
    paging.filteredTotal = page.filtered_total ?? paging.filteredTotal;
    if (page.hidden_connect_total != null) paging.hiddenConnectTotal = page.hidden_connect_total;
    paging.hasMore = Boolean(page.has_more);
    paging.fullyLoaded = !paging.hasMore;
    if (added || hadMore !== paging.hasMore || !background) {
      shouldRenderAfterLoad = true;
    }
    shouldBackfillAfterLoad = background && !added && paging.hasMore;
    return added;
  } catch (error) {
    console.error("Failed to load older transactions:", error);
    return 0;
  } finally {
    if (state.historyPaging === paging && paging.querySignature === querySignature) {
      paging.loading = false;
      if (shouldRenderAfterLoad && isCurrentHistoryQuerySignature(querySignature)) renderHistory();
      if (shouldBackfillAfterLoad && isCurrentHistoryQuerySignature(querySignature)) scheduleHistoryBackfill();
    }
  }
}

async function loadNewerTransactions({ background = false } = {}) {
  const paging = state.historyPaging || (state.historyPaging = createHistoryPagingState());
  if (paging.loading || paging.trimmedHeadCount <= 0) {
    return 0;
  }
  const queryState = createHistoryQueryState();
  const querySignature = historyQuerySignature(queryState);
  if (paging.querySignature && paging.querySignature !== querySignature) {
    return 0;
  }
  paging.querySignature = querySignature;

  let shouldRenderAfterLoad = !background;
  const generation = paging.generation;
  const newerOffset = Math.max(0, paging.trimmedHeadCount - paging.pageSize);
  const usesSequenceCursor = canUseSequenceCursorForHistoryPaging();
  paging.loading = true;
  if (!background) renderHistory();
  try {
    const page = await fetchTransactionPage({ offset: newerOffset, queryState, querySignature });
    if (!page) {
      return 0;
    }
    if (
      state.historyPaging !== paging
      || state.historyPaging.generation !== generation
      || state.historyPaging.querySignature !== querySignature
      || !isCurrentHistoryQuerySignature(querySignature)
    ) {
      return 0;
    }
    const pageItems = jsonArray(page.items);
    const added = mergeHistoryItems(pageItems, { prepend: true });
    if (usesSequenceCursor) {
      paging.trimmedHeadCount = Math.max(0, paging.trimmedHeadCount - pageItems.length);
      paging.offset = state.items.length;
    } else {
      paging.trimmedHeadCount = newerOffset;
      paging.offset = paging.trimmedHeadCount + state.items.length;
    }
    paging.total = page.total ?? paging.total;
    paging.filteredTotal = page.filtered_total ?? paging.filteredTotal;
    if (page.hidden_connect_total != null) paging.hiddenConnectTotal = page.hidden_connect_total;
    paging.hasMore = Boolean(page.has_more) || paging.trimmedTailCount > 0;
    paging.fullyLoaded = !paging.hasMore;
    if (added || !background) {
      shouldRenderAfterLoad = true;
    }
    return added;
  } catch (error) {
    console.error("Failed to load newer transactions:", error);
    return 0;
  } finally {
    if (state.historyPaging === paging && paging.querySignature === querySignature) {
      paging.loading = false;
      if (shouldRenderAfterLoad && isCurrentHistoryQuerySignature(querySignature)) renderHistory();
    }
  }
}

let _historyBackfillTimer = 0;
function scheduleHistoryBackfill(delayMs = HTTP_HISTORY_BACKFILL_DELAY_MS, options = {}) {
  const paging = state.historyPaging;
  if (!paging || paging.loading || paging.backfillScheduled || !paging.hasMore || paging.fullyLoaded) {
    return;
  }
  const allowAtCap = !!options.allowAtCap;
  if (!allowAtCap && state.items.length >= HTTP_HISTORY_MAX_LOADED_ITEMS) {
    return;
  }
  if (!paging.querySignature) {
    paging.querySignature = historyQuerySignature();
  }
  paging.backfillScheduled = true;
  const generation = paging.generation;
  const querySignature = paging.querySignature;
  _historyBackfillTimer = window.setTimeout(async () => {
    _historyBackfillTimer = 0;
    const currentPaging = state.historyPaging;
    if (!currentPaging) return;
    if (currentPaging.generation !== generation || currentPaging.querySignature !== querySignature) return;
    currentPaging.backfillScheduled = false;
    if (!isCurrentHistoryQuerySignature(querySignature)) return;
    if (_searchActiveUntil > Date.now()) {
      scheduleHistoryBackfill(HTTP_HISTORY_BACKFILL_DELAY_MS, { allowAtCap });
      return;
    }
    await loadMoreTransactions({ background: true });
  }, delayMs);
}

function clearHistoryBackfill() {
  if (_historyBackfillTimer) {
    clearTimeout(_historyBackfillTimer);
    _historyBackfillTimer = 0;
  }
  if (state.historyPaging) {
    state.historyPaging.backfillScheduled = false;
  }
}

function canMergeRecentTransactions() {
  const filters = state.filterSettings || {};
  return state.sortKey === "index"
    && state.sortDirection === "desc"
    && !(filters.searchTerm && filters.regex);
}

function canUseSequenceCursorForHistoryPaging() {
  return state.sortKey === "index" && state.sortDirection === "desc";
}

function isHttpHistoryVisible() {
  return state.activeTool === "proxy" && state.activeProxyTab === "http-history";
}

function isWebsocketHistoryVisible() {
  return state.activeTool === "proxy" && state.activeProxyTab === "websockets-history";
}

/** Incremental refresh: fetch only recent transactions and merge into cache. */
let _incrementalTimer = 0;
let _transactionDeltaTimer = 0;
let _historyFullLoadInFlight = 0;
const _pendingTransactionSummaries = [];

function applyTransactionDeltaEvent(event, sessionId = currentSessionId()) {
  if (sessionId !== currentSessionId()) {
    return true;
  }
  if (!isHttpHistoryVisible()) {
    state.historyDirty = true;
    return true;
  }
  if (!canMergeRecentTransactions() || _searchActiveUntil > Date.now()) {
    return false;
  }

  try {
    const summary = JSON.parse(event.data || "null");
    if (!summary || !summary.id) return false;
    _pendingTransactionSummaries.push({ sessionId, summary });
    scheduleTransactionDeltaFlush();
    return true;
  } catch (error) {
    console.error("Failed to parse transaction event:", error);
    return false;
  }
}

function scheduleTransactionDeltaFlush() {
  if (_transactionDeltaTimer) return;
  _transactionDeltaTimer = window.setTimeout(() => {
    _transactionDeltaTimer = 0;
    flushTransactionDeltas();
  }, 120);
}

function flushTransactionDeltas() {
  if (!_pendingTransactionSummaries.length) return;
  const activeSessionId = currentSessionId();
  for (let i = _pendingTransactionSummaries.length - 1; i >= 0; i -= 1) {
    if (_pendingTransactionSummaries[i]?.sessionId !== activeSessionId) {
      _pendingTransactionSummaries.splice(i, 1);
    }
  }
  if (!_pendingTransactionSummaries.length) return;
  if (_historyFullLoadInFlight) {
    scheduleTransactionDeltaFlush();
    return;
  }
  const pending = _pendingTransactionSummaries.splice(0);
  if (!isHttpHistoryVisible()) {
    state.historyDirty = true;
    return;
  }
  if (!canMergeRecentTransactions() || _searchActiveUntil > Date.now()) {
    scheduleIncrementalRefresh();
    return;
  }

  const fresh = [];
  const seenIds = new Set();
  let totalAdded = 0;
  let hiddenConnectAdded = 0;
  for (const { summary } of pending) {
    if (!summary?.id || seenIds.has(summary.id) || getHistoryItem(summary.id)) continue;
    seenIds.add(summary.id);
    totalAdded += 1;
    if (String(summary.method || "").toUpperCase() === "CONNECT") {
      if (summaryMatchesActiveHistoryFilters(summary, { includeConnect: true })) hiddenConnectAdded += 1;
      continue;
    }
    if (!summaryMatchesActiveHistoryFilters(summary)) continue;
    fresh.push(summary);
  }

  if (fresh.length && state.historyPaging?.trimmedHeadCount > 0 && canUseSequenceCursorForHistoryPaging()) {
    scheduleIncrementalRefresh();
    return;
  }

  fresh.sort((a, b) => Number(b.sequence ?? 0) - Number(a.sequence ?? 0));
  const added = mergeHistoryItems(fresh, { prepend: true });
  if (state.historyPaging) {
    state.historyPaging.total += totalAdded;
    if (isKnownCount(state.historyPaging.filteredTotal)) {
      state.historyPaging.filteredTotal += added;
    }
    if (isKnownCount(state.historyPaging.hiddenConnectTotal)) {
      state.historyPaging.hiddenConnectTotal += hiddenConnectAdded;
    }
    state.historyPaging.offset = state.items.length;
  }
  if (totalAdded || added) {
    state.historyDirty = false;
    renderHistory();
  }
}

function summaryMatchesActiveHistoryFilters(item, options = {}) {
  const method = String(item.method || "").toUpperCase();
  if (!options.includeConnect && method === "CONNECT") return false;
  if (state.method && String(item.method || "").toLowerCase() !== state.method.toLowerCase()) return false;

  const filters = state.filterSettings;
  if (filters.inScopeOnly && !isInScopeHost(item.host || "")) return false;
  if (filters.hideWithoutResponses && !item.has_response) return false;
  if (filters.onlyParameterized && !String(item.path || "").includes("?")) return false;
  if (filters.onlyNotes && !item.note_count && !item.has_user_note) return false;
  if (!summaryMatchesStatusFilter(item, filters)) return false;
  if (!summaryMatchesMimeFilter(item, filters)) return false;
  if (inferMimeType(item) !== "websocket" && !summaryMatchesHiddenExtensions(item, filters)) return false;
  if (!summaryMatchesPortFilter(item, filters)) return false;
  if (!summaryMatchesColorTags(item, filters)) return false;
  if (!summaryMatchesAdvancedSearch(item, filters)) return false;
  if (state.query && !summaryQuickSearchHaystack(item).includes(state.query.toLowerCase())) return false;
  return true;
}

function summaryMatchesStatusFilter(item, filters) {
  const selected = selectedStatusClasses(filters);
  if (!selected.length) return false;
  const status = Number(item.status);
  const statusClass = Number.isFinite(status) && status >= 200 && status < 300
    ? "success"
    : Number.isFinite(status) && status >= 300 && status < 400
      ? "redirect"
      : Number.isFinite(status) && status >= 400 && status < 500
        ? "client_error"
        : Number.isFinite(status) && status >= 500 && status < 600
          ? "server_error"
          : "other";
  return selected.includes(statusClass);
}

function summaryMatchesMimeFilter(item, filters) {
  const selected = selectedMimeTypes(filters);
  return selected.length > 0 && selected.includes(inferMimeType(item));
}

function summaryMatchesHiddenExtensions(item, filters) {
  const hidden = String(filters.hiddenExtensions || "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
  if (!hidden.length) return true;
  const extension = extractSummaryPathExtension(item.path || "");
  return !extension || !hidden.includes(extension);
}

function extractSummaryPathExtension(path) {
  const clean = String(path || "").split("?")[0];
  const index = clean.lastIndexOf(".");
  if (index < 0) return "";
  const extension = clean.slice(index + 1).toLowerCase();
  return /^[a-z0-9]+$/.test(extension) ? extension : "";
}

function summaryMatchesPortFilter(item, filters) {
  const expected = String(filters.port || "").trim();
  if (!expected) return true;
  return effectiveSummaryPort(item) === expected;
}

function effectiveSummaryPort(item) {
  return extractHostPort(item?.host || "") || defaultSummaryPortForScheme(item?.scheme || "");
}

function defaultSummaryPortForScheme(scheme) {
  switch (String(scheme || "").toLowerCase()) {
    case "http":
    case "ws":
      return "80";
    case "https":
    case "wss":
      return "443";
    default:
      return "";
  }
}

function summaryMatchesColorTags(item, filters) {
  const tags = filters.colorTags;
  if (!tags?.size) return true;
  return tags.has(item.color_tag || "");
}

function summaryMatchesAdvancedSearch(item, filters) {
  const term = String(filters.searchTerm || "").trim();
  if (!term) return true;
  const haystack = `${item.host || ""} ${item.method || ""} ${item.path || ""} ${item.content_type || ""}`;
  let matched = false;
  if (filters.regex) {
    try {
      matched = new RegExp(term, filters.caseSensitive ? "" : "i").test(haystack);
    } catch (_) {
      return !filters.negativeSearch;
    }
  } else {
    matched = filters.caseSensitive
      ? haystack.includes(term)
      : haystack.toLowerCase().includes(term.toLowerCase());
  }
  return filters.negativeSearch ? !matched : matched;
}

function summaryQuickSearchHaystack(item) {
  const totalBytes = (item.request_bytes ?? 0) + (item.response_bytes ?? 0);
  const startedAt = item.started_at || "";
  let formattedTime = "";
  try {
    formattedTime = startedAt ? formatTimestamp(startedAt) : "";
  } catch (_) {
    formattedTime = "";
  }
  return [
    item.id || "",
    item.sequence ?? "",
    item.method || "",
    item.host || "",
    item.path || "",
    item.status ?? "",
    item.content_type || "",
    inferMimeType(item),
    totalBytes,
    formatSize(totalBytes),
    startedAt,
    formattedTime,
  ].join(" ").toLowerCase();
}

function scheduleIncrementalRefresh() {
  if (_incrementalTimer) return;
  _incrementalTimer = window.setTimeout(async () => {
    _incrementalTimer = 0;
    // Skip incremental refresh while user is actively typing in search
    if (_searchActiveUntil > Date.now()) {
      // Reschedule a tick later instead of dropping
      scheduleIncrementalRefresh();
      return;
    }
    try {
      if (!canMergeRecentTransactions()) {
        scheduleRefresh();
        return;
      }
      const refreshQueryState = createHistoryQueryState();
      const refreshQuerySignature = historyQuerySignature(refreshQueryState);
      if (state.historyPaging?.querySignature && state.historyPaging.querySignature !== refreshQuerySignature) {
        scheduleRefresh();
        return;
      }
      const refreshSessionId = state.activeSession?.id || null;
      const resp = await fetch(buildTransactionsPageUrl({ limit: 50, offset: 0, queryState: refreshQueryState }));
      if (
        refreshSessionId !== (state.activeSession?.id || null)
        || !isCurrentHistoryQuerySignature(refreshQuerySignature)
      ) {
        return;
      }
      if (!resp.ok) {
        const message = await resp.text().catch(() => "");
        if (!isCurrentHistoryQuerySignature(refreshQuerySignature)) {
          return;
        }
        if (els.historyMeta) els.historyMeta.textContent = `HTTP History refresh error: ${message || resp.status}`;
        if (els.liveStatus) {
          els.liveStatus.textContent = "Refresh error";
          els.liveStatus.classList.remove("online");
        }
        throw new Error(message || `HTTP History refresh failed: ${resp.status}`);
      }
      const page = await resp.json();
      if (
        refreshSessionId !== (state.activeSession?.id || null)
        || !isCurrentHistoryQuerySignature(refreshQuerySignature)
        || state.historyPaging?.querySignature !== refreshQuerySignature
      ) {
        return;
      }
      const recent = jsonArray(page.items);
      const previousTotal = state.historyPaging?.total;
      const previousFilteredTotal = state.historyPaging?.filteredTotal;
      const previousHasMore = state.historyPaging?.hasMore;
      const wasFullyLoaded = state.historyPaging?.fullyLoaded === true;
      const hasOverlap = recent.some((item) => item?.id && getHistoryItem(item.id));
      const hasGapBeforeLoadedWindow = Boolean(page.has_more)
        && state.items.length > 0
        && recent.length > 0
        && !hasOverlap
        && canUseSequenceCursorForHistoryPaging();
      if (state.historyPaging) {
        state.historyPaging._trimmedTailOnLastMerge = false;
      }
      const added = hasGapBeforeLoadedWindow
        ? replaceHistoryItemsForGap(recent)
        : mergeHistoryItems(recent, { prepend: true });
      if (state.historyPaging) {
        if (page.total != null) state.historyPaging.total = page.total;
        if (page.filtered_total != null) state.historyPaging.filteredTotal = page.filtered_total;
        if (page.hidden_connect_total != null) state.historyPaging.hiddenConnectTotal = page.hidden_connect_total;
        state.historyPaging.hasMore = wasFullyLoaded
          && !hasGapBeforeLoadedWindow
          && !state.historyPaging._trimmedTailOnLastMerge
          ? false
          : Boolean(page.has_more) || state.historyPaging._trimmedTailOnLastMerge;
        state.historyPaging.fullyLoaded = !state.historyPaging.hasMore;
      }
      if (added > 0 && state.historyPaging) state.historyPaging.offset = state.items.length;
      if (hasGapBeforeLoadedWindow) {
        scheduleHistoryBackfill(0);
      }
      if (
        added > 0
        || previousTotal !== state.historyPaging?.total
        || previousFilteredTotal !== state.historyPaging?.filteredTotal
        || previousHasMore !== state.historyPaging?.hasMore
      ) {
        renderHistory();
      }
    } catch (err) {
      console.error("Incremental refresh failed:", err);
    }
  }, 300);
}

// Search activity guard: incremental refresh pauses while user is typing
let _searchActiveUntil = 0;

function renderToolPanels() {
  state.activeTool = sanitizeActiveTool(state.activeTool);

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
      activateSessionById(id).catch(handleWorkspaceActionError);
    });
  });

  // Right-click context menu on session rows
  Array.from(els.dashboardSessionsBody.querySelectorAll("tr[data-id]")).forEach((row) => {
    row.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      event.stopPropagation();
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
      revealSessionFolder(sessionId).catch((error) => {
        console.error(error);
        showToast(error?.message || "Failed to open session folder.", "error");
      });
    } else if (action === "delete") {
      deleteSessionById(sessionId);
    }
    closeSessionContextMenu();
  });
}

async function revealSessionFolder(sessionId) {
  const response = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/reveal`, {
    method: "POST",
  });
  await requireOkResponse(response, "Failed to open session folder.");
  const result = await response.json().catch(() => null);
  showToast(result?.path ? `Opened ${result.path}` : "Session folder opened.");
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
      showToast(error?.message || "Failed to delete session.", "error");
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
let findingsBadgeCount = 0;
let findingsLoadPromise = null;
let findingsLoadSessionId = null;
let findingsStateGeneration = 0;
let findingsLoadGeneration = 0;
let findingsBadgeRefreshTimer = 0;
let findingsListRefreshTimer = 0;
let lastFindingsBadgePollAt = 0;
let scannerConfigCache = null;
let scannerSettingsSessionId = null;
let findingsSortKey = "found_at";
let findingsSortDir = "desc";
const FINDINGS_LIST_LIMIT = 5000;

const BUILTIN_RULE_LABELS = {
  jwt: "JWT Analysis",
  header: "Security Headers",
  cookie: "Cookie Flags",
  disclosure: "Sensitive Data Exposure",
  cors: "CORS Misconfiguration",
  server: "Server Disclosure",
  error: "Error Messages",
  misconfig: "Security Misconfiguration",
  info: "Information Disclosure",
  auth: "Authentication Issues",
};

const BUILTIN_FINDING_CATEGORIES = new Set(Object.keys(BUILTIN_RULE_LABELS));

let selectedFindingId = null;

async function loadFindings() {
  const sessionId = currentSessionId();
  if (findingsLoadPromise && findingsLoadSessionId === sessionId) {
    return findingsLoadPromise;
  }
  const stateGeneration = findingsStateGeneration;
  const loadGeneration = ++findingsLoadGeneration;
  findingsLoadSessionId = sessionId;
  let loadPromise;
  loadPromise = (async () => {
    try {
      const countPromise = fetchFindingsCount(sessionId).catch(() => null);
      const response = await fetch(sessionQueryPath(`/api/findings?limit=${FINDINGS_LIST_LIMIT}`, sessionId));
      if (!response.ok) return;
      const findings = jsonArray(await response.json());
      const fullCount = await countPromise;
      if (
        sessionId !== currentSessionId()
        || stateGeneration !== findingsStateGeneration
        || loadGeneration !== findingsLoadGeneration
      ) {
        return;
      }
      findingsData = findings;
      findingsBadgeCount = fullCount == null ? findings.length : Math.max(fullCount, findings.length);
      renderFindings();
      updateFindingsBadge();
    } catch (error) {
      console.error("Failed to load findings:", error);
    } finally {
      if (
        findingsLoadPromise === loadPromise
        && findingsLoadSessionId === sessionId
        && loadGeneration === findingsLoadGeneration
      ) {
        findingsLoadPromise = null;
        findingsLoadSessionId = null;
      }
    }
  })();
  findingsLoadPromise = loadPromise;
  return findingsLoadPromise;
}

async function updateFindingsBadgeOnly() {
  const sessionId = currentSessionId();
  const stateGeneration = findingsStateGeneration;
  try {
    const count = await fetchFindingsCount(sessionId);
    if (sessionId !== currentSessionId() || stateGeneration !== findingsStateGeneration) return;
    if (count == null) return;
    findingsBadgeCount = count;
    updateFindingsBadge();
  } catch (e) { /* silent */ }
}

async function fetchFindingsCount(sessionId) {
  const response = await fetch(sessionQueryPath("/api/findings/count", sessionId));
  if (!response.ok) return null;
  const payload = await response.json();
  const count = Number(payload?.count);
  return Number.isFinite(count) && count >= 0 ? count : 0;
}

function updateFindingsBadge() {
  if (!els.findingsBadge) return;
  const count = findingsBadgeCount;
  els.findingsBadge.textContent = count > 0 ? String(count) : "";
  els.findingsBadge.classList.toggle("hidden", count === 0);
}

function shouldPollFindingsBadge(now = Date.now()) {
  if (now - lastFindingsBadgePollAt < FINDINGS_BADGE_POLL_INTERVAL_MS) {
    return false;
  }
  lastFindingsBadgePollAt = now;
  return true;
}

function scheduleFindingsBadgeRefresh(delay = 250) {
  if (findingsBadgeRefreshTimer) return;
  findingsBadgeRefreshTimer = window.setTimeout(() => {
    findingsBadgeRefreshTimer = 0;
    lastFindingsBadgePollAt = Date.now();
    updateFindingsBadgeOnly().catch((error) => console.error(error));
  }, delay);
}

function scheduleFindingsListRefresh(delay = 250) {
  if (findingsListRefreshTimer) return;
  findingsListRefreshTimer = window.setTimeout(() => {
    findingsListRefreshTimer = 0;
    loadFindings().catch((error) => console.error(error));
  }, delay);
}

function handleFindingEvent(event) {
  try {
    const summary = JSON.parse(event.data || "null");
    if (summary?.id) {
      findingsBadgeCount += 1;
      updateFindingsBadge();
    }
  } catch (error) {
    console.error("Failed to parse finding event:", error);
  }
  if (state.activeTool === "proxy" && state.activeProxyTab === "findings") {
    scheduleFindingsListRefresh();
  } else {
    scheduleFindingsBadgeRefresh(1000);
  }
}

function clearFindingDetail() {
  selectedFindingId = null;
  if (els.findingsDetailJump) {
    delete els.findingsDetailJump.dataset.recordId;
  }
  setFindingDetailActionsEnabled(false);
  if (els.findingsDetailContent) {
    els.findingsDetailContent.classList.add("hidden");
  }
  if (els.findingsDetailPlaceholder) {
    els.findingsDetailPlaceholder.classList.remove("hidden");
  }
  if (els.findingsDetailTitle) els.findingsDetailTitle.textContent = "";
  if (els.findingsDetailCategory) els.findingsDetailCategory.textContent = "";
  if (els.findingsDetailDesc) els.findingsDetailDesc.textContent = "";
  if (getCMView("findingsReq")) updateCodePaneCM("findingsReq", els.findingsReqCM, "", { mode: "http" });
  if (getCMView("findingsRes")) updateCodePaneCM("findingsRes", els.findingsResCM, "", { mode: "http" });
  if (els.findingsReqView) els.findingsReqView.innerHTML = "";
  if (els.findingsResView) els.findingsResView.innerHTML = "";
  resetFindingsSearchUi();
}

function setFindingDetailActionsEnabled(enabled) {
  [
    els.findingsDetailJump,
    document.getElementById("findingsDetailSendReplay"),
    document.getElementById("findingsDetailSendFuzzer"),
  ].forEach((button) => {
    if (button) button.disabled = !enabled;
  });
}

function renderFindingDetailLoading() {
  setFindingDetailActionsEnabled(false);
  if (els.findingsDetailPlaceholder) els.findingsDetailPlaceholder.classList.add("hidden");
  if (els.findingsDetailContent) els.findingsDetailContent.classList.remove("hidden");
  if (els.findingsDetailSeverity) {
    els.findingsDetailSeverity.className = "severity-badge";
    els.findingsDetailSeverity.textContent = "";
  }
  if (els.findingsDetailCategory) els.findingsDetailCategory.textContent = "";
  if (els.findingsDetailTitle) els.findingsDetailTitle.textContent = "Loading finding...";
  if (els.findingsDetailDesc) els.findingsDetailDesc.textContent = "";
  if (els.findingsReqCM) {
    updateCodePaneCM("findingsReq", els.findingsReqCM, "Loading finding detail...", { mode: "http" });
  } else if (els.findingsReqView) {
    els.findingsReqView.innerHTML = '<span class="code-line code-line-empty">Loading finding detail...</span>';
    if (els.findingsReqLines) els.findingsReqLines.textContent = "";
  }
  if (els.findingsResCM) {
    updateCodePaneCM("findingsRes", els.findingsResCM, "", { mode: "http" });
  } else if (els.findingsResView) {
    els.findingsResView.innerHTML = "";
    if (els.findingsResLines) els.findingsResLines.textContent = "";
  }
  resetFindingsSearchUi({ lineCount: 1 });
}

function resetFindingsUiState() {
  findingsStateGeneration += 1;
  findingsLoadGeneration += 1;
  findingsData = [];
  findingsBadgeCount = 0;
  findingsLoadPromise = null;
  findingsLoadSessionId = null;
  lastFindingsBadgePollAt = 0;
  if (findingsBadgeRefreshTimer) {
    window.clearTimeout(findingsBadgeRefreshTimer);
    findingsBadgeRefreshTimer = 0;
  }
  if (findingsListRefreshTimer) {
    window.clearTimeout(findingsListRefreshTimer);
    findingsListRefreshTimer = 0;
  }
  state._findingsEntries = [];
  clearFindingDetail();
  renderFindings();
  updateFindingsBadge();
}

function resetFindingsSearchUi(options = {}) {
  const lineCount = Number.isFinite(Number(options.lineCount)) ? Number(options.lineCount) : 0;
  const pairs = [
    ["findingsReq", els.findingsReqSearchInput, els.findingsReqSearchMeta, els.findingsReqView],
    ["findingsRes", els.findingsResSearchInput, els.findingsResSearchMeta, els.findingsResView],
  ];
  for (const [key, input, meta, legacyView] of pairs) {
    if (input) input.value = "";
    const cv = getCMView(key);
    if (cv) cv.applySearch("");
    else if (legacyView) clearSearchHighlights(legacyView);
    if (meta) meta.innerHTML = buildSearchMeta(lineCount, "raw", 0);
  }
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
  const extraCats = new Set();
  // Remove old custom options
  Array.from(els.findingsFilterCategory.options).forEach((opt) => {
    if (opt.dataset.custom) opt.remove();
  });

  for (const f of findingsData) {
    const category = String(f.category || "").trim();
    if (!category) continue;
    if (BUILTIN_FINDING_CATEGORIES.has(category)) {
      ensureFindingsCategoryOption(category);
    } else {
      extraCats.add(category);
    }
  }

  for (const cat of [...extraCats].sort((a, b) => a.localeCompare(b))) {
    ensureFindingsCategoryOption(cat, { custom: true });
  }
  els.findingsFilterCategory.value = current;
}

function ensureFindingsCategoryOption(category, options = {}) {
  if (!els.findingsFilterCategory || !category) return;
  const exists = Array.from(els.findingsFilterCategory.options).some((opt) => opt.value === category);
  if (exists) return;

  const opt = document.createElement("option");
  opt.value = category;
  opt.textContent = BUILTIN_RULE_LABELS[category] || category;
  if (options.custom) opt.dataset.custom = "1";
  els.findingsFilterCategory.appendChild(opt);
}

function renderFindings() {
  if (!els.findingsBody) return;
  updateCategoryFilter();
  state._findingsEntries = getFilteredFindings();
  if (selectedFindingId && !state._findingsEntries.some((finding) => finding.id === selectedFindingId)) {
    clearFindingDetail();
  }

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

  const viewportHeight = shell.clientHeight;
  const totalCount = entries.length;
  const maxScrollTop = Math.max(0, totalCount * FINDINGS_ROW_HEIGHT - viewportHeight);
  const scrollTop = Math.min(shell.scrollTop, maxScrollTop);
  if (shell.scrollTop !== scrollTop) {
    shell.scrollTop = scrollTop;
  }

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
  const sessionId = currentSessionId();
  if (selectedFindingId === id && els.findingsDetailJump) {
    delete els.findingsDetailJump.dataset.recordId;
    renderFindingDetailLoading();
  }
  try {
    const res = await fetch(sessionQueryPath(`/api/findings/${encodeURIComponent(id)}`, sessionId));
    if (currentSessionId() !== sessionId || selectedFindingId !== id) return;
    if (!res.ok) {
      clearFindingDetail();
      return;
    }
    const finding = await res.json();
    if (currentSessionId() !== sessionId) return;
    if (selectedFindingId !== id) return;
    // Also fetch the transaction record for request/response
    let record = null;
    try {
      const tRes = await fetch(transactionPath(finding.record_id, sessionId));
      if (tRes.ok) record = await tRes.json();
    } catch (_) { /* silent */ }
    if (currentSessionId() !== sessionId) return;
    if (selectedFindingId !== id) return;
    showFindingDetail(finding, record);
  } catch (error) {
    console.error("Failed to load finding detail:", error);
    if (selectedFindingId === id && sessionId === currentSessionId()) {
      clearFindingDetail();
    }
  }
}

function showFindingDetail(finding, record) {
  if (!els.findingsDetailPanel) return;
  setFindingDetailActionsEnabled(Boolean(finding.record_id));
  if (els.findingsDetailPlaceholder) els.findingsDetailPlaceholder.classList.add("hidden");
  if (els.findingsDetailContent) els.findingsDetailContent.classList.remove("hidden");

  // Header info
  els.findingsDetailSeverity.className = `severity-badge ${severityClass(finding.severity)}`;
  els.findingsDetailSeverity.textContent = severityLabel(finding.severity);
  els.findingsDetailCategory.textContent = finding.category;
  els.findingsDetailTitle.textContent = finding.title;

  // Description + evidence
  renderFindingDescription(finding);

  // Jump button — store record_id
  els.findingsDetailJump.dataset.recordId = finding.record_id;

  // Render request/response with highlight
  const evidence = finding.evidence || "";
  let requestPaneResult = null;
  let responsePaneResult = null;
  if (record) {
    const reqText = buildFindingsRawMessage(record, "request");
    const resText = buildFindingsRawMessage(record, "response");
    // CM path
    if (els.findingsReqCM) {
      requestPaneResult = updateFindingsCodePaneCM(
        "findingsReq",
        els.findingsReqCM,
        reqText,
        evidence,
        finding,
        els.findingsReqSearchInput,
        els.findingsReqSearchMeta,
      );
    }
    if (els.findingsResCM) {
      responsePaneResult = updateFindingsCodePaneCM(
        "findingsRes",
        els.findingsResCM,
        resText,
        evidence,
        finding,
        els.findingsResSearchInput,
        els.findingsResSearchMeta,
      );
    }
    // Legacy fallback
    if (!els.findingsReqCM) {
      renderFindingsCodePane(els.findingsReqView, els.findingsReqLines, reqText, evidence, "request", finding);
    }
    if (!els.findingsResCM) {
      renderFindingsCodePane(els.findingsResView, els.findingsResLines, resText, evidence, "response", finding);
    }
    const fallbackLocation = fallbackFindingLocationFromPaneResults(finding, requestPaneResult, responsePaneResult);
    renderFindingDescription(finding, fallbackLocation);
    scrollFindingLocationIntoView(finding.location || fallbackLocation);
  } else {
    if (els.findingsReqCM) {
      updateCodePaneCM("findingsReq", els.findingsReqCM, "Transaction not available.", { mode: "http" });
    } else if (els.findingsReqView) {
      els.findingsReqView.innerHTML = '<span class="code-line code-line-empty">Transaction not available.</span>';
      if (els.findingsReqLines) els.findingsReqLines.textContent = "";
    }
    if (els.findingsResCM) {
      updateCodePaneCM("findingsRes", els.findingsResCM, "Transaction not available.", { mode: "http" });
    } else if (els.findingsResView) {
      els.findingsResView.innerHTML = '<span class="code-line code-line-empty">Transaction not available.</span>';
      if (els.findingsResLines) els.findingsResLines.textContent = "";
    }
    resetFindingsSearchUi({ lineCount: 1 });
  }
}

function updateFindingsCodePaneCM(key, container, text, evidence, finding, searchInput, searchMeta) {
  const highlightQueries = findingHighlightQueries(evidence, finding);
  let result = null;
  for (const highlightQuery of highlightQueries) {
    result = updateCodePaneCM(key, container, text, {
      mode: "http",
      search: highlightQuery,
      searchClasses: {
        hit: "tok-finding-evidence-hit",
        active: "tok-finding-evidence-active",
      },
    });
    if (result.matchCount > 0 || highlightQuery === highlightQueries[highlightQueries.length - 1]) {
      break;
    }
  }
  if (!result) {
    result = updateCodePaneCM(key, container, text, { mode: "http" });
  }
  if (searchInput) searchInput.value = "";
  if (searchMeta) searchMeta.innerHTML = buildSearchMeta(result.lineCount, "raw", result.matchCount);
  const cv = getCMView(key);
  const firstMatchLine = cv && result.matchPositions?.length
    ? cv.view.state.doc.lineAt(result.matchPositions[0]).number
    : null;
  return {
    ...result,
    firstMatchLine,
  };
}

function renderFindingDescription(finding, fallbackLocation = null) {
  if (!els.findingsDetailDesc) return;
  const location = normalizeFindingLocation(finding.location || fallbackLocation);
  const locationLabel = formatFindingLocationLabel(location);
  const locationHtml = locationLabel
    ? `<span class="findings-location-chip">${escapeHtml(locationLabel)}</span>`
    : "";
  els.findingsDetailDesc.innerHTML = `${locationHtml}<span class="findings-desc-text">${escapeHtml(finding.detail || "")}</span>`;
}

function normalizeFindingLocation(location) {
  if (!location || typeof location !== "object") return null;
  const side = String(location.side || "").toLowerCase();
  if (side !== "request" && side !== "response") return null;
  const line = Number(location.line);
  return {
    side,
    section: String(location.section || "").toLowerCase(),
    line: Number.isFinite(line) && line > 0 ? Math.trunc(line) : null,
  };
}

function formatFindingLocationLabel(location) {
  if (!location) return "";
  const side = location.side === "request" ? "Request" : "Response";
  const section = location.section
    ? location.section.replace(/_/g, " ").replace(/\b\w/g, (ch) => ch.toUpperCase())
    : "";
  if (location.line) {
    return section ? `${side} line ${location.line} · ${section}` : `${side} line ${location.line}`;
  }
  return section ? `${side} ${section}` : side;
}

function fallbackFindingLocationFromPaneResults(finding, requestPaneResult, responsePaneResult) {
  if (finding.location) return null;
  const responseLine = responsePaneResult?.firstMatchLine;
  const requestLine = requestPaneResult?.firstMatchLine;
  const preferRequest = String(finding.category || "") === "auth"
    || String(finding.evidence || "").toLowerCase().startsWith("authorization:");
  if (preferRequest && requestLine) {
    return { side: "request", section: "match", line: requestLine };
  }
  if (responseLine) {
    return { side: "response", section: "match", line: responseLine };
  }
  if (requestLine) {
    return { side: "request", section: "match", line: requestLine };
  }
  return null;
}

function scrollFindingLocationIntoView(location) {
  const normalized = normalizeFindingLocation(location);
  if (!normalized?.line) return;
  const key = normalized.side === "request" ? "findingsReq" : "findingsRes";
  const cv = getCMView(key);
  if (!cv) return;
  const doc = cv.view.state.doc;
  const line = doc.line(Math.max(1, Math.min(normalized.line, doc.lines)));
  cv.view.dispatch({ selection: { anchor: line.from }, scrollIntoView: true });
}

function renderFindingsCodePane(viewEl, lineEl, text, evidence, target, finding) {
  if (!viewEl || !lineEl) return;
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

function findingHighlightQuery(evidence, finding) {
  return findingHighlightQueries(evidence, finding)[0] || "";
}

function findingHighlightQueries(evidence, finding) {
  const queries = [];
  const evidenceQuery = firstUsableFindingQuery(evidence);
  if (evidenceQuery) queries.push(evidenceQuery);
  for (const keyword of extractFindingKeywords(finding)) {
    if (keyword.length >= 3) queries.push(keyword);
  }
  return [...new Set(queries)];
}

function firstUsableFindingQuery(value) {
  const normalized = String(value || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find((line) => line.length >= 3);
  if (!normalized) return "";
  const untruncated = normalized.endsWith("...")
    ? normalized.slice(0, -3).trimEnd()
    : normalized;
  const redactedBasic = untruncated.match(/^(authorization\s*:\s*basic)\s+\*+$/i);
  const query = redactedBasic ? redactedBasic[1] : untruncated;
  return query.length > 512 ? query.slice(0, 512) : query;
}

function highlightFindingLines(container, evidence, finding) {
  const codeLines = container.querySelectorAll(".code-line");
  let scrollTarget = null;

  // 1) If evidence exists, highlight lines containing the evidence text.
  for (const query of findingHighlightQueries(evidence, finding)) {
    const escapedQuery = query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    let pattern;
    try { pattern = new RegExp(`(${escapedQuery})`, "gi"); } catch (_) { pattern = null; }
    if (!pattern) continue;

    let matched = false;
    codeLines.forEach((line) => {
      pattern.lastIndex = 0;
      if (pattern.test(line.textContent)) {
        matched = true;
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
    if (matched) break;
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
  setActiveTool("proxy");
  setActiveProxyTab("http-history");
  const hadRenderedDetail = Boolean(state.selectedRecord?.id);
  state.selectedId = recordId;
  state.selectedRecord = null;
  renderProxyPanels();
  scheduleHistoryDetailLoading(recordId, "Loading selected transaction...", {
    immediate: !hadRenderedDetail,
  });
  loadTransactionDetail(recordId).then(async (record) => {
    if (!record || state.selectedId !== recordId) return;
    const revealed = await ensureHistoryWindowContainsRecord(record);
    if (!revealed) {
      if (state.selectedId === recordId) {
        state.selectedId = null;
        state.selectedRecord = null;
        renderEmptyDetail();
        renderHistory();
      }
      return;
    }
    focusHistoryRecord(recordId);
  }).catch((error) => console.error(error));
}

function sequenceCursorAfter(sequence) {
  const raw = String(sequence ?? "").trim();
  if (/^\d+$/.test(raw)) {
    try {
      return (BigInt(raw) + 1n).toString();
    } catch (_error) {
      // Fall through to Number parsing for older runtimes.
    }
  }
  const numeric = Number(sequence);
  if (!Number.isFinite(numeric) || numeric < 0) return null;
  return String(Math.trunc(numeric) + 1);
}

async function ensureHistoryWindowContainsRecord(record) {
  if (!record?.id || getHistoryItem(record.id)) {
    return true;
  }
  if (!canUseSequenceCursorForHistoryPaging()) {
    showToast("Use index sort to reveal this older transaction in HTTP History.", "info", 4000);
    return false;
  }
  const beforeSequence = sequenceCursorAfter(record.sequence);
  if (!beforeSequence) {
    showToast("This transaction is outside the loaded HTTP History window.", "info", 4000);
    return false;
  }

  clearHistoryBackfill();
  const paging = state.historyPaging || (state.historyPaging = createHistoryPagingState());
  const queryState = createHistoryQueryState();
  const querySignature = historyQuerySignature(queryState);
  const generation = ++_historyPagingGeneration;
  const sessionId = currentSessionId();
  paging.generation = generation;
  paging.querySignature = querySignature;
  paging.loading = true;
  try {
    const page = await fetchTransactionPage({ beforeSequence, queryState, querySignature });
    if (!page || sessionId !== currentSessionId() || state.selectedId !== record.id) {
      return false;
    }
    if (
      state.historyPaging !== paging
      || paging.generation !== generation
      || paging.querySignature !== querySignature
      || !isCurrentHistoryQuerySignature(querySignature)
    ) {
      return false;
    }

    const pageItems = jsonArray(page.items);
    if (!pageItems.some((item) => item?.id === record.id)) {
      showToast("Current HTTP History filters hide this transaction.", "info", 4000);
      return false;
    }

    replaceHistoryItemsForGap(pageItems);
    if (page.total != null) paging.total = page.total;
    if (page.filtered_total != null) paging.filteredTotal = page.filtered_total;
    if (page.hidden_connect_total != null) paging.hiddenConnectTotal = page.hidden_connect_total;
    paging.offset = state.items.length;
    paging.hasMore = Boolean(page.has_more);
    paging.fullyLoaded = !paging.hasMore;
    return true;
  } catch (error) {
    console.error("Failed to reveal history transaction:", error);
    showToast(error?.message || "Failed to reveal transaction in HTTP History.", "error", 5000);
    return false;
  } finally {
    if (state.historyPaging === paging && paging.generation === generation && paging.querySignature === querySignature) {
      paging.loading = false;
      if (isCurrentHistoryQuerySignature(querySignature)) renderHistory();
    }
  }
}

function focusHistoryRecord(recordId) {
  if (state.selectedId !== recordId) return;
  updateHistorySelection(recordId);
  scrollSelectedHistoryRowIntoView();
  window.requestAnimationFrame(() => {
    if (state.selectedId !== recordId || !isHttpHistoryVisible()) return;
    updateHistorySelection(recordId);
    scrollSelectedHistoryRowIntoView();
  });
}

async function sendFindingToReplay(recordId) {
  const sessionId = currentSessionId();
  const response = await fetch(transactionPath(recordId, sessionId));
  if (currentSessionId() !== sessionId) return;
  await requireOkResponse(response, "Failed to load finding transaction.");
  const record = await response.json();
  if (currentSessionId() !== sessionId) return;
  openTransactionRecordInReplay(record);
}

function openTransactionRecordInReplay(record) {
  if (!record || record.kind === "tunnel") {
    throw new Error("Tunnel records cannot be sent to Replay.");
  }
  if (isWebSocketUpgradeRecord(record)) {
    const scheme = record.scheme === "https" ? "wss" : record.scheme === "http" ? "ws" : record.scheme || "wss";
    const target = authorityToTargetState(record.host || "", record.scheme || "https");
    createWsReplayTab({
      scheme,
      host: target.host,
      port: normalizePortValue(target.port) || (scheme === "wss" ? 443 : 80),
      path: record.path || "/",
      headers: normalizedHeaders(record.request?.headers),
    });
    setActiveTool("replay");
    scheduleWorkspaceStateSave();
    renderToolPanels();
    return;
  }
  const request = editableRequestFromRecord(record);
  const tab = createReplayTab({
    baseRequest: request,
    sourceTransactionId: record.id,
    notice: isRequestPreviewTruncated(record) ? buildTruncatedBodyNotice(record, "Replay") : "",
    requestText: buildEditableRawRequest(request),
  });
  state.replayTabs.push(tab);
  state.activeReplayTabId = tab.id;
  setActiveTool("replay");
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

function isWebSocketUpgradeRecord(record) {
  if (Number(record?.status) !== 101) return false;
  const headers = normalizedHeaders(record?.request?.headers);
  const hasUpgradeWebsocket = headers.some(
    (h) => headerNameEquals(h, "upgrade") && headerValueContainsToken(h.value, "websocket"),
  );
  const hasConnectionUpgrade = headers.some(
    (h) => headerNameEquals(h, "connection") && headerValueContainsToken(h.value, "upgrade"),
  );
  return hasUpgradeWebsocket && hasConnectionUpgrade;
}

async function sendFindingToFuzzer(recordId) {
  const sessionId = currentSessionId();
  const response = await fetch(transactionPath(recordId, sessionId));
  if (currentSessionId() !== sessionId) return;
  await requireOkResponse(response, "Failed to load finding transaction.");
  const record = await response.json();
  if (currentSessionId() !== sessionId) return;
  if (!record || record.kind === "tunnel") {
    throw new Error("Tunnel records cannot be sent to Fuzzer.");
  }
  const request = editableRequestFromRecord(record);
  invalidateFuzzerRun();
  state.fuzzerBaseRequest = request;
  state.fuzzerSourceTransactionId = record.id;
  state.fuzzerTarget = null;
  state.fuzzerTargetRequestText = null;
  updateFuzzerRequestText(buildEditableRawRequest(request), { userEdit: true });
  state.fuzzerNotice = isRequestPreviewTruncated(record) ? buildTruncatedBodyNotice(record, "Fuzzer") : "";
  updateFuzzerPayloadsText("", { userEdit: true });
  clearFuzzerAttackRecord();
  state._selectedFuzzerResultKey = null;
  hideFuzzerDetailPanel();
  setActiveTool("fuzzer");
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

function handleFindingActionError(error) {
  console.error(error);
  showToast(error?.message || "Finding action failed.", "error");
}

// ── Scanner Settings Modal ──

async function loadScannerConfig(sessionId = currentSessionId()) {
  try {
    const res = await fetch(sessionQueryPath("/api/scanner-config", sessionId));
    await requireOkResponse(res, "Failed to load scanner settings.");
    const config = await res.json();
    if (sessionId !== currentSessionId()) {
      return null;
    }
    scannerConfigCache = config;
    return scannerConfigCache;
  } catch (e) {
    console.error("Failed to load scanner config:", e);
    showToast(e?.message || "Failed to load scanner settings.", "error");
    return null;
  }
}

async function saveScannerConfig(config, sessionId = currentSessionId(), options = {}) {
  if (sessionId !== currentSessionId()) {
    return false;
  }
  if (options.preserveEnabled) {
    const latestResponse = await fetch(sessionQueryPath("/api/scanner-config", sessionId));
    await requireOkResponse(latestResponse, "Failed to load scanner settings.");
    const latestConfig = await latestResponse.json();
    if (sessionId !== currentSessionId()) {
      return false;
    }
    config.enabled = latestConfig.enabled !== false;
  }
  const res = await fetch(sessionWritePath("/api/scanner-config", sessionId), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
  await requireOkResponse(res, "Failed to save scanner settings.");
  if (sessionId !== currentSessionId()) {
    return false;
  }
  scannerConfigCache = config;
  return true;
}

async function openScannerSettings() {
  const sessionId = currentSessionId();
  const config = await loadScannerConfig(sessionId);
  if (!config || sessionId !== currentSessionId()) return;
  scannerSettingsSessionId = sessionId;

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
    .map((rule, idx) => {
      const ruleId = customRuleId(rule.id);
      return `
      <div class="scanner-custom-rule-card" data-custom-idx="${idx}" data-rule-id="${escapeHtml(ruleId)}">
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
    `;
    })
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
    id: customRuleId(card.dataset.ruleId),
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

function customRuleId(value) {
  const id = String(value || "").trim();
  if (id) return id;
  if (globalThis.crypto?.randomUUID) {
    return `custom_${globalThis.crypto.randomUUID()}`;
  }
  return `custom_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
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
  scannerSettingsSessionId = null;
  if (els.scannerSettingsBackdrop) {
    els.scannerSettingsBackdrop.classList.add("hidden");
  }
}

async function saveScannerSettingsFromModal() {
  const sessionId = scannerSettingsSessionId;
  if (!sessionId || sessionId !== currentSessionId()) {
    closeScannerSettings();
    showToast("Scanner settings changed sessions. Reopen settings and save again.", "error");
    return;
  }
  const config = collectScannerConfig();
  if (!(await saveScannerConfig(config, sessionId, { preserveEnabled: true }))) {
    return;
  }
  syncQuickToggle(config.enabled);
  closeScannerSettings();
  showToast("Scanner settings saved");
}

async function refreshScannerQuickToggle() {
  if (!els.scannerQuickToggle) return;
  const sessionId = currentSessionId();
  const config = await loadScannerConfig(sessionId);
  if (config && sessionId === currentSessionId()) {
    syncQuickToggle(config.enabled);
  }
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
  const sessionId = currentSessionId();
  const [cbRes, statusRes] = await Promise.all([
    fetch(sessionQueryPath("/api/oast/callbacks", sessionId)),
    fetch(sessionQueryPath("/api/oast/status", sessionId)),
  ]);
  await requireOkResponse(cbRes, "Failed to load OAST callbacks.");
  const callbacks = jsonArray(await cbRes.json());
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.oastCallbacks = callbacks;
  if (state.selectedOastId && !state.oastCallbacks.some((cb) => cb.id === state.selectedOastId)) {
    state.selectedOastId = null;
    clearOastDetail();
  }
  renderOastCallbacks();
  updateOastBadge();
  // Update registration status display
  try {
    await requireOkResponse(statusRes, "Failed to load OAST status.");
    const status = await statusRes.json() || {};
    if (sessionId !== currentSessionId()) {
      return;
    }
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

function clearOastDetail() {
  if (els.oastDetailView) els.oastDetailView.textContent = "Select an OAST callback to view details.";
  if (els.oastDetailTitle) els.oastDetailTitle.textContent = "Select a callback";
}

function renderOastDetailLoading() {
  if (els.oastDetailView) els.oastDetailView.textContent = "Loading selected OAST callback...";
  if (els.oastDetailTitle) els.oastDetailTitle.textContent = "Loading callback";
}

function resetOastUiState() {
  state.oastCallbacks = [];
  state.selectedOastId = null;
  state.oastTokenClearPending = false;
  if (els.oastPayloadText) els.oastPayloadText.value = "";
  renderOastCallbacks();
  updateOastBadge();
  clearOastDetail();
  const status = document.getElementById("oastStatusText");
  if (status) {
    status.textContent = "Not configured";
    status.className = "oast-status-text not-registered";
  }
}

function handleOastActionError(error) {
  console.error(error);
  showToast(error?.message || "OAST action failed.", "error");
}

async function loadOastDetail(id) {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath(`/api/oast/callbacks/${id}`, sessionId));
  if (sessionId !== currentSessionId() || state.selectedOastId !== id) {
    return;
  }
  if (!response.ok) {
    state.selectedOastId = null;
    clearOastDetail();
    renderOastCallbacks();
    return;
  }
  const cb = await response.json();
  if (sessionId !== currentSessionId() || state.selectedOastId !== id) {
    return;
  }
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
  if (!state.runtime.oast_enabled) {
    showToast("Enable OAST in Settings before generating a payload", "error");
    return;
  }
  if (!serverUrl) {
    showToast("Set an OAST server URL in Settings first", "error");
    return;
  }
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath("/api/oast/generate", sessionId), { method: "POST" });
  if (!response.ok) {
    showToast(await response.text(), "error");
    return;
  }
  const data = await response.json();
  if (sessionId !== currentSessionId()) {
    return;
  }
  if (els.oastPayloadText) els.oastPayloadText.value = data.payload;
  showToast(`OAST payload: ${data.payload}`);
}

async function clearOastCallbacks() {
  const sessionId = currentSessionId();
  const response = await fetch(sessionWritePath("/api/oast/callbacks/clear", sessionId), { method: "POST" });
  await requireOkResponse(response, "Failed to clear OAST callbacks.");
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.oastCallbacks = [];
  state.selectedOastId = null;
  renderOastCallbacks();
  updateOastBadge();
  clearOastDetail();
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
      clearFindingDetail();
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
      if (recordId) sendFindingToReplay(recordId).catch(handleFindingActionError);
    });
  }
  const findingsFuzzerBtn = document.getElementById("findingsDetailSendFuzzer");
  if (findingsFuzzerBtn) {
    findingsFuzzerBtn.addEventListener("click", () => {
      const recordId = els.findingsDetailJump?.dataset.recordId;
      if (recordId) sendFindingToFuzzer(recordId).catch(handleFindingActionError);
    });
  }
  if (els.findingsClearButton) {
    els.findingsClearButton.addEventListener("click", async () => {
      const sessionId = currentSessionId();
      try {
        const response = await fetch(sessionWritePath("/api/findings/clear", sessionId), { method: "POST" });
        await requireOkResponse(response, "Failed to clear findings.");
        if (sessionId !== currentSessionId()) return;
        resetFindingsUiState();
      } catch (error) {
        console.error(error);
        showToast(error?.message || "Failed to clear findings.", "error");
      }
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
      // CM path
      const cv = getCMView("findingsReq");
      if (cv) {
        const result = cv.applySearch(query);
        const lineCount = cv.view.state.doc.lines;
        els.findingsReqSearchMeta.innerHTML = buildSearchMeta(lineCount, "raw", result.matchCount);
        return;
      }
      // Legacy fallback
      if (!els.findingsReqView) return;
      const { count } = applyCodeSearch(els.findingsReqView, query);
      const lines = els.findingsReqView.querySelectorAll(".code-line").length;
      els.findingsReqSearchMeta.innerHTML = buildSearchMeta(lines, "raw", count);
    });
  }
  if (els.findingsResSearchInput) {
    els.findingsResSearchInput.addEventListener("input", () => {
      const query = els.findingsResSearchInput.value;
      // CM path
      const cv = getCMView("findingsRes");
      if (cv) {
        const result = cv.applySearch(query);
        const lineCount = cv.view.state.doc.lines;
        els.findingsResSearchMeta.innerHTML = buildSearchMeta(lineCount, "raw", result.matchCount);
        return;
      }
      // Legacy fallback
      if (!els.findingsResView) return;
      const { count } = applyCodeSearch(els.findingsResView, query);
      const lines = els.findingsResView.querySelectorAll(".code-line").length;
      els.findingsResSearchMeta.innerHTML = buildSearchMeta(lines, "raw", count);
    });
  }
  initSearchHitNavigation(els.findingsReqSearchMeta, () => els.findingsReqView);
  initSearchHitNavigation(els.findingsResSearchMeta, () => els.findingsResView);
  initCMSearchNavigation(els.findingsReqSearchMeta, "findingsReq");
  initCMSearchNavigation(els.findingsResSearchMeta, "findingsRes");

  // Quick toggle (on/off in toolbar)
  if (els.scannerQuickToggle) {
    els.scannerQuickToggle.addEventListener("change", async () => {
      const enabled = els.scannerQuickToggle.checked;
      const sessionId = currentSessionId();
      els.scannerQuickToggle.disabled = true;
      try {
        const config = await loadScannerConfig(sessionId);
        if (sessionId !== currentSessionId()) {
          return;
        }
        if (!config) {
          syncQuickToggle(!enabled);
          return;
        }
        config.enabled = enabled;
        if (!(await saveScannerConfig(config, sessionId))) {
          return;
        }
        syncQuickToggle(enabled);
      } catch (error) {
        console.error(error);
        showToast(error?.message || "Failed to save scanner settings.", "error");
        syncQuickToggle(!enabled);
      } finally {
        els.scannerQuickToggle.disabled = false;
      }
    });
    // Sync initial state from server
    refreshScannerQuickToggle();
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
    els.scannerSettingsSave.addEventListener("click", () => {
      saveScannerSettingsFromModal().catch((error) => {
        console.error(error);
        showToast(error?.message || "Failed to save scanner settings.", "error");
      });
    });
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
  state.activeProxyTab = sanitizeActiveProxyTab(state.activeProxyTab);
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
    applySavedWebsocketPaneWidth();
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
  railTabs.forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.inspectorTab === state.activeInspectorTab);
  });
  if (
    !state.inspectorCollapsed
    && state.activeInspectorTab === "notes"
    && els.notesPanel
    && els.inspectorContent
  ) {
    window.requestAnimationFrame(() => {
      els.notesPanel.scrollIntoView({ block: "start", behavior: "smooth" });
    });
  }
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

function renderHistory() {
  const visibleEntries = getVisibleEntries();
  const hiddenConnectCount = countHiddenConnectItems();
  const paging = state.historyPaging || createHistoryPagingState();
  const hiddenConnectExact = isKnownCount(paging.hiddenConnectTotal);
  const summary = [];
  const totalCount = visibleEntries.length;
  summary.push(`${totalCount} loaded item(s) visible`);
  if (hiddenConnectCount) summary.push(`${hiddenConnectCount}${hiddenConnectExact || paging.fullyLoaded ? "" : " loaded"} CONNECT tunnel(s) hidden`);
  if (isKnownCount(paging.filteredTotal)) {
    summary.push(`${state.items.length}/${paging.filteredTotal} server-matched summaries loaded`);
  }
  if (paging.total && (!isKnownCount(paging.filteredTotal) || paging.total !== paging.filteredTotal)) {
    summary.push(`${paging.total} retained`);
  }
  if (!paging.fullyLoaded) {
    summary.push(paging.loading ? "loading older history" : "scroll for older history");
  }
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

  if (!visibleEntries.length) {
    els.historyTableBody.innerHTML = `
      <tr class="empty-row">
        <td colspan="${state.historyColumnOrder.length}">${escapeHtml(historyEmptyMessage(hiddenConnectCount, paging))}</td>
      </tr>
    `;
    if (paging.hasMore && !paging.loading && !paging.fullyLoaded) {
      scheduleHistoryBackfill(0, { allowAtCap: true });
    }
    return;
  }

  renderHistoryVirtual();
}

function renderHistoryVirtual() {
  const entries = state._historyEntries;
  if (!entries || !entries.length) return;

  const shell = els.historyTable.closest(".history-table-shell");
  if (!shell) return;

  const rowHeight = measuredHistoryRowHeight || HISTORY_ROW_HEIGHT;
  const viewportHeight = shell.clientHeight;
  const totalCount = entries.length;
  const colCount = state.historyColumnOrder.length;
  const maxScrollTop = Math.max(0, totalCount * rowHeight - viewportHeight);
  const scrollTop = Math.min(shell.scrollTop, maxScrollTop);
  if (shell.scrollTop !== scrollTop) {
    shell.scrollTop = scrollTop;
  }

  const startIdx = Math.max(0, Math.floor(scrollTop / rowHeight) - HISTORY_BUFFER_ROWS);
  const endIdx = Math.min(totalCount, Math.ceil((scrollTop + viewportHeight) / rowHeight) + HISTORY_BUFFER_ROWS);
  if (
    startIdx <= HTTP_HISTORY_SCROLL_PREFETCH_ROWS
    && state.historyPaging?.trimmedHeadCount > 0
    && !state.historyPaging.loading
  ) {
    loadNewerTransactions({ background: true }).catch((error) => console.error(error));
  }
  if (totalCount - endIdx <= HTTP_HISTORY_SCROLL_PREFETCH_ROWS) {
    const atLoadedBottom = scrollTop >= maxScrollTop - rowHeight;
    scheduleHistoryBackfill(0, { allowAtCap: atLoadedBottom });
  }

  const topPadding = startIdx * rowHeight;
  const bottomPadding = Math.max(0, (totalCount - endIdx) * rowHeight);

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

  const measuredRow = els.historyTableBody.querySelector(".history-row");
  const measured = measuredRow?.getBoundingClientRect().height || 0;
  if (measured > 0 && Math.abs(measured - rowHeight) >= 1) {
    measuredHistoryRowHeight = measured;
    renderHistoryVirtual();
  }
}

function historyEmptyMessage(hiddenConnectCount, paging) {
  if (state.historyListError) {
    return `HTTP History filter error: ${state.historyListError}`;
  }
  if (hiddenConnectCount) {
    return "Only CONNECT tunnels were captured, and they are hidden from HTTP history. Trust the Sniper Root CA and retry the HTTPS client if you expect decrypted traffic.";
  }
  if (!paging.fullyLoaded) {
    return paging.loading
      ? "No loaded traffic matches yet. Older history is still loading."
      : "No loaded traffic matches yet. Older history will load as needed.";
  }
  return "No traffic matches the current filter settings.";
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
  const targetTop = idx * (measuredHistoryRowHeight || HISTORY_ROW_HEIGHT);
  shell.scrollTop = Math.max(0, targetTop - shell.clientHeight / 2);
  renderHistoryVirtual();
}

async function moveHistorySelection(offset) {
  let visibleEntries = getVisibleEntries();
  if (!visibleEntries.length) {
    return;
  }

  const currentIndex = visibleEntries.findIndex((entry) => entry.item.id === state.selectedId);
  const fallbackIndex = offset > 0 ? 0 : visibleEntries.length - 1;
  if (offset > 0
    && currentIndex === visibleEntries.length - 1
    && state.historyPaging?.hasMore
    && !state.historyPaging.loading
    && state.historyPaging.fullyLoaded !== true) {
    const selectedIdBeforeLoad = state.selectedId;
    const added = await loadMoreTransactions();
    if (added <= 0) return;
    visibleEntries = getVisibleEntries();
    const loadedIndex = visibleEntries.findIndex((entry) => entry.item.id === selectedIdBeforeLoad);
    const loadedNextId = loadedIndex >= 0 ? visibleEntries[loadedIndex + 1]?.item.id : null;
    if (loadedNextId) {
      await selectHistoryTransaction(loadedNextId, { scroll: true });
    }
    return;
  }
  if (offset < 0
    && currentIndex === 0
    && state.historyPaging?.trimmedHeadCount > 0
    && !state.historyPaging.loading) {
    const selectedIdBeforeLoad = state.selectedId;
    const added = await loadNewerTransactions();
    if (added <= 0) return;
    visibleEntries = getVisibleEntries();
    const loadedIndex = visibleEntries.findIndex((entry) => entry.item.id === selectedIdBeforeLoad);
    const loadedPreviousId = loadedIndex >= 0
      ? visibleEntries[loadedIndex - 1]?.item.id
      : visibleEntries[visibleEntries.length - 1]?.item.id;
    if (loadedPreviousId) {
      await selectHistoryTransaction(loadedPreviousId, { scroll: true });
    }
    return;
  }
  const nextIndex = clamp(
    currentIndex === -1 ? fallbackIndex : currentIndex + offset,
    0,
    visibleEntries.length - 1,
  );
  const nextId = visibleEntries[nextIndex]?.item.id;
  if (!nextId) {
    return;
  }

  await selectHistoryTransaction(nextId, { scroll: true });
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
  const rowHeight = measuredHistoryRowHeight || HISTORY_ROW_HEIGHT;
  const rowTop = idx * rowHeight;
  const rowBottom = rowTop + rowHeight;
  const viewTop = shell.scrollTop;
  const viewBottom = viewTop + shell.clientHeight;
  if (rowTop < viewTop) {
    shell.scrollTop = rowTop;
    renderHistoryVirtual();
  } else if (rowBottom > viewBottom) {
    shell.scrollTop = rowBottom - shell.clientHeight;
    renderHistoryVirtual();
  }
}

async function moveWebsocketSelection(offset) {
  let sortedEntries = getSortedWebsocketEntries();
  if (!sortedEntries.length) return;

  const currentIndex = sortedEntries.findIndex(({ session }) => session.id === state.selectedWebsocketId);
  const fallbackIndex = offset > 0 ? 0 : sortedEntries.length - 1;
  if (
    offset > 0
    && currentIndex === sortedEntries.length - 1
    && state.websocketPaging?.hasMore
    && !state.websocketPaging.loading
  ) {
    const selectedIdBeforeLoad = state.selectedWebsocketId;
    const added = await loadMoreWebsockets();
    if (added <= 0) return;
    sortedEntries = getSortedWebsocketEntries();
    const loadedIndex = sortedEntries.findIndex(({ session }) => session.id === selectedIdBeforeLoad);
    const loadedNextId = loadedIndex >= 0 ? sortedEntries[loadedIndex + 1]?.session?.id : null;
    if (loadedNextId) {
      await selectWebsocketSession(loadedNextId, { scroll: true });
    }
    return;
  }
  const nextIndex = clamp(
    currentIndex === -1 ? fallbackIndex : currentIndex + offset,
    0,
    sortedEntries.length - 1,
  );
  const nextId = sortedEntries[nextIndex]?.session?.id;
  if (!nextId) return;

  await selectWebsocketSession(nextId, { scroll: true });
}

async function selectWebsocketSession(id, options = {}) {
  const nextId = id ?? null;
  if (!nextId) return;

  const hadRenderedWebsocketDetail = Boolean(state.selectedWebsocketRecord?.id);
  if (state.selectedWebsocketId !== nextId) {
    state.selectedFrameIdx = null;
    state.selectedWebsocketRecord = null;
    state.selectedWebsocketDetailError = "";
    hideFrameDetail();
    resetWebsocketFrameScroll();
  }
  state.selectedWebsocketId = nextId;
  renderWebsocketSessionTable();
  scheduleWebsocketDetailLoading(nextId, {
    immediate: !hadRenderedWebsocketDetail,
  });
  if (options.scroll) {
    scrollSelectedWebsocketRowIntoView();
  }
  await loadWebsocketDetail(nextId);
}

function scrollSelectedWebsocketRowIntoView() {
  const selectedRow = els.websocketTableBody.querySelector(".history-row.selected");
  if (selectedRow) {
    selectedRow.scrollIntoView({ block: "nearest" });
    return;
  }
  scrollWebsocketSessionToId(state.selectedWebsocketId);
}

function scrollWebsocketSessionToId(targetId) {
  if (!targetId) return;
  const sortedEntries = getSortedWebsocketEntries();
  if (!ensureWebsocketSessionInView(targetId, sortedEntries, { center: true })) {
    return;
  }
  renderWebsocketSessionTable(sortedEntries);
}

function ensureWebsocketSessionInView(targetId, sortedEntries = getSortedWebsocketEntries(), options = {}) {
  if (!targetId) return false;
  const idx = sortedEntries.findIndex(({ session }) => session.id === targetId);
  if (idx === -1) return false;
  const shell = document.querySelector("#websocketTable")?.closest(".history-table-shell");
  if (!shell) return false;
  if (sortedEntries.length <= WEBSOCKET_MAX_RENDERED_SESSION_ROWS) {
    shell.scrollTop = 0;
    return true;
  }
  const rowHeight = measuredWebsocketSessionRowHeight || WEBSOCKET_SESSION_ROW_HEIGHT;
  const rowTop = idx * rowHeight;
  const rowBottom = rowTop + rowHeight;
  const viewTop = shell.scrollTop;
  const viewBottom = viewTop + shell.clientHeight;
  if (options.center) {
    shell.scrollTop = Math.max(0, rowTop - shell.clientHeight / 2);
    return true;
  }
  if (rowTop < viewTop) {
    shell.scrollTop = rowTop;
    return true;
  }
  if (rowBottom > viewBottom) {
    shell.scrollTop = Math.max(0, rowBottom - shell.clientHeight);
    return true;
  }
  return true;
}

function moveFrameSelection(offset) {
  const session = state.selectedWebsocketRecord;
  const frames = getWebsocketFrames(session);
  if (!frames.length) return;

  const current = state.selectedFrameIdx;
  const currentPosition = current == null
    ? -1
    : frames.findIndex((frame) => frame.index === current);
  const fallback = offset > 0 ? 0 : frames.length - 1;
  const nextPosition = clamp(
    currentPosition === -1 ? fallback : currentPosition + offset,
    0,
    frames.length - 1,
  );

  const frame = frames[nextPosition];
  if (!frame) return;
  state.selectedFrameIdx = frame.index;

  // Update selection highlight — find by data attribute, not DOM index
  els.websocketFramesBody.querySelectorAll(".frame-selected").forEach((r) => r.classList.remove("frame-selected"));
  let target = els.websocketFramesBody.querySelector(`.history-row[data-frame-index="${frame.index}"]`);
  if (!target && frames.length > WEBSOCKET_MAX_RENDERED_FRAME_ROWS) {
    ensureWebsocketFramePositionInView(nextPosition, { center: true });
    renderWebsocketFrameTable();
    target = els.websocketFramesBody.querySelector(`.history-row[data-frame-index="${frame.index}"]`);
  }
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

  if (document.activeElement instanceof Node) {
    if (els.requestViewCM?.contains(document.activeElement)) {
      return "request";
    }

    if (els.responseViewCM?.contains(document.activeElement)) {
      return "response";
    }
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

    if (els.requestViewCM?.contains(anchorNode)) {
      return "request";
    }

    if (els.responseViewCM?.contains(anchorNode)) {
      return "response";
    }
  }

  return state.activeMessagePane;
}

function getSelectedCodePaneText() {
  const activePane = getActiveMessagePane();
  if (activePane === "request" || activePane === "response") {
    const activeCMText = getSelectedCMText(activePane);
    if (activeCMText) return activeCMText;
  }

  const cmSelections = ["request", "response"]
    .filter((pane) => pane !== activePane)
    .map((pane) => getSelectedCMText(pane))
    .filter(Boolean);
  if (cmSelections.length === 1) return cmSelections[0];

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
    || els.requestViewCM?.contains(container)
    || els.responseViewCM?.contains(container)
  ) {
    return selection.toString();
  }

  const anchorNode = selection.anchorNode;
  const focusNode = selection.focusNode;
  if (
    (anchorNode instanceof Node && (els.requestView?.contains(anchorNode) || els.responseView?.contains(anchorNode)))
    || (focusNode instanceof Node && (els.requestView?.contains(focusNode) || els.responseView?.contains(focusNode)))
    || (anchorNode instanceof Node && (els.requestViewCM?.contains(anchorNode) || els.responseViewCM?.contains(anchorNode)))
    || (focusNode instanceof Node && (els.requestViewCM?.contains(focusNode) || els.responseViewCM?.contains(focusNode)))
  ) {
    return selection.toString();
  }

  return "";
}

function getSelectedCMText(targetPane) {
  const codeView = getCMView(targetPane);
  const view = codeView?.view;
  if (!view) return "";
  const ranges = view.state.selection.ranges
    .filter((range) => !range.empty)
    .map((range) => view.state.sliceDoc(range.from, range.to));
  return ranges.join("\n");
}

async function copyTextToClipboard(text) {
  if (text == null) {
    return;
  }
  const clipboardText = String(text);

  // Try modern Clipboard API first, fall back to textarea+execCommand
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(clipboardText);
      return;
    } catch (_) {
      // Clipboard API rejected (common in WKWebView) — fall through to fallback
    }
  }

  const textarea = document.createElement("textarea");
  textarea.value = clipboardText;
  textarea.setAttribute("readonly", "true");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  textarea.style.pointerEvents = "none";
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) {
    throw new Error("Clipboard copy failed");
  }
}

function selectCodePaneContents(targetPane) {
  const codeView = getCMView(targetPane);
  const cmView = codeView?.view;
  if (cmView) {
    cmView.focus();
    cmView.dispatch({
      selection: { anchor: 0, head: cmView.state.doc.length },
      scrollIntoView: true,
    });
    return;
  }

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

function cancelHistoryDetailLoading() {
  if (_historyDetailLoadingTimer) {
    window.clearTimeout(_historyDetailLoadingTimer);
    _historyDetailLoadingTimer = null;
  }
}

function scheduleHistoryDetailLoading(id, message = "Loading selected transaction...", options = {}) {
  cancelHistoryDetailLoading();
  if (!id) return;
  const renderIfCurrent = () => {
    if (state.selectedId !== id || state.selectedRecord?.id === id) {
      return;
    }
    renderLoadingDetail(message);
  };
  if (options.immediate) {
    renderIfCurrent();
    return;
  }
  _historyDetailLoadingTimer = window.setTimeout(() => {
    _historyDetailLoadingTimer = null;
    renderIfCurrent();
  }, DETAIL_LOADING_DELAY_MS);
}

function renderDetail(record, options = {}) {
  if (!els.detailTitle) return;
  cancelHistoryDetailLoading();
  state.loadingDetailId = null;
  if (!options.preserveOriginalToggles) {
    state.showOriginal.request = false;
    state.showOriginal.response = false;
  }
  els.detailTitle.textContent = "Inspector";
  els.detailTags.innerHTML = "";

  const protocolState = inferProtocolState(record);
  const request = record.request || {};
  const response = record.response || null;
  const requestHeaders = normalizedHeaders(request.headers);
  const responseHeaders = normalizedHeaders(response?.headers);
  const notes = Array.isArray(record.notes) ? record.notes : [];

  const attributes = [
    { label: "Method", value: record.method },
    { label: "Path", value: record.path || "/" },
    ["Started", formatTimestamp(record.started_at)],
    ["Duration", `${record.duration_ms} ms`],
    ["Host", record.host],
    ["Request size", formatSize(request.body_size)],
    ["Response size", formatSize(response?.body_size ?? 0)],
    ["MIME type", response?.content_type || request.content_type || "n/a"],
    ["Notes", `${notes.length}`],
    ...(record.color_tag ? [["Color tag", record.color_tag]] : []),
    ...(record.user_note ? [["User note", record.user_note]] : []),
  ];

  els.attributesCount.textContent = String(attributes.length);
  els.protocolStrip.innerHTML = renderProtocolStrip(protocolState);
  els.summaryList.innerHTML = renderSummaryRows(attributes);

  els.requestHeaderCount.textContent = String(requestHeaders.length);
  els.responseHeaderCount.textContent = String(responseHeaders.length);
  els.requestHeadersBody.innerHTML = renderHeaderList(requestHeaders);
  els.responseHeadersBody.innerHTML = response
    ? renderHeaderList(responseHeaders)
    : "<p class=\"empty-copy\">No response headers were captured.</p>";

  const noteParts = [];
  if (record.user_note) {
    noteParts.push(`<p class="user-note-display"><strong>Note:</strong> ${escapeHtml(record.user_note)}</p>`);
  }
  if (notes.length) {
    noteParts.push(...notes.map((note) => `<p>${escapeHtml(note)}</p>`));
  }
  els.notesCard.innerHTML = noteParts.length
    ? noteParts.join("")
    : "<p>No anomalies were recorded for this transaction.</p>";

  renderViewTabs();
  renderMessagePanes();
}

function renderEmptyDetail() {
  cancelHistoryDetailLoading();
  state.selectedRecord = null;
  state.loadingDetailId = null;
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

function renderLoadingDetail(message = "Loading selected transaction...") {
  state.selectedRecord = null;
  state.loadingDetailId = state.selectedId;
  els.detailTitle.textContent = "Inspector";
  els.detailTags.innerHTML = "";
  els.protocolStrip.innerHTML = renderProtocolStrip({ current: "HTTP/1", supportsHttp2: false });
  els.attributesCount.textContent = "1";
  els.requestHeaderCount.textContent = "0";
  els.responseHeaderCount.textContent = "0";
  els.summaryList.innerHTML = renderSummaryRows([
    { label: "Status", value: message },
  ]);
  els.requestHeadersBody.innerHTML = `<p class="empty-copy">${escapeHtml(message)}</p>`;
  els.responseHeadersBody.innerHTML = "<p class=\"empty-copy\">Loading response details.</p>";
  els.notesCard.innerHTML = "<p>No anomalies were recorded for this transaction.</p>";
  renderViewTabs();
  renderMessagePanes();
}

function renderMessagePanes() {
  const record = state.selectedRecord;
  const detailLoading = Boolean(state.selectedId && state.loadingDetailId === state.selectedId);
  const requestRecord = record && state.showOriginal.request && record.original_request
    ? { ...record, request: record.original_request }
    : record;
  const responseRecord = record && state.showOriginal.response && record.original_response
    ? { ...record, response: record.original_response }
    : record;
  const requestText = requestRecord
    ? buildMessagePresentation("request", requestRecord)
    : (detailLoading ? "Loading selected transaction..." : "Select a transaction from HTTP.");
  const responseText = responseRecord
    ? buildMessagePresentation("response", responseRecord)
    : (detailLoading ? "Loading response details." : "No response selected.");

  const reqMode = state.messageViews.request;
  const resMode = state.messageViews.response;
  // Map view mode to CM highlight mode: pretty/raw → http, hex → hex, diff → diff
  const cmMode = (m) => (m === "hex" ? "hex" : m === "diff" ? "diff" : "http");
  const requestPane = els.requestViewCM
    ? updateCodePaneCM("request", els.requestViewCM, requestText, { mode: cmMode(reqMode), search: state.messageSearch.request })
    : (els.requestView && els.requestLines ? updateCodePane(els.requestView, els.requestLines, requestText, reqMode, "request") : null);
  const responsePane = els.responseViewCM
    ? updateCodePaneCM("response", els.responseViewCM, responseText, { mode: cmMode(resMode), search: state.messageSearch.response })
    : (els.responseView && els.responseLines ? updateCodePane(els.responseView, els.responseLines, responseText, resMode, "response") : null);
  if (els.requestSearchInput.value !== state.messageSearch.request) {
    els.requestSearchInput.value = state.messageSearch.request;
  }
  if (els.responseSearchInput.value !== state.messageSearch.response) {
    els.responseSearchInput.value = state.messageSearch.response;
  }
  els.requestSearchMeta.innerHTML = requestPane
    ? buildSearchMeta(requestPane.lineCount, state.messageViews.request, requestPane.matchCount)
    : buildSearchMeta(0, state.messageViews.request, 0);
  els.responseSearchMeta.innerHTML = responsePane
    ? buildSearchMeta(responsePane.lineCount, state.messageViews.response, responsePane.matchCount)
    : buildSearchMeta(0, state.messageViews.response, 0);
}

function updateMessagePaneSearch(target) {
  const query = state.messageSearch[target] || "";
  const mode = state.messageViews[target];
  const meta = target === "response" ? els.responseSearchMeta : els.requestSearchMeta;
  const cmView = getCMView(target);
  if (cmView) {
    const result = cmView.applySearch(query);
    if (meta) {
      meta.innerHTML = buildSearchMeta(cmView.view.state.doc.lines, mode, result.matchCount);
    }
    return;
  }

  const viewElement = target === "response" ? els.responseView : els.requestView;
  if (!viewElement) {
    if (meta) meta.innerHTML = buildSearchMeta(0, mode, 0);
    return;
  }
  const result = applyCodeSearch(viewElement, query);
  if (meta) {
    meta.innerHTML = buildSearchMeta(countLines(viewElement.textContent || ""), mode, result.count);
  }
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

function getVisibleRequestInterceptSummaries() {
  return state.interceptInScopeOnly
    ? state.intercepts.filter((item) => isInScopeHost(item.host))
    : state.intercepts;
}

function getVisibleResponseInterceptSummaries() {
  return state.interceptInScopeOnly
    ? state.responseIntercepts.filter((item) => isInScopeHost(item.host))
    : state.responseIntercepts;
}

function reconcileRequestInterceptSelection(visibleIntercepts = getVisibleRequestInterceptSummaries()) {
  const selectedIsVisible = visibleIntercepts.some((item) => item.id === state.selectedInterceptId);
  if (!selectedIsVisible) {
    state.selectedInterceptId = visibleIntercepts[0]?.id ?? null;
    state.selectedInterceptRecord = null;
    state.interceptEditorSeedId = null;
    return;
  }
  if (state.selectedInterceptRecord && state.selectedInterceptRecord.id !== state.selectedInterceptId) {
    state.selectedInterceptRecord = null;
    state.interceptEditorSeedId = null;
  }
}

function reconcileResponseInterceptSelection(visibleIntercepts = getVisibleResponseInterceptSummaries()) {
  const selectedIsVisible = visibleIntercepts.some((item) => item.id === state.selectedResponseInterceptId);
  if (!selectedIsVisible) {
    state.selectedResponseInterceptId = visibleIntercepts[0]?.id ?? null;
    state.selectedResponseInterceptRecord = null;
    state.responseInterceptEditorSeedId = null;
    return;
  }
  if (state.selectedResponseInterceptRecord && state.selectedResponseInterceptRecord.id !== state.selectedResponseInterceptId) {
    state.selectedResponseInterceptRecord = null;
    state.responseInterceptEditorSeedId = null;
  }
}

async function refreshInterceptDetailsForCurrentSelection() {
  const tasks = [];
  if (state.selectedInterceptId && (!state.selectedInterceptRecord || state.selectedInterceptRecord.id !== state.selectedInterceptId)) {
    tasks.push(loadInterceptDetail(state.selectedInterceptId));
  }
  if (state.selectedResponseInterceptId && (!state.selectedResponseInterceptRecord || state.selectedResponseInterceptRecord.id !== state.selectedResponseInterceptId)) {
    tasks.push(loadResponseInterceptDetail(state.selectedResponseInterceptId));
  }
  if (tasks.length) {
    await Promise.all(tasks);
  }
}

async function applyInterceptScopeFilterLocally() {
  reconcileRequestInterceptSelection();
  reconcileResponseInterceptSelection();
  renderIntercepts();
  renderResponseIntercepts();
  updateInterceptQueueBadges();
  await refreshInterceptDetailsForCurrentSelection();
}

function renderIntercepts() {
  const filteredIntercepts = getVisibleRequestInterceptSummaries();
  reconcileRequestInterceptSelection(filteredIntercepts);
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
      const id = row.dataset.id;
      if (state.selectedInterceptId !== id) {
        state.selectedInterceptId = id;
        state.selectedInterceptRecord = null;
        state.interceptEditorSeedId = null;
        renderIntercepts();
      }
      loadInterceptDetail(id).catch((error) => console.error(error));
    });
  });

  if (!state.selectedInterceptRecord) {
    state.interceptEditorSeedId = null;
    els.interceptDetailPath.textContent = "Intercept";
    els.interceptDetailTitle.textContent = "No request selected";
    if (els.interceptRequestCM) {
      setInterceptPaneContent("interceptReq", els.interceptRequestCM, "", {
        mode: "http", readOnly: false,
        placeholder: "Intercepted request will appear here...",
      });
    } else {
      els.interceptRequestEditor.value = "";
      renderInterceptRequestHighlight("");
    }
    els.interceptMeta.textContent = state.runtime?.intercept_enabled
      ? "Intercept is on. New requests will queue here."
      : "Intercept is off. Toggle it on to pause requests before forwarding.";
    els.forwardInterceptButton.disabled = true;
    els.dropInterceptButton.disabled = true;
    return;
  }

  els.interceptDetailPath.textContent = `${state.selectedInterceptRecord.request.scheme.toUpperCase()} / ${state.selectedInterceptRecord.peer_addr}`;
  els.interceptDetailTitle.textContent = `${state.selectedInterceptRecord.request.method} ${state.selectedInterceptRecord.request.host}`;
  if (els.interceptRequestCM) {
    const cv = getCMView("interceptReq");
    const isFocused = cv && cv.view.hasFocus;
    const rawText = buildEditableRawRequest(state.selectedInterceptRecord.request);
    // Re-seeding rewrites the document, which resets search highlights and the
    // match-cycling position, so skip it when the text is already identical.
    const contentDiffers = !cv || cv.getContent() !== rawText;
    if (state.interceptEditorSeedId !== state.selectedInterceptRecord.id || (!isFocused && contentDiffers)) {
      setInterceptPaneContent("interceptReq", els.interceptRequestCM, rawText, {
        mode: "http", readOnly: false,
      });
      state.interceptEditorSeedId = state.selectedInterceptRecord.id;
    }
  } else {
    if (state.interceptEditorSeedId !== state.selectedInterceptRecord.id || document.activeElement !== els.interceptRequestEditor) {
      els.interceptRequestEditor.value = buildEditableRawRequest(state.selectedInterceptRecord.request);
      state.interceptEditorSeedId = state.selectedInterceptRecord.id;
    }
    renderInterceptRequestHighlight(els.interceptRequestEditor.value);
  }
  els.interceptMeta.textContent = [
    state.selectedInterceptRecord.is_websocket ? "WebSocket upgrade" : "HTTP request",
    `queued at ${formatTimestamp(state.selectedInterceptRecord.started_at)}`,
    state.selectedInterceptRecord.request.preview_truncated ? "captured request body is preview-truncated" : "body captured in memory",
  ].join(" · ");
  els.forwardInterceptButton.disabled = false;
  els.dropInterceptButton.disabled = false;
}

function renderWebsocketSessionTable(sortedEntries = getSortedWebsocketEntries()) {
  const windowed = websocketRenderedSessionWindow(sortedEntries);
  scheduleWebsocketQueryBackfill(sortedEntries.length);
  if (els.websocketSearchInput.value !== state.websocketQuery) {
    els.websocketSearchInput.value = state.websocketQuery;
  }
  els.websocketMeta.textContent = buildWebsocketFilterSummary(
    sortedEntries.length,
    windowed.renderedEntries.length,
    state.websocketSessions.length,
    state.websocketPaging?.total ?? state.websocketSessions.length,
    state.websocketPaging?.filteredTotal ?? null,
    Boolean(state.websocketPaging?.hasMore),
    Boolean(state.websocketPaging?.capReached),
    state.websocketQuery,
  );

  updateWebsocketSortIndicators();

  if (!sortedEntries.length) {
    els.websocketTableBody.innerHTML = `
        <tr class="empty-row">
          <td colspan="7">${escapeHtml(
            state.websocketListError
              ? `WebSocket history filter error: ${state.websocketListError}`
              : (state.websocketPaging?.loading
                ? "Loading WebSocket sessions..."
                : (state.websocketSessions.length || websocketFilterIsActive()
              ? (websocketFilterIsActive() && state.websocketPaging?.hasMore
                ? "Loading more matching WebSocket sessions..."
                : (websocketFilterIsActive() && state.websocketPaging?.capReached
                  ? "WebSocket history cap reached for this filter."
                  : "No WebSocket sessions match the current filter."))
              : "No WebSocket sessions have been captured yet."))
          )}</td>
        </tr>
      `;
    return;
  }

  const rows = windowed.renderedEntries
    .map(({ session, index }) => {
      const selected = session.id === state.selectedWebsocketId ? "selected" : "";
      const rowNumber = websocketSessionDisplayNumber(session, index);
      return `
            <tr class="history-row ${selected}" data-id="${session.id}">
              <td>${rowNumber}</td>
              <td>${escapeHtml(session.host)}</td>
              <td>${escapeHtml(session.path)}</td>
              <td>${escapeHtml(formatStatus(session.status))}</td>
              <td>${session.frame_count}</td>
              <td>${session.closed_at == null ? "live" : (session.duration_ms == null ? "closed" : `${session.duration_ms} ms`)}</td>
              <td>${escapeHtml(formatTimestamp(session.started_at))}</td>
            </tr>
          `;
    })
    .join("");
  els.websocketTableBody.innerHTML =
    (windowed.topPadding > 0 ? `<tr class="virtual-spacer"><td colspan="7" style="height:${windowed.topPadding}px;padding:0;border:none"></td></tr>` : "") +
    rows +
    (windowed.bottomPadding > 0 ? `<tr class="virtual-spacer"><td colspan="7" style="height:${windowed.bottomPadding}px;padding:0;border:none"></td></tr>` : "");

  const measuredRow = els.websocketTableBody.querySelector(".history-row");
  const measured = measuredRow?.getBoundingClientRect().height || 0;
  if (measured > 0 && Math.abs(measured - measuredWebsocketSessionRowHeight) >= 1) {
    measuredWebsocketSessionRowHeight = measured;
    renderWebsocketSessionTable(sortedEntries);
    return;
  }
}

function cancelWebsocketDetailLoading() {
  if (_websocketDetailLoadingTimer) {
    window.clearTimeout(_websocketDetailLoadingTimer);
    _websocketDetailLoadingTimer = null;
  }
}

function scheduleWebsocketDetailLoading(id, options = {}) {
  cancelWebsocketDetailLoading();
  if (!id) return;
  const renderIfCurrent = () => {
    if (state.selectedWebsocketId !== id || state.selectedWebsocketRecord?.id === id) {
      return;
    }
    renderWebsocketSessions();
  };
  if (options.immediate) {
    renderIfCurrent();
    return;
  }
  _websocketDetailLoadingTimer = window.setTimeout(() => {
    _websocketDetailLoadingTimer = null;
    renderIfCurrent();
  }, DETAIL_LOADING_DELAY_MS);
}

function renderWebsocketSessions(options = {}) {
  const sortedEntries = getSortedWebsocketEntries();
  if (options.ensureSelectedVisible) {
    ensureWebsocketSessionInView(state.selectedWebsocketId, sortedEntries);
  }
  renderWebsocketSessionTable(sortedEntries);

  if (!state.selectedWebsocketRecord) {
    const detailLoading = Boolean(state.selectedWebsocketId);
    if (!detailLoading) {
      cancelWebsocketDetailLoading();
    }
    const noSessionMsg = state.selectedWebsocketDetailError
      || (detailLoading
        ? "Loading selected WebSocket session..."
        : (state.websocketSessions.length && !sortedEntries.length
          ? "No WebSocket session matches the current filter."
          : "Select a WebSocket session."));
    if (els.websocketHandshakeCM) {
      updateCodePaneCM("wsHandshake", els.websocketHandshakeCM, noSessionMsg, { mode: "http" });
    } else {
      if (els.websocketRequestView) els.websocketRequestView.textContent = noSessionMsg;
      if (els.websocketResponseView) els.websocketResponseView.textContent = "No response selected.";
    }
    els.websocketFramesBody.innerHTML = `
      <tr class="empty-row">
        <td colspan="5">${
        state.selectedWebsocketDetailError
          ? "Select the session again or wait for the next refresh."
          : (detailLoading
            ? "Loading captured frames..."
            : (state.websocketSessions.length && !sortedEntries.length
              ? "Clear or adjust the filter to inspect captured frames."
              : "Frame capture will appear here after a WebSocket handshake completes."))
        }</td>
      </tr>
    `;
    updateWsHandshakeLineNumbers();
    updateWsHandshakeSearch();
    return;
  }

  cancelWebsocketDetailLoading();
  const session = state.selectedWebsocketRecord;
  const reqText = buildRawWebsocketRequest(session);
  const resText = buildRawWebsocketResponse(session);
  // Preserve current handshake tab selection (default to Request)
  const resBtn = document.getElementById("wsHandshakeResBtn");
  const showingResponse = resBtn?.classList.contains("active");
  const activeHandshakeText = showingResponse ? resText : reqText;

  // CM path
  if (els.websocketHandshakeCM) {
    updateCodePaneCM("wsHandshake", els.websocketHandshakeCM, activeHandshakeText, { mode: "http" });
    // Hide legacy views
    if (els.websocketRequestView) els.websocketRequestView.classList.add("hidden");
    if (els.websocketResponseView) els.websocketResponseView.classList.add("hidden");
    // Apply handshake search via CM
    const query = (els.wsHandshakeSearchInput?.value || "").trim();
    if (query) {
      const cv = getCMView("wsHandshake");
      if (cv) cv.applySearch(query);
    }
  } else {
    // Legacy fallback
    const savedReqFocus = window._saveCodeViewFocus?.(els.websocketRequestView);
    const savedResFocus = window._saveCodeViewFocus?.(els.websocketResponseView);
    els.websocketRequestView.innerHTML = renderHttpHtml(reqText, "request");
    els.websocketResponseView.innerHTML = renderHttpHtml(resText, "response");
    window._restoreCodeViewFocus?.(els.websocketRequestView, savedReqFocus);
    window._restoreCodeViewFocus?.(els.websocketResponseView, savedResFocus);
    els.websocketRequestView.classList.toggle("hidden", !!showingResponse);
    els.websocketResponseView.classList.toggle("hidden", !showingResponse);
    updateWsHandshakeSearch();
  }
  // Update line numbers for active handshake view
  const hsLineCount = countLines(activeHandshakeText);
  if (els.wsHandshakeLines) {
    els.wsHandshakeLines.textContent = buildLineNumbers(hsLineCount);
  }
  if (els.websocketHandshakeCM) {
    updateWsHandshakeSearch();
  }
  renderWebsocketFrameTable();
}

function renderWebsocketFrameTable() {
  const session = state.selectedWebsocketRecord;
  if (!session) return;

  const frames = getWebsocketFrames(session);
  if (
    state.selectedFrameIdx != null
    && !frames.some((frame) => frame.index === state.selectedFrameIdx)
  ) {
    state.selectedFrameIdx = null;
    hideFrameDetail();
  }
  const fullFrameCount = Number.isFinite(Number(session.frame_count))
    ? Number(session.frame_count)
    : frames.length;
  const firstLoadedFrameIndex = frames.length ? Number(frames[0]?.index) : 0;
  const firstRetainedFrameIndex = websocketFirstRetainedFrameIndex(session, frames);
  const loadableOlderFrameCount = Number.isFinite(firstLoadedFrameIndex)
    ? Math.max(0, firstLoadedFrameIndex - firstRetainedFrameIndex)
    : Math.max(0, fullFrameCount - frames.length);
  const discardedOlderFrameCount = Math.max(0, firstRetainedFrameIndex);
  const olderFrameCount = loadableOlderFrameCount + discardedOlderFrameCount;
  const canLoadOlderFrames = loadableOlderFrameCount > 0 && !session.older_frames_exhausted;
  const olderFramesLoading = !!session.older_frames_loading;
  const olderFrameNotice = [
    loadableOlderFrameCount > 0 ? `${loadableOlderFrameCount} older not loaded` : "",
    discardedOlderFrameCount > 0 ? `${discardedOlderFrameCount} discarded by retention` : "",
    frames.length >= WEBSOCKET_MAX_LOADED_FRAMES && fullFrameCount > frames.length
      ? `${WEBSOCKET_MAX_LOADED_FRAMES}-frame browser cache active`
      : "",
  ].filter(Boolean).join(", ");
  const hasFrameWindowNotice = (session.frames_truncated || olderFrameCount > 0) && olderFrameCount > 0;
  const frameWindow = websocketRenderedFrameWindow(frames, {
    leadingHeight: hasFrameWindowNotice
      ? (measuredWebsocketFrameRowHeight || WEBSOCKET_FRAME_ROW_HEIGHT)
      : 0,
  });
  const renderedFrames = frameWindow.renderedFrames;
  const framePositions = new Map(frames.map((frame, index) => {
    const frameIndex = Number(frame.index);
    return [
      frame.index,
      Number.isFinite(frameIndex) ? frameIndex + 1 : olderFrameCount + index + 1,
    ];
  }));
  const frameWindowNotice = hasFrameWindowNotice
    ? `
          <tr class="ws-frame-window-row">
            <td colspan="5">
              Showing ${frames.length} loaded frame(s) (${olderFrameNotice}).
              ${canLoadOlderFrames
                ? `<button type="button" class="link-button${olderFramesLoading ? " disabled" : ""}" data-ws-load-older-frames ${olderFramesLoading ? "disabled" : ""}>${olderFramesLoading ? "Loading..." : "Load older frames"}</button>`
                : ""}
            </td>
          </tr>`
    : "";
  const frameTopSpacer = frameWindow.topPadding > 0
    ? `<tr class="virtual-spacer"><td colspan="5" style="height:${frameWindow.topPadding}px;padding:0;border:none"></td></tr>`
    : "";
  const frameBottomSpacer = frameWindow.bottomPadding > 0
    ? `<tr class="virtual-spacer"><td colspan="5" style="height:${frameWindow.bottomPadding}px;padding:0;border:none"></td></tr>`
    : "";
  els.websocketFramesBody.innerHTML = frames.length
    ? frameWindowNotice + frameTopSpacer + renderedFrames
        .map((frame) => {
          const dir = frame.direction === "client_to_server" ? "\u2192" : "\u2190";
          const dirClass = frame.direction === "client_to_server" ? "dir-client" : "dir-server";
          return `
          <tr class="history-row${frame.index === state.selectedFrameIdx ? ' frame-selected' : ''}" data-frame-index="${frame.index}">
            <td class="cell-narrow">${framePositions.get(frame.index) || ""}</td>
            <td class="cell-narrow ${dirClass}">${dir}</td>
            <td class="cell-narrow">${frame.kind}</td>
            <td class="cell-narrow">${escapeHtml(formatSize(frame.body_size))}</td>
            <td class="cell-url">${escapeHtml(renderFramePreview(frame))}</td>
          </tr>`;
        })
        .join("") + frameBottomSpacer
    : `
        <tr class="empty-row">
          <td colspan="5">No frames recorded yet.</td>
        </tr>
      `;

  const measuredRow = els.websocketFramesBody.querySelector(".history-row");
  const measured = measuredRow?.getBoundingClientRect().height || 0;
  if (measured > 0 && Math.abs(measured - measuredWebsocketFrameRowHeight) >= 1) {
    measuredWebsocketFrameRowHeight = measured;
    renderWebsocketFrameTable();
  }
}

function selectWebsocketFrameRow(row) {
  const frameIndex = parseInt(row?.dataset?.frameIndex ?? "", 10);
  if (!Number.isFinite(frameIndex)) {
    return false;
  }
  const frames = getWebsocketFrames(state.selectedWebsocketRecord);
  const frame = frames.find((candidate) => candidate.index === frameIndex);
  if (!frame) {
    return false;
  }

  state.selectedFrameIdx = frame.index;
  state.wsKeyboardFocus = "frames";
  els.websocketFramesBody.querySelectorAll(".frame-selected").forEach((item) => item.classList.remove("frame-selected"));
  row.classList.add("frame-selected");
  showFrameDetail(frame);
  return true;
}

function buildWebsocketFilterSummary(visibleCount, renderedCount, loadedCount, totalCount, filteredCount, hasMore, capReached, query) {
  const visibleLabel = renderedCount < visibleCount
    ? `${renderedCount}/${visibleCount} session(s) shown`
    : `${visibleCount} session(s) visible`;
  const parts = [visibleLabel];
  const filters = [];
  if (state.websocketInScopeOnly) filters.push("in scope");
  if (state.websocketLiveOnly) filters.push("live only");
  if (query) filters.push(query);
  if (filters.length) parts.push(`filter: ${filters.join(", ")}`);
  if (isKnownCount(filteredCount)) {
    parts.push((hasMore || capReached)
      ? `${loadedCount}/${filteredCount} matching sessions loaded${capReached ? " (cap reached)" : ""}`
      : `${filteredCount} matching of ${totalCount || filteredCount} total`);
  } else if (totalCount) {
    parts.push((hasMore || capReached)
      ? `${loadedCount}/${totalCount} sessions loaded${capReached ? " (cap reached)" : ""}`
      : `${totalCount} retained`);
  } else {
    parts.push("No sessions captured yet");
  }
  return parts.join(" · ");
}

function centeredWindow(items, selectedPosition, maxItems) {
  if (!Array.isArray(items) || items.length <= maxItems) {
    return items || [];
  }
  const fallbackStart = 0;
  const halfWindow = Math.floor(maxItems / 2);
  const position = Number.isFinite(selectedPosition) && selectedPosition >= 0
    ? selectedPosition
    : fallbackStart;
  const start = Math.max(
    0,
    Math.min(position - halfWindow, items.length - maxItems),
  );
  return items.slice(start, start + maxItems);
}

function websocketRenderedSessionWindow(entries) {
  if (!Array.isArray(entries) || !entries.length) {
    return {
      renderedEntries: [],
      startIdx: 0,
      endIdx: 0,
      topPadding: 0,
      bottomPadding: 0,
    };
  }
  const shell = document.querySelector("#websocketTable")?.closest(".history-table-shell");
  const rowHeight = measuredWebsocketSessionRowHeight || WEBSOCKET_SESSION_ROW_HEIGHT;
  if (!shell || entries.length <= WEBSOCKET_MAX_RENDERED_SESSION_ROWS) {
    return {
      renderedEntries: entries,
      startIdx: 0,
      endIdx: entries.length,
      topPadding: 0,
      bottomPadding: 0,
    };
  }
  const viewportHeight = shell.clientHeight || rowHeight * WEBSOCKET_MAX_RENDERED_SESSION_ROWS;
  const maxScrollTop = Math.max(0, entries.length * rowHeight - viewportHeight);
  const scrollTop = Math.min(shell.scrollTop, maxScrollTop);
  if (shell.scrollTop !== scrollTop) {
    shell.scrollTop = scrollTop;
  }
  const startIdx = Math.max(0, Math.floor(scrollTop / rowHeight) - WEBSOCKET_SESSION_BUFFER_ROWS);
  let endIdx = Math.min(
    entries.length,
    Math.ceil((scrollTop + viewportHeight) / rowHeight) + WEBSOCKET_SESSION_BUFFER_ROWS,
  );
  if (endIdx - startIdx > WEBSOCKET_MAX_RENDERED_SESSION_ROWS) {
    endIdx = startIdx + WEBSOCKET_MAX_RENDERED_SESSION_ROWS;
  }
  return {
    renderedEntries: entries.slice(startIdx, endIdx),
    startIdx,
    endIdx,
    topPadding: startIdx * rowHeight,
    bottomPadding: Math.max(0, (entries.length - endIdx) * rowHeight),
  };
}

function websocketFramesShell() {
  return els.websocketFramesBody?.closest(".history-table-shell") || null;
}

function resetWebsocketFrameScroll() {
  const shell = websocketFramesShell();
  if (shell) {
    shell.scrollTop = 0;
  }
}

function ensureWebsocketFramePositionInView(position, options = {}) {
  const shell = websocketFramesShell();
  if (!shell || !Number.isFinite(position) || position < 0) {
    return false;
  }
  const rowHeight = measuredWebsocketFrameRowHeight || WEBSOCKET_FRAME_ROW_HEIGHT;
  const noticeRow = els.websocketFramesBody?.querySelector(".ws-frame-window-row") || null;
  const leadingHeight = noticeRow?.getBoundingClientRect().height || 0;
  const rowTop = leadingHeight + position * rowHeight;
  const rowBottom = rowTop + rowHeight;
  const viewTop = shell.scrollTop;
  const viewBottom = viewTop + shell.clientHeight;
  if (options.center) {
    shell.scrollTop = Math.max(0, rowTop - shell.clientHeight / 2);
    return true;
  }
  if (rowTop < viewTop) {
    shell.scrollTop = rowTop;
    return true;
  }
  if (rowBottom > viewBottom) {
    shell.scrollTop = Math.max(0, rowBottom - shell.clientHeight);
    return true;
  }
  return true;
}

function websocketRenderedFrameWindow(frames, options = {}) {
  if (!Array.isArray(frames) || !frames.length) {
    return {
      renderedFrames: [],
      startIdx: 0,
      endIdx: 0,
      topPadding: 0,
      bottomPadding: 0,
    };
  }
  const shell = websocketFramesShell();
  const rowHeight = measuredWebsocketFrameRowHeight || WEBSOCKET_FRAME_ROW_HEIGHT;
  const leadingHeight = Math.max(0, Number(options.leadingHeight || 0) || 0);
  if (!shell || frames.length <= WEBSOCKET_MAX_RENDERED_FRAME_ROWS) {
    return {
      renderedFrames: frames,
      startIdx: 0,
      endIdx: frames.length,
      topPadding: 0,
      bottomPadding: 0,
    };
  }
  const viewportHeight = shell.clientHeight || rowHeight * WEBSOCKET_MAX_RENDERED_FRAME_ROWS;
  const maxScrollTop = Math.max(0, leadingHeight + frames.length * rowHeight - viewportHeight);
  const scrollTop = Math.min(shell.scrollTop, maxScrollTop);
  if (shell.scrollTop !== scrollTop) {
    shell.scrollTop = scrollTop;
  }
  const frameScrollTop = Math.max(0, scrollTop - leadingHeight);
  const startIdx = Math.max(0, Math.floor(frameScrollTop / rowHeight) - WEBSOCKET_FRAME_BUFFER_ROWS);
  let endIdx = Math.min(
    frames.length,
    Math.ceil((frameScrollTop + viewportHeight) / rowHeight) + WEBSOCKET_FRAME_BUFFER_ROWS,
  );
  if (endIdx - startIdx > WEBSOCKET_MAX_RENDERED_FRAME_ROWS) {
    endIdx = startIdx + WEBSOCKET_MAX_RENDERED_FRAME_ROWS;
  }
  return {
    renderedFrames: frames.slice(startIdx, endIdx),
    startIdx,
    endIdx,
    topPadding: startIdx * rowHeight,
    bottomPadding: Math.max(0, (frames.length - endIdx) * rowHeight),
  };
}

function getVisibleWebsocketSessions() {
  return Array.isArray(state.websocketSessions) ? state.websocketSessions : [];
}

function getSortedWebsocketEntries() {
  return getVisibleWebsocketSessions().map((session, index) => ({ session, index }));
}

function websocketSessionDisplayNumber(session, loadedIndex = 0) {
  const sequence = Number(session?.sequence);
  if (Number.isFinite(sequence) && sequence > 0) {
    return Math.floor(sequence);
  }
  const fallback = Number(loadedIndex);
  return Number.isFinite(fallback) && fallback >= 0 ? Math.floor(fallback) + 1 : "";
}

function defaultWebsocketSortDirection(key) {
  return ["index", "started_at", "status", "frame_count", "duration_ms"].includes(key) ? "desc" : "asc";
}

function toggleWebsocketSort(key) {
  const sortKey = sanitizeWebsocketSortKey(key);
  if (state.websocketSortKey === sortKey) {
    state.websocketSortDirection = state.websocketSortDirection === "asc" ? "desc" : "asc";
  } else {
    state.websocketSortKey = sortKey;
    state.websocketSortDirection = defaultWebsocketSortDirection(sortKey);
  }
  scheduleUiSettingsSave();
  clearWebsocketQueryBackfill();
  clearWebsocketSelectionPreview({ render: true });
  loadWebsocketsPageRefresh(false, { resetWindow: true }).catch((error) => console.error(error));
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

async function syncVisibleWebsocketSelection(preserveSelection = true, options = {}) {
  const renderOptions = { ensureSelectedVisible: options.ensureSelectedVisible === true };
  const deferStaleDetail = options.deferStaleDetail === true;
  const previousSelectedId = state.selectedWebsocketId;
  const visibleSessions = getVisibleWebsocketSessions();
  const selectedIsVisible = visibleSessions.some((item) => item.id === state.selectedWebsocketId);
  const selectionCanStayWindowed = preserveSelection
    && !selectedIsVisible
    && Boolean(state.selectedWebsocketId)
    && state.selectedWebsocketRecord?.id === state.selectedWebsocketId
    && websocketLoadedWindowCanHideSelection()
    && websocketSummaryMatchesCurrentQuery(state.selectedWebsocketRecord);
  if (!preserveSelection || (!selectedIsVisible && !selectionCanStayWindowed)) {
    state.selectedWebsocketId = visibleSessions[0]?.id ?? null;
  }
  if (previousSelectedId !== state.selectedWebsocketId) {
    state.selectedFrameIdx = null;
    state.selectedWebsocketDetailError = "";
    hideFrameDetail();
    resetWebsocketFrameScroll();
  }

  if (!state.selectedWebsocketId) {
    state.selectedWebsocketRecord = null;
    state.selectedWebsocketDetailError = "";
    renderWebsocketSessions(renderOptions);
    return;
  }

  if (state.selectedWebsocketRecord?.id !== state.selectedWebsocketId) {
    state.selectedWebsocketRecord = null;
    state.selectedWebsocketDetailError = "";
  }
  const selectedSummary = visibleSessions.find((item) => item.id === state.selectedWebsocketId);
  const selectedRefreshTarget = _websocketDetailRefreshNeeded?.id === state.selectedWebsocketId
    ? _websocketDetailRefreshNeeded
    : null;
  const selectedDetailMissesRefreshTarget = Boolean(
    selectedRefreshTarget
    && !selectedWebsocketDetailMeetsRefreshTarget(selectedRefreshTarget),
  );
  const selectedDetailIsStale = Boolean(
    state.selectedWebsocketRecord
    && (
      selectedDetailMissesRefreshTarget
      || (selectedSummary && (
      Number(state.selectedWebsocketRecord.frame_count || 0) !== Number(selectedSummary.frame_count || 0)
      || Number(state.selectedWebsocketRecord.loaded_last_frame_index ?? -1) !== Number(selectedSummary.last_frame_index ?? -1)
      || state.selectedWebsocketRecord.status !== selectedSummary.status
      || (state.selectedWebsocketRecord.closed_at || null) !== (selectedSummary.closed_at || null)
      || (state.selectedWebsocketRecord.duration_ms ?? null) !== (selectedSummary.duration_ms ?? null)
      ))
    )
  );
  renderWebsocketSessions(renderOptions);
  if (selectedDetailIsStale && deferStaleDetail) {
    scheduleSelectedWebsocketDetailRefresh(
      state.selectedWebsocketId,
      selectedRefreshTarget?.lastFrameIndex ?? selectedSummary?.last_frame_index ?? null,
    );
    return;
  }
  if (!state.selectedWebsocketRecord || selectedDetailIsStale) {
    await loadWebsocketDetail(state.selectedWebsocketId);
  }
}

function websocketLoadedWindowCanHideSelection() {
  const paging = state.websocketPaging || createWebsocketPagingState();
  const loadedCount = Array.isArray(state.websocketSessions) ? state.websocketSessions.length : 0;
  const total = Number(paging.total);
  return Boolean(paging.hasMore || paging.capReached)
    || (Number.isFinite(total) && loadedCount < total);
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
  if (document.activeElement !== els.proxySettingScopePatterns) {
    els.proxySettingScopePatterns.value = (state.runtime.scope_patterns || []).join("\n");
  }
  if (document.activeElement !== els.proxySettingPassthroughHosts) {
    els.proxySettingPassthroughHosts.value = (state.runtime.passthrough_hosts || []).join("\n");
  }
  if (startup && document.activeElement !== els.proxySettingBindHost) {
    els.proxySettingBindHost.value = startup.proxy_bind_host;
  }
  if (startup && document.activeElement !== els.proxySettingPort) {
    els.proxySettingPort.value = String(startup.proxy_port);
  }
  els.proxySettingsProxyAddr.textContent = state.settings.proxy_addr;
  els.proxySettingsNextProxyAddr.textContent = startup?.proxy_addr || state.settings.proxy_addr;
  els.proxySettingsUiAddr.textContent = state.settings.ui_addr;
  els.proxySettingsCaptureCap.textContent = `${formatSize(state.settings.body_preview_bytes)} preview / ${configuredTransactionEntryLimit()} HTTP entries`;
  els.proxySettingsBootstrap.textContent = state.settings.certificate.special_host_https;
  // Auto Content-Length (local UI setting, not server-side)
  const aclEl = document.getElementById("proxySettingAutoContentLength");
  if (aclEl) aclEl.checked = localStorage.getItem("sniper_auto_content_length") !== "false";

  renderOastSettingsControls({ hydrateValues: true });

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

function renderOastSettingsControls(options = {}) {
  if (!state.runtime) return;
  const hydrateValues = Boolean(options.hydrateValues);
  const oastEnabled = document.getElementById("proxySettingOastEnabled");
  const oastProvider = document.getElementById("proxySettingOastProvider");
  const oastUrl = document.getElementById("proxySettingOastServerUrl");
  const oastToken = document.getElementById("proxySettingOastToken");
  const oastInterval = document.getElementById("proxySettingOastInterval");
  const oastUrlHint = document.getElementById("oastServerUrlHint");
  const oastTokenField = document.getElementById("oastTokenField");
  const tokenConfigured = state.runtime.oast_token === OAST_TOKEN_REDACTION;
  if (hydrateValues && oastEnabled) oastEnabled.checked = Boolean(state.runtime.oast_enabled);
  if (hydrateValues && oastProvider && document.activeElement !== oastProvider) {
    oastProvider.value = state.runtime.oast_provider || "custom";
  }
  if (hydrateValues && oastUrl && document.activeElement !== oastUrl) oastUrl.value = state.runtime.oast_server_url || "";
  if (hydrateValues && oastToken && document.activeElement !== oastToken) {
    oastToken.value = "";
    oastToken.placeholder = tokenConfigured
      ? "Token configured; leave blank to keep it"
      : "Optional token";
  } else if (oastToken) {
    oastToken.placeholder = tokenConfigured
      ? "Token configured; leave blank to keep it"
      : "Optional token";
  }
  if (els.proxySettingOastClearToken) {
    els.proxySettingOastClearToken.disabled = !tokenConfigured || state.oastTokenClearPending;
    els.proxySettingOastClearToken.textContent = state.oastTokenClearPending ? "Clearing" : "Clear";
  }
  if (els.proxySettingOastTokenHint) {
    els.proxySettingOastTokenHint.textContent = state.oastTokenClearPending
      ? "Token will be cleared when settings are saved."
      : tokenConfigured
        ? "Leave blank to keep the saved token, or clear it explicitly."
        : "Enter a token only if your OAST server requires one.";
  }
  if (hydrateValues && oastInterval && document.activeElement !== oastInterval) {
    oastInterval.value = state.runtime.oast_polling_interval_secs || 5;
  }
  // Update UI based on provider
  const prov = oastProvider?.value || state.runtime.oast_provider || "custom";
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
    if (els.replayRequestCM) {
      updateCodePaneCM("replayReq", els.replayRequestCM, "", {
        mode: "http", readOnly: false,
        placeholder: "Paste or type an HTTP request here...",
        onChange: syncReplayRequestTextFromEditor,
      });
    } else {
      if (els.replayRequestEditor) els.replayRequestEditor.value = "";
      renderReplayRequestHighlight("");
    }
    els.replayHostInput.value = "";
    els.replayPortInput.value = "";
    els.replaySchemeSelect.value = "https";
    els.replayResponseMeta.textContent = "No response yet.";
    renderReplayResponseView("Send a request from Replay to capture the response here.");
    updateReplaySearchPane("request", "");
    updateReplaySearchPane("response", "Send a request from Replay to capture the response here.");
    els.sendReplayButton.disabled = true;
    els.cancelReplayButton.disabled = true;
    els.replayBackButton.disabled = true;
    els.replayForwardButton.disabled = true;
    els.replayFollowRedirectButton.classList.add("hidden");
    return;
  }

  syncReplayToolbar(tab);
  const reqMode = state.replayMessageViews.request;
  if (els.replayRequestCM) {
    // CM path for all modes
    if (reqMode === "hex") {
      // Hex mode: read-only hex dump view
      if (!tab.requestBytes) {
        tab.requestBytes = new TextEncoder().encode(tab.requestText);
        tab.requestOriginalBytes = new Uint8Array(tab.requestBytes);
      }
      const hexText = toHexDumpFromBytes(tab.requestBytes);
      updateCodePaneCM("replayReq", els.replayRequestCM, hexText, {
        mode: "hex", readOnly: true,
      });
      updateReplaySearchPane("request", hexText);
    } else {
      // Pretty/Raw mode: editable
      if (tab.requestBytes) {
        tab.requestText = new TextDecoder().decode(tab.requestBytes);
        tab.requestBytes = null;
        tab.requestOriginalBytes = null;
      }
      updateCodePaneCM("replayReq", els.replayRequestCM, tab.requestText, {
        mode: "http", readOnly: false,
        onChange: syncReplayRequestTextFromEditor,
      });
      updateReplaySearchPane("request", tab.requestText);
    }
  } else if (reqMode === "hex") {
    if (els.replayRequestHighlight) els.replayRequestHighlight.removeAttribute("contenteditable");
    if (!tab.requestBytes) {
      tab.requestBytes = new TextEncoder().encode(tab.requestText);
      tab.requestOriginalBytes = new Uint8Array(tab.requestBytes);
    }
    if (els.replayRequestHighlight) {
      els.replayRequestHighlight.innerHTML = renderEditableHexHtml(tab.requestBytes, tab.requestOriginalBytes);
      bindHexByteHandlers(els.replayRequestHighlight, tab);
    }
    updateReplaySearchPane("request", toHexDumpFromBytes(tab.requestBytes));
  } else {
    // Legacy non-CM path
    if (tab.requestBytes) {
      tab.requestText = new TextDecoder().decode(tab.requestBytes);
      if (els.replayRequestEditor) els.replayRequestEditor.value = tab.requestText;
      tab.requestBytes = null;
      tab.requestOriginalBytes = null;
    }
    if (els.replayRequestHighlight && !els.replayRequestHighlight.isContentEditable) {
      els.replayRequestHighlight.setAttribute("contenteditable", "plaintext-only");
    }
    if (els.replayRequestEditor) els.replayRequestEditor.value = tab.requestText;
    renderReplayRequestHighlight(tab.requestText);
    updateReplaySearchPane("request", tab.requestText);
  }

  if (!tab.responseRecord) {
    renderReplayEmptyResponse(tab);
    return;
  }

  // Show/hide Follow button for redirect responses
  const isRedirect = [301, 302, 303, 307, 308].includes(tab.responseRecord.status);
  const hasLocation = normalizedHeaders(tab.responseRecord.response?.headers).some((h) => headerNameEquals(h, "location"));
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
    responseText = rawResponseText;
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

function setReplayRequestEditorText(text, { preserveSelection = true } = {}) {
  const nextText = text || "";
  const cv = getCMView("replayReq");
  if (cv) {
    if (preserveSelection && typeof cv.setContentPreservingSelection === "function") {
      cv.setContentPreservingSelection(nextText);
    } else {
      cv.setContent(nextText);
    }
    return;
  }
  if (els.replayRequestEditor) {
    els.replayRequestEditor.value = nextText;
  }
  if (els.replayRequestHighlight && state.replayMessageViews.request !== "hex") {
    if (preserveSelection) {
      replayHighlightRerender(nextText);
    } else {
      els.replayRequestHighlight.innerHTML = renderCodeHtml(nextText, state.replayMessageViews.request, "request");
    }
  }
}

function syncReplayRequestTextFromEditor(newText) {
  const activeTab = getActiveReplayTab();
  if (!activeTab || activeTab.type === "websocket") {
    return;
  }
  let nextText = newText;
  let parsed = null;
  try {
    parsed = parseEditableRawRequest(
      newText,
      activeTab.baseRequest || createDefaultEditableRequest(),
    );
    if (parsed._normalizedRawText && parsed._normalizedRawText !== newText) {
      nextText = parsed._normalizedRawText;
      setReplayRequestEditorText(nextText, { preserveSelection: true });
    }
  } catch (_error) {
    // Keep partially typed drafts as-is until they are parseable again.
  }
  activeTab.requestText = nextText;
  activeTab.httpVersionMode = replayHttpVersionState(parsed, nextText, activeTab.httpVersionMode);
  activeTab.requestBytes = null;
  activeTab.requestOriginalBytes = null;
  clearReplayResponseForDraftChange(activeTab);
  syncReplayToolbar(activeTab);
  refreshReplayTabLabel(activeTab.id);
  updateReplaySearchPane("request", nextText, { scrollToFirst: false });
  scheduleWorkspaceStateSave();
}

function clearReplayResponseForDraftChange(tab) {
  if (!tab || tab.type === "websocket") return;
  const hadResponseState = !!tab.responseRecord || !!tab.notice;
  tab.responseRecord = null;
  tab.notice = "";
  if (hadResponseState && state.activeTool === "replay" && state.activeReplayTabId === tab.id) {
    renderReplayEmptyResponse(tab);
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
  if (!els.interceptResponseHighlight || !els.interceptResponseEditor) return;
  els.interceptResponseHighlight.innerHTML = renderCodeHtml(text, "pretty", "response");
  els.interceptResponseHighlight.scrollTop = els.interceptResponseEditor.scrollTop;
  els.interceptResponseHighlight.scrollLeft = els.interceptResponseEditor.scrollLeft;
}

function renderFuzzerRequestHighlight(text) {
  if (!els.fuzzerRequestHighlight) {
    return;
  }

  let html = renderCodeHtml(text, "pretty", "request");
  // Highlight $payload$ markers
  html = html.replace(/(\$payload\$)/gi, '<span class="hl-payload-placeholder">$1</span>');
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
let _replayResponseCMMode = null;
function renderReplayResponseView(text) {
  // Use CodeMirror if container exists
  if (els.replayResponseCM) {
    const mode = state.replayMessageViews.response;
    const cmMode = mode === "hex" ? "hex" : mode === "diff" ? "diff" : "http";
    // Recreate if mode changed
    if (_replayResponseCMView && _replayResponseCMMode !== cmMode) {
      _replayResponseCMView.destroy();
      _replayResponseCMView = null;
    }
    if (!_replayResponseCMView) {
      const opts = { readOnly: true };
      if (cmMode === "http") opts.httpHighlight = true;
      else if (cmMode === "hex") opts.hexHighlight = true;
      else if (cmMode === "diff") opts.diffHighlight = true;
      _replayResponseCMView = new SniperCodeView(els.replayResponseCM, opts);
      _replayResponseCMMode = cmMode;
    }
    _replayResponseCMView.setContent(text || "");
    // Apply search
    const query = (state.replayMessageSearch?.response || "").trim();
    _replayResponseCMView.applySearch(query);
    return;
  }
  // Fallback to legacy
  const mode = state.replayMessageViews.response;
  if (els.replayResponseView) els.replayResponseView.innerHTML = renderCodeHtml(text, mode, "response");
}

function renderReplayEmptyResponse(tab) {
  const notice = tab?.notice || "Send a request from Replay to capture the response here.";
  els.replayResponseMeta.textContent = tab?.notice || "No response yet.";
  renderReplayResponseView(notice);
  updateReplaySearchPane("response", notice);
  els.replayFollowRedirectButton.classList.add("hidden");
  renderReplayViewTabs();
}

/** Update only the response pane + meta after a send — preserves request cursor/scroll. */
function renderReplayResponseOnly(tab) {
  if (!tab.responseRecord) {
    renderReplayEmptyResponse(tab);
    return;
  }
  const isRedirect = [301, 302, 303, 307, 308].includes(tab.responseRecord.status);
  const hasLocation = normalizedHeaders(tab.responseRecord.response?.headers).some((h) => headerNameEquals(h, "location"));
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
    responseText = rawResponseText;
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
    if (els.replayRequestCM) {
      // CM path for all modes
      if (mode === "hex") {
        if (!tab.requestBytes) {
          tab.requestBytes = new TextEncoder().encode(tab.requestText);
          tab.requestOriginalBytes = new Uint8Array(tab.requestBytes);
        }
        const hexText = toHexDumpFromBytes(tab.requestBytes);
        updateCodePaneCM("replayReq", els.replayRequestCM, hexText, { mode: "hex", readOnly: true });
        updateReplaySearchPane("request", hexText);
      } else {
        if (tab.requestBytes) {
          tab.requestText = new TextDecoder().decode(tab.requestBytes);
          tab.requestBytes = null;
          tab.requestOriginalBytes = null;
        }
        updateCodePaneCM("replayReq", els.replayRequestCM, tab.requestText, {
          mode: "http",
          readOnly: false,
          onChange: syncReplayRequestTextFromEditor,
        });
        updateReplaySearchPane("request", tab.requestText);
      }
    } else {
      // Legacy non-CM path
      if (mode === "hex") {
        if (els.replayRequestHighlight) els.replayRequestHighlight.removeAttribute("contenteditable");
        if (!tab.requestBytes) {
          tab.requestBytes = new TextEncoder().encode(tab.requestText);
          tab.requestOriginalBytes = new Uint8Array(tab.requestBytes);
        }
        if (els.replayRequestHighlight) {
          els.replayRequestHighlight.innerHTML = renderEditableHexHtml(tab.requestBytes, tab.requestOriginalBytes);
          bindHexByteHandlers(els.replayRequestHighlight, tab);
        }
        updateReplaySearchPane("request", toHexDumpFromBytes(tab.requestBytes));
      } else {
        if (tab.requestBytes) {
          tab.requestText = new TextDecoder().decode(tab.requestBytes);
          if (els.replayRequestEditor) els.replayRequestEditor.value = tab.requestText;
          tab.requestBytes = null;
          tab.requestOriginalBytes = null;
        }
        if (els.replayRequestHighlight && !els.replayRequestHighlight.isContentEditable) {
          els.replayRequestHighlight.setAttribute("contenteditable", "plaintext-only");
        }
        renderReplayRequestHighlight(tab.requestText);
        updateReplaySearchPane("request", tab.requestText);
      }
    }
  }

  if (target === "response") {
    if (!tab.responseRecord) {
      renderReplayEmptyResponse(tab);
      return;
    }
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

function updateReplaySearchPane(target, text, options = {}) {
  const isRequest = target === "request";
  const scrollToFirst = options.scrollToFirst !== false;
  const query = state.replayMessageSearch[target];
  const input = isRequest ? els.replayRequestSearchInput : els.replayResponseSearchInput;
  const meta = isRequest ? els.replayRequestSearchMeta : els.replayResponseSearchMeta;

  if (input && input.value !== query) {
    input.value = query;
  }

  if (!meta) return;

  // CM path for request
  if (isRequest) {
    const cv = getCMView("replayReq");
    if (cv) {
      const result = cv.applySearch(query || "", { scrollToFirst });
      const mode = state.replayMessageViews[target] || "pretty";
      meta.innerHTML = buildSearchMeta(cv.view.state.doc.lines, mode, result.matchCount);
      return;
    }
  }
  // CM path for response (via existing _replayResponseCMView)
  if (!isRequest && _replayResponseCMView) {
    const result = _replayResponseCMView.applySearch(query || "", { scrollToFirst });
    const mode = state.replayMessageViews[target] || "pretty";
    meta.innerHTML = buildSearchMeta(_replayResponseCMView.view.state.doc.lines, mode, result.matchCount);
    return;
  }

  const view = isRequest ? els.replayRequestHighlight : els.replayResponseView;
  if (!view) return;

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
  setReplayTargetInputValidity(validateManualRepeaterTargetInput(
    els.replayHostInput.value,
    els.replayPortInput.value,
  ));
  const versionSelect = document.getElementById("replayHttpVersionSelect");
  if (versionSelect && document.activeElement !== versionSelect) {
    versionSelect.value = normalizeReplayHttpVersion(tab.httpVersionMode || "");
  }
  const sending = isReplayTabSending(tab.id);
  els.sendReplayButton.disabled = sending;
  els.cancelReplayButton.disabled = !sending;
  if (els.replayFollowRedirectButton) {
    els.replayFollowRedirectButton.disabled = sending;
  }
  els.replayBackButton.disabled = sending || !canNavigateReplayHistory(tab, -1);
  els.replayForwardButton.disabled = sending || !canNavigateReplayHistory(tab, 1);
  return target;
}

function normalizeReplayHttpVersion(value) {
  const normalized = String(value || "").trim().toUpperCase();
  if (normalized === "HTTP/1.0" || normalized === "1.0") return "HTTP/1.0";
  if (normalized === "HTTP/1.1" || normalized === "1.1") return "HTTP/1.1";
  if (normalized === "HTTP/2" || normalized === "HTTP/2.0" || normalized === "2" || normalized === "2.0") return "HTTP/2";
  return "";
}

function normalizeReplayHttpVersionMode(value) {
  const raw = String(value ?? "").trim();
  if (!raw || raw.toLowerCase() === "auto") return "";
  return normalizeReplayHttpVersion(raw);
}

function replayHttpVersionFromText(text) {
  const firstLine = (text || "").split(/\r?\n/)[0] || "";
  const match = firstLine.match(/^[A-Z]+\s+\S+\s+(HTTP\/[0-9.]+)$/i);
  return normalizeReplayHttpVersion(match ? match[1] : "");
}

function replayHttpVersionState(request, requestText, mode) {
  return replayHttpVersionFromText(requestText || "")
    || normalizeReplayHttpVersionMode(mode);
}

function replayLegacyHttpVersionState(request, requestText, mode) {
  return replayHttpVersionState(request, requestText, mode)
    || normalizeReplayHttpVersion(request?.http_version || "");
}

function replayEffectiveHttpVersion(request, requestText, mode) {
  return normalizeReplayHttpVersion(request?.http_version || "")
    || replayHttpVersionFromText(requestText || "")
    || normalizeReplayHttpVersionMode(mode)
    || undefined;
}

function replayStoredHttpVersionMode(request, requestText, mode, hasStoredMode) {
  if (hasStoredMode) {
    return normalizeReplayHttpVersionMode(mode);
  }
  return replayLegacyHttpVersionState(request, requestText, mode);
}

function parseReplayHttpVersionToken(token) {
  if (!token) return undefined;
  const normalized = normalizeReplayHttpVersion(token);
  if (!normalized) {
    throw new Error(`Unsupported HTTP version: ${token}`);
  }
  return normalized;
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
        saveMatchReplaceRules().catch((error) => {
          console.error(error);
          showToast(error?.message || "Failed to save rule", "error");
          loadMatchReplaceRules().catch(console.error);
        });
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
  const sessionId = currentSessionId();
  if (!state.targetScopeDirty) {
    state.targetScopeDraft = formatScopePatternsText(state.runtime?.scope_patterns);
  }

  const editorSessionMismatch = state.targetScopeEditorSessionId !== sessionId;
  if (
    (editorSessionMismatch || document.activeElement !== els.targetScopeEditor)
    && els.targetScopeEditor.value !== state.targetScopeDraft
  ) {
    els.targetScopeEditor.value = state.targetScopeDraft;
  }
  if (editorSessionMismatch || document.activeElement !== els.targetScopeEditor) {
    state.targetScopeEditorSessionId = sessionId;
  }

  const siteMap = Array.isArray(state.targetSiteMap) ? state.targetSiteMap : [];
  const liveHosts = new Set(siteMap.map((host) => String(host.host || "")));
  state.targetExpandedHosts = new Set(
    Array.from(state.targetExpandedHosts).filter((host) => liveHosts.has(host)),
  );

  els.targetTree.innerHTML = siteMap.length
    ? siteMap
        .map((host) => {
          const hostName = String(host.host || "");
          const paths = Array.isArray(host.paths) ? host.paths : [];
          const schemes = Array.isArray(host.schemes) ? host.schemes.map(String).filter(Boolean) : [];
          const requestCount = Number.isFinite(Number(host.request_count)) ? Number(host.request_count) : 0;
          const expanded = state.targetExpandedHosts.has(hostName);
          return `
            <section class="target-host-card">
              <button
                class="target-host-toggle ${expanded ? "expanded" : ""}"
                type="button"
                data-target-host="${escapeHtml(hostName)}"
                aria-expanded="${expanded ? "true" : "false"}"
              >
                <div class="target-host-copy">
                  <div class="target-host-title">${escapeHtml(hostName)}</div>
                  <div class="target-path-meta">${requestCount} request(s) · ${paths.length} path(s) · ${escapeHtml(schemes.join(", ") || "http")}</div>
                </div>
                <div class="target-host-actions">
                  <span class="detail-chip ${host.in_scope ? "ok" : "none"}">${host.in_scope ? "In scope" : "Out of scope"}</span>
                  <span class="target-host-chevron" aria-hidden="true">▾</span>
                </div>
              </button>
              <div class="target-path-list" ${expanded ? "" : "hidden"}>
                ${paths.map((path) => {
                  const methods = Array.isArray(path.methods) ? path.methods.map(String) : [];
                  const noteCount = Number.isFinite(Number(path.note_count)) ? Number(path.note_count) : 0;
                  return `
                    <div class="target-path-item">
                      <div class="target-path-title">${escapeHtml(path.path || "/")}</div>
                      <div class="target-path-meta">
                        ${escapeHtml(methods.join(", "))} · ${escapeHtml(formatStatus(path.status))} · ${escapeHtml(formatTimestamp(path.last_seen))}${path.is_websocket ? " · websocket" : ""}${noteCount ? ` · ${noteCount} note(s)` : ""}
                      </div>
                    </div>
                  `;
                }).join("")}
              </div>
            </section>
          `;
        })
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
  if (els.fuzzerRequestCM) {
    // CM path
    const cv = getCMView("fuzzerReq");
    if (!cv || cv.getContent() !== state.fuzzerRequestText) {
      updateCodePaneCM("fuzzerReq", els.fuzzerRequestCM, state.fuzzerRequestText, {
        mode: "http", readOnly: false,
        payloadHighlight: true,
        placeholder: "Paste an HTTP request with $payload$ markers...",
      });
      // Wire onChange to sync state
      const newCv = getCMView("fuzzerReq");
      if (newCv && !newCv._fuzzerOnChangeWired) {
        newCv._fuzzerOnChangeWired = true;
        addCMUpdateListener(newCv.view, (newText) => {
          updateFuzzerRequestText(newText, { userEdit: true });
          scheduleWorkspaceStateSave();
        });
      }
    }
  } else if (els.fuzzerRequestEditor) {
    if (els.fuzzerRequestEditor.value !== state.fuzzerRequestText) {
      els.fuzzerRequestEditor.value = state.fuzzerRequestText;
    }
    renderFuzzerRequestHighlight(state.fuzzerRequestText);
  }
  if (els.fuzzerPayloadsEditor.value !== state.fuzzerPayloadsText) {
    els.fuzzerPayloadsEditor.value = state.fuzzerPayloadsText;
  }
  if (els.startFuzzerButton) {
    els.startFuzzerButton.disabled = !!state.fuzzerRunning;
  }
  if (els.resetFuzzerButton) {
    els.resetFuzzerButton.disabled = !!state.fuzzerRunning;
  }

  const attackRecord = normalizeFuzzerAttackRecord(state.fuzzerAttackRecord);
  state.fuzzerAttackRecord = attackRecord;
  if (attackRecord?.id) {
    state.fuzzerAttackRecordId = attackRecord.id;
  }
  if (!attackRecord) {
    els.fuzzerMeta.textContent = state.fuzzerNotice || "No fuzz run has been started yet.";
    renderEmptyFuzzerResults(state.fuzzerNotice || "Use $payload$ markers in the request template, then click Start.");
    return;
  }

  els.fuzzerMeta.textContent = [
    `${attackRecord.payload_count ?? attackRecord.results.length} payload(s)`,
    `${attackRecord.marker_count ?? 0} marker(s)`,
    attackRecord.status || "completed",
  ].join(" · ");
  renderFuzzerResultsVirtual();
}

function fuzzerSelectionKeyForResult(result, rowIndex) {
  const txId = String(result?.transaction_id || "");
  return txId ? `tx:${txId}` : `row:${rowIndex}`;
}

function fuzzerSelectedResultIndex() {
  const selectionKey = String(state._selectedFuzzerResultKey || "");
  if (!selectionKey) {
    return -1;
  }
  if (selectionKey.startsWith("row:")) {
    const rowIndex = Number(selectionKey.slice(4));
    return Number.isFinite(rowIndex) ? rowIndex : -1;
  }
  if (selectionKey.startsWith("tx:")) {
    const txId = selectionKey.slice(3);
    return jsonArray(state.fuzzerAttackRecord?.results).findIndex((result) => result?.transaction_id === txId);
  }
  return -1;
}

function fuzzerResultsShell() {
  return els.fuzzerResultsBody?.closest(".history-table-shell") || null;
}

function renderEmptyFuzzerResults(message) {
  if (els.fuzzerResultsBody) {
    els.fuzzerResultsBody.innerHTML = `
      <tr class="empty-row">
        <td colspan="6">${escapeHtml(message || "No fuzzer results.")}</td>
      </tr>
    `;
  }
  const shell = fuzzerResultsShell();
  if (shell) {
    shell.scrollTop = 0;
  }
  state._selectedFuzzerResultKey = null;
  hideFuzzerDetailPanel();
}

function renderFuzzerResultsVirtual() {
  const results = jsonArray(state.fuzzerAttackRecord?.results);
  if (!els.fuzzerResultsBody) {
    return;
  }
  if (!results.length) {
    renderEmptyFuzzerResults("No fuzzer results are available for this run.");
    return;
  }
  const shell = fuzzerResultsShell();
  if (!shell) {
    return;
  }

  const rowHeight = measuredFuzzerResultRowHeight || FUZZER_RESULT_ROW_HEIGHT;
  const viewportHeight = shell.clientHeight || rowHeight;
  const totalCount = results.length;
  const maxScrollTop = Math.max(0, totalCount * rowHeight - viewportHeight);
  const scrollTop = Math.min(shell.scrollTop, maxScrollTop);
  if (shell.scrollTop !== scrollTop) {
    shell.scrollTop = scrollTop;
  }

  const startIdx = Math.max(0, Math.floor(scrollTop / rowHeight) - FUZZER_RESULT_BUFFER_ROWS);
  const endIdx = Math.min(totalCount, Math.ceil((scrollTop + viewportHeight) / rowHeight) + FUZZER_RESULT_BUFFER_ROWS);
  const topPadding = startIdx * rowHeight;
  const bottomPadding = Math.max(0, (totalCount - endIdx) * rowHeight);

  const rows = [];
  for (let rowIndex = startIdx; rowIndex < endIdx; rowIndex++) {
    const result = results[rowIndex];
    const resultIndex = Number.isFinite(Number(result.index)) ? Number(result.index) : rowIndex;
    const selectionKey = fuzzerSelectionKeyForResult(result, rowIndex);
    const selectedClass = state._selectedFuzzerResultKey === selectionKey ? " fuzzer-result-selected" : "";
    rows.push(`
      <tr class="fuzzer-result-row${selectedClass}" data-transaction-id="${escapeHtml(result.transaction_id || "")}" data-result-index="${resultIndex}" data-row-index="${rowIndex}">
        <td>${resultIndex + 1}</td>
        <td class="cell-url">${escapeHtml(result.payload)}</td>
        <td>${escapeHtml(formatStatus(result.status))}</td>
        <td>${result.duration_ms == null ? "-" : `${result.duration_ms} ms`}</td>
        <td>${escapeHtml(formatSize(result.response_bytes))}</td>
        <td>${result.transaction_id ? escapeHtml(String(result.transaction_id).slice(0, 8)) : escapeHtml(result.note || "-")}</td>
      </tr>
    `);
  }

  els.fuzzerResultsBody.innerHTML =
    (topPadding > 0 ? `<tr class="virtual-spacer"><td colspan="6" style="height:${topPadding}px;padding:0;border:none"></td></tr>` : "") +
    rows.join("") +
    (bottomPadding > 0 ? `<tr class="virtual-spacer"><td colspan="6" style="height:${bottomPadding}px;padding:0;border:none"></td></tr>` : "");

  const measuredRow = els.fuzzerResultsBody.querySelector(".fuzzer-result-row");
  const measured = measuredRow?.getBoundingClientRect().height || 0;
  if (measured > 0 && Math.abs(measured - rowHeight) >= 1) {
    measuredFuzzerResultRowHeight = measured;
    renderFuzzerResultsVirtual();
  }
}

function scrollFuzzerResultToIndex(rowIndex) {
  const shell = fuzzerResultsShell();
  if (!shell) {
    return;
  }
  const rowHeight = measuredFuzzerResultRowHeight || FUZZER_RESULT_ROW_HEIGHT;
  shell.scrollTop = Math.max(0, rowIndex * rowHeight - shell.clientHeight / 2);
  renderFuzzerResultsVirtual();
}

function selectFuzzerResultIndex(rowIndex, options = {}) {
  const results = jsonArray(state.fuzzerAttackRecord?.results);
  if (rowIndex < 0 || rowIndex >= results.length) {
    return;
  }
  const result = results[rowIndex];
  const txId = String(result?.transaction_id || "");
  const selectionKey = fuzzerSelectionKeyForResult(result, rowIndex);
  state._selectedFuzzerResultKey = selectionKey;

  if (options.scroll !== false) {
    scrollFuzzerResultToIndex(rowIndex);
  } else {
    renderFuzzerResultsVirtual();
  }

  if (txId) {
    showFuzzerResultDetail(txId, selectionKey).catch((err) => console.error(err));
  } else {
    state._fuzzerDetailRecord = null;
    if (els.fuzzerDetailPanel) els.fuzzerDetailPanel.classList.remove("hidden");
    const detailResizer = document.getElementById("fuzzerDetailResizer");
    if (detailResizer) detailResizer.classList.remove("hidden");
    if (els.fuzzerDetailReqCM) updateCodePaneCM("fuzzerDetailReq", els.fuzzerDetailReqCM, result?.note || "No transaction was captured for this payload.", { mode: "http" });
    if (els.fuzzerDetailResCM) updateCodePaneCM("fuzzerDetailRes", els.fuzzerDetailResCM, "", { mode: "http" });
    if (els.fuzzerDetailResponseMeta) els.fuzzerDetailResponseMeta.textContent = "";
  }
}

function selectFuzzerRow(row) {
  if (!row) return;
  const rowIndex = Number.isFinite(Number(row.dataset.rowIndex))
    ? Number(row.dataset.rowIndex)
    : Number(row.dataset.resultIndex);
  selectFuzzerResultIndex(rowIndex, { scroll: false });
}

function normalizeFuzzerAttackRecord(record) {
  if (!record || typeof record !== "object") return null;
  return {
    ...record,
    payload_count: Number.isFinite(Number(record.payload_count)) ? Number(record.payload_count) : jsonArray(record.results).length,
    marker_count: Number.isFinite(Number(record.marker_count)) ? Number(record.marker_count) : 0,
    results: jsonArray(record.results),
  };
}

function setFuzzerAttackRecord(record) {
  const attackRecord = normalizeFuzzerAttackRecord(record);
  state.fuzzerAttackRecord = attackRecord;
  state.fuzzerAttackRecordId = typeof attackRecord?.id === "string" && attackRecord.id
    ? attackRecord.id
    : null;
  return attackRecord;
}

function clearFuzzerAttackRecord() {
  state.fuzzerAttackRecord = null;
  state.fuzzerAttackRecordId = null;
}

function fuzzerWorkspaceAttackRecordId(fuzzerWS, legacyRecord = null) {
  const explicitId = typeof fuzzerWS?.attack_record_id === "string" ? fuzzerWS.attack_record_id : "";
  if (explicitId) return explicitId;
  const legacyId = typeof legacyRecord?.id === "string" ? legacyRecord.id : "";
  return legacyId || null;
}

async function hydrateFuzzerAttackRecordById(recordId, sessionId) {
  if (!recordId) return;
  const expectedSessionId = sessionId || currentSessionId();
  try {
    const response = await fetch(sessionQueryPath(`/api/fuzzer/attacks/${encodeURIComponent(recordId)}`, expectedSessionId));
    if (state.fuzzerAttackRecordId !== recordId || currentSessionId() !== expectedSessionId) {
      return;
    }
    if (response.status === 404) {
      clearFuzzerAttackRecord();
      if (!state.fuzzerNotice || state.fuzzerNotice === "Loading saved fuzzer run...") {
        state.fuzzerNotice = "Saved fuzzer run is no longer available.";
      }
      scheduleWorkspaceStateSave();
      renderFuzzer();
      return;
    }
    await requireOkResponse(response, "Failed to load saved fuzzer run.");
    const detail = await response.json();
    if (state.fuzzerAttackRecordId !== recordId || currentSessionId() !== expectedSessionId) {
      return;
    }
    const attackRecord = setFuzzerAttackRecord(detail);
    if (!attackRecord) {
      return;
    }
    if (state.fuzzerNotice === "Loading saved fuzzer run...") {
      state.fuzzerNotice = "";
    }
    renderFuzzer();
  } catch (error) {
    if (state.fuzzerAttackRecordId !== recordId || currentSessionId() !== expectedSessionId) {
      return;
    }
    console.error(error);
    if (!state.fuzzerNotice || state.fuzzerNotice === "Loading saved fuzzer run...") {
      state.fuzzerNotice = error?.message || "Failed to load saved fuzzer run.";
    }
    renderFuzzer();
  }
}

// ─── Fuzzer result detail panel ────────────────────────────────────────────

let _fuzzerDetailViewModes = { request: "pretty", response: "pretty" };

/** Show request/response detail for a fuzzer result. */
async function showFuzzerResultDetail(transactionId, selectionKey = `tx:${transactionId}`) {
  if (!transactionId || !els.fuzzerDetailPanel) return;

  els.fuzzerDetailPanel.classList.remove("hidden");
  const detailResizer = document.getElementById("fuzzerDetailResizer");
  if (detailResizer) detailResizer.classList.remove("hidden");
  state._fuzzerDetailRecord = null;
  if (els.fuzzerDetailResponseMeta) els.fuzzerDetailResponseMeta.textContent = "";
  updateCodePaneCM("fuzzerDetailReq", els.fuzzerDetailReqCM, "Loading transaction...", { mode: "http" });
  updateCodePaneCM("fuzzerDetailRes", els.fuzzerDetailResCM, "", { mode: "http" });

  try {
    const sessionId = currentSessionId();
    const resp = await fetch(transactionPath(transactionId, sessionId));
    if (sessionId !== currentSessionId()) return;
    if (!resp.ok) {
      if (state._selectedFuzzerResultKey !== selectionKey) return;
      updateCodePaneCM("fuzzerDetailReq", els.fuzzerDetailReqCM, `Failed to load transaction: ${resp.status}`, { mode: "http" });
      updateCodePaneCM("fuzzerDetailRes", els.fuzzerDetailResCM, "", { mode: "http" });
      if (els.fuzzerDetailResponseMeta) els.fuzzerDetailResponseMeta.textContent = "";
      return;
    }
    const record = await resp.json();
    if (state._selectedFuzzerResultKey !== selectionKey || sessionId !== currentSessionId()) return;

    // Store for mode switching
    state._fuzzerDetailRecord = record;

    renderFuzzerDetailPanes(record);
  } catch (err) {
    if (state._selectedFuzzerResultKey !== selectionKey) return;
    updateCodePaneCM("fuzzerDetailReq", els.fuzzerDetailReqCM, `Error: ${err.message}`, { mode: "http" });
    updateCodePaneCM("fuzzerDetailRes", els.fuzzerDetailResCM, "", { mode: "http" });
    if (els.fuzzerDetailResponseMeta) els.fuzzerDetailResponseMeta.textContent = "";
  }
}

function syncFuzzerDetailTabs() {
  document.querySelectorAll(".fuzzer-detail-view-tab").forEach((btn) => {
    const target = btn.dataset.fuzzerDetailTarget;
    const view = btn.dataset.fuzzerDetailView;
    btn.classList.toggle("active", view === _fuzzerDetailViewModes[target]);
  });
}

function renderFuzzerDetailPanes(record) {
  if (!record) return;

  syncFuzzerDetailTabs();

  const reqMode = _fuzzerDetailViewModes.request;
  const resMode = _fuzzerDetailViewModes.response;

  // Request
  const rawReq = buildRawRequest(record);
  let reqText = rawReq;
  if (reqMode === "pretty") {
    const fakeMsg = { content_type: record.request?.content_type };
    reqText = prettyFormat(rawReq, fakeMsg);
  } else if (reqMode === "hex") {
    reqText = toHexDump(rawReq);
  }
  const cmReqMode = reqMode === "hex" ? "hex" : "http";
  if (els.fuzzerDetailReqCM) {
    updateCodePaneCM("fuzzerDetailReq", els.fuzzerDetailReqCM, reqText, { mode: cmReqMode });
  }

  // Response
  if (record.response) {
    const rawRes = buildRawResponse(record);
    let resText = rawRes;
    if (resMode === "pretty") {
      resText = prettyFormat(rawRes, record.response);
    } else if (resMode === "hex") {
      resText = toHexDump(rawRes);
    }
    const cmResMode = resMode === "hex" ? "hex" : "http";
    if (els.fuzzerDetailResCM) {
      updateCodePaneCM("fuzzerDetailRes", els.fuzzerDetailResCM, resText, { mode: cmResMode });
    }
    if (els.fuzzerDetailResponseMeta) {
      els.fuzzerDetailResponseMeta.textContent = `${record.status ?? ""} · ${record.response?.content_type || ""}`;
    }
  } else {
    if (els.fuzzerDetailResCM) {
      updateCodePaneCM("fuzzerDetailRes", els.fuzzerDetailResCM, "No response captured.", { mode: "http" });
    }
    if (els.fuzzerDetailResponseMeta) {
      els.fuzzerDetailResponseMeta.textContent = "";
    }
  }
}

function hideFuzzerDetailPanel() {
  if (els.fuzzerDetailPanel) els.fuzzerDetailPanel.classList.add("hidden");
  const dr = document.getElementById("fuzzerDetailResizer");
  if (dr) dr.classList.add("hidden");
  state._fuzzerDetailRecord = null;
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

  const next = {
    description: "",
    scope: els.matchReplaceScope.value,
    target: els.matchReplaceTarget.value,
    search: els.matchReplaceSearch.value,
    replace: els.matchReplaceReplace.value,
    regex: els.matchReplaceRegex.checked,
    case_sensitive: els.matchReplaceCaseSensitive.checked,
  };
  const changed = rule.description !== next.description
    || rule.scope !== next.scope
    || rule.target !== next.target
    || rule.search !== next.search
    || rule.replace !== next.replace
    || Boolean(rule.regex) !== next.regex
    || Boolean(rule.case_sensitive) !== next.case_sensitive;
  Object.assign(rule, next);
  if (changed) {
    state.matchReplaceDirty = true;
    state.matchReplaceEditorSessionId = currentSessionId();
  }
}

async function deleteSelectedMatchReplaceRule() {
  if (!state.selectedMatchReplaceRuleId) {
    return;
  }

  state.matchReplaceRules = state.matchReplaceRules.filter((rule) => rule.id !== state.selectedMatchReplaceRuleId);
  state.selectedMatchReplaceRuleId = state.matchReplaceRules[0]?.id ?? null;
  renderMatchReplaceRules();
  await saveMatchReplaceRules();
  showToast("Rule deleted");
}

async function saveTargetScope(options = {}) {
  const sessionId = options.sessionId || currentSessionId();
  if (!sessionId) {
    return;
  }
  if (state.targetScopeEditorSessionId && state.targetScopeEditorSessionId !== sessionId) {
    await loadTargetSiteMap(true);
    throw new Error("Scope editor changed sessions. Review the scope and save again.");
  }
  const scopeText = state.targetScopeEditorSessionId === sessionId
    ? els.targetScopeEditor.value
    : state.targetScopeDraft;
  const scopePatterns = String(scopeText || "")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const response = await fetch("/api/runtime", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      session_id: sessionId,
      expected_active_session_id: expectedActiveSessionIdForWrite(sessionId, options),
      scope_patterns: scopePatterns,
    }),
  });
  if (!response.ok) {
    throw new Error(`saveTargetScope failed: ${response.status}`);
  }
  const runtime = await response.json();
  if (sessionId !== currentSessionId()) {
    if (state.targetScopeEditorSessionId === sessionId) {
      state.targetScopeDraft = formatScopePatternsText(runtime?.scope_patterns);
      state.targetScopeDirty = false;
      state.targetScopeEditorSessionId = null;
    }
    return;
  }
  state.runtime = runtime;
  state.targetScopeDraft = formatScopePatternsText(state.runtime?.scope_patterns);
  state.targetScopeDirty = false;
  state.targetScopeEditorSessionId = sessionId;
  if (els.targetScopeEditor.value !== state.targetScopeDraft) {
    els.targetScopeEditor.value = state.targetScopeDraft;
  }
  renderInterceptStatus();
  renderProxySettings();
  if (!options.skipReload) {
    await loadTargetSiteMap();
  }
  invalidateVisibleEntriesCache();
  scheduleRefresh();
}

async function openFuzzerFromReplay() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type === "websocket") {
    throw new Error("Select an HTTP Replay tab before sending to Fuzzer.");
  }
  const request = parseEditableRawRequest(tab.requestText, tab.baseRequest);
  const target = getRepeaterTargetConfig(tab, request);
  invalidateFuzzerRun();
  state.fuzzerBaseRequest = request;
  state.fuzzerSourceTransactionId = tab.sourceTransactionId || null;
  state.fuzzerTarget = normalizeFuzzerTargetOverride(replayTargetOverridePayload(tab, request, target));
  state.fuzzerTargetRequestText = state.fuzzerTarget ? fuzzerTargetAuthorityFromRequestText(tab.requestText) : null;
  state.fuzzerNotice = "";
  state.fuzzerRequestText = tab.requestText;
  state.fuzzerPayloadsText = "";
  clearFuzzerAttackRecord();
  state._selectedFuzzerResultKey = null;
  hideFuzzerDetailPanel();
  setActiveTool("fuzzer");
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

async function openFuzzerFromSelection() {
  const record = await loadSelectedTransactionRecord();

  if (!record) {
    throw new Error("Selected transaction could not be loaded.");
  }
  openFuzzerFromRecord(record);
}

function openFuzzerFromRecord(record) {
  if (record.kind === "tunnel") {
    throw new Error("Tunnel records cannot be sent to Fuzzer.");
  }

  const request = editableRequestFromRecord(record);
  invalidateFuzzerRun();
  state.fuzzerBaseRequest = request;
  state.fuzzerSourceTransactionId = record.id;
  state.fuzzerTarget = null;
  state.fuzzerTargetRequestText = null;
  state.fuzzerNotice = isRequestPreviewTruncated(record)
    ? buildTruncatedBodyNotice(record, "Fuzzer")
    : "";
  state.fuzzerRequestText = buildEditableRawRequest(request);
  state.fuzzerPayloadsText = "";
  clearFuzzerAttackRecord();
  state._selectedFuzzerResultKey = null;
  hideFuzzerDetailPanel();
  setActiveTool("fuzzer");
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

async function sendToSequenceFromSelection() {
  const record = await loadSelectedTransactionRecord();
  if (!record) {
    throw new Error("Selected transaction could not be loaded.");
  }
  await sendRecordToSequence(record);
}

async function sendRecordToSequence(record) {
  if (record.kind === "tunnel") {
    throw new Error("Tunnel records cannot be sent to Sequence.");
  }

  const request = editableRequestFromRecord(record);
  if (!state.editingSequence) {
    if (!(await createNewSequence())) {
      return;
    }
  }
  if (!state.editingSequence) {
    return;
  }
  state.editingSequence.steps.push({
    id: crypto.randomUUID(),
    label: `${request.method} ${request.path}`,
    request,
    source_transaction_id: record.id,
    http_version: normalizeReplayHttpVersion(request.http_version || ""),
    target: null,
    extractions: [],
  });
  markSequenceDraftDirty();
  setActiveTool("sequence");
  if (!(await saveCurrentSequence())) {
    return;
  }
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

function handleSendActionError(error) {
  console.error(error);
  showToast(error?.message || "Failed to send selected item.", "error");
}

function handleClipboardActionError(error) {
  console.error(error);
  showToast(error?.message || "Failed to copy selected item.", "error");
}

function handleReplayActionError(error) {
  console.error(error);
  showToast(error?.message || "Replay action failed.", "error");
}

function initFuzzerResizers() {
  const colHandle = document.getElementById("fuzzerColResizer");
  const rowHandle = document.getElementById("fuzzerRowResizer");
  const topRow = document.querySelector(".fuzzer-top-row");
  const templateCard = document.querySelector(".fuzzer-template-card");
  const payloadsCard = document.querySelector(".fuzzer-payloads-card");

  // Column resizer: template ↔ payloads
  if (colHandle && topRow && templateCard && payloadsCard) {
    colHandle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      const startX = e.clientX;
      const startTemplateW = templateCard.offsetWidth;
      const startPayloadsW = payloadsCard.offsetWidth;
      const totalW = startTemplateW + startPayloadsW;
      document.body.classList.add("pane-resizing-x");
      colHandle.classList.add("active");
      const onMove = (me) => {
        const delta = me.clientX - startX;
        const newTemplateW = Math.max(200, Math.min(totalW - 120, startTemplateW + delta));
        const newPayloadsW = totalW - newTemplateW;
        templateCard.style.flex = `0 0 ${newTemplateW}px`;
        payloadsCard.style.flex = `0 0 ${newPayloadsW}px`;
      };
      const onUp = () => {
        document.body.classList.remove("pane-resizing-x");
        colHandle.classList.remove("active");
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
      };
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
    colHandle.addEventListener("dblclick", () => {
      templateCard.style.flex = "";
      payloadsCard.style.flex = "";
    });
  }

  // Row resizer: top row ↔ results
  if (rowHandle && topRow) {
    rowHandle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      const startY = e.clientY;
      const startH = topRow.offsetHeight;
      const layout = topRow.closest(".fuzzer-layout");
      const layoutH = layout ? layout.offsetHeight : 800;
      document.body.classList.add("pane-resizing-y");
      rowHandle.classList.add("active");
      const onMove = (me) => {
        const delta = me.clientY - startY;
        const newH = Math.max(120, Math.min(layoutH - 200, startH + delta));
        topRow.style.height = `${newH}px`;
      };
      const onUp = () => {
        document.body.classList.remove("pane-resizing-y");
        rowHandle.classList.remove("active");
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
      };
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
    rowHandle.addEventListener("dblclick", () => {
      topRow.style.height = "";
    });
  }

  // Detail resizer: results table ↔ detail panel
  const detailHandle = document.getElementById("fuzzerDetailResizer");
  const detailPanel = els.fuzzerDetailPanel;
  if (detailHandle && detailPanel) {
    detailHandle.addEventListener("mousedown", (e) => {
      e.preventDefault();
      const startY = e.clientY;
      const startH = detailPanel.offsetHeight;
      const parentH = detailPanel.parentElement.offsetHeight;
      document.body.classList.add("pane-resizing-y");
      detailHandle.classList.add("active");
      const onMove = (me) => {
        const delta = startY - me.clientY; // drag up = bigger detail
        const newH = Math.max(100, Math.min(parentH - 100, startH + delta));
        detailPanel.style.flex = `0 0 ${newH}px`;
      };
      const onUp = () => {
        document.body.classList.remove("pane-resizing-y");
        detailHandle.classList.remove("active");
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
      };
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
    detailHandle.addEventListener("dblclick", () => {
      detailPanel.style.flex = "";
    });
  }
}

function resetFuzzer() {
  invalidateFuzzerRun();
  updateFuzzerRequestText(
    state.fuzzerBaseRequest ? buildEditableRawRequest(state.fuzzerBaseRequest) : "",
    { userEdit: true },
  );
  state.fuzzerPayloadsText = "";
  clearFuzzerAttackRecord();
  state.fuzzerNotice = "";
  state._selectedFuzzerResultKey = null;
  hideFuzzerDetailPanel();
  scheduleWorkspaceStateSave();
  renderFuzzer();
}

function updateFuzzerRequestText(text, { userEdit = false } = {}) {
  const normalized = text || "";
  if (state.fuzzerRequestText !== normalized) {
    state.fuzzerRequestText = normalized;
    if (userEdit) markFuzzerDraftChanged();
  }
}

function updateFuzzerPayloadsText(text, { userEdit = false } = {}) {
  const normalized = text || "";
  if (state.fuzzerPayloadsText !== normalized) {
    state.fuzzerPayloadsText = normalized;
    if (userEdit) markFuzzerDraftChanged();
  }
}

function markFuzzerDraftChanged() {
  state.fuzzerDraftVersion = (state.fuzzerDraftVersion || 0) + 1;
  if (state.fuzzerAttackRecord || state.fuzzerAttackRecordId) {
    clearFuzzerAttackRecord();
    state._selectedFuzzerResultKey = null;
    state.fuzzerNotice = "Fuzzer draft changed. Start a new run to see results for the current template.";
    hideFuzzerDetailPanel();
    renderFuzzer();
  }
}

function invalidateFuzzerRun() {
  state.fuzzerRunToken = (state.fuzzerRunToken || 0) + 1;
  state.fuzzerRunning = false;
}

function fuzzerRequestAuthorityFromText(requestText, fallbackRequest = state.fuzzerBaseRequest || createDefaultEditableRequest()) {
  try {
    const request = parseEditableRawRequest(
      requestText,
      fallbackRequest || createDefaultEditableRequest(),
    );
    return { scheme: request.scheme || "https", host: request.host || "" };
  } catch (_error) {
    return null;
  }
}

function fuzzerAuthorityFromSavedValue(value) {
  const text = String(value || "").trim();
  if (!text) {
    return null;
  }
  if (/^https?:\/\//i.test(text)) {
    try {
      const parsed = new URL(text);
      const scheme = parsed.protocol.replace(":", "").toLowerCase();
      if ((scheme !== "http" && scheme !== "https") || !parsed.host) {
        return null;
      }
      return { scheme, host: parsed.host };
    } catch (_error) {
      return null;
    }
  }
  return fuzzerRequestAuthorityFromText(text);
}

function activeFuzzerTargetForRequest(requestText) {
  if (!state.fuzzerTarget) return null;
  if (!state.fuzzerTargetRequestText) return null;
  const original = fuzzerAuthorityFromSavedValue(state.fuzzerTargetRequestText);
  const current = fuzzerRequestAuthorityFromText(requestText);
  if (
    !original
    || !current
    || original.scheme !== current.scheme
    || !httpRequestAuthoritiesEquivalent(original.host, current.host, current.scheme)
  ) {
    return null;
  }
  return normalizeFuzzerTargetOverride(state.fuzzerTarget);
}

function fuzzerTargetAuthorityFromRequestText(requestText, fallbackRequest) {
  const authority = fuzzerRequestAuthorityFromText(requestText || "", fallbackRequest);
  if (!authority || !authority.host) {
    return null;
  }
  return `${authority.scheme}://${authority.host}`;
}

function fuzzerTargetAuthorityFromEditableRequest(request) {
  if (!request || !request.host) {
    return null;
  }
  const scheme = String(request.scheme || "https").toLowerCase();
  if (scheme !== "http" && scheme !== "https") {
    return null;
  }
  return `${scheme}://${request.host}`;
}

function normalizeFuzzerTargetAuthority(value) {
  const authority = fuzzerAuthorityFromSavedValue(value);
  if (!authority || !authority.host) {
    return null;
  }
  return `${authority.scheme}://${authority.host}`;
}

function isCurrentFuzzerRun(runToken, sessionId) {
  return state.fuzzerRunToken === runToken && state.activeSession?.id === sessionId;
}

async function runFuzzerAttack() {
  if (state.fuzzerRunning) {
    return;
  }
  const runToken = (state.fuzzerRunToken || 0) + 1;
  const sessionId = state.activeSession?.id || null;
  state.fuzzerRunToken = runToken;
  state.fuzzerRunning = true;
  renderFuzzer();
  const draftVersion = state.fuzzerDraftVersion || 0;
  try {
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
    const fuzzerReqText = getCMView("fuzzerReq")
      ? getCMView("fuzzerReq").getContent()
      : (els.fuzzerRequestEditor ? els.fuzzerRequestEditor.value : "");
    if (!fuzzerReqText.trim()) {
      clearFuzzerAttackRecord();
      state.fuzzerNotice = "Request template is empty. Paste a raw HTTP request with $payload$ markers, or send one from HTTP History (Command+I).";
      scheduleWorkspaceStateSave();
      renderFuzzer();
      return;
    }

    let template;
    try {
      template = parseEditableRawRequest(fuzzerReqText, fallback);
    } catch (parseErr) {
      clearFuzzerAttackRecord();
      state.fuzzerNotice = parseErr.message || "Failed to parse the request template.";
      scheduleWorkspaceStateSave();
      renderFuzzer();
      return;
    }

    const payloadsText = els.fuzzerPayloadsEditor.value;
    const payloads = splitFuzzerPayloadLines(payloadsText);

    if (payloads.length === 0) {
      clearFuzzerAttackRecord();
      state.fuzzerNotice = "No payloads provided. Enter one payload per line in the Payloads panel.";
      scheduleWorkspaceStateSave();
      renderFuzzer();
      return;
    }

    const target = activeFuzzerTargetForRequest(fuzzerReqText);
    const httpVersion = replayHttpVersionFromText(fuzzerReqText) || undefined;
    const expectedWorkspaceRevision = await flushWorkspaceStateForReplayAction();
    const response = await fetch("/api/fuzzer/attacks", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        session_id: sessionId,
        expected_active_session_id: expectedActiveSessionIdForWrite(sessionId),
        expected_workspace_revision: expectedWorkspaceRevision,
        template,
        payloads,
        source_transaction_id: state.fuzzerSourceTransactionId,
        http_version: httpVersion,
        target,
      }),
    });
    if (!isCurrentFuzzerRun(runToken, sessionId)) {
      return;
    }
    if (!response.ok) {
      const workspaceConflict = await readWorkspaceRevisionConflictPayload(response);
      if (workspaceConflict) {
        handleFuzzerWorkspaceRevisionConflict(workspaceConflict);
        return;
      }
      const notice = await readApiErrorMessage(response, `Fuzzer run failed (${response.status})`);
      if (!isCurrentFuzzerRun(runToken, sessionId)) {
        return;
      }
      const draftUnchanged = (state.fuzzerDraftVersion || 0) === draftVersion;
      if (!draftUnchanged) {
        showToast(notice || "Fuzzer run failed after the draft changed.", "error", 4000);
        return;
      }
      clearFuzzerAttackRecord();
      state.fuzzerNotice = notice;
      scheduleWorkspaceStateSave();
      renderFuzzer();
      return;
    }
    const attackRecord = normalizeFuzzerAttackRecord(await response.json());
    if (!isCurrentFuzzerRun(runToken, sessionId)) {
      return;
    }
    const draftUnchanged = (state.fuzzerDraftVersion || 0) === draftVersion;
    if (!draftUnchanged) {
      clearFuzzerAttackRecord();
      state.fuzzerNotice = "Fuzzer run completed, but the draft changed while it was running. Start again to see current results.";
      state._selectedFuzzerResultKey = null;
      hideFuzzerDetailPanel();
      scheduleWorkspaceStateSave();
      renderFuzzer();
      scheduleRefresh();
      return;
    }
    state.fuzzerBaseRequest = template;
    state.fuzzerTarget = target;
    state.fuzzerTargetRequestText = target ? fuzzerTargetAuthorityFromRequestText(fuzzerReqText) : null;
    state.fuzzerRequestText = fuzzerReqText;
    state.fuzzerPayloadsText = payloadsText;
    state.fuzzerNotice = "";
    state._selectedFuzzerResultKey = null;
    hideFuzzerDetailPanel();
    setFuzzerAttackRecord(attackRecord);
    scheduleWorkspaceStateSave();
    renderFuzzer();
    scheduleRefresh();
  } catch (error) {
    if (!isCurrentFuzzerRun(runToken, sessionId)) {
      return;
    }
    if (error instanceof WorkspaceStateConflictError) {
      handleFuzzerWorkspaceRevisionConflict(error.latest);
      return;
    }
    console.error("Fuzzer run error:", error);
    const draftUnchanged = (state.fuzzerDraftVersion || 0) === draftVersion;
    if (!draftUnchanged) {
      showToast(error?.message || "Fuzzer run failed after the draft changed.", "error", 4000);
      return;
    }
    clearFuzzerAttackRecord();
    state.fuzzerNotice = error?.message || "An unexpected error occurred while starting the fuzzer.";
    scheduleWorkspaceStateSave();
    renderFuzzer();
  } finally {
    if (isCurrentFuzzerRun(runToken, sessionId)) {
      state.fuzzerRunning = false;
      renderFuzzer();
    }
  }
}

function splitFuzzerPayloadLines(text) {
  const normalized = String(text ?? "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  if (normalized.length === 0) return [];
  const lines = normalized.split("\n");
  if (lines.length > 1 && lines[lines.length - 1] === "") {
    lines.pop();
  }
  return lines;
}

/* ─── Sequence/Macro ─── */

function currentSequenceSessionId() {
  return state.activeSession?.id || null;
}

function isCurrentSequenceSession(sessionId) {
  return (state.activeSession?.id || null) === sessionId;
}

function isCurrentSequenceRun(runGeneration, sequenceId, sessionId, draftVersion) {
  return Boolean(
    state.sequenceRunGeneration === runGeneration
    && state.selectedSequenceId === sequenceId
    && isCurrentSequenceSession(sessionId)
    && (state.sequenceDraftVersion || 0) === draftVersion
  );
}

function sequenceSessionPath(path, sessionId) {
  if (!sessionId) return path;
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}session_id=${encodeURIComponent(sessionId)}`;
}

async function loadSequences({ sessionId = currentSequenceSessionId() } = {}) {
  const [defsResp, runsResp] = await Promise.all([
    fetch(sequenceSessionPath("/api/sequences", sessionId)),
    fetch(sequenceSessionPath("/api/sequence-runs?limit=20", sessionId)),
  ]);
  await requireOkResponse(defsResp, "Failed to load sequences.");
  await requireOkResponse(runsResp, "Failed to load sequence runs.");
  const definitions = jsonArray(await defsResp.json());
  const pastRuns = jsonArray(await runsResp.json());
  if (!isCurrentSequenceSession(sessionId)) {
    return false;
  }
  state.sequenceDefinitions = definitions;
  state.sequencePastRuns = pastRuns;
  return true;
}

function handleSequenceActionError(error) {
  console.error(error);
  showToast(error?.message || "Sequence action failed.", "error", 6000);
}

async function createNewSequence() {
  if (!(await flushSequenceDraft())) {
    return false;
  }
  const sessionId = currentSequenceSessionId();
  const def = {
    id: crypto.randomUUID(),
    name: "New Sequence",
    steps: [],
  };
  const response = await fetch("/api/sequences", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      ...def,
      session_id: sessionId,
      expected_active_session_id: expectedActiveSessionIdForWrite(sessionId),
    }),
  });
  if (!isCurrentSequenceSession(sessionId)) {
    return false;
  }
  await requireOkResponse(response, "Failed to create sequence.");
  if (!isCurrentSequenceSession(sessionId)) {
    return false;
  }
  const loaded = await loadSequences({ sessionId });
  if (!loaded) {
    return false;
  }
  state.selectedSequenceId = def.id;
  state.editingSequence = JSON.parse(JSON.stringify(def));
  state.sequenceDirty = false;
  bumpSequenceDraftVersion();
  renderSequencePanel();
  return true;
}

async function selectSequence(id) {
  if (state.selectedSequenceId === id) {
    syncSequenceStepFromDom({ allowInvalidRequests: true });
    return;
  }
  const selectionGeneration = (state.sequenceSelectionGeneration || 0) + 1;
  state.sequenceSelectionGeneration = selectionGeneration;
  if (!(await flushSequenceDraft())) {
    return;
  }
  if (state.sequenceSelectionGeneration !== selectionGeneration) {
    return;
  }
  state.selectedSequenceId = id;
  const def = state.sequenceDefinitions.find((d) => d.id === id);
  state.editingSequence = def ? JSON.parse(JSON.stringify(def)) : null;
  state.sequenceDirty = false;
  bumpSequenceDraftVersion();
  state.sequenceRunResult = null;
  renderSequencePanel();
}

function bumpSequenceDraftVersion() {
  state.sequenceDraftVersion = (state.sequenceDraftVersion || 0) + 1;
}

function markSequenceDraftDirty() {
  state.sequenceDirty = true;
  bumpSequenceDraftVersion();
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
  markSequenceDraftDirty();
  renderSequencePanel();
}

function removeSequenceStep(index) {
  if (!state.editingSequence) return;
  state.editingSequence.steps.splice(index, 1);
  markSequenceDraftDirty();
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
  markSequenceDraftDirty();
  renderSequencePanel();
}

function removeExtractionRule(stepIndex, ruleIndex) {
  if (!state.editingSequence) return;
  const step = state.editingSequence.steps[stepIndex];
  if (!step) return;
  step.extractions.splice(ruleIndex, 1);
  markSequenceDraftDirty();
  renderSequencePanel();
}

function syncSequenceStepFromDom({ allowInvalidRequests = false } = {}) {
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
      step.request_text = reqTextarea.value;
      const httpVersion = replayHttpVersionFromText(reqTextarea.value);
      step.http_version = httpVersion || null;
      try {
        const parsed = parseEditableRawRequest(reqTextarea.value, step.request);
        parsed.http_version = httpVersion || undefined;
        Object.assign(step.request, parsed);
        delete step.request_parse_error;
      } catch (error) {
        step.request_parse_error = error?.message || "Invalid request";
        if (!allowInvalidRequests) {
          throw error;
        }
      }
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

async function saveCurrentSequence({
  render = true,
  preserveSelection = false,
  bypassExpectedActiveSessionGuard = false,
  sessionId: targetSessionId = null,
  skipPostSaveStateSync = false,
} = {}) {
  if (!state.editingSequence) return false;
  syncSequenceStepFromDom({ allowInvalidRequests: true });
  const sessionId = targetSessionId || currentSequenceSessionId();
  const savedId = state.editingSequence.id;
  const selectedBeforeSave = state.selectedSequenceId;
  const draftVersion = state.sequenceDraftVersion || 0;
  const payload = JSON.parse(JSON.stringify(state.editingSequence));
  payload.session_id = sessionId;
  payload.expected_active_session_id = expectedActiveSessionIdForWrite(sessionId, {
    bypassExpectedActiveSessionGuard,
  });
  const response = await fetch("/api/sequences", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!skipPostSaveStateSync && !isCurrentSequenceSession(sessionId)) {
    return false;
  }
  await requireOkResponse(response, "Failed to save sequence.");
  if (!skipPostSaveStateSync && !isCurrentSequenceSession(sessionId)) {
    return false;
  }
  if (skipPostSaveStateSync) {
    if ((state.sequenceDraftVersion || 0) !== draftVersion) {
      state.sequenceDirty = true;
      return false;
    }
    state.sequenceDirty = false;
    return true;
  }
  const loaded = await loadSequences({ sessionId });
  if (!loaded) {
    return false;
  }
  if (state.selectedSequenceId !== selectedBeforeSave) {
    return false;
  }
  if ((state.sequenceDraftVersion || 0) !== draftVersion) {
    state.sequenceDirty = true;
    return false;
  }
  const saved = state.sequenceDefinitions.find((def) => def.id === savedId);
  if (saved && (!preserveSelection || state.selectedSequenceId === savedId)) {
    state.editingSequence = JSON.parse(JSON.stringify(saved));
    state.selectedSequenceId = savedId;
  }
  state.sequenceDirty = false;
  if (render) {
    renderSequencePanel();
  }
  return true;
}

async function flushSequenceDraft(options = {}) {
  if (!state.sequenceDirty || !state.editingSequence) return true;
  return saveCurrentSequence({ render: false, preserveSelection: true, ...options });
}

async function flushSequenceDraftBeforeExternalSessionReload(options = {}) {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    if (!state.sequenceDirty || !state.editingSequence) return true;
    if (await flushSequenceDraft({ ...options, skipPostSaveStateSync: true })) {
      return true;
    }
  }
  return !state.sequenceDirty || !state.editingSequence;
}

async function deleteSequence(id) {
  const sessionId = currentSequenceSessionId();
  const response = await fetch(sessionWritePath(`/api/sequences/${id}`, sessionId), { method: "DELETE" });
  if (!isCurrentSequenceSession(sessionId)) {
    return;
  }
  await requireOkResponse(response, "Failed to delete sequence.");
  if (!isCurrentSequenceSession(sessionId)) {
    return;
  }
  if (state.selectedSequenceId === id) {
    state.selectedSequenceId = null;
    state.editingSequence = null;
    bumpSequenceDraftVersion();
  }
  await loadSequences({ sessionId });
  renderSequencePanel();
}

async function runCurrentSequence() {
  if (!state.editingSequence || state.sequenceRunning) return;
  state.sequenceRunning = true;
  renderSequencePanel();
  const runSequenceId = state.editingSequence.id;
  const sessionId = currentSequenceSessionId();
  const runGeneration = (state.sequenceRunGeneration || 0) + 1;
  state.sequenceRunGeneration = runGeneration;
  let runDraftVersion = null;

  try {
    syncSequenceStepFromDom();
    const saved = await saveCurrentSequence();
    if (!saved) {
      return;
    }
    if (
      state.sequenceRunGeneration !== runGeneration
      || state.selectedSequenceId !== runSequenceId
      || !isCurrentSequenceSession(sessionId)
    ) {
      return;
    }
    runDraftVersion = state.sequenceDraftVersion || 0;

    const runBtn = document.getElementById("runSequenceButton");
    runBtn.disabled = true;
    runBtn.textContent = "Running...";

    const response = await fetch(`/api/sequences/${runSequenceId}/run`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        session_id: sessionId,
        expected_active_session_id: expectedActiveSessionIdForWrite(sessionId),
      }),
    });
    if (!isCurrentSequenceRun(runGeneration, runSequenceId, sessionId, runDraftVersion)) {
      return;
    }
    if (!response.ok) {
      const errText = await readApiErrorMessage(response, `Sequence failed (${response.status})`);
      if (!isCurrentSequenceRun(runGeneration, runSequenceId, sessionId, runDraftVersion)) {
        return;
      }
      showToast(`Sequence failed: ${errText}`, "error");
      return;
    }
    const result = normalizeSequenceRunResult(await response.json());
    if (!isCurrentSequenceRun(runGeneration, runSequenceId, sessionId, runDraftVersion)) {
      return;
    }
    state.sequenceRunResult = result;
    await loadSequences({ sessionId });
    scheduleRefresh();
  } catch (err) {
    const currentRun = runDraftVersion == null
      ? state.sequenceRunGeneration === runGeneration
        && state.selectedSequenceId === runSequenceId
        && isCurrentSequenceSession(sessionId)
      : isCurrentSequenceRun(runGeneration, runSequenceId, sessionId, runDraftVersion);
    if (!currentRun) {
      return;
    }
    showToast(`Sequence error: ${err.message}`, "error");
  } finally {
    if (
      state.sequenceRunGeneration === runGeneration
      && state.selectedSequenceId === runSequenceId
      && isCurrentSequenceSession(sessionId)
    ) {
      state.sequenceRunning = false;
      renderSequencePanel();
    }
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
      selectSequence(row.dataset.seqId).catch(handleSequenceActionError);
    });
  });
  listBody.querySelectorAll(".seq-delete").forEach((btn) => {
    btn.addEventListener("click", () => deleteSequence(btn.dataset.seqDelete).catch(handleSequenceActionError));
  });

  // Editor
  const editing = state.editingSequence;
  const hasSequence = !!editing;
  const sequenceRunning = Boolean(state.sequenceRunning);
  addStepBtn.disabled = !hasSequence;
  saveBtn.disabled = !hasSequence;
  runBtn.disabled = sequenceRunning || !hasSequence || !editing?.steps?.length;
  runBtn.textContent = sequenceRunning ? "Running..." : "Run";
  editorTitle.textContent = hasSequence ? editing.name : "No sequence selected";

  if (hasSequence) {
    stepsContainer.innerHTML = editing.steps.map((step, idx) => {
      const requestForRender = {
        ...(step.request || {}),
        http_version: normalizeReplayHttpVersion(step.http_version || step.request?.http_version || "")
          || step.request?.http_version,
      };
      const reqText = step.request_text ?? buildEditableRawRequest(requestForRender);
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

    if (!stepsContainer._sequenceDraftSyncWired) {
      stepsContainer._sequenceDraftSyncWired = true;
      const markSequenceDirty = () => {
        syncSequenceStepFromDom({ allowInvalidRequests: true });
        markSequenceDraftDirty();
      };
      stepsContainer.addEventListener("input", markSequenceDirty);
      stepsContainer.addEventListener("change", markSequenceDirty);
    }

    stepsContainer.querySelectorAll(".step-remove").forEach((btn) => {
      btn.addEventListener("click", () => {
        syncSequenceStepFromDom({ allowInvalidRequests: true });
        removeSequenceStep(parseInt(btn.dataset.removeStep, 10));
      });
    });
    stepsContainer.querySelectorAll(".ext-add").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        syncSequenceStepFromDom({ allowInvalidRequests: true });
        addExtractionRule(parseInt(btn.dataset.addExt, 10));
      });
    });
    stepsContainer.querySelectorAll(".ext-remove").forEach((btn) => {
      btn.addEventListener("click", () => {
        syncSequenceStepFromDom({ allowInvalidRequests: true });
        removeExtractionRule(parseInt(btn.dataset.step, 10), parseInt(btn.dataset.rule, 10));
      });
    });
  } else {
    stepsContainer.innerHTML = `<div style="padding:20px;color:var(--text-muted);font-size:0.85rem">Select or create a sequence to start building steps.</div>`;
  }

  // Run results
  const run = normalizeSequenceRunResult(state.sequenceRunResult);
  state.sequenceRunResult = run;
  if (run) {
    const stepResults = jsonArray(run.step_results);
    runMeta.textContent = `${run.sequence_name || "Sequence"} — ${run.status || "unknown"} — ${stepResults.length} steps`;
    resultsBody.innerHTML = stepResults.map((sr, i) => {
      const extracted = Object.entries((sr && typeof sr.extracted === "object" && sr.extracted) || {}).map(([k, v]) => `${k}=${v}`).join(", ");
      return `<tr>
        <td>${i + 1}</td>
        <td>${escapeHtml(sr?.label || `Step ${i + 1}`)}</td>
        <td>${sr?.error ? `<span style="color:var(--danger)">${escapeHtml(sr.error)}</span>` : escapeHtml(String(sr?.status ?? "-"))}</td>
        <td>${sr?.duration_ms != null ? `${sr.duration_ms} ms` : "-"}</td>
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

function normalizeSequenceRunResult(run) {
  if (!run || typeof run !== "object") return null;
  return {
    ...run,
    step_results: jsonArray(run.step_results),
  };
}

async function toggleIntercept() {
  if (!state.runtime || _interceptToggleInFlight) {
    return;
  }

  const sessionId = currentSessionId();
  const turningOff = state.runtime.intercept_enabled;
  const previousInterceptEnabled = Boolean(state.runtime.intercept_enabled);
  // Optimistic UI update — render immediately, sync in background
  state.runtime.intercept_enabled = !state.runtime.intercept_enabled;
  const desiredInterceptEnabled = state.runtime.intercept_enabled;
  const requestSeq = ++_interceptToggleRequestSeq;
  _interceptToggleInFlight = true;
  els.interceptStatus.disabled = true;
  renderInterceptStatus();

  try {
    const runtimeResponse = await fetch("/api/runtime", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        session_id: sessionId,
        expected_active_session_id: expectedActiveSessionIdForWrite(sessionId),
        intercept_enabled: desiredInterceptEnabled,
      }),
    });
    await requireOkResponse(runtimeResponse, "Failed to update intercept mode.");
    const runtime = await runtimeResponse.json();
    if (requestSeq !== _interceptToggleRequestSeq || sessionId !== currentSessionId()) {
      return;
    }
    state.runtime = runtime;
    renderInterceptStatus();

    if (turningOff && state.runtime?.intercept_enabled === false) {
      const [requestResponse, responseResponse] = await Promise.all([
        fetch(sessionWritePath("/api/intercepts/forward-all", sessionId), { method: "POST" }),
        fetch(sessionWritePath("/api/response-intercepts/forward-all", sessionId), { method: "POST" }),
      ]);
      await requireOkResponse(requestResponse, "Failed to forward queued requests.");
      await requireOkResponse(responseResponse, "Failed to forward queued responses.");
      if (requestSeq !== _interceptToggleRequestSeq || sessionId !== currentSessionId()) {
        return;
      }
      await Promise.all([loadIntercepts(false), loadResponseIntercepts(false)]);
      if (sessionId === currentSessionId()) {
        scheduleRefresh();
      }
    }
  } catch (error) {
    if (requestSeq !== _interceptToggleRequestSeq || sessionId !== currentSessionId()) {
      return;
    }
    console.error(error);
    showToast(error?.message || "Failed to update intercept mode.", "error");
    if (state.runtime) {
      state.runtime.intercept_enabled = previousInterceptEnabled;
      renderInterceptStatus();
    }
    loadRuntimeSettings().catch(console.error);
    if (turningOff) {
      Promise.all([loadIntercepts(false), loadResponseIntercepts(false)]).catch(console.error);
    }
  } finally {
    if (requestSeq === _interceptToggleRequestSeq) {
      _interceptToggleInFlight = false;
      els.interceptStatus.disabled = false;
      if (sessionId === currentSessionId()) {
        renderInterceptStatus();
      }
    }
  }
}

async function saveProxySettings() {
  const sessionId = currentSessionId();
  const scopePatterns = els.proxySettingScopePatterns.value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  const passthroughHosts = els.proxySettingPassthroughHosts.value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  const bindHost = els.proxySettingBindHost.value.trim();
  const proxyPortText = els.proxySettingPort.value.trim();
  const proxyPort = strictIntegerInRange(proxyPortText, 1, 65535);
  if (!bindHost) {
    throw new Error("Proxy bind host is required.");
  }
  if (!proxyPortText) {
    throw new Error("Proxy port is required.");
  }
  if (proxyPort === null) {
    throw new Error("Proxy port must be an integer between 1 and 65535.");
  }
  if (!isValidIpLiteral(bindHost)) {
    throw new Error("Proxy bind host must be an IPv4 or IPv6 address.");
  }
  const normalizedBindHost = normalizeIpLiteralForSettings(bindHost);
  const startupUpdate = {
    expected_active_session_id: expectedActiveSessionIdForWrite(sessionId),
    proxy_bind_host: normalizedBindHost,
    proxy_port: proxyPort,
  };
  const currentStartup = state.settings?.startup || null;
  const startupChanged = !currentStartup
    || currentStartup.proxy_bind_host !== normalizedBindHost
    || Number(currentStartup.proxy_port) !== proxyPort;
  const oastTokenValue = document.getElementById("proxySettingOastToken")?.value?.trim() || "";
  const oastIntervalText = document.getElementById("proxySettingOastInterval")?.value?.trim() || "";
  const oastInterval = oastIntervalText ? strictIntegerInRange(oastIntervalText, 1, 300) : 5;
  if (oastInterval === null) {
    throw new Error("OAST polling interval must be an integer between 1 and 300 seconds.");
  }
  const oastProvider = document.getElementById("proxySettingOastProvider")?.value || "custom";
  const previousOastProvider = state.runtime?.oast_provider || "custom";
  const oastProviderChanged = oastProvider !== previousOastProvider;
  const oastServerUrl = validateOastServerUrlForSettings(
    document.getElementById("proxySettingOastServerUrl")?.value || "",
  );
  const runtimeUpdate = {
    session_id: sessionId,
    expected_active_session_id: expectedActiveSessionIdForWrite(sessionId),
    intercept_enabled: els.proxySettingIntercept.checked,
    websocket_capture_enabled: els.proxySettingWebsocketCapture.checked,
    upstream_insecure: els.proxySettingUpstreamInsecure.checked,
    scope_patterns: scopePatterns,
    passthrough_hosts: passthroughHosts,
    oast_enabled: document.getElementById("proxySettingOastEnabled")?.checked ?? false,
    oast_provider: oastProvider,
    oast_server_url: oastServerUrl,
    oast_polling_interval_secs: oastInterval,
  };
  if (
    state.oastTokenClearPending ||
    oastProvider === "boast" ||
    (oastProviderChanged && (!oastTokenValue || oastTokenValue === OAST_TOKEN_REDACTION))
  ) {
    runtimeUpdate.oast_token = "";
  } else if (oastProvider !== "boast" && oastTokenValue && oastTokenValue !== OAST_TOKEN_REDACTION) {
    runtimeUpdate.oast_token = oastTokenValue;
  }

  const tokenWillBeUpdated = Object.prototype.hasOwnProperty.call(runtimeUpdate, "oast_token");
  let startupResult = currentStartup;
  if (startupChanged) {
    const startupResponse = await fetch("/api/startup-settings", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(startupUpdate),
    });

    if (!startupResponse.ok) {
      const message = await startupResponse.text();
      if (sessionId === currentSessionId()) {
        try {
          await loadSettings(0);
        } catch (reloadError) {
          console.error(reloadError);
        }
      }
      throw new Error(message);
    }
    startupResult = await startupResponse.json();
  }

  const runtimeResponse = await fetch("/api/runtime", {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(runtimeUpdate),
  });

  if (!runtimeResponse.ok) {
    const message = await runtimeResponse.text();
    if (sessionId === currentSessionId()) {
      try {
        await loadSettings(0);
      } catch (reloadError) {
        console.error(reloadError);
      }
    }
    throw new Error(message);
  }
  const runtimeResult = await runtimeResponse.json();
  if (sessionId !== currentSessionId()) {
    return startupResult;
  }
  state.runtime = runtimeResult;
  state.oastTokenClearPending = false;
  if (startupResult) {
    state.settings.startup = startupResult;
  }

  // If proxy was rebound, update the main proxy_addr in settings too
  if (startupResult?.rebound === true) {
    state.settings.proxy_addr = startupResult.active_proxy_addr;
  }

  renderInterceptStatus();
  renderProxySettings();
  if (tokenWillBeUpdated) {
    const oastTokenInput = document.getElementById("proxySettingOastToken");
    if (oastTokenInput) {
      oastTokenInput.value = "";
    }
  }
  invalidateVisibleEntriesCache();
  scheduleRefresh();
  return startupResult;
}

function isValidIpLiteral(value) {
  const host = String(value || "").trim();
  if (!host) return false;
  if (host.includes(":")) {
    const inner = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
    if (!inner || inner.includes("[") || inner.includes("]")) return false;
    try {
      const parsed = new URL(`http://[${inner}]/`);
      return parsed.hostname.startsWith("[") && parsed.hostname.endsWith("]");
    } catch (_error) {
      return false;
    }
  }
  const octets = host.split(".");
  return octets.length === 4 && octets.every((octet) => {
    if (!/^\d{1,3}$/.test(octet)) return false;
    const value = Number(octet);
    return value >= 0 && value <= 255 && String(value) === octet;
  });
}

function normalizeIpLiteralForSettings(value) {
  const host = String(value || "").trim();
  if (host.startsWith("[") && host.endsWith("]")) {
    return host.slice(1, -1);
  }
  return host;
}

function validateOastServerUrlForSettings(value) {
  const serverUrl = String(value || "").trim();
  if (!serverUrl) return "";
  let parsed;
  try {
    parsed = new URL(serverUrl);
  } catch (_error) {
    throw new Error("OAST server URL is invalid.");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("OAST server URL must use http or https.");
  }
  if (parsed.username || parsed.password) {
    throw new Error("OAST server URL must not include credentials.");
  }
  if (!parsed.hostname) {
    throw new Error("OAST server URL must include a host.");
  }
  if ((parsed.pathname && parsed.pathname !== "/") || parsed.search || parsed.hash) {
    throw new Error("OAST server URL must not include a path, query, or fragment.");
  }
  return serverUrl;
}

async function requireOkResponse(response, fallbackMessage) {
  if (response.ok) return;
  const message = await readApiErrorMessage(response, fallbackMessage);
  throw new Error(message || fallbackMessage);
}

async function readApiErrorMessage(response, fallbackMessage = "") {
  const contentType = response.headers.get("content-type") || "";
  if (contentType.toLowerCase().includes("application/json")) {
    try {
      const payload = await response.clone().json();
      const structured = formatStructuredApiErrorMessage(payload);
      if (structured) return structured;
    } catch (_error) {
      // Fall through to plain text.
    }
  }
  const message = await response.text().catch(() => "");
  return message || fallbackMessage;
}

function formatStructuredApiErrorMessage(payload) {
  if (!payload || typeof payload !== "object") return "";
  const error = typeof payload.error === "string" ? payload.error.trim() : "";
  if (!error) return "";
  const ownerSessionId = typeof payload.owner_session_id === "string" ? payload.owner_session_id.trim() : "";
  if (ownerSessionId) return `${error} (owner_session_id ${ownerSessionId})`;
  const sessionId = typeof payload.session_id === "string" ? payload.session_id.trim() : "";
  if (sessionId) return `${error} (session_id ${sessionId})`;
  return error;
}

async function forwardSelectedIntercept() {
  if (!state.selectedInterceptRecord || state.selectedInterceptRecord.id !== state.selectedInterceptId) {
    return;
  }

  const sessionId = currentSessionId();
  const id = state.selectedInterceptRecord.id;
  const interceptReqText = getCMView("interceptReq")
    ? getCMView("interceptReq").getContent()
    : (els.interceptRequestEditor ? els.interceptRequestEditor.value : "");
  const request = parseEditableRawRequest(
    interceptReqText,
    state.selectedInterceptRecord.request,
  );
  if (state.selectedInterceptRecord.is_websocket && request.body) {
    showToast("WebSocket upgrade requests must not include a request body.", "error");
    return;
  }

  // Optimistic: remove from UI immediately
  state.intercepts = state.intercepts.filter((i) => i.id !== id);
  state.selectedInterceptRecord = null;
  state.interceptEditorSeedId = null;
  state.selectedInterceptId = getVisibleRequestInterceptSummaries()[0]?.id ?? null;
  renderIntercepts();
  updateInterceptQueueBadges();

  try {
    const response = await fetch(sessionWritePath(`/api/intercepts/${id}/forward`, sessionId), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ request }),
    });
    await requireOkResponse(response, "Failed to forward intercepted request.");
    if (sessionId !== currentSessionId()) {
      return;
    }
    await loadIntercepts(true);
    scheduleRefresh();
  } catch (e) {
    if (sessionId !== currentSessionId()) {
      return;
    }
    console.error(e);
    showToast(e?.message || "Failed to forward intercepted request.", "error");
    await loadIntercepts(false).catch(console.error);
  }
}

async function dropSelectedIntercept() {
  if (!state.selectedInterceptRecord || state.selectedInterceptRecord.id !== state.selectedInterceptId) {
    return;
  }

  const sessionId = currentSessionId();
  const id = state.selectedInterceptRecord.id;

  // Optimistic: remove from UI immediately
  state.intercepts = state.intercepts.filter((i) => i.id !== id);
  state.selectedInterceptRecord = null;
  state.interceptEditorSeedId = null;
  state.selectedInterceptId = getVisibleRequestInterceptSummaries()[0]?.id ?? null;
  renderIntercepts();
  updateInterceptQueueBadges();

  try {
    const response = await fetch(sessionWritePath(`/api/intercepts/${id}/drop`, sessionId), { method: "POST" });
    await requireOkResponse(response, "Failed to drop intercepted request.");
    if (sessionId !== currentSessionId()) {
      return;
    }
    await loadIntercepts(true);
    scheduleRefresh();
  } catch (e) {
    if (sessionId !== currentSessionId()) {
      return;
    }
    console.error(e);
    showToast(e?.message || "Failed to drop intercepted request.", "error");
    await loadIntercepts(false).catch(console.error);
  }
}

/* ─── Response Intercept ─── */

async function loadResponseIntercepts(preserveSelection = true) {
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath("/api/response-intercepts", sessionId));
  await requireOkResponse(response, "Failed to load intercepted responses.");
  const responseIntercepts = jsonArray(await response.json());
  if (sessionId !== currentSessionId()) {
    return;
  }
  state.responseIntercepts = responseIntercepts;

  const visibleResponseIntercepts = getVisibleResponseInterceptSummaries();
  if (!preserveSelection || !visibleResponseIntercepts.some((item) => item.id === state.selectedResponseInterceptId)) {
    state.selectedResponseInterceptId = visibleResponseIntercepts[0]?.id ?? null;
    state.selectedResponseInterceptRecord = null;
    state.responseInterceptEditorSeedId = null;
  }

  renderResponseIntercepts();
  updateInterceptQueueBadges();
  // Auto-switch to Response Queue when responses arrive and Request Queue is empty
  if (visibleResponseIntercepts.length > 0 && getVisibleRequestInterceptSummaries().length === 0 && state.interceptQueueTab === "request") {
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
  const sessionId = currentSessionId();
  const response = await fetch(sessionQueryPath(`/api/response-intercepts/${id}`, sessionId));
  if (sessionId !== currentSessionId() || state.selectedResponseInterceptId !== id) {
    return;
  }
  if (!response.ok) {
    state.selectedResponseInterceptRecord = null;
    renderResponseIntercepts();
    return;
  }

  const record = await response.json();
  if (sessionId !== currentSessionId() || state.selectedResponseInterceptId !== id) {
    return;
  }
  state.selectedResponseInterceptRecord = record;
  renderResponseIntercepts();
}

function buildEditableRawResponse(resp) {
  const source = resp || {};
  let text = `HTTP/1.1 ${source.status ?? 200}\r\n`;
  for (const h of normalizedHeaders(source.headers)) {
    text += `${h.name}: ${h.value}\r\n`;
  }
  text += "\r\n";
  if (source.body_encoding === "base64") {
    text += safeDecodeBase64(source.body);
  } else {
    text += source.body || "";
  }
  return text;
}

function parseEditableRawResponse(text, original, requestMethod = "") {
  const { head, body } = splitRawHttpMessage(text);
  const lines = head.split("\n").filter((line) => line.length > 0);
  const statusLine = lines[0] || "";
  const hasStatusLine = /^HTTP\//i.test(statusLine);
  const statusMatch = hasStatusLine ? statusLine.match(/^HTTP\/[0-9.]+\s+(\d{3})(?:\s+.*)?$/i) : null;
  if (hasStatusLine && !statusMatch) {
    throw new Error("Invalid response status line in editor");
  }
  const status = statusMatch ? parseInt(statusMatch[1], 10) : (original?.status || 200);

  const headers = [];
  for (let i = hasStatusLine ? 1 : 0; i < lines.length; i++) {
    const line = lines[i];
    const colonIdx = line.indexOf(":");
    if (colonIdx > 0) {
      headers.push({
        name: line.substring(0, colonIdx).trim(),
        value: line.substring(colonIdx + 1).trim(),
      });
    } else {
      throw new Error(`Invalid response header line: ${line}`);
    }
  }

  const bodyText = body;
  const isText = !original || original.body_encoding === "utf8";
  const bodyEncoding = isText ? "utf8" : "base64";
  const bodyLength = editableResponseBodyLength(bodyText, bodyEncoding);
  if (responseMustNotIncludeBody(status, requestMethod) && bodyLength > 0) {
    throw new Error(`Response status ${status} must not include a body`);
  }
  const allowRepresentationContentLength = responseContentLengthMayDescribeRepresentation(status, requestMethod)
    && bodyLength === 0;

  // Auto-update Content-Length if enabled
  if (document.getElementById("proxySettingAutoContentLength")?.checked && !allowRepresentationContentLength) {
    for (const header of headers) {
      if (headerNameEquals(header, "content-length")) {
        header.value = String(bodyLength);
      }
    }
  }
  validateRawHttpBodyFraming(headers, bodyLength, [bodyLength], {
    allowRepresentationContentLength,
  });

  return {
    status,
    headers,
    body: isText ? bodyText : safeEncodeBase64(bodyText),
    body_encoding: bodyEncoding,
  };
}

function renderResponseIntercepts() {
  const filteredResponseIntercepts = getVisibleResponseInterceptSummaries();
  reconcileResponseInterceptSelection(filteredResponseIntercepts);
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
      const id = row.dataset.id;
      if (state.selectedResponseInterceptId !== id) {
        state.selectedResponseInterceptId = id;
        state.selectedResponseInterceptRecord = null;
        state.responseInterceptEditorSeedId = null;
        renderResponseIntercepts();
      }
      loadResponseInterceptDetail(id).catch((error) => console.error(error));
    });
  });

  if (!state.selectedResponseInterceptRecord) {
    state.responseInterceptEditorSeedId = null;
    if (state.interceptQueueTab === "response") {
      els.interceptDetailPath.textContent = "Response Intercept";
      els.interceptDetailTitle.textContent = "No response selected";
      if (els.interceptResponseCM) {
        setInterceptPaneContent("interceptRes", els.interceptResponseCM, "", {
          mode: "http", readOnly: false,
          placeholder: "Intercepted response will appear here...",
        });
      } else {
        els.interceptResponseEditor.value = "";
        renderInterceptResponseHighlight("");
      }
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
    if (els.interceptResponseCM) {
      const cv = getCMView("interceptRes");
      const isFocused = cv && cv.view.hasFocus;
      const rawText = buildEditableRawResponse(rec.response);
      // See the request pane above: avoid a no-op re-seed that would clear the
      // active search highlights and match position.
      const contentDiffers = !cv || cv.getContent() !== rawText;
      if (state.responseInterceptEditorSeedId !== rec.id || (!isFocused && contentDiffers)) {
        setInterceptPaneContent("interceptRes", els.interceptResponseCM, rawText, {
          mode: "http", readOnly: false,
        });
        state.responseInterceptEditorSeedId = rec.id;
      }
    } else {
      if (state.responseInterceptEditorSeedId !== rec.id || document.activeElement !== els.interceptResponseEditor) {
        els.interceptResponseEditor.value = buildEditableRawResponse(rec.response);
        state.responseInterceptEditorSeedId = rec.id;
      }
      renderInterceptResponseHighlight(els.interceptResponseEditor.value);
    }
    els.interceptMeta.textContent = `Response queued at ${formatTimestamp(rec.started_at)}`;
  }
  els.forwardResponseInterceptButton.disabled = false;
  els.dropResponseInterceptButton.disabled = false;
}

async function forwardSelectedResponseIntercept() {
  if (!state.selectedResponseInterceptRecord || state.selectedResponseInterceptRecord.id !== state.selectedResponseInterceptId) return;

  const sessionId = currentSessionId();
  const id = state.selectedResponseInterceptRecord.id;
  const interceptResText = getCMView("interceptRes")
    ? getCMView("interceptRes").getContent()
    : (els.interceptResponseEditor ? els.interceptResponseEditor.value : "");
  const editedResponse = parseEditableRawResponse(
    interceptResText,
    state.selectedResponseInterceptRecord.response,
    state.selectedResponseInterceptRecord.method,
  );

  // Optimistic UI
  state.responseIntercepts = state.responseIntercepts.filter((i) => i.id !== id);
  state.selectedResponseInterceptRecord = null;
  state.responseInterceptEditorSeedId = null;
  state.selectedResponseInterceptId = getVisibleResponseInterceptSummaries()[0]?.id ?? null;
  renderResponseIntercepts();
  updateInterceptQueueBadges();

  try {
    const response = await fetch(sessionWritePath(`/api/response-intercepts/${id}/forward`, sessionId), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ response: editedResponse }),
    });
    await requireOkResponse(response, "Failed to forward intercepted response.");
    if (sessionId !== currentSessionId()) {
      return;
    }
    await loadResponseIntercepts(true);
    scheduleRefresh();
  } catch (e) {
    if (sessionId !== currentSessionId()) {
      return;
    }
    console.error(e);
    showToast(e?.message || "Failed to forward intercepted response.", "error");
    await loadResponseIntercepts(false).catch(console.error);
  }
}

async function dropSelectedResponseIntercept() {
  if (!state.selectedResponseInterceptRecord || state.selectedResponseInterceptRecord.id !== state.selectedResponseInterceptId) return;

  const sessionId = currentSessionId();
  const id = state.selectedResponseInterceptRecord.id;

  // Optimistic UI
  state.responseIntercepts = state.responseIntercepts.filter((i) => i.id !== id);
  state.selectedResponseInterceptRecord = null;
  state.responseInterceptEditorSeedId = null;
  state.selectedResponseInterceptId = getVisibleResponseInterceptSummaries()[0]?.id ?? null;
  renderResponseIntercepts();
  updateInterceptQueueBadges();

  try {
    const response = await fetch(sessionWritePath(`/api/response-intercepts/${id}/drop`, sessionId), { method: "POST" });
    await requireOkResponse(response, "Failed to drop intercepted response.");
    if (sessionId !== currentSessionId()) {
      return;
    }
    await loadResponseIntercepts(true);
    scheduleRefresh();
  } catch (e) {
    if (sessionId !== currentSessionId()) {
      return;
    }
    console.error(e);
    showToast(e?.message || "Failed to drop intercepted response.", "error");
    await loadResponseIntercepts(false).catch(console.error);
  }
}

function updateInterceptQueueBadges() {
  const reqCount = state.intercepts.length;
  const resCount = state.responseIntercepts.length;
  els.interceptQueueTabRequest.textContent = reqCount > 0 ? `Request Queue (${reqCount})` : "Request Queue";
  els.interceptQueueTabResponse.textContent = resCount > 0 ? `Response Queue (${resCount})` : "Response Queue";
}

/** Key of the intercept CM pane that is currently visible. */
function activeInterceptCMKey() {
  return state.interceptQueueTab === "response" ? "interceptRes" : "interceptReq";
}

// Re-apply the intercept search box to whichever intercept editor is showing.
// Setting editor content goes through updateCodePaneCM, which clears highlights,
// so this has to run after content changes and on every queue-tab switch.
function updateInterceptSearch() {
  if (!els.interceptSearchMeta) return;
  const cv = getCMView(activeInterceptCMKey());
  if (!cv) {
    els.interceptSearchMeta.innerHTML = buildSearchMeta(0, "raw", 0);
    return;
  }
  const query = els.interceptSearchInput ? els.interceptSearchInput.value.trim() : "";
  const result = cv.applySearch(query);
  els.interceptSearchMeta.innerHTML = buildSearchMeta(cv.view.state.doc.lines, "raw", result.matchCount);
}

// Set an intercept editor's content with the active search applied in the same
// pass, and refresh the footer meta when the pane being written is the visible one.
function setInterceptPaneContent(key, container, text, options = {}) {
  const query = els.interceptSearchInput ? els.interceptSearchInput.value.trim() : "";
  const result = updateCodePaneCM(key, container, text, { ...options, search: query });
  if (els.interceptSearchMeta && activeInterceptCMKey() === key) {
    els.interceptSearchMeta.innerHTML = buildSearchMeta(result.lineCount, "raw", result.matchCount);
  }
  return result;
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
  updateInterceptSearch();
}

async function openReplayFromSelection() {
  const record = await loadSelectedTransactionRecord();

  if (!record) {
    throw new Error("Selected transaction could not be loaded.");
  }
  if (record.kind === "tunnel") {
    throw new Error("Tunnel records cannot be sent to Replay.");
  }

  openTransactionRecordInReplay(record);
}

function resetReplay() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type === "websocket") {
    return;
  }
  if (isReplayTabSending(tab.id)) {
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

const _replaySendControllers = new Map();

function isReplayTabSending(tabId) {
  return Boolean(tabId && _replaySendControllers.has(tabId));
}

function setReplaySending(sending) {
  const tab = getActiveReplayTab();
  if (tab && tab.type !== "websocket") {
    syncReplayToolbar(tab);
    return;
  }
  els.sendReplayButton.disabled = true;
  els.cancelReplayButton.disabled = true;
  if (els.replayFollowRedirectButton) {
    els.replayFollowRedirectButton.disabled = true;
  }
  els.replayBackButton.disabled = true;
  els.replayForwardButton.disabled = true;
}

function cancelReplaySend() {
  const tab = getActiveReplayTab();
  const sendingTabId = tab?.id || null;
  const controller = sendingTabId ? _replaySendControllers.get(sendingTabId) : null;
  if (!controller) {
    setReplaySending(false);
    return;
  }
  _replaySendControllers.delete(sendingTabId);
  controller.abort();
  if (tab && tab.type !== "websocket") {
    tab.responseRecord = null;
    tab.notice = "Cancelled.";
    scheduleWorkspaceStateSave();
    renderReplayTabs();
  }
  setReplaySending(false);
  if (tab && tab.type !== "websocket") {
    renderReplayEmptyResponse(tab);
  } else {
    els.replayResponseMeta.textContent = "Cancelled.";
    els.replayFollowRedirectButton?.classList.add("hidden");
    renderReplayResponseView("");
  }
}

function clearReplaySendInFlight() {
  for (const controller of _replaySendControllers.values()) {
    controller.abort();
  }
  _replaySendControllers.clear();
  setReplaySending(false);
}

function isReplayTabStillCurrent(tab, tabId, sessionId) {
  return Boolean(
    tab
    && state.replayTabs.includes(tab)
    && tab.id === tabId
    && (state.activeSession?.id || null) === sessionId
  );
}

async function sendReplay() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type === "websocket") {
    return;
  }
  if (isReplayTabSending(tab.id)) {
    return;
  }

  const targetValidation = validateManualRepeaterTargetInput(
    els.replayHostInput.value,
    els.replayPortInput.value,
  );
  setReplayTargetInputValidity(targetValidation);
  if (!targetValidation.valid) {
    els.replayHostInput.reportValidity();
    els.replayPortInput.reportValidity();
    return;
  }

  let request, requestText, target;
  try {
    const fallback = tab.baseRequest || createDefaultEditableRequest();
    const replayReqText = tab.requestText || "";
    request = parseEditableRawRequest(replayReqText, fallback);
    if (request.preview_truncated) {
      throw new Error("Cannot send Replay because the request body is preview-truncated. Edit the body or reopen it from the original capture.");
    }
    requestText = request._normalizedRawText || replayReqText;
    if (requestText !== replayReqText) {
      tab.requestText = requestText;
      setReplayRequestEditorText(requestText, { preserveSelection: true });
      scheduleWorkspaceStateSave();
    }
    target = getRepeaterTargetConfig(tab, request);
  } catch (e) {
    tab.responseRecord = null;
    tab.notice = e.message || "Failed to parse request.";
    els.replayFollowRedirectButton?.classList.add("hidden");
    els.replayResponseMeta.textContent = "Error";
    renderReplayResponseView(tab.notice);
    updateReplaySearchPane("response", tab.notice);
    scheduleWorkspaceStateSave();
    return;
  }

  const conflictSnapshot = cloneReplayTabState(tab);
  const sendingTabId = tab.id;
  const sendingSessionId = state.activeSession?.id || null;
  const httpVersion = replayEffectiveHttpVersion(request, requestText, tab.httpVersionMode);
  const replayController = new AbortController();
  _replaySendControllers.set(sendingTabId, replayController);
  setReplaySending(true);

  let expectedWorkspaceRevision;
  try {
    expectedWorkspaceRevision = await flushWorkspaceStateForReplayAction();
  } catch (error) {
    if (_replaySendControllers.get(sendingTabId) !== replayController || replayController.signal.aborted) {
      return;
    }
    _replaySendControllers.delete(sendingTabId);
    setReplaySending(false);
    if (error instanceof WorkspaceStateConflictError) {
      restoreReplayTabConflictState(tab, conflictSnapshot);
    }
    handleWorkspaceActionError(error);
    return;
  }
  if (_replaySendControllers.get(sendingTabId) !== replayController || replayController.signal.aborted) {
    return;
  }
  if (!isReplayTabStillCurrent(tab, sendingTabId, sendingSessionId)) {
    _replaySendControllers.delete(sendingTabId);
    setReplaySending(false);
    return;
  }

  // Enter sending state after validation so only a valid send clears the response pane.
  tab.responseRecord = null;
  tab.notice = "";
  els.replayFollowRedirectButton?.classList.add("hidden");
  els.replayResponseMeta.textContent = "";
  renderReplayResponseView("");

  let response;
  try {
    const targetPayload = replayTargetOverridePayload(tab, request, target);
    response = await fetch("/api/replay/send", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        session_id: sendingSessionId,
        expected_active_session_id: expectedActiveSessionIdForWrite(sendingSessionId),
        expected_workspace_revision: expectedWorkspaceRevision,
        request,
        target: targetPayload,
        source_transaction_id: tab.sourceTransactionId,
        http_version: httpVersion,
      }),
      signal: replayController.signal,
    });
  } catch (e) {
    if (e.name === "AbortError") return; // cancelled
    if (!isReplayTabStillCurrent(tab, sendingTabId, sendingSessionId)) return;
    const notice = e?.message || "Failed to send replay.";
    const draftUnchanged = replaySentDraftUnchanged(tab, requestText, target);
    if (draftUnchanged) {
      tab.responseRecord = null;
      tab.notice = notice;
      applyReplaySentDraftIfUnchanged(tab, request, requestText, target);
    }
    recordRepeaterHistory(tab, {
      request,
      requestText,
      responseRecord: null,
      notice,
      target,
    });
    scheduleWorkspaceStateSave();
    if (draftUnchanged && state.activeReplayTabId === sendingTabId) {
      renderReplayResponseOnly(tab);
      syncReplayToolbar(tab);
    }
    showToast(notice, "error");
    return;
  } finally {
    if (_replaySendControllers.get(sendingTabId) === replayController) {
      _replaySendControllers.delete(sendingTabId);
      setReplaySending(false);
    }
  }

  if (!state.replayTabs.some((item) => item.id === sendingTabId)) {
    return;
  }
  if (!isReplayTabStillCurrent(tab, sendingTabId, sendingSessionId)) {
    return;
  }

  if (!response.ok) {
    const errorPayload = await readReplaySendError(response);
    if (!isReplayTabStillCurrent(tab, sendingTabId, sendingSessionId)) {
      return;
    }
    if (errorPayload.workspaceConflict) {
      restoreReplayTabConflictState(tab, conflictSnapshot);
      handleReplayWorkspaceRevisionConflict(errorPayload.workspaceSnapshot);
      return;
    }
    const notice = errorPayload.notice;
    const responseRecord = errorPayload.responseRecord;
    const draftUnchanged = replaySentDraftUnchanged(tab, requestText, target);
    if (draftUnchanged) {
      tab.responseRecord = responseRecord;
      tab.notice = notice;
      applyReplaySentDraftIfUnchanged(tab, request, requestText, target);
    }
    recordRepeaterHistory(tab, {
      request,
      requestText,
      responseRecord,
      notice,
      target,
    });
    scheduleWorkspaceStateSave();
    if (draftUnchanged && state.activeReplayTabId === sendingTabId) {
      renderReplayResponseOnly(tab);
      syncReplayToolbar(tab);
    }
    showToast(notice, "error");
    if (responseRecord) {
      scheduleRefresh();
    }
    return;
  }

  const responseRecord = await response.json();
  if (!isReplayTabStillCurrent(tab, sendingTabId, sendingSessionId)) {
    return;
  }
  const draftUnchanged = replaySentDraftUnchanged(tab, requestText, target);
  if (draftUnchanged) {
    applyReplaySentDraftIfUnchanged(tab, request, requestText, target);
    tab.notice = "";
    tab.responseRecord = responseRecord;
  }
  recordRepeaterHistory(tab, {
    request,
    requestText,
    responseRecord,
    notice: "",
    target,
  });
  scheduleWorkspaceStateSave();
  // Only update response side — don't re-render request to preserve cursor/scroll
  if (draftUnchanged && state.activeReplayTabId === sendingTabId) {
    renderReplayResponseOnly(tab);
    syncReplayToolbar(tab);
    renderReplayViewTabs();
  } else if (!draftUnchanged && state.activeReplayTabId === sendingTabId) {
    syncReplayToolbar(tab);
    showToast("Replay response was saved to history; current request changed while sending.", "info", 4000);
  }
  scheduleRefresh();
}

function isWorkspaceRevisionConflictPayload(payload) {
  return Boolean(
    payload
    && typeof payload === "object"
    && Number.isFinite(payload.revision)
    && payload.replay
    && payload.fuzzer
  );
}

async function readWorkspaceRevisionConflictPayload(response) {
  if (response.status !== 409) return null;
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) return null;
  try {
    const payload = await response.clone().json();
    return isWorkspaceRevisionConflictPayload(payload) ? payload : null;
  } catch (_error) {
    return null;
  }
}

function handleReplayWorkspaceRevisionConflict(snapshot = null) {
  workspaceSaveConflictPending = true;
  workspaceSaveConflictLatest = snapshot || null;
  showToast(
    "Workspace changed elsewhere; replay was not sent. Reload the workspace to reconcile.",
    "error",
    6000,
  );
}

function handleFuzzerWorkspaceRevisionConflict(snapshot = null) {
  workspaceSaveConflictPending = true;
  workspaceSaveConflictLatest = snapshot || null;
  showToast(
    "Workspace changed elsewhere; fuzzer was not started. Reload the workspace to reconcile.",
    "error",
    6000,
  );
}

async function readReplaySendError(response) {
  const fallback = `Replay failed (${response.status})`;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.toLowerCase().includes("application/json")) {
    try {
      const payload = await response.json();
      const workspaceConflict = response.status === 409 && isWorkspaceRevisionConflictPayload(payload);
      return {
        notice: workspaceConflict
          ? "Workspace changed elsewhere; replay was not sent."
          : String(payload?.error || fallback),
        responseRecord: payload?.record || payload?.response_record || null,
        workspaceConflict,
        workspaceSnapshot: workspaceConflict ? payload : null,
      };
    } catch (_error) {
      return { notice: fallback, responseRecord: null, workspaceConflict: false };
    }
  }
  const text = await response.text();
  return {
    notice: text || fallback,
    responseRecord: null,
    workspaceConflict: false,
  };
}

function replaySentDraftUnchanged(tab, requestText, target) {
  if (!tab || tab.type === "websocket") return false;
  if ((tab.requestText || "") !== requestText) {
    return false;
  }
  const effectiveTarget = getRepeaterTargetConfig(tab, requestText ? deriveRepeaterRequest(tab) : null);
  return targetStatesEquivalent(effectiveTarget, target);
}

function applyReplaySentDraftIfUnchanged(tab, request, requestText, target) {
  if (!replaySentDraftUnchanged(tab, requestText, target)) {
    return;
  }
  tab.baseRequest = cloneEditableRequest(request);
  tab.httpVersionMode = replayHttpVersionState(request, requestText, tab.httpVersionMode);
  tab.targetScheme = target.scheme;
  tab.targetHost = target.host;
  tab.targetPort = target.port;
  tab.targetManuallyEdited = !targetStatesEquivalent(
    target,
    authorityToTargetState(request.host, request.scheme),
  );
  tab.requestText = requestText;
}

function redirectTargetsSameOrigin(currentTarget, currentRequest, nextScheme, nextHost, nextPort) {
  const currentScheme = String(currentTarget?.scheme || currentRequest?.scheme || "https").toLowerCase();
  const normalizedNextScheme = String(nextScheme || "https").toLowerCase();
  if (currentScheme !== normalizedNextScheme) {
    return false;
  }
  const currentHost = stripIpv6Brackets(String(
    currentTarget?.host || currentRequest?.host || "",
  ).trim());
  const currentPort = normalizePortValue(currentTarget?.port)
    || defaultHttpPortForScheme(currentScheme);
  const currentAuthority = joinAuthority(
    currentHost,
    isDefaultPortForScheme(currentScheme, currentPort) ? "" : currentPort,
  );
  const nextAuthority = joinAuthority(
    nextHost,
    isDefaultPortForScheme(normalizedNextScheme, nextPort) ? "" : nextPort,
  );
  return Boolean(currentAuthority && nextAuthority)
    && httpRequestAuthoritiesEquivalent(currentAuthority, nextAuthority, currentScheme);
}

function isRedirectCredentialHeader(header) {
  const name = String(header?.name || "").trim().toLowerCase();
  return name === "authorization" || name === "proxy-authorization";
}

function isRedirectRequestBodyHeader(header) {
  const name = String(header?.name || "").trim().toLowerCase();
  return name === "content-length"
    || name === "transfer-encoding"
    || name === "content-type"
    || name === "content-encoding";
}

async function followRedirect() {
  const tab = getActiveReplayTab();
  if (!tab || !tab.responseRecord) return;
  if (isReplayTabSending(tab.id)) return;
  const conflictSnapshot = cloneReplayTabState(tab);

  const resp = tab.responseRecord.response;
  if (!resp) return;

  const status = tab.responseRecord.status;
  const responseHeaders = normalizedHeaders(resp.headers);
  const locationHeader = responseHeaders.find((h) => headerNameEquals(h, "location"));
  if (!locationHeader) return;

  // Build new request from current request
  const fallback = tab.baseRequest || createDefaultEditableRequest();
  const replayReqText = tab.requestText || "";
  let currentRequest;
  let httpVersion;
  try {
    currentRequest = parseEditableRawRequest(replayReqText, fallback);
    httpVersion = replayEffectiveHttpVersion(currentRequest, replayReqText, tab.httpVersionMode);
  } catch (e) {
    const message = e?.message || "Failed to parse request.";
    els.replayResponseMeta.textContent = "Error";
    showToast(message, "error");
    return;
  }

  const location = String(locationHeader.value || "").trim();
  let redirectUrl;
  let currentTarget;
  try {
    currentTarget = getRepeaterTargetConfig(tab, currentRequest);
    const currentUrl = buildUrlFromTarget(
      currentTarget.scheme || currentRequest.scheme || "https",
      currentTarget.host || currentRequest.host || "localhost",
      currentTarget.port || "",
      currentRequest.path || "/",
    );
    redirectUrl = new URL(location, currentUrl);
  } catch (_error) {
    showToast("Invalid redirect Location header", "error");
    return;
  }
  const newScheme = redirectUrl.protocol.replace(":", "") || currentRequest.scheme || "https";
  const newHost = stripIpv6Brackets(redirectUrl.hostname);
  const newPort = redirectUrl.port || (newScheme === "https" ? "443" : "80");
  const newPath = `${redirectUrl.pathname || "/"}${redirectUrl.search || ""}`;
  const sameOriginRedirect = redirectTargetsSameOrigin(
    currentTarget,
    currentRequest,
    newScheme,
    newHost,
    newPort,
  );

  // 301/302/303 → GET (drop body), 307/308 → keep method
  const useGet = status === 301 || status === 302 || status === 303;
  if (currentRequest.preview_truncated && !useGet) {
    showToast("Cannot follow redirect because the request body is preview-truncated.", "error");
    return;
  }
  const newMethod = useGet ? "GET" : currentRequest.method;
  const newBody = useGet ? "" : currentRequest.body;
  const newBodyEncoding = useGet ? "utf8" : (currentRequest.body_encoding || "utf8");

  // Collect Set-Cookie from response
  const setCookies = responseHeaders
    .filter((h) => headerNameEquals(h, "set-cookie"))
    .map((h) => {
      // Extract just the cookie name=value (before ;)
      const raw = h.value.split(";")[0].trim();
      return raw;
    })
    .filter(Boolean);

  // Merge with existing cookies
  let existingCookies = [];
  const currentHeaders = normalizedHeaders(currentRequest.headers);
  const cookieHeader = sameOriginRedirect
    ? currentHeaders.find((h) => headerNameEquals(h, "cookie"))
    : null;
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
  if (sameOriginRedirect) {
    for (const c of setCookies) {
      const eqIdx = c.indexOf("=");
      const name = eqIdx > 0 ? c.substring(0, eqIdx) : c;
      cookieMap.set(name, c);
    }
  }

  // Build new headers
  const newHeaders = currentHeaders
    .filter((h) => (
      !headerNameEquals(h, "cookie")
      && !headerNameEquals(h, "host")
      && (!useGet || !isRedirectRequestBodyHeader(h))
      && (sameOriginRedirect || !isRedirectCredentialHeader(h))
    ))
    .map((h) => ({ name: h.name, value: h.value }));

  // Add updated host
  const newHostPort = isDefaultPortForScheme(newScheme, newPort) ? "" : newPort;
  newHeaders.unshift({ name: "host", value: joinAuthority(newHost, newHostPort) });

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
    body_encoding: newBodyEncoding,
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
  tab.responseRecord = null;
  tab.notice = "Following redirect...";
  if (getCMView("replayReq")) {
    getCMView("replayReq").setContent(requestText);
  } else if (els.replayRequestEditor) {
    els.replayRequestEditor.value = requestText;
    renderReplayRequestHighlight(requestText);
  }
  scheduleWorkspaceStateSave();
  if (state.activeReplayTabId === tab.id) {
    renderReplayResponseOnly(tab);
    syncReplayToolbar(tab);
    renderReplayViewTabs();
  }

  let expectedWorkspaceRevision;
  try {
    expectedWorkspaceRevision = await flushWorkspaceStateForReplayAction();
  } catch (error) {
    if (error instanceof WorkspaceStateConflictError) {
      restoreReplayTabConflictState(tab, conflictSnapshot);
    }
    handleWorkspaceActionError(error);
    return;
  }

  // Send the follow request
  const target = { scheme: newScheme, host: newHost, port: newPort };
  const followingTabId = tab.id;
  const followingSessionId = state.activeSession?.id || null;
  const replayController = new AbortController();
  _replaySendControllers.set(followingTabId, replayController);
  setReplaySending(true);
  let response;
  try {
    response = await fetch("/api/replay/send", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        session_id: followingSessionId,
        expected_active_session_id: expectedActiveSessionIdForWrite(followingSessionId),
        expected_workspace_revision: expectedWorkspaceRevision,
        request: newRequest,
        target,
        source_transaction_id: null,
        http_version: httpVersion,
      }),
      signal: replayController.signal,
    });
  } catch (e) {
    if (e.name === "AbortError") return;
    if (!isReplayTabStillCurrent(tab, followingTabId, followingSessionId)) return;
    const notice = e?.message || "Failed to follow redirect.";
    const draftUnchanged = replaySentDraftUnchanged(tab, requestText, target);
    if (draftUnchanged) {
      tab.responseRecord = null;
      tab.notice = notice;
      applyReplaySentDraftIfUnchanged(tab, newRequest, requestText, target);
    }
    recordRepeaterHistory(tab, { request: newRequest, requestText, responseRecord: null, notice, target });
    scheduleWorkspaceStateSave();
    if (draftUnchanged && state.activeReplayTabId === followingTabId) {
      renderReplayResponseOnly(tab);
      syncReplayToolbar(tab);
    }
    showToast(notice, "error");
    return;
  } finally {
    if (_replaySendControllers.get(followingTabId) === replayController) {
      _replaySendControllers.delete(followingTabId);
      setReplaySending(false);
    }
  }

  if (!isReplayTabStillCurrent(tab, followingTabId, followingSessionId)) return;

  if (!response.ok) {
    const errorPayload = await readReplaySendError(response);
    if (!isReplayTabStillCurrent(tab, followingTabId, followingSessionId)) return;
    if (errorPayload.workspaceConflict) {
      restoreReplayTabConflictState(tab, conflictSnapshot);
      handleReplayWorkspaceRevisionConflict(errorPayload.workspaceSnapshot);
      return;
    }
    const notice = errorPayload.notice;
    const responseRecord = errorPayload.responseRecord;
    const draftUnchanged = replaySentDraftUnchanged(tab, requestText, target);
    if (draftUnchanged) {
      tab.responseRecord = responseRecord;
      tab.notice = notice;
      applyReplaySentDraftIfUnchanged(tab, newRequest, requestText, target);
    }
    recordRepeaterHistory(tab, { request: newRequest, requestText, responseRecord, notice, target });
    scheduleWorkspaceStateSave();
    if (draftUnchanged && state.activeReplayTabId === followingTabId) {
      renderReplayResponseOnly(tab);
      syncReplayToolbar(tab);
    }
    if (responseRecord) {
      scheduleRefresh();
    }
    return;
  }

  const responseRecord = await response.json();
  if (!isReplayTabStillCurrent(tab, followingTabId, followingSessionId)) return;
  const draftUnchanged = replaySentDraftUnchanged(tab, requestText, target);
  if (draftUnchanged) {
    applyReplaySentDraftIfUnchanged(tab, newRequest, requestText, target);
    tab.notice = "";
    tab.responseRecord = responseRecord;
  }
  recordRepeaterHistory(tab, { request: newRequest, requestText, responseRecord, notice: "", target });
  scheduleWorkspaceStateSave();
  if (draftUnchanged && state.activeReplayTabId === followingTabId) {
    renderReplayResponseOnly(tab);
    syncReplayToolbar(tab);
    renderReplayViewTabs();
  } else if (!draftUnchanged && state.activeReplayTabId === followingTabId) {
    syncReplayToolbar(tab);
    showToast("Redirect response was saved to history; current request changed while sending.", "info", 4000);
  }
  scheduleRefresh();
}

function openBlankReplayTab() {
  const tab = createReplayTab();
  state.replayTabs.push(tab);
  state.activeReplayTabId = tab.id;
  setActiveTool("replay");
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

function duplicateActiveReplayTab() {
  const tab = getActiveReplayTab();
  if (!tab) {
    return;
  }

  if (tab.type === "websocket") {
    let handshakeEdited = !!tab.wsHandshakeEdited;
    let handshakeText = handshakeEdited ? (tab.wsHandshakeText || "") : "";
    if (state.activeReplayTabId === tab.id && els.wsHandshakeHeaders) {
      const visibleHandshakeText = els.wsHandshakeHeaders.value;
      handshakeEdited = handshakeEdited || visibleHandshakeText !== wsReplayDisplayHandshakeText(tab);
      handshakeText = handshakeEdited ? visibleHandshakeText : "";
      if (handshakeEdited) {
        tab.wsHandshakeText = visibleHandshakeText;
        tab.wsHandshakeEdited = true;
      }
    }
    createWsReplayTab({
      scheme: tab.wsScheme,
      host: tab.wsHost,
      port: tab.wsPort,
      path: tab.wsPath,
      headers: normalizedHeaders(tab.wsHeaders),
      handshakeText,
      handshakeEdited,
      editorText: tab.wsEditorText || "",
      messageType: tab.wsMessageType || "text",
      editorBodyEncoded: !!tab.wsEditorBodyEncoded,
      setupQueue: Array.isArray(tab.wsSetupQueue)
        ? tab.wsSetupQueue.map((item) => ({ ...item }))
        : [],
      setupQueueNotice: tab.wsSetupNotice || "",
      capturedFrames: getWsReplayFrames(tab),
      selectedFrameIndex: tab.wsSelectedFrameIndex,
      frameWindowStart: tab.wsFrameWindowStart,
      framesTruncated: !!tab.wsFramesTruncated,
      customLabel: tab.customLabel || "",
    });
    return;
  }

  const fallback = tab.baseRequest || createDefaultEditableRequest();
  const requestText = tab.requestText || buildEditableRawRequest(fallback);
  let request = cloneEditableRequest(fallback);
  try {
    request = parseEditableRawRequest(requestText, fallback);
  } catch (_error) {
    request = cloneEditableRequest(fallback);
  }

  const target = getRepeaterTargetConfig(tab, request);

  const historyEntries = Array.isArray(tab.historyEntries)
    ? tab.historyEntries.map(cloneRepeaterHistoryEntry)
    : [];
  const duplicate = createReplayTab({
    baseRequest: request,
    sourceTransactionId: tab.sourceTransactionId,
    notice: tab.notice,
    requestText,
    httpVersionMode: replayHttpVersionState(request, requestText, tab.httpVersionMode),
    customLabel: tab.customLabel || "",
    responseRecord: cloneTransactionRecord(tab.responseRecord),
    targetScheme: target.scheme,
    targetHost: target.host,
    targetPort: target.port,
    targetManuallyEdited: !!tab.targetManuallyEdited,
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
  const requestText = seed.requestText ?? buildEditableRawRequest(baseRequest);
  const target = authorityToTargetState(baseRequest.host, baseRequest.scheme);
  const normalizedTarget = normalizeRepeaterTargetInput(
    seed.targetHost ?? target.host,
    seed.targetPort ?? target.port,
    seed.targetScheme || target.scheme,
  );
  return {
    id: crypto.randomUUID(),
    sequence: state.replayTabSequence,
    customLabel: normalizeReplayTabCustomLabel(seed.customLabel || ""),
    pinned: !!seed.pinned,
    baseRequest,
    sourceTransactionId: seed.sourceTransactionId || null,
    notice: seed.notice || "",
    requestText,
    httpVersionMode: replayHttpVersionState(baseRequest, requestText, seed.httpVersionMode),
    responseRecord: cloneTransactionRecord(seed.responseRecord),
    targetScheme: normalizedTarget.scheme,
    targetHost: normalizedTarget.host,
    targetPort: normalizedTarget.port,
    targetManuallyEdited: !!seed.targetManuallyEdited,
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
      const pinBtnState = tab.pinned ? "on" : (!isActive ? "idle" : "");
      const pinHiddenAttrs = pinBtnState === "idle" ? 'tabindex="-1"' : "";
      const pinLabel = tab.pinned ? "Unpin tab" : "Pin tab";
      const pinBtn = `<button class="replay-tab-pin-btn ${pinBtnState}" type="button" aria-label="${pinLabel}" title="${pinLabel}" aria-pressed="${tab.pinned ? "true" : "false"}" ${pinHiddenAttrs}>\uD83D\uDCCC</button>`;
      const autoLabel = replayTabAutoLabel(tab);
      const label = replayTabLabel(tab);
      const title = replayTabTooltipLabel(tab, label, autoLabel);
      const labelControl = state.replayRenamingTabId === tab.id
        ? `<input class="replay-tab-name-input" type="text" value="${escapeHtml(tab.customLabel || "")}" placeholder="${escapeHtml(autoLabel)}" maxlength="80" aria-label="Replay tab name">`
        : `<button class="replay-tab-button" type="button" title="${escapeHtml(title)}">${escapeHtml(label)}</button>`;
      return `
        <div class="replay-tab ${active} ${pinned}" data-replay-tab-id="${tab.id}">
          ${pinBtn}
          ${labelControl}
          <button class="replay-tab-close" type="button" aria-label="Close replay tab">\u00d7</button>
        </div>
      `;
    })
    .join("");

  Array.from(els.replayTabStrip.querySelectorAll(".replay-tab")).forEach((tabElement) => {
    const id = tabElement.dataset.replayTabId;
    const nameInput = tabElement.querySelector(".replay-tab-name-input");
    tabElement.addEventListener("pointerdown", (event) => {
      const editingId = state.replayRenamingTabId;
      if (!editingId || event.target.closest(".replay-tab-name-input")) {
        return;
      }
      const actionTabElement = event.target.closest(".replay-tab");
      const actionTabId = actionTabElement?.dataset.replayTabId;
      if (!actionTabId) {
        return;
      }
      const closeButton = event.target.closest(".replay-tab-close");
      const pinButton = event.target.closest(".replay-tab-pin-btn");
      const tabButton = event.target.closest(".replay-tab-button");
      if (!closeButton && !pinButton && !tabButton) {
        return;
      }
      const editingInput = els.replayTabStrip.querySelector(
        `.replay-tab[data-replay-tab-id="${CSS.escape(editingId)}"] .replay-tab-name-input`,
      );
      event.preventDefault();
      event.stopPropagation();
      commitReplayTabRename(editingId, editingInput?.value || "");
      if (closeButton) {
        closeRepeaterTab(actionTabId).catch(handleWorkspaceActionError);
      } else if (pinButton) {
        toggleReplayTabPin(actionTabId);
      } else if (tabButton && state.activeReplayTabId !== actionTabId) {
        state.activeReplayTabId = actionTabId;
        state.replayRenamingTabId = null;
        scheduleWorkspaceStateSave();
        renderReplay();
      }
    }, { capture: true });
    if (nameInput) {
      nameInput.addEventListener("click", (event) => event.stopPropagation());
      nameInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          commitReplayTabRename(id, nameInput.value);
        } else if (event.key === "Escape") {
          event.preventDefault();
          state.replayRenamingTabId = null;
          renderReplayTabs();
        }
      });
      nameInput.addEventListener("blur", () => {
        commitReplayTabRename(id, nameInput.value);
      });
      requestAnimationFrame(() => {
        if (state.replayRenamingTabId === id) {
          nameInput.focus();
          nameInput.select();
        }
      });
    }
    tabElement.querySelector(".replay-tab-button")?.addEventListener("click", () => {
      if (state.activeReplayTabId === id) {
        beginReplayTabRename(id);
        return;
      }
      state.activeReplayTabId = id;
      state.replayRenamingTabId = null;
      scheduleWorkspaceStateSave();
      renderReplay();
    });
    tabElement.querySelector(".replay-tab-pin-btn")?.addEventListener("click", (event) => {
      event.stopPropagation();
      toggleReplayTabPin(id);
    });
    tabElement.querySelector(".replay-tab-close")?.addEventListener("click", (event) => {
      event.stopPropagation();
      closeRepeaterTab(id).catch(handleWorkspaceActionError);
    });
  });

  // Scroll active tab into view
  scrollActiveReplayTabIntoView();
}

function refreshReplayTabLabel(id) {
  if (!els.replayTabStrip) return;
  const tab = state.replayTabs.find((item) => item.id === id);
  if (!tab) return;
  const tabElement = Array.from(els.replayTabStrip.querySelectorAll(".replay-tab"))
    .find((element) => element.dataset.replayTabId === id);
  if (!tabElement) return;

  const autoLabel = replayTabAutoLabel(tab);
  const label = replayTabLabel(tab);
  const title = replayTabTooltipLabel(tab, label, autoLabel);
  const button = tabElement.querySelector(".replay-tab-button");
  if (button) {
    button.textContent = label;
    button.title = title;
  }
  const input = tabElement.querySelector(".replay-tab-name-input");
  if (input) {
    input.placeholder = autoLabel;
  }
}

function beginReplayTabRename(id) {
  if (!state.replayTabs.some((tab) => tab.id === id)) {
    return;
  }
  state.replayRenamingTabId = id;
  renderReplayTabs();
}

function commitReplayTabRename(id, value) {
  if (state.replayRenamingTabId !== id) {
    return;
  }
  const tab = state.replayTabs.find((item) => item.id === id);
  if (!tab) {
    state.replayRenamingTabId = null;
    renderReplayTabs();
    return;
  }
  const previousLabel = tab.customLabel || "";
  tab.customLabel = normalizeReplayTabCustomLabel(value);
  const attemptedLabel = tab.customLabel;
  state.replayRenamingTabId = null;
  scheduleWorkspaceStateSave();
  flushWorkspaceState().catch((error) => {
    if (tab.customLabel === attemptedLabel) {
      tab.customLabel = previousLabel;
    }
    handleWorkspaceActionError(error);
    renderReplayTabs();
  });
  renderReplayTabs();
}

function normalizeReplayTabCustomLabel(value) {
  return String(value || "").replace(/\s+/g, " ").trim().slice(0, 80);
}

function toggleReplayTabPin(id) {
  const tab = state.replayTabs.find((t) => t.id === id);
  if (!tab) return;
  const previousPinned = !!tab.pinned;
  tab.pinned = !tab.pinned;
  const attemptedPinned = tab.pinned;
  // Flush immediately so pin state survives quick app quit
  scheduleWorkspaceStateSave();
  flushWorkspaceState().catch((error) => {
    if (tab.pinned === attemptedPinned) {
      tab.pinned = previousPinned;
    }
    handleWorkspaceActionError(error);
    renderReplayTabs();
  });
  renderReplayTabs();
}


function scrollActiveReplayTabIntoView() {
  const activeTab = els.replayTabStrip.querySelector(".replay-tab.active");
  if (activeTab) {
    activeTab.scrollIntoView({ behavior: "smooth", inline: "nearest", block: "nearest" });
  }
}

async function closeRepeaterTab(id) {
  const index = state.replayTabs.findIndex((tab) => tab.id === id);
  if (index === -1) {
    return;
  }

  const closeSnapshot = snapshotReplayTabsState();
  const visualOrderBeforeClose = getReplayTabVisualOrder().map((tab) => tab.id);
  const visualIndex = visualOrderBeforeClose.indexOf(id);
  const closingTab = state.replayTabs[index];
  const currentIndex = state.replayTabs.findIndex((tab) => tab.id === id);
  if (currentIndex === -1) {
    return;
  }
  const controller = _replaySendControllers.get(id);
  if (controller) {
    _replaySendControllers.delete(id);
    controller.abort();
    setReplaySending(false);
  }
  if (state.replayRenamingTabId === id) {
    state.replayRenamingTabId = null;
  }

  state.replayTabs.splice(currentIndex, 1);
  if (!state.replayTabs.length) {
    state.replayTabSequence = 0;
    const replacement = createReplayTab();
    state.replayTabs = [replacement];
    state.activeReplayTabId = replacement.id;
  } else if (state.activeReplayTabId === id) {
    const remainingVisualIds = visualOrderBeforeClose.filter((tabId) =>
      tabId !== id && state.replayTabs.some((tab) => tab.id === tabId)
    );
    const replacementIndex = Math.min(Math.max(0, visualIndex - 1), remainingVisualIds.length - 1);
    state.activeReplayTabId = remainingVisualIds[replacementIndex] || state.replayTabs[Math.max(0, currentIndex - 1)].id;
  }
  scheduleWorkspaceStateSave();
  renderReplay();
  try {
    await flushWorkspaceState();
  } catch (error) {
    restoreReplayTabsState(closeSnapshot);
    handleWorkspaceActionError(error);
    renderReplay();
    return;
  }

  if (closingTab.type === "websocket") {
    try {
      await cleanupWsReplayTab(closingTab, {
        removeBackend: true,
        guardWorkspaceRevision: false,
      });
    } catch (error) {
      console.warn("Failed to clean up WebSocket replay tab after close:", error);
      stopWsPoll(closingTab);
    }
  }
}

function replayTabLabel(tab) {
  if (tab.customLabel) {
    return tab.customLabel;
  }
  return replayTabAutoLabel(tab);
}

function replayTabTooltipLabel(tab, label = replayTabLabel(tab), autoLabel = replayTabAutoLabel(tab)) {
  return tab.customLabel ? label : autoLabel;
}

function replayTabAutoLabel(tab) {
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

  const validation = validateManualRepeaterTargetInput(
    els.replayHostInput.value,
    els.replayPortInput.value,
  );
  setReplayTargetInputValidity(validation);
  if (!validation.valid) {
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
  tab.targetManuallyEdited = true;
  tab.responseRecord = null;
  tab.notice = "";
  scheduleWorkspaceStateSave();
  renderReplay();
}

function setReplayTargetInputValidity(validation) {
  if (!els.replayHostInput || !els.replayPortInput) {
    return;
  }
  els.replayHostInput.setCustomValidity(validation.hostError || "");
  els.replayPortInput.setCustomValidity(validation.portError || "");
  els.replayHostInput.toggleAttribute("aria-invalid", !!validation.hostError);
  els.replayPortInput.toggleAttribute("aria-invalid", !!validation.portError);
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
  const target = {
    scheme: normalizedOverride.scheme || derived.scheme,
    host: normalizedOverride.host || derived.host,
    port: normalizedOverride.port || derived.port,
  };
  return target;
}

function replayTargetOverridePayload(tab, request, target) {
  if (!request || !target) return null;
  const requestTarget = authorityToTargetState(request.host, request.scheme);
  if (targetStatesEquivalent(target, requestTarget)) {
    return null;
  }
  return {
    scheme: target.scheme,
    host: target.host,
    port: target.port,
  };
}

function targetStatesEquivalent(left, right) {
  const scheme = String(left?.scheme || right?.scheme || "https").toLowerCase();
  const leftScheme = String(left?.scheme || scheme).toLowerCase();
  const rightScheme = String(right?.scheme || scheme).toLowerCase();
  if (leftScheme !== rightScheme) {
    return false;
  }
  const leftAuthority = joinAuthority(left?.host, left?.port);
  const rightAuthority = joinAuthority(right?.host, right?.port);
  if (!leftAuthority || !rightAuthority) {
    return leftAuthority === rightAuthority;
  }
  return httpRequestAuthoritiesEquivalent(leftAuthority, rightAuthority, scheme);
}

function authorityToTargetState(authority, scheme = "https") {
  const fallbackScheme = scheme || "https";
  if (!authority) {
    return { scheme: fallbackScheme, host: "", port: "" };
  }

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(authority)) {
    try {
      const parsed = new URL(authority);
      return {
        scheme: parsed.protocol ? parsed.protocol.replace(":", "") : fallbackScheme,
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

function explicitAuthorityPort(authority) {
  const normalized = String(authority || "").trim();
  if (!normalized) {
    return "";
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(normalized)) {
    try {
      const parsed = new URL(normalized);
      const authorityStart = normalized.toLowerCase().indexOf(`${parsed.protocol}//`);
      const authorityText = authorityStart >= 0
        ? normalized.slice(authorityStart + parsed.protocol.length + 2).split(/[/?#]/, 1)[0]
        : parsed.host;
      return explicitAuthorityPort(authorityText) || parsed.port || "";
    } catch (_error) {
      return "";
    }
  }
  if (normalized.startsWith("[")) {
    const closingBracket = normalized.indexOf("]");
    if (closingBracket >= 0 && normalized[closingBracket + 1] === ":") {
      return normalized.slice(closingBracket + 2);
    }
    return "";
  }
  const colonIndex = normalized.lastIndexOf(":");
  if (colonIndex <= 0) {
    return "";
  }
  if (normalized.slice(0, colonIndex).includes(":")) {
    return "";
  }
  return normalized.slice(colonIndex + 1);
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

function isDefaultPortForScheme(scheme, port) {
  const normalizedScheme = String(scheme || "").toLowerCase();
  const normalizedPort = normalizePortValue(port);
  return (normalizedScheme === "https" && normalizedPort === "443")
    || (normalizedScheme === "http" && normalizedPort === "80")
    || (normalizedScheme === "wss" && normalizedPort === "443")
    || (normalizedScheme === "ws" && normalizedPort === "80");
}

function buildUrlFromTarget(scheme, host, port, path = "/") {
  const normalizedScheme = scheme || "https";
  const rawPath = String(path || "/");
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(rawPath)) {
    return rawPath;
  }
  const target = normalizeRepeaterTargetInput(host, port, normalizedScheme);
  const normalizedPort = isDefaultPortForScheme(normalizedScheme, target.port) ? "" : target.port;
  const authority = joinAuthority(target.host, normalizedPort);
  const normalizedPath = rawPath.startsWith("/") ? rawPath : `/${rawPath}`;
  return `${normalizedScheme}://${authority || "localhost"}${normalizedPath}`;
}

function normalizeRepeaterTargetInput(host, port, scheme = "https") {
  const normalizedScheme = scheme || "https";
  const normalizedHost = String(host || "").trim();
  const parsedHost = authorityToTargetState(normalizedHost, normalizedScheme);
  const normalizedPort = normalizePortValue(port);
  const effectiveScheme = parsedHost.scheme || normalizedScheme;
  return {
    scheme: effectiveScheme,
    host: normalizedHost ? parsedHost.host : "",
    port: (parsedHost.port && normalizedHost)
      ? parsedHost.port
      : (normalizedHost ? (normalizedPort || defaultHttpPortForScheme(effectiveScheme)) : normalizedPort),
  };
}

function validateManualRepeaterTargetInput(host, port) {
  const rawHost = String(host || "").trim();
  const rawPort = String(port ?? "").trim();
  let hostError = "";
  let portError = "";

  if (rawHost) {
    const absoluteTarget = /^[a-z][a-z0-9+.-]*:\/\//i.test(rawHost);
    if (/\s/.test(rawHost) || rawHost.includes("\\") || rawHost.includes("@")) {
      hostError = "Target host must not include whitespace, user info, or URL components.";
    } else if (absoluteTarget) {
      try {
        const parsed = new URL(rawHost);
        const scheme = parsed.protocol.replace(":", "").toLowerCase();
        const hasUrlComponents = parsed.username
          || parsed.password
          || (parsed.pathname && parsed.pathname !== "/")
          || parsed.search
          || parsed.hash;
        if (scheme !== "http" && scheme !== "https") {
          hostError = "Target URL scheme must be HTTP or HTTPS.";
        } else if (hasUrlComponents) {
          hostError = "Target host must not include path, query, fragment, or credentials.";
        } else if (parsed.port && rawPort && normalizePortValue(rawPort) !== parsed.port) {
          portError = `Port conflicts with target URL port ${parsed.port}.`;
        }
      } catch (_error) {
        hostError = "Target host is not a valid URL.";
      }
    } else if (/[/?#]/.test(rawHost)) {
      hostError = "Target host must not include path, query, or fragment.";
    } else if (rawHost.includes(":") && !isLikelyIpv6Literal(rawHost)) {
      hostError = "Target host must not include a port; use the Port field.";
    }
  }

  if (rawPort && (!/^\d+$/.test(rawPort) || !normalizePortValue(rawPort))) {
    portError = "Port must be a number from 1 to 65535.";
  }

  return {
    valid: !hostError && !portError,
    hostError,
    portError,
  };
}

function validateWsReplayTargetInput(scheme, host, port, path) {
  const normalizedScheme = String(scheme || "").toLowerCase();
  const base = { hostError: "", portError: "" };
  let schemeError = "";
  let pathError = "";
  if (!["ws", "wss"].includes(normalizedScheme)) {
    schemeError = "WebSocket scheme must be WS or WSS.";
  }
  const rawHost = String(host || "").trim();
  if (!rawHost) {
    base.hostError = "WebSocket host is required.";
  } else if (/^[a-z][a-z0-9+.-]*:\/\//i.test(rawHost)) {
    base.hostError = "WebSocket host must not include URL components.";
  } else if (/\s/.test(rawHost) || rawHost.includes("\\") || rawHost.includes("@")) {
    base.hostError = "WebSocket host must not include whitespace, user info, or URL components.";
  } else if (/[/?#]/.test(rawHost)) {
    base.hostError = "WebSocket host must not include path, query, or fragment.";
  } else if (rawHost.includes(":") && !isLikelyIpv6Literal(rawHost)) {
    const authorityPort = explicitAuthorityPort(rawHost)
      || authorityToTargetState(rawHost, normalizedScheme || "wss").port;
    if (!normalizePortValue(authorityPort)) {
      base.hostError = "WebSocket host port must be a number from 1 to 65535.";
    }
  }
  const rawPort = String(port ?? "").trim();
  const authorityPort = rawHost && !base.hostError
    ? normalizePortValue(
      explicitAuthorityPort(rawHost) || authorityToTargetState(rawHost, normalizedScheme || "wss").port,
    )
    : "";
  if (rawPort && (!/^\d+$/.test(rawPort) || !normalizePortValue(rawPort))) {
    base.portError = "WebSocket port must be a number from 1 to 65535.";
  } else if (rawPort && authorityPort && normalizePortValue(rawPort) !== authorityPort) {
    base.portError = `Port conflicts with WebSocket host port ${authorityPort}.`;
  } else if (!rawPort && !authorityPort) {
    base.portError = "WebSocket port is required.";
  }
  const rawPath = String(path || "").trim();
  if (!rawPath) {
    pathError = "WebSocket path is required.";
  } else if (!rawPath.startsWith("/") || rawPath.startsWith("//") || /[\s#]/.test(rawPath)) {
    pathError = "WebSocket path must start with / and must not include whitespace or fragment.";
  }
  return {
    valid: !schemeError && !base.hostError && !base.portError && !pathError,
    schemeError,
    hostError: base.hostError,
    portError: base.portError,
    pathError,
  };
}

function normalizeWsReplayTargetFields(scheme, host, port) {
  const normalizedScheme = String(scheme || "wss").trim().toLowerCase();
  const rawHost = String(host || "").trim();
  const target = authorityToTargetState(rawHost, normalizedScheme);
  const authorityPort = normalizePortValue(explicitAuthorityPort(rawHost) || target.port);
  const inputPort = normalizePortValue(port);
  return {
    scheme: normalizedScheme,
    host: stripIpv6Brackets(String(target.host || rawHost).trim()),
    port: authorityPort || inputPort || String(defaultWsPortForScheme(normalizedScheme)),
  };
}

function setWsReplayTargetInputValidity(validation) {
  if (!els.wsSchemeSelect || !els.wsHostInput || !els.wsPortInput || !els.wsPathInput) {
    return;
  }
  els.wsSchemeSelect.setCustomValidity(validation.schemeError || "");
  els.wsHostInput.setCustomValidity(validation.hostError || "");
  els.wsPortInput.setCustomValidity(validation.portError || "");
  els.wsPathInput.setCustomValidity(validation.pathError || "");
  els.wsSchemeSelect.toggleAttribute("aria-invalid", !!validation.schemeError);
  els.wsHostInput.toggleAttribute("aria-invalid", !!validation.hostError);
  els.wsPortInput.toggleAttribute("aria-invalid", !!validation.portError);
  els.wsPathInput.toggleAttribute("aria-invalid", !!validation.pathError);
}

function isLikelyIpv6Literal(host) {
  const normalized = String(host || "").trim();
  if (normalized.startsWith("[") || normalized.endsWith("]")) {
    return normalized.startsWith("[") && normalized.endsWith("]");
  }
  return (normalized.match(/:/g) || []).length >= 2;
}

function stripIpv6Brackets(host) {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

function normalizePortValue(value) {
  const normalized = String(value ?? "").trim();
  if (!normalized) {
    return "";
  }

  if (!/^\d+$/.test(normalized)) {
    return "";
  }
  const parsed = Number(normalized);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 65535) {
    return "";
  }

  return String(parsed);
}

function strictIntegerInRange(value, min, max) {
  const normalized = String(value ?? "").trim();
  if (!normalized || !/^\d+$/.test(normalized)) {
    return null;
  }
  const parsed = Number(normalized);
  return Number.isSafeInteger(parsed) && parsed >= min && parsed <= max ? parsed : null;
}

function defaultHttpPortForScheme(scheme) {
  return String(scheme || "").toLowerCase() === "http" ? "80" : "443";
}

function normalizeHttpRequestAuthority(authority, scheme = "https") {
  const normalizedScheme = String(scheme || "https").toLowerCase();
  const target = authorityToTargetState(authority, normalizedScheme);
  return {
    host: stripIpv6Brackets(String(target.host || "").trim()).toLowerCase(),
    port: normalizePortValue(target.port) || defaultHttpPortForScheme(normalizedScheme),
  };
}

function httpRequestAuthoritiesEquivalent(left, right, scheme = "https") {
  const normalizedLeft = normalizeHttpRequestAuthority(left, scheme);
  const normalizedRight = normalizeHttpRequestAuthority(right, scheme);
  return normalizedLeft.host === normalizedRight.host && normalizedLeft.port === normalizedRight.port;
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
    httpVersionMode: replayHttpVersionState(entry.request, entry.requestText, entry.httpVersionMode),
    responseRecord: cloneTransactionRecord(entry.responseRecord),
    notice: entry.notice || "",
    targetScheme: normalizedTarget.scheme,
    targetHost: normalizedTarget.host,
    targetPort: normalizedTarget.port,
  };
}

function cloneReplayTabState(tab) {
  if (!tab || typeof tab !== "object") {
    return null;
  }

  if (tab.type === "websocket") {
    const wsFrames = getWsReplayFrames(tab).map((frame) => ({ ...frame }));
    const clone = {
      id: tab.id,
      type: "websocket",
      sequence: tab.sequence,
      customLabel: normalizeReplayTabCustomLabel(tab.customLabel || ""),
      pinned: !!tab.pinned,
      label: tab.label || `WS ${tab.wsHost || "draft"}`,
      wsScheme: tab.wsScheme || "wss",
      wsHost: tab.wsHost || "",
      wsPort: normalizePortValue(tab.wsPort) || defaultWsPortForScheme(tab.wsScheme || "wss"),
      wsPath: tab.wsPath || "/",
      wsHeaders: normalizedHeaders(tab.wsHeaders),
      wsHandshakeText: tab.wsHandshakeText || "",
      wsHandshakeEdited: !!tab.wsHandshakeEdited,
      wsStatus: tab.wsStatus || "disconnected",
      wsFrames,
      wsFramesTruncated: !!tab.wsFramesTruncated,
      wsSelectedFrameIndex: normalizeWsReplaySavedFrameIndex(wsFrames, tab.wsSelectedFrameIndex),
      wsFrameWindowStart: normalizeWsReplaySavedFrameWindowStart(wsFrames, tab.wsFrameWindowStart),
      wsSessionId: tab.wsSessionId || null,
      wsEditorText: tab.wsEditorText || "",
      wsMessageType: normalizeWsMessageType(tab.wsMessageType),
      wsEditorBodyEncoded: !!tab.wsEditorBodyEncoded,
      wsError: tab.wsError || null,
      wsPollTimer: null,
      wsLifecycleToken: Number(tab.wsLifecycleToken) || 0,
      wsSetupPending: !!tab.wsSetupPending,
      wsSetupRunning: !!tab.wsSetupRunning,
      wsSetupNotice: tab.wsSetupNotice || "",
      wsSetupQueue: Array.isArray(tab.wsSetupQueue)
        ? tab.wsSetupQueue.map((item) => ({
            ...normalizeWsSetupItem(item),
            sent: !!item.sent,
          }))
        : [],
    };
    rebuildWsReplayFrameTracking(clone);
    return clone;
  }

  const historyEntries = Array.isArray(tab.historyEntries)
    ? tab.historyEntries.map(cloneRepeaterHistoryEntry)
    : [];
  return {
    id: tab.id,
    sequence: tab.sequence,
    customLabel: normalizeReplayTabCustomLabel(tab.customLabel || ""),
    pinned: !!tab.pinned,
    baseRequest: tab.baseRequest ? cloneEditableRequest(tab.baseRequest) : createDefaultEditableRequest(),
    sourceTransactionId: tab.sourceTransactionId || null,
    notice: tab.notice || "",
    requestText: tab.requestText || "",
    httpVersionMode: normalizeReplayHttpVersionMode(tab.httpVersionMode),
    responseRecord: cloneTransactionRecord(tab.responseRecord),
    targetScheme: tab.targetScheme || "https",
    targetHost: tab.targetHost || "",
    targetPort: normalizePortValue(tab.targetPort),
    targetManuallyEdited: !!tab.targetManuallyEdited,
    historyEntries,
    historyIndex: normalizeRepeaterHistoryIndex(tab.historyIndex, historyEntries.length),
    requestBytes: tab.requestBytes ? new Uint8Array(tab.requestBytes) : null,
    requestOriginalBytes: tab.requestOriginalBytes ? new Uint8Array(tab.requestOriginalBytes) : null,
  };
}

function restoreReplayTabState(tab, snapshot) {
  const restored = cloneReplayTabState(snapshot);
  if (!tab || !restored) {
    return;
  }
  for (const key of Object.keys(tab)) {
    delete tab[key];
  }
  Object.assign(tab, restored);
  if (tab.type === "websocket") {
    rebuildWsReplayFrameTracking(tab);
  }
}

function snapshotReplayTabsState() {
  return {
    tabs: state.replayTabs.map(cloneReplayTabState).filter(Boolean),
    activeReplayTabId: state.activeReplayTabId,
    replayTabSequence: state.replayTabSequence,
    replayRenamingTabId: state.replayRenamingTabId,
  };
}

function restoreReplayTabsState(snapshot) {
  if (!snapshot || !Array.isArray(snapshot.tabs)) {
    return;
  }
  state.replayTabs = snapshot.tabs.map(cloneReplayTabState).filter(Boolean);
  state.activeReplayTabId = state.replayTabs.some((tab) => tab.id === snapshot.activeReplayTabId)
    ? snapshot.activeReplayTabId
    : state.replayTabs[0]?.id ?? null;
  state.replayTabSequence = Number.isFinite(snapshot.replayTabSequence)
    ? snapshot.replayTabSequence
    : Math.max(...state.replayTabs.map((tab) => Number(tab.sequence) || 0), 0);
  state.replayRenamingTabId = state.replayTabs.some((tab) => tab.id === snapshot.replayRenamingTabId)
    ? snapshot.replayRenamingTabId
    : null;
}

function restoreReplayTabConflictState(tab, snapshot) {
  restoreReplayTabState(tab, snapshot);
  if (state.activeReplayTabId === tab?.id) {
    renderReplay();
  } else {
    renderReplayTabs();
  }
}

function recordRepeaterHistory(tab, snapshot) {
  const requestText = snapshot.requestText || "";
  const entry = {
    request: cloneEditableRequest(snapshot.request),
    requestText,
    httpVersionMode: replayHttpVersionState(
      snapshot.request,
      requestText,
      snapshot.httpVersionMode || tab.httpVersionMode,
    ),
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
  tab.httpVersionMode = replayHttpVersionState(entry.request, tab.requestText, entry.httpVersionMode);
  tab.responseRecord = entry.responseRecord || null;
  tab.notice = entry.notice || "";
  tab.targetScheme = normalizedTarget.scheme;
  tab.targetHost = normalizedTarget.host;
  tab.targetPort = normalizedTarget.port;
  tab.targetManuallyEdited = !targetStatesEquivalent(
    normalizedTarget,
    authorityToTargetState(entry.request.host, entry.request.scheme),
  );
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
  const source = request || {};
  return {
    scheme: source.scheme,
    host: source.host,
    method: source.method,
    path: source.path,
    headers: normalizedHeaders(source.headers),
    body: source.body,
    body_encoding: source.body_encoding,
    preview_truncated: source.preview_truncated,
  };
}

function cloneTransactionRecord(record) {
  return record ? JSON.parse(JSON.stringify(record)) : null;
}

function buildTruncatedBodyNotice(record, tool) {
  const request = record?.request || {};
  const previewCap = state.settings?.body_preview_bytes || String(request.body_preview || "").length;
  const originalSize = request.decoded_body_size ?? request.body_size;
  return `${tool} cannot safely resend this capture yet. The original request body is ${formatSize(originalSize)}, but only a ${formatSize(previewCap)} preview was captured. Increase the preview cap and capture it again, or paste the full body manually before sending.`;
}

function isRequestPreviewTruncated(record) {
  return Boolean(record?.request?.preview_truncated);
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

  if (isModalVisible(els.curlImportModal)) {
    return {
      close: closeCurlImportModal,
      apply: null,
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

function sanitizeActiveTool(value) {
  const tool = String(value || "").trim();
  return IMPLEMENTED_TOOLS.has(tool) ? tool : "proxy";
}

function sanitizeActiveProxyTab(value) {
  const proxyTab = String(value || "").trim();
  return IMPLEMENTED_PROXY_TABS.has(proxyTab) ? proxyTab : "http-history";
}

function sanitizeHttpQuery(value) {
  return String(value || "").trim().slice(0, 512);
}

function sanitizeHttpMethod(value) {
  const method = String(value || "").trim().toUpperCase();
  return HTTP_METHOD_FILTER_OPTIONS.has(method) ? method : "";
}

function sanitizeHttpSortKey(value) {
  const sortKey = String(value || "").trim();
  return HTTP_HISTORY_SORT_KEYS.has(sortKey) ? sortKey : "index";
}

function sanitizeHttpSortDirection(value) {
  return String(value || "").trim() === "asc" ? "asc" : "desc";
}

function sanitizeHttpBooleanMap(candidate, defaults) {
  const next = { ...defaults };
  if (candidate && typeof candidate === "object") {
    Object.keys(defaults).forEach((key) => {
      if (typeof candidate[key] === "boolean") {
        next[key] = candidate[key];
      }
    });
    if (Object.prototype.hasOwnProperty.call(defaults, "clientError") && typeof candidate.client_error === "boolean") {
      next.clientError = candidate.client_error;
    }
    if (Object.prototype.hasOwnProperty.call(defaults, "serverError") && typeof candidate.server_error === "boolean") {
      next.serverError = candidate.server_error;
    }
  }
  return Object.values(next).some(Boolean) ? next : { ...defaults };
}

function sanitizeHttpColorTags(value) {
  const values = Array.isArray(value)
    ? value
    : (value && typeof value[Symbol.iterator] === "function" ? [...value] : []);
  const tags = new Set();
  values.forEach((candidate) => {
    const tag = String(candidate || "").trim();
    if (HTTP_COLOR_TAG_OPTIONS.has(tag)) {
      tags.add(tag);
    }
  });
  return tags;
}

function sanitizeHttpFilterSettings(candidate) {
  const defaults = createDefaultFilterSettings();
  const filters = candidate && typeof candidate === "object" ? candidate : {};
  return {
    inScopeOnly: Boolean(filters.in_scope_only ?? filters.inScopeOnly ?? defaults.inScopeOnly),
    hideWithoutResponses: Boolean(filters.hide_without_responses ?? filters.hideWithoutResponses ?? defaults.hideWithoutResponses),
    onlyParameterized: Boolean(filters.only_parameterized ?? filters.onlyParameterized ?? defaults.onlyParameterized),
    onlyNotes: Boolean(filters.only_notes ?? filters.onlyNotes ?? defaults.onlyNotes),
    searchTerm: String(filters.search_term ?? filters.searchTerm ?? defaults.searchTerm).trim().slice(0, 512),
    regex: Boolean(filters.regex ?? defaults.regex),
    caseSensitive: Boolean(filters.case_sensitive ?? filters.caseSensitive ?? defaults.caseSensitive),
    negativeSearch: Boolean(filters.negative_search ?? filters.negativeSearch ?? defaults.negativeSearch),
    mime: sanitizeHttpBooleanMap(filters.mime, defaults.mime),
    status: sanitizeHttpBooleanMap(filters.status, defaults.status),
    hiddenExtensions: String(filters.hidden_extensions ?? filters.hiddenExtensions ?? defaults.hiddenExtensions).trim().slice(0, 512),
    port: String(filters.port ?? defaults.port).trim().slice(0, 512),
    colorTags: sanitizeHttpColorTags(filters.color_tags ?? filters.colorTags),
  };
}

function serializeHttpFilterSettings() {
  const filters = sanitizeHttpFilterSettings(state.filterSettings);
  return {
    in_scope_only: filters.inScopeOnly,
    hide_without_responses: filters.hideWithoutResponses,
    only_parameterized: filters.onlyParameterized,
    only_notes: filters.onlyNotes,
    search_term: filters.searchTerm,
    regex: filters.regex,
    case_sensitive: filters.caseSensitive,
    negative_search: filters.negativeSearch,
    mime: { ...filters.mime },
    status: {
      success: filters.status.success,
      redirect: filters.status.redirect,
      client_error: filters.status.clientError,
      server_error: filters.status.serverError,
      other: filters.status.other,
    },
    hidden_extensions: filters.hiddenExtensions,
    port: filters.port,
    color_tags: [...filters.colorTags],
  };
}

function sanitizeWebsocketQuery(value) {
  return String(value || "").trim().slice(0, 512);
}

function sanitizeWebsocketSortKey(value) {
  const sortKey = String(value || "").trim();
  return WEBSOCKET_SORT_KEYS.has(sortKey) ? sortKey : "started_at";
}

function sanitizeWebsocketSortDirection(value) {
  return String(value || "").trim() === "asc" ? "asc" : "desc";
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
      return `<td>${item.sequence != null ? item.sequence : entry.index + 1}</td>`;
    case "host":
      return `<td class="cell-host">${escapeHtml(item.host)}</td>`;
    case "method":
      return `<td><span class="method-pill ${methodTone(item.method)}">${escapeHtml(item.method)}</span></td>`;
    case "path":
      return `<td class="cell-url">${escapeHtml(item.path || "(CONNECT tunnel)")}</td>`;
    case "status":
      return `<td><span class="status-pill-row ${statusTone(item.status)}">${escapeHtml(formatStatus(item.status))}</span></td>`;
    case "length":
      return `<td class="col-center">${escapeHtml(item._sizeLabel || formatSize((item.request_bytes ?? 0) + (item.response_bytes ?? 0)))}</td>`;
    case "mime":
      return `<td class="col-center">${escapeHtml(item._mime || inferMimeType(item))}</td>`;
    case "notes": {
      // No colour dot here: the tag already tints the whole row.
      const noteIndicator = item.has_user_note ? `<span class="note-icon" title="Has note">\ud83d\udcdd</span>` : "";
      const hasNotes = !!(item.note_count || item.has_user_note);
      // Show what the note says rather than how many there are; the cell
      // ellipsises and reveals more as the column is widened.
      const preview = typeof item.note_preview === "string" ? item.note_preview : "";
      const extra = item.note_count > 1 ? `<span class="note-more">+${item.note_count - 1}</span>` : "";
      const body = preview
        ? `<span class="note-preview">${escapeHtml(preview)}</span>${extra}`
        : (item.note_count ? ` ${item.note_count}` : "");
      const cellAttrs = hasNotes
        ? ` data-col="notes" class="notes-cell-actionable" title="${escapeHtml(preview || "Click to view notes")}"`
        : ' data-col="notes"';
      return `<td${cellAttrs}>${noteIndicator}${body}</td>`;
    }
    case "tls": {
      const tls = isTlsRecord(item) ? '<span class="tls-badge">TLS</span>' : '<span class="tls-badge empty">-</span>';
      return `<td class="tls-cell">${tls}</td>`;
    }
    case "started_at":
      return `<td>${escapeHtml(getHistoryTimeLabel(item))}</td>`;
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
  uiSettingsDirty = true;
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

function updateUiSettingsServerRevision(snapshot) {
  const revision = Number(snapshot?.server_revision);
  if (Number.isFinite(revision) && revision >= 0) {
    uiSettingsServerRevision = Math.max(0, Math.floor(revision));
  }
}

function applyUiSettingsSnapshot(snapshot) {
  updateUiSettingsServerRevision(snapshot);
  state.displaySettings = sanitizeDisplaySettings({
    sizePx: snapshot?.display_settings?.size_px,
    theme: snapshot?.display_settings?.theme,
    uiFont: snapshot?.display_settings?.ui_font,
    monoFont: snapshot?.display_settings?.mono_font,
  });
  state.activeTool = sanitizeActiveTool(snapshot?.active_tool);
  state.activeProxyTab = sanitizeActiveProxyTab(snapshot?.active_proxy_tab);
  state.historyColumnWidths = sanitizeHistoryColumnWidths(snapshot?.history_column_widths);
  state.historyColumnOrder = sanitizeHistoryColumnOrder(snapshot?.history_column_order);
  state.query = sanitizeHttpQuery(snapshot?.http_query);
  state.method = sanitizeHttpMethod(snapshot?.http_method);
  state.sortKey = sanitizeHttpSortKey(snapshot?.http_sort_key);
  state.sortDirection = sanitizeHttpSortDirection(snapshot?.http_sort_direction);
  state.filterSettings = sanitizeHttpFilterSettings(snapshot?.http_filter_settings);
  if (snapshot?.ws_column_widths && typeof snapshot.ws_column_widths === "object") {
    Object.entries(snapshot.ws_column_widths).forEach(([k, v]) => {
      if (WS_COLUMN_RULES[k] && WS_COLUMN_RULES[k].max > 0 && typeof v === "number") {
        state.wsColumnWidths[k] = clamp(v, WS_COLUMN_RULES[k].min, WS_COLUMN_RULES[k].max);
      }
    });
  }
  state.workbenchHeight = sanitizeWorkbenchHeight(snapshot?.workbench_height);
  state.workbenchPaneWidths = sanitizeWorkbenchPaneWidths(snapshot?.workbench_pane_widths);
  state.websocketPaneWidth = sanitizeWebsocketPaneWidth(snapshot?.websocket_pane_width);
  state.websocketQuery = sanitizeWebsocketQuery(snapshot?.websocket_query);
  state.websocketSortKey = sanitizeWebsocketSortKey(snapshot?.websocket_sort_key);
  state.websocketSortDirection = sanitizeWebsocketSortDirection(snapshot?.websocket_sort_direction);
  state.websocketInScopeOnly = Boolean(snapshot?.websocket_in_scope_only);
  state.websocketLiveOnly = Boolean(snapshot?.websocket_live_only);
  state.websocketStackHeight = sanitizeWebsocketStackHeight(snapshot?.websocket_stack_height);
  state.wsReplayLeftWidth = sanitizeWsReplayLeftWidth(snapshot?.ws_replay_left_width);
  state.wsReplayFrameDetailHeight = sanitizeWsReplayFrameDetailHeight(snapshot?.ws_replay_frame_detail_height);
  if (els.websocketSearchInput) {
    els.websocketSearchInput.value = state.websocketQuery;
  }
  if (els.searchInput) {
    els.searchInput.value = state.query;
  }
  if (els.methodFilter) {
    els.methodFilter.value = state.method;
  }
  hydrateFilterForm();
  syncHttpInScopePill();
  document.getElementById("wsInScopeOnly")?.classList.toggle("active", state.websocketInScopeOnly);
  document.getElementById("wsHideClosed")?.classList.toggle("active", state.websocketLiveOnly);
  applyDisplaySettingsState();
  renderHistoryHeader();
  applyHistoryColumnWidths();
  applyWsColumnWidths();
  updateWebsocketSortIndicators();
  applySavedWorkbenchPaneWidths();
  applySavedWebsocketPaneWidth();
  applySavedWebsocketStackHeight();
  applySavedWsReplayLayout();

  if (state.workbenchHeight) {
    applyWorkbenchStackHeight(state.workbenchHeight, false);
  } else {
    els.proxyShell?.style.removeProperty("--workbench-pane-height");
  }
}

function snapshotUiSettings() {
  return {
    client_id: uiSettingsClientId,
    client_version: uiSettingsSaveVersion,
    server_revision: uiSettingsServerRevision,
    display_settings: {
      size_px: state.displaySettings.sizePx,
      theme: state.displaySettings.theme,
      ui_font: state.displaySettings.uiFont,
      mono_font: state.displaySettings.monoFont,
    },
    active_tool: sanitizeActiveTool(state.activeTool),
    active_proxy_tab: sanitizeActiveProxyTab(state.activeProxyTab),
    history_column_widths: { ...state.historyColumnWidths },
    history_column_order: [...state.historyColumnOrder],
    ws_column_widths: { ...state.wsColumnWidths },
    http_query: sanitizeHttpQuery(state.query),
    http_method: sanitizeHttpMethod(state.method),
    http_sort_key: sanitizeHttpSortKey(state.sortKey),
    http_sort_direction: sanitizeHttpSortDirection(state.sortDirection),
    http_filter_settings: serializeHttpFilterSettings(),
    workbench_height: state.workbenchHeight > 0 ? state.workbenchHeight : null,
    workbench_pane_widths: serializeWorkbenchPaneWidths(),
    websocket_pane_width: state.websocketPaneWidth > 0 ? state.websocketPaneWidth : null,
    websocket_query: sanitizeWebsocketQuery(state.websocketQuery),
    websocket_sort_key: sanitizeWebsocketSortKey(state.websocketSortKey),
    websocket_sort_direction: sanitizeWebsocketSortDirection(state.websocketSortDirection),
    websocket_in_scope_only: Boolean(state.websocketInScopeOnly),
    websocket_live_only: Boolean(state.websocketLiveOnly),
    websocket_stack_height: state.websocketStackHeight > 0 ? state.websocketStackHeight : null,
    ws_replay_left_width: state.wsReplayLeftWidth > 0 ? state.wsReplayLeftWidth : null,
    ws_replay_frame_detail_height: state.wsReplayFrameDetailHeight > 0 ? state.wsReplayFrameDetailHeight : null,
  };
}

function nextUiSettingsSnapshot() {
  uiSettingsSaveVersion += 1;
  return snapshotUiSettings();
}

function nextUiSettingsPayload() {
  return JSON.stringify(nextUiSettingsSnapshot());
}

function scheduleUiSettingsSave(delay = 180) {
  uiSettingsDirty = true;
  window.clearTimeout(uiSettingsSaveTimer);
  uiSettingsSaveTimer = window.setTimeout(() => {
    uiSettingsSaveTimer = null;
    persistUiSettings().catch((error) => console.error(error));
  }, delay);
}

function scheduleUiSettingsRetry(delay = 1000) {
  if (uiSettingsSaveTimer) {
    return;
  }
  uiSettingsSaveTimer = window.setTimeout(() => {
    uiSettingsSaveTimer = null;
    persistUiSettings().catch((error) => console.error(error));
  }, delay);
}

async function persistUiSettings() {
  if (uiSettingsSavePromise) {
    return uiSettingsSavePromise;
  }
  const savePromise = (async () => {
    uiSettingsInFlight = true;
    try {
      while (uiSettingsDirty) {
        uiSettingsDirty = false;
        const payloadSnapshot = nextUiSettingsSnapshot();
        const payload = JSON.stringify(payloadSnapshot);
        lastUiSettingsPayload = payload;
        let response;
        try {
          response = await fetch("/api/ui-settings", {
            method: "POST",
            headers: {
              "content-type": "application/json",
            },
            body: payload,
          });
        } catch (error) {
          uiSettingsDirty = true;
          scheduleUiSettingsRetry();
          throw error;
        }

        if (!response.ok) {
          uiSettingsDirty = true;
          scheduleUiSettingsRetry();
          throw new Error(await response.text());
        }
        const savedSnapshot = await response.json().catch(() => null);
        if (savedSnapshot && typeof savedSnapshot === "object") {
          updateUiSettingsServerRevision(savedSnapshot);
          const savedClientId = String(savedSnapshot.client_id || "");
          const savedClientVersion = Math.max(0, Number(savedSnapshot.client_version || 0) || 0);
          if (savedClientId !== payloadSnapshot.client_id || savedClientVersion !== payloadSnapshot.client_version) {
            applyUiSettingsSnapshot(savedSnapshot);
          }
        }
      }
    } finally {
      uiSettingsInFlight = false;
    }
  })();
  uiSettingsSavePromise = savePromise;
  try {
    return await savePromise;
  } finally {
    if (uiSettingsSavePromise === savePromise) {
      uiSettingsSavePromise = null;
    }
  }
}

function flushUiSettingsOnUnload() {
  if (!uiSettingsSaveTimer && !uiSettingsDirty && !uiSettingsInFlight) {
    return;
  }
  window.clearTimeout(uiSettingsSaveTimer);
  uiSettingsSaveTimer = null;
  const payload = uiSettingsDirty ? nextUiSettingsPayload() : lastUiSettingsPayload;
  if (!payload) {
    return;
  }
  lastUiSettingsPayload = payload;
  const blob = new Blob([payload], { type: "application/json" });
  if (navigator.sendBeacon && navigator.sendBeacon("/api/ui-settings", blob)) {
    return;
  }
  fetch("/api/ui-settings", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: payload,
    keepalive: true,
  }).catch(() => {});
}

function sanitizeWorkbenchHeight(candidate) {
  const parsed = Number(candidate);
  return Number.isFinite(parsed) && parsed > 0 ? Math.round(parsed) : null;
}

function sanitizeWorkbenchPaneWidths(candidate) {
  if (!candidate || typeof candidate !== "object") {
    return null;
  }
  const requestPercent = Number(candidate.request_percent);
  const responsePercent = Number(candidate.response_percent);
  const inspectorWidth = Number(candidate.inspector_width);
  const next = {};
  if (Number.isFinite(requestPercent) && requestPercent > 0) {
    next.requestPercent = clamp(Math.round(requestPercent), 18, 72);
  }
  if (Number.isFinite(responsePercent) && responsePercent > 0) {
    next.responsePercent = clamp(Math.round(responsePercent), 18, 72);
  }
  if (Number.isFinite(inspectorWidth) && inspectorWidth > 0) {
    next.inspectorWidth = clamp(Math.round(inspectorWidth), WORKBENCH_MIN_WIDTHS.inspector, 4096);
  }
  return Object.keys(next).length ? next : null;
}

function sanitizeWebsocketPaneWidth(candidate) {
  const parsed = Number(candidate);
  return Number.isFinite(parsed) && parsed > 0
    ? clamp(Math.round(parsed), WEBSOCKET_WORKBENCH_MIN_WIDTHS.handshake, 4096)
    : null;
}

function serializeWorkbenchPaneWidths() {
  if (!state.workbenchPaneWidths) {
    return {};
  }
  return {
    request_percent: state.workbenchPaneWidths.requestPercent ?? null,
    response_percent: state.workbenchPaneWidths.responsePercent ?? null,
    inspector_width: state.workbenchPaneWidths.inspectorWidth ?? null,
  };
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
  els.filterMimeWebsocket.checked = filters.mime.websocket !== false;
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
  const searchTerm = els.filterSearchTerm.value.trim();
  const nextMime = {
    html: els.filterMimeHtml.checked,
    script: els.filterMimeScript.checked,
    json: els.filterMimeJson.checked,
    css: els.filterMimeCss.checked,
    image: els.filterMimeImage.checked,
    websocket: els.filterMimeWebsocket.checked,
    other: els.filterMimeOther.checked,
  };
  const nextStatus = {
    success: els.filterStatus2xx.checked,
    redirect: els.filterStatus3xx.checked,
    clientError: els.filterStatus4xx.checked,
    serverError: els.filterStatus5xx.checked,
    other: els.filterStatusOther.checked,
  };
  if (!Object.values(nextStatus).some(Boolean)) {
    showToast("Select at least one status filter.", "error");
    return;
  }
  if (!Object.values(nextMime).some(Boolean)) {
    showToast("Select at least one MIME filter.", "error");
    return;
  }
  if (els.filterRegex.checked && searchTerm) {
    try {
      new RegExp(searchTerm, els.filterCaseSensitive.checked ? "" : "i");
    } catch (error) {
      const message = `Invalid regex: ${error.message}`;
      if (els.historyMeta) els.historyMeta.textContent = message;
      showToast(message, "error");
      return;
    }
  }
  state.filterSettings = {
    inScopeOnly: els.filterInScopeOnly.checked,
    hideWithoutResponses: els.filterHideWithoutResponses.checked,
    onlyParameterized: els.filterOnlyParameterized.checked,
    onlyNotes: els.filterOnlyNotes.checked,
    searchTerm,
    regex: els.filterRegex.checked,
    caseSensitive: els.filterCaseSensitive.checked,
    negativeSearch: els.filterNegativeSearch.checked,
    mime: nextMime,
    status: nextStatus,
    hiddenExtensions: els.filterHiddenExtensions.value.trim(),
    port: els.filterPort.value.trim(),
    colorTags: state.filterSettings.colorTags,
  };
  closeFilterModal();
  syncHttpInScopePill();
  scheduleUiSettingsSave();
  clearHttpHistorySelectionPreview();
  scheduleRefresh({ resetScroll: true });
}

async function openCertificateFolder() {
  try {
    const response = await fetch("/api/certificates/reveal", { method: "POST" });
    await requireOkResponse(response, "Failed to open certificate folder.");
  } catch (error) {
    console.error("Failed to open certificate folder:", error);
    showToast(error?.message || "Failed to open certificate folder.", "error");
  }
}

function buildMessagePresentation(target, record) {
  const mode = state.messageViews[target];
  const text = target === "request" ? buildRawRequest(record) : buildRawResponse(record);

  if (mode === "hex") {
    return buildMessageHexPresentation(target, record, text);
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
  const head = buildRawRequestHead(record);
  const request = record.request || {};
  const body = renderBody(request);
  return body.length > 0 ? `${head}\n\n${body}` : head;
}

function buildRawRequestHead(record) {
  const httpVer = record.http_version || "HTTP/1.1";
  const startLine = record.kind === "tunnel"
    ? `CONNECT ${record.host} ${httpVer}`
    : `${record.method} ${record.path || "/"} ${httpVer}`;
  const request = record.request || {};
  const merged = mergeHeaders(request.headers);
  // Ensure a host header is present — the proxy stores the host separately
  // and some tunnelled HTTPS requests omit Host from the captured headers.
  if (record.host && !merged.some((h) => headerNameEquals(h, "host"))) {
    merged.unshift({ name: "host", value: record.host });
  }
  const headers = merged
    .map((header) => `${header.name}: ${header.value}`)
    .join("\n");
  return headers ? `${startLine}\n${headers}` : startLine;
}

function mergeHeaders(headers) {
  const merged = [];
  const cookieParts = [];
  for (const h of normalizedHeaders(headers)) {
    if (headerNameEquals(h, "cookie")) {
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

function normalizedHeaders(headers) {
  return (Array.isArray(headers) ? headers : [])
    .map((h) => ({
      name: String(h?.name || ""),
      value: String(h?.value ?? ""),
    }))
    .filter((h) => h.name);
}

function headerNameEquals(header, name) {
  return String(header?.name || "").toLowerCase() === String(name || "").toLowerCase();
}

function headerValueContainsToken(value, token) {
  const expected = String(token || "").trim().toLowerCase();
  if (!expected) return false;
  return String(value || "")
    .split(",")
    .map((part) => part.trim().toLowerCase())
    .includes(expected);
}

function buildRawResponse(record) {
  if (!record.response) {
    return "No response was captured for this exchange.";
  }

  const head = buildRawResponseHead(record);
  const body = renderBody(record.response || {});
  return body.length > 0 ? `${head}\n\n${body}` : head;
}

function buildRawResponseHead(record) {
  const response = record.response || {};
  const headers = normalizedHeaders(response.headers)
    .map((header) => `${header.name}: ${header.value}`)
    .join("\n");
  const httpVer = record.response_http_version || record.http_version || "HTTP/1.1";
  const statusLine = `${httpVer} ${record.status ?? 0}`;
  return headers ? `${statusLine}\n${headers}` : statusLine;
}

function buildFindingsRawMessage(record, side) {
  const msg = side === "request" ? record.request : record.response;
  const httpVer = side === "request"
    ? record.http_version || "HTTP/1.1"
    : record.response_http_version || record.http_version || "HTTP/1.1";
  if (side === "request") {
    const startLine = record.kind === "tunnel"
      ? `CONNECT ${record.host} ${httpVer}`
      : `${record.method} ${record.path || "/"} ${httpVer}`;
    const request = record.request || {};
    const merged = mergeHeaders(request.headers);
    if (record.host && !merged.some((h) => headerNameEquals(h, "host"))) {
      merged.unshift({ name: "host", value: record.host });
    }
    const headers = merged.map((h) => `${h.name}: ${h.value}`).join("\n");
    const body = findingsBodyPlaceholder(msg);
    const head = headers ? `${startLine}\n${headers}` : startLine;
    return body.length > 0 ? `${head}\n\n${body}` : head;
  }
  if (!msg) return "No response was captured for this exchange.";
  const headers = normalizedHeaders(msg.headers).map((h) => `${h.name}: ${h.value}`).join("\n");
  const body = findingsBodyPlaceholder(msg);
  const head = headers ? `${httpVer} ${record.status ?? 0}\n${headers}` : `${httpVer} ${record.status ?? 0}`;
  return body.length > 0 ? `${head}\n\n${body}` : head;
}

function findingsBodyPlaceholder(msg) {
  if (!msg || !msg.body_preview) return "";
  if (msg.body_encoding === "base64") {
    return binaryBodyPlaceholder(msg);
  }
  return msg.preview_truncated
    ? `${msg.body_preview}\n\n[preview truncated]`
    : msg.body_preview;
}

function binaryBodyPlaceholder(msg) {
  const contentType = msg.content_type || "binary";
  const decodedSize = msg.decoded_body_size ?? msg.body_size;
  const size = Number.isFinite(Number(decodedSize)) ? `, ${formatSize(decodedSize)}` : "";
  return `[${contentType}${size}, base64 preview omitted]`;
}

function buildRawWebsocketRequest(session) {
  const headers = mergeHeaders(session?.request?.headers)
    .map((header) => `${header.name}: ${header.value}`)
    .join("\n");
  return `GET ${session?.path || "/"} HTTP/1.1\n${headers}`.trim();
}

function buildRawWebsocketResponse(session) {
  if (!session.response) {
    return "No handshake response was captured.";
  }

  const headers = normalizedHeaders(session.response.headers)
    .map((header) => `${header.name}: ${header.value}`)
    .join("\n");
  return `HTTP/1.1 ${session.status ?? 101}\n${headers}`.trim();
}

function renderBody(message) {
  if (!message || !message.body_preview) {
    return "";
  }

  if (message.body_encoding === "base64") {
    return binaryBodyPlaceholder(message);
  }

  return message.preview_truncated
    ? `${message.body_preview}\n\n[preview truncated]`
    : message.body_preview;
}

function buildMessageHexPresentation(target, record, fallbackText) {
  if (target === "request") {
    return toHexDumpFromHttpParts(buildRawRequestHead(record), record.request, fallbackText);
  }
  if (!record.response) {
    return toHexDump(fallbackText);
  }
  return toHexDumpFromHttpParts(buildRawResponseHead(record), record.response, fallbackText);
}

function toHexDumpFromHttpParts(head, message, fallbackText) {
  const bodyBytes = messageBodyBytes(message);
  if (!bodyBytes) {
    return toHexDump(fallbackText);
  }
  const encoder = new TextEncoder();
  const headBytes = encoder.encode(head || "");
  if (!bodyBytes.length) {
    return toHexDumpFromBytes(headBytes);
  }
  const separator = encoder.encode("\n\n");
  const bytes = new Uint8Array(headBytes.length + separator.length + bodyBytes.length);
  bytes.set(headBytes, 0);
  bytes.set(separator, headBytes.length);
  bytes.set(bodyBytes, headBytes.length + separator.length);
  return toHexDumpFromBytes(bytes);
}

function messageBodyBytes(message) {
  if (!message || !message.body_preview) {
    return new Uint8Array();
  }
  if (message.body_encoding === "base64") {
    return base64ToBytes(message.body_preview);
  }
  const text = message.preview_truncated
    ? `${message.body_preview}\n\n[preview truncated]`
    : message.body_preview;
  return new TextEncoder().encode(text);
}

function base64ToBytes(value) {
  try {
    const decoded = atob(value || "");
    const bytes = new Uint8Array(decoded.length);
    for (let index = 0; index < decoded.length; index += 1) {
      bytes[index] = decoded.charCodeAt(index);
    }
    return bytes;
  } catch (_error) {
    return null;
  }
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
  const request = record.request || {};
  return {
    scheme: record.scheme,
    host: record.host,
    method: record.method,
    path: record.path || "/",
    http_version: record.http_version,
    headers: normalizedHeaders(request.headers),
    body: request.body_preview || "",
    body_encoding: request.body_encoding,
    preview_truncated: request.preview_truncated,
  };
}

function buildEditableRawRequest(request) {
  const source = request || {};
  const headers = normalizedHeaders(source.headers);
  if (!headers.some((header) => headerNameEquals(header, "host")) && source.host) {
    headers.unshift({ name: "host", value: source.host });
  }
  const httpVer = source.http_version || "HTTP/1.1";
  const head = `${source.method || "GET"} ${source.path || "/"} ${httpVer}`;
  const headerBlock = mergeHeaders(headers).map((header) => `${header.name}: ${header.value}`).join("\n");
  const body = source.body || "";
  const rawHead = headerBlock ? `${head}\n${headerBlock}` : head;
  return body.length > 0 ? `${rawHead}\n\n${body}` : rawHead;
}

function parseEditableRawRequest(text, fallback) {
  const { head, body } = splitRawHttpMessage(text);
  const lines = head.split("\n").filter((line) => line.length > 0);
  const fallbackPath = fallback?.path && String(fallback.path).trim()
    ? String(fallback.path)
    : "/";
  const requestLineWasSynthesized = lines.length === 0;
  const [startLine = `${fallback?.method || "GET"} ${fallbackPath}`, ...headerLines] = lines;
  const match = startLine.match(/^([A-Za-z0-9!#$%&'*+.^_`|~-]+)\s+(\S+)(?:\s+(HTTP\/[0-9.]+))?$/);

  if (!match) {
    throw new Error("Invalid request line in editor");
  }

  let [, method, target, httpVersionToken] = match;
  const httpVersion = requestLineWasSynthesized ? undefined : parseReplayHttpVersionToken(httpVersionToken);
  let scheme = fallback?.scheme || "https";
  let host = fallback?.host || "";
  let path = target;
  let absoluteAuthority = "";
  const headers = headerLines
    .map((line) => {
      const index = line.indexOf(":");
      if (index === -1) {
        throw new Error(`Invalid header line: ${line}`);
      }
      return {
        name: line.slice(0, index).trim(),
        value: line.slice(index + 1).trim(),
      };
    })
    .filter(Boolean);

  if (/^https?:\/\//i.test(target)) {
    const absolute = new URL(target);
    if (absolute.username || absolute.password) {
      throw new Error("Absolute request target must not include credentials");
    }
    if (absolute.hash) {
      throw new Error("Absolute request target must not include a fragment");
    }
    scheme = absolute.protocol.replace(":", "");
    host = absolute.host;
    absoluteAuthority = absolute.host;
    path = `${absolute.pathname || "/"}${absolute.search || ""}`;
  }

  const hostHeader = headerValue(headers, "host");
  if (hostHeader) {
    if (absoluteAuthority) {
      if (!httpRequestAuthoritiesEquivalent(absoluteAuthority, hostHeader, scheme)) {
        throw new Error("Absolute-form request target does not match Host header");
      }
    } else {
      host = hostHeader;
    }
  }

  if (method.toUpperCase() === "CONNECT") {
    throw new Error("CONNECT authority-form requests are not supported by Replay");
  }

  if (path !== "*" && !path.startsWith("/")) {
    path = `/${path}`;
  }

  if (!host) {
    throw new Error("Request is missing a Host header");
  }

  const bodyEncoding = fallback?.body_encoding === "base64" ? "base64" : "utf8";
  const bodyLength = editableRequestBodyLength(body, bodyEncoding);
  const acceptedBodyLengths = [bodyLength];
  let contentLengthChanged = false;

  // Auto-update Content-Length if enabled
  if (document.getElementById("proxySettingAutoContentLength")?.checked) {
    for (const header of headers) {
      if (headerNameEquals(header, "content-length")) {
        const nextValue = String(bodyLength);
        if (header.value !== nextValue) {
          header.value = nextValue;
          contentLengthChanged = true;
        }
      }
    }
  }
  validateRawHttpBodyFraming(headers, bodyLength, acceptedBodyLengths);

  const fallbackBody = String(fallback?.body ?? fallback?.body_preview ?? "");
  const fallbackBodyEncoding = fallback?.body_encoding === "base64" ? "base64" : "utf8";
  const previewTruncated = Boolean(fallback?.preview_truncated)
    && body === fallbackBody
    && bodyEncoding === fallbackBodyEncoding;

  const request = {
    scheme,
    host,
    method,
    path,
    http_version: httpVersion,
    headers,
    body,
    body_encoding: bodyEncoding,
    preview_truncated: previewTruncated,
  };
  if (contentLengthChanged) {
    Object.defineProperty(request, "_normalizedRawText", {
      value: buildEditableRawRequest(request),
      enumerable: false,
    });
  }
  return request;
}

function responseStatusMustNotIncludeBody(status) {
  const code = Number(status);
  return Number.isInteger(code) && (code < 200 || code === 204 || code === 205 || code === 304);
}

function responseMustNotIncludeBody(status, requestMethod = "") {
  return responseStatusMustNotIncludeBody(status)
    || String(requestMethod || "").toUpperCase() === "HEAD";
}

function responseContentLengthMayDescribeRepresentation(status, requestMethod = "") {
  const code = Number(status);
  return Number.isInteger(code)
    && (code === 304
      || (String(requestMethod || "").toUpperCase() === "HEAD" && !(code >= 100 && code <= 199) && code !== 204 && code !== 205));
}

function validateRawHttpBodyFraming(headers, bodyLength, acceptedBodyLengths = [bodyLength], options = {}) {
  if (headers.some((header) => headerNameEquals(header, "transfer-encoding")
    && String(header.value || "").split(",").some((value) => value.trim().toLowerCase() === "chunked"))) {
    throw new Error("Raw HTTP input with Transfer-Encoding: chunked is not supported");
  }

  let contentLength = null;
  for (const header of headers.filter((item) => headerNameEquals(item, "content-length"))) {
    const value = String(header.value || "").trim();
    if (!/^\d+$/.test(value)) {
      throw new Error(`Invalid Content-Length: ${header.value}`);
    }
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed)) {
      throw new Error(`Invalid Content-Length: ${header.value}`);
    }
    if (contentLength !== null && contentLength !== parsed) {
      throw new Error("Conflicting Content-Length headers");
    }
    contentLength = parsed;
  }

  const allowRepresentationContentLength = !!options.allowRepresentationContentLength && bodyLength === 0;
  if (contentLength !== null && !acceptedBodyLengths.includes(contentLength) && !allowRepresentationContentLength) {
    throw new Error(`Content-Length ${contentLength} does not match raw body length ${bodyLength}`);
  }
}

function splitRawHttpMessage(text) {
  const raw = String(text ?? "");
  const crlfBoundary = raw.indexOf("\r\n\r\n");
  if (crlfBoundary !== -1) {
    return {
      head: raw.slice(0, crlfBoundary).replace(/\r\n/g, "\n"),
      body: raw.slice(crlfBoundary + 4),
    };
  }

  const lfBoundary = raw.indexOf("\n\n");
  if (lfBoundary !== -1) {
    return {
      head: raw.slice(0, lfBoundary).replace(/\r\n/g, "\n"),
      body: raw.slice(lfBoundary + 2),
    };
  }

  return { head: raw.replace(/\r\n/g, "\n"), body: "" };
}

function headerValue(headers, name) {
  return normalizedHeaders(headers).find((header) => headerNameEquals(header, name))?.value || null;
}

function renderFramePreview(frame) {
  if (!frame.body_preview) {
    return "(empty)";
  }
  if (frame.body_encoding === "base64") {
    const preview = String(frame.body_preview);
    return preview.length > WEBSOCKET_FRAME_ROW_PREVIEW_CHARS
      ? `[base64] ${preview.slice(0, WEBSOCKET_FRAME_ROW_PREVIEW_CHARS)}...`
      : `[base64] ${preview}`;
  }
  return frame.body_preview;
}

function showFrameDetail(frame) {
  const isClient = frame.direction === "client_to_server";
  const dirClass = isClient ? "dir-client" : "dir-server";
  const dirLabel = isClient ? "client \u2192" : "\u2190 server";
  const truncatedLabel = frame.preview_truncated ? `<span>preview truncated</span>` : "";
  els.frameDetailMeta.innerHTML = `
    <span>#${(frame.index ?? 0) + 1}</span>
    <span class="${dirClass}">${dirLabel}</span>
    <span>${escapeHtml(frame.kind)}</span>
    <span>${escapeHtml(formatSize(frame.body_size))}</span>
    ${truncatedLabel}
  `;

  let body = frame.body_preview || "(empty)";
  if (frame.body_encoding === "base64") {
    els.frameDetailBody.innerHTML = escapeHtml(renderBinaryFrameDetailText(frame));
    els.frameDetailResizer.classList.remove("hidden");
    els.frameDetailPanel.classList.remove("hidden");
    return;
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

function renderBinaryFrameDetailText(frame) {
  const base64 = String(frame?.body_preview ?? frame?.body ?? "");
  const bytes = base64ToBytes(base64);
  const previewSize = bytes ? bytes.length : 0;
  const metadata = [
    `Binary frame kind: ${frame?.kind || "binary"}`,
    `Total size: ${formatSize(frame?.body_size || 0)}`,
    `Preview size: ${formatSize(previewSize)}`,
    `Encoding: base64`,
    `Preview truncated: ${frame?.preview_truncated ? "yes" : "no"}`,
  ].join("\n");

  if (!base64) {
    return `${metadata}\n\n(empty binary preview)`;
  }
  if (!bytes) {
    return `${metadata}\n\nInvalid base64 preview:\n${base64}`;
  }
  return `${metadata}\n\nHex / ASCII preview:\n${toHexDumpFromBytes(bytes)}\n\nBase64 preview:\n${base64}`;
}

function hideFrameDetail() {
  state.selectedFrameIdx = null;
  els.frameDetailResizer.classList.add("hidden");
  els.frameDetailPanel.classList.add("hidden");
  els.websocketFramesBody.querySelectorAll(".ws-frame-bubble.selected").forEach((r) => r.classList.remove("selected"));
  els.websocketFramesBody.querySelectorAll(".frame-selected").forEach((r) => r.classList.remove("frame-selected"));
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
    clearReplayResponseForDraftChange(tab);
    renderReplayTabs();
    updateReplaySearchPane("request", tab.requestText);
    scheduleWorkspaceStateSave();
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
      normalizeWorkbenchStackHeight({ persist: true });
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
    scheduleUiSettingsSave();
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
      if (mode === "response-inspector") {
        const combinedWidth = start.response + start.inspector;
        const nextResponse = clamp(
          start.response + delta,
          WORKBENCH_MIN_WIDTHS.response,
          combinedWidth - WORKBENCH_MIN_WIDTHS.inspector,
        );
        applyWorkbenchPaneWidths(
          start.request,
          nextResponse,
          start.total,
          combinedWidth - nextResponse,
        );
      }
    };

    const onUp = () => {
      document.body.classList.remove("pane-resizing-x");
      handle.classList.remove("active");
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      if (mode === "request-response") {
        normalizeWorkbenchPaneWidths({ updateState: true });
      }
      scheduleUiSettingsSave();
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
    inspector: els.inspectorColumn?.getBoundingClientRect().width || 0,
  };
}

function applySavedWorkbenchPaneWidths() {
  if (!state.workbenchPaneWidths || !els.lowerWorkbench) {
    resetWorkbenchPaneWidths(false);
    return;
  }
  const totalWidth = els.lowerWorkbench.getBoundingClientRect().width;
  if (!totalWidth || window.matchMedia(WORKBENCH_STACK_BREAKPOINT).matches) {
    return;
  }
  const currentRequestWidth = els.requestColumn?.getBoundingClientRect().width || totalWidth / 3;
  const currentResponseWidth = els.responseColumn?.getBoundingClientRect().width || totalWidth / 3;
  const requestWidth = state.workbenchPaneWidths.requestPercent
    ? (state.workbenchPaneWidths.requestPercent / 100) * totalWidth
    : currentRequestWidth;
  const responseWidth = state.workbenchPaneWidths.responsePercent
    ? (state.workbenchPaneWidths.responsePercent / 100) * totalWidth
    : currentResponseWidth;
  applyWorkbenchPaneWidths(
    requestWidth,
    responseWidth,
    totalWidth,
    state.workbenchPaneWidths.inspectorWidth ?? null,
    { updateState: false },
  );
}

function applyWorkbenchPaneWidths(
  requestWidth,
  responseWidth,
  totalWidth = els.lowerWorkbench.getBoundingClientRect().width,
  inspectorWidth = null,
  options = {},
) {
  if (!totalWidth) {
    return;
  }

  const requestPercent = clamp((requestWidth / totalWidth) * 100, 18, 72);
  const responsePercent = clamp((responseWidth / totalWidth) * 100, 18, 72);
  els.lowerWorkbench.style.setProperty("--request-pane-width", `${requestPercent}%`);
  els.lowerWorkbench.style.setProperty("--response-pane-width", `${responsePercent}%`);
  const updateState = options.updateState !== false;
  if (updateState) {
    state.workbenchPaneWidths = {
      ...(state.workbenchPaneWidths || {}),
      requestPercent: Math.round(requestPercent),
      responsePercent: Math.round(responsePercent),
    };
  }
  if (Number.isFinite(inspectorWidth)) {
    const maxInspectorWidth = Math.max(
      WORKBENCH_MIN_WIDTHS.inspector,
      totalWidth - WORKBENCH_MIN_WIDTHS.request - WORKBENCH_MIN_WIDTHS.response,
    );
    const clampedInspectorWidth = clamp(
      inspectorWidth,
      WORKBENCH_MIN_WIDTHS.inspector,
      maxInspectorWidth,
    );
    els.lowerWorkbench.style.setProperty("--inspector-pane-width", `${Math.round(clampedInspectorWidth)}px`);
    if (updateState) {
      state.workbenchPaneWidths.inspectorWidth = Math.round(clampedInspectorWidth);
    }
  }
}

function normalizeWorkbenchPaneWidths(options = {}) {
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
  applyWorkbenchPaneWidths(requestWidth, responseWidth, bounds.total, null, {
    ...options,
    updateState: options.updateState === true,
  });
}

function resetWorkbenchPaneWidths(clearState = true) {
  els.lowerWorkbench.style.removeProperty("--request-pane-width");
  els.lowerWorkbench.style.removeProperty("--response-pane-width");
  els.lowerWorkbench.style.removeProperty("--inspector-pane-width");
  if (clearState) {
    state.workbenchPaneWidths = null;
  }
}

function bindWebsocketPaneResizer(handle) {
  if (!handle) {
    return;
  }

  handle.addEventListener("dblclick", () => {
    resetWebsocketPaneWidth();
    scheduleUiSettingsSave();
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
      normalizeWebsocketPaneWidth({ updateState: true });
      scheduleUiSettingsSave();
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

function applyWebsocketPaneWidth(handshakeWidth, options = {}) {
  if (!els.websocketWorkbench) {
    return;
  }
  const bounds = getWebsocketWorkbenchWidths();
  const maxWidth = bounds
    ? bounds.total - WEBSOCKET_WORKBENCH_MIN_WIDTHS.frames
    : 4096;
  const roundedWidth = Math.round(clamp(
    handshakeWidth,
    WEBSOCKET_WORKBENCH_MIN_WIDTHS.handshake,
    Math.max(WEBSOCKET_WORKBENCH_MIN_WIDTHS.handshake, maxWidth),
  ));
  els.websocketWorkbench.style.setProperty("--websocket-left-pane-width", `${roundedWidth}px`);
  if (options.updateState !== false) {
    state.websocketPaneWidth = roundedWidth;
  }
}

function applySavedWebsocketPaneWidth() {
  if (!state.websocketPaneWidth || !els.websocketWorkbench) {
    resetWebsocketPaneWidth(false);
    return;
  }
  if (window.matchMedia(WEBSOCKET_WORKBENCH_BREAKPOINT).matches) {
    return;
  }
  const bounds = getWebsocketWorkbenchWidths();
  if (!bounds || bounds.total <= 0) {
    return;
  }
  applyWebsocketPaneWidth(state.websocketPaneWidth, { updateState: false });
}

function normalizeWebsocketPaneWidth(options = {}) {
  if (!els.websocketWorkbench) {
    return;
  }
  if (window.matchMedia(WEBSOCKET_WORKBENCH_BREAKPOINT).matches) {
    resetWebsocketPaneWidth(false);
    return;
  }

  const customWidth = els.websocketWorkbench.style.getPropertyValue("--websocket-left-pane-width");
  if (!customWidth) {
    applySavedWebsocketPaneWidth();
    return;
  }

  const bounds = getWebsocketWorkbenchWidths();
  if (!bounds || bounds.total <= 0) {
    return;
  }

  const nextHandshake = clamp(
    bounds.handshake,
    WEBSOCKET_WORKBENCH_MIN_WIDTHS.handshake,
    bounds.total - WEBSOCKET_WORKBENCH_MIN_WIDTHS.frames,
  );
  applyWebsocketPaneWidth(nextHandshake, {
    ...options,
    updateState: options.updateState === true,
  });
}

function resetWebsocketPaneWidth(clearState = true) {
  els.websocketWorkbench?.style.removeProperty("--websocket-left-pane-width");
  if (clearState) {
    state.websocketPaneWidth = null;
  }
}

function sanitizeWebsocketStackHeight(height) {
  const value = Number(height);
  return Number.isFinite(value) && value > 0
    ? Math.round(clamp(value, WEBSOCKET_STACK_MIN_HEIGHTS.sessions, 4096))
    : null;
}

function websocketSessionsCard() {
  return els.websocketPanel?.querySelector(".ws-sessions-card");
}

function applyWebsocketStackHeight(height, options = {}) {
  const sanitized = sanitizeWebsocketStackHeight(height);
  const sessionsCard = websocketSessionsCard();
  if (!sanitized || !sessionsCard) {
    return;
  }
  sessionsCard.style.flex = "none";
  sessionsCard.style.height = `${sanitized}px`;
  if (options.updateState !== false) {
    state.websocketStackHeight = sanitized;
  }
}

function resetWebsocketStackHeight(clearState = true) {
  const sessionsCard = websocketSessionsCard();
  if (sessionsCard) {
    sessionsCard.style.removeProperty("flex");
    sessionsCard.style.removeProperty("height");
  }
  if (clearState) {
    state.websocketStackHeight = null;
  }
}

function applySavedWebsocketStackHeight() {
  if (state.websocketStackHeight) {
    applyWebsocketStackHeight(state.websocketStackHeight, { updateState: false });
  } else {
    resetWebsocketStackHeight(false);
  }
}

function sanitizeWsReplayLeftWidth(width) {
  const value = Number(width);
  return Number.isFinite(value) && value > 0
    ? Math.round(clamp(value, 280, 4096))
    : null;
}

function sanitizeWsReplayFrameDetailHeight(height) {
  const value = Number(height);
  return Number.isFinite(value) && value > 0
    ? Math.round(clamp(value, 120, 4096))
    : null;
}

function applyWsReplayLeftWidth(width, options = {}) {
  const sanitized = sanitizeWsReplayLeftWidth(width);
  if (!sanitized || !els.wsReplayPanel) {
    return;
  }
  els.wsReplayPanel.style.setProperty("--ws-replay-left-width", `${sanitized}px`);
  if (options.updateState !== false) {
    state.wsReplayLeftWidth = sanitized;
  }
}

function resetWsReplayLeftWidth(clearState = true) {
  els.wsReplayPanel?.style.removeProperty("--ws-replay-left-width");
  if (clearState) {
    state.wsReplayLeftWidth = null;
  }
}

function applyWsReplayFrameDetailHeight(height, options = {}) {
  const sanitized = sanitizeWsReplayFrameDetailHeight(height);
  const detail = els.wsReplayPanel?.querySelector(".ws-frame-detail");
  if (!sanitized || !detail) {
    return;
  }
  detail.style.flex = `0 0 ${sanitized}px`;
  if (options.updateState !== false) {
    state.wsReplayFrameDetailHeight = sanitized;
  }
}

function resetWsReplayFrameDetailHeight(clearState = true) {
  const detail = els.wsReplayPanel?.querySelector(".ws-frame-detail");
  if (detail) {
    detail.style.removeProperty("flex");
  }
  if (clearState) {
    state.wsReplayFrameDetailHeight = null;
  }
}

function applySavedWsReplayLayout() {
  if (state.wsReplayLeftWidth) {
    applyWsReplayLeftWidth(state.wsReplayLeftWidth, { updateState: false });
  } else {
    resetWsReplayLeftWidth(false);
  }
  if (state.wsReplayFrameDetailHeight) {
    applyWsReplayFrameDetailHeight(state.wsReplayFrameDetailHeight, { updateState: false });
  } else {
    resetWsReplayFrameDetailHeight(false);
  }
}

function bindWebsocketStackResizer(handle) {
  if (!handle) return;
  const stackPanel = handle.parentElement;
  if (!stackPanel) return;

  const sessionsCard = stackPanel.querySelector(".panel-card-top");

  handle.addEventListener("dblclick", () => {
    resetWebsocketStackHeight();
    scheduleUiSettingsSave();
  });

  handle.addEventListener("mousedown", (event) => {
    event.preventDefault();
    const workbench = els.websocketWorkbench;
    if (!sessionsCard || !workbench) return;

    const startY = event.clientY;
    const startSessions = sessionsCard.getBoundingClientRect().height;
    const combinedHeight = startSessions + workbench.getBoundingClientRect().height;
    let nextSessionsHeight = Math.round(startSessions);
    let moved = false;

    document.body.classList.add("pane-resizing-y");
    handle.classList.add("active");

    const onMove = (moveEvent) => {
      const delta = moveEvent.clientY - startY;
      const nextSessions = clamp(
        startSessions + delta,
        WEBSOCKET_STACK_MIN_HEIGHTS.sessions,
        combinedHeight - WEBSOCKET_STACK_MIN_HEIGHTS.workbench,
      );
      nextSessionsHeight = Math.round(nextSessions);
      moved = true;
      applyWebsocketStackHeight(nextSessionsHeight, { updateState: false });
    };

    const onUp = () => {
      document.body.classList.remove("pane-resizing-y");
      handle.classList.remove("active");
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      if (moved) {
        state.websocketStackHeight = sanitizeWebsocketStackHeight(nextSessionsHeight);
        scheduleUiSettingsSave();
      }
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

function normalizeWorkbenchStackHeight(options = {}) {
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
  applyWorkbenchStackHeight(nextMessages, options.persist === true);
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

function initReplayResponseCMSearchNavigation() {
  if (!els.replayResponseSearchMeta) return;
  els.replayResponseSearchMeta.addEventListener("click", (event) => {
    if (!event.target.closest(".search-hit-count") || !_replayResponseCMView) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    _replayResponseCMView.nextSearchMatch();
  });
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
  clearHttpHistorySelectionPreview();
  scheduleUiSettingsSave();
  scheduleRefresh({ resetScroll: true });
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
  const cv = getCMView("wsHandshake");
  if (cv) {
    els.wsHandshakeLines.textContent = buildLineNumbers(cv.view.state.doc.lines);
    return;
  }
  const resBtn = document.getElementById("wsHandshakeResBtn");
  const showingResponse = resBtn?.classList.contains("active");
  const activeView = showingResponse ? els.websocketResponseView : els.websocketRequestView;
  if (!activeView) return;
  const lineCount = activeView.querySelectorAll(".code-line").length || 1;
  els.wsHandshakeLines.textContent = buildLineNumbers(lineCount);
}

function getCurrentSelectedRecord() {
  return state.selectedRecord?.id === state.selectedId ? state.selectedRecord : null;
}

function updateWsHandshakeSearch() {
  const query = els.wsHandshakeSearchInput?.value || "";
  // CM path
  const cv = getCMView("wsHandshake");
  if (cv) {
    const result = cv.applySearch(query);
    const lineCount = cv.view.state.doc.lines;
    if (els.wsHandshakeSearchMeta) {
      els.wsHandshakeSearchMeta.innerHTML = buildSearchMeta(lineCount, "pretty", result.matchCount);
    }
    return;
  }
  // Legacy path
  const resBtn = document.getElementById("wsHandshakeResBtn");
  const showingResponse = resBtn?.classList.contains("active");
  const activeView = showingResponse ? els.websocketResponseView : els.websocketRequestView;
  if (!activeView) return;
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
    const savedCaret = saveContentEditableCaret(els.wsMessageHighlight);

    els.wsMessageHighlight.innerHTML = highlightJson(text);

    if (document.activeElement === els.wsMessageHighlight) {
      restoreContentEditableCaret(els.wsMessageHighlight, savedCaret);
    }
  }
}

function highlightJson(text) {
  const source = String(text ?? "");
  const tokenPattern = /("(?:[^"\\]|\\.)*")\s*:|("(?:[^"\\]|\\.)*")|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)\b|(true|false)\b|(null)\b|([{}[\]:,])/g;
  let cursor = 0;
  let html = "";
  let match;

  while ((match = tokenPattern.exec(source)) !== null) {
    html += escapeHtml(source.slice(cursor, match.index));
    const [token, key, str, num, bool, nul, punct] = match;
    if (key) html += `<span class="json-key">${escapeHtml(key)}</span>:`;
    else if (str) html += `<span class="json-string">${escapeHtml(str)}</span>`;
    else if (num) html += `<span class="json-number">${escapeHtml(num)}</span>`;
    else if (bool) html += `<span class="json-bool">${escapeHtml(bool)}</span>`;
    else if (nul) html += `<span class="json-null">${escapeHtml(nul)}</span>`;
    else if (punct) html += `<span class="json-punct">${escapeHtml(punct)}</span>`;
    else html += escapeHtml(token);
    cursor = tokenPattern.lastIndex;
  }

  html += escapeHtml(source.slice(cursor));
  return html;
}

let wsMessageHighlightTimer = null;
let wsMessageHighlightPendingText = null;
let wsMessageHighlightComposing = false;

function scheduleWsMessageJsonHighlight(text) {
  if (wsMessageHighlightComposing) return;
  wsMessageHighlightPendingText = text;
  if (wsMessageHighlightTimer) return;
  wsMessageHighlightTimer = window.setTimeout(() => {
    wsMessageHighlightTimer = null;
    if (els.wsMessageHighlight && els.wsMessageHighlight.innerText === wsMessageHighlightPendingText) {
      applyWsMessageJsonHighlight();
    }
  }, 120);
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
  const headerNames = normalizedHeaders(record.request?.headers).map((header) => header.name);
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
  if (item._mime) return item._mime;
  if (item.is_websocket) return (item._mime = "websocket");
  const contentType = (item.content_type || "").toLowerCase();
  if (contentType.includes("html")) return (item._mime = "html");
  if (contentType.includes("javascript") || contentType.includes("ecmascript")) return (item._mime = "script");
  if (contentType.includes("css")) return (item._mime = "css");
  if (contentType.includes("json")) return (item._mime = "json");
  if (contentType.includes("image")) return (item._mime = "image");
  const extension = extractSummaryPathExtension(item.path || "");
  if (extension === "js") return (item._mime = "script");
  if (extension === "css") return (item._mime = "css");
  if (extension === "json") return (item._mime = "json");
  if (extension === "html") return (item._mime = "html");
  if (["png", "jpg", "jpeg", "gif", "svg", "ico"].includes(extension)) return (item._mime = "image");
  return (item._mime = "other");
}

function isTlsRecord(item) {
  return item.kind === "tunnel" || item.scheme === "https";
}

function getVisibleItems() {
  return getVisibleEntries().map((entry) => entry.item);
}

function invalidateVisibleEntriesCache() {
  state._cachedVisibleEntries = null;
  state._cachedVisibleEntriesKey = "";
}

function getVisibleEntries() {
  const cacheKey = String(state._itemsVersion);
  if (state._cachedVisibleEntries && state._cachedVisibleEntriesKey === cacheKey) {
    return state._cachedVisibleEntries;
  }

  const result = [];
  const items = state.items;
  for (let i = 0, len = items.length; i < len; i++) {
    const item = items[i];
    result.push({ item, index: i });
  }

  state._cachedVisibleEntries = result;
  state._cachedVisibleEntriesKey = cacheKey;
  return state._cachedVisibleEntries;
}

function syncColorTagFilterUI() {
  const tags = state.filterSettings.colorTags;
  els.colorTagFilter.querySelectorAll(".color-dot-btn").forEach((btn) => {
    btn.classList.toggle("active", tags.has(btn.dataset.color));
  });
}

function isInScopeHost(host) {
  const patterns = state.runtime?.scope_patterns || [];
  if (!patterns.length) {
    return true;
  }

  const hostname = normalizeHostForMatching(host);
  return patterns.some((pattern) => {
    const normalized = normalizeHostForMatching(pattern);
    if (normalized.startsWith("*.")) {
      const suffix = normalized.slice(2);
      return hostname === suffix || hostname.endsWith(`.${suffix}`);
    }
    return hostname === normalized;
  });
}

function normalizeHostForMatching(host) {
  let value = String(host || "").trim().toLowerCase();
  const schemeIndex = value.indexOf("://");
  if (schemeIndex >= 0) {
    value = value.slice(schemeIndex + 3);
  } else if (value.startsWith("//")) {
    value = value.slice(2);
  }
  const hostOnly = value.split(/[/?#]/, 1)[0].trim();
  return hostWithoutPort(hostOnly).toLowerCase();
}

function hostWithoutPort(host) {
  const value = String(host || "").trim();
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    if (end > 0) return value.slice(1, end);
  }
  return (value.match(/:/g) || []).length === 1 ? value.split(":")[0] : value;
}

function extractHostPort(host) {
  const value = String(host || "").trim();
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    return end > 0 && value[end + 1] === ":" ? value.slice(end + 2) : "";
  }
  return (value.match(/:/g) || []).length === 1 ? value.split(":")[1] : "";
}

/** Pre-compute per-item display values and lookup indexes used by the history table. */
function precomputeItemIndexes() {
  let connectCount = 0;
  const items = state.items;
  for (let i = 0, len = items.length; i < len; i++) {
    const item = items[i];
    prepareHistoryItem(item);
    if (item.method === "CONNECT") connectCount++;
  }
  state._connectCount = connectCount;
  rebuildHistoryItemIndex();
}

function prepareHistoryItem(item) {
  observeAnnotationRevision(item);
  item._totalBytes = (item.request_bytes ?? 0) + (item.response_bytes ?? 0);
  item._sizeLabel = formatSize(item._totalBytes);
  item._mime = inferMimeType(item);
  item._timeLabel = "";
  return item;
}

function getHistoryTimeLabel(item) {
  if (!item._timeLabel) {
    item._timeLabel = formatTimestamp(item.started_at);
  }
  return item._timeLabel;
}

function rebuildHistoryItemIndex() {
  state._itemById = new Map();
  state._itemIndexById = new Map();
  for (let i = 0, len = state.items.length; i < len; i++) {
    const item = state.items[i];
    state._itemById.set(item.id, item);
    state._itemIndexById.set(item.id, i);
  }
}

function getHistoryItem(id) {
  return state._itemById?.get(id) || null;
}

function getHistoryItemIndex(id) {
  const index = state._itemIndexById?.get(id);
  return Number.isInteger(index) ? index : -1;
}

function visibleHistoryNoteCount(item) {
  const noteCount = Number(item?.note_count);
  return (Number.isFinite(noteCount) ? noteCount : 0) + (item?.has_user_note || item?.user_note ? 1 : 0);
}

function compareHistorySequence(left, right) {
  const leftSequence = Number(left?.sequence ?? left?.index ?? 0);
  const rightSequence = Number(right?.sequence ?? right?.index ?? 0);
  return (Number.isFinite(leftSequence) ? leftSequence : 0) - (Number.isFinite(rightSequence) ? rightSequence : 0);
}

function resortLoadedHistoryItemsForCurrentSort() {
  if (state.sortKey !== "notes") return false;
  const direction = state.sortDirection === "asc" ? 1 : -1;
  state.items.sort((left, right) => {
    const noteComparison = visibleHistoryNoteCount(left) - visibleHistoryNoteCount(right);
    const comparison = noteComparison || compareHistorySequence(left, right);
    return comparison * direction;
  });
  return true;
}

function countHiddenConnectItems() {
  const hiddenTotal = state.historyPaging?.hiddenConnectTotal;
  if (isKnownCount(hiddenTotal)) return hiddenTotal;
  // Use precomputed count when available; fall back to scan otherwise.
  if (typeof state._connectCount === "number") return state._connectCount;
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

function compareSortValues(left, right) {
  if (typeof left === "number" && typeof right === "number") {
    return left - right;
  }

  const leftText = String(left);
  const rightText = String(right);
  if (leftText === rightText) return 0;
  return HISTORY_SORT_COLLATOR.compare(leftText, rightText);
}

function formatKind(kind) {
  return kind === "tunnel" ? "CONNECT tunnel" : "HTTP exchange";
}

function formatStatus(status) {
  if (status == null) return "n/a";
  return String(status);
}

function statusTone(status) {
  const code = Number(status);
  if (!Number.isFinite(code)) return "none";
  if (code >= 200 && code < 300) return "ok";
  if (code >= 300 && code < 400) return "info";
  if (code >= 400 && code < 500) return "warn";
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
  if (value == null || value === "") {
    return "-";
  }
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) {
    return "-";
  }
  return HISTORY_TIME_FORMATTER.format(date);
}

function formatSize(bytes) {
  let size = Number(bytes);
  if (!Number.isFinite(size) || size <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(size >= 10 || index === 0 ? 0 : 1)} ${units[index]}`;
}

function configuredTransactionEntryLimit() {
  return state.settings?.max_transaction_entries ?? state.settings?.max_entries ?? 0;
}

function titleCase(value) {
  const text = String(value || "");
  return text.charAt(0).toUpperCase() + text.slice(1);
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

function normalizeWebsocketFrames(frames) {
  return (Array.isArray(frames) ? frames : [])
    .filter((frame) => frame && typeof frame === "object")
    .map((frame, fallbackIndex) => normalizeWebsocketFrame(frame, fallbackIndex));
}

function normalizeWebsocketFrame(frame, fallbackIndex = 0) {
  if (!frame || typeof frame !== "object") return null;
  const index = Number(frame.index);
  return {
    ...frame,
    index: Number.isFinite(index) ? index : fallbackIndex,
    direction: frame.direction === "client_to_server" ? "client_to_server" : "server_to_client",
    kind: String(frame.kind || "text"),
    body: String(frame.body ?? frame.body_preview ?? ""),
    body_preview: String(frame.body_preview ?? frame.body ?? ""),
  };
}

function getWebsocketFrames(session) {
  return normalizeWebsocketFrames(session?.frames);
}

function websocketFramesAreTruncated(frames, summary) {
  if (!Array.isArray(frames) || !frames.length) {
    return false;
  }
  const firstFrameIndex = Number(frames[0]?.index);
  const firstRetainedFrameIndex = websocketFirstRetainedFrameIndex(summary, frames);
  if (
    Number.isFinite(firstFrameIndex)
    && (firstFrameIndex > firstRetainedFrameIndex || firstRetainedFrameIndex > 0)
  ) {
    return true;
  }
  return Number.isFinite(Number(summary?.frame_count))
    && frames.length < Number(summary.frame_count);
}

function getWsReplayFrames(tab) {
  return normalizeWebsocketFrames(tab?.wsFrames);
}

function getRawWsReplayFrames(tab) {
  return Array.isArray(tab?.wsFrames) ? tab.wsFrames : [];
}

function wsFrameIndexValue(frame, fallbackIndex = 0) {
  const index = Number(frame?.index);
  return Number.isFinite(index) ? index : fallbackIndex;
}

function wsReplayFrameIndexSet(tab) {
  return rebuildWsReplayFrameTracking(tab);
}

function rebuildWsReplayFrameTracking(tab) {
  const indexes = new Set();
  let nextIndex = 0;
  const frames = getRawWsReplayFrames(tab);
  for (let index = 0; index < frames.length; index += 1) {
    const frameIndex = wsFrameIndexValue(frames[index], index);
    indexes.add(frameIndex);
    nextIndex = Math.max(nextIndex, frameIndex + 1);
  }
  if (tab && typeof tab === "object") {
    tab.wsFrameIndexes = indexes;
    tab.wsNextFrameIndex = nextIndex;
  }
  return indexes;
}

function ensureWsReplayFrameTracking(tab) {
  if (
    !tab
    || !(tab.wsFrameIndexes instanceof Set)
    || !Number.isFinite(Number(tab.wsNextFrameIndex))
  ) {
    return rebuildWsReplayFrameTracking(tab);
  }
  return tab.wsFrameIndexes;
}

function resetWsReplayFrameTracking(tab) {
  if (!tab || typeof tab !== "object") return;
  tab.wsFrameIndexes = new Set();
  tab.wsNextFrameIndex = 0;
}

function trackWsReplayFrameIndex(tab, frame, fallbackIndex = 0) {
  const indexes = ensureWsReplayFrameTracking(tab);
  const frameIndex = wsFrameIndexValue(frame, fallbackIndex);
  indexes.add(frameIndex);
  tab.wsNextFrameIndex = Math.max(Number(tab.wsNextFrameIndex) || 0, frameIndex + 1);
  return frameIndex;
}

function forgetWsReplayFrameIndex(tab, frame, fallbackIndex = 0) {
  if (!tab?.wsFrameIndexes) return;
  tab.wsFrameIndexes.delete(wsFrameIndexValue(frame, fallbackIndex));
}

function updateWsReplayNextFrameIndex(tab, nextIndex) {
  if (!tab || !Number.isFinite(Number(nextIndex))) return;
  ensureWsReplayFrameTracking(tab);
  tab.wsNextFrameIndex = Math.max(Number(tab.wsNextFrameIndex) || 0, Number(nextIndex));
}

function utf8ByteLength(value) {
  return new TextEncoder().encode(String(value || "")).length;
}

function truncateUtf8(value, maxBytes) {
  return truncateUtf8Preview(value, maxBytes).body;
}

function truncateUtf8Preview(value, maxBytes) {
  const text = String(value || "");
  const fullBytes = utf8ByteLength(text);
  if (fullBytes <= maxBytes) {
    return {
      body: text,
      bodyBytes: fullBytes,
      storedBytes: fullBytes,
      truncated: false,
    };
  }
  const encoder = new TextEncoder();
  let body = "";
  let storedBytes = 0;
  for (const char of text) {
    const charBytes = encoder.encode(char).length;
    if (storedBytes + charBytes > maxBytes) break;
    body += char;
    storedBytes += charBytes;
  }
  return {
    body,
    bodyBytes: storedBytes,
    storedBytes,
    truncated: true,
  };
}

function truncateBase64Preview(
  value,
  maxStoredBytes,
  maxBodyBytes = WS_REPLAY_MAX_PERSISTED_FRAME_BODY_BYTES,
) {
  const encoded = String(value || "");
  const storedLimit = Math.max(0, Number.isFinite(maxStoredBytes)
    ? maxStoredBytes
    : WS_REPLAY_MAX_PERSISTED_FRAME_BODY_BYTES);
  const bodyLimit = Math.max(0, Number.isFinite(maxBodyBytes)
    ? maxBodyBytes
    : WS_REPLAY_MAX_PERSISTED_FRAME_BODY_BYTES);
  let decoded = "";
  try {
    decoded = atob(encoded);
  } catch (_error) {
    return { body: "", bodyBytes: 0, storedBytes: 0, truncated: true };
  }
  const fullStoredBytes = utf8ByteLength(encoded);
  if (fullStoredBytes <= storedLimit && decoded.length <= bodyLimit) {
    return {
      body: encoded,
      bodyBytes: decoded.length,
      storedBytes: fullStoredBytes,
      truncated: false,
    };
  }
  let bodyBytes = Math.min(decoded.length, bodyLimit);
  let body = "";
  let storedBytes = 0;
  while (bodyBytes > 0) {
    body = btoa(decoded.slice(0, bodyBytes));
    storedBytes = utf8ByteLength(body);
    if (storedBytes <= storedLimit) break;
    const excessBytes = storedBytes - storedLimit;
    bodyBytes -= Math.max(1, Math.ceil((excessBytes * 3) / 4));
  }
  if (bodyBytes <= 0) {
    return { body: "", bodyBytes: 0, storedBytes: 0, truncated: true };
  }
  return {
    body,
    bodyBytes,
    storedBytes,
    truncated: true,
  };
}

function snapshotWsReplayFrames(tab, budget = null) {
  const frameLimit = budget
    ? Math.min(WS_REPLAY_MAX_PERSISTED_FRAMES, Math.max(0, budget.frames))
    : WS_REPLAY_MAX_PERSISTED_FRAMES;
  const rawFrames = getRawWsReplayFrames(tab);
  const frames = [];
  for (
    let rawIndex = rawFrames.length - 1;
    rawIndex >= 0 && frames.length < frameLimit;
    rawIndex -= 1
  ) {
    const frame = normalizeWebsocketFrame(rawFrames[rawIndex], rawIndex);
    if (frame) frames.unshift(frame);
  }
  const selected = [];
  let truncated = rawFrames.length > frames.length;
  for (let reverseIndex = frames.length - 1; reverseIndex >= 0; reverseIndex -= 1) {
    const frame = frames[reverseIndex];
    const fallbackIndex = reverseIndex;
    if (budget && (budget.frames <= 0 || budget.bytes <= 0)) {
      truncated = true;
      break;
    }
    const encoding = frame.body_encoding === "base64" ? "base64" : "utf8";
    const bodySource = String(frame.body ?? frame.body_preview ?? "");
    const frameByteLimit = budget
      ? Math.min(WS_REPLAY_MAX_PERSISTED_FRAME_BODY_BYTES, Math.max(0, budget.bytes))
      : WS_REPLAY_MAX_PERSISTED_FRAME_BODY_BYTES;
    const preview = encoding === "base64"
      ? truncateBase64Preview(bodySource, frameByteLimit)
      : truncateUtf8Preview(bodySource, frameByteLimit);
    const declaredBodySize = Number(frame.body_size);
    const bodySize = Number.isFinite(declaredBodySize) && declaredBodySize >= preview.bodyBytes
      ? declaredBodySize
      : preview.bodyBytes;
    const capturedAt = Number.isFinite(Date.parse(frame.captured_at))
      ? String(frame.captured_at)
      : new Date().toISOString();
    const index = Number(frame.index);
    if (budget) {
      budget.frames -= 1;
      budget.bytes -= preview.storedBytes;
    }
    selected.push({
      index: Number.isFinite(index) ? index : fallbackIndex,
      captured_at: capturedAt,
      direction: frame.direction === "client_to_server" ? "client_to_server" : "server_to_client",
      kind: normalizeWsFrameKind(frame.kind),
      body: preview.body,
      body_encoding: encoding,
      body_size: bodySize,
      preview_truncated: Boolean(frame.preview_truncated || preview.truncated || bodySize > preview.bodyBytes),
    });
  }
  if (selected.length < frames.length) {
    truncated = true;
  }
  const persistedFrames = selected.reverse();
  return {
    frames: persistedFrames,
    truncated: truncated || websocketFramesAreTruncated(persistedFrames, null),
  };
}

function snapshotWsReplaySelectedFrameIndex(tab, frames) {
  const selectedIndex = Number(tab?.wsSelectedFrameIndex);
  if (!Number.isInteger(selectedIndex) || selectedIndex < 0) {
    return null;
  }
  return frames.some((frame) => frame.index === selectedIndex) ? selectedIndex : null;
}

function snapshotWsReplayFrameWindowStart(tab, frames) {
  const start = Number(tab?.wsFrameWindowStart);
  const maxStart = wsReplayFrameWindowMaxStart(frames);
  if (!Number.isFinite(start) || start < 0 || maxStart <= 0) {
    return null;
  }
  const normalized = clamp(Math.floor(start), 0, maxStart);
  return normalized >= maxStart ? null : normalized;
}

function normalizeWsMessageType(value) {
  const normalized = String(value || "").trim().toLowerCase();
  return ["binary", "ping", "pong"].includes(normalized) ? normalized : "text";
}

function normalizeWsFrameKind(value) {
  const normalized = String(value || "").trim().toLowerCase();
  return ["binary", "ping", "pong", "close", "other"].includes(normalized) ? normalized : "text";
}

function normalizeWsSetupItem(item = {}) {
  const kind = normalizeWsMessageType(item.kind || item.messageType || item.message_type);
  const body = String(item.body ?? "");
  const bodyEncoded = !!(item.bodyEncoded ?? item.body_encoded);
  return {
    body,
    kind,
    bodyEncoded,
    autoSend: !!item.autoSend,
    sent: !!item.sent,
    label: item.label || truncateSetupLabel(body, kind),
  };
}

function appendWsSetupNotice(existingNotice, notice) {
  const existing = String(existingNotice || "").trim();
  const next = String(notice || "").trim();
  if (!next || existing.includes(next)) return existing;
  return existing ? `${existing} ${next}` : next;
}

function limitWsSetupQueueItems(items, options = {}) {
  const setupItems = Array.isArray(items) ? items : [];
  if (setupItems.length <= WS_REPLAY_MAX_SETUP_QUEUE_ITEMS) {
    return { items: setupItems, notice: "" };
  }
  if (options.disableWhenOverflow) {
    return {
      items: [],
      notice: `Auto-send setup was disabled because ${setupItems.length} earlier client messages exceed the ${WS_REPLAY_MAX_SETUP_QUEUE_ITEMS}-message saved setup limit.`,
    };
  }
  return {
    items: setupItems.slice(0, WS_REPLAY_MAX_SETUP_QUEUE_ITEMS),
    notice: `Setup queue was limited to the first ${WS_REPLAY_MAX_SETUP_QUEUE_ITEMS} messages so the replay tab can be saved.`,
  };
}

function wsSetupItemFromCapturedFrame(frame) {
  if (!isWsFrameReplayable(frame)) {
    return null;
  }
  const kind = wsReplayMessageTypeForFrame(frame);
  const rawFrameBody = frame.body || frame.body_preview || "";
  const bodyEncoded = kind !== "text" && frame.body_encoding === "base64";
  const body = kind === "text" && frame.body_encoding === "base64"
    ? safeDecodeBase64(rawFrameBody, rawFrameBody)
    : rawFrameBody;
  return normalizeWsSetupItem({
    body,
    kind,
    bodyEncoded,
    autoSend: true,
    sent: false,
    label: truncateSetupLabel(body, kind),
  });
}

function createWsReplayTab(seed = {}) {
  state.replayTabSequence += 1;
  const selectedFrameIndex = Number(seed.selectedFrameIndex);
  const seedFrames = normalizeWebsocketFrames(seed.capturedFrames);
  const seedHasSetupQueue = Array.isArray(seed.setupQueue);
  const setupQueueSource = seedHasSetupQueue
    ? seed.setupQueue.map((item) => normalizeWsSetupItem(item))
    : seedFrames
      .filter((f) => f.direction === "client_to_server")
      .filter((f) => !Number.isFinite(selectedFrameIndex) || f.index < selectedFrameIndex)
      .filter((f) => !f.preview_truncated)
      .map((f) => wsSetupItemFromCapturedFrame(f))
      .filter(Boolean);
  const limitedSetupQueue = limitWsSetupQueueItems(setupQueueSource, {
    disableWhenOverflow: !seedHasSetupQueue,
  });
  const tab = {
    id: crypto.randomUUID(),
    type: "websocket",
    sequence: state.replayTabSequence,
    customLabel: normalizeReplayTabCustomLabel(seed.customLabel || ""),
    label: `WS ${seed.host || "draft"}`,
    wsScheme: seed.scheme || "wss",
    wsHost: seed.host || "",
    wsPort: seed.port || defaultWsPortForScheme(seed.scheme),
    wsPath: seed.path || "/",
    wsHeaders: normalizedHeaders(seed.headers),
    wsHandshakeText: seed.handshakeText || "",
    wsHandshakeEdited: !!seed.handshakeEdited,
    wsStatus: "disconnected",
    wsFrames: seedFrames,
    wsFrameIndexes: new Set(),
    wsNextFrameIndex: 0,
    wsFramesTruncated: !!seed.framesTruncated || websocketFramesAreTruncated(seedFrames, null),
    wsSelectedFrameIndex: normalizeWsReplaySavedFrameIndex(seedFrames, seed.selectedFrameIndex),
    wsFrameWindowStart: normalizeWsReplaySavedFrameWindowStart(seedFrames, seed.frameWindowStart),
    wsSessionId: null,
    wsEditorText: seed.editorText || "",
    wsMessageType: normalizeWsMessageType(seed.messageType),
    wsEditorBodyEncoded: !!seed.editorBodyEncoded,
    wsError: null,
    wsPollTimer: null,
    wsLifecycleToken: 0,
    wsSetupPending: false,
    wsSetupRunning: false,
    wsSetupNotice: appendWsSetupNotice(seed.setupQueueNotice || "", limitedSetupQueue.notice),
    wsSetupQueue: limitedSetupQueue.items,
  };
  rebuildWsReplayFrameTracking(tab);
  state.replayTabs.push(tab);
  state.activeReplayTabId = tab.id;
  scheduleWorkspaceStateSave();
  renderReplay();
  return tab;
}

function truncateSetupLabel(body, kind = "text") {
  const messageKind = normalizeWsMessageType(kind);
  if (messageKind !== "text") {
    return messageKind.toUpperCase();
  }
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
  const sessionId = state.activeSession?.id || null;

  // Sync fields from UI
  const wsScheme = els.wsSchemeSelect.value;
  const wsHost = els.wsHostInput.value.trim();
  const wsPortText = els.wsPortInput.value.trim();
  const wsPath = els.wsPathInput.value.trim();
  const validation = validateWsReplayTargetInput(wsScheme, wsHost, wsPortText, wsPath);
  setWsReplayTargetInputValidity(validation);
  if (!validation.valid) {
    els.wsSchemeSelect.reportValidity();
    els.wsHostInput.reportValidity();
    els.wsPortInput.reportValidity();
    els.wsPathInput.reportValidity();
    return;
  }
  const conflictSnapshot = cloneReplayTabState(tab);
  const lifecycleToken = (tab.wsLifecycleToken || 0) + 1;
  tab.wsLifecycleToken = lifecycleToken;
  tab.wsSessionId = sessionId;
  const normalizedTarget = normalizeWsReplayTargetFields(wsScheme, wsHost, wsPortText);
  const wsPort = normalizePortValue(normalizedTarget.port);
  tab.wsScheme = normalizedTarget.scheme;
  tab.wsHost = normalizedTarget.host;
  tab.wsPort = wsPort;
  tab.wsPath = wsPath;
  els.wsSchemeSelect.value = tab.wsScheme;
  els.wsHostInput.value = tab.wsHost;
  els.wsPortInput.value = tab.wsPort;

  tab.wsStatus = "connecting";
  tab.wsError = null;
  tab.wsSetupPending = Array.isArray(tab.wsSetupQueue)
    && tab.wsSetupQueue.some((item) => item.autoSend && !item.sent);
  tab.wsSetupRunning = false;
  for (const item of Array.isArray(tab.wsSetupQueue) ? tab.wsSetupQueue : []) {
    item.sent = false;
  }
  scheduleWorkspaceStateSave();
  renderWsStatus();
  renderWsSetupQueue();
  renderWsFrameList();

  try {
    const expectedWorkspaceRevision = await flushWorkspaceStateForReplayAction();
    const headers = parseWsHandshakeHeaders(tab);
    const resp = await fetch("/api/replay/ws-connect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_id: sessionId,
        expected_active_session_id: expectedActiveSessionIdForWrite(sessionId),
        expected_workspace_revision: expectedWorkspaceRevision,
        id: tab.id,
        scheme: tab.wsScheme,
        host: tab.wsHost,
        port: Number(wsPort),
        path: wsPath,
        headers,
      }),
    });
    if (!isWsReplayTabAlive(tab, lifecycleToken)) {
      await disconnectWsReplayBackend(tab.id, { remove: true, sessionId });
      return;
    }
    if (!resp.ok) {
      const workspaceConflict = await readWorkspaceRevisionConflictPayload(resp);
      if (workspaceConflict) {
        restoreReplayTabConflictState(tab, conflictSnapshot);
        handleReplayWorkspaceRevisionConflict(workspaceConflict);
        return;
      }
      const text = await resp.text().catch(() => "Connection failed");
      throw new Error(text);
    }
    tab.wsFrames = [];
    resetWsReplayFrameTracking(tab);
    tab.wsFramesTruncated = false;
    tab.wsSelectedFrameIndex = -1;
    tab.wsFrameWindowStart = null;
    scheduleWorkspaceStateSave();
    renderWsFrameList();
    startWsPoll(tab);
    renderReplayTabs();

    // Auto-send setup queue after connection
    await runSetupQueue(tab, lifecycleToken);
  } catch (e) {
    if (!isWsReplayTabAlive(tab, lifecycleToken)) {
      return;
    }
    if (e instanceof WorkspaceStateConflictError) {
      restoreReplayTabConflictState(tab, conflictSnapshot);
      handleWorkspaceActionError(e);
      return;
    }
    tab.wsStatus = "error";
    tab.wsError = e.message;
    scheduleWorkspaceStateSave();
    renderWsStatus();
    renderReplayTabs();
    showToast(tab.wsError || "WebSocket connection failed.", "error");
  }
}

async function runSetupQueue(tab, lifecycleToken = tab?.wsLifecycleToken) {
  const setupQueue = Array.isArray(tab?.wsSetupQueue) ? tab.wsSetupQueue : [];
  if (!setupQueue.some((item) => item.autoSend && !item.sent)) {
    if (tab) tab.wsSetupPending = false;
    return;
  }
  if (tab.wsSetupRunning) return;
  tab.wsSetupRunning = true;

  try {
    // Wait for connection to be established
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 150));
      if (!isWsReplayTabAlive(tab, lifecycleToken)) return;
      if (tab.wsStatus === "connected") break;
      if (tab.wsStatus === "error" || tab.wsStatus === "disconnected") return;
    }
    if (tab.wsStatus !== "connected") {
      tab.wsSetupPending = true;
      return;
    }
    for (const item of setupQueue) {
      if (!item.autoSend || item.sent) continue;
      if (!isWsReplayTabAlive(tab, lifecycleToken)) return;
      if (tab.wsStatus !== "connected") break;

      try {
        const kind = normalizeWsMessageType(item.kind);
        const sendBody = wsReplayBodyForSend(item.body, kind, !!item.bodyEncoded);
        const expectedWorkspaceRevision = await flushWorkspaceStateForReplayAction();
        const resp = await fetch("/api/replay/ws-send", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            session_id: tab.wsSessionId || state.activeSession?.id || null,
            expected_active_session_id: expectedActiveSessionIdForWrite(tab.wsSessionId || state.activeSession?.id || null),
            expected_workspace_revision: expectedWorkspaceRevision,
            id: tab.id,
            body: sendBody,
            binary: kind !== "text",
            kind,
          }),
        });
        if (!isWsReplayTabAlive(tab, lifecycleToken)) return;
        const workspaceConflict = !resp.ok ? await readWorkspaceRevisionConflictPayload(resp) : null;
        if (workspaceConflict) {
          tab.wsSetupPending = true;
          renderWsSetupQueue();
          scheduleWorkspaceStateSave();
          handleReplayWorkspaceRevisionConflict(workspaceConflict);
          return;
        }
        if (!resp.ok) {
          const notice = await resp.text().catch(() => "");
          const message = notice || `Setup message send failed (${resp.status})`;
          tab.wsSetupPending = true;
          tab.wsSetupNotice = appendWsSetupNotice(tab.wsSetupNotice || "", message);
          showToast(message, "error", 4000);
          renderWsSetupQueue();
          scheduleWorkspaceStateSave();
          return;
        }
        await refreshWsReplayFramesOnce(tab, { lifecycleToken });
        item.sent = true;
        renderWsSetupQueue();
        scheduleWorkspaceStateSave();
      } catch (e) {
        const message = e?.message || "Setup message send failed.";
        tab.wsSetupPending = true;
        tab.wsSetupNotice = appendWsSetupNotice(tab.wsSetupNotice || "", message);
        showToast(message, "error", 4000);
        renderWsSetupQueue();
        scheduleWorkspaceStateSave();
        return;
      }
      // Small delay between messages
      await new Promise((r) => setTimeout(r, 100));
    }
    if (isWsReplayTabAlive(tab, lifecycleToken)) {
      tab.wsSetupPending = setupQueue.some((item) => item.autoSend && !item.sent);
    }
  } finally {
    if (isWsReplayTabAlive(tab, lifecycleToken)) {
      tab.wsSetupRunning = false;
    }
  }
}

function parseWsHandshakeHeaders(tab) {
  const headers = [];
  const text = els.wsHandshakeHeaders ? els.wsHandshakeHeaders.value : (tab.wsHandshakeText || "");
  if (text.trim()) {
    for (const line of text.split("\n")) {
      if (!line.trim()) {
        continue;
      }
      const colonIdx = line.indexOf(":");
      const name = colonIdx > 0 ? line.slice(0, colonIdx).trim() : "";
      if (!name) {
        throw new Error(`Invalid WebSocket handshake header: ${line.trim()}`);
      }
      headers.push({
        name,
        value: line.slice(colonIdx + 1).trim(),
      });
    }
  }
  if (tab.wsHandshakeEdited) {
    return headers;
  }
  // Merge with any pre-set headers from seed
  const merged = headers.filter((h) => !headerNameEquals(h, "host"));
  for (const h of normalizedHeaders(tab.wsHeaders)) {
    if (!headerNameEquals(h, "host") && !merged.some(m => headerNameEquals(m, h.name))) {
      merged.push(h);
    }
  }
  const hostHeader = wsReplayHostHeaderValue(tab);
  if (hostHeader) {
    merged.unshift({ name: "Host", value: hostHeader });
  }
  return merged;
}

function wsReplayHostHeaderValue(tab) {
  if (!tab) return "";
  const scheme = tab.wsScheme || "wss";
  const port = normalizePortValue(tab.wsPort) || String(defaultWsPortForScheme(scheme));
  return joinAuthority(tab.wsHost, isDefaultPortForScheme(scheme, port) ? "" : port);
}

function wsReplayDisplayHandshakeHeaders(tab) {
  const headers = normalizedHeaders(tab?.wsHeaders)
    .filter((h) => !headerNameEquals(h, "host"));
  const hostHeader = wsReplayHostHeaderValue(tab);
  if (hostHeader) {
    headers.unshift({ name: "Host", value: hostHeader });
  }
  return headers;
}

function wsReplayDisplayHandshakeText(tab) {
  const headers = wsReplayDisplayHandshakeHeaders(tab);
  return headers.length
    ? headers.map((h) => `${h.name}: ${h.value}`).join("\n")
    : "";
}

function refreshWsHandshakeHeadersForTarget(tab) {
  if (!tab || tab.type !== "websocket" || tab.wsHandshakeEdited || !els.wsHandshakeHeaders) return;
  els.wsHandshakeHeaders.value = wsReplayDisplayHandshakeText(tab);
  tab.wsHandshakeText = "";
}

async function wsSend() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket" || tab.wsStatus !== "connected") return;

  const body = els.wsMessageEditor.value;
  const lifecycleToken = tab.wsLifecycleToken;

  tab.wsMessageType = normalizeWsMessageType(els.wsMessageType.value);
  const binary = tab.wsMessageType !== "text";
  const sendBody = wsReplayBodyForSend(body, tab.wsMessageType, tab.wsEditorBodyEncoded);
  scheduleWorkspaceStateSave();

  try {
    const expectedWorkspaceRevision = await flushWorkspaceStateForReplayAction();
    const resp = await fetch("/api/replay/ws-send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_id: tab.wsSessionId || state.activeSession?.id || null,
        expected_active_session_id: expectedActiveSessionIdForWrite(tab.wsSessionId || state.activeSession?.id || null),
        expected_workspace_revision: expectedWorkspaceRevision,
        id: tab.id,
        body: sendBody,
        binary,
        kind: tab.wsMessageType,
      }),
    });
    if (!resp.ok) {
      const workspaceConflict = await readWorkspaceRevisionConflictPayload(resp);
      if (workspaceConflict) {
        handleReplayWorkspaceRevisionConflict(workspaceConflict);
        return;
      }
      const text = await resp.text().catch(() => "Send failed");
      showToast(text, "error");
    } else {
      await refreshWsReplayFramesOnce(tab, { lifecycleToken });
    }
  } catch (e) {
    showToast(`Send failed: ${e.message}`, "error");
  }
}

async function wsDisconnect() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return;

  await cleanupWsReplayTab(tab, {
    markDisconnected: true,
    removeBackend: tab.wsStatus === "connecting",
  });
}

async function cleanupWsReplayTab(tab, {
  markDisconnected = false,
  removeBackend = true,
  bypassExpectedActiveSessionGuard = false,
  guardWorkspaceRevision = true,
  sessionId = null,
} = {}) {
  if (!tab || tab.type !== "websocket") return;
  const targetSessionId = sessionId || tab.wsSessionId || state.activeSession?.id || null;
  const previousStatus = tab.wsStatus;
  tab.wsLifecycleToken = (tab.wsLifecycleToken || 0) + 1;
  const lifecycleToken = tab.wsLifecycleToken;
  clearWsFrameListRender(tab);
  await refreshWsReplayFramesOnce(tab, { lifecycleToken, sessionId: targetSessionId });
  stopWsPoll(tab);
  const expectedWorkspaceRevision = guardWorkspaceRevision
    ? await flushWorkspaceStateForReplayAction()
    : null;
  const disconnectResult = await disconnectWsReplayBackend(tab.id, {
    remove: removeBackend,
    sessionId: targetSessionId,
    bypassExpectedActiveSessionGuard,
    expectedWorkspaceRevision,
  });
  if (!disconnectResult.ok) {
    if (disconnectResult.workspaceConflict) {
      handleReplayWorkspaceRevisionConflict(disconnectResult.workspaceConflict);
      throw new WorkspaceStateConflictError(disconnectResult.workspaceConflict);
    }
    if (isWsReplayTabAlive(tab, lifecycleToken)) {
      tab.wsStatus = previousStatus === "connecting" ? "error" : previousStatus;
      tab.wsError = disconnectResult.message || "WebSocket replay disconnect failed.";
      if (previousStatus === "connected" || previousStatus === "connecting") {
        startWsPoll(tab);
      }
      scheduleWorkspaceStateSave();
      if (state.activeReplayTabId === tab.id) {
        renderWsStatus();
      }
      renderReplayTabs();
    }
    throw new Error(disconnectResult.message || "WebSocket replay disconnect failed.");
  }
  if (!removeBackend) {
    await refreshWsReplayFramesUntilSettled(tab, { lifecycleToken, sessionId: targetSessionId });
  }
  if (markDisconnected) {
    tab.wsStatus = "disconnected";
    tab.wsError = null;
    scheduleWorkspaceStateSave();
    if (state.activeReplayTabId === tab.id) {
      renderWsStatus();
    }
  }
}

async function refreshWsReplayFramesOnce(tab, options = {}) {
  if (!tab || tab.type !== "websocket") return false;
  const lifecycleToken = Number.isFinite(Number(options.lifecycleToken))
    ? Number(options.lifecycleToken)
    : tab.wsLifecycleToken;
  if (!isWsReplayTabAlive(tab, lifecycleToken)) return false;
  const rawSessionId = options.sessionId || tab.wsSessionId || state.activeSession?.id || "";
  const sessionId = encodeURIComponent(rawSessionId);
  if (!rawSessionId) return false;
  const sinceIndex = nextWsFrameIndex(tab);
  const resp = await fetch(`/api/replay/ws-frames/${tab.id}?since=${sinceIndex}&session_id=${sessionId}`)
    .catch(() => null);
  if (!isWsReplayTabAlive(tab, lifecycleToken)) return false;
  if (!resp || !resp.ok) {
    return false;
  }
  const data = await resp.json().catch(() => null) || {};
  if (!isWsReplayTabAlive(tab, lifecycleToken)) return false;
  const result = applyWsReplayFramePollResponse(tab, data, sinceIndex);
  if (data.status && data.status !== tab.wsStatus) {
    tab.wsStatus = data.status;
    tab.wsError = data.error || null;
    scheduleWorkspaceStateSave();
    if (state.activeReplayTabId === tab.id) {
      renderWsStatus();
    }
  }
  return result.addedFrames;
}

async function refreshWsReplayFramesUntilSettled(tab, options = {}) {
  const started = Date.now();
  const lifecycleToken = Number.isFinite(Number(options.lifecycleToken))
    ? Number(options.lifecycleToken)
    : (tab.wsLifecycleToken || 0);
  let sawFrame = false;
  do {
    if (!isWsReplayTabAlive(tab, lifecycleToken)) {
      return sawFrame;
    }
    const added = await refreshWsReplayFramesOnce(tab, {
      lifecycleToken,
      sessionId: options.sessionId || null,
    });
    sawFrame = sawFrame || added;
    await new Promise((resolve) => window.setTimeout(resolve, WS_REPLAY_FINAL_POLL_INTERVAL_MS));
  } while (Date.now() - started < WS_REPLAY_FINAL_POLL_TIMEOUT_MS);
  return sawFrame;
}

async function disconnectWsReplayBackend(id, {
  remove = false,
  sessionId = state.activeSession?.id || null,
  bypassExpectedActiveSessionGuard = false,
  expectedWorkspaceRevision = null,
} = {}) {
  try {
    const response = await fetch("/api/replay/ws-disconnect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_id: sessionId,
        expected_active_session_id: expectedActiveSessionIdForWrite(sessionId, {
          bypassExpectedActiveSessionGuard,
        }),
        expected_workspace_revision: expectedWorkspaceRevision,
        id,
        remove,
      }),
    });
    if (response.ok || response.status === 404) {
      return { ok: true, message: "" };
    }
    const workspaceConflict = await readWorkspaceRevisionConflictPayload(response);
    if (workspaceConflict) {
      return {
        ok: false,
        workspaceConflict,
        message: "Workspace changed elsewhere; WebSocket replay was not disconnected.",
      };
    }
    const message = await readApiErrorMessage(
      response,
      `WebSocket replay disconnect failed (${response.status}).`,
    );
    return {
      ok: false,
      message,
    };
  } catch (e) {
    return {
      ok: false,
      message: e?.message ? `WebSocket replay disconnect failed: ${e.message}` : "WebSocket replay disconnect failed.",
    };
  }
}

function isWsReplayTabAlive(tab, lifecycleToken) {
  return Boolean(
    tab
    && state.replayTabs.includes(tab)
    && tab.wsLifecycleToken === lifecycleToken
  );
}

function clearWsFrameListRender(tab) {
  if (tab?.wsFrameRenderTimer) {
    window.clearTimeout(tab.wsFrameRenderTimer);
    tab.wsFrameRenderTimer = null;
  }
}

function scheduleWsFrameListRender(tab) {
  if (!tab || state.activeReplayTabId !== tab.id || tab.wsFrameRenderTimer) {
    return;
  }
  tab.wsFrameRenderTimer = window.setTimeout(() => {
    tab.wsFrameRenderTimer = null;
    if (state.activeReplayTabId === tab.id && state.replayTabs.includes(tab)) {
      renderWsFrameList();
    }
  }, 300);
}

function startWsPoll(tab) {
  stopWsPoll(tab);
  let sinceIndex = nextWsFrameIndex(tab);
  const generation = (tab.wsPollGeneration || 0) + 1;
  const lifecycleToken = tab.wsLifecycleToken;
  tab.wsPollGeneration = generation;

  const poll = async () => {
    if (!tab.wsPollTimer || tab.wsPollGeneration !== generation || !isWsReplayTabAlive(tab, lifecycleToken)) return;
    try {
      const sessionId = encodeURIComponent(tab.wsSessionId || state.activeSession?.id || "");
      const resp = await fetch(`/api/replay/ws-frames/${tab.id}?since=${sinceIndex}&session_id=${sessionId}`);
      if (!tab.wsPollTimer || tab.wsPollGeneration !== generation || !isWsReplayTabAlive(tab, lifecycleToken)) return;
      if (!resp.ok) {
        if (resp.status === 404 || resp.status === 409) {
          const text = await resp.text().catch(() => "");
          if (!tab.wsPollTimer || tab.wsPollGeneration !== generation || !isWsReplayTabAlive(tab, lifecycleToken)) return;
          tab.wsStatus = resp.status === 404 ? "disconnected" : "error";
          tab.wsError = text || (resp.status === 404
            ? "WebSocket replay connection is no longer available."
            : "WebSocket replay session changed.");
          stopWsPoll(tab);
          scheduleWorkspaceStateSave();
          if (state.activeReplayTabId === tab.id) {
            renderWsStatus();
          }
          renderReplayTabs();
        }
        return;
      }
      const data = await resp.json() || {};
      if (!tab.wsPollTimer || tab.wsPollGeneration !== generation || !isWsReplayTabAlive(tab, lifecycleToken)) return;

      const frameResult = applyWsReplayFramePollResponse(tab, data, sinceIndex);
      sinceIndex = frameResult.nextIndex;

      if (data.status && data.status !== tab.wsStatus) {
        tab.wsStatus = data.status;
        if (data.error) tab.wsError = data.error;
        if (state.activeReplayTabId === tab.id) {
          renderWsStatus();
        }
        if (data.status === "connected" && tab.wsSetupPending) {
          runSetupQueue(tab, tab.wsLifecycleToken).catch((error) => console.error(error));
        }
      }
      if (
        (data.status === "disconnected" || data.status === "error")
        && !frameResult.truncated
      ) {
        scheduleWorkspaceStateSave();
        stopWsPoll(tab);
        return;
      }
    } catch (_e) {
      // ignore poll errors
    } finally {
      if (tab.wsPollTimer && tab.wsPollGeneration === generation && isWsReplayTabAlive(tab, lifecycleToken)) {
        tab.wsPollTimer = setTimeout(poll, 200);
      }
    }
  };

  tab.wsPollTimer = setTimeout(poll, 0);
}

function applyWsReplayFramePollResponse(tab, data, sinceIndex) {
  const incomingFrames = normalizeWebsocketFrames(data?.frames);
  const firstRetainedIndex = Number(data?.first_retained_index);
  const serverGap = typeof data?.gap === "boolean"
    ? data.gap === true
    : (Number.isFinite(firstRetainedIndex) && firstRetainedIndex > sinceIndex);
  if (serverGap) {
    tab.wsFramesTruncated = true;
    const firstAvailable = Number.isFinite(firstRetainedIndex)
      ? firstRetainedIndex
      : Number(incomingFrames[0]?.index);
    tab.wsError = Number.isFinite(firstAvailable)
      ? `WebSocket replay transcript is missing frames before #${firstAvailable + 1}.`
      : "WebSocket replay transcript is missing earlier frames.";
    scheduleWorkspaceStateSave();
    if (state.activeReplayTabId === tab.id) {
      renderWsStatus();
    }
  }

  let addedFrames = false;
  if (incomingFrames.length > 0) {
    const existing = ensureWsReplayFrameTracking(tab);
    const fresh = [];
    for (const frame of incomingFrames) {
      const frameIndex = wsFrameIndexValue(frame, fresh.length);
      if (existing.has(frameIndex)) {
        continue;
      }
      trackWsReplayFrameIndex(tab, frame, fresh.length);
      fresh.push(frame);
    }
    if (fresh.length) {
      if (!Array.isArray(tab.wsFrames)) tab.wsFrames = [];
      tab.wsFrames.push(...fresh);
      trimWsReplayFrames(tab);
      scheduleWsTranscriptWorkspaceSave();
      addedFrames = true;
      if (state.activeReplayTabId === tab.id) {
        scheduleWsFrameListRender(tab);
      }
    }
  }

  let nextIndex = Math.max(sinceIndex, Number(tab.wsNextFrameIndex) || nextWsFrameIndex(tab));
  const responseNextIndex = Number(data?.next_index);
  if (Number.isFinite(responseNextIndex)) {
    nextIndex = Math.max(nextIndex, responseNextIndex);
  }
  updateWsReplayNextFrameIndex(tab, nextIndex);
  return {
    addedFrames,
    nextIndex,
    truncated: data?.truncated === true,
  };
}

function stopWsPoll(tab) {
  if (!tab) return;
  tab.wsPollGeneration = (tab.wsPollGeneration || 0) + 1;
  if (tab && tab.wsPollTimer) {
    clearTimeout(tab.wsPollTimer);
    tab.wsPollTimer = null;
  }
}

function nextWsFrameIndex(tab) {
  if (tab?.wsFrameIndexes instanceof Set && Number.isFinite(Number(tab.wsNextFrameIndex))) {
    return Math.max(0, Number(tab.wsNextFrameIndex));
  }
  const frames = getRawWsReplayFrames(tab);
  let next = frames.length;
  for (let fallbackIndex = 0; fallbackIndex < frames.length; fallbackIndex += 1) {
    next = Math.max(next, wsFrameIndexValue(frames[fallbackIndex], fallbackIndex) + 1);
  }
  if (tab && typeof tab === "object") {
    tab.wsNextFrameIndex = next;
    rebuildWsReplayFrameTracking(tab);
  }
  return next;
}

function trimWsReplayFrames(tab) {
  if (!tab) return;
  tab.wsFrames = getWsReplayFrames(tab);
  const overflow = tab.wsFrames.length - WS_REPLAY_MAX_LOADED_FRAMES;
  if (overflow <= 0) return;
  const removedFrames = tab.wsFrames.splice(0, overflow);
  tab.wsFramesTruncated = true;
  const firstAvailable = Number(tab.wsFrames[0]?.index);
  tab.wsError = Number.isFinite(firstAvailable)
    ? `WebSocket replay transcript is missing frames before #${firstAvailable + 1}.`
    : "WebSocket replay transcript is missing earlier frames.";
  for (let index = 0; index < removedFrames.length; index += 1) {
    forgetWsReplayFrameIndex(tab, removedFrames[index], index);
  }
  if (tab.wsFrameWindowStart != null) {
    const windowStart = Number(tab.wsFrameWindowStart);
    tab.wsFrameWindowStart = Number.isFinite(windowStart)
      ? Math.max(0, windowStart - overflow)
      : null;
  }
  if (
    tab.wsSelectedFrameIndex !== -1
    && !tab.wsFrames.some((frame) => frame.index === tab.wsSelectedFrameIndex)
  ) {
    tab.wsSelectedFrameIndex = -1;
  }
  scheduleWorkspaceStateSave();
  if (state.activeReplayTabId === tab.id) {
    renderWsStatus();
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
    if (tab.wsHandshakeEdited) {
      els.wsHandshakeHeaders.value = tab.wsHandshakeText;
    } else {
      els.wsHandshakeHeaders.value = wsReplayDisplayHandshakeText(tab);
    }
  }

  // Restore editor text
  if (els.wsMessageType) {
    els.wsMessageType.value = normalizeWsMessageType(tab.wsMessageType);
  }
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
  const setupQueue = Array.isArray(tab?.wsSetupQueue) ? tab.wsSetupQueue : [];
  const setupNotice = String(tab?.wsSetupNotice || "");
  if (tab && tab.type === "websocket" && !Array.isArray(tab.wsSetupQueue)) {
    tab.wsSetupQueue = setupQueue;
  }
  if (!tab || tab.type !== "websocket" || (!setupQueue.length && !setupNotice)) {
    container.classList.add("hidden");
    return;
  }
  container.classList.remove("hidden");

  const listEl = document.getElementById("wsSetupQueueList");
  if (!listEl) return;

  const noticeHtml = setupNotice
    ? `<div class="ws-setup-notice">${escapeHtml(setupNotice)}</div>`
    : "";
  const queueHtml = setupQueue.map((item, i) => {
    const sentClass = item.sent ? "sent" : "";
    const checked = item.autoSend ? "checked" : "";
    return `<div class="ws-setup-row ${sentClass}" data-idx="${i}">
      <input type="checkbox" class="ws-setup-check" data-idx="${i}" ${checked} />
      <span class="ws-setup-index">#${i + 1}</span>
      <span class="ws-setup-label" title="${escapeHtml(item.label)}">${escapeHtml(item.label)}</span>
      <button class="ws-setup-send" data-idx="${i}" title="Send this message">▶</button>
      ${item.sent ? '<span class="ws-setup-sent-badge">✓</span>' : ""}
    </div>`;
  }).join("");
  listEl.innerHTML = noticeHtml + queueHtml;

  // Checkbox toggle
  listEl.querySelectorAll(".ws-setup-check").forEach((cb) => {
    cb.addEventListener("change", () => {
      const idx = parseInt(cb.dataset.idx);
      const item = setupQueue[idx];
      if (!item) return;
      item.autoSend = cb.checked;
      scheduleWorkspaceStateSave();
    });
  });

  // Individual send button
  listEl.querySelectorAll(".ws-setup-send").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const idx = parseInt(btn.dataset.idx);
      const item = setupQueue[idx];
      if (!item || tab.wsStatus !== "connected") return;
      const lifecycleToken = tab.wsLifecycleToken;
      try {
        const kind = normalizeWsMessageType(item.kind);
        const sendBody = wsReplayBodyForSend(item.body, kind, !!item.bodyEncoded);
        const expectedWorkspaceRevision = await flushWorkspaceStateForReplayAction();
        const resp = await fetch("/api/replay/ws-send", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            session_id: tab.wsSessionId || state.activeSession?.id || null,
            expected_active_session_id: expectedActiveSessionIdForWrite(tab.wsSessionId || state.activeSession?.id || null),
            expected_workspace_revision: expectedWorkspaceRevision,
            id: tab.id,
            body: sendBody,
            binary: kind !== "text",
            kind,
          }),
        });
        if (!isWsReplayTabAlive(tab, lifecycleToken) || tab.wsStatus !== "connected") return;
        if (!resp.ok) {
          const workspaceConflict = await readWorkspaceRevisionConflictPayload(resp);
          if (workspaceConflict) {
            handleReplayWorkspaceRevisionConflict(workspaceConflict);
            return;
          }
          const text = await resp.text().catch(() => "Setup message send failed");
          showToast(text, "error");
          return;
        }
        await refreshWsReplayFramesOnce(tab, { lifecycleToken });
        item.sent = true;
        renderWsSetupQueue();
        scheduleWorkspaceStateSave();
      } catch (e) {
        console.error(e);
        showToast(e?.message || "Setup message send failed.", "error");
      }
    });
  });

  // Click row to load into editor
  listEl.querySelectorAll(".ws-setup-row").forEach((row) => {
    row.addEventListener("dblclick", () => {
      const idx = parseInt(row.dataset.idx);
      const item = setupQueue[idx];
      if (item) {
        const kind = normalizeWsMessageType(item.kind);
        els.wsMessageEditor.value = item.body;
        if (els.wsMessageType) {
          els.wsMessageType.value = kind;
        }
        tab.wsMessageType = kind;
        tab.wsEditorText = item.body;
        tab.wsEditorBodyEncoded = !!item.bodyEncoded;
        setWsMessageHighlightText(item.body);
        scheduleWorkspaceStateSave();
      }
    });
  });
}

function renderWsStatus() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return;

  const status = tab.wsStatus;
  els.wsStatusIndicator.className = `ws-status-dot ${status}`;
  let statusText = status === "connected" ? "Connected"
    : status === "connecting" ? "Connecting..."
    : status === "error" ? `Error: ${tab.wsError || "unknown"}`
    : "Disconnected";
  if (status === "connected" && tab.wsFramesTruncated) {
    statusText = tab.wsError || "Connected (frames trimmed)";
  }
  els.wsStatusText.textContent = statusText;

  els.wsConnectButton.disabled = status === "connected" || status === "connecting";
  els.wsDisconnectButton.disabled = status !== "connected" && status !== "connecting";
  els.wsSendButton.disabled = status !== "connected";
  const targetLocked = status === "connected" || status === "connecting";
  els.wsSchemeSelect.disabled = targetLocked;
  els.wsHostInput.disabled = targetLocked;
  els.wsPortInput.disabled = targetLocked;
  els.wsPathInput.disabled = targetLocked;
  if (els.wsHandshakeHeaders) {
    els.wsHandshakeHeaders.disabled = targetLocked;
  }
}

function wsReplayFrameWindowMaxStart(frames) {
  return Math.max(0, frames.length - WS_REPLAY_MAX_RENDERED_FRAMES);
}

function normalizeWsReplaySavedFrameIndex(frames, candidate) {
  const index = Number(candidate);
  if (!Number.isInteger(index) || index < 0) {
    return -1;
  }
  return frames.some((frame) => frame.index === index) ? index : -1;
}

function normalizeWsReplaySavedFrameWindowStart(frames, candidate) {
  if (candidate == null) {
    return null;
  }
  const start = Number(candidate);
  const maxStart = wsReplayFrameWindowMaxStart(frames);
  if (!Number.isFinite(start) || start < 0 || maxStart <= 0) {
    return null;
  }
  const normalized = clamp(Math.floor(start), 0, maxStart);
  return normalized >= maxStart ? null : normalized;
}

function normalizeWsReplayFrameWindowStart(frames, preferredStart) {
  const defaultStart = wsReplayFrameWindowMaxStart(frames);
  if (preferredStart == null) {
    return defaultStart;
  }
  const numericStart = Number(preferredStart);
  if (!Number.isFinite(numericStart)) {
    return defaultStart;
  }
  return clamp(Math.floor(numericStart), 0, defaultStart);
}

function wsReplayRenderedFrameWindow(frames, selectedFrameIndex, preferredStart = null) {
  if (frames.length <= WS_REPLAY_MAX_RENDERED_FRAMES) {
    return {
      frames,
      start: 0,
      end: frames.length,
      total: frames.length,
    };
  }
  const tailStart = wsReplayFrameWindowMaxStart(frames);
  const selectedPosition = frames.findIndex((frame) => frame.index === selectedFrameIndex);
  let start = normalizeWsReplayFrameWindowStart(frames, preferredStart);
  if (selectedPosition !== -1) {
    const selectedInPreferredWindow =
      selectedPosition >= start && selectedPosition < start + WS_REPLAY_MAX_RENDERED_FRAMES;
    if (!selectedInPreferredWindow) {
      if (selectedPosition >= tailStart) {
        start = tailStart;
      } else {
        const halfWindow = Math.floor(WS_REPLAY_MAX_RENDERED_FRAMES / 2);
        start = Math.max(
          0,
          Math.min(selectedPosition - halfWindow, tailStart),
        );
      }
    }
  }
  const end = Math.min(frames.length, start + WS_REPLAY_MAX_RENDERED_FRAMES);
  return {
    frames: frames.slice(start, end),
    start,
    end,
    total: frames.length,
  };
}

function pageWsReplayFrameWindow(tab, direction, anchor) {
  if (!tab || tab.type !== "websocket") return false;
  const frames = getWsReplayFrames(tab);
  const maxStart = wsReplayFrameWindowMaxStart(frames);
  if (maxStart <= 0) return false;
  const currentStart = wsReplayRenderedFrameWindow(
    frames,
    tab.wsSelectedFrameIndex,
    tab.wsFrameWindowStart,
  ).start;
  const pageSize = Math.max(1, Math.floor(WS_REPLAY_MAX_RENDERED_FRAMES * 0.8));
  const nextStart = clamp(currentStart + (direction * pageSize), 0, maxStart);
  if (nextStart === currentStart) return false;
  tab.wsFrameWindowStart = nextStart >= maxStart ? null : nextStart;
  tab.wsSelectedFrameIndex = -1;
  scheduleWorkspaceStateSave();
  tab.wsFrameWindowPaging = true;
  try {
    renderWsFrameList();
  } finally {
    tab.wsFrameWindowPaging = false;
  }
  window.requestAnimationFrame(() => {
    if (anchor === "bottom") {
      els.wsFrameList.scrollTop = Math.max(0, els.wsFrameList.scrollHeight - els.wsFrameList.clientHeight - 1);
    } else {
      els.wsFrameList.scrollTop = 1;
    }
  });
  return true;
}

function renderWsFrameList() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return;
  clearWsFrameListRender(tab);

  const frames = getWsReplayFrames(tab);
  tab.wsFrames = frames;
  els.wsFrameCount.textContent = `${frames.length} frame${frames.length === 1 ? "" : "s"}`;
  const previousFrameListScrollTop = els.wsFrameList.scrollTop;
  const wasNearBottom = els.wsFrameList.scrollHeight - els.wsFrameList.scrollTop - els.wsFrameList.clientHeight < 24;
  const hasSelectedFrame = tab.wsSelectedFrameIndex != null && tab.wsSelectedFrameIndex >= 0;
  const hasPreferredFrameWindow = tab.wsFrameWindowStart != null
    && Number.isFinite(Number(tab.wsFrameWindowStart));

  if (!frames.length) {
    els.wsFrameList.onclick = null;
    els.wsFrameList.ondblclick = null;
    els.wsFrameList.onwheel = null;
    els.wsFrameList.innerHTML = '<div class="empty-copy">Connect to start a WebSocket conversation.</div>';
    renderWsFrameDetail();
    return;
  }

  const frameWindow = wsReplayRenderedFrameWindow(frames, tab.wsSelectedFrameIndex, tab.wsFrameWindowStart);
  const renderedFrames = frameWindow.frames;
  const windowAtTail = frameWindow.end >= frames.length;
  const tailWindowUnpinned = !hasSelectedFrame && !hasPreferredFrameWindow;
  tab.wsFrameWindowStart = tailWindowUnpinned && windowAtTail ? null : frameWindow.start;

  els.wsFrameList.innerHTML = renderedFrames.map((frame) => {
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

  if ((wasNearBottom && windowAtTail) || (tailWindowUnpinned && windowAtTail)) {
    els.wsFrameList.scrollTop = els.wsFrameList.scrollHeight;
  } else {
    els.wsFrameList.scrollTop = previousFrameListScrollTop;
  }

  els.wsFrameList.onwheel = (event) => {
    if (frames.length <= WS_REPLAY_MAX_RENDERED_FRAMES) return;
    const remainingBottom = els.wsFrameList.scrollHeight - els.wsFrameList.scrollTop - els.wsFrameList.clientHeight;
    const atTop = els.wsFrameList.scrollTop <= 0;
    const atBottom = remainingBottom <= 1;
    if (event.deltaY < 0 && atTop && frameWindow.start > 0) {
      event.preventDefault();
      pageWsReplayFrameWindow(tab, -1, "bottom");
    } else if (event.deltaY > 0 && atBottom && frameWindow.end < frames.length) {
      event.preventDefault();
      pageWsReplayFrameWindow(tab, 1, "top");
    }
  };

  els.wsFrameList.onclick = (event) => {
    const target = event.target instanceof Element ? event.target : event.target?.parentElement;
    const bubble = target?.closest(".ws-frame-bubble");
    if (!bubble || !els.wsFrameList.contains(bubble)) return;
    const idx = parseInt(bubble.dataset.frameIndex, 10);
    tab.wsSelectedFrameIndex = idx;
    scheduleWorkspaceStateSave();
    els.wsFrameList.querySelectorAll(".ws-frame-bubble").forEach((node) => node.classList.remove("selected"));
    bubble.classList.add("selected");
    renderWsFrameDetail();
  };
  els.wsFrameList.ondblclick = (event) => {
    const target = event.target instanceof Element ? event.target : event.target?.parentElement;
    const bubble = target?.closest(".ws-frame-bubble");
    if (!bubble || !els.wsFrameList.contains(bubble)) return;
    const idx = parseInt(bubble.dataset.frameIndex, 10);
    const frame = frames.find((item) => item.index === idx);
    if (frame && frame.direction === "client_to_server") {
      if (frame.preview_truncated) {
        showToast("Frame preview is truncated and cannot be replayed safely.", "error");
        return;
      }
      if (!isWsFrameReplayable(frame)) {
        showToast("Close and unknown WebSocket frames cannot be replayed safely.", "error");
        return;
      }
      const messageType = wsReplayMessageTypeForFrame(frame);
      const editorText = wsReplayEditorTextForFrame(frame);
      const editorBodyEncoded = messageType !== "text" && frame.body_encoding === "base64";
      if (els.wsMessageType) {
        els.wsMessageType.value = messageType;
      }
      els.wsMessageEditor.value = editorText;
      tab.wsMessageType = messageType;
      tab.wsEditorText = editorText;
      tab.wsEditorBodyEncoded = editorBodyEncoded;
      setWsMessageHighlightText(editorText);
      scheduleWorkspaceStateSave();
    }
  };

  renderWsFrameDetail();
}

function renderWsFrameDetail() {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return;

  const frames = getWsReplayFrames(tab);
  const frame = frames.find(f => f.index === tab.wsSelectedFrameIndex);
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
    return safeDecodeBase64(frame.body);
  }
  return frame.body;
}

function wsReplayMessageTypeForFrame(frame) {
  const kind = normalizeWsMessageType(frame?.kind);
  if (kind === "ping" || kind === "pong") return kind;
  return kind === "binary" || frame?.body_encoding === "base64" ? "binary" : "text";
}

function isWsFrameReplayable(frame) {
  const kind = normalizeWsFrameKind(frame?.kind);
  return kind !== "close" && kind !== "other";
}

function wsReplayEditorTextForFrame(frame) {
  const rawBody = frame?.body || frame?.body_preview || "";
  if (wsReplayMessageTypeForFrame(frame) !== "text") {
    return rawBody;
  }
  return frame?.body_encoding === "base64" ? safeDecodeBase64(rawBody) : rawBody;
}

function formatWsFrameSize(bytes) {
  const size = Number(bytes);
  if (!Number.isFinite(size) || size < 0) return "";
  if (size < 1024) return `${size} B`;
  return `${(size / 1024).toFixed(1)} KB`;
}

function handleWsReplayActionError(error) {
  console.error(error);
  if (error instanceof WorkspaceStateConflictError) {
    handleWorkspaceActionError(error);
    return;
  }
  showToast(error?.message || "WebSocket Replay action failed.", "error");
}

function syncWsReplayPortInput(options = {}) {
  const tab = getActiveReplayTab();
  if (!tab || tab.type !== "websocket") return false;
  const rawPort = els.wsPortInput.value.trim();
  const validation = validateWsReplayTargetInput(
    els.wsSchemeSelect.value,
    els.wsHostInput.value,
    rawPort,
    els.wsPathInput.value,
  );
  setWsReplayTargetInputValidity(validation);
  if (!validation.valid) {
    if (options.reportValidity) {
      els.wsPortInput.reportValidity();
    }
    return false;
  }
  const normalizedTarget = normalizeWsReplayTargetFields(
    els.wsSchemeSelect.value,
    els.wsHostInput.value,
    rawPort,
  );
  let changed = false;
    if (
      tab.wsScheme !== normalizedTarget.scheme
      || tab.wsHost !== normalizedTarget.host
      || tab.wsPort !== normalizedTarget.port
    ) {
      tab.wsScheme = normalizedTarget.scheme;
      tab.wsHost = normalizedTarget.host;
      tab.wsPort = normalizedTarget.port;
      refreshWsHandshakeHeadersForTarget(tab);
      scheduleWorkspaceStateSave();
      changed = true;
    }
  if (options.normalizeInput) {
    els.wsHostInput.value = normalizedTarget.host;
    els.wsPortInput.value = normalizedTarget.port;
  }
  return changed;
}

function bindWsReplayEvents() {
  if (!els.wsConnectButton) return;

  els.wsConnectButton.addEventListener("click", () => {
    wsConnect().catch(handleWsReplayActionError);
  });
  els.wsDisconnectButton.addEventListener("click", () => {
    wsDisconnect().catch(handleWsReplayActionError);
  });
  els.wsSendButton.addEventListener("click", () => {
    wsSend().catch(handleWsReplayActionError);
  });

  els.wsSchemeSelect.addEventListener("change", () => {
    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      tab.wsScheme = els.wsSchemeSelect.value;
      tab.wsPort = defaultWsPortForScheme(tab.wsScheme);
      els.wsPortInput.value = tab.wsPort;
      setWsReplayTargetInputValidity(validateWsReplayTargetInput(
        tab.wsScheme,
        els.wsHostInput.value,
        els.wsPortInput.value,
        els.wsPathInput.value,
      ));
      refreshWsHandshakeHeadersForTarget(tab);
      renderReplayTabs();
      scheduleWorkspaceStateSave();
    }
  });
  els.wsHostInput.addEventListener("input", () => {
    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      const validation = validateWsReplayTargetInput(
        els.wsSchemeSelect.value,
        els.wsHostInput.value,
        els.wsPortInput.value,
        els.wsPathInput.value,
      );
      setWsReplayTargetInputValidity(validation);
      if (validation.valid) {
        const normalizedTarget = normalizeWsReplayTargetFields(
          els.wsSchemeSelect.value,
          els.wsHostInput.value,
          els.wsPortInput.value,
        );
        tab.wsScheme = normalizedTarget.scheme;
        tab.wsHost = normalizedTarget.host;
        tab.wsPort = normalizedTarget.port;
        refreshWsHandshakeHeadersForTarget(tab);
      } else {
        tab.wsHost = els.wsHostInput.value.trim();
      }
      renderReplayTabs();
      scheduleWorkspaceStateSave();
    }
  });
  els.wsPortInput.addEventListener("input", () => {
    syncWsReplayPortInput();
  });
  els.wsPortInput.addEventListener("change", () => {
    syncWsReplayPortInput({ normalizeInput: true, reportValidity: true });
  });
  els.wsPathInput.addEventListener("input", () => {
    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      tab.wsPath = els.wsPathInput.value.trim();
      setWsReplayTargetInputValidity(validateWsReplayTargetInput(
        els.wsSchemeSelect.value,
        els.wsHostInput.value,
        els.wsPortInput.value,
        tab.wsPath,
      ));
      scheduleWorkspaceStateSave();
    }
  });
  els.wsHandshakeHeaders.addEventListener("input", () => {
    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      tab.wsHandshakeText = els.wsHandshakeHeaders.value;
      tab.wsHandshakeEdited = true;
      scheduleWorkspaceStateSave();
    }
  });
  els.wsMessageType?.addEventListener("change", () => {
    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      tab.wsMessageType = normalizeWsMessageType(els.wsMessageType.value);
      tab.wsEditorBodyEncoded = false;
      scheduleWorkspaceStateSave();
    }
  });
  // WS Message highlight editor: input → sync to hidden textarea + JSON highlight
  els.wsMessageHighlight.addEventListener("compositionstart", () => {
    wsMessageHighlightComposing = true;
  });
  els.wsMessageHighlight.addEventListener("compositionend", () => {
    wsMessageHighlightComposing = false;
    scheduleWsMessageJsonHighlight(els.wsMessageHighlight.innerText || "");
  });
  els.wsMessageHighlight.addEventListener("input", () => {
    const plainText = els.wsMessageHighlight.innerText || "";
    els.wsMessageEditor.value = plainText;
	    const tab = getActiveReplayTab();
    if (tab && tab.type === "websocket") {
      tab.wsEditorText = plainText;
      tab.wsEditorBodyEncoded = false;
      scheduleWorkspaceStateSave();
    }
    scheduleWsMessageJsonHighlight(plainText);
  });

  // Cmd+Enter to send in WS editor
  els.wsMessageHighlight.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
      e.preventDefault();
      wsSend().catch(handleWsReplayActionError);
    }
  });

  // WS Replay pane resizer (left/right)
  if (els.wsReplayPaneResizer) {
    let startX = 0;
    let startW = 0;
    let nextW = 0;
    const onMove = (e) => {
      const delta = e.clientX - startX;
      const panel = els.wsReplayPanel;
      const total = panel.getBoundingClientRect().width - 10;
      nextW = Math.max(280, Math.min(total - 280, startW + delta));
      applyWsReplayLeftWidth(nextW, { updateState: false });
    };
    const onUp = () => {
      document.body.classList.remove("pane-resizing-x");
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      if (nextW > 0) {
        applyWsReplayLeftWidth(nextW);
        scheduleUiSettingsSave();
      }
    };
    els.wsReplayPaneResizer.addEventListener("mousedown", (e) => {
      e.preventDefault();
      startX = e.clientX;
      const left = els.wsReplayPanel.querySelector(".ws-replay-left");
      startW = left ? left.getBoundingClientRect().width : 400;
      nextW = startW;
      document.body.classList.add("pane-resizing-x");
      window.addEventListener("mousemove", onMove);
      window.addEventListener("mouseup", onUp);
    });
    els.wsReplayPaneResizer.addEventListener("dblclick", () => {
      resetWsReplayLeftWidth();
      scheduleUiSettingsSave();
    });
  }

  // WS Replay frame detail resizer (vertical)
  if (els.wsReplayFrameResizer) {
    let startY = 0;
    let startH = 0;
    let nextH = 0;
    const onMove = (e) => {
      const delta = startY - e.clientY;
      const right = els.wsReplayPanel.querySelector(".ws-replay-right");
      const total = right ? right.getBoundingClientRect().height : 600;
      nextH = Math.max(120, Math.min(total * 0.8, startH + delta));
      applyWsReplayFrameDetailHeight(nextH, { updateState: false });
    };
    const onUp = () => {
      document.body.classList.remove("pane-resizing-y");
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      if (nextH > 0) {
        applyWsReplayFrameDetailHeight(nextH);
        scheduleUiSettingsSave();
      }
    };
    els.wsReplayFrameResizer.addEventListener("mousedown", (e) => {
      e.preventDefault();
      startY = e.clientY;
      const detail = els.wsReplayPanel.querySelector(".ws-frame-detail");
      startH = detail ? detail.getBoundingClientRect().height : 200;
      nextH = startH;
      document.body.classList.add("pane-resizing-y");
      window.addEventListener("mousemove", onMove);
      window.addEventListener("mouseup", onUp);
    });
    els.wsReplayFrameResizer.addEventListener("dblclick", () => {
      resetWsReplayFrameDetailHeight();
      scheduleUiSettingsSave();
    });
  }

}

/* ─── Compare / Diff ─── */
let compareBaseId = null;
let compareBaseSessionId = null;
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
  compareBaseSessionId = currentSessionId();
  const btn = document.getElementById("compareWithBaseBtn");
  if (btn) btn.disabled = false;
  const item = getHistoryItem(transactionId);
  if (btn && item) btn.textContent = `Compare with #${item.index ?? "?"}`;
}

async function openCompareModal(targetId) {
  if (!compareBaseId || compareBaseId === targetId) return;
  const sessionId = currentSessionId();
  if (compareBaseSessionId !== sessionId) {
    clearCompareState();
    return;
  }
  const [baseRes, targetRes] = await Promise.all([
    fetch(transactionPath(compareBaseId, sessionId)).then((r) => r.ok ? r.json() : null),
    fetch(transactionPath(targetId, sessionId)).then((r) => r.ok ? r.json() : null),
  ]);
  if (currentSessionId() !== sessionId) return;
  if (!baseRes || !targetRes) return;
  compareBaseRecord = baseRes;
  compareTargetRecord = targetRes;
  compareActiveTab = "request";
  renderCompareModal();
  document.getElementById("compareModal").classList.remove("hidden");
}

function renderCompareModal() {
  if (!compareBaseRecord || !compareTargetRecord) return;
  const baseItem = getHistoryItem(compareBaseRecord.id);
  const targetItem = getHistoryItem(compareTargetRecord.id);
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

function clearCompareState() {
  compareBaseId = null;
  compareBaseSessionId = null;
  compareBaseRecord = null;
  compareTargetRecord = null;
  compareActiveTab = "request";
  const btn = document.getElementById("compareWithBaseBtn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Compare with base";
  }
  document.getElementById("compareModal")?.classList.add("hidden");
}

/* ─── Context menu (color tags & notes) ─── */
let contextMenuTargetId = null;
let contextMenuAnchor = { x: 0, y: 0 };
let contextMenuSessionId = null;
let contextMenuRecordTarget = null;
let contextMenuNoteTimer = null;
let contextMenuPendingNote = null;

function openContextMenu(x, y, transactionId) {
  contextMenuTargetId = transactionId;
  contextMenuSessionId = currentSessionId();
  contextMenuRecordTarget = createTransactionRecordMenuTarget(transactionId, contextMenuSessionId);
  const menu = els.contextMenu;
  menu.classList.remove("hidden");

  const item = getHistoryItem(transactionId);
  const currentColor = item?.color_tag || "";

  menu.querySelectorAll(".color-dot").forEach((dot) => {
    dot.classList.toggle("active", dot.dataset.color === currentColor);
  });

  els.contextMenuNote.value = "";
  renderContextMenuNotes(null);
  if (transactionId) {
    loadUserNote(transactionId);
  }

  contextMenuAnchor = { x, y };
  positionContextMenu();
}

// Keep the menu on screen. Called again after the async note load, because
// rendering recorded notes changes the menu height after it was first placed.
function positionContextMenu() {
  const menu = els.contextMenu;
  if (!menu || menu.classList.contains("hidden")) return;
  const maxX = window.innerWidth - menu.offsetWidth - 8;
  const maxY = window.innerHeight - menu.offsetHeight - 8;
  menu.style.left = `${Math.max(0, Math.min(contextMenuAnchor.x, maxX))}px`;
  menu.style.top = `${Math.max(0, Math.min(contextMenuAnchor.y, maxY))}px`;
}

// Recorded (server-side) notes are read-only here. They are otherwise only
// visible in the inspector column, which responsive CSS hides below 1481px,
// so this is the one surface that always works.
function renderContextMenuNotes(notes) {
  if (!els.contextMenuNotes || !els.contextMenuNotesSection) return;
  const items = Array.isArray(notes)
    ? notes.filter((note) => typeof note === "string" && note.trim())
    : [];
  els.contextMenuNotes.innerHTML = items.map((note) => `<p>${escapeHtml(note)}</p>`).join("");
  els.contextMenuNotesSection.classList.toggle("hidden", items.length === 0);
  if (els.contextMenuNotesDivider) {
    els.contextMenuNotesDivider.classList.toggle("hidden", items.length === 0);
  }
}

function closeContextMenu() {
  flushContextMenuPendingNote();
  els.contextMenu.classList.add("hidden");
  contextMenuTargetId = null;
  contextMenuSessionId = null;
  contextMenuRecordTarget = null;
}

function contextMenuSessionIsCurrent() {
  return !!contextMenuSessionId && contextMenuSessionId === currentSessionId();
}

async function loadUserNote(transactionId) {
  const sessionId = currentSessionId();
  try {
    const response = await fetch(transactionPath(transactionId, sessionId));
    if (currentSessionId() !== sessionId) return;
    if (response.ok) {
      const record = await response.json();
      if (currentSessionId() === sessionId && contextMenuTargetId === transactionId) {
        els.contextMenuNote.value = record.user_note || "";
        renderContextMenuNotes(record.notes);
        positionContextMenu();
      }
    }
  } catch { /* ignore */ }
}

async function updateAnnotations(transactionId, payload, sessionId = currentSessionId()) {
  if (!state._pendingAnnotations) state._pendingAnnotations = new Map();
  if (!state._annotationInFlight) state._annotationInFlight = new Set();
  const pending = state._pendingAnnotations;
  const existing = pending.get(transactionId);
  const mergedPayload = {
    ...(existing?.sessionId === sessionId ? existing.payload : {}),
    ...payload,
    client_id: annotationClientId,
    client_version: nextAnnotationClientVersion(),
  };
  pending.set(transactionId, {
    sessionId,
    payload: mergedPayload,
  });
  if (!state._annotationInFlight.has(transactionId)) {
    flushPendingAnnotations(transactionId);
  }
}

function flushContextMenuPendingNote(options = {}) {
  window.clearTimeout(contextMenuNoteTimer);
  contextMenuNoteTimer = null;
  const pending = contextMenuPendingNote;
  if (!pending?.id || !pending.sessionId) {
    contextMenuPendingNote = null;
    return false;
  }
  if (options.sessionId && pending.sessionId !== options.sessionId) {
    return false;
  }
  contextMenuPendingNote = null;
  updateAnnotations(pending.id, { user_note: pending.value || null }, pending.sessionId);
  return true;
}

function flushAnnotationsOnUnload() {
  flushContextMenuPendingNote();
  if (!state._pendingAnnotations) {
    return;
  }
  for (const [transactionId, entry] of state._pendingAnnotations.entries()) {
    if (!entry?.sessionId || !entry.payload) continue;
    const body = JSON.stringify(entry.payload);
    if (utf8ByteLength(body) > WORKSPACE_UNLOAD_KEEPALIVE_MAX_BYTES) continue;
    fetch(sessionWritePath(`/api/transactions/${encodeURIComponent(transactionId)}/annotations`, entry.sessionId), {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body,
      keepalive: true,
    }).catch(() => {});
  }
}

async function flushAllPendingAnnotations(options = {}) {
  flushContextMenuPendingNote(options);
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const pendingIds = state._pendingAnnotations ? Array.from(state._pendingAnnotations.keys()) : [];
    const inFlight = state._annotationInFlight || new Set();
    if (!pendingIds.length && !inFlight.size) {
      return;
    }
    const idleIds = pendingIds.filter((id) => !inFlight.has(id));
    if (idleIds.length) {
      await Promise.all(idleIds.map((id) => flushPendingAnnotations(id, {
        ...options,
        throwOnError: true,
      })));
    }
    if ((!state._pendingAnnotations || state._pendingAnnotations.size === 0) && (!state._annotationInFlight || state._annotationInFlight.size === 0)) {
      return;
    }
    await new Promise((resolve) => window.setTimeout(resolve, 50));
  }
  throw new Error("Timed out saving pending annotations.");
}

async function flushPendingAnnotations(transactionId, options = {}) {
  if (!state._pendingAnnotations) return false;
  if (!state._annotationInFlight) state._annotationInFlight = new Set();
  if (state._annotationInFlight.has(transactionId)) return false;
  const pending = state._pendingAnnotations;
  const entry = pending.get(transactionId);
  if (!entry) return false;
  const { sessionId, payload } = entry;

  state._annotationInFlight.add(transactionId);
  let failureMessage = "";
  let saved = false;
  try {
    const response = await fetch(sessionWritePath(
      `/api/transactions/${encodeURIComponent(transactionId)}/annotations`,
      sessionId,
      options,
    ), {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      failureMessage = await response.text().catch(() => "Failed to save annotation");
      throw new Error(failureMessage || "Failed to save annotation");
    }
    const summary = await response.json();
    observeAnnotationRevision(summary);
    saved = true;
    if (currentSessionId() !== sessionId) {
      return saved;
    } else if (pending.get(transactionId) === entry) {
      const index = getHistoryItemIndex(transactionId);
      if (index !== -1) {
        Object.assign(state.items[index], summary);
        prepareHistoryItem(state.items[index]);
        if (!summaryMatchesActiveHistoryFilters(state.items[index])) {
          state.items.splice(index, 1);
          adjustHistoryPagingAfterLocalRemoval(1, { decrementTotal: false });
          if (state.selectedId === transactionId) {
            state.selectedId = null;
            state.selectedRecord = null;
            renderEmptyDetail();
          }
          rebuildHistoryItemIndex();
          refreshHistoryPagingCursorFromItems();
        } else {
          if (resortLoadedHistoryItemsForCurrentSort()) {
            rebuildHistoryItemIndex();
          } else {
            state._itemById.set(transactionId, state.items[index]);
          }
        }
        state._itemsVersion += 1;
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
        if (summary.annotation_revision !== undefined) {
          state.selectedRecord.annotation_revision = summary.annotation_revision;
        }
        renderDetail(state.selectedRecord, { preserveOriginalToggles: true });
      }
    }
  } catch (error) {
    console.error("Failed to update annotations:", error);
    if (currentSessionId() === sessionId) {
      showToast(failureMessage || error.message || "Failed to save annotation", "error");
      loadTransactions(true).catch((reloadError) => console.error(reloadError));
    }
    if (options.throwOnError) {
      throw error;
    }
    return false;
  } finally {
    state._annotationInFlight.delete(transactionId);
    if (pending.get(transactionId) === entry) {
      if (saved) {
        pending.delete(transactionId);
      }
    } else if (pending.has(transactionId)) {
      flushPendingAnnotations(transactionId);
    }
  }
  return saved;
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
    if (!contextMenuSessionIsCurrent()) {
      closeContextMenu();
      return;
    }
    const color = dot.dataset.color || null;
    updateAnnotations(contextMenuTargetId, { color_tag: color }, contextMenuSessionId);
    els.contextMenu.querySelectorAll(".color-dot").forEach((d) => {
      d.classList.toggle("active", d.dataset.color === (color || ""));
    });
  });
});

els.contextMenu.querySelectorAll(".context-menu-item").forEach((item) => {
  item.addEventListener("click", () => {
    const action = item.dataset.action;
    const target = contextMenuRecordTarget;
    const targetId = target?.id || contextMenuTargetId;
    const targetSessionId = target?.sessionId || contextMenuSessionId;
    if (!targetId) return;
    if (!contextMenuSessionIsCurrent()) {
      closeContextMenu();
      return;
    }
    state.selectedId = targetId;
    closeContextMenu();
    const loadTargetRecord = () => loadMenuTargetRecord(target)
      || loadTransactionRecordById(targetId, targetSessionId);
    if (action === "send-to-replay") {
      loadTargetRecord()
        .then((record) => {
          if (!record) throw new Error("Selected transaction could not be loaded.");
          if (record.kind === "tunnel") throw new Error("Tunnel records cannot be sent to Replay.");
          openTransactionRecordInReplay(record);
        })
        .catch(handleSendActionError);
    } else if (action === "send-to-fuzzer") {
      loadTargetRecord()
        .then((record) => {
          if (!record) throw new Error("Selected transaction could not be loaded.");
          openFuzzerFromRecord(record);
        })
        .catch(handleSendActionError);
    } else if (action === "send-to-sequence") {
      loadTargetRecord()
        .then((record) => {
          if (!record) throw new Error("Selected transaction could not be loaded.");
          return sendRecordToSequence(record);
        })
        .catch(handleSendActionError);
    } else if (action === "copy-url") {
      copyMenuTargetUrl(target);
    } else if (action?.startsWith("copy-as-")) {
      const format = action.replace("copy-as-", "");
      loadTargetRecord()
        .then((record) => {
          if (!record) throw new Error("Selected transaction could not be loaded.");
          const text = recordToFormat(record, format);
          if (!text) return null;
          return copyTextToClipboard(text).then(() => showToast(`Copied as ${format}`));
        })
        .catch(handleClipboardActionError);
    } else if (action === "compare-set-base") {
      setCompareBase(targetId);
    } else if (action === "compare-with-base") {
      openCompareModal(targetId).catch((error) => console.error(error));
    }
  });
});

els.contextMenuNote.addEventListener("input", () => {
  if (!contextMenuTargetId) return;
  if (!contextMenuSessionIsCurrent()) {
    closeContextMenu();
    return;
  }
  clearTimeout(contextMenuNoteTimer);
  const id = contextMenuTargetId;
  const sessionId = contextMenuSessionId;
  const value = truncateUtf8(els.contextMenuNote.value, MAX_ANNOTATION_NOTE_BYTES);
  if (value !== els.contextMenuNote.value) {
    els.contextMenuNote.value = value;
  }
  contextMenuPendingNote = { id, sessionId, value };
  contextMenuNoteTimer = setTimeout(() => {
    flushContextMenuPendingNote();
  }, 500);
});

els.contextMenuNote.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    if (!contextMenuTargetId) return;
    if (!contextMenuSessionIsCurrent()) {
      closeContextMenu();
      return;
    }
    contextMenuPendingNote = {
      id: contextMenuTargetId,
      sessionId: contextMenuSessionId,
      value: truncateUtf8(els.contextMenuNote.value, MAX_ANNOTATION_NOTE_BYTES),
    };
    flushContextMenuPendingNote();
    closeContextMenu();
  }
  event.stopPropagation();
});

/* ─── WS Frame context menu ─── */

let wsFrameContextMenuTarget = null;

function openWsFrameContextMenu(x, y) {
  const session = state.selectedWebsocketRecord;
  wsFrameContextMenuTarget = {
    sessionId: session?.id || state.selectedWebsocketId || null,
    frameIdx: state.selectedFrameIdx,
  };
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
  wsFrameContextMenuTarget = null;
}

document.getElementById("wsFrameToReplayBtn").addEventListener("click", () => {
  const target = wsFrameContextMenuTarget;
  closeWsFrameContextMenu();
  if (!target) return;
  const session = state.selectedWebsocketRecord;
  if (target.sessionId && session?.id && session.id !== target.sessionId) {
    showToast("WebSocket session changed. Open the frame menu again.", "error");
    return;
  }
  sendWsFrameToReplay(target.frameIdx);
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
  if (!session) return;
  if (session.id && state.selectedWebsocketId && session.id !== state.selectedWebsocketId) {
    showToast("WebSocket session is still loading. Select the frame again.", "error");
    return;
  }
  if (frameIdx == null) {
    showToast("Select a WebSocket frame first.", "error");
    return;
  }
  const frames = getWebsocketFrames(session);
  const requestedIndex = Number(frameIdx);
  if (!Number.isFinite(requestedIndex)) {
    showToast("Select a WebSocket frame first.", "error");
    return;
  }
  const frame = frames.find((candidate) => candidate.index === requestedIndex);
  if (!frame) {
    showToast("That WebSocket frame is no longer loaded. Refreshing frames...", "error");
    state.selectedFrameIdx = null;
    hideFrameDetail();
    if (session.id) {
      loadWebsocketDetail(session.id, { force: true }).catch((error) => console.error(error));
    }
    return;
  }
  if (frame.direction !== "client_to_server") {
    showToast("Only client-to-server WebSocket frames can be sent to Replay.", "error");
    return;
  }
  const firstLoadedFrameIndex = frames.length ? Number(frames[0]?.index) : 0;
  const priorClientSetupFrameTruncated = frames.some((candidate) => (
    candidate.direction === "client_to_server"
    && Number(candidate.index) < requestedIndex
    && candidate.preview_truncated
  ));
  const setupQueueMayBeIncomplete = !!session.frames_truncated
    || (Number.isFinite(firstLoadedFrameIndex) && firstLoadedFrameIndex > 0)
    || priorClientSetupFrameTruncated;

  // Determine WS scheme
  let wsScheme;
  if (session.scheme === "wss" || session.scheme === "ws") {
    wsScheme = session.scheme;
  } else if (session.scheme === "https" || (session.host && session.host.endsWith(":443"))) {
    wsScheme = "wss";
  } else {
    wsScheme = "ws";
  }

  if (frame.preview_truncated) {
    showToast("Frame preview is truncated and cannot be replayed safely.", "error");
    return;
  }
  if (!isWsFrameReplayable(frame)) {
    showToast("Close and unknown WebSocket frames cannot be replayed safely.", "error");
    return;
  }
  const messageType = wsReplayMessageTypeForFrame(frame);
  const body = wsReplayEditorTextForFrame(frame);
  const editorBodyEncoded = messageType !== "text" && frame.body_encoding === "base64";

  const target = authorityToTargetState(session.host || "", wsScheme === "ws" ? "http" : "https");
  const port = normalizePortValue(target.port) || defaultWsPortForScheme(wsScheme);
  const replayTab = createWsReplayTab({
    scheme: wsScheme,
    host: target.host,
    port,
    path: session.path || "/",
    headers: normalizedHeaders(session.request?.headers),
    capturedFrames: setupQueueMayBeIncomplete ? [] : frames,
    setupQueue: setupQueueMayBeIncomplete ? [] : undefined,
    setupQueueNotice: setupQueueMayBeIncomplete
      ? "This WebSocket history is truncated, so earlier client setup frames may be missing. Auto-send setup was disabled for this replay tab."
      : "",
    selectedFrameIndex: frame.index,
    editorText: body,
    messageType,
    editorBodyEncoded,
  });
  if (setupQueueMayBeIncomplete) {
    showToast("WebSocket history is truncated. Replay setup auto-send was disabled.", "warning");
  } else if (replayTab.wsSetupNotice) {
    showToast("WebSocket replay setup auto-send was disabled because there are too many earlier client messages.", "warning");
  }
  setActiveTool("replay");
  renderToolPanels();
}

// duplicate removed — renderWsReplay() at line ~9443 is the canonical version

/* ─── Replay request context menu ─── */

let replayContextMenuTabId = null;

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
  replayContextMenuTabId = tab.id;

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
  replayContextMenuTabId = null;
}

function getReplayTabById(tabId) {
  return state.replayTabs.find((tab) => tab.id === tabId) || null;
}

function syncReplayRequestEditorForTab(tab) {
  if (!tab) return;
  if (state.activeReplayTabId !== tab.id) {
    refreshReplayTabLabel(tab.id);
    return;
  }
  const cv = getCMView("replayReq");
  if (cv) {
    cv.setContent(tab.requestText);
  } else if (els.replayRequestEditor) {
    els.replayRequestEditor.value = tab.requestText;
    renderReplayRequestHighlight(tab.requestText);
  }
  updateReplaySearchPane("request", tab.requestText);
  syncReplayToolbar(tab);
  renderReplayTabs();
}

function changeReplayMethod(newMethod, tabId = state.activeReplayTabId) {
  const tab = getReplayTabById(tabId);
  if (!tab || tab.type === "websocket") return;

  const isActiveTab = state.activeReplayTabId === tab.id;
  const cv = isActiveTab ? getCMView("replayReq") : null;
  const text = cv
    ? cv.getContent()
    : (isActiveTab && els.replayRequestEditor ? els.replayRequestEditor.value : tab.requestText) || "";
  const updated = text.replace(/^[A-Z]+(\s)/i, newMethod + "$1");
  tab.requestText = updated;
  clearReplayResponseForDraftChange(tab);
  syncReplayRequestEditorForTab(tab);
  scheduleWorkspaceStateSave();
}

function replayRequestToCurl(tab = getActiveReplayTab()) {
  if (!tab) return "";
  const blocked = replayExportBlockedReason(tab);
  if (blocked) {
    showToast(blocked, "error");
    return "";
  }
  const target = getReplayExportTarget(tab);
  const parsed = parseRequestForExport(
    tab.requestText ?? "",
    target.scheme || "https",
    target.host || "",
    target.port || "",
  );
  return requestToCurl(parsed);
}

function replayExportBlockedReason(tab) {
  if (!tab || tab.type === "websocket") return "";
  const request = deriveRepeaterRequest(tab);
  if (request.body_encoding === "base64" && String(request.body || "").length > 0) {
    return "Binary request bodies cannot be exported safely from Replay.";
  }
  return "";
}

function historyRequestExportBlockedReason(record) {
  const request = record?.request;
  if (!request) return "";
  if (request.body_encoding === "base64" && String(request.body_preview || "").length > 0) {
    return "Binary captured request bodies cannot be exported safely.";
  }
  if (request.preview_truncated) {
    return "Truncated captured request bodies cannot be exported safely.";
  }
  return "";
}

function getReplayExportTarget(tab) {
  const request = deriveRepeaterRequest(tab);
  return getRepeaterTargetConfig(tab, request);
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

function parseRequestForExport(rawText, scheme, host, port) {
  const lines = String(rawText || "").replace(/\r\n/g, "\n").split("\n");
  const [startLine = "GET / HTTP/1.1", ...rest] = lines;
  const match = startLine.match(/^([A-Za-z0-9!#$%&'*+.^_`|~-]+)\s+(\S+)(?:\s+(HTTP\/[0-9.]+))?$/);
  if (!match) return null;
  const method = match[1];
  const path = match[2];
  const httpVersion = normalizeReplayHttpVersion(match[3] || "");
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
  const bodyProvided = bodyIdx !== -1;
  const headers = headerLines.map((h) => parseHeaderLineForExport(h)).filter(Boolean);
  const authority = exportHeaderValue(headers, ":authority");
  const exportHost = host || exportHeaderValue(headers, "host") || authority || "localhost";
  return { method, url: buildUrlFromTarget(scheme, exportHost, port, path), headers, body, bodyProvided, httpVersion };
}

function parseHeaderLineForExport(line) {
  const text = String(line || "");
  if (text.startsWith(":")) {
    const idx = text.indexOf(":", 1);
    return idx > 1 ? { name: text.slice(0, idx).trim(), value: text.slice(idx + 1).trim() } : null;
  }
  const idx = text.indexOf(":");
  return idx > 0 ? { name: text.slice(0, idx).trim(), value: text.slice(idx + 1).trim() } : null;
}

function exportHeaderValue(headers, name) {
  return exportableHeaderCandidates(headers).find((header) => headerNameEquals(header, name))?.value || "";
}

function exportableHeaderCandidates(headers) {
  return (Array.isArray(headers) ? headers : [])
    .map((header) => ({
      name: String(header?.name || "").trim(),
      value: String(header?.value ?? ""),
    }))
    .filter((header) => header.name);
}

function isHttpPseudoHeaderName(name) {
  return String(name || "").trim().startsWith(":");
}

function requestToPython(parsed) {
  if (!parsed) return "";
  const py = (s) => JSON.stringify(String(s));
  const lines = [`import requests`, ""];
  const hasBody = parsed.bodyProvided || parsed.body.length > 0;
  const headerObj = exportableHeaders(parsed.headers, parsed.url);
  if (headerObj.length) {
    lines.push("headers = {");
    for (const h of headerObj) lines.push(`    ${py(h.name)}: ${py(h.value)},`);
    lines.push("}");
    lines.push("");
  }
  if (hasBody) {
    lines.push(`data = ${py(parsed.body)}`);
    lines.push("");
  }
  const args = [py(parsed.url)];
  args.unshift(py(parsed.method));
  if (headerObj.length) args.push("headers=headers");
  if (hasBody) args.push("data=data");
  lines.push(`response = requests.request(${args.join(", ")})`);
  lines.push(`print(response.status_code)`);
  lines.push(`print(response.text)`);
  return lines.join("\n");
}

function exportableHeaders(headers, url = "") {
  return exportableHeadersForUrl(headers, url);
}

function exportableHeadersForUrl(headers, url = "") {
  const normalized = exportableHeaderCandidates(headers);
  const hostHeader = normalized.find((h) => headerNameEquals(h, "host"));
  const preserveHost = hostHeader && hostHeaderDiffersFromUrl(hostHeader.value, url);
  return normalized
    .filter((h) => {
      if (isHttpPseudoHeaderName(h.name)) return false;
      if (headerNameEquals(h, "content-length")) return false;
      if (headerNameEquals(h, "host")) return !!preserveHost;
      return true;
    });
}

function hostHeaderDiffersFromUrl(hostHeader, url) {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    const scheme = parsed.protocol.replace(":", "") || "https";
    const port = parsed.port || (scheme === "https" ? "443" : "80");
    const authority = joinAuthority(stripIpv6Brackets(parsed.hostname), port);
    return !httpRequestAuthoritiesEquivalent(authority, hostHeader, scheme);
  } catch (_error) {
    return false;
  }
}

function requestToFetch(parsed) {
  if (!parsed) return "";
  const js = (s) => JSON.stringify(String(s));
  if (fetchExportBlockedReason(parsed)) {
    return "";
  }
  const headerObj = exportableHeadersForUrl(parsed.headers, parsed.url);
  const opts = [];
  if (parsed.method !== "GET") opts.push(`  method: ${js(parsed.method)}`);
  if (headerObj.length) {
    const hLines = headerObj.map((h) => `    ${js(h.name)}: ${js(h.value)}`).join(",\n");
    opts.push(`  headers: {\n${hLines}\n  }`);
  }
  if (parsed.bodyProvided || parsed.body.length > 0) {
    opts.push(`  body: ${JSON.stringify(parsed.body)}`);
  }
  if (!opts.length) return `fetch(${js(parsed.url)})\n  .then(res => res.text())\n  .then(console.log);`;
  return `fetch(${js(parsed.url)}, {\n${opts.join(",\n")}\n})\n  .then(res => res.text())\n  .then(console.log);`;
}

function fetchExportBlockedReason(parsed) {
  if (!parsed) return "";
  const hasBody = parsed.bodyProvided || parsed.body.length > 0;
  if (hasBody && ["GET", "HEAD"].includes(parsed.method.toUpperCase())) {
    return "Fetch cannot send GET or HEAD requests with a body. Use cURL or Python export instead.";
  }
  const hostHeader = normalizedHeaders(parsed.headers).find((h) => headerNameEquals(h, "host"));
  if (hostHeader && hostHeaderDiffersFromUrl(hostHeader.value, parsed.url)) {
    return "Fetch cannot preserve a custom Host header. Use cURL or Python export instead.";
  }
  return "";
}

function requestToPowerShell(parsed) {
  if (!parsed) return "";
  const esc = (s) => s.replace(/'/g, "''");
  const parts = [`Invoke-WebRequest -Uri '${esc(parsed.url)}'`];
  if (parsed.method !== "GET") parts.push(`-Method ${parsed.method}`);
  const headerObj = exportableHeaders(parsed.headers, parsed.url);
  if (headerObj.length) {
    const hLines = headerObj.map((h) => `'${esc(h.name)}'='${esc(h.value)}'`).join("; ");
    parts.push(`-Headers @{${hLines}}`);
  }
  if (parsed.bodyProvided || parsed.body.length > 0) {
    parts.push(`-Body '${esc(parsed.body)}'`);
  }
  return parts.join(" `\n  ");
}

function requestToCurl(parsed) {
  if (!parsed) return "";
  const parts = [`curl -X ${shellQuote(parsed.method)}`];
  const versionFlag = curlHttpVersionFlag(parsed.httpVersion);
  if (versionFlag) parts.push(versionFlag);
  if (urlNeedsPathAsIs(parsed.url)) parts.push("--path-as-is");
  for (const h of exportableHeaders(parsed.headers, parsed.url)) {
    parts.push(`-H ${shellQuote(`${h.name}: ${h.value}`)}`);
  }
  if (parsed.bodyProvided || parsed.body.length > 0) {
    parts.push(`--data-raw ${shellQuote(parsed.body)}`);
  }
  parts.push(shellQuote(parsed.url));
  return parts.join(" \\\n  ");
}

function curlHttpVersionFlag(httpVersion) {
  const normalized = normalizeReplayHttpVersion(httpVersion || "");
  if (normalized === "HTTP/1.0") return "--http1.0";
  if (normalized === "HTTP/1.1") return "--http1.1";
  if (normalized === "HTTP/2") return "--http2";
  return "";
}

function urlNeedsPathAsIs(url) {
  return /(?:^|\/)\.\.?(?=\/|\?|$)/.test(rawPathFromUrlString(url || "") || "");
}

function replayRequestToFormat(format, tab = getActiveReplayTab()) {
  if (!tab) return "";
  const blocked = replayExportBlockedReason(tab);
  if (blocked) {
    showToast(blocked, "error");
    return "";
  }
  const target = getReplayExportTarget(tab);
  const parsed = parseRequestForExport(
    tab.requestText,
    target.scheme || "https",
    target.host || "",
    target.port || "",
  );
  if (format === "fetch") {
    const fetchBlocked = fetchExportBlockedReason(parsed);
    if (fetchBlocked) {
      showToast(fetchBlocked, "error");
      return "";
    }
  }
  if (format === "curl") return requestToCurl(parsed);
  if (format === "python") return requestToPython(parsed);
  if (format === "fetch") return requestToFetch(parsed);
  if (format === "powershell") return requestToPowerShell(parsed);
  return "";
}

function copySelectedTransactionUrl() {
  const record = getCurrentSelectedRecord();
  if (!record) return;
  const url = transactionUrlFromSource(record);
  copyTextToClipboard(url)
    .then(() => showToast("Copied URL"))
    .catch(() => showToast("Failed to copy", "error"));
}

function copyResponseContent(format) {
  const record = getCurrentSelectedRecord();
  copyResponseContentForRecord(record, format);
}

function copyResponseContentForRecord(record, format) {
  if (!record?.response) return;
  let text = "";
  if (format === "response-headers") {
    text = `${buildRawResponseHead(record).replace(/\n/g, "\r\n")}\r\n`;
  } else if (format === "response-body") {
    text = record.response.body_encoding === "base64"
      ? safeDecodeBase64(record.response.body_preview || "")
      : (record.response.body_preview || "");
    if (record.response.preview_truncated) {
      text = `${text}\n\n[preview truncated]`;
    }
  } else {
    text = buildRawResponse(record);
  }
  const label = format === "response-headers"
    ? "Copied headers"
    : format === "response-body" && record.response.preview_truncated
      ? "Copied response preview"
      : format === "response-body"
        ? "Copied body"
        : "Copied raw response";
  return copyTextToClipboard(text)
    .then(() => showToast(label))
    .catch(() => showToast("Failed to copy", "error"));
}

// Synchronous version using already-loaded selectedRecord (preserves user gesture for clipboard)
function selectedRecordToFormat(format) {
  const record = getCurrentSelectedRecord();
  return recordToFormat(record, format);
}

function recordToFormat(record, format) {
  if (!record) return "";
  const blocked = historyRequestExportBlockedReason(record);
  if (blocked) {
    showToast(blocked, "error");
    return "";
  }
  const rawText = buildRawRequest(record);
  const scheme = record.scheme || "https";
  const hostHeader = normalizedHeaders(record.request?.headers).find((h) => headerNameEquals(h, "host"));
  const authorityHeader = normalizedHeaders(record.request?.headers).find((h) => headerNameEquals(h, ":authority"));
  const host = record.host || hostHeader?.value || authorityHeader?.value || "";
  const parsed = parseRequestForExport(rawText, scheme, host, "");
  if (!parsed) return "";
  if (format === "fetch") {
    const fetchBlocked = fetchExportBlockedReason(parsed);
    if (fetchBlocked) {
      showToast(fetchBlocked, "error");
      return "";
    }
  }
  if (format === "curl") return requestToCurl(parsed);
  if (format === "python") return requestToPython(parsed);
  if (format === "fetch") return requestToFetch(parsed);
  if (format === "powershell") return requestToPowerShell(parsed);
  return "";
}

async function historyRequestToFormat(transactionId, format) {
  const sessionId = currentSessionId();
  const response = await fetch(transactionPath(transactionId, sessionId));
  if (currentSessionId() !== sessionId) return "";
  if (!response.ok) return "";
  const record = await response.json();
  if (currentSessionId() !== sessionId) return "";
  const blocked = historyRequestExportBlockedReason(record);
  if (blocked) {
    showToast(blocked, "error");
    return "";
  }
  const rawText = buildRawRequest(record);
  const scheme = record.scheme || "https";
  const hostHeader = normalizedHeaders(record.request?.headers).find((h) => headerNameEquals(h, "host"));
  const authorityHeader = normalizedHeaders(record.request?.headers).find((h) => headerNameEquals(h, ":authority"));
  const host = record.host || hostHeader?.value || authorityHeader?.value || "";
  const parsed = parseRequestForExport(rawText, scheme, host, "");
  if (!parsed) return "";
  if (format === "fetch") {
    const fetchBlocked = fetchExportBlockedReason(parsed);
    if (fetchBlocked) {
      showToast(fetchBlocked, "error");
      return "";
    }
  }
  if (format === "curl") return requestToCurl(parsed);
  if (format === "python") return requestToPython(parsed);
  if (format === "fetch") return requestToFetch(parsed);
  if (format === "powershell") return requestToPowerShell(parsed);
  return "";
}

function copyTransactionUrl(transactionId) {
  const item = getHistoryItem(transactionId);
  if (!item) return;
  const url = transactionUrlFromSource(item);
  copyTextToClipboard(url).then(() => showToast("Copied URL")).catch(() => {});
}

function copyReplayUrl(tab = getActiveReplayTab()) {
  if (!tab) return;
  const target = getReplayExportTarget(tab);
  const scheme = target.scheme || "https";
  const host = target.host || "localhost";
  const port = target.port || "";
  const text = tab.requestText || "";
  const match = text.match(/^[A-Z]+\s+(\S+)/i);
  const path = match ? match[1] : "/";
  const url = buildUrlFromTarget(scheme, host, port, path);
  copyTextToClipboard(url).then(() => showToast("Copied URL")).catch(() => {});
}

function parseCurlCommand(text) {
  const normalized = text.replace(/\\\s*\n/g, " ").trim();
  const shellWords = splitShellWords(normalized);
  if (!shellWords.length || shellWords[0].toLowerCase() !== "curl") return null;
  const tokens = shellWords.slice(1);
  let method = "GET";
  let methodExplicit = false;
  let getMode = false;
  let pathAsIs = false;
  let httpVersion = "";
  let url = "";
  const headers = [];
  const bodyParts = [];
  let bodyProvided = false;
  let needsDefaultFormContentType = false;
  const curlOptionsWithValue = new Set([
    "--abstract-unix-socket",
    "--cacert",
    "--capath",
    "--cert",
    "--cert-type",
    "--ciphers",
    "--connect-timeout",
    "--connect-to",
    "--cookie-jar",
    "--dns-interface",
    "--dns-ipv4-addr",
    "--dns-ipv6-addr",
    "--dns-servers",
    "--interface",
    "--key",
    "--key-type",
    "--limit-rate",
    "--local-port",
    "--max-filesize",
    "--max-redirs",
    "--max-time",
    "--output",
    "--proxy",
    "--proxy-header",
    "--proxy-user",
    "--request-target",
    "--resolve",
    "--socks5",
    "--socks5-hostname",
    "--tls-max",
    "--unix-socket",
  ]);
  const curlShortOptionsWithValue = new Set(["-E", "-m", "-o", "-x", "-y", "-Y"]);
  const requireOptionValue = (flag) => {
    if (t + 1 >= tokens.length) {
      return { error: `cURL ${flag} requires a value.` };
    }
    const value = tokens[t + 1];
    if (value === undefined || value === "") {
      return { error: `cURL ${flag} requires a value.` };
    }
    t += 1;
    return { value };
  };
  const addHeader = (rawHeader, flag = "-H") => {
    const hVal = String(rawHeader || "");
    const ci = hVal.indexOf(":");
    if (ci <= 0) return `cURL ${flag} requires a header in Name: Value form.`;
    const name = hVal.slice(0, ci).trim();
    if (!name) return `cURL ${flag} requires a header name.`;
    if (headerNameEquals({ name }, "content-length")) return "";
    headers.push({ name, value: hVal.slice(ci + 1).trim() });
    return "";
  };
  const addBodyPart = (flag, value, options = {}) => {
    if (flag === "--data-urlencode") {
      const encoded = encodeCurlDataUrlencode(value);
      if (encoded.error) return encoded.error;
      bodyParts.push(encoded.value);
      bodyProvided = true;
      if (options.defaultContentType !== false) needsDefaultFormContentType = true;
      if (!getMode && !methodExplicit && (!method || method === "GET")) method = "POST";
      return "";
    }
    if (flag === "--data-binary" && !curlDataBinaryBodyIsPlainText(value)) {
      return "cURL --data-binary imports are only supported for plain text bodies. Use --data-raw for text bodies.";
    }
    if (flag !== "--data-raw" && value.startsWith("@")) {
      return "cURL @file body imports are not supported. Use --data-raw for literal @ bodies.";
    }
    bodyParts.push(value);
    bodyProvided = true;
    if (options.defaultContentType !== false) needsDefaultFormContentType = true;
    if (!getMode && !methodExplicit && (!method || method === "GET")) method = "POST";
    return "";
  };
  const ensureHeader = (name, value) => {
    if (!normalizedHeaders(headers).some((header) => headerNameEquals(header, name))) {
      headers.push({ name, value });
    }
  };
  const addJsonBody = (value) => {
    const raw = String(value ?? "");
    if (raw.startsWith("@")) {
      return "cURL --json @file imports are not supported.";
    }
    const error = addBodyPart("--data-raw", raw, { defaultContentType: false });
    if (error) return error;
    ensureHeader("Content-Type", "application/json");
    ensureHeader("Accept", "application/json");
    return "";
  };
  for (var t = 0; t < tokens.length; t++) {
    const tok = tokens[t];
    if (tok === "-X" || tok === "--request") {
      const value = requireOptionValue(tok);
      if (value.error) return value;
      method = value.value.toUpperCase();
      methodExplicit = true;
    }
    else if (tok.startsWith("-X") && tok.length > 2) {
      method = tok.slice(2).toUpperCase() || "GET";
      methodExplicit = true;
    }
    else if (tok.startsWith("--request=")) {
      method = tok.slice("--request=".length).toUpperCase() || "GET";
      methodExplicit = true;
    }
    else if (tok === "-I" || tok === "--head") {
      method = "HEAD";
      methodExplicit = true;
    }
    else if (tok === "-G" || tok === "--get") {
      getMode = true;
      if (!methodExplicit) method = "GET";
    }
    else if (tok === "--http1.0") {
      httpVersion = "HTTP/1.0";
    }
    else if (tok === "--http1.1") {
      httpVersion = "HTTP/1.1";
    }
    else if (tok === "--http2" || tok === "--http2-prior-knowledge") {
      httpVersion = "HTTP/2";
    }
    else if (tok === "--http3" || tok === "--http3-only") {
      return { error: "cURL HTTP/3 imports are not supported by Replay." };
    }
    else if (tok === "-H" || tok === "--header") {
      const value = requireOptionValue(tok);
      if (value.error) return value;
      const error = addHeader(value.value, tok);
      if (error) return { error };
    }
    else if (tok.startsWith("-H") && tok.length > 2) {
      const error = addHeader(tok.slice(2), "-H");
      if (error) return { error };
    }
    else if (tok.startsWith("--header=")) {
      const error = addHeader(tok.slice("--header=".length), "--header");
      if (error) return { error };
    }
    else if (tok === "-d" || tok === "--data" || tok === "--data-raw" || tok === "--data-binary" || tok === "--data-urlencode") {
      const value = requireOptionValue(tok);
      if (value.error) return value;
      const error = addBodyPart(tok, value.value);
      if (error) return { error };
    }
    else if (tok === "--json") {
      const value = requireOptionValue(tok);
      if (value.error) return value;
      const error = addJsonBody(value.value);
      if (error) return { error };
    }
    else if (tok.startsWith("-d") && tok.length > 2) {
      const error = addBodyPart("-d", tok.slice(2));
      if (error) return { error };
    }
    else if (tok.startsWith("--data=") || tok.startsWith("--data-raw=") || tok.startsWith("--data-binary=") || tok.startsWith("--data-urlencode=")) {
      const flag = tok.slice(0, tok.indexOf("="));
      const error = addBodyPart(flag, tok.slice(tok.indexOf("=") + 1));
      if (error) return { error };
    }
    else if (tok.startsWith("--json=")) {
      const error = addJsonBody(tok.slice("--json=".length));
      if (error) return { error };
    }
    else if (tok === "-F" || tok === "--form" || tok === "--form-string") {
      const value = requireOptionValue(tok);
      if (value.error) return value;
      return { error: "cURL multipart form imports are not supported yet." };
    }
    else if ((tok.startsWith("-F") && tok.length > 2) || tok.startsWith("--form=") || tok.startsWith("--form-string=")) {
      return { error: "cURL multipart form imports are not supported yet." };
    }
    else if (tok === "-u" || tok === "--user") {
      const value = requireOptionValue(tok);
      if (value.error) return value;
      headers.push({ name: "Authorization", value: `Basic ${safeEncodeBase64(value.value)}` });
    }
    else if (tok.startsWith("-u") && tok.length > 2) {
      const cred = tok.slice(2);
      headers.push({ name: "Authorization", value: `Basic ${safeEncodeBase64(cred)}` });
    }
    else if (tok.startsWith("--user=")) {
      const cred = tok.slice("--user=".length);
      headers.push({ name: "Authorization", value: `Basic ${safeEncodeBase64(cred)}` });
    }
    else if (tok === "-A" || tok === "--user-agent") {
      const value = requireOptionValue(tok);
      if (value.error) return value;
      headers.push({ name: "User-Agent", value: value.value });
    }
    else if (tok.startsWith("-A") && tok.length > 2) {
      headers.push({ name: "User-Agent", value: tok.slice(2) });
    }
    else if (tok.startsWith("--user-agent=")) {
      headers.push({ name: "User-Agent", value: tok.slice("--user-agent=".length) });
    }
    else if (tok === "-e" || tok === "--referer") {
      const value = requireOptionValue(tok);
      if (value.error) return value;
      headers.push({ name: "Referer", value: value.value });
    }
    else if (tok.startsWith("-e") && tok.length > 2) {
      headers.push({ name: "Referer", value: tok.slice(2) });
    }
    else if (tok.startsWith("--referer=")) {
      headers.push({ name: "Referer", value: tok.slice("--referer=".length) });
    }
    else if (tok === "-b" || tok === "--cookie") {
      const value = requireOptionValue(tok);
      if (value.error) return value;
      headers.push({ name: "Cookie", value: value.value });
    }
    else if (tok.startsWith("-b") && tok.length > 2) {
      headers.push({ name: "Cookie", value: tok.slice(2) });
    }
    else if (tok.startsWith("--cookie=")) {
      headers.push({ name: "Cookie", value: tok.slice("--cookie=".length) });
    }
    else if (tok === "--url") {
      const value = requireOptionValue(tok);
      if (value.error) return value;
      url = value.value;
    }
    else if (tok.startsWith("--url=")) {
      url = tok.slice("--url=".length);
    }
    else if (tok === "--path-as-is") {
      pathAsIs = true;
    }
    else if (tok === "--compressed" || tok === "-k" || tok === "--insecure" || tok === "-s" || tok === "--silent" || tok === "-v" || tok === "--verbose" || tok === "-L" || tok === "--location") { /* skip flags */ }
    else if (curlShortOptionsWithValue.has(tok) || curlOptionsWithValue.has(tok)) {
      const value = requireOptionValue(tok);
      if (value.error) return value;
    }
    else if (/^--[^=]+=.*/.test(tok) && curlOptionsWithValue.has(tok.slice(0, tok.indexOf("=")))) { /* skip option=value */ }
    else if (!tok.startsWith("-") && !url) { url = tok; }
  }
  if (!url) return null;
  if (getMode && !methodExplicit) {
    method = "GET";
  }
  if (!HTTP_METHOD_TOKEN_RE.test(method)) {
    return { error: "Invalid HTTP method in cURL command." };
  }
  let body = bodyParts.join("&");
  if (getMode && body) {
    url = appendCurlGetQuery(url, body);
    body = "";
    bodyProvided = false;
  }
  let scheme = "https";
  let host = "";
  let port = "";
  let path = "/";
  try {
    const parsed = new URL(url);
    scheme = parsed.protocol.replace(":", "");
    if (scheme !== "http" && scheme !== "https") {
      return { error: "cURL import requires an http:// or https:// URL." };
    }
    host = parsed.host;
    port = parsed.port || defaultHttpPortForScheme(scheme);
    path = pathAsIs ? rawPathFromUrlString(url) : `${parsed.pathname || "/"}${parsed.search || ""}`;
  } catch (_) { return null; }
  if (needsDefaultFormContentType && !getMode) {
    ensureHeader("Content-Type", "application/x-www-form-urlencoded");
  }
  const hasHost = normalizedHeaders(headers).some((h) => headerNameEquals(h, "host"));
  if (!hasHost) headers.unshift({ name: "Host", value: host });
  const headerText = headers.map((h) => `${h.name}: ${h.value}`).join("\n");
  const requestHttpVersion = httpVersion || "HTTP/1.1";
  const requestText = bodyProvided ? `${method} ${path} ${requestHttpVersion}\n${headerText}\n\n${body}` : `${method} ${path} ${requestHttpVersion}\n${headerText}`;
  return { scheme, host, port, method, path, headers, body, httpVersion, requestText };
}

function curlDataBinaryBodyIsPlainText(value) {
  const text = String(value ?? "");
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code === 0x09 || code === 0x0a || code === 0x0d) continue;
    if (code < 0x20) return false;
  }
  return true;
}

function appendCurlGetQuery(url, query) {
  const input = String(url || "");
  const hashIndex = input.indexOf("#");
  const head = hashIndex >= 0 ? input.slice(0, hashIndex) : input;
  const fragment = hashIndex >= 0 ? input.slice(hashIndex) : "";
  return `${head}${head.includes("?") ? "&" : "?"}${query}${fragment}`;
}

function encodeCurlDataUrlencode(value) {
  const raw = String(value ?? "");
  if (raw.startsWith("@") || (!raw.includes("=") && /^[^@=]+@/.test(raw))) {
    return { error: "cURL --data-urlencode @file imports are not supported." };
  }
  const formEncode = (part) => encodeURIComponent(part).replace(/%20/g, "+");
  const eq = raw.indexOf("=");
  if (eq > 0) {
    return { value: `${raw.slice(0, eq)}=${formEncode(raw.slice(eq + 1))}` };
  }
  if (eq === 0) {
    return { value: formEncode(raw.slice(1)) };
  }
  return { value: formEncode(raw) };
}

function rawPathFromUrlString(url) {
  const input = String(url || "");
  const schemeIndex = input.indexOf("://");
  if (schemeIndex < 0) return "";
  const authorityStart = schemeIndex + 3;
  let pathStart = input.length;
  for (const marker of ["/", "?", "#"]) {
    const index = input.indexOf(marker, authorityStart);
    if (index >= 0 && index < pathStart) pathStart = index;
  }
  const raw = pathStart < input.length ? input.slice(pathStart) : "/";
  const hashIndex = raw.indexOf("#");
  const withoutHash = hashIndex >= 0 ? raw.slice(0, hashIndex) : raw;
  if (withoutHash.startsWith("?")) return `/${withoutHash}`;
  return withoutHash || "/";
}

function splitShellWords(input) {
  const tokens = [];
  let token = "";
  let quote = null;
  let active = false;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (quote === "'") {
      if (ch === "'") quote = null;
      else { token += ch; active = true; }
      continue;
    }
    if (quote === '"') {
      if (ch === '"') {
        quote = null;
      } else if (ch === "\\" && i + 1 < input.length) {
        token += input[++i];
        active = true;
      } else {
        token += ch;
        active = true;
      }
      continue;
    }
    if (quote === "$'") {
      if (ch === "'") {
        quote = null;
      } else if (ch === "\\" && i + 1 < input.length) {
        const decoded = decodeAnsiCStringEscape(input, i + 1);
        token += decoded.value;
        i = decoded.index;
        active = true;
      } else {
        token += ch;
        active = true;
      }
      continue;
    }

    if (/\s/.test(ch)) {
      if (active || token.length) tokens.push(token);
      token = "";
      active = false;
      continue;
    }
    if (ch === "$" && input[i + 1] === "'") {
      quote = "$'";
      active = true;
      i += 1;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      active = true;
      continue;
    }
    if (ch === "\\" && i + 1 < input.length) {
      token += input[++i];
      active = true;
      continue;
    }
    token += ch;
    active = true;
  }

  if (quote) return [];
  if (active || token.length) tokens.push(token);
  return tokens;
}

function decodeAnsiCStringEscape(input, index) {
  const ch = input[index] || "";
  const simple = {
    a: "\x07",
    b: "\b",
    e: "\x1b",
    E: "\x1b",
    f: "\f",
    n: "\n",
    r: "\r",
    t: "\t",
    v: "\v",
    "\\": "\\",
    "'": "'",
    "\"": "\"",
    "?": "?",
  };
  if (Object.prototype.hasOwnProperty.call(simple, ch)) {
    return { value: simple[ch], index };
  }
  if (ch === "x") {
    const hex = input.slice(index + 1).match(/^[0-9a-fA-F]{1,2}/)?.[0] || "";
    if (hex) {
      return { value: String.fromCharCode(parseInt(hex, 16)), index: index + hex.length };
    }
  }
  if (ch === "u") {
    const hex = input.slice(index + 1, index + 5);
    if (/^[0-9a-fA-F]{4}$/.test(hex)) {
      return { value: String.fromCharCode(parseInt(hex, 16)), index: index + 4 };
    }
  }
  if (ch === "U") {
    const hex = input.slice(index + 1, index + 9);
    if (/^[0-9a-fA-F]{8}$/.test(hex)) {
      const codePoint = parseInt(hex, 16);
      if (codePoint <= 0x10ffff) {
        return { value: String.fromCodePoint(codePoint), index: index + 8 };
      }
    }
  }
  if (/^[0-7]$/.test(ch)) {
    const octal = input.slice(index, index + 3).match(/^[0-7]{1,3}/)?.[0] || ch;
    return { value: String.fromCharCode(parseInt(octal, 8)), index: index + octal.length - 1 };
  }
  return { value: ch, index };
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
  if (!result) {
    showToast("Could not parse cURL command", "error");
    return;
  }
  if (result.error) {
    showToast(result.error, "error");
    return;
  }
  const tab = createReplayTab();
  tab.httpVersionMode = normalizeReplayHttpVersion(result.httpVersion || "");
  const target = normalizeRepeaterTargetInput(result.host, result.port || "", result.scheme || "https");
  tab.requestText = result.requestText;
  tab.targetScheme = result.scheme;
  tab.targetHost = target.host;
  tab.targetPort = target.port;
  tab.targetManuallyEdited = hostHeaderDiffersFromUrl(
    headerValue(result.headers, "host") || result.host,
    buildUrlFromTarget(result.scheme, target.host, target.port, result.path),
  );
  tab.baseRequest = {
    scheme: result.scheme,
    host: result.host,
    method: result.method,
    path: result.path,
    http_version: normalizeReplayHttpVersion(result.httpVersion || "") || undefined,
    headers: normalizedHeaders(result.headers),
    body: result.body,
    body_encoding: "utf8",
    preview_truncated: false,
  };
  state.replayTabs.push(tab);
  state.activeReplayTabId = tab.id;
  setActiveTool("replay");
  closeCurlImportModal();
  scheduleWorkspaceStateSave();
  renderToolPanels();
}

function initReplayContextMenu() {
  // Method buttons
  getReplayContextMenu().querySelectorAll(".method-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const tabId = replayContextMenuTabId;
      if (tabId) {
        changeReplayMethod(btn.dataset.method, tabId);
      }
      closeReplayContextMenu();
    });
  });

  // Action buttons
  getReplayContextMenu().querySelectorAll("[data-replay-action]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const action = btn.dataset.replayAction;
      const tabId = replayContextMenuTabId;
      const tab = getReplayTabById(tabId);
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
        clearReplayResponseForDraftChange(tab);
        syncReplayRequestEditorForTab(tab);
        scheduleWorkspaceStateSave();
      } else if (action === "add-content-type-json") {
        setReplayHeader("Content-Type", "application/json", tab.id);
      } else if (action === "add-content-type-form") {
        setReplayHeader("Content-Type", "application/x-www-form-urlencoded", tab.id);
      } else if (action === "copy-url") {
        copyReplayUrl(tab);
      } else if (action === "copy-as-curl" || action === "copy-as-python" || action === "copy-as-fetch" || action === "copy-as-powershell") {
        const format = action.replace("copy-as-", "");
        const text = replayRequestToFormat(format, tab);
        if (text) {
          copyTextToClipboard(text).then(() => showToast(`Copied as ${format}`)).catch(() => {});
        }
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

function setReplayHeader(name, value, tabId = state.activeReplayTabId) {
  const tab = getReplayTabById(tabId);
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
  clearReplayResponseForDraftChange(tab);
  syncReplayRequestEditorForTab(tab);
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
    tabSize: "2",
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
    backgroundColor: "rgba(255, 255, 255, 0.07)",
    outline: "1px solid rgba(255, 255, 255, 0.12)",
    outlineOffset: "-1px",
    borderRadius: "2px",
  },
  "&:not(.cm-focused) .cm-activeLine": {
    backgroundColor: "transparent",
    outline: "none",
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
  /* ── HTTP syntax highlight tokens (scoped via CM theme for WKWebView) ── */
  ".tok-method":       { color: "var(--token-method-color, #73c991)" },
  ".tok-target":       { color: "var(--token-target-color, #e0e4ea)" },
  ".tok-url":          { color: "var(--token-url-color, #6cb6d9)" },
  ".tok-version":      { color: "var(--token-version-color, #808898)" },
  ".tok-header":       { color: "var(--token-info-color, #c9a96e)" },
  ".tok-status":       { color: "var(--token-info-color, #c9a96e)", fontWeight: "700" },
  ".tok-status-ok":    { color: "var(--success, #73c991)", fontWeight: "700" },
  ".tok-status-info":  { color: "var(--info, #6cb6d9)", fontWeight: "700" },
  ".tok-status-warn":  { color: "var(--warning, #e0a050)", fontWeight: "700" },
  ".tok-status-error": { color: "var(--danger, #f87171)", fontWeight: "700" },
  ".tok-plain":        { color: "var(--token-plain-color, #cdd2da)" },
  ".tok-punct":        { color: "var(--token-plain-color, #cdd2da)" },
  ".tok-cookie-name":  { color: "#e06c88" },
  ".tok-cookie-val":   { color: "var(--text-soft, #aab0bc)" },
  ".tok-cookie-sep":   { color: "#6cb6d9" },
  ".tok-cookie-flag":  { color: "#7cb8a0" },
  ".tok-json-key":     { color: "var(--token-info-color, #c9a96e)" },
  ".tok-json-str":     { color: "var(--token-string-color, #e8e8e8)" },
  ".tok-json-num":     { color: "var(--warning, #e0a050)" },
  ".tok-json-bool":    { color: "#b89f7c" },
  ".tok-query-key":    { color: "var(--token-info-color, #c9a96e)" },
  ".tok-query-val":    { color: "var(--token-query-value-color, #e8e8e8)" },
  ".tok-markup-tag":   { color: "var(--token-info-color, #c9a96e)" },
  ".tok-markup-attr":  { color: "var(--token-info-color, #c9a96e)" },
  ".tok-markup-str":   { color: "var(--token-string-color, #e8e8e8)" },
  ".tok-markup-meta":  { color: "#b89f7c" },
  ".tok-meta":         { color: "#b89f7c" },
  ".tok-kw":           { color: "var(--token-info-color, #c9a96e)" },
  /* ── Hex view tokens ── */
  ".tok-hex-offset":   { color: "var(--token-info-color, #c9a96e)", display: "inline-block", width: "70px", paddingRight: "12px", overflow: "hidden", verticalAlign: "top", whiteSpace: "pre", fontFamily: "'Menlo', 'Monaco', 'Cascadia Mono', 'Courier New', monospace", fontSize: "11px" },
  ".tok-hex-bytes":    { color: "var(--token-string-color, #e8e8e8)", display: "inline-block", width: "355px", paddingRight: "8px", overflow: "hidden", verticalAlign: "top", whiteSpace: "pre", fontFamily: "'Menlo', 'Monaco', 'Cascadia Mono', 'Courier New', monospace", fontSize: "11px" },
  ".tok-hex-ascii":    { color: "var(--token-plain-color, #cdd2da)", fontFamily: "'Menlo', 'Monaco', 'Cascadia Mono', 'Courier New', monospace", fontSize: "11px" },
  /* ── Diff view tokens ── */
  ".tok-diff-added":   { color: "var(--success, #50c878)", background: "rgba(80, 200, 120, 0.12)" },
  ".tok-diff-removed": { color: "var(--danger, #e05252)", background: "rgba(200, 80, 80, 0.12)", textDecoration: "line-through" },
  ".tok-diff-header":  { color: "var(--point, #7d91ab)", fontWeight: "600" },
  /* ── Payload placeholder ── */
  ".tok-payload":      { color: "#f8d06b", background: "rgba(248, 208, 107, 0.18)", borderRadius: "3px", padding: "0 2px", fontWeight: "600" },
  /* ── Search highlight ── */
  ".tok-search-hit":   { background: "rgba(132, 151, 173, 0.42)", borderRadius: "4px", padding: "0 1px", boxShadow: "inset 0 0 0 1px rgba(170, 190, 214, 0.72)" },
  ".tok-search-active": { background: "rgba(201, 169, 110, 0.62)", borderRadius: "4px", padding: "0 1px", boxShadow: "inset 0 0 0 1px rgba(232, 201, 141, 0.9)" },
  ".tok-finding-evidence-hit": { color: "#f3e7cc", background: "rgba(201, 169, 110, 0.24)", borderRadius: "3px", padding: "0 2px", fontWeight: "700", boxShadow: "0 0 0 1px rgba(201, 169, 110, 0.44), 0 0 0 1px rgba(0, 0, 0, 0.18)" },
  ".tok-finding-evidence-active": { color: "#fff3cf", background: "rgba(201, 169, 110, 0.34)", borderRadius: "3px", padding: "0 2px", fontWeight: "800", boxShadow: "0 0 0 1px rgba(230, 199, 139, 0.58), 0 0 8px rgba(201, 169, 110, 0.12)" },
}, { dark: true });

// ─── HTTP decoration plugin ─────────────────────────────────────────────────
//
// Reuses the existing highlight* functions (highlightStartLine, highlightHeaderLine,
// highlightBodyLine, highlightCookieValue) to produce CM Decoration.mark() spans
// with the same CSS classes as the legacy <pre> renderer.  This ensures pixel-perfect
// colour parity with the non-CM code path.

/** Map legacy CSS class → CM-scoped tok-* class. */
const _tokMap = {
  "token-method": "tok-method",
  "token-target": "tok-target",
  "token-url": "tok-url",
  "token-version": "tok-version",
  "token-header": "tok-header",
  "token-plain": "tok-plain",
  "token-punctuation": "tok-punct",
  "token-cookie-name": "tok-cookie-name",
  "token-cookie-value": "tok-cookie-val",
  "token-cookie-sep": "tok-cookie-sep",
  "token-cookie-flag": "tok-cookie-flag",
  "token-json-key": "tok-json-key",
  "token-json-string": "tok-json-str",
  "token-json-number": "tok-json-num",
  "token-json-boolean": "tok-json-bool",
  "token-meta": "tok-meta",
  "token-query-key": "tok-query-key",
  "token-query-value": "tok-query-val",
  "token-markup-tag": "tok-markup-tag",
  "token-markup-attr": "tok-markup-attr",
  "token-markup-string": "tok-markup-str",
  "token-markup-meta": "tok-markup-meta",
  "token-js-keyword": "tok-kw",
  "token-js-string": "tok-json-str",
  "token-css-property": "tok-kw",
  "token-css-selector": "tok-kw",
  "token-css-keyword": "tok-kw",
  "token-css-value": "tok-json-str",
  "token-hex-offset": "tok-header",
  "token-hex-bytes": "tok-json-str",
  "token-hex-ascii": "tok-plain",
  "token-string": "tok-json-str",
};

function mapTokenClass(legacyCls) {
  // Handle compound status classes like "token-status ok"
  if (legacyCls.startsWith("token-status")) {
    const tone = legacyCls.replace("token-status", "").trim();
    if (tone === "ok") return "tok-status-ok";
    if (tone === "info") return "tok-status-info";
    if (tone === "warn") return "tok-status-warn";
    if (tone === "error") return "tok-status-error";
    return "tok-status";
  }
  return _tokMap[legacyCls] || "";
}

/** Parse an HTML-highlighted line into [{cls, start, end}] token ranges. */
function extractTokenRanges(htmlStr, plainText) {
  const ranges = [];
  const tagRe = /<span class="([^"]+)">([^<]*)<\/span>/g;
  let m;
  let searchFrom = 0;
  while ((m = tagRe.exec(htmlStr)) !== null) {
    const cls = mapTokenClass(m[1]);
    if (!cls) continue;
    const text = m[2].replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&#39;/g, "'").replace(/&quot;/g, '"');
    if (!text) continue;
    const idx = plainText.indexOf(text, searchFrom);
    if (idx === -1) continue;
    ranges.push({ cls, from: idx, to: idx + text.length });
    searchFrom = idx + text.length;
  }
  return ranges;
}

/** Build a RangeSet<Decoration> for an HTTP message document. */
function buildHttpDecorations(view) {
  const doc = view.state.doc;
  const text = doc.toString();
  if (!text) return CM.Decoration.none;

  const lines = text.split("\n");
  const builder = [];

  // Determine where blank separator line is (end of headers)
  let blankIdx = -1;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i] === "") { blankIdx = i; break; }
  }

  // Detect body highlight mode from Content-Type header
  let bodyMode = "plain";
  for (let i = 1; i < (blankIdx === -1 ? lines.length : blankIdx); i++) {
    const lower = lines[i].toLowerCase();
    if (lower.startsWith("content-type:")) {
      bodyMode = inferBodyHighlightMode(lines[i].slice(13).trim());
      break;
    }
  }

  // Detect request vs response from first line
  const isResponse = /^HTTP\/[\d.]+\s/.test(lines[0]);
  const target = isResponse ? "response" : "request";

  let offset = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineStart = offset;
    offset += line.length + 1; // +1 for \n

    if (!line) continue;

    let highlighted;
    if (i === 0) {
      highlighted = highlightStartLine(line, target);
    } else if (blankIdx === -1 || i < blankIdx) {
      highlighted = highlightHeaderLine(line);
    } else if (i > blankIdx) {
      highlighted = highlightBodyLine(line, bodyMode);
    } else {
      continue; // blank line
    }

    const ranges = extractTokenRanges(highlighted, line);
    for (const r of ranges) {
      const from = lineStart + r.from;
      const to = lineStart + r.to;
      if (from >= to || to > doc.length) continue;
      builder.push(CM.Decoration.mark({ class: r.cls }).range(from, to));
    }
  }

  // Sort by from position (required by RangeSet)
  builder.sort((a, b) => a.from - b.from || a.to - b.to);
  return CM.Decoration.set(builder);
}

const httpDecoPlugin = CM.ViewPlugin.fromClass(
  class {
    constructor(view) { this.decorations = buildHttpDecorations(view); }
    update(update) {
      if (update.docChanged || update.startState.facet !== update.state.facet) {
        this.decorations = buildHttpDecorations(update.view);
      }
    }
  },
  { decorations: (v) => v.decorations },
);

/** Build decorations for hex dump (offset / bytes / ascii columns). */
function buildHexDecorations(view) {
  const doc = view.state.doc;
  const text = doc.toString();
  if (!text) return CM.Decoration.none;
  const builder = [];
  let offset = 0;
  for (const line of text.split("\n")) {
    if (line.length >= 10) {
      // offset column: "00000000" (8 chars), same as non-CM .hex-col-offset
      builder.push(CM.Decoration.mark({ class: "tok-hex-offset" }).range(offset, offset + 8));
      if (line.length > 10) {
        // bytes column: chars 10-58 (49 chars of hex pairs), same as non-CM .hex-col-bytes
        const hEnd = Math.min(59, line.length);
        builder.push(CM.Decoration.mark({ class: "tok-hex-bytes" }).range(offset + 10, offset + hEnd));
      }
      if (line.length > 60) {
        // ascii column: rest of line
        builder.push(CM.Decoration.mark({ class: "tok-hex-ascii" }).range(offset + 60, offset + line.length));
      }
    }
    offset += line.length + 1;
  }
  return CM.Decoration.set(builder);
}

const hexDecoPlugin = CM.ViewPlugin.fromClass(
  class {
    constructor(view) { this.decorations = buildHexDecorations(view); }
    update(update) {
      if (update.docChanged) this.decorations = buildHexDecorations(update.view);
    }
  },
  { decorations: (v) => v.decorations },
);

/** Build decorations for diff view (+/- lines). */
function buildDiffDecorations(view) {
  const doc = view.state.doc;
  const text = doc.toString();
  if (!text) return CM.Decoration.none;
  const builder = [];
  let offset = 0;
  for (const line of text.split("\n")) {
    if (line.length > 0) {
      let cls = "";
      if (line.startsWith("--- ") || line.startsWith("+++ ")) cls = "tok-diff-header";
      else if (line.startsWith("+ ")) cls = "tok-diff-added";
      else if (line.startsWith("- ")) cls = "tok-diff-removed";
      if (cls) builder.push(CM.Decoration.mark({ class: cls }).range(offset, offset + line.length));
    }
    offset += line.length + 1;
  }
  return CM.Decoration.set(builder);
}

const diffDecoPlugin = CM.ViewPlugin.fromClass(
  class {
    constructor(view) { this.decorations = buildDiffDecorations(view); }
    update(update) {
      if (update.docChanged) this.decorations = buildDiffDecorations(update.view);
    }
  },
  { decorations: (v) => v.decorations },
);

// ─── Payload marker decoration plugin ($payload$) ────────
function buildPayloadDecorations(view) {
  const doc = view.state.doc;
  const text = doc.toString();
  if (!text) return CM.Decoration.none;
  const re = /\$payload\$/gi;
  const builder = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    builder.push(CM.Decoration.mark({ class: "tok-payload" }).range(m.index, m.index + m[0].length));
  }
  return builder.length ? CM.Decoration.set(builder) : CM.Decoration.none;
}

const payloadDecoPlugin = CM.ViewPlugin.fromClass(
  class {
    constructor(view) { this.decorations = buildPayloadDecorations(view); }
    update(update) {
      if (update.docChanged) this.decorations = buildPayloadDecorations(update.view);
    }
  },
  { decorations: (v) => v.decorations },
);

const cmProgrammaticViews = new WeakSet();

/** Add an update listener to a CM EditorView; returns a dispose function. */
function addCMUpdateListener(view, callback) {
  const listener = CM.EditorView.updateListener.of((update) => {
    if (update.docChanged && !cmProgrammaticViews.has(update.view)) {
      callback(update.state.doc.toString());
    }
  });
  view.dispatch({ effects: CM.StateEffect.appendConfig.of(listener) });
  return () => {}; // CM does not support removing extensions, but the view will be destroyed
}

const CM_SEARCH_DECORATION_LIMIT = 5000;
const CM_DEFAULT_SEARCH_CLASSES = Object.freeze({
  hit: "tok-search-hit",
  active: "tok-search-active",
});

function normalizeSearchClasses(classes) {
  return {
    hit: classes?.hit || CM_DEFAULT_SEARCH_CLASSES.hit,
    active: classes?.active || CM_DEFAULT_SEARCH_CLASSES.active,
  };
}

function normalizeSearchEffectValue(value) {
  if (value && typeof value === "object") {
    return {
      query: String(value.query || ""),
      classes: normalizeSearchClasses(value.classes),
    };
  }
  return {
    query: String(value || ""),
    classes: CM_DEFAULT_SEARCH_CLASSES,
  };
}

/** Build search highlight decorations. Returns { decos, matchCount, matchPositions }. */
function buildSearchDecorations(doc, query, activeIndex = -1, classes = CM_DEFAULT_SEARCH_CLASSES) {
  const searchClasses = normalizeSearchClasses(classes);
  if (!query) {
    return {
      query: "",
      activeIndex: -1,
      classes: searchClasses,
      decos: CM.Decoration.none,
      matchCount: 0,
      matchPositions: [],
    };
  }
  const text = doc.toString();
  const lower = text.toLowerCase();
  const lq = query.toLowerCase();
  const builder = [];
  const positions = [];
  let matchCount = 0;
  let pos = 0;
  while ((pos = lower.indexOf(lq, pos)) !== -1) {
    const matchIndex = matchCount;
    if (positions.length < CM_SEARCH_DECORATION_LIMIT) {
      positions.push(pos);
    }
    if (matchIndex < CM_SEARCH_DECORATION_LIMIT) {
      const cls = matchIndex === activeIndex ? searchClasses.active : searchClasses.hit;
      builder.push(CM.Decoration.mark({ class: cls }).range(pos, pos + lq.length));
    }
    matchCount += 1;
    pos += 1;
  }
  const safeActiveIndex = activeIndex >= 0 && activeIndex < positions.length ? activeIndex : -1;
  return {
    query,
    activeIndex: safeActiveIndex,
    classes: searchClasses,
    decos: CM.Decoration.set(builder),
    matchCount,
    matchPositions: positions,
  };
}

function createBaseExtensions(options = {}) {
  const exts = [
    sniperCMTheme,
    CM.EditorState.tabSize.of(2),
    CM.lineNumbers(),
    CM.highlightSpecialChars(),
    CM.drawSelection(),
    CM.highlightSelectionMatches(),
  ];
  // Hex mode: no line wrapping for column alignment
  if (!options.hexHighlight) {
    exts.push(CM.EditorView.lineWrapping);
  }
  if (options.readOnly) {
    exts.push(CM.EditorState.readOnly.of(true));
    // Keep editable:true so text selection and native copy work.
    // readOnly prevents actual edits while allowing cursor placement.
    // Cmd+C with no selection → copy current line
    exts.push(CM.keymap.of([{
      key: "Mod-c",
      run(view) {
        const sel = view.state.selection.main;
        if (sel.from !== sel.to) return false; // has selection → let native copy handle it
        const line = view.state.doc.lineAt(sel.head);
        navigator.clipboard.writeText(line.text).catch(() => {});
        return true;
      },
    }]));
  } else {
    exts.push(CM.history());
    exts.push(CM.keymap.of([...CM.defaultKeymap, ...CM.historyKeymap]));
  }
  if (options.placeholder) {
    exts.push(CM.placeholder(options.placeholder));
  }
  if (options.httpHighlight) exts.push(httpDecoPlugin);
  if (options.hexHighlight) {
    exts.push(hexDecoPlugin);
    // Match non-CM hex font exactly
    exts.push(CM.EditorView.theme({
      ".cm-content": { fontFamily: "'Menlo', 'Monaco', 'Cascadia Mono', 'Courier New', monospace", fontSize: "11px", lineHeight: "1.48" },
      ".cm-line": { fontFamily: "'Menlo', 'Monaco', 'Cascadia Mono', 'Courier New', monospace", fontSize: "11px" },
    }));
  }
  if (options.diffHighlight) exts.push(diffDecoPlugin);
  if (options.payloadHighlight) exts.push(payloadDecoPlugin);
  return exts;
}

// Search decoration effect & field
const setSearchQuery = CM.StateEffect.define();
const setSearchActiveIndex = CM.StateEffect.define();
const searchDecoField = CM.StateField.define({
  create() {
    return {
      query: "",
      activeIndex: -1,
      classes: CM_DEFAULT_SEARCH_CLASSES,
      decos: CM.Decoration.none,
      matchCount: 0,
      matchPositions: [],
    };
  },
  update(value, tr) {
    for (const e of tr.effects) {
      if (e.is(setSearchQuery)) {
        const config = normalizeSearchEffectValue(e.value);
        return buildSearchDecorations(tr.state.doc, config.query, -1, config.classes);
      }
      if (e.is(setSearchActiveIndex)) {
        return buildSearchDecorations(tr.state.doc, value.query, e.value, value.classes);
      }
    }
    if (tr.docChanged && value.query) {
      return buildSearchDecorations(tr.state.doc, value.query, value.activeIndex, value.classes);
    }
    return value;
  },
  provide: (f) => CM.EditorView.decorations.from(f, (val) => val.decos),
});

/** Reusable CodeMirror wrapper for Sniper code views. */
class SniperCodeView {
  constructor(container, options = {}) {
    this._options = options;
    this._searchNavIndex = -1;
    this.view = new CM.EditorView({
      state: CM.EditorState.create({
        doc: "",
        extensions: [...createBaseExtensions(options), searchDecoField],
      }),
      parent: container,
    });
  }

  setContent(text) {
    const { view } = this;
    const nextText = text || "";
    if (view.state.doc.toString() === nextText) {
      return;
    }
    cmProgrammaticViews.add(view);
    try {
      view.dispatch({
        changes: { from: 0, to: view.state.doc.length, insert: nextText },
      });
    } finally {
      cmProgrammaticViews.delete(view);
    }
  }

  setContentPreservingSelection(text) {
    const { view } = this;
    const nextText = text || "";
    if (view.state.doc.toString() === nextText) {
      return;
    }
    const selection = view.state.selection.main;
    const anchor = Math.min(selection.anchor, nextText.length);
    const head = Math.min(selection.head, nextText.length);
    cmProgrammaticViews.add(view);
    try {
      view.dispatch({
        changes: { from: 0, to: view.state.doc.length, insert: nextText },
        selection: { anchor, head },
      });
    } finally {
      cmProgrammaticViews.delete(view);
    }
  }

  /** Apply search highlights and return match info. */
  applySearch(query, options = {}) {
    this._searchNavIndex = -1;
    this.view.dispatch({
      effects: setSearchQuery.of({
        query: query || "",
        classes: normalizeSearchClasses(options.classes),
      }),
    });
    const field = this.view.state.field(searchDecoField);
    // Scroll to first match
    if (options.scrollToFirst !== false && field.matchPositions.length > 0) {
      const pos = field.matchPositions[0];
      this.view.dispatch({ selection: { anchor: pos }, scrollIntoView: true });
    }
    return field;
  }

  /** Navigate to next search match (cyclic). Returns current index or -1. */
  nextSearchMatch() {
    const field = this.view.state.field(searchDecoField);
    if (!field.matchPositions.length) return -1;
    this._searchNavIndex = (this._searchNavIndex + 1) % field.matchPositions.length;
    const pos = field.matchPositions[this._searchNavIndex];
    this.view.dispatch({
      effects: setSearchActiveIndex.of(this._searchNavIndex),
      selection: { anchor: pos, head: pos + field.query.length },
      scrollIntoView: true,
    });
    return this._searchNavIndex;
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

/** Hook CM search navigation onto a search-meta element. */
function initCMSearchNavigation(metaElement, cmKey) {
  if (!metaElement) return;
  metaElement.addEventListener("click", (e) => {
    if (!e.target.closest(".search-hit-count")) return;
    const cv = _cmViews[cmKey];
    if (!cv) return;
    cv.nextSearchMatch();
  });
}

function updateCodePaneCM(key, container, text, options = {}) {
  const mode = options.mode || "http"; // "http" | "hex" | "diff"
  const editable = options.readOnly === false;
  // Recreate CM view if highlight mode or editable changed
  if (_cmViews[key] && (_cmViews[key]._hlMode !== mode || !!_cmViews[key]._editable !== editable)) {
    _cmViews[key].destroy();
    delete _cmViews[key];
  }
  if (!_cmViews[key]) {
    const cmOpts = {};
    cmOpts.readOnly = !editable;
    if (mode === "http") cmOpts.httpHighlight = true;
    else if (mode === "hex") cmOpts.hexHighlight = true;
    else if (mode === "diff") cmOpts.diffHighlight = true;
    if (options.placeholder) cmOpts.placeholder = options.placeholder;
    if (options.payloadHighlight) cmOpts.payloadHighlight = true;
    _cmViews[key] = new SniperCodeView(container, cmOpts);
    _cmViews[key]._hlMode = mode;
    _cmViews[key]._editable = editable;
  }
  const cv = _cmViews[key];
  if (editable && options.onChange && !cv._onChangeWired) {
    cv._onChangeDispose = addCMUpdateListener(cv.view, options.onChange);
    cv._onChangeWired = true;
  }
  cv.setContent(text || "");

  // Search highlights
  const query = (options.search || "").trim();
  const searchResult = cv.applySearch(query, { classes: options.searchClasses });

  const lineCount = cv.view.state.doc.lines;
  return {
    lineCount,
    matchCount: searchResult.matchCount,
    matchPositions: searchResult.matchPositions || [],
  };
}

/** Helper: get a CM view from the managed pool by key. */
function getCMView(key) {
  return _cmViews[key] || null;
}

init().catch((error) => {
  console.error(error);
  els.historyMeta.textContent = "Failed to load Sniper.";
  els.liveStatus.textContent = "Error";
  els.liveStatus.classList.remove("online");
});
