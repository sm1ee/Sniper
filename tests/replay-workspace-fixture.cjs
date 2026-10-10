// Synthetic saved workspace only. No app startup, server, request execution or
// live connection is used; the adoption/save logic is extracted from app.js.
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");
const plain = value => JSON.parse(JSON.stringify(value));
const functions = [
  "adoptExternalReplayTabs", "replayTabHasUncommittedEditorState", "adoptExternalReplayResult",
  "adoptExternalReplayLabel", "adoptExternalReplayRequest", "replayTabRequestShape",
  "snapshotHttpReplayTab", "snapshotWorkspaceState", "workspaceReplayTabsById", "workspaceSnapshotValueChanged",
  "cloneWorkspaceSnapshotForBaseline", "hydrateReplayTab", "hydrateRepeaterHistoryEntry", "normalizeReplayTabCustomLabel",
  "normalizeReplayHttpVersion", "normalizeReplayHttpVersionMode", "replayHttpVersionFromText", "replayHttpVersionState",
  "replayLegacyHttpVersionState", "replayStoredHttpVersionMode", "normalizeRepeaterHistoryIndex",
  "normalizePortValue", "normalizeRepeaterTargetInput", "authorityToTargetState", "stripIpv6Brackets", "defaultHttpPortForScheme",
  "cloneEditableRequest", "normalizedHeaders", "cloneTransactionRecord", "createDefaultEditableRequest",
  "buildEditableRawRequest", "mergeHeaders", "headerNameEquals", "replayRequestTextsEquivalent",
  "getRepeaterTargetConfig", "getActiveReplayTab", "getReplayTabVisualOrder", "isReplayTabSending", "sessionQueryPath",
  "createReplayTab", "ensureRepeaterTab", "currentSessionId", "workspaceSnapshotMatchesActiveSession",
  "closeRepeaterTab", "preserveActiveHttpReplayDraftBeforeNavigation", "validateManualRepeaterTargetInput", "isLikelyIpv6Literal",
  "persistReplayTabMetadataEdit",
  "snapshotReplayTabsState", "cloneReplayTabState", "cloneRepeaterHistoryEntry", "restoreReplayTabsState",
  "scheduleWorkspaceStateSave", "flushQueuedWorkspaceStateSave", "runQueuedWorkspaceStateSaves", "saveWorkspaceState",
  "flushWorkspaceState", "clearBypassableWorkspaceConflict", "isActiveSessionChangedConflict", "isTooManyReplayTabsError",
  "flushWorkspaceStateOnUnload", "requestWorkspaceUnloadPrompt", "workspaceUnloadPayload", "utf8ByteLength",
];
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function fixture() {
  const requests = [], toasts = [], renders = [], beacons = [], timers = new Map();
  const state = {
    activeSession: { id: "session-a" }, workspaceRevision: 10, replayTabs: [], replayTabSequence: 0,
    activeReplayTabId: null, replayRenamingTabId: null, replayMessageViews: { request: "raw" },
    fuzzerRequestText: "GET /local-fuzzer HTTP/1.1", fuzzerPayloadsText: "local", fuzzerNotice: "local notice",
  };
  let uuid = 0, timer = 0, editor = null;
  const els = { replayRequestHighlight: { innerText: "" }, replayRequestEditor: { value: "" },
    replayHostInput: { value: "" }, replayPortInput: { value: "" }, replaySchemeSelect: { value: "https" } };
  const versionSelect = { value: "HTTP/1.1" };
  const document = { activeElement: els.replayRequestHighlight, getElementById: id => id === "replayHttpVersionSelect" ? versionSelect : null };
  const context = loadFunctions(functions, {
    state, els, document, URL, TextEncoder, Blob, Uint8Array,
    workspacePendingReplayCloses: new Map(), workspaceReplayMetadataEdits: new WeakMap(), MAX_REPLAY_TABS: 512,
    workspaceLoaded: true, workspaceStateGeneration: 0, workspaceExternalLoadGeneration: 0, workspaceExternalAppliedGeneration: 0,
    workspaceSaveConflictPending: false, workspaceSaveConflictLatest: null, workspaceSaveCommittedSnapshot: null,
    workspaceClientId: "ui-client", workspaceSaveVersion: 0, workspaceSaveDirty: false, workspaceSaveTimer: null,
    workspaceSaveLastSnapshot: null, workspaceSaveInFlight: false, workspaceSaveLoopPromise: null,
    workspaceTabCapNoticeShown: false, workspaceResponseTrimNoticeShown: false,
    wsTranscriptSaveTimer: null, wsTranscriptFirstDirtyAt: 0, _replaySendControllers: new Map(),
    WORKSPACE_UNLOAD_UNSAVED_MESSAGE: "Unsaved edits", WORKSPACE_UNLOAD_KEEPALIVE_MAX_BYTES: 60000,
    generateUuid: () => `00000000-0000-4000-8000-${String(++uuid).padStart(12, "0")}`,
    clamp: (n, low, high) => Math.min(high, Math.max(low, n)),
    createWsReplaySnapshotBudgetAllocator: () => () => ({ frames: 0, bytes: 0 }),
    expectedActiveSessionIdForWrite: id => id,
    normalizeFuzzerTargetOverride: target => target || null,
    deriveRepeaterRequest: tab => tab.baseRequest,
    getCMView: () => editor,
    boundWorkspaceSnapshotForSave: snapshot => snapshot,
    window: { setTimeout: callback => { timers.set(++timer, callback); return timer; }, clearTimeout: id => timers.delete(id) },
    navigator: { sendBeacon: (url, blob) => { beacons.push({ url, blob }); return true; } },
    syncReplayDraftsBeforeWorkspaceClose() {}, disconnectWsReplayTabsOnUnload() {},
    handleWorkspaceActionError(error) { throw error; },
    showToast: (...args) => toasts.push(args),
    fetch: (url, options) => { const pending = { url, options, ...deferred() }; requests.push(pending); return pending.promise; },
  });
  vm.runInContext(appSource.match(/^class WorkspaceStateConflictError[^]*?^\}/m)[0], context);
  function syncDom() {
    const tab = context.getActiveReplayTab();
    if (!tab || tab.type === "websocket") return;
    if (els.replayRequestHighlight) els.replayRequestHighlight.innerText = tab.requestText;
    els.replayRequestEditor.value = tab.requestText;
    const target = context.getRepeaterTargetConfig(tab);
    els.replayHostInput.value = target.host; els.replayPortInput.value = target.port; els.replaySchemeSelect.value = target.scheme;
    versionSelect.value = context.normalizeReplayHttpVersionMode(tab.httpVersionMode);
  }
  context.renderReplay = options => { renders.push({ kind: "full", options }); context.ensureRepeaterTab(); syncDom(); };
  context.renderReplayTabs = () => renders.push({ kind: "strip" });
  function tab(label, pinned = false) {
    return context.createReplayTab({ customLabel: label, pinned,
      baseRequest: { scheme: "https", host: "example.com", method: "GET", path: `/${label}`, headers: [], body: "", body_encoding: "utf8", preview_truncated: false },
      requestText: `GET /${label} HTTP/1.1\r\nHost: example.com\r\n\r\n`,
    });
  }
  function seed(tabs, active = tabs[0]?.id) {
    state.replayTabs = tabs; state.activeReplayTabId = active || null;
    context.workspaceSaveCommittedSnapshot = plain(context.snapshotWorkspaceState());
    syncDom();
  }
  function remote(tabs = [], revision = 11) {
    return { session_id: state.activeSession.id, revision,
      replay: { tabs: tabs.map(item => item.requestText === undefined ? plain(item) : plain(context.snapshotHttpReplayTab(item))), tab_sequence: state.replayTabSequence, active_tab_id: tabs[0]?.id || null },
      fuzzer: { request_text: "remote fuzzer" },
    };
  }
  const succeed = (index, snapshot) => requests[index].resolve({ ok: true, status: 200, json: async () => plain(snapshot) });
  const adopt = async snapshot => { const index = requests.length; const pending = context.adoptExternalReplayTabs(); if (requests.length > index) succeed(index, snapshot); await pending; };
  return { context, state, els, document, versionSelect, requests, toasts, renders, beacons, timers, tab, seed, remote, succeed, adopt, syncDom,
    setEditor: value => { editor = { getContent: () => value }; }, plain };
}
module.exports = { fixture, functions, plain, deferred };
