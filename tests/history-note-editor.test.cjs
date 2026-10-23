// Offline passive note editing checks. No app startup, API, or captured data.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function noteCell() {
  let html = '<span class="note-text">Saved note</span>';
  let input = null;
  return {
    isConnected: true, dataset: {},
    get innerHTML() { return html; },
    set innerHTML(value) { html = value; input = null; },
    querySelector() { return input; },
    appendChild(value) { input = value; },
    contains(value) { return value === this || value === input; },
  };
}

function eventTarget() {
  const listeners = new Map();
  return {
    listeners,
    addEventListener(type, callback, capture = false) {
      const entries = listeners.get(type) || new Map();
      entries.set(callback, capture);
      listeners.set(type, entries);
    },
    removeEventListener(type, callback, capture = false) {
      const entries = listeners.get(type);
      if (entries?.get(callback) === capture) entries.delete(callback);
      if (!entries?.size) listeners.delete(type);
    },
    dispatch(type, fields = {}) {
      const event = { type, target: this, defaultPrevented: false,
        preventDefault() { this.defaultPrevented = true; }, ...fields };
      for (const callback of Array.from(listeners.get(type)?.keys() || [])) callback(event);
      return event;
    },
  };
}

function modal() {
  const classes = new Set(["hidden"]);
  return { classList: {
    add: (name) => classes.add(name), remove: (name) => classes.delete(name),
    contains: (name) => classes.has(name),
  } };
}

function fixture({ joinAnnotations = false } = {}) {
  const requests = [], inputs = [], saves = [], toasts = [], timers = new Map();
  const historyWrites = [], detailWrites = [];
  const item = { id: "fixture-record", sequence: 1, has_user_note: true, note_preview: "Saved note" };
  const state = {
    activeTool: "proxy", activeProxyTab: "http-history",
    items: [item], _itemById: new Map([[item.id, item]]), _itemsVersion: 0,
    historyPaging: { fullyLoaded: true, total: 1, filteredTotal: 1 },
    historyColumnOrder: ["notes"], filterSettings: {}, sortKey: "index", sortDirection: "desc",
  };
  const shell = { clientHeight: 500, scrollTop: 0 };
  let clientVersion = 0;
  let nextTimer = 0;
  const cell = noteCell();
  const cells = [cell];
  const document = { ...eventTarget(), visibilityState: "visible" };
  const focusable = () => ({
    isConnected: true, tabIndex: 0, getClientRects: () => [{}],
    focus() {
      if (document.activeElement === this) return;
      document.activeElement = this;
      document.dispatch("focusin", { target: this });
    },
  });
  const focusOwner = focusable();
  document.activeElement = focusOwner;
  const functions = [
    "beginNoteEdit", "releaseHistoryNoteEdit", "inheritPendingHistoryNoteEdit", "requireOkResponse", "readApiErrorMessage", "formatStructuredApiErrorMessage",
    "truncateUtf8", "truncateUtf8Preview", "utf8ByteLength",
    "isHttpHistoryVisible", "isModalVisible", "restoreModalFocus",
    "openDisplaySettingsModal", "closeDisplaySettingsModal", "openFilterModal", "closeFilterModal",
    "retireFindingActionProgress", "invalidateFindingNavigation", "setActiveTool", "setActiveProxyTab", "sanitizeActiveTool", "sanitizeActiveProxyTab",
    "openContextMenu", "closeContextMenu", "positionContextMenu", "renderContextMenuNotes",
    "createTransactionRecordMenuTarget", "getHistoryItem",
  ];
  if (joinAnnotations) functions.push(
    "updateAnnotations", "flushPendingAnnotations", "currentHistoryNoteEditWindow", "syncHistoryNoteEditWindow",
    "flushTransactionDeltas", "applyLiveSummaryUpdate", "canMergeRecentTransactions",
    "retainFilteredHistoryNote", "releaseDetachedHistoryNoteEdits", "renderHistory", "getHistoryRowHeight", "renderHistoryVirtual",
    "renderHistoryCell", "escapeHtml", "isSessionEmpty", "historyEmptyMessage",
    "rebuildHistoryItemIndex", "getHistoryItemIndex", "resortLoadedHistoryItemsForCurrentSort",
    "visibleHistoryNoteCount", "compareHistorySequence",
    "createDefaultFilterSettings", "summaryMatchesActiveHistoryFilters", "summaryMatchesStatusFilter",
    "selectedStatusClasses", "summaryMatchesMimeFilter", "selectedMimeTypes", "summaryMatchesHiddenExtensions",
    "extractSummaryPathExtension", "summaryMatchesPortFilter", "summaryMatchesColorTags", "summaryMatchesAdvancedSearch",
    "inferMimeType", "prepareHistoryItem", "formatSize", "getVisibleEntries", "invalidateVisibleEntriesCache",
    "adjustHistoryPagingAfterLocalRemoval", "isKnownCount", "refreshHistoryPagingCursorFromItems",
    "canUseSequenceCursorForHistoryPaging", "createHistoryQueryState", "historyQuerySignature",
    "loadMoreTransactions", "loadNewerTransactions", "isCurrentHistoryQuerySignature", "updateHistoryPagingCursor",
    "mergeHistoryItems", "applyPendingAnnotationsToItems", "jsonArray", "getHistoryItem",
  );
  const context = loadFunctions(functions, {
    session: "fixture-session", MAX_ANNOTATION_NOTE_BYTES: 32 * 1024, TextEncoder,
    closeScannerSettings() {},
    pendingHistoryNoteRead: null,
    IMPLEMENTED_TOOLS: new Set(["proxy", "replay"]),
    IMPLEMENTED_PROXY_TABS: new Set(["http-history", "websockets-history"]),
    compareLoadGeneration: 0, displaySettingsReturnFocus: null, displaySettingsPreviewActive: false, displaySettingsEditedControls: new Set(), filterSettingsReturnFocus: null,
    filterSettingsEditedControls: new Set(),
    hydrateDisplaySettingsForm() {}, applyDisplaySettingsState() {}, renderShortcutReference() {}, selectSettingsTab() {},
    hydrateFilterForm() {},
    contextMenuTargetId: null, contextMenuSessionId: null, contextMenuRecordTarget: null, contextMenuAnchor: { x: 0, y: 0 },
    async selectHistoryTransaction() {}, loadUserNote() {},
    transactionPath: (id, session) => `fixture-only:${session}/${id}`,
    fetch(url, options) { const request = { url, options, ...deferred() }; requests.push(request); return request.promise; },
    showToast(...args) { toasts.push(args); },
    updateAnnotations(...args) { saves.push(args); },
    state, _pendingTransactionSummaries: [], _historyFullLoadInFlight: 0, _searchActiveUntil: 0,
    scheduleTransactionDeltaFlush() {}, scheduleIncrementalRefresh() {},
    annotationClientId: "fixture-client", nextAnnotationClientVersion: () => ++clientVersion,
    sessionWritePath: (url, session) => `fixture-only:${session}${url}`, observeAnnotationRevision() {},
    getHistoryItemIndex: (id) => state.items.findIndex((entry) => entry.id === id),
    prepareHistoryItem() {},
    summaryMatchesActiveHistoryFilters: (entry) => !state.filterSettings.onlyNotes || entry.has_user_note,
    resortLoadedHistoryItemsForCurrentSort: () => false,
    invalidateVisibleEntriesCache() {},
    getVisibleEntries: () => state.items.map((entry, index) => ({ item: entry, index })),
    countHiddenConnectItems: () => 0, isKnownCount: (value) => typeof value === "number",
    humanizeSortKey: (key) => key, renderSortHeaders() {},
    measuredHistoryRowHeight: 30, HISTORY_ROW_HEIGHT: 30, HISTORY_BUFFER_ROWS: 5,
    HTTP_HISTORY_SCROLL_PREFETCH_ROWS: 20, scheduleHistoryBackfill() {}, measuredRowPitch: () => 30,
    adjustHistoryPagingAfterLocalRemoval(count) { state.historyPaging.filteredTotal -= count; },
    rebuildHistoryItemIndex() { state._itemById = new Map(state.items.map((entry) => [entry.id, entry])); },
    refreshHistoryPagingCursorFromItems() {}, renderEmptyDetail() {}, mountBrowserLaunchers() {},
    async fetchTransactionPage() { return null; },
    renderDetail(record) { detailWrites.push({ ...record }); },
    els: {
      contextMenu: { ...modal(), style: {}, offsetWidth: 180, offsetHeight: 200, querySelectorAll: () => [] },
      displaySettingsModal: modal(), closeDisplaySettingsButton: focusable(), openDisplaySettingsButton: focusable(),
      filterModal: modal(), closeFilterModalButton: focusable(), openFilterSettingsButton: focusable(),
      historyMeta: {}, historyTable: { closest: () => shell },
      historyTableBody: {
        ...eventTarget(),
        querySelector(selector) {
          return cells.find((entry) => entry.isConnected && entry.querySelector(selector))?.querySelector(selector) || null;
        },
        set innerHTML(value) { historyWrites.push(value); cells.forEach((entry) => { entry.isConnected = false; }); },
      },
    },
    window: {
      innerWidth: 1000, innerHeight: 800,
      ...eventTarget(), getComputedStyle: () => ({ visibility: "visible" }),
      setTimeout(callback) { const id = ++nextTimer; timers.set(id, callback); return id; },
      clearTimeout(id) { timers.delete(id); },
    },
    document: {
      ...document,
      querySelectorAll(selector) {
        return selector === "input.note-inline-input" ? cells.filter(cell => cell.isConnected).map(cell => cell.querySelector()).filter(Boolean) : [];
      },
      createElement(tag) {
        assert.equal(tag, "input");
        const listeners = {};
        let inputValue = "";
        const created = {
          ...focusable(),
          dataset: {}, type: "text",
          get value() { return inputValue; },
          set value(value) {
            // Model the HTML text-input value sanitizer, including assignment of
            // a saved note. A plain property would hide CR/LF loss on editor open.
            inputValue = this.type === "text" ? String(value).replace(/[\r\n]/g, "") : String(value);
          },
          addEventListener(type, callback) { listeners[type] = callback; },
          select() { this.selected = true; },
          dispatch(type, key, fields = {}) {
            const event = { key, defaultPrevented: false, stopPropagation() {},
              preventDefault() { this.defaultPrevented = true; }, ...fields };
            listeners[type]?.(event);
            return event;
          },
        };
        inputs.push(created);
        return created;
      },
    },
  });
  // Production focus calls update the same document seen by the loaded handlers.
  Object.defineProperty(context.document, "activeElement", {
    get: () => document.activeElement, set: (value) => { document.activeElement = value; },
  });
  context.currentSessionId = () => context.session;
  if (joinAnnotations) {
    state.filterSettings = context.createDefaultFilterSettings();
    state.historyPaging.offset = state.items.length;
    state.historyPaging.beforeSequence = item.sequence;
  }
  context.rebuildHistoryItemIndex();
  const listenerCount = () => [context.document, context.window].reduce((sum, target) =>
    sum + Array.from(target.listeners.values()).reduce((count, entries) => count + entries.size, 0), 0);
  return { context, cell, cells, requests, inputs, saves, toasts, timers, state, item, historyWrites, detailWrites,
    focusOwner, focusable, listenerCount };
}

const notes = (f) => f.saves.map((save) => save[1].user_note);

function runTimers(f) {
  for (const [id, callback] of Array.from(f.timers)) {
    f.timers.delete(id);
    callback();
  }
}

async function openSavedNote(f, note = "Saved note") {
  const loading = f.context.beginNoteEdit(f.cell, "fixture-record");
  f.requests.at(-1).resolve(response({ user_note: note }));
  await loading;
  return f.inputs.at(-1);
}

const response = (body = {}) => ({ ok: true, json: async () => body });
const failedResponse = (status = 500) => ({
  ok: false, status, headers: { get: () => "text/plain" }, text: async () => "Could not read saved note",
});

const annotationRequests = (f) => f.requests.filter((request) => request.options?.method === "PATCH");
async function acknowledgeAnnotation(f, request, overrides = {}) {
  const { user_note } = JSON.parse(request.options.body);
  request.resolve(response({
    ...f.item, has_user_note: Boolean(user_note), note_preview: user_note || null,
    annotation_revision: 2, ...overrides,
  }));
  await new Promise(setImmediate);
}

const savedMultilineNotes = [
  ["LF", "Saved\nnote"],
  ["CR", "Saved\rnote"],
  ["CRLF", "Saved\r\nnote"],
  ["edge-only line breaks", "\r\nSaved note\r\n"],
  ["newline-only", "\r\n\n\r"],
  ["Korean and emoji", "한글\r\n😀\n로그인\r🔒"],
  ["near the UTF-8 limit", "가".repeat(10920) + "\r\n😀"],
  ["at the UTF-8 limit", "가".repeat(10920) + "ab\r\n😀"],
];

for (const [label, savedNote] of savedMultilineNotes) {
  for (const close of ["blur", "Enter", "Escape"]) {
    test(`unchanged ${label} note survives ${close} and repeated close events without a write`, async () => {
      const f = fixture();
      const before = f.cell.innerHTML;
      assert.ok(Buffer.byteLength(savedNote) <= 32768, "the saved fixture is backend-valid UTF-8");
      const input = await openSavedNote(f, savedNote);
      assert.equal(input.type, "text");
      assert.equal(input.value, savedNote.replace(/[\r\n]/g, ""));
      assert.notEqual(input.value, savedNote, "the fixture must model the single-line input's sanitizer");
      input.dispatch(close === "blur" ? "blur" : "keydown", close);
      input.dispatch("blur");
      input.dispatch("keydown", "Enter");
      input.dispatch("keydown", "Escape");
      input.dispatch("compositionend");
      runTimers(f);
      assert.equal(f.saves.length, 0, "opening and closing must preserve the raw saved note");
      assert.equal(f.cell.innerHTML, before);
      assert.equal(f.cell.querySelector(), null);
      assert.equal(f.timers.size, 0);
    });
  }

  test(`editing and reverting the ${label} note before autosave preserves the raw saved note`, async () => {
    const f = fixture();
    const input = await openSavedNote(f, savedNote);
    input.value = "Temporary edit 한국어 😀";
    input.dispatch("input");
    input.value = savedNote;
    input.dispatch("input");
    runTimers(f);
    assert.equal(f.saves.length, 0, "reverting to the initial visible value is a no-op");
    input.dispatch("keydown", "Enter");
    input.dispatch("blur");
    assert.equal(f.saves.length, 0);
  });
}

test("unchanged input events and their debounce preserve the raw saved note", async () => {
  const f = fixture();
  const input = await openSavedNote(f, "한글\r\n😀\nSaved note");
  input.dispatch("input");
  input.dispatch("input");
  assert.equal(f.timers.size, 1);
  runTimers(f);
  assert.equal(f.saves.length, 0);
  input.dispatch("input");
  runTimers(f);
  assert.equal(f.saves.length, 0);
  input.dispatch("blur");
  assert.equal(f.saves.length, 0);
  assert.equal(f.timers.size, 0);
});

test("reverting after an explicit autosave saves the current single-line text", async () => {
  const f = fixture({ joinAnnotations: true });
  const savedNote = "  한글\r\n😀\nSaved note  ";
  const input = await openSavedNote(f, savedNote);
  input.value = "  Explicit edit 한국어 😀  ";
  input.dispatch("input");
  runTimers(f);
  assert.equal(annotationRequests(f).length, 1);
  assert.equal(JSON.parse(annotationRequests(f)[0].options.body).user_note, "Explicit edit 한국어 😀");
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  input.value = savedNote;
  input.dispatch("input");
  runTimers(f);
  assert.equal(annotationRequests(f).length, 2, "reverting after a save is a new explicit change");
  assert.equal(JSON.parse(annotationRequests(f)[1].options.body).user_note, "한글😀Saved note");
  await acknowledgeAnnotation(f, annotationRequests(f)[1]);
  input.dispatch("keydown", "Enter");
  input.dispatch("blur");
  assert.equal(annotationRequests(f).length, 2);
  assert.equal(f.item.note_preview, "한글😀Saved note");
});

test("reverting during the first in-flight autosave queues the single-line text exactly once", async () => {
  const f = fixture({ joinAnnotations: true });
  const savedNote = "  한글\r\n😀\nSaved note  ";
  const input = await openSavedNote(f, savedNote);
  input.value = "  Explicit edit 한국어 😀  ";
  input.dispatch("input");
  runTimers(f);
  const first = annotationRequests(f)[0];
  assert.equal(JSON.parse(first.options.body).user_note, "Explicit edit 한국어 😀");
  input.value = savedNote;
  input.dispatch("input");
  runTimers(f);
  assert.equal(annotationRequests(f).length, 1, "the revert waits for the first in-flight request");
  const queuedRevert = f.state._pendingAnnotations.get(f.item.id);
  assert.equal(queuedRevert.payload.user_note, "한글😀Saved note");
  input.dispatch("keydown", "Enter");
  input.dispatch("blur");
  assert.equal(annotationRequests(f).length, 1, "close must not start a duplicate request");
  assert.equal(f.state._pendingAnnotations.get(f.item.id), queuedRevert);
  await acknowledgeAnnotation(f, first);
  assert.equal(annotationRequests(f).length, 2);
  assert.equal(f.item.note_preview, "Saved note", "the superseded first save cannot repaint its text");
  assert.equal(f.state._itemsVersion, 0);
  const revert = annotationRequests(f)[1];
  assert.equal(JSON.parse(revert.options.body).user_note, "한글😀Saved note");
  assert.match(revert.url, /^fixture-only:fixture-session\//);
  await acknowledgeAnnotation(f, revert, { annotation_revision: 3 });
  assert.equal(f.item.note_preview, "한글😀Saved note");
  assert.equal(f.state._pendingAnnotations.size, 0);
  assert.equal(f.state._annotationInFlight.size, 0);
  input.dispatch("blur");
  input.dispatch("keydown", "Enter");
  runTimers(f);
  assert.equal(annotationRequests(f).length, 2);
});

for (const savedNote of [" \t한글 😀 \u00a0", " \t\r\n \u00a0"]) {
  test(`note trimming still ignores padding-only changes for ${JSON.stringify(savedNote)}`, async () => {
    const f = fixture();
    const input = await openSavedNote(f, savedNote);
    input.value = `  ${input.value.trim()}\t`;
    input.dispatch("input");
    runTimers(f);
    assert.equal(f.saves.length, 0);
    input.value = " \tUpdated 한국어 😀 \u00a0";
    input.dispatch("input");
    runTimers(f);
    assert.deepEqual(notes(f), ["Updated 한국어 😀"]);
    input.value = " \t\r\n \u00a0";
    input.dispatch("keydown", "Enter");
    input.dispatch("blur");
    assert.deepEqual(notes(f), ["Updated 한국어 😀", null]);
  });
}

test("a failed explicit edit remains queued through unchanged close and retries in its original session", async () => {
  const f = fixture({ joinAnnotations: true });
  const errors = [], reloads = [];
  f.context.console = { error: (...args) => errors.push(args) };
  f.context.loadTransactions = async (...args) => { reloads.push(args); };
  const input = await openSavedNote(f, "한글\r\n😀\nSaved note");
  input.value = "  Changed\r\n한국어 😀  ";
  input.dispatch("input");
  runTimers(f);
  const first = annotationRequests(f)[0];
  assert.equal(JSON.parse(first.options.body).user_note, "Changed한국어 😀");
  first.resolve(failedResponse());
  await new Promise(setImmediate);
  assert.equal(errors.length, 1);
  assert.equal(reloads.length, 1);
  assert.equal(f.toasts.length, 1);
  assert.equal(f.state._annotationInFlight.size, 0);
  const pending = f.state._pendingAnnotations.get(f.item.id);
  assert.equal(pending.payload.user_note, "Changed한국어 😀");
  assert.equal(pending.sessionId, "fixture-session");
  assert.equal(pending.noteEdit.sessionId, "fixture-session");
  input.dispatch("input");
  runTimers(f);
  input.dispatch("blur");
  input.dispatch("keydown", "Enter");
  assert.equal(annotationRequests(f).length, 1, "the existing pending edit owns retry, not unchanged close");
  assert.equal(f.state._pendingAnnotations.get(f.item.id), pending);
  f.context.session = "another-session";
  const retry = f.context.flushPendingAnnotations(f.item.id);
  const retried = annotationRequests(f)[1];
  assert.match(retried.url, /^fixture-only:fixture-session\//);
  assert.equal(retried.options.body, first.options.body);
  await acknowledgeAnnotation(f, retried);
  assert.equal(await retry, true);
  assert.equal(f.state._pendingAnnotations.size, 0);
  assert.equal(f.state._annotationInFlight.size, 0);
  assert.equal(f.item.note_preview, "Saved note", "a late retry cannot repaint a different session");
  assert.equal(f.historyWrites.length, 0);
});

test("a real candidate autosave acknowledgement keeps the composing editor connected", async () => {
  const f = fixture({ joinAnnotations: true });
  const input = await openSavedNote(f);
  input.dispatch("compositionstart");
  input.value = "로그인";
  input.dispatch("input", undefined, { isComposing: true });
  runTimers(f);
  assert.equal(annotationRequests(f).length, 1, "the candidate must still autosave before compositionend");
  assert.equal(JSON.parse(annotationRequests(f)[0].options.body).user_note, "로그인");
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  assert.equal(f.cell.isConnected, true, "the actual acknowledgement renderer must not detach the composing input");
  assert.equal(f.cell.querySelector(), input);
  assert.equal(input.value, "로그인");
  assert.equal(f.historyWrites.length, 0);
  assert.equal(f.item.note_preview, "로그인");
  assert.equal(f.state._pendingAnnotations.size, 0);
  assert.equal(f.state._annotationInFlight.size, 0);
  assert.equal(f.state._itemsVersion, 1);
  assert.equal(f.state.historyPaging.annotationMutationGeneration, 1);
  assert.equal(f.state._historyEntries[0].item, f.item);
  assert.match(f.context.els.historyMeta.textContent, /1 loaded item visible/);
  input.dispatch("compositionend");
  runTimers(f);
  assert.equal(annotationRequests(f).length, 1, "ending the same candidate must not duplicate the save");
});

for (const close of ["blur", "Enter", "Escape"]) {
  test(`closing an acknowledged editor with ${close} paints the saved summary exactly once`, async () => {
    const f = fixture({ joinAnnotations: true });
    const input = await openSavedNote(f);
    input.dispatch("compositionstart");
    input.value = "한국어 <saved>";
    input.dispatch("input", undefined, { isComposing: true });
    runTimers(f);
    await acknowledgeAnnotation(f, annotationRequests(f)[0]);
    input.dispatch("compositionend");
    runTimers(f);
    if (close === "Escape") {
      input.value = "An unsaved change";
      input.dispatch("input");
    }
    input.dispatch(close === "blur" ? "blur" : "keydown", close);
    assert.equal(f.historyWrites.length, 1);
    assert.match(f.historyWrites[0], /한국어 &lt;saved&gt;/);
    assert.doesNotMatch(f.historyWrites[0], /note-inline-input|An unsaved change/);
    assert.equal(f.cell.querySelector(), null);
    input.dispatch("blur");
    input.dispatch("keydown", "Enter");
    input.dispatch("keydown", "Escape");
    input.dispatch("compositionend");
    runTimers(f);
    assert.equal(f.historyWrites.length, 1, "late events cannot drain the deferred repaint again");
    assert.equal(annotationRequests(f).length, 1, "closing an already saved note does not issue another PATCH");
    assert.equal(f.timers.size, 0);
  });
}

for (const finalInputOrder of ["before-end", "after-end", "no-final-input"]) {
  test(`an acknowledged candidate survives blur until the final ${finalInputOrder} input is saved`, async () => {
    const f = fixture({ joinAnnotations: true });
    const input = await openSavedNote(f);
    input.dispatch("compositionstart");
    input.value = "にほん";
    input.dispatch("input", undefined, { isComposing: true });
    runTimers(f);
    input.dispatch("blur");
    await acknowledgeAnnotation(f, annotationRequests(f)[0]);
    assert.equal(f.cell.isConnected, true, "an unfocused composing input must also survive the ack");
    input.value = "日本";
    if (finalInputOrder === "before-end") input.dispatch("input", undefined, { isComposing: true });
    input.dispatch("compositionend");
    if (finalInputOrder === "after-end") input.dispatch("input", undefined, { isComposing: false });
    runTimers(f);
    assert.equal(f.historyWrites.length, 1, "close drains the deferred candidate paint once");
    assert.equal(annotationRequests(f).length, 2);
    assert.equal(JSON.parse(annotationRequests(f)[1].options.body).user_note, "日本");
    await acknowledgeAnnotation(f, annotationRequests(f)[1]);
    assert.equal(f.historyWrites.length, 2, "the finished-note acknowledgement paints normally");
    assert.match(f.historyWrites[1], /日本/);
    input.dispatch("blur");
    runTimers(f);
    assert.equal(f.historyWrites.length, 2);
    assert.equal(annotationRequests(f).length, 2);
  });
}

test("a superseded candidate acknowledgement cannot replace a newer draft or summary", async () => {
  const f = fixture({ joinAnnotations: true });
  const input = await openSavedNote(f);
  input.dispatch("compositionstart");
  input.value = "にほん";
  input.dispatch("input", undefined, { isComposing: true });
  runTimers(f);
  input.value = "日本";
  input.dispatch("compositionend");
  input.dispatch("input");
  runTimers(f);
  assert.equal(annotationRequests(f).length, 1, "newer text waits behind the in-flight candidate");
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  assert.equal(f.item.note_preview, "Saved note", "the stale ack must not merge its candidate");
  assert.equal(f.state._itemsVersion, 0);
  assert.equal(annotationRequests(f).length, 2);
  assert.equal(JSON.parse(annotationRequests(f)[1].options.body).user_note, "日本");
  await acknowledgeAnnotation(f, annotationRequests(f)[1], { annotation_revision: 3 });
  assert.equal(f.item.note_preview, "日本");
  assert.equal(input.value, "日本");
  assert.equal(f.cell.isConnected, true);
  assert.equal(f.historyWrites.length, 0);
  input.dispatch("blur");
  assert.equal(f.historyWrites.length, 1);
  assert.match(f.historyWrites[0], /日本/);
});

test("ordinary note autosave keeps its editor and still updates selected-record details", async () => {
  const f = fixture({ joinAnnotations: true });
  f.state.selectedRecord = { id: f.item.id, user_note: "Saved note" };
  const input = await openSavedNote(f);
  input.value = "Ordinary text";
  input.dispatch("input");
  runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  assert.equal(f.cell.isConnected, true);
  assert.equal(f.state.selectedRecord.user_note, "Ordinary text");
  assert.equal(f.detailWrites.length, 1);
  assert.equal(f.detailWrites[0].annotation_revision, 2);
  input.dispatch("keydown", "Enter");
  assert.equal(f.historyWrites.length, 1);
  assert.match(f.historyWrites[0], /Ordinary text/);
});

test("an unrelated record acknowledgement preserves the open note while updating its own summary", async () => {
  const f = fixture({ joinAnnotations: true });
  const other = { id: "other-fixture-record", sequence: 2, has_user_note: true, note_preview: "Other note" };
  f.state.items.push(other);
  f.context.rebuildHistoryItemIndex();
  const input = await openSavedNote(f);
  input.dispatch("compositionstart");
  input.value = "아직";
  f.context.updateAnnotations(other.id, { color_tag: "blue" });
  await acknowledgeAnnotation(f, annotationRequests(f)[0], { ...other, color_tag: "blue" });
  assert.equal(other.color_tag, "blue");
  assert.equal(f.cell.isConnected, true);
  assert.equal(input.value, "아직");
  assert.equal(f.historyWrites.length, 0);
  assert.match(f.context.els.historyMeta.textContent, /2 loaded items visible/);
  input.dispatch("compositionend");
  input.dispatch("keydown", "Escape");
  assert.equal(f.historyWrites.length, 1);
  assert.match(f.historyWrites[0], /tagged-blue/);
  assert.equal(annotationRequests(f).length, 1, "cancelling the unrelated draft must not save it");
});

test("an acknowledgement can remove a filtered row without interrupting its editor", async () => {
  const f = fixture({ joinAnnotations: true });
  f.state.filterSettings.onlyNotes = true;
  const input = await openSavedNote(f);
  input.dispatch("compositionstart");
  input.value = "";
  input.dispatch("input", undefined, { isComposing: true });
  runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  assert.equal(f.state.items.length, 0);
  assert.equal(f.state._itemById.size, 0);
  assert.equal(f.state.historyPaging.filteredTotal, 0);
  assert.equal(f.state.historyPaging.total, 1);
  assert.equal(f.state._historyEntries.length, 0);
  assert.match(f.context.els.historyMeta.textContent, /0 loaded items visible.*notes only/);
  assert.equal(f.historyWrites.length, 0, "even an empty-list acknowledgement must defer tbody replacement");
  assert.equal(f.cell.isConnected, true);
  input.dispatch("compositionend");
  runTimers(f);
  input.dispatch("blur");
  assert.equal(f.historyWrites.length, 1);
  assert.match(f.historyWrites[0], /No traffic matches/);
  assert.equal(annotationRequests(f).length, 1);
});

for (const composing of [false, true]) {
  for (const close of ["blur", "Enter", "Escape"]) {
    test(`a filtered note reenters before ${close} with IME=${composing}`, async () => {
      const f = fixture({ joinAnnotations: true });
      f.state.filterSettings.onlyNotes = true;
      f.state.selectedId = f.item.id;
      f.state.selectedRecord = { id: f.item.id, user_note: "Saved note" };
      const input = await openSavedNote(f);
      if (composing) input.dispatch("compositionstart");
      input.value = "";
      input.dispatch("input", undefined, { isComposing: composing });
      runTimers(f);
      await acknowledgeAnnotation(f, annotationRequests(f)[0]);
      assert.equal(f.state.items.length, 0);
      assert.equal(f.state.historyPaging.filteredTotal, 0);
      assert.equal(f.state.historyPaging.offset, 0);
      assert.equal(f.state.selectedId, null);
      input.value = "Restored 日本";
      input.dispatch("input", undefined, { isComposing: composing });
      runTimers(f);
      await acknowledgeAnnotation(f, annotationRequests(f)[1], { annotation_revision: 3 });
      assert.deepEqual(Array.from(f.state.items, (item) => item.id), [f.item.id]);
      assert.equal(f.state.items[0].note_preview, "Restored 日本");
      assert.equal(f.state.historyPaging.filteredTotal, 1);
      assert.equal(f.state.historyPaging.offset, 1);
      assert.equal(f.state.historyPaging.total, 1);
      assert.equal(f.state.selectedId, null, "restoration must not reclaim selection");
      assert.equal(f.state.selectedRecord, null);
      assert.equal(f.state._itemById.get(f.item.id), f.state.items[0]);
      assert.equal(f.state._itemIndexById.get(f.item.id), 0);
      assert.match(f.context.els.historyMeta.textContent, /1 loaded item visible/);
      assert.equal(f.cell.querySelector(), input);
      assert.equal(f.historyWrites.length, 0);
      if (composing) { input.dispatch("compositionend"); runTimers(f); }
      input.dispatch(close === "blur" ? "blur" : "keydown", close);
      assert.equal(f.historyWrites.length, 1);
      assert.match(f.historyWrites[0], /Restored 日本/);
      assert.equal(annotationRequests(f).length, 2);
      for (const request of annotationRequests(f)) {
        assert.deepEqual(Object.keys(JSON.parse(request.options.body)).sort(), ["client_id", "client_version", "user_note"]);
      }
    });
  }
}

for (const close of ["blur", "Enter"]) {
  test(`a final note acknowledgement reenters after ${close} queued its save`, async () => {
    const f = fixture({ joinAnnotations: true });
    f.state.filterSettings.onlyNotes = true;
    const input = await openSavedNote(f);
    input.value = ""; input.dispatch("input"); runTimers(f);
    await acknowledgeAnnotation(f, annotationRequests(f)[0]);
    input.value = "Final after close";
    input.dispatch("input");
    input.dispatch(close === "blur" ? "blur" : "keydown", close);
    assert.equal(f.cell.querySelector(), null);
    assert.equal(annotationRequests(f).length, 2);
    await acknowledgeAnnotation(f, annotationRequests(f)[1]);
    assert.equal(f.state.items.length, 1);
    assert.equal(f.state.items[0].note_preview, "Final after close");
    assert.equal(f.state.historyPaging.filteredTotal, 1);
    assert.match(f.historyWrites.at(-1), /Final after close/);
  });
}

for (const sortKey of ["index", "host", "notes"]) {
  for (const restoreOrder of [["first", "second"], ["second", "first"]]) {
    test(`two filtered editors restore once in ${sortKey} order: ${restoreOrder}`, async () => {
      const f = fixture({ joinAnnotations: true });
      f.state.sortKey = sortKey;
      f.state.sortDirection = sortKey === "host" ? "asc" : "desc";
      f.state.filterSettings.onlyNotes = true;
      const other = { id: "second-record", sequence: 0, host: "b.example.com", has_user_note: true, note_preview: "Second note" };
      f.item.host = "a.example.com";
      f.state.items.push(other);
      Object.assign(f.state.historyPaging, { fullyLoaded: false, total: 8, filteredTotal: 8, offset: 5, trimmedHeadCount: 3, trimmedTailCount: 3, hasMore: true });
      f.context.rebuildHistoryItemIndex();
      const first = await openSavedNote(f);
      first.dispatch("compositionstart");
      const secondCell = noteCell(); f.cells.push(secondCell);
      const loading = f.context.beginNoteEdit(secondCell, other.id);
      f.requests.at(-1).resolve(response({ user_note: "Second note" })); await loading;
      const second = f.inputs.at(-1);
      second.dispatch("compositionstart");
      first.value = ""; first.dispatch("input", undefined, { isComposing: true }); runTimers(f);
      await acknowledgeAnnotation(f, annotationRequests(f).at(-1));
      second.value = ""; second.dispatch("input", undefined, { isComposing: true }); runTimers(f);
      await acknowledgeAnnotation(f, annotationRequests(f).at(-1), { ...other, has_user_note: false, note_preview: null });
      assert.equal(f.state.items.length, 0);
      assert.equal(f.state.historyPaging.filteredTotal, 6);
      const expectedRemovedOffset = sortKey === "index" ? 0 : 3;
      assert.equal(f.state.historyPaging.offset, expectedRemovedOffset);
      for (const name of restoreOrder) {
        const input = name === "first" ? first : second;
        const item = name === "first" ? f.item : other;
        input.value = `Restored ${name}`; input.dispatch("input", undefined, { isComposing: true }); runTimers(f);
        await acknowledgeAnnotation(f, annotationRequests(f).at(-1), { ...item, has_user_note: true, note_preview: `Restored ${name}` });
      }
      assert.deepEqual(Array.from(f.state.items, (item) => item.id), [f.item.id, other.id]);
      assert.equal(f.state.historyPaging.filteredTotal, 8);
      assert.equal(f.state.historyPaging.offset, sortKey === "index" ? 2 : 5);
      assert.equal(f.state.historyPaging.total, 8);
      assert.equal(f.historyWrites.length, 0);
      first.dispatch("compositionend"); second.dispatch("compositionend"); runTimers(f);
      first.dispatch("keydown", "Escape"); second.dispatch("keydown", "Escape");
      assert.equal(f.historyWrites.length, 1);
    });
  }
}

test("repeated filter exits and reentries do not accumulate rows or counts", async () => {
  const f = fixture({ joinAnnotations: true });
  f.state.filterSettings.onlyNotes = true;
  const input = await openSavedNote(f);
  for (let cycle = 0; cycle < 3; cycle++) {
    for (const value of ["", `Restored ${cycle}`]) {
      input.value = value; input.dispatch("input"); runTimers(f);
      await acknowledgeAnnotation(f, annotationRequests(f).at(-1));
      assert.equal(f.state.items.length, value ? 1 : 0);
      assert.equal(f.state.historyPaging.filteredTotal, value ? 1 : 0);
      assert.equal(f.state.historyPaging.total, 1);
      assert.equal(Boolean(f.state._historyNoteEditWindow), !value);
    }
  }
  assert.equal(f.state.historyPaging.localRemovalGeneration, 6);
  input.dispatch("blur");
  assert.equal(annotationRequests(f).length, 6);
  assert.equal(f.state._historyNoteEditWindow, null);
});

test("a system note keeps a cleared user-note row matched", async () => {
  const f = fixture({ joinAnnotations: true });
  f.state.filterSettings.onlyNotes = true;
  f.item.note_count = 1;
  const input = await openSavedNote(f);
  input.value = ""; input.dispatch("input"); runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  assert.equal(f.state.items.length, 1);
  assert.equal(f.state.historyPaging.filteredTotal, 1);
  assert.equal(f.state._historyNoteEditWindow, undefined);
  assert.equal(f.state.items[0].has_user_note, false);
  input.dispatch("blur");
});

test("restoring a note leaves an unrelated selected record untouched", async () => {
  const f = fixture({ joinAnnotations: true });
  f.state.filterSettings.onlyNotes = true;
  const other = { id: "selected-other", sequence: 0, has_user_note: true, note_preview: "Other" };
  f.state.items.push(other); f.context.rebuildHistoryItemIndex();
  Object.assign(f.state.historyPaging, { total: 2, filteredTotal: 2, offset: 2 });
  f.state.selectedId = other.id;
  f.state.selectedRecord = { ...other, user_note: "Other" };
  const selectedRecord = f.state.selectedRecord;
  const input = await openSavedNote(f);
  for (const value of ["", "Restored"]) {
    input.value = value; input.dispatch("input"); runTimers(f);
    await acknowledgeAnnotation(f, annotationRequests(f).at(-1));
  }
  assert.equal(f.state.selectedId, other.id);
  assert.equal(f.state.selectedRecord, selectedRecord);
  assert.equal(f.detailWrites.length, 0);
  input.dispatch("blur");
});

for (const mutation of ["query", "sort", "paging", "rows", "version", "count", "offset"]) {
  test(`a removed editor cannot reenter a replaced ${mutation} view`, async () => {
    const f = fixture({ joinAnnotations: true });
    f.state.filterSettings.onlyNotes = true;
    const input = await openSavedNote(f);
    input.value = ""; input.dispatch("input"); runTimers(f);
    await acknowledgeAnnotation(f, annotationRequests(f)[0]);
    const editor = [...f.state._historyNoteEditWindow.editors][0];
    input.value = "Should stay outside the new view"; input.dispatch("input"); runTimers(f);
    if (mutation === "query") f.state.query = "a different query";
    else if (mutation === "sort") f.state.sortKey = "host";
    else if (mutation === "paging") f.state.historyPaging = { ...f.state.historyPaging };
    else if (mutation === "rows") f.state.items = [];
    else if (mutation === "version") f.state._itemsVersion++;
    else if (mutation === "count") f.state.historyPaging.filteredTotal = 2;
    else f.state.historyPaging.offset = 10;
    const count = f.state.historyPaging.filteredTotal;
    await acknowledgeAnnotation(f, annotationRequests(f)[1]);
    assert.equal(f.state.items.length, 0);
    assert.equal(f.state.historyPaging.filteredTotal, count);
    assert.equal(f.state._historyNoteEditWindow, null);
    assert.equal(editor.removed, null);
  });
}

test("a list replacement immediately discards recovery even with a final save pending", async () => {
  const f = fixture({ joinAnnotations: true });
  f.state.filterSettings.onlyNotes = true;
  const input = await openSavedNote(f);
  input.value = ""; input.dispatch("input"); runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  const editor = [...f.state._historyNoteEditWindow.editors][0];
  input.value = "Pending"; input.dispatch("input"); runTimers(f);
  f.state.items = [];
  f.context.renderHistory();
  assert.equal(f.state._historyNoteEditWindow, null);
  assert.equal(editor.removed, null);
  await acknowledgeAnnotation(f, annotationRequests(f)[1]);
  assert.equal(f.state.items.length, 0);
});

for (const leave of ["Escape", "blur", "render", "virtual render"]) {
  test(`removed-note recovery is released after ${leave} with no pending save`, async () => {
    const f = fixture({ joinAnnotations: true });
    f.state.filterSettings.onlyNotes = true;
    const other = { id: "other-row", sequence: 0, has_user_note: true, note_preview: "Other" };
    f.state.items.push(other); f.context.rebuildHistoryItemIndex();
    Object.assign(f.state.historyPaging, { total: 2, filteredTotal: 2, offset: 2 });
    const input = await openSavedNote(f);
    input.value = ""; input.dispatch("input"); runTimers(f);
    await acknowledgeAnnotation(f, annotationRequests(f)[0]);
    const editor = [...f.state._historyNoteEditWindow.editors][0];
    if (leave === "render") f.context.renderHistory();
    else if (leave === "virtual render") f.context.renderHistoryVirtual();
    else input.dispatch(leave === "blur" ? "blur" : "keydown", leave);
    assert.equal(editor.removed, null);
    assert.equal(f.state._historyNoteEditWindow, null);
    assert.equal(annotationRequests(f).length, 1);
  });
}

test("a final matching acknowledgement survives detachment while its save remains pending", async () => {
  const f = fixture({ joinAnnotations: true });
  f.state.filterSettings.onlyNotes = true;
  const input = await openSavedNote(f);
  input.value = ""; input.dispatch("input"); runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  const editor = [...f.state._historyNoteEditWindow.editors][0];
  input.value = "Saved after detachment"; input.dispatch("input"); runTimers(f);
  f.context.renderHistory();
  assert.equal(f.cell.isConnected, false);
  assert.ok(editor.removed, "the already queued save owns this recovery");
  await acknowledgeAnnotation(f, annotationRequests(f)[1]);
  assert.equal(f.state.items.length, 1);
  assert.equal(f.state.items[0].note_preview, "Saved after detachment");
  assert.equal(editor.removed, null);
  assert.equal(f.state._historyNoteEditWindow, null);
});

test("a superseded matching candidate cannot resurrect the row before the latest save", async () => {
  const f = fixture({ joinAnnotations: true });
  f.state.filterSettings.onlyNotes = true;
  const input = await openSavedNote(f);
  input.value = ""; input.dispatch("input"); runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  input.value = "Superseded"; input.dispatch("input"); runTimers(f);
  input.value = ""; input.dispatch("input"); runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[1]);
  assert.equal(f.state.items.length, 0);
  assert.equal(f.state.historyPaging.filteredTotal, 0);
  assert.equal(annotationRequests(f).length, 3);
  await acknowledgeAnnotation(f, annotationRequests(f)[2]);
  assert.equal(f.state.items.length, 0);
  input.dispatch("keydown", "Escape");
  assert.equal(f.state._historyNoteEditWindow, null);
});

test("ordinary annotation acknowledgements cannot insert arbitrary unloaded rows", async () => {
  const f = fixture({ joinAnnotations: true });
  f.state.items = []; f.context.rebuildHistoryItemIndex();
  Object.assign(f.state.historyPaging, { offset: 0, filteredTotal: 0 });
  f.context.updateAnnotations(f.item.id, { user_note: "Updated elsewhere" });
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  assert.equal(f.state.items.length, 0);
  assert.equal(f.state.historyPaging.filteredTotal, 0);
  assert.equal(f.state._historyNoteEditWindow, undefined);
});

for (const finalInputOrder of ["before-end", "after-end", "no-final-input"]) {
  test(`a removed composing note reenters after blur with final input ${finalInputOrder}`, async () => {
    const f = fixture({ joinAnnotations: true });
    f.state.filterSettings.onlyNotes = true;
    const input = await openSavedNote(f);
    input.dispatch("compositionstart");
    input.value = ""; input.dispatch("input", undefined, { isComposing: true }); runTimers(f);
    await acknowledgeAnnotation(f, annotationRequests(f)[0]);
    input.dispatch("blur");
    input.value = "日本";
    if (finalInputOrder === "before-end") input.dispatch("input", undefined, { isComposing: true });
    input.dispatch("compositionend");
    if (finalInputOrder === "after-end") input.dispatch("input", undefined, { isComposing: false });
    runTimers(f);
    assert.equal(f.cell.querySelector(), null);
    assert.equal(annotationRequests(f).length, 2);
    await acknowledgeAnnotation(f, annotationRequests(f)[1]);
    assert.equal(f.state.items.length, 1);
    assert.equal(f.state.items[0].note_preview, "日本");
    assert.equal(f.state._historyNoteEditWindow, null);
    assert.match(f.historyWrites.at(-1), /日本/);
  });
}

for (const loader of ["loadMoreTransactions", "loadNewerTransactions"]) {
  test(`a reentry invalidates the stale ${loader} page and counts`, async () => {
    const f = fixture({ joinAnnotations: true });
    f.state.sortKey = "host"; f.state.sortDirection = "asc";
    f.state.filterSettings.onlyNotes = true;
    Object.assign(f.state.historyPaging, { hasMore: true, fullyLoaded: false, trimmedHeadCount: 2, pageSize: 1, offset: 3, filteredTotal: 5, total: 8 });
    const input = await openSavedNote(f);
    input.value = ""; input.dispatch("input"); runTimers(f);
    await acknowledgeAnnotation(f, annotationRequests(f)[0]);
    const pages = [];
    f.context.fetchTransactionPage = (options) => {
      const page = { options, ...deferred() }; pages.push(page); return page.promise;
    };
    const loading = f.context[loader]({ background: true });
    assert.equal(pages.length, 1);
    input.value = "Restored during page read"; input.dispatch("input"); runTimers(f);
    await acknowledgeAnnotation(f, annotationRequests(f)[1]);
    assert.equal(f.state.historyPaging.filteredTotal, 5);
    pages[0].resolve({ items: [], total: 8, filtered_total: 4, has_more: false });
    await new Promise(setImmediate);
    assert.equal(pages.length, 2, "the pre-reentry page must retry instead of adopting stale counts");
    pages[1].resolve({ items: [], total: 8, filtered_total: 5, has_more: false });
    await loading;
    assert.equal(f.state.items.length, 1);
    assert.equal(f.state.historyPaging.filteredTotal, 5);
    if (loader === "loadMoreTransactions") assert.deepEqual(pages.slice(0, 2).map((page) => page.options.offset), [2, 3]);
    for (const page of pages.slice(2)) page.resolve(null); // Virtual rendering can begin the next prefetch.
  });
}

for (const direction of ["asc", "desc"]) {
  test(`restored note counts use the actual notes ${direction} sorter`, async () => {
    const f = fixture({ joinAnnotations: true });
    f.state.filterSettings.onlyNotes = true;
    f.state.sortKey = "notes"; f.state.sortDirection = direction;
    const other = { id: "other-note", sequence: 2, has_user_note: true, note_preview: "Other", note_count: 1 };
    f.state.items.push(other); f.context.resortLoadedHistoryItemsForCurrentSort(); f.context.rebuildHistoryItemIndex();
    Object.assign(f.state.historyPaging, { total: 2, filteredTotal: 2, offset: 2 });
    const input = await openSavedNote(f);
    input.value = ""; input.dispatch("input"); runTimers(f);
    await acknowledgeAnnotation(f, annotationRequests(f)[0]);
    input.value = "Restored"; input.dispatch("input"); runTimers(f);
    await acknowledgeAnnotation(f, annotationRequests(f)[1], { note_count: 2 });
    assert.deepEqual(Array.from(f.state.items, (item) => item.id), direction === "asc" ? [other.id, f.item.id] : [f.item.id, other.id]);
    assert.equal(f.state._itemIndexById.get(f.item.id), direction === "asc" ? 1 : 0);
  });
}

test("reentry preserves unknown counts and clears omitted annotation fields", async () => {
  const f = fixture({ joinAnnotations: true });
  f.state.filterSettings.onlyNotes = true;
  f.item.color_tag = "blue";
  f.state.historyPaging.filteredTotal = null;
  const input = await openSavedNote(f);
  input.value = ""; input.dispatch("input"); runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  input.value = "Restored"; input.dispatch("input"); runTimers(f);
  annotationRequests(f)[1].resolve(response({ id: f.item.id, sequence: 1, has_user_note: true, note_preview: "Restored" }));
  await new Promise(setImmediate);
  assert.equal(f.state.items.length, 1);
  assert.equal(f.state.items[0].color_tag, null);
  assert.equal(f.state.items[0].annotation_revision, 0);
  assert.equal(f.state.historyPaging.filteredTotal, null);
});

test("a reopened editor inherits recovery from the same record's pending save", async () => {
  const f = fixture({ joinAnnotations: true });
  f.state.filterSettings.onlyNotes = true;
  const input = await openSavedNote(f);
  input.value = ""; input.dispatch("input"); runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  const previousEditor = [...f.state._historyNoteEditWindow.editors][0];
  // A second composing editor keeps the first row's cell present after it closes.
  const otherCell = noteCell(); f.cells.push(otherCell);
  const openingOther = f.context.beginNoteEdit(otherCell, "other-record");
  f.requests.at(-1).resolve(response({ user_note: "Other note" })); await openingOther;
  f.inputs.at(-1).dispatch("compositionstart");
  input.value = "Pending restoration"; input.dispatch("input"); runTimers(f);
  const previousRequest = annotationRequests(f)[1];
  input.dispatch("keydown", "Escape");
  assert.equal(f.cell.isConnected, true);
  const reopening = f.context.beginNoteEdit(f.cell, f.item.id);
  f.requests.at(-1).resolve(response({ user_note: "Pending restoration" })); await reopening;
  const reopened = f.inputs.at(-1);
  reopened.value = "Latest editor note"; reopened.dispatch("input"); runTimers(f);
  await acknowledgeAnnotation(f, previousRequest);
  assert.equal(f.state.items.length, 0, "superseded acknowledgement must not restore");
  await acknowledgeAnnotation(f, annotationRequests(f)[2]);
  assert.equal(f.state.items.length, 1);
  assert.equal(f.state.items[0].note_preview, "Latest editor note");
  assert.equal(f.state.historyPaging.filteredTotal, 1);
  assert.equal(previousEditor.removed, null);
  assert.equal(f.state._historyNoteEditWindow, null);
  assert.equal(f.cell.querySelector(), reopened);
});

test("a released filtered-out cell cannot reopen while another composing editor defers repaint", async () => {
  const f = fixture({ joinAnnotations: true });
  f.state.filterSettings.onlyNotes = true;
  const other = { id: "second-record", sequence: 0, has_user_note: true, note_preview: "Other note" };
  f.state.items.push(other); f.context.rebuildHistoryItemIndex();
  Object.assign(f.state.historyPaging, { total: 2, filteredTotal: 2, offset: 2 });
  const first = await openSavedNote(f);
  first.dispatch("compositionstart");
  first.value = ""; first.dispatch("input", undefined, { isComposing: true }); runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  first.dispatch("blur");
  const otherCell = noteCell(); f.cells.push(otherCell);
  const opening = f.context.beginNoteEdit(otherCell, other.id);
  f.requests.at(-1).resolve(response({ user_note: "Other note" })); await opening;
  const second = f.inputs.at(-1); second.dispatch("compositionstart");
  first.dispatch("compositionend"); runTimers(f);
  assert.equal(f.cell.isConnected, true, "the other IME still owns the deferred table");
  assert.equal(f.cell.querySelector(), null);
  assert.equal(f.state._historyNoteEditWindow, null, "no summary survives its editor or pending save");
  const requestsBefore = f.requests.length;
  const inputsBefore = f.inputs.length;
  const reopening = f.context.beginNoteEdit(f.cell, f.item.id);
  if (f.requests.length > requestsBefore) f.requests.at(-1).resolve(response({ user_note: "" }));
  await reopening;
  assert.equal(f.requests.length, requestsBefore, "the obsolete cell must not start a fresh edit/read");
  assert.equal(f.inputs.length, inputsBefore);
  assert.equal(otherCell.querySelector(), second);
  second.dispatch("compositionend"); runTimers(f); second.dispatch("blur");
  assert.equal(f.cell.isConnected, false, "ordinary repaint naturally removes the stale-cell guard");
  assert.deepEqual(Array.from(f.state.items, (item) => item.id), [other.id]);
  assert.equal(f.state.historyPaging.filteredTotal, 1);
});

test("a stale-cell marker never blocks a record present in the current loaded window", async () => {
  const f = fixture({ joinAnnotations: true });
  f.cell.dataset.noteFilteredOut = "true";
  const input = await openSavedNote(f);
  assert.equal(f.cell.dataset.noteFilteredOut, undefined);
  input.value = "Valid edit"; input.dispatch("input"); runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  assert.equal(f.state.items[0].note_preview, "Valid edit");
});

test("an unrelated annotation keeps a removed editor's window and summary recovery valid", async () => {
  const f = fixture({ joinAnnotations: true });
  f.state.filterSettings.onlyNotes = true;
  const other = { id: "other-annotated-record", sequence: 0, has_user_note: true, note_preview: "Other" };
  f.state.items.push(other); f.context.rebuildHistoryItemIndex();
  Object.assign(f.state.historyPaging, { total: 2, filteredTotal: 2, offset: 2 });
  const input = await openSavedNote(f);
  input.value = ""; input.dispatch("input"); runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  const recoveryWindow = f.state._historyNoteEditWindow;
  f.context.updateAnnotations(other.id, { color_tag: "blue" });
  await acknowledgeAnnotation(f, annotationRequests(f)[1], { ...other, color_tag: "blue" });
  assert.equal(f.state._historyNoteEditWindow, recoveryWindow);
  input.value = "Restored after other annotation"; input.dispatch("input"); runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[2]);
  assert.deepEqual(Array.from(f.state.items, (item) => item.id), [f.item.id, other.id]);
  assert.equal(other.color_tag, "blue");
  assert.equal(f.state.historyPaging.filteredTotal, 2);
  assert.equal(f.state._historyNoteEditWindow, null);
});

test("a late note read cannot reopen a cell released while the read was pending", async () => {
  const f = fixture({ joinAnnotations: true });
  f.state.filterSettings.onlyNotes = true;
  const other = { id: "second-record", sequence: 0, has_user_note: true, note_preview: "Other" };
  f.state.items.push(other); f.context.rebuildHistoryItemIndex();
  Object.assign(f.state.historyPaging, { total: 2, filteredTotal: 2, offset: 2 });
  const first = await openSavedNote(f);
  first.value = ""; first.dispatch("input"); runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  const otherCell = noteCell(); f.cells.push(otherCell);
  const openingOther = f.context.beginNoteEdit(otherCell, other.id);
  f.requests.at(-1).resolve(response({ user_note: "Other" })); await openingOther;
  f.inputs.at(-1).dispatch("compositionstart");
  first.value = "Transient restore"; first.dispatch("input"); runTimers(f);
  const restoring = annotationRequests(f)[1];
  first.value = ""; first.dispatch("input"); runTimers(f);
  first.dispatch("keydown", "Escape");
  const reopening = f.context.beginNoteEdit(f.cell, f.item.id);
  const reading = f.requests.at(-1);
  await acknowledgeAnnotation(f, restoring);
  await acknowledgeAnnotation(f, annotationRequests(f)[2]);
  assert.equal(f.cell.dataset.noteFilteredOut, "true");
  assert.equal(f.state._historyNoteEditWindow, null);
  const inputCount = f.inputs.length;
  reading.resolve(response({ user_note: "" })); await reopening;
  assert.equal(f.inputs.length, inputCount, "a completed read must revalidate the released cell");
  assert.equal(f.cell.querySelector(), null);
  assert.equal(f.cell.dataset.noteLoading, undefined);
  assert.equal(f.state.items.length, 1);
  assert.equal(f.state.historyPaging.filteredTotal, 1);
});

test("reopening before the old acknowledgement assumes recovery before the new editor saves", async () => {
  const f = fixture({ joinAnnotations: true });
  f.state.filterSettings.onlyNotes = true;
  const other = { id: "second-record", sequence: 0, has_user_note: true, note_preview: "Other" };
  f.state.items.push(other); f.context.rebuildHistoryItemIndex();
  Object.assign(f.state.historyPaging, { total: 2, filteredTotal: 2, offset: 2 });
  const first = await openSavedNote(f);
  first.value = ""; first.dispatch("input"); runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  const oldEditor = [...f.state._historyNoteEditWindow.editors][0];
  const otherCell = noteCell(); f.cells.push(otherCell);
  const openingOther = f.context.beginNoteEdit(otherCell, other.id);
  f.requests.at(-1).resolve(response({ user_note: "Other" })); await openingOther;
  f.inputs.at(-1).dispatch("compositionstart");
  first.value = "Transient restore"; first.dispatch("input"); runTimers(f);
  const restoring = annotationRequests(f)[1];
  first.value = ""; first.dispatch("input"); runTimers(f);
  first.dispatch("keydown", "Escape");
  const reopening = f.context.beginNoteEdit(f.cell, f.item.id);
  f.requests.at(-1).resolve(response({ user_note: "" })); await reopening;
  const reopened = f.inputs.at(-1);
  await acknowledgeAnnotation(f, restoring);
  await acknowledgeAnnotation(f, annotationRequests(f)[2]);
  assert.equal(f.state.items.length, 1);
  reopened.value = "Restored from reopened editor"; reopened.dispatch("input"); runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[3]);
  assert.equal(f.state.items.length, 2);
  assert.equal(f.state.items[0].note_preview, "Restored from reopened editor");
  assert.equal(f.state.historyPaging.filteredTotal, 2);
  assert.equal(oldEditor.removed, null);
  assert.equal(f.state._historyNoteEditWindow, null);
});

test("acknowledgement sorting updates the model before the deferred table is repainted", async () => {
  const f = fixture({ joinAnnotations: true });
  const other = { id: "other-fixture-record", sequence: 2, has_user_note: true, note_preview: "Other note" };
  f.state.items.push(other);
  f.state.sortKey = "notes";
  f.state.sortDirection = "desc";
  f.context.rebuildHistoryItemIndex();
  const input = await openSavedNote(f);
  input.value = "";
  input.dispatch("input");
  runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  assert.deepEqual(Array.from(f.state.items, (entry) => entry.id), [other.id, f.item.id]);
  assert.equal(f.state._itemIndexById.get(f.item.id), 1);
  assert.equal(f.state._historyEntries[0].item, other);
  assert.match(f.context.els.historyMeta.textContent, /sort: notes desc/);
  assert.equal(f.historyWrites.length, 0);
  input.dispatch("blur");
  assert.equal(f.historyWrites.length, 1);
  assert.ok(f.historyWrites[0].indexOf(other.id) < f.historyWrites[0].indexOf(f.item.id));
});

for (const leave of ["session", "cell"]) {
  test(`an old editor cannot drain its deferred repaint after leaving the ${leave}`, async () => {
    const f = fixture({ joinAnnotations: true });
    const input = await openSavedNote(f);
    input.value = "Acknowledged note";
    input.dispatch("input");
    runTimers(f);
    await acknowledgeAnnotation(f, annotationRequests(f)[0]);
    if (leave === "session") f.context.session = "another-session";
    else f.cell.isConnected = false;
    input.dispatch("keydown", "Escape");
    assert.equal(f.historyWrites.length, 0);
    assert.equal(annotationRequests(f).length, 1);
  });
}

test("a late acknowledgement from a previous session never defers or repaints the current history", async () => {
  const f = fixture({ joinAnnotations: true });
  const input = await openSavedNote(f);
  input.value = "Old session draft";
  input.dispatch("input");
  runTimers(f);
  f.context.session = "another-session";
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  assert.equal(f.item.note_preview, "Saved note");
  assert.equal(f.state._itemsVersion, 0);
  assert.equal(f.state.historyPaging.annotationMutationGeneration, undefined);
  assert.equal(input.dataset.historyRenderPending, undefined);
  assert.equal(f.historyWrites.length, 0);
  assert.equal(f.state._pendingAnnotations.size, 0);
});

for (const render of ["renderHistory", "renderHistoryVirtual"]) {
  test(`ordinary ${render} is not frozen by a deferred annotation paint`, async () => {
    const f = fixture({ joinAnnotations: true });
    const input = await openSavedNote(f);
    input.value = "Saved before navigation";
    input.dispatch("input");
    runTimers(f);
    await acknowledgeAnnotation(f, annotationRequests(f)[0]);
    assert.equal(f.historyWrites.length, 0);
    f.context[render]();
    assert.equal(f.historyWrites.length, 1);
    assert.equal(f.cell.isConnected, false);
    input.dispatch("keydown", "Escape");
    assert.equal(f.historyWrites.length, 1, "detached editor events must not cause another repaint");
  });
}

test("closing a composing editor transfers its pending repaint to another live editor", async () => {
  const f = fixture({ joinAnnotations: true });
  const firstInput = await openSavedNote(f);
  firstInput.dispatch("compositionstart");
  firstInput.value = "로그인";
  firstInput.dispatch("input", undefined, { isComposing: true });
  runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f)[0]);
  firstInput.dispatch("blur");
  const secondCell = noteCell();
  f.cells.push(secondCell);
  const loading = f.context.beginNoteEdit(secondCell, "other-fixture-record");
  f.requests.at(-1).resolve(response({ user_note: "Other saved note" }));
  await loading;
  const secondInput = f.inputs.at(-1);
  firstInput.dispatch("compositionend");
  runTimers(f);
  assert.equal(f.cell.querySelector(), null);
  assert.equal(f.historyWrites.length, 0);
  assert.equal(secondCell.isConnected, true);
  assert.equal(secondCell.querySelector(), secondInput);
  assert.equal(secondInput.dataset.historyRenderPending, "true");
  secondInput.dispatch("keydown", "Escape");
  assert.equal(f.historyWrites.length, 1);
  assert.match(f.historyWrites[0], /로그인/);
  firstInput.dispatch("blur");
  secondInput.dispatch("blur");
  runTimers(f);
  assert.equal(f.historyWrites.length, 1);
  assert.equal(annotationRequests(f).length, 1);
});

async function pendingNoteRead(f, stage = "fetch", cell = f.cell, id = "fixture-record") {
  const loading = f.context.beginNoteEdit(cell, id);
  const request = f.requests.at(-1);
  if (stage === "fetch") return { loading, finish: (body) => request.resolve(response(body)) };
  const json = deferred();
  const parsing = deferred();
  request.resolve({ ok: true, json() { parsing.resolve(); return json.promise; } });
  await parsing.promise;
  return { loading, finish: (body) => json.resolve(body) };
}

for (const stage of ["fetch", "JSON"]) {
  for (const settings of [true, false]) {
    for (const close of [false, true]) {
      test(`a pending note ${stage} read cannot take focus after ${settings ? "Settings" : "Filter"} ${close ? "opens and closes" : "opens"}`, async () => {
        const f = fixture();
        const before = f.cell.innerHTML;
        const pending = await pendingNoteRead(f, stage);
        const open = settings ? "openDisplaySettingsModal" : "openFilterModal";
        const dismiss = settings ? "closeDisplaySettingsModal" : "closeFilterModal";
        f.context[open]();
        if (close) f.context[dismiss]();
        const intendedFocus = f.context.document.activeElement;
        if (close) assert.equal(intendedFocus, f.focusOwner, "the real close handler restores the original focus owner");
        pending.finish({ user_note: "Saved note" });
        await pending.loading;
        assert.equal(f.inputs.length, 0, "obsolete reads must not create background editors");
        assert.equal(f.context.document.activeElement, intendedFocus);
        assert.equal(f.cell.innerHTML, before);
        assert.equal(f.saves.length, 0);
        assert.equal(f.toasts.length, 0);
        assert.equal(f.cell.dataset.noteLoading, undefined);
        assert.equal(f.listenerCount(), 0);
      });
    }
  }
}

const abandonNoteIntent = {
  "outside pointer": (f) => f.context.document.dispatch("pointerdown", { target: {} }),
  "focus move": (f) => f.focusable().focus(),
  "focus move and return": (f) => { f.focusable().focus(); f.focusOwner.focus(); },
  "keyboard Escape": (f) => f.context.document.dispatch("keydown", { key: "Escape" }),
  "keyboard Tab": (f) => f.context.document.dispatch("keydown", { key: "Tab" }),
  "keyboard row navigation": (f) => f.context.document.dispatch("keydown", { key: "ArrowDown" }),
  "tool change": (f) => f.context.setActiveTool("replay", { persist: false }),
  "proxy tab change": (f) => f.context.setActiveProxyTab("websockets-history", { persist: false }),
  "session change": (f) => { f.context.session = "another-session"; },
  "cell detach": (f) => { f.cell.isConnected = false; },
  "window blur": (f) => f.context.window.dispatch("blur"),
  "page hidden and shown": (f) => {
    f.context.document.visibilityState = "hidden";
    f.context.document.dispatch("visibilitychange");
    f.context.document.visibilityState = "visible";
  },
};

for (const [intent, abandon] of Object.entries(abandonNoteIntent)) {
  for (const stage of ["fetch", "JSON"]) {
    test(`a delayed note ${stage} read yields to ${intent}`, async () => {
      const f = fixture();
      const pending = await pendingNoteRead(f, stage);
      abandon(f);
      const intendedFocus = f.context.document.activeElement;
      pending.finish({ user_note: "Saved note" });
      await pending.loading;
      assert.equal(f.inputs.length, 0);
      assert.equal(f.context.document.activeElement, intendedFocus);
      assert.equal(f.saves.length, 0);
      assert.equal(f.toasts.length, 0);
      assert.equal(f.cell.dataset.noteLoading, undefined);
      assert.equal(f.listenerCount(), 0);
    });
  }
}

test("capture listeners cancel pending intent without intercepting the new action", async () => {
  const f = fixture();
  const pending = await pendingNoteRead(f);
  for (const type of ["pointerdown", "contextmenu", "focusin", "keydown"]) {
    const listeners = f.context.document.listeners.get(type);
    assert.ok(listeners?.size, `missing ${type} listener`);
    assert.ok(Array.from(listeners.values()).every((capture) => capture === true));
  }
  const event = f.context.document.dispatch("pointerdown", { target: {} });
  assert.equal(event.defaultPrevented, false);
  assert.equal(f.listenerCount(), 0, "cancel cleans up even if the read never settles");
  assert.equal(f.cell.dataset.noteLoading, undefined);
  pending.finish({ user_note: "Saved note" });
  await pending.loading;
  assert.equal(f.listenerCount(), 0);
});

test("an unchanged note intent opens normally after both asynchronous read stages", async () => {
  const f = fixture();
  const pending = await pendingNoteRead(f, "JSON");
  f.context.document.dispatch("pointerdown", { target: f.cell, button: 0 });
  f.focusOwner.focus();
  pending.finish({ user_note: "Full saved note" });
  await pending.loading;
  assert.equal(f.inputs.length, 1);
  assert.equal(f.inputs[0].value, "Full saved note");
  assert.equal(f.context.document.activeElement, f.inputs[0]);
  assert.equal(f.inputs[0].selected, true);
  assert.equal(f.listenerCount(), 0);
  assert.equal(f.cell.dataset.noteLoading, undefined);
  f.inputs[0].value = "New draft";
  f.inputs[0].dispatch("input");
  runTimers(f);
  assert.deepEqual(notes(f), ["New draft"]);
});

for (const stage of ["fetch", "JSON"]) {
  test(`a pending note ${stage} read yields to the same cell's production context menu handler`, async () => {
    const f = fixture();
    f.state.selectedRecord = f.item;
    const handler = appSource.match(/  els\.historyTableBody\.addEventListener\("contextmenu", \(event\) => \{[^]*?\n  \}\);/);
    assert.ok(handler, "the production history contextmenu handler must be used");
    vm.runInContext(handler[0], f.context);
    f.cell.closest = () => ({ dataset: { id: f.item.id } });
    const pending = await pendingNoteRead(f, stage);
    // A context menu can arrive without a secondary pointerdown (for example,
    // a long press). Dispatch capture before the real table handler as the DOM does.
    const event = { target: f.cell, clientX: 20, clientY: 30 };
    assert.equal(f.context.document.dispatch("contextmenu", event).defaultPrevented, false);
    assert.equal(f.context.els.historyTableBody.dispatch("contextmenu", event).defaultPrevented, true);
    assert.equal(f.context.els.contextMenu.classList.contains("hidden"), false);
    assert.equal(f.context.contextMenuTargetId, f.item.id);
    assert.equal(f.context.document.activeElement, f.focusOwner, "opening this menu does not move focus");
    pending.finish({ user_note: "Saved note" });
    await pending.loading;
    assert.equal(f.inputs.length, 0);
    assert.equal(f.context.document.activeElement, f.focusOwner);
    assert.equal(f.context.els.contextMenu.classList.contains("hidden"), false);
    assert.equal(f.saves.length, 0);
    assert.equal(f.toasts.length, 0);
    assert.equal(f.cell.dataset.noteLoading, undefined);
    assert.equal(f.listenerCount(), 0);
  });
}

for (const button of [1, 2]) {
  test(`a same-cell pointer button ${button} cancels before any later context menu event`, async () => {
    const f = fixture();
    const pending = await pendingNoteRead(f, "JSON");
    const event = f.context.document.dispatch("pointerdown", { target: f.cell, button });
    assert.equal(event.defaultPrevented, false);
    assert.equal(f.listenerCount(), 0);
    pending.finish({ user_note: "Saved note" });
    await pending.loading;
    assert.equal(f.inputs.length, 0);
    assert.equal(f.cell.dataset.noteLoading, undefined);
    assert.equal(f.context.document.activeElement, f.focusOwner);
  });
}

for (const finishOldFirst of [true, false]) {
  test(`superseded note reads preserve the newer editor when the older read finishes ${finishOldFirst ? "first" : "last"}`, async () => {
    const f = fixture();
    const first = await pendingNoteRead(f, "JSON");
    const secondCell = noteCell();
    f.cells.push(secondCell);
    const second = await pendingNoteRead(f, "JSON", secondCell, "second-record");
    const finishFirst = async () => { first.finish({ user_note: "Old note" }); await first.loading; };
    const finishSecond = async () => { second.finish({ user_note: "Second note" }); await second.loading; };
    if (finishOldFirst) {
      await finishFirst();
      assert.equal(f.inputs.length, 0);
      assert.equal(secondCell.dataset.noteLoading, "true");
      await finishSecond();
    } else {
      await finishSecond();
      f.inputs[0].value = "Current unsaved draft";
      await finishFirst();
      assert.equal(f.inputs[0].value, "Current unsaved draft");
    }
    assert.equal(f.inputs.length, 1);
    assert.equal(f.context.document.activeElement, secondCell.querySelector());
    assert.equal(f.cell.querySelector(), null);
    assert.equal(f.saves.length, 0);
    assert.equal(f.listenerCount(), 0);
  });
}

test("a cancelled same-cell read cannot clear a newer loading marker or duplicate its listeners", async () => {
  const f = fixture();
  const first = await pendingNoteRead(f, "JSON");
  f.context.document.dispatch("keydown", { key: "Escape" });
  assert.equal(f.cell.dataset.noteLoading, undefined);
  assert.equal(f.listenerCount(), 0);
  const second = await pendingNoteRead(f, "JSON");
  const listenerCount = f.listenerCount();
  assert.ok(listenerCount > 0);
  first.finish({ user_note: "Obsolete note" });
  await first.loading;
  assert.equal(f.cell.dataset.noteLoading, "true");
  assert.equal(f.listenerCount(), listenerCount);
  assert.equal(f.inputs.length, 0);
  await f.context.beginNoteEdit(f.cell, "fixture-record");
  assert.equal(f.requests.length, 2, "the newer pending read still blocks duplicate opens");
  second.finish({ user_note: "Current note" });
  await second.loading;
  assert.equal(f.inputs.length, 1);
  assert.equal(f.inputs[0].value, "Current note");
  assert.equal(f.cell.dataset.noteLoading, undefined);
  assert.equal(f.listenerCount(), 0);
});

for (const stage of ["fetch", "JSON", "error text"]) {
  test(`obsolete note ${stage} failures do not replace the current UI with a toast`, async () => {
    const f = fixture();
    const loading = f.context.beginNoteEdit(f.cell, "fixture-record");
    let fail = () => f.requests[0].reject(new Error("Obsolete read failure"));
    if (stage !== "fetch") {
      const parsing = deferred();
      const body = deferred();
      f.requests[0].resolve(stage === "JSON"
        ? { ok: true, json() { parsing.resolve(); return body.promise; } }
        : { ...failedResponse(), text() { parsing.resolve(); return body.promise; } });
      await parsing.promise;
      fail = stage === "JSON" ? () => body.reject(new Error("Invalid JSON")) : () => body.resolve("Old error");
    }
    f.context.openDisplaySettingsModal();
    f.context.closeDisplaySettingsModal();
    fail();
    await loading;
    assert.equal(f.toasts.length, 0);
    assert.equal(f.inputs.length, 0);
    assert.equal(f.cell.dataset.noteLoading, undefined);
    assert.equal(f.listenerCount(), 0);
  });
}

for (const failure of ["server", "missing record", "network", "invalid JSON"]) {
  test(`note ${failure} read failure preserves the cell and does not open an empty editor`, async () => {
    const f = fixture();
    const before = f.cell.innerHTML;
    const loading = f.context.beginNoteEdit(f.cell, "fixture-record");
    if (failure === "network") f.requests[0].reject(new Error("Connection lost"));
    else if (failure === "invalid JSON") f.requests[0].resolve({ ok: true, json: async () => { throw new Error("Invalid response"); } });
    else f.requests[0].resolve(failedResponse(failure === "server" ? 500 : 404));
    await loading;
    assert.equal(f.inputs.length, 0, "unknown saved content must not be presented as empty");
    assert.equal(f.cell.innerHTML, before);
    assert.equal(f.saves.length, 0);
    assert.equal(f.toasts.length, 1, "read failure must be visible");
    assert.equal(f.toasts[0][1], "error");
    assert.equal(f.listenerCount(), 0);
  });
}

for (const leave of ["session", "cell"]) {
  test(`note read failure after leaving the ${leave} does not show an obsolete error`, async () => {
    const f = fixture();
    const loading = f.context.beginNoteEdit(f.cell, "fixture-record");
    if (leave === "session") f.context.session = "another-session";
    else f.cell.isConnected = false;
    f.requests[0].resolve(failedResponse());
    await loading;
    assert.equal(f.inputs.length, 0);
    assert.equal(f.toasts.length, 0);
  });
}

test("retrying a failed note read loads the full saved note before editing", async () => {
  const f = fixture();
  let loading = f.context.beginNoteEdit(f.cell, "fixture-record");
  f.requests[0].resolve(failedResponse());
  await loading;
  loading = f.context.beginNoteEdit(f.cell, "fixture-record");
  assert.equal(f.requests.length, 2, "failed read must allow a clean retry");
  f.requests[1].resolve(response({ user_note: "Saved note beyond the preview" }));
  await loading;
  assert.equal(f.inputs.at(-1).value, "Saved note beyond the preview");
  f.inputs.at(-1).dispatch("blur");
  assert.equal(f.saves.length, 0, "unmodified note must not be overwritten");
});

test("a repeated note open cannot start a second read or replace the current draft", async () => {
  const f = fixture();
  const loading = f.context.beginNoteEdit(f.cell, "fixture-record");
  const repeated = f.context.beginNoteEdit(f.cell, "fixture-record");
  for (const request of f.requests) request.resolve(response({ user_note: "Saved note" }));
  await Promise.all([loading, repeated]);
  assert.equal(f.requests.length, 1, "the current cell must have only one pending read");
  f.inputs[0].value = "In-progress draft";
  await f.context.beginNoteEdit(f.cell, "fixture-record");
  assert.equal(f.requests.length, 1);
  assert.equal(f.inputs.length, 1);
  assert.equal(f.inputs[0].value, "In-progress draft");
});

test("a genuinely empty note remains editable and saves to its original session", async () => {
  const f = fixture();
  const loading = f.context.beginNoteEdit(f.cell, "fixture-record");
  f.requests[0].resolve(response());
  await loading;
  assert.equal(f.inputs[0].value, "");
  f.inputs[0].value = "  New note 文 😀  ";
  f.inputs[0].dispatch("keydown", "Enter");
  f.inputs[0].dispatch("blur");
  assert.equal(f.saves.length, 1);
  assert.equal(f.saves[0][1].user_note, "New note 文 😀");
  assert.equal(f.saves[0][2], "fixture-session");
});

test("note input respects the UTF-8 byte limit without splitting a character", async () => {
  const f = fixture();
  const loading = f.context.beginNoteEdit(f.cell, "fixture-record");
  f.requests[0].resolve(response());
  await loading;
  const value = "a".repeat(32764) + "😀";
  f.inputs[0].value = value + "extra";
  f.inputs[0].dispatch("input");
  assert.equal(f.inputs[0].value, value);
  assert.equal(Buffer.byteLength(f.inputs[0].value), 32768);
  f.inputs[0].dispatch("keydown", "Enter");
  assert.equal(f.saves[0][1].user_note, value);
  assert.equal(f.timers.size, 0);
});

test("Escape before autosave keeps the existing note", async () => {
  const f = fixture();
  const before = f.cell.innerHTML;
  const loading = f.context.beginNoteEdit(f.cell, "fixture-record");
  f.requests[0].resolve(response({ user_note: "Saved note" }));
  await loading;
  f.inputs[0].value = "Uncommitted";
  f.inputs[0].dispatch("input");
  f.inputs[0].dispatch("keydown", "Escape");
  f.inputs[0].dispatch("blur");
  assert.equal(f.cell.innerHTML, before);
  assert.equal(f.saves.length, 0);
  assert.equal(f.timers.size, 0);
});

for (const invalid of [null, [], "not a record", { user_note: 123 }, { user_note: {} }]) {
  test(`malformed note response ${JSON.stringify(invalid)} preserves the cell`, async () => {
    const f = fixture();
    const before = f.cell.innerHTML;
    const loading = f.context.beginNoteEdit(f.cell, "fixture-record");
    f.requests[0].resolve(response(invalid));
    await loading;
    assert.equal(f.inputs.length, 0);
    assert.equal(f.cell.innerHTML, before);
    assert.equal(f.toasts.length, 1);
    assert.equal(f.saves.length, 0);
    assert.equal(f.cell.dataset.noteLoading, undefined);
  });
}

for (const key of ["Enter", "Escape"]) {
  for (const flags of [{ isComposing: true }, { isComposing: false, keyCode: 229 }]) {
    test(`note ${key} belongs to the IME while composing: ${JSON.stringify(flags)}`, async () => {
      const f = fixture();
      const input = await openSavedNote(f);
      input.dispatch("compositionstart");
      input.value = "にほん";
      input.dispatch("input", undefined, { isComposing: true });
      const event = input.dispatch("keydown", key, flags);
      assert.equal(event.defaultPrevented, false, "the IME must receive its confirmation/cancel key");
      assert.equal(f.cell.querySelector(), input, "composition must not close the editor");
      runTimers(f);
      assert.deepEqual(notes(f), ["にほん"], "what is typed is kept while the IME still owns it");
      assert.equal(f.cell.querySelector(), input, "an autosave must not close the editor");
      assert.equal(input.value, "にほん");
    });
  }
}

for (const finalInputOrder of ["before-end", "after-end", "no-final-input"]) {
  test(`note composition autosaves final Japanese text when input is ${finalInputOrder}`, async () => {
    const f = fixture();
    const input = await openSavedNote(f);
    input.value = "Before composition";
    input.dispatch("input");
    input.dispatch("compositionstart");
    runTimers(f);
    assert.equal(f.saves.length, 0, "a prior debounce must stop when composition starts");
    input.value = "にほん";
    input.dispatch("input", undefined, { isComposing: true });
    runTimers(f);
    assert.deepEqual(notes(f), ["にほん"], "a pause mid-composition keeps the candidate");
    input.value = "日本";
    if (finalInputOrder === "before-end") input.dispatch("input", undefined, { isComposing: true });
    input.dispatch("compositionend");
    if (finalInputOrder === "after-end") input.dispatch("input", undefined, { isComposing: false });
    assert.equal(f.saves.length, 1, "composition completion preserves the autosave debounce");
    runTimers(f);
    assert.deepEqual(notes(f), ["にほん", "日本"], "the final text replaces the candidate");
    input.dispatch("blur");
    assert.equal(f.saves.length, 2, "blur must not duplicate an acknowledged draft");
  });
}

for (const key of ["Enter", "Escape"]) {
  for (const flags of [{ isComposing: true }, { isComposing: false, keyCode: 229 }]) {
    test(`note ${key} still belongs to the IME just after compositionend: ${JSON.stringify(flags)}`, async () => {
      const f = fixture();
      const input = await openSavedNote(f);
      input.dispatch("compositionstart");
      input.value = "にほん";
      input.dispatch("compositionend");
      const event = input.dispatch("keydown", key, flags);
      assert.equal(event.defaultPrevented, false);
      assert.equal(f.cell.querySelector(), input);
      assert.equal(f.saves.length, 0);
      input.value = "日本";
      input.dispatch("input", undefined, { isComposing: false });
      runTimers(f);
      assert.equal(f.saves.length, 1);
      assert.equal(f.saves[0][1].user_note, "日本");
    });
  }
}

// Korean makes each syllable its own composition and leaves the last one open
// until the next key, so a pause there is when typed text has to be kept: a
// redraw or a closed window would otherwise take the whole note with it.
test("note Korean text is saved while its last syllable is still composing", async () => {
  const f = fixture();
  const input = await openSavedNote(f);
  for (const text of ["로", "로그", "로그인"]) {
    input.dispatch("compositionstart");
    input.value = text;
    input.dispatch("input", undefined, { isComposing: true });
    if (text !== "로그인") input.dispatch("compositionend");
  }
  assert.equal(f.saves.length, 0, "typing without a pause saves nothing yet");
  runTimers(f);
  assert.deepEqual(notes(f), ["로그인"]);
  assert.equal(f.cell.querySelector(), input, "the editor stays open for the IME");
  assert.equal(input.value, "로그인");
  input.dispatch("compositionend");
  runTimers(f);
  assert.deepEqual(notes(f), ["로그인"], "the finished syllable is not saved twice");
});

for (const finalInputOrder of ["before-end", "after-end"]) {
  test(`note blur during composition waits for final text with input ${finalInputOrder}`, async () => {
    const f = fixture();
    const input = await openSavedNote(f);
    input.dispatch("compositionstart");
    input.value = "にほん";
    input.dispatch("input", undefined, { isComposing: true });
    input.dispatch("blur");
    input.dispatch("blur");
    runTimers(f);
    assert.equal(f.saves.length, 0, "blur must not persist an unfinished candidate");
    assert.equal(f.cell.querySelector(), input);
    if (finalInputOrder === "before-end") {
      input.value = "日本";
      input.dispatch("input", undefined, { isComposing: true });
    }
    input.dispatch("compositionend");
    if (finalInputOrder === "after-end") {
      input.value = "日本";
      input.dispatch("input", undefined, { isComposing: false });
    }
    runTimers(f);
    assert.equal(f.cell.querySelector(), null);
    assert.equal(f.saves.length, 1);
    assert.equal(f.saves[0][1].user_note, "日本");
    input.dispatch("blur");
    input.dispatch("compositionend");
    runTimers(f);
    assert.equal(f.saves.length, 1);
    assert.equal(f.timers.size, 0);
  });
}

for (const blurredWhileComposing of [false, true]) {
  test(`note blur between compositionend and final input waits for final text (earlier blur: ${blurredWhileComposing})`, async () => {
    const f = fixture();
    const input = await openSavedNote(f);
    input.dispatch("compositionstart");
    input.value = "にほん";
    input.dispatch("input", undefined, { isComposing: true });
    if (blurredWhileComposing) input.dispatch("blur");
    input.dispatch("compositionend");
    input.dispatch("blur");
    assert.equal(f.saves.length, 0, "a second blur must not bypass final-input deferral");
    assert.equal(f.cell.querySelector(), input);
    input.value = "日本";
    input.dispatch("input", undefined, { isComposing: false });
    runTimers(f);
    assert.equal(f.saves.length, 1);
    assert.equal(f.saves[0][1].user_note, "日本");
    assert.equal(f.cell.querySelector(), null);
  });
}

test("note does not truncate an IME candidate before composition ends", async () => {
  const f = fixture();
  const input = await openSavedNote(f);
  input.dispatch("compositionstart");
  const finalValue = "a".repeat(32764) + "😀";
  input.value = finalValue + "文";
  input.dispatch("input", undefined, { isComposing: true });
  assert.equal(input.value, finalValue + "文", "rewriting input.value interrupts IME composition");
  assert.equal(f.saves.length, 0);
  input.dispatch("compositionend");
  runTimers(f);
  assert.equal(input.value, finalValue);
  assert.equal(f.saves[0][1].user_note, finalValue);
});

test("note Escape after composition cancels its pending autosave and late events", async () => {
  const f = fixture();
  const before = f.cell.innerHTML;
  const input = await openSavedNote(f);
  input.dispatch("compositionstart");
  input.value = "日本";
  input.dispatch("compositionend");
  input.dispatch("keydown", "Escape", { isComposing: false });
  input.dispatch("input", undefined, { isComposing: false });
  input.dispatch("compositionend");
  input.dispatch("blur");
  runTimers(f);
  assert.equal(f.cell.innerHTML, before);
  assert.equal(f.saves.length, 0);
  assert.equal(f.timers.size, 0);
});

test("note ordinary Enter after composition commits final text exactly once", async () => {
  const f = fixture();
  const input = await openSavedNote(f);
  input.dispatch("compositionstart");
  input.value = "한국어";
  input.dispatch("compositionend");
  input.dispatch("keydown", "Enter", { isComposing: false });
  input.dispatch("blur");
  input.dispatch("compositionend");
  runTimers(f);
  assert.equal(f.saves.length, 1);
  assert.equal(f.saves[0][1].user_note, "한국어");
  assert.equal(f.timers.size, 0);
});

for (const acknowledgementFirst of [false, true]) {
  test(`live completion preserves a composing note editor ${acknowledgementFirst ? "after a clear acknowledgement" : "before its first save"}`, async () => {
    const f = fixture({ joinAnnotations: true });
    f.state.filterSettings.onlyNotes = true;
    Object.assign(f.item, { method: "GET", status: 200, note_count: 1 });
    const input = await openSavedNote(f);
    if (acknowledgementFirst) {
      input.value = ""; input.dispatch("input"); runTimers(f);
      await acknowledgeAnnotation(f, annotationRequests(f)[0]);
    } else {
      f.item.has_user_note = false;
    }
    input.dispatch("compositionstart");
    input.value = "한글"; input.dispatch("input", undefined, { isComposing: true });
    f.context._pendingTransactionSummaries.push({ sessionId: f.context.session, summary: { ...f.item, note_count: 0 } });
    f.context.flushTransactionDeltas();
    assert.equal(f.state.items.length, 0);
    assert.equal(f.state.historyPaging.filteredTotal, 0);
    assert.equal(f.cell.querySelector(), input, "completion must not detach the IME input");
    assert.equal(input.value, "한글");
    assert.ok(f.state._historyNoteEditWindow, "live filtering preserves the editor's row recovery");
    input.dispatch("compositionend"); runTimers(f);
    await acknowledgeAnnotation(f, annotationRequests(f).at(-1));
    assert.equal(f.state.items.length, 1);
    assert.equal(f.state.items[0].note_preview, "한글");
    assert.equal(f.state.historyPaging.filteredTotal, 1);
    assert.equal(f.state.historyPaging.total, 1);
    input.dispatch("blur");
  });
}

test("unrelated live completion preserves a filtered composing editor's recovery", async () => {
  const f = fixture({ joinAnnotations: true });
  f.state.filterSettings.onlyNotes = true;
  Object.assign(f.item, { method: "GET", status: 200, note_count: 1, has_user_note: false });
  const other = { id: "other-record", sequence: 2, method: "GET", status: 200, note_count: 1, has_user_note: true, note_preview: "Other" };
  f.state.items.push(other); f.context.rebuildHistoryItemIndex();
  Object.assign(f.state.historyPaging, { total: 2, filteredTotal: 2, offset: 2 });
  const input = await openSavedNote(f, "");
  input.dispatch("compositionstart");
  input.value = "한글"; input.dispatch("input", undefined, { isComposing: true });
  f.context._pendingTransactionSummaries.push({ sessionId: f.context.session, summary: { ...f.item, note_count: 0 } });
  f.context.flushTransactionDeltas();
  assert.equal(f.state.items.length, 1);
  f.context._pendingTransactionSummaries.push({ sessionId: f.context.session, summary: { ...other, response_bytes: 42 } });
  f.context.flushTransactionDeltas();
  assert.equal(f.cell.querySelector(), input);
  input.dispatch("compositionend"); runTimers(f);
  await acknowledgeAnnotation(f, annotationRequests(f).at(-1));
  assert.equal(f.state.items.length, 2, "saved nonempty note must restore its matching row after unrelated completion");
  assert.equal(f.context.getHistoryItem(f.item.id).note_preview, "한글");
});
