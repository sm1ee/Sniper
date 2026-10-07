// Offline passive note editing checks. No app startup, API, or captured data.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

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
  };
}

function fixture({ joinAnnotations = false } = {}) {
  const requests = [], inputs = [], saves = [], toasts = [], timers = new Map();
  const historyWrites = [], detailWrites = [];
  const item = { id: "fixture-record", sequence: 1, has_user_note: true, note_preview: "Saved note" };
  const state = {
    items: [item], _itemById: new Map([[item.id, item]]), _itemsVersion: 0,
    historyPaging: { fullyLoaded: true, total: 1, filteredTotal: 1 },
    historyColumnOrder: ["notes"], filterSettings: {}, sortKey: "index", sortDirection: "desc",
  };
  const shell = { clientHeight: 500, scrollTop: 0 };
  let clientVersion = 0;
  let nextTimer = 0;
  const cell = noteCell();
  const cells = [cell];
  const functions = [
    "beginNoteEdit", "requireOkResponse", "readApiErrorMessage", "formatStructuredApiErrorMessage",
    "truncateUtf8", "truncateUtf8Preview", "utf8ByteLength",
  ];
  if (joinAnnotations) functions.push(
    "updateAnnotations", "flushPendingAnnotations", "renderHistory", "getHistoryRowHeight", "renderHistoryVirtual",
    "renderHistoryCell", "escapeHtml", "isSessionEmpty", "historyEmptyMessage",
    "rebuildHistoryItemIndex", "getHistoryItemIndex", "resortLoadedHistoryItemsForCurrentSort",
    "visibleHistoryNoteCount", "compareHistorySequence",
  );
  const context = loadFunctions(functions, {
    session: "fixture-session", MAX_ANNOTATION_NOTE_BYTES: 32 * 1024, TextEncoder,
    closeContextMenu() {},
    transactionPath: (id, session) => `fixture-only:${session}/${id}`,
    fetch(url, options) { const request = { url, options, ...deferred() }; requests.push(request); return request.promise; },
    showToast(...args) { toasts.push(args); },
    updateAnnotations(...args) { saves.push(args); },
    state, annotationClientId: "fixture-client", nextAnnotationClientVersion: () => ++clientVersion,
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
    renderDetail(record) { detailWrites.push({ ...record }); },
    els: {
      historyMeta: {}, historyTable: { closest: () => shell },
      historyTableBody: {
        querySelector(selector) {
          return cells.find((entry) => entry.isConnected && entry.querySelector(selector))?.querySelector(selector) || null;
        },
        set innerHTML(value) { historyWrites.push(value); cells.forEach((entry) => { entry.isConnected = false; }); },
      },
    },
    window: {
      setTimeout(callback) { const id = ++nextTimer; timers.set(id, callback); return id; },
      clearTimeout(id) { timers.delete(id); },
    },
    document: {
      createElement(tag) {
        assert.equal(tag, "input");
        const listeners = {};
        const created = {
          dataset: {},
          addEventListener(type, callback) { listeners[type] = callback; },
          focus() {}, select() {},
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
  context.currentSessionId = () => context.session;
  context.rebuildHistoryItemIndex();
  return { context, cell, cells, requests, inputs, saves, toasts, timers, state, item, historyWrites, detailWrites };
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
  assert.match(f.context.els.historyMeta.textContent, /1 loaded item\(s\) visible/);
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
  assert.match(f.context.els.historyMeta.textContent, /2 loaded item\(s\) visible/);
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
  assert.match(f.context.els.historyMeta.textContent, /0 loaded item\(s\) visible.*notes only/);
  assert.equal(f.historyWrites.length, 0, "even an empty-list acknowledgement must defer tbody replacement");
  assert.equal(f.cell.isConnected, true);
  input.dispatch("compositionend");
  runTimers(f);
  input.dispatch("blur");
  assert.equal(f.historyWrites.length, 1);
  assert.match(f.historyWrites[0], /No traffic matches/);
  assert.equal(annotationRequests(f).length, 1);
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
