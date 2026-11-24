// Saved note/settings metadata only. Actual frontend handlers and the native
// wrapper run in a VM; fetch, timers, IPC and other lifecycle steps are inert.
// Live editors include unfired debounces and IME transitions; detached drafts
// are deliberately outside this live-DOM guard's contract.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const desktopSource = fs.readFileSync(path.join(__dirname, "../src/bin/sniper-desktop.rs"), "utf8")
  .replace(/\r\n/g, "\n");
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function nativeCloseScript(generation) {
  const template = desktopSource.match(/fn desktop_close_flush_script\(generation: u64\)[^]*?r#"([^]*?)"#/);
  assert.ok(template, "Missing native close wrapper");
  let script = template[1].replaceAll("{{", "{").replaceAll("}}", "}");
  for (const name of ["DESKTOP_CLOSE_FLUSH_OK_PREFIX", "DESKTOP_CLOSE_FLUSH_ERROR_PREFIX"]) {
    const prefix = desktopSource.match(new RegExp(`const ${name}: &str = "([^"]+)";`));
    assert.ok(prefix, `Missing ${name}`);
    script = script.replaceAll(`{${name}}`, prefix[1]);
  }
  return script.replaceAll("{generation}", String(generation));
}

function eventTarget() {
  const listeners = new Map();
  return {
    addEventListener(type, callback) {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type).add(callback);
    },
    removeEventListener(type, callback) { listeners.get(type)?.delete(callback); },
    dispatch(type, fields = {}) {
      const event = { type, target: this, stopPropagation() {}, preventDefault() {}, ...fields };
      for (const callback of listeners.get(type) || []) callback(event);
    },
  };
}

function fixture() {
  const requests = [], messages = [], timers = new Map(), lifecycleCalls = [], toasts = [];
  const cells = [], editorEffects = [], timerCalls = [];
  let timerId = 0, annotationVersion = 0;
  const state = {
    activeSession: { id: "synthetic-session-a" }, items: [], selectedRecord: null, historyPaging: {},
    _pendingAnnotations: new Map(), _annotationInFlight: new Set(),
    displaySettings: { sizePx: 12, theme: "paper", uiFont: "plex", monoFont: "jetbrains" },
    historyColumnWidths: {}, historyColumnOrder: [], wsColumnWidths: {},
  };
  const createCell = () => {
    let input = null, html = "Saved synthetic note";
    const cell = {
      isConnected: true, dataset: {},
      transactionId: cells.length ? `synthetic-note-${cells.length + 1}` : "synthetic-note",
      get innerHTML() { return html; },
      set innerHTML(value) {
        html = value;
        if (input) {
          input.parentElement = null;
          if (document.activeElement === input) document.activeElement = {};
        }
        input = null;
      },
      querySelector: () => input,
      appendChild(value) { input = value; value.parentElement = this; },
      contains(value) { return value === this || value === input; },
    };
    cells.push(cell);
    return cell;
  };
  const cell = createCell();
  const document = {
    ...eventTarget(), activeElement: {}, visibilityState: "visible",
    querySelectorAll(selector) {
      assert.equal(selector, "input.note-inline-input");
      return cells.filter(cell => cell.isConnected).map(cell => cell.querySelector(selector))
        .filter(input => input?.className === "note-inline-input");
    },
    createElement(tag) {
      assert.equal(tag, "input");
      return { ...eventTarget(), dataset: {}, parentElement: null, _value: "",
        get value() { return this._value; },
        // A text input strips line breaks when assigned a saved multiline note.
        set value(value) { this._value = String(value).replace(/[\r\n]/g, ""); },
        select() { editorEffects.push("select"); },
        focus() {
          editorEffects.push("focus");
          if (document.activeElement !== this) document.activeElement.blur?.();
          document.activeElement = this;
        },
        blur() {
          editorEffects.push("blur");
          if (document.activeElement === this) document.activeElement = {};
          this.dispatch("blur");
        },
      };
    },
  };
  const lifecycle = name => () => { lifecycleCalls.push(name); };
  const context = loadFunctions([
    "flushBeforeNativeClose", "flushAllPendingAnnotations", "updateAnnotations", "flushPendingAnnotations",
    "beginNoteEdit", "releaseHistoryNoteEdit", "inheritPendingHistoryNoteEdit", "requireOkResponse",
    "truncateUtf8", "truncateUtf8Preview", "utf8ByteLength",
    "currentSessionId", "sessionWritePath", "expectedActiveSessionIdForWrite",
    "persistUiSettings", "snapshotUiSettings", "nextUiSettingsSnapshot", "scheduleUiSettingsRetry",
    "updateUiSettingsServerRevision",
  ], {
    state, document, URLSearchParams, TextEncoder, workspaceStateGeneration: 0,
    annotationClientId: "synthetic-note-client", nextAnnotationClientVersion: () => ++annotationVersion,
    pendingHistoryNoteRead: null, MAX_ANNOTATION_NOTE_BYTES: 32 * 1024,
    uiSettingsClientId: "synthetic-settings-client", uiSettingsSaveVersion: 0, uiSettingsServerRevision: 3,
    uiSettingsSaveTimer: null, uiSettingsDirty: true, uiSettingsInFlight: false, uiSettingsSavePromise: null,
    lastUiSettingsPayload: null, displaySettingsReady: true, pendingDisplaySettingsApply: null,
    console: { error() {} }, showToast: (...args) => toasts.push(args),
    window: {
      ...eventTarget(), ipc: { postMessage: message => messages.push(message) },
      setTimeout(callback, delay) {
        timerCalls.push(["set", delay]);
        timers.set(++timerId, { callback, delay }); return timerId;
      },
      clearTimeout(id) { timerCalls.push(["clear", id]); timers.delete(id); },
    },
    fetch(url, options) {
      assert.ok((url === "fixture-only:note-read" && !options)
        || (url === "/api/ui-settings" && options?.method === "POST")
        || (/^\/api\/transactions\/synthetic-note(?:-\d+)?\/annotations\?/.test(url) && options?.method === "PATCH"),
      `Unexpected fixture fetch: ${url}`);
      const request = { url, options, ...deferred() };
      requests.push(request);
      return request.promise;
    },
    // No request, proxy, replay, WebSocket, sequence, scanner or native action
    // implementation is loaded. The native close function sees inert phases.
    flushProxySettingsSaveBeforeClose: lifecycle("proxy-settings"),
    flushSequenceDraft: lifecycle("sequence"),
    syncReplayDraftsBeforeWorkspaceClose: lifecycle("replay-drafts"),
    flushWsReplayTabsBeforeClose: lifecycle("websocket"),
    flushWorkspaceState: lifecycle("workspace"),
    transactionPath: () => "fixture-only:note-read", isHttpHistoryVisible: () => true,
    isModalVisible: () => false, closeContextMenu() {}, els: {},
    currentHistoryNoteEditWindow: () => null, getHistoryItemIndex: () => -1,
    observeAnnotationRevision() {}, loadTransactions: async () => {},
    sanitizeActiveTool: () => "proxy", sanitizeActiveProxyTab: () => "http-history",
    sanitizeHttpQuery: () => "", sanitizeHttpMethod: () => "", sanitizeHttpSortKey: () => "index",
    sanitizeHttpSortDirection: () => "desc", serializeHttpFilterSettings: () => ({}),
    serializeWorkbenchPaneWidths: () => ({}), sanitizeWebsocketQuery: () => "",
    sanitizeWebsocketSortKey: () => "started_at", sanitizeWebsocketSortDirection: () => "desc",
    updateDisplaySettingsReadiness() {},
    applyUiSettingsSnapshot() { assert.fail("No conflict snapshot is expected"); },
  });
  const hook = appSource.match(/^window\.__sniperFlushBeforeNativeClose = flushBeforeNativeClose;$/m);
  assert.ok(hook, "Missing native-close frontend hook");
  vm.runInContext(hook[0], context);

  const close = (generation = 42) => vm.runInContext(nativeCloseScript(generation), context);
  const settingsRequests = () => requests.filter(request => request.url === "/api/ui-settings");
  const annotationRequests = () => requests.filter(request => request.options?.method === "PATCH");
  const runTimer = delay => {
    const entry = [...timers].find(([, timer]) => timer.delay === delay);
    assert.ok(entry, `Missing ${delay} ms timer`);
    timers.delete(entry[0]); entry[1].callback();
  };
  const openNote = async (savedNote = "Saved synthetic note", targetCell = cell) => {
    const loading = context.beginNoteEdit(targetCell, targetCell.transactionId);
    requests.at(-1).resolve({ ok: true, json: async () => ({ user_note: savedNote }) });
    await loading;
    const input = targetCell.querySelector("input.note-inline-input");
    assert.ok(input);
    return input;
  };
  const typeNote = async (value = "Synthetic late note", targetCell = cell) => {
    const input = await openNote("Saved synthetic note", targetCell);
    input.value = value; input.dispatch("input");
    return input;
  };
  const completeSettings = () => {
    const request = settingsRequests().at(-1), payload = JSON.parse(request.options.body);
    request.resolve({ ok: true, json: async () => ({ ...payload, server_revision: 4 }) });
  };
  const completeNote = async (ok = true) => {
    annotationRequests().at(-1).resolve(ok
      ? { ok: true, json: async () => ({ id: "synthetic-note", annotation_revision: 1 }) }
      : { ok: false, text: async () => "Synthetic note save failure" });
    await tick();
  };
  const beginLateNote = async () => {
    await typeNote();
    assert.equal(state._pendingAnnotations.size, 0, "Editor debounce has not queued its note yet");
    const closing = close(); await tick();
    assert.equal(settingsRequests().length, 1);
    runTimer(500);
    assert.equal(annotationRequests().length, 1, "Actual note timer queues a PATCH during settings save");
    return { closing, entry: state._pendingAnnotations.get("synthetic-note") };
  };
  return { context, state, requests, messages, timers, lifecycleCalls, toasts, close, typeNote, runTimer,
    cell, createCell, document, openNote, editorEffects, timerCalls,
    settingsRequests, annotationRequests, completeSettings, completeNote, beginLateNote };
}

test("completed note PATCH and settings save permit native success", async () => {
  const f = fixture(); await f.typeNote(); f.runTimer(500); await f.completeNote();
  const closing = f.close(); await tick(); f.completeSettings(); await closing;
  assert.deepEqual(f.messages, ["sniper:native-close-flush-ok:42"]);
  assert.equal(f.state._pendingAnnotations.size, 0);
  assert.equal(f.state._annotationInFlight.size, 0);
  assert.equal(f.lifecycleCalls.length, 5);
});

for (const outcome of ["in-flight", "failed"]) {
  test(`late ${outcome} note refuses native success without retrying or consuming the edit`, async () => {
    const f = fixture(), { closing, entry } = await f.beginLateNote();
    if (outcome === "failed") await f.completeNote(false);
    f.completeSettings(); await closing;
    assert.match(f.messages[0], /^sniper:native-close-flush-error:42:/);
    assert.equal(f.messages.length, 1);
    assert.equal(f.state._pendingAnnotations.get("synthetic-note"), entry);
    assert.equal(entry.payload.user_note, "Synthetic late note");
    assert.equal(f.state._annotationInFlight.size, outcome === "in-flight" ? 1 : 0);
    assert.equal(f.annotationRequests().length, 1, "Final guard does not start another save");
    assert.equal(f.timers.size, 0, "Final guard does not add retry work");
  });
}

test("late acknowledged PATCH permits success without a redundant annotation write", async () => {
  const f = fixture(), { closing } = await f.beginLateNote();
  await f.completeNote(); f.completeSettings(); await closing;
  assert.deepEqual(f.messages, ["sniper:native-close-flush-ok:42"]);
  assert.equal(f.annotationRequests().length, 1);
  assert.equal(f.state._pendingAnnotations.size, 0);
});

test("subsequent close retries the preserved failed note and waits for its acknowledgement", async () => {
  const f = fixture(), { closing, entry } = await f.beginLateNote();
  await f.completeNote(false); f.completeSettings(); await closing;
  assert.match(f.messages[0], /^sniper:native-close-flush-error:42:/);
  const retry = f.close(43); await tick();
  assert.equal(f.messages.length, 1);
  assert.equal(f.annotationRequests().length, 2);
  assert.equal(f.annotationRequests()[1].options.body, JSON.stringify(entry.payload));
  await f.completeNote(); await retry;
  assert.equal(f.messages[1], "sniper:native-close-flush-ok:43");
  assert.equal(f.state._pendingAnnotations.size, 0);
  assert.equal(f.settingsRequests().length, 1, "Acknowledged settings are not saved again");
});

test("settings failure still refuses close and preserves its existing retry", async () => {
  const f = fixture(), closing = f.close(); await tick();
  f.settingsRequests()[0].resolve({ ok: false, text: async () => "Synthetic settings failure" });
  await closing;
  assert.deepEqual(f.messages, ["sniper:native-close-flush-error:42:Synthetic settings failure"]);
  assert.equal(f.context.uiSettingsDirty, true);
  assert.equal(f.context.uiSettingsInFlight, false);
  assert.equal([...f.timers.values()].filter(timer => timer.delay === 1000).length, 1);
});

for (const sameId of [false, true]) {
  test(`final guard preserves a new note after a ${sameId ? "generation" : "session"} change`, async () => {
    const f = fixture(), closing = f.close(); await tick();
    f.state.activeSession = { id: sameId ? "synthetic-session-a" : "synthetic-session-b" };
    f.context.workspaceStateGeneration++;
    await f.typeNote("Synthetic replacement note"); f.runTimer(500);
    const entry = f.state._pendingAnnotations.get("synthetic-note");
    const url = new URL(f.annotationRequests()[0].url, "http://example.com");
    assert.equal(url.searchParams.get("session_id"), f.state.activeSession.id);
    assert.equal(url.searchParams.has("expected_active_session_id"), false);
    f.completeSettings(); await closing;
    assert.match(f.messages[0], /^sniper:native-close-flush-error:42:/);
    assert.equal(f.state._pendingAnnotations.get("synthetic-note"), entry);
    assert.equal(entry.payload.user_note, "Synthetic replacement note");
    assert.equal(f.annotationRequests().length, 1);
  });
}

async function finishClose(f) {
  const closing = f.close();
  await tick();
  f.completeSettings();
  await closing;
}

function assertRefused(f) {
  assert.equal(f.messages.length, 1);
  assert.match(f.messages[0], /^sniper:native-close-flush-error:42:/);
}

function assertSucceeded(f) {
  assert.deepEqual(f.messages, ["sniper:native-close-flush-ok:42"]);
}

test("unfired dirty debounce refuses close without changing the editor or its save work", async () => {
  const f = fixture(), input = await f.typeNote();
  const closing = f.close(); await tick();
  assert.equal(f.state._pendingAnnotations.size, 0);
  assert.equal(f.state._annotationInFlight.size, 0);
  const timers = [...f.timers], timerCalls = [...f.timerCalls], effects = [...f.editorEffects];
  f.completeSettings(); await closing;
  assertRefused(f);
  assert.equal(f.annotationRequests().length, 0, "Close must not force-save a live draft");
  assert.deepEqual([...f.timers], timers, "The same unfired debounce remains scheduled");
  assert.deepEqual(f.timerCalls, timerCalls, "Final guard must not add, clear or fire timers");
  assert.deepEqual(f.editorEffects, effects, "Final guard must not focus, select or blur the input");
  assert.equal(f.document.activeElement, input);
  assert.equal(f.cell.querySelector("input.note-inline-input"), input);
  assert.equal(input.value, "Synthetic late note");
});

for (const scenario of [
  "compositionstart cancels a dirty debounce",
  "composing unchanged text",
  "compositionFinishing unchanged text",
  "acknowledged composing candidate",
  "acknowledged compositionFinishing candidate",
  "IME Escape keeps the editor composing",
]) {
  test(`${scenario} refuses native success`, async () => {
    const f = fixture();
    const input = scenario === "compositionstart cancels a dirty debounce"
      ? await f.typeNote() : await f.openNote();
    input.dispatch("compositionstart");
    if (scenario.includes("acknowledged")) {
      input.value = "Synthetic 日本 candidate";
      input.dispatch("input", { isComposing: true });
      f.runTimer(500); await f.completeNote();
      assert.equal(f.state._pendingAnnotations.size, 0);
      assert.equal(f.state._annotationInFlight.size, 0);
    }
    if (scenario.includes("compositionFinishing")) input.dispatch("compositionend");
    if (scenario.includes("IME Escape")) input.dispatch("keydown", { key: "Escape", isComposing: true });
    const value = input.value, timers = [...f.timers];
    await finishClose(f);
    assertRefused(f);
    assert.equal(f.cell.querySelector("input.note-inline-input"), input);
    assert.equal(input.value, value);
    assert.deepEqual([...f.timers], timers);
    assert.equal(f.annotationRequests().length, scenario.includes("acknowledged") ? 1 : 0);
  });
}

test("reading a composing over-limit candidate leaves its value and focus untouched", async () => {
  const f = fixture(), input = await f.openNote();
  input.dispatch("compositionstart");
  input.value = "🦊".repeat(8193);
  input.dispatch("input", { isComposing: true });
  const value = input.value, timers = [...f.timers], effects = [...f.editorEffects];
  await finishClose(f);
  assertRefused(f);
  assert.equal(input.value, value, "The guard must not truncate a live IME candidate");
  assert.equal(f.document.activeElement, input);
  assert.deepEqual([...f.timers], timers);
  assert.deepEqual(f.editorEffects, effects);
  assert.equal(f.annotationRequests().length, 0);
});

for (const scenario of ["unchanged", "whitespace only", "reverted before save", "saved CR/LF", "32 KiB Unicode"]) {
  test(`${scenario} live note permits close without a redundant PATCH`, async () => {
    const f = fixture();
    const saved = scenario === "saved CR/LF" ? "Saved\r\nsynthetic\nnote\r"
      : scenario === "32 KiB Unicode" ? "🦊".repeat(8192) : "Saved synthetic note";
    const input = await f.openNote(saved);
    if (scenario === "saved CR/LF") assert.equal(input.value, "Savedsyntheticnote");
    if (scenario === "32 KiB Unicode") assert.equal(new TextEncoder().encode(input.value).length, 32 * 1024);
    if (scenario === "whitespace only") {
      input.value = `  ${saved}  `; input.dispatch("input");
    } else if (scenario === "reverted before save") {
      input.value = "Temporary synthetic draft"; input.dispatch("input");
      input.value = saved; input.dispatch("input");
    }
    await finishClose(f);
    assertSucceeded(f);
    assert.equal(f.annotationRequests().length, 0);
    assert.equal(f.cell.querySelector("input.note-inline-input"), input);
  });
}

test("an unsaved edit at the 32 KiB Unicode boundary refuses close", async () => {
  const f = fixture(), input = await f.openNote("🦊".repeat(8192));
  input.value = "🦊".repeat(8191) + "🐇"; input.dispatch("input");
  assert.equal(new TextEncoder().encode(input.value).length, 32 * 1024);
  await finishClose(f);
  assertRefused(f);
  assert.equal(f.annotationRequests().length, 0);
  assert.equal(input.value, "🦊".repeat(8191) + "🐇");
});

for (const value of ["Saved synthetic note", "Newest synthetic draft"]) {
  test(`${value.startsWith("Saved") ? "revert" : "new text"} after an acknowledged save refuses close`, async () => {
    const f = fixture(), input = await f.typeNote("First saved edit");
    f.runTimer(500); await f.completeNote();
    assert.equal(f.state._pendingAnnotations.size, 0);
    input.value = value; input.dispatch("input");
    await finishClose(f);
    assertRefused(f);
    assert.equal(f.annotationRequests().length, 1);
    assert.equal(input.value, value);
    assert.equal([...f.timers.values()].filter(timer => timer.delay === 500).length, 1);
  });
}

for (const afterComposition of [false, true]) {
  test(`Escape ${afterComposition ? "after compositionend " : ""}settles and removes an unsaved editor`, async () => {
    const f = fixture(), input = await f.typeNote();
    if (afterComposition) {
      input.dispatch("compositionstart");
      input.dispatch("compositionend");
    }
    input.dispatch("keydown", { key: "Escape", isComposing: false });
    // Late events from the removed input must not revive its settled edit.
    input.dispatch("input"); input.dispatch("compositionstart"); input.dispatch("blur");
    assert.equal(f.document.querySelectorAll("input.note-inline-input").length, 0);
    assert.equal(input.parentElement, null);
    await finishClose(f);
    assertSucceeded(f);
    assert.equal(f.annotationRequests().length, 0);
    assert.equal(f.timers.size, 0);
  });
}

test("ordinary blur settles the editor and acknowledged cleanup permits close", async () => {
  const f = fixture(), input = await f.typeNote();
  input.blur(); await f.completeNote();
  assert.equal(f.document.querySelectorAll("input.note-inline-input").length, 0);
  await finishClose(f);
  assertSucceeded(f);
  assert.equal(f.annotationRequests().length, 1);
  assert.equal(f.timers.size, 0);
});

for (const pendingBlur of [false, true]) {
  test(`compositionend then ${pendingBlur ? "deferred blur" : "autosave"} timer and acknowledgement permit close`, async () => {
    const f = fixture(), input = await f.openNote();
    input.dispatch("compositionstart");
    input.value = "Synthetic にほん"; input.dispatch("input", { isComposing: true });
    if (pendingBlur) input.blur();
    input.value = "Synthetic 日本"; input.dispatch("compositionend");
    const closing = f.close(); await tick();
    f.runTimer(pendingBlur ? 0 : 500); await f.completeNote();
    f.completeSettings(); await closing;
    assertSucceeded(f);
    assert.equal(f.annotationRequests().length, 1);
    assert.equal(JSON.parse(f.annotationRequests()[0].options.body).user_note, "Synthetic 日本");
    assert.equal(f.document.querySelectorAll("input.note-inline-input").length, pendingBlur ? 0 : 1);
    assert.equal(f.timers.size, 0);
  });
}

for (const newEditor of [false, true]) {
  test(`${newEditor ? "new live editor" : "typing in an existing editor"} during settings await is checked at final close`, async () => {
    const f = fixture();
    let input = newEditor ? null : await f.openNote();
    const closing = f.close(); await tick();
    if (newEditor) input = await f.openNote();
    input.value = "Typed during synthetic settings save"; input.dispatch("input");
    f.completeSettings(); await closing;
    assertRefused(f);
    assert.equal(f.annotationRequests().length, 0);
    assert.equal(f.state._pendingAnnotations.size, 0);
    assert.equal(input.value, "Typed during synthetic settings save");
  });
}

test("a note read completed during settings await creates a live draft checked before success", async () => {
  const f = fixture();
  const reading = f.context.beginNoteEdit(f.cell, "synthetic-note"), request = f.requests.at(-1);
  const closing = f.close(); await tick();
  request.resolve({ ok: true, json: async () => ({ user_note: "Saved synthetic note" }) });
  await reading;
  const input = f.cell.querySelector("input.note-inline-input");
  input.value = "Late-opened synthetic draft"; input.dispatch("input");
  f.completeSettings(); await closing;
  assertRefused(f);
  assert.equal(f.annotationRequests().length, 0);
  assert.equal(input.value, "Late-opened synthetic draft");
});

for (const sameId of [false, true]) {
  test(`an unfired live note after a ${sameId ? "generation" : "session"} change still refuses close`, async () => {
    const f = fixture(), closing = f.close(); await tick();
    f.state.activeSession = { id: sameId ? "synthetic-session-a" : "synthetic-session-b" };
    f.context.workspaceStateGeneration++;
    const input = await f.typeNote("Replacement live synthetic draft");
    f.completeSettings(); await closing;
    assertRefused(f);
    assert.equal(f.annotationRequests().length, 0);
    assert.equal(f.state._pendingAnnotations.size, 0);
    assert.equal(f.document.activeElement, input);
    assert.equal([...f.timers.values()].filter(timer => timer.delay === 500).length, 1);
  });
}

for (const finishing of [false, true]) {
  test(`a ${finishing ? "composition-finishing" : "composing"} non-active draft among two live inputs refuses close`, async () => {
    const f = fixture(), input = await f.openNote();
    input.dispatch("compositionstart");
    input.value = "Non-active synthetic 日本 draft";
    input.dispatch("input", { isComposing: true });
    // Focus transfer blurs the first input, but its composition defers commit.
    const second = await f.openNote("Saved second synthetic note", f.createCell());
    if (finishing) input.dispatch("compositionend");
    assert.equal(f.document.activeElement, second);
    assert.equal(f.document.querySelectorAll("input.note-inline-input").length, 2);
    await finishClose(f);
    assertRefused(f);
    assert.equal(f.annotationRequests().length, 0);
    assert.equal(f.document.activeElement, second);
    assert.equal(f.cell.querySelector("input.note-inline-input"), input);
  });
}

test("detached unfired drafts remain outside the live-input close guard", async () => {
  const f = fixture(), input = await f.typeNote();
  f.cell.isConnected = false;
  assert.equal(f.document.querySelectorAll("input.note-inline-input").length, 0);
  await finishClose(f);
  assertSucceeded(f);
  assert.equal(f.annotationRequests().length, 0);
  assert.equal(input.value, "Synthetic late note");
  assert.equal([...f.timers.values()].filter(timer => timer.delay === 500).length, 1);
});

test("native rejection source returns to Wait before session persistence or teardown", () => {
  // Source contract only: never start the Rust executable, window or event loop.
  const start = desktopSource.indexOf("Event::UserEvent(DesktopUserEvent::WebviewCloseFlushFinished {");
  const end = desktopSource.indexOf("Event::UserEvent(DesktopUserEvent::WebviewCloseFlushTimedOut", start);
  assert.ok(start >= 0 && end > start);
  const handler = desktopSource.slice(start, end);
  assert.match(handler, /if !close_flush_in_progress \|\| generation != close_flush_generation \{\s+return;/);
  assert.match(handler, /close_flush_in_progress = false;\s+if !ok \{\s+\*control_flow = block_desktop_shutdown\([^]*?\);\s+return;\s+\}\s+match persist_desktop_session_state/);
  const blocker = desktopSource.match(/fn block_desktop_shutdown\([^]*?^\}/m)?.[0];
  assert.ok(blocker);
  assert.match(blocker, /ControlFlow::Wait\s+\}/);
  assert.doesNotMatch(blocker, /ControlFlow::Exit|teardown_once|persist_desktop_session_state/);
  const parser = desktopSource.match(/fn desktop_user_event_from_ipc\([^]*?^\}/m)?.[0];
  assert.match(parser, /strip_prefix\(DESKTOP_CLOSE_FLUSH_ERROR_PREFIX\)[^]*?ok: false/);
});
