// Offline passive note editing checks. No app startup, API, or captured data.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function fixture() {
  const requests = [], inputs = [], saves = [], toasts = [], timers = new Map();
  let nextTimer = 0;
  let html = '<span class="note-text">Saved note</span>';
  let input = null;
  const cell = {
    isConnected: true, dataset: {},
    get innerHTML() { return html; },
    set innerHTML(value) { html = value; input = null; },
    querySelector() { return input; },
    appendChild(value) { input = value; },
  };
  const context = loadFunctions([
    "beginNoteEdit", "requireOkResponse", "readApiErrorMessage", "formatStructuredApiErrorMessage",
    "truncateUtf8", "truncateUtf8Preview", "utf8ByteLength",
  ], {
    session: "fixture-session", MAX_ANNOTATION_NOTE_BYTES: 32 * 1024, TextEncoder,
    closeContextMenu() {},
    transactionPath: (id, session) => `fixture-only:${session}/${id}`,
    fetch(url) { const request = { url, ...deferred() }; requests.push(request); return request.promise; },
    showToast(...args) { toasts.push(args); },
    updateAnnotations(...args) { saves.push(args); },
    window: {
      setTimeout(callback) { const id = ++nextTimer; timers.set(id, callback); return id; },
      clearTimeout(id) { timers.delete(id); },
    },
    document: {
      createElement(tag) {
        assert.equal(tag, "input");
        const listeners = {};
        const created = {
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
  return { context, cell, requests, inputs, saves, toasts, timers };
}

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
      assert.equal(f.saves.length, 0, "interim composition must not be saved");
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
    assert.equal(f.saves.length, 0);
    input.value = "日本";
    if (finalInputOrder === "before-end") input.dispatch("input", undefined, { isComposing: true });
    input.dispatch("compositionend");
    if (finalInputOrder === "after-end") input.dispatch("input", undefined, { isComposing: false });
    assert.equal(f.saves.length, 0, "composition completion preserves the autosave debounce");
    runTimers(f);
    assert.equal(f.saves.length, 1);
    assert.equal(f.saves[0][1].user_note, "日本");
    input.dispatch("blur");
    assert.equal(f.saves.length, 1, "blur must not duplicate an acknowledged draft");
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

test("note successive Korean compositions cancel the previous autosave", async () => {
  const f = fixture();
  const input = await openSavedNote(f);
  for (const syllable of ["ㅎ", "한"]) {
    input.dispatch("compositionstart");
    input.value = syllable;
    input.dispatch("input", undefined, { isComposing: true });
    runTimers(f);
    assert.equal(f.saves.length, 0);
    input.dispatch("compositionend");
  }
  runTimers(f);
  assert.equal(f.saves.length, 1);
  assert.equal(f.saves[0][1].user_note, "한");
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
