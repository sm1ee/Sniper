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
          dispatch(type, key) { listeners[type]?.({ key, stopPropagation() {}, preventDefault() {} }); },
        };
        inputs.push(created);
        return created;
      },
    },
  });
  context.currentSessionId = () => context.session;
  return { context, cell, requests, inputs, saves, toasts, timers };
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
