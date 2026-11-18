// CodeMirror keeps "\n" between lines; a raw request needs its CRLF, CR and LF
// back byte for byte. Runs the production tracker on CodeMirror's EditorState
// in Node: no view, no app bootstrap.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const bundle = vm.createContext({ console, navigator: { userAgent: "node", platform: "MacIntel" }, window: {} });
vm.runInContext(`${fs.readFileSync(path.join(__dirname, "../web/codemirror.bundle.js"), "utf8")}\nthis.CM = CM;`, bundle);
const CM = bundle.CM;
const endings = loadFunctions(["createLineEndingTracker"], { CM }).createLineEndingTracker();

function opened(text) {
  return CM.EditorState.create({ doc: text, extensions: [endings.field] }).update({ effects: endings.record(text) }).state;
}
const edit = (state, changes) => state.update({ changes }).state;

test("a document gives back each line break as it came in", () => {
  const upload = "POST /upload HTTP/1.1\nContent-Type: multipart/form-data; boundary=b\n\n"
    + "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.png\"\r\n\r\n"
    + "\x89PNG\r\n\x1a\n\x00\r\xff\r\n--b--\r\n";
  assert.equal(endings.text(opened(upload)), upload);
  for (const text of ["", "\n", "\r", "\r\n", "\n\r", "\r\r\n\n", "no break"]) {
    assert.equal(endings.text(opened(text)), text, JSON.stringify(text));
  }
});

test("edits keep the endings around them", () => {
  // The document CodeMirror holds is "a\nb\nc\nd".
  let state = opened("a\r\nb\r\nc\nd");
  state = edit(state, { from: 2, to: 3, insert: "filename" });
  assert.equal(endings.text(state), "a\r\nfilename\r\nc\nd");
  state = edit(state, { from: 10, insert: "\n" });
  assert.equal(endings.text(state), "a\r\nfilename\r\n\r\nc\nd", "typed after a CRLF break");
  state = edit(state, { from: state.doc.length, insert: "\nnew" });
  assert.equal(endings.text(state), "a\r\nfilename\r\n\r\nc\nd\nnew", "typed after an LF break");
});

test("a typed break takes the ending of the break after it, so a multipart body keeps CRLF", () => {
  // The head's lines end in LF and the body's in CRLF; the document is "H\n\n--b\nX\n--b--\n".
  let state = opened("H\n\n--b\r\nX\r\n--b--\r\n");
  state = edit(state, { from: 6, insert: "\n" });
  assert.equal(endings.text(state), "H\n\n--b\r\n\r\nX\r\n--b--\r\n", "Enter at the end of the first body line");
  state = edit(state, { from: 3, insert: "--b\nContent-Disposition: form-data; name=\"x\"\n\nnew\n" });
  assert.equal(endings.text(state),
    "H\n\n--b\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nnew\r\n--b\r\n\r\nX\r\n--b--\r\n", "a part typed at the top");
});

test("Undo and Redo give back the endings of the text they return to", () => {
  const text = "a\rb\r\nc\nd";
  let state = CM.EditorState.create({ doc: text, extensions: [endings.field, endings.undoable, CM.history({ newGroupDelay: 0 })] })
    .update({ effects: endings.record(text) }).state;
  const target = { get state() { return state; }, dispatch(transaction) { state = transaction.state; } };
  // The document is "a\nb\nc\nd": delete "\nb\n", a CR and a CRLF.
  state = edit(state, { from: 1, to: 4 });
  assert.equal(endings.text(state), "ac\nd");
  assert.equal(CM.undo(target), true);
  assert.equal(endings.text(state), text);
  assert.equal(CM.redo(target), true);
  assert.equal(endings.text(state), "ac\nd");
  // A document replaced as setContent replaces it comes back the same way.
  state = state.update({ changes: { from: 0, to: state.doc.length, insert: "x\ny" }, effects: endings.record("x\r\ny") }).state;
  assert.equal(CM.undo(target), true);
  assert.equal(endings.text(state), "ac\nd");
  assert.equal(CM.redo(target), true);
  assert.equal(endings.text(state), "x\r\ny");
});

test("a deleted break takes its ending with it", () => {
  let state = opened("a\rb\r\nc");
  state = edit(state, { from: 1, to: 2 });
  assert.equal(endings.text(state), "ab\r\nc");
  state = edit(state, { from: 0, to: state.doc.length, insert: "x\ny" });
  assert.equal(endings.text(state), "x\ny", "a replaced document has only typed breaks");
});

test("a document opened without recorded endings reads as before", () => {
  const state = CM.EditorState.create({ doc: "a\r\nb", extensions: [endings.field] });
  assert.equal(endings.text(state), "a\nb");
  assert.equal(endings.text(CM.EditorState.create({ doc: "a\r\nb" })), "a\nb", "an editor without the tracker");
});
