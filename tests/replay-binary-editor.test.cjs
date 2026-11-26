// Replay's editor on a body that is not text, through the production Replay code
// and CodeMirror's own state and history (replay-editor-fixture.cjs), with the
// default "Update Content-Length" on. Synthetic requests only.
const assert = require("node:assert/strict");
const test = require("node:test");
const { editorFixture } = require("./replay-editor-fixture.cjs");

const upload = "--b\r\nContent-Disposition: form-data; name=\"image\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n"
  + "\x89PNG\r\n\x1a\n\x00\x00\r\xff\xfe\n\r\n--b\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nX\r\n--b--\r\n";
const base64 = text => Buffer.from(text, "latin1").toString("base64");
const bodyOf = draft => draft.slice(draft.indexOf("\n\n") + 2);

function opened(body, encoding) {
  const f = editorFixture();
  const get = f.document.getElementById;
  f.document.getElementById = id => id === "proxySettingAutoContentLength" ? { checked: true } : get(id);
  const stored = encoding === "base64" ? base64(body) : body;
  f.a.baseRequest = { scheme: "https", host: "example.com", method: "POST", path: "/upload",
    headers: [{ name: "Host", value: "example.com" }, { name: "Content-Length", value: String(body.length) }],
    body: stored, body_encoding: encoding, preview_truncated: false };
  f.a.requestText = `POST /upload HTTP/1.1\nHost: example.com\nContent-Length: ${body.length}\n\n${stored}`;
  f.render();
  return f;
}
// A keystroke: the change, with the caret after it.
function type(f, at, text, to = at) {
  f.cv().view.dispatch({ changes: { from: at, to, insert: text }, selection: { anchor: at + text.length }, userEvent: "input.type" });
}

test("Undo and Redo give back every byte of a binary body", () => {
  const f = opened(upload, "base64"), original = f.a.requestText;
  type(f, f.cv().getContent().indexOf("a.png") + 1, "b");
  const edited = f.a.requestText;
  assert.equal(Buffer.from(bodyOf(edited), "base64").toString("latin1"), upload.replace("a.png", "ab.png"));
  assert.ok(edited.includes(`Content-Length: ${upload.length + 1}\n`));
  assert.equal(f.undo(), true);
  assert.equal(f.a.requestText, original);
  assert.equal(f.cv().getText(), f.context.rawRequestWithBinaryBody(original));
  assert.equal(f.redo(), true);
  assert.equal(f.a.requestText, edited);
});

test("a character above U+00FF stays as typed in a binary body and goes as UTF-8", () => {
  const f = opened(upload, "base64");
  const at = f.cv().getContent().indexOf("\nX\n") + 1;
  type(f, at, "사", at + 1);
  assert.equal(f.cv().view.state.selection.main.head, at + 1, "the caret stays after it");
  type(f, at + 1, "진");
  const utf8 = Buffer.from("사진").toString("latin1");
  assert.equal(Buffer.from(bodyOf(f.a.requestText), "base64").toString("latin1"), upload.replace("\r\nX\r\n", `\r\n${utf8}\r\n`));
  assert.ok(f.cv().getText().endsWith("\r\n\r\n사진\r\n--b--\r\n"), "the editor shows what was typed");
  assert.equal(f.context.replayTabHasUncommittedEditorState(f.a), false);
});

test("the caret stays put when Content-Length gains a digit", () => {
  // A 99-byte body: the next character makes Content-Length 100.
  const f = opened(`name${"a".repeat(95)}`, "utf8");
  const at = f.cv().getContent().indexOf("name") + 4;
  type(f, at, "=");
  assert.match(f.a.requestText, /Content-Length: 100\n/);
  const caret = f.cv().view.state.selection.main.head;
  assert.equal(caret, at + 2, "after the '=', one place on for the new digit");
  type(f, caret, "x");
  assert.ok(bodyOf(f.a.requestText).startsWith("name=xaaa"));
});
