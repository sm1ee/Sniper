// A body that is not text is edited one character per byte, as Burp's Raw view
// shows it, while drafts keep it as Base64. Production functions only.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const c = loadFunctions(["binaryBodyText", "binaryBodyBase64", "rawRequestWithBinaryBody", "rawRequestWithBase64Body"],
  { atob, btoa, TextEncoder });
const base64 = bytes => Buffer.from(bytes).toString("base64");
const bytesOf = text => [...Buffer.from(text, "base64")];

test("every byte value survives the trip through text", () => {
  const all = Array.from({ length: 256 }, (_, byte) => byte);
  const text = c.binaryBodyText(base64(all));
  assert.equal(text.length, 256, "one character per byte");
  assert.deepEqual(bytesOf(c.binaryBodyBase64(text)), all);
});

test("a character above U+00FF was typed, and goes as UTF-8", () => {
  assert.deepEqual(bytesOf(c.binaryBodyBase64("aé")), [0x61, 0xe9], "é is one byte here, as in Burp's Raw view");
  assert.deepEqual(bytesOf(c.binaryBodyBase64("한😀")), [0xed, 0x95, 0x9c, 0xf0, 0x9f, 0x98, 0x80]);
  assert.equal(c.binaryBodyText("not base64!"), null);
});

const upload = "POST /upload HTTP/1.1\nHost: example.com\nContent-Type: multipart/form-data; boundary=b\n\n";
const body = "--b\r\nContent-Disposition: form-data; name=\"image\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n"
  + "\x89PNG\r\n\x1a\n\x00\x00\r\xff\xfe\n--b--\r\n";

test("a raw request shows its Base64 body as bytes and turns an edit back into Base64", () => {
  const draft = upload + base64(Buffer.from(body, "latin1"));
  const shown = c.rawRequestWithBinaryBody(draft);
  assert.equal(shown, upload + body);
  assert.equal(c.rawRequestWithBase64Body(shown), draft, "an unchanged view gives the draft back");
  const edited = c.rawRequestWithBase64Body(shown.replace("a.png", "shell.php"));
  assert.equal(Buffer.from(edited.slice(upload.length), "base64").toString("latin1"), body.replace("a.png", "shell.php"));
  assert.equal(c.rawRequestWithBinaryBody("GET / HTTP/1.1\nHost: example.com"), "GET / HTTP/1.1\nHost: example.com", "no body");
  assert.equal(c.rawRequestWithBinaryBody(`${upload}%%%`), `${upload}%%%`, "a body that is not Base64 stays as it is");
});

test("Replay shows a binary body as bytes in every view and keeps the draft in Base64", () => {
  const tab = { baseRequest: { body_encoding: "base64" } };
  const state = { replayMessageViews: { request: "pretty" } };
  const r = loadFunctions(["replayRequestEditorText", "replayDraftFromEditor", "replayEditorShowsDraft",
    "replayRequestTextsEquivalent", "replayTabBodyIsBinary", "rawRequestWithBinaryBody", "rawRequestWithBase64Body",
    "binaryBodyText", "binaryBodyBase64"],
  { atob, btoa, TextEncoder, state, getActiveReplayTab: () => tab, prettyFormat: () => { throw new Error("not pretty-printed"); } });
  const draft = upload + base64(Buffer.from(body, "latin1"));
  const shown = r.replayRequestEditorText(draft);
  assert.equal(shown, upload + body);
  assert.equal(r.replayDraftFromEditor(shown), draft);
  assert.equal(r.replayEditorShowsDraft(shown, draft), true, "an unedited view is the draft");
  assert.equal(r.replayEditorShowsDraft(shown.replace("a.png", "b.png"), draft), false);
  const text = { baseRequest: { body_encoding: "utf8" } };
  assert.equal(r.replayDraftFromEditor("GET / HTTP/1.1\n\nplain", text), "GET / HTTP/1.1\n\nplain", "a text body is the draft as shown");
});

const raw = loadFunctions(["buildEditableRawRequest", "parseEditableRawRequest", "buildEditableRawResponse",
  "parseEditableRawResponse", "binaryBodyText", "binaryBodyBase64"], {
  atob, btoa, TextEncoder,
  normalizedHeaders: headers => (headers || []).filter(header => header?.name),
  headerNameEquals: (header, name) => String(header?.name || "").toLowerCase() === name,
  mergeHeaders: headers => headers,
  splitRawHttpMessage: text => {
    const boundary = /\r?\n\r?\n/.exec(text);
    return boundary ? { head: text.slice(0, boundary.index).replace(/\r\n/g, "\n"), body: text.slice(boundary.index + boundary[0].length) }
      : { head: text.replace(/\r\n/g, "\n"), body: "" };
  },
  headerValue: (headers, name) => headers.find(header => header.name.toLowerCase() === name)?.value || null,
  parseReplayHttpVersionToken: token => token || undefined,
  httpRequestAuthoritiesEquivalent: () => true,
  editableRequestBodyLength: (body, encoding) => encoding === "base64" ? atob(body).length : Buffer.byteLength(body),
  editableResponseBodyLength: (body, encoding) => encoding === "base64" ? atob(body).length : Buffer.byteLength(body),
  validateRawHttpBodyFraming() {}, responseMustNotIncludeBody: () => false,
  responseContentLengthMayDescribeRepresentation: () => false,
  document: { getElementById: () => null },
});

test("Intercept shows a held binary request and response as bytes and forwards an edit as Base64", () => {
  const held = { method: "POST", path: "/upload", host: "example.com", http_version: "HTTP/1.1",
    headers: [{ name: "Host", value: "example.com" }, { name: "Content-Type", value: "multipart/form-data; boundary=b" }],
    body: base64(Buffer.from(body, "latin1")), body_encoding: "base64" };
  const shown = raw.buildEditableRawRequest(held, true, { bytes: true });
  assert.ok(shown.endsWith(body), "the body shows as bytes");
  assert.equal(raw.parseEditableRawRequest(shown, held, true, { bytes: true }).body, held.body);
  const forwarded = raw.parseEditableRawRequest(shown.replace("a.png", "shell.php"), held, true, { bytes: true });
  assert.equal(Buffer.from(forwarded.body, "base64").toString("latin1"), body.replace("a.png", "shell.php"));
  assert.equal(raw.buildEditableRawRequest(held, true).endsWith(held.body), true, "without the option the body stays Base64");

  const image = { status: 200, headers: [{ name: "Content-Type", value: "image/png" }],
    body: base64([0x89, 0x50, 0x0d, 0x0a, 0x00, 0xff]), body_encoding: "base64" };
  const response = raw.buildEditableRawResponse(image, { bytes: true });
  assert.ok(response.endsWith("\x89P\r\n\x00\xff"));
  assert.equal(raw.parseEditableRawResponse(response, image, "GET", { bytes: true }).body, image.body);
});
