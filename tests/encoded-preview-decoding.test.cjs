const assert = require("node:assert/strict");
const test = require("node:test");
const { fixture, CM } = require("./encoded-preview-fixture.cjs");
const { context: c } = fixture();
const plain = value => JSON.parse(JSON.stringify(value));
const doc = value => CM.EditorState.create({ doc: value }).doc;
const encode = value => Buffer.from(value).toString("base64");

for (const [value, expected] of [
  ["hello%20world", "hello world"], ["%ED%95%9C%EA%B8%80", "한글"],
  ["one+two%20three", "one+two three"], [encode("hello world"), "hello world"],
  [encode("safe text!?"), "safe text!?"], [encode("café 😀 한글"), "café 😀 한글"],
  [Buffer.from("😀 hello").toString("base64url"), "😀 hello"],
  ["%3Cscript%3Eharmless%3C%2Fscript%3E", "<script>harmless</script>"],
]) test(`strict textual decoding: ${value}`, () => {
  assert.equal(c.decodePreviewLayers(value)[0]?.text, expected);
});

test("nested URL and Base64 transformations stop at three layers", () => {
  assert.deepEqual(plain(c.decodePreviewLayers(encodeURIComponent(encode("hello world")))), [
    { encoding: "URL percent encoding", text: encode("hello world") },
    { encoding: "Base64", text: "hello world" },
  ]);
  assert.equal(c.decodePreviewLayers("%2525252541").length, 3);
  assert.equal(c.decodePreviewLayers("%2525252541")[2].text, "%2541");
});

for (const value of ["hello", "function", "deadbeef", "YQ==", "hello+world", "%", "%GG", "%FF", "%C0%AF", "%41%ZZ", "YWJjZGU", "YWJjZGV=", "YWJjZGU==", "YWJjZGU===", "a-b/c_d+", encode("\0harmless"), encode("\x7ftext"), encode("\u202efake"), encode("\n\t"), "x".repeat(4097), encode("x".repeat(2049))]) {
  test(`reject malformed, ambiguous, binary or over-budget value: ${value.slice(0, 30)}`, () => {
    // Unpadded YWJjZGU is valid standard Base64.
    if (value === "YWJjZGU") assert.equal(c.decodePreviewLayers(value).length, 0, "Tokens shorter than eight are deliberately not guessed");
    else assert.equal(c.decodePreviewLayers(value).length, 0);
  });
}

for (const [text, token] of [
  ['GET /?q=hello%20world&other=plain HTTP/1.1', "hello%20world"],
  ['Cookie: data=aGVsbG8gd29ybGQ=; flag=yes', "aGVsbG8gd29ybGQ="],
  ['{"value":"aGVsbG8gd29ybGQ="}', "aGVsbG8gd29ybGQ="],
  ['Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzYWZlIjp0cnVlfQ.', "eyJzYWZlIjp0cnVlfQ"],
  ['value=one+two%20three', "one+two%20three"],
]) test(`token bounds in HTTP syntax: ${text}`, () => {
  const start = text.indexOf(token);
  for (let i = start; i < start + token.length; i += 1) {
    const result = c.encodedPreviewAt(doc(text), i);
    assert.ok(result, `position ${i}`);
    assert.equal(result.from, start); assert.equal(result.to, start + token.length);
  }
});

test("only a small document slice is read, and oversized tokens cannot be decoded by suffix", () => {
  const text = `${"x".repeat(200000)} hello%20world ${"x".repeat(200000)}`;
  let read = 0;
  const bounded = { length: text.length, sliceString(from, to) { read += to - from; assert.ok(to - from <= 8195); return text.slice(from, to); } };
  assert.equal(c.encodedPreviewAt(bounded, 200004).layers[0].text, "hello world");
  assert.ok(read <= 8195);
  for (const position of [0, 2000, 4096, 8000]) assert.equal(c.encodedPreviewAt(doc("%41".repeat(5000)), position), null);
});

test("delimiters, malformed tokens and invalid positions do not offer previews", () => {
  for (const text of ["%ZZaGVsbG8gd29ybGQ=", "aGVsbG8gd29ybGQ%ZZ", "plain text", "0x68656c6c6f"]) {
    for (let i = 0; i < text.length; i += 1) assert.equal(c.encodedPreviewAt(doc(text), i), null);
  }
  for (const position of [-1, 1.5, 99]) assert.equal(c.encodedPreviewAt(doc("hello%20world"), position), null);
  assert.equal(c.encodedPreviewAt(doc("hello%20world next"), 13), null);
});


test("all Unicode bidi controls are rejected in URL and Base64 previews", () => {
  for (const char of ["\u061c", "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"]) {
    for (const value of [encode(`safe${char}text`), encodeURIComponent(`safe${char}text`)]) {
      assert.equal(c.decodePreviewLayers(value).length, 0);
    }
  }
});
