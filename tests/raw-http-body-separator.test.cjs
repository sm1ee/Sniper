const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const c = loadFunctions([
  "splitRawHttpMessage", "parseEditableRawRequest", "parseEditableRawResponse",
  "parseReplayHttpVersionToken", "normalizeReplayHttpVersion", "headerValue",
  "headerNameEquals", "normalizedHeaders", "editableRequestBodyLength",
  "editableResponseBodyLength", "validateRawHttpBodyFraming",
  "responseMustNotIncludeBody", "responseStatusMustNotIncludeBody",
  "responseContentLengthMayDescribeRepresentation",
], { URL, TextEncoder, document: { getElementById: () => null } });

const bodies = [
  ["CRLF multipart", '--boundary\r\nContent-Disposition: form-data; name="field"\r\n\r\nvalue\r\n--boundary--\r\n'],
  ["LF blank lines", "first\n\nlast\n"],
  ["CRLF blank lines", "first\r\n\r\nlast\r\n"],
  ["mixed blank lines", "\r\nfirst\n\r\nlast\r\n\r\n"],
  ["Unicode and whitespace", "\t한글 🦊\r\n  \n\t"],
  ["empty", ""],
];

for (const [style, separator] of [
  ["LF", "\n\n"], ["CRLF", "\r\n\r\n"],
  ["LF then CRLF", "\n\r\n"], ["CRLF then LF", "\r\n\n"],
]) {
  for (const [name, body] of bodies) {
    test(`${style} separator precedes ${name} in requests and responses`, () => {
      for (const host of ["example.com", "127.0.0.1:8080", "[2001:db8::7]:8080"]) {
        const head = `POST /upload HTTP/1.1\r\nHost: ${host}\nContent-Length: ${Buffer.byteLength(body)}`;
        const raw = head + separator + body;
        assert.equal(c.splitRawHttpMessage(raw).head, head.replace(/\r\n/g, "\n"));
        assert.equal(c.splitRawHttpMessage(raw).body, body);
        const parsed = c.parseEditableRawRequest(raw, { scheme: "http" });
        assert.equal(parsed.body, body);
        assert.equal(parsed.host, host);
        assert.equal(parsed.path, "/upload");
        assert.equal(parsed.headers.length, 2);
      }
      const response = `HTTP/1.1 200 OK\nContent-Length: ${Buffer.byteLength(body)}${separator}${body}`;
      assert.equal(c.parseEditableRawResponse(response).body, body);
    });
  }

  test(`${style} boundary keeps malformed request lines and headers rejected`, () => {
    assert.throws(() => c.parseEditableRawRequest(`invalid${separator}body\r\n\r\n`), /Invalid request line/);
    assert.throws(() => c.parseEditableRawRequest(`POST / HTTP/1.1\nMalformed${separator}body\r\n\r\n`), /Invalid header line/);
    assert.throws(() => c.parseEditableRawResponse(`HTTP/1.1 200\nMalformed${separator}body\r\n\r\n`), /Invalid response header/);
    assert.throws(() => c.parseEditableRawRequest(`POST / HTTP/1.1\nHost: example.com\nContent-Length: 0${separator}body\r\n\r\n`), /does not match raw body length/);
    assert.throws(() => c.parseEditableRawRequest(`POST / HTTP/1.1\nHost: example.com\nTransfer-Encoding: chunked${separator}0\r\n\r\n`), /chunked is not supported/);
  });
}

test("missing separators remain a header-only message", () => {
  for (const raw of [null, "", "GET / HTTP/1.1", "GET / HTTP/1.1\r\nHost: example.com\r\n"]) {
    assert.equal(c.splitRawHttpMessage(raw).head, String(raw ?? "").replace(/\r\n/g, "\n"));
    assert.equal(c.splitRawHttpMessage(raw).body, "");
  }
});

test("a body beginning with request or header syntax remains entirely body data", () => {
  const body = "GET /body HTTP/1.1\r\nHost: body.example.com\r\n\r\nlast\n\n";
  const parsed = c.parseEditableRawRequest(`POST / HTTP/1.1\nHost: example.com\n\n${body}`);
  assert.equal(parsed.body, body);
  assert.equal(parsed.host, "example.com");
  assert.equal(parsed.headers.length, 1);
});
