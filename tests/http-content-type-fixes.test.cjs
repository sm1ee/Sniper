const test = require("node:test");
const assert = require("node:assert/strict");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function loadHelpers() {
  return loadFunctions([
    "normalizedHeaders",
    "headerNameEquals",
    "editableRequestFromRecord",
    "validateRawHttpBodyFraming",
    "extractSummaryPathExtension",
    "inferMimeType",
    "escapeHtml",
    "highlightJsonLine",
    "highlightBodyLine",
    "looksLikeJson",
    "looksLikeMarkup",
    "looksLikeFormEncoded",
    "prettyJsonText",
    "prettyFormat",
  ], {
    prettyMarkup: () => "SHOULD_NOT_RUN_MARKUP",
  });
}

test("editableRequestFromRecord strips Content-Encoding and Content-Length for decoded bodies", () => {
  const c = loadHelpers();
  const decoded = c.editableRequestFromRecord({
    scheme: "https",
    host: "example.com",
    method: "POST",
    path: "/submit",
    http_version: "HTTP/1.1",
    request: {
      headers: [
        { name: "Host", value: "example.com" },
        { name: "Content-Type", value: "application/json" },
        { name: "Content-Encoding", value: "gzip" },
        { name: "Content-Length", value: "42" },
      ],
      body_preview: '{"ok":true}',
      body_encoding: "utf8",
      content_decoded: true,
    },
  });
  const names = decoded.headers.map((h) => h.name.toLowerCase());
  assert.deepEqual(names, ["host", "content-type"]);

  const raw = c.editableRequestFromRecord({
    scheme: "https",
    host: "example.com",
    method: "POST",
    path: "/submit",
    http_version: "HTTP/1.1",
    request: {
      headers: [
        { name: "Content-Encoding", value: "gzip" },
        { name: "Content-Length", value: "42" },
      ],
      body_preview: "H4sI",
      body_encoding: "base64",
      content_decoded: false,
    },
  });
  assert.deepEqual(raw.headers.map((h) => h.name.toLowerCase()), ["content-encoding", "content-length"]);
});

test("inferMimeType parses MIME essence and does not override explicit types with path extension", () => {
  const c = loadHelpers();
  assert.equal(c.inferMimeType({ content_type: 'application/json; profile="https://example.com/html"', path: "/api" }), "json");
  assert.equal(c.inferMimeType({ content_type: "multipart/form-data; boundary=----jsonBoundary", path: "/upload" }), "other");
  assert.equal(c.inferMimeType({ content_type: "text/plain; charset=utf-8", path: "/app.js" }), "other");
  assert.equal(c.inferMimeType({ content_type: "", path: "/bundle.mjs" }), "script");
  assert.equal(c.inferMimeType({ content_type: "application/octet-stream", path: "/hero.webp" }), "image");
});

test("highlightBodyLine preserves JSON highlighting on single-line JSON arrays and scientific numbers", () => {
  const c = loadHelpers();
  const rendered = c.highlightBodyLine('[{"id":1e5,"ok":true}]', "json");
  assert.ok(!rendered.startsWith('<span class="token-meta">'), rendered);
  assert.match(rendered, /token-json-key/);
  assert.match(rendered, /1e5/);
  assert.equal(c.highlightBodyLine("[preview truncated]", "json"), '<span class="token-meta">[preview truncated]</span>');
});

test("prettyFormat inspects MIME essence rather than Content-Type parameters", () => {
  const c = loadHelpers();
  const formatted = c.prettyFormat(
    'HTTP/1.1 200 OK\nContent-Type: application/json; profile="https://example.com/xml"\n\n{"a":1}',
    { content_type: 'application/json; profile="https://example.com/xml"' },
  );
  assert.ok(!formatted.includes("SHOULD_NOT_RUN_MARKUP"));
  assert.match(formatted, /\{\n  "a": 1\n\}/);
});

// Sniper cannot frame a chunked body it was given whole, so that one is
// refused. Any other coding is what the tester wrote and is sent: a
// request-smuggling test is made of values a server may or may not read as
// chunked.
test("validateRawHttpBodyFraming refuses chunked and sends any other Transfer-Encoding", () => {
  const c = loadHelpers();
  assert.throws(
    () => c.validateRawHttpBodyFraming([{ name: "Transfer-Encoding", value: "chunked" }], 4),
    /Transfer-Encoding: chunked is not supported/,
  );
  for (const coding of ["xchunked", "identity", "gzip", "chunked-false"]) {
    assert.doesNotThrow(() => c.validateRawHttpBodyFraming([
      { name: "Content-Length", value: "4" },
      { name: "Transfer-Encoding", value: coding },
    ], 4), coding);
  }
});
