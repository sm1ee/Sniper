const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const zlib = require("node:zlib");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const toasts = [];
const c = loadFunctions([
  "recordToFormat", "selectedRecordToFormat", "historyRequestToFormat", "historyRequestExportBlockedReason",
  "buildRawRequest", "buildRawRequestHead", "renderBody", "safeDecodeBase64", "mergeHeaders", "normalizedHeaders", "headerNameEquals",
  "parseRequestForExport", "parseHeaderLineForExport", "normalizeReplayHttpVersion",
  "exportHeaderValue", "exportableHeaderCandidates", "buildUrlFromTarget", "normalizeRepeaterTargetInput",
  "authorityToTargetState", "stripIpv6Brackets", "normalizePortValue", "defaultHttpPortForScheme",
  "isDefaultPortForScheme", "joinAuthority", "requestToPython", "requestToFetch", "requestToPowerShell",
  "requestToCurl", "shellQuote", "curlHttpVersionFlag", "urlNeedsPathAsIs", "rawPathFromUrlString",
  "exportableHeaders", "exportableHeadersForUrl", "isHttpPseudoHeaderName", "hostHeaderDiffersFromUrl",
  "httpRequestAuthoritiesEquivalent", "normalizeHttpRequestAuthority", "fetchExportBlockedReason", "requestFormatExportBlockedReason",
  "replayRequestToFormat", "replayExportBlockedReason", "getReplayExportTarget",
], {
  URL, TextEncoder,
  currentSessionId: () => "fixture-session",
  transactionPath: id => `/fixture/${id}`,
  showToast: (...args) => toasts.push(args),
  deriveRepeaterRequest: tab => ({ body: tab.body || "", body_encoding: "utf8" }),
  getRepeaterTargetConfig: () => ({ scheme: "https", host: "example.com", port: "" }),
});
const formats = ["curl", "python", "fetch", "powershell"];
const objectFormats = ["python", "fetch", "powershell"];
function record(body = "fixture", headers = []) {
  return {
    id: "fixture", kind: "http", method: "POST", scheme: "https", host: "example.com",
    path: "/export?key=one&key=two", http_version: "HTTP/1.1",
    request: {
      headers: [{ name: "host", value: "example.com" }, ...headers],
      body_preview: body, body_encoding: "utf8", body_size: Buffer.byteLength(body), preview_truncated: false,
    },
  };
}
function decodedRecord(body, contentType = "application/json") {
  const gzip = zlib.gzipSync(Buffer.from(body));
  assert.equal(zlib.gunzipSync(gzip).toString("utf8"), body);
  const result = record(body, [
    { name: "Content-Type", value: contentType },
    { name: "cOnTeNt-EnCoDiNg", value: "gzip" },
    { name: "Content-Length", value: String(gzip.length) },
    { name: "x-fixture", value: "retained" },
  ]);
  Object.assign(result.request, {
    content_decoded: true, body_size: gzip.length, decoded_body_size: Buffer.byteLength(body), content_type: contentType,
  });
  return result;
}
async function assertControllers(result, format, expected) {
  c.getCurrentSelectedRecord = () => result;
  c.fetch = async () => ({ ok: true, json: async () => result });
  assert.equal(c.recordToFormat(result, format), expected);
  assert.equal(c.selectedRecordToFormat(format), expected);
  assert.equal(await c.historyRequestToFormat(result.id, format), expected);
}
function inspectFetch(source) {
  let args;
  vm.runInNewContext(source, {
    fetch: (...input) => { args = input; return Promise.resolve({ text: async () => "" }); },
    console: { log() {} },
  });
  assert.ok(args);
  // Construct the request bytes; never invoke native fetch or contact an origin.
  return new Request(...args);
}

for (const [label, body, contentType] of [
  ["JSON", '{"fixture":"café 😀","items":[1,2]}', "application/json"],
  ["text with CRLF", "\r\n café 😀\r\nlast\r\n\r\n", "text/plain;charset=utf-8"],
  ["empty decoded gzip", "", "text/plain"],
]) {
  for (const format of formats) {
    test(`${format} exports ${label} with decoded entity headers through both controllers`, async () => {
      const result = decodedRecord(body, contentType);
      const snapshot = JSON.stringify(result);
      const displayed = c.buildRawRequest(result);
      assert.match(displayed, /cOnTeNt-EnCoDiNg: gzip/);
      const exported = c.recordToFormat(result, format);
      assert.ok(exported);
      assert.doesNotMatch(exported, /content-(encoding|length)/i);
      assert.match(exported, /x-fixture/);
      await assertControllers(result, format, exported);
      assert.equal(JSON.stringify(result), snapshot);
      assert.equal(c.buildRawRequest(result), displayed);
      if (format === "fetch") {
        const request = inspectFetch(exported);
        assert.equal(request.headers.get("content-encoding"), null);
        assert.deepEqual(Buffer.from(await request.arrayBuffer()), Buffer.from(body));
      }
    });
  }
}

for (const format of formats) {
  test(`${format} preserves Content-Encoding when content_decoded is false or omitted`, async () => {
    // Unknown encodings are retained by the capture model and may still contain UTF-8 text.
    for (const decoded of [false, undefined]) {
      const result = record("fixture\r\n", [{ name: "Content-Encoding", value: "x-fixture-encoding" }]);
      if (decoded !== undefined) result.request.content_decoded = decoded;
      const exported = c.recordToFormat(result, format);
      assert.match(exported, /Content-Encoding/);
      assert.match(exported, /x-fixture-encoding/);
      await assertControllers(result, format, exported);
    }
  });
  test(`${format} still blocks retained binary, missing preview bytes, and truncated decoded text`, async () => {
    const gzip = zlib.gzipSync(Buffer.from("fixture"));
    const cases = [
      { body_preview: gzip.toString("base64"), body_encoding: "base64", body_size: gzip.length },
      { body_preview: "AP+A", body_encoding: "base64", body_size: 3, content_decoded: true, decoded_body_size: 3 },
      // A zero preview cap retains metadata and a truncation flag, but no body bytes.
      { body_preview: "", body_encoding: "base64", body_size: gzip.length, preview_truncated: true },
      { body_preview: "partial", body_encoding: "utf8", body_size: gzip.length, content_decoded: true, decoded_body_size: 100, preview_truncated: true },
    ];
    for (const input of cases) {
      const result = record();
      Object.assign(result.request, input);
      await assertControllers(result, format, "");
      assert.match(toasts.at(-1)[0], /Binary|Truncated/);
    }
  });
}

for (const format of objectFormats) {
  for (const secondName of ["x-fixture", "X-FiXtUrE"]) {
    test(`${format} refuses repeated ${secondName} rather than losing values`, async () => {
      const result = record("fixture", [
        { name: "x-fixture", value: "first" }, { name: "x-between", value: "middle" },
        { name: secondName, value: "second" },
      ]);
      const snapshot = JSON.stringify(result);
      await assertControllers(result, format, "");
      assert.match(toasts.at(-1)[0], /repeated headers/i);
      assert.match(toasts.at(-1)[0], /cURL/);
      const parsed = c.parseRequestForExport(c.buildRawRequest(result), "https", "example.com", "");
      const exporter = { python: "requestToPython", fetch: "requestToFetch", powershell: "requestToPowerShell" }[format];
      assert.equal(c[exporter](parsed), "");
      assert.equal(c.replayRequestToFormat(format, { requestText: c.buildRawRequest(result) }), "");
      assert.equal(JSON.stringify(result), snapshot);
    });
  }
  test(`${format} permits unique fields, merged Cookie fields, and filtered length fields`, async () => {
    const result = record("fixture", [
      { name: "Cookie", value: "first=1" }, { name: "cookie", value: "second=2" },
      { name: "x-fixture", value: "first" }, { name: "x-other", value: "second" },
      { name: "content-length", value: "7" }, { name: "Content-Length", value: "7" },
    ]);
    const exported = c.recordToFormat(result, format);
    assert.ok(exported);
    assert.match(exported, /first=1; second=2/);
    assert.doesNotMatch(exported, /content-length/i);
    await assertControllers(result, format, exported);
  });
}

test("cURL keeps repeated exported header fields and their order", async () => {
  const result = record("fixture", [
    { name: "x-fixture", value: "first" }, { name: "x-between", value: "middle" },
    { name: "X-Fixture", value: "second" },
  ]);
  const exported = c.recordToFormat(result, "curl");
  assert.ok(exported.indexOf("x-fixture: first") < exported.indexOf("x-between: middle"));
  assert.ok(exported.indexOf("x-between: middle") < exported.indexOf("X-Fixture: second"));
  await assertControllers(result, "curl", exported);
});

test("history export keeps its session checks and does not export stale fetched records", async () => {
  let session = "before";
  c.currentSessionId = () => session;
  c.fetch = async () => ({ ok: true, json: async () => { session = "after"; return decodedRecord("fixture"); } });
  assert.equal(await c.historyRequestToFormat("fixture", "fetch"), "");
  c.currentSessionId = () => "fixture-session";
});

test("Fetch retains its existing body and custom Host warnings", () => {
  const result = record("fixture");
  for (const method of ["GET", "HEAD"]) {
    result.method = method;
    assert.equal(c.recordToFormat(result, "fetch"), "");
    assert.match(toasts.at(-1)[0], /GET or HEAD/);
  }
  result.method = "POST";
  result.request.headers[0].value = "alternate.example.com";
  assert.equal(c.recordToFormat(result, "fetch"), "");
  assert.match(toasts.at(-1)[0], /custom Host/);
  assert.ok(c.recordToFormat(result, "python"));
});
