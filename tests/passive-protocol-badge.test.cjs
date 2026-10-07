// Passive inspector metadata only, using synthetic saved-record fixtures.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");
const c = loadFunctions(["inferProtocolState", "renderProtocolStrip", "normalizedHeaders", "escapeHtml"]);
const ordinaryHeaders = [{ name: "content-type", value: "text/plain" }];
const pseudoHeaders = [{ name: ":method", value: "GET" }];
function check(record, expected) {
  const state = c.inferProtocolState(record);
  assert.equal(state.current, expected);
  assert.equal(state.supportsHttp2, expected === "HTTP/2");
  const html = c.renderProtocolStrip(state);
  const active = [...html.matchAll(/<span class="protocol-pill ([^"]*)">([^<]*)<\/span>/g)]
    .filter(match => match[1].split(/\s+/).includes("active"))
    .map(match => match[2]);
  assert.deepEqual(active, [expected], "exactly the recorded protocol must be active");
}

for (const headers of [[], ordinaryHeaders, undefined]) {
  test(`explicit HTTP/2 metadata wins without pseudo-headers (${JSON.stringify(headers)})`, () => {
    check({ http_version: "HTTP/2", request: { headers } }, "HTTP/2");
  });
}

for (const version of ["HTTP/1.0", "HTTP/1.1"]) {
  test(`${version} metadata takes precedence over incidental pseudo-header names`, () => {
    check({ http_version: version, request: { headers: pseudoHeaders } }, "HTTP/1");
  });
}

for (const version of ["HTTP/0.9", "HTTP/3"]) {
  test(`${version} receives its own active badge instead of HTTP/1`, () => {
    check({ http_version: version, request: { headers: ordinaryHeaders } }, version);
  });
}

test("HTTP/2 metadata remains usable when legacy request metadata is absent", () => {
  check({ http_version: "HTTP/2" }, "HTTP/2");
});

for (const http_version of [undefined, null, ""]) {
  test(`legacy ${JSON.stringify(http_version)} version retains header-based inference`, () => {
    check({ http_version, request: { headers: pseudoHeaders } }, "HTTP/2");
    check({ http_version, request: { headers: ordinaryHeaders } }, "HTTP/1");
  });
}

test("the response protocol does not replace captured request protocol metadata", () => {
  check({ http_version: "HTTP/1.1", response_http_version: "HTTP/2", request: { headers: ordinaryHeaders } }, "HTTP/1");
  check({ http_version: "HTTP/2", response_http_version: "HTTP/1.1", request: { headers: ordinaryHeaders } }, "HTTP/2");
});

test("an empty inspector retains its existing neutral HTTP/1 placeholder", () => {
  check({ request: { headers: [] } }, "HTTP/1");
});
