const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const c = loadFunctions([
  "parseCurlCommand", "splitShellWords", "decodeAnsiCStringEscape", "shellQuote",
  "encodeCurlDataUrlencode", "curlDataBinaryBodyIsPlainText", "appendCurlGetQuery",
  "defaultHttpPortForScheme", "rawPathFromUrlString", "normalizedHeaders", "headerNameEquals",
  "splitRawHttpMessage", "parseEditableRawRequest", "parseReplayHttpVersionToken",
  "normalizeReplayHttpVersion", "headerValue", "editableRequestBodyLength", "validateRawHttpBodyFraming",
], {
  URL, TextEncoder, TextDecoder, document: { getElementById: () => null },
  HTTP_METHOD_TOKEN_RE: /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/,
});

function replay(command) {
  const imported = c.parseCurlCommand(command);
  assert.ok(imported && !imported.error, imported?.error || "Import failed");
  const parsed = c.parseEditableRawRequest(imported.requestText, { scheme: "https", body_encoding: "utf8" });
  assert.equal(parsed.body, imported.body);
  return imported;
}

// The local curl argv oracle checks mixed option order as well as empty
// fragments: the next option chooses the separator, not the first one.
const joinCases = [
  [["--json", '{"x":'], ["--json", "1}"]],
  [["--json", "[1,"], ["--json", "2]"]],
  [["--json", ""], ["--json", '{"x":1}'], ["--json", ""]],
  [["--json", ""], ["--json", ""]],
  [["--data-raw", "a"], ["--data-raw", "b"]],
  [["--data-binary", "a"], ["--data-binary", "b"]],
  [["--data-raw", "a"], ["--json", "b"]],
  [["--json", "a"], ["--data-raw", "b"]],
  [["--json", "a"], ["--data-binary", "b"]],
  [["--data-raw", ""], ["--json", "b"], ["--data-raw", ""]],
  [["--json", "a"], ["--data-urlencode", "x=y z"], ["--json", "c"]],
  [["--json", ""], ["--data-raw", "a"]],
  [["--data-raw", ""], ["--json", "a"]],
  [["--data-raw", ""], ["--data-raw", "value"], ["--data-raw", ""]],
  [["--data-raw", ""], ["--data-raw", ""]],
];
const expectedBodies = ['{"x":1}', "[1,2]", '{"x":1}', "", "a&b", "a&b", "ab", "a&b", "a&b", "b&", "a&x=y+zc", "a", "a", "value&", ""];

for (const [index, parts] of joinCases.entries()) {
  test(`cURL body fragments retain option-specific separators and empties (${index + 1})`, () => {
    for (const assignment of [false, true]) {
      const options = parts.map(([flag, value]) => `${flag}${assignment ? "=" : " "}${c.shellQuote(value)}`).join(" ");
      const parsed = replay(`curl https://example.com/synthetic ${options}`);
      assert.equal(parsed.body, expectedBodies[index]);
      assert.equal(parsed.method, "POST");
      if (parts.some(([flag]) => flag === "--json")) {
        assert.equal(c.headerValue(parsed.headers, "content-type"), "application/json");
        assert.equal(c.headerValue(parsed.headers, "accept"), "application/json");
      }
    }
  });
}

test("JSON joins retain explicit methods and supported GET query imports", () => {
  assert.equal(replay("curl https://example.com -X PATCH --json a --json b").method, "PATCH");
  const get = replay("curl https://example.com --get --json a --json b");
  assert.equal(get.method, "GET");
  assert.equal(get.path, "/?ab");
  assert.equal(get.body, "");
});

const textCases = [
  ["hex UTF-8", "$'\\xc3\\xa9'", "é"],
  ["octal UTF-8", "$'\\303\\251'", "é"],
  ["mixed byte escapes", "$'\\xc3\\251'", "é"],
  ["Korean UTF-8", "$'\\xed\\x95\\x9c\\xea\\xb8\\x80'", "한글"],
  ["CJK and emoji UTF-8", "$'caf\\xc3\\xa9 \\xe6\\x96\\x87 \\xf0\\x9f\\x98\\x80'", "café 文 😀"],
  ["literal Unicode and escapes", "$'café 文 \\xf0\\x9f\\x98\\x80 \\u03c0'", "café 文 😀 π"],
  ["known ASCII escapes", "$'first\\r\\n\\t\\x41\\u0042\\101'", "first\r\n\tABA"],
  ["Unicode code points", "$'\\u00e9 \\U0001f600'", "é 😀"],
  ["short Unicode escapes", "$'\\uE9 \\U1f600'", "é 😀"],
  ["adjacent quote segments", "'literal 文 '$'\\xc3'$'\\xa9'\" 😀\"", "literal 文 é 😀"],
  ["empty segments inside bytes", "$'\\xc3'\"\"''$'\\xa9'", "é"],
  ["quoted apostrophes and slashes", "$'\\xc3\\xa9\\\'\\\\\\\"'", 'é\'\\"'],
  ["byte BOM", "$'\\xef\\xbb\\xbftext'", "\ufefftext"],
  ["literal BOM and bytes", "$'\ufeff\\xc3\\xa9'", "\ufeffé"],
  ["encoded replacement character", "$'\\xef\\xbf\\xbd'", "\ufffd"],
  ["non-ANSI quote text", "'\\xc3\\xa9'", "\\xc3\\xa9"],
  ["literal Unicode", "'café 文 😀'", "café 文 😀"],
  ["unknown escapes", "$'\\xQ \\uZ \\q'", "\\xQ \\uZ \\q"],
];

for (const [name, word, expected] of textCases) {
  test(`ANSI-C ${name} preserves UTF-8 bytes through Replay`, () => {
    for (const flag of ["--data", "--data-raw", "--data-binary", "--json"]) {
      const parsed = replay(`curl https://example.com/synthetic ${flag} ${word}`);
      assert.equal(parsed.body, expected);
      assert.deepEqual(Buffer.from(parsed.body), Buffer.from(expected));
    }
  });
}

test("byte decoding happens within each shell word and also applies to URL-encoded text", () => {
  const parsed = replay("curl https://example.com --data-urlencode $'name=caf\\xc3\\xa9'");
  assert.equal(parsed.body, "name=caf%C3%A9");
  assert.match(c.parseCurlCommand("curl https://example.com --json $'\\xc3' --json $'\\xa9'").error, /UTF-8/);
});

test("unrepresentable bytes and Unicode escapes fail explicitly instead of replacing bytes", () => {
  const invalid = [
    "\\xc3", "\\xe6\\x96", "\\xa9", "\\xff", "\\377", "\\777",
    "\\xc0\\xaf", "\\xed\\xa0\\x80", "\\xf4\\x90\\x80\\x80", "\\xc3x",
    "\\xc3\\u00a9", "\\x00", "\\0", "\\400", "\\u0000", "\\ud800", "\\U00110000",
  ];
  for (const word of invalid) {
    for (const flag of ["--data-raw", "--data-binary", "--json", "--data-urlencode"]) {
      assert.match(c.parseCurlCommand(`curl https://example.com ${flag} $'${word}'`).error, /UTF-8|Unicode|NUL/);
    }
  }
  for (const literal of ["\ud800", "\udc00", "\0"]) {
    assert.match(c.parseCurlCommand(`curl https://example.com --data-raw '${literal}'$'\\x41'`).error, /Unicode|NUL/);
  }
});

test("file, multipart and binary-control limitations remain explicit", () => {
  for (const options of [
    "--json @fixture.txt", "--json=@-", "--data @fixture.txt", "--data-binary @fixture.txt",
    "--data-urlencode @fixture.txt", "--form field=value", "--form-string field=value", "--http3",
    "--data-binary $'\\x01'", "--data-binary $'\\401'",
  ]) {
    assert.ok(c.parseCurlCommand(`curl https://example.com ${options}`).error);
  }
  assert.equal(replay("curl https://example.com --data-raw '@literal'").body, "@literal");
});
