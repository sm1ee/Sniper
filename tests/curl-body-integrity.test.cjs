const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const toasts = [];
const c = loadFunctions([
  "recordToFormat", "historyRequestExportBlockedReason", "buildRawRequest", "buildRawRequestHead",
  "renderBody", "mergeHeaders", "normalizedHeaders", "headerNameEquals",
  "parseRequestForExport", "parseHeaderLineForExport", "normalizeReplayHttpVersion",
  "exportHeaderValue", "exportableHeaderCandidates", "buildUrlFromTarget",
  "normalizeRepeaterTargetInput", "authorityToTargetState", "stripIpv6Brackets",
  "normalizePortValue", "defaultHttpPortForScheme", "isDefaultPortForScheme", "joinAuthority",
  "requestToCurl", "curlHttpVersionFlag", "urlNeedsPathAsIs", "rawPathFromUrlString",
  "shellQuote", "exportableHeaders", "exportableHeadersForUrl", "isHttpPseudoHeaderName",
  "hostHeaderDiffersFromUrl", "httpRequestAuthoritiesEquivalent", "normalizeHttpRequestAuthority",
  "requestToPython", "requestToFetch", "fetchExportBlockedReason", "requestToPowerShell",
  "parseCurlCommand", "splitShellWords", "decodeAnsiCStringEscape",
  "encodeCurlDataUrlencode", "curlDataBinaryBodyIsPlainText", "appendCurlGetQuery",
], {
  URL, TextEncoder, TextDecoder,
  showToast: (...args) => toasts.push(args),
  HTTP_METHOD_TOKEN_RE: /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/,
});

const multipart = '--boundary\r\nContent-Disposition: form-data; name="field"\r\n\r\nvalue\r\n--boundary--\r\n';
const bodyCases = [
  ["CRLF multipart", multipart],
  ["mixed line endings and blank lines", "\r\nfirst\n\r\nlast\r\n\r\n"],
  ["trailing carriage return", "first\r\nlast\r"],
  ["literal shell characters", "C:\\temp\\file\r\n'quoted' \\n $value `literal`\\\nnext"],
  ["Unicode and whitespace", "\t한글 🦊\r\n  \n\t"],
  ["explicit empty body", ""],
];

for (const [name, body] of bodyCases) {
  for (const [style, newline] of [["LF", "\n"], ["CRLF", "\r\n"]]) {
    test(`${style} request headers preserve ${name} on export`, () => {
      const raw = ["POST /upload HTTP/1.1", "Host: example.com", "Content-Type: text/plain", "", body].join(newline);
      const parsed = c.parseRequestForExport(raw, "https", "example.com", "");
      assert.equal(parsed.body, body);
      assert.equal(parsed.bodyProvided, true);
      const imported = c.parseCurlCommand(c.requestToCurl(parsed));
      assert.ok(imported && !imported.error);
      assert.equal(imported.body, body);
      assert.equal(imported.method, "POST");
      assert.equal(imported.path, "/upload");
      if (!body) assert.ok(c.requestToCurl(parsed).includes("--data-raw ''"));
      assert.ok(c.requestToPython(parsed).includes(`data = ${JSON.stringify(body)}`));
      assert.ok(c.requestToFetch(parsed).includes(`body: ${JSON.stringify(body)}`));
      assert.ok(c.requestToPowerShell(parsed).includes(`-Body '${body.replace(/'/g, "''")}'`));
    });
  }
}

test("history cURL export keeps multipart bytes after LF headers and removes stale Content-Length", () => {
  const record = {
    kind: "http", method: "POST", scheme: "https", host: "example.com", path: "/upload", http_version: "HTTP/1.1",
    request: {
      headers: [
        { name: "content-type", value: "multipart/form-data; boundary=boundary" },
        { name: "content-length", value: String(Buffer.byteLength(multipart)) },
      ],
      body_preview: multipart, body_encoding: "utf8", body_size: Buffer.byteLength(multipart), preview_truncated: false,
    },
  };
  assert.ok(c.buildRawRequest(record).endsWith(multipart));
  const exported = c.recordToFormat(record, "curl");
  const imported = c.parseCurlCommand(exported);
  assert.equal(imported.body, multipart);
  assert.equal(Buffer.byteLength(imported.body), 81);
  assert.doesNotMatch(exported, /content-length/i);
  assert.match(exported, /multipart\/form-data; boundary=boundary/);
});

test("export still recognizes a missing blank separator without changing body bytes", () => {
  const body = '{"first":1,\r\n"second":2}\r\n';
  // No trailing blank line: a blank line would be the explicit separator.
  const raw = `POST / HTTP/1.1\r\nHost: example.com\r\n${body.slice(0, -2)}`;
  const parsed = c.parseRequestForExport(raw, "https", "", "");
  assert.equal(parsed.body, body.slice(0, -2));
  assert.equal(parsed.headers.length, 1);
  assert.equal(parsed.url, "https://example.com/");
});

test("export distinguishes missing and explicitly empty bodies with either header newline", () => {
  for (const newline of ["\n", "\r\n"]) {
    const raw = ["GET / HTTP/1.1", "Host: example.com"].join(newline);
    assert.equal(c.parseRequestForExport(raw, "https", "", "").bodyProvided, false);
    assert.equal(c.parseRequestForExport(raw + newline + newline, "https", "", "").bodyProvided, true);
  }
});

const shellCases = [
  ["single-quoted backslashes", "'C:\\temp\\file'", "C:\\temp\\file"],
  ["single-quoted backslash newline", "'line one\\\nline two'", "line one\\\nline two"],
  ["single-quoted backslash CRLF", "'line one\\\r\nline two'", "line one\\\r\nline two"],
  ["single-quoted spaced backslash newline", "'line one\\ \t\nline two'", "line one\\ \t\nline two"],
  ["double-quoted ordinary backslashes", '"C:\\temp\\file\\q"', "C:\\temp\\file\\q"],
  ["double-quoted shell escapes", '"a\\$b\\`c\\"d\\\\e"', 'a$b`c"d\\e'],
  ["double-quoted continuation", '"first\\\nsecond"', "firstsecond"],
  ["unquoted continuation", "first\\\nsecond", "firstsecond"],
  ["double-quoted literal CRLF", '"first\\\r\nsecond"', "first\\\r\nsecond"],
  ["double-quoted spaced backslash newline", '"first\\ \nsecond"', "first\\ \nsecond"],
  ["escaped trailing space", "last\\ ", "last "],
  ["adjacent quoting", "first' second'\" third\"\\ fourth", "first second third fourth"],
  ["shellQuote apostrophe", "'can'\\''t'", "can't"],
  ["ANSI-C known escapes", "$'first\\r\\n\\t\\x41\\u0042\\101'", "first\r\n\tABA"],
  ["ANSI-C literal backslash newline", "$'first\\\nsecond'", "first\\\nsecond"],
  ["ANSI-C unknown escape", "$'C:\\path'", "C:\\path"],
];

for (const [name, word, expected] of shellCases) {
  test(`cURL import preserves ${name}`, () => {
    assert.deepEqual(Array.from(c.splitShellWords(word)), [expected]);
    const parsed = c.parseCurlCommand(`curl 'https://example.com/path' --data-raw ${word}`);
    assert.ok(parsed && !parsed.error);
    assert.equal(parsed.body, expected);
    assert.equal(parsed.requestText.slice(parsed.requestText.indexOf("\n\n") + 2), expected);
  });
}

test("continuations join command, option and URL tokens without creating empty arguments", () => {
  const parsed = c.parseCurlCommand("cu\\\nrl \\\n--data-\\\nraw 'body' \\\n'https://example.com/path'");
  assert.ok(parsed && !parsed.error);
  assert.equal(parsed.body, "body");
  assert.equal(parsed.path, "/path");
  assert.deepEqual(Array.from(c.splitShellWords("\\\n")), []);
  assert.deepEqual(Array.from(c.splitShellWords("first\\ \nsecond")), ["first ", "second"]);
});

test("quoted empty words and malformed quotes keep their existing contracts", () => {
  assert.deepEqual(Array.from(c.splitShellWords("one '' \"\" $'' two")), ["one", "", "", "", "two"]);
  for (const input of ["'missing", '"missing', "$'missing"]) {
    assert.deepEqual(Array.from(c.splitShellWords(input)), []);
    assert.equal(c.parseCurlCommand(`curl https://example.com --data-raw ${input}`), null);
  }
});

for (const option of ["-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "--json"]) {
  test(`${option} distinguishes an empty body argument from a missing argument`, () => {
    for (const quoted of ["''", '\"\"', "$''"]) {
      for (const command of [
        `curl https://example.com/upload ${option} ${quoted}`,
        `curl ${option} ${quoted} https://example.com/upload`,
      ]) {
        const parsed = c.parseCurlCommand(command);
        assert.ok(parsed && !parsed.error);
        assert.equal(parsed.method, "POST");
        assert.equal(parsed.body, "");
        assert.ok(parsed.requestText.endsWith("\n\n"));
        const headers = Array.from(parsed.headers, header => [header.name, header.value]);
        assert.ok(headers.some(([name, value]) => name === "Content-Type"
          && value === (option === "--json" ? "application/json" : "application/x-www-form-urlencoded")));
      }
    }
    assert.match(c.parseCurlCommand(`curl https://example.com ${option}`).error, /requires a value/);
  });
}

test("empty body arguments retain explicit methods and multi-part concatenation", () => {
  assert.equal(c.parseCurlCommand("curl https://example.com -X PUT --data-raw ''").method, "PUT");
  assert.equal(c.parseCurlCommand("curl https://example.com --get --data-raw ''").method, "GET");
  assert.equal(c.parseCurlCommand("curl https://example.com --data-raw '' --data-raw value --data-raw ''").body, "value&");
});

test("empty and missing non-body option values remain rejected", () => {
  for (const option of ["-X", "--request", "-H", "--header", "--url"]) {
    for (const value of ["", " ''"]) {
      assert.match(c.parseCurlCommand(`curl https://example.com ${option}${value}`).error, /requires a value/);
    }
  }
});

test("shell syntax is imported as text without evaluating substitutions", () => {
  const body = '$HOME $(printf unsafe) `printf unsafe`; <literal> *';
  const parsed = c.parseCurlCommand(`curl https://example.com --data-raw '${body}'`);
  assert.equal(parsed.body, body);
  assert.deepEqual(Array.from(c.splitShellWords('"$HOME $(printf unsafe) `printf unsafe`"')), ['$HOME $(printf unsafe) `printf unsafe`']);
});

test("unsupported cURL body sources and captured binary or truncated bodies stay blocked", () => {
  for (const option of ["--data @fixture.txt", "--data-binary @fixture.txt", "--data-urlencode @fixture.txt", "--form field=value"]) {
    assert.ok(c.parseCurlCommand(`curl https://example.com ${option}`).error);
  }
  assert.ok(c.parseCurlCommand("curl https://example.com --data-binary $'\\x01'").error);
  assert.equal(c.parseCurlCommand("curl https://example.com --data-raw '@literal'").body, "@literal");
  for (const request of [
    { body_preview: "AQ==", body_encoding: "base64" },
    { body_preview: "partial", body_encoding: "utf8", preview_truncated: true },
  ]) {
    assert.equal(c.recordToFormat({ request }, "curl"), "");
  }
  assert.equal(toasts.length, 2);
});
