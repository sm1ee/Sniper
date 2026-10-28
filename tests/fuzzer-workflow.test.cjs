// Synthetic draft fixtures only. No browser, proxy, server, or outbound requests.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const workflow = require("../web/fuzzer-workflow.js");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const request = (patch = {}) => ({
  scheme: "https", host: "example.com", method: "GET", path: "/items?q=$payload$",
  headers: [{ name: "Host", value: "example.com" }], body: "", body_encoding: "utf8", preview_truncated: false,
  ...patch,
});
const rawForm = (body = "q=one&q=two&empty=", newline = "\n") => [
  "POST /search?q=a%2Bb&q=x+y&empty=&flag&value=a=b HTTP/1.1", "Host: example.com",
  "Content-Type: application/x-www-form-urlencoded; charset=UTF-8", "", body,
].join(newline);

test("module exports the same pure browser and CommonJS API", () => {
  const source = fs.readFileSync(path.join(__dirname, "../web/fuzzer-workflow.js"), "utf8");
  const context = vm.createContext({ window: {}, TextEncoder });
  vm.runInContext(source, context);
  assert.deepEqual(Object.keys(context.window.SniperFuzzerWorkflow), Object.keys(workflow));
  assert.ok(Object.isFrozen(context.window.SniperFuzzerWorkflow));
  assert.equal(context.window.SniperFuzzerWorkflow.payloadText([""]), "\n");
});

test("local safety limits stay aligned with the backend Fuzzer constants", () => {
  const rust = fs.readFileSync(path.join(__dirname, "../src/fuzzer.rs"), "utf8");
  for (const [key, name] of [
    ["payloads", "MAX_FUZZER_PAYLOADS"], ["payloadBytes", "MAX_FUZZER_PAYLOAD_BYTES"],
    ["totalPayloadBytes", "MAX_FUZZER_TOTAL_PAYLOAD_BYTES"], ["markers", "MAX_FUZZER_MARKERS_PER_REQUEST"],
    ["expandedRequestBytes", "MAX_FUZZER_EXPANDED_REQUEST_BYTES"], ["requests", "MAX_FUZZER_REQUESTS"],
    ["concurrency", "MAX_FUZZER_CONCURRENCY"],
  ]) {
    const expression = rust.match(new RegExp(`const ${name}: usize = ([0-9_* ]+);`));
    assert.ok(expression, name);
    const value = expression[1].split("*").reduce((product, part) => product * Number(part.trim().replace(/_/g, "")), 1);
    assert.equal(workflow.limits[key], value, name);
  }
});

test("payload lines match the existing editor semantics exactly", () => {
  const legacy = loadFunctions(["splitFuzzerPayloadLines"]);
  for (const text of [undefined, null, "", "a", " ", "a\n", "\n", "\n\n", "a\n\n", " a \r\nb\r\r\n", "$1\n$&\n😀\n"]) {
    assert.deepEqual(workflow.payloadLines(text), Array.from(legacy.splitFuzzerPayloadLines(text)));
  }
});

test("editor serialization round-trips empty and trailing empty payloads without trimming or deduplication", () => {
  for (const payloads of [[], [""], ["", ""], ["a", ""], ["a", "", ""], [" a ", "😀", "a", "a"]]) {
    assert.deepEqual(workflow.payloadLines(workflow.payloadText(payloads)), payloads);
  }
  assert.throws(() => workflow.payloadText(["a\nb"]), /single-line/);
  assert.throws(() => workflow.payloadText(["a\rb"]), /single-line/);
  assert.throws(() => workflow.payloadText([1]), /single-line/);
});

test("payload validation uses UTF-8 bytes and Rust's single trailing-CR normalization", () => {
  assert.deepEqual(workflow.validatePayloads(["", " a ", "é", "😀", "x\r", "y\r\r"]), {
    valid: true, errors: [], count: 6, totalBytes: 12, maxPayloadBytes: 4,
    payloads: ["", " a ", "é", "😀", "x", "y\r"],
  });
  assert.equal(workflow.validatePayloads([]).valid, false);
  assert.equal(workflow.validatePayloads([null]).valid, false);
  assert.equal(workflow.validatePayloads(Array(5000).fill("")).valid, true);
  assert.match(workflow.validatePayloads(Array(5001).fill("")).errors[0], /5000/);
  assert.equal(workflow.validatePayloads(["😀".repeat(16384)]).valid, true);
  assert.match(workflow.validatePayloads(["😀".repeat(16385)]).errors[0], /65536 bytes/);
  assert.equal(workflow.validatePayloads(Array(64).fill("a".repeat(65536))).valid, true);
  assert.match(workflow.validatePayloads(Array(65).fill("a".repeat(65536))).errors[0], /4194304 total bytes/);
});

test("generic presets include an empty payload, stay bounded, and serialize losslessly", () => {
  assert.deepEqual(workflow.presets.map(preset => preset.id), ["text-boundaries", "number-boundaries"]);
  for (const preset of workflow.presets) {
    assert.ok(preset.payloads.includes(""));
    assert.equal(workflow.validatePayloads(preset.payloads).valid, true);
    assert.deepEqual(workflow.payloadLines(workflow.payloadText(preset.payloads)), preset.payloads);
    assert.ok(Object.isFrozen(preset.payloads));
  }
});

test("numeric ranges are inclusive when reachable and support safe descending integers", () => {
  assert.deepEqual(workflow.numericRange("1", "5", "2"), ["1", "3", "5"]);
  assert.deepEqual(workflow.numericRange(5, -1, -2), ["5", "3", "1", "-1"]);
  assert.deepEqual(workflow.numericRange(1, 4, 2), ["1", "3"]);
  assert.deepEqual(workflow.numericRange(3, 3, -5), ["3"]);
  assert.deepEqual(workflow.numericRange(Number.MAX_SAFE_INTEGER - 1, Number.MAX_SAFE_INTEGER), ["9007199254740990", "9007199254740991"]);
  assert.deepEqual(workflow.numericRange(-Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER), ["-9007199254740991", "0", "9007199254740991"]);
  assert.equal(workflow.numericRange(1, 5000).length, 5000);
});

test("numeric ranges reject unsafe, fractional, missing, zero-step, reverse and oversized ranges before allocating", () => {
  for (const args of [["", 10, 1], [0, 1, ""], [1.2, 3, 1], [1, 3, 0], [1, 3, -1], [3, 1, 1], [1, 5001, 1], ["1e2", 200, 1], [false, 1, 1], [Infinity, 5, 1], [Number.MAX_SAFE_INTEGER + 1, 2, 1]]) {
    assert.throws(() => workflow.numericRange(...args), Error, String(args));
  }
});

for (const newline of ["\n", "\r\n"]) {
  test(`query and form candidates preserve literal values and duplicate offsets with ${JSON.stringify(newline)}`, () => {
    const raw = rawForm(undefined, newline);
    const candidates = workflow.candidates(raw);
    assert.deepEqual(candidates.map(candidate => [candidate.kind, raw.slice(candidate.start, candidate.end)]), [
      ["query", "a%2Bb"], ["query", "x+y"], ["query", ""], ["query", "a=b"],
      ["form", "one"], ["form", "two"], ["form", ""],
    ]);
    assert.deepEqual(candidates.slice(0, 2).map(candidate => candidate.label), ["Query: q (1)", "Query: q (2)"]);
    assert.deepEqual(candidates.slice(4, 6).map(candidate => candidate.label), ["Form: q (1)", "Form: q (2)"]);
    for (const candidate of candidates) {
      assert.deepEqual(Object.keys(candidate), ["kind", "label", "start", "end"]);
      const changed = workflow.replaceSelection(raw, candidate.start, candidate.end);
      assert.equal(changed.slice(0, candidate.start), raw.slice(0, candidate.start));
      assert.equal(changed.slice(candidate.start, candidate.end + 2), `§${raw.slice(candidate.start, candidate.end)}§`);
      assert.equal(changed.slice(candidate.end + 2), raw.slice(candidate.end));
    }
  });
}

test("absolute request targets, Unicode offsets and encoded parameter names stay draft-local", () => {
  const raw = "GET https://example.com/😀?na%6De=%2F&na%6De=é&x=😀#ignored=yes HTTP/1.1\nHost: example.com";
  const candidates = workflow.candidates(raw);
  assert.deepEqual(candidates.map(candidate => raw.slice(candidate.start, candidate.end)), ["%2F", "é", "😀"]);
  assert.equal(candidates[1].label, "Query: na%6De (2)");
  assert.equal(candidates[2].start, raw.indexOf("😀#"));
});

test("suggestions skip credential names, headers, existing markers and non-value parameters", () => {
  const raw = "GET /?q=ok&token=synthetic&password=synthetic&api_key=synthetic&session_id=synthetic&key=synthetic&q=$payload$&flag HTTP/1.1\nHost: example.com\nX-Query: q=header\nCookie: q=synthetic";
  assert.deepEqual(workflow.candidates(raw).map(candidate => raw.slice(candidate.start, candidate.end)), ["ok"]);
});

test("suggestions are capped without combining or rewriting duplicate keys", () => {
  const raw = `GET /?${Array.from({ length: 200 }, (_, i) => `q=${i}`).join("&")} HTTP/1.1\nHost: example.com`;
  const candidates = workflow.candidates(raw);
  assert.equal(candidates.length, workflow.limits.candidates);
  assert.equal(candidates.at(-1).label, "Query: q (128)");
  assert.equal(raw.slice(candidates.at(-1).start, candidates.at(-1).end), "127");
});

test("form suggestions reject binary, base64, truncated, encoded, ambiguous and non-form bodies while retaining safe query spans", () => {
  const cases = [
    [rawForm(), { bodyEncoding: "base64" }], [rawForm(), { previewTruncated: true }],
    [rawForm("q=\u0000"), {}], [rawForm("q=one\r\n"), {}], [rawForm("q=�"), {}],
    [rawForm().replace("Content-Type:", "Content-Encoding: gzip\nContent-Type:"), {}],
    [rawForm().replace("Content-Type:", "Content-Type: application/json\nContent-Type:"), {}],
    [rawForm().replace("application/x-www-form-urlencoded", "application/json"), {}],
    [rawForm().replace("application/x-www-form-urlencoded", "multipart/form-data"), {}],
  ];
  for (const [raw, options] of cases) {
    const candidates = workflow.candidates(raw, options);
    assert.ok(candidates.length > 0);
    assert.ok(candidates.every(candidate => candidate.kind === "query"));
  }
  assert.ok(workflow.candidates(rawForm().replace("Content-Type:", "Content-Encoding: identity\nContent-Type:")).some(candidate => candidate.kind === "form"));
});

test("selection marking keeps the original between marks, allows empty values, and rejects nested/partial markers and split characters", () => {
  assert.equal(workflow.replaceSelection("a=", 2, 2), "a=§§");
  assert.equal(workflow.replaceSelection("a=$&", 2, 4), "a=§$&§");
  for (const [start, end] of [[1, 2], [2, 4], [0, 8], [3, 3]]) {
    assert.throws(() => workflow.replaceSelection("$payload$", start, end), /overlaps a marked position/);
  }
  assert.throws(() => workflow.replaceSelection("q=§one§", 3, 4), /overlaps a marked position/);
  assert.throws(() => workflow.replaceSelection("a§b", 0, 3), /without §/);
  assert.equal(workflow.replaceSelection("$payload$", 9, 9), "$payload$§§");
  assert.throws(() => workflow.replaceSelection("😀", 1, 2), /complete character/);
  for (const [start, end] of [[-1, 0], [0, 3], [2, 1], [0.5, 1], [NaN, 1]]) {
    assert.throws(() => workflow.replaceSelection("ab", start, end), /current request/);
  }
});

test("expansion replaces all supported markers with the same literal payload and leaves scheme untouched", () => {
  const template = request({ scheme: "$payload$", host: "$payload$.example.com", method: "$payload$", path: "/$payload$/$payload$", headers: [{ name: "x-$payload$", value: "$payload$" }], body: "$payload$" });
  const snapshot = JSON.stringify(template), payload = "$1-$&-$$-$`-$'-$payload$";
  const expanded = workflow.expandTemplate(template, payload);
  assert.equal(expanded.scheme, "$payload$");
  assert.equal(expanded.host, `${payload}.example.com`);
  assert.equal(expanded.method, payload);
  assert.equal(expanded.path, `/${payload}/${payload}`);
  assert.deepEqual(expanded.headers, [{ name: `x-${payload}`, value: payload }]);
  assert.equal(expanded.body, payload);
  assert.equal(JSON.stringify(template), snapshot);
});

test("literal Host precedence ignores authority markers and chooses the first expanded Host", () => {
  const template = request({ host: "authority-$payload$.example.com", path: "/", headers: [{ name: "hOsT", value: "header-$payload$.example.com" }, { name: "Host", value: "second.example.com" }] });
  assert.equal(workflow.preflight(template, ["demo"]).markerCount, 1);
  assert.equal(workflow.expandTemplate(template, "demo").host, "header-demo.example.com");
  template.headers[0].value = "fixed.example.com";
  const checked = workflow.preflight(template, ["demo"]);
  assert.equal(checked.markerCount, 0);
  assert.match(checked.errors[0], /Mark at least one position/);
  assert.ok(!checked.warnings.some(warning => /Host markers/.test(warning)));
});

test("a marker in a header name can create Host after literal expansion", () => {
  const template = request({ host: "old.example.com", headers: [{ name: "$payload$", value: "new.example.com" }] });
  const expanded = workflow.expandTemplate(template, "Host");
  assert.equal(expanded.host, "new.example.com");
  assert.match(workflow.preflight(template, ["Host"]).warnings.join(" "), /Header-name markers/);
});

test("Content-Length normalization matches Rust UTF-8 sizing, deduplication and ordering", () => {
  const template = request({ body: "q=$payload$", headers: [{ name: "content-length", value: "0" }, { name: "X-Keep", value: "yes" }, { name: "CONTENT-LENGTH", value: "20" }] });
  const expanded = workflow.expandTemplate(template, "é😀");
  assert.deepEqual(expanded.headers, [{ name: "X-Keep", value: "yes" }, { name: "Content-Length", value: "8" }]);
  assert.deepEqual(workflow.expandTemplate(request({ body: "$payload$", headers: [] }), "x").headers, []);
  assert.equal(workflow.expandTemplate(template, "").headers.at(-1).value, "2");
});

test("base64 Content-Length uses decoded length only for canonical Rust STANDARD input", () => {
  for (const [body, length] of [["", "0"], ["YQ==", "1"], ["YWI=", "2"], ["YWJj", "3"], ["8J+YgA==", "4"]]) {
    const expanded = workflow.expandTemplate(request({ body, body_encoding: "base64", headers: [{ name: "content-length", value: "99" }] }), "x");
    assert.deepEqual(expanded.headers, [{ name: "Content-Length", value: length }]);
  }
  for (const body of ["YQ", "YR==", "YWJ=", "YQ==\n", "====", "A===", "-w==", "$payload$"]) {
    const expanded = workflow.expandTemplate(request({ body, body_encoding: "base64", headers: [{ name: "content-length", value: "99" }] }), "!");
    assert.deepEqual(expanded.headers, [{ name: "content-length", value: "99" }], body);
  }
  const expanded = workflow.expandTemplate(request({ body: "$payload$", body_encoding: "base64", headers: [{ name: "Content-Length", value: "99" }] }), "YQ==");
  assert.equal(expanded.headers[0].value, "1");
});

test("preflight reports one planned request per payload, repeated markers, exact counts and normalized samples", () => {
  const template = request({ method: "POST", body: "$payload$", headers: [{ name: "Host", value: "example.com" }, { name: "Content-Length", value: "0" }] });
  const checked = workflow.preflight(template, ["", "é\r", "😀", "extra"], { httpVersion: "HTTP/2" });
  assert.equal(checked.valid, true);
  assert.equal(checked.markerCount, 2);
  assert.equal(checked.payloadCount, 4);
  assert.equal(checked.requestCount, 4);
  assert.equal(checked.totalPayloadBytes, 11);
  assert.equal(checked.httpVersion, "HTTP/2");
  assert.equal(checked.samples.length, 3);
  assert.equal(checked.samples[1].payload, "é");
  assert.equal(checked.samples[1].request.path, "/items?q=é");
  assert.equal(checked.samples[1].request.body, "é");
  assert.match(checked.warnings.join(" "), /Match and Replace/);
  const sniper = workflow.preflight(template, ["", "é\r", "😀", "extra"], { attackType: "sniper" });
  assert.equal(sniper.requestCount, 8, "each of the two positions takes every payload");
  assert.deepEqual(sniper.samples.map(sample => sample.position), [0, 0, 0]);
});

test("Sniper fills one position and keeps the others, as src/fuzzer.rs does", () => {
  const template = request({ path: "/search?q=§test§&page=§1§" });
  assert.equal(workflow.expandTemplate(template, "x", { position: 0 }).path, "/search?q=x&page=1");
  assert.equal(workflow.expandTemplate(template, "x", { position: 1 }).path, "/search?q=test&page=x");
  assert.equal(workflow.expandTemplate(template, "x").path, "/search?q=x&page=x", "Battering ram");
  const legacy = request({ path: "/a/$payload$?q=§test§" });
  assert.equal(workflow.expandTemplate(legacy, "x", { position: 1 }).path, "/a/?q=x");
  assert.deepEqual(workflow.planRequests("sniper", 2, 3), [[0, 0], [0, 1], [0, 2], [1, 0], [1, 1], [1, 2]]);
  assert.deepEqual(workflow.planRequests("battering_ram", 2, 3), [[null, 0], [null, 1], [null, 2]]);
});

test("URL encoding keeps a payload one value and touches only the URL, as src/fuzzer.rs does", () => {
  const payload = "../a b&c=d%27\"<x>#";
  assert.equal(workflow.encodeUrlPayload(payload), "../a%20b%26c%3Dd%27%22%3Cx%3E%23");
  assert.equal(workflow.encodeUrlPayload("é"), "%C3%A9");
  const template = request({ method: "POST", path: "/p?q=§§&n=1", body: '{"v":"§§"}' });
  const built = workflow.expandTemplate(template, payload, { urlEncode: true });
  assert.equal(built.path, "/p?q=../a%20b%26c%3Dd%27%22%3Cx%3E%23&n=1");
  assert.equal(built.body, `{"v":"${payload}"}`);
  assert.equal(workflow.expandTemplate(template, "a b").path, "/p?q=a b&n=1");
});

test("an attack sends at most the backend's request limit", () => {
  const template = request({ path: "/" + "§a§".repeat(20) });
  const checked = workflow.preflight(template, Array(5000).fill("x"), { attackType: "sniper" });
  assert.equal(checked.requestCount, 100000);
  assert.match(checked.errors.join(" "), /at most 50000/);
  assert.equal(workflow.preflight(template, Array(5000).fill("x")).valid, true, "Battering ram sends one request per payload");
});

test("effective targets preserve overrides, explicit ports, IPv6 and payload-dependent Host", () => {
  const template = request({ host: "logical.example.com:8080", headers: [{ name: "Host", value: "$payload$.example.com:8080" }] });
  const checked = workflow.preflight(template, ["one", "two"]);
  assert.equal(checked.effectiveTarget, "https://$payload$.example.com:8080");
  assert.equal(checked.samples[0].effectiveTarget, "https://one.example.com:8080");
  assert.equal(checked.samples[1].effectiveTarget, "https://two.example.com:8080");
  const overridden = workflow.preflight(template, ["one"], { target: { scheme: "http", host: "::1", port: "9000" } });
  assert.equal(overridden.effectiveTarget, "http://[::1]:9000");
  assert.equal(overridden.samples[0].request.host, "one.example.com:8080");
  assert.equal(workflow.preflight(template, ["x"], { target: { host: "destination.example.com" } }).effectiveTarget, "https://destination.example.com:8080");
  assert.equal(workflow.preflight(request(), ["x"]).effectiveTarget, "https://example.com:443");
});

test("preflight marker and expanded byte limits mirror backend field accounting", () => {
  const marker = workflow.MARKER;
  assert.equal(workflow.preflight(request({ path: marker.repeat(128) }), [""]).valid, true);
  assert.match(workflow.preflight(request({ path: marker.repeat(129) }), [""]).errors.join(" "), /128/);
  const oversized = workflow.preflight(request({ path: marker.repeat(65) }), ["a".repeat(65536)]);
  assert.equal(oversized.valid, false);
  assert.match(oversized.errors.join(" "), /4194304/);
  assert.equal(oversized.samples.length, 0);
  const template = request({ host: marker.repeat(128), path: "/", headers: [{ name: "Host", value: `header-${marker}.example.com` }] });
  const checked = workflow.preflight(template, ["a".repeat(65536)]);
  assert.equal(checked.valid, true);
  assert.equal(checked.markerCount, 1);
  assert.equal(checked.maxExpandedRequestBytes, Buffer.byteLength("https") + Buffer.byteLength(template.host) + 3 + 1 + 4 + Buffer.byteLength("header-.example.com") + 65536);
});

test("expanded byte accounting measures UTF-8, including non-marker fields", () => {
  const template = request({ path: "/é/$payload$", body: "😀$payload$", headers: [{ name: "X-Text", value: "é" }] });
  const checked = workflow.preflight(template, ["", "😀"]);
  const expanded = workflow.expandTemplate(template, "😀");
  const fields = [expanded.scheme, expanded.host, expanded.method, expanded.path, expanded.body, ...expanded.headers.flatMap(header => [header.name, header.value])];
  assert.equal(checked.maxExpandedRequestBytes, fields.reduce((sum, value) => sum + Buffer.byteLength(value), 0));
});

test("preflight samples are bounded and never silently truncate generated request objects", () => {
  const checked = workflow.preflight(request({ body: workflow.MARKER.repeat(32) }), Array(5000).fill("a".repeat(800)));
  assert.equal(checked.valid, true);
  assert.ok(checked.samples.length < 3);
  assert.equal(checked.samples.length + checked.samplesOmitted, 3);
  assert.ok(checked.samples.every(sample => sample.request.body === "a".repeat(800 * 32)));
  assert.match(checked.warnings.join(" "), /omitted/);
  const oversizedSample = workflow.preflight(request(), ["a".repeat(65536)]);
  assert.equal(oversizedSample.valid, true);
  assert.equal(oversizedSample.samples.length, 0);
  assert.equal(oversizedSample.samplesOmitted, 1);
});

test("truncated request bodies fail setup while a base64 source warns and keeps literal expansion semantics", () => {
  assert.equal(workflow.preflight(request({ preview_truncated: true }), ["x"]).valid, false);
  const checked = workflow.preflight(request({ body: "YQ==", body_encoding: "base64" }), ["x"]);
  assert.equal(checked.valid, true);
  assert.match(checked.warnings.join(" "), /encoded text/);
  assert.equal(checked.samples[0].request.body, "YQ==");
});

test("helpers reject missing validated request models without exposing traffic in errors", () => {
  assert.throws(() => workflow.preflight({}, ["x"]), /validated by the request editor/);
  assert.throws(() => workflow.expandTemplate(request(), null), /Payload must be a string/);
});


test('marker edits preserve originals and reject malformed pairing, surrogate and CRLF splits', () => {
  assert.equal(workflow.clearPositions('§original§/$payload$/§§/lone§'), 'original///lone§');
  assert.equal(workflow.clearPositions('§$payload$§'), '$payload$');
  assert.equal(workflow.replaceSelection('abc', 1, 1), 'a§§bc');
  assert.throws(() => workflow.replaceSelection('§abc', 2, 3), /unmatched/);
  assert.throws(() => workflow.replaceSelection('a\r\nb', 2, 2), /line break/);
  assert.throws(() => workflow.replaceSelection('😀', 1, 1), /complete character/);
  assert.throws(() => workflow.replaceSelection('§abc§', 2, 2), /overlaps/);
});

test('raw request marker editing is field bounded and preserves mixed line endings', () => {
  const raw = 'GET /§a§/literal§ HTTP/1.1\nHost: example.com\r\nX-§: value§\n\n§line\r\nbody§';
  assert.equal(workflow.clearRequestPositions(raw), 'GET /a/literal§ HTTP/1.1\nHost: example.com\r\nX-§: value§\n\nline\r\nbody');
  const unmarked = 'GET /literal§ HTTP/1.1\r\nHost: example.com\r\nX-Note: value\r\n\r\n';
  const at = unmarked.indexOf('value');
  assert.equal(workflow.markRequestSelection(unmarked, at, at + 5), unmarked.replace('value', '§value§'));
  assert.throws(() => workflow.markRequestSelection(raw, raw.indexOf('X-'), raw.indexOf('value') + 5), /one request field/);
  assert.equal(workflow.clearRequestPositions('GET https://example.com/§a§ HTTP/1.1\r\n\r\n'), 'GET https://example.com/a HTTP/1.1\r\n\r\n');
});

test('targeted removal keeps originals and only removes unambiguous selected positions', () => {
  const raw = 'GET /§one§/§two§/$payload$/literal§ HTTP/1.1\r\nHost: example.com\r\n\r\n';
  const a = raw.indexOf('§one§'), b = raw.indexOf('§two§');
  for (const [from, to] of [[a + 1, a + 1], [a, a + 5], [a + 2, a + 3]]) {
    const result = workflow.removeRequestSelection(raw, from, to);
    assert.equal(result.text, raw.replace('§one§', 'one'));
    assert.equal(result.text.slice(result.from, result.to), 'one');
  }
  assert.equal(workflow.removeRequestSelection(raw, a, b + 5).text, raw.replace('§one§/§two§', 'one/two'));
  const legacy = raw.indexOf('$payload$');
  assert.equal(workflow.removeRequestSelection(raw, legacy + 2, legacy + 2).text, raw.replace('$payload$', ''));
  for (const [from, to] of [[a, a], [a + 5, a + 5], [0, 0], [a + 2, b + 5], [a, b + 2]]) {
    assert.throws(() => workflow.removeRequestSelection(raw, from, to));
  }
  const empty = 'GET /§§ HTTP/1.1\r\n\r\n';
  assert.equal(workflow.removeRequestSelection(empty, 6, 6).text, 'GET / HTTP/1.1\r\n\r\n');
});

test('targeted removal respects request fields, literal syntax, Unicode and unchanged raw bytes', () => {
  const raw = 'GET /literal§ HTTP/1.1\r\nX-§: value§\nOther: §한😀글§\r\n\r\n§line\r\nbody§';
  const from = raw.indexOf('§한'), to = raw.length;
  assert.equal(workflow.removeRequestSelection(raw, from, to).text, raw.replace('§한😀글§', '한😀글').replace('§line\r\nbody§', 'line\r\nbody'));
  assert.throws(() => workflow.removeRequestSelection(raw, raw.indexOf('😀') + 1, raw.indexOf('😀') + 1), /complete character/);
  assert.throws(() => workflow.removeRequestSelection(raw, raw.lastIndexOf('\r\n') + 1, raw.lastIndexOf('\r\n') + 1), /line break/);
  assert.throws(() => workflow.removeRequestSelection(raw, raw.indexOf('literal'), raw.indexOf('Other')), /marked position/);
  const escaped = 'GET /\\§value\\§ HTTP/1.1\n\n';
  assert.equal(workflow.removeRequestSelection(escaped, 8, 8).text, 'GET /\\value\\ HTTP/1.1\n\n');
  const nested = 'GET /§$payload$§ HTTP/1.1\n\n';
  assert.throws(() => workflow.removeRequestSelection(nested, 7, 7), /expose another position/);
  for (const offsets of [[-1, 0], [2, 1], [0, raw.length + 1], [NaN, 1]]) assert.throws(() => workflow.removeRequestSelection(raw, ...offsets));
});


test('targeted removal rejects marker exposure across the removed delimiters too', () => {
  const raw = 'GET /$pay§load§$ HTTP/1.1\r\n\r\n';
  assert.throws(() => workflow.removeRequestSelection(raw, raw.indexOf('load'), raw.indexOf('load')), /expose another position/);
});


test('targeted legacy removal cannot join payload-token fragments into a new position', () => {
  const raw = 'POST / HTTP/1.1\r\nHost: example.com\r\n\r\n$pay$payload$load$';
  const at = raw.indexOf('$payload$');
  assert.throws(() => workflow.removeRequestSelection(raw, at, at + 9), /expose another position/);
});
