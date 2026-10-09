// Pure display of synthetic saved transactions; no fuzzer execution or requests.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture(modes) {
  const panes = new Map();
  const els = { fuzzerDetailReqCM: {}, fuzzerDetailResCM: {}, fuzzerDetailResponseMeta: {} };
  const c = loadFunctions([
    "renderFuzzerDetailPanes", "buildRawRequest", "buildRawResponse", "buildRawRequestHead", "buildRawResponseHead",
    "normalizedHeaders", "mergeHeaders", "headerNameEquals", "renderBody", "binaryBodyPlaceholder", "formatSize",
    "prettyFormat", "prettyJsonText", "toHexDump", "buildMessageHexPresentation", "toHexDumpFromHttpParts",
    "messageBodyBytes", "base64ToBytes", "toHexDumpFromBytes",
  ], {
    els, _fuzzerDetailViewModes: modes, TextEncoder, Uint8Array, atob,
    syncFuzzerDetailTabs() {}, syncFuzzerResponsePreview() {},
    updateCodePaneCM(key, container, text, options) { panes.set(key, { text, options }); },
  });
  return { c, panes, els };
}

function record(side, message) {
  return {
    kind: "http", host: "example.com", method: "POST", path: "/saved", status: 200,
    http_version: "HTTP/1.1", response_http_version: "HTTP/2",
    request: { headers: [], body_preview: "" }, response: { headers: [], body_preview: "" },
    [side]: { headers: [], body_size: 128, ...message },
  };
}

function head(side) {
  return side === "request" ? "POST /saved HTTP/1.1\nhost: example.com" : "HTTP/2 200";
}

function dumpBytes(text) {
  return text.split("\n").filter(line => /^[0-9a-f]{8}  /i.test(line))
    .flatMap(line => (line.slice(10, 59).match(/[0-9a-f]{2}/g) || []).map(byte => parseInt(byte, 16)));
}

const examples = [
  ["complete binary", "AAEC/w==", "base64", false],
  ["truncated binary", "AAEC/w==", "base64", true],
  ["complete text", "café 😀\n  ", "utf8", false],
  ["truncated text", "café 😀\n  ", "utf8", true],
  ["complete empty", "", "utf8", false],
  ["truncated empty text", "", "utf8", true],
  ["truncated empty binary", "", "base64", true],
];

for (const side of ["request", "response"]) {
  for (const [label, body_preview, body_encoding, preview_truncated] of examples) {
    test(`saved-result ${side} Hex contains only saved bytes for ${label}`, () => {
      const f = fixture({ request: "raw", response: "raw", [side]: "hex" });
      const saved = record(side, { body_preview, body_encoding, preview_truncated });
      const original = JSON.stringify(saved);
      f.c.renderFuzzerDetailPanes(saved);
      const pane = f.panes.get(side === "request" ? "fuzzerDetailReq" : "fuzzerDetailRes");
      const body = Buffer.from(body_preview, body_encoding === "base64" ? "base64" : "utf8");
      const expected = Buffer.concat([Buffer.from(head(side)), ...(body.length ? [Buffer.from("\n\n"), body] : [])]);
      assert.deepEqual(dumpBytes(pane.text), Array.from(expected));
      assert.equal(pane.options.mode, "hex");
      assert.equal(pane.text.includes("\n\n[preview truncated]"), preview_truncated);
      assert.equal(JSON.stringify(saved), original);
    });
  }

  test(`saved-result ${side} invalid binary Hex keeps its notice outside body bytes`, () => {
    const f = fixture({ request: "hex", response: "hex" });
    const saved = record(side, { body_preview: "not valid base64!", body_encoding: "base64", preview_truncated: true });
    f.c.renderFuzzerDetailPanes(saved);
    const pane = f.panes.get(side === "request" ? "fuzzerDetailReq" : "fuzzerDetailRes");
    assert.deepEqual(dumpBytes(pane.text), Array.from(Buffer.from(head(side))));
    assert.match(pane.text, /\n\n\[Invalid base64 preview; body bytes unavailable\]\n\n\[preview truncated\]$/);
  });

  for (const mode of ["raw", "pretty"]) {
    test(`saved-result ${side} ${mode} retains existing text formatting`, () => {
      const f = fixture({ request: mode, response: mode });
      const saved = record(side, { body_preview: '{"id":9007199254740993,"tag":"a","tag":"b"}', body_encoding: "utf8", content_type: "application/json" });
      const original = JSON.stringify(saved);
      f.c.renderFuzzerDetailPanes(saved);
      const pane = f.panes.get(side === "request" ? "fuzzerDetailReq" : "fuzzerDetailRes");
      const body = mode === "raw"
        ? '{"id":9007199254740993,"tag":"a","tag":"b"}'
        : '{\n  "id": 9007199254740993,\n  "tag": "a",\n  "tag": "b"\n}';
      assert.equal(pane.text, `${head(side)}\n\n${body}`);
      assert.equal(pane.options.mode, "http");
      assert.equal(JSON.stringify(saved), original);
    });
  }
}

test("saved-result missing response keeps its existing text and empty metadata in every view", () => {
  for (const mode of ["raw", "pretty", "hex"]) {
    const f = fixture({ request: mode, response: mode });
    const saved = record("request", {});
    delete saved.response;
    f.c.renderFuzzerDetailPanes(saved);
    assert.equal(f.panes.get("fuzzerDetailRes").text, "No response captured.");
    assert.equal(f.panes.get("fuzzerDetailRes").options.mode, "http");
    assert.equal(f.els.fuzzerDetailResponseMeta.textContent, "");
  }
});

test("saved-result Hex preserves status metadata and ignores an absent saved record", () => {
  const f = fixture({ request: "hex", response: "hex" });
  f.c.renderFuzzerDetailPanes(null);
  assert.equal(f.panes.size, 0);
  f.c.renderFuzzerDetailPanes(record("response", { body_preview: "AAEC", body_encoding: "base64", content_type: "application/octet-stream" }));
  assert.equal(f.els.fuzzerDetailResponseMeta.textContent, "200 · application/octet-stream");
});
