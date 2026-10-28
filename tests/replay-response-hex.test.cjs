// Synthetic response display only; no Replay sends, traffic, or persisted state.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const HEAD = "HTTP/2 200\nContent-Type: application/octet-stream\nX-Example: first\nX-Example: second";

function fixture(message = {}, mode = "hex", legacy = false) {
  const record = {
    id: "synthetic-record", kind: "http", method: "GET", host: "example.com", path: "/synthetic",
    status: 200, duration_ms: 1, http_version: "HTTP/1.1", response_http_version: "HTTP/2",
    request: { headers: [], body_preview: "", body_encoding: "utf8" },
    response: {
      headers: [
        { name: "Content-Type", value: "application/octet-stream" },
        { name: "X-Example", value: "first" }, { name: "X-Example", value: "second" },
      ],
      body_size: 4, body_encoding: "utf8", content_type: "application/octet-stream", ...message,
    },
  };
  const tab = { id: "synthetic-tab", type: "http", requestText: "GET /synthetic HTTP/1.1\nhost: example.com", responseRecord: record };
  const state = { replayMessageViews: { request: "raw", response: mode }, replayMessageSearch: { request: "", response: "" } };
  const els = {
    replayResponseCM: legacy ? null : {}, replayResponseView: {}, replayRequestCM: {}, replayResponseMeta: {},
    replayHostInput: {}, replayPortInput: {}, replaySchemeSelect: {},
    sendReplayButton: {}, cancelReplayButton: {}, replayBackButton: {}, replayForwardButton: {},
    replayFollowRedirectButton: { classList: { toggle() {}, add() {} } },
  };
  for (const input of [els.replayHostInput, els.replayPortInput]) {
    input.attributes = {};
    input.setCustomValidity = message => { input.validationMessage = message; };
    input.setAttribute = (name, value) => { input.attributes[name] = String(value); };
  }
  let shown = null;
  let searched = null;
  const editorOptions = [];
  let destroyed = 0;
  class CodeView {
    constructor(container, options) { editorOptions.push(options); }
    setContent(text) { shown = text; }
    applySearch() {}
    destroy() { destroyed += 1; }
  }
  const c = loadFunctions([
    "renderReplay", "renderReplayResponseOnly", "renderReplayViewContent", "renderReplayResponseView", "renderReplayEmptyResponse", "setReplayTargetInputValidity",
    "buildRawResponse", "buildRawResponseHead", "normalizedHeaders", "headerNameEquals",
    "renderBody", "binaryBodyPlaceholder", "formatSize", "formatStatus", "prettyFormat", "prettyJsonText",
    "toHexDump", "buildMessageHexPresentation", "toHexDumpFromHttpParts", "messageBodyBytes",
    "base64ToBytes", "toHexDumpFromBytes", "renderCodeHtml", "renderHexHtml", "wrapCodeLine", "escapeHtml",
  ], {
    state, els, TextEncoder, TextDecoder, Uint8Array, atob,
    _replayResponseCMView: null, _replayResponseCMMode: null, SniperCodeView: CodeView,
    getActiveReplayTab: () => tab, ensureRepeaterTab: () => tab,
    getRenderedHttpReplayDraftOwner: () => null,
    syncReplayResponsePreview(text) { if (legacy) shown = text; },
    renderReplayViewTabs() {}, renderReplayTabs() {}, syncReplayToolbar() {},
    updateCodePaneCM() {}, syncReplayRequestTextFromEditor() {},
    updateReplaySearchPane(side, text) { if (side === "response") searched = text; },
    currentSessionId: () => "synthetic-session", workspaceStateGeneration: 0,
  });
  return { c, tab, record, state, els, editorOptions, destroyed: () => destroyed, shown: () => shown, searched: () => searched };
}

function dumpBytes(text) {
  return text.split("\n").filter(line => /^[0-9a-f]{8}  /i.test(line))
    .flatMap(line => (line.slice(10, 59).match(/[0-9a-f]{2}/g) || []).map(byte => parseInt(byte, 16)));
}

function expectedBytes(message) {
  const body = Buffer.from(message.body_preview || "", message.body_encoding === "base64" ? "base64" : "utf8");
  return Array.from(Buffer.concat([Buffer.from(HEAD), ...(body.length ? [Buffer.from("\n\n"), body] : [])]));
}

const controllers = {
  full: f => f.c.renderReplay(),
  responseOnly: f => f.c.renderReplayResponseOnly(f.tab),
  viewSwitch: f => f.c.renderReplayViewContent("response"),
};
const examples = [
  ["complete binary", { body_preview: "AAEC/w==", body_encoding: "base64" }],
  ["whitespace in base64", { body_preview: "AAEC\n/w==", body_encoding: "base64" }],
  ["all byte values", { body_preview: Buffer.from(Array.from({ length: 256 }, (_, i) => i)).toString("base64"), body_encoding: "base64" }],
  ["truncated binary", { body_preview: "AAEC/w==", body_encoding: "base64", preview_truncated: true, body_size: 128 }],
  ["complete Unicode", { body_preview: "café 文 😀\n  ", content_type: "text/plain" }],
  ["truncated Unicode", { body_preview: "café 文 😀\n  ", content_type: "text/plain", preview_truncated: true, body_size: 128 }],
  ["empty", { body_preview: "" }],
  ["null preview", { body_preview: null }],
  ["omitted preview", {}],
  ["truncated empty", { body_preview: "", preview_truncated: true, body_size: 128 }],
  ["truncated empty binary", { body_preview: "", body_encoding: "base64", preview_truncated: true, body_size: 128 }],
];

for (const [controller, run] of Object.entries(controllers)) {
  for (const [label, message] of examples) {
    test(`${controller}: Replay response Hex preserves saved bytes for ${label}`, () => {
      const f = fixture(message);
      const original = JSON.stringify(f.record);
      run(f);
      assert.deepEqual(dumpBytes(f.shown()), expectedBytes(message));
      assert.equal(f.shown().includes("\n\n[preview truncated]"), !!message.preview_truncated);
      assert.doesNotMatch(f.shown(), /base64 preview omitted|body bytes unavailable/);
      assert.equal(f.shown(), f.c.buildMessageHexPresentation("response", f.record, f.c.buildRawResponse(f.record)));
      assert.equal(f.searched(), f.shown());
      assert.equal(f.editorOptions.at(-1).hexHighlight, true);
      assert.equal(f.editorOptions.at(-1).readOnly, true);
      assert.equal(JSON.stringify(f.record), original);
    });
  }

  for (const preview of ["not valid base64!", "a", "AA=A", "===="]) {
    for (const truncated of [false, true]) {
      test(`${controller}: invalid binary ${JSON.stringify(preview)} keeps notices outside bytes (truncated=${truncated})`, () => {
        const f = fixture({ body_preview: preview, body_encoding: "base64", preview_truncated: truncated });
        const original = JSON.stringify(f.record);
        run(f);
        assert.deepEqual(dumpBytes(f.shown()), Array.from(Buffer.from(HEAD)));
        assert.match(f.shown(), /\n\n\[Invalid base64 preview; body bytes unavailable\]/);
        assert.equal(f.shown().includes("\n\n[preview truncated]"), truncated);
        assert.equal(f.searched(), f.shown());
        assert.equal(JSON.stringify(f.record), original);
      });
    }
  }

  for (const mode of ["raw", "pretty"]) {
    for (const truncated of [false, true]) {
      test(`${controller}: ${mode} preserves JSON text formatting (truncated=${truncated})`, () => {
        const raw = '{"id":9007199254740993,"tag":"a","tag":"b"}';
        const f = fixture({ body_preview: raw, content_type: "application/json", preview_truncated: truncated }, mode);
        const original = JSON.stringify(f.record);
        run(f);
        const body = mode === "pretty" && !truncated ? '{\n  "id": 9007199254740993,\n  "tag": "a",\n  "tag": "b"\n}' : raw;
        assert.equal(f.shown(), `${HEAD}\n\n${body}${truncated ? "\n\n[preview truncated]" : ""}`);
        assert.equal(f.editorOptions.at(-1).httpHighlight, true);
        assert.equal(f.searched(), f.shown());
        assert.equal(JSON.stringify(f.record), original);
      });

      test(`${controller}: ${mode} keeps the binary placeholder (truncated=${truncated})`, () => {
        const f = fixture({ body_preview: "AAEC/w==", body_encoding: "base64", preview_truncated: truncated }, mode);
        run(f);
        assert.equal(f.shown(), `${HEAD}\n\n[application/octet-stream, 4 B, base64 preview omitted]${truncated ? "\n\n[preview truncated]" : ""}`);
        assert.equal(f.searched(), f.shown());
      });
    }
  }

  for (const missing of [null, undefined]) {
    test(`${controller}: an exchange with ${missing} response retains its existing Hex fallback`, () => {
      const f = fixture();
      f.record.response = missing;
      run(f);
      assert.deepEqual(dumpBytes(f.shown()), Array.from(Buffer.from("No response was captured for this exchange.")));
      assert.equal(f.searched(), f.shown());
    });
  }

  for (const notice of ["", "Cancelled.", "Failed to parse request.", "Response removed by retention."]) {
    test(`${controller}: an empty response keeps the ${JSON.stringify(notice)} notice as text`, () => {
      const f = fixture();
      f.tab.responseRecord = null;
      f.tab.notice = notice;
      run(f);
      assert.equal(f.shown(), notice || "Send a request from Replay to capture the response here.");
      assert.equal(f.searched(), f.shown());
      assert.equal(f.els.replayResponseMeta.textContent, notice || "No response yet.");
      assert.deepEqual(dumpBytes(f.shown()), []);
    });
  }

  test(`${controller}: legacy response Hex displays bytes and a separate retention notice`, () => {
    const message = { body_preview: "AAEC/w==", body_encoding: "base64", preview_truncated: true, body_size: 128 };
    const f = fixture(message, "hex", true);
    run(f);
    assert.deepEqual(dumpBytes(f.shown()), expectedBytes(message));
    assert.equal(f.els.replayResponseView.innerHTML, f.c.renderHexHtml(f.shown()));
    assert.match(f.els.replayResponseView.innerHTML, /code-line-hex">\[preview truncated\]<\/span>/);
    assert.equal(f.searched(), f.shown());
  });
}

test("switching Replay response modes and records does not leak old bytes or notices", () => {
  const f = fixture({ body_preview: "AAEC/w==", body_encoding: "base64", preview_truncated: true });
  const original = JSON.stringify(f.record);
  for (const mode of ["hex", "raw", "pretty", "hex"]) {
    f.state.replayMessageViews.response = mode;
    f.c.renderReplayViewContent("response");
    if (mode === "hex") assert.deepEqual(dumpBytes(f.shown()), expectedBytes(f.record.response));
    else assert.equal(f.shown(), `${HEAD}\n\n[application/octet-stream, 4 B, base64 preview omitted]\n\n[preview truncated]`);
    assert.equal(f.searched(), f.shown());
  }
  assert.equal(f.destroyed(), 2);
  assert.equal(JSON.stringify(f.record), original);
  f.tab.responseRecord = { ...f.record, response: { ...f.record.response, body_preview: "new 😀", body_encoding: "utf8", preview_truncated: false } };
  f.c.renderReplayResponseOnly(f.tab);
  assert.deepEqual(dumpBytes(f.shown()), expectedBytes(f.tab.responseRecord.response));
  assert.doesNotMatch(f.shown(), /preview truncated/);
  assert.equal(f.searched(), f.shown());
});

test("the full Replay renderer keeps the no-tab prompt as text in Hex mode", () => {
  const f = fixture();
  f.c.ensureRepeaterTab = () => null;
  f.c.renderReplay();
  assert.equal(f.shown(), "Send a request from Replay to capture the response here.");
  assert.equal(f.searched(), f.shown());
  assert.equal(f.els.replayResponseMeta.textContent, "No response yet.");
  assert.equal(f.els.sendReplayButton.disabled, true);
  for (const input of [f.els.replayHostInput, f.els.replayPortInput]) {
    assert.equal(input.validationMessage, "");
    assert.equal(input.attributes["aria-invalid"], "false");
  }
});
