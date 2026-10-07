// Saved-transaction presentation only; no scanning, actions, or live records.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const functions = [
  "findingsBodyPlaceholder", "renderBody", "binaryBodyPlaceholder", "formatSize",
  "buildFindingsRawMessage", "normalizedHeaders", "mergeHeaders", "headerNameEquals",
];
const c = loadFunctions(functions);

function savedRecord(side, message) {
  return {
    kind: "http", method: "POST", path: "/saved", host: "example.com", status: 200,
    http_version: "HTTP/1.1", response_http_version: "HTTP/2",
    request: { headers: [], body_preview: "" }, response: { headers: [], body_preview: "" },
    [side]: { headers: [{ name: "x-example", value: "saved  " }], body_size: 128, ...message },
  };
}

function expectedHead(side) {
  return side === "request"
    ? "POST /saved HTTP/1.1\nhost: example.com\nx-example: saved  "
    : "HTTP/2 200\nx-example: saved  ";
}

const previews = [
  ["empty text", { body_preview: "", body_encoding: "utf8" }, ""],
  ["empty binary", { body_preview: "", body_encoding: "base64" }, ""],
  ["omitted preview", { body_encoding: "utf8" }, ""],
  ["binary", { body_preview: "AAEC", body_encoding: "base64" }, "[binary, 128 B, base64 preview omitted]"],
  ["text", { body_preview: "café 😀\n  ", body_encoding: "utf8" }, "café 😀\n  "],
];

for (const side of ["request", "response"]) {
  for (const [label, preview, body] of previews) {
    test(`saved findings ${side} marks truncated ${label}`, () => {
      const record = savedRecord(side, { ...preview, preview_truncated: true });
      const original = JSON.stringify(record);
      assert.equal(c.buildFindingsRawMessage(record, side),
        `${expectedHead(side)}\n\n${body}${body ? "\n\n" : ""}[preview truncated]`);
      assert.equal(JSON.stringify(record), original);
    });
  }

  test(`saved findings complete ${side} preserves existing empty, text, and binary display`, () => {
    for (const [, preview, body] of previews) {
      const record = savedRecord(side, { ...preview, preview_truncated: false });
      const original = JSON.stringify(record);
      assert.equal(c.buildFindingsRawMessage(record, side), `${expectedHead(side)}${body ? `\n\n${body}` : ""}`);
      assert.equal(JSON.stringify(record), original);
    }
  });
}

test("missing saved messages keep existing empty and unavailable presentations", () => {
  for (const message of [null, undefined, {}]) assert.equal(c.findingsBodyPlaceholder(message), "");
  const record = savedRecord("request", {});
  delete record.response;
  assert.equal(c.buildFindingsRawMessage(record, "response"), "No response was captured for this exchange.");
});

for (const useCodeMirror of [false, true]) {
  test(`saved finding detail passes truncation notices to ${useCodeMirror ? "CodeMirror" : "legacy"} panes`, () => {
    const noop = () => {};
    const element = () => ({ classList: { add: noop, remove: noop }, dataset: {} });
    const els = {
      findingsDetailPanel: element(), findingsDetailPlaceholder: element(), findingsDetailContent: element(),
      findingsDetailSeverity: element(), findingsDetailCategory: element(), findingsDetailTitle: element(),
      findingsDetailJump: element(), findingsReqView: element(), findingsResView: element(),
      findingsReqCM: useCodeMirror ? element() : null, findingsResCM: useCodeMirror ? element() : null,
    };
    const rendered = [];
    const view = loadFunctions([...functions, "showFindingDetail"], {
      els, setFindingDetailActionsEnabled: noop, severityClass: () => "info", severityLabel: () => "Info",
      renderFindingDescription: noop, fallbackFindingLocationFromPaneResults: noop, scrollFindingLocationIntoView: noop,
      updateFindingsCodePaneCM(key, container, text) { rendered.push(text); },
      renderFindingsCodePane(container, lines, text) { rendered.push(text); },
    });
    const record = savedRecord("request", { body_preview: "", body_encoding: "utf8", preview_truncated: true });
    record.response = { headers: [], body_preview: "AAEC", body_encoding: "base64", body_size: 128, preview_truncated: true };
    const original = JSON.stringify(record);
    view.showFindingDetail({ record_id: "synthetic-record", severity: "info", category: "saved", title: "Saved entry" }, record);
    assert.equal(rendered.length, 2);
    assert.equal(rendered[0], `${expectedHead("request")}\n\n[preview truncated]`);
    assert.equal(rendered[1], "HTTP/2 200\n\n[binary, 128 B, base64 preview omitted]\n\n[preview truncated]");
    assert.equal(JSON.stringify(record), original);
  });
}
