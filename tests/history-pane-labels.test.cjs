// Production Capture rendering and shipped editor state with an in-memory view.
// No app bootstrap, browser, native DOM/layout, capture, or request execution.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { editorFixture, source } = require("./replay-editor-fixture.cjs");

const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
function elementFromHtml(id) {
  const tag = html.match(new RegExp(`<[^>]+\\bid="${id}"[^>]*>`))?.[0];
  assert.ok(tag, `Missing ${id}`);
  return { getAttribute: name => tag.match(new RegExp(`\\b${name}="([^"]*)"`))?.[1] ?? null };
}
const record = id => ({ id, request: { body_preview: `request-${id}` }, response: { body_preview: `response-${id}` } });

function setup() {
  const f = editorFixture();
  const MemoryEditorView = f.context.CM.EditorView;
  f.context.CM.EditorView = class extends MemoryEditorView {
    constructor(options) {
      super(options);
      const attributes = new Map();
      this.contentDOM = {
        setAttribute: (name, value) => attributes.set(name, String(value)),
        getAttribute: name => attributes.get(name) ?? null,
      };
    }
  };
  for (const side of ["request", "response"]) {
    f.els[`${side}ViewCM`] = elementFromHtml(`${side}ViewCM`);
    f.els[`${side}SearchInput`] = { value: "" };
    f.els[`${side}SearchMeta`] = { innerHTML: "" };
  }
  Object.assign(f.state, {
    selectedRecord: record("a"), selectedId: "a", loadingDetailId: null, historyDetailError: "",
    messageViews: { request: "raw", response: "raw" }, messageSearch: { request: "", response: "" },
    showOriginal: { request: false, response: false },
  });
  Object.assign(f.context, {
    historyPacketViewer: null,
    // Presentation is supplied text; this task does not exercise parsing or render resources.
    buildMessagePresentation: (side, value) => value[side].body_preview,
    recordPageUrl: () => "https://example.com/",
    renderResponsePreview() {},
  });
  for (const name of ["createPacketViewerController", "getHistoryPacketViewer", "renderMessagePanes"])
    vm.runInContext(source(name), f.context);
  f.captureView = side => f.context.getCMView(side);
  f.name = side => f.captureView(side).view.contentDOM.getAttribute("aria-label");
  f.renderCapture = () => f.context.renderMessagePanes();
  return f;
}

for (const [side, label] of [["request", "Captured request"], ["response", "Captured response"]]) {
  test(`Capture ${side} container supplies its distinct editor name`, () => {
    assert.equal(elementFromHtml(`${side}ViewCM`).getAttribute("data-editor-label"), label);
  });

  test(`Capture ${side} preserves its name, read-only state and selection on redraw`, () => {
    const f = setup(); f.renderCapture();
    const first = f.captureView(side);
    assert.equal(f.name(side), label);
    assert.equal(first._options.readOnly, true);
    assert.equal(first.view.state.readOnly, true);
    first.view.dispatch({ selection: { anchor: 1, head: 4 } });
    f.renderCapture();
    assert.equal(f.captureView(side), first);
    assert.equal(f.name(side), label);
    assert.equal(first.view.state.selection.main.anchor, 1);
    assert.equal(first.view.state.selection.main.head, 4);
    assert.equal(first.getContent(), `${side}-a`);
    assert.equal(f.requests.length, 0);
  });

  test(`Capture ${side} mode recreation and selecting another record retain its name`, () => {
    const f = setup();
    let previous = null;
    for (const mode of ["raw", "pretty", "hex", "raw"]) {
      f.state.messageViews[side] = mode;
      f.renderCapture();
      const current = f.captureView(side);
      assert.equal(f.name(side), label);
      assert.equal(current._options.readOnly, true);
      if (mode === "pretty") assert.equal(current, previous);
      else if (previous) {
        assert.notEqual(current, previous);
        assert.equal(previous.view.destroyed, true);
      }
      previous = current;
    }
    f.state.selectedRecord = record("b"); f.state.selectedId = "b";
    f.renderCapture();
    assert.equal(f.name(side), label);
    assert.equal(f.captureView(side).getContent(), `${side}-b`);
    f.context.getHistoryPacketViewer().destroy();
    assert.equal(previous.view.destroyed, true);
    f.context.historyPacketViewer = null;
    f.renderCapture();
    assert.notEqual(f.captureView(side), previous);
    assert.equal(f.name(side), label);
    assert.equal(f.requests.length, 0);
  });
}

test("Capture names remain distinct for no selection, loading and detail-error messages", () => {
  const f = setup();
  f.state.selectedRecord = null; f.state.selectedId = null;
  for (const status of ["empty", "loading", "error"]) {
    if (status === "loading") f.state.selectedId = f.state.loadingDetailId = "pending";
    if (status === "error") f.state.historyDetailError = "Synthetic detail error";
    f.renderCapture();
    assert.equal(f.name("request"), "Captured request");
    assert.equal(f.name("response"), "Captured response");
    assert.equal(f.captureView("request").getContent(), status === "empty" ? "Select a transaction from HTTP."
      : status === "loading" ? "Loading selected transaction..." : "Synthetic detail error");
    assert.equal(f.captureView("response").getContent(), status === "empty" ? "No response selected."
      : status === "loading" ? "Loading response details." : "Synthetic detail error");
  }
  assert.equal(f.requests.length, 0);
});

test("Capture search labels stay unchanged and editor metadata does not spread to other views", () => {
  for (const side of ["request", "response"]) {
    assert.match(html, new RegExp(`<label class="pane-search" aria-label="Search ${side}">\\s*<input id="${side}SearchInput"`));
    assert.equal(elementFromHtml(`${side}SearchInput`).getAttribute("placeholder"), `Search ${side}`);
  }
  const labels = {
    requestViewCM: "Captured request", responseViewCM: "Captured response",
    replayRequestCM: "Replay request", replayResponseCM: "Replay response",
    fuzzerDetailReqCM: "Fuzzer result request", fuzzerDetailResCM: "Fuzzer result response",
  };
  for (const match of html.matchAll(/<div id="([^"]+)" class="cm-container"[^>]*>/g)) {
    assert.equal(elementFromHtml(match[1]).getAttribute("data-editor-label"), labels[match[1]] ?? null, match[1]);
  }
});
