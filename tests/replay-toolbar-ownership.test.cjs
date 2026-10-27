// Delayed captured-record opens and real sendReplay payload construction. All
// HTTP responses are in-memory fixtures; no upstream traffic or runtime starts.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { editorFixture, source } = require("./replay-editor-fixture.cjs");
const { deferred } = require("./replay-workspace-fixture.cjs");

function setup({ legacy = false } = {}) {
  const f = editorFixture();
  if (legacy) {
    f.els.replayRequestCM = null;
    f.els.replayRequestSearchMeta = null;
    f.els.replayRequestHighlight.setAttribute = () => {};
    f.els.replayRequestHighlight.removeAttribute = () => {};
    f.context.renderReplayRequestHighlight = text => { f.els.replayRequestHighlight.innerText = text; };
  }
  f.replays = []; f.pendingRecord = deferred();
  Object.assign(f.context, {
    AbortController, REPEATER_HISTORY_LIMIT: 100,
    loadSelectedTransactionRecord: () => f.pendingRecord.promise,
    flushWorkspaceStateForReplayAction: async () => 10,
    handleWorkspaceActionError: error => { throw error; },
    renderReplayResponseOnly() {}, scheduleRefresh() {},
    fetch: async (url, options) => {
      assert.equal(url, "/api/replay/send");
      f.replays.push(JSON.parse(options.body));
      return { ok: true, json: async () => ({ id: "sent", status: 200, response: { headers: [] } }) };
    },
  });
  for (const name of [
    "openReplayFromSelection", "createRecordClipboardOwner", "openTransactionRecordInReplay", "isWebSocketUpgradeRecord",
    "editableRequestFromRecord", "isRequestPreviewTruncated", "sendReplay", "isReplayTabStillCurrent",
    "setReplaySending", "replayEffectiveHttpVersion", "httpRequestAuthoritiesEquivalent", "normalizeHttpRequestAuthority",
    "replayTargetOverridePayload", "replaySentDraftUnchanged", "applyReplaySentDraftIfUnchanged", "targetStatesEquivalent",
    "recordRepeaterHistory", "buildUrlFromTarget", "joinAuthority", "isDefaultPortForScheme",
  ]) vm.runInContext(source(name), f.context);
  f.record = {
    id: "historical-new", kind: "http", method: "POST", scheme: "http", host: "new.example.com:8080", path: "/new",
    http_version: "HTTP/1.0", request: { headers: [{ name: "Host", value: "new.example.com:8080" }], body_preview: "synthetic", body_encoding: "utf8" },
  };
  f.render();
  return f;
}

for (const legacy of [false, true]) {
  for (const control of ["host", "port", "scheme", "version"]) {
    test(`${legacy ? "legacy" : "CodeMirror"}: late historical open replaces a focused old ${control} and sends the displayed new target`, async () => {
      const f = setup({ legacy });
      const focused = { host: f.els.replayHostInput, port: f.els.replayPortInput,
        scheme: f.els.replaySchemeSelect, version: f.versionSelect }[control];
      const pending = f.context.openReplayFromSelection();
      f.document.activeElement = focused;
      f.pendingRecord.resolve(f.record); await pending;
      const tab = f.context.getActiveReplayTab();
      assert.notEqual(tab, f.a);
      assert.equal(f.els.replayHostInput.value, "new.example.com");
      assert.equal(f.els.replayPortInput.value, "8080");
      assert.equal(f.els.replaySchemeSelect.value, "http");
      assert.equal(f.versionSelect.value, "HTTP/1.0");
      assert.equal(f.document.activeElement, focused);
      await f.context.sendReplay();
      assert.equal(f.replays.length, 1);
      assert.equal(f.replays[0].request.host, "new.example.com:8080");
      assert.equal(f.replays[0].request.scheme, f.els.replaySchemeSelect.value);
      assert.equal(f.replays[0].request.path, "/new");
      assert.equal(f.replays[0].request.body, "synthetic");
      assert.equal(f.replays[0].http_version, f.versionSelect.value);
      assert.equal(f.replays[0].target, null);
      assert.equal(tab.targetHost, f.els.replayHostInput.value);
      assert.equal(tab.targetPort, f.els.replayPortInput.value);
    });
  }
}

for (const control of ["host", "port", "scheme", "version"]) test(`same-owner redraw preserves the focused ${control} draft`, () => {
  const f = setup();
  const [focused, draft] = {
    host: [f.els.replayHostInput, "partial host"], port: [f.els.replayPortInput, "8x"],
    scheme: [f.els.replaySchemeSelect, "http"], version: [f.versionSelect, "HTTP/2"],
  }[control];
  focused.value = draft; f.document.activeElement = focused;
  for (let i = 0; i < 3; i++) f.render();
  assert.equal(focused.value, draft); assert.equal(f.document.activeElement, focused);
  assert.equal(f.a.targetHost, "example.com"); assert.equal(f.a.targetPort, "443");
  assert.equal(f.a.targetScheme, "https"); assert.equal(f.a.httpVersionMode, "HTTP/1.1");
});

for (const boundary of ["same-ID replacement", "session identity", "workspace generation"]) {
  test(`${boundary} replaces focused toolbar values even without a changed tab ID`, () => {
    const f = setup(), request = f.context.editableRequestFromRecord(f.record);
    const replacement = f.context.createReplayTab({
      baseRequest: request, requestText: f.context.buildEditableRawRequest(request),
    });
    replacement.id = f.a.id;
    if (boundary === "same-ID replacement") f.state.replayTabs[0] = replacement;
    else {
      Object.assign(f.a, replacement);
      if (boundary === "session identity") f.state.activeSession = { id: "session-b" };
      else f.context.workspaceStateGeneration++;
    }
    f.document.activeElement = f.els.replayHostInput; f.render();
    assert.equal(f.els.replayHostInput.value, "new.example.com");
    assert.equal(f.els.replayPortInput.value, "8080"); assert.equal(f.els.replaySchemeSelect.value, "http");
    assert.equal(f.versionSelect.value, "HTTP/1.0");
  });
}
