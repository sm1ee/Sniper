// Production Replay rendering and shipped CodeMirror, with select values limited
// to the shipped HTML options. No browser, application startup, or requests.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource } = require("./frontend-test-helpers.cjs");
const { editorFixture, source } = require("./replay-editor-fixture.cjs");

const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
const selectHtml = html.match(/<select id="replayHttpVersionSelect">([^]*?)<\/select>/)[1];
const versionOptions = [...selectHtml.matchAll(/<option value="([^"]*)"/g)].map(match => match[1]);
const lf = text => text.replace(/\r\n?/g, "\n");

function setup(version = "HTTP/1.0") {
  const f = editorFixture();
  let selectedIndex = 0;
  // Unlike a plain { value }, a single select cannot retain an absent option.
  Object.defineProperties(f.versionSelect, {
    value: { get: () => versionOptions[selectedIndex] ?? "",
      set: value => { selectedIndex = versionOptions.indexOf(String(value)); } },
    selectedIndex: { get: () => selectedIndex },
  });
  f.versionSelect.addEventListener = (type, listener) => {
    if (type === "change") f.changeVersion = listener;
  };
  const binding = appSource.slice(appSource.indexOf(
    '  document.getElementById("replayHttpVersionSelect")?.addEventListener("change", (e) => {',
  ));
  vm.runInContext(binding.slice(0, binding.indexOf("\n  });") + 6), f.context);
  for (const name of ["buildRawResponse", "buildRawResponseHead", "renderBody", "formatStatus"]) {
    vm.runInContext(source(name), f.context);
  }
  f.a.requestText = f.a.requestText.replace("HTTP/1.1", version);
  f.a.httpVersionMode = version;
  f.a.baseRequest.http_version = version;
  f.a.responseRecord = {
    id: "synthetic-response", status: 200, duration_ms: 1,
    request: { headers: [] },
    response: { headers: [], content_type: "text/plain", body_preview: "synthetic", body_encoding: "utf8" },
  };
  f.a.notice = "Synthetic retained notice";
  f.seed([f.a, f.b]);
  f.render();
  f.selectVersion = value => {
    f.document.activeElement = f.versionSelect;
    f.versionSelect.value = value;
    f.changeVersion({ target: f.versionSelect });
  };
  return f;
}

test("the HTML-derived select rejects values that are not offered", () => {
  const f = setup("HTTP/1.1");
  f.versionSelect.value = "HTTP/3";
  assert.equal(f.versionSelect.value, "");
  assert.equal(f.versionSelect.selectedIndex, -1);
});

for (const version of ["HTTP/1.0", "HTTP/1.1", "HTTP/2"]) {
  test(`${version} survives a Replay tab round-trip without changing the draft or scheduling a save`, () => {
    const f = setup(version), original = f.a.requestText, response = f.a.responseRecord, notice = f.a.notice;
    assert.equal(f.versionSelect.value, version);
    assert.notEqual(f.versionSelect.selectedIndex, -1);
    f.switchTo(f.b); f.switchTo(f.a);
    assert.equal(f.a.requestText, original);
    assert.equal(f.a.httpVersionMode, version);
    assert.equal(f.cv().getContent(), lf(original));
    assert.equal(f.versionSelect.value, version);
    assert.equal(f.a.responseRecord, response);
    assert.equal(f.a.notice, notice);
    assert.equal(f.context.workspaceSaveDirty, false);
    assert.equal(f.timers.size, 0);
    assert.equal(f.requests.length, 0);
  });
}

test("opening a new Replay tab preserves the original HTTP/1.0 draft and retained response", () => {
  const f = setup(), original = f.a.requestText, response = f.a.responseRecord, notice = f.a.notice;
  f.context.openBlankReplayTab();
  assert.notEqual(f.context.getActiveReplayTab(), f.a);
  f.switchTo(f.a);
  assert.equal(f.a.requestText, original);
  assert.equal(f.a.httpVersionMode, "HTTP/1.0");
  assert.equal(f.cv().getContent(), lf(original));
  assert.equal(f.versionSelect.value, "HTTP/1.0");
  assert.equal(f.a.responseRecord, response);
  assert.equal(f.a.notice, notice);
  assert.equal(f.requests.length, 0);
});

test("deliberately selecting Auto still removes the explicit HTTP version", () => {
  const f = setup();
  f.selectVersion("");
  assert.match(f.a.requestText, /^GET \/a\r?\n/);
  assert.equal(f.a.httpVersionMode, "");
  assert.equal(f.a.responseRecord, null);
  assert.equal(f.a.notice, "");
  assert.equal(f.context.workspaceSaveDirty, true);
  const autoRequest = f.a.requestText;
  f.switchTo(f.b); f.switchTo(f.a);
  assert.equal(f.a.requestText, autoRequest);
  assert.equal(f.cv().getContent(), lf(autoRequest));
  assert.equal(f.versionSelect.value, "");
  assert.equal(f.versionSelect.selectedIndex, 0);
  assert.equal(f.requests.length, 0);
});

test("deliberately selecting HTTP/1.0 updates the request and survives navigation", () => {
  const f = setup("HTTP/1.1");
  f.selectVersion("HTTP/1.0");
  assert.match(f.a.requestText, /^GET \/a HTTP\/1\.0\r?\n/);
  assert.equal(f.a.httpVersionMode, "HTTP/1.0");
  assert.equal(f.a.responseRecord, null);
  assert.equal(f.a.notice, "");
  assert.equal(f.context.workspaceSaveDirty, true);
  const request = f.a.requestText;
  f.switchTo(f.b); f.switchTo(f.a);
  assert.equal(f.a.requestText, request);
  assert.equal(f.cv().getContent(), lf(request));
  assert.equal(f.versionSelect.value, "HTTP/1.0");
  assert.equal(f.requests.length, 0);
});
