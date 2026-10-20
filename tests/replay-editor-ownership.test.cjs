const assert = require("node:assert/strict");
const test = require("node:test");
const { editorFixture } = require("./replay-editor-fixture.cjs");
const { appSource } = require("./frontend-test-helpers.cjs");
const vm = require("node:vm");
const lf = text => text.replace(/\r\n?/g, "\n");

function editPath(f) { f.edit(5, 6, "edited"); }

test("a newly rendered Replay request starts with an empty undo history", () => {
  const f = editorFixture(); f.render();
  assert.equal(f.cv().getContent(), lf(f.a.requestText));
  assert.equal(f.undo(), false);
  assert.equal(f.cv().getContent(), lf(f.a.requestText));
});

test("switching Replay tabs cannot undo another tab's request into the active model", () => {
  const f = editorFixture(); f.render(); editPath(f);
  const oldView = f.cv(), savedA = f.a.requestText, savedB = f.b.requestText;
  f.switchTo(f.b);
  assert.equal(f.undo(), false);
  assert.equal(f.redo(), false);
  assert.notEqual(f.cv(), oldView);
  assert.equal(oldView.view.destroyed, true);
  assert.equal(f.cv().getContent(), lf(savedB));
  assert.equal(f.b.requestText, savedB);
  assert.equal(f.a.requestText, savedA);
  editPath(f);
  assert.match(f.b.requestText, /GET \/edited /);
  assert.equal(f.a.requestText, savedA, "the replacement listener updates only the active owner");
  assert.equal(f.undo(), true); assert.equal(f.cv().getContent(), lf(savedB));
  assert.equal(f.undo(), false);
  f.switchTo(f.a);
  assert.equal(f.cv().getContent(), lf(savedA));
  assert.equal(f.undo(), false);
});

for (const query of ["", "Host"]) test(`same-tab redraw keeps real history, selection and focus with search ${JSON.stringify(query)}`, () => {
  const f = editorFixture(); f.state.replayMessageSearch.request = query; f.render();
  const original = lf(f.a.requestText), cv = f.cv();
  editPath(f); const edited = f.a.requestText;
  cv.view.dispatch({ selection: { anchor: 3, head: 8 } }); cv.view.focus();
  const selection = f.selection(), focus = f.document.activeElement;
  for (let i = 0; i < 3; i++) f.render();
  assert.equal(f.cv(), cv); assert.deepEqual(f.selection(), selection);
  assert.equal(f.document.activeElement, focus);
  assert.equal(f.undo(), true); assert.equal(f.cv().getContent(), original);
  assert.equal(f.a.requestText, original);
  f.render();
  assert.equal(f.redo(), true); assert.equal(f.cv().getContent(), edited);
  assert.equal(f.a.requestText, edited);
  assert.equal(f.undo(), true); assert.equal(f.undo(), false);
});

test("an unchanged CRLF request redraw neither records history nor moves selection", () => {
  const f = editorFixture(); f.render(); const cv = f.cv();
  cv.view.dispatch({ selection: { anchor: 6, head: 3 } }); cv.view.focus();
  const selection = f.selection(), count = cv.view.transactions.filter(tr => tr.docChanged).length;
  f.render(); f.render();
  assert.equal(f.cv(), cv); assert.deepEqual(f.selection(), selection);
  assert.equal(cv.view.transactions.filter(tr => tr.docChanged).length, count);
  assert.equal(f.undo(), false); assert.equal(f.document.activeElement, cv.view.contentDOM);
});

test("duplicating a request copies its text without copying undo or redo history", () => {
  const f = editorFixture(); f.render(); editPath(f);
  const original = f.a, cv = f.cv();
  f.context.duplicateActiveReplayTab();
  const duplicate = f.context.getActiveReplayTab();
  assert.notEqual(duplicate, original); assert.equal(duplicate.requestText, original.requestText);
  assert.notEqual(f.cv(), cv); assert.equal(cv.view.destroyed, true);
  assert.equal(f.undo(), false); assert.equal(f.redo(), false);
});

test("closing the active tab retires its undo stack before showing its neighbor", async () => {
  const f = editorFixture(); f.render(); editPath(f); const cv = f.cv();
  await f.context.closeRepeaterTab(f.a.id);
  assert.equal(f.context.getActiveReplayTab(), f.b);
  assert.notEqual(f.cv(), cv); assert.equal(cv.view.destroyed, true);
  assert.equal(f.undo(), false); assert.equal(f.cv().getContent(), lf(f.b.requestText));
});

for (const boundary of ["same-ID replacement", "session identity", "workspace generation", "session clear", "WebSocket tab"]) {
  test(`${boundary} retires Replay history even when IDs or text are reused`, () => {
    const f = editorFixture(); f.render(); editPath(f); const cv = f.cv();
    if (boundary === "same-ID replacement") f.state.replayTabs[0] = { ...f.a };
    if (boundary === "session identity") f.state.activeSession = { id: "session-b" };
    if (boundary === "workspace generation") f.context.workspaceStateGeneration++;
    if (boundary === "session clear") f.context.renderReplayClearedState();
    if (boundary === "WebSocket tab") {
      f.state.replayTabs.push({ id: "ws", type: "websocket" });
      f.state.activeReplayTabId = "ws"; f.render(); f.state.activeReplayTabId = f.a.id;
    }
    f.render();
    assert.notEqual(f.cv(), cv); assert.equal(cv.view.destroyed, true);
    assert.equal(f.undo(), false); assert.equal(f.redo(), false);
    assert.equal(f.cv().getContent(), lf(f.context.getActiveReplayTab().requestText));
  });
}

test("Pretty and Raw preserve same-owner history; Hex round-trip starts clean editable history", () => {
  const f = editorFixture(); f.render(); editPath(f); const cv = f.cv();
  f.state.replayMessageViews.request = "pretty"; f.context.renderReplayViewContent("request");
  assert.equal(f.cv(), cv); assert.equal(f.undo(), true); assert.equal(f.redo(), true);
  const text = f.a.requestText;
  f.state.replayMessageViews.request = "hex"; f.context.renderReplayViewContent("request");
  assert.notEqual(f.cv(), cv); assert.equal(cv.view.destroyed, true);
  assert.equal(f.cv()._editable, false);
  assert.equal(f.undo(), false);
  f.state.replayMessageViews.request = "raw"; f.context.renderReplayViewContent("request");
  assert.equal(f.cv()._editable, true); assert.equal(f.cv().getContent(), text);
  assert.equal(f.undo(), false); assert.equal(f.redo(), false);
  editPath(f); assert.equal(f.undo(), true); assert.equal(f.cv().getContent(), text);
});

for (const focus of ["editor", "toolbar", "tab button"]) {
  test(`owner replacement preserves ${focus} focus without stealing it`, () => {
    const f = editorFixture(); f.render(); const old = f.cv();
    if (focus === "editor") old.view.focus();
    else f.document.activeElement = focus === "toolbar" ? f.els.replayHostInput : {};
    const previousFocus = f.document.activeElement;
    f.switchTo(f.b);
    assert.equal(old.view.destroyed, true);
    assert.equal(f.document.activeElement, focus === "editor" ? f.cv().view.contentDOM : previousFocus);
  });
}

for (const route of ["Ctrl+Tab", "Ctrl+Shift+Tab", "duplicate", "close"]) {
  test(`${route} keeps keyboard focus in the new owner editor`, async () => {
    const f = editorFixture(); f.render(); const old = f.cv(); old.view.focus();
    if (route === "duplicate") f.context.duplicateActiveReplayTab();
    else if (route === "close") await f.context.closeRepeaterTab(f.a.id);
    else {
      let handler;
      f.document.addEventListener = (type, callback) => { if (type === "keydown") handler = callback; };
      f.context.getActiveModalAction = () => null; f.context.Element = class {};
      const binding = appSource.slice(appSource.indexOf('  document.addEventListener("keydown", (event) => {'));
      vm.runInContext(binding.slice(0, binding.indexOf('\n  });') + 6), f.context);
      const event = { target: old.view.contentDOM, key: "Tab", ctrlKey: true,
        shiftKey: route === "Ctrl+Shift+Tab", preventDefault() { this.defaultPrevented = true; } };
      handler(event); assert.equal(event.defaultPrevented, true);
    }
    assert.notEqual(f.cv(), old); assert.equal(old.view.destroyed, true);
    assert.equal(f.document.activeElement, f.cv().view.contentDOM);
  });
}
