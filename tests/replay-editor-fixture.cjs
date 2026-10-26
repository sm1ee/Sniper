// Shipped CodeMirror state/history and production Replay rendering, with a small
// in-memory view adapter. This does not claim native DOM/layout coverage or send
// target traffic; all request transport is supplied by the individual test.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { appSource } = require("./frontend-test-helpers.cjs");
const { fixture, plain } = require("./replay-workspace-fixture.cjs");
const source = name => appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, "m"))[0];
const bundle = vm.createContext({ console, setTimeout, clearTimeout });
vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/codemirror.bundle.js"), "utf8"), bundle);
const { CM } = bundle;

function editorFixture() {
  const f = fixture(), pool = {};
  Object.assign(f.state, {
    activeTool: "replay", replayMessageViews: { request: "raw", response: "raw" },
    replayMessageSearch: { request: "", response: "" },
  });
  f.a = f.tab("a"); f.b = f.tab("b"); f.seed([f.a, f.b]);
  f.els.replayRequestCM = {};
  f.els.replayRequestSearchInput = { value: "" };
  f.els.replayRequestSearchMeta = { innerHTML: "" };
  f.els.replayResponseMeta = {};
  f.els.replayFollowRedirectButton = { classList: { add() {}, toggle() {} } };
  for (const key of ["sendReplayButton", "cancelReplayButton", "replayBackButton", "replayForwardButton"]) f.els[key] = {};
  for (const input of [f.els.replayHostInput, f.els.replayPortInput]) {
    input.setCustomValidity = message => { input.validationMessage = message; };
    input.toggleAttribute = () => {};
    input.reportValidity = () => !input.validationMessage;
  }
  f.document.querySelectorAll = () => [];
  f.document.activeElement = null;
  f.views = [];
  class MemoryEditorView {
    constructor({ state, parent }) {
      this.state = state; this.parent = parent; this.contentDOM = {};
      this.transactions = []; this.destroyed = false;
      this.dispatch = (...specs) => {
        assert.equal(this.destroyed, false, "a retired view must not dispatch");
        const transaction = specs[0]?.startState ? specs[0] : this.state.update(...specs);
        this.transactions.push(transaction); this.state = transaction.state;
        for (const listener of this.state.facet(CM.EditorView.updateListener)) {
          listener({ view: this, state: this.state, docChanged: transaction.docChanged });
        }
      };
      f.views.push(this);
    }
    get hasFocus() { return f.document.activeElement === this.contentDOM; }
    focus() { f.document.activeElement = this.contentDOM; }
    destroy() {
      this.destroyed = true;
      if (f.document.activeElement === this.contentDOM) f.document.activeElement = null;
    }
  }
  Object.setPrototypeOf(MemoryEditorView, CM.EditorView);
  Object.assign(f.context, {
    CM: { ...CM, EditorView: MemoryEditorView }, _cmViews: pool,
    CM_SEARCH_DECORATION_LIMIT: 5000,
    CM_DEFAULT_SEARCH_CLASSES: { hit: "tok-search-hit", active: "tok-search-active" },
    cmProgrammaticViews: new WeakSet(), sniperCMTheme: [], httpDecoPlugin: [], hexDecoPlugin: [],
    diffDecoPlugin: [], payloadDecoPlugin: [], encodedPreviewPlugin: [], TextDecoder,
    renderReplayEmptyResponse() {}, renderReplayResponseView() {}, renderWsReplay() {},
    refreshReplayTabLabel() {}, canNavigateReplayHistory: () => false,
    renderReplayRequestHighlight() {}, flushWorkspaceState: async () => {},
    setActiveTool: tool => { f.state.activeTool = tool; },
    renderToolPanels: () => f.context.renderReplay(),
  });
  for (const name of [
    "titleCase", "createBaseExtensions", "addCMUpdateListener", "normalizeSearchClasses", "normalizeSearchEffectValue",
    "forEachCodeSearchMatch", "buildSearchDecorations", "buildChangedLineDecorations", "buildSearchMeta",
    "updateCodePaneCM", "getCMView", "renderReplay", "renderReplayViewContent", "renderReplayViewTabs",
    "renderReplayClearedState", "syncReplayToolbar", "updateReplaySearchPane", "toHexDumpFromBytes",
    "syncReplayRequestTextFromEditor", "clearReplayResponseForDraftChange", "setReplayTargetInputValidity",
    "parseEditableRawRequest", "splitRawHttpMessage", "parseReplayHttpVersionToken", "headerValue",
    "editableRequestBodyLength", "validateRawHttpBodyFraming", "deriveRepeaterRequest",
    "duplicateActiveReplayTab", "openBlankReplayTab", "setReplayRequestEditorText",
  ]) vm.runInContext(source(name), f.context);
  const fieldsStart = appSource.indexOf("const setSearchQuery = CM.StateEffect.define();");
  const fieldsEnd = appSource.indexOf("function buildChangedLineDecorations", fieldsStart);
  vm.runInContext(appSource.slice(fieldsStart, fieldsEnd), f.context);
  const packetFieldsStart = appSource.indexOf("const setPacketEvidenceRanges = CM.StateEffect.define();");
  const classStart = appSource.indexOf("class SniperCodeView {");
  vm.runInContext(appSource.slice(packetFieldsStart, classStart), f.context);
  const classEnd = appSource.indexOf("// CodeMirror-based code pane instances", classStart);
  vm.runInContext(appSource.slice(classStart, classEnd), f.context);
  f.cv = () => f.context.getCMView("replayReq");
  f.render = () => f.context.renderReplay();
  f.switchTo = tab => {
    assert.equal(f.context.preserveActiveHttpReplayDraftBeforeNavigation(f.context.getActiveReplayTab(), "switching tabs"), true);
    f.state.activeReplayTabId = tab.id; f.render();
  };
  f.edit = (from, to, insert) => f.cv().view.dispatch({ changes: { from, to, insert }, userEvent: "input.type" });
  f.undo = () => CM.undo(f.cv().view);
  f.redo = () => CM.redo(f.cv().view);
  f.selection = () => plain(f.cv().view.state.selection.main);
  return f;
}

module.exports = { editorFixture, source, CM };
