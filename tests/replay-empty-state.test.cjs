// Replay with no tabs says how to start one instead of making a blank tab up.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const element = () => {
  const set = new Set();
  return { classList: { contains: (name) => set.has(name), add: (name) => set.add(name),
    toggle: (name, on) => (on ? set.add(name) : set.delete(name)) } };
};

test("with no tabs, Replay shows how to start one and creates none", () => {
  const state = { replayTabs: [], activeReplayTabId: null };
  const els = {
    httpReplayToolbar: element(), httpReplayWorkbench: element(), wsReplayPanel: element(), replayEmptyState: element(),
    replayFollowRedirectButton: element(), replayHostInput: {}, replayPortInput: {}, replaySchemeSelect: {},
    replayResponseMeta: {}, sendReplayButton: {}, cancelReplayButton: {}, replayBackButton: {}, replayForwardButton: {},
  };
  els.replayEmptyState.classList.add("hidden");
  const c = loadFunctions(["renderReplay", "ensureRepeaterTab", "getActiveReplayTab"], {
    state, els, renderedHttpReplayDraftOwner: null, renderReplayTabs() {}, renderReplayRequestHighlight() {},
    renderReplayResponseView() {}, updateReplaySearchPane() {},
  });
  c.renderReplay();
  assert.equal(state.replayTabs.length, 0);
  assert.equal(state.activeReplayTabId, null);
  assert.equal(els.replayEmptyState.classList.contains("hidden"), false);
  for (const name of ["httpReplayToolbar", "httpReplayWorkbench", "wsReplayPanel"]) {
    assert.equal(els[name].classList.contains("hidden"), true, name);
  }
});
