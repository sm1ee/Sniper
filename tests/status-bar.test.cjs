// The status bar names the tool in front, whichever panel rendered last.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function element() {
  const classes = new Set();
  return {
    style: {}, textContent: "", dataset: {},
    classList: {
      contains: name => classes.has(name),
      toggle(name, enabled) { if (enabled) classes.add(name); else classes.delete(name); },
    },
  };
}

function statusAfterCaptureRender(activeTool, activeProxyTab) {
  const els = Object.fromEntries([
    "proxyShell", "colorTagFilter", "filterBar", "trafficRegion", "historyWorkbenchResizer",
    "lowerWorkbench", "interceptPanel", "websocketPanel", "matchReplacePanel", "findingsPanel",
    "oastPanel", "proxySettingsPanel", "proxySubPlaceholder", "footerMode", "proxySubPath",
    "proxySubTitle", "proxySubDescription",
  ].map(key => [key, element()]));
  els.footerMode.textContent = "Fuzzer active";
  const context = loadFunctions(["renderProxyPanels"], {
    els, state: { activeTool, activeProxyTab }, proxyTabs: [], sanitizeActiveProxyTab: value => value,
    loadFindings() {}, applySavedWebsocketPaneWidth() {}, renderMatchReplaceRules() {},
    humanizeProxyTab: value => value,
  });
  context.renderProxyPanels();
  return els.footerMode.textContent;
}

test("rendering Capture behind another tool leaves that tool's status line", () => {
  // Startup renders Capture's panels whichever tool was left open.
  assert.equal(statusAfterCaptureRender("fuzzer", "http-history"), "Fuzzer active");
});

test("each Capture tab names itself while Capture is in front", () => {
  assert.equal(statusAfterCaptureRender("proxy", "http-history"), "HTTP active");
  assert.equal(statusAfterCaptureRender("proxy", "oast"), "OAST active");
});
