// Source/state contracts and a bounded flex allocation model, not browser or
// WKWebView geometry. All data is synthetic; no app startup or requests run.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");
const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");

function element() {
  const classes = new Set();
  return {
    style: {}, textContent: "", dataset: {},
    classList: {
      contains: name => classes.has(name),
      add: name => classes.add(name), remove: name => classes.delete(name),
      toggle(name, enabled) { if (enabled) classes.add(name); else classes.delete(name); },
    },
  };
}

function tabFixture() {
  const els = Object.fromEntries([
    "proxyShell", "colorTagFilter", "filterBar", "trafficRegion", "historyWorkbenchResizer",
    "lowerWorkbench", "interceptPanel", "websocketPanel", "matchReplacePanel", "findingsPanel",
    "oastPanel", "proxySettingsPanel", "proxySubPlaceholder", "footerMode", "proxySubPath",
    "proxySubTitle", "proxySubDescription",
  ].map(key => [key, element()]));
  let loads = 0;
  const state = { activeProxyTab: "findings" };
  const context = loadFunctions(["renderProxyPanels"], {
    els, state, proxyTabs: [], sanitizeActiveProxyTab: value => value,
    loadFindings() { loads++; }, applySavedWebsocketPaneWidth() {}, renderMatchReplaceRules() {},
    humanizeProxyTab: value => value,
  });
  return { els, state, render: () => context.renderProxyPanels(), get loads() { return loads; } };
}

test("first Findings entry gets its own track without touching the saved HTTP split", () => {
  const f = tabFixture();
  f.els.proxyShell.style["--workbench-pane-height"] = "420px";
  f.render();
  assert.equal(f.els.proxyShell.classList.contains("findings-active"), true);
  assert.equal(f.els.findingsPanel.classList.contains("hidden"), false);
  assert.equal(f.els.lowerWorkbench.classList.contains("hidden"), true);
  assert.equal(f.els.proxyShell.style["--workbench-pane-height"], "420px");
  assert.equal(f.loads, 1);
});

test("leaving and repeatedly reentering Findings restores the appropriate shell layout", () => {
  const f = tabFixture();
  for (const tab of ["http-history", "intercept", "websockets-history", "replace", "oast", "proxy-settings"]) {
    for (let repeat = 0; repeat < 3; repeat++) {
      f.state.activeProxyTab = "findings"; f.render();
      assert.equal(f.els.proxyShell.classList.contains("findings-active"), true);
      f.state.activeProxyTab = tab; f.render();
      assert.equal(f.els.proxyShell.classList.contains("findings-active"), false);
      assert.equal(f.els.findingsPanel.classList.contains("hidden"), true);
    }
  }
});

test("Findings owns a definite full-height track independently of HTTP media-query tracks", () => {
  const ownTrack = css.match(/\.proxy-shell\.findings-active\s*\{([^}]+)\}/);
  assert.ok(ownTrack);
  assert.match(ownTrack[1], /grid-template-rows:\s*auto minmax\(0,\s*1fr\)/);
  assert.doesNotMatch(ownTrack[1], /workbench-pane-height/);
  const panel = css.match(/#findingsPanel\s*\{([^}]+)\}/);
  assert.match(panel[1], /height:\s*100%/);
  assert.match(panel[1], /flex-direction:\s*column/);
  // Both .proxy-shell.findings-active and #findingsPanel outrank the generic
  // .proxy-shell declarations in the height/width media queries.
  assert.equal((css.match(/\.proxy-shell\.findings-active\s*\{/g) || []).length, 1);
});

function dragFixture() {
  const listeners = new Map();
  const document = { body: element(),
    addEventListener(type, fn) { listeners.set(type, fn); },
    removeEventListener(type) { listeners.delete(type); },
  };
  const window = { addEventListener() {}, removeEventListener() {} };
  const resizer = element();
  resizer.addEventListener = (type, fn) => { resizer[type] = fn; };
  let available = 600;
  const table = element(), detail = element();
  table.style.flex = "1 1 0px";
  detail.style.flex = "0 0 240px";
  // This model covers only these two flex items after toolbar/handle space has
  // been removed. It is intentionally not a CSS engine or rendering assertion.
  const geometry = () => {
    const [grow, shrink, basis] = detail.style.flex.split(/\s+/).map(parseFloat);
    const h = shrink ? Math.max(120, Math.min(basis, available - 60)) : basis;
    const t = Number.parseFloat(table.style.flex) > 0 ? Math.max(60, available - h)
      : Number.parseFloat(table.style.flex.split(/\s+/)[2]);
    return { table: t, detail: h, unused: available - t - h };
  };
  table.getBoundingClientRect = () => ({ height: geometry().table });
  detail.getBoundingClientRect = () => ({ height: geometry().detail });
  const context = loadFunctions(["initFindingsResizer"], { document, window,
    els: { findingsDetailResizer: resizer, findingsDetailPanel: detail,
      findingsPanel: { querySelector: () => table } },
  });
  context.initFindingsResizer();
  return {
    table, detail, geometry,
    resize(value) { available = value; },
    drag(delta) {
      resizer.mousedown({ clientY: 300, preventDefault() {} });
      listeners.get("mousemove")({ clientY: 300 + delta, buttons: 1 });
      listeners.get("mouseup")();
    },
  };
}

test("a chosen detail height leaves the table flexible through viewport growth and shrinkage", () => {
  const f = dragFixture();
  f.drag(-50);
  assert.equal(f.table.style.flex, "1 1 0px");
  assert.equal(f.detail.style.flex, "0 1 290px");
  for (const [height, table, detail] of [[1000, 710, 290], [250, 60, 190], [1000, 710, 290]]) {
    f.resize(height);
    assert.deepEqual(f.geometry(), { table, detail, unused: 0 });
  }
  f.drag(-50);
  assert.deepEqual(f.geometry(), { table: 660, detail: 340, unused: 0 });
});

test("split limits and chosen detail height survive repeated drags", () => {
  const f = dragFixture();
  f.drag(10000);
  assert.deepEqual(f.geometry(), { table: 480, detail: 120, unused: 0 });
  f.drag(-10000);
  assert.deepEqual(f.geometry(), { table: 60, detail: 540, unused: 0 });
  const chosen = f.detail.style.flex;
  f.resize(300);
  assert.deepEqual(f.geometry(), { table: 60, detail: 240, unused: 0 });
  f.resize(600);
  assert.equal(f.detail.style.flex, chosen);
  assert.deepEqual(f.geometry(), { table: 60, detail: 540, unused: 0 });
});
