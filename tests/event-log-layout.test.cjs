// Source/layout-budget contracts and extracted rendering/navigation only.
// No app startup, API requests, Clear action, browser, or native runtime runs.
// Browser geometry and narrow-width local scrolling are verified separately.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");
const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");
const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");

function rule(selector) {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const matches = [...css.matchAll(new RegExp(`^${escaped}\\s*\\{([^}]+)\\}`, "gm"))];
  assert.equal(matches.length, 1, `one scoped rule for ${selector}`);
  return matches[0][1];
}

function fixture(entries = []) {
  const state = { activeTool: "dashboard", eventLog: entries };
  const els = { eventLogStatus: {}, eventLogTableBody: {}, openEventLogButton: {} };
  const context = loadFunctions(["renderEventLog", "escapeHtml", "setActiveTool"], {
    state, els, formatTimestamp: value => value,
    sanitizeActiveTool: value => value, closeScannerSettings() {},
    invalidateFindingNavigation() {}, scheduleUiSettingsSave() {},
  });
  return { state, els, context };
}

test("only Logger Source, Title, and Message cells gain full-token wrapping", () => {
  const wrap = rule(".event-log-table tbody td:nth-child(n + 3)");
  assert.match(wrap, /overflow-wrap:\s*anywhere;/);
  // Retain the existing whitespace semantics, normal word boundaries, column
  // widths, and full text: no ellipsis, clipping, or fixed-height alternative.
  const properties = [...wrap.matchAll(/([\w-]+)\s*:/g)].map(match => match[1]);
  assert.deepEqual(properties, ["overflow-wrap"]);
});

test("Logger keeps a usable Message budget and scrolls in its existing wrapper", () => {
  // Two classes outrank the later narrow-screen .mini-table min-width reset.
  const minimum = Number(rule(".mini-table.event-log-table").match(/min-width:\s*(\d+)px;/)[1]);
  assert.equal(minimum, 640);
  assert.match(rule(".mini-table"), /table-layout:\s*fixed;/);
  assert.match(rule(".history-table-shell"), /overflow:\s*auto;/);
  const table = html.match(/<div class="history-table-shell">\s*(<table class="mini-table event-log-table">[\s\S]*?<\/table>)/)[1];
  const columns = [...table.matchAll(/<col(?: style="width: (\d+)px")?\s*\/>/g)];
  assert.deepEqual(columns.map(match => Number(match[1]) || null), [140, 60, 80, 160, null]);
  const fixedBudget = columns.slice(0, 4).reduce((sum, match) => sum + Number(match[1]), 0);
  for (const container of [320, 400, 488, 640, 1184]) {
    const tableWidth = Math.max(container, minimum);
    assert.ok(tableWidth - fixedBudget >= 200, `Message budget at ${container}px`);
  }
});

test("Logger renders escaped full text without changing long tokens or whitespace", () => {
  const entry = {
    captured_at: "2026-01-01 00:00:00", level: "info",
    source: `synthetic.${"s".repeat(256)}<source>&`,
    title: `  ${"t".repeat(256)} "quoted" 'title'  `,
    message: `First  line\n\t${"m".repeat(256)}\n<script>synthetic & text</script>\n끝 😀  `,
  };
  const before = JSON.stringify(entry);
  const f = fixture([entry]);
  f.context.renderEventLog();
  const cells = [...f.els.eventLogTableBody.innerHTML.matchAll(/<td>([\s\S]*?)<\/td>/g)].map(match => match[1]);
  assert.deepEqual(cells, [
    entry.captured_at, entry.level,
    `synthetic.${"s".repeat(256)}&lt;source&gt;&amp;`,
    `  ${"t".repeat(256)} &quot;quoted&quot; &#039;title&#039;  `,
    `First  line\n\t${"m".repeat(256)}\n&lt;script&gt;synthetic &amp; text&lt;/script&gt;\n끝 😀  `,
  ]);
  assert.equal(JSON.stringify(entry), before);
  assert.equal(f.els.eventLogStatus.textContent, "1 entry");
  assert.doesNotMatch(f.els.eventLogTableBody.innerHTML, /<script>|text-truncate/);
});

test("main Logger and footer Event log navigate to the same rendered table", async () => {
  const f = fixture([{ captured_at: "fixture-time", level: "info", source: "synthetic.preview", title: "Fixture", message: "Read-only fixture" }]);
  let mainClick, footerClick, reads = 0;
  const panels = [];
  f.context.mainTabs = [{ dataset: { tool: "logger" }, addEventListener(type, callback) {
    assert.equal(type, "click"); mainClick = callback;
  } }];
  f.context.onClickWithProgress = (button, callback) => {
    assert.equal(button, f.els.openEventLogButton); footerClick = callback;
  };
  f.context.loadEventLog = async () => { reads += 1; };
  f.context.renderToolPanels = () => { panels.push(f.state.activeTool); f.context.renderEventLog(); };
  f.context.showToast = () => assert.fail("read-only navigation should not report an error");
  const mainStart = appSource.indexOf("  mainTabs.forEach((tab) => {", appSource.indexOf("function bindEvents()"));
  const mainEnd = appSource.indexOf("\n  proxyTabs.forEach", mainStart);
  assert.ok(mainStart >= 0 && mainEnd > mainStart);
  vm.runInContext(appSource.slice(mainStart, mainEnd), f.context);
  const footerStart = appSource.indexOf("  onClickWithProgress(els.openEventLogButton,");
  const footerEnd = appSource.indexOf("  onClickWithProgress(els.dashboardReloadSessionsButton,", footerStart);
  assert.ok(footerStart >= 0 && footerEnd > footerStart);
  vm.runInContext(appSource.slice(footerStart, footerEnd), f.context);
  mainClick();
  const mainRows = f.els.eventLogTableBody.innerHTML;
  f.state.activeTool = "dashboard";
  await footerClick();
  assert.deepEqual(panels, ["logger", "logger"]);
  assert.equal(reads, 2);
  assert.equal(f.els.eventLogTableBody.innerHTML, mainRows);
  assert.match(mainRows, /synthetic\.preview/);
  assert.equal((html.match(/class="mini-table event-log-table"/g) || []).length, 1);
  assert.equal((html.match(/id="eventLogTableBody"/g) || []).length, 1);
  assert.match(appSource, /if \(loggerVisible\) \{\s*renderEventLog\(\);\s*\}/);
});

test("Logger retains empty and short rows with accurate footer counts", () => {
  const f = fixture();
  f.context.renderEventLog();
  assert.match(f.els.eventLogTableBody.innerHTML, /<td colspan="5">No runtime events have been recorded yet\.<\/td>/);
  assert.equal(f.els.eventLogStatus.textContent, "0 entries");
  const entry = { captured_at: "fixture-time", level: "info", source: "fixture", title: "Short", message: "Saved event" };
  f.state.eventLog = [entry, { ...entry, title: "Second" }];
  f.context.renderEventLog();
  assert.equal(f.els.eventLogStatus.textContent, "2 entries");
  assert.equal((f.els.eventLogTableBody.innerHTML.match(/<tr>/g) || []).length, 2);
  assert.match(f.els.eventLogTableBody.innerHTML, /<td>Short<\/td>/);
  assert.match(f.els.eventLogTableBody.innerHTML, /<td>Second<\/td>/);
});
