// Source/markup contracts and synthetic intrinsic-width constraints only.
// This is not a browser layout engine or a screenshot/visual assertion.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions, toggleButton } = require("./frontend-test-helpers.cjs");

const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");
const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");

function declarations(selector) {
  const rules = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)]
    .filter(([, selectors]) => selectors.trim() === selector);
  assert.equal(rules.length, 1, `${selector} has one source rule`);
  return Object.fromEntries(rules[0][2].split(";").filter(value => value.includes(":"))
    .map(value => value.trim().split(/:\s*/)));
}

const toolbar = declarations(".findings-toolbar");
const filters = declarations(".findings-filter-bar");
const actions = declarations(".findings-toolbar-actions");
const search = declarations(".findings-filter-input");
const select = declarations(".findings-filter-select");

test("Findings toolbar and both groups wrap without automatic content-width floors", () => {
  for (const [name, rule] of Object.entries({ toolbar, filters, actions })) {
    assert.equal(rule.display, "flex", name);
    assert.equal(rule["flex-wrap"], "wrap", name);
    assert.equal(rule["min-width"], "0", name);
  }
  for (const rule of [filters, actions]) assert.equal(rule["max-width"], "100%");
  assert.equal(filters.flex, "1 1 auto");
  assert.equal(actions.flex, "0 1 auto");
  assert.equal(actions["margin-left"], "auto");
  assert.equal(toolbar["flex-shrink"], "0", "wrapped rows keep their control height");
});

test("Findings fields fit a narrow group while retaining a usable preferred search width", () => {
  assert.equal(search.flex, "1 1 160px");
  assert.equal(search["min-width"], "0");
  assert.equal(search["max-width"], "220px");
  assert.equal(select["min-width"], "0");
  assert.equal(select["max-width"], "100%", "long custom categories cannot widen the group");
});

function packedLines(widths, available, gap, wrap) {
  const lines = [[]];
  for (const width of widths) {
    const line = lines.at(-1);
    const occupied = line.reduce((sum, size) => sum + size, 0) + gap * line.length;
    if (wrap && line.length && occupied + width > available) lines.push([width]);
    else line.push(width);
  }
  return lines.map(line => ({
    widths: line,
    used: line.reduce((sum, size) => sum + size, 0) + gap * (line.length - 1),
  }));
}

function widthConstraints(panelWidth, categoryWidth = 148) {
  const available = panelWidth - 2 * Number.parseFloat(toolbar.padding.split(/\s+/)[1]);
  // Supplied synthetic intrinsic widths, not font/native-control measurements.
  // Model only bounds and line packing, not flex growth or rendered geometry.
  const controls = [[110, categoryWidth, Number.parseFloat(search.flex?.split(/\s+/)[2] || search["min-width"])],
    [90, 120, 40, 65, 55]];
  const groups = [filters, actions].map((rule, index) => {
    const gap = Number.parseFloat(rule.gap);
    const bounded = controls[index].map((width, controlIndex) => {
      const canFit = index === 0 && (controlIndex < 2
        ? select["max-width"] === "100%"
        : search["min-width"] === "0");
      return canFit ? Math.min(width, available) : width;
    });
    const preferred = bounded.reduce((sum, width) => sum + width, 0) + gap * (bounded.length - 1);
    const width = rule["max-width"] === "100%" ? Math.min(preferred, available) : preferred;
    return { width, lines: packedLines(bounded, width, gap, rule["flex-wrap"] === "wrap") };
  });
  return {
    available, groups,
    lines: packedLines(groups.map(group => group.width), available,
      Number.parseFloat(toolbar.gap), toolbar["flex-wrap"] === "wrap"),
  };
}

test("synthetic old no-wrap constraints exceed a 480px panel", () => {
  const filterMinimum = 110 + 148 + 120 + 2 * 6;
  const unshrinkableActions = 90 + 120 + 40 + 65 + 55 + 4 * 6;
  assert.ok(filterMinimum + 8 + unshrinkableActions > 480 - 24);
});

test("synthetic wide/narrow/wide widths fit through group and control wrapping", () => {
  for (const width of [1280, 900, 800, 480, 320, 240, 320, 800, 1280]) {
    const result = widthConstraints(width);
    assert.ok(result.lines.every(line => line.used <= result.available), `outer width ${width}`);
    for (const group of result.groups) {
      assert.ok(group.lines.every(line => line.used <= group.width), `inner width ${width}`);
    }
    assert.equal(result.lines.length, width >= 900 ? 1 : 2, `group rows at ${width}`);
    if (width <= 320) assert.ok(result.groups.every(group => group.lines.length > 1));
  }
});

test("synthetic oversized custom categories are bounded before subsequent filters wrap", () => {
  for (const width of [1280, 480, 240]) {
    const result = widthConstraints(width, 2000);
    assert.ok(result.lines.every(line => line.used <= result.available));
    assert.ok(result.groups[0].lines.every(line => line.used <= result.groups[0].width));
    assert.ok(result.groups[0].lines.length > 1);
  }
});

const ids = [
  "findingsFilterSeverity", "findingsFilterCategory", "findingsFilterSearch",
  "findingsInScopeOnly", "scannerQuickToggle", "findingsSettingsButton",
  "findingsRescanButton", "findingsClearButton",
];

test("the wrapping toolbar retains one ordered copy of every existing control", () => {
  const start = html.indexOf('<div class="findings-toolbar">');
  const end = html.indexOf('<div class="history-table-shell">', start);
  assert.ok(start >= 0 && end > start);
  const markup = html.slice(start, end);
  assert.deepEqual([...markup.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]), ids);
  for (const id of ids) assert.equal(html.split(`id="${id}"`).length - 1, 1, id);
  // The same outlined pill buttons as HTTP's In scope and Capturing.
  for (const id of ["findingsInScopeOnly", "scannerQuickToggle"]) {
    assert.match(markup, new RegExp(`<button class="scope-pill[^"]*" id="${id}" type="button" aria-pressed="(true|false)"`));
  }
  assert.doesNotMatch(markup, /type="checkbox"/);
  assert.doesNotMatch(markup, /\bhidden\b|\bdisabled\b|\btabindex=/);
});

test("existing filter controls keep their selection and debounce through repeated edits", () => {
  const handlers = new Map(), timers = new Map();
  let nextTimer = 0;
  const els = Object.fromEntries(ids.slice(0, 4).map(id => [id, Object.assign(
    id === "findingsInScopeOnly" ? toggleButton() : { value: "" },
    { addEventListener(type, handler) { handlers.set(`${id}:${type}`, handler); } },
  )]));
  const saved = Object.freeze([
    Object.freeze({ id: "match", severity: "high", category: "header", title: "Saved match",
      host: "example.com", path: "/saved" }),
    Object.freeze({ id: "low", severity: "low", category: "cookie", title: "Other saved",
      host: "outside.example.com", path: "/saved" }),
  ]);
  const renders = [];
  const c = loadFunctions(["getFilteredFindings", "setToggleButton"], {
    els, findingsData: saved, findingsSortKey: "title", findingsSortDir: "asc",
    SEVERITY_ORDER: { critical: 0, high: 1, medium: 2, low: 3, info: 4 },
    isInScopeHost: host => host === "example.com",
    renderFindings() { renders.push(Array.from(c.getFilteredFindings(), row => row.id)); },
    clearTimeout: id => timers.delete(id),
    setTimeout(callback, delay) {
      assert.equal(delay, 200);
      timers.set(++nextTimer, callback);
      return nextTimer;
    },
    fetch() { assert.fail("Local filter interactions must not make requests"); },
  });
  const start = appSource.indexOf("  // Filters\n", appSource.indexOf("function bindFindingsEvents()"));
  const end = appSource.indexOf("  // Arrow key navigation", start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(appSource.slice(start, end), c);
  const fire = (id, type = "change") => handlers.get(`${id}:${type}`)();
  const flush = () => {
    for (const [id, callback] of [...timers]) { timers.delete(id); callback(); }
  };
  for (let repeat = 0; repeat < 3; repeat++) {
    els.findingsFilterSeverity.value = "high"; fire("findingsFilterSeverity");
    els.findingsFilterCategory.value = "header"; fire("findingsFilterCategory");
    fire("findingsInScopeOnly", "click");
    els.findingsFilterSearch.value = "missing"; fire("findingsFilterSearch", "input");
    els.findingsFilterSearch.value = "MATCH"; fire("findingsFilterSearch", "input");
    assert.equal(timers.size, 1);
    flush();
    assert.deepEqual(renders.at(-1), ["match"]);
    assert.equal(els.findingsFilterCategory.value, "header");
    assert.equal(els.findingsFilterSeverity.value, "high");
    assert.equal(els.findingsInScopeOnly.checked, true);
    for (const id of ids.slice(0, 3)) els[id].value = "";
    fire("findingsInScopeOnly", "click");
    assert.deepEqual(renders.at(-1), ["low", "match"]);
  }
  assert.equal(c.findingsData, saved);
});
