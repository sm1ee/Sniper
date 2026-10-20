// Local Findings filtering only. Exercise production category rebuilding and
// filtering against synthetic metadata; never boot the app or make API calls.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function categorySelect() {
  const options = [];
  let selected = null;
  const select = {
    options,
    get value() { return selected?.value || ""; },
    set value(value) {
      // A real single-select cannot retain a value without a matching option.
      selected = options.find(option => option.value === value) || null;
    },
    appendChild(option) {
      options.push(option);
      option.remove = () => {
        options.splice(options.indexOf(option), 1);
        if (selected === option) selected = options[0] || null;
      };
      if (!selected) selected = option;
    },
  };
  for (const value of ["", "header", "cookie"]) {
    select.appendChild({ value, dataset: {}, textContent: value });
  }
  return select;
}

const row = (id, category, extra = {}) => Object.freeze({
  id, category, title: `Saved ${id}`, severity: "info", host: "example.com",
  path: "/saved", found_at: "2026-10-18T00:00:00Z", ...extra,
});

function fixture(data) {
  const category = categorySelect();
  const els = {
    findingsBody: { innerHTML: "" }, findingsFilterCategory: category,
    findingsFilterSearch: { value: "" }, findingsFilterSeverity: { value: "" },
    findingsInScopeOnly: { checked: false },
  };
  const state = { _findingsEntries: [] };
  let clearCount = 0;
  const c = loadFunctions([
    "renderFindings", "updateCategoryFilter", "ensureFindingsCategoryOption", "getFilteredFindings",
    "resetFindingsUiState",
  ], {
    els, state, findingsData: Object.freeze(data), selectedFindingId: null,
    findingsStateGeneration: 0, findingsLoadGeneration: 0, findingsBadgeCount: data.length,
    findingsLoadPromise: null, findingsLoadSessionId: null, lastFindingsBadgePollAt: 0,
    findingsBadgeRefreshTimer: 0, findingsListRefreshTimer: 0,
    findingsSortKey: "title", findingsSortDir: "asc",
    SEVERITY_ORDER: { critical: 0, high: 1, medium: 2, low: 3, info: 4 },
    BUILTIN_FINDING_CATEGORIES: new Set(["header", "cookie"]),
    BUILTIN_RULE_LABELS: { header: "Security Headers", cookie: "Cookie Flags" },
    document: { createElement(tag) {
      assert.equal(tag, "option");
      return { value: "", dataset: {}, textContent: "" };
    } },
    isInScopeHost: host => host === "example.com",
    clearFindingDetail() { c.selectedFindingId = null; clearCount++; },
    renderFindingsVirtual() { els.findingsBody.innerHTML = "rendered matching rows"; },
    updateFindingsBadge() {},
    fetch() { assert.fail("Local category filtering must not read or write an API"); },
  });
  c.renderFindings();
  return {
    c, els, category, state,
    render(data) { if (data) c.findingsData = Object.freeze(data); c.renderFindings(); },
    choose(value) { category.value = value; assert.equal(category.value, value); c.renderFindings(); },
    ids: () => Array.from(state._findingsEntries, entry => entry.id),
    values: () => category.options.map(option => option.value),
    clearCount: () => clearCount,
  };
}

test("refreshing the capped list does not silently clear a vanished custom category", () => {
  const f = fixture([row("custom", "custom-check"), row("header", "header")]);
  f.choose("custom-check");
  f.c.selectedFindingId = "custom";
  assert.deepEqual(f.ids(), ["custom"]);

  f.render([row("header", "header"), row("other", "other-check")]);
  assert.equal(f.category.value, "custom-check");
  assert.deepEqual(f.ids(), []);
  assert.match(f.els.findingsBody.innerHTML, /No findings match your filters\./);
  assert.equal(f.c.selectedFindingId, null);
  assert.equal(f.clearCount(), 1);
});

test("an empty refresh retains the category for later matching and unrelated arrivals", () => {
  const f = fixture([row("custom", "custom-check")]);
  f.choose("custom-check");
  f.render([]);
  assert.equal(f.category.value, "custom-check");
  assert.match(f.els.findingsBody.innerHTML, /No findings yet\./);

  f.render([row("header", "header")]);
  assert.equal(f.category.value, "custom-check");
  assert.deepEqual(f.ids(), []);
  f.render([row("header", "header"), row("returned", "custom-check")]);
  assert.deepEqual(f.ids(), ["returned"]);
  assert.equal(f.values().filter(value => value === "custom-check").length, 1);
});

test("only the selected absent custom category is retained and it can be cleared", () => {
  const f = fixture([row("alpha", "alpha-check"), row("beta", "beta-check")]);
  f.choose("beta-check");
  f.render([row("header", "header"), row("gamma", "gamma-check")]);
  assert.deepEqual(f.values(), ["", "header", "cookie", "beta-check", "gamma-check"]);
  f.choose("");
  assert.deepEqual(f.ids(), ["gamma", "header"]);
  assert.deepEqual(f.values(), ["", "header", "cookie", "gamma-check"]);
});

test("changing to another category drops the previously selected absent custom option", () => {
  const f = fixture([row("custom", "custom-check")]);
  f.choose("custom-check");
  f.render([row("header", "header"), row("other", "other-check")]);
  f.choose("other-check");
  assert.deepEqual(f.ids(), ["other"]);
  assert.deepEqual(f.values(), ["", "header", "cookie", "other-check"]);
  f.choose("header");
  assert.deepEqual(f.ids(), ["header"]);
});

test("retained categories still combine with local search, severity and scope filters", () => {
  const f = fixture([row("custom", "custom-check")]);
  f.choose("custom-check");
  f.render([]);
  f.els.findingsFilterSearch.value = "MATCH";
  f.els.findingsFilterSeverity.value = "high";
  f.els.findingsInScopeOnly.checked = true;
  const data = [
    row("match", "custom-check", { severity: "high" }),
    row("match-low", "custom-check"),
    row("match-scope", "custom-check", { severity: "high", host: "out-of-scope.example.com" }),
    row("no-search", "custom-check", { severity: "high" }),
    row("match-category", "header", { severity: "high" }),
  ];
  const original = JSON.stringify(data);
  f.render(data);
  assert.equal(f.category.value, "custom-check");
  assert.deepEqual(f.ids(), ["match"]);
  assert.equal(JSON.stringify(data), original);
});

test("built-in category and all-category selections keep their existing behavior", () => {
  const f = fixture([row("custom", "custom-check"), row("header", "header")]);
  f.choose("cookie");
  f.render([row("custom", "custom-check")]);
  assert.equal(f.category.value, "cookie");
  assert.deepEqual(f.ids(), []);
  f.choose("");
  assert.deepEqual(f.ids(), ["custom"]);
  f.render([]);
  assert.equal(f.category.value, "");
  assert.deepEqual(f.values(), ["", "header", "cookie"]);
});

for (const transition of ["cleared findings", "changed session"]) {
  test(`${transition} clears saved data and selection while preserving the view's filter controls`, () => {
    const f = fixture([row("custom", "custom-check")]);
    f.choose("custom-check");
    f.els.findingsFilterSearch.value = "saved";
    f.els.findingsFilterSeverity.value = "info";
    f.els.findingsInScopeOnly.checked = true;
    f.c.selectedFindingId = "custom";
    f.state.activeSession = { id: "session-a" };
    if (transition === "changed session") f.state.activeSession = { id: "session-b" };

    f.c.resetFindingsUiState();
    assert.equal(f.c.findingsData.length, 0);
    assert.equal(f.c.selectedFindingId, null);
    assert.equal(f.c.findingsBadgeCount, 0);
    assert.deepEqual(f.ids(), []);
    assert.equal(f.category.value, "custom-check");
    assert.equal(f.els.findingsFilterSearch.value, "saved");
    assert.equal(f.els.findingsFilterSeverity.value, "info");
    assert.equal(f.els.findingsInScopeOnly.checked, true);
    assert.match(f.els.findingsBody.innerHTML, /No findings yet\./);

    f.render([row("new-header", "header")]);
    assert.deepEqual(f.ids(), []);
    f.choose("");
    assert.deepEqual(f.ids(), ["new-header"]);
    assert.deepEqual(f.values(), ["", "header", "cookie"]);
  });
}
