// Offline DOM/coordinate model only. Row heights are supplied fixtures, not
// browser/font measurements. All detail reads are stubbed; no app is started.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const constants = Object.fromEntries([...appSource.matchAll(
  /^const ((?:HISTORY|FINDINGS)_(?:ROW_HEIGHT|BUFFER_ROWS)) = (\d+);$/gm,
)].map(([, name, value]) => [name, Number(value)]));

function physicalTable(options = {}) {
  let height = options.rowHeight ?? 28;
  let scrollTop = options.scrollTop ?? 0;
  let html = "", rows = [], writes = 0;
  const nativeScrolls = [], scrollWrites = [];
  const headerHeight = options.missingHeader ? 0 : (options.headerHeight ?? 38);
  const shellTop = options.shellTop ?? 143.5;
  const shell = {
    clientHeight: options.viewportHeight ?? 300, clientTop: options.clientTop ?? 1.25,
    get scrollTop() { return scrollTop; },
    set scrollTop(value) { scrollWrites.push(value); scrollTop = Math.max(0, Math.min(value, maxScroll())); },
    getBoundingClientRect: () => ({ top: shellTop }),
  };
  const contentTop = () => shellTop + shell.clientTop;
  const rowSize = row => row.spacer ?? height;
  const maxScroll = () => Math.max(0, headerHeight + rows.reduce((sum, row) => sum + rowSize(row), 0) - shell.clientHeight);
  const rect = row => {
    const preceding = rows.slice(0, rows.indexOf(row)).reduce((sum, entry) => sum + rowSize(entry), 0);
    const top = contentTop() + headerHeight + preceding - scrollTop;
    return { top, bottom: top + height, height: options.measurementHeight?.(writes) ?? height };
  };
  const table = {
    closest: () => options.missingShell ? null : shell,
    tHead: options.missingHeader ? null : { getBoundingClientRect: () => ({ height: headerHeight }) },
  };
  const body = {
    get innerHTML() { return html; },
    set innerHTML(value) {
      html = value;
      writes++;
      assert.ok(writes < 100, "measurement correction must be bounded");
      rows = [...value.matchAll(/<tr\b([^>]*)>([\s\S]*?)<\/tr>/g)].map(([, attrs, cells]) => {
        if (attrs.includes("virtual-spacer")) return { spacer: Number(cells.match(/height:([\d.]+)px/)[1]) };
        const row = {
          id: attrs.match(/data-(?:finding-)?id="([^"]+)"/)?.[1],
          selected: /class="[^"]*\bselected\b/.test(attrs),
        };
        row.classList = { add() { row.selected = true; }, remove() { row.selected = false; } };
        row.getBoundingClientRect = () => rect(row);
        row.scrollIntoView = options => {
          nativeScrolls.push(options);
          // Native nearest sees the scrollport, but does not account for the
          // separately painted sticky table header inside it.
          const bounds = rect(row);
          if (bounds.top < contentTop()) shell.scrollTop += bounds.top - contentTop();
          else if (bounds.bottom > contentTop() + shell.clientHeight) shell.scrollTop += bounds.bottom - contentTop() - shell.clientHeight;
        };
        return row;
      });
      scrollTop = Math.max(0, Math.min(scrollTop, maxScroll()));
    },
    closest: selector => selector === "table" ? table : (options.missingShell ? null : shell),
    querySelector(selector) {
      if (selector === ".history-row") return rows.find(row => row.id) || null;
      if (selector === ".history-row.selected") return rows.find(row => row.selected) || null;
      const id = selector.match(/data-(?:finding-)?id="([^"]+)"/)?.[1];
      return id ? rows.find(row => row.id === id) || null : null;
    },
  };
  return {
    shell, table, body, nativeScrolls, scrollWrites, headerHeight,
    setHeight(value) { height = value; },
    get height() { return height; },
    get writes() { return writes; },
    get rows() { return rows; },
    maxScroll,
    assertVisible(id) {
      const row = rows.find(row => row.id === id);
      assert.ok(row, `${id} must be rendered`);
      const bounds = rect(row);
      assert.ok(bounds.top >= contentTop() + headerHeight - 1e-8,
        `row ${id} top ${bounds.top} is above sticky content edge ${contentTop() + headerHeight}`);
      assert.ok(bounds.bottom <= contentTop() + shell.clientHeight + 1e-8,
        `row ${id} bottom ${bounds.bottom} exceeds viewport bottom ${contentTop() + shell.clientHeight}`);
    },
  };
}

function historyFixture(options = {}) {
  const dom = physicalTable(options), loads = [];
  const entries = Array.from({ length: 200 }, (_, i) => ({ item: { id: `saved-${i}` }, index: i }));
  const state = {
    _historyEntries: entries, selectedId: `saved-${options.selectedIndex ?? 20}`,
    historyColumnOrder: ["index"], historyPaging: { hasMore: false, trimmedHeadCount: 0 },
  };
  const c = loadFunctions([
    "moveHistorySelection", "selectHistoryTransaction", "updateHistorySelection",
    "scrollHistoryToId", "scrollSelectedHistoryRowIntoView", "measuredRowPitch", "renderHistoryVirtual", "clamp",
  ], {
    ...constants, state, els: { historyTable: dom.table, historyTableBody: dom.body },
    measuredHistoryRowHeight: dom.height, HTTP_HISTORY_SCROLL_PREFETCH_ROWS: 120,
    getVisibleEntries: () => entries, canReuseSelectedHistoryRecord: () => false,
    scheduleHistoryDetailLoading() {}, scheduleHistoryBackfill() {},
    loadTransactionDetail(id) { loads.push(id); return Promise.resolve({ id }); },
    renderHistoryCell: (_col, item) => `<td>${item.id}</td>`,
  });
  c.renderHistoryVirtual();
  return { ...dom, dom, c, state, loads };
}

for (const scrollTop of [19 * 28 + 4, 20 * 28 + 12]) {
  test(`HTTP ArrowUp caller reveals an existing row under the sticky header from ${scrollTop}px`, async () => {
    const f = historyFixture({ scrollTop });
    assert.ok(f.dom.body.querySelector('.history-row[data-id="saved-19"]'), "target already exists in the DOM");
    await f.c.moveHistorySelection(-1);
    assert.equal(f.state.selectedId, "saved-19");
    f.dom.assertVisible("saved-19");
    assert.equal(f.dom.nativeScrolls.length, 0, "only adjust this scrollport vertically");
    assert.equal(f.shell.scrollTop, 19 * 28);
    f.c.renderHistoryVirtual();
    f.dom.assertVisible("saved-19");
    assert.deepEqual(f.loads, ["saved-19"]);
  });
}

test("HTTP repeated ArrowUp remains visible across the first rendered rows", async () => {
  const f = historyFixture({ scrollTop: 20 * 28 });
  for (let i = 19; i >= 0; i--) {
    await f.c.moveHistorySelection(-1);
    f.dom.assertVisible(`saved-${i}`);
    f.c.renderHistoryVirtual();
    f.dom.assertVisible(`saved-${i}`);
  }
  assert.equal(f.shell.scrollTop, 0);
});

test("HTTP existing visible row preserves nearest scroll and its containing scrollport offset", async () => {
  const f = historyFixture({ scrollTop: 17 * 28, shellTop: 610.25, clientTop: 3 });
  await f.c.moveHistorySelection(-1);
  f.dom.assertVisible("saved-19");
  assert.equal(f.shell.scrollTop, 17 * 28);
});

test("HTTP ArrowDown existing DOM row remains visible at the bottom edge", async () => {
  const f = historyFixture({ selectedIndex: 8, scrollTop: 0 });
  await f.c.moveHistorySelection(1);
  f.dom.assertVisible("saved-9");
  assert.equal(f.shell.scrollTop, 38 + 10 * 28 - 300);
});

function findingsFixture(options = {}) {
  const dom = physicalTable({ headerHeight: 29, ...options }), loads = [], handlers = new Map(), frames = [];
  const state = { _findingsEntries: Array.from({ length: options.rowCount ?? 200 }, (_, i) => ({
    id: `saved-${i}`, record_id: `record-${i}`, severity: "info", category: "saved",
    title: "Saved fixture", host: "example.com", path: "/saved", found_at: "",
  })) };
  const functions = ["renderFindingsVirtual", "scrollFindingsToId", "findingsArrowNav", "updateFindingsSelection", "escapeHtml", "severityClass", "severityLabel"];
  if (appSource.includes("function getFindingsRowHeight(")) functions.push("measuredRowPitch", "getFindingsRowHeight");
  const c = loadFunctions(functions, {
    ...constants, state, els: { findingsBody: dom.body },
    measuredFindingsRowHeight: options.cachedHeight ?? constants.FINDINGS_ROW_HEIGHT,
    selectedFindingId: `saved-${options.selectedIndex ?? 0}`,
    formatTimestamp: () => "-", loadFindingDetail: id => loads.push(id),
    requestAnimationFrame(callback) { frames.push(callback); return frames.length; },
  });
  dom.shell.addEventListener = (type, callback) => handlers.set(type, callback);
  const start = appSource.indexOf("  const findingsShell =", appSource.indexOf("function bindFindingsEvents()"));
  const end = appSource.indexOf("\n  // Event delegation for findings table rows", start);
  vm.runInContext(appSource.slice(start, end), c);
  return {
    dom, c, state, loads,
    scrollRender() { handlers.get("scroll")(); while (frames.length) frames.shift()(); },
  };
}

for (const rowHeight of [24, 27.5, 34.75, 41]) {
  test(`Findings first paint measures supplied ${rowHeight}px rows and rebuilds spacers once`, () => {
    const f = findingsFixture({ rowHeight });
    f.c.renderFindingsVirtual();
    assert.equal(f.c.measuredFindingsRowHeight, rowHeight);
    assert.equal(f.dom.writes, 2);
    assert.equal(f.dom.maxScroll(), 29 + 200 * rowHeight - 300);
    f.dom.shell.scrollTop = f.dom.maxScroll();
    f.scrollRender();
    f.dom.assertVisible("saved-199");
    const bottom = f.dom.shell.scrollTop;
    f.scrollRender();
    assert.equal(f.dom.shell.scrollTop, bottom);
    f.dom.assertVisible("saved-199");
  });

  test(`Findings keyboard callers use supplied ${rowHeight}px row height at virtual boundaries`, () => {
    const f = findingsFixture({ rowHeight, selectedIndex: 189, rowCount: 400 });
    f.c.renderFindingsVirtual();
    f.c.findingsArrowNav(1);
    f.scrollRender();
    assert.equal(f.c.selectedFindingId, "saved-190");
    f.dom.assertVisible("saved-190");
    f.dom.shell.scrollTop = 190 * rowHeight + 4;
    f.c.findingsArrowNav(-1);
    f.scrollRender();
    f.dom.assertVisible("saved-189");
    assert.equal(f.dom.shell.scrollTop, 189 * rowHeight);
    assert.deepEqual(f.loads, ["saved-190", "saved-189"]);
  });

  test(`Findings first paint clamps stale scroll after learning supplied ${rowHeight}px height`, () => {
    const f = findingsFixture({ rowHeight, scrollTop: 100000 });
    f.c.renderFindingsVirtual();
    assert.equal(f.dom.shell.scrollTop, 29 + 200 * rowHeight - 300);
    f.dom.assertVisible("saved-199");
  });
}

test("Findings live height changes update clamp, spacers, and selection without an old-height clamp", () => {
  const f = findingsFixture({ rowHeight: 27 });
  f.c.renderFindingsVirtual();
  f.dom.setHeight(41);
  f.dom.shell.scrollTop = f.dom.maxScroll();
  const requested = f.dom.shell.scrollTop;
  f.scrollRender();
  assert.equal(f.c.measuredFindingsRowHeight, 41);
  assert.equal(f.dom.shell.scrollTop, requested);
  assert.equal(f.dom.maxScroll(), 29 + 200 * 41 - 300);
  f.c.selectedFindingId = "saved-198";
  f.c.findingsArrowNav(1);
  f.scrollRender();
  f.dom.assertVisible("saved-199");
  f.dom.setHeight(24);
  f.scrollRender();
  assert.equal(f.dom.shell.scrollTop, 29 + 200 * 24 - 300);
  f.dom.assertVisible("saved-199");
});

for (const measurementHeight of [0, NaN, Infinity, -1]) {
  test(`Findings ignores unusable ${measurementHeight} row measurements`, () => {
    const f = findingsFixture({ rowHeight: 27, measurementHeight: () => measurementHeight });
    f.c.renderFindingsVirtual();
    assert.equal(f.c.measuredFindingsRowHeight, 27);
    assert.equal(f.dom.writes, 1);
    assert.equal(f.dom.maxScroll(), 29 + 200 * 27 - 300);
  });
}

test("Findings correction is bounded when supplied row measurements keep changing", () => {
  const f = findingsFixture({ rowHeight: 28, measurementHeight: writes => 28 + writes });
  f.c.renderFindingsVirtual();
  assert.ok(f.dom.writes <= 2);
});

for (const navigation of ["keyboard", "near-center"]) {
  test(`Findings ${navigation} updates font-changed spacers before a distant scroll can clamp`, () => {
    const f = findingsFixture({ rowHeight: 27, selectedIndex: 198 });
    f.c.renderFindingsVirtual();
    f.dom.setHeight(41);
    if (navigation === "keyboard") f.c.findingsArrowNav(1);
    else f.c.scrollFindingsToId("saved-199");
    f.scrollRender();
    f.dom.assertVisible("saved-199");
    assert.equal(f.dom.maxScroll(), 29 + 200 * 41 - 300);
  });
}

for (const viewportHeight of [0, 38, 66]) {
  test(`HTTP rendered selection in a ${viewportHeight}px viewport remains bounded on repeat`, () => {
    const f = historyFixture({ viewportHeight, scrollTop: 20 * 28, selectedIndex: 19 });
    const initial = f.shell.scrollTop;
    const writesBefore = f.scrollWrites.length;
    f.c.scrollSelectedHistoryRowIntoView();
    const afterFirst = f.shell.scrollTop;
    const writesAfter = f.scrollWrites.length;
    for (let i = 0; i < 4; i++) f.c.scrollSelectedHistoryRowIntoView();
    assert.equal(f.shell.scrollTop, afterFirst);
    assert.ok(writesAfter - writesBefore <= 1, "one correction at most");
    assert.equal(f.scrollWrites.length, writesAfter, "no repeated transient scroll assignments");
    assert.equal(f.nativeScrolls.length, 0);
    assert.ok(f.shell.scrollTop >= 0);
    if (viewportHeight === 0) {
      assert.equal(f.shell.scrollTop, initial);
      assert.equal(f.nativeScrolls.length, 0);
    }
    if (viewportHeight === 66) f.dom.assertVisible("saved-19");
  });
}


test("HTTP rendered row taller than the usable viewport stays top-aligned on downward selection", async () => {
  const f = historyFixture({ viewportHeight: 56, selectedIndex: 20, scrollTop: 20 * 28 });
  await f.c.moveHistorySelection(1);
  assert.equal(f.shell.scrollTop, 21 * 28);
  const writes = f.scrollWrites.length;
  f.c.scrollSelectedHistoryRowIntoView();
  f.c.scrollSelectedHistoryRowIntoView();
  assert.equal(f.shell.scrollTop, 21 * 28);
  assert.equal(f.scrollWrites.length, writes);
});

test("HTTP rendered row guards a missing shell and supports a missing header", async () => {
  const f = historyFixture({ missingHeader: true, selectedIndex: 20, scrollTop: 20 * 28 });
  await f.c.moveHistorySelection(-1);
  f.dom.assertVisible("saved-19");
  const scrollTop = f.shell.scrollTop;
  f.dom.table.closest = () => null;
  f.c.scrollSelectedHistoryRowIntoView();
  assert.equal(f.shell.scrollTop, scrollTop);
  assert.equal(f.nativeScrolls.length, 0);
});

test("Findings revalidates a cached height after unavailable row geometry becomes measurable", () => {
  const f = findingsFixture({ rowHeight: 41 });
  f.c.renderFindingsVirtual();
  f.dom.setHeight(0);
  f.c.renderFindingsVirtual();
  assert.equal(f.c.measuredFindingsRowHeight, 41);
  f.dom.setHeight(27.5);
  f.c.renderFindingsVirtual();
  assert.equal(f.c.measuredFindingsRowHeight, 27.5);
  assert.equal(f.dom.maxScroll(), 29 + 200 * 27.5 - 300);
  f.dom.shell.scrollTop = f.dom.maxScroll();
  f.scrollRender();
  f.dom.assertVisible("saved-199");
});

for (const viewportHeight of [29, 66]) {
  test(`Findings measured row taller than ${viewportHeight}px viewport space stays stable at the keyboard boundary`, () => {
    const f = findingsFixture({ rowHeight: 41, headerHeight: 29, viewportHeight, selectedIndex: 198 });
    f.c.renderFindingsVirtual();
    f.c.findingsArrowNav(1);
    f.scrollRender();
    assert.equal(f.c.selectedFindingId, "saved-199");
    assert.equal(f.dom.shell.scrollTop, 199 * 41);
    const writes = f.dom.scrollWrites.length;
    for (let i = 0; i < 4; i++) {
      f.c.findingsArrowNav(1);
      f.scrollRender();
      assert.equal(f.dom.shell.scrollTop, 199 * 41);
    }
    assert.equal(f.dom.scrollWrites.length, writes, "no repeated scroll assignments at the selected boundary");
  });
}
