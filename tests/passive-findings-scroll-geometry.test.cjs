// Supplied table coordinates only; no browser, scanning, actions, or live reads.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const constants = Object.fromEntries([...appSource.matchAll(/^const (FINDINGS_(?:ROW_HEIGHT|BUFFER_ROWS)) = (\d+);$/gm)]
  .map(([, name, value]) => [name, Number(value)]));

function fixture(options = {}) {
  const rowHeight = constants.FINDINGS_ROW_HEIGHT;
  const headerHeight = options.missingHeader ? 0 : (options.headerHeight ?? 29);
  const rowCount = options.rowCount ?? 40;
  const viewportHeight = options.viewportHeight ?? 200;
  const handlers = new Map(), frames = [], loads = [];
  const shell = {
    clientHeight: viewportHeight, scrollTop: options.scrollTop ?? 0,
    addEventListener(type, callback) { handlers.set(type, callback); },
  };
  const table = { tHead: options.missingHeader ? null : { getBoundingClientRect: () => ({ height: headerHeight }) } };
  const node = { classList: { add() {}, remove() {} } };
  const body = {
    innerHTML: "",
    closest(selector) { return selector === "table" ? table : (options.missingShell ? null : shell); },
    querySelector(selector) {
      if (selector === ".history-row.selected") return node;
      return options.unrenderedRow ? null : node;
    },
  };
  const state = { _findingsEntries: Array.from({ length: rowCount }, (_, index) => ({
    id: `saved-${index}`, record_id: `record-${index}`, severity: "info", category: "saved",
    title: "Saved entry", host: "example.com", path: "/saved", found_at: "",
  })) };
  const c = loadFunctions([
    "renderFindingsVirtual", "scrollFindingsToId", "findingsArrowNav", "updateFindingsSelection",
    "escapeHtml", "severityClass", "severityLabel",
  ], {
    ...constants, state, els: { findingsBody: body }, selectedFindingId: `saved-${options.selectedIndex ?? 0}`,
    formatTimestamp: () => "-", loadFindingDetail: id => loads.push(id),
    requestAnimationFrame(callback) { frames.push(callback); return frames.length; },
  });
  // Use the real passive scroll callback, excluding all finding action bindings.
  const start = appSource.indexOf("  const findingsShell =", appSource.indexOf("function bindFindingsEvents()"));
  const end = appSource.indexOf("\n  // Event delegation for findings table rows", start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(appSource.slice(start, end), c);
  const f = {
    c, state, body, shell, loads, rowHeight, headerHeight, rowCount, viewportHeight,
    renderAfterScroll() {
      handlers.get("scroll")?.();
      while (frames.length) frames.shift()();
    },
    rowRect(index) {
      const top = headerHeight + index * rowHeight - shell.scrollTop;
      return { top, bottom: top + rowHeight };
    },
    assertVisible(index) {
      const rect = f.rowRect(index);
      assert.ok(rect.top >= headerHeight, `row top ${rect.top} is above sticky header ${headerHeight}`);
      assert.ok(rect.bottom <= viewportHeight, `row bottom ${rect.bottom} is below viewport ${viewportHeight}`);
    },
  };
  return f;
}

for (const headerHeight of [0, 29, 38.5]) {
  test(`saved findings final row stays visible through repeated scroll rendering with ${headerHeight}px header`, () => {
    const f = fixture({ headerHeight, rowCount: 20 });
    const bottom = headerHeight + f.rowCount * f.rowHeight - f.viewportHeight;
    f.shell.scrollTop = bottom;
    f.renderAfterScroll();
    f.assertVisible(19);
    assert.equal(f.shell.scrollTop, bottom);
    assert.match(f.body.innerHTML, /data-finding-id="saved-19"/);
    f.renderAfterScroll();
    assert.equal(f.shell.scrollTop, bottom);
  });

  test(`saved findings clamps stale scroll to the shorter list including ${headerHeight}px header`, () => {
    const f = fixture({ headerHeight, rowCount: 20, scrollTop: 2400 });
    f.c.renderFindingsVirtual();
    assert.equal(f.shell.scrollTop, headerHeight + 20 * f.rowHeight - f.viewportHeight);
    f.assertVisible(19);
  });

  test(`saved findings keyboard bottom boundary counts ${headerHeight}px header`, () => {
    const f = fixture({ headerHeight, selectedIndex: 7, viewportHeight: 250 });
    const original = JSON.stringify(f.state._findingsEntries);
    f.c.findingsArrowNav(1);
    assert.equal(f.c.selectedFindingId, "saved-8");
    f.assertVisible(8);
    f.renderAfterScroll();
    f.assertVisible(8);
    assert.deepEqual(f.loads, ["saved-8"]);
    assert.equal(JSON.stringify(f.state._findingsEntries), original);
  });

  test(`saved findings keyboard virtual-row fallback survives rendering with ${headerHeight}px header`, () => {
    const f = fixture({ headerHeight, selectedIndex: 18, rowCount: 20, unrenderedRow: true });
    f.c.findingsArrowNav(1);
    f.assertVisible(19);
    f.renderAfterScroll();
    f.assertVisible(19);
    assert.match(f.body.innerHTML, /data-finding-id="saved-19"/);
    assert.deepEqual(f.loads, ["saved-19"]);
  });

  test(`saved findings upward navigation aligns beneath ${headerHeight}px header`, () => {
    const f = fixture({ headerHeight, selectedIndex: 20, scrollTop: 19 * constants.FINDINGS_ROW_HEIGHT + 4 });
    f.c.findingsArrowNav(-1);
    assert.equal(f.shell.scrollTop, 19 * f.rowHeight);
    assert.equal(f.rowRect(19).top, headerHeight);
    f.assertVisible(19);
    f.renderAfterScroll();
    f.assertVisible(19);
  });
}

for (const viewportHeight of [56, 57, 80, 300]) {
  test(`saved findings near-center selection keeps its row visible in ${viewportHeight}px viewport`, () => {
    const f = fixture({ viewportHeight, unrenderedRow: true });
    f.c.updateFindingsSelection("saved-20");
    f.assertVisible(20);
    f.renderAfterScroll();
    f.assertVisible(20);
    if (viewportHeight === 300) assert.equal(f.shell.scrollTop, 20 * f.rowHeight - 150);
  });
}

for (const useKeyboard of [false, true]) {
  test(`saved findings ${useKeyboard ? "keyboard" : "near-center"} navigation preserves known scroll without a viewport measurement`, () => {
    const f = fixture({ viewportHeight: 0, selectedIndex: 18, unrenderedRow: true, scrollTop: 125 });
    if (useKeyboard) f.c.findingsArrowNav(1); else f.c.scrollFindingsToId("saved-19");
    assert.equal(f.shell.scrollTop, 125);
  });
}

test("saved findings list fitting the viewport resets stale scroll to the top", () => {
  const f = fixture({ rowCount: 5, scrollTop: 2400 });
  f.c.renderFindingsVirtual();
  assert.equal(f.shell.scrollTop, 0);
  f.assertVisible(0);
  f.assertVisible(4);
});

test("saved findings missing header preserves body-only geometry", () => {
  const f = fixture({ rowCount: 20, missingHeader: true, scrollTop: 2400 });
  f.c.renderFindingsVirtual();
  assert.equal(f.shell.scrollTop, 20 * f.rowHeight - f.viewportHeight);
  f.assertVisible(19);
});

test("saved findings absent rows or shell do not change known scroll or initiate a detail read", () => {
  for (const options of [{ rowCount: 0 }, { missingShell: true }]) {
    const f = fixture({ ...options, scrollTop: 125 });
    f.c.renderFindingsVirtual();
    f.c.scrollFindingsToId("missing");
    assert.equal(f.shell.scrollTop, 125);
    assert.deepEqual(f.loads, []);
  }
});
