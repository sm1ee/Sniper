const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function createFixture({ rowCount = 100, rowHeight = 27, headerHeight = 27, viewportHeight = 300, scrollTop } = {}) {
  const state = {
    _historyEntries: Array.from({ length: rowCount }, (_, index) => ({ item: { id: `fixture-${index}` }, index })),
    historyColumnOrder: ["index"],
    historyPaging: { trimmedHeadCount: 0, loading: false },
    selectedId: null,
  };
  const shell = {
    clientHeight: viewportHeight,
    scrollTop: scrollTop ?? Math.max(0, headerHeight + rowCount * rowHeight - viewportHeight),
  };
  const body = {
    innerHTML: "",
    querySelector: () => ({ getBoundingClientRect: () => ({ height: rowHeight }) }),
  };
  const context = loadFunctions(["renderHistoryVirtual"], {
    state,
    els: {
      historyTable: {
        closest: () => shell,
        tHead: { getBoundingClientRect: () => ({ height: headerHeight }) },
      },
      historyTableBody: body,
    },
    measuredHistoryRowHeight: rowHeight,
    HISTORY_ROW_HEIGHT: 27,
    HISTORY_BUFFER_ROWS: 30,
    HTTP_HISTORY_SCROLL_PREFETCH_ROWS: 120,
    renderHistoryCell: (_column, item) => `<td>${item.id}</td>`,
    scheduleHistoryBackfill() {},
  });
  return { context, state, shell, body, rowCount, rowHeight, headerHeight, viewportHeight };
}

for (const headerHeight of [27, 38]) {
  test(`the final history row stays fully visible below a ${headerHeight}px header`, () => {
    const fixture = createFixture({ headerHeight });
    const expectedBottom = fixture.shell.scrollTop;
    fixture.context.renderHistoryVirtual();

    assert.equal(fixture.shell.scrollTop, expectedBottom);
    assert.equal(headerHeight + fixture.rowCount * fixture.rowHeight - fixture.shell.scrollTop, fixture.viewportHeight);
    assert.match(fixture.body.innerHTML, /data-id="fixture-99"/);
    fixture.context.renderHistoryVirtual();
    assert.equal(fixture.shell.scrollTop, expectedBottom, "repeated renders must not pull the viewport up");
  });
}

test("a shorter history list still clamps stale scroll to its new bottom", () => {
  const fixture = createFixture({ rowCount: 15, scrollTop: 2400 });
  fixture.context.renderHistoryVirtual();
  assert.equal(fixture.shell.scrollTop, 27 + 15 * 27 - 300);
  assert.match(fixture.body.innerHTML, /data-id="fixture-14"/);
});

test("a history list that fits the viewport resets stale scroll to the top", () => {
  const fixture = createFixture({ rowCount: 5, scrollTop: 2400 });
  fixture.context.renderHistoryVirtual();
  assert.equal(fixture.shell.scrollTop, 0);
  assert.match(fixture.body.innerHTML, /data-id="fixture-0"/);
  assert.match(fixture.body.innerHTML, /data-id="fixture-4"/);
});

test("a headerless fixture preserves body-only scroll geometry", () => {
  const fixture = createFixture({ headerHeight: 0 });
  delete fixture.context.els.historyTable.tHead;
  fixture.context.renderHistoryVirtual();
  assert.equal(fixture.shell.scrollTop, 2400);
});
