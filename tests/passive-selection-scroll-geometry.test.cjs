// Offline coordinate fixtures only. These tests extract passive display helpers;
// they do not run the app, create a browser DOM, or make network requests.
const assert = require("node:assert/strict");
const test = require("node:test");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const constants = Object.fromEntries(Array.from(appSource.matchAll(
  /^const ((?:HISTORY_(?:ROW_HEIGHT|BUFFER_ROWS))|(?:WEBSOCKET_(?:MAX_RENDERED_(?:SESSION|FRAME)_ROWS|(?:SESSION|FRAME)_(?:ROW_HEIGHT|BUFFER_ROWS)))) = (\d+);$/gm,
), ([, name, value]) => [name, Number(value)]));

function createFixture(kind, options = {}) {
  let rowHeight = options.rowHeight ?? 28;
  const headerHeight = options.headerHeight ?? 38;
  const noticeHeight = options.noticeHeight ?? 0;
  const rowCount = options.rowCount ?? 2000;
  const viewportHeight = options.viewportHeight ?? 300;
  const shell = { clientHeight: viewportHeight, scrollTop: options.scrollTop ?? 0 };
  const table = {
    closest: () => options.missingShell ? null : shell,
    tHead: options.missingHeader ? null : { getBoundingClientRect: () => ({ height: headerHeight }) },
  };
  const body = {
    innerHTML: "",
    closest: selector => selector === "table" ? table : (options.missingShell ? null : shell),
    querySelector(selector) {
      if (selector === ".ws-frame-window-row" && noticeHeight) {
        return { getBoundingClientRect: () => ({ height: noticeHeight }) };
      }
      if (selector === ".history-row") {
        return { getBoundingClientRect: () => ({ height: rowHeight }) };
      }
      // The HTTP selection helper must exercise its virtual-row fallback.
      return null;
    },
  };
  const historyEntries = Array.from({ length: rowCount }, (_, index) => ({ item: { id: `fixture-${index}` }, index }));
  const sessionEntries = Array.from({ length: rowCount }, (_, index) => ({ session: { id: `fixture-${index}` }, index }));
  const frames = Array.from({ length: rowCount }, (_, index) => ({ index }));
  const state = {
    _historyEntries: historyEntries,
    selectedId: null,
    historyColumnOrder: ["index"],
    historyPaging: { trimmedHeadCount: 0, loading: false },
  };
  const context = loadFunctions([
    "scrollHistoryToId", "scrollSelectedHistoryRowIntoView", "measuredRowPitch", "renderHistoryVirtual",
    "ensureWebsocketSessionInView", "websocketRenderedSessionWindow",
    "ensureWebsocketFramePositionInView", "websocketFramesShell", "websocketRenderedFrameWindow",
  ], {
    ...constants,
    state,
    els: { historyTable: table, historyTableBody: body, websocketFramesBody: body },
    document: { querySelector: () => table },
    measuredHistoryRowHeight: rowHeight,
    measuredWebsocketSessionRowHeight: rowHeight,
    measuredWebsocketFrameRowHeight: rowHeight,
    HTTP_HISTORY_SCROLL_PREFETCH_ROWS: 120,
    getSortedWebsocketEntries: () => sessionEntries,
    renderHistoryCell: (_column, item) => `<td>${item.id}</td>`,
    scheduleHistoryBackfill() {},
  });
  const effectiveHeaderHeight = options.missingHeader ? 0 : headerHeight;
  const fixture = {
    context, shell, state, rowCount, headerHeight: effectiveHeaderHeight, viewportHeight,
    rowTop(position) { return (kind === "frames" ? noticeHeight : 0) + position * rowHeight; },
    rowRect(position) {
      const top = effectiveHeaderHeight + fixture.rowTop(position) - shell.scrollTop;
      return { top, bottom: top + rowHeight };
    },
    select(position, { center = false } = {}) {
      const id = `fixture-${position}`;
      state.selectedId = id;
      if (kind === "history") {
        return center ? context.scrollHistoryToId(id) : context.scrollSelectedHistoryRowIntoView();
      }
      if (kind === "sessions") return context.ensureWebsocketSessionInView(id, sessionEntries, { center });
      return context.ensureWebsocketFramePositionInView(position, { center });
    },
    render() {
      if (kind === "history") return context.renderHistoryVirtual();
      if (kind === "sessions") return context.websocketRenderedSessionWindow(sessionEntries);
      return context.websocketRenderedFrameWindow(frames, { leadingHeight: noticeHeight });
    },
    setRowHeight(height) {
      rowHeight = height;
      context.measuredHistoryRowHeight = height;
      context.measuredWebsocketSessionRowHeight = height;
      context.measuredWebsocketFrameRowHeight = height;
    },
  };
  return fixture;
}

function assertFullyVisible(fixture, position) {
  const rect = fixture.rowRect(position);
  assert.ok(rect.top >= fixture.headerHeight,
    `row top ${rect.top} is obscured by the ${fixture.headerHeight}px sticky header`);
  assert.ok(rect.bottom <= fixture.viewportHeight,
    `row bottom ${rect.bottom} exceeds the ${fixture.viewportHeight}px viewport`);
}

for (const kind of ["history", "sessions", "frames"]) {
  test(`${kind}: nearest-bottom selection includes header height and survives rerender`, () => {
    const f = createFixture(kind);
    f.select(1900);
    assertFullyVisible(f, 1900);
    assert.equal(f.rowRect(1900).bottom, f.viewportHeight);
    const selectedScrollTop = f.shell.scrollTop;
    f.render();
    assert.equal(f.shell.scrollTop, selectedScrollTop);
    assertFullyVisible(f, 1900);
  });

  test(`${kind}: a body-relative bottom inside the viewport can overflow after counting the header`, () => {
    const f = createFixture(kind);
    // Body bottom 280 is below 300, but its table-relative bottom is 318.
    f.select(9);
    assertFullyVisible(f, 9);
    assert.equal(f.shell.scrollTop, 18);
  });

  test(`${kind}: scrolling upward aligns the row below the sticky header`, () => {
    const f = createFixture(kind);
    f.shell.scrollTop = f.rowTop(20) + 7;
    f.select(20);
    assert.equal(f.shell.scrollTop, f.rowTop(20));
    assert.equal(f.rowRect(20).top, f.headerHeight);
    assertFullyVisible(f, 20);
  });

  test(`${kind}: an already-visible selection preserves scroll on repeated calls`, () => {
    const f = createFixture(kind);
    f.shell.scrollTop = f.rowTop(20) - 100;
    const initialScrollTop = f.shell.scrollTop;
    f.select(20);
    f.select(20);
    assert.equal(f.shell.scrollTop, initialScrollTop);
    assertFullyVisible(f, 20);
  });

  test(`${kind}: selection uses updated measured row height`, () => {
    const f = createFixture(kind);
    f.setRowHeight(41);
    f.select(100);
    assertFullyVisible(f, 100);
    assert.equal(f.rowRect(100).bottom, f.viewportHeight);
  });

  test(`${kind}: a missing header retains body-only geometry`, () => {
    const f = createFixture(kind, { missingHeader: true });
    f.select(100);
    assertFullyVisible(f, 100);
    assert.equal(f.rowRect(100).bottom, f.viewportHeight);
  });

  test(`${kind}: a fitting list remains at the top`, () => {
    const f = createFixture(kind, { rowCount: 5 });
    f.select(4);
    assert.equal(f.shell.scrollTop, 0);
    assertFullyVisible(f, 4);
  });

  test(`${kind}: missing scroll shell leaves selection scrolling unchanged`, () => {
    const f = createFixture(kind, { missingShell: true, scrollTop: 777 });
    f.select(100);
    f.select(100, { center: true });
    assert.equal(f.shell.scrollTop, 777);
  });

  test(`${kind}: invalid or missing selection targets leave scroll unchanged`, () => {
    const f = createFixture(kind, { scrollTop: 777 });
    const positions = kind === "frames" ? [-1, undefined, NaN, Infinity] : [-1, f.rowCount];
    for (const position of positions) {
      f.select(position);
      f.select(position, { center: true });
      assert.equal(f.shell.scrollTop, 777);
    }
  });

  test(`${kind}: centered selection stays visible in a tight but sufficient viewport`, () => {
    const f = createFixture(kind, { viewportHeight: 80 });
    // 80px can fit the 38px sticky header plus the complete 28px row.
    f.select(100, { center: true });
    assertFullyVisible(f, 100);
  });

  test(`${kind}: centered selection remains visible in a roomy viewport`, () => {
    const f = createFixture(kind);
    f.select(100, { center: true });
    assertFullyVisible(f, 100);
    assert.equal(f.shell.scrollTop, Math.max(0, f.rowTop(100) - f.viewportHeight / 2),
      "keep the existing near-center position when it already reveals the complete row");
  });

  for (const center of [false, true]) {
    test(`${kind}: ${center ? "center" : "nearest"} fits a row when header plus row exactly fills the viewport`, () => {
      const f = createFixture(kind, { viewportHeight: 66 });
      f.select(100, { center });
      assert.equal(f.shell.scrollTop, f.rowTop(100),
        "the single fully visible position aligns the row immediately below the header");
      assertFullyVisible(f, 100);
      assert.equal(f.rowRect(100).top, f.headerHeight);
      assert.equal(f.rowRect(100).bottom, f.viewportHeight);
    });
  }

  test(`${kind}: centering the first row never requests negative scroll`, () => {
    const f = createFixture(kind, { scrollTop: 777 });
    f.select(0, { center: true });
    assert.equal(f.shell.scrollTop, 0);
    assertFullyVisible(f, 0);
  });

  for (const center of [false, true]) {
    test(`${kind}: ${center ? "center" : "nearest"} preserves known scroll without viewport geometry`, () => {
      const f = createFixture(kind, { viewportHeight: 0, headerHeight: 0, scrollTop: 777 });
      f.select(100, { center });
      // This is an unavailable-geometry contract, not a browser-hidden DOM claim.
      assert.equal(f.shell.scrollTop, 777);
    });
  }
}

test("sessions: an overflowing unvirtualized list reveals a distant selection", () => {
  const f = createFixture("sessions", { rowCount: 100 });
  f.select(99);
  assertFullyVisible(f, 99);
  assert.equal(f.rowRect(99).bottom, f.viewportHeight);
});

test("sessions: refreshing an already-visible unvirtualized selection does not reset scroll", () => {
  const f = createFixture("sessions", { rowCount: 100, scrollTop: 2538 });
  assertFullyVisible(f, 99);
  f.select(99);
  assert.equal(f.shell.scrollTop, 2538);
  assertFullyVisible(f, 99);
});

test("sessions: a list that actually fits resets stale scroll regardless of render threshold", () => {
  const f = createFixture("sessions", { rowCount: 5, scrollTop: 777 });
  f.select(4);
  assert.equal(f.shell.scrollTop, 0);
  assertFullyVisible(f, 4);
});

for (const noticeHeight of [28, 42]) {
  test(`frames: nearest-bottom includes the measured ${noticeHeight}px older-frame notice and header`, () => {
    const f = createFixture("frames", { noticeHeight });
    f.select(100);
    assertFullyVisible(f, 100);
    assert.equal(f.rowRect(100).bottom, f.viewportHeight);
    const selectedScrollTop = f.shell.scrollTop;
    f.render();
    assert.equal(f.shell.scrollTop, selectedScrollTop);
  });

  test(`frames: top alignment preserves the measured ${noticeHeight}px older-frame notice offset`, () => {
    const f = createFixture("frames", { noticeHeight });
    f.shell.scrollTop = f.rowTop(100) + 7;
    f.select(100);
    assert.equal(f.shell.scrollTop, f.rowTop(100));
    assertFullyVisible(f, 100);
  });

  test(`frames: tight-viewport centering includes the ${noticeHeight}px notice offset`, () => {
    const f = createFixture("frames", { noticeHeight, viewportHeight: 80 });
    f.select(100, { center: true });
    assertFullyVisible(f, 100);
  });
}
