// Offline render-caller regressions. Bounds and innerHTML are synthetic, and
// only extracted passive display functions run. No browser layout is asserted.
const assert = require("node:assert/strict");
const test = require("node:test");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const constants = Object.fromEntries(Array.from(appSource.matchAll(
  /^const (WEBSOCKET_(?:MAX_(?:RENDERED_FRAME_ROWS|LOADED_FRAMES)|FRAME_(?:ROW_HEIGHT|BUFFER_ROWS))) = (\d+);$/gm,
), ([, name, value]) => [name, Number(value)]));

function createFixture(options = {}) {
  const rowCount = options.rowCount ?? 2000;
  const headerHeight = options.headerHeight ?? 38;
  const viewportHeight = options.viewportHeight ?? 300;
  let nextNoticeHeight = options.noticeHeight ?? 42;
  let nextRowHeight = options.rowHeight ?? 28;
  let noticeExists = options.initialNoticeHeight !== null;
  let renderedNoticeHeight = options.initialNoticeHeight ?? nextNoticeHeight;
  let renderedRowHeight = nextRowHeight;
  let renderedContentHeight = (options.missingHeader ? 0 : headerHeight)
    + (noticeExists ? renderedNoticeHeight : 0) + rowCount * renderedRowHeight;
  let renders = 0;
  let html = "";
  const scrollWrites = [];
  let scrollTop = options.scrollTop ?? Math.max(0, headerHeight + nextNoticeHeight + rowCount * nextRowHeight - viewportHeight);
  const shell = {
    clientHeight: viewportHeight,
    get scrollTop() { return scrollTop; },
    set scrollTop(value) {
      scrollWrites.push(value);
      scrollTop = options.clampToRenderedHeight
        ? Math.max(0, Math.min(value, renderedContentHeight - viewportHeight))
        : value;
    },
  };
  const table = {
    tHead: options.missingHeader ? null : { getBoundingClientRect: () => ({ height: headerHeight }) },
  };
  const body = {
    closest: selector => selector === "table" ? table : (options.missingShell ? null : shell),
    get innerHTML() { return html; },
    set innerHTML(value) {
      html = value;
      renders++;
      assert.ok(renders < 12, "stable or unavailable measurements must not cause unbounded rerenders");
      noticeExists = value.includes('class="ws-frame-window-row"');
      const nextRenderedNoticeHeight = options.noticeHeightSequence?.length
        ? options.noticeHeightSequence[(renders - 1) % options.noticeHeightSequence.length]
        : nextNoticeHeight;
      renderedNoticeHeight = noticeExists ? nextRenderedNoticeHeight : 0;
      renderedRowHeight = nextRowHeight;
      const spacerHeight = Array.from(value.matchAll(/style="height:([\d.]+)px;padding:0;border:none"/g))
        .reduce((sum, match) => sum + Number(match[1]), 0);
      const renderedFrameCount = Array.from(value.matchAll(/class="history-row(?: frame-selected)?"/g)).length;
      renderedContentHeight = (options.missingHeader ? 0 : headerHeight)
        + renderedNoticeHeight + spacerHeight + renderedFrameCount * renderedRowHeight;
    },
    querySelector(selector) {
      if (selector === ".ws-frame-window-row") {
        if (!noticeExists || options.noticeMeasurement === "missing") return null;
        return { getBoundingClientRect: () => ({ height: options.noticeMeasurement === "zero" ? 0 : renderedNoticeHeight }) };
      }
      if (selector === ".history-row") {
        if (options.rowMeasurement === "missing") return null;
        return { getBoundingClientRect: () => ({ height: options.rowMeasurement === "zero" ? 0 : renderedRowHeight }) };
      }
      return null;
    },
  };
  function makeFrames(firstIndex) {
    return Array.from({ length: rowCount }, (_, index) => ({
      index: firstIndex + index, direction: "client_to_server", kind: "text", body_size: 0,
    }));
  }
  const session = { frames: makeFrames(100), frame_count: rowCount + 100, frames_truncated: true };
  const state = { selectedWebsocketRecord: session, selectedFrameIdx: session.frames.at(-1)?.index ?? null };
  const context = loadFunctions([
    "renderWebsocketFrameTable", "websocketRenderedFrameWindow", "websocketFramesShell",
    "ensureWebsocketFramePositionInView",
  ], {
    ...constants,
    state,
    els: { websocketFramesBody: body },
    measuredWebsocketFrameRowHeight: options.initialRowHeight ?? nextRowHeight,
    getWebsocketFrames: value => value.frames,
    websocketFirstRetainedFrameIndex: () => 0,
    hideFrameDetail() {},
    escapeHtml: String,
    formatSize: String,
    renderFramePreview: () => "Synthetic frame",
  });
  const fixture = {
    shell, body, context, state, session, rowCount, viewportHeight, scrollWrites,
    get renders() { return renders; },
    get headerHeight() { return options.missingHeader ? 0 : headerHeight; },
    render() { context.renderWebsocketFrameTable(); },
    bottom(noticeHeight = noticeExists ? renderedNoticeHeight : 0, rowHeight = renderedRowHeight) {
      return Math.max(0, fixture.headerHeight + noticeHeight + rowCount * rowHeight - viewportHeight);
    },
    lastRowRect() {
      const bottom = fixture.headerHeight + (noticeExists ? renderedNoticeHeight : 0)
        + rowCount * renderedRowHeight - shell.scrollTop;
      return { top: bottom - renderedRowHeight, bottom };
    },
    setNoticeHeight(height, { beforeRender = false } = {}) {
      nextNoticeHeight = height;
      if (beforeRender && noticeExists) renderedNoticeHeight = height;
    },
    setRowHeight(height) { nextRowHeight = height; },
    removeNotice() {
      session.frames = makeFrames(0);
      session.frame_count = rowCount;
      session.frames_truncated = false;
      state.selectedFrameIdx = session.frames.at(-1)?.index ?? null;
    },
  };
  return fixture;
}

function assertLastRowAtBottom(f) {
  const rect = f.lastRowRect();
  assert.equal(rect.bottom, f.viewportHeight, "the last row must align with the viewport bottom");
  assert.ok(rect.top >= f.headerHeight, "the selected last row must remain below the sticky header");
  assert.match(f.body.innerHTML, new RegExp(`class="history-row frame-selected" data-frame-index="${f.state.selectedFrameIdx}"`));
}

for (const headerHeight of [0, 27, 38]) {
  test(`existing measured frame notice preserves selected-bottom geometry with a ${headerHeight}px header`, () => {
    const f = createFixture({ headerHeight });
    const intendedScrollTop = f.shell.scrollTop;
    f.render();
    assert.equal(f.shell.scrollTop, intendedScrollTop);
    assertLastRowAtBottom(f);
    f.render();
    assert.equal(f.shell.scrollTop, intendedScrollTop, "repeated renders must not replace a valid measured height with the row estimate");
    assertLastRowAtBottom(f);
  });
}

test("a measured notice matching the frame-row estimate retains existing geometry", () => {
  const f = createFixture({ noticeHeight: 28 });
  const intendedScrollTop = f.shell.scrollTop;
  f.render();
  assert.equal(f.shell.scrollTop, intendedScrollTop);
  assertLastRowAtBottom(f);
});

test("rendering after selecting the last frame preserves the notice-aware selection scroll", () => {
  const f = createFixture({ scrollTop: 0 });
  f.context.ensureWebsocketFramePositionInView(f.rowCount - 1);
  assert.equal(f.shell.scrollTop, f.bottom());
  const selectedScrollTop = f.shell.scrollTop;
  f.render();
  assert.equal(f.shell.scrollTop, selectedScrollTop);
  assertLastRowAtBottom(f);
});

for (const noticeHeight of [42, 70]) {
  test(`a new ${noticeHeight}px notice is measured before an initial estimate permanently loses scroll`, () => {
    const f = createFixture({ initialNoticeHeight: null, noticeHeight });
    const intendedScrollTop = f.shell.scrollTop;
    f.render();
    assert.equal(f.shell.scrollTop, intendedScrollTop);
    assertLastRowAtBottom(f);
    assert.ok(f.renders <= 3, "one stable measured correction should settle promptly");
  });
}

test("an existing notice that grows before render uses its current measured height", () => {
  const f = createFixture({ noticeHeight: 28 });
  f.render();
  f.setNoticeHeight(70, { beforeRender: true });
  f.shell.scrollTop = f.bottom();
  const intendedScrollTop = f.shell.scrollTop;
  f.render();
  assert.equal(f.shell.scrollTop, intendedScrollTop);
  assertLastRowAtBottom(f);
});

test("notice growth caused by new row markup preserves the incoming scroll intent", () => {
  const f = createFixture({ noticeHeight: 28 });
  f.render();
  f.setNoticeHeight(70);
  // The input scroll is valid for the newly rendered measured geometry. An old
  // notice estimate may be used for the first pass, but cannot destroy it.
  f.shell.scrollTop = f.bottom(70);
  const intendedScrollTop = f.shell.scrollTop;
  f.render();
  assert.equal(f.shell.scrollTop, intendedScrollTop);
  assertLastRowAtBottom(f);
});

test("notice shrinkage clamps only to the new measured content bottom", () => {
  const f = createFixture({ noticeHeight: 70 });
  f.setNoticeHeight(14);
  f.render();
  assert.equal(f.shell.scrollTop, f.bottom(14));
  assertLastRowAtBottom(f);
});

test("a new fractional-height notice preserves scroll below the frame-row estimate tolerance", () => {
  const f = createFixture({ initialNoticeHeight: null, noticeHeight: 28.5 });
  const intendedScrollTop = f.shell.scrollTop;
  f.render();
  assert.equal(f.shell.scrollTop, intendedScrollTop);
  assertLastRowAtBottom(f);
  assert.ok(f.renders <= 2);
});

for (const [initialNoticeHeight, noticeHeight] of [[42, 42.5], [42.5, 42]]) {
  test(`a notice changing from ${initialNoticeHeight}px to ${noticeHeight}px receives a measured correction`, () => {
    const f = createFixture({ initialNoticeHeight, noticeHeight });
    f.shell.scrollTop = f.bottom(Math.max(initialNoticeHeight, noticeHeight));
    f.render();
    assert.equal(f.shell.scrollTop, f.bottom(noticeHeight));
    assertLastRowAtBottom(f);
    assert.ok(f.renders <= 2);
  });
}

test("alternating notice measurements receive at most one corrective pass per render call", () => {
  const f = createFixture({
    initialNoticeHeight: 28,
    noticeHeightSequence: [42, 70],
    scrollTop: 100000,
  });
  for (let call = 0; call < 3; call++) {
    const previousRenders = f.renders;
    f.render();
    assert.equal(f.renders - previousRenders, 2, "unstable bounds must not cause unbounded corrective passes");
    assert.ok(Number.isFinite(f.shell.scrollTop));
    assert.ok(f.scrollWrites.every(Number.isFinite));
    assert.match(f.body.innerHTML, /history-row frame-selected/);
  }
});

test("a short measured notice clamps stale scroll without leaving estimated empty space", () => {
  const f = createFixture({ noticeHeight: 14, scrollTop: 100000 });
  f.render();
  assert.equal(f.shell.scrollTop, f.bottom(14));
  assertLastRowAtBottom(f);
});

test("notice removal ignores the old rendered notice when clamping the shorter table", () => {
  const f = createFixture({ noticeHeight: 42 });
  f.removeNotice();
  f.render();
  assert.doesNotMatch(f.body.innerHTML, /ws-frame-window-row/);
  assert.equal(f.shell.scrollTop, f.bottom(0));
  assertLastRowAtBottom(f);
  const noNoticeScroll = f.shell.scrollTop;
  f.render();
  assert.equal(f.shell.scrollTop, noNoticeScroll);
});

test("a row-height correction also retains scroll captured before the first estimated clamp", () => {
  const f = createFixture({ initialRowHeight: 28, rowHeight: 40, noticeHeight: 42 });
  const intendedScrollTop = f.shell.scrollTop;
  f.render();
  assert.equal(f.context.measuredWebsocketFrameRowHeight, 40);
  assert.equal(f.shell.scrollTop, intendedScrollTop);
  assertLastRowAtBottom(f);
  assert.ok(f.renders <= 3);
});

test("a row-height correction preserves entry scroll when assignments clamp to current synthetic content", () => {
  const f = createFixture({
    initialRowHeight: 28,
    rowHeight: 40,
    noticeHeight: 42,
    clampToRenderedHeight: true,
  });
  const intendedScrollTop = f.shell.scrollTop;
  f.render();
  assert.equal(f.context.measuredWebsocketFrameRowHeight, 40);
  assert.equal(f.shell.scrollTop, intendedScrollTop,
    "restoring scroll before corrected spacers exist must not discard the original numeric target");
  assertLastRowAtBottom(f);
  assert.ok(f.renders <= 2);
});

test("interior scroll does not jump when measured notice geometry is refreshed", () => {
  const f = createFixture({ scrollTop: 12000 });
  f.render();
  assert.equal(f.shell.scrollTop, 12000);
  f.setNoticeHeight(70);
  f.render();
  assert.equal(f.shell.scrollTop, 12000);
});

test("a missing table header preserves measured notice geometry", () => {
  const f = createFixture({ missingHeader: true, headerHeight: 0 });
  const intendedScrollTop = f.shell.scrollTop;
  f.render();
  assert.equal(f.shell.scrollTop, intendedScrollTop);
  assertLastRowAtBottom(f);
});

for (const noticeMeasurement of ["missing", "zero"]) {
  for (const rowMeasurement of ["missing", "zero"]) {
    test(`${noticeMeasurement} notice and ${rowMeasurement} row measurements use a bounded finite fallback`, () => {
      const f = createFixture({ noticeMeasurement, rowMeasurement, noticeHeight: 28 });
      const intendedScrollTop = f.shell.scrollTop;
      f.render();
      f.render();
      assert.equal(f.shell.scrollTop, intendedScrollTop);
      assert.ok(Number.isFinite(f.shell.scrollTop));
      assert.ok(f.scrollWrites.every(Number.isFinite));
      assert.ok(f.renders <= 4, "unavailable measurements cannot continually trigger corrections");
      assert.match(f.body.innerHTML, /ws-frame-window-row/);
      assert.match(f.body.innerHTML, /history-row frame-selected/);
    });
  }
}

test("a missing scroll shell still renders the frame table without inventing scroll geometry", () => {
  const f = createFixture({ missingShell: true, scrollTop: 777 });
  f.render();
  assert.equal(f.shell.scrollTop, 777);
  assert.match(f.body.innerHTML, /history-row frame-selected/);
  assert.ok(f.renders <= 3);
});

test("zero viewport and unavailable row bounds preserve known scroll instead of clamping to a fallback viewport", () => {
  const f = createFixture({
    viewportHeight: 0, headerHeight: 0, scrollTop: 55000,
    noticeMeasurement: "zero", rowMeasurement: "zero",
  });
  f.render();
  // Unavailable-geometry robustness only; this fixture is not a hidden browser.
  assert.equal(f.shell.scrollTop, 55000);
  assert.ok(f.renders <= 3);
});

test("absence of a selected frame session leaves the existing display and scroll alone", () => {
  const f = createFixture({ scrollTop: 777 });
  f.state.selectedWebsocketRecord = null;
  f.render();
  assert.equal(f.shell.scrollTop, 777);
  assert.equal(f.renders, 0);
});
