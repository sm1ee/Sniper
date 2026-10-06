const assert = require("node:assert/strict");
const test = require("node:test");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const constants = Object.fromEntries(Array.from(appSource.matchAll(
  /^const (WEBSOCKET_(?:MAX_RENDERED_(?:SESSION|FRAME)_ROWS|(?:SESSION|FRAME)_(?:ROW_HEIGHT|BUFFER_ROWS))) = (\d+);$/gm,
), ([, name, value]) => [name, Number(value)]));

function createFixture(kind, { headerHeight = 27, leadingHeight = 0, rowCount = 2000, scrollTop } = {}) {
  const rowHeight = 27;
  const viewportHeight = 300;
  const bottom = Math.max(0, headerHeight + leadingHeight + rowCount * rowHeight - viewportHeight);
  const shell = { clientHeight: viewportHeight, scrollTop: scrollTop ?? bottom };
  const table = {
    closest: () => shell,
    tHead: headerHeight ? { getBoundingClientRect: () => ({ height: headerHeight }) } : null,
  };
  const context = loadFunctions([
    "websocketRenderedSessionWindow", "websocketRenderedFrameWindow", "websocketFramesShell",
  ], {
    ...constants,
    document: { querySelector: () => table },
    els: { websocketFramesBody: { closest: (selector) => selector === "table" ? table : shell } },
    measuredWebsocketSessionRowHeight: rowHeight,
    measuredWebsocketFrameRowHeight: rowHeight,
  });
  const rows = Array.from({ length: rowCount }, (_, index) => ({ index }));
  const render = () => kind === "sessions"
    ? context.websocketRenderedSessionWindow(rows)
    : context.websocketRenderedFrameWindow(rows, { leadingHeight });
  return { shell, bottom, render };
}

for (const kind of ["sessions", "frames"]) {
  for (const headerHeight of [27, 38]) {
    test(`the last ${kind} row remains fully visible with a ${headerHeight}px header`, () => {
      const { shell, bottom, render } = createFixture(kind, { headerHeight });
      const result = render();
      assert.equal(shell.scrollTop, bottom);
      assert.equal(result.endIdx, 2000);
      assert.equal(result.bottomPadding, 0);
      render();
      assert.equal(shell.scrollTop, bottom, "repeated renders must not pull the viewport up");
    });
  }

  test(`${kind} clamp stale scroll after the window becomes shorter`, () => {
    const { shell, bottom, render } = createFixture(kind, { scrollTop: 100000 });
    render();
    assert.equal(shell.scrollTop, bottom);
  });

  test(`${kind} preserve headerless geometry`, () => {
    const { shell, bottom, render } = createFixture(kind, { headerHeight: 0 });
    render();
    assert.equal(shell.scrollTop, bottom);
  });

  test(`${kind} keep short unvirtualized lists unchanged`, () => {
    const { shell, render } = createFixture(kind, { rowCount: 5 });
    const result = render();
    assert.equal(shell.scrollTop, 0);
    assert.equal(result.startIdx, 0);
    assert.equal(result.endIdx, 5);
  });
}

test("frame scrolling includes both the header and the older-frame notice", () => {
  const { shell, bottom, render } = createFixture("frames", { headerHeight: 38, leadingHeight: 27 });
  const result = render();
  assert.equal(shell.scrollTop, bottom);
  assert.equal(result.endIdx, 2000);
  assert.equal(result.bottomPadding, 0);
});
