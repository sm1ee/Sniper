// Replay tab bar: the pinned row, pinning by drag, and drops on wrapped lines.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const box = (left, top, width = 100, height = 20) =>
  ({ left, top, width, height, right: left + width, bottom: top + height });
const element = (id, rect) => ({ dataset: { replayTabId: id }, getBoundingClientRect: () => rect });

function dragFixture(ids, pinnedIds) {
  const tabs = ids.map((id) => ({ id, pinned: pinnedIds.includes(id) }));
  const calls = { persisted: [], saves: 0 };
  const context = loadFunctions(["commitReplayTabDrag", "moveReplayTabBeside", "replayTabById"], {
    state: { replayTabs: tabs },
    els: {},
    clearReplayTabDropSlot() {},
    renderReplayTabs() {},
    persistReplayTabMetadataEdit: (tab, field, previous) => calls.persisted.push([tab.id, field, previous]),
    scheduleWorkspaceStateSave: () => calls.saves++,
  });
  // Drops the dragged tab's slot into a row between two neighbours (or none).
  const drop = (draggedId, row, beforeId, afterId) => {
    const slot = {
      parentElement: { dataset: { replayTabRow: row } },
      previousElementSibling: beforeId ? { dataset: { replayTabId: beforeId } } : null,
      nextElementSibling: afterId ? { dataset: { replayTabId: afterId } } : null,
    };
    context.els.replayTabStrip = { querySelector: () => slot };
    vmSet(context, "replayTabDragId", draggedId);
    context.commitReplayTabDrag();
  };
  const order = () => context.state.replayTabs.map((tab) => tab.id);
  return { context, tabs, calls, drop, order };
}

// `let` bindings in a vm context are not properties of it.
function vmSet(context, name, value) {
  require("node:vm").runInContext(`var ${name} = ${JSON.stringify(value)};`, context);
}

test("dragging a tab onto the pinned row pins it through the pin button's save path", () => {
  const f = dragFixture(["p", "a", "b"], ["p"]);
  f.drop("b", "pinned", "p", null);
  assert.deepEqual(f.order(), ["p", "b", "a"]);
  assert.equal(f.tabs.find((tab) => tab.id === "b").pinned, true);
  assert.deepEqual(f.calls.persisted, [["b", "pinned", false]]);
  assert.equal(f.calls.saves, 0);
});

test("dragging a pinned tab onto the tab row unpins it where it was dropped", () => {
  const f = dragFixture(["p", "q", "a", "b"], ["p", "q"]);
  f.drop("p", "tabs", "a", "b");
  assert.deepEqual(f.order(), ["q", "a", "p", "b"]);
  assert.equal(f.tabs.find((tab) => tab.id === "p").pinned, false);
  assert.deepEqual(f.calls.persisted, [["p", "pinned", true]]);
});

test("dropping on an empty pinned row pins without moving, and a same-row drag only reorders", () => {
  const f = dragFixture(["a", "b", "c"], []);
  f.drop("c", "pinned", null, null);
  assert.deepEqual(f.order(), ["a", "b", "c"]);
  assert.deepEqual(f.calls.persisted, [["c", "pinned", false]]);
  f.drop("a", "tabs", "b", null);
  assert.deepEqual(f.order(), ["b", "a", "c"]);
  assert.equal(f.calls.persisted.length, 1);
  assert.equal(f.calls.saves, 1);
});

test("the drop anchor follows the pointer across wrapped lines", () => {
  const { replayTabDropAnchor } = loadFunctions(["replayTabDropAnchor"]);
  const a = element("a", box(0, 0)), b = element("b", box(100, 0)), c = element("c", box(0, 30));
  const slot = element("slot", box(200, 0));
  const row = { querySelectorAll: () => [a, slot, b, c] };
  const at = (clientX, clientY) => replayTabDropAnchor(row, slot, { clientX, clientY });
  assert.equal(at(30, 40), c, "left of the second line's first tab");
  assert.equal(at(150, 40), null, "past the last tab on the last line");
  assert.equal(at(120, 10), b, "first line, left of b's middle");
  assert.equal(at(180, 10), c, "end of the first line comes before the second");
  assert.equal(at(120, -50), b, "the bar's top padding lands on the first line");
  assert.equal(at(120, 400), null, "below every line lands on the last");
  const single = { querySelectorAll: () => [a, b] };
  assert.equal(replayTabDropAnchor(single, slot, { clientX: 500, clientY: 10 }), null, "over the + button");
  assert.equal(replayTabDropAnchor({ querySelectorAll: () => [] }, slot, { clientX: 0, clientY: 0 }), null);
});

test("the drop row splits stacked rows by height and a side pin zone by width", () => {
  const rows = [];
  const { replayTabDropRow } = loadFunctions(["replayTabDropRow"], {
    els: { replayTabStrip: { querySelectorAll: () => rows } },
  });
  const [pinned, tabs] = [element("pinned", null), element("tabs", null)];
  const layout = (pinnedBox, tabsBox) => {
    pinned.getBoundingClientRect = () => pinnedBox;
    tabs.getBoundingClientRect = () => tabsBox;
    rows.splice(0, rows.length, pinned, tabs);
  };
  layout(box(0, 0, 300, 26), box(0, 32, 300, 26));
  assert.equal(replayTabDropRow({ clientX: 10, clientY: 10 }), pinned);
  assert.equal(replayTabDropRow({ clientX: 10, clientY: 40 }), tabs);
  layout(box(0, 0, 96, 26), box(102, 0, 200, 26));
  assert.equal(replayTabDropRow({ clientX: 50, clientY: 10 }), pinned);
  assert.equal(replayTabDropRow({ clientX: 200, clientY: 10 }), tabs);
  layout(box(0, 0, 0, 0), box(0, 0, 300, 26));
  assert.equal(replayTabDropRow({ clientX: 0, clientY: 0 }), tabs, "hidden pinned row");
});

test("pinned tabs render on their own row, which renders empty when nothing is pinned", () => {
  let markup = "";
  const state = {
    replayTabs: [{ id: "a", pinned: false }, { id: "p", pinned: true }],
    activeReplayTabId: "a", replayRenamingTabId: null,
  };
  const context = loadFunctions(["renderReplayTabs", "getReplayTabVisualOrder"], {
    state,
    els: { replayTabStrip: { set innerHTML(value) { markup = value; }, querySelectorAll: () => [], classList: { toggle() {} } } },
    replayTabAutoLabel: (tab) => tab.id, replayTabLabel: (tab) => tab.id,
    replayTabTooltipLabel: (tab, label) => label, escapeHtml: String,
    scrollActiveReplayTabIntoView() {}, document: { activeElement: null },
  });
  context.renderReplayTabs();
  const rows = markup.match(/<div class="replay-tab-list[^"]*" data-replay-tab-row="(\w+)"[^>]*>/g);
  assert.equal(rows.length, 2);
  const [pinnedRow, tabRow] = markup.split('data-replay-tab-row="tabs"');
  assert.match(pinnedRow, /data-replay-tab-id="p"/);
  assert.doesNotMatch(pinnedRow, /data-replay-tab-id="a"/);
  assert.match(tabRow, /data-replay-tab-id="a"/);
  state.replayTabs[1].pinned = false;
  context.renderReplayTabs();
  assert.match(markup, /data-replay-tab-row="pinned" aria-label="Pinned tabs"><\/div>/, "empty, so :empty hides it");
});

// One tab, pinned: the pinned row took its own line and + and the gear sat
// alone on a second, empty one.
test("with every tab pinned, the pinned row shares its line with + and the gear", () => {
  const classes = new Set();
  const state = { replayTabs: [{ id: "p", pinned: true }], activeReplayTabId: "p", replayRenamingTabId: null };
  const context = loadFunctions(["renderReplayTabs", "getReplayTabVisualOrder"], {
    state,
    els: { replayTabStrip: {
      set innerHTML(_value) {}, querySelectorAll: () => [],
      classList: { toggle: (name, force) => (force ? classes.add(name) : classes.delete(name)) },
    } },
    replayTabAutoLabel: (tab) => tab.id, replayTabLabel: (tab) => tab.id,
    replayTabTooltipLabel: (tab, label) => label, escapeHtml: String,
    scrollActiveReplayTabIntoView() {}, document: { activeElement: null },
  });
  context.renderReplayTabs();
  assert.ok(classes.has("all-pinned"));
  state.replayTabs.push({ id: "a", pinned: false });
  context.renderReplayTabs();
  assert.ok(!classes.has("all-pinned"), "a tab row of its own starts the second line again");
  state.replayTabs = [];
  context.renderReplayTabs();
  assert.ok(!classes.has("all-pinned"), "no tabs at all");
  const css = require("node:fs").readFileSync(require("node:path").join(__dirname, "../web/styles.css"), "utf8");
  assert.match(css, /\.replay-tab-rows\.all-pinned > \.replay-tab-list-pinned \{[^}]*flex: 0 1 auto;/);
});

// Selecting a tab rebuilt the rows, which came back scrolled to their start,
// and revealing the active tab from there pushed one already in view to the
// far edge of the strip.
test("a re-render keeps each row where it was scrolled and reveals the active tab from there", () => {
  const scrolled = (scrollLeft, scrollTop) => ({ scrollLeft, scrollTop });
  let rows = [scrolled(40, 0), scrolled(900, 30)];
  const revealedFrom = [];
  const state = {
    replayTabs: [{ id: "a", pinned: false }, { id: "b", pinned: false }],
    activeReplayTabId: "b", replayRenamingTabId: null,
  };
  const context = loadFunctions(["renderReplayTabs", "getReplayTabVisualOrder"], {
    state,
    els: { replayTabStrip: {
      // Like the real innerHTML, both rows come back new and at their start.
      set innerHTML(_value) { rows = [scrolled(0, 0), scrolled(0, 0)]; },
      querySelectorAll: (selector) => (selector === ".replay-tab-list" ? rows : []),
      classList: { toggle() {} },
    } },
    replayTabAutoLabel: (tab) => tab.id, replayTabLabel: (tab) => tab.id,
    replayTabTooltipLabel: (tab, label) => label, escapeHtml: String,
    scrollActiveReplayTabIntoView: () => revealedFrom.push(rows.map((row) => ({ ...row }))),
    document: { activeElement: null },
  });
  context.renderReplayTabs();
  assert.deepEqual(revealedFrom, [[scrolled(40, 0), scrolled(900, 30)]]);
  context.renderReplayTabs({ keepScroll: true });
  assert.equal(revealedFrom.length, 1, "a reorder does not reveal the active tab");
  assert.deepEqual(rows, [scrolled(40, 0), scrolled(900, 30)], "the wrapped view's vertical scroll too");
});
