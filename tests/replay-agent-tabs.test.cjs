// Tabs sniper-cli opened sit in a blue row of their own, each named with who
// opened it (Claude, Codex, or CLI). A person can take one out, by dragging it
// to another row or pinning it, but cannot put a tab in. A person's tab the CLI
// changed shows a dot, saying who changed it, until selected.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { loadFunctions } = require("./frontend-test-helpers.cjs");
const { fixture } = require("./replay-workspace-fixture.cjs");

const box = (left, top, width = 300, height = 26) =>
  ({ left, top, width, height, right: left + width, bottom: top + height });
const row = (name, rect) => ({ dataset: { replayTabRow: name }, getBoundingClientRect: () => rect });

test("the rows run pinned, an agent's, then the rest", () => {
  const { getReplayTabVisualOrder } = loadFunctions(["getReplayTabVisualOrder"], {
    state: { replayTabs: [
      { id: "a" }, { id: "g", openedBy: "Claude" }, { id: "p", pinned: true }, { id: "b" },
      { id: "gp", openedBy: "Claude", pinned: true },
    ] },
  });
  assert.deepEqual([...getReplayTabVisualOrder().map((tab) => tab.id)], ["p", "gp", "g", "a", "b"]);
});

test("the CLI's tabs render on a row of their own under who opened them, and a person's tab it changed shows a dot", () => {
  let markup = "";
  const state = {
    replayTabs: [{ id: "a", changedBy: "Codex" }, { id: "g", openedBy: "Claude" }, { id: "x", openedBy: '<b "x">' }],
    activeReplayTabId: "a", replayRenamingTabId: null,
  };
  const context = loadFunctions(["renderReplayTabs", "getReplayTabVisualOrder", "escapeHtml"], {
    state,
    els: { replayTabStrip: { set innerHTML(value) { markup = value; }, querySelectorAll: () => [], classList: { toggle() {} } } },
    replayTabAutoLabel: (tab) => tab.id, replayTabLabel: (tab) => tab.id,
    replayTabTooltipLabel: (tab, label) => label,
    scrollActiveReplayTabIntoView() {}, document: { activeElement: null },
  });
  context.renderReplayTabs();
  assert.deepEqual([...markup.matchAll(/data-replay-tab-row="(\w+)"/g)].map((match) => match[1]), ["pinned", "agent", "tabs"]);
  const agentRow = markup.split('data-replay-tab-row="agent"')[1].split('data-replay-tab-row="tabs"')[0];
  assert.match(agentRow, /data-replay-tab-id="g"/);
  assert.doesNotMatch(agentRow, /data-replay-tab-id="a"/);
  const tabMarkup = (id) => markup.split(`data-replay-tab-id="${id}"`)[1].split("</div>")[0];
  assert.match(tabMarkup("a"), /class="replay-tab-agent-dot" role="img" aria-label="Changed by Codex" title="Changed by Codex"/);
  assert.doesNotMatch(tabMarkup("a"), /data-actor/, "a person's tab names no one");
  assert.match(tabMarkup("g"), /<button class="replay-tab-button"[^>]* data-actor="Claude"/);
  assert.doesNotMatch(tabMarkup("g"), /replay-tab-agent-dot/, "its own tab needs no dot");
  assert.match(tabMarkup("x"), /data-actor="&lt;b &quot;x&quot;&gt;"/, "a name is text");
  state.replayTabs.forEach((tab) => { tab.openedBy = null; });
  context.renderReplayTabs();
  assert.match(markup, /data-replay-tab-row="agent" aria-label="Opened from sniper-cli"><\/div>/, "empty, so :empty hides it");
});

// A tab that is not selected shows no pin button: an invisible one would sit
// in front of the name as empty space.
test("only the selected tab and a pinned one hold a pin button", () => {
  const css = require("node:fs").readFileSync(require("node:path").join(__dirname, "../web/styles.css"), "utf8");
  assert.match(css, /\.replay-tab-pin-btn\.idle \{\s*display: none;\s*\}/);
  assert.doesNotMatch(css, /:hover \.replay-tab-pin-btn\.idle/);
  assert.match(css, /\.replay-tab-button\[data-actor\]::before \{[^}]*content: attr\(data-actor\);/);
});

// A pin sits before the name the way the name of who opened a tab does, with
// no line between them.
test("no line separates a tab's pin from its name", () => {
  const css = require("node:fs").readFileSync(require("node:path").join(__dirname, "../web/styles.css"), "utf8");
  const rule = css.match(/\n\.replay-tab-pin-btn \{([^}]*)\}/)[1];
  assert.doesNotMatch(rule, /border-right/);
});

// An agent opened every tab: the agent's row would take a line and leave +
// and the gear alone on a second, empty one.
test("with no tab of the person's, the agent's row shares its line with + and the gear", () => {
  const classes = new Set();
  const state = { replayTabs: [{ id: "p", pinned: true }, { id: "g", openedBy: "Claude" }],
    activeReplayTabId: "g", replayRenamingTabId: null };
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
  assert.deepEqual([...classes], ["agent-last"], "the pinned row keeps a line of its own");
  state.replayTabs.push({ id: "a" });
  context.renderReplayTabs();
  assert.deepEqual([...classes], []);
  const css = require("node:fs").readFileSync(require("node:path").join(__dirname, "../web/styles.css"), "utf8");
  assert.match(css, /\.replay-tab-rows\.agent-last > \.replay-tab-list-agent \{[^}]*flex: 0 1 auto;/);
});

test("a person's tab cannot be put among an agent's, but an agent's can stay there", () => {
  const rows = [row("pinned", box(0, 0, 0, 0)), row("agent", box(0, 0)), row("tabs", box(0, 32))];
  const context = loadFunctions(["replayTabDropRow", "replayTabById"], {
    state: { replayTabs: [{ id: "g", openedBy: "Claude" }, { id: "a" }] },
    els: { replayTabStrip: { querySelectorAll: () => rows } },
  });
  vm.runInContext('var replayTabDragId = "g";', context);
  assert.equal(context.replayTabDropRow({ clientX: 10, clientY: 10 }).dataset.replayTabRow, "agent");
  assert.equal(context.replayTabDropRow({ clientX: 10, clientY: 40 }).dataset.replayTabRow, "tabs");
  vm.runInContext('var replayTabDragId = "a";', context);
  assert.equal(context.replayTabDropRow({ clientX: 10, clientY: 10 }).dataset.replayTabRow, "tabs");
});

function drop(tabs, draggedId, rowName) {
  const calls = { persisted: [], saves: 0 };
  const context = loadFunctions(["commitReplayTabDrag", "moveReplayTabBeside", "replayTabById"], {
    state: { replayTabs: tabs }, els: {},
    clearReplayTabDropSlot() {}, renderReplayTabs() {},
    persistReplayTabMetadataEdit: (tab, field, previous) => calls.persisted.push([tab.id, field, previous]),
    scheduleWorkspaceStateSave: () => calls.saves++,
  });
  const slot = { parentElement: { dataset: { replayTabRow: rowName } }, previousElementSibling: null, nextElementSibling: null };
  context.els.replayTabStrip = { querySelector: () => slot };
  vm.runInContext(`var replayTabDragId = ${JSON.stringify(draggedId)};`, context);
  context.commitReplayTabDrag();
  return calls;
}

test("dragging the CLI's tab out of its row makes it the person's", () => {
  const out = [{ id: "g", openedBy: "Claude" }, { id: "a" }];
  const calls = drop(out, "g", "tabs");
  assert.equal(out[0].openedBy, null);
  assert.equal(calls.saves, 1);
  const pinned = [{ id: "g", openedBy: "Claude" }];
  drop(pinned, "g", "pinned");
  assert.equal(pinned[0].pinned, true);
  assert.equal(pinned[0].openedBy, null);
  const stays = [{ id: "g", openedBy: "Claude" }];
  drop(stays, "g", "agent");
  assert.equal(stays[0].openedBy, "Claude");
});

test("pinning an agent's tab makes it the person's", () => {
  const tab = { id: "g", openedBy: "Claude" };
  const { toggleReplayTabPin } = loadFunctions(["toggleReplayTabPin"], {
    state: { replayTabs: [tab] }, persistReplayTabMetadataEdit() {}, renderReplayTabs() {},
  });
  toggleReplayTabPin("g");
  assert.equal(tab.pinned, true);
  assert.equal(tab.openedBy, null);
});

test("the tab in front of the person loses its dot, and that is saved", () => {
  let markup = "";
  let saves = 0;
  const state = {
    replayTabs: [{ id: "a", changedBy: "Codex" }, { id: "b", changedBy: "Codex" }],
    activeReplayTabId: "a", replayRenamingTabId: null, activeTool: "history",
  };
  const context = loadFunctions(["renderReplayTabs", "getReplayTabVisualOrder"], {
    state, scheduleWorkspaceStateSave: () => saves++,
    els: { replayTabStrip: { set innerHTML(value) { markup = value; }, querySelectorAll: () => [], classList: { toggle() {} } } },
    replayTabAutoLabel: (tab) => tab.id, replayTabLabel: (tab) => tab.id,
    replayTabTooltipLabel: (tab, label) => label, escapeHtml: String,
    scrollActiveReplayTabIntoView() {}, document: { activeElement: null },
  });
  context.renderReplayTabs();
  assert.equal(state.replayTabs[0].changedBy, "Codex", "Replay is not on screen");
  state.activeTool = "replay";
  context.renderReplayTabs();
  assert.equal(state.replayTabs[0].changedBy, null);
  assert.equal(state.replayTabs[1].changedBy, "Codex", "only the tab in front");
  assert.equal(saves, 1);
  assert.equal((markup.match(/replay-tab-agent-dot/g) || []).length, 1);
});

test("a person's tab hovering over the agent's row stays with the rest; pinned, agent and pin zone split by line", () => {
  const rows = [];
  const context = loadFunctions(["replayTabDropRow", "replayTabById"], {
    state: { replayTabs: [{ id: "g", openedBy: "Claude" }, { id: "a" }] },
    els: { replayTabStrip: { querySelectorAll: () => rows } },
  });
  const named = (event) => context.replayTabDropRow(event).dataset.replayTabRow;
  // Nothing pinned while dragging: the agent's row above, the pin zone opened
  // at the head of the tabs' line.
  rows.splice(0, rows.length, row("pinned", box(0, 40, 96, 26)), row("agent", box(0, 0, 400, 32)),
    row("tabs", box(102, 37, 200, 32)));
  vm.runInContext('var replayTabDragId = "g";', context);
  assert.equal(named({ clientX: 10, clientY: 10 }), "agent");
  assert.equal(named({ clientX: 10, clientY: 50 }), "pinned");
  assert.equal(named({ clientX: 200, clientY: 50 }), "tabs");
  vm.runInContext('var replayTabDragId = "a";', context);
  assert.equal(named({ clientX: 200, clientY: 10 }), "tabs");
  // Only the agent's tabs and a pinned one: the agent's row shares its line
  // with the empty tab row.
  rows.splice(0, rows.length, row("pinned", box(0, 0, 400, 32)), row("agent", box(0, 40, 200, 32)),
    row("tabs", box(206, 53, 120, 6)));
  vm.runInContext('var replayTabDragId = "g";', context);
  assert.equal(named({ clientX: 100, clientY: 50 }), "agent");
  assert.equal(named({ clientX: 300, clientY: 50 }), "tabs");
  assert.equal(named({ clientX: 300, clientY: 10 }), "pinned");
});

test("the CLI's marks arrive with the saved workspace and go back out with the next save", async () => {
  const f = fixture();
  const mine = f.tab("mine");
  f.seed([mine]);
  const snapshot = f.remote([mine], 12);
  snapshot.replay.tabs[0].changed_by = "Codex";
  snapshot.replay.tabs.push({ ...snapshot.replay.tabs[0], id: "opened-by-claude", sequence: 9,
    custom_label: "claude", changed_by: null, opened_by: "Claude" });
  await f.adopt(snapshot);
  assert.equal(mine.changedBy, "Codex");
  const opened = f.state.replayTabs.find((tab) => tab.id === "opened-by-claude");
  assert.equal(opened.openedBy, "Claude");
  assert.equal(f.context.snapshotHttpReplayTab(mine).changed_by, "Codex");
  assert.equal(f.context.snapshotHttpReplayTab(mine).opened_by, null, "an unset mark is written as null");
  assert.equal(f.context.snapshotHttpReplayTab(opened).opened_by, "Claude");
});
