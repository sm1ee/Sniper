// The session list beside the workspace. Synthetic sessions; no API runs.
const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

function element() {
  const classes = new Set();
  const attributes = {};
  return {
    innerHTML: "", title: "",
    classList: {
      toggle(name, force = !classes.has(name)) { if (force) classes.add(name); else classes.delete(name); return force; },
      contains: name => classes.has(name),
      add: name => classes.add(name),
      remove: name => classes.delete(name),
    },
    setAttribute(name, value) { attributes[name] = String(value); },
    getAttribute: name => attributes[name] ?? null,
    querySelector: () => null,
    querySelectorAll: () => [],
  };
}

const session = (id, created, extra = {}) => ({
  id, name: `Session ${id}`, created_at: `2026-11-${created}T09:00:00Z`, active: false, ...extra,
});

function fixture({ sessions, activeId, hidden = false, names = [], globals = {} }) {
  const state = {
    sessions,
    activeSession: sessions.find(entry => entry.id === activeId) || null,
    sessionSidebarHidden: hidden,
    sessionActivity: new Map(),
    sessionsFinished: new Map(),
    sessionRename: null,
  };
  const els = { sessionSidebar: element(), sessionSidebarToggle: element(), sessionSidebarList: element() };
  const reloads = [];
  const context = loadFunctions(["renderSessionSidebar", "sessionSidebarLayout", "sessionSidebarRow", "sessionIdentity", "applySessionActivity", ...names], {
    state, els, sidebarDrag: null,
    document: { activeElement: null },
    sessionRenameInput: null, sessionSidebarMarkup: "", sessionListRefresh: null, sidebarRenameEdit: null,
    currentSessionId: () => state.activeSession?.id || null,
    escapeHtml: value => String(value).replace(/[&<>"]/g, char => `&#${char.charCodeAt(0)};`),
    wireSessionRenameInput() {},
    renderSessionFeed() {},
    loadSessions: options => { reloads.push(options); return new Promise(() => {}); },
    ...globals,
  });
  return { state, els, context, reloads };
}

const rows = html => [...html.matchAll(/data-id="([^"]+)"/g)].map(match => match[1]);

test("the sidebar lists sessions newest first and marks the open one", () => {
  const f = fixture({
    sessions: [session("old", "01"), session("new", "19"), session("mid", "10", { overview: { scope: ["*.example.com"], scope_count: 1 } })],
    activeId: "mid",
  });
  f.context.renderSessionSidebar();
  const html = f.els.sessionSidebarList.innerHTML;
  assert.deepEqual(rows(html), ["new", "mid", "old"]);
  assert.match(html, /data-id="mid" aria-current="true"/);
  assert.equal((html.match(/aria-current/g) || []).length, 1);
  // Tab enters the list at the open session; arrows move between the rest.
  assert.deepEqual([...html.matchAll(/<button class="session-sidebar-row[^>]* tabindex="(-?\d)"/g)].map(match => match[1]), ["-1", "0", "-1"]);
  assert.match(html, /\*\.example\.com/, "a row names what the session is about");
  assert.equal(f.els.sessionSidebar.classList.contains("hidden"), false);
  assert.equal(f.els.sessionSidebarToggle.getAttribute("aria-expanded"), "true");
  assert.equal(f.els.sessionSidebarToggle.getAttribute("aria-label"), "Hide sessions");
});

test("a row shows what Intercept holds and which jobs run", () => {
  const f = fixture({ sessions: [session("a", "01"), session("b", "02")], activeId: "a" });
  f.context.applySessionActivity([
    { id: "a", name: "Session a", running: [], held: 2 },
    { id: "b", name: "Session b", running: ["fuzzer", "scan"], held: 0 },
  ]);
  const html = f.els.sessionSidebarList.innerHTML;
  const [b, a] = html.split("</li>");
  assert.match(a, /title="2 held in Intercept">2</);
  assert.match(a, /aria-label="Session a, 2 held in Intercept"/);
  assert.match(b, /title="Running: Fuzzer, Scan"/);
  assert.doesNotMatch(b, /held/);
  assert.equal(f.reloads.length, 0, "the same sessions are not read again");
});

test("a job that ends in another session marks it until the session is opened", () => {
  const f = fixture({ sessions: [session("a", "01"), session("b", "02")], activeId: "a" });
  f.context.applySessionActivity([{ id: "a", name: "Session a", running: ["recon"], held: 0 }, { id: "b", name: "Session b", running: ["fuzzer"], held: 0 }]);
  f.context.applySessionActivity([{ id: "a", name: "Session a", running: [], held: 0 }, { id: "b", name: "Session b", running: [], held: 0 }]);
  let [b, a] = f.els.sessionSidebarList.innerHTML.split("</li>");
  assert.match(b, /title="Fuzzer finished"/);
  assert.doesNotMatch(a, /finished/, "a job ending in the open session is seen there");
  // Opening the session is seeing it.
  f.state.activeSession = f.state.sessions.find(entry => entry.id === "b");
  f.context.renderSessionSidebar();
  [b] = f.els.sessionSidebarList.innerHTML.split("</li>");
  assert.doesNotMatch(b, /finished/);
  assert.equal(f.state.sessionsFinished.size, 0);
});

test("sessions created, renamed or deleted elsewhere are read again", () => {
  const f = fixture({ sessions: [session("a", "01")], activeId: "a" });
  f.context.applySessionActivity([{ id: "a", name: "Session a", running: [], held: 0 }, { id: "c", name: "From the CLI", running: [], held: 0 }]);
  assert.deepEqual(f.reloads.map(options => options.preserveWorkspaceOwner), [true]);
  // One read at a time, however often the activity arrives.
  f.context.applySessionActivity([{ id: "a", name: "Renamed", running: [], held: 0 }]);
  assert.equal(f.reloads.length, 1);
});

test("a hidden sidebar draws nothing and its button offers to show it", () => {
  const f = fixture({ sessions: [session("a", "01")], activeId: "a", hidden: true });
  f.context.renderSessionSidebar();
  assert.equal(f.els.sessionSidebar.classList.contains("hidden"), true);
  assert.equal(f.els.sessionSidebarList.innerHTML, "");
  assert.equal(f.els.sessionSidebarToggle.getAttribute("aria-expanded"), "false");
  assert.equal(f.els.sessionSidebarToggle.getAttribute("aria-label"), "Show sessions");
});

test("a rename started while a row has focus leaves the focus in the name field", () => {
  const f = fixture({ sessions: [session("a", "01"), session("b", "02")], activeId: "a" });
  const focused = [];
  const rowA = { classList: { contains: name => name === "session-sidebar-row" }, dataset: { id: "a" }, focus: () => focused.push("row a") };
  f.context.document = { activeElement: rowA };
  f.els.sessionSidebarList.querySelectorAll = () => [rowA];
  f.context.wireSessionRenameInput = () => focused.push("field");
  f.state.sessionRename = { id: "b", draft: "Session b", place: "sidebar", focus: true };
  f.context.renderSessionSidebar();
  assert.equal(focused.at(-1), "field");
});

test("a name being changed in the sidebar is edited there", () => {
  const f = fixture({ sessions: [session("a", "01"), session("b", "02")], activeId: "a" });
  f.state.sessionRename = { id: "b", draft: "Draft <b>", place: "sidebar" };
  f.context.renderSessionSidebar();
  const html = f.els.sessionSidebarList.innerHTML;
  assert.match(html, /<input class="session-name-input session-sidebar-rename"[^>]*value="Draft &#60;b&#62;"/);
  assert.deepEqual(rows(html), ["a"], "the row being renamed is the field");
});

test("a name being typed in the sidebar keeps its field across reads", () => {
  const f = fixture({ sessions: [session("a", "01"), session("b", "02")], activeId: "a" });
  // A redrawn field would lose IME composition and undo.
  f.context.wireSessionRenameInput = () => { f.context.sessionRenameInput = { isConnected: true }; };
  f.state.sessionRename = { id: "b", draft: "Session b", place: "sidebar", focus: true };
  f.context.renderSessionSidebar();
  const drawn = f.els.sessionSidebarList.innerHTML;
  f.state.sessionRename.draft = "Session b2";
  f.context.applySessionActivity([
    { id: "a", name: "Session a", running: ["scan"], held: 1 },
    { id: "b", name: "Session b", running: [], held: 0 },
  ]);
  assert.equal(f.els.sessionSidebarList.innerHTML, drawn);
  // The rows catch up once the rename ends.
  f.state.sessionRename = null;
  f.context.renderSessionSidebar();
  assert.match(f.els.sessionSidebarList.innerHTML, /Running: Scan/);
});

test("opening a session clears its finished mark while the sidebar is put away", () => {
  const f = fixture({ sessions: [session("a", "01"), session("b", "02")], activeId: "b", hidden: true });
  f.state.sessionsFinished.set("b", ["fuzzer"]);
  f.context.renderSessionSidebar();
  assert.equal(f.state.sessionsFinished.has("b"), false);
});

for (const creating of [false, true]) {
  test(`closing the new session field ${creating ? "keeps the name a create already sent" : "discards what was typed"}`, () => {
    const els = { sessionSidebarCreate: element(), sessionSidebarNewButton: element(), sessionSidebarCreateName: { value: "orders-api" } };
    els.sessionSidebarNewButton.classList.add("hidden");
    const context = loadFunctions(["closeSidebarSessionCreate"], { els, sidebarSessionCreating: creating });
    context.closeSidebarSessionCreate();
    // createSession reads the name only after the drafts it saves first.
    assert.equal(els.sessionSidebarCreateName.value, creating ? "orders-api" : "");
    assert.equal(els.sessionSidebarCreate.classList.contains("hidden"), true);
    assert.equal(els.sessionSidebarNewButton.classList.contains("hidden"), false, "the row is back where its field was");
  });
}

test("a session activity read still waiting is not asked again", () => {
  let reads = 0;
  const context = loadFunctions(["loadSessionActivity"], {
    sessionActivityReading: false, applySessionActivity() {},
    fetch: () => { reads += 1; return new Promise(() => {}); },
  });
  context.loadSessionActivity();
  context.loadSessionActivity();
  assert.equal(reads, 1);
});

// A read sent before a port opened can be answered after it, with the session
// still without the port. The read that follows the change was skipped as "one
// is in flight", so the rows showed the old answer for up to three seconds.
test("a read asked for after a change follows the one in flight", async () => {
  const answers = [];
  const applied = [];
  const context = loadFunctions(["loadSessionActivity"], {
    sessionActivityReading: null, applySessionActivity: (rows) => applied.push(rows),
    fetch: () => new Promise((resolve) => answers.push((rows) => resolve({ ok: true, json: async () => rows }))),
  });
  const periodic = context.loadSessionActivity();
  const afterChange = context.loadSessionActivity({ fresh: true });
  assert.equal(answers.length, 1, "one read at a time");
  answers[0]("before the change");
  await periodic;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(answers.length, 2, "the read after the change was not sent");
  answers[1]("after the change");
  await afterChange;
  assert.deepEqual(applied, ["before the change", "after the change"]);
});

// Sessions a person gathered under a name are listed under it, after the ones
// in no group. A folded group shows its name and how many it holds.
const groupHeaders = html => [...html.matchAll(
  /class="session-sidebar-group-toggle" type="button" data-group="([^"]+)" aria-expanded="(true|false)"><span class="session-sidebar-group-name">[^<]*<\/span><\/button>/g,
)].map(match => match.slice(1));

test("grouped sessions are listed under their group, after the ones in none", () => {
  const f = fixture({
    sessions: [session("loose", "01"), session("a1", "05", { group: "acme" }),
      session("b1", "07", { group: "beta" }), session("a2", "09", { group: "acme" })],
    activeId: "loose",
  });
  f.state.sessionGroupsCollapsed = ["beta"];
  f.context.renderSessionSidebar();
  const html = f.els.sessionSidebarList.innerHTML;
  assert.deepEqual(rows(html), ["loose", "a2", "a1"], "a folded group's sessions are not drawn");
  assert.deepEqual(groupHeaders(html), [["acme", "true"], ["beta", "false"]]);
  // A name says what the folder is. How many sessions it holds is not said.
  assert.doesNotMatch(html, /session-sidebar-group-count/);
  assert.ok(html.indexOf('data-id="loose"') < html.indexOf('data-group="acme"'));
});

test("a group folds and unfolds, and the choice is saved", () => {
  let saves = 0;
  const f = fixture({
    sessions: [session("a1", "05", { group: "acme" })], activeId: null,
    names: ["toggleSessionGroup"], globals: { scheduleUiSettingsSave: () => { saves += 1; } },
  });
  f.state.sessionGroupsCollapsed = [];
  f.context.toggleSessionGroup("acme");
  assert.deepEqual([...f.state.sessionGroupsCollapsed], ["acme"]);
  assert.deepEqual(rows(f.els.sessionSidebarList.innerHTML), []);
  f.context.toggleSessionGroup("acme");
  assert.deepEqual([...f.state.sessionGroupsCollapsed], []);
  assert.deepEqual(rows(f.els.sessionSidebarList.innerHTML), ["a1"]);
  assert.equal(saves, 2);
});

// The line under a session's name is what the list's menu chose. The days and
// the count are short and come first, so a long list of domains gives way.
test("a row shows under its name what the list's menu chose", () => {
  // Noon, so the day is the same wherever the test runs.
  const year = new Date().getFullYear();
  const overview = { scope: ["*.example.com"], scope_count: 1, last_captured_at: `${year}-03-09T12:00:00Z` };
  const f = fixture({
    sessions: [session("a", "01", { overview, created_at: `${year}-03-02T12:00:00Z`, request_count: 1204 })], activeId: "a",
  });
  const line = (details) => {
    if (details) f.state.sessionRowDetails = details;
    f.context.renderSessionSidebar();
    return f.els.sessionSidebarList.innerHTML.match(/<span class="session-sidebar-identity" title="([^"]*)">([^<]*)<\/span>/)?.slice(1) ?? null;
  };
  // A list that never chose shows the domains, as it did before there was a choice.
  assert.deepEqual(line(), ["*.example.com", "*.example.com"]);
  assert.deepEqual(line(["domains", "created"]), ["Created Mar 2 · *.example.com", "Mar 2 · *.example.com"]);
  assert.deepEqual(line(["captured"]), ["Last capture Mar 9", "Mar 9"]);
  // Both days read as the span the session was used over.
  assert.deepEqual(line(["domains", "captured", "created", "requests"]),
    ["Created Mar 2 · Last capture Mar 9 · 1,204 requests · *.example.com", "Mar 2 – Mar 9 · 1,204 requests · *.example.com"]);
  assert.match(f.els.sessionSidebarList.innerHTML, /aria-label="Session a, created Mar 2, last capture Mar 9, 1,204 requests"/);
  // The same day is said once, and a session that never captured has only the day it was made.
  f.state.sessions[0].overview.last_captured_at = `${year}-03-02T12:30:00Z`;
  assert.deepEqual(line(["captured", "created"]), ["Created Mar 2 · Last capture Mar 2", "Mar 2"]);
  f.state.sessions[0].overview.last_captured_at = null;
  assert.deepEqual(line(["captured", "created"]), ["Created Mar 2", "Mar 2"]);
  assert.equal(line(["captured"]), null, "a fact the session does not have leaves no line");
  f.state.sessions[0].request_count = 1;
  assert.deepEqual(line(["requests"]), ["1 request", "1 request"]);
  assert.equal(line([]), null, "nothing chosen is a row of one line");
});

test("a day of another year says the year", () => {
  const { sessionDay } = loadFunctions(["sessionDay"], {});
  const now = new Date("2026-11-26T12:00:00Z");
  assert.equal(sessionDay("2026-03-02T12:00:00Z", now), "Mar 2");
  assert.equal(sessionDay("2025-03-02T12:00:00Z", now), "Mar 2, 2025");
  assert.equal(sessionDay(null, now), "");
  assert.equal(sessionDay("not a date", now), "");
});

// The same name a Replay tab carries for who opened it, so the same glyph.
test("a row names who made the session, and one the person made names nobody", () => {
  const f = fixture({ sessions: [session("a", "01", { created_by: "Claude" }), session("b", "02")], activeId: "a" });
  f.context.renderSessionSidebar();
  const [b, a] = f.els.sessionSidebarList.innerHTML.split("</li>");
  assert.match(a, /<span class="session-sidebar-name"><span class="session-actor" data-actor="Claude" title="Made by Claude"><\/span>Session a<\/span>/);
  assert.match(a, /aria-label="Session a, made by Claude"/);
  assert.doesNotMatch(b, /session-actor|made by/);
});

test("a session's menu offers each other group, a new one, and the way out", () => {
  const state = { sessions: [session("a", "01", { group: "acme" }), session("b", "02", { group: "beta" }), session("c", "03")] };
  const context = loadFunctions(["sessionGroupMenuItems"], { state, escapeHtml: value => String(value) });
  const items = html => [...html.matchAll(/data-action="([^"]+)"(?: data-group="([^"]+)")?>([^<]+)</g)].map(match => match.slice(1));
  assert.deepEqual(items(context.sessionGroupMenuItems(state.sessions[0])),
    [["ungroup", undefined, "Move to Default"], ["group", "beta", "Move to beta"], ["new-group", undefined, "New group…"]]);
  assert.deepEqual(items(context.sessionGroupMenuItems(state.sessions[2])),
    [["group", "acme", "Move to acme"], ["group", "beta", "Move to beta"], ["new-group", undefined, "New group…"]]);
  // A group the list keeps is somewhere to move to before a session is in it.
  state.sessionGroupOrder = ["empty", "acme"];
  assert.deepEqual(items(context.sessionGroupMenuItems(state.sessions[0])).map(([, group]) => group).filter(Boolean), ["beta", "empty"]);
});

test("moving a session asks the server, shows its group open, and reads the list again", async () => {
  const requests = [], reads = [];
  const state = { sessionGroupsCollapsed: ["acme", "beta"] };
  const context = loadFunctions(["moveSessionToGroup", "unfoldSessionGroup"], {
    state, encodeURIComponent,
    fetch: async (url, options) => { requests.push([url, options.method, JSON.parse(options.body)]); return { ok: true }; },
    requireOkResponse: async () => {},
    loadSessions: async options => { reads.push({ ...options }); },
    scheduleUiSettingsSave() {},
  });
  await context.moveSessionToGroup("s 1", "acme");
  await context.moveSessionToGroup("s 1", null);
  assert.deepEqual(requests, [["/api/sessions/s%201/group", "POST", { group: "acme" }], ["/api/sessions/s%201/group", "POST", { group: null }]]);
  assert.deepEqual([...state.sessionGroupsCollapsed], ["beta"]);
  assert.deepEqual(reads, [{ preserveWorkspaceOwner: true }, { preserveWorkspaceOwner: true }]);
});

for (const failing of [false, true]) test(`a new group's name ${failing ? "stays in its field when the server refuses it" : "moves the session and closes its field"}`, async () => {
  const moved = [];
  let closed = 0, shown = 0;
  const state = { sessionSidebarHidden: false, sessionGroupOrder: ["beta"] };
  const els = { sessionSidebarGroup: element(), sessionSidebarNewGroupButton: element(),
    sessionSidebarGroupName: { value: "", focus() {}, select() {} } };
  const context = loadFunctions(["openSidebarGroupName", "closeSidebarGroupName", "submitSidebarGroupName", "keepSessionGroup"], {
    els, state, sidebarGroupEdit: null,
    renderSessionSidebar() {}, scheduleUiSettingsSave() {},
    toggleSessionSidebar: () => { shown += 1; state.sessionSidebarHidden = !state.sessionSidebarHidden; },
    closeSidebarSessionCreate: () => { closed += 1; },
    moveSessionToGroup: async (id, group) => { moved.push([id, group]); if (failing) throw new Error("refused"); },
    renameSessionGroup: async (from, to) => { moved.push(["rename", from, to]); },
  });
  els.sessionSidebarGroup.classList.add("hidden");
  context.openSidebarGroupName({ session: "s1" });
  assert.equal(els.sessionSidebarGroup.classList.contains("hidden"), false);
  assert.equal(els.sessionSidebarNewGroupButton.classList.contains("hidden"), true, "the field takes the place of its row");
  assert.equal(closed, 1, "the new-session field gives way: the two look alike");
  els.sessionSidebarGroupName.value = "  acme  ";
  const outcome = await context.submitSidebarGroupName().then(() => "moved", error => error.message);
  assert.deepEqual(moved, [["s1", "acme"]]);
  assert.equal(outcome, failing ? "refused" : "moved");
  // A group a person named is the list's to keep, once a session is in it.
  assert.deepEqual([...state.sessionGroupOrder], failing ? ["beta"] : ["beta", "acme"]);
  assert.equal(els.sessionSidebarGroup.classList.contains("hidden"), !failing);
  assert.equal(els.sessionSidebarNewGroupButton.classList.contains("hidden"), failing, "and gives it back when it closes");
  assert.equal(els.sessionSidebarGroupName.value, failing ? "  acme  " : "");
  // An empty name moves nothing.
  if (!failing) {
    context.openSidebarGroupName({ session: "s1" });
    await context.submitSidebarGroupName();
    assert.equal(moved.length, 1);
    assert.equal(els.sessionSidebarGroup.classList.contains("hidden"), true);
    // The same field renames a group: it opens with the name, and the same
    // name again changes nothing.
    context.openSidebarGroupName({ group: "acme" });
    assert.equal(els.sessionSidebarGroupName.value, "acme");
    await context.submitSidebarGroupName();
    context.openSidebarGroupName({ group: "acme" });
    els.sessionSidebarGroupName.value = " lab ";
    await context.submitSidebarGroupName();
    assert.deepEqual(moved.slice(1), [["rename", "acme", "lab"]]);
    // The field is in the list. A menu on the session page can ask for it
    // while the list is hidden, so the list is shown first.
    assert.equal(shown, 0, "a list on screen is left as it is");
    state.sessionSidebarHidden = true;
    context.openSidebarGroupName({ session: "s1" });
    assert.equal(shown, 1);
    assert.equal(state.sessionSidebarHidden, false);
  }
});

// ── dragging ──
// The list keeps the order a person dragged it into. What was never dragged
// keeps the order it had: a session newest first and ahead of the dragged
// ones, so a new session shows at the top; a group by name, after them.
test("the list is drawn in the order sessions and groups were dragged into", () => {
  const f = fixture({
    sessions: [session("a", "01"), session("b", "02"), session("c", "03"), session("new", "09"),
      session("x1", "04", { group: "xeno" }), session("m1", "05", { group: "mid" }), session("a1", "06", { group: "acme" })],
    activeId: "a",
  });
  f.state.sessionOrder = ["a", "c", "b", "gone"];
  f.state.sessionGroupOrder = ["xeno"];
  f.context.renderSessionSidebar();
  const html = f.els.sessionSidebarList.innerHTML;
  assert.deepEqual(rows(html), ["new", "a", "c", "b", "x1", "a1", "m1"]);
  assert.deepEqual(groupHeaders(html).map(([name]) => name), ["xeno", "acme", "mid"]);
});

test("a row and a group can be dragged, a name being edited cannot", () => {
  const f = fixture({ sessions: [session("a", "01"), session("b", "02", { group: "acme" })], activeId: "a" });
  f.state.sessionRename = { id: "a", place: "sidebar", draft: "x" };
  f.context.renderSessionSidebar();
  const html = f.els.sessionSidebarList.innerHTML;
  assert.match(html, /<li draggable="true" data-drag-session="b"><button class="session-sidebar-row/);
  assert.match(html, /<li class="session-sidebar-group" draggable="true" data-drag-group="acme">/);
  assert.match(html, /<li><input class="session-name-input session-sidebar-rename"/);
});

test("a render waits while something is dragged, so the dragged row stays", () => {
  const f = fixture({ sessions: [session("a", "01")], activeId: "a" });
  f.context.renderSessionSidebar();
  const drawn = f.els.sessionSidebarList.innerHTML;
  f.context.sidebarDrag = { session: "a" };
  f.state.sessions = [session("a", "01"), session("b", "02")];
  f.context.renderSessionSidebar();
  assert.equal(f.els.sessionSidebarList.innerHTML, drawn);
});

test("ids are put before or after the one they are dropped on", () => {
  const { reorderedIds } = loadFunctions(["reorderedIds"], {});
  assert.deepEqual([...reorderedIds(["a", "b", "c"], "c", "a", false)], ["c", "a", "b"]);
  assert.deepEqual([...reorderedIds(["a", "b", "c"], "a", "b", true)], ["b", "a", "c"]);
  assert.deepEqual([...reorderedIds(["a", "b"], "new", "b", true)], ["a", "b", "new"]);
  assert.deepEqual([...reorderedIds(["a", "b"], "new", "gone", false)], ["a", "b", "new"]);
});

function dropFixture(sessions) {
  const moved = [], renders = [];
  let saves = 0;
  const state = { sessions, sessionOrder: [], sessionGroupOrder: [], sessionPinned: [], sessionSort: "manual" };
  const context = loadFunctions(["dropSidebarSession", "dropSidebarGroup", "sessionSidebarLayout", "reorderedIds"], {
    state,
    moveSessionToGroup: async (id, group) => { moved.push([id, group]); },
    renderSessionSidebar: () => renders.push(1),
    scheduleUiSettingsSave: () => { saves += 1; },
  });
  return { state, context, moved, renders, saves: () => saves };
}

test("a session dropped beside another in its own list changes place, and nothing is asked of the server", async () => {
  // Drawn newest first: c, b, a.
  const f = dropFixture([session("a", "01"), session("b", "02"), session("c", "03"), session("g", "04", { group: "acme" })]);
  await f.context.dropSidebarSession("a", { session: "c", after: false });
  assert.deepEqual([...f.state.sessionOrder], ["a", "c", "b"]);
  await f.context.dropSidebarSession("c", { session: "b", after: true });
  assert.deepEqual([...f.state.sessionOrder], ["a", "b", "c"]);
  assert.deepEqual(f.moved, []);
  assert.equal(f.renders.length, 2);
  assert.equal(f.saves(), 2);
});

test("a session dropped in another group joins it at that place", async () => {
  const f = dropFixture([session("a", "01"), session("g1", "04", { group: "acme" }), session("g2", "05", { group: "acme" })]);
  f.state.sessionOrder = ["a", "deleted"];
  // acme is drawn g2, g1.
  await f.context.dropSidebarSession("a", { session: "g1", after: false });
  assert.deepEqual(f.moved, [["a", "acme"]]);
  assert.deepEqual([...f.state.sessionOrder], ["g2", "a", "g1"], "a session that is gone leaves the saved order");
  assert.deepEqual(f.moved.slice(1), []);
});

// On a group's name the session is first in that group, whatever its age; on
// the list itself it is first among the sessions in no group.
test("a session dropped on a group's name, or on the list, is first there", async () => {
  // acme is drawn new, old: neither was dragged, so by age.
  const f = dropFixture([session("loose", "01"), session("mine", "02"),
    session("old", "03", { group: "acme" }), session("new", "09", { group: "acme" }), session("b1", "05", { group: "beta" })]);
  await f.context.dropSidebarSession("mine", { group: "acme", into: true });
  assert.deepEqual(f.moved, [["mine", "acme"]]);
  assert.deepEqual([...f.state.sessionOrder], ["mine", "new", "old"]);
  await f.context.dropSidebarSession("b1", { group: null, into: true });
  assert.deepEqual(f.moved[1], ["b1", null]);
  // The move here is a stub, so "mine" is still drawn in no group: after
  // "loose", which was never dragged.
  assert.deepEqual([...f.state.sessionOrder].slice(-3), ["b1", "loose", "mine"]);
});

test("a group dropped beside another changes place among the groups", () => {
  const f = dropFixture([session("a1", "01", { group: "acme" }), session("b1", "02", { group: "beta" }), session("c1", "03", { group: "core" })]);
  f.context.dropSidebarGroup("core", { group: "acme", after: false });
  assert.deepEqual([...f.state.sessionGroupOrder], ["core", "acme", "beta"]);
  f.context.dropSidebarGroup("core", { group: "beta", after: true });
  assert.deepEqual([...f.state.sessionGroupOrder], ["acme", "beta", "core"]);
  assert.equal(f.state.sessionDefaultAfter, "", "Default is still first");
  assert.equal(f.renders.length, 2);
  assert.equal(f.saves(), 2);
});

// Default is a folder among the groups. It is no group, so it is null where a
// group is its name, and what is kept is the group it comes after.
test("a group dropped above Default is above it, and Default is moved as a group is", () => {
  const f = dropFixture([session("l", "01"), session("a1", "02", { group: "acme" }), session("b1", "03", { group: "beta" })]);
  // Drawn Default, acme, beta.
  f.context.dropSidebarGroup("beta", { group: null, after: false });
  assert.deepEqual([...f.state.sessionGroupOrder], ["beta", "acme"]);
  assert.equal(f.state.sessionDefaultAfter, "beta");
  // Default itself, dropped under the last group, then back above the first.
  f.context.dropSidebarGroup(null, { group: "acme", after: true });
  assert.deepEqual([...f.state.sessionGroupOrder], ["beta", "acme"]);
  assert.equal(f.state.sessionDefaultAfter, "acme");
  f.context.dropSidebarGroup(null, { group: "beta", after: false });
  assert.equal(f.state.sessionDefaultAfter, "");
  // A group moved from below Default to above it leaves Default under both.
  f.state.sessionDefaultAfter = "beta";
  f.context.dropSidebarGroup("acme", { group: "beta", after: false });
  assert.deepEqual([...f.state.sessionGroupOrder], ["acme", "beta"]);
  assert.equal(f.state.sessionDefaultAfter, "beta");
  // The group Default was under, moved below it: Default is under the one before.
  f.context.dropSidebarGroup("beta", { group: null, after: true });
  assert.deepEqual([...f.state.sessionGroupOrder], ["acme", "beta"]);
  assert.equal(f.state.sessionDefaultAfter, "acme");
  assert.equal(f.saves(), 5);
});

// A fake of the two things the target reads from an element: the nearest
// draggable item of each kind, and its box.
function dragElement({ session = null, group = null, pinned = false, inDefault = false, top = 0, height = 20 } = {}) {
  const item = kind => ({ kind, dataset: kind === "session" ? { dragSession: session } : kind === "group" ? { dragGroup: group } : {},
    getBoundingClientRect: () => ({ top, height }) });
  return { closest: selector => (selector === "li[data-drag-session]" ? (session ? item("session") : null)
    : selector === "li[data-drag-group]" ? (group ? item("group") : null)
      : selector === "li[data-drop-pinned]" ? (pinned ? item("pinned") : null)
        : selector === "li[data-drop-default]" ? (inDefault ? item("default") : null) : null) };
}

test("where a drag may land depends on what is dragged", () => {
  const list = {};
  const state = { sessionSort: "manual" };
  const context = loadFunctions(["sidebarDropTarget"], { state, els: { sessionSidebarList: list }, sidebarDrag: null });
  const at = (element, y) => {
    const target = context.sidebarDropTarget({ target: element, clientY: y });
    return target && { ...target, element: target.element === list ? "list" : target.element.kind || "item" };
  };
  assert.equal(at(dragElement({ session: "b" }), 5), null, "nothing is dragged");
  context.sidebarDrag = { session: "a" };
  assert.deepEqual(at(dragElement({ session: "b", group: "acme" }), 5), { element: "session", session: "b", after: false });
  assert.deepEqual(at(dragElement({ session: "b" }), 15), { element: "session", session: "b", after: true });
  assert.equal(at(dragElement({ session: "a" }), 5), null, "not onto itself");
  assert.deepEqual(at(dragElement({ group: "acme" }), 5), { element: "group", group: "acme", into: true });
  assert.deepEqual(at(dragElement(), 5), { element: "list", group: null, into: true });
  // On Default, which is no group: its name, or the space of the list under
  // everything, which marks Default when the list has drawn it.
  assert.deepEqual(at(dragElement({ inDefault: true }), 5), { element: "default", group: null, into: true });
  assert.deepEqual(at(dragElement({ session: "b", inDefault: true }), 5), { element: "session", session: "b", after: false });
  list.querySelector = selector => (selector === "li[data-drop-default]" ? { kind: "default" } : null);
  assert.deepEqual(at(dragElement(), 5), { element: "default", group: null, into: true });
  delete list.querySelector;
  // Among the pinned: beside one of them, or on their block, which is last.
  assert.deepEqual(at(dragElement({ session: "p", pinned: true }), 15), { element: "session", session: "p", after: true, pinned: true });
  assert.deepEqual(at(dragElement({ pinned: true }), 5), { element: "pinned", pinned: true, into: true });
  assert.equal(at(dragElement({ session: "a", pinned: true }), 5), null, "not onto itself");
  // A sorted list has no place beside a session: the drop is into its group.
  state.sessionSort = "name";
  assert.deepEqual(at(dragElement({ session: "b", group: "acme" }), 5), { element: "group", group: "acme", into: true });
  assert.deepEqual(at(dragElement({ session: "b" }), 5), { element: "list", group: null, into: true });
  assert.deepEqual(at(dragElement({ session: "p", pinned: true }), 5), { element: "session", session: "p", after: false, pinned: true },
    "the pinned keep the order they were put in");
  state.sessionSort = "manual";
  context.sidebarDrag = { group: "acme" };
  assert.deepEqual(at(dragElement({ session: "b", group: "beta", height: 40 }), 30), { element: "group", group: "beta", after: true });
  assert.equal(at(dragElement({ session: "b", group: "acme" }), 5), null);
  // Default is a folder among the groups: a group lands beside it, from its
  // name or from a session in it.
  assert.deepEqual(at(dragElement({ inDefault: true, height: 40 }), 5), { element: "default", group: null, after: false });
  assert.deepEqual(at(dragElement({ session: "b", inDefault: true, height: 40 }), 30), { element: "default", group: null, after: true });
  assert.equal(at(dragElement(), 5), null, "a folder has no place on the space under the list");
  assert.equal(at(dragElement({ session: "p", pinned: true }), 5), null, "nor among the pinned");
  // Default is dragged as a group is, and lands beside one.
  context.sidebarDrag = { group: null };
  assert.deepEqual(at(dragElement({ session: "b", group: "beta", height: 40 }), 30), { element: "group", group: "beta", after: true });
  assert.equal(at(dragElement({ session: "b", inDefault: true }), 5), null, "not onto itself");
  assert.equal(at(dragElement({ session: "p", pinned: true }), 5), null);
  // The drag starts on a row, on a group, or on Default, which carries no
  // name; the drop goes by which of the two kinds it was.
  assert.match(appSource, /const item = event\.target\.closest\?\.\("li\[data-drag-session\], li\[data-drag-group\], li\[data-drop-default\]"\);/);
  assert.match(appSource, /sidebarDrag = item\.dataset\.dragSession \? \{ session: item\.dataset\.dragSession \} : \{ group: item\.dataset\.dragGroup \?\? null \};/);
  assert.match(appSource, /if \(drag\.session\) dropSidebarSession\(drag\.session, target\)\.catch\(handleWorkspaceActionError\);\n\s*else dropSidebarGroup\(drag\.group, target\);/);
});

test("renaming a group asks the server once and carries over what was saved for the old name", async () => {
  const requests = [], reads = [];
  const state = { sessionGroupsCollapsed: ["acme", "beta"], sessionGroupOrder: ["beta", "acme"],
    sessions: [session("a", "01", { group: "acme" }), session("l", "02", { group: "lab" })] };
  const context = loadFunctions(["renameSessionGroup"], {
    state,
    fetch: async (url, options) => { requests.push([url, options.method, JSON.parse(options.body)]); return { ok: true }; },
    requireOkResponse: async () => {},
    loadSessions: async options => { reads.push({ ...options }); },
    scheduleUiSettingsSave() {},
  });
  await context.renameSessionGroup("acme", "lab");
  assert.deepEqual(requests, [["/api/session-groups/rename", "POST", { from: "acme", to: "lab" }]]);
  assert.deepEqual([...state.sessionGroupsCollapsed], ["lab", "beta"]);
  assert.deepEqual([...state.sessionGroupOrder], ["beta", "lab"]);
  // With no new name the group ends.
  await context.renameSessionGroup("lab", null);
  assert.deepEqual(requests[1][2], { from: "lab", to: null });
  assert.deepEqual([...state.sessionGroupsCollapsed], ["beta"]);
  assert.deepEqual(reads, [{ preserveWorkspaceOwner: true }, { preserveWorkspaceOwner: true }]);
  // A group no session is in is the list's alone: the server knows no such
  // group, and is not asked.
  await context.renameSessionGroup("beta", "gamma");
  assert.deepEqual([...state.sessionGroupOrder], ["gamma"]);
  await context.renameSessionGroup("gamma", null);
  assert.deepEqual([...state.sessionGroupOrder], []);
  assert.equal(requests.length, 2, "nothing more was asked");
});

test("Default stays under a group that is renamed, and under the one before a group that ends", async () => {
  // Drawn acme, beta, Default, core.
  const state = { sessionGroupsCollapsed: [], sessionGroupOrder: ["acme", "beta", "core"], sessionDefaultAfter: "beta", sessions: [] };
  const context = loadFunctions(["renameSessionGroup"], {
    state, loadSessions: async () => {}, scheduleUiSettingsSave() {},
  });
  await context.renameSessionGroup("beta", "lab");
  assert.equal(state.sessionDefaultAfter, "lab");
  await context.renameSessionGroup("core", null);
  assert.equal(state.sessionDefaultAfter, "lab", "a group under Default ends and Default stays");
  await context.renameSessionGroup("lab", null);
  assert.equal(state.sessionDefaultAfter, "acme");
  await context.renameSessionGroup("acme", null);
  assert.equal(state.sessionDefaultAfter, "", "with no group above it Default is first");
});


// ── pinned, sorted, and groups the list keeps ──
const loose = context => Array.from(context.sessionSidebarLayout().loose, entry => entry.id);

test("pinned sessions are drawn first, in the order pinned, and nowhere else", () => {
  const f = fixture({
    sessions: [session("a", "01"), session("b", "02", { group: "acme" }), session("c", "03"), session("d", "04", { group: "acme" })],
    activeId: "a",
  });
  f.context.renderSessionSidebar();
  assert.doesNotMatch(f.els.sessionSidebarList.innerHTML, /session-sidebar-pinned/, "nothing pinned, no block for it");
  f.state.sessionPinned = ["b", "gone", "a"];
  f.context.renderSessionSidebar();
  const html = f.els.sessionSidebarList.innerHTML;
  assert.match(html, /^<li class="session-sidebar-group session-sidebar-section session-sidebar-pinned" data-drop-pinned><div class="session-sidebar-group-head"><button class="session-sidebar-group-toggle" type="button" data-section="pinned" aria-expanded="true"><span class="session-sidebar-group-name">Pinned<\/span><\/button><\/div><ul class="session-sidebar-group-list">/);
  assert.deepEqual(rows(html), ["b", "a", "c", "d"]);
  assert.deepEqual(rows(html.slice(0, html.indexOf("</ul></li>"))), ["b", "a"]);
  // The folder of a pinned session is drawn without it.
  assert.deepEqual(rows(html.slice(html.indexOf('data-group="acme"'))), ["d"]);
});

test("a group the list keeps is drawn while no session is in it", () => {
  const f = fixture({ sessions: [session("a1", "01", { group: "acme" }), session("z1", "02", { group: "zeta" })], activeId: null });
  f.state.sessionGroupOrder = ["lab", "acme"];
  f.context.renderSessionSidebar();
  assert.deepEqual(groupHeaders(f.els.sessionSidebarList.innerHTML), [["lab", "true"], ["acme", "true"], ["zeta", "true"]]);
});

test("a group's name has a + beside it that makes a session there", () => {
  const f = fixture({ sessions: [session("a1", "01", { group: "a&b" })], activeId: null });
  f.context.renderSessionSidebar();
  assert.match(f.els.sessionSidebarList.innerHTML,
    /<div class="session-sidebar-group-head"><button class="session-sidebar-group-toggle" type="button" data-group="a&#38;b" aria-expanded="true">.*?<\/button><button class="session-sidebar-group-add" type="button" data-add-to-group="a&#38;b" aria-label="New session in a&#38;b" title="New session in a&#38;b">\+<\/button><\/div>/);
});

test("the list can be put in an order of its own, and the dragged order is kept for later", () => {
  const f = fixture({
    sessions: [
      session("old", "01", { name: "delta", created_by: "Codex", overview: { last_captured_at: "2026-11-20T00:00:00Z" } }),
      session("mid", "05", { name: "Bravo", overview: { last_captured_at: "2026-11-22T00:00:00Z" } }),
      session("new", "09", { name: "alpha", created_by: "Claude" }),
      session("own", "07", { name: "Charlie" }),
      session("agent", "03", { name: "echo", created_by: "Claude" }),
    ],
    activeId: null,
  });
  f.state.sessionOrder = ["old", "new", "mid", "own", "agent"];
  f.state.sessionSort = "manual";
  assert.deepEqual(loose(f.context), ["old", "new", "mid", "own", "agent"]);
  f.state.sessionSort = "created";
  assert.deepEqual(loose(f.context), ["new", "own", "mid", "agent", "old"]);
  // What captured last, then what never captured, newest first.
  f.state.sessionSort = "recent";
  assert.deepEqual(loose(f.context), ["mid", "old", "new", "own", "agent"]);
  f.state.sessionSort = "name";
  assert.deepEqual(loose(f.context), ["new", "mid", "own", "old", "agent"]);
  // A person's own first, then each agent's together, newest first.
  f.state.sessionSort = "agent";
  assert.deepEqual(loose(f.context), ["own", "mid", "new", "agent", "old"]);
  // A name this build does not know is the dragged order.
  f.state.sessionSort = "by moon phase";
  assert.deepEqual(loose(f.context), ["old", "new", "mid", "own", "agent"]);
  assert.deepEqual([...f.state.sessionOrder], ["old", "new", "mid", "own", "agent"]);
});

test("a sort orders the sessions of a group, and leaves the pinned and the groups as they were put", () => {
  const f = fixture({
    sessions: [session("b1", "01", { name: "b", group: "zeta" }), session("a1", "02", { name: "a", group: "zeta" }),
      session("p2", "03", { name: "z" }), session("p1", "04", { name: "y" }), session("c1", "05", { name: "c", group: "acme" })],
    activeId: null,
  });
  f.state.sessionSort = "name";
  f.state.sessionPinned = ["p2", "p1"];
  f.state.sessionGroupOrder = ["zeta", "acme"];
  const layout = f.context.sessionSidebarLayout();
  assert.deepEqual(Array.from(layout.pinned, entry => entry.id), ["p2", "p1"]);
  assert.deepEqual(Array.from(layout.groups, ([name, sessions]) => [name, Array.from(sessions, entry => entry.id)]),
    [["zeta", ["a1", "b1"]], ["acme", ["c1"]]]);
});

test("pinning puts a session last among the pinned, and again takes it out", () => {
  let saves = 0;
  const f = fixture({
    sessions: [session("a", "01"), session("b", "02")], activeId: "a",
    names: ["toggleSessionPin"], globals: { scheduleUiSettingsSave: () => { saves += 1; } },
  });
  f.state.sessionPinned = ["deleted", "b"];
  f.context.toggleSessionPin("a");
  assert.deepEqual([...f.state.sessionPinned], ["b", "a"], "a session that is gone leaves the pinned");
  assert.match(f.els.sessionSidebarList.innerHTML, /session-sidebar-pinned/);
  f.context.toggleSessionPin("b");
  assert.deepEqual([...f.state.sessionPinned], ["a"]);
  assert.equal(saves, 2);
});

test("a session dropped among the pinned is pinned at that place, and keeps its group", async () => {
  const f = dropFixture([session("a", "01", { group: "acme" }), session("p1", "02"), session("p2", "03")]);
  f.state.sessionPinned = ["p1", "p2"];
  await f.context.dropSidebarSession("a", { session: "p1", after: true, pinned: true });
  assert.deepEqual([...f.state.sessionPinned], ["p1", "a", "p2"]);
  // On the block itself it is last.
  await f.context.dropSidebarSession("p1", { pinned: true, into: true });
  assert.deepEqual([...f.state.sessionPinned], ["a", "p2", "p1"]);
  assert.deepEqual(f.moved, [], "its group is not asked about");
  assert.deepEqual([...f.state.sessionOrder], [], "nor its place among the others");
  assert.equal(f.renders.length, 2);
  assert.equal(f.saves(), 2);
});

test("a pinned session dropped anywhere else is pinned no more", async () => {
  const f = dropFixture([session("a", "01"), session("b", "02"), session("g", "03", { group: "acme" })]);
  f.state.sessionPinned = ["a", "g"];
  await f.context.dropSidebarSession("a", { session: "b", after: true });
  assert.deepEqual([...f.state.sessionPinned], ["g"]);
  assert.deepEqual([...f.state.sessionOrder], ["b", "a"]);
  assert.deepEqual(f.moved, []);
  // Out of the pinned and out of its group, onto the list.
  await f.context.dropSidebarSession("g", { group: null, into: true });
  assert.deepEqual([...f.state.sessionPinned], []);
  assert.deepEqual(f.moved, [["g", null]]);
});

test("a drop in a sorted list changes the group and leaves the dragged order alone", async () => {
  const f = dropFixture([session("a", "01"), session("g1", "02", { group: "acme" })]);
  f.state.sessionSort = "name";
  f.state.sessionOrder = ["g1", "a"];
  await f.context.dropSidebarSession("a", { group: "acme", into: true });
  assert.deepEqual(f.moved, [["a", "acme"]]);
  assert.deepEqual([...f.state.sessionOrder], ["g1", "a"]);
});

function sortFixture(sort = "manual") {
  const state = { sessionSort: sort, sessionRowDetails: ["domains"] };
  const calls = [];
  const focused = [];
  const menu = { listeners: {}, style: {}, className: "", innerHTML: "", attributes: {},
    setAttribute(name, value) { this.attributes[name] = value; },
    getBoundingClientRect: () => ({ width: 180, height: 200 }),
    querySelector: selector => ({ focus: () => focused.push(selector) }),
    addEventListener(type, handler) { this.listeners[type] = handler; } };
  const context = loadFunctions(["showSessionViewMenu", "setSessionSort", "toggleSessionRowDetail"], {
    state, sessionContextMenuEl: null, closeSessionContextMenu: () => calls.push("closed"),
    document: { createElement: () => menu, body: { appendChild() {} } }, window: { innerWidth: 1200 },
    renderSessionSidebar: () => calls.push("render"), scheduleUiSettingsSave: () => calls.push("save"),
  });
  const anchor = { getBoundingClientRect: () => ({ left: 120, bottom: 32 }) };
  const choose = dataset => menu.listeners.click({ target: { closest: () => ({ dataset }) }, stopPropagation: () => calls.push("held") });
  return { state, calls, menu, context, anchor, choose, focused };
}

// The checks of a menu section: [key, label, aria-checked, marked].
const menuItems = (html, role, key) => [...html.matchAll(new RegExp(
  `<button class="context-menu-item" role="${role}" aria-checked="(true|false)" data-${key}="([a-z]+)">([^<]+)(<span class="context-menu-shortcut" aria-hidden="true">✓</span>)?</button>`, "g",
))].map(match => [match[2], match[3], match[1], Boolean(match[4])]);

test("the list's menu names the orders and marks the one in use", () => {
  const f = sortFixture("name");
  f.context.showSessionViewMenu(f.anchor);
  assert.equal(f.menu.attributes.role, "menu");
  assert.match(f.menu.innerHTML, /^<div class="context-menu-section"><span class="context-menu-label">Sort by<\/span><\/div>/);
  assert.deepEqual(menuItems(f.menu.innerHTML, "menuitemradio", "sort"), [["manual", "Manual order", "false", false], ["recent", "Last capture", "false", false],
    ["created", "Created", "false", false], ["name", "Name", "true", true], ["agent", "Agent", "false", false]]);
  assert.equal(f.menu.style.left, "120px");
  assert.equal(f.menu.style.top, "36px");
  assert.equal(f.context.sessionContextMenuEl, f.menu, "it closes as a session's menu does");
});

test("choosing an order sorts the list and saves the choice", () => {
  const f = sortFixture();
  f.context.showSessionViewMenu(f.anchor);
  f.calls.length = 0;
  f.choose({ sort: "agent" });
  assert.equal(f.state.sessionSort, "agent");
  assert.deepEqual(f.calls, ["render", "save", "closed"]);
});

// Under the orders, what a row says under its name: any of them, or none.
test("the list's menu offers what a row shows under its name, and marks what it shows now", () => {
  const f = sortFixture();
  f.state.sessionRowDetails = ["domains", "created"];
  f.context.showSessionViewMenu(f.anchor);
  const show = f.menu.innerHTML.slice(f.menu.innerHTML.indexOf('data-sort="agent"'));
  assert.match(show, /^data-sort="agent">Agent<\/button><div class="context-menu-section"><span class="context-menu-label">Show<\/span><\/div><button /);
  assert.deepEqual(menuItems(f.menu.innerHTML, "menuitemcheckbox", "show"), [["domains", "Domains", "true", true],
    ["captured", "Last capture", "false", false], ["created", "Created", "true", true], ["requests", "Requests", "false", false]]);
  assert.match(f.menu.innerHTML, /data-show="requests">Requests<\/button>$/, "the orders, what is shown, and nothing else");
});

test("choosing what a row shows keeps the menu open, so more than one can be chosen", () => {
  const f = sortFixture();
  f.context.showSessionViewMenu(f.anchor);
  f.calls.length = 0;
  f.choose({ show: "captured" });
  // Kept in the menu's order, whatever order they were chosen in.
  assert.deepEqual([...f.state.sessionRowDetails], ["domains", "captured"]);
  assert.deepEqual(f.calls, ["held", "render", "save"], "the click does not reach the document, which closes the menu");
  assert.deepEqual(menuItems(f.menu.innerHTML, "menuitemcheckbox", "show").map(([key, , checked]) => [key, checked]),
    [["domains", "true"], ["captured", "true"], ["created", "false"], ["requests", "false"]]);
  assert.deepEqual(f.focused, ['[data-show="captured"]'], "the item chosen from the keyboard keeps the focus");
  f.choose({ show: "domains" });
  f.choose({ show: "captured" });
  assert.deepEqual([...f.state.sessionRowDetails], [], "none is a choice too");
  f.choose({ show: "by moon phase" });
  assert.deepEqual([...f.state.sessionRowDetails], [], "a name the menu does not offer is not kept");
});

test("a group made by name is the list's to keep, and nothing is asked of the server", async () => {
  const state = { sessionSidebarHidden: false, sessionGroupOrder: ["acme"] };
  const calls = [];
  const els = { sessionSidebarGroup: element(), sessionSidebarNewGroupButton: element(),
    sessionSidebarGroupName: { value: "", focus() {}, select() {} } };
  const context = loadFunctions(["openSidebarGroupName", "closeSidebarGroupName", "submitSidebarGroupName", "keepSessionGroup"], {
    els, state, sidebarGroupEdit: null, closeSidebarSessionCreate() {},
    renderSessionSidebar: () => calls.push("render"), scheduleUiSettingsSave: () => calls.push("save"),
    moveSessionToGroup: async () => { assert.fail("no session is moved"); },
    renameSessionGroup: async () => { assert.fail("no group is renamed"); },
  });
  context.openSidebarGroupName({ create: true });
  assert.equal(els.sessionSidebarGroupName.value, "");
  els.sessionSidebarGroupName.value = "  lab ";
  await context.submitSidebarGroupName();
  assert.deepEqual([...state.sessionGroupOrder], ["acme", "lab"]);
  assert.deepEqual(calls, ["render", "save"]);
  assert.equal(els.sessionSidebarGroup.classList.contains("hidden"), true);
  // A name the list already keeps is not kept twice.
  context.openSidebarGroupName({ create: true });
  els.sessionSidebarGroupName.value = "acme";
  await context.submitSidebarGroupName();
  assert.deepEqual([...state.sessionGroupOrder], ["acme", "lab"]);
  assert.equal(calls.length, 2);
});

test("a group's menu ungroups its sessions, or deletes a group that has none", () => {
  const menus = [];
  const state = { sessions: [session("a", "01", { group: "acme" })] };
  const context = loadFunctions(["showSessionGroupMenu"], {
    state, sessionContextMenuEl: null, closeSessionContextMenu() {},
    document: { createElement: () => { const menu = { style: {}, innerHTML: "", addEventListener() {}, getBoundingClientRect: () => ({ width: 10, height: 10 }) }; menus.push(menu); return menu; }, body: { appendChild() {} } },
    window: { innerWidth: 800, innerHeight: 600 },
  });
  const labels = group => { context.showSessionGroupMenu({ clientX: 0, clientY: 0 }, group); return [...menus.at(-1).innerHTML.matchAll(/>([^<]+)<\/button>/g)].map(match => match[1]); };
  assert.deepEqual(labels("acme"), ["Rename group", "Ungroup"]);
  assert.deepEqual(labels("lab"), ["Rename group", "Delete group"]);
});

function createFixture() {
  const state = { sessionGroupsCollapsed: ["acme", "beta"] };
  const created = [];
  let saves = 0;
  const els = { sessionSidebarCreate: element(), sessionSidebarNewButton: element(),
    sessionSidebarCreateName: { value: "", placeholder: "", focused: 0, focus() { this.focused += 1; } } };
  els.sessionSidebarCreate.classList.add("hidden");
  const context = loadFunctions(["openSidebarSessionCreate", "closeSidebarSessionCreate", "createSidebarSession", "unfoldSessionGroup"], {
    state, els, sidebarSessionCreating: false, sidebarCreateGroup: null,
    closeSidebarGroupName() {}, scheduleUiSettingsSave: () => { saves += 1; },
    createSession: async (input, group) => { created.push([input === els.sessionSidebarCreateName, group]); input.value = ""; },
  });
  return { state, els, context, created, saves: () => saves };
}

test("a group's + opens the name field for a session in that group", async () => {
  const f = createFixture();
  f.context.openSidebarSessionCreate("acme");
  assert.equal(f.els.sessionSidebarCreate.classList.contains("hidden"), false);
  assert.equal(f.els.sessionSidebarNewButton.classList.contains("hidden"), true, "the field takes the place of New session");
  assert.equal(f.els.sessionSidebarCreateName.placeholder, "New session in acme");
  assert.equal(f.els.sessionSidebarCreateName.focused, 1);
  f.els.sessionSidebarCreateName.value = "Checkout";
  await f.context.createSidebarSession();
  assert.deepEqual(f.created, [[true, "acme"]]);
  assert.deepEqual([...f.state.sessionGroupsCollapsed], ["beta"], "the group it went to is shown open");
  assert.equal(f.saves(), 1);
  assert.equal(f.els.sessionSidebarCreate.classList.contains("hidden"), true);
  assert.equal(f.els.sessionSidebarNewButton.classList.contains("hidden"), false);
});

test("New session makes a session in no group, also after a group's + was closed", async () => {
  const f = createFixture();
  f.context.openSidebarSessionCreate("acme");
  f.context.closeSidebarSessionCreate();
  // The button hands its click to the function.
  f.context.openSidebarSessionCreate({ type: "click" });
  assert.equal(f.els.sessionSidebarCreateName.placeholder, "Session name");
  await f.context.createSidebarSession();
  assert.deepEqual(f.created, [[true, null]]);
  assert.deepEqual([...f.state.sessionGroupsCollapsed], ["acme", "beta"]);
});

test("a click on a group's + asks for a session in that group, and on its name folds it", () => {
  const start = appSource.indexOf("  // On the list, which outlives the rows each render replaces.\n  els.sessionSidebarList.addEventListener(\"click\"");
  const end = appSource.indexOf("  // \"Not receiving\" opens the two actions that change it.", start);
  assert.ok(start !== -1 && end > start);
  const calls = [];
  let click;
  const context = vm.createContext({
    els: { sessionSidebarList: { addEventListener: (type, handler) => { click = handler; } } },
    toggleSessionGroup: name => calls.push(["fold", name]),
    toggleSessionSection: name => calls.push(["fold section", name]),
    toggleSessionPin: id => calls.push(["pin", id]),
    openSidebarSessionCreate: group => calls.push(["new in", group]),
    currentSessionId: () => "shown", withButtonProgress: () => assert.fail("no session is opened"),
  });
  vm.runInContext(appSource.slice(start, end), context);
  const on = (selector, dataset) => ({ target: { closest: asked => (asked === selector ? { dataset } : null) } });
  click(on(".session-sidebar-group-add", { addToGroup: "acme" }));
  click(on(".session-sidebar-group-toggle", { group: "acme" }));
  // Default and Pinned are the list's own sections: no group has their name.
  click(on(".session-sidebar-group-add", { addToGroup: "" }));
  click(on(".session-sidebar-group-toggle", { section: "default" }));
  // A row's pin is beside the row, not in it: the session is not opened.
  click(on(".session-sidebar-pin", { pin: "b" }));
  assert.deepEqual(calls, [["new in", "acme"], ["fold", "acme"], ["new in", null], ["fold section", "default"], ["pin", "b"]]);
});

test("what is pinned and how the list is sorted are read from the settings and written back", () => {
  assert.match(appSource, /state\.sessionPinned = strings\(snapshot\?\.session_pinned\);/);
  assert.match(appSource, /state\.sessionSort = typeof snapshot\?\.session_sort === "string" \? snapshot\.session_sort : "manual";/);
  assert.match(appSource, /session_pinned: state\.sessionPinned,\n\s*session_sort: state\.sessionSort,\n\s*session_row_details: state\.sessionRowDetails,/);
  // A settings file from before the choice shows the domains, as the list did.
  assert.match(appSource, /state\.sessionRowDetails = Array\.isArray\(snapshot\?\.session_row_details\) \? strings\(snapshot\.session_row_details\) : \["domains"\];/);
});

test("the list's menu button shows that a sort is on, so a drag that keeps no place is no surprise", () => {
  const f = fixture({ sessions: [session("a", "01")], activeId: "a" });
  f.els.sessionSortButton = element();
  f.state.sessionSort = "name";
  f.context.renderSessionSidebar();
  assert.equal(f.els.sessionSortButton.classList.contains("is-sorted"), true);
  f.state.sessionSort = "manual";
  f.context.renderSessionSidebar();
  assert.equal(f.els.sessionSortButton.classList.contains("is-sorted"), false);
});

// ── the tidied list: a fixed top, and every session under a section ──
const indexHtml = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8").replace(/\r\n/g, "\n");
const sectionHeaders = html => [...html.matchAll(
  /class="session-sidebar-group-toggle" type="button" data-section="([a-z]+)" aria-expanded="(true|false)"><span class="session-sidebar-group-name">([^<]+)<\/span><\/button>/g,
)].map(match => match.slice(1));

test("the list has a fixed top where a session and a group are made, each a row with its name", () => {
  const sidebar = indexHtml.slice(indexHtml.indexOf('id="sessionSidebar"'), indexHtml.indexOf('<main class="workspace">'));
  assert.match(sidebar, /<div class="session-sidebar-top">\s*<button class="session-sidebar-action" id="sessionSidebarNewButton" type="button">\s*<svg[^]*?<\/svg>\s*<span>New session<\/span>\s*<\/button>\s*<div class="session-sidebar-create hidden" id="sessionSidebarCreate">[^]*?<\/div>\s*<button class="session-sidebar-action" id="sessionSidebarNewGroupButton" type="button">\s*<svg[^]*?<\/svg>\s*<span>New group<\/span>\s*<\/button>\s*<div class="session-sidebar-create hidden" id="sessionSidebarGroup">[^]*?<\/div>\s*<\/div>/);
  // The top, then the list's two tools, then the list, which is what scrolls.
  const order = ['class="session-sidebar-top"', 'class="session-sidebar-header"', 'id="sessionSidebarList"'].map(mark => sidebar.indexOf(mark));
  assert.ok(order[0] !== -1 && order[0] < order[1] && order[1] < order[2], String(order));
  // "List" names what is under it. "Sessions" is a section of it now, so the
  // title is not that word.
  const header = sidebar.match(/<header class="session-sidebar-header">([^]*?)<\/header>/)[1];
  assert.match(header, /^\s*<span class="session-sidebar-title">List<\/span>\s*<span class="session-sidebar-actions">[^]*<\/span>\s*$/);
  const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8").replace(/\r\n/g, "\n");
  assert.match(css, /^\.session-sidebar-header \{[^}]*justify-content: space-between;/m);
  assert.match(css, /^\.session-sidebar-title \{/m);
  assert.match(appSource, /els\.sessionSidebarNewGroupButton\.addEventListener\("click", \(\) => openSidebarGroupName\(\{ create: true \}\)\);/);
});

// A folder of Sessions by what its name carries: a group's name, or null for
// Default.
const folderNames = html => [...html.matchAll(/data-(?:section="default"|group="([^"]+)") aria-expanded/g)].map(match => match[1] ?? null);

test("sessions in no group are listed under Default, which is always there and the first folder of Sessions until it is moved", () => {
  const f = fixture({ sessions: [session("loose", "01"), session("a1", "05", { group: "acme" })], activeId: "loose" });
  f.context.renderSessionSidebar();
  let html = f.els.sessionSidebarList.innerHTML;
  // Sessions is the section every folder is in. Default is dragged as a group is.
  assert.match(html, /^<li class="session-sidebar-group session-sidebar-section"><div class="session-sidebar-group-head"><button class="session-sidebar-group-toggle" type="button" data-section="sessions" aria-expanded="true"><span class="session-sidebar-group-name">Sessions<\/span><\/button><\/div><ul class="session-sidebar-folders"><li class="session-sidebar-group session-sidebar-default" draggable="true" data-drop-default><div class="session-sidebar-group-head"><button class="session-sidebar-group-toggle" type="button" data-section="default" aria-expanded="true"><span class="session-sidebar-group-name">Default<\/span><\/button><button class="session-sidebar-group-add" type="button" data-add-to-group="" aria-label="New session in Default" title="New session in Default">\+<\/button><\/div><ul class="session-sidebar-group-list"><li draggable="true" data-drag-session="loose">/);
  assert.deepEqual(rows(html), ["loose", "a1"]);
  assert.deepEqual(folderNames(html), [null, "acme"]);
  // With every session in a group, Default is still where a new one goes.
  f.state.sessions = [session("a1", "05", { group: "acme" })];
  f.context.renderSessionSidebar();
  html = f.els.sessionSidebarList.innerHTML;
  assert.deepEqual(sectionHeaders(html), [["sessions", "true", "Sessions"], ["default", "true", "Default"]]);
  assert.ok(html.indexOf('data-section="default"') < html.indexOf('data-group="acme"'));
  assert.match(html, /<\/ul><\/li><\/ul><\/li>$/, "the folders close inside Sessions");
});

test("Default is drawn under the group it was left under, and the place is saved", () => {
  const f = fixture({
    sessions: [session("loose", "01"), session("a1", "05", { group: "acme" }), session("b1", "06", { group: "beta" })], activeId: "loose",
  });
  f.state.sessionGroupOrder = ["beta", "acme"];
  f.state.sessionDefaultAfter = "beta";
  f.context.renderSessionSidebar();
  let html = f.els.sessionSidebarList.innerHTML;
  assert.deepEqual(folderNames(html), ["beta", null, "acme"]);
  assert.deepEqual(rows(html), ["b1", "loose", "a1"]);
  // Under the last group Default is the last folder.
  f.state.sessionDefaultAfter = "acme";
  f.context.renderSessionSidebar();
  assert.deepEqual(folderNames(f.els.sessionSidebarList.innerHTML), ["beta", "acme", null]);
  // A group that is no longer there leaves Default first, as it began.
  f.state.sessionDefaultAfter = "gone";
  f.context.renderSessionSidebar();
  html = f.els.sessionSidebarList.innerHTML;
  assert.deepEqual(folderNames(html), [null, "beta", "acme"]);
  assert.deepEqual(rows(html), ["loose", "b1", "a1"]);
  assert.match(appSource, /state\.sessionDefaultAfter = typeof snapshot\?\.session_default_after === "string" \? snapshot\.session_default_after : "";/);
  assert.match(appSource, /session_group_order: state\.sessionGroupOrder,\n\s*session_default_after: state\.sessionDefaultAfter,/);
});

test("Pinned, Sessions and Default fold as a group does, and the choice is saved", () => {
  let saves = 0;
  const f = fixture({
    sessions: [session("a", "01"), session("b", "02"), session("g", "03", { group: "acme" })], activeId: null,
    names: ["toggleSessionSection"], globals: { scheduleUiSettingsSave: () => { saves += 1; } },
  });
  f.state.sessionPinned = ["b"];
  f.state.sessionSectionsCollapsed = [];
  f.context.renderSessionSidebar();
  assert.deepEqual(sectionHeaders(f.els.sessionSidebarList.innerHTML),
    [["pinned", "true", "Pinned"], ["sessions", "true", "Sessions"], ["default", "true", "Default"]]);
  f.context.toggleSessionSection("default");
  assert.deepEqual([...f.state.sessionSectionsCollapsed], ["default"]);
  assert.deepEqual(rows(f.els.sessionSidebarList.innerHTML), ["b", "g"], "a folded section draws its name only");
  assert.deepEqual(sectionHeaders(f.els.sessionSidebarList.innerHTML).at(-1), ["default", "false", "Default"]);
  f.context.toggleSessionSection("pinned");
  assert.deepEqual(rows(f.els.sessionSidebarList.innerHTML), ["g"]);
  f.context.toggleSessionSection("default");
  assert.deepEqual([...f.state.sessionSectionsCollapsed], ["pinned"]);
  // Sessions folded leaves the pinned ones: no folder of it is drawn.
  f.context.toggleSessionSection("pinned");
  f.context.toggleSessionSection("sessions");
  assert.deepEqual(rows(f.els.sessionSidebarList.innerHTML), ["b"]);
  assert.deepEqual(sectionHeaders(f.els.sessionSidebarList.innerHTML),
    [["pinned", "true", "Pinned"], ["sessions", "false", "Sessions"]]);
  assert.doesNotMatch(f.els.sessionSidebarList.innerHTML, /session-sidebar-folders|data-group="acme"/);
  assert.equal(saves, 5);
});

test("Default as a group's name means no group", async () => {
  const state = { sessionSidebarHidden: false, sessionGroupOrder: [] };
  const calls = [];
  const els = { sessionSidebarGroup: element(), sessionSidebarNewGroupButton: element(),
    sessionSidebarGroupName: { value: "", focus() {}, select() {} } };
  const context = loadFunctions(["openSidebarGroupName", "closeSidebarGroupName", "submitSidebarGroupName", "keepSessionGroup"], {
    els, state, sidebarGroupEdit: null, closeSidebarSessionCreate() {},
    renderSessionSidebar() {}, scheduleUiSettingsSave() {},
    moveSessionToGroup: async (id, group) => { calls.push(["move", id, group]); },
    renameSessionGroup: async (from, to) => { calls.push(["rename", from, to]); },
  });
  const submit = async (edit, name) => { context.openSidebarGroupName(edit); els.sessionSidebarGroupName.value = name; await context.submitSidebarGroupName(); };
  await submit({ session: "s1" }, " default ");
  await submit({ create: true }, "Default");
  await submit({ group: "acme" }, "DEFAULT");
  // The session leaves its group, no second Default is kept, and a group
  // renamed to it is ungrouped.
  assert.deepEqual(calls, [["move", "s1", null], ["rename", "acme", null]]);
  assert.deepEqual([...state.sessionGroupOrder], []);
});

test("which sections are folded is read from the settings and written back", () => {
  assert.match(appSource, /state\.sessionSectionsCollapsed = strings\(snapshot\?\.session_sections_collapsed\);/);
  assert.match(appSource, /session_sections_collapsed: state\.sessionSectionsCollapsed,/);
});

test("the top rows and the section names are styled as the list's own", () => {
  const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8").replace(/\r\n/g, "\n");
  assert.match(css, /^\.session-sidebar-top \{[^}]*border-bottom: 1px solid var\(--line\);/m);
  assert.match(css, /^\.session-sidebar-action \{[^}]*display: flex;[^}]*width: 100%;/m);
  assert.doesNotMatch(css, /session-sidebar-pinned-list/, "one list under every name");
});

// ── what a session is doing, at the front of its row ──
test("a row begins with what the session is doing: a job running, one that ended, traffic arriving, or nothing", () => {
  const f = fixture({
    sessions: [session("idle", "01"), session("main", "02"), session("port", "03"), session("busy", "04"), session("done", "05")],
    activeId: "idle",
  });
  f.state.settings = { proxy_addr: "127.0.0.1:8080" };
  const activity = (extra) => ({ name: "", running: [], held: 0, active: false, port: null, portOpen: false, ...extra });
  f.state.sessionActivity = new Map([
    ["main", activity({ active: true })],
    ["port", activity({ port: 18081, portOpen: true })],
    // What needs a look comes before what merely arrives.
    ["busy", activity({ port: 18082, portOpen: true, running: ["fuzzer"] })],
    ["done", activity({ port: 18083, portOpen: true })],
  ]);
  f.state.sessionsFinished = new Map([["done", ["scan"]]]);
  const row = id => f.context.sessionSidebarRow(f.state.sessions.find(entry => entry.id === id), false, null);
  const status = id => row(id).match(/<span class="session-sidebar-status([^"]*)"( title="[^"]*")?><\/span>/).slice(1, 3);
  assert.deepEqual(status("idle"), ["", undefined], "the place is kept, so the names line up");
  assert.deepEqual(status("main"), [" receiving", ' title="The proxy listener records into this session"']);
  assert.deepEqual(status("port"), [" receiving", ' title="This session records from its own port"']);
  assert.deepEqual(status("busy"), [" running", ' title="Running: Fuzzer"']);
  assert.deepEqual(status("done"), [" finished", ' title="Scan finished"']);
  for (const id of ["idle", "main", "busy", "done"]) {
    // One mark, and it is the first thing in the row.
    assert.match(row(id), /aria-label="[^"]*"><span class="session-sidebar-status[^>]*><\/span><span class="session-sidebar-text">/, id);
    assert.equal(row(id).match(/session-sidebar-status/g).length, 1, id);
    assert.doesNotMatch(row(id), /session-sidebar-running|session-sidebar-finished/, id);
  }
  // Which port is still said at the row's other end.
  assert.match(row("busy"), /<span class="session-sidebar-port"[^>]*>:18082<\/span><\/button>/);
});

test("the mark is in the column of a group's caret, and the rows run the list's width", () => {
  const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8").replace(/\r\n/g, "\n");
  const rule = selector => css.match(new RegExp(`^${selector.replace(/[.:[\]="]/g, "\\$&")} \\{[^}]*\\}`, "m"))?.[0] || "";
  assert.match(rule(".session-sidebar-group-list"), /padding: 0;/, "no indent: the mark's place is the indent");
  // The place is as wide as a folder's icon, which is in the same column.
  assert.match(rule(".session-sidebar-status"), /flex: none;[^}]*width: 14px;[^}]*height: 14px;/);
  // The green of the proxy indicator, which says the same of the session on screen.
  assert.match(rule(".session-sidebar-status.receiving::before"), /background: #50c878;/);
  assert.match(rule(".session-sidebar-status.finished::before"), /background: var\(--point\);/);
  // A dot is smaller than its place and in the middle of it: a quiet signal,
  // and the names stay where they are.
  assert.match(css, /^\.session-sidebar-status\.receiving::before,\n\.session-sidebar-status\.finished::before \{\s*width: 6px;\s*height: 6px;/m);
  assert.match(rule(".session-sidebar-status.running::before"), /animation: button-spinner/);
  // A group is a folder: open while its sessions are drawn, shut when folded.
  assert.match(rule(".session-sidebar-group-toggle::before"), /width: 14px;[^}]*height: 14px;[^}]*mask: var\(--folder-shut\)/);
  assert.match(rule('.session-sidebar-group-toggle[aria-expanded="true"]::before'), /mask: var\(--folder-open\)/);
  // A section is a name with a chevron after it, and no folder.
  assert.match(css, /^\.session-sidebar-section > \.session-sidebar-group-head > \.session-sidebar-group-toggle::before \{\s*content: none;/m);
  assert.doesNotMatch(css, /\.session-sidebar-running|\.session-sidebar-finished/);
});

// ── a browser Sniper opened that sends to the session ──
test("a row shows that a browser Sniper opened is sending to the session, before the port it sends to", () => {
  const f = fixture({ sessions: [session("a", "01"), session("b", "02")], activeId: "a" });
  f.state.settings = { proxy_addr: "127.0.0.1:8080" };
  const rowsNow = () => Object.fromEntries(f.els.sessionSidebarList.innerHTML.split("</li>").filter(part => part.includes("data-id="))
    .map(part => [part.match(/data-id="([^"]+)"/)[1], part]));
  f.context.applySessionActivity([
    { id: "a", name: "Session a", running: [], held: 0, active: true, browser: true },
    { id: "b", name: "Session b", running: [], held: 0, active: false },
  ]);
  assert.equal(f.state.sessionActivity.get("a").browser, true);
  assert.equal(f.state.sessionActivity.get("b").browser, false, "nothing said is no browser");
  assert.match(rowsNow().a, /<span class="session-sidebar-browser" title="A browser opened from Sniper sends its traffic here"><\/span><span class="session-sidebar-port"[^>]*>:8080<\/span>/);
  assert.match(rowsNow().a, /aria-label="Session a, proxy :8080, browser open"/);
  assert.doesNotMatch(rowsNow().b, /session-sidebar-browser|browser open/);
  // The browser quits: the next read takes the mark away.
  f.context.applySessionActivity([
    { id: "a", name: "Session a", running: [], held: 0, active: true, browser: false },
    { id: "b", name: "Session b", running: [], held: 0, active: false },
  ]);
  assert.doesNotMatch(rowsNow().a, /session-sidebar-browser/);
  const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8").replace(/\r\n/g, "\n");
  assert.match(css, /^\.session-sidebar-browser \{[^}]*mask: url\("data:image\/svg\+xml,[^}]*background: var\(--text-dim\);/m);
});

// ── the relay listeners a session runs ──
test("a row shows the port a session relays TCP from, and its tooltip where to", () => {
  const f = fixture({ sessions: [session("a", "01"), session("b", "02"), session("c", "03")], activeId: "a" });
  f.state.settings = { proxy_addr: "127.0.0.1:8080" };
  const rowsNow = () => Object.fromEntries(f.els.sessionSidebarList.innerHTML.split("</li>").filter(part => part.includes("data-id="))
    .map(part => [part.match(/data-id="([^"]+)"/)[1], part]));
  const idle = { id: "c", name: "Session c", running: [], held: 0, active: false };
  f.context.applySessionActivity([
    { id: "a", name: "Session a", running: [], held: 0, active: true, browser: true,
      tcp: [{ local_port: 9000, target: "example.com:7000", udp: false, running: true }] },
    { id: "b", name: "Session b", running: [], held: 0, active: false, proxy_port: 8101, proxy_port_open: true,
      tcp: [{ local_port: 9001, target: "example.org:53", udp: true, running: true },
        { local_port: 9000, target: "example.com:7000", udp: false, running: false }] },
    idle,
  ]);
  // One token with its own port, so it is not read with the proxy port that
  // follows. Before the globe and that port, which read as one thing.
  assert.match(rowsNow().a, /<span class="session-sidebar-tcp" title="TCP :9000 → example.com:7000">tcp:9000<\/span><span class="session-sidebar-browser"/);
  assert.match(rowsNow().a, /aria-label="Session a, proxy :8080, TCP :9000 → example.com:7000, browser open"/);
  // The first that runs is shown, with how many more there are. A listener
  // that is on and did not start colours the mark, and the tooltip says so.
  assert.match(rowsNow().b, /<span class="session-sidebar-tcp failed" title="UDP :9001 → example.org:53\nTCP :9000 → example.com:7000, not running">udp:9001\+1<\/span><span class="session-sidebar-port"/);
  assert.doesNotMatch(rowsNow().c, /session-sidebar-tcp|→/);
  assert.deepEqual(Array.from(f.state.sessionActivity.get("c").tcp), [], "nothing said is no listener");

  // What is not a listener is dropped.
  f.context.applySessionActivity([
    { id: "a", name: "Session a", running: [], held: 0, active: true,
      tcp: [null, { local_port: "9000", target: "x:1" }, { local_port: 9000, target: "<b>:1", udp: true, running: true }] },
    { id: "b", name: "Session b", running: [], held: 0, active: false, tcp: "9001" },
    idle,
  ]);
  assert.match(rowsNow().a, /<span class="session-sidebar-tcp" title="UDP :9000 → &#60;b&#62;:1">udp:9000<\/span>/);
  assert.doesNotMatch(rowsNow().b, /session-sidebar-tcp/);
  const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8").replace(/\r\n/g, "\n");
  assert.match(css, /^\.session-sidebar-tcp \{[^}]*color: var\(--text-dim\);[^}]*font-size: var\(--font-xs\);[^}]*font-variant-numeric: tabular-nums;/m);
  assert.match(css, /^\.session-sidebar-tcp\.failed \{\s*color: var\(--danger\);/m);
});

// ── a pin under the pointer ──
test("a row has a pin beside it that shows under the pointer, and says whether the session is pinned", () => {
  const f = fixture({ sessions: [session("a", "01"), session("b", "02")], activeId: "a" });
  f.state.sessionPinned = ["b"];
  f.context.renderSessionSidebar();
  const html = f.els.sessionSidebarList.innerHTML;
  // After the row, in the same item: a button in a button is no markup.
  assert.match(html, /<\/button><button class="session-sidebar-pin" type="button" data-pin="a" tabindex="-1" aria-pressed="false" aria-label="Pin Session a" title="Pin"><\/button><\/li>/);
  assert.match(html, /<button class="session-sidebar-pin" type="button" data-pin="b" tabindex="-1" aria-pressed="true" aria-label="Unpin Session b" title="Unpin"><\/button><\/li>/);
  // A name being edited has no pin.
  f.state.sessionRename = { id: "a", draft: "x", place: "sidebar" };
  f.context.renderSessionSidebar();
  assert.equal(f.els.sessionSidebarList.innerHTML.match(/class="session-sidebar-pin"/g).length, 1);
  const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8").replace(/\r\n/g, "\n");
  assert.match(css, /^\.session-sidebar-pin \{[^}]*position: absolute;[^}]*opacity: 0;/m);
  assert.match(css, /^\.session-sidebar-list li:hover > \.session-sidebar-pin,\n\.session-sidebar-pin:focus-visible \{\s*opacity: 1;/m);
  // Under the pointer the pin takes the place of the mark.
  assert.match(css, /^\.session-sidebar-list li:hover > \.session-sidebar-row > \.session-sidebar-status \{\s*visibility: hidden;/m);
});
