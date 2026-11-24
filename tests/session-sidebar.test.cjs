// The session list beside the workspace. Synthetic sessions; no API runs.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

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
  const context = loadFunctions(["renderSessionSidebar", "sessionSidebarRow", "sessionIdentity", "applySessionActivity", ...names], {
    state, els,
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
  assert.deepEqual([...html.matchAll(/tabindex="(-?\d)"/g)].map(match => match[1]), ["-1", "0", "-1"]);
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
    const els = { sessionSidebarCreate: element(), sessionSidebarCreateName: { value: "orders-api" } };
    const context = loadFunctions(["closeSidebarSessionCreate"], { els, sidebarSessionCreating: creating });
    context.closeSidebarSessionCreate();
    // createSession reads the name only after the drafts it saves first.
    assert.equal(els.sessionSidebarCreateName.value, creating ? "orders-api" : "");
    assert.equal(els.sessionSidebarCreate.classList.contains("hidden"), true);
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
  /class="session-sidebar-group-toggle" type="button" data-group="([^"]+)" aria-expanded="(true|false)">.*?<span class="session-sidebar-group-count">(\d+)<\/span>/g,
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
  assert.deepEqual(groupHeaders(html), [["acme", "true", "2"], ["beta", "false", "1"]]);
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
    [["group", "beta", "Move to beta"], ["new-group", undefined, "New group…"], ["ungroup", undefined, "Remove from group"]]);
  assert.deepEqual(items(context.sessionGroupMenuItems(state.sessions[2])),
    [["group", "acme", "Move to acme"], ["group", "beta", "Move to beta"], ["new-group", undefined, "New group…"]]);
});

test("moving a session asks the server, shows its group open, and reads the list again", async () => {
  const requests = [], reads = [];
  const state = { sessionGroupsCollapsed: ["acme", "beta"] };
  const context = loadFunctions(["moveSessionToGroup"], {
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
  let closed = 0;
  const els = { sessionSidebarGroup: element(), sessionSidebarGroupName: { value: "", focus() {} } };
  const context = loadFunctions(["openSidebarGroupName", "closeSidebarGroupName", "submitSidebarGroupName"], {
    els, sidebarGroupSession: null,
    closeSidebarSessionCreate: () => { closed += 1; },
    moveSessionToGroup: async (id, group) => { moved.push([id, group]); if (failing) throw new Error("refused"); },
  });
  els.sessionSidebarGroup.classList.add("hidden");
  context.openSidebarGroupName("s1");
  assert.equal(els.sessionSidebarGroup.classList.contains("hidden"), false);
  assert.equal(closed, 1, "the new-session field gives way: the two look alike");
  els.sessionSidebarGroupName.value = "  acme  ";
  const outcome = await context.submitSidebarGroupName().then(() => "moved", error => error.message);
  assert.deepEqual(moved, [["s1", "acme"]]);
  assert.equal(outcome, failing ? "refused" : "moved");
  assert.equal(els.sessionSidebarGroup.classList.contains("hidden"), !failing);
  assert.equal(els.sessionSidebarGroupName.value, failing ? "  acme  " : "");
  // An empty name moves nothing.
  if (!failing) {
    context.openSidebarGroupName("s1");
    await context.submitSidebarGroupName();
    assert.equal(moved.length, 1);
    assert.equal(els.sessionSidebarGroup.classList.contains("hidden"), true);
  }
});

