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

function fixture({ sessions, activeId, hidden = false }) {
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
  const context = loadFunctions(["renderSessionSidebar", "sessionSidebarRow", "sessionIdentity", "applySessionActivity"], {
    state, els,
    document: { activeElement: null },
    sessionRenameInput: null, sessionSidebarMarkup: "", sessionListRefresh: null, sidebarRenameEdit: null,
    currentSessionId: () => state.activeSession?.id || null,
    escapeHtml: value => String(value).replace(/[&<>"]/g, char => `&#${char.charCodeAt(0)};`),
    wireSessionRenameInput() {},
    renderSessionFeed() {},
    loadSessions: options => { reloads.push(options); return new Promise(() => {}); },
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
