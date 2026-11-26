// The session page: opened by the gear beside the session list, it shows the
// session on screen first and every session beside it. Synthetic sessions and
// elements only; nothing starts and no request is sent.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8").replace(/\r\n/g, "\n");
const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8").replace(/\r\n/g, "\n");

function element(dataset = {}) {
  const classes = new Set(), attributes = {};
  return {
    dataset, innerHTML: "", textContent: "", hidden: false, focused: 0, clicks: 0,
    classList: {
      add: name => classes.add(name), remove: name => classes.delete(name), contains: name => classes.has(name),
      toggle(name, force = !classes.has(name)) { if (force) classes.add(name); else classes.delete(name); return force; },
    },
    setAttribute(name, value) { attributes[name] = String(value); },
    getAttribute: name => attributes[name] ?? null,
    querySelector: () => null, querySelectorAll: () => [],
    focus() { this.focused += 1; }, click() { this.clicks += 1; },
    getBoundingClientRect: () => ({ left: 900, right: 930, top: 60, bottom: 86, width: 30, height: 26 }),
  };
}

const session = (id, extra = {}) => ({
  id, name: `Session ${id}`, active: false, storage_path: `/fixture/sessions/${id}`,
  storage_bytes: 0, request_count: 0, websocket_count: 0, tcp_connection_count: 0,
  created_at: "2026-11-01T00:00:00Z", overview: {}, ...extra,
});

test("the top strip has no Session tab, and a gear above the session list opens the page", () => {
  const tabs = html.slice(html.indexOf('<nav class="main-tabs"'), html.indexOf("</nav>", html.indexOf('<nav class="main-tabs"')));
  assert.doesNotMatch(tabs, /data-tool="dashboard"/);
  const header = html.match(/<header class="session-sidebar-header">([^]*?)<\/header>/)[1];
  assert.match(header, /<button class="utility-button icon-button" id="sessionPageButton" type="button" aria-label="Manage sessions" title="Manage sessions" aria-pressed="false" aria-controls="dashboardShell">/);
  // Above the list: how it is sorted and what a row shows, then the gear.
  // Making a session or a group is a row of its own above.
  assert.match(header, /<button class="utility-button icon-button" id="sessionSortButton" type="button" aria-label="View options" title="View options" aria-haspopup="menu">/);
  assert.ok(header.indexOf('id="sessionSortButton"') < header.indexOf('id="sessionPageButton"'));
  assert.doesNotMatch(header, /sessionSidebarNewButton|>\+</);
  // The two stay quiet until the pointer is on one.
  assert.match(css, /\.session-sidebar-actions \.icon-button:not\(:hover\):not\(\[aria-pressed="true"\]\)\s*\{[^}]*border-color: transparent;[^}]*background: none;/);
});

test("the page has two views, the session on screen first, and one way to make a session", () => {
  const page = html.slice(html.indexOf('id="dashboardShell"'), html.indexOf('id="proxyShell"'));
  assert.match(page, /<nav class="sub-tabs" aria-label="Session views">\s*<button class="sub-tab active" type="button" data-session-view="overview">Overview<\/button>\s*<button class="sub-tab" type="button" data-session-view="all">All sessions<\/button>\s*<\/nav>/);
  const overview = page.slice(page.indexOf('id="sessionOverviewPanel"'), page.indexOf('id="sessionAllPanel"'));
  for (const id of ["sessionOverviewName", "sessionOverviewStorage", "sessionOverviewPath", "sessionOverviewOpenStorageBtn",
    "sessionOverviewMoreButton", "sessionOverviewTiles", "sessionOverviewDetail"]) {
    assert.match(overview, new RegExp(`id="${id}"`), id);
  }
  const all = page.slice(page.indexOf('id="sessionAllPanel"'));
  assert.match(page, /<section class="panel-card hidden" id="sessionAllPanel">/);
  assert.match(all, /id="dashboardReloadSessionsButton"[^>]*>Reload sessions<\/button>/);
  assert.match(all, /<th data-sort-key="name"[^>]*>[^]*?<\/th>\s*<th data-sort-key="group" aria-sort="none"><button class="session-sort-button" type="button">Group<\/button><\/th>/);
  // The list's + is where a session is made.
  assert.doesNotMatch(page, /New session|dashboardCreateSession|dashboardNewSessionButton/);
});

function pageFixture(tool = "replay") {
  const state = { activeTool: tool, sessionPageView: "all", scanTool: "recon" };
  const calls = [];
  const mainTabs = ["target", "proxy", "map", "templates", "replay"].map(name => element({ tool: name }));
  const context = loadFunctions(["toggleSessionPage"], {
    state, mainTabs,
    setActiveTool: next => { calls.push(`tool ${next}`); state.activeTool = next; },
    renderToolPanels: () => calls.push("panels"),
    loadSessions: async () => { calls.push("sessions"); },
    handleWorkspaceActionError() {},
  });
  const clicked = () => mainTabs.filter(tab => tab.clicks).map(tab => `${tab.dataset.tool}×${tab.clicks}`);
  return { state, calls, context, clicked };
}

test("the gear opens the page on the Overview and reads the sessions", () => {
  const f = pageFixture();
  f.context.toggleSessionPage();
  assert.deepEqual(f.calls, ["tool dashboard", "panels", "sessions"]);
  assert.equal(f.state.sessionPageView, "overview", "each opening starts on the session on screen");
  assert.deepEqual(f.clicked(), []);
});

test("the gear pressed again gives back the tool that was open, as its tab does", () => {
  const f = pageFixture();
  f.context.toggleSessionPage();
  f.calls.length = 0;
  f.context.toggleSessionPage();
  assert.deepEqual(f.clicked(), ["replay×1"]);
  assert.deepEqual(f.calls, [], "the tab's own click loads what the tool shows");
});

test("a Scan tool comes back through the Scan tab, and nothing remembered is Capture", () => {
  const scan = pageFixture("recon");
  scan.context.toggleSessionPage();
  scan.context.toggleSessionPage();
  assert.deepEqual(scan.clicked(), ["templates×1"]);
  // The page was open when the window loaded.
  const loaded = pageFixture("dashboard");
  loaded.context.toggleSessionPage();
  assert.deepEqual(loaded.clicked(), ["proxy×1"]);
});

test("a view's tab shows its panel and hides the other", () => {
  const state = { sessionPageView: "overview" };
  const els = {
    sessionPageTabs: [element({ sessionView: "overview" }), element({ sessionView: "all" })],
    sessionOverviewPanel: element(), sessionAllPanel: element(),
  };
  let drawn = 0;
  const context = loadFunctions(["setSessionPageView", "renderSessionPageView"], { state, els, renderDashboard: () => { drawn += 1; context.renderSessionPageView(); } });
  context.setSessionPageView("all");
  assert.equal(drawn, 1);
  assert.deepEqual(els.sessionPageTabs.map(tab => tab.classList.contains("active")), [false, true]);
  assert.deepEqual([els.sessionOverviewPanel, els.sessionAllPanel].map(panel => panel.classList.contains("hidden")), [true, false]);
  context.setSessionPageView("overview");
  assert.deepEqual(els.sessionPageTabs.map(tab => tab.classList.contains("active")), [true, false]);
  assert.deepEqual([els.sessionOverviewPanel, els.sessionAllPanel].map(panel => panel.classList.contains("hidden")), [false, true]);
  // A view that does not exist is the first one.
  context.setSessionPageView("nothing");
  assert.equal(state.sessionPageView, "overview");
});

function dashboardFixture(sessions, { shown = sessions[0], selected = null, extra = {} } = {}) {
  const state = { sessions, activeSession: shown, selectedSessionId: selected, sessionPageView: "overview", sessionRename: null, ...extra };
  const els = new Proxy({}, { get: (target, key) => target[key] ||= element() });
  const context = loadFunctions(["renderDashboard", "sessionFindingCount", "formatSize", "formatCappedCount"], {
    state, els, document: { activeElement: null, getElementById: () => null }, getSortedSessions: () => sessions,
    retainedTransactionsCap() {}, retainedEntriesCap: () => null,
    formatTimestamp: value => `at ${value}`, escapeHtml: value => String(value).replace(/</g, "&lt;"),
    // With no container named, the editor is the table's.
    sessionRenameInput: null, wireSessionRenameInput: (selection, container = els.dashboardSessionsBody) => { context.wired = container; },
  });
  return { state, els, context };
}

test("the Overview is the session on screen: its name, folder, numbers and what was done in it", () => {
  const shown = session("shown", {
    request_count: 11, websocket_count: 2, tcp_connection_count: 3, storage_bytes: 2048, created_by: "Claude",
    overview: { scope: ["shop.example.com"], scope_count: 1, findings: { medium: 1, info: 3 }, last_captured_at: "16:02" },
  });
  const other = session("other", { active: true, request_count: 400, overview: { scope: ["other.example.com"], scope_count: 1 } });
  const f = dashboardFixture([shown, other], { selected: "other" });
  f.context.renderDashboard();
  assert.equal(f.state.overviewSessionId, "shown");
  assert.match(f.els.sessionOverviewName.innerHTML, /^<span class="session-actor" data-actor="Claude"[^>]*><\/span>Session shown$/);
  assert.equal(f.els.sessionOverviewPath.textContent, "/fixture/sessions/shown");
  assert.equal(f.els.sessionOverviewStorage.hidden, false);
  const tiles = [...f.els.sessionOverviewTiles.innerHTML.matchAll(/<div class="dashboard-tile-value">([^<]*)<\/div><div class="dashboard-tile-label">([^<]*)<\/div>(?:<div class="dashboard-tile-note">([^<]*)<\/div>)?/g)]
    .map(match => match.slice(1, 4));
  assert.deepEqual(tiles, [
    ["11", "Requests", "and 2 WebSocket sessions · 3 TCP connections"],
    ["4", "Findings", "1 medium · 3 info"],
    ["at 16:02", "Last HTTP capture", undefined],
    ["2.0 KB", "On disk", undefined],
  ]);
  const detail = f.els.sessionOverviewDetail.innerHTML;
  assert.doesNotMatch(detail, /<h3>/, "the title above already names the session");
  assert.match(detail, /<span class="dashboard-chip">shop\.example\.com<\/span>/);
  assert.doesNotMatch(detail, /other\.example\.com/);
  // It is open: its TCP history is one tab away.
  assert.match(detail, /3 retained connections · Capture → TCP\./);
  // The selected session keeps its own summary under the table.
  assert.match(f.els.dashboardDetail.innerHTML, /<h3>Session other<\/h3>[^]*other\.example\.com/);
});

test("a session that recorded nothing says so, and no session shows nothing", () => {
  const empty = dashboardFixture([session("shown")]);
  empty.context.renderDashboard();
  assert.equal(empty.els.sessionOverviewDetail.innerHTML, '<p class="dashboard-dim">Nothing recorded in this session yet.</p>');
  assert.match(empty.els.sessionOverviewTiles.innerHTML, /<div class="dashboard-tile-value">None yet<\/div><div class="dashboard-tile-label">Last HTTP capture<\/div>/);
  const none = dashboardFixture([], { shown: null });
  none.context.renderDashboard();
  assert.equal(none.state.overviewSessionId, null);
  assert.equal(none.els.sessionOverviewName.innerHTML, "No session");
  assert.equal(none.els.sessionOverviewStorage.hidden, true);
  assert.equal(none.els.sessionOverviewTiles.innerHTML, "");
  assert.equal(none.els.sessionOverviewDetail.innerHTML, "");
});

test("a session not on screen is told to be opened for its TCP history", () => {
  const f = dashboardFixture([session("shown"), session("other", { tcp_connection_count: 1 })], { selected: "other" });
  f.context.renderDashboard();
  assert.match(f.els.dashboardDetail.innerHTML, /1 retained connection · Open this session, then Capture → TCP\./);
});

test("the table names each session's group", () => {
  const f = dashboardFixture([session("shown", { group: "Shop <b" }), session("loose")]);
  f.context.renderDashboard();
  const cells = [...f.els.dashboardSessionsBody.innerHTML.matchAll(/<td class="session-group-cell"([^>]*)>([^]*?)<\/td>/g)].map(match => match.slice(1, 3));
  // A long name is cut short in its cell and whole in its title.
  // A session in no group is in Default, as the list says.
  assert.deepEqual(cells, [[' title="Shop &lt;b"', "Shop &lt;b"], ["", '<span class="dashboard-dim">Default</span>']]);
  // The empty row spans the header, which has one column more.
  assert.match(f.context.renderDashboard.toString(), /<td colspan="10">No sessions are available yet\.<\/td>/);
});

test("renaming from the Overview edits the title, and the table row keeps its name", () => {
  const f = dashboardFixture([session("shown"), session("other")]);
  f.state.sessionRename = { id: "shown", draft: "Typed <so> far", pending: false, focus: true, place: "overview" };
  f.context.renderDashboard();
  assert.equal(f.els.sessionOverviewName.innerHTML,
    '<input class="session-name-input" type="text" value="Typed &lt;so> far" aria-label="Rename session Session shown" spellcheck="false" autocomplete="off" />');
  assert.equal(f.context.wired, f.els.sessionOverviewName, "the field in the title is the editor");
  assert.match(f.els.dashboardSessionsBody.innerHTML, /session-select-button[^>]*>Session shown</);
  assert.doesNotMatch(f.els.dashboardSessionsBody.innerHTML, /session-name-input/);
});

test("a rename in the table is not drawn in the title", () => {
  const f = dashboardFixture([session("shown")]);
  f.state.sessionRename = { id: "shown", draft: "Draft", pending: false, focus: true, place: "dashboard" };
  f.context.renderDashboard();
  assert.equal(f.els.sessionOverviewName.innerHTML, "Session shown");
  assert.match(f.els.dashboardSessionsBody.innerHTML, /<input class="session-name-input"/);
  assert.equal(f.context.wired, f.els.dashboardSessionsBody);
});

test("a rename from the Overview gives the focus back to its menu button", () => {
  const els = { sessionOverviewMoreButton: element(), sessionSidebarList: element(), dashboardSessionsBody: element() };
  const context = loadFunctions(["focusSessionNameButton"], { els });
  context.focusSessionNameButton("shown", "overview");
  assert.equal(els.sessionOverviewMoreButton.focused, 1);
});

function menuFixture(place) {
  const shown = session("shown", { group: "acme" });
  const state = { sessions: [shown, session("other", { group: "beta" })], sessionActivity: new Map(), settings: {},
    sessionPinned: place === "sidebar" ? ["shown"] : [] };
  const calls = [];
  const body = { appended: [], appendChild(node) { this.appended.push(node); } };
  const menu = { listeners: {}, style: {}, className: "", innerHTML: "",
    getBoundingClientRect: () => ({ width: 180, height: 200 }),
    addEventListener(type, handler) { this.listeners[type] = handler; }, remove() {} };
  const context = loadFunctions(["showSessionContextMenu"], {
    state, sessionContextMenuEl: null, closeSessionContextMenu() {},
    document: { createElement: () => menu, body }, window: { innerWidth: 1200, innerHeight: 800 },
    escapeHtml: value => String(value),
    startSessionRename: (id, where) => calls.push(["rename", id, where]),
    revealSessionFolder: async () => {}, deleteSessionById: id => calls.push(["delete", id]),
    moveSessionToGroup: async (id, group) => { calls.push(["move", id, group]); },
    openSidebarGroupName: edit => calls.push(["new group", edit.session]),
    toggleSessionPin: id => calls.push(["pin", id]),
    runSessionFeedAction: async () => {}, handleWorkspaceActionError() {},
  });
  context.showSessionContextMenu({ clientX: 900, clientY: 90 }, "shown", place);
  const choose = (action, group) => menu.listeners.click({ target: { closest: () => ({ dataset: { action, group } }) } });
  return { menu, calls, choose };
}

for (const place of ["dashboard", "sidebar", "overview"]) {
  test(`a session's menu is the same in the ${place}: where it records, its name, its folder, its group`, () => {
    const f = menuFixture(place);
    const labels = [...f.menu.innerHTML.matchAll(/<button class="context-menu-item[^"]*" data-action="([^"]+)"[^>]*>([^<]*)<\/button>/g)].map(match => match[2]);
    // A pinned session offers the way back, as here in the list.
    assert.deepEqual(labels, ["Record the proxy here", "Open a port", "Rename session", "Open session folder",
      place === "sidebar" ? "Unpin" : "Pin", "Move to Default", "Move to beta", "New group…", "Delete session"]);
    f.choose("rename");
    f.choose("group", "beta");
    f.choose("new-group");
    f.choose("pin");
    assert.deepEqual(f.calls, [["rename", "shown", place], ["move", "shown", "beta"], ["new group", "shown"], ["pin", "shown"]]);
  });
}

test("the Overview's ⋯ opens the menu of the session it shows, under the button", () => {
  const state = { overviewSessionId: "shown" };
  const els = { sessionOverviewMoreButton: element() };
  const opened = [];
  const menu = { style: {}, getBoundingClientRect: () => ({ width: 200 }) };
  const context = loadFunctions(["openSessionOverviewMenu"], {
    state, els, sessionContextMenuEl: null,
    showSessionContextMenu: (event, id, place) => {
      opened.push([event.clientX, event.clientY, id, place]);
      context.sessionContextMenuEl = menu;
    },
  });
  let stopped = 0;
  context.openSessionOverviewMenu({ stopPropagation() { stopped += 1; } });
  // The document closes this menu on any click that reaches it.
  assert.equal(stopped, 1);
  assert.deepEqual(opened, [[900, 90, "shown", "overview"]]);
  // Its right edge is the button's, as the ⋯ menu of All sessions opens.
  assert.equal(menu.style.left, "730px");
  state.overviewSessionId = null;
  context.openSessionOverviewMenu({ stopPropagation() {} });
  assert.equal(opened.length, 1, "no session, no menu");
});

test("the gear is pressed while the page is open", () => {
  const state = { activeTool: "dashboard" };
  const names = ["dashboardShell", "proxyShell", "replayShell", "toolsShell", "fuzzerShell", "sequenceShell", "targetShell", "loggerShell"];
  const els = Object.fromEntries([...names, "sessionPageButton"].map(name => [name, element()]));
  const context = loadFunctions(["renderToolPanels"], {
    state, els, mainTabs: [], sanitizeActiveTool: tool => tool, renderDashboard() {}, renderProxyPanels() {},
  });
  context.renderToolPanels();
  assert.equal(els.sessionPageButton.getAttribute("aria-pressed"), "true");
  assert.equal(els.dashboardShell.classList.contains("hidden"), false);
  state.activeTool = "proxy";
  context.renderToolPanels();
  assert.equal(els.sessionPageButton.getAttribute("aria-pressed"), "false");
  assert.equal(els.dashboardShell.classList.contains("hidden"), true);
});

test("sessions sort by group as the list reads: those in none, then each group by name", () => {
  const state = { sessionSortKey: "group", sessionSortDir: "asc",
    sessions: [session("b", { group: "beta" }), session("none"), session("a", { group: "Acme" })] };
  const context = loadFunctions(["getSortedSessions", "sessionFindingCount"], { state });
  const ids = () => Array.from(context.getSortedSessions(), entry => entry.id);
  assert.deepEqual(ids(), ["none", "a", "b"]);
  state.sessionSortDir = "desc";
  assert.deepEqual(ids(), ["b", "a", "none"]);
});

test("the page keeps its tabs in place while a long list scrolls under them", () => {
  const rule = selector => css.match(new RegExp(`^${selector.replace(/[.>]/g, "\\$&")} \\{[^}]*\\}`, "m"))?.[0] || "";
  assert.match(rule(".session-page"), /display: flex;[^}]*flex-direction: column;/);
  assert.match(rule(".session-page > .sub-tabs"), /flex: 0 0 auto;/);
  assert.match(rule(".session-page > .dashboard-shell"), /flex: 1 1 auto;[^}]*height: auto;/);
  assert.match(css, /#sessionPageButton\[aria-pressed="true"\]\s*\{[^}]*color: var\(--point\);/);
});
