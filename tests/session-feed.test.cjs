// How the window says where a session's traffic comes from: the main proxy
// listener, a port of its own, or nowhere. Synthetic sessions; no API runs.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const session = (id, active = false) => ({ id, name: `Session ${id}`, created_at: "2026-11-24T09:00:00Z", active });

function element() {
  const classes = new Set();
  const attributes = {};
  return {
    innerHTML: "", textContent: "", title: "", hidden: false,
    classList: {
      toggle(name, force = !classes.has(name)) { if (force) classes.add(name); else classes.delete(name); return force; },
      contains: name => classes.has(name), add: name => classes.add(name), remove: name => classes.delete(name),
    },
    classes,
    setAttribute(name, value) { attributes[name] = String(value); },
    getAttribute: name => attributes[name] ?? null,
    removeAttribute(name) { delete attributes[name]; },
    querySelector: () => null, querySelectorAll: () => [],
  };
}

// Three sessions: the proxy listener records into `main`, `agent` has a port
// of its own, and nothing reaches `idle`.
function fixture(names, { shown = "main", online = true, extra = {} } = {}) {
  const sessions = [session("main", true), session("agent"), session("idle")];
  const state = {
    sessions, activeSession: sessions.find(entry => entry.id === shown), viewedSessionId: shown,
    settings: { proxy_addr: "127.0.0.1:8080", proxy_online: online }, runtime: { http_capture_enabled: true },
    sessionActivity: new Map([
      ["main", { name: "Session main", running: [], held: 0, active: true, port: null, portOpen: false }],
      ["agent", { name: "Session agent", running: [], held: 0, active: false, port: 18081, portOpen: true }],
      // A number the session keeps from an earlier port, which is closed now.
      ["idle", { name: "Session idle", running: [], held: 0, active: false, port: 18082, portOpen: false }],
    ]),
    sessionsFinished: new Map(), sessionRename: null, sessionSidebarHidden: false,
  };
  const els = { proxyStatusIndicator: element(), proxyStatusLabel: element() };
  const context = loadFunctions(["sessionFeed", "mainProxyPort", "mainListenerSession", "sessionProxyAddress",
    "recordHereLabel", "currentSessionId", ...names], {
    state, els,
    escapeHtml: value => String(value).replace(/[&<>"]/g, char => `&#${char.charCodeAt(0)};`),
    ...extra,
  });
  return { state, els, context, sessions };
}

test("a session receives through the proxy listener, a port of its own, or not at all", () => {
  const f = fixture([]);
  assert.deepEqual({ ...f.context.sessionFeed("main") }, { kind: "main", port: "8080" });
  assert.deepEqual({ ...f.context.sessionFeed("agent") }, { kind: "port", port: 18081 });
  assert.deepEqual({ ...f.context.sessionFeed("idle") }, { kind: "none", port: null }, "a closed port feeds nothing");
  // Before the first activity read the list says where the listener records.
  f.state.sessionActivity = new Map();
  assert.equal(f.context.sessionFeed("main").kind, "main");
  assert.equal(f.context.sessionFeed("agent").kind, "none");
});

for (const [shown, online, label, state] of [
  ["main", true, "Proxy :8080", "online"],
  ["agent", true, "Proxy :18081", "online"],
  ["idle", true, "Not receiving", "idle"],
  ["main", false, "Offline", "offline"],
  // The listener being down does not stop a session's own port.
  ["agent", false, "Proxy :18081", "online"],
]) {
  test(`the indicator reads ${label} for ${shown} with the listener ${online ? "up" : "down"}`, () => {
    const f = fixture(["updateProxyStatusIndicator"], { shown, online });
    f.context.updateProxyStatusIndicator();
    assert.equal(f.els.proxyStatusLabel.textContent, label);
    assert.deepEqual([...f.els.proxyStatusIndicator.classes].filter(name => ["online", "offline", "idle"].includes(name)), [state]);
    // Only a session nothing reaches has something to choose.
    assert.equal(f.els.proxyStatusIndicator.disabled, state !== "idle");
    assert.match(f.els.proxyStatusIndicator.title, shown === "idle" ? /No traffic reaches this session.*Session main/ : /8080|18081/);
  });
}

test("a row says which port feeds its session", () => {
  const f = fixture(["sessionSidebarRow", "sessionIdentity"]);
  const row = id => f.context.sessionSidebarRow(f.sessions.find(entry => entry.id === id), id === "main", null);
  assert.match(row("main"), /<span class="session-sidebar-port" title="The proxy listener records into this session">:8080<\/span>/);
  assert.match(row("agent"), /<span class="session-sidebar-port" title="This session records from its own port">:18081<\/span>/);
  assert.doesNotMatch(row("idle"), /session-sidebar-port/);
  assert.match(row("agent"), /aria-label="Session agent, proxy :18081"/);
});

function menuFixture() {
  const menus = [];
  const f = fixture(["showSessionContextMenu", "sessionFeedMenuItems"], {
    extra: {
      sessionContextMenuEl: null, closeSessionContextMenu() {},
      window: { innerWidth: 1000, innerHeight: 800 },
      document: {
        createElement: () => ({ className: "", innerHTML: "", style: {}, addEventListener() {}, getBoundingClientRect: () => ({ width: 10, height: 10 }) }),
        body: { appendChild: menu => menus.push(menu) },
      },
    },
  });
  const labels = id => {
    f.context.showSessionContextMenu({ clientX: 0, clientY: 0 }, id);
    return [...menus.at(-1).innerHTML.matchAll(/<button class="context-menu-item[^"]*" data-action="([a-z-]+)">([^<]+)<|<div class="(context-menu-divider)">/g)]
      .map(match => match[3] ? "-" : `${match[1]}=${match[2]}`);
  };
  return { ...f, labels };
}

test("a session's menu offers what its feed allows, and nothing the server would refuse", () => {
  const f = menuFixture();
  assert.deepEqual(f.labels("idle"), ["record=Record :8080 here", "open-port=Open a port", "-",
    "rename=Rename session", "folder=Open session folder", "pin=Pin", "-", "new-group=New group…", "-", "delete=Delete session"]);
  // A session with an open port is not activated and not deleted.
  assert.deepEqual(f.labels("agent"), ["close-port=Close port :18081", "copy-address=Copy proxy address", "-",
    "rename=Rename session", "folder=Open session folder", "pin=Pin", "-", "new-group=New group…"]);
  // The listener's session gets no port, and is not deleted.
  assert.deepEqual(f.labels("main"), ["copy-address=Copy proxy address", "-",
    "rename=Rename session", "folder=Open session folder", "pin=Pin", "-", "new-group=New group…"]);
});

test("Capture says a session that records but receives nothing is not receiving", () => {
  const pill = element();
  const run = (shown, runtime) => {
    const f = fixture(["syncHttpCapturePill"], { shown, extra: { document: { getElementById: () => pill } } });
    f.state.runtime = runtime;
    f.context.syncHttpCapturePill();
    return pill.textContent;
  };
  assert.equal(run("main", { http_capture_enabled: true }), "Capturing");
  assert.equal(run("agent", { http_capture_enabled: true }), "Capturing");
  assert.equal(run("idle", { http_capture_enabled: true }), "Not receiving");
  assert.equal(pill.classes.has("active"), false);
  assert.match(pill.title, /no traffic reaches this session/i);
  // Paused is still what the session is set to.
  assert.equal(run("idle", { http_capture_enabled: false }), "Paused");
});

test("an empty history says where the proxy records and where to point a client", () => {
  const message = shown => fixture(["emptySessionMessage"], { shown }).context.emptySessionMessage();
  assert.match(message("main"), /point any client at 127\.0\.0\.1:8080/);
  assert.match(message("agent"), /point any client at 127\.0\.0\.1:18081/);
  assert.equal(message("idle"), "No traffic reaches this session. The proxy on 127.0.0.1:8080 records into Session main.");
});

test("the activity read says where the listener records and which ports are open", () => {
  const drawn = [];
  const f = fixture(["applySessionActivity"], {
    extra: {
      sessionListRefresh: null, loadSessions: () => new Promise(() => {}),
      renderSessionSidebar: () => drawn.push("sidebar"),
      renderSessionFeed: () => drawn.push("feed"),
    },
  });
  // Another client moved the listener to `idle` and closed the agent's port.
  f.context.applySessionActivity([
    { id: "main", name: "Session main", running: [], held: 0, active: false, proxy_port: null, proxy_port_open: false },
    { id: "agent", name: "Session agent", running: [], held: 0, active: false, proxy_port: 18081, proxy_port_open: false },
    { id: "idle", name: "Session idle", running: [], held: 0, active: true, proxy_port: 18082, proxy_port_open: false },
  ]);
  assert.equal(f.context.sessionFeed("idle").kind, "main");
  assert.equal(f.context.sessionFeed("main").kind, "none");
  assert.equal(f.context.sessionFeed("agent").kind, "none");
  assert.deepEqual(f.sessions.map(entry => entry.active), [false, false, true], "the rows follow without a list read");
  assert.equal(f.state.activeSession.id, "main", "the window keeps its session");
  assert.deepEqual(drawn, ["feed", "sidebar"]);
  // The same answer again redraws nothing that says where traffic comes from.
  drawn.length = 0;
  f.context.applySessionActivity([
    { id: "main", name: "Session main", running: [], held: 0, active: false, proxy_port: null, proxy_port_open: false },
    { id: "agent", name: "Session agent", running: [], held: 0, active: false, proxy_port: 18081, proxy_port_open: false },
    { id: "idle", name: "Session idle", running: [], held: 0, active: true, proxy_port: 18082, proxy_port_open: false },
  ]);
  assert.deepEqual(drawn, ["sidebar"]);
});

test("the table of all sessions marks the session on screen and offers only what can be done", () => {
  const f = fixture(["renderDashboard", "sessionFindingCount", "formatSize"], {
    shown: "idle",
    extra: {
      document: { activeElement: null, getElementById: () => null },
      getSortedSessions: () => f.sessions, formatCappedCount: value => String(value ?? 0),
      retainedTransactionsCap() {}, retainedEntriesCap() {}, formatTimestamp: () => "-",
    },
  });
  const body = element();
  Object.assign(f.els, new Proxy({ dashboardSessionsBody: body }, { get: (target, key) => target[key] ||= element() }));
  f.context.els = new Proxy({ dashboardSessionsBody: body }, { get: (target, key) => target[key] ||= element() });
  f.state.selectedSessionId = null;
  f.context.renderDashboard();
  const rows = Object.fromEntries([...body.innerHTML.matchAll(/<tr class="([^"]*)" data-id="([^"]+)">([^]*?)<\/tr>/g)]
    .map(match => [match[2], { classes: match[1], html: match[3] }]));
  assert.equal(f.state.selectedSessionId, "idle", "the selection starts on the session on screen");
  assert.match(rows.idle.classes, /session-active/);
  assert.doesNotMatch(rows.main.classes, /session-active/);
  assert.match(rows.main.html, /<span class="session-sidebar-port in-table"[^>]*>:8080<\/span>/);
  assert.match(rows.agent.html, /<span class="session-sidebar-port in-table"[^>]*>:18081<\/span>/);
  // The session on screen needs no Open. A fed session is not deleted.
  assert.doesNotMatch(rows.idle.html, /session-open-button|session-delete-button/);
  assert.match(rows.main.html, /session-open-button/);
  assert.doesNotMatch(rows.main.html, /session-delete-button/);
  assert.match(rows.agent.html, /session-open-button/);
  assert.doesNotMatch(rows.agent.html, /session-delete-button/);
});

test("the session list runs the full height, with the tabs and the status bar beside it", () => {
  const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");
  const rule = selector => css.match(new RegExp(`^${selector.replace(".", "\\.")} \\{[^}]*\\}`, "m"))[0];
  assert.match(rule(".session-sidebar"), /grid-row: 1 \/ -1;/);
  assert.match(rule(".top-strip"), /grid-column: 2;/);
  assert.match(rule(".status-bar"), /grid-column: 2;/);
});
