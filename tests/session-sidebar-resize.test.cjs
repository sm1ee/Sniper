// The session list's width: dragged at its trailing edge, kept in the UI
// settings. Synthetic elements; nothing starts and no request is sent.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8").replace(/\r\n/g, "\n");
const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8").replace(/\r\n/g, "\n");

function fixture(width = 208) {
  const state = { sessionSidebarWidth: null };
  const style = new Map(), classes = new Set(), bodyClasses = new Set();
  const listeners = {}, documentListeners = {};
  const sidebar = {
    style: { setProperty: (name, value) => style.set(name, value), removeProperty: name => style.delete(name) },
    getBoundingClientRect: () => ({ width: state.sessionSidebarWidth || width }),
  };
  const handle = {
    classList: { add: name => classes.add(name), remove: name => classes.delete(name) },
    addEventListener: (type, handler) => { listeners[type] = handler; },
  };
  let saves = 0;
  const context = loadFunctions(["sanitizeSessionSidebarWidth", "applySessionSidebarWidth", "bindSessionSidebarResizer", "clamp"], {
    state, els: { sessionSidebar: sidebar },
    SESSION_SIDEBAR_MIN_WIDTH: 160, SESSION_SIDEBAR_MAX_WIDTH: 480,
    document: {
      body: { classList: { add: name => bodyClasses.add(name), remove: name => bodyClasses.delete(name) } },
      addEventListener: (type, handler) => { documentListeners[type] = handler; },
      removeEventListener: (type, handler) => { if (documentListeners[type] === handler) delete documentListeners[type]; },
    },
    scheduleUiSettingsSave: () => { saves += 1; },
  });
  context.bindSessionSidebarResizer(handle);
  return { state, style, classes, bodyClasses, listeners, documentListeners, context, saves: () => saves };
}

test("the list has a resize handle at its trailing edge, and takes the width it is given", () => {
  const sidebar = html.slice(html.indexOf('id="sessionSidebar"'), html.indexOf('<main class="workspace">'));
  assert.match(sidebar, /<div class="session-sidebar-resizer" id="sessionSidebarResizer" role="separator" aria-orientation="vertical" aria-label="Resize session list" tabindex="0"><\/div>\s*<\/nav>/);
  const rule = css.match(/^\.session-sidebar \{[^}]*\}/m)[0];
  assert.match(rule, /width: var\(--session-sidebar-width, 208px\);/);
  assert.match(rule, /position: relative;/);
  assert.match(css, /^\.session-sidebar-resizer \{[^}]*cursor: col-resize;/m);
  assert.match(appSource, /bindSessionSidebarResizer\(els\.sessionSidebarResizer\);/);
});

test("a saved width is kept between the narrowest and widest the list goes", () => {
  const { context } = fixture();
  assert.equal(context.sanitizeSessionSidebarWidth(300.4), 300);
  assert.equal(context.sanitizeSessionSidebarWidth(20), 160);
  assert.equal(context.sanitizeSessionSidebarWidth(9999), 480);
  for (const nothing of [null, undefined, 0, -5, "wide", NaN]) assert.equal(context.sanitizeSessionSidebarWidth(nothing), null);
});

test("dragging the handle follows the pointer and saves once, when it is let go", () => {
  const f = fixture(208);
  let prevented = 0;
  f.listeners.mousedown({ clientX: 208, preventDefault() { prevented += 1; } });
  assert.equal(prevented, 1, "no text is selected by the drag");
  assert.ok(f.bodyClasses.has("pane-resizing-x") && f.classes.has("active"));
  f.documentListeners.mousemove({ clientX: 300 });
  assert.equal(f.state.sessionSidebarWidth, 300);
  assert.equal(f.style.get("--session-sidebar-width"), "300px");
  f.documentListeners.mousemove({ clientX: 40 });
  assert.equal(f.state.sessionSidebarWidth, 160, "no narrower than its rows can be read");
  f.documentListeners.mousemove({ clientX: 900 });
  assert.equal(f.state.sessionSidebarWidth, 480);
  assert.equal(f.saves(), 0);
  f.documentListeners.mouseup();
  assert.equal(f.saves(), 1);
  assert.ok(!f.bodyClasses.has("pane-resizing-x") && !f.classes.has("active"));
  assert.deepEqual(Object.keys(f.documentListeners), [], "the drag is over");
});

test("the arrow keys move the edge, and a double-click puts the width back", () => {
  const f = fixture(208);
  const key = name => { let prevented = 0; f.listeners.keydown({ key: name, preventDefault() { prevented += 1; } }); return prevented; };
  assert.equal(key("ArrowRight"), 1);
  assert.equal(f.state.sessionSidebarWidth, 232);
  assert.equal(key("ArrowLeft"), 1);
  assert.equal(f.state.sessionSidebarWidth, 208);
  assert.equal(key("Enter"), 0);
  assert.equal(f.saves(), 2);
  f.listeners.dblclick();
  assert.equal(f.state.sessionSidebarWidth, null);
  assert.equal(f.style.has("--session-sidebar-width"), false, "the stylesheet's own width");
  assert.equal(f.saves(), 3);
});

test("the width is read from the settings and written back to them", () => {
  assert.match(appSource, /state\.sessionSidebarWidth = sanitizeSessionSidebarWidth\(snapshot\?\.session_sidebar_width\);\n\s*applySessionSidebarWidth\(\);/);
  assert.match(appSource, /session_sidebar_width: state\.sessionSidebarWidth > 0 \? state\.sessionSidebarWidth : null,/);
});
