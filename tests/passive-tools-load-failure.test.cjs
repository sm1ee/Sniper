// Tools load-error presentation only. Extracted production functions run against
// inert script nodes and initialization stubs; no asset contents, transforms,
// app bootstrap, browser, runtime, requests, clipboard, or user data are used.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");
const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
const noticeMarkup = html.match(/<p\b([^>]*\bid="toolsLoadError"[^>]*)>([^<]*)<\/p>/);
const nextTurn = () => new Promise(resolve => setImmediate(resolve));
const privateError = "private synthetic initialization detail";

function fixture({ missingGlobals = false, partialFailure = false } = {}) {
  const scripts = [], bindings = [], errors = [], focusMoves = [], scrolls = [];
  const state = { activeTool: "tools", toolsReady: false };
  const activeElement = { name: "existing focus" };
  const document = { activeElement };
  function element(initialClasses = []) {
    const classes = new Set(initialClasses), listeners = new Map();
    let text = "";
    const value = {
      dataset: {}, classWrites: 0, textWrites: 0,
      get textContent() { return text; },
      set textContent(next) { this.textWrites++; text = next; },
      classList: {
        contains: name => classes.has(name),
        add(name) { value.classWrites++; classes.add(name); },
        remove(name) { value.classWrites++; classes.delete(name); },
        toggle(name, force = !classes.has(name)) {
          value.classWrites++;
          if (force) classes.add(name); else classes.delete(name);
        },
      },
      addEventListener(type, callback, options) {
        if (!listeners.has(type)) listeners.set(type, []);
        listeners.get(type).push({ callback, once: options?.once === true });
      },
      dispatch(type) {
        const handlers = [...(listeners.get(type) || [])];
        listeners.set(type, handlers.filter(handler => !handler.once));
        handlers.forEach(handler => handler.callback());
      },
      listenerCount: () => [...listeners.values()].reduce((count, list) => count + list.length, 0),
      focus() { focusMoves.push(value); document.activeElement = value; },
      remove() { assert.fail("Failure guidance must not remove or retry scripts"); },
    };
    return value;
  }
  const els = Object.fromEntries([
    "dashboardShell", "proxyShell", "replayShell", "toolsShell", "fuzzerShell",
    "sequenceShell", "targetShell", "loggerShell", "toolsActiveToolTitle",
  ].map(name => [name, element()]));
  els.toolsLoadError = element(["hidden"]);
  els.toolsLoadError.textContent = noticeMarkup?.[2] || "";
  els.toolsLoadError.textWrites = 0;
  const input = element();
  input.value = "unsaved fixture text";
  document.getElementById = id => id === "input-value" ? input : null;
  document.createElement = tag => {
    assert.equal(tag, "script", "Only inert script nodes may be created");
    return element();
  };
  document.head = { appendChild: script => scripts.push(script) };
  document.querySelector = selector => {
    if (selector === "#tabs li.on") return { textContent: "Encode" };
    const match = selector.match(/^script\[data-dynamic-src="([^"]+)"\]$/);
    assert.ok(match, `Unexpected synthetic DOM query: ${selector}`);
    return scripts.find(script => script.dataset.dynamicSrc === match[1]) || null;
  };
  let updates = 0;
  const window = missingGlobals ? {} : {
    tabs: { encode: "fixture" },
    jQuery: selector => ({ on(type, callback) { bindings.push({ selector, type, callback }); } }),
    hasher: {
      update() { assert.fail("No transform may execute in a presentation test"); },
      updateUI() { updates++; if (partialFailure) throw new Error(privateError); },
    },
    autoScroll: shell => scrolls.push(shell),
  };
  const context = loadFunctions([
    "renderToolPanels", "ensureDecoderWorkbench", "bootToolsWorkbench", "loadScriptOnce", "syncDecoderToolMeta",
  ], {
    state, els, document, window, mainTabs: [], toolsBootPromise: null,
    DECODER_SCRIPT_SOURCES: ["/fixture-private-first.js", "/fixture-private-second.js"],
    sanitizeActiveTool: tool => tool, renderDashboard() {}, renderProxyPanels() {},
    renderReplay() {}, renderFuzzer() {}, renderSequencePanel() {}, renderTarget() {}, renderEventLog() {},
    console: { error: error => errors.push(error) },
    fetch() { assert.fail("No request may execute in a presentation test"); },
    showToast() { assert.fail("Tools failure guidance must remain inside its panel"); },
  });
  function render(tool = state.activeTool) {
    state.activeTool = tool;
    context.renderToolPanels();
  }
  async function loadAll() {
    for (let index = 0; index < 2; index++) {
      assert.equal(scripts.length, index + 1);
      scripts[index].dispatch("load");
      await nextTurn();
    }
  }
  function assertUnchangedFocusAndDraft() {
    assert.equal(document.activeElement, activeElement);
    assert.deepEqual(focusMoves, []);
    assert.equal(input.value, "unsaved fixture text");
  }
  return { context, state, els, scripts, bindings, errors, scrolls, render, loadAll,
    updates: () => updates, assertUnchangedFocusAndDraft };
}

function assertGuidance(f) {
  assert.equal(f.els.toolsLoadError.classList.contains("hidden"), false);
  assert.match(f.els.toolsLoadError.textContent, /Tools.*(?:could not|failed).*load/i);
  assert.match(f.els.toolsLoadError.textContent, /(?:preserve|save).*unsaved work.*reload/i);
  assert.doesNotMatch(f.els.toolsLoadError.textContent, /private|fixture|\.js|Error:/i);
  assert.equal(f.els.toolsLoadError.textWrites, 0, "A static notice must not be rewritten by repeated catches");
  f.assertUnchangedFocusAndDraft();
}

test("Tools guidance is a single initially hidden, polite status inside the Tools panel", () => {
  assert.ok(noticeMarkup, "Tools needs a visible load-failure notice");
  assert.equal((html.match(/id="toolsLoadError"/g) || []).length, 1);
  assert.match(noticeMarkup[1], /class="[^"]*\bhidden\b/);
  assert.match(noticeMarkup[1], /role="status"/);
  assert.match(noticeMarkup[1], /aria-live="polite"/);
  assert.doesNotMatch(noticeMarkup[1], /tabindex|onclick/);
  const start = html.indexOf('id="toolsShell"');
  const end = html.indexOf('id="fuzzerShell"', start);
  assert.ok(start < noticeMarkup.index && noticeMarkup.index < end);
  assert.match(appSource, /toolsLoadError:\s*document\.getElementById\("toolsLoadError"\)/);
});

for (const failure of ["first script", "later script", "missing globals", "partial initialization"]) {
  test(`${failure} failure shows reload guidance and preserves the failed boot without retries`, async () => {
    const f = fixture({ missingGlobals: failure === "missing globals", partialFailure: failure === "partial initialization" });
    f.render();
    const boot = f.context.toolsBootPromise;
    if (failure === "first script") f.scripts[0].dispatch("error");
    else if (failure === "later script") {
      f.scripts[0].dispatch("load"); await nextTurn(); f.scripts[1].dispatch("error");
    } else await f.loadAll();
    await nextTurn();
    assertGuidance(f);
    assert.equal(f.state.toolsReady, false);
    assert.equal(f.errors.length, 1);
    if (failure === "partial initialization") {
      assert.equal(f.bindings.length, 2, "The failing initialization already bound both handlers");
      assert.equal(f.errors[0].message, privateError);
    } else assert.equal(f.bindings.length, 0);
    const before = { scripts: f.scripts.length, bindings: f.bindings.length, updates: f.updates(),
      listeners: f.scripts.map(script => script.listenerCount()), writes: f.els.toolsLoadError.classWrites };
    for (let index = 0; index < 5; index++) f.render();
    await nextTurn();
    f.render("dashboard");
    assert.equal(f.els.toolsShell.classList.contains("hidden"), true);
    f.render("tools"); await nextTurn();
    assertGuidance(f);
    assert.equal(f.context.toolsBootPromise, boot);
    assert.deepEqual({ scripts: f.scripts.length, bindings: f.bindings.length, updates: f.updates(),
      listeners: f.scripts.map(script => script.listenerCount()), writes: f.els.toolsLoadError.classWrites }, before);
    assert.equal(before.writes, 1, "Repeated renders must not re-announce the status");
    assert.deepEqual(f.scrolls, []);
  });
}

test("repeated renders while loading do not reveal an error or duplicate script listeners", async () => {
  const f = fixture();
  f.render();
  const boot = f.context.toolsBootPromise;
  for (let index = 0; index < 5; index++) f.render();
  await nextTurn();
  assert.equal(f.els.toolsLoadError.classList.contains("hidden"), true);
  assert.equal(f.els.toolsLoadError.classWrites, 0);
  assert.equal(f.scripts.length, 1);
  assert.equal(f.scripts[0].listenerCount(), 2);
  assert.equal(f.context.toolsBootPromise, boot);
  assert.deepEqual(f.bindings, []);
  assert.deepEqual(f.errors, []);
  f.assertUnchangedFocusAndDraft();
  f.scripts[0].dispatch("error"); await nextTurn();
  assertGuidance(f);
  assert.equal(f.els.toolsLoadError.classWrites, 1);
});

test("a late load failure stays silent on another tab and appears on the next Tools visit", async () => {
  const f = fixture();
  f.render();
  f.render("dashboard");
  f.scripts[0].dispatch("error"); await nextTurn();
  assert.equal(f.state.activeTool, "dashboard");
  assert.equal(f.els.toolsShell.classList.contains("hidden"), true);
  assert.equal(f.els.toolsLoadError.classList.contains("hidden"), true);
  assert.equal(f.els.toolsLoadError.classWrites, 0);
  f.assertUnchangedFocusAndDraft();
  f.render("tools"); await nextTurn();
  assertGuidance(f);
  assert.equal(f.els.toolsLoadError.classWrites, 1);
  assert.equal(f.scripts.length, 1);
});

test("returning to Tools before a pending failure reveals just one notice", async () => {
  const f = fixture();
  f.render(); f.render("dashboard"); f.render("tools");
  f.scripts[0].dispatch("error"); await nextTurn();
  assertGuidance(f);
  assert.equal(f.els.toolsLoadError.classWrites, 1);
  assert.equal(f.scripts.length, 1);
});

test("successful inert initialization and later visits keep the error hidden without rebinding", async () => {
  const f = fixture();
  f.render(); await f.loadAll();
  assert.equal(f.state.toolsReady, true);
  assert.equal(f.bindings.length, 2);
  assert.equal(f.updates(), 1);
  assert.equal(f.els.toolsActiveToolTitle.textContent, "Encode output");
  f.render(); f.render("dashboard"); f.render("tools"); await nextTurn();
  assert.equal(f.els.toolsLoadError.classList.contains("hidden"), true);
  assert.equal(f.els.toolsLoadError.classWrites, 0);
  assert.equal(f.els.toolsLoadError.textWrites, 0);
  assert.equal(f.scripts.length, 2);
  assert.equal(f.bindings.length, 2);
  assert.equal(f.updates(), 1);
  assert.deepEqual(f.errors, []);
  assert.deepEqual(f.scrolls, [f.els.toolsShell]);
  f.assertUnchangedFocusAndDraft();
});
