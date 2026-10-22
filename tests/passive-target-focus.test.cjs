// Offline Target rendering and focus contracts with inert example.com data.
// The supplied DOM models node replacement/focus; this is not browser or native
// GUI proof, and no app bootstrap, scope action, API, or clipboard is exercised.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function classes(initial = []) {
  const values = new Set(initial);
  return {
    contains: value => values.has(value),
    add: value => values.add(value),
    remove: value => values.delete(value),
  };
}

function decodeAttribute(text) {
  const entities = { amp: "&", lt: "<", gt: ">", quot: '"', "#039": "'" };
  return text.replace(/&(amp|lt|gt|quot|#039);/g, (_, name) => entities[name]);
}

function targetFixture(hosts = ["one.example.com", "two.example.com"]) {
  const document = { activeElement: null };
  let sessionId = "session-one", replaceHook = null;
  const focusCalls = [];
  function node(options = {}) {
    const handlers = new Map();
    const value = {
      dataset: {}, classList: classes(), isConnected: true, disabled: false,
      tabIndex: 0, visibility: "visible", rects: [1], parentElement: null,
      value: "", textContent: "",
      getClientRects() { return this.isConnected ? this.rects : []; },
      contains(child) {
        for (let current = child; current; current = current.parentElement) {
          if (current === this) return true;
        }
        return false;
      },
      closest(selector) {
        assert.equal(selector, ".target-host-toggle");
        for (let current = this; current; current = current.parentElement) {
          if (current.classList.contains("target-host-toggle")) return current;
        }
        return null;
      },
      focus(options) { focusCalls.push({ node: this, options }); document.activeElement = this; },
      addEventListener(type, callback) {
        const callbacks = handlers.get(type) || [];
        callbacks.push(callback);
        handlers.set(type, callbacks);
      },
      click() { handlers.get("click")?.forEach(callback => callback({ target: this })); },
      ...options,
    };
    return value;
  }
  document.body = node();
  document.documentElement = node();
  document.activeElement = document.body;
  let modal = null;
  document.querySelector = selector => {
    assert.equal(selector, ".modal-backdrop:not(.hidden), dialog[open]");
    return modal;
  };
  const els = {
    targetShell: node(), targetScopeEditor: node(), targetScopeExcludeEditor: node(),
    reloadTargetButton: node(), saveTargetScopeButton: node(),
  };
  const tree = node({ parentElement: els.targetShell, buttons: [] });
  tree.querySelectorAll = selector => {
    assert.equal(selector, ".target-host-toggle");
    return tree.buttons;
  };
  let html = "";
  Object.defineProperty(tree, "innerHTML", {
    get: () => html,
    set(value) {
      html = value;
      if (tree.contains(document.activeElement)) document.activeElement = document.body;
      tree.buttons.forEach(button => {
        button.isConnected = false;
        button.parentElement = null;
        button.label.isConnected = false;
      });
      // Read host identity and expansion from the real renderer's markup.
      tree.buttons = [...value.matchAll(/<button\s+([^]*?)<\/button>\s*<div class="target-path-list"([^>]*)>/g)]
        .map(([, content, pathAttrs]) => {
          const host = content.match(/data-target-host="([^"]*)"/);
          assert.ok(host, "Rendered host button must carry its exact identity");
          const expanded = content.match(/aria-expanded="([^"]*)"/)[1];
          const button = node({
            dataset: { targetHost: decodeAttribute(host[1]) },
            classList: classes(["target-host-toggle", ...(expanded === "true" ? ["expanded"] : [])]),
            parentElement: tree, expanded, pathsHidden: /\bhidden\b/.test(pathAttrs),
          });
          button.label = node({ parentElement: button });
          return button;
        });
      replaceHook?.();
    },
  });
  els.targetTree = tree;
  const state = {
    activeTool: "target", runtime: { scope_patterns: [], excluded_scope_patterns: [] },
    targetScopeDirty: false, targetScopeDraft: "", targetScopeExcludeDraft: "",
    targetScopeEditorSessionId: null, targetSiteMap: [], targetExpandedHosts: new Set(),
  };
  const context = loadFunctions([
    "renderTarget", "syncTargetScopeDraft", "formatScopePatternsText", "escapeHtml",
  ], {
    document, els, state,
    window: { getComputedStyle: value => ({ visibility: value.visibility }) },
    currentSessionId: () => sessionId,
    formatStatus: value => String(value), formatTimestamp: value => String(value),
    fetch() { assert.fail("Passive Target tests must not make requests"); },
    copyTextToClipboard() { assert.fail("Passive Target tests must not use clipboard"); },
  });
  const fixture = {
    context, document, els, tree, state, focusCalls, node,
    button(host) { return tree.buttons.find(button => button.dataset.targetHost === host); },
    setHosts(names) {
      state.targetSiteMap = names.map(host => ({
        host, paths: [{ path: "/display-only", methods: ["GET"], status: 200, last_seen: "inert" }],
        schemes: ["https"], request_count: 1, in_scope: false,
      }));
    },
    setSession(value) { sessionId = value; },
    setModal(value) { modal = value; },
    onReplace(callback) { replaceHook = callback; },
    focus(value) { document.activeElement = value; focusCalls.length = 0; },
    render() { context.renderTarget(); },
  };
  fixture.setHosts(hosts);
  fixture.render();
  return fixture;
}

function assertRestored(f, old, host) {
  const replacement = f.button(host);
  assert.notEqual(replacement, old);
  assert.equal(old.isConnected, false);
  assert.equal(f.document.activeElement, replacement);
  assert.equal(f.focusCalls.length, 1);
  assert.equal(f.focusCalls[0].node, replacement);
  assert.equal(f.focusCalls[0].options.preventScroll, true);
}

test("actual Target host click keeps focus on its replacement while expanding and collapsing", () => {
  const f = targetFixture();
  for (const expanded of [true, false, true, false]) {
    const old = f.button("two.example.com");
    f.focus(old);
    old.click();
    assertRestored(f, old, "two.example.com");
    assert.equal(f.state.targetExpandedHosts.has("two.example.com"), expanded);
    assert.equal(f.button("two.example.com").expanded, String(expanded));
    assert.equal(f.button("two.example.com").pathsHidden, !expanded);
    assert.equal(f.button("one.example.com").expanded, "false");
  }
});

test("identical periodic refresh preserves host focus even after forced scope-draft sync", () => {
  const f = targetFixture();
  const old = f.button("two.example.com");
  f.state.targetExpandedHosts.add("two.example.com");
  f.focus(old);
  f.context.syncTargetScopeDraft(true);
  assert.equal(f.state.targetScopeEditorSessionId, null);
  f.render();
  assertRestored(f, old, "two.example.com");
  assert.equal(f.button("two.example.com").expanded, "true");
});

test("focus inside a host button returns to that button after replacement", () => {
  const f = targetFixture();
  const old = f.button("two.example.com");
  f.focus(old.label);
  f.render();
  assertRestored(f, old, "two.example.com");
});

test("reordered hosts retain exact focused identity rather than a list index", () => {
  const f = targetFixture();
  const old = f.button("two.example.com");
  f.focus(old);
  f.setHosts(["two.example.com", "three.example.com", "one.example.com"]);
  f.render();
  assertRestored(f, old, "two.example.com");
});

test("Unicode and quoted host identity survives escaped markup without selector interpolation", () => {
  const host = 'café-文-😀-"quote"-\'single\'-[x]&.example.com';
  const f = targetFixture(["one.example.com", host, "CAFE.example.com"]);
  const old = f.button(host);
  assert.ok(old);
  f.focus(old);
  old.click();
  assertRestored(f, old, host);
  assert.equal(f.state.targetExpandedHosts.has(host), true);
});

test("host matching does not fold case or Unicode normalization when the exact host disappears", () => {
  const host = "Café.example.com";
  const f = targetFixture([host, "café.example.com", "Cafe\u0301.example.com"]);
  f.focus(f.button(host));
  f.setHosts(["café.example.com", "Cafe\u0301.example.com"]);
  f.render();
  assert.equal(f.document.activeElement, f.document.body);
  assert.equal(f.focusCalls.length, 0);
});

for (const remaining of [["one.example.com"], []]) {
  test(`removed focused host has no fallback with ${remaining.length} remaining hosts`, () => {
    const f = targetFixture();
    f.state.targetExpandedHosts.add("two.example.com");
    f.focus(f.button("two.example.com"));
    f.setHosts(remaining);
    f.render();
    assert.equal(f.document.activeElement, f.document.body);
    assert.equal(f.focusCalls.length, 0);
    assert.equal(f.state.targetExpandedHosts.has("two.example.com"), false);
    if (!remaining.length) assert.match(f.tree.innerHTML, /No targets yet/);
  });
}

test("initial render and unchanged empty state do not invent focus", () => {
  const f = targetFixture([]);
  f.render();
  assert.equal(f.document.activeElement, f.document.body);
  assert.equal(f.focusCalls.length, 0);
});

for (const name of ["targetScopeEditor", "targetScopeExcludeEditor", "reloadTargetButton", "saveTargetScopeButton"]) {
  test(`Target refresh leaves ${name} focus and unsaved scope text alone`, () => {
    const f = targetFixture();
    f.state.targetScopeDirty = true;
    f.state.targetScopeDraft = "*.draft.example.com";
    f.state.targetScopeExcludeDraft = "excluded.example.com";
    f.els.targetScopeEditor.value = f.state.targetScopeDraft;
    f.els.targetScopeExcludeEditor.value = f.state.targetScopeExcludeDraft;
    f.focus(f.els[name]);
    f.render();
    assert.equal(f.document.activeElement, f.els[name]);
    assert.equal(f.focusCalls.length, 0);
    assert.equal(f.els.targetScopeEditor.value, "*.draft.example.com");
    assert.equal(f.els.targetScopeExcludeEditor.value, "excluded.example.com");
    assert.equal(f.state.targetScopeDirty, true);
  });
}

test("a similarly classed button outside the current Target tree never transfers focus", () => {
  const f = targetFixture();
  const outside = f.node({ classList: classes(["target-host-toggle"]), dataset: { targetHost: "two.example.com" } });
  f.focus(outside);
  f.render();
  assert.equal(f.document.activeElement, outside);
  assert.equal(f.focusCalls.length, 0);
});

for (const moment of ["before", "during"]) {
  for (const kind of ["other control", "modal"]) {
    test(`${kind} focused ${moment} Target replacement is never displaced`, () => {
      const f = targetFixture();
      const other = f.node();
      const change = () => {
        if (kind === "modal") f.setModal(f.node());
        f.document.activeElement = other;
      };
      f.focus(f.button("two.example.com"));
      if (moment === "before") change(); else f.onReplace(change);
      f.render();
      assert.equal(f.document.activeElement, other);
      assert.equal(f.focusCalls.length, 0);
    });
  }
}

test("a newer unrelated detached focus owner is not treated as lost host focus", () => {
  const f = targetFixture();
  const other = f.node({ isConnected: false });
  f.focus(f.button("two.example.com"));
  f.onReplace(() => { f.document.activeElement = other; });
  f.render();
  assert.equal(f.document.activeElement, other);
  assert.equal(f.focusCalls.length, 0);
});

for (const remainingFocus of ["null", "original detached element"]) {
  test(`replacement restores the host when focus is ${remainingFocus}`, () => {
    const f = targetFixture();
    const old = f.button("two.example.com");
    f.focus(old);
    f.onReplace(() => { f.document.activeElement = remainingFocus === "null" ? null : old; });
    f.render();
    assertRestored(f, old, "two.example.com");
  });
}

for (const [name, change] of [
  ["disabled", button => { button.disabled = true; }],
  ["unfocusable", button => { button.tabIndex = -1; }],
  ["detached", button => { button.isConnected = false; }],
  ["without layout", button => { button.rects = []; }],
  ["hidden", button => { button.visibility = "hidden"; }],
]) {
  test(`a ${name} replacement host button does not receive focus`, () => {
    const f = targetFixture();
    f.focus(f.button("two.example.com"));
    f.onReplace(() => change(f.button("two.example.com")));
    f.render();
    assert.equal(f.document.activeElement, f.document.body);
    assert.equal(f.focusCalls.length, 0);
  });
}

for (const moment of ["before", "during"]) {
  for (const [name, change] of [
    ["inactive Target", f => { f.state.activeTool = "proxy"; }],
    ["hidden Target panel", f => { f.els.targetShell.classList.add("hidden"); }],
    ["hidden tree layout", f => { f.tree.rects = []; }],
    ["hidden tree visibility", f => { f.tree.visibility = "hidden"; }],
    ["detached tree", f => { f.tree.isConnected = false; }],
    ["visible modal", f => { f.setModal(f.node()); }],
  ]) {
    test(`${name} ${moment} render suppresses focus restoration`, () => {
      const f = targetFixture();
      f.focus(f.button("two.example.com"));
      if (moment === "before") change(f); else f.onReplace(() => change(f));
      f.render();
      assert.equal(f.document.activeElement, f.document.body);
      assert.equal(f.focusCalls.length, 0);
    });
  }
}

test("replacing the Target tree reference during rendering prevents stale-tree restoration", () => {
  const f = targetFixture();
  f.focus(f.button("two.example.com"));
  f.onReplace(() => { f.els.targetTree = f.node({ querySelectorAll: () => [] }); });
  f.render();
  assert.equal(f.document.activeElement, f.document.body);
  assert.equal(f.focusCalls.length, 0);
});

for (const moment of ["before", "during"]) {
  test(`session change ${moment} render does not transfer focus to the same host in a different session`, () => {
    const f = targetFixture();
    f.focus(f.button("two.example.com"));
    const change = () => { f.setSession("session-two"); f.context.syncTargetScopeDraft(true); };
    if (moment === "before") change(); else f.onReplace(change);
    f.render();
    assert.equal(f.document.activeElement, f.document.body);
    assert.equal(f.focusCalls.length, 0);
  });
}

test("after a session change the freshly rendered tree can preserve its own focus", () => {
  const f = targetFixture();
  f.setSession("session-two");
  f.context.syncTargetScopeDraft(true);
  f.render();
  const old = f.button("two.example.com");
  f.focus(old);
  old.click();
  assertRestored(f, old, "two.example.com");
});

test("a tree without a current session never restores a previous host's focus", () => {
  const f = targetFixture();
  f.setSession(null);
  f.render();
  f.focus(f.button("two.example.com"));
  f.context.syncTargetScopeDraft(true);
  f.render();
  assert.equal(f.document.activeElement, f.document.body);
  assert.equal(f.focusCalls.length, 0);
});


test("Recon discoveries show provenance without implying captured traffic or a live status", () => {
  const f = targetFixture(["example.com"]);
  f.state.targetSiteMap[0].request_count = 0;
  f.state.targetSiteMap[0].paths = [{
    path: "/archived?item=1", methods: ["GET"], status: null,
    captured: false, discovered: true, last_seen: "discovery-time",
    recon_sources: ["wayback", "<script>"], recon_kinds: ["history", "candidate"],
  }];
  f.render();
  assert.match(f.tree.innerHTML, /0 captured requests/);
  assert.match(f.tree.innerHTML, /Recon discovery · not captured/);
  assert.match(f.tree.innerHTML, /Last discovered: discovery-time/);
  assert.match(f.tree.innerHTML, /Recon: wayback, &lt;script&gt; · history, candidate/);
  assert.doesNotMatch(f.tree.innerHTML, /null|<script>|Last captured/);
});

test("captured paths with Recon evidence retain captured status and source labels", () => {
  const f = targetFixture(["example.com"]);
  Object.assign(f.state.targetSiteMap[0].paths[0], {
    captured: true, discovered: true, recon_sources: ["crawler"], recon_kinds: ["live"],
  });
  f.render();
  assert.match(f.tree.innerHTML, /Captured \+ Recon · GET · 200 · Last captured: inert/);
  assert.match(f.tree.innerHTML, /Recon: crawler · live/);
  assert.doesNotMatch(f.tree.innerHTML, /not captured/);
});

test("legacy sitemap responses remain captured and empty state offers Recon", () => {
  const f = targetFixture(["example.com"]);
  assert.match(f.tree.innerHTML, /Captured · GET · 200 · Last captured: inert/);
  f.setHosts([]);
  f.render();
  assert.match(f.tree.innerHTML, /Capture proxy traffic or run Recon/);
});
