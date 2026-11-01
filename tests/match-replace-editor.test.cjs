// The Replace editor offers fields only for a rule that exists, saves on Save,
// and lets the On switch save only itself. Synthetic rules only.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const tick = () => new Promise((resolve) => setImmediate(resolve));
const classes = () => {
  const set = new Set();
  return { add: (name) => set.add(name), remove: (name) => set.delete(name), contains: (name) => set.has(name),
    toggle: (name, on) => (on ? set.add(name) : set.delete(name)) };
};
const rule = (id, extra = {}) => ({ id, enabled: true, description: "", scope: "request", target: "any",
  search: `${id}.example.com`, replace: "bar.example.com", regex: false, case_sensitive: false, ...extra });

function fixture(saved = []) {
  const state = {
    matchReplaceRules: saved.map((item) => ({ ...item })), matchReplaceSavedRules: saved.map((item) => ({ ...item })),
    selectedMatchReplaceRuleId: saved[0]?.id ?? null, matchReplaceDirty: false, matchReplaceDraftVersion: 0,
    activeSession: { id: "session-a" },
  };
  const rows = new Map();
  const row = (id) => rows.get(id) || rows.set(id, { dataset: { id }, classList: classes(), title: "", listeners: {}, addEventListener(name, handler) { this.listeners[name] = handler; } }).get(id);
  const field = (value = "") => ({ value, checked: false, focused: false, focus() { this.focused = true; } });
  const els = {
    matchReplaceTableBody: { innerHTML: "", querySelectorAll: (selector) => ((selector === "tr[data-id]" || selector === ".history-row")
      ? state.matchReplaceRules.map((item) => row(item.id)) : []) },
    matchReplaceEditorHeader: { classList: classes() }, matchReplaceForm: { classList: classes() },
    matchReplaceEmpty: { classList: classes() }, matchReplaceEditorPath: {}, matchReplaceEditorTitle: {},
    matchReplaceScope: field("request"), matchReplaceTarget: field("any"), matchReplaceSearch: field(),
    matchReplaceReplace: field(), matchReplaceReplaceEnabled: { ...field(), checked: true },
    matchReplaceAnnotationNote: field(), matchReplaceAnnotationColor: field(), matchReplaceAnnotation: { open: false },
    matchReplaceRegex: field(), matchReplaceCaseSensitive: field(),
    deleteMatchReplaceRuleButton: { disabled: false }, saveMatchReplaceRuleButton: { disabled: false },
  };
  const requests = [];
  const c = loadFunctions(["renderMatchReplaceRules", "getSelectedMatchReplaceRule", "syncMatchReplaceEditor", "matchReplaceRuleActivity", "setMatchReplaceRuleActivity", "canonicalMatchReplaceRule", "matchReplaceRulesPayload", "matchReplaceRuleActions", "matchReplaceRuleTitle", "getMatchReplaceSaveOwner", "beginMatchReplaceWrite", "matchReplaceWriteIsCurrent", "acknowledgeMatchReplaceRules", "finishMatchReplaceWrite",
    "createNewMatchReplaceRule", "updateMatchReplaceSaveState", "matchReplaceRuleUnsaved",
    "untouchedNewMatchReplaceRule", "saveMatchReplaceSwitch", "jsonArray"], {
    state, els, TextEncoder, HTTP_COLOR_TAG_OPTIONS: new Set(["red", "orange", "yellow", "green", "blue", "purple"]), workspaceStateGeneration: 0, escapeHtml: (value) => String(value).replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`), generateUuid: () => "new-rule",
    currentSessionId: () => "session-a", sessionWritePath: (path) => path,
    requireOkResponse: async () => {}, saveMatchReplaceRules: async () => requests.push("full save"),
    fetch: async (url, options) => {
      requests.push(JSON.parse(options.body));
      return { json: async () => JSON.parse(options.body).rules };
    },
  });
  const edit = (name, value) => { els[name].value = value; c.syncMatchReplaceEditor(); c.updateMatchReplaceSaveState(); };
  return { c, state, els, row, requests, edit };
}

test("with no rule selected, the editor says how to start instead of offering fields", () => {
  const f = fixture();
  f.c.renderMatchReplaceRules();
  assert.equal(f.els.matchReplaceForm.classList.contains("hidden"), true);
  assert.equal(f.els.matchReplaceEditorHeader.classList.contains("hidden"), true);
  assert.equal(f.els.matchReplaceEmpty.classList.contains("hidden"), false);
  assert.equal(f.els.deleteMatchReplaceRuleButton.disabled, true);
});

test("Add opens a new rule's fields; Save waits for a search term", () => {
  const f = fixture();
  f.c.createNewMatchReplaceRule();
  assert.equal(f.els.matchReplaceForm.classList.contains("hidden"), false);
  assert.equal(f.els.matchReplaceEmpty.classList.contains("hidden"), true);
  assert.equal(f.els.matchReplaceEditorTitle.textContent, "New rule");
  assert.equal(f.els.saveMatchReplaceRuleButton.disabled, true);
  f.edit("matchReplaceReplace", "bar.example.com");
  assert.equal(f.els.saveMatchReplaceRuleButton.disabled, true, "a rule with no search term matches nothing");
  f.edit("matchReplaceSearch", "foo.example.com");
  assert.equal(f.els.saveMatchReplaceRuleButton.disabled, false);
  assert.equal(f.row("new-rule").classList.contains("unsaved"), true);
});

test("a saved rule's Save stays off until it is changed, and off again once changed back", () => {
  const f = fixture([rule("a")]);
  f.c.renderMatchReplaceRules();
  assert.equal(f.els.saveMatchReplaceRuleButton.disabled, true);
  f.edit("matchReplaceReplace", "baz.example.com");
  assert.equal(f.els.saveMatchReplaceRuleButton.disabled, false);
  assert.equal(f.row("a").classList.contains("unsaved"), true);
  f.edit("matchReplaceReplace", "bar.example.com");
  assert.equal(f.els.saveMatchReplaceRuleButton.disabled, true);
  assert.equal(f.row("a").classList.contains("unsaved"), false);
});

test("the On switch saves only itself while another rule has unsaved edits", async () => {
  const f = fixture([rule("a"), rule("b")]);
  f.c.renderMatchReplaceRules();
  f.edit("matchReplaceSearch", "draft.example.com");
  f.state.matchReplaceRules[1].enabled = false;
  await f.c.saveMatchReplaceSwitch("b", false);
  assert.equal(f.requests.length, 1);
  const [a, b] = f.requests[0].rules;
  assert.equal(a.search, "a.example.com", "the edit stays a draft");
  assert.equal(b.enabled, false);
  assert.equal(f.state.matchReplaceRules[0].search, "draft.example.com");
  assert.equal(f.state.matchReplaceSavedRules[1].enabled, false);
  f.c.updateMatchReplaceSaveState();
  assert.equal(f.row("a").classList.contains("unsaved"), true);
  assert.equal(f.row("b").classList.contains("unsaved"), false);
});

test("with nothing unsaved, the On switch takes the ordinary save", async () => {
  const f = fixture([rule("a")]);
  f.state.matchReplaceRules[0].enabled = false;
  await f.c.saveMatchReplaceSwitch("a", false);
  assert.deepEqual(f.requests, ["full save"]);
  await tick();
});

test("a button whose state depends on the work can set it once progress has ended", async () => {
  let click;
  const button = { disabled: false, classList: { add() {}, remove() {} }, addEventListener: (_, handler) => { click = handler; } };
  const c = loadFunctions(["onClickWithProgress", "withButtonProgress"], {
    setTimeout, clearTimeout, BUTTON_PROGRESS_DELAY_MS: 180,
  });
  c.onClickWithProgress(button, async () => {}, () => { button.disabled = true; });
  click({});
  await tick();
  assert.equal(button.disabled, true, "nothing is left to save, so Save stays off");
});

test("only a new rule with nothing typed in it counts as untouched", () => {
  const f = fixture([rule("a")]);
  assert.equal(f.c.untouchedNewMatchReplaceRule(), null, "a saved rule is never dropped");
  f.c.createNewMatchReplaceRule();
  assert.equal(f.c.untouchedNewMatchReplaceRule()?.id, "new-rule");
  f.edit("matchReplaceSearch", "foo.example.com");
  assert.equal(f.c.untouchedNewMatchReplaceRule(), null);
});

// Only local selection is exercised here: any request/save path fails closed.
function localSelectionFixture(saved) {
  const f = fixture(saved);
  const forbidden = () => { throw new Error("Selection must not save or request"); };
  f.c.fetch = forbidden;
  f.c.saveMatchReplaceRules = forbidden;
  f.c.saveMatchReplaceSwitch = forbidden;
  f.c.renderMatchReplaceRules();
  return f;
}

test("rule controls have escaped payload-free names and native edit buttons", () => {
  const f = localSelectionFixture([
    rule("a", { scope: 'request"<', target: 'body&', search: "private-search", replace: "private-replacement" }),
    rule("b", { annotation_only_enabled: false, annotation_note: "private-note", target: "header_value" }),
  ]);
  const html = f.els.matchReplaceTableBody.innerHTML;
  assert.match(html, /<button type="button" class="match-replace-edit-rule" aria-label="Edit rule 1: request&#34;&#60; \/ body&#38;">body&#38;<\/button>/);
  assert.match(html, /aria-label="Enable rule 2: request \/ header_value"/);
  const labels = [...html.matchAll(/aria-label="([^"]*)"/g)].map(m => m[1]);
  assert.equal(labels.length, 4);
  assert.equal(new Set(labels).size, 4);
  assert.ok(labels.every(label => !/private-|a.example.com|b.example.com/.test(label)));
  assert.doesNotMatch(html, /<tr[^>]*(?:tabindex|role)=/);
  const empty = localSelectionFixture([]);
  assert.doesNotMatch(empty.els.matchReplaceTableBody.innerHTML, /match-replace-edit-rule|data-rule-toggle/);
});

test("native rule edit activation selects once then focuses the rendered Search field", () => {
  const f = localSelectionFixture([rule("a"), rule("b")]);
  let renders = 0;
  const render = f.c.renderMatchReplaceRules;
  f.c.renderMatchReplaceRules = () => { renders++; render(); };
  f.els.matchReplaceSearch.focus = () => {
    assert.equal(f.state.selectedMatchReplaceRuleId, "b");
    assert.equal(f.els.matchReplaceSearch.value, "b.example.com");
    assert.equal(renders, 1);
    f.els.matchReplaceSearch.focused = true;
  };
  f.row("b").listeners.click({ target: { closest: selector => selector === ".match-replace-edit-rule" ? {} : null } });
  assert.equal(f.els.matchReplaceSearch.focused, true);
  assert.equal(f.state.matchReplaceDirty, false);
  assert.deepEqual(f.requests, []);
});

test("ordinary rule clicks retain focus behavior and toggle clicks never select", () => {
  const f = localSelectionFixture([rule("a"), rule("b")]);
  f.row("b").listeners.click({ target: { closest: () => null } });
  assert.equal(f.state.selectedMatchReplaceRuleId, "b");
  assert.equal(f.els.matchReplaceSearch.focused, false);
  f.row("a").listeners.click({ target: { closest: selector => selector === ".mini-toggle" ? {} : null } });
  assert.equal(f.state.selectedMatchReplaceRuleId, "b");
  assert.equal(f.state.matchReplaceDirty, false);
  assert.deepEqual(f.requests, []);
});

test("rule table edit buttons and transparent toggles expose scoped keyboard focus", () => {
  const fs = require("node:fs");
  const path = require("node:path");
  const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");
  assert.match(css, /#matchReplaceTableBody \.match-replace-edit-rule:focus-visible,\s*#matchReplaceTableBody \.mini-toggle input:focus-visible \+ \.mini-toggle-track\s*\{[^}]*outline: 2px solid var\(--point\);/);
});

test("search options sit next to Search before replacement and annotation actions", () => {
  const fs = require("node:fs");
  const path = require("node:path");
  const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
  const form = html.slice(html.indexOf('id="matchReplaceForm"'), html.indexOf('<section class="proxy-panel hidden" id="findingsPanel"'));
  const ordered = ["matchReplaceSearch", "matchReplaceRegex", "matchReplaceCaseSensitive", "matchReplaceReplaceEnabled", "matchReplaceAnnotation"];
  let previous = -1;
  for (const id of ordered) {
    const marker = `id="${id}"`;
    assert.equal(form.split(marker).length - 1, 1, `${id} must remain unique`);
    const index = form.indexOf(marker);
    assert.ok(index > previous, `${id} must follow the prior control`);
    previous = index;
  }
  assert.match(form, /class="match-replace-search-group"[\s\S]*?<label class="settings-field">\s*<span>Search<\/span>\s*<input id="matchReplaceSearch"/);
  assert.match(form, /class="match-replace-search-options">\s*<label class="settings-toggle">\s*<input id="matchReplaceRegex" type="checkbox" \/>\s*<span>Regex<\/span>\s*<\/label>\s*<label class="settings-toggle">\s*<input id="matchReplaceCaseSensitive" type="checkbox" \/>\s*<span>Case sensitive<\/span>/);
});

test("search options wrap without imposing fixed widths", () => {
  const fs = require("node:fs");
  const path = require("node:path");
  const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");
  const options = css.match(/\.match-replace-search-options\s*\{([^}]+)\}/)?.[1];
  assert.ok(options);
  assert.match(options, /display:\s*flex/);
  assert.match(options, /flex-wrap:\s*wrap/);
  assert.doesNotMatch(options, /(?:min-|max-)?width\s*:/);
});
