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
  const row = (id) => rows.get(id) || rows.set(id, { dataset: { id }, classList: classes(), title: "" }).get(id);
  const field = (value = "") => ({ value, checked: false, focused: false, focus() { this.focused = true; } });
  const els = {
    matchReplaceTableBody: { innerHTML: "", querySelectorAll: (selector) => (selector === "tr[data-id]"
      ? state.matchReplaceRules.map((item) => row(item.id)) : []) },
    matchReplaceEditorHeader: { classList: classes() }, matchReplaceForm: { classList: classes() },
    matchReplaceEmpty: { classList: classes() }, matchReplaceEditorPath: {}, matchReplaceEditorTitle: {},
    matchReplaceScope: field("request"), matchReplaceTarget: field("any"), matchReplaceSearch: field(),
    matchReplaceReplace: field(), matchReplaceRegex: field(), matchReplaceCaseSensitive: field(),
    deleteMatchReplaceRuleButton: { disabled: false }, saveMatchReplaceRuleButton: { disabled: false },
  };
  const requests = [];
  const c = loadFunctions(["renderMatchReplaceRules", "getSelectedMatchReplaceRule", "syncMatchReplaceEditor",
    "createNewMatchReplaceRule", "updateMatchReplaceSaveState", "matchReplaceRuleUnsaved",
    "untouchedNewMatchReplaceRule", "saveMatchReplaceSwitch", "jsonArray"], {
    state, els, escapeHtml: (value) => String(value), generateUuid: () => "new-rule",
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
