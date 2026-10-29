// With no sequence the Sequence tool shows one line on what a sequence does
// and the button that makes one, not three empty panes and disabled buttons.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture(definitions, editing = null) {
  const nodes = new Map();
  const node = () => {
    const names = new Set();
    return {
      innerHTML: "", textContent: "", disabled: false, querySelectorAll: () => [],
      classList: { toggle: (n, on) => (on ? names.add(n) : names.delete(n)), contains: (n) => names.has(n) },
    };
  };
  const document = { getElementById: (id) => nodes.get(id) || nodes.set(id, node()).get(id) };
  const state = {
    sequenceDefinitions: definitions, sequencePastRuns: [], selectedSequenceId: definitions[0]?.id || null,
    editingSequence: editing, sequenceRunning: false, sequenceRunResult: null,
  };
  const c = loadFunctions(["renderSequencePanel", "renderSequenceList", "sequenceDisplayName", "sequenceNameInputValue", "syncSequenceRunButton"], {
    document, state, escapeHtml: String, formatTimestamp: String, normalizeSequenceRunResult: () => null,
    jsonArray: (value) => (Array.isArray(value) ? value : []),
  });
  return { c, el: (id) => document.getElementById(id) };
}

const hidden = (f, id) => f.el(id).classList.contains("hidden");

test("no sequence: the empty state stands in for the header and the panes", () => {
  const f = fixture([]);
  f.c.renderSequencePanel();
  assert.equal(hidden(f, "sequenceEmpty"), false);
  assert.equal(hidden(f, "sequenceHeader"), true);
  assert.equal(hidden(f, "sequenceLayout"), true);
});

test("with sequences the panes return, and the editor's buttons wait for a sequence", () => {
  const f = fixture([{ id: "seq-1", name: "Login", steps: [] }]);
  f.c.renderSequencePanel();
  assert.equal(hidden(f, "sequenceEmpty"), true);
  assert.equal(hidden(f, "sequenceHeader"), false);
  assert.equal(hidden(f, "sequenceLayout"), false);
  for (const id of ["addSequenceStepButton", "saveSequenceButton", "runSequenceButton"]) assert.equal(hidden(f, id), true, id);
});

test("the empty state offers New sequence and names what a step can reuse", () => {
  const html = require("node:fs").readFileSync(require("node:path").join(__dirname, "../web/index.html"), "utf8");
  const empty = html.match(/<section class="sequence-empty hidden" id="sequenceEmpty">[^]*?<\/section>/)[0];
  assert.match(empty, /<code>\{\{variable\}\}<\/code>/);
  assert.match(empty, /id="sequenceEmptyNewButton"[^>]*>New sequence<\/button>/);
});
