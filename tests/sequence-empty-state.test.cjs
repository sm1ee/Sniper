// With no sequence the Sequence tool shows one line on what a sequence does
// and the button that makes one, not three empty panes and disabled buttons.
// Selected-empty guidance and local step edits use inert DOM only: no requests.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture(definitions, editing = null) {
  const nodes = new Map();
  const node = () => {
    const names = new Set();
    return {
      innerHTML: "", textContent: "", disabled: false, querySelectorAll: () => [], addEventListener() {},
      classList: { toggle: (n, on) => (on ? names.add(n) : names.delete(n)), contains: (n) => names.has(n) },
    };
  };
  const document = { getElementById: (id) => nodes.get(id) || nodes.set(id, node()).get(id) };
  const state = {
    sequenceDefinitions: definitions, sequencePastRuns: [], selectedSequenceId: definitions[0]?.id || null,
    editingSequence: editing, sequenceRunning: false, sequenceRunResult: null,
    sequenceDirty: false, sequenceDraftVersion: 0,
  };
  let nextId = 0;
  const c = loadFunctions([
    "renderSequencePanel", "renderSequenceList", "sequenceDisplayName", "sequenceNameInputValue", "syncSequenceRunButton",
    "addSequenceStep", "removeSequenceStep", "markSequenceDraftDirty", "bumpSequenceDraftVersion", "escapeHtml",
  ], {
    document, state, formatTimestamp: String, normalizeSequenceRunResult: () => null,
    jsonArray: (value) => (Array.isArray(value) ? value : []),
    generateUuid: () => `synthetic-step-${++nextId}`, normalizeReplayHttpVersion: value => value,
    buildEditableRawRequest: request => `${request.method} ${request.path} HTTP/1.1`,
    fetch: () => assert.fail("empty guidance and local step edits must not send requests"),
  });
  return { c, state, el: (id) => document.getElementById(id) };
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
  assert.match(f.el("sequenceStepsContainer").innerHTML, /Select or create a sequence to start building steps\./);
  assert.doesNotMatch(f.el("sequenceStepsContainer").innerHTML, /No steps yet/);
});

test("the empty state offers New sequence and names what a step can reuse", () => {
  const html = require("node:fs").readFileSync(require("node:path").join(__dirname, "../web/index.html"), "utf8");
  const empty = html.match(/<section class="sequence-empty hidden" id="sequenceEmpty">[^]*?<\/section>/)[0];
  assert.match(empty, /<code>\{\{variable\}\}<\/code>/);
  assert.match(empty, /id="sequenceEmptyNewButton"[^>]*>New sequence<\/button>/);
});

test("a selected zero-step sequence names the next action without adding controls or changing the draft", () => {
  const definition = { id: "seq-1", name: "New sequence", steps: [] };
  const f = fixture([definition], structuredClone(definition));
  const before = JSON.stringify(f.state.editingSequence);
  f.c.renderSequencePanel();
  const markup = f.el("sequenceStepsContainer").innerHTML;
  assert.equal(markup, '<p class="empty-copy">No steps yet. Choose <strong>+ Step</strong>, then paste a raw HTTP request into the step.</p>');
  assert.doesNotMatch(markup, /<button|<textarea|<summary|\{\{variable\}\}/);
  assert.equal(hidden(f, "sequenceEmpty"), true);
  assert.equal(hidden(f, "sequenceLayout"), false);
  assert.equal(f.el("addSequenceStepButton").disabled, false);
  assert.equal(f.el("runSequenceButton").disabled, true);
  assert.equal(JSON.stringify(f.state.editingSequence), before);
  assert.equal(f.state.sequenceDirty, false);
  assert.equal(f.state.sequenceDraftVersion, 0);
});

test("adding the first local step removes the cue and removing the final step restores it", () => {
  const definition = { id: "seq-1", name: "New sequence", steps: [] };
  const f = fixture([definition], structuredClone(definition));
  f.c.renderSequencePanel();
  for (let repeat = 0; repeat < 2; repeat += 1) {
    f.c.addSequenceStep();
    const step = f.state.editingSequence.steps[0];
    assert.equal(step.request.method, "GET");
    assert.equal(step.request.host, "");
    assert.equal(step.request.path, "/");
    assert.equal(step.extractions.length, 0);
    assert.equal(step.target, null);
    assert.match(f.el("sequenceStepsContainer").innerHTML, /class="step-request-text"/);
    assert.match(f.el("sequenceStepsContainer").innerHTML, /Extractions \(0\)/);
    assert.doesNotMatch(f.el("sequenceStepsContainer").innerHTML, /No steps yet/);
    assert.equal(f.el("runSequenceButton").disabled, false);
    f.c.removeSequenceStep(0);
    assert.equal(f.state.editingSequence.steps.length, 0);
    assert.equal((f.el("sequenceStepsContainer").innerHTML.match(/No steps yet/g) || []).length, 1);
    assert.equal(f.el("runSequenceButton").disabled, true);
  }
  assert.equal(f.state.sequenceDirty, true);
  assert.equal(f.state.sequenceDraftVersion, 4);
});

test("nonempty drafts retain escaped request and extraction markup with unchanged Run availability", () => {
  const definition = { id: "seq-1", name: "Saved sequence", steps: [{
    id: "step-1", label: 'First <step> & "label"', request: {},
    request_text: "GET / HTTP/1.1\nHost: example.com\n\n<draft>&",
    extractions: [{ variable_name: "token", source: "response_header", pattern: "X-Fixture", group: 1 }],
  }] };
  const f = fixture([definition], structuredClone(definition));
  const before = JSON.stringify(f.state.editingSequence);
  f.c.renderSequencePanel();
  const markup = f.el("sequenceStepsContainer").innerHTML;
  assert.match(markup, /value="First &lt;step&gt; &amp; &quot;label&quot;"/);
  assert.ok(markup.includes("GET / HTTP/1.1\nHost: example.com\n\n&lt;draft&gt;&amp;</textarea>"));
  assert.match(markup, /Extractions \(1\)/);
  assert.match(markup, /<option value="response_header" selected>Header<\/option>/);
  assert.match(markup, /value="X-Fixture"/);
  assert.doesNotMatch(markup, /No steps yet/);
  assert.equal(f.el("runSequenceButton").disabled, false);
  assert.equal(f.el("runSequenceButton").textContent, "Run");
  f.state.sequenceRunning = true;
  f.c.renderSequencePanel();
  assert.equal(f.el("sequenceStepsContainer").innerHTML, markup);
  assert.equal(f.el("runSequenceButton").disabled, true);
  assert.equal(f.el("runSequenceButton").textContent, "Running...");
  assert.equal(JSON.stringify(f.state.editingSequence), before);
  assert.equal(f.state.sequenceDirty, false);
  assert.equal(f.state.sequenceDraftVersion, 0);
});
