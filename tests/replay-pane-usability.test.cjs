// Shipped editor state and production rendering with an in-memory contentDOM.
// CSS assertions are contracts, not browser geometry or screen-reader tests.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { editorFixture, source } = require("./replay-editor-fixture.cjs");

const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");

function elementFromHtml(id) {
  const tag = html.match(new RegExp(`<[^>]+\\bid="${id}"[^>]*>`))[0];
  return { getAttribute: name => tag.match(new RegExp(`\\b${name}="([^"]*)"`))?.[1] ?? null };
}

function setup() {
  const f = editorFixture();
  const MemoryEditorView = f.context.CM.EditorView;
  f.context.CM.EditorView = class extends MemoryEditorView {
    constructor(options) {
      super(options);
      const attributes = new Map();
      this.contentDOM = {
        setAttribute: (name, value) => attributes.set(name, String(value)),
        getAttribute: name => attributes.get(name) ?? null,
      };
    }
  };
  f.els.replayRequestCM = elementFromHtml("replayRequestCM");
  f.els.replayResponseCM = elementFromHtml("replayResponseCM");
  Object.assign(f.context, {
    _replayResponseCMView: null, _replayResponseCMMode: null, syncReplayResponsePreview() {},
  });
  vm.runInContext(source("renderReplayResponseView"), f.context);
  vm.runInContext("globalThis.TestCodeView = SniperCodeView;", f.context);
  f.name = view => view.view.contentDOM.getAttribute("aria-label");
  return f;
}

for (const [id, label] of [
  ["replayRequestSearchInput", "Search Replay request"],
  ["replayResponseSearchInput", "Search Replay response"],
]) {
  test(`${id} has an explicit distinct accessible name`, () => {
    assert.equal(elementFromHtml(id).getAttribute("aria-label"), label);
  });
}

test("Replay request keeps its accessible name across redraw, tab replacement and view recreation", () => {
  const f = setup(); f.render();
  const first = f.cv();
  assert.equal(f.name(first), "Replay request");
  first.view.focus(); f.edit(5, 6, "edited");
  const edited = f.a.requestText;
  f.render();
  assert.equal(f.cv(), first);
  assert.equal(f.name(f.cv()), "Replay request");
  assert.equal(f.document.activeElement, first.view.contentDOM);
  assert.equal(f.undo(), true); assert.equal(f.redo(), true);
  assert.equal(f.a.requestText, edited);
  f.switchTo(f.b);
  assert.notEqual(f.cv(), first);
  assert.equal(f.name(f.cv()), "Replay request");
  assert.equal(f.undo(), false);
  for (const mode of ["pretty", "hex", "raw"]) {
    f.state.replayMessageViews.request = mode;
    f.context.renderReplayViewContent("request");
    assert.equal(f.name(f.cv()), "Replay request");
  }
  assert.equal(f.requests.length, 0);
});

test("Replay response keeps its distinct accessible name through response-mode recreation", () => {
  const f = setup();
  let previous = null;
  for (const mode of ["raw", "pretty", "hex", "raw"]) {
    f.state.replayMessageViews.response = mode;
    f.context.renderReplayResponseView("synthetic response");
    const current = f.context._replayResponseCMView;
    assert.equal(f.name(current), "Replay response");
    assert.equal(current._options.readOnly, true);
    if (mode === "pretty") assert.equal(current, previous);
    else if (previous) {
      assert.notEqual(current, previous);
      assert.equal(previous.view.destroyed, true);
    }
    previous = current;
  }
  assert.equal(f.requests.length, 0);
});

test("a CodeView name is applied without dispatching an editor transaction", () => {
  const f = setup();
  const view = new f.context.TestCodeView({ getAttribute: () => "Synthetic editor" }, { content: "unchanged" });
  assert.equal(f.name(view), "Synthetic editor");
  assert.equal(view.getContent(), "unchanged");
  assert.equal(view.view.transactions.length, 0);
});

for (const label of [null, "", "   "]) {
  test(`CodeView without a nonempty label (${JSON.stringify(label)}) does not gain an accessible-name override`, () => {
    const f = setup();
    const view = new f.context.TestCodeView({ getAttribute: () => label }, { content: "unchanged" });
    assert.equal(f.name(view), null);
    assert.equal(view.getContent(), "unchanged");
    assert.equal(view.view.transactions.length, 0);
  });
}

test("CodeView without attribute access remains unchanged", () => {
  const f = setup();
  const view = new f.context.TestCodeView({}, { content: "unchanged" });
  assert.equal(f.name(view), null);
  assert.equal(view.getContent(), "unchanged");
});

test("Replay cards fit their assigned rows instead of overlapping the next search footer", () => {
  const card = css.match(/\.replay-workbench > \.panel-card\s*\{([^]*?)\}/)[1];
  assert.match(card, /min-height:\s*0\s*;/);
  assert.match(card, /grid-template-rows:\s*auto minmax\(0, 1fr\) auto\s*;/);
});

test("stacked Replay rows shrink with available height while the desktop split and proportions remain unchanged", () => {
  const desktop = css.match(/\.replay-workbench\s*\{([^]*?)\}/)[1];
  assert.match(desktop, /grid-template-columns:\s*repeat\(2, minmax\(0, 1fr\)\)\s*;/);
  assert.match(desktop, /grid-auto-rows:\s*minmax\(0, 1fr\)\s*;/);
  const narrow = css.slice(css.indexOf("@media (max-width: 1240px)"), css.indexOf("@media (max-width: 760px)"));
  const stacked = narrow.match(/\.replay-workbench\s*\{([^]*?)\}/)[1];
  assert.match(stacked, /grid-template-columns:\s*1fr\s*;/);
  assert.match(stacked, /grid-template-rows:\s*minmax\(0, 0\.9fr\) minmax\(0, 1\.1fr\)\s*;/);
});
