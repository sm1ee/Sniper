// Findings detail panes: the evidence highlight and the pane search are separate
// layers, so typing and clearing a search never loses the evidence. Runs the
// shipped CodeMirror state fields and the production search listeners offline.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const bundle = vm.createContext({ console, setTimeout, clearTimeout });
vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/codemirror.bundle.js"), "utf8"), bundle);
const { CM } = bundle;
const fieldsStart = appSource.indexOf("const setSearchQuery = CM.StateEffect.define();");
const fieldsEnd = appSource.indexOf("// CodeMirror-based code pane instances", fieldsStart);
const listenersStart = appSource.indexOf("  // Findings detail search\n");
const listenersEnd = appSource.indexOf("  initSearchHitNavigation(els.findingsReqSearchMeta", listenersStart);
assert.ok(fieldsStart >= 0 && fieldsEnd > fieldsStart && listenersStart >= 0 && listenersEnd > listenersStart);

const EVIDENCE = "set-cookie: JSESSIONID=0123ABCD; Path=/; HttpOnly";
const TEXT = `HTTP/1.1 302\r\ncontent-length: 0\r\n${EVIDENCE}\r\nlocation: https://example.com/next\r\n\r\n`;
const FINDING = { title: "Cookie 'JSESSIONID' missing Secure flag", category: "cookie", evidence: EVIDENCE };

function fixture(key) {
  const views = {};
  const inputs = {}, metas = {};
  for (const name of ["findingsReq", "findingsRes"]) {
    inputs[name] = { value: "", listeners: {}, addEventListener(event, callback) { this.listeners[event] = callback; } };
    metas[name] = { innerHTML: "" };
  }
  const context = loadFunctions([
    "normalizeSearchClasses", "normalizeSearchEffectValue", "forEachCodeSearchMatch", "buildSearchDecorations",
    "updateCodePaneCM", "getCMView", "buildSearchMeta", "updateFindingsCodePaneCM", "findingEvidenceRanges",
    "findingHighlightQueries", "firstUsableFindingQuery", "extractFindingKeywords",
  ], {
    CM,
    CM_SEARCH_DECORATION_LIMIT: 5000,
    CM_DEFAULT_SEARCH_CLASSES: { hit: "tok-search-hit", active: "tok-search-active" },
    cmProgrammaticViews: new WeakSet(),
    _cmViews: views,
    els: {
      findingsReqSearchInput: inputs.findingsReq, findingsReqSearchMeta: metas.findingsReq,
      findingsResSearchInput: inputs.findingsRes, findingsResSearchMeta: metas.findingsRes,
    },
  });
  vm.runInContext(`${appSource.slice(fieldsStart, fieldsEnd)}
globalThis.CodeView = SniperCodeView;
globalThis.codeFields = [searchDecoField, changedDecoField, packetEvidenceField];`, context);
  vm.runInContext(appSource.slice(listenersStart, listenersEnd), context);
  // A mounted pane without a DOM: the real wrapper over a plain EditorState.
  const container = {};
  const cv = Object.create(context.CodeView.prototype);
  Object.assign(cv, { _searchNavIndex: -1, _hlMode: "http", _editable: false, _container: container });
  cv.view = {
    state: CM.EditorState.create({ doc: "", extensions: [...context.codeFields] }),
    dispatch(transaction) { this.state = this.state.update(transaction).state; },
  };
  views[key] = cv;
  const input = inputs[key];
  return {
    show(finding = FINDING, text = TEXT) {
      return context.updateFindingsCodePaneCM(key, container, text, finding.evidence, finding, input, metas[key]);
    },
    search(value) {
      input.value = value;
      input.listeners.input();
    },
    // Text under every rendered mark with this class, across all decoration layers.
    marked(className) {
      const { state } = cv.view;
      const found = [];
      for (const source of state.facet(CM.EditorView.decorations)) {
        if (typeof source === "function") continue;
        for (let cursor = source.iter(); cursor.value; cursor.next()) {
          if (cursor.value.spec.class === className) found.push(state.doc.sliceString(cursor.from, cursor.to));
        }
      }
      return found;
    },
  };
}

for (const key of ["findingsReq", "findingsRes"]) {
  test(`${key}: clearing a search over the evidence brings the evidence highlight back`, () => {
    const f = fixture(key);
    const shown = f.show();
    assert.deepEqual(f.marked("tok-finding-evidence-hit"), [EVIDENCE]);
    assert.equal(shown.firstMatchLine, 3);

    f.search("0123ABCD");
    assert.deepEqual(f.marked("tok-search-hit"), ["0123ABCD"]);
    // The search is drawn over the evidence, not instead of it.
    assert.deepEqual(f.marked("tok-finding-evidence-hit"), [EVIDENCE]);

    f.search("");
    assert.deepEqual(f.marked("tok-search-hit"), []);
    assert.deepEqual(f.marked("tok-finding-evidence-hit"), [EVIDENCE]);
  });

  test(`${key}: selecting another finding on the same text replaces the evidence`, () => {
    const f = fixture(key);
    f.show();
    f.search("content");
    const other = { title: "Open redirect", category: "misconfig", evidence: "location: https://example.com/next" };
    f.show(other);
    assert.deepEqual(f.marked("tok-finding-evidence-hit"), [other.evidence]);
    // A newly selected finding starts with an empty search box and no hits.
    assert.deepEqual(f.marked("tok-search-hit"), []);
  });
}
