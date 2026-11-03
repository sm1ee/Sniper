// Exercise the shipped search state and viewer controllers without mounting a
// DOM EditorView or starting the app and its API requests.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const bundle = vm.createContext({ console, setTimeout, clearTimeout });
vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/codemirror.bundle.js"), "utf8"), bundle);
const { CM } = bundle;
const fieldStart = appSource.indexOf("const setSearchQuery = CM.StateEffect.define();");
const fieldEnd = appSource.indexOf("// Changed-line decoration:", fieldStart);
const classStart = appSource.indexOf("class SniperCodeView {");
const classEnd = appSource.indexOf("// CodeMirror-based code pane instances", classStart);
assert.ok(fieldStart >= 0 && fieldEnd > fieldStart && classStart >= 0 && classEnd > classStart);

function fixture(area, side, text, query) {
  const views = {};
  const state = {
    messageSearch: { [side]: query },
    messageViews: { [side]: "raw" },
    replayMessageSearch: { [side]: query },
    replayMessageViews: { [side]: "raw" },
  };
  const meta = {};
  const input = { value: query };
  const context = loadFunctions([
    "normalizeSearchClasses", "normalizeSearchEffectValue", "forEachCodeSearchMatch",
    "buildSearchDecorations", "updateCodePaneCM", "getCMView", "buildSearchMeta",
    "updateMessagePaneSearch", "updateReplaySearchPane", "renderReplayResponseView",
  ], {
    CM,
    CM_SEARCH_DECORATION_LIMIT: 5000,
    CM_DEFAULT_SEARCH_CLASSES: { hit: "tok-search-hit", active: "tok-search-active" },
    cmProgrammaticViews: new WeakSet(),
    _cmViews: views,
    _replayResponseCMMode: "http",
    state,
    els: {
      requestSearchMeta: meta, responseSearchMeta: meta,
      replayRequestSearchMeta: meta, replayResponseSearchMeta: meta,
      replayRequestSearchInput: input, replayResponseSearchInput: input,
      replayResponseCM: {},
    },
    syncReplayResponsePreview() {},
  });
  vm.runInContext(appSource.slice(fieldStart, fieldEnd), context);
  vm.runInContext(`${appSource.slice(classStart, classEnd)}\nglobalThis.CodeView = SniperCodeView;`, context);
  const field = vm.runInContext("searchDecoField", context);
  const cv = Object.create(context.CodeView.prototype);
  cv._searchNavIndex = -1;
  cv._hlMode = "http";
  cv._editable = area === "replay" && side === "request";
  cv.applyChangedLines = () => {};
  cv.view = {
    state: CM.EditorState.create({ doc: text, extensions: [field] }),
    dispatch(transaction) { this.state = this.state.update(transaction).state; },
  };
  const key = area === "history" ? side : "replayReq";
  views[key] = cv;
  context._replayResponseCMView = cv;
  const searchState = area === "history" ? state.messageSearch : state.replayMessageSearch;
  function updateSearch() {
    if (area === "history") context.updateMessagePaneSearch(side);
    else context.updateReplaySearchPane(side, cv.getContent());
  }
  function redraw(nextText = cv.getContent()) {
    if (area === "replay" && side === "response") {
      context.renderReplayResponseView(nextText);
    } else {
      context.updateCodePaneCM(key, {}, nextText, {
        mode: "http", readOnly: !cv._editable,
        // History passes search with the redraw; Replay updates it afterwards.
        search: area === "history" ? searchState[side] : undefined,
      });
      if (area === "replay") updateSearch();
    }
  }
  function snapshot() {
    const result = cv.view.state.field(field);
    return {
      query: result.query,
      count: result.matchCount,
      ranges: Array.from(result.matchPositions, (from, index) => [from, result.matchEnds[index]]),
    };
  }
  return { cv, meta, input, updateSearch, redraw, snapshot, setQuery(value) { searchState[side] = value; } };
}

const cases = [
  ["foo foo ", " ", [[3, 4], [7, 8]]],
  ["foo  foo  ", "  ", [[3, 5], [8, 10]]],
  ["foo foo ", " foo", [[3, 7]]],
  ["foo foo ", "  foo", []],
  ["foo foo ", "foo ", [[0, 4], [4, 8]]],
  [" foo \n foo ", " foo ", [[0, 5], [6, 11]]],
  ["foo\tfoo\t", "\t", [[3, 4], [7, 8]]],
  ["foo\nfoo\n", "\n", [[3, 4], [7, 8]]],
  ["foo\nfoo \n", "\nfoo ", [[3, 8]]],
  [" İ \n i\u0307 ", " İ ", [[0, 3], [4, 8]]],
  ["İ😀 \n😀 ", "😀 ", [[1, 4], [5, 8]]],
  ["foo\u00a0foo\u00a0", "\u00a0", [[3, 4], [7, 8]]],
  ["foo foo ", "", []],
];

for (const area of ["history", "replay"]) {
  for (const side of ["request", "response"]) {
    for (const [text, query, expected] of cases) {
      test(`${area} ${side} keeps literal ${JSON.stringify(query)} through repeated redraw and clear`, () => {
        const f = fixture(area, side, text, query);
        f.updateSearch();
        const typed = f.snapshot();
        assert.deepEqual(typed, { query, count: expected.length, ranges: expected });
        const typedMeta = f.meta.innerHTML;
        for (let refresh = 0; refresh < 3; refresh += 1) {
          f.redraw();
          assert.deepEqual(f.snapshot(), typed);
          for (const [index, [anchor, head]] of expected.entries()) {
            assert.equal(f.cv.nextSearchMatch(), index);
            const selection = f.cv.view.state.selection.main;
            assert.deepEqual([selection.anchor, selection.head], [anchor, head]);
          }
          f.updateSearch();
          assert.equal(f.meta.innerHTML, typedMeta);
          assert.deepEqual(f.snapshot(), typed);
          assert.equal(f.input.value, query);
        }
        f.setQuery("");
        f.updateSearch();
        f.redraw();
        assert.deepEqual(f.snapshot(), { query: "", count: 0, ranges: [] });
        assert.equal(f.cv.nextSearchMatch(), -1);
      });
    }

    test(`${area} ${side} recomputes literal ranges when refreshed text changes`, () => {
      const f = fixture(area, side, "foo ", "foo ");
      f.updateSearch();
      f.redraw("İ😀 foo \nfoo ");
      assert.deepEqual(f.snapshot(), { query: "foo ", count: 2, ranges: [[4, 8], [9, 13]] });
      f.redraw();
      assert.equal(f.cv.nextSearchMatch(), 0);
      const selection = f.cv.view.state.selection.main;
      assert.deepEqual([selection.anchor, selection.head], [4, 8]);
    });
  }
}
