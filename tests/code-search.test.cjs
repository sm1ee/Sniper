// Saved-text search checks run offline against the shipped CodeMirror bundle.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const bundle = vm.createContext({ console, setTimeout, clearTimeout });
vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/codemirror.bundle.js"), "utf8"), bundle);
const { CM } = bundle;
const context = loadFunctions(["normalizeSearchClasses", "normalizeSearchEffectValue", "forEachCodeSearchMatch", "buildSearchDecorations", "applyCodeSearch"], {
  CM,
  CM_SEARCH_DECORATION_LIMIT: 5000,
  CM_DEFAULT_SEARCH_CLASSES: { hit: "tok-search-hit", active: "tok-search-active" },
});
function search(text, query, activeIndex = -1) {
  const doc = CM.EditorState.create({ doc: text }).doc;
  return context.buildSearchDecorations(doc, query, activeIndex);
}
function ranges(result) {
  const values = [];
  for (let cursor = result.decos.iter(); cursor.value; cursor.next()) {
    values.push([cursor.from, cursor.to]);
  }
  return values;
}

test("saved-text search keeps highlights in original coordinates after expanding Unicode", () => {
  assert.deepEqual(ranges(search("İx", "x")), [[1, 2]]);
});

test("a search query whose lowercase expands highlights the complete original match", () => {
  assert.deepEqual(ranges(search("i\u0307", "İ")), [[0, 2]]);
  assert.deepEqual(ranges(search("İ", "İ")), [[0, 1]]);
});

for (const [text, query, expected] of [
  ["İx İx", "x", [[1, 2], [4, 5]]],
  ["İ", "i", [[0, 1]]],
  ["İ", "\u0307", [[0, 1]]],
  ["İ\nnext", "\nNEXT", [[1, 6]]],
  ["İ😀X😀x", "😀x", [[1, 4], [4, 7]]],
  ["İ😀", "\ude00", [[2, 3]]],
  ["İ𐐀𐐨", "𐐨", [[1, 3], [3, 5]]],
  ["İΟΣ", "ος", [[1, 3]]],
  ["İΟΣ", "οσ", []],
  ["İword sword WORD", "word", [[1, 5], [7, 11], [12, 16]]],
  ["İ[a.*] [A.*]", "[a.*]", [[1, 6], [7, 12]]],
  ["İaaa", "aa", [[1, 3], [2, 4]]],
  ["abc", "", []],
  ["", "x", []],
  ["İx", "missing", []],
]) {
  test(`literal saved-text search ${JSON.stringify(text)} / ${JSON.stringify(query)}`, () => {
    const result = search(text, query);
    assert.deepEqual(ranges(result), expected);
    assert.deepEqual(Array.from(result.matchPositions), expected.map(range => range[0]));
    assert.deepEqual(Array.from(result.matchEnds), expected.map(range => range[1]));
    assert.equal(result.matchCount, expected.length);
    for (const [from, to] of ranges(result)) {
      assert.ok(from >= 0 && from < to && to <= text.length);
    }
  });
}

test("search caps stored navigation ranges while retaining the full match count", () => {
  const result = search("İx".repeat(6001), "x", 4999);
  assert.equal(result.matchCount, 6001);
  assert.equal(result.matchPositions.length, 5000);
  assert.equal(result.matchEnds.length, 5000);
  assert.equal(result.matchPositions[4999], 9999);
  assert.equal(result.matchEnds[4999], 10000);
  assert.equal(result.activeIndex, 4999);
  assert.equal(ranges(result).length, 5000);
  assert.equal(search("İx".repeat(6001), "x", 5000).activeIndex, -1);
});

// Use the real search state field and navigation methods, without mounting an
// EditorView or starting the app and its API requests.
const fieldStart = appSource.indexOf("const setSearchQuery = CM.StateEffect.define();");
const fieldEnd = appSource.indexOf("// Changed-line decoration:", fieldStart);
const classStart = appSource.indexOf("class SniperCodeView {");
const classEnd = appSource.indexOf("// CodeMirror-based code pane instances", classStart);
assert.ok(fieldStart >= 0 && fieldEnd > fieldStart && classStart >= 0 && classEnd > classStart);
vm.runInContext(appSource.slice(fieldStart, fieldEnd), context);
vm.runInContext(`${appSource.slice(classStart, classEnd)}\nglobalThis.CodeView = SniperCodeView;`, context);
const searchField = vm.runInContext("searchDecoField", context);
function codeView(text) {
  const cv = Object.create(context.CodeView.prototype);
  cv._searchNavIndex = -1;
  cv.view = {
    state: CM.EditorState.create({ doc: text, extensions: [searchField] }),
    dispatch(transaction) { this.state = this.state.update(transaction).state; },
  };
  return cv;
}
function selection(cv) {
  const { anchor, head } = cv.view.state.selection.main;
  return [anchor, head];
}

test("search navigation selects full original matches and wraps without out-of-range selections", () => {
  const cv = codeView("İ i\u0307");
  cv.applySearch("İ");
  assert.equal(cv.nextSearchMatch(), 0);
  assert.deepEqual(selection(cv), [0, 1]);
  assert.equal(cv.nextSearchMatch(), 1);
  assert.deepEqual(selection(cv), [2, 4]);
  assert.equal(cv.nextSearchMatch(), 0);
  assert.deepEqual(selection(cv), [0, 1]);
});

test("repeated queries and clearing search replace both navigation endpoints", () => {
  const cv = codeView("İx");
  cv.applySearch("x");
  cv.nextSearchMatch();
  assert.deepEqual(selection(cv), [1, 2]);
  cv.applySearch("İ");
  cv.nextSearchMatch();
  assert.deepEqual(selection(cv), [0, 1]);
  cv.applySearch("");
  assert.equal(cv.nextSearchMatch(), -1);
  assert.equal(cv.view.state.field(searchField).matchEnds.length, 0);
});

test("search recomputes mapped endpoints when the displayed document changes", () => {
  const cv = codeView("x");
  cv.applySearch("x");
  cv.view.dispatch({ changes: { from: 0, to: 1, insert: "İx" } });
  cv.nextSearchMatch();
  assert.deepEqual(selection(cv), [1, 2]);
});

function domSearch(texts, query) {
  const nodes = texts.map(nodeValue => ({ nodeValue }));
  const fullText = texts.join("");
  const offset = (node, local) => texts.slice(0, nodes.indexOf(node)).join("").length + local;
  const marked = [];
  const document = {
    createTreeWalker() {
      let index = -1;
      return { nextNode() { return !!nodes[++index]; }, get currentNode() { return nodes[index]; } };
    },
    createRange() {
      let from, to;
      return {
        setStart(node, local) { from = offset(node, local); },
        setEnd(node, local) { to = offset(node, local); },
        surroundContents(mark) { mark.textContent = fullText.slice(from, to); marked.push({ from, to, mark }); },
      };
    },
    createElement() { return {}; },
  };
  context.document = document;
  context.NodeFilter = { SHOW_TEXT: 4 };
  context.clearSearchHighlights = () => {};
  const result = context.applyCodeSearch({}, query);
  return { result, marked };
}

test("fallback text-node search shares original offsets across highlighted element boundaries", () => {
  const { result, marked } = domSearch(["İ", "x ", "i", "\u0307"], "İ");
  assert.equal(result.count, 2);
  assert.deepEqual(marked.map(({ from, to }) => [from, to]), [[3, 5], [0, 1]]);
  assert.equal(result.firstMatch.textContent, "İ");
});

test("fallback search after expanding Unicode highlights the displayed character", () => {
  const { result, marked } = domSearch(["İ", "x"], "x");
  assert.equal(result.count, 1);
  assert.deepEqual(marked.map(({ from, to }) => [from, to]), [[1, 2]]);
  assert.equal(result.firstMatch.textContent, "x");
});
