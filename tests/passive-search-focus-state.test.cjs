// Offline passive search and readonly focus contracts. Supplied DOM/focus models
// establish callback behavior only; no browser selection/layout claim is made.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

function classes(initial = []) {
  const values = new Set(initial);
  return { add: value => values.add(value), remove: value => values.delete(value), contains: value => values.has(value) };
}

function domNavigationFixture() {
  const observers = [], handlers = [];
  const meta = { addEventListener(type, fn) { assert.equal(type, "click"); handlers.push(fn); } };
  let view;
  const context = loadFunctions(["initSearchHitNavigation"], {
    MutationObserver: class {
      constructor(callback) { this.callback = callback; observers.push(this); }
      observe(target, options) { assert.equal(target, meta); this.options = options; }
    },
  });
  context.initSearchHitNavigation(meta, () => view);
  function makeView(count) {
    const result = { offsetTop: 20, scrollTop: 0 };
    result.marks = Array.from({ length: count }, (_, i) => ({
      offsetTop: 50 + i * 100, classList: classes(["search-hit"]), closest: () => result,
    }));
    result.querySelectorAll = () => result.marks;
    result.querySelector = () => result.marks.find(mark => mark.classList.contains("search-hit-active")) || null;
    return result;
  }
  return {
    context, observers, meta, makeView,
    setView(next) { view = next; },
    click(hit = true) { handlers.forEach(fn => fn({ target: { closest: () => hit ? {} : null } })); },
    reset() { observers.forEach(observer => observer.callback([])); },
  };
}

for (const count of [1, 2, 3, 12]) {
  test(`fallback search cycles through ${count} supplied marks and clears the previous highlight`, () => {
    const f = domNavigationFixture(), view = f.makeView(count);
    f.setView(view);
    for (let step = 0; step < count * 2 + 1; step++) {
      f.click();
      assert.deepEqual(view.marks.flatMap((mark, i) => mark.classList.contains("search-hit-active") ? [i] : []), [step % count]);
      assert.equal(view.scrollTop, Math.max(view.marks[step % count].offsetTop - view.offsetTop - 40, 0));
    }
  });
}

test("fallback search ignores other metadata text, absent views, and zero matches", () => {
  const f = domNavigationFixture();
  f.click();
  f.setView(f.makeView(0));
  f.click();
  const view = f.makeView(2); f.setView(view);
  f.click(false);
  assert.equal(view.querySelector(), null);
  f.click();
  assert.equal(view.querySelector(), view.marks[0]);
});

test("fallback search metadata replacement resets the cycle in the current target view", () => {
  const f = domNavigationFixture(), first = f.makeView(3), second = f.makeView(2);
  f.setView(first); f.click(); f.click();
  f.setView(second); f.reset(); f.click();
  assert.equal(second.querySelector(), second.marks[0]);
  f.click(); assert.equal(second.querySelector(), second.marks[1]);
  f.setView(first); f.reset(); f.click();
  assert.equal(first.querySelector(), first.marks[0]);
  assert.deepEqual(Object.keys(f.observers[0].options).sort(), ["childList", "subtree"]);
});

test("fallback search new marks of equal count start at the first after metadata replacement", () => {
  const f = domNavigationFixture(), view = f.makeView(3);
  f.setView(view); f.click(); f.click();
  view.marks = f.makeView(3).marks;
  view.marks.forEach(mark => { mark.closest = () => view; });
  f.reset(); f.click();
  assert.equal(view.querySelector(), view.marks[0]);
});

test("fallback search accepts a missing metadata element without binding", () => {
  const f = domNavigationFixture();
  f.context.initSearchHitNavigation(null, () => { throw new Error("must not resolve a view"); });
});

const bundle = vm.createContext({ console, setTimeout, clearTimeout });
vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/codemirror.bundle.js"), "utf8"), bundle);
const { CM } = bundle;
function cmNavigationFixture(text = "x x x") {
  const pool = {}, handlers = [];
  const context = loadFunctions([
    "normalizeSearchClasses", "normalizeSearchEffectValue", "forEachCodeSearchMatch", "buildSearchDecorations",
    "initCMSearchNavigation", "updateCodePaneCM", "getCMView", "updateMessagePaneSearch", "buildSearchMeta", "countLines",
  ], {
    CM, CM_SEARCH_DECORATION_LIMIT: 5000,
    CM_DEFAULT_SEARCH_CLASSES: { hit: "tok-search-hit", active: "tok-search-active" },
    cmProgrammaticViews: new WeakSet(), _cmViews: pool,
    titleCase: value => value, state: { messageSearch: { request: "x" }, messageViews: { request: "raw" } },
  });
  const fieldStart = appSource.indexOf("const setSearchQuery = CM.StateEffect.define();");
  const fieldEnd = appSource.indexOf("// Changed-line decoration:", fieldStart);
  const classStart = appSource.indexOf("class SniperCodeView {");
  const classEnd = appSource.indexOf("// CodeMirror-based code pane instances", classStart);
  assert.ok(fieldStart >= 0 && fieldEnd > fieldStart && classStart >= 0 && classEnd > classStart);
  vm.runInContext(appSource.slice(fieldStart, fieldEnd), context);
  vm.runInContext(`${appSource.slice(classStart, classEnd)}\nglobalThis.CodeView = SniperCodeView;`, context);
  const field = vm.runInContext("searchDecoField", context);
  function makeView(value) {
    const cv = Object.create(context.CodeView.prototype);
    cv._searchNavIndex = -1;
    cv.transactions = [];
    cv.view = {
      state: CM.EditorState.create({ doc: value, extensions: [field] }),
      dispatch(transaction) { cv.transactions.push(transaction); this.state = this.state.update(transaction).state; },
      destroy() { cv.destroyed = true; },
    };
    cv.applyChangedLines = () => {};
    return cv;
  }
  const meta = { innerHTML: "", addEventListener(type, fn) { assert.equal(type, "click"); handlers.push(fn); } };
  context.els = { requestSearchMeta: meta };
  pool.request = makeView(text);
  context.initCMSearchNavigation(meta, "request");
  return {
    context, pool, meta, makeView, field,
    click(hit = true) { handlers.forEach(fn => fn({ target: { closest: () => hit ? {} : null } })); },
    selection(cv = pool.request) { const { anchor, head } = cv.view.state.selection.main; return [anchor, head]; },
  };
}

test("CM metadata click delegates to the current readonly view and cycles complete ranges", () => {
  const f = cmNavigationFixture();
  f.context.updateMessagePaneSearch("request");
  f.click(false); assert.equal(f.pool.request._searchNavIndex, -1);
  for (const expected of [[0, 1], [2, 3], [4, 5], [0, 1]]) { f.click(); assert.deepEqual(f.selection(), expected); }
});

for (const query of ["", "missing", "  "]) {
  test(`CM metadata click does nothing for no matches: ${JSON.stringify(query)}`, () => {
    const f = cmNavigationFixture();
    f.context.state.messageSearch.request = query;
    f.context.updateMessagePaneSearch("request");
    const before = f.pool.request.transactions.length;
    f.click();
    assert.equal(f.pool.request.transactions.length, before);
    assert.equal(f.pool.request._searchNavIndex, -1);
  });
}

test("actual passive search update resets navigation even for the same query and count", () => {
  const f = cmNavigationFixture();
  f.context.updateMessagePaneSearch("request"); f.click(); f.click();
  f.context.updateMessagePaneSearch("request"); f.click();
  assert.deepEqual(f.selection(), [0, 1]);
  assert.match(f.meta.innerHTML, /3 highlights/);
});

test("CM navigation resolves replacements per click and ignores a deleted view", () => {
  const f = cmNavigationFixture(), old = f.pool.request;
  f.context.updateMessagePaneSearch("request"); f.click();
  old.destroy(); delete f.pool.request;
  const before = old.transactions.length;
  f.click(); assert.equal(old.transactions.length, before);
  f.pool.request = f.makeView("a x");
  f.context.updateMessagePaneSearch("request"); f.click();
  assert.deepEqual(f.selection(), [2, 3]);
  assert.equal(old.transactions.length, before);
});

test("readonly pane update recomputes ranges after document replacement and resets the cycle", () => {
  const f = cmNavigationFixture(), cv = f.pool.request;
  cv._hlMode = "http"; cv._editable = false;
  f.context.updateMessagePaneSearch("request"); f.click(); f.click();
  const result = f.context.updateCodePaneCM("request", {}, "xx\nx", { mode: "http", search: "x" });
  assert.equal(result.matchCount, 3);
  assert.equal(result.lineCount, 2);
  assert.equal(f.pool.request, cv);
  f.click(); assert.deepEqual(f.selection(), [0, 1]);
});

function focusFixture() {
  const handlers = new Map(), selections = [], scrolls = [], views = [];
  const document = {
    readyState: "complete", activeElement: null,
    querySelectorAll: () => views,
    addEventListener(type, fn) { const list = handlers.get(type) || []; list.push(fn); handlers.set(type, list); },
    createRange() { return { setStart(node, offset) { selections.push([node, offset]); }, collapse() {} }; },
  };
  const window = { getSelection: () => ({ removeAllRanges() {}, addRange() {} }) };
  function makeView(id, count, focusedIndex = -1) {
    const attrs = new Map(), listeners = new Map();
    const view = {
      id, dataset: {}, getAttribute: name => attrs.get(name), setAttribute: (name, value) => attrs.set(name, value),
      listenerAdds: 0,
      addEventListener(type, fn) { view.listenerAdds += 1; listeners.set(type, fn); },
      focus() { document.activeElement = view; },
      querySelector: () => view.lines.find(line => line.classList.contains("line-focus")) || null,
      querySelectorAll: () => view.lines,
    };
    view.lines = Array.from({ length: count }, (_, index) => ({
      classList: classes(index === focusedIndex ? ["line-focus"] : []), firstChild: { textContent: `line ${index}` },
      scrollIntoView: options => scrolls.push({ view, index, options }),
    }));
    views.push(view);
    return view;
  }
  const start = appSource.indexOf("(function initCodeViewLineNav() {");
  const end = appSource.indexOf("// ─── CodeMirror 6 Integration", start);
  assert.ok(start >= 0 && end > start);
  const context = vm.createContext({ document, window, copyTextToClipboard() { throw new Error("copy is outside this fixture"); } });
  vm.runInContext(appSource.slice(start, end), context);
  return {
    window, document, selections, scrolls, makeView,
    key(key) { const event = { key, preventDefault() { this.defaultPrevented = true; } }; handlers.get("keydown").forEach(fn => fn(event)); return event; },
  };
}

for (const active of [true, false]) {
  test(`readonly line restore preserves its highlight ${active ? "with" : "without"} a caret for the previously active view`, () => {
    const f = focusFixture(), view = f.makeView("request", 3, 1), other = {};
    f.window._enableReadonlyCaret(view);
    f.document.activeElement = active ? view : other;
    const saved = f.window._saveCodeViewFocus(view);
    assert.deepEqual({ ...saved }, { viewId: "request", lineIndex: 1, wasActive: active });
    view.lines = f.makeView("replacement", 4).lines;
    f.window._restoreCodeViewFocus(view, saved);
    assert.equal(view.querySelector(), view.lines[1]);
    assert.equal(f.document.activeElement, active ? view : other);
    assert.equal(f.selections.length, active ? 1 : 0);
    assert.equal(f.scrolls.length, active ? 1 : 0);
  });
}

for (const length of [0, 1, 2]) {
  test(`readonly line restore safely ignores a removed line in a ${length}-line replacement`, () => {
    const f = focusFixture(), view = f.makeView("request", 4, 3);
    f.window._enableReadonlyCaret(view); f.document.activeElement = view;
    const saved = f.window._saveCodeViewFocus(view);
    view.lines = f.makeView("replacement", length).lines;
    f.window._restoreCodeViewFocus(view, saved);
    assert.equal(view.querySelector(), null);
    assert.equal(f.selections.length, 0);
    assert.equal(f.scrolls.length, 0);
    const event = f.key("ArrowDown");
    assert.equal(Boolean(event.defaultPrevented), length > 0);
    assert.equal(view.querySelector(), length ? view.lines[0] : null);
  });
}

test("readonly focus save/restore accepts absent views and missing highlights", () => {
  const f = focusFixture(), view = f.makeView("request", 2);
  assert.equal(f.window._saveCodeViewFocus(null), null);
  assert.equal(f.window._saveCodeViewFocus(view), null);
  f.window._restoreCodeViewFocus(null, { lineIndex: 0 });
  f.window._restoreCodeViewFocus(view, null);
  f.window._restoreCodeViewFocus(view, { lineIndex: -1 });
  assert.equal(f.selections.length, 0);
});

test("readonly caret initialization is idempotent and leaves designated editors alone", () => {
  const f = focusFixture(), view = f.makeView("request", 2), editor = f.makeView("editable", 2);
  editor.dataset.placeholder = "Edit";
  f.window._enableReadonlyCaret(view); f.window._enableReadonlyCaret(view);
  f.window._enableReadonlyCaret(editor);
  assert.equal(view.getAttribute("data-readonly-editable"), "1");
  assert.equal(view.getAttribute("contenteditable"), "true");
  assert.equal(view.listenerAdds, 3);
  assert.equal(editor.listenerAdds, 0);
  assert.equal(editor.getAttribute("contenteditable"), undefined);
});

for (const active of [false, true]) {
  test(`actual legacy pane rendering restores a retained line without taking focus from ${active ? "the same view" : "another control"}`, () => {
    const f = focusFixture(), view = f.makeView("request", 3, 1), other = {};
    f.window._enableReadonlyCaret(view);
    f.document.activeElement = active ? view : other;
    view.scrollTop = 25;
    Object.defineProperty(view, "innerHTML", { set(value) { view.lines = f.makeView("replacement", value.split("\n").length).lines; } });
    const context = loadFunctions(["updateCodePane", "countLines", "buildLineNumbers"], {
      window: f.window, state: { messageSearch: { request: "" } },
      renderCodeHtml: text => text, applyCodeSearch: () => ({ count: 0, firstMatch: null }),
    });
    const lineElement = {};
    const result = context.updateCodePane(view, lineElement, "first\nsecond\nthird\nfourth", "raw", "request");
    assert.equal(result.lineCount, 4);
    assert.equal(view.querySelector(), view.lines[1]);
    assert.equal(f.document.activeElement, active ? view : other);
    assert.equal(f.selections.length, active ? 1 : 0);
    assert.equal(lineElement.textContent, "1\n2\n3\n4");
    assert.equal(lineElement.scrollTop, view.scrollTop);
  });
}
