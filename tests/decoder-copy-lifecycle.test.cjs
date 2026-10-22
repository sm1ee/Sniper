// Actual Decoder copy handlers with synthetic DOM and clipboard implementations.
// No browser, system clipboard, app bootstrap, runtime, or external traffic.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function fixture({ modern = true, secure = true, fallbackResult = true, copyError, modernError } = {}) {
  const nodes = new Map(), writes = [], fallback = [], selections = [];
  const outputIds = new Set();
  function add(id) {
    const node = { id, value: "", textContent: "", visible: false, handlers: {},
      selectionStart: 0, selectionEnd: 0, contains: other => other === node };
    nodes.set(id, node);
    return node;
  }
  add("input-value"); add("input-password"); add("output");
  function $(selector) {
    const selected = selector === "#output .note" ? [...nodes.values()].filter(node => node.id.endsWith("-note"))
      // A value wrapper stands in for the row around it.
      : selector === "#output .element" ? [...nodes.values()].filter(node => node.id.endsWith("-value"))
      : [nodes.get(selector.slice(1))].filter(Boolean);
    const result = { length: selected.length,
      val(value) {
        if (!arguments.length) return selected[0]?.value;
        selected.forEach(node => { node.value = value; }); return this;
      },
      text(value) {
        if (!arguments.length) return selected[0]?.textContent;
        selected.forEach(node => { node.textContent = value; }); return this;
      },
      hide() { selected.forEach(node => { node.visible = false; }); return this; },
      show() { selected.forEach(node => { node.visible = true; }); return this; },
      attr() { return this; },
      addClass(name) { selected.forEach(node => { (node.classes ||= new Set()).add(name); }); return this; },
      removeClass(name) { selected.forEach(node => node.classes?.delete(name)); return this; },
      closest() { return this; },
      html() {
        if (selector === "#output") {
          outputIds.forEach(id => nodes.delete(id)); outputIds.clear();
        }
        return this;
      },
      append(html) {
        for (const match of html.matchAll(/\bid="([^"]+)"/g)) {
          outputIds.add(match[1]); add(match[1]);
        }
        return this;
      },
      click(handler) { selected.forEach(node => { node.handlers.click = handler; }); return this; },
      select() {
        selected.forEach(node => {
          selections.push(node.id); node.selectionStart = 0; node.selectionEnd = node.value.length;
        });
        return this;
      },
    };
    selected.forEach((node, index) => { result[index] = node; });
    return result;
  }
  const context = vm.createContext({ $, autoScroll() {}, ipCalc: function () {},
    window: { isSecureContext: secure },
    navigator: modern ? { clipboard: { writeText(text) {
      if (modernError) throw modernError;
      const write = { text, ...deferred() }; writes.push(write); return write.promise;
    } } } : {},
    document: { execCommand(command) {
      assert.equal(command, "copy"); fallback.push(nodes.get(selections.at(-1)).value);
      if (copyError) throw copyError;
      return fallbackResult;
    } },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/decoder/hasher.js"), "utf8"), context);
  const hasher = context.hasher;
  hasher.elements = {
    first: { id: "first", title: "Synthetic first", tab: 1, calculate: input => input },
    second: { id: "second", title: "Synthetic second", tab: 1, calculate: input => input.toUpperCase() },
    other: { id: "other", title: "Synthetic other tab", tab: 2, calculate: input => input },
  };
  hasher.tab = 1;
  hasher.init();
  function update(value) { nodes.get("input-value").value = value; hasher.update(); }
  function click(id = "first", target = nodes.get(id + "-value")) {
    const wrapper = nodes.get(id + "-value");
    return wrapper.handlers.click.call(wrapper, { target });
  }
  function feedback() {
    return [...nodes.values()].filter(node => node.id.endsWith("-note") && node.visible)
      .map(node => [node.id, node.textContent]);
  }
  update("synthetic café 한글 😀\nsecond line");
  return { context, hasher, nodes, writes, fallback, selections, update, click, feedback };
}

test("current modern copy captures the complete displayed Unicode output synchronously", async () => {
  const f = fixture(); f.click();
  assert.equal(f.writes.length, 1);
  assert.equal(f.writes[0].text, f.nodes.get("first").value);
  assert.deepEqual(f.feedback(), []);
  f.writes[0].resolve(); await tick();
  assert.deepEqual(f.feedback(), [["first-note", "Copied"]]);
  assert.deepEqual(f.selections, []); assert.deepEqual(f.fallback, []);
});

test("current modern copy rejection reports failure", async () => {
  const f = fixture(); f.click();
  f.writes[0].reject(new Error("Synthetic denial")); await tick();
  assert.deepEqual(f.feedback(), [["first-note", "Copy failed"]]);
});

for (const fallbackResult of [true, false]) for (const modern of [false, true]) {
  test(`fallback result ${fallbackResult} is reported accurately with modern API ${modern ? "insecure" : "absent"}`, async () => {
    const f = fixture({ modern, secure: false, fallbackResult }); f.click(); await tick();
    assert.deepEqual(f.fallback, [f.nodes.get("first").value]);
    assert.deepEqual(f.selections, ["first"]); assert.deepEqual(f.writes, []);
    assert.deepEqual(f.feedback(), [["first-note", fallbackResult ? "Copied" : "Copy failed"]]);
  });
}

for (const api of ["modern", "fallback"]) {
  test(`a synchronous ${api} exception reports copy failure`, async () => {
    const error = new Error("Synthetic copy failure");
    const f = fixture(api === "modern" ? { modernError: error } : { modern: false, copyError: error });
    assert.doesNotThrow(() => f.click()); await tick();
    assert.deepEqual(f.feedback(), [["first-note", "Copy failed"]]);
  });
}

const boundaries = [
  ["new input", f => f.update("new synthetic value")],
  ["empty input", f => f.update("")],
  ["input ABA", f => { const old = f.nodes.get("input-value").value; f.update("intermediate"); f.update(old); }],
  ["same-tab rerender", f => { f.hasher.init(); f.hasher.update(); }],
  ["tab round trip", f => {
    f.hasher.tab = 2; f.hasher.init(); f.hasher.update();
    f.hasher.tab = 1; f.hasher.init(); f.hasher.update();
  }],
  ["selecting output text", f => f.click("first", f.nodes.get("first"))],
];
for (const [name, boundary] of boundaries) for (const outcome of ["success", "failure"]) {
  test(`${name} suppresses delayed copy ${outcome}`, async () => {
    const f = fixture(); f.click(); boundary(f);
    if (outcome === "success") f.writes[0].resolve(); else f.writes[0].reject(new Error("Synthetic delayed failure"));
    await tick(); assert.deepEqual(f.feedback(), []);
  });
}

for (const id of ["first", "second"]) for (const outcome of ["success", "failure"]) {
  test(`newer copy of ${id} owns feedback after an older ${outcome}`, async () => {
    const f = fixture(); f.click(); f.click(id);
    f.writes[1].resolve(); await tick();
    if (outcome === "success") f.writes[0].resolve(); else f.writes[0].reject(new Error("Synthetic delayed failure"));
    await tick(); assert.deepEqual(f.feedback(), [[id + "-note", "Copied"]]);
  });
}

test("an older failure stays quiet while the newer copy is pending", async () => {
  const f = fixture(); f.click(); f.click("second");
  f.writes[0].reject(new Error("Synthetic delayed failure")); await tick();
  assert.deepEqual(f.feedback(), []);
  f.writes[1].resolve(); await tick(); assert.deepEqual(f.feedback(), [["second-note", "Copied"]]);
});

test("selecting output text preserves the selection and never automatically copies", async () => {
  const f = fixture(); const textarea = f.nodes.get("first");
  textarea.selectionStart = 2; textarea.selectionEnd = 6;
  f.click("first", textarea); await tick();
  assert.deepEqual(f.writes, []); assert.deepEqual(f.selections, []);
  assert.equal(textarea.selectionStart, 2); assert.equal(textarea.selectionEnd, 6);
});

test("empty output does not copy a previously displayed value", async () => {
  const f = fixture(); f.update(""); f.click(); await tick();
  assert.deepEqual(f.writes, []); assert.deepEqual(f.fallback, []); assert.deepEqual(f.feedback(), []);
});

// "Copied" beside a name was easy to miss; the row it came from lights up too,
// until the next copy or the next recalculation.
test("a copy lights its row until the next copy or recalculation", async () => {
  const f = fixture();
  const lit = id => f.nodes.get(id + "-value").classes?.has("copied") || false;
  f.click(); f.writes[0].resolve(); await tick();
  assert.equal(lit("first"), true);
  f.click("second"); assert.equal(lit("first"), false);
  f.writes[1].resolve(); await tick();
  assert.equal(lit("second"), true);
  f.update("next value"); assert.equal(lit("second"), false);
});

test("a failed copy says so without lighting the row", async () => {
  const f = fixture(); f.click();
  f.writes[0].reject(new Error("Synthetic denial")); await tick();
  assert.equal(f.nodes.get("first-value").classes?.has("copied") || false, false);
});
