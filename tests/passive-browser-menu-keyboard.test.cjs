// Browser chooser navigation only. Synthetic focus objects and extracted
// callbacks never load a catalog, launch a browser, install, or start the app.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture(count = 3) {
  const document = { activeElement: null };
  const focused = [], attrs = new Map();
  function node(name) {
    const value = {
      name,
      focus() { document.activeElement = value; focused.push(name); },
    };
    return value;
  }
  const anchor = node("caret"), outside = node("outside"), child = node("menu child"), element = node("menu");
  anchor.setAttribute = (name, value) => attrs.set(name, value);
  attrs.set("aria-expanded", "true");
  const controls = Array.from({ length: count }, (_, index) => node(`control-${index}`));
  element.contains = value => value === element || value === child || controls.includes(value);
  element.querySelectorAll = selector => {
    assert.equal(selector, "button:not(:disabled), input, a[href]");
    return controls;
  };
  element.remove = () => { element.removed = true; };
  const context = loadFunctions(["onBrowserMenuKeydown", "closeBrowserMenu"], {
    browserMenu: { anchor, element }, document,
    fetch() { assert.fail("Keyboard navigation must not make a request"); },
  });
  function key(key, activeElement = anchor) {
    document.activeElement = activeElement;
    const event = { key, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } };
    context.onBrowserMenuKeydown(event);
    return event;
  }
  return { context, document, focused, attrs, anchor, element, child, outside, controls, key };
}

for (const count of [1, 2, 3, 5]) {
  for (const origin of ["caret", "container", "unlisted child"]) {
    for (const [key, expected] of [["ArrowDown", 0], ["ArrowUp", count - 1]]) {
      test(`${key} from ${origin} chooses the ${key === "ArrowDown" ? "first" : "last"} of ${count} controls`, () => {
        const f = fixture(count);
        const target = origin === "caret" ? f.anchor : origin === "container" ? f.element : f.child;
        const event = f.key(key, target);
        assert.equal(f.document.activeElement, f.controls[expected]);
        assert.deepEqual(f.focused, [`control-${expected}`]);
        assert.equal(event.defaultPrevented, true);
        assert.ok(f.context.browserMenu);
      });
    }
  }
  test(`up/down wrap normally among ${count} existing menu controls`, () => {
    const f = fixture(count);
    for (let index = 0; index < count; index += 1) {
      for (const [key, step] of [["ArrowDown", 1], ["ArrowUp", -1]]) {
        const event = f.key(key, f.controls[index]);
        assert.equal(f.document.activeElement, f.controls[(index + step + count) % count]);
        assert.equal(event.defaultPrevented, true);
      }
    }
  });
}

for (const key of ["ArrowUp", "ArrowDown"]) {
  test(`${key} leaves focus alone when the chooser has no controls`, () => {
    const f = fixture(0);
    const event = f.key(key);
    assert.equal(f.document.activeElement, f.anchor);
    assert.equal(event.defaultPrevented, false);
    assert.deepEqual(f.focused, []);
  });
  test(`${key} outside the chooser remains available to the page`, () => {
    const f = fixture();
    const event = f.key(key, f.outside);
    assert.equal(f.document.activeElement, f.outside);
    assert.equal(event.defaultPrevented, false);
    assert.deepEqual(f.focused, []);
  });
  test(`${key} does nothing once the chooser is closed`, () => {
    const f = fixture();
    f.context.closeBrowserMenu();
    const event = f.key(key);
    assert.equal(f.document.activeElement, f.anchor);
    assert.equal(event.defaultPrevented, false);
    assert.deepEqual(f.focused, []);
  });
}

for (const key of ["Enter", "Tab", "ArrowLeft", "ArrowRight", "a"]) {
  test(`${key} retains its existing control behavior`, () => {
    const f = fixture();
    const event = f.key(key, f.controls[1]);
    assert.equal(f.document.activeElement, f.controls[1]);
    assert.equal(event.defaultPrevented, false);
    assert.deepEqual(f.focused, []);
  });
}

test("Escape still closes the chooser, restores its caret, and consumes the event", () => {
  const f = fixture();
  const event = f.key("Escape", f.controls[1]);
  assert.equal(f.context.browserMenu, null);
  assert.equal(f.element.removed, true);
  assert.equal(f.attrs.get("aria-expanded"), "false");
  assert.equal(f.document.activeElement, f.anchor);
  assert.equal(event.defaultPrevented, true);
  assert.deepEqual(f.focused, ["caret"]);
});
