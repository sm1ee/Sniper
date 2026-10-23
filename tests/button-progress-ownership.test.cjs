// Exercise the shared production progress wrapper with inert timers and work.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function fixture() {
  const timers = new Map(), callbacks = [], classes = new Set();
  let nextTimer = 0;
  const button = {
    disabled: false,
    classList: {
      add: (...names) => names.forEach(name => classes.add(name)),
      remove: (...names) => names.forEach(name => classes.delete(name)),
    },
  };
  const c = loadFunctions(["withButtonProgress"], {
    BUTTON_PROGRESS_DELAY_MS: 180,
    setTimeout(callback, delay) {
      assert.equal(delay, 180);
      callbacks.push(callback);
      timers.set(++nextTimer, callback);
      return nextTimer;
    },
    clearTimeout: id => timers.delete(id),
  });
  return { c, button, timers, callbacks, classes };
}

for (const outcome of ["resolve", "reject", "throw"]) {
  test(`current progress restores its button after ${outcome}`, async () => {
    const f = fixture(), work = deferred();
    const pending = f.c.withButtonProgress(f.button, () => {
      if (outcome === "throw") throw new Error("Current work failed.");
      return work.promise;
    });
    if (outcome !== "throw") {
      assert.equal(f.button.disabled, true);
      f.callbacks[0]();
      assert.equal(f.classes.has("is-working-shown"), true);
    }
    if (outcome === "resolve") { work.resolve(42); assert.equal(await pending, 42); }
    else {
      if (outcome === "reject") work.reject(new Error("Current work failed."));
      await assert.rejects(pending, /Current work failed/);
    }
    assert.equal(f.button.disabled, false);
    assert.equal(f.classes.size, 0);
    assert.equal(f.timers.size, 0);
    assert.equal(f.button._buttonProgress, undefined);
  });
}

test("disabled buttons reject duplicate work without starting a timer", async () => {
  const f = fixture(), work = deferred();
  const pending = f.c.withButtonProgress(f.button, () => work.promise);
  assert.equal(await f.c.withButtonProgress(f.button, () => assert.fail("duplicate work")), undefined);
  assert.equal(f.timers.size, 1);
  work.resolve(); await pending;
});

for (const outcome of ["resolve", "reject"]) {
  test(`old ${outcome} cannot finish a newer owner's progress after external re-enable`, async () => {
    const f = fixture(), old = deferred(), next = deferred();
    const first = f.c.withButtonProgress(f.button, () => old.promise);
    f.button.disabled = false;
    const second = f.c.withButtonProgress(f.button, () => next.promise);
    f.callbacks[0]();
    assert.equal(f.classes.has("is-working-shown"), false, "obsolete timer cannot reveal a bar");
    f.callbacks[1]();
    if (outcome === "resolve") { old.resolve(); await first; }
    else { old.reject(new Error("Old work failed.")); await assert.rejects(first, /Old work failed/); }
    assert.equal(f.button.disabled, true);
    assert.equal(f.classes.has("is-working-shown"), true);
    assert.equal(f.timers.size, 1);
    next.resolve(); await second;
    assert.equal(f.button.disabled, false);
    assert.equal(f.classes.size, 0);
    assert.equal(f.timers.size, 0);
  });
}

test("retiring visual progress preserves a newer disabled state through late timers and work", async () => {
  const f = fixture(), work = deferred();
  const pending = f.c.withButtonProgress(f.button, () => work.promise);
  const retire = f.button._buttonProgress.finish;
  retire();
  f.button.disabled = true;
  retire();
  f.callbacks[0]();
  work.resolve(); await pending;
  assert.equal(f.button.disabled, true);
  assert.equal(f.classes.size, 0);
  assert.equal(f.timers.size, 0);
});

test("a missing button preserves the work return value", async () => {
  const f = fixture();
  assert.equal(await f.c.withButtonProgress(null, () => 42), 42);
  assert.equal(f.timers.size, 0);
});
