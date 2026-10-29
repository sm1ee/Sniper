// Top-bar update presentation only. Actual frontend handlers run in a VM with
// synthetic fetches, progress streams, clocks, and window.open. No app startup,
// network, browser, download, updater, installer, restart, or user data access.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const nextTurn = () => new Promise(resolve => setImmediate(resolve));
const RELEASE_TITLE = "Update to v9.9.9";

function element() {
  const classes = new Set();
  const attributes = new Map();
  let text = "Update";
  let html = "";
  let arc = null;
  return {
    title: RELEASE_TITLE,
    style: {},
    classList: {
      add: (...names) => names.forEach(name => classes.add(name)),
      remove: (...names) => names.forEach(name => classes.delete(name)),
      contains: name => classes.has(name),
      toggle(name, force) {
        const add = force === undefined ? !classes.has(name) : force;
        if (add) classes.add(name); else classes.delete(name);
        return add;
      },
    },
    setAttribute(name, value) { attributes.set(name, String(value)); },
    getAttribute(name) { return attributes.get(name) ?? null; },
    removeAttribute(name) { attributes.delete(name); },
    getBoundingClientRect() { return { width: 70 }; },
    get textContent() { return text; },
    set textContent(value) {
      text = value;
      html = "";
      // DOM text replacement detaches the old ring; keeping it here would hide
      // a stale timer replacing the active attempt's progress presentation.
      arc = null;
    },
    get innerHTML() { return html; },
    set innerHTML(value) {
      html = value;
      text = "";
      arc = value.includes("update-ring-arc") ? { style: {} } : null;
    },
    querySelector(selector) {
      assert.equal(selector, ".update-ring-arc");
      return arc;
    },
  };
}

function syntheticProgressStream() {
  const pending = [];
  const queued = [];
  let readCount = 0;
  const deliver = item => {
    const waiter = pending.shift();
    if (!waiter) queued.push(item);
    else if (item.error) waiter.reject(item.error);
    else waiter.resolve(item);
  };
  return {
    body: {
      getReader() {
        return {
          read() {
            readCount += 1;
            const item = queued.shift();
            if (item) return item.error ? Promise.reject(item.error) : Promise.resolve(item);
            return new Promise((resolve, reject) => pending.push({ resolve, reject }));
          },
        };
      },
    },
    event(payload) { this.raw(`data: ${JSON.stringify(payload)}\n\n`); },
    raw(value) { deliver({ done: false, value: new TextEncoder().encode(value) }); },
    end() { deliver({ done: true }); },
    error() { deliver({ error: new Error("Synthetic connection lost") }); },
    readCount() { return readCount; },
  };
}

function fixture() {
  const button = element();
  const requests = [];
  const timers = new Map();
  const timerHistory = [];
  const opened = [];
  let now = 0;
  let nextTimerId = 1;
  const state = {
    appVersion: {
      current_version: "0.0.0", latest_version: "v9.9.9",
      update_available: true, self_update_supported: true,
    },
    activeTool: "proxy",
  };
  const context = loadFunctions([
    "loadAppVersionInfo", "performSelfUpdate", "requireOkResponse",
    "readApiErrorMessage", "formatStructuredApiErrorMessage", "retireFindingActionProgress", "invalidateFindingNavigation", "setActiveTool",
  ], {
    closeScannerSettings() {},
    TextDecoder,
    state,
    appVersionReadGeneration: 0,
    els: { openUpdateButton: button, appVersionLabel: element() },
    console: { error() {} },
    fetch(url, options) {
      return new Promise((resolve, reject) => requests.push({ url, options, resolve, reject }));
    },
    setTimeout(callback, delay) {
      const timer = { id: nextTimerId++, callback, delay, due: now + delay, cleared: false };
      timers.set(timer.id, timer);
      timerHistory.push(timer);
      return timer.id;
    },
    clearTimeout(id) {
      const timer = timers.get(id);
      if (timer) timer.cleared = true;
      timers.delete(id);
    },
    window: { open(...args) { opened.push(args); } },
    sanitizeActiveTool: value => value,
    scheduleUiSettingsSave() { throw new Error("Persistence is outside this inert fixture"); },
  });
  for (const pattern of [
    /^const UPDATE_STEPS = new Set\(\[[^]*?^\]\);/m,
    /^const UPDATE_RING_MARKUP = `[^]*?`;/m,
  ]) {
    const match = appSource.match(pattern);
    assert.ok(match, `Missing production update constant: ${pattern}`);
    vm.runInContext(match[0], context);
  }
  // Before the fix this declaration is absent and no old handler refers to it.
  // After the fix, load the production owner declaration alongside its handler.
  const owner = appSource.match(/^let pendingSelfUpdateFailureReset = null;/m);
  if (owner) vm.runInContext(owner[0], context);

  function advance(milliseconds) {
    const until = now + milliseconds;
    for (;;) {
      const timer = [...timers.values()].filter(item => item.due <= until)
        .sort((a, b) => a.due - b.due || a.id - b.id)[0];
      if (!timer) break;
      now = timer.due;
      timers.delete(timer.id);
      timer.callback();
    }
    now = until;
  }
  const resolve = (index, stream) => requests[index].resolve({ ok: true, body: stream?.body ?? null });
  async function start() {
    const stream = syntheticProgressStream();
    const task = context.performSelfUpdate();
    resolve(requests.length - 1, stream);
    await nextTurn();
    return { task, stream };
  }
  async function fail(attempt, reason = "Synthetic failure") {
    attempt.stream.event({ step: `error: ${reason}` });
    await attempt.task;
  }
  return { context, button, state, requests, timers, timerHistory, opened, advance, resolve, start, fail };
}

function assertUpdating(fixture) {
  const { button } = fixture;
  assert.equal(button.getAttribute("aria-disabled"), "true", "active update keeps its click guard");
  assert.equal(button.getAttribute("aria-busy"), "true", "active update remains busy");
  assert.equal(button.classList.contains("is-updating"), true);
  assert.ok(button.querySelector(".update-ring-arc"), "active update keeps its visible ring");
  assert.equal(button.style.width, "70px");
}

function assertIdle(fixture) {
  const { button } = fixture;
  assert.equal(button.textContent, "Update");
  assert.equal(button.title, RELEASE_TITLE);
  assert.equal(button.style.width, "");
  for (const attribute of ["aria-busy", "aria-disabled", "aria-label"]) {
    assert.equal(button.getAttribute(attribute), null);
  }
  for (const className of ["is-updating", "is-busy", "is-failed"]) {
    assert.equal(button.classList.contains(className), false);
  }
}

for (const percent of [null, 42]) {
  test(`failure clears the ${percent === null ? "busy" : "percentage"} accessible name before retry`, async () => {
    const f = fixture();
    const first = await f.start();
    if (percent !== null) {
      first.stream.event({ step: "Downloading update...", percent });
      await nextTurn();
    }
    assert.equal(f.button.getAttribute("aria-label"), percent === null
      ? "Updating" : "Updating, 42 percent");
    await f.fail(first);
    assert.equal(f.button.textContent, "Failed");
    assert.equal(f.button.getAttribute("aria-label"), null,
      "The visible failure text must not be overridden by stale progress");
    const retry = await f.start();
    assert.equal(f.button.getAttribute("aria-label"), "Updating");
    retry.stream.event({ step: "Downloading update...", percent: 17 });
    await nextTurn();
    assert.equal(f.button.getAttribute("aria-label"), "Updating, 17 percent");
    await f.fail(retry);
    assert.equal(f.button.getAttribute("aria-label"), null);
    f.advance(4000);
    assertIdle(f);
    assert.equal(f.requests.length, 2);
  });
}

test("version metadata reveals the update button and preserves its release tooltip", async () => {
  const f = fixture();
  const pending = f.context.loadAppVersionInfo();
  assert.equal(f.requests[0].url, "/api/app-version");
  f.requests[0].resolve({ ok: true, json: async () => f.state.appVersion });
  await pending;
  assert.equal(f.context.els.appVersionLabel.textContent, "v0.0.0");
  assert.equal(f.button.title, RELEASE_TITLE);
  assert.equal(f.button.classList.contains("hidden"), false);
});

test("version metadata without an update hides the button", async () => {
  const f = fixture();
  const pending = f.context.loadAppVersionInfo();
  f.requests[0].resolve({ ok: true, json: async () => ({ ...f.state.appVersion, update_available: false }) });
  await pending;
  assert.equal(f.button.classList.contains("hidden"), true);
});

test("version metadata failure leaves the old button untouched and starts no update", async () => {
  const f = fixture();
  const pending = f.context.loadAppVersionInfo();
  f.requests[0].resolve({ ok: false, text: async () => "Synthetic metadata failure" });
  await assert.rejects(pending, /Synthetic metadata failure/);
  assert.equal(f.button.title, RELEASE_TITLE);
  assert.equal(f.requests.length, 1);
});

test("unsupported platform calls only the synthetic release-link opener", async () => {
  const f = fixture();
  f.state.appVersion.self_update_supported = false;
  f.state.appVersion.latest_release_url = "https://example.com/release";
  await f.context.performSelfUpdate();
  assert.equal(f.requests.length, 0);
  assert.deepEqual(f.opened, [["https://example.com/release", "_blank", "noopener,noreferrer"]]);
});

test("normal progress and Restarting retain the pending-restart presentation", async () => {
  const f = fixture();
  const attempt = await f.start();
  assertUpdating(f);
  attempt.stream.event({ step: "Downloading update...", percent: 42 });
  await nextTurn();
  assert.equal(f.button.title, "42%");
  assert.equal(f.button.querySelector(".update-ring-arc").style.strokeDasharray, "42 100");
  attempt.stream.event({ step: "Synthetic diagnostic detail" });
  await nextTurn();
  assert.equal(f.button.title, "42%");
  attempt.stream.event({ step: "Restarting..." });
  attempt.stream.end();
  await attempt.task;
  assertUpdating(f);
  assert.equal(f.button.classList.contains("is-busy"), true);
  assert.equal(f.timers.size, 0);
});

test("duplicate click while fetch is pending sends one synthetic POST", async () => {
  const f = fixture();
  const pending = f.context.performSelfUpdate();
  await f.context.performSelfUpdate();
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].url, "/api/self-update");
  assert.equal(f.requests[0].options.method, "POST");
  f.resolve(0);
  await pending;
});

test("duplicate click while progress is pending sends one synthetic POST", async () => {
  const f = fixture();
  const attempt = await f.start();
  await f.context.performSelfUpdate();
  assert.equal(f.requests.length, 1);
  attempt.stream.end();
  await attempt.task;
});

test("server failure is retryable and resets its presentation after four seconds", async () => {
  const f = fixture();
  await f.fail(await f.start());
  assert.equal(f.button.textContent, "Failed");
  assert.equal(f.button.title, "Synthetic failure");
  assert.equal(f.button.getAttribute("aria-disabled"), null);
  assert.equal(f.timerHistory[0].delay, 4000);
  f.advance(3999);
  assert.equal(f.button.textContent, "Failed");
  f.advance(1);
  assertIdle(f);
  assert.equal(f.timers.size, 0);
});

test("HTTP start failure exposes the response error and remains retryable", async () => {
  const f = fixture();
  const pending = f.context.performSelfUpdate();
  f.requests[0].resolve(new Response("Synthetic start refused", { status: 500 }));
  await pending;
  assert.equal(f.button.textContent, "Failed");
  assert.equal(f.button.title, "Synthetic start refused");
  assert.equal(f.button.getAttribute("aria-disabled"), null);
  f.advance(4000);
  assertIdle(f);
});

test("fetch failure resets without automatically retrying", async () => {
  const f = fixture();
  const pending = f.context.performSelfUpdate();
  f.requests[0].reject(new Error("Synthetic fetch failure"));
  await pending;
  assert.equal(f.button.title, "Synthetic fetch failure");
  f.advance(4000);
  assertIdle(f);
  assert.equal(f.requests.length, 1);
});

test("connection loss before Restarting reports failure", async () => {
  const f = fixture();
  const attempt = await f.start();
  attempt.stream.error();
  await attempt.task;
  assert.equal(f.button.textContent, "Failed");
  assert.equal(f.button.title, "Synthetic connection lost");
});

test("connection loss after Restarting retains pending-restart presentation", async () => {
  const f = fixture();
  const attempt = await f.start();
  attempt.stream.event({ step: "Restarting..." });
  await nextTurn();
  attempt.stream.error();
  await attempt.task;
  assertUpdating(f);
  assert.equal(f.timers.size, 0);
});

test("fragmented progress and malformed frames preserve existing stream handling", async () => {
  const f = fixture();
  const attempt = await f.start();
  attempt.stream.raw('data: not-json\n\ndata: {"step":"Downloading update...","percent":');
  attempt.stream.raw("25}\n\n");
  await nextTurn();
  assert.equal(f.button.title, "25%");
  attempt.stream.end();
  await attempt.task;
});

test("a failed attempt stops consuming late progress while an explicit retry runs", async () => {
  const f = fixture();
  const first = await f.start();
  await f.fail(first, "First synthetic failure");
  const previousReadCount = first.stream.readCount();
  const second = await f.start();
  second.stream.event({ step: "Downloading update...", percent: 17 });
  await nextTurn();
  first.stream.event({ step: "Downloading update...", percent: 99 });
  await nextTurn();
  assert.equal(first.stream.readCount(), previousReadCount);
  assert.equal(f.button.title, "17%");
  assertUpdating(f);
  second.stream.end();
  await second.task;
});

test("a tool-state change leaves shared top-bar progress intact", async () => {
  const f = fixture();
  const attempt = await f.start();
  f.context.setActiveTool("replay", { persist: false });
  attempt.stream.event({ step: "Downloading update...", percent: 51 });
  await nextTurn();
  assert.equal(f.state.activeTool, "replay");
  assert.equal(f.button.title, "51%");
  assertUpdating(f);
  assert.equal(f.requests.length, 1);
  attempt.stream.end();
  await attempt.task;
});

test("a superseded failure callback cannot clear an active retry", async () => {
  const f = fixture();
  await f.fail(await f.start(), "First synthetic failure");
  const oldTimer = f.timerHistory[0];
  const second = await f.start();
  second.stream.event({ step: "Downloading update...", percent: 17 });
  await nextTurn();
  // Even a callback already queued before cancellation must respect ownership.
  oldTimer.callback();
  assert.equal(f.button.title, "17%");
  assertUpdating(f);
  second.stream.end();
  await second.task;
});

test("a superseded failure callback cannot enable a third duplicate POST", async () => {
  const f = fixture();
  await f.fail(await f.start(), "First synthetic failure");
  const oldTimer = f.timerHistory[0];
  const second = await f.start();
  oldTimer.callback();
  const third = f.context.performSelfUpdate();
  if (f.requests.length === 3) f.resolve(2);
  await third;
  second.stream.end();
  await second.task;
  assert.equal(f.requests.length, 2, "an active retry still owns the click guard");
});

test("repeated failure resets restore the original release tooltip", async () => {
  const f = fixture();
  await f.fail(await f.start(), "First synthetic failure");
  await f.fail(await f.start(), "Second synthetic failure");
  f.advance(4000);
  assertIdle(f);
  assert.equal(f.timers.size, 0);
});

test("an explicit retry immediately clears the previous failed visual state", async () => {
  const f = fixture();
  await f.fail(await f.start(), "First synthetic failure");
  const second = await f.start();
  assert.equal(f.button.classList.contains("is-failed"), false);
  assert.equal(f.button.title, "");
  assertUpdating(f);
  second.stream.end();
  await second.task;
});

test("starting an explicit retry cancels the previous failure timer", async () => {
  const f = fixture();
  await f.fail(await f.start(), "First synthetic failure");
  const oldTimer = f.timerHistory[0];
  const second = await f.start();
  assert.equal(oldTimer.cleared, true);
  assert.equal(f.timers.size, 0);
  f.advance(4000);
  assertUpdating(f);
  second.stream.end();
  await second.task;
});

test("a newer failure receives its own full four-second display", async () => {
  const f = fixture();
  await f.fail(await f.start(), "First synthetic failure");
  const oldTimer = f.timerHistory[0];
  f.advance(1000);
  const second = await f.start();
  f.advance(1000);
  await f.fail(second, "Second synthetic failure");
  // A queued old callback must not reset the new failure or clear its timer.
  oldTimer.callback();
  assert.equal(f.button.textContent, "Failed");
  assert.equal(f.button.title, "Second synthetic failure");
  f.advance(3999);
  assert.equal(f.button.textContent, "Failed");
  assert.equal(f.button.title, "Second synthetic failure");
  f.advance(1);
  assertIdle(f);
  assert.equal(f.timers.size, 0);
});
