const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function deferred() {
  let resolve, reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

function createFixture() {
  const pending = [], rendered = [];
  const classes = new Set(["hidden"]);
  const modal = { classList: {
    add: (name) => classes.add(name),
    remove: (name) => classes.delete(name),
    contains: (name) => classes.has(name),
  } };
  const button = { disabled: false, textContent: "Compare with #1" };
  const context = loadFunctions([
    "openCompareModal", "closeCompareModal", "clearCompareState", "setCompareBase",
  ], {
    compareBaseId: "base", compareBaseSessionId: "session-a", compareActiveTab: "request",
    compareBaseRecord: null, compareTargetRecord: null, compareLoadGeneration: 0,
    sessionId: "session-a",
    transactionPath: (id, sessionId) => `${sessionId}/${id}`,
    getHistoryItem: () => ({ index: 1 }),
    document: { getElementById: (id) => id === "compareModal" ? modal : button },
    fetch(path) {
      const response = deferred();
      pending.push({ path, ...response });
      return response.promise;
    },
  });
  context.currentSessionId = () => context.sessionId;
  context.renderCompareModal = () => rendered.push({
    base: context.compareBaseRecord, target: context.compareTargetRecord,
  });
  const resolve = (index, record) => pending[index].resolve({ ok: true, json: async () => record });
  const resolvePair = (offset, base, target) => {
    resolve(offset, base);
    resolve(offset + 1, target);
  };
  const hidden = () => modal.classList.contains("hidden");
  return { context, pending, rendered, button, hidden, resolve, resolvePair };
}

test("a current comparison opens the requested records from its session", async () => {
  const { context, pending, rendered, hidden, resolvePair } = createFixture();
  const base = { id: "base" }, target = { id: "target" };
  const load = context.openCompareModal("target");
  assert.deepEqual(pending.map((request) => request.path), ["session-a/base", "session-a/target"]);
  resolvePair(0, base, target);
  await load;
  assert.equal(context.compareBaseRecord, base);
  assert.equal(context.compareTargetRecord, target);
  assert.equal(hidden(), false);
  assert.deepEqual(rendered, [{ base, target }]);
});

for (const sameTarget of [false, true]) {
  test(`a slower previous comparison cannot replace the latest ${sameTarget ? "same-target" : "different-target"} comparison`, async () => {
    const { context, rendered, resolvePair } = createFixture();
    const older = context.openCompareModal("target");
    const latestId = sameTarget ? "target" : "newer-target";
    const latest = context.openCompareModal(latestId);
    const base = { id: "base", marker: "current" }, target = { id: latestId, marker: "current" };
    resolvePair(2, base, target);
    await latest;
    resolvePair(0, { id: "base", marker: "stale" }, { id: "target", marker: "stale" });
    await older;
    assert.equal(context.compareBaseRecord, base);
    assert.equal(context.compareTargetRecord, target);
    assert.deepEqual(rendered, [{ base, target }]);
  });
}

for (const bodyIndex of [0, 1]) {
  test(`a stale ${bodyIndex === 0 ? "base" : "target"} body that finishes parsing later cannot replace the latest comparison`, async () => {
    const { context, pending, rendered, resolve, resolvePair } = createFixture();
    const body = deferred();
    const older = context.openCompareModal("older-target");
    pending[bodyIndex].resolve({ ok: true, json: () => body.promise });
    resolve(1 - bodyIndex, { id: bodyIndex === 0 ? "older-target" : "base" });
    await Promise.resolve();
    const latest = context.openCompareModal("newer-target");
    const base = { id: "base" }, target = { id: "newer-target" };
    resolvePair(2, base, target);
    await latest;
    body.resolve({ id: bodyIndex === 0 ? "base" : "older-target" });
    await older;
    assert.equal(context.compareTargetRecord, target);
    assert.deepEqual(rendered, [{ base, target }]);
  });
}

for (const duringParsing of [false, true]) {
  test(`closing Compare ${duringParsing ? "during parsing" : "before the response"} prevents a late load from reopening it`, async () => {
    const { context, pending, rendered, hidden, resolve, resolvePair } = createFixture();
    const body = deferred();
    const load = context.openCompareModal("target");
    if (duringParsing) {
      resolve(0, { id: "base" });
      pending[1].resolve({ ok: true, json: () => body.promise });
      await Promise.resolve();
    }
    context.closeCompareModal();
    if (duringParsing) body.resolve({ id: "target" });
    else resolvePair(0, { id: "base" }, { id: "target" });
    await load;
    assert.equal(hidden(), true);
    assert.equal(context.compareTargetRecord, null);
    assert.deepEqual(rendered, []);
  });
}

test("dismissing the latest comparison also invalidates an older pending request", async () => {
  const { context, hidden, rendered, resolvePair } = createFixture();
  const older = context.openCompareModal("older-target");
  const latest = context.openCompareModal("newer-target");
  const base = { id: "base" }, target = { id: "newer-target" };
  resolvePair(2, base, target);
  await latest;
  context.closeCompareModal();
  resolvePair(0, { id: "base" }, { id: "older-target" });
  await older;
  assert.equal(hidden(), true);
  assert.equal(context.compareTargetRecord, target);
  assert.deepEqual(rendered, [{ base, target }]);
});

test("a fresh comparison can open after the previous request was dismissed", async () => {
  const { context, hidden, rendered, resolvePair } = createFixture();
  const older = context.openCompareModal("older-target");
  context.closeCompareModal();
  const latest = context.openCompareModal("newer-target");
  resolvePair(0, { id: "base" }, { id: "older-target" });
  await older;
  assert.equal(hidden(), true);
  const base = { id: "base" }, target = { id: "newer-target" };
  resolvePair(2, base, target);
  await latest;
  assert.equal(hidden(), false);
  assert.deepEqual(rendered, [{ base, target }]);
});

for (const returnToSameBase of [false, true]) {
  test(`changing the base${returnToSameBase ? " and returning to it" : ""} invalidates an in-flight comparison`, async () => {
    const { context, hidden, rendered, resolvePair } = createFixture();
    const load = context.openCompareModal("target");
    await context.setCompareBase("new-base");
    if (returnToSameBase) await context.setCompareBase("base");
    resolvePair(0, { id: "base" }, { id: "target" });
    await load;
    assert.equal(context.compareBaseId, returnToSameBase ? "base" : "new-base");
    assert.equal(context.compareBaseRecord, null);
    assert.equal(hidden(), true);
    assert.deepEqual(rendered, []);
  });
}

test("a comparison of a replacement base can open without an earlier request replacing it", async () => {
  const { context, pending, rendered, resolvePair } = createFixture();
  const older = context.openCompareModal("target");
  await context.setCompareBase("new-base");
  const latest = context.openCompareModal("target");
  assert.equal(pending[2].path, "session-a/new-base");
  const base = { id: "new-base" }, target = { id: "target", marker: "current" };
  resolvePair(2, base, target);
  await latest;
  resolvePair(0, { id: "base" }, { id: "target", marker: "stale" });
  await older;
  assert.deepEqual(rendered, [{ base, target }]);
});

test("clearing comparison state prevents an in-flight request from restoring its records", async () => {
  const { context, button, hidden, rendered, resolvePair } = createFixture();
  const load = context.openCompareModal("target");
  context.clearCompareState();
  resolvePair(0, { id: "base" }, { id: "target" });
  await load;
  assert.equal(context.compareBaseId, null);
  assert.equal(context.compareBaseSessionId, null);
  assert.equal(context.compareBaseRecord, null);
  assert.equal(context.compareTargetRecord, null);
  assert.equal(button.disabled, true);
  assert.equal(button.textContent, "Compare with base");
  assert.equal(hidden(), true);
  assert.deepEqual(rendered, []);
});

for (const duringParsing of [false, true]) {
  test(`a session switch ${duringParsing ? "during parsing" : "before the response"} drops the old comparison`, async () => {
    const { context, pending, hidden, rendered, resolve, resolvePair } = createFixture();
    const body = deferred();
    const load = context.openCompareModal("target");
    if (duringParsing) {
      resolve(0, { id: "base" });
      pending[1].resolve({ ok: true, json: () => body.promise });
      await Promise.resolve();
    }
    context.sessionId = "session-b";
    if (duringParsing) body.resolve({ id: "target" });
    else resolvePair(0, { id: "base" }, { id: "target" });
    await load;
    assert.equal(hidden(), true);
    assert.equal(context.compareTargetRecord, null);
    assert.deepEqual(rendered, []);
  });
}

test("switching away and back cannot restore a comparison from before the session reset", async () => {
  const { context, hidden, rendered, resolvePair } = createFixture();
  const load = context.openCompareModal("target");
  context.sessionId = "session-b";
  context.clearCompareState();
  context.sessionId = "session-a";
  context.clearCompareState();
  await context.setCompareBase("base");
  resolvePair(0, { id: "base" }, { id: "target" });
  await load;
  assert.equal(context.compareBaseId, "base");
  assert.equal(context.compareTargetRecord, null);
  assert.equal(hidden(), true);
  assert.deepEqual(rendered, []);
});

test("a base belonging to another session is cleared without loading any records", async () => {
  const { context, pending, hidden } = createFixture();
  context.sessionId = "session-b";
  await context.openCompareModal("target");
  assert.equal(context.compareBaseId, null);
  assert.equal(pending.length, 0);
  assert.equal(hidden(), true);
});

for (const failedIndex of [2, 3]) {
  test(`a failed latest ${failedIndex === 2 ? "base" : "target"} response cannot let an older comparison become current`, async () => {
    const { context, pending, rendered, hidden, resolve, resolvePair } = createFixture();
    const older = context.openCompareModal("older-target");
    const latest = context.openCompareModal("newer-target");
    pending[failedIndex].resolve({ ok: false });
    resolve(5 - failedIndex, { id: failedIndex === 2 ? "newer-target" : "base" });
    await latest;
    resolvePair(0, { id: "base" }, { id: "older-target" });
    await older;
    assert.equal(context.compareTargetRecord, null);
    assert.equal(hidden(), true);
    assert.deepEqual(rendered, []);
  });
}

test("selecting the base itself does not let an earlier comparison appear", async () => {
  const { context, pending, rendered, hidden, resolvePair } = createFixture();
  const load = context.openCompareModal("target");
  await context.openCompareModal("base");
  assert.equal(pending.length, 2);
  resolvePair(0, { id: "base" }, { id: "target" });
  await load;
  assert.equal(hidden(), true);
  assert.deepEqual(rendered, []);
});

test("a rejected stale request cannot alter the already displayed latest comparison", async () => {
  const { context, pending, rendered, resolve, resolvePair } = createFixture();
  const older = context.openCompareModal("older-target");
  const latest = context.openCompareModal("newer-target");
  const base = { id: "base" }, target = { id: "newer-target" };
  resolvePair(2, base, target);
  await latest;
  const rejected = assert.rejects(older, /offline fixture error/);
  pending[0].reject(new Error("offline fixture error"));
  resolve(1, { id: "older-target" });
  await rejected;
  assert.equal(context.compareTargetRecord, target);
  assert.deepEqual(rendered, [{ base, target }]);
});

for (const missingRecord of ["base", "target"]) {
  test(`a stale missing ${missingRecord} response leaves the latest comparison visible`, async () => {
    const { context, hidden, rendered, resolvePair } = createFixture();
    const older = context.openCompareModal("older-target");
    const latest = context.openCompareModal("newer-target");
    const base = { id: "base" }, target = { id: "newer-target" };
    resolvePair(2, base, target);
    await latest;
    resolvePair(0, missingRecord === "base" ? null : { id: "base" },
      missingRecord === "target" ? null : { id: "older-target" });
    await older;
    assert.equal(context.compareTargetRecord, target);
    assert.equal(hidden(), false);
    assert.deepEqual(rendered, [{ base, target }]);
  });
}
