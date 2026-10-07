// Comparison-label fixtures only; no transaction reads or app runtime start.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");
const record = (id, sequence) => ({ id, sequence, method: "GET", host: "example.com", path: `/${id}` });
function fixture(items = []) {
  const nodes = new Map();
  const itemMap = new Map(items.map(item => [item.id, item]));
  const c = loadFunctions(["setCompareBase", "renderCompareModal"], {
    compareLoadGeneration: 0, compareBaseId: null, compareBaseSessionId: null,
    compareBaseRecord: record("base", 1201), compareTargetRecord: record("target", 1302), compareActiveTab: "request",
    currentSessionId: () => "saved-session", getHistoryItem: id => itemMap.get(id),
    document: { getElementById(id) { if (!nodes.has(id)) nodes.set(id, {}); return nodes.get(id); }, querySelectorAll: () => [] },
    buildRawRequest: row => `Saved request ${row.id}`, buildRawResponse: row => `Saved response ${row.id}`,
    computeUnifiedDiff: () => "Saved fixture diff", renderDiffHtml: text => text,
  });
  return { c, nodes, itemMap };
}

for (const sequence of [0, 7, 1201]) {
  test(`comparison base button uses the saved sequence ${sequence}`, async () => {
    const f = fixture([{ id: "base", sequence }]);
    await f.c.setCompareBase("base");
    assert.equal(f.nodes.get("compareWithBaseBtn").textContent, `Compare with #${sequence}`);
    assert.equal(f.c.compareBaseId, "base");
    assert.equal(f.c.compareBaseSessionId, "saved-session");
    assert.equal(f.c.compareLoadGeneration, 1);
  });
}

test("choosing a base absent from the cache clears the previous base's button label", async () => {
  const f = fixture([{ id: "old-base", sequence: 4, index: 4 }]);
  await f.c.setCompareBase("old-base");
  await f.c.setCompareBase("uncached-base");
  assert.equal(f.nodes.get("compareWithBaseBtn").textContent, "Compare with base");
  assert.equal(f.nodes.get("compareWithBaseBtn").disabled, false);
  assert.equal(f.c.compareBaseId, "uncached-base");
});

test("a legacy cached index still labels the base button", async () => {
  const f = fixture([{ id: "base", index: 9 }]);
  await f.c.setCompareBase("base");
  assert.equal(f.nodes.get("compareWithBaseBtn").textContent, "Compare with #9");
});

for (const tab of ["request", "response"]) {
  test(`${tab} comparison keeps loaded record sequence labels after row-cache eviction`, () => {
    const f = fixture();
    f.c.compareActiveTab = tab;
    f.c.renderCompareModal();
    assert.equal(f.nodes.get("compareKicker").textContent, "#1201 GET example.com/base  vs  #1302 GET example.com/target");
  });
}

test("comparison labels prefer actual compared record sequences over cached display metadata", () => {
  const f = fixture([{ id: "base", sequence: 2, index: 5 }, { id: "target", sequence: 3, index: 6 }]);
  f.c.compareBaseRecord.sequence = 0;
  f.c.renderCompareModal();
  assert.equal(f.nodes.get("compareKicker").textContent, "#0 GET example.com/base  vs  #1302 GET example.com/target");
});

test("legacy compared records can use cached summary sequences or indexes", () => {
  const f = fixture([{ id: "base", sequence: 8 }, { id: "target", index: 9 }]);
  f.c.compareBaseRecord.sequence = undefined;
  f.c.compareTargetRecord.sequence = undefined;
  f.c.renderCompareModal();
  assert.equal(f.nodes.get("compareKicker").textContent, "#8 GET example.com/base  vs  #9 GET example.com/target");
});

test("comparison labels remain explicitly unknown if neither source has a number", () => {
  const f = fixture();
  f.c.compareBaseRecord.sequence = undefined;
  f.c.compareTargetRecord.sequence = undefined;
  f.c.renderCompareModal();
  assert.equal(f.nodes.get("compareKicker").textContent, "#? GET example.com/base  vs  #? GET example.com/target");
});
