const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function loadWebsocketHelpers() {
  return loadFunctions([
    "jsonArray",
    "websocketPagePayload",
    "isKnownCount",
    "buildWebsocketFilterSummary",
  ], { state: { websocketInScopeOnly: false, websocketLiveOnly: false } });
}

test("a null filtered count stays unknown for a partial WebSocket page", () => {
  const { websocketPagePayload, buildWebsocketFilterSummary } = loadWebsocketHelpers();
  const page = websocketPagePayload({
    items: [{ id: "fixture-session" }],
    total: 1000,
    filtered_total: null,
    offset: 0,
    limit: 500,
    has_more: true,
  });

  assert.equal(page.filteredTotal, null);
  // An unknown count is a lower bound while more sessions can load.
  assert.equal(buildWebsocketFilterSummary(1, 1, page.filteredTotal, page.has_more, false), "1+ sessions");
  assert.equal(buildWebsocketFilterSummary(500, 500, null, false, true), "500+ sessions · first 500 listed");
});

test("an omitted filtered count stays unknown", () => {
  const { websocketPagePayload } = loadWebsocketHelpers();
  assert.equal(websocketPagePayload({ items: [], total: 10 }).filteredTotal, null);
});

test("known zero and positive filtered counts are preserved", () => {
  const { websocketPagePayload, buildWebsocketFilterSummary } = loadWebsocketHelpers();
  for (const value of [0, 25, "25"]) {
    const page = websocketPagePayload({ items: [], total: 50, filtered_total: value });
    assert.equal(page.filteredTotal, Number(value));
  }
  assert.equal(buildWebsocketFilterSummary(0, 0, 0, false, false), "0 sessions");
  assert.equal(buildWebsocketFilterSummary(1, 1, 1, false, false), "1 session");
  assert.equal(buildWebsocketFilterSummary(500, 500, 1200, false, true), `${(1200).toLocaleString()} sessions · first 500 listed`);
});

test("invalid filtered counts stay unknown and legacy arrays still load", () => {
  const { websocketPagePayload } = loadWebsocketHelpers();
  assert.equal(websocketPagePayload({ filtered_total: "invalid" }).filteredTotal, null);
  const items = [{ id: "fixture-session" }];
  const page = websocketPagePayload(items);
  assert.equal(page.items, items);
  assert.equal(page.total, 1);
  assert.equal(page.has_more, false);
});
