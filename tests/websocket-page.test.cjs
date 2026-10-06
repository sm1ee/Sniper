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
  const summary = buildWebsocketFilterSummary(
    1, 1, 1, page.total, page.filteredTotal, page.has_more, false, "example.com",
  );
  assert.match(summary, /1\/1000 sessions loaded/);
  assert.doesNotMatch(summary, /\/0 matching sessions/);
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
  assert.match(buildWebsocketFilterSummary(0, 0, 0, 50, 0, false, false, "missing"), /0 matching of 50 total/);
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
