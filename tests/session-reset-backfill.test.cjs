"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { appSource } = require("./frontend-test-helpers.cjs");

// Showing another session empties the history and draws it. An empty list that
// may hold more asks for more at once, and at that moment the session on
// screen is still the one being left: a page of up to 5,000 of its rows was
// read and thrown away on every change of session.
test("emptying the history for another session cancels the read for more that the redraw asks for", () => {
  const start = appSource.indexOf("function resetSessionScopedUiState() {");
  assert.ok(start >= 0);
  const body = appSource.slice(start, appSource.indexOf("\n}\n", start));
  assert.match(body, /\n  renderHistory\(\);\n(?:  \/\/[^\n]*\n)*  clearHistoryBackfill\(\);\n/);
});
