// Status display metadata only, with no request or response activity.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");
const c = loadFunctions(["statusTone", "formatStatus", "renderHistoryCell", "escapeHtml"]);

for (const status of [null, undefined]) {
  test(`${String(status)} missing status has the existing neutral n/a presentation`, () => {
    const item = { status };
    assert.equal(c.statusTone(status), "none");
    assert.equal(c.formatStatus(status), "n/a");
    assert.equal(c.renderHistoryCell("status", item, {}), '<td><span class="status-pill-row none">n/a</span></td>');
    assert.equal(item.status, status);
  });
}

test("all existing numeric status palettes remain unchanged", () => {
  for (let code = 100; code <= 999; code++) {
    const expected = code >= 200 && code < 300 ? "ok"
      : code >= 300 && code < 400 ? "info"
      : code >= 400 && code < 500 ? "warn" : "error";
    assert.equal(c.statusTone(code), expected);
    assert.equal(c.statusTone(String(code)), expected);
    assert.equal(c.formatStatus(code), String(code));
  }
});
