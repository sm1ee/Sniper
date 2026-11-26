// Source/layout-budget contracts, not browser font or geometry assertions.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");
const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8").replace(/\r\n/g, "\n");
const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8").replace(/\r\n/g, "\n");

function rule(selector) {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = css.match(new RegExp(`^${escaped}\\s*\\{([^}]+)\\}`, "m"));
  assert.ok(match, `missing ${selector}`);
  return match[1];
}

function width(selector) {
  return Number(rule(selector).match(/(?:^|;)\s*width:\s*(\d+)px/)[1]);
}

// The queue's own box in a window 1280 wide with the session list at the
// width it starts with: the list takes 208px, and the queue's half of what is
// left is 472px. Measured in the app; the split and its margins set it.
const BESIDE_THE_SESSION_LIST = 472;

test("both intercept queues use readable fixed columns and flexible Host/Path", () => {
  for (const id of ["interceptRequestTable", "responseInterceptTable"]) {
    const table = html.match(new RegExp(`<table[^>]*id="${id}"[\\s\\S]*?</table>`))[0];
    assert.match(table, /class="mini-table intercept-queue-table(?: hidden)?"/);
    for (const name of ["method", "host", "path", "time"]) {
      assert.match(table, new RegExp(`<th class="iq-col-${name}">`));
    }
    if (id === "responseInterceptTable") assert.match(table, /<th class="iq-col-status">/);
  }
  assert.equal(width(".iq-col-method"), 80);
  assert.equal(width(".iq-col-status"), 70);
  // The time of day and no date.
  assert.equal(width(".iq-col-time"), 88);
  for (const name of ["host", "path"]) assert.match(rule(`.iq-col-${name}`), /width:\s*auto;/);
});

test("narrow queues scroll locally and retain a usable Host/Path budget", () => {
  // Two classes outrank the later narrow-screen .mini-table min-width reset.
  const min = Number(rule(".mini-table.intercept-queue-table").match(/min-width:\s*(\d+)px/)[1]);
  assert.match(rule(".history-table-shell"), /overflow:\s*auto;/);
  assert.match(rule(".mini-table"), /table-layout:\s*fixed;/);
  for (const container of [320, 400, BESIDE_THE_SESSION_LIST, 520, 640]) {
    const tableWidth = Math.max(container, min);
    const requestRemainder = tableWidth - width(".iq-col-method") - width(".iq-col-time");
    const responseRemainder = requestRemainder - width(".iq-col-status");
    assert.ok(requestRemainder / 2 >= 152);
    assert.ok(responseRemainder / 2 >= 117);
  }
});

// The session list took 208px of every window. At 1280 the queue's table was
// wider than its box, scrolled sideways, and its Time column was cut off.
test("the queues show every column beside the session list in a window 1280 wide", () => {
  const min = Number(rule(".mini-table.intercept-queue-table").match(/min-width:\s*(\d+)px/)[1]);
  assert.ok(min <= BESIDE_THE_SESSION_LIST, `the table is at least ${min}px wide and its box is ${BESIDE_THE_SESSION_LIST}px`);
});

// A hold is minutes old: the queue says the time of day, which leaves the
// width to Host and Path, and the day is in the cell's tooltip.
test("a held message shows the time of day, and the day in its tooltip", () => {
  const { formatHeldTime } = loadFunctions(["formatHeldTime"], {});
  // Local times, so the test reads the same in any time zone.
  assert.equal(formatHeldTime(new Date(2026, 10, 26, 9, 5, 7).toISOString()), "09:05:07");
  assert.equal(formatHeldTime(new Date(2026, 10, 26, 23, 59, 59).toISOString()), "23:59:59");
  assert.equal(formatHeldTime(new Date(2026, 10, 26, 0, 0, 0).toISOString()), "00:00:00", "midnight is 00, not 24");
  assert.equal(formatHeldTime(null), "-");
  assert.equal(formatHeldTime("not a time"), "-");
  const cells = [...appSource.matchAll(/<td class="iq-col-time"[^\n]*<\/td>/g)].map(match => match[0]);
  assert.deepEqual(cells, Array(2).fill(
    '<td class="iq-col-time" title="${escapeHtml(formatTimestamp(item.started_at))}">${escapeHtml(formatHeldTime(item.started_at))}</td>',
  ), "the request queue and the response queue");
});
