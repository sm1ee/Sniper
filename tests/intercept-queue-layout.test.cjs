// Source/layout-budget contracts, not browser font or geometry assertions.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");
const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");

function rule(selector) {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = css.match(new RegExp(`^${escaped}\\s*\\{([^}]+)\\}`, "m"));
  assert.ok(match, `missing ${selector}`);
  return match[1];
}

function width(selector) {
  return Number(rule(selector).match(/(?:^|;)\s*width:\s*(\d+)px/)[1]);
}

test("both intercept queues use readable fixed columns and flexible Host/Path", () => {
  for (const id of ["interceptRequestTable", "responseInterceptTable"]) {
    const table = html.match(new RegExp(`<table[^>]*id="${id}"[\\s\\S]*?</table>`))[0];
    assert.match(table, /class="mini-table intercept-queue-table(?: hidden)?"/);
    for (const name of ["method", "host", "path", "time"]) {
      assert.match(table, new RegExp(`<th class="iq-col-${name}">`));
    }
    if (id === "responseInterceptTable") assert.match(table, /<th class="iq-col-status">/);
  }
  assert.equal(width(".iq-col-method"), 96);
  assert.equal(width(".iq-col-status"), 70);
  assert.equal(width(".iq-col-time"), 120);
  for (const name of ["host", "path"]) assert.match(rule(`.iq-col-${name}`), /width:\s*auto;/);
});

test("narrow queues scroll locally and retain a usable Host/Path budget", () => {
  // Two classes outrank the later narrow-screen .mini-table min-width reset.
  const min = Number(rule(".mini-table.intercept-queue-table").match(/min-width:\s*(\d+)px/)[1]);
  assert.equal(min, 520);
  assert.match(rule(".history-table-shell"), /overflow:\s*auto;/);
  assert.match(rule(".mini-table"), /table-layout:\s*fixed;/);
  for (const container of [320, 400, 520, 640]) {
    const tableWidth = Math.max(container, min);
    const requestRemainder = tableWidth - width(".iq-col-method") - width(".iq-col-time");
    const responseRemainder = requestRemainder - width(".iq-col-status");
    assert.ok(requestRemainder / 2 >= 152);
    assert.ok(responseRemainder / 2 >= 117);
  }
});
