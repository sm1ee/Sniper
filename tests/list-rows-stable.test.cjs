"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

// Findings, Intercept and OAST are read again every second or so. Writing the
// same rows again made new elements each time, which took the pointer's hover
// and the keyboard's focus from the row they were on.
test("rows are written only when they differ from what was written last", () => {
  const { writeRows } = loadFunctions(["writeRows"], {});
  let writes = 0;
  const body = { set innerHTML(value) { writes += 1; this.shown = value; } };
  assert.equal(writeRows(body, "<tr><td>a</td></tr>"), true);
  assert.equal(writeRows(body, "<tr><td>a</td></tr>"), false, "the same rows are left alone");
  assert.equal(writes, 1);
  assert.equal(writeRows(body, "<tr><td>b</td></tr>"), true);
  assert.equal(body.shown, "<tr><td>b</td></tr>");
  // Each list keeps its own.
  const other = { set innerHTML(value) { this.shown = value; } };
  assert.equal(writeRows(other, "<tr><td>b</td></tr>"), true);
});

test("the lists that are read on a timer write their rows through it", () => {
  for (const body of ["findingsBody", "oastTableBody", "interceptTableBody", "responseInterceptTableBody"]) {
    assert.doesNotMatch(appSource, new RegExp(`els\\.${body}\\.innerHTML\\s*=`), `${body} is written directly`);
    assert.match(appSource, new RegExp(`writeRows\\(\\s*els\\.${body},`), `${body} does not use writeRows`);
  }
  // A row's own listeners are added once, with the row.
  assert.match(appSource, /if \(writeRows\(\s*els\.interceptTableBody,[\s\S]{0,1600}?\)\) \{\s*Array\.from\(els\.interceptTableBody\.querySelectorAll/);
});
