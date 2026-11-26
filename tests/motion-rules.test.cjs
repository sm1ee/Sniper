"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8")
  .replace(/\r\n/g, "\n").replace(/\/\*[\s\S]*?\*\//g, "");
const rules = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)]
  .map(([, selector, body]) => ({ selector: selector.trim().replace(/\s+/g, " "), body }));
const declared = (selector) => rules.filter((rule) => rule.selector.split(",").map((part) => part.trim()).includes(selector))
  .map((rule) => rule.body).join("\n");

// A tab shrank to 92% under the pointer's press, and a colour dot grew by a
// fifth when pointed at. A control stays the size it is, and says it is
// pressed or pointed at with its colour.
test("no control changes size when it is pressed or pointed at", () => {
  const resized = rules.filter((rule) => /:(hover|active)/.test(rule.selector) && /scale\(/.test(rule.body))
    .map((rule) => rule.selector);
  assert.deepEqual(resized, []);
  assert.match(declared(".primary-action:active"), /opacity: 0\.8;/, "a press still shows");
  assert.doesNotMatch(declared(".primary-action"), /transition:[^;]*transform/);
});

// Rows are selected with the arrow keys and rewritten as traffic arrives. A
// background that fades left a trail behind the selection and a blink under
// the pointer.
test("a table row's background does not fade", () => {
  assert.doesNotMatch(declared(".history-row"), /transition/);
});

// White at a few percent shows on a dark theme and is nothing on a light one,
// where pointing at a row then gave no sign. The theme's own text colour at
// the same strength shows on both.
test("pointing at something is shown with the theme's colour, not with white", () => {
  const fixed = rules.filter((rule) => rule.selector.includes(":hover")
    && /background(-color)?:\s*rgba\(255, 255, 255, 0\.0\d+\)/.test(rule.body)).map((rule) => rule.selector);
  assert.deepEqual(fixed, []);
  assert.match(declared(".history-row:hover"), /background: color-mix\(in srgb, var\(--text\) 4%, transparent\);/);
});
