// Markup-only checks: the Settings control must not depend on an OS emoji font.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");
const button = html.match(/<button\b[^>]*\bid="openDisplaySettingsButton"[^>]*>([^]*?)<\/button>/);
assert.ok(button, "Missing Settings button");

test("Settings retains its native button and accessible name", () => {
  const openingTag = button[0].slice(0, button[0].indexOf(">") + 1);
  assert.match(openingTag, /\bclass="utility-button icon-button"/);
  assert.match(openingTag, /\btype="button"/);
  assert.match(openingTag, /\baria-label="Settings"/);
  assert.match(openingTag, /\btitle="Settings"/);
  assert.doesNotMatch(openingTag, /\b(?:disabled|tabindex|aria-hidden)\b/);
  assert.equal((html.match(/\bid="openDisplaySettingsButton"/g) || []).length, 1);
});

test("Settings uses a self-contained theme-colored SVG instead of a font glyph", () => {
  const svg = button[1].match(/^\s*<svg\b([^>]*)>([^]*?)<\/svg>\s*$/);
  assert.ok(svg, "Settings must contain only an inline SVG");
  for (const attribute of [
    'width="18"', 'height="18"', 'viewBox="0 0 24 24"',
    'fill="currentColor"', 'aria-hidden="true"', 'focusable="false"',
  ]) assert.ok(svg[1].includes(attribute), `Missing SVG ${attribute}`);
  assert.match(svg[2], /<path\b[^>]*\bfill-rule="evenodd"[^>]*\bd="[^"]+"\s*\/>/);
  assert.doesNotMatch(button[1], /[\u2699\ufe0f]|&#(?:9881|x2699);/i);
  assert.doesNotMatch(svg[0], /<(?:text|image|use|foreignObject|script)\b|\b(?:href|src|tabindex|on\w+)\s*=/i);
  assert.doesNotMatch(svg[2], /\b(?:fill|stroke)="(?!currentColor")/);
});

test("Settings keeps its existing compact button geometry", () => {
  const rule = css.match(/\.utility-button\.icon-button\s*\{([^}]+)\}/);
  assert.ok(rule, "Missing icon-button styles");
  for (const property of ["width", "min-width", "height", "min-height"]) {
    assert.match(rule[1], new RegExp(`(?:^|[;\\s])${property}:\\s*24px;`));
  }
  assert.match(rule[1], /padding:\s*0;/);
});
