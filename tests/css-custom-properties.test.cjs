"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

// A declaration that reads a property nothing defines, with no fallback, is
// invalid when it is computed: the radius, colour or font quietly becomes the
// default, and nothing reports it.
test("the stylesheet reads no custom property that nothing defines", () => {
  const web = path.join(__dirname, "../web");
  const css = fs.readFileSync(path.join(web, "styles.css"), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
  const defined = new Set([...css.matchAll(/(--[\w-]+)\s*:/g)].map((match) => match[1]));
  // A script or the markup can set one too.
  for (const file of fs.readdirSync(web).filter((name) => /\.(js|html)$/.test(name))) {
    const text = fs.readFileSync(path.join(web, file), "utf8");
    for (const match of text.matchAll(/setProperty\(\s*["'`](--[\w-]+)/g)) defined.add(match[1]);
    for (const match of text.matchAll(/(--[\w-]+)\s*:/g)) defined.add(match[1]);
  }
  const read = [...css.matchAll(/var\(\s*(--[\w-]+)\s*\)/g)].map((match) => match[1]);
  const missing = [...new Set(read.filter((name) => !defined.has(name)))].sort();
  // Older rules that still need a token that exists. Nothing may join them.
  const known = ["--code-font", "--font-mono", "--muted", "--radius"];
  assert.deepEqual(missing.filter((name) => !known.includes(name)), []);
});
