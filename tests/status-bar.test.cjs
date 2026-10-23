// The status bar holds the event log and its count. It once also named the tab
// in front and the body preview cap, which the tabs and Settings already show.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
const app = fs.readFileSync(path.join(__dirname, "../web/app.js"), "utf8");

test("the status bar holds the event log and nothing that repeats the tabs", () => {
  const bar = html.match(/<footer class="status-bar">[^]*?<\/footer>/)[0];
  const ids = [...bar.matchAll(/id="([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(ids, ["openEventLogButton", "eventLogStatus"]);
  assert.doesNotMatch(app, /footerMode|captureMode/);
});
