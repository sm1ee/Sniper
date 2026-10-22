// The JWT tool opens for a value that can only be a JWT. A guess that moved
// the operator off the tool they chose would cost more than it saves.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const b64 = value => Buffer.from(JSON.stringify(value)).toString("base64url");
// A synthetic token: it signs nothing and names no real account.
const header = b64({ alg: "HS256", typ: "JWT" });
const payload = b64({ sub: "7", scope: "example" });
const jwt = [header, payload, "c3ludGhldGlj"].join(".");

function load(extra = {}) {
  return loadFunctions(["decoderTabFor", "followDecoderInput"], { atob, decoderInputKind: null, ...extra });
}

test("only a value that is certainly a JWT names the JWT tool", () => {
  const c = load();
  assert.equal(c.decoderTabFor(jwt), "jwt");
  assert.equal(c.decoderTabFor(`  ${jwt}\n`), "jwt", "surrounding whitespace");
  assert.equal(c.decoderTabFor(`${header}.${payload}.`), "jwt", "unsigned");
  for (const value of [
    "", "plain text", `${header}.${payload}`, `${jwt}.extra`, `Bearer ${jwt}`,
    [b64({ typ: "JWT" }), payload, "sig"].join("."),
    [header, Buffer.from("not json").toString("base64url"), "sig"].join("."),
    "aGVsbG8.d29ybGQ.Zm9v", `${header}.${payload}.sig+nature`,
  ]) assert.equal(c.decoderTabFor(value), null, value);
});

test("a JWT opens the JWT tool once; going back sticks while the value stays a JWT", () => {
  const ui = [];
  const window = { tabs: { encode: 7, jwt: 10 }, hasher: { tab: 7, updateUI() { ui.push(this.tab); } } };
  const c = load({ window });
  assert.equal(c.followDecoderInput("plain"), false);
  assert.equal(c.followDecoderInput(jwt), true);
  assert.deepEqual([window.hasher.tab, ui], [10, [10]]);
  window.hasher.tab = 7;
  assert.equal(c.followDecoderInput(jwt.slice(0, -1)), false, "still a JWT, and the operator chose Encode");
  assert.equal(window.hasher.tab, 7);
  assert.equal(c.followDecoderInput("plain"), false);
  assert.equal(c.followDecoderInput(jwt), true, "a new JWT opens the tool again");
});

test("Tools' categories carry the sliding line and the input follows a JWT", () => {
  const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
  const app = fs.readFileSync(path.join(__dirname, "../web/app.js"), "utf8");
  assert.match(html, /<ul id="tabs" class="tools-tool-list" data-tab-active="\.on">/);
  assert.match(app, /wireTabIndicator\(document\.getElementById\("tabs"\)\)/);
  assert.match(app, /if \(!followDecoderInput\(/);
});
