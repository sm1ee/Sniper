// A card's chip lists (+N, ⚠, the lock, an advisory badge) were ::after boxes
// inside the map's layer, which clips what reaches past it: on a one-row map a
// list showed one line. They now open in one popup on the page.
const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

const source = fs.readFileSync(path.join(__dirname, "../web/service-map.js"), "utf8");
const context = vm.createContext({ URL, URLSearchParams, AbortController, console });
vm.runInContext(source, context);
const map = context.SniperServiceMap;
const plain = (value) => JSON.parse(JSON.stringify(value));

test("a list opens below its chip, above it near the window's bottom, and inside the window", () => {
  const view = { width: 800, height: 600 };
  const size = { width: 200, height: 120 };
  assert.deepEqual(plain(map.morePopupPlacement({ left: 100, top: 100, bottom: 116 }, size, view)), { left: 100, top: 120 });
  assert.deepEqual(plain(map.morePopupPlacement({ left: 100, top: 540, bottom: 556 }, size, view)), { left: 100, top: 416 });
  assert.deepEqual(plain(map.morePopupPlacement({ left: 700, top: 100, bottom: 116 }, size, view)), { left: 600, top: 120 });
  // Taller than either side: kept on screen from below.
  assert.deepEqual(plain(map.morePopupPlacement({ left: 0, top: 300, bottom: 316 }, { width: 100, height: 700 }, view)), { left: 0, top: 0 });
});

test("the popup lives on the page, outside the map's clipping layer", () => {
  const appended = [];
  const element = () => ({
    hidden: true, style: {}, attributes: {}, offsetWidth: 180, offsetHeight: 60, textContent: "",
    setAttribute(name, value) { this.attributes[name] = value; },
    remove() { appended.splice(appended.indexOf(this), 1); },
  });
  const doc = {
    createElement: () => element(),
    body: { appendChild(child) { appended.push(child); } },
    documentElement: { clientWidth: 800, clientHeight: 600 },
  };
  const popup = map.createMorePopup(doc);
  const chip = {
    getAttribute: (name) => (name === "data-more" ? "Next.js\nnginx 1.24.0" : null),
    getBoundingClientRect: () => ({ left: 300, top: 200, bottom: 216 }),
  };
  popup.show(chip);
  assert.equal(appended.length, 1, "appended to the page body");
  const shown = appended[0];
  assert.equal(shown.className, "service-map-more");
  assert.equal(shown.attributes.role, "tooltip");
  assert.equal(shown.textContent, "Next.js\nnginx 1.24.0", "text, never markup");
  assert.equal(shown.hidden, false);
  assert.deepEqual([shown.style.left, shown.style.top], ["300px", "220px"]);
  popup.show(chip);
  assert.equal(appended.length, 1, "one popup, reused");
  popup.hide();
  assert.equal(shown.hidden, true);
  popup.remove();
  assert.equal(appended.length, 0);
});

test("the stylesheet no longer draws chip lists inside the map", () => {
  const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");
  assert.doesNotMatch(css, /\.service-map-(products-more|exposure|auth|advisories|kev):hover::after/);
  assert.match(css, /\.service-map-more \{[^}]*position: fixed;/);
});
