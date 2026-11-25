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
  assert.match(css, /\.service-map-more \{[^}]*overflow: hidden;/);
  assert.match(css, /\.service-map-more \{[^}]*overflow-wrap: anywhere;/);
  assert.match(css, /\.service-map-more-code \{[^}]*word-break: break-all;/);
  assert.match(css, /\.service-map-products > \.service-map-known:has\(\.service-map-kev\) \{[^}]*min-width:/);
});

test("rich popup renders structured DOM via textContent only (never innerHTML) for each chip kind", () => {
  const appended = [];
  const makeNode = (tag = "div") => {
    const node = {
      tag,
      className: "",
      hidden: true,
      style: {},
      attributes: {},
      children: [],
      offsetWidth: 260,
      offsetHeight: 110,
      textContent: "",
      set innerHTML(_) { throw new Error("innerHTML must never be used in tooltips"); },
      setAttribute(name, value) { this.attributes[name] = value; },
      appendChild(child) { this.children.push(child); return child; },
      replaceChildren(...nodes) { this.children = [...nodes]; },
      remove() { appended.splice(appended.indexOf(this), 1); },
    };
    return node;
  };
  const walk = (node, list = []) => {
    list.push(node);
    for (const child of node.children) walk(child, list);
    return list;
  };
  const doc = {
    createElement: (tag) => makeNode(tag),
    body: { appendChild(child) { appended.push(child); return child; } },
    documentElement: { clientWidth: 1024, clientHeight: 768 },
  };
  const popup = map.createMorePopup(doc);
  const chip = (className, more) => ({
    className,
    getAttribute: (name) => (name === "data-more" ? more : null),
    getBoundingClientRect: () => ({ left: 120, top: 100, bottom: 116 }),
  });

  // Auth: groups repeated Session cookies into monospace code chips, preserves
  // Negotiate's parenthesised description, and treats HTML-like input as text.
  popup.show(chip("service-map-auth", [
    "Session cookie (wordpress_logged_in_0c71125a0f9e5f02a15ba460b1033106)",
    "Session cookie (PHPSESSID)",
    "Basic authentication",
    "Negotiate (Kerberos or NTLM)",
    "Session cookie (<svg/onload=1>)",
  ].join("\n")));
  const shown = appended[0];
  assert.equal(shown.attributes["data-more-kind"], "auth");
  const authNodes = walk(shown);
  assert.ok(authNodes.some((n) => n.className === "service-map-more-title" && n.textContent === "Authentication"));
  assert.ok(authNodes.some((n) => n.className === "service-map-more-count" && n.textContent === "5"));
  const codes = authNodes.filter((n) => n.tag === "code").map((n) => n.textContent);
  assert.deepEqual(codes, [
    "wordpress_logged_in_0c71125a0f9e5f02a15ba460b1033106",
    "PHPSESSID",
    "<svg/onload=1>",
  ]);
  assert.ok(authNodes.some((n) => n.className === "service-map-more-label" && n.textContent === "Negotiate (Kerberos or NTLM)"));

  // Products: splits product name and version into compact tags.
  popup.show(chip("service-map-products-more", "nginx 1.24.0\nPHP · 3 versions\nCloudflare"));
  assert.equal(shown.attributes["data-more-kind"], "products");
  const prodNodes = walk(shown);
  assert.ok(prodNodes.some((n) => n.className === "service-map-more-title" && n.textContent === "More technologies"));
  assert.deepEqual(
    prodNodes.filter((n) => n.className === "service-map-more-tag-name").map((n) => n.textContent),
    ["nginx", "PHP", "Cloudflare"],
  );
  assert.deepEqual(
    prodNodes.filter((n) => n.className === "service-map-more-tag-ver").map((n) => n.textContent),
    ["1.24.0", "3 versions"],
  );

  // Advisories: structures counts, KEV status, and renders the tentative note once.
  popup.show(chip("service-map-kev", [
    "6 known advisories for WordPress 6.4.2, 1 exploited (CISA KEV). Tentative: version match only.",
    "1 known advisory for jQuery 3.3.1, 0 exploited (CISA KEV). Tentative: version match only.",
  ].join("\n")));
  assert.equal(shown.attributes["data-more-kind"], "advisories");
  const advNodes = walk(shown);
  assert.ok(advNodes.some((n) => n.className.includes("service-map-more-count") && n.textContent === "KEV"));
  assert.equal(advNodes.filter((n) => n.className === "service-map-more-note").length, 1);
  assert.ok(advNodes.some((n) => n.className === "service-map-more-meta is-danger" && n.textContent === "1 exploited (CISA KEV)"));

  // Exposures: danger header and structured items.
  popup.show(chip("service-map-exposure", "Java stack trace\nSpring Boot Actuator"));
  assert.equal(shown.attributes["data-more-kind"], "exposure");
  const expNodes = walk(shown);
  assert.ok(expNodes.some((n) => n.className === "service-map-more-title is-danger" && n.textContent === "Exposures"));
  assert.deepEqual(
    expNodes.filter((n) => n.className === "service-map-more-label").map((n) => n.textContent),
    ["Java stack trace", "Spring Boot Actuator"],
  );
});
