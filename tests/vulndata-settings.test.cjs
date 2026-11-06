// Settings ▸ Runtime ▸ Vulnerability data: synthetic statuses and a fetch stub;
// no server and no data host.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const source = (id, extra = {}) => ({
  id, name: { retire: "retire.js", kev: "CISA KEV", epss: "FIRST EPSS" }[id], url: "https://example.com/data",
  license: "Apache-2.0", verified: false, ...extra,
});
const status = (extra = {}) => ({
  auto_update: true, updating: false, revision: null,
  sources: [source("retire", { fetched_at: "2026-11-04T00:00:00Z", origin: "import" }), source("kev", { error: "data.example.com could not be reached" }), source("epss")],
  ...extra,
});

function fixture() {
  const nodes = {};
  const node = (id) => nodes[id] ??= {
    id, innerHTML: "", textContent: "", value: "", files: [], open: false, attributes: {},
    classes: new Set(), classList: { toggle(name, on) { if (on) nodes[id].classes.add(name); else nodes[id].classes.delete(name); } },
    setAttribute(name, value) { this.attributes[name] = value; },
  };
  const posts = [];
  const c = loadFunctions([
    "renderVulndataStatus", "loadVulndataStatus", "vulndataRequest", "setVulndataMessage",
    "toggleVulndataAutoUpdate", "updateVulndataNow", "importVulndataFiles", "escapeHtml",
  ], {
    document: { getElementById: node },
    vulndataStatus: null, vulndataPoll: 0, setTimeout: () => 0, clearTimeout() {},
    formatTimestamp: (value) => value,
    requireOkResponse: async (response, message) => { if (!response.ok) throw new Error(message); },
    fetch: async (url, init = {}) => {
      if (init.method === "POST") posts.push({ url, body: init.body });
      return { ok: true, json: async () => (url === "/api/vulndata/import" ? { source: "kev", status: status() } : status({ auto_update: false })) };
    },
  });
  return { c, node, posts };
}

test("a source whose last update failed says so, with why, and no dialog", () => {
  const f = fixture();
  f.c.renderVulndataStatus(status());
  const html = f.node("vulndataSources").innerHTML;
  assert.match(html, /CISA KEV[\s\S]*Last update failed: data\.example\.com could not be reached/);
  // TLS carried only what Sniper downloaded; an imported file came by hand.
  assert.match(html, /retire\.js<\/strong><span class="vulndata-facts">imported 2026-11-04T00:00:00Z · Apache-2\.0 · not verified<\/span>/);
  assert.match(html, /FIRST EPSS<\/strong><span class="vulndata-facts">not fetched yet · Apache-2\.0 · not verified \(TLS only\)<\/span>/);
  assert.equal(f.node("vulndataAutoUpdate").attributes["aria-checked"], "true");
  assert.ok(f.node("vulndataRescanNote").classes.has("hidden"), "no rescan note before the data loads");
  f.c.renderVulndataStatus(status({ revision: "abc" }));
  assert.ok(!f.node("vulndataRescanNote").classes.has("hidden"));
});

test("the switch posts the value it turns to", async () => {
  const f = fixture();
  f.c.renderVulndataStatus(status());
  await f.c.toggleVulndataAutoUpdate();
  assert.deepEqual(f.posts, [{ url: "/api/vulndata/auto-update", body: JSON.stringify({ enabled: false }) }]);
  assert.equal(f.node("vulndataAutoUpdate").attributes["aria-checked"], "false");
});

test("two files chosen in Import make two uploads", async () => {
  const f = fixture();
  const input = { files: [{ name: "kev.json" }, { name: "epss.csv.gz" }], value: "chosen" };
  await f.c.importVulndataFiles(input);
  assert.deepEqual(f.posts.map((post) => post.url), ["/api/vulndata/import", "/api/vulndata/import"]);
  assert.equal(input.value, "", "the same files can be chosen again");
});
