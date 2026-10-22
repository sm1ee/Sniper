const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const templates = require("../web/templates.js");

test("list queries page by the page size and drop empty filters", () => {
  assert.equal(
    templates.listQuery({ search: "  wordpress ", severity: "high", support: "passive", enabledOnly: true }, 2),
    "/api/templates?search=wordpress&severity=high&support=passive&enabled=true&limit=100&offset=200",
  );
  assert.equal(templates.listQuery({ search: " ", severity: "", support: "" }, -1), "/api/templates?limit=100&offset=0");
});

test("bulk changes only ever select passive-capable templates", () => {
  assert.deepEqual(templates.passiveRequest({ search: "waf", severity: "", enabledOnly: true }, true), {
    filter: { support: "passive", search: "waf" },
    enabled: true,
  });
  assert.deepEqual(templates.passiveRequest({}, 0), { filter: { support: "passive" }, enabled: false });
});

test("the library summary names what is installed, says whether it was verified, and counts", () => {
  assert.deepEqual(templates.librarySummary(null), { name: "Loading…", badge: null, detail: "", counts: "", title: "" });
  assert.deepEqual(templates.librarySummary({ library: null }),
    { name: "No templates", badge: null, detail: "", counts: "Download a release or import an archive.", title: "" });
  assert.deepEqual(templates.librarySummary({
    library: { source: "github", tag: "v10.5.0", verified: true, commit: "f8b8b8dcd70d1234567890abcdef12345678901" },
    templates: 14035, passive_supported: 2082, passive_enabled: 3, active_supported: 9784,
  }), {
    name: "v10.5.0", badge: { text: "verified", tone: "ok" }, detail: "",
    counts: "14,035 templates · 2,082 passive (3 on) · 9,784 scan", title: "nuclei-templates v10.5.0 · commit f8b8b8dcd70d",
  });
  assert.deepEqual(templates.librarySummary({
    library: { source: "github", tag: "main", verified: false, commit: "50852f5ce7".repeat(4), committed_at: "2026-10-21T22:47:08Z" },
    templates: 14100, passive_supported: 2100, passive_enabled: 0, active_supported: 9000,
  }), {
    name: "main", badge: { text: "unreleased", tone: "warn" }, detail: "50852f5 · 2026-10-21",
    counts: "14,100 templates · 2,100 passive · 9,000 scan", title: "nuclei-templates main · commit 50852f5ce750 · no checksum",
  });
  assert.deepEqual(templates.librarySummary({ library: { source: "import", verified: false }, templates: 1, passive_supported: 0, passive_enabled: 0 }), {
    name: "Imported archive", badge: { text: "not verified", tone: "warn" }, detail: "",
    counts: "1 template · 0 passive · 0 scan", title: "",
  });
});

test("an update check says what the installed channel has", () => {
  assert.equal(templates.checkLine({ channel: "release", latest: "v10.5.1", current: "v10.5.0", update_available: true }),
    "Release v10.5.1 is available (installed: v10.5.0).");
  assert.equal(templates.checkLine({ channel: "release", latest: "v10.5.0", current: "v10.5.0", update_available: false }),
    "Release v10.5.0 is installed and current.");
  assert.equal(
    templates.checkLine({ channel: "main", latest: "a".repeat(40), latest_at: "2026-10-22T01:02:03Z", current: "50852f5ce7".repeat(4), update_available: true }),
    "Main has a newer commit, aaaaaaaaaaaa from 2026-10-22. Download main to take it.",
  );
  assert.equal(templates.checkLine({ channel: "main", latest: "a".repeat(40), current: "a".repeat(40), update_available: false }),
    "Main is installed and current.");
});

test("the progress bar counts the templates checked once the total is known", () => {
  assert.equal(templates.progressOf({ state: "idle" }), null);
  assert.deepEqual(templates.progressOf({ state: "downloading" }), { label: "Contacting GitHub…", value: null, max: null });
  assert.deepEqual(templates.progressOf({ state: "downloading", received_bytes: 3355443 }),
    { label: "Downloading… 3.2 MiB", value: null, max: null });
  assert.deepEqual(templates.progressOf({ state: "importing" }), { label: "Reading the archive…", value: null, max: null });
  assert.deepEqual(templates.progressOf({ state: "importing", checked: 6200, check_total: 14035 }),
    { label: "Checking templates… 6,200 of 14,035", value: 6200, max: 14035 });
  assert.deepEqual(templates.progressOf({ state: "failed", error: "boom" }), { label: "The last download or import failed: boom", error: true });
});

test("every template is listed by default, and the list reads like Findings", () => {
  const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
  const support = html.match(/<select id="templatesSupport"[^]*?<\/select>/)[0];
  assert.match(support, /<option value="" selected>All<\/option>/);
  assert.match(html, /<table class="mini-table recon-table templates-table">/);
  // Every row one line high: long names and tag lists end in an ellipsis.
  const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");
  assert.match(css, /\.templates-table td[^{]*\{[^}]*white-space: nowrap;[^}]*text-overflow: ellipsis;/);
});

test("rows show severity as Findings do, and a box wherever a template can run", async () => {
  const els = new Map();
  const shell = {
    ownerDocument: fakeDocument((tag) => Object.assign(fakeElement(), { tag })),
    querySelector(selector) { const element = fakeElement(); els.set(selector, element); return element; },
  };
  const status = { state: "idle", library: { source: "import", verified: false }, templates: 2, passive_supported: 1, passive_enabled: 0 };
  const items = [
    { id: "example-active", name: "Example Active", severity: "high", tags: ["cve", "php"], passive_supported: false, active_supported: true },
    { id: "example-passive", name: "Example Passive", severity: "unknown", tags: [], passive_supported: true, passive: "global" },
    { id: "example-dns", name: "Example DNS", severity: "info", tags: [], reasons: ["protocol:dns"] },
  ];
  const controller = templates.createController({
    root: shell, getSessionId: () => null, getScopeIncludeCount: () => 1,
    fetch: async (url) => ({ ok: true, json: async () => (String(url).includes("/library") ? status : { items, total: 2 }) }),
    setTimeout: () => 0, clearTimeout() {},
  });
  controller.setVisible(true);
  for (let tick = 0; tick < 5; tick += 1) await new Promise((resolve) => setImmediate(resolve));
  const [active, passive, dns] = els.get("#templatesRows").children;
  const badge = active.children[1].children[0];
  assert.equal(badge.className, "severity-badge severity-high");
  assert.equal(badge.textContent, "high");
  assert.equal(passive.children[1].children[0].className, "severity-badge severity-info");
  // One that must send its requests is on for the auto scan; one that can
  // judge captured traffic is on for that; one Sniper cannot run says so.
  assert.equal(active.children[0].children[0].type, "checkbox");
  assert.equal(active.children[0].children[0].dataset.templateAuto, "example-active");
  assert.equal(passive.children[0].children[0].type, "checkbox");
  assert.equal(passive.children[0].children[0].dataset.templateToggle, "example-passive");
  assert.equal(dns.children[0].children[0].textContent, "—");
  assert.deepEqual(active.children[4].children.map((chip) => [chip.className, chip.textContent]),
    [["templates-tag", "cve"], ["templates-tag", "php"]]);
  // Turning on what the list shows applies to passive templates, so it is
  // offered only while the list shows those.
  assert.equal(els.get("#templatesEnableShown").classList.contains("hidden"), true);
  controller.dispose();
});

test("the mode says passive, scan or the first reason a template cannot run", () => {
  assert.equal(templates.supportLabel({ passive_supported: true, passive: "global" }), "Passive");
  assert.equal(templates.supportLabel({ passive_supported: true, passive: "base_url_get" }), "Passive");
  assert.equal(templates.supportLabel({ passive_supported: false, reasons: ["protocol:dns", "x"] }), "No: protocol:dns");
  assert.equal(templates.supportLabel({ passive_supported: true, passive: "base_url_get", active_supported: true }), "Passive · Scan");
  assert.equal(templates.supportLabel({ active_supported: true, reasons: ["randomness"] }), "Scan");
  assert.equal(templates.supportLabel({ active_supported: true, oast: true }), "Scan · OAST");
});

test("the list filters keep their own width beside the search box", () => {
  // The shell sizes its form controls to their column; a later rule must
  // give the toolbar's selects their own width back, or the search box
  // shrinks to nothing and the toolbar overlaps itself.
  const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");
  const shell = css.indexOf(".templates-shell select,");
  const own = css.indexOf(".templates-shell .recon-search-controls select {");
  assert.ok(shell > 0 && own > shell, "the toolbar rule follows the shell's");
  assert.match(css.slice(own, css.indexOf("}", own)), /width: auto/);
});

test("a scan request names its targets, its selection and whether it only counts", () => {
  const values = { targets: " https://app.example.com\nhttp://api.example.com:8080/v1 ", selection: "filter",
    risks: ["intrusive", "made-up"], rate: "5", concurrency: "2", maxRequests: "500", applyMatchReplace: false };
  assert.deepEqual(templates.scanRequest(values, { search: " wordpress ", severity: "high" }, null, "s-1", true), {
    session_id: "s-1",
    targets: ["https://app.example.com", "http://api.example.com:8080/v1"],
    allow_risks: ["intrusive"],
    rate: 5, concurrency: 2, max_requests: 500, apply_match_replace: false,
    filter: { search: "wordpress", severity: "high" },
    preview: true,
  });
  const one = templates.scanRequest({ ...values, selection: "selected" }, {}, "git-config", "s-1", false);
  assert.deepEqual(one.ids, ["git-config"]);
  assert.equal(one.acknowledged, true);
  assert.equal(one.filter, undefined);
  // Its On box does not select a template; clicking its row does.
  assert.throws(() => templates.scanRequest({ ...values, selection: "selected" }, {}, null, "s-1", true), /Click a template's row/);
  assert.throws(() => templates.scanRequest(values, {}, null, null, true), /session/);
  assert.throws(() => templates.scanRequest({ ...values, rate: "51" }, {}, null, "s-1", true), /from 1 to 50/);
  for (const bad of ["", "app.example.com", "https://app.example.com/?q=1", "https://user:pw@app.example.com", "ftp://app.example.com"]) {
    assert.throws(() => templates.parseTargets(bad), Error, bad);
  }
  assert.throws(() => templates.parseTargets(Array.from({ length: 21 }, (_, i) => `https://h${i}.example.com`).join(" ")), /at most 20/);
});

test("previews and jobs read as what was or will be sent", () => {
  assert.equal(
    templates.previewLine({ requests: 1200, templates: 300, targets: ["https://app.example.com"], max_requests: 10000, excluded_by_risk: { intrusive: 4 } }),
    "Sends 1,200 requests from 300 templates to https://app.example.com. Left out: intrusive 4.",
  );
  assert.equal(
    templates.previewLine({ requests: 3, templates: 1, targets: ["https://app.example.com"], max_requests: 10, oast_unavailable: 2 }),
    "Sends 3 requests from 1 template to https://app.example.com. Left out: 2 OAST templates (no Interactsh server).",
  );
  assert.equal(
    templates.jobLine({ status: "running", sent: 10, planned: 20, matched: 1, failed: 2, blocked: 0 }),
    "running · 10 of 20 sent · 1 matched · 2 failed",
  );
});

// Each segment written as {kind|text}; plain text as it is.
function yamlNotation(text) {
  const short = { key: "k", punct: "p", string: "s", number: "n", bool: "b", comment: "c", expr: "e" };
  return templates.yamlLines(text).map((line) => line.map(([kind, part]) => (kind === "text" ? part : `{${short[kind]}|${part}}`)).join(""));
}

test("a template's YAML is split into keys, values, comments and {{expressions}}", () => {
  const yaml = [
    "id: example",
    "info:",
    '  name: "Example" # note',
    "  tags: a,b",
    "http:",
    "  - raw:",
    "      - |",
    "        GET /{{path}} HTTP/1.1",
    "        Host: {{Hostname}}",
    "    matchers:",
    "      - type: status",
    "        status:",
    "          - 200",
    "        negative: true",
    '    path: "{{BaseURL}}/.git/config"',
  ].join("\n");
  assert.deepEqual(yamlNotation(yaml), [
    "{k|id}{p|:} example",
    "{k|info}{p|:}",
    '  {k|name}{p|:} {s|"Example"} {c|# note}',
    "  {k|tags}{p|:} a,b",
    "{k|http}{p|:}",
    "  {p|-} {k|raw}{p|:}",
    "      {p|-} {p||}",
    // A block scalar's lines are its text, not keys, even with a colon.
    "        GET /{e|{{path}}} HTTP/1.1",
    "        Host: {e|{{Hostname}}}",
    "    {k|matchers}{p|:}",
    "      {p|-} {k|type}{p|:} status",
    "        {k|status}{p|:}",
    "          {p|-} {n|200}",
    "        {k|negative}{p|:} {b|true}",
    '    {k|path}{p|:} {s|"}{e|{{BaseURL}}}{s|/.git/config"}',
  ]);
});

test("template text is never written as markup", () => {
  const source = fs.readFileSync(path.join(__dirname, "../web/templates.js"), "utf8");
  assert.doesNotMatch(source, /innerHTML|insertAdjacentHTML|outerHTML/);
  assert.doesNotMatch(source, /\.href\s*=/);
});

test("the Scan tool is registered where the UI and the server keep their tool lists", () => {
  const root = path.join(__dirname, "..");
  const html = fs.readFileSync(path.join(root, "web/index.html"), "utf8");
  const app = fs.readFileSync(path.join(root, "web/app.js"), "utf8");
  const settings = fs.readFileSync(path.join(root, "src/ui_settings.rs"), "utf8");
  assert.match(html, /<button class="main-tab" data-tool="templates">Scan<\/button>/);
  assert.match(html, /<script src="\/templates\.js" defer><\/script>/);
  assert.match(app, /const IMPLEMENTED_TOOLS = new Set\(\[[^\]]*"templates"/);
  assert.match(settings, /const ACTIVE_TOOL_OPTIONS: &\[&str\] = &\[[^\]]*"templates"/);
  for (const id of ["Status", "Progress", "ProgressBar", "Channel", "Download", "Check", "Import", "ImportFile", "Notice", "ScopeNote",
    "Search", "Severity", "Support", "EnabledOnly", "EnableShown", "DisableShown", "Meta", "Rows", "Detail",
    "PageMeta", "Previous", "Next", "ScanTargets", "ScanSelection", "ScanRisks", "ScanRate", "ScanConcurrency",
    "ScanMaxRequests", "ScanMatchReplace", "ScanPlan", "ScanStart", "ScanNotice",
    "ScanJobs", "Version", "AutoToggle", "AutoSummary", "AutoHosts", "AutoRate"]) {
    assert.match(html, new RegExp(`id="templates${id}"`), id);
  }
  // Manual scan beside Auto scan: the one you start, the one that starts itself.
  assert.match(html, /<h2 id="templatesScanTitle">Manual scan<\/h2>/);
  assert.doesNotMatch(html, />Template scan</);
  // One switch says whether the auto scan is on and turns it on; a scan
  // starts without a preview step.
  for (const gone of ["AutoState", "AutoSave", "ScanPreview"]) assert.doesNotMatch(html, new RegExp(`id="templates${gone}"`), gone);
  // A button is the consent; the screen asks for no box to be ticked first.
  const shell = html.slice(html.indexOf('id="templatesShell"'), html.indexOf('id="templatesRows"'));
  assert.doesNotMatch(shell, /Consent/);
  // Each risk the server allows has its box, and dos has none.
  const boxes = [...html.matchAll(/data-risk="([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(boxes, templates.RISKS);
  assert.ok(!boxes.includes("dos"));
  assert.match(app, /getSessionId: currentSessionId,\s*openRecord: jumpToTransaction/);
  assert.equal((app.match(/templatesController\?\.syncSession\(\)/g) || []).length, 2);
});

// An inert stand-in for each element the controller looks up by id.
function fakeElement() {
  const classes = new Set();
  return {
    textContent: "", value: "", checked: false, disabled: false, dataset: {}, children: [], style: {},
    classList: {
      toggle(name, on) { if (on === undefined ? !classes.has(name) : on) classes.add(name); else classes.delete(name); },
      contains: (name) => classes.has(name), add: (name) => classes.add(name), remove: (name) => classes.delete(name),
    },
    addEventListener() {}, removeEventListener() {}, setAttribute() {}, removeAttribute() {},
    replaceChildren(...nodes) { this.children = nodes; }, append(...nodes) { this.children.push(...nodes); },
    querySelector: () => null, querySelectorAll: () => [], closest: () => null,
  };
}

// The document the controller listens on for ↑/↓.
function fakeDocument(createElement) {
  return Object.assign(listeningElement(), { createElement });
}

function listeningElement() {
  const element = fakeElement();
  const listeners = {};
  element.addEventListener = (type, callback) => { (listeners[type] ||= []).push(callback); };
  element.removeEventListener = (type, callback) => { listeners[type] = (listeners[type] || []).filter((fn) => fn !== callback); };
  element.dispatch = (type, event) => (listeners[type] || []).forEach((callback) => callback({ preventDefault() {}, ...event }));
  return element;
}

// An event target inside `element`, whose `closest` finds it by the data
// attribute a selector names, as the browser's would.
function inside(element) {
  return {
    closest(selector) {
      const name = selector.match(/^\[data-([a-z-]+)\]$/)?.[1];
      const key = name?.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
      return key && element.dataset[key] !== undefined ? element : null;
    },
  };
}

const settle = async () => { for (let tick = 0; tick < 5; tick += 1) await new Promise((resolve) => setImmediate(resolve)); };

async function listFixture(items, arrowStep, { sessionId = null, auto = null, scopeCount = 1, library = { source: "import", verified: false }, jobs = [], openRecord, scanError = null } = {}) {
  const els = new Map();
  const sent = [];
  const doc = fakeDocument((tag) => Object.assign(listeningElement(), { tag }));
  const shell = {
    ownerDocument: doc,
    querySelector(selector) { if (!els.has(selector)) els.set(selector, listeningElement()); return els.get(selector); },
  };
  const status = { state: "idle", library, templates: items.length, passive_supported: 0, passive_enabled: 0 };
  const urls = [];
  const timers = [];
  const controller = templates.createController({
    root: shell, getSessionId: () => sessionId, getScopeIncludeCount: () => scopeCount, arrowStep, openRecord,
    fetch: async (url, init = {}) => {
      urls.push(String(url));
      if (init.method === "POST") sent.push({ url: String(url), body: JSON.parse(init.body) });
      if (scanError && String(url) === "/api/templates/scans" && init.method === "POST") {
        return { ok: false, status: 400, text: async () => JSON.stringify({ error: scanError }) };
      }
      const id = String(url).match(/^\/api\/templates\/([^?/]+)$/)?.[1];
      const body = String(url).includes("/library") ? status
        : String(url).startsWith("/api/templates/auto/templates") ? { auto_enabled: 1, ignored: 0 }
          : String(url).startsWith("/api/templates/auto") ? Object.assign(auto, init.method === "POST" ? JSON.parse(init.body) : {})
            : String(url).startsWith("/api/templates/scans") && init.method === "POST"
              ? (JSON.parse(init.body).preview
                ? { requests: 3, templates: 1, targets: JSON.parse(init.body).targets, max_requests: 10000 }
                : { id: "example-job", session_id: sessionId, status: "running", targets: JSON.parse(init.body).targets })
            : String(url).startsWith("/api/templates/scans/") ? jobs.find((job) => String(url).includes(job.id))
              : String(url).startsWith("/api/templates/scans") ? { session_id: sessionId, jobs }
              : id ? { yaml: "", ...items.find((meta) => meta.id === decodeURIComponent(id)) }
                : { items, total: items.length };
      return { ok: true, json: async () => body };
    },
    setTimeout: (callback) => timers.push({ callback, live: true }), clearTimeout(handle) { if (timers[handle - 1]) timers[handle - 1].live = false; },
  });
  controller.setVisible(true);
  await settle();
  // Runs what is waiting on a timer once, as the time passing would.
  const runTimers = async () => {
    for (const timer of timers.splice(0)) if (timer.live) timer.callback();
    await settle();
  };
  return { controller, els, doc, urls, sent, runTimers, rows: () => els.get("#templatesRows").children };
}

test("the auto scan request carries its hosts and pace, and turning it on is the consent", () => {
  const values = { hosts: " *.example.com\napi.example.com:8443 ", rate: "5" };
  assert.deepEqual(templates.autoRequest(values, "s-1", true), {
    session_id: "s-1", enabled: true, hosts: ["*.example.com", "api.example.com:8443"], rate: 5, acknowledged: true,
  });
  assert.deepEqual(templates.autoRequest(values, "s-1", false), {
    session_id: "s-1", enabled: false, hosts: ["*.example.com", "api.example.com:8443"], rate: 5,
  });
  assert.throws(() => templates.autoRequest({ ...values, hosts: "https://app.example.com/" }, "s-1", true), /as Scope takes it/);
  assert.throws(() => templates.autoRequest({ ...values, rate: "0" }, "s-1", true), /from 1 to 50/);
  assert.throws(() => templates.autoRequest(values, null, true), /session/);
  // The card's badge says On or Off.
  assert.equal(templates.autoLine({ enabled: false, templates: 0 }), "0 templates");
  assert.equal(
    templates.autoLine({ enabled: true, templates: 12, scanned: 1, queued: 3 }),
    "12 templates · 1 host scanned · 3 waiting",
  );
});

test("an On box turns a scan template on for the auto scan, and its switch turns it on", async () => {
  const items = [{ id: "example-active", name: "Example Active", severity: "high", tags: [], active_supported: true }];
  const auto = { session_id: "s-1", enabled: false, hosts: [], rate: 10, templates: 0, scanned: 0, queued: 0 };
  const f = await listFixture(items, () => 0, { sessionId: "s-1", auto });
  const box = f.rows()[0].children[0].children[0];
  box.checked = true;
  f.els.get("#templatesRows").dispatch("click", { target: inside(box) });
  await settle();
  assert.deepEqual(f.sent.at(-1), { url: "/api/templates/auto/templates", body: { ids: ["example-active"], enabled: true } });

  // Typed, so a refresh leaves them.
  f.els.get("#templatesAutoHosts").value = "*.example.com";
  f.els.get("#templatesAutoHosts").dispatch("input", {});
  f.els.get("#templatesAutoRate").value = "5";
  f.els.get("#templatesAutoRate").dispatch("input", {});
  const toggle = f.els.get("#templatesAutoToggle");
  assert.equal(toggle.textContent, "Off");
  toggle.dispatch("click", {});
  await settle();
  assert.deepEqual(f.sent.at(-1), {
    url: "/api/templates/auto",
    body: { session_id: "s-1", enabled: true, hosts: ["*.example.com"], rate: 5, acknowledged: true },
  });
  assert.equal(toggle.textContent, "On");
  assert.equal(toggle.classList.contains("online"), true);
  f.controller.dispose();
});

test("the auto scan's hosts and pace save when the field is left", async () => {
  const items = [{ id: "example-active", name: "Example Active", severity: "high", tags: [], active_supported: true }];
  const auto = { session_id: "s-1", enabled: false, hosts: [], rate: 10, templates: 1, scanned: 0, queued: 0 };
  const f = await listFixture(items, () => 0, { sessionId: "s-1", auto });
  const hosts = f.els.get("#templatesAutoHosts");
  hosts.value = "*.example.com";
  hosts.dispatch("input", {});
  hosts.dispatch("change", {});
  await settle();
  assert.deepEqual(f.sent.at(-1), {
    url: "/api/templates/auto",
    body: { session_id: "s-1", enabled: false, hosts: ["*.example.com"], rate: 10 },
  });
  assert.equal(f.els.get("#templatesAutoToggle").textContent, "Off");
  f.controller.dispose();
});

test("Download takes the latest release unless main is picked, and says it consents", async () => {
  const f = await listFixture([], () => 0, { sessionId: "s-1" });
  const download = f.els.get("#templatesDownload");
  assert.equal(download.disabled, false);
  download.dispatch("click", {});
  await settle();
  assert.deepEqual(f.sent.at(-1), { url: "/api/templates/library/download", body: { acknowledged: true, channel: "release" } });
  const channel = f.els.get("#templatesChannel");
  channel.value = "main";
  channel.dispatch("change", {});
  assert.match(download.title, /no checksum/);
  download.dispatch("click", {});
  await settle();
  assert.deepEqual(f.sent.at(-1), { url: "/api/templates/library/download", body: { acknowledged: true, channel: "main" } });
  f.controller.dispose();
});

// Updating a library taken from main must not fall back to the release.
test("Download starts on main when main is what is installed", async () => {
  const library = { source: "github", tag: "main", verified: false, commit: "50852f5ce7".repeat(4) };
  const f = await listFixture([], () => 0, { sessionId: "s-1", library });
  assert.equal(f.els.get("#templatesChannel").value, "main");
  f.els.get("#templatesDownload").dispatch("click", {});
  await settle();
  assert.deepEqual(f.sent.at(-1), { url: "/api/templates/library/download", body: { acknowledged: true, channel: "main" } });
  f.controller.dispose();
});

test("Start scan is ready at once and sends the form as it stands, and the plan follows the form", async () => {
  const items = [{ id: "example-active", name: "Example Active", severity: "high", tags: [], active_supported: true }];
  const f = await listFixture(items, () => 0, { sessionId: "s-1" });
  const start = f.els.get("#templatesScanStart");
  // The form's own defaults.
  f.els.get("#templatesScanSelection").value = "filter";
  f.els.get("#templatesScanRate").value = "10";
  f.els.get("#templatesScanConcurrency").value = "4";
  f.els.get("#templatesScanMaxRequests").value = "10000";
  assert.equal(start.disabled, false, "nothing to do before Start");
  start.dispatch("click", {});
  await settle();
  assert.match(f.els.get("#templatesScanNotice").textContent, /Name at least one target/);
  assert.equal(f.sent.filter((sent) => sent.url === "/api/templates/scans").length, 0);

  f.els.get("#templatesScanTargets").value = "https://app.example.com";
  f.els.get("#templatesScanTargets").dispatch("input", {});
  // The form changed, so the last refusal no longer applies.
  assert.equal(f.els.get("#templatesScanNotice").textContent, "");
  await f.runTimers();
  assert.equal(f.sent.at(-1).body.preview, true);
  assert.equal(f.els.get("#templatesScanPlan").textContent, "Sends 3 requests from 1 template to https://app.example.com.");
  start.dispatch("click", {});
  await settle();
  const sent = f.sent.at(-1);
  assert.equal(sent.url, "/api/templates/scans");
  assert.equal(sent.body.acknowledged, true);
  assert.equal(sent.body.preview, undefined);
  assert.deepEqual(sent.body.targets, ["https://app.example.com"]);
  f.controller.dispose();
});

test("a scan's matches open their exchange, and its requests read as status, request and template", async () => {
  const job = {
    id: "example-job", session_id: "s-1", status: "completed", targets: ["https://app.example.com"], sent: 2, planned: 2, matched: 1,
    templates: 1, started_at: "2026-10-22T01:00:00Z",
    results: [{ record_id: "r-1", severity: "medium", name: "Git Configuration - Detect", template_id: "git-config", method: "GET",
      url: "https://app.example.com/.git/config", evidence: "[core]" }],
    recent: [
      { method: "GET", url: "https://app.example.com/x", error: "timeout", template_id: "git-config" },
      { method: "GET", url: "https://app.example.com/.git/config", status: 200, ms: 3, matched: true, template_id: "git-config" },
    ],
  };
  const opened = [];
  const f = await listFixture([], () => 0, { sessionId: "s-1", jobs: [job], openRecord: (id) => opened.push(id) });
  const card = f.els.get("#templatesScanJobs").children[0];
  const open = card.children[0].children.find((node) => node.dataset.openScan === "example-job");
  f.els.get("#templatesScanJobs").dispatch("click", { target: inside(open) });
  await settle();
  const nodes = [];
  const walk = (node) => { nodes.push(node); for (const child of node.children || []) walk(child); };
  walk(f.els.get("#templatesDetail"));
  assert.equal(nodes.find((node) => node.tag === "h3").textContent, "Manual scan · completed");
  const match = nodes.find((node) => node.className === "templates-match-open");
  assert.equal(match.dataset.recordId, "r-1");
  assert.deepEqual(match.children.map((part) => part.textContent), ["medium", "Git Configuration - Detect"]);
  f.els.get("#templatesDetail").dispatch("click", { target: inside(match) });
  assert.deepEqual(opened, ["r-1"]);
  // Newest first.
  const requests = nodes.find((node) => node.className === "templates-requests").children;
  // One target, so the path is what each line shows; the whole URL is its tooltip.
  assert.deepEqual(requests.map((row) => row.children.map((part) => part.textContent)), [
    ["200", "GET /.git/config", "3 ms · git-config"],
    ["error", "GET /x", "timeout · git-config"],
  ]);
  assert.equal(requests[0].title, "GET https://app.example.com/.git/config");
  assert.equal(requests[0].className, "templates-matched");
  f.controller.dispose();
});

test("a refusal reads as what the server said, not as its JSON", async () => {
  const items = [{ id: "example-active", name: "Example Active", severity: "high", tags: [], active_supported: true }];
  const refusal = "https://app.example.com is one of Sniper's own listeners.";
  const f = await listFixture(items, () => 0, { sessionId: "s-1", scanError: refusal });
  f.els.get("#templatesScanSelection").value = "filter";
  f.els.get("#templatesScanRate").value = "10";
  f.els.get("#templatesScanConcurrency").value = "4";
  f.els.get("#templatesScanMaxRequests").value = "10000";
  f.els.get("#templatesScanTargets").value = "https://app.example.com";
  f.els.get("#templatesScanTargets").dispatch("input", {});
  await f.runTimers();
  assert.equal(f.els.get("#templatesScanPlan").textContent, refusal);
  f.els.get("#templatesScanStart").dispatch("click", {});
  await settle();
  assert.equal(f.els.get("#templatesScanNotice").textContent, refusal);
  f.controller.dispose();
});

test("the detail shows tags as chips and the template highlighted", async () => {
  const items = [{ id: "example-active", name: "Example Active", severity: "high", tags: ["cve", "php"], active_supported: true,
    yaml: "id: example-active\ninfo:\n  name: Example Active" }];
  const f = await listFixture(items, () => 0, { sessionId: "s-1" });
  f.els.get("#templatesRows").dispatch("click", { target: inside(f.rows()[0]) });
  await settle();
  const nodes = [];
  const walk = (node) => { nodes.push(node); for (const child of node.children || []) walk(child); };
  walk(f.els.get("#templatesDetail"));
  assert.deepEqual(nodes.filter((node) => node.className === "templates-tag").map((chip) => chip.textContent), ["cve", "php"]);
  const yaml = nodes.find((node) => node.className === "templates-yaml");
  const keys = [];
  const collect = (node) => { if (node.className === "token-json-key") keys.push(node.textContent); for (const child of node.children || []) collect(child); };
  collect(yaml);
  assert.deepEqual(keys, ["id", "info", "name"]);
  f.controller.dispose();
});

test("the auto scan says when it has nowhere to send", async () => {
  const items = [{ id: "example-active", name: "Example Active", severity: "high", tags: [], active_supported: true }];
  const auto = { session_id: "s-1", enabled: true, hosts: [], rate: 10, templates: 1, scanned: 0, queued: 0 };
  const scopeless = await listFixture(items, () => 0, { sessionId: "s-1", auto, scopeCount: 0 });
  assert.match(scopeless.els.get("#templatesAutoSummary").textContent, /Scope is empty and no hosts are listed/);
  scopeless.controller.dispose();
  const listed = await listFixture(items, () => 0, { sessionId: "s-1", auto: { ...auto, hosts: ["*.example.com"] }, scopeCount: 0 });
  assert.doesNotMatch(listed.els.get("#templatesAutoSummary").textContent, /Scope is empty/);
  listed.controller.dispose();
});

test("a list sorted by a column asks the server for that order", () => {
  assert.equal(
    templates.listQuery({ search: "", sort: "severity", direction: "desc" }, 0),
    "/api/templates?sort=severity&direction=desc&limit=100&offset=0",
  );
  assert.deepEqual(templates.nextSort({ key: "", direction: "asc" }, "name"), { key: "name", direction: "asc" });
  assert.deepEqual(templates.nextSort({ key: "name", direction: "asc" }, "name"), { key: "name", direction: "desc" });
  assert.deepEqual(templates.nextSort({ key: "name", direction: "desc" }, "severity"), { key: "severity", direction: "asc" });
});

test("a header sorts the list, and a click anywhere on a row or ↑/↓ selects", async () => {
  const items = ["example-a", "example-b", "example-c"].map((id) => ({ id, name: id, severity: "info", tags: [], active_supported: true }));
  let step = 0;
  const f = await listFixture(items, () => step);
  const severity = Object.assign(fakeElement(), { dataset: { sort: "severity" } });
  f.els.get("#templatesHead").dispatch("click", { target: inside(severity) });
  await settle();
  assert.match(f.urls.at(-1), /sort=severity&direction=asc/);
  f.els.get("#templatesHead").dispatch("click", { target: inside(severity) });
  await settle();
  assert.match(f.urls.at(-1), /sort=severity&direction=desc/);

  f.els.get("#templatesRows").dispatch("click", { target: inside(f.rows()[1]) });
  await settle();
  assert.equal(f.urls.at(-1), "/api/templates/example-b");
  // The app decides when the arrows belong to the list: not while typing,
  // not under a modal.
  step = 1;
  f.doc.dispatch("keydown", { key: "ArrowDown", target: {} });
  await settle();
  assert.equal(f.urls.at(-1), "/api/templates/example-c");
  assert.equal(f.rows()[2].className, "recon-selected");
  step = 0;
  const sent = f.urls.length;
  f.doc.dispatch("keydown", { key: "ArrowUp", target: {} });
  await settle();
  assert.equal(f.urls.length, sent);
  f.controller.setVisible(false);
  step = -1;
  f.doc.dispatch("keydown", { key: "ArrowUp", target: {} });
  await settle();
  assert.equal(f.urls.length, sent, "a hidden list keeps its hands off the arrows");
  f.controller.dispose();
});

test("opening Scan rereads the scope, and its warning follows the scope it is told about", async () => {
  const els = new Map();
  const shell = {
    ownerDocument: fakeDocument(() => fakeElement()),
    querySelector(selector) { const element = fakeElement(); els.set(selector, element); return element; },
  };
  const status = { state: "idle", library: { source: "import", verified: false }, templates: 1, passive_supported: 1, passive_enabled: 1 };
  let includes = 0, shown = 0;
  const controller = templates.createController({
    root: shell, getSessionId: () => null, getScopeIncludeCount: () => includes, onShow: () => { shown += 1; },
    fetch: async (url) => ({ ok: true, json: async () => (String(url).includes("/library") ? status : { items: [], total: 0 }) }),
    setTimeout: () => 0, clearTimeout() {},
  });
  controller.setVisible(true);
  assert.equal(shown, 1);
  for (let tick = 0; tick < 5; tick += 1) await new Promise((resolve) => setImmediate(resolve));
  const note = els.get("#templatesScopeNote");
  assert.equal(note.classList.contains("hidden"), false, "templates are on and Scope has no include");
  includes = 2;
  controller.scopeChanged();
  assert.equal(note.classList.contains("hidden"), true);
  controller.setVisible(true);
  assert.equal(shown, 1, "only opening Scan rereads the scope");
  controller.dispose();
});

test("Start scan can be pressed once the library has loaded", async () => {
  const els = new Map();
  const shell = {
    ownerDocument: fakeDocument(() => fakeElement()),
    querySelector(selector) { const element = fakeElement(); els.set(selector, element); return element; },
  };
  const status = { state: "idle", library: { source: "import", verified: false }, templates: 1, passive_supported: 0, passive_enabled: 0 };
  const controller = templates.createController({
    root: shell, getSessionId: () => null, getScopeIncludeCount: () => 1,
    fetch: async (url) => ({ ok: true, json: async () => (String(url).includes("/library") ? status : { items: [], total: 0 }) }),
    setTimeout: () => 0, clearTimeout() {},
  });
  const start = els.get("#templatesScanStart");
  assert.equal(start.disabled, true, "nothing to send before the library loads");
  controller.setVisible(true);
  for (let tick = 0; tick < 5; tick += 1) await new Promise((resolve) => setImmediate(resolve));
  assert.equal(start.disabled, false);
  controller.dispose();
});

test("Recon and Active Scan are the Scan tab's own tabs", () => {
  const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
  assert.doesNotMatch(html, /class="main-tab" data-tool="recon"/);
  const scan = html.slice(html.indexOf('id="scanShell"'));
  assert.match(scan, /data-scan-tool="recon"[^>]*>Recon</);
  assert.match(scan, /data-scan-tool="templates"[^>]*>Active Scan</);
  assert.ok(scan.indexOf('id="reconShell"') > 0 && scan.indexOf('id="templatesShell"') > 0, "both open inside it");
  const app = fs.readFileSync(path.join(__dirname, "../web/app.js"), "utf8");
  assert.match(app, /scanShell: document\.getElementById\("scanShell"\)/);
});
