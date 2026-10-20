const test = require("node:test");
const assert = require("node:assert/strict");
const recon = require("../web/recon.js");

function values(overrides = {}) {
  return { target: "https://example.com/start#section", crawler: true, maxRequests: "100", maxDepth: "3", maxEndpoints: "5000", maxPages: "5", ...overrides };
}

test("the default request is scoped, bounded and does not submit a browser scan", () => {
  const body = recon.buildJobRequest(values(), "session-a");
  assert.equal(body.session_id, "session-a");
  assert.equal(body.target_url, "https://example.com/start");
  assert.equal(body.include_subdomains, false);
  assert.deepEqual(body.sources, ["crawler"]);
  assert.equal(body.history_acknowledged, false);
  assert.equal(body.scan_acknowledged, false);
  assert.equal(body.scan_visibility, "private");
  assert.equal(body.max_requests, 100);
});

test("targets require an explicit HTTP(S) URL and reject embedded credentials", () => {
  for (const target of ["example.com", "//example.com/path", "javascript:alert(1)", "file:///etc/passwd", "https://name:secret@example.com/"]) {
    assert.throws(() => recon.parseTarget(target));
  }
  assert.equal(recon.parseTarget("http://example.com:8080/a?b=2").href, "http://example.com:8080/a?b=2");
});

test("a session and at least one explicit source are required", () => {
  assert.throws(() => recon.buildJobRequest(values(), null), /session/);
  assert.throws(() => recon.buildJobRequest(values({ crawler: false }), "session-a"), /source/);
});

test("historical searches require a separate acknowledgment", () => {
  for (const source of ["urlscan", "wayback"]) {
    assert.throws(() => recon.buildJobRequest(values({ [source]: true }), "session-a"), /domain sharing/);
    const body = recon.buildJobRequest(values({ [source]: true, historyAcknowledged: true }), "session-a");
    assert.equal(body.history_acknowledged, true);
    assert.equal(body.scan_acknowledged, false);
    assert.ok(!body.sources.includes("urlscan_submit"));
  }
});

test("new urlscan scans require independent acknowledgment and valid visibility", () => {
  assert.throws(() => recon.buildJobRequest(values({ target: "https://example.com/start", urlscan_submit: true, historyAcknowledged: true }), "session-a"), /new urlscan/);
  assert.throws(() => recon.buildJobRequest(values({ target: "https://example.com/start", urlscan_submit: true, scanAcknowledged: true, scanVisibility: "invalid" }), "session-a"), /visibility/);
  for (const visibility of ["private", "unlisted", "public"]) {
    const body = recon.buildJobRequest(values({ target: "https://example.com/start", crawler: false, urlscan_submit: true, scanAcknowledged: true, scanVisibility: visibility }), "session-a");
    assert.deepEqual(body.sources, ["urlscan_submit"]);
    assert.equal(body.scan_visibility, visibility);
    assert.equal(body.scan_acknowledged, true);
    assert.equal(body.history_acknowledged, false);
  }
});

test("client limits match backend bounds and never silently clamp", () => {
  for (const [field, min, max] of [["maxRequests", 1, 1000], ["maxDepth", 0, 10], ["maxEndpoints", 1, 5000], ["maxPages", 1, 20]]) {
    for (const value of [min - 1, max + 1, 1.5, "", "NaN", "Infinity"]) {
      assert.throws(() => recon.buildJobRequest(values({ [field]: value }), "session-a"));
    }
    assert.doesNotThrow(() => recon.buildJobRequest(values({ [field]: min }), "session-a"));
    assert.doesNotThrow(() => recon.buildJobRequest(values({ [field]: max }), "session-a"));
  }
});

test("search matches method, raw URLs and provenance while respecting evidence filters", () => {
  const items = [
    { method: "POST", url: "https://example.com/login", raw_urls: ["/Login#panel"], evidence: [{ source: "crawler", kind: "candidate", location: "https://example.com/app.js" }] },
    { method: "GET", url: "https://example.com/old", evidence: [{ source: "wayback", kind: "history", location: "archive result" }] },
  ];
  assert.equal(recon.filterEndpoints(items, "post", "").length, 1);
  assert.equal(recon.filterEndpoints(items, "#panel", "").length, 1);
  assert.equal(recon.filterEndpoints(items, "APP.JS", "candidate").length, 1);
  assert.equal(recon.filterEndpoints(items, "wayback", "history").length, 1);
  assert.equal(recon.filterEndpoints(items, "", "live").length, 0);
  assert.equal(recon.filterEndpoints(items, "wayback", "candidate").length, 0);
});

test("pagination is capped at 50 visible rows and clamps after filters shrink", () => {
  const items = Array.from({ length: 121 }, (_, i) => i);
  assert.deepEqual(recon.pageEndpoints(items, 0), { page: 0, pages: 3, items: items.slice(0, 50) });
  assert.deepEqual(recon.pageEndpoints(items, 999), { page: 2, pages: 3, items: items.slice(100) });
  assert.deepEqual(recon.pageEndpoints([], 2), { page: 0, pages: 1, items: [] });
});

test("GET and POST discovery entries remain distinct", () => {
  assert.notEqual(recon.endpointKey({ method: "GET", url: "https://example.com/" }), recon.endpointKey({ method: "POST", url: "https://example.com/" }));
});

test("session guards reject late responses after navigation, even A → B → A", () => {
  let id = "a";
  let generation = 0;
  const guard = recon.createSessionGuard(() => id, () => generation);
  const original = guard.capture();
  assert.equal(guard.current(original), true);
  id = "b";
  generation += 1;
  assert.equal(guard.current(original), false);
  id = "a";
  generation += 1;
  assert.equal(guard.current(original), false);
  const latest = guard.capture();
  assert.equal(guard.current(latest), true);
  guard.invalidate();
  assert.equal(guard.current(latest), false);
});

test("a reset rejects same-session responses and unbound sessions", () => {
  const guard = recon.createSessionGuard(() => "a");
  const token = guard.capture();
  guard.invalidate();
  assert.equal(guard.current(token), false);
  const unbound = recon.createSessionGuard(() => null);
  assert.equal(unbound.current(unbound.capture()), false);
});

test("new scans reject query strings and fragments before transmitting", () => {
  for (const target of ["https://example.com/?token=value", "https://example.com/#value"]) {
    assert.throws(() => recon.buildJobRequest(values({ target, urlscan_submit: true, scanAcknowledged: true, scanVisibility: "private" }), "session-a"), /query strings and fragments/);
  }
});

// A small DOM fixture keeps controller race tests runnable with stock Node.
// Network mocks intentionally ignore abort so the ownership guard is exercised.
class NodeFixture {
  constructor(tag = "div") {
    this.tagName = tag.toUpperCase(); this.childNodes = []; this.dataset = {}; this.attributes = {};
    this.value = ""; this.checked = false; this.disabled = false; this.listeners = new Map(); this._text = "";
    const classes = new Set();
    this.classList = { toggle(name, enabled) { if (enabled) classes.add(name); else classes.delete(name); }, contains(name) { return classes.has(name); } };
  }
  set textContent(value) { this._text = String(value); this.childNodes = []; }
  get textContent() { return this._text + this.childNodes.map(child => child.textContent).join(""); }
  append(...children) { for (const child of children) { if (child.tagName === "FRAGMENT") this.append(...child.childNodes); else this.childNodes.push(child); } }
  replaceChildren(...children) { this.childNodes = []; this._text = ""; this.append(...children); }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener(name, callback) { this.listeners.set(name, callback); }
  removeEventListener(name) { this.listeners.delete(name); }
  emit(name, event = {}) { this.listeners.get(name)?.({ target: this, preventDefault() {}, ...event }); }
  closest(selector) { return selector === "[data-stop-job]" && this.dataset.stopJob || selector === "[data-endpoint-key]" && this.dataset.endpointKey ? this : null; }
}

function controllerFixture() {
  const nodes = new Map();
  const document = { createElement: tag => new NodeFixture(tag), createDocumentFragment: () => new NodeFixture("fragment") };
  const root = new NodeFixture(); root.ownerDocument = document;
  root.querySelector = selector => { if (!nodes.has(selector)) nodes.set(selector, new NodeFixture()); return nodes.get(selector); };
  const node = suffix => root.querySelector(`#recon${suffix}`);
  node("Form").reset = () => {
    for (const item of nodes.values()) { item.value = ""; item.checked = false; }
    node("Crawler").checked = true;
    for (const [key, value] of Object.entries({ MaxRequests: "100", MaxDepth: "3", MaxEndpoints: "5000", MaxPages: "5", ScanVisibility: "private" })) node(key).value = value;
  };
  const endpoint = (path, method = "GET") => ({ url: `https://example.com/${path}`, method, raw_urls: [`/${path}`, "<img src=x onerror=alert(1)>"], evidence: [{ source: "crawler", kind: "candidate", location: "https://example.com/app.js" }] });
  const snapshots = {
    a: { session_id: "a", jobs: [], endpoints: Array.from({ length: 111 }, (_, i) => endpoint(`api/${i}`)) },
    b: { session_id: "b", jobs: [], endpoints: [endpoint("session-b-only")] },
  };
  const fixture = { node, snapshots, session: "a", generation: 0, calls: [], hold: null, held: null, timers: new Map(), nextTimer: 0 };
  const response = payload => ({ ok: true, json: async () => JSON.parse(JSON.stringify(payload)) });
  const fetcher = async (path, options = {}) => {
    const body = options.body ? JSON.parse(options.body) : null;
    const method = options.method || "GET";
    fixture.calls.push({ path, body, method });
    if (fixture.failNext === method) { fixture.failNext = null; return { ok: false, status: 503, text: async () => '{"error":"Temporary failure"}' }; }
    const sid = body?.session_id || new URL(path, "http://localhost").searchParams.get("session_id");
    const snapshot = snapshots[sid];
    if (fixture.hold === method) {
      fixture.hold = null;
      const payload = body ? { id: "late-job", status: "running", target_url: body.target_url, sources: [] } : JSON.parse(JSON.stringify(snapshot));
      return new Promise(resolve => { fixture.held = () => resolve(response(payload)); });
    }
    if (method === "POST" && path.endsWith("/stop")) {
      const job = snapshot.jobs.find(item => path.includes(item.id));
      job.status = "cancelled";
      return response({ stopped: true, session_id: sid });
    }
    if (method === "POST") {
      const job = { id: `job-${fixture.calls.length}`, status: "running", target_url: body.target_url, started_at: "2026-10-14T10:00:00Z", sources: body.sources.map(source => ({ source, status: "running", requests: 2, discovered: 3, truncated: false, warnings: [] })) };
      snapshot.jobs.unshift(job);
      return response(job);
    }
    return response(snapshot);
  };
  fixture.controller = recon.createController({ root, getSessionId: () => fixture.session, getSessionGeneration: () => fixture.generation, fetch: fetcher,
    setTimeout(callback) { fixture.timers.set(++fixture.nextTimer, callback); return fixture.nextTimer; }, clearTimeout(id) { fixture.timers.delete(id); } });
  fixture.switchTo = session => { fixture.controller.reset(); fixture.session = session; fixture.generation += 1; fixture.controller.syncSession(); };
  fixture.controller.setVisible(true);
  return fixture;
}
async function settled() { for (let i = 0; i < 10; i += 1) await new Promise(resolve => setImmediate(resolve)); }
function descendants(node) { return node.childNodes.flatMap(child => [child, ...descendants(child)]); }

test("controller renders bounded pages, search and text-only provenance", async () => {
  const f = controllerFixture(); await settled();
  assert.equal(f.node("Endpoints").childNodes.length, 50);
  f.node("Next").emit("click"); assert.match(f.node("PageMeta").textContent, /51–100/);
  f.node("Search").value = "api/110"; f.node("Search").emit("input");
  assert.equal(f.node("Endpoints").childNodes.length, 1);
  const button = descendants(f.node("Endpoints")).find(item => item.dataset.endpointKey);
  f.node("Endpoints").emit("click", { target: button });
  assert.match(f.node("Detail").textContent, /<img src=x/);
  assert.equal(descendants(f.node("Detail")).some(item => item.tagName === "IMG"), false);
  f.controller.dispose();
});

test("successful start and stop use pinned sessions and retain inventory", async () => {
  const f = controllerFixture(); await settled();
  f.node("Target").value = "https://example.com/";
  f.node("Form").emit("submit"); await settled();
  assert.equal(f.calls.find(call => call.method === "POST").body.session_id, "a");
  assert.equal(f.node("Start").disabled, true);
  const stop = descendants(f.node("Jobs")).find(item => item.dataset.stopJob);
  assert.ok(stop);
  f.node("Jobs").emit("click", { target: stop }); await settled();
  assert.match(f.node("Jobs").textContent, /cancelled/);
  assert.match(f.node("ActionStatus").textContent, /Stop requested/);
  assert.equal(f.node("ActionStatus").classList.contains("recon-error"), false);
  assert.match(f.node("InventoryMeta").textContent, /111 endpoints/);
  assert.equal(f.node("Start").disabled, false);
  f.controller.dispose();
});

test("completed sources retain partial extraction warnings and accurate counts", async () => {
  const f = controllerFixture(); await settled();
  f.snapshots.a.endpoints = f.snapshots.a.endpoints.slice(0, 1);
  f.snapshots.a.jobs = [{ id: "bounded-job", status: "completed", target_url: "https://example.com/tags", sources: [{
    source: "crawler", status: "completed", requests: 3, discovered: 1, truncated: true,
    warnings: ["A static document extraction limit was reached; more evidence may exist.", "Collection was bounded; more evidence may exist."],
  }] }];
  await f.controller.refresh();
  assert.match(f.node("Jobs").textContent, /completed.*3 requests.*1 discovered.*LIMIT REACHED \/ PARTIAL/);
  assert.match(f.node("Jobs").textContent, /static document extraction limit/);
  assert.match(f.node("InventoryMeta").textContent, /^1 endpoints in this session$/);
  assert.equal(descendants(f.node("Jobs")).some(item => item.dataset.stopJob), false);
  f.snapshots.a.jobs[0].sources[0] = { source: "crawler", status: "completed", requests: 4, discovered: 2, truncated: false, warnings: [] };
  await f.controller.refresh();
  assert.match(f.node("Jobs").textContent, /4 requests.*2 discovered/);
  assert.doesNotMatch(f.node("Jobs").textContent, /LIMIT REACHED|extraction limit/);
  f.controller.dispose();
});

test("late GET cannot replace a new session's endpoints, including A → B → A", async () => {
  const f = controllerFixture(); await settled();
  f.hold = "GET"; void f.controller.refresh(); await settled();
  f.switchTo("b"); await settled();
  f.held(); await settled();
  assert.match(f.node("Endpoints").textContent, /session-b-only/);
  assert.equal(f.node("Endpoints").childNodes.length, 1);
  f.hold = "GET"; void f.controller.refresh(); await settled();
  f.switchTo("a"); f.switchTo("b"); await settled();
  f.snapshots.b.endpoints = [];
  await f.controller.refresh();
  f.held(); await settled();
  assert.doesNotMatch(f.node("Endpoints").textContent, /session-b-only/);
  f.controller.dispose();
});

test("late POST cannot inject old jobs, notifications or input values into another session", async () => {
  const f = controllerFixture(); await settled();
  f.node("Target").value = "https://example.com/old-session";
  f.node("HistoryConsent").checked = true; f.node("ScanConsent").checked = true;
  f.hold = "POST"; f.node("Form").emit("submit"); await settled();
  f.switchTo("b"); await settled();
  f.held(); await settled();
  assert.doesNotMatch(f.node("Jobs").textContent, /old-session|late-job/);
  assert.equal(f.node("ActionStatus").textContent, "");
  assert.equal(f.node("Target").value, "");
  assert.equal(f.node("HistoryConsent").checked, false);
  assert.equal(f.node("ScanConsent").checked, false);
  assert.equal(f.node("Start").disabled, false);
  f.controller.dispose();
});

test("source and URL changes revoke transmission consent; hidden tabs stop polling", async () => {
  const f = controllerFixture(); await settled();
  for (const field of ["Target", "Subdomains", "Urlscan", "Wayback", "UrlscanSubmit", "ScanVisibility"]) {
    f.node("HistoryConsent").checked = true; f.node("ScanConsent").checked = true;
    f.node(field).emit(field === "Target" ? "input" : "change");
    assert.equal(f.node("HistoryConsent").checked, false);
    assert.equal(f.node("ScanConsent").checked, false);
  }
  assert.equal(f.timers.size, 1);
  f.controller.setVisible(false);
  assert.equal(f.timers.size, 0);
  f.controller.dispose();
});

test("read failures retain results with a stale warning and clear it after recovery", async () => {
  const f = controllerFixture(); await settled();
  f.failNext = "GET"; await f.controller.refresh();
  assert.match(f.node("LoadStatus").textContent, /Temporary failure.*status may be out of date/);
  assert.equal(f.node("Endpoints").childNodes.length, 50);
  assert.equal(f.timers.size, 1);
  await f.controller.refresh();
  assert.equal(f.node("LoadStatus").textContent, "");
  f.controller.dispose();
});

test("failed mutations are never automatically repeated", async () => {
  const f = controllerFixture(); await settled();
  f.node("Target").value = "https://example.com/";
  f.failNext = "POST"; f.node("Form").emit("submit"); await settled();
  assert.equal(f.calls.filter(call => call.method === "POST").length, 1);
  assert.match(f.node("ActionStatus").textContent, /confirm the current state before trying again/);
  assert.equal(f.node("ActionStatus").classList.contains("recon-error"), true);
  f.controller.dispose();
});

test("late stop responses cannot change a newer session's job controls", async () => {
  const f = controllerFixture(); await settled();
  f.node("Target").value = "https://example.com/";
  f.node("Form").emit("submit"); await settled();
  const stop = descendants(f.node("Jobs")).find(item => item.dataset.stopJob);
  f.hold = "POST"; f.node("Jobs").emit("click", { target: stop }); await settled();
  f.switchTo("b"); await settled();
  f.held(); await settled();
  assert.equal(f.node("ActionStatus").textContent, "");
  assert.equal(f.node("Start").disabled, false);
  assert.equal(descendants(f.node("Jobs")).some(item => item.dataset.stopJob), false);
  f.controller.dispose();
});

// Exercise the actual app integration too: controller-only fixtures cannot catch
// an optional feature breaking legacy functions loaded into isolated contexts.
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const appSource = fs.readFileSync(path.join(__dirname, "../web/app.js"), "utf8").replace(/\r\n/g, "\n");
function loadAppFunctions(names, globals) {
  const context = vm.createContext({ console, ...globals });
  for (const name of names) {
    const match = appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, "m"));
    assert.ok(match, `Missing frontend function: ${name}`);
    vm.runInContext(match[0], context, { filename: `web/app.js:${name}` });
  }
  return context;
}

function panelsFixture(extra = {}) {
  const names = ["dashboard", "proxy", "replay", "tools", "fuzzer", "sequence", "target", "logger"];
  const state = { activeTool: "dashboard" };
  const els = Object.fromEntries(names.map(name => [`${name}Shell`, new NodeFixture()]));
  els.footerMode = new NodeFixture();
  return loadAppFunctions(["renderToolPanels"], { state, els, mainTabs: [], sanitizeActiveTool: tool => tool,
    renderDashboard() {}, renderProxyPanels() {}, renderReplay() {}, renderFuzzer() {}, renderSequencePanel() {}, renderTarget() {}, renderEventLog() {},
    ensureDecoderWorkbench: async () => {}, ...extra });
}

for (const optionalController of ["absent", "null"]) {
  test(`legacy tool panels work with a missing or ${optionalController} Recon controller and no Recon shell`, () => {
    const context = panelsFixture(optionalController === "null" ? { reconController: null } : {});
    assert.equal(Object.hasOwn(context, "reconController"), optionalController !== "absent");
    for (const tool of ["dashboard", "proxy", "replay", "tools", "fuzzer", "sequence", "target", "logger"]) {
      context.state.activeTool = tool;
      assert.doesNotThrow(() => context.renderToolPanels());
      assert.equal(context.els[`${tool}Shell`].classList.contains("hidden"), false);
    }
  });
}

test("Recon navigation still toggles its mounted shell and initialized controller", () => {
  const calls = [];
  const context = panelsFixture({ reconController: { setVisible: value => calls.push(value) } });
  context.els.reconShell = new NodeFixture();
  context.state.activeTool = "recon";
  context.renderToolPanels();
  assert.equal(context.els.reconShell.classList.contains("hidden"), false);
  assert.equal(context.els.dashboardShell.classList.contains("hidden"), true);
  assert.equal(context.els.footerMode.textContent, "Recon active");
  context.state.activeTool = "dashboard";
  context.renderToolPanels();
  assert.equal(context.els.reconShell.classList.contains("hidden"), true);
  assert.deepEqual(calls, [true, false]);
});

for (const hasController of [false, true]) {
  test(`session listing adopts the new session ${hasController ? "before syncing Recon" : "without requiring Recon"}`, async () => {
    const state = { activeSession: { id: "old" } };
    const sessions = [{ id: "new", name: "Fixture session", active: true }];
    const calls = [];
    const context = loadAppFunctions(["loadSessions"], { state, sessionsLoadGeneration: 0, sessionsAppliedLoadGeneration: 0,
      currentSessionId: () => state.activeSession?.id, fetch: async () => ({ json: async () => sessions }), requireOkResponse: async () => {},
      renderDashboard: () => calls.push(`dashboard:${state.activeSession.id}`),
      ...(hasController ? { reconController: { syncSession: () => calls.push(`recon:${state.activeSession.id}`) } } : {}),
    });
    await context.loadSessions();
    assert.equal(state.activeSession.id, "new");
    assert.deepEqual(calls, hasController ? ["recon:new", "dashboard:new"] : ["dashboard:new"]);
  });

  test(`settings hydration ${hasController ? "syncs the new Recon session" : "works without a Recon binding"}`, async () => {
    const state = { activeSession: { id: "old" } };
    const calls = [];
    const els = Object.fromEntries(["proxyAddr", "uiAddr", "captureMode", "settingsSpecialHostHttp", "certificateName", "certificateExpiry", "certificatePemPath", "certificateDerPath", "specialHostHttps", "dataDir", "certificateNote"].map(id => [id, new NodeFixture()]));
    const context = loadAppFunctions(["_applySettings"], { state, els, document: { getElementById: () => null },
      syncHttpCapturePill() {}, formatSize: value => String(value), formatTimestamp: value => value, escapeHtml: value => value,
      updateProxyStatusIndicator() {}, updateRemoteUiIndicator() {}, renderInterceptStatus() {}, renderProxySettings() {}, renderDashboard() {},
      ...(hasController ? { reconController: { syncSession: () => calls.push(state.activeSession.id) } } : {}),
    });
    await context._applySettings({ json: async () => ({ active_session: { id: "new" }, runtime: {}, body_preview_bytes: 1024, certificate: {} }) });
    assert.equal(state.activeSession.id, "new");
    assert.deepEqual(calls, hasController ? ["new"] : []);
    assert.match(els.captureMode.textContent, /1024 body preview cap/);
  });

  test(`session reset ${hasController ? "invalidates Recon after advancing generation" : "does not require a Recon binding"}`, () => {
    const reachedLegacyReset = new Error("Legacy replay cleanup reached");
    const generations = [];
    // Stop at the first legacy cleanup call; the existing replay fixtures cover
    // the remaining reset work, while this fixture isolates the new entry hook.
    const context = loadAppFunctions(["resetSessionScopedUiState"], { state: {}, workspaceStateGeneration: 7, workspaceLoaded: true,
      clearReplaySendInFlight() { throw reachedLegacyReset; },
      ...(hasController ? { reconController: { reset: () => generations.push(context.workspaceStateGeneration) } } : {}),
    });
    assert.throws(() => context.resetSessionScopedUiState(), error => error === reachedLegacyReset);
    assert.equal(context.workspaceStateGeneration, 8);
    assert.equal(context.workspaceLoaded, false);
    assert.deepEqual(generations, hasController ? [8] : []);
  });
}
