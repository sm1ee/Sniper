const test = require("node:test");
const assert = require("node:assert/strict");
const recon = require("../web/recon.js");

function values(overrides = {}) {
  return { target: "https://example.com/start#section", crawler: true, maxRequests: "0", maxDepth: "0", maxEndpoints: "0", maxPages: "0", ...overrides };
}

test("the default request is scoped, unbudgeted and does not submit a browser scan", () => {
  const body = recon.buildJobRequest(values(), "session-a");
  assert.equal(body.session_id, "session-a");
  assert.equal(body.target_url, "https://example.com/start");
  assert.equal(body.include_subdomains, false);
  assert.deepEqual(body.sources, ["crawler"]);
  assert.equal(body.history_acknowledged, false);
  assert.equal(body.scan_acknowledged, false);
  assert.equal(body.scan_visibility, "private");
  for (const field of ["max_requests", "max_depth", "max_endpoints", "max_pages"]) assert.equal(body[field], 0);
});

test("discovery budget inputs default to zero without maximum attributes", () => {
  const markup = require("node:fs").readFileSync(require("node:path").join(__dirname, "../web/index.html"), "utf8");
  for (const id of ["reconMaxRequests", "reconMaxDepth", "reconMaxEndpoints", "reconMaxPages"]) {
    const input = markup.match(new RegExp(`<input[^>]*id="${id}"[^>]*>`))?.[0];
    assert.ok(input, id);
    assert.match(input, /min="0"/);
    assert.match(input, /value="0"/);
    assert.doesNotMatch(input, /\bmax=/);
  }
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

test("optional budgets accept zero and values above former ceilings without silently clamping", () => {
  for (const field of ["maxRequests", "maxDepth", "maxEndpoints", "maxPages"]) {
    for (const value of [-1, 1.5, "NaN", "Infinity", Number.MAX_SAFE_INTEGER + 1]) {
      assert.throws(() => recon.buildJobRequest(values({ [field]: value }), "session-a"));
    }
    for (const value of [0, "", undefined, 50_000, Number.MAX_SAFE_INTEGER]) {
      assert.doesNotThrow(() => recon.buildJobRequest(values({ [field]: value }), "session-a"));
    }
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
  querySelectorAll() { return []; }
  addEventListener(name, callback) { this.listeners.set(name, callback); }
  removeEventListener(name) { this.listeners.delete(name); }
  emit(name, event = {}) { this.listeners.get(name)?.({ target: this, preventDefault() {}, ...event }); }
  closest(selector) { return selector === "[data-stop-job]" && this.dataset.stopJob || selector === "[data-endpoint-key]" && this.dataset.endpointKey || selector === "[data-sort]" && this.dataset.sort ? this : null; }
}

function controllerFixture() {
  const nodes = new Map();
  const document = Object.assign(new NodeFixture("document"), { createElement: tag => new NodeFixture(tag), createDocumentFragment: () => new NodeFixture("fragment") });
  const root = new NodeFixture(); root.ownerDocument = document;
  root.querySelector = selector => { if (!nodes.has(selector)) nodes.set(selector, new NodeFixture()); return nodes.get(selector); };
  const node = suffix => root.querySelector(`#recon${suffix}`);
  node("Form").reset = () => {
    for (const item of nodes.values()) { item.value = ""; item.checked = false; }
    node("Crawler").checked = true;
    for (const [key, value] of Object.entries({ MaxRequests: "0", MaxDepth: "0", MaxEndpoints: "0", MaxPages: "0", ScanVisibility: "private" })) node(key).value = value;
  };
  const endpoint = (path, method = "GET") => ({ url: `https://example.com/${path}`, method, raw_urls: [`/${path}`, "<img src=x onerror=alert(1)>"], evidence: [{ source: "crawler", kind: "candidate", location: "https://example.com/app.js" }] });
  const snapshots = {
    a: { session_id: "a", jobs: [], endpoints: Array.from({ length: 111 }, (_, i) => endpoint(`api/${i}`)) },
    b: { session_id: "b", jobs: [], endpoints: [endpoint("session-b-only")] },
  };
  const fixture = { node, document, step: 0, snapshots, session: "a", generation: 0, calls: [], hold: null, held: null, timers: new Map(), nextTimer: 0 };
  const response = payload => ({ ok: true, json: async () => JSON.parse(JSON.stringify(payload)) });
  const fetcher = async (path, options = {}) => {
    const body = options.body ? JSON.parse(options.body) : null;
    const method = options.method || "GET";
    fixture.calls.push({ path, body, method, signal: options.signal });
    if (fixture.respondNext) {
      const respond = fixture.respondNext;
      fixture.respondNext = null;
      return respond();
    }
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
  fixture.controller = recon.createController({ root, getSessionId: () => fixture.session, getSessionGeneration: () => fixture.generation, fetch: fetcher, arrowStep: () => fixture.step,
    setTimeout(callback, delay) { fixture.timers.set(++fixture.nextTimer, { callback, delay }); return fixture.nextTimer; }, clearTimeout(id) { fixture.timers.delete(id); } });
  fixture.switchTo = session => { fixture.controller.reset(); fixture.session = session; fixture.generation += 1; fixture.controller.syncSession(); };
  fixture.controller.setVisible(true);
  return fixture;
}
async function settled() { for (let i = 0; i < 10; i += 1) await new Promise(resolve => setImmediate(resolve)); }
function descendants(node) { return node.childNodes.flatMap(child => [child, ...descendants(child)]); }

function deferredResponse(fixture, phase) {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  fixture.respondNext = () => phase === "fetch" ? promise : {
    ok: phase === "json", status: 503, json: () => promise, text: () => promise,
  };
  return {
    succeed(payload) { resolve(phase === "fetch" ? { ok: true, json: async () => payload } : phase === "json" ? payload : '{"error":"Old HTTP error"}'); },
    fail() { reject(new Error("Old transport error")); },
  };
}

function controllerState(f) {
  return {
    jobs: f.node("Jobs").textContent, endpoints: f.node("Endpoints").textContent,
    detail: f.node("Detail").textContent, inventory: f.node("InventoryMeta").textContent,
    load: f.node("LoadStatus").textContent, action: f.node("ActionStatus").textContent,
    target: f.node("Target").value, search: f.node("Search").value, kind: f.node("Kind").value,
    startDisabled: f.node("Start").disabled, refreshDisabled: f.node("Refresh").disabled,
    timers: [...f.timers.keys()], calls: f.calls.length,
  };
}

function runRefreshTimer(f) {
  assert.equal(f.timers.size, 1);
  const [id, { callback }] = [...f.timers.entries()][0];
  f.timers.delete(id);
  callback();
}

for (const phase of ["fetch", "json", "error body"]) {
  for (const outcome of ["success", "failure"]) {
    for (const completion of ["hidden", "new read pending", "new read complete"]) {
      test(`hide releases ${phase} read; late ${outcome} while ${completion} cannot repaint or release newer work`, async () => {
        const f = controllerFixture(); await settled();
        const old = deferredResponse(f, phase);
        const pending = f.controller.refresh(); await settled();
        const oldRequest = f.calls.at(-1);
        assert.equal(f.node("Refresh").disabled, true);
        f.controller.setVisible(false);
        assert.equal(oldRequest.signal.aborted, true);
        assert.equal(f.node("Refresh").disabled, false);
        assert.equal(f.timers.size, 0);
        await f.controller.refresh();
        assert.equal(f.calls.length, 2, "hidden refresh cannot acquire a read");

        let fresh;
        const latest = { session_id: "a", jobs: [], endpoints: [f.snapshots.a.endpoints[110]] };
        if (completion !== "hidden") {
          fresh = deferredResponse(f, "fetch");
          f.controller.setVisible(true); await settled();
          assert.equal(f.calls.length, 3, "reopening starts a fresh read before the old read settles");
          assert.equal(f.node("Refresh").disabled, true);
          f.controller.setVisible(true);
          assert.equal(f.calls.length, 3, "same-visible render does not duplicate the read");
          if (completion === "new read complete") { fresh.succeed(latest); await settled(); }
        }
        const before = controllerState(f);
        if (outcome === "success") old.succeed({ session_id: "a", jobs: [], endpoints: [] });
        else old.fail();
        await pending; await settled();
        assert.deepEqual(controllerState(f), before, "old success, catch and finally must all be inert");

        if (completion === "hidden") {
          f.snapshots.a = latest;
          f.controller.setVisible(true); await settled();
        } else if (completion === "new read pending") {
          assert.equal(f.calls.at(-1).signal.aborted, false);
          fresh.succeed(latest); await settled();
        }
        assert.match(f.node("Endpoints").textContent, /api\/110/);
        assert.equal(f.node("Endpoints").childNodes.length, 1);
        assert.equal(f.node("LoadStatus").textContent, "");
        assert.equal(f.node("Refresh").disabled, false);
        assert.equal(f.timers.size, 1);
        assert.equal([...f.timers.values()][0].delay, 10000);
        f.snapshots.a = latest;
        runRefreshTimer(f); await settled();
        assert.equal(f.calls.length, 4, "reopened polling continues");
        assert.equal(f.timers.size, 1);
        f.controller.dispose();
      });
    }
  }
}

test("same-visible renders preserve read ownership and the existing poll timer", async () => {
  const f = controllerFixture(); await settled();
  const originalTimer = [...f.timers.keys()];
  f.controller.setVisible(true); f.controller.setVisible(true);
  assert.equal(f.calls.length, 1);
  assert.deepEqual([...f.timers.keys()], originalTimer);
  const pending = deferredResponse(f, "json");
  const refreshing = f.controller.refresh(); await settled();
  const signal = f.calls.at(-1).signal;
  f.controller.setVisible(true); f.controller.setVisible(true);
  assert.equal(signal.aborted, false);
  assert.equal(f.calls.length, 2);
  assert.equal(f.node("Refresh").disabled, true);
  assert.equal(f.timers.size, 0);
  pending.succeed(f.snapshots.a); await refreshing;
  assert.equal(f.node("Refresh").disabled, false);
  assert.equal(f.timers.size, 1);
  f.controller.dispose();
});

for (const type of ["start", "stop"]) {
  for (const phase of ["fetch", "json", "error body"]) {
    for (const outcome of ["success", "failure"]) {
      for (const completion of ["hidden", "reopened"]) {
        test(`hide preserves ${type} ownership through ${phase} ${outcome} completed ${completion}`, async () => {
          const f = controllerFixture(); await settled();
          f.node("Target").value = "https://example.com/";
          const job = { id: "owned-job", status: "running", target_url: "https://example.com/", sources: [] };
          if (type === "stop") { f.snapshots.a.jobs = [job]; await f.controller.refresh(); }
          const pending = deferredResponse(f, phase);
          const stop = descendants(f.node("Jobs")).find(item => item.dataset.stopJob);
          if (type === "start") f.node("Form").emit("submit");
          else f.node("Jobs").emit("click", { target: stop });
          await settled();
          const mutationRequest = f.calls.at(-1);
          const callsBefore = f.calls.length;
          f.controller.setVisible(false); f.controller.setVisible(false);
          assert.equal(mutationRequest.signal.aborted, false, "hiding must not abort the POST");
          assert.equal(f.node("Start").disabled, true);
          assert.equal(f.node("Refresh").disabled, true);
          assert.equal(f.timers.size, 0);
          if (completion === "reopened") { f.controller.setVisible(true); await settled(); }
          f.node("Form").emit("submit");
          if (stop) f.node("Jobs").emit("click", { target: stop });
          await f.controller.refresh();
          assert.equal(f.calls.length, callsBefore, "pending mutation owns the controls across hide/reopen");
          assert.equal(mutationRequest.signal.aborted, false);
          assert.equal(f.node("Target").value, "https://example.com/");

          const succeeded = outcome === "success" && phase !== "error body";
          if (succeeded) f.snapshots.a.jobs = [{ ...job, status: type === "start" ? "running" : "cancelled" }];
          if (outcome === "success") pending.succeed(type === "start" ? job : { stopped: true, session_id: "a" });
          else pending.fail();
          await settled();
          assert.equal(f.calls.filter(call => call.method === "POST").length, 1);
          assert.match(f.node("ActionStatus").textContent, succeeded ? type === "start" ? /Discovery started/ : /Stop requested/ : /Refresh jobs to confirm/);
          if (completion === "hidden") {
            assert.equal(f.calls.length, callsBefore, "hidden mutation completion must not launch a GET");
            assert.equal(f.timers.size, 0);
            assert.equal(f.node("Refresh").disabled, false);
            f.controller.setVisible(true); await settled();
          }
          assert.equal(f.calls.length, callsBefore + 1, "exactly one read reconciles the visible inventory");
          assert.equal(f.node("Refresh").disabled, false);
          assert.equal(f.node("Start").disabled, type === "start" ? succeeded : !succeeded);
          assert.equal(f.timers.size, 1);
          assert.equal([...f.timers.values()][0].delay, (type === "start" ? succeeded : !succeeded) ? 2000 : 10000);
          runRefreshTimer(f); await settled();
          assert.equal(f.calls.length, callsBefore + 2);
          assert.equal(f.calls.filter(call => call.method === "POST").length, 1);
          f.controller.dispose();
        });
      }
    }
  }
}

test("reopening recovers immediately even if the previous inventory fetch never settles", async () => {
  const f = controllerFixture(); await settled();
  deferredResponse(f, "fetch");
  void f.controller.refresh(); await settled();
  f.controller.setVisible(false);
  f.controller.setVisible(true); await settled();
  assert.equal(f.calls.length, 3);
  assert.equal(f.node("Refresh").disabled, false);
  assert.equal(f.timers.size, 1);
  f.controller.dispose();
});

test("repeated hide/reopen cancels each read without cancelling its successor", async () => {
  const f = controllerFixture(); await settled();
  const first = deferredResponse(f, "json");
  const firstRead = f.controller.refresh(); await settled();
  const firstSignal = f.calls.at(-1).signal;
  f.controller.setVisible(false);
  const second = deferredResponse(f, "error body");
  f.controller.setVisible(true); await settled();
  const secondSignal = f.calls.at(-1).signal;
  f.controller.setVisible(false);
  const third = deferredResponse(f, "fetch");
  f.controller.setVisible(true); await settled();
  const thirdSignal = f.calls.at(-1).signal;
  const before = controllerState(f);
  second.succeed(); await settled();
  first.succeed({ session_id: "a", jobs: [], endpoints: [] }); await firstRead;
  assert.deepEqual(controllerState(f), before);
  assert.equal(firstSignal.aborted, true);
  assert.equal(secondSignal.aborted, true);
  assert.equal(thirdSignal.aborted, false);
  third.succeed(f.snapshots.a); await settled();
  assert.equal(f.node("Refresh").disabled, false);
  assert.equal(f.timers.size, 1);
  f.controller.dispose();
});

for (const operation of ["read", "start", "stop"]) {
  for (const transition of ["session ABA", "dispose"]) {
    for (const outcome of ["success", "failure"]) {
      test(`hidden ${operation} late JSON ${outcome} is inert after ${transition}`, async () => {
        const f = controllerFixture(); await settled();
        f.node("Target").value = "https://example.com/";
        if (operation === "stop") {
          f.snapshots.a.jobs = [{ id: "old-job", status: "running", target_url: "https://example.com/", sources: [] }];
          await f.controller.refresh();
        }
        const pending = deferredResponse(f, "json");
        if (operation === "read") void f.controller.refresh();
        else if (operation === "start") f.node("Form").emit("submit");
        else f.node("Jobs").emit("click", { target: descendants(f.node("Jobs")).find(item => item.dataset.stopJob) });
        await settled();
        const request = f.calls.at(-1);
        f.controller.setVisible(false);
        assert.equal(request.signal.aborted, operation === "read");
        if (transition === "dispose") f.controller.dispose();
        else {
          f.session = "b"; f.generation += 1; f.controller.syncSession();
          f.session = "a"; f.generation += 1; f.controller.syncSession();
          f.snapshots.a.jobs = [];
          f.snapshots.a.endpoints = [f.snapshots.a.endpoints[110]];
          f.controller.setVisible(true); await settled();
        }
        assert.equal(request.signal.aborted, true, "session reset and disposal still cancel mutations");
        const before = controllerState(f);
        if (outcome === "failure") pending.fail();
        else pending.succeed(operation === "read" ? { session_id: "a", jobs: [], endpoints: [] }
          : operation === "start" ? { id: "old-start", status: "running" } : { stopped: true, session_id: "a" });
        await settled();
        assert.deepEqual(controllerState(f), before);
        if (transition === "session ABA") {
          assert.match(f.node("Endpoints").textContent, /api\/110/);
          assert.equal(f.node("Start").disabled, false);
          assert.equal(f.timers.size, 1);
        } else assert.equal(f.timers.size, 0);
        f.controller.dispose();
      });
    }
  }
}

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

test("endpoints sort by a column, ties keeping the order they came in", () => {
  const list = [
    { method: "POST", url: "https://example.com/b", evidence: [{ source: "wayback", kind: "history" }] },
    { method: "GET", url: "https://example.com/c", evidence: [{ source: "crawler", kind: "live" }] },
    { method: "GET", url: "https://example.com/a", evidence: [{ source: "crawler", kind: "candidate" }] },
  ];
  const order = sort => recon.sortEndpoints(list, sort).map(endpoint => endpoint.url.slice(-1)).join("");
  assert.equal(order({ key: "", direction: "asc" }), "bca");
  assert.equal(order({ key: "url", direction: "asc" }), "abc");
  assert.equal(order({ key: "url", direction: "desc" }), "cba");
  assert.equal(order({ key: "method", direction: "asc" }), "cab");
  assert.equal(order({ key: "evidence", direction: "asc" }), "abc");
  assert.equal(order({ key: "sources", direction: "desc" }), "bca");
  assert.equal(recon.sortEndpoints(list, { key: "url", direction: "asc" })[0], list[2], "sorting copies, never reorders the inventory");
  assert.equal(list[0].url, "https://example.com/b");
});

test("a header sorts the endpoints, and a click anywhere on a row or ↑/↓ selects", async () => {
  const f = controllerFixture(); await settled();
  const rows = () => f.node("Endpoints").childNodes;
  f.node("Endpoints").emit("click", { target: rows()[2] });
  assert.equal(rows()[2].className, "recon-selected");
  // The app decides when the arrows belong to the list.
  f.step = 1; f.document.emit("keydown", { key: "ArrowDown" });
  assert.equal(rows()[3].className, "recon-selected");
  f.step = -1; f.document.emit("keydown", { key: "ArrowUp" });
  assert.equal(rows()[2].className, "recon-selected");
  f.step = 0; f.document.emit("keydown", { key: "ArrowUp" });
  assert.equal(rows()[2].className, "recon-selected");
  const header = new NodeFixture("th"); header.dataset.sort = "url";
  f.node("Head").emit("click", { target: header });
  f.node("Head").emit("click", { target: header });
  const urls = rows().map(row => row.dataset.endpointKey.split("\n")[1]);
  assert.deepEqual(urls, [...urls].sort().reverse());
  assert.equal(urls[0], "https://example.com/api/99");
  f.controller.setVisible(false);
  f.step = 1; f.document.emit("keydown", { key: "ArrowDown" });
  f.controller.dispose();
});

test("controller keeps and searches endpoints beyond the old 5,000 display cap", async () => {
  const f = controllerFixture(); await settled();
  f.snapshots.a.endpoints = Array.from({ length: 5_101 }, (_, i) => ({
    url: `https://example.com/large/${i}`, method: "GET", raw_urls: [], evidence: [],
  }));
  await f.controller.refresh();
  assert.match(f.node("InventoryMeta").textContent, /^5,101 endpoints in this session$/);
  f.node("Search").value = "/large/5100"; f.node("Search").emit("input");
  assert.equal(f.node("Endpoints").childNodes.length, 1);
  assert.match(f.node("Endpoints").textContent, /large\/5100/);
  assert.doesNotMatch(f.node("InventoryMeta").textContent, /cap|partial/);
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

test("completed sources retain optional budget warnings and accurate counts", async () => {
  const f = controllerFixture(); await settled();
  f.snapshots.a.endpoints = f.snapshots.a.endpoints.slice(0, 1);
  f.snapshots.a.jobs = [{ id: "bounded-job", status: "completed", target_url: "https://example.com/tags", sources: [{
    source: "crawler", status: "completed", requests: 3, discovered: 1, truncated: true,
    warnings: ["Crawler request budget reached.", "Collection is partial; more evidence may exist."],
  }] }];
  await f.controller.refresh();
  assert.match(f.node("Jobs").textContent, /completed.*3 requests.*1 discovered.*LIMIT REACHED \/ PARTIAL/);
  assert.match(f.node("Jobs").textContent, /request budget reached/);
  assert.match(f.node("InventoryMeta").textContent, /^1 endpoints in this session$/);
  assert.equal(descendants(f.node("Jobs")).some(item => item.dataset.stopJob), false);
  f.snapshots.a.jobs[0].sources[0] = { source: "crawler", status: "completed", requests: 4, discovered: 2, truncated: false, warnings: [] };
  await f.controller.refresh();
  assert.match(f.node("Jobs").textContent, /4 requests.*2 discovered/);
  assert.doesNotMatch(f.node("Jobs").textContent, /LIMIT REACHED|request budget/);
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
  const context = vm.createContext({ console, resetFindingsUiState() {},
    currentSessionId: () => globals.state?.activeSession?.id || null, ...globals });
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

test("Scan navigation names Scan in the status bar, not the tool left behind", () => {
  const context = panelsFixture({ templatesController: { setVisible() {} } });
  context.els.templatesShell = new NodeFixture();
  context.state.activeTool = "fuzzer";
  context.renderToolPanels();
  context.state.activeTool = "templates";
  context.renderToolPanels();
  assert.equal(context.els.templatesShell.classList.contains("hidden"), false);
  assert.equal(context.els.footerMode.textContent, "Scan active");
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

// These inventory checks use only synthetic snapshot GETs. Detail rendering is
// synchronous, so a pending inventory read must resolve the latest selection.
function selectEndpoint(f, endpoint) {
  const key = recon.endpointKey(endpoint);
  const row = descendants(f.node("Endpoints")).find(item => item.dataset.endpointKey === key);
  assert.ok(row, `Expected a visible endpoint row for ${key}`);
  f.node("Endpoints").emit("click", { target: row });
}

function detailFields(f) {
  const list = f.node("Detail").childNodes.find(node => node.tagName === "DL");
  if (!list) return null;
  const fields = {};
  for (let i = 0; i < list.childNodes.length; i += 2) fields[list.childNodes[i].textContent] = list.childNodes[i + 1].textContent;
  return fields;
}

function assertSelectedEndpoint(f, endpoint, visible = true) {
  assert.equal(detailFields(f)?.Method, endpoint.method);
  assert.equal(detailFields(f)?.["Normalized URL"], endpoint.url);
  const selected = descendants(f.node("Endpoints")).filter(item => item.attributes["aria-selected"] === "true");
  assert.deepEqual(selected.map(item => item.dataset.endpointKey), visible ? [recon.endpointKey(endpoint)] : []);
}

for (const phase of ["fetch", "json"]) {
  for (const selection of ["different endpoint", "same URL different method", "selection ABA"]) {
    test(`a current ${phase} inventory read refreshes the latest ${selection} detail`, async () => {
      const f = controllerFixture(); await settled();
      const first = { ...f.snapshots.a.endpoints[0], raw_urls: ["/first-original"] };
      const second = { ...f.snapshots.a.endpoints[1], raw_urls: ["/second-original"] };
      if (selection === "same URL different method") { second.url = first.url; second.method = "POST"; }
      f.snapshots.a.endpoints = [first, second];
      await f.controller.refresh();
      selectEndpoint(f, first);
      const pending = deferredResponse(f, phase);
      const read = f.controller.refresh(); await settled();
      selectEndpoint(f, second);
      if (selection === "selection ABA") selectEndpoint(f, first);
      const selected = selection === "selection ABA" ? first : second;
      assertSelectedEndpoint(f, selected);
      const selectedIndex = selection === "selection ABA" ? 0 : 1;
      const latest = [first, second].map((endpoint, index) => ({ ...endpoint, raw_urls: [`/fresh-${index}`] }));
      pending.succeed({ session_id: "a", jobs: [], endpoints: latest });
      await read;
      assertSelectedEndpoint(f, selected);
      assert.match(f.node("Detail").textContent, new RegExp(`/fresh-${selectedIndex}`));
      assert.doesNotMatch(f.node("Detail").textContent, /original/);
      assert.equal(f.node("Refresh").disabled, false);
      assert.equal(f.timers.size, 1);
      assert.equal(f.calls.every(call => call.method === "GET"), true);
      f.controller.dispose();
    });
  }
}

for (const filter of ["Search", "Kind"]) {
  test(`a pending snapshot uses the latest ${filter} filter without retargeting endpoint detail`, async () => {
    const f = controllerFixture(); await settled();
    const [selected, other] = f.snapshots.a.endpoints;
    f.snapshots.a.endpoints = [selected, { ...other, evidence: [{ source: "wayback", kind: "history", location: "synthetic history" }] }];
    await f.controller.refresh();
    selectEndpoint(f, selected);
    const pending = deferredResponse(f, "json");
    const read = f.controller.refresh(); await settled();
    f.node(filter).value = filter === "Search" ? other.url : "history";
    f.node(filter).emit(filter === "Search" ? "input" : "change");
    assertSelectedEndpoint(f, selected, false);
    pending.succeed({ ...f.snapshots.a, endpoints: f.snapshots.a.endpoints.map(endpoint => ({ ...endpoint, raw_urls: ["/latest-filtered-inventory"] })) });
    await read;
    assert.equal(f.node("PageMeta").textContent, "1–1 of 1 matching · Page 1 / 1");
    assertSelectedEndpoint(f, selected, false);
    assert.match(f.node("Detail").textContent, /latest-filtered-inventory/);
    f.node(filter).value = filter === "Search" ? "no-synthetic-match" : "live";
    f.node(filter).emit(filter === "Search" ? "input" : "change");
    assert.equal(f.node("PageMeta").textContent, "0 matching endpoints");
    assert.match(f.node("Endpoints").textContent, /No endpoints match these filters/);
    assertSelectedEndpoint(f, selected, false);
    f.node(filter).value = "";
    f.node(filter).emit(filter === "Search" ? "input" : "change");
    assertSelectedEndpoint(f, selected);
    f.controller.dispose();
  });
}

test("paging during an inventory read preserves the selected endpoint and clamps a shrinking page", async () => {
  const f = controllerFixture(); await settled();
  const selected = f.snapshots.a.endpoints[0];
  selectEndpoint(f, selected);
  const pending = deferredResponse(f, "fetch");
  const read = f.controller.refresh(); await settled();
  f.node("Next").emit("click");
  f.node("Next").emit("click");
  assert.match(f.node("PageMeta").textContent, /101–111/);
  assertSelectedEndpoint(f, selected, false);
  pending.succeed({ session_id: "a", jobs: [], endpoints: [{ ...selected, raw_urls: ["/latest-page"] }] });
  await read;
  assert.equal(f.node("PageMeta").textContent, "1–1 of 1 matching · Page 1 / 1");
  assertSelectedEndpoint(f, selected);
  assert.equal(f.node("Previous").disabled, true);
  assert.equal(f.node("Next").disabled, true);
  assert.match(f.node("Detail").textContent, /latest-page/);
  f.controller.dispose();
});

test("an empty current snapshot clears old detail and never substitutes a different endpoint", async () => {
  const f = controllerFixture(); await settled();
  const [selected, other] = f.snapshots.a.endpoints;
  selectEndpoint(f, selected);
  f.snapshots.a.endpoints = [];
  await f.controller.refresh();
  assert.equal(detailFields(f), null);
  assert.match(f.node("Detail").textContent, /Select an endpoint/);
  assert.doesNotMatch(f.node("Detail").textContent, /api\/0/);
  assert.equal(f.node("PageMeta").textContent, "0 matching endpoints");
  f.snapshots.a.endpoints = [other];
  await f.controller.refresh();
  assert.equal(detailFields(f), null);
  f.snapshots.a.endpoints = [other, { ...selected, raw_urls: ["/returned-detail"] }];
  await f.controller.refresh();
  assertSelectedEndpoint(f, selected);
  assert.match(f.node("Detail").textContent, /returned-detail/);
  selectEndpoint(f, other);
  assertSelectedEndpoint(f, other);
  f.controller.dispose();
});

for (const transition of ["different session", "session ABA", "same session generation"]) {
  for (const outcome of ["success", "failure"]) {
    test(`old selected detail stays cleared after ${transition} and late ${outcome}`, async () => {
      const f = controllerFixture(); await settled();
      const selected = f.snapshots.a.endpoints[0];
      selectEndpoint(f, selected);
      const pending = deferredResponse(f, "json");
      const read = f.controller.refresh(); await settled();
      if (transition !== "same session generation") { f.session = "b"; f.generation += 1; f.controller.syncSession(); }
      if (transition !== "different session") { f.session = "a"; f.generation += 1; f.controller.syncSession(); }
      await settled();
      assert.equal(detailFields(f), null, "session ownership change clears the previous selection even for identical endpoint keys");
      const current = f.snapshots[f.session].endpoints[0];
      selectEndpoint(f, current);
      const before = controllerState(f);
      if (outcome === "success") pending.succeed({ session_id: "a", jobs: [], endpoints: [{ ...selected, raw_urls: ["/stale-detail"] }] });
      else pending.fail();
      await read;
      assert.deepEqual(controllerState(f), before);
      assertSelectedEndpoint(f, current);
      assert.doesNotMatch(f.node("Detail").textContent, /stale-detail/);
      f.controller.dispose();
    });
  }
}

for (const phase of ["fetch", "json", "error body"]) {
  test(`a current ${phase} read error retains the newest selected detail until successful recovery`, async () => {
    const f = controllerFixture(); await settled();
    const [first, second] = f.snapshots.a.endpoints;
    selectEndpoint(f, first);
    const pending = deferredResponse(f, phase);
    const read = f.controller.refresh(); await settled();
    selectEndpoint(f, second);
    if (phase === "error body") pending.succeed(); else pending.fail();
    await read;
    assertSelectedEndpoint(f, second);
    assert.match(f.node("LoadStatus").textContent, /Showing the last loaded results; status may be out of date/);
    assert.equal(f.node("Refresh").disabled, false);
    f.snapshots.a.endpoints = [{ ...second, raw_urls: ["/recovered-detail"] }];
    await f.controller.refresh();
    assertSelectedEndpoint(f, second);
    assert.match(f.node("Detail").textContent, /recovered-detail/);
    assert.equal(f.node("LoadStatus").textContent, "");
    f.controller.dispose();
  });
}

test("same-session synchronization and repeated visible renders allow the owned detail refresh to finish", async () => {
  const f = controllerFixture(); await settled();
  const selected = f.snapshots.a.endpoints[0];
  selectEndpoint(f, selected);
  const pending = deferredResponse(f, "json");
  const read = f.controller.refresh(); await settled();
  const count = f.calls.length;
  f.controller.syncSession();
  f.controller.setVisible(true);
  f.controller.setVisible(true);
  assert.equal(f.calls.length, count);
  assert.equal(f.calls.at(-1).signal.aborted, false);
  pending.succeed({ session_id: "a", jobs: [], endpoints: [{ ...selected, raw_urls: ["/owned-detail"] }] });
  await read;
  assertSelectedEndpoint(f, selected);
  assert.match(f.node("Detail").textContent, /owned-detail/);
  assert.equal(f.node("Refresh").disabled, false);
  assert.equal(f.timers.size, 1);
  f.controller.dispose();
});

for (const phase of ["fetch", "json", "error body"]) {
  for (const outcome of ["success", "failure"]) {
    test(`workspace read generation keeps Recon live after later UI read failure and old ${phase} ${outcome}`, async () => {
      const f = controllerFixture(); await settled();
      const old = deferredResponse(f, phase);
      const reachedLegacyReset = new Error("Unrelated reset cleanup boundary");
      const historyFailure = new Error("Synthetic history read failure");
      const forbidden = label => () => assert.fail(`Unexpected ${label}`);
      const app = loadAppFunctions(["retireFindingActionProgress", "applyWorkspaceState", "reloadSessionWorkspace", "resetSessionScopedUiState", "loadSessions", "loadWorkspaceState"], {
        state: { activeSession: { id: "a" }, replayTabs: [], activeTool: "recon" },
        workspaceLoaded: true, sessionsLoadGeneration: 0, sessionsAppliedLoadGeneration: 0,
        reconController: f.controller, currentSessionId: () => f.session,
        // The full production reset is stopped immediately after its UI owner
        // hooks, before unrelated replay cleanup or state-saving machinery.
        clearReplaySendInFlight() { throw reachedLegacyReset; },
        fetch: async path => {
          assert.ok(["/api/sessions", "/api/workspace-state"].includes(path));
          return { ok: true, json: async () => path === "/api/sessions"
            ? [{ id: "a", name: "Synthetic session", active: true }]
            : { session_id: "a", replay: { tabs: [] }, fuzzer: {} } };
        },
        requireOkResponse: async () => {}, renderDashboard() {}, loadSettings: async () => {},
        workspaceSnapshotMatchesActiveSession: snapshot => snapshot.session_id === f.session,
        hydrateReplayTab: value => value, normalizeFuzzerTargetOverride: () => null,
        normalizeFuzzerAttackRecord: () => null, setFuzzerAttackRecord() {},
        fuzzerWorkspaceAttackRecordId: () => null, snapshotWorkspaceState: () => ({}),
        cloneWorkspaceSnapshotForBaseline: value => value,
        scheduleWorkspaceStateSave: forbidden("workspace save"), cleanupWsReplayTab: forbidden("replay cleanup"),
        cleanupWsReplayTabsBeforeStateReset: forbidden("pre-reset cleanup"),
        loadTransactions: async () => { throw historyFailure; },
        loadIntercepts: forbidden("load after rejected history read"),
        renderToolPanels: forbidden("final render after rejected history read"),
      });
      Object.defineProperty(app, "workspaceStateGeneration", { get: () => f.generation, set: value => { f.generation = value; } });
      const resetUiOwner = app.resetSessionScopedUiState;
      app.resetSessionScopedUiState = () => assert.throws(resetUiOwner, error => error === reachedLegacyReset);
      await assert.rejects(app.reloadSessionWorkspace({ cleanupBeforeReset: false }), error => error === historyFailure);
      await settled();
      assert.equal(f.generation, 2, "reset and accepted workspace hydration each advance the production UI generation");
      assert.equal(f.node("Refresh").disabled, false, "an unrelated read failure must not strand Recon's Refresh button");
      assert.equal(f.calls[1].signal.aborted, true, "hydration retires the older-generation inventory read immediately");
      assert.equal(f.calls.length, 3, "hydration starts a current-generation read without waiting for the final panel render");
      assert.equal(f.timers.size, 1);
      const selected = f.snapshots.a.endpoints[1];
      selectEndpoint(f, selected);
      const before = controllerState(f);
      if (outcome === "success") old.succeed({ session_id: "a", jobs: [], endpoints: [] }); else old.fail();
      await settled();
      assert.deepEqual(controllerState(f), before, "old completion cannot release the current read, clear detail, or replace its timer");
      assertSelectedEndpoint(f, selected);
      await f.controller.refresh();
      assert.equal(f.calls.length, 4, "manual refresh remains usable after the unrelated read failure");
      assert.equal(f.timers.size, 1);
      f.controller.dispose();
    });
  }
}
