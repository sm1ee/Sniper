// A fake DOM and a local fetch stub only; nothing is sent.
// Settings saved the whole form, so a setting another client changed after the
// form was filled (sniper-cli turning intercept on, an agent's scope edit) was
// put back by a save of something else.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
for (const [id, expected] of [
  ["oastPayloadText", { id: "oastPayloadText", class: "oast-payload-input", type: "text",
    placeholder: "Generate or paste a domain", spellcheck: "false", "aria-label": "OAST payload" }],
  ["proxySettingOastToken", { id: "proxySettingOastToken", type: "password", autocomplete: "off", spellcheck: "false",
    placeholder: "Optional", "aria-label": "OAST token" }],
]) test(`${id} retains its explicit name, input policy and empty default`, () => {
  const matches = [...html.matchAll(new RegExp(`<input\\b([^>]*\\bid="${id}"[^>]*)/>`, "g"))];
  assert.equal(matches.length, 1);
  const attrs = Object.fromEntries([...matches[0][1].matchAll(/([^\s=]+)(?:="([^"]*)")?/g)]
    .map(([, name, value]) => [name, value ?? ""]));
  assert.deepEqual(attrs, expected);
});

function fixture() {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      let value = "";
      elements.set(id, {
        id, checked: false, textContent: "", placeholder: "", disabled: false, style: {}, handlers: new Map(),
        addEventListener(type, handler) { this.handlers.set(type, handler); },
        classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
        // A form field keeps its value as text, as the DOM does.
        get value() { return value; },
        set value(next) { value = String(next ?? ""); },
      });
    }
    return elements.get(id);
  };
  const els = new Proxy({}, { get: (_, key) => element(String(key)) });
  const state = {
    activeSession: { id: "s-1" },
    settings: {
      startup: { proxy_bind_host: "127.0.0.1", proxy_port: 8080, proxy_addr: "127.0.0.1:8080" },
      proxy_addr: "127.0.0.1:8080", ui_addr: "127.0.0.1:8081", body_preview_bytes: 1024, data_dir: "/data",
      certificate: { special_host_https: "https://sniper", common_name: "Sniper", expires_at: "2030-01-01T00:00:00Z" },
    },
    runtime: {
      intercept_enabled: false, websocket_capture_enabled: false, upstream_insecure: true,
      upstream_proxy: { enabled: false, url: "", username: "", password: "" },
      scope_patterns: ["app.example.com"], passthrough_hosts: [], upstream_bypass_hosts: [],
      oast_enabled: false, oast_provider: "custom", oast_server_url: "", oast_polling_interval_secs: 5,
    },
  };
  const posts = [];
  const document = { getElementById: element, activeElement: null };
  const c = loadFunctions([
    "renderProxySettings", "renderOastSettingsControls", "proxySettingsFromRuntime", "saveProxySettings",
    "syncCaptureSettingsForm", "proxySettingsDirty", "proxySettingsFormValues",
    "postRuntimeSettings", "currentSessionId", "strictIntegerInRange", "isValidIpLiteral",
    "normalizeIpLiteralForSettings", "validateOastServerUrlForSettings",
  ], {
    state, els, document,
    localStorage: { getItem: () => null }, OAST_TOKEN_REDACTION: "********",
    renderUpstreamPeerSettings() {}, renderHistoryRetentionSettings() {}, formatSize: String, formatTimestamp: String,
    expectedActiveSessionIdForWrite: (id) => id, renderInterceptStatus() {}, invalidateVisibleEntriesCache() {},
    scheduleRefresh() {}, loadSettings: async () => {}, URL,
    fetch: async (url, init) => {
      const body = JSON.parse(init.body);
      posts.push({ url, body });
      return { ok: true, json: async () => ({ ...state.runtime, ...body }) };
    },
  });
  return { c, state, element, document, posts };
}

// Only initialized local token editing and an explicitly invoked, stubbed
// runtime save. No startup request, service or real credential is permitted.
function tokenFixture(configured = true) {
  const f = fixture();
  f.state.runtime.oast_token = configured ? "********" : "";
  f.state.oastTokenClearPending = false;
  f.c.fetch = async (url, init) => {
    assert.equal(url, "/api/runtime"); assert.equal(init.method, "POST");
    const body = JSON.parse(init.body); f.posts.push({ url, body });
    const reply = { ...f.state.runtime, ...body };
    if (reply.oast_token) reply.oast_token = "********";
    return { ok: true, json: async () => reply };
  };
  f.c.renderProxySettings();
  const start = appSource.indexOf("  if (els.proxySettingOastClearToken) {", appSource.indexOf("  // OAST\n"));
  const end = appSource.indexOf("  if (els.oastGenerateButton) {", start);
  assert.ok(start > 0 && end > start);
  vm.runInContext(appSource.slice(start, end), f.c);
  f.token = f.element("proxySettingOastToken");
  f.input = value => { f.document.activeElement = f.token; f.token.value = value; f.token.handlers.get("input")(); };
  f.clear = () => f.element("proxySettingOastClearToken").handlers.get("click")();
  return f;
}

for (const configured of [false, true]) test(`OAST token ${configured ? "configured" : "empty"} display stays blank without any request`, () => {
  const f = tokenFixture(configured);
  assert.equal(f.token.value, "");
  assert.equal(f.token.placeholder, configured ? "Token configured; leave blank to keep it" : "Optional token");
  assert.equal(f.element("proxySettingOastClearToken").disabled, !configured);
  assert.equal(f.posts.length, 0);
});

test("OAST token edit and focused redraw preserve the draft without saving until explicit action", async () => {
  const f = tokenFixture(); f.input("  SYNTHETIC-NOT-A-TOKEN  ");
  f.token.selectionStart = 2; f.token.selectionEnd = 8;
  f.c.renderOastSettingsControls({ hydrateValues: true });
  assert.equal(f.element("proxySettingOastToken"), f.token);
  assert.equal(f.token.value, "  SYNTHETIC-NOT-A-TOKEN  ");
  assert.equal(f.token.selectionStart, 2); assert.equal(f.token.selectionEnd, 8);
  assert.equal(f.state.oastTokenClearPending, false); assert.equal(f.posts.length, 0);
  await f.c.saveProxySettings();
  assert.equal(f.posts.length, 1); assert.equal(f.posts[0].body.oast_token, "SYNTHETIC-NOT-A-TOKEN");
  assert.deepEqual(Object.keys(f.posts[0].body).sort(), ["expected_active_session_id", "oast_token", "session_id"]);
  assert.equal(f.token.value, ""); assert.equal(f.state.runtime.oast_token, "********");
});

test("OAST token Clear is local until explicit save and then sends only the existing empty-token intent", async () => {
  const f = tokenFixture(); f.input("SYNTHETIC-NOT-A-TOKEN"); f.clear();
  assert.equal(f.token.value, ""); assert.equal(f.state.oastTokenClearPending, true); assert.equal(f.posts.length, 0);
  await f.c.saveProxySettings();
  assert.equal(f.posts.length, 1); assert.equal(f.posts[0].body.oast_token, "");
  assert.equal(f.state.oastTokenClearPending, false); assert.equal(f.token.value, "");
});

test("new OAST token input cancels pending clear without saving or exposing a stored value", async () => {
  const f = tokenFixture(); f.clear(); f.input("SYNTHETIC-NOT-A-TOKEN");
  assert.equal(f.state.oastTokenClearPending, false); assert.equal(f.token.value, "SYNTHETIC-NOT-A-TOKEN");
  assert.equal(f.posts.length, 0);
  await f.c.saveProxySettings();
  assert.equal(f.posts.length, 1); assert.equal(f.posts[0].body.oast_token, "SYNTHETIC-NOT-A-TOKEN");
  assert.equal(f.token.value, "");
});

for (const value of ["", "********"]) test(`OAST token ${value ? "redaction marker" : "blank entry"} does not overwrite the configured token`, async () => {
  const f = tokenFixture(); f.input(value);
  assert.equal(f.posts.length, 0);
  await f.c.saveProxySettings();
  assert.equal(f.posts.length, 1); assert.equal(Object.hasOwn(f.posts[0].body, "oast_token"), false);
  assert.equal(f.state.runtime.oast_token, "********");
});

test("OAST provider display keeps its existing token-field visibility without sending anything", () => {
  const f = tokenFixture();
  for (const provider of ["boast", "interactsh", "custom"]) {
    f.element("proxySettingOastProvider").value = provider;
    f.c.renderOastSettingsControls();
    assert.equal(f.element("oastTokenField").style.display, provider === "boast" ? "none" : "");
  }
  assert.equal(f.posts.length, 0);
});

test("saving Settings sends the fields changed in the form, not settings changed elsewhere", async () => {
  const f = fixture();
  f.c.renderProxySettings();
  // The operator turns WebSocket capture on and saves, while sniper-cli had
  // turned intercept on and an agent had added a scope pattern.
  f.element("proxySettingWebsocketCapture").checked = true;
  await f.c.saveProxySettings();
  assert.equal(f.posts.length, 1);
  const sent = f.posts[0].body;
  assert.equal(sent.websocket_capture_enabled, true);
  for (const untouched of ["intercept_enabled", "scope_patterns", "upstream_proxy", "upstream_insecure", "oast_enabled"]) {
    assert.equal(Object.hasOwn(sent, untouched), false, `${untouched} was sent: ${JSON.stringify(sent)}`);
  }
  assert.equal(sent.session_id, "s-1");
});

test("a field typed in Settings is sent even when the form was redrawn under it", async () => {
  const f = fixture();
  f.c.renderProxySettings();
  const scope = f.element("proxySettingScopePatterns");
  scope.value = "app.example.com\napi.example.com";
  // A runtime refresh redraws the form while the scope field is still in use.
  f.document.activeElement = scope;
  f.c.renderProxySettings();
  f.element("proxyChainUrl").value = "http://proxy.example.com:3128";
  f.element("proxyChainEnabled").checked = true;
  await f.c.saveProxySettings();
  const sent = f.posts[0].body;
  assert.deepEqual(sent.scope_patterns, ["app.example.com", "api.example.com"]);
  assert.deepEqual(sent.upstream_proxy, { enabled: true, url: "http://proxy.example.com:3128", username: "", password: "" });
  assert.equal(Object.hasOwn(sent, "intercept_enabled"), false);
});

// Save and Revert appear only while there is something to save, and go away
// when a change is put back by hand.
test("Save and Revert show only while the form differs from what was loaded", () => {
  const f = fixture();
  let hidden = true;
  f.element("proxySettingsSaveBar").classList = { toggle(name, value) { if (name === "hidden") hidden = value; } };
  f.c.renderProxySettings();
  assert.equal(hidden, true, "a freshly loaded form has nothing to save");
  f.element("proxySettingWebsocketCapture").checked = true; f.c.syncCaptureSettingsForm();
  assert.equal(hidden, false);
  f.element("proxySettingWebsocketCapture").checked = false; f.c.syncCaptureSettingsForm();
  assert.equal(hidden, true, "putting a change back leaves nothing to save");
  f.element("proxySettingScopePatterns").value = "app.example.com\n  \n"; f.c.syncCaptureSettingsForm();
  assert.equal(hidden, true, "blank lines are not a change, as Save reads them");
  f.element("proxySettingPort").value = "8081"; f.c.syncCaptureSettingsForm();
  assert.equal(hidden, false, "a new listener port is a change");
  f.element("proxySettingPort").value = "8080"; f.state.oastTokenClearPending = true; f.c.syncCaptureSettingsForm();
  assert.equal(hidden, false, "clearing the OAST token is a change");
  assert.equal(f.posts.length, 0, "showing the bar saves nothing");
});
