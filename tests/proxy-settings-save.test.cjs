// A fake DOM and a local fetch stub only; nothing is sent.
// Settings saved the whole form, so a setting another client changed after the
// form was filled (sniper-cli turning intercept on, an agent's scope edit) was
// put back by a save of something else.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture() {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      let value = "";
      elements.set(id, {
        id, checked: false, textContent: "", placeholder: "", disabled: false, style: {},
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
