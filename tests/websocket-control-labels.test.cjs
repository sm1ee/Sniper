// Static markup and isolated renderer checks; no browser or WebSocket operation runs.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");

// These controls use quoted attributes and explicit closing tags in index.html.
function elementById(id) {
  const matches = [...html.matchAll(new RegExp(`<([a-z][\\w-]*)\\b([^>]*\\bid="${id}"[^>]*)>([^]*?)<\\/\\1>`, "g"))];
  assert.equal(matches.length, 1, `Expected one element with id ${id}`);
  const [, tag, source, content] = matches[0];
  const attrs = Object.fromEntries([...source.matchAll(/([^\s=]+)(?:="([^"]*)")?/g)]
    .map(([, name, value]) => [name, value ?? ""]));
  return { tag, attrs, content };
}

for (const [id, name, className] of [
  ["wsSchemeSelect", "WebSocket scheme", "compact-field-inline"],
  ["wsMessageType", "WebSocket message type", "compact-field-inline ws-type-field"],
]) {
  test(`${id} has an explicit name and retains its native select semantics`, () => {
    const control = elementById(id);
    assert.equal(control.tag, "select");
    assert.deepEqual(control.attrs, { id, class: className, "aria-label": name });
  });
}

for (const [id, name, className, type, placeholder] of [
  ["wsHostInput", "WebSocket host", "compact-field-inline ws-host-field", "text", "host"],
  ["wsPortInput", "WebSocket port", "compact-field-inline ws-port-field", "number", "443"],
  ["wsPathInput", "WebSocket path", "compact-field-inline ws-path-field", "text", "/path"],
]) {
  test(`${id} has a stable purpose name without changing its native input or example`, () => {
    const matches = [...html.matchAll(new RegExp(`<input\\b([^>]*\\bid="${id}"[^>]*)/>`, "g"))];
    assert.equal(matches.length, 1, `Expected one input with id ${id}`);
    const attrs = Object.fromEntries([...matches[0][1].matchAll(/([^\s=]+)(?:="([^"]*)")?/g)]
      .map(([, name, value]) => [name, value ?? ""]));
    assert.deepEqual(attrs, { id, class: className, type, placeholder, "aria-label": name });
  });
}

test("captured WebSocket search names the session filter rather than frame contents", () => {
  const matches = [...html.matchAll(/<input\b([^>]*\bid="websocketSearchInput"[^>]*)\/>/g)];
  assert.equal(matches.length, 1);
  const attrs = Object.fromEntries([...matches[0][1].matchAll(/([^\s=]+)(?:="([^"]*)")?/g)]
    .map(([, name, value]) => [name, value ?? ""]));
  assert.deepEqual(attrs, {
    id: "websocketSearchInput", type: "search", placeholder: "Host, path, status", autocomplete: "off",
    "aria-label": "Search captured WebSocket sessions",
  });
});

test("handshake headers has a stable name and retains its native textarea", () => {
  const control = elementById("wsHandshakeHeaders");
  assert.equal(control.tag, "textarea");
  assert.deepEqual(control.attrs, {
    id: "wsHandshakeHeaders", class: "ws-handshake-editor", rows: "4",
    placeholder: "header-name: value", spellcheck: "false", "aria-label": "WebSocket handshake headers",
  });
  assert.equal(control.content, "");
});

test("the named selectors retain their existing option order and implicit defaults", () => {
  for (const [id, expected] of [
    ["wsSchemeSelect", [["wss", "WSS"], ["ws", "WS"]]],
    ["wsMessageType", [["text", "Text"], ["binary", "Binary"], ["ping", "Ping"], ["pong", "Pong"]]],
  ]) {
    const { content } = elementById(id);
    const options = [...content.matchAll(/<option value="([^"]+)">([^<]+)<\/option>/g)];
    assert.deepEqual(options.map(([, value, text]) => [value, text]), expected);
    assert.equal(content.replace(/<option value="[^"]+">[^<]+<\/option>/g, "").trim(), "");
  }
});

test("the editable message is named by its existing visible MESSAGE caption", () => {
  const editor = elementById("wsMessageHighlight");
  assert.equal(editor.attrs["aria-labelledby"], "wsMessageLabel");
  const label = elementById(editor.attrs["aria-labelledby"]);
  assert.equal(label.tag, "label");
  assert.deepEqual(label.attrs, { id: "wsMessageLabel", class: "ws-editor-label" });
  assert.equal(label.content.trim(), "MESSAGE");
  assert.equal(editor.attrs["aria-label"], undefined);
  const rule = css.match(/\.ws-editor-label\s*\{([^}]+)\}/);
  assert.ok(rule, "The existing caption styles remain present");
  assert.doesNotMatch(rule[1], /(?:display:\s*none|visibility:\s*hidden)/);
});

test("textbox semantics belong to the existing plaintext-only multiline editor", () => {
  const editor = elementById("wsMessageHighlight");
  assert.equal(editor.tag, "pre");
  assert.deepEqual(editor.attrs, {
    id: "wsMessageHighlight",
    class: "ws-message-highlight",
    contenteditable: "plaintext-only",
    role: "textbox",
    "aria-multiline": "true",
    "aria-labelledby": "wsMessageLabel",
    spellcheck: "false",
    "data-placeholder": "Type a message...",
  });
  assert.equal(editor.content, "");
});

test("the hidden backing textarea remains separate from the named editable region", () => {
  const proxy = elementById("wsMessageEditor");
  assert.equal(proxy.tag, "textarea");
  assert.deepEqual(proxy.attrs, {
    id: "wsMessageEditor", class: "ws-message-editor-hidden", rows: "6", spellcheck: "false",
  });
  const rule = css.match(/\.ws-message-editor-hidden\s*\{([^}]+)\}/);
  assert.ok(rule, "The backing textarea retains its hidden styles");
  assert.match(rule[1], /display:\s*none\s*!important;/);
});

test("the new label reference resolves uniquely without dangling or duplicate IDs", () => {
  const editor = elementById("wsMessageHighlight");
  const references = (editor.attrs["aria-labelledby"] || "").trim().split(/\s+/).filter(Boolean);
  assert.deepEqual(references, ["wsMessageLabel"]);
  for (const id of [...references, "wsMessageHighlight", "wsMessageEditor", "wsSchemeSelect", "wsMessageType"]) {
    const occurrences = [...html.matchAll(new RegExp(`\\bid="${id}"`, "g"))];
    assert.equal(occurrences.length, 1, `${id} must identify exactly one element`);
    elementById(id);
  }
});


// Run only the actual renderer and escaping helper, never app initialization or
// any registered event callback. All queue content below is synthetic.
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function renderSetupQueue(tab) {
  const classes = new Set(["hidden"]);
  const container = { classList: { add: name => classes.add(name), remove: name => classes.delete(name) } };
  const list = { innerHTML: "", querySelectorAll: () => [] };
  const { renderWsSetupQueue } = loadFunctions(["escapeHtml", "renderWsSetupQueue"], {
    document: { getElementById: id => ({ wsSetupQueue: container, wsSetupQueueList: list })[id] },
    getActiveReplayTab: () => tab,
  });
  renderWsSetupQueue();
  return { markup: list.innerHTML, hidden: classes.has("hidden") };
}

function setupControls(markup) {
  return [...markup.matchAll(/<(input|button)\b([^>]*class="ws-setup-(?:check|send)"[^>]*)>(?:([^<]*)<\/button>)?/g)]
    .map(([, tag, attrs, text]) => ({ tag, text, attrs: Object.fromEntries(
      [...attrs.matchAll(/([^\s=\/]+)(?:="([^"]*)")?/g)].map(([, name, value]) => [name, value ?? ""])
    ) }));
}

for (const status of ["disconnected", "connecting", "connected"]) {
  test(`rendered setup queue names actions without changing checked/sent/button state: ${status}`, () => {
    const queue = [
      { label: "Fixture one", autoSend: true, sent: false },
      { label: "Fixture two", autoSend: false, sent: true },
    ];
    const before = JSON.stringify(queue);
    const { markup, hidden } = renderSetupQueue({ type: "websocket", wsStatus: status, wsSetupQueue: queue });
    assert.equal(hidden, false);
    const controls = setupControls(markup);
    assert.equal(controls.length, 4);
    for (let i = 0; i < queue.length; i++) {
      assert.deepEqual(controls[i * 2].attrs, {
        type: "checkbox", class: "ws-setup-check", "data-idx": String(i),
        "aria-label": `Auto-send setup message ${i + 1}`, ...(i === 0 ? { checked: "" } : {}),
      });
      assert.deepEqual(controls[i * 2 + 1], {
        tag: "button", text: "▶", attrs: {
          class: "ws-setup-send", "data-idx": String(i),
          "aria-label": `Send setup message ${i + 1}`, title: "Send this message",
        },
      });
    }
    assert.match(markup, /class="ws-setup-row sent" data-idx="1"/);
    assert.equal((markup.match(/ws-setup-sent-badge/g) || []).length, 1);
    assert.equal(JSON.stringify(queue), before);
  });
}

test("setup queue names follow the displayed ordinal after reorder, removal and addition", () => {
  const first = { label: "Fixture first" };
  const second = { label: "Fixture second" };
  for (const queue of [[first, second], [second, first], [second], [second, first, { label: "Fixture new" }]]) {
    const { markup } = renderSetupQueue({ type: "websocket", wsSetupQueue: queue });
    queue.forEach((item, i) => {
      assert.ok(markup.includes(`<span class="ws-setup-index">#${i + 1}</span>`));
      assert.equal(setupControls(markup)[i * 2].attrs["aria-label"], `Auto-send setup message ${i + 1}`);
      assert.equal(setupControls(markup)[i * 2 + 1].attrs["aria-label"], `Send setup message ${i + 1}`);
    });
  }
});

test("rendered setup labels and notices stay escaped and never enter accessible names", () => {
  const label = '<img src=x onerror="fixture"> & \'quoted\'';
  const { markup } = renderSetupQueue({ type: "websocket", wsSetupQueue: [{ label }], wsSetupNotice: label });
  assert.doesNotMatch(markup, /<img|onerror="fixture"/);
  assert.match(markup, /&lt;img src=x onerror=&quot;fixture&quot;&gt; &amp;/);
  assert.deepEqual(setupControls(markup).map(control => control.attrs["aria-label"]),
    ["Auto-send setup message 1", "Send setup message 1"]);
  assert.equal((markup.match(/&lt;img/g) || []).length, 3);
});

test("empty, notice-only and non-WebSocket setup queues retain visibility behavior", () => {
  assert.equal(renderSetupQueue({ type: "websocket", wsSetupQueue: [] }).hidden, true);
  const notice = renderSetupQueue({ type: "websocket", wsSetupQueue: [], wsSetupNotice: "Fixture notice" });
  assert.equal(notice.hidden, false);
  assert.equal(notice.markup, '<div class="ws-setup-notice">Fixture notice</div>');
  assert.equal(renderSetupQueue({ type: "http", wsSetupQueue: [{ label: "Fixture" }] }).hidden, true);
  assert.equal(renderSetupQueue(null).hidden, true);
});
