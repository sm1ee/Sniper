const test = require("node:test");
const assert = require("node:assert/strict");
const tcp = require("../web/tcp-capture.js");
const tick = () => new Promise(resolve => setImmediate(resolve));

function fixture() {
  const nodes = new Map(), requests = [], sent = [];
  function node() {
    return { value: "", checked: false, children: [], dataset: {}, listeners: {}, textContent: "", disabled: false, hidden: false, attributes: {},
      classList: { toggle() {} }, setAttribute(k, v) { this.attributes[k] = v; }, addEventListener(e, f) { this.listeners[e] = f; },
      append(...n) { this.children.push(...n); }, replaceChildren(...n) { this.children = [...n]; } };
  }
  const document = { getElementById(id) { if (!nodes.has(id)) nodes.set(id, node()); return nodes.get(id); }, createElement: node };
  const controller = tcp.createReplayController({
    document, sessionId: () => "a", writePath: (p, s) => p + "?session_id=" + s + "&expected_active_session_id=" + s,
    request(path, options) {
      let resolve; const promise = new Promise(r => resolve = r);
      requests.push({ path, options, resolve(data, status = 200) { resolve({ ok: status === 200, status, json: async () => data, text: async () => typeof data === "string" ? data : JSON.stringify(data) }); } });
      return promise;
    },
    onSent: record => sent.push(record)
  });
  const get = id => document.getElementById(id);
  const editors = () => get("tcpReplayMessages").children.map(block => block.children[0]);
  return { controller, requests, sent, get, editors };
}
const chunk = (sequence, direction, offset, text) => ({ sequence, direction, offset, data_base64: Buffer.from(text).toString("base64") });
const record = { id: "c1", target: "db.example.com:5432", status: "closed", server_tls: true,
  chunks: [chunk(0, "client_to_server", 0, "one"), chunk(1, "server_to_client", 0, "ack"), chunk(2, "client_to_server", 3, "two")] };

test("Replay starts from the connection: its target, its TLS, and each client read as a message", () => {
  const f = fixture();
  f.controller.load(record);
  assert.equal(f.get("tcpReplayHost").value, "db.example.com");
  assert.equal(f.get("tcpReplayPort").value, "5432");
  assert.equal(f.get("tcpReplayTls").checked, true);
  assert.deepEqual(f.editors().map(editor => editor.value), ["6f 6e 65", "74 77 6f"]);
  f.get("tcpReplayTextMode").listeners.click();
  assert.deepEqual(f.editors().map(editor => editor.value), ["one", "two"]);
  f.controller.load({ ...record, target: "[::1]:9000", server_tls: false });
  assert.equal(f.get("tcpReplayHost").value, "::1");
  assert.equal(f.get("tcpReplayTls").checked, false);
});

test("Send posts the edited messages to the target and hands back the new connection", async () => {
  const f = fixture();
  f.controller.load(record);
  f.get("tcpReplayTextMode").listeners.click();
  f.editors()[1].value = "TWO\\r\n"; f.editors()[1].listeners.input();
  f.get("tcpReplayWait").value = "300";
  f.get("tcpReplaySend").listeners.click();
  f.get("tcpReplaySend").listeners.click();
  assert.equal(f.requests.length, 1, "one send at a time");
  assert.match(f.requests[0].path, /^\/api\/tcp\/replay\?session_id=a&expected_active_session_id=a$/);
  assert.deepEqual(JSON.parse(f.requests[0].options.body), {
    target_host: "db.example.com", target_port: 5432, tls: true, wait_ms: 300, from: "c1",
    messages: [Buffer.from("one").toString("base64"), Buffer.from("TWO\r\n").toString("base64")]
  });
  f.requests[0].resolve({ id: "r1", source: "replay" }); await tick();
  assert.deepEqual(f.sent, [{ id: "r1", source: "replay" }]);
  assert.equal(f.get("tcpReplaySend").disabled, false);
});

test("messages can be added and removed, and one that does not parse stops the send", async () => {
  const f = fixture();
  f.controller.load(record);
  f.get("tcpReplayAdd").listeners.click();
  assert.equal(f.editors().length, 3);
  f.get("tcpReplayMessages").listeners.click({ target: { closest: selector => selector === "[data-replay-remove]" ? { dataset: { replayRemove: "0" } } : null } });
  assert.deepEqual(f.editors().map(editor => editor.value), ["74 77 6f", ""]);
  f.get("tcpReplaySend").listeners.click();
  assert.equal(f.requests.length, 0);
  assert.match(f.get("tcpReplayError").textContent, /Message 2/);
  f.editors()[1].value = "zz"; f.editors()[1].listeners.input();
  f.get("tcpReplaySend").listeners.click();
  assert.equal(f.requests.length, 0);
  f.editors()[1].value = "41"; f.editors()[1].listeners.input();
  f.get("tcpReplaySend").listeners.click();
  assert.equal(f.requests.length, 1);
  f.requests[0].resolve("TCP history is full. Clear it to replay.", 409); await tick();
  assert.equal(f.get("tcpReplayError").textContent, "TCP history is full. Clear it to replay.");
});
