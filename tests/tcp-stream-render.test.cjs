const test = require("node:test");
const assert = require("node:assert/strict");
const tcp = require(process.env.TCP_CAPTURE_MODULE || "../web/tcp-capture.js");
const C = "client_to_server", S = "server_to_client";
const chunk = (direction, offset, bytes) => ({ direction, offset, data_base64: Buffer.from(bytes).toString("base64") });
const record = () => ({ id: "x", target: "example.com:9000", status: "open", client_bytes: 2, server_bytes: 0, chunks: [chunk(C, 0, [65, 66])] });
function fixture(initial = record(), intercept = false) {
  const nodes = new Map();
  function node() {
    let value = "";
    return { value: "", children: [], dataset: {}, listeners: {}, writes: 0,
      get textContent() { return value; }, set textContent(next) { value = next; this.writes++; },
      classList: { toggle() {} }, setAttribute() {}, addEventListener(e, fn) { this.listeners[e] = fn; },
      append(...n) { this.children.push(...n); }, replaceChildren() { this.children = []; }, querySelectorAll() { return []; } };
  }
  // The bytes each chunk of the stream shows, joined; the head line is apart.
  const bytes = () => get("tcpStreamBytes").children.map(block => block.children[1].textContent).join("\n");
  const get = id => { if (!nodes.has(id)) nodes.set(id, node()); return nodes.get(id); };
  const document = { getElementById: get, createElement: node };
  let session = "a", detail = initial, pending = [];
  get("tcpDirection").value = C;
  const controller = tcp.createController({ document, sessionId: () => session, readPath: p => p, writePath: p => p, openSettings() {}, intercept,
    request: async path => ({ ok: true, json: async () => structuredClone(path.endsWith("/intercept") ? { enabled: true, direction: "both", revision: 1, pending_count: pending.length } : path.endsWith("/pending") ? { items: pending } : path.endsWith("/status") ? { enabled: false, history_count: 1, history_limit: 256 } : path.endsWith("/connections") ? [{ ...detail, chunks: undefined }] : detail) }) });
  return { get, bytes, controller, pending(next) { pending = next; }, set(next) { detail = next; }, session(next) { session = next; }, direction(next) { get("tcpDirection").value = next; get("tcpDirection").listeners.change(); }, mode(next) { get(next === "hex" ? "tcpHexView" : "tcpTextView").listeners.click(); } };
}
test("metadata and opposite direction polls do not decode or replace selected bytes", async () => {
  const f = fixture(), data = record(); let decodes = 0;
  const atob = global.atob; global.atob = value => { decodes++; return atob(value); };
  try {
    await f.controller.select("x");
    const writes = f.get("tcpStreamBytes").writes;
    for (let i = 0; i < 5; i++) {
      data.client_bytes++; data.server_bytes++; data.chunks.push(chunk(S, i, [i]));
      data.pending_count = i; data.capture_truncated = true;
      f.set(data); await f.controller.refresh();
    }
    assert.equal(decodes, 1); assert.equal(f.get("tcpStreamBytes").writes, writes);
    assert.match(f.get("tcpStreamMeta").textContent, /Partial capture/);
    data.status = "closed"; data.durable = true; f.set(data); await f.controller.refresh();
    assert.equal(decodes, 1); assert.equal(f.get("tcpStreamBytes").writes, writes);
    assert.doesNotMatch(f.get("tcpStreamMeta").textContent, /Not saved/);
  } finally { global.atob = atob; }
});
test("equal-length byte replacements and changed offsets invalidate exact snapshots", async () => {
  const f = fixture(); await f.controller.select("x");
  const data = record(); data.chunks[0] = chunk(C, 0, [67, 68]); f.set(data); await f.controller.refresh();
  assert.match(f.bytes(), /43 44/);
  data.chunks[0].offset = 1; f.set(data); await f.controller.refresh();
  assert.equal(f.bytes(), ""); assert.match(f.get("tcpStreamMeta").textContent, /Missing bytes/);
  data.chunks[0].offset = 0; f.set(data); await f.controller.refresh();
  assert.match(f.bytes(), /43 44/);
  data.chunks[0].data_base64 = "!"; f.set(data); await f.controller.refresh();
  assert.equal(f.bytes(), "");
  data.chunks = [chunk(C, 0, [69, 70])]; f.set(data); await f.controller.refresh();
  assert.match(f.bytes(), /45 46/);
});
test("direction, mode, empty capture, connection selection and session reset invalidate the view", async () => {
  const f = fixture(); await f.controller.select("x");
  f.mode("text"); assert.equal(f.bytes(), "AB");
  f.direction(S); assert.match(f.get("tcpStreamBytes").textContent, /No bytes captured/);
  f.direction(C); assert.equal(f.bytes(), "AB");
  f.mode("hex"); assert.match(f.bytes(), /41 42/);
  f.set({ ...record(), id: "y", chunks: [chunk(C, 0, [71])] }); await f.controller.select("y");
  assert.match(f.bytes(), /47/);
  f.session("b"); f.controller.reset(); assert.equal(f.get("tcpStreamBytes").textContent, "Select a connection.");
  f.set({ ...record(), id: "y", chunks: [chunk(C, 0, [72])] }); await f.controller.select("y");
  assert.match(f.bytes(), /48/);
});
test("Pending updates remain live while cached captured bytes are untouched", async () => {
  const f = fixture(record(), true); await f.controller.select("x");
  await new Promise(resolve => setImmediate(resolve));
  f.get("tcpPendingTab").listeners.click();
  const before = f.get("tcpStreamBytes").writes;
  f.pending([{ pending_id: "p1", sequence: 1, revision: 0, direction: S, original_base64: "AP8=", original_length: 2, state: "pending" }]);
  f.set({ ...record(), pending_count: 1 }); await f.controller.refresh();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.get("tcpStreamBytes").writes, before);
  assert.equal(f.get("tcpPendingHex").value, "00 ff");
  assert.equal(f.get("tcpForward").textContent, "Forward to client");
  assert.equal(f.get("tcpForward").disabled, false);
  assert.equal(f.get("tcpStreamSurface").hidden, true);
  assert.equal(f.get("tcpPendingSurface").hidden, false);
  f.get("tcpPendingHex").value = "aa bb"; f.get("tcpPendingHex").listeners.input();
  f.set({ ...record(), client_bytes: 3, pending_count: 1 }); await f.controller.refresh();
  assert.equal(f.get("tcpPendingHex").value, "aa bb");
  assert.equal(f.get("tcpStreamBytes").writes, before);
});
test("oversized snapshot inputs are not retained in the cache", async () => {
  const data = record(); data.chunks = Array.from({ length: 1025 }, () => chunk(C, 0, []));
  const f = fixture(data); let decodes = 0;
  const atob = global.atob; global.atob = value => { decodes++; return atob(value); };
  try {
    await f.controller.select("x"); data.client_bytes++; f.set(data); await f.controller.refresh();
    assert.equal(decodes, 2050);
    assert.match(f.get("tcpStreamBytes").textContent, /No bytes captured/);
    data.chunks = [chunk(C, 0, Buffer.alloc(1100 * 1024))]; f.set(data); await f.controller.refresh();
    assert.match(f.get("tcpStreamMeta").textContent, /too large/);
    const before = decodes; data.client_bytes++; f.set(data); await f.controller.refresh();
    assert.equal(decodes, before + 1, "oversized encoded bytes must not be retained as a snapshot");
  } finally { global.atob = atob; }
});
test("malformed chunk collections clear stale bytes and recover without a cached view", async () => {
  const f = fixture(); await f.controller.select("x");
  for (const chunks of [{ invalid: true }, [null], "invalid"]) {
    f.set({ ...record(), chunks }); await f.controller.refresh();
    assert.equal(f.bytes(), "");
    assert.match(f.get("tcpStreamMeta").textContent, /malformed/);
    f.set(record()); await f.controller.refresh();
    assert.match(f.bytes(), /41 42/);
  }
});
test("stream render benchmark", { skip: !process.env.TCP_RENDER_BENCH }, async () => {
  const data = record(); data.chunks = Array.from({ length: 1024 }, (_, i) => chunk(C, i * 256, Buffer.alloc(256, i % 256)));
  const f = fixture(data); await f.controller.select("x");
  const before = f.get("tcpStreamBytes").writes, times = [];
  for (let i = 0; i < 12; i++) {
    data.client_bytes++; f.set(data);
    const start = performance.now(); await f.controller.refresh(); times.push(performance.now() - start);
  }
  console.log(JSON.stringify({ benchmark: "256KiB/1024 chunks, metadata-only polling", samples_ms: times, average_ms: times.reduce((a,b) => a+b, 0) / times.length, stream_dom_writes: f.get("tcpStreamBytes").writes - before, output_chars: f.get("tcpStreamBytes").textContent.length }));
});
