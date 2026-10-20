// Synthetic metadata only: no app bootstrap, network, persistence, or actions.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture(names = [], globals = {}) {
  const c = loadFunctions([
    "formatTimestamp", "formatSize", "formatWsFrameSize", "formatStatus", "statusTone", "escapeHtml", ...names,
  ], globals);
  const formatter = appSource.match(/^const HISTORY_TIME_FORMATTER = new Intl\.DateTimeFormat\([^]*?^\}\);/m);
  assert.ok(formatter, "use the app's actual timestamp locale and precision");
  vm.runInContext(formatter[0], c);
  return c;
}

const node = () => ({ textContent: "", innerHTML: "", value: "", querySelector: () => null });

// The API uses chrono DateTime<Utc>. AutoSi serializes fractions with 0, 3, 6,
// or 9 digits. Display intentionally stops at seconds; sorting is separate.
test("timestamp display accepts every server precision and equivalent UTC offsets", () => {
  const c = fixture();
  const expected = c.formatTimestamp("2026-10-19T12:34:56Z");
  assert.notEqual(expected, "-");
  for (const timestamp of [
    "2026-10-19T12:34:56.123Z", "2026-10-19T12:34:56.123456Z",
    "2026-10-19T12:34:56.123456789Z", "2026-10-19T14:34:56+02:00",
    "2026-10-19T07:34:56-05:00",
  ]) assert.equal(c.formatTimestamp(timestamp), expected);
});

test("missing or unparseable timestamp metadata has a neutral fallback", () => {
  const c = fixture();
  for (const value of [undefined, null, "", "invalid timestamp", "2026-99-99T00:00:00Z"])
    assert.equal(c.formatTimestamp(value), "-");
});

test("byte formatters retain their established 1024-based units and rounding", () => {
  const c = fixture();
  for (const [bytes, expected] of [
    [0, "0 B"], [1, "1 B"], [1023, "1023 B"], [1024, "1.0 KB"], [1536, "1.5 KB"],
    [10 * 1024, "10 KB"], [1024 ** 2, "1.0 MB"], [16 * 1024 ** 2, "16 MB"], [1024 ** 3, "1.0 GB"],
  ]) assert.equal(c.formatSize(bytes), expected);
  for (const [bytes, expected] of [[0, "0 B"], [1023, "1023 B"], [1024, "1.0 KB"], [1536, "1.5 KB"], [1024 ** 2, "1024.0 KB"]])
    assert.equal(c.formatWsFrameSize(bytes), expected);
});

test("defensive byte guards do not emit nonfinite labels", () => {
  // NaN/Infinity cannot arrive in valid JSON or the unsigned API fields. These
  // assertions protect existing helper defenses, not a claimed server defect.
  const c = fixture();
  for (const value of [undefined, "unknown", -1, NaN, Infinity, -Infinity]) {
    assert.equal(c.formatSize(value), "0 B");
    assert.equal(c.formatWsFrameSize(value), "");
  }
});

test("history cells use the shared labels and refresh their derived time and size", () => {
  const c = fixture(["prepareHistoryItem", "getHistoryTimeLabel", "renderHistoryCell"], {
    observeAnnotationRevision() {}, inferMimeType: () => "text",
  });
  const item = { started_at: "2026-10-19T12:34:56.123456789Z", request_bytes: 1024, response_bytes: 512, status: null };
  c.prepareHistoryItem(item);
  assert.equal(c.renderHistoryCell("length", item, {}), '<td class="col-center">1.5 KB</td>');
  assert.equal(c.renderHistoryCell("status", item, {}), '<td><span class="status-pill-row none">n/a</span></td>');
  assert.equal(c.renderHistoryCell("started_at", item, {}), `<td>${c.escapeHtml(c.formatTimestamp(item.started_at))}</td>`);
  item.started_at = "2026-10-19T13:34:56Z";
  item.response_bytes = 1024;
  item.status = 204;
  c.prepareHistoryItem(item);
  assert.equal(c.renderHistoryCell("length", item, {}), '<td class="col-center">2.0 KB</td>');
  assert.equal(c.renderHistoryCell("status", item, {}), '<td><span class="status-pill-row ok">204</span></td>');
  assert.equal(c.renderHistoryCell("started_at", item, {}), `<td>${c.escapeHtml(c.formatTimestamp(item.started_at))}</td>`);
});

test("optional decoded body size falls back to wire size while an explicit zero stays zero", () => {
  const c = fixture(["binaryBodyPlaceholder"]);
  for (const decoded_body_size of [undefined, null, 0, 2048]) {
    const msg = Object.freeze({ body_size: 1024, content_type: "application/octet-stream",
      ...(decoded_body_size === undefined ? {} : { decoded_body_size }) });
    const expected = decoded_body_size == null ? "1.0 KB" : decoded_body_size === 0 ? "0 B" : "2.0 KB";
    assert.equal(c.binaryBodyPlaceholder(msg), `[application/octet-stream, ${expected}, base64 preview omitted]`);
  }
});

test("HTTP inspector renders zero duration and a missing response without invalid metadata", () => {
  const els = Object.fromEntries([
    "detailTitle", "detailTags", "attributesCount", "protocolStrip", "summaryList", "requestHeaderCount",
    "responseHeaderCount", "requestHeadersBody", "responseHeadersBody", "notesCard",
  ].map(key => [key, node()]));
  const c = fixture(["renderDetail", "renderSummaryRows", "normalizedHeaders", "renderHeaderList"], {
    els, state: { showOriginal: {} }, cancelHistoryDetailLoading() {}, inferProtocolState: () => ({}),
    renderProtocolStrip: () => "", renderViewTabs() {}, renderMessagePanes() {},
  });
  const record = Object.freeze({
    kind: "http", method: "GET", scheme: "https", host: "example.com", path: "/",
    started_at: "2026-10-19T12:34:56Z", status: null, duration_ms: 0, notes: [],
    request: { headers: [], body_size: 0, content_type: null }, response: null,
  });
  c.renderDetail(record);
  assert.match(els.summaryList.innerHTML, />Duration<[^]*?>0 ms</);
  assert.match(els.summaryList.innerHTML, />Request size<[^]*?>0 B</);
  assert.match(els.summaryList.innerHTML, />Response size<[^]*?>0 B</);
  assert.match(els.summaryList.innerHTML, />MIME type<[^]*?>n\/a</);
  assert.doesNotMatch(els.summaryList.innerHTML, /undefined|NaN|Infinity|Invalid Date/);
});

for (const [closed_at, duration_ms, expected] of [
  [null, null, "live"], ["2026-10-19T12:34:56Z", null, "closed"],
  ["2026-10-19T12:34:56Z", 0, "0 ms"], ["2026-10-19T12:34:56Z", 1250, "1250 ms"],
]) {
  test(`WebSocket history presents optional duration as ${expected}`, () => {
    const session = Object.freeze({ id: "synthetic-session", host: "example.com", path: "/",
      status: null, frame_count: 0, started_at: "2026-10-19T12:34:56Z", closed_at, duration_ms });
    const els = { websocketSearchInput: node(), websocketMeta: node(), websocketTableBody: node() };
    const c = fixture(["renderWebsocketSessionTable"], {
      els, state: { websocketQuery: "", websocketSessions: [session] },
      websocketRenderedSessionWindow: entries => ({ renderedEntries: entries, topPadding: 0, bottomPadding: 0 }),
      scheduleWebsocketQueryBackfill() {}, buildWebsocketFilterSummary: () => "", updateWebsocketSortIndicators() {},
      websocketSessionDisplayNumber: () => 1,
    });
    c.renderWebsocketSessionTable([{ session, index: 0 }]);
    assert.match(els.websocketTableBody.innerHTML, new RegExp(`<td>${expected}</td>`));
    assert.match(els.websocketTableBody.innerHTML, /<td>n\/a<\/td>/);
    assert.doesNotMatch(els.websocketTableBody.innerHTML, /undefined|NaN|Infinity|Invalid Date/);
  });
}

for (const duration_ms of [null, 0, 1250]) {
  test(`saved result table renders nullable duration ${duration_ms} and status without starting work`, () => {
    const result = Object.freeze({ index: 0, payload: "synthetic", transaction_id: null,
      status: null, duration_ms, response_bytes: 0, note: null });
    const body = node();
    const c = fixture(["renderFuzzerResultsVirtual", "jsonArray", "fuzzerSelectionKeyForResult"], {
      visibleFuzzerResults: () => [{ result, sourceIndex: 0 }], renderFuzzerResultsWorkflow() {},
      els: { fuzzerResultsBody: body }, state: { fuzzerAttackRecord: { results: [result] } },
      fuzzerResultsShell: () => ({ clientHeight: 100, scrollTop: 0 }),
      measuredFuzzerResultRowHeight: 27, FUZZER_RESULT_ROW_HEIGHT: 27, FUZZER_RESULT_BUFFER_ROWS: 0,
    });
    c.renderFuzzerResultsVirtual();
    assert.match(body.innerHTML, new RegExp(`<td>${duration_ms == null ? "-" : `${duration_ms} ms`}</td>`));
    assert.match(body.innerHTML, /<td>n\/a<\/td>/);
    assert.match(body.innerHTML, /<td>0 B<\/td>/);
    assert.doesNotMatch(body.innerHTML, /undefined|NaN|Infinity|Invalid Date/);
  });
}
