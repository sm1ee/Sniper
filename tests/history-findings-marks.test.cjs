// HTTP history marks for passive scan findings: built from the Findings list,
// drawn under the operator's own note and colour, and never stored on a record.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions, toggleButton } = require("./frontend-test-helpers.cjs");

const tick = () => new Promise(resolve => setImmediate(resolve));
const finding = (id, record_id, severity, title, side = "response") => ({
  id, record_id, severity, title, category: "header", host: "example.com", path: "/",
  ...(side ? { location: { side, line: 2 } } : {}),
});
const FINDINGS = Object.freeze([
  finding("f-low", "rec-a", "low", "Missing X-Frame-Options", null),
  finding("f-medium", "rec-a", "medium", "Cookie 'sid' missing Secure flag"),
  finding("f-info", "rec-b", "info", "Email address in response"),
]);

function fixture({ show = true, color = "severity", colorTags = [] } = {}) {
  // HTTP's Findings pill and the Findings tab's Mark in HTTP show one setting.
  const pills = { httpFindingsToggle: toggleButton(!show), findingsHistoryToggle: toggleButton(!show) };
  const pill = pills.httpFindingsToggle;
  const reads = [], redraws = { rows: 0, panes: 0, lists: 0 };
  const state = {
    httpShowFindings: show, displaySettings: { findingsColor: color },
    activeSession: { id: "session-a" }, selectedRecord: null,
    query: "", filterSettings: { colorTags: new Set(colorTags) },
  };
  const context = loadFunctions([
    "refreshHistoryFindings", "historyFindingSignature", "historyFindingEvidenceRanges", "loadHistoryFindingEvidence",
    "findingEvidenceRanges", "findingHighlightQueries", "firstUsableFindingQuery", "extractFindingKeywords",
    "forEachCodeSearchMatch", "normalizeFindingLocation", "setToggleButton", "renderHistoryCell",
    "severityClass", "severityLabel", "escapeHtml", "currentSessionId", "sessionQueryPath",
    "summaryMatchesColorTags", "createHistoryQueryState", "buildTransactionsPageUrl",
    "selectedStatusClasses", "selectedMimeTypes",
  ], {
    state, findingsData: FINDINGS, URLSearchParams,
    SEVERITY_ORDER: { critical: 0, high: 1, medium: 2, low: 3, info: 4 },
    historyFindingEvidence: new Map(), historyFindingEvidencePending: new Set(), historyFindingEvidenceSessionId: null,
    document: { getElementById: id => pills[id] || null }, HTTP_HISTORY_PAGE_SIZE: 5000,
    renderHistoryVirtual: () => redraws.rows++, renderMessagePanes: () => redraws.panes++,
    scheduleRefresh: () => redraws.lists++,
    fetch(url) {
      reads.push(url);
      return Promise.resolve({ ok: true, json: async () => ({ evidence: "set-cookie: sid=abc; Path=/" }) });
    },
  });
  vm.runInContext(appSource.match(/^const FINDING_SEVERITY_TONES = .*$/m)[0], context);
  context.refreshHistoryFindings();
  return { context, state, pill, pills, reads, redraws };
}

test("records are marked by their worst finding, in the chosen colour, only while shown", () => {
  const f = fixture();
  assert.equal(f.pill.checked, true);
  assert.equal(f.redraws.rows, 1);
  const a = f.state._historyFindings.get("rec-a");
  assert.deepEqual(Array.from(a.findings, item => item.id), ["f-medium", "f-low"]);
  assert.equal(a.rowClass, " has-finding finding-tone-yellow");
  assert.equal(f.state._historyFindings.get("rec-b").rowClass, " has-finding finding-tone-blue");
  assert.equal(f.state._historyFindings.has("rec-c"), false);

  assert.equal(fixture({ color: "purple" }).state._historyFindings.get("rec-b").rowClass, " has-finding finding-tone-purple");
  assert.equal(fixture({ color: "none" }).state._historyFindings.get("rec-a").rowClass, "");

  const hidden = fixture({ show: false });
  assert.equal(hidden.state._historyFindings, null);
  assert.equal(hidden.pill.checked, false);
  assert.equal(hidden.pills.findingsHistoryToggle.checked, false);
  assert.equal(f.pills.findingsHistoryToggle.checked, true);
});

test("Notes shows the worst finding in an empty cell and only its badge beside the operator's note", () => {
  const f = fixture();
  const empty = f.context.renderHistoryCell("notes", { id: "rec-a" });
  assert.match(empty, /class="severity-badge finding-note-badge severity-medium">Medium<\/span><span class="finding-note">Cookie &#039;sid&#039; missing Secure flag<\/span><span class="note-more">\+1<\/span>/);
  assert.match(empty, /title="Medium: Cookie &#039;sid&#039; missing Secure flag\nLow: Missing X-Frame-Options"/);
  assert.doesNotMatch(empty, /notes-cell-actionable/);

  const noted = f.context.renderHistoryCell("notes", { id: "rec-a", has_user_note: true, note_count: 1, note_preview: "mine" });
  assert.match(noted, /^<td data-col="notes" class="notes-cell-actionable" title="mine\n\nMedium: Cookie/);
  assert.match(noted, /severity-medium">Medium<\/span>.*<span class="note-preview">mine<\/span>/);
  assert.doesNotMatch(noted, /class="finding-note"/);

  // A record without findings renders exactly as before.
  assert.equal(f.context.renderHistoryCell("notes", { id: "rec-c" }), '<td data-col="notes"></td>');
  assert.equal(fixture({ show: false }).context.renderHistoryCell("notes", { id: "rec-a" }), '<td data-col="notes"></td>');
});

test("the open record's evidence is read once and marked on the side the finding names", async () => {
  const f = fixture();
  f.state.selectedRecord = { id: "rec-a" };
  const text = "HTTP/1.1 200 OK\r\nset-cookie: sid=abc; Path=/\r\n\r\n";
  assert.deepEqual(Array.from(f.context.historyFindingEvidenceRanges("rec-a", "response", text, "raw")), []);
  f.context.historyFindingEvidenceRanges("rec-a", "response", text, "raw");
  assert.deepEqual(f.reads, ["/api/findings/f-medium?session_id=session-a"]);
  await tick(); await tick();
  assert.equal(f.redraws.panes, 1);
  const [range] = f.context.historyFindingEvidenceRanges("rec-a", "response", text, "raw");
  assert.equal(text.replace(/\r\n/g, "\n").slice(range.from, range.to), "set-cookie: sid=abc; Path=/");
  assert.deepEqual(Array.from(f.context.historyFindingEvidenceRanges("rec-a", "request", "GET / HTTP/1.1", "raw")), []);
  assert.deepEqual(Array.from(f.context.historyFindingEvidenceRanges("rec-a", "response", text, "hex")), []);
  assert.equal(f.reads.length, 1);
});

test("the colour filter gathers rows by the colour they are drawn in", () => {
  const f = fixture({ colorTags: ["yellow"] });
  const url = () => new URL(f.context.buildTransactionsPageUrl(), "http://example.com").searchParams;
  assert.equal(url().get("color_tags"), "yellow");
  assert.equal(url().get("finding_color"), "severity");
  assert.equal(f.redraws.lists, 1, "a filtered list is read again when its findings change");
  f.context.refreshHistoryFindings();
  assert.equal(f.redraws.lists, 1, "unchanged findings do not reread it");

  const matches = item => f.context.summaryMatchesColorTags(item, f.state.filterSettings);
  assert.equal(matches({ id: "rec-a" }), true);
  assert.equal(matches({ id: "rec-b" }), false);
  assert.equal(matches({ id: "rec-a", color_tag: "blue" }), false, "a colour tag wins over the tint");
  assert.equal(matches({ id: "rec-c", color_tag: "yellow" }), true);

  // Without marks, or with no tint, the server is not asked to count findings.
  assert.equal(fixture({ colorTags: ["yellow"], show: false }).context.createHistoryQueryState().findingColor, "");
  assert.equal(fixture({ colorTags: ["yellow"], color: "none" }).context.createHistoryQueryState().findingColor, "");
  assert.equal(fixture().context.createHistoryQueryState().findingColor, "");
});
