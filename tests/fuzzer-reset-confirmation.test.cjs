// Actual header binding, local confirmation and initialized draft adoption only.
// No app startup, native dialogs, persistence, Start or network execution.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");
const plain = value => JSON.parse(JSON.stringify(value));
const raw = "GET /synthetic?q=§draft§ HTTP/1.1\nHost: example.com\n\n";
const base = () => ({ scheme: "https", host: "example.com", method: "GET", path: "/original",
  headers: [{ name: "Host", value: "example.com" }], body: "", body_encoding: "utf8", preview_truncated: false });
function fixture(kind = "manual") {
  const state = { activeSession: { id: "session-a" }, fuzzerRequestText: raw, fuzzerPayloadsText: "alpha\nbeta",
    fuzzerBaseRequest: kind === "manual" ? null : kind === "scheme-only" ? { ...base(), scheme: "http", host: "", path: "/", headers: [] } : base(),
    fuzzerSourceTransactionId: kind === "imported" ? "synthetic-source" : null,
    fuzzerTarget: kind === "imported" ? { scheme: "https", host: "connect.example.com", port: "8443" } : null,
    fuzzerTargetRequestText: kind === "imported" ? "https://example.com" : null,
    fuzzerAttackType: "battering_ram", fuzzerUrlEncode: false, fuzzerConcurrency: 9,
    fuzzerDraftVersion: 3, fuzzerRunToken: 5, fuzzerRunning: false, fuzzerRunningAttackId: null,
    fuzzerAttackRecord: null, fuzzerAttackRecordId: null, _selectedFuzzerResultKey: null, _fuzzerDetailRecord: null };
  const handlers = {}, confirmations = [], saves = [], renders = [], toasts = [];
  let visibleRaw = raw, requests = 0;
  const els = { resetFuzzerButton: { addEventListener(type, callback) { handlers[type] = callback; } },
    fuzzerPayloadsEditor: { value: state.fuzzerPayloadsText } };
  const names = ["resetFuzzer", "invalidateFuzzerRun", "updateFuzzerRequestText", "updateFuzzerPayloadsText", "markFuzzerDraftChanged",
    "fuzzerRequestTextForAction", "fuzzerResultsWorkflowState", "currentSessionId", "buildEditableRawRequest", "normalizedHeaders", "mergeHeaders", "headerNameEquals",
    "setFuzzerAttackRecord", "clearFuzzerAttackRecord", "normalizeFuzzerAttackRecord", "jsonArray", "hideFuzzerDetailPanel", "cancelPendingFuzzerComparison",
    "applyFuzzerWorkspace", "snapshotFuzzerWorkspace", "cloneEditableRequest", "workspaceSnapshotValueChanged", "finishFuzzerOptionChange"];
  if (appSource.includes("function confirmFuzzerReset(")) names.push("confirmFuzzerReset");
  const c = loadFunctions(names, {
    state, els, workspaceLoaded: true, workspaceStateGeneration: 7,
    _fuzzerAttackLoadGeneration: 2, _fuzzerDetailGeneration: 4, compareLoadGeneration: 0,
    getCMView: () => ({ getContent: () => visibleRaw }), document: { getElementById: () => null },
    showConfirmDialog(message, confirm, options) { confirmations.push({ message, confirm, options }); },
    showToast(message, tone) { toasts.push({ message, tone }); },
    scheduleWorkspaceStateSave() { saves.push(plain(state)); }, scheduleFuzzerSetupRender() {}, renderFuzzerSetup() {},
    renderFuzzer() { visibleRaw = state.fuzzerRequestText.replace(/\r\n?/g, "\n"); els.fuzzerPayloadsEditor.value = state.fuzzerPayloadsText; renders.push(visibleRaw); },
    normalizeFuzzerTargetOverride: value => value || null, normalizeFuzzerTargetAuthority: value => value || null,
    hydrateFuzzerAttackRecordById() { assert.fail("Unexpected saved-run read"); },
    fetch() { requests++; assert.fail("Reset must not perform an API request"); },
  });
  c.fuzzerResultsWorkflowState().runs = [{ id: "saved-run", status: "completed" }];
  state.fuzzerResultsWorkflow.selectedRunId = "saved-run";
  const binding = appSource.match(/^  els\.resetFuzzerButton\.addEventListener\("click", (?:confirmFuzzerReset|resetFuzzer)\);$/m)?.[0];
  assert.ok(binding); vm.runInContext(binding, c);
  return { c, state, els, confirmations, saves, renders, toasts,
    click() { return handlers.click(); }, confirm() { assert.equal(confirmations.length, 1); return confirmations[0].confirm(); },
    draft(text = raw + "new") { visibleRaw = text; c.updateFuzzerRequestText(text, { userEdit: true }); },
    payload(text) { els.fuzzerPayloadsEditor.value = text; c.updateFuzzerPayloadsText(text, { userEdit: true }); },
    visible(text) { visibleRaw = text; },
    snapshot() { return JSON.stringify([state, visibleRaw, els.fuzzerPayloadsEditor.value, saves, renders]); },
    expected() { return state.fuzzerBaseRequest ? c.buildEditableRawRequest(state.fuzzerBaseRequest) : ""; },
    adopt(text, payloads = state.fuzzerPayloadsText, notice = "") {
      c.applyFuzzerWorkspace({ fuzzerBaseRequest: state.fuzzerBaseRequest, fuzzerSourceTransactionId: state.fuzzerSourceTransactionId,
        fuzzerTarget: state.fuzzerTarget, fuzzerTargetRequestText: state.fuzzerTargetRequestText,
        fuzzerRequestText: text, fuzzerPayloadsText: payloads, fuzzerNotice: notice,
        fuzzerAttackRecordId: state.fuzzerAttackRecordId, legacyAttackRecord: null }, c.currentSessionId(), { keepShownRun: true });
      c.renderFuzzer();
    },
    get requests() { return requests; },
  };
}
function kept(f) {
  const s = f.state;
  return plain({ base: s.fuzzerBaseRequest, source: s.fuzzerSourceTransactionId, target: s.fuzzerTarget, binding: s.fuzzerTargetRequestText,
    attack: s.fuzzerAttackType, concurrency: s.fuzzerConcurrency, encode: s.fuzzerUrlEncode,
    runs: s.fuzzerResultsWorkflow.runs, selectedRun: s.fuzzerResultsWorkflow.selectedRunId });
}
for (const kind of ["manual", "imported", "scheme-only"]) {
  test(`${kind}: clicking Reset waits without changing draft, editors, results or persistence`, () => {
    const f = fixture(kind); f.c.setFuzzerAttackRecord({ id: "saved-run", results: [] });
    const before = f.snapshot(); f.click();
    assert.equal(f.confirmations.length, 1); assert.equal(f.snapshot(), before);
    // Cancel only dismisses the generic modal; it never calls its confirm callback.
    assert.equal(f.requests, 0);
    assert.equal(f.confirmations[0].options.title, "Reset Fuzzer draft?");
    assert.equal(f.confirmations[0].options.confirmLabel, "Reset draft");
    assert.match(f.confirmations[0].message, /payload list.*current results/s);
    assert.match(f.confirmations[0].message, /overrides.*options.*saved runs/s);
    assert.doesNotMatch(f.confirmations[0].message, /cannot be undone|permanent|delete/i);
  });
  test(`${kind}: current confirmation resets once through the unchanged core and preserves options and saved runs`, () => {
    const f = fixture(kind); f.c.setFuzzerAttackRecord({ id: "saved-run", results: [] });
    f.state._selectedFuzzerResultKey = "tx:old"; f.state._fuzzerDetailRecord = { id: "old" };
    const expected = f.expected(), preserved = kept(f), token = f.state.fuzzerRunToken;
    f.click(); f.confirm();
    assert.equal(f.state.fuzzerRequestText, expected); assert.equal(f.state.fuzzerPayloadsText, "");
    assert.equal(f.els.fuzzerPayloadsEditor.value, ""); assert.equal(f.state.fuzzerAttackRecordId, null);
    assert.equal(f.state._selectedFuzzerResultKey, null); assert.equal(f.state._fuzzerDetailRecord, null);
    assert.equal(f.state.fuzzerRunToken, token + 1); assert.deepEqual(kept(f), preserved);
    assert.equal(f.saves.length, 1); assert.equal(f.requests, 0); assert.equal(f.toasts.length, 0);
    const after = f.snapshot(); f.confirm(); assert.equal(f.snapshot(), after);
  });
}
for (const payload of ["alpha", "\n", "\r\n", "  "]) test(`payload-only ${JSON.stringify(payload)} still requires confirmation`, () => {
  const f = fixture(); f.state.fuzzerRequestText = ""; f.visible(""); f.payload(payload);
  const before = f.snapshot(); f.click(); assert.equal(f.confirmations.length, 1); assert.equal(f.snapshot(), before);
  f.confirm(); assert.equal(f.state.fuzzerPayloadsText, ""); assert.equal(f.saves.length, 1);
});
for (const owner of ["editor", "state"]) test(`nonempty payload ${owner} alone cannot bypass confirmation`, () => {
  const f = fixture(); f.state.fuzzerRequestText = ""; f.visible(""); f.payload("");
  if (owner === "editor") f.els.fuzzerPayloadsEditor.value = "\n";
  else f.state.fuzzerPayloadsText = "\n";
  const before = f.snapshot(); f.click(); assert.equal(f.confirmations.length, 1); assert.equal(f.snapshot(), before);
});
for (const field of ["fuzzerAttackRecord", "fuzzerAttackRecordId", "_selectedFuzzerResultKey", "_fuzzerDetailRecord"]) {
  test(`shown ${field} requires confirmation even with empty draft inputs`, () => {
    const f = fixture(); f.state.fuzzerRequestText = ""; f.visible(""); f.payload("");
    f.state[field] = field.endsWith("Record") ? { id: "shown" } : "shown";
    const before = f.snapshot(); f.click(); assert.equal(f.confirmations.length, 1); assert.equal(f.snapshot(), before);
  });
}
for (const kind of ["manual", "imported"]) test(`${kind}: unchanged request and empty payloads retain direct harmless Reset`, () => {
  const f = fixture(kind); f.state.fuzzerRequestText = f.expected(); f.visible(f.expected()); f.payload("");
  const preserved = kept(f), expected = f.expected(); f.click();
  assert.equal(f.confirmations.length, 0); assert.equal(f.state.fuzzerRequestText, expected);
  assert.deepEqual(kept(f), preserved); assert.equal(f.saves.length, 1); assert.equal(f.requests, 0);
});
for (const when of ["before click", "after prompt"]) for (const guard of ["workspace unavailable", "local run", "restored run"]) {
  test(`${guard} ${when} prevents Reset`, () => {
    const f = fixture(); if (when === "after prompt") f.click();
    if (guard === "workspace unavailable") f.c.workspaceLoaded = false;
    else if (guard === "local run") f.state.fuzzerRunning = true;
    else f.state.fuzzerRunningAttackId = "running";
    const before = f.snapshot(); if (when === "after prompt") f.confirm(); else f.click();
    assert.equal(f.snapshot(), before); assert.equal(f.requests, 0);
    if (when === "before click") assert.equal(f.confirmations.length, 0);
  });
}
const changes = {
  "request edit": f => f.draft(),
  "payload edit": f => f.payload("new payload"),
  "request editor ahead of state": f => f.visible(raw + "unsynced"),
  "payload editor ahead of state": f => { f.els.fuzzerPayloadsEditor.value = "unsynced"; },
  "request state ahead of editor": f => { f.state.fuzzerRequestText += "state"; },
  "payload state ahead of editor": f => { f.state.fuzzerPayloadsText += "state"; },
  "option change": f => { f.state.fuzzerConcurrency = 2; f.c.finishFuzzerOptionChange(true); },
  "new run intent": f => f.c.invalidateFuzzerRun(),
  "different session": f => { f.state.activeSession.id = "session-b"; },
  "workspace reset ABA": f => { f.c.workspaceStateGeneration += 2; },
  "new result view": f => f.c.setFuzzerAttackRecord({ id: "new-view", results: [] }),
  "same-ID newer view": f => f.c.setFuzzerAttackRecord({ id: "saved-run", results: [] }),
  "workflow replacement": f => { f.state.fuzzerResultsWorkflow = { ...f.state.fuzzerResultsWorkflow }; },
  "pending saved view intent": f => { f.state.fuzzerResultsWorkflow.readGeneration++; },
};
for (const [name, change] of Object.entries(changes)) test(`${name} retires an earlier Reset confirmation`, () => {
  const f = fixture(); f.c.setFuzzerAttackRecord({ id: "saved-run", results: [] }); f.click(); change(f);
  const before = f.snapshot(); f.confirm(); assert.equal(f.snapshot(), before); assert.equal(f.requests, 0);
  assert.equal(f.toasts.length, 1); assert.equal(f.toasts[0].tone, "info");
  assert.match(f.toasts[0].message, /Reset canceled.*changed.*try again/);
});
for (const bounce of [false, true]) test(`accepted initialized external draft${bounce ? " A→B→A" : " replacement"} retires Reset without counter changes`, () => {
  const f = fixture(); f.c.setFuzzerAttackRecord({ id: "saved-run", results: [] }); f.click();
  const counters = [f.c.workspaceStateGeneration, f.state.fuzzerDraftVersion, f.state.fuzzerRunToken, f.c._fuzzerAttackLoadGeneration];
  const read = f.state.fuzzerResultsWorkflow.readGeneration;
  f.adopt(raw + "external", "external payload"); if (bounce) f.adopt(raw, "alpha\nbeta");
  assert.deepEqual([f.c.workspaceStateGeneration, f.state.fuzzerDraftVersion, f.state.fuzzerRunToken, f.c._fuzzerAttackLoadGeneration], counters);
  assert.ok(f.state.fuzzerResultsWorkflow.readGeneration > read);
  const before = f.snapshot(); f.confirm(); assert.equal(f.snapshot(), before); assert.equal(f.requests, 0);
});
test("status-only keepShownRun adoption does not invalidate the current draft confirmation", () => {
  const f = fixture(); f.c.setFuzzerAttackRecord({ id: "saved-run", results: [] }); f.click();
  const read = f.state.fuzzerResultsWorkflow.readGeneration;
  f.adopt(raw, "alpha\nbeta", "Updated status"); assert.equal(f.state.fuzzerResultsWorkflow.readGeneration, read);
  f.confirm(); assert.equal(f.state.fuzzerRequestText, ""); assert.equal(f.state.fuzzerPayloadsText, ""); assert.equal(f.saves.length, 1);
});
test("CodeMirror LF display preserves the captured CRLF request identity", () => {
  const f = fixture(); f.state.fuzzerRequestText = raw.replaceAll("\n", "\r\n"); f.visible(raw);
  f.click(); f.visible(raw); f.confirm(); assert.equal(f.state.fuzzerRequestText, ""); assert.equal(f.saves.length, 1);
});
test("a confirmed callback cannot later clear a new draft", () => {
  const f = fixture(); f.click(); f.confirm(); f.draft("GET /new HTTP/1.1\nHost: example.com"); f.payload("new");
  const before = f.snapshot(); f.confirm(); assert.equal(f.snapshot(), before);
});
