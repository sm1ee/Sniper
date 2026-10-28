// Exercise production session/workspace adoption and Findings reset functions.
// Responses and timers are in memory; no app bootstrap, server, or traffic.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const tick = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const response = data => ({ ok: true, json: async () => data });
const record = { id: "record-a", host: "example.com", path: "/finding" };
const finding = { id: "finding-a", record_id: record.id, title: "Old finding",
  category: "header", severity: "low", host: "example.com", path: "/finding" };

function element({ textContent = "", innerHTML = "", value = "", classes = [] } = {}) {
  const names = new Set(classes);
  return {
    disabled: false, dataset: {}, listeners: {}, classes: names, textContent, innerHTML, value,
    classList: {
      add: (...values) => values.forEach(value => names.add(value)),
      remove: (...values) => values.forEach(value => names.delete(value)),
      contains: value => names.has(value),
      toggle(value, force = !names.has(value)) {
        if (force) names.add(value); else names.delete(value);
        return force;
      },
    },
    addEventListener(name, callback) { this.listeners[name] = callback; },
    click() { if (!this.disabled) this.listeners.click?.({}); },
    querySelectorAll: () => [],
  };
}

function fixture() {
  const reads = [], opens = [], errors = [], warnings = [], actions = [], timers = new Map();
  let timerSequence = 0;
  const setTimer = callback => { timers.set(++timerSequence, callback); return timerSequence; };
  const clearTimer = id => timers.delete(id);
  const state = {
    activeSession: { id: "session-a", name: "A", active: true }, sessions: [],
    activeTool: "proxy", activeProxyTab: "findings", settings: { max_entries: 100 },
    runtime: { intercept_scope_only: true }, _findingsEntries: [finding],
    replayTabs: [{ id: "prepared-replay", requestText: "GET /prepared HTTP/1.1\r\nHost: example.com\r\n\r\n" }],
    activeReplayTabId: "prepared-replay", replayTabSequence: 1,
    fuzzerBaseRequest: { host: "example.com", path: "/prepared-fuzzer" },
    fuzzerSourceTransactionId: "prepared-record", fuzzerRequestText: "GET /prepared-fuzzer HTTP/1.1",
    fuzzerPayloadsText: "prepared payload", fuzzerNotice: "Prepared draft",
    fuzzerDraftVersion: 7, fuzzerRunToken: 3,
  };
  const buttons = { findingsDetailSendReplay: element(), findingsDetailSendFuzzer: element() };
  const selectedRow = element({ classes: ["selected"] });
  const els = {
    findingsDetailJump: element(), findingsBody: element({ innerHTML: "<tr>Old finding</tr>" }),
    findingsDetailContent: element(), findingsDetailPlaceholder: element({ classes: ["hidden"] }),
    findingsDetailTitle: element({ textContent: finding.title }),
    findingsDetailCategory: element({ textContent: finding.category }),
    findingsDetailDesc: element({ textContent: "Old description" }),
    findingsReqView: element({ innerHTML: "GET /finding HTTP/1.1" }),
    findingsResView: element({ innerHTML: "HTTP/1.1 200 OK" }),
    findingsReqSearchInput: element({ value: "request match" }),
    findingsResSearchInput: element({ value: "response match" }),
    findingsReqSearchMeta: element({ innerHTML: "Old request highlights" }),
    findingsResSearchMeta: element({ innerHTML: "Old response highlights" }),
    findingsBadge: element({ textContent: "1" }),
  };
  els.findingsDetailJump.dataset.recordId = record.id;
  els.findingsBody.querySelector = selector =>
    selector === ".history-row.selected" && selectedRow.classes.has("selected") ? selectedRow : null;
  for (const name of ["proxyAddr", "uiAddr", "settingsSpecialHostHttp",
    "certificateName", "certificateExpiry", "certificatePemPath", "certificateDerPath",
    "specialHostHttps", "dataDir", "certificateNote"]) els[name] = element();
  const interceptPill = element();
  const c = loadFunctions([
    "applyWorkspaceState", "readFuzzerWorkspace", "applyFuzzerWorkspace", "workspaceSnapshotMatchesActiveSession", "_applySettings", "loadSessions",
    "currentSessionId", "sessionQueryPath", "transactionPath",
    "runFindingAction", "sendFindingToReplay", "sendFindingToFuzzer", "openFuzzerFromRecordLoader",
    "retireFindingActionProgress", "invalidateFindingNavigation", "setActiveTool",
    "onClickWithProgress", "withButtonProgress", "requireOkResponse", "readApiErrorMessage",
    "formatStructuredApiErrorMessage", "resetFindingsUiState", "clearFindingDetail",
    "setFindingDetailActionsEnabled", "renderFindingDetailLoading", "updateFindingsSelection",
    "resetFindingsSearchUi", "clearSearchHighlights", "buildSearchMeta", "titleCase",
    "renderFindings", "getFilteredFindings", "updateCategoryFilter", "updateFindingsBadge",
    "retainedEntriesCap", "formatCappedCount", "loadFindings", "fetchFindingsCount",
    "commitFindingsBadgeCount", "loadFindingDetail",
  ], {
    state, els, console: { warn: (...args) => warnings.push(args), error: (...args) => errors.push(args) },
    document: { getElementById: id => buttons[id] || (id === "interceptInScopeToggle" ? interceptPill : null) },
    window: { setTimeout: setTimer, clearTimeout: clearTimer }, setTimeout: setTimer, clearTimeout: clearTimer,
    workspaceLoaded: true, workspaceStateGeneration: 4, workspaceSaveCommittedSnapshot: null,
    sessionsLoadGeneration: 0, sessionsAppliedLoadGeneration: 0,
    selectedFindingId: finding.id, findingsDetailGeneration: 2, findingActionPending: null,
    findingsStateGeneration: 5, findingsLoadGeneration: 6, findingsData: [finding],
    findingsBadgeCount: 1, findingsLoadPromise: null, findingsLoadSessionId: null,
    findingsCountReadGeneration: 0, findingsCountAcceptedGeneration: 0, findingsEventEpoch: 0,
    findingsBadgeRefreshTimer: setTimer(() => {}), findingsListRefreshTimer: setTimer(() => {}),
    lastFindingsBadgePollAt: 123, findingsSortKey: "found_at", findingsSortDir: "desc",
    BUTTON_PROGRESS_DELAY_MS: 180, FINDINGS_LIST_LIMIT: 5000,
    fetch(url) { const read = { url, ...deferred() }; reads.push(read); return read.promise; },
    openTransactionRecordInReplay(value) { opens.push(["replay", value.id]); c.setActiveTool("replay"); },
    openFuzzerFromRecord(value) { opens.push(["fuzzer", value.id]); c.setActiveTool("fuzzer"); },
    handleFindingActionError: error => errors.push(error.message),
    showFindingDetail: () => assert.fail("an old detail read must not render after session adoption"),
    sanitizeActiveTool: value => value, getCMView: () => null,
    normalizeFuzzerTargetOverride: () => null, normalizeFuzzerAttackRecord: () => null,
    fuzzerWorkspaceAttackRecordId: () => null, setFuzzerAttackRecord() {},
    snapshotWorkspaceState: () => ({}), cloneWorkspaceSnapshotForBaseline: value => value,
    jsonArray: value => Array.isArray(value) ? value : [],
    formatSize: value => `${value} B`, formatTimestamp: value => value, escapeHtml: value => value,
    scheduleUiSettingsSave() {}, closeScannerSettings() {}, syncHttpCapturePill() {},
    updateProxyStatusIndicator() {}, updateRemoteUiIndicator() {},
    renderInterceptStatus() {}, renderProxySettings() {}, renderDashboard() {},
  });
  for (const name of ["sendFindingToReplay", "sendFindingToFuzzer"]) {
    const production = c[name];
    c[name] = (...args) => {
      const pending = production(...args);
      actions.push(pending);
      return pending;
    };
  }
  const bindStart = appSource.indexOf("  const findingsReplayBtn =", appSource.indexOf("function bindFindingsEvents()"));
  const bindEnd = appSource.indexOf("  if (els.findingsRescanButton)", bindStart);
  assert.ok(bindStart > 0 && bindEnd > bindStart);
  vm.runInContext(appSource.slice(bindStart, bindEnd), c);
  const control = kind => buttons[kind === "replay" ? "findingsDetailSendReplay" : "findingsDetailSendFuzzer"];
  function begin(kind) {
    const before = actions.length;
    control(kind).click();
    return actions.length > before ? actions.at(-1) : undefined;
  }
  function showProgress(kind) {
    const progress = control(kind)._buttonProgress;
    assert.ok(progress);
    timers.get(progress.reveal)();
    assert.equal(control(kind).classes.has("is-working-shown"), true);
  }
  return { c, state, els, buttons, selectedRow, reads, opens, errors, warnings, actions, timers,
    control, begin, showProgress };
}

function settings(id) {
  return {
    active_session: id ? { id, name: id, active: true } : null,
    runtime: { intercept_scope_only: true }, proxy_addr: "example.com:8080",
    ui_addr: "example.com:8000", body_preview_bytes: 1024, max_entries: 100,
    certificate: { common_name: "Synthetic CA", expires_at: "2030-01-01T00:00:00Z",
      special_host_http: "http://example.com", special_host_https: "https://example.com",
      pem_path: "/synthetic/ca.pem", der_path: "/synthetic/ca.der" },
    data_dir: "/synthetic/session", proxy_online: false, remote_ui_exposed: false,
  };
}

async function adoptSession(f, source, id, options = {}) {
  if (source === "settings") return f.c._applySettings(response(settings(id)));
  const pending = f.c.loadSessions(options);
  const read = f.reads.at(-1);
  assert.equal(read.url, "/api/sessions");
  read.resolve(response(id ? [{ id, name: id, active: true }] : []));
  return pending;
}

function workspace(id = "session-a") {
  return { session_id: id, revision: 12, replay: { tabs: [] },
    fuzzer: { request_text: "GET /saved HTTP/1.1\r\nHost: example.com\r\n\r\n",
      payloads_text: "saved payload", notice: "Saved draft" } };
}

function drafts(f) {
  const keys = ["replayTabs", "activeReplayTabId", "replayTabSequence", "fuzzerBaseRequest",
    "fuzzerSourceTransactionId", "fuzzerRequestText", "fuzzerPayloadsText", "fuzzerNotice",
    "fuzzerDraftVersion", "fuzzerRunToken"];
  return Object.fromEntries(keys.map(key => [key, f.state[key]]));
}

function assertDraftsRetained(f, before) {
  for (const [key, value] of Object.entries(before)) assert.equal(f.state[key], value, key);
}

function assertCleared(f) {
  assert.equal(f.c.selectedFindingId, null);
  assert.equal(f.c.findingsData.length, 0);
  assert.equal(f.state._findingsEntries.length, 0);
  assert.equal(f.c.findingsBadgeCount, 0);
  assert.equal(f.c.findingsLoadPromise, null);
  assert.equal(f.c.findingsLoadSessionId, null);
  assert.equal(f.c.findingsBadgeRefreshTimer, 0);
  assert.equal(f.c.findingsListRefreshTimer, 0);
  assert.equal(f.c.lastFindingsBadgePollAt, 0);
  assert.equal(f.els.findingsDetailJump.dataset.recordId, undefined);
  assert.equal(f.selectedRow.classes.has("selected"), false);
  assert.match(f.els.findingsBody.innerHTML, /No findings yet/);
  assert.equal(f.els.findingsDetailContent.classes.has("hidden"), true);
  assert.equal(f.els.findingsDetailPlaceholder.classes.has("hidden"), false);
  for (const name of ["findingsDetailTitle", "findingsDetailCategory", "findingsDetailDesc",
    "findingsBadge"]) assert.equal(f.els[name].textContent, "", name);
  for (const name of ["findingsReqView", "findingsResView"]) assert.equal(f.els[name].innerHTML, "", name);
  for (const side of ["Req", "Res"]) {
    assert.equal(f.els[`findings${side}SearchInput`].value, "");
    assert.equal(f.els[`findings${side}SearchMeta`].innerHTML, "0 lines");
  }
  assert.equal(f.els.findingsBadge.classes.has("hidden"), true);
  for (const button of [f.els.findingsDetailJump, ...Object.values(f.buttons)]) {
    assert.equal(button.disabled, true);
    assert.equal(button.classes.has("is-working"), false);
    assert.equal(button.classes.has("is-working-shown"), false);
    assert.equal(button._buttonProgress, undefined);
  }
}

async function pauseRead(read, stage) {
  if (stage === "fetch") return read;
  const body = deferred();
  read.resolve({ ok: true, json: () => body.promise });
  await tick();
  return body;
}

function completeRead(read, stage, outcome, data = record) {
  if (outcome === "failure") read.reject(new Error("Obsolete request failed."));
  else read.resolve(stage === "json" ? data : response(data));
}

for (const kind of ["replay", "fuzzer"]) {
  for (const stage of ["fetch", "json"]) {
    for (const outcome of ["success", "failure"]) {
      test(`${kind} accepted workspace retires ${stage} progress before old ${outcome} and permits retry`, async () => {
        const f = fixture(), pending = f.begin(kind);
        f.showProgress(kind);
        const oldRead = await pauseRead(f.reads[0], stage);
        f.c.applyWorkspaceState(workspace());
        assert.equal(f.c.workspaceStateGeneration, 5);
        assert.equal(f.control(kind).disabled, false);
        assert.equal(f.control(kind).classes.size, 0);
        assert.equal(f.c.selectedFindingId, finding.id);
        assert.equal(f.c.findingsData[0], finding);
        assert.equal(f.els.findingsDetailJump.dataset.recordId, record.id);
        assert.equal(f.state.replayTabs.length, 0, "accepted snapshots still replace workspace drafts");
        assert.equal(f.state.fuzzerRequestText, workspace().fuzzer.request_text);
        assert.equal(f.state.fuzzerPayloadsText, "saved payload");
        const savedDrafts = drafts(f), retry = f.begin(kind);
        assert.equal(f.reads.length, 2);
        f.showProgress(kind);
        completeRead(oldRead, stage, outcome);
        assert.equal(await pending, false);
        await tick();
        assert.equal(f.control(kind).disabled, true, "old completion cannot retire retry progress");
        assert.equal(f.control(kind).classes.has("is-working-shown"), true);
        assertDraftsRetained(f, savedDrafts);
        f.reads[1].resolve(response(record));
        assert.equal(await retry, true);
        await tick();
        assert.equal(f.control(kind).disabled, false);
        assert.equal(f.control(kind).classes.size, 0);
        assert.deepEqual(f.opens, [[kind, record.id]]);
        assert.deepEqual(f.errors, []);
      });

      for (const source of ["settings", "sessions"]) {
        test(`${kind} ${source} session change clears UI before old ${stage} ${outcome}`, async () => {
          const f = fixture(), before = drafts(f), pending = f.begin(kind);
          f.showProgress(kind);
          const oldRead = await pauseRead(f.reads[0], stage);
          await adoptSession(f, source, "session-b");
          assert.equal(f.c.currentSessionId(), "session-b");
          assert.equal(f.c.findingsStateGeneration, 6);
          assert.equal(f.c.workspaceStateGeneration, 4, "session list/settings alone do not replace workspace drafts");
          assertCleared(f);
          assertDraftsRetained(f, before);
          completeRead(oldRead, stage, outcome);
          assert.equal(await pending, false);
          await tick();
          assertCleared(f);
          assertDraftsRetained(f, before);
          assert.deepEqual(f.opens, []);
          assert.deepEqual(f.errors, []);
          assert.equal(f.timers.size, 0);
          assert.equal(f.begin(kind), undefined, "cleared detail cannot send the previous record again");
        });
      }
    }
  }

  for (const boundary of ["wrong-workspace", "same-settings", "same-sessions", "preserved-workspace"]) {
    for (const outcome of ["success", "failure"]) {
      test(`${kind} ${boundary} preserves the current mouse action through ${outcome}`, async () => {
        const f = fixture(), before = drafts(f), pending = f.begin(kind);
        f.showProgress(kind);
        const owner = f.c.findingActionPending, progress = f.control(kind)._buttonProgress;
        if (boundary === "wrong-workspace") f.c.applyWorkspaceState(workspace("session-b"));
        else if (boundary === "same-settings") await adoptSession(f, "settings", "session-a");
        else await adoptSession(f, "sessions", boundary === "preserved-workspace" ? "session-b" : "session-a",
          { preserveWorkspaceOwner: boundary === "preserved-workspace" });
        assert.equal(f.c.currentSessionId(), "session-a");
        assert.equal(f.c.workspaceStateGeneration, 4);
        assert.equal(f.c.findingsStateGeneration, 5);
        assert.equal(f.c.findingActionPending, owner);
        assert.equal(owner.isCurrent(), true);
        assert.equal(f.control(kind)._buttonProgress, progress);
        assert.equal(f.control(kind).disabled, true);
        assert.equal(f.control(kind).classes.has("is-working-shown"), true);
        assert.equal(f.c.selectedFindingId, finding.id);
        assert.equal(f.c.findingsData[0], finding);
        assert.equal(f.els.findingsDetailTitle.textContent, finding.title);
        assert.equal(f.els.findingsDetailJump.dataset.recordId, record.id);
        assert.equal(f.begin(kind), undefined, "preserved ownership keeps the mouse duplicate guard");
        assertDraftsRetained(f, before);
        if (boundary === "preserved-workspace") assert.equal(f.state.sessions[0].id, "session-b");
        if (boundary === "wrong-workspace") assert.equal(f.warnings.length, 1);
        if (outcome === "success") {
          f.reads[0].resolve(response(record));
          assert.equal(await pending, true);
        } else {
          f.reads[0].reject(new Error("Current request failed."));
          await assert.rejects(pending, /Current request failed/);
        }
        await tick();
        assert.equal(f.control(kind).disabled, false);
        assert.equal(f.control(kind).classes.size, 0);
        assert.deepEqual(f.opens, outcome === "success" ? [[kind, record.id]] : []);
        assert.deepEqual(f.errors, outcome === "success" ? [] : ["Current request failed."]);
        assertDraftsRetained(f, before);
      });
    }
  }

  for (const source of ["settings", "sessions"]) {
    test(`${kind} actual ${source} session A-B-A cannot revive the old action`, async () => {
      const f = fixture(), pending = f.begin(kind), before = drafts(f);
      await adoptSession(f, source, "session-b");
      await adoptSession(f, source, "session-a");
      f.reads[0].resolve(response(record));
      assert.equal(await pending, false);
      await tick();
      assert.equal(f.c.currentSessionId(), "session-a");
      assert.equal(f.c.findingsStateGeneration, 7);
      assertCleared(f);
      assertDraftsRetained(f, before);
      assert.deepEqual(f.opens, []);
      assert.deepEqual(f.errors, []);
    });
  }

  for (const detail of ["closed", "loading"]) {
    test(`${kind} accepted workspace does not enable a ${detail} detail`, async () => {
      const f = fixture(), pending = f.begin(kind);
      if (detail === "closed") f.c.clearFindingDetail();
      else f.c.renderFindingDetailLoading();
      f.c.applyWorkspaceState(workspace());
      assert.equal(f.control(kind).disabled, true);
      assert.equal(f.control(kind).classes.size, 0);
      f.reads[0].resolve(response(record));
      assert.equal(await pending, false);
      await tick();
      assert.equal(f.control(kind).disabled, true);
      assert.deepEqual(f.opens, []);
      assert.deepEqual(f.errors, []);
    });
  }
}

for (const source of ["settings", "sessions"]) {
  test(`${source} removal of the active session also clears existing Findings`, async () => {
    const f = fixture(), before = drafts(f);
    await adoptSession(f, source, null);
    assert.equal(f.c.currentSessionId(), null);
    assertCleared(f);
    assertDraftsRetained(f, before);
  });

  for (const stage of ["fetch", "json"]) {
    for (const outcome of ["success", "failure"]) {
      test(`${source} session A-B-A rejects old Findings list, count and detail ${stage} ${outcome}`, async () => {
        const f = fixture(), before = drafts(f);
        const list = f.c.loadFindings(), detail = f.c.loadFindingDetail(finding.id);
        assert.deepEqual(f.reads.map(read => read.url), [
          "/api/findings/count?session_id=session-a",
          "/api/findings?limit=5000&session_id=session-a",
          "/api/findings/finding-a?session_id=session-a",
        ]);
        const oldReads = await Promise.all(f.reads.map(read => pauseRead(read, stage)));
        await adoptSession(f, source, "session-b");
        await adoptSession(f, source, "session-a");
        assertCleared(f);
        const values = [{ count: 37 }, [finding], finding];
        oldReads.forEach((read, index) => completeRead(read, stage, outcome, values[index]));
        await Promise.all([list, detail]);
        await tick();
        assertCleared(f);
        assertDraftsRetained(f, before);
        assert.equal(f.reads.some(read => read.url.startsWith("/api/transactions")), false);
        assert.deepEqual(f.errors, []);
      });
    }
  }
}
