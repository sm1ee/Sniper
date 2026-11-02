// Production queue render/selection and read-only detail controllers. Synthetic
// records and DOM only: no app bootstrap, proxy, or mutation endpoint is used.
const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");
const tick = () => new Promise(setImmediate);
const modes = {
  request: { queue: "intercepts", selected: "selectedInterceptId", record: "selectedInterceptRecord", seed: "interceptEditorSeedId",
    render: "renderIntercepts", load: "loadIntercepts", body: "interceptTableBody", table: "interceptRequestTable", editor: "interceptRequestEditor", key: "interceptReq" },
  response: { queue: "responseIntercepts", selected: "selectedResponseInterceptId", record: "selectedResponseInterceptRecord", seed: "responseInterceptEditorSeedId",
    render: "renderResponseIntercepts", load: "loadResponseIntercepts", body: "responseInterceptTableBody", table: "responseInterceptTable", editor: "interceptResponseEditor", key: "interceptRes" },
};
const record = id => ({ id, host: "example.com", scheme: "https", path: `/${id}`, method: "GET", status: 200,
  started_at: "2026-01-01", peer_addr: "127.0.0.1:1",
  request: { scheme: "https", host: "example.com", path: `/${id}`, method: "GET", headers: [], body: "", body_encoding: "utf8" },
  response: { status: 200, headers: [], body: id, body_encoding: "utf8" } });

function fixture(mode, cm = true) {
  const document = { activeElement: null }, requests = [], errors = [], mutations = [], views = new Map();
  class HTMLElement {
    constructor(tagName = "DIV") {
      this.tagName = tagName; this.dataset = {}; this.value = ""; this.innerHTML = ""; this.textWrites = 0; this._text = "";
      this.attributes = {}; this.listeners = {}; this.classes = new Set(); this.rows = [];
      this.clientHeight = 100; this.clientTop = 0; this.scrollTop = 0; this.scrollLeft = 17;
      this.classList = { contains: name => this.classes.has(name), toggle: (name, on) => on ? this.classes.add(name) : this.classes.delete(name) };
    }
    addEventListener(type, fn) { this.listeners[type] = fn; }
    set textContent(value) { this.textWrites++; this._text = value; }
    get textContent() { return this._text; }
    setAttribute(name, value) { this.attributes[name] = value; }
    getAttribute(name) { return this.attributes[name]; }
    getClientRects() { return this.classes.has("hidden") ? [] : [1]; }
    getBoundingClientRect() { return this.rect || { top: 0, bottom: this.clientHeight, height: this.clientHeight }; }
    closest() { return null; }
    focus() { document.activeElement = this; this.listeners.focus?.({ target: this }); }
    click() { this.listeners.click?.({ target: this }); }
    querySelectorAll() {
      this.rows = [...this.innerHTML.matchAll(/<tr class="history-row ([^"]*)" data-id="([^"]+)"/g)].map(([, selected, id]) => {
        const row = new HTMLElement("TR"); row.dataset.id = id;
        if (selected.includes("selected")) row.classes.add("selected");
        row.getBoundingClientRect = () => ({ top: 30 + this.rows.indexOf(row) * 30 - els.interceptQueueShell.scrollTop,
          bottom: 60 + this.rows.indexOf(row) * 30 - els.interceptQueueShell.scrollTop });
        return row;
      });
      return this.rows;
    }
    querySelector(selector) { assert.equal(selector, ".history-row.selected"); return this.rows.find(row => row.classes.has("selected")) || null; }
  }
  const els = {};
  for (const name of ["interceptQueueShell", "interceptQueueSelectionStatus", "interceptTableBody", "responseInterceptTableBody",
    "interceptDetailTitle", "interceptMeta", "forwardInterceptButton", "dropInterceptButton",
    "forwardResponseInterceptButton", "dropResponseInterceptButton", "interceptRequestEditor", "interceptResponseEditor",
    "interceptQueueTabRequest", "interceptQueueTabResponse", "interceptRequestTable", "responseInterceptTable",
    "interceptRequestEditorPanel", "interceptResponseEditorPanel", "interceptRequestActions", "responseInterceptActions",
    "interceptSearchInput", "interceptSearchMeta"]) els[name] = new HTMLElement();
  for (const name of ["interceptRequestTable", "responseInterceptTable"]) els[name].tHead = { getBoundingClientRect: () => ({ height: 30 }) };
  if (cm) { els.interceptRequestCM = new HTMLElement(); els.interceptResponseCM = new HTMLElement(); }
  const state = { activeTool: "proxy", activeProxyTab: "intercept", activeSession: { id: "session-a" }, interceptQueueTab: mode,
    intercepts: [record("request-a"), record("request-b"), record("request-c")],
    responseIntercepts: [record("response-a"), record("response-b"), record("response-c")], runtime: { intercept_enabled: true } };
  const forbidden = name => () => { mutations.push(name); assert.fail(`Unexpected ${name}`); };
  const c = loadFunctions([
    "onInterceptQueueKeydown", "getInterceptDraftRecovery", "captureInterceptDraftRecoveryOwners", "handleInterceptDraftReadFailure", "takeInterceptDraftRecovery",
    "selectInterceptQueueItem", "getInterceptDetailRead", "updateInterceptDetailFeedback", "retrySelectedInterceptDetail", "updateInterceptQueueSelectionStatus", "scrollSelectedInterceptRowIntoView",
    "tableArrowStep", "isEditableTarget", "loadIntercepts", "loadInterceptDetail", "loadResponseIntercepts", "loadResponseInterceptDetail",
    "renderIntercepts", "renderResponseIntercepts", "getVisibleRequestInterceptSummaries", "getVisibleResponseInterceptSummaries",
    "reconcileRequestInterceptSelection", "reconcileResponseInterceptSelection", "refreshInterceptDetailsForCurrentSelection",
    "applyInterceptScopeFilterLocally", "switchInterceptQueueTab", "updateInterceptQueueBadges", "activeInterceptCMKey",
    "updateInterceptSearch", "setInterceptPaneContent", "buildEditableRawRequest", "buildEditableRawResponse", "normalizedHeaders",
    "mergeHeaders", "headerNameEquals", "currentSessionId", "sessionQueryPath", "jsonArray",
  ], { state, els, document, HTMLElement, URLSearchParams, TextEncoder, workspaceStateGeneration: 0,
    console: { ...console, error: error => errors.push(error) }, modal: null,
    getActiveModalAction() { return c.modal; }, isInScopeHost: host => host === "example.com",
    getCMView: key => views.get(key), buildSearchMeta: () => "", escapeHtml: String, formatTimestamp: String,
    updateCodePaneCM(key, _container, text) {
      if (!views.has(key)) views.set(key, { text: "", getContent() { return this.text; }, applySearch: () => ({ matchCount: 0 }), view: { state: { doc: { lines: 1 } } } });
      views.get(key).text = text; return { lineCount: 1, matchCount: 0 };
    }, renderInterceptRequestHighlight() {}, renderInterceptResponseHighlight() {},
    requireOkResponse: async response => assert.equal(response.ok, true),
    fetch(url, options) {
      assert.equal(options, undefined, "Queue navigation only performs detail/list reads");
      assert.match(url, /^\/api\/(?:response-)?intercepts(?:\/[\w-]+)?\?session_id=session-[ab]$/);
      let resolve; const promise = new Promise(yes => resolve = yes); requests.push({ url, resolve }); return promise;
    }, forwardSelectedIntercept: forbidden("Forward"), dropSelectedIntercept: forbidden("Drop"),
    forwardSelectedResponseIntercept: forbidden("response Forward"), dropSelectedResponseIntercept: forbidden("response Drop"),
    scheduleWorkspaceStateSave: forbidden("workspace write"), toggleIntercept: forbidden("runtime mutation"),
  });
  const binding = appSource.match(/^  els\.interceptQueueShell\?\.addEventListener\("keydown", onInterceptQueueKeydown\);$/m);
  assert.ok(binding, "The production shell installs the local keyboard handler"); vm.runInContext(binding[0], c);
  const focusBinding = appSource.match(/^  els\.interceptQueueShell\?\.addEventListener\("focus", [^\n]+$/m);
  assert.ok(focusBinding, "Entering the queue reveals its current selection"); vm.runInContext(focusBinding[0], c);
  c.renderIntercepts(); c.renderResponseIntercepts();
  const config = modes[mode];
  const respond = (index, payload) => requests[index].resolve({ ok: true, json: async () => payload });
  const key = (key, options = {}, target = els.interceptQueueShell) => {
    const event = { key, target, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, ...options };
    els.interceptQueueShell.listeners.keydown(event); return event;
  };
  const prime = () => {
    for (const queue of ["request", "response"]) { const m = modes[queue]; state[m.record] = state[m.queue][0]; c[m.render](); }
    c.switchInterceptQueueTab(mode); els.interceptQueueShell.focus();
  };
  const content = () => cm ? views.get(config.key)?.text : els[config.editor].value;
  const edit = text => { if (cm) views.get(config.key).text = text; else els[config.editor].value = text; };
  return { c, state, els, config, document, requests, errors, mutations, respond, key, prime, content, edit, HTMLElement };
}

test("one labelled, described Tab entry stays outside replaceable queue rows", () => {
  const html = fs.readFileSync(require.resolve("../web/index.html"), "utf8");
  const shell = html.match(/<div[^>]+id="interceptQueueShell"[^>]*>/)?.[0]; assert.ok(shell);
  assert.match(shell, /tabindex="0"/); assert.match(shell, /role="group"/); assert.match(shell, /aria-label="Request Queue"/);
  assert.match(shell, /aria-describedby="interceptQueueInstructions interceptQueueSelectionStatus"/);
  assert.match(html, /id="interceptQueueSelectionStatus"[^>]*role="status"[^>]*aria-live="polite"/);
  const css = fs.readFileSync(require.resolve("../web/styles.css"), "utf8");
  assert.match(css, /#interceptQueueShell:focus-visible\s*\{[^}]*outline:/);
});

for (const mode of Object.keys(modes)) {
  test(`${mode}: local arrows select rows with stable shell focus and zero mutation callbacks`, async () => {
    const f = fixture(mode); f.prime(); const m = f.config;
    assert.equal(f.key("ArrowDown").defaultPrevented, true); assert.equal(f.state[m.selected], `${mode}-b`);
    assert.equal(f.document.activeElement, f.els.interceptQueueShell); assert.equal(f.requests.length, 1);
    assert.match(f.els.interceptQueueSelectionStatus.textContent, /2 of 3.*GET.*example\.com/);
    f.respond(0, record(`${mode}-b`)); await tick();
    assert.match(f.content(), new RegExp(`${mode}-b`)); assert.equal(f.document.activeElement, f.els.interceptQueueShell);
    f.key("ArrowUp"); assert.equal(f.state[m.selected], `${mode}-a`); f.respond(1, record(`${mode}-a`)); await tick();
    assert.equal(f.requests.length, 2); assert.deepEqual(f.mutations, []); assert.deepEqual(f.errors, []);
  });
  test(`${mode}: focus entry reveals selection; missing selection starts at the matching edge`, () => {
    for (const [key, id] of [["ArrowDown", `${mode}-a`], ["ArrowUp", `${mode}-c`]]) {
      const f = fixture(mode); f.prime(); f.els.interceptQueueShell.scrollTop = 60;
      f.els.interceptQueueShell.focus(); assert.equal(f.els.interceptQueueShell.scrollTop, 0);
      assert.equal(f.requests.length, 0); assert.equal(f.els.interceptQueueShell.scrollLeft, 17);
      f.state[f.config.selected] = "removed"; f.key(key);
      assert.equal(f.state[f.config.selected], id); assert.equal(f.requests.length, 1);
    }
  });
  for (const cm of [true, false]) test(`${mode} ${cm ? "CM" : "fallback"}: boundary, queue refresh and tab switch preserve draft and focus`, async () => {
    const f = fixture(mode, cm); f.prime(); f.edit("local draft");
    f.key("ArrowUp"); assert.equal(f.requests.length, 0); assert.equal(f.content(), "local draft");
    const before = f.els.interceptQueueSelectionStatus.textContent, announcements = f.els.interceptQueueSelectionStatus.textWrites;
    const poll = f.c[f.config.load](); f.respond(0, f.state[f.config.queue]); await tick();
    f.respond(1, record(`${mode}-a`)); await poll;
    assert.equal(f.content(), "local draft"); assert.equal(f.document.activeElement, f.els.interceptQueueShell);
    assert.equal(f.els.interceptQueueSelectionStatus.textContent, before);
    assert.equal(f.els.interceptQueueSelectionStatus.textWrites, announcements, "identical polls do not repeat the live announcement");
    f.c.switchInterceptQueueTab(mode === "request" ? "response" : "request"); f.c.switchInterceptQueueTab(mode);
    assert.equal(f.content(), "local draft"); assert.equal(f.document.activeElement, f.els.interceptQueueShell);
    f.state[f.config.selected] = `${mode}-c`; f.state[f.config.record] = record(`${mode}-c`); f.c[f.config.render]();
    const reads = f.requests.length; f.key("ArrowDown"); assert.equal(f.requests.length, reads);
  });
  test(`${mode}: empty and filtered queues only select visible rows`, async () => {
    const f = fixture(mode); f.prime(); const m = f.config;
    f.state[m.queue][1].host = "outside.example.com"; f.state.interceptInScopeOnly = true;
    f.c[m.render](); f.key("ArrowDown"); assert.equal(f.state[m.selected], `${mode}-c`);
    assert.match(f.els.interceptQueueSelectionStatus.textContent, /2 of 2/);
    f.respond(0, record(`${mode}-c`)); await tick();
    f.state[m.queue] = []; f.c[m.render]();
    const reads = f.requests.length; f.key("ArrowDown"); f.key("ArrowUp");
    assert.equal(f.state[m.selected], null); assert.equal(f.requests.length, reads);
    assert.match(f.els.interceptQueueSelectionStatus.textContent, /queue is empty/i);
  });
  test(`${mode}: late hidden detail/queue refresh cannot relabel, scroll or navigate the visible queue`, async () => {
    const f = fixture(mode); f.prime(); f.key("ArrowDown");
    const other = mode === "request" ? "response" : "request", m = modes[other];
    f.c.switchInterceptQueueTab(other); const label = f.els.interceptQueueShell.getAttribute("aria-label");
    const status = f.els.interceptQueueSelectionStatus.textContent, scroll = f.els.interceptQueueShell.scrollTop;
    f.respond(0, record(`${mode}-b`)); await tick();
    const poll = f.c[f.config.load](); f.respond(1, f.state[f.config.queue]); await tick(); f.respond(2, record(`${mode}-b`)); await poll;
    assert.equal(f.els.interceptQueueShell.getAttribute("aria-label"), label);
    assert.equal(f.els.interceptQueueSelectionStatus.textContent, status); assert.equal(f.els.interceptQueueShell.scrollTop, scroll);
    f.key("ArrowDown"); assert.equal(f.state[m.selected], `${other}-b`); assert.equal(f.state[f.config.selected], `${mode}-b`);
    f.respond(3, record(`${other}-b`)); await tick(); assert.equal(f.document.activeElement, f.els.interceptQueueShell);
  });
  test(`${mode}: repeated keys keep latest read owner and edge does not restart pending read`, async () => {
    const f = fixture(mode); f.prime(); f.key("ArrowDown"); f.key("ArrowDown"); f.key("ArrowDown");
    assert.equal(f.requests.length, 2); f.respond(1, record(`${mode}-c`)); await tick(); f.respond(0, record(`${mode}-b`)); await tick();
    assert.equal(f.state[f.config.selected], `${mode}-c`); assert.match(f.content(), new RegExp(`${mode}-c`));
    assert.equal(f.els.interceptQueueShell.scrollTop, 20); assert.equal(f.els.interceptQueueShell.scrollLeft, 17);
    f.key("ArrowUp"); f.key("ArrowUp"); assert.equal(f.els.interceptQueueShell.scrollTop, 0, "first row clears the sticky header");
  });
  test(`${mode}: pointer selection shares the same detail path`, async () => {
    const f = fixture(mode); f.prime(); f.els[f.config.body].rows[1].click();
    assert.equal(f.state[f.config.selected], `${mode}-b`); assert.equal(f.requests.length, 1);
    f.respond(0, record(`${mode}-b`)); await tick(); assert.match(f.content(), new RegExp(`${mode}-b`));
  });
  test(`${mode}: explicit same-row pointer retry still reads without replacing its draft`, async () => {
    const f = fixture(mode); f.prime(); f.edit("local draft"); f.els[f.config.body].rows[0].click();
    assert.equal(f.requests.length, 1); f.respond(0, record(`${mode}-a`)); await tick();
    assert.equal(f.content(), "local draft");
    f.state[f.config.record] = null; f.c[f.config.render](); f.els[f.config.body].rows[0].click();
    assert.equal(f.requests.length, 2); f.respond(1, record(`${mode}-a`)); await tick();
    assert.match(f.content(), new RegExp(`${mode}-a`));
  });
  test(`${mode}: an open queue context menu owns arrows even when shell focus remains`, () => {
    const f = fixture(mode); f.prime(); f.els.interceptContextMenu = new f.HTMLElement();
    assert.equal(f.key("ArrowDown").defaultPrevented, false); assert.equal(f.key("ArrowUp").defaultPrevented, false);
    assert.equal(f.state[f.config.selected], `${mode}-a`); assert.equal(f.requests.length, 0);
    f.els.interceptContextMenu.classes.add("hidden"); f.key("ArrowDown");
    assert.equal(f.state[f.config.selected], `${mode}-b`); assert.equal(f.requests.length, 1);
  });
  test(`${mode}: a pending keyboard detail read cannot overwrite a newer session`, async () => {
    const f = fixture(mode); f.prime(); f.key("ArrowDown");
    f.state.activeSession = { id: "session-b" }; f.state[f.config.queue] = [record("new-session")];
    f.state[f.config.selected] = "new-session"; f.state[f.config.record] = record("new-session"); f.state[f.config.seed] = null;
    f.c[f.config.render](); const content = f.content(), status = f.els.interceptQueueSelectionStatus.textContent;
    f.respond(0, record(`${mode}-b`)); await tick();
    assert.equal(f.content(), content); assert.equal(f.els.interceptQueueSelectionStatus.textContent, status);
    assert.equal(f.state[f.config.selected], "new-session"); assert.equal(f.document.activeElement, f.els.interceptQueueShell);
  });
}

test("queue keys exclude modifiers, composition, consumed events, editors, modals, hidden tools and incidental focus", () => {
  const f = fixture("request"); f.prime();
  for (const key of ["ArrowUp", "ArrowDown"]) {
    for (const flag of ["metaKey", "ctrlKey", "altKey", "shiftKey", "isComposing"]) assert.equal(f.key(key, { [flag]: true }).defaultPrevented, false);
    assert.equal(f.key(key, { defaultPrevented: true }).defaultPrevented, true);
    for (const tag of ["INPUT", "TEXTAREA", "BUTTON", "SELECT", "DIV"]) {
      const target = new f.HTMLElement(tag); target.isContentEditable = tag === "DIV";
      assert.equal(f.key(key, {}, target).defaultPrevented, false);
    }
    f.c.modal = {}; assert.equal(f.key(key).defaultPrevented, false); f.c.modal = null;
    f.state.activeProxyTab = "http-history"; assert.equal(f.key(key).defaultPrevented, false); f.state.activeProxyTab = "intercept";
    f.state.activeTool = "dashboard"; assert.equal(f.key(key).defaultPrevented, false); f.state.activeTool = "proxy";
    f.els.interceptQueueShell.classes.add("hidden"); assert.equal(f.key(key).defaultPrevented, false); f.els.interceptQueueShell.classes.delete("hidden");
    f.document.activeElement = new f.HTMLElement(); assert.equal(f.key(key).defaultPrevented, false); f.els.interceptQueueShell.focus();
  }
  for (const key of ["Enter", " ", "Tab", "Escape"]) assert.equal(f.key(key).defaultPrevented, false);
  assert.equal(f.requests.length, 0); assert.deepEqual(f.mutations, []);
});

// Rule editor controls: production local delegates only. Every mutation is a
// counter stub; no real action body, bootstrap, browser or network is evaluated.
function ruleControlsFixture() {
  const counts = { save: 0, delete: 0, toggle: 0 }, listeners = {};
  const document = { activeElement: null, getElementById: () => list };
  const row = { dataset: { ruleId: 'rule-a' }, writes: 0, fields: {},
    querySelector(selector) { return this.fields[selector.match(/data-field="([^"]+)"/)?.[1]] || null; },
    set innerHTML(value) {
      this.html = value; this.writes++; this.fields = {};
      for (const field of ['scope', 'method_filter', 'host_pattern', 'path_pattern']) {
        this.fields[field] = control(field === 'scope' ? 'SELECT' : 'INPUT', { field });
      }
    }, get innerHTML() { return this.html; } };
  function control(tagName, dataset = {}) {
    return { tagName, type: tagName === 'INPUT' ? 'text' : 'button', dataset, value: '',
      focus() { document.activeElement = this; },
      closest(selector) {
        if (selector === '[data-rule-id]') return row;
        for (const [attribute, key] of [['delete', 'ruleDelete'], ['save', 'ruleSave'], ['edit', 'ruleEdit'], ['toggle', 'ruleToggle']]) {
          if (selector === `[data-rule-${attribute}]`) return this.dataset[key] ? this : null;
        }
        return selector.split(', ').includes(tagName.toLowerCase()) ? this : null;
      } };
  }
  const list = { html: '', addEventListener: (name, fn) => listeners[name] = fn,
    querySelector: () => row, set innerHTML(value) { this.html = value; }, get innerHTML() { return this.html; } };
  const c = loadFunctions(['renderInterceptRules', 'editInterceptRule'], {
    document, state: { interceptRules: [{ id: 'rule-a', enabled: true, scope: 'request', host_pattern: 'example.com', path_pattern: '/api', method_filter: ['GET'] }] },
    escapeHtml: String, fetch() { assert.fail('Network forbidden'); },
    saveInterceptRuleFromRow: async () => { counts.save++; },
    deleteInterceptRule: async () => { counts.delete++; },
    toggleInterceptRuleEnabled: async () => { counts.toggle++; },
    addInterceptRule() { assert.fail('Add forbidden'); }, handleInterceptRuleError(error) { throw error; },
  });
  const start = appSource.indexOf('  document.getElementById("interceptRulesList").addEventListener("click"');
  const end = appSource.indexOf('  if (els.refreshWebsocketsButton)', start);
  assert.ok(start > 0 && end > start); vm.runInContext(appSource.slice(start, end), c);
  const click = target => listeners.click({ target });
  const key = (target, options = {}) => { const event = { target, key: 'Enter', defaultPrevented: false,
    preventDefault() { this.defaultPrevented = true; }, ...options }; listeners.keydown(event); return event; };
  return { c, counts, row, list, document, control, click, key, listeners };
}

test('Intercept rule native Edit opens locally with scope focus and descriptive control names', () => {
  const f = ruleControlsFixture(); f.c.renderInterceptRules();
  assert.match(f.list.innerHTML, /type="button" data-rule-edit="rule-a" aria-label="Edit intercept rule 1"/);
  assert.match(f.list.innerHTML, /aria-label="Enable intercept rule 1"/);
  const edit = f.control('BUTTON', { ruleEdit: 'rule-a' });
  for (const key of ['Enter', ' ']) {
    const before = f.row.writes;
    assert.equal(f.key(edit, { key }).defaultPrevented, false);
    assert.equal(f.row.writes, before);
    // Explicit native-activation simulation: a real browser is not used here.
    f.click(edit); assert.equal(f.row.writes, before + 1);
    assert.equal(f.document.activeElement, f.row.fields.scope);
  }
  for (const label of ['Enable', 'Direction for', 'Methods for', 'Host pattern for', 'Path contains for', 'Save', 'Delete']) {
    assert.ok(f.row.innerHTML.includes(`aria-label="${label} intercept rule 1"`));
  }
  assert.deepEqual(f.counts, { save: 0, delete: 0, toggle: 0 });
});

test('Intercept rule plain text Enter is one save; native controls and guarded events never double-dispatch', () => {
  const f = ruleControlsFixture(); f.c.editInterceptRule('rule-a');
  for (const field of ['method_filter', 'host_pattern', 'path_pattern']) {
    assert.equal(f.key(f.row.fields[field]).defaultPrevented, true);
  }
  assert.equal(f.counts.save, 3); f.counts.save = 0;
  for (const options of [{ key: ' ' }, { repeat: true }, { isComposing: true }, { keyCode: 229 },
    { defaultPrevented: true }, { metaKey: true }, { ctrlKey: true }, { altKey: true }, { shiftKey: true }]) {
    const event = f.key(f.row.fields.host_pattern, options);
    assert.equal(event.defaultPrevented, !!options.defaultPrevented);
  }
  const detached = f.control('INPUT', { field: 'host_pattern' }); f.key(detached);
  const checkbox = f.control('INPUT', { ruleToggle: 'rule-a' }); checkbox.type = 'checkbox';
  for (const target of [f.row.fields.scope, checkbox, f.control('BUTTON', { ruleEdit: 'rule-a' })]) {
    assert.equal(f.key(target).defaultPrevented, false);
  }
  for (const [action, data] of [['save', 'ruleSave'], ['delete', 'ruleDelete']]) {
    const button = f.control('BUTTON', { [data]: 'rule-a' });
    for (const key of ['Enter', ' ']) {
      const before = f.counts[action];
      assert.equal(f.key(button, { key }).defaultPrevented, false);
      assert.equal(f.counts[action], before);
      f.click(button); assert.equal(f.counts[action], before + 1);
    }
  }
  assert.deepEqual(f.counts, { save: 2, delete: 2, toggle: 0 });
});

test('Intercept rule editor select, label and padding preserve drafts; summary click still opens', () => {
  const f = ruleControlsFixture(); const summary = f.control('SPAN');
  const label = f.control('LABEL'); f.click(label); assert.equal(f.row.writes, 0);
  f.click(summary); assert.equal(f.row.writes, 1); assert.equal(f.document.activeElement, null);
  f.row.fields.host_pattern.value = 'draft.example.com'; const fields = f.row.fields;
  for (const target of [fields.scope, fields.host_pattern, label, summary, f.control('DIV')]) f.click(target);
  f.listeners.change({ target: fields.scope });
  assert.equal(f.row.writes, 1); assert.equal(f.row.fields, fields);
  assert.equal(fields.host_pattern.value, 'draft.example.com');
  const toggle = f.control('INPUT', { ruleToggle: 'rule-a' }); toggle.type = 'checkbox';
  f.click(toggle); f.listeners.change({ target: toggle });
  assert.equal(f.row.writes, 1); assert.equal(fields.host_pattern.value, 'draft.example.com');
  assert.deepEqual(f.counts, { save: 0, delete: 0, toggle: 1 });
});

test('Inactive intercept rules dim summary text, not editable fields or native actions', () => {
  const css = fs.readFileSync(require('node:path').join(__dirname, '../web/styles.css'), 'utf8');
  assert.doesNotMatch(css, /\.intercept-rule-row\.disabled\s*\{/);
  const rule = css.match(/(\.intercept-rule-row\.disabled[^{}]+)\{\s*opacity:\s*0\.45;\s*\}/);
  assert.ok(rule, 'Inactive summary styling remains available');
  assert.deepEqual(rule[1].trim().split(/,\s*/), ['scope', 'methods', 'host', 'path'].map(name => `.intercept-rule-row.disabled > .intercept-rule-${name}`));
});
