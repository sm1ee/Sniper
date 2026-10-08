// Bundled CLI packaging UI only. Requests and DOM are synthetic; no app,
// shell profile, registry, scanner, or external CLI is started or modified.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const IDS = [
  "cliPathBanner", "cliPathDescription", "cliPathBannerDescription", "cliPathDirectory",
  "installCliPathButton", "refreshCliPathButton", "installCliPathStatus", "cliPathBannerStatus",
  "cliPathAddButton", "cliPathLaterButton", "cliPathDismissButton", "cliPathSettingsButton",
];
const BANNER_IDS = new Set([
  "cliPathAddButton", "cliPathLaterButton", "cliPathDismissButton", "cliPathSettingsButton",
]);
const AVAILABLE = {
  platform: "macos", supported: true, registered: false, can_install: true,
  should_prompt: true, directory: "/fixture/Sniper.app/Contents/MacOS",
  message: "Bundled command-line tool is available.",
};
const SUCCESS = {
  updated: ["fixture profile"], unchanged: [], warnings: [],
  message: "Added to PATH. Open a new terminal and run sniper-cli.",
};
const nextTurn = () => new Promise(resolve => setImmediate(resolve));

function fixture() {
  const document = { activeElement: null, activeModal: null, querySelector() { return this.activeModal; } };
  function element(id) {
    const classes = new Set();
    const listeners = new Map();
    const attrs = new Map();
    return {
      id, classList: {
        add: (...names) => names.forEach(name => classes.add(name)),
        remove: (...names) => names.forEach(name => classes.delete(name)),
        contains: name => classes.has(name),
        toggle(name, force) {
          const add = force === undefined ? !classes.has(name) : force;
          if (add) classes.add(name); else classes.delete(name);
          return add;
        },
      }, attrs, textContent: "", disabled: false,
      addEventListener(name, callback) { listeners.set(name, [...(listeners.get(name) || []), callback]); },
      click() { if (!this.disabled) for (const callback of listeners.get("click") || []) callback({ target: this }); },
      focus() { document.activeElement = this; },
      contains(node) { return id === "cliPathBanner" && BANNER_IDS.has(node?.id); },
      setAttribute(name, value) { attrs.set(name, value); },
      listeners,
    };
  }
  const nodes = Object.fromEntries(IDS.map(id => [id, element(id)]));
  document.getElementById = id => nodes[id] || null;
  const opener = element("settingsOpener");
  document.activeElement = opener;
  const events = new Map();
  const requests = [];
  let settingsOpened = 0;
  const context = loadFunctions([
    "createCliPathState", "bindCliPathControls", "initCliPathOnboarding", "cliPathCanInstall",
    "cliPathDescription", "renderCliPathUi", "validCliPathStatus", "loadCliPathStatus",
    "installCliPath", "deferCliPath", "hideCliPathBanner", "disposeCliPathUi",
    "requireOkResponse", "readApiErrorMessage", "formatStructuredApiErrorMessage",
  ], {
    document, els: { openDisplaySettingsButton: opener }, AbortController,
    window: { addEventListener(name, callback) { events.set(name, [...(events.get(name) || []), callback]); } },
    openDisplaySettingsModal() { settingsOpened += 1; },
    fetch(url, options = {}) {
      return new Promise((resolve, reject) => requests.push({ url, options, resolve, reject }));
    },
  });
  context.cliPathState = context.createCliPathState();
  context.bindCliPathControls();
  const json = (index, body, status = 200) => requests[index].resolve(new Response(JSON.stringify(body), {
    status, headers: { "content-type": "application/json" },
  }));
  async function ready(status = AVAILABLE) {
    context.initCliPathOnboarding();
    await nextTurn();
    json(0, { ...status });
    await nextTurn();
  }
  return {
    context, state: context.cliPathState, nodes, document, requests, json, ready, opener,
    emit(name, event = {}) { for (const callback of events.get(name) || []) callback(event); },
    settingsOpened: () => settingsOpened,
  };
}

function hidden(element) { return element.classList.contains("hidden"); }

test("startup checks once, stays read-only, and offers optional setup without stealing focus", async () => {
  const f = fixture();
  f.context.initCliPathOnboarding();
  f.context.initCliPathOnboarding();
  await nextTurn();
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].url, "/api/cli-path");
  assert.equal(f.requests[0].options.method, undefined);
  assert.equal(f.nodes.installCliPathButton.disabled, true);
  assert.equal(hidden(f.nodes.cliPathBanner), true);
  f.json(0, AVAILABLE);
  await nextTurn();
  assert.equal(hidden(f.nodes.cliPathBanner), false);
  assert.equal(f.nodes.installCliPathButton.disabled, false);
  assert.equal(f.document.activeElement, f.opener);
  assert.match(f.nodes.cliPathBannerDescription.textContent, /optional/i);
  assert.match(f.nodes.cliPathDescription.textContent, /zsh profile.*ZDOTDIR.*existing ~\/\.bash_profile and ~\/\.bashrc/);
  assert.match(f.nodes.cliPathDirectory.textContent, /\/fixture\/Sniper.app/);
  assert.equal(f.requests.length, 1);
});

test("a late first-run read leaves active dialog input and keyboard handling untouched", async () => {
  const f = fixture();
  f.context.initCliPathOnboarding(); await nextTurn();
  const composingInput = { id: "dialog-text-input", value: "unfinished input", isComposing: true };
  f.document.activeElement = composingInput;
  f.document.activeModal = { id: "active-dialog" };
  f.json(0, AVAILABLE); await nextTurn();
  assert.equal(f.document.activeElement, composingInput);
  assert.equal(composingInput.value, "unfinished input");
  assert.equal(composingInput.isComposing, true);
  assert.equal(hidden(f.nodes.cliPathBanner), true);
  assert.equal(f.requests.length, 1);
  assert.equal(f.state.decided, false);
  for (const node of Object.values(f.nodes)) {
    assert.deepEqual([...node.listeners.keys()].filter(type => type !== "click"), []);
  }
});

test("Windows copy describes user PATH rather than shell profiles", async () => {
  const f = fixture();
  await f.ready({ ...AVAILABLE, platform: "windows", directory: "C:\\Fixture\\Sniper" });
  assert.match(f.nodes.cliPathDescription.textContent, /your user PATH/);
  assert.doesNotMatch(f.nodes.cliPathDescription.textContent, /zshrc|bashrc/);
  assert.match(f.nodes.cliPathDescription.textContent, /restart your terminal app/);
});

for (const [name, overrides, installEnabled] of [
  ["registered", { registered: true }, false],
  ["unsupported", { platform: "unsupported", supported: false, can_install: false, directory: null }, false],
  ["missing bundle", { can_install: false, directory: null }, false],
  ["previously deferred", { should_prompt: false }, true],
]) {
  test(`${name} does not trigger first-run prompt`, async () => {
    const f = fixture();
    await f.ready({ ...AVAILABLE, ...overrides });
    assert.equal(hidden(f.nodes.cliPathBanner), true);
    assert.equal(f.nodes.installCliPathButton.disabled, !installEnabled);
    assert.equal(f.requests.length, 1);
  });
}

test("only explicit Add starts installation and duplicate or conflicting choices share a guard", async () => {
  const f = fixture(); await f.ready();
  f.nodes.cliPathAddButton.focus();
  f.nodes.cliPathAddButton.click();
  f.nodes.cliPathAddButton.click();
  await f.context.installCliPath();
  await f.context.deferCliPath();
  await f.context.loadCliPathStatus();
  assert.equal(f.requests.length, 2);
  assert.equal(f.requests[1].url, "/api/cli-path");
  assert.equal(f.requests[1].options.method, "POST");
  assert.equal(f.state.decided, true);
  assert.equal(f.nodes.installCliPathButton.disabled, true);
  assert.equal(f.nodes.cliPathLaterButton.disabled, true);
  assert.equal(f.nodes.refreshCliPathButton.disabled, true);
  assert.equal(f.nodes.cliPathBanner.attrs.get("aria-busy"), "true");
  f.json(1, SUCCESS); await nextTurn();
  assert.equal(f.nodes.cliPathBannerStatus.textContent, SUCCESS.message);
  assert.equal(f.nodes.installCliPathStatus.textContent, SUCCESS.message);
  assert.equal(f.nodes.installCliPathButton.disabled, true);
  assert.equal(f.state.status.registered, true);
  assert.equal(hidden(f.nodes.cliPathAddButton), true);
  assert.equal(hidden(f.nodes.cliPathDismissButton), false);
  assert.equal(f.document.activeElement, f.nodes.cliPathDismissButton);
  f.nodes.cliPathDismissButton.click();
  assert.equal(hidden(f.nodes.cliPathBanner), true);
  assert.equal(f.document.activeElement, f.opener);
});

test("Later persists dismissal without installing and does not re-prompt on later reads", async () => {
  const f = fixture(); await f.ready();
  f.nodes.cliPathLaterButton.focus();
  f.nodes.cliPathLaterButton.click();
  f.nodes.cliPathLaterButton.click();
  await f.context.installCliPath();
  assert.equal(f.requests.length, 2);
  assert.equal(f.requests[1].url, "/api/cli-path/defer");
  assert.equal(f.requests[1].options.method, "POST");
  assert.equal(f.requests[1].options.body, undefined);
  f.requests[1].resolve(new Response(null, { status: 204 })); await nextTurn();
  assert.equal(hidden(f.nodes.cliPathBanner), true);
  assert.equal(f.nodes.installCliPathButton.disabled, false);
  assert.match(f.nodes.installCliPathStatus.textContent, /later.*Settings/);
  assert.equal(f.document.activeElement, f.opener);
  const read = f.context.loadCliPathStatus({ allowPrompt: true }); await nextTurn();
  f.json(2, AVAILABLE); await read;
  assert.equal(hidden(f.nodes.cliPathBanner), true);
  f.nodes.installCliPathButton.click();
  assert.equal(f.requests[3].url, "/api/cli-path");
  f.json(3, SUCCESS); await nextTurn();
  assert.equal(hidden(f.nodes.cliPathBanner), true);
});

test("install failure is actionable in Settings and a retry clears the prior result immediately", async () => {
  const f = fixture(); await f.ready();
  f.nodes.cliPathAddButton.click();
  f.json(1, { error: "Profile is read-only." }, 500); await nextTurn(); await nextTurn();
  assert.equal(f.state.error, true);
  assert.match(f.nodes.cliPathBannerStatus.textContent, /Profile is read-only.*retry.*Settings/);
  assert.equal(hidden(f.nodes.cliPathAddButton), true);
  assert.equal(f.nodes.installCliPathButton.disabled, false);
  f.nodes.cliPathSettingsButton.click();
  assert.equal(f.settingsOpened(), 1);
  assert.equal(hidden(f.nodes.cliPathBanner), true);
  f.nodes.installCliPathButton.click();
  assert.equal(f.state.error, false);
  assert.equal(f.nodes.installCliPathStatus.classList.contains("error"), false);
  assert.equal(f.nodes.installCliPathStatus.textContent, "Adding bundled sniper-cli to PATH...");
  f.json(2, SUCCESS); await nextTurn();
  assert.equal(f.state.status.registered, true);
  assert.equal(hidden(f.nodes.cliPathBanner), true);
});

test("partial success preserves backend warnings and keeps manual retry enabled", async () => {
  const f = fixture(); await f.ready();
  f.nodes.cliPathAddButton.click();
  f.json(1, { ...SUCCESS, warnings: ["The existing bash profile could not be updated."] });
  await nextTurn();
  assert.equal(f.state.status.registered, false);
  assert.equal(f.nodes.installCliPathButton.disabled, false);
  assert.match(f.nodes.installCliPathStatus.textContent, /existing bash profile.*retry/);
  f.nodes.installCliPathButton.click();
  assert.doesNotMatch(f.nodes.installCliPathStatus.textContent, /finished|Added|bash profile/);
  f.json(2, SUCCESS); await nextTurn();
});

test("failed dismissal explains that it may return, but offers no repeated first-run choice", async () => {
  const f = fixture(); await f.ready();
  f.nodes.cliPathLaterButton.click();
  f.requests[1].reject(new Error("Connection lost.")); await nextTurn();
  assert.match(f.nodes.cliPathBannerStatus.textContent, /Connection lost.*may appear again/);
  assert.equal(hidden(f.nodes.cliPathAddButton), true);
  assert.equal(hidden(f.nodes.cliPathLaterButton), true);
  f.nodes.cliPathDismissButton.click();
  const read = f.context.loadCliPathStatus({ allowPrompt: true }); await nextTurn();
  f.json(2, AVAILABLE); await read;
  assert.equal(hidden(f.nodes.cliPathBanner), true);
});

test("failed startup check can be retried in Settings without creating a delayed first-run prompt", async () => {
  const f = fixture(); f.context.initCliPathOnboarding(); await nextTurn();
  f.requests[0].reject(new Error("Offline.")); await nextTurn();
  assert.equal(hidden(f.nodes.cliPathBanner), true);
  assert.equal(f.nodes.installCliPathButton.disabled, true);
  assert.match(f.nodes.installCliPathStatus.textContent, /Offline.*Refresh status/);
  f.nodes.refreshCliPathButton.click();
  f.nodes.refreshCliPathButton.click(); await nextTurn();
  assert.equal(f.requests.length, 2);
  assert.equal(f.nodes.installCliPathStatus.classList.contains("error"), false);
  f.json(1, AVAILABLE); await nextTurn();
  assert.equal(f.nodes.installCliPathButton.disabled, false);
  assert.equal(hidden(f.nodes.cliPathBanner), true);
});

test("availability reads are shared and a changed app directory can be registered from Settings", async () => {
  const f = fixture(); await f.ready({ ...AVAILABLE, registered: true, should_prompt: false });
  const first = f.context.loadCliPathStatus();
  const second = f.context.loadCliPathStatus();
  assert.equal(first, second); await nextTurn();
  assert.equal(f.requests.length, 2);
  f.json(1, { ...AVAILABLE, directory: "/fixture/moved/Sniper.app/Contents/MacOS" }); await first;
  assert.equal(f.nodes.installCliPathButton.disabled, false);
  assert.equal(hidden(f.nodes.cliPathBanner), true);
  assert.match(f.nodes.cliPathDirectory.textContent, /moved/);
});

test("malformed availability and install replies never claim success", async () => {
  const f = fixture(); await f.ready({ ...AVAILABLE, can_install: "yes" });
  assert.equal(f.state.error, true);
  assert.equal(f.nodes.installCliPathButton.disabled, true);
  assert.equal(hidden(f.nodes.cliPathBanner), true);
  const read = f.context.loadCliPathStatus(); await nextTurn(); f.json(1, AVAILABLE); await read;
  f.nodes.installCliPathButton.click(); f.json(2, { message: "Not a valid result" }); await nextTurn();
  assert.equal(f.state.error, true);
  assert.equal(f.state.status.registered, false);
  assert.match(f.nodes.installCliPathStatus.textContent, /Invalid PATH setup response.*retry/);
});

test("pagehide aborts pending read and rejects its late result after a back/forward restore", async () => {
  const f = fixture(); f.context.initCliPathOnboarding(); await nextTurn();
  f.emit("pagehide");
  assert.equal(f.requests[0].options.signal.aborted, true);
  f.emit("pageshow", { persisted: true }); await nextTurn();
  assert.equal(f.requests.length, 2);
  f.json(1, { ...AVAILABLE, platform: "windows", should_prompt: false }); await nextTurn();
  f.json(0, AVAILABLE); await nextTurn();
  assert.equal(f.state.status.platform, "windows");
  assert.equal(f.state.loading, false);
  assert.equal(hidden(f.nodes.cliPathBanner), true);
});

for (const action of ["installCliPath", "deferCliPath"]) {
  test(`pagehide aborts ${action} presentation and ignores its late completion`, async () => {
    const f = fixture(); await f.ready();
    const pending = f.context[action]();
    f.emit("pagehide");
    assert.equal(f.requests[1].options.signal.aborted, true);
    f.emit("pageshow", { persisted: true }); await nextTurn();
    f.json(2, { ...AVAILABLE, registered: true, should_prompt: false, message: "Verified after returning." });
    await nextTurn();
    if (action === "deferCliPath") f.requests[1].resolve(new Response(null, { status: 204 }));
    else f.json(1, { ...SUCCESS, message: "Stale install reply." });
    await pending;
    assert.equal(f.nodes.installCliPathStatus.textContent, "Verified after returning.");
    assert.equal(hidden(f.nodes.cliPathBanner), true);
    assert.equal(f.state.action, null);
  });
}

test("completed work never reopens Settings or takes focus after the operator navigates away", async () => {
  const f = fixture(); await f.ready();
  f.nodes.cliPathAddButton.focus(); f.nodes.cliPathAddButton.click();
  const elsewhere = { id: "other-tab" }; f.document.activeElement = elsewhere;
  f.json(1, SUCCESS); await nextTurn();
  assert.equal(f.document.activeElement, elsewhere);
  assert.equal(f.settingsOpened(), 0);
});

test("event binding is idempotent and disposed controls cannot make requests", async () => {
  const f = fixture(); await f.ready();
  f.context.bindCliPathControls();
  assert.equal(f.nodes.cliPathAddButton.listeners.get("click").length, 1);
  f.emit("pagehide");
  await f.context.installCliPath(); await f.context.deferCliPath(); await f.context.loadCliPathStatus();
  assert.equal(f.requests.length, 1);
});

test("HTML exposes accessible status regions and a disabled initial install control", () => {
  const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
  for (const id of ["installCliPathStatus", "cliPathBannerStatus"]) {
    assert.match(html, new RegExp(`id="${id}"[^>]*role="status"[^>]*aria-live="polite"[^>]*aria-atomic="true"`));
  }
  assert.match(html, /class="cli-path-banner hidden"[^>]*aria-labelledby="cliPathBannerTitle"/);
  assert.match(html, /id="installCliPathButton"[^>]*disabled/);
  const initStart = appSource.indexOf("async function init() {");
  const initEnd = appSource.indexOf("\nfunction resetLayoutTextareas()", initStart);
  const setupCall = appSource.indexOf("  initCliPathOnboarding();", initStart);
  assert.ok(setupCall > appSource.indexOf("  await loadSettings();", initStart) && setupCall < initEnd);
  assert.match(appSource.slice(initStart, initEnd), /initCliPathOnboarding\(\);\n}\n$/);
  assert.equal((appSource.match(/initCliPathOnboarding\(\);/g) || []).length, 1);
});
