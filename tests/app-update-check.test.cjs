// Check for Updates… only. The page's real handlers and the script the desktop
// app runs from its Sniper menu execute in a VM against a synthetic version
// endpoint and toast. Nothing reaches GitHub, downloads, or installs.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const desktopSource = fs.readFileSync(path.join(__dirname, "../src/bin/sniper-desktop.rs"), "utf8")
  .replace(/\r\n/g, "\n");
const UP_TO_DATE = { current_version: "0.3.2", update_available: false, self_update_supported: true };
const AVAILABLE = { ...UP_TO_DATE, latest_version: "v9.9.9", update_available: true };

function fixture() {
  const classes = new Set(["hidden"]);
  const button = {
    title: "",
    classList: {
      add: (...names) => names.forEach(name => classes.add(name)),
      remove: (...names) => names.forEach(name => classes.delete(name)),
      contains: name => classes.has(name),
    },
  };
  const els = { appVersionLabel: { textContent: "v...", title: "" }, openUpdateButton: button };
  const requests = [], toasts = [], dialogs = [], updates = [];
  const state = { appVersion: null };
  const context = loadFunctions(["loadAppVersionInfo", "checkForUpdatesNow"], {
    state, els, window: {}, appVersionReadGeneration: 0,
    fetch(url) { return new Promise((resolve, reject) => requests.push({ url, resolve, reject })); },
    showToast(message, type) { toasts.push({ message, type }); },
    showConfirmDialog(message, onConfirm, options) { dialogs.push({ message, onConfirm, options }); },
    performSelfUpdate() { updates.push(state.appVersion.latest_version); },
  });
  const hook = appSource.match(/^window\.__sniperCheckForUpdates = checkForUpdatesNow;$/m);
  assert.ok(hook, "The page does not publish Check for Updates for the desktop menu");
  vm.runInContext(hook[0], context);
  return { context, els, state, requests, toasts, dialogs, updates };
}

// The script sniper-desktop runs when the Sniper menu's item is chosen.
function menuScript() {
  const match = desktopSource.match(
    /DesktopUserEvent::CheckForUpdates\) => \{\s*let _ = webview\.evaluate_script\(\s*"([^"]+)"/,
  );
  assert.ok(match, "The desktop app runs no script for Check for Updates");
  return match[1];
}

test("Check for Updates… asks GitHub afresh and says the app is up to date", async () => {
  const f = fixture();
  const done = vm.runInContext(menuScript(), f.context);
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].url, "/api/app-version?refresh=true");
  f.requests[0].resolve({ ok: true, json: async () => UP_TO_DATE });
  await done;
  assert.deepEqual(f.toasts, [{ message: "Sniper v0.3.2 is up to date.", type: "success" }]);
  assert.equal(f.els.appVersionLabel.textContent, "v0.3.2");
  assert.equal(f.els.openUpdateButton.classList.contains("hidden"), true);
});

// A toast would sit over the top bar's Update button for as long as it shows,
// so a found release asks in a dialog instead.
test("Check for Updates… that finds a release offers it in a dialog and shows Update", async () => {
  const f = fixture();
  const done = vm.runInContext(menuScript(), f.context);
  f.requests[0].resolve({ ok: true, json: async () => AVAILABLE });
  await done;
  assert.deepEqual(f.toasts, []);
  assert.equal(f.dialogs.length, 1);
  assert.equal(f.dialogs[0].message, "Sniper v9.9.9 is available. You have v0.3.2.");
  // Copied out of the VM, whose objects have another realm's prototype.
  assert.deepEqual({ ...f.dialogs[0].options }, {
    title: "Update available", confirmLabel: "Update", cancelLabel: "Later", confirmClass: "primary-action",
  });
  assert.equal(f.els.openUpdateButton.classList.contains("hidden"), false);
  assert.equal(f.els.openUpdateButton.title, "Update to v9.9.9");
  assert.deepEqual(f.updates, []);
  f.dialogs[0].onConfirm();
  assert.deepEqual(f.updates, ["v9.9.9"]);
});

test("Check for Updates… that GitHub refused says why instead of reporting no update", async () => {
  const f = fixture();
  const done = vm.runInContext(menuScript(), f.context);
  f.requests[0].resolve({
    ok: false, status: 502, text: async () => "GitHub's request limit was reached. Try again later.",
  });
  await done;
  assert.deepEqual(f.toasts, [{
    message: "Couldn't check for updates. GitHub's request limit was reached. Try again later.",
    type: "error",
  }]);
  assert.equal(f.state.appVersion, null);
  assert.equal(f.els.openUpdateButton.classList.contains("hidden"), true);
});
