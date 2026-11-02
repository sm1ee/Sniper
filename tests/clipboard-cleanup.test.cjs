// Static Copy markup and synthetic clipboard APIs only; never a real clipboard.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

const html = fs.readFileSync(path.join(__dirname, "../web/index.html"), "utf8");
const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8");

test("OAST Copy uses visible text and an explicit purpose without changing its native action", () => {
  const buttons = [...html.matchAll(/<button\b([^>]*\bid="oastCopyPayloadButton"[^>]*)>([^]*?)<\/button>/g)];
  assert.equal(buttons.length, 1);
  const attrs = Object.fromEntries([...buttons[0][1].matchAll(/([\w:-]+)="([^"]*)"/g)].map(([, key, value]) => [key, value]));
  assert.deepEqual(attrs, { class: "utility-button", id: "oastCopyPayloadButton", type: "button",
    title: "Copy", "aria-label": "Copy OAST payload" });
  assert.equal(buttons[0][2], "Copy");
  assert.doesNotMatch(buttons[0][2], /\p{Extended_Pictographic}|<svg/u);
});

function cssDeclarations(body) {
  return Object.fromEntries(body.replace(/\/\*[^]*?\*\//g, "").split(";").filter(part => part.includes(":"))
    .map(part => part.trim().split(/:\s*/)));
}

function mobileUtilityRule(maxWidth, selector) {
  const marker = `@media (max-width: ${maxWidth}px)`;
  const matches = [];
  let start = css.indexOf(marker);
  while (start >= 0) {
    const open = css.indexOf("{", start);
    let end = open + 1, depth = 1;
    while (depth && end < css.length) {
      if (css[end] === "{") depth++;
      if (css[end] === "}") depth--;
      end++;
    }
    assert.equal(depth, 0, "Media block must close");
    const body = css.slice(open + 1, end - 1);
    for (const [, selectors, declarations] of body.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
      if (selectors.trim() === selector) matches.push(cssDeclarations(declarations));
    }
    start = css.indexOf(marker, end);
  }
  assert.equal(matches.length, 1, `${selector} at ${maxWidth}px`);
  return matches[0];
}

test("OAST Copy keeps compact sizing while its input remains flexible", () => {
  const row = css.match(/\.oast-payload-display\s*\{([^}]+)\}/)?.[1];
  const button = css.match(/\.oast-payload-display \.utility-button\s*\{([^}]+)\}/)?.[1];
  const input = css.match(/\.oast-payload-input\s*\{([^}]+)\}/)?.[1];
  assert.match(row, /display:\s*flex;/);
  assert.match(row, /gap:\s*10px;/);
  assert.match(row, /padding:\s*10px 16px;/);
  assert.match(button, /min-height:\s*var\(--control-h\);/);
  assert.match(button, /padding:\s*0 10px;/);
  assert.match(input, /flex:\s*1;/);
  assert.match(input, /min-width:\s*0;/);
});

test("OAST Copy overrides both generic mobile utility rules without changing other utility buttons", () => {
  const flexRule = mobileUtilityRule(760, ".utility-button,\n  .status-pill");
  const widthRule = mobileUtilityRule(560, ".metric-pill,\n  .utility-button,\n  .status-pill");
  assert.equal(flexRule.flex, "1 1 auto", "Keep the existing generic mobile behavior");
  assert.equal(widthRule.width, "100%", "Keep the existing generic narrow behavior");
  const local = cssDeclarations(css.match(/\.oast-payload-display \.utility-button\s*\{([^}]+)\}/)[1]);
  assert.equal(local.flex, "0 0 auto");
  assert.equal(local.width, "auto");
  const markup = html.match(/<div id="oastPayloadDisplay"[^>]*>([^]*?)<\/div>/)[1];
  const buttons = [...markup.matchAll(/<button\b[^>]*class="utility-button"[^>]*id="([^"]+)"/g)];
  assert.deepEqual(buttons.map(match => match[1]), ["oastCopyPayloadButton"]);
  // Resolve only the actual relevant width/flex declarations: each generic
  // selector has one class; the OAST descendant selector has two. This tests
  // the cascade conflict, not text measurement or browser pixel geometry.
  const properties = (width, inOast) => {
    const rules = [
      { max: 760, specificity: 1, declarations: flexRule },
      { max: 560, specificity: 1, declarations: widthRule },
      ...(inOast ? [{ max: Infinity, specificity: 2, declarations: local }] : []),
    ].filter(rule => width <= rule.max).sort((a, b) => a.specificity - b.specificity);
    const resolved = { width: "auto", flex: "0 1 auto" };
    for (const rule of rules) for (const key of ["width", "flex"])
      if (Object.hasOwn(rule.declarations, key)) resolved[key] = rule.declarations[key];
    return resolved;
  };
  for (const width of [900, 761, 760, 600, 561, 560, 500, 320]) {
    assert.deepEqual(properties(width, true), { width: "auto", flex: "0 0 auto" }, `OAST at ${width}px`);
    assert.deepEqual(properties(width, false), {
      width: width <= 560 ? "100%" : "auto", flex: width <= 760 ? "1 1 auto" : "0 1 auto",
    }, `unrelated utility at ${width}px`);
  }
});

for (const value of ["", "synthetic.example.com"]) {
  test(`OAST Copy actual binding ${value ? "copies the displayed synthetic value" : "keeps empty input a no-op"}`, async () => {
    const handlers = new Map(), copies = [], notices = [];
    const els = { oastPayloadText: { value },
      oastCopyPayloadButton: { addEventListener: (type, callback) => handlers.set(type, callback) } };
    const forbidden = () => assert.fail("No OAST service, network or real clipboard action is permitted");
    const context = vm.createContext({ els, copyTextToClipboard: async text => { copies.push(text); },
      showToast: text => notices.push(text), fetch: forbidden, generateOastPayload: forbidden,
      navigator: { clipboard: { writeText: forbidden } } });
    const start = appSource.indexOf("  if (els.oastCopyPayloadButton) {");
    const end = appSource.indexOf("  if (els.oastTableBody) {", start);
    assert.ok(start >= 0 && end > start);
    vm.runInContext(appSource.slice(start, end), context);
    assert.deepEqual([...handlers.keys()], ["click"]);
    assert.deepEqual(copies, []);
    assert.equal(handlers.get("click")(), undefined);
    assert.deepEqual(copies, value ? [value] : []);
    assert.deepEqual(notices, []);
    await finishCopyTurn();
    assert.deepEqual(notices, value ? ["Copied OAST payload"] : []);
    assert.equal(els.oastPayloadText.value, value);
  });
}

function fixture({ modern, selectError, copyError, copied = true } = {}) {
  const attached = new Set(), writes = [], calls = [];
  const document = {
    body: { appendChild(node) { attached.add(node); } },
    createElement(tag) {
      assert.equal(tag, "textarea");
      return {
        value: "", style: {}, setAttribute() {},
        select() {
          calls.push("select");
          if (selectError) throw selectError;
        },
        remove() { calls.push("remove"); attached.delete(this); },
      };
    },
    execCommand(command) {
      assert.equal(command, "copy");
      calls.push("copy");
      assert.equal(attached.size, 1);
      writes.push([...attached][0].value);
      if (copyError) throw copyError;
      return copied;
    },
  };
  const navigator = {};
  if (modern) navigator.clipboard = { writeText: modern };
  const context = loadFunctions(["copyTextToClipboard"], { document, navigator });
  return { copyTextToClipboard: context.copyTextToClipboard, context, attached, writes, calls };
}

test("modern clipboard success does not create a fallback node", async () => {
  const values = [];
  const f = fixture({ modern: async text => values.push(text) });
  await f.copyTextToClipboard("plain synthetic text");
  assert.deepEqual(values, ["plain synthetic text"]);
  assert.equal(f.attached.size, 0);
  assert.deepEqual(f.calls, []);
});

for (const modernRejected of [false, true]) {
  test(`fallback success cleans up (modern rejected: ${modernRejected})`, async () => {
    const f = fixture({ modern: modernRejected ? async () => { throw new Error("unavailable"); } : undefined });
    await f.copyTextToClipboard("synthetic 日本語 😀\nsecond line");
    assert.deepEqual(f.writes, ["synthetic 日本語 😀\nsecond line"]);
    assert.deepEqual(f.calls, ["select", "copy", "remove"]);
    assert.equal(f.attached.size, 0);
  });
}

test("a false fallback result rejects after removing its temporary node", async () => {
  const f = fixture({ copied: false });
  await assert.rejects(f.copyTextToClipboard("synthetic text"), /Clipboard copy failed/);
  assert.equal(f.attached.size, 0);
  assert.deepEqual(f.calls, ["select", "copy", "remove"]);
});

for (const operation of ["select", "copy"]) {
  test(`a throwing ${operation} removes its temporary node and preserves the error`, async () => {
    const error = new Error(`synthetic ${operation} failure`);
    const f = fixture(operation === "select" ? { selectError: error } : { copyError: error });
    for (let i = 0; i < 5; i++) {
      await assert.rejects(f.copyTextToClipboard(`synthetic attempt ${i}`), actual => actual === error);
      assert.equal(f.attached.size, 0, "failed attempts must not accumulate temporary textareas");
    }
    assert.equal(f.calls.filter(call => call === "remove").length, 5);
    if (operation === "select") assert.deepEqual(f.writes, []);
  });
}

test("nullish input stays a no-op and other values retain string conversion", async () => {
  const f = fixture();
  await f.copyTextToClipboard(null);
  await f.copyTextToClipboard(undefined);
  assert.deepEqual(f.calls, []);
  await f.copyTextToClipboard(0);
  await f.copyTextToClipboard("");
  assert.deepEqual(f.writes, ["0", ""]);
  assert.equal(f.attached.size, 0);
});

// Evaluate only the actual initialized OAST Copy registration. The helper and
// fallback are real source; navigator/document above are exclusively inert.
function oastCopyFixture(options = {}) {
  const f = fixture(options), toasts = [];
  let click;
  const button = {
    disabled: false,
    addEventListener(type, handler) { assert.equal(type, "click"); click = handler; },
  };
  f.context.els = { oastCopyPayloadButton: button, oastPayloadText: { value: "synthetic.example.com" } };
  f.context.showToast = (...args) => toasts.push(args);
  const start = appSource.indexOf("  if (els.oastCopyPayloadButton) {");
  const end = appSource.indexOf("  if (els.oastTableBody) {", start);
  assert.ok(start > 0 && end > start);
  vm.runInContext(appSource.slice(start, end), f.context);
  return { ...f, button, toasts, click, payload: f.context.els.oastPayloadText };
}

function pendingWrite() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

// A full event-loop turn drains the promise chain and lets node:test detect
// any unhandled rejection; the tests do not attach their own rejection catch.
const finishCopyTurn = () => new Promise(resolve => setImmediate(resolve));

test("OAST copy waits for modern success without returning a pending click promise", async () => {
  const pending = pendingWrite(), values = [];
  const f = oastCopyFixture({ modern: text => { values.push(text); return pending.promise; } });
  const result = f.click();
  const immediateToasts = [...f.toasts];
  assert.equal(result, undefined); assert.equal(f.button.disabled, false);
  pending.resolve(); await finishCopyTurn();
  assert.deepEqual(immediateToasts, [], "no success before clipboard fulfillment");
  assert.deepEqual(f.toasts, [["Copied OAST payload"]]);
  assert.deepEqual(values, ["synthetic.example.com"]);
  assert.deepEqual(f.calls, []); assert.equal(f.attached.size, 0);
});

for (const modernRejected of [false, true]) test(`OAST copy announces successful fallback after settlement (modern rejected: ${modernRejected})`, async () => {
  const f = oastCopyFixture({ modern: modernRejected ? async () => { throw new Error("synthetic unavailable"); } : undefined });
  assert.equal(f.click(), undefined); assert.deepEqual(f.toasts, []);
  await finishCopyTurn();
  assert.deepEqual(f.toasts, [["Copied OAST payload"]]);
  assert.deepEqual(f.writes, ["synthetic.example.com"]);
  assert.deepEqual(f.calls, ["select", "copy", "remove"]); assert.equal(f.attached.size, 0);
});

test("OAST copy handles pending modern refusal and failed fallback without any success toast", async () => {
  const pending = pendingWrite();
  const f = oastCopyFixture({ modern: () => pending.promise, copied: false });
  assert.equal(f.click(), undefined); assert.deepEqual(f.toasts, []); assert.equal(f.button.disabled, false);
  pending.reject(new Error("synthetic clipboard refusal")); await finishCopyTurn();
  assert.deepEqual(f.toasts, [["Failed to copy OAST payload", "error"]]);
  assert.deepEqual(f.calls, ["select", "copy", "remove"]); assert.equal(f.attached.size, 0);
});

for (const failure of ["false", "select", "copy"]) test(`OAST copy handles ${failure} fallback failure and retains temporary-node cleanup`, async () => {
  const error = new Error(`synthetic ${failure} failure`);
  const options = failure === "false" ? { copied: false } : failure === "select" ? { selectError: error } : { copyError: error };
  const f = oastCopyFixture(options);
  assert.equal(f.click(), undefined); assert.deepEqual(f.toasts, []);
  await finishCopyTurn();
  assert.deepEqual(f.toasts, [["Failed to copy OAST payload", "error"]]);
  assert.equal(f.attached.size, 0);
  assert.deepEqual(f.calls, failure === "select" ? ["select", "remove"] : ["select", "copy", "remove"]);
});

test("empty OAST payload remains a silent no-op", async () => {
  let writes = 0;
  const f = oastCopyFixture({ modern: async () => { writes++; } });
  f.payload.value = "";
  assert.equal(f.click(), undefined); await finishCopyTurn();
  assert.equal(writes, 0); assert.deepEqual(f.toasts, []); assert.deepEqual(f.calls, []);
  assert.equal(f.button.disabled, false); assert.equal(f.attached.size, 0);
});

// Only initialized Replay menu action registrations and the production clipboard
// helper run here. All clipboard/document APIs are the inert fixture above.
function replayCopyFixture(action, options = {}) {
  const f = fixture(options), toasts = [], exports = [], urls = [];
  const tab = { id: "synthetic-tab", requestText: "GET /synthetic HTTP/1.1" };
  let click, closes = 0;
  const button = { dataset: { replayAction: action },
    addEventListener(type, handler) { assert.equal(type, "click"); click = handler; } };
  const forbidden = () => assert.fail("No network, native or request action is permitted");
  Object.assign(f.context, {
    getReplayContextMenu: () => ({ querySelectorAll(selector) {
      assert.equal(selector, "[data-replay-action]"); return [button];
    } }),
    replayContextMenuTabId: tab.id, getReplayTabById: id => id === tab.id ? tab : null,
    getReplayExportTarget: selected => {
      assert.equal(selected, tab); return { scheme: "https", host: "example.com", port: "" };
    },
    buildUrlFromTarget: (...args) => { urls.push(args); return "https://example.com/synthetic"; },
    replayRequestToFormat: (format, selected) => {
      assert.equal(selected, tab); exports.push(format); return `synthetic ${format} export text`;
    },
    closeReplayContextMenu: () => closes++, showToast: (...args) => toasts.push(args),
    fetch: forbidden, sendReplay: forbidden, openCurlImportModal: forbidden,
  });
  const copyUrl = appSource.match(/^function copyReplayUrl\([^]*?^\}/m);
  assert.ok(copyUrl);
  vm.runInContext(copyUrl[0], f.context);
  const init = appSource.indexOf("function initReplayContextMenu() {");
  const start = appSource.indexOf("  // Action buttons\n", init);
  const end = appSource.indexOf("  // Close on outside click\n", start);
  assert.ok(init >= 0 && start > init && end > start);
  vm.runInContext(appSource.slice(start, end), f.context);
  return { ...f, toasts, exports, urls, tab, click, closes: () => closes };
}

for (const action of ["copy-url", "copy-as-curl", "copy-as-python", "copy-as-fetch", "copy-as-powershell"]) {
  for (const outcome of ["modern success", "fallback success", "false", "select", "copy"]) {
    test(`Replay ${action} actual binding settles ${outcome} with truthful feedback`, async () => {
      const pending = pendingWrite(), modernWrites = [];
      const error = new Error("synthetic private clipboard detail");
      const f = replayCopyFixture(action, {
        modern: text => { modernWrites.push(text); return pending.promise; },
        copied: outcome !== "false",
        selectError: outcome === "select" ? error : undefined,
        copyError: outcome === "copy" ? error : undefined,
      });
      const original = f.tab.requestText;
      assert.equal(f.click(), undefined);
      assert.equal(f.closes(), 1, "menu closes immediately, not after clipboard settlement");
      assert.deepEqual(f.toasts, [], "no notification while modern clipboard is pending");
      assert.equal(f.attached.size, 0);
      assert.deepEqual(modernWrites, [action === "copy-url" ? "https://example.com/synthetic" : `synthetic ${action.replace("copy-as-", "")} export text`]);
      assert.deepEqual(f.urls, action === "copy-url" ? [["https", "example.com", "", "/synthetic"]] : []);
      assert.deepEqual(f.exports, action !== "copy-url" ? [action.replace("copy-as-", "")] : []);
      if (outcome === "modern success") pending.resolve();
      else pending.reject(error);
      await finishCopyTurn();
      const success = outcome.endsWith("success");
      assert.deepEqual(f.toasts, [success
        ? [action === "copy-url" ? "Copied URL" : `Copied as ${action.replace("copy-as-", "")}`]
        : ["Failed to copy", "error"]]);
      assert.equal(f.attached.size, 0);
      assert.equal(f.closes(), 1);
      assert.equal(f.tab.requestText, original);
      assert.deepEqual(f.calls, outcome === "modern success" ? [] : outcome === "select"
        ? ["select", "remove"] : ["select", "copy", "remove"]);
    });
  }
}

for (const action of ["copy-url", "copy-as-curl", "copy-as-python", "copy-as-fetch", "copy-as-powershell"]) {
  test(`Replay ${action} failed attempt can be retried successfully`, async () => {
    let attempt = 0;
    const f = replayCopyFixture(action, { copied: false, modern: async () => {
      if (++attempt === 1) throw new Error("synthetic refusal");
    } });
    f.click(); await finishCopyTurn();
    f.click(); await finishCopyTurn();
    assert.deepEqual(f.toasts, [
      ["Failed to copy", "error"],
      [action === "copy-url" ? "Copied URL" : `Copied as ${action.replace("copy-as-", "")}`],
    ]);
    assert.equal(f.closes(), 2); assert.equal(f.attached.size, 0);
  });
}


for (const action of ["copy-url", "copy-as-curl", "copy-as-python", "copy-as-fetch", "copy-as-powershell"]) {
  test(`Replay ${action} missing menu tab stays a silent no-op`, async () => {
    const f = replayCopyFixture(action, { modern: () => assert.fail("must not copy") });
    f.context.replayContextMenuTabId = "missing";
    f.click(); await finishCopyTurn();
    assert.deepEqual(f.toasts, []); assert.deepEqual(f.calls, []); assert.equal(f.closes(), 1);
  });
}

for (const action of ["copy-as-curl", "copy-as-python", "copy-as-fetch", "copy-as-powershell"]) test(`Replay empty ${action} export stays a silent no-op`, async () => {
  const f = replayCopyFixture(action, { modern: () => assert.fail("must not copy") });
  f.context.replayRequestToFormat = () => "";
  f.click(); await finishCopyTurn();
  assert.deepEqual(f.toasts, []); assert.deepEqual(f.calls, []); assert.equal(f.closes(), 1);
});
