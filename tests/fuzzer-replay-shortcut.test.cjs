// Cmd+R on a Fuzzer result sends its request to Replay, as it does in HTTP
// history. The production shortcut block runs in a VM; nothing is sent.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource } = require("./frontend-test-helpers.cjs");

function shortcutBlock(marker) {
  const start = appSource.indexOf(marker);
  const firstIf = appSource.indexOf("\n    if (", start);
  const end = appSource.indexOf("\n    if (", firstIf + 1);
  assert.ok(start > 0 && end > firstIf, `missing shortcut block: ${marker}`);
  return appSource.slice(start, end);
}

// A focused element: `inside` lists the selectors it sits within.
const focused = (...inside) => ({
  closest: (selectors) => (selectors.split(",").some((selector) => inside.includes(selector.trim())) ? {} : null),
});

function press(context, extra = {}) {
  const event = { metaKey: true, ctrlKey: false, shiftKey: false, altKey: false, key: "r", prevented: false,
    target: focused("#fuzzerDetailResCM"), preventDefault() { this.prevented = true; }, ...extra };
  context.shortcut(event);
  return event;
}

test("Cmd+R on a Fuzzer result opens its request in Replay", () => {
  const opened = [];
  const record = { id: "tx-1", host: "example.com" };
  const c = vm.createContext({
    state: { activeTool: "fuzzer", _fuzzerDetailRecord: record },
    fuzzerSelectedTransactionId: () => "tx-1",
    openTransactionRecordInReplay: (shown) => opened.push(shown),
    handleSendActionError() {},
  });
  vm.runInContext(`function shortcut(event) {${shortcutBlock("    // Cmd+R on a Fuzzer result")}\n}`, c);
  assert.equal(press(c).prevented, true, "from the response pane");
  assert.equal(press(c, { target: focused(".history-table-shell") }).prevented, true, "from the results");
  assert.equal(press(c, { ctrlKey: true, metaKey: false }).prevented, true, "Ctrl on other platforms");
  assert.deepEqual(opened, [record, record, record]);

  // Typing in the template or a field, another tool or chord, or no result
  // loaded: untouched.
  assert.equal(press(c, { target: focused("#fuzzerRequestCM") }).prevented, false);
  assert.equal(press(c, { target: focused("input") }).prevented, false);
  assert.equal(press(c, { shiftKey: true }).prevented, false);
  c.state.activeTool = "replay";
  assert.equal(press(c).prevented, false);
  c.state.activeTool = "fuzzer";
  c.fuzzerSelectedTransactionId = () => null;
  assert.equal(press(c).prevented, false);
  assert.equal(opened.length, 3);
});

test("a result Replay refuses is reported, not thrown out of the key handler", () => {
  const errors = [];
  const c = vm.createContext({
    state: { activeTool: "fuzzer", _fuzzerDetailRecord: { id: "tx-1" } },
    fuzzerSelectedTransactionId: () => "tx-1",
    openTransactionRecordInReplay: () => { throw new Error("Tunnel records cannot be sent to Replay."); },
    handleSendActionError: (error) => errors.push(error.message),
  });
  vm.runInContext(`function shortcut(event) {${shortcutBlock("    // Cmd+R on a Fuzzer result")}\n}`, c);
  assert.doesNotThrow(() => press(c));
  assert.deepEqual(errors, ["Tunnel records cannot be sent to Replay."]);
});

test("the shortcut reference lists Cmd+R for the Fuzzer", () => {
  assert.match(appSource, /\["Fuzzer", \[\s*\["mod\+r", "Send the selected result to Replay"\]/);
});
