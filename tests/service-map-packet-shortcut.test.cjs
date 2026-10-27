// Cmd+R on the packet in Map > Details. The production shortcut block and
// viewer mount run in a VM with inert stand-ins; nothing is sent or opened.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

function shortcutBlock(marker) {
  const start = appSource.indexOf(marker);
  const firstIf = appSource.indexOf("\n    if (", start);
  const end = appSource.indexOf("\n    if (", firstIf + 1);
  assert.ok(start > 0 && end > firstIf, `missing shortcut block: ${marker}`);
  return appSource.slice(start, end);
}

function press(context, extra = {}) {
  const event = { metaKey: true, ctrlKey: false, shiftKey: false, altKey: false, key: "r", prevented: false,
    preventDefault() { this.prevented = true; }, ...extra };
  context.shortcut(event);
  return event;
}

// The packet menu offers Send to Replay with the chord, so the chord works
// wherever the menu does, as it does in HTTP history.
test("Cmd+R in Map Details sends the shown packet to Replay, as its menu does", () => {
  const sent = [];
  const target = { kind: "retained-packet", packet: {}, isCurrent: () => true };
  const c = vm.createContext({
    state: { activeTool: "map" }, serviceMapPacketMenuTarget: target, handleSendActionError() {},
    runPacketMenuAction: (menuTarget, action) => { sent.push([menuTarget, action]); return Promise.resolve(true); },
  });
  vm.runInContext(`function shortcut(event) {${shortcutBlock("    // Cmd+R in Map ▸ Details")}\n}`, c);
  assert.equal(press(c).prevented, true);
  assert.deepEqual(sent, [[target, "send-to-replay"]]);

  // Another tool, another chord, no packet shown, or a stale packet: untouched.
  c.state.activeTool = "proxy"; assert.equal(press(c).prevented, false);
  c.state.activeTool = "map"; assert.equal(press(c, { shiftKey: true }).prevented, false);
  target.isCurrent = () => false; assert.equal(press(c).prevented, false);
  c.serviceMapPacketMenuTarget = null; assert.equal(press(c).prevented, false);
  assert.equal(sent.length, 1);
});

test("the Map packet viewer offers its packet to Cmd+R only while it is mounted", () => {
  const node = () => ({ querySelector: () => ({ querySelector: () => ({}) }) });
  const container = { isConnected: true, querySelector: () => node() };
  const menus = [];
  const c = loadFunctions(["mountServiceMapPacketViewer"], {
    serviceMapPacketMenuTarget: null,
    createRecordClipboardOwner: () => () => true,
    createPacketViewerController: (options) => ({ update() {}, destroy() {}, options }),
    buildPacketMessagePresentation: () => ({ text: "", head: "", notice: "" }),
    packetEvidenceRanges: () => [], packetRequestTarget: () => null, getCMView: () => null,
    paneMenuOpen: (_event, menuTarget) => menus.push(menuTarget),
  });
  const packet = { variant: "current", request: null, response: null, evidence_id: "evidence" };
  const viewer = c.mountServiceMapPacketViewer(container, { packet, row: {}, isCurrent: () => true });
  const target = c.serviceMapPacketMenuTarget;
  assert.equal(target.kind, "retained-packet");
  assert.equal(target.packet, packet);
  assert.equal(target.isCurrent(), true);
  viewer.destroy();
  assert.equal(c.serviceMapPacketMenuTarget, null);
  assert.equal(target.isCurrent(), false);
});
