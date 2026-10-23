// Real shipped CodeMirror state + production preview plugin callbacks, with an
// event-capable DOM adapter. No app bootstrap, browser geometry or network.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { appSource } = require("./frontend-test-helpers.cjs");
const bundle = vm.createContext({ console, setTimeout, clearTimeout });
vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/codemirror.bundle.js"), "utf8"), bundle);
const { CM } = bundle;
const start = appSource.indexOf("const ENCODED_PREVIEW_INPUT_LIMIT =");
const end = appSource.indexOf("function createBaseExtensions", start);
assert.ok(start > 0 && end > start);

class Node {
  constructor(tagName = "DIV") {
    this.tagName = tagName; this.listeners = new Map(); this.children = [];
    this.attributes = new Map(); this.style = {}; this.textContent = ""; this.visible = true;
    this.scrollTop = 0; this.clientHeight = 160; this.scrollHeight = 800;
  }
  set innerHTML(value) { assert.fail("Preview content must never be HTML"); }
  focus(options) { this.ownerDocument.activeElement = this; this.focusOptions = options; }
  get isConnected() { return this.root || !!this.parent?.isConnected; }
  appendChild(node) { node.parent = this; node.ownerDocument = this.ownerDocument; this.children.push(node); return node; }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); this.parent = null; }
  contains(node) { return node === this || this.children.some(child => child.contains(node)); }
  closest(selector) {
    for (let node = this; node; node = node.parent) {
      if (selector.includes(".encoded-preview-tooltip") && node.className === "encoded-preview-tooltip") return node;
    }
    return null;
  }
  setAttribute(key, value) { this.attributes.set(key, value); }
  getAttribute(key) { return this.attributes.get(key) ?? null; }
  removeAttribute(key) { this.attributes.delete(key); }
  addEventListener(type, callback, capture = false) {
    const list = this.listeners.get(type) || [];
    this.listeners.set(type, [...list, { callback, capture }]);
  }
  removeEventListener(type, callback, capture = false) {
    this.listeners.set(type, (this.listeners.get(type) || []).filter(entry => entry.callback !== callback || entry.capture !== capture));
  }
  fire(type, props = {}) {
    const event = { type, target: this, defaultPrevented: false, propagationStopped: false,
      preventDefault() { this.defaultPrevented = true; }, stopPropagation() { this.propagationStopped = true; }, ...props };
    for (const { callback } of [...this.listeners.get(type) || []]) callback(event);
    return event;
  }
  getClientRects() { return this.visible ? [this.getBoundingClientRect()] : []; }
  getBoundingClientRect() { return { left: 10, top: 10, bottom: 30, right: 100, width: 300, height: 160 }; }
}

function fixture(text = "hello%20world", selection = 1) {
  const timers = new Map(); let timerId = 0;
  const window = new Node("WINDOW");
  window.setTimeout = (callback, delay) => { timers.set(++timerId, { callback, delay }); return timerId; };
  window.clearTimeout = id => timers.delete(id);
  const document = new Node("DOCUMENT");
  document.root = true; document.ownerDocument = document; document.defaultView = window;
  document.createElement = tag => { const node = new Node(tag); node.ownerDocument = document; return node; };
  document.documentElement = { clientWidth: 800, clientHeight: 600 };
  const dom = document.createElement("div"), contentDOM = document.createElement("div");
  document.appendChild(dom); dom.appendChild(contentDOM);
  const context = vm.createContext({ CM, console, atob, btoa, TextDecoder, Uint8Array });
  vm.runInContext(appSource.slice(start, end) + "\nglobalThis.Preview = EncodedPreviewController; globalThis.plugin = encodedPreviewPlugin;", context);
  const view = {
    dom, contentDOM,
    state: CM.EditorState.create({ doc: text, selection: typeof selection === "number" ? { anchor: selection } : selection,
      extensions: [CM.history(), context.plugin] }),
    posAtCoords: ({ x }) => Math.round(x / 8),
    coordsAtPos: pos => ({ left: pos * 8, right: pos * 8, top: 10, bottom: 26 }),
    dispatch(spec) {
      const transaction = this.state.update(spec);
      this.state = transaction.state;
      controller.update({ docChanged: transaction.docChanged, selectionSet: !!transaction.selection });
    },
  };
  const controller = context.plugin.create(view);
  const run = delay => {
    for (const [id, timer] of [...timers]) if (delay == null || delay === timer.delay) {
      timers.delete(id); timer.callback();
    }
  };
  const hover = (pos, props = {}) => dom.fire("mousemove", { target: contentDOM, clientX: pos * 8 + 2, clientY: 15, buttons: 0, ...props });
  const source = name => appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, "m"))[0];
  return { context, controller, view, dom, contentDOM, document, window, timers, run, hover, source };
}
module.exports = { fixture, CM, Node };
