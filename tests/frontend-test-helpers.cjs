const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// Windows checkouts use CRLF, while fixture source markers use LF. Normalize
// source text only; escaped line endings in runtime payloads stay untouched.
const appSource = fs.readFileSync(path.join(__dirname, "../web/app.js"), "utf8").replace(/\r\n/g, "\n");

// Load only the named functions: running app.js itself would start the UI and
// make API requests. Top-level functions in this file end at column zero.
function loadFunctions(names, globals = {}) {
  const context = vm.createContext({ console, ...globals });
  for (const name of names) {
    assert.match(name, /^[A-Za-z_$][\w$]*$/);
    const match = appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, "m"));
    assert.ok(match, `Missing frontend function: ${name}`);
    vm.runInContext(match[0], context, { filename: `web/app.js:${name}` });
  }
  return context;
}

// An on/off pill button (`setToggleButton`). `checked` is test shorthand for
// its pressed state, so fixtures read like the checkboxes these buttons replaced.
function toggleButton(on = false) {
  const classes = new Set(on ? ["active"] : []);
  const attributes = { "aria-pressed": String(on) };
  return {
    disabled: false, title: "", listeners: {},
    classList: {
      add: name => classes.add(name), remove: name => classes.delete(name), contains: name => classes.has(name),
      toggle(name, force = !classes.has(name)) { if (force) classes.add(name); else classes.delete(name); return force; },
    },
    getAttribute: name => attributes[name] ?? null,
    setAttribute(name, value) { attributes[name] = String(value); },
    addEventListener(name, callback) { this.listeners[name] = callback; },
    get checked() { return classes.has("active"); },
    set checked(value) { this.classList.toggle("active", Boolean(value)); attributes["aria-pressed"] = String(Boolean(value)); },
  };
}

module.exports = { appSource, loadFunctions, toggleButton };
