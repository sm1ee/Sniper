const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const appSource = fs.readFileSync(path.join(__dirname, "../web/app.js"), "utf8");

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

module.exports = { appSource, loadFunctions };
