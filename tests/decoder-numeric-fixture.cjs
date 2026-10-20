// Load actual Decoder scripts without app startup, a browser, or external I/O.
// SNIPER_DECODER_ROOT selects a repository snapshot for before/after probes.
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function fixture() {
  const root = process.env.SNIPER_DECODER_ROOT || path.join(__dirname, "..");
  const values = new Map([["#input-value", ""], ["#input-password", ""]]);
  const context = vm.createContext({
    document: {}, autoScroll() {},
    $(selector) {
      return {
        val(value) {
          if (!arguments.length) return values.get(selector) || "";
          values.set(selector, value); return this;
        },
        hide() { return this; }, attr() { return this; },
        text() { return this; }, html() { return this; },
      };
    },
  });
  for (const file of ["lib/snov/ipcalc.js", "lib/snov/numbers.js", "lib/snov/romanconverter.js", "hasher.js"]) {
    vm.runInContext(fs.readFileSync(path.join(root, "web/decoder", file), "utf8"), context,
      { filename: `web/decoder/${file}` });
  }
  return {
    context, values, elements: context.hasher.elements,
    update(tab, input) {
      context.hasher.tab = context.tabs[tab];
      values.set("#input-value", input);
      context.hasher.update();
      return Object.fromEntries(Object.entries(context.hasher.elements)
        .filter(([, element]) => element.tab === context.tabs[tab])
        .map(([key, element]) => [key, values.get("#" + element.id)]));
    },
  };
}

module.exports = { fixture };
