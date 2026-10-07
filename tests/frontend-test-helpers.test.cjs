const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const helperSource = fs.readFileSync(path.join(__dirname, "frontend-test-helpers.cjs"), "utf8");
const source = 'function sourceFixture() {\n  return "first\\r\\nsecond";\n}\n';

for (const [name, newline] of [["LF", "\n"], ["CRLF", "\r\n"]]) {
  test(`${name} source loading preserves runtime CRLF payloads`, () => {
    const context = vm.createContext({
      console,
      __dirname,
      module: { exports: {} },
      require(name) {
        if (name === "node:fs") return {
          readFileSync(filename, encoding) {
            assert.equal(filename, path.join(__dirname, "../web/app.js"));
            assert.equal(encoding, "utf8");
            return source.replace(/\n/g, newline);
          },
        };
        return require(name);
      },
    });
    vm.runInContext(helperSource, context);
    const { appSource, loadFunctions } = context.module.exports;
    assert.equal(appSource, source);
    assert.equal(loadFunctions(["sourceFixture"]).sourceFixture(), "first\r\nsecond");
  });
}
