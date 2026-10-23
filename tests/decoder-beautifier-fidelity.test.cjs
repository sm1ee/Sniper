const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function fixture() {
  const values = new Map([["#input-value", ""], ["#input-password", ""]]);
  const context = vm.createContext({
    document: {}, autoScroll() {},
    $(selector) {
      return {
        val(value) {
          if (arguments.length === 0) return values.get(selector) || "";
          values.set(selector, value);
          return this;
        },
        hide() { return this; }, removeClass() { return this; }, attr() { return this; },
        text() { return this; }, html() { return this; },
      };
    },
  });
  for (const file of ["lib/custom-json.js", "lib/snov/ipcalc.js", "hasher.js"]) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, "../web/decoder", file), "utf8"),
      context, { filename: `web/decoder/${file}` });
  }
  return { context, values, elements: context.hasher.elements };
}

test("JSON beautification preserves number spelling without converting to JavaScript numbers", () => {
  const { elements } = fixture();
  for (const number of ["9007199254740993", "-9007199254740993", "1e400", "1e-400", "-0",
    "-0.0", "1.2300000000000000000001", "1E+003", "0.00000000000000000001"]) {
    assert.equal(elements.json1.calculate(number), number, number);
    assert.equal(elements.json1.calculate(`{"n":[${number}]}`),
      `{\n  "n": [\n    ${number}\n  ]\n}`, number);
  }
});

test("JSON beautification preserves duplicate keys, key order and escaped key spelling", () => {
  const { elements } = fixture();
  const input = String.raw`{"2":"second","1":"first","a":1,"\u0061":2,"a":3,"__proto__":4}`;
  const expected = String.raw`{
  "2": "second",
  "1": "first",
  "a": 1,
  "\u0061": 2,
  "a": 3,
  "__proto__": 4
}`;
  assert.equal(elements.json1.calculate(input), expected);
});

test("JSON beautification changes only whitespace outside nested strings", () => {
  const { elements } = fixture();
  const input = String.raw` { "x" : ["a,{}[]: b",{"escaped":"\u0061\t\r\n\/\\\"","raw":"café 한글 😀"},[],{}],"bool":true,"nil":null } `;
  const expected = String.raw`{
  "x": [
    "a,{}[]: b",
    {
      "escaped": "\u0061\t\r\n\/\\\"",
      "raw": "café 한글 😀"
    },
    [],
    {}
  ],
  "bool": true,
  "nil": null
}`;
  assert.equal(elements.json1.calculate(input), expected);
  assert.equal(elements.json1.calculate(expected), expected);
  assert.deepEqual(JSON.parse(expected), JSON.parse(input));
});

test("JSON beautification accepts empty containers and scalar values", () => {
  const { elements } = fixture();
  for (const value of ["{}", "[]", "true", "false", "null", '""', String.raw`"\ud800"`]) {
    assert.equal(elements.json1.calculate(` \r\n\t${value}\r\n`), value);
  }
});

test("JSON beautification rejects malformed input without deleting invalid whitespace", () => {
  const { elements } = fixture();
  for (const input of ["", " \t\n", "[1,]", '{"a":}', "[1 2]", "01", "+1", "1e",
    "1.", "Infinity", "NaN", "{'a':1}", "{a:1}", "// comment\n{}", "{}[]", "[\u00a01]",
    '"a\nb"', String.raw`"bad\q"`, '"unfinished', String.raw`{"a":"unfinished\"}`]) {
    assert.equal(elements.json1.calculate(input), "", JSON.stringify(input));
  }
});

test("Dict beautification escapes apostrophes in keys and values", () => {
  const { elements } = fixture();
  const input = `{"O'Key":"O'Reilly"}`;
  const expected = String.raw`{
  'O\'Key': 'O\'Reilly'
}`;
  assert.equal(elements.json2.calculate(input), expected);
  assert.equal(elements.json2.calculate(expected), expected);
});

test("Dict beautification handles nested arrays and mixed string delimiters", () => {
  const { elements } = fixture();
  const input = String.raw`{'words':['first',"second",{'quote':'O\'Reilly says "hello"'}],"empty":{},'ok':true,'nil':null}`;
  const expected = String.raw`{
  'words': [
    'first',
    'second',
    {
      'quote': 'O\'Reilly says "hello"'
    }
  ],
  'empty': {},
  'ok': true,
  'nil': null
}`;
  assert.equal(elements.json2.calculate(input), expected);
  assert.equal(elements.json2.calculate(expected), expected);
});

test("Dict beautification leaves quote-like content inside strings intact", () => {
  const { elements } = fixture();
  const value = `text {'key': 'value'}, "quotes", apostrophe's, slash\\ and \n newline`;
  const output = elements.json2.calculate(JSON.stringify({ text: value }));
  // Independently parse this synthetic JSON-like dict as a JavaScript literal.
  assert.equal(vm.runInNewContext(`(${output})`).text, value);
  assert.equal(elements.json2.calculate(output), output);
});

test("Dict beautification preserves every combination of quotes and backslashes", () => {
  const { elements } = fixture();
  let values = [""];
  let level = [""];
  for (let length = 1; length <= 4; length++) {
    level = level.flatMap(prefix => ["'", '"', "\\"].map(char => prefix + char));
    values.push(...level);
  }
  for (const value of values) {
    const output = elements.json2.calculate(JSON.stringify({ [value]: value, array: [value] }));
    const parsed = vm.runInNewContext(`(${output})`);
    assert.equal(parsed[value], value, JSON.stringify(value));
    assert.equal(parsed.array[0], value, JSON.stringify(value));
    assert.equal(elements.json2.calculate(output), output, JSON.stringify(value));
  }
});

test("Dict beautification preserves number lexemes, duplicate keys and existing escapes", () => {
  const { elements } = fixture();
  const input = String.raw`{'2':9007199254740993,'1':1e400,'2':1e-400,'zero':-0.0,'\u0061':'\u0062\/\t'}`;
  const expected = String.raw`{
  '2': 9007199254740993,
  '1': 1e400,
  '2': 1e-400,
  'zero': -0.0,
  '\u0061': '\u0062\/\t'
}`;
  assert.equal(elements.json2.calculate(input), expected);
  assert.equal(elements.json2.calculate(expected), expected);
});

test("Dict beautification rejects malformed input and unsupported Python expressions", () => {
  const { elements } = fixture();
  for (const input of ["", "'unfinished", "{'a':'unfinished}", "{'a':1 2}", "{'a':01}",
    "{'a':True}", "{'a':None}", "{'a':(1,2)}", "{'a':1,}", "{'a':1}\u00a0", "['a' 'b']",
    "'a\nb'", String.raw`{'a':'bad\q'}`, String.raw`{"a":"bad\'"}`, String.raw`{'a':'bad\'}`]) {
    assert.equal(elements.json2.calculate(input), "", JSON.stringify(input));
  }
});

test("repeated JSON-tab updates preserve input and clear stale formatted output", () => {
  const { context, values, elements } = fixture();
  context.hasher.tab = context.tabs.json;
  for (const input of ['{"id":9007199254740993}', '{"name":"O\'Reilly"}', "{broken}", "[]"]) {
    values.set("#input-value", input);
    context.hasher.update();
    for (const element of [elements.json1, elements.json2]) {
      assert.equal(values.get(`#${element.id}`), element.calculate(input));
    }
    assert.equal(values.get("#input-value"), input);
  }
});
