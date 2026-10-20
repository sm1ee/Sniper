const assert = require("node:assert/strict");
const test = require("node:test");
const { fixture } = require("./decoder-numeric-fixture.cjs");

test("Hex to Dec accepts uppercase and mixed-case hexadecimal digits", () => {
  const { context, elements } = fixture();
  for (const [input, expected] of [["ff", "255"], ["FF", "255"], ["fF", "255"], ["00FF", "255"],
    ["aBcDeF", "11259375"], ["ABCDEF", "11259375"], ["0", "0"], ["0000", "0"],
    ["FFFFFFFF", "4294967295"], ["1FFFFFFFFFFFFF", "9007199254740991"]]) {
    assert.equal(context.numbers.hexToDec(input), expected, input);
    assert.equal(elements.n6.calculate(input), expected, input);
  }
});

test("Hex to Dec keeps its empty, prefix, sign, whitespace, and range policy", () => {
  const { context, elements } = fixture();
  assert.equal(context.numbers.hexToDec(""), "");
  for (const input of ["0xff", "0XFF", " FF", "FF ", "FF\n", "\tFF", "F F", "+FF", "-FF",
    "ff.0", "FG", "0b11z", "ＦＦ", "1_00"]) {
    assert.equal(context.numbers.hexToDec(input), "NaN", JSON.stringify(input));
    assert.equal(elements.n6.calculate(input), "NaN", JSON.stringify(input));
  }
  for (const input of ["20000000000000", "FFFFFFFFFFFFFF", "F".repeat(400)]) {
    assert.equal(context.numbers.hexToDec(input), "Out of range", input);
    assert.equal(context.numbers.hexToDec(input.toLowerCase()), "Out of range", input);
  }
  assert.equal(context.numbers.decToHex("255"), "ff");
  assert.equal(context.numbers.decToBin("255"), "11111111");
  assert.equal(context.numbers.binToDec("11111111"), "255");
  assert.equal(context.numbers.decToHex("FF"), "NaN");
  assert.equal(context.numbers.binToDec("FF"), "NaN");
});

test("Hex decimal round trips accept either letter case throughout the byte range", () => {
  const { context } = fixture();
  for (let value = 0; value < 256; value++) {
    const input = String(value);
    const hex = context.numbers.decToHex(input);
    assert.equal(context.numbers.hexToDec(hex.toUpperCase()), input, hex);
  }
});

test("Numbers updates replace malformed and out-of-range results and recover", () => {
  const { update, values } = fixture();
  for (const [input, expected] of [["FF", "255"], ["0XFF", "NaN"], ["fF", "255"],
    ["FFFFFFFFFFFFFF", "Out of range"], ["00FF", "255"], ["", ""], ["aB", "171"]]) {
    assert.equal(update("number", input).n6, expected, input);
    assert.equal(values.get("#input-value"), input);
  }
});
