const assert = require("node:assert/strict");
const test = require("node:test");
const { fixture } = require("./decoder-numeric-fixture.cjs");

test("IPv4 decimal bounds include zero and 2^32 - 1 but exclude 2^32", () => {
  const { context, elements } = fixture();
  const calc = new context.ipCalc();
  for (const [input, ip, octets] of [
    ["0", 0, "0.0.0.0"], ["1", 1, "0.0.0.1"],
    ["4294967294", 4294967294, "255.255.255.254"],
    ["4294967295", 4294967295, "255.255.255.255"],
  ]) {
    calc.parse(input);
    assert.equal(calc.isIpValid(), true, input);
    assert.equal(calc.getIp(), ip, input);
    assert.equal(elements.net1.calculate(input), ip, input);
    assert.equal(elements.net2.calculate(input), octets, input);
  }
  for (const input of ["4294967296", "4294967297", "999999999999999999999999999999"]) {
    calc.parse(input);
    assert.equal(calc.isIpValid(), false, input);
    assert.equal(calc.getIp(), null, input);
    assert.equal(elements.net2.calculate(input), "Invalid IP", input);
    for (const id of ["net1", "net3", "net4"]) assert.equal(elements[id].calculate(input), "", `${id}: ${input}`);
  }
});

test("IPv4 invalid decimal clears prior network calculations and later valid input recovers", () => {
  const { context } = fixture();
  const calc = new context.ipCalc("192.0.2.42/24");
  assert.equal(calc.intToOctetString(calc.getNetwork()), "192.0.2.0");
  calc.parse("4294967296");
  for (const getter of ["getIp", "getNetmask", "getNetwork", "getBroadcast", "gethHostMin", "gethHostMax"]) {
    assert.equal(calc[getter](), null, getter);
  }
  assert.equal(calc.isIpValid(), false);
  calc.parse("4294967295");
  assert.equal(calc.getIp(), 4294967295);
  assert.equal(calc.isIpValid(), true);
});

test("Net updates clear stale outputs at the IPv4 boundary and recover", () => {
  const { update, values } = fixture();
  const subnet = update("net", "192.0.2.42/24");
  assert.equal(subnet.net5, "192.0.2.0/255.255.255.0");
  assert.equal(subnet.net9, "254");
  for (const input of ["4294967296", "4294967297"]) {
    const invalid = update("net", input);
    for (const [id, value] of Object.entries(invalid)) assert.equal(value, id === "net2" ? "Invalid IP" : "", id);
    assert.equal(values.get("#input-value"), input);
    const max = update("net", "4294967295");
    assert.equal(max.net1, "4294967295");
    assert.equal(max.net2, "255.255.255.255");
    assert.equal(max.net3, "1".repeat(32));
    assert.equal(max.net4, "ffffffff");
    for (const id of ["net5", "net6", "net7", "net8", "net9"]) assert.equal(max[id], "", id);
  }
  assert.equal(update("net", "0").net2, "0.0.0.0");
});
