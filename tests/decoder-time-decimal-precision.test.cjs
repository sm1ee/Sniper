const assert = require("node:assert/strict");
const test = require("node:test");
const { fixture } = require("./decoder-numeric-fixture.cjs");

function inZone(zone, fn) {
  const previous = process.env.TZ;
  process.env.TZ = zone;
  try {
    assert.equal(new Date("2004-06-01T00:00:00Z").getTimezoneOffset(), zone === "UTC" ? 0 : 240);
    fn();
  } finally {
    if (previous === undefined) delete process.env.TZ;
    else process.env.TZ = previous;
  }
}

for (const zone of ["UTC", "America/New_York"]) {
  for (const epoch of [0, 1000, -2000, 1086048000000, -1086048001000, 1700000000000, -1700000001000]) {
    test(`every millisecond at epoch ${epoch} round-trips through all Time outputs in ${zone}`, () => inZone(zone, () => {
      const { update, elements, values } = fixture();
      for (let milliseconds = 0; milliseconds < 1000; milliseconds++) {
        const instant = epoch + milliseconds;
        const iso = new Date(instant).toISOString();
        const fromIso = update("time", iso);
        assert.equal(fromIso.time1, String(instant / 1000), iso);
        assert.equal(elements.time5.calculate(fromIso.time1), iso, fromIso.time1);
        const fromUnix = update("time", fromIso.time1);
        assert.deepEqual(fromUnix, fromIso, `${iso}: ${fromIso.time1}`);
        assert.equal(values.get("#input-value"), fromIso.time1);
      }
    }));
  }

  test(`decimal digits beyond milliseconds truncate toward zero without rounding in ${zone}`, () => inZone(zone, () => {
    const { update, elements } = fixture();
    for (const [input, milliseconds] of [
      ["1.001", 1001], ["-1.001", -1001], ["1.003", 1003], ["-1.003", -1003],
      ["1.2345", 1234], ["-1.2345", -1234],
      ["1.001999", 1001], ["-1.001999", -1001],
      ["1.00099999999999999999999", 1000], ["-1.00099999999999999999999", -1000],
      ["1.99999999999999999999999", 1999], ["-1.99999999999999999999999", -1999],
      ["0.00099999999999999999999", 0], ["-0.00099999999999999999999", 0],
      ["1086048000.001", 1086048000001], ["-1086048000.001", -1086048000001],
      ["1086048000.9999999999999999999", 1086048000999],
      ["-1086048000.9999999999999999999", -1086048000999],
      ["+000000000000000000001.001000000000000000", 1001],
      ["-000000000000000000000.001000000000000000", -1],
    ]) {
      const iso = new Date(milliseconds).toISOString();
      assert.equal(elements.time5.calculate(input), iso, input);
      assert.deepEqual(update("time", input), update("time", iso), input);
    }
  }));

  test(`decimal Time range is checked before sub-millisecond truncation in ${zone}`, () => inZone(zone, () => {
    const { update, elements, values } = fixture();
    for (const [input, milliseconds] of [
      ["8640000000000", 8640000000000000], ["-8640000000000", -8640000000000000],
      ["+08640000000000.000000", 8640000000000000],
      ["-08640000000000.000000", -8640000000000000],
      ["8639999999999.999999999999", 8639999999999999],
      ["-8639999999999.999999999999", -8639999999999999],
    ]) assert.equal(elements.time5.calculate(input), new Date(milliseconds).toISOString(), input);
    for (const input of ["8640000000000.0001", "-8640000000000.0001", "8640000000000.001",
      "-8640000000000.001", "8640000000001", "-8640000000001", "9".repeat(400),
      "-" + "9".repeat(400), "8640000000000." + "0".repeat(400) + "1"]) {
      update("time", "1.001");
      for (const [id, value] of Object.entries(update("time", input))) assert.equal(value, "", `${id}: ${input}`);
      assert.equal(values.get("#input-value"), input);
      assert.equal(update("time", "-1.003").time5, "1969-12-31T23:59:58.997Z");
    }
  }));

  test(`precision parsing preserves nonnumeric date syntax and invalid clearing in ${zone}`, () => inZone(zone, () => {
    const { update, elements } = fixture();
    for (const input of ["2004-06-01T00:00:00.001Z", "2004-06-01T01:00:00.001+01:00",
      "Tue, 01 Jun 2004 00:00:00 GMT", "2004-06-01 00:00:00", "1.001\n", " 1.001 ",
      "1.001e3", "0x1000", ".001", "1.", "--1.001", "+-1.001", "1.001junk", "", " \t\n"]) {
      const date = new Date(input);
      const iso = isNaN(date.getTime()) ? "" : date.toISOString();
      assert.equal(elements.time5.calculate(input), iso, JSON.stringify(input));
      update("time", "1086048000.001");
      assert.equal(update("time", input).time5, iso, JSON.stringify(input));
      assert.equal(update("time", "1086048000.001").time5, "2004-06-01T00:00:00.001Z");
    }
  }));
}
