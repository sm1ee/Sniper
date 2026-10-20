const assert = require("node:assert/strict");
const test = require("node:test");
const { fixture } = require("./decoder-numeric-fixture.cjs");

const timeIds = ["time1", "time2", "time3", "time31", "time4", "time5"];
const vectors = [
  ["-1", "1969-12-31T23:59:59.000Z", "1969-12-31 18:59:59"],
  ["-0.5", "1969-12-31T23:59:59.500Z", "1969-12-31 18:59:59"],
  ["-0.001", "1969-12-31T23:59:59.999Z", "1969-12-31 18:59:59"],
  ["0", "1970-01-01T00:00:00.000Z", "1969-12-31 19:00:00"],
  ["1.5", "1970-01-01T00:00:01.500Z", "1969-12-31 19:00:01"],
  ["+1.5", "1970-01-01T00:00:01.500Z", "1969-12-31 19:00:01"],
  ["+1", "1970-01-01T00:00:01.000Z", "1969-12-31 19:00:01"],
  ["0001.500", "1970-01-01T00:00:01.500Z", "1969-12-31 19:00:01"],
  ["1700000000.5", "2023-11-14T22:13:20.500Z", "2023-11-14 17:13:20"],
  ["1721044800", "2024-07-15T12:00:00.000Z", "2024-07-15 08:00:00"],
];

function inZone(zone, fn) {
  const previous = process.env.TZ;
  process.env.TZ = zone;
  try {
    assert.equal(new Date("2024-07-15T12:00:00Z").getTimezoneOffset(), zone === "UTC" ? 0 : 240);
    fn();
  } finally {
    if (previous === undefined) delete process.env.TZ;
    else process.env.TZ = previous;
  }
}

function expectedTime(iso, local) {
  const date = new Date(iso);
  return {
    time1: date.getTime() / 1000,
    time2: date.toLocaleString(),
    time3: local,
    time31: iso.slice(0, 19).replace("T", " "),
    time4: date.toUTCString(),
    time5: iso,
  };
}

for (const zone of ["UTC", "America/New_York"]) {
  test(`all six Time converters recognize signed/fractional Unix seconds in ${zone}`, () => inZone(zone, () => {
    const { elements } = fixture();
    for (const [input, iso, newYork] of vectors) {
      const local = zone === "UTC" ? iso.slice(0, 19).replace("T", " ") : newYork;
      const expected = expectedTime(iso, local);
      for (const id of timeIds) assert.equal(elements[id].calculate(input), expected[id], `${id}: ${input}`);
    }
  }));

  test(`Time outputs round-trip pre-epoch and fractional instants in ${zone}`, () => inZone(zone, () => {
    const { elements } = fixture();
    for (const [, iso] of vectors) {
      const unix = elements.time1.calculate(iso);
      assert.equal(unix, new Date(iso).getTime() / 1000);
      assert.equal(elements.time5.calculate(String(unix)), iso);
      assert.equal(elements.time1.calculate(String(unix)), unix);
      // RFC-1123 intentionally has only whole-second precision.
      const rfc = elements.time4.calculate(String(unix));
      assert.equal(elements.time1.calculate(rfc), Math.floor(unix));
    }
  }));

  test(`Time preserves date-text parsing and does not broaden numeric syntax in ${zone}`, () => inZone(zone, () => {
    const { elements } = fixture();
    for (const input of ["2023-11-14T22:13:20.500Z", "2023-11-14T17:13:20.500-05:00",
      "Tue, 14 Nov 2023 22:13:20 GMT", "2023-11-14 17:13:20", "2024-07-15T08:00:00",
      " 1 ", "1\n", "1.5\n", "\t1.5", "1.", ".5", "0x10", "1e3", "1e-3",
      "Infinity", "NaN", "not a date", "1.5seconds", "--1", "+-1", "1.2.3", "", " \t\n"]) {
      const date = new Date(input);
      const valid = !isNaN(date.getTime());
      assert.equal(elements.time1.calculate(input), valid ? date.getTime() / 1000 : "", JSON.stringify(input));
      assert.equal(elements.time5.calculate(input), valid ? date.toISOString() : "", JSON.stringify(input));
    }
  }));

  test(`Time retains millisecond precision and Date range limits in ${zone}`, () => inZone(zone, () => {
    const { elements } = fixture();
    for (const [input, iso] of [
      ["1.2345", "1970-01-01T00:00:01.234Z"],
      ["-1.2345", "1969-12-31T23:59:58.766Z"],
      ["8640000000000", "+275760-09-13T00:00:00.000Z"],
      ["-8640000000000", "-271821-04-20T00:00:00.000Z"],
    ]) assert.equal(elements.time5.calculate(input), iso, input);
    for (const input of ["8640000000001", "-8640000000001", "9".repeat(400)]) {
      for (const id of timeIds) assert.equal(elements[id].calculate(input), "", `${id}: ${input}`);
    }
  }));

  test(`Time updates replace every stale output and preserve input in ${zone}`, () => inZone(zone, () => {
    const { update, values } = fixture();
    for (const [input, iso, newYork] of [vectors[0], ["not a date"], vectors[8], [""], vectors[3]]) {
      const local = zone === "UTC" && iso ? iso.slice(0, 19).replace("T", " ") : newYork;
      const expected = iso ? expectedTime(iso, local) : Object.fromEntries(timeIds.map(id => [id, ""]));
      const outputs = update("time", input);
      for (const id of timeIds) assert.equal(outputs[id], String(expected[id]), `${id}: ${input}`);
      assert.equal(values.get("#input-value"), input);
    }
  }));
}
