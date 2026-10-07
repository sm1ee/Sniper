// Saved list metadata only; no scanner, application runtime, or network calls.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const base = "2026-10-07T00:00:00";
const record = (id, found_at, extra = {}) => ({
  id, found_at, severity: "info", category: "header", title: "Saved entry",
  host: "example.com", path: "/saved", ...extra,
});
function fixture(rows, direction = "asc", extra = {}) {
  return loadFunctions(["getFilteredFindings"], {
    findingsData: rows, findingsSortKey: "found_at", findingsSortDir: direction,
    els: {}, SEVERITY_ORDER: { critical: 0, high: 1, medium: 2, low: 3, info: 4 },
    isInScopeHost: host => host === "example.com", ...extra,
  });
}
const ids = rows => Array.from(rows, row => row.id);

// Chrono's AutoSi format uses no fraction, or exactly 3, 6, or 9 digits.
function canonicalTimestamp(nanoseconds) {
  if (nanoseconds === 0) return `${base}Z`;
  const digits = String(nanoseconds).padStart(9, "0");
  const length = nanoseconds % 1000000 === 0 ? 3 : nanoseconds % 1000 === 0 ? 6 : 9;
  return `${base}.${digits.slice(0, length)}Z`;
}

for (const direction of ["asc", "desc"]) {
  for (const [label, earlier, later] of [
    ["whole second before milliseconds", `${base}Z`, `${base}.500Z`],
    ["millisecond prefix before microseconds", `${base}.500Z`, `${base}.500001Z`],
    ["microsecond prefix before nanoseconds", `${base}.500001Z`, `${base}.500001001Z`],
    ["whole second before one nanosecond", `${base}Z`, `${base}.000000001Z`],
    ["adjacent seconds", `${base}.999999999Z`, "2026-10-07T00:00:01Z"],
    ["adjacent days", "2026-10-07T23:59:59.999999999Z", "2026-10-08T00:00:00Z"],
  ]) {
    test(`Findings ${direction}: ${label}`, () => {
      const rows = [record("later", later), record("earlier", earlier)];
      const c = fixture(rows, direction);
      assert.deepEqual(ids(c.getFilteredFindings()), direction === "asc" ? ["earlier", "later"] : ["later", "earlier"]);
    });
  }

  test(`Findings ${direction}: every canonical precision orders by exact nanoseconds`, () => {
    const nanos = [0, 1, 999, 1000, 1001, 999999, 1000000, 1000001, 1000999,
      1001000, 1001001, 99000000, 99999999, 100000000, 100000001, 123000000,
      123001000, 123001001, 500000000, 500001000, 500001001, 999000000, 999999000, 999999999];
    const expected = direction === "asc" ? nanos : [...nanos].reverse();
    for (let shift = 0; shift < nanos.length; shift += 1) {
      const shuffled = nanos.slice(shift).concat(nanos.slice(0, shift)).reverse();
      const c = fixture(shuffled.map(n => record(String(n), canonicalTimestamp(n))), direction);
      assert.deepEqual(ids(c.getFilteredFindings()), expected.map(String));
    }
  });

  test(`Findings ${direction}: equal timestamps retain original row identity and tie order`, () => {
    for (const value of [`${base}Z`, `${base}.500Z`, `${base}.500001Z`, `${base}.500001001Z`]) {
      const rows = [record("third", value), record("first", value), record("second", value)];
      const sorted = fixture(rows, direction).getFilteredFindings();
      assert.deepEqual(ids(sorted), ["third", "first", "second"]);
      rows.forEach((row, index) => assert.equal(sorted[index], row));
    }
  });

  test(`Findings ${direction}: equivalent fraction spellings remain stable ties`, () => {
    for (const values of [
      [`${base}.000000000Z`, `${base}Z`, `${base}.000Z`, `${base}.000000Z`],
      [`${base}.500000000Z`, `${base}.500Z`, `${base}.500000Z`],
    ]) {
      const rows = values.map((value, index) => record(String(index), value));
      assert.deepEqual(ids(fixture(rows, direction).getFilteredFindings()), ids(rows));
    }
  });

  test(`Findings ${direction}: missing and noncanonical values keep legacy fallback comparisons`, () => {
    const values = [undefined, null, "", false, 0, "invalid", "brokenZ", "2026-10-07",
      "2026-10-07T00:00:00.5Z", "2026-10-07T00:00:00.50Z", "2026-10-07T00:00:00.5000Z",
      "2026-10-07T00:00:00.1234567890Z", "2026-10-07T00:00:00+00:00", "+010000-01-01T00:00:00Z"];
    const rows = values.map((value, index) => record(String(index), value));
    const dir = direction === "asc" ? 1 : -1;
    const expected = [...rows].sort((a, b) => {
      const va = a.found_at || "", vb = b.found_at || "";
      return va < vb ? -dir : va > vb ? dir : 0;
    });
    assert.deepEqual(ids(fixture(rows, direction).getFilteredFindings()), ids(expected));
  });

  test(`Findings ${direction}: other sort columns keep existing ordering and stable ties`, () => {
    const rows = [
      record("b", `${base}Z`, { title: "Beta", severity: "low" }),
      record("a", `${base}.500Z`, { title: "alpha", severity: "critical" }),
      record("c", `${base}.500001Z`, { title: "Alpha", severity: "critical" }),
    ];
    for (const key of ["title", "severity"]) {
      const c = fixture(rows, direction, { findingsSortKey: key });
      assert.deepEqual(ids(c.getFilteredFindings()), direction === "asc" ? ["a", "c", "b"] : ["b", "a", "c"]);
    }
  });
}

test("Findings time sorting preserves filters and excludes no additional saved rows", () => {
  const rows = [
    record("late", `${base}.500001Z`, { severity: "high" }),
    record("early", `${base}Z`, { severity: "critical" }),
    record("filtered-severity", `${base}.100Z`, { severity: "info" }),
    record("filtered-category", `${base}.200Z`, { severity: "high", category: "cookie" }),
    record("filtered-search", `${base}.300Z`, { severity: "high", title: "Other item" }),
    record("filtered-scope", `${base}.400Z`, { severity: "high", host: "outside.example.com" }),
  ];
  const c = fixture(rows, "asc", { els: {
    findingsFilterSeverity: { value: "high" }, findingsFilterCategory: { value: "header" },
    findingsFilterSearch: { value: " Saved entry " }, findingsInScopeOnly: { checked: true },
  } });
  assert.deepEqual(ids(c.getFilteredFindings()), ["early", "late"]);
});

test("Findings time sorting does not rewrite timestamps or mutate the source array", () => {
  const rows = Object.freeze([
    Object.freeze(record("late", `${base}.500001Z`)), Object.freeze(record("early", `${base}Z`)),
  ]);
  const before = JSON.stringify(rows);
  const sorted = fixture(rows).getFilteredFindings();
  assert.notEqual(sorted, rows);
  assert.equal(sorted[0], rows[1]);
  assert.equal(sorted[1], rows[0]);
  assert.equal(JSON.stringify(rows), before);
});
