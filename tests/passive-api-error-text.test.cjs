// Offline error-presentation checks. No app startup, API calls, or real data.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function fixture() {
  return loadFunctions([
    "formatStructuredApiErrorMessage", "readApiErrorMessage", "requireOkResponse",
  ]);
}

const fallback = "Could not load fixture.";
const response = (body, contentType = "text/plain") => new Response(body, {
  status: 500,
  headers: { "content-type": contentType },
});

for (const [label, body] of [
  ["spaces", "   "],
  ["line breaks and tabs", " \r\n\t "],
  ["Unicode whitespace", "\u00a0\u2003"],
]) {
  for (const contentType of ["text/plain", "application/json"]) {
    test(`${contentType} error body containing only ${label} uses the fallback`, async () => {
      const c = fixture();
      assert.equal(await c.readApiErrorMessage(response(body, contentType), fallback), fallback);
    });
  }
}

test("requireOkResponse reports the fallback for a whitespace-only failure", async () => {
  const c = fixture();
  await assert.rejects(c.requireOkResponse(response(" \r\n\t "), fallback), {
    message: fallback,
  });
});

for (const contentType of ["text/plain", "application/json"]) {
  test(`${contentType} nonblank text retains every original character`, async () => {
    const c = fixture();
    const body = " \t\u00a0Read failed\r\n  Details: fixture \u2003\n";
    assert.equal(await c.readApiErrorMessage(response(body, contentType), fallback), body);
  });

  test(`${contentType} empty body uses the supplied fallback`, async () => {
    const c = fixture();
    assert.equal(await c.readApiErrorMessage(response("", contentType), fallback), fallback);
  });
}

for (const [label, payload, expected] of [
  ["null", null, ""],
  ["string", "Read failed", ""],
  ["number", 42, ""],
  ["boolean", false, ""],
  ["array", [], ""],
  ["missing error", {}, ""],
  ["null error", { error: null }, ""],
  ["numeric error", { error: 42 }, ""],
  ["object error", { error: {} }, ""],
  ["array error", { error: [] }, ""],
  ["blank error", { error: " \t\n" }, ""],
  ["trimmed error", { error: " \tRead failed\n" }, "Read failed"],
  ["owner precedence", { error: "Read failed", owner_session_id: " owner-a ", session_id: "session-b" }, "Read failed (owner_session_id owner-a)"],
  ["blank owner fallback", { error: "Read failed", owner_session_id: " \t ", session_id: " session-b\n" }, "Read failed (session_id session-b)"],
  ["invalid owner fallback", { error: "Read failed", owner_session_id: 42, session_id: "session-b" }, "Read failed (session_id session-b)"],
  ["invalid identifiers", { error: "Read failed", owner_session_id: [], session_id: {} }, "Read failed"],
  ["identifiers without error", { owner_session_id: "owner-a", session_id: "session-b" }, ""],
  ["embedded newlines", { error: "line one\nline two" }, "line one\nline two"],
]) {
  test(`structured error formatting handles ${label}`, () => {
    const c = fixture();
    assert.equal(c.formatStructuredApiErrorMessage(payload), expected);
  });
}

for (const [label, body, contentType, expected] of [
  ["structured JSON", '{"error":"Read failed","session_id":"session-a"}', "application/json", "Read failed (session_id session-a)"],
  ["case-insensitive JSON with charset", '{"error":"Read failed"}', "Application/JSON; Charset=UTF-8", "Read failed"],
  ["JSON-looking plain text", '{"error":"Read failed"}', "text/plain", '{"error":"Read failed"}'],
  ["malformed JSON", ' \n{"error":\t ', "application/json", ' \n{"error":\t '],
  ["unsupported JSON shape", '{"message":"Other shape"}', "application/json", '{"message":"Other shape"}'],
  ["invalid structured error type", '{"error":42}', "application/json", '{"error":42}'],
  ["blank structured error", '{"error":"   "}', "application/json", '{"error":"   "}'],
  ["JSON string", '"Read failed"', "application/json", '"Read failed"'],
  ["JSON null", "null", "application/json", "null"],
  ["JSON array", "[]", "application/json", "[]"],
]) {
  test(`error text retains existing handling for ${label}`, async () => {
    const c = fixture();
    assert.equal(await c.readApiErrorMessage(response(body, contentType), fallback), expected);
  });
}

test("structured JSON errors are read from a clone and preserve the original body", async () => {
  const c = fixture();
  const body = '{"error":"Read failed"}';
  const res = response(body, "application/json");
  assert.equal(await c.readApiErrorMessage(res, fallback), "Read failed");
  assert.equal(res.bodyUsed, false);
  assert.equal(await res.text(), body);
});

for (const contentType of ["text/plain", "application/json"]) {
  test(`${contentType} fallback reads the original body and tolerates an already-consumed response`, async () => {
    const c = fixture();
    const body = "Read failed";
    const res = response(body, contentType);
    assert.equal(await c.readApiErrorMessage(res, fallback), body);
    assert.equal(res.bodyUsed, true);
    assert.equal(await c.readApiErrorMessage(res, fallback), fallback);
  });
}

test("unreadable JSON and plain-text fallback bodies use the supplied fallback", async () => {
  const c = fixture();
  const body = new ReadableStream({
    start(controller) { controller.error(new Error("Synthetic read failure")); },
  });
  assert.equal(await c.readApiErrorMessage(response(body, "application/json"), fallback), fallback);
});

test("an absent body and omitted fallback return an empty message", async () => {
  const c = fixture();
  assert.equal(await c.readApiErrorMessage(response(null)), "");
});

test("requireOkResponse leaves successful response bodies unread", async () => {
  const c = fixture();
  const res = new Response('{"value":"fixture"}', { status: 200 });
  assert.equal(await c.requireOkResponse(res, fallback), undefined);
  assert.equal(res.bodyUsed, false);
});
