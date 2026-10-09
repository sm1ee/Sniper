// What the response Render view decides to show. No app startup, API, or DOM;
// the sandboxing itself is checked in a browser.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const loaded = loadFunctions(["responseRenderModel"]);
// The function runs in another realm; copy its result so deepEqual compares values.
const responseRenderModel = (response) => ({ ...loaded.responseRenderModel(response) });

const html = (overrides = {}) => ({
  content_type: "text/html; charset=utf-8",
  body_encoding: "utf8",
  body_preview: "<h1>Hello</h1>",
  preview_truncated: false,
  ...overrides,
});

test("an HTML response is rendered", () => {
  assert.deepEqual(responseRenderModel(html()), { html: "<h1>Hello</h1>", truncated: false });
  assert.equal(responseRenderModel(html({ content_type: "Application/XHTML+XML" })).html, "<h1>Hello</h1>");
});

test("a cut body is flagged rather than refused", () => {
  assert.deepEqual(responseRenderModel(html({ preview_truncated: true })), { html: "<h1>Hello</h1>", truncated: true });
});

test("each reason for not rendering is explained", () => {
  assert.match(responseRenderModel(null).note, /no response/);
  assert.match(responseRenderModel(html({ content_type: "application/json" })).note, /application\/json/);
  assert.match(responseRenderModel(html({ content_type: null })).note, /untyped/);
  assert.match(responseRenderModel(html({ body_encoding: "base64" })).note, /binary/);
  assert.match(responseRenderModel(html({ body_preview: "" })).note, /no body/);
});
