// Replay's "Change method" menu moves parameters the way Burp's "Change request
// method" does: GET and HEAD carry no body, so a form body becomes the query
// string and any other body is dropped; GET to POST moves the query into a form
// body. Synthetic requests only.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const c = loadFunctions(["requestTextWithMethod", "splitRawHttpMessage", "editableRequestBodyLength"], { TextEncoder });
const lines = (...parts) => parts.join("\n");

test("a form body becomes the query string when the method changes to GET", () => {
  const post = lines(
    "POST /search?lang=en HTTP/1.1",
    "Host: example.com",
    "Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
    "Content-Length: 14",
    "Accept: */*",
    "",
    "q=shoes&page=2",
  );
  assert.equal(c.requestTextWithMethod(post, "GET"), lines(
    "GET /search?lang=en&q=shoes&page=2 HTTP/1.1",
    "Host: example.com",
    "Accept: */*",
  ));
});

test("a body that is not a form is dropped on GET and HEAD, with its headers", () => {
  const post = lines(
    "POST /api/items?limit=5 HTTP/1.1",
    "Host: example.com",
    "content-type: application/json",
    "content-length: 11",
    "",
    "{\"id\": 42}\n",
  );
  const expected = (method) => lines(`${method} /api/items?limit=5 HTTP/1.1`, "Host: example.com");
  assert.equal(c.requestTextWithMethod(post, "HEAD"), expected("HEAD"));
  assert.equal(c.requestTextWithMethod(post, "GET"), expected("GET"));
});

test("characters a request line cannot hold are percent-encoded when a form moves into the query", () => {
  const post = lines(
    "POST /note HTTP/1.1",
    "Host: example.com",
    "Content-Type: application/x-www-form-urlencoded",
    "",
    "text=hello world#1&name=김\r\n",
  );
  assert.equal(c.requestTextWithMethod(post, "GET"), lines(
    "GET /note?text=hello%20world%231&name=%EA%B9%80 HTTP/1.1",
    "Host: example.com",
  ));
});

test("GET to POST moves the query into a form body with its length", () => {
  const get = lines("GET /search?q=shoes&page=2 HTTP/1.1", "Host: example.com", "Content-Type: text/plain");
  assert.equal(c.requestTextWithMethod(get, "POST"), lines(
    "POST /search HTTP/1.1",
    "Host: example.com",
    "Content-Type: application/x-www-form-urlencoded",
    "Content-Length: 14",
    "",
    "q=shoes&page=2",
  ));
});

test("a form survives POST to GET and back", () => {
  const post = lines(
    "POST /login HTTP/1.1",
    "Host: example.com",
    "Content-Type: application/x-www-form-urlencoded",
    "Content-Length: 19",
    "",
    "user=a&next=%2Fhome",
  );
  const back = c.requestTextWithMethod(c.requestTextWithMethod(post, "GET"), "POST");
  assert.equal(back, lines(
    "POST /login HTTP/1.1",
    "Host: example.com",
    "Content-Type: application/x-www-form-urlencoded",
    "Content-Length: 19",
    "",
    "user=a&next=%2Fhome",
  ));
});

test("other changes only replace the method", () => {
  const json = "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{\"a\":1}";
  assert.equal(c.requestTextWithMethod(json, "PUT"), json.replace("POST", "PUT"));
  const query = lines("GET /items?id=7 HTTP/1.1", "Host: example.com");
  assert.equal(c.requestTextWithMethod(query, "DELETE"), query.replace("GET", "DELETE"));
  assert.equal(c.requestTextWithMethod(query, "HEAD"), query.replace("GET", "HEAD"));
  const plain = lines("GET /items HTTP/1.1", "Host: example.com");
  assert.equal(c.requestTextWithMethod(plain, "POST"), plain.replace("GET", "POST"));
  const empty = lines("POST /items HTTP/1.1", "Host: example.com", "", "");
  assert.equal(c.requestTextWithMethod(empty, "GET"), empty.replace("POST", "GET"));
});

test("the menu applies the change to the tab and clears its stale response", () => {
  const tab = { id: "r1", requestText: lines("POST /a HTTP/1.1", "Host: example.com", "Content-Type: application/x-www-form-urlencoded", "", "b=1") };
  const calls = [];
  const menu = loadFunctions(["changeReplayMethod", "requestTextWithMethod", "splitRawHttpMessage", "editableRequestBodyLength",
    "replayEditorShowsDraft", "replayRequestTextsEquivalent", "replayRequestEditorText"], {
    TextEncoder,
    state: { activeReplayTabId: "other", replayMessageViews: { request: "raw" } },
    els: {},
    getReplayTabById: () => tab,
    getCMView: () => null,
    clearReplayResponseForDraftChange: () => calls.push("clear"),
    syncReplayRequestEditorForTab: () => calls.push("sync"),
    scheduleWorkspaceStateSave: () => calls.push("save"),
  });
  menu.changeReplayMethod("GET", "r1");
  assert.equal(tab.requestText, lines("GET /a?b=1 HTTP/1.1", "Host: example.com"));
  assert.deepEqual(calls, ["clear", "sync", "save"]);
});
