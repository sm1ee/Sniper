// Render draws a page, an image or a file to save. For a response in text that
// Pretty shows whole it only said it had nothing to draw, so it is hidden
// there, and a choice of Render shows such a response in Pretty.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const json = { content_type: "application/json", body_preview: "{\"a\":1}", body_encoding: "utf8" };
const html = { content_type: "text/html; charset=utf-8", body_preview: "<p>hi</p>", body_encoding: "utf8" };
const pdf = { content_type: "application/pdf", body_preview: "JVBERi0=", body_encoding: "base64" };
const svg = { content_type: "image/svg+xml", body_preview: "<svg/>", body_encoding: "utf8" };

test("Render is offered for pages, images and files, not for text Pretty shows", () => {
  const { shownResponseView } = loadFunctions(["shownResponseView", "responseRenders"]);
  assert.equal(shownResponseView("render", html), "render");
  assert.equal(shownResponseView("render", svg), "render");
  assert.equal(shownResponseView("render", pdf), "render", "a file to save");
  assert.equal(shownResponseView("render", json), "pretty");
  assert.equal(shownResponseView("render", { ...html, body_preview: "" }), "pretty", "nothing to draw");
  assert.equal(shownResponseView("render", null), "pretty");
  assert.equal(shownResponseView("raw", json), "raw", "other choices stand");
});

function tab(attrs) {
  const classes = new Set(attrs.active ? ["active"] : []);
  return { dataset: attrs.dataset, hidden: false,
    classList: { toggle: (name, on) => (on ? classes.add(name) : classes.delete(name)), contains: (name) => classes.has(name) } };
}

test("Replay hides Render for a JSON response and shows Pretty as chosen, keeping Render for the next page", () => {
  const tabs = ["pretty", "raw", "hex", "render"].map((view) => tab({ dataset: { replayTarget: "response", replayView: view } }));
  const state = { replayMessageViews: { request: "pretty", response: "render" }, replayTabs: [] };
  let record = { response: json };
  const c = loadFunctions(["renderReplayViewTabs", "shownResponseView", "responseRenders"], {
    state, document: { querySelectorAll: () => tabs }, getActiveReplayTab: () => ({ responseRecord: record }),
  });
  c.renderReplayViewTabs();
  const shown = () => tabs.filter((t) => !t.hidden).map((t) => `${t.dataset.replayView}${t.classList.contains("active") ? "*" : ""}`);
  assert.deepEqual(shown(), ["pretty*", "raw", "hex"]);
  assert.equal(state.replayMessageViews.response, "render", "the choice stands");
  record = { response: html };
  c.renderReplayViewTabs();
  assert.deepEqual(shown(), ["pretty", "raw", "hex", "render*"]);
});

test("the Fuzzer's result detail and History hide it the same way", () => {
  const fuzzerTabs = ["pretty", "raw", "hex", "render"].map((view) => tab({ dataset: { fuzzerDetailTarget: "response", fuzzerDetailView: view } }));
  const f = loadFunctions(["syncFuzzerDetailTabs", "shownResponseView", "responseRenders"], {
    document: { querySelectorAll: () => fuzzerTabs }, state: { _fuzzerDetailRecord: { response: json } },
  });
  vm.runInContext('var _fuzzerDetailViewModes = { request: "pretty", response: "render" };', f);
  f.syncFuzzerDetailTabs();
  assert.deepEqual(fuzzerTabs.filter((t) => !t.hidden).map((t) => `${t.dataset.fuzzerDetailView}${t.classList.contains("active") ? "*" : ""}`),
    ["pretty*", "raw", "hex"]);

  const historyTabs = ["pretty", "raw", "hex", "render"].map((view) => tab({ dataset: { target: "response", view } }));
  const toggle = () => ({ classList: { toggle() {} } });
  const h = loadFunctions(["renderViewTabs", "shownResponseView", "responseRenders"], {
    state: { selectedRecord: { response: json }, messageViews: { request: "pretty", response: "render" }, showOriginal: {} },
    viewTabs: historyTabs, els: { requestMrToggle: toggle(), responseMrToggle: toggle() },
    document: { querySelectorAll: () => [] },
  });
  h.renderViewTabs();
  assert.deepEqual(historyTabs.filter((t) => !t.hidden).map((t) => `${t.dataset.view}${t.classList.contains("active") ? "*" : ""}`),
    ["pretty*", "raw", "hex"]);
});
