// What the response Render view decides to show. No app startup, API, or DOM;
// the sandboxing itself is checked in a browser.
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const { appSource, loadFunctions } = require("./frontend-test-helpers.cjs");

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

test("a body Render cannot draw, such as a PDF, is offered as a download instead", () => {
  const pdf = { content_type: "application/pdf", body_encoding: "base64", body_preview: "JVBERi0xLjQ=" };
  assert.equal(responseRenderModel(pdf).download, true);
  assert.match(responseRenderModel(pdf).note, /application\/pdf/);
  assert.equal(responseRenderModel(html({ body_encoding: "base64" })).download, true);
  assert.equal(responseRenderModel({ ...pdf, body_preview: "" }).download, undefined, "nothing to save");
  assert.equal(responseRenderModel(html()).download, undefined);
});

test("a download is named from Content-Disposition, then the URL, and never names a path", () => {
  const { downloadFileName } = loadFunctions(["downloadFileName", "normalizedHeaders", "headerNameEquals"], { URL });
  const response = (disposition, type = "application/pdf") => ({
    content_type: type, headers: disposition ? [{ name: "Content-Disposition", value: disposition }] : [],
  });
  assert.equal(downloadFileName(response('attachment; filename="Q3 report.pdf"'), "https://www.example.com/files/x"), "Q3_report.pdf");
  assert.equal(downloadFileName(response("attachment; filename*=UTF-8''%EB%B3%B4%EA%B3%A0%EC%84%9C.pdf"), ""), "보고서.pdf");
  assert.equal(downloadFileName(response(""), "https://www.example.com/files/report.pdf?v=2"), "report.pdf");
  assert.equal(downloadFileName(response('attachment; filename="../../etc/passwd"'), ""), "passwd");
  assert.equal(downloadFileName(response("", "application/pdf"), "https://www.example.com/"), "response.pdf");
  assert.equal(downloadFileName(response("", "application/octet-stream"), "https://www.example.com/"), "response.bin");
  assert.equal(downloadFileName(response('attachment; filename=".hidden"'), ""), "hidden");
});

test("in the desktop app Download stays busy until the save ends, a cancel included", async () => {
  const toasts = [];
  const clicks = [];
  const tick = () => new Promise((resolve) => setTimeout(resolve, 5));
  const c = loadFunctions(["downloadResponseBody", "reportDesktopDownload"], {
    pendingDesktopDownload: null, clearTimeout, Blob,
    // The blob URL is freed a minute later; that timer must not hold the run open.
    setTimeout: (fn, ms) => { const timer = setTimeout(fn, ms); timer.unref(); return timer; },
    window: { ipc: { postMessage() {} } },
    showToast: (...args) => toasts.push(args),
    messageBodyBytes: () => new Uint8Array([37, 80, 68, 70]),
    downloadFileName: () => "report.pdf",
    URL: { createObjectURL: () => "blob:x", revokeObjectURL() {} },
    document: {
      createElement: () => ({ click() { clicks.push(this.download); }, remove() {} }),
      body: { appendChild() {} },
    },
  });
  let settled = false;
  c.downloadResponseBody({}, "").then(() => { settled = true; });
  await tick();
  assert.deepEqual(clicks, ["report.pdf"]);
  assert.equal(settled, false, "still saving");
  c.reportDesktopDownload({ place: null, ok: false });
  await tick();
  assert.equal(settled, true);
  assert.deepEqual(toasts, [], "a cancel in the save panel says nothing");
});

test("the desktop app's download report says where the file went", () => {
  const toasts = [];
  const { reportDesktopDownload } = loadFunctions(["reportDesktopDownload"], { pendingDesktopDownload: null, showToast: (...args) => toasts.push(args) });
  reportDesktopDownload({ place: "~/Downloads/report.pdf", ok: true });
  reportDesktopDownload({ place: "~/Downloads/report.pdf", ok: false });
  assert.equal(toasts[0][0], "Saved to ~/Downloads/report.pdf");
  assert.ok(toasts[0][2] >= 5000, "long enough to read the path");
  assert.equal(toasts[1][0], "Could not save ~/Downloads/report.pdf.");
  assert.equal(toasts[1][1], "error");
});

test("an image response is shown, as Burp's Render tab does", () => {
  const png = responseRenderModel({ content_type: "image/png", body_encoding: "base64", body_preview: "iVBORw0KGgo=", preview_truncated: true });
  assert.deepEqual(png, { image: "data:image/png;base64,iVBORw0KGgo=", truncated: true });
  // SVG arrives as text; it is shown through <img>, where its scripts never run.
  const svg = responseRenderModel({ content_type: "image/svg+xml", body_encoding: "utf8", body_preview: "<svg/>" });
  assert.equal(svg.image, "data:image/svg+xml;charset=utf-8,%3Csvg%2F%3E");
});

// Shaped like what DOMParser returns, enough for the walk over a page's body.
const text = (data) => ({ nodeType: 3, data });
const element = (localName, childNodes = [], attributes = {}) => ({
  nodeType: 1, localName, childNodes, type: attributes.type,
  hasAttribute: (name) => name in attributes,
});
// A Next.js static export: an empty root its scripts fill in, as a real login page shipped.
const scriptShell = () => element("body", [
  element("script", [text("(function(){})();")]),
  element("div", [], { id: "__next", "data-reactroot": "" }),
  element("script", [text('{"props":{"pageProps":{}}}')], { id: "__NEXT_DATA__", type: "application/json" }),
]);
// The real element list, so a tag dropped from it fails here.
const withDrawnElements = (context) => {
  vm.runInContext(appSource.match(/^const RENDER_DRAWN_ELEMENTS = .+;$/m)[0], context);
  return context;
};
const draws = withDrawnElements(loadFunctions(["renderDocumentDraws"])).renderDocumentDraws;

test("a page its scripts build has nothing to draw", () => {
  assert.equal(draws(scriptShell()), false);
  // React streams content in hidden and reveals it with a script.
  assert.equal(draws(element("body", [element("div", [text("Sign in")], { hidden: "" })])), false);
  assert.equal(draws(element("body", [element("style", [text("body{color:red}")]), text(" \n ")])), false);
  assert.equal(draws(element("body", [element("input", [], { type: "hidden" })])), false);
});

test("text and elements that draw without scripts are found at any depth", () => {
  // The sandbox runs no scripts, so <noscript> content is shown.
  assert.equal(draws(element("body", [element("noscript", [text("Enable JavaScript")])])), true);
  assert.equal(draws(element("body", [element("div", [element("span", [text("Sign in")])])])), true);
  assert.equal(draws(element("body", [element("div", [element("img")])])), true);
  assert.equal(draws(element("body", [element("input", [], { type: "email" })])), true);
});

test("the sandboxed document says whether it draws anything", () => {
  const c = withDrawnElements(loadFunctions(["sandboxedResponseDocument", "renderDocumentDraws"], {
    DOMParser: class { parseFromString(html) { return { html, body: html === "shell" ? scriptShell() : element("body", [text("Hi")]) }; } },
    sanitizeRenderDocument() {},
    serializeRenderDocument: (doc) => `safe:${doc.html}`,
  }));
  assert.deepEqual({ ...c.sandboxedResponseDocument("shell") }, { html: "safe:shell", draws: false });
  assert.deepEqual({ ...c.sandboxedResponseDocument("page") }, { html: "safe:page", draws: true });
});

// Render with a fake DOM: only what renderResponsePreview touches.
function renderFixture({ renderResources, draws: drawsSomething }) {
  const node = () => ({ dataset: {}, classList: { toggle() {} }, children: [], replaceChildren(...next) { this.children = next; } });
  const resourcePasses = [];
  const c = loadFunctions(["renderResponsePreview", "responseRenderModel"], {
    state: { displaySettings: { renderResources } },
    document: { createElement: (tag) => ({ tag, isConnected: true, textContent: "", setAttribute() {}, remove() {} }) },
    RENDER_RESOURCE_REFERENCE: /<link\b/,
    currentSessionId: () => "session",
    sandboxedResponseDocument: (doc) => ({ html: `safe:${doc}`, draws: drawsSomething }),
    createRenderResourceFetcher: () => ({ failures: () => 0 }),
    sandboxedResponseDocumentWithResources: (...args) => { resourcePasses.push(args); return new Promise(() => {}); },
  });
  const view = node();
  c.renderResponsePreview({ view, editor: node(), search: {} }, true,
    { response: html({ body_preview: '<link rel="stylesheet" href="/a.css"><div id="__next"></div>' }), key: "1", url: "https://example.com/login" });
  const banners = view.children.filter((child) => child.className === "render-banner").map((child) => child.textContent);
  return { banners, resourcePasses, frame: view.children.find((child) => child.tag === "iframe") };
}

test("an empty page says its scripts draw it instead of pointing at resource loading", () => {
  for (const renderResources of [false, true]) {
    const shown = renderFixture({ renderResources, draws: false });
    assert.equal(shown.frame.srcdoc, 'safe:<link rel="stylesheet" href="/a.css"><div id="__next"></div>');
    assert.deepEqual(shown.banners, ["Nothing to show: this page is drawn by its scripts, which Render does not run."]);
    // Styles cannot draw a page that has nothing in it, so none are fetched.
    assert.equal(shown.resourcePasses.length, 0);
  }
  assert.match(renderFixture({ renderResources: false, draws: true }).banners[0], /not loaded/);
  assert.equal(renderFixture({ renderResources: true, draws: true }).resourcePasses.length, 1);
});
