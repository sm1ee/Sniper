const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// Windows checkouts use CRLF, while fixture source markers use LF. Normalize
// source text only; escaped line endings in runtime payloads stay untouched.
const appSource = fs.readFileSync(path.join(__dirname, "../web/app.js"), "utf8").replace(/\r\n/g, "\n");

// Load only the named functions: running app.js itself would start the UI and
// make API requests. Top-level functions in this file end at column zero.
function loadFunctions(names, globals = {}) {
  const context = vm.createContext({ console, ...globals });
  const hexCallers = ["replayRequestHexText", "renderReplay", "renderReplayResponseOnly", "renderReplayViewContent", "updateReplaySearchPane"];
  if (names.some(name => hexCallers.includes(name))) {
    names = [...new Set([...names, "replayHexTextSource", "replayHexPageText", "syncReplayHexPager"])];
  }
  const replaySizeCallers = ["createReplayTab", "applyCurlImport", "syncReplayRequestTextFromEditor", "preserveActiveHttpReplayDraftBeforeNavigation", "renderReplay", "changeReplayMethod", "setReplayHeader", "saveWorkspaceState"];
  if (names.some(name => replaySizeCallers.includes(name))) {
    names = [...new Set([...names, "replayRequestSizeError", "canStoreReplayRequest", "replayRequestEditCandidate", "acceptReplayRequestEdit"])];
  }
  // The Replay editor shows a binary body as bytes and keeps the draft in Base64.
  const binaryBodyCallers = ["replayRequestEditorText", "replayEditorShowsDraft", "syncReplayRequestTextFromEditor",
    "changeReplayMethod", "acceptReplayRequestEdit", "renderReplay", "renderReplayViewContent"];
  if (names.some(name => binaryBodyCallers.includes(name))) {
    names = [...new Set([...names, "replayTabBodyIsBinary", "replayDraftFromEditor", "replayDraftShown",
      "rawRequestWithBinaryBody", "rawRequestWithBase64Body", "binaryBodyText", "binaryBodyBase64"])];
  }
  if (names.includes("parseCurlCommand")) names = [...new Set([...names, "parseCurlFormField"])];
  // The Fuzzer editor shows a binary body as bytes and keeps the draft in Base64.
  const fuzzerBodyCallers = ["renderFuzzer", "fuzzerRequestTextForAction", "markFuzzerPosition", "markFuzzerEditorSelection",
    "fuzzerMarkerRemoval", "removeFuzzerEditorPosition", "clearFuzzerMarkers", "runFuzzerAttack", "readFuzzerSavedRun"];
  if (names.some(name => fuzzerBodyCallers.includes(name))) {
    names = [...new Set([...names, "fuzzerBodyIsBinary", "fuzzerShownText", "fuzzerStoredText", "fuzzerDraftShowsBytes",
      "fuzzerMarkerDraft", "fuzzerBaseRequestFor"])];
  }
  // The Session table names a session as the sidebar does.
  if (names.includes("renderDashboard")) names = [...new Set([...names, "sessionIdentity"])];
  // Whatever says where a session's traffic comes from asks these. A fixture
  // that supplies one of its own keeps it.
  const feedCallers = ["renderDashboard", "sessionSidebarRow", "syncHttpCapturePill", "emptySessionMessage",
    "emptySessionActions", "showSessionContextMenu", "sessionFeedMenuItems", "updateProxyStatusIndicator"];
  // An empty history offers what makes traffic reach the session.
  if (names.includes("renderHistory") && !("emptySessionActions" in globals)) names = [...new Set([...names, "emptySessionActions"])];
  if (names.some(name => feedCallers.includes(name))) {
    const feed = ["sessionFeed", "mainProxyPort", "mainListenerSession", "sessionProxyAddress", "recordHereLabel",
      "sessionFeedMenuItems", "sessionMakerMark", "sessionGroupMenuItems"];
    names = [...new Set([...names, ...feed.filter(name => !(name in globals))])];
  }
  // Whatever places a session in the list asks which order the list is in.
  if (names.some(name => ["sessionSidebarLayout", "sidebarDropTarget", "dropSidebarSession"].includes(name))) {
    names = [...new Set([...names, "sessionSortOrder"])];
  }
  // Intercept shows a held binary body as bytes through the raw build and parse.
  const rawBodyCallers = ["buildEditableRawRequest", "parseEditableRawRequest", "buildEditableRawResponse", "parseEditableRawResponse"];
  if (names.some(name => rawBodyCallers.includes(name))) {
    names = [...new Set([...names, "binaryBodyText", "binaryBodyBase64"])];
  }
  for (const name of names) {
    assert.match(name, /^[A-Za-z_$][\w$]*$/);
    const match = appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, "m"));
    assert.ok(match, `Missing frontend function: ${name}`);
    vm.runInContext(match[0], context, { filename: `web/app.js:${name}` });
  }
  // Every Session table redraw redraws the sidebar and shows the page's view,
  // which these fixtures lack.
  for (const drawn of ["renderSessionSidebar", "renderSessionPageView"]) {
    if (names.includes("renderDashboard") && !(drawn in context)) context[drawn] = () => {};
  }
  return context;
}

// An on/off pill button (`setToggleButton`). `checked` is test shorthand for
// its pressed state, so fixtures read like the checkboxes these buttons replaced.
function toggleButton(on = false) {
  const classes = new Set(on ? ["active"] : []);
  const attributes = { "aria-pressed": String(on) };
  return {
    disabled: false, title: "", listeners: {},
    classList: {
      add: name => classes.add(name), remove: name => classes.delete(name), contains: name => classes.has(name),
      toggle(name, force = !classes.has(name)) { if (force) classes.add(name); else classes.delete(name); return force; },
    },
    getAttribute: name => attributes[name] ?? null,
    setAttribute(name, value) { attributes[name] = String(value); },
    addEventListener(name, callback) { this.listeners[name] = callback; },
    get checked() { return classes.has("active"); },
    set checked(value) { this.classList.toggle("active", Boolean(value)); attributes["aria-pressed"] = String(Boolean(value)); },
  };
}

module.exports = { appSource, loadFunctions, toggleButton };
