// The finding description strip showed two lines of any detail, so a known-
// vulnerability finding's advisory list, and a template's references, could
// not be read in the UI.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function render(detail) {
  const desc = { innerHTML: "" };
  const c = loadFunctions(
    ["renderFindingDescription", "normalizeFindingLocation", "formatFindingLocationLabel", "escapeHtml"],
    { els: { findingsDetailDesc: desc } },
  );
  c.renderFindingDescription({ detail });
  return desc.innerHTML;
}

test("a one-line detail stays a clamped line", () => {
  const html = render("Server banner names nginx 1.18.0.");
  assert.match(html, /<span class="findings-desc-text">Server banner names nginx 1\.18\.0\.<\/span>/);
  assert.doesNotMatch(html, /<details/);
});

test("a longer detail opens from its first line, line breaks kept and text escaped", () => {
  const html = render("Tentative: matched on the version string alone (jQuery 3.4.1).\n\nCVE-2020-11023 · medium · KEV\n<img src=x onerror=alert(1)>");
  assert.match(html, /<details class="findings-desc-more"><summary class="findings-desc-summary">Tentative: matched on the version string alone \(jQuery 3\.4\.1\)\.<\/summary>/);
  assert.match(html, /<div class="findings-desc-rest">\nCVE-2020-11023 · medium · KEV\n&lt;img src=x onerror=alert\(1\)&gt;<\/div><\/details>/);
  const css = require("node:fs").readFileSync(require("node:path").join(__dirname, "../web/styles.css"), "utf8").replace(/\r\n/g, "\n");
  assert.match(css, /\.findings-desc-rest \{[^}]*white-space: pre-line;/);
});
