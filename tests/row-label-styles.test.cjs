// Stylesheet text only: how per-row labels read in History and Scope.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

// Windows checkouts use CRLF; the rules below are matched line by line.
const css = fs.readFileSync(path.join(__dirname, "../web/styles.css"), "utf8").replace(/\r\n/g, "\n");
const rule = (selector) => css.match(new RegExp(`^${selector.replace(/[.()[\]]/g, "\\$&")} \\{([^}]*)\\}`, "m"))?.[1] ?? "";

// A bordered pill on every row was louder than the data, as it was for
// Method and Status before them.
test("History's TLS reads as toned text like Method, not a pill", () => {
  assert.doesNotMatch(css, /^\.tls-badge,$/m, "TLS is no longer in the pill group");
  const tls = rule(".tls-badge");
  assert.match(tls, /font-weight: 600;/);
  assert.doesNotMatch(tls, /border|background|border-radius|padding/);
  assert.match(rule(".tls-badge.empty"), /color: var\(--text-dim\);/);
});

// In scope is gold in the Map inspector; the Scope site map now matches it.
test("Scope's site map marks in-scope hosts in the Map inspector's gold", () => {
  const gold = css.match(/((?:^[^{}\n]+,\n)*^[^{}\n]+) \{ color: var\(--point\); background: var\(--point-soft\); border-color: var\(--point-border\); \}/m)?.[1] ?? "";
  assert.match(gold, /\.service-map-detail \.detail-chip\.ok/);
  assert.match(gold, /\.target-host-actions \.detail-chip\.ok/);
});

test("shared app surfaces use flat theme fills without decorative gloss", () => {
  const body = css.match(/^html,\nbody \{([^}]*)\}/m)[1];
  const controls = css.match(/^\.metric-pill,\n\.utility-button,\n\.status-pill \{([^}]*)\}/m)[1];
  assert.match(body, /background: var\(--bg\);/);
  assert.match(controls, /background: var\(--panel-elevated\);/);
  for (const block of [body, controls, rule(".placeholder-card"), rule(".modal-card"), rule(".primary-action")]) {
    assert.doesNotMatch(block, /(?:radial|linear)-gradient/);
  }
  assert.doesNotMatch(controls, /box-shadow:/);
  assert.doesNotMatch(rule(".placeholder-card"), /box-shadow:/);
  assert.match(rule(".modal-card"), /box-shadow: var\(--shadow\);/, "floating dialogs retain depth");
  assert.match(rule(".primary-action"), /background: var\(--point-soft\);/);
  assert.match(rule(".primary-action"), /border-color: var\(--point-border\);/);
});

test("functional progress, selection and keyboard focus cues remain", () => {
  assert.match(rule(".templates-progress:indeterminate"), /linear-gradient\(90deg, transparent, var\(--point\), transparent\)/);
  assert.match(rule(".templates-progress:indeterminate"), /animation: templates-progress-slide/);
  assert.match(rule(".service-map-card.selected"), /background: linear-gradient\(var\(--point-soft\), var\(--point-soft\)\), var\(--panel\)/);
  assert.match(rule(".tools-output-list .value:focus-within"), /outline: 2px solid var\(--point\)/);
  assert.match(css, /\.primary-action:disabled,[\s\S]*?opacity: 0\.35/);
});

function themeProperties(block) {
  return Object.fromEntries([...block.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)].map(match => [match[1], match[2].trim()]));
}
function rgba(value) {
  if (value.startsWith("#")) {
    let hex = value.slice(1);
    if (hex.length === 3) hex = [...hex].map(char => char + char).join("");
    assert.equal(hex.length, 6);
    return [0, 2, 4].map(index => parseInt(hex.slice(index, index + 2), 16) / 255).concat(1);
  }
  const values = value.match(/[\d.]+/g).map(Number);
  return values.slice(0, 3).map(number => number / 255).concat(values[3] ?? 1);
}
function composite(foreground, background) {
  return foreground.slice(0, 3).map((channel, index) => channel * foreground[3] + background[index] * (1 - foreground[3]));
}
function luminance(color) {
  return color.slice(0, 3).reduce((sum, channel, index) => sum + [0.2126, 0.7152, 0.0722][index]
    * (channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4), 0);
}
function contrast(a, b) {
  const values = [luminance(a), luminance(b)].sort((x, y) => x - y);
  return (values[1] + 0.05) / (values[0] + 0.05);
}

test("flat primary and utility fills retain normal text contrast in all twelve themes", () => {
  const defaults = themeProperties(css.match(/:root\s*\{([^}]+)\}/)[1]);
  const themes = [["charcoal", defaults], ...[...css.matchAll(/body\[data-theme="([^"]+)"\]\s*\{([^}]+)\}/g)]
    .map(match => [match[1], { ...defaults, ...themeProperties(match[2]) }])];
  assert.equal(themes.length, 12);
  for (const [name, theme] of themes) {
    const text = rgba(theme["--text"]);
    assert.match(rule(".metric-pill span"), /color: var\(--text-soft\);/);
    assert.ok(contrast(rgba(theme["--text-soft"]), rgba(theme["--panel-elevated"])) >= 4.5, `${name}: metric caption`);
    assert.ok(contrast(text, rgba(theme["--panel-elevated"])) >= 4.5, `${name}: utility label`);
    for (const surface of ["--bg", "--shell", "--panel", "--panel-elevated"]) {
      const fill = composite(rgba(theme["--point-soft"]), rgba(theme[surface]));
      assert.ok(contrast(text, fill) >= 4.5, `${name}: primary label over ${surface}`);
    }
  }
});


test("only the six named work-pane surfaces share a flat medium-radius treatment", () => {
  const selectors = [
    "#matchReplacePanel > .split-panel > .panel-card",
    "#fuzzerShell .fuzzer-top-row > .fuzzer-template-card",
    "#fuzzerShell .fuzzer-top-row > .fuzzer-payloads-card",
    "#fuzzerShell > .fuzzer-layout > .fuzzer-results-card",
    "#templatesShell > .templates-side",
    "#templatesShell > .templates-list",
  ];
  const block = css.slice(css.indexOf(selectors[0]));
  assert.equal(block.trim(), `${selectors.join(",\n")} {\n  background: var(--panel);\n  border-radius: var(--radius-md);\n}`);
  assert.match(css, /--radius-md: 10px;/);
  assert.match(css, /--radius-lg: 16px;/);
  assert.match(rule(".templates-side .panel-card"), /border-radius: 0; background: none;/);
});
