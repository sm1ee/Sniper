// Scope shows its rules and paths together; the Map tool's view strip
// uses the same density rules as existing Capture tabs.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

// Windows checkouts end lines in CRLF; the shell match below spans lines.
const read = (file) => fs.readFileSync(path.join(__dirname, file), 'utf8').replace(/\r\n/g, '\n');
const html = read('../web/index.html');
const css = read('../web/styles.css');
const app = read('../web/app.js');
const header = html.match(/<header class="target-workspace-header">([^]*?)<\/header>/)?.[1];
const scopeShell = html.match(/<section class="target-shell hidden" id="targetShell">([^]*?)\n        <\/section>\n/)?.[1];
const rule = (selector, expectedDefinitions = 1) => {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const matches = [...css.matchAll(new RegExp(`${escaped}\\s*\\{([^}]+)\\}`, 'g'))];
  assert.equal(matches.length, expectedDefinitions, `${selector} density definition count`);
  return matches[0][1];
};

test('Map tabs share existing sub-tab styling without Capture handlers', () => {
  assert.ok(header);
  const tabs = [...header.matchAll(/<button\b([^>]+)>/g)].map(match => match[1]);
  assert.equal(tabs.length, 2);
  for (const tab of tabs) {
    assert.match(tab, /class="sub-tab target-tab(?: active)?"/);
    assert.match(tab, /data-target-view="(?:service-map|apis)"/);
    assert.match(tab, /role="tab"/);
    assert.doesNotMatch(tab, /data-proxy-tab/);
  }
  assert.match(app, /querySelectorAll\("\.sub-tab\[data-proxy-tab\]"\)/);
});

test('Scope and Map are main tools, the map right after Capture', () => {
  const tools = [...html.matchAll(/<button class="main-tab(?: active)?" data-tool="([^"]+)">([^<]+)</g)].map(match => [match[1], match[2]]);
  const at = (tool) => tools.findIndex(([id]) => id === tool);
  assert.deepEqual(tools[at('target')], ['target', 'Scope']);
  assert.deepEqual(tools[at('map')], ['map', 'Map']);
  assert.equal(at('map'), at('proxy') + 1);
  assert.match(app, /const IMPLEMENTED_TOOLS = new Set\(\[[^\]]*"map"/);
});

test('Scope shows its rules and paths side by side, with no views to switch', () => {
  assert.ok(scopeShell);
  assert.doesNotMatch(scopeShell, /role="tab(?:list|panel)?"|data-target-view|class="[^"]*\bhidden\b/);
  assert.match(scopeShell, /<section class="split-panel split-panel-tight">/);
  assert.match(scopeShell, /id="targetRulesPanel" aria-labelledby="targetRulesTitle"/);
  assert.match(scopeShell, /id="targetPathsPanel" aria-labelledby="targetPathsTitle"/);
  assert.ok(scopeShell.indexOf('id="targetRulesPanel"') < scopeShell.indexOf('id="targetPathsPanel"'));
});

test('Map strip omits the duplicate title and keeps accessible navigation labels', () => {
  assert.doesNotMatch(header, /<h[1-6]\b[^>]*>\s*(?:Scope|Map)\s*<\/h[1-6]>/);
  assert.match(header, /role="tablist" aria-label="Map views"/);
  assert.deepEqual([...header.matchAll(/data-target-view="([^"]+)"[^>]*>([^<]+)</g)].map(match => [match[1], match[2]]),
    [['service-map', 'Service Map'], ['apis', 'APIs']]);
  assert.match(html, /<section class="map-shell hidden" id="mapShell">\s*<header class="target-workspace-header">/);
  assert.match(html, /id="targetServiceMapPanel" role="tabpanel" aria-labelledby="targetServiceMapTab"/);
});

test('Map strip keeps compact height and adds no vertical padding', () => {
  const strip = rule('.target-workspace-header');
  assert.match(strip, /padding:\s*0 8px;/);
  assert.match(strip, /min-height:\s*24px;/);
  assert.doesNotMatch(strip, /(?:^|;)\s*(?:height|padding-top|padding-bottom):/);
  assert.doesNotMatch(css, /\.target-tab(?:\.active)?\s*\{/);
});

// Every strip of tabs is one size at every window height. The active tab is
// gold text over a thin gold line: one mark, not a filled pill with a bar.
test('every tab strip uses one medium tab size and marks the active tab with a thin line', () => {
  assert.match(css, /\n\.sub-tab \{\n  padding: 6px 12px;/);
  const short = css.slice(css.indexOf('@media (max-height: 920px)'));
  assert.doesNotMatch(short.slice(0, short.indexOf('\n}\n')), /\.sub-tab\s*\{/);
  const indicator = css.match(/\n\.tab-indicator \{([^}]+)\}/)?.[1] || '';
  assert.match(indicator, /background: transparent;/);
  // The Pretty / Raw / Hex views of a message pane are tabs like any other.
  const tabs = (state) => ['main-tab', 'sub-tab', 'view-tab', 'replay-view-tab']
    .map((name) => `\\.${name}${state}`).join(',\\n');
  for (const line of [css.match(/\n\.tab-indicator::after \{([^}]+)\}/)?.[1] || '',
    css.match(new RegExp(`\\n${tabs('\\.active::after')} \\{([^}]+)\\}`))?.[1] || '']) {
    assert.match(line, /height: 2px;/);
    assert.match(line, /background: var\(--point\);/);
  }
  const active = css.match(new RegExp(`\\n${tabs('\\.active')} \\{([^}]+)\\}`))?.[1] || '';
  assert.doesNotMatch(active, /background:/);
  // Gold text on the dark themes; on the light ones gold is a mid-tone that
  // reads dimmer than the tabs beside it, so they use their text colour.
  assert.match(active, /color: var\(--tab-active, var\(--point\)\);/);
  for (const theme of ['white', 'paper', 'snow', 'ivory', 'frost']) {
    const block = css.match(new RegExp(`body\\[data-theme="${theme}"\\] \\{([^}]+)\\}`))?.[1] || '';
    assert.match(block, /--tab-active: var\(--text\);/, theme);
  }
  // Each strip slides the same highlight, not only the first one on the page.
  assert.match(app, /document\.querySelectorAll\("\.sub-tabs, \.target-tabs, \.compare-tabs, \.view-tabs"\)\.forEach\(wireTabIndicator\)/);
  // Scan's strip sits in a flex column, where it shrank and cut its tabs off.
  assert.match(css, /\.scan-shell > \.sub-tabs \{ flex: 0 0 auto; \}/);
  assert.match(rule('.target-tabs'), /overflow-x:\s*auto;/);
  assert.match(rule('.target-passive-label', 2), /margin-left:\s*auto;/);
});


test('Scrollable Map tabs keep the keyboard focus ring inside their bounds', () => {
  assert.match(rule('.target-tab:focus-visible'), /outline-offset:\s*-2px;/);
});
