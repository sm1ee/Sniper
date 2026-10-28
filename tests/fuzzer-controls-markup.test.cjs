// Static markup contracts only. No application, network, payload execution or backend is loaded.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
const fuzzer = html.slice(html.indexOf('<section class="fuzzer-shell'), html.indexOf('<section class="sequence-shell'));
const tags = [...fuzzer.matchAll(/<([a-z][\w-]*)\b([^>]*?)(\/?)>/gi)].map(([, tag, source]) => {
  const attrs = {};
  for (const [, key, value] of source.matchAll(/([\w-]+)(?:="([^"]*)")?/g)) attrs[key] = value ?? '';
  return { tag, attrs };
});
function byId(id) {
  const matches = tags.filter(node => node.attrs.id === id);
  assert.equal(matches.length, 1, `Expected exactly one Fuzzer element #${id}`);
  return matches[0];
}
function values(id) {
  const contents = fuzzer.match(new RegExp(`<select[^>]*id="${id}"[^>]*>([\\s\\S]*?)<\\/select>`))?.[1];
  assert.ok(contents, `Missing select #${id}`);
  return [...contents.matchAll(/<option value="([^"]*)"/g)].map(([, value]) => value);
}

const buttons = ['resetFuzzerButton', 'stopFuzzerButton', 'startFuzzerButton', 'fuzzerMarkSelectionButton', 'fuzzerRemoveMarkerButton', 'fuzzerClearMarkersButton', 'fuzzerUndoMarkerButton',
  'fuzzerMarkCandidateButton', 'fuzzerImportPayloadButton', 'fuzzerApplyPresetButton', 'fuzzerGenerateRangeButton',
  'fuzzerCompareBaseButton', 'fuzzerCompareButton', 'fuzzerRefreshRunsButton', 'fuzzerViewRunButton', 'fuzzerReuseRunButton'];
const labeledControls = ['fuzzerCandidateSelect', 'fuzzerAttackType', 'fuzzerTransportSelect', 'fuzzerConcurrency', 'fuzzerUrlEncode', 'fuzzerPayloadImportMode', 'fuzzerPayloadPreset',
  'fuzzerRangeStart', 'fuzzerRangeEnd', 'fuzzerRangeStep', 'fuzzerPayloadsEditor', 'fuzzerResultStatus',
  'fuzzerResultMinBytes', 'fuzzerResultMaxBytes', 'fuzzerResultMinMs', 'fuzzerResultMaxMs',
  'fuzzerResultSort', 'fuzzerResultDirection', 'fuzzerSavedRunSelect'];

test('Fuzzer controls retain unique IDs and keyboard-native button actions', () => {
  for (const id of buttons) {
    assert.equal(byId(id).tag, 'button');
    assert.equal(byId(id).attrs.type, 'button');
    assert.equal((html.match(new RegExp(`\\bid="${id}"`, 'g')) || []).length, 1);
  }
  for (const id of labeledControls) {
    byId(id);
    assert.ok(tags.some(node => node.tag === 'label' && node.attrs.for === id), `Missing label for #${id}`);
  }
  for (const node of tags) assert.notEqual(node.attrs.tabindex, '-1', `${node.attrs.id} cannot be removed from keyboard navigation`);
});

test('payload controls declare append default, exact presets and accessible file picker', () => {
  assert.deepEqual(values('fuzzerPayloadImportMode'), ['append', 'replace']);
  assert.match(fuzzer, /<option value="append" selected>Append to list<\/option>/);
  assert.deepEqual(values('fuzzerPayloadPreset'), ['text-boundaries', 'number-boundaries']);
  assert.equal(byId('fuzzerPayloadFile').attrs.type, 'file');
  assert.ok('hidden' in byId('fuzzerPayloadFile').attrs);
  assert.ok(byId('fuzzerPayloadFile').attrs['aria-label']);
  assert.equal(byId('fuzzerImportPayloadButton').attrs['aria-controls'], 'fuzzerPayloadFile');
  for (const id of ['fuzzerRangeStart', 'fuzzerRangeEnd', 'fuzzerRangeStep']) assert.equal(byId(id).attrs.type, 'number');
  assert.equal(byId('fuzzerPayloadsEditor').attrs['aria-describedby'], 'fuzzerPayloadHelp');
  assert.match(fuzzer, /Spaces are preserved\. Blank lines are empty payloads; a final line break is ignored\./);
});

test('Transport is a labeled native HTTP/HTTPS selector beside the destination with visible contextual help', () => {
  assert.deepEqual(values('fuzzerTransportSelect'), ['https', 'http']);
  assert.equal(byId('fuzzerTransportSelect').attrs['aria-describedby'], 'fuzzerTransportHelp fuzzerTargetSummary');
  assert.ok('disabled' in byId('fuzzerTransportSelect').attrs);
  assert.equal(disclosureDepthAt('fuzzerTransportSelect'), 0);
  assert.equal(disclosureDepthAt('fuzzerTransportHelp'), 0);
  assert.ok(fuzzer.indexOf('id="fuzzerTransportSelect"') < fuzzer.indexOf('id="fuzzerTargetSummary"'));
});

test('preflight names the two ways payloads fill positions, and a running attack can be stopped', () => {
  assert.match(fuzzer, /Sniper puts each payload in one position at a time; Battering ram puts it in every position at once/);
  assert.deepEqual(values('fuzzerAttackType'), ['sniper', 'battering_ram']);
  assert.match(fuzzer, /<button class="secondary-action hidden" id="stopFuzzerButton" type="button" aria-describedby="fuzzerStopStatus">Stop<\/button>/);
  for (const id of ['fuzzerPreflightSummary', 'fuzzerPreflightNotice']) assert.equal(byId(id).attrs.role, 'status');
  assert.equal(byId('fuzzerPreviewSamples').tag, 'div');
  assert.match(fuzzer, /<details[^>]*fuzzer-preview-disclosure[^>]*>\s*<summary>Preview &amp; details<\/summary>[\s\S]*?<div id="fuzzerPreviewSamples"/);
  assert.doesNotMatch(fuzzer, /<progress\b/i);
  // Status and next step share one line; what there is not yet to show waits.
  assert.match(css, /\.fuzzer-preflight \{[^}]*display: flex;[^}]*flex-wrap: wrap;/);
  for (const id of ['fuzzerValueRow', 'fuzzerPreviewDisclosure']) assert.match(byId(id).attrs.class, /\bhidden\b/);
});

test('result filters, comparison and saved run controls match JS contracts', () => {
  assert.deepEqual(values('fuzzerResultStatus'), ['all', 'error', '2xx', '3xx', '4xx', '5xx']);
  assert.deepEqual(values('fuzzerResultSort'), ['index', 'payload', 'status', 'bytes', 'duration']);
  assert.deepEqual(values('fuzzerResultDirection'), ['asc', 'desc']);
  for (const id of ['fuzzerResultMinBytes', 'fuzzerResultMaxBytes', 'fuzzerResultMinMs', 'fuzzerResultMaxMs']) {
    assert.equal(byId(id).attrs.type, 'number');
    assert.equal(byId(id).attrs.min, '0');
  }
  for (const id of ['fuzzerCompareBaseButton', 'fuzzerCompareButton', 'fuzzerViewRunButton', 'fuzzerReuseRunButton']) {
    assert.ok('disabled' in byId(id).attrs, `#${id} must wait for a selected result or run`);
  }
  assert.equal(byId('fuzzerResultFilterCount').attrs.role, 'status');
  assert.equal(byId('fuzzerSavedRunNotice').attrs.role, 'status');
  assert.match(fuzzer, /View results keeps your current draft\. Reuse setup asks before replacing it; the original target or source request may be unavailable\./);
});

test('helpers load before app and disclosures keep bounded responsive controls', () => {
  const helper = html.indexOf('<script src="/fuzzer-workflow.js" defer></script>');
  assert.ok(helper >= 0 && helper < html.indexOf('<script src="/app.js" defer></script>'));
  for (const node of tags.filter(node => node.tag === 'details')) assert.ok(!('open' in node.attrs));
  assert.match(css, /\.fuzzer-disclosure-body\s*\{[^}]*max-height:[^}]*overflow: auto;/s);
  assert.match(css, /\.fuzzer-top-row \.editor-panel\s*\{[^}]*min-height: 80px;/s);
  assert.match(css, /@media \(max-width: 620px\)\s*\{[\s\S]*\.fuzzer-filter-grid/);
  assert.match(css, /\.fuzzer-disclosure > summary:focus-visible/);
});

test('helper script has an embedded API route and is loaded before app initialization', () => {
  const api = fs.readFileSync(path.join(__dirname, '../src/api.rs'), 'utf8');
  assert.match(api, /\.route\("\/fuzzer-workflow\.js", get\(fuzzer_workflow_js\)\)/);
  assert.match(api, /include_str!\("\.\.\/web\/fuzzer-workflow\.js"\)/);
});

function disclosureDepthAt(id) {
  const prefix = fuzzer.slice(0, fuzzer.indexOf(`id="${id}"`));
  return [...prefix.matchAll(/<details\b[^>]*>|<\/details>/g)].reduce((depth, [tag]) => depth + (tag.startsWith('</') ? -1 : 1), 0);
}
test('common value and file actions are immediate while advanced options and explanations stay collapsed', () => {
  for (const id of ['fuzzerPayloadImportMode', 'fuzzerMarkSelectionButton', 'fuzzerRemoveMarkerButton', 'fuzzerClearMarkersButton', 'fuzzerImportPayloadButton', 'startFuzzerButton']) {
    assert.equal(disclosureDepthAt(id), 0, `${id} should not require opening a disclosure`);
  }
  for (const id of ['fuzzerCandidateSelect', 'fuzzerMarkCandidateButton', 'fuzzerConcurrency', 'fuzzerUrlEncode', 'fuzzerPayloadPreset', 'fuzzerRangeStart', 'fuzzerPreviewNotes', 'fuzzerPayloadHelp']) {
    assert.equal(disclosureDepthAt(id), 1, `${id} should remain in a closed disclosure`);
  }
  assert.doesNotMatch(fuzzer, /Send a captured request to Fuzzer, mark positions, load payloads/);
  assert.match(fuzzer, /placeholder="Paste payloads, one per line"/);
});

test('active-filter indication remains in summary and one-click clearing is outside closed details', () => {
  assert.equal(byId('fuzzerResultFilterSummary').tag, 'summary');
  assert.equal(byId('fuzzerResultFilterBadge').tag, 'span');
  assert.match(byId('fuzzerResultFilterBadge').attrs.class, /\bhidden\b/);
  assert.equal(byId('fuzzerClearResultFiltersButton').tag, 'button');
  assert.equal(byId('fuzzerClearResultFiltersButton').attrs.type, 'button');
  assert.equal(disclosureDepthAt('fuzzerClearResultFiltersButton'), 0);
  assert.match(byId('fuzzerClearResultFiltersButton').attrs.class, /\bhidden\b/);
});

test('payload import has a compact local live status connected to its trigger', () => {
  assert.equal(byId('fuzzerPayloadImportStatus').attrs.role, 'status');
  assert.equal(byId('fuzzerPayloadImportStatus').attrs['aria-live'], 'polite');
  assert.match(byId('fuzzerPayloadImportStatus').attrs.class, /\bhidden\b/);
  assert.equal(byId('fuzzerImportPayloadButton').attrs['aria-describedby'], 'fuzzerPayloadImportStatus');
  assert.equal(disclosureDepthAt('fuzzerPayloadImportStatus'), 0);
  assert.match(css, /#fuzzerPayloadImportStatus\.fuzzer-notice-error/);
});

test('Stop has a hidden compact live error status with matching error styling', () => {
  assert.equal(byId('fuzzerStopStatus').attrs.role, 'status');
  assert.equal(byId('fuzzerStopStatus').attrs['aria-live'], 'polite');
  assert.match(byId('fuzzerStopStatus').attrs.class, /\bhidden\b/);
  assert.match(byId('fuzzerStopStatus').attrs.class, /\bfuzzer-notice-error\b/);
  assert.equal(byId('stopFuzzerButton').attrs['aria-describedby'], 'fuzzerStopStatus');
  assert.equal(disclosureDepthAt('fuzzerStopStatus'), 0);
  assert.match(css, /#fuzzerStopStatus\.fuzzer-notice-error\s*\{[^}]*color:/s);
});


test('targeted removal is distinct from clear-all and included in Undo description', () => {
  assert.ok('disabled' in byId('fuzzerRemoveMarkerButton').attrs);
  assert.match(byId('fuzzerRemoveMarkerButton').attrs.title, /selected value; keep the value/);
  assert.match(byId('fuzzerClearMarkersButton').attrs.title, /keeping their original values/);
  assert.match(byId('fuzzerUndoMarkerButton').attrs.title, /Add, Remove or Clear/);
});
