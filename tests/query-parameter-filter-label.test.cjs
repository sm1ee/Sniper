// Synthetic summaries only. No app startup, body reads, capture or networking.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { appSource, loadFunctions } = require('./frontend-test-helpers.cjs');

test('shared History/Map query filter explains URL-only matching accessibly', () => {
  const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
  assert.match(html, /id="filterOnlyParameterized"[^>]*aria-describedby="filterOnlyParameterizedHelp"[^>]*\/><span>Show only requests with query parameters<\/span>/);
  assert.match(html, /<small id="filterOnlyParameterizedHelp">Matches a \? in the URL, including an empty query\. JSON, form and multipart body fields do not affect this filter\.<\/small>/);
  assert.equal((html.match(/id="filterOnlyParameterized"/g) || []).length, 1, 'History and Map keep one shared dialog');
  assert.match(appSource, /state\.filterSettings\.onlyParameterized\) summary\.push\("query parameters only"\)/);
  assert.doesNotMatch(html + appSource, /Show only parameterized requests|["']parameterized only["']/);
});

test('Map toolbar summary names query parameters without changing the saved flag', () => {
  const state = { serviceMapFilterSettings: { onlyParameterized: true } };
  const context = loadFunctions(['createDefaultFilterSettings', 'serviceMapFilterSummary'], {
    state, SERVICE_MAP_FILTER_MIME_LABELS: {}, SERVICE_MAP_FILTER_STATUS_LABELS: {},
    sanitizeHttpFilterSettings: value => ({ hiddenExtensions: '', mime: {}, status: {}, ...value }),
  });
  assert.equal(context.serviceMapFilterSummary().text, 'query parameters only');
  assert.equal(context.serviceMapFilterSummary().detail, 'Service Map filter: query parameters only');
  assert.equal(state.serviceMapFilterSettings.onlyParameterized, true);
});

for (const contentType of ['application/json', 'application/x-www-form-urlencoded', 'multipart/form-data; boundary=fixture']) {
  test(`query filter keeps existing body-only visibility semantics: ${contentType}`, () => {
    const state = { method: '', query: '', filterSettings: {} };
    const context = loadFunctions(['summaryMatchesActiveHistoryFilters'], {
      state, isInScopeHost: () => true, inferMimeType: () => 'other',
      summaryMatchesStatusFilter: () => true, summaryMatchesMimeFilter: () => true,
      summaryMatchesHiddenExtensions: () => true, summaryMatchesPortFilter: () => true,
      summaryMatchesColorTags: () => true, summaryMatchesAdvancedSearch: () => true,
    });
    const item = { method: 'POST', host: 'example.com', path: '/submit', content_type: contentType, request_bytes: 64 };
    Object.defineProperty(item, 'request', { get() { throw new Error('The query filter must not read request bodies'); } });
    assert.equal(context.summaryMatchesActiveHistoryFilters(item), true, 'body-only rows stay visible with the filter off');
    state.filterSettings.onlyParameterized = true;
    assert.equal(context.summaryMatchesActiveHistoryFilters(item), false, 'body fields alone do not match the URL query filter');
    item.path = '/submit?name=value';
    assert.equal(context.summaryMatchesActiveHistoryFilters(item), true);
    item.path = '/submit?';
    assert.equal(context.summaryMatchesActiveHistoryFilters(item), true, 'empty queries preserve the existing delimiter predicate');
    item.path = '/submit%3Fname=value';
    assert.equal(context.summaryMatchesActiveHistoryFilters(item), false, 'an encoded question mark in the path is not a query');
    state.filterSettings.onlyParameterized = false;
    assert.equal(context.summaryMatchesActiveHistoryFilters(item), true);
  });
}

test('CLI and public guides explain the unchanged URL-query flag', () => {
  const cli = fs.readFileSync(path.join(__dirname, '../src/bin/sniper-cli.rs'), 'utf8');
  assert.match(cli, /Keep only rows whose URL has a query string; body fields do not match\./);
  assert.match(cli, /Display filter: keep only rows whose URL has a query string; body fields do not match\. Null uses false\./);
  for (const file of ['README.md', 'docs/integrations/service-map.md', 'packaging/skills/codex/sniper-operator/SKILL.md', 'packaging/skills/claude/sniper-operator/SKILL.md']) {
    const text = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');
    assert.match(text, /JSON, form and multipart body fields do not\s+(?:affect|match)/, file);
  }
});
