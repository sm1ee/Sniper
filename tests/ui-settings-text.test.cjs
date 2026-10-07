const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

const functions = [
  "truncateUiSettingsText",
  "createDefaultFilterSettings",
  "sanitizeHttpQuery",
  "sanitizeWebsocketQuery",
  "sanitizeHttpFilterSettings",
  "sanitizeHttpBooleanMap",
  "sanitizeHttpColorTags",
  "serializeHttpFilterSettings",
];
const state = {};
const context = loadFunctions(functions, {
  state,
  HTTP_COLOR_TAG_OPTIONS: new Set(["red", "orange", "yellow", "green", "blue", "purple"]),
});

const textFields = [
  ["HTTP query", value => context.sanitizeHttpQuery(value)],
  ["WebSocket query", value => context.sanitizeWebsocketQuery(value)],
  ...[
    ["search_term", "searchTerm"],
    ["hidden_extensions", "hiddenExtensions"],
    ["port", "port"],
  ].map(([savedKey, stateKey]) => [savedKey, value => {
    const loaded = context.sanitizeHttpFilterSettings({ [savedKey]: value });
    state.filterSettings = { ...loaded, [stateKey]: value };
    const saved = context.serializeHttpFilterSettings();
    assert.equal(saved[savedKey], loaded[stateKey], "load and save must use the same limit");
    return saved[savedKey];
  }]),
];

for (const [label, sanitize] of textFields) {
  test(`${label} preserves a supplementary character at the saved text boundary`, () => {
    const value = "a".repeat(511) + "😀";
    const saved = sanitize(`  ${value}  `);
    assert.equal(saved, value);
    assert.doesNotThrow(() => encodeURIComponent(saved), "settings JSON must not contain a lone surrogate");
  });

  test(`${label} counts Unicode characters consistently with persisted settings`, () => {
    const value = "😀".repeat(511) + "z";
    assert.equal(sanitize(value + "extra"), value);
    assert.equal(sanitize("a".repeat(513)), "a".repeat(512));
    assert.equal(sanitize("  short 文 😀  "), "short 文 😀");
  });
}
