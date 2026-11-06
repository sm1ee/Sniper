const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
function rule(selector) {
  const start = css.indexOf(selector + ' {');
  assert.ok(start >= 0, `missing ${selector}`);
  return css.slice(start, css.indexOf('}', start) + 1);
}
test('Hex pager controls follow theme colors without global input changes', () => {
  const shared = rule('.replay-hex-pager :is(input, button)');
  for (const declaration of ['background: var(--panel-code)', 'color: var(--text-soft)', 'border: 1px solid var(--line)', 'font: inherit']) assert.ok(shared.includes(declaration));
  assert.match(rule('.replay-hex-pager input'), /width: 64px/);
  assert.match(rule('.replay-hex-pager button:hover:not(:disabled)'), /background: var\(--panel-soft\)/);
});
test('Hex pager keeps keyboard focus visible and disabled navigation distinct', () => {
  assert.match(rule('.replay-hex-pager :is(input, button):focus-visible'), /outline: 2px solid var\(--point\)/);
  assert.match(rule('.replay-hex-pager button:disabled'), /cursor: default/);
  assert.match(rule('.replay-hex-pager\[hidden\]'), /display: none/);
});
