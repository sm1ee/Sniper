// Synthetic list DOM only: no startup, session loading, or real activation.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const { loadFunctions } = require('./frontend-test-helpers.cjs');

function fixture() {
  const state = { sessions: [{ id: 'a', name: 'Active', active: true }, { id: 'b', name: 'Saved "review"' }], selectedSessionId: 'a' };
  const document = { body: {}, getElementById: () => null };
  document.activeElement = document.body;
  let rows = [], markup = '', renders = 0;
  const body = {
    contains: control => rows.some(row => Object.values(row.controls).includes(control)),
    querySelectorAll(selector) {
      if (selector === 'tr[data-id]') return rows;
      return rows.flatMap(row => row.controls[selector.slice(1)] || []);
    },
  };
  Object.defineProperty(body, 'innerHTML', {
    get: () => markup,
    set(value) {
      if (body.contains(document.activeElement)) document.activeElement = document.body;
      markup = value; renders++;
      rows = [...value.matchAll(/<tr class="history-row[^]*?data-id="([^"]+)"[^]*?<\/tr>/g)].map(match => {
        const listeners = {};
        const row = { dataset: { id: match[1] }, controls: {}, addEventListener: (type, fn) => listeners[type] = fn, querySelector: selector => row.controls[selector.slice(1)] };
        for (const controlMatch of match[0].matchAll(/<button class="([^"]+)"([^>]*)>/g)) {
          const classes = controlMatch[1].split(' '), name = classes.find(c => /^session-.*-button$/.test(c));
          const handlers = {};
          const control = { classList: { contains: c => classes.includes(c) }, closest: () => row,
            addEventListener: (type, fn) => handlers[type] = fn,
            focus() { document.activeElement = control; },
            click() { const e = { stopped: false, stopPropagation() { this.stopped = true; } }; handlers.click?.(e); if (!e.stopped) listeners.click?.(e); },
          };
          row.controls[name] = control;
        }
        return row;
      });
    },
  });
  const els = new Proxy({ dashboardSessionsBody: body }, { get: (o, k) => o[k] ||= {} });
  const activated = [];
  const c = loadFunctions(['renderDashboard', 'sessionFindingCount', 'formatSize', 'escapeHtml'], {
    state, document, els, getSortedSessions: () => state.sessions, formatCappedCount: String,
    retainedEntriesCap() {}, formatTimestamp: () => '-', onClickWithProgress: (btn, fn) => btn.addEventListener('click', fn),
    withButtonProgress: (btn, fn) => Promise.resolve(fn()), activateSessionById: id => activated.push(id), handleWorkspaceActionError: assert.fail,
  });
  c.renderDashboard();
  return { state, document, c, body, activated, rows: () => rows, renders: () => renders };
}

for (const key of ['Enter', 'Space']) test(`${key}'s native button click selects once and retains focus`, () => {
  const f = fixture();
  const select = f.rows()[1].controls['session-select-button'];
  select.focus();
  const count = f.renders();
  // Native button keyboard activation produces click; actual key dispatch is browser QA.
  select.click();
  assert.equal(f.renders(), count + 1, 'one bubbling row handler, no duplicate dispatch');
  assert.equal(f.state.selectedSessionId, 'b');
  assert.equal(f.document.activeElement, f.rows()[1].controls['session-select-button']);
  assert.match(f.body.innerHTML, /session-select-button" type="button" title="Saved &quot;review&quot;" aria-pressed="true" aria-label="Select session Saved &quot;review&quot;"/);
  const open = f.rows()[1].controls['session-open-button'];
  open.focus(); open.click();
  assert.deepEqual(f.activated, ['b']);
  assert.equal(f.renders(), count + 1, 'Open must not bubble into row selection');
});

test('repeated renders restore the same list control, never outside focus', () => {
  const f = fixture();
  for (const name of ['session-select-button', 'session-open-button', 'session-delete-button']) {
    f.rows()[1].controls[name].focus();
    for (let i = 0; i < 3; i++) { f.c.renderDashboard(); assert.equal(f.document.activeElement, f.rows()[1].controls[name]); }
  }
  const outside = {}; f.document.activeElement = outside;
  f.c.renderDashboard(); assert.equal(f.document.activeElement, outside);
  f.rows()[1].controls['session-select-button'].focus();
  f.state.sessions.pop(); f.c.renderDashboard();
  assert.equal(f.document.activeElement, f.document.body, 'removed controls do not target another session');
});

test('native selection controls expose contextual actions and focus styling', () => {
  const f = fixture();
  assert.match(f.body.innerHTML, /aria-label="Open session Saved &quot;review&quot;"/);
  assert.match(f.body.innerHTML, /aria-label="Delete session Saved &quot;review&quot;"/);
  assert.match(f.body.innerHTML, /session-select-button" type="button" title="Saved &quot;review&quot;" aria-pressed="false"/);
  assert.doesNotMatch(f.body.innerHTML, /session-select-button[^>]*tabindex="-1"/);
  const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
  assert.match(css, /session-select-button[^}]*:focus-visible\s*\{[^}]*outline:/);
  assert.match(css, /:is\(:hover, :focus-within, \.selected\) \.session-actions\s*\{\s*visibility: visible/);
  const row = f.body.innerHTML.split('</tr>')[1];
  assert.ok(row.indexOf('session-select-button') < row.indexOf('session-open-button'), 'Tab order reaches Open after selection');
});


test('long session names stay within the cell with a full-name tooltip', () => {
  const f = fixture();
  assert.match(f.body.innerHTML, /title="Saved &quot;review&quot;"/);
  const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
  const rule = css.match(/\.session-table \.session-select-button \{([^}]+)\}/)[1];
  for (const declaration of ['display: block', 'max-width: 100%', 'box-sizing: border-box', 'overflow: hidden', 'text-overflow: ellipsis', 'white-space: nowrap', 'margin: -3px 0']) {
    assert.ok(rule.includes(declaration), declaration);
  }
});


test('Session column budgets leave room for names and both actions without changing other tables', () => {
  const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
  assert.match(css, /\.history-table\.session-table \{\s*width: 100%;\s*min-width: 1140px;/);
  assert.match(css, /\.session-table thead th \{\s*box-sizing: border-box;/);
  for (const [column, width] of [[2, 136], [3, 88], [4, 104], [5, 80], [8, 180]]) {
    assert.ok(css.includes(`.session-table thead th:nth-child(${column}) { width: ${width}px; }`));
  }
  assert.match(css, /\.session-table thead th:nth-child\(6\),\s*\.session-table thead th:nth-child\(7\) \{ width: 160px; \}/);
  assert.doesNotMatch(css, /\.session-table thead th:nth-child\(1\)\s*\{[^}]*width:/);
  assert.match(css, /\.history-table-shell \{[^}]*overflow: auto;/);
});
