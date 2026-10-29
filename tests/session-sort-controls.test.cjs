// Synthetic Session headers only; no startup, loading, activation, or network.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { appSource } = require('./frontend-test-helpers.cjs');
const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
const markup = html.match(/<table[^>]*id="dashboardSessionsTable"[^]*?<\/thead>/)[0];
const keys = ['name', 'storage_bytes', 'request_count', 'websocket_count', 'finding_count', 'last_captured_at', 'created_at'];

function fixture() {
  const state = { sessionSortKey: 'created_at', sessionSortDir: 'desc', selectedSessionId: 'selected' };
  const headers = keys.map(key => {
    const attributes = {}, listeners = {};
    const button = { appendChild(arrow) { this.arrow = arrow; } };
    return { dataset: { sortKey: key }, attributes, button, listeners,
      setAttribute(name, value) { attributes[name] = value; },
      appendChild(arrow) { button.arrow = arrow; },
      querySelector(selector) { return selector === '.session-sort-button' ? button : button.arrow; },
      addEventListener(type, handler) { listeners[type] = handler; },
    };
  });
  const document = { activeElement: headers[0].button,
    querySelectorAll: () => headers,
    getElementById: () => ({ querySelectorAll: () => headers }),
    createElement: () => ({ attributes: {}, setAttribute(name, value) { this.attributes[name] = value; }, remove() { headers.forEach(h => { if (h.button.arrow === this) delete h.button.arrow; }); } }),
  };
  let renders = 0;
  const renderSource = appSource.split('  // Render sort arrows in headers\n')[1].split('\n  els.dashboardSessionsBody.innerHTML')[0];
  const context = vm.createContext({ state, document, renderDashboard() { renders++; vm.runInContext(`{${renderSource}}`, context); } });
  const bindingSource = appSource.split('  // Session table sort headers\n')[1].split('\n  onClickWithProgress(els.clearEventLogButton')[0];
  vm.runInContext(bindingSource, context);
  context.renderDashboard();
  return { state, headers, document, render: context.renderDashboard, renders: () => renders };
}

test('seven native header buttons are tab-reachable; Action is not a control', () => {
  for (const key of keys) {
    assert.match(markup, new RegExp(`<th data-sort-key="${key}"[^>]*><button class="session-sort-button" type="button">[^<]+<\\/button><\\/th>`));
  }
  assert.match(markup, /<th>Action<\/th>/);
  assert.doesNotMatch(markup, /tabindex="-1"/);
  assert.match(css, /\.session-table \.session-sort-button:focus-visible\s*\{[^}]*outline:/);
  assert.doesNotMatch(css, /\.session-table thead th\s*\{[^}]*cursor: pointer/);
});

test('native click and header-cell click toggle once with existing defaults', () => {
  const f = fixture();
  for (const header of f.headers) {
    f.state.sessionSortKey = 'other';
    const initial = header.dataset.sortKey === 'name' ? 'asc' : 'desc';
    const count = f.renders();
    // Enter/Space on native buttons bubble one click; actual key dispatch is browser QA.
    header.listeners.click({ target: header.button });
    assert.equal(f.renders(), count + 1);
    assert.equal(f.state.sessionSortKey, header.dataset.sortKey);
    assert.equal(f.state.sessionSortDir, initial);
    header.listeners.click({ target: header });
    assert.equal(f.renders(), count + 2);
    assert.equal(f.state.sessionSortDir, initial === 'asc' ? 'desc' : 'asc');
    assert.deepEqual(Object.keys(header.listeners), ['click']);
  }
  assert.equal(f.state.selectedSessionId, 'selected');
});

test('sort state is announced, arrows decorative, and repeated renders preserve header focus', () => {
  const f = fixture();
  assert.equal(f.headers[6].attributes['aria-sort'], 'descending');
  f.headers[0].listeners.click({ target: f.headers[0].button });
  for (let i = 0; i < 3; i++) {
    f.render();
    assert.equal(f.document.activeElement, f.headers[0].button);
    for (const [index, header] of f.headers.entries()) {
      assert.equal(header.attributes['aria-sort'], index === 0 ? 'ascending' : 'none');
      if (index === 0) {
        assert.equal(header.button.arrow.textContent, '▲');
        assert.equal(header.button.arrow.attributes['aria-hidden'], 'true');
      } else assert.equal(header.button.arrow, undefined);
    }
  }
  f.headers[0].listeners.click({ target: f.headers[0].button });
  assert.equal(f.headers[0].attributes['aria-sort'], 'descending');
  assert.equal(f.headers[0].button.arrow.textContent, '▼');
});
