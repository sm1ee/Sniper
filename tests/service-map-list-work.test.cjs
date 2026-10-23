// Synthetic retained metadata and inert DOM only. Deterministic work bounds,
// rather than timing thresholds, keep this regression independent of CPU load.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../web/service-map.js'), 'utf8');

function node() {
  return { value: '', dataset: {}, innerHTML: '', textContent: '', style: { setProperty() {} },
    clientWidth: 800, clientHeight: 600, scrollTop: 0, scrollLeft: 0,
    classList: { toggle() {}, contains() { return false; } },
    addEventListener() {}, setAttribute() {}, contains() { return false; }, querySelectorAll() { return []; } };
}

for (const originCount of [250, 500]) {
  test(`overview redraw uses bounded origin lookups at ${originCount} loaded origins`, async (t) => {
    const context = vm.createContext({ URL, URLSearchParams, AbortController, console });
    vm.runInContext(source, context);
    const origins = Array.from({ length: originCount }, (_, index) => ({
      origin: `https://service-${String(index).padStart(3, '0')}.example.com`, in_scope: true, request_count: 4,
      endpoints: Array.from({ length: 4 }, (_, endpoint) => ({ method: 'GET', path: `/api/path-${endpoint}`,
        request_count: 1, statuses: [200], content_types: ['application/json'], evidence: [`evidence-${index}-${endpoint}`] })),
      technology_clues: [], redirects: [], header_links: [],
    }));
    const payload = { schema_version: 1, session_id: 'synthetic-session',
      snapshot: { generation: 'synthetic-generation', complete: true, considered_rows: originCount * 4,
        retained_rows: originCount * 4, included_rows: originCount * 4, excluded_rows: 0, omitted_rows: 0, stopped_by: [] }, origins };
    const els = Object.fromEntries(['panel', 'status', 'refresh', 'search', 'scope', 'canvas', 'graphBounds', 'detail', 'content', 'catalog', 'viewport'].map(key => [key, node()]));
    let requests = 0;
    const controller = context.SniperServiceMap.createController({ elements: els, getSessionId: () => 'synthetic-session',
      document: { activeElement: null, body: {}, querySelector() { return null; } },
      async request(url) { assert.ok(url.startsWith('/api/target/service-map?')); requests++; return { ok: true, json: async () => payload }; } });
    controller.setVisible(true);
    await controller.refresh();
    const state = controller.getState();
    const selected = origins[Math.floor(originCount / 2)].origin;
    controller.selectOrigin(selected);
    const before = els.canvas.innerHTML;
    const order = Array.from(state.order);
    let originReads = 0;
    for (const origin of state.snapshot.origins) {
      const id = origin.origin;
      Object.defineProperty(origin, 'origin', { enumerable: true, get() { originReads++; return id; } });
    }
    controller.displayChanged();
    t.diagnostic(`${originReads} origin reads for ${originCount} origins`);
    assert.ok(originReads < originCount * 40, `Expected linear lookup work, observed ${originReads} origin reads`);
    assert.equal(els.canvas.innerHTML, before, 'unchanged overview retains exact markup and layout');
    assert.deepEqual(Array.from(state.order), order, 'snapshot ordering stays unchanged');
    assert.equal(state.selectedOrigin, selected, 'out-of-card-window selection stays owned by the selected origin');
    assert.equal(requests, 1, 'redraw remains local');
    assert.equal([...els.canvas.innerHTML.matchAll(/class="service-map-card /g)].length, 24);
  });
}
