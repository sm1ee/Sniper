// Synthetic Flow snapshots only; no browser, proxy, or network access.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const context = vm.createContext({ URL, URLSearchParams });
vm.runInContext(fs.readFileSync(path.join(__dirname, '../web/service-map.js'), 'utf8'), context);
const map = context.SniperServiceMap;
const origin = 'https://app.example.com';
const record = '11111111-1111-4111-8111-111111111111';
function flow(extra = {}) {
  return map.normalizeFlow({ schema_version: 1, session_id: 'session-one', origin, lanes: [origin],
    considered_rows: 12, flow_rows: 5, complete: true, phases: [{ page: null, steps: [
      { origin, method: 'GET', path: '/config', status: 200, request_kind: 'api', count: 3, record_id: record },
      { origin, method: 'GET', path: '/logo.png', status: 200, request_kind: 'static', count: 2, record_id: record },
    ] }], ...extra }, 'session-one', origin);
}
function metadata(output) {
  const line = output.split('\n').find(line => line.startsWith('  %% Sniper Flow: '));
  assert.ok(line, 'the copied diagram keeps its bounds and filter provenance');
  return JSON.parse(line.slice('  %% Sniper Flow: '.length));
}

test('Mermaid preserves flow completeness, stop reasons, counts, and hidden request kinds', () => {
  const output = map.flowMermaid(flow({ complete: false, stopped_by: ['max_records', 'steps_limit'] }), ['static']);
  assert.deepEqual(metadata(output), { origin, considered_rows: 12, flow_rows: 5, complete: false,
    stopped_by: ['max_records', 'steps_limit'], hidden_request_kinds: ['static'], shown_steps: 1, shown_rows: 3 });
  assert.match(output, /Note over C,O0: Partial flow: /);
  assert.match(output, /older steps left out/);
  assert.match(output, /C->>O0: GET \/config ×3 200/);
  assert.doesNotMatch(output, /logo\.png/);
});

test('a complete export keeps provenance without adding a partial-flow warning', () => {
  const output = map.flowMermaid(flow());
  assert.equal(metadata(output).complete, true);
  assert.deepEqual(metadata(output).stopped_by, []);
  assert.equal(metadata(output).shown_rows, 5);
  assert.equal(metadata(output).shown_steps, 2);
  assert.doesNotMatch(output, /Note over C,O0: Partial flow/);
});

test('empty and fully hidden flows retain the reason they have no exported requests', () => {
  const hidden = map.flowMermaid(flow(), ['api', 'static']);
  assert.equal(metadata(hidden).shown_rows, 0);
  assert.deepEqual(metadata(hidden).hidden_request_kinds, ['api', 'static']);
  assert.doesNotMatch(hidden, /C->>/);
  const incomplete = map.flowMermaid(flow({ phases: [], complete: false, stopped_by: ['metadata_bytes'] }));
  assert.equal(metadata(incomplete).shown_steps, 0);
  assert.match(incomplete, /Note over C,O0: Partial flow: /);
});

test('an incomplete export without a known reason still warns, and reason text cannot add Mermaid statements', () => {
  assert.match(map.flowMermaid(flow({ complete: false })), /Note over C,O0: Partial flow\n/);
  const reason = 'new_limit;\nC->>O0: injected#10;';
  const output = map.flowMermaid(flow({ complete: false, stopped_by: [reason] }));
  assert.deepEqual(metadata(output).stopped_by, [reason]);
  assert.equal(output.split('\n').filter(line => line.includes('injected')).length, 2, 'one escaped metadata comment and one flattened warning');
  assert.doesNotMatch(output, /^C->>O0: injected/m);
});
