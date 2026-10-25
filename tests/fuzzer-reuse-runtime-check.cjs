// Passive VM check of the exact app.js served by the owned runtime. No bootstrap.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const served = fs.readFileSync(process.argv[2]);
assert.ok(served.equals(fs.readFileSync(path.join(__dirname, '../web/app.js'))), 'Served app.js must match this checkout');
const appSource = served.toString('utf8').replace(/\r\n/g, '\n');
function loadFunctions(names, globals = {}) {
  const context = vm.createContext({ console, ...globals });
  for (const name of names) {
    assert.match(name, /^[A-Za-z_$][\w$]*$/);
    const match = appSource.match(new RegExp(`^(?:async )?function ${name}\\([^]*?^\\}`, 'm'));
    assert.ok(match, `Missing served frontend function: ${name}`);
    vm.runInContext(match[0], context, { filename: `served-app.js:${name}` });
  }
  return context;
}
const fixturePath = path.join(__dirname, 'fuzzer-results-workflow.test.cjs');
const fixtureSource = fs.readFileSync(fixturePath, 'utf8');
const boundary = fixtureSource.indexOf("\ntest('status, byte and time filters");
assert.ok(boundary > 0, 'Fixture declaration boundary must remain explicit');
const context = { TextEncoder, setImmediate, console, module: { exports: {} }, require(name) {
  if (name === './frontend-test-helpers.cjs') return { appSource, loadFunctions };
  assert.ok(['node:assert/strict', 'node:test', 'node:vm'].includes(name), `Unexpected fixture dependency: ${name}`);
  return require(name);
} };
vm.runInNewContext(fixtureSource.slice(0, boundary) + '\nmodule.exports = { fixture, response, draft };', context, { filename: fixturePath });
const { fixture, response, draft } = context.module.exports;
async function reuse(record, expected, subset = false, superseded = false) {
  const f = fixture(), before = draft(f.state);
  f.pick(record.id);
  const reading = f.reuse();
  assert.equal(f.requests.length, 1);
  f.requests[0].resolve(response(record));
  await reading;
  assert.equal(draft(f.state), before, 'Fetching retained results must not replace the draft');
  assert.equal(f.confirmations.length, 1, f.state.fuzzerResultsWorkflow?.notice);
  const message = f.confirmations[0].message;
  if (subset) assert.ok(message.includes('Only 2 of 3 original payload slots remain. Missing payloads will not be restored.'));
  else assert.ok(!message.includes('original payload slots remain'));
  if (superseded) f.c.updateFuzzerPayloadsText('newer draft', { userEdit: true });
  const newer = draft(f.state);
  f.confirmations[0].confirm();
  assert.equal(f.requests.length, 1, 'Reuse/confirmation must never send a request');
  if (superseded) assert.equal(draft(f.state), newer, 'A stale confirmation cannot replace a newer draft');
  else {
    assert.deepEqual(Array.from(f.c.splitFuzzerPayloadLines(f.state.fuzzerPayloadsText)), expected);
    assert.equal(f.state.fuzzerSourceTransactionId, null);
    assert.equal(f.state.fuzzerTarget, null);
  }
}
(async () => {
  const record = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
  assert.equal(Boolean(record.running), false); // serde omits false
  assert.equal(record.stopped, true);
  assert.deepEqual(record.results.map(row => row.index), [0, 2, 3, 4, 5]);
  await reuse(record, ['A', 'B', 'C']);
  // Derived in-memory controls, not additional runtime records or sends.
  const subset = { ...record, results: record.results.filter(row => row.index !== 4) };
  await reuse(subset, ['A', 'C'], true);
  const duplicates = { ...record, results: record.results.map(row => ({ ...row, payload: ['same', 'same', ''][row.index % 3] })) };
  await reuse(duplicates, ['same', 'same', '']);
  await reuse(subset, [], true, true);
  console.log(JSON.stringify({ served_app_sha256: crypto.createHash('sha256').update(served).digest('hex'),
    actual_saved_indices: record.results.map(row => row.index), recovered_payloads: ['A', 'B', 'C'],
    derived_subset: ['A', 'C'], derived_duplicates_and_empty: ['same', 'same', ''],
    mock_reads_per_case: 1, mutating_requests: 0, stale_confirmation_preserved: true }));
  console.log('PASS: served Reuse functions recover actual stopped slots; explicit subset, duplicate/empty and ownership controls pass without sends');
})().catch(error => { console.error(error); process.exitCode = 1; });
