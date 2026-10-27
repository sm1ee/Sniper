const test = require('node:test');
const assert = require('node:assert/strict');
const { fixture, scan, inside, settle } = require('./templates-lifecycle-fixture.cjs');

async function openJob(f, job) {
  f.jobs.set('session-a', [job]);
  await f.controller.syncSession();
  f.get('ScanJobs').dispatch('click', { target: inside(f.get('ScanJobs').children[0]) });
  await settle();
}

test('Matched only describes the recent log when an older retained match has rolled out', async () => {
  const f = await fixture();
  const job = scan('retained-match', 'session-a', 'completed');
  job.sent = 201; job.planned = 201; job.matched = 1;
  job.recent = Array.from({ length: 200 }, (_, index) => ({
    at: String(index), template_id: 'example-template', method: 'GET',
    url: `https://app.example.com/recent/${index}`, status: 404, ms: 1, matched: false,
  }));
  job.results = [{ record_id: 'retained-record', template_id: 'example-template', method: 'GET', url: 'https://app.example.com/earlier' }];
  await openJob(f, job);
  assert.equal(f.get('ResultsRows').children.length, 200);
  f.get('ResultsMatched').dispatch('click');
  assert.match(f.get('ResultsTitle').textContent, /201 of 201 sent · 1 matched/);
  assert.equal(f.get('ResultsRows').children[0].children[0].textContent, 'No matches in the recent request log.');
  assert.equal(job.results[0].record_id, 'retained-record', 'the retained match is not discarded');
  f.get('ResultsMatched').dispatch('click');
  assert.equal(f.get('ResultsRows').children.length, 200);
  f.controller.dispose();
});

for (const [status, message] of [['running', 'No requests yet.'], ['completed', 'No requests.']]) {
  test(`an unfiltered ${status} empty job keeps its concise empty state`, async () => {
    const f = await fixture(); await openJob(f, scan('empty-job', 'session-a', status));
    assert.equal(f.get('ResultsRows').children[0].children[0].textContent, message);
    f.controller.dispose();
  });
}
