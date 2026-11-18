// Production Fuzzer editor and position actions over a binary body, with the
// shipped CodeMirror state and history; synthetic bytes, no request is sent.
const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const { editorFixture, source, CM } = require('./replay-editor-fixture.cjs');
const workflow = require('../web/fuzzer-workflow.js');

const head = 'POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: 6\r\n\r\n';
// Byte A7 is `§`; the body also holds a CRLF.
const bytes = '\x89\xa7\x00\r\nZ';
const A7 = workflow.BYTE_A7;
const btoa = value => Buffer.from(value, 'binary').toString('base64');
const atob = value => Buffer.from(value, 'base64').toString('binary');
const docHead = head.replace(/\r\n/g, '\n').length;

function fixture() {
  const f = editorFixture();
  const OriginalView = f.context.CM.EditorView;
  class View extends OriginalView {
    constructor(options) { super(options); this.contentDOM.setAttribute = () => {}; }
  }
  f.context.CM.EditorView = View;
  Object.assign(f.els, { fuzzerRequestCM: {}, fuzzerPayloadsEditor: { value: '' }, fuzzerMeta: {} });
  Object.assign(f.context, {
    SniperFuzzerWorkflow: workflow,
    renderFuzzerResultsWorkflow() {}, renderFuzzerSetup() {}, renderEmptyFuzzerResults() {},
    renderFuzzerPayloadsEditor() {}, wireFuzzerMarkerSelection() {}, scheduleFuzzerSetupRender() {},
    scheduleWorkspaceStateSave() {}, fuzzerSetupNode: () => null,
  });
  for (const name of ['renderFuzzer', 'updateFuzzerRequestText', 'markFuzzerDraftChanged', 'fuzzerBodyIsBinary',
    'fuzzerShownText', 'fuzzerStoredText', 'fuzzerDraftShowsBytes', 'fuzzerMarkerDraft', 'fuzzerRequestTextForAction', 'parseFuzzerRequestTemplate',
    'fuzzerRawOffsetForEditorOffset', 'markFuzzerPosition', 'markFuzzerEditorSelection', 'fuzzerMarkerRemoval',
    'renderFuzzerRemoveMarkerControl', 'removeFuzzerEditorPosition', 'clearFuzzerMarkers', 'undoFuzzerMarker']) {
    vm.runInContext(source(name), f.context);
  }
  f.state.fuzzerBaseRequest = {
    scheme: 'https', host: 'example.com', method: 'POST', path: '/upload', body: btoa(bytes), body_encoding: 'base64',
    headers: [{ name: 'Host', value: 'example.com' }, { name: 'Content-Type', value: 'application/octet-stream' }],
    preview_truncated: false,
  };
  f.state.fuzzerRequestText = head + btoa(bytes);
  f.state.fuzzerPayloadsText = '';
  f.cv = () => f.context.getCMView('fuzzerReq');
  f.render = () => f.context.renderFuzzer();
  f.select = (anchor, headOffset = anchor) => f.cv().view.dispatch({ selection: { anchor, head: headOffset } });
  f.undo = () => CM.undo(f.cv().view);
  f.render();
  return f;
}

test('the Fuzzer editor shows a binary body as bytes and keeps what is typed as typed', () => {
  const f = fixture();
  assert.equal(f.cv().getText(), `${head}\x89${A7}\x00\r\nZ`);
  const end = f.cv().view.state.doc.length;
  f.edit(end, end, '한');
  assert.equal(f.state.fuzzerRequestText, head + btoa(`${bytes}\xed\x95\x9c`));
  f.render();
  assert.equal(f.cv().getText(), `${head}\x89${A7}\x00\r\nZ한`, 'not redrawn as its UTF-8 bytes');
  assert.equal(f.undo(), true);
  assert.equal(f.state.fuzzerRequestText, head + btoa(bytes));
});

test('a typed pair of § is a position and a lone § is byte A7', () => {
  const f = fixture();
  const end = f.cv().view.state.doc.length;
  f.edit(end, end, '§');
  assert.equal(f.state.fuzzerRequestText, head + btoa(`${bytes}\xa7`));
  f.edit(end + 1, end + 1, 'q§');
  assert.equal(f.state.fuzzerRequestText, `${head}${btoa(bytes)}§${btoa('q')}§`);
});

test('Add § marks the selected bytes; Undo, Remove and Clear give the bytes back', () => {
  const f = fixture();
  const marked = `${head}${btoa('\x89')}§${btoa('\xa7\x00')}§${btoa('\r\nZ')}`;
  f.select(docHead + 1, docHead + 3);
  f.context.markFuzzerEditorSelection();
  assert.equal(f.state.fuzzerRequestText, marked);
  assert.equal(f.cv().getText(), `${head}\x89§${A7}\x00§\r\nZ`);
  const template = f.context.parseFuzzerRequestTemplate(marked);
  assert.equal(template.body, marked.slice(head.length));
  assert.equal(template.headers.find(header => header.name === 'Content-Length').value, '6');
  const checked = workflow.preflight(template, ['é'], { attackType: 'sniper' });
  assert.equal(checked.valid, true, checked.errors.join(' '));
  assert.equal(checked.markerCount, 1);
  assert.equal(atob(checked.samples[0].request.body), '\x89\xc3\xa9\r\nZ');

  f.context.undoFuzzerMarker();
  assert.equal(f.state.fuzzerRequestText, head + btoa(bytes));
  assert.equal(f.cv().getText(), `${head}\x89${A7}\x00\r\nZ`);

  f.select(docHead + 1, docHead + 3);
  f.context.markFuzzerEditorSelection();
  f.select(docHead + 3);
  f.context.removeFuzzerEditorPosition();
  assert.equal(f.state.fuzzerRequestText, head + btoa(bytes));

  f.select(docHead + 1, docHead + 3);
  f.context.markFuzzerEditorSelection();
  f.context.clearFuzzerMarkers();
  assert.equal(f.state.fuzzerRequestText, head + btoa(bytes));
});

test('a stored body that is not Base64 is shown and edited as it is stored', () => {
  const f = fixture();
  const stored = `${head}iVBORw0$payload$KGgoAAAANSUhEUg==`;
  f.state.fuzzerRequestText = stored;
  f.render();
  assert.equal(f.cv().getText(), stored);
  f.edit(6, 6, 'x');
  assert.equal(f.state.fuzzerRequestText, stored.replace('/upload', '/xupload'));
});

test('bytes that spell $payload$ stay bytes through edits and Clear', () => {
  const f = fixture();
  const withHeader = head.replace('Content-Length: 6', 'X-T: 1\r\nContent-Length: 13');
  const edited = withHeader.replace('/upload', '/xupload') + btoa('AB$payload$CD');
  f.state.fuzzerRequestText = withHeader + btoa('AB$payload$CD');
  f.render();
  assert.equal(f.cv().getText(), `${withHeader}AB${workflow.BYTE_24}payload$CD`);
  f.edit(6, 6, 'x');
  assert.equal(f.state.fuzzerRequestText, edited);
  const one = f.cv().getContent().indexOf('X-T: 1') + 5;
  f.select(one, one + 1);
  f.context.markFuzzerEditorSelection();
  f.context.clearFuzzerMarkers();
  assert.equal(f.state.fuzzerRequestText, edited);
});

test('a CR byte and an LF byte brought together by an edit still mark the selected byte', () => {
  const f = fixture();
  f.state.fuzzerRequestText = head + btoa('A\rB\nCD');
  f.render();
  const b = f.cv().getContent().lastIndexOf('B');
  f.edit(b, b + 1, '');
  assert.equal(f.state.fuzzerRequestText, head + btoa('A\r\nCD'));
  const c = f.cv().getContent().lastIndexOf('C');
  f.select(c, c + 1);
  f.context.markFuzzerEditorSelection();
  assert.equal(f.state.fuzzerRequestText, `${head}${btoa('A\r\n')}§${btoa('C')}§${btoa('D')}`);
});
