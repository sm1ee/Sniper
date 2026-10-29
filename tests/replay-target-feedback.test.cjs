// Static markup and production handlers/rendering in memory; no browser or Send.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');
const { appSource } = require('./frontend-test-helpers.cjs');
const { editorFixture, source } = require('./replay-editor-fixture.cjs');

const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');
const css = fs.readFileSync(path.join(__dirname, '../web/styles.css'), 'utf8');
const fields = [['replayHostInput', 'replayHostError', 'hostError'], ['replayPortInput', 'replayPortError', 'portError']];

function setup() {
  const f = editorFixture();
  vm.runInContext(source('applyReplayTargetFields'), f.context);
  Object.assign(f.context, { formatStatus: value => String(value), buildRawResponse: () => 'Prior response' });
  for (const [inputId, errorId] of fields) {
    const input = f.els[inputId];
    input.attributes = {};
    input.setAttribute = (name, value) => { input.attributes[name] = String(value); };
    input.toggleAttribute = (name, enabled) => {
      if (enabled) input.attributes[name] = ''; else delete input.attributes[name];
    };
    input.listeners = {};
    input.addEventListener = (type, listener) => { input.listeners[type] = listener; };
    const error = f.els[errorId] = { textContent: '' };
    Object.defineProperty(error, 'innerHTML', { set() { throw new Error('Error messages must use textContent'); } });
    const marker = `  els.${inputId}.addEventListener("input", () => {`;
    const binding = appSource.slice(appSource.indexOf(marker));
    vm.runInContext(binding.slice(0, binding.indexOf('\n  });') + 6), f.context);
  }
  f.render();
  f.a.responseRecord = { id: 'prior-response', status: 200, response: { headers: [], content_type: 'text/plain' } };
  f.a.notice = 'Prior response notice';
  f.input = async (id, value) => {
    f.document.activeElement = f.els[id]; f.els[id].value = value;
    f.els[id].listeners.input(); await Promise.resolve();
  };
  return f;
}

function assertFeedback(f, hostError = '', portError = '') {
  for (const [inputId, errorId, key] of fields) {
    const message = key === 'hostError' ? hostError : portError;
    assert.equal(f.els[inputId].validationMessage, message);
    assert.equal(f.els[inputId].attributes['aria-invalid'], String(!!message));
    assert.equal(f.els[errorId].textContent, message);
  }
}

test('target inputs have unique error descriptions outside their labels', () => {
  const toolbar = html.match(/<header class="replay-toolbar" id="httpReplayToolbar">([^]*?)<\/header>/)[1];
  for (const [inputId, errorId] of fields) {
    assert.equal([...html.matchAll(new RegExp(`\\bid="${errorId}"`, 'g'))].length, 1);
    const input = toolbar.match(new RegExp(`<input\\b[^>]*\\bid="${inputId}"[^>]*>`))[0];
    assert.match(input, new RegExp(`aria-describedby="${errorId}"`));
    assert.match(toolbar, new RegExp(`<p\\b[^>]*\\bid="${errorId}"[^>]*class="replay-target-error"[^>]*><\\/p>`));
    for (const label of toolbar.matchAll(/<label\b[^>]*>[^]*?<\/label>/g)) {
      assert.doesNotMatch(label[0], new RegExp(`id="${errorId}"`));
    }
  }
});

test('both errors span the target grid, collapse when empty, and wrap rather than truncate', () => {
  const rule = css.match(/\.replay-target-error\s*\{([^}]+)\}/)?.[1];
  assert.ok(rule);
  for (const declaration of [/grid-column:\s*1\s*\/\s*-1/, /min-width:\s*0/, /margin:\s*0/,
    /overflow-wrap:\s*anywhere/, /color:\s*var\(--danger\)/]) assert.match(rule, declaration);
  assert.doesNotMatch(rule, /white-space:\s*nowrap|text-overflow:\s*ellipsis|(?:^|;)\s*(?:max-)?height:\s*\d/);
  assert.match(css, /\.replay-target-error:empty\s*\{\s*display:\s*none;?\s*\}/);
  assert.match(css, /\.replay-target-bar input\[aria-invalid="true"\]\s*\{[^}]*border-color:\s*var\(--danger\)/);
});

for (const [id, value, hostError, portError] of [
  ['replayHostInput', 'bad host', 'Target host must not include whitespace, user info, or URL components.', ''],
  ['replayPortInput', '70000', '', 'Port must be a number from 1 to 65535.'],
  ['replayHostInput', 'https://example.com:8443', '', 'Port conflicts with target URL port 8443.'],
]) {
  test(`${id} shows its error on input without changing the prior response or draft`, async () => {
    const f = setup(), before = JSON.stringify(f.a), response = f.a.responseRecord;
    const saveVersion = f.context.workspaceSaveVersion;
    await f.input(id, value);
    assertFeedback(f, hostError, portError);
    assert.equal(JSON.stringify(f.a), before);
    assert.equal(f.a.responseRecord, response);
    assert.equal(f.context.workspaceSaveVersion, saveVersion);
    assert.equal(f.document.activeElement, f.els[id]);
    assert.equal(f.els[id].value, value);
  });
}

test('both field errors remain distinct and correction clears each one independently', async () => {
  const f = setup(), response = f.a.responseRecord;
  await f.input('replayHostInput', 'bad host'); await f.input('replayPortInput', '70000');
  assertFeedback(f, 'Target host must not include whitespace, user info, or URL components.', 'Port must be a number from 1 to 65535.');
  await f.input('replayHostInput', 'example.com');
  assertFeedback(f, '', 'Port must be a number from 1 to 65535.');
  assert.equal(f.a.responseRecord, response);
  await f.input('replayPortInput', '443'); assertFeedback(f);
});

test('feedback is assigned as literal text, not markup', () => {
  const f = setup(), message = '<img src=x onerror=example> & invalid';
  f.context.setReplayTargetInputValidity({ hostError: message, portError: message });
  assertFeedback(f, message, message);
});

for (const missing of [
  ['replayHostError'], ['replayPortError'], ['replayHostError', 'replayPortError'],
  ['replayHostInput'], ['replayPortInput'], ['replayHostInput', 'replayPortInput'],
  fields.flatMap(([input, error]) => [input, error]),
]) {
  test(`validity tolerates missing ${missing.join(', ')} without skipping other controls`, () => {
    const f = setup(); for (const id of missing) delete f.els[id];
    f.context.setReplayTargetInputValidity({ hostError: 'Host error', portError: 'Port error' });
    for (const [inputId, errorId, key] of fields) {
      const message = key === 'hostError' ? 'Host error' : 'Port error';
      if (f.els[inputId]) {
        assert.equal(f.els[inputId].validationMessage, message);
        assert.equal(f.els[inputId].attributes['aria-invalid'], 'true');
      }
      if (f.els[errorId]) assert.equal(f.els[errorId].textContent, message);
    }
  });
}

test('same-owner focused redraw retains invalid draft feedback and refused tab navigation', async () => {
  const f = setup(); await f.input('replayPortInput', '70000');
  const before = JSON.stringify(f.a);
  for (let i = 0; i < 2; i++) f.render();
  assertFeedback(f, '', 'Port must be a number from 1 to 65535.');
  assert.equal(f.els.replayPortInput.value, '70000');
  assert.equal(f.context.preserveActiveHttpReplayDraftBeforeNavigation(f.a, 'switching tabs'), false);
  assert.equal(JSON.stringify(f.a), before);
  await f.input('replayPortInput', '443'); f.switchTo(f.b);
  assert.equal(f.state.activeReplayTabId, f.b.id); assertFeedback(f);
});

for (const boundary of ['tab', 'same-ID owner', 'session', 'workspace generation']) {
  test(`${boundary} replacement resets stale feedback from focused prior controls`, async () => {
    const f = setup(); await f.input('replayPortInput', '70000');
    if (boundary === 'tab') f.state.activeReplayTabId = f.b.id;
    else if (boundary === 'same-ID owner') f.state.replayTabs[0] = { ...f.a };
    else if (boundary === 'session') f.state.activeSession = { id: 'session-b' };
    else f.context.workspaceStateGeneration++;
    f.render(); assertFeedback(f);
    assert.equal(f.els.replayPortInput.value, '443');
  });
}

for (const clear of ['no tab', 'cleared session']) {
  test(`${clear} rendering clears inline, native, and semantic target errors`, async () => {
    const f = setup(); await f.input('replayHostInput', 'bad host'); await f.input('replayPortInput', '70000');
    if (clear === 'no tab') {
      f.state.replayTabs = []; f.state.activeReplayTabId = null; f.render();
    } else f.context.renderReplayClearedState();
    assertFeedback(f);
    assert.equal(f.els.replayHostInput.value, ''); assert.equal(f.els.replayPortInput.value, '');
  });
}
