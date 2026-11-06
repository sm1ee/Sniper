const test = require('node:test');
const assert = require('node:assert/strict');
const tcp = require(process.env.TCP_CAPTURE_MODULE || '../web/tcp-capture.js');
const tick = () => new Promise(resolve => setImmediate(resolve));
const policy = {enabled:true, direction:'both', revision:7, pending_count:1, paused_count:1, forwarding_count:0};
const pending = {pending_id:'p1', sequence:1, revision:0, direction:'client_to_server', original_base64:'QQ==', original_length:1, state:'pending'};
const connection = {id:'c1', status:'open', intercept_events:[]};
const event = n => ({...pending, pending_id:'event-' + n, sequence:n, state:'forwarded', selected_length:1, written_bytes:1, original_offset:n, destination_offset:n});

// Deliberately model the native focus-loss paths missing from the older mocks:
// removing a focused summary or disabling a focused button returns focus to BODY.
// Genuine browser coverage is recorded separately, not inferred from this model.
function fixture() {
  const nodes = new Map(), requests = [], listeners = {};
  let session = 'a', foreground = true;
  const document = {
    activeElement:null,
    addEventListener(name, fn) { (listeners[name] ||= []).push(fn); },
    hasFocus:() => foreground,
    getElementById(id) {
      if (!nodes.has(id)) { const node = createElement('div'); node.id = id; nodes.set(id, node); document.body.append(node); }
      return nodes.get(id);
    },
    createElement
  };
  function dispatch(name, target = document.activeElement) { for (const fn of listeners[name] || []) fn({target}); }
  function createElement(tag) {
    let disabled = false;
    return {
      tagName:tag.toUpperCase(), children:[], parentElement:null, dataset:{}, listeners:{}, value:'', textContent:'', hidden:false, open:false,
      scrollTop:0, scrollLeft:0, focusCalls:[], classList:{toggle() {}}, setAttribute() {},
      get disabled() { return disabled; },
      set disabled(value) { disabled = Boolean(value); if (disabled && document.activeElement === this) document.activeElement = document.body; },
      get isConnected() { return this === document.body || Boolean(this.parentElement?.isConnected); },
      contains(node) { return this === node || this.children.some(child => child.contains(node)); },
      closest(selector) { assert.equal(selector, '[hidden]'); return this.hidden ? this : this.parentElement?.closest(selector); },
      append(child) {
        if (child.parentElement) child.parentElement.children.splice(child.parentElement.children.indexOf(child), 1);
        this.children.push(child); child.parentElement = this;
      },
      replaceChildren() {
        if (this.children.some(child => child.contains(document.activeElement))) document.activeElement = document.body;
        for (const child of this.children) child.parentElement = null;
        this.children = []; this.scrollTop = 0; this.scrollLeft = 0;
      },
      querySelectorAll(selector) {
        return this.children.flatMap(child => [...(child.tagName.toLowerCase() === selector ? [child] : []), ...child.querySelectorAll(selector)]);
      },
      addEventListener(name, fn) { this.listeners[name] = fn; },
      focus(options) {
        if (this.disabled || !this.isConnected || this.closest('[hidden]')) return;
        this.focusCalls.push(options); document.activeElement = this; dispatch('focusin', this);
      }
    };
  }
  document.body = createElement('body'); document.documentElement = createElement('html'); document.activeElement = document.body;
  const get = id => document.getElementById(id);
  for (const id of ['tcpPendingPicker', 'tcpPendingHex', 'tcpForward', 'tcpDrop', 'tcpPendingReset']) get('tcpPendingSurface').append(get(id));
  get('tcpStreamSurface').append(get('tcpInterceptHistory'));
  const controller = tcp.createInterceptController({document, sessionId:() => session, readPath:p => p, writePath:p => p,
    request(path, options) {
      let resolve; const promise = new Promise(done => { resolve = done; });
      requests.push({path, options, resolve(data, status = 200) { resolve({ok:status >= 200 && status < 300, status, json:async () => data}); }});
      return promise;
    }});
  return {document, get, controller, requests, dispatch, session(value) { session = value; }, foreground(value) { foreground = value; },
    click(id) { get(id).listeners.click(); }};
}
async function resolveRead(f, items = [pending], status = 200) {
  f.requests.at(-2).resolve(policy); f.requests.at(-1).resolve({items}, status); await tick();
}
async function ready(f) { f.controller.setConnection(connection); await resolveRead(f); }
async function complete(f, items = [pending], status = 200, readStatus = 200) {
  f.requests.at(-1).resolve({}, status); await tick(); await resolveRead(f, items, readStatus);
}

test('a focused middle history summary survives appends and updates with expansion and scroll intact', async () => {
  const f = fixture(); await ready(f);
  const events = [0, 1, 2, 3].map(event);
  f.controller.setConnection({...connection, intercept_events:events});
  const host = f.get('tcpInterceptHistory'), old = host.children[2];
  old.open = true; old.children[0].focus(); host.scrollTop = 175; host.scrollLeft = 13;
  for (const next of [[...events, event(4)], [...events.slice(0, 2), {...event(2), written_bytes:0}, event(3), event(4)]]) {
    f.controller.setConnection({...connection, intercept_events:next});
    assert.equal(f.document.activeElement, host.children[2].children[0]);
    assert.equal(host.children[2].open, true);
    assert.deepEqual(f.document.activeElement.focusCalls.at(-1), {preventScroll:true});
    assert.equal(host.scrollTop, 175); assert.equal(host.scrollLeft, 13);
  }
  assert.equal(old.isConnected, false, 'the assertion exercises replacement, not an unchanged render');
});

test('history updates do not steal outside focus or restore removed events and cross-connection state', async () => {
  const f = fixture(); await ready(f);
  f.controller.setConnection({...connection, intercept_events:[event(1)]});
  const host = f.get('tcpInterceptHistory');
  f.get('tcpInterceptToggle').focus();
  f.controller.setConnection({...connection, intercept_events:[event(1), event(2)]});
  assert.equal(f.document.activeElement, f.get('tcpInterceptToggle'));
  host.children[0].children[0].focus();
  f.controller.setConnection({...connection, intercept_events:[event(2)]});
  assert.equal(f.document.activeElement, f.document.body);
  host.children[0].open = true; host.children[0].children[0].focus();
  f.controller.setConnection({...connection, id:'c2', intercept_events:[event(2)]});
  assert.equal(f.document.activeElement, f.document.body);
  assert.equal(host.children[0].open, false, 'matching event IDs in another connection do not inherit expansion');
});

test('history reset and session changes never refocus a matching event from another session', async () => {
  for (const reset of [false, true]) {
    const f = fixture(); await ready(f);
    f.controller.setConnection({...connection, intercept_events:[event(1)]});
    f.get('tcpInterceptHistory').children[0].children[0].focus();
    f.session('b'); if (reset) f.controller.reset();
    f.controller.setConnection({...connection, intercept_events:[event(1)]});
    assert.equal(f.document.activeElement, f.document.body);
  }
});

test('history without a usable event identity never acquires document focus', async () => {
  const f = fixture(); await ready(f);
  f.controller.setConnection({...connection, intercept_events:[{...event(1), pending_id:undefined}]});
  assert.equal(f.document.activeElement, f.document.body);
});

test('toggle and direction recover their focus only after authoritative action refresh, including errors', async () => {
  for (const id of ['tcpInterceptToggle', 'tcpInterceptDirection']) for (const status of [200, 409, 500]) {
    const f = fixture(); await ready(f); const target = f.get(id); target.focus();
    target.listeners[id === 'tcpInterceptDirection' ? 'change' : 'click']();
    assert.equal(f.document.activeElement, f.document.body); assert.equal(target.disabled, true);
    f.requests.at(-1).resolve({}, status); await tick();
    assert.equal(f.document.activeElement, f.document.body, 'do not restore before the fresh state read');
    await resolveRead(f);
    assert.equal(f.document.activeElement, target);
    assert.deepEqual(target.focusCalls.at(-1), {preventScroll:true});
    assert.equal(f.requests.filter(request => request.options).length, 1, 'focus recovery never retries the action');
    if (status !== 200) assert.match(f.get('tcpInterceptError').textContent, /outcome may be uncertain/);
  }
});

test('failed refresh keeps controls unavailable and restores on recovery only without intervening navigation', async () => {
  for (const navigate of [false, true]) {
    const f = fixture(); await ready(f); f.get('tcpInterceptToggle').focus(); f.click('tcpInterceptToggle');
    await complete(f, [pending], 200, 500);
    assert.equal(f.document.activeElement, f.document.body); assert.equal(f.get('tcpInterceptToggle').disabled, true);
    if (navigate) f.dispatch('keydown');
    const poll = f.controller.refresh(); await resolveRead(f); await poll;
    assert.equal(f.document.activeElement, navigate ? f.document.body : f.get('tcpInterceptToggle'));
  }
});

test('keyboard, pointer, focus, background and hidden-panel navigation all cancel action restoration', async () => {
  for (const navigate of [
    f => f.dispatch('keydown'),
    f => f.dispatch('pointerdown'),
    f => { f.get('tcpStreamTab').focus(); f.document.activeElement = f.document.body; },
    f => f.foreground(false),
    f => { f.get('tcpInterceptToggle').hidden = true; }
  ]) {
    const f = fixture(); await ready(f); f.get('tcpInterceptToggle').focus(); f.click('tcpInterceptToggle');
    navigate(f); await complete(f);
    assert.equal(f.document.activeElement, f.document.body);
    assert.equal(f.get('tcpInterceptToggle').focusCalls.length, 1);
  }
});

test('unfocused activation does not acquire focus, and focus elsewhere is preserved', async () => {
  for (const during of [false, true]) {
    const f = fixture(); await ready(f);
    if (during) f.get('tcpInterceptToggle').focus(); else f.get('tcpStreamTab').focus();
    f.click('tcpInterceptToggle');
    if (during) f.get('tcpStreamTab').focus();
    await complete(f); assert.equal(f.document.activeElement, f.get('tcpStreamTab'));
  }
});

test('connection changes away and back and session reset discard obsolete action focus', async () => {
  for (const sessionChange of [false, true]) {
    const f = fixture(); await ready(f); f.get('tcpInterceptToggle').focus(); f.click('tcpInterceptToggle');
    const write = f.requests.at(-1);
    if (sessionChange) { f.session('b'); f.controller.reset(); }
    else f.controller.setConnection({...connection, id:'c2'});
    f.controller.setConnection(connection);
    write.resolve({}); await tick(); await resolveRead(f);
    assert.equal(f.document.activeElement, f.document.body);
  }
});

test('Forward and Drop move to unselected pending navigation or stable tab without forwarding new bytes', async () => {
  for (const id of ['tcpForward', 'tcpDrop']) for (const remaining of [[], [{...pending, pending_id:'p2'}]]) {
    const f = fixture(); await ready(f); f.click('tcpPendingTab');
    f.get(id).focus(); f.click(id); await complete(f, remaining);
    assert.equal(f.document.activeElement, f.get(remaining.length ? 'tcpPendingPicker' : 'tcpPendingTab'));
    assert.equal(f.get('tcpPendingPicker').value, ''); assert.equal(f.get('tcpPendingHex').value, '');
    assert.equal(f.get('tcpForward').disabled, true);
    assert.equal(f.requests.filter(request => request.options).length, 1);
  }
});

test('failed decision restores the same action only while that pending range remains actionable', async () => {
  const f = fixture(); await ready(f); f.click('tcpPendingTab'); f.get('tcpForward').focus(); f.click('tcpForward');
  await complete(f, [pending], 409);
  assert.equal(f.document.activeElement, f.get('tcpForward'));
  assert.equal(f.get('tcpPendingPicker').value, 'p1');
  assert.match(f.get('tcpInterceptError').textContent, /state changed/);
});

test('decision completion never pulls focus from Stream navigation', async () => {
  const f = fixture(); await ready(f); f.click('tcpPendingTab'); f.get('tcpForward').focus(); f.click('tcpForward');
  f.dispatch('keydown'); f.get('tcpStreamTab').focus(); f.click('tcpStreamTab');
  await complete(f, [{...pending, pending_id:'p2'}]);
  assert.equal(f.document.activeElement, f.get('tcpStreamTab'));
});

test('Close restores its control while waiting, or the current tab when final state arrived first', async () => {
  for (const ended of [false, true]) {
    const f = fixture(); await ready(f); f.get('tcpCloseConnection').focus(); f.click('tcpCloseConnection');
    if (ended) f.controller.setConnection({...connection, status:'closed'});
    await complete(f, []);
    assert.equal(f.document.activeElement, f.get(ended ? 'tcpStreamTab' : 'tcpCloseConnection'));
  }
});

test('accepted Close keeps focus ownership until delayed terminal detail disables the button', async () => {
  for (const status of ['closed', 'stopped', 'failed', 'interrupted']) for (const tab of ['tcpStreamTab', 'tcpPendingTab']) {
    const f = fixture(); await ready(f); f.click(tab); f.get('tcpCloseConnection').focus(); f.click('tcpCloseConnection');
    await complete(f, []);
    assert.equal(f.document.activeElement, f.get('tcpCloseConnection'));
    assert.match(f.get('tcpInterceptNotice').textContent, /Waiting for final state/);
    f.controller.setConnection({...connection, status:'open'});
    assert.equal(f.document.activeElement, f.get('tcpCloseConnection'));
    f.controller.setConnection({...connection, status});
    assert.equal(f.document.activeElement, f.get(tab));
    assert.equal(f.get('tcpCloseConnection').disabled, true);
    assert.equal(f.get('tcpInterceptNotice').textContent, '');
    assert.deepEqual(f.get(tab).focusCalls.at(-1), {preventScroll:true});
  }
});

test('delayed Close completion yields to later navigation, new operations and session/connection changes', async () => {
  for (const move of [
    f => { f.dispatch('keydown'); f.get('tcpPendingTab').focus(); },
    f => { f.dispatch('pointerdown'); f.get('tcpPendingTab').focus(); },
    f => f.get('tcpPendingTab').focus(),
    f => { f.get('tcpInterceptToggle').focus(); f.click('tcpInterceptToggle'); },
    f => { f.controller.setConnection({...connection, id:'c2'}); f.controller.setConnection(connection); },
    f => { f.session('b'); f.controller.reset(); f.controller.setConnection(connection); }
  ]) {
    const f = fixture(); await ready(f); f.get('tcpCloseConnection').focus(); f.click('tcpCloseConnection');
    await complete(f, []); move(f);
    const active = f.document.activeElement;
    f.controller.setConnection({...connection, status:'closed'});
    assert.equal(f.document.activeElement, active);
    assert.equal(f.get('tcpStreamTab').focusCalls.length, 0);
  }
});

test('an uncertain Close does not reserve focus after recovery for unrelated later terminal state', async () => {
  const f = fixture(); await ready(f); f.get('tcpCloseConnection').focus(); f.click('tcpCloseConnection');
  await complete(f, [], 500);
  assert.equal(f.document.activeElement, f.get('tcpCloseConnection'));
  f.controller.setConnection({...connection, status:'closed'});
  assert.equal(f.document.activeElement, f.document.body);
  assert.match(f.get('tcpInterceptError').textContent, /outcome may be uncertain/);
});

test('accepted forwarding moves action focus to selected read-only bytes without overriding navigation', async () => {
  for (const navigate of [false, true]) {
    const f = fixture(); await ready(f); f.click('tcpPendingTab');
    f.get('tcpPendingHex').value = 'ff'; f.get('tcpPendingHex').listeners.input();
    f.get('tcpForward').focus(); f.click('tcpForward');
    if (navigate) { f.dispatch('keydown'); f.get('tcpStreamTab').focus(); f.click('tcpStreamTab'); }
    await complete(f, [{...pending, state:'forwarding', edited:true, selected_length:1, selected_base64:'/w=='}]);
    assert.equal(f.get('tcpPendingHex').value, 'ff');
    assert.equal(f.get('tcpPendingHex').readOnly, true);
    assert.equal(f.document.activeElement, f.get(navigate ? 'tcpStreamTab' : 'tcpPendingHex'));
    assert.equal(f.requests.filter(request => request.options).length, 1);
  }
});

test('selected byte focus moves to safe navigation when forwarding settles, without selecting new bytes', async () => {
  for (const remaining of [[], [{...pending, pending_id:'p2'}]]) {
    const f = fixture(); await ready(f); f.click('tcpPendingTab');
    f.get('tcpForward').focus(); f.click('tcpForward');
    await complete(f, [{...pending, state:'forwarding', edited:true, selected_length:1, selected_base64:'/w=='}]);
    assert.equal(f.document.activeElement, f.get('tcpPendingHex'));
    const poll = f.controller.refresh(); await resolveRead(f, remaining); await poll;
    assert.equal(f.document.activeElement, f.get(remaining.length ? 'tcpPendingPicker' : 'tcpPendingTab'));
    assert.equal(f.get('tcpPendingPicker').value, ''); assert.equal(f.get('tcpForward').disabled, true);
    assert.equal(f.requests.filter(request => request.options).length, 1);
  }
});

test('failed forwarding poll moves preview focus to a stable tab and recovery does not steal navigation', async () => {
  const item = {...pending, state:'forwarding', edited:true, selected_length:1, selected_base64:'/w=='};
  for (const navigate of [false, true]) {
    const f = fixture(); await ready(f); f.click('tcpPendingTab');
    f.get('tcpForward').focus(); f.click('tcpForward'); await complete(f, [item]);
    assert.equal(f.document.activeElement, f.get('tcpPendingHex'));
    const fail = f.controller.refresh(); await resolveRead(f, [], 500); await fail;
    assert.equal(f.document.activeElement, f.get('tcpPendingTab'));
    if (navigate) { f.dispatch('keydown'); f.get('tcpStreamTab').focus(); f.click('tcpStreamTab'); }
    const recover = f.controller.refresh(); await resolveRead(f, [item]); await recover;
    assert.equal(f.document.activeElement, f.get(navigate ? 'tcpStreamTab' : 'tcpPendingTab'));
    assert.equal(f.get('tcpPendingHex').value, 'ff'); assert.equal(f.get('tcpPendingHex').readOnly, true);
    assert.equal(f.requests.filter(request => request.options).length, 1);
  }
});
