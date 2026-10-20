// Production controller and tool-navigation functions with an inert, synthetic
// DOM. No app bootstrap, browser, server, sockets, or retained user data.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const { loadFunctions } = require('./frontend-test-helpers.cjs');
const source = fs.readFileSync(path.join(__dirname, '../web/service-map.js'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, '../web/index.html'), 'utf8');

function fixture() {
  const document = { activeElement: null, querySelector: () => null };
  function node(tagName = 'DIV', dataset = {}) {
    const classes = new Set(), listeners = new Map();
    let markup = '';
    const value = {
      tagName, dataset, children: [], parentElement: null, open: false, isConnected: true,
      value: '', textContent: '', disabled: false, scrollTop: 0, scrollLeft: 0, clientWidth: 800, clientHeight: 500,
      style: { setProperty() {} }, attributes: {}, focusCount: 0,
      classList: { toggle(name, on = !classes.has(name)) { on ? classes.add(name) : classes.delete(name); }, contains: name => classes.has(name) },
      setAttribute(name, content) { this.attributes[name] = content; },
      append(child) { child.parentElement = this; this.children.push(child); return child; },
      contains(child) { return !!child && (child === this || this.children.some(item => item.contains(child))); },
      closest(selector) {
        if ((selector === 'button' && this.tagName === 'BUTTON') || (selector === 'details' && this.tagName === 'DETAILS')) return this;
        return this.parentElement?.closest(selector) || null;
      },
      querySelector(selector) { return this.querySelectorAll(selector)[0] || null; },
      querySelectorAll(selector) {
        const matches = item => selector === 'summary' ? item.tagName === 'SUMMARY'
          : selector === '#serviceMapProductFilters' ? item.id === 'serviceMapProductFilters'
          : selector === '[data-service-focus]' ? !!item.dataset.serviceFocus : false;
        return this.children.flatMap(child => [...(matches(child) ? [child] : []), ...child.querySelectorAll(selector)]);
      },
      getClientRects() { return this.isConnected ? [{}] : []; },
      focus(options) { document.activeElement = this; this.focusCount += 1; this.focusOptions = options; },
      addEventListener(type, callback, options) {
        const items = listeners.get(type) || [];
        items.push({ callback, capture: options === true || !!options?.capture }); listeners.set(type, items);
      },
      removeEventListener(type, callback) { listeners.set(type, (listeners.get(type) || []).filter(item => item.callback !== callback)); },
      listenerCount(type) { return (listeners.get(type) || []).length; },
      emit(type, extra = {}) {
        const event = { type, target: this, defaultPrevented: false, propagationStopped: false,
          preventDefault() { this.defaultPrevented = true; }, stopPropagation() { this.propagationStopped = true; }, ...extra };
        const chain = []; for (let item = this; item; item = item.parentElement) chain.push(item);
        const call = (item, capture) => {
          event.currentTarget = item;
          for (const listener of item._listeners.get(type) || []) if (listener.capture === capture) listener.callback(event);
        };
        for (const item of [...chain].reverse()) { call(item, true); if (event.propagationStopped) break; }
        if (!event.propagationStopped) for (const item of chain) { call(item, false); if (event.propagationStopped) break; }
        if (type === 'click' && this.tagName === 'SUMMARY' && !event.defaultPrevented) this.parentElement.open = !this.parentElement.open;
        return event;
      },
      _listeners: listeners,
      get innerHTML() { return markup; },
      set innerHTML(content) {
        markup = content;
        if (this.id !== 'serviceMapProductFilters') return;
        for (const child of this.children) {
          child.isConnected = false;
          if (document.activeElement === child) document.activeElement = document.body;
        }
        this.children = [];
        for (const [, tag, attrs] of content.matchAll(/<(select|button)\b([^>]+)>/g)) {
          const data = {};
          for (const [, key, text] of attrs.matchAll(/data-([a-z-]+)="([^"]+)"/g)) data[key.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = text;
          this.append(node(tag.toUpperCase(), data));
        }
      },
    };
    return value;
  }
  Object.assign(document, node('DOCUMENT'));
  document.body = document.append(node('BODY'));
  document.activeElement = document.body;
  const els = Object.fromEntries(['panel', 'status', 'refresh', 'search', 'scope', 'canvas', 'graphBounds', 'detail', 'content', 'catalog', 'viewport'].map(key => [key, node()]));
  document.body.append(els.panel);
  for (const [key, item] of Object.entries(els)) if (key !== 'panel') els.panel.append(item);
  assert.match(html, /<details class="service-map-product-filters"><summary>Products \/ versions<\/summary><div id="serviceMapProductFilters"/);
  const popover = els.panel.append(node('DETAILS'));
  const summary = popover.append(node('SUMMARY'));
  const products = popover.append(node()); products.id = 'serviceMapProductFilters';
  const outside = document.body.append(node('BUTTON'));
  const context = vm.createContext({ URL, URLSearchParams, AbortController, console });
  vm.runInContext(source, context);
  const requests = [];
  const controller = context.SniperServiceMap.createController({ elements: els, document, getSessionId: () => 'session-one',
    request(url, options) { requests.push({ url, options }); return Promise.resolve({ ok: true, json: async () => ({ schema_version: 1, session_id: 'session-one',
      snapshot: { generation: 'generation-one', complete: true, stopped_by: [], considered_rows: 1, retained_rows: 1, included_rows: 1, excluded_rows: 0, omitted_rows: 0 },
      origins: [{ origin: 'https://app.example.com', in_scope: true, request_count: 1, endpoints: [], technology_clues: [], redirects: [], header_links: [] }] }) }); } });
  controller.setVisible(true);
  const product = () => products.children.find(item => item.dataset.serviceProductFilter === 'product');
  const version = () => products.children.find(item => item.dataset.serviceProductFilter === 'version');
  const clear = () => products.children.find(item => item.dataset.serviceProductFilterClear);
  const appEls = Object.fromEntries(['dashboardShell', 'proxyShell', 'replayShell', 'toolsShell', 'fuzzerShell', 'sequenceShell', 'targetShell', 'mapShell', 'loggerShell', 'footerMode'].map(key => [key, node()]));
  const app = loadFunctions(['renderToolPanels'], { state: { activeTool: 'map', activeTargetView: 'service-map' }, els: appEls,
    targetServiceMapController: controller, mainTabs: [], sanitizeActiveTool: value => value, renderProxyPanels() {} });
  return { controller, state: controller.getState(), els, document, popover, summary, products, product, version, clear, outside, requests,
    open() { summary.emit('pointerdown'); summary.focus(); summary.emit('click'); assert.equal(popover.open, true); },
    navigate(tool) { app.state.activeTool = tool; app.renderToolPanels(); },
    filter(kind, value) { const control = kind === 'product' ? product() : version(); control.value = value; control.focus(); control.emit('change'); },
  };
}

test('inside product controls and native summary activation preserve the open disclosure', () => {
  const f = fixture(); f.open();
  f.product().focus();
  const pointer = f.product().emit('pointerdown'); f.product().emit('click');
  assert.equal(f.popover.open, true); assert.equal(pointer.defaultPrevented, false);
  f.filter('product', 'nginx'); f.filter('version', 'reported:1.26.2');
  assert.equal(f.popover.open, true); assert.equal(f.state.productId, 'nginx'); assert.equal(f.state.productVersion, 'reported:1.26.2');
  assert.equal(f.document.activeElement, f.version(), 'a rerender keeps the active filter control focused');
  f.clear().emit('pointerdown'); f.clear().emit('click');
  assert.equal(f.popover.open, true); assert.equal(f.state.productId, ''); assert.equal(f.state.productVersion, '');
  f.summary.emit('pointerdown'); f.summary.emit('click');
  assert.equal(f.popover.open, false, 'native summary still closes once instead of closing and reopening');
  f.controller.destroy();
});

test('outside pointer dismissal preserves filter values, selection, and the new pointer target', async () => {
  const f = fixture(); await f.controller.refresh(); f.controller.selectOrigin('https://app.example.com');
  f.open(); f.filter('product', 'nginx'); f.filter('version', 'reported:1.26.2');
  f.outside.focus();
  const event = f.outside.emit('pointerdown');
  assert.equal(f.popover.open, false);
  assert.equal(event.defaultPrevented, false); assert.equal(f.document.activeElement, f.outside);
  assert.equal(f.summary.focusCount, 1, 'pointer dismissal never steals focus back');
  assert.equal(f.state.productId, 'nginx'); assert.equal(f.state.productVersion, 'reported:1.26.2');
  assert.equal(f.state.selectedOrigin, 'https://app.example.com'); assert.equal(f.requests.length, 1);
  f.controller.destroy();
});

test('Escape from a product control closes once and restores the summary without scrolling', () => {
  const f = fixture(); f.open(); f.filter('product', 'nginx'); f.product().focus();
  const event = f.product().emit('keydown', { key: 'Escape' });
  assert.equal(f.popover.open, false); assert.equal(event.defaultPrevented, true);
  assert.equal(f.document.activeElement, f.summary); assert.equal(f.state.productId, 'nginx');
  assert.equal(f.summary.focusOptions.preventScroll, true);
  const closed = f.summary.emit('keydown', { key: 'Escape' });
  assert.equal(closed.defaultPrevented, false); assert.equal(f.summary.focusCount, 2);
  f.controller.destroy();
});

test('unrelated keys, IME Escape, and an already-handled Escape leave product filters open', () => {
  const f = fixture(); f.open(); f.product().focus();
  for (const event of [{ key: 'Tab' }, { key: 'Escape', isComposing: true }, { key: 'Escape', defaultPrevented: true }]) {
    f.product().emit('keydown', event); assert.equal(f.popover.open, true); assert.equal(f.document.activeElement, f.product());
  }
  f.controller.destroy();
});

test('Escape after focus moves elsewhere closes the popover without taking focus back', () => {
  const f = fixture(); f.open(); f.outside.focus();
  const event = f.outside.emit('keydown', { key: 'Escape' });
  assert.equal(f.popover.open, false); assert.equal(event.defaultPrevented, true); assert.equal(f.document.activeElement, f.outside);
  f.controller.destroy();
});

test('real tool-panel navigation closes product filters, retains selection, and does not reopen on return', async () => {
  const f = fixture(); await f.controller.refresh(); f.controller.selectOrigin('https://app.example.com');
  f.open(); f.filter('product', 'nginx'); f.outside.focus(); f.navigate('proxy');
  assert.equal(f.popover.open, false); assert.equal(f.document.activeElement, f.outside);
  f.navigate('map');
  assert.equal(f.popover.open, false); assert.equal(f.state.productId, 'nginx'); assert.equal(f.state.selectedOrigin, 'https://app.example.com');
  f.controller.destroy();
});

test('same-view renders preserve an open popover while changing Map views dismisses it without focusing a hidden control', () => {
  const f = fixture(); f.open(); f.product().focus();
  f.navigate('map'); assert.equal(f.popover.open, true);
  f.controller.setVisible(true, 'apis');
  assert.equal(f.popover.open, false); assert.equal(f.summary.focusCount, 1);
  f.controller.setVisible(true, 'service-map'); assert.equal(f.popover.open, false);
  f.controller.destroy();
});

test('outside pointer dismisses even when its target stops bubbling, without cancelling the target action', () => {
  const f = fixture(); f.open();
  let clicked = 0;
  f.outside.addEventListener('pointerdown', event => event.stopPropagation());
  f.outside.addEventListener('click', () => { clicked += 1; });
  assert.equal(f.outside.emit('pointerdown').defaultPrevented, false);
  f.outside.emit('click');
  assert.equal(f.popover.open, false); assert.equal(clicked, 1);
  f.controller.destroy();
});

test('repeated product opens and dismissals do not accumulate document listeners', () => {
  const f = fixture(), initial = [f.document.listenerCount('pointerdown'), f.document.listenerCount('keydown')];
  assert.deepEqual(initial, [1, 1]);
  for (let i = 0; i < 4; i += 1) {
    f.open(); f.product().focus(); f.product().emit('keydown', { key: 'Escape' }); assert.equal(f.popover.open, false);
    f.open(); f.outside.emit('pointerdown'); assert.equal(f.popover.open, false);
    assert.deepEqual([f.document.listenerCount('pointerdown'), f.document.listenerCount('keydown')], initial);
  }
  f.controller.destroy();
  assert.equal(f.document.listenerCount('pointerdown'), 0); assert.equal(f.document.listenerCount('keydown'), 0);
});

test('destroy closes the current popover and releases document handlers without restoring focus', () => {
  const f = fixture(); f.open(); f.product().focus(); const focused = f.document.activeElement;
  f.controller.destroy();
  assert.equal(f.popover.open, false); assert.equal(f.document.activeElement, focused);
  f.popover.open = true;
  f.outside.emit('pointerdown'); f.product().emit('keydown', { key: 'Escape' });
  assert.equal(f.popover.open, true); assert.equal(f.document.activeElement, focused);
  assert.equal(f.document.listenerCount('pointerdown'), 0); assert.equal(f.document.listenerCount('keydown'), 0);
});
