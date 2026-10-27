const templates = require('../web/templates.js');

function element() {
  const classes = new Set(), attributes = new Map(), listeners = new Map();
  return {
    textContent: '', value: '', checked: false, disabled: false, dataset: {}, children: [], style: {},
    classList: {
      toggle(name, on) { if (on === undefined ? !classes.has(name) : on) classes.add(name); else classes.delete(name); },
      contains: (name) => classes.has(name), add: (name) => classes.add(name), remove: (name) => classes.delete(name),
    },
    addEventListener(type, callback) { if (!listeners.has(type)) listeners.set(type, []); listeners.get(type).push(callback); },
    removeEventListener(type, callback) { listeners.set(type, (listeners.get(type) || []).filter((fn) => fn !== callback)); },
    dispatch(type, event = {}) { for (const callback of listeners.get(type) || []) callback({ preventDefault() {}, ...event }); },
    setAttribute: (name, value) => attributes.set(name, String(value)), removeAttribute: (name) => attributes.delete(name),
    getAttribute: (name) => attributes.get(name) ?? null,
    replaceChildren(...nodes) { this.children = nodes; }, append(...nodes) { this.children.push(...nodes); },
    querySelector: () => null, querySelectorAll: () => [], closest: () => null,
  };
}
const settle = async () => { for (let i = 0; i < 6; i++) await new Promise(setImmediate); };
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
const response = (body) => ({ ok: true, json: async () => body });
function inside(node) {
  return { closest(selector) { const key = selector.match(/^\[data-([a-z-]+)\]$/)?.[1]?.replace(/-([a-z])/g, (_, c) => c.toUpperCase()); return key && key in node.dataset ? node : null; } };
}
async function fixture() {
  let session = 'session-a', intercept = () => undefined;
  const els = new Map(), requests = [], timers = new Map(), jobs = new Map();
  let timerId = 0;
  const doc = Object.assign(element(), { createElement: element });
  const root = { ownerDocument: doc, querySelector(selector) { if (!els.has(selector)) els.set(selector, element()); return els.get(selector); } };
  const controller = templates.createController({
    root, getSessionId: () => session, getScopeIncludeCount: () => 1,
    setTimeout(callback) { const id = ++timerId; timers.set(id, callback); return id; }, clearTimeout(id) { timers.delete(id); },
    fetch: async (url, init = {}) => {
      const request = { url: String(url), method: init.method || 'GET', body: init.body ? JSON.parse(init.body) : null };
      requests.push(request);
      const intercepted = intercept(request);
      if (intercepted !== undefined) return intercepted;
      const owner = new URL(String(url), 'http://example.com').searchParams.get('session_id') || session;
      if (request.url === '/api/templates/library') return response({ state: 'idle', library: { source: 'import' }, templates: 1 });
      if (request.url.startsWith('/api/templates/auto')) return response({ session_id: owner, enabled: false, hosts: [`${owner}.example.com`], rate: 10, templates: 1 });
      if (request.url.startsWith('/api/templates/scans?')) return response({ session_id: owner, jobs: jobs.get(owner) || [] });
      if (request.url.startsWith('/api/templates/scans/')) return response((jobs.get(owner) || []).find((job) => request.url.includes(job.id)));
      if (request.url === '/api/templates/scans') return response(request.body.preview ? { requests: 1, templates: 1, targets: request.body.targets } : scan('created', owner));
      return response({ items: [], total: 0 });
    },
  });
  const get = (name) => els.get(`#templates${name}`);
  get('ScanTargets').value = 'https://app.example.com'; get('ScanSelection').value = 'on';
  get('ScanRate').value = '10'; get('ScanConcurrency').value = '4'; get('ScanMaxRequests').value = '10000'; get('ScanKeepAll').checked = true;
  controller.setVisible(true); await settle();
  return { controller, get, requests, jobs, timers,
    intercept(fn) { intercept = fn; },
    async session(id) { session = id; await controller.syncSession(); await settle(); },
    runTimers() { const current = [...timers.values()]; timers.clear(); current.forEach((fn) => fn()); },
  };
}
function scan(id, session_id = 'session-a', status = 'running') { return { id, session_id, status, targets: [`https://${id}.example.com`], recent: [], sent: 0, planned: 1, matched: 0 }; }
module.exports = { fixture, deferred, response, inside, scan, settle };
