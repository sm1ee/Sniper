// Synthetic menu/API fixtures only: no browser, filesystem profile, or network.
const assert = require("node:assert/strict");
const test = require("node:test");
const { loadFunctions } = require("./frontend-test-helpers.cjs");

function menuFixture() {
  const inputs = new Map();
  let html = "";
  const element = {
    isConnected: true,
    setAttribute() {},
    querySelector(selector) {
      return inputs.get(selector.match(/data-option="([^"]+)"/)?.[1]) || null;
    },
    get innerHTML() { return html; },
    set innerHTML(value) {
      html = value;
      inputs.clear();
      for (const match of value.matchAll(/<input[^>]*data-option="([^"]+)"([^>]*)>/g)) {
        inputs.set(match[1], { checked: /\bchecked\b/.test(match[2]) });
      }
    },
  };
  const opened = [];
  let closed = 0;
  const context = loadFunctions(["renderBrowserMenu"], {
    browserMenu: { anchor: {}, element },
    browserMenuRowHtml: () => "",
    closeBrowserMenu() { closed++; },
    openSniperBrowser: async options => opened.push(JSON.parse(JSON.stringify(options))),
    setPreferredBrowser() { assert.fail("No preference update expected"); },
  });
  function render() { context.renderBrowserMenu([]); }
  async function open(browser) {
    const button = { dataset: { open: browser }, disabled: false };
    await element.onclick({ target: { closest: selector => selector === "[data-open]" ? button : null } });
  }
  return { inputs, element, opened, render, open, get closed() { return closed; } };
}

for (const browser of ["aside", "ego"]) {
  test(`${browser} menu defaults to the saved profile and explains isolation`, async () => {
    const f = menuFixture();
    f.render();
    assert.equal(f.inputs.get("fresh").checked, false);
    assert.match(f.element.innerHTML, /saved Sniper profile/);
    assert.match(f.element.innerHTML, /everyday browser profile is separate/);
    assert.match(f.element.innerHTML, /sites can still expire logins/);
    assert.doesNotMatch(f.element.innerHTML, /Sign in there once/, "the browser account is not required by this hint");
    assert.match(f.element.innerHTML, /Throwaway profile \(discard logins on quit\)/);
    await f.open(browser);
    assert.deepEqual(f.opened, [{ browser, agent: false, fresh: false }]);
    assert.equal(f.closed, 1);
  });

  test(`${browser} throwaway is an explicit one-opening option, including rerender`, async () => {
    const f = menuFixture();
    f.render();
    f.inputs.get("fresh").checked = true;
    f.inputs.get("agent").checked = true;
    f.render(); // "Make default" rerenders the same chooser.
    assert.equal(f.inputs.get("fresh").checked, true);
    await f.open(browser);
    assert.deepEqual(f.opened, [{ browser, agent: true, fresh: true }]);
    const reopened = menuFixture();
    reopened.render();
    await reopened.open(browser);
    assert.equal(reopened.opened[0].fresh, false, "a later chooser starts with saved-profile mode");
  });
}

test("button and named launches never request a throwaway profile implicitly", async () => {
  const bodies = [];
  const context = loadFunctions(["openSniperBrowser"], {
    fetch: async (url, options) => {
      assert.equal(url, "/api/browser/launch");
      bodies.push(JSON.parse(options.body));
      return { json: async () => ({}) };
    },
    requireOkResponse: async () => {},
    showToast() { assert.fail("No toast expected for a successful ordinary launch"); },
  });
  await context.openSniperBrowser();
  await context.openSniperBrowser({ browser: "aside" });
  await context.openSniperBrowser({ browser: "ego", agent: true });
  await context.openSniperBrowser({ browser: "aside", fresh: true });
  assert.deepEqual(bodies, [{}, { browser: "aside" }, { browser: "ego", agent: true }, { browser: "aside", fresh: true }]);
});
