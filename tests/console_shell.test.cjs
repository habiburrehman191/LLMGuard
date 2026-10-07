const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../static/product.js'), 'utf8');

function element() {
    const listeners = new Map();
    const attrs = new Map();
    const classes = new Set();
    return {
        hidden: false, dataset: {}, focused: false,
        addEventListener(type, handler) { listeners.set(type, handler); },
        dispatch(type, event = {}) {
            return listeners.get(type)?.({
                target: this, currentTarget: this,
                preventDefault() {}, stopPropagation() {}, ...event,
            });
        },
        setAttribute(name, value) { attrs.set(name, value); },
        getAttribute(name) { return attrs.get(name); },
        removeAttribute(name) { attrs.delete(name); },
        focus() { this.focused = true; },
        contains(target) { return target === this; },
        querySelector() { return null; }, closest() { return null; },
        classList: {
            contains(name) { return classes.has(name); },
            toggle(name, active) { active ? classes.add(name) : classes.delete(name); },
        },
    };
}

function setup(pathname = '/admin/dashboard') {
    const trigger = element(), menu = element(), logout = element(), wrapper = element();
    menu.hidden = true;
    menu.querySelector = () => logout;
    menu.contains = target => target === menu || target === logout;
    wrapper.contains = target => [wrapper, trigger, menu, logout].includes(target);
    trigger.closest = () => wrapper;
    const links = ['dashboard', 'applications', 'security', 'evaluation'].map(section => {
        const link = element(); link.dataset.consoleSection = section; return link;
    });
    const document = element();
    document.body = element();
    document.querySelector = selector => ({
        '[data-user-menu-toggle]': trigger, '[data-user-menu]': menu,
    })[selector] || null;
    document.querySelectorAll = selector => ({
        '[data-console-section]': links, '[data-logout]': [logout],
    })[selector] || [];
    document.getElementById = () => null;
    const storage = new Map([['llmguard_token', 'synthetic-test-token']]);
    const requests = [];
    const window = {
        location: {pathname, href: ''},
        matchMedia: () => ({matches: true}),
        localStorage: {getItem: key => storage.get(key), removeItem: key => storage.delete(key)},
    };
    const context = vm.createContext({
        document, window, Headers, URLSearchParams,
        fetch: async (url, options) => {
            requests.push({url, options});
            return {ok: true, json: async () => ({logged_out: true})};
        },
    });
    vm.runInContext(source, context);
    return {trigger, menu, logout, wrapper, document, links, window, storage, requests, context};
}

test('account menu toggles, keeps inside clicks open, and dismisses outside', () => {
    const ui = setup();
    ui.trigger.dispatch('click');
    assert.equal(ui.menu.hidden, false);
    assert.equal(ui.trigger.getAttribute('aria-expanded'), 'true');
    ui.document.dispatch('click', {target: ui.logout});
    assert.equal(ui.menu.hidden, false);
    ui.document.dispatch('click', {target: element()});
    assert.equal(ui.menu.hidden, true);
    assert.equal(ui.trigger.getAttribute('aria-expanded'), 'false');
});

test('ArrowDown focuses sign out and Escape restores trigger focus', () => {
    const ui = setup();
    ui.trigger.dispatch('keydown', {key: 'ArrowDown'});
    assert.equal(ui.menu.hidden, false);
    assert.equal(ui.logout.focused, true);
    ui.document.dispatch('keydown', {key: 'Escape'});
    assert.equal(ui.menu.hidden, true);
    assert.equal(ui.trigger.focused, true);
});

test('tabbing away dismisses the menu, tabbing within it does not', () => {
    const ui = setup();
    ui.trigger.dispatch('click');
    ui.wrapper.dispatch('focusout', {relatedTarget: ui.logout});
    assert.equal(ui.menu.hidden, false);
    ui.wrapper.dispatch('focusout', {relatedTarget: element()});
    assert.equal(ui.menu.hidden, true);
});

test('nested console routes retain the correct single active navigation link', () => {
    for (const [pathname, section] of [
        ['/admin/dashboard', 'dashboard'],
        ['/admin/applications/synthetic-app', 'applications'],
        ['/admin/soc/trace', 'security'],
        ['/admin/security-dashboard', 'security'],
        ['/admin/documents', 'security'],
        ['/admin/audit', 'security'],
        ['/admin/evaluation', 'evaluation'],
        ['/admin/compare', 'evaluation'],
        ['/admin/redteam', 'evaluation'],
    ]) {
        const ui = setup(pathname);
        const active = ui.links.filter(link => link.getAttribute('aria-current') === 'page');
        assert.equal(active.length, 1, pathname);
        assert.equal(active[0].dataset.consoleSection, section, pathname);
    }
});

test('existing API helper retains bearer and JSON headers', async () => {
    const ui = setup();
    await vm.runInContext('apiRequest("/synthetic/test", {method: "POST", body: "{}"})', ui.context);
    const {options} = ui.requests[0];
    assert.equal(options.headers.get('Authorization'), 'Bearer synthetic-test-token');
    assert.equal(options.headers.get('Content-Type'), 'application/json');
});

test('sign out calls the existing endpoint, clears local token, and redirects', async () => {
    const ui = setup();
    await ui.logout.dispatch('click');
    assert.equal(ui.requests[0].url, '/auth/logout');
    assert.equal(ui.requests[0].options.method, 'POST');
    assert.equal(ui.storage.has('llmguard_token'), false);
    assert.equal(ui.window.location.href, '/login');
});
