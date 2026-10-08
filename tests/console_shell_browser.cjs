// Optional browser smoke test: attach to a fresh Chrome profile on port 9227.
// Run against the task's isolated synthetic FastAPI preview on port 8765.
const fs = require('node:fs/promises');
const path = require('node:path');
const assert = require('node:assert/strict');

async function main() {
    const targets = await fetch('http://127.0.0.1:9227/json/list').then(r => r.json());
    const target = targets.find(t => t.type === 'page' && t.url.startsWith('http://127.0.0.1:8765/'));
    assert.ok(target, 'Isolated preview tab must already be open');
    const socket = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
        socket.addEventListener('open', resolve, {once: true});
        socket.addEventListener('error', reject, {once: true});
    });
    let nextId = 0;
    const pending = new Map(), errors = [];
    socket.addEventListener('message', event => {
        const message = JSON.parse(event.data);
        if (message.id) {
            const task = pending.get(message.id);
            if (!task) return;
            pending.delete(message.id);
            clearTimeout(task.timer);
            message.error ? task.reject(new Error(message.error.message)) : task.resolve(message.result);
        } else if (message.method === 'Runtime.exceptionThrown') {
            errors.push(message.params.exceptionDetails.text);
        } else if (message.method === 'Runtime.consoleAPICalled' && message.params.type === 'error') {
            errors.push(message.params.args.map(arg => arg.value ?? arg.description).join(' '));
        }
    });
    const send = (method, params = {}) => new Promise((resolve, reject) => {
        const id = ++nextId;
        const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Timed out: ${method}`)); }, 15000);
        pending.set(id, {resolve, reject, timer});
        socket.send(JSON.stringify({id, method, params}));
    });
    const evaluate = async expression => {
        const result = await send('Runtime.evaluate', {expression, awaitPromise: true, returnByValue: true});
        if (result.exceptionDetails) throw new Error(result.exceptionDetails.text);
        return result.result.value;
    };
    const waitFor = async expression => {
        const deadline = Date.now() + 15000;
        while (Date.now() < deadline) {
            try { if (await evaluate(expression)) return; } catch (_) { /* navigating */ }
            await new Promise(resolve => setTimeout(resolve, 150));
        }
        throw new Error(`Condition not reached: ${expression}`);
    };
    const output = path.join(__dirname, '../reports/ui/shared-shell');
    await fs.mkdir(output, {recursive: true});
    const capture = async name => {
        await evaluate('document.fonts.ready.then(() => true)');
        const screenshot = await send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: false});
        await fs.writeFile(path.join(output, name + '.png'), Buffer.from(screenshot.data, 'base64'));
    };
    const viewport = async (width, height) => {
        await send('Emulation.setDeviceMetricsOverride', {width, height, deviceScaleFactor: 1, mobile: false});
        await waitFor(`innerWidth === ${width}`);
        await evaluate('window.scrollTo(0,0)');
    };
    try {
        await send('Page.enable'); await send('Runtime.enable');
        await viewport(1280, 900);
        await send('Page.navigate', {url: 'http://127.0.0.1:8765/login'});
        await waitFor('document.readyState === "complete" && !!document.getElementById("login-form")');
        await capture('login-shared-controls');
        await evaluate(`document.getElementById('username').value='admin1';
            document.getElementById('password').value='Admin@123';
            document.getElementById('login-form').requestSubmit(); true`);
        await waitFor('location.pathname === "/admin/dashboard" && !!document.querySelector("[data-console-nav]")');
        const routes = [
            '/admin/dashboard', '/admin/applications',
            '/admin/applications/university-of-haripur', '/admin/security-dashboard',
            '/admin/soc/events', '/admin/soc/incidents', '/admin/soc/trace',
            '/admin/soc/quarantine', '/admin/evaluation', '/admin/compare',
            '/admin/documents', '/admin/redteam', '/admin/audit',
        ];
        const pages = [];
        for (const route of routes) {
            await send('Page.navigate', {url: 'http://127.0.0.1:8765' + route});
            await waitFor(`location.pathname === ${JSON.stringify(route)} && document.readyState === 'complete' && !!document.querySelector('[data-console-nav]')`);
            const state = await evaluate(`(() => {
                const header=document.querySelector('.console-header');
                const style=getComputedStyle(header);
                return {route:location.pathname, headers:document.querySelectorAll('.console-header').length,
                    active:document.querySelectorAll('[data-console-section][aria-current="page"]').length,
                    bodyFont:getComputedStyle(document.body).fontFamily,
                    navLabels:[...document.querySelectorAll('.console-nav-label')].map(el=>el.textContent),
                    menuHook:!!document.querySelector('[data-user-menu]'),
                    width:header.getBoundingClientRect().width, position:style.position,
                    bodyWidth:document.documentElement.scrollWidth, viewport:innerWidth,
                    stylesheets:[...document.querySelectorAll('link[rel="stylesheet"]')].map(el=>el.href),
                    tailwindRuntime:!!document.querySelector('script[src*="tailwind"]')};
            })()`);
            assert.equal(state.headers, 1, route); assert.equal(state.active, 1, route);
            assert.equal(state.menuHook, true, route);
            assert.ok(state.bodyFont.includes('Plus Jakarta Sans'), route);
            assert.ok(state.bodyWidth <= state.viewport, route + ' overflow');
            assert.equal(state.stylesheets.filter(url => url.includes('/static/console.css')).length, 1, route);
            assert.equal(new Set(state.stylesheets).size, state.stylesheets.length, route + ' duplicate stylesheet');
            assert.ok(state.stylesheets.every(url => url.startsWith('http://127.0.0.1:8765/static/')), route);
            assert.equal(state.tailwindRuntime, false, route);
            pages.push(state);
            if (route === '/admin/applications') await capture('desktop-applications');
            if (route === '/admin/dashboard') await capture('desktop-dashboard');
            if (route === '/admin/applications/university-of-haripur') {
                for (const tab of ['integration', 'protection', 'credentials', 'overview']) {
                    await evaluate(`document.querySelector('[data-application-tab="${tab}"]').click()`);
                    assert.equal(await evaluate(`document.querySelector('[data-application-panel="${tab}"]').classList.contains('active')`), true);
                }
                assert.equal(await evaluate("!!document.querySelector('[data-protection-control]')"), true);
            }
        }
        await send('Page.navigate', {url: 'http://127.0.0.1:8765/admin/applications'});
        await waitFor('document.readyState === "complete" && !!document.querySelector("[data-user-menu-toggle]")');
        // Computed-style fixtures exercise the real CSS cascade, including legacy sheets.
        const sharedControls = await evaluate(`(() => {
            const fixture=document.createElement('div');
            fixture.innerHTML='<button class="primary-button">Primary</button><button class="secondary-button">Secondary</button><button class="table-action danger-action">Delete</button><span class="credential-status status-revoked">Revoked</span>';
            document.body.append(fixture);
            const states=[...fixture.children].map(el=>({background:getComputedStyle(el).backgroundColor,
                color:getComputedStyle(el).color,font:getComputedStyle(el).fontFamily,
                height:el.getBoundingClientRect().height}));
            fixture.remove(); return states;
        })()`);
        assert.equal(sharedControls[0].background, 'rgb(30, 107, 255)');
        assert.equal(sharedControls[1].background, 'rgb(32, 43, 56)');
        assert.equal(sharedControls[2].background, 'rgb(186, 26, 26)');
        assert.equal(sharedControls[3].color, 'rgb(255, 180, 171)');
        assert.ok(sharedControls.every(state=>state.font.includes('Plus Jakarta Sans')));
        assert.ok(sharedControls.slice(0,3).every(state=>state.height===36));
        await send('Page.bringToFront');
        await evaluate('document.querySelector("[data-user-menu-toggle]").focus()');
        // This Windows headless session does not deliver OS keyboard input.
        // Exercise the browser's actual handler/focus behavior with DOM key events.
        await evaluate('document.querySelector("[data-user-menu-toggle]").dispatchEvent(new KeyboardEvent("keydown", {key:"ArrowDown", bubbles:true, cancelable:true}))');
        assert.equal(await evaluate('document.activeElement.matches("[data-logout]")'), true);
        await capture('desktop-account-menu');
        await evaluate('document.dispatchEvent(new KeyboardEvent("keydown", {key:"Escape", bubbles:true}))');
        assert.equal(await evaluate('document.querySelector("[data-user-menu]").hidden && document.activeElement.matches("[data-user-menu-toggle]")'), true);
        const mobile = [];
        for (const width of [768, 375, 320]) {
            await viewport(width, 900);
            await evaluate('document.querySelector("[data-user-menu-toggle]").click()');
            const bounds = await evaluate(`(() => {
                const nav=document.querySelector('[data-console-nav]');
                const menu=document.querySelector('[data-user-menu]').getBoundingClientRect();
                return {width:innerWidth, bodyWidth:document.documentElement.scrollWidth,
                    navVisible:getComputedStyle(nav).display!=='none',
                    menuLeft:menu.left,menuRight:menu.right,menuTop:menu.top};
            })()`);
            assert.equal(bounds.navVisible, true);
            await capture('account-menu-' + width);
            assert.ok(bounds.menuLeft >= 0 && bounds.menuRight <= width + 1, JSON.stringify(bounds));
            assert.ok(bounds.bodyWidth <= width + 1, `overflow at ${width}`);
            mobile.push(bounds);
            await evaluate('document.querySelector("[data-user-menu-toggle]").click()');
        }
        await viewport(1280, 900);
        await evaluate('document.querySelector("[data-user-menu-toggle]").click(); document.querySelector("[data-logout]").click(); true');
        await waitFor('location.pathname === "/login" && !!document.getElementById("login-form")');
        const loggedOutStatus = await evaluate('fetch("/admin/dashboard").then(r=>r.status)');
        assert.equal(loggedOutStatus, 401);
        assert.deepEqual(errors, []);
        const results = {pages, mobile, sharedControls, loggedOutStatus, javascriptErrors: errors,
            login: 'passed', navigation: 'passed', applicationTabs: 'passed',
            protectionHook: 'preserved', accountKeyboard: 'passed', logout: 'passed'};
        await fs.writeFile(path.join(output, 'browser-results.json'), JSON.stringify(results, null, 2));
        console.log(JSON.stringify(results, null, 2));
    } finally { socket.close(); }
}
main().catch(error => { console.error(error.stack); process.exitCode = 1; });
