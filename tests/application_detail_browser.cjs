// Application Detail-only QA against the isolated synthetic preview (8766 / 9228).
const fs = require('node:fs/promises');
const path = require('node:path');
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');

async function main() {
    const origin = 'http://127.0.0.1:8766';
    const detail = '/admin/applications/university-of-haripur';
    const root = path.resolve(__dirname, '..');
    const output = path.join(root, 'reports/ui/application-detail');
    const targets = await fetch('http://127.0.0.1:9228/json/list').then(r => r.json());
    const target = targets.find(t => t.type === 'page' && t.url.startsWith(origin));
    assert.ok(target, 'Start tests.application_detail_preview serve and the isolated Chrome CDP browser first');
    const socket = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
        socket.addEventListener('open', resolve, {once: true});
        socket.addEventListener('error', reject, {once: true});
    });
    let nextId = 0;
    const pending = new Map(), errors = [], assetFailures = [], protectionRequests = [];
    socket.addEventListener('message', event => {
        const msg = JSON.parse(event.data);
        if (msg.id) {
            const task = pending.get(msg.id);
            if (!task) return;
            pending.delete(msg.id); clearTimeout(task.timer);
            msg.error ? task.reject(new Error(msg.error.message)) : task.resolve(msg.result);
        } else if (msg.method === 'Runtime.exceptionThrown') {
            errors.push(msg.params.exceptionDetails.text);
        } else if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
            errors.push(msg.params.args.map(arg => arg.value ?? arg.description).join(' '));
        } else if (msg.method === 'Network.responseReceived') {
            const r = msg.params.response;
            if (r.url.includes('/static/') && r.status >= 400) assetFailures.push(r.url);
        } else if (msg.method === 'Network.requestWillBeSent' && msg.params.request.url.endsWith('/protection')) {
            protectionRequests.push(JSON.parse(msg.params.request.postData));
        }
    });
    const send = (method, params = {}) => new Promise((resolve, reject) => {
        const id = ++nextId;
        const timer = setTimeout(() => { pending.delete(id); reject(new Error('Timed out: ' + method)); }, 15000);
        pending.set(id, {resolve, reject, timer}); socket.send(JSON.stringify({id, method, params}));
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
            await new Promise(resolve => setTimeout(resolve, 100));
        }
        throw new Error('Condition not reached: ' + expression);
    };
    const fixture = mode => {
        const result = spawnSync(path.join(root, '.venv/Scripts/python.exe'), ['-m', 'tests.application_detail_preview', mode], {cwd: root, encoding: 'utf8'});
        assert.equal(result.status, 0, result.stderr);
    };
    const navigate = async (hash = '') => {
        await send('Page.navigate', {url: origin + detail + hash});
        await waitFor('document.readyState === "complete" && !!document.querySelector(".application-detail-main .is-enhanced")');
    };
    const activate = async name => {
        await evaluate(`document.querySelector('[data-application-tab="${name}"]').click(); true`);
        await waitFor(`document.querySelector('[data-application-panel="${name}"]').classList.contains('active')`);
    };
    const capture = async name => {
        await evaluate('document.fonts.ready.then(() => true)');
        const shot = await send('Page.captureScreenshot', {format: 'png', captureBeyondViewport: false});
        await fs.writeFile(path.join(output, name + '.png'), Buffer.from(shot.data, 'base64'));
    };
    const layout = () => evaluate(`(() => {
        const panel = document.querySelector('.ad-tab-panel.active');
        const body = document.documentElement;
        const tabs = [...document.querySelectorAll('[data-application-tab]')];
        return {width:innerWidth, height:innerHeight, scrollWidth:body.scrollWidth,
            panel:panel.id, visiblePanels:[...document.querySelectorAll('.ad-tab-panel')].filter(el=>getComputedStyle(el).display!=='none').length,
            headers:document.querySelectorAll('.console-header').length,
            tabsInViewport:tabs.every(el=>{const b=el.getBoundingClientRect();return b.left>=0 && b.right<=innerWidth;}),
            clipped: [...panel.querySelectorAll('code,time,.ad-credential-row,.ad-metadata,.ad-guard-row')].filter(el=>{
                const b=el.getBoundingClientRect();return b.left<0 || b.right>innerWidth || el.scrollWidth>el.clientWidth+1;
            }).map(el=>el.className || el.tagName)};
    })()`);
    try {
        await fs.mkdir(output, {recursive:true});
        await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
        await send('Page.navigate', {url:origin + '/login'});
        await waitFor('document.readyState === "complete" && !!document.getElementById("login-form")');
        await evaluate(`document.getElementById('username').value='admin1'; document.getElementById('password').value='Admin@123'; document.getElementById('login-form').requestSubmit(); true`);
        await waitFor('location.pathname === "/admin/dashboard"');
        await send('Emulation.setDeviceMetricsOverride', {width:1440,height:900,deviceScaleFactor:1,mobile:false});
        fixture('reset'); await navigate();
        assert.equal(await evaluate('document.querySelector("[data-runtime-state]").dataset.runtimeState'), 'INTEGRATION_PENDING');
        assert.equal(await evaluate('document.querySelector("#overview").innerText.includes("VERIFIED")'), false);
        assert.equal(await evaluate('document.querySelector("#integration").querySelectorAll("time").length'), 0);
        await activate('credentials');
        assert.ok(await evaluate('document.querySelector("#credentials").innerText.includes("No API credentials yet")'));
        await activate('protection');
        assert.ok(await evaluate('document.querySelector("#protection").innerText.includes("No protection changes recorded")'));
        fixture('protected'); await navigate();
        assert.equal(await evaluate('document.querySelector("[data-runtime-state]").dataset.runtimeState'), 'PROTECTED');
        assert.equal(await evaluate('document.querySelector("#overview").querySelectorAll("[data-verified=true]").length'), 3);
        assert.ok(await evaluate('document.querySelector("#overview").innerText.includes("University RBAC enforced by protected application")'));
        await activate('integration');
        const integration = await evaluate('document.querySelector("#integration").innerText');
        for (const text of ['synthetic-qa-app','synthetic-qa-integration','Registered channels','Reported channels','Protected Application','Security Pipeline','Local Model']) assert.ok(integration.toLowerCase().includes(text.toLowerCase()), text);
        const heartbeat = await evaluate('document.querySelector("#integration time").dateTime');
        assert.ok(heartbeat);
        await activate('protection');
        assert.equal(await evaluate('getComputedStyle(document.querySelector(".protection-disable-button")).color'), 'rgb(255, 180, 171)');
        await evaluate('document.querySelector("[data-protection-control]").requestSubmit(); true');
        assert.equal(protectionRequests.length, 0, 'Native required validation blocks an empty reason');
        await evaluate('document.querySelector("#protection-reason").value="   "; document.querySelector("[data-protection-control]").requestSubmit(); true');
        assert.ok(await evaluate('document.querySelector("[data-protection-message]").textContent.includes("reason is required")'));
        assert.equal(protectionRequests.length, 0, 'JS rejects whitespace-only reasons');
        await evaluate('document.querySelector("#protection-reason").value="Synthetic browser QA disable"; document.querySelector("[data-protection-control]").requestSubmit(); true');
        await waitFor('document.querySelector("[data-runtime-state]").dataset.runtimeState === "BYPASSED"');
        assert.ok(await evaluate('document.querySelector("#protection").innerText.includes("Synthetic browser QA disable")'));
        await capture('protection-bypassed-1440');
        await evaluate('document.querySelector("#protection-reason").value="Synthetic browser QA restore"; document.querySelector("[data-protection-control]").requestSubmit(); true');
        await waitFor('document.querySelector("[data-runtime-state]").dataset.runtimeState === "PROTECTED"');
        assert.ok(await evaluate('document.querySelector("#protection").innerText.includes("Synthetic browser QA restore")'));
        await activate('credentials');
        await evaluate('document.querySelector("#credentials .ad-panel-heading form").requestSubmit(); true');
        await waitFor('document.readyState === "complete" && !!document.querySelector("[data-one-time-secret]") && !!document.querySelector("#credentials.active")');
        assert.ok(await evaluate('document.querySelector("[data-one-time-secret]").textContent.startsWith("llmg_secret_")'));
        assert.ok(await evaluate('document.querySelector("#credentials").innerText.includes("It will not be shown again.")'));
        await send('Emulation.setDeviceMetricsOverride', {width:375,height:812,deviceScaleFactor:1,mobile:false});
        const oneTimeLayout = await layout();
        assert.ok(oneTimeLayout.scrollWidth <= 375); assert.deepEqual(oneTimeLayout.clipped, []);
        await send('Emulation.setDeviceMetricsOverride', {width:1440,height:900,deviceScaleFactor:1,mobile:false});
        // Compare one-time response to a later GET without returning/logging the synthetic secret.
        assert.ok(await evaluate(`(async()=>{const secret=document.querySelector('[data-one-time-secret]').textContent;
            const html=await fetch('${detail}').then(r=>r.text());return !html.includes(secret) && !html.includes('data-one-time-secret');})()`));
        const key = await evaluate('document.querySelector("[data-credential-id]").dataset.credentialId');
        await navigate('#credentials');
        assert.equal(await evaluate('!!document.querySelector("[data-one-time-secret]")'), false);
        await evaluate('document.querySelector(".credential-revoke-button").closest("form").requestSubmit(); true');
        await waitFor('document.readyState === "complete" && !!document.querySelector(".status-revoked")');
        await activate('credentials');
        assert.ok(await evaluate(`document.querySelector('[data-credential-id="${key}"]').innerText.includes('Revoked')`));
        assert.equal(await evaluate('document.body.textContent.includes("llmg_secret_")'), false);
        // Add one actual synthetic credential for responsive active-row coverage.
        await evaluate('document.querySelector("#credentials .ad-panel-heading form").requestSubmit(); true');
        await waitFor('!!document.querySelector("[data-one-time-secret]")');
        await navigate('#credentials');
        const layouts = [];
        for (const [width,height] of [[1280,1329],[1440,900],[1366,768],[1024,768],[375,812],[320,568]]) {
            await send('Emulation.setDeviceMetricsOverride', {width,height,deviceScaleFactor:1,mobile:false});
            await waitFor(`innerWidth === ${width}`);
            for (const name of ['overview','integration','protection','credentials']) {
                await activate(name);
                const rendered = await layout();
                assert.ok(rendered.scrollWidth <= width, JSON.stringify(rendered));
                assert.equal(rendered.visiblePanels, 1); assert.equal(rendered.headers, 1);
                assert.equal(rendered.tabsInViewport, true); assert.deepEqual(rendered.clipped, [], JSON.stringify(rendered));
                await capture(`${name}-${width}x${height}`); layouts.push(rendered);
            }
            if (width === 1440 || width === 375) {
                await evaluate('document.querySelector(".ad-credential-list").scrollIntoView({block:"start",behavior:"instant"}); true');
                await capture(`credential-rows-${width}`);
                await activate('protection');
                await evaluate('document.querySelector(".ad-audit-list").scrollIntoView({block:"center",behavior:"instant"}); true');
                await capture(`protection-audit-${width}`);
                await evaluate('window.scrollTo({top:0,behavior:"instant"}); true');
            }
        }
        await activate('overview');
        await evaluate(`document.querySelector('#tab-overview').focus(); document.activeElement.dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowRight',bubbles:true})); true`);
        assert.equal(await evaluate('document.activeElement.id'), 'tab-integration');
        assert.equal(await evaluate('document.querySelector("#tab-integration").getAttribute("aria-selected")'), 'true');
        await evaluate(`document.activeElement.dispatchEvent(new KeyboardEvent('keydown',{key:'End',bubbles:true})); true`);
        assert.equal(await evaluate('document.activeElement.id'), 'tab-credentials');
        await evaluate(`document.activeElement.dispatchEvent(new KeyboardEvent('keydown',{key:'Home',bubbles:true})); true`);
        assert.equal(await evaluate('document.activeElement.id'), 'tab-overview');
        const assets = await evaluate(`(async()=>{const text=await fetch('/static/llmguard-icons.svg').then(r=>r.text());
            const sprite=new DOMParser().parseFromString(text,'image/svg+xml'); return {
            icons:[...document.querySelectorAll('svg use')].every(el=>sprite.getElementById(el.getAttribute('href').split('#')[1])),
            font:document.fonts.check('13px "Plus Jakarta Sans"'),brokenImages:[...document.images].filter(img=>!img.complete||!img.naturalWidth).length};})()`);
        assert.equal(assets.icons,true); assert.equal(assets.font,true); assert.equal(assets.brokenImages,0);
        const states = [];
        for (const [mode,expected] of [['degraded','DEGRADED'],['disconnected','DISCONNECTED'],['pending','INTEGRATION_PENDING']]) {
            fixture(mode); await navigate();
            const actual=await evaluate('document.querySelector("[data-runtime-state]").dataset.runtimeState');
            assert.equal(actual,expected); states.push(actual);
        }
        const content = await evaluate('document.querySelector(".application-detail-main").textContent');
        for (const fake of ['gpt-4o-mini','Pinecone','ChromaDB','84,920','LLM-SOC-V3','SLA','Promote to Production','Register Application','Rotate Key','llmg_live_']) assert.ok(!content.includes(fake),fake);
        assert.deepEqual(errors,[]); assert.deepEqual(assetFailures,[]);
        fixture('protected'); await navigate();
        await send('Emulation.setDeviceMetricsOverride',{width:1440,height:900,deviceScaleFactor:1,mobile:false});
        await capture('final-overview-1440x900');
        const result = {layouts,states,assets,heartbeat,errors,assetFailures,protectionRequests,
            tabs:'passed',keyboard:'passed',protectionControl:'passed',requiredReason:'passed',audit:'passed',
            credentials:'passed',oneTimeSecret:'passed',revoke:'passed',overflow:'passed',noDemoData:'passed'};
        await fs.writeFile(path.join(output,'browser-results.json'),JSON.stringify(result,null,2));
        console.log(JSON.stringify({layouts:layouts.length,states,tabs:result.tabs,keyboard:result.keyboard,
            protectionControl:result.protectionControl,credentials:result.credentials,oneTimeSecret:result.oneTimeSecret,
            overflow:result.overflow,assets,errors,assetFailures},null,2));
    } finally { socket.close(); }
}
main().catch(error=>{console.error(error.stack);process.exitCode=1;});
