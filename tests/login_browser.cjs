// Optional CDP smoke test: isolated synthetic preview on 8765 / fresh Chrome process on 9227.
const fs = require('node:fs/promises');
const path = require('node:path');
const assert = require('node:assert/strict');

async function main() {
    const targets = await fetch('http://127.0.0.1:9227/json/list').then(r => r.json());
    const target = targets.find(t => t.type === 'page' && t.url.startsWith('http://127.0.0.1:8765/'));
    assert.ok(target, 'Isolated login preview must already be open');
    const socket = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
        socket.addEventListener('open', resolve, {once:true});
        socket.addEventListener('error', reject, {once:true});
    });
    let nextId = 0;
    const pending = new Map(), errors = [], requests = [], assetFailures = [];
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
            errors.push(msg.params.args.map(arg=>arg.value ?? arg.description).join(' '));
        } else if (msg.method === 'Network.requestWillBeSent') {
            const request=msg.params.request, url=new URL(request.url);
            if (url.pathname === '/auth/login') requests.push({method:request.method,
                path:url.pathname, fields:Object.keys(JSON.parse(request.postData))});
        } else if (msg.method === 'Network.responseReceived') {
            const response=msg.params.response;
            if (response.url.includes('/static/') && response.status >= 400) assetFailures.push(response.url);
        }
    });
    const send = (method, params = {}) => new Promise((resolve, reject) => {
        const id=++nextId;
        const timer=setTimeout(()=>{pending.delete(id); reject(new Error('Timed out: '+method));},15000);
        pending.set(id,{resolve,reject,timer}); socket.send(JSON.stringify({id,method,params}));
    });
    const evaluate = async expression => {
        const result=await send('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});
        if (result.exceptionDetails) throw new Error(result.exceptionDetails.text);
        return result.result.value;
    };
    const waitFor = async expression => {
        const deadline=Date.now()+15000;
        while(Date.now()<deadline) {
            try {if(await evaluate(expression)) return;} catch (_) { /* navigating */ }
            await new Promise(resolve=>setTimeout(resolve,100));
        }
        throw new Error('Condition not reached: '+expression);
    };
    const output=path.join(__dirname,'../reports/ui/login');
    await fs.mkdir(output,{recursive:true});
    const capture=async name=>{
        await evaluate('document.fonts.ready.then(()=>true)');
        const result=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});
        await fs.writeFile(path.join(output,name+'.png'),Buffer.from(result.data,'base64'));
    };
    const viewport=async(width,height)=>{
        await send('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
        await waitFor(`innerWidth===${width} && innerHeight===${height}`);
    };
    const key=async(name,code,virtualKey,text)=>{
        await send('Input.dispatchKeyEvent',{type:'keyDown',key:name,code,
            windowsVirtualKeyCode:virtualKey,nativeVirtualKeyCode:virtualKey,...(text?{text}: {})});
        await send('Input.dispatchKeyEvent',{type:'keyUp',key:name,code,
            windowsVirtualKeyCode:virtualKey,nativeVirtualKeyCode:virtualKey});
    };
    try {
        await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
        await send('Network.setCacheDisabled',{cacheDisabled:true});
        await send('Page.navigate',{url:'http://127.0.0.1:8765/login'});
        await waitFor('document.readyState === "complete" && !!document.getElementById("login-form")');
        const layouts=[];
        for(const [width,height] of [[1280,942],[1440,900],[1366,768],[1280,720],[1024,768],[800,600],[375,667],[320,568]]) {
            await viewport(width,height);
            await capture(`login-${width}x${height}`);
            const layout=await evaluate(`(() => {
                const card=document.querySelector('.reference-login-card').getBoundingClientRect();
                const sheets=[...document.querySelectorAll('link[rel="stylesheet"]')].map(el=>el.href);
                const fields=[...document.querySelectorAll('.login-input-wrap')].map(wrap=>{
                    const input=wrap.querySelector('input'), icon=wrap.querySelector('svg');
                    const inputRect=input.getBoundingClientRect(), iconRect=icon.getBoundingClientRect();
                    return {id:input.id,height:inputRect.height,paddingLeft:getComputedStyle(input).paddingLeft,
                        centerDelta:Math.abs((inputRect.top+inputRect.height/2)-(iconRect.top+iconRect.height/2))};
                });
                const brand=document.querySelector('.reference-login-icon img');
                return {width:innerWidth,height:innerHeight,scrollWidth:document.documentElement.scrollWidth,
                    scrollHeight:document.documentElement.scrollHeight,cardWidth:card.width,cardTop:card.top,
                    cardLeft:card.left,cardRight:card.right,bodyFont:getComputedStyle(document.body).fontFamily,
                    fields,brandSrc:brand.getAttribute('src'),brandNaturalWidth:brand.naturalWidth,
                    favicon:new URL(document.querySelector('link[rel=icon]').href).pathname,
                    headers:document.querySelectorAll('header').length,sheets};
            })()`);
            assert.ok(layout.scrollWidth<=width, JSON.stringify(layout));
            assert.ok(layout.scrollHeight<=height, JSON.stringify(layout));
            assert.ok(layout.cardLeft>=0 && layout.cardRight<=width);
            assert.equal(layout.headers,0);
            assert.deepEqual(layout.fields.map(field=>field.height),[46,46]);
            assert.deepEqual(layout.fields.map(field=>field.paddingLeft),['44px','44px']);
            assert.ok(layout.fields.every(field=>field.centerDelta<=0.5),JSON.stringify(layout));
            assert.equal(layout.brandSrc,'/static/branding/llmguard-mark.png');
            assert.ok(layout.brandNaturalWidth>0);
            assert.equal(layout.favicon,'/static/branding/llmguard-mark-32.png');
            assert.ok(layout.bodyFont.includes('Plus Jakarta Sans'));
            assert.equal(new Set(layout.sheets).size,2);
            assert.ok(layout.sheets.every(url=>url.startsWith('http://127.0.0.1:8765/static/')));
            layouts.push(layout);
        }
        const assets=await evaluate(`(async () => {
            const sprite=await fetch('/static/llmguard-icons.svg').then(r=>r.text());
            const doc=new DOMParser().parseFromString(sprite,'image/svg+xml');
            return {icons:[...document.querySelectorAll('svg use')].every(el=>doc.getElementById(el.getAttribute('href').split('#')[1])),
                radar:(await fetch('/static/login-radar.svg')).ok,
                fonts:document.fonts.check('13px "Plus Jakarta Sans"'),
                brokenImages:[...document.images].filter(img=>!img.complete || !img.naturalWidth).length};
        })()`);
        assert.deepEqual(assets,{icons:true,radar:true,fonts:true,brokenImages:0});
        await viewport(1440,900); await send('Page.bringToFront');
        await send('Emulation.setFocusEmulationEnabled',{enabled:true});
        await evaluate('document.getElementById("username").focus()');
        await waitFor('document.hasFocus() && document.activeElement.id === "username"');
        await key('Tab','Tab',9);
        await waitFor('document.activeElement.id === "password"');
        assert.equal(await evaluate('document.activeElement.id'),'password','Native Tab navigation');
        await capture('login-focus');
        await key('Tab','Tab',9);
        await waitFor('document.activeElement.matches("button[type=submit]")');
        assert.equal(await evaluate('document.activeElement.matches("button[type=submit]")'),true,'Native Tab reaches submit');
        await evaluate(`document.getElementById('username').value='admin1';
            document.getElementById('password').value='incorrect-synthetic-password';
            document.getElementById('password').focus(); true`);
        await key('Enter','Enter',13,'\r');
        await waitFor('document.getElementById("login-message").classList.contains("error")');
        assert.ok(await evaluate('document.getElementById("login-message").textContent.length > 0'));
        assert.equal(await evaluate('document.querySelector("button[type=submit]").textContent'),'Sign In to Security Console');
        assert.equal(await evaluate('location.pathname'),'/login');
        await capture('login-error');
        await evaluate(`document.getElementById('password').value='Admin@123'; true`);
        await key('Enter','Enter',13,'\r');
        await waitFor('location.pathname === "/admin/dashboard" && document.readyState === "complete" && !!document.querySelector("[data-logout]")');
        const cookies=await send('Network.getCookies');
        const httpOnlyCookie=cookies.cookies.some(cookie=>cookie.httpOnly);
        assert.equal(httpOnlyCookie,true);
        assert.equal(await evaluate('!!localStorage.getItem("llmguard_token")'),true);
        await evaluate('document.querySelector("[data-user-menu-toggle]").click(); document.querySelector("[data-logout]").click(); true');
        await waitFor('location.pathname === "/login" && document.readyState === "complete" && !!document.getElementById("login-form")');
        assert.equal(await evaluate('localStorage.getItem("llmguard_token")'),null);
        const loggedOutStatus=await evaluate('fetch("/admin/dashboard").then(r=>r.status)');
        assert.equal(loggedOutStatus,401);
        assert.equal(requests.length,2);
        assert.ok(requests.every(r=>r.method==='POST' && r.fields.join(',')==='username,password'));
        assert.deepEqual(errors,[]); assert.deepEqual(assetFailures,[]);
        const results={layouts,assets,requests,httpOnlyCookie,loggedOutStatus,errors,assetFailures,
            nativeTab:'passed',nativeEnter:'passed',failedLogin:'passed',successfulLogin:'passed',logoutRedirect:'passed'};
        await fs.writeFile(path.join(output,'browser-results.json'),JSON.stringify(results,null,2));
        console.log(JSON.stringify(results,null,2));
    } finally {socket.close();}
}
main().catch(error=>{console.error(error.stack); process.exitCode=1;});
