// Dashboard CDP QA: isolated synthetic preview on 8765 / Chrome on 9227.
// Seed only the guarded preview database using tests/dashboard_browser_seed.py.
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
    const pending = new Map(), errors = [], requests = [], assetFailures = [], networkRequests = [];
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
            const request=msg.params.request, url=new URL(request.url); networkRequests.push(url.pathname);
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
    const output=path.join(__dirname,'../reports/ui/dashboard');
    await fs.mkdir(output,{recursive:true});
    const viewport=async(width,height)=>{
        await send('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
        await waitFor(`innerWidth===${width} && innerHeight===${height}`);
    };
    const capture=async(name,full=false)=>{
        await evaluate('document.fonts.ready.then(()=>true)');
        const params={format:'png',captureBeyondViewport:full};
        if(full) {
            const metrics=await send('Page.getLayoutMetrics');
            params.clip={x:0,y:0,width:metrics.cssContentSize.width,height:metrics.cssContentSize.height,scale:1};
        }
        const result=await send('Page.captureScreenshot',params);
        await fs.writeFile(path.join(output,name+'.png'),Buffer.from(result.data,'base64'));
    };
    try {
        await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
        await send('Network.setCacheDisabled',{cacheDisabled:true});
        await send('Page.navigate',{url:'http://127.0.0.1:8765/login'});
        await waitFor('document.readyState==="complete" && !!document.getElementById("login-form")');
        await evaluate(`document.getElementById('username').value='admin1';
            document.getElementById('password').value='Admin@123';
            document.getElementById('login-form').requestSubmit(); true`);
        await waitFor('location.pathname==="/admin/dashboard" && !!document.querySelector("[data-runtime-loop]")');
        await send('Page.navigate',{url:'http://127.0.0.1:8765/admin/dashboard?application_id=university-of-haripur'});
        await waitFor('document.readyState==="complete" && document.getElementById("dashboard-application")?.value==="university-of-haripur"');
        await waitFor('document.querySelector("[data-runtime-loop]").dataset.runtimeInitialized==="true"');
        assert.equal(await evaluate('document.querySelectorAll(".console-header").length'),1);
        assert.equal(await evaluate('document.querySelectorAll("[data-console-section][aria-current=page]").length'),1);
        assert.equal(await evaluate('document.querySelector("[data-console-section][aria-current=page]").dataset.consoleSection'),'dashboard');
        assert.equal(await evaluate('document.querySelector(".dashboard-context-tags .integration-state").textContent.trim()'),'Protected');
        assert.equal(await evaluate('document.querySelectorAll("[data-security-event]").length'),5);
        assert.equal(await evaluate('document.querySelectorAll("[data-runtime-stage]").length'),7);
        assert.equal(await evaluate('document.querySelectorAll("[data-runtime-checkpoint]").length'),7);
        assert.ok(await evaluate('[...document.querySelectorAll("[data-runtime-path]")].every(p=>p.getAttribute("d").length>100)'));
        const layouts=[];
        for(const [width,height] of [[1280,1701],[1440,900],[1366,768],[1024,768],[375,812],[320,568]]) {
            await viewport(width,height); await evaluate('scrollTo(0,0)');
            await capture(`dashboard-${width}x${height}`);
            if(width===1440) await capture('dashboard-1440-full',true);
            const layout=await evaluate(`(() => {
                const panels=[...document.querySelectorAll('.reference-dashboard-grid > .dashboard-panel')].map(el=>{
                    const r=el.getBoundingClientRect(); return {left:r.left,right:r.right,width:r.width,height:r.height};
                });
                const runtime=document.querySelector('.runtime-visual').getBoundingClientRect();
                const gauge=document.querySelector('.protection-gauge').getBoundingClientRect();
                const gaugeCopy=document.querySelector('.protection-gauge-copy').getBoundingClientRect();
                const gaugeLines=[...document.querySelector('.protection-gauge-copy').children].map(el=>{
                    const r=el.getBoundingClientRect(); return {top:r.top,bottom:r.bottom,left:r.left,right:r.right};
                });
                const brand=document.querySelector('.console-brand-mark img');
                return {width:innerWidth,height:innerHeight,scrollWidth:document.documentElement.scrollWidth,
                    scrollHeight:document.documentElement.scrollHeight,panels,
                    runtimeVisual:{left:runtime.left,top:runtime.top,right:runtime.right,bottom:runtime.bottom},
                    gaugeCenterDelta:Math.abs((gauge.left+gauge.width/2)-(gaugeCopy.left+gaugeCopy.width/2)),
                    gaugeTextAlign:getComputedStyle(document.querySelector('.protection-gauge-copy')).textAlign,
                    gaugeLines,brandSrc:brand.getAttribute('src'),brandNaturalWidth:brand.naturalWidth,
                    favicon:new URL(document.querySelector('link[rel=icon]').href).pathname,
                    sheets:[...document.querySelectorAll('link[rel=stylesheet]')].map(el=>el.href)};
            })()`);
            assert.ok(layout.scrollWidth<=width,JSON.stringify(layout));
            assert.ok(layout.panels.every(panel=>panel.left>=0 && panel.right<=width),JSON.stringify(layout));
            assert.ok(layout.gaugeCenterDelta<=0.5,JSON.stringify(layout));
            assert.equal(layout.gaugeTextAlign,'center');
            assert.ok(layout.gaugeLines.every((line,index,lines)=>index===0 || lines[index-1].bottom<=line.top),JSON.stringify(layout));
            assert.equal(layout.brandSrc,'/static/branding/llmguard-mark-light-64.png');
            assert.ok(layout.brandNaturalWidth>0);
            assert.equal(layout.favicon,'/static/branding/llmguard-mark-32.png');
            assert.equal(new Set(layout.sheets).size,3);
            assert.ok(layout.sheets.every(url=>url.startsWith('http://127.0.0.1:8765/static/')));
            layouts.push(layout);
        }
        await viewport(1440,900);
        await evaluate('document.querySelector("[data-runtime-loop]").scrollIntoView({block:"center"}); true');
        await waitFor('document.querySelector("[data-runtime-loop]").dataset.runtimePlaying==="true"');
        const initialMotion=await evaluate('document.querySelector("[data-runtime-motion]").getAttribute("transform")');
        const requestsBefore=networkRequests.length;
        await new Promise(resolve=>setTimeout(resolve,400));
        assert.notEqual(await evaluate('document.querySelector("[data-runtime-motion]").getAttribute("transform")'),initialMotion);
        assert.equal(networkRequests.length,requestsBefore,'Motion makes no requests');
        await capture('runtime-desktop');
        await evaluate('document.querySelector("[data-runtime-toggle]").click(); true');
        assert.equal(await evaluate('document.querySelector("[data-runtime-loop]").dataset.runtimePlaying'),'false');
        const pausedMotion=await evaluate('document.querySelector("[data-runtime-motion]").getAttribute("transform")');
        await evaluate('scrollTo(0,0)'); await new Promise(resolve=>setTimeout(resolve,150));
        await evaluate('document.querySelector("[data-runtime-loop]").scrollIntoView({block:"center"}); true');
        await new Promise(resolve=>setTimeout(resolve,200));
        assert.equal(await evaluate('document.querySelector("[data-runtime-motion]").getAttribute("transform")'),pausedMotion);
        assert.equal(await evaluate('document.querySelector("[data-runtime-loop]").dataset.runtimePlaying'),'false');
        await send('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
        await waitFor('document.querySelector("[data-runtime-toggle]").textContent==="Reduced motion"');
        await send('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'no-preference'}]});
        await waitFor('document.querySelector("[data-runtime-toggle]").textContent==="Resume animation"');
        assert.equal(await evaluate('document.querySelector("[data-runtime-loop]").dataset.runtimePlaying'),'false');
        await evaluate('document.querySelectorAll("[data-runtime-stage]")[3].click(); true');
        assert.equal(await evaluate('document.querySelector("[data-runtime-status]").textContent'),'QUARANTINE');
        assert.equal(await evaluate('getComputedStyle(document.querySelectorAll("[data-runtime-checkpoint]")[3].querySelector(".runtime-node-status")).fill'),'rgb(251, 191, 36)');
        assert.equal(await evaluate('document.querySelector("[data-runtime-loop]").dataset.runtimeFocus'),'4');
        await capture('runtime-quarantine');
        await evaluate('document.querySelector("[data-runtime-speed]").click(); document.querySelector("[data-runtime-toggle]").click(); true');
        await waitFor('document.querySelector("[data-runtime-loop]").dataset.runtimePlaying==="true"');
        assert.equal(await evaluate('document.querySelector("[data-runtime-speed]").textContent'),'2× Speed');
        const assets=await evaluate(`(async()=>{
            const sprite=await fetch('/static/llmguard-icons.svg').then(r=>r.text());
            const doc=new DOMParser().parseFromString(sprite,'image/svg+xml');
            return {icons:[...document.querySelectorAll('svg use')].every(el=>doc.getElementById(el.getAttribute('href').split('#')[1])),
                brokenImages:[...document.images].filter(img=>!img.complete || !img.naturalWidth).length,
                fonts:document.fonts.check('13px "Plus Jakarta Sans"')};
        })()`);
        assert.deepEqual(assets,{icons:true,brokenImages:0,fonts:true});
        const body=await evaluate('document.body.innerText');
        for(const fake of ['gpt-4o-mini','Pinecone','ChromaDB','PCAP','100% Verified','Simulate Prompt Attack','GHz']) assert.ok(!body.includes(fake),fake);
        await evaluate(`const selector=document.getElementById('dashboard-application');
            selector.value='synthetic-empty'; selector.dispatchEvent(new Event('change',{bubbles:true})); true`);
        await waitFor('location.search.includes("application_id=synthetic-empty") && document.readyState==="complete" && !!document.querySelector("[data-runtime-loop]")');
        assert.ok(await evaluate('document.body.innerText.includes("No security events yet")'));
        assert.ok(await evaluate('document.body.innerText.includes("No security activity yet")'));
        assert.equal(await evaluate('document.querySelectorAll("[data-security-event]").length'),0);
        assert.equal(await evaluate('document.querySelectorAll("[data-activity-action]").length'),0);
        assert.equal(await evaluate('document.querySelector(".dashboard-context-tags .integration-state").textContent.trim()'),'Integration Pending');
        await evaluate('scrollTo(0,0)'); await capture('dashboard-empty-1440');
        await capture('dashboard-empty-full',true);
        assert.deepEqual(errors,[]); assert.deepEqual(assetFailures,[]);
        const results={layouts,assets,errors,assetFailures,successfulLogin:'passed',applicationSelector:'passed',
            realState:'passed',storedEvents:'passed',emptyState:'passed',sevenStages:'passed',
            animation:'passed',manualPauseOffscreen:'passed',manualPauseReducedMotion:'passed',noMotionRequests:'passed',
            stageSelection:'passed',speedControl:'passed',singleHeader:'passed',activeNav:'passed'};
        await fs.writeFile(path.join(output,'browser-results.json'),JSON.stringify(results,null,2));
        console.log(JSON.stringify(results,null,2));
    } finally { socket.close(); }
}
main().catch(error=>{console.error(error.stack);process.exitCode=1;});
