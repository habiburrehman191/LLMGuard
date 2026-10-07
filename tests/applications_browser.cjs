// Applications-only CDP QA; isolated preview on 8765 and Chrome CDP on 9227.
const fs = require('node:fs/promises');
const path = require('node:path');
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');

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
    const output=path.join(__dirname,'../reports/ui/applications');
    await fs.mkdir(output,{recursive:true});
    const fixture=mode=>{
        const root=path.resolve(__dirname,'..');
        const result=spawnSync(path.join(root,'.venv/Scripts/python.exe'),['-m','tests.applications_browser_state',mode],{
            cwd:root,encoding:'utf8',env:{...process.env,LLMGUARD_DB_PATH:path.join(root,'reports/ui/applications-preview/llmguard.db')},
        });
        assert.equal(result.status,0,result.stderr);
    };
    const viewport=async(width,height)=>{
        await send('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
        await waitFor(`innerWidth===${width} && innerHeight===${height}`);
    };
    const capture=async name=>{
        await evaluate('document.fonts.ready.then(()=>true)');
        const shot=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});
        await fs.writeFile(path.join(output,name+'.png'),Buffer.from(shot.data,'base64'));
    };
    const navigateList=async()=>{
        await send('Page.navigate',{url:'http://127.0.0.1:8765/admin/applications'});
        await waitFor('document.readyState==="complete" && !!document.querySelector(".applications-list-main")');
        await waitFor('!!document.querySelector("[data-console-section=applications][aria-current=page]")');
    };
    const snapshot=()=>evaluate(`(() => {
        const card=document.querySelector('[data-application-card]');
        const runtime=card?.querySelector('[data-runtime-state]');
        const heartbeat=card?.querySelector('time');
        const main=document.querySelector('.applications-list-main');
        const bounds=card?.getBoundingClientRect();
        return {state:runtime?.dataset.runtimeState,color:runtime?getComputedStyle(runtime).color:null,
            protection:card?.querySelector('.application-protection strong').textContent,
            channels:[...main.querySelectorAll('[data-channel]')].map(el=>el.textContent),
            heartbeat:heartbeat?.dateTime,heartbeatText:heartbeat?.textContent,
            verified:[...main.querySelectorAll('[data-guard-stage]')].map(el=>el.dataset.verified),
            count:main.querySelectorAll('[data-application-card]').length,
            links:[...main.querySelectorAll('.application-card-link')].map(el=>new URL(el.href).pathname),
            headers:document.querySelectorAll('.console-header').length,
            scrollWidth:document.documentElement.scrollWidth,
            card:bounds?{left:bounds.left,top:bounds.top,right:bounds.right,bottom:bounds.bottom,height:bounds.height}:null,
            forms:main.querySelectorAll('form,button').length};
    })()`);
    try {
        await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
        fixture('pending');
        await send('Page.navigate',{url:'http://127.0.0.1:8765/login'});
        await waitFor('document.readyState==="complete" && !!document.getElementById("login-form")');
        await evaluate(`document.getElementById('username').value='admin1';
            document.getElementById('password').value='Admin@123';
            document.getElementById('login-form').requestSubmit(); true`);
        await waitFor('location.pathname==="/admin/dashboard" && !!document.querySelector(".dashboard-main")');
        await viewport(1440,900); await navigateList();
        const states=[];
        const pendingState=await snapshot();
        assert.equal(pendingState.state,'INTEGRATION_PENDING');
        assert.deepEqual(pendingState.verified,['false','false','false']);
        assert.equal(pendingState.heartbeat,undefined);
        await capture('applications-pending-1440');
        states.push(pendingState);
        fixture('protected'); await navigateList();
        const layouts=[];
        for(const [width,height] of [[1280,1329],[1440,900],[1366,768],[1024,768],[375,812],[320,568]]) {
            await viewport(width,height); await capture(`applications-${width}x${height}`);
            const layout=await snapshot();
            assert.ok(layout.scrollWidth<=width,JSON.stringify(layout));
            assert.ok(layout.card.left>=0 && layout.card.right<=width,JSON.stringify(layout));
            assert.equal(layout.count,1); assert.equal(layout.headers,1);
            assert.equal(layout.forms,0,'No list credential/protection/configuration controls');
            assert.deepEqual(layout.links,['/admin/applications/university-of-haripur']);
            assert.equal(layout.state,'PROTECTED');
            assert.deepEqual(layout.channels,['Public','Student','Employee']);
            assert.deepEqual(layout.verified,['true','true','true']);
            assert.equal(layout.protection,'Enabled');
            assert.ok(layout.heartbeat);
            assert.ok(layout.heartbeatText.includes('UTC'));
            layouts.push({width,height,...layout});
        }
        await viewport(1440,900);
        for(const [mode,state,color] of [
            ['protected','PROTECTED','rgb(78, 222, 163)'],
            ['degraded','DEGRADED','rgb(251, 191, 36)'],
            ['bypassed','BYPASSED','rgb(251, 191, 36)'],
            ['disconnected','DISCONNECTED','rgb(255, 180, 171)'],
        ]) {
            fixture(mode); await navigateList();
            const rendered=await snapshot();
            assert.equal(rendered.state,state); assert.equal(rendered.color,color);
            if(mode==='degraded') assert.deepEqual(rendered.verified,['true','false','false']);
            if(mode==='bypassed') assert.equal(rendered.protection,'Disabled');
            await capture('applications-'+mode+'-1440');
            states.push(rendered);
        }
        fixture('protected'); await navigateList();
        const assets=await evaluate(`(async()=>{
            const sprite=await fetch('/static/llmguard-icons.svg').then(r=>r.text());
            const doc=new DOMParser().parseFromString(sprite,'image/svg+xml');
            return {icons:[...document.querySelectorAll('svg use')].every(el=>doc.getElementById(el.getAttribute('href').split('#')[1])),
                brokenImages:[...document.images].filter(img=>!img.complete || !img.naturalWidth).length,
                fonts:document.fonts.check('13px "Plus Jakarta Sans"'),
                sheets:[...document.querySelectorAll('link[rel=stylesheet]')].map(el=>el.href)};
        })()`);
        assert.equal(assets.icons,true); assert.equal(assets.brokenImages,0); assert.equal(assets.fonts,true);
        assert.equal(new Set(assets.sheets).size,3);
        assert.ok(assets.sheets.every(url=>url.startsWith('http://127.0.0.1:8765/static/')));
        const text=await evaluate('document.querySelector(".applications-list-main").innerText');
        for(const fake of ['Register Application','Live WebSocket','SSO','MFA','gpt-4o-mini','Pinecone','ChromaDB',
            '84,920','1,428','Exfiltration Flag','LLM-SOC-V3','SLA','Promote to Production']) assert.ok(!text.includes(fake),fake);
        await evaluate('document.querySelector(".application-card-link").click(); true');
        await waitFor('location.pathname==="/admin/applications/university-of-haripur" && !!document.querySelector("[data-application-tabs]")');
        const detailNavigation=await evaluate('location.pathname');
        fixture('empty'); await navigateList();
        const empty=await snapshot();
        assert.equal(empty.count,0); assert.deepEqual(empty.links,[]);
        assert.equal(empty.forms,0);
        assert.ok(await evaluate('document.querySelector(".applications-list-main").textContent.includes("0 registered applications") && document.body.innerText.includes("No applications registered")'));
        assert.ok(await evaluate('document.body.innerText.includes("Applications appear here after they are registered with LLMGuard.")'));
        assert.ok(!await evaluate('document.querySelector(".applications-list-main").innerText.includes("University of Haripur AI System")'));
        await capture('applications-empty-1440');
        await viewport(375,812); await capture('applications-empty-375');
        assert.ok((await snapshot()).scrollWidth<=375);
        fixture('pending'); await viewport(1440,900); await navigateList();
        assert.deepEqual(errors,[]); assert.deepEqual(assetFailures,[]);
        const results={layouts,states,empty,assets,detailNavigation,errors,assetFailures,
            realCard:'passed',emptyRegistry:'passed',realStates:'passed',channels:'passed',heartbeat:'passed',
            pipeline:'passed',detailLink:'passed',singleHeader:'passed',noFakeTelemetry:'passed',
            noSecondaryControls:'passed',overflow:'passed'};
        await fs.writeFile(path.join(output,'browser-results.json'),JSON.stringify(results,null,2));
        console.log(JSON.stringify({viewportCount:layouts.length,stateCount:states.length,emptyRegistry:results.emptyRegistry,
            detailNavigation,errors,assetFailures,icons:assets.icons,overflow:results.overflow},null,2));
    } finally { socket.close(); }
}
main().catch(error=>{console.error(error.stack);process.exitCode=1;});
