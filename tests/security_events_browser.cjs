// Events-only browser QA: fixed synthetic preview on 8767, isolated Chrome CDP 9229.
const fs = require('node:fs/promises');
const path = require('node:path');
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');

async function main() {
    const origin='http://127.0.0.1:8767', route='/admin/soc/events';
    const root=path.resolve(__dirname,'..'), output=path.join(root,'reports/ui/security-events');
    const targets=await fetch('http://127.0.0.1:9229/json/list').then(r=>r.json());
    const target=targets.find(t=>t.type==='page' && t.url.startsWith(origin));
    assert.ok(target,'Start the synthetic Events preview and isolated Chrome first');
    const socket=new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((resolve,reject)=>{socket.addEventListener('open',resolve,{once:true});socket.addEventListener('error',reject,{once:true});});
    let nextId=0;
    const pending=new Map(), errors=[], assetFailures=[], filterRequests=[];
    socket.addEventListener('message',event=>{
        const msg=JSON.parse(event.data);
        if(msg.id) {
            const task=pending.get(msg.id);if(!task)return;
            pending.delete(msg.id);clearTimeout(task.timer);
            msg.error?task.reject(new Error(msg.error.message)):task.resolve(msg.result);
        } else if(msg.method==='Runtime.exceptionThrown') errors.push(msg.params.exceptionDetails.text);
        else if(msg.method==='Runtime.consoleAPICalled' && msg.params.type==='error') errors.push(msg.params.args.map(arg=>arg.value??arg.description).join(' '));
        else if(msg.method==='Network.responseReceived') {
            const r=msg.params.response;if(r.url.includes('/static/') && r.status>=400)assetFailures.push(r.url);
        } else if(msg.method==='Network.requestWillBeSent') {
            const request=msg.params.request,url=new URL(request.url);
            if(url.pathname===route && request.type!=='Other')filterRequests.push({method:request.method,params:Object.fromEntries(url.searchParams)});
        }
    });
    const send=(method,params={})=>new Promise((resolve,reject)=>{
        const id=++nextId,timer=setTimeout(()=>{pending.delete(id);reject(new Error('Timed out: '+method));},15000);
        pending.set(id,{resolve,reject,timer});socket.send(JSON.stringify({id,method,params}));
    });
    const evaluate=async expression=>{
        const r=await send('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});
        if(r.exceptionDetails)throw new Error(r.exceptionDetails.text);return r.result.value;
    };
    const waitFor=async expression=>{
        const deadline=Date.now()+15000;
        while(Date.now()<deadline){try{if(await evaluate(expression))return;}catch(_){/* navigating */}
            await new Promise(resolve=>setTimeout(resolve,100));}
        throw new Error('Condition not reached: '+expression);
    };
    const fixture=mode=>{
        const r=spawnSync(path.join(root,'.venv/Scripts/python.exe'),['-m','tests.security_events_preview',mode],{cwd:root,encoding:'utf8'});
        assert.equal(r.status,0,r.stderr);
    };
    const navigate=async(query='',enhanced=true)=>{
        await send('Page.navigate',{url:origin+route+query});
        await waitFor(`document.readyState==='complete' && !!document.querySelector('[data-security-events]')${enhanced?" && !!document.querySelector('.se-enhanced-filters')":""}`);
    };
    const viewport=async(width,height)=>{
        await send('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:false});
        await waitFor(`innerWidth===${width}`);
    };
    const capture=async name=>{
        await evaluate('document.fonts.ready.then(()=>true)');
        const shot=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});
        await fs.writeFile(path.join(output,name+'.png'),Buffer.from(shot.data,'base64'));
    };
    const snapshot=()=>evaluate(`(() => {
        const root=document.querySelector('[data-security-events]');
        return {width:innerWidth,height:innerHeight,scrollWidth:document.documentElement.scrollWidth,
            headers:document.querySelectorAll('.console-header').length,
            events:[...root.querySelectorAll('[data-security-event]')].map(el=>({id:el.dataset.securityEvent,
                name:el.querySelector('h3').textContent,stage:el.dataset.stage,action:el.dataset.action,
                classification:el.dataset.classification,risk:el.querySelector('.se-risk-score strong')?.textContent,
                time:el.querySelector('time').dateTime,visibleText:el.innerText})),
            clipped:[...root.querySelectorAll('input,select,.se-event-row,.se-event-main,.se-risk-classification,.se-event-time,.se-action')].filter(el=>{
                const b=el.getBoundingClientRect();return b.left<0 || b.right>innerWidth || el.scrollWidth>el.clientWidth+1;
            }).map(el=>({element:el.className||el.tagName,client:el.clientWidth,scroll:el.scrollWidth})),
            subnav:[...document.querySelectorAll('nav[aria-label="Security views"] a')].map(el=>({path:new URL(el.href).pathname,active:el.classList.contains('active')})),
            params:Object.fromEntries(new URL(location.href).searchParams),
            secondaryVisible:getComputedStyle(root.querySelector('.se-advanced-filters')).display!=='none'};
    })()`);
    const submit=async params=>{
        await evaluate(`(() => {const form=document.querySelector('[data-security-event-filters]');
            const params=${JSON.stringify(params)}; for(const field of form.querySelectorAll('input,select'))field.value=params[field.name]||'';
            form.requestSubmit(); return true;})()`);
        await waitFor(`document.readyState==='complete' && !!document.querySelector('.se-enhanced-filters') && ${Object.entries(params).map(([k,v])=>`new URL(location.href).searchParams.get(${JSON.stringify(k)})===${JSON.stringify(v)}`).join(' && ')||'true'}`);
        return snapshot();
    };
    try {
        await fs.mkdir(output,{recursive:true});await send('Page.enable');await send('Runtime.enable');await send('Network.enable');
        await send('Page.navigate',{url:origin+'/login'});
        await waitFor('document.readyState==="complete" && !!document.getElementById("login-form")');
        await evaluate(`document.getElementById('username').value='admin1';document.getElementById('password').value='Admin@123';document.getElementById('login-form').requestSubmit();true`);
        await waitFor('location.pathname==="/admin/dashboard"');
        fixture('events');await viewport(1440,900);await navigate();
        const initial=await snapshot();assert.equal(initial.events.length,9);assert.equal(initial.headers,1);
        assert.equal(initial.secondaryVisible,false);
        assert.deepEqual(initial.subnav,[{path:'/admin/soc/events',active:true},{path:'/admin/soc/incidents',active:false},{path:'/admin/soc/trace',active:false},{path:'/admin/soc/quarantine',active:false}]);
        assert.ok(initial.events.some(e=>e.classification==='bypassed' && e.risk===undefined));
        assert.ok(initial.events.some(e=>e.risk==='0.00'));assert.ok(initial.events.every(e=>e.time));
        assert.ok(initial.events.every(e=>!e.visibleText.includes('synthetic-events-qa-')),'Identifiers must not dominate visible rows');
        await evaluate('document.querySelector("[data-more-filters]").click();true');
        assert.equal((await snapshot()).secondaryVisible,true);
        assert.equal(await evaluate('document.querySelector("[data-more-filters]").getAttribute("aria-expanded")'),'true');
        await capture('events-more-filters-1440x900');
        await evaluate('document.querySelector("[data-more-filters]").click();true');
        const layouts=[];
        for(const [width,height] of [[1600,1485],[1440,900],[1366,768],[1024,768],[375,812]]) {
            await viewport(width,height);await evaluate('window.scrollTo({top:0,behavior:"instant"});true');
            const state=await snapshot();assert.ok(state.scrollWidth<=width,JSON.stringify(state));
            assert.deepEqual(state.clipped,[],JSON.stringify(state));assert.equal(state.headers,1);
            await capture(`events-${width}x${height}`);layouts.push(state);
            if(width===375){await evaluate('document.querySelector(".se-event-list").scrollIntoView({block:"start",behavior:"instant"});true');await capture('event-rows-375');}
        }
        await viewport(1440,900);await navigate();
        const cases=[
            [{application_id:'university-of-haripur'},8],
            [{application_id:'synthetic-qa-events'},1],
            [{stage:'context'},2],
            [{action:'block'},2],
            [{application_id:'university-of-haripur',stage:'input',action:'block',channel:'student',classification:'malicious',severity:'high',event_type:'PROMPT_INJECTION'},1],
            [{event_type:'INPUT_FIREWALL'},2],
            [{event_type:'CROSS'},0],
        ];
        const filters=[];
        for(const [params,count] of cases){const state=await submit(params);assert.equal(state.events.length,count,JSON.stringify(params));
            for(const [key,value] of Object.entries(params))assert.equal(state.params[key],value);
            assert.ok(Object.keys(state.params).every(key=>['application_id','channel','stage','action','classification','severity','event_type'].includes(key)));
            if(params.channel)assert.equal(state.secondaryVisible,true);
            filters.push({params,count});await capture('filter-'+filters.length);
        }
        await navigate();
        const trace=await evaluate('document.querySelector(".se-trace-link").getAttribute("href")');
        assert.ok(trace.startsWith('/admin/soc/trace?application_id=university-of-haripur&request_id=synthetic-events-qa-'));
        await evaluate('document.querySelector(".se-trace-link").click();true');
        await waitFor('location.pathname==="/admin/soc/trace" && document.readyState==="complete"');
        assert.ok(await evaluate('document.body.innerText.includes("Request trace") || document.body.innerText.includes("Request Trace")'));
        fixture('empty');await navigate();
        assert.equal((await snapshot()).events.length,0);
        assert.ok(await evaluate('document.querySelector(".se-empty-state").innerText.includes("No security events")'));
        await capture('events-empty-1440');
        await viewport(375,812);await capture('events-empty-375');
        assert.ok((await snapshot()).scrollWidth<=375);
        fixture('events');await viewport(1440,900);
        await send('Emulation.setScriptExecutionDisabled',{value:true});await navigate('',false);
        assert.equal((await snapshot()).secondaryVisible,true,'Without JS all real filters remain available');
        assert.equal(await evaluate('document.querySelector("[data-more-filters]").hidden'),true);
        await evaluate('document.querySelector("select[name=stage]").value="output";document.querySelector("[data-security-event-filters]").requestSubmit();true');
        await waitFor('new URL(location.href).searchParams.get("stage")==="output" && document.readyState==="complete"');
        assert.equal((await snapshot()).events.length,2,'Native GET filtering works without page JS');
        await capture('events-no-js');
        await send('Emulation.setScriptExecutionDisabled',{value:false});await navigate();
        const assets=await evaluate(`(async()=>{const text=await fetch('/static/llmguard-icons.svg').then(r=>r.text());
            const sprite=new DOMParser().parseFromString(text,'image/svg+xml');return {
            icons:[...document.querySelectorAll('svg use')].every(el=>sprite.getElementById(el.getAttribute('href').split('#')[1])),
            fonts:document.fonts.check('13px "Plus Jakarta Sans"'),brokenImages:[...document.images].filter(img=>!img.complete||!img.naturalWidth).length};})()`);
        assert.equal(assets.icons,true);assert.equal(assets.fonts,true);assert.equal(assets.brokenImages,0);
        const text=await evaluate('document.querySelector("[data-security-events]").innerText');
        for(const fake of ['PCAP','Source IP','Destination IP','Packet','Isolate','Assign SOC','86,340','3,420','INC-2025-089','Threat Matrix','198.51.100.44'])assert.ok(!text.includes(fake),fake);
        assert.deepEqual(errors,[]);assert.deepEqual(assetFailures,[]);
        assert.ok(filterRequests.every(r=>r.method==='GET'));
        await capture('final-events-1440x900');
        const result={layouts,filters,assets,filterRequests,errors,assetFailures,rows:'passed',emptyState:'passed',
            filtersPreserved:'passed',subnav:'passed',traceLink:'passed',progressiveEnhancement:'passed',
            privacy:'passed',noNetworkDemo:'passed',overflow:'passed'};
        await fs.writeFile(path.join(output,'browser-results.json'),JSON.stringify(result,null,2));
        console.log(JSON.stringify({viewports:layouts.length,filterCases:filters.length,events:initial.events.length,
            filters:result.filtersPreserved,noJavaScript:result.progressiveEnhancement,overflow:result.overflow,assets,errors,assetFailures},null,2));
    } finally {await send('Emulation.setScriptExecutionDisabled',{value:false}).catch(()=>{});socket.close();}
}
main().catch(error=>{console.error(error.stack);process.exitCode=1;});
