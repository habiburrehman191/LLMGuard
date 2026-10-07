const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../static/product.js'), 'utf8');

function element() {
    const handlers = new Map(), attrs = new Map(), classes = new Set();
    return {
        dataset: {}, textContent: '', hidden: false,
        addEventListener(type, handler) {
            if (!handlers.has(type)) handlers.set(type, new Set());
            handlers.get(type).add(handler);
        },
        removeEventListener(type, handler) { handlers.get(type)?.delete(handler); },
        dispatch(type) { for (const handler of handlers.get(type) || []) handler({target:this}); },
        setAttribute(name, value) { attrs.set(name, String(value)); },
        getAttribute(name) { return attrs.get(name); },
        removeAttribute(name) { attrs.delete(name); },
        classList: {contains: name => classes.has(name),
            toggle(name, value) { value ? classes.add(name) : classes.delete(name); }},
        querySelector() { return null; }, querySelectorAll() { return []; },
    };
}
function setup({reduced = false, checkpointCount = 7} = {}) {
    const stages = Array.from({length:7}, (_, i) => {
        const el = element();
        el.dataset = {stageName:'Stage '+(i+1), stageStatus:i===3?'QUARANTINE':'Not reported',
            stageSource:'Actual stored status', stageDetail:'Architecture description'};
        return el;
    });
    const checkpoints = Array.from({length:checkpointCount}, () => {
        const el=element(), label=element(), status=element();
        el.querySelector = selector => selector.includes('label') ? label : status;
        return el;
    });
    const paths=Array.from({length:3}, element);
    const parts = Object.fromEntries([
        '[data-runtime-motion]', '[data-runtime-toggle]', '[data-runtime-speed]',
        '[data-runtime-focus]', '[data-runtime-status]', '[data-runtime-source]',
        '[data-runtime-detail]', '.runtime-hub-ring',
    ].map(selector=>[selector, element()]));
    const section=element();
    section.querySelector=selector=>parts[selector];
    section.querySelectorAll=selector=>({
        '[data-runtime-stage]':stages, '[data-runtime-checkpoint]':checkpoints,
        '[data-runtime-path]':paths,
    })[selector] || [];
    const document=element(); document.body=element(); document.getElementById=()=>null;
    document.querySelectorAll=selector=>selector==='[data-runtime-loop]' ? [section] : [];
    const media=element(); media.matches=reduced;
    const window=element();
    window.matchMedia=()=>media;
    window.location={pathname:'/admin/dashboard'};
    window.localStorage={getItem:()=>null};
    let nextId=0, observer;
    const frames=new Map();
    const context=vm.createContext({
        document, window, Headers, URLSearchParams,
        fetch() { throw new Error('Runtime motion must never make API calls'); },
        setTimeout() { throw new Error('Runtime must not start timeout chains'); },
        requestAnimationFrame(callback) { const id=++nextId; frames.set(id,callback); return id; },
        cancelAnimationFrame(id) { frames.delete(id); },
        IntersectionObserver:class {
            constructor(callback) { this.callback=callback; observer=this; }
            observe() {} disconnect() { this.disconnected=true; }
        },
    });
    vm.runInContext(source,context);
    const tick = timestamp => {
        const queued=[...frames.values()]; frames.clear();
        queued.forEach(callback=>callback(timestamp));
    };
    return {section,stages,paths,parts,frames,tick,context,document,window,media,
        get observer() { return observer; }};
}

test('seven stages initialize once, share one frame chain, and keep recorded statuses', () => {
    const ui=setup(), controller=ui.section.llmguardRuntime;
    assert.ok(controller);
    for(let i=0;i<10;i++) {
        assert.equal(vm.runInContext('initLLMGuardRuntime(document.querySelectorAll("[data-runtime-loop]")[0])',ui.context), controller);
        controller.resume(); ui.document.dispatch('visibilitychange');
        assert.equal(ui.frames.size,1);
    }
    const statuses=ui.stages.map(stage=>stage.dataset.stageStatus);
    const start=ui.parts['[data-runtime-motion]'].getAttribute('transform');
    for(let i=0;i<100;i++) { ui.tick(i*100); assert.equal(ui.frames.size,1); }
    assert.notEqual(ui.parts['[data-runtime-motion]'].getAttribute('transform'),start);
    assert.deepEqual(ui.stages.map(stage=>stage.dataset.stageStatus),statuses);
    assert.ok(ui.paths.every(p=>p.getAttribute('d').startsWith('M')));
});
test('hidden, offscreen and page-hide suspend motion without overriding manual pause', () => {
    const ui=setup();
    ui.document.hidden=true; ui.document.dispatch('visibilitychange'); assert.equal(ui.frames.size,0);
    ui.document.hidden=false; ui.document.dispatch('visibilitychange'); assert.equal(ui.frames.size,1);
    ui.observer.callback([{isIntersecting:false}]); assert.equal(ui.frames.size,0);
    ui.observer.callback([{isIntersecting:true}]); assert.equal(ui.frames.size,1);
    ui.window.dispatch('pagehide'); assert.equal(ui.frames.size,0);
    ui.window.dispatch('pageshow'); assert.equal(ui.frames.size,1);
    ui.parts['[data-runtime-toggle]'].dispatch('click');
    for(const hidden of [true,false]) { ui.document.hidden=hidden; ui.document.dispatch('visibilitychange'); }
    ui.observer.callback([{isIntersecting:false}]); ui.observer.callback([{isIntersecting:true}]);
    ui.window.dispatch('pagehide'); ui.window.dispatch('pageshow');
    assert.equal(ui.frames.size,0); assert.equal(ui.section.dataset.runtimePlaying,'false');
    assert.equal(ui.parts['[data-runtime-toggle]'].textContent,'Resume animation');
});
test('reduced motion stays static and a preference change preserves explicit pause', () => {
    const ui=setup({reduced:true});
    assert.equal(ui.frames.size,0); assert.equal(ui.parts['[data-runtime-toggle]'].disabled,true);
    ui.media.matches=false; ui.media.dispatch('change'); assert.equal(ui.frames.size,0);
    ui.section.llmguardRuntime.resume(); assert.equal(ui.frames.size,1);
    ui.section.llmguardRuntime.pause();
    ui.media.matches=true; ui.media.dispatch('change');
    ui.media.matches=false; ui.media.dispatch('change'); assert.equal(ui.frames.size,0);
});
test('stage selection pauses animation and exposes recorded quarantine without timers', () => {
    const ui=setup();
    ui.stages[3].dispatch('click');
    assert.equal(ui.frames.size,0);
    assert.equal(ui.section.dataset.runtimeFocus,'4');
    assert.equal(ui.parts['[data-runtime-status]'].textContent,'QUARANTINE');
    assert.equal(ui.stages[3].getAttribute('aria-current'),'step');
    ui.parts['[data-runtime-speed]'].dispatch('click');
    assert.equal(ui.parts['[data-runtime-speed]'].textContent,'2× Speed');
    ui.parts['[data-runtime-speed]'].dispatch('click');
    assert.equal(ui.parts['[data-runtime-speed]'].textContent,'0.5× Speed');
    ui.parts['[data-runtime-speed]'].dispatch('click');
    assert.equal(ui.parts['[data-runtime-speed]'].textContent,'1× Speed');
});
test('destroy removes motion and listeners, then supports clean reinitialization', () => {
    const ui=setup(), original=ui.section.llmguardRuntime;
    original.destroy();
    assert.equal(ui.frames.size,0); assert.equal(ui.observer.disconnected,true);
    ui.parts['[data-runtime-toggle]'].dispatch('click');
    ui.window.dispatch('pageshow'); assert.equal(ui.frames.size,0);
    const replacement=vm.runInContext('initLLMGuardRuntime(document.querySelectorAll("[data-runtime-loop]")[0])',ui.context);
    assert.notEqual(replacement,original); assert.equal(ui.frames.size,1);
});
test('inconsistent checkpoint count fails safely without a frame or partial initialization', () => {
    const ui=setup({checkpointCount:6});
    assert.equal(ui.frames.size,0); assert.equal(ui.section.llmguardRuntime,undefined);
    assert.equal(ui.section.dataset.runtimeInitialized,undefined);
});
