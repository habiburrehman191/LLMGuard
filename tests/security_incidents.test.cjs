const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const code = fs.readFileSync('static/security_incidents.js', 'utf8');

test('native GET form omits empty optional parameters and preserves actual values', () => {
    let listener;
    const form = {addEventListener(type, callback) { assert.equal(type, 'formdata'); listener = callback; }};
    vm.runInNewContext(code, {document: {querySelector(selector) { assert.equal(selector, '[data-incident-filters]'); return form; }}});
    const formData = new FormData();
    for (const [key, value] of Object.entries({application_id: 'synthetic-app', incident_status: '', severity: 'critical', category: 'MALICIOUS_ACTIVITY'})) formData.set(key, value);
    listener({formData});
    assert.deepEqual(Object.fromEntries(formData), {application_id: 'synthetic-app', severity: 'critical', category: 'MALICIOUS_ACTIVITY'});
    formData.set('incident_status', 'ACKNOWLEDGED');
    listener({formData});
    assert.equal(formData.get('incident_status'), 'ACKNOWLEDGED');
    for (const name of [...formData.keys()]) formData.set(name, '');
    listener({formData});
    assert.deepEqual(Object.fromEntries(formData), {});
});

test('page enhancement safely ignores other completed pages', () => {
    vm.runInNewContext(code, {document: {querySelector() { return null; }}});
});
