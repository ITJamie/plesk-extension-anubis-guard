/* Execute the shipped browser script against a small DOM/fetch harness. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const script = fs.readFileSync(path.join(__dirname, '../src/htdocs/dist/app.js'), 'utf8');
let checks = 0;
function check(value, message) { assert.ok(value, message); checks++; }

function node() {
    return { textContent: '', disabled: false, events: {},
        addEventListener(name, callback) { this.events[name] = callback; },
        setAttribute() {} };
}
function form() {
    const result = node();
    const children = { '.ag-name': node(), '.ag-status': node(), '.ag-error': node(), '.ag-challenge-help': node() };
    result.elements = { enabled: { checked: false }, paths: { value: '' }, ips: { value: '' } };
    result.elements.challenge_mode = Object.assign(node(), { value: 'adaptive' });
    result.elements.difficulty = Object.assign(node(), { value: '2' });
    result.elements.failure_mode = { value: 'closed' };
    result.elements.image_style = { value: 'original' };
    result.elements.protection_scope = Object.assign(node(), { value: 'all' });
    result.elements.included_paths = Object.assign(node(), { value: '' });
    result.querySelector = name => children[name];
    return result;
}
function jsonResponse(body, status = 200) {
    return { ok: status < 400, status, json: async () => body };
}
async function harness({ token = 'panel-token', saveResponse, saveNetworkError = false, domainId = '', domains, admin = false, expectedForms = 1, geo = null, geoSaveError = '', runtime = null, runtimeNetworkError = false } = {}) {
    const message = node();
    const refresh = node();
    const list = Object.assign(node(), { forms: [],
        replaceChildren() { this.forms = []; },
        appendChild(value) { this.forms.push(value); } });
    const template = { content: { firstElementChild: { cloneNode: () => form() } } };
    const lookup = { '#ag-message': message, '#ag-refresh': refresh,
        '#ag-domains': list, '#ag-domain-template': template };
    const timers = [];
    const geoForm = node();
    const geoStatus = node();
    const geoUpdate = node();
    const geoInspect = node();
    const geoSubmit = node();
    const geoChildren = {'.ag-geoip-maxmind': node(), '.ag-geoip-local': node(), '.ag-geoip-key-status': node()};
    geoForm.elements = {};
    for (const key of ['mode', 'account_id', 'license_key', 'country_path', 'asn_path', 'clear_key']) {
        geoForm.elements[key] = Object.assign(node(), { value: key === 'mode' ? 'disabled' : '', checked: false });
    }
    geoForm.querySelector = selector => geoChildren[selector];
    geoForm.querySelectorAll = () => [geoSubmit, geoUpdate, geoInspect];
    if (geo) Object.assign(lookup, {'#ag-geoip-form': geoForm, '#ag-geoip-status': geoStatus,
        '#ag-geoip-refresh': geoUpdate, '#ag-geoip-status-refresh': geoInspect});
    const runtimePanel = node();
    const runtimeNodes = {};
    for (const key of ['status', 'release', 'downloaded', 'releases', 'more', 'download', 'activate', 'auto', 'rollback', 'inspect']) {
        runtimeNodes[key] = Object.assign(node(), {value: '', children: [],
            replaceChildren() {this.children = [];}, appendChild(child) {this.children.push(child);} });
    }
    runtimePanel.querySelector = selector => runtimeNodes[selector.replace('#ag-runtime-', '')];
    runtimePanel.querySelectorAll = () => ['releases', 'more', 'download', 'activate', 'auto', 'rollback', 'inspect'].map(key => runtimeNodes[key]);
    if (runtime) lookup['#ag-runtime'] = runtimePanel;
    const root = { dataset: { baseUrl: '/modules/anubis-guard/', csrf: 'extension-token', domainId },
        querySelector: selector => lookup[selector], querySelectorAll: () => [refresh] };
    const panelMeta = token === null ? null : { content: token };
    const calls = [];
    const domain = { id: 7, name: 'example.test', hosting: 'vrt_hst', active: true,
        enabled: false, healthy: null, paths: [], ips: [], last_error: '' };
    const context = {
        document: { readyState: 'complete', getElementById: id => id === 'anubis-guard' ? root : panelMeta,
            createElement: () => Object.assign(node(), {value: ''}) },
        Headers, TypeError,
        setTimeout: callback => { timers.push(callback); return timers.length; }, clearTimeout() {},
        fetch: async (url, options) => {
            calls.push({ url, options });
            if (url.endsWith('/runtimestatus')) return jsonResponse(runtime);
            if (url.endsWith('/runtimejob')) {
                if (runtimeNetworkError) throw new TypeError('Failed to fetch');
                runtime.job = {status: 'queued', action: JSON.parse(options.body).action};
                return jsonResponse({ok: true, job_id: 'runtime-test-job'}, 202);
            }
            if (url.endsWith('/geoipstatus')) return jsonResponse(geo);
            if (url.endsWith('/geoipsave') || url.endsWith('/geoiprefresh')) {
                if (geoSaveError) return jsonResponse({error: geoSaveError}, 400);
                geo.job = {status: 'queued'};
                return jsonResponse({ok: true, job_id: 'test-job'}, 202);
            }
            if (options.method === 'POST' && saveNetworkError) throw new TypeError('Failed to fetch');
            return options.method === 'POST' ? (saveResponse || jsonResponse({ ok: true }))
                : jsonResponse({ domains: domains || [domain], is_admin: admin });
        }
    };
    vm.runInNewContext(script, context);
    await new Promise(setImmediate);
    assert.equal(list.forms.length, expectedForms, 'Initial domain list did not load');
    return { calls, message, list, panelMeta, refresh, geoForm, geoStatus, geoUpdate, geoInspect, timers, runtimeNodes, async submitGeo() {
        await geoForm.events.submit({preventDefault() {}});
    }, async submit() {
        list.forms[0].elements.enabled.checked = true;
        await list.forms[0].events.submit({ preventDefault() {} });
    } };
}

(async () => {
    const normal = await harness();
    check(normal.list.forms[0].elements.image_style.value === 'original', 'Legacy site did not keep Anubis artwork');
    check(normal.list.forms[0].elements.protection_scope.value === 'all' && normal.list.forms[0].elements.included_paths.disabled,
        'Legacy sites did not keep entire-site protection');
    check(normal.list.forms[0].elements.failure_mode.value === 'closed', 'Legacy site did not default to fail closed');
    check(normal.list.forms[0].elements.challenge_mode.value === 'adaptive' && normal.list.forms[0].elements.difficulty.value === '2',
        'Legacy site did not load with the current challenge defaults');
    check(normal.calls[0].options.headers.get('X-Forgery-Protection-Token') === 'panel-token', 'GET lacks Plesk token');
    normal.panelMeta.content = 'refreshed-panel-token';
    await normal.submit();
    const save = normal.calls.find(call => call.options.method === 'POST');
    check(save.options.headers.get('X-Forgery-Protection-Token') === 'refreshed-panel-token', 'POST did not read current panel token');
    check(save.options.headers.get('X-Anubis-CSRF') === 'extension-token', 'Extension token was lost while merging headers');
    check(save.options.headers.get('X-Requested-With') === 'XMLHttpRequest', 'Plesk AJAX header is missing');
    check(save.options.headers.get('Accept') === 'application/json', 'JSON Accept header was lost');
    check(save.options.headers.get('Content-Type') === 'application/json', 'POST content type was lost');
    check(save.options.credentials === 'same-origin' && save.options.cache === 'no-store', 'Panel request changed cookie/cache handling');
    check(JSON.parse(save.options.body).enabled === true, 'Save payload is incorrect');
    check(normal.message.textContent === 'Settings saved.', 'Success was not displayed');

    const missing = await harness({ token: null });
    await missing.submit();
    check(!missing.calls.some(call => call.options.method === 'POST'), 'Save sent without a Plesk token');
    check(missing.message.textContent.includes('Plesk session token is unavailable'), 'Missing token does not show an actionable error');

    const html = await harness({ saveResponse: { ok: false, status: 500,
        json: async () => { throw new SyntaxError('Unexpected token <'); } } });
    await html.submit();
    check(html.message.textContent.includes('HTTP 500') && html.message.textContent.includes('Reload the panel'), 'HTML error lacks recovery instructions');
    check(!html.message.textContent.includes('Unexpected token'), 'JSON parser internals leaked into the UI');
    check(!html.message.textContent.includes('Settings saved'), 'Failed save was reported as successful');

    for (const options of [{ saveNetworkError: true }, { saveResponse: { ok: true, status: 200,
        json: async () => { throw new TypeError('Failed to fetch'); } } }]) {
        const disconnected = await harness(options);
        await disconnected.submit();
        check(disconnected.message.textContent.includes('Settings may have been applied') &&
            disconnected.message.textContent.includes('Refresh status'), 'Interrupted save lacks recovery instructions');
        check(disconnected.calls.filter(call => call.options.method === 'POST').length === 1,
            'Interrupted mutation was retried automatically');
        check(!disconnected.refresh.disabled, 'Refresh status remained disabled after an interrupted save');
    }

    const apiError = await harness({ saveResponse: jsonResponse({ error: 'nginx configuration failed' }, 400) });
    await apiError.submit();
    check(apiError.message.textContent === 'nginx configuration failed', 'API error text was discarded');

    const focused = await harness({ domainId: '8', domains: [
        { id: 7, name: 'one.test', hosting: 'vrt_hst', active: true, enabled: false, paths: [], ips: [] },
        { id: 8, name: 'two.test', hosting: 'vrt_hst', active: true, enabled: false, paths: [], ips: [] }
    ] });
    check(focused.list.forms[0].querySelector('.ag-name').textContent === 'two.test', 'Domain entry did not focus the requested authorized site');
    focused.list.forms[0].elements.paths.value = '/api/\n/webhooks/';
    focused.list.forms[0].elements.ips.value = '192.0.2.0/24';
    focused.list.forms[0].elements.challenge_mode.value = 'proof-of-work';
    focused.list.forms[0].elements.difficulty.value = '3';
    focused.list.forms[0].elements.failure_mode.value = 'open';
    focused.list.forms[0].elements.image_style.value = 'generic';
    focused.list.forms[0].elements.protection_scope.value = 'selected';
    focused.list.forms[0].elements.protection_scope.events.change();
    focused.list.forms[0].elements.included_paths.value = '/forums/*\n/help/';
    check(!focused.list.forms[0].elements.included_paths.disabled && focused.list.forms[0].elements.included_paths.required,
        'Selected paths did not enable the required path field');
    await focused.submit();
    const customerPayload = JSON.parse(focused.calls.find(call => call.options.method === 'POST').options.body);
    check(customerPayload.id === 8 && customerPayload.paths.length === 2 && customerPayload.ips[0] === '192.0.2.0/24',
        'Customer domain save lost exclusions or changed target site');
    check(customerPayload.challenge_mode === 'proof-of-work' && customerPayload.difficulty === 3,
        'Challenge selection was not submitted as typed settings');
    check(customerPayload.failure_mode === 'open', 'Customer fail-open selection was lost during save');
    check(customerPayload.image_style === 'generic', 'Customer image choice was lost during save');
    check(customerPayload.protection_scope === 'selected' && customerPayload.included_paths.join(',') === '/forums/*,/help/',
        'Customer save lost selected paths');
    const unavailable = await harness({ domains: [
        { id: 7, name: 'one.test', hosting: 'vrt_hst', active: true, enabled: true, healthy: false,
            paths: [], ips: [], failure_mode: 'open', protection_scope: 'selected', included_paths: ['/forums'], image_style: 'generic' }
    ] });
    check(unavailable.list.forms[0].elements.failure_mode.value === 'open'
        && unavailable.list.forms[0].querySelector('.ag-status').textContent.includes('fail-open fallback enabled'),
        'Saved fail-open setting or outage status is incorrect');
    check(unavailable.list.forms[0].elements.protection_scope.value === 'selected'
        && unavailable.list.forms[0].elements.included_paths.value === '/forums', 'Stored selected paths did not load');
    check(unavailable.list.forms[0].elements.image_style.value === 'generic', 'Saved image choice did not load');
    const configured = await harness({ domains: [
        { id: 7, name: 'one.test', hosting: 'vrt_hst', active: true, enabled: true, paths: [], ips: [],
            challenge_mode: 'metarefresh', difficulty: 4 }
    ] });
    const challengeForm = configured.list.forms[0];
    check(challengeForm.elements.difficulty.disabled && challengeForm.elements.difficulty.value === '4',
        'Refresh mode did not disable and retain the proof-of-work difficulty');
    challengeForm.elements.challenge_mode.value = 'adaptive';
    challengeForm.elements.challenge_mode.events.change();
    check(!challengeForm.elements.difficulty.disabled && challengeForm.querySelector('.ag-challenge-help').textContent.includes('4, 6, and 6'),
        'Adaptive mode did not restore difficulty or describe its effective levels');
    const noEntitlement = await harness({ domains: [], expectedForms: 0 });
    check(noEntitlement.list.textContent.includes('account or hosting plan'), 'Customer empty state does not explain account/plan access');

    const geoState = {config: {mode: 'disabled'}, active: null, last_check: null, last_success: null,
        warnings: [], job: {}, has_license_key: true, recovery_required: false};
    const geoAdmin = await harness({admin: true, geo: geoState});
    check(geoAdmin.geoStatus.textContent.includes('Active source: disabled'), 'GeoIP source status did not load');
    check(geoAdmin.geoForm.elements.license_key.value === '', 'GeoIP displayed a saved secret');
    geoAdmin.geoForm.elements.mode.value = 'local';
    geoAdmin.geoForm.elements.mode.events.change();
    check(geoAdmin.geoForm.querySelector('.ag-geoip-maxmind').hidden && !geoAdmin.geoForm.querySelector('.ag-geoip-local').hidden,
        'GeoIP source fields did not follow selected source');
    geoAdmin.geoForm.elements.country_path.value = '/srv/geoip/*/GeoLite2-Country.mmdb';
    geoAdmin.geoForm.elements.asn_path.value = '/srv/geoip/GeoLite2-ASN_*.mmdb';
    geoAdmin.geoForm.elements.license_key.value = 'new-private-key';
    await geoAdmin.submitGeo();
    const geoSave = geoAdmin.calls.find(call => call.url.endsWith('/geoipsave'));
    check(JSON.parse(geoSave.options.body).country_path === '/srv/geoip/*/GeoLite2-Country.mmdb'
        && JSON.parse(geoSave.options.body).mode === 'local', 'GeoIP save lost wildcard configuration');
    check(geoSave.options.headers.get('X-Anubis-CSRF') === 'extension-token'
        && geoSave.options.headers.get('X-Forgery-Protection-Token') === 'panel-token', 'GeoIP save lost forgery protection');
    check(geoAdmin.geoForm.elements.license_key.value === '' && !geoAdmin.geoStatus.textContent.includes('new-private-key'),
        'GeoIP save retained or rendered the submitted key');
    check(geoAdmin.timers.length > 0 && geoAdmin.geoUpdate.disabled && !geoAdmin.geoInspect.disabled,
        'GeoIP background job lacks polling or status recovery');
    geoState.job = {status: 'succeeded'};
    geoState.config = {mode: 'local', country_path: '/srv/geoip/*/GeoLite2-Country.mmdb', asn_path: '/srv/geoip/GeoLite2-ASN_*.mmdb'};
    await geoAdmin.timers[geoAdmin.timers.length - 1]();
    check(!geoAdmin.geoUpdate.disabled && geoAdmin.geoStatus.textContent.includes('succeeded'), 'GeoIP completion left controls locked');
    const geoRejected = await harness({admin: true, geo: {...geoState, job: {}}, geoSaveError: 'Invalid local database path'});
    await geoRejected.submitGeo();
    check(geoRejected.geoStatus.textContent.includes('Invalid local database path'), 'GeoIP validation failure was overwritten by status');
    check(geoRejected.calls.filter(call => call.url.endsWith('/geoipsave')).length === 1, 'GeoIP save was replayed');

    const runtimeState = {mode: 'automatic', version: '1.28.1', pinned_version: '1.28.1', previous: null,
        downloaded: ['1.28.1'], pages: {'1': {releases: [{version: '1.29.0'}], has_more: true}}, job: {}, recovery_required: false};
    const runtimeAdmin = await harness({admin: true, runtime: runtimeState});
    check(runtimeAdmin.runtimeNodes.status.textContent.includes('Automatic') && runtimeAdmin.runtimeNodes.status.textContent.includes('1.28.1'),
        'Runtime selection and pinned default did not load');
    check(runtimeAdmin.runtimeNodes.rollback.disabled && runtimeAdmin.runtimeNodes.downloaded.value === '1.28.1', 'Runtime controls ignored downloaded/previous versions');
    runtimeAdmin.runtimeNodes.release.value = '1.29.0';
    await runtimeAdmin.runtimeNodes.download.events.click();
    const runtimeDownload = runtimeAdmin.calls.find(call => call.url.endsWith('/runtimejob'));
    check(JSON.parse(runtimeDownload.options.body).action === 'download' && JSON.parse(runtimeDownload.options.body).version === '1.29.0',
        'Runtime download selected the wrong release or action');
    check(runtimeDownload.options.headers.get('X-Anubis-CSRF') === 'extension-token'
        && runtimeDownload.options.headers.get('X-Forgery-Protection-Token') === 'panel-token', 'Runtime action lost CSRF protection');
    check(runtimeAdmin.runtimeNodes.activate.disabled && !runtimeAdmin.runtimeNodes.inspect.disabled && runtimeAdmin.timers.length > 0,
        'Runtime queue did not disable mutations and poll status');
    runtimeState.job = {status: 'succeeded'};
    runtimeState.downloaded = ['1.29.0', '1.28.1'];
    await runtimeAdmin.timers[runtimeAdmin.timers.length - 1]();
    check(runtimeState.version === '1.28.1' && !runtimeAdmin.runtimeNodes.activate.disabled, 'Download changed the active runtime');
    runtimeAdmin.runtimeNodes.downloaded.value = '1.29.0';
    await runtimeAdmin.runtimeNodes.activate.events.click();
    const runtimeActivate = runtimeAdmin.calls.filter(call => call.url.endsWith('/runtimejob')).at(-1);
    check(JSON.parse(runtimeActivate.options.body).mode === 'override' && JSON.parse(runtimeActivate.options.body).action === 'activate',
        'Runtime override did not require explicit activation');
    runtimeState.job = {status: 'succeeded'}; runtimeState.mode = 'override'; runtimeState.version = '1.29.0'; runtimeState.previous = '1.28.1';
    await runtimeAdmin.timers[runtimeAdmin.timers.length - 1]();
    check(!runtimeAdmin.runtimeNodes.rollback.disabled && runtimeAdmin.runtimeNodes.status.textContent.includes('Override'), 'Runtime override status or rollback is missing');
    await runtimeAdmin.runtimeNodes.auto.events.click();
    const runtimeAuto = JSON.parse(runtimeAdmin.calls.filter(call => call.url.endsWith('/runtimejob')).at(-1).options.body);
    check(runtimeAuto.mode === 'automatic' && runtimeAuto.action === 'activate' && !runtimeAuto.version, 'Automatic selection was tied to a fixed override');

    const interruptedRuntime = await harness({admin: true, runtime: {...runtimeState, job: {}}, runtimeNetworkError: true});
    await interruptedRuntime.runtimeNodes.auto.events.click();
    check(interruptedRuntime.runtimeNodes.status.textContent.includes('Settings may have been applied'), 'Interrupted runtime action lacks recovery guidance');
    check(interruptedRuntime.calls.filter(call => call.url.endsWith('/runtimejob')).length === 1, 'Interrupted runtime POST was replayed');
    const busyRuntime = await harness({admin: true, runtime: {...runtimeState, job: {status: 'running'}}, geo: {...geoState, job: {}}});
    await busyRuntime.submitGeo();
    check(!busyRuntime.calls.some(call => call.url.endsWith('/geoipsave')), 'GeoIP mutation was sent during runtime activation');
    console.log(`${checks} frontend checks passed`);
})().catch(error => { console.error(error); process.exitCode = 1; });
