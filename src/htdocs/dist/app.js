/* Native Plesk PHP SDK page enhancement; no external scripts or build dependencies. */
(function () {
    'use strict';
    function init() {
        const root = document.getElementById('anubis-guard');
        if (!root) return;
        const base = root.dataset.baseUrl.replace(/\/$/, '');
        const list = root.querySelector('#ag-domains');
        const message = root.querySelector('#ag-message');
        const refresh = root.querySelector('#ag-refresh');
        let saving = false;
        let geoBusy = false;
        let runtimeBusy = false;
        async function request(action, options) {
            options = options || {};
            const headers = new Headers(options.headers || {});
            headers.set('Accept', 'application/json');
            headers.set('X-Requested-With', 'XMLHttpRequest');
            // Plesk validates its own panel token before our API controller runs.
            // Read it for every request so a refreshed panel token is respected.
            const panelToken = document.getElementById('forgery_protection_token');
            if (panelToken && panelToken.content) {
                headers.set('X-Forgery-Protection-Token', panelToken.content);
            } else if (!['GET', 'HEAD'].includes((options.method || 'GET').toUpperCase())) {
                throw new Error('The Plesk session token is unavailable. Reload the panel before saving.');
            }
            let response;
            const interrupted = 'The connection to Plesk was interrupted. Settings may have been applied. ' +
                'Use Refresh status to check before saving again. If the panel is unavailable, wait a moment and reload it.';
            try {
                response = await fetch(base + '/index.php/api/' + action, Object.assign({}, options, {
                    credentials: 'same-origin', cache: 'no-store', headers: headers
                }));
            } catch (error) {
                throw new Error(interrupted);
            }
            let body;
            try {
                body = await response.json();
            } catch (error) {
                if (error instanceof TypeError) throw new Error(interrupted);
                throw new Error('Plesk returned a panel page instead of API data (HTTP ' + response.status +
                    '). Reload the panel and sign in again if needed, then retry.');
            }
            if (!body || typeof body !== 'object' || Array.isArray(body)) {
                throw new Error('Plesk returned an unexpected API response. Reload the panel and retry.');
            }
            if (!response.ok) throw new Error(typeof body.error === 'string' ? body.error : 'The request failed.');
            return body;
        }
        function lines(value) { return value.split(/\r?\n/).map(s => s.trim()).filter(Boolean); }
        const runtimePanel = root.querySelector('#ag-runtime');
        if (runtimePanel) {
            const status = runtimePanel.querySelector('#ag-runtime-status');
            const releases = runtimePanel.querySelector('#ag-runtime-release');
            const downloaded = runtimePanel.querySelector('#ag-runtime-downloaded');
            const buttons = {};
            for (const key of ['releases', 'more', 'download', 'activate', 'auto', 'rollback', 'inspect']) {
                buttons[key] = runtimePanel.querySelector('#ag-runtime-' + key);
            }
            let pollTimer, nextPage = 1;
            function choices(select, values, preferred) {
                const selected = select.value || preferred;
                select.replaceChildren();
                for (const value of values) {
                    const option = document.createElement('option');
                    option.value = value;
                    option.textContent = value;
                    select.appendChild(option);
                }
                select.value = values.includes(selected) ? selected : (values.includes(preferred) ? preferred : (values[0] || ''));
            }
            async function runtimeStatus() {
                clearTimeout(pollTimer);
                try {
                    const data = await request('runtimestatus');
                    runtimeBusy = ['queued', 'running'].includes(data.job.status);
                    const versions = new Set([data.pinned_version]);
                    const pages = Object.keys(data.pages).map(Number).sort((a, b) => a - b);
                    for (const page of pages) for (const release of data.pages[String(page)].releases) versions.add(release.version);
                    choices(releases, Array.from(versions), data.pinned_version);
                    choices(downloaded, data.downloaded, data.version);
                    nextPage = pages.length ? pages[pages.length - 1] + 1 : 1;
                    const rows = ['Selection: ' + (data.mode === 'automatic' ? 'Automatic' : 'Override'),
                        'Pinned default: ' + data.pinned_version, 'Active runtime: ' + data.version,
                        'Previous runtime: ' + (data.previous || 'None'), 'Update: ' + (data.job.status || 'idle')];
                    if (data.job.error) rows.push(data.job.error);
                    if (data.recovery_required) rows.push('Recovery required. Previous runtime retained; inspect the runtime worker journal.');
                    status.textContent = rows.join('\n');
                    runtimePanel.querySelectorAll('button').forEach(button => { button.disabled = runtimeBusy || saving || geoBusy; });
                    buttons.inspect.disabled = false;
                    buttons.download.disabled ||= !releases.value;
                    buttons.activate.disabled ||= !downloaded.value;
                    buttons.rollback.disabled ||= !data.previous;
                    buttons.more.disabled ||= nextPage > 100 || (pages.length > 0 && !data.pages[String(pages[pages.length - 1])].has_more);
                    releases.disabled = downloaded.disabled = runtimeBusy;
                    if (runtimeBusy) pollTimer = setTimeout(runtimeStatus, 2000);
                } catch (error) {
                    status.textContent = error.message;
                    buttons.inspect.disabled = false;
                    if (runtimeBusy) pollTimer = setTimeout(runtimeStatus, 5000);
                }
            }
            async function runtimeJob(payload) {
                if (saving || geoBusy || runtimeBusy) {
                    status.textContent = 'Wait for the current configuration update to finish, then refresh status.';
                    return;
                }
                runtimeBusy = true;
                runtimePanel.querySelectorAll('button').forEach(button => { button.disabled = true; });
                let failure = '';
                status.textContent = 'Runtime job queued…';
                try {
                    await request('runtimejob', {method: 'POST', headers: {'Content-Type': 'application/json',
                        'X-Anubis-CSRF': root.dataset.csrf}, body: JSON.stringify(payload)});
                } catch (error) {
                    failure = error.message;
                } finally {
                    await runtimeStatus();
                    if (failure) status.textContent += '\n' + failure;
                }
            }
            buttons.releases.addEventListener('click', () => runtimeJob({action: 'refresh', page: 1}));
            buttons.more.addEventListener('click', () => runtimeJob({action: 'refresh', page: nextPage}));
            buttons.download.addEventListener('click', () => runtimeJob({action: 'download', version: releases.value}));
            buttons.activate.addEventListener('click', () => runtimeJob({action: 'activate', mode: 'override', version: downloaded.value}));
            buttons.auto.addEventListener('click', () => runtimeJob({action: 'activate', mode: 'automatic'}));
            buttons.rollback.addEventListener('click', () => runtimeJob({action: 'rollback'}));
            buttons.inspect.addEventListener('click', runtimeStatus);
            runtimeStatus();
        }
        const geoForm = root.querySelector('#ag-geoip-form');
        if (geoForm) {
            const status = root.querySelector('#ag-geoip-status');
            const update = root.querySelector('#ag-geoip-refresh');
            const inspect = root.querySelector('#ag-geoip-status-refresh');
            let pollTimer;
            function sourceFields() {
                const mode = geoForm.elements.mode.value;
                for (const source of ['maxmind', 'local']) {
                    const fieldset = geoForm.querySelector('.ag-geoip-' + source);
                    fieldset.hidden = mode !== source;
                    fieldset.disabled = mode !== source || geoBusy;
                }
                geoForm.elements.account_id.required = mode === 'maxmind';
                geoForm.elements.country_path.required = geoForm.elements.asn_path.required = mode === 'local';
                geoForm.elements.clear_key.disabled = mode === 'maxmind' || geoBusy;
                if (mode === 'maxmind') geoForm.elements.clear_key.checked = false;
            }
            geoForm.elements.mode.addEventListener('change', sourceFields);
            sourceFields();
            async function geoStatus(populate) {
                clearTimeout(pollTimer);
                try {
                    const data = await request('geoipstatus');
                    geoBusy = ['queued', 'running'].includes(data.job.status);
                    if (populate) {
                        for (const name of ['mode', 'account_id', 'country_path', 'asn_path']) {
                            geoForm.elements[name].value = data.config[name] || (name === 'mode' ? 'disabled' : '');
                        }
                        geoForm.elements.license_key.value = '';
                        geoForm.elements.clear_key.checked = false;
                    }
                    geoForm.querySelector('.ag-geoip-key-status').textContent = data.has_license_key
                        ? 'A key is saved. Leave blank to retain it.' : 'No license key is saved.';
                    const date = value => value ? new Date(value * 1000).toISOString() : 'Never';
                    const rows = ['Active source: ' + data.config.mode,
                        'Last check: ' + date(data.last_check), 'Last successful refresh: ' + date(data.last_success)];
                    for (const kind of ['country', 'asn']) {
                        const db = data.active && data.active[kind];
                        rows.push(kind.toUpperCase() + ': ' + (db ? db.source + ' (built ' + date(db.build_epoch) + ')' : 'Not configured'));
                    }
                    rows.push('Update: ' + (data.job.status || 'idle'));
                    if (data.job.error) rows.push(data.job.error);
                    if (data.recovery_required) rows.push('Recovery required. The previous generation is retained; inspect the GeoIP worker journal.');
                    rows.push(...(data.warnings || []));
                    status.textContent = rows.join('\n');
                    geoForm.querySelectorAll('button').forEach(button => { button.disabled = geoBusy || saving; });
                    inspect.disabled = false;
                    geoForm.elements.mode.disabled = geoBusy;
                    sourceFields();
                    if (geoBusy) pollTimer = setTimeout(() => geoStatus(true), 2000);
                } catch (error) {
                    status.textContent = error.message;
                    // Only poll reads after disconnects; never replay a save.
                    inspect.disabled = false;
                    if (geoBusy) pollTimer = setTimeout(() => geoStatus(true), 5000);
                }
            }
            async function geoMutation(action, payload) {
                if (saving || geoBusy || runtimeBusy) {
                    status.textContent = 'Wait for the current configuration update to finish, then refresh status.';
                    return;
                }
                geoBusy = true;
                geoForm.querySelectorAll('button').forEach(button => { button.disabled = true; });
                status.textContent = 'GeoIP update queued…';
                let failure = '';
                try {
                    await request(action, {method: 'POST', headers: {'Content-Type': 'application/json',
                        'X-Anubis-CSRF': root.dataset.csrf}, body: JSON.stringify(payload)});
                    geoForm.elements.license_key.value = '';
                } catch (error) {
                    failure = error.message;
                } finally {
                    await geoStatus(true);
                    if (failure) status.textContent += '\n' + failure;
                }
            }
            geoForm.addEventListener('submit', async event => {
                event.preventDefault();
                const payload = {};
                for (const name of ['mode', 'account_id', 'license_key', 'country_path', 'asn_path']) payload[name] = geoForm.elements[name].value;
                payload.clear_key = geoForm.elements.clear_key.checked;
                await geoMutation('geoipsave', payload);
            });
            update.addEventListener('click', () => geoMutation('geoiprefresh', {}));
            inspect.addEventListener('click', () => geoStatus(true));
            geoStatus(true);
        }
        async function load() {
            if (saving) return;
            refresh.disabled = true;
            list.setAttribute('aria-busy', 'true');
            try {
                const result = await request('list');
                const domains = root.dataset.domainId
                    ? result.domains.filter(domain => String(domain.id) === root.dataset.domainId)
                    : result.domains;
                list.replaceChildren();
                if (!domains.length) {
                    list.textContent = result.is_admin
                        ? 'No websites yet. Add a website in Plesk, then refresh this list.'
                        : 'No websites are available for Anubis management under your account or hosting plan.';
                }
                for (const domain of domains) {
                    const form = root.querySelector('#ag-domain-template').content.firstElementChild.cloneNode(true);
                    form.querySelector('.ag-name').textContent = domain.name;
                    const available = domain.hosting === 'vrt_hst' && domain.active;
                    form.querySelector('.ag-status').textContent = domain.enabled
                        ? (!domain.active ? 'Enabled · website suspended' : (domain.healthy ? 'Enabled · Anubis is healthy'
                            : (domain.failure_mode === 'open' ? 'Enabled · Anubis unavailable; fail-open fallback enabled'
                                : 'Enabled · Anubis unavailable; protected requests remain blocked')))
                        : (available ? 'Protection disabled' : 'Protection unavailable for this hosting state');
                    form.elements.enabled.checked = domain.enabled;
                    // An enabled site can always be disabled, including during suspension.
                    form.elements.enabled.disabled = !available && !domain.enabled;
                    form.elements.failure_mode.value = domain.failure_mode || 'closed';
                    form.elements.image_style.value = domain.image_style || 'original';
                    form.elements.protection_scope.value = domain.protection_scope || 'all';
                    form.elements.included_paths.value = (domain.included_paths || []).join('\n');
                    function describeScope() {
                        const selected = form.elements.protection_scope.value === 'selected';
                        form.elements.included_paths.disabled = !selected;
                        form.elements.included_paths.required = selected;
                    }
                    form.elements.protection_scope.addEventListener('change', describeScope);
                    describeScope();
                    form.elements.paths.value = domain.paths.join('\n');
                    form.elements.ips.value = domain.ips.join('\n');
                    form.elements.challenge_mode.value = domain.challenge_mode || 'adaptive';
                    form.elements.difficulty.value = String(domain.difficulty ?? 2);
                    function describeChallenge() {
                        const mode = form.elements.challenge_mode.value;
                        const difficulty = Number(form.elements.difficulty.value);
                        form.elements.difficulty.disabled = mode === 'metarefresh';
                        form.querySelector('.ag-challenge-help').textContent = mode === 'adaptive'
                            ? 'Uses request suspicion: low-risk traffic passes or refreshes; proof-of-work levels are ' +
                                difficulty + ', ' + Math.min(difficulty + 2, 6) + ', and ' + Math.min(difficulty + 4, 6) + '.'
                            : (mode === 'proof-of-work'
                                ? 'Remaining requests must complete JavaScript proof of work at the selected difficulty.'
                                : 'Remaining requests receive a lightweight browser refresh, without JavaScript proof of work. Offers less bot resistance.');
                    }
                    form.elements.challenge_mode.addEventListener('change', describeChallenge);
                    form.elements.difficulty.addEventListener('input', describeChallenge);
                    describeChallenge();
                    form.querySelector('.ag-error').textContent = domain.last_error;
                    form.addEventListener('submit', async event => {
                        event.preventDefault();
                        if (saving || geoBusy || runtimeBusy) {
                            message.textContent = 'Wait for the current configuration update to finish, then refresh status.';
                            return;
                        }
                        const payload = { id: domain.id, enabled: form.elements.enabled.checked,
                            paths: lines(form.elements.paths.value), ips: lines(form.elements.ips.value),
                            challenge_mode: form.elements.challenge_mode.value, difficulty: Number(form.elements.difficulty.value),
                            failure_mode: form.elements.failure_mode.value,
                            image_style: form.elements.image_style.value,
                            protection_scope: form.elements.protection_scope.value,
                            included_paths: lines(form.elements.included_paths.value) };
                        saving = true;
                        root.querySelectorAll('button').forEach(button => { button.disabled = true; });
                        message.textContent = 'Applying settings…';
                        try {
                            await request('save', { method: 'POST', headers: {
                                'Content-Type': 'application/json', 'X-Anubis-CSRF': root.dataset.csrf
                            }, body: JSON.stringify(payload) });
                            message.textContent = 'Settings saved.';
                            saving = false;
                            await load();
                        } catch (error) {
                            message.textContent = error.message;
                        } finally {
                            saving = false;
                            root.querySelectorAll('button').forEach(button => { button.disabled = false; });
                        }
                    });
                    list.appendChild(form);
                }
            } catch (error) {
                message.textContent = error.message;
            } finally {
                refresh.disabled = false;
                list.setAttribute('aria-busy', 'false');
            }
        }
        refresh.addEventListener('click', load);
        load();
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
}());
