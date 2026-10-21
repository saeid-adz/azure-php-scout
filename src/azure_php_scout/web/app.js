'use strict';
const $ = id => document.getElementById(id);
const state = {token: sessionStorage.getItem('scout-token') || '', selected: '', offset: 0, limit: 50, rows: [], jobs: [], busy: false, timer: null, catalog: null, findingRequest: 0};
const labels = {potentially_affected: 'Potentially affected', end_of_life: 'Upstream end of life', verify_version: 'Verify runtime version', configuration_only: 'Configuration only', no_catalog_match: 'Outside tracked ranges', undetermined: 'Undetermined'};
const resourceLabels = {vm: 'Virtual machine', appservice: 'App Service', staticwebapp: 'Static Web App', target: 'Manual target'};
const runningStates = new Set(['queued', 'running', 'cancelling']);
function el(tag, className, text) { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = String(text); return node; }
function safeLink(url, text) { try { const parsed = new URL(url); if (!['http:', 'https:'].includes(parsed.protocol)) throw Error(); const link = el('a', '', text); link.href = parsed.href; link.target = '_blank'; link.rel = 'noopener noreferrer'; return link; } catch (_) { return el('span', '', text); } }
function toast(message) { $('toast').textContent = message; $('toast').hidden = false; setTimeout(() => {$('toast').hidden = true;}, 4500); }
async function api(path, options = {}) {
  const headers = {'Authorization': 'Bearer ' + state.token, ...(options.body ? {'Content-Type': 'application/json'} : {}), ...options.headers};
  const response = await fetch(path, {...options, headers});
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const detail = Array.isArray(body.detail) ? body.detail.map(item => item.msg).join('\n') : body.detail;
    if (response.status === 401 && path !== '/api/status') logout();
    throw Error(detail || 'Request failed (' + response.status + ')');
  }
  return options.download ? response.blob() : response.json();
}
function logout() { clearTimeout(state.timer); state.findingRequest++; state.token = ''; state.selected = ''; sessionStorage.removeItem('scout-token'); $('app').hidden = true; $('login-screen').hidden = false; $('token').value = ''; }
async function connect(token) {
  state.token = token;
  const status = await api('/api/status');
  sessionStorage.setItem('scout-token', token);
  $('version').textContent = status.version;
  $('connection-label').textContent = status.azureCliAvailable ? 'Azure CLI available' : 'Inventory / manual mode';
  $('coverage-date').textContent = status.advisoryReviewedAt;
  state.catalog = await api('/api/advisories');
  $('login-screen').hidden = true; $('app').hidden = false;
  await refresh(true); schedule();
}
function schedule() { clearTimeout(state.timer); state.timer = setTimeout(async () => { if (!state.token) return; try { await refresh(); } catch (error) { $('workspace-error').textContent = error.message; } schedule(); }, 5000); }
function statusLabel(job) { return {complete: 'Complete', partial: 'Partial coverage', failed: 'Failed', running: 'Scanning', queued: 'Queued', cancelling: 'Cancelling', cancelled: 'Cancelled', interrupted: 'Interrupted'}[job.state] || job.state; }
async function refresh(force = false) {
  if (state.busy || !state.token) return;
  state.busy = true;
  try {
    const jobs = await api('/api/scans'); state.jobs = jobs;
    const previous = state.selected;
    if (!state.selected || !jobs.some(job => job.id === state.selected)) state.selected = jobs[0]?.id || '';
    const select = $('scan-select'); select.replaceChildren();
    if (!jobs.length) select.append(el('option', '', 'No scans yet'));
    for (const job of jobs) { const option = el('option', '', job.config.name + ' · ' + new Date(job.created).toLocaleString([], {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'})); option.value = job.id; select.append(option); }
    select.value = state.selected;
    const current = jobs.find(job => job.id === state.selected);
    if (current && (force || previous !== state.selected || runningStates.has(current.state) || state.lastState !== current.state)) await loadSelected();
    if (!current) renderEmpty();
    $('workspace-error').textContent = '';
  } finally { state.busy = false; }
}
function renderEmpty() { $('scan-state').textContent = 'No scans yet'; $('findings-body').replaceChildren(); $('empty-state').hidden = false; $('finding-count').textContent = '0'; }
async function loadSelected() {
  if (!state.selected) return;
  const selected = state.selected;
  const job = await api('/api/scans/' + selected);
  if (selected !== state.selected || !state.token) return;
  state.lastState = job.state;
  const summary = job.summary || {}, scope = job.coverage || {}, resources = scope.resources || {}, tcp = scope.tcp || {};
  $('stat-affected').textContent = summary.potentiallyAffected || 0; $('stat-eol').textContent = summary.endOfLife || 0; $('stat-verify').textContent = summary.verifyVersion || 0; $('stat-http').textContent = summary.responded || 0;
  $('stat-endpoints').textContent = (summary.endpoints || 0) + ' endpoints checked';
  $('scan-state').className = 'status-badge ' + job.state; $('scan-state').textContent = statusLabel(job);
  $('cancel-scan').hidden = !runningStates.has(job.state); $('cancel-scan').disabled = job.state === 'cancelling';
  $('download-html').disabled = !summary.endpoints; $('download-csv').disabled = !summary.endpoints;
  $('demo-notice').hidden = job.config.mode !== 'demo';
  $('coverage-resources').textContent = resources.vm !== undefined ? resources.vm + ' VMs · ' + (resources.appservice || 0) + ' apps · ' + (resources.staticwebapp || 0) + ' static apps' : scope.source || 'Inventory discovery in progress';
  $('coverage-ports').textContent = scope.vmPortScope || (job.config.vm_ports === 'all' ? 'Full TCP range 1–65535' : job.config.vm_ports);
  $('coverage-tcp').textContent = tcp.total ? tcp.checked.toLocaleString() + ' / ' + tcp.total.toLocaleString() + ' · ' + tcp.open + ' open' : job.config.mode === 'demo' ? 'Synthetic data' : 'Waiting for discovery';
  $('run-progress').hidden = !runningStates.has(job.state);
  $('tcp-progress').value = tcp.total ? Math.round(100 * tcp.checked / tcp.total) : 0;
  $('progress-text').textContent = tcp.total ? tcp.open + ' open TCP ports · ' + (scope.httpChecked || 0) + ' HTTP checks completed' : job.state === 'queued' ? 'Queued behind the current scan' : 'Collecting inventory and HTTP evidence…';
  const errors = [...(scope.errors || [])]; if (job.error && !errors.includes(job.error)) errors.push(job.error);
  $('coverage-errors').replaceChildren(...errors.map(error => el('p', '', error))); $('coverage-errors').hidden = !errors.length;
  const skipped = scope.skipped || [];
  $('coverage-skipped').textContent = skipped.length ? skipped.length + ' resources have no directly scannable public endpoint. See the HTML/JSON export for full coverage details.' : 'No skipped resources reported in the current snapshot.';
  await loadFindings();
}
async function loadFindings() {
  if (!state.selected) return;
  const request = ++state.findingRequest, selected = state.selected;
  const params = new URLSearchParams({offset: state.offset, limit: state.limit, q: $('search').value.trim(), resource_type: $('resource-filter').value, assessment: $('assessment-filter').value});
  const data = await api('/api/scans/' + selected + '/results?' + params);
  if (request !== state.findingRequest || selected !== state.selected || !state.token) return;
  state.rows = data.rows;
  $('finding-count').textContent = data.total;
  const body = $('findings-body'); body.replaceChildren();
  data.rows.forEach(row => {
    const tr = el('tr');
    const service = el('td'); service.append(el('span', 'service-name', row.vm || row.app || row.hostname || row.target), el('span', 'endpoint', (row.hostname || row.target) + ':' + row.port), el('span', 'asset-type', resourceLabels[row.resourceType] || 'Manual target'));
    const context = el('td'); context.append(el('span', 'customer-name', row.subscription || 'Unassigned'), el('span', 'resource-group', row.resourceGroup || '—'));
    const runtime = el('td'); runtime.append(el('span', 'runtime-version', row.phpVersion ? 'PHP ' + row.phpVersion : row.php === 'unknown' ? 'PHP unknown' : 'PHP version hidden'), el('span', 'signal-label', row.wordpress !== 'unknown' && row.wordpress ? 'WordPress' + (row.wordpressVersion ? ' ' + row.wordpressVersion : ' signals') : row.reachable === 'yes' ? 'HTTP ' + row.httpStatus : row.tcpOpen === 'yes' ? 'Open TCP / no HTTP' : 'No HTTP response'));
    const assessment = el('td'); assessment.append(el('span', 'risk-badge ' + row.riskLevel, labels[row.assessment] || 'Undetermined')); if (row.cves) assessment.append(el('span', 'cve-label', row.cves));
    const action = el('td'); const button = el('button', 'inspect', '↗'); button.type = 'button'; button.setAttribute('aria-label', 'Inspect ' + (row.vm || row.app || row.target)); button.addEventListener('click', () => showDetails(row)); action.append(button);
    tr.append(service, context, runtime, assessment, action); body.append(tr);
  });
  $('empty-state').hidden = data.rows.length > 0;
  const emptyHeading = $('empty-state').querySelector('h3'), emptyText = $('empty-state').querySelector('p');
  emptyHeading.textContent = state.selected ? 'No findings match this view.' : 'Your Azure exposure, in one place.';
  emptyText.textContent = state.selected ? 'Try different filters, or wait for the scan to collect results.' : 'Start a scan, import an inventory, or explore the synthetic demo.';
  $('empty-demo').hidden = Boolean(state.selected);
  $('page-label').textContent = data.total ? (state.offset + 1) + '–' + (state.offset + data.rows.length) + ' of ' + data.total + ' results' : 'No findings to display';
  $('previous').disabled = state.offset === 0; $('next').disabled = state.offset + state.limit >= data.total;
}
function section(container, title, text) { const group = el('section', 'detail-section'); group.append(el('h3', '', title), el('p', '', text || '—')); container.append(group); return group; }
function showDetails(row) {
  $('detail-title').textContent = row.vm || row.app || row.hostname || row.target;
  const content = $('detail-content'); content.replaceChildren(el('span', 'risk-badge ' + row.riskLevel, labels[row.assessment] || 'Undetermined'));
  const grid = el('dl', 'detail-grid');
  for (const [label, value] of [['Resource type', resourceLabels[row.resourceType]], ['Subscription', row.subscription], ['Resource group', row.resourceGroup], ['Endpoint', row.finalUrl || row.url], ['Reported PHP', row.phpVersions || row.phpVersion], ['WordPress', row.wordpressVersion || row.wordpress], ['Configured PHP', row.configuredPhpVersion], ['Server', row.server], ['HTTP status', row.httpStatus], ['PHP support', row.phpSupport], ['Rules reviewed', row.advisoryReviewedAt]]) { if (value) grid.append(el('dt', '', label), el('dd', '', value)); }
  content.append(grid);
  section(content, 'Version assessment', row.assessmentBasis); section(content, 'Recommended action', row.remediation); section(content, 'Detection evidence', row.evidence || 'No explicit technology signature was collected.'); if (row.note) section(content, 'Connection notes', row.note);
  if (row.cves) { const group = section(content, 'Official advisories', 'Review the vendor guidance and verify applicability to the deployed runtime.'); for (const item of state.catalog?.advisories || []) if (row.cves.includes(item.id)) group.append(safeLink(item.url, item.id + ' ↗'), el('br')); }
  if (row.resourceId?.startsWith('/subscriptions/')) { const group = section(content, 'Azure resource', row.resourceId); group.append(safeLink('https://portal.azure.com/#resource' + row.resourceId, 'Open resource in Azure Portal ↗')); }
  $('detail-dialog').showModal();
}
function showAdvisories() {
  const content = $('advisory-content'); content.replaceChildren(el('p', 'muted', state.catalog?.scope || 'Two reviewed PHP core advisories.'));
  for (const item of state.catalog?.advisories || []) { const card = el('article', 'advisory-card'); card.append(el('span', 'risk-badge critical', item.id + ' · Critical · CVSS ' + item.cvss), el('h3', '', item.title), el('p', '', 'Upstream fixed releases by branch. Vendor backports require separate verification.')); const versions = el('div', 'patch-grid'); for (const fixed of Object.values(item.fixed)) versions.append(el('span', '', fixed)); card.append(versions, el('p', '', 'Published ' + item.published + ' · Catalog reviewed ' + state.catalog.reviewed_at), safeLink(item.url, 'Read official advisory ↗')); content.append(card); }
  section(content, 'How findings are assessed', 'A PHP header version can match an upstream advisory range. This does not prove exploitability, establish a vendor backport status, or identify every vulnerability. Unknown runtime versions remain verification tasks. Configuration values are reported separately.');
  $('advisory-dialog').showModal();
}
async function createDemo() { try { const job = await api('/api/scans', {method:'POST', body:JSON.stringify({mode:'demo', name:'Community demo · synthetic resources'})}); state.selected = job.id; state.offset = 0; state.lastState = ''; await refresh(true); toast('Demo loaded. No network scan was started.'); } catch (error) { $('workspace-error').textContent = error.message; } }
function updateSource() { const mode = $('source-mode').value; $('azure-fields').hidden = mode !== 'azure'; $('target-fields').hidden = mode !== 'targets'; $('inventory-fields').hidden = mode !== 'inventory'; }
function updateProfile() { const value = $('port-profile').value; $('custom-port-field').hidden = value !== 'custom'; $('port-hint').textContent = value === 'all' ? 'Tests 65,535 TCP ports per public VM address. Large fleets can take hours. Managed application hostnames use ports 80 and 443.' : 'Open VM ports are checked for HTTP and HTTPS. App Services and Static Web Apps use hostname ports 80 and 443.'; }
$('login-form').addEventListener('submit', async event => { event.preventDefault(); $('login-error').textContent = ''; const button = event.submitter || event.target.querySelector('button[type="submit"]'); button.disabled = true; try { await connect($('token').value.trim()); $('token').value = ''; } catch (error) { $('login-error').textContent = error.message; } finally { button.disabled = false; } });
$('sign-out').addEventListener('click', logout);
$('new-scan').addEventListener('click', () => {$('scan-form-error').textContent = ''; $('scan-dialog').showModal();});
for (const button of document.querySelectorAll('.close-dialog')) button.addEventListener('click', () => button.closest('dialog').close());
for (const id of ['nav-advisories','view-advisories']) $(id).addEventListener('click', showAdvisories);
$('nav-workspace').addEventListener('click', () => window.scrollTo({top:0, behavior:'smooth'}));
for (const id of ['load-demo','empty-demo']) $(id).addEventListener('click', createDemo);
$('refresh').addEventListener('click', () => refresh(true).catch(error => {$('workspace-error').textContent = error.message;}));
$('scan-select').addEventListener('change', async event => { state.selected = event.target.value; state.offset = 0; state.lastState = ''; await loadSelected(); });
let searchTimer;
$('search').addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => {state.offset = 0; loadFindings().catch(error => toast(error.message));}, 200); });
for (const id of ['resource-filter','assessment-filter']) $(id).addEventListener('change', () => {state.offset = 0; loadFindings().catch(error => toast(error.message));});
$('previous').addEventListener('click', () => {state.offset = Math.max(0, state.offset - state.limit); loadFindings().catch(error => toast(error.message));});
$('next').addEventListener('click', () => {state.offset += state.limit; loadFindings().catch(error => toast(error.message));});
$('cancel-scan').addEventListener('click', async () => { try { await api('/api/scans/' + state.selected + '/cancel', {method:'POST', body:'{}'}); await refresh(true); } catch (error) { toast(error.message); } });
$('load-logs').addEventListener('click', async () => { if (!state.selected) return; try { const data = await api('/api/scans/' + state.selected + '/logs'); $('scan-log').textContent = data.text || 'No log output yet.'; $('scan-log').hidden = false; } catch (error) { toast(error.message); } });
for (const format of ['html','csv']) $('download-' + format).addEventListener('click', async () => { if (!state.selected) return; try { const blob = await api('/api/scans/' + state.selected + '/export/' + format, {download:true}); const url = URL.createObjectURL(blob); const link = el('a'); link.href = url; link.download = 'azure-php-scout-' + state.selected.slice(0,8) + '.' + format; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); } catch (error) { toast(error.message); } });
$('source-mode').addEventListener('change', updateSource); $('port-profile').addEventListener('change', updateProfile);
$('list-subscriptions').addEventListener('click', async () => { const list = $('subscription-list'); list.hidden = false; list.textContent = 'Checking Azure CLI session…'; try { const records = await api('/api/azure/subscriptions'); list.replaceChildren(el('p', '', records.length + ' enabled subscriptions. Copy the IDs you want into the field above, or leave it empty for all.')); for (const record of records) list.append(el('p', '', record.name + ' · ' + record.id)); } catch (error) { list.textContent = error.message; } });
$('scan-form').addEventListener('submit', async event => {
  event.preventDefault(); const form = new FormData(event.target); const button = $('start-scan'); button.disabled = true; $('scan-form-error').textContent = '';
  try {
    const mode = form.get('mode'), profile = form.get('profile');
    const config = {mode, name:form.get('name'), vm_ports:profile === 'custom' ? form.get('custom_ports').trim() : profile, subscriptions:mode === 'azure' ? form.get('subscriptions').split(/[\s,;]+/).filter(Boolean) : [], targets:mode === 'targets' ? form.get('targets').split(/[\s,;]+/).filter(Boolean) : []};
    for (const key of ['timeout','workers','port_rate','port_workers']) config[key] = Number(form.get(key));
    for (const key of ['running_only','no_probes','verify_tls']) config[key] = form.has(key);
    if (mode === 'inventory') { const file = $('inventory-file').files[0]; if (!file) throw Error('Choose an inventory CSV.'); if (file.size > 1500000) throw Error('Inventory CSV must be smaller than 1.5 MB.'); config.inventory_csv = await file.text(); }
    const job = await api('/api/scans', {method:'POST', body:JSON.stringify(config)}); state.selected = job.id; state.offset = 0; state.lastState = ''; $('scan-dialog').close(); await refresh(true); toast('Scan queued. Results will appear as endpoints are checked.');
  } catch (error) { $('scan-form-error').textContent = error.message; } finally { button.disabled = false; }
});
if (state.token) connect(state.token).catch(error => {logout(); $('login-error').textContent = error.message;});
