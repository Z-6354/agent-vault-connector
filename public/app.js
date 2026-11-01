'use strict';
const byId = id => document.getElementById(id);
let csrf = '';
let editing;
let pending;
let services = [];
let oauthProviders = [];
let managementState = 'S0';
let sessionGeneration = 0;
const message = text => { byId('message').textContent = text; };
const oauthMinimumScopes = provider => provider === 'github' ? ['read:user'] : provider === 'google' ? ['openid', 'email'] : [];
const providerName = provider => provider === 'github' ? 'GitHub' : provider === 'google' ? 'Google' : provider;
const formatExpiry = value => {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toLocaleString() : 'Unavailable';
};
function detailsList(fields) {
  const list = document.createElement('dl');
  for (const [name, value] of Object.entries(fields)) {
    const term = document.createElement('dt'); term.textContent = name;
    const description = document.createElement('dd'); description.textContent = String(value ?? '—');
    list.append(term, description);
  }
  return list;
}
const recoveryStorageKey = 'agent-vault:last-save-request';
function rememberSaveRequest(requestId) {
  byId('save-request-id').value = requestId;
  try { sessionStorage.setItem(recoveryStorageKey, requestId); } catch { /* Manual request ID recovery remains available. */ }
}
try { byId('save-request-id').value = sessionStorage.getItem(recoveryStorageKey) || ''; } catch { /* Storage may be disabled. */ }
async function api(path, method = 'GET', body) {
  const response = await fetch(path, {
    method, credentials: 'same-origin',
    headers: method === 'GET' ? {} : { 'content-type': 'application/json', 'x-csrf-token': csrf },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) {
    if (response.status === 401 || response.status === 423) await session();
    throw new Error(data.error || 'Request failed');
  }
  return data;
}
function resetEditor() {
  editing = undefined; pending = undefined;
  byId('credential-form').reset();
  byId('editor-title').textContent = 'Add a connection';
  byId('save-button').textContent = 'Review connection';
  byId('cancel-button').hidden = true;
  byId('editor-panel').hidden = false;
  byId('confirmation-panel').hidden = true;
  byId('draft-details').replaceChildren();
  if (services.length) serviceChanged();
}
function showState(data) {
  sessionGeneration++;
  managementState = data.state;
  csrf = data.csrf || '';
  byId('login-panel').hidden = data.state !== 'S0';
  byId('unlock-panel').hidden = data.state !== 'S1';
  byId('vault-panel').hidden = data.state !== 'S2';
  byId('login-passphrase').value = ''; byId('passphrase').value = '';
  if (data.state !== 'S2') {
    byId('credentials').replaceChildren();
    byId('browser-approvals').replaceChildren();
    byId('browser-support-status').textContent = '';
    byId('browser-approval-status').textContent = 'Refresh to check for requests. This panel does not poll or keep your management session alive.';
    byId('oauth-providers').replaceChildren();
    byId('oauth-provider-status').textContent = '';
    byId('operations').replaceChildren(); byId('audit-events').replaceChildren();
    oauthProviders = [];
    resetEditor();
  }
}
function serviceChanged() {
  const service = services.find(item => item.service_id === byId('service').value);
  if (!service) return;
  const types = byId('credential-type'); types.replaceChildren();
  for (const type of service.credential_types) { const option = document.createElement('option'); option.value = type; option.textContent = type; types.append(option); }
  const external = service.service_id === 'external-reference';
  const oauth = types.value === 'oauth';
  byId('origin').value = service.origin;
  byId('origin').readOnly = !external;
  byId('secret-field').hidden = external || oauth;
  byId('token').required = !external && !oauth;
  byId('token').value = '';
  const choices = byId('operation-choices'); choices.replaceChildren();
  for (const operation of service.operations) {
    const label = document.createElement('label'); label.className = 'check-label';
    const check = document.createElement('input'); check.type = 'checkbox'; check.value = operation; check.checked = false;
    label.append(check, document.createTextNode(operation)); choices.append(label);
  }
  if (!service.operations.length) choices.textContent = 'No execution permission.';
  byId('service-hint').textContent = external ? 'Reference only: no secret or delegation is imported, and the center cannot execute for this platform.' : service.synthetic ? 'Local synthetic service. Explicitly select each operation to grant.' : 'Fixed production HTTPS service. Use only an authorized credential; provider setup and upstream scope must also permit each operation.';
  credentialTypeChanged();
}
function renderServices() {
  const select = byId('service'); select.replaceChildren();
  for (const service of services) { const option = document.createElement('option'); option.value = service.service_id; option.textContent = service.service_id; select.append(option); }
  serviceChanged();
}
function button(text, handler) {
  const element = document.createElement('button'); element.type = 'button'; element.className = 'secondary'; element.textContent = text;
  element.addEventListener('click', async () => {
    element.disabled = true;
    try { await handler(); } catch (error) { message(error.message); }
    finally { element.disabled = false; }
  });
  return element;
}
async function refreshProviders() {
  const generation = sessionGeneration;
  try {
    const { providers } = await api('/management/oauth/providers');
    if (generation !== sessionGeneration || managementState !== 'S2') return;
    oauthProviders = providers;
    const list = byId('oauth-providers'); list.replaceChildren();
    byId('oauth-provider-status').textContent = providers.length ? '' : 'No OAuth providers are configured.';
    for (const provider of providers) {
      const row = document.createElement('li'); row.dataset.provider = provider.provider; const content = document.createElement('div'); content.className = 'provider-content';
      const title = document.createElement('strong'); title.textContent = `${providerName(provider.provider)}${provider.synthetic ? ' · local synthetic provider' : ''}`;
      const status = document.createElement('p'); status.textContent = `${provider.enabled ? 'Enabled' : 'Disabled'}${provider.reason ? ` · ${provider.reason}` : ''}`;
      const fields = detailsList({ 'Exact redirect URI': provider.redirect_uri, 'Fixed minimum scopes': oauthMinimumScopes(provider.provider).join(' '), 'Client version': provider.version ?? 0 });
      content.append(title, status, fields);
      if (!provider.synthetic) {
        const instructions = document.createElement('p');
        instructions.append(document.createTextNode(provider.provider === 'github' ? 'Manually create a GitHub OAuth App and set its Authorization callback URL to the exact redirect URI above. ' : 'Manually create a Google OAuth web application client, configure its consent screen and add the exact redirect URI above to Authorized redirect URIs. '));
        const docs = document.createElement('a'); docs.textContent = `${providerName(provider.provider)} application registration instructions`;
        docs.href = provider.provider === 'github' ? 'https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app' : 'https://developers.google.com/identity/protocols/oauth2/web-server#creatingcred';
        docs.target = '_blank'; docs.rel = 'noopener noreferrer'; instructions.append(docs); content.append(instructions);
      }
      const form = document.createElement('form'); form.autocomplete = 'off';
      const idLabel = document.createElement('label'); idLabel.textContent = 'Client ID';
      const clientId = document.createElement('input'); clientId.id = `oauth-${provider.provider}-client-id`; clientId.name = 'clientId'; clientId.value = provider.client_id || ''; clientId.required = true; clientId.maxLength = 1024; clientId.autocomplete = 'off'; clientId.spellcheck = false; idLabel.append(clientId);
      const secretLabel = document.createElement('label'); secretLabel.textContent = 'Client secret';
      const secret = document.createElement('input'); secret.id = `oauth-${provider.provider}-client-secret`; secret.name = 'clientSecret'; secret.type = 'password'; secret.required = true; secret.maxLength = 16384; secret.autocomplete = 'new-password'; secret.spellcheck = false; secretLabel.append(secret);
      const hint = document.createElement('p'); hint.className = 'hint'; hint.textContent = 'Enter the secret to save or replace this client. It is cleared immediately on submission and is never displayed or read back.';
      const submit = document.createElement('button'); submit.type = 'submit'; submit.textContent = provider.version ? 'Replace provider client' : 'Save provider client';
      const result = document.createElement('p'); result.setAttribute('role', 'status');
      form.append(idLabel, secretLabel, hint, submit, result);
      form.addEventListener('submit', async event => {
        event.preventDefault();
        const payload = { provider: provider.provider, clientId: clientId.value, clientSecret: secret.value, expectedVersion: provider.version ?? 0 };
        secret.value = ''; submit.disabled = true;
        try {
          await api('/management/oauth/client', 'POST', payload);
          if (generation !== sessionGeneration || managementState !== 'S2') return;
          await refresh(); message(`${providerName(provider.provider)} client saved. Authorize each OAuth connection separately.`);
        } catch (error) { result.textContent = error.message; }
        finally { payload.clientSecret = ''; submit.disabled = false; }
      });
      content.append(form); row.append(content); list.append(row);
    }
  } catch (error) {
    if (generation === sessionGeneration && managementState === 'S2') {
      oauthProviders = []; byId('oauth-providers').replaceChildren();
      byId('oauth-provider-status').textContent = `Provider setup unavailable: ${error.message}`;
    }
    throw error;
  }
}
function approvedAuthorizationUrl(value, provider) {
  const url = new URL(value);
  const production = provider.provider === 'github' ? ['https://github.com', '/login/oauth/authorize'] : ['https://accounts.google.com', '/o/oauth2/v2/auth'];
  const permitted = provider.synthetic
    ? url.protocol === 'http:' && url.hostname === '127.0.0.1' && ['/authorize', `/${provider.provider}/authorize`].includes(url.pathname)
    : url.origin === production[0] && url.pathname === production[1];
  if (!permitted || url.username || url.password || url.hash) throw new Error('The provider returned an unsupported authorization address. Refresh providers and try again.');
  return url;
}
function appendOAuthActions(connection, content) {
  const provider = oauthProviders.find(item => item.provider === connection.service_id);
  const form = document.createElement('form'); form.className = 'oauth-actions';
  const consentLabel = document.createElement('label'); consentLabel.className = 'check-label';
  const consent = document.createElement('input'); consent.type = 'checkbox'; consent.name = 'consent';
  consentLabel.append(consent, document.createTextNode('Explicitly request the provider consent screen, including when recovering offline access.'));
  const hint = document.createElement('p'); hint.className = 'hint';
  hint.textContent = `${providerName(connection.service_id)} · fixed minimum scopes: ${oauthMinimumScopes(connection.service_id).join(' ')}. Authorization requests offline access. Review and approve access at the provider.`;
  const actions = document.createElement('div'); actions.className = 'actions';
  const submit = document.createElement('button'); submit.type = 'submit'; submit.textContent = connection.material_version > 1 ? 'Reauthorize' : 'Authorize';
  submit.disabled = !provider?.enabled || Boolean(connection.material_change_unresolved);
  const revoke = button('Revoke OAuth', async () => {
    if (!window.confirm(`Revoke OAuth access for ${connection.label} (${connection.account_alias})?`)) return;
    await api('/management/oauth/revoke', 'POST', { connectionId: connection.id, expectedRecordVersion: connection.record_version });
    await refresh(); message('OAuth revocation request completed. Review the refreshed connection status.');
  });
  revoke.disabled = !provider?.enabled || Boolean(connection.material_change_unresolved);
  actions.append(submit, revoke);
  const result = document.createElement('div'); result.setAttribute('role', 'status');
  if (!provider?.enabled) {
    const unavailable = document.createElement('p'); unavailable.className = 'hint'; unavailable.textContent = `Authorization unavailable: ${provider?.reason || 'refresh providers and configure this provider client below'}.`; form.append(unavailable);
  } else if (connection.material_change_unresolved) {
    const unresolved = document.createElement('p'); unresolved.className = 'hint'; unresolved.textContent = 'Reconcile the uncertain OAuth material before authorizing or revoking.'; form.append(unresolved);
  }
  form.append(hint, consentLabel, actions, result);
  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (submit.disabled || !provider?.enabled) return;
    const generation = sessionGeneration;
    result.replaceChildren(); submit.disabled = true; revoke.disabled = true;
    try {
      const data = await api('/management/oauth/authorize', 'POST', { connectionId: connection.id, expectedRecordVersion: connection.record_version, offline: true, consent: consent.checked });
      if (generation !== sessionGeneration || managementState !== 'S2') return;
      const url = approvedAuthorizationUrl(data.authorizationUrl, provider);
      const expiry = new Date(data.expiresAt).getTime();
      if (!Number.isFinite(expiry) || expiry <= Date.now()) throw new Error('Authorization has expired. Request a new link.');
      const explanation = document.createElement('p'); explanation.textContent = `Ready for ${connection.label} · ${connection.account_alias}. Expires ${formatExpiry(data.expiresAt)}. Click the link to continue; this page will leave for ${url.origin}${url.pathname}.`;
      const link = document.createElement('a'); link.href = url.href; link.rel = 'noreferrer'; link.textContent = `Continue to ${providerName(connection.service_id)}${provider.synthetic ? ' simulator' : ''}`;
      link.addEventListener('click', event => {
        if (managementState !== 'S2' || generation !== sessionGeneration || Date.now() >= expiry) {
          event.preventDefault(); result.textContent = 'Authorization expired or the management session changed. Request a new link.';
        }
      });
      result.append(explanation, link);
      message('Authorization prepared. Click the provider link to continue.');
    } catch (error) { result.textContent = error.message; }
    finally { submit.disabled = !provider?.enabled || Boolean(connection.material_change_unresolved); revoke.disabled = submit.disabled; }
  });
  content.append(form);
}
async function refreshApprovals() {
  const generation = sessionGeneration;
  byId('refresh-approvals-button').disabled = true;
  try {
    const { pending: requests } = await api('/management/browser/pending');
    if (generation !== sessionGeneration || managementState !== 'S2') return;
    const list = byId('browser-approvals'); list.replaceChildren();
    byId('browser-approval-status').textContent = requests.length ? 'Requests shown as of this refresh. Approval is checked again by the server.' : 'No pending browser approvals.';
    for (const request of requests) {
      const row = document.createElement('li'); row.dataset.pendingId = request.pending_id; row.dataset.operation = request.operation; const content = document.createElement('div');
      const title = document.createElement('strong'); title.textContent = request.operation === 'login_submit' ? 'Submit login form · separate approval' : request.operation === 'browser_fill' ? 'Fill login fields · no submission' : request.operation;
      const status = request.status ?? request.state;
      const fields = detailsList({ 'Authenticated requesting principal': request.principal_id, 'Fixed site': request.site_id, 'Exact origin': request.origin, ...(request.browser_session_id ? { 'Controlled browser session': request.browser_session_id } : {}), 'Connection record': request.connection_id, ...(request.label ? { Label: request.label } : {}), ...(request.account_alias ? { 'Account alias': request.account_alias } : {}), 'Action': request.operation, 'Expected record version': request.expected_record_version, 'Expires': formatExpiry(request.expires_at), ...(status ? { Status: status } : {}) });
      const approve = button(request.operation === 'login_submit' ? 'Approve login submit once' : 'Approve fill once', async () => {
        if (request.operation === 'login_submit' && !window.confirm(`Approve submitting the login form for ${request.label || request.connection_id} at ${request.origin}, requested by ${request.principal_id}? This is separate from filling fields.`)) return;
        await api(`/management/browser/approvals/${encodeURIComponent(request.pending_id)}`, 'POST', {});
        await refreshApprovals(); message('Browser action approved once. The authenticated executor can use it before expiry.');
      });
      const expiry = new Date(request.expires_at).getTime();
      approve.disabled = !['browser_fill', 'login_submit'].includes(request.operation) || !Number.isFinite(expiry) || expiry <= Date.now() || Boolean(status && status !== 'pending');
      content.append(title, fields, approve); row.append(content); list.append(row);
    }
  } catch (error) {
    if (generation === sessionGeneration && managementState === 'S2') {
      byId('browser-approvals').replaceChildren(); byId('browser-approval-status').textContent = `Browser approvals unavailable: ${error.message}`;
    }
    throw error;
  } finally { byId('refresh-approvals-button').disabled = false; }
}
async function refresh() {
  const generation = sessionGeneration;
  const data = await api('/management/connections');
  if (generation !== sessionGeneration || managementState !== 'S2') return;
  services = data.services;
  byId('browser-support-status').textContent = data.browser ? data.browser.supported ? 'Controlled browser host enabled. Only configured fixed sites can be approved.' : `Browser actions unavailable: ${data.browser.reason || 'unsupported; no controlled host configured'}.` : '';
  try { await refreshProviders(); } catch { /* Provider availability is reported in its own panel. */ }
  if (generation !== sessionGeneration || managementState !== 'S2') return;
  if (!byId('service').options.length) renderServices();
  const list = byId('credentials'); list.replaceChildren();
  if (!data.connections.length) { const empty = document.createElement('li'); empty.textContent = 'No connections yet.'; list.append(empty); }
  for (const connection of data.connections) {
    const row = document.createElement('li'); row.dataset.connectionId = connection.id;
    const text = document.createElement('div'); const label = document.createElement('strong'); label.textContent = connection.label;
    const detail = document.createElement('small'); detail.textContent = `${connection.service_id} · ${connection.account_alias} · ${connection.status} · record ${connection.record_version} / status ${connection.status_version}`;
    const scope = document.createElement('small'); scope.textContent = `${connection.origin} · ${connection.granted_operations.join(', ') || 'No operations'}${connection.can_execute ? '' : ' · cannot execute'}`;
    text.append(label, detail, scope);
    if (connection.credential_type === 'oauth') appendOAuthActions(connection, text);
    const actions = document.createElement('div'); actions.className = 'actions';
    actions.append(button('Replace', () => {
      resetEditor(); editing = connection;
      byId('service').value = connection.service_id; serviceChanged();
      byId('credential-type').value = connection.credential_type;
      credentialTypeChanged();
      byId('label').value = connection.label; byId('account-alias').value = connection.account_alias; byId('origin').value = connection.origin;
      for (const check of byId('operation-choices').querySelectorAll('input')) check.checked = connection.granted_operations.includes(check.value);
      byId('editor-title').textContent = 'Replace a connection'; byId('save-button').textContent = 'Review replacement'; byId('cancel-button').hidden = false;
      byId('token').focus();
    }));
    actions.append(button(connection.status === 'active' ? 'Pause' : 'Activate', async () => {
      await api(`/management/connections/${connection.id}/status`, 'PATCH', { status: connection.status === 'active' ? 'paused' : 'active', expected_status_version: connection.status_version });
      await refresh(); message('Connection status updated.');
    }));
    if (connection.credential_type === 'oauth' && connection.material_change_unresolved) actions.append(button('Reconcile OAuth material', async () => {
      const evidence = window.prompt('Enter a nonsecret evidence reference for the uncertain OAuth authorization or refresh. Continuing abandons old token material and requires fresh provider authorization.');
      if (!evidence || !window.confirm('Abandon all old OAuth token material for this connection and require fresh authorization?')) return;
      await api(`/management/connections/${connection.id}/reconcile-material`, 'POST', { expected_record_version: connection.record_version, expected_status_version: connection.status_version, expected_material_version: connection.material_version, evidence_note: evidence, abandon_old_material: true });
      await refresh(); message('Uncertain OAuth material abandoned. Authorize this connection through the provider again.');
    }));
    actions.append(button('Purge retained copies', async () => {
      if (!window.confirm('Purge retained request comparison copies and results for this connection? Future retries return result_unavailable. Existing backups are not removed.')) return;
      await api(`/management/connections/${connection.id}/purge-retained`, 'POST', {});
      message('Retained request comparison copies purged. Request tombstones prevent re-execution. Existing backups must be managed separately.');
    }));
    actions.append(button('Delete', async () => {
      await api(`/management/connections/${connection.id}`, 'DELETE', { expected_record_version: connection.record_version });
      if (editing?.id === connection.id) resetEditor();
      await refresh(); message('Connection deleted locally. Revoke the token at its service separately. Encrypted request comparison copies may remain for up to 7 days.');
    }));
    row.append(text, actions); list.append(row);
  }
  await refreshOperations();
  await refreshAudit();
}
async function refreshAudit() {
  const data = await api('/management/audit');
  const list = byId('audit-events'); list.replaceChildren();
  if (!data.events.length) { const empty = document.createElement('li'); empty.textContent = 'No audit events yet.'; list.append(empty); }
  for (const event of data.events) {
    const row = document.createElement('li');
    row.textContent = `${new Date(event.time).toLocaleString()} · ${event.principal_id} · ${event.action} · record ${event.record_id || '—'} · record version ${event.record_version ?? '—'} / status version ${event.status_version ?? '—'}`;
    list.append(row);
  }
}
async function refreshOperations() {
  const data = await api('/management/operations');
  const list = byId('operations'); list.replaceChildren();
  if (!data.operations.length) { const empty = document.createElement('li'); empty.textContent = 'No operations recorded.'; list.append(empty); }
  for (const operation of data.operations) {
    const row = document.createElement('li');
    const content = document.createElement('div');
    const title = document.createElement('strong'); title.textContent = `${operation.operation_id} · ${operation.state}`;
    const detail = document.createElement('small'); detail.textContent = `${operation.connection_id} · request ${operation.request_id.slice(0, 16)}… · status version ${operation.operation_status_version}`;
    content.append(title, detail);
    if (operation.state === 'outcome_unknown') {
      const warning = document.createElement('p'); warning.textContent = 'Possibly executed. Review upstream evidence before reconciling or attempting again.'; content.append(warning);
      const form = document.createElement('form');
      const evidenceLabel = document.createElement('label'); evidenceLabel.textContent = 'Nonsecret evidence reference';
      const evidence = document.createElement('input'); evidence.required = true; evidence.maxLength = 500; evidence.autocomplete = 'off'; evidenceLabel.append(evidence);
      const resolutionLabel = document.createElement('label'); resolutionLabel.textContent = 'Finding';
      const resolution = document.createElement('select');
      for (const [value, text] of [['confirmed_succeeded', 'Evidence confirms success'], ['confirmed_failed', 'Evidence confirms failure'], ['authorize_new_attempt', 'Authorize a new attempt despite unknown outcome']]) { const option = document.createElement('option'); option.value = value; option.textContent = text; resolution.append(option); }
      resolutionLabel.append(resolution);
      const riskLabel = document.createElement('label'); riskLabel.className = 'check-label'; const risk = document.createElement('input'); risk.type = 'checkbox'; riskLabel.append(risk, document.createTextNode('I accept the risk of duplicate effects if I authorize a new attempt.'));
      const submit = document.createElement('button'); submit.type = 'submit'; submit.textContent = 'Record reconciliation';
      form.append(evidenceLabel, resolutionLabel, riskLabel, submit);
      form.addEventListener('submit', async event => {
        event.preventDefault(); submit.disabled = true;
        try {
          await api('/management/operations/reconcile', 'POST', { request_id: operation.request_id, operation_name: operation.operation_id, principal_id: operation.principal_id, expected_operation_status_version: operation.operation_status_version, resolution: resolution.value, evidence_note: evidence.value, accept_duplicate_risk: risk.checked });
          await refreshOperations(); message('Reconciliation recorded. No request was dispatched.');
        } catch (error) { message(error.message); } finally { submit.disabled = false; }
      });
      content.append(form);
    }
    row.append(content); list.append(row);
  }
}
async function session() {
  // Direct fetch avoids recursively recovering an expired session.
  const response = await fetch('/management/session', { credentials: 'same-origin' });
  if (!response.ok) throw new Error('Session unavailable');
  const data = await response.json(); showState(data);
  if (data.state === 'S2') await refresh();
}
async function authenticate(event, kind) {
  event.preventDefault();
  const field = byId(kind === 'login' ? 'login-passphrase' : 'passphrase');
  let passphrase = field.value; field.value = '';
  try { const data = await api(`/management/${kind}`, 'POST', { passphrase }); showState(data); if (data.state === 'S2') await refresh(); message(kind === 'login' ? 'Signed in. Unlock the vault to manage connections.' : 'Vault unlocked.'); }
  catch (error) { message(error.message); }
  finally { passphrase = ''; }
}
byId('login-form').addEventListener('submit', event => authenticate(event, 'login'));
byId('unlock-form').addEventListener('submit', event => authenticate(event, 'unlock'));
byId('service').addEventListener('change', serviceChanged);
function credentialTypeChanged() {
  const oauth = byId('credential-type').value === 'oauth';
  byId('secret-field').hidden = oauth || byId('credential-type').value === 'external_reference';
  byId('token').required = !byId('secret-field').hidden;
  byId('token').value = '';
  if (oauth) byId('service-hint').textContent = `Approve the fixed profile operation and minimum scopes (${oauthMinimumScopes(byId('service').value).join(' ')}) here. Review and save creates a pending OAuth connection. Then choose Authorize for that connection and approve access at the provider.`;
}
byId('credential-type').addEventListener('change', credentialTypeChanged);
byId('credential-form').addEventListener('submit', async event => {
  event.preventDefault();
  const payload = {
    mode: editing ? 'replace' : 'create', label: byId('label').value, service_id: byId('service').value,
    credential_type: byId('credential-type').value, account_alias: byId('account-alias').value,
    secret: byId('credential-type').value === 'oauth' ? JSON.stringify({ schema: 1, provider: byId('service').value, approvedScopes: oauthMinimumScopes(byId('service').value) }) : byId('token').value,
    origin: byId('origin').value, environment: 'local', granted_operations: Array.from(byId('operation-choices').querySelectorAll('input:checked'), check => check.value),
    ...(editing ? { target_record_id: editing.id, expected_record_version: editing.record_version } : {}),
  };
  byId('token').value = '';
  try {
    const data = await api('/management/drafts', 'POST', payload); pending = data;
    const details = byId('draft-details'); details.replaceChildren();
    const card = data.draft;
    const fields = { Action: card.mode, Label: card.label, Service: card.service_id, Type: card.credential_type, Account: card.account_alias, Origin: card.origin, Environment: card.environment, Operations: card.granted_operations.join(', ') || 'None', ...(card.credential_type === 'oauth' ? { 'Fixed minimum OAuth scopes': oauthMinimumScopes(card.service_id).join(' '), 'Next step': 'Authorize this connection at the provider after saving.' } : {}), ...(card.target_record_id ? { 'Target record': card.target_record_id, 'Expected record version': card.expected_record_version } : {}) };
    for (const [name, value] of Object.entries(fields)) { const term = document.createElement('dt'); term.textContent = name; const description = document.createElement('dd'); description.textContent = String(value); details.append(term, description); }
    byId('draft-expiry').textContent = `Draft expires ${new Date(card.expires_at).toLocaleTimeString()}. Saving requires this confirmation.`;
    byId('editor-panel').hidden = true; byId('confirmation-panel').hidden = false; message('Draft ready. Review and confirm to save.');
  } catch (error) { message(error.message); }
  finally { payload.secret = ''; }
});
byId('confirm-button').addEventListener('click', async () => {
  if (!pending) return;
  const current = pending; byId('confirm-button').disabled = true;
  rememberSaveRequest(current.request_id);
  try {
    await api(`/management/drafts/${current.draft.draft_id}/confirm`, 'POST', { draft_version: current.draft.draft_version, request_id: current.request_id });
    resetEditor(); await refresh(); message('Connection saved after confirmation. Secret hidden.');
  } catch (error) { message(error.message); }
  finally { byId('confirm-button').disabled = false; }
});
byId('cancel-draft-button').addEventListener('click', async () => {
  try { if (pending) await api(`/management/drafts/${pending.draft.draft_id}`, 'DELETE', {}); resetEditor(); message('Draft cancelled. Nothing saved.'); }
  catch (error) { message(error.message); }
});
byId('save-recovery-form').addEventListener('submit', async event => {
  event.preventDefault();
  const requestId = byId('save-request-id').value.trim();
  try {
    const { connection } = await api('/management/save-result', 'POST', { request_id: requestId });
    rememberSaveRequest(requestId);
    byId('save-recovery-result').textContent = `Save completed: ${connection.label} · ${connection.id} · saved record version ${connection.record_version}. No new save was performed.`;
    await refresh();
  } catch (error) { byId('save-recovery-result').textContent = error.message; }
});
byId('refresh-operations-button').addEventListener('click', () => refreshOperations().catch(error => message(error.message)));
byId('cancel-button').addEventListener('click', resetEditor);
byId('lock-button').addEventListener('click', async () => {
  try { showState(await api('/management/lock', 'POST', {})); message('Vault locked. You remain signed in.'); }
  catch (error) { message(error.message); }
});
async function logout() {
  try { await api('/management/logout', 'POST', {}); await session(); message('Signed out. Vault locked.'); }
  catch (error) { message(error.message); }
}
byId('logout-button').addEventListener('click', logout); byId('locked-logout-button').addEventListener('click', logout);
byId('refresh-approvals-button').addEventListener('click', () => refreshApprovals().catch(error => message(error.message)));
byId('refresh-providers-button').addEventListener('click', async () => {
  const control = byId('refresh-providers-button'); control.disabled = true;
  try { await refresh(); message('Provider clients and connection statuses refreshed.'); }
  catch (error) { message(error.message); }
  finally { control.disabled = false; }
});
function consumeOAuthReturn() {
  const url = new URL(window.location.href);
  const complete = url.searchParams.get('oauth') === 'complete' || url.hash === '#oauth=complete';
  if (url.searchParams.has('oauth')) url.searchParams.delete('oauth');
  if (url.hash === '#oauth=complete') url.hash = '';
  if (complete) window.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
  return complete;
}
const oauthReturned = consumeOAuthReturn();
// No background session polling: it would incorrectly keep the management session alive.
session().then(() => {
  if (oauthReturned) message(managementState === 'S2' ? 'Returned from OAuth authorization. Review the refreshed connection status.' : managementState === 'S1' ? 'Returned from OAuth authorization. Unlock the vault to review the connection status.' : 'Returned from OAuth authorization. Sign in and unlock to review the connection status.');
}).catch(error => message(error.message));
