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
// Presentation only: protocol values and form values remain unchanged.
const labels = {
  github: 'GitHub', google: 'Google', 'external-reference': '外部引用',
  'synthetic-mock': '本地模拟账号', 'synthetic-login': '本地模拟登录站点',
  'mock.account_summary': '读取模拟账号摘要', 'github.current_user': '读取 GitHub 当前用户资料', 'google.userinfo': '读取 Google 用户资料',
  api_key: 'API 密钥', password: '密码', oauth: 'OAuth 授权', external_reference: '外部引用', delegation: '委托凭据',
  active: '已启用', paused: '已暂停', pending: '待处理', expired: '已过期', revoked: '已撤销',
  needs_user_action: '需要您处理', unknown: '状态未知', error: '发生错误',
  pending_authorization: '待授权', reauthorization_required: '需要重新授权',
  accepted: '已受理', dispatching: '正在发送', succeeded: '执行成功', failed_before_dispatch: '发送前失败', failed_confirmed: '已确认执行失败', outcome_unknown: '执行结果未知',
  confirmed_succeeded: '已确认成功', confirmed_failed: '已确认失败', authorize_new_attempt: '允许再次尝试',
  browser_fill: '填充登录信息', login_submit: '提交登录表单', approved: '已批准', consumed: '已使用',
  create: '添加', replace: '替换', local: '本地',
  connection_created: '已创建连接', connection_replaced: '已替换连接', connection_deleted: '已删除连接',
  connection_status_changed: '已更新连接状态', vault_unlocked: '已解锁保险库', vault_locked: '已锁定保险库',
};
const displayValue = value => labels[value] || `未识别的类型（${String(value ?? '—')}）`;
const errorLabels = {
  session_required: '请先登录并解锁保险库', unauthorized: '请先登录', forbidden: '没有执行此操作的权限',
  vault_locked: '保险库已锁定，请先解锁', invalid_passphrase: '口令不正确', authentication_failed: '身份验证失败',
  invalid_csrf: '页面验证已失效，请刷新后重试', csrf_invalid: '页面验证已失效，请刷新后重试',
  not_found: '未找到所请求的记录', conflict: '记录已发生变化，请刷新后重试', version_conflict: '记录版本已变化，请刷新后重试',
  invalid_request: '请求无效，请检查输入', invalid_input: '输入无效，请检查后重试', rate_limited: '请求过于频繁，请稍后重试',
  result_unavailable: '保存结果已不可用', oauth_failed: 'OAuth 授权失败', oauth_not_configured: '尚未配置 OAuth 客户端',
  unsupported: '当前环境不支持此功能',
};
function errorText(error) {
  const code = error instanceof Error ? error.message : String(error ?? '');
  if (/[㐀-鿿]/.test(code)) return code;
  return errorLabels[code] ? `${errorLabels[code]}（${code}）` : /^[a-z][a-z0-9_.-]{0,99}$/.test(code) ? `操作未完成（${code}）。请核对状态后重试。` : '操作未完成，请检查网络连接或刷新页面后重试。';
}
const reasonText = reason => errorLabels[reason] ? `${errorLabels[reason]}（${reason}）` : '当前配置或运行环境暂不满足要求，请检查提供方或浏览器配置。';
const formatExpiry = value => {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toLocaleString('zh-CN') : '无法获取';
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
    throw new Error(data.error || '请求失败');
  }
  return data;
}
function resetEditor() {
  editing = undefined; pending = undefined;
  byId('credential-form').reset();
  byId('editor-title').textContent = '添加连接';
  byId('save-button').textContent = '审核连接';
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
    byId('browser-approval-status').textContent = '请刷新以查看请求。此面板不会自动轮询，也不会延长管理会话。';
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
  for (const type of service.credential_types) { const option = document.createElement('option'); option.value = type; option.textContent = displayValue(type); types.append(option); }
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
    label.append(check, document.createTextNode(displayValue(operation))); choices.append(label);
  }
  if (!service.operations.length) choices.textContent = '无执行权限。';
  byId('service-hint').textContent = external ? '仅作引用：不导入机密信息或委托权限，管理中心无法代此平台执行操作。' : service.synthetic ? '本地模拟服务。请逐项勾选要授予的操作权限。' : '预设的生产环境 HTTPS 服务。请仅使用已获授权的凭据；提供方配置与上游权限范围也必须允许相应操作。';
  credentialTypeChanged();
}
function renderServices() {
  const select = byId('service'); select.replaceChildren();
  for (const service of services) { const option = document.createElement('option'); option.value = service.service_id; option.textContent = displayValue(service.service_id); select.append(option); }
  serviceChanged();
}
function button(text, handler) {
  const element = document.createElement('button'); element.type = 'button'; element.className = 'secondary'; element.textContent = text;
  element.addEventListener('click', async () => {
    element.disabled = true;
    try { await handler(); } catch (error) { message(errorText(error)); }
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
    byId('oauth-provider-status').textContent = providers.length ? '' : '尚未配置 OAuth 提供方。';
    for (const provider of providers) {
      const row = document.createElement('li'); row.dataset.provider = provider.provider; const content = document.createElement('div'); content.className = 'provider-content';
      const title = document.createElement('strong'); title.textContent = `${providerName(provider.provider)}${provider.synthetic ? ' · 本地模拟提供方' : ''}`;
      const status = document.createElement('p'); status.textContent = `${provider.enabled ? '已启用' : '已停用'}${provider.reason ? ` · ${reasonText(provider.reason)}` : ''}`;
      const fields = detailsList({ '完整重定向 URI': provider.redirect_uri, '预设最小权限范围': oauthMinimumScopes(provider.provider).join(' '), '客户端版本': provider.version ?? 0 });
      content.append(title, status, fields);
      if (!provider.synthetic) {
        const instructions = document.createElement('p');
        instructions.append(document.createTextNode(provider.provider === 'github' ? '请手动创建 GitHub OAuth 应用，将其授权回调地址设置为上方完整的重定向 URI。 ' : '请手动创建 Google OAuth 网页应用客户端，配置授权同意页面，并将上方完整的重定向 URI 添加到已获授权的重定向 URI 中。 '));
        const docs = document.createElement('a'); docs.textContent = `${providerName(provider.provider)} 应用注册指南`;
        docs.href = provider.provider === 'github' ? 'https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app' : 'https://developers.google.com/identity/protocols/oauth2/web-server#creatingcred';
        docs.target = '_blank'; docs.rel = 'noopener noreferrer'; instructions.append(docs); content.append(instructions);
      }
      const form = document.createElement('form'); form.autocomplete = 'off';
      const idLabel = document.createElement('label'); idLabel.textContent = '客户端 ID';
      const clientId = document.createElement('input'); clientId.id = `oauth-${provider.provider}-client-id`; clientId.name = 'clientId'; clientId.value = provider.client_id || ''; clientId.required = true; clientId.maxLength = 1024; clientId.autocomplete = 'off'; clientId.spellcheck = false; idLabel.append(clientId);
      const secretLabel = document.createElement('label'); secretLabel.textContent = '客户端密钥';
      const secret = document.createElement('input'); secret.id = `oauth-${provider.provider}-client-secret`; secret.name = 'clientSecret'; secret.type = 'password'; secret.required = true; secret.maxLength = 16384; secret.autocomplete = 'new-password'; secret.spellcheck = false; secretLabel.append(secret);
      const hint = document.createElement('p'); hint.className = 'hint'; hint.textContent = '输入密钥以保存或替换此客户端。提交后输入框会立即清空，密钥不会显示，也无法读回。';
      const submit = document.createElement('button'); submit.type = 'submit'; submit.textContent = provider.version ? '替换提供方客户端' : '保存提供方客户端';
      const result = document.createElement('p'); result.setAttribute('role', 'status');
      form.append(idLabel, secretLabel, hint, submit, result);
      form.addEventListener('submit', async event => {
        event.preventDefault();
        const payload = { provider: provider.provider, clientId: clientId.value, clientSecret: secret.value, expectedVersion: provider.version ?? 0 };
        secret.value = ''; submit.disabled = true;
        try {
          await api('/management/oauth/client', 'POST', payload);
          if (generation !== sessionGeneration || managementState !== 'S2') return;
          await refresh(); message(`${providerName(provider.provider)} 客户端已保存。请为每个 OAuth 连接分别授权。`);
        } catch (error) { result.textContent = errorText(error); }
        finally { payload.clientSecret = ''; submit.disabled = false; }
      });
      content.append(form); row.append(content); list.append(row);
    }
  } catch (error) {
    if (generation === sessionGeneration && managementState === 'S2') {
      oauthProviders = []; byId('oauth-providers').replaceChildren();
      byId('oauth-provider-status').textContent = `无法获取提供方配置：${errorText(error)}`;
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
  if (!permitted || url.username || url.password || url.hash) throw new Error('提供方返回了不受支持的授权地址。请刷新提供方后重试。');
  return url;
}
function appendOAuthActions(connection, content) {
  const provider = oauthProviders.find(item => item.provider === connection.service_id);
  const form = document.createElement('form'); form.className = 'oauth-actions';
  const consentLabel = document.createElement('label'); consentLabel.className = 'check-label';
  const consent = document.createElement('input'); consent.type = 'checkbox'; consent.name = 'consent';
  consentLabel.append(consent, document.createTextNode('要求提供方显示授权同意页面（恢复离线访问权限时也适用）。'));
  const hint = document.createElement('p'); hint.className = 'hint';
  hint.textContent = `${providerName(connection.service_id)} · 预设最小权限范围：${oauthMinimumScopes(connection.service_id).join(' ')}。授权将申请离线访问权限，请前往提供方核对并批准。`;
  const actions = document.createElement('div'); actions.className = 'actions';
  const submit = document.createElement('button'); submit.type = 'submit'; submit.textContent = connection.material_version > 1 ? '重新授权' : '授权';
  submit.disabled = !provider?.enabled || Boolean(connection.material_change_unresolved);
  const revoke = button('撤销 OAuth 授权', async () => {
    if (!window.confirm(`确定撤销 ${connection.label}（${connection.account_alias}）的 OAuth 访问权限？`)) return;
    await api('/management/oauth/revoke', 'POST', { connectionId: connection.id, expectedRecordVersion: connection.record_version });
    await refresh(); message('OAuth 撤销请求已完成，请查看刷新后的连接状态。');
  });
  revoke.disabled = !provider?.enabled || Boolean(connection.material_change_unresolved);
  actions.append(submit, revoke);
  const result = document.createElement('div'); result.setAttribute('role', 'status');
  if (!provider?.enabled) {
    const unavailable = document.createElement('p'); unavailable.className = 'hint'; unavailable.textContent = `暂时无法授权：${provider?.reason ? reasonText(provider.reason) : '请刷新提供方，并在下方配置此提供方的客户端'}。`; form.append(unavailable);
  } else if (connection.material_change_unresolved) {
    const unresolved = document.createElement('p'); unresolved.className = 'hint'; unresolved.textContent = '请先核查并处理状态不确定的 OAuth 凭据材料，再授权或撤销。'; form.append(unresolved);
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
      if (!Number.isFinite(expiry) || expiry <= Date.now()) throw new Error('授权已过期，请重新获取链接。');
      const explanation = document.createElement('p'); explanation.textContent = `已为 ${connection.label} · ${connection.account_alias} 准备好授权，有效期至 ${formatExpiry(data.expiresAt)}。点击链接后将离开此页面，前往 ${url.origin}${url.pathname}。`;
      const link = document.createElement('a'); link.href = url.href; link.rel = 'noreferrer'; link.textContent = `前往 ${providerName(connection.service_id)}${provider.synthetic ? ' 模拟器' : ''} 继续授权`;
      link.addEventListener('click', event => {
        if (managementState !== 'S2' || generation !== sessionGeneration || Date.now() >= expiry) {
          event.preventDefault(); result.textContent = '授权已过期或管理会话已变化，请重新获取链接。';
        }
      });
      result.append(explanation, link);
      message('授权已准备就绪，请点击提供方链接继续。');
    } catch (error) { result.textContent = errorText(error); }
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
    byId('browser-approval-status').textContent = requests.length ? '以下为本次刷新时的请求，批准时服务端会再次核验。' : '暂无待审批的浏览器操作。';
    for (const request of requests) {
      const row = document.createElement('li'); row.dataset.pendingId = request.pending_id; row.dataset.operation = request.operation; const content = document.createElement('div');
      const title = document.createElement('strong'); title.textContent = request.operation === 'login_submit' ? '提交登录表单 · 需单独批准' : request.operation === 'browser_fill' ? '填充登录信息 · 不提交表单' : displayValue(request.operation);
      const status = request.status ?? request.state;
      const fields = detailsList({ '已认证的请求主体': request.principal_id, '预设站点': displayValue(request.site_id), '完整来源地址': request.origin, ...(request.browser_session_id ? { '受控浏览器会话': request.browser_session_id } : {}), '连接记录': request.connection_id, ...(request.label ? { '名称': request.label } : {}), ...(request.account_alias ? { '账号别名': request.account_alias } : {}), '操作': displayValue(request.operation), '预期记录版本': request.expected_record_version, '有效期至': formatExpiry(request.expires_at), ...(status ? { '状态': displayValue(status) } : {}) });
      const approve = button(request.operation === 'login_submit' ? '批准提交一次' : '批准填充一次', async () => {
        if (request.operation === 'login_submit' && !window.confirm(`确定批准 ${request.principal_id} 请求的登录表单提交操作？连接：${request.label || request.connection_id}；来源：${request.origin}。此批准独立于填充操作。`)) return;
        await api(`/management/browser/approvals/${encodeURIComponent(request.pending_id)}`, 'POST', {});
        await refreshApprovals(); message('已批准浏览器操作一次，已认证的执行方可在有效期内使用。');
      });
      const expiry = new Date(request.expires_at).getTime();
      approve.disabled = !['browser_fill', 'login_submit'].includes(request.operation) || !Number.isFinite(expiry) || expiry <= Date.now() || Boolean(status && status !== 'pending');
      content.append(title, fields, approve); row.append(content); list.append(row);
    }
  } catch (error) {
    if (generation === sessionGeneration && managementState === 'S2') {
      byId('browser-approvals').replaceChildren(); byId('browser-approval-status').textContent = `无法获取浏览器审批请求：${errorText(error)}`;
    }
    throw error;
  } finally { byId('refresh-approvals-button').disabled = false; }
}
async function refresh() {
  const generation = sessionGeneration;
  const data = await api('/management/connections');
  if (generation !== sessionGeneration || managementState !== 'S2') return;
  services = data.services;
  byId('browser-support-status').textContent = data.browser ? data.browser.supported ? '受控浏览器宿主已启用，仅可批准已配置的预设站点。' : `浏览器操作不可用：${data.browser.reason ? reasonText(data.browser.reason) : '未配置受控浏览器宿主'}。` : '';
  try { await refreshProviders(); } catch { /* Provider availability is reported in its own panel. */ }
  if (generation !== sessionGeneration || managementState !== 'S2') return;
  if (!byId('service').options.length) renderServices();
  const list = byId('credentials'); list.replaceChildren();
  if (!data.connections.length) { const empty = document.createElement('li'); empty.textContent = '尚未添加连接。'; list.append(empty); }
  for (const connection of data.connections) {
    const row = document.createElement('li'); row.dataset.connectionId = connection.id;
    const text = document.createElement('div'); const label = document.createElement('strong'); label.textContent = connection.label;
    const detail = document.createElement('small'); detail.textContent = `${displayValue(connection.service_id)} · ${connection.account_alias} · ${displayValue(connection.status)} · 记录版本 ${connection.record_version} / 状态版本 ${connection.status_version}`;
    const scope = document.createElement('small'); scope.textContent = `${connection.origin} · ${connection.granted_operations.map(displayValue).join('、') || '无操作权限'}${connection.can_execute ? '' : ' · 无法执行'}`;
    text.append(label, detail, scope);
    if (connection.credential_type === 'oauth') appendOAuthActions(connection, text);
    const actions = document.createElement('div'); actions.className = 'actions';
    actions.append(button('替换', () => {
      resetEditor(); editing = connection;
      byId('service').value = connection.service_id; serviceChanged();
      byId('credential-type').value = connection.credential_type;
      credentialTypeChanged();
      byId('label').value = connection.label; byId('account-alias').value = connection.account_alias; byId('origin').value = connection.origin;
      for (const check of byId('operation-choices').querySelectorAll('input')) check.checked = connection.granted_operations.includes(check.value);
      byId('editor-title').textContent = '替换连接'; byId('save-button').textContent = '审核替换内容'; byId('cancel-button').hidden = false;
      byId('token').focus();
    }));
    actions.append(button(connection.status === 'active' ? '暂停' : '启用', async () => {
      await api(`/management/connections/${connection.id}/status`, 'PATCH', { status: connection.status === 'active' ? 'paused' : 'active', expected_status_version: connection.status_version });
      await refresh(); message('连接状态已更新。');
    }));
    if (connection.credential_type === 'oauth' && connection.material_change_unresolved) actions.append(button('核查 OAuth 凭据材料', async () => {
      const evidence = window.prompt('请输入用于核查此次 OAuth 授权或刷新结果的证据引用，请勿包含机密信息。继续后将弃用旧令牌材料，并要求重新向提供方授权。');
      if (!evidence || !window.confirm('确定弃用此连接的全部旧 OAuth 令牌材料，并要求重新授权？')) return;
      await api(`/management/connections/${connection.id}/reconcile-material`, 'POST', { expected_record_version: connection.record_version, expected_status_version: connection.status_version, expected_material_version: connection.material_version, evidence_note: evidence, abandon_old_material: true });
      await refresh(); message('状态不确定的 OAuth 凭据材料已弃用，请重新前往提供方为此连接授权。');
    }));
    actions.append(button('清除保留副本', async () => {
      if (!window.confirm('确定清除此连接保留的请求比对副本和结果？之后重试将返回“结果不可用”（result_unavailable）。现有备份不会被删除。')) return;
      await api(`/management/connections/${connection.id}/purge-retained`, 'POST', {});
      message('保留的请求比对副本已清除，保留的请求标记会阻止重复执行。现有备份需单独管理。');
    }));
    actions.append(button('删除', async () => {
      await api(`/management/connections/${connection.id}`, 'DELETE', { expected_record_version: connection.record_version });
      if (editing?.id === connection.id) resetEditor();
      await refresh(); message('连接已在本地删除，请另行前往对应服务撤销令牌。用于比对请求的加密副本最多仍会保留 7 天。');
    }));
    row.append(text, actions); list.append(row);
  }
  await refreshOperations();
  await refreshAudit();
}
async function refreshAudit() {
  const data = await api('/management/audit');
  const list = byId('audit-events'); list.replaceChildren();
  if (!data.events.length) { const empty = document.createElement('li'); empty.textContent = '暂无审计事件。'; list.append(empty); }
  for (const event of data.events) {
    const row = document.createElement('li');
    row.textContent = `${formatExpiry(event.time)} · ${event.principal_id} · ${displayValue(event.action)} · 记录 ${event.record_id || '—'} · 记录版本 ${event.record_version ?? '—'} / 状态版本 ${event.status_version ?? '—'}`;
    list.append(row);
  }
}
async function refreshOperations() {
  const data = await api('/management/operations');
  const list = byId('operations'); list.replaceChildren();
  if (!data.operations.length) { const empty = document.createElement('li'); empty.textContent = '暂无操作记录。'; list.append(empty); }
  for (const operation of data.operations) {
    const row = document.createElement('li');
    const content = document.createElement('div');
    const title = document.createElement('strong'); title.textContent = `${displayValue(operation.operation_id)} · ${displayValue(operation.state)}`;
    const detail = document.createElement('small'); detail.textContent = `${operation.connection_id} · 请求 ${operation.request_id.slice(0, 16)}… · 状态版本 ${operation.operation_status_version}`;
    content.append(title, detail);
    if (operation.state === 'outcome_unknown') {
      const warning = document.createElement('p'); warning.textContent = '此操作可能已执行。请先核查上游证据，再确认结果或再次尝试。'; content.append(warning);
      const form = document.createElement('form');
      const evidenceLabel = document.createElement('label'); evidenceLabel.textContent = '证据引用（请勿包含机密信息）';
      const evidence = document.createElement('input'); evidence.required = true; evidence.maxLength = 500; evidence.autocomplete = 'off'; evidenceLabel.append(evidence);
      const resolutionLabel = document.createElement('label'); resolutionLabel.textContent = '核查结论';
      const resolution = document.createElement('select');
      for (const [value, text] of [['confirmed_succeeded', '证据确认执行成功'], ['confirmed_failed', '证据确认执行失败'], ['authorize_new_attempt', '结果未知，仍允许再次尝试']]) { const option = document.createElement('option'); option.value = value; option.textContent = text; resolution.append(option); }
      resolutionLabel.append(resolution);
      const riskLabel = document.createElement('label'); riskLabel.className = 'check-label'; const risk = document.createElement('input'); risk.type = 'checkbox'; riskLabel.append(risk, document.createTextNode('允许再次尝试时，我接受可能产生重复效果的风险。'));
      const submit = document.createElement('button'); submit.type = 'submit'; submit.textContent = '记录核查结论';
      form.append(evidenceLabel, resolutionLabel, riskLabel, submit);
      form.addEventListener('submit', async event => {
        event.preventDefault(); submit.disabled = true;
        try {
          await api('/management/operations/reconcile', 'POST', { request_id: operation.request_id, operation_name: operation.operation_id, principal_id: operation.principal_id, expected_operation_status_version: operation.operation_status_version, resolution: resolution.value, evidence_note: evidence.value, accept_duplicate_risk: risk.checked });
          await refreshOperations(); message('核查结论已记录，未发送任何执行请求。');
        } catch (error) { message(errorText(error)); } finally { submit.disabled = false; }
      });
      content.append(form);
    }
    row.append(content); list.append(row);
  }
}
async function session() {
  // Direct fetch avoids recursively recovering an expired session.
  const response = await fetch('/management/session', { credentials: 'same-origin' });
  if (!response.ok) throw new Error('无法获取管理会话，请刷新后重试');
  const data = await response.json(); showState(data);
  if (data.state === 'S2') await refresh();
}
async function authenticate(event, kind) {
  event.preventDefault();
  const field = byId(kind === 'login' ? 'login-passphrase' : 'passphrase');
  let passphrase = field.value; field.value = '';
  try { const data = await api(`/management/${kind}`, 'POST', { passphrase }); showState(data); if (data.state === 'S2') await refresh(); message(kind === 'login' ? '已登录，请解锁保险库以管理连接。' : '保险库已解锁。'); }
  catch (error) { message(errorText(error)); }
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
  if (oauth) byId('service-hint').textContent = `请在此批准预设的个人资料读取操作及最小权限范围（${oauthMinimumScopes(byId('service').value).join(' ')}）。审核并保存后将创建待授权的 OAuth 连接，再为该连接选择“授权”，前往提供方批准访问。`;
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
    const fields = { '操作': displayValue(card.mode), '名称': card.label, '服务': displayValue(card.service_id), '凭据类型': displayValue(card.credential_type), '账号': card.account_alias, '来源地址': card.origin, '环境': displayValue(card.environment), '允许的操作': card.granted_operations.map(displayValue).join('、') || '无', ...(card.credential_type === 'oauth' ? { '预设最小 OAuth 权限范围': oauthMinimumScopes(card.service_id).join(' '), '下一步': '保存后请前往提供方为此连接授权。' } : {}), ...(card.target_record_id ? { '目标记录': card.target_record_id, '预期记录版本': card.expected_record_version } : {}) };
    for (const [name, value] of Object.entries(fields)) { const term = document.createElement('dt'); term.textContent = name; const description = document.createElement('dd'); description.textContent = String(value); details.append(term, description); }
    byId('draft-expiry').textContent = `草稿有效期至 ${formatExpiry(card.expires_at)}。必须在此确认后才能保存。`;
    byId('editor-panel').hidden = true; byId('confirmation-panel').hidden = false; message('草稿已就绪，请核对并确认保存。');
  } catch (error) { message(errorText(error)); }
  finally { payload.secret = ''; }
});
byId('confirm-button').addEventListener('click', async () => {
  if (!pending) return;
  const current = pending; byId('confirm-button').disabled = true;
  rememberSaveRequest(current.request_id);
  try {
    await api(`/management/drafts/${current.draft.draft_id}/confirm`, 'POST', { draft_version: current.draft.draft_version, request_id: current.request_id });
    resetEditor(); await refresh(); message('连接已确认并保存，机密信息不会显示。');
  } catch (error) { message(errorText(error)); }
  finally { byId('confirm-button').disabled = false; }
});
byId('cancel-draft-button').addEventListener('click', async () => {
  try { if (pending) await api(`/management/drafts/${pending.draft.draft_id}`, 'DELETE', {}); resetEditor(); message('草稿已取消，未保存任何内容。'); }
  catch (error) { message(errorText(error)); }
});
byId('save-recovery-form').addEventListener('submit', async event => {
  event.preventDefault();
  const requestId = byId('save-request-id').value.trim();
  try {
    const { connection } = await api('/management/save-result', 'POST', { request_id: requestId });
    rememberSaveRequest(requestId);
    byId('save-recovery-result').textContent = `保存已完成：${connection.label} · ${connection.id} · 已保存的记录版本 ${connection.record_version}。本次查询未执行新的保存。`;
    await refresh();
  } catch (error) { byId('save-recovery-result').textContent = errorText(error); }
});
byId('refresh-operations-button').addEventListener('click', () => refreshOperations().catch(error => message(errorText(error))));
byId('cancel-button').addEventListener('click', resetEditor);
byId('lock-button').addEventListener('click', async () => {
  try { showState(await api('/management/lock', 'POST', {})); message('保险库已锁定，您仍处于登录状态。'); }
  catch (error) { message(errorText(error)); }
});
async function logout() {
  try { await api('/management/logout', 'POST', {}); await session(); message('已退出登录，保险库已锁定。'); }
  catch (error) { message(errorText(error)); }
}
byId('logout-button').addEventListener('click', logout); byId('locked-logout-button').addEventListener('click', logout);
byId('refresh-approvals-button').addEventListener('click', () => refreshApprovals().catch(error => message(errorText(error))));
byId('refresh-providers-button').addEventListener('click', async () => {
  const control = byId('refresh-providers-button'); control.disabled = true;
  try { await refresh(); message('提供方客户端和连接状态已刷新。'); }
  catch (error) { message(errorText(error)); }
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
  if (oauthReturned) message(managementState === 'S2' ? '已从 OAuth 授权页面返回，请查看刷新后的连接状态。' : managementState === 'S1' ? '已从 OAuth 授权页面返回，请解锁保险库以查看连接状态。' : '已从 OAuth 授权页面返回，请登录并解锁保险库以查看连接状态。');
}).catch(error => message(errorText(error)));
