'use strict';
(async () => {
  document.documentElement.lang = 'zh-CN';
  document.title = 'OAuth 授权回调 · 智能体凭据保险库';
  const heading = document.querySelector('h1');
  if (heading) heading.textContent = 'OAuth 授权';
  const callbackUrl = location.href;
  const callbackPath = location.pathname;
  history.replaceState(null, '', callbackPath);
  for (const link of document.querySelectorAll('a[href="/"]')) link.textContent = '返回管理页面';
  const status = document.getElementById('oauth-result');
  status.textContent = '正在完成授权，请稍候…';
  try {
    const sessionResponse = await fetch('/management/session', { credentials: 'same-origin', redirect: 'error' });
    const session = await sessionResponse.json();
    if (!sessionResponse.ok || session.state !== 'S2') throw new Error('session_required');
    const response = await fetch(callbackPath, {
      method: 'POST', credentials: 'same-origin', redirect: 'error',
      headers: { 'content-type': 'application/json', 'x-csrf-token': session.csrf },
      body: JSON.stringify({ callbackUrl }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(typeof data.error === 'string' && /^[a-z][a-z0-9_]{0,79}$/.test(data.error) ? data.error : 'oauth_failed');
    location.replace('/?oauth=complete');
  } catch (error) {
    const code = error instanceof Error && /^[a-z][a-z0-9_]{0,79}$/.test(error.message) ? error.message : 'oauth_failed';
    const reasons = { session_required: '请先登录并解锁保险库', oauth_failed: 'OAuth 授权未完成', oauth_state_invalid: '授权状态无效或已过期', oauth_expired: '授权已过期', access_denied: '授权被拒绝' };
    status.textContent = `${reasons[code] || '授权未完成'}（${code}）。请返回管理页面，必要时重新发起授权。`;
    const link = document.createElement('a'); link.href = '/'; link.textContent = '返回管理页面';
    status.append(document.createTextNode(' '), link);
  }
})();
