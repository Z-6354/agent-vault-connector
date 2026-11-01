'use strict';
(async () => {
  const callbackUrl = location.href;
  const callbackPath = location.pathname;
  history.replaceState(null, '', callbackPath);
  const status = document.getElementById('oauth-result');
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
    status.textContent = `Authorization was not completed (${code}). Return to management and start a new authorization if needed.`;
  }
})();
