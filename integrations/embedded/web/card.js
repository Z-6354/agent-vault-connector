'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const endpoint = new URL(location.href);
  endpoint.searchParams.delete('format');
  let request = null;
  let busy = false;
  let finished = false;
  let deadline = 0;
  let countdownTimer = null;
  function controls() {
    $('secret').disabled = !request || busy || finished;
    $('submit').disabled = !request || busy || finished;
    $('cancel').disabled = !request || busy || finished;
    $('close').disabled = busy || finished;
  }
  function setNotice(text, kind) {
    const el = $('notice');
    el.textContent = text;
    el.className = kind || '';
  }
  function terminal(result) {
    if (!['captured', 'declined', 'expired'].includes(result.status)) return false;
    finished = true;
    if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }
    $('secret').value = '';
    controls();
    setNotice(result.status === 'captured' ? '已安全存入。' : result.status === 'expired' ? '本次输入已过期。' : '本次输入已结束。', result.status === 'captured' ? 'ok' : 'err');
    // Only allowlisted completion metadata leaves the isolated frame. No input value.
    const safe = { type: 'vault-input-result', request_id: request.request_id, status: result.status };
    if (result.status === 'captured' && typeof result.ref === 'string') safe.ref = result.ref;
    parent.postMessage(safe, '*');
    return true;
  }
  async function finish(cancel) {
    if (!request || busy || finished) return;
    busy = true;
    const body = cancel ? {declined: true} : {secret: $('secret').value};
    $('secret').value = '';
    controls();
    try {
      const response = await fetch(endpoint, {method: 'POST', credentials: 'omit', redirect: 'error',
        headers: {'Content-Type': 'text/plain'}, body: JSON.stringify(body)});
      const result = await response.json();
      if (!response.ok || !terminal(result)) throw Error('unconfirmed');
    } catch {
      setNotice('保存未确认，请先检查记录再重试。', 'err');
    } finally { body.secret = ''; busy = false; controls(); }
  }
  $('submit').addEventListener('click', () => {if ($('secret').value) finish(false);});
  $('secret').addEventListener('keydown', event => {if (event.key === 'Enter') {event.preventDefault();if ($('secret').value) finish(false);}});
  $('cancel').addEventListener('click', () => finish(true));
  $('close').addEventListener('click', () => finish(true));
  document.addEventListener('keydown', event => {if (event.key === 'Escape') {event.preventDefault();finish(true);}});
  window.addEventListener('pagehide', () => {$('secret').value = '';});
  async function start() {
    try {
      const metadata = new URL(endpoint);metadata.searchParams.set('format', 'json');
      const response = await fetch(metadata, {credentials: 'omit', redirect: 'error'});
      const value = await response.json();
      if (!response.ok || typeof value.request_id !== 'string') throw Error('unavailable');
      request = {request_id: value.request_id};
      $('title').textContent = `${value.service} / ${value.account}`;
      $('prompt').textContent = value.prompt;
      if (typeof value.timeout_s === 'number' && value.timeout_s > 0) {
        deadline = Date.now() + value.timeout_s * 1000;
        countdownTimer = setInterval(() => {
          const left = Math.ceil((deadline - Date.now()) / 1000);
          if (left > 0 && !finished) setNotice('剩余 ' + left + ' 秒');
          if (left <= 0 && !finished) terminal({status: 'expired'});
        }, 1000);
      }
      if (!terminal(value)) {controls();$('secret').focus();$('secret').select();}
    } catch {setNotice('安全输入暂不可用，请重新发起请求。', 'err');}
  }
  controls();start();
})();
