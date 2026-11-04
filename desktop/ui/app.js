"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const native = window.__TAURI__;
  let current = null;
  let busy = false;
  const queue = [];
  const invoke = (command, args) => native.core.invoke(command, args);
  function controls() {
    $('secure-input-secret').disabled = !current || busy;
    $('authorize').disabled = !current || busy;
    $('decline-secure-input').disabled = !current || busy;
    $('close-secure-input').disabled = busy;
  }
  function next() {
    current = queue.shift() || null;
    $('secure-input-secret').value = '';
    $('secure-input-notice').textContent = '';
    $('secure-input-title').textContent = current ? `${current.service} / ${current.account}` : 'Agent Vault';
    $('secure-input-detail').textContent = current?.prompt || '等待安全输入请求';
    controls();
    if (current) { $('secure-input-secret').focus(); $('secure-input-secret').select(); }
  }
  async function finish(cancel) {
    if (!current || busy) return;
    busy = true; controls();
    const args = {requestId: current.request_id};
    if (!cancel) args.secret = $('secure-input-secret').value;
    $('secure-input-secret').value = '';
    try {
      const result = await invoke(cancel ? 'decline_secure_input' : 'submit_secure_input', args);
      if (result?.status !== (cancel ? 'declined' : 'submitted')) throw Error('unconfirmed');
      current = null;
      next();
    } catch {
      $('secure-input-notice').textContent = '请求未完成或已过期，请重试。';
    } finally { args.secret = ''; busy = false; controls(); }
  }
  $('secure-input-form').addEventListener('submit', event => {event.preventDefault(); finish(false);});
  $('decline-secure-input').addEventListener('click', () => finish(true));
  $('close-secure-input').addEventListener('click', () => finish(true));
  document.addEventListener('keydown', event => {if (event.key === 'Escape') {event.preventDefault(); finish(true);}});
  window.addEventListener('pagehide', () => { $('secure-input-secret').value = ''; });
  controls();
  native?.event?.listen('secure-input', event => {
    const request = event.payload;
    if (!request?.request_id) return;
    queue.push(request);
    if (!current) next();
  }).then(async () => {
    document.documentElement.dataset.ready = 'true';
    await invoke('secure_card_ready', {});
  });
})();
