/* Trusted host-side adapter. Load in a host renderer, never in an agent-generated page.
 * Frame capabilities come from the host's native/preload broker client, never an LLM URL.
 */
export function mountSecureInput(container, request, {presentation = 'inline', onResult = () => {}} = {}) {
  if (!(container instanceof Element)) throw new TypeError('A host-owned mount element is required');
  if (!['inline', 'overlay', 'anchored'].includes(presentation)) throw new TypeError('Unknown presentation');
  if (!request || typeof request.request_id !== 'string') throw new TypeError('Missing request metadata');
  const url = new URL(request.frame_url);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.username || url.password ||
      url.pathname !== `/card/${encodeURIComponent(request.request_id)}` || !url.searchParams.get('key')) {
    throw new TypeError('Only a request-scoped loopback card can be mounted');
  }
  if (url.origin === location.origin) throw new TypeError('Input frame must be isolated from the host origin');
  const frame = document.createElement('iframe');
  frame.title = '安全凭据输入';
  frame.setAttribute('sandbox', 'allow-scripts');
  frame.referrerPolicy = 'no-referrer';
  frame.src = url.href;
  frame.width = '400';frame.height = '260';
  Object.assign(frame.style, {border: '0', borderRadius: '12px', display: 'block', width: 'min(400px, 100%)', height: '260px'});
  let modal = null;
  let disposed = false;
  const previousFocus = document.activeElement;
  function dispose() {
    if (disposed) return;
    disposed = true;window.removeEventListener('message', message);
    frame.src = 'about:blank';
    if (modal) {modal.close();modal.remove();} else frame.remove();
    if (previousFocus instanceof HTMLElement) previousFocus.focus();
  }
  function message(event) {
    // Sandboxed card has an opaque origin. Source and request ID bind the response.
    if (event.source !== frame.contentWindow || event.origin !== 'null') return;
    const value = event.data;
    if (!value || value.type !== 'vault-input-result' || value.request_id !== request.request_id ||
        !['captured', 'declined', 'expired'].includes(value.status)) return;
    const safe = {request_id: request.request_id, status: value.status};
    if (value.status === 'captured') {
      if (typeof value.ref !== 'string' || !value.ref.startsWith('vault://')) return;
      safe.ref = value.ref;
    }
    dispose();onResult(safe);
  }
  window.addEventListener('message', message);
  if (presentation === 'overlay') {
    modal = document.createElement('dialog');
    modal.setAttribute('aria-label', '安全凭据输入');
    Object.assign(modal.style, {border: '0', padding: '0', borderRadius: '12px', background: '#161a16', overflow: 'hidden', width: '400px', maxWidth: 'calc(100vw - 24px)'});
    // Cancellation must be handled inside the card; destroying a pending frame doesn't imply declined.
    modal.addEventListener('cancel', event => {event.preventDefault();frame.focus();});
    modal.append(frame);container.append(modal);modal.showModal();
  } else {
    // `anchored`: the host positions this container next to a field it owns.
    // Do not inject untrusted page scripts into the secure frame.
    container.append(frame);
  }
  return Object.freeze({dispose});
}
