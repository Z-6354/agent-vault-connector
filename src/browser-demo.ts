import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { timingSafeEqual } from 'node:crypto';
import type { BrowserSiteRules } from './browser.js';

export interface SyntheticBrowserDemo {
  readonly origin: string;
  readonly rules: BrowserSiteRules;
  readonly frameRules: BrowserSiteRules;
  readonly stats: { submissions: number; authenticated: number; sessionVisits: number };
  setSubmitBehavior(behavior: 'respond' | 'disconnect' | 'commit_then_500'): void;
  close(): Promise<void>;
}
function same(a: string, b: string) {
  const first = Buffer.from(a), second = Buffer.from(b);
  return first.length === second.length && timingSafeEqual(first, second);
}
const form = `<form id="login" action="/session" method="post"><label>Account <input id="username" name="username" autocomplete="off"></label><label>Password <input id="password" name="password" type="password" autocomplete="off"></label><button type="submit">Log in</button></form>`;
/** Local synthetic target only. Secrets stay in memory, request bodies are never retained or logged.
 * Port 0 is intended for tests; use 43122 only for the registered synthetic-login demonstration. */
export async function startSyntheticBrowserDemo(options: { username: string; password: string; port?: number }): Promise<SyntheticBrowserDemo> {
  if (!options.username.startsWith('synthetic_') || !options.password.startsWith('synthetic_')) throw new Error('synthetic_values_required');
  const stats = { submissions: 0, authenticated: 0, sessionVisits: 0 };
  let submitBehavior: 'respond' | 'disconnect' | 'commit_then_500' = 'respond';
  const server = http.createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'none'; connect-src 'none'; form-action 'self'; frame-ancestors 'self'; base-uri 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const html = (body: string, status = 200) => { res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(`<!doctype html><meta charset="utf-8"><title>Synthetic local browser demonstration</title><h1>Synthetic local browser demonstration</h1>${body}`); };
    if (req.method === 'GET' && (req.url === '/login' || req.url === '/next' || req.url === '/frame')) return html(form);
    if (req.method === 'GET' && req.url === '/framed') return html('<iframe name="login-frame" src="/frame" title="Synthetic login"></iframe>');
    if (req.method === 'POST' && req.url === '/session') {
      stats.submissions++;
      let body = '';
      try {
        for await (const part of req) { body += part.toString(); if (Buffer.byteLength(body) > 4096) { res.writeHead(413); res.end(); return; } }
        const fields = new URLSearchParams(body);
        const valid = same(fields.get('username') ?? '', options.username) && same(fields.get('password') ?? '', options.password);
        body = '';
        if (valid) stats.authenticated++;
        if (submitBehavior === 'disconnect') { req.socket.destroy(); return; }
        if (!valid) return html('<p>Rejected synthetic login.</p>', 401);
        res.setHeader('Set-Cookie', 'synthetic_demo_session=authenticated; HttpOnly; SameSite=Strict; Path=/');
        if (submitBehavior === 'commit_then_500') return html('<p>Synthetic response rendering failed after login.</p>', 500);
        return html('<p>Synthetic login accepted.</p><a href="/account">Continue</a>');
      } catch { body = ''; if (!res.headersSent) res.writeHead(400); res.end(); return; }
    }
    if (req.method === 'GET' && req.url === '/account') {
      if (!(req.headers.cookie ?? '').split(';').some(c => c.trim() === 'synthetic_demo_session=authenticated')) return html('<p>Manual login required.</p>', 401);
      stats.sessionVisits++;
      return html('<p>Synthetic session active.</p>');
    }
    if (req.method === 'POST' && req.url === '/expire') { res.setHeader('Set-Cookie', 'synthetic_demo_session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/'); return html('<p>Synthetic session expired; manual login required.</p>'); }
    html('<p>Not found.</p>', 404);
  });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(options.port ?? 0, '127.0.0.1', () => { server.off('error', reject); resolve(); }); });
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const rules: BrowserSiteRules = { id: 'synthetic-login', version: 1, origin, loginPath: '/login', formSelector: '#login', usernameSelector: '#username', passwordSelector: '#password', submitPath: '/session', syntheticLoopback: true };
  return {
    origin, rules, frameRules: { ...rules, id: 'synthetic-login-frame', loginPath: '/framed', frameName: 'login-frame' }, stats,
    setSubmitBehavior: behavior => { submitBehavior = behavior; },
    close: () => new Promise<void>((resolve, reject) => { server.close(error => error ? reject(error) : resolve()); server.closeAllConnections(); }),
  };
}
