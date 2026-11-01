import { createHash, randomBytes } from 'node:crypto';
import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { OAuthProvider, SyntheticOAuthOptions } from './oauth.js';

/** Local protocol fixture only; does not emulate a provider account or consent policy. */
export interface OAuthSimulatorOptions {
  provider: OAuthProvider;
  clock?: () => number;
  /** Exact product callback for end-to-end fixtures; defaults to this fixture's /callback. */
  redirectUri?: string;
  /** Short real-clock expiry for product acceptance; ordinary fixtures keep one hour. */
  tokenLifetimeSeconds?: number;
  rotateGoogleRefresh?: boolean;
  issueGoogleRefresh?: boolean;
  /** Google's actual identity endpoint may return canonical URI scope spellings. */
  googleScopeAliases?: boolean;
}
interface Code { client: string; redirect: string; challenge: string; scopes: string[]; offline: boolean; expires: number; used: boolean }
interface Grant { access: string; refresh?: string; scopes: string[]; active: boolean; accessExpires: number; refreshExpires: number }
export interface OAuthSimulator {
  readonly origin: string;
  readonly clientId: string;
  readonly clientSecret: string;
  readonly redirectUri: string;
  readonly endpoints: SyntheticOAuthOptions['endpoints'];
  readonly counts: { authorize: number; exchange: number; refresh: number; identity: number; revoke: number; callback: number };
  /** Deterministic provider-side faults, consumed by the next token HTTP request. */
  nextTokenFault?: 'invalid_grant' | 'invalid_client' | 'malformed' | 'redirect' | 'drop_after_rotation' | 'scope_expansion';
  nextAuthorizationDenied: boolean;
  nextIdentityFailure: boolean;
  close(): Promise<void>;
}
const opaque = () => randomBytes(32).toString('base64url');
function json(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  response.end(JSON.stringify(body));
}
async function body(request: IncomingMessage): Promise<string> {
  let text = '';
  for await (const chunk of request) {
    text += String(chunk);
    if (text.length > 64 * 1024) throw new Error('fixture_request_too_large');
  }
  return text;
}
export async function startOAuthSimulator(options: OAuthSimulatorOptions): Promise<OAuthSimulator> {
  const now = options.clock ?? Date.now;
  const tokenLifetimeSeconds = options.tokenLifetimeSeconds ?? 3600;
  if (!Number.isSafeInteger(tokenLifetimeSeconds) || tokenLifetimeSeconds < 1 || tokenLifetimeSeconds > 86400) throw new Error('invalid_fixture_token_lifetime');
  if (options.redirectUri !== undefined) {
    const redirect = new URL(options.redirectUri);
    if (redirect.protocol !== 'http:' || redirect.hostname !== '127.0.0.1' || !redirect.port || redirect.username || redirect.password || redirect.search || redirect.hash) throw new Error('invalid_fixture_redirect_uri');
  }
  const codes = new Map<string, Code>();
  const access = new Map<string, Grant>();
  const refresh = new Map<string, Grant>();
  const clientId = `synthetic-${options.provider}`;
  const clientSecret = `synthetic-secret-${opaque()}`;
  const counts = { authorize: 0, exchange: 0, refresh: 0, identity: 0, revoke: 0, callback: 0 };
  let fixture!: OAuthSimulator;
  function issue(scopes: string[], offline: boolean, old?: Grant): Record<string, unknown> {
    const expiring = options.provider === 'google' || offline;
    const rotate = options.provider === 'github' || options.rotateGoogleRefresh;
    const issueRefresh = offline && (options.provider === 'github' || options.issueGoogleRefresh !== false);
    const value: Grant = {
      access: opaque(), scopes, active: true,
      refresh: issueRefresh ? old && !rotate ? old.refresh : opaque() : undefined,
      accessExpires: expiring ? now() + tokenLifetimeSeconds * 1000 : Number.POSITIVE_INFINITY,
      refreshExpires: old && !rotate ? old.refreshExpires : now() + 180 * 86400_000,
    };
    if (old) {
      old.active = false;
      access.delete(old.access);
      if (old.refresh) refresh.delete(old.refresh);
    }
    access.set(value.access, value);
    if (value.refresh) refresh.set(value.refresh, value);
    return {
      access_token: value.access,
      token_type: 'Bearer', scope: scopes.map(scope => options.provider === 'google' && options.googleScopeAliases && ['email', 'profile'].includes(scope) ? `https://www.googleapis.com/auth/userinfo.${scope}` : scope).join(options.provider === 'github' ? ',' : ' '),
      ...(expiring ? { expires_in: tokenLifetimeSeconds } : {}),
      ...(value.refresh && (!old || rotate) ? {
        refresh_token: value.refresh,
        ...(options.provider === 'github' || rotate ? { refresh_token_expires_in: 180 * 86400 } : {}),
      } : {}),
    };
  }
  const server = http.createServer((request, response) => {
    void (async () => {
      const url = new URL(request.url ?? '/', fixture.origin);
      if (request.method === 'GET' && url.pathname === '/authorize') {
        counts.authorize++;
        const q = url.searchParams;
        if (q.get('client_id') !== clientId || q.get('redirect_uri') !== fixture.redirectUri || q.get('response_type') !== 'code' || q.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/u.test(q.get('code_challenge') ?? '') || !q.get('state')) {
          return json(response, 400, { error: 'invalid_request' });
        }
        const callback = new URL(fixture.redirectUri);
        callback.searchParams.set('state', q.get('state')!);
        if (fixture.nextAuthorizationDenied) {
          fixture.nextAuthorizationDenied = false;
          callback.searchParams.set('error', 'access_denied');
          callback.searchParams.set('error_description', 'Synthetic denied');
        } else {
          const code = opaque();
          const scopes = (q.get('scope') ?? '').split(' ').filter(s => s && s !== 'offline_access');
          codes.set(code, {
            client: clientId, redirect: fixture.redirectUri, challenge: q.get('code_challenge')!, scopes,
            offline: options.provider === 'github' ? (q.get('scope') ?? '').split(' ').includes('offline_access') : q.get('access_type') === 'offline',
            expires: now() + 600_000, used: false,
          });
          callback.searchParams.set('code', code);
        }
        response.writeHead(302, { Location: callback.href, 'Cache-Control': 'no-store' });
        return response.end();
      }
      if (request.method === 'POST' && url.pathname === '/token') {
        const q = new URLSearchParams(await body(request));
        const grantType = q.get('grant_type');
        if (grantType === 'authorization_code') counts.exchange++;
        else if (grantType === 'refresh_token') counts.refresh++;
        const fault = fixture.nextTokenFault;
        fixture.nextTokenFault = undefined;
        if (fault === 'invalid_grant' || fault === 'invalid_client') return json(response, 400, { error: fault, error_description: 'must-not-leak-synthetic-provider-description' });
        if (fault === 'redirect') { response.writeHead(307, { Location: `${fixture.origin}/forbidden-redirect` }); return response.end(); }
        if (fault === 'malformed') { response.writeHead(200, { 'Content-Type': 'application/json' }); return response.end('{'); }
        if (q.get('client_id') !== clientId || q.get('client_secret') !== clientSecret) return json(response, 401, { error: 'invalid_client' });
        let result: Record<string, unknown>;
        if (grantType === 'authorization_code') {
          const code = codes.get(q.get('code') ?? '');
          const verifier = q.get('code_verifier') ?? '';
          if (!code || code.used || code.expires <= now() || code.client !== q.get('client_id') || code.redirect !== q.get('redirect_uri') || !/^[A-Za-z0-9._~-]{43,128}$/u.test(verifier) || createHash('sha256').update(verifier).digest('base64url') !== code.challenge) return json(response, 400, { error: 'invalid_grant' });
          code.used = true;
          result = issue(code.scopes, code.offline);
        } else if (grantType === 'refresh_token') {
          const token = refresh.get(q.get('refresh_token') ?? '');
          if (!token || !token.active || token.refreshExpires <= now()) return json(response, 400, { error: options.provider === 'github' ? 'bad_refresh_token' : 'invalid_grant' });
          if (q.has('scope')) return json(response, 400, { error: 'invalid_scope' });
          result = issue(token.scopes, true, token);
        } else return json(response, 400, { error: 'unsupported_grant_type' });
        if (fault === 'drop_after_rotation') { request.socket.destroy(); return; }
        if (fault === 'scope_expansion') result.scope = String(result.scope) + ' unexpected_scope';
        return json(response, 200, result);
      }
      if (request.method === 'GET' && url.pathname === '/identity') {
        counts.identity++;
        if (fixture.nextIdentityFailure) { fixture.nextIdentityFailure = false; return json(response, 503, { error: 'unavailable' }); }
        const token = access.get((request.headers.authorization ?? '').replace(/^Bearer /u, ''));
        if (!token || !token.active || token.accessExpires <= now()) return json(response, 401, { error: 'invalid_grant' });
        return json(response, 200, options.provider === 'github' ? { id: 1234567, login: 'synthetic-user' } : { sub: 'synthetic-google-subject', email: 'fixture@example.invalid' });
      }
      if ((options.provider === 'google' && request.method === 'POST' && url.pathname === '/revoke') || (options.provider === 'github' && request.method === 'DELETE' && url.pathname === `/applications/${clientId}/grant`)) {
        counts.revoke++;
        const content = await body(request);
        let token: Grant | undefined;
        if (options.provider === 'github') {
          if (request.headers.authorization !== `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`) return json(response, 401, { error: 'invalid_client' });
          token = access.get((JSON.parse(content) as { access_token: string }).access_token);
        } else {
          const value = new URLSearchParams(content).get('token') ?? '';
          token = refresh.get(value) ?? access.get(value);
        }
        if (token) {
          token.active = false; access.delete(token.access);
          if (token.refresh) refresh.delete(token.refresh);
        } else return json(response, 400, { error: 'invalid_token' });
        response.writeHead(options.provider === 'github' ? 204 : 200, { 'Cache-Control': 'no-store' });
        return response.end();
      }
      if (url.pathname === '/callback') { counts.callback++; return json(response, 200, { synthetic: true }); }
      return json(response, 404, { error: 'fixture_route_not_found' });
    })().catch(() => { if (!response.headersSent) json(response, 500, { error: 'fixture_error' }); else response.destroy(); });
  });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  fixture = {
    origin, clientId, clientSecret, redirectUri: options.redirectUri ?? `${origin}/callback`, counts,
    endpoints: {
      authorize: `${origin}/authorize`, token: `${origin}/token`, identity: `${origin}/identity`,
      revoke: `${origin}/${options.provider === 'github' ? 'applications' : 'revoke'}`,
    },
    nextAuthorizationDenied: false, nextIdentityFailure: false,
    close: () => new Promise<void>((resolve, reject) => { server.closeAllConnections(); server.close(error => error ? reject(error) : resolve()); }),
  };
  return fixture;
}
