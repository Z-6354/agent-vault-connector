import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import ipaddr from 'ipaddr.js';

export const MOCK_ORIGIN = 'http://127.0.0.1:43121';
export const MOCK_OPERATION = 'mock.account_summary';
export const MAX_RESPONSE_BYTES = 32 * 1024;
export const REQUEST_TIMEOUT_MS = 2500;
const OAUTH_REQUEST_TIMEOUT_MS = 5000;
const OAUTH_MAX_RESPONSE_BYTES = 64 * 1024;

export class UpstreamAuthorizationError extends Error {
  constructor() {
    super('Upstream authorization denied');
    this.name = 'UpstreamAuthorizationError';
  }
}

interface Address { address: string; family: number }
type Resolver = (hostname: string) => Promise<Address[]>;
export interface Destination { origin: string; method: 'GET'; path: string; operationId: string; mock: boolean }

export function isPublicAddress(address: string): boolean {
  try {
    if (address.includes('%') || !ipaddr.isValid(address)) return false;
    const parsed = ipaddr.parse(address);
    if (parsed.range() !== 'unicast') return false;
    if (parsed.kind() === 'ipv6') {
      const ipv6 = parsed as ipaddr.IPv6;
      if (!ipv6.match(ipaddr.parseCIDR('2000::/3'))) return false;
      for (const cidr of ['2001::/23', '2002::/16', '3fff::/20']) {
        if (ipv6.match(ipaddr.parseCIDR(cidr))) return false;
      }
    }
    return true;
  } catch { return false; }
}

export async function validateDestination(destination: Destination, resolver: Resolver = hostname => dns.lookup(hostname, { all: true, verbatim: true })): Promise<{ url: URL; pinned: Address }> {
  const url = new URL(destination.origin);
  if (url.origin !== destination.origin || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error('Origin denied');
  if (destination.method !== 'GET' || !destination.path.startsWith('/') || destination.path.startsWith('//') || /[\\?#\r\n]/.test(destination.path)) throw new Error('Request denied');
  if (destination.mock) {
    if (destination.origin !== MOCK_ORIGIN || destination.operationId !== MOCK_OPERATION || destination.path !== '/v1/account/summary') throw new Error('Mock destination denied');
    return { url, pinned: { address: '127.0.0.1', family: 4 } };
  }
  if (url.protocol !== 'https:' || (url.port && url.port !== '443')) throw new Error('HTTPS required');
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  let timer: ReturnType<typeof setTimeout> | undefined;
  let addresses: Address[];
  try {
    addresses = net.isIP(hostname) ? [{ address: hostname, family: net.isIP(hostname) }] : await Promise.race([
      resolver(hostname),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('DNS timeout')), REQUEST_TIMEOUT_MS); }),
    ]);
  } finally { clearTimeout(timer); }
  if (!addresses.length || addresses.some(item => !isPublicAddress(item.address) || net.isIP(item.address) !== item.family)) throw new Error('Address denied');
  return { url, pinned: addresses[0]! };
}

/** Production OAuth endpoints are selected by the caller's immutable registry.
 * Keep the synthetic loopback transport separate: this path always uses the
 * shared public-address policy and connects directly to its validated IP. */
export async function restrictedOAuthRequest(value: string, init: RequestInit): Promise<Response> {
  try {
    const url = new URL(value);
    if (url.username || url.password || url.search || url.hash || /[\\\r\n]/u.test(value)) throw new Error();
    if (Object.keys(init).some(key => !['method', 'headers', 'body', 'redirect', 'signal'].includes(key))) throw new Error();
    const method = init.method ?? 'GET';
    if (!['GET', 'POST', 'DELETE'].includes(method) || (init.redirect !== undefined && init.redirect !== 'error')) throw new Error();
    if (init.body !== undefined && init.body !== null && typeof init.body !== 'string' && !(init.body instanceof URLSearchParams)) throw new Error();
    if (method === 'GET' && init.body !== undefined && init.body !== null) throw new Error();
    const headers = new Headers(init.headers);
    const allowedHeaders = new Set(['accept', 'authorization', 'content-type', 'user-agent', 'x-github-api-version']);
    for (const name of headers.keys()) if (!allowedHeaders.has(name)) throw new Error();
    if (init.body instanceof URLSearchParams && !headers.has('content-type')) headers.set('content-type', 'application/x-www-form-urlencoded;charset=UTF-8');
    headers.set('host', url.host);
    headers.set('accept-encoding', 'identity');
    if (!headers.has('user-agent')) headers.set('user-agent', 'agent-vault-connector/1.0');
    const body = init.body === undefined || init.body === null ? undefined : init.body.toString();

    return await new Promise<Response>((resolve, reject) => {
      let settled = false;
      let request: http.ClientRequest | undefined;
      let response: http.IncomingMessage | undefined;
      const cleanup = () => {
        clearTimeout(deadline);
        init.signal?.removeEventListener('abort', deny);
      };
      const deny = () => {
        if (settled) return;
        settled = true;
        cleanup();
        response?.destroy();
        request?.destroy();
        reject(new Error('OAuth request failed'));
      };
      // This deadline covers DNS, TLS, headers and the complete response body.
      const deadline = setTimeout(deny, OAUTH_REQUEST_TIMEOUT_MS);
      if (init.signal?.aborted) { deny(); return; }
      init.signal?.addEventListener('abort', deny, { once: true });
      void validateDestination({ origin: url.origin, method: 'GET', path: url.pathname, operationId: 'oauth', mock: false }).then(({ pinned }) => {
        if (settled) return;
        try {
          request = https.request({
            protocol: 'https:', hostname: pinned.address, family: pinned.family,
            port: url.port || 443,
            servername: net.isIP(url.hostname.replace(/^\[|\]$/g, '')) ? undefined : url.hostname,
            method, path: url.pathname, headers: Object.fromEntries(headers),
            agent: false, maxHeaderSize: 8192,
          }, incoming => {
            if (settled) { incoming.destroy(); return; }
            response = incoming;
            response.on('error', deny);
            response.on('aborted', deny);
            const status = response.statusCode ?? 0;
            // No redirect client is involved, and Location is never followed.
            if (status < 200 || status >= 300 && status < 400 || status > 599 || response.headers['content-encoding'] && response.headers['content-encoding'] !== 'identity') { deny(); return; }
            let size = 0;
            const chunks: Buffer[] = [];
            response.on('data', (chunk: Buffer) => {
              if (settled) return;
              size += chunk.length;
              if (size > OAUTH_MAX_RESPONSE_BYTES) { deny(); return; }
              chunks.push(chunk);
            });
            response.on('end', () => {
              if (settled) return;
              try {
                const content = Buffer.concat(chunks);
                const responseHeaders = new Headers();
                for (const [name, values] of Object.entries(incoming.headers)) {
                  if (values !== undefined) for (const item of Array.isArray(values) ? values : [values]) responseHeaders.append(name, item);
                }
                const result = new Response(status === 204 || status === 205 ? null : content, { status, headers: responseHeaders });
                settled = true;
                cleanup();
                resolve(result);
              } catch { deny(); }
            });
            response.on('close', () => { if (!incoming.complete) deny(); });
          });
          request.on('error', deny);
          request.end(body);
        } catch { deny(); }
      }, deny);
    });
  } catch {
    // Never surface URLs, credentials, DNS/TLS messages or provider content.
    throw new Error('OAuth request failed');
  }
}

export async function restrictedRequest(destination: Destination, token: string, signal: AbortSignal): Promise<unknown> {
  const { url, pinned } = await validateDestination(destination);
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const request = (url.protocol === 'https:' ? https : http).request({
      protocol: url.protocol,
      hostname: pinned.address,
      family: pinned.family,
      port: url.port || 443,
      servername: net.isIP(url.hostname) ? undefined : url.hostname,
      method: destination.method,
      path: destination.path,
      headers: { host: url.host, authorization: `Bearer ${token}`, accept: 'application/json', 'accept-encoding': 'identity', 'user-agent': 'agent-vault-connector/1.0' },
      agent: false,
      signal,
      maxHeaderSize: 8192,
    }, response => {
      // There is no redirect-following client and Location is never used.
      if (response.statusCode === 401) {
        response.destroy();
        reject(new UpstreamAuthorizationError());
        return;
      }
      if (response.statusCode !== 200 || !/^application\/json(?:\s*;|$)/i.test(String(response.headers['content-type'] ?? '')) || response.headers['content-encoding']) {
        response.destroy();
        reject(new Error('Upstream response denied'));
        return;
      }
      let size = 0;
      const chunks: Buffer[] = [];
      response.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) {
          response.destroy(new Error('Response too large'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('error', () => reject(new Error('Upstream failed')));
      response.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { reject(new Error('Invalid upstream JSON')); }
      });
    });
    const deadline = setTimeout(() => request.destroy(new Error('Upstream timeout')), REQUEST_TIMEOUT_MS);
    request.on('error', () => reject(new Error('Upstream failed')));
    request.on('close', () => clearTimeout(deadline));
    request.end();
  });
}
