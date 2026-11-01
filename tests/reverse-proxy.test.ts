import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';
import { execFileSync } from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { initialize } from '../src/vault.js';
import { createServer } from '../src/server.js';
import { isLoopbackPeer, requestHostAllowed, validateNetworkOptions } from '../src/server-config.js';

const passphrase = 'synthetic reverse proxy passphrase';
const scratchDirectory = () => {
  assert(process.env.TMPDIR, 'Set TMPDIR to the configured private scratch directory');
  return process.env.TMPDIR;
};

test('network configuration rejects ambiguous origins before opening a vault', async () => {
  for (const publicOrigin of ['', 'http://vault.example', 'https://vault.example/', 'https://vault.example/path', 'https://vault.example?x', 'https://vault.example#x', 'https://user@vault.example', 'https://*.example', 'https://vault.example,https://other.example', ' https://vault.example', 'https://VAULT.example', 'https://vault.example:443', 'https://vault.example\\evil', 'null']) {
    assert.throws(() => validateNetworkOptions({ publicOrigin }));
    await assert.rejects(createServer('/unopened-invalid-config', 0, { publicOrigin }), /origin/i);
  }
  assert.throws(() => validateNetworkOptions({ publicOrigin: 'https://vault.example', allowedOrigin: 'https://vault.example' }));
  for (const bindHost of ['0.0.0.0', '192.0.2.1']) assert.throws(() => validateNetworkOptions({ bindHost }));
  assert.throws(() => validateNetworkOptions({ bindHost: 'localhost', publicOrigin: 'https://vault.example' }));
  assert.equal(validateNetworkOptions({ allowedOrigin: 'https://vault.example:8443' }).publicOrigin, 'https://vault.example:8443');
  assert.equal(validateNetworkOptions({ publicOrigin: 'http://127.0.0.1:43120' }).secureCookies, false);
  assert.equal(validateNetworkOptions({ bindHost: '0.0.0.0', publicOrigin: 'https://vault.example' }).bindHost, '0.0.0.0');
});

test('trusted loopback requires explicit HTTPS configuration and exact raw headers and socket peer', async () => {
  assert.equal(validateNetworkOptions({}).trustedProxy, undefined);
  for (const options of [{ trustedProxy: 'loopback' }, { trustedProxy: 'loopback', publicOrigin: 'http://127.0.0.1:3210' }, { trustedProxy: true, publicOrigin: 'https://vault.example' }]) {
    assert.throws(() => validateNetworkOptions(options as never));
  }
  const publicOrigin = 'https://vault.example:8443', local = 'http://127.0.0.1:3210';
  const raw = ['Host', '127.0.0.1:3210', 'X-Forwarded-Host', 'vault.example:8443', 'X-Forwarded-Proto', 'https'];
  const allowed = (headers: string[], peer: string | undefined = '127.0.0.1', execution = false) => requestHostAllowed(headers, peer, publicOrigin, local, true, execution);
  for (const peer of ['127.0.0.1', '::ffff:127.0.0.1', '::ffff:7f00:1']) {
    assert(isLoopbackPeer(peer)); assert(allowed(raw, peer));
    assert(allowed(['Host', '127.0.0.1:3210'], peer, true));
  }
  assert(!isLoopbackPeer(undefined));
  assert(!requestHostAllowed(raw, undefined, publicOrigin, local, true, false));
  assert(!requestHostAllowed(['Host', '127.0.0.1:3210'], undefined, publicOrigin, local, true, true));
  for (const peer of ['::1', '127.0.0.2', '127.1', 'localhost', '192.0.2.1', '::ffff:192.0.2.1', '0:0:0:0:0:ffff:7f00:1', '127.0.0.1 ']) {
    assert(!isLoopbackPeer(peer)); assert(!allowed(raw, peer));
    assert(!allowed(['Host', '127.0.0.1:3210'], peer, true));
  }
  assert(!requestHostAllowed(raw, '127.0.0.1', publicOrigin, local, false, false));
  assert(allowed(['Host', 'vault.example:8443']));
  assert(allowed(['Host', 'vault.example:8443', ...raw.slice(2)]));
  for (const headers of [[], raw.slice(2), raw.slice(0, 2), raw.slice(0, 4), [...raw.slice(0, 2), ...raw.slice(4)],
    [...raw, 'hOsT', '127.0.0.1:3210'], [...raw, 'x-forwarded-host', 'vault.example:8443'], [...raw, 'X-FORWARDED-PROTO', 'https'],
    [...raw, 'Forwarded', 'host=vault.example:8443;proto=https']]) assert(!allowed(headers));
  for (const [index, values] of [[1, ['localhost:3210', '127.0.0.1:3211', 'evil.example', '127.0.0.1:3210, vault.example:8443']],
    [3, ['evil.example', 'vault.example', 'vault.example:8443, vault.example:8443', 'VAULT.example:8443', '']],
    [5, ['http', 'HTTPS', 'https, https', '']]] as const) {
    for (const value of values) { const bad = [...raw]; bad[index] = value; assert(!allowed(bad)); }
  }
  assert(!allowed(['Host', 'vault.example:8443', 'X-Forwarded-Host', 'evil.example', 'X-Forwarded-Proto', 'https']));
  assert(!allowed(raw, '127.0.0.1', true));
  const root = fs.mkdtempSync(path.join(scratchDirectory(), 'proxy-headers-'));
  await initialize(path.join(root, 'vault'), passphrase);
  const server = await createServer(path.join(root, 'vault'), 0, { publicOrigin, trustedProxy: 'loopback' });
  try {
    const host = new URL(server.executionOrigin).host;
    const headers = { host, 'x-forwarded-host': new URL(publicOrigin).host, 'x-forwarded-proto': 'https' };
    assert.equal((await server.app.inject({ url: '/', headers, remoteAddress: '127.0.0.1' })).statusCode, 200);
    for (const bad of [{ host: 'vault.example:8443', 'x-forwarded-host': 'evil.example', 'x-forwarded-proto': 'https' },
      { ...headers, 'x-forwarded-host': ['vault.example:8443', 'vault.example:8443'] },
      { ...headers, 'x-forwarded-proto': ['https', 'https'] }, { ...headers, 'x-forwarded-proto': 'https, https' }]) {
      assert.equal((await server.app.inject({ url: '/', headers: bad, remoteAddress: '127.0.0.1' })).statusCode, 403);
    }
    assert.equal((await server.app.inject({ url: '/', headers: { ...headers, 'x-forwarded-for': '127.0.0.1' }, remoteAddress: '192.0.2.1' })).statusCode, 403);
  } finally { await server.app.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('default exact loopback Host, Origin and non-Secure HTTP cookie remain unchanged', async () => {
  const root = fs.mkdtempSync(path.join(scratchDirectory(), 'proxy-default-'));
  await initialize(path.join(root, 'vault'), passphrase);
  const server = await createServer(path.join(root, 'vault'), 0);
  try {
    assert.equal(server.origin, server.listeningOrigin);
    assert.equal(server.origin, server.executionOrigin);
    const host = new URL(server.origin).host;
    const response = await server.app.inject({ url: '/management/session', headers: { host } });
    assert.equal(response.statusCode, 200);
    assert.doesNotMatch(String(response.headers['set-cookie']), /; Secure/i);
    assert.equal((await server.app.inject({ url: '/', headers: { host: host.replace('127.0.0.1', 'localhost') } })).statusCode, 403);
    assert.equal((await server.app.inject({ url: '/', headers: { host, origin: 'https://vault.example', 'x-forwarded-host': host } })).statusCode, 403);
  } finally { await server.app.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

for (const trustedProxy of [undefined, 'loopback'] as const) test(`real local TLS reverse proxy ${trustedProxy ?? 'preserved-host'} preserves public management origin and local stdio execution isolation`, async () => {
  const root = fs.mkdtempSync(path.join(scratchDirectory(), 'proxy-tls-'));
  const directory = path.join(root, 'vault');
  const key = path.join(root, 'tls.key'), cert = path.join(root, 'tls.crt');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=vault.example'], { stdio: 'ignore' });
  await initialize(directory, passphrase);
  let upstream = '';
  const proxy = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, (request, reply) => {
    const headers = { ...request.headers };
    if (trustedProxy) {
      // Model the administrator-observed gateway: overwrite routing fields, preserve Origin.
      delete headers.forwarded;
      headers.host = new URL(upstream).host;
      headers['x-forwarded-host'] = new URL(origin).host;
      headers['x-forwarded-proto'] = 'https';
    }
    const outgoing = http.request(`${upstream}${request.url}`, { method: request.method, headers }, response => {
      reply.writeHead(response.statusCode!, response.headers); response.pipe(reply);
    });
    outgoing.on('error', () => { reply.writeHead(502); reply.end(); });
    request.pipe(outgoing);
  });
  await new Promise<void>(resolve => proxy.listen(0, '127.0.0.1', resolve));
  const address = proxy.address(); assert(address && typeof address === 'object');
  const origin = `https://vault.example:${address.port}`;
  const server = await createServer(directory, 0, { publicOrigin: origin, bindHost: '0.0.0.0', trustedProxy });
  upstream = server.executionOrigin;
  let cookie = '', csrf = '';
  const request = (url: string, method = 'GET', body?: unknown, headers: Record<string, string> = {}) => new Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }>((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const outgoing = https.request({ hostname: '127.0.0.1', port: address.port, path: url, method, rejectUnauthorized: false, headers: {
      host: new URL(origin).host, ...(cookie ? { cookie } : {}), ...(payload === undefined ? {} : { origin, 'x-csrf-token': csrf, 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(payload)) }), ...headers,
    } }, response => {
      const chunks: Buffer[] = []; response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode!, headers: response.headers, body: Buffer.concat(chunks).toString() }));
    });
    outgoing.on('error', reject); outgoing.end(payload);
  });
  const adopt = (response: Awaited<ReturnType<typeof request>>, state: string) => {
    assert.equal(response.status, 200);
    const set = response.headers['set-cookie']?.[0]; assert(set);
    assert.match(set, /; Secure/i); assert.match(set, /HttpOnly/); assert.match(set, /SameSite=Strict/i);
    cookie = set.split(';')[0]!; csrf = JSON.parse(response.body).csrf;
    assert.equal(JSON.parse(response.body).state, state);
  };
  const transport = new StdioClientTransport({ command: process.execPath, args: ['dist/src/cli.js', 'bridge', '--origin', server.executionOrigin, '--credential-file', path.join(directory, 'execution.key')], stderr: 'pipe' });
  const client = new Client({ name: 'synthetic-proxy-test', version: '1' });
  try {
    assert.notEqual(server.listeningOrigin, origin);
    assert.equal((await request('/')).status, 200);
    adopt(await request('/management/session'), 'S0');
    assert.equal((await request('/management/unlock', 'POST', { passphrase })).status, 401);
    const deniedHeaders: Record<string, string>[] = [{ origin: 'https://evil.example' }, { origin: upstream }, { origin: '' }, { 'x-csrf-token': 'wrong' }, { 'x-csrf-token': '' }];
    if (!trustedProxy) deniedHeaders.push({ host: 'evil.example' }, { host: new URL(upstream).host, 'x-forwarded-host': new URL(origin).host, 'x-forwarded-proto': 'https', forwarded: `host=${new URL(origin).host};proto=https` });
    for (const headers of deniedHeaders) {
      assert.equal((await request('/management/login', 'POST', { passphrase }, headers)).status, 403);
    }
    adopt(await request('/management/login', 'POST', { passphrase }), 'S1');
    assert.equal(server.vault.unlocked, false);
    adopt(await request('/management/unlock', 'POST', { passphrase }), 'S2');
    const renewed = await request('/management/connections'); assert.equal(renewed.status, 200); assert.match(renewed.headers['set-cookie']![0]!, /; Secure/i);
    const providers = JSON.parse((await request('/management/oauth/providers')).body).providers;
    assert.deepEqual(providers.map((p: { redirect_uri: string }) => p.redirect_uri), [`${origin}/management/oauth/callback/github`, `${origin}/management/oauth/callback/google`]);
    const configured = await request('/management/oauth/client', 'POST', { provider: 'github', clientId: 'synthetic-client', clientSecret: 'synthetic-client-secret', expectedVersion: 0 });
    assert.equal(configured.status, 200); assert.equal(JSON.parse(configured.body).client.redirect_uri, `${origin}/management/oauth/callback/github`);
    const bearer = `Bearer ${fs.readFileSync(path.join(directory, 'execution.key'), 'utf8').trim()}`;
    assert.equal((await request('/execution/connections', 'GET', undefined, { authorization: bearer })).status, 403);
    const localHost = new URL(upstream).host;
    assert.equal((await server.app.inject({ url: '/management/session', remoteAddress: '127.0.0.1', headers: { host: localHost, cookie, 'x-forwarded-host': new URL(origin).host, 'x-forwarded-proto': 'https' } })).statusCode, trustedProxy ? 200 : 403);
    assert.equal((await request('/management/oauth/callback/github?code=synthetic', 'GET', undefined, { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' })).status, 200);
    assert.equal((await request('/app.js')).status, 200);
    assert.equal((await request('/oauth-callback.js')).status, 200);
    for (const forwarding of [{ 'x-forwarded-host': new URL(origin).host }, { 'x-forwarded-proto': 'https' }]) {
      assert.equal((await server.app.inject({ url: '/execution/connections', remoteAddress: '127.0.0.1', headers: { host: localHost, authorization: bearer, ...forwarding } })).statusCode, 403);
    }
    assert.equal((await server.app.inject({ url: '/management/session', headers: { host: new URL(origin).host, authorization: bearer } })).statusCode, 403);
    assert.equal((await server.app.inject({ url: '/execution/connections', remoteAddress: '192.0.2.1', headers: { host: localHost, authorization: bearer, 'x-forwarded-for': '127.0.0.1' } })).statusCode, 403);
    assert.equal((await server.app.inject({ url: '/execution/connections', headers: { host: localHost, authorization: bearer, cookie } })).statusCode, 403);
    assert.equal((await server.app.inject({ url: '/execution/connections', headers: { host: localHost, authorization: bearer, origin } })).statusCode, 403);
    assert.equal((await server.app.inject({ url: '/execution/connections', headers: { host: localHost } })).statusCode, 401);
    assert.equal((await server.app.inject({ url: '/execution/connections', headers: { host: localHost, authorization: `Bearer ${'0'.repeat(64)}` } })).statusCode, 401);
    await client.connect(transport);
    const result = await client.callTool({ name: 'list_connections', arguments: {} });
    assert(!result.isError); assert.deepEqual(JSON.parse((result.content as { text: string }[])[0]!.text), { connections: [] });
    adopt(await request('/management/lock', 'POST', {}), 'S1');
    assert.equal((await client.callTool({ name: 'list_connections', arguments: {} })).isError, true);
    const logout = await request('/management/logout', 'POST', {}); assert.equal(logout.status, 200);
    assert.match(logout.headers['set-cookie']![0]!, /; Secure/i); assert.match(logout.headers['set-cookie']![0]!, /Max-Age=0/);
  } finally {
    await client.close(); await transport.close();
    await new Promise<void>((resolve, reject) => proxy.close(error => error ? reject(error) : resolve()));
    await server.app.close(); fs.rmSync(root, { recursive: true, force: true });
  }
});
