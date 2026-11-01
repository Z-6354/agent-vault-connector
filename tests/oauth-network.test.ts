import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { restrictedOAuthRequest, restrictedRequest, UpstreamAuthorizationError } from '../src/network.js';

interface Address { address: string; family: number }
interface Reply {
  status?: number;
  headers?: http.IncomingHttpHeaders;
  chunks?: Buffer[];
  error?: Error;
  stall?: boolean;
  incomplete?: boolean;
}
function transport(t: TestContext, options: {
  addresses?: Address[];
  resolver?: () => Promise<Address[]>;
  reply?: Reply;
} = {}) {
  const requests: { options: https.RequestOptions; body: unknown; destroyed: boolean; response?: http.IncomingMessage }[] = [];
  const lookups: string[] = [];
  t.mock.method(dns, 'lookup', (async (hostname: string) => {
    lookups.push(hostname);
    return options.resolver ? options.resolver() : options.addresses ?? [{ address: '8.8.8.8', family: 4 }];
  }) as unknown as typeof dns.lookup);
  t.mock.method(https, 'request', ((requestOptions: https.RequestOptions, callback: (response: http.IncomingMessage) => void) => {
    const call = { options: requestOptions, body: undefined as unknown, destroyed: false, response: undefined as http.IncomingMessage | undefined };
    requests.push(call);
    const request = new EventEmitter() as http.ClientRequest;
    request.destroy = (() => { call.destroyed = true; return request; }) as typeof request.destroy;
    request.end = ((body: unknown) => {
      call.body = body;
      queueMicrotask(() => {
        const reply = options.reply ?? {};
        if (reply.error) { request.emit('error', reply.error); return; }
        if (call.destroyed) return;
        const stream = new PassThrough();
        const response = stream as unknown as http.IncomingMessage;
        response.statusCode = reply.status ?? 200;
        response.headers = reply.headers ?? { 'content-type': 'application/json' };
        response.complete = false;
        call.response = response;
        callback(response);
        if (response.destroyed || reply.stall) return;
        for (const chunk of reply.chunks ?? [Buffer.from('{"ok":true}')]) stream.write(chunk);
        response.complete = !reply.incomplete;
        if (reply.incomplete) response.destroy();
        else stream.end();
      });
      return request;
    }) as typeof request.end;
    return request;
  }) as typeof https.request);
  return { requests, lookups };
}
const failed = (error: unknown) => error instanceof Error && error.name === 'Error' && error.message === 'OAuth request failed' && error.cause === undefined;
const flush = async () => { for (let count = 0; count < 8; count++) await Promise.resolve(); };

test('OAuth public-address policy denies private, metadata, mixed and malformed DNS answers before dispatch', async t => {
  const answers: Address[][] = [
    [{ address: '127.0.0.1', family: 4 }],
    [{ address: '10.0.0.1', family: 4 }],
    [{ address: '169.254.169.254', family: 4 }],
    [{ address: '::1', family: 6 }],
    [{ address: 'fc00::1', family: 6 }],
    [{ address: '::ffff:169.254.169.254', family: 6 }],
    [{ address: '8.8.8.8', family: 4 }, { address: '192.168.1.1', family: 4 }],
    [{ address: '2606:4700:4700::1111', family: 6 }, { address: 'fe80::1', family: 6 }],
    [{ address: '8.8.8.8', family: 6 }],
    [],
  ];
  for (const addresses of answers) await t.test(JSON.stringify(addresses), async child => {
    const fake = transport(child, { addresses });
    await assert.rejects(restrictedOAuthRequest('https://oauth.example.test/token', { method: 'POST', body: 'client_secret=synthetic_only' }), failed);
    assert.equal(fake.requests.length, 0);
    assert.deepEqual(fake.lookups, ['oauth.example.test']);
  });
});

test('OAuth validates endpoint shape, HTTPS, port, methods and headers without any network dispatch', async t => {
  const fake = transport(t);
  for (const url of [
    'not a URL', 'http://oauth.example.test/token', 'https://oauth.example.test:8443/token',
    'https://user:synthetic_only@oauth.example.test/token', 'https://oauth.example.test/token?secret=synthetic_only',
    'https://oauth.example.test/token#fragment', 'https://oauth.example.test//other.test/path',
    'https://oauth.example.test/a\\b', 'https://oauth.example.test/to\nken',
    'https://127.0.0.1/token', 'https://169.254.169.254/token', 'https://[::ffff:127.0.0.1]/token',
  ]) await assert.rejects(restrictedOAuthRequest(url, {}), failed);
  for (const init of [
    { method: 'PUT' }, { method: 'GET', body: 'synthetic_only' }, { method: 'POST', body: new Blob(['synthetic_only']) },
    { redirect: 'follow' }, { headers: { Host: 'other.test' } }, { headers: { Connection: 'keep-alive' } },
    { credentials: 'include' },
  ] as RequestInit[]) await assert.rejects(restrictedOAuthRequest('https://oauth.example.test/token', init), failed);
  assert.equal(fake.requests.length, 0);
  assert.equal(fake.lookups.length, 0);
});

test('OAuth resolves once, pins selected IP, preserves original Host/SNI and supports fixed form POST', async t => {
  const fake = transport(t, { addresses: [{ address: '8.8.8.8', family: 4 }, { address: '1.1.1.1', family: 4 }] });
  const form = new URLSearchParams({ grant_type: 'authorization_code', client_secret: 'synthetic + only' });
  const response = await restrictedOAuthRequest('https://oauth.example.test/oauth2/token', {
    method: 'POST', headers: { Accept: 'application/json' }, body: form, redirect: 'error',
  });
  assert.deepEqual(await response.json(), { ok: true });
  assert.deepEqual(fake.lookups, ['oauth.example.test']);
  assert.equal(fake.requests.length, 1);
  const call = fake.requests[0]!;
  assert.equal(call.options.hostname, '8.8.8.8');
  assert.equal(call.options.family, 4);
  assert.equal(call.options.servername, 'oauth.example.test');
  assert.equal(call.options.port, 443);
  assert.equal(call.options.protocol, 'https:');
  assert.equal(call.options.method, 'POST');
  assert.equal(call.options.path, '/oauth2/token');
  assert.equal(call.options.agent, false);
  assert.equal(call.options.maxHeaderSize, 8192);
  assert.equal(call.options.lookup, undefined);
  const headers = call.options.headers as Record<string, string>;
  assert.equal(headers.host, 'oauth.example.test');
  assert.equal(headers['accept-encoding'], 'identity');
  assert.equal(headers['content-type'], 'application/x-www-form-urlencoded;charset=UTF-8');
  assert.equal(call.body, form.toString());
});

test('OAuth IPv6 pin retains GET bearer headers; GitHub composed revoke DELETE accepts JSON and204', async t => {
  await t.test('identity', async child => {
    const fake = transport(child, { addresses: [{ address: '2606:4700:4700::1111', family: 6 }] });
    await restrictedOAuthRequest('https://api.example.test/user', { headers: { Authorization: 'Bearer synthetic_only', 'X-GitHub-Api-Version': '2026-03-10' } });
    const options = fake.requests[0]!.options;
    assert.equal(options.method, 'GET');
    assert.equal(options.hostname, '2606:4700:4700::1111');
    assert.equal(options.family, 6);
    assert.equal(options.servername, 'api.example.test');
    assert.equal((options.headers as Record<string, string>).authorization, 'Bearer synthetic_only');
    assert.equal(fake.requests[0]!.body, undefined);
  });
  await t.test('revoke', async child => {
    const fake = transport(child, { reply: { status: 204, chunks: [] } });
    const body = JSON.stringify({ access_token: 'synthetic_only' });
    const response = await restrictedOAuthRequest('https://api.example.test/applications/synthetic_client/grant', {
      method: 'DELETE', headers: { Authorization: 'Basic synthetic_only', 'Content-Type': 'application/json', 'User-Agent': 'agent-vault-connector' }, body,
    });
    assert.equal(response.status, 204);
    assert.equal(response.body, null);
    assert.equal(fake.requests[0]!.options.path, '/applications/synthetic_client/grant');
    assert.equal(fake.requests[0]!.options.method, 'DELETE');
    assert.equal(fake.requests[0]!.body, body);
  });
});

test('OAuth denies redirects and compressed responses without following Location', async t => {
  for (const reply of [
    { status: 302, headers: { location: 'https://169.254.169.254/secret' } },
    { status: 307, headers: { location: 'https://other.test/token' } },
    { status: 200, headers: { 'content-encoding': 'gzip' } },
    { status: 200, incomplete: true },
  ]) await t.test(JSON.stringify(reply), async child => {
    const fake = transport(child, { reply });
    await assert.rejects(restrictedOAuthRequest('https://oauth.example.test/token', {}), failed);
    assert.equal(fake.requests.length, 1);
    assert.equal(fake.requests[0]!.destroyed, true);
    assert.equal(fake.requests[0]!.response?.destroyed, true);
    assert.equal(fake.lookups.length, 1);
  });
});

test('OAuth buffers at most64KiB and preserves bounded provider errors for caller classification', async t => {
  await t.test('exact limit', async child => {
    transport(child, { reply: { chunks: [Buffer.alloc(64 * 1024, 'x')] } });
    const response = await restrictedOAuthRequest('https://oauth.example.test/token', {});
    assert.equal((await response.arrayBuffer()).byteLength, 64 * 1024);
  });
  await t.test('over limit', async child => {
    const fake = transport(child, { reply: { chunks: [Buffer.alloc(64 * 1024), Buffer.alloc(1)] } });
    await assert.rejects(restrictedOAuthRequest('https://oauth.example.test/token', {}), failed);
    assert.equal(fake.requests[0]!.destroyed, true);
  });
  await t.test('provider error', async child => {
    transport(child, { reply: { status: 400, chunks: [Buffer.from('{"error":"invalid_grant"}')] } });
    const response = await restrictedOAuthRequest('https://oauth.example.test/token', {});
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: 'invalid_grant' });
  });
});

test('OAuth enforces one five-second deadline across DNS and response consumption', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  let finishDns!: (addresses: Address[]) => void;
  const fake = transport(t, { resolver: () => new Promise(resolve => { finishDns = resolve; }), reply: { stall: true } });
  let settled = false;
  const pending = restrictedOAuthRequest('https://oauth.example.test/token', {}).finally(() => { settled = true; });
  const rejected = assert.rejects(pending, failed);
  t.mock.timers.tick(2000);
  finishDns([{ address: '8.8.8.8', family: 4 }]);
  await flush();
  assert.equal(fake.requests.length, 1);
  t.mock.timers.tick(2999);
  await flush();
  assert.equal(settled, false);
  t.mock.timers.tick(1);
  await rejected;
  assert.equal(fake.requests[0]!.destroyed, true);
  assert.equal(fake.requests[0]!.response?.destroyed, true);
});

test('OAuth bounds hanging DNS and honors cancellation without surfacing reason', async t => {
  await t.test('DNS timeout', async child => {
    child.mock.timers.enable({ apis: ['setTimeout'] });
    const fake = transport(child, { resolver: () => new Promise(() => {}) });
    const rejected = assert.rejects(restrictedOAuthRequest('https://oauth.example.test/token', {}), failed);
    child.mock.timers.tick(2500);
    await rejected;
    assert.equal(fake.requests.length, 0);
  });
  await t.test('abort before DNS', async child => {
    const fake = transport(child);
    await assert.rejects(restrictedOAuthRequest('https://oauth.example.test/token', { signal: AbortSignal.abort(new Error('synthetic_secret_only')) }), failed);
    assert.equal(fake.lookups.length, 0);
  });
  await t.test('abort while reading', async child => {
    const fake = transport(child, { reply: { stall: true } });
    const controller = new AbortController();
    const rejected = assert.rejects(restrictedOAuthRequest('https://oauth.example.test/token', { signal: controller.signal }), failed);
    await flush();
    controller.abort(new Error('synthetic_secret_only'));
    await rejected;
    assert.equal(fake.requests[0]!.destroyed, true);
  });
});

test('OAuth DNS and TLS failures have fixed errors with no URL, body, credentials or underlying cause', async t => {
  for (const phase of ['DNS', 'TLS']) await t.test(phase, async child => {
    const failure = new Error('synthetic_secret_only https://oauth.example.test/token');
    transport(child, phase === 'DNS' ? { resolver: async () => { throw failure; } } : { reply: { error: failure } });
    await assert.rejects(restrictedOAuthRequest('https://oauth.example.test/token', { method: 'POST', body: 'synthetic_secret_only', headers: { Authorization: 'Basic synthetic_secret_only' } }), failed);
  });
});

test('shared fixed-operation transport classifies401 safely, while403 remains generic', async t => {
  for (const status of [401, 403]) await t.test(String(status), async child => {
    const fake = transport(child, { reply: { status, chunks: [Buffer.from('synthetic_secret_only')] } });
    await assert.rejects(restrictedRequest({ origin: 'https://api.example.test', method: 'GET', path: '/user', operationId: 'trusted', mock: false }, 'synthetic_secret_only', new AbortController().signal), error => {
      assert(error instanceof Error);
      assert.equal(error instanceof UpstreamAuthorizationError, status === 401);
      assert.equal(error.name, status === 401 ? 'UpstreamAuthorizationError' : 'Error');
      assert.equal(error.message, status === 401 ? 'Upstream authorization denied' : 'Upstream response denied');
      assert.equal(error.cause, undefined);
      return true;
    });
    assert.equal(fake.requests[0]!.response?.destroyed, true);
  });
});
