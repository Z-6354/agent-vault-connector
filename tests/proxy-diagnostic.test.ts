import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { initialize } from '../src/vault.js';
import { createServer } from '../src/server.js';
import { validateNetworkOptions } from '../src/server-config.js';
import { proxyHeaderDiagnostic } from '../src/proxy-diagnostic.js';

test('proxy diagnostic is bounded and sanitizes raw duplicates and controls', async () => {
  assert.equal(validateNetworkOptions({}).diagnoseProxyHeaders, false);
  for (const value of ['true', 'false', 1, null]) {
    await assert.rejects(createServer('/unopened-invalid-config', 0, { diagnoseProxyHeaders: value as never }), /diagnostic/);
  }
  const raw = ['HOST', 'bad\r\n\u001b\u0085 host', 'hOsT', 'second.example', 'Origin', 'x'.repeat(300),
    'X-Forwarded-Host', 'public.example', 'X-Forwarded-Proto', 'https', 'Authorization', 'Bearer secret-canary', 'Cookie', 'secret-canary'];
  for (let i = 0; i < 20; i++) raw.push('Host', 'extra.example');
  const line = proxyHeaderDiagnostic(raw, '192.0.2.8\nspoof');
  const record = JSON.parse(line);
  assert.equal(record.host_count, 22);
  assert.equal(record.host_values.length, 8);
  assert.equal(record.host_values[0], 'bad?????host');
  assert.equal(record.host_values[1], 'second.example');
  assert.equal(record.origin[0].length, 256);
  assert.equal(record.peer, '192.0.2.8?spoof');
  assert.equal(line.split('\n').length, 2);
  assert.doesNotMatch(line, /secret-canary|Authorization|Cookie|[\u001b\u0085\u2028]/);
});

test('synthetic vault logs only allowed fields on host_denied when explicitly enabled', async t => {
  assert(process.env.TMPDIR, 'Set TMPDIR to the configured private scratch directory');
  const root = fs.mkdtempSync(path.join(process.env.TMPDIR, 'proxy-diagnostic-'));
  const directory = path.join(root, 'vault');
  const output: string[] = [];
  const write = t.mock.method(process.stderr, 'write', (chunk: string | Uint8Array) => { output.push(String(chunk)); return true; });
  const publicOrigin = 'https://vault.example';
  const headers = { host: 'synthetic-upstream.example', origin: publicOrigin, 'x-forwarded-host': 'vault.example', 'x-forwarded-proto': 'https',
    'x-forwarded-for': '198.51.100.99', authorization: 'Bearer auth-canary', cookie: 'vault_session=cookie-canary', 'x-extra': 'header-canary' };
  try {
    await initialize(directory, 'synthetic diagnostic passphrase');
    for (const diagnoseProxyHeaders of [undefined, false, true]) {
      const server = await createServer(directory, 0, { publicOrigin, diagnoseProxyHeaders });
      try {
        output.length = 0;
        const response = await server.app.inject({ method: 'POST', url: '/path-canary?query-canary', headers, payload: { secret: 'body-canary' }, remoteAddress: '192.0.2.8' });
        assert.equal(response.statusCode, 403);
        assert.deepEqual(response.json(), { error: 'host_denied' });
        assert.equal(output.length, diagnoseProxyHeaders === true ? 1 : 0);
        if (diagnoseProxyHeaders) {
          assert.deepEqual(JSON.parse(output[0]!), { event: 'host_denied', host_count: 1, host_values: ['synthetic-upstream.example'], origin: [publicOrigin], x_forwarded_host: ['vault.example'], x_forwarded_proto: ['https'], peer: '192.0.2.8' });
          assert.doesNotMatch(output.join(''), /canary|authorization|cookie|198\.51\.100\.99|secret|url|body|error|headers/i);
        }
        output.length = 0;
        assert.equal((await server.app.inject({ url: '/', headers: { host: 'vault.example' } })).statusCode, 200);
        assert.equal((await server.app.inject({ url: '/', headers: { host: 'vault.example', origin: 'https://wrong.example' } })).json().error, 'origin_denied');
        assert.deepEqual(output, []);
      } finally { await server.app.close(); }
    }
  } finally { write.mock.restore(); fs.rmSync(root, { recursive: true, force: true }); }
});
