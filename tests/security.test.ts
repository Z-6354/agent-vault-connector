import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { seal, unseal, deriveKey } from '../src/crypto.js';
import { initialize, Vault } from '../src/vault.js';
import { isPublicAddress, validateDestination, MOCK_OPERATION, MOCK_ORIGIN, restrictedRequest } from '../src/network.js';
import { redactSecrets } from '../src/registry.js';
import { bridgeOrigin } from '../src/bridge.js';
import { privateDirectory, privateFile, readPrivateFile } from '../src/files.js';

function temporary(prefix: string) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `agent-vault-${prefix}`));
}

test('AES-GCM random nonces, scrypt, tamper and authenticated context', async () => {
  const key = await deriveKey('synthetic passphrase for unit test', Buffer.alloc(32, 1));
  try {
    const a = seal(key, Buffer.from('synthetic_crypto_token_1234'), 'context-a');
    const b = seal(key, Buffer.from('synthetic_crypto_token_1234'), 'context-a');
    assert.notEqual(a.nonce, b.nonce);
    assert.notEqual(a.ciphertext, b.ciphertext);
    assert.equal(unseal(key, a, 'context-a').toString(), 'synthetic_crypto_token_1234');
    assert.throws(() => unseal(key, a, 'context-b'));
    for (const field of ['nonce', 'ciphertext', 'tag'] as const) {
      const bytes = Buffer.from(a[field], 'base64');
      bytes[0] = bytes[0]! ^ 1;
      assert.throws(() => unseal(key, { ...a, [field]: bytes.toString('base64') }, 'context-a'));
    }
    assert.throws(() => unseal(randomBytes(32), a, 'context-a'));
  } finally { key.fill(0); }
});

test('outbound policy rejects private/reserved IPv4 and IPv6 and unsafe origins without network', async () => {
  const forbidden = [
    '0.0.0.0', '10.0.0.1', '100.64.0.1', '127.0.0.1', '169.254.169.254', '172.16.0.1', '192.168.0.1',
    '192.0.0.1', '192.0.2.1', '198.18.0.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '240.0.0.1',
    '255.255.255.255', '::', '::1', '::ffff:127.0.0.1', '64:ff9b::7f00:1', 'fc00::1', 'fe80::1', 'ff02::1',
    '2001:db8::1', '2001::1', '2002:7f00:1::', '3fff::1', 'fe80::1%eth0',
  ];
  for (const address of forbidden) assert.equal(isPublicAddress(address), false, address);
  assert.equal(isPublicAddress('8.8.8.8'), true);
  assert.equal(isPublicAddress('2606:4700:4700::1111'), true);
  const base = { origin: 'https://example.test', method: 'GET' as const, path: '/fixed', operationId: 'trusted', mock: false };
  for (const address of forbidden.filter(item => !item.includes('%'))) {
    await assert.rejects(validateDestination(base, async () => [{ address, family: address.includes(':') ? 6 : 4 }]));
  }
  await assert.rejects(validateDestination(base, async () => [{ address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 } ]));
  await assert.rejects(validateDestination(base, async () => []));
  let resolutions = 0;
  const resolved = await validateDestination(base, async () => { resolutions++; return [{ address: '8.8.8.8', family: 4 }]; });
  assert.equal(resolutions, 1);
  assert.equal(resolved.pinned.address, '8.8.8.8');
  for (const origin of ['http://example.test', 'https://example.test:8443', 'https://user:password@example.test', 'https://example.test/path', 'https://example.test?x=1', 'https://example.test#x', 'https://example.test/']) {
    await assert.rejects(validateDestination({ ...base, origin }, async () => [{ address: '8.8.8.8', family: 4 }]));
  }
  for (const requestPath of ['//evil.test', '/a?url=x', '/a#x', '/a\\b', '/a\r\nInjected: yes']) {
    await assert.rejects(validateDestination({ ...base, path: requestPath }));
  }
  await assert.rejects(restrictedRequest({ ...base, origin: 'https://127.0.0.1' }, 'synthetic_test_value', new AbortController().signal));
  const mock = { ...base, origin: MOCK_ORIGIN, path: '/v1/account/summary', operationId: MOCK_OPERATION, mock: true };
  assert.equal((await validateDestination(mock)).pinned.address, '127.0.0.1');
  for (const altered of [{ origin: 'http://127.0.0.1:43122' }, { path: '/arbitrary' }, { operationId: 'arbitrary' }]) await assert.rejects(validateDestination({ ...mock, ...altered }));
});

test('secret scrubber removes nested values and object keys', () => {
  const token = 'synthetic_scrubber_token_123';
  const output = redactSecrets({ [token]: [{ inner: `before ${token} after`, [token]: token }], encoded: Buffer.from(token).toString('base64') }, [token]);
  assert(!JSON.stringify(output).includes(token));
  assert(!JSON.stringify(output).includes(Buffer.from(token).toString('base64')));
  assert(JSON.stringify(output).includes('[REDACTED]'));
});

test('init refuses overwrite; files enforce modes, ownership and symlink rejection', async () => {
  const root = temporary('filesystem-');
  const directory = path.join(root, 'vault');
  try {
    await initialize(directory, 'synthetic unit passphrase');
    const before = fs.readFileSync(path.join(directory, 'vault.sqlite'));
    await assert.rejects(initialize(directory, 'another synthetic passphrase'));
    assert.deepEqual(fs.readFileSync(path.join(directory, 'vault.sqlite')), before);
    assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
    for (const entry of fs.readdirSync(directory)) assert.equal(fs.statSync(path.join(directory, entry)).mode & 0o777, 0o600);
    fs.symlinkSync(directory, path.join(root, 'link'));
    assert.throws(() => privateDirectory(path.join(root, 'link')));
    const execution = path.join(directory, 'execution.key');
    fs.symlinkSync(execution, path.join(root, 'key-link'));
    assert.throws(() => readPrivateFile(path.join(root, 'key-link')));
    fs.chmodSync(execution, 0o644);
    assert.throws(() => privateFile(execution));
    assert.throws(() => new Vault(directory));
    fs.chmodSync(execution, 0o600);
    fs.chmodSync(directory, 0o755);
    assert.throws(() => privateDirectory(directory));
    fs.chmodSync(directory, 0o700);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('lock zeroes retained master key buffer and unlock failures persist across restarts', async () => {
  const root = temporary('lock-');
  const directory = path.join(root, 'vault');
  await initialize(directory, 'synthetic unit passphrase');
  let vault = new Vault(directory);
  try {
    await vault.unlock('synthetic unit passphrase');
    const key = vault.requireUnlocked();
    assert(key.some(byte => byte !== 0));
    vault.lock();
    assert(key.every(byte => byte === 0));
    assert.throws(() => vault.list());
    for (let index = 0; index < 4; index++) await assert.rejects(vault.unlock('wrong passphrase'));
    vault.close();
    vault = new Vault(directory);
    await assert.rejects(vault.unlock('wrong passphrase'));
    await assert.rejects(vault.unlock('synthetic unit passphrase'), /temporarily blocked/);
  } finally { vault.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('bridge requires exact loopback server origin', () => {
  assert.equal(bridgeOrigin('http://127.0.0.1:43120'), 'http://127.0.0.1:43120');
  for (const value of ['http://localhost:43120', 'http://127.0.0.1:43120/', 'https://127.0.0.1:43120', 'http://127.0.0.1:43120/path', 'http://example.test:43120', 'http://user@127.0.0.1:43120']) assert.throws(() => bridgeOrigin(value));
});
