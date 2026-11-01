import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Authority } from '../src/contracts.js';
import {
  DelegationExecutor, SyntheticLoopbackDelegationHost, externalReferenceStatus,
  type DelegationGrant, type DelegationCall, type DelegationPolicy, type DelegatedOperation,
} from '../src/delegation.js';

const authority: Authority = { owner_id: 'local', principal_id: 'agent:fixture', client_id: 'fixture-mcp' };
const operation: DelegatedOperation = { id: 'synthetic.account.read', audience: 'synthetic-platform',
  resource: 'account:fixture', scopes: ['account:read'], endpoint: 'synthetic-host:account-summary' };
const grant: DelegationGrant = {
  id: 'fixture-grant', owner_id: 'local', center_principal_id: 'center:fixture',
  upstream_principal_id: 'platform:shared-member', upstream_account: 'fixture-platform-account', host_id: 'fixture-host',
  authorization_source: 'synthetic_fixture_authorization', verification_evidence: 'synthetic_fixture_grant_v1',
  audience: operation.audience, resources: [operation.resource], scopes: operation.scopes,
  operations: [operation.id], endpoints: [operation.endpoint], expires_at: 10_000, revoked: false,
};
const connection = { id: 'delegated-connection', owner_id: 'local' as const, credential_type: 'delegation' as const, delegation_id: grant.id };
const policy = (): DelegationPolicy => ({ operations: [operation.id], audiences: [operation.audience],
  resources: [operation.resource], scopes: [...operation.scopes], endpoints: [operation.endpoint] });

// An actual HTTP loopback fixture, not a real platform API. It validates the center independently
// and performs its own grant/scope checks at execute time, including revocation after verification.
async function fixture() {
  const key = randomBytes(32);
  let currentGrant = structuredClone(grant);
  let now = 1_000;
  let verifyHits = 0, executeHits = 0;
  let mutateAfterVerify: (() => void) | undefined;
  let invalidSignature = false;
  let hangVerification = false;
  const nonces = new Set<string>();
  const server = http.createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', chunk => chunks.push(chunk));
    request.on('end', () => {
      const route = request.url!;
      const body = Buffer.concat(chunks).toString();
      const nonce = String(request.headers['x-synthetic-nonce'] ?? '');
      const expected = createHmac('sha256', key).update(`request\n${route}\n${nonce}\n${body}`).digest();
      const received = Buffer.from(String(request.headers['x-synthetic-signature'] ?? ''), 'hex');
      if (request.method !== 'POST' || !['/synthetic/verify', '/synthetic/execute'].includes(route) ||
          received.length !== expected.length || !timingSafeEqual(expected, received) || nonces.has(nonce)) {
        response.writeHead(403).end(); return;
      }
      nonces.add(nonce);
      const call = JSON.parse(body) as DelegationCall;
      if (call.center_principal_id !== currentGrant.center_principal_id || call.grant.id !== currentGrant.id ||
          call.grant.upstream_principal_id !== currentGrant.upstream_principal_id ||
          call.grant.upstream_account !== currentGrant.upstream_account || call.requesting_principal_id !== authority.principal_id) {
        response.writeHead(403).end(); return;
      }
      let result: unknown;
      if (route === '/synthetic/verify') {
        verifyHits++;
        if (hangVerification) return;
        result = { state: currentGrant.revoked ? 'revoked' : currentGrant.expires_at <= now ? 'expired' : 'active',
          grant: structuredClone(currentGrant), verified_at: now };
        mutateAfterVerify?.();
      } else {
        if (currentGrant.revoked || currentGrant.expires_at <= now || call.operation.audience !== currentGrant.audience ||
            !currentGrant.resources.includes(call.operation.resource) || !currentGrant.operations.includes(call.operation.id) ||
            !currentGrant.endpoints.includes(call.operation.endpoint) || call.operation.scopes.some(scope => !currentGrant.scopes.includes(scope))) {
          response.writeHead(403).end(); return;
        }
        executeHits++;
        result = { upstream_principal_id: currentGrant.upstream_principal_id, upstream_account: currentGrant.upstream_account,
          operation_id: call.operation.id, resource: call.operation.resource, outcome: 'succeeded' };
      }
      const text = JSON.stringify(result);
      const signature = createHmac('sha256', invalidSignature ? Buffer.alloc(32) : key).update(`response\n${route}\n${nonce}\n${text}`).digest('hex');
      response.writeHead(200, { 'content-type': 'application/json', 'x-synthetic-signature': signature }).end(text);
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address() as { port: number };
  const host = new SyntheticLoopbackDelegationHost('fixture-host', `http://127.0.0.1:${address.port}`, key);
  let security = { unlocked: true, epoch: 1 };
  let localPolicy = policy();
  const executor = new DelegationExecutor({ host, centerPrincipalId: 'center:fixture',
    security: () => security, policy: () => localPolicy, clock: () => now, timeoutMs: 100 });
  return { host, executor, get hits() { return { verifyHits, executeHits }; },
    setGrant: (next: DelegationGrant) => { currentGrant = structuredClone(next); },
    setPolicy: (next: DelegationPolicy) => { localPolicy = next; }, setNow: (next: number) => { now = next; },
    setSecurity: (next: typeof security) => { security = next; },
    afterVerify: (callback: () => void) => { mutateAfterVerify = callback; },
    invalidSignature: () => { invalidSignature = true; },
    hangVerification: () => { hangVerification = true; },
    stop: async () => { if (server.listening) await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); },
    close: async () => { host.close(); key.fill(0); if (server.listening) await new Promise<void>(resolve => server.close(() => resolve())); },
  };
}

test('external reference stays metadata-only even when a grant and trusted host exist', async () => {
  const f = await fixture();
  try {
    assert.deepEqual(externalReferenceStatus(), { can_execute: false, status: 'unknown', last_verified_at: null,
      error: 'external_execution_unsupported', needs_user_action: 'Use the original platform connection.' });
    await assert.rejects(f.executor.execute(authority, { ...connection, credential_type: 'external_reference' }, grant, operation), /external_execution_unsupported/);
    assert.deepEqual(f.hits, { verifyHits: 0, executeHits: 0 });
  } finally { await f.close(); }
});

test('synthetic loopback formal host authenticates center and reports actual shared upstream identity', async () => {
  const f = await fixture();
  try {
    const result = await f.executor.execute(authority, connection, grant, operation);
    assert.equal(result.requesting_principal_id, authority.principal_id);
    assert.equal(result.center_principal_id, 'center:fixture');
    assert.equal(result.upstream_principal_id, 'platform:shared-member');
    assert.equal(result.upstream_account, 'fixture-platform-account');
    assert.equal(result.outcome, 'succeeded');
    assert.deepEqual(f.hits, { verifyHits: 1, executeHits: 1 });
    const output = JSON.stringify(result);
    for (const forbidden of ['authorization_source', 'verification_evidence', 'token', 'password', 'shell']) assert(!output.includes(forbidden));
  } finally { await f.close(); }
});

test('delegation requires intersection of local and upstream operations, scopes, audience, resource and endpoint', async () => {
  const f = await fixture();
  try {
    for (const field of ['operations', 'audiences', 'resources', 'scopes', 'endpoints'] as const) {
      f.setPolicy({ ...policy(), [field]: [] });
      await assert.rejects(f.executor.execute(authority, connection, grant, operation), /delegation_scope_denied/);
    }
    f.setPolicy(policy());
    for (const [field, value] of [['operations', ['other']], ['scopes', ['other']], ['resources', ['other']],
      ['endpoints', ['other']], ['audience', 'other']] as const) {
      await assert.rejects(f.executor.execute(authority, connection, { ...grant, [field]: value }, operation), /delegation_scope_denied/);
    }
    assert.deepEqual(f.hits, { verifyHits: 0, executeHits: 0 });
  } finally { await f.close(); }
});

test('missing formal evidence, wrong owner/center/host/upstream identities, expiry and revocation deny without execution', async () => {
  const f = await fixture();
  try {
    await assert.rejects(f.executor.execute(authority, connection, undefined, operation), /external_execution_unsupported/);
    await assert.rejects(f.executor.execute(authority, connection, { ...grant, verification_evidence: '' }, operation), /external_execution_unsupported/);
    for (const changed of [{ center_principal_id: 'other' }, { host_id: 'other' }, { owner_id: 'other' },
      { upstream_principal_id: 'other' }, { upstream_account: 'other' }]) {
      await assert.rejects(f.executor.execute(authority, connection, { ...grant, ...changed } as DelegationGrant, operation));
    }
    await assert.rejects(f.executor.execute(authority, connection, { ...grant, revoked: true }, operation), /delegation_inactive/);
    f.setNow(grant.expires_at);
    await assert.rejects(f.executor.execute(authority, connection, grant, operation), /delegation_inactive/);
    assert.equal(f.hits.executeHits, 0);
  } finally { await f.close(); }
});

test('each call verifies current host grant; revoked/unknown identity/signature/unreachable host deny', async () => {
  const f = await fixture();
  try {
    f.setGrant({ ...grant, revoked: true });
    await assert.rejects(f.executor.execute(authority, connection, grant, operation), /delegation_inactive/);
    f.setGrant({ ...grant, scopes: ['account:write'] });
    await assert.rejects(f.executor.execute(authority, connection, grant, operation), /delegation_identity_mismatch/);
    f.setGrant(grant);
    f.invalidSignature();
    await assert.rejects(f.executor.execute(authority, connection, grant, operation), /delegation_unreachable/);
    await f.stop();
    await assert.rejects(f.executor.execute(authority, connection, grant, operation), /delegation_unreachable/);
    assert.equal(f.hits.executeHits, 0);
  } finally { await f.close(); }
});

test('host rechecks revocation at dispatch, and core epoch/policy are checked again after verification', async () => {
  for (const change of ['revoke', 'lock', 'policy'] as const) {
    const f = await fixture();
    try {
      f.afterVerify(() => {
        if (change === 'revoke') f.setGrant({ ...grant, revoked: true });
        if (change === 'lock') f.setSecurity({ unlocked: false, epoch: 2 });
        if (change === 'policy') f.setPolicy({ ...policy(), scopes: [] });
      });
      await assert.rejects(f.executor.execute(authority, connection, grant, operation));
      assert.equal(f.hits.executeHits, 0);
    } finally { await f.close(); }
  }
});

test('unresponsive host times out before dispatch with no upstream execution', async () => {
  const f = await fixture();
  try {
    f.hangVerification();
    await assert.rejects(f.executor.execute(authority, connection, grant, operation), /delegation_unreachable/);
    assert.equal(f.hits.verifyHits, 1);
    assert.equal(f.hits.executeHits, 0);
  } finally { await f.close(); }
});

test('synthetic host endpoint cannot be redirected to a nonloopback or arbitrary URL', () => {
  for (const origin of ['http://localhost:1234', 'http://example.test:1234', 'https://127.0.0.1:1234',
    'http://127.0.0.1:1234/', 'http://user@127.0.0.1:1234', 'http://127.0.0.1:1234/path']) {
    assert.throws(() => new SyntheticLoopbackDelegationHost('fixture', origin, randomBytes(32)), /invalid_synthetic_host/);
  }
});
