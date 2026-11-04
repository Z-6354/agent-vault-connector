import assert from 'node:assert/strict';
import test from 'node:test';
import { STORAGE_ONLY_POLICY, validateSavePayload } from '../src/registry.js';

const payload = {
  mode: 'create', label: 'Stored password', service_id: 'deepseek-api',
  credential_type: 'password', account_alias: 'main', secret: 'SYNTHETIC-ONLY',
  origin: STORAGE_ONLY_POLICY.origin, environment: 'local', granted_operations: [],
};

test('storage policy accepts arbitrary service names including registered execution services', () => {
  for (const service_id of ['deepseek-api', 'github', 'google', 'custom-user-service']) {
    const saved = validateSavePayload({ ...payload, service_id });
    assert.equal(saved.service_id, service_id);
    assert.deepEqual(saved.granted_operations, []);
    assert.equal(saved.origin, STORAGE_ONLY_POLICY.origin);
  }
});

test('storage policy rejects executable scope for an unknown service', () => {
  assert.throws(() => validateSavePayload({ ...payload, granted_operations: ['login_submit'] }));
});

test('storage policy rejects an unauthorized credential type', () => {
  assert.throws(() => validateSavePayload({ ...payload, credential_type: 'api_key' }));
});

test('storage policy rejects an unapproved origin', () => {
  assert.throws(() => validateSavePayload({ ...payload, origin: 'https://unapproved.example' }));
});

test('storage policy rejects a blank service name', () => {
  assert.throws(() => validateSavePayload({ ...payload, service_id: '   ' }));
});
