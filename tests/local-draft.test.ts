import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { Authority, SavePayload } from '../src/contracts.js';
import { Vault, initialize } from '../src/vault.js';
import { LocalDraftSession, bindVaultLocalDraftCore, type LocalInference, type LocalTranscriber } from '../src/local-draft.js';

const passphrase = 'synthetic local draft passphrase';
const authority: Authority = { owner_id: 'local', principal_id: 'admin:local', client_id: 'local-draft-fixture', session_id: 'synthetic-session' };
const canary = 'synthetic_local_draft_exact_secret_123456';
const payload: SavePayload = { mode: 'create', label: 'Synthetic draft', service_id: 'synthetic-mock', credential_type: 'api_key',
  account_alias: 'synthetic-account', secret: canary, origin: 'http://127.0.0.1:43121', environment: 'local', granted_operations: ['mock.account_summary'] };

async function fixture(options: { infer?: LocalInference['infer']; asr?: LocalTranscriber; timeout?: number } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'avc-draft-'));
  const directory = path.join(root, 'vault');
  let now = Date.now();
  await initialize(directory, passphrase);
  const vault = new Vault(directory, { clock: () => now });
  await vault.unlock(passphrase);
  let inferenceCalls = 0, approvalCalls = 0, saveCalls = 0;
  const core = bindVaultLocalDraftCore(vault, (session, csrf) => {
    if (session !== authority.session_id || csrf !== 'synthetic-csrf') throw new Error('confirmation_denied');
    return authority;
  });
  const session = new LocalDraftSession({ authority, security: () => ({ unlocked: vault.unlocked, epoch: vault.epoch }),
    clock: () => now, inferenceTimeoutMs: options.timeout,
    inference: { endpoint: 'http://127.0.0.1:9999/explicit-fixture', evidence: 'synthetic_fixture',
      infer: async (text, signal) => { inferenceCalls++; return options.infer ? options.infer(text, signal) : structuredClone(payload); } },
    ...(options.asr ? { transcriber: options.asr } : {}),
    core: { ...core, approve: (...args) => { approvalCalls++; return core.approve(...args); },
      save: (...args) => { saveCalls++; return core.save(...args); } },
  });
  const confirm = (card: { draft_id: string; draft_version: number }) => session.confirm({ administrator_session: authority.session_id!,
    csrf: 'synthetic-csrf', ...card, request_id: vault.prepareRequest(authority, 'save_connection') });
  return { vault, session, directory, confirm, counts: () => ({ inferenceCalls, approvalCalls, saveCalls }),
    advance: (amount: number) => { now += amount; },
    close: () => { session.dispose(); vault.close(); fs.rmSync(root, { recursive: true, force: true }); } };
}

test('injected synthetic inference creates only memory draft; real core saves exact secret after UI confirmation', async () => {
  let seenInput = '';
  const f = await fixture({ infer: async text => { seenInput = text; return structuredClone(payload); } });
  try {
    const input = `Save this synthetic service key exactly: ${canary}`;
    const card = await f.session.fromText(input);
    assert.equal(seenInput, input);
    assert.equal(card.secret_mask, '••••••••');
    assert(!JSON.stringify(card).includes(canary));
    assert(!('secret' in card));
    assert(!('approval_token' in card));
    assert.equal(f.vault.list().length, 0);
    assert.deepEqual(f.counts(), { inferenceCalls: 1, approvalCalls: 0, saveCalls: 0 });
    for (const name of fs.readdirSync(f.directory)) assert(!fs.readFileSync(path.join(f.directory, name)).includes(Buffer.from(canary)));
    const result = await f.confirm(card);
    assert.equal(result.record_version, 1);
    assert.equal(f.vault.list().length, 1);
    assert.deepEqual(f.counts(), { inferenceCalls: 1, approvalCalls: 1, saveCalls: 1 });
    await f.vault.withToken(result.id, async secret => { assert.equal(secret, canary); });
    for (const name of fs.readdirSync(f.directory)) assert(!fs.readFileSync(path.join(f.directory, name)).includes(Buffer.from(canary)));
    await assert.rejects(f.confirm(card), /draft_mismatch/);
    assert.equal(f.vault.list().length, 1);
    assert.equal(f.session.locality.completely_local_verified, false);
    assert.equal(f.session.locality.inference, 'synthetic_fixture');
  } finally { f.close(); }
});

test('model cannot self-confirm or persist unknown approval fields; secret whitespace is preserved', async () => {
  const fake = await fixture({ infer: async () => ({ ...payload, confirmed: true, approval_token: 'model-made-up' }) });
  try {
    await assert.rejects(fake.session.fromText('synthetic input'), /invalid_inference_draft/);
    assert.equal(fake.vault.list().length, 0);
    assert.equal(fake.counts().saveCalls, 0);
  } finally { fake.close(); }
  const secret = '  synthetic password\nwith exact bytes  ';
  const f = await fixture({ infer: async () => ({ ...payload, service_id: 'synthetic-login', credential_type: 'password',
    origin: 'http://127.0.0.1:43122', granted_operations: ['browser_fill'], secret }) });
  try {
    const card = await f.session.fromText('input with synthetic password');
    const record = await f.confirm(card);
    await f.vault.withToken(record.id, async actual => { assert.equal(actual, secret); });
  } finally { f.close(); }
});

test('confirmation checks session/CSRF and core-bound draft version; bad confirmation saves nothing', async () => {
  const f = await fixture();
  try {
    const card = await f.session.fromText('synthetic input');
    const request = { administrator_session: authority.session_id!, csrf: 'bad', draft_id: card.draft_id,
      draft_version: card.draft_version, request_id: f.vault.prepareRequest(authority, 'save_connection') };
    await assert.rejects(f.session.confirm(request), /confirmation_denied/);
    await assert.rejects(f.session.confirm({ ...request, csrf: 'synthetic-csrf', administrator_session: 'model-session' }), /confirmation_denied/);
    await assert.rejects(f.confirm({ ...card, draft_version: card.draft_version + 1 }), /draft_mismatch/);
    assert.equal(f.vault.list().length, 0);
    await f.confirm(card);
    assert.equal(f.vault.list().length, 1);
  } finally { f.close(); }
});

test('cancel, draft expiry, editing and lock invalidate old memory draft with zero saves', async () => {
  for (const action of ['cancel', 'expire', 'edit', 'lock'] as const) {
    const f = await fixture();
    try {
      const card = await f.session.fromText('synthetic initial input');
      if (action === 'cancel') f.session.cancel();
      if (action === 'expire') f.advance(10 * 60_000 + 1);
      if (action === 'edit') await f.session.fromText('synthetic edited input');
      if (action === 'lock') { f.vault.lock(); f.session.cancel(); await f.vault.unlock(passphrase); }
      await assert.rejects(f.confirm(card));
      assert.equal(f.vault.list().length, 0);
      assert.equal(f.counts().saveCalls, 0);
      assert.throws(() => f.vault.draftPayload(authority, card.draft_id));
    } finally { f.close(); }
  }
});

test('inference timeout/cancel/lock ignores late results and creates no core draft or persistent record', async () => {
  for (const action of ['timeout', 'cancel', 'lock'] as const) {
    let resolve!: (value: unknown) => void;
    let signalSeen: AbortSignal | undefined;
    const f = await fixture({ timeout: 15, infer: async (_text, signal) => {
      signalSeen = signal; return new Promise(value => { resolve = value; });
    } });
    try {
      const promise = f.session.fromText('synthetic input');
      const rejection = assert.rejects(promise);
      if (action === 'cancel') f.session.cancel();
      if (action === 'lock') { f.vault.lock(); resolve(payload); }
      await rejection;
      if (action !== 'lock') assert.equal(signalSeen?.aborted, true);
      resolve(payload);
      await Promise.resolve();
      if (!f.vault.unlocked) await f.vault.unlock(passphrase);
      assert.equal(f.vault.list().length, 0);
      assert.deepEqual(f.counts(), { inferenceCalls: 1, approvalCalls: 0, saveCalls: 0 });
    } finally { f.close(); }
  }
});

test('late synthetic ASR after cancellation never dispatches inference or persists a draft', async () => {
  let complete!: (text: string) => void;
  const f = await fixture({ asr: { endpoint: 'http://127.0.0.1:9998/explicit-asr-fixture', evidence: 'synthetic_fixture',
    transcribe: async () => new Promise(resolve => { complete = resolve; }) } });
  try {
    const pending = f.session.fromAudio(new Uint8Array([1, 2, 3]));
    const rejection = assert.rejects(pending, /draft_cancelled_or_timed_out/);
    f.session.cancel();
    await rejection;
    complete('synthetic late fixture transcript');
    await new Promise<void>(resolve => setImmediate(resolve));
    assert.equal(f.counts().inferenceCalls, 0);
    assert.equal(f.counts().saveCalls, 0);
    assert.equal(f.vault.list().length, 0);
  } finally { f.close(); }
});

test('synthetic ASR fixture is explicitly labeled; absent ASR and remote endpoints are refused', async () => {
  let audioSeen: number[] | undefined;
  const f = await fixture({ asr: { endpoint: 'http://127.0.0.1:9998/explicit-asr-fixture', evidence: 'synthetic_fixture',
    transcribe: async audio => { audioSeen = [...audio]; return 'synthetic prewritten fixture transcript'; } } });
  try {
    const card = await f.session.fromAudio(new Uint8Array([1, 2, 3]));
    assert.deepEqual(audioSeen, [1, 2, 3]);
    assert.equal(f.session.locality.asr, 'synthetic_fixture');
    assert.equal(f.session.locality.completely_local_verified, false);
    assert.equal(f.vault.list().length, 0);
    f.session.cancel();
    await assert.rejects(f.confirm(card), /draft_mismatch/);
  } finally { f.close(); }
  const absent = await fixture();
  try {
    await assert.rejects(absent.session.fromAudio(new Uint8Array([1])), /asr_unavailable/);
    for (const url of ['https://external.example/model', 'http://localhost:9999', 'http://user@127.0.0.1:9999', 'http://127.0.0.1:9999?key=test']) {
      assert.throws(() => new LocalDraftSession({ authority, core: bindVaultLocalDraftCore(absent.vault, () => authority),
        security: () => ({ unlocked: true, epoch: 1 }), inference: { endpoint: url, evidence: 'synthetic_fixture', infer: async () => payload } }), /local_endpoint_required/);
    }
  } finally { absent.close(); }
});
