import Database from 'better-sqlite3';
import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkDataFiles, createPrivateFile, privateDirectory, privateFile, readPrivateFile } from './files.js';
import { deriveKey, seal, unseal, type Sealed } from './crypto.js';
import { validateSavePayload } from './registry.js';
import type { Authority, SavePayload, DraftCard, SaveRequest, Metadata, ConnectionStatus, OperationInput, OperationDefinition, OperationResult, OperationState } from './contracts.js';
export type { Metadata } from './contracts.js';

const verifierContext = 'agent-vault:v1:local:verifier';
const verifierValue = 'agent-vault-key-check-v1';
export const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const DAY = 86_400_000;
const DRAFT_TTL = 10 * 60_000;
const APPROVAL_TTL = 2 * 60_000;
const random = () => randomBytes(32).toString('hex');
const equal = (a: string, b: string) => {
  const aa = Buffer.from(a), bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
};
export function canonical(value: unknown): string {
  if (value === undefined) return '["undefined"]';
  if (value === null) return '["null"]';
  if (Array.isArray(value)) return `["array",${value.map(canonical).join(',')}]`;
  if (typeof value === 'object') return `["object",${Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `[${JSON.stringify(k)},${canonical(v)}]`).join(',')}]`;
  if (typeof value === 'string' || typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return JSON.stringify([typeof value, value]);
  throw new VaultError(400, 'Invalid canonical payload');
}
interface Meta { salt: string; verifier: string; execution_hash: string; unlock_failures: number; unlock_blocked_until: number; auth_salt: string | null; auth_verifier: string | null; security_epoch: number }
interface Row extends Omit<Metadata, 'granted_operations' | 'can_execute' | 'storage_mode'> { encrypted: string; encryption_context: string; granted_operations: string }
const metadataColumns = 'id,owner_id,label,provider,service_id,credential_type,account_alias,origin,environment,granted_operations,record_version,status_version,material_version,status,last_verified_at,created_at,updated_at';
interface RequestRow {
  owner_id: string; principal_id: string; operation_name: string; request_id: string; registered_at: number; retain_until: number;
  canonical_encrypted: string | null; result: string | null; state: string; connection_id: string | null; business_target: string | null;
  semantics: string | null; operation_status_version: number; dispatch_epoch: number | null;
}
interface Draft { auth: Authority; payload: SavePayload; card: DraftCard; epoch: number; approval?: { token: string; expires: number; session: string; consumed: boolean } }
export interface VaultOptions { clock?: () => number; enrollmentTtlMs?: number; fault?: (point: 'after_write' | 'after_approval_consumed' | 'after_request_result') => void }
const migration = (name: string) => fs.readFileSync(fileURLToPath(new URL(`../../migrations/${name}`, import.meta.url)), 'utf8');
export class VaultError extends Error { constructor(public status: number, message: string) { super(message); } }

function migrate(db: Database.Database): boolean {
  const version = Number(db.pragma('user_version', { simple: true }));
  if (![1, 2, 3, 4].includes(version)) throw new Error('Unsupported database version');
  if (version < 4) db.transaction(() => {
    if (version === 1) db.exec(migration('002-enrollment.sql'));
    if (version < 3) db.exec(migration('003-v1-contracts.sql'));
    db.exec(migration('004-oauth-clients.sql'));
  })();
  return version < 3;
}

export async function initialize(directory: string, passphrase: string): Promise<void> {
  process.umask(0o077);
  directory = privateDirectory(directory, true);
  if (fs.readdirSync(directory).length) throw new Error('Initialization requires an empty data directory; existing data will not be overwritten');
  if (passphrase.length < 12 || passphrase.length > 1024) throw new Error('Passphrase must be 12–1024 characters');
  const filename = path.join(directory, 'vault.sqlite');
  createPrivateFile(filename, '');
  const db = new Database(filename);
  let key: Buffer | undefined, auth: Buffer | undefined;
  try {
    db.pragma('journal_mode = DELETE'); db.pragma('secure_delete = ON');
    const salt = randomBytes(32), authSalt = randomBytes(32);
    key = await deriveKey(passphrase, salt);
    auth = await deriveKey(passphrase, Buffer.concat([Buffer.from('agent-vault:authentication:v1:'), authSalt]));
    const execution = random();
    db.transaction(() => {
      db.exec(migration('001-initial.sql'));
      db.prepare('INSERT INTO vault_meta (id, version, salt, verifier, execution_hash) VALUES (1, 1, ?, ?, ?)')
        .run(salt.toString('base64'), JSON.stringify(seal(key!, Buffer.from(verifierValue), verifierContext)), digest(execution));
      db.exec(migration('002-enrollment.sql')); db.exec(migration('003-v1-contracts.sql')); db.exec(migration('004-oauth-clients.sql'));
      db.prepare('UPDATE vault_meta SET auth_salt=?,auth_verifier=? WHERE id=1').run(authSalt.toString('base64'), auth!.toString('base64'));
    })();
    createPrivateFile(path.join(directory, 'execution.key'), `${execution}\n`);
    createPrivateFile(path.join(directory, 'request-signing.key'), randomBytes(32));
  } finally { key?.fill(0); auth?.fill(0); db.close(); }
  checkDataFiles(directory);
}

export class Vault {
  private db: Database.Database;
  private key?: Buffer;
  private keyEpoch?: number;
  private signingKey: Buffer;
  private generation = 0;
  private unlocking = false;
  private controllers = new Set<AbortController>();
  private drafts = new Map<string, Draft>();
  private now: () => number;
  constructor(readonly directory: string, private options: VaultOptions = {}) {
    process.umask(0o077); privateDirectory(directory); checkDataFiles(directory);
    this.now = options.clock ?? Date.now;
    const filename = path.join(directory, 'vault.sqlite'); privateFile(filename);
    this.db = new Database(filename, { fileMustExist: true });
    this.db.pragma('journal_mode = DELETE'); this.db.pragma('secure_delete = ON');
    this.db.pragma('temp_store = MEMORY'); this.db.pragma('busy_timeout = 2000'); this.db.pragma('foreign_keys = ON');
    const previousVersion = Number(this.db.pragma('user_version', {simple:true}));
    if ([1,2].includes(previousVersion)) {
      const backupPath = path.join(directory, `vault.pre-v${previousVersion}-to-v3.sqlite`);
      if (!fs.existsSync(backupPath)) createPrivateFile(backupPath,fs.readFileSync(filename));
      else privateFile(backupPath);
    }
    if (previousVersion === 3) {
      const backupPath = path.join(directory, 'vault.pre-v3-to-v4.sqlite');
      if (!fs.existsSync(backupPath)) createPrivateFile(backupPath, fs.readFileSync(filename));
      else privateFile(backupPath);
    }
    const upgraded = migrate(this.db);
    const signingPath = path.join(directory, 'request-signing.key');
    if (upgraded && !fs.existsSync(signingPath)) createPrivateFile(signingPath, randomBytes(32));
    try { this.signingKey = readPrivateFile(signingPath); if (this.signingKey.length !== 32) throw new Error('Invalid request signing key'); }
    catch (error) { this.db.close(); throw error; }
    this.db.transaction(() => {
      this.db.prepare('UPDATE vault_meta SET security_epoch=security_epoch+1 WHERE id=1').run();
      this.db.prepare("UPDATE requests SET state='outcome_unknown',operation_status_version=operation_status_version+1 WHERE state='dispatching'").run();
      this.db.prepare("UPDATE requests SET state='failed_before_dispatch',operation_status_version=operation_status_version+1 WHERE state='accepted'").run();
      this.db.prepare("UPDATE material_leases SET state='outcome_unknown' WHERE state='pending'").run();
    })();
    this.meta();
    this.cleanupRetention();
  }
  private meta(): Meta {
    const meta = this.db.prepare('SELECT * FROM vault_meta WHERE id=1').get() as Meta | undefined;
    if (!meta) throw new Error('Invalid vault'); return meta;
  }
  get epoch(): number { return this.meta().security_epoch; }
  get unlocked(): boolean {
    if (this.key && this.keyEpoch !== this.epoch) {
      this.key.fill(0); this.key = undefined; this.keyEpoch = undefined; this.generation++; this.drafts.clear();
      for (const controller of this.controllers) controller.abort(); this.controllers.clear();
    }
    return this.key !== undefined;
  }
  executionAuthorized(value: string): boolean { return equal(digest(value), this.meta().execution_hash); }
  private authority(auth: Authority): void {
    if (auth.owner_id !== 'local' || !/^[a-zA-Z0-9:._-]{1,160}$/.test(auth.principal_id) || !/^[a-zA-Z0-9:._-]{1,160}$/.test(auth.client_id)) throw new VaultError(403, 'Authority denied');
  }
  private failure(meta: Meta): never {
    const failures = meta.unlock_failures + 1;
    this.db.prepare('UPDATE vault_meta SET unlock_failures=?,unlock_blocked_until=? WHERE id=1').run(failures, failures >= 5 ? this.now() + 60_000 : 0);
    if (failures >= 5) this.lock();
    throw new VaultError(401, 'Unlock failed');
  }
  private async legacyCandidate(passphrase: string, meta: Meta): Promise<Buffer> {
    const candidate = await deriveKey(passphrase, Buffer.from(meta.salt, 'base64'));
    try {
      const check = unseal(candidate, JSON.parse(meta.verifier) as Sealed, verifierContext);
      const valid = equal(check.toString(), verifierValue); check.fill(0);
      if (!valid) throw new Error('Invalid key'); return candidate;
    } catch { candidate.fill(0); return this.failure(meta); }
  }
  async authenticate(passphrase: string): Promise<void> {
    if (this.unlocking) throw new VaultError(429, 'Unlock busy');
    const meta = this.meta();
    if (this.now() < meta.unlock_blocked_until) throw new VaultError(429, 'Unlock temporarily blocked');
    this.unlocking = true; const generation = this.generation;
    let candidate: Buffer | undefined;
    try {
      if (meta.auth_salt && meta.auth_verifier) {
        candidate = await deriveKey(passphrase, Buffer.concat([Buffer.from('agent-vault:authentication:v1:'), Buffer.from(meta.auth_salt, 'base64')]));
        if (!equal(candidate.toString('base64'), meta.auth_verifier)) this.failure(meta);
      } else {
        const legacy = await this.legacyCandidate(passphrase, meta); legacy.fill(0);
        const authSalt = randomBytes(32);
        candidate = await deriveKey(passphrase, Buffer.concat([Buffer.from('agent-vault:authentication:v1:'), authSalt]));
        if (generation !== this.generation || meta.security_epoch !== this.epoch) throw new VaultError(423, 'Vault locked');
        this.db.prepare('UPDATE vault_meta SET auth_salt=?,auth_verifier=? WHERE id=1').run(authSalt.toString('base64'), candidate.toString('base64'));
      }
      if (generation !== this.generation || meta.security_epoch !== this.epoch) throw new VaultError(423, 'Vault locked');
      this.db.prepare('UPDATE vault_meta SET unlock_failures=0,unlock_blocked_until=0 WHERE id=1').run();
    } finally { candidate?.fill(0); this.unlocking = false; }
  }
  async unlock(passphrase: string): Promise<void> {
    if (this.unlocking) throw new VaultError(429, 'Unlock busy');
    const meta = this.meta(); if (this.now() < meta.unlock_blocked_until) throw new VaultError(429, 'Unlock temporarily blocked');
    this.unlocking = true; const generation = this.generation;
    let candidate: Buffer | undefined;
    try {
      candidate = await this.legacyCandidate(passphrase, meta);
      if (generation !== this.generation || meta.security_epoch !== this.epoch) throw new VaultError(423, 'Vault locked');
      this.key?.fill(0); this.key = candidate; this.keyEpoch = this.epoch; candidate = undefined;
      this.db.prepare('UPDATE vault_meta SET unlock_failures=0,unlock_blocked_until=0 WHERE id=1').run();
    } finally { candidate?.fill(0); this.unlocking = false; }
  }
  lock(): void {
    this.db.transaction(() => {
      this.db.prepare('UPDATE vault_meta SET security_epoch=security_epoch+1 WHERE id=1').run();
      this.generation++; this.key?.fill(0); this.key = undefined; this.keyEpoch = undefined; this.drafts.clear();
    })();
    for (const controller of this.controllers) controller.abort(); this.controllers.clear();
  }
  requireUnlocked(): Buffer { if (!this.unlocked) throw new VaultError(423, 'Vault locked'); return this.key!; }
  private metadata(row: Omit<Row,'encrypted'|'encryption_context'> & Partial<Pick<Row,'encrypted'|'encryption_context'>>): Metadata {
    const { encrypted: _encrypted, encryption_context: _context, ...rest } = row;
    const unresolved = !!this.db.prepare('SELECT 1 FROM material_leases WHERE connection_id=?').get(row.id);
    const operations = JSON.parse(row.granted_operations) as string[];
    return { ...rest, storage_mode: row.credential_type === 'external_reference' ? 'external_reference' : 'managed', granted_operations: operations, can_execute: row.credential_type !== 'external_reference' && row.status === 'active' && operations.length > 0 && !unresolved, material_change_unresolved: unresolved };
  }
  private row(id: string): Row {
    const row = this.db.prepare("SELECT * FROM credentials WHERE id=? AND owner_id='local'").get(id) as Row | undefined;
    if (!row) throw new VaultError(404, 'Connection not found'); return row;
  }
  list(): Metadata[] { this.requireUnlocked(); return (this.db.prepare(`SELECT ${metadataColumns} FROM credentials WHERE owner_id='local' ORDER BY created_at,id`).all() as Omit<Row,'encrypted'|'encryption_context'>[]).map(row => this.metadata(row)); }
  get(id: string): Metadata {
    this.requireUnlocked();
    const row=this.db.prepare(`SELECT ${metadataColumns} FROM credentials WHERE id=? AND owner_id='local'`).get(id) as Omit<Row,'encrypted'|'encryption_context'> | undefined;
    if (!row) throw new VaultError(404,'Connection not found'); return this.metadata(row);
  }
  private audit(auth: Authority, action: string, record?: Metadata): void {
    this.db.prepare('INSERT INTO audit_events(owner_id,principal_id,action,record_id,record_version,status_version,time) VALUES(?,?,?,?,?,?,?)')
      .run(auth.owner_id, auth.principal_id, action, record?.id ?? null, record?.record_version ?? null, record?.status_version ?? null, this.now());
  }
  createDraft(auth: Authority, input: SavePayload): DraftCard {
    this.authority(auth); this.requireUnlocked();
    if (!auth.session_id) throw new VaultError(403, 'Admin session required');
    let payload: SavePayload;
    try { payload = structuredClone(validateSavePayload(input)); } catch { throw new VaultError(400, 'Invalid connection payload'); }
    for (const [id,draft] of this.drafts) if (draft.card.expires_at <= this.now()) this.drafts.delete(id);
    if (this.drafts.size >= 64) throw new VaultError(429, 'Too many drafts');
    if (payload.mode === 'replace') {
      const old = this.row(payload.target_record_id!);
      if (old.record_version !== payload.expected_record_version) throw new VaultError(409, 'record_version_conflict');
    }
    const { secret: _secret, ...preview } = payload;
    const card: DraftCard = { ...preview, draft_id: randomUUID(), draft_version: 1, expires_at: this.now() + DRAFT_TTL };
    this.drafts.set(card.draft_id, { auth: structuredClone(auth), payload, card, epoch: this.epoch });
    return structuredClone(card);
  }
  private draft(auth: Authority, id: string, version?: number): Draft {
    this.authority(auth); this.requireUnlocked(); const draft = this.drafts.get(id);
    if (!draft || draft.card.expires_at <= this.now() || draft.epoch !== this.epoch) { this.drafts.delete(id); throw new VaultError(410, 'Draft expired'); }
    if (auth.owner_id !== draft.auth.owner_id || auth.principal_id !== draft.auth.principal_id || auth.client_id !== draft.auth.client_id || auth.session_id !== draft.auth.session_id) throw new VaultError(403, 'Draft authority denied');
    if (version !== undefined && version !== draft.card.draft_version) throw new VaultError(409, 'draft_version_conflict'); return draft;
  }
  draftPayload(auth: Authority, id: string): SavePayload { return structuredClone(this.draft(auth,id).payload); }
  approveDraft(auth: Authority, id: string, version: number): { approval_token: string; expires_at: number } {
    const draft = this.draft(auth,id,version);
    if (!auth.session_id) throw new VaultError(403, 'Admin confirmation required');
    const expires = Math.min(this.now() + APPROVAL_TTL, draft.card.expires_at);
    const token = random(); draft.approval = { token, expires, session: auth.session_id, consumed: false };
    return { approval_token: token, expires_at: expires };
  }
  cancelDraft(auth: Authority, id: string): void { this.draft(auth,id); this.drafts.delete(id); }
  prepareRequest(auth: Authority, operation_name: string): string {
    this.authority(auth); this.requireUnlocked();
    if (!/^[a-zA-Z0-9_.:-]{1,100}$/.test(operation_name)) throw new VaultError(400, 'Invalid operation');
    const body = Buffer.from(JSON.stringify([1, this.now(), random(), auth.owner_id, auth.principal_id, operation_name])).toString('base64url');
    return `${body}.${createHmac('sha256', this.signingKey).update(body).digest('base64url')}`;
  }
  private ticket(auth: Authority, operation: string, ticket: string): number {
    this.authority(auth);
    if (typeof ticket !== 'string' || ticket.length > 2048) throw new VaultError(400, 'request_invalid');
    const parts = ticket.split('.'); if (parts.length !== 2 || !equal(parts[1]!, createHmac('sha256', this.signingKey).update(parts[0]!).digest('base64url'))) throw new VaultError(400, 'request_invalid');
    let fields: unknown; try { fields = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString()); } catch { throw new VaultError(400, 'request_invalid'); }
    if (!Array.isArray(fields) || fields.length !== 6 || fields[0] !== 1 || !Number.isSafeInteger(fields[1]) || fields[1] > this.now() || fields[3] !== auth.owner_id || fields[4] !== auth.principal_id || fields[5] !== operation) throw new VaultError(403, 'request_scope_denied');
    return fields[1] as number;
  }
  private requestRow(auth: Authority, operation: string, ticket: string): RequestRow | undefined {
    return this.db.prepare('SELECT * FROM requests WHERE owner_id=? AND principal_id=? AND operation_name=? AND request_id=?').get(auth.owner_id,auth.principal_id,operation,ticket) as RequestRow | undefined;
  }
  private requestContext(auth: Authority, operation: string, ticket: string): string { return `agent-vault:v3:request:${auth.owner_id}:${auth.principal_id}:${operation}:${ticket}`; }
  private encryptedCanonical(auth: Authority, operation: string, ticket: string, input: unknown): string {
    const bytes = Buffer.from(canonical(input)); try { return JSON.stringify(seal(this.requireUnlocked(),bytes,this.requestContext(auth,operation,ticket))); } finally { bytes.fill(0); }
  }
  private replay(auth: Authority, operation: string, ticket: string, input: unknown): RequestRow | undefined {
    const issued = this.ticket(auth,operation,ticket); const row = this.requestRow(auth,operation,ticket);
    if (row) {
      if (!row.canonical_encrypted || (row.retain_until <= this.now() && !['accepted','dispatching','outcome_unknown'].includes(row.state))) throw new VaultError(410, 'result_unavailable');
      const bytes = unseal(this.requireUnlocked(),JSON.parse(row.canonical_encrypted) as Sealed,this.requestContext(auth,operation,ticket));
      try { if (!equal(bytes.toString(),canonical(input))) throw new VaultError(409, 'idempotency_conflict'); } finally { bytes.fill(0); }
      return row;
    }
    if (this.now() - issued >= DAY) throw new VaultError(410, 'request_expired'); return undefined;
  }
  saveApproved(auth: Authority, request: SaveRequest): Metadata {
    this.authority(auth); this.requireUnlocked();
    const operation = 'save_connection';
    // Approval handles and draft IDs are transport details; immutable full payload is comparison material.
    const saved = this.db.transaction(() => {
      this.requireUnlocked();
      const existing = this.replay(auth,operation,request.request_id,request.payload);
      if (existing) { if (!existing.result) throw new VaultError(410,'result_unavailable'); return JSON.parse(existing.result) as Metadata; }
      if (this.db.prepare('SELECT 1 FROM consumed_drafts WHERE draft_id=?').get(request.draft_id)) throw new VaultError(403,'Approval consumed');
      const draft = this.draft(auth,request.draft_id,request.draft_version); const approval = draft.approval;
      if (!approval || approval.consumed || approval.expires <= this.now() || approval.session !== auth.session_id || !equal(approval.token,request.approval_token)) throw new VaultError(403,'Approval required');
      if (!equal(canonical(request.payload),canonical(draft.payload))) throw new VaultError(409,'approval_payload_conflict');
      const p = draft.payload;
      let id = p.target_record_id ?? randomUUID(), recordVersion = 1, statusVersion = 1, materialVersion = 1;
      const stamp = new Date(this.now()).toISOString();
      const aad = `agent-vault:v3:record:local:${id}:${p.service_id}:${p.credential_type}`;
      let encrypted = '';
      if (p.credential_type !== 'external_reference') {
        const plaintext = Buffer.from(p.secret);
        try { encrypted = JSON.stringify(seal(this.requireUnlocked(),plaintext,aad)); } finally { plaintext.fill(0); }
      }
      try {
        if (p.mode === 'replace') {
          const old = this.row(id);
          if (old.record_version !== p.expected_record_version) throw new VaultError(409,'record_version_conflict');
          if (this.db.prepare('SELECT 1 FROM material_leases WHERE connection_id=?').get(id)) throw new VaultError(409,'material_change_unresolved');
          recordVersion = old.record_version + 1; statusVersion = old.status_version + 1; materialVersion = old.material_version + 1;
          this.db.prepare('UPDATE credentials SET label=?,provider=?,service_id=?,credential_type=?,account_alias=?,origin=?,environment=?,encrypted=?,encryption_context=?,granted_operations=?,record_version=?,status_version=?,material_version=?,status=?,last_verified_at=NULL,updated_at=? WHERE id=? AND record_version=?')
            .run(p.label,p.service_id,p.service_id,p.credential_type,p.account_alias,p.origin,p.environment,encrypted,aad,JSON.stringify(p.granted_operations),recordVersion,statusVersion,materialVersion,old.status === 'active' && p.credential_type === 'oauth' ? 'needs_user_action' : old.status,stamp,id,p.expected_record_version!);
        } else {
          this.db.prepare('INSERT INTO credentials(id,owner_id,label,provider,service_id,credential_type,account_alias,origin,environment,encrypted,encryption_context,granted_operations,record_version,status_version,material_version,status,last_verified_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
            .run(id,auth.owner_id,p.label,p.service_id,p.service_id,p.credential_type,p.account_alias,p.origin,p.environment,encrypted,aad,JSON.stringify(p.granted_operations),1,1,1,p.credential_type === 'external_reference' ? 'unknown' : p.credential_type === 'oauth' ? 'needs_user_action' : 'active',null,stamp,stamp);
        }
      } catch (error) { if ((error as {code?:string}).code?.startsWith('SQLITE_CONSTRAINT')) throw new VaultError(409,'connection_identity_conflict'); throw error; }
      this.options.fault?.('after_write');
      const record = this.metadata(this.row(id));
      const comparison = this.encryptedCanonical(auth,operation,request.request_id,p);
      this.db.prepare('INSERT INTO requests(owner_id,principal_id,operation_name,request_id,registered_at,retain_until,canonical_encrypted,result,state,connection_id) VALUES(?,?,?,?,?,?,?,?,?,?)')
        .run(auth.owner_id,auth.principal_id,operation,request.request_id,this.now(),this.now()+7*DAY,comparison,JSON.stringify(record),'completed',id);
      this.db.prepare('INSERT INTO consumed_drafts(draft_id,epoch,request_id,consumed_at) VALUES(?,?,?,?)').run(request.draft_id,this.epoch,request.request_id,this.now());
      this.options.fault?.('after_approval_consumed');
      this.audit(auth,p.mode === 'create' ? 'connection_created' : 'connection_replaced',record);
      this.options.fault?.('after_request_result');
      return record;
    })();
    // Release committed secret drafts only after the database commit succeeds. A rollback retains the approval.
    this.drafts.delete(request.draft_id);
    return saved;
  }
  getSaveResult(auth: Authority, request_id: string): Metadata {
    this.authority(auth); this.requireUnlocked();
    if (auth.principal_id !== 'admin' || !auth.session_id || auth.client_id !== 'management') throw new VaultError(403,'Admin session required');
    const issued = this.ticket(auth,'save_connection',request_id);
    const row = this.requestRow(auth,'save_connection',request_id);
    if (!row) throw new VaultError(this.now()-issued >= DAY ? 410 : 404,this.now()-issued >= DAY ? 'request_expired' : 'Request not found');
    if (row.state !== 'completed' || !row.result || !row.canonical_encrypted || row.retain_until <= this.now()) throw new VaultError(410,'result_unavailable');
    // This is a scoped result lookup, not a replay submission or a new approval.
    return JSON.parse(row.result) as Metadata;
  }
  delete(auth: Authority, id: string, expected_record_version: number): void {
    this.authority(auth); this.requireUnlocked(); this.db.transaction(() => {
      const row = this.row(id); if (row.record_version !== expected_record_version) throw new VaultError(409,'record_version_conflict');
      this.db.prepare('DELETE FROM credentials WHERE id=?').run(id); this.audit(auth,'connection_deleted',this.metadata(row));
      for (const [key,draft] of this.drafts) if (draft.payload.target_record_id === id) this.drafts.delete(key);
    })();
  }
  requireOAuthReauthorization(auth: Authority, id: string, expected: Metadata, epoch: number): void {
    this.authority(auth); this.requireUnlocked();
    this.db.transaction(() => {
      const row = this.row(id);
      if (this.epoch !== epoch || row.credential_type !== 'oauth' || row.status !== 'active'
        || row.record_version !== expected.record_version || row.status_version !== expected.status_version || row.material_version !== expected.material_version
        || this.db.prepare('SELECT 1 FROM material_leases WHERE connection_id=?').get(id)) return;
      this.db.prepare("UPDATE credentials SET status='needs_user_action',status_version=status_version+1,updated_at=? WHERE id=?").run(new Date(this.now()).toISOString(), id);
      this.audit(auth, 'oauth_resource_authorization_required', this.metadata(this.row(id)));
    })();
  }
  setStatus(auth: Authority, id: string, status: ConnectionStatus, expected_status_version: number): Metadata {
    this.authority(auth); this.requireUnlocked();
    if (!['active','paused','revoked','expired','needs_user_action','unknown'].includes(status)) throw new VaultError(400,'Invalid status');
    return this.db.transaction(() => {
      const row = this.row(id); if (row.status_version !== expected_status_version) throw new VaultError(409,'status_version_conflict');
      this.db.prepare('UPDATE credentials SET status=?,status_version=status_version+1,updated_at=? WHERE id=?').run(status,new Date(this.now()).toISOString(),id);
      const metadata = this.metadata(this.row(id)); this.audit(auth,'status_changed',metadata); return metadata;
    })();
  }
  purgeComparison(auth: Authority, request_id: string, operation_name: string): void {
    this.authority(auth); this.requireUnlocked(); this.ticket(auth,operation_name,request_id);
    this.db.transaction(() => {
      this.db.prepare('UPDATE requests SET canonical_encrypted=NULL,result=NULL WHERE owner_id=? AND principal_id=? AND operation_name=? AND request_id=?').run(auth.owner_id,auth.principal_id,operation_name,request_id);
      this.audit(auth,'request_comparison_purged');
    })();
  }
  purgeRecordComparisons(auth: Authority, id: string): void {
    this.authority(auth); this.requireUnlocked();
    if (auth.principal_id !== 'admin' || !auth.session_id || auth.client_id !== 'management') throw new VaultError(403,'Admin session required');
    this.db.transaction(() => {
      this.db.prepare("UPDATE requests SET canonical_encrypted=NULL,result=NULL WHERE owner_id=? AND connection_id=?").run(auth.owner_id,id);
      this.audit(auth,'record_comparisons_purged');
    })();
  }
  cleanupRetention(): void {
    this.db.prepare("UPDATE requests SET canonical_encrypted=NULL,result=NULL WHERE retain_until<=? AND state NOT IN ('accepted','dispatching','outcome_unknown')").run(this.now());
    for (const [id,draft] of this.drafts) if (draft.card.expires_at <= this.now()) this.drafts.delete(id);
  }
  private operationResult(row: RequestRow): OperationResult {
    const saved = row.result ? JSON.parse(row.result) as {result?:unknown;error?:string} : {};
    return {request_id:row.request_id,connection_id:row.connection_id!,operation_id:row.operation_name,state:row.state as OperationState,operation_status_version:row.operation_status_version,...saved};
  }
  replayOperation(auth: Authority, input: OperationInput): OperationResult | undefined {
    this.authority(auth); this.requireUnlocked();
    const existing = this.replay(auth, input.operation_id, input.request_id, input);
    return existing ? this.operationResult(existing) : undefined;
  }
  beginOperation(auth: Authority, input: OperationInput, definition: OperationDefinition): {replayed:boolean;operation:OperationResult} {
    this.authority(auth); this.requireUnlocked();
    if (definition.id !== input.operation_id) throw new VaultError(400,'Operation denied');
    return this.db.transaction(() => {
      const existing = this.replay(auth,input.operation_id,input.request_id,input);
      if (existing) return {replayed:true,operation:this.operationResult(existing)};
      const row = this.row(input.connection_id);
      if (row.credential_type === 'external_reference') throw new VaultError(403,'external_execution_unsupported');
      if (row.record_version !== input.expected_record_version) throw new VaultError(409,'record_version_conflict');
      if (row.status !== 'active') throw new VaultError(403,'connection_unavailable');
      if (row.service_id !== definition.service_id || row.origin !== definition.origin || !JSON.parse(row.granted_operations).includes(input.operation_id)) throw new VaultError(403,'Operation denied');
      if (this.db.prepare('SELECT 1 FROM material_leases WHERE connection_id=?').get(row.id)) throw new VaultError(409,'material_change_unresolved');
      if (definition.semantics !== 'read_only' && this.db.prepare("SELECT 1 FROM requests WHERE connection_id=? AND operation_name=? AND business_target=? AND state IN ('accepted','dispatching','outcome_unknown')").get(row.id,input.operation_id,definition.business_target)) throw new VaultError(409,'operation_reconciliation_required');
      this.db.prepare('INSERT INTO requests(owner_id,principal_id,operation_name,request_id,registered_at,retain_until,canonical_encrypted,state,connection_id,business_target,semantics,dispatch_epoch) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
        .run(auth.owner_id,auth.principal_id,input.operation_id,input.request_id,this.now(),this.now()+7*DAY,this.encryptedCanonical(auth,input.operation_id,input.request_id,input),'accepted',row.id,definition.business_target,definition.semantics,this.epoch);
      this.audit(auth,'operation_accepted',this.metadata(row));
      return {replayed:false,operation:this.operationResult(this.requestRow(auth,input.operation_id,input.request_id)!)};
    })();
  }
  markDispatching(auth: Authority, input: OperationInput): OperationResult {
    this.authority(auth); this.requireUnlocked();
    return this.db.transaction(() => {
      const request = this.requestRow(auth,input.operation_id,input.request_id);
      if (!request || request.state !== 'accepted' || request.dispatch_epoch !== this.epoch) throw new VaultError(409,'Dispatch denied');
      const row = this.row(input.connection_id);
      if (row.record_version !== input.expected_record_version || row.status !== 'active' || !JSON.parse(row.granted_operations).includes(input.operation_id) || this.db.prepare('SELECT 1 FROM material_leases WHERE connection_id=?').get(row.id)) throw new VaultError(403,'Operation denied');
      this.db.prepare("UPDATE requests SET state='dispatching',operation_status_version=operation_status_version+1 WHERE owner_id=? AND principal_id=? AND operation_name=? AND request_id=?").run(auth.owner_id,auth.principal_id,input.operation_id,input.request_id);
      return this.operationResult(this.requestRow(auth,input.operation_id,input.request_id)!);
    })();
  }
  finishOperation(auth: Authority, input: OperationInput, state: OperationState, result?: unknown, error?: string): OperationResult {
    this.authority(auth);
    if (!['succeeded','failed_before_dispatch','failed_confirmed','outcome_unknown'].includes(state)) throw new VaultError(400,'Invalid operation result');
    return this.db.transaction(() => {
      const row = this.requestRow(auth,input.operation_id,input.request_id);
      if (!row) throw new VaultError(404,'Request not found');
      if (!['accepted','dispatching'].includes(row.state)) return this.operationResult(row);
      if (row.state === 'dispatching' && state === 'failed_before_dispatch') throw new VaultError(409,'Dispatch outcome cannot be proven');
      if (row.state === 'accepted' && state !== 'failed_before_dispatch') throw new VaultError(409,'Dispatch not recorded');
      // Caller supplies only a whitelisted/redacted result. Raw upstream bodies never enter the journal.
      const saved = JSON.stringify({...result === undefined ? {} : {result},...error === undefined ? {} : {error}});
      this.db.prepare('UPDATE requests SET state=?,result=?,operation_status_version=operation_status_version+1 WHERE owner_id=? AND principal_id=? AND operation_name=? AND request_id=?').run(state,saved,auth.owner_id,auth.principal_id,input.operation_id,input.request_id);
      this.audit(auth,`operation_${state}`); return this.operationResult(this.requestRow(auth,input.operation_id,input.request_id)!);
    })();
  }
  listAudit(auth: Authority, limit = 100): {id:number;owner_id:string;principal_id:string;action:string;record_id:string|null;record_version:number|null;status_version:number|null;time:number}[] {
    this.authority(auth); this.requireUnlocked();
    if (auth.principal_id !== 'admin' || !auth.session_id || auth.client_id !== 'management') throw new VaultError(403,'Admin session required');
    if (!Number.isInteger(limit) || limit < 1 || limit > 200) throw new VaultError(400,'Invalid audit limit');
    return this.db.prepare('SELECT id,owner_id,principal_id,action,record_id,record_version,status_version,time FROM audit_events WHERE owner_id=? ORDER BY id DESC LIMIT ?').all(auth.owner_id,limit) as ReturnType<Vault['listAudit']>;
  }
  listOperationHistory(auth: Authority): (OperationResult & {principal_id:string;business_target:string|null})[] {
    this.authority(auth); this.requireUnlocked();
    if (auth.principal_id !== 'admin' || !auth.session_id || auth.client_id !== 'management') throw new VaultError(403,'Admin session required');
    return (this.db.prepare("SELECT * FROM requests WHERE owner_id=? AND semantics IS NOT NULL AND (state IN ('accepted','dispatching','outcome_unknown') OR rowid IN (SELECT rowid FROM requests WHERE owner_id=? AND semantics IS NOT NULL ORDER BY registered_at DESC LIMIT 200)) ORDER BY registered_at DESC").all(auth.owner_id,auth.owner_id) as RequestRow[])
      .map(row=>({...this.operationResult(row),principal_id:row.principal_id,business_target:row.business_target}));
  }
  reconcileOperation(auth: Authority, input: {request_id:string;operation_name:string;principal_id:string;expected_operation_status_version:number;resolution:'confirmed_succeeded'|'confirmed_failed'|'authorize_new_attempt';evidence_note:string;accept_duplicate_risk?:boolean}): OperationResult {
    this.authority(auth); this.requireUnlocked();
    if (auth.principal_id !== 'admin' || !auth.session_id || auth.client_id !== 'management') throw new VaultError(403,'Admin session required');
    if (!['confirmed_succeeded','confirmed_failed','authorize_new_attempt'].includes(input.resolution) || typeof input.evidence_note !== 'string' || input.evidence_note.trim().length < 8 || input.evidence_note.length > 1000) throw new VaultError(400,'Reconciliation evidence required');
    if (input.resolution === 'authorize_new_attempt' && input.accept_duplicate_risk !== true) throw new VaultError(403,'Duplicate risk acknowledgement required');
    const targetAuth: Authority={owner_id:auth.owner_id,principal_id:input.principal_id,client_id:'execution'};
    this.ticket(targetAuth,input.operation_name,input.request_id);
    return this.db.transaction(()=>{
      const row=this.requestRow(targetAuth,input.operation_name,input.request_id);
      if (!row || row.state !== 'outcome_unknown' || row.operation_status_version !== input.expected_operation_status_version) throw new VaultError(409,'operation_status_version_conflict');
      const state=input.resolution === 'confirmed_succeeded' ? 'succeeded' : 'failed_confirmed';
      // Evidence text is inspected by the administrator but never persisted as free text: it might contain secrets.
      const saved=JSON.stringify({result:{reconciliation:input.resolution,duplicate_risk_accepted:input.resolution === 'authorize_new_attempt'}});
      this.db.prepare('UPDATE requests SET state=?,result=?,operation_status_version=operation_status_version+1 WHERE owner_id=? AND principal_id=? AND operation_name=? AND request_id=?')
        .run(state,saved,auth.owner_id,input.principal_id,input.operation_name,input.request_id);
      this.audit(auth,`operation_reconciled_${input.resolution}`);
      return this.operationResult(this.requestRow(targetAuth,input.operation_name,input.request_id)!);
    })();
  }
  getOperationStatus(auth: Authority, request_id: string, operation_name: string): OperationResult {
    this.authority(auth); this.requireUnlocked(); this.ticket(auth,operation_name,request_id);
    const row = this.requestRow(auth,operation_name,request_id); if (!row) throw new VaultError(404,'Request not found');
    if (!row.canonical_encrypted || (row.retain_until <= this.now() && !['accepted','dispatching','outcome_unknown'].includes(row.state))) throw new VaultError(410,'result_unavailable');
    return this.operationResult(row);
  }
  async withToken<T>(id: string, callback: (token: string, signal: AbortSignal) => Promise<T>, expected_record_version?: number, operation_id?: string): Promise<T> {
    const key = this.requireUnlocked(), row = this.row(id);
    if (row.credential_type === 'external_reference') throw new VaultError(403,'external_execution_unsupported');
    if (row.status !== 'active') throw new VaultError(403,'connection_unavailable');
    if (expected_record_version !== undefined && row.record_version !== expected_record_version) throw new VaultError(409,'record_version_conflict');
    if (operation_id && !JSON.parse(row.granted_operations).includes(operation_id)) throw new VaultError(403,'Operation denied');
    const controller = new AbortController(), generation = this.generation; this.controllers.add(controller);
    let plaintext: Buffer | undefined;
    try {
      plaintext = unseal(key,JSON.parse(row.encrypted) as Sealed,row.encryption_context);
      const result = await callback(plaintext.toString(),controller.signal);
      if (generation !== this.generation) throw new VaultError(423,'Vault locked'); return result;
    } finally { plaintext?.fill(0); this.controllers.delete(controller); }
  }
  private oauthClientContext(provider: 'github' | 'google', version: number): string {
    return `agent-vault:v4:oauth-client:local:${provider}:${version}`;
  }
  readOAuthClient(auth: Authority, provider: 'github' | 'google'): {clientId:string;clientSecret:string;redirectUri:string;version:number} | undefined {
    this.authority(auth); this.requireUnlocked();
    if (!['github', 'google'].includes(provider)) throw new VaultError(400, 'unsupported_provider');
    const row = this.db.prepare('SELECT version,encrypted FROM oauth_clients WHERE owner_id=? AND provider=?').get(auth.owner_id, provider) as {version:number;encrypted:string} | undefined;
    if (!row) return undefined;
    const bytes = unseal(this.requireUnlocked(), JSON.parse(row.encrypted) as Sealed, this.oauthClientContext(provider, row.version));
    try { return { ...JSON.parse(bytes.toString()) as {clientId:string;clientSecret:string;redirectUri:string}, version: row.version }; }
    finally { bytes.fill(0); }
  }
  listOAuthClients(auth: Authority): {provider:'github'|'google';client_id:string;redirect_uri:string;version:number}[] {
    this.authority(auth); this.requireUnlocked();
    if (auth.principal_id !== 'admin' || !auth.session_id || auth.client_id !== 'management') throw new VaultError(403, 'Admin session required');
    return (['github', 'google'] as const).flatMap(provider => {
      const client = this.readOAuthClient(auth, provider);
      return client ? [{ provider, client_id: client.clientId, redirect_uri: client.redirectUri, version: client.version }] : [];
    });
  }
  writeOAuthClient(auth: Authority, provider: 'github' | 'google', client: {clientId:string;clientSecret:string;redirectUri:string}, expected_version: number): {provider:'github'|'google';client_id:string;redirect_uri:string;version:number} {
    this.authority(auth); this.requireUnlocked();
    if (auth.principal_id !== 'admin' || !auth.session_id || auth.client_id !== 'management') throw new VaultError(403, 'Admin session required');
    if (!['github', 'google'].includes(provider) || !Number.isSafeInteger(expected_version) || expected_version < 0
      || !/^[A-Za-z0-9._-]{1,256}$/.test(client.clientId) || !/^[\x21-\x7e]{1,16384}$/.test(client.clientSecret)
      || typeof client.redirectUri !== 'string' || client.redirectUri.length > 2048) throw new VaultError(400, 'invalid_oauth_client');
    return this.db.transaction(() => {
      const row = this.db.prepare('SELECT version FROM oauth_clients WHERE owner_id=? AND provider=?').get(auth.owner_id, provider) as {version:number} | undefined;
      if ((row?.version ?? 0) !== expected_version) throw new VaultError(409, 'oauth_client_version_conflict');
      const version = expected_version + 1;
      const bytes = Buffer.from(JSON.stringify({ clientId: client.clientId, clientSecret: client.clientSecret, redirectUri: client.redirectUri }));
      let encrypted: string;
      try { encrypted = JSON.stringify(seal(this.requireUnlocked(), bytes, this.oauthClientContext(provider, version))); }
      finally { bytes.fill(0); }
      this.db.prepare('INSERT INTO oauth_clients(owner_id,provider,version,encrypted) VALUES(?,?,?,?) ON CONFLICT(owner_id,provider) DO UPDATE SET version=excluded.version,encrypted=excluded.encrypted').run(auth.owner_id, provider, version, encrypted);
      if (row) this.db.prepare("UPDATE credentials SET status=CASE WHEN status='active' THEN 'needs_user_action' ELSE status END,status_version=status_version+1 WHERE owner_id=? AND service_id=? AND credential_type='oauth'").run(auth.owner_id, provider);
      this.audit(auth, 'oauth_client_configured');
      return { provider, client_id: client.clientId, redirect_uri: client.redirectUri, version };
    })();
  }
  readMaterial(auth: Authority, id: string): {metadata: Metadata; secret: string} {
    this.authority(auth); const key = this.requireUnlocked(), row = this.row(id);
    if (row.credential_type !== 'oauth') throw new VaultError(403,'OAuth material denied');
    const bytes = unseal(key,JSON.parse(row.encrypted) as Sealed,row.encryption_context);
    try { return {metadata:this.metadata(row),secret:bytes.toString()}; } finally { bytes.fill(0); }
  }
  reserveMaterial(auth: Authority, id: string, expected: {record_version:number;status_version:number;material_version:number}, action: string): {lease_id:string;epoch:number;record_version:number;status_version:number;material_version:number} {
    this.authority(auth); this.requireUnlocked();
    if (!['authorize','refresh','revoke'].includes(action)) throw new VaultError(400,'Invalid material action');
    return this.db.transaction(() => {
      const row = this.row(id);
      if (row.credential_type !== 'oauth') throw new VaultError(403,'OAuth material denied');
      if (row.record_version !== expected.record_version || row.status_version !== expected.status_version || row.material_version !== expected.material_version) throw new VaultError(409,'material_version_conflict');
      if (this.db.prepare('SELECT 1 FROM material_leases WHERE connection_id=?').get(id)) throw new VaultError(409,'material_change_unresolved');
      if (action === 'refresh' && row.status !== 'active'
        || action === 'revoke' && !['active', 'paused', 'needs_user_action', 'expired', 'revoked'].includes(row.status)
        || action === 'authorize' && row.status === 'paused') throw new VaultError(403,'OAuth material denied');
      const lease_id = random(), epoch = this.epoch;
      this.db.prepare('INSERT INTO material_leases(connection_id,lease_id,epoch,record_version,status_version,material_version,action,principal_id,state,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)')
        .run(id,lease_id,epoch,row.record_version,row.status_version,row.material_version,action,auth.principal_id,'pending',this.now());
      this.audit(auth,'material_change_reserved',this.metadata(row));
      return {lease_id,epoch,record_version:row.record_version,status_version:row.status_version,material_version:row.material_version};
    })();
  }
  reconcileMaterial(auth: Authority, id: string, input: {expected_record_version:number;expected_status_version:number;expected_material_version:number;evidence_note:string;abandon_old_material:true}): Metadata {
    this.authority(auth); this.requireUnlocked();
    if (auth.principal_id !== 'admin' || !auth.session_id || auth.client_id !== 'management') throw new VaultError(403,'Admin session required');
    if (typeof input.evidence_note !== 'string' || input.evidence_note.trim().length < 8 || input.evidence_note.length > 1000 || input.abandon_old_material !== true) throw new VaultError(400,'Material reconciliation evidence required');
    return this.db.transaction(()=>{
      const row=this.row(id);
      const lease=this.db.prepare('SELECT * FROM material_leases WHERE connection_id=?').get(id) as {state:string;epoch:number;record_version:number;status_version:number;material_version:number} | undefined;
      const versionsInvalid = lease && (lease.record_version !== row.record_version || lease.status_version !== row.status_version || lease.material_version !== row.material_version);
      if (!lease || (lease.state !== 'outcome_unknown' && lease.epoch === this.epoch && !versionsInvalid) || row.credential_type !== 'oauth') throw new VaultError(409,'material_reconciliation_denied');
      if (row.record_version !== input.expected_record_version || row.status_version !== input.expected_status_version || row.material_version !== input.expected_material_version) throw new VaultError(409,'material_version_conflict');
      const bytes=unseal(this.requireUnlocked(),JSON.parse(row.encrypted) as Sealed,row.encryption_context);
      let value: {schema?:number;provider?:string;approvedScopes?:unknown;subject?:unknown};
      try { value=JSON.parse(bytes.toString()) as typeof value; } finally {bytes.fill(0);}
      if (!value || value.schema !== 1 || value.provider !== row.service_id || !Array.isArray(value.approvedScopes)) throw new VaultError(400,'Invalid OAuth envelope');
      // Discard all uncertain token material. Scope approval remains; a new code flow is required.
      const clear={schema:1,provider:value.provider,approvedScopes:value.approvedScopes,...typeof value.subject === 'string' ? {subject:value.subject} : {},status:'reauthorization_required'};
      const plaintext=Buffer.from(JSON.stringify(clear));let encrypted:string;
      try {encrypted=JSON.stringify(seal(this.requireUnlocked(),plaintext,row.encryption_context));}finally{plaintext.fill(0);}
      this.db.prepare("UPDATE credentials SET encrypted=?,material_version=material_version+1,status='needs_user_action',status_version=status_version+1,updated_at=? WHERE id=?").run(encrypted,new Date(this.now()).toISOString(),id);
      this.db.prepare('DELETE FROM material_leases WHERE connection_id=?').run(id);
      const record=this.metadata(this.row(id));this.audit(auth,'material_reconciled_requires_reauthorization',record);return record;
    })();
  }
  completeMaterial(auth: Authority, id: string, lease_id: string, change: {secret?:string;status:ConnectionStatus;last_verified_at?:string;outcome_unknown?:boolean;expected_epoch?:number}): Metadata {
    this.authority(auth); this.requireUnlocked();
    if (!['active','paused','revoked','expired','needs_user_action','unknown'].includes(change.status)) throw new VaultError(400,'Invalid material status');
    return this.db.transaction(() => {
      const lease = this.db.prepare('SELECT * FROM material_leases WHERE connection_id=? AND lease_id=?').get(id,lease_id) as {epoch:number;record_version:number;status_version:number;material_version:number;principal_id:string;state:string} | undefined;
      const row = this.row(id);
      if (!lease || lease.principal_id !== auth.principal_id || lease.epoch !== this.epoch || change.expected_epoch !== undefined && change.expected_epoch !== this.epoch || lease.state !== 'pending') throw new VaultError(409,'material_lease_conflict');
      if (row.record_version !== lease.record_version || row.status_version !== lease.status_version || row.material_version !== lease.material_version) throw new VaultError(409,'material_version_conflict');
      let encrypted = row.encrypted;
      if (change.secret !== undefined) {
        const bytes = Buffer.from(change.secret); try { encrypted = JSON.stringify(seal(this.requireUnlocked(),bytes,row.encryption_context)); } finally { bytes.fill(0); }
      }
      this.db.prepare('UPDATE credentials SET encrypted=?,material_version=material_version+?,status=?,status_version=status_version+1,last_verified_at=?,updated_at=? WHERE id=?')
        .run(encrypted,change.secret === undefined ? 0 : 1,change.status,change.last_verified_at ?? row.last_verified_at,new Date(this.now()).toISOString(),id);
      if (change.outcome_unknown) this.db.prepare("UPDATE material_leases SET state='outcome_unknown' WHERE connection_id=?").run(id);
      else this.db.prepare('DELETE FROM material_leases WHERE connection_id=?').run(id);
      const record = this.metadata(this.row(id)); this.audit(auth,change.outcome_unknown ? 'material_outcome_unknown' : 'material_changed',record); return record;
    })();
  }
  close(): void { this.lock(); this.signingKey.fill(0); this.db.close(); }
}
