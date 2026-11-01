import { z } from 'zod';
import type { Authority, DraftCard, Metadata, SavePayload, SaveRequest } from './contracts.js';
import { savePayloadSchema, validateSavePayload } from './registry.js';

// Preserve the core's limits, strict fields and create/replace refinements; inference only
// narrows the credential types it may propose. Formal OAuth/other grants have their own flows.
const payloadSchema = savePayloadSchema.superRefine((payload, context) => {
  if (payload.credential_type !== 'api_key' && payload.credential_type !== 'password') {
    context.addIssue({ code: z.ZodIssueCode.custom, message: 'unsupported_inference_type' });
  }
});
export interface LocalInference {
  /** Explicit endpoint of the injected backend; loopback alone cannot prove it never forwards to a cloud. */
  readonly endpoint: string;
  readonly evidence: 'synthetic_fixture' | 'unverified_local_backend';
  infer(text: string, signal: AbortSignal): Promise<unknown>;
}
export interface LocalTranscriber {
  readonly endpoint: string;
  readonly evidence: 'synthetic_fixture' | 'unverified_local_backend';
  transcribe(audio: Uint8Array, signal: AbortSignal): Promise<string>;
}
/** These methods must delegate to the core's immutable draft/approval/atomic-save implementation.
 * approve() runs in a trusted UI handler which checks administrator session and CSRF, never in inference.
 * The returned approval is retained by this trusted orchestrator and is never in the model-facing card.
 */
export interface LocalDraftCore {
  propose(authority: Authority, payload: SavePayload): DraftCard;
  approve(administratorSession: string, csrf: string, draftId: string, draftVersion: number): { approval_token: string };
  save(authority: Authority, request: SaveRequest): Metadata | Promise<Metadata>;
  cancel(authority: Authority, draftId: string): void;
}
/** Bind the actual core, with confirmation authentication supplied by the management server.
 * That callback must validate both current session and CSRF before returning server-mapped authority.
 */
export function bindVaultLocalDraftCore(vault: {
  createDraft(auth: Authority, payload: SavePayload): DraftCard;
  approveDraft(auth: Authority, id: string, version: number): { approval_token: string };
  saveApproved(auth: Authority, request: SaveRequest): Metadata;
  cancelDraft(auth: Authority, id: string): void;
}, confirmationAuthority: (session: string, csrf: string) => Authority): LocalDraftCore {
  return {
    propose: (auth, payload) => vault.createDraft(auth, payload),
    approve: (session, csrf, id, version) => vault.approveDraft(confirmationAuthority(session, csrf), id, version),
    save: (auth, request) => vault.saveApproved(auth, request),
    cancel: (auth, id) => {
      try { vault.cancelDraft(auth, id); }
      catch (error) {
        // Expiry and lock have already invalidated the core draft; cleanup is idempotent.
        if (![410, 423].includes((error as { status?: number }).status ?? 0)) throw error;
      }
    },
  };
}
export class LocalDraftError extends Error {
  constructor(readonly code: string) { super(code); }
}
function endpoint(value: string): void {
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || !['127.0.0.1', '[::1]'].includes(url.hostname) ||
        url.username || url.password || url.hash || url.search) throw new Error();
  } catch { throw new LocalDraftError('local_endpoint_required'); }
}
interface Pending { card: DraftCard; payload: SavePayload; epoch: number }

/** Optional, memory-only, single-draft client. This module supplies no model, ASR, network discovery or fallback.
 * Input is passed unchanged. The trusted backend must preserve secret bytes and clarify ambiguity itself.
 * Cancellation/timeout/lock discard draft references; JavaScript cannot promise forensic memory erasure.
 */
export class LocalDraftSession {
  private pending?: Pending;
  private controller?: AbortController;
  private sequence = 0;
  private expiry?: ReturnType<typeof setTimeout>;
  private submitting = false;
  private readonly authority: Authority;
  constructor(private readonly options: {
    authority: Authority; core: LocalDraftCore; inference: LocalInference; transcriber?: LocalTranscriber;
    security: () => { unlocked: boolean; epoch: number }; clock?: () => number; inferenceTimeoutMs?: number;
  }) {
    endpoint(options.inference.endpoint);
    if (options.transcriber) endpoint(options.transcriber.endpoint);
    this.authority = structuredClone(options.authority);
  }
  get locality() {
    return { inference: this.options.inference.evidence, asr: this.options.transcriber?.evidence ?? 'absent',
      completely_local_verified: false as const };
  }
  async fromText(text: string): Promise<DraftCard & { secret_mask: '••••••••' }> {
    if (typeof text !== 'string' || !text.length || Buffer.byteLength(text) > 65_536) throw new LocalDraftError('invalid_input');
    return this.propose(signal => this.options.inference.infer(text, signal));
  }
  async fromAudio(audio: Uint8Array): Promise<DraftCard & { secret_mask: '••••••••' }> {
    const asr = this.options.transcriber;
    if (!asr) throw new LocalDraftError('asr_unavailable');
    if (!(audio instanceof Uint8Array) || audio.byteLength === 0 || audio.byteLength > 8_388_608) throw new LocalDraftError('invalid_input');
    return this.propose(async signal => {
      const text = await asr.transcribe(audio, signal);
      signal.throwIfAborted();
      if (typeof text !== 'string' || !text.length || Buffer.byteLength(text) > 65_536) throw new LocalDraftError('invalid_input');
      return this.options.inference.infer(text, signal);
    });
  }
  private async propose(infer: (signal: AbortSignal) => Promise<unknown>): Promise<DraftCard & { secret_mask: '••••••••' }> {
    this.cancel();
    const security = this.options.security();
    if (!security.unlocked) throw new LocalDraftError('vault_locked');
    const sequence = this.sequence;
    const controller = new AbortController();
    this.controller = controller;
    const timeout = setTimeout(() => controller.abort(), this.options.inferenceTimeoutMs ?? 30_000);
    let onAbort: (() => void) | undefined;
    try {
      const output = await Promise.race([infer(controller.signal), new Promise<never>((_, reject) => {
        onAbort = () => reject(new LocalDraftError('draft_cancelled_or_timed_out'));
        controller.signal.addEventListener('abort', onAbort, { once: true });
        if (controller.signal.aborted) onAbort();
      })]);
      const current = this.options.security();
      if (sequence !== this.sequence || controller.signal.aborted) throw new LocalDraftError('draft_cancelled_or_timed_out');
      if (!current.unlocked || current.epoch !== security.epoch) throw new LocalDraftError('vault_locked');
      const parsed = payloadSchema.safeParse(output);
      if (!parsed.success) throw new LocalDraftError('invalid_inference_draft');
      const payload: SavePayload = structuredClone(validateSavePayload(parsed.data));
      const card = this.options.core.propose(this.authority, structuredClone(payload));
      // Construct a metadata-only card; do not spread a backend- or core-provided object into the UI.
      const safeCard: DraftCard = {
        draft_id: card.draft_id, draft_version: card.draft_version, expires_at: card.expires_at,
        mode: payload.mode, label: payload.label, service_id: payload.service_id, credential_type: payload.credential_type,
        account_alias: payload.account_alias, origin: payload.origin, environment: payload.environment,
        granted_operations: [...payload.granted_operations],
        ...(payload.target_record_id === undefined ? {} : { target_record_id: payload.target_record_id }),
        ...(payload.expected_record_version === undefined ? {} : { expected_record_version: payload.expected_record_version }),
      };
      this.pending = { card: safeCard, payload, epoch: security.epoch };
      const remaining = safeCard.expires_at - (this.options.clock ?? Date.now)();
      if (remaining <= 0) { this.cancel(); throw new LocalDraftError('draft_expired'); }
      this.expiry = setTimeout(() => this.cancel(), Math.min(remaining, 2_147_483_647));
      this.expiry.unref();
      return { ...structuredClone(safeCard), secret_mask: '••••••••' };
    } catch (error) {
      if (error instanceof LocalDraftError) throw error;
      throw new LocalDraftError('draft_failed');
    } finally {
      clearTimeout(timeout);
      if (onAbort) controller.signal.removeEventListener('abort', onAbort);
      if (this.controller === controller) this.controller = undefined;
    }
  }
  /** Called only by authenticated, CSRF-protected confirmation UI with its server-issued request ticket. */
  async confirm(input: { administrator_session: string; csrf: string; draft_id: string; draft_version: number; request_id: string }): Promise<Metadata> {
    if (this.submitting) throw new LocalDraftError('draft_busy');
    const pending = this.pending;
    if (!pending || input.draft_id !== pending.card.draft_id || input.draft_version !== pending.card.draft_version) throw new LocalDraftError('draft_mismatch');
    if (pending.card.expires_at <= (this.options.clock ?? Date.now)()) { this.cancel(); throw new LocalDraftError('draft_expired'); }
    const security = this.options.security();
    if (!security.unlocked || security.epoch !== pending.epoch) { this.cancel(); throw new LocalDraftError('vault_locked'); }
    // No approval can originate in a model response. The core binds and consumes it atomically.
    const approval = this.options.core.approve(input.administrator_session, input.csrf, input.draft_id, input.draft_version);
    this.submitting = true;
    try {
      const result = await this.options.core.save(this.authority, {
        request_id: input.request_id, draft_id: input.draft_id, draft_version: input.draft_version,
        approval_token: approval.approval_token, payload: structuredClone(pending.payload),
      });
      if (this.pending === pending) {
        this.pending = undefined;
        if (this.expiry) clearTimeout(this.expiry);
        this.expiry = undefined;
      }
      return result;
    } finally { this.submitting = false; }
  }
  /** Wire the core's lock/logout/restart notification to this method as well as its own draft cleanup. */
  cancel(): void {
    this.sequence++;
    this.controller?.abort();
    this.controller = undefined;
    if (this.expiry) clearTimeout(this.expiry);
    this.expiry = undefined;
    const pending = this.pending;
    this.pending = undefined;
    if (pending) this.options.core.cancel(this.authority, pending.card.draft_id);
  }
  dispose(): void { this.cancel(); }
}
