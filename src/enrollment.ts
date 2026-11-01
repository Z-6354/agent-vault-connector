import { z } from 'zod';
import { MOCK_OPERATION, MOCK_ORIGIN } from './network.js';

// Trusted source registry; only the fixed synthetic exception is executable today.
export const services = Object.freeze([Object.freeze({
  service_id: 'synthetic-mock', origin: MOCK_ORIGIN, synthetic: true,
  credential_type: 'api_key', operation_id: MOCK_OPERATION,
})]);
export const enrollmentSchema = z.object({
  credential_type: z.literal('api_key'),
  service_id: z.literal('synthetic-mock'),
  account_alias: z.string().trim().min(1).max(80),
  mode: z.enum(['create', 'replace']),
  target_record_id: z.string().uuid().optional(),
  expected_version: z.number().int().positive().max(Number.MAX_SAFE_INTEGER).optional(),
}).strict().superRefine((value, ctx) => {
  if (value.mode === 'create' ? value.target_record_id !== undefined || value.expected_version !== undefined : value.target_record_id === undefined || value.expected_version === undefined) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Invalid create/replace metadata' });
  }
});
export const enrollmentStatusSchema = z.object({ request_id: z.string().uuid() }).strict();
export type EnrollmentInput = z.infer<typeof enrollmentSchema>;
export type EnrollmentStatus = 'pending' | 'approved' | 'completed' | 'conflict' | 'expired' | 'cancelled' | 'locked';
export interface EnrollmentRow {
  request_id: string; owner: 'local'; service_id: 'synthetic-mock'; credential_type: 'api_key';
  account_alias: string; mode: 'create' | 'replace'; target_record_id: string | null;
  expected_version: number | null; status: EnrollmentStatus; operation_id: string | null;
  record_id: string | null; version: number | null; expires_at: number;
}
export const enrollmentPrompt = 'Open the fixed local management UI. Review the registered origin and enrollment metadata, explicitly grant the fixed operation, then enter the synthetic API key directly there. Never send a secret in chat or MCP. Chat secrets already sent are not erased or protected by these schemas.';
