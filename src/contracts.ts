export type CredentialType = 'api_key' | 'password' | 'oauth' | 'external_reference' | 'delegation';
export type ConnectionStatus = 'active' | 'paused' | 'revoked' | 'expired' | 'needs_user_action' | 'unknown';
export interface Authority { owner_id: 'local'; principal_id: string; client_id: string; session_id?: string }
export interface SavePayload {
  mode: 'create' | 'replace'; label: string; service_id: string; credential_type: CredentialType;
  account_alias: string; secret: string; origin: string; environment: 'local'; granted_operations: string[];
  target_record_id?: string; expected_record_version?: number;
}
export interface Metadata {
  id: string; owner_id: 'local'; label: string; provider: string; service_id: string; credential_type: CredentialType;
  account_alias: string; origin: string; environment: 'local'; granted_operations: string[];
  storage_mode: 'managed' | 'external_reference';
  record_version: number; status_version: number; material_version: number; status: ConnectionStatus;
  last_verified_at: string | null; created_at: string; updated_at: string; can_execute: boolean; material_change_unresolved?: boolean;
}
export interface DraftCard {
  draft_id: string; draft_version: number; expires_at: number;
  mode: 'create' | 'replace'; label: string; service_id: string; credential_type: CredentialType;
  account_alias: string; origin: string; environment: 'local'; granted_operations: string[];
  target_record_id?: string; expected_record_version?: number;
}
export interface SaveRequest { request_id: string; draft_id: string; draft_version: number; approval_token: string; payload: SavePayload }
export type OperationState = 'accepted' | 'dispatching' | 'succeeded' | 'failed_before_dispatch' | 'failed_confirmed' | 'outcome_unknown';
export interface OperationInput { request_id: string; connection_id: string; operation_id: string; expected_record_version: number; args: Record<string, unknown> }
export interface OperationResult {
  request_id: string; connection_id: string; operation_id: string; state: OperationState; operation_status_version: number;
  result?: unknown; error?: string;
}
export interface OperationDefinition { id: string; service_id: string; origin: string; semantics: 'read_only' | 'upstream_idempotent' | 'non_idempotent'; business_target: string }
